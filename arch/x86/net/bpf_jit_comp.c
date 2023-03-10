/* bpf_jit_comp.c : BPF JIT compiler
 *
 * Copyright (C) 2011-2013 Eric Dumazet (eric.dumazet@gmail.com)
 * Internal BPF Copyright (c) 2011-2014 PLUMgrid, http://plumgrid.com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#include <linux/moduleloader.h>
#include <asm/cacheflush.h>
#include <linux/netdevice.h>
#include <linux/filter.h>
#include <linux/if_vlan.h>
#include <linux/random.h>

int bpf_jit_enable __read_mostly;

/*
 * assembly code in arch/x86/net/bpf_jit.S
 */
extern u8 sk_load_word[], sk_load_half[], sk_load_byte[];
extern u8 sk_load_word_positive_offset[], sk_load_half_positive_offset[];
extern u8 sk_load_byte_positive_offset[];
extern u8 sk_load_word_negative_offset[], sk_load_half_negative_offset[];
extern u8 sk_load_byte_negative_offset[];

static inline u8 *emit_code(u8 *ptr, u32 bytes, unsigned int len)
{
	if (len == 1)
		*ptr = bytes;
	else if (len == 2)
		*(u16 *)ptr = bytes;
	else {
		*(u32 *)ptr = bytes;
		barrier();
	}
	return ptr + len;
}

#define EMIT(bytes, len)	do { prog = emit_code(prog, bytes, len); } while (0)

#define EMIT1(b1)		EMIT(b1, 1)
#define EMIT2(b1, b2)		EMIT((b1) + ((b2) << 8), 2)
#define EMIT3(b1, b2, b3)	EMIT((b1) + ((b2) << 8) + ((b3) << 16), 3)
#define EMIT4(b1, b2, b3, b4)   EMIT((b1) + ((b2) << 8) + ((b3) << 16) + ((b4) << 24), 4)
#define EMIT1_off32(b1, off) \
	do {EMIT1(b1); EMIT(off, 4); } while (0)
#define EMIT2_off32(b1, b2, off) \
	do {EMIT2(b1, b2); EMIT(off, 4); } while (0)
#define EMIT3_off32(b1, b2, b3, off) \
	do {EMIT3(b1, b2, b3); EMIT(off, 4); } while (0)
#define EMIT4_off32(b1, b2, b3, b4, off) \
	do {EMIT4(b1, b2, b3, b4); EMIT(off, 4); } while (0)

static inline bool is_imm8(int value)
{
	return value <= 127 && value >= -128;
}

static inline bool is_simm32(s64 value)
{
	return value == (s64) (s32) value;
}

/* mov A, X */
#define EMIT_mov(A, X) \
	do {if (A != X) \
		EMIT3(add_2mod(0x48, A, X), 0x89, add_2reg(0xC0, A, X)); \
	} while (0)

static int bpf_size_to_x86_bytes(int bpf_size)
{
	if (bpf_size == BPF_W)
		return 4;
	else if (bpf_size == BPF_H)
		return 2;
	else if (bpf_size == BPF_B)
		return 1;
	else if (bpf_size == BPF_DW)
		return 4; /* imm32 */
	else
		return 0;
}

/* list of x86 cond jumps opcodes (. + s8)
 * Add 0x10 (and an extra 0x0f) to generate far jumps (. + s32)
 */
#define X86_JB  0x72
#define X86_JAE 0x73
#define X86_JE  0x74
#define X86_JNE 0x75
#define X86_JBE 0x76
#define X86_JA  0x77
#define X86_JGE 0x7D
#define X86_JG  0x7F

static inline void bpf_flush_icache(void *start, void *end)
{
	mm_segment_t old_fs = get_fs();

	set_fs(KERNEL_DS);
	smp_wmb();
	flush_icache_range((unsigned long)start, (unsigned long)end);
	set_fs(old_fs);
}

#define CHOOSE_LOAD_FUNC(K, func) \
	((int)K < 0 ? ((int)K >= SKF_LL_OFF ? func##_negative_offset : func) : func##_positive_offset)

/* Note : for security reasons, bpf code will follow a randomly
 * sized amount of int3 instructions
 */
static u8 *bpf_alloc_binary(unsigned int proglen,
						  u8 **image_ptr)
{
	unsigned int sz, hole;
	u8 *header;

	/* Most of BPF filters are really small,
	 * but if some of them fill a page, allow at least
	 * 128 extra bytes to insert a random section of int3
	 */
	sz = round_up(proglen + 128, PAGE_SIZE);
	header = module_alloc_exec(sz);
 	if (!header)
	if (!header)
		return NULL;

	pax_open_kernel();
	memset(header, 0xcc, sz); /* fill whole space with int3 instructions */
	pax_close_kernel();

	hole = PAGE_SIZE - (proglen & ~PAGE_MASK);

	/* insert a random number of int3 instructions before BPF code */
	*image_ptr = &header[prandom_u32() % hole];
	return header;
}

/* pick a register outside of BPF range for JIT internal work */
#define AUX_REG (MAX_BPF_REG + 1)

/* the following table maps BPF registers to x64 registers.
 * x64 register r12 is unused, since if used as base address register
 * in load/store instructions, it always needs an extra byte of encoding
 */
static const int reg2hex[] = {
	[BPF_REG_0] = 0,  /* rax */
	[BPF_REG_1] = 7,  /* rdi */
	[BPF_REG_2] = 6,  /* rsi */
	[BPF_REG_3] = 2,  /* rdx */
	[BPF_REG_4] = 1,  /* rcx */
	[BPF_REG_5] = 0,  /* r8 */
	[BPF_REG_6] = 3,  /* rbx callee saved */
	[BPF_REG_7] = 5,  /* r13 callee saved */
	[BPF_REG_8] = 6,  /* r14 callee saved */
	[BPF_REG_9] = 7,  /* r15 callee saved */
	[BPF_REG_FP] = 5, /* rbp readonly */
	[AUX_REG] = 3,    /* r11 temp register */
};

/* is_ereg() == true if BPF register 'reg' maps to x64 r8..r15
 * which need extra byte of encoding.
 * rax,rcx,...,rbp have simpler encoding
 */
static inline bool is_ereg(u32 reg)
{
	if (reg == BPF_REG_5 || reg == AUX_REG ||
	    (reg >= BPF_REG_7 && reg <= BPF_REG_9))
		return true;
	else
		return false;
}

/* add modifiers if 'reg' maps to x64 registers r8..r15 */
static inline u8 add_1mod(u8 byte, u32 reg)
{
	if (is_ereg(reg))
		byte |= 1;
	return byte;
}

static inline u8 add_2mod(u8 byte, u32 r1, u32 r2)
{
	if (is_ereg(r1))
		byte |= 1;
	if (is_ereg(r2))
		byte |= 4;
	return byte;
}

/* encode dest register 'a_reg' into x64 opcode 'byte' */
static inline u8 add_1reg(u8 byte, u32 a_reg)
{
	return byte + reg2hex[a_reg];
}

/* encode dest 'a_reg' and src 'x_reg' registers into x64 opcode 'byte' */
static inline u8 add_2reg(u8 byte, u32 a_reg, u32 x_reg)
{
	return byte + reg2hex[a_reg] + (reg2hex[x_reg] << 3);
}

struct jit_context {
	unsigned int cleanup_addr; /* epilogue code offset */
	bool seen_ld_abs;
};

static int do_jit(struct sk_filter *bpf_prog, int *addrs, u8 *image,
		  int oldproglen, struct jit_context *ctx)
{
	struct sock_filter_int *insn = bpf_prog->insnsi;
	int insn_cnt = bpf_prog->len;
	u8 temp[64];

	/* JITed image shrinks with every pass and the loop iterates
	 * until the image stops shrinking. Very large bpf programs
	 * may converge on the last pass. In such case do one more
	 * pass to emit the final image
	 */
	int i;
	int proglen = 0;
	u8 *prog = temp;
	int stacksize = MAX_BPF_STACK +
		32 /* space for rbx, r13, r14, r15 */ +
		8 /* space for skb_copy_bits() buffer */;

	EMIT1(0x55); /* push rbp */
	EMIT3(0x48, 0x89, 0xE5); /* mov rbp,rsp */

	/* sub rsp, stacksize */
	EMIT3_off32(0x48, 0x81, 0xEC, stacksize);

	/* all classic BPF filters use R6(rbx) save it */

	/* mov qword ptr [rbp-X],rbx */
	EMIT3_off32(0x48, 0x89, 0x9D, -stacksize);

	/* sk_convert_filter() maps classic BPF register X to R7 and uses R8
	 * as temporary, so all tcpdump filters need to spill/fill R7(r13) and
	 * R8(r14). R9(r15) spill could be made conditional, but there is only
	 * one 'bpf_error' return path out of helper functions inside bpf_jit.S
	 * The overhead of extra spill is negligible for any filter other
	 * than synthetic ones. Therefore not worth adding complexity.
	 */

	/* mov qword ptr [rbp-X],r13 */
	EMIT3_off32(0x4C, 0x89, 0xAD, -stacksize + 8);
	/* mov qword ptr [rbp-X],r14 */
	EMIT3_off32(0x4C, 0x89, 0xB5, -stacksize + 16);
	/* mov qword ptr [rbp-X],r15 */
	EMIT3_off32(0x4C, 0x89, 0xBD, -stacksize + 24);

	/* clear A and X registers */
	EMIT2(0x31, 0xc0); /* xor eax, eax */
	EMIT3(0x4D, 0x31, 0xED); /* xor r13, r13 */

	if (ctx->seen_ld_abs) {
		/* r9d : skb->len - skb->data_len (headlen)
		 * r10 : skb->data
		 */
		if (is_imm8(offsetof(struct sk_buff, len)))
			/* mov %r9d, off8(%rdi) */
			EMIT4(0x44, 0x8b, 0x4f,
			      offsetof(struct sk_buff, len));
		else
			/* mov %r9d, off32(%rdi) */
			EMIT3_off32(0x44, 0x8b, 0x8f,
				    offsetof(struct sk_buff, len));

		if (is_imm8(offsetof(struct sk_buff, data_len)))
			/* sub %r9d, off8(%rdi) */
			EMIT4(0x44, 0x2b, 0x4f,
			      offsetof(struct sk_buff, data_len));
		else
			EMIT3_off32(0x44, 0x2b, 0x8f,
				    offsetof(struct sk_buff, data_len));

		if (is_imm8(offsetof(struct sk_buff, data)))
			/* mov %r10, off8(%rdi) */
			EMIT4(0x4c, 0x8b, 0x57,
			      offsetof(struct sk_buff, data));
		else
			/* mov %r10, off32(%rdi) */
			EMIT3_off32(0x4c, 0x8b, 0x97,
				    offsetof(struct sk_buff, data));
	}

	for (i = 0; i < insn_cnt; i++, insn++) {
		const s32 K = insn->imm;
		u32 a_reg = insn->a_reg;
		u32 x_reg = insn->x_reg;
		u8 b1 = 0, b2 = 0, b3 = 0;
		s64 jmp_offset;
		u8 jmp_cond;
		int ilen;
		u8 *func;

		switch (insn->code) {
			/* ALU */
		case BPF_ALU | BPF_ADD | BPF_X:
		case BPF_ALU | BPF_SUB | BPF_X:
		case BPF_ALU | BPF_AND | BPF_X:
		case BPF_ALU | BPF_OR | BPF_X:
		case BPF_ALU | BPF_XOR | BPF_X:
		case BPF_ALU64 | BPF_ADD | BPF_X:
		case BPF_ALU64 | BPF_SUB | BPF_X:
		case BPF_ALU64 | BPF_AND | BPF_X:
		case BPF_ALU64 | BPF_OR | BPF_X:
		case BPF_ALU64 | BPF_XOR | BPF_X:
			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b2 = 0x01; break;
			case BPF_SUB: b2 = 0x29; break;
			case BPF_AND: b2 = 0x21; break;
			case BPF_OR: b2 = 0x09; break;
			case BPF_XOR: b2 = 0x31; break;
			}
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_2mod(0x48, a_reg, x_reg));
			else if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT1(add_2mod(0x40, a_reg, x_reg));
			EMIT2(b2, add_2reg(0xC0, a_reg, x_reg));
			break;

			/* mov A, X */
		case BPF_ALU64 | BPF_MOV | BPF_X:
			EMIT_mov(a_reg, x_reg);
			break;

			/* mov32 A, X */
		case BPF_ALU | BPF_MOV | BPF_X:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT1(add_2mod(0x40, a_reg, x_reg));
			EMIT2(0x89, add_2reg(0xC0, a_reg, x_reg));
			break;

			/* neg A */
		case BPF_ALU | BPF_NEG:
		case BPF_ALU64 | BPF_NEG:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, a_reg));
			else if (is_ereg(a_reg))
				EMIT1(add_1mod(0x40, a_reg));
			EMIT2(0xF7, add_1reg(0xD8, a_reg));
			break;

		case BPF_ALU | BPF_ADD | BPF_K:
		case BPF_ALU | BPF_SUB | BPF_K:
		case BPF_ALU | BPF_AND | BPF_K:
		case BPF_ALU | BPF_OR | BPF_K:
		case BPF_ALU | BPF_XOR | BPF_K:
		case BPF_ALU64 | BPF_ADD | BPF_K:
		case BPF_ALU64 | BPF_SUB | BPF_K:
		case BPF_ALU64 | BPF_AND | BPF_K:
		case BPF_ALU64 | BPF_OR | BPF_K:
		case BPF_ALU64 | BPF_XOR | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, a_reg));
			else if (is_ereg(a_reg))
				EMIT1(add_1mod(0x40, a_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_ADD: b3 = 0xC0; break;
			case BPF_SUB: b3 = 0xE8; break;
			case BPF_AND: b3 = 0xE0; break;
			case BPF_OR: b3 = 0xC8; break;
			case BPF_XOR: b3 = 0xF0; break;
			}

			if (is_imm8(K))
				EMIT3(0x83, add_1reg(b3, a_reg), K);
			else
				EMIT2_off32(0x81, add_1reg(b3, a_reg), K);
			break;

		case BPF_ALU64 | BPF_MOV | BPF_K:
			/* optimization: if imm32 is positive,
			 * use 'mov eax, imm32' (which zero-extends imm32)
			 * to save 2 bytes
			 */
			if (K < 0) {
				/* 'mov rax, imm32' sign extends imm32 */
				b1 = add_1mod(0x48, a_reg);
				b2 = 0xC7;
				b3 = 0xC0;
				EMIT3_off32(b1, b2, add_1reg(b3, a_reg), K);
				break;
			}

		case BPF_ALU | BPF_MOV | BPF_K:
			/* mov %eax, imm32 */
			if (is_ereg(a_reg))
				EMIT1(add_1mod(0x40, a_reg));
			EMIT1_off32(add_1reg(0xB8, a_reg), K);
			break;

			/* A %= X, A /= X, A %= K, A /= K */
		case BPF_ALU | BPF_MOD | BPF_X:
		case BPF_ALU | BPF_DIV | BPF_X:
		case BPF_ALU | BPF_MOD | BPF_K:
		case BPF_ALU | BPF_DIV | BPF_K:
		case BPF_ALU64 | BPF_MOD | BPF_X:
		case BPF_ALU64 | BPF_DIV | BPF_X:
		case BPF_ALU64 | BPF_MOD | BPF_K:
		case BPF_ALU64 | BPF_DIV | BPF_K:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			if (BPF_SRC(insn->code) == BPF_X)
				/* mov r11, X */
				EMIT_mov(AUX_REG, x_reg);
			else
				/* mov r11, K */
				EMIT3_off32(0x49, 0xC7, 0xC3, K);

			/* mov rax, A */
			EMIT_mov(BPF_REG_0, a_reg);

			/* xor edx, edx
			 * equivalent to 'xor rdx, rdx', but one byte less
			 */
			EMIT2(0x31, 0xd2);

			if (BPF_SRC(insn->code) == BPF_X) {
				/* if (X == 0) return 0 */

				/* cmp r11, 0 */
				EMIT4(0x49, 0x83, 0xFB, 0x00);

				/* jne .+9 (skip over pop, pop, xor and jmp) */
				EMIT2(X86_JNE, 1 + 1 + 2 + 5);
				EMIT1(0x5A); /* pop rdx */
				EMIT1(0x58); /* pop rax */
				EMIT2(0x31, 0xc0); /* xor eax, eax */

				/* jmp cleanup_addr
				 * addrs[i] - 11, because there are 11 bytes
				 * after this insn: div, mov, pop, pop, mov
				 */
				jmp_offset = ctx->cleanup_addr - (addrs[i] - 11);
				EMIT1_off32(0xE9, jmp_offset);
			}

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				/* div r11 */
				EMIT3(0x49, 0xF7, 0xF3);
			else
				/* div r11d */
				EMIT3(0x41, 0xF7, 0xF3);

			if (BPF_OP(insn->code) == BPF_MOD)
				/* mov r11, rdx */
				EMIT3(0x49, 0x89, 0xD3);
			else
				/* mov r11, rax */
				EMIT3(0x49, 0x89, 0xC3);

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov A, r11 */
			EMIT_mov(a_reg, AUX_REG);
			break;

		case BPF_ALU | BPF_MUL | BPF_K:
		case BPF_ALU | BPF_MUL | BPF_X:
		case BPF_ALU64 | BPF_MUL | BPF_K:
		case BPF_ALU64 | BPF_MUL | BPF_X:
			EMIT1(0x50); /* push rax */
			EMIT1(0x52); /* push rdx */

			/* mov r11, A */
			EMIT_mov(AUX_REG, a_reg);

			if (BPF_SRC(insn->code) == BPF_X)
				/* mov rax, X */
				EMIT_mov(BPF_REG_0, x_reg);
			else
				/* mov rax, K */
				EMIT3_off32(0x48, 0xC7, 0xC0, K);

			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, AUX_REG));
			else if (is_ereg(AUX_REG))
				EMIT1(add_1mod(0x40, AUX_REG));
			/* mul(q) r11 */
			EMIT2(0xF7, add_1reg(0xE0, AUX_REG));

			/* mov r11, rax */
			EMIT_mov(AUX_REG, BPF_REG_0);

			EMIT1(0x5A); /* pop rdx */
			EMIT1(0x58); /* pop rax */

			/* mov A, r11 */
			EMIT_mov(a_reg, AUX_REG);
			break;

			/* shifts */
		case BPF_ALU | BPF_LSH | BPF_K:
		case BPF_ALU | BPF_RSH | BPF_K:
		case BPF_ALU | BPF_ARSH | BPF_K:
		case BPF_ALU64 | BPF_LSH | BPF_K:
		case BPF_ALU64 | BPF_RSH | BPF_K:
		case BPF_ALU64 | BPF_ARSH | BPF_K:
			if (BPF_CLASS(insn->code) == BPF_ALU64)
				EMIT1(add_1mod(0x48, a_reg));
			else if (is_ereg(a_reg))
				EMIT1(add_1mod(0x40, a_reg));

			switch (BPF_OP(insn->code)) {
			case BPF_LSH: b3 = 0xE0; break;
			case BPF_RSH: b3 = 0xE8; break;
			case BPF_ARSH: b3 = 0xF8; break;
			}
			EMIT3(0xC1, add_1reg(b3, a_reg), K);
			break;

		case BPF_ALU | BPF_END | BPF_FROM_BE:
			switch (K) {
			case 16:
				/* emit 'ror %ax, 8' to swap lower 2 bytes */
				EMIT1(0x66);
				if (is_ereg(a_reg))
					EMIT1(0x41);
				EMIT3(0xC1, add_1reg(0xC8, a_reg), 8);
				break;
			case 32:
				/* emit 'bswap eax' to swap lower 4 bytes */
				if (is_ereg(a_reg))
					EMIT2(0x41, 0x0F);
				else
					EMIT1(0x0F);
				EMIT1(add_1reg(0xC8, a_reg));
				break;
			case 64:
				/* emit 'bswap rax' to swap 8 bytes */
				EMIT3(add_1mod(0x48, a_reg), 0x0F,
				      add_1reg(0xC8, a_reg));
				break;
			}
			break;

		case BPF_ALU | BPF_END | BPF_FROM_LE:
			break;

			/* ST: *(u8*)(a_reg + off) = imm */
		case BPF_ST | BPF_MEM | BPF_B:
			if (is_ereg(a_reg))
				EMIT2(0x41, 0xC6);
			else
				EMIT1(0xC6);
			goto st;
		case BPF_ST | BPF_MEM | BPF_H:
			if (is_ereg(a_reg))
				EMIT3(0x66, 0x41, 0xC7);
			else
				EMIT2(0x66, 0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_W:
			if (is_ereg(a_reg))
				EMIT2(0x41, 0xC7);
			else
				EMIT1(0xC7);
			goto st;
		case BPF_ST | BPF_MEM | BPF_DW:
			EMIT2(add_1mod(0x48, a_reg), 0xC7);

st:			if (is_imm8(insn->off))
				EMIT2(add_1reg(0x40, a_reg), insn->off);
			else
				EMIT1_off32(add_1reg(0x80, a_reg), insn->off);

			EMIT(K, bpf_size_to_x86_bytes(BPF_SIZE(insn->code)));
			break;

			/* STX: *(u8*)(a_reg + off) = x_reg */
		case BPF_STX | BPF_MEM | BPF_B:
			/* emit 'mov byte ptr [rax + off], al' */
			if (is_ereg(a_reg) || is_ereg(x_reg) ||
			    /* have to add extra byte for x86 SIL, DIL regs */
			    x_reg == BPF_REG_1 || x_reg == BPF_REG_2)
				EMIT2(add_2mod(0x40, a_reg, x_reg), 0x88);
			else
				EMIT1(0x88);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_H:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT3(0x66, add_2mod(0x40, a_reg, x_reg), 0x89);
			else
				EMIT2(0x66, 0x89);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_W:
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT2(add_2mod(0x40, a_reg, x_reg), 0x89);
			else
				EMIT1(0x89);
			goto stx;
		case BPF_STX | BPF_MEM | BPF_DW:
			EMIT2(add_2mod(0x48, a_reg, x_reg), 0x89);
stx:			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, a_reg, x_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, a_reg, x_reg),
					    insn->off);
			break;

			/* LDX: a_reg = *(u8*)(x_reg + off) */
		case BPF_LDX | BPF_MEM | BPF_B:
			/* emit 'movzx rax, byte ptr [rax + off]' */
			EMIT3(add_2mod(0x48, x_reg, a_reg), 0x0F, 0xB6);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_H:
			/* emit 'movzx rax, word ptr [rax + off]' */
			EMIT3(add_2mod(0x48, x_reg, a_reg), 0x0F, 0xB7);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_W:
			/* emit 'mov eax, dword ptr [rax+0x14]' */
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT2(add_2mod(0x40, x_reg, a_reg), 0x8B);
			else
				EMIT1(0x8B);
			goto ldx;
		case BPF_LDX | BPF_MEM | BPF_DW:
			/* emit 'mov rax, qword ptr [rax+0x14]' */
			EMIT2(add_2mod(0x48, x_reg, a_reg), 0x8B);
ldx:			/* if insn->off == 0 we can save one extra byte, but
			 * special case of x86 r13 which always needs an offset
			 * is not worth the hassle
			 */
			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, x_reg, a_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, x_reg, a_reg),
					    insn->off);
			break;

			/* STX XADD: lock *(u32*)(a_reg + off) += x_reg */
		case BPF_STX | BPF_XADD | BPF_W:
			/* emit 'lock add dword ptr [rax + off], eax' */
			if (is_ereg(a_reg) || is_ereg(x_reg))
				EMIT3(0xF0, add_2mod(0x40, a_reg, x_reg), 0x01);
			else
				EMIT2(0xF0, 0x01);
			goto xadd;
		case BPF_STX | BPF_XADD | BPF_DW:
			EMIT3(0xF0, add_2mod(0x48, a_reg, x_reg), 0x01);
xadd:			if (is_imm8(insn->off))
				EMIT2(add_2reg(0x40, a_reg, x_reg), insn->off);
			else
				EMIT1_off32(add_2reg(0x80, a_reg, x_reg),
					    insn->off);
			break;

			/* call */
		case BPF_JMP | BPF_CALL:
			func = (u8 *) __bpf_call_base + K;
			jmp_offset = func - (image + addrs[i]);
			if (ctx->seen_ld_abs) {
				EMIT2(0x41, 0x52); /* push %r10 */
				EMIT2(0x41, 0x51); /* push %r9 */
				/* need to adjust jmp offset, since
				 * pop %r9, pop %r10 take 4 bytes after call insn
				 */
				jmp_offset += 4;
			}
			if (!K || !is_simm32(jmp_offset)) {
				pr_err("unsupported bpf func %d addr %p image %p\n",
				       K, func, image);
				return -EINVAL;
			}
			EMIT1_off32(0xE8, jmp_offset);
			if (ctx->seen_ld_abs) {
				EMIT2(0x41, 0x59); /* pop %r9 */
				EMIT2(0x41, 0x5A); /* pop %r10 */
			}
			break;

			/* cond jump */
		case BPF_JMP | BPF_JEQ | BPF_X:
		case BPF_JMP | BPF_JNE | BPF_X:
		case BPF_JMP | BPF_JGT | BPF_X:
		case BPF_JMP | BPF_JGE | BPF_X:
		case BPF_JMP | BPF_JSGT | BPF_X:
		case BPF_JMP | BPF_JSGE | BPF_X:
			/* cmp a_reg, x_reg */
			EMIT3(add_2mod(0x48, a_reg, x_reg), 0x39,
			      add_2reg(0xC0, a_reg, x_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_X:
			/* test a_reg, x_reg */
			EMIT3(add_2mod(0x48, a_reg, x_reg), 0x85,
			      add_2reg(0xC0, a_reg, x_reg));
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JSET | BPF_K:
			/* test a_reg, imm32 */
			EMIT1(add_1mod(0x48, a_reg));
			EMIT2_off32(0xF7, add_1reg(0xC0, a_reg), K);
			goto emit_cond_jmp;

		case BPF_JMP | BPF_JEQ | BPF_K:
		case BPF_JMP | BPF_JNE | BPF_K:
		case BPF_JMP | BPF_JGT | BPF_K:
		case BPF_JMP | BPF_JGE | BPF_K:
		case BPF_JMP | BPF_JSGT | BPF_K:
		case BPF_JMP | BPF_JSGE | BPF_K:
			/* cmp a_reg, imm8/32 */
			EMIT1(add_1mod(0x48, a_reg));

			if (is_imm8(K))
				EMIT3(0x83, add_1reg(0xF8, a_reg), K);
			else
				EMIT2_off32(0x81, add_1reg(0xF8, a_reg), K);

emit_cond_jmp:		/* convert BPF opcode to x86 */
			switch (BPF_OP(insn->code)) {
			case BPF_JEQ:
				jmp_cond = X86_JE;
				break;
			case BPF_JSET:
			case BPF_JNE:
				jmp_cond = X86_JNE;
				break;
			case BPF_JGT:
				/* GT is unsigned '>', JA in x86 */
				jmp_cond = X86_JA;
				break;
			case BPF_JGE:
				/* GE is unsigned '>=', JAE in x86 */
				jmp_cond = X86_JAE;
				break;
			case BPF_JSGT:
				/* signed '>', GT in x86 */
				jmp_cond = X86_JG;
				break;
			case BPF_JSGE:
				/* signed '>=', GE in x86 */
				jmp_cond = X86_JGE;
				break;
			default: /* to silence gcc warning */
				return -EFAULT;
			}
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (is_imm8(jmp_offset)) {
				EMIT2(jmp_cond, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT2_off32(0x0F, jmp_cond + 0x10, jmp_offset);
			} else {
				pr_err("cond_jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}

			break;

		case BPF_JMP | BPF_JA:
			jmp_offset = addrs[i + insn->off] - addrs[i];
			if (!jmp_offset)
				/* optimize out nop jumps */
				break;
emit_jmp:
			if (is_imm8(jmp_offset)) {
				EMIT2(0xEB, jmp_offset);
			} else if (is_simm32(jmp_offset)) {
				EMIT1_off32(0xE9, jmp_offset);
			} else {
				pr_err("jmp gen bug %llx\n", jmp_offset);
				return -EFAULT;
			}
			break;

		case BPF_LD | BPF_IND | BPF_W:
			func = sk_load_word;
			goto common_load;
		case BPF_LD | BPF_ABS | BPF_W:
			func = CHOOSE_LOAD_FUNC(K, sk_load_word);
common_load:		ctx->seen_ld_abs = true;
			jmp_offset = func - (image + addrs[i]);
			if (!func || !is_simm32(jmp_offset)) {
				pr_err("unsupported bpf func %d addr %p image %p\n",
				       K, func, image);
				return -EINVAL;
			}
			if (BPF_MODE(insn->code) == BPF_ABS) {
				/* mov %esi, imm32 */
				EMIT1_off32(0xBE, K);
			} else {
				/* mov %rsi, x_reg */
				EMIT_mov(BPF_REG_2, x_reg);
				if (K) {
					if (is_imm8(K))
						/* add %esi, imm8 */
						EMIT3(0x83, 0xC6, K);
					else
						/* add %esi, imm32 */
						EMIT2_off32(0x81, 0xC6, K);
				}
			}
			/* skb pointer is in R6 (%rbx), it will be copied into
			 * %rdi if skb_copy_bits() call is necessary.
			 * sk_load_* helpers also use %r10 and %r9d.
			 * See bpf_jit.S
			 */
			EMIT1_off32(0xE8, jmp_offset); /* call */
			break;

		case BPF_LD | BPF_IND | BPF_H:
			func = sk_load_half;
			goto common_load;
		case BPF_LD | BPF_ABS | BPF_H:
			func = CHOOSE_LOAD_FUNC(K, sk_load_half);
			goto common_load;
		case BPF_LD | BPF_IND | BPF_B:
			func = sk_load_byte;
			goto common_load;
		case BPF_LD | BPF_ABS | BPF_B:
			func = CHOOSE_LOAD_FUNC(K, sk_load_byte);
			goto common_load;

		case BPF_JMP | BPF_EXIT:
			if (i != insn_cnt - 1) {
				jmp_offset = ctx->cleanup_addr - addrs[i];
				goto emit_jmp;
			}
			/* update cleanup_addr */
			ctx->cleanup_addr = proglen;
			/* mov rbx, qword ptr [rbp-X] */
			EMIT3_off32(0x48, 0x8B, 0x9D, -stacksize);
			/* mov r13, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xAD, -stacksize + 8);
			/* mov r14, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xB5, -stacksize + 16);
			/* mov r15, qword ptr [rbp-X] */
			EMIT3_off32(0x4C, 0x8B, 0xBD, -stacksize + 24);

			EMIT1(0xC9); /* leave */
			EMIT1(0xC3); /* ret */
			break;

		default:
			/* By design x64 JIT should support all BPF instructions
			 * This error will be seen if new instruction was added
			 * to interpreter, but not to JIT
			 * or if there is junk in sk_filter
			 */
			pr_err("bpf_jit: unknown opcode %02x\n", insn->code);
			return -EINVAL;
		}

		ilen = prog - temp;
		if (image) {
			if (unlikely(proglen + ilen > oldproglen)) {
				pr_err("bpf_jit_compile fatal error\n");
				return -EFAULT;
			}
			pax_open_kernel();
			memcpy(image + proglen, temp, ilen);
			pax_close_kernel();
		}
		proglen += ilen;
		addrs[i] = proglen;
		prog = temp;
	}
	return proglen;
}

void bpf_jit_compile(struct sk_filter *prog)
{
}

void bpf_int_jit_compile(struct sk_filter *prog)
{
	int proglen, oldproglen = 0;
	struct jit_context ctx = {};
	u8 *image = NULL;
	u8 *header = NULL;
	int *addrs;
	int pass;
	int i;

	if (!bpf_jit_enable)
		return;

	if (!prog || !prog->len)
		return;

	addrs = kmalloc(prog->len * sizeof(*addrs), GFP_KERNEL);
	if (!addrs)
		return;

	/* Before first pass, make a rough estimation of addrs[]
	 * each bpf instruction is translated to less than 64 bytes
	 */
	for (proglen = 0, i = 0; i < prog->len; i++) {
		proglen += 64;
		addrs[i] = proglen;
	}
	ctx.cleanup_addr = proglen;

	for (pass = 0; pass < 10 || image; pass++) {
		proglen = do_jit(prog, addrs, image, oldproglen, &ctx);
		if (proglen <= 0) {
			image = NULL;
			if (header)
				module_free(NULL, header);
			goto out;
		}
		if (image) {
			if (proglen != oldproglen)
				pr_err("bpf_jit: proglen=%d != oldproglen=%d\n",
				       proglen, oldproglen);
			break;
		}
		if (proglen == oldproglen) {
			header = bpf_alloc_binary(proglen, &image);
			if (!header)
				goto out;
		}
		oldproglen = proglen;
	}

	if (bpf_jit_enable > 1)
		bpf_jit_dump(prog->len, proglen, 0, image);

	if (image) {
		bpf_flush_icache(header, image + proglen);
		prog->bpf_func = (void *)image;
		prog->jited = 1;
	}
out:
	kfree(addrs);
}

static void bpf_jit_free_deferred(struct work_struct *work)
{
	struct sk_filter *fp = container_of(work, struct sk_filter, work);
	unsigned long addr = (unsigned long)fp->bpf_func & PAGE_MASK;

	set_memory_rw(addr, 1);
	module_free_exec(NULL, (void *)addr);
	kfree(fp);
}

/* run from softirq, we must use a work_struct to call
 * module_free_exec() from process context
 */
void bpf_jit_free(struct sk_filter *fp)
{
	if (fp->jited) {
		INIT_WORK(&fp->work, bpf_jit_free_deferred);
		schedule_work(&fp->work);
	} else {
		kfree(fp);
	}
}
