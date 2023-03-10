/* bpf_jit.S : BPF JIT helper functions
 *
 * Copyright (C) 2011 Eric Dumazet (eric.dumazet@gmail.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */
#include <linux/linkage.h>
#include <asm/dwarf2.h>
#include <asm/alternative-asm.h>

/*
 * Calling convention :
 * rbx : skb pointer (callee saved)
 * esi : offset of byte(s) to fetch in skb (can be scratched)
 * r10 : copy of skb->data
 * r9d : hlen = skb->len - skb->data_len
 */
#define SKBDATA	%r10
#define SKF_MAX_NEG_OFF    $(-0x200000) /* SKF_LL_OFF from filter.h */
#define MAX_BPF_STACK (512 /* from filter.h */ + \
	32 /* space for rbx,r13,r14,r15 */ + \
	8 /* space for skb_copy_bits */)

sk_load_word:
	.globl	sk_load_word

	test	%esi,%esi
	js	bpf_slow_path_word_neg

sk_load_word_positive_offset:
	.globl	sk_load_word_positive_offset

	mov	%r9d,%eax		# hlen
	sub	%esi,%eax		# hlen - offset
	cmp	$3,%eax
	jle	bpf_slow_path_word
	mov     (SKBDATA,%rsi),%eax
	bswap   %eax  			/* ntohl() */
	pax_force_retaddr
	ret

sk_load_half:
	.globl	sk_load_half

	test	%esi,%esi
	js	bpf_slow_path_half_neg

sk_load_half_positive_offset:
	.globl	sk_load_half_positive_offset

	mov	%r9d,%eax
	sub	%esi,%eax		#	hlen - offset
	cmp	$1,%eax
	jle	bpf_slow_path_half
	movzwl	(SKBDATA,%rsi),%eax
	rol	$8,%ax			# ntohs()
	pax_force_retaddr
	ret

sk_load_byte:
	.globl	sk_load_byte

	test	%esi,%esi
	js	bpf_slow_path_byte_neg

sk_load_byte_positive_offset:
	.globl	sk_load_byte_positive_offset

	cmp	%esi,%r9d   /* if (offset >= hlen) goto bpf_slow_path_byte */
	jle	bpf_slow_path_byte
	movzbl	(SKBDATA,%rsi),%eax
	pax_force_retaddr
	ret

/* rsi contains offset and can be scratched */
#define bpf_slow_path_common(LEN)		\
	mov	%rbx, %rdi; /* arg1 == skb */	\
	push	%r9;				\
	push	SKBDATA;			\
/* rsi already has offset */			\
	mov	$LEN,%ecx;	/* len */	\
	lea	- MAX_BPF_STACK + 32(%rbp),%rdx;			\
	call	skb_copy_bits;			\
	test    %eax,%eax;			\
	pop	SKBDATA;			\
	pop	%r9;


bpf_slow_path_word:
	bpf_slow_path_common(4)
	js	bpf_error
	mov	- MAX_BPF_STACK + 32(%rbp),%eax
	bswap	%eax
	pax_force_retaddr
	ret

bpf_slow_path_half:
	bpf_slow_path_common(2)
	js	bpf_error
	mov	- MAX_BPF_STACK + 32(%rbp),%ax
	rol	$8,%ax
	movzwl	%ax,%eax
	pax_force_retaddr
	ret

bpf_slow_path_byte:
	bpf_slow_path_common(1)
	js	bpf_error
	movzbl  - MAX_BPF_STACK + 32(%rbp),%eax
	pax_force_retaddr
	ret

#define sk_negative_common(SIZE)				\
	mov	%rbx, %rdi; /* arg1 == skb */			\
	push	%r9;						\
	push	SKBDATA;					\
/* rsi already has offset */					\
	mov	$SIZE,%edx;	/* size */			\
	call	bpf_internal_load_pointer_neg_helper;		\
	test	%rax,%rax;					\
	pop	SKBDATA;					\
	pop	%r9;						\
	jz	bpf_error

bpf_slow_path_word_neg:
	cmp	SKF_MAX_NEG_OFF, %esi	/* test range */
	jl	bpf_error	/* offset lower -> error  */
sk_load_word_negative_offset:
	.globl	sk_load_word_negative_offset
	sk_negative_common(4)
	mov	(%rax), %eax
	bswap	%eax
	pax_force_retaddr
	ret

bpf_slow_path_half_neg:
	cmp	SKF_MAX_NEG_OFF, %esi
	jl	bpf_error
sk_load_half_negative_offset:
	.globl	sk_load_half_negative_offset
	sk_negative_common(2)
	mov	(%rax),%ax
	rol	$8,%ax
	movzwl	%ax,%eax
	pax_force_retaddr
	ret

bpf_slow_path_byte_neg:
	cmp	SKF_MAX_NEG_OFF, %esi
	jl	bpf_error
sk_load_byte_negative_offset:
	.globl	sk_load_byte_negative_offset
	sk_negative_common(1)
	movzbl	(%rax), %eax
	pax_force_retaddr
	ret

bpf_error:
# force a return 0 from jit handler
	xor	%eax,%eax
	mov	- MAX_BPF_STACK(%rbp),%rbx
	mov	- MAX_BPF_STACK + 8(%rbp),%r13
	mov	- MAX_BPF_STACK + 16(%rbp),%r14
	mov	- MAX_BPF_STACK + 24(%rbp),%r15
	leaveq
	pax_force_retaddr
	ret
