/*
 * Low-level exception handling code
 *
 * Copyright (C) 2012 ARM Ltd.
 * Authors:	Catalin Marinas <catalin.marinas@arm.com>
 *		Will Deacon <will.deacon@arm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/init.h>
#include <linux/linkage.h>

#include <asm/alternative.h>
#include <asm/assembler.h>
#include <asm/asm-offsets.h>
#include <asm/cpufeature.h>
#include <asm/errno.h>
#include <asm/esr.h>
#include <asm/thread_info.h>
#include <asm/unistd.h>
#include <asm/unistd32.h>
#include <asm/ftrace.h>
#include <asm/pgtable.h>

/*
 * Bad Abort numbers
 *-----------------
 */
#define BAD_SYNC	0
#define BAD_IRQ		1
#define BAD_FIQ		2
#define BAD_ERROR	3

	.macro	kernel_entry, el, regsize = 64
	sub	sp, sp, #S_FRAME_SIZE - S_LR	// room for LR, SP, SPSR, ELR
	.if	\regsize == 32
	mov	w0, w0				// zero upper 32 bits of x0
	.endif
#ifdef CONFIG_THUNDERX_PASS1_ERRATA_22558
	str	q0, [sp, #-16]!
	tbl     v0.8b, {v1.16b}, v0.8b
	ldr	q0, [sp], #16
#endif
	push	x28, x29
	push	x26, x27
	push	x24, x25
	push	x22, x23
	push	x20, x21
	push	x18, x19
	push	x16, x17
	push	x14, x15
	push	x12, x13
	push	x10, x11
	push	x8, x9
	push	x6, x7
	push	x4, x5
	push	x2, x3
	push	x0, x1
	.if	\el == 0
	mrs	x21, sp_el0
	.else
	add	x21, sp, #S_FRAME_SIZE
	.endif
	mrs	x22, elr_el1
	mrs	x23, spsr_el1
	stp	lr, x21, [sp, #S_LR]
	stp	x22, x23, [sp, #S_PC]

	/*
	 * Set syscallno to -1 by default (overridden later if real syscall).
	 */
	.if	\el == 0
	mvn	x21, xzr
	str	x21, [sp, #S_SYSCALLNO]
	.endif

#ifdef CONFIG_MICROSTATE_ACCT
	bl	msa_kernel
	/* Restore parameters and x8 (syscall nr). */
	ldp	x0, x1, [sp, #S_X0]
	ldp	x2, x3, [sp, #S_X2]
	ldp	x4, x5, [sp, #S_X4]
	ldp	x6, x7, [sp, #S_X6]
	ldr	x8, [sp, #S_X8]
#endif
	/*
	 * Registers that may be useful after this macro is invoked:
	 *
	 * x21 - aborted SP
	 * x22 - aborted PC
	 * x23 - aborted PSTATE
	*/
	.endm

	.macro	kernel_exit, el, ret = 0
	ldp	x21, x22, [sp, #S_PC]		// load ELR, SPSR
	.if	\el == 0
	ldr	x23, [sp, #S_SP]		// load return stack pointer
	.endif
#ifdef CONFIG_THUNDERX_PASS1_ERRATA_22558
	str	q0, [sp, #-16]!
	tbl     v0.16b, {v1.16b}, v0.16b
	ldr	q0, [sp], #16
#endif
	.if	\ret
	ldr	x1, [sp, #S_X1]			// preserve x0 (syscall return)
	add	sp, sp, S_X2
	.else
	pop	x0, x1
	.endif
	pop	x2, x3				// load the rest of the registers
	pop	x4, x5
	pop	x6, x7
	pop	x8, x9
	msr	elr_el1, x21			// set up the return data
	msr	spsr_el1, x22
	.if	\el == 0
	msr	sp_el0, x23
#ifdef CONFIG_ARM64_ERRATUM_845719
	alternative_insn						\
	"nop",								\
	"tbz x22, #4, 1f",						\
	ARM64_WORKAROUND_845719
#ifdef CONFIG_PID_IN_CONTEXTIDR
	alternative_insn						\
	"nop; nop",							\
	"mrs x29, contextidr_el1; msr contextidr_el1, x29; 1:",		\
	ARM64_WORKAROUND_845719
#else
	alternative_insn						\
	"nop",								\
	"msr contextidr_el1, xzr; 1:",					\
	ARM64_WORKAROUND_845719
#endif
#endif
	.endif
	pop	x10, x11
	pop	x12, x13
	pop	x14, x15
	pop	x16, x17
	pop	x18, x19
	pop	x20, x21
	pop	x22, x23
	pop	x24, x25
	pop	x26, x27
	pop	x28, x29
	ldr	lr, [sp], #S_FRAME_SIZE - S_LR	// load LR and restore SP
	eret					// return to kernel
	.endm

	.macro	get_thread_info, rd
	mov	\rd, sp
	and	\rd, \rd, #~(THREAD_SIZE - 1)	// top of stack
	.endm

/*
 * These are the registers used in the syscall handler, and allow us to
 * have in theory up to 7 arguments to a function - x0 to x6.
 *
 * x7 is reserved for the system call number in 32-bit mode.
 */
sc_nr	.req	x25		// number of system calls
scno	.req	x26		// syscall number
stbl	.req	x27		// syscall table pointer
tsk	.req	x28		// current thread_info

/*
 * Interrupt handling.
 */
	.macro	irq_handler
	ldr	x1, handle_arch_irq
	mov	x0, sp
	blr	x1
	.endm

	.text

/*
 * Exception vectors.
 */

	.align	11
ENTRY(vectors)
	ventry	el1_sync_invalid		// Synchronous EL1t
	ventry	el1_irq_invalid			// IRQ EL1t
	ventry	el1_fiq_invalid			// FIQ EL1t
	ventry	el1_error_invalid		// Error EL1t

	ventry	el1_sync			// Synchronous EL1h
	ventry	el1_irq				// IRQ EL1h
	ventry	el1_fiq_invalid			// FIQ EL1h
#ifdef CONFIG_IGNORE_ASYNC_ABORT
	ventry	el1_ignore
#else
	ventry	el1_error_invalid		// Error EL1h
#endif

	ventry	el0_sync			// Synchronous 64-bit EL0
	ventry	el0_irq				// IRQ 64-bit EL0
	ventry	el0_fiq_invalid			// FIQ 64-bit EL0
#ifdef CONFIG_IGNORE_ASYNC_ABORT
	/* If CONFIG_IGNORE_ASYNC_ABORT is enabled, in a case of exeption,
	 * ignore it be performing eret (in el0_ignore).
	 */
	ventry	el0_ignore
#else
	ventry	el0_error_invalid		// Error 64-bit EL0
#endif

#ifdef CONFIG_AARCH32_EL0
	ventry	el0_sync_compat			// Synchronous 32-bit EL0
	ventry	el0_irq_compat			// IRQ 32-bit EL0
	ventry	el0_fiq_invalid_compat		// FIQ 32-bit EL0
	ventry	el0_error_invalid_compat	// Error 32-bit EL0
#else
	ventry	el0_sync_invalid		// Synchronous 32-bit EL0
	ventry	el0_irq_invalid			// IRQ 32-bit EL0
	ventry	el0_fiq_invalid			// FIQ 32-bit EL0
	ventry	el0_error_invalid		// Error 32-bit EL0
#endif
END(vectors)

/*
 * Invalid mode handlers
 */
	.macro	inv_entry, el, reason, regsize = 64
	kernel_entry el, \regsize
	mov	x0, sp
	mov	x1, #\reason
	mrs	x2, esr_el1
	b	bad_mode
	.endm

el0_sync_invalid:
	inv_entry 0, BAD_SYNC
ENDPROC(el0_sync_invalid)

el0_irq_invalid:
	inv_entry 0, BAD_IRQ
ENDPROC(el0_irq_invalid)

el0_fiq_invalid:
	inv_entry 0, BAD_FIQ
ENDPROC(el0_fiq_invalid)

el0_error_invalid:
	inv_entry 0, BAD_ERROR
ENDPROC(el0_error_invalid)

#ifdef CONFIG_AARCH32_EL0
el0_fiq_invalid_compat:
	inv_entry 0, BAD_FIQ, 32
ENDPROC(el0_fiq_invalid_compat)

el0_error_invalid_compat:
	inv_entry 0, BAD_ERROR, 32
ENDPROC(el0_error_invalid_compat)
#endif

el1_sync_invalid:
	inv_entry 1, BAD_SYNC
ENDPROC(el1_sync_invalid)

el1_irq_invalid:
	inv_entry 1, BAD_IRQ
ENDPROC(el1_irq_invalid)

el1_fiq_invalid:
	inv_entry 1, BAD_FIQ
ENDPROC(el1_fiq_invalid)

el1_error_invalid:
	inv_entry 1, BAD_ERROR
ENDPROC(el1_error_invalid)

#ifdef CONFIG_IGNORE_ASYNC_ABORT
el1_ignore:
	eret
ENDPROC(el1_ignore)

el0_ignore:
	eret
ENDPROC(el0_ignore)
#endif

/*
 * EL1 mode handlers.
 */
	.align	6
el1_sync:
	kernel_entry 1
	mrs	x1, esr_el1			// read the syndrome register
	lsr	x24, x1, #ESR_EL1_EC_SHIFT	// exception class
	cmp	x24, #ESR_EL1_EC_DABT_EL1	// data abort in EL1
	b.eq	el1_da
	cmp	x24, #ESR_EL1_EC_SYS64		// configurable trap
	b.eq	el1_undef
	cmp	x24, #ESR_EL1_EC_SP_ALIGN	// stack alignment exception
	b.eq	el1_sp_pc
	cmp	x24, #ESR_EL1_EC_PC_ALIGN	// pc alignment exception
	b.eq	el1_sp_pc
	cmp	x24, #ESR_EL1_EC_UNKNOWN	// unknown exception in EL1
	b.eq	el1_undef
	cmp	x24, #ESR_EL1_EC_BREAKPT_EL1	// debug exception in EL1
	b.ge	el1_dbg
	b	el1_inv
el1_da:
	/*
	 * Data abort handling
	 */
	mrs	x0, far_el1
	enable_dbg_if_not_stepping x2
	// re-enable interrupts if they were enabled in the aborted context
	tbnz	x23, #7, 1f			// PSR_I_BIT
	enable_irq
1:
	mov	x2, sp				// struct pt_regs
	bl	do_mem_abort

	// disable interrupts before pulling preserved data off the stack
	disable_irq
	kernel_exit 1
el1_sp_pc:
	/*
	 * Stack or PC alignment exception handling
	 */
	mrs	x0, far_el1
	mov	x2, sp
	b	do_sp_pc_abort
el1_undef:
	/*
	 * Undefined instruction
	 */
	mov	x0, sp
	b	do_undefinstr
el1_dbg:
	/*
	 * Debug exception handling
	 */
	cmp	x24, #ESR_EL1_EC_BRK64		// if BRK64
	cinc	x24, x24, eq			// set bit '0'
	tbz	x24, #0, el1_inv		// EL1 only
	mrs	x0, far_el1
	mov	x2, sp				// struct pt_regs
	bl	do_debug_exception

	kernel_exit 1
el1_inv:
	// TODO: add support for undefined instructions in kernel mode
	mov	x0, sp
	mov	x1, #BAD_SYNC
	mrs	x2, esr_el1
	b	bad_mode
ENDPROC(el1_sync)

	.align	6
el1_irq:
	kernel_entry 1
#ifdef CONFIG_PAX_KERNEXEC
	bl pax_enter_irq
#endif
	enable_dbg_if_not_stepping x0
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_off
#endif
#ifdef CONFIG_PREEMPT
	get_thread_info tsk
	ldr	x24, [tsk, #TI_PREEMPT]		// get preempt count
	add	x0, x24, #1			// increment it
	str	x0, [tsk, #TI_PREEMPT]
#endif
	irq_handler
#ifdef CONFIG_PREEMPT
	str	x24, [tsk, #TI_PREEMPT]		// restore preempt count
	cbnz	x24, 1f				// preempt count != 0
	ldr	x0, [tsk, #TI_FLAGS]		// get flags
	// needs rescheduling?
	mov	x2, #_TIF_NEED_RESCHED | _TIF_NEED_RESCHED_LAZY
	tst	x0, x2
	b.eq	1f
	bl	el1_preempt
1:
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_on
#endif
#ifdef CONFIG_PAX_KERNEXEC
	bl pax_exit_irq
#endif
	kernel_exit 1
ENDPROC(el1_irq)

#ifdef CONFIG_PREEMPT
el1_preempt:
	mov	x24, lr
1:	enable_dbg
	bl	preempt_schedule_irq		// irq en/disable is done inside
	ldr	x0, [tsk, #TI_FLAGS]		// get new tasks TI_FLAGS
	tbnz	x0, #TIF_NEED_RESCHED, 1b	// needs rescheduling?
	tbnz    x0, #TIF_NEED_RESCHED_LAZY, 1b
	ret	x24
#endif

/*
 * EL0 mode handlers.
 */
	.align	6
el0_sync:
	kernel_entry 0
	mrs	x25, esr_el1			// read the syndrome register
	lsr	x24, x25, #ESR_EL1_EC_SHIFT	// exception class
	cmp	x24, #ESR_EL1_EC_SVC64		// SVC in 64-bit state
	b.eq	el0_svc
	adr	lr, ret_from_exception
	cmp	x24, #ESR_EL1_EC_DABT_EL0	// data abort in EL0
	b.eq	el0_da
	cmp	x24, #ESR_EL1_EC_IABT_EL0	// instruction abort in EL0
	b.eq	el0_ia
	cmp	x24, #ESR_EL1_EC_FP_ASIMD	// FP/ASIMD access
	b.eq	el0_fpsimd_acc
	cmp	x24, #ESR_EL1_EC_FP_EXC64	// FP/ASIMD exception
	b.eq	el0_fpsimd_exc
	cmp	x24, #ESR_EL1_EC_SYS64		// configurable trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_SP_ALIGN	// stack alignment exception
	b.eq	el0_sp_pc
	cmp	x24, #ESR_EL1_EC_PC_ALIGN	// pc alignment exception
	b.eq	el0_sp_pc
	cmp	x24, #ESR_EL1_EC_UNKNOWN	// unknown exception in EL0
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_BREAKPT_EL0	// debug exception in EL0
	b.ge	el0_dbg
	b	el0_inv

#ifdef CONFIG_AARCH32_EL0
	.align	6
el0_sync_compat:
	kernel_entry 0, 32
	mrs	x25, esr_el1			// read the syndrome register
	lsr	x24, x25, #ESR_EL1_EC_SHIFT	// exception class
	cmp	x24, #ESR_EL1_EC_SVC32		// SVC in 32-bit state
	b.eq	el0_svc_compat
	adr	lr, ret_from_exception
	cmp	x24, #ESR_EL1_EC_DABT_EL0	// data abort in EL0
	b.eq	el0_da
	cmp	x24, #ESR_EL1_EC_IABT_EL0	// instruction abort in EL0
	b.eq	el0_ia
	cmp	x24, #ESR_EL1_EC_FP_ASIMD	// FP/ASIMD access
	b.eq	el0_fpsimd_acc
	cmp	x24, #ESR_EL1_EC_FP_EXC32	// FP/ASIMD exception
	b.eq	el0_fpsimd_exc
	cmp	x24, #ESR_EL1_EC_UNKNOWN	// unknown exception in EL0
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_CP15_32	// CP15 MRC/MCR trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_CP15_64	// CP15 MRRC/MCRR trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_CP14_MR	// CP14 MRC/MCR trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_CP14_LS	// CP14 LDC/STC trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_CP14_64	// CP14 MRRC/MCRR trap
	b.eq	el0_undef
	cmp	x24, #ESR_EL1_EC_BREAKPT_EL0	// debug exception in EL0
	b.ge	el0_dbg
	b	el0_inv
el0_svc_compat:
	/*
	 * AArch32 syscall handling
	 */
	adr	stbl, compat_sys_call_table	// load compat syscall table pointer
	uxtw	scno, w7			// syscall number in w7 (r7)
	mov     sc_nr, #__NR_compat_syscalls
	b	el0_svc_naked

	.align	6
el0_irq_compat:
	kernel_entry 0, 32
	b	el0_irq_naked
#endif

el0_da:
	/*
	 * Data abort handling
	 */
	mrs	x0, far_el1
	bic     x0, x0, #(0xff << 56)
	disable_step x1
	isb
	enable_dbg
	// enable interrupts before calling the main handler
	enable_irq
	mov	x1, x25
	mov	x2, sp
	b	do_mem_abort
el0_ia:
	/*
	 * Instruction abort handling
	 */
	mrs	x0, far_el1
	disable_step x1
	isb
	enable_dbg
	// enable interrupts before calling the main handler
	enable_irq
	orr	x1, x25, #1 << 24		// use reserved ISS bit for instruction aborts
	mov	x2, sp
	b	do_mem_abort
el0_fpsimd_acc:
	/*
	 * Floating Point or Advanced SIMD access
	 */
	mov	x0, x25
	mov	x1, sp
	b	do_fpsimd_acc
el0_fpsimd_exc:
	/*
	 * Floating Point or Advanced SIMD exception
	 */
	mov	x0, x25
	mov	x1, sp
	b	do_fpsimd_exc
el0_sp_pc:
	/*
	 * Stack or PC alignment exception handling
	 */
	mrs	x0, far_el1
	disable_step x1
	isb
	enable_dbg
	// enable interrupts before calling the main handler
	enable_irq
	mov	x1, x25
	mov	x2, sp
	b	do_sp_pc_abort
el0_undef:
	/*
	 * Undefined instruction
	 */
	mov	x0, sp
	b	do_undefinstr
el0_dbg:
	/*
	 * Debug exception handling
	 */
	tbnz	x24, #0, el0_inv		// EL0 only
	mrs	x0, far_el1
	disable_step x1
	mov	x1, x25
	mov	x2, sp
	b	do_debug_exception
el0_inv:
	mov	x0, sp
	mov	x1, #BAD_SYNC
	mrs	x2, esr_el1
	b	bad_el0_sync
ENDPROC(el0_sync)

	.align	6
el0_irq:
	kernel_entry 0
el0_irq_naked:
	disable_step x1
	isb
	enable_dbg
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_off
#endif
	get_thread_info tsk
#ifdef CONFIG_PREEMPT
	ldr	x24, [tsk, #TI_PREEMPT]		// get preempt count
	add	x23, x24, #1			// increment it
	str	x23, [tsk, #TI_PREEMPT]
#endif
	irq_handler
#ifdef CONFIG_PREEMPT
	ldr	x0, [tsk, #TI_PREEMPT]
	str	x24, [tsk, #TI_PREEMPT]
	cmp	x0, x23
	b.eq	1f
	mov	x1, #0
	str	x1, [x1]			// BUG
1:
#endif
#ifdef CONFIG_TRACE_IRQFLAGS
	bl	trace_hardirqs_on
#endif
	b	ret_to_user
ENDPROC(el0_irq)

/*
 * This is the return code to user mode for abort handlers
 */
ret_from_exception:
	get_thread_info tsk
	b	ret_to_user
ENDPROC(ret_from_exception)

/*
 * Register switch for AArch64. The callee-saved registers need to be saved
 * and restored. On entry:
 *   x0 = previous task_struct (must be preserved across the switch)
 *   x1 = next task_struct
 * Previous and next are guaranteed not to be the same.
 *
 */
ENTRY(cpu_switch_to)
	add	x8, x0, #THREAD_CPU_CONTEXT
	mov	x9, sp
	stp	x19, x20, [x8], #16		// store callee-saved registers
	stp	x21, x22, [x8], #16
	stp	x23, x24, [x8], #16
	stp	x25, x26, [x8], #16
	stp	x27, x28, [x8], #16
	stp	x29, x9, [x8], #16
	str	lr, [x8]
	add	x8, x1, #THREAD_CPU_CONTEXT
	ldp	x19, x20, [x8], #16		// restore callee-saved registers
	ldp	x21, x22, [x8], #16
	ldp	x23, x24, [x8], #16
	ldp	x25, x26, [x8], #16
	ldp	x27, x28, [x8], #16
	ldp	x29, x9, [x8], #16
	ldr	lr, [x8]
	mov	sp, x9
	ret
ENDPROC(cpu_switch_to)

/*
 * This is the fast syscall return path.  We do as little as possible here,
 * and this includes saving x0 back into the kernel stack.
 */
ret_fast_syscall:
	disable_irq				// disable interrupts
	ldr	x1, [tsk, #TI_FLAGS]
	and	x2, x1, #_TIF_WORK_MASK
	cbnz	x2, fast_work_pending
	tbz	x1, #TIF_SINGLESTEP, fast_exit
	disable_dbg
	enable_step x2
fast_exit:
	kernel_exit 0, ret = 1

/*
 * Ok, we need to do extra processing, enter the slow path.
 */
fast_work_pending:
	str	x0, [sp, #S_X0]			// returned x0
work_pending:
	tbnz	x1, #TIF_NEED_RESCHED, work_resched
	tbnz	x1, #TIF_NEED_RESCHED_LAZY, work_resched
	/* TIF_SIGPENDING or TIF_NOTIFY_RESUME case */
	ldr	x2, [sp, #S_PSTATE]
	mov	x0, sp				// 'regs'
	tst	x2, #PSR_MODE_MASK		// user mode regs?
	b.ne	no_work_pending			// returning to kernel
	enable_irq				// enable interrupts for do_notify_resume()
	bl	do_notify_resume
	b	ret_to_user
work_resched:
	enable_dbg
	bl	schedule

/*
 * "slow" syscall return path.
 */
ret_to_user:
	disable_irq				// disable interrupts
	ldr	x1, [tsk, #TI_FLAGS]
	and	x2, x1, #_TIF_WORK_MASK
	cbnz	x2, work_pending
	tbz	x1, #TIF_SINGLESTEP, no_work_pending
	disable_dbg
	enable_step x2
no_work_pending:
#ifdef CONFIG_MICROSTATE_ACCT
	bl	msa_user
#endif
	kernel_exit 0, ret = 0
ENDPROC(ret_to_user)

/*
 * This is how we return from a fork.
 */
ENTRY(ret_from_fork)
	bl	schedule_tail
	cbz	x19, 1f				// not a kernel thread
	mov	x0, x20
	blr	x19
1:	get_thread_info tsk
	b	ret_to_user
ENDPROC(ret_from_fork)

/*
 * SVC handler.
 */
	.align	6
el0_svc:
	uxtw	scno, w8			// syscall number in w8
	mov	sc_nr, #__NR_syscalls
#ifdef CONFIG_ARM64_ILP32
	get_thread_info tsk
	ldr	x16, [tsk, #TI_FLAGS]
	tbnz	x16, #TIF_32BIT, el0_ilp32_svc	// We are using ILP32
#endif
	adrp	stbl, sys_call_table		// load syscall table pointer
el0_svc_naked:					// compat entry point
	stp	x0, scno, [sp, #S_ORIG_X0]	// save the original x0 and syscall number
	disable_step x16
	isb
	enable_dbg
	enable_irq

	get_thread_info tsk
	ldr	x16, [tsk, #TI_FLAGS]		// check for syscall tracing
	tbnz	x16, #TIF_SYSCALL_TRACE, __sys_trace // are we tracing syscalls?
	adr	lr, ret_fast_syscall		// return address
	cmp     scno, sc_nr                     // check upper syscall limit
	b.hs	ni_sys
	ldr	x16, [stbl, scno, lsl #3]	// address in the syscall table
	br	x16				// call sys_* routine
ni_sys:
	mov	x0, sp
	b	do_ni_syscall
ENDPROC(el0_svc)

#ifdef CONFIG_ARM64_ILP32
el0_ilp32_svc:
	adrp	stbl, sys_call_ilp32_table // load syscall table pointer
	b el0_svc_naked
#endif

	/*
	 * This is the really slow path.  We're going to be doing context
	 * switches, and waiting for our parent to respond.
	 */
__sys_trace:
	mov	x1, sp
	mov	w0, #0				// trace entry
	bl	syscall_trace
	adr	lr, __sys_trace_return		// return address
	uxtw	scno, w0			// syscall number (possibly new)
	mov	x1, sp				// pointer to regs
	cmp	scno, sc_nr			// check upper syscall limit
	b.hs	ni_sys
	ldp	x0, x1, [sp]			// restore the syscall args
	ldp	x2, x3, [sp, #S_X2]
	ldp	x4, x5, [sp, #S_X4]
	ldp	x6, x7, [sp, #S_X6]
	ldr	x16, [stbl, scno, lsl #3]	// address in the syscall table
	br	x16				// call sys_* routine

__sys_trace_return:
	str	x0, [sp]			// save returned x0
	mov	x1, sp
	mov	w0, #1				// trace exit
	bl	syscall_trace
	b	ret_to_user

/*
 * Special system call wrappers.
 */
ENTRY(sys_rt_sigreturn_wrapper)
	mov	x0, sp
	b	sys_rt_sigreturn
ENDPROC(sys_rt_sigreturn_wrapper)

ENTRY(handle_arch_irq)
	.quad	0


#ifdef CONFIG_FUNCTION_TRACER
/*
 * When compiling with -pg, gcc inserts a call to the mcount routine at the
 * start of every function.  In _mcount, apart from the function's address (in
 * lr), we need to get hold of the function's caller's address.
 *
 * Make sure, your GNU compiler inserts the _mcount and x30(lr) stored beneath
 * the stack frame when compiled with -pg option as below,
 *
 *      ## echo 'main(){}' | ./aarch64-linux-gnu-gcc -x c -S -o - - -pg
 *		.cpu thunder+fp+simd+crypto+crc
 *		.file   ""
 *		.global _mcount
 *		.text
 *		.align  2
 *		.global main
 *		.type   main, %function
 *	main:
 *		stp     x29, x30, [sp, -16]!
 *		add     x29, sp, 0
 *		mov     x0, x30
 *		bl      _mcount
 *		ldp     x29, x30, [sp], 16
 *		ret
 *		.size   main, .-main
 *
 *
 *	Stack content after mcount_enter
 *
 *	  |------------------| x29 + 16
 *	  |                  |
 *	  |       x30        | <= lr of instrumented func
 *	  |                  |
 *	  |------------------| x29 + 8
 *	  |                  |
 *	  |       x29        | <= sp of instrumented func
 *	  |                  |
 *	  |------------------| x29 + 0  <= frame pointer/stack base address.
 *	  |                  |
 *	  |       x3         | <= used as temporary register
 *	  |                  |
 *	  |------------------| x29 - 8
 *	  |                  |
 *	  |       x2         | <= used as temporary register
 *	  |                  |
 *	  |------------------| x29 - 16
 *	  |                  |
 *	  |       x1         | <=  used as temporary register
 *	  |                  |
 *	  |------------------| x29 - 24
 *	  |                  |
 *	  |       x0         | <= used as temporary register
 *	  |                  |
 *	  |------------------| x29 - 32
 *	  |                  |
 *	  |       x30        | <=  lr of _mcount/__ftrace_caller
 *	  |                  |
 *	  |------------------| x29 - 40
 *	  |                  |
 *	  |       x29        | <= stack frame address.
 *	  |                  |
 *	  |------------------| x29 - 48
 *
 */

.macro mcount_adjust_addr xd, xn
	sub	\xd, \xn, #MCOUNT_INSN_SIZE
.endm

.macro mcount_enter
	push	x2, x3
	push	x0, x1
	push 	x29, x30
.endm

.macro mcount_exit
	pop 	x29,x30
	pop	x0, x1
	pop	x2, x3
	ret
.endm

.macro __mcount
	mcount_enter
	ldr	x0, =ftrace_trace_function
	ldr	x2, [x0]
	adr	x0, .Lftrace_stub
	cmp	x0, x2
	bne	1f

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	ldr     x1, =ftrace_graph_return
	ldr     x2, [x1]
	cmp     x0, x2
	bne     ftrace_graph_caller

	ldr     x1, =ftrace_graph_entry
	ldr     x2, [x1]
	ldr     x0, =ftrace_graph_entry_stub
	cmp     x0, x2
	bne     ftrace_graph_caller
#endif
	mcount_exit

1: 	ldr	x1, [x29, #8]           /* lr of instrumented func */
	mcount_adjust_addr x0, lr	/* lr of _mcount */
	blr x2
	mcount_exit
.endm

.macro __ftrace_caller
	mcount_enter
	ldr	x1, [x29, #8]          /* lr of instrumented func */
#ifdef CONFIG_DYNAMIC_FTRACE
	/* lr of _mcount, called from __ftrace_caller, saved in mcount_enter */
	ldr	x0, [x29, #-40]
	mcount_adjust_addr	x0, x0
#else
	/* lr of _moucnt, called from __mcount, untouched lr */
	mcount_adjust_addr x0, lr
#endif
	.globl ftrace_call
ftrace_call:
	nop
#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	.globl ftrace_graph_call
ftrace_graph_call:
	nop
#endif
	mcount_exit
.endm

.macro __ftrace_graph_caller
	/* &lr of instrumented routine (&parent) */
	add	x0, x29, #8
#ifdef CONFIG_DYNAMIC_FTRACE
	/* lr of _mcount, called from __ftrace_caller, saved in mcount_enter */
	ldr	x1, [x29, #-40]
	mcount_adjust_addr	x1, x1
#else
	/* lr of _moucnt, called from __mcount, untouched lr */
	mcount_adjust_addr x1, lr
#endif
 	ldr	x2, [x29]               /* frame pointer*/
	bl	prepare_ftrace_return
	mcount_exit
.endm

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
	.globl return_to_handler
return_to_handler:
	str	x0, [sp, #-16]!
	mov     x0, x29			   /* frame pointer */
	bl	ftrace_return_to_handler
	mov 	lr, x0
	ldr	x0, [sp], #16
	ret
#endif

ENTRY(_mcount)
#ifdef CONFIG_DYNAMIC_FTRACE
	ret
#else
	__mcount
#endif
ENDPROC(_mcount)

#ifdef CONFIG_DYNAMIC_FTRACE
ENTRY(ftrace_caller)
	__ftrace_caller
ENDPROC(ftrace_caller)
#endif

#ifdef CONFIG_FUNCTION_GRAPH_TRACER
ENTRY(ftrace_graph_caller)
	__ftrace_graph_caller
ENDPROC(ftrace_graph_caller)
#endif

ENTRY(ftrace_stub)
.Lftrace_stub:
	ret
ENDPROC(ftrace_stub)

.purgem mcount_enter
.purgem mcount_exit
#endif /* CONFIG_FUNCTION_TRACER */
