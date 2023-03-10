/*
 * offset.c: Calculate pt_regs and task_struct offsets.
 *
 * Copyright (C) 1996 David S. Miller
 * Copyright (C) 1997, 1998, 1999, 2000, 2001, 2002, 2003 Ralf Baechle
 * Copyright (C) 1999, 2000 Silicon Graphics, Inc.
 *
 * Kevin Kissell, kevink@mips.com and Carsten Langgaard, carstenl@mips.com
 * Copyright (C) 2000 MIPS Technologies, Inc.
 */
#include <linux/compat.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/kbuild.h>
#include <linux/suspend.h>
#include <asm/ptrace.h>
#include <asm/processor.h>

#include <linux/kvm_host.h>
#include <asm/kvm_mips_te.h>
#include <asm/kvm_mips_vz.h>

void output_ptreg_defines(void)
{
	COMMENT("MIPS pt_regs offsets.");
	OFFSET(PT_R0, pt_regs, regs[0]);
	OFFSET(PT_R1, pt_regs, regs[1]);
	OFFSET(PT_R2, pt_regs, regs[2]);
	OFFSET(PT_R3, pt_regs, regs[3]);
	OFFSET(PT_R4, pt_regs, regs[4]);
	OFFSET(PT_R5, pt_regs, regs[5]);
	OFFSET(PT_R6, pt_regs, regs[6]);
	OFFSET(PT_R7, pt_regs, regs[7]);
	OFFSET(PT_R8, pt_regs, regs[8]);
	OFFSET(PT_R9, pt_regs, regs[9]);
	OFFSET(PT_R10, pt_regs, regs[10]);
	OFFSET(PT_R11, pt_regs, regs[11]);
	OFFSET(PT_R12, pt_regs, regs[12]);
	OFFSET(PT_R13, pt_regs, regs[13]);
	OFFSET(PT_R14, pt_regs, regs[14]);
	OFFSET(PT_R15, pt_regs, regs[15]);
	OFFSET(PT_R16, pt_regs, regs[16]);
	OFFSET(PT_R17, pt_regs, regs[17]);
	OFFSET(PT_R18, pt_regs, regs[18]);
	OFFSET(PT_R19, pt_regs, regs[19]);
	OFFSET(PT_R20, pt_regs, regs[20]);
	OFFSET(PT_R21, pt_regs, regs[21]);
	OFFSET(PT_R22, pt_regs, regs[22]);
	OFFSET(PT_R23, pt_regs, regs[23]);
	OFFSET(PT_R24, pt_regs, regs[24]);
	OFFSET(PT_R25, pt_regs, regs[25]);
	OFFSET(PT_R26, pt_regs, regs[26]);
	OFFSET(PT_R27, pt_regs, regs[27]);
	OFFSET(PT_R28, pt_regs, regs[28]);
	OFFSET(PT_R29, pt_regs, regs[29]);
	OFFSET(PT_R30, pt_regs, regs[30]);
	OFFSET(PT_R31, pt_regs, regs[31]);
	OFFSET(PT_LO, pt_regs, lo);
	OFFSET(PT_HI, pt_regs, hi);
#ifdef CONFIG_CPU_HAS_SMARTMIPS
	OFFSET(PT_ACX, pt_regs, acx);
#endif
	OFFSET(PT_EPC, pt_regs, cp0_epc);
	OFFSET(PT_BVADDR, pt_regs, cp0_badvaddr);
	OFFSET(PT_STATUS, pt_regs, cp0_status);
	OFFSET(PT_CAUSE, pt_regs, cp0_cause);
#ifdef CONFIG_MIPS_MT_SMTC
	OFFSET(PT_TCSTATUS, pt_regs, cp0_tcstatus);
#endif /* CONFIG_MIPS_MT_SMTC */
#ifdef CONFIG_CPU_CAVIUM_OCTEON
	OFFSET(PT_MPL, pt_regs, mpl);
	OFFSET(PT_MTP, pt_regs, mtp);
#endif /* CONFIG_CPU_CAVIUM_OCTEON */
	DEFINE(PT_SIZE, sizeof(struct pt_regs));
	BLANK();
}

void output_task_defines(void)
{
	COMMENT("MIPS task_struct offsets.");
	OFFSET(TASK_STATE, task_struct, state);
	OFFSET(TASK_THREAD_INFO, task_struct, stack);
	OFFSET(TASK_FLAGS, task_struct, flags);
	OFFSET(TASK_MM, task_struct, mm);
	OFFSET(TASK_PID, task_struct, pid);
	DEFINE(TASK_STRUCT_SIZE, sizeof(struct task_struct));
	BLANK();
}

void output_thread_info_defines(void)
{
	COMMENT("MIPS thread_info offsets.");
	OFFSET(TI_TASK, thread_info, task);
	OFFSET(TI_EXEC_DOMAIN, thread_info, exec_domain);
	OFFSET(TI_FLAGS, thread_info, flags);
	OFFSET(TI_TP_VALUE, thread_info, tp_value);
	OFFSET(TI_CPU, thread_info, cpu);
	OFFSET(TI_PRE_COUNT, thread_info, preempt_count);
	OFFSET(TI_ADDR_LIMIT, thread_info, addr_limit);
	OFFSET(TI_RESTART_BLOCK, thread_info, restart_block);
	OFFSET(TI_REGS, thread_info, regs);
	DEFINE(_THREAD_SIZE, THREAD_SIZE);
	DEFINE(_THREAD_MASK, THREAD_MASK);
	BLANK();
}

void output_thread_defines(void)
{
	COMMENT("MIPS specific thread_struct offsets.");
	OFFSET(THREAD_REG16, task_struct, thread.reg16);
	OFFSET(THREAD_REG17, task_struct, thread.reg17);
	OFFSET(THREAD_REG18, task_struct, thread.reg18);
	OFFSET(THREAD_REG19, task_struct, thread.reg19);
	OFFSET(THREAD_REG20, task_struct, thread.reg20);
	OFFSET(THREAD_REG21, task_struct, thread.reg21);
	OFFSET(THREAD_REG22, task_struct, thread.reg22);
	OFFSET(THREAD_REG23, task_struct, thread.reg23);
	OFFSET(THREAD_REG29, task_struct, thread.reg29);
	OFFSET(THREAD_REG30, task_struct, thread.reg30);
	OFFSET(THREAD_REG31, task_struct, thread.reg31);
	OFFSET(THREAD_STATUS, task_struct,
	       thread.cp0_status);
	OFFSET(THREAD_FPU, task_struct, thread.fpu);

	OFFSET(THREAD_BVADDR, task_struct, \
	       thread.cp0_badvaddr);
	OFFSET(THREAD_BUADDR, task_struct, \
	       thread.cp0_baduaddr);
	OFFSET(THREAD_ECODE, task_struct, \
	       thread.error_code);
	BLANK();
}

void output_thread_fpu_defines(void)
{
	OFFSET(THREAD_FPR0, task_struct, thread.fpu.fpr[0]);
	OFFSET(THREAD_FPR1, task_struct, thread.fpu.fpr[1]);
	OFFSET(THREAD_FPR2, task_struct, thread.fpu.fpr[2]);
	OFFSET(THREAD_FPR3, task_struct, thread.fpu.fpr[3]);
	OFFSET(THREAD_FPR4, task_struct, thread.fpu.fpr[4]);
	OFFSET(THREAD_FPR5, task_struct, thread.fpu.fpr[5]);
	OFFSET(THREAD_FPR6, task_struct, thread.fpu.fpr[6]);
	OFFSET(THREAD_FPR7, task_struct, thread.fpu.fpr[7]);
	OFFSET(THREAD_FPR8, task_struct, thread.fpu.fpr[8]);
	OFFSET(THREAD_FPR9, task_struct, thread.fpu.fpr[9]);
	OFFSET(THREAD_FPR10, task_struct, thread.fpu.fpr[10]);
	OFFSET(THREAD_FPR11, task_struct, thread.fpu.fpr[11]);
	OFFSET(THREAD_FPR12, task_struct, thread.fpu.fpr[12]);
	OFFSET(THREAD_FPR13, task_struct, thread.fpu.fpr[13]);
	OFFSET(THREAD_FPR14, task_struct, thread.fpu.fpr[14]);
	OFFSET(THREAD_FPR15, task_struct, thread.fpu.fpr[15]);
	OFFSET(THREAD_FPR16, task_struct, thread.fpu.fpr[16]);
	OFFSET(THREAD_FPR17, task_struct, thread.fpu.fpr[17]);
	OFFSET(THREAD_FPR18, task_struct, thread.fpu.fpr[18]);
	OFFSET(THREAD_FPR19, task_struct, thread.fpu.fpr[19]);
	OFFSET(THREAD_FPR20, task_struct, thread.fpu.fpr[20]);
	OFFSET(THREAD_FPR21, task_struct, thread.fpu.fpr[21]);
	OFFSET(THREAD_FPR22, task_struct, thread.fpu.fpr[22]);
	OFFSET(THREAD_FPR23, task_struct, thread.fpu.fpr[23]);
	OFFSET(THREAD_FPR24, task_struct, thread.fpu.fpr[24]);
	OFFSET(THREAD_FPR25, task_struct, thread.fpu.fpr[25]);
	OFFSET(THREAD_FPR26, task_struct, thread.fpu.fpr[26]);
	OFFSET(THREAD_FPR27, task_struct, thread.fpu.fpr[27]);
	OFFSET(THREAD_FPR28, task_struct, thread.fpu.fpr[28]);
	OFFSET(THREAD_FPR29, task_struct, thread.fpu.fpr[29]);
	OFFSET(THREAD_FPR30, task_struct, thread.fpu.fpr[30]);
	OFFSET(THREAD_FPR31, task_struct, thread.fpu.fpr[31]);

	OFFSET(THREAD_FCR31, task_struct, thread.fpu.fcr31);
	BLANK();
}

void output_mm_defines(void)
{
	COMMENT("Size of struct page");
	DEFINE(STRUCT_PAGE_SIZE, sizeof(struct page));
	BLANK();
	COMMENT("Linux mm_struct offsets.");
	OFFSET(MM_USERS, mm_struct, mm_users);
	OFFSET(MM_PGD, mm_struct, pgd);
	OFFSET(MM_CONTEXT, mm_struct, context);
	BLANK();
	DEFINE(_PGD_T_SIZE, sizeof(pgd_t));
	DEFINE(_PUD_T_SIZE, sizeof(pud_t));
	DEFINE(_PMD_T_SIZE, sizeof(pmd_t));
	DEFINE(_PTE_T_SIZE, sizeof(pte_t));
	BLANK();
	DEFINE(_PGD_T_LOG2, PGD_T_LOG2);
#ifndef __PAGETABLE_PUD_FOLDED
	DEFINE(_PUD_T_LOG2, PUD_T_LOG2);
#endif
#ifndef __PAGETABLE_PMD_FOLDED
	DEFINE(_PMD_T_LOG2, PMD_T_LOG2);
#endif
	DEFINE(_PTE_T_LOG2, PTE_T_LOG2);
	BLANK();
	DEFINE(_PGD_ORDER, PGD_ORDER);
#ifndef __PAGETABLE_PUD_FOLDED
	DEFINE(_PUD_ORDER, PUD_ORDER);
#endif
#ifndef __PAGETABLE_PMD_FOLDED
	DEFINE(_PMD_ORDER, PMD_ORDER);
#endif
	DEFINE(_PTE_ORDER, PTE_ORDER);
	BLANK();
	DEFINE(_PMD_SHIFT, PMD_SHIFT);
	DEFINE(_PUD_SHIFT, PUD_SHIFT);
	DEFINE(_PGDIR_SHIFT, PGDIR_SHIFT);
	BLANK();
	DEFINE(_PTRS_PER_PGD, PTRS_PER_PGD);
	DEFINE(_PTRS_PER_PMD, PTRS_PER_PMD);
	DEFINE(_PTRS_PER_PUD, PTRS_PER_PUD);
	DEFINE(_PTRS_PER_PTE, PTRS_PER_PTE);
	BLANK();
	DEFINE(_PAGE_SHIFT, PAGE_SHIFT);
	DEFINE(_PAGE_SIZE, PAGE_SIZE);
	BLANK();
}

#ifdef CONFIG_32BIT
void output_sc_defines(void)
{
	COMMENT("Linux sigcontext offsets.");
	OFFSET(SC_REGS, sigcontext, sc_regs);
	OFFSET(SC_FPREGS, sigcontext, sc_fpregs);
	OFFSET(SC_ACX, sigcontext, sc_acx);
	OFFSET(SC_MDHI, sigcontext, sc_mdhi);
	OFFSET(SC_MDLO, sigcontext, sc_mdlo);
	OFFSET(SC_PC, sigcontext, sc_pc);
	OFFSET(SC_FPC_CSR, sigcontext, sc_fpc_csr);
	OFFSET(SC_FPC_EIR, sigcontext, sc_fpc_eir);
	OFFSET(SC_HI1, sigcontext, sc_hi1);
	OFFSET(SC_LO1, sigcontext, sc_lo1);
	OFFSET(SC_HI2, sigcontext, sc_hi2);
	OFFSET(SC_LO2, sigcontext, sc_lo2);
	OFFSET(SC_HI3, sigcontext, sc_hi3);
	OFFSET(SC_LO3, sigcontext, sc_lo3);
	BLANK();
}
#endif

#ifdef CONFIG_64BIT
void output_sc_defines(void)
{
	COMMENT("Linux sigcontext offsets.");
	OFFSET(SC_REGS, sigcontext, sc_regs);
	OFFSET(SC_FPREGS, sigcontext, sc_fpregs);
	OFFSET(SC_MDHI, sigcontext, sc_mdhi);
	OFFSET(SC_MDLO, sigcontext, sc_mdlo);
	OFFSET(SC_PC, sigcontext, sc_pc);
	OFFSET(SC_FPC_CSR, sigcontext, sc_fpc_csr);
	BLANK();
}
#endif

#ifdef CONFIG_MIPS32_COMPAT
void output_sc32_defines(void)
{
	COMMENT("Linux 32-bit sigcontext offsets.");
	OFFSET(SC32_FPREGS, sigcontext32, sc_fpregs);
	OFFSET(SC32_FPC_CSR, sigcontext32, sc_fpc_csr);
	OFFSET(SC32_FPC_EIR, sigcontext32, sc_fpc_eir);
	BLANK();
}
#endif

void output_signal_defined(void)
{
	COMMENT("Linux signal numbers.");
	DEFINE(_SIGHUP, SIGHUP);
	DEFINE(_SIGINT, SIGINT);
	DEFINE(_SIGQUIT, SIGQUIT);
	DEFINE(_SIGILL, SIGILL);
	DEFINE(_SIGTRAP, SIGTRAP);
	DEFINE(_SIGIOT, SIGIOT);
	DEFINE(_SIGABRT, SIGABRT);
	DEFINE(_SIGEMT, SIGEMT);
	DEFINE(_SIGFPE, SIGFPE);
	DEFINE(_SIGKILL, SIGKILL);
	DEFINE(_SIGBUS, SIGBUS);
	DEFINE(_SIGSEGV, SIGSEGV);
	DEFINE(_SIGSYS, SIGSYS);
	DEFINE(_SIGPIPE, SIGPIPE);
	DEFINE(_SIGALRM, SIGALRM);
	DEFINE(_SIGTERM, SIGTERM);
	DEFINE(_SIGUSR1, SIGUSR1);
	DEFINE(_SIGUSR2, SIGUSR2);
	DEFINE(_SIGCHLD, SIGCHLD);
	DEFINE(_SIGPWR, SIGPWR);
	DEFINE(_SIGWINCH, SIGWINCH);
	DEFINE(_SIGURG, SIGURG);
	DEFINE(_SIGIO, SIGIO);
	DEFINE(_SIGSTOP, SIGSTOP);
	DEFINE(_SIGTSTP, SIGTSTP);
	DEFINE(_SIGCONT, SIGCONT);
	DEFINE(_SIGTTIN, SIGTTIN);
	DEFINE(_SIGTTOU, SIGTTOU);
	DEFINE(_SIGVTALRM, SIGVTALRM);
	DEFINE(_SIGPROF, SIGPROF);
	DEFINE(_SIGXCPU, SIGXCPU);
	DEFINE(_SIGXFSZ, SIGXFSZ);
	BLANK();
}

#ifdef CONFIG_CPU_CAVIUM_OCTEON
void output_octeon_cop2_state_defines(void)
{
	COMMENT("Octeon specific octeon_cop2_state offsets.");
	OFFSET(OCTEON_CP2_CRC_IV,	octeon_cop2_state, cop2_crc_iv);
	OFFSET(OCTEON_CP2_CRC_LENGTH,	octeon_cop2_state, cop2_crc_length);
	OFFSET(OCTEON_CP2_CRC_POLY,	octeon_cop2_state, cop2_crc_poly);
	OFFSET(OCTEON_CP2_LLM_DAT,	octeon_cop2_state, cop2_llm_dat);
	OFFSET(OCTEON_CP2_3DES_IV,	octeon_cop2_state, cop2_3des_iv);
	OFFSET(OCTEON_CP2_3DES_KEY,	octeon_cop2_state, cop2_3des_key);
	OFFSET(OCTEON_CP2_3DES_RESULT,	octeon_cop2_state, cop2_3des_result);
	OFFSET(OCTEON_CP2_AES_INP0,	octeon_cop2_state, cop2_aes_inp0);
	OFFSET(OCTEON_CP2_AES_IV,	octeon_cop2_state, cop2_aes_iv);
	OFFSET(OCTEON_CP2_AES_KEY,	octeon_cop2_state, cop2_aes_key);
	OFFSET(OCTEON_CP2_AES_KEYLEN,	octeon_cop2_state, cop2_aes_keylen);
	OFFSET(OCTEON_CP2_AES_RESULT,	octeon_cop2_state, cop2_aes_result);
	OFFSET(OCTEON_CP2_GFM_MULT,	octeon_cop2_state, cop2_gfm_mult);
	OFFSET(OCTEON_CP2_GFM_POLY,	octeon_cop2_state, cop2_gfm_poly);
	OFFSET(OCTEON_CP2_GFM_RESULT,	octeon_cop2_state, cop2_gfm_result);
	OFFSET(OCTEON_CP2_HSH_DATW,	octeon_cop2_state, cop2_hsh_datw);
	OFFSET(OCTEON_CP2_HSH_IVW,	octeon_cop2_state, cop2_hsh_ivw);
	OFFSET(OCTEON_CP2_SHA3,		octeon_cop2_state, cop2_sha3);
	OFFSET(THREAD_CP2,	task_struct, thread.cp2);
	OFFSET(THREAD_CVMSEG,	task_struct, thread.cvmseg.cvmseg);
	BLANK();
}
#endif

#ifdef CONFIG_HIBERNATION
void output_pbe_defines(void)
{
	COMMENT(" Linux struct pbe offsets. ");
	OFFSET(PBE_ADDRESS, pbe, address);
	OFFSET(PBE_ORIG_ADDRESS, pbe, orig_address);
	OFFSET(PBE_NEXT, pbe, next);
	DEFINE(PBE_SIZE, sizeof(struct pbe));
	BLANK();
}
#endif

#if IS_ENABLED(CONFIG_KVM)
void output_kvm_defines(void)
{
	COMMENT(" KVM/MIPS Specfic offsets. ");
	OFFSET(KVM_ARCH_IMPL, kvm, arch.impl);
	OFFSET(KVM_VCPU_KVM, kvm_vcpu, kvm);
	DEFINE(VCPU_ARCH_SIZE, sizeof(struct kvm_vcpu_arch));
	OFFSET(VCPU_RUN, kvm_vcpu, run);
	OFFSET(VCPU_HOST_ARCH, kvm_vcpu, arch);


	OFFSET(KVM_VCPU_ARCH_R0, kvm_vcpu, arch.gprs[0]);
	OFFSET(KVM_VCPU_ARCH_R1, kvm_vcpu, arch.gprs[1]);
	OFFSET(KVM_VCPU_ARCH_R2, kvm_vcpu, arch.gprs[2]);
	OFFSET(KVM_VCPU_ARCH_R3, kvm_vcpu, arch.gprs[3]);
	OFFSET(KVM_VCPU_ARCH_R4, kvm_vcpu, arch.gprs[4]);
	OFFSET(KVM_VCPU_ARCH_R5, kvm_vcpu, arch.gprs[5]);
	OFFSET(KVM_VCPU_ARCH_R6, kvm_vcpu, arch.gprs[6]);
	OFFSET(KVM_VCPU_ARCH_R7, kvm_vcpu, arch.gprs[7]);
	OFFSET(KVM_VCPU_ARCH_R8, kvm_vcpu, arch.gprs[8]);
	OFFSET(KVM_VCPU_ARCH_R9, kvm_vcpu, arch.gprs[9]);
	OFFSET(KVM_VCPU_ARCH_R10, kvm_vcpu, arch.gprs[10]);
	OFFSET(KVM_VCPU_ARCH_R11, kvm_vcpu, arch.gprs[11]);
	OFFSET(KVM_VCPU_ARCH_R12, kvm_vcpu, arch.gprs[12]);
	OFFSET(KVM_VCPU_ARCH_R13, kvm_vcpu, arch.gprs[13]);
	OFFSET(KVM_VCPU_ARCH_R14, kvm_vcpu, arch.gprs[14]);
	OFFSET(KVM_VCPU_ARCH_R15, kvm_vcpu, arch.gprs[15]);
	OFFSET(KVM_VCPU_ARCH_R16, kvm_vcpu, arch.gprs[16]);
	OFFSET(KVM_VCPU_ARCH_R17, kvm_vcpu, arch.gprs[17]);
	OFFSET(KVM_VCPU_ARCH_R18, kvm_vcpu, arch.gprs[18]);
	OFFSET(KVM_VCPU_ARCH_R19, kvm_vcpu, arch.gprs[19]);
	OFFSET(KVM_VCPU_ARCH_R20, kvm_vcpu, arch.gprs[20]);
	OFFSET(KVM_VCPU_ARCH_R21, kvm_vcpu, arch.gprs[21]);
	OFFSET(KVM_VCPU_ARCH_R22, kvm_vcpu, arch.gprs[22]);
	OFFSET(KVM_VCPU_ARCH_R23, kvm_vcpu, arch.gprs[23]);
	OFFSET(KVM_VCPU_ARCH_R24, kvm_vcpu, arch.gprs[24]);
	OFFSET(KVM_VCPU_ARCH_R25, kvm_vcpu, arch.gprs[25]);
	OFFSET(KVM_VCPU_ARCH_R26, kvm_vcpu, arch.gprs[26]);
	OFFSET(KVM_VCPU_ARCH_R27, kvm_vcpu, arch.gprs[27]);
	OFFSET(KVM_VCPU_ARCH_R28, kvm_vcpu, arch.gprs[28]);
	OFFSET(KVM_VCPU_ARCH_R29, kvm_vcpu, arch.gprs[29]);
	OFFSET(KVM_VCPU_ARCH_R30, kvm_vcpu, arch.gprs[30]);
	OFFSET(KVM_VCPU_ARCH_R31, kvm_vcpu, arch.gprs[31]);
	OFFSET(KVM_VCPU_ARCH_LO, kvm_vcpu, arch.lo);
	OFFSET(KVM_VCPU_ARCH_HI, kvm_vcpu, arch.hi);
	OFFSET(KVM_VCPU_ARCH_EPC, kvm_vcpu, arch.epc);
	OFFSET(KVM_VCPU_ARCH_IMPL, kvm_vcpu, arch.impl);
	BLANK();
	OFFSET(KVM_VCPU_ARCH_FPR,	kvm_vcpu, arch.fpr);
	OFFSET(KVM_VCPU_ARCH_FIR,	kvm_vcpu, arch.fir);
	OFFSET(KVM_VCPU_ARCH_FCCR,	kvm_vcpu, arch.fccr);
	OFFSET(KVM_VCPU_ARCH_FEXR,	kvm_vcpu, arch.fexr);
	OFFSET(KVM_VCPU_ARCH_FENR,	kvm_vcpu, arch.fenr);
	OFFSET(KVM_VCPU_ARCH_FCSR,	kvm_vcpu, arch.fcsr);
	BLANK();

	OFFSET(KVM_MIPS_VCPU_TE_HOST_EBASE, kvm_mips_vcpu_te, host_ebase);
	OFFSET(KVM_MIPS_VCPU_TE_GUEST_EBASE, kvm_mips_vcpu_te, guest_ebase);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_STACK, kvm_mips_vcpu_te, host_stack);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_GP, kvm_mips_vcpu_te, host_gp);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_CP0_BADVADDR, kvm_mips_vcpu_te, host_cp0_badvaddr);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_CP0_CAUSE, kvm_mips_vcpu_te, host_cp0_cause);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_EPC, kvm_mips_vcpu_te, host_cp0_epc);
	OFFSET(KVM_MIPS_VCPU_TE_HOST_ENTRYHI, kvm_mips_vcpu_te, host_cp0_entryhi);
	OFFSET(KVM_MIPS_VCPU_TE_GUEST_INST, kvm_mips_vcpu_te, guest_inst);
	OFFSET(KVM_MIPS_VCPU_TE_COP0, kvm_mips_vcpu_te, cop0);
	OFFSET(KVM_MIPS_VCPU_TE_GUEST_KERNEL_ASID, kvm_mips_vcpu_te, guest_kernel_asid);
	OFFSET(KVM_MIPS_VCPU_TE_GUEST_USER_ASID, kvm_mips_vcpu_te, guest_user_asid);

	OFFSET(KVM_MIPS_VCPU_VZ_INJECTED_IPX, kvm_mips_vcpu_vz, injected_ipx);
	OFFSET(KVM_MIPS_VCPU_VZ_MM_ASID, kvm_mips_vcpu_vz, mm_asid);
	OFFSET(KVM_MIPS_VCPU_VZ_GUEST_ASID, kvm_mips_vcpu_vz, guest_asid);

	DEFINE(KVM_MIPS_VZ_REGS_SIZE, sizeof(struct kvm_mips_vz_regs));

	OFFSET(COP0_TLB_HI, mips_coproc, reg[MIPS_CP0_TLB_HI][0]);
	OFFSET(COP0_STATUS, mips_coproc, reg[MIPS_CP0_STATUS][0]);
	BLANK();

	COMMENT(" Linux struct kvm mipsvz offsets. ");
	OFFSET(KVM_MIPS_VZ_PGD,	kvm_mips_vz, pgd);
	BLANK();
}
#endif
