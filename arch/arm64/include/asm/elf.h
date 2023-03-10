/*
 * Copyright (C) 2012 ARM Ltd.
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
#ifndef __ASM_ELF_H
#define __ASM_ELF_H

#include <asm/errno.h>
#include <asm/hwcap.h>
#include <asm/cpu.h>

/*
 * ELF register definitions..
 */
#include <asm/ptrace.h>
#include <asm/user.h>

typedef unsigned long elf_greg_t;

#define ELF_NGREG (sizeof(struct user_pt_regs) / sizeof(elf_greg_t))
#define ELF_CORE_COPY_REGS(dest, regs)	\
	*(struct user_pt_regs *)&(dest) = (regs)->user_regs;

typedef elf_greg_t elf_gregset_t[ELF_NGREG];
typedef struct user_fpsimd_state elf_fpregset_t;

#define EM_AARCH64		183

/*
 * AArch64 static relocation types.
 */

/* Miscellaneous. */
#define R_ARM_NONE			0
#define R_AARCH64_NONE			256

/* Data. */
#define R_AARCH64_ABS64			257
#define R_AARCH64_ABS32			258
#define R_AARCH64_ABS16			259
#define R_AARCH64_PREL64		260
#define R_AARCH64_PREL32		261
#define R_AARCH64_PREL16		262

/* Instructions. */
#define R_AARCH64_MOVW_UABS_G0		263
#define R_AARCH64_MOVW_UABS_G0_NC	264
#define R_AARCH64_MOVW_UABS_G1		265
#define R_AARCH64_MOVW_UABS_G1_NC	266
#define R_AARCH64_MOVW_UABS_G2		267
#define R_AARCH64_MOVW_UABS_G2_NC	268
#define R_AARCH64_MOVW_UABS_G3		269

#define R_AARCH64_MOVW_SABS_G0		270
#define R_AARCH64_MOVW_SABS_G1		271
#define R_AARCH64_MOVW_SABS_G2		272

#define R_AARCH64_LD_PREL_LO19		273
#define R_AARCH64_ADR_PREL_LO21		274
#define R_AARCH64_ADR_PREL_PG_HI21	275
#define R_AARCH64_ADR_PREL_PG_HI21_NC	276
#define R_AARCH64_ADD_ABS_LO12_NC	277
#define R_AARCH64_LDST8_ABS_LO12_NC	278

#define R_AARCH64_TSTBR14		279
#define R_AARCH64_CONDBR19		280
#define R_AARCH64_JUMP26		282
#define R_AARCH64_CALL26		283
#define R_AARCH64_LDST16_ABS_LO12_NC	284
#define R_AARCH64_LDST32_ABS_LO12_NC	285
#define R_AARCH64_LDST64_ABS_LO12_NC	286
#define R_AARCH64_LDST128_ABS_LO12_NC	299

#define R_AARCH64_MOVW_PREL_G0		287
#define R_AARCH64_MOVW_PREL_G0_NC	288
#define R_AARCH64_MOVW_PREL_G1		289
#define R_AARCH64_MOVW_PREL_G1_NC	290
#define R_AARCH64_MOVW_PREL_G2		291
#define R_AARCH64_MOVW_PREL_G2_NC	292
#define R_AARCH64_MOVW_PREL_G3		293

/*
 * These are used to set parameters in the core dumps.
 */
#define ELF_CLASS	ELFCLASS64
#ifdef __AARCH64EB__
#define ELF_DATA	ELFDATA2MSB
#else
#define ELF_DATA	ELFDATA2LSB
#endif
#define ELF_ARCH	EM_AARCH64

/*
 * This yields a string that ld.so will use to load implementation
 * specific libraries for optimization.  This is more specific in
 * intent than poking at uname or /proc/cpuinfo.
 */
#define ELF_PLATFORM_SIZE	16
#ifdef __AARCH64EB__
#define ELF_PLATFORM		("aarch64_be")
#else
#define ELF_PLATFORM		("aarch64")
#endif

/*
 * This is used to ensure we don't load something for the wrong architecture.
 */
#define elf_check_arch(x)		((x)->e_machine == EM_AARCH64)

#define elf_read_implies_exec(ex,stk)	(stk != EXSTACK_DISABLE_X)

#define CORE_DUMP_USE_REGSET
#define ELF_EXEC_PAGESIZE	PAGE_SIZE

/*
 * This is the location that an ET_DYN program is loaded if exec'ed.  Typical
 * use of this is to invoke "./ld.so someprog" to test out a new version of
 * the loader.  We need to make sure that it is out of the way of the program
 * that it will "exec", and that there is sufficient room for the brk.
 */
#define ELF_ET_DYN_BASE	(2 * TASK_SIZE_64 / 3)

#ifdef CONFIG_PAX_ASLR
#define PAX_ELF_ET_DYN_BASE	0x00040000UL

#define PAX_DELTA_MMAP_LEN	16
#define PAX_DELTA_STACK_LEN	16

#endif

/*
 * When the program starts, a1 contains a pointer to a function to be
 * registered with atexit, as per the SVR4 ABI.  A value of 0 means we have no
 * such handler.
 */
#define ELF_PLAT_INIT(_r, load_addr)	(_r)->regs[0] = 0

#define SET_PERSONALITY(ex)			\
do {						\
	clear_thread_flag(TIF_AARCH32);		\
	clear_thread_flag(TIF_32BIT);		\
} while (0)


/* update AT_VECTOR_SIZE_ARCH if the number of NEW_AUX_ENT entries changes */
#define ARCH_DLINFO								\
do {										\
	u32 midr;								\
										\
	NEW_AUX_ENT(AT_SYSINFO_EHDR,						\
		    (elf_addr_t)current->mm->context.vdso);			\
	midr = get_arm64_midr();						\
	if (midr != -1)								\
		NEW_AUX_ENT(AT_ARM64_MIDR, (elf_addr_t)(get_arm64_midr()));	\
} while (0)

#define ARCH_HAS_SETUP_ADDITIONAL_PAGES
struct linux_binprm;
extern int arch_setup_additional_pages(struct linux_binprm *bprm,
				       int uses_interp);

/* 1GB of VA */
#ifdef CONFIG_COMPAT
#define STACK_RND_MASK			(test_thread_flag(TIF_32BIT) ? \
						0x7ff >> (PAGE_SHIFT - 12) : \
						0x3ffff >> (PAGE_SHIFT - 12))
#else
#define STACK_RND_MASK			(0x3ffff >> (PAGE_SHIFT - 12))
#endif

struct mm_struct;
extern unsigned long arch_randomize_brk(struct mm_struct *mm);
#define arch_randomize_brk arch_randomize_brk

#ifdef CONFIG_COMPAT
#define EM_ARM				40
#ifdef __AARCH64EB__
#define COMPAT_ELF_PLATFORM		("v8b")
#else
#define COMPAT_ELF_PLATFORM		("v8l")
#endif

#define COMPAT_ELF_ET_DYN_BASE		(2 * TASK_SIZE_32 / 3)

#ifdef CONFIG_AARCH32_EL0

/* AArch32 registers. */
#define COMPAT_A32_ELF_NGREG		18
typedef unsigned int			compat_a32_elf_greg_t;
typedef compat_a32_elf_greg_t		compat_a32_elf_gregset_t[COMPAT_A32_ELF_NGREG];

/* AArch32 EABI. */
#define EF_ARM_EABI_MASK		0xff000000
#define compat_a32_elf_check_arch(x)	(((x)->e_machine == EM_ARM) && \
					 ((x)->e_flags & EF_ARM_EABI_MASK))

#define compat_start_thread		compat_start_thread
#define COMPAT_A32_SET_PERSONALITY(ex)		\
do {						\
	set_thread_flag(TIF_AARCH32);		\
	set_thread_flag(TIF_32BIT);		\
} while (0)
#define COMPAT_A32_ARCH_DLINFO		do {} while (0)
extern int aarch32_setup_vectors_page(struct linux_binprm *bprm,
				      int uses_interp);

#else
typedef elf_greg_t			compat_elf_greg_t;
typedef elf_gregset_t			compat_elf_gregset_t;
#define compat_a32_elf_check_arch(x)	0
#define COMPAT_A32_SET_PERSONALITY(ex)	do {} while (0)
#define COMPAT_A32_ARCH_DLINFO		do {} while (0)
static inline int aarch32_setup_vectors_page(struct linux_binprm *bprm,
					     int uses_interp)
{
	return -EINVAL;
}
#endif

/*
 * If ILP32 is turned on, we want to define the compat_elf_greg_t to the non compat
 * one and define PR_REG_SIZE/PRSTATUS_SIZE/SET_PR_FPVALID so we pick up the correct
 * ones for AARCH32.
 */
#ifdef CONFIG_ARM64_ILP32
typedef elf_greg_t			compat_elf_greg_t;
typedef elf_gregset_t			compat_elf_gregset_t;
#define COMPAT_PR_REG_SIZE(S)		(is_a32_compat_task() ? 72 : 272)
#define COMPAT_PRSTATUS_SIZE(S)		(is_a32_compat_task() ? 124 : 352)
#define COMPAT_SET_PR_FPVALID(S, V)							\
do {										\
	*(int *) (((void *) &((S)->pr_reg)) + PR_REG_SIZE((S)->pr_reg)) = (V);	\
} while (0)
#else
typedef compat_a32_elf_greg_t compat_elf_greg_t;
typedef compat_a32_elf_gregset_t compat_elf_gregset_t;
#endif

#ifdef CONFIG_ARM64_ILP32
#define compat_ilp32_elf_check_arch(x) ((x)->e_machine == EM_AARCH64)
#define COMPAT_ILP32_SET_PERSONALITY(ex)	\
do {						\
	clear_thread_flag(TIF_AARCH32);		\
	set_thread_flag(TIF_32BIT);		\
} while (0)
#define COMPAT_ILP32_ARCH_DLINFO						\
do {										\
	u32 midr;								\
	NEW_AUX_ENT(AT_SYSINFO_EHDR,						\
		    (elf_addr_t)(long)current->mm->context.vdso);		\
	midr = get_arm64_midr();						\
	if (midr != -1)								\
		NEW_AUX_ENT(AT_ARM64_MIDR, (elf_addr_t)(get_arm64_midr()));	\
} while (0)
#else
#define compat_ilp32_elf_check_arch(x) 0
#define COMPAT_ILP32_SET_PERSONALITY(ex)	do {} while (0)
#define COMPAT_ILP32_ARCH_DLINFO		do {} while (0)
#endif

#define compat_elf_check_arch(x)	(compat_a32_elf_check_arch(x) || compat_ilp32_elf_check_arch(x))
#define COMPAT_SET_PERSONALITY(ex)			\
do {							\
	if (compat_a32_elf_check_arch(&ex))		\
		COMPAT_A32_SET_PERSONALITY(ex);		\
	else						\
		COMPAT_ILP32_SET_PERSONALITY(ex);	\
} while (0)

/* ILP32 uses the "LP64-like" vdso pages */
#define compat_arch_setup_additional_pages	\
	(is_a32_compat_task()			\
	 ? &aarch32_setup_vectors_page		\
	 : &(arch_setup_additional_pages))

#define COMPAT_ARCH_DLINFO			\
do {						\
	if (is_a32_compat_task())		\
		COMPAT_A32_ARCH_DLINFO;		\
	else					\
		COMPAT_ILP32_ARCH_DLINFO;	\
} while (0)

#endif /* CONFIG_COMPAT */

#endif
