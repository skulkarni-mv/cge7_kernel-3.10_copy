#ifndef _ASM_X86_EFI_H
#define _ASM_X86_EFI_H

#include <asm/i387.h>
#include <asm/nospec-branch.h>

/*
 * We map the EFI regions needed for runtime services non-contiguously,
 * with preserved alignment on virtual addresses starting from -4G down
 * for a total max space of 64G. This way, we provide for stable runtime
 * services addresses across kernels so that a kexec'd kernel can still
 * use them.
 *
 * This is the main reason why we're doing stable VA mappings for RT
 * services.
 *
 * This flag is used in conjuction with a chicken bit called
 * "efi=old_map" which can be used as a fallback to the old runtime
 * services mapping method in case there's some b0rkage with a
 * particular EFI implementation (haha, it is hard to hold up the
 * sarcasm here...).
 */
#define EFI_OLD_MEMMAP		EFI_ARCH_1

#include <asm/pgtable.h>

#ifdef CONFIG_X86_32

#define EFI_LOADER_SIGNATURE	"EL32"

extern unsigned long asmlinkage efi_call_phys(void *, ...);

/*
 * Wrap all the virtual calls in a way that forces the parameters on the stack.
 */

/* Use this macro if your virtual returns a non-void value */
#define efi_call_virt(f, args...) \
({									\
	efi_status_t __s;						\
	kernel_fpu_begin();						\
	firmware_restrict_branch_speculation_start();			\
	__s = ((efi_##f##_t __attribute__((regparm(0)))*)		\
		efi.systab->runtime->f)(args);				\
	firmware_restrict_branch_speculation_end();			\
	kernel_fpu_end();						\
	__s;								\
})

/* Use this macro if your virtual call does not return any value */
#define __efi_call_virt(f, args...) \
({									\
	kernel_fpu_begin();						\
	firmware_restrict_branch_speculation_start();			\
	((efi_##f##_t __attribute__((regparm(0)))*)			\
		efi.systab->runtime->f)(args);				\
	firmware_restrict_branch_speculation_end();			\
	kernel_fpu_end();						\
})

#define efi_ioremap(addr, size, type, attr)	ioremap_cache(addr, size)

#else /* !CONFIG_X86_32 */

#define EFI_LOADER_SIGNATURE	"EL64"

extern u64 asmlinkage efi_call(void *fp, ...);

#define efi_call_phys(f, args...)		efi_call((f), args)

#define efi_call_virt(f, ...)						\
({									\
	efi_status_t __s;						\
									\
	efi_sync_low_kernel_mappings();					\
	preempt_disable();						\
	__kernel_fpu_begin();						\
	firmware_restrict_branch_speculation_start();			\
	__s = efi_call((void *)efi.systab->runtime->f, __VA_ARGS__);	\
	firmware_restrict_branch_speculation_end();			\
	__kernel_fpu_end();						\
	preempt_enable();						\
	__s;								\
})

/*
 * All X86_64 virt calls return non-void values. Thus, use non-void call for
 * virt calls that would be void on X86_32.
 */
#define __efi_call_virt(f, args...) efi_call_virt(f, args)

extern void __iomem *__init efi_ioremap(unsigned long addr, unsigned long size,
					u32 type, u64 attribute);

#endif /* CONFIG_X86_32 */

extern int add_efi_memmap;
extern unsigned long x86_efi_facility;
extern struct efi_scratch efi_scratch;
extern void __init efi_set_executable(efi_memory_desc_t *md, bool executable);
extern int __init efi_memblock_x86_reserve_range(void);
extern pgd_t * __init efi_call_phys_prolog(void);
extern void __init efi_call_phys_epilog(pgd_t *save_pgd);
extern void __init efi_unmap_memmap(void);
extern void __init efi_memory_uc(u64 addr, unsigned long size);
extern void __init efi_map_region(efi_memory_desc_t *md);
extern void __init efi_map_region_fixed(efi_memory_desc_t *md);
extern void efi_sync_low_kernel_mappings(void);
extern void efi_setup_page_tables(void);
extern void __init old_map_region(efi_memory_desc_t *md);

#ifdef CONFIG_EFI

static inline bool efi_is_native(void)
{
	return IS_ENABLED(CONFIG_X86_64) == efi_enabled(EFI_64BIT);
}

extern struct console early_efi_console;

#else
/*
 * IF EFI is not configured, have the EFI calls return -ENOSYS.
 */
#define efi_call0(_f)					(-ENOSYS)
#define efi_call1(_f, _a1)				(-ENOSYS)
#define efi_call2(_f, _a1, _a2)				(-ENOSYS)
#define efi_call3(_f, _a1, _a2, _a3)			(-ENOSYS)
#define efi_call4(_f, _a1, _a2, _a3, _a4)		(-ENOSYS)
#define efi_call5(_f, _a1, _a2, _a3, _a4, _a5)		(-ENOSYS)
#define efi_call6(_f, _a1, _a2, _a3, _a4, _a5, _a6)	(-ENOSYS)
#endif /* CONFIG_EFI */

#endif /* _ASM_X86_EFI_H */
