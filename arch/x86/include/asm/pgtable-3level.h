#ifndef _ASM_X86_PGTABLE_3LEVEL_H
#define _ASM_X86_PGTABLE_3LEVEL_H

/*
 * Intel Physical Address Extension (PAE) Mode - three-level page
 * tables on PPro+ CPUs.
 *
 * Copyright (C) 1999 Ingo Molnar <mingo@redhat.com>
 */

#define pte_ERROR(e)							\
	pr_err("%s:%d: bad pte %p(%08lx%08lx)\n",			\
	       __FILE__, __LINE__, &(e), (e).pte_high, (e).pte_low)
#define pmd_ERROR(e)							\
	pr_err("%s:%d: bad pmd %p(%016Lx)\n",				\
	       __FILE__, __LINE__, &(e), pmd_val(e))
#define pgd_ERROR(e)							\
	pr_err("%s:%d: bad pgd %p(%016Lx)\n",				\
	       __FILE__, __LINE__, &(e), pgd_val(e))

/* Rules for using set_pte: the pte being assigned *must* be
 * either not present or in a state where the hardware will
 * not attempt to update the pte.  In places where this is
 * not possible, use pte_get_and_clear to obtain the old pte
 * value and then use set_pte to update it.  -ben
 */
static inline void native_set_pte(pte_t *ptep, pte_t pte)
{
	ptep->pte_high = pte.pte_high;
	smp_wmb();
	ptep->pte_low = pte.pte_low;
}

#define pmd_read_atomic pmd_read_atomic
/*
 * pte_offset_map_lock on 32bit PAE kernels was reading the pmd_t with
 * a "*pmdp" dereference done by gcc. Problem is, in certain places
 * where pte_offset_map_lock is called, concurrent page faults are
 * allowed, if the mmap_sem is hold for reading. An example is mincore
 * vs page faults vs MADV_DONTNEED. On the page fault side
 * pmd_populate rightfully does a set_64bit, but if we're reading the
 * pmd_t with a "*pmdp" on the mincore side, a SMP race can happen
 * because gcc will not read the 64bit of the pmd atomically. To fix
 * this all places running pmd_offset_map_lock() while holding the
 * mmap_sem in read mode, shall read the pmdp pointer using this
 * function to know if the pmd is null nor not, and in turn to know if
 * they can run pmd_offset_map_lock or pmd_trans_huge or other pmd
 * operations.
 *
 * Without THP if the mmap_sem is hold for reading, the pmd can only
 * transition from null to not null while pmd_read_atomic runs. So
 * we can always return atomic pmd values with this function.
 *
 * With THP if the mmap_sem is hold for reading, the pmd can become
 * trans_huge or none or point to a pte (and in turn become "stable")
 * at any time under pmd_read_atomic. We could read it really
 * atomically here with a atomic64_read for the THP enabled case (and
 * it would be a whole lot simpler), but to avoid using cmpxchg8b we
 * only return an atomic pmdval if the low part of the pmdval is later
 * found stable (i.e. pointing to a pte). And we're returning a none
 * pmdval if the low part of the pmd is none. In some cases the high
 * and low part of the pmdval returned may not be consistent if THP is
 * enabled (the low part may point to previously mapped hugepage,
 * while the high part may point to a more recently mapped hugepage),
 * but pmd_none_or_trans_huge_or_clear_bad() only needs the low part
 * of the pmd to be read atomically to decide if the pmd is unstable
 * or not, with the only exception of when the low part of the pmd is
 * zero in which case we return a none pmd.
 */
static inline pmd_t pmd_read_atomic(pmd_t *pmdp)
{
	pmdval_t ret;
	u32 *tmp = (u32 *)pmdp;

	ret = (pmdval_t) (*tmp);
	if (ret) {
		/*
		 * If the low part is null, we must not read the high part
		 * or we can end up with a partial pmd.
		 */
		smp_rmb();
		ret |= ((pmdval_t)*(tmp + 1)) << 32;
	}

	return (pmd_t) { ret };
}

static inline void native_set_pte_atomic(pte_t *ptep, pte_t pte)
{
	set_64bit((unsigned long long *)(ptep), native_pte_val(pte));
}

static inline void native_set_pmd(pmd_t *pmdp, pmd_t pmd)
{
	pax_open_kernel();
	set_64bit((unsigned long long *)(pmdp), native_pmd_val(pmd));
	pax_close_kernel();
}

static inline void native_set_pud(pud_t *pudp, pud_t pud)
{
	pax_open_kernel();
	set_64bit((unsigned long long *)(pudp), native_pud_val(pud));
	pax_close_kernel();
}

/*
 * For PTEs and PDEs, we must clear the P-bit first when clearing a page table
 * entry, so clear the bottom half first and enforce ordering with a compiler
 * barrier.
 */
static inline void native_pte_clear(struct mm_struct *mm, unsigned long addr,
				    pte_t *ptep)
{
	ptep->pte_low = 0;
	smp_wmb();
	ptep->pte_high = 0;
}

static inline void native_pmd_clear(pmd_t *pmd)
{
	u32 *tmp = (u32 *)pmd;
	*tmp = 0;
	smp_wmb();
	*(tmp + 1) = 0;
}

static inline void pud_clear(pud_t *pudp)
{
	set_pud(pudp, __pud(0));

	/*
	 * According to Intel App note "TLBs, Paging-Structure Caches,
	 * and Their Invalidation", April 2007, document 317080-001,
	 * section 8.1: in PAE mode we explicitly have to flush the
	 * TLB via cr3 if the top-level pgd is changed...
	 *
	 * Currently all places where pud_clear() is called either have
	 * flush_tlb_mm() followed or don't need TLB flush (x86_64 code or
	 * pud_clear_bad()), so we don't need TLB flush here.
	 */
}

#ifdef CONFIG_SMP
static inline pte_t native_ptep_get_and_clear(pte_t *ptep)
{
	pte_t res;

	/* xchg acts as a barrier before the setting of the high bits */
	res.pte_low = xchg(&ptep->pte_low, 0);
	res.pte_high = ptep->pte_high;
	ptep->pte_high = 0;

	return res;
}
#else
#define native_ptep_get_and_clear(xp) native_local_ptep_get_and_clear(xp)
#endif

#ifdef CONFIG_SMP
union split_pmd {
	struct {
		u32 pmd_low;
		u32 pmd_high;
	};
	pmd_t pmd;
};
static inline pmd_t native_pmdp_get_and_clear(pmd_t *pmdp)
{
	union split_pmd res, *orig = (union split_pmd *)pmdp;

	/* xchg acts as a barrier before setting of the high bits */
	res.pmd_low = xchg(&orig->pmd_low, 0);
	res.pmd_high = orig->pmd_high;
	orig->pmd_high = 0;

	return res.pmd;
}
#else
#define native_pmdp_get_and_clear(xp) native_local_pmdp_get_and_clear(xp)
#endif

/*
 * Bits 0, 6 and 7 are taken in the low part of the pte,
 * put the 32 bits of offset into the high part.
 *
 * For soft-dirty tracking 11 bit is taken from
 * the low part of pte as well.
 */
#define pte_to_pgoff(pte) ((pte).pte_high)
#define pgoff_to_pte(off)						\
	((pte_t) { { .pte_low = _PAGE_FILE, .pte_high = (off) } })
#define PTE_FILE_MAX_BITS       32

/* Encode and de-code a swap entry */
#define SWP_TYPE_BITS		5

#define SWP_OFFSET_FIRST_BIT	(_PAGE_BIT_PROTNONE + 1)

/* We always extract/encode the offset by shifting it all the way up, and then down again */
#define SWP_OFFSET_SHIFT	(SWP_OFFSET_FIRST_BIT + SWP_TYPE_BITS)

#define MAX_SWAPFILES_CHECK() BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > 5)
#define __swp_type(x)			(((x).val) & 0x1f)
#define __swp_offset(x)			((x).val >> 5)
#define __swp_entry(type, offset)	((swp_entry_t){(type) | (offset) << 5})

/*
 * Normally, __swp_entry() converts from arch-independent swp_entry_t to
 * arch-dependent swp_entry_t, and __swp_entry_to_pte() just stores the result
 * to pte. But here we have 32bit swp_entry_t and 64bit pte, and need to use the
 * whole 64 bits. Thus, we shift the "real" arch-dependent conversion to
 * __swp_entry_to_pte() through the following helper macro based on 64bit
 * __swp_entry().
 */
#define __swp_pteval_entry(type, offset) ((pteval_t) { \
	(~(pteval_t)(offset) << SWP_OFFSET_SHIFT >> SWP_TYPE_BITS) \
	| ((pteval_t)(type) << (64 - SWP_TYPE_BITS)) })

#if 1
/*
 * This is a temporary hack until a compiler bug can be fixed.  If we
 * use the code in the #else section, we currently get:
 *
 *   /work/cge7/mvl7kernel/include/linux/swapops.h: In function 'swp_entry_to_pte':
 *   /work/cge7/mvl7kernel/include/linux/swapops.h:85:2: internal compiler error: Segmentation fault
 *   Please submit a full bug report,
 *   with preprocessed source if appropriate.
 *   See <http://support.mvista.com/> for instructions.
 *   Preprocessed source stored into /tmp/ccD560Oa.out file, please attach this to your bugreport.
 *
 * It looks like the way the cast is done breaks gcc at the moment.
 * So don't do a cast, do an inline function setting and returning the
 * proper type.
 *
 * Remove all this when the compiler bug is fixed.
 */
static inline pte_t ___swp_entry_to_pte(unsigned long type,
					unsigned long offset)
{
	pte_t pte;

	pte.pte = __swp_pteval_entry(type, offset);
	return pte;
}
#define __swp_entry_to_pte(x)	___swp_entry_to_pte(__swp_type(x), \
						    __swp_offset(x))
#else
#define __swp_entry_to_pte(x)	((pte_t){ .pte = \
		__swp_pteval_entry(__swp_type(x), __swp_offset(x)) })
#endif

/*
 * Analogically, __pte_to_swp_entry() doesn't just extract the arch-dependent
 * swp_entry_t, but also has to convert it from 64bit to the 32bit
 * intermediate representation, using the following macros based on 64bit
 * __swp_type() and __swp_offset().
 */
#define __pteval_swp_type(x) ((unsigned long)((x).pte >> (64 - SWP_TYPE_BITS)))
#define __pteval_swp_offset(x) ((unsigned long)(~((x).pte) << SWP_TYPE_BITS >> SWP_OFFSET_SHIFT))

#define __pte_to_swp_entry(pte)	(__swp_entry(__pteval_swp_type(pte), \
					     __pteval_swp_offset(pte)))

#include <asm/pgtable-invert.h>

#endif /* _ASM_X86_PGTABLE_3LEVEL_H */
