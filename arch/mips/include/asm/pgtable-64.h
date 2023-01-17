/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 1994, 95, 96, 97, 98, 99, 2000, 2003 Ralf Baechle
 * Copyright (C) 1999, 2000, 2001 Silicon Graphics, Inc.
 */
#ifndef _ASM_PGTABLE_64_H
#define _ASM_PGTABLE_64_H

#include <linux/compiler.h>
#include <linux/linkage.h>

#include <asm/addrspace.h>
#include <asm/page.h>
#include <asm/cachectl.h>
#include <asm/fixmap.h>


/*
 * Memory mapping options:
 *
 * Virtual address bits supported by tables:
 * +------+---------+----------+
 * | Page | Default | "48 bit" |
 * +------+---------+----------+
 * | 4K   |  40     |  48      |
 * | 8K   |  43     |  53      |
 * | 16K  |  47     |  48      |
 * | 32K  |  51     |  51      |
 * | 64K  |  42     |  54      |
 * +------+---------+----------+
 *
 *
 * 4K pages:
 * With two levels of page tables, one 4K page per level, and 4K page:
 * PTE provides 12 + 9 = 21 bits
 * PGD provides 9 bits
 * Total 30 bits (not used).
 *
 * With three levels of page tables, one 4K page per level, and 4K page:
 * PTE provides 12 + 9 = 21 bits
 * PMD provides 9 bits
 * PGD provides 9 bits
 * Total 39 bits (not used).
 *
 * With three levels of page tables, one 4K page per level except for
 * two-page PGD, and 4K page:
 * PTE provides 12 + 9 = 21 bits
 * PMD provides 9 bits
 * PGD provides 10 bits
 * Total 40 bits (the default for 4K pages).
 *
 * With four levels of page tables, one 4K page per level, and 4K page:
 * PTE provides 12 + 9 = 21 bits
 * PMD provides 9 bits
 * PUD provides 9 bits
 * PGD provides 9 bits
 * Total 48 bits (used when 48 bit address is enabled with 4K pages).
 *
 *
 * 8K pages:
 * With two levels of page tables, one 8K page per level, and 8K page:
 * PTE provides 13 + 10 = 23 bits
 * PGD provides 10 bits
 * Total 33 bits (not used).
 *
 * With three levels of page tables, one 8K page per level, and 8K page:
 * PTE provides 13 + 10 = 23 bits
 * PMD provides 10 bits
 * PGD provides 10 bits
 * Total 43 bits (what is set when 8K pages are selected).
 *
 * With four levels of page tables, one 8K page per level, and 8K page:
 * PTE provides 13 + 10 = 23 bits
 * PMD provides 10 bits
 * PUD provides 10 bits
 * PGD provides 10 bits
 * Total 53 bits (used when 48 bit address is enabled with 8K pages).
 *
 *
 * 16K pages:
 * With two levels of page tables, one 16K page per level, and 16K page:
 * PTE provides 14 + 11 = 25 bits
 * PGD provides 11 bits
 * Total 36 bits (not used).
 *
 * With three levels of page tables, one 16K page per level, and 16K page:
 * PTE provides 14 + 11 = 25 bits
 * PMD provides 11 bits
 * PGD provides 11 bits
 * Total 47 bits (the default for 16K pages).
 *
 * With three levels of page tables, one 16K page per level except for
 * two-page PGD, and 16K page:
 * PTE provides 14 + 11 = 25 bits
 * PMD provides 11 bits
 * PGD provides 12 bits
 * Total 48 bits (used when 48 bit address is enabled with 16K pages).
 *
 *
 * 32K pages:
 * With two levels of page tables, one 32K page per level, and 32K page:
 * PTE provides 15 + 12 = 27 bits
 * PGD provides 12 bits
 * Total 39 bits (not used).
 *
 * With three levels of page tables, one 32K page per level, and 32K page:
 * PTE provides 15 + 12 = 27 bits
 * PMD provides 12 bits
 * PGD provides 12 bits
 * Total 51 bit (the default for 32K pages).
 *
 *
 * 64K pages:
 * With two levels of page tables, one 64K page per level, and 64K page:
 * PTE provides 16 + 13 = 29 bits
 * PGD provides 13 bits
 * Total 42 bits (the default for 64K pages).
 *
 * With three levels of page tables, one 64K page per level, and 64K page:
 * PTE provides 16 + 13 = 29 bits
 * PMD provides 13 bits
 * PGD provides 13 bits
 * Total 54 bits (used when 48 bit address is enabled with 64K pages).
 *
 * Actually supported virtual address bits can not exceed 48 bits
 * or whatever is supported by CPU, see arch/mips/include/asm/processor.h
 *
 */

#ifdef CONFIG_MIPS_VA_BITS_48
/* 48-bit virtual memory */
#if !defined(CONFIG_PAGE_SIZE_4KB) && !defined(CONFIG_PAGE_SIZE_8KB)
/* All page sizes except 4K and 8K will use three-level page tables */
#include <asm-generic/pgtable-nopud.h>
#endif
/* 4K and 8K pages use four-level page tables */
#else
/* Reduced (below 48 bit) virtual memory size */
#ifdef CONFIG_PAGE_SIZE_64KB
/* Two-level page table */
#include <asm-generic/pgtable-nopmd.h>
#else
/* All other page sizes will use three-level page tables */
#include <asm-generic/pgtable-nopud.h>
#endif
#endif

/*
 * Default configuration with 4K pages:
 *
 * Each address space has 2 4K pages as its page directory, giving 1024
 * (== PTRS_PER_PGD) 8 byte pointers to pmd tables. Each pmd table is a
 * single 4K page, giving 512 (== PTRS_PER_PMD) 8 byte pointers to page
 * tables. Each page table is also a single 4K page, giving 512 (==
 * PTRS_PER_PTE) 8 byte ptes. Each pud entry is initialized to point to
 * invalid_pmd_table, each pmd entry is initialized to point to
 * invalid_pte_table, each pte is initialized to 0. When memory is low,
 * and a pmd table or a page table allocation fails, empty_bad_pmd_table
 * and empty_bad_page_table is returned back to higher layer code, so
 * that the failure is recognized later on. Linux does not seem to
 * handle these failures very well though. The empty_bad_page_table has
 * invalid pte entries in it, to force page faults.
 *
 * Kernel mappings: kernel mappings are held in the swapper_pg_table.
 * The layout is identical to userspace except it's indexed with the
 * fault address - VMALLOC_START.
 */

#ifdef __PAGETABLE_PUD_FOLDED

/* Here PGDIR_SHIFT determines what a third-level page table entry can map */
#ifdef __PAGETABLE_PMD_FOLDED
#define PGDIR_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#else

/* PMD_SHIFT determines the size of the area a second-level page table can map */
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))


#define PGDIR_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
#endif
#else
/* PUD is not folded */

/* PMD_SHIFT determines the size of the area a second-level page table can map */
#define PMD_SHIFT	(PAGE_SHIFT + (PAGE_SHIFT + PTE_ORDER - 3))
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))

/* PUD_SHIFT determines the size of the area a third-level page table can map */

#define PUD_SHIFT	(PMD_SHIFT + (PAGE_SHIFT + PMD_ORDER - 3))
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))

/* Here PGDIR_SHIFT determines what a fourth-level page table entry can map */

#define PGDIR_SHIFT	(PUD_SHIFT + (PAGE_SHIFT + PUD_ORDER - 3))
#endif

#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))


/*
 * For 4kB page size we use a 3 level page tree and an 8kB pgd, which
 * permits us mapping 40 bits of virtual address space.
 *
 * We used to implement 41 bits by having an order 1 pmd level but that seemed
 * rather pointless.
 *
 * For 8kB page size we use a 3 level page tree which permits a total of
 * 8TB of address space.  Alternatively a 33-bit / 8GB organization using
 * two levels would be easy to implement.
 *
 * For 16kB page size we use a 3 level page tree which permits a total of
 * 47 bits of virtual address space.
 *
 * For 64kB page size we use a 2 level page table tree for a total of 42 bits
 * of virtual address space.
 */
#ifdef CONFIG_PAGE_SIZE_4KB
#ifdef CONFIG_MIPS_VA_BITS_48
#define PGD_ORDER		0
#define PUD_ORDER		0
#else
#define PGD_ORDER		1
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#endif
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif

#ifdef CONFIG_PAGE_SIZE_8KB
#define PGD_ORDER		0
#ifdef CONFIG_MIPS_VA_BITS_48
#define PUD_ORDER		0
#else
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#endif
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif

#ifdef CONFIG_PAGE_SIZE_16KB
#ifdef CONFIG_MIPS_VA_BITS_48
#define PGD_ORDER		1
#else
#define PGD_ORDER		0
#endif
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif

#ifdef CONFIG_PAGE_SIZE_32KB
#define PGD_ORDER		0
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#define PMD_ORDER		0
#define PTE_ORDER		0
#endif

#ifdef CONFIG_PAGE_SIZE_64KB
#define PGD_ORDER		0
#define PUD_ORDER		aieeee_attempt_to_allocate_pud
#ifdef CONFIG_MIPS_VA_BITS_48
#define PMD_ORDER		0
#else
#define PMD_ORDER		aieeee_attempt_to_allocate_pmd
#endif
#define PTE_ORDER		0
#endif

#define PTRS_PER_PGD	((PAGE_SIZE << PGD_ORDER) / sizeof(pgd_t))
#ifndef __PAGETABLE_PUD_FOLDED
#define PTRS_PER_PUD	((PAGE_SIZE << PUD_ORDER) / sizeof(pud_t))
#endif
#ifndef __PAGETABLE_PMD_FOLDED
#define PTRS_PER_PMD	((PAGE_SIZE << PMD_ORDER) / sizeof(pmd_t))
#endif
#define PTRS_PER_PTE	((PAGE_SIZE << PTE_ORDER) / sizeof(pte_t))

#define USER_PTRS_PER_PGD	((TASK_SIZE64 / PGDIR_SIZE) ? (TASK_SIZE64 / PGDIR_SIZE) : 1)
#define FIRST_USER_ADDRESS	0UL

/*
 * TLB refill handlers also map the vmalloc area into xuseg.  Avoid
 * the first half of the MAP_BASE area so NULL pointer dereferences
 * will still reliably trap, and to avoid OCTEON III errata.
 */
#ifdef __PAGETABLE_PUD_FOLDED
#define VMALLOC_END	\
	(MAP_BASE + \
	 min(PTRS_PER_PGD * PTRS_PER_PMD * PTRS_PER_PTE * PAGE_SIZE, \
	     (1UL << cpu_vmbits)) - (1UL << 32))
#else
#define VMALLOC_END	\
	(MAP_BASE + \
	 min(PTRS_PER_PGD * PTRS_PER_PUD * PTRS_PER_PMD * PTRS_PER_PTE \
	     * PAGE_SIZE,					       \
	     (1UL << cpu_vmbits)) - (1UL << 32))
#endif

#define VMALLOC_START		((MAP_BASE / 2 + VMALLOC_END / 2) & PAGE_MASK)

#if defined(CONFIG_MODULES) && defined(KBUILD_64BIT_SYM32)

/* Load modules into 32bit-compatible segment. */
#ifdef CONFIG_MAPPED_KERNEL
extern unsigned long kernel_image_end;
#define MODULE_START	kernel_image_end
#else
#define MODULE_START   CKSSEG
#endif
#define MODULE_END	(FIXADDR_START-2*PAGE_SIZE)
#endif

#define pte_ERROR(e) \
	printk("%s:%d: bad pte %016lx.\n", __FILE__, __LINE__, pte_val(e))
#ifndef __PAGETABLE_PMD_FOLDED
#define pmd_ERROR(e) \
	printk("%s:%d: bad pmd %016lx.\n", __FILE__, __LINE__, pmd_val(e))
#endif
#ifndef __PAGETABLE_PUD_FOLDED
#define pud_ERROR(e) \
	printk("%s:%d: bad pud %016lx.\n", __FILE__, __LINE__, pud_val(e))
#endif
#define pgd_ERROR(e) \
	printk("%s:%d: bad pgd %016lx.\n", __FILE__, __LINE__, pgd_val(e))

extern pte_t invalid_pte_table[PTRS_PER_PTE];
extern pte_t empty_bad_page_table[PTRS_PER_PTE];

#ifndef __PAGETABLE_PUD_FOLDED
/*
 * For 4-level pagetables we defines these ourselves, for 3-level the
 * definitions are below, for 2-level the
 * definitions are supplied by <asm-generic/pgtable-nopmd.h>.
 */
typedef struct { unsigned long pud; } pud_t;
#define pud_val(x)	((x).pud)
#define __pud(x)	((pud_t) { (x) })

extern pud_t invalid_pud_table[PTRS_PER_PUD];
#endif

#ifndef __PAGETABLE_PMD_FOLDED
/*
 * For 3-level pagetables we defines these ourselves, for 2-level the
 * definitions are supplied by <asm-generic/pgtable-nopmd.h>.
 */
typedef struct { unsigned long pmd; } pmd_t;
#define pmd_val(x)	((x).pmd)
#define __pmd(x)	((pmd_t) { (x) } )


extern pmd_t invalid_pmd_table[PTRS_PER_PMD];
#endif

/*
 * Empty pgd/pmd entries point to the invalid_pte_table.
 */
static inline int pmd_none(pmd_t pmd)
{
	return pmd_val(pmd) == (unsigned long) invalid_pte_table;
}

static inline int pmd_bad(pmd_t pmd)
{
#ifdef CONFIG_MIPS_HUGE_TLB_SUPPORT
	/* pmd_huge(pmd) but inline */
	if (unlikely(pmd_val(pmd) & _PAGE_HUGE))
		return 0;
#endif

	if (unlikely(pmd_val(pmd) & ~PAGE_MASK))
		return 1;

	return 0;
}

static inline int pmd_present(pmd_t pmd)
{
	return pmd_val(pmd) != (unsigned long) invalid_pte_table;
}

static inline void pmd_clear(pmd_t *pmdp)
{
	pmd_val(*pmdp) = ((unsigned long) invalid_pte_table);
}

#ifndef __PAGETABLE_PUD_FOLDED

/*
 * Empty pgd entries point to the invalid_pud_table.
 */
static inline int pgd_none(pgd_t pgd)
{
	return pgd_val(pgd) == (unsigned long) invalid_pud_table;
}

static inline int pgd_bad(pgd_t pgd)
{
	return pgd_val(pgd) & ~PAGE_MASK;
}

static inline int pgd_present(pgd_t pgd)
{
	return pgd_val(pgd) != (unsigned long) invalid_pud_table;
}

static inline void pgd_clear(pgd_t *pgdp)
{
	pgd_val(*pgdp) = ((unsigned long) invalid_pud_table);
}
#endif

#ifndef __PAGETABLE_PMD_FOLDED

/*
 * Empty pud entries point to the invalid_pmd_table.
 */
static inline int pud_none(pud_t pud)
{
	return pud_val(pud) == (unsigned long) invalid_pmd_table;
}

static inline int pud_bad(pud_t pud)
{
	return pud_val(pud) & ~PAGE_MASK;
}

static inline int pud_present(pud_t pud)
{
	return pud_val(pud) != (unsigned long) invalid_pmd_table;
}

static inline void pud_clear(pud_t *pudp)
{
	pud_val(*pudp) = ((unsigned long) invalid_pmd_table);
}
#endif

#define pte_page(x)		pfn_to_page(pte_pfn(x))

#ifdef CONFIG_CPU_VR41XX
#define pte_pfn(x)		((unsigned long)((x).pte >> (PAGE_SHIFT + 2)))
#define pfn_pte(pfn, prot)	__pte(((pfn) << (PAGE_SHIFT + 2)) | pgprot_val(prot))
#else
#define pte_pfn(x)		((unsigned long)((x).pte >> _PFN_SHIFT))
#define pfn_pte(pfn, prot)	__pte(((pfn) << _PFN_SHIFT) | pgprot_val(prot))
#define pfn_pmd(pfn, prot)	__pmd(((pfn) << _PFN_SHIFT) | pgprot_val(prot))
#endif

#define __pgd_offset(address)	pgd_index(address)
#ifndef __PAGETABLE_PUD_FOLDED
#define __pud_offset(address)	pud_index(address)
#else
#define __pud_offset(address)  (((address) >> PUD_SHIFT) & (PTRS_PER_PUD-1))
#endif
#define __pmd_offset(address)	pmd_index(address)

/* to find an entry in a kernel page-table-directory */
#define pgd_offset_k(address) pgd_offset(&init_mm, address)

#define pgd_index(address)	(((address) >> PGDIR_SHIFT) & (PTRS_PER_PGD-1))
#ifndef __PAGETABLE_PUD_FOLDED
#define pud_index(address)	(((address) >> PUD_SHIFT) & (PTRS_PER_PUD-1))
#endif
#define pmd_index(address)	(((address) >> PMD_SHIFT) & (PTRS_PER_PMD-1))

/* to find an entry in a page-table-directory */
#define pgd_offset(mm, addr)	((mm)->pgd + pgd_index(addr))

#ifndef __PAGETABLE_PUD_FOLDED
static inline unsigned long pgd_page_vaddr(pgd_t pgd)
{
	return pgd_val(pgd);
}

/*
 * Find an entry in the upper-level (below global) page table..
 */
static inline pud_t *pud_offset(pgd_t *pgd, unsigned long address)
{
	return (pud_t *) pgd_page_vaddr(*pgd) + pud_index(address);
}
#endif

#ifndef __PAGETABLE_PMD_FOLDED
static inline unsigned long pud_page_vaddr(pud_t pud)
{
	return pud_val(pud);
}
#define pud_phys(pud)		virt_to_phys((void *)pud_val(pud))
#define pud_page(pud)		(pfn_to_page(pud_phys(pud) >> PAGE_SHIFT))

/*
 * Find an entry in the middle-level (below upper, if any, otherwise global)
 * page table..
 */
static inline pmd_t *pmd_offset(pud_t * pud, unsigned long address)
{
	return (pmd_t *) pud_page_vaddr(*pud) + pmd_index(address);
}
#endif

/*
 * Find an entry in the low-level page table..
 */
#define __pte_offset(address)						\
	(((address) >> PAGE_SHIFT) & (PTRS_PER_PTE - 1))
#define pte_offset(dir, address)					\
	((pte_t *) pmd_page_vaddr(*(dir)) + __pte_offset(address))
#define pte_offset_kernel(dir, address)					\
	((pte_t *) pmd_page_vaddr(*(dir)) + __pte_offset(address))
#define pte_offset_map(dir, address)					\
	((pte_t *)page_address(pmd_page(*(dir))) + __pte_offset(address))
#define pte_unmap(pte) ((void)(pte))

/*
 * Initialize a new pgd / pud / pmd table with invalid pointers.
 */
extern void pgd_init(unsigned long page);
#ifndef __PAGETABLE_PUD_FOLDED
extern void pud_init(unsigned long page, unsigned long pagetable);
#endif
#ifndef __PAGETABLE_PMD_FOLDED
extern void pmd_init(unsigned long page, unsigned long pagetable);
#endif

/*
 * Non-present pages:  high 40 bits are offset, next 8 bits type,
 * low 16 bits zero.
 */
static inline pte_t mk_swap_pte(unsigned long type, unsigned long offset)
{ pte_t pte; pte_val(pte) = (type << 16) | (offset << 24); return pte; }

#define __swp_type(x)		(((x).val >> 16) & 0xff)
#define __swp_offset(x)		((x).val >> 24)
#define __swp_entry(type, offset) ((swp_entry_t) { pte_val(mk_swap_pte((type), (offset))) })
#define __pte_to_swp_entry(pte) ((swp_entry_t) { pte_val(pte) })
#define __swp_entry_to_pte(x)	((pte_t) { (x).val })

/*
 * Leave low order 16 bits for the various page table bits, and only
 * use the upper 48 bits for the page offset...
 */
#define PTE_FILE_MAX_BITS	48

#define pte_to_pgoff(_pte)	((_pte).pte >> 16)
#define pgoff_to_pte(off)	((pte_t) { ((off) << 16) | _PAGE_FILE })

#endif /* _ASM_PGTABLE_64_H */
