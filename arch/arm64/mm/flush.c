/*
 * Based on arch/arm/mm/flush.c
 *
 * Copyright (C) 1995-2002 Russell King
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

#include <linux/export.h>
#include <linux/mm.h>
#include <linux/pagemap.h>
#include <linux/smp.h>

#include <asm/cacheflush.h>
#include <asm/cachetype.h>
#include <asm/tlbflush.h>

#include "mm.h"

#ifdef CONFIG_OPTIMIZE_MANY_CPUS
static void flush_tlb_local(void *info)
{
	asm volatile("\n"
		     "	tlbi	vmalle1\n"
		     "	isb	sy"
		);
}

static void flush_tlb_mm_local(void *info)
{
	unsigned long asid = (unsigned long)info;

	asm volatile("\n"
		     "	tlbi	aside1, %0\n"
		     "	isb	sy"
		     : : "r" (asid)
		);
}

void flush_tlb_all(void)
{
	/* Make sure page table modifications are visible. */
	dsb(ishst);
	/* IPI to all CPUs to do local flush. */
	on_each_cpu(flush_tlb_local, NULL, 1);

}
EXPORT_SYMBOL(flush_tlb_all);

void flush_tlb_mm(struct mm_struct *mm)
{
	if (!mm) {
		flush_tlb_all();
	} else {
		unsigned long asid = (unsigned long)ASID(mm) << 48;
		/* Make sure page table modifications are visible. */
		dsb(ishst);
		/* IPI to all CPUs to do local flush. */
		on_each_cpu_mask(mm_cpumask(mm),
				 flush_tlb_mm_local, (void *)asid, 1);
	}

}
EXPORT_SYMBOL(flush_tlb_mm);
#endif

void flush_cache_range(struct vm_area_struct *vma, unsigned long start,
		       unsigned long end)
{
	if (vma->vm_flags & VM_EXEC)
		__flush_icache_all();
}

static void flush_ptrace_access(struct vm_area_struct *vma, struct page *page,
				unsigned long uaddr, void *kaddr,
				unsigned long len)
{
	if (vma->vm_flags & VM_EXEC) {
		unsigned long addr = (unsigned long)kaddr;
		if (icache_is_aliasing()) {
			__flush_dcache_area(kaddr, len);
			__flush_icache_all();
		} else {
			flush_icache_range(addr, addr + len);
		}
	}
}

/*
 * Copy user data from/to a page which is mapped into a different processes
 * address space.  Really, we want to allow our "user space" model to handle
 * this.
 *
 * Note that this code needs to run on the current CPU.
 */
void copy_to_user_page(struct vm_area_struct *vma, struct page *page,
		       unsigned long uaddr, void *dst, const void *src,
		       unsigned long len)
{
#ifdef CONFIG_SMP
	preempt_disable();
#endif
	memcpy(dst, src, len);
	flush_ptrace_access(vma, page, uaddr, dst, len);
#ifdef CONFIG_SMP
	preempt_enable();
#endif
}

void __sync_icache_dcache(pte_t pte, unsigned long addr)
{
	struct page *page = pte_page(pte);

	/* no flushing needed for anonymous pages */
	if (!page_mapping(page))
		return;

	if (!test_and_set_bit(PG_dcache_clean, &page->flags)) {
		__flush_dcache_area(page_address(page),
				PAGE_SIZE << compound_order(page));
		__flush_icache_all();
	} else if (icache_is_aivivt()) {
		__flush_icache_all();
	}
}

/*
 * This function is called when a page has been modified by the kernel. Mark
 * it as dirty for later flushing when mapped in user space (if executable,
 * see __sync_icache_dcache).
 */
void flush_dcache_page(struct page *page)
{
	if (test_bit(PG_dcache_clean, &page->flags))
		clear_bit(PG_dcache_clean, &page->flags);
}
EXPORT_SYMBOL(flush_dcache_page);

/*
 * Additional functions defined in assembly.
 */
EXPORT_SYMBOL(flush_cache_all);
EXPORT_SYMBOL(flush_icache_range);
