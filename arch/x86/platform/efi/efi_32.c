/*
 * Extensible Firmware Interface
 *
 * Based on Extensible Firmware Interface Specification version 1.0
 *
 * Copyright (C) 1999 VA Linux Systems
 * Copyright (C) 1999 Walt Drummond <drummond@valinux.com>
 * Copyright (C) 1999-2002 Hewlett-Packard Co.
 *	David Mosberger-Tang <davidm@hpl.hp.com>
 *	Stephane Eranian <eranian@hpl.hp.com>
 *
 * All EFI Runtime Services are not implemented yet as EFI only
 * supports physical mode addressing on SoftSDV. This is to be fixed
 * in a future version.  --drummond 1999-07-20
 *
 * Implemented EFI runtime services and virtual mode calls.  --davidm
 *
 * Goutham Rao: <goutham.rao@intel.com>
 *	Skip non-WB memory and ignore empty memory ranges.
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/ioport.h>
#include <linux/efi.h>

#include <asm/io.h>
#include <asm/desc.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/tlbflush.h>
#include <asm/efi.h>

/*
 * To make EFI call EFI runtime service in physical addressing mode we need
 * prolog/epilog before/after the invocation to claim the EFI runtime service
 * handler exclusively and to duplicate a memory mapping in low memory space,
 * say 0 - 3G.
 */

void efi_sync_low_kernel_mappings(void) {}
void efi_setup_page_tables(void) {}

void __init efi_map_region(efi_memory_desc_t *md)
{
	old_map_region(md);
}

void __init efi_map_region_fixed(efi_memory_desc_t *md) {}

pgd_t * __init efi_call_phys_prolog(void)
{
	struct desc_ptr gdt_descr;
	pgd_t *save_pgd;

#ifdef CONFIG_PAX_KERNEXEC
	struct desc_struct d;
#endif

        /* Current pgd is swapper_pg_dir, we'll restore it later: */
        save_pgd = swapper_pg_dir;
	load_cr3(initial_page_table);
	__flush_tlb_all();

#ifdef CONFIG_PAX_KERNEXEC
	pack_descriptor(&d, 0, 0xFFFFF, 0x9B, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_CS, &d, DESCTYPE_S);
	pack_descriptor(&d, 0, 0xFFFFF, 0x93, 0xC);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_DS, &d, DESCTYPE_S);
#endif

	gdt_descr.address = __pa(get_cpu_gdt_table(0));
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);

	return save_pgd;
}

void __init efi_call_phys_epilog(pgd_t *save_pgd)
{
	struct desc_ptr gdt_descr;

#ifdef CONFIG_PAX_KERNEXEC
	struct desc_struct d;

	memset(&d, 0, sizeof d);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_CS, &d, DESCTYPE_S);
	write_gdt_entry(get_cpu_gdt_table(0), GDT_ENTRY_KERNEXEC_EFI_DS, &d, DESCTYPE_S);
#endif

	gdt_descr.address = (unsigned long)get_cpu_gdt_table(0);
	gdt_descr.size = GDT_SIZE - 1;
	load_gdt(&gdt_descr);

#ifdef CONFIG_PAX_PER_CPU_PGD
	load_cr3(get_cpu_pgd(smp_processor_id(), kernel));
#else
	load_cr3(save_pgd);
#endif

	__flush_tlb_all();
}
