/*
 * Copyright 2001 MontaVista Software Inc.
 * Author: Matt Porter <mporter@mvista.com>
 *
 * Copyright (C) 2009 Lemote, Inc.
 * Author: Wu Zhangjin <wuzhangjin@gmail.com>
 *
 * This program is free software; you can redistribute	it and/or modify it
 * under  the terms of	the GNU General	 Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/elf.h>

#include <asm/addrspace.h>
#include "vmlinux_bin_size.h"

/*
 * These two variables specify the free mem region
 * that can be used for temporary malloc area
 */
unsigned long free_mem_ptr;
unsigned long free_mem_end_ptr;

/* The linker tells us where the image is. */
extern unsigned char __image_begin, __image_end;

/* debug interfaces  */
extern void puts(const char *s);
extern void puthex(unsigned long long val);

void error(char *x)
{
	puts("\n\n");
	puts(x);
	puts("\n\n -- System halted");

	while (1)
		;	/* Halt */
}

/* activate the code for pre-boot environment */
#define STATIC static

#ifdef CONFIG_KERNEL_GZIP
void *memcpy(void *dest, const void *src, size_t n)
{
	int i;
	const char *s = src;
	char *d = dest;

	for (i = 0; i < n; i++)
		d[i] = s[i];
	return dest;
}
#include "../../../../lib/decompress_inflate.c"
#endif

#ifdef CONFIG_KERNEL_BZIP2
void *memset(void *s, int c, size_t n)
{
	int i;
	char *ss = s;

	for (i = 0; i < n; i++)
		ss[i] = c;
	return s;
}
#include "../../../../lib/decompress_bunzip2.c"
#endif

#ifdef CONFIG_KERNEL_LZMA
#include "../../../../lib/decompress_unlzma.c"
#endif

#ifdef CONFIG_KERNEL_LZO
#include "../../../../lib/decompress_unlzo.c"
#endif

#ifdef CONFIG_RANDOMIZE_BASE
struct rel {
	unsigned long long offset;
	unsigned int rel_type;
} __attribute__((packed));

void handle_relocations(void *output_addr, unsigned long load_offset)
{
	unsigned char *ptr;
	struct rel *rel_ptr;
	unsigned long insnlo, insnhi, val, vallo;
	unsigned long long insnlo_addr, location;

	puts("Performing relocations...\n");

	ptr = output_addr;

	ptr += VMLINUX_BIN_SIZE; /*Go to the start of relocations*/
	rel_ptr = (struct rel *)ptr;
	while (rel_ptr->offset) {
		location = rel_ptr->offset + load_offset;

		switch (rel_ptr->rel_type) {
		case R_MIPS_HI16:
			insnlo_addr = location + 4;
			insnlo = *((int *)insnlo_addr);
			vallo = ((insnlo & 0xffff) ^ 0x8000) - 0x8000;
			insnhi = *((int *)location);
			val = ((insnhi & 0xffff) << 16) + vallo;
			val += load_offset;
			val = ((val >> 16) + ((val & 0x8000) != 0)) & 0xffff;
			insnhi = (insnhi & ~0xffff) | val;
			*((int *)location) = insnhi; /*Replace hi*/
			val = load_offset + vallo;
			insnlo = (insnlo & ~0xffff) | (val & 0xffff);
			*((int *)insnlo_addr) = insnlo; /*Replace lo*/
			break;

		case R_MIPS_64:
			(*(unsigned long long *)location) += load_offset;
			break;

		case R_MIPS_26:
			*((int *)location) = (*((int *)location) & ~0x03ffffff) |
					((*((int *)location) + (load_offset >> 2)) & 0x03ffffff);
			break;

		case R_MIPS_LO16:
		break; /*Nothing to do, we would have already handled this in HI_16*/
		default:
		break;
		}
		rel_ptr++;
	}
}

/* The region for random loading is selected in CKSEG0 such that the area between
 * the fist load address and the last load address + vmlinux size does not corrupt
 * the bootloader passed data and  the compressed vmlinuz. Also leave enough safe
 * space for OCTEON_VMLINUZ_BOOT_WORD and OCTEON_VMLINUX_LOAD_OFFSET (See
 * compressed/head.S). All the load addresses are 1MB aligned.
 */

#define VMLINUX_LOAD_ADDRESS_FIRST	VMLINUX_LOAD_ADDRESS
#define VMLINUX_LOAD_ADDRESS_LAST	CONFIG_RANDOMIZE_BASE_MAX_OFFSET
#define VMLINUX_LOAD_SLOTS	(VMLINUX_LOAD_ADDRESS_LAST - VMLINUX_LOAD_ADDRESS_FIRST) >> 20

unsigned long long find_random_address(void)
{
	unsigned long count;
	unsigned long random;

	count =  read_c0_count();

	/* Find a random load offset and add it to the link address */
	random = count % ((VMLINUX_LOAD_SLOTS) + 1);

	return VMLINUX_LOAD_ADDRESS + (random << 20);
}
#endif

unsigned long decompress_kernel(unsigned long boot_heap_start)
{
	unsigned long zimage_start, zimage_size;
	unsigned long long load_address = VMLINUX_LOAD_ADDRESS_ULL;
	unsigned long load_offset = 0;

	zimage_start = (unsigned long)(&__image_begin);
	zimage_size = (unsigned long)(&__image_end) -
	    (unsigned long)(&__image_begin);

	puts("zimage at:     ");
	puthex(zimage_start);
	puts(" ");
	puthex(zimage_size + zimage_start);
	puts("\n");

	/* This area are prepared for mallocing when decompressing */
	free_mem_ptr = boot_heap_start;
	free_mem_end_ptr = boot_heap_start + BOOT_HEAP_SIZE;

#ifndef CONFIG_RANDOMIZE_BASE
	/* Display standard Linux/MIPS boot prompt */
	puts("Uncompressing Linux at load address ");
	puthex(VMLINUX_LOAD_ADDRESS_ULL);
	puts("\n");
#else
	puts("Randomizing Linux load address...\n");
	load_address = find_random_address();
	load_offset = load_address - VMLINUX_LOAD_ADDRESS_ULL;
#endif

	/* Decompress the kernel with according algorithm */
	decompress((char *)zimage_start, zimage_size, 0, 0,
		   (void *)load_address, 0, error);
#ifdef CONFIG_RANDOMIZE_BASE
	if (load_offset)
		handle_relocations((void *)load_address, load_offset);
#endif

	/* FIXME: should we flush cache here? */
	puts("Now, booting the kernel...\n");

	return load_offset;
}
