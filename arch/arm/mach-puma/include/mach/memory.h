/*
 * Copyright (C) 2010 Wind River Systems, Inc.
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */


#ifndef __ASM_ARCH_MEMORY_H
#define __ASM_ARCH_MEMORY_H

#include <asm/page.h>
#include <asm/sizes.h>

/*
 * Change the split of virtual addressing space
 * from 3GB kernel / 1GB user
 * to 2GB / 2GB
 */
#define PAGE_OFFSET        UL(0x80000000)
#define TASK_SIZE          UL(0x7f000000)
#define TASK_UNMAPPED_BASE UL(0x40000000)

/*
 * Physical DRAM offset.
 */

#define PHYS_OFFSET        UL(0x40000000)

/*
 * Increase size of DMA-consistent memory region
 */
#define CONSISTENT_DMA_SIZE (14<<20)

#define ISA_DMA_THRESHOLD       (PHYS_OFFSET + SZ_256M - 1)
#define MAX_DMA_ADDRESS         (PAGE_OFFSET + SZ_256M)


/*
 * Bus address is physical address
 */
#define __virt_to_bus(x)        __virt_to_phys(x)
#define __bus_to_virt(x)        __phys_to_virt(x)


#endif
