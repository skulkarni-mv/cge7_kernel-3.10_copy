/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.

*******************************************************************************/

/*******************************************************************************
* mvOsCpuArchLib.c - Marvell CPU architecture library
*
* DESCRIPTION:
*       This library introduce Marvell API for OS dependent CPU architecture
*       APIs. This library introduce single CPU architecture services APKI
*       cross OS.
*
* DEPENDENCIES:
*       None.
*
*******************************************************************************/

/* includes */
#include "mvOs.h"

static MV_U32 read_p15_c0(void);
static MV_U32 read_p15_c1(void);

/* defines  */
#define ARM_ID_REVISION_OFFS	0
#define ARM_ID_REVISION_MASK	(0xf << ARM_ID_REVISION_OFFS)

#define ARM_ID_PART_NUM_OFFS	4
#define ARM_ID_PART_NUM_MASK	(0xfff << ARM_ID_PART_NUM_OFFS)

#define ARM_ID_ARCH_OFFS	16
#define ARM_ID_ARCH_MASK	(0xf << ARM_ID_ARCH_OFFS)

#define ARM_ID_VAR_OFFS		20
#define ARM_ID_VAR_MASK		(0xf << ARM_ID_VAR_OFFS)

#define ARM_ID_ASCII_OFFS	24
#define ARM_ID_ASCII_MASK	(0xff << ARM_ID_ASCII_OFFS)

#define ARM_FEATURE_THUMBEE_OFFS	12
#define ARM_FEATURE_THUMBEE_MASK	(0xf << ARM_FEATURE_THUMBEE_OFFS)


void *mvOsIoCachedMalloc(void *osHandle, MV_U32 size, MV_ULONG *pPhyAddr,
			  MV_U32 *memHandle)
{
	void *p = kmalloc(size, GFP_ATOMIC);
	dma_addr_t dma_addr;
	dma_addr = dma_map_single(osHandle, p, 0, DMA_BIDIRECTIONAL);
	*pPhyAddr = (MV_ULONG)(dma_addr & 0xFFFFFFFF);
	return p;
}
EXPORT_SYMBOL(mvOsIoCachedMalloc);
void *mvOsIoUncachedMalloc(void *osHandle, MV_U32 size, MV_ULONG *pPhyAddr,
			    MV_U32 *memHandle)
{
	dma_addr_t dma_addr;
	void *ptr = dma_alloc_coherent(osHandle, size, &dma_addr, GFP_KERNEL);
	*pPhyAddr = (MV_ULONG)(dma_addr & 0xFFFFFFFF);
	return ptr;
}
EXPORT_SYMBOL(mvOsIoUncachedMalloc);
void mvOsIoUncachedFree(void *osHandle, MV_U32 size, MV_ULONG phyAddr, void *pVirtAddr,
			 MV_U32 memHandle)
{
	dma_free_coherent(osHandle, size, pVirtAddr, (dma_addr_t)phyAddr);
}

void mvOsIoCachedFree(void *osHandle, MV_U32 size, MV_ULONG phyAddr, void *pVirtAddr,
		       MV_U32 memHandle)
{
	return kfree(pVirtAddr);
}
EXPORT_SYMBOL(mvOsIoCachedFree);
int mvOsRand(void)
{
	int rand;
	get_random_bytes(&rand, sizeof(rand));
	return rand;
}

/*******************************************************************************
* mvOsCpuVerGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Revision
*
*******************************************************************************/
MV_U32 mvOsCpuRevGet(MV_VOID)
{
	return (read_p15_c0() & ARM_ID_REVISION_MASK) >> ARM_ID_REVISION_OFFS;
}
/*******************************************************************************
* mvOsCpuPartGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Part number
*
*******************************************************************************/
MV_U32 mvOsCpuPartGet(MV_VOID)
{
	return (read_p15_c0() & ARM_ID_PART_NUM_MASK) >> ARM_ID_PART_NUM_OFFS;
}
/*******************************************************************************
* mvOsCpuArchGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Architicture number
*
*******************************************************************************/
MV_U32 mvOsCpuArchGet(MV_VOID)
{
	return (read_p15_c0() & ARM_ID_ARCH_MASK) >> ARM_ID_ARCH_OFFS;
}
/*******************************************************************************
* mvOsCpuVarGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Variant number
*
*******************************************************************************/
MV_U32 mvOsCpuVarGet(MV_VOID)
{
	return (read_p15_c0() & ARM_ID_VAR_MASK) >> ARM_ID_VAR_OFFS;
}
/*******************************************************************************
* mvOsCpuAsciiGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Variant number
*
*******************************************************************************/
MV_U32 mvOsCpuAsciiGet(MV_VOID)
{
	return (read_p15_c0() & ARM_ID_ASCII_MASK) >> ARM_ID_ASCII_OFFS;
}

/*******************************************************************************
* mvOsCpuThumbEEGet() -
*
* DESCRIPTION:
*
* INPUT:
*       None.
*
* OUTPUT:
*       None.
*
* RETURN:
*       32bit CPU Variant number
*
*******************************************************************************/
MV_U32 mvOsCpuThumbEEGet(MV_VOID)
{
	return (read_p15_c1() & ARM_FEATURE_THUMBEE_MASK) >> ARM_FEATURE_THUMBEE_OFFS;
}

/*
static unsigned long read_p15_c0 (void)
*/
/* read co-processor 15, register #0 (ID register) */
static MV_U32 read_p15_c0 (void)
{
	MV_U32 value;

	__asm__ __volatile__(
		"mrc	p15, 0, %0, c0, c0, 0   @ read control reg\n"
		: "=r" (value)
		:
		: "memory");

	return value;
}

/* read co-processor 15, register #1 (Feature 0) */
static MV_U32 read_p15_c1 (void)
{
	MV_U32 value;

	__asm__ __volatile__(
						 "mrc	p15, 0, %0, c0, c1, 0   @ read feature0 reg\n"
	: "=r" (value)
	:
	: "memory");

	return value;
}
