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

#ifndef __mvBm_h__
#define __mvBm_h__

/* includes */
#include "mvTypes.h"
#include "mvCommon.h"
#include "mvStack.h"
#include "mv802_3.h"

#include "mvBmRegs.h"

typedef struct {
	int valid;
	int longPool;
	int shortPool;
	int longBufNum;
	int shortBufNum;

} MV_BM_CONFIG;

typedef struct {
	int         pool;
	int         capacity;
	int         bufNum;
	int         bufSize;
	MV_U32      *pVirt;
	MV_ULONG    physAddr;
} MV_BM_POOL;

extern MV_U8 *mvBmVirtBase;
/* defines */

/* bits[8-9] of address define pool 0-3 */
#define BM_POOL_ACCESS_OFFS     8

/* INLINE functions */
static INLINE void mvBmPoolPut(int poolId, MV_ULONG bufPhysAddr)
{
	volatile MV_U32 *poolAddr = (MV_U32 *)((unsigned)mvBmVirtBase | (poolId << BM_POOL_ACCESS_OFFS));

	*poolAddr = MV_32BIT_LE((MV_U32)bufPhysAddr);
}

static INLINE MV_ULONG mvBmPoolGet(int poolId)
{
	volatile MV_U32 *poolAddr = (MV_U32 *)((unsigned)mvBmVirtBase | (poolId << BM_POOL_ACCESS_OFFS));
	MV_U32	bufPhysAddr = *poolAddr;

	return (MV_ULONG)(MV_32BIT_LE(bufPhysAddr));
}

/* prototypes */
MV_STATUS mvNetaBmInit(MV_U8 *virtBase);
void      mvNetaBmRegsInit(void);
void      mvNetaBmConfigSet(MV_U32 mask);
void      mvNetaBmConfigClear(MV_U32 mask);
MV_STATUS mvNetaBmControl(MV_COMMAND cmd);
MV_STATE  mvNetaBmStateGet(void);
void      mvNetaBmPoolTargetSet(int pool, MV_U8 targetId, MV_U8 attr);
void      mvNetaBmPoolEnable(int pool);
void      mvNetaBmPoolDisable(int pool);
MV_BOOL   mvNetaBmPoolIsEnabled(int pool);
MV_STATUS mvNetaBmPoolInit(int pool, void *virtPoolBase, MV_ULONG physPoolBase, int capacity);
MV_STATUS mvNetaBmPoolBufNumUpdate(int pool, int buf_num, int add);
MV_STATUS mvNetaBmPoolBufferSizeSet(int pool, int buf_size);
void      mvNetaBmRegs(void);
void      mvNetaBmStatus(void);
void      mvNetaBmPoolDump(int pool, int mode);
void      mvNetaBmPoolPrint(int pool);

#endif /* __mvBm_h__ */
