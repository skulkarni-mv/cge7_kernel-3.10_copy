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
#include "mvList.h"
#include "mv802_3.h"
#include "common/mvPp2Common.h"
#include "mvBmRegs.h"

typedef struct {
	int valid;
	int longPool;
	int shortPool;
	int longBufNum;
	int shortBufNum;
	int hwfLongPool;
	int hwfShortPool;
	int hwfLongBufNum;
	int hwfShortBufNum;

} MV_BM_CONFIG;

typedef struct {
	int id;
	int pool;
	int refCount;
	int maxShared;
	int maxGrntd;
} MV_BM_QSET;

typedef struct {
	int		pool;
	int		capacity;
	int		bufNum;
	int		bufSize;
	MV_U32		*pVirt;
	MV_ULONG	physAddr;
	int		maxShared;
	MV_BM_QSET	*defQset; /* default qset */
	MV_BM_QSET	*mcQset;  /* MC qset */
	MV_LIST_ELEMENT	*qsets;   /* list of qsets attached to this pool */
} MV_BM_POOL;

/* defines */

/* bits[8-9] of address define pool 0-3 */
#define BM_POOL_ACCESS_OFFS     8

/* Qsets 0-7 reserved for MC */
#define MV_BM_POOL_QSET_BASE		8
#define MV_BM_QSET_MAX			128
#define MV_BM_QSET_PRIO_MAX		255

/* INLINE functions */
static INLINE void mvBmPoolPut(int pool, MV_U32 bufPhysAddr, MV_U32 bufVirtAddr)
{
	mvPp2WrReg(MV_BM_VIRT_RLS_REG, bufVirtAddr);
	mvPp2WrReg(MV_BM_PHY_RLS_REG(pool), bufPhysAddr);
}

static INLINE void mvBmPoolMcPut(int pool, MV_U32 bufPhysAddr, MV_U32 bufVirtAddr, int mcId, int isForce)
{
	MV_U32 regVal = 0;

	regVal |= ((mcId << MV_BM_MC_ID_OFFS) & MV_BM_MC_ID_MASK);
	if (isForce)
		regVal |= MV_BM_FORCE_RELEASE_MASK;

	mvPp2WrReg(MV_BM_MC_RLS_REG, regVal);
	mvBmPoolPut(pool, bufPhysAddr | MV_BM_PHY_RLS_MC_BUFF_MASK, bufVirtAddr);
}

static INLINE void mvBmPoolQsetPut(int pool, MV_U32 bufPhysAddr, MV_U32 bufVirtAddr, int qset, int isGrntd)
{
	MV_U32 regVal, bufPhysAddrPrio;

	regVal = (qset << MV_BM_RLS_QSET_NUM_OFFS) & MV_BM_RLS_QSET_NUM_MASK;
	mvPp2WrReg(MV_BM_QSET_RLS_REG, regVal);

	bufPhysAddrPrio = bufPhysAddr | MV_BM_PHY_RLS_PRIO_EN_MASK;
	if (isGrntd)
		bufPhysAddrPrio |= MV_BM_PHY_RLS_GRNTD_MASK;

	mvBmPoolPut(pool, bufPhysAddrPrio, bufVirtAddr);
}

static INLINE void mvBmPoolQsetMcPut(int pool, MV_U32 bufPhysAddr, MV_U32 bufVirtAddr,
					int qset, int isGrntd, int mcId, int isForce)
{
	MV_U32 regVal, bufPhysAddrPrio;

	regVal = (qset << MV_BM_RLS_QSET_NUM_OFFS) & MV_BM_RLS_QSET_NUM_MASK;
	mvPp2WrReg(MV_BM_QSET_RLS_REG, regVal);

	bufPhysAddrPrio = bufPhysAddr | MV_BM_PHY_RLS_PRIO_EN_MASK;
	if (isGrntd)
		bufPhysAddrPrio |= MV_BM_PHY_RLS_GRNTD_MASK;

	mvBmPoolMcPut(pool, bufPhysAddrPrio, bufVirtAddr, mcId, isForce);
}

static INLINE MV_U32 mvBmPoolGet(int pool, MV_U32 *bufPhysAddr)
{
	MV_U32 bufVirtAddr, physAddr;

	physAddr = mvPp2RdReg(MV_BM_PHY_ALLOC_REG(pool)); /* read physical address */
	bufVirtAddr = mvPp2RdReg(MV_BM_VIRT_ALLOC_REG); /* return virtual address */
	if (bufPhysAddr)
		*bufPhysAddr = physAddr;

	return bufVirtAddr;
}

/* prototypes */
MV_STATUS mvBmInit(void);
MV_STATUS mvBmPoolControl(int pool, MV_COMMAND cmd);
MV_STATE  mvBmPoolStateGet(int pool);
void      mvBmPoolEnable(int pool);
void      mvBmPoolDisable(int pool);
MV_BOOL   mvBmPoolIsEnabled(int pool);
MV_STATUS mvBmPoolInit(int pool, MV_U32 *virtPoolBase, MV_ULONG physPoolBase, int capacity);
MV_STATUS mvBmPoolBufNumUpdate(int pool, int buf_num, int add);
MV_STATUS mvBmPoolBufSizeSet(int pool, int buf_size);
void      mvBmRegs(void);
void      mvBmStatus(void);
void      mvBmPoolDump(int pool, int mode);
void      mvBmV1PoolDropCntDump(int pool);
void      mvBmPoolPrint(int pool);

/* BM priority API */
MV_STATUS mvBmQsetCreate(int qset, int pool);
MV_STATUS mvBmQsetDelete(int qset);
void mvBmQsetConfigDumpAll(void);
int mvBmDefaultQsetNumGet(int pool);
void mvBmQueueMapDumpAll(void);
MV_STATUS mvBmQsetShow(int qset);

MV_STATUS mvBmRxqToQsetLongClean(int queue);
MV_STATUS mvBmRxqToQsetShortClean(int queue);
MV_STATUS mvBmTxqToQsetLongClean(int queue);
MV_STATUS mvBmTxqToQsetShortClean(int queue);

MV_STATUS mvBmRxqToQsetLongSet(int queue, int qset);
MV_STATUS mvBmRxqToQsetShortSet(int queue, int qset);
MV_STATUS mvBmTxqToQsetLongSet(int queue, int qset);
MV_STATUS mvBmTxqToQsetShortSet(int queue, int qset);
int mvBmRxqToQsetLongGet(int queue);
int mvBmRxqToQsetShortGet(int queue);
int mvBmTxqToQsetLongGet(int queue);
int mvBmTxqToQsetShortGet(int queue);

MV_STATUS mvBmQsetBuffMaxSet(int qset, int maxGrntd, int maxShared);
MV_STATUS mvBmQsetBuffCountersSet(int qset, int cntrGrntd, int cntrShared);
MV_STATUS mvBmPoolBuffNumSet(int pool, int buffNum);
MV_STATUS mvBmPoolBuffCountersSet(int pool, int cntrGrntd, int cntrShared);

#endif /* __mvBm_h__ */

