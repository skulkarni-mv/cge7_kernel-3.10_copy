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

#ifndef __mvPp2DipHw_h__
#define __mvPp2DipHw_h__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "mvTypes.h"
#include "mvCommon.h"
#include "mvOs.h"

#include "common/mvPp2Common.h"
#include "gbe/mvPp2Gbe.h"

#define MV_PP2_DPI_CNTRS		16
#define MV_PP2_DPI_MAX_PKT_SIZE		1024

#define MV_PP2_DPI_Q_SIZE		32

/*********************************** DPI Counters Registers *******************/

#define MV_PP2_DPI_INIT_REG		(MV_PP2_REG_BASE + 0x4800)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_BYTE_VAL_REG		(MV_PP2_REG_BASE + 0x4810)

#define MV_PP2_DPI_BYTE_VAL_OFFS	0
#define MV_PP2_DPI_BYTE_VAL_MAX		256
#define MV_PP2_DPI_BYTE_VAL_MASK	((MV_PP2_DPI_BYTE_VAL_MAX - 1) << MV_PP2_DPI_BYTE_VAL_OFFS)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_CNTR_CTRL_REG	(MV_PP2_REG_BASE + 0x4814)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_CNTR_WIN_REG(cntr)	(MV_PP2_REG_BASE + 0x4840 + (cntr) * 4)

#define MV_PP2_DPI_WIN_OFFSET_OFFS	0
#define MV_PP2_DPI_WIN_OFFSET_BITS	9
#define MV_PP2_DPI_WIN_OFFSET_MAX	((1 << MV_PP2_DPI_WIN_OFFSET_BITS) - 1)
#define MV_PP2_DPI_WIN_OFFSET_ALL_MASK	(MV_PP2_DPI_WIN_OFFSET_MAX << MV_PP2_DPI_WIN_OFFSET_OFFS)
#define MV_PP2_DPI_WIN_OFFSET_MASK(v)   ((v << MV_PP2_DPI_WIN_OFFSET_OFFS) & MV_PP2_DPI_WIN_OFFSET_ALL_MASK)

#define MV_PP2_DPI_WIN_SIZE_OFFS	16
#define MV_PP2_DPI_WIN_SIZE_BITS	8
#define MV_PP2_DPI_WIN_SIZE_MAX		((1 << MV_PP2_DPI_WIN_SIZE_BITS) - 1)
#define MV_PP2_DPI_WIN_SIZE_ALL_MASK	(MV_PP2_DPI_WIN_SIZE_MAX << MV_PP2_DPI_WIN_SIZE_OFFS)
#define MV_PP2_DPI_WIN_SIZE_MASK(v)	((v << MV_PP2_DPI_WIN_SIZE_OFFS) & MV_PP2_DPI_WIN_SIZE_ALL_MASK)
/*---------------------------------------------------------------------------------------------*/

/*********************************** DPI Request / Result Queues Registers *******************/
#define MV_PP2_DPI_Q_SIZE_BITS		12
#define MV_PP2_DPI_Q_SIZE_MAX		((1 < MV_PP2_DPI_Q_SIZE_BITS) - 1)

#define MV_PP2_DPI_Q_ALIGN		(1 << 7)

#define MV_PP2_DPI_REQ_Q_ADDR_REG	(MV_PP2_REG_BASE + 0x4880)
#define MV_PP2_DPI_RES_Q_ADDR_REG	(MV_PP2_REG_BASE + 0x4884)
#define MV_PP2_DPI_Q_SIZE_REG		(MV_PP2_REG_BASE + 0x4888)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_Q_CNTR_BITS          12
#define MV_PP2_DPI_Q_CNTR_MAX           ((1 << MV_PP2_DPI_Q_CNTR_BITS) - 1)

#define MV_PP2_DPI_Q_UPDATE_REG		(MV_PP2_REG_BASE + 0x4890)

#define MV_PP2_DPI_RES_DEC_OCCUP_OFFS	0
#define MV_PP2_DPI_RES_DEC_OCCUP_MASK   (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_RES_DEC_OCCUP_OFFS)

#define MV_PP2_DPI_REQ_ADD_PEND_OFFS	16
#define MV_PP2_DPI_REQ_ADD_PEND_MASK   (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_REQ_ADD_PEND_OFFS)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_Q_STATUS_REG		(MV_PP2_REG_BASE + 0x4894)

#define MV_PP2_DPI_RES_Q_OCCUP_OFFS	0
#define MV_PP2_DPI_RES_Q_OCCUP_MASK     (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_RES_Q_OCCUP_OFFS)

#define MV_PP2_DPI_REQ_Q_PEND_OFFS	16
#define MV_PP2_DPI_REQ_Q_PEND_MASK      (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_REQ_Q_PEND_OFFS)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_Q_INDEX_REG		(MV_PP2_REG_BASE + 0x4898)

#define MV_PP2_DPI_RES_Q_INDEX_OFFS	0
#define MV_PP2_DPI_RES_Q_INDEX_MASK     (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_RES_Q_INDEX_OFFS)

#define MV_PP2_DPI_REQ_Q_INDEX_OFFS	16
#define MV_PP2_DPI_REQ_Q_INDEX_MASK     (MV_PP2_DPI_Q_CNTR_MAX << MV_PP2_DPI_REQ_Q_INDEX_OFFS)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_DPI_Q_PEND_REG		(MV_PP2_REG_BASE + 0x489C)
#define MV_PP2_DPI_Q_THRESH_REG		(MV_PP2_REG_BASE + 0x48A0)
/*---------------------------------------------------------------------------------------------*/

typedef struct pp2_dpi_req_desc {
	MV_U32 bufPhysAddr;
	MV_U32 dataSize;
} PP2_DPI_REQ_DESC;

typedef struct pp2_dpi_res_desc {
	MV_U8 counter[MV_PP2_DPI_CNTRS];
} PP2_DPI_RES_DESC;


/* Update HW with number of DPI RequestQ descriptors to be processed */
static INLINE void mvPp2DpiReqPendAdd(int pend)
{
	MV_U32 regVal;

	regVal = (pend << MV_PP2_DPI_REQ_ADD_PEND_OFFS);
	mvPp2WrReg(MV_PP2_DPI_Q_UPDATE_REG, regVal);
}

/* Get number of DPI requestQ  descriptors are waiting for processing */
static INLINE int mvPp2DpiReqPendGet(void)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_DPI_Q_STATUS_REG);
	regVal = (regVal >> MV_PP2_DPI_REQ_Q_PEND_OFFS);

	return regVal;
}

/* Update HW with number of DPI ResultQ descriptors to be reused */
static INLINE void mvPp2DpiResOccupDec(int occup)
{
	MV_U32 regVal;

	regVal = (occup << MV_PP2_DPI_RES_Q_OCCUP_OFFS);
	mvPp2WrReg(MV_PP2_DPI_Q_UPDATE_REG, regVal);
}

/* Get number of RX descriptors occupied by received packets */
static INLINE int mvPp2DpiResOccupGet(void)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_DPI_Q_STATUS_REG);
	regVal = ((regVal & MV_PP2_DPI_RES_Q_OCCUP_MASK) >> MV_PP2_DPI_RES_Q_OCCUP_OFFS);

	return regVal;
}

static INLINE int mvPp2DpiReqNextIdx(void)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_DPI_Q_INDEX_REG);
	regVal = ((regVal & MV_PP2_DPI_REQ_Q_INDEX_MASK) >> MV_PP2_DPI_REQ_Q_INDEX_OFFS);

	return regVal;
}

static INLINE int mvPp2DpiResNextIdx(void)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_DPI_Q_INDEX_REG);
	regVal = ((regVal & MV_PP2_DPI_RES_Q_INDEX_MASK) >> MV_PP2_DPI_RES_Q_INDEX_OFFS);

	return regVal;
}

static INLINE MV_BOOL mvPp2DpiReqIsFull(MV_PP2_QUEUE_CTRL *pQueueCtrl)
{
	if ((pQueueCtrl->lastDesc + 1) - mvPp2DpiReqPendGet() > 0)
		return MV_FALSE;

	return MV_TRUE;
}

static INLINE MV_BOOL mvPp2DpiResIsEmpty(MV_PP2_QUEUE_CTRL *pQueueCtrl)
{
	if (mvPp2DpiResOccupGet() > 0)
		return MV_FALSE;

	return MV_TRUE;
}

/* Public function prototypes */
void	  mvPp2DpiInit(void);
void	  mvPp2DpiRegs(void);
MV_STATUS mvPp2DpiCntrWinSet(int cntr, int offset, int size);
MV_STATUS mvPp2DpiByteConfig(MV_U8 byte, MV_U16 cntrs_map);
MV_STATUS mvPp2DpiCntrByteSet(int cntr, MV_U8 byte, int en);
MV_STATUS mvPp2DpiCntrDisable(int cntr);

void	  mvPp2DpiQueueShow(int mode);
MV_STATUS mvPp2DpiQueuesCreate(int num);
MV_STATUS mvPp2DpiQueuesDelete(void);

MV_STATUS mvPp2DpiRequestSet(unsigned long paddr, int size);
MV_STATUS mvPp2DpiResultGet(MV_U8 *counters, int num);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __mvPp2DipHw_h__ */
