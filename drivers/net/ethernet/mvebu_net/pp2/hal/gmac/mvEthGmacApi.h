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
#ifndef __mvEthGmac_h__
#define __mvEthGmac_h__

#include "mvEthGmacRegs.h"

#include "mvTypes.h"
#include "mvCommon.h"
#include "mvOs.h"

typedef enum {
	MV_ETH_SPEED_AN,
	MV_ETH_SPEED_10,
	MV_ETH_SPEED_100,
	MV_ETH_SPEED_1000,
	MV_ETH_SPEED_2000,
} MV_ETH_PORT_SPEED;

typedef enum {
	MV_ETH_DUPLEX_AN,
	MV_ETH_DUPLEX_HALF,
	MV_ETH_DUPLEX_FULL
} MV_ETH_PORT_DUPLEX;

typedef enum {
	MV_ETH_FC_AN_NO,
	MV_ETH_FC_AN_SYM,
	MV_ETH_FC_AN_ASYM,
	MV_ETH_FC_DISABLE,
	MV_ETH_FC_ENABLE,
	MV_ETH_FC_ACTIVE

} MV_ETH_PORT_FC;

typedef struct eth_link_status {
	MV_BOOL			linkup;
	MV_ETH_PORT_SPEED	speed;
	MV_ETH_PORT_DUPLEX	duplex;
	MV_ETH_PORT_FC		rxFc;
	MV_ETH_PORT_FC		txFc;

} MV_ETH_PORT_STATUS;

/***************************************************************************/
/*                          Inline functions                               */
/***************************************************************************/
static INLINE void mvGmacIsrSummaryMask(MV_VOID)
{
	MV_REG_WRITE(ETH_ISR_SUM_MASK_REG, 0);
}

static INLINE void mvGmacIsrSummaryUnmask(MV_VOID)
{
	MV_REG_WRITE(ETH_ISR_SUM_MASK_REG, ETH_ISR_SUM_PORT0_MASK |
		     ETH_ISR_SUM_PORT1_MASK | 0x20 /* magic bit */);
}

static INLINE MV_U32 mvGmacIsrSummaryCauseGet(MV_VOID)
{
	return MV_REG_READ(ETH_ISR_SUM_CAUSE_REG);
}

static INLINE MV_U32 mvGmacPortIsrCauseGet(int port)
{
	return MV_REG_READ(ETH_PORT_ISR_CAUSE_REG(port));
}

static INLINE MV_VOID mvGmacPortIsrMask(int port)
{
	MV_REG_WRITE(ETH_PORT_ISR_MASK_REG(port), 0);
}

static INLINE MV_VOID mvGmacPortIsrUnmask(int port)
{
	MV_REG_WRITE(ETH_PORT_ISR_MASK_REG(port), ETH_PORT_LINK_CHANGE_MASK);
}

static INLINE MV_VOID mvGmacPortSumIsrMask(int port)
{
	MV_REG_WRITE(ETH_PORT_ISR_SUM_MASK_REG(port), 0);
}

static INLINE MV_VOID mvGmacPortSumIsrUnmask(int port)
{
	MV_REG_WRITE(ETH_PORT_ISR_SUM_MASK_REG(port), ETH_PORT_ISR_SUM_INTERN_MASK);
}


void mvGmacPhyPollEnable(int enable);
void mvGmacDefaultsSet(int port);
void mvGmacPortEnable(int port);
void mvGmacPortDisable(int port);
void mvGmacPortMhSet(int port, int enable);
void mvGmacPortPeriodicXonSet(int port, int enable);
MV_BOOL mvGmacPortIsLinkUp(int port);
MV_STATUS mvGmacLinkStatus(int port, MV_ETH_PORT_STATUS *pStatus);
void mvGmacPortLbSet(int port, int isGmii, int isPcsEn);
void mvGmacPortResetSet(int port, MV_BOOL setReset);
void mvGmacPortPowerUp(int port, MV_BOOL isSgmii, MV_BOOL isRgmii);
void mvGmacPortPowerDown(int port);
char *mvGmacSpeedStrGet(MV_ETH_PORT_SPEED speed);

/******************************************************************************/
/*                          Port Configuration functions                      */
/******************************************************************************/
MV_STATUS mvGmacMaxRxSizeSet(int port, int maxRxSize);
MV_STATUS mvGmacForceLinkModeSet(int portNo, MV_BOOL force_link_up, MV_BOOL force_link_down);
MV_STATUS mvGmacSpeedDuplexSet(int portNo, MV_ETH_PORT_SPEED speed, MV_ETH_PORT_DUPLEX duplex);
MV_STATUS mvGmacSpeedDuplexGet(int portNo, MV_ETH_PORT_SPEED *speed, MV_ETH_PORT_DUPLEX *duplex);
MV_STATUS mvGmacFlowCtrlSet(int port, MV_ETH_PORT_FC flowControl);
MV_STATUS mvGmacFlowCtrlGet(int port, MV_ETH_PORT_FC *pFlowCntrl);
MV_STATUS mvGmacPortLinkSpeedFlowCtrl(int port, MV_ETH_PORT_SPEED speed,
				     int forceLinkUp);

/******************************************************************************/
/*                         PHY Control Functions                              */
/******************************************************************************/
void mvGmacPhyAddrSet(int port, int phyAddr);
int mvGmacPhyAddrGet(int port);

/****************************************/
/*        MIB counters		       	*/
/****************************************/
MV_U32 mvGmacMibCounterRead(int port, unsigned int mibOffset, MV_U32 *pHigh32);
void mvGmacMibCountersClear(int port);
void mvGmacMibCountersShow(int port);
void mvGmacPortRegs(int port);
void mvGmacLmsRegs(void);

#endif /* __mvGmacGmac_h__ */
