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

#include "mvCommon.h"  /* Should be included before mvSysHwConfig */
#include "mvTypes.h"
#include "mvDebug.h"
#include "mvOs.h"

#include "common/mvPp2Common.h"
#include "gbe/mvPp2Gbe.h"
#include "mvPp2PlcrHw.h"


void        mvPp2PlcrHwRegs(void)
{
	int    i;
	MV_U32 regVal;

	mvOsPrintf("\n[PLCR registers: %d policers]\n", MV_PP2_PLCR_NUM);

	mvPp2PrintReg(MV_PP2_PLCR_MODE_REG,	"MV_PP2_PLCR_MODE_REG");
	mvPp2PrintReg(MV_PP2_PLCR_BASE_PERIOD_REG,	"MV_PP2_PLCR_BASE_PERIOD_REG");
	mvPp2PrintReg(MV_PP2_PLCR_MIN_PKT_LEN_REG,	"MV_PP2_PLCR_MIN_PKT_LEN_REG");
	mvPp2PrintReg(MV_PP2_PLCR_EDROP_EN_REG,		"MV_PP2_PLCR_EDROP_EN_REG");

	for (i = 0; i < MV_PP2_PLCR_NUM; i++) {
		mvOsPrintf("\n[Policer %d registers]\n", i);

		mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, i);
		mvPp2PrintReg(MV_PP2_PLCR_COMMIT_TOKENS_REG, "MV_PP2_PLCR_COMMIT_TOKENS_REG");
		mvPp2PrintReg(MV_PP2_PLCR_EXCESS_TOKENS_REG, "MV_PP2_PLCR_EXCESS_TOKENS_REG");
		mvPp2PrintReg(MV_PP2_PLCR_BUCKET_SIZE_REG,   "MV_PP2_PLCR_BUCKET_SIZE_REG");
		mvPp2PrintReg(MV_PP2_PLCR_TOKEN_CFG_REG,     "MV_PP2_PLCR_TOKEN_CFG_REG");
	}

	mvOsPrintf("\nEarly Drop Thresholds for SW and HW forwarding\n");
	for (i = 0; i < MV_PP2_V1_PLCR_EDROP_THRESH_NUM; i++) {
		mvPp2PrintReg2(MV_PP2_V1_PLCR_EDROP_CPU_TR_REG(i),   "MV_PP2_V1_PLCR_EDROP_CPU_TR_REG", i);
		mvPp2PrintReg2(MV_PP2_V1_PLCR_EDROP_HWF_TR_REG(i),   "MV_PP2_V1_PLCR_EDROP_HWF_TR_REG", i);
	}
	mvOsPrintf("\nPer RXQ: Non zero early drop thresholds\n");
	for (i = 0; i < MV_PP2_RXQ_TOTAL_NUM; i++) {
		mvPp2WrReg(MV_PP2_PLCR_EDROP_RXQ_REG, i);
		regVal = mvPp2RdReg(MV_PP2_PLCR_EDROP_RXQ_TR_REG);
		if (regVal != 0)
			mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", "MV_PP2_PLCR_EDROP_RXQ_TR_REG", MV_PP2_PLCR_EDROP_RXQ_TR_REG, regVal);
	}
	mvOsPrintf("\nPer TXQ: Non zero Early Drop Thresholds\n");
	for (i = 0; i < MV_PP2_TXQ_TOTAL_NUM; i++) {
		mvPp2WrReg(MV_PP2_PLCR_EDROP_TXQ_REG, i);
		regVal = mvPp2RdReg(MV_PP2_PLCR_EDROP_TXQ_TR_REG);
		if (regVal != 0)
			mvOsPrintf("  %-32s: 0x%x = 0x%08x\n", "MV_PP2_PLCR_EDROP_TXQ_TR_REG", MV_PP2_PLCR_EDROP_TXQ_TR_REG, regVal);
	}
}

static void        mvPp2PlcrHwDumpTitle(void)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_PLCR_BASE_PERIOD_REG);
	mvOsPrintf("PLCR status: %d policers, period=%d (%s), ",
				MV_PP2_PLCR_NUM, regVal & MV_PP2_PLCR_BASE_PERIOD_ALL_MASK,
				regVal & MV_PP2_PLCR_ADD_TOKENS_EN_MASK ? "En" : "Dis");

	regVal = mvPp2RdReg(MV_PP2_PLCR_EDROP_EN_REG);
	mvOsPrintf("edrop=%s, ", regVal & MV_PP2_PLCR_EDROP_EN_MASK ? "En" : "Dis");

	regVal = mvPp2RdReg(MV_PP2_PLCR_MIN_PKT_LEN_REG);
	mvOsPrintf("min_pkt=%d bytes\n", (regVal & MV_PP2_PLCR_MIN_PKT_LEN_ALL_MASK) >> MV_PP2_PLCR_MIN_PKT_LEN_OFFS);

	mvOsPrintf("PLCR: enable period  unit   type  tokens  color  c_size  e_size  c_tokens  e_tokens\n");
}

static void        mvPp2PlcrHwDump(int plcr)
{
	int units, type, tokens, color, enable;
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);
	mvOsPrintf("%3d:  ", plcr);


	regVal = mvPp2RdReg(MV_PP2_PLCR_TOKEN_CFG_REG);
	units = regVal & MV_PP2_PLCR_TOKEN_UNIT_MASK;
	color = regVal & MV_PP2_PLCR_COLOR_MODE_MASK;
	type = (regVal & MV_PP2_PLCR_TOKEN_TYPE_ALL_MASK) >> MV_PP2_PLCR_TOKEN_TYPE_OFFS;
	tokens =  (regVal & MV_PP2_PLCR_TOKEN_VALUE_ALL_MASK) >> MV_PP2_PLCR_TOKEN_VALUE_OFFS;
	enable = regVal & MV_PP2_PLCR_ENABLE_MASK;
	mvOsPrintf("%4s", enable ? "Yes" : "No");
	mvOsPrintf("   %-5s  %2d   %5d", units ? "pkts" : "bytes", type, tokens);
	mvOsPrintf("  %-5s", color ? "aware" : "blind");

	regVal = mvPp2RdReg(MV_PP2_PLCR_BASE_PERIOD_REG);
	mvOsPrintf("  %6d", regVal & MV_PP2_PLCR_BASE_PERIOD_ALL_MASK);

	regVal = mvPp2RdReg(MV_PP2_PLCR_BUCKET_SIZE_REG);
	mvOsPrintf("    %04x    %04x",
			(regVal & MV_PP2_PLCR_COMMIT_SIZE_ALL_MASK) >> MV_PP2_PLCR_COMMIT_SIZE_OFFS,
			(regVal & MV_PP2_PLCR_EXCESS_SIZE_ALL_MASK) >> MV_PP2_PLCR_EXCESS_SIZE_OFFS);

	regVal = mvPp2RdReg(MV_PP2_PLCR_COMMIT_TOKENS_REG);
	mvOsPrintf("    %08x", regVal);

	regVal = mvPp2RdReg(MV_PP2_PLCR_EXCESS_TOKENS_REG);
	mvOsPrintf("  %08x", regVal);

	mvOsPrintf("\n");
}

void        mvPp2PlcrHwDumpAll(void)
{
	int i;

	mvPp2PlcrHwDumpTitle();
	for (i = 0; i < MV_PP2_PLCR_NUM; i++)
		mvPp2PlcrHwDump(i);
}

void        mvPp2PlcrHwDumpSingle(int plcr)
{
	mvPp2PlcrHwDumpTitle();
	mvPp2PlcrHwDump(plcr);
}

MV_STATUS   mvPp2PlcrHwBaseRateGenEnable(int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_PLCR_BASE_PERIOD_REG);
	if (enable)
		regVal |= MV_PP2_PLCR_ADD_TOKENS_EN_MASK;
	else
		regVal &= ~MV_PP2_PLCR_ADD_TOKENS_EN_MASK;

	mvPp2WrReg(MV_PP2_PLCR_BASE_PERIOD_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwBasePeriodSet(int period)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_PLCR_BASE_PERIOD_REG);
	regVal &= ~MV_PP2_PLCR_BASE_PERIOD_ALL_MASK;
	regVal |= MV_PP2_PLCR_BASE_PERIOD_MASK(period);
	mvPp2WrReg(MV_PP2_PLCR_BASE_PERIOD_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwMode(int mode)
{
	mvPp2WrReg(MV_PP2_PLCR_MODE_REG, mode);
	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwEnable(int plcr, int enable)
{
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);

	regVal = mvPp2RdReg(MV_PP2_PLCR_TOKEN_CFG_REG);
	if (enable)
		regVal |= MV_PP2_PLCR_ENABLE_MASK;
	else
		regVal &= ~MV_PP2_PLCR_ENABLE_MASK;

	mvPp2WrReg(MV_PP2_PLCR_TOKEN_CFG_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwMinPktLen(int bytes)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_PLCR_MIN_PKT_LEN_REG);
	regVal &= ~MV_PP2_PLCR_MIN_PKT_LEN_ALL_MASK;
	regVal |= MV_PP2_PLCR_MIN_PKT_LEN_MASK(bytes);
	mvPp2WrReg(MV_PP2_PLCR_MIN_PKT_LEN_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwEarlyDropSet(int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_PLCR_EDROP_EN_REG);
	if (enable)
		regVal |= MV_PP2_PLCR_EDROP_EN_MASK;
	else
		regVal &= ~MV_PP2_PLCR_EDROP_EN_MASK;

	mvPp2WrReg(MV_PP2_PLCR_EDROP_EN_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwTokenConfig(int plcr, int unit, int type)
{
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);
	regVal = mvPp2RdReg(MV_PP2_PLCR_TOKEN_CFG_REG);
	if (unit)
		regVal |= MV_PP2_PLCR_TOKEN_UNIT_MASK;
	else
		regVal &= ~MV_PP2_PLCR_TOKEN_UNIT_MASK;

	regVal &= ~MV_PP2_PLCR_TOKEN_TYPE_ALL_MASK;
	regVal |= MV_PP2_PLCR_TOKEN_TYPE_MASK(type);

	mvPp2WrReg(MV_PP2_PLCR_TOKEN_CFG_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwTokenValue(int plcr, int value)
{
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);
	regVal = mvPp2RdReg(MV_PP2_PLCR_TOKEN_CFG_REG);

	regVal &= ~MV_PP2_PLCR_TOKEN_VALUE_ALL_MASK;
	regVal |= MV_PP2_PLCR_TOKEN_VALUE_MASK(value);
	mvPp2WrReg(MV_PP2_PLCR_TOKEN_CFG_REG, regVal);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwColorModeSet(int plcr, int enable)
{
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);
	regVal = mvPp2RdReg(MV_PP2_PLCR_TOKEN_CFG_REG);
	if (enable)
		regVal |= MV_PP2_PLCR_COLOR_MODE_MASK;
	else
		regVal &= ~MV_PP2_PLCR_COLOR_MODE_MASK;

	mvPp2WrReg(MV_PP2_PLCR_TOKEN_CFG_REG, regVal);

	return MV_OK;
}


MV_STATUS   mvPp2PlcrHwBucketSizeSet(int plcr, int commit, int excess)
{
	MV_U32 regVal;

	mvPp2WrReg(MV_PP2_PLCR_TABLE_INDEX_REG, plcr);
	regVal = MV_PP2_PLCR_EXCESS_SIZE_MASK(excess) | MV_PP2_PLCR_COMMIT_SIZE_MASK(commit);
	mvPp2WrReg(MV_PP2_PLCR_BUCKET_SIZE_REG, regVal);

	return MV_OK;
}
/*ppv2.1 policer early drop threshold mechanism changed*/
MV_STATUS   mvPp2V0PlcrHwCpuThreshSet(int idx, int threshold)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_V0_PLCR_EDROP_CPU_TR_REG(idx));
	regVal &= ~MV_PP2_V0_PLCR_EDROP_TR_ALL_MASK(idx);
	regVal |= MV_PP2_V0_PLCR_EDROP_TR_MASK(idx, threshold);
	mvPp2WrReg(MV_PP2_V0_PLCR_EDROP_CPU_TR_REG(idx), regVal);

	return MV_OK;
}
/*ppv2.1 policer early drop threshold mechanism changed*/
MV_STATUS   mvPp2V1PlcrHwCpuThreshSet(int idx, int threshold)
{
	mvPp2WrReg(MV_PP2_V1_PLCR_EDROP_CPU_TR_REG(idx), threshold);

	return MV_OK;
}

/*ppv2.1 policer early drop threshold mechanism changed*/
MV_STATUS   mvPp2V0PlcrHwHwfThreshSet(int idx, int threshold)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_V0_PLCR_EDROP_HWF_TR_REG(idx));
	regVal &= ~MV_PP2_V0_PLCR_EDROP_TR_ALL_MASK(idx);
	regVal |= MV_PP2_V0_PLCR_EDROP_TR_MASK(idx, threshold);
	mvPp2WrReg(MV_PP2_V0_PLCR_EDROP_HWF_TR_REG(idx), regVal);

	return MV_OK;
}

/*ppv2.1 policer early drop threshold mechanism changed*/
MV_STATUS   mvPp2V1PlcrHwHwfThreshSet(int idx, int threshold)
{
	mvPp2WrReg(MV_PP2_V1_PLCR_EDROP_HWF_TR_REG(idx), threshold);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwRxqThreshSet(int rxq, int idx)
{
	mvPp2WrReg(MV_PP2_PLCR_EDROP_RXQ_REG, rxq);
	mvPp2WrReg(MV_PP2_PLCR_EDROP_RXQ_TR_REG, idx);

	return MV_OK;
}

MV_STATUS   mvPp2PlcrHwTxqThreshSet(int txq, int idx)
{
	mvPp2WrReg(MV_PP2_PLCR_EDROP_TXQ_REG, txq);
	mvPp2WrReg(MV_PP2_PLCR_EDROP_TXQ_TR_REG, idx);

	return MV_OK;
}

void mvPp2V1PlcrTbCntDump(int plcr)
{
	mvPp2PrintReg2(MV_PP2_V1_PLCR_PKT_GREEN_REG(plcr), "MV_PP2_V1_PLCR_PKT_GREEN_REG", plcr);
	mvPp2PrintReg2(MV_PP2_V1_PLCR_PKT_YELLOW_REG(plcr), "MV_PP2_V1_PLCR_PKT_YELLOW_REG", plcr);
	mvPp2PrintReg2(MV_PP2_V1_PLCR_PKT_RED_REG(plcr), "MV_PP2_V1_PLCR_PKT_RED_REG", plcr);

}


