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
#include "mvPp2Wol.h"


void        mvPp2WolRegs(void)
{
	int    i, reg;

	mvOsPrintf("\n[WoL registers]\n");

	mvPp2PrintReg(MV_PP2_WOL_MODE_REG,       "MV_PP2_WOL_MODE_REG");
	mvPp2PrintReg(MV_PP2_WOL_MAC_HIGH_REG,   "MV_PP2_WOL_MAC_HIGH_REG");
	mvPp2PrintReg(MV_PP2_WOL_MAC_LOW_REG,    "MV_PP2_WOL_MAC_LOW_REG");
	mvPp2PrintReg(MV_PP2_WOL_ARP_IP0_REG,    "MV_PP2_WOL_ARP_IP0_REG");
	mvPp2PrintReg(MV_PP2_WOL_ARP_IP1_REG,    "MV_PP2_WOL_ARP_IP1_REG");
	mvPp2PrintReg(MV_PP2_WOL_WAKEUP_EN_REG,  "MV_PP2_WOL_WAKEUP_EN_REG");
	mvPp2PrintReg(MV_PP2_WOL_INTR_CAUSE_REG, "MV_PP2_WOL_INTR_CAUSE_REG");
	mvPp2PrintReg(MV_PP2_WOL_INTR_MASK_REG,  "MV_PP2_WOL_INTR_MASK_REG");
	mvPp2PrintReg(MV_PP2_WOL_PTRN_SIZE_REG,  "MV_PP2_WOL_PTRN_SIZE_REG");


	for (i = 0; i < MV_PP2_WOL_PTRN_NUM; i++) {
		mvOsPrintf("\nWoL Wakeup Frame pattern #%d\n", i);

		mvPp2WrReg(MV_PP2_WOL_PTRN_IDX_REG, i);
		for (reg = 0; reg < MV_PP2_WOL_PTRN_REGS; reg++) {
			mvPp2RegPrintNonZero2(MV_PP2_WOL_PTRN_DATA_REG(reg), "MV_PP2_WOL_PTRN_DATA_REG", reg);
			mvPp2RegPrintNonZero2(MV_PP2_WOL_PTRN_MASK_REG(reg), "MV_PP2_WOL_PTRN_MASK_REG", reg);
		}
	}
}

void      mvPp2WolStatus(void)
{
}

MV_STATUS mvPp2WolSleep(int port)
{
	MV_U32 regVal;

	if (mvPp2PortCheck(port))
		return MV_BAD_PARAM;

	/* Clear cause register and unmask enabled WoL events */
	mvPp2WrReg(MV_PP2_WOL_INTR_CAUSE_REG, 0);
	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	mvPp2WrReg(MV_PP2_WOL_INTR_MASK_REG, regVal);

	regVal = mvPp2RdReg(MV_PP2_WOL_MODE_REG);
	if (regVal & MV_PP2_WOL_IS_SLEEP_MASK) {
		mvOsPrintf("WoL is already activated on port #%d\n",
			(regVal >> MV_PP2_WOL_SLEEP_PORT_OFFS) & MV_PP2_WOL_SLEEP_PORT_MAX);
		return MV_BUSY;
	}
	regVal = MV_PP2_WOL_SLEEP_PORT_MASK(port) | MV_PP2_WOL_GO_SLEEP_MASK;
	mvPp2WrReg(MV_PP2_WOL_MODE_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolWakeup(void)
{
	MV_U32 regVal;

	/* Clear cause register and mask all WoL events */
	mvPp2WrReg(MV_PP2_WOL_INTR_CAUSE_REG, 0);
	mvPp2WrReg(MV_PP2_WOL_INTR_MASK_REG, 0);

	regVal = mvPp2RdReg(MV_PP2_WOL_MODE_REG);
	regVal &= ~MV_PP2_WOL_GO_SLEEP_MASK;
	mvPp2WrReg(MV_PP2_WOL_MODE_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolMagicDaSet(MV_U8 *mac_da)
{
	MV_U32 regVal;

	regVal = (mac_da[0] << 24) | (mac_da[1] << 16) | (mac_da[2] << 8) | (mac_da[3] << 0);
	mvPp2WrReg(MV_PP2_WOL_MAC_HIGH_REG, regVal);

	regVal = (mac_da[4] << 8) | (mac_da[5]);
	mvPp2WrReg(MV_PP2_WOL_MAC_LOW_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolArpIpSet(int idx, MV_U32 ip)
{
	MV_U32 regVal;

	if (mvPp2MaxCheck(idx, MV_PP2_WOL_ARP_IP_NUM, "ARP IP index"))
		return MV_BAD_PARAM;

	regVal = MV_32BIT_BE(ip);
	mvPp2WrReg(MV_PP2_WOL_ARP_IP_REG(idx), regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolPtrnSet(int idx, int off, int size, MV_U8 *data, MV_U8 *mask)
{
	MV_U32 regVal, regData, regMask;
	int i, j, reg, new_size;
	MV_U8 *new_data;
	MV_U8 *new_mask;
	int aligned_size = 0, mh_off = 0;

	/* Take Marvell Header offset into consideration  */
	mh_off = off + MV_ETH_MH_SIZE;

	if (mvPp2MaxCheck(idx, MV_PP2_WOL_PTRN_NUM, "PTRN index"))
		return MV_BAD_PARAM;

	if (mvPp2MaxCheck((mh_off + size), MV_PP2_WOL_PTRN_BYTES, "PTRN size"))
		return MV_BAD_PARAM;

	regVal = mvPp2RdReg(MV_PP2_WOL_PTRN_SIZE_REG);
	regVal &= ~MV_PP2_WOL_PTRN_SIZE_MAX_MASK(idx);
	regVal |= MV_PP2_WOL_PTRN_SIZE_MASK(idx, size + mh_off);

	mvPp2WrReg(MV_PP2_WOL_PTRN_SIZE_REG, regVal);

	mvPp2WrReg(MV_PP2_WOL_PTRN_IDX_REG, idx);
	if (mh_off % 4) {
		aligned_size = size + 4 - (mh_off % 4);
		new_data = kmalloc(sizeof(MV_U8) * aligned_size, GFP_KERNEL);
		if (!new_data) {
			mvOsPrintf("CPU memory allocation fail\n");
			return MV_OUT_OF_CPU_MEM;
		}

		new_mask = kmalloc(sizeof(MV_U8) * aligned_size, GFP_KERNEL);
		if (!new_mask) {
			kfree(new_data);
			mvOsPrintf("CPU memory allocation fail\n");
			return MV_OUT_OF_CPU_MEM;
		}

		memset(new_data, 0, sizeof(MV_U8) * aligned_size);
		memset(new_mask, 0, sizeof(MV_U8) * aligned_size);

		memcpy(&new_data[mh_off % 4], data, size);
		memcpy(&new_mask[mh_off % 4], mask, size);
	} else {
		new_data = data;
		new_mask = mask;
	}
	new_size = size + (mh_off % 4);
	for (i = 0; i < new_size; i += 4) {
		reg = (mh_off + i) / 4;
		regData = mvPp2RdReg(MV_PP2_WOL_PTRN_DATA_REG(reg));
		regMask = mvPp2RdReg(MV_PP2_WOL_PTRN_MASK_REG(reg));
		for (j = 0; j < 4; j++) {

			if ((i + j) >= new_size)
				break;

			regData &= ~MV_PP2_WOL_PTRN_DATA_BYTE_MASK(3 - j);
			regData |= MV_PP2_WOL_PTRN_DATA_BYTE(3 - j, new_data[i + j]);
			/* mask on byte level */
			if (new_mask[i + j] == 0)
				regMask &= ~MV_PP2_WOL_PTRN_MASK_BIT(3 - j);
			else
				regMask |= MV_PP2_WOL_PTRN_MASK_BIT(3 - j);
		}
		mvPp2WrReg(MV_PP2_WOL_PTRN_DATA_REG(reg), regData);
		mvPp2WrReg(MV_PP2_WOL_PTRN_MASK_REG(reg), regMask);
	}
	if (mh_off % 4) {
		kfree(new_data);
		kfree(new_mask);
	}

	return MV_OK;
}

MV_STATUS mvPp2WolArpEventSet(int idx, int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	if (enable)
		regVal |= MV_PP2_WOL_ARP_IP_MASK(idx);
	else
		regVal &= ~MV_PP2_WOL_ARP_IP_MASK(idx);

	mvPp2WrReg(MV_PP2_WOL_WAKEUP_EN_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolMcastEventSet(int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	if (enable)
		regVal |= MV_PP2_WOL_MCAST_MASK;
	else
		regVal &= ~MV_PP2_WOL_MCAST_MASK;

	mvPp2WrReg(MV_PP2_WOL_WAKEUP_EN_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolUcastEventSet(int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	if (enable)
		regVal |= MV_PP2_WOL_UCAST_MASK;
	else
		regVal &= ~MV_PP2_WOL_UCAST_MASK;

	mvPp2WrReg(MV_PP2_WOL_WAKEUP_EN_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolMagicEventSet(int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	if (enable)
		regVal |= MV_PP2_WOL_MAGIC_PTRN_MASK;
	else
		regVal &= ~MV_PP2_WOL_MAGIC_PTRN_MASK;

	mvPp2WrReg(MV_PP2_WOL_WAKEUP_EN_REG, regVal);

	return MV_OK;
}

MV_STATUS mvPp2WolPtrnEventSet(int idx, int enable)
{
	MV_U32 regVal;

	regVal = mvPp2RdReg(MV_PP2_WOL_WAKEUP_EN_REG);
	if (enable)
		regVal |= MV_PP2_WOL_PTRN_IDX_MASK(idx);
	else
		regVal &= ~MV_PP2_WOL_PTRN_IDX_MASK(idx);

	mvPp2WrReg(MV_PP2_WOL_WAKEUP_EN_REG, regVal);

	return MV_OK;
}
