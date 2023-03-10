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

#include "mvOs.h"
#include "mvCommon.h"

#include "gbe/mvNetaRegs.h"

#include "mvPnc.h"
#include "mvTcam.h"

#ifdef MV_ETH_PNC_LB
int pnc_lb_first_frag_l4;
int mvPncLbFirstFragL4(int en)
{
	pnc_lb_first_frag_l4 = en;
	return 0;
}

void    mvPncLbDump(void)
{
	MV_U32	regVal;
	int i, j, rxq;

	MV_REG_WRITE(MV_PNC_LB_TBL_ACCESS_REG, 0);
	mvOsPrintf("Hash:    rxq    rxq    rxq    rxq\n");
	for (i = 0; i <= MV_PNC_LB_TBL_ADDR_MASK; i++) {
		/* Each read returns 4 hash entries */
		regVal = MV_REG_READ(MV_PNC_LB_TBL_ACCESS_REG);
		/* Extract data */
		regVal = (regVal & MV_PNC_LB_TBL_DATA_MASK) >> MV_PNC_LB_TBL_DATA_OFFS;
		mvOsPrintf("%4d:    ", (i * 4));
		for (j = 0; j < 4; j++) {
			rxq = regVal & 7;
			mvOsPrintf("%3d   ", rxq);
			regVal = regVal >> 3;
		}
		mvOsPrintf("\n");
	}
}

int    mvPncLbRxqSet(int hash, int rxq)
{
	MV_U32 regVal, entry, index;

	entry = (hash / 4) & MV_PNC_LB_TBL_ADDR_MASK;
	index = (hash & 3);

	MV_REG_WRITE(MV_PNC_LB_TBL_ACCESS_REG, entry);
	regVal = MV_REG_READ(MV_PNC_LB_TBL_ACCESS_REG);

	regVal &= ~MV_PNC_LB_TBL_ADDR_MASK;
	regVal |= entry;
	regVal &= ~((7 << (index * 3)) << MV_PNC_LB_TBL_DATA_OFFS);
	regVal |= ((rxq << (index * 3)) << MV_PNC_LB_TBL_DATA_OFFS);
	regVal |= MV_PNC_LB_TBL_WRITE_TRIG_MASK;
	MV_REG_WRITE(MV_PNC_LB_TBL_ACCESS_REG, regVal);

	return 0;
}
void		mvPncLbModeSet(int pnc_entry_num, int lb)
{
	struct tcam_entry te;

	tcam_hw_read(&te, pnc_entry_num);
	sram_sw_set_load_balance(&te, lb);
	tcam_hw_write(&te, pnc_entry_num);
}
int	mvPncLbModeIp4(int mode)
{
	int lb;

	switch (mode) {
	case 0:
		lb = LB_DISABLE_VALUE;
		break;
	case 1:
		lb = LB_2_TUPLE_VALUE;
		break;
	case 2:
	default:
		mvOsPrintf("%s: %d - unexpected mode value\n", __func__, mode);
		return 1;
	}
	mvPncLbModeSet(TE_IP4_TCP, lb);
	mvPncLbModeSet(TE_IP4_UDP, lb);
	mvPncLbModeSet(TE_IP4_TCP_FRAG, lb);
	mvPncLbModeSet(TE_IP4_UDP_FRAG, lb);
	mvPncLbModeSet(TE_IP4_EOF, lb);

	return 0;
}

int	mvPncLbModeIp6(int mode)
{
	int lb;

	switch (mode) {
	case 0:
		lb = LB_DISABLE_VALUE;
		break;
	case 1:
		lb = LB_2_TUPLE_VALUE;
		break;
	case 2:
	default:
		mvOsPrintf("%s: %d - unexpected mode value\n", __func__, mode);
		return 1;
	}
	mvPncLbModeSet(TE_IP6_TCP, lb);
	mvPncLbModeSet(TE_IP6_UDP, lb);
	mvPncLbModeSet(TE_IP6_UNKNOWN_L4, lb);
	mvPncLbModeSet(TE_IP6_2ND_PHASE_TCP_UDP, lb);
	mvPncLbModeSet(TE_IP6_2ND_PHASE_UNKNOWN_L4, lb);

	return 0;
}

int	mvPncLbModeL4(int mode)
{
	int lb;

	switch (mode) {
	case 0:
		lb = LB_DISABLE_VALUE;
		break;
	case 1:
		lb = LB_2_TUPLE_VALUE;
		break;
	case 2:
		lb = LB_4_TUPLE_VALUE;
		break;
	default:
		mvOsPrintf("%s: %d - unexpected mode value\n", __func__, mode);
		return 1;
	}

#ifdef CONFIG_MV_ETH_PNC_L3_FLOW
	mvOsPrintf("%s: Not supported\n", __func__);
	return 1;
#else
	/* IP4 */
	mvPncLbModeSet(TE_IP4_TCP, lb);
	mvPncLbModeSet(TE_IP4_UDP, lb);
	/* IP6 */
	mvPncLbModeSet(TE_IP6_TCP, lb);
	mvPncLbModeSet(TE_IP6_UDP, lb);
	mvPncLbModeSet(TE_IP6_2ND_PHASE_TCP_UDP, lb);

	if (pnc_lb_first_frag_l4) {
		mvPncLbModeSet(TE_IP4_TCP_FRAG, lb);
		mvPncLbModeSet(TE_IP4_UDP_FRAG, lb);
	}
	return 0;
#endif /* CONFIG_MV_ETH_PNC_L3_FLOW */
}
#endif /* MV_ETH_PNC_LB */
