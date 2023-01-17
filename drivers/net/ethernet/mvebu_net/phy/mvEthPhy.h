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

#ifndef __INCETHPHYH
#define __INCETHPHYH

#ifdef __cplusplus
extern "C" {
#endif


#define MV_PHY_88E3061  0x1      /* E3061, E3081 */
#define MV_PHY_88E104X  0x2      /* E1040, E1041, E1042 */
#define MV_PHY_88E10X0  0x4      /* E1000, E1010, E1020 */
#define MV_PHY_88E10X0S 0x5      /* E1000S, E1010S, E1020S */
#define MV_PHY_88E1011  0x6      /* E1011, E1011S */
#define MV_PHY_88E3082  0x8
#define MV_PHY_88E1112  0x9
#define MV_PHY_88E1149  0xA
#define MV_PHY_88E1121  0xB
#define MV_PHY_88E1111  0xC      /* E1111, E1115 */
#define MV_PHY_88E114X  0xD
#define MV_PHY_88E1181  0xE
#define MV_PHY_88E1340S 0x1C     /* 88E1340S */
#define MV_PHY_88E1512  0x1D
#define MV_PHY_88E1340  0x1E     /* 88E1340/x0a */
#define MV_PHY_88E1543  0x2A     /* 88E15453 */
#define MV_PHY_88E154X  0x2B     /* 88E1545M */
#define MV_PHY_88E1340M 0x1F     /* 88E1340M/x0a */
#define MV_PHY_88E1116R 0x24
#define MV_PHY_88E1116  0x21     /* E1116, E1116R */
#define MV_PHY_88E3016_88E3019  0x22     /* E3015, E3016, E3018, 88E3019 */
#define MV_PHY_88E1240  0x23
#define MV_PHY_88E1149R 0x25
#define MV_PHY_88E1119R 0x28    /* 88E1119R */
#define MV_PHY_88E1310  0x29    /* 88E1310 */
#define MV_PHY_KW2_INTERNAL_GE		0x2b
#define MV_PHY_KW2_INTERNAL_3FE		0x26
#define MV_PHY_ALP_INTERNAL_QUAD_GE	0x0

#define MV_IS_MARVELL_OUI(_reg2, _reg3)		\
	(((_reg2) == 0x0141) && (((_reg3)&0xFC00) == 0x0C00))

MV_STATUS mvEthPhySmiAddrSet(MV_U32 smi_addr);
MV_STATUS	mvEthPhyRegRead(MV_U32 phyAddr, MV_U32 regOffs, MV_U16 *data);
MV_STATUS	mvEthPhyRegPrint(MV_U32 phyAddr, MV_U32 regOffs);
void		mvEthPhyRegs(int phyAddr);
MV_STATUS	mvEthPhyRegWrite(MV_U32 phyAddr, MV_U32 regOffs, MV_U16 data);
MV_STATUS	mvEthPhyReset(MV_U32 phyAddr, int timeout);
MV_STATUS	mvEthPhyRestartAN(MV_U32 phyAddr, int timeout);
MV_STATUS	mvEthPhyDisableAN(MV_U32 phyAddr, int speed, int duplex);
MV_STATUS	mvEthPhyLoopback(MV_U32 phyAddr, MV_BOOL isEnable);
MV_BOOL		mvEthPhyCheckLink(MV_U32 phyAddr);
MV_STATUS	mvEthPhyPrintStatus(MV_U32 phyAddr);
MV_STATUS	mvEthPhyAdvertiseSet(MV_U32 phyAddr, MV_U16 advertise);
MV_STATUS	mvEthPhyAdvertiseGet(MV_U32 phyAddr, MV_U16 *advertise);

#ifdef __cplusplus
}
#endif

#endif /* #ifndef __INCETHPHYH */
