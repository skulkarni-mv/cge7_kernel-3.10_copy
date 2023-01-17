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

#ifndef __mvPp2Wol_h__
#define __mvPp2Wol_h__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "gbe/mvPp2Gbe.h"

/*********************************** RX Policer Registers *******************/

#define MV_PP2_WOL_MODE_REG                 (MV_PP2_REG_BASE + 0x400)

#define MV_PP2_WOL_GO_SLEEP_BIT             0
#define MV_PP2_WOL_GO_SLEEP_MASK            (1 << MV_PP2_WOL_GO_SLEEP_BIT)

#define MV_PP2_WOL_IS_SLEEP_BIT             1
#define MV_PP2_WOL_IS_SLEEP_MASK            (1 << MV_PP2_WOL_IS_SLEEP_BIT)

#define MV_PP2_WOL_SLEEP_PORT_OFFS          4
#define MV_PP2_WOL_SLEEP_PORT_BITS          3
#define MV_PP2_WOL_SLEEP_PORT_MAX           ((1 << MV_PP2_WOL_SLEEP_PORT_BITS) - 1)
#define MV_PP2_WOL_SLEEP_PORT_ALL_MASK      (MV_PP2_WOL_SLEEP_PORT_MAX << MV_PP2_WOL_SLEEP_PORT_OFFS)
#define MV_PP2_WOL_SLEEP_PORT_MASK(p)       (((p) & MV_PP2_WOL_SLEEP_PORT_MAX) << MV_PP2_WOL_SLEEP_PORT_OFFS)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_WOL_MAC_HIGH_REG             (MV_PP2_REG_BASE + 0x410)
#define MV_PP2_WOL_MAC_LOW_REG              (MV_PP2_REG_BASE + 0x414)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_WOL_ARP_IP_NUM               2

#define MV_PP2_WOL_ARP_IP0_REG              (MV_PP2_REG_BASE + 0x418)
#define MV_PP2_WOL_ARP_IP1_REG              (MV_PP2_REG_BASE + 0x41C)
#define MV_PP2_WOL_ARP_IP_REG(idx)          (MV_PP2_WOL_ARP_IP0_REG + ((idx) << 2))
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_WOL_PTRN_NUM                 4
#define MV_PP2_WOL_PTRN_BYTES               128
#define MV_PP2_WOL_PTRN_REGS                (MV_PP2_WOL_PTRN_BYTES / 4)

#define MV_PP2_WOL_WAKEUP_EN_REG            (MV_PP2_REG_BASE + 0x420)
#define MV_PP2_WOL_INTR_CAUSE_REG           (MV_PP2_REG_BASE + 0x424)
#define MV_PP2_WOL_INTR_MASK_REG            (MV_PP2_REG_BASE + 0x428)

/* Bits are the same for all three registers above */
#define MV_PP2_WOL_PTRN_IDX_BIT(idx)        (0 + (idx))
#define MV_PP2_WOL_PTRN_IDX_MASK(idx)       (1 << MV_PP2_WOL_PTRN_IDX_BIT(idx))

#define MV_PP2_WOL_MAGIC_PTRN_BIT           4
#define MV_PP2_WOL_MAGIC_PTRN_MASK          (1 << MV_PP2_WOL_MAGIC_PTRN_BIT)

#define MV_PP2_WOL_ARP_IP0_BIT              5
#define MV_PP2_WOL_ARP_IP1_BIT              6
#define MV_PP2_WOL_ARP_IP_MASK(idx)         (1 << (MV_PP2_WOL_ARP_IP0_BIT + (idx)))

#define MV_PP2_WOL_UCAST_BIT                7
#define MV_PP2_WOL_UCAST_MASK               (1 << MV_PP2_WOL_UCAST_BIT)

#define MV_PP2_WOL_MCAST_BIT                8
#define MV_PP2_WOL_MCAST_MASK               (1 << MV_PP2_WOL_MCAST_BIT)
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_WOL_PTRN_SIZE_REG            (MV_PP2_REG_BASE + 0x430)

#define MV_PP2_WOL_PTRN_SIZE_BITS           8
#define MV_PP2_WOL_PTRN_SIZE_MAX            ((1 << MV_PP2_WOL_PTRN_SIZE_BITS) - 1)
#define MV_PP2_WOL_PTRN_SIZE_MAX_MASK(i)    (MV_PP2_WOL_PTRN_SIZE_MAX << ((i) << MV_PP2_WOL_PTRN_SIZE_BITS))
#define MV_PP2_WOL_PTRN_SIZE_MASK(i, s)     ((s) << ((i) * MV_PP2_WOL_PTRN_SIZE_BITS))
/*---------------------------------------------------------------------------------------------*/

#define MV_PP2_WOL_PTRN_IDX_REG             (MV_PP2_REG_BASE + 0x434)
#define MV_PP2_WOL_PTRN_DATA_REG(i)         (MV_PP2_REG_BASE + 0x500 + ((i) << 2))
#define MV_PP2_WOL_PTRN_MASK_REG(i)         (MV_PP2_REG_BASE + 0x580 + ((i) << 2))

#define MV_PP2_WOL_PTRN_DATA_BYTE_MASK(i)   (0xFF << ((i) * 8))
#define MV_PP2_WOL_PTRN_DATA_BYTE(i, b)     ((b)  << ((i) * 8))
#define MV_PP2_WOL_PTRN_MASK_BIT(i)         (1    << ((i) * 8))
/*---------------------------------------------------------------------------------------------*/

/*********************************** ENUMERATIONS *******************/

enum wol_event_enable_t {
	WOL_EVENT_DIS = 0,
	WOL_EVENT_EN,
};

/* WoL APIs */
void      mvPp2WolRegs(void);
void      mvPp2WolStatus(void);
MV_STATUS mvPp2WolSleep(int port);
MV_STATUS mvPp2WolWakeup(void);
int       mvPp2WolIsSleep(int *port);
MV_STATUS mvPp2WolMagicDaSet(MV_U8 *mac_da);
MV_STATUS mvPp2WolArpIpSet(int idx, MV_U32 ip);
MV_STATUS mvPp2WolPtrnSet(int idx, int off, int size, MV_U8 *data, MV_U8 *mask);
MV_STATUS mvPp2WolArpEventSet(int idx, int enable);
MV_STATUS mvPp2WolMcastEventSet(int enable);
MV_STATUS mvPp2WolUcastEventSet(int enable);
MV_STATUS mvPp2WolMagicEventSet(int enable);
MV_STATUS mvPp2WolPtrnEventSet(int idx, int enable);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __mvPp2Wol_h__ */
