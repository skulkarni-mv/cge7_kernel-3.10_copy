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

#ifndef __MV_PNC_HW_H__
#define __MV_PNC_HW_H__

#include "mvPp2ClsHw.h"
#include "mvPp2ClsActHw.h"
#include "../common/mvPp2ErrCode.h"
#include "../common/mvPp2Common.h"

#ifdef CONFIG_MV_ETH_PP2_CLS2
#include "mvPp2Cls2Hw.h"
#endif
#ifdef CONFIG_MV_ETH_PP2_CLS3
#include "mvPp2Cls3Hw.h"
#endif
#ifdef CONFIG_MV_ETH_PP2_CLS4
#include "mvPp2Cls4Hw.h"
#endif
#ifdef CONFIG_MV_ETH_PP2_CLS_MC
#include "mvPp2ClsMcHw.h"
#endif

/* call to defult init of cls, C2, C3, C4, MC, Clear all HW structure , clean all shadow arrays */
int mvPp2ClassifierDefInit(void);

/*
Assign Rx queue to a protocol
int mvPp2ClassifierProtoRxq(unsigned int proto, unsigned int rxq); rxq to arp
Assign Rx queue to a vlan priority
int mvPp2ClassifierVlanPrioRxq(int port, int prio, int rxq);
int mvPp2Classifier2tupleIp4Rxq(unsigned int eth_port, unsigned int sip, unsigned int dip, int rxq);
int mvPp2Classifier5tupleIp4Rxq(unsigned int eth_port, unsigned int sip, unsigned int dip, unsigned int ports,
				unsigned int proto, int rxq);
int  mvPp2ClassifierIp4DscpRxq(int port, unsigned char dscp, unsigned char mask, int rxq);
change def rxq per port
int  mvPp2ClassifierPortRxq(int port, int rxq);
*/

#endif /*__MV_PNC_HW_H__ */

