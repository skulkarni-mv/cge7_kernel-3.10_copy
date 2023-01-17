/* Copyright 2014 Broadcom Corporation.  All rights reserved.
 * Unless you and Broadcom execute a separate written software license
 * agreement governing use of this software, this software is licensed to you
 * under the terms of the GNU General Public License version 2, available at
 * http://www.broadcom.com/licenses/GPLv2.php (the "GPL").
 */

#ifndef __BCM_AMAC_DBG_H__
#define __BCM_AMAC_DBG_H__

#include "bcm-amac-enet.h"

#define AMAC_DEBUG 0


#define AMAC_DBG_GMAC0          1
#define AMAC_DBG_TX_DMA         2
#define AMAC_DBG_RX_DMA         3
#define AMAC_DBG_RX_PHY0        4
#define AMAC_DBG_RX_PHY1        5
#define AMAC_DBG_RX_DUMP_DESC   6
#define AMAC_DBG_TX_DUMP_DESC   7
#define AMAC_DBG_DISP_STATS     8
#define AMAC_DBG_DISP_PORT_INFO 9
#define AMAC_DBG_ARL_ENTRY      10


#if AMAC_DEBUG
#define AMAC_DBG_PRN(ndev, msg, arg...) do {\
	netdev_emerg(ndev, "[%s/%s():%d]", __FILE__, __func__, __LINE__);\
	netdev_emerg(ndev, msg, ##arg);\
	} while (0)

#define DBG_PRN\
	netdev_emerg("AT :%s:%d/%s\n", __FILE__, __LINE__, __func__)

#else
#define DBG_PRN
#define AMAC_DBG_PRN(msg, arg...) netdev_dbg(msg, ##arg)
#endif

void bcm_amac_dbg_display(struct bcm_amac_priv *privp, int block);
void bcm_amac_dbg_frame_hdr(char *buff, char *info, int tag_offset);

#endif /*__BCM_AMAC_DBG_H__*/
