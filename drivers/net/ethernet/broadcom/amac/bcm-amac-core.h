/* Copyright (C) 2015 Broadcom Corporation
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 */

#ifndef __BCM_AMAC_CORE_H__
#define __BCM_AMAC_CORE_H__


#include <linux/phy.h>
#include <linux/netdevice.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/spinlock_types.h>
#include <linux/kernel.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>
#include <linux/kfifo.h>

#include <net/sock.h>

#define GMAC_HIGH_DMA_SUPPORT 0

extern gfp_t gfp_mask;
extern gfp_t gfp_atomic_mask;

void bcm_amac_gphy_set_lswap(unsigned int val);
int bcm_amac_gphy_init(struct net_device *dev);
void bcm_amac_gphy_powerup(struct bcm_amac_priv *privp);
void bcm_amac_gphy_shutdown(struct bcm_amac_priv *privp);
void bcm_amac_gphy_enable(struct bcm_amac_priv *privp, int phy, int enable);
void bcm_amac_gphy_enter_wol(struct bcm_amac_priv *privp,
	u8 wol_port, u32 speed);
void bcm_amac_gphy_exit_wol(struct bcm_amac_priv *privp);
void bcm_amac_gphy_stop_phy(struct bcm_amac_priv *privp);
void bcm_amac_gphy_start_phy(struct bcm_amac_priv *privp);

int bcm_amac_core_init(struct bcm_amac_priv *privp);
int bcm_amac_dma_start(struct bcm_amac_priv *privp);
void bcm_amac_dma_stop(struct bcm_amac_priv *privp);
void bcm_amac_core_enable(struct bcm_amac_priv *privp, int enable);
void bcm_amac_tx_send_packet(struct bcm_amac_priv *privp);
void bcm_amac_tx_clean(struct bcm_amac_priv *privp);
int bcm_amac_enable_tx_dma(struct bcm_amac_priv *privp, bool enable);
int bcm_amac_enable_rx_dma(struct bcm_amac_priv *privp, bool enable);
void bcm_amac_enable_rx_intr(struct bcm_amac_priv *privp, bool enable);
void bcm_amac_enable_intr(struct bcm_amac_priv *privp, int intr_bit);
void bcm_amac_disable_intr(struct bcm_amac_priv *privp, int intr_bit);

int bcm_amac_get_tx_flag(void);
int bcm_amac_dma_get_rx_data(struct bcm_amac_priv *privp,
	struct sk_buff **skbp);
void bcm_amac_set_rx_mode(struct net_device *ndev);
int bcm_amac_set_mac(struct bcm_amac_priv *privp, char *macp);

irqreturn_t bcm_amac_isr(int irq, void *userdata);
extern int bcm_amac_print_mib_counters(struct bcm_amac_priv *privp);

#endif /*__BCM_AMAC_CORE_H__*/
