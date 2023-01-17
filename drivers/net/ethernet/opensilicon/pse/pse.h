/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#ifndef _PSE_H_
#define _PSE_H_

#include "pse_dev.h"
#include "pse_common.h"
#include "pse_desc.h"	/* TS/FS descriptor */
#include "pse_vlan.h"	/* PSE VLAN */
#include "pse_mac.h"	/* PSE MAC check */
#include "pse_ring.h"
#include "pse_config.h"
#include "pse_api.h"


#define PSE_MAX_FS_RING_NUM	(16)
#define PSE_MAX_TS_RING_NUM	(16)


#define PSE_RX_RING_SIZE_DEFAULT	(128)
#define PSE_TX_RING_SIZE_DEFAULT	(128)
#if 0
#define PSE_PACKET_SIZE_DEFAULT		(1514)
#define PSE_PACKET_SIZE_ALIGN		(1514)
#else
#define PSE_PACKET_SIZE_DEFAULT		(1534)
#define PSE_PACKET_SIZE_ALIGN		(1534)
#endif
#define PSE_JUMBO_FRAME_MAX_SIZE	(9600)

#define PSE_FLAG_PHYLIB 0x00000001
#define PSE_FLAG_PHY_CONNECTED 0x00000002


#define PSE_MAC0_PORT	0
#define PSE_MAC1_PORT	1
#define PSE_CPU_PORT	2
u32 pse_alloc_ring(struct pse_resource *, u16, u16, u16);
void pse_reset_rx_buffer_pktsz(struct pse_ring *ring);
u32 pse_alloc_rx_buffer(struct net_device *, struct pse_ring *, u32);

struct pse_ring_alloc {
	int ring_id;
};

extern struct pse_ring_alloc pse_ring_id[SW_FP_RING_MAX];
extern int pse_ring_count;
extern int pse_hibernation;
void pse_dma_idle(void);

void pse_receive_skb(struct sk_buff *);
void pse_sys_reset(void);
int pse_sys_init(struct pse_platform_data *);

void pse_status_intr_cfg(u32);
void pse_fs_dma_enable(u16);
void pse_ts_dma_enable(u16);
void pse_fs_intr_unmask(u8 id);
void pse_fs_intr_mask(u8 id);
void pse_ts_intr_unmask(u8 id);
void pse_ts_intr_mask(u8 id);
void pse_port_cfg(u8 port, bool enable);
void pse_port_ingress_check(u8 port, bool enable);
void pse_port_blocking_state(u8 port, bool enable);
void pse_port_block_mode(u8 port, bool enable);
void pse_port_skip_l2_lookup(u8 port, bool enable);
void pse_res_mc_flt(bool enable);
void pse_unknown_vlan_tocpu(bool enable);
void pse_accept_crc_pkt(bool enable);
void pse_promisc_mode(u8 port, bool enable);
void pse_my_mac_only(u8 port, bool enable);
void pse_set_max_frame_len(u8 port, u32 max_frame);
void pse_rx_broadcast_storm_rate(u8 rate);
void pse_port_broadcast_storm_rate_control(u8 port, bool enable);
void pse_col_mode(u8 mode);
void pse_bp_mode(u8 mode);
void pse_jam_no(u8 num);
void pse_bkoff_mode(u8 mode);
void pse_port_bp_enable(u8 port, bool enable);

void pse_lso_init(void);
void pse_tso_enable(bool enable);
void pse_ufo_enable(bool enable);
void pse_ufo_df_enable(bool enable);

int pse_lro_table_buffer_init(void);
void pse_lro_table_buffer_fini(void);

void pse_fs_ring_multipe_cfg(bool);
void pse_ts_ring_multipe_cfg(bool);
int pse_rx_ring_init(struct pse_priv *, u16, u16);
int pse_tx_ring_init(struct pse_priv *, u16);
void pse_ring_init_hw(struct pse_priv *);
int pse_alloc_swfp_ring(struct net_device *dev, u8 ring_id, u8 intr_group);
int __pse_alloc_swfp_ring(struct net_device *dev, u8 ring_id, u8 intr_group, int (*poll)(struct napi_struct *, int));
int pse_send(struct pse_ring *ring, struct sk_buff *skb, u8 pmap);

void pse_free_tx_ring(struct pse_ring *);
void pse_free_rx_ring(struct pse_ring *);

int pse_mii_init(struct pse_resource *);
void pse_mii_fini(struct pse_resource *);
int pse_phy_init(struct pse_priv *);
void pse_phy_start(struct net_device *);
void pse_phy_stop(struct net_device *);

int pse_lro_resource_init(struct net_device *, struct pse_resource *);

int pse_lro_ring_init(struct pse_priv *priv, u16 ring_size);
void pse_lro_ring_init_hw(struct pse_priv *priv);

int pse_irq_init(struct pse_resource *);
void pse_irq_fini(struct pse_resource *);

int pse_proc_init(void);
int pse_proc_fini(void);

int pse_sysfs_init(struct platform_device *pdev);
int pse_sysfs_finit(struct platform_device *pdev);

void pse_debug_init(void);
void pse_debug_fini(void);

void pse_set_ethtool_ops(struct net_device *netdev);

int pse_add_vlan(struct pse_priv *priv, u16 vid);
int pse_del_vlan(struct pse_priv *priv, u16 vid);
bool pse_vlan_used(struct pse_priv *priv);
void pse_vlan_filter_on_off(struct pse_priv *priv, bool filter_on);

bool pse_hw_checksum_valid(struct pse_fs_desc *desc, struct sk_buff *skb);
int pse_pre_process(struct sk_buff *, struct pse_fs_desc *, struct pse_ring *);
int pse_hdr_setup(struct sk_buff *skb, struct pse_fs_desc *desc, struct pse_ring *ring);

bool pse_tx_desc_avail(struct pse_ring *tx_ring, int no_of_desc);

bool pse_ppe_port_en(void);

void pse_acp_cfg(bool en);
void pse_acp_table_cfg(bool en);

void pse_ts_suspend_cfg(bool en);
void pse_fs_suspend_cfg(bool en);

extern void *pse_base;
extern void *pse_base_fast;
extern struct pse_resource *pse_res;
extern int (*opv5xc_pse_interface_change_hook)(struct sk_buff *skb);
extern int (*opv5xc_pse_no_slot_hook)(struct sk_buff *skb);


#endif /* _PSE_H_ */
