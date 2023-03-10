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
#ifndef __mv_tag_netdev_h__
#define __mv_tag_netdev_h__

#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <net/ip.h>

#include "mvCommon.h"
#include "mvTypes.h"
#include "mvOs.h"
#include "mv802_3.h"

#define MV_MUX_SKB_TAG_VAL		(0xabcd)
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 33)
#define MV_MUX_SKB_TAG_SET(skb)		(skb->iif = (MV_MUX_SKB_TAG_VAL))
#define MV_MUX_SKB_IS_TAGGED(skb)	(skb->iif == (MV_MUX_SKB_TAG_VAL))
#else
#define MV_MUX_SKB_TAG_SET(skb)		(skb->skb_iif = (MV_MUX_SKB_TAG_VAL))
#define MV_MUX_SKB_IS_TAGGED(skb)	(skb->skb_iif == (MV_MUX_SKB_TAG_VAL))
#endif
/*MV_MUX_UNKNOWN_GROUP is usedfor sysfs creating mux device.*/
/*e.g. when switch is in HGU mode, then mux device is created in -1 group*/
#define MV_MUX_UNKNOWN_GROUP		(-1)
#define MV_MUX_GROUP_IDX_2_DB(idx)	((idx) == MV_MUX_UNKNOWN_GROUP ? 0 : idx)

/* Mux tag related definition */
/* DSA/EDSA, the unit is Byte */
#define MV_DSA_HDR_TAG_CMD_OFF (6)
#define MV_DSA_HDR_TAG_CMD_TO_CPU (0x0)
#define MV_DSA_HDR_TAG_CMD_FORWARD (0x3)
#define MV_DSA_HDR_TAG_CMD_MASK (0x3)
#define MV_DSA_HDR_TAG_CMD_GET(hdr) ((hdr[0] >> MV_DSA_HDR_TAG_CMD_OFF) & MV_DSA_HDR_TAG_CMD_MASK)

#define MV_DSA_HDR_SRC_DEV_MASK (0x1f)
#define MV_DSA_HDR_SRC_DEV_GET(hdr) (hdr[0] & MV_DSA_HDR_SRC_DEV_MASK)

#define MV_DSA_HDR_SRC_PORT_OFF (3)
#define MV_DSA_HDR_SRC_PORT_MASK (0x1f)
#define MV_DSA_HDR_SRC_PORT_GET(hdr) ((hdr[1] >> MV_DSA_HDR_SRC_PORT_OFF) & MV_DSA_HDR_SRC_PORT_MASK)
#define MV_EDSA_HDR_SRC_PORT_BIT5_GET(hdr) (hdr[6] & 0x4)

#define MV_DSA_HDR_TRG_DEV_WORD_OFF (24)
#define MV_DSA_HDR_TRG_DEV_MASK (0x1f)
#define MV_DSA_HDR_TRG_PORT_WORD_OFF (19)
#define MV_DSA_HDR_TRG_PORT_MASK (0x1f)

#define MV_DSA_HDR_TAGGED_MASK (0x20)
#define MV_DSA_HDR_TAGGED(hdr) (hdr[0] & MV_DSA_HDR_TAGGED_MASK)

extern const struct ethtool_ops mv_mux_tool_ops;

struct mux_netdev {
	int	idx;
	int	port;
	bool    leave_tag;
	MV_U16  proto_type;
	MV_TAG  tx_tag;
	MV_TAG  rx_tag_ptrn;
	MV_TAG  rx_tag_mask;
	struct  net_device *next;
};

#define MV_MUX_PRIV(dev)        ((struct mux_netdev *)(netdev_priv(dev)))


struct mv_mux_eth_port {
	int    tag_type;
	struct net_device *switch_dev;
	struct net_device *root;
	unsigned long flags;
};

#define MV_MUX_F_DBG_RX_BIT         0
#define MV_MUX_F_DBG_TX_BIT         1

#define MV_MUX_F_DBG_RX            (1 << MV_MUX_F_DBG_RX_BIT)
#define MV_MUX_F_DBG_TX            (1 << MV_MUX_F_DBG_TX_BIT)

struct mv_mux_switch_port {
	int    tag_type;
	int    preset;
	int    vid;
	int    switch_port;
	int    gbe_port;
	int    mtu;
	bool   attach;
};


/* operations requested by switch device from mux device */
struct mv_switch_mux_ops {
	int	(*update_link)(void *cookie, int link_up);
};

/* operations requested by mux device from switch device */
struct mv_mux_switch_ops {
	int	(*promisc_set)(int db, u8 promisc_on);
	int	(*jumbo_mode_set)(int max_size);
	int	(*group_disable)(int db);
	int	(*group_enable)(int db);
	int	(*link_status_get)(int db);
	int     (*all_mcast_del)(int db);
	int	(*mac_addr_set)(int db, unsigned char *mac_addr, unsigned char op);
	int	(*group_cookie_set)(int db, void *cookie);
	bool	(*tag_get)(int db, MV_TAG_TYPE tag_mode, MV_SWITCH_PRESET_TYPE preset, int vid, MV_MUX_TAG *tag);
	int	(*preset_init)(MV_TAG_TYPE tag_mode, MV_SWITCH_PRESET_TYPE preset, int vid);
	void	(*interrupt_unmask)(void);
};

struct mv_mux_eth_ops {
	int	(*set_tag_type)(int port, int tag_type);
};

int mv_mux_update_link(void *cookie, int link_up);
struct net_device *mv_mux_netdev_add(int port, struct net_device *mux_dev);
struct net_device *mv_mux_netdev_alloc(char *name, int idx, MV_MUX_TAG *tag_cfg);
char *mv_mux_get_mac(struct net_device *mux_dev);
int mv_mux_netdev_delete(struct net_device *mux_dev);
int mv_mux_tag_type_set(int port, int type);
void mv_mux_vlan_set(MV_MUX_TAG *mux_cfg, unsigned int vid);
void mv_mux_cfg_get(struct net_device *mux_dev, MV_MUX_TAG *mux_cfg);
int mv_mux_rx(struct sk_buff *skb, int port, struct napi_struct *napi);
void mv_mux_netdev_print(struct net_device *mux_dev);
void mv_mux_netdev_print_all(int port);
void mv_mux_shadow_print(int gbe_port);
struct net_device *mv_mux_switch_ptr_get(int port);
int mv_mux_ctrl_dbg_flag(int port, u32 flag, u32 val);
void mv_mux_eth_attach(int port, struct net_device *root, struct mv_mux_eth_ops *ops);
void mv_mux_switch_attach(int gbe_port, int preset, int vid, int tag, int switch_port);
void mv_mux_eth_detach(int port);
int mv_mux_switch_ops_set(const struct mv_mux_switch_ops *switch_ops_ptr);
int mv_mux_netdev_find(unsigned int dev_idx);


#endif /* __mv_tag_netdev_h__ */
