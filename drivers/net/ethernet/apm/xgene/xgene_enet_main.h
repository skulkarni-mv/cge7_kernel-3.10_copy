/* Applied Micro X-Gene SoC Ethernet Driver
 *
 * Copyright (c) 2014, Applied Micro Circuits Corporation
 * Authors: Iyappan Subramanian <isubramanian@apm.com>
 *	    Ravi Patel <rapatel@apm.com>
 *	    Keyur Chudgar <kchudgar@apm.com>
 *          Hrishikesh Karanjikar <hkaranjikar@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XGENE_ENET_MAIN_H__
#define __XGENE_ENET_MAIN_H__

#include <linux/clk.h>
#include <linux/version.h>
#include <linux/of_platform.h>
#include <linux/of_net.h>
#include <linux/io.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/tcp.h>
#include <net/ip.h>
#include <linux/if_vlan.h>
#include <linux/phy.h>
#include "xgene_enet_sm_ring.h"
#include "xgene_enet_sc_ring.h"
#include "xgene_enet_gmac.h"
#include "xgene_enet_xgmac.h"
#include <misc/xgene/cle/apm_cle_config.h>

#undef ENET_DEBUG

#define DRV_VERSION		"1.0"

/* Direct Address mode */
#define BLOCK_ETH_CSR_OFFSET		0x2000
#define BLOCK_ETH_CLE_CSR_OFFSET	0x6000
#define BLOCK_ETH_RING_IF_OFFSET	0x9000
#define BLOCK_ETH_CLKRST_CSR_OFFSET	0xC000
#define BLOCK_ETH_DIAG_CSR_OFFSET	0xD000

#define BLOCK_XGE_CSR_OFFSET		0x2000

/* Indirect & Direct  Address mode for MCX_MAC and AXG_MAC */
#define BLOCK_ETH_MAC_OFFSET		0x0000
#define BLOCK_ETH_STATS_OFFSET		0x0014
#define BLOCK_ETH_MAC_CSR_OFFSET	0x2800
#define BLOCK_XGE_MCXMAC_CSR_OFFSET	0x3000

#define BLOCK_AXG_MAC_OFFSET		0x0800
#define BLOCK_AXG_STATS_OFFSET		0x0814
#define BLOCK_AXG_MAC_CSR_OFFSET	0x2000

#if defined(CONFIG_XGENE_CLE) || defined(CONFIG_XGENE_CLE_MODULE)
#define XGENE_NET_CLE
/* Define to enable set_rx_mode functionalty */
#define SET_RX_MODE
#endif
#define XGENE_ENET_MAX_MTU	1536
#define SKB_BUFFER_SIZE		(XGENE_ENET_MAX_MTU - NET_IP_ALIGN)

#define XGENE_NUM_PKT_BUF	64
#define XGENE_ENET_FP_NBUF	32

#ifndef UDP_HDR_SIZE
#define UDP_HDR_SIZE		2
#endif

#define TSO_IPPROTO_TCP			1
#define TSO_IPPROTO_UDP			0

/* Empty slot soft signature */
#define EMPTY_SLOT_INDEX	1
#define EMPTY_SLOT		~(u64)0
#define BUFLEN_16K		16384

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0))
/* Create a contiguous bitmask starting at bit position @l and ending at
 * position @h. For example
 * GENMASK_ULL(39, 21) gives us the 64bit vector 0x000000ffffe00000.
 */
#define GENMASK(h, l)           (((U32_C(1) << ((h) - (l) + 1)) - 1) << (l))
#define GENMASK_ULL(h, l)       (((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))

#endif /* LINUX_VERSION_CODE < KERNEL_VERSION(3, 14, 0) */

#define TX_RING_CFGSIZE		RING_CFGSIZE_2KB
#define RX_RING_CFGSIZE		RING_CFGSIZE_16KB
#define BUFPOOL_CFGSIZE		RING_CFGSIZE_2KB
#define MAX_EXP_BUFFS		16

enum xgene_enet_interface {
	XGENE_SM_MENET = 1,
	XGENE_MN_MENET,
	XGENE_MN_RGMII1,
	XGENE_MN_SGENET_0,
	XGENE_MN_SGENET_1,
	XGENE_MN_SGENET_2,
	XGENE_MN_XGENET_0,
	XGENE_SM_XGENET_0,
	XGENE_SM_XGENET_1,
	XGENE_SM_SGENET_0,
	XGENE_SM_SGENET_1,
	XGENE_SC_XGENET_0,
	XGENE_SC_XGENET_1,
	XGENE_SC_SGENET_0,
	XGENE_SC_SGENET_1,
	XGENE_MAX_INTERFACE
};

enum xgene_mac_type {
	XGENE_GMAC,
	XGENE_SGMAC,
	XGENE_XGMAC,
	XGENE_MAX_MAC
};

enum xgene_ring_type {
	XGENE_SC_RING = 0,
	XGENE_SM_RING_0 = 0,
	XGENE_SM_RING_1 = 1,
	XGENE_SM_RING_3 = 3,
	XGENE_MAX_RING
};

enum xgene_rx_buf_num_start {
	XGENE_SM_MENET_RX_BUF_NUM_START = 0x0,
	XGENE_SM_XGENET0_RX_BUF_NUM_START = 0x0,
	XGENE_SM_XGENET1_RX_BUF_NUM_START = 0xC,
	XGENE_SM_SGENET0_RX_BUF_NUM_START = 0x0,
	XGENE_SM_SGENET1_RX_BUF_NUM_START = 0xC,
	XGENE_SC_ENET0_RX_BUF_NUM_START = 0x0,
	XGENE_SC_ENET1_RX_BUF_NUM_START = 0xC,
	XGENE_MN_MENET_RX_BUF_NUM_START = 16, 
	XGENE_MN_RGMII1_RX_BUF_NUM_START = 18,
	XGENE_MN_SGENET0_RX_BUF_NUM_START = 8,
	XGENE_MN_SGENET1_RX_BUF_NUM_START = 12,
	XGENE_MN_SGENET2_RX_BUF_NUM_START = 0,
	XGENE_MN_XGENET0_RX_BUF_NUM_START = 0,
};

enum xgene_tx_buf_num_start {
	XGENE_SM_MENET_TX_BUF_NUM_START = 0x0,
	XGENE_SM_XGENET0_TX_BUF_NUM_START = 0x0,
	XGENE_SM_XGENET1_TX_BUF_NUM_START = 0x0,
	XGENE_SM_SGENET0_TX_BUF_NUM_START = 0x0,
	XGENE_SM_SGENET1_TX_BUF_NUM_START = 0x8,
	XGENE_SC_ENET0_TX_BUF_NUM_START = 0x0,
	XGENE_SC_ENET1_TX_BUF_NUM_START = 0x0,
	XGENE_MN_MENET_TX_BUF_NUM_START = 0x0,
	XGENE_MN_RGMII1_TX_BUF_NUM_START = 0x8,
	XGENE_MN_SGENET0_TX_BUF_NUM_START = 0x0,
	XGENE_MN_SGENET1_TX_BUF_NUM_START = 0x8,
	XGENE_MN_SGENET2_TX_BUF_NUM_START = 0x0,
	XGENE_MN_XGENET0_TX_BUF_NUM_START = 0x0,
};

enum xgene_buf_pool_num_start {
	XGENE_SM_MENET_BUF_POOL_NUM_START = 0x20,
	XGENE_SM_XGENET0_BUF_POOL_NUM_START = 0x20,
	XGENE_SM_XGENET1_BUF_POOL_NUM_START = 0x20,
	XGENE_SM_SGENET0_BUF_POOL_NUM_START = 0x20,
	XGENE_SM_SGENET1_BUF_POOL_NUM_START = 0x28,
	XGENE_SC_ENET0_BUF_POOL_NUM_START = 0x20,
	XGENE_SC_ENET1_BUF_POOL_NUM_START = 0x20,
	XGENE_MN_MENET_BUF_POOL_NUM_START = 0x20,
	XGENE_MN_RGMII1_BUF_POOL_NUM_START = 0x22,
	XGENE_MN_SGENET0_BUF_POOL_NUM_START = 0x22,
	XGENE_MN_SGENET1_BUF_POOL_NUM_START = 0x2a,
	XGENE_MN_SGENET2_BUF_POOL_NUM_START = 0x22,
	XGENE_MN_XGENET0_BUF_POOL_NUM_START = 0x22,
};

enum xgene_ring_num_start {
	XGENE_SM_MENET_RING_NUM_START = 0x0,
	XGENE_SM_XGENET0_RING_NUM_START = 0x0,
	XGENE_SM_XGENET1_RING_NUM_START = 0x100,
	XGENE_SM_SGENET0_RING_NUM_START = 0x0,
	XGENE_SM_SGENET1_RING_NUM_START = 0x100,
	XGENE_SC_ENET0_RING_NUM_START = 0x0,
	XGENE_SC_ENET1_RING_NUM_START = 0x100,
	XGENE_MN_MENET_RING_NUM_START = 192,
	XGENE_MN_RGMII1_RING_NUM_START = 256,
	XGENE_MN_SGENET0_RING_NUM_START = 64,
	XGENE_MN_SGENET1_RING_NUM_START = 128,
	XGENE_MN_SGENET2_RING_NUM_START = 0,
	XGENE_MN_XGENET0_RING_NUM_START = 0,
};

struct xgene_mac_ops {
	enum xgene_mac_type type;
	void (*init)(struct xgene_enet_pdata *pdata);
	void (*reset)(struct xgene_enet_pdata *pdata);
	void (*enable)(struct xgene_enet_pdata *pdata);
	void (*disable)(struct xgene_enet_pdata *pdata);
	void (*get_stats)(struct xgene_enet_pdata *pdata);
	void (*set_mac_addr)(struct xgene_enet_pdata *pdata);
	void (*set_mss)(struct xgene_enet_pdata *pdata);
	int (*mdio_config)(struct xgene_enet_pdata *pdata);
	int (*mdio_remove)(struct xgene_enet_pdata *pdata);
	void (*cle_bypass)(struct xgene_enet_pdata *pdata, 
			u32 dst_ring_num, u32 fpsel, bool enable);
	void (*port_reset)(struct xgene_enet_pdata *pdata);
	void (*port_shutdown)(struct xgene_enet_pdata *pdata);
};

struct xgene_enet_rd_wr_ops {
	void (*rd_stats)(struct xgene_enet_pdata *pdata, 
			u32 rd_addr, u32 *rd_data);
	void (*rd_mac)(struct xgene_enet_pdata *pdata, 
			u32 rd_addr, u32 *rd_data);
	void (*rd_mac_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 *val);
	void (*rd_diag_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 *val);
	void (*rd_ring_if)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 *val);
	void (*rd_clkrst_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 *val);
	void (*rd_enet_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 *val);
	void (*mii_phy_read)(struct xgene_enet_pdata *pdata, u8 phy_id,
			u32 reg, u32 *data);

	void (*wr_mac)(struct xgene_enet_pdata *pdata, 
			u32 wr_addr, u32 wr_data);
	void (*wr_mac_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 val);
	void (*wr_diag_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 val);
	void (*wr_ring_if)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 val);
	void (*wr_clkrst_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 val);
	void (*wr_enet_csr)(struct xgene_enet_pdata *pdata, 
			u32 offset, u32 val);
	void (*mii_phy_write)(struct xgene_enet_pdata *pdata, u8 phy_id,
			u32 reg, u16 data);
};

struct xgene_enet_ring_info {
	u32 headptr;
	u32 nummsginq;
};

struct xgene_ring_ops {
	enum xgene_ring_type type;
	int num_ring_cfg;
	//u16 num;
	struct xgene_enet_desc_ring * (*setup)(struct xgene_enet_desc_ring *);
	void (*clear)(struct xgene_enet_desc_ring *);
	void (*set_desc)(struct xgene_enet_desc *desc,
			 enum desc_info_index index,
			 u64 val);
	u64 (*get_desc)(struct xgene_enet_desc *desc,
			enum desc_info_index index);
	void (*set_cmd_base)(struct xgene_enet_desc_ring *);
	void (*wr_cmd)(struct xgene_enet_desc_ring *ring, int cntr);
	u32 (*len)(struct xgene_enet_desc_ring *ring);
	void (*dump_ring_state)(struct xgene_enet_desc_ring *ring);
	void (*get_ring_info)(struct xgene_enet_desc_ring *ring, 
				struct xgene_enet_ring_info *info);
	void (*ring_csr_rd)(struct xgene_enet_desc_ring *ring, 
				u32 offset, u32 *data);
	void (*ring_csr_wr)(struct xgene_enet_desc_ring *ring, 
				u32 offset, u32 data);
	u16 (*get_num)(struct xgene_enet_pdata *pdata);
	void (*set_addr_and_len)(void *desc, u8 index,
	       		     dma_addr_t addr, u32 len);
	void (*clear_pb)(struct xgene_enet_desc_ring *ring);
};

struct xgene_enet_exp_buff_desc {
	u64 m0;
	u64 m1;
};

/* software context of a descriptor ring */
struct xgene_enet_desc_ring {
	struct net_device *ndev;
	u16 id;
	u16 num;
	u16 head;
	u16 tail;
	u16 slots;
	u16 irq;
	char irq_name[16];
	u32 size;
	u32 state[NUM_RING_CONFIG];
	bool is_bufpool;
	u8 buf_num;
	enum xgene_enet_ring_owner owner;
	void __iomem *cmd_base;
	void __iomem *cmd;
	dma_addr_t dma;
	dma_addr_t irq_mbox_dma;
	void *irq_mbox_addr;
	u16 dst_ring_num;
	u8 nbufpool;
	struct sk_buff *(*rx_skb);
	struct sk_buff *(*cp_skb);
	enum xgene_enet_ring_cfgsize cfgsize;
	struct xgene_enet_desc_ring *cp_ring;
	struct xgene_enet_desc_ring *buf_pool;
	struct napi_struct napi;
	union {
		void *desc_addr;
		struct xgene_enet_desc *desc;
		struct xgene_enet_desc16 *desc16;
	};
	struct xgene_enet_exp_buff_desc *exp_buff;
	dma_addr_t exp_buff_dma;
};

#define exp_buff_incr(n, s)	(((n) + 1) & ((s) - 1))

struct xgene_enet_frame_stats {
	u32 c_64B_frames;	/**< Tx & Rx 64 Byte	Frame Counter */
	u32 c_65_127B_frames;	/**< Tx & Rx 65 to 127 Byte Frame Counter */
	u32 c_128_255B_frames;	/**< Tx & Rx 128 to 255 Byte Frame Counter */
	u32 c_256_511B_frames;	/**< Tx & Rx 256 to 511 Byte Frame Counter */
	u32 c_512_1023B_frames;	/**< Tx & Rx 512 to 1023 Byte Frame Counter */
	u32 c_1024_1518B_frames;/**< Tx & Rx 1024 to 1518 Byte Frame Counter */
	u32 c_1519_1522B_frames;/**< Tx & Rx 1519 to 1522 Byte Frame Counter */
};

struct xgene_enet_rx_stats {
	u32 rx_byte_count;	/**< Receive Byte Counter */
	u32 rx_packet_count;	/**< Receive Packet Counter */
	u32 rx_fcs_err_count;	/**< Receive FCS Error Counter */
	u32 rx_multicast_pkt_count;	/**< Receive Multicast Packet Counter */
	u32 rx_broadcast_pkt_count;	/**< Receive Broadcast Packet Counter */
	u32 rx_cntrl_frame_pkt_count;	/**< Rx Control Frame Packet Counter */
	u32 rx_pause_frame_pkt_count;	/**< Rx Pause Frame Packet Counter */
	u32 rx_unknown_op_pkt_count;	/**< Rx Unknown Opcode Packet Counter */
	u32 rx_alignment_err_pkt_count;	/**< Rx Alignment Err Packet Counter */
	u32 rx_frm_len_err_pkt_count;	/**< Rx Frame Len Err Packet Counter */
	u32 rx_code_err_pkt_count;	/**< Rx Code Error Packet Counter */
	u32 rx_false_carrier_count;	/**< Rx False Carrier Err Counter*/
	u32 rx_undersize_pkt_count;	/**< Receive Undersize Packet Counter */
	u32 rx_oversize_pkt_count;	/**< Receive Oversize Packet Counter */
	u32 rx_fragment_count;	/**< Receive Fragment Counter */
	u32 rx_jabber_count;	/**< Receive Jabber Counter */
	u32 rx_drop_pkt_count;	/**< Receive Drop Packet Counter */
	u32 rx_icm_drop_count;	/**< Input Overrun Counter */
	u32 rx_total_err_count;	/**< Receive Total Error Counter */
};

struct xgene_enet_tx_stats {
	u32 tx_byte_count;		/**< Tx Byte cnt */
	u32 tx_packet_count;		/**< Tx pkt cnt */
	u32 tx_multicast_pkt_count;	/**< Tx Multicast Pkt cnt */
	u32 tx_broadcast_pkt_count;	/**< Tx Broadcast pkt cnt */
	u32 tx_cntrl_frame_pkt_count;	/**< Tx Control Frame Packet Counter */
	u32 tx_pause_frame_count;	/**< Tx Pause Control Frame cnt */
	u32 tx_deferral_pkt_count;	/**< Tx Deferral pkt cnt */
	u32 tx_exesiv_def_pkt_count;	/**< Tx Excessive Deferral pkt cnt */
	u32 tx_single_coll_pkt_count;	/**< Tx Single Collision pkt cnt */
	u32 tx_multi_coll_pkt_count;	/**< Tx Multiple Collision pkt cnt */
	u32 tx_late_coll_pkt_count;	/**< Tx Late Collision pkt cnt */
	u32 tx_exesiv_coll_pkt_count;	/**< Tx Excessive Collision pkt cnt */
	u32 tx_toll_coll_pkt_count;	/**< Tx Toll Collision pkt cnt */
	u32 tx_pause_frm_hon_count;	/**< Tx Pause Frame Honored cnt */
	u32 tx_drop_frm_count;		/**< Tx Drop Frame cnt */
	u32 tx_jabber_frm_count;	/**< Tx Jabber Frame cnt */
	u32 tx_fcs_err_frm_count;	/**< Tx FCS Error Frame cnt */
	u32 tx_control_frm_count;	/**< Tx Control Frame cnt */
	u32 tx_oversize_frm_count;	/**< Tx Oversize Frame cnt */
	u32 tx_undersize_frm_count;	/**< Tx Undersize Frame cnt */
	u32 tx_fragments_frm_count;	/**< Tx Fragments Frame cnt */
	u32 tx_ecm_drop_count;		/**< Outpur Overrun Counter */
};

struct xgene_enet_stats {
	struct xgene_enet_frame_stats eth_combined_stats;
	struct xgene_enet_rx_stats rx_stats;
	struct xgene_enet_tx_stats tx_stats;
};

struct xgene_ring_params {
	bool is_bufpool;
	u16 num;
	u8 buf_num;
	enum xgene_enet_ring_owner owner;
	enum xgene_enet_ring_cfgsize cfg_size;
};
	
struct pbn_errata_table {                                                                                               
        u32 reg_offset;                                                                                                 
        u32 reg_offset1;                                                                                                
        u32 start_bit;                                                                                                  
        u32 end_bit;                                                                                                    
        u32 start_bit1;                                                                                                 
        u32 end_bit1;                                                                                                   
        u32 shift_width;                                                                                                
        u32 qmlite_hold_en;                                                                                         
};

/* ethernet private data */
struct xgene_enet_pdata {
	struct net_device *ndev;
	struct mii_bus *mdio_bus;
	struct phy_device *phy_dev;
	int phy_link;
	int phy_speed;
	struct clk *clk;
	struct platform_device *pdev;
	struct xgene_enet_desc_ring *tx_ring[MAX_TX_QUEUES];
	struct xgene_enet_desc_ring *rx_ring[MAX_RX_QUEUES];
	struct xgene_mac_ops mac_ops;
	struct xgene_ring_ops ring_ops;
	struct xgene_enet_rd_wr_ops enet_rd_wr_ops;
	struct net_device_stats nstats;
	struct xgene_enet_stats stats;
	char *dev_name;
	u32 num_rx_queues;
	u32 num_tx_queues;
	u32 num_tx_completion_queues;
	u32 rx_buff_cnt;
	u32 tx_qcnt_hi;
	u32 cp_qcnt_hi;
	u32 cp_qcnt_low;
	u32 rx_irq;
	u32 rx_ring_buf_num;
	u32 tx_ring_buf_num;
	u32 buf_pool_buf_num;
	u16 ring_num;
	u16 ring_start;
	u16 total_rings;
	void __iomem *eth_csr_addr;
	void __iomem *eth_cle_csr_addr;
	void __iomem *eth_ring_if_addr;
	void __iomem *eth_diag_csr_addr;
	void __iomem *mcx_mac_addr;
	void __iomem *mcx_stats_addr;
	void __iomem *mcx_mac_csr_addr;
	void __iomem *mdio_addr;
	void __iomem *axg_mac_addr;
	void __iomem *axg_stats_addr;
	void __iomem *axg_mac_csr_addr;
	void __iomem *base_addr;
	void __iomem *ring_csr_addr;
	struct resource *ring_csr_res;
	void __iomem *ring_cmd_addr;
	u32 phy_addr;
	int phy_mode;
	u32 speed;
	u16 mss;
	enum xgene_enet_interface intf;
#ifdef XGENE_NET_CLE
	struct xgene_enet_cle *cle_cfg;
#endif
	/* netmap call back routines */
	void (*xgene_netmap_open) (void *);
	void (*xgene_netmap_close) (void *);
};

/* Set the specified value into a bit-field defined by its starting position
 * and length within a single u64.
 */
static inline u64 xgene_enet_set_field_value(int pos, int len, u64 val)
{
	return (val & ((1ULL << len) - 1)) << pos;
}

#define SET_VAL(field, val) \
		xgene_enet_set_field_value(field ## _POS, field ## _LEN, val)

#define SET_BIT(field) \
		xgene_enet_set_field_value(field ## _POS, 1, 1)

static inline u16 xgene_enet_dst_ring_num(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	return ((u16)pdata->ring_ops.type << 10) | ring->num;
}

static inline struct device *ndev_to_dev(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	return &pdata->pdev->dev;
}

static inline u8 xgene_enet_hdr_len(const void *data)
{
	const struct ethhdr *eth = data;
	return (eth->h_proto == htons(ETH_P_8021Q)) ? VLAN_ETH_HLEN : ETH_HLEN;
}

extern struct xgene_mac_ops xgene_sgmac_ops;
extern struct xgene_enet_rd_wr_ops xgene_sgmac_rd_wr_ops;

#endif /* __XGENE_ENET_MAIN_H__ */
