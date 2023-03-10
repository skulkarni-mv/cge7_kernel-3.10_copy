/* Copyright 2014-2015 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __DPAA2_ETH_H
#define __DPAA2_ETH_H

#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include "../../fsl-mc/include/fsl_dpaa2_io.h"
#include "../../fsl-mc/include/fsl_dpaa2_fd.h"
#include "../../fsl-mc/include/dpbp.h"
#include "../../fsl-mc/include/dpcon.h"
#include "dpni.h"
#include "dpni-cmd.h"

#include "dpaa2-eth-trace.h"
#include "dpaa2-eth-debugfs.h"

/* TODO : how many queues here? NR_CPUS? */
#define DPAA2_ETH_TX_QUEUES		8	/* FIXME */
#define DPAA2_ETH_STORE_SIZE		16
/* NAPI weight *must* be a multiple of 16, i.e. the store size. */
#define DPAA2_ETH_NAPI_WEIGHT		64

/* TODO: Sort of arbitrary values for bpools, but we'll need to tune.
 * Supply enough buffers to reassembly several fragmented datagrams. Making it a
 * multiple of 7, because we're doing dpaa2_bp_add_7(). This is a per-CPU
 * counter.
 */
#define DPAA2_ETH_NUM_BUFS		(16 * 7)
#define DPAA2_ETH_REFILL_THRESH		(DPAA2_ETH_NUM_BUFS * 5 / 6)

/* Maximum receive frame size is 64K */
#define DPAA2_ETH_MAX_SG_ENTRIES	((64 * 1024) / DPAA2_ETH_RX_BUFFER_SIZE)

/* Maximum acceptable MTU value. It is in direct relation with the MC-enforced
 * Max Frame Length (currently 10k).
 */
#define DPAA2_ETH_MAX_MTU	(10000 - VLAN_ETH_HLEN)
/* Convert L3 MTU to L2 MFL */
#define DPAA2_ETH_L2_MAX_FRM(mtu)	(mtu + VLAN_ETH_HLEN)

/* Hardware requires alignment for ingress/egress buffer addresses
 * and ingress buffer lengths.
 */
#define DPAA2_ETH_RX_BUFFER_SIZE	2048
#define DPAA2_ETH_TX_BUF_ALIGN		64
#define DPAA2_ETH_RX_BUF_ALIGN		256
#define DPAA2_ETH_NEEDED_HEADROOM(p_priv) \
	((p_priv)->tx_data_offset + DPAA2_ETH_TX_BUF_ALIGN)

#define DPAA2_ETH_BUF_RAW_SIZE \
	(DPAA2_ETH_RX_BUFFER_SIZE + \
	SKB_DATA_ALIGN(sizeof(struct skb_shared_info)) + \
	DPAA2_ETH_RX_BUF_ALIGN)

/* We are accomodating a skb backpointer and potentially other data (see
 * struct backpointers) in the frame's software annotation. The hardware
 * options are either 0 or 64, so we choose the latter.
 */
#define DPAA2_ETH_SWA_SIZE		64

/* Annotation valid bits in FD FRC */
#define DPAA2_FD_FRC_FASV		0x8000
#define DPAA2_FD_FRC_FAEADV		0x4000
#define DPAA2_FD_FRC_FAPRV		0x2000
#define DPAA2_FD_FRC_FAIADV		0x1000
#define DPAA2_FD_FRC_FASWOV		0x0800
#define DPAA2_FD_FRC_FAICFDV		0x0400

/* Annotation bits in FD CTRL */
#define DPAA2_FD_CTRL_ASAL		0x00020000	/* ASAL = 128 */
#define DPAA2_FD_CTRL_PTA		0x00800000
#define DPAA2_FD_CTRL_PTV1		0x00400000

/* TODO: we may want to move this and other WRIOP related defines
 * to a separate header
 */
/* Frame annotation status */
struct dpaa2_fas {
	u8 reserved;
	u8 ppid;
	__le16 ifpid;
	__le32 status;
} __packed;

/* Debug frame, otherwise supposed to be discarded */
#define DPAA2_ETH_FAS_DISC		0x80000000
/* MACSEC frame */
#define DPAA2_ETH_FAS_MS		0x40000000
#define DPAA2_ETH_FAS_PTP		0x08000000
/* Ethernet multicast frame */
#define DPAA2_ETH_FAS_MC		0x04000000
/* Ethernet broadcast frame */
#define DPAA2_ETH_FAS_BC		0x02000000
#define DPAA2_ETH_FAS_KSE		0x00040000
#define DPAA2_ETH_FAS_EOFHE		0x00020000
#define DPAA2_ETH_FAS_MNLE		0x00010000
#define DPAA2_ETH_FAS_TIDE		0x00008000
#define DPAA2_ETH_FAS_PIEE		0x00004000
/* Frame length error */
#define DPAA2_ETH_FAS_FLE		0x00002000
/* Frame physical error; our favourite pastime */
#define DPAA2_ETH_FAS_FPE		0x00001000
#define DPAA2_ETH_FAS_PTE		0x00000080
#define DPAA2_ETH_FAS_ISP		0x00000040
#define DPAA2_ETH_FAS_PHE		0x00000020
#define DPAA2_ETH_FAS_BLE		0x00000010
/* L3 csum validation performed */
#define DPAA2_ETH_FAS_L3CV		0x00000008
/* L3 csum error */
#define DPAA2_ETH_FAS_L3CE		0x00000004
/* L4 csum validation performed */
#define DPAA2_ETH_FAS_L4CV		0x00000002
/* L4 csum error */
#define DPAA2_ETH_FAS_L4CE		0x00000001
/* These bits always signal errors */
#define DPAA2_ETH_RX_ERR_MASK		(DPAA2_ETH_FAS_KSE	| \
					 DPAA2_ETH_FAS_EOFHE	| \
					 DPAA2_ETH_FAS_MNLE	| \
					 DPAA2_ETH_FAS_TIDE	| \
					 DPAA2_ETH_FAS_PIEE	| \
					 DPAA2_ETH_FAS_FLE	| \
					 DPAA2_ETH_FAS_FPE	| \
					 DPAA2_ETH_FAS_PTE	| \
					 DPAA2_ETH_FAS_ISP	| \
					 DPAA2_ETH_FAS_PHE	| \
					 DPAA2_ETH_FAS_BLE	| \
					 DPAA2_ETH_FAS_L3CE	| \
					 DPAA2_ETH_FAS_L4CE)
/* Unsupported features in the ingress */
#define DPAA2_ETH_RX_UNSUPP_MASK	DPAA2_ETH_FAS_MS
/* TODO trim down the bitmask; not all of them apply to Tx-confirm */
#define DPAA2_ETH_TXCONF_ERR_MASK	(DPAA2_ETH_FAS_KSE	| \
					 DPAA2_ETH_FAS_EOFHE	| \
					 DPAA2_ETH_FAS_MNLE	| \
					 DPAA2_ETH_FAS_TIDE)

/* Time in milliseconds between link state updates */
#define DPAA2_ETH_LINK_STATE_REFRESH	1000

/* TODO Temporarily, until dpni_clear_mac_table() is implemented */
struct dpaa2_eth_mac_list {
	u8 addr[ETH_ALEN];
	struct list_head list;
};

/* Driver statistics, other than those in struct rtnl_link_stats64.
 * These are usually collected per-CPU and aggregated by ethtool.
 */
struct dpaa2_eth_stats {
	__u64	tx_conf_frames;
	__u64	tx_conf_bytes;
	__u64	tx_sg_frames;
	__u64	tx_sg_bytes;
	__u64	rx_sg_frames;
	__u64	rx_sg_bytes;
	/* Enqueues retried due to portal busy */
	__u64	tx_portal_busy;
};
/* Per-FQ statistics */
struct dpaa2_eth_fq_stats {
	/* Number of frames received on this queue */
	__u64 frames;
};

/* Per-channel statistics */
struct dpaa2_eth_ch_stats {
	/* Volatile dequeues retried due to portal busy */
	__u64 dequeue_portal_busy;
	/* Number of CDANs; useful to estimate avg NAPI len */
	__u64 cdan;
	/* Number of frames received on queues from this channel */
	__u64 frames;
};

/* Maximum number of Rx queues associated with a DPNI */
/* TODO: Use dynamic allocation based on max dist size reported by MC */
#define DPAA2_ETH_MAX_RX_QUEUES		16
#define DPAA2_ETH_MAX_TX_QUEUES		NR_CPUS
#define DPAA2_ETH_MAX_RX_ERR_QUEUES	1
#define DPAA2_ETH_MAX_QUEUES	(DPAA2_ETH_MAX_RX_QUEUES + \
				DPAA2_ETH_MAX_TX_QUEUES + \
				DPAA2_ETH_MAX_RX_ERR_QUEUES)

#define DPAA2_ETH_MAX_DPCONS		NR_CPUS

enum dpaa2_eth_fq_type {
	DPAA2_RX_FQ = 0,
	DPAA2_TX_CONF_FQ,
	DPAA2_RX_ERR_FQ
};

struct dpaa2_eth_priv;

struct dpaa2_eth_fq {
	uint32_t fqid;
	uint16_t flowid;
	int target_cpu;
	struct dpaa2_eth_channel *channel;
	enum dpaa2_eth_fq_type type;

	void (*consume)(struct dpaa2_eth_priv *,
			const struct dpaa2_fd *,
			struct napi_struct *);
	struct dpaa2_eth_priv *netdev_priv;	/* backpointer */
	struct dpaa2_eth_fq_stats stats;
};

struct dpaa2_eth_channel {
	struct dpaa2_io_notification_ctx nctx;
	struct fsl_mc_device *dpcon;
	int dpcon_id;
	int ch_id;
	int dpio_id;
	struct napi_struct napi;
	struct dpaa2_io_store *store;
	struct dpaa2_eth_priv *priv;
	struct dpaa2_eth_ch_stats stats;
};

struct dpaa2_cls_rule {
	struct ethtool_rx_flow_spec fs;
	bool in_use;
};

struct dpaa2_eth_priv {
	struct net_device *net_dev;

	uint8_t num_fqs;
	/* First queue is tx conf, the rest are rx */
	struct dpaa2_eth_fq fq[DPAA2_ETH_MAX_QUEUES];

	uint8_t num_channels;
	struct dpaa2_eth_channel *channel[DPAA2_ETH_MAX_DPCONS];

	int dpni_id;
	struct dpni_attr dpni_attrs;
	/* Insofar as the MC is concerned, we're using one layout on all 3 types
	 * of buffers (Rx, Tx, Tx-Conf).
	 */
	struct dpni_buffer_layout buf_layout;
	uint16_t tx_data_offset;

	/* TODO: Support multiple BPs */
	struct fsl_mc_device *dpbp_dev;
	struct dpbp_attr dpbp_attrs;

	int __percpu *buf_count;

	uint16_t tx_qdid;
	struct fsl_mc_io *mc_io;
	/* SysFS-controlled affinity mask for TxConf FQs */
	struct cpumask txconf_cpumask;
	/* Cores which have an affine DPIO/DPCON.
	 * This is the cpu set on which Rx frames are processed;
	 * Tx confirmation frames are processed on a subset of this,
	 * depending on user settings.
	 */
	struct cpumask dpio_cpumask;

	/* Standard statistics */
	struct rtnl_link_stats64 __percpu *percpu_stats;
	/* Extra stats, in addition to the ones known by the kernel */
	struct dpaa2_eth_stats __percpu *percpu_extras;
	uint32_t msg_enable;	/* net_device message level */

	uint16_t mc_token;

	struct dpni_link_state link_state;
	struct task_struct *poll_thread;

	/* enabled ethtool hashing bits */
	u64 rx_hash_fields;

#ifdef CONFIG_FSL_DPAA2_ETH_DEBUGFS
	struct dpaa2_debugfs dbg;
#endif

	/* array of classification rules */
	struct dpaa2_cls_rule *cls_rule;

	struct dpni_tx_shaping_cfg shaping_cfg;
};

/* default Rx hash options, set during probing */
#define DPAA2_RXH_SUPPORTED	(RXH_L2DA | RXH_VLAN | RXH_L3_PROTO \
				| RXH_IP_SRC | RXH_IP_DST | RXH_L4_B_0_1 \
				| RXH_L4_B_2_3)

#define dpaa2_eth_hash_enabled(priv)	\
	((priv)->dpni_attrs.options & DPNI_OPT_DIST_HASH)

#define dpaa2_eth_fs_enabled(priv)	\
	((priv)->dpni_attrs.options & DPNI_OPT_DIST_FS)

/*TODO: this should be taken from DPNI attributes */
#define DPAA2_CLASSIFIER_ENTRY_COUNT 16

extern const struct ethtool_ops dpaa2_ethtool_ops;

/* Set RX hash options
 * flags is a combination of RXH_ bits
 */
int dpaa2_set_hash(struct net_device *net_dev, u64 flags);

static inline int dpaa2_queue_count(struct dpaa2_eth_priv *priv)
{
	if (!dpaa2_eth_hash_enabled(priv))
		return 1;

	/* TODO: fix for multiple TCs */
	return priv->dpni_attrs.max_dist_per_tc[0];
}

static inline int dpaa2_max_channels(struct dpaa2_eth_priv *priv)
{
	/* Ideally, we want a number of channels large enough
	 * to accommodate both the Rx distribution size
	 * and the max number of Tx confirmation queues
	 */
	return max_t(int, dpaa2_queue_count(priv),
		     priv->dpni_attrs.max_senders);
}

void dpaa2_cls_check(struct net_device *);

#endif	/* __DPAA2_H */
