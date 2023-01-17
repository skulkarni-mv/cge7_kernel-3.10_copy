/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Keyur Chudgar <kchudgar@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * @file apm_enet_access.c
 *
 * This file implements driver for APM862xx SoC Ethernet subsystem
 *
 */

#include <linux/clk.h>
#include <linux/interrupt.h>
#include <linux/of_platform.h>
#include <linux/module.h>
#include <net/ip.h>
#include <linux/spinlock.h>
#include <linux/if_vlan.h>
#include <linux/inetdevice.h>
#include <linux/proc_fs.h>
#include <linux/netdev_features.h>
#include <linux/phy.h>
#include <net/addrconf.h>
#include <asm/ipp.h>
#include <asm/cacheflush.h>
#if defined(CONFIG_SMP)
#include <asm/smp.h>
#endif
#include <asm/apm86xxx_soc.h>
#include <asm/apm_qm_utils.h>
#if !defined(CONFIG_SMP)
#include <asm/apm_shm.h>
#endif

#include "apm_enet_misc.h"
#include "apm_cle_cfg.h"
#ifdef CONFIG_INET_OFFLOAD
#include "apm_enet_offload.h"
#ifdef CONFIG_APM_ENET_LRO
#include "apm_enet_lro.h"
#include "apm_cle_lro.h"
#endif
#ifdef CONFIG_APM_ENET_QOS
#include "apm_enet_qos.h"
#include "apm_cle_qos.h"
#endif
#endif

#define UDP_HDR_SIZE		2

/* Define to enable Extended Link List Support */
#if !defined(CONFIG_APM862xx)
#define SAVE_ELL_PTR(s, v)	APM_ENET_SKB_CB((s))->ell = (v)
#define FREE_ELL_PTR(s)		if (APM_ENET_SKB_CB((s))->ell != NULL) \
					kfree(APM_ENET_SKB_CB((s))->ell);
#else
#define SAVE_ELL_PTR(s, v)
#define FREE_ELL_PTR(s)
#endif

static u32 cmp_cnt = 0;
#if defined(CONFIG_SLAB_HW)
extern int eth0_fp_id;
extern int eth1_fp_id;
extern int ppc_fp_id;
extern int ppc_fp_mbid;
extern int ppc_hw_buff_pool_init;
extern struct kmem_cache *virt_to_cache_ext(const void *obj);
extern int apm_enet_init_fp(int queue_id, int buff_size,
				int no_of_buffs, int qm_blk, int hdr_rsvd);
extern int apm_enet_rx_frame(struct apm_qm_msg_desc *rx_msg_desc);
#endif

#if defined(CONFIG_PM)
static int wol_state_saved = 0;
static int wol_state_value = 0;
#endif

void change_wake_on_lan_state(int);	/* From ipp.c */
int is_wake_on_lan_enabled(void);	/* From ipp.c */

/* Global structure for all ports */

#ifndef CONFIG_IE4000
/* mdio lock is global as all accesses are done using port 0 only */
static spinlock_t apm_mdio_lock;
static int mdio_lock_init = 0;
#endif
/* reg access lock is global as MII and normal reg read/write  are done using port 0 only */
static spinlock_t apm_reg_access_lock;
static int reg_access_lock_init = 0;

static struct apm_enet_dev enet_dev_glb;
/* Global private structure per port */
struct apm_data_enet_dev *enet_dev[MAX_PORTS];
/* Queue ID mapper to private structure for reverse lookup */
struct apm_enet_dev_base *qid2priv[QM_MAX_QUEUES];
static int ipp_notifier_registered = 0;
struct proc_dir_entry *enet_proc_entry;
#if defined(CONFIG_PM)
static int apm_enet_drain_fp(struct apm_enet_dev_base *pdev, int qid, int pbn,
			int drain_pbn_only, int disable_pbn);
#endif
static inline u16 apm_enet_len_encode(u32 len)
{
	return len >= (16*1024) ? 0 : len;
}

struct apm_enet_skb_cb {
	void *ell;	/* Extended link list */
};
#define APM_ENET_SKB_CB(__skb)	\
	((struct apm_enet_skb_cb *)&((__skb)->cb[0]))

int apm_enet_wr32(struct apm_data_priv *priv, u8 block_id,
		u32 reg_offset, u32 value)
{
	u32 command_done;
	u8  indirect = 0;
	u32 count = 0;
	u32 base_addr_v;
	u32 addr_reg_offst = 0, cmd_reg_offst = 0, wr_reg_offst = 0;
	u32 cmd_done_reg_offst = 0;
	int ret = 0;

	switch (block_id) {
	case BLOCK_ETH_MAC:
	case BLOCK_ETH_INTPHY:
		base_addr_v = priv->mac_base_addr_v;

		addr_reg_offst =
			base_addr_v + MAC_ADDR_REG_OFFSET;
		cmd_reg_offst =
			base_addr_v + MAC_COMMAND_REG_OFFSET;
		wr_reg_offst =
			base_addr_v + MAC_WRITE_REG_OFFSET;
		cmd_done_reg_offst =
			base_addr_v + MAC_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_WR("MAC/Internal PHY write\n");
		break;

	case BLOCK_ETH_EXTPHY:
		base_addr_v = priv->enet_mii_base_addr_v;

		addr_reg_offst =
			base_addr_v + MAC_ADDR_REG_OFFSET;
		cmd_reg_offst =
			base_addr_v + MAC_COMMAND_REG_OFFSET;
		wr_reg_offst =
			base_addr_v + MAC_WRITE_REG_OFFSET;
		cmd_done_reg_offst =
			base_addr_v + MAC_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_WR("External PHY write\n");
		break;

	case BLOCK_ETH_STATS:
		addr_reg_offst =
			priv->stats_base_addr_v + STAT_ADDR_REG_OFFSET;
		cmd_reg_offst =
			priv->stats_base_addr_v + STAT_COMMAND_REG_OFFSET;
		wr_reg_offst =
			priv->stats_base_addr_v + STAT_WRITE_REG_OFFSET;
		cmd_done_reg_offst =
			priv->stats_base_addr_v + STAT_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_WR("STATS write\n");
		break;

	case BLOCK_ETH_GBL:
		addr_reg_offst = priv->eth_gbl_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET Global CSR write\n");
		break;

	case BLOCK_ETH_FFDIV:
		addr_reg_offst = priv->eth_ffdiv_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET FFDIV CSR write\n");
		break;

	case BLOCK_ETH_MAC_GBL:
		addr_reg_offst = priv->mac_gbl_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET MAC Global CSR write\n");
		break;

	case BLOCK_ETH_PTP:
		addr_reg_offst = priv->eth_ptp_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET PTP CSR write\n");
		break;

	case BLOCK_ETH_UNISEC:
		addr_reg_offst = priv->eth_unisec_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET UNISEC CSR write\n");
		break;

	case BLOCK_ETH_DIAG:
		addr_reg_offst = priv->eth_diag_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ETH DIAG CSR write\n");
		break;

	case BLOCK_ETH_QMI_SLAVE:
		addr_reg_offst = priv->eth_qmi_base_addr_v + reg_offset;
		ENET_DEBUG_WR("ENET QMI SLAVE CSR write\n");
		break;

	case BLOCK_ETH_MACIP_IND:
		addr_reg_offst = priv->vpaddr_base + reg_offset;
		ENET_DEBUG_WR("ENET MACIP INDIRECT CSR write\n");
		break;

	default:
		printk(KERN_ERR
			"Invalid block id %d write reg\n", block_id);
		ret = -1;
		goto err;
	}

	/*
	 * take the lock, This is would not harm performance as registers are
	 * mostly accessed at init time or during maitenance like link poll etc.
	 */
	spin_lock(&apm_reg_access_lock);
	if (indirect) {
		/* Write the register offset in DCR */
		out_be32((void __iomem *) addr_reg_offst, reg_offset);
		ENET_DEBUG_WR("Indirect addr_reg_offst : 0x%X,"
				"value(reg_offset) 0x%X\n",
				addr_reg_offst, reg_offset);

		/* Write the data in the wrData register */
		out_be32((void __iomem *) wr_reg_offst, value);
		ENET_DEBUG_WR("Indirect wr_reg_offst: 0x%X value 0x%X\n",
			      wr_reg_offst, value);

		/* Invoke write command */
		out_be32((void __iomem *) cmd_reg_offst, WRITE0_WR(1));
		ENET_DEBUG_WR("Indirect cmd_reg_offst: 0x%X "
			      "value(cmd) 0x%X\n",
			      cmd_reg_offst,  WRITE0_WR(1) );

		/* check command done */
		while (1) {
			command_done =
				in_be32((void __iomem *) cmd_done_reg_offst);
			ENET_DEBUG_WR("Indirect cmd_done_reg_offst: 0x%X,"
					"command_done:0x%X \n",
					cmd_done_reg_offst, command_done);

			if (command_done)
				break;

			udelay(ACCESS_DELAY_TIMEMS);
			if(count++ > MAX_LOOP_POLL_CNT) {
				printk(KERN_ERR
					"Write failed for blk %d\n",block_id);
				ret = -1;
				goto err;
			}
		}
		/* Reset command reg */
		ENET_DEBUG_RD("Reset command reg[0X%08X] \n ", cmd_reg_offst);
		out_be32((void __iomem *) cmd_reg_offst, 0);
	} else {
		out_be32((void __iomem *) addr_reg_offst, value);
		ENET_DEBUG_WR("Direct write addr: 0x%X value 0x%X\n",
				addr_reg_offst, value);
	}

err:
	spin_unlock(&apm_reg_access_lock);
	return ret;
}

int apm_enet_rd32(struct apm_data_priv *priv, u8 block_id,
		u32 reg_offset, u32 *value)
{
	u8 indirect = 0;
	u32 command_done;
	u32 count = 0;
	u32 base_addr_v;
	u32 addr_reg_offst = 0, cmd_reg_offst = 0, rd_reg_offst = 0;
	u32 cmd_done_reg_offst = 0;
	int ret = 0;

	switch (block_id) {
	case BLOCK_ETH_MAC:
	case BLOCK_ETH_INTPHY:
		base_addr_v = priv->mac_base_addr_v;

		addr_reg_offst =
			base_addr_v + MAC_ADDR_REG_OFFSET;
		cmd_reg_offst =
			base_addr_v + MAC_COMMAND_REG_OFFSET;
		rd_reg_offst =
			base_addr_v + MAC_READ_REG_OFFSET;
		cmd_done_reg_offst =
			base_addr_v + MAC_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_RD("MAC read \n");
		break;

	case BLOCK_ETH_EXTPHY:
		base_addr_v = priv->enet_mii_base_addr_v;

		addr_reg_offst =
			base_addr_v + MAC_ADDR_REG_OFFSET;
		cmd_reg_offst =
			base_addr_v + MAC_COMMAND_REG_OFFSET;
		rd_reg_offst =
			base_addr_v + MAC_READ_REG_OFFSET;
		cmd_done_reg_offst =
			base_addr_v + MAC_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_RD("MAC read \n");
		break;

	case BLOCK_ETH_STATS:
		addr_reg_offst =
			priv->stats_base_addr_v + STAT_ADDR_REG_OFFSET;
		cmd_reg_offst =
			priv->stats_base_addr_v + STAT_COMMAND_REG_OFFSET;
		rd_reg_offst =
			priv->stats_base_addr_v + STAT_READ_REG_OFFSET;
		cmd_done_reg_offst =
		priv->stats_base_addr_v + STAT_COMMAND_DONE_REG_OFFSET;
		indirect = 1;
		ENET_DEBUG_RD("STATS read \n");
		break;

	case BLOCK_ETH_GBL:
		addr_reg_offst = priv->eth_gbl_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET Global CSR read\n");
		break;

	case BLOCK_ETH_FFDIV:
		addr_reg_offst = priv->eth_ffdiv_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET FFDIV CSR read\n");
		break;

	case BLOCK_ETH_MAC_GBL:
		addr_reg_offst = priv->mac_gbl_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET MAC Global CSR read\n");
		break;

	case BLOCK_ETH_PTP:
		addr_reg_offst = priv->eth_ptp_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET PTP CSR read\n");
		break;

	case BLOCK_ETH_UNISEC:
		addr_reg_offst = priv->eth_unisec_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET UNISEC CSR read\n");
		break;

	case BLOCK_ETH_DIAG:
		addr_reg_offst = priv->eth_diag_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ETH DIAG CSR read\n");
		break;

	case BLOCK_ETH_QMI_SLAVE:
		addr_reg_offst = priv->eth_qmi_base_addr_v + reg_offset;
		ENET_DEBUG_RD("ENET QMI SLAVE CSR read\n");
		break;

	case BLOCK_ETH_MACIP_IND:
		addr_reg_offst = priv->vpaddr_base + reg_offset;
		ENET_DEBUG_RD("ENET MACIP INDIRECT CSR read\n");
		break;

	default:
		printk(KERN_ERR "Invalid blockid in read reg: %d\n", block_id);
		ret = -1;
		goto err;
	}

	spin_lock(&apm_reg_access_lock);

	if (indirect) {
		/* Write the MAC register offset in DCR */
		out_be32((void __iomem *) addr_reg_offst, reg_offset);
		ENET_DEBUG_RD("Indirect addr_reg_offst: 0x%X "
				"value(reg_offset) 0x%X\n",
				addr_reg_offst, reg_offset);

		/* Invoke read command */
		out_be32((void __iomem *) cmd_reg_offst, READ0_WR(1));
		ENET_DEBUG_RD("Indirect cmd_reg_offst: 0x%X "
				"value(cmd) 0x%X\n",
				cmd_reg_offst,	READ0_WR(1));

		/* Poll for command done */
		while (1) {
			command_done =
				in_be32((void __iomem *) cmd_done_reg_offst);
			ENET_DEBUG_RD("Indirect cmd_done_reg_offst: 0x%X "
					"command_done:0x%X \n",
					cmd_done_reg_offst, command_done);

			if (command_done)
				break;

			udelay(ACCESS_DELAY_TIMEMS);
			if(count++ > MAX_LOOP_POLL_CNT) {
				printk(KERN_ERR
					"Read failed for blk %d\n",block_id);
				ret = -1;
				goto err;
			}
		}

		*value = in_be32((void __iomem *) rd_reg_offst);
		ENET_DEBUG_RD("Indirect rd_reg_offst: 0x%X value read 0x%X\n",
				rd_reg_offst, *value);

		/* Reset command reg */
		ENET_DEBUG_RD("Reset command reg[0X%08X] \n ", cmd_reg_offst);
		out_be32((void __iomem *) cmd_reg_offst, 0);
	} else {
		*value = in_be32((void __iomem *) addr_reg_offst);
		ENET_DEBUG_RD("Direct read addr: 0x%X value: 0x%X\n",
				addr_reg_offst, *value);
	}

err:
	spin_unlock(&apm_reg_access_lock);
	return ret;
}

void apm_enet_set_qidctx(int qid, struct apm_enet_dev_base *pdev)
{
	qid2priv[qid] = pdev;
}

struct apm_enet_dev_base *apm_enet_get_qidctx(int qid)
{
	return qid2priv[qid];
}

int apm_enet_is_smp(void)
{
	return enet_dev_glb.is_smp;
}

int apm_enet_fp_pb_flush(struct apm_data_priv *priv, int pbn)
{
        int num_qmi_buffers;
        u32 word0;
        u32 word1;
        u32 word2;
        u32 word3;

        /* Now drain the ETH pre-fetch buffer */
        num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
        ENET_DEBUG("Flush PBN %d msg cnt %d\n", pbn, num_qmi_buffers);

        while (num_qmi_buffers > 0)  {
                apm_enet_qmi_read_pb_msg(priv, pbn + 0x20, 0, 0, &word3);
                apm_enet_qmi_read_pb_msg(priv, pbn + 0x20, 1, 0, &word2);
                apm_enet_qmi_read_pb_msg(priv, pbn + 0x20, 2, 0, &word1);
                apm_enet_qmi_pop_pb_msg(priv, pbn + 0x20, 3, 1, &word0);

                num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
        }

        num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
        ENET_DEBUG("PBN msg cnt remain %d\n", num_qmi_buffers);
        return 0;
}

#if !defined(CONFIG_SLAB_HW) && !defined(CONFIG_DRIVER_POOL)
static int apm_enet_init_fp(int queue_id, int buf_len,
		int no_of_buffs, int qm_blk, int hdr_rsvd)
{
	int i;
	struct sk_buff *tmp_skb;
	phys_addr_t phy_addr;
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	int rc = 0;

	/* If buf_len is greatern that PKT_BUF_SIZE then we set buf_len
	 * to PKT_BUF_SIZE. This will ensure that for any frame greater
	 * than PKT_BUF_SIZE bot FP queue and NXTFP are used.
         */
	if (APM_ENET_PKT_BUF_SIZE < buf_len) {
		buf_len = APM_ENET_PKT_BUF_SIZE;
	}

	memset(&msg, 0, sizeof(msg));
	fp_msg_desc.msg = &msg;

	/* Common fields */
	msg.C = apm_enet_pkt_iscoherent();
	msg.BufDataLen = apm_qm_encode_bufdatalen(buf_len);
	msg.FPQNum = queue_id;
	msg.RType = APM_QM_ETH_RTYPE;

	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = queue_id;
	fp_msg_desc.msg = &msg;

	/* Program all the free buffer pools */
	for (i = 0; i < no_of_buffs; i++) {
		tmp_skb = dev_alloc_skb(buf_len + hdr_rsvd);
		if (unlikely(!tmp_skb)) {
			printk(KERN_ERR
				"Failed to allocate new skb size %d",
				buf_len + hdr_rsvd);
			return -ENOMEM;
		}
		skb_reserve(tmp_skb, hdr_rsvd);

		msg.UserInfo = (u32) tmp_skb;

		/* Convert to physical address and program free buffer pool */
		phy_addr = virt_to_phys(tmp_skb->data);
		msg.DataAddrMSB = (u32) (phy_addr >> 32);
		msg.DataAddrLSB = (u32) phy_addr;

#if defined CONFIG_NOT_COHERENT_CACHE && !defined CONFIG_APM86xxx_IOCOHERENT
		invalidate_dcache_range((u32) tmp_skb->data,
			(u32) tmp_skb->data + buf_len);
#endif
		/* Fill with the new buffer address */
		if (qm_blk == 0) {
			if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
				printk(KERN_ERR
					"Can not allocate QM FP buffer\n");
				return -1;
			}
		} else if (!is_apm86xxx_lite()) {
			if (unlikely((apm_qml_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
				printk(KERN_ERR
					"Can not allocate QML FP buffer\n");
				return -1;
			}
		}
	}
	return rc;
}

static int inline apm_enet_refill_fp(int queue_id, int size, int hdr_rsvd)
{
	u16 bufdatalen = apm_qm_encode_bufdatalen(size);
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	struct sk_buff *tmp_skb;
	phys_addr_t phy_addr;

	fp_msg_desc.msg = &msg;
	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = queue_id;

	tmp_skb = dev_alloc_skb(size + hdr_rsvd);
	if (unlikely(!tmp_skb)){
		printk(KERN_ERR "Failed to allocate new skb size %d\n",
			size + hdr_rsvd);
		return -ENOMEM;
	}
	skb_reserve(tmp_skb, hdr_rsvd);

	phy_addr = virt_to_phys(tmp_skb->data);

	/* Program individual WORD to avoid use of memzero */
	((u32 *) &msg)[0] = apm_enet_pkt_iscoherent() << 23 |
				(bufdatalen << 8) |
				(u32) (phy_addr >> 32);
	((u32 *) &msg)[1] = (u32) phy_addr;
	((u32 *) &msg)[2] = APM_QM_ETH_RTYPE << 24 | queue_id;
	((u32 *) &msg)[3] = (u32) tmp_skb;

#if defined CONFIG_NOT_COHERENT_CACHE && !defined CONFIG_APM86xxx_IOCOHERENT
	invalidate_dcache_range((u32) tmp_skb->data,
		(u32) tmp_skb->data + size);
#endif
	/* Fill with the new buffer address */
	if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
		kfree_skb(tmp_skb);
		printk(KERN_ERR "Can not replenish FP buffer\n");
		return -1;
	}
	return 0;
}

static int apm_enet_deinit_fp(int qid)
{
	struct apm_qm_qstate qstate;
	struct apm_qm_msg32 msg;
	struct apm_qm_msg_desc desc;
	int rc;
	int i;

	rc = apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
	if (rc < 0)
		return rc;
	desc.qid = qid;
	desc.mb_id = qid;
	desc.msg = &msg;
	for (i = 0; i < qstate.nummsgs; i++) {
		rc = apm_qm_fp_alloc_buf(&desc);
		if (rc < 0)
			break;
		if (msg.msg16.UserInfo)
			kfree_skb((struct sk_buff *) msg.msg16.UserInfo);
	}
	return 0;
}
#endif

static int apm_enet_init_nxtfp(int queue_id, int no_of_buffs, int qm_blk)
{
	int i;
	struct page *tmp_page;
	phys_addr_t phy_addr;
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	int rc = 0;

	memset(&msg, 0, sizeof(msg));
	fp_msg_desc.msg = &msg;

	/* Common fields */
	msg.C = apm_enet_pkt_iscoherent();
	msg.BufDataLen = apm_qm_encode_bufdatalen((u16) APM_ENET_PKT_NXTBUF_SIZE);
	msg.FPQNum = queue_id;
	msg.RType = APM_QM_ETH_RTYPE;

	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = queue_id;
	fp_msg_desc.msg = &msg;

	/* Program all the free buffer pools */
	for (i = 0; i < no_of_buffs; i++) {
		tmp_page = alloc_page(GFP_ATOMIC);
		if (unlikely(!tmp_page)) {
			printk(KERN_ERR "Failed to allocate new page");
			return -ENOMEM;
		}

		msg.UserInfo = (u32) tmp_page;

		/* Convert to physical address and program free buffer pool */
		phy_addr = page_to_phys(tmp_page);
		msg.DataAddrMSB = (u32) (phy_addr >> 32);
		msg.DataAddrLSB = (u32) phy_addr;

#if defined CONFIG_NOT_COHERENT_CACHE && !defined CONFIG_APM86xxx_IOCOHERENT
		invalidate_dcache_range((u32)page_address(tmp_page),
			(u32)page_address(tmp_page) + APM_ENET_PKT_NXTBUF_SIZE);
#endif
		/* Fill with the new buffer address */
		if (qm_blk == 0) {
			if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
				printk(KERN_ERR
					"Can not allocate QM Next FP buffer\n");
				return -1;
			}
		} else if (!is_apm86xxx_lite()) {
			if (unlikely((apm_qml_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
				printk(KERN_ERR
					"Can not allocate QML Next FP buffer\n");
				return -1;
			}
		}
	}
	return rc;
}

static int inline apm_enet_refill_nxtfp(int queue_id)
{
	u16 bufdatalen = apm_qm_encode_bufdatalen((u16) APM_ENET_PKT_NXTBUF_SIZE);
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	struct page *tmp_page;
	phys_addr_t phy_addr;

	fp_msg_desc.msg = &msg;
	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = queue_id;

	tmp_page = alloc_page(GFP_ATOMIC);
	if (unlikely(!tmp_page)){
		printk(KERN_ERR "Failed to allocate new page\n");
		return -ENOMEM;
	}

	phy_addr = page_to_phys(tmp_page);

	/* Program individual WORD to avoid use of memzero */
	((u32 *) &msg)[0] = apm_enet_pkt_iscoherent() << 23 |
				(bufdatalen << 8) |
				(u32) (phy_addr >> 32);
	((u32 *) &msg)[1] = (u32) phy_addr;
	((u32 *) &msg)[2] = APM_QM_ETH_RTYPE << 24 | queue_id;
	((u32 *) &msg)[3] = (u32) tmp_page;

#if defined CONFIG_NOT_COHERENT_CACHE && !defined CONFIG_APM86xxx_IOCOHERENT
	invalidate_dcache_range((u32)page_address(tmp_page),
		(u32)page_address(tmp_page) + APM_ENET_PKT_NXTBUF_SIZE);
#endif
	/* Fill with the new buffer address */
	if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
		free_page((u32)page_address(tmp_page));
		printk(KERN_ERR "Can not replenish Next FP buffer\n");
		return -1;
	}
	return 0;
}

#if !defined (CONFIG_SLAB_HW)
static int apm_enet_deinit_nxtfp(int qid)
{
	struct apm_qm_qstate qstate;
	struct apm_qm_msg32 msg;
	struct apm_qm_msg_desc desc;
	int rc;
	int i;

	rc = apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
	if (rc < 0)
		return rc;
	desc.qid = qid;
	desc.mb_id = qid;
	desc.msg = &msg;
	for (i = 0; i < qstate.nummsgs; i++) {
		rc = apm_qm_fp_alloc_buf(&desc);
		if (rc < 0)
			break;
		if (msg.msg16.UserInfo)
			free_page((u32)page_address((struct page *)msg.msg16.UserInfo));
	}
	return 0;
}
#endif

static int apm_enet_change_mtu(struct net_device *ndev, int new_mtu)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;
	int eth_running;
#if !defined (CONFIG_SLAB_HW)
	u32 core_id = apm_processor_id();
	int rc = 0;
#endif

	if (HW_MTU(new_mtu) < APM_ENET_MIN_MTU || HW_MTU(new_mtu) > APM_ENET_MAX_MTU) {
		printk(KERN_ERR "Invalid MTU: %d\n", new_mtu);
		return -EINVAL;
	}

	printk(KERN_INFO "changing MTU from %d to %d\n", ndev->mtu, new_mtu);

	eth_running = netif_running(ndev);
	if (eth_running) {
		netif_stop_queue(ndev);
		apm_gmac_rx_disable(priv);
		apm_gmac_tx_disable(priv);
	}
	ndev->mtu = new_mtu;
	apm_gmac_change_mtu(priv, HW_MTU(new_mtu));

#if !defined(CONFIG_SLAB_HW)
#ifdef CONFIG_PM
	/* Drain the free pool */
	rc = apm_enet_drain_fp(pdev,
			pdev->qm_queues[core_id].hw_fp_qid,
			pdev->qm_queues[core_id].hw_fp_pbn - 0x20, 0, 0);
	if (rc < 0)
		return rc;
	ENET_DEBUG("drain %d buffer from QID %d\n", rc,
		pdev->qm_queues[core_id].hw_fp_qid);
#endif
	/* Re-fill the free pool with new buffer size */
	rc = apm_enet_init_fp(pdev->qm_queues[core_id].hw_fp_qid,
			HW_MTU(ndev->mtu), APM_HW_PKT_BUF, 0,
			pdev->hdr_rsvd);
	if (rc)
		return rc;

#ifdef CONFIG_APM_ENET_OFFLOAD
	if (pdev->offload.offload_available & IPP_NETOFFLOAD_FW_MASK)
		apm_enet_offload_set_bufdatalen(pdev);
#endif
#endif

	if (eth_running) {
		apm_gmac_rx_enable(priv);
		apm_gmac_tx_enable(priv);
		netif_start_queue(ndev);
	}
	return 0;
}

#ifndef CONFIG_IE4000
#if !defined(CONFIG_SMP) && defined(CONFIG_APM86xxx_SHMEM)
int apm_enet_mdio_res_lock(struct apm_data_priv *priv, int lock)
{
	if (lock)
		atomic_cpu_lock();
	else
		atomic_cpu_unlock();
        return 0;
}
#else
int apm_enet_mdio_res_lock(struct apm_data_priv *priv, int lock)
{
	if (lock){
		spin_lock(&apm_mdio_lock);
	}
	else{
		spin_unlock(&apm_mdio_lock);
	}
	return 0;
}
#endif
static int apm_enet_mdio_read(struct mii_bus *bus, int mii_id, int regnum)
{
	struct apm_enet_dev_base *pdev = bus->priv;
	struct apm_data_priv *priv = &pdev->priv;
	u32 regval1;
	u32 regval2;
	u32 regval3;

mdio_read_again:

	/* take mdio lock */
	apm_enet_mdio_res_lock(priv, 1);

	apm_genericmiiphy_read(priv, mii_id, regnum, &regval1);
	if (pdev->wka_flag & 0x01) {
		/* Work around to MDIO errata (MDIO hold issue) */
		apm_genericmiiphy_read(priv, mii_id, regnum, &regval2);
		if (regval1 != regval2) {
			apm_genericmiiphy_read(priv, mii_id, regnum, &regval3);
			if (regval2 != regval3) {
				goto retry;
			}
			regval1 = regval2;
		}
	}

	PHY_PRINT("%s: bus=%d reg=%d val=%x\n", __func__, mii_id, regnum, regval1);

	/* release the lock */
	apm_enet_mdio_res_lock(priv, 0);

	return (int)regval1;

retry:
	/* release the lock */
	apm_enet_mdio_res_lock(priv, 0);
	/* try later */
	schedule();
	/* read again */
	goto mdio_read_again;
}

static int apm_enet_mdio_write(struct mii_bus *bus, int mii_id, int regnum,
			   u16 regval)
{
	struct apm_enet_dev_base *pdev = bus->priv;
	struct apm_data_priv *priv = &pdev->priv;

	PHY_PRINT("%s: bus=%d reg=%d val=%x\n", __func__, mii_id, regnum, regval);

	/* take the mdio lock */
	apm_enet_mdio_res_lock(priv, 1);

	apm_genericmiiphy_write(priv, mii_id, regnum, regval);

	/* release the lock */
	apm_enet_mdio_res_lock(priv, 0);

	return 0;
}

static int apm_enet_mdio_reset(struct mii_bus *bus)
{
	return 0;
}

static void apm_enet_mdio_link_change(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;
	struct phy_device *phydev = pdev->phy_dev;
	int status_change = 0;

	/* to reject cases of up-to-up and down-to-down */
	if(phydev->link != pdev->phy_link) {
		/* consider speed only if link is up */
		if (phydev->link) {
			if (pdev->phy_speed != phydev->speed) {
				/* check whether speed workaround is required on not */
				if((pdev->phy_speed_wka_count < 2) && (pdev->wka_flag & 0x02)){
					/* Increase count, Take no action and Try next time */
					pdev->phy_speed_wka_count++;
				} else {
					apm_gmac_init(priv, ndev->dev_addr, phydev->speed,
							HW_MTU(ndev->mtu), priv->crc, 0);
					pdev->phy_speed = phydev->speed;
					status_change = 1;
					/* reset the count */
					pdev->phy_speed_wka_count = 0;
				}
			} else {
				/* speed matches to previous, reset speed count */
				pdev->phy_speed_wka_count = 0;
			}
		} else {
			/* link status down, reset speed count */
			pdev->phy_speed_wka_count = 0;
		}

		/* check whether link workaround is required on not */
		if((pdev->phy_link_wka_count < 2) && (pdev->wka_flag & 0x02)
				&& (phydev->state != PHY_HALTED)){
			/* Increase count */
			pdev->phy_link_wka_count++;
			if(phydev->state == PHY_NOLINK) {
				/* Do polling again and Try next time */
				phydev->state = PHY_RUNNING;
			netif_carrier_on(phydev->attached_dev);
			}
		} else {
			if (!phydev->link) {
				pdev->phy_speed = 0;
			}
			pdev->phy_link = phydev->link;
			status_change = 1;
			/* reset the link count */
			pdev->phy_link_wka_count = 0;
			/* link status has changed, reset speed count */
			pdev->phy_speed_wka_count = 0;
		}
	} else {
		/* link matches to previous, reset link count */
		pdev->phy_link_wka_count = 0;
	}

	if (status_change) {
		if (phydev->link) {
			if (pdev->phy_speed == phydev->speed) {
				/* Enable Rx & Tx in MAC */
				apm_gmac_rx_enable(priv);
				apm_gmac_tx_enable(priv);
				/* Print link up banner */
				printk(KERN_INFO "%s: link up %d Mbps\n", ndev->name, phydev->speed);
			}
		} else {
			/* No need to TX, just disable RX */

			apm_gmac_rx_disable(priv);

			/* Print link down banner */
			printk(KERN_INFO "%s: link down\n", ndev->name);
		}
	}
}

static int apm_enet_mdio_probe(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;
	struct phy_device *phydev = NULL;
	int phy_addr;

	/* find the first phy */
	for (phy_addr = 0; phy_addr < PHY_MAX_ADDR; phy_addr++) {
		if (pdev->mdio_bus->phy_map[phy_addr]) {
			phydev = pdev->mdio_bus->phy_map[phy_addr];
			break;
		}
	}

	if (!phydev) {
		printk (KERN_ERR "%s: no PHY found\n", ndev->name);
		return -1;
	}

	pdev->phy_link = 0;
	pdev->phy_speed = 0;
	pdev->phy_link_wka_count = 0;
	pdev->phy_speed_wka_count = 0;

	/* attach the mac to the phy */
	if (priv->phy_mode == PHY_MODE_SGMII) {
		phydev = phy_connect(ndev, dev_name(&phydev->dev),
			&apm_enet_mdio_link_change, PHY_INTERFACE_MODE_SGMII);
	} else {
		phydev = phy_connect(ndev, dev_name(&phydev->dev),
			&apm_enet_mdio_link_change, PHY_INTERFACE_MODE_RGMII);
	}

	if (IS_ERR(phydev)) {
		pdev->phy_dev = NULL;
		printk(KERN_ERR "%s: Could not attach to PHY\n", ndev->name);
		return PTR_ERR(phydev);
	} else {
		pdev->phy_dev = phydev;
	}

	printk("%s: phy_id=0x%08x phy_drv=\"%s\"",
		ndev->name, phydev->phy_id, phydev->drv->name);

	return 0;
}
#endif
static inline int eth_hdr_len(const void *data)
{
	const struct ethhdr *eth = data;

	return eth->h_proto == htons(ETH_P_8021Q) ? VLAN_ETH_HLEN : ETH_HLEN;
}

static inline int apm_enet_free_comp_skb(struct sk_buff * skb)
{
	if (likely(skb != NULL)) {
		FREE_ELL_PTR(skb);
		FREE_SKB(skb);
		if (cmp_cnt == 0)
			printk(KERN_ERR "Comp Q counter is zero.\n");
		else
			--cmp_cnt;
		return 0;
	} else {
		printk(KERN_ERR "completion skb is NULL\n");
		return -1;
	}
}

/* Packet transmit function */
static int apm_enet_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	phys_addr_t paddr;
	struct apm_qm_msg_desc tx_msg_desc;
	struct apm_qm_msg64 msg;
	u32 clean_compq = 0;
#ifndef NOTIFICATION_OFF
	u32 skbval;
#elif defined CONFIG_SLAB_HW
	struct kmem_cache *c;
	u8 is_eth_fp = 0;
	u8 is_ppc_fp = 0;
#endif
	struct apm_qm_msg16 *msg16;
	struct apm_qm_msg_up8 *msg8_1;
	int core_id = apm_processor_id();
	u32 nr_frags = skb_shinfo(skb)->nr_frags;

	if (pdev->pm_flags) {
		/* While port is in suspend, do not allow Tx packet. */
		return NETDEV_TX_BUSY;
	}

	paddr = virt_to_phys((volatile void *) skb->data);

	ENET_DEBUGTX("TX Frame PADDR: 0x%010llx VADDR: 0x%p len: %d frag %d\n",
		paddr, skb->data, skb->len, nr_frags);

	msg16 = &msg.msg32_1.msg16;
	msg8_1 = &msg.msg32_1.msgup8_1;

	/* Packet not fragmented */
	if (likely(nr_frags == 0)) {
		memset(&msg.msg32_1, 0, sizeof(msg.msg32_1));
		SAVE_ELL_PTR(skb, NULL);
		/* Prepare QM message */
		msg16->BufDataLen = apm_enet_len_encode(skb->len);
#if defined(CONFIG_SLAB_HW)
		msg16->BufDataLen = apm_qm_encode_datalen(2048);
		c = virt_to_cache_ext(skb->head);
		/* Check if allocated from ethernet free pool */
		if (c->flags & __GFP_FREEPOOL_ETH0) {
			/* Ask Enet hardware to free up buffer after its done */
			msg16->FPQNum = eth0_fp_id;
			msg8_1->HR = 1;
			is_eth_fp = 1;
		} else if (c->flags & __GFP_FREEPOOL_ETH1) {
			/* Ask Enet hardware to free up buffer after its done */
			msg16->FPQNum = eth1_fp_id;
			msg8_1->HR = 1;
			is_eth_fp = 1;
		} else if (c->flags & __GFP_FREEPOOL_PPC) {
			is_ppc_fp = 1;
			msg8_1->HR = 1;
			msg16->FPQNum = ppc_fp_id;
		}
#endif
		msg16->FPQNum = 0;
		msg16->DataAddrMSB = (u32) (paddr >> 32);
		msg16->DataAddrLSB = (u32) paddr;

		ENET_DUMP("TX ", skb->data, skb->len);
	} else {
		struct apm_qm_msg_ext8 *ext_msg_ll;
		struct apm_qm_msg_ext8 *ext_msg_ll_ptr;
		struct apm_qm_msg_ext8 *ext_msg;
		skb_frag_t *frag;
		u8 *vaddr;
		int offset = 0;
		int len = 0;
		int frag_no;
		int ell_bcnt;
		int ell_cnt;
		int i;

		memset(&msg, 0, sizeof(msg));

		/* First Fragment */
		msg16->FPQNum = 0;
		msg16->BufDataLen = apm_enet_len_encode(skb_headlen(skb));
		msg16->DataAddrMSB = (u32) (paddr >> 32);
		msg16->DataAddrLSB = (u32) paddr;
		msg16->UserInfo = (u32) skb;
		msg16->NV = 1;		/* 64B message */

		/* 2nd, 3rd, and 4th fragments */
		frag_no = 0;
		vaddr = NULL;
		ext_msg = (struct apm_qm_msg_ext8 *) &msg.msg32_2;
		for (i = 0; i < 3 && frag_no < nr_frags; i++) {
			if (vaddr == NULL) {
				frag = &skb_shinfo(skb)->frags[frag_no];
				len = frag->size;
				vaddr = page_address(frag->page.p) + frag->page_offset;
				offset = 0;
#if defined(CONFIG_NOT_COHERENT_CACHE)
				flush_dcache_range((u32) vaddr,
						(u32) vaddr + len);
#endif
				ENET_DEBUGTX("SKB Frag[%d] 0x%p len %d\n",
						frag_no, vaddr, len);
			}
			paddr = virt_to_phys(vaddr + offset);
			ext_msg->NxtDataAddrMSB = (u32) (paddr >> 32);
			ext_msg->NxtDataAddrLSB = (u32) paddr;
			if (len <= 16*1024) {
				/* Encode using 16K buffer size format */
				ext_msg->NxtBufDataLength =
						apm_enet_len_encode(len);
				vaddr = NULL;
				frag_no++;
			} else {
				len -= 16*1024;
				offset += 16*1024;
				/* Encode using 16K buffer size format */
				ext_msg->NxtBufDataLength = 0;
			}
			ENET_DEBUGTX("Frag[%d] PADDR 0x%X.%08X len %d\n",
				i, ext_msg->NxtDataAddrMSB,
				ext_msg->NxtDataAddrLSB,
				ext_msg->NxtBufDataLength);
			ext_msg++;
		}
		/* Determine no more fragment, last one, or more than one */
		if (vaddr == NULL) {
			/* Check next fragment */
			if (frag_no >= nr_frags) {
				/* No more fragment */
				goto no_more_frag;
			} else {
				frag = &skb_shinfo(skb)->frags[frag_no];
				if (frag->size <= 16*1024 &&
				    (frag_no + 1) >= nr_frags)
					goto one_more_frag;
				else
					goto more_than_one_frag;
			}
		} else if (len <= 16*1024) {
			/* Current fragment <= 16K, check if last fragment */
			if ((frag_no + 1) >= nr_frags)
				/* last fragment */
				goto one_more_frag;
			else	/* Not last fragment */
				goto more_than_one_frag;
		} else {
			/* Current fragment requires two pointers */
			goto more_than_one_frag;
		}

no_more_frag:	/* Terminate all remaining pointers */
		SAVE_ELL_PTR(skb, NULL);
		for ( ; i < 4; i++) {
			ext_msg->NxtBufDataLength = 0x7800;
			ext_msg++;
		}
		goto done;

one_more_frag:
		SAVE_ELL_PTR(skb, NULL);
		if (vaddr == NULL) {
			frag = &skb_shinfo(skb)->frags[frag_no];
			len = frag->size;
			vaddr = page_address(frag->page.p) + frag->page_offset;
			offset = 0;
#if defined(CONFIG_NOT_COHERENT_CACHE)
			flush_dcache_range((u32) vaddr,
					(u32) vaddr + len);
#endif
			ENET_DEBUGTX("SKB Frag[%d] 0x%p len %d\n",
					frag_no, vaddr, len);
		}
		paddr = virt_to_phys(vaddr + offset);
		ext_msg->NxtDataAddrMSB = (u32) (paddr >> 32);
		ext_msg->NxtDataAddrLSB = (u32) paddr;
		/* Encode using 16K buffer size format */
		ext_msg->NxtBufDataLength = apm_enet_len_encode(len);
		ENET_DEBUGTX("Frag[%d] PADDR 0x%X.%08X len %d\n",
			i, ext_msg->NxtDataAddrMSB,
			ext_msg->NxtDataAddrLSB,
			ext_msg->NxtBufDataLength);
		goto done;

more_than_one_frag:
		msg16->LL = 1;		/* Extended link list */
		ext_msg_ll_ptr = kmalloc(255 * sizeof(struct apm_qm_msg_ext8),
					GFP_KERNEL);
		if (ext_msg_ll_ptr == NULL) {
			printk(KERN_ERR
				"Out of memory for HW Ethernet link list\n");
			pdev->estats.tx_dropped++;
			dev_kfree_skb(skb);
			return NETDEV_TX_OK;
		}
		ell_bcnt = 0;
		ell_cnt = 0;
		ext_msg_ll = ext_msg_ll_ptr;
		SAVE_ELL_PTR(skb, ext_msg_ll);
		paddr = virt_to_phys(ext_msg_ll);
		ext_msg->NxtDataAddrMSB = (u32) (paddr >> 32);
		ext_msg->NxtDataAddrLSB = (u32) paddr;
		for (i = 0; i < 255 && frag_no < nr_frags; ) {
			if (vaddr == NULL) {
				frag = &skb_shinfo(skb)->frags[frag_no];
				len = frag->size;
				vaddr = page_address(frag->page.p) + frag->page_offset;
				offset = 0;
#if defined(CONFIG_NOT_COHERENT_CACHE)
				flush_dcache_range((u32) vaddr,
						(u32) vaddr + len);
#endif
				ENET_DEBUGTX("SKB Frag[%d] 0x%p len %d\n",
						frag_no, vaddr, len);
			}
			paddr = virt_to_phys(vaddr + offset);
			ext_msg_ll->NxtFPQNum = 0;
			ext_msg_ll->Rv1 = 0;
			ext_msg_ll->Rv2 = 0;
			ext_msg_ll->NxtDataAddrMSB = (u32) (paddr >> 32);
			ext_msg_ll->NxtDataAddrLSB = (u32) paddr;
			if (len <= 16*1024) {
				/* Encode using 16K buffer size format */
				ext_msg_ll->NxtBufDataLength =
						apm_enet_len_encode(len);
				ell_bcnt += len;
				vaddr = NULL;
				frag_no++;
			} else {
				len -= 16*1024;
				offset += 16*1024;
				ell_bcnt += 16*1024;
				/* Encode using 16K buffer size format */
				ext_msg_ll->NxtBufDataLength = 0;
			}
			ell_cnt++;
			ENET_DEBUGTX("Frag ELL[%d] PADDR 0x%X.%08X len %d\n",
				i, ext_msg_ll->NxtDataAddrMSB,
				ext_msg_ll->NxtDataAddrLSB,
				ext_msg_ll->NxtBufDataLength);
			ext_msg_ll++;
			i++;
		}
		/* Encode the extended link list byte count and link count */
		*(u32 *) ext_msg = (ell_bcnt << 12) | (ell_cnt << 4);
		ENET_QMSG("ELL msg ", ext_msg_ll_ptr, 8 * ell_cnt);
#if defined(CONFIG_NOT_COHERENT_CACHE)
		flush_dcache_range((u32) ext_msg_ll_ptr,
				(u32) ext_msg_ll_ptr +
				ell_cnt * sizeof(struct apm_qm_msg_ext8));
#endif
	}
done:
	/* Common message Fields */
	msg16->C = apm_enet_pkt_iscoherent();
	msg16->UserInfo = (u32) skb;
	msg8_1->HE = 1;
	msg8_1->H0Enq_Num = pdev->qm_queues[core_id].comp_qid;

	/* Set TYPE_SEL for egress work message */
	msg8_1->H0Info_msb = (TYPE_SEL_WORK_MSG << 4);

	/* Enable CRC insertion */
	if (!pdev->priv.crc)
		msg8_1->H0Info_msb |= (TSO_INS_CRC_ENABLE << 3); /* Set InsertCRC bit */

	/* Setup mac header length H0Info */
	msg8_1->H0Info_lsb |= (eth_hdr_len(skb->data) & TSO_ETH_HLEN_MASK) << 12;

	/* VLAN tag insertion offload processing */
	if (likely(ndev->features & (NETIF_F_HW_VLAN_CTAG_RX | NETIF_F_HW_VLAN_CTAG_TX)) &&
	    likely(skb->vlan_tci != 0x0)) {
		msg8_1->H0Info_msb |= (1 << 2); /* Set InsertVLAN bit */
		if (pdev->port_id & 0x1) { /* For port 1 & 3*/
			apm_enet_wr32(&pdev->priv, BLOCK_ETH_GBL,
				      TSO_CFG_INSERT_VLAN_1_ADDR,
				      (htons(ETH_P_8021Q) << 16) | htons(skb->vlan_tci));
		} else { /* For port 0 & 2*/
			apm_enet_wr32(&pdev->priv, BLOCK_ETH_GBL,
				      TSO_CFG_INSERT_VLAN_0_ADDR,
				      (htons(ETH_P_8021Q) << 16) | htons(skb->vlan_tci));
		}
	}

	/* Checksum offload processing */
	if (likely(ndev->features & NETIF_F_IP_CSUM) &&
	    (likely(skb->protocol == htons(ETH_P_IP)) ||
	     likely(skb->protocol == htons(ETH_P_8021Q)))) {
		int maclen = eth_hdr_len(skb->data);
		struct iphdr *iph = ip_hdr(skb);
		u32 ihl = ip_hdrlen(skb) >> 2;

		if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET))) {
			goto xmit;
		}

		if (iph->protocol == IPPROTO_TCP) {
			int xhlen;

			xhlen = tcp_hdrlen(skb)/4;
			msg8_1->H0Info_lsb |=
					(xhlen & TSO_TCP_HLEN_MASK) |
					((ihl & TSO_IP_HLEN_MASK) << 6) |
					(TSO_CHKSUM_ENABLE << 22) |
					(TSO_IPPROTO_TCP << 24);
			ENET_DEBUGTX("Checksum Offload H0Info 0x%02X.%08X\n",
				msg8_1->H0Info_msb, msg8_1->H0Info_lsb);

			/* TCP Segmentation offload processing */
			if (unlikely(ndev->features & NETIF_F_TSO)) {
				u32 mss = skb_shinfo(skb)->gso_size;
				int mss_len = skb->len - maclen + ihl + xhlen;

				if (skb_headlen(skb) < maclen + ihl + xhlen) {
					/* HW requires all header resides
					   in the first buffer */
					printk(KERN_ERR
						"Un-support header length "
						"location by Ethernet HW\n");
					pdev->estats.tx_dropped++;
					dev_kfree_skb(skb);
					return NETDEV_TX_OK;
				}
				if (mss && mss_len > mss) {
					struct apm_data_priv *priv;

					priv = &pdev->priv;
					if (mss != pdev->mss) {
						apm_enet_change_mss(priv, mss);
						pdev->mss = mss;
					}
					msg8_1->H0Info_lsb |=
						((0 & TSO_MSS_MASK) << 20) |
						((TSO_ENABLE & TSO_ENABLE_MASK) << 23);
					ENET_DEBUG_TSO(
						"TCP TSO H0Info 0x%02X.%08X mss %d",
						msg8_1->H0Info_msb,
						msg8_1->H0Info_lsb, mss);
				}
			}
		} else if (iph->protocol == IPPROTO_UDP) {
			msg8_1->H0Info_lsb |=
				(UDP_HDR_SIZE & TSO_TCP_HLEN_MASK) |
				((ihl & TSO_IP_HLEN_MASK) << 6) |
				(TSO_CHKSUM_ENABLE << 22) |
				(TSO_IPPROTO_UDP << 24);
			ENET_DEBUGTX("Checksum Offload H0Info 0x%02X.%08X",
			msg8_1->H0Info_msb, msg8_1->H0Info_lsb);
		} else {
			msg8_1->H0Info_lsb |= (ihl & TSO_IP_HLEN_MASK) << 6;
		}
	}

xmit:
	/* Flush here as it is referenced multiple place */
#if defined(CONFIG_NOT_COHERENT_CACHE)
	if (likely(nr_frags == 0))
		flush_dcache_range((u32) skb->data,
				(u32) skb->data + skb->len);
	else
		flush_dcache_range((u32) skb->data,
				(u32) skb->data + skb_headlen(skb));
#endif

	/* Push the work message to ENET HW */
	tx_msg_desc.qid = pdev->qm_queues[core_id].default_tx_qid;
	tx_msg_desc.msg = &msg;
	ENET_DEBUGRXTX("TX CQID %d QID %d len %d\n",
		msg8_1->H0Enq_Num, tx_msg_desc.qid, msg16->BufDataLen);
	ENET_QMSG("TX msg ", tx_msg_desc.msg, msg16->NV ? 64 : 32);
	apm_qm_push_msg(&tx_msg_desc);

	/* Update local statistics */
	ndev->trans_start = jiffies;
	++pdev->stats.tx_packets;
	pdev->stats.tx_bytes += skb->len;
#if defined(CONFIG_SLAB_HW)
#if defined(FAM_BUF_POOL)
#else
	FREE_ELL_PTR(skb);
	if (is_eth_fp == 1 || is_ppc_fp == 1)
		free_skb_control(skb); /* HW is freeing the data part */
	else
		FREE_SKB(skb);
#endif
#elif defined(NOTIFICATION_OFF)
	FREE_ELL_PTR(skb);
	FREE_SKB(skb);
#endif

#if !defined (NOTIFICATION_OFF) && !defined (CONFIG_SLAB_HW)
	if (++cmp_cnt >= 8)  {
		ENET_DEBUGRXTX("Checking completion queue %d mailbox %d\n",
			pdev->qm_queues[core_id].comp_qid,
			pdev->qm_queues[core_id].comp_mb);
empty_again:
		while ((skbval = apm_qm_pull_comp_msg2(pdev->qm_queues[core_id].comp_mb)) != -1) {
			/* Retrieve skb address */
			if (apm_enet_free_comp_skb((struct sk_buff *) skbval))
				break;
		}

		apm_qm_pull_comp_flush(pdev->qm_queues[core_id].comp_mb);

		if (clean_compq && (cmp_cnt > pdev->tx_cqt_low))
			goto empty_again;

                if (unlikely(cmp_cnt > pdev->tx_cqt_hi)) {
			clean_compq = 1;
			goto empty_again;
		}
	}
#endif

	return NETDEV_TX_OK;
}

/* Process received frame */
#if !defined (CONFIG_SLAB_HW) && !defined (CONFIG_DRIVER_POOL)
static int apm_enet_rx_frame(struct apm_qm_msg_desc *rx_msg_desc)
{
	struct apm_qm_msg32 *msg = (struct apm_qm_msg32 *) rx_msg_desc->msg;
	struct apm_qm_msg16 *msg16 = &msg->msg16;
	struct sk_buff *skb;
	struct apm_enet_dev_base *pdev;
	struct eth_queue_ids *qm_queues;
	unsigned int truesize;

	u32 data_mtu;
	/* Save variables locally from MailBox as we will lose the slot */
	u32 data_len = apm_qm_decode_datalen(msg16->BufDataLen);
	u8 NV = msg16->NV;
#if defined(CONFIG_APM862xx)
	u8 LErr = msg16->LErr;
#else
	u8 LErr = ((u8) msg16->ELErr << 3) | msg16->LErr;
#endif
	u8 HC = msg16->HC;
	u32 UserInfo = msg16->UserInfo;
#ifdef ENET_DBGRXTX
	u32 DataAddrMSB = msg16->DataAddrMSB;
	u32 DataAddrLSB = msg16->DataAddrLSB;
#endif
#ifdef CONFIG_APM_ENET_OFFLOAD
	struct apm_qm_msg_up8 *msgup8_1 = &msg->msgup8_1;
	u16 offload_enabled = msgup8_1->HE;
#endif

	ENET_DEBUGRXTX("RX frame QID %d Rtype %d\n",
		rx_msg_desc->qid, msg16->RType);

	pdev = apm_enet_get_qidctx(rx_msg_desc->qid);

#ifdef ENET_CHK
	if (unlikely(pdev == NULL)) {
		ENET_DEBUG_ERR("private ptr for QID %d is NULL\n",
			rx_msg_desc->qid);
		print_hex_dump(KERN_INFO, "QM msg:",
			DUMP_PREFIX_ADDRESS, 16, 4, msg, NV ? 64 : 32, 1);
		goto err_unfill;
	}
#endif

	data_mtu = HW_MTU(pdev->ndev->mtu);
#if !defined(CONFIG_SMP) || defined(SMP_LOAD_BALANCE)
	qm_queues = &pdev->qm_queues[apm_processor_id()];
#else
	qm_queues = &pdev->qm_queues[0];
#endif

	/* Retrieve skb address */
	skb = (struct sk_buff *)UserInfo;
#ifdef ENET_CHK
	if (unlikely(UserInfo == 0)) {
		ENET_DEBUG_ERR("ENET UserInfo is NULL for QID %d MB %d\n",
			rx_msg_desc->qid, rx_msg_desc->mb_id);
		print_hex_dump(KERN_INFO, "QM msg:",
			DUMP_PREFIX_ADDRESS, 16, 4, msg, NV ? 64 : 32, 1);

		if (msg16->FPQNum == qm_queues->rx_fp_qid)
			goto err_refill;
		else
			goto err_unfill;
	}

	if (unlikely(skb->head == NULL) || unlikely(skb->data == NULL)) {
		ENET_DEBUG_ERR("Corrupted QM msg skb 0x%p head 0x%p data 0x%p\n",
			skb, skb->head, skb->data);
		print_hex_dump(KERN_INFO, "QM msg:",
			DUMP_PREFIX_ADDRESS, 16, 4, msg, NV ? 64 : 32, 1);

		if (msg16->FPQNum == qm_queues->rx_fp_qid)
			goto err_refill;
		else
			goto err_unfill;
	}

	if (unlikely(skb->len)) {
		ENET_DEBUG_ERR("Corrupted QM msg skb 0x%p len %d\n",
			skb, skb->len);
		print_hex_dump(KERN_INFO, "QM msg:",
			DUMP_PREFIX_ADDRESS, 16, 4, msg, NV ? 64 : 32, 1);

		if (msg16->FPQNum == qm_queues->rx_fp_qid)
			goto err_refill;
		else
			goto err_unfill;
	}
#endif

	/* Check for error, if packet received with error */
	if (unlikely(LErr)) {
#if defined(CONFIG_APM862xx)
		if (LErr == 7)
			goto process_pkt;
#endif
		if (LErr == 5)
			goto process_pkt;

		pdev->estats.rx_hw_errors++;
		apm_enet_parse_error(LErr, HC, rx_msg_desc->qid);

		if (msg16->FPQNum == qm_queues->rx_fp_qid)
			goto err_refill;
		else
			goto err_unfill;

		print_hex_dump(KERN_ERR, "QM Msg: ",
			DUMP_PREFIX_ADDRESS, 16, 4, msg, NV ? 64 : 32, 1);
		return -1;
	}

process_pkt:
	/* prefetch data in cache */
	prefetch(skb->data - pdev->hdr_rsvd);
#if APM_ENET_SKB_RESERVE_SIZE > NET_IP_ALIGN
	prefetch(skb->data - NET_IP_ALIGN);
#endif
	ENET_DEBUGRXTX("RX port %d SKB data VADDR: 0x%p PADDR: 0x%02X_%08X\n",
		pdev->port_id, skb->data, DataAddrMSB, DataAddrLSB);

	if (likely(!NV)) {
		/* Strip off CRC as HW isn't doing this */
		data_len -= 4;
#ifdef CONFIG_APM_ENET_OFFLOAD
#if defined(CONFIG_APM_QOS)
		/* CL 40997 change conditions to do offload. It blocks traffic of
		 * APM QoS. This is the work-around */
		u16 offload_type;
		offload_type = msgup8_1->H0FPSel;
		if (offload_type && offload_enabled) {
#else
		/* APM_ETH_OFFLOAD enabled */
		if (offload_enabled) {
#endif
			u16 internal_eport = msgup8_1->HR;

			/* APM_ETH_OFFLOAD enabled and EGRESS Port is Internal interface */
			if (internal_eport) {
				if(apm_ethoffload_ops.perform_offload(CLE_INT_PORT0, (void *)msg, data_len)){
					apm_enet_refill_fp(qm_queues->rx_fp_qid, data_mtu, pdev->hdr_rsvd);
				}
			/* APM_ETH_OFFLOAD enabled and EGRESS Port is External interface */
				/* Check for external interface netif_carrier_ok & !netif_queue_stopped */
			} else if (apm_ethoffload_ops.check_offload((void *)msg, data_len,
					pdev->offload.bufdatalen.val)) {
				apm_enet_refill_fp(qm_queues->rx_fp_qid, data_mtu, pdev->hdr_rsvd);
			}
			goto _ret_rx_frame;
		}
#endif
		skb_put(skb, data_len);
		ENET_DEBUGRX("RX port %d SKB len %d\n",
			pdev->port_id, data_len);
	} else {
		struct apm_qm_msg_ext8 *ext_msg;
		int i;

		/* Multiple fragment */
		skb_put(skb, data_len);
		ENET_DEBUGRX("RX port %d SKB multiple len %d\n",
			pdev->port_id, data_len);

		/* Handle fragments */
		ext_msg = (struct apm_qm_msg_ext8 *) &msg[1];
		for (i = 0; i < 4; i++) {
			struct page *tmp_page;
			void *data;
			int frag_size;
			if (!apm_qm_nxtbufdatalen_is_valid(ext_msg[i].NxtBufDataLength)) {
				break;
			}
			data = phys_to_virt(
					((u64) ext_msg[i].NxtDataAddrMSB << 32) |
					ext_msg[i].NxtDataAddrLSB);
			tmp_page = virt_to_page(data);
			if (!tmp_page) {
				kfree_skb(skb);
				skb = NULL;
				goto err_refill;
			}
			frag_size = apm_qm_decode_datalen(
						ext_msg[i].NxtBufDataLength);
			if (i >= 3 ||
			    !apm_qm_nxtbufdatalen_is_valid(ext_msg[i].NxtBufDataLength)) {
				/* Strip off CRC as HW does not handle this */
				frag_size -= 4;
			}
			truesize = ALIGN(frag_size, L1_CACHE_BYTES);
			skb_add_rx_frag(skb, i, tmp_page, 0, frag_size, truesize);
			apm_enet_refill_nxtfp(qm_queues->rx_nxtfp_qid);
		}
	}
	ENET_DUMP("RX ", (u8 *) skb->data, data_len);

	apm_enet_refill_fp(qm_queues->rx_fp_qid, data_mtu, pdev->hdr_rsvd);
	skb->protocol = eth_type_trans(skb, pdev->ndev);

#if defined(IPV4_RX_CHKSUM) || defined(IPV4_TSO)
	if (likely(pdev->features & FLAG_RX_CSUM_ENABLED) &&
	    likely(LErr == 0) &&
	    likely(skb->protocol == htons(ETH_P_IP))) {
		struct iphdr *iph = (struct iphdr *) skb->data;
		if (likely(!(iph->frag_off & htons(IP_MF | IP_OFFSET))) ||
			likely(iph->protocol != IPPROTO_TCP &&
			iph->protocol != IPPROTO_UDP)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
	}
#endif
	if (unlikely(in_irq())) {
		printk(":::Shouldn't have come here:::Giving"
		       "frame to stack in IRQ\n");
#ifdef DRIVER_LOOPBACK
		apm_enet_start_xmit(skb, ndev);
#if defined(NOTIFICATION_OFF)
		FREE_SKB(skb);
#endif
#elif defined DRIVER_DROP
		FREE_SKB(skb);
		++pdev->estats.rx_dropped_stack;
#else
		ENET_DEBUGRXTX("Calling netif_rx\n");
		if (unlikely(netif_rx(skb) == NET_RX_DROP)) {
			++pdev->estats.rx_dropped_stack;
		}
#endif
	} else {
#ifdef DRIVER_LOOPBACK
		apm_enet_start_xmit(skb, ndev);
#if defined(NOTIFICATION_OFF)
		FREE_SKB(skb);
#endif
#elif defined DRIVER_DROP
		FREE_SKB(skb);
		++pdev->estats.rx_dropped_stack;
#else
		netif_receive_skb(skb);
#endif
	}

#ifdef CONFIG_APM_ENET_OFFLOAD
_ret_rx_frame:
#endif
	++pdev->stats.rx_packets;
	pdev->stats.rx_bytes += data_len;

	return 0;

err_refill:
	if (skb != NULL)
		FREE_SKB(skb);

	apm_enet_refill_fp(qm_queues->rx_fp_qid, data_mtu, pdev->hdr_rsvd);
err_unfill:
	return -1;
}
#endif

int apm_enet_rx_irq(struct apm_qm_msg_desc *rx_msg_desc)
{
	struct apm_enet_dev_base *pdev;

	pdev = apm_enet_get_qidctx(rx_msg_desc->qid);

#ifdef ENET_CHK
	if (pdev == NULL) {
		printk(KERN_ERR "Context is NULL for QID %d MBoxID %d\n",
			rx_msg_desc->qid, rx_msg_desc->mb_id);
		return -1;
	}
#endif

#ifdef CONFIG_NAPI
	ENET_DEBUGRXTX("Rx Frame interface %d in NAPI\n", pdev->port_id);

	/* Schedule polling */
	if (napi_schedule_prep(&pdev->napi)) {
		/* Disable interrupts for this port */
		ENET_DEBUGRXTX("RX disable interrupt MBID %d\n",
			   rx_msg_desc->mb_id);
		apm_qm_disable_mb_irq(rx_msg_desc->mb_id);

		pdev->in_poll_rx_msg_desc.mb_id = rx_msg_desc->mb_id;
		pdev->in_poll_rx_msg_desc.qid = rx_msg_desc->qid;

		/* Tell system we have work to be done. */
		__napi_schedule(&pdev->napi);
	}
	return 1;
#else
	return apm_enet_rx_frame(rx_msg_desc);
#endif
}

static void apm_enet_timeout(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;
	apm_gmac_reset(priv);
}

/* Will be called whenever the device will change state to 'Up' */
static int apm_enet_open(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_enet_dev *enet_dev =
		(struct apm_data_enet_dev *)pdev;
	struct apm_data_priv *priv = &pdev->priv;
#ifdef ENET_LINK_IRQ
	u32 speed, state;
#endif

	/* Initialize Eth subsystem if this is master core for this port */
	if (!enet_dev->hw_config)
		goto init_done;

	ENET_DEBUG("Master core config for port %d\n", pdev->port_id);
#if (defined(CONFIG_APM_ENET_LRO) && defined(CONFIG_PPC_64K_PAGES))||(defined(CONFIG_APM_ENET_QOS))
	if (!enet_dev_glb.apm_preclass_init_done[pdev->port_id]) {
		#ifdef CONFIG_APM_ENET_LRO
			if (pdev->lro.lro_available)
				apm_enet_lro_init(pdev);
			else if (enet_dev_glb.ipp_loaded)
				printk("LRO feature is disabled in SlimPRO firmware\n");
		#endif
		#ifdef CONFIG_APM_ENET_QOS
			apm_enet_qos_init(pdev);
		#endif
		enet_dev_glb.apm_preclass_init_done[pdev->port_id] = 1;
	}
#endif

init_done:
#if defined(CONFIG_PM)
	if (pdev->port_id == 0) {
		if (wol_state_saved &&
		    !is_wake_on_lan_enabled()) {
			change_wake_on_lan_state(wol_state_value);
		}
		wol_state_saved = 0;
	}
#endif

#ifndef CONFIG_IE4000
	/* start phy */
	if (pdev->phy_dev) {
		phy_start(pdev->phy_dev);
	}
#endif
	/* start network queue */
	netif_start_queue(ndev);

	if (pdev->ipg > 0)
		apm_gmac_set_ipg(priv, pdev->ipg);
#ifdef ENET_LINK_IRQ
	apm_gmac_phy_link_mode(priv, &speed, &state);
	pdev->link_status = state;
	apm_enet_enable_link_intr(priv, pdev->link_status);
#endif
	return 0;
}

static int apm_enet_close(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);

	/* If WoL port going down then save WoL state
	 * and restore it later when WoL port is going up.
	 */
#if defined(CONFIG_PM)
	if (pdev->port_id == 0) {
		wol_state_saved = 1;
		wol_state_value = is_wake_on_lan_enabled();
		change_wake_on_lan_state(0);
	}
#endif

	/* Stop xmit queue */
	netif_stop_queue(ndev);

	/* stop phy */
	if (pdev->phy_dev) {
		phy_stop(pdev->phy_dev);
	}

#ifdef ENET_LINK_IRQ
	/* Disable link status interrupt for this port only */
	apm_enet_enable_link_intr(&pdev->priv, 0);
#endif
	return 0;
}

unsigned int find_port(char *device)
{
	int i;

	for (i = 0;i < MAX_PORTS; i++) {
		if (!enet_dev[i] || !enet_dev[i]->dev_base.ndev)
			continue;

		if (!strcmp(device, enet_dev[i]->dev_base.ndev->name))
			return i;
	}

	return -1;
}

struct net_device *find_netdev(int port_id)
{
	if (port_id >= MAX_PORTS || enet_dev[port_id] == NULL)
		return NULL;

	return enet_dev[port_id]->dev_base.ndev;
}

struct eth_queue_ids *find_ethqids(int port_id, int core_id)
{
	struct apm_enet_dev_base *pdev;
	struct net_device *dev;

	if (port_id > MAX_PORTS || core_id > MAX_CORES
			|| ((dev = find_netdev(port_id)) == NULL))
		return NULL;

	pdev = netdev_priv(dev);

	return &pdev->qm_queues[core_id];
}

static int apm_enet_qconfig(struct apm_enet_dev_base *pdev,
			int is_smp, int core_id, int port)
{
	struct apm_qm_qstate *comp_qstate;
	struct qm_cfg_qconfig qconfig;
	struct qm_cfg_qgroup  qgroup;
	unsigned long priv_data = (unsigned long) pdev;

	u16 hw_port_id = (IP_ETH0 - GIGE_PORT0) + port;
	u16 core = (is_smp) ? 0 : core_id;
	int rc = 0;

	/* TODO: It default sets the tx_idx and rx_idx to zero */
	memset(pdev->qm_queues, 0,
		sizeof(struct eth_queue_ids) * MAX_CORES);
	apm_enet_qm_cfg_register(priv_data, port);

	for ( ; core < MAX_CORES; core++) {
		/* Allocate EGRESS work queues from PPCx to ETHx*/
		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_EGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_PQ;

		rc = apm_enet_add_qconfig(priv_data, &qconfig);
		if (rc != 0) {
			goto done;
		}

		if (qconfig.qtype == QM_CFG_QTYPE_VQ) {
			pdev->qm_queues[core].default_tx_qid =
				pdev->qm_queues[core].tx[0].qsel[0];
		} else {
			pdev->qm_queues[core].default_tx_qid =
				pdev->qm_queues[core].tx[0].qid;
		}

		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_EGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_PQ;

		rc = qm_cfg_add_qconfig(&qconfig);
		if (rc != 0) {
			goto done;
		}
		/* Clear PBN */
		apm_enet_pbn_clr(pdev, qconfig.slave, qconfig.pbn);

		pdev->qm_queues[core].hw_tx_qid = qconfig.qid;
		pdev->qm_queues[core].hw_tx_mbid = qconfig.mbox;
		pdev->qm_queues[core].hw_tx_pbn = qconfig.pbn;

#ifdef PKT_LOSSLESS_WOL
		/* Allocate one ingress queue for WoL */
		if (port == GIGE_PORT0) {
			enet_dev_glb.wol_qid = DSLEEP_ENET_RX_FQ_TO_DDR;
		}
#endif
		/* Get completion queue info for ETHx to PPCx */
		comp_qstate = apm_qm_get_compl_queue(hw_port_id, core);
		pdev->qm_queues[core].comp_qid = comp_qstate->q_id;
		pdev->qm_queues[core].comp_mb = comp_qstate->mb_id;
		apm_qm_mailbox_rx_register(comp_qstate->mb_id, apm_enet_rx_irq);

		/* Allocate INGRESS work queue from ETHx to PPCx */
		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_INGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_PQ;

		rc = apm_enet_add_qconfig(priv_data, &qconfig);
		if (rc != 0) {
			goto done;
		}

		if (qconfig.qtype == QM_CFG_QTYPE_VQ) {
			pdev->qm_queues[core].default_rx_qid =
				pdev->qm_queues[core].rx[0].qsel[0];
		} else {
			pdev->qm_queues[core].default_rx_qid =
				pdev->qm_queues[core].rx[0].qid;
		}
		pdev->qm_queues[core].default_rx_mb = qconfig.mbox;
		pdev->qm_queues[core].default_rx_pbn = qconfig.pbn;
		apm_qm_mailbox_rx_register(qconfig.mbox, apm_enet_rx_irq);
		/* Enable interrupt coalescence for Rx queue. This will
		   reduce the interrupt overhead and better performance
                   for application that source the packet such as iperf */
		apm_qm_mbox_set_coal(qconfig.mbox, 0x4);

		/* Save this for reverse lookup */
		apm_enet_set_qidctx(comp_qstate->q_id, pdev);

		/* Disable interrupts for completion queue mailboxes */
		apm_qm_disable_mb_irq(pdev->qm_queues[core].comp_mb);

		/* Allocate free pool for ETHx from PPCx */
		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_EGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_FP;

		if ((rc = qm_cfg_add_qconfig(&qconfig)) != 0) {
			printk(KERN_ERR "Error: could not allocate "
				"free pool for ETH%d PPC=%d\n", port, core);
			goto done;
		}
		/* Clear PBN */
		apm_enet_pbn_clr(pdev, qconfig.slave, qconfig.pbn);

		pdev->qm_queues[core].rx_fp_qid = qconfig.qid;
		pdev->qm_queues[core].rx_fp_pbn = qconfig.pbn;
		pdev->qm_queues[core].rx_fp_mbid = qconfig.mbox;

		/* Allocate next free pool for ETHx from PPCx */
		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_EGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_FP;

		if ((rc = qm_cfg_add_qconfig(&qconfig)) != 0) {
			printk(KERN_ERR "Error: could not allocate "
				"next free pool for ETH%d PPC=%d\n", port, core);
			goto done;
		}
		/* Clear PBN */
		apm_enet_pbn_clr(pdev, qconfig.slave, qconfig.pbn);

		pdev->qm_queues[core].rx_nxtfp_qid = qconfig.qid;
		pdev->qm_queues[core].rx_nxtfp_pbn = qconfig.pbn;
		pdev->qm_queues[core].rx_nxtfp_mbid = qconfig.mbox;

		/* Allocate HW free pool for ETHx from PPCx */
		memset(&qconfig, QM_CFG_INVALID, sizeof(struct qm_cfg_qconfig));
		qconfig.ip    = IP_BLK_QM;
		qconfig.dev   = hw_port_id;
		qconfig.ppc   = core;
		qconfig.dir   = QM_CFG_DIR_EGRESS;
		qconfig.qsize = QM_CFG_QSIZE_16KB;
		qconfig.thr   = 1;
		qconfig.qtype = QM_CFG_QTYPE_FP;

		if ((rc = qm_cfg_add_qconfig(&qconfig)) != 0) {
			printk(KERN_ERR "Error: could not allocate "
				"HW free pool for ETH%d PPC=%d\n", port, core);
			goto done;
		}
		/* Clear PBN */
		apm_enet_pbn_clr(pdev, qconfig.slave, qconfig.pbn);

		pdev->qm_queues[core].hw_fp_qid = qconfig.qid;
		pdev->qm_queues[core].hw_fp_pbn = qconfig.pbn;
		pdev->qm_queues[core].hw_fp_mbid = qconfig.mbox;

#if defined(CONFIG_SLAB_HW)
		if (port == GIGE_PORT0) {
			eth0_fp_id =  qconfig.qid;
			apm_enet_set_qidctx(eth0_fp_id, pdev);
			DEBG_HW_POOL("Got ETH0 free pool QID: %d\n",
				eth0_fp_id);
			/* Allocate free pool for PPC0 from ETH */
			memset(&qconfig, QM_CFG_INVALID,
				sizeof(struct qm_cfg_qconfig));
			qconfig.ip    = IP_BLK_QM;
			qconfig.dev   = IP_PPC0;
			qconfig.ppc   = core;
			qconfig.dir   = QM_CFG_DIR_INGRESS;
			qconfig.qsize = QM_CFG_QSIZE_16KB;
			qconfig.thr   = 1;
			qconfig.qtype = QM_CFG_QTYPE_FP;

			if ((rc = qm_cfg_add_qconfig(&qconfig)) != 0) {
				printk(KERN_ERR "Error: could not allocate "
					"free pool for PPC%d\n", core);
				goto done;
			}
			/* Clear PBN */
			apm_enet_pbn_clr(pdev, qconfig.slave, qconfig.pbn);

			ppc_fp_mbid = qconfig.mbox;
			ppc_fp_id = qconfig.qid;
			DEBG_HW_POOL("Got PPC%d free pool QID: %d MB ID: %d\n",
				ppc_fp_id, ppc_fp_mbid);
			/* disable interrupts for ppc fp queue mailboxe */
			apm_qm_disable_mb_irq(ppc_fp_mbid);
		} else if (core == 0) {
			eth1_fp_id = qconfig.qid;
			apm_enet_set_qidctx(eth1_fp_id, pdev);
			DEBG_HW_POOL("Got ETH1 free pool QID: %d\n",
				eth1_fp_id);
		}
#endif
		ENET_DBG_Q("Port %d CPU%d CQID %d CMB %d FP %d FP PBN %d\n",
			port, core,
			pdev->qm_queues[core].comp_qid,
			pdev->qm_queues[core].comp_mb,
			pdev->qm_queues[core].rx_fp_qid,
			pdev->qm_queues[core].rx_fp_pbn);

		if (pdev->qm_queues[core].rx[0].qtype == QM_CFG_QTYPE_VQ) {
			int i;
			int count = pdev->qm_queues[core].rx[0].qcount;

			ENET_DBG_Q("RX VQ QID %d RX MB %d\n",
				pdev->qm_queues[core].rx[0].qid,
				pdev->qm_queues[core].rx[0].mbox);

			for (i = 0; i <  count; i++) {
				ENET_DBG_Q("RX QSEL%i QID %d\n", i,
				pdev->qm_queues[core].rx[0].qsel[i]);
			}
		} else {
			ENET_DBG_Q("RX QID %d RX MB %d\n",
				pdev->qm_queues[core].rx[0].qid,
				pdev->qm_queues[core].rx[0].mbox);
		}

		if (pdev->qm_queues[core].tx[0].qtype == QM_CFG_QTYPE_VQ) {
			int i;
			int count = pdev->qm_queues[core].tx[0].qcount;

			ENET_DBG_Q("TX VQ QID %d\n",
				pdev->qm_queues[core].tx[0].qid);

			for (i = 0; i <  count; i++) {
				ENET_DBG_Q("TX QSEL%i QID %d\n", i,
				pdev->qm_queues[core].tx[0].qsel[i]);
			}
		} else {
			ENET_DBG_Q("TX QID %d\n",
				pdev->qm_queues[core].tx[0].qid);
		}

		strcpy(qgroup.name,"default\0");
		qgroup.dev  = hw_port_id;
		qgroup.ppc  = core;
		qgroup.eqid = pdev->qm_queues[core].default_tx_qid;
		qgroup.iqid = pdev->qm_queues[core].default_rx_qid;
		qgroup.fqid = pdev->qm_queues[core].rx_fp_qid;
		qgroup.nxtfqid = pdev->qm_queues[core].rx_nxtfp_qid;
		qgroup.hqid = pdev->qm_queues[core].hw_fp_qid;
		qgroup.heqid = pdev->qm_queues[core].hw_tx_qid;
		qgroup.cqid = pdev->qm_queues[core].comp_qid;

		qm_cfg_add_qgroup(&qgroup);

		if (!is_smp)
			break;
	}
done:
	return rc;
}

#ifdef CONFIG_NAPI
int apm_enet_poll(struct napi_struct *napi, int budget)
{
	struct apm_enet_dev_base *pdev =
	    container_of(napi, struct apm_enet_dev_base, napi);
	struct apm_qm_msg_desc in_poll_rx_msg_desc;
	register int cnt = 0;
	struct apm_qm_msg64 msg;

	memcpy(&in_poll_rx_msg_desc,
               &pdev->in_poll_rx_msg_desc, sizeof(struct apm_qm_msg_desc));
	in_poll_rx_msg_desc.msg = &msg;
#if defined(CONFIG_APM_ENET_LRO) && defined(CONFIG_PPC_64K_PAGES)
	in_poll_rx_msg_desc.is_msg16 = 0;
#endif
	while(budget--) {
		if (unlikely (apm_qm_pull_msg(&in_poll_rx_msg_desc) == -1)) {
			/* No more messages, enable int and return */
			napi_complete(napi);
			apm_qm_enable_mb_irq(in_poll_rx_msg_desc.mb_id);
			return cnt;
		}
#if defined(CONFIG_APM_ENET_LRO) && defined(CONFIG_PPC_64K_PAGES)
		if (msg.msg32_1.msg16.RType == APM_QM_LRO_RTYPE)
			apm_enet_lro_rx_frame(&in_poll_rx_msg_desc);
		else
#endif
			apm_enet_rx_frame(&in_poll_rx_msg_desc);

		cnt++;
	};

	return cnt;
}
#endif

static struct net_device_stats *apm_enet_stats(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &(pdev->priv);
	struct net_device_stats *nst = &pdev->nstats;
	struct apm_emac_stats *st = &pdev->stats;
	struct eth_detailed_stats detailed_stats;
	struct eth_rx_stat *rx_stats;
	struct eth_tx_stats *tx_stats;

	memset(&detailed_stats, 0, sizeof(struct eth_detailed_stats));

	rx_stats = &detailed_stats.rx_stats;
	tx_stats = &detailed_stats.tx_stats;

	local_irq_disable();

	nst->rx_packets = st->rx_packets;
	nst->rx_bytes = st->rx_bytes;
	nst->tx_packets = st->tx_packets;
	nst->tx_bytes = st->tx_bytes;

	apm_enet_get_detailed_stats(priv, &detailed_stats);

	nst->rx_dropped += rx_stats->rx_drop_pkt_count;
	nst->tx_dropped += tx_stats->tx_drop_frm_count;
	nst->rx_errors += rx_stats->rx_fcs_err_count +
		rx_stats->rx_alignment_err_pkt_count +
		rx_stats->rx_frm_len_err_pkt_count +
		rx_stats->rx_code_err_pkt_count +
		rx_stats->rx_carrier_sense_err_pkt_count +
		rx_stats->rx_undersize_pkt_count +
		pdev->estats.rx_hw_errors;

	nst->tx_errors += tx_stats->tx_fcs_err_frm_count +
		tx_stats->tx_undersize_frm_count;

	local_irq_enable();

	return nst;
}

static int apm_enet_set_mac_addr(struct net_device *ndev, void *p)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &(pdev->priv);
	struct sockaddr *addr = p;

	if (netif_running(ndev))
		return -EBUSY;

	memcpy(ndev->dev_addr, addr->sa_data, ndev->addr_len);
	apm_gmac_set_gmac_addr(priv, (unsigned char *)(ndev->dev_addr));
	apm_preclass_update_mac(pdev->port_id, TYPE_SYS_MACADDR,
				ETHERNET_MACADDR,
				apm_sys_macmask[ETHERNET_MACADDR],
				ndev->dev_addr);
#ifdef CONFIG_APM_ENET_OFFLOAD
	if (pdev->offload.offload_available & IPP_NETOFFLOAD_FW_MASK)
		apm_enet_offload_set_mac(pdev);
#endif

	return 0;
}

static int update_avl_list(struct net_device *ndev, u8 *addr, struct list_head *head)
{
	struct avl_entry *entry, *temp, *new;
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	int rc = APM_RC_OK;

	/* Search for existing matched address */
	list_for_each_entry_safe(entry, temp, head, list) {
		if (!compare_ether_addr(entry->addr, addr)) {
			entry->flag = AVL_MARK_PRESENT;
			return 0;
		}
	}

	/* Since we did not found matched entry,
	 * this must be new mac address to be added in to the list.
	 */
	rc = apm_preclass_add_avl_entry(pdev->port_id, addr);
	if (rc == APM_RC_OK) {
		new = kzalloc(sizeof(struct avl_entry), GFP_ATOMIC);
		INIT_LIST_HEAD(&new->list);
		memcpy(new->addr, addr, 6);
		new->flag = AVL_MARK_PRESENT;
		list_add_tail(&new->list, head);
	}

	return rc;
}

static void remove_stale_avl_entries(struct net_device *ndev, struct list_head *head)
{
	struct avl_entry *entry, *temp;
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);

	/* Delete all avl the entries which are not present in kernel list */
	list_for_each_entry_safe(entry, temp, head,list) {
		if (entry->flag == AVL_MARK_DEL) {
			apm_preclass_delete_avl_entry(pdev->port_id,
							entry->addr);
			list_del(&entry->list);
			kfree(entry);
		}
	}

}

static inline void mark_all_avl_entries(struct list_head *head, int flag)
{
	struct avl_entry *entry, *temp;

	/*Mark All the entries as to be deleted */
	list_for_each_entry_safe(entry, temp, head,list)
		entry->flag = flag;
}

static int update_list(struct net_device *dev, int list_type)
{
	struct netdev_hw_addr *ha;
	struct apm_enet_dev_base *pdev = netdev_priv(dev);
	struct list_head *head = NULL;
	int err = 0;

	if (list_type == UNICAST_LIST) {
		head = &pdev->ucast_avl_head;
		/*Mark All the entries as to be deleted */
		mark_all_avl_entries(head, AVL_MARK_DEL);

		/* Update avl unicast list with respect to kernel unicast list */
		netdev_for_each_uc_addr(ha, dev)
			update_avl_list(dev, ha->addr, head);

		/* Traverse and remove all the entries which are marked for deletion. */
		remove_stale_avl_entries(dev, head);


	} else if (list_type == MULTICAST_LIST) {

		head = &pdev->mcast_avl_head;

		/*Mark All the entries as to be deleted */
		mark_all_avl_entries(head, AVL_MARK_DEL);

		/* Update avl multicast list with respect to kernel multicast list */
		netdev_for_each_mc_addr(ha, dev)
			update_avl_list(dev, ha->addr, head);
		/* Traverse and remove all the entries which are marked for deletion. */
		remove_stale_avl_entries(dev, head);
	}

	return err;
}

/**
 * apm_enet_set_rx_mode - Secondary Unicast, Multicast and Promiscuous mode set
 * @netdev: network interface device structure
 *
 * The set_rx_mode entry point is called whenever the unicast or multicast
 * address lists or the network interface flags are updated. This routine is
 * responsible for configuring the hardware for proper unicast, multicast,
 * promiscuous mode, and all-multi behavior.
 **/
static void apm_enet_set_rx_mode(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	bool use_uc = false;
	bool use_mc = false;
	u32 port_id = pdev->port_id;

	/* Check for Promiscuous and All Multicast modes */
	if (ndev->flags & IFF_PROMISC) {
		if (!(pdev->flags & IFF_PROMISC)) {
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				UNICAST_MACADDR,
				apm_sys_macmask[UNICAST_MACADDR],
				apm_sys_macaddr[UNICAST_MACADDR]);
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				MULTICAST_MACADDR,
				apm_sys_macmask[MULTICAST_MACADDR],
				apm_sys_macaddr[MULTICAST_MACADDR]);
		}
	} else if (ndev->flags & IFF_ALLMULTI) {
		if (!(pdev->flags & IFF_ALLMULTI)) {
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				MULTICAST_MACADDR,
				apm_sys_macmask[MULTICAST_MACADDR],
				apm_sys_macaddr[MULTICAST_MACADDR]);
		}
	} else {
		if (pdev->flags & (IFF_PROMISC | IFF_ALLMULTI)) {
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				MULTICAST_MACADDR, NULL, NULL);
		}
		use_mc = true;
	}

	/* Check for Unicast Promiscuous mode */
	if (ndev->uc.count > APM_MAX_UNICAST_MACADDR) {
		if (!(pdev->uc_count > APM_MAX_UNICAST_MACADDR)) {
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				UNICAST_MACADDR,
				apm_sys_macmask[UNICAST_MACADDR],
				apm_sys_macaddr[UNICAST_MACADDR]);
		}
	} else if (!(ndev->flags & IFF_PROMISC)) {
		if (pdev->flags & IFF_PROMISC) {
			apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR,
				UNICAST_MACADDR, NULL, NULL);
		}
		use_uc = true;
	}

	if (use_uc) {
	/* Add Unicast MAC address in AVL which are present in ndev->uc.list and absent in our_uc_list */
	/* Del Unicast MAC address in AVL which are present in our_uc_list and absent in ndev->uc.list */
		update_list(ndev, UNICAST_LIST);
	}

	if (use_mc) {
	/* Add Multicast MAC address in AVL which are present in ndev->mc_list and absent in our_mc_list */
	/* Del Multicast MAC address in AVL which are present in our_mc_list and absent in ndev->mc_list */
		update_list(ndev, MULTICAST_LIST);
	}

	pdev->flags = ndev->flags;
	pdev->uc_count = ndev->uc.count;
}

#if defined(ENET_LINK_IRQ)
static void apm_enet_link_down(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;

	/* Disable Mac Rx */
	apm_gmac_rx_disable(priv);

	netif_carrier_off(ndev);
	/* Stop xmit queue */
	netif_stop_queue(ndev);

	/* Disable Mac Tx */
	apm_gmac_tx_disable(priv);

	pdev->link_status = 0;
}

static void apm_enet_link_up(struct net_device *ndev)
{
	struct apm_enet_dev_base *pdev = netdev_priv(ndev);
	struct apm_data_priv *priv = &pdev->priv;
	u32 speed, state;

	/* Start xmit queue */
	netif_carrier_on(ndev);
	netif_start_queue(ndev);

	apm_gmac_phy_link_mode(priv, &speed, &state);
	pdev->link_status = 1;

	apm_gmac_init(priv, ndev->dev_addr, speed, HW_MTU(ndev->mtu), priv->crc, 1);

	if (pdev->ipg > 0)
		apm_gmac_set_ipg(priv, pdev->ipg);

	PHY_PRINT("port:%d, phyid:%d, speed:%d, link_status: %d \n",
		priv->port, priv->phy_addr, speed, pdev->link_status);
	pdev->link_status = 1;
}
#endif

irqreturn_t apm_enet_irq(int irq, void *ndev)
{
#if defined(ENET_LINK_IRQ)
	struct apm_data_enet_dev *port_dev;
	struct apm_data_priv *priv = NULL;
	u32 port_chg;
	u32 port_status;
	int port;

	for (port = 0; port < 2; port++) {
		/* Link for port 0 changed */
		port_dev = enet_dev[port];
		if (port_dev == NULL)
			continue;
		/* Check for link change */
		priv = &port_dev->dev_base.priv;
		apm_enet_rd32(priv, BLOCK_ETH_GBL, LINK_AGGR_INTR_ADDR, &port_chg);
		apm_enet_rd32(priv, BLOCK_ETH_GBL, LINK_STATUS_ADDR, &port_status);
		ENET_DEBUG("Port %d change 0x%08X status 0x%08X\n",
			port, port_chg, port_status);
		if (!(port_chg & (1 << port)))
			continue;
		if (port_status & (1 << port)) {
			apm_enet_link_up(port_dev->dev_base.ndev);
			printk(KERN_INFO "%s link is up\n",
				port_dev->dev_base.ndev->name);
		} else {
			apm_enet_link_down(port_dev->dev_base.ndev);
			printk(KERN_INFO "%s link is down\n",
				port_dev->dev_base.ndev->name);
		}
	}
	if (priv)
		apm_enet_wr32(priv, BLOCK_ETH_GBL, LINK_AGGR_INTR_ADDR,
				0xFFFFFFFF);
#endif
	/* Check for error interrupt */
	apm_enet_err_irq(irq, ndev);
	return IRQ_HANDLED;
}

/* net_device_ops structure for data path ethernet */
static const struct net_device_ops apm_dnetdev_ops = {
	.ndo_open		= apm_enet_open,
	.ndo_stop		= apm_enet_close,
	.ndo_start_xmit		= apm_enet_start_xmit,
	.ndo_do_ioctl		= apm_enet_ioctl,
	.ndo_tx_timeout		= apm_enet_timeout,
	.ndo_get_stats		= apm_enet_stats,
	.ndo_change_mtu		= apm_enet_change_mtu,
	.ndo_set_mac_address	= apm_enet_set_mac_addr,
	.ndo_set_rx_mode	= apm_enet_set_rx_mode,
};

static int apm_enet_scu_init(int dev_id, int hw_cfg)
{
	struct clk *clk;
	int rc = 0;
#if defined(CONFIG_APM862xx)
	static int enet_init_done = 0;
	struct apm86xxx_pll_ctrl eth_pll;

	if (hw_cfg && !enet_init_done) {
		/* Enable Ethernet PLL */
		eth_pll.clkf_val = 0x13;
		eth_pll.clkod_val = 0;
		eth_pll.clkr_val = 0;
		eth_pll.bwadj_val = 0x13;
		enable_eth_pll(&eth_pll);
		enet_init_done = 1;
	}
#endif

	if (dev_id == GIGE_PORT0) {
		/* reset Eth0 */
		clk = clk_get(NULL, "enet0");
		if (IS_ERR(clk))
			return -ENODEV;
		clk_enable(clk);
	} else if (dev_id == GIGE_PORT1) {
		/* reset Eth1 */
		clk = clk_get(NULL, "enet1");
		if (IS_ERR(clk))
			return -ENODEV;
		clk_enable(clk);
	}

	return rc;
}

static int fwload_callback(struct notifier_block *self, unsigned long action,
				void *dev)
{
	int ret;
	struct ipp_net_stats netstats;

	if (action != IPP_FIRMWARE_LOADED)
		goto _ret_fwload_callback;

	ret = apm_enet_pkt_iscoherent();

	ENET_DEBUG("Sending QM_COHERENT bit C %d to iPP\n", ret);

	/* Set QM Coherent Access bit setting to iPP */
	ret = ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
				IPP_QM_COHERENT_ACCESS, (u8)ret,
				IPP_MSG_CONTROL_URG_BIT,
				IPP_MSG_PARAM_UNUSED);
	if (ret < 0) {
		printk(KERN_ERR "Failed to send QM_COHERENT setting "
				"value to IPP: %d\n", ret);
	}

	/* Firmware loading complete */
	ret = get_ipp_features();
#ifdef CONFIG_APM_ENET_OFFLOAD
	if (ret & IPP_NETOFFLOAD_FW_MASK) {
		int i;

		for (i = 0; i < MAX_PORTS; i++) {
			struct apm_enet_dev_base *pdev;
			struct net_device *dev;

			if ((dev = find_netdev(i)) == NULL)
				continue;

			pdev = netdev_priv(dev);
			pdev->offload.offload_available =
				(ret & IPP_NETOFFLOAD_FW_MASK);
			apm_enet_offload_init(pdev);
		}
	} else {
		printk("NET Offload feature is disabled in SlimPRO firmware\n");
	}
#endif
#if defined(CONFIG_APM_ENET_LRO) && defined(CONFIG_PPC_64K_PAGES)
	if (ret & IPP_LRO_FW_MASK) {
		int i;

		for (i = 0; i < MAX_PORTS; i++) {
			struct apm_enet_dev_base *pdev;
			struct net_device *dev;

			if ((dev = find_netdev(i)) == NULL)
				continue;

			pdev = netdev_priv(dev);
			pdev->lro.lro_available = 1;
			apm_enet_lro_init(pdev);
		}
	} else {
		printk("LRO feature is disabled in SlimPRO firmware\n");
	}
#endif
#ifdef CONFIG_APM_ENET_SLIMPRO_IPFW
	if (ret & IPP_IPV4FWD_OFFLOAD_FW_MASK) {
		int i;

		for (i = 0; i < MAX_PORTS; i++) {
			struct apm_enet_dev_base *pdev;
			struct net_device *dev;

			if ((dev = find_netdev(i)) == NULL)
				continue;

			pdev = netdev_priv(dev);
			pdev->slimpro_ipfw.ipfw_available = 1;
			apm_enet_slimpro_ipfw_init(pdev);
		}
	}
#endif

	if (get_ipp_netstats(&netstats) == 0)
		enet_dev_glb.ipp_hw_mtu = netstats.hw_mtu;
	else
		enet_dev_glb.ipp_hw_mtu = IPP_PKT_BUF_SIZE;
	enet_dev_glb.ipp_hw_mtu = enet_dev_glb.ipp_hw_mtu > 9600 ?
					9600 : enet_dev_glb.ipp_hw_mtu;

	/* Send QMLite Init Msg */
	ret = ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
				IPP_QMLITE_INIT_VAR,
				IPP_QMLITE_INIT_START,
				IPP_MSG_CONTROL_URG_BIT,
				IPP_MSG_PARAM_UNUSED);
	if (ret < 0) {
		printk(KERN_ERR "Failed to send QMLite "
				"Init Msg to IPP: %d\n", ret);
	}

	if (apm_cle_system_id != CORE_0)
		goto _ret_fwload_callback;

	ret = apm_preclass_init_wol_inter_tree(GIGE_PORT0);

	if (ret == APM_RC_ERROR) {
		printk("Preclass Wol Intermediate Tree init error\n");
		goto _ret_fwload_callback;
	}

	/* Set snptr0 for Wake-On-LAN */
	ret = ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
				IPP_ENET0_CLE0_SNPTR0, (u8)ret,
				IPP_MSG_CONTROL_URG_BIT,
				IPP_MSG_PARAM_UNUSED);
	if (ret < 0) {
		printk(KERN_ERR "Failed to send SNPTR0 "
				"value to IPP: %d\n", ret);
	}

_ret_fwload_callback:
	enet_dev_glb.ipp_loaded = 1;
	return NOTIFY_OK;
}

static struct notifier_block fwload_nb = {
	.notifier_call = fwload_callback,
};

static int apm_enet_proc_open(struct inode *inode, struct file *file)
{
        return 0;
}

static int apm_enet_proc_release(struct inode *inode, struct file *file)
{
        return 0;
}

static ssize_t apm_enet_proc_read(struct file *file, char __user *buf,
                                        size_t count, loff_t *ppos)
{
	struct apm_data_enet_dev *port_dev;
        struct apm_data_priv *priv = NULL;
	u32 reg_val;

        port_dev = enet_dev[1];
        priv = &port_dev->dev_base.priv;

	apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_1_ADDR, &reg_val);
       printk("MAC_CONFIG_1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC, MAC_CONFIG_2_ADDR, &reg_val);
       printk("MAC_CONFIG_2_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC, MAX_FRAME_LEN_ADDR, &reg_val);
       printk("MAX_FRAME_LEN_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC, STATION_ADDR0_ADDR, &reg_val);
       printk("STATION_ADDR0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC, STATION_ADDR1_ADDR, &reg_val);
       printk("STATION_ADDR1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC, INTERFACE_CONTROL_ADDR, &reg_val);
       printk("INTERFACE_CONTROL_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, RSIF_RAM_DBG_REG0_ADDR, &reg_val);
       printk("RSIF_RAM_DBG_REG0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, RSIF_CONFIG_REG_ADDR, &reg_val);
       printk("RSIF_CONFIG_REG_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, ENET_SPARE_CFG_REG_ADDR, &reg_val);
       printk("ENET_SPARE_CFG_REG_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, TSIF_MSS_REG0_0_ADDR, &reg_val);
       printk("TSIF_MSS_REG0_0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, TSIF_MSS_REG0_1_ADDR, &reg_val);
       printk("TSIF_MSS_REG0_1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_GBL, CFG_LINK_AGGR_ADDR, &reg_val);
       printk("CFG_LINK_AGGR_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, HDRPRS_CONFIG2_REG_0_ADDR, &reg_val);
       printk("HDRPRS_CONFIG2_REG_0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, HDRPRS_CONFIG2_REG_1_ADDR, &reg_val);
       printk("HDRPRS_CONFIG2_REG_1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, HDRPRS_CONFIG3_REG_0_ADDR, &reg_val);
       printk("HDRPRS_CONFIG3_REG_0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, HDRPRS_CONFIG3_REG_1_ADDR, &reg_val);
       printk("HDRPRS_CONFIG3_REG_1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_0_ADDR, &reg_val);
       printk("RX_DV_GATE_REG_0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, RX_DV_GATE_REG_1_ADDR, &reg_val);
       printk("RX_DV_GATE_REG_1_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, CFG_LPBK_GATE_TX_ADDR, &reg_val);
       printk("CFG_LPBK_GATE_TX_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, ICM_CONFIG0_REG_0_ADDR, &reg_val);
       printk("ICM_CONFIG0_REG_0_ADDR = %x\n", reg_val);
       apm_emac_read32(priv, BLOCK_ETH_MAC_GBL, ICM_CONFIG0_REG_1_ADDR, &reg_val);
       printk("ICM_CONFIG0_REG_1_ADDR = %x\n", reg_val);

        return 0;
}

static ssize_t apm_enet_proc_write(struct file *file, const char __user *buf,
                                        size_t count, loff_t *ppos)
{
	return count;
}

struct file_operations apm_enet_proc_fops = {
        .owner = THIS_MODULE,
        .open = apm_enet_proc_open,
        .release = apm_enet_proc_release,
        .read = apm_enet_proc_read,
        .write = apm_enet_proc_write,
};


/*
 * IE4k has some properties missing in its enet node and Linux does not have access to
 * the device tree source. So hardcode these here
 */
static int ie4k_dev_id = 1;
static int ie4k_phyid = 6;
static int ie4k_master_cfg = 0;
static int ie4k_hw_cfg = 1;

static int apm_enet_of_probe(struct platform_device *_pdev)
{
	struct apm_enet_dev *apm_netdev_glb;
	const u8 *ethaddr;
	const u32 *dev_id, *phy_id;
	int rc = 0;
	int mac_addr_len;
	u32 enet_irq = 0, enet_mac_irq = 0, enet_qmi_irq = 0;
	u32 *hw_cfg;
	u32 *mas_cfg;
#ifndef CONFIG_IE4000
	u32 hw_cfg_len, mas_cfg_len, dev_id_len;
#endif
	u32 csr_addr_size;
	u32 port_addr = 0;
	u64 port_addr_p = 0;
	u32 port_id;
	int enable_pcie_internal_clk = 0; //default: external clock
	u32 core_id = apm_processor_id();
	struct net_device *ndev;
#ifndef CONFIG_IE4000
	struct mii_bus *mdio_bus;
#endif
	struct apm_enet_dev_base *pdev;
	struct apm_data_enet_dev *port_dev;
	struct apm_data_priv *priv;
	struct device_node *np = _pdev->dev.of_node;
	struct resource res;
	u32 *node_val;
	u32 node_len;
	u32 enet_mii_access_base_addr;
	u64 enet_gbl_base_addr_p;
	u32 enet_gbl_base_addr;
	u32 cid;
	int enet_enable = 0;
#if !defined(CONFIG_APM862xx)
	u32 tmp;
	const u32 *hw_vlan;
	int hw_vlan_len;
#endif
	const char *pm, *phy_modes[] = {
                [PHY_MODE_RGMII] = "rgmii",
                [PHY_MODE_SGMII] = "sgmii",
        };

#if defined(CONFIG_IE4000)
	enet_enable = 1;
#endif

	/* Retrieve Device ID for this port */
#ifdef CONFIG_IE4000
	dev_id = (u32 *)&ie4k_dev_id;
#else
	dev_id = (u32 *) of_get_property(np, "devid", &dev_id_len);
	if (dev_id == NULL || dev_id_len < sizeof(u32) ||
	    *dev_id > MAX_PORTS) {
		printk(KERN_ERR "No device ID or invalid value in DTS\n");
		return -EINVAL;
	}
#endif
	port_id = *dev_id;
	apm_netdev_glb = &enet_dev_glb;

	if (is_apm864xx()) {
		if (port_id == 2 || port_id == 3) {
			ENET_DEBUG("No SGMII HW Support "
					"port%d unavailable\n", port_id);
			return -ENODEV;
		}
	}

	if (!np || !of_device_is_available(np)) {
		printk(KERN_INFO "APM Ethernet Port %d: unavailable",
		       port_id);
		return -ENODEV;
	} else {
		printk(KERN_INFO "APM Ethernet Port %d: available",
		       port_id);
	}

#ifdef CONFIG_IE4000
	mas_cfg = (u32 *)&ie4k_master_cfg;
#else
	mas_cfg = (u32 *) of_get_property(np, "master-cfg", &mas_cfg_len);
#endif
	if (mas_cfg == NULL)
		apm_netdev_glb->master_cfg = 1;
	else
		apm_netdev_glb->master_cfg = *mas_cfg;

	/* Retrieve Enet Port CSR register address and size */
	if ((rc = of_address_to_resource(np, 0, &res)) != 0) {
		printk(KERN_ERR "Unable to retrive Enet csr addr from DTS\n");
		return rc;
	}
	port_addr_p = res.start;
	csr_addr_size = RES_SIZE(&res);
	port_addr = (u32) ioremap_nocache(port_addr_p, csr_addr_size);
	ENET_DEBUG("CSR PADDR: 0x%010llx VADDR: 0x%08X\n",
		port_addr_p, port_addr);

	/* Retrieve Classifier CSR register address and size */
	if ((rc = of_address_to_resource(np, 1, &res)) != 0) {
		printk(KERN_ERR "Unable to retrive Classifier csr"
			"addr from DTS\n");
		return rc;
	}
	cid = PID2CID[port_id];
	apm_class_base_addr_p[cid] = res.start;
	csr_addr_size = RES_SIZE(&res);
	apm_class_base_addr[cid] = (u32) ioremap_nocache(apm_class_base_addr_p[cid],
						   csr_addr_size);
	ENET_DEBUG("Classifier PADDR: 0x%010llx VADDR: 0x%08X\n",
		apm_class_base_addr_p[cid], apm_class_base_addr[cid]);

	/* Retrieve Enet Global CSR register address and size */
	if ((rc = of_address_to_resource(np, 2, &res)) != 0) {
		printk(KERN_ERR
			"Unable to retrive Enet Global csr addr from DTS\n");
		return rc;
	}

	enet_gbl_base_addr_p = res.start;
	csr_addr_size = RES_SIZE(&res);
	enet_gbl_base_addr = (u32) ioremap_nocache(enet_gbl_base_addr_p,
						   csr_addr_size);

	ENET_DEBUG("Enet Global PADDR: 0x%010llx VADDR: 0x%08X\n",
		   enet_gbl_base_addr_p, enet_gbl_base_addr);

	/* Retrieve Enet MII accsess register address and size */
	if ((rc = of_address_to_resource(np, 3, &res)) != 0) {
		printk(KERN_ERR "Unable to retrive Enet MII access addr"
			"from DTS\n");
		return rc;
	}

	enet_mii_access_base_addr = (u32) ioremap_nocache(res.start,
							  RES_SIZE(&res));

	ENET_DEBUG("Enet MII Access PADDR: 0x%010llx  VADDR: 0x%08X\n",
		   res.start, enet_mii_access_base_addr);

	if (apm_netdev_glb->master_cfg) {
		/* Retrieve ENET Error IRQ number */
		if ((enet_irq = of_irq_to_resource(np, 0, NULL)) == NO_IRQ) {
			printk(KERN_ERR "Unable to retrive ENET Error"
					"IRQ number from DTS\n");
			return -EINVAL;
		}
		ENET_DEBUG("Enet Error IRQ no: 0x%x\n", enet_irq);

		/* Retrieve ENET MAC Error IRQ number */
		if ((enet_mac_irq = of_irq_to_resource(np, 1,
						NULL)) == NO_IRQ) {
			printk(KERN_ERR "Unable to retrive ENET MAC Error IRQ"
					" number from DTS\n");
			return -EINVAL;
		}
		ENET_DEBUG("Enet MAC Error IRQ no: 0x%x\n", enet_mac_irq);

		/* Retrieve ENET QMI Error IRQ number */
		if ((enet_qmi_irq = of_irq_to_resource(np, 2,
						NULL)) == NO_IRQ) {
			printk(KERN_ERR "Unable to retrive ENET QMI Error IRQ"
					" number from DTS\n");
			return -EINVAL;
		}
		ENET_DEBUG("Enet QMI Error IRQ no: 0x%x\n", enet_qmi_irq);
	}

	ndev = alloc_etherdev(sizeof(struct apm_data_enet_dev));
	if (!ndev) {
		printk(KERN_ERR "Not able to allocate memory for netdev\n");
		return -ENOMEM;
	}

#ifndef CONFIG_IE4000
	mdio_bus = mdiobus_alloc();
	if (!mdio_bus) {
		printk(KERN_ERR "Not able to allocate memory for MDIO bus\n");
		return -ENOMEM;
	}
#endif
	port_dev = (struct apm_data_enet_dev *) netdev_priv(ndev);
	enet_dev[port_id] = port_dev;

	pdev = (struct apm_enet_dev_base *) netdev_priv(ndev);
	pdev->ndev = ndev;
#ifndef CONFIG_IE4000
	pdev->mdio_bus = mdio_bus;
#endif
	pdev->_pdev = _pdev;
	pdev->node = _pdev->dev.of_node;
	pdev->q_poll_timer_status = Q_POLL_TIMER_OFF;
#ifdef ENET_LINK_IRQ
	pdev->link_status = 0;
#endif
	INIT_LIST_HEAD(&pdev->mcast_avl_head);
	INIT_LIST_HEAD(&pdev->ucast_avl_head);

	SET_NETDEV_DEV(ndev, &_pdev->dev);
	dev_set_drvdata(&_pdev->dev, pdev);

	priv = &pdev->priv;

	priv->enet_write32 = apm_enet_wr32;
	priv->enet_read32 = apm_enet_rd32;

	priv->paddr_base = enet_gbl_base_addr_p;
	priv->vaddr_base = enet_gbl_base_addr;
	priv->ppaddr_base = port_addr_p;
	priv->vpaddr_base = port_addr;

	/* Per Port Indirect access */
	priv->mac_base_addr_v  = port_addr + BLOCK_ETH_MAC_OFFSET;
	priv->stats_base_addr_v = port_addr + BLOCK_ETH_STATS_OFFSET;
	/* Global direct access	 */
	priv->eth_gbl_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_GBL_OFFSET;
	priv->eth_ffdiv_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_FFDIV_OFFSET;
	priv->mac_gbl_base_addr_v  =
		enet_gbl_base_addr + BLOCK_ETH_MAC_GBL_OFFSET;
	priv->eth_ptp_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_PTP_OFFSET  ;
	priv->eth_unisec_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_UNISEC_OFFSET;
	priv->eth_diag_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_DIAG_OFFSET;
	priv->eth_qmi_base_addr_v =
		enet_gbl_base_addr + BLOCK_ETH_QMI_SLAVE_OFFSET ;
	priv->enet_mii_base_addr_v = enet_mii_access_base_addr;

	/* Retrieve PHY ID for this port */
#ifdef CONFIG_IE4000
	phy_id = (u32 *)&ie4k_phyid;
#else
	phy_id = (u32 *) of_get_property(np, "phyid", &dev_id_len);
	if (phy_id == NULL || dev_id_len < sizeof(u32) ||
	    *phy_id > 0x1F) {
		printk(KERN_ERR "No phy ID or invalid value in DTS\n");
		return -EINVAL;
	}
#endif
        pm = of_get_property(np, "phy-mode", &node_len);
        priv->phy_mode = PHY_MODE_RGMII;
        if (pm != NULL) {
                if (!strncasecmp(pm, phy_modes[PHY_MODE_SGMII], 3))
                        priv->phy_mode = PHY_MODE_SGMII;
                else
                        priv->phy_mode = PHY_MODE_RGMII;

        }

	if (priv->phy_mode == PHY_MODE_SGMII) {
		pm = of_get_property(np, "internal-clock", NULL);
		if (pm && !strcmp(pm, "enabled")) {
			enable_pcie_internal_clk = 1;
		} else
			enable_pcie_internal_clk = 0;
	}
	node_val = (u32 *) of_get_property(np, "rx-fifo-cnt", &node_len);
	if (node_val != NULL && node_len >= sizeof(u32) &&
	    *node_val >= 32 && *node_val <= 512)
		pdev->rx_buff_cnt = *node_val;
	else
		pdev->rx_buff_cnt = APM_NO_PKT_BUF;

	/*
	 * Assign TX completion queue net interface threshold
	 * based on rx queue size
	 */
	pdev->tx_cqt_low = (apm_qm_get_compl_queue_size(IP_ETH0, 0) / 64) / 4;
	pdev->tx_cqt_hi = pdev->tx_cqt_low * 3;

	node_val = (u32 *) of_get_property(np, "hdr-rsvd", &node_len);
	if (node_val != NULL && node_len >= sizeof(u32) &&
	    *node_val >= 0 && *node_val <= 512)
		pdev->hdr_rsvd = *node_val;
	else
		pdev->hdr_rsvd = APM_ENET_SKB_RESERVE_SIZE;

	node_val = (u32 *) of_get_property(np, "ipg", &node_len);
	if (node_val != NULL && node_len >= sizeof(u32))
		pdev->ipg = *node_val;
	else
		pdev->ipg = 0;
#ifdef CONFIG_IE4000
	hw_cfg = (u32 *) &ie4k_hw_cfg;
#else
	hw_cfg = (u32 *) of_get_property(np, "hw-cfg", &hw_cfg_len);
#endif
	if (hw_cfg == NULL) {
		port_dev->hw_config = 1;
		apm_netdev_glb->is_smp = 1;
	} else {
		port_dev->hw_config = *hw_cfg;
	}

	if ((rc = apm_enet_scu_init(port_id, port_dev->hw_config)) != 0) {
		printk(KERN_ERR "Error in apm_enet_scu_init \n");
		return rc;
	}

	node_val = (u32 *) of_get_property(np, "wka_flag", &node_len);
	if (node_val != NULL)
		pdev->wka_flag = *node_val;
	else
		pdev->wka_flag = 1;

	priv->port = port_id;
	priv->phy_addr = *phy_id;
	priv->crc = 0;
#if defined(CONFIG_IE4000)
	priv->crc = 1;
#endif
	pdev->port_id = port_id;

	printk(KERN_INFO "APM Ethernet Port %d: phy_addr=0x%x phy_mode=%s\n",
			 port_id, priv->phy_addr, phy_modes[priv->phy_mode]);

	if(!reg_access_lock_init){
		spin_lock_init(&apm_reg_access_lock);
		reg_access_lock_init = 1;
	}

#if !defined(CONFIG_APM862xx)
	/* Ensure CFG_PHYID reflect hardwired PHY IDs */
	apm_enet_rd32(priv, BLOCK_ETH_GBL, CFG_PHYID_ADDR, &tmp);
	tmp &= ~(0xFF << (priv->port * 8));
	tmp |= (priv->phy_addr & 0xFF) << (priv->port * 8);
	apm_enet_wr32(priv, BLOCK_ETH_GBL, CFG_PHYID_ADDR, tmp);
#endif

	/* SGMII ports require serdes initialization */
	if (priv->phy_mode == PHY_MODE_SGMII) {
		apm_enet_serdes_init(port_id, enable_pcie_internal_clk);
	}

	/* Enable Enet CLK, Reset Enet and CLE */
	if (apm_netdev_glb->is_smp || !core_id || enet_enable) {
		/* Remove ENET CSR memory shutdown */
		if ((rc = apm86xxx_disable_mem_shutdown(
			(u32 __iomem *)(priv->eth_diag_base_addr_v +
				ENET_CFG_MEM_RAM_SHUTDOWN_ADDR),
					ENET0_F2_MASK)) != 0) {
			printk(KERN_ERR
				"Failed to remove Eth CSR memory shutdown\n");
			return rc;
		}
	}

	/* To ensure no packet enters the system, disable Rx/Tx before
           configure the inline classifier */
	apm_gmac_tx_disable(priv);
	apm_gmac_rx_disable(priv);

	/* Initialize CLE Inline Engine */
	if ((rc = apm_cle_init(port_id)) != 0) {
		printk(KERN_ERR "Error in apm_cle_init\n");
		return rc;
	}

	/* Fill in the driver function table */
	ndev->netdev_ops = &apm_dnetdev_ops;

#ifdef CONFIG_NAPI
	/*
	 * Reducing the budget increased traffic forwarding
	 * throughput by 100% from our ethernet to external
	 * network device for packet size <= 512 bytes
	 */
	netif_napi_add(ndev, &pdev->napi, apm_enet_poll, 32);
#endif

#if defined(IPV4_TX_CHKSUM) || defined(IPV4_TSO)
	/* Enable TX IPV4 TCP/UDP HW checksum */
	ndev->features |= NETIF_F_IP_CSUM | NETIF_F_SG;
#endif

#if defined(IPV4_RX_CHKSUM) || defined(IPV4_TSO)
	/* Enable RX IPV4 TCP/UDP HW checksum */
	pdev->features |= FLAG_RX_CSUM_ENABLED;
#endif

#if defined(IPV4_TSO)
	ndev->features |= NETIF_F_TSO;
	/* Program TSO config */
	apm_enet_wr32(&pdev->priv, BLOCK_ETH_GBL, TSO_CFG_0_ADDR, 0xC0);
	apm_enet_wr32(&pdev->priv, BLOCK_ETH_GBL, TSO_CFG_1_ADDR, 0xC0);
#endif
	pdev->mss = 0;	/* Set to 0 so that on Tx it update HW */

#if defined(IPV4_TSO)
	/* Check if HW offload of VLAN is enabled or not */
	hw_vlan = (u32 *) of_get_property(np, "hw_vlan", &hw_vlan_len);

	if (hw_vlan != NULL && hw_vlan_len == sizeof(u32)) {
		if (*(hw_vlan) == 1)
			ndev->features |= NETIF_F_HW_VLAN_CTAG_TX;
	}
#endif

	SET_ETHTOOL_OPS(ndev, &apm_ethtool_ops);

	if ((rc = register_netdev(ndev)) != 0) {
		printk(KERN_ERR "enet%d: failed to register net dev(%d)!\n",
		       pdev->port_id, rc);
		return rc;
	}

	ethaddr = (u8 *) of_get_property(np, "local-mac-address",
					 &mac_addr_len);
	if (ethaddr == NULL || mac_addr_len < ETH_ALEN)
		printk(KERN_ERR "Can't get Device MAC address\n");
	else
		memcpy(ndev->dev_addr, ethaddr, ETH_ALEN);

	ENET_DEBUG("%s: emac%d MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
	       ndev->name, pdev->port_id,
	       ndev->dev_addr[0], ndev->dev_addr[1], ndev->dev_addr[2],
	       ndev->dev_addr[3], ndev->dev_addr[4], ndev->dev_addr[5]);

	/* QM configuration */
	if ((rc = apm_enet_qconfig(pdev, apm_netdev_glb->is_smp, core_id, port_id)) != 0) {
		printk(KERN_ERR "Error in QM configuration\n");
		return rc;
	}
	pdev->irq_en = 1;

	/* Configure free pool */
	if (apm_netdev_glb->is_smp) {
#ifdef SMP_LOAD_BALANCE
		apm_enet_init_fp(
			pdev->qm_queues[port_id % MAX_CORES].rx_fp_qid,
			HW_MTU(ndev->mtu), pdev->rx_buff_cnt, 0,
			pdev->hdr_rsvd);
		apm_enet_init_nxtfp(
			pdev->qm_queues[port_id % MAX_CORES].rx_nxtfp_qid,
			pdev->rx_buff_cnt, 0);
		apm_enet_init_fp(pdev->qm_queues[port_id % MAX_CORES].hw_fp_qid,
			HW_MTU(ndev->mtu), APM_HW_PKT_BUF, 0, pdev->hdr_rsvd);

#else
		apm_enet_init_fp(pdev->qm_queues[0].rx_fp_qid,
			HW_MTU(ndev->mtu), pdev->rx_buff_cnt, 0,
			pdev->hdr_rsvd);
		apm_enet_init_nxtfp(
			pdev->qm_queues[0].rx_nxtfp_qid,
			pdev->rx_buff_cnt, 0);
		apm_enet_init_fp(pdev->qm_queues[0].hw_fp_qid,
			HW_MTU(ndev->mtu), APM_HW_PKT_BUF, 0, pdev->hdr_rsvd);

#endif
#ifdef PKT_LOSSLESS_WOL
		/* configure intermediate free pool */
		if (port_id == 0 && !is_apm86xxx_lite()) {
			apm_enet_init_fp(DSLEEP_ENET_RX_FQ_TO_DDR,
				HW_MTU(ndev->mtu), 10, 1,
				pdev->hdr_rsvd);
		}
#endif
	} else {
		apm_enet_init_fp(pdev->qm_queues[core_id].rx_fp_qid,
			HW_MTU(ndev->mtu), pdev->rx_buff_cnt, 0,
			pdev->hdr_rsvd);
		apm_enet_init_nxtfp(pdev->qm_queues[core_id].rx_nxtfp_qid,
			pdev->rx_buff_cnt, 0);
		apm_enet_init_fp(pdev->qm_queues[core_id].hw_fp_qid,
			HW_MTU(ndev->mtu), APM_HW_PKT_BUF, 0, pdev->hdr_rsvd);

#ifdef PKT_LOSSLESS_WOL
		/* configure intermediate free pool */
		if (port_id == 0 && !is_apm86xxx_lite()) {
			apm_enet_init_fp(DSLEEP_ENET_RX_FQ_TO_DDR,
				HW_MTU(ndev->mtu), 10, 1, pdev->hdr_rsvd);
		}
#endif
	}

	if (!enet_dev_glb.enet_config_done) {
		/* Register QM callback function for Ethernet */
		apm_qm_msg_rx_register(APM_QM_ETH_RTYPE, apm_enet_rx_frame);
		enet_dev_glb.enet_config_done = 1;
	}

	apm_enet_add_sysfs(_pdev->dev.driver);

	/* Default MAC initialization */
	apm_gmac_init(priv, ndev->dev_addr, SPEED_1000, HW_MTU(ndev->mtu), priv->crc, 1);

#ifndef CONFIG_IE4000
	/* Ensure Rx & Tx are disabled in MAC.
	 * MDIO Link state changes will enable/disable Rx & Tx in MAC
	 */
	apm_gmac_tx_disable(priv);
	apm_gmac_rx_disable(priv);

	/* Setup MDIO bus */
	mdio_bus->name = "APM Ethernet MII Bus";
	mdio_bus->read = &apm_enet_mdio_read;
	mdio_bus->write = &apm_enet_mdio_write;
	mdio_bus->reset = &apm_enet_mdio_reset;
	snprintf(mdio_bus->id, MII_BUS_ID_SIZE, "%x", port_id);
	mdio_bus->priv = port_dev;
	mdio_bus->parent = &ndev->dev;
	mdio_bus->phy_mask = ~(1 << priv->phy_addr);

	if(!mdio_lock_init){
		spin_lock_init(&apm_mdio_lock);
		mdio_lock_init = 1;
	}

	if ((rc = mdiobus_register(mdio_bus)) != 0) {
		printk(KERN_ERR "enet%d: failed to register MDIO bus(%d)!\n",
		       pdev->port_id, rc);
		return rc;
	}
	if ((rc = apm_enet_mdio_probe(ndev))) {
		printk(KERN_ERR "enet%d: no PHY device found (%d)!\n",
		       pdev->port_id, rc);
	}
#endif
	/* Set InterPacket Gap if greater than 0 (existed in DTS) */
	if (pdev->ipg > 0)
		apm_gmac_set_ipg(priv, pdev->ipg);

	/* Register iPP Firmware Notifier */
	if (!ipp_notifier_registered) {
		register_ipp_fwload_notifier(&fwload_nb);
		ipp_notifier_registered = 1;
	}

	/* Initialize PreClassifier Tree for this port */
	ENET_DEBUG("Initialize Preclassifier Tree for port %d core %d\n",
		port_id, core_id);
#ifdef SMP_LOAD_BALANCE
	apm_preclass_init(port_id, &pdev->qm_queues[port_id % MAX_CORES]);
#else
	if (enet_dev_glb.is_smp)
		apm_preclass_init(port_id, &pdev->qm_queues[0]);
	else
		apm_preclass_init(port_id, &pdev->qm_queues[core_id]);
#endif

	apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR, BROADCAST_MACADDR,
				apm_sys_macmask[BROADCAST_MACADDR],
				apm_sys_macaddr[BROADCAST_MACADDR]);
	apm_preclass_update_mac(port_id, TYPE_SYS_MACADDR, ETHERNET_MACADDR,
				apm_sys_macmask[ETHERNET_MACADDR],
				ndev->dev_addr);

	/* Start Preclassifier Engine for this port */
	ENET_DEBUG("Start Preclassifier for port %d\n", port_id);
	apm_preclass_switch_tree(port_id, CLE_PTREE_DEFAULT, 0);
	pdev->in_poll_rx_msg_desc.is_msg16 = 0;

	/* Request for IRQ interrupt */
	port_dev->enet_err_irq = enet_irq;
	port_dev->enet_mac_err_irq = enet_mac_irq;
	port_dev->enet_qmi_err_irq = enet_qmi_irq;
	if (apm_netdev_glb->master_cfg && apm_netdev_glb->refcnt++ == 0) {
		/* First one, register for IRQ */
		/* Interrupts are not per port, its per block */
		if ((request_irq(port_dev->enet_err_irq, apm_enet_irq,
				IRQF_SHARED, ndev->name, ndev)) != 0)
			printk(KERN_ERR "Failed to reg Enet Error IRQ %d\n",
			       port_dev->enet_err_irq);
		if ((request_irq(port_dev->enet_mac_err_irq,
				apm_enet_mac_err_irq, IRQF_SHARED,
				ndev->name, ndev)) != 0)
			printk(KERN_ERR "Failed to reg Enet MAC Error IRQ %d\n",
				port_dev->enet_mac_err_irq);
		if ((request_irq(port_dev->enet_qmi_err_irq,
				apm_enet_qmi_err_irq,
				IRQF_SHARED, ndev->name, ndev)) != 0)
			printk(KERN_ERR "Failed to reg Enet QMI Error IRQ %d\n",
				port_dev->enet_qmi_err_irq);
	}

	/* Unmask error IRQ regardless of port */
	apm_enet_unmask_int(priv);
#ifdef CONFIG_PM
	/* Init List for storing Ethernet RX MSG before going to suspend */
	INIT_LIST_HEAD(&pdev->head);
#endif

#ifdef CONFIG_NAPI
	napi_enable(&pdev->napi);
#endif
	enet_proc_entry = proc_create("apm_enet", 0644, NULL, &apm_enet_proc_fops);

	if (enet_proc_entry ==  NULL)
		printk("ENET procfs entry creation failed\n");

	return 0;
}

/* Called when module is unloaded */
static int apm_enet_of_remove(struct platform_device *_pdev)
{
	struct apm_enet_dev *apm_netdev_glb;
	struct apm_enet_dev_base *pdev;
	struct apm_data_enet_dev *port_dev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	int port;
	int i;

	ENET_DEBUG("Unloading Ethernet driver\n");

	pdev = dev_get_drvdata(&_pdev->dev);
	port_dev = (struct apm_data_enet_dev *) pdev;
	ndev = pdev->ndev;
	priv = &pdev->priv;
	apm_netdev_glb = &enet_dev_glb;

	port = pdev->port_id;

	apm_enet_remove_sysfs(_pdev->dev.driver);

	/* Stop any traffic and disable MAC */
	apm_gmac_rx_disable(priv);
	apm_gmac_tx_disable(priv);

	/* Unregister netdev in kernel and free it */
	unregister_netdev(ndev);
	free_netdev(ndev);

#if !defined (CONFIG_SLAB_HW)
	for (i = 0; i < MAX_CORES; i++) {
		if (pdev->qm_queues[i].rx_fp_qid > 0)
			apm_enet_deinit_fp(pdev->qm_queues[i].rx_fp_qid);
		if (pdev->qm_queues[i].rx_nxtfp_qid > 0)
			apm_enet_deinit_nxtfp(pdev->qm_queues[i].rx_nxtfp_qid);
		if (pdev->qm_queues[i].hw_fp_qid > 0)
			apm_enet_deinit_fp(pdev->qm_queues[i].hw_fp_qid);
	}
#ifdef PKT_LOSSLESS_WOL
	if (port == GIGE_PORT0 && !is_apm86xxx_lite())
		apm_enet_deinit_fp(DSLEEP_ENET_RX_FQ_TO_DDR);
#endif
#endif

	if (--apm_netdev_glb->refcnt == 0) {
		/* Release IRQ */
		free_irq(port_dev->enet_err_irq, ndev);
		free_irq(port_dev->enet_mac_err_irq, ndev);
		free_irq(port_dev->enet_qmi_err_irq, ndev);

		/* Unregister iPP Firmware Notifier */
		if (ipp_notifier_registered) {
			unregister_ipp_fwload_notifier(&fwload_nb);
			ipp_notifier_registered = 0;
		}
	}

	proc_remove(enet_proc_entry);

	return 0;
}

#if defined(CONFIG_PM)
static inline int apm_put_enet_rx_desc(struct apm_enet_dev_base *pdev)
{
	struct list_head *head = &pdev->head;
	struct apm_enet_rx_desc *entry;
	struct apm_qm_msg64 msg;

	pdev->in_poll_rx_msg_desc.msg = &msg;

	if (unlikely (apm_qm_pull_msg(&pdev->in_poll_rx_msg_desc) == -1)) {
		return APM_RC_ERROR;
	}

	entry = kmalloc(sizeof (struct apm_enet_rx_desc),
			GFP_KERNEL | __GFP_ZERO);

	if (unlikely(entry == NULL))
		return APM_RC_ERROR;

	memcpy(&entry->msg, &msg, sizeof(struct apm_qm_msg64));
	list_add_tail(&entry->node, head);

	return APM_RC_OK;
}

static inline int apm_get_enet_rx_desc(struct apm_enet_dev_base *pdev)
{
	struct list_head *head = &pdev->head;
	struct apm_enet_rx_desc *entry;

	if (unlikely(list_empty(head)))
		return APM_RC_ERROR;

	entry = list_first_entry(head, struct apm_enet_rx_desc, node);

	if (unlikely(entry == NULL))
		return APM_RC_ERROR;

	pdev->in_poll_rx_msg_desc.msg = &entry->msg;
	apm_enet_rx_frame(&pdev->in_poll_rx_msg_desc);
	list_del(&entry->node);
	kfree(entry);

	return APM_RC_OK;
}

static int apm_enet_empty_rx(struct apm_enet_dev_base *pdev, int budget)
{
	int cnt = 0;

	while (budget--) {
		ENET_DEBUG("Emptying RX Q before suspending\n");
		if (likely(apm_put_enet_rx_desc(pdev) == -1)) {
			break;
		}
		cnt++;
	};

	return cnt;
}

static int apm_enet_queue_rx(struct apm_enet_dev_base *pdev)
{
	int cnt = 0;

	while ((unlikely(apm_get_enet_rx_desc(pdev) != -1))) {
		ENET_DEBUG("Queuing RX Q after resuming\n");
		cnt++;
	}

	return cnt;
}

static int apm_enet_drain_wq(struct apm_data_priv *priv, int qid, int pbn,
				int delay_sec, int delayms)
{
	struct apm_qm_qstate qstate;
	unsigned long ts_start;
	int rc;

	ts_start = jiffies;
	/* Wait for queue to drain */
	do {
		rc = apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
		if (rc < 0) {
			printk(KERN_ERR "fail to drain queue %d\n", qid);
			return rc;
		}
		if (time_after(jiffies, ts_start + delay_sec*HZ)) {
			printk(KERN_ERR "fail to drain queue %d\n", qid);
			dump_qstate(&qstate);
			return -1;
		}
	} while (qstate.nummsgs);

	/* Now, what about pre-fetch buffer and PPC mailbox.
	   For alternative enqueue, it is not possible to read the pre-fetch
	   buffer state. Therefore, we will use a delay */
	if (pbn < 0 || delayms > 0) {
		mdelay(delayms);
	} else if (pbn >= 0) {
		/* Read the pre-fetch buffer count until it is 0 */
		u32 val;
		u32 nomsg;

		do {
			apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE,
					ENET_STSSSQMIWQBUFFER2_ADDR, &val);
			nomsg = (val >> (pbn * 3))  & 0x7;
			if (time_after(jiffies, ts_start + delay_sec*HZ)) {
				printk(KERN_ERR "fail to drain queue %d\n",
					qid);
				return -1;
			}
		} while (nomsg);
	}
	return 0;
}

static int apm_enet_drain_fp(struct apm_enet_dev_base *pdev, int qid, int pbn,
			int drain_pbn_only, int disable_pbn)
{
	struct apm_data_priv *priv = &pdev->priv;
	struct apm_qm_qstate qstate;
	int num_qmi_buffers;
	int drained_cnt = 0;
	int eth_ip;
	u32 word3;
	u32 word2;
	u32 word1;
	u32 word0;
	u32 val;
	u32 qmi_fp_status = 0;

	if (pdev->port_id <= 1)
		eth_ip = PB_SLAVE_ID_ETH;
	else
		eth_ip = PB_SLAVE_ID_ETHX;

	apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
	ENET_DBG_Q("ETH%d draining pre-fetch buffer QID %d PBN %d msg %d",
		pdev->port_id, qid, pbn, qstate.nummsgs);
	num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
	val = apm_qm_pb_get(IP_BLK_QM, eth_ip, pbn + 0x20);
	ENET_DBG_Q("ETH PBN msg cnt %d QM PBN cnt 0x%08X\n",
		num_qmi_buffers, val);

	if (drain_pbn_only) {
		/* Disable queue pre-fetch buffer to not push message */
		val = apm_qm_pb_get(IP_BLK_QM, eth_ip, pbn + 0x20);
		val &= ~(1 << 14);	/* Disable pre-fetch buffer pushing */
		apm_qm_pb_set(IP_BLK_QM, eth_ip, pbn + 0x20, val);
		/* Wait for any in-service to finish */
		do {
			val = apm_qm_pb_get(IP_BLK_QM, eth_ip, pbn + 0x20);
		} while (val & (1<<18));

		apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE, ENET_CFGSSQMIFPBUFFER_ADDR,
				&qmi_fp_status);
		apm_enet_wr32(priv, BLOCK_ETH_QMI_SLAVE, ENET_CFGSSQMIFPBUFFER_ADDR,
				0xffff0000);

		udelay(100);

		/* Now drain the ETH pre-fetch buffer but do not remove it */
		num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
		while (num_qmi_buffers > 0)  {
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				0, 0, &word3);
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				1, 0, &word2);
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				2, 0, &word1);
			apm_enet_qmi_pop_pb_msg(priv, pbn + 0x20,
				3, 1, &word0);
			if (word3 > 0x10)
				FREE_SKB((struct sk_buff *) word3);
			else {
				printk("Failed to get skb to drain for port %d\n",
						pdev->port_id);
				break;
			}

			drained_cnt++;

			num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
		}

		apm_enet_wr32(priv, BLOCK_ETH_QMI_SLAVE, ENET_CFGSSQMIFPBUFFER_ADDR,
				qmi_fp_status);

		num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
		val = apm_qm_pb_get(IP_BLK_QM, eth_ip, pbn + 0x20);
		ENET_DBG_Q("PBN msg cnt remain %d QM PBN cnt 0x%08X\n",
			num_qmi_buffers, val);
		return drained_cnt;
	}

	/* Drain all message in this ETH pre-fetch buffer and remove it */
	do {
		apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
		if (qstate.nummsgs == 0) {
			/* Wait for any in-service to finish */
			do {
				val = apm_qm_pb_get(IP_BLK_QM, eth_ip,
						pbn + 0x20);
			} while (val & (1<<18));
		}
		/* Now drain the ETH pre-fetch buffer but do not remove it */
		num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
		while (num_qmi_buffers > 0)  {
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				0, 0, &word3);
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				1, 0, &word2);
			apm_enet_qmi_read_pb_msg(priv, pbn + 0x20,
				2, 0, &word1);
			apm_enet_qmi_pop_pb_msg(priv, pbn + 0x20,
				3, 1, &word0);
			if (word3 > 0x10)
				FREE_SKB((struct sk_buff *) word3);
			drained_cnt++;

			num_qmi_buffers = apm_enet_get_pb_cnt(priv, pbn);
		}
	} while (qstate.nummsgs > 0);

	/* Disable queue pre-fetch buffer to not push message */
	if (disable_pbn) {
		val = apm_qm_pb_get(IP_BLK_QM, eth_ip, pbn + 0x20);
		val &= ~(1 << 14);	/* Disable pre-fetch buffer pushing */
		apm_qm_pb_set(IP_BLK_QM, eth_ip, pbn + 0x20, val);
	}
	return drained_cnt;
}

#if !defined (NOTIFICATION_OFF) && !defined (CONFIG_SLAB_HW)
static inline void apm_qm_pull_tx_comp_msg(u32 mailbox, u32 count)
{
	int skbval;

	while (count--) {
		while ((skbval = apm_qm_pull_comp_msg(mailbox)) != -1) {
			if (apm_enet_free_comp_skb((struct sk_buff *) skbval))
				break;
		}
	}
}
#endif

void apm_enet_drain_cq(struct apm_enet_dev_base *pdev)
{
#if !defined(NOTIFICATION_OFF) && !defined(CONFIG_SLAB_HW)
	int core_id = apm_processor_id();
	struct apm_qm_qstate qstate;

	do {
		apm_qm_qstate_rd(IP_BLK_QM,
				pdev->qm_queues[core_id].comp_qid, &qstate);

		/* When the number queue message is zero, allow some time
		   for the HW to push the last message to the mailbox */
		if (qstate.nummsgs == 0)
			mdelay(1);

		/* Pull all completion message from all slot */
		apm_qm_pull_tx_comp_msg(pdev->qm_queues[core_id].comp_mb,
					8);
	} while (qstate.nummsgs > 0);

	/* Pull one last time */
	apm_qm_pull_tx_comp_msg(pdev->qm_queues[core_id].comp_mb, 8);
#endif
}

static int apm_enet_of_suspend_clk(struct platform_device* _pdev, pm_message_t state)
{
	struct apm_enet_dev_base *pdev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	int core_id;
	int port;
	int qid;
	int comp_timeout = 2000;
	ENET_DEBUG("Ethernet Suspend Clock...\n");
	pdev = dev_get_drvdata(&_pdev->dev);
	priv = &pdev->priv;
	port = pdev->port_id;
	ndev = pdev->ndev;
	core_id = apm_processor_id();

	/* Stop Rx in MAC */
	pdev->pm_save_rx_enabled = apm_gmac_is_rx_enable(priv);
	apm_gmac_rx_disable(priv);

	/* Stop network stack for this port */
	pdev->pm_intf_restart = netif_running(ndev);
	netif_device_detach(ndev);
	if (pdev->pm_intf_restart) {
		netif_stop_queue(ndev);
		apm_qm_disable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
#ifdef CONFIG_NAPI
		napi_disable(&pdev->napi);
#endif
	} else {
		/* for clock suspend, if interface is down, set state to READY */
		if (pdev->phy_dev) {
			pdev->phy_dev->state = PHY_READY;
		}
	}

	while ((cmp_cnt > 0) && (comp_timeout-- >= 0)) {
		apm_enet_drain_cq(pdev);
		mdelay(1);
	}
	if (cmp_cnt > 0) {
		printk(KERN_WARNING
			"Ethernet completion message not "
			"cleared completely\n");
		/* make completion count back to 0 */
		cmp_cnt = 0;
	}

	/* stop tx now */
	apm_gmac_tx_disable(priv);


	/* Flush FP */
	apm_enet_drain_fp(pdev, pdev->qm_queues[core_id].rx_fp_qid,
		pdev->qm_queues[core_id].rx_fp_pbn - 0x20, 1, 1);
	apm_enet_drain_fp(pdev, pdev->qm_queues[core_id].hw_fp_qid,
		pdev->qm_queues[core_id].hw_fp_pbn - 0x20, 1, 1);

	/* Power Down PHY */
	if (pdev->phy_dev) {
		genphy_suspend(pdev->phy_dev);
	}

	if (enet_dev[0]) {
		enet_dev[0]->dev_base.pm_flags &= ~APM_ENET_PM_FLAG_PENDINGCLKGATE;
		enet_dev[0]->dev_base.pm_flags |= APM_ENET_PM_FLAG_PENDINGCLKEN;
	}

	return 0;
}

static int apm_enet_of_suspend_pwroff(struct platform_device* _pdev, pm_message_t state)
{
	struct apm_enet_dev_base *pdev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	int port;

	ENET_DEBUG("Ethernet Suspend Power Off...\n");
	pdev = dev_get_drvdata(&_pdev->dev);
	priv = &pdev->priv;
	port = pdev->port_id;
	ndev = pdev->ndev;

	pdev->pm_flags |= APM_ENET_PM_FLAG_PWROFF;

	/* Stop Rx & Tx in MAC */
	pdev->pm_save_rx_enabled = apm_gmac_is_rx_enable(priv);
	apm_gmac_rx_disable(priv);
	apm_gmac_tx_disable(priv);

	/* Stop network stack for this port */
	pdev->pm_intf_restart = netif_running(ndev);
	netif_device_detach(ndev);
	if (pdev->pm_intf_restart) {
		netif_stop_queue(ndev);
		apm_qm_disable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
#ifdef CONFIG_NAPI
		napi_disable(&pdev->napi);
#endif
	} else {
		/* for power off, if interface is down, set state to READY */
		if (pdev->phy_dev) {
			pdev->phy_dev->state = PHY_READY;
		}
	}

	/* Don't need Stop the PHY as we going to power down. */

        /* We choose not to clock gate as we goig power it off. Also,
         * if we do choose to clock gate, then we need to wait for both
         * ports (port 0/port 1 or port 2/port 3) before clock gate both.
         */
        return 0;
}

static int apm_enet_of_suspend_wol(struct platform_device* _pdev, pm_message_t state)
{
#if !defined (NOTIFICATION_OFF) && !defined (CONFIG_SLAB_HW)
	int core_id = apm_processor_id();
#endif
	struct apm_enet_dev_base *pdev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	int port;
	struct in_device *in_dev;
	struct inet6_dev *in6_dev;
	u32 ipv6_addr_data[5] = {0};
	u32 ipaddr = 0;
	int rc = -EINVAL;
	struct list_head *head;
	struct inet6_ifaddr *temp, *entry;
	int comp_timeout = 2000;

	ENET_DEBUG("Ethernet Suspend WOL...\n");

	pdev = dev_get_drvdata(&_pdev->dev);
	if (pdev == NULL) {
		/* Skip disabled port */
		return 0;
	}

	priv = &pdev->priv;
	port = pdev->port_id;
	ndev = pdev->ndev;

	in_dev = in_dev_get(ndev);
	if (in_dev && in_dev->ifa_list)
		ipaddr = in_dev->ifa_list->ifa_address;

	in6_dev = in6_dev_get(ndev);

	head  = &(in6_dev->addr_list);
	list_for_each_entry_safe(entry, temp, head, if_list) {
		memcpy(&ipv6_addr_data[1], &(entry->addr),
			IPV6_ADDR_LEN);
		break;
	}

	if (!is_apm86xxx_lite()) {
		int saved_rx_msg = 0;

		pdev->pm_save_rx_enabled = apm_gmac_is_rx_enable(priv);
		apm_gmac_rx_disable(priv);
		apm_gmac_tx_enable(priv);

		/* Stop interface */
		pdev->pm_intf_restart = netif_running(ndev);
		if (pdev->pm_intf_restart) {
			netif_stop_queue(ndev);
			apm_qm_disable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
#ifdef CONFIG_NAPI
			napi_disable(&pdev->napi);
#endif
		} else {
			/* for WOL, if interface is down, set state to HALTED */
			if (pdev->phy_dev) {
				pdev->phy_dev->state = PHY_HALTED;
			}
		}
		netif_device_detach(ndev);

		/* Flush completion queue when notifications are ON
		 * 1. Wait for all Tx queue to drain completely as TX is enabled
		 * 2. Drain the completion queue
		 */
		while ((cmp_cnt > 0) && (comp_timeout-- >= 0)) {
			apm_enet_drain_cq(pdev);
			mdelay(1);
		}
		if (cmp_cnt > 0) {
			printk(KERN_WARNING
				"Ethernet completion message not "
				"cleared completely\n");
			/* make completion count back to 0 */
			cmp_cnt = 0;
		}

		saved_rx_msg = apm_enet_empty_rx(pdev, 1024);
		if (saved_rx_msg) {
			printk(KERN_INFO
				"ETHERNET SUSPEND: Saved %d rx frames\n",
				saved_rx_msg);
		}

		/* Ensure MAC CRC is enabled for SlimPRO */
		if (!pdev->priv.crc) {
			apm_gmac_crc_enable(priv, 1);
			apm_gmac_pad_crc_enable(priv, 1);
		}

		/* Change the Mac Frame Length that iPP can handle */
		apm_gmac_change_mtu(priv, enet_dev_glb.ipp_hw_mtu);

		rc = apm_preclass_switch_tree(port, CLE_PTREE_WOL, 1);
		if (rc != APM_RC_OK) {
			printk(KERN_ERR "ETHERNET SUSPEND: "
				"Changing tree to WOL Failed\n");
			goto error;
		}

		/* Send Ipv4 Address to iPP */
		rc = ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
					IPP_SEND_IPv4_ADDR_VAR,
					IPP_MSG_PARAM_UNUSED,
					IPP_MSG_CONTROL_URG_BIT, ipaddr);
		if (rc != APM_RC_OK) {
			printk(KERN_ERR "ETHERNET SUSPEND: "
				"Sending IPv4 addr to iPP Failed\n");
			goto error;
		}
		/* Send Ipv6 Address to iPP */
		ipv6_addr_data[0] = IPP_ENCODE_NETDATA_CTRL_WORD(
					IPP_NETDATA_IPv6_TYPE,
					IPP_IPv6_UCAST, 0, 0);

		rc = ipp_send_data_msg(IPP_NETDATA_HDLR,
				ipv6_addr_data, sizeof(ipv6_addr_data), NULL);
		if (rc != APM_RC_OK) {
			printk(KERN_ERR "ETHERNET SUSPEND: "
				"Sending IPv6 address to iPP Failed\n");
			goto error;
		}
	}

#ifdef  CONFIG_NET_PROTO
	ENET_DEBUG("EHTERNET SUSPEND: send_snmp_param \n");
	rc = send_snmp_param();
	if (rc != APM_RC_OK) {
		printk(KERN_ERR
			"EHTERNET SUSPEND: Sending snmp_param to iPP Failed\n");
		goto error;
	}
	ENET_DEBUG("EHTERNET SUSPEND: send_netbios_param \n");
	rc = send_netbios_param();
	if (rc != APM_RC_OK) {
		printk(KERN_ERR
			"EHTERNET SUSPEND: Sending netbios_param to iPP Failed\n");
		goto error;
	}
#endif
error:
	return rc;
}

static int apm_enet_of_suspend(struct platform_device* _pdev, pm_message_t state)
{
        struct apm_enet_dev_base *pdev = dev_get_drvdata(&_pdev->dev);

	if (pdev == NULL)
		return 0;	/* Skip disabled port */

        if (state.event & PM_EVENT_FREEZE) {
                /* To hibernate */
                pdev->pm_flags |= APM_ENET_PM_FLAG_PWROFF;
        } else if (state.event & PM_EVENT_SUSPEND) {
                /* To suspend (deep sleep). Pleae note that only port 0
                   and port 1 are in the deep sleep domain. */
                if (pdev->port_id == 0) {
                        if (is_wake_on_lan_enabled())
		                pdev->pm_flags |= APM_ENET_PM_FLAG_WOL;
			else
				pdev->pm_flags |= APM_ENET_PM_FLAG_CLKGATED;
		} else if (pdev->port_id == 1) {
			pdev->pm_flags |= APM_ENET_PM_FLAG_CLKGATED;
	        } else {
	                pdev->pm_flags |= APM_ENET_PM_FLAG_PWROFF;
		}
        } else if (state.event & PM_EVENT_RESUME) {
                /* To resume */
        } else if (state.event & PM_EVENT_RECOVER) {
                /* To recover from enter suspend failure */
        }

	ENET_DEBUG("ETH%d Suspend (0x%08X 0x%08X)...\n",
		pdev->port_id, state.event, pdev->pm_flags);
        if (pdev->pm_flags & APM_ENET_PM_FLAG_PWROFF)
	        return apm_enet_of_suspend_pwroff(_pdev, state);
        if (pdev->pm_flags & APM_ENET_PM_FLAG_WOL)
	        return apm_enet_of_suspend_wol(_pdev, state);
        if (pdev->pm_flags & APM_ENET_PM_FLAG_CLKGATED)
	        return apm_enet_of_suspend_clk(_pdev, state);
	return 0;
}

static int apm_enet_of_resume_pwroff(struct platform_device* _pdev)
{
        struct apm_enet_dev_base *pdev;
        struct apm_data_priv *priv;
        struct net_device *ndev;
	int core_id = apm_processor_id();
        int port;

        pdev = dev_get_drvdata(&_pdev->dev);
        priv = &pdev->priv;
        port = pdev->port_id;
	ndev = pdev->ndev;

        ENET_DEBUG("Ethernet Resume Power Off...\n");

	pdev->pm_flags = 0;		/* Clear all PM flags */

	/* Re-program interrupt coalescence for Rx queue as QM powerred off */
	apm_qm_mbox_set_coal(pdev->qm_queues[core_id].default_rx_mb, 0x4);

	if (pdev->pm_intf_restart) {
#ifdef CONFIG_NAPI
		napi_enable(&pdev->napi);
#endif
		apm_qm_enable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
	}
	netif_device_attach(ndev);

        if (pdev->pm_intf_restart)
                netif_wake_queue(ndev);

        /* Re-enable MAC RX & Tx if enabled before we entered deep sleep */
        if (pdev->pm_save_rx_enabled) {
                apm_gmac_rx_enable(priv);
                apm_gmac_tx_enable(priv);
        } else {
                apm_gmac_rx_disable(priv);
                apm_gmac_tx_disable(priv);
	}

	return 0;
}

static int apm_enet_of_resume_clk(struct platform_device* _pdev)
{
	struct apm_enet_dev_base *pdev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	int core_id;
	int port;
	int rc;
	struct apm_qm_qstate qstate;
	int add_fp;
	u32 val;

	ENET_DEBUG("Ethernet Resume Clock...\n");
	pdev = dev_get_drvdata(&_pdev->dev);
	priv = &pdev->priv;
	port = pdev->port_id;
	ndev = pdev->ndev;
	core_id = apm_processor_id();

	if (!(pdev->pm_flags & APM_ENET_PM_FLAG_PENDINGCLKEN))
		goto skip_enclk;

	pdev->pm_flags = 0;		/* Clear all PM flags */

	/* Enable clock */
	if (enet_dev_glb.is_smp || !core_id) {
		/* Remove ENET CSR memory shutdown */
		ENET_DEBUG("Port %d Removing memshutdown\n", port);
		if ((rc = apm86xxx_disable_mem_shutdown(
				(u32 __iomem *)(priv->eth_diag_base_addr_v +
				ENET_CFG_MEM_RAM_SHUTDOWN_ADDR),
				ENET0_F2_MASK)) != 0) {
			printk(KERN_ERR
				"Failed to remove Eth CSR memory shutdown\n");
			return rc;
		}
		/* Remove CLE CSR memory shutdown */
		if ((rc = apm86xxx_disable_mem_shutdown(
				(u32 __iomem *)(apm_class_base_addr +
				APM_GLBL_DIAG_OFFSET +
				CLE_CFG_MEM_RAM_SHUTDOWN_ADDR),
				CLE_MASK)) != 0) {
			printk(KERN_ERR "Failed to remove Classifier CSR "
				"memory shutdown\n");
			return rc;
		}
	}

skip_enclk:
	pdev->pm_flags = 0;		/* Clear all PM flags */

	/* Re-program interrupt coalescence for Rx queue as QM powerred off */
	apm_qm_mbox_set_coal(pdev->qm_queues[core_id].default_rx_mb, 0x4);

	 /* Read queue state to see how many message in the queue */
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].rx_fp_qid,
                        &qstate);
        add_fp = pdev->rx_buff_cnt - qstate.nummsgs;
        ENET_DEBUG("ETH QID %d msg %d\n",
                pdev->qm_queues[core_id].rx_fp_qid, qstate.nummsgs);

        /* Clear the pre-fetch buffer state of Ethernet for this PBN */
        apm_enet_wr32(priv, BLOCK_ETH_QMI_SLAVE, ENET_CFGSSQMIFPBUFFER_ADDR,
                        1 << (pdev->qm_queues[core_id].rx_fp_pbn-0x20));
        do {
                apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE,
                                ENET_CFGSSQMIFPBUFFER_ADDR, &val);
        } while (val & (1 << (pdev->qm_queues[core_id].rx_fp_pbn-0x20)));

        /* Clear QM PBN state as we already drained the PBN of the Ethernet */
	val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH,
                        pdev->qm_queues[core_id].rx_fp_pbn);
	val &= ~0xF;            /* Clear PBN num msg */
	val &= ~0x00038000;     /* Clear slot number */
	val |= (1 << 14);       /* Enable pre-fetch buffer pushing */
	val |= 0x80000000;
	apm_qm_pb_set(IP_BLK_QM, PB_SLAVE_ID_ETH,
                       pdev->qm_queues[core_id].rx_fp_pbn, val);

        /* Read queue state to see how many message in the queue */
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].rx_fp_qid,
                        &qstate);
        ENET_DEBUG("ETH enable QID %d msg %d\n",
                pdev->qm_queues[core_id].rx_fp_qid, qstate.nummsgs);

	 /* Now add buffer */
        if (add_fp > 0)
                apm_enet_init_fp(pdev->qm_queues[core_id].rx_fp_qid,
                        pdev->rx_buff_cnt, add_fp, 0, pdev->hdr_rsvd);
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].rx_fp_qid,
                        &qstate);
        ENET_DEBUG("ETH refill %d QID %d msg %d\n", add_fp,
                pdev->qm_queues[core_id].rx_fp_qid, qstate.nummsgs);

        apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE,
                        pdev->qm_queues[core_id].rx_fp_pbn <= 0x27 ?
                                ENET_STSSSQMIFPBUFFER1_ADDR :
                                ENET_STSSSQMIFPBUFFER2_ADDR, &val);
        ENET_DEBUG("ETH pbn %d 0x%08X\n",
                pdev->qm_queues[core_id].rx_fp_pbn, val);
        val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH,
                pdev->qm_queues[core_id].rx_fp_pbn);
        ENET_DEBUG("QM PBN 0x%08X\n", val);
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].rx_fp_qid,
                        &qstate);

	  /* Read queue state to see how many message in the queue */
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].hw_fp_qid,
                        &qstate);
        add_fp = APM_HW_PKT_BUF - qstate.nummsgs;
        ENET_DEBUG("ETH QID %d msg %d\n",
                pdev->qm_queues[core_id].hw_fp_qid, qstate.nummsgs);

        /* Clear the pre-fetch buffer state of Ethernet for this PBN */
        apm_enet_wr32(priv, BLOCK_ETH_QMI_SLAVE, ENET_CFGSSQMIFPBUFFER_ADDR,
                        1 << (pdev->qm_queues[core_id].hw_fp_pbn-0x20));
        do {
                apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE,
                                ENET_CFGSSQMIFPBUFFER_ADDR, &val);
        } while (val & (1 << (pdev->qm_queues[core_id].hw_fp_pbn-0x20)));

        /* Clear QM PBN state as we already drained the PBN of the Ethernet */
	val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH,
                       pdev->qm_queues[core_id].hw_fp_pbn);
	val &= ~0xF;            /* Clear PBN num msg */
	val &= ~0x00038000;     /* Clear slot number */
	val |= (1 << 14);       /* Enable pre-fetch buffer pushing */
	val |= 0x80000000;
	apm_qm_pb_set(IP_BLK_QM, PB_SLAVE_ID_ETH,
                        pdev->qm_queues[core_id].hw_fp_pbn, val);

        /* Now add buffer */
        if (add_fp > 0)
                apm_enet_init_fp(pdev->qm_queues[core_id].hw_fp_qid,
                        APM_HW_PKT_BUF, add_fp, 0, pdev->hdr_rsvd);
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].hw_fp_qid,
                        &qstate);
	ENET_DEBUG("ETH refill %d QID %d msg %d\n", add_fp,
			pdev->qm_queues[core_id].hw_fp_qid, qstate.nummsgs);

        apm_enet_rd32(priv, BLOCK_ETH_QMI_SLAVE,
                        pdev->qm_queues[core_id].hw_fp_pbn <= 0x27 ?
                                ENET_STSSSQMIFPBUFFER1_ADDR :
                                ENET_STSSSQMIFPBUFFER2_ADDR, &val);
        ENET_DEBUG("ETH pbn %d 0x%08X\n",
                pdev->qm_queues[core_id].hw_fp_pbn, val);
        val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH,
                pdev->qm_queues[core_id].hw_fp_pbn);
        ENET_DEBUG("QM PBN 0x%08X\n", val);
        apm_qm_qstate_rd(IP_BLK_QM, pdev->qm_queues[core_id].hw_fp_qid,
                        &qstate);

	/* Power Up PHY */
	if (pdev->phy_dev) {
		genphy_resume(pdev->phy_dev);
	}

	/* Reinit MAC */
	apm_gmac_init(priv, ndev->dev_addr, SPEED_1000, HW_MTU(ndev->mtu),
			priv->crc, 1);

        /* Re-enable MAC RX & Tx if enabled before we entered deep sleep */
        if (pdev->pm_save_rx_enabled) {
                apm_gmac_rx_enable(priv);
                apm_gmac_tx_enable(priv);
        } else {
                apm_gmac_rx_disable(priv);
                apm_gmac_tx_disable(priv);
	}

	if (pdev->pm_intf_restart) {
		ENET_DEBUG("Enabling QM intr\n");
#ifdef CONFIG_NAPI
		napi_enable(&pdev->napi);
#endif
		apm_qm_enable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
		netif_wake_queue(ndev);
	}
	netif_device_attach(ndev);

	ENET_DEBUG("Ethernet Resume Clock done...\n");
	return 0;
}

static int apm_enet_of_resume_wol(struct platform_device* _pdev)
{
	int rc = 0;
	struct apm_enet_dev_base *pdev;
	struct apm_data_priv *priv;
	struct net_device *ndev;
	u32 core_id = apm_processor_id();
	int port;
	u32 val;
#ifdef PKT_LOSSLESS_WOL
	struct apm_qm_msg32 qml_msg;
	struct apm_qm_msg_desc tx_msg_desc;
	struct apm_qm_msg16 *msg16;
#endif

	ENET_DEBUG("Ethernet Resume WOL...\n");

	pdev = dev_get_drvdata(&_pdev->dev);
	if (pdev == NULL) {
		/* Skip disabled port */
		ENET_DEBUG("Ethernet Resume WOL done...\n");
		return 0;
	}

	pdev->pm_flags = 0;		/* Clear all PM flags */

	priv = &pdev->priv;
	port = pdev->port_id;
	ndev = pdev->ndev;

	/* Re-program interrupt coalescence for Rx queue as QM powerred off */
	apm_qm_mbox_set_coal(pdev->qm_queues[core_id].default_rx_mb, 0x4);

	if (!is_apm86xxx_lite()) {
		int restored_rx_msg = 0;

		/* Set MAC CRC state */
		if (!pdev->priv.crc) {
			apm_gmac_crc_enable(priv, 0);
			apm_gmac_pad_crc_enable(priv, 0);
		}

		/* Ensure correct MTU in hardware */
		apm_gmac_change_mtu(priv, HW_MTU(ndev->mtu));

		rc = apm_preclass_switch_tree(port, CLE_PTREE_DEFAULT, 0);
		if (rc != APM_RC_OK)  {
			printk(KERN_ERR "ETHERNET RESUME: "
				"Changing the tree to Power UP mode failed\n");
		}

		rc = apm_enet_wr32(priv, BLOCK_ETH_GBL,
			RSIF_WOL_MODE0_ADDR, CFG_MPA_ENET_WAKE_UP0_WR(1)
#if !defined(CONFIG_APM862xx)
			| CFG_MPA_ENET_TX_WAKEUP_QMSEL_PORT00_MASK
#endif
			);
		if (rc) {
			printk(KERN_ERR "ETHERNET RESUME: "
				"Failed to switch ethernet to normal mode.\n");
		}
		apm_enet_rd32(priv, BLOCK_ETH_GBL, RSIF_WOL_MODE0_ADDR, &val);

#ifdef PKT_LOSSLESS_WOL
		/* Retrieve WoL intermediate messages from
		   QM light and give it to QM */
		while (apm_qml_pull_msg(&qml_msg) != -1) {
			msg16 = (struct apm_qm_msg16 *) &qml_msg;
			ENET_DEBUG("Received QML inte msg with RTYPE: %d\n",
				msg16->RType);
			/* prepare message and enqueue on WoL queue */
			tx_msg_desc.msg = &qml_msg;
			tx_msg_desc.qid = enet_dev_glb.wol_qid;
			apm_qm_push_msg(&tx_msg_desc);
		}
#endif
		restored_rx_msg = apm_enet_queue_rx(pdev);
		if (restored_rx_msg) {
			printk("ETHERNET RESUME: Restored %d rx frames.\n",
				restored_rx_msg);
		}

		if (pdev->pm_intf_restart) {
#ifdef CONFIG_NAPI
			napi_enable(&pdev->napi);
#endif
			apm_qm_enable_mb_irq(pdev->in_poll_rx_msg_desc.mb_id);
			netif_wake_queue(ndev);
		}
		netif_device_attach(ndev);

		/* Re-enable MAC RX & Tx if enabled before we entered deep sleep */
		if (pdev->pm_save_rx_enabled) {
			apm_gmac_rx_enable(priv);
			apm_gmac_tx_enable(priv);
		} else {
			apm_gmac_rx_disable(priv);
			apm_gmac_tx_disable(priv);
		}

	}

	ENET_DEBUG("Ethernet Resume WOL done...\n");
	return rc;
}

static int apm_enet_of_resume(struct platform_device* _pdev)
{
        struct apm_enet_dev_base *pdev = dev_get_drvdata(&_pdev->dev);

	if (pdev == NULL)
		return 0;	/* Skip disabled port */

	ENET_DEBUG("ETH%d Resume...\n", pdev->port_id);

        if (pdev->pm_flags & APM_ENET_PM_FLAG_PWROFF)
	        return apm_enet_of_resume_pwroff(_pdev);
        if (pdev->pm_flags & APM_ENET_PM_FLAG_WOL)
	        return apm_enet_of_resume_wol(_pdev);
        if (pdev->pm_flags & APM_ENET_PM_FLAG_CLKGATED)
	        return apm_enet_of_resume_clk(_pdev);
	return 0;
}
#endif

static struct of_device_id apm_enet_match[] = {
	{.compatible = "apm, apm86xxx-enet",},
	{},
};

static struct platform_driver apm_enet_driver = {
	.driver.name = APM86XXX_ENET_DRIVER_NAME,
	.driver.of_match_table = apm_enet_match,
	.probe = apm_enet_of_probe,
	.remove = apm_enet_of_remove,
#if defined(CONFIG_PM)
	.suspend = apm_enet_of_suspend,
	.resume = apm_enet_of_resume,
#endif
};

static int __init apm_net_init(void)
{
	int i;

	/* Initialize global structure */
	for (i = 0; i < MAX_PORTS; i++) {
		enet_dev[i] = NULL;
	}

	/* Initialize Classifier global data structure */
	for (i = 0; i < MAX_CLE_ENGINE; i++) {
		apm_class_base_addr_p[i] = 0;
		apm_class_base_addr[i] = 0;
	}

	/* For AMP Systems, we are partitioning cle resoures */
#ifdef CONFIG_SMP
	apm_cle_system_id = CORE_0;
	apm_cle_systems = 1;
#else
	apm_cle_system_id = mfspr(SPRN_PIR);
	apm_cle_systems = 1;
#if !defined(CONFIG_APM867xx)
	for (i = CORE_1; i < MAX_SYSTEMS; i++)
		if (cpu_enabled(i))
			apm_cle_systems++;
#endif
#endif

	memset(&enet_dev_glb, 0, sizeof(enet_dev_glb));

	return platform_driver_register(&apm_enet_driver);
}

static void __exit apm_net_exit(void)
{
	platform_driver_unregister(&apm_enet_driver);
}

module_init(apm_net_init);
module_exit(apm_net_exit);

MODULE_AUTHOR("Keyur Chudgar <kchudgar@apm.com>");
MODULE_DESCRIPTION("APM862xx SoC Ethernet driver");
MODULE_LICENSE("GPL");
