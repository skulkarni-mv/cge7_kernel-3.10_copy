/**
 * AppliedMicro APM86xxx SoC Ethernet LRO Driver
 *
 * Copyright (c) 2012 Applied Micro Circuits Corporation.
 * All rights reserved. Loc Ho <lho@apm.com>
 *                      Ravi Patel <rapatel@apm.com>
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
 * @file apm_enet_lro.c
 *
 * APM86xxx Ethernet LRO implementation for APM86xxx SoC.
 */
#include <asm/cacheflush.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <asm/ipp.h>
#include <asm/apm_slimpro_offload.h>
#include "asm/apm_pktdma.h"
#include "apm_enet_access.h"
#include "apm_enet_lro.h"
#include "apm_cle_lro.h"
#include "apm_enet_offload.h"

#ifdef CONFIG_APM_ENET_LRO

#define LROID			"LRO: "

static unsigned long lro_work_domain = 0;

int apm_enet_lro_enable(struct apm_enet_dev_base *priv, u32 enable)
{
	int rc = APM_RC_OK;

	/* Enable or disable LRO */
	if (priv->lro.enable == enable)
		goto _ret_enet_lro_enable;

	priv->lro.enable = enable;
	if (enable) {
		ENET_DEBUG_LRO("LRO enabled\n");
		rc = apm_inet_switch(priv, ETHOFFLOAD_IPP_LRO);
	} else {
		ENET_DEBUG_LRO("LRO disabled\n");
		rc = apm_inet_switch(priv, ETHOFFLOAD_DEFAULT);
	}

_ret_enet_lro_enable:
	return rc;
}

int apm_enet_lro_set_timeout(struct apm_enet_dev_base *priv, u32 timeoutms)
{
	int rc;
	struct ipp_lro_message ipp_lro;

	/* Send timeout to SlimPRO */
	ipp_lro.cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_LRO_TYPE,
			IPP_LRO_TIMEOUT, priv->port_id, 0);
	ipp_lro.val = timeoutms;
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, &ipp_lro,
			sizeof(ipp_lro), NULL);
	if (rc) {
		printk(KERN_ERR "Fail to send Ethernet LRO timeout\n");
		return rc;
	}
	priv->lro.timeout_ms = timeoutms;
	ENET_DEBUG_LRO("LRO timeout %d\n", timeoutms);
	return 0;
}

int apm_enet_lro_set_maxbytecnt(struct apm_enet_dev_base *priv, u32 maxbytecnt)
{
	int rc;
	struct ipp_lro_message ipp_lro;

	/* Send byte count to SlimPRO */
	ipp_lro.cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_LRO_TYPE,
			IPP_LRO_BYTECNT, priv->port_id, 0);
	ipp_lro.val = maxbytecnt;
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, &ipp_lro,
			sizeof(ipp_lro), NULL);
	if (rc) {
		printk(KERN_ERR "Fail to send Ethernet LRO max byte\n");
		return rc;
	}
	priv->lro.max_byte_cnt = maxbytecnt;
	ENET_DEBUG_LRO("LRO max byte %d\n", maxbytecnt);
	return 0;
}

static int apm_enet_lro_set_queue(struct apm_enet_dev_base *priv)
{
	int rc;
	struct ipp_lro_qm_sys_wq *qm_sys = &priv->lro.qm_sys;
	struct ipp_lro_qm_src_fp *qm_src = &priv->lro.qm_src;
	struct ipp_lro_qm_dst_fp *qm_dst = &priv->lro.qm_dst;

	qm_sys->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_LRO_TYPE,
			IPP_LRO_QM_SYS_WQ, priv->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, qm_sys, sizeof(*qm_sys),
				NULL);
	if (rc) {
		printk(KERN_ERR "Fail to send QM System Work queue\n");
		return rc;
	}

	qm_src->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_LRO_TYPE,
			IPP_LRO_QM_SRC_FP, priv->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, qm_src, sizeof(*qm_src),
				NULL);
	if (rc) {
		printk(KERN_ERR "Fail to send QM Source Free Pool queue\n");
		return rc;
	}

	qm_dst->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_LRO_TYPE,
			IPP_LRO_QM_DST_FP, priv->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, qm_dst, sizeof(*qm_dst),
				NULL);
	if (rc) {
		printk(KERN_ERR "Fail to send QM Destination Free Pool queue\n");
		return rc;
	}

	return 0;
}

static int apm_enet_lro_fill_fp(int queue_id, int buffer_size)
{
	u16 BufDataLen;
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	struct sk_buff *skb;
	u8 *skb_data;
	phys_addr_t data_addr;
	u32 data_len = (buffer_size - (2 * NET_SKB_PAD) -
		SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	u32 *skb_addr;
	u32 skb_offset = (buffer_size - NET_IP_ALIGN - (2 * NET_SKB_PAD));

	fp_msg_desc.msg = &msg;
	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = 0;

	skb = dev_alloc_skb(data_len);
	if (unlikely(!skb)) {
		printk(KERN_ERR "Failed to allocate new skb size %d\n",
			buffer_size);
		return -ENOMEM;
	}
	skb_reserve(skb, NET_IP_ALIGN);
	skb_data = skb->data;
	data_len = data_len - NET_IP_ALIGN;
	BufDataLen = apm_qm_encode_bufdatalen(data_len);

	/* Convert to physical address */
	data_addr = virt_to_phys(skb_data);

	/* Program individual WORD to avoid use of memzero */
	((u32 *) &msg)[0] = (apm_enet_pkt_iscoherent() << 23) |
				(BufDataLen << 8) |
				(u32) (data_addr >> 32);
	((u32 *) &msg)[1] = (u32) data_addr;
	((u32 *) &msg)[2] = (APM_QM_LRO_RTYPE << 24) | queue_id;
	((u32 *) &msg)[3] = (u32) skb;

	skb_addr = (u32 *)&skb_data[skb_offset];
	*skb_addr = (u32)skb;

#if defined(CONFIG_NOT_COHERENT_CACHE)
	flush_dcache_range((u32) skb_addr, (u32) skb_addr + sizeof(void *));
#if !defined(CONFIG_APM86xxx_IOCOHERENT)
	invalidate_dcache_range((u32) skb_data, (u32) skb_data + data_len);
#endif
#endif
	/* Fill with the new buffer address */
#if defined(QM_NON_ALTERNATE_ENQUEUE_FP)
	if (unlikely((apm_qm_fp_dealloc_buf_non_alt(&fp_msg_desc)) != 0)) {
#else
	if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
#endif
		kfree_skb(skb);
		printk(KERN_ERR "Can not replenish FP buffer\n");
		return -1;
	}

	return 0;
}

static int apm_enet_lro_get_queue(struct apm_enet_dev_base *priv)
{
	struct qm_cfg_qconfig qconfig;
	u16 core = lro_work_domain;
	int rc = 0;
	struct dma_chan_info dma_info;
	int i;
	struct slimpro_queue *slimpro_q;
	struct apm_qm_qstate qstate = {0};
	int dma_asm_qid = QM_CFG_INVALID;

	/* Allocate SlimPRO Rx work queue */
	slimpro_q = slimpro_queue_request(NULL);
	if (slimpro_q == NULL) {
		rc = -ENODEV;
		printk(KERN_ERR LROID
			"Failed to retrieve SlimPRO offload work queue\n");
		goto done;
	}

	priv->lro.qm_sys.seg_rx_qid = slimpro_q->wqid;
	priv->lro.qm_sys.seg_rx_mbid = slimpro_q->mbox;
	priv->lro.qm_sys.seg_rx_pbn = slimpro_q->pbn;

	/* Assign DMA work queue for assembling packets */
	apm_pktdma_get_total_chan(&dma_info);
	for (i = 0; i < dma_info.max_chan; i++) {
		if (apm_qm_alt_enqueue_enable() && dma_info.chan_rsvd[i]) {
			dma_asm_qid = apm_pktdma_chan2qid(dma_info.chan_en[i],
						IODMA_DEFAULT_COS);
			ENET_DEBUG_LRO("LRO DMA channel %d\n",
					dma_info.chan_en[i]);
			break;
		}
	}
	if (dma_asm_qid == QM_CFG_INVALID) {
		/* Pick whichever channel is available */
		for (i = (dma_info.max_chan - 1); i >= 0; i--) {
			if (dma_info.chan_en[i] == i) {
				dma_asm_qid = apm_pktdma_chan2qid(
						dma_info.chan_en[i],
						IODMA_DEFAULT_COS);
				ENET_DEBUG_LRO("LRO DMA channel %d\n",
						dma_info.chan_en[i]);
				break;
			}
		}
	}

	if (dma_asm_qid == QM_CFG_INVALID) {
		printk(KERN_ERR "no DMA reserve queue for SlimPRO LRO\n");
		rc = -ENODEV;
		goto done;

	}

	priv->lro.qm_sys.dma_asm_qid = dma_asm_qid;
	apm_qm_qstate_rd(IP_BLK_QM, dma_asm_qid, &qstate);
	priv->lro.qm_sys.dma_asm_mbid = qstate.mb_id;
	priv->lro.qm_sys.dma_asm_pbn = qstate.pbn;

	/* Assign PPC Rx work queue */
	priv->lro.qm_sys.lro_rx_qid = priv->qm_queues[core].rx[0].qid;
	priv->lro.qm_sys.lro_rx_mbid = priv->qm_queues[core].rx[0].mbox;
	priv->lro.qm_sys.lro_rx_pbn = priv->qm_queues[core].rx[0].pbn;

	/* CLE Splits Single MTU paclet into Ethernet MAC/IP/TCP Header & Ethernet TCP Data */
	/* Allocate a commaon free pool for Ethernet MAC/IP/TCP Header & Ethernet TCP Data */
	memset(&qconfig, 0, sizeof(qconfig));
	qconfig.qid   = QM_CFG_INVALID;
	qconfig.ip    = IP_BLK_QM;
	qconfig.dev   = IP_ETH0 + priv->port_id;
	qconfig.ppc   = core;
	qconfig.dir   = QM_CFG_DIR_EGRESS;
	qconfig.qsize = QM_CFG_QSIZE_512KB;
	qconfig.thr   = 1;
	qconfig.qtype = QM_CFG_QTYPE_FP;
	if ((rc = qm_cfg_add_qconfig(&qconfig))) {
		printk(KERN_ERR LROID
			"Failed to configure common Ethernet MAC/IP/TCP header & TCP Data FP queue\n");
		goto done;
	}

	priv->lro.qm_src.seg_fp_qid = qconfig.qid;
	priv->lro.qm_src.seg_fp_mbid = qconfig.mbox;
	priv->lro.qm_src.seg_fp_pbn = qconfig.pbn;
	priv->lro.qm_src.seg_BufDataLen =
		apm_qm_encode_bufdatalen(SEG_BUF_SIZE -
		NET_IP_ALIGN - (2 * NET_SKB_PAD) -
                SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));

	/* Fill pool with buffer */
	for (i = 0; i < APM_SEG_PKT_BUF; i++) {
		if ((rc = apm_enet_lro_fill_fp(priv->lro.qm_src.seg_fp_qid, SEG_BUF_SIZE)) != 0) {
			printk(KERN_ERR LROID
				"Failed to fill common Ethernet MAC/IP/TCP header & TCP Data FP queue\n");
			goto done;
		}
	}

	/* Allocate free pool for Ethernet Single Packet */
	memset(&qconfig, 0, sizeof(qconfig));
	qconfig.qid   = QM_CFG_INVALID;
	qconfig.ip    = IP_BLK_QM;
	qconfig.dev   = IP_DMA;
	qconfig.ppc   = core;
	qconfig.dir   = QM_CFG_DIR_EGRESS;
	qconfig.qsize = QM_CFG_QSIZE_64KB;
	qconfig.thr   = 1;
	qconfig.qtype = QM_CFG_QTYPE_FP;
	if ((rc = qm_cfg_add_qconfig(&qconfig))) {
		printk(KERN_ERR LROID
			"Failed to configure Ethernet Single Packet FP queue\n");
		goto done;
	}

	priv->lro.qm_dst.one_fp_qid = qconfig.qid;
	priv->lro.qm_dst.one_fp_mbid = qconfig.mbox;
	priv->lro.qm_dst.one_fp_pbn = qconfig.pbn;
	priv->lro.qm_dst.one_BufDataLen =
		apm_qm_encode_bufdatalen(ONE_BUF_SIZE -
		NET_IP_ALIGN - (2 * NET_SKB_PAD) -
                SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));

	/* Fill pool with buffer */
	for (i = 0; i < APM_LRO_PKT_BUF; i++) {
		if ((rc = apm_enet_lro_fill_fp(priv->lro.qm_dst.one_fp_qid, ONE_BUF_SIZE)) != 0) {
			printk(KERN_ERR LROID
				"Failed to fill Ethernet Single Packet FP queue\n");
			goto done;
		}
	}

	/* Allocate free pool for Ethernet LRO Packet */
	memset(&qconfig, 0, sizeof(qconfig));
	qconfig.qid   = QM_CFG_INVALID;
	qconfig.ip    = IP_BLK_QM;
#ifdef LRO_DMA_SINGLE_DST_BUF
	qconfig.dev   = IP_DMA;
#else
	qconfig.dev   = IP_IPP;
#endif
	qconfig.ppc   = core;
	qconfig.dir   = QM_CFG_DIR_EGRESS;
	qconfig.qsize = QM_CFG_QSIZE_64KB;
	qconfig.thr   = 1;
	qconfig.qtype = QM_CFG_QTYPE_FP;
	if ((rc = qm_cfg_add_qconfig(&qconfig))) {
		printk(KERN_ERR LROID
			"Failed to configure Ethernet LRO Packet FP queue\n");
		goto done;
	}

	priv->lro.qm_dst.lro_fp_qid = qconfig.qid;
	priv->lro.qm_dst.lro_fp_mbid = qconfig.mbox;
	priv->lro.qm_dst.lro_fp_pbn = qconfig.pbn;
	priv->lro.qm_dst.lro_BufDataLen =
		apm_qm_encode_bufdatalen(LRO_BUF_SIZE -
		NET_IP_ALIGN - (2 * NET_SKB_PAD) -
                SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));

	/* Fill pool with buffer */
	for (i = 0; i < APM_LRO_PKT_BUF; i++) {
		if ((rc = apm_enet_lro_fill_fp(priv->lro.qm_dst.lro_fp_qid, LRO_BUF_SIZE)) != 0) {
			printk(KERN_ERR LROID
				"Failed to fill Ethernet LRO Packet FP queue\n");
			goto done;
		}
	}

	ENET_DEBUG_LRO("QM: ENET %d\n"
		"Segment RX QID %d MBID %d PBN %d\n"
		"DMA Assembler QID %d MBID %d PBN %d\n"
		"LRO RX QID %d MBID %d PBN %d\n"
		"TCPIPMAC HDR FP QID %d MBID %d PBN %d ENC_LEN %08x\n"
		"TCP PAYLOAD FP QID %d MBID %d PBN %d ENC_LEN %08x\n"
		"ONE PACKET FP QID %d MBID %d PBN %d ENC_LEN %08x\n"
		"LRO PACKET FP QID %d MBID %d PBN %d ENC_LEN %08x\n",

		priv->port_id,

		priv->lro.qm_sys.seg_rx_qid,
		priv->lro.qm_sys.seg_rx_mbid,
		priv->lro.qm_sys.seg_rx_pbn,

		priv->lro.qm_sys.dma_asm_qid,
		priv->lro.qm_sys.dma_asm_mbid,
		priv->lro.qm_sys.dma_asm_pbn,

		priv->lro.qm_sys.lro_rx_qid,
		priv->lro.qm_sys.lro_rx_mbid,
		priv->lro.qm_sys.lro_rx_pbn,

		priv->lro.qm_src.seg_fp_qid,
		priv->lro.qm_src.seg_fp_mbid,
		priv->lro.qm_src.seg_fp_pbn,
		priv->lro.qm_src.seg_BufDataLen,

		priv->lro.qm_src.seg_fp_qid,
		priv->lro.qm_src.seg_fp_mbid,
		priv->lro.qm_src.seg_fp_pbn,
		priv->lro.qm_src.seg_BufDataLen,

		priv->lro.qm_dst.one_fp_qid,
		priv->lro.qm_dst.one_fp_mbid,
		priv->lro.qm_dst.one_fp_pbn,
		priv->lro.qm_dst.one_BufDataLen,

		priv->lro.qm_dst.lro_fp_qid,
		priv->lro.qm_dst.lro_fp_mbid,
		priv->lro.qm_dst.lro_fp_pbn,
		priv->lro.qm_dst.lro_BufDataLen);

done:
	return rc;
}

int apm_enet_lro_init(struct apm_enet_dev_base *priv)
{
	struct apm_enet_lro_ctx	*lro_ctx = &priv->lro;

	if (lro_ctx->enable)
		goto _ret_enet_lro_init;

	if (lro_ctx->init_done) {
		apm_enet_lro_enable(priv, 1);
		goto _ret_enet_lro_init;
	}

#ifdef CONFIG_SMP
	lro_work_domain = 0;
#else
	lro_work_domain = apm_processor_id();
#endif

	lro_ctx->max_byte_cnt = LRO_ASM_BYTE;	/* Default 64240 */
	lro_ctx->timeout_ms = LRO_TIME_OUT;	/* Default is 10ms */

	apm_enet_lro_get_queue(priv);
	apm_enet_lro_set_queue(priv);
	apm_enet_lro_set_maxbytecnt(priv, priv->lro.max_byte_cnt);
	apm_enet_lro_set_timeout(priv, priv->lro.timeout_ms);
	apm_ipp_lro_offload_enable(priv->ndev);
	lro_ctx->enable = 1;
	lro_ctx->init_done = 1;

	printk(KERN_INFO "APM86xxx LRO initialized for %s interface\n",
			priv->ndev->name);

_ret_enet_lro_init:
	return 0;
}

int apm_enet_lro_rx_frame(struct apm_qm_msg_desc *rx_msg_desc)
{
	struct apm_enet_dev_base *priv_dev;
	struct apm_qm_msg32 *msg = (struct apm_qm_msg32 *) rx_msg_desc->msg;
	struct apm_qm_msg16 *msg16 = &msg->msg16;
	struct sk_buff *skb;
	u8 *skb_data;
	phys_addr_t data_addr;
	u32 data_len, buffer_size;
	u32 *skb_addr;
	u32 skb_offset;
	u8 queue_id;

	priv_dev = apm_enet_get_qidctx(rx_msg_desc->qid);
	data_len = msg16->UserInfo;
	data_addr = ((u64) msg16->DataAddrMSB << 32) | msg16->DataAddrLSB;
	queue_id = msg16->FPQNum;
	if (queue_id == priv_dev->lro.qm_dst.one_fp_qid) {
		buffer_size = ONE_BUF_SIZE;
	} else {
#ifdef LRO_DMA_SINGLE_DST_MEM
		queue_id = priv_dev->lro.qm_dst.lro_fp_qid;
#endif
		buffer_size = LRO_BUF_SIZE;
	}

	if (unlikely(!data_addr)) {
		printk(KERN_ERR "DataAddr NULL\n");
		print_hex_dump(KERN_INFO, "LRO msg: ",
				DUMP_PREFIX_ADDRESS, 16, 4, msg, 32, 1);
		return 0;
	}

	skb_offset = (buffer_size - NET_IP_ALIGN - (2 * NET_SKB_PAD));

	if (unlikely(data_len == 0 ||
			data_len > (skb_offset -
			SKB_DATA_ALIGN(sizeof(struct skb_shared_info))))) {
		printk(KERN_ERR "Corrupt data_len %d\n", data_len);
		print_hex_dump(KERN_INFO, "LRO msg: ",
				DUMP_PREFIX_ADDRESS, 16, 4, msg, 32, 1);
		return 0;
	}

	/* Get address of skb_data and skb from skb_data */
	skb_data = phys_to_virt(data_addr);
	skb_addr = (u32 *)&skb_data[skb_offset];
	skb = (struct sk_buff *)*skb_addr;

	if (unlikely(skb_data != skb->data)) {
		printk(KERN_ERR "Corrupt skb_data %p or encoded skb_data %p\n",
				skb_data, skb->data);
		print_hex_dump(KERN_INFO, "LRO msg: ",
				DUMP_PREFIX_ADDRESS, 16, 4, msg, 32, 1);
		return 0;
	}

	/* alloc one new skb in ONE FP or LRO FP */
	apm_enet_lro_fill_fp(queue_id, buffer_size);

	skb_put(skb, data_len);

	/* specify tcp checksum is unnecessary */
#if defined(CONFIG_APM_QOS)
	/* Work-around to bug 27737: NAS write fail with l7-filter of APM QoS
	 * l7-filter sets rule to PREROUTING xtables. Matching traffic traverses
	 * through NFQUEUE for further processing.
	 * NFQUEUE somehow does handling the queued packet. In case of APM QoS,
	 * setting to CHECKSUM_PARTIAL can help NFQUEUE work */
	/* At system perspective, there is chance offloading traffic traverse
	 * through ADVANCED_LINUX_TRAFFIC_CONTROL (e.g. traffic control
	 * framework built on router).
	 * There might be work to fix upper layer (e.g. xtables and
	 * intermediate queues) or LRO.
	 * Mark the fix as work-around */
	skb->ip_summed = CHECKSUM_PARTIAL;
#else
	skb->ip_summed = CHECKSUM_UNNECESSARY;
#endif
	skb->protocol = eth_type_trans(skb, priv_dev->ndev);

	/* Update ip header checksum */
	ip_send_check((struct iphdr *)skb->data);

	/* Send to upper layers */
	netif_receive_skb(skb);

	return 0;
}
#endif
