/**
 * APM APM86xxx virtual ethernet for inter-core communication
 *
 * Copyright (c) 2010, Applied Micro Circuits Corporation
 * Author: Loc Ho <lho@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 */
#include <linux/types.h>
#include <linux/string.h>
#include "../../../arch/powerpc/boot/stdio.h"
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <net/ip.h>
#include <asm/cacheflush.h>
#include <asm/apm_pktdma.h>
#include <asm/apm_qm_access.h>
#define IOS_INTERWORKING
#include <asm/apm_pktdma_core.h>
#include <asm/mpic.h>
#include "apm_enet_tools.h"
#include "apm_vnet.h"


#define VNET_USE_LMSG_Q
#undef VNET_USE_GEN_COMP_QUEUE

#undef VNET_DEBUGTX
#undef VNET_DEBUGRX
#undef VNET_DEBUG2
#undef VNET_DEBUG_DUMP

#if defined(VNET_DEBUG)
#define VNETD(fmt, ...)		printk(KERN_INFO PFX fmt "\n", ##__VA_ARGS__);
#else
#define VNETD(fmt, ...)
#endif

#if defined(VNET_DEBUGRX)
#define VNETDRX(fmt, ...)	printk(KERN_INFO PFX fmt "\n", ##__VA_ARGS__);
#else
#define VNETDRX(fmt, ...)
#endif

#if defined(VNET_DEBUGTX)
#define VNETDTX(fmt, ...)	printk(KERN_INFO PFX fmt "\n", ##__VA_ARGS__);
#else
#define VNETDTX(fmt, ...)
#endif

#if defined(VNET_DEBUG2)
#define VNETD2(fmt, ...)	printk(KERN_INFO PFX fmt "\n", ##__VA_ARGS__);
#else
#define VNETD2(fmt, ...)
#endif

#if defined(VNET_DEBUG_DUMP)
#define VNET_DUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
	} while(0);
#else
#define VNET_DUMP(hdr, fmt, ...)
#endif

struct vnet_skb_cb {
	struct apm_vnet_priv_dev *ctx;
	u32 UserInfo;
	u32 frags;
};

struct vnet_single_skb_cb {
	struct vnet_skb_cb info;
	u64 sa;
	u64 da;
	u16 cnt;
};
#define VNET_SINGLE_SKB_CB(__skb) 	\
		((struct vnet_single_skb_cb *)&((__skb)->cb[0]))

struct vnet_multi_skb_cb {
	struct vnet_skb_cb info;
	u64 *sa;
	u64 *da;
	u16 *cnt;
};
#define VNET_MULTI_SKB_CB(__skb) 	\
		((struct vnet_multi_skb_cb *)&((__skb)->cb[0]))

int apm_vnet_dma_callback(struct apm_pktdma_op_result *);

/* Reverse look up from virtual port to private context */
#define APM_VNET_MAX_PORT		16
struct apm_vnet_priv_dev *port2priv[APM_VNET_MAX_PORT];

static int apm_vnet_map_cpu2ip(int cpuid)
{
	switch (cpuid) {
	case 0:
	default:
		return IP_PPC0;
	case 1:
		return IP_PPC1;
	}
}

static int apm_vnet_queue_free_skb(struct apm_vnet_priv_dev *ctx,
				struct sk_buff *skb)
{
	unsigned long flags = 0;
	struct vnet_percpu_data *percpu_data = NULL;
	int cpu = get_cpu();

	percpu_data = (struct vnet_percpu_data *)
					per_cpu_ptr(ctx->percpu_ptr, cpu);
	spin_lock_irqsave(&percpu_data->lock, flags);
	if (percpu_data->to_free_skb == NULL) {
		percpu_data->to_free_skb = skb;
		skb->next = NULL;
	} else {
		skb->next = percpu_data->to_free_skb;
		percpu_data->to_free_skb = skb;
	}
	spin_unlock_irqrestore(&percpu_data->lock, flags);
	tasklet_schedule(&percpu_data->rx_tasklet);
	return 0;
}

void apm_free_skb(void *skb) {

    struct apm_vnet_priv_dev *ctx = NULL;
    ctx = port2priv[0];
    apm_vnet_queue_free_skb(ctx, skb);
}

static int apm_vnet_rx_frame(struct apm_qm_msg_desc *rx_msg_desc)
{
	struct apm_qm_msg32 *msg = (struct apm_qm_msg32 *) rx_msg_desc->msg;
	struct apm_qm_msg16 *msg16 = &msg->msg16;
	struct apm_vnet_priv_dev *ctx = NULL;
	struct sk_buff *skb = NULL;
	struct apm_pktdma_m2m_params m2m;
	struct apm_qm_msg_desc msg_desc;
	int rc;
        static int lastchan = 0; /* this must be 0, as 1st chan is not rsvd */

        memset((void*)&m2m, 0, sizeof(m2m));
        memset((void*)&msg_desc, 0, sizeof(msg_desc));

	VNETDRX("RX msg QID %d MBID %d RTYPE %d Port %d",
		rx_msg_desc->qid, rx_msg_desc->mb_id, msg16->RType,
		msg16->FPQNum);

	/* Look up net device with this MB ID */
	ctx = port2priv[msg16->FPQNum];
	if (ctx == NULL) {
#ifdef VNET_DEBUGRX
		printk(KERN_ERR "no context for new frame\n");
#endif
		return -EINVAL;
	}

	if (unlikely(msg16->LErr)) {
		pr_err(PFX "error %d QID %d\n", msg16->LErr, rx_msg_desc->qid);
		msg16->LErr = 0;
		skb = NULL;
		goto err_done;
	}

	if (msg16->DataAddrLSB == 0 && msg16->DataAddrMSB == 0) {
		/* Operation completed, free the skb */
		struct sk_buff *skb =
                    (struct sk_buff *)apm_pktdma_find_op(msg16->UserInfo);
                if (skb == NULL) {
                    VNETDRX("IOS returned index is invalid: %x\n",
                            msg16->UserInfo);
                    return 0;
                }
		VNETDRX("RX frame accepted skb 0x%p", skb);
		VNETDRX("LTX.2: (%p) frame accepted\n", skb);
		atomic_dec(&ctx->remote_inflight);
		apm_vnet_queue_free_skb(ctx, skb);
		return 0;
	}

	if (msg16->BufDataLen > VNET_MAX_FRAME) {
		/* drop over size frame */
		printk(KERN_ERR "frame over size %d\n", msg16->BufDataLen);
		skb = NULL;
		goto err_done;
	}

	/* Allocate new SKB for this new frame */
	skb = netdev_alloc_skb(ctx->ndev, msg16->BufDataLen);
	if (skb == NULL) {
		/* Out of memory, drop frame */
		printk(KERN_ERR "no memory for new frame length %d\n",
			msg16->BufDataLen);
		goto err_done;
	}
	if (skb_shinfo(skb)->nr_frags != 0) {
            printk("netdev_alloc_skb allocated %u fragments",
                   skb_shinfo(skb)->nr_frags);
        }

	if (!msg16->NV) {
		/* Single fragment SKB */
		struct vnet_single_skb_cb *vnetcb = VNET_SINGLE_SKB_CB(skb);
		vnetcb->sa = ((u64) msg16->DataAddrMSB << 32) |
				msg16->DataAddrLSB;
		vnetcb->da = __pa(skb->data);
		vnetcb->cnt = msg16->BufDataLen;
		vnetcb->info.ctx = ctx;
		vnetcb->info.UserInfo = msg16->UserInfo;
		vnetcb->info.frags = 1;

		m2m.sa = &vnetcb->sa;
		m2m.da = &vnetcb->da;
		m2m.m2m_mode = IODMA_COPY;
		m2m.byte_count = &vnetcb->cnt;

#if defined(CONFIG_NOT_COHERENT_CACHE)
                flush_dcache_range((u32)vnetcb,
                                   (u32)(((char *)vnetcb) + sizeof(vnetcb)));
#endif

		VNETDRX("RX frame len %d", msg16->BufDataLen);
	} else {
		/* Multiple fragments SKB is un-supported */
		printk(KERN_ERR "un-support multiple fragments\n");
		goto err_done;
	}

	m2m.chid = ctx->dmach.chan_en[lastchan];
        if (!ctx->dmach.chan_rsvd[1 - lastchan]) {
            /* if other chan is not reserved, do round robin */
            lastchan = 1 - lastchan;
        }
	m2m.cb = apm_vnet_dma_callback;
	m2m.context = (void *)apm_pktdma_add_op(skb, apm_free_skb);
        VNETDRX("LRX.1: (%x, %p) msg received\n", msg16->UserInfo, skb);
	VNETDRX("RX frame DMA chan %d skb 0x%p", m2m.chid, skb);
	if (unlikely((rc = apm_pktdma_m2m_xfer(&m2m)) < 0)) {
		printk(KERN_ERR "unable to submit DMA operation error %d\n",
			rc);
		goto err_done;
	}

	return 0;

err_done:
	++ctx->estats.tx_dropped_error;
	if (skb)
		apm_vnet_queue_free_skb(ctx, skb);

	/* Notify other side operation completed */
	msg16->DataAddrMSB = msg16->DataAddrLSB = 0;
	msg_desc.qid = ctx->remote_qid;
	msg_desc.msg = rx_msg_desc->msg;
        rc = apm_qm_push_msg(&msg_desc);
	if (rc < 0) {
		printk(KERN_ERR
			"fail to notify remote side QID %d error %d\n",
			ctx->remote_qid, rc);
		return rc;
	}
	return 0;
}

static void apm_vnet_bh_tasklet_cb(unsigned long data)
{
	struct vnet_percpu_data *percpu_data = NULL;
	struct apm_vnet_priv_dev *ctx = NULL;
	struct sk_buff *skb = NULL;
	unsigned long flags = 0;
	int cpu = 0;
        int lockup_cnrtr = 10000;

	ctx = (struct apm_vnet_priv_dev *) data;
	cpu = get_cpu();
	percpu_data = (struct vnet_percpu_data *)
				per_cpu_ptr(ctx->percpu_ptr, cpu);

	/* Process completed pending operation */
	spin_lock_irqsave(&percpu_data->lock, flags);


	while (percpu_data->to_free_skb) {
		skb = percpu_data->to_free_skb;

		percpu_data->to_free_skb = skb->next;

		spin_unlock_irqrestore(&percpu_data->lock, flags);

		kfree_skb(skb);
		spin_lock_irqsave(&percpu_data->lock, flags);

                if (0 == lockup_cnrtr--) {
                    printk(KERN_INFO PFX "%s:%d:ERROR lockup\n", __FILE__, __LINE__);
                    break;
                }
	}
	spin_unlock_irqrestore(&percpu_data->lock, flags);
}

int apm_vnet_dma_callback(struct apm_pktdma_op_result *pktdma_result)
{
	struct sk_buff *skb = NULL;
	struct apm_qm_msg_desc msg_desc;
	struct apm_qm_msg_up8 *msg8_1 = NULL;
	struct apm_qm_msg16 *msg16 = NULL;
	struct apm_qm_msg32 msg;
	struct apm_vnet_priv_dev *ctx = NULL;
	struct vnet_skb_cb *vnetcb = NULL;
	int rc;
	int len;

	memset((void*)&msg, 0, sizeof(msg));
	memset((void*)&msg_desc, 0, sizeof(msg_desc));
	msg16 = &msg.msg16;
	msg8_1 = &msg.msgup8_1;
	msg16->RType = APM_QM_VENET_RTYPE;
#if !defined(CONFIG_NOT_COHERENT_CACHE)
	msg16->C = 1;			/* Enable coherency */
#endif
	/* Extract the SKB */
	skb = apm_pktdma_find_op((int)pktdma_result->ctx);
        if (skb == NULL) {
		printk(KERN_ERR "DMA operation with NULL context\n");
		return 0;
	}

        vnetcb = (struct vnet_skb_cb *) VNET_SINGLE_SKB_CB(skb);
	ctx = vnetcb->ctx;
	if (ctx == NULL) {
		printk(KERN_ERR "DMA operation encode NULL context\n");
		return 0;
	}

	if (vnetcb->frags == 1) {
		struct vnet_single_skb_cb *vnetcbs;
		vnetcbs = (struct vnet_single_skb_cb *) VNET_SINGLE_SKB_CB(skb);

#if defined(CONFIG_NOT_COHERENT_CACHE)
                invalidate_dcache_range((u32) (skb->data),
                                        (u32)(((char *)(skb->data)) + vnetcbs->cnt));
#endif

		msg16->UserInfo = vnetcbs->info.UserInfo;
		if (pktdma_result->err){
                        printk("Pktdma error %x\n", pktdma_result->err);
			goto op_failed;
                }
		len = vnetcbs->cnt;
		skb_put(skb, vnetcbs->cnt);
                VNETDRX("LRX.2: (%p) DMA operation done\n", skb);

                VNETDRX("RX frame DMA done skb 0x%p len %d", skb, len);
		VNET_DUMP("RX: ", skb->data, skb->len);
	} else {
		/* Do not support multiple fragments */
                printk("Pktdma error, multiple frags \n");
		goto op_failed;
	}

	skb->protocol = eth_type_trans(skb, ctx->ndev);
#ifdef IPV4_RX_CHKSUM
	if (likely(skb->protocol == htons(ETH_P_IP))) {
		struct iphdr *iph = (struct iphdr *) skb->data;
		if (likely(!(iph->frag_off & htons(IP_MF | IP_OFFSET)))) {
			if (likely(iph->protocol == IPPROTO_TCP ||
					iph->protocol == IPPROTO_UDP))
				skb->ip_summed = CHECKSUM_UNNECESSARY;
		}
	}
#endif
	if (in_irq()) {
		if (unlikely(netif_rx(skb) == NET_RX_DROP))
			++ctx->estats.rx_dropped_stack;
	} else {
		netif_receive_skb(skb);
	}

	++ctx->stats.rx_packets;
	ctx->stats.rx_bytes += len;

notify:
	/* Notify remote side frame received */
	msg_desc.qid = ctx->remote_qid;
	msg_desc.msg = &msg;
	VNETDRX("RX frame notify complete UserInfo 0x%08X", msg16->UserInfo);
        VNETDRX("LRX.3: (%p) notify other side\n", skb);
	rc = apm_qm_push_msg(&msg_desc);
	if (rc < 0) {
		printk(KERN_ERR "fail to notify remote side %d\n", rc);
		return rc;
	}
	return 0;

op_failed:
        printk("DMA op failed ctx:%p\n", pktdma_result->ctx);
	++ctx->estats.tx_dropped_error;
	kfree_skb(skb);
	goto notify;
}

#define APM_VNET_INTERNAL_IP_PROT 253

typedef enum apm_intercore_type {
	APM_INTERCORE_MSG_FLASH,
        APM_INTERCORE_MSG_DFLT
} apm_intercore_type_e;

typedef struct apm_intercore_msg {
	 apm_intercore_type_e type;   /* Message type to demux on */
	 u8 len;                   /* Length of data to send */
	 u8 value[500];            /* Max 500 bytes can be sent */
} apm_intercore_msg_t;

static int apm_vnet_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	struct apm_vnet_priv_dev *ctx = NULL;
	struct apm_qm_msg_desc msg_desc;
	struct apm_qm_msg_up8 *msg8_1 = NULL;
	struct apm_qm_msg16 *msg16 = NULL;
	struct apm_qm_msg64 msg64;
	int nr_frags = skb_shinfo(skb)->nr_frags;
	int rc;
	u64 paddr;
	VNETDRX("LTX.1 (%p) send\n", skb);
        memset((void*)&msg_desc, 0, sizeof(msg_desc));
        memset((void*)&msg64, 0, sizeof(msg64));

        ctx = netdev_priv(ndev);

	/* Make sure there is space for this */
	if (atomic_inc_return(&ctx->remote_inflight) >= 2048) {
		/* Queue is close to full, indicate busy */
                printk("BUSY\n");
		atomic_dec(&ctx->remote_inflight);
		return NETDEV_TX_BUSY;
	}

	/* Prepare a control msg with data pointer to send to other side */

        msg_desc.qid = ctx->remote_qid;
	msg_desc.msg = &msg64;
	msg16 = &msg64.msg32_1.msg16;
	msg8_1 = &msg64.msg32_1.msgup8_1;

	if (likely(nr_frags == 0)) {
		memset(&msg64, 0, sizeof(msg64.msg32_1));
		msg16->BufDataLen = skb->len;
		paddr = virt_to_phys(skb->data);
		msg16->DataAddrMSB = (u32) (paddr >> 32);
		msg16->DataAddrLSB = (u32) paddr;
#if defined(CONFIG_NOT_COHERENT_CACHE)
		flush_dcache_range((u32) skb->data,
				(u32) (skb->data + skb->len));
#endif
		VNETDTX("TX xmit QID %d skb 0x%p len %d",
			msg_desc.qid, skb, skb->len);
		VNET_DUMP("VTX:", skb->data, skb->len);
	} else {
                printk("Unsupported number of fragments\n");
		kfree_skb(skb);
		pr_err(PFX "Un-supported number of frags %d\n", nr_frags);
		return 0;
	}
#if !defined(CONFIG_NOT_COHERENT_CACHE)
	msg16->C = 1;			/* Enable coherency */
#endif
	msg16->UserInfo = (u32)apm_pktdma_add_op(skb, apm_free_skb);
	msg16->FPQNum = ctx->remote_port;
	msg16->RType = APM_QM_VENET_RTYPE;
	rc = apm_qm_push_msg(&msg_desc);
	if (unlikely(rc < 0)) {
                printk("VNET can't enqueue, rc = %u\n", rc);
		pr_err(PFX "Unable to queue msg to remote side\n");
		++ctx->estats.tx_dropped_error;
                apm_pktdma_find_op(msg16->UserInfo);
		kfree_skb(skb);
		return 0;
	}

	ctx->ndev->trans_start = jiffies;
	++ctx->stats.tx_packets;
	ctx->stats.tx_bytes += skb->len;
	return 0;
}

struct net_device_stats *apm_vnet_stats(struct net_device *ndev)
{
	struct apm_vnet_priv_dev *priv_dev = netdev_priv(ndev);
	struct net_device_stats *nst = &priv_dev->nstats;
	struct apm_vnet_stats *st = &priv_dev->stats;

	nst->rx_packets = (unsigned long) st->rx_packets;
	nst->rx_bytes = (unsigned long) st->rx_bytes;
	nst->tx_packets = (unsigned long) st->tx_packets;
	nst->tx_bytes = (unsigned long) st->tx_bytes;
	nst->rx_dropped = (unsigned long) priv_dev->estats.rx_dropped;
	nst->tx_dropped = (unsigned long) priv_dev->estats.tx_dropped;
	nst->rx_errors = (unsigned long) priv_dev->estats.rx_dropped_error;
	nst->tx_errors = (unsigned long) priv_dev->estats.tx_dropped_error;

	return nst;
}

static void apm_vnet_down_link(struct apm_vnet_priv_dev *ctx)
{
	ctx->remote_link = 0;
}
#ifndef IOS_INTERWORKING
static irqreturn_t apm_vnet_irq(int irqno, void *ctx)
{
	int val = mpic_read_msg(irqno);
	struct xchng_qcfg *qcfg = (struct xchng_qcfg *) &val;
	struct apm_vnet_priv_dev *priv = (struct apm_vnet_priv_dev *) ctx;

	if (qcfg->src_core_id == mfspr(SPRN_PIR)) {
		VNETD("Ignore remote %d msg id %d raw 0x%08X",
			qcfg->src_core_id, qcfg->src_msg_id, val);
		return IRQ_HANDLED;
	}
	VNETD("Remote %d msg id %d raw 0x%08X", qcfg->src_core_id,
		qcfg->src_msg_id, val);

	if (qcfg->dying_core) {
		priv->remote_link = 0;
		return IRQ_HANDLED;
	}

	priv->remote_port = qcfg->port;
	priv->remote_link = 1;

	if (qcfg->ack) {
		struct xchng_qcfg qcfgtx;

		qcfgtx.dying_core = 0;
		qcfgtx.rsvd1 = 0;
		qcfgtx.rsvd2 = 0;
		qcfgtx.ack = 0;
		qcfgtx.src_msg_id = priv->local_msg_idx;
		qcfgtx.src_core_id = mfspr(SPRN_PIR);

		VNETD("Send response trigger %d core id %d msg 0x%08X",
			qcfg->src_msg_id, qcfg->src_core_id, *(u32 *) &qcfgtx);
		mpic_send_trigger(qcfg->src_msg_id, qcfg->src_core_id,
				*(u32 *) &qcfgtx);
	}
	return IRQ_HANDLED;
}
#endif

static int apm_vnet_open(struct net_device *ndev)
{
#ifndef IOS_INTERWORKING
	struct apm_vnet_priv_dev *ctx = netdev_priv(ndev);
	struct xchng_qcfg qcfg;

        memset((void*)&qcfg, 0, sizeof(qcfg));

        qcfg.dying_core = 0;
	qcfg.rsvd1 = 0;
	qcfg.rsvd2 = 0;
	qcfg.ack = 1;
	qcfg.port = ctx->port_id;
	qcfg.src_msg_id = ctx->local_msg_idx;
	qcfg.src_core_id = mfspr(SPRN_PIR);

	ctx->remote_link_start_ts = jiffies;

	VNETD("Send trigger to core id 0x%08X msg idx %d msg 0x%08X\n",
		ctx->remote_core_id, ctx->remote_msg_idx, *(u32 *) &qcfg);
	mpic_send_trigger(ctx->remote_msg_idx, ctx->remote_core_id,
			*(u32 *) &qcfg);
#endif
#if defined(CONFIG_NAPI)
        napi_enable(&ctx->napi);
#endif

        netif_start_queue(ndev);
	return 0;
}

static void apm_vnet_shutdown(struct platform_device *ofdev)
{
#ifndef IOS_INTERWORKING
	struct net_device *ndev = dev_get_drvdata(&ofdev->dev);
	struct apm_vnet_priv_dev *ctx = netdev_priv(ndev);
	struct xchng_qcfg qcfg;

        memset((void*)&qcfg, 0, sizeof(qcfg));
	apm_vnet_down_link(ctx);

	qcfg.dying_core = mfspr(SPRN_PIR) + 1; /* Core ID count from 1 */
	qcfg.rsvd1 = 0;
	qcfg.rsvd2 = 0;
	qcfg.ack = 0;
	qcfg.port = ctx->port_id;
	qcfg.src_msg_id = ctx->local_msg_idx;
	qcfg.src_core_id = mfspr(SPRN_PIR);

	VNETD("Send shutdown to core id 0x%08X msg idx %d msg 0x%08X\n",
		ctx->remote_core_id, ctx->remote_msg_idx,
		*(u32 *) &qcfg);
	mpic_send_trigger(ctx->remote_msg_idx, ctx->remote_core_id,
			*(u32 *) &qcfg);
#endif
	return;
}

static int apm_vnet_close(struct net_device *ndev)
{
#if defined(CONFIG_NAPI)
	struct apm_vnet_priv_dev *ctx = netdev_priv(ndev);

        napi_disable(&ctx->napi);
#endif
	netif_stop_queue(ndev);
	return 0;
}

static int apm_vnet_poll(struct napi_struct *napi, int budget)
{
#if defined(CONFIG_NAPI)
	int howmany = 0;
	struct apm_qm_msg_desc *rx_msg_desc = NULL;
	struct apm_vnet_priv_dev *ctx = NULL;

	ctx = container_of(napi, struct apm_vnet_priv_dev, napi);

	while (budget--) {
		if (unlikely(!howmany)) {
			VNETD2("Rx frame port %d", ctx->port_id);
			rx_msg_desc = &ctx->pending_fn_args;
			rx_msg_desc->msg = &ctx->napi_qm_msg;
			apm_vnet_rx_frame(rx_msg_desc);
		} else {
			VNETD2("Rx frame NAPI poll");
			if (apm_qm_pull_msg(rx_msg_desc) == -1) {
				napi_complete(napi);
				apm_qm_enable_mb_irq(rx_msg_desc->mb_id);
				return howmany;
			}
			apm_vnet_rx_frame(rx_msg_desc);
		}
		howmany++;
	}
	return howmany;
#else
	return 0;
#endif
}

static int apm_vnet_qconfig(struct apm_vnet_priv_dev *ctx)
{
	struct apm_qm_qstate *vnet_qs = NULL;
	struct apm_qm_qalloc vnet_qalloc;
	unsigned char id = mfspr(SPRN_PIR);
	int rc = 0;

        memset((void*)&vnet_qalloc, 0, sizeof(vnet_qalloc));
	vnet_qs = kzalloc(sizeof(struct apm_qm_qstate), GFP_KERNEL);
	if (!vnet_qs) {
		pr_err(PFX "No memory for vnet queues state\n");
		return -ENOMEM;
	}

	/* Allocate queue for Tx work to remote side */
	vnet_qalloc.qstates = vnet_qs;
	vnet_qalloc.ip_blk = apm_vnet_map_cpu2ip(id);
	vnet_qalloc.qm_ip_blk = IP_BLK_QM;
	vnet_qalloc.ppc_id = ctx->remote_qm_id;
	vnet_qalloc.q_type = P_QUEUE;
	vnet_qalloc.q_count = 1;
	vnet_qalloc.direction = DIR_EGRESS;
	vnet_qalloc.qsize = SIZE_64KB;
	vnet_qalloc.thr_set = 1;

#ifdef VNET_USE_LMSG_Q
        ctx->remote_qid = QM_10_MSG_L_QID;
#else
        /*
         * TODO: This should use the output physical queue for VNET
         * that shares the same vq as VCONS
         */
#ifdef VNET_USE_GEN_COMP_QUEUE
	/* Use general complete queue for now */
	{
		vnet_qs = apm_qm_get_compl_queue(IP_PPC0 + ctx->remote_qm_id,
						ctx->remote_core_id);
		if (vnet_qs == NULL)
			goto err;
		ctx->remote_qid = vnet_qs->q_id;
	}
#else
	if ((rc = apm_qm_alloc_q(&vnet_qalloc)) < 0) {
		pr_err(PFX "No room for egress queues\n");
		goto err;
	}
	ctx->remote_qid = vnet_qs->q_id;
#endif
	VNETD("Queue config IP blk %d PPC ID %d Direction %d QID %d MBID %d",
		vnet_qalloc.ip_blk, vnet_qalloc.ppc_id,
		vnet_qalloc.direction, vnet_qs->q_id, vnet_qs->mb_id);

err:
#if !defined(VNET_USE_GEN_COMP_QUEUE)
	kfree(vnet_qs);
#endif
#endif
	return rc;
}

static int apm_vnet_change_mtu(struct net_device *ndev, int new_mtu)
{
	if (new_mtu < 64 || new_mtu > (VNET_MAX_FRAME - VNET_FRAME_PAD)) {
		printk(KERN_ERR "Invalid MTU %d\n", new_mtu);
		return -EINVAL;
	}

	printk(KERN_INFO "changing MTU from %d to %d\n", ndev->mtu, new_mtu);
	ndev->mtu = new_mtu;
	return 0;
}

static const struct net_device_ops apm_vnet_ops = {
	.ndo_open = apm_vnet_open,
	.ndo_stop = apm_vnet_close,
	.ndo_start_xmit = apm_vnet_start_xmit,
	.ndo_get_stats = apm_vnet_stats,
	.ndo_change_mtu	= apm_vnet_change_mtu,
};

static int apm_vnet_probe(struct platform_device *ofdev)
{
	struct apm_vnet_priv_dev *ctx = NULL;
	const u32 *prop = NULL;
	const u8 *ethaddr = NULL;
	struct net_device *ndev = NULL;
	char vname[IFNAMSIZ] = {'\0'};
	int len;
	int rc = 0;

	/* Get device ID */
	prop = of_get_property(ofdev->dev.of_node, "devid", &len);
	if (!prop || len < sizeof(u32)) {
		dev_err(&ofdev->dev, "Can't get device id\n");
		return -EINVAL;
	}
	if (*prop > APM_VNET_MAX_PORT) {
		dev_err(&ofdev->dev, "max supported virtual port is %d\n",
			APM_VNET_MAX_PORT);
		return -EINVAL;
	}
	sprintf(vname, "%s%d", APM_VNET_NAME, *prop);

	/* Allocate net dev */
	ndev = alloc_netdev(sizeof(*ctx), vname, ether_setup);
	if (!ndev) {
		dev_err(&ofdev->dev, "Failed to allocate netdev\n");
		return -ENOMEM;
	}
	ctx = netdev_priv(ndev);
	ctx->ndev = ndev;
	ctx->port_id = *prop;
	port2priv[ctx->port_id] = ctx;	/* Save context for port look up */
        printk("------- VNET device ID: %u\n", ctx->port_id);

	prop = of_get_property(ofdev->dev.of_node, "remote-core-id", &len);
	if (!prop || len < sizeof(u32)) {
		dev_err(&ofdev->dev, "Can't get remote core id\n");
		free_netdev(ndev);
		return -EINVAL;
	}
	ctx->remote_core_id = *prop;

	prop = of_get_property(ofdev->dev.of_node, "remote-msg-idx", &len);
	if (!prop || len < sizeof(u32)) {
		dev_err(&ofdev->dev, "Can't get remote msg index\n");
		free_netdev(ndev);
		return -EINVAL;
	}
	ctx->remote_msg_idx = *prop;

	prop = of_get_property(ofdev->dev.of_node, "remote-qm-id", &len);
	if (!prop || len < sizeof(u32)) {
		dev_err(&ofdev->dev, "Can't get remote QM ID\n");
		free_netdev(ndev);
		return -EINVAL;
	}
	ctx->remote_qm_id = *prop;

	ctx->irq = of_irq_to_resource(ofdev->dev.of_node, 0, NULL);
	if (ctx->irq == NO_IRQ) {
                dev_err(&ofdev->dev, "no IRQ entry\n");
		rc = -EINVAL;
		goto irqerr;
	}
	ctx->local_msg_idx = ctx->irq - 116; /* Compute msg interrupt index */

	ctx->remote_link_start_ts = jiffies;
	ctx->remote_qid = 0;
	ctx->remote_link = 1;		/* Start off link in down state */
	atomic_set(&ctx->remote_inflight, 0);
	ctx->remote_port = 0;

	/* Configure Queue */
	if ((rc = apm_vnet_qconfig(ctx)) < 0) {
		dev_err(&ofdev->dev, "Failed to config QM\n");
		goto qerr;
	}

	/* Get list of DMA channel */
	apm_pktdma_get_total_chan(&ctx->dmach);

	ethaddr = (u8 *) of_get_property(ofdev->dev.of_node, "local-mac-address",
					&len);
	if (!ethaddr || len < ETH_ALEN) {
		dev_err(&ofdev->dev, "Can't get device's MAC address\n");
		rc = -EINVAL;
		goto macerr;
	}
	memcpy(ndev->dev_addr, ethaddr, ETH_ALEN);
	printk(KERN_INFO PFX "MAC %02x:%02x:%02x:%02x:%02x:%02x\n",
		ndev->dev_addr[0], ndev->dev_addr[1], ndev->dev_addr[2],
		ndev->dev_addr[3], ndev->dev_addr[4], ndev->dev_addr[5]);

	SET_NETDEV_DEV(ndev, &ofdev->dev);
	ndev->mtu = VNET_MAX_FRAME - VNET_FRAME_PAD;
	ndev->netdev_ops = &apm_vnet_ops;
	ndev->watchdog_timeo = 5 * HZ;
	netif_napi_add(ndev, &ctx->napi, apm_vnet_poll, APM_ENET_NAPI_WT);

#ifdef IPV4_TX_CHKSUM
	/* We enable IPv4 TCP/UDP hardware checksum as this is virtual
	   Ethernet and packet are reliable */
        ndev->features |= NETIF_F_IP_CSUM;
#endif
	if (register_netdev(ndev)) {
		dev_err(&ofdev->dev, "Failed to register net device!\n");
		rc = -EFAULT;
		goto regerr;
	}
	dev_set_drvdata(&ofdev->dev, ndev);

#ifndef IOS_INTERWORKING
	/* Register for IRQ */
	rc = request_irq(ctx->irq, apm_vnet_irq, 0, "vnet-msg", ctx);
	if (rc != 0) {
		dev_err(&ofdev->dev, "unable to register IRQ\n");
		goto irqerr;
	}
#endif
	apm_qm_msg_rx_register(APM_QM_VENET_RTYPE, apm_vnet_rx_frame);

	ctx->percpu_ptr = alloc_percpu(struct vnet_percpu_data);
	if (ctx->percpu_ptr) {
		struct vnet_percpu_data *percpu_data;
		int cpu;

		for_each_possible_cpu(cpu) {
			percpu_data = (struct vnet_percpu_data *)
					per_cpu_ptr(ctx->percpu_ptr, cpu);
			spin_lock_init(&percpu_data->lock);
			percpu_data->to_free_skb = NULL;
			tasklet_init(&percpu_data->rx_tasklet,
				apm_vnet_bh_tasklet_cb, (unsigned long) ctx);
		}
	} else {
		dev_err(&ofdev->dev, "per cpu ptr allocation failed");
	}

	VNETD("IRQ %d local msg idx %d "
		"remote core id 0x%08X MSG ID %d QID %d IP ID %d",
		ctx->irq, ctx->local_msg_idx,
		ctx->remote_core_id, ctx->remote_msg_idx,
		ctx->remote_qid, ctx->remote_qm_id);

	printk(KERN_INFO "%s initialized\n", APM86xxx_VNET);
	return 0;

irqerr:	/* Failed to read IRQ */
	unregister_netdev(ndev);

regerr:	/* Fail to register with network stack */
macerr:	/* Fail to set MAC */
qerr:	/* Fail to configure queue */
	free_netdev(ndev);
	return rc;
}

static int apm_vnet_remove(struct platform_device *ofdev)
{
	struct net_device *ndev = dev_get_drvdata(&ofdev->dev);
	struct apm_vnet_priv_dev *ctx = NULL;

	ctx = netdev_priv(ndev);

	/* Un-register for IRQ */
	if (ctx->irq != NO_IRQ)
		free_irq(ctx->irq, NULL);

	/* Bring link down */
	apm_vnet_down_link(ctx);

	if (apm_qm_msg_rx_unregister(APM_QM_VENET_RTYPE))
		dev_err(&ofdev->dev, "Failed to unregister with QM\n");

	unregister_netdev(ndev);

	if (ctx->percpu_ptr)
		free_percpu(ctx->percpu_ptr);

	free_netdev(ndev);

	dev_info(&ofdev->dev, "%s unloaded\n", APM86xxx_VNET);
	return 0;
}

static struct of_device_id apm_vnet_match[] = {
	{ .compatible = "apm,apm86xxx-vnet", },
	{},
};

static struct platform_driver apm_vnet_of_driver = {
        .driver = {
		.name		= "apm86xxx-vnet",
		.of_match_table	= apm_vnet_match,
	},
	.probe = apm_vnet_probe,
	.remove = apm_vnet_remove,
	.shutdown = apm_vnet_shutdown,
};

static int __init apm_vnet_init(void)
{
	printk(KERN_INFO "%s initializing\n", APM86xxx_VNET);
	return platform_driver_register(&apm_vnet_of_driver);
}

static void __exit apm_vnet_exit(void)
{
	platform_driver_unregister(&apm_vnet_of_driver);
}

module_init(apm_vnet_init);
module_exit(apm_vnet_exit);

MODULE_AUTHOR("Loc Ho <lho@apm.com>");
MODULE_DESCRIPTION(APM86xxx_VNET);
MODULE_LICENSE("GPL v2");
