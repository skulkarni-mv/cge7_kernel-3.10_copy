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

#include <misc/xgene/cle/apm_preclass_data.h>
#include <misc/xgene/cle/apm_cle_config.h>
#include "xgene_enet_main.h"
#include "xgene_enet_tools.h"

/* Global pdata structure, used by netmap*/
struct xgene_enet_pdata *enet_pdata[XGENE_MAX_INTERFACE];

static struct of_device_id xgene_enet_device_ids[] = {
	{
		.compatible = "apm,xgene-storm-menet",
		.data = (void *)XGENE_SM_MENET
	},	
	{
		.compatible = "apm,xgene-magneto-menet",
		.data = (void *)XGENE_MN_MENET
	},
	{
		.compatible = "apm,xgene-magneto-rgmii1",
		.data = (void *)XGENE_MN_RGMII1
	},
	{
		.compatible = "apm,xgene-magneto-sgenet0",
		.data = (void *)XGENE_MN_SGENET_0
	},
	{
		.compatible = "apm,xgene-magneto-sgenet1",
		.data = (void *)XGENE_MN_SGENET_1
	},
	{
		.compatible = "apm,xgene-magneto-sgenet2",
		.data = (void *)XGENE_MN_SGENET_2
	},
	{
		.compatible = "apm,xgene-magneto-xgenet0",
		.data = (void *)XGENE_MN_XGENET_0
	},
	{
		.compatible = "apm,xgene-storm-xgenet0",
		.data = (void *)XGENE_SM_XGENET_0
	},
	{
		.compatible = "apm,xgene-storm-xgenet1",
		.data = (void *)XGENE_SM_XGENET_1
	},
	{
		.compatible = "apm,xgene-storm-sgenet0",
		.data = (void *)XGENE_SM_SGENET_0
	},
	{
		.compatible = "apm,xgene-storm-sgenet1",
		.data = (void *)XGENE_SM_SGENET_1
	},
	{
		.compatible = "apm,xgene-shadowcat-xgenet0",
		.data = (void *)XGENE_SC_XGENET_0
	},
	{
		.compatible = "apm,xgene-shadowcat-xgenet1",
		.data = (void *)XGENE_SC_XGENET_1
	},
	{
		.compatible = "apm,xgene-shadowcat-sgenet0",
		.data = (void *)XGENE_SC_SGENET_0
	},
	{
		.compatible = "apm,xgene-shadowcat-sgenet1",
		.data = (void *)XGENE_SC_SGENET_1
	},
	{},
};

static void xgene_enet_cpu_to_le64(struct xgene_enet_desc *desc,
					  int count)
{
	int i;

	for (i = 0; i < count; i++)
		((u64 *)desc)[i] = cpu_to_le64(((u64 *)desc)[i]);
}

static void xgene_enet_le64_to_cpu(struct xgene_enet_desc *desc,
					  int count)
{
	int i;

	for (i = 0; i < count; i++)
		((u64 *)desc)[i] = le64_to_cpu(((u64 *)desc)[i]);
}

static void xgene_enet_desc16_to_le64(struct xgene_enet_desc *desc)
{
	((u64 *)desc)[1] = cpu_to_le64(((u64 *)desc)[1]);
}

static void xgene_enet_le64_to_desc16(struct xgene_enet_desc *desc)
{
	((u64 *)desc)[1] = le64_to_cpu(((u64 *)desc)[1]);
}

static void xgene_enet_init_bufpool(struct xgene_enet_desc_ring *buf_pool)
{
	struct xgene_enet_pdata *pdata = netdev_priv(buf_pool->ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	struct xgene_enet_desc *desc;
	int i;

	for (i = 0; i < buf_pool->slots; i++) {
		desc = (struct xgene_enet_desc *)&buf_pool->desc16[i];

		ring_ops->set_desc(desc, USERINFO, i);
		ring_ops->set_desc(desc, FPQNUM, buf_pool->dst_ring_num);
		ring_ops->set_desc(desc, STASH, 1);

		switch (pdata->intf) {
		case XGENE_MN_MENET:
		case XGENE_MN_RGMII1:
		case XGENE_MN_SGENET_0:
		case XGENE_MN_SGENET_1:
		case XGENE_MN_SGENET_2:	
		case XGENE_MN_XGENET_0:
		case XGENE_SC_XGENET_0:
		case XGENE_SC_XGENET_1:
		case XGENE_SC_SGENET_0:
		case XGENE_SC_SGENET_1:
			ring_ops->set_desc(desc, AM, 1);
			break;
		default:
			break;
		}

		xgene_enet_cpu_to_le64(desc, 4);
	}
}

static int xgene_enet_refill_bufpool(struct xgene_enet_desc_ring *buf_pool,
				     u32 nbuf)
{
	struct xgene_enet_pdata *pdata = netdev_priv(buf_pool->ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	struct sk_buff *skb;
	struct xgene_enet_desc *desc;
	struct net_device *ndev;
	struct device *dev;
	dma_addr_t dma_addr;
	u32 tail = buf_pool->tail;
	u32 slots = buf_pool->slots - 1;
	int i, ret = 0;
	u16 bufdatalen = BUF_LEN_CODE_2K;

	ndev = buf_pool->ndev;
	dev = ndev_to_dev(buf_pool->ndev);

	for (i = 0; i < nbuf; i++) {
		desc = (struct xgene_enet_desc *)&buf_pool->desc16[tail];

		skb = netdev_alloc_skb_ip_align(ndev, XGENE_ENET_MAX_MTU);
		if (unlikely(!skb)) {
			netdev_err(ndev, "Could not allocate skb");
			ret = -ENOMEM;
			goto out;
		}
		buf_pool->rx_skb[tail] = skb;

		dma_addr = dma_map_single(dev, skb->data, XGENE_ENET_MAX_MTU,
					  DMA_FROM_DEVICE);
		if (dma_mapping_error(dev, dma_addr)) {
			netdev_err(ndev, "DMA mapping error\n");
			dev_kfree_skb_any(skb);
			ret = -EINVAL;
			goto out;
		}
		ring_ops->set_desc(desc, DATAADDR, dma_addr);
		ring_ops->set_desc(desc, BUFDATALEN, bufdatalen);
		ring_ops->set_desc(desc, COHERENT, 1);

		xgene_enet_desc16_to_le64(desc);
		tail = (tail + 1) & slots;
	}

	ring_ops->wr_cmd(buf_pool, nbuf);
	buf_pool->tail = tail;

out:
	return ret;
}

static void xgene_enet_delete_bufpool(struct xgene_enet_desc_ring *buf_pool)
{
	struct xgene_enet_pdata *pdata = netdev_priv(buf_pool->ndev);
	u32 tail = buf_pool->tail;
	u32 slots = buf_pool->slots - 1;
	int len = pdata->ring_ops.len(buf_pool);
	struct xgene_enet_desc *desc;
	u32 userinfo;
	int i;

	for (i = 0; i < len; i++) {
		tail = (tail - 1) & slots;
		desc = (struct xgene_enet_desc *)&buf_pool->desc16[tail];

		xgene_enet_le64_to_desc16(desc);
		userinfo = (u32) pdata->ring_ops.get_desc(desc, USERINFO);
		dev_kfree_skb_any(buf_pool->rx_skb[userinfo]);
	}

	pdata->ring_ops.wr_cmd(buf_pool, -len);
	buf_pool->tail = tail;
}

irqreturn_t xgene_enet_rx_irq(const int irq, void *data)
{
	struct xgene_enet_desc_ring *rx_ring = data;

	if (napi_schedule_prep(&rx_ring->napi)) {
		disable_irq_nosync(irq);
		__napi_schedule(&rx_ring->napi);
	}

	return IRQ_HANDLED;
}

static int xgene_enet_tx_completion(struct xgene_enet_desc_ring *cp_ring,
				    struct xgene_enet_desc *desc,
				    struct xgene_enet_desc *exp_desc)
{
	struct xgene_enet_pdata *pdata = netdev_priv(cp_ring->ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	struct sk_buff *skb;
	dma_addr_t pa;
	size_t len;
	struct device *dev;
	u16 skb_index;
	int ret = 0;

	skb_index = (u32)ring_ops->get_desc(desc, USERINFO);
	skb = cp_ring->cp_skb[skb_index];

	dev = ndev_to_dev(cp_ring->ndev);
	pa = (dma_addr_t) ring_ops->get_desc(desc, DATAADDR);
	len = ring_ops->get_desc(desc, BUFDATALEN);
	dma_unmap_single(dev, pa, len, DMA_TO_DEVICE);
	if (exp_desc) {
		pa = (dma_addr_t) ring_ops->get_desc(exp_desc, DATAADDR);
		len = ring_ops->get_desc(exp_desc, BUFDATALEN);
		dma_unmap_single(dev, pa, len, DMA_TO_DEVICE);
	}

	if (likely(skb)) {
		dev_kfree_skb_any(skb);
	} else {
		netdev_info(cp_ring->ndev, "tx completion skb is NULL\n");
		ret = -1;
	}

	return ret;
}

static void xgene_enet_checksum_offload(struct xgene_enet_desc *desc,
					struct sk_buff *skb)
{
	u32 maclen;
	struct iphdr *iph;
	u8 l4hlen = 0;
	u8 l3hlen = 0;
	u8 csum_enable = 0;
	u8 proto = 0;
	u32 mss, all_hdr_len;
	int mss_len;
	struct net_device *ndev = skb->dev;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;

	if (unlikely(!(ndev->features & NETIF_F_IP_CSUM)))
		goto out;
	if (unlikely(skb->protocol != htons(ETH_P_IP)) &&
	    unlikely(skb->protocol != htons(ETH_P_8021Q)))
		goto out;

	maclen = xgene_enet_hdr_len(skb->data);
	iph = ip_hdr(skb);
	l3hlen = ip_hdrlen(skb) >> 2;

	if (unlikely(iph->frag_off & htons(IP_MF | IP_OFFSET)))
		goto out;
	if (likely(iph->protocol == IPPROTO_TCP)) {
		l4hlen = tcp_hdrlen(skb) / 4;
		csum_enable = 1;
		proto = TSO_IPPROTO_TCP;
		if (ndev->features & NETIF_F_TSO) {
			mss = skb_shinfo(skb)->gso_size;
			all_hdr_len = maclen + ip_hdrlen(skb) + tcp_hdrlen(skb);
			mss_len = skb->len - all_hdr_len;

			if (!mss || mss_len <= mss)
				goto skip_tso;

			if (mss != pdata->mss) {
				pdata->mss = mss;
				pdata->mac_ops.set_mss(pdata);
			}

			ring_ops->set_desc(desc, ET, 1);
		}
	} else if (iph->protocol == IPPROTO_UDP) {
		l4hlen = UDP_HDR_SIZE;
		csum_enable = 1;
		proto = TSO_IPPROTO_UDP;
	}

skip_tso:
	ring_ops->set_desc(desc, TCPHDR, l4hlen);
	ring_ops->set_desc(desc, IPHDR, l3hlen);
	ring_ops->set_desc(desc, EC, csum_enable);
	ring_ops->set_desc(desc, IS, proto);
out:
	return;
}

static int xgene_enet_setup_tx_desc(struct xgene_enet_desc_ring *tx_ring,
				     struct sk_buff *skb)
{
	struct xgene_enet_desc *desc, *exp_desc;
	struct device *dev;
	struct xgene_enet_pdata *pdata = netdev_priv(tx_ring->ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	u8 nr_frags = skb_shinfo(skb)->nr_frags;
	skb_frag_t *frag = NULL;
	dma_addr_t dma_addr;
	u32 i, idx, frag_idx, len, size = 0;
	u8 ethhdr;
	struct xgene_enet_exp_buff_desc *exp_buff = NULL;
	u16 tail = tx_ring->tail;
	bool split = false;
	u32 offset = 0;
	u8 count = 1;
	u16 ell_bytes = 0, ell_info;
	dma_addr_t dma_ll_addr;

	dev = ndev_to_dev(tx_ring->ndev);

	desc = (struct xgene_enet_desc *)&tx_ring->desc[tx_ring->tail];
	tx_ring->tail = (tx_ring->tail + 1) & (tx_ring->slots - 1);
	memset(desc, 0, sizeof(struct xgene_enet_desc));

	len = skb_headlen(skb);
	dma_addr = dma_map_single(dev, skb->data, len, DMA_TO_DEVICE);
	if (dma_mapping_error(dev, dma_addr)) {
		netdev_err(tx_ring->ndev, "DMA mapping error\n");
		return -EINVAL;
	}
	((u64 *)desc)[1] = SET_VAL(DATAADDR, dma_addr) |
	       		   SET_VAL(BUFDATALEN, len) |
			   SET_VAL(COHERENT, 1);

	if (!skb_is_nonlinear(skb))
		goto out;

	/* scatter gather */
	ring_ops->set_desc(desc, NV, 1);
	exp_desc = (struct xgene_enet_desc *)&tx_ring->desc[tx_ring->tail];
	tx_ring->tail = (tx_ring->tail + 1) & (tx_ring->slots - 1);
	memset(exp_desc, 0, sizeof(struct xgene_enet_desc));
	count = 2;

	for (i = 0 ; i < 4 ; i++)
		((u64 *)exp_desc)[i] = LAST_BUFFER;

	for (i = 0, idx = 0, frag_idx = 0; split || frag_idx < nr_frags ; i++) {
		if (!split) {
			frag = &skb_shinfo(skb)->frags[frag_idx++];
			size = frag->size;
			offset = 0;
			if (size > BUFLEN_16K)
				split = true;
		}

		if (size <= BUFLEN_16K) {
			len = size;
			split = false;
		} else {
			len = BUFLEN_16K;
			size -= BUFLEN_16K;
		}

		dma_addr = skb_frag_dma_map(dev, frag, offset, len, DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_addr)) {
			netdev_err(tx_ring->ndev, "DMA mapping error\n");
			/* TODO: handle this */
			return -EINVAL;
		}

		switch(i) {
		case 0:
		case 1:
		case 2:
			((u64 *)exp_desc)[i ^ 1] = SET_VAL(DATAADDR, dma_addr) | SET_VAL(TSO_BUF, len);
			break;
		case 3:
			if (split || (frag_idx != nr_frags)) {
				ring_ops->set_desc(desc, LL, 1);
				exp_buff = &tx_ring->exp_buff[tail * MAX_EXP_BUFFS];
				((u64 *)exp_buff)[idx ^ 1] = SET_VAL(DATAADDR, dma_addr) |
				       			     SET_VAL(TSO_BUF, len);
				xgene_enet_cpu_to_le64((struct xgene_enet_desc *)
						&(((u64 *)exp_buff)[idx ^ 1]), 1);
				idx++;
				ell_bytes = len;
			} else {
				((u64 *)exp_desc)[i ^ 1] = SET_VAL(DATAADDR, dma_addr) |
				       			   SET_VAL(TSO_BUF, len);
			}
			break;
		default:
			((u64 *)exp_buff)[idx ^ 1] = SET_VAL(DATAADDR, dma_addr) | SET_VAL(TSO_BUF, len);
			xgene_enet_cpu_to_le64((struct xgene_enet_desc *)
					&(((u64 *)exp_buff)[idx ^ 1]), 1);
			idx++;
			ell_bytes += len;
			break;
		}

		if (split)
		       	offset += BUFLEN_16K;
	}

	/* setting expanded buffer address */
	if (idx) {
		dma_ll_addr = dma_map_single(dev, exp_buff,
				sizeof(struct xgene_enet_exp_buff_desc) * MAX_EXP_BUFFS,
				DMA_TO_DEVICE);
		if (dma_mapping_error(dev, dma_ll_addr)) {
			netdev_err(tx_ring->ndev, "DMA mapping error\n");
			dev_kfree_skb_any(skb);
			return -EINVAL;
		}
		ell_info = (((ell_bytes & 0xff000) >> 12) << 8)| idx;
		((u64 *)exp_desc)[3] = SET_VAL(DATAADDR, dma_ll_addr) | SET_VAL(LL_INFO,  ell_info);
		ring_ops->set_desc(desc, LL_LSB, ell_bytes & 0Xfff);
	}
	
	xgene_enet_cpu_to_le64(exp_desc, 4);
	
out:
	tx_ring->cp_ring->cp_skb[tail] = skb;
	ring_ops->set_desc(desc, AM, 1);
	ring_ops->set_desc(desc, USERINFO, tail);
	ring_ops->set_desc(desc, HENQNUM, tx_ring->dst_ring_num);
	ring_ops->set_desc(desc, TYPESEL, 1);
	ethhdr = xgene_enet_hdr_len(skb->data);
	ring_ops->set_desc(desc, ETHHDR, ethhdr);
	ring_ops->set_desc(desc, IC, 1);

	xgene_enet_checksum_offload(desc, skb);
	xgene_enet_cpu_to_le64(desc, 4);

	ring_ops->wr_cmd(tx_ring, count);

	return 0;
}

static netdev_tx_t xgene_enet_start_xmit(struct sk_buff *skb,
					 struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct xgene_enet_desc_ring *tx_ring = pdata->tx_ring[skb->queue_mapping];
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	u32 tx_level;

	tx_level = ring_ops->len(tx_ring);
	if (tx_level > pdata->tx_qcnt_hi) {
		/* FIXME: use subqueue */
		netif_stop_queue(ndev);
		return NETDEV_TX_BUSY;
	}

	if (xgene_enet_setup_tx_desc(tx_ring, skb)) {
		dev_kfree_skb_any(skb);
		goto out;
	}

	skb_tx_timestamp(skb);
out:
	return NETDEV_TX_OK;
}

inline void xgene_enet_skip_csum(struct sk_buff *skb)
{
	struct iphdr *iph = (struct iphdr *)skb->data;
	if (!(iph->frag_off & htons(IP_MF | IP_OFFSET)) ||
	    (iph->protocol != IPPROTO_TCP && iph->protocol != IPPROTO_UDP)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
}

static int xgene_enet_rx_frame(struct xgene_enet_desc_ring *rx_ring,
				struct xgene_enet_desc *desc)
{
	struct net_device *ndev = rx_ring->ndev;
	struct xgene_enet_desc_ring *buf_pool = rx_ring->buf_pool;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct xgene_ring_ops *ring_ops = &pdata->ring_ops;
	u32 datalen, skb_index;
	struct sk_buff *skb;
	dma_addr_t pa;
	struct device *dev;
	int ret = 0;
	
	dev = ndev_to_dev(rx_ring->ndev);

	skb_index = (u32) ring_ops->get_desc(desc, USERINFO);
	skb = buf_pool->rx_skb[skb_index];
	/* FIXME: Why do we need this check? Looks like for ACPI??*/
	if (unlikely(!skb)) {
		netdev_err(ndev,
			"receive invalid message context index %d (SKB is NULL)\n",
			skb_index);
		return -EINVAL;
	}
	buf_pool->rx_skb[skb_index] = NULL;
	prefetch(skb->data - NET_IP_ALIGN);

	/* Strip off CRC as HW isn't doing this */
	datalen = (u32) ring_ops->get_desc(desc, BUFDATALEN);
	datalen -= 4;
	skb_put(skb, datalen);

	pa = (dma_addr_t) ring_ops->get_desc(desc, DATAADDR);
	dma_unmap_single(dev, pa, XGENE_ENET_MAX_MTU, DMA_FROM_DEVICE);

#ifdef ENET_DEBUG
	print_hex_dump(KERN_INFO, "+ Rx:MSG: ",
			DUMP_PREFIX_ADDRESS, 16, 4, (void *)desc, 32, 1);
	print_hex_dump(KERN_INFO, "+ Rx:SKB data: ", DUMP_PREFIX_ADDRESS,
                16, 4, (void *)skb->data, skb->len, 1);
#endif

	if (--rx_ring->nbufpool == 0) {
		ret = xgene_enet_refill_bufpool(buf_pool, XGENE_ENET_FP_NBUF);
		rx_ring->nbufpool = XGENE_ENET_FP_NBUF;
	}

	skb_checksum_none_assert(skb);
	skb->protocol = eth_type_trans(skb, ndev);
	if (likely((ndev->features & NETIF_F_IP_CSUM) &&
		   skb->protocol == htons(ETH_P_IP))) {
		xgene_enet_skip_csum(skb);
	}

	napi_gro_receive(&rx_ring->napi, skb);

	return ret;
}

static int xgene_enet_process_ring(struct xgene_enet_desc_ring *ring,
				   int budget)
{
	struct net_device *ndev = ring->ndev;
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	struct xgene_enet_desc *desc, *exp_desc;
	int napi_budget = budget;
	int cmd = 0, ret = 0;
	u16 head = ring->head;
	u16 slots = ring->slots - 1;
#ifdef ENET_DEBUG
	u8 elerr, lerr;
#endif

	do {
		desc = &ring->desc[head];
		exp_desc = NULL;
		if (unlikely(((u64 *)desc)[EMPTY_SLOT_INDEX] == EMPTY_SLOT))
			break;

		xgene_enet_le64_to_cpu(desc, 4);
		if (pdata->ring_ops.get_desc(desc, NV)) {
			head = (head + 1) & slots;
			exp_desc = &ring->desc[head];
			if (unlikely(((u64 *)exp_desc)[EMPTY_SLOT_INDEX] == EMPTY_SLOT)) {
				head = (head - 1) & slots;
				xgene_enet_cpu_to_le64(exp_desc, 4);
				break;
			}
			cmd++;
		}

		if (pdata->ring_ops.get_desc(desc, FPQNUM))
			ret = xgene_enet_rx_frame(ring, desc);
		else
			ret = xgene_enet_tx_completion(ring, desc, exp_desc);
		((u64 *)desc)[EMPTY_SLOT_INDEX] = EMPTY_SLOT;
		if (exp_desc)
		       	((u64 *)exp_desc)[EMPTY_SLOT_INDEX] = EMPTY_SLOT;

		head = (head + 1) & slots;
		cmd++;

		if (ret)
			goto out;
	} while (--budget);

	if (likely(cmd)) {
		pdata->ring_ops.wr_cmd(ring, -cmd);
		ring->head = head;

		if (netif_queue_stopped(ndev)) {
			if (pdata->ring_ops.len(ring) < pdata->cp_qcnt_low)
				netif_wake_queue(ndev);
		}
	}

out:
	return napi_budget - budget;
}

static int xgene_enet_napi(struct napi_struct *napi, const int budget)
{
	struct xgene_enet_desc_ring *ring =
	    container_of(napi, struct xgene_enet_desc_ring, napi);
	int processed = xgene_enet_process_ring(ring, budget);

	if (processed != budget) {
		napi_complete(napi);
		enable_irq(ring->irq);
	}

	return processed;
}

static void xgene_enet_timeout(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	pdata->mac_ops.reset(pdata);
}

static int xgene_enet_register_irq(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata;
	struct device *dev;
	int ret, i, j;

	pdata = (struct xgene_enet_pdata *)netdev_priv(ndev);
	dev = &pdata->pdev->dev;
	for (i = 0; i < pdata->num_rx_queues; i++) {
		ret = devm_request_irq(dev, pdata->rx_ring[i]->irq, 
			xgene_enet_rx_irq, IRQF_SHARED, 
			pdata->rx_ring[i]->irq_name, 
			pdata->rx_ring[i]);
		if (ret) {
			netdev_err(ndev,"rx[%d] %d interrupt request failed\n",
				i, pdata->rx_ring[i]->irq);
			goto rx_err;
		}
	}

	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		ret = devm_request_irq(dev, pdata->tx_ring[i]->cp_ring->irq,
			xgene_enet_rx_irq, IRQF_SHARED,
			pdata->tx_ring[i]->cp_ring->irq_name,
			pdata->tx_ring[i]->cp_ring);
		if (ret) {
			netdev_err(ndev, "tx_completion [%d] %d interrupt request failed\n",
				 i, pdata->tx_ring[i]->cp_ring->irq);
			goto tx_err;
                }
	}
	return ret;
rx_err:
	for (j = 0; j < i; j++) {
		devm_free_irq(dev, pdata->rx_ring[j]->irq, 
				pdata->rx_ring[j]);
	}
	return ret;
tx_err:
	for (j = 0; j < i; j++) {
		devm_free_irq(dev, pdata->tx_ring[j]->cp_ring->irq,
			pdata->tx_ring[j]->cp_ring);
	}
	return ret;
}

static void xgene_enet_free_irq(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata;
	struct device *dev;
	u32 i;

	pdata = (struct xgene_enet_pdata *)netdev_priv(ndev);
	dev = &pdata->pdev->dev;

	for (i = 0; i < pdata->num_rx_queues; i++) {
		devm_free_irq(dev, pdata->rx_ring[i]->irq, 
				pdata->rx_ring[i]);
	}
	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		devm_free_irq(dev, pdata->tx_ring[i]->cp_ring->irq,
				pdata->tx_ring[i]->cp_ring);
	}
}
static int xgene_enet_open(struct net_device *ndev)
{
	int ret, i;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);

	/* FIXME: remove this later */
	pdata->mac_ops.disable(pdata);

	netif_set_real_num_tx_queues(ndev, pdata->num_tx_queues);
	netif_set_real_num_rx_queues(ndev, pdata->num_rx_queues);
	for (i = 0; i < pdata->num_rx_queues; i++) {
		napi_enable(&pdata->rx_ring[i]->napi);
	}
	for (i = 0; i < pdata->num_tx_completion_queues; i++) {	
		napi_enable(&pdata->tx_ring[i]->cp_ring->napi);
	}
	ret = xgene_enet_register_irq(ndev);
	pdata->mac_ops.enable(pdata);
	if (ret)
		goto out;

	if (pdata->phy_dev) {
#ifdef CONFIG_NET_XGENE_PHY
		if (((pdata->intf == XGENE_MN_SGENET_0) ||
		    (pdata->intf == XGENE_MN_SGENET_1)) &&
		    (pdata->phy_mode == PHY_INTERFACE_MODE_SGMII) &&
		    (pdata->phy_dev->phy_id == 0x01410eb1)) {
			    pdata->phy_dev->addr ++;
			    genphy_resume(pdata->phy_dev);
			    pdata->phy_dev->addr --;
		}
#endif
		phy_start(pdata->phy_dev);
	}

	netif_tx_start_all_queues(ndev);
	
        if (pdata->xgene_netmap_open)
                pdata->xgene_netmap_open((void *)pdata);

out:
	return ret;
}

static int xgene_enet_close(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	int i;

        if (pdata->xgene_netmap_close)
                pdata->xgene_netmap_close((void *)pdata);

	netif_stop_queue(ndev);

	if (pdata->phy_dev) {
#ifdef CONFIG_NET_XGENE_PHY
		if (((pdata->intf == XGENE_MN_SGENET_0) ||
		    (pdata->intf == XGENE_MN_SGENET_1)) &&
		    (pdata->phy_mode == PHY_INTERFACE_MODE_SGMII) &&
		    (pdata->phy_dev->phy_id == 0x01410eb1)) {
			    pdata->phy_dev->addr ++;
			    genphy_suspend(pdata->phy_dev);
			    pdata->phy_dev->addr --;
		}
#endif
		phy_stop(pdata->phy_dev);
	}

	for (i = 0; i < pdata->num_rx_queues; i++) {
		napi_disable(&pdata->rx_ring[i]->napi);
	}
	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		napi_disable(&pdata->tx_ring[i]->cp_ring->napi);
	}

	xgene_enet_free_irq(ndev);

	for (i = 0; i < pdata->num_rx_queues; i++) {
		xgene_enet_process_ring(pdata->rx_ring[i], -1);
	}
	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		xgene_enet_process_ring(pdata->tx_ring[i]->cp_ring, -1);
	}

	pdata->mac_ops.disable(pdata);

	return 0;
}

void xgene_enet_delete_ring(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	struct device *dev = &pdata->pdev->dev;

	pdata->ring_ops.clear(ring);
	dma_free_coherent(dev, INTR_MBOX_SIZE, ring->irq_mbox_addr, ring->irq_mbox_dma);
	dma_free_coherent(dev, ring->size, ring->desc_addr, ring->dma);
	devm_kfree(dev, ring);
}

static void xgene_enet_delete_desc_rings(struct xgene_enet_pdata *pdata)
{
	struct device *dev = &pdata->pdev->dev;
	struct xgene_enet_desc_ring *buf_pool, *cp_ring;
	u32 i;

	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		if (pdata->tx_ring[i]) {
			if (pdata->tx_ring[i]->cp_ring) {
				xgene_enet_delete_ring(pdata->tx_ring[i]->cp_ring);
				devm_kfree(dev, pdata->tx_ring[i]->cp_ring->cp_skb);
				pdata->tx_ring[i]->cp_ring = NULL;
			}
		}
	}

	for (i = 0; i < pdata->num_tx_queues; i++) {
		if (pdata->tx_ring[i]) {
			xgene_enet_delete_ring(pdata->tx_ring[i]);
			pdata->tx_ring[i] = NULL;
		}
	}

	for (i = 0; i < pdata->num_rx_queues; i++) {
		if (pdata->rx_ring[i]) {
			/* For menet We use same queue for rx and
			   tx completion. So just free cp_ckb for cp ring */
			if (pdata->intf == XGENE_SM_MENET) {
				cp_ring = pdata->tx_ring[i]->cp_ring;
				devm_kfree(dev, cp_ring->cp_skb);
			}
			buf_pool = pdata->rx_ring[i]->buf_pool;
			xgene_enet_delete_bufpool(buf_pool);
			xgene_enet_delete_ring(buf_pool);
			devm_kfree(dev, buf_pool->rx_skb);
			xgene_enet_delete_ring(pdata->rx_ring[i]);
			pdata->rx_ring[i] = NULL;
		}
	}
}

static int xgene_enet_get_ring_size(struct device *dev,
				    enum xgene_enet_ring_cfgsize cfgsize)
{
	int size = -1;

	switch (cfgsize) {
	case RING_CFGSIZE_512B:
		size = 0x200;
		break;
	case RING_CFGSIZE_2KB:
		size = 0x800;
		break;
	case RING_CFGSIZE_16KB:
		size = 0x4000;
		break;
	case RING_CFGSIZE_64KB:
		size = 0x10000;
		break;
	case RING_CFGSIZE_512KB:
		size = 0x80000;
		break;
	default:
		dev_err(dev, "Unsupported cfg ring size %d\n", cfgsize);
		break;
	}

	return size;
}

struct xgene_enet_desc_ring *xgene_enet_create_desc_ring(
			struct net_device *ndev, struct xgene_ring_params *ring_params,
			int irq)
{
	struct xgene_enet_desc_ring *ring;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct device *dev = &pdata->pdev->dev;
	u32 size;

	ring = devm_kzalloc(dev, sizeof(struct xgene_enet_desc_ring),
			    GFP_KERNEL);
	if (!ring) {
		netdev_err(ndev, "Could not allocate ring\n");
		goto err;
	}

	ring->ndev = ndev;
	ring->num = ring_params->num;
	ring->cfgsize = ring_params->cfg_size;
	ring->is_bufpool = ring_params->is_bufpool;
	ring->owner = ring_params->owner;
	ring->buf_num = ring_params->buf_num;

	size = xgene_enet_get_ring_size(dev, ring->cfgsize);
	ring->desc_addr = dma_zalloc_coherent(dev, size, &ring->dma,
					      GFP_KERNEL);
	if (!ring->desc_addr) {
		netdev_err(ndev, "Could not allocate desc_addr\n");
		goto err;
	}
	ring->size = size;

	switch (pdata->intf) {
	case XGENE_MN_MENET:
	case XGENE_MN_RGMII1:
	case XGENE_MN_SGENET_0:
	case XGENE_MN_SGENET_1:
	case XGENE_MN_SGENET_2:
	case XGENE_MN_XGENET_0:
	case XGENE_SM_XGENET_0:
	case XGENE_SM_XGENET_1:
	case XGENE_SM_SGENET_0:
	case XGENE_SM_SGENET_1:
	case XGENE_SC_XGENET_0:
	case XGENE_SC_XGENET_1:
	case XGENE_SC_SGENET_0:
	case XGENE_SC_SGENET_1:
		if (irq > 0) {
			ring->irq_mbox_addr = dma_zalloc_coherent(dev, INTR_MBOX_SIZE,
					&ring->irq_mbox_dma, GFP_KERNEL);
			if (!ring->irq_mbox_addr) {
				netdev_err(ndev, "Could not allocate irq_mb\n");
				goto err;
			}
		}
		break;
	default:
			break;
	}

	pdata->ring_ops.set_cmd_base(ring);
	ring->cmd = ring->cmd_base + 0x2C;
	ring->irq = irq;
	ring = pdata->ring_ops.setup(ring);

	return ring;
err:
	if (ring) {
		if (ring->desc_addr)
			dma_free_coherent(dev, size, ring->desc_addr, ring->dma);
		/* TODO: add code to free up irq_mb */
		devm_kfree(dev, ring);
	}
	return NULL;
}

static int xgene_enet_create_desc_rings(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct device *dev = &pdata->pdev->dev;
	struct xgene_enet_desc_ring *rx_ring, *tx_ring, *cp_ring;
	struct xgene_enet_desc_ring *buf_pool = NULL;
	struct xgene_ring_params ring_params;
	int size, ret = 0, i, irq;

	/* allocate rx descriptor ring */
	for (i = 0; i < pdata->num_rx_queues; i++) {
		memset(&ring_params, 0, sizeof(struct xgene_ring_params));
		ring_params.is_bufpool = false;
		ring_params.owner = RING_OWNER_CPU;
		ring_params.buf_num = pdata->rx_ring_buf_num++;
		ring_params.num = pdata->ring_ops.get_num(pdata);
		ring_params.cfg_size = RING_CFGSIZE_16KB;
		rx_ring = xgene_enet_create_desc_ring(ndev, &ring_params,
				pdata->rx_irq + i);
		if (IS_ERR_OR_NULL(rx_ring)) {
			ret = PTR_ERR(rx_ring);
			goto err;
		}
#ifdef ENET_DEBUG
		pr_info("+ rx qnum %d pbn %x\n", rx_ring->num, rx_ring->buf_num);
#endif
		/* We use same queue for rx and tx completion */
		if (pdata->intf == XGENE_SM_MENET) {
			snprintf(rx_ring->irq_name, sizeof(rx_ring->irq_name),
			"%s-rx-tx-cp%d", ndev->name, i);
		} else {
			snprintf(rx_ring->irq_name, sizeof(rx_ring->irq_name),
			"%s-rx%d", ndev->name, i);
		}

#ifdef ENET_DEBUG
		pr_info("+ irq name %s irq %d\n", rx_ring->irq_name, pdata->rx_irq + i);
#endif

		/* allocate buffer pool for receiving packets */
		memset(&ring_params, 0, sizeof(struct xgene_ring_params));
		ring_params.is_bufpool = true;

		switch(pdata->intf) {
		case XGENE_MN_MENET:
		case XGENE_MN_RGMII1:
			ring_params.owner = RING_OWNER_ETH2;
			break;
		case XGENE_MN_SGENET_0:
		case XGENE_MN_SGENET_1:
		case XGENE_SC_XGENET_1:
		case XGENE_SC_SGENET_1:
		case XGENE_SM_XGENET_1:
			ring_params.owner = RING_OWNER_ETH1;
			break;
		default:
			ring_params.owner = RING_OWNER_ETH0;
			break;
		}

		ring_params.buf_num = pdata->buf_pool_buf_num++;
		ring_params.num = pdata->ring_ops.get_num(pdata);
		ring_params.cfg_size = RING_CFGSIZE_16KB;

		buf_pool = xgene_enet_create_desc_ring(ndev, &ring_params, 0);
		if (IS_ERR_OR_NULL(buf_pool)) {
			ret = PTR_ERR(buf_pool);
			goto err;
		}

		rx_ring->nbufpool = XGENE_ENET_FP_NBUF;
		rx_ring->buf_pool = buf_pool;
		buf_pool->rx_skb = devm_kcalloc(dev, buf_pool->slots,
				     sizeof(struct sk_buff *), GFP_KERNEL);
		if (!buf_pool->rx_skb) {
			netdev_err(ndev, "Could not allocate rx_skb pointers\n");
			ret = -ENOMEM;
			goto err;
		}

		buf_pool->dst_ring_num = xgene_enet_dst_ring_num(buf_pool);
#ifdef ENET_DEBUG
		pr_info("+ fp qnum %d pbn %x dst_ring_num: %08x\n", buf_pool->num, buf_pool->buf_num, buf_pool->dst_ring_num);
#endif
		rx_ring->buf_pool = buf_pool;
		pdata->rx_ring[i] = rx_ring;
	}

	/* allocate tx descriptor ring */
	for (i = 0; i < pdata->num_tx_queues; i++) {
		memset(&ring_params, 0, sizeof(struct xgene_ring_params));
		ring_params.is_bufpool = false;

		switch(pdata->intf) {
		case XGENE_MN_MENET:
		case XGENE_MN_RGMII1:
			ring_params.owner = RING_OWNER_ETH2;
			break;
		case XGENE_MN_SGENET_0:
		case XGENE_MN_SGENET_1:
		case XGENE_SC_XGENET_1:
		case XGENE_SC_SGENET_1:
		case XGENE_SM_XGENET_1:
			ring_params.owner = RING_OWNER_ETH1;
			break;
		default:
			ring_params.owner = RING_OWNER_ETH0;
			break;
		}

		ring_params.buf_num = pdata->tx_ring_buf_num++;
		ring_params.num = pdata->ring_ops.get_num(pdata);
		ring_params.cfg_size = RING_CFGSIZE_16KB;
		tx_ring = xgene_enet_create_desc_ring(ndev, &ring_params, 0);
		if (IS_ERR_OR_NULL(tx_ring)) {
			ret = PTR_ERR(tx_ring);
			goto err;
		}
#ifdef ENET_DEBUG
		pr_info("+ tx qnum %d pbn %x\n", tx_ring->num, tx_ring->buf_num);
#endif

		pdata->tx_ring[i] = tx_ring;
		size = MAX_EXP_BUFFS * sizeof(struct xgene_enet_exp_buff_desc) * tx_ring->slots;
		tx_ring->exp_buff = devm_kzalloc(dev, size, GFP_KERNEL);
		if (!tx_ring->exp_buff) {
			netdev_err(ndev, "Could not allocate exp_buff_desc\n");
			/* TODO: handle error */
			goto err;
		}

		/* allocate tx completion ring */
		/* Since menet has only 1 irq for dequeue 
		   so we will use same queue for tx completion and rx */
		if (pdata->intf == XGENE_SM_MENET) {
			cp_ring = pdata->rx_ring[i];
			irq = pdata->rx_irq;
		} else {
			memset(&ring_params, 0,
				sizeof(struct xgene_ring_params));
			ring_params.is_bufpool = false;
			ring_params.owner = RING_OWNER_CPU;
			ring_params.buf_num = pdata->rx_ring_buf_num++;
			ring_params.num = pdata->ring_ops.get_num(pdata);
			ring_params.cfg_size = RING_CFGSIZE_16KB;
			irq = pdata->rx_irq + pdata->num_rx_queues + i;
			cp_ring = xgene_enet_create_desc_ring(ndev,
					&ring_params, irq);
			if (IS_ERR_OR_NULL(cp_ring)) {
				ret = PTR_ERR(cp_ring);
				goto err;
			}
		}
#ifdef ENET_DEBUG
		pr_info("+ cp qnum %d pbn %d\n", cp_ring->num, cp_ring->buf_num);
#endif
		cp_ring->cp_skb = devm_kcalloc(dev, tx_ring->slots,
				sizeof(struct sk_buff *), GFP_KERNEL);

		if (!cp_ring->cp_skb) {
			netdev_err(ndev, "Could not allocate cp_skb pointers\n");
			ret = -ENOMEM;
			goto err;
		}
		pdata->tx_ring[i]->cp_ring = cp_ring;
		pdata->tx_ring[i]->dst_ring_num = xgene_enet_dst_ring_num(cp_ring);
		
		/* For menet we use same queue for rx and tx completion so
		   we don't need to reassign the name */
		if (pdata->intf != XGENE_SM_MENET) {
			snprintf(cp_ring->irq_name, sizeof(cp_ring->irq_name),
				"%s-tx-cp%d", ndev->name, i);
		}
#ifdef ENET_DEBUG
		pr_info("+ %s %d irq name %s irq no %x \n",
		__func__, __LINE__, cp_ring->irq_name, irq);
#endif
	}
	pdata->tx_qcnt_hi = pdata->tx_ring[0]->slots / 2;
	pdata->cp_qcnt_hi = pdata->rx_ring[0]->slots / 2;
	pdata->cp_qcnt_low = pdata->cp_qcnt_hi / 2;

	return 0;

err:
	xgene_enet_delete_desc_rings(pdata);
	return ret;
}

static struct net_device_stats *xgene_enet_stats(struct net_device *ndev)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct net_device_stats *nst = &pdata->nstats;
	struct xgene_enet_rx_stats *rx_stats;
	struct xgene_enet_tx_stats *tx_stats;
	u32 pkt_bytes, crc_bytes = 4;

	rx_stats = &pdata->stats.rx_stats;
	tx_stats = &pdata->stats.tx_stats;

	local_irq_disable();
	pdata->mac_ops.get_stats(pdata);

	pkt_bytes = rx_stats->rx_byte_count;
	pkt_bytes -= rx_stats->rx_packet_count * crc_bytes;
	nst->rx_packets = rx_stats->rx_packet_count;
	nst->rx_bytes = pkt_bytes;

	pkt_bytes = tx_stats->tx_byte_count;
	pkt_bytes -= tx_stats->tx_packet_count * crc_bytes;
	nst->tx_packets = tx_stats->tx_packet_count;
	nst->tx_bytes = pkt_bytes;

	nst->rx_dropped = rx_stats->rx_drop_pkt_count;
	nst->tx_dropped = tx_stats->tx_drop_frm_count;

	nst->rx_crc_errors = rx_stats->rx_fcs_err_count;
	nst->rx_length_errors = rx_stats->rx_frm_len_err_pkt_count;
	nst->rx_frame_errors = rx_stats->rx_alignment_err_pkt_count;
	nst->rx_over_errors = rx_stats->rx_oversize_pkt_count;

	nst->rx_errors = rx_stats->rx_total_err_count;

	nst->tx_errors = tx_stats->tx_fcs_err_frm_count;

	local_irq_enable();

	return nst;
}

static int xgene_enet_set_mac_address(struct net_device *ndev, void *addr)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	int ret;

	ret = eth_mac_addr(ndev, addr);
	if (ret)
		goto out;

	pdata->mac_ops.set_mac_addr(pdata);
out:
	return ret;
}

static const struct net_device_ops xgene_ndev_ops = {
	.ndo_open = xgene_enet_open,
	.ndo_stop = xgene_enet_close,
	.ndo_start_xmit = xgene_enet_start_xmit,
	.ndo_tx_timeout = xgene_enet_timeout,
	.ndo_get_stats = xgene_enet_stats,
	.ndo_change_mtu = eth_change_mtu,
	.ndo_set_mac_address = xgene_enet_set_mac_address,
};

#ifdef XGENE_NET_CLE
static struct xgene_enet_cle *xgene_enet_cle_init(struct net_device *ndev, char *ptree_id, u32 port_id)
{
	struct xgene_enet_cle *cle_cfg = NULL;
	struct xgene_enet_cle_ptree *ptree_cfg = NULL;
	struct xgene_enet_pdata *pdata = netdev_priv(ndev);
	struct device *dev = &pdata->pdev->dev;
	u16 rx_fpsel[MAX_RX_QUEUES];
	u16 rx_dstqid[MAX_RX_QUEUES];
	u32 cid = PID2CID[port_id];
	int ret = 0;
	int i;
	/* Initialize CLE Inline Engine */
	if ((cle_cfg = apm_cle_init(port_id)) == NULL) {
		netdev_err(ndev, "Error in apm_cle_init\n");
		return NULL;
	}
	cle_cfg->port = port_id;
	pdata->cle_cfg = cle_cfg;

        /* Derive Classifier CSR register address */
	apm_class_base_addr[cid] = pdata->eth_cle_csr_addr;

	/* Initialize PreClassifier Tree for this port */
	for (i = 0; i < MAX_RX_QUEUES; i++) {
		rx_dstqid[i] = 0;
		rx_fpsel[i] = 0;
	}
	for (i = 0; i < pdata->num_rx_queues; i++) {
		rx_dstqid[i] = xgene_enet_dst_ring_num(pdata->rx_ring[i]);
		rx_fpsel[i] = pdata->rx_ring[i]->buf_pool->buf_num;
	}
	if (!strcmp(ptree_id, CLE_PTREE_DEFAULT)) {
		ptree_cfg = apm_preclass_init(port_id, rx_dstqid, rx_fpsel);
		if (ptree_cfg == NULL) {
			netdev_err(ndev, "Preclass Tree init error\n");
			goto err;
		}
	}

	/* Start Preclassifier Engine for this port */
	ret = apm_preclass_switch_tree(port_id, CLE_PTREE_DEFAULT);
	if (ret != APM_RC_OK) {
		ptree_cfg->enable = 0;
		netdev_err(ndev, "Could not start Preclassifier Engine");
	} else
		ptree_cfg->enable = 1;

	cle_cfg->ptree_cfg = ptree_cfg;
	return cle_cfg;

err:
	if (cle_cfg)
		devm_kfree(dev, cle_cfg);
	return NULL;
}
#endif

static int xgene_enet_get_resources(struct xgene_enet_pdata *pdata)
{
	struct platform_device *pdev;
	struct net_device *ndev;
	struct device *dev;
	struct resource *res;
	void *base_addr;
	const char *mac;
	u32 mcx_mac_csr_offset;
	int irq, ret = 0;

	pdev = pdata->pdev;
	dev = &pdev->dev;
	ndev = pdata->ndev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (pdata->intf == XGENE_SM_SGENET_1 ||
	    pdata->intf == XGENE_MN_RGMII1   ||
	    pdata->intf == XGENE_MN_SGENET_1 ) {
		pdata->base_addr = 
			ioremap_nocache(res->start - (resource_size_t)0x30,
					resource_size(res));
	} else {
		pdata->base_addr =
			ioremap_nocache(res->start, resource_size(res));
	}
	
	if (IS_ERR(pdata->base_addr)) {
		dev_err(dev, "Unable to retrieve ENET Port CSR region\n");
		return PTR_ERR(pdata->base_addr);
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	pdata->ring_csr_res = res;
	pdata->ring_csr_addr = devm_ioremap(&pdev->dev, res->start,
					    resource_size(res));
	if (IS_ERR(pdata->ring_csr_addr)) {
		dev_err(dev, "Unable to retrieve ENET Ring CSR region\n");
		return PTR_ERR(pdata->ring_csr_addr);
	}

	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	pdata->ring_cmd_addr = devm_ioremap(&pdev->dev, res->start,
					    resource_size(res));
	if (IS_ERR(pdata->ring_cmd_addr)) {
		dev_err(dev, "Unable to retrieve ENET Ring command region\n");
		return PTR_ERR(pdata->ring_cmd_addr);
	}

	if (pdata->intf != XGENE_MN_MENET && pdata->intf != XGENE_SM_MENET
		&& pdata->intf != XGENE_MN_RGMII1) {
		res = platform_get_resource(pdev, IORESOURCE_MEM, 3);
		pdata->mdio_addr = devm_ioremap(&pdev->dev, res->start,
						resource_size(res));
		if (IS_ERR(pdata->mdio_addr)) {
			dev_err(dev, "Unable to retrieve MDIO Address region\n");
			return PTR_ERR(pdata->mdio_addr);
		}
	}

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(dev, "Unable to get ENET Rx IRQ\n");
		ret = irq;
		goto out;
	}
	pdata->rx_irq = irq;

	mac = of_get_mac_address(dev->of_node);
	if (mac)
		memcpy(ndev->dev_addr, mac, ndev->addr_len);
	else
		eth_hw_addr_random(ndev);
	memcpy(ndev->perm_addr, ndev->dev_addr, ndev->addr_len);

	pdata->phy_mode = of_get_phy_mode(pdev->dev.of_node);
	if (pdata->phy_mode == PHY_INTERFACE_MODE_RGMII) {
		ret = of_property_read_u32(pdev->dev.of_node, "phy-addr",
					   &pdata->phy_addr);
		if (ret || pdata->phy_addr < 0 ||
        	    pdata->phy_addr > PHY_MAX_ADDR) {
        		dev_err(dev, "No or invalid phy-addr entry in DTS\n");
        		ret = -EINVAL;
        		goto out;
		}
	}

	pdata->clk = devm_clk_get(&pdev->dev, NULL);
	ret = IS_ERR(pdata->clk);
	if (ret) {
		dev_err(&pdev->dev, "can't get clock\n");
		goto out;
	}

	base_addr = pdata->base_addr;
	pdata->eth_csr_addr = base_addr + BLOCK_ETH_CSR_OFFSET;
	pdata->eth_cle_csr_addr = base_addr + BLOCK_ETH_CLE_CSR_OFFSET;
	pdata->eth_ring_if_addr = base_addr + BLOCK_ETH_RING_IF_OFFSET;
	pdata->eth_diag_csr_addr = base_addr + BLOCK_ETH_DIAG_CSR_OFFSET;
	pdata->mcx_mac_addr = base_addr + BLOCK_ETH_MAC_OFFSET;
	pdata->mcx_stats_addr = base_addr + BLOCK_ETH_STATS_OFFSET;
	mcx_mac_csr_offset = (pdata->intf == XGENE_SM_MENET) ||
			     (pdata->intf == XGENE_MN_MENET) ||
			     (pdata->intf == XGENE_MN_RGMII1) ||
			     (pdata->intf == XGENE_MN_SGENET_0) ||
			     (pdata->intf == XGENE_MN_SGENET_1) ||
			     //(pdata->intf == XGENE_MN_XGENET_0) ||
			     (pdata->intf == XGENE_SM_SGENET_0) ||
			     (pdata->intf == XGENE_SM_SGENET_1) ?
			     BLOCK_ETH_MAC_CSR_OFFSET :
			     BLOCK_XGE_MCXMAC_CSR_OFFSET;
	pdata->mcx_mac_csr_addr = base_addr + mcx_mac_csr_offset;
	pdata->axg_mac_addr = base_addr + BLOCK_AXG_MAC_OFFSET;
	pdata->axg_stats_addr = base_addr + BLOCK_AXG_STATS_OFFSET;
	pdata->axg_mac_csr_addr = base_addr + BLOCK_AXG_MAC_CSR_OFFSET;
	pdata->rx_buff_cnt = XGENE_NUM_PKT_BUF;

	switch(pdata->intf) {
	case XGENE_SM_MENET:
		pdata->rx_ring_buf_num = XGENE_SM_MENET_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SM_MENET_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SM_MENET_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SM_MENET_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_SM_XGENET_0:
		pdata->rx_ring_buf_num = XGENE_SM_XGENET0_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SM_XGENET0_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SM_XGENET0_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SM_XGENET0_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_SM_XGENET_1:
		pdata->rx_ring_buf_num = XGENE_SM_XGENET1_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SM_XGENET1_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SM_XGENET1_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SM_XGENET1_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_SM_SGENET_0:
		pdata->rx_ring_buf_num = XGENE_SM_SGENET0_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SM_SGENET0_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SM_SGENET0_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SM_SGENET0_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_SM_SGENET_1:
		pdata->rx_ring_buf_num = XGENE_SM_SGENET1_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SM_SGENET1_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SM_SGENET1_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SM_SGENET1_RING_NUM_START;
		pdata->total_rings = 256;
		/* For SGMII1 port the indirect cmd registers offset by 0x30
		   from the indirect cmd registers of port SGMII0 */
		pdata->mcx_mac_addr += 0x30;
		pdata->mcx_stats_addr += 0x30;
		break;
	case XGENE_SC_XGENET_0:
	case XGENE_SC_SGENET_0:
		pdata->rx_ring_buf_num = XGENE_SC_ENET0_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SC_ENET0_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SC_ENET0_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SC_ENET0_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_SC_XGENET_1:
	case XGENE_SC_SGENET_1:
		pdata->rx_ring_buf_num = XGENE_SC_ENET1_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_SC_ENET1_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_SC_ENET1_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_SC_ENET1_RING_NUM_START;
		pdata->total_rings = 256;
		break;
	case XGENE_MN_MENET:
		pdata->rx_ring_buf_num = XGENE_MN_MENET_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_MN_MENET_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_MN_MENET_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_MN_MENET_RING_NUM_START;
		pdata->total_rings = 64;
		break;
	case XGENE_MN_RGMII1:
		pdata->rx_ring_buf_num = XGENE_MN_RGMII1_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_MN_RGMII1_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_MN_RGMII1_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_MN_RGMII1_RING_NUM_START;
		pdata->total_rings = 64;
		pdata->mcx_mac_addr += 0x30;
		pdata->mcx_stats_addr += 0x30;
		break;
        case XGENE_MN_SGENET_0:
                pdata->rx_ring_buf_num = XGENE_MN_SGENET0_RX_BUF_NUM_START;
                pdata->tx_ring_buf_num = XGENE_MN_SGENET0_TX_BUF_NUM_START;
                pdata->buf_pool_buf_num = XGENE_MN_SGENET0_BUF_POOL_NUM_START;
                pdata->ring_start = XGENE_MN_SGENET0_RING_NUM_START;
                pdata->total_rings = 256;
                break;
        case XGENE_MN_SGENET_1:
                pdata->rx_ring_buf_num = XGENE_MN_SGENET1_RX_BUF_NUM_START;
                pdata->tx_ring_buf_num = XGENE_MN_SGENET1_TX_BUF_NUM_START;
                pdata->buf_pool_buf_num = XGENE_MN_SGENET1_BUF_POOL_NUM_START;
                pdata->ring_start = XGENE_MN_SGENET1_RING_NUM_START;
                pdata->total_rings = 256;
		/* For SGMII1 port the indirect cmd registers offset by 0x30
		   from the indirect cmd registers of port SGMII0 */
		pdata->mcx_mac_addr += 0x30;
		pdata->mcx_stats_addr += 0x30;
                break;
	case XGENE_MN_SGENET_2:
		pdata->rx_ring_buf_num = XGENE_MN_SGENET2_RX_BUF_NUM_START;
		pdata->tx_ring_buf_num = XGENE_MN_SGENET2_TX_BUF_NUM_START;
		pdata->buf_pool_buf_num = XGENE_MN_SGENET2_BUF_POOL_NUM_START;
		pdata->ring_start = XGENE_MN_SGENET2_RING_NUM_START;
		pdata->total_rings = 256;
	case XGENE_MN_XGENET_0:
                pdata->rx_ring_buf_num = XGENE_MN_XGENET0_RX_BUF_NUM_START;
                pdata->tx_ring_buf_num = XGENE_MN_XGENET0_TX_BUF_NUM_START;
                pdata->buf_pool_buf_num = XGENE_MN_XGENET0_BUF_POOL_NUM_START;
                pdata->ring_start = XGENE_MN_XGENET0_RING_NUM_START;
                pdata->total_rings = 256;
		break;
	default:
		pr_info("+ TBD\n");
		break;
	}
	pdata->ring_num = pdata->ring_start;

#ifdef ENET_DEBUG
	pr_info("+ %s %d Ring CSR %p\n", __func__, __LINE__,
		pdata->ring_csr_addr);
	pr_info("+ %s %d Ring CMD %p\n", __func__, __LINE__,
		pdata->ring_cmd_addr);
	pr_info("+ %s %d Rx IRQ %d\n", __func__, __LINE__,
		pdata->rx_irq);
	pr_info("+ %s %d Rx Ring Buf No %d\n", __func__, __LINE__,
		pdata->rx_ring_buf_num);
	pr_info("+ %s %d Tx Ring Buf No %d\n", __func__, __LINE__,
		pdata->tx_ring_buf_num);
	pr_info("+ %s %d Buf Pool Buf No %d\n", __func__, __LINE__,
		pdata->buf_pool_buf_num);
	pr_info("+ %s %d base_addr %p\n", __func__, __LINE__,
		base_addr);
	pr_info("+ %s %d eth_csr_addr %p\n", __func__, __LINE__,
		pdata->eth_csr_addr);
	pr_info("+ %s %d eth_cle_csr_addr %p\n", __func__, __LINE__,
		pdata->eth_cle_csr_addr);
	pr_info("+ %s %d eth_ring_if_addr %p\n", __func__, __LINE__,
		pdata->eth_ring_if_addr);
	pr_info("+ %s %d eth_diag_csr_addr %p\n", __func__, __LINE__,
		pdata->eth_diag_csr_addr);
	pr_info("+ %s %d mcx_mac_addr %p\n", __func__, __LINE__,
		pdata->mcx_mac_addr);
	pr_info("+ %s %d mcx_stat_addr %p\n", __func__, __LINE__,
		pdata->mcx_stats_addr);
	pr_info("+ %s %d mcx_mac_csr_offset %08x\n", __func__, __LINE__,
		mcx_mac_csr_offset);
	pr_info("+ %s %d mcx_mac_csr_addr %p\n", __func__, __LINE__,
		pdata->mcx_mac_csr_addr);
	pr_info("+ %s %d axg_mac_addr %p\n", __func__, __LINE__,
		pdata->axg_mac_addr);
	pr_info("+ %s %d axg_stat_addr %p\n", __func__, __LINE__,
		pdata->axg_stats_addr);
	pr_info("+ %s %d axg_mac_csr_addr %p\n", __func__, __LINE__,
		pdata->axg_mac_csr_addr);
#endif
out:
	return ret;
}

static int xgene_enet_init_hw(struct xgene_enet_pdata *pdata)
{
	struct net_device *ndev = pdata->ndev;
	struct xgene_enet_desc_ring *buf_pool;
#ifdef XGENE_NET_CLE
	struct xgene_enet_cle *cle_cfg = NULL;
#endif
	int ret = 0, i;

	pdata->mac_ops.disable(pdata);

	ret = xgene_enet_create_desc_rings(ndev);
	if (ret) {
		netdev_err(ndev, "Error in ring configuration\n");
		goto out;
	}

	/* setup buffer pool */
	for (i = 0; i < pdata->num_rx_queues; i++) {
		buf_pool = pdata->rx_ring[i]->buf_pool;
		xgene_enet_init_bufpool(buf_pool);
		ret = xgene_enet_refill_bufpool(buf_pool, pdata->rx_buff_cnt);
		if (ret){
			goto out;
		}
	}

#ifndef XGENE_NET_CLE
	pdata->mac_ops.cle_bypass(pdata,
				       xgene_enet_dst_ring_num(pdata->rx_ring[0]),
				       pdata->rx_ring[0]->buf_pool->buf_num - 0x20,
				       true);
#else
	/* Initialize and Enable  PreClassifier Tree */
	switch(pdata->intf) {
	case XGENE_SM_MENET:
		cle_cfg = xgene_enet_cle_init(ndev, CLE_PTREE_DEFAULT, CLE_ENET_4);
		break;
	case XGENE_SC_XGENET_0:
	case XGENE_SC_SGENET_0:
	case XGENE_SM_XGENET_0:
	case XGENE_MN_XGENET_0:
	case XGENE_MN_SGENET_2:
		cle_cfg = xgene_enet_cle_init(ndev, CLE_PTREE_DEFAULT, CLE_XGENET_0);
		break;
	case XGENE_SC_XGENET_1:
	case XGENE_SC_SGENET_1:
	case XGENE_SM_XGENET_1:
		cle_cfg = xgene_enet_cle_init(ndev, CLE_PTREE_DEFAULT, CLE_XGENET_1);
		break;
	case XGENE_SM_SGENET_0:
		cle_cfg = xgene_enet_cle_init(ndev, CLE_PTREE_DEFAULT, CLE_ENET_0);
		break;
	case XGENE_SM_SGENET_1:
		cle_cfg = xgene_enet_cle_init(ndev, CLE_PTREE_DEFAULT, CLE_ENET_1);
		break;
	default:
		pr_info("+ TBD\n");
		break;
	}

	if (IS_ERR_OR_NULL(cle_cfg)) {
		ret = PTR_ERR(cle_cfg);
		netdev_err(ndev, "Error in classifier initialization\n");
		goto out;
	}
	pdata->cle_cfg = cle_cfg;
#endif

	switch (pdata->intf) {
	case XGENE_SM_MENET:
	case XGENE_MN_MENET:
	case XGENE_MN_RGMII1:
	case XGENE_MN_SGENET_0:
	case XGENE_MN_SGENET_1:
	case XGENE_MN_SGENET_2:
	case XGENE_SM_SGENET_0:
	case XGENE_SM_SGENET_1:
	case XGENE_SC_SGENET_0:
	case XGENE_SC_SGENET_1:
		pdata->phy_speed = SPEED_1000;
		break;
	default:
		break;
	}
	pdata->mac_ops.init(pdata);
out:
	return ret;
}

static void xgene_enet_setup_ops(struct xgene_enet_pdata *pdata, const struct of_device_id *of_devid)
{
	enum xgene_enet_interface intf = (enum xgene_enet_interface)of_devid->data;
	pdata->intf = intf;
	switch(intf) {
	case XGENE_SM_MENET:
		memcpy(&pdata->mac_ops, &xgene_gmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sm_ring_ops, sizeof(struct xgene_ring_ops));
		pdata->ring_ops.type = XGENE_SM_RING_3;
		memcpy(&pdata->enet_rd_wr_ops, &xgene_gmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	case XGENE_MN_MENET:
	case XGENE_MN_RGMII1:
		memcpy(&pdata->mac_ops, &xgene_gmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sc_ring_ops, sizeof(struct xgene_ring_ops));
		memcpy(&pdata->enet_rd_wr_ops, &xgene_gmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	case XGENE_SM_XGENET_0:
	case XGENE_SM_XGENET_1:
		memcpy(&pdata->mac_ops, &xgene_xgmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sm_ring_ops, sizeof(struct xgene_ring_ops));
		pdata->ring_ops.type = XGENE_SM_RING_0;
		memcpy(&pdata->enet_rd_wr_ops, &xgene_xgmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	case XGENE_SM_SGENET_0:
	case XGENE_SM_SGENET_1:
		memcpy(&pdata->mac_ops, &xgene_sgmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sm_ring_ops, sizeof(struct xgene_ring_ops));
		pdata->ring_ops.type = XGENE_SM_RING_1;
		memcpy(&pdata->enet_rd_wr_ops, &xgene_sgmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	case XGENE_SC_XGENET_0:
	case XGENE_SC_XGENET_1:
	case XGENE_MN_XGENET_0:
		memcpy(&pdata->mac_ops, &xgene_xgmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sc_ring_ops, sizeof(struct xgene_ring_ops));
		memcpy(&pdata->enet_rd_wr_ops, &xgene_xgmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	case XGENE_MN_SGENET_0:
        case XGENE_MN_SGENET_1:
	case XGENE_MN_SGENET_2:
	case XGENE_SC_SGENET_0:
	case XGENE_SC_SGENET_1:
		memcpy(&pdata->mac_ops, &xgene_sgmac_ops, sizeof(struct xgene_mac_ops));
		memcpy(&pdata->ring_ops, &xgene_sc_ring_ops, sizeof(struct xgene_ring_ops));
		memcpy(&pdata->enet_rd_wr_ops, &xgene_sgmac_rd_wr_ops, 
				sizeof(struct xgene_enet_rd_wr_ops));
		break;
	default:
		pr_info("+ TBD\n");
		break;
	}
}

#if 0  // Remove this after testing on Tigershark and Mustang
static void xgene_enet_ring_reset(struct xgene_enet_pdata *pdata)
{
	switch (pdata->intf) {
	case XGENE_SM_MENET:
	case XGENE_MN_MENET:
	case XGENE_MN_SGENET_0:
	case XGENE_MN_SGENET_1:
	case XGENE_SM_XGENET_0:
	case XGENE_SM_SGENET_0:
	case XGENE_SC_XGENET_0:
	case XGENE_SC_SGENET_0:
		if (xgene_qmtm_enable(pdata))
			pr_err("+ QM reset failed\n");
		break;
	default:
		break;
	}
}
#endif

static int xgene_enet_probe(struct platform_device *pdev)
{
	struct net_device *ndev;
	struct xgene_enet_pdata *pdata;
	struct device *dev = &pdev->dev;
	struct napi_struct *napi;
	const struct of_device_id *of_devid;
	int ret = 0, i;
	u32 num_tx_queues = 0, num_rx_queues = 0;

	of_devid = of_match_device(xgene_enet_device_ids, dev);
	
	pr_info("+ device found: %s\n", of_devid->compatible);

	if (!strcmp(of_devid->compatible, "apm,xgene-storm-menet")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-menet")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-rgmii1")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-sgenet0")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-sgenet1")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-sgenet2")
	|| !strcmp(of_devid->compatible, "apm,xgene-magneto-xgenet0")){
		num_tx_queues = 1;
		num_rx_queues = 1;
	} else {
		num_tx_queues = MAX_TX_QUEUES;
		num_rx_queues = MAX_RX_QUEUES;
	}
	
	ndev = alloc_etherdev_mqs(sizeof(struct xgene_enet_pdata),
		num_tx_queues, num_rx_queues);
	if (!ndev) {
		dev_err(dev, "Could not allocate netdev\n");
		return -ENOMEM;
	}

	pdata = netdev_priv(ndev);

	pdata->pdev = pdev;
	pdata->ndev = ndev;
	pdata->num_tx_queues = num_tx_queues;
	pdata->num_rx_queues = num_rx_queues;

	if (!of_devid || !of_devid->data) {
		pr_err("Device not found or device->data is empty\n");
		goto err;
	}
	xgene_enet_setup_ops(pdata, of_devid);

	/* For menet We use same queue for rx and tx completion */
	if (pdata->intf == XGENE_SM_MENET)
		pdata->num_tx_completion_queues = 0;
	else
		pdata->num_tx_completion_queues = num_tx_queues;

	ret = xgene_enet_get_resources(pdata);
	if (ret)
		goto err;

	/* Reset ethernet */
	pdata->mac_ops.port_reset(pdata);

	SET_NETDEV_DEV(ndev, dev);
	platform_set_drvdata(pdev, pdata);
	ndev->netdev_ops = &xgene_ndev_ops;
	ndev->features |= NETIF_F_IP_CSUM;
	ndev->features |= NETIF_F_GSO;
	ndev->features |= NETIF_F_GRO;
	ndev->features |= NETIF_F_SG;

	if (pdata->phy_mode != PHY_INTERFACE_MODE_RGMII &&
	    pdata->phy_mode != PHY_INTERFACE_MODE_SGMII) {
		ndev->features |= NETIF_F_TSO;
		pdata->mss = 1448;
		pdata->mac_ops.set_mss(pdata);
	}
	ndev->hw_features = ndev->features;
	ndev->ethtool_ops = &xgene_ethtool_ops;

	ret = register_netdev(ndev);
	if (ret) {
		netdev_err(ndev, "Failed to register net dev\n");
		goto err;
	}

	ret = dma_coerce_mask_and_coherent(dev, DMA_BIT_MASK(64));
	if (ret) {
		netdev_err(ndev, "No usable DMA configuration\n");
		goto err;
	}

	ret = xgene_enet_init_hw(pdata);
	if (ret)
		goto err;

	for (i = 0; i < pdata->num_rx_queues; i++) {
		napi = &pdata->rx_ring[i]->napi;
		netif_napi_add(ndev, napi, xgene_enet_napi, NAPI_POLL_WEIGHT);
	}

	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		napi = &pdata->tx_ring[i]->cp_ring->napi;
		netif_napi_add(ndev, napi, xgene_enet_napi,
				NAPI_POLL_WEIGHT);
	}

	if (pdata->intf != XGENE_MN_SGENET_2 &&
	    pdata->intf != XGENE_MN_SGENET_0 &&
	    pdata->intf != XGENE_MN_SGENET_1 &&
	    pdata->intf != XGENE_MN_RGMII1)
		if (pdata->mac_ops.mdio_config)
			pdata->mac_ops.mdio_config(pdata);

	enet_pdata[pdata->intf] = pdata;
	return ret;
err:
	unregister_netdev(ndev);
	free_netdev(ndev);
	return ret;
}

static int xgene_enet_remove(struct platform_device *pdev)
{
	struct xgene_enet_pdata *pdata;
	struct net_device *ndev;
	u32 i;

	pdata = platform_get_drvdata(pdev);
	ndev = pdata->ndev;
	
	enet_pdata[pdata->intf] = NULL;
	pdata->mac_ops.disable(pdata);
	for (i = 0; i < pdata->num_rx_queues; i++) {
		netif_napi_del(&pdata->rx_ring[i]->napi);
	}
	for (i = 0; i < pdata->num_tx_completion_queues; i++) {
		netif_napi_del(&pdata->tx_ring[i]->cp_ring->napi);
	}
	if (pdata->mac_ops.mdio_remove)
		pdata->mac_ops.mdio_remove(pdata);

	xgene_enet_delete_desc_rings(pdata);
	unregister_netdev(ndev);
	/* xgene_enet_shutdown(pdata); */
	pdata->mac_ops.port_shutdown(pdata);
	free_netdev(ndev);

	return 0;
}

MODULE_DEVICE_TABLE(of, xgene_enet_device_ids);

static struct platform_driver xgene_enet_driver = {
	.driver = {
		   .name = "xgene-enet",
		   .owner = THIS_MODULE,
		   .of_match_table = xgene_enet_device_ids,
		   },
	.probe = xgene_enet_probe,
	.remove = xgene_enet_remove,
};

EXPORT_SYMBOL(enet_pdata);
EXPORT_SYMBOL(xgene_enet_create_desc_ring);
EXPORT_SYMBOL(xgene_enet_delete_ring);

module_platform_driver(xgene_enet_driver);

MODULE_DESCRIPTION("APM X-Gene SoC Ethernet driver");
MODULE_VERSION("1.0");
MODULE_AUTHOR("Keyur Chudgar <kchudgar@apm.com>");
MODULE_LICENSE("GPL");
