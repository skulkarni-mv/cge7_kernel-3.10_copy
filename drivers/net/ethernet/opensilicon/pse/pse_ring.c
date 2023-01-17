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

#include "pse.h"

int ufo_cs_enable = 1; /* throught sysfs control, test performance */
#define PSE_FS_ALIGN_SIZE (64)

static struct sk_buff *pse_alloc_skb(unsigned int size)
{
	struct sk_buff *skb;

	P_TRACE("<%s> skb_size %d\n", __func__, size);

	skb = dev_alloc_skb(size + NET_IP_ALIGN);

	if (skb) {
		u8 *start;
		start = PTR_ALIGN(skb->data, PSE_FS_ALIGN_SIZE);
		skb_reserve(skb, start - skb->data);
	}

	return skb;
}

static struct pse_ring *pse_alloc_tx_ring(struct net_device *ndev, u16 ring_size)
{
	struct pse_ring *ring;
	struct pse_dma_desc *desc;
	struct pse_buffer_info *bi;
	int i;

	ring = vmalloc(sizeof(struct pse_ring));

	if (!ring) {
		/* TODO debug message*/
		goto fail_alloc_ring;
	}

	memset(ring, 0, sizeof(struct pse_ring));

	desc = pse_desc_dma_alloc(ndev->dev.parent, ring_size * PSE_DESC_SIZE_ALIGN, &ring->dma, GFP_KERNEL);

	if (!desc) {
		/* TODO debug message*/
		goto fail_alloc_desc;
	}

	ring->desc = desc;
	ring->ringsz = ring_size;

	bi = vmalloc(ring_size * sizeof(struct pse_buffer_info));

	if (!bi) {
		/* TODO debug message*/
		goto fail_alloc_bi;
	}

	ring->bi = bi;

	for (i = 0; i < ring_size; i++) {
		bi->skb = NULL;
		bi->desc = (void *)desc;
		desc->cown = 1;
		bi++; desc++;
	}
	desc = ring->bi->desc;
	desc[ring_size-1].eor = 1;

	spin_lock_init(&(ring->lock));


	return ring;

fail_alloc_bi:
	pse_desc_dma_free(ndev->dev.parent, ring_size * PSE_DESC_SIZE_ALIGN,
			ring->desc, ring->dma);
fail_alloc_desc:
	vfree(ring);
fail_alloc_ring:
	return NULL;
}

#define PSE_DIRECTION_TS 0
#define PSE_DIRECTION_FS 1

/**
 * pse_free_ring_generic - free allocated PSE ring
 * @ring: pointer to allocated ring
 * @fs: false=> TS, true=>FS
 *
 **/
static void pse_free_ring_generic(struct pse_ring *ring, bool fs)
{
	struct pse_dma_desc *desc;
	struct pse_buffer_info *bi;
	int i, ring_size, intr_group = 0;
	enum dma_data_direction dir;

	if (NULL == ring)
		return;

	if (fs)
		dir = DMA_FROM_DEVICE;
	else
		dir = DMA_TO_DEVICE;

	ring_size = ring->ringsz;
	bi = ring->bi;

	for (i = 0; i < ring_size; i++) {
		if (bi->skb) {
			desc = (struct pse_dma_desc *) bi->desc;
			pse_dma_unmap_single(ring->dev->dev.parent, desc->sdp, desc->sdl, dir);
			dev_kfree_skb_any(bi->skb);
		}
		bi++;
	}

	pse_desc_dma_free(ring->dev->dev.parent,
			  ring_size * PSE_DESC_SIZE_ALIGN,
			  ring->desc, ring->dma);

	if ((ring->ring_id == 3) && (fs == 1)) {

		napi_disable(&ring->napi);
		netif_napi_del(&ring->napi);
		ring->dev = NULL;
		pse_res->rx_ring[ring->ring_id] = NULL;
		intr_group = ~((0x3 << (ring->ring_id) << 1));
		pse_res->fs_intr_group[ring->cpu_id] &= intr_group;

	} else if ((ring->ring_id == 3) && (fs == 0)) {

		ring->dev = NULL;
		pse_res->tx_ring[ring->ring_id] = NULL;
		intr_group = ~((0x3 << (ring->ring_id) << 1));
		pse_res->ts_intr_group[ring->cpu_id] &= intr_group;

	} else if ((ring->ring_id != 3) && (ring->ring_id >= 2 && ring->ring_id <= 15)) {

		if (fs == 1) {
			if (pse_hibernation == 1) {
				if (&ring->napi) {
					napi_disable(&ring->napi);
					netif_napi_del(&ring->napi);
					pse_ring_id[pse_ring_count++].ring_id = ring->ring_id;
				}
				pse_hibernation = 0;
			}
			pse_res->rx_ring[ring->ring_id] = NULL;
			intr_group = ~((0x3 << (ring->ring_id) << 1));
			pse_res->fs_intr_group[ring->cpu_id] &= intr_group;
		} else {
			pse_res->tx_ring[ring->ring_id] = NULL;
			intr_group = ~((0x3 << (ring->ring_id) << 1));
			pse_res->ts_intr_group[ring->cpu_id] &= intr_group;
		}

	} else {

		if (fs == 1) {
			if (pse_hibernation == 1) {
				if (&ring->napi)
					netif_napi_del(&ring->napi);
				pse_hibernation = 0;
			}
			pse_res->rx_ring[ring->ring_id] = NULL;
			intr_group = ~((0x3 << (ring->ring_id) << 1));
			pse_res->fs_intr_group[ring->cpu_id] &= intr_group;
		} else {
			pse_res->tx_ring[ring->ring_id] = NULL;
			intr_group = ~((0x3 << (ring->ring_id) << 1));
			pse_res->ts_intr_group[ring->cpu_id] &= intr_group;
		}
	}

	vfree(ring->bi);
	vfree(ring);
	ring = NULL;
}

void pse_free_tx_ring(struct pse_ring *ring)
{
	return pse_free_ring_generic(ring, false);
}
EXPORT_SYMBOL(pse_free_tx_ring);

void pse_reset_rx_buffer_pktsz(struct pse_ring *ring)
{
	struct pse_dma_desc *desc;
	struct pse_buffer_info *bi;
	int i, ring_size;

	P_TRACE("<%s>: ring ID %d, reset packet size to %d\n",
		__func__, ring->ring_id, ring->pktsz);

	ring_size = ring->ringsz;
	bi = ring->bi;

	for (i = 0; i < ring_size; i++) {
		if (bi->skb) {
			desc = (struct pse_dma_desc *) bi->desc;
			pse_dma_unmap_single(ring->dev->dev.parent, desc->sdp, desc->sdl, DMA_FROM_DEVICE);
			dev_kfree_skb_any(bi->skb);
		}
		bi->skb = NULL;
		bi++;
	}

	i = pse_alloc_rx_buffer(ring->dev, ring, ring_size);
	if (ring_size != i) {
		DPRINT(WARNING,
			"<%s>: Allocate sk_buff (%d) is less then ring size (%d)\n", __func__, i, ring_size);
		/* TODO: set cown bit to avoid DMA access if no sk_buff */
	}
	return;
}

/**
 * pse_alloc_rx_buffer - allocate sk_buff for used receive buffer
 * @ring: pointer to RX ring
 * @cnt: how many sk_buff to allocate.
 *
 * Return number of allocated sk_buff
 */
u32 pse_alloc_rx_buffer(struct net_device *ndev, struct pse_ring *ring, u32 cnt)
{
	struct pse_buffer_info *bi;
	struct pse_fs_desc *desc;
	struct sk_buff *skb;
	u32 index, pktsz, done = 0;

	P_TRACE("<%s>: ring ID %d, ring size %d packet size %d\n",
		__func__, ring->ring_id, ring->ringsz, ring->pktsz);

	index = ring->next_to_use;
	pktsz = ring->pktsz;

	while (cnt--) {
		bi = (ring->bi + index);
		desc = (struct pse_fs_desc *)bi->desc;

		if (bi->skb) {
			/* TODO free skb?? */
			P_ERR("<%s>: PSE buffer_info error!!!\n", __func__);
		}
		skb = pse_alloc_skb(pktsz);
		if (!skb) {
			P_WARN("No resource to receive packet.\n");
			/* try to allocate sk_buff next time */
			goto alloc_skb_exit;
		}

		desc->sdp = pse_dma_map_single(ndev->dev.parent, skb->data,
					pktsz, DMA_FROM_DEVICE);
		desc->sdl = pktsz + NET_IP_ALIGN;
		desc->fsd = 1;
		desc->lsd = 1;
		desc->cown = 0;
		bi->skb = skb;

		index++; done++;

		if (ring->ringsz == index) {
			/* we reach the end of ring */
			index = 0;
		}
	}

alloc_skb_exit:
	ring->next_to_use = index;
	return done;
}
EXPORT_SYMBOL(pse_alloc_rx_buffer);

static struct pse_ring *pse_alloc_rx_ring(struct net_device *ndev, u16 ring_size, u16 pkt_size)
{
	struct pse_ring *ring;
	struct pse_dma_desc *desc;
	struct pse_buffer_info *bi;
	int i;

	P_TRACE("<%s>\n", __func__);

	ring = vmalloc(sizeof(struct pse_ring));

	if (!ring) {
		/* TODO debug message*/
		goto fail_alloc_ring;
	}


	memset(ring, 0, sizeof(struct pse_ring));

	desc = pse_desc_dma_alloc(ndev->dev.parent, ring_size * PSE_DESC_SIZE_ALIGN, &ring->dma, GFP_KERNEL);

	if (!desc) {
		/* TODO debug message*/
		goto fail_alloc_desc;
	}

	ring->desc = desc;
	ring->ringsz = ring_size;
	ring->pktsz = pkt_size;

	bi = vmalloc(ring_size * sizeof(struct pse_buffer_info));

	if (!bi) {
		/* TODO debug message*/
		goto fail_alloc_bi;
	}

	ring->bi = bi;

	for (i = 0; i < ring_size; i++) {
		bi->desc = desc;
		bi->skb = NULL;
		desc->cown = 1;
		bi++; desc++;
	}
	desc = ring->bi->desc;
	desc[ring_size - 1].eor = 1;


	ring->next_to_use = 0;
	ring->next_to_clean = 0;

	i = pse_alloc_rx_buffer(ndev, ring, ring_size);
	if (ring_size != i) {
		DPRINT(WARNING,
			"<%s>: Allocate sk_buff (%d) is less then ring size (%d)\n",
			__func__, i, ring_size);
		/* TODO: set cown bit to avoid DMA access if no sk_buff */
	}

	return ring;

fail_alloc_bi:
	pse_desc_dma_free(ndev->dev.parent, ring_size * PSE_DESC_SIZE_ALIGN,
			ring->desc, ring->dma);
fail_alloc_desc:
	vfree(ring);
fail_alloc_ring:
	return NULL;
}

void pse_free_rx_ring(struct pse_ring *ring)
{
	return pse_free_ring_generic(ring, true);
}
EXPORT_SYMBOL(pse_free_rx_ring);

u32 pse_receive_packet(struct pse_ring *ring, u32 *work_done, u32 budget);

void pse_dma_idle(void)
{
	u32 i, work_done, count;
	struct pse_ring *ring;

	pse_port_cfg(OPV5XC_PSE_PORT_MAC0, false);
	pse_port_cfg(OPV5XC_PSE_PORT_MAC1, false);
	pse_port_cfg(OPV5XC_PSE_PORT_MAC2, false);

	mdelay(500);

	count = 0;
	do {
		i = rd32(FS_DMA_STA);
		if (count > 32768)
			goto err;
		count++;
	} while (i);

	do {
		for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
			ring = pse_res->rx_ring[i];
			if (ring)
				pse_receive_packet(ring, &work_done, ring->ringsz);
		}
		i = rd32(MEM_QUEUE_STATUS0);
	} while (i & 0x7FF);


	count = 0;
	do {
		i = rd32(TS_DMA_STA);
		if (count > 32768)
			goto err;
		count++;
	} while (i);

	return;

err:
	pr_err("<%s> FS_DMA_STA 0x%.8x\n", __func__, rd32(FS_DMA_STA));
	pr_err("<%s> TS_DMA_STA 0x%.8x\n", __func__, rd32(TS_DMA_STA));
	BUG();
}

int pse_tx_ring_init(struct pse_priv *priv, u16 ring_size)
{
	struct pse_ring *ring;
	int i;
	for (i = 0; i < PSE_MAX_TX_QUEUE; i++) {
		ring = pse_alloc_tx_ring(priv->netdev, ring_size);

		if (ring) {
#ifdef PSE_SUPPORT_MQ
			if (priv->sp == 0)
				ring->ring_id = i;
			else
				ring->ring_id = PSE_MAX_TX_QUEUE + i;
#else
			ring->ring_id = priv->index;
#endif
#ifdef PSE_INTR_ASSIGN_CORE
			/* eth0 --> intr_group0 */
			/* eth1 --> intr_group1 */
			ring->cpu_id = priv->index;
#else
			ring->cpu_id = 0;
#endif
			ring->pmap = (1 << priv->sp);
			ring->dev = priv->netdev;

			priv->tx_ring[i] = ring;
			/* link tx ring to pse_resource*/
			priv->res->tx_ring[ring->ring_id] = ring;
		} else {
			return -ENOMEM;
		}
	}
	return 0;
}

int pse_rx_ring_init(struct pse_priv *priv, u16 ring_size, u16 pkt_size)
{
	struct pse_ring *ring;
	struct net_device *dev;
	int i;
	u32 val;
	P_TRACE("<%s>\n", __func__);

	dev = priv->netdev;

	for (i = 0; i < PSE_MAX_RX_QUEUE; i++) {

		ring = pse_alloc_rx_ring(dev, ring_size, pkt_size);

		if (ring) {
#ifdef PSE_SUPPORT_MQ
			if (priv->sp == 0)
				ring->ring_id = i;
			else
				ring->ring_id = PSE_MAX_RX_QUEUE + i;
#else
			ring->ring_id = priv->index;
#endif
#ifdef PSE_INTR_ASSIGN_CORE
			/* eth0 --> intr_group0 */
			/* eth1 --> intr_group1 */
			ring->cpu_id = priv->index;
#else
			ring->cpu_id = 0;
#endif
			ring->pmap = (1 << priv->sp);
			ring->dev = dev;

			priv->rx_ring[i] = ring;
			/* link rx ring to pse_resource*/
			priv->res->rx_ring[ring->ring_id] = ring;
		} else {
			return -ENOMEM;
		}
	}
	/* FIXME: map tc to ring */
	val = (0x1 << 15) | (priv->sp);
	wr32(val, PORT_PRI_CMD);
	while (val & (0x1 << 15))
		val = rd32(PORT_PRI_CMD);

	val = rd32(PORT_PRI_CTRL);
	val &= ~(0xF << 24);
	wr32(val, PORT_PRI_CTRL);

#ifdef PSE_SUPPORT_MQ
	val = 0;
	for (i = 0; i < PSE_MAX_RX_QUEUE; i++)
		val |= priv->rx_ring[i]->ring_id << ((7-i)*4);
#else
	val = ((ring->ring_id << 28) | (ring->ring_id << 24)
	       | (ring->ring_id << 20) | (ring->ring_id << 16)
	       | (ring->ring_id << 12) | (ring->ring_id << 8)
	       | (ring->ring_id << 4) | ring->ring_id);
#endif
	wr32(val, PORT_PRI_RING);

	val = (0x1 << 15)
		| (0x1 << 14)
		| (priv->sp);
	wr32(val, PORT_PRI_CMD);
	while (val & (0x1 << 15))
		val = rd32(PORT_PRI_CMD);

	return 0;
}


static void tx_ring_init_hw(struct pse_ring *ring, struct pse_resource *res)
{
	u32 val;

	P_TRACE("<%s>TX ring: ID %d, CPU ID %d, dma 0x%.8x\n",
			__func__, ring->ring_id, ring->cpu_id, ring->dma);

	res->ts_intr_group[ring->cpu_id] |= (0x3 << (ring->ring_id << 1));

	wr32(ring->dma, TS_DESC_PTR);
	wr32(ring->dma, TS_DESC_BASE);

	val = (0x1 << 15) /* access start */
		| (0x1 << 14) /* write */
		| ((ring->ring_id & 0xF) << 6)
		| ((ring->cpu_id & 0x3) << 4)
		| (ring->ring_id & 0xF);
	wr32(val, TS_DESC_ACCESS);

	while (val & (0x1 << 15))
		val = rd32(TS_DESC_ACCESS);

	wr32((1 << ring->ring_id) , TS_DMA_CTRL);
}

static void rx_ring_init_hw(struct pse_ring *ring, struct pse_resource *res)
{
	u32 val;

	P_TRACE("<%s>RX ring: ID %d, CPU ID %d, dma 0x%.8x\n",
			__func__, ring->ring_id, ring->cpu_id, ring->dma);

	res->fs_intr_group[ring->cpu_id] |= (0x3 << (ring->ring_id << 1));

	wr32(ring->dma, FS_DESC_PTR);
	wr32(ring->dma, FS_DESC_BASE);

	val = (0x1 << 15) /* access start */
		| (0x1 << 14) /* write */
		| ((ring->cpu_id & 0x3) << 4)
		| (ring->ring_id & 0xF);
	wr32(val, FS_DESC_ACCESS);

	while (val & (0x1 << 15))
		val = rd32(FS_DESC_ACCESS);

	wr32((1 << ring->ring_id) , FS_DMA_CTRL);
}

void pse_ring_init_hw(struct pse_priv *priv)
{
	int i;

	/* TX */
	for (i = 0; i < PSE_MAX_TX_QUEUE; i++)
		tx_ring_init_hw(priv->tx_ring[i], priv->res);

	/* RX */
	for (i = 0; i < PSE_MAX_RX_QUEUE; i++)
		rx_ring_init_hw(priv->rx_ring[i], priv->res);
}

void pse_fs_ring_multipe_cfg(bool enable)
{
	u32 val;
	val = rd32(DMA_RING_CTRL);

	if (enable)
		val |= (0x1);
	else
		val &= ~(0x1);

	wr32(val, DMA_RING_CTRL);
};

void pse_ts_ring_multipe_cfg(bool enable)
{
	u32 val;
	val = rd32(DMA_RING_CTRL);

	if (enable)
		val |= (0x1 << 16);
	else
		val &= ~(0x1 << 16);

	wr32(val, DMA_RING_CTRL);

};

static int pse_map_tx(struct pse_ring *ring, struct sk_buff *skb)
{
	struct net_device *ndev = ring->dev;
	struct pse_skb_frag *nf;
	struct skb_frag_struct *frag;
	struct pse_buffer_info *bi;

	int i, nr_frags;
	dma_addr_t map;

	bi = ring->bi + ring->next_to_use;
	nr_frags = skb_shinfo(skb)->nr_frags;
	nf = &bi->frag_array[0];

	map = pse_dma_map_single(ndev->dev.parent, skb->data,
			skb_headlen(skb), DMA_TO_DEVICE);
	if (dma_mapping_error(ndev->dev.parent, map))
		goto out_err;

	nf->dma = map;
	nf->length = skb_headlen(skb);

	for (i = 0; i < nr_frags; i++) {
		frag = &skb_shinfo(skb)->frags[i];
		nf = &bi->frag_array[i+1];

		map = pse_skb_frag_dma_map(ndev->dev.parent, frag, 0, skb_frag_size(frag),
				       DMA_TO_DEVICE);
		if (dma_mapping_error(ndev->dev.parent, map))
			goto unwind;

		nf->dma = map;
		nf->length = skb_frag_size(frag);
	}
	bi->frag_count = nr_frags + 1;

	return 0;

unwind:
	while (--i >= 0) {
		nf = &bi->frag_array[i+1];
		pse_dma_unmap_page(ndev->dev.parent, nf->dma, nf->length, DMA_TO_DEVICE);
	}

	nf = &bi->frag_array[0];
	pse_dma_unmap_single(ndev->dev.parent, nf->dma, skb_headlen(skb), DMA_TO_DEVICE);

out_err:
	return -ENOMEM;
}

bool pse_tx_desc_avail(struct pse_ring *tx_ring, int no_of_desc)
{
	struct pse_buffer_info *bi;
	struct pse_ts_desc *desc;
	void *first_desc, *last_desc;
	int i;

	bi = tx_ring->bi;
	first_desc = bi->desc;
	bi = tx_ring->bi + tx_ring->ringsz - 1;
	last_desc = bi->desc;
	bi = tx_ring->bi + tx_ring->next_to_use;
	desc = (struct pse_ts_desc *) bi->desc;
	for (i = 0; i < no_of_desc; i++) {
		if (!desc->cown)
			return false;

		if (desc == (struct pse_ts_desc *)last_desc)
			desc = (struct pse_ts_desc *)first_desc;
		else
			desc++;
	}
	return true;
}

int get_gso_mss_mtu(struct sk_buff *skb)
{
	if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))
		/* return mss */
		return skb_shinfo(skb)->gso_size;
	else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
		/* return mtu */
		return skb_shinfo(skb)->gso_size + skb_network_header_len(skb);
	else
		return 0;
}

int get_gso_payload_len(struct sk_buff *skb)
{

	if (skb_shinfo(skb)->gso_type & (SKB_GSO_TCPV4 | SKB_GSO_TCPV6))
		return skb->len - (skb_transport_offset(skb) + tcp_hdrlen(skb));

	else if (skb_shinfo(skb)->gso_type & SKB_GSO_UDP)
		return skb->len - (skb_network_offset(skb) + skb_network_header_len(skb));

	else
		return 0;
}

static inline u8 is_tcp_pkt(struct sk_buff *skb)
{
	u8 val = 0;

	if (ip_hdr(skb)->version == 4)
		val = (ip_hdr(skb)->protocol == IPPROTO_TCP);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (ip_hdr(skb)->version == 6)
		val = (ipv6_hdr(skb)->nexthdr == IPPROTO_TCP);
#endif
	return val;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
static inline u8 is_ipv6_udp_pkt(struct sk_buff *skb)
{
	const struct ipv6hdr *ip6h;
	const struct frag_hdr *fh;

	ip6h = ipv6_hdr(skb);
	if (ip6h->nexthdr == NEXTHDR_FRAGMENT) {
		fh = (struct frag_hdr *)(skb_network_header(skb) + sizeof(struct ipv6hdr));
		return fh->nexthdr == NEXTHDR_UDP;
	}
	return ip6h->nexthdr == NEXTHDR_UDP;
}
#endif

static inline u8 is_udp_pkt(struct sk_buff *skb)
{
	u8 val = 0;

	if (ip_hdr(skb)->version == 4)
		val = (ip_hdr(skb)->protocol == IPPROTO_UDP);
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	else if (ip_hdr(skb)->version == 6)
		val = is_ipv6_udp_pkt(skb);
#endif
	return val;
}

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)

/* copy from net/ipv6/ip6_output.c */
static int ip6_find_1stfragopt_local(struct sk_buff *skb, u8 **nexthdr)
{
	u16 offset = sizeof(struct ipv6hdr);
	struct ipv6_opt_hdr *exthdr =
				(struct ipv6_opt_hdr *)(ipv6_hdr(skb) + 1);
	unsigned int packet_len = skb->tail - skb->network_header;
	int found_rhdr = 0;
	*nexthdr = &ipv6_hdr(skb)->nexthdr;

	while (offset + 1 <= packet_len) {

		switch (**nexthdr) {

		case NEXTHDR_HOP:
			break;
		case NEXTHDR_ROUTING:
			found_rhdr = 1;
			break;
		case NEXTHDR_DEST:
			if (found_rhdr)
				return offset;
			break;
		default:
			return offset;
		}

		offset += ipv6_optlen(exthdr);
		*nexthdr = &exthdr->nexthdr;
		exthdr = (struct ipv6_opt_hdr *)(skb_network_header(skb) +
						 offset);
	}

	return offset;
}

/* modified from net/ipv6/ip6_output.c */
static void ipv6_select_ident_local(struct frag_hdr *fhdr)
{
	static atomic_t ipv6_fragmentation_id;
	int old, new;

	do {
		old = atomic_read(&ipv6_fragmentation_id);
		new = old + 1;
		if (!new)
			new = 1;
	} while (atomic_cmpxchg(&ipv6_fragmentation_id, old, new) != old);
	fhdr->identification = htonl(new);
}

void udp6_insert_frag_header(struct sk_buff *skb)
{
	unsigned int unfrag_ip6hlen;
	struct frag_hdr *fptr;
	u8 *prevhdr;
	u8 nexthdr;
	u8 frag_hdr_sz = sizeof(struct frag_hdr);

	/* Find the unfragmentable header and shift it left by frag_hdr_sz
	 * bytes to insert fragment header.
	 */
	unfrag_ip6hlen = ip6_find_1stfragopt_local(skb, &prevhdr);
	nexthdr = *prevhdr;
	*prevhdr = NEXTHDR_FRAGMENT;

	memmove(skb->transport_header + frag_hdr_sz,
		skb->transport_header, frag_hdr_sz);
	skb->transport_header += frag_hdr_sz;

	fptr = (struct frag_hdr *)(skb_network_header(skb) + unfrag_ip6hlen);
	fptr->nexthdr = nexthdr;
	fptr->reserved = 0;
	fptr->frag_off = 0;
	ipv6_select_ident_local(fptr);

	skb->len += frag_hdr_sz;
}
#endif

static int __pse_send(struct pse_ring *ring, struct sk_buff *skb, u8 pmap, u8 mymac, u8 ssid, u8 no_free_skb)
{
	struct pse_buffer_info *bi;
	volatile struct pse_ts_desc *desc;
	int err;
	int frag_count, no_of_desc, i;
	struct pse_skb_frag *nf;
#ifndef UFO_IGNORE_UDP_CHECKSUM
	struct iphdr *iph = ip_hdr(skb);
#endif

	frag_count = skb_shinfo(skb)->nr_frags + 1;
	no_of_desc = frag_count;

	spin_lock(&ring->lock);

	bi = ring->bi + ring->next_to_use;

	desc = (struct pse_ts_desc *) bi->desc;

	/* need to check if enough empty ts_desc */
	if (!pse_tx_desc_avail(ring, no_of_desc)) {
		P_TRACE("<%s>: No resource to send packet.\n",  __func__);
		spin_unlock(&ring->lock);
		return NETDEV_TX_BUSY;
	}

	if ((!no_free_skb) && bi->skb) {
		if (skb_shinfo(bi->skb)->nr_frags == 0) {
			pse_dma_unmap_single(ring->dev->dev.parent,
					 desc->sdp, desc->sdl, DMA_TO_DEVICE);
		} else {
			struct pse_skb_frag *nf;
			nf = &bi->frag_array[0];
			pse_dma_unmap_single(ring->dev->dev.parent,
					 nf->dma, nf->length, DMA_TO_DEVICE);
			for (i = 1; i < bi->frag_count; i++) {
				nf = &bi->frag_array[i];
				pse_dma_unmap_page(ring->dev->dev.parent, nf->dma,
					       nf->length, DMA_TO_DEVICE);
			}
		}

		dev_kfree_skb_any(bi->skb);
		bi->skb = NULL;
	}

	if (skb_is_gso(skb)) {
		if (ip_hdr(skb)->version == 4)
			skb_set_transport_header(skb, skb_network_offset(skb) + ip_hdrlen(skb));

		if (skb_header_cloned(skb)) {
			err = pskb_expand_head(skb, 0, 0, GFP_ATOMIC);
			if (err) {
				spin_unlock(&ring->lock);
				return err;
			}
		}
	}

	if (skb_is_gso(skb) && is_udp_pkt(skb)) {
		/* UFO , need software to calculate UDP checksum */
		unsigned int offset;

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
		if (ip_hdr(skb)->version == 6) {
			/* UFO doesn't support NO extention FRAG header */
			udp6_insert_frag_header(skb);
		}
#endif

		offset = skb_transport_offset(skb);
		skb->csum = 0;
		udp_hdr(skb)->check = 0;
#ifndef UFO_IGNORE_UDP_CHECKSUM
		if (ufo_cs_enable) {
			skb->csum =
				skb_checksum(skb, offset,
					     skb->len - offset, 0);

			if (ip_hdr(skb)->version == 4) {
				/* ipv4 */
				udp_hdr(skb)->check =
					csum_tcpudp_magic(iph->saddr,
							  iph->daddr,
							  skb->len - offset,
							  IPPROTO_UDP,
							  skb->csum);
			} else {
				/* IPV6 */
#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
				udp_hdr(skb)->check = csum_ipv6_magic(&ipv6_hdr(skb)->saddr,
								      &ipv6_hdr(skb)->daddr,
								      skb->len - offset,
								      IPPROTO_UDP,
								      skb->csum);
#endif
			}
		}
#endif
	}

	/* run destructor before passing skb to HW */
	if (likely(!skb_shared(skb)))
		skb_orphan(skb);

	if (skb_shinfo(skb)->nr_frags == 0) {
		/* not scatter gather */
		desc->sdl = skb->len;
		desc->sdp = pse_dma_map_single(ring->dev->dev.parent, skb->data,
						desc->sdl, DMA_TO_DEVICE);
		desc->fsd = 1;
		desc->lsd = 1;
		desc->fr = 1;
		if (0 == pmap)
			desc->pmap = ring->pmap;
		else
			desc->pmap = pmap;
		desc->ico = 1;
		desc->uco = 1;
		desc->tco = 1;
		desc->mymac = mymac;
		desc->ssid = ssid;

		if (skb_is_gso(skb)) {
			/* not scatter gather, gso */
			desc->mss_mtu = get_gso_mss_mtu(skb);
			desc->payload_len = get_gso_payload_len(skb);
			if (is_tcp_pkt(skb)) {
				/* TSO */
				desc->ufo = 0;
				desc->tso = 1;
			} else if (is_udp_pkt(skb)) {
				/* UFO */
				desc->tso = 0;
				desc->ufo = 1;
			}
		} else {
			/* not scatter gather, not gso */
			desc->tso = 0;
			desc->ufo = 0;
		}
		desc->cown = 0;
	} else {
		/* scatter gather */
		void *first_desc, *last_desc;
		struct pse_buffer_info *bi_tmp;


		pse_map_tx(ring, skb);
		bi_tmp = ring->bi;
		first_desc = bi_tmp->desc;
		bi_tmp = ring->bi + ring->ringsz - 1;
		last_desc = bi_tmp->desc;

		nf = &bi->frag_array[0];
		for (i = 0; i < frag_count; i++) {
			desc->sdp = nf[i].dma;
			desc->sdl = nf[i].length;

			if (i == 0) {
				/* first descriptor */

				desc->fsd = 1;
				desc->lsd = 0;

				/* Only need to fill in the first descriptor */
				desc->fr = 1;
				if (0 == pmap)
					desc->pmap = ring->pmap;
				else
					desc->pmap = pmap;
				desc->ico = 1;
				desc->uco = 1;
				desc->tco = 1;
				desc->mymac = mymac;
				desc->ssid = ssid;
				if (skb_is_gso(skb)) {
					/* scatter gather, gso */
					desc->mss_mtu = get_gso_mss_mtu(skb);
					desc->payload_len = get_gso_payload_len(skb);
					if (is_tcp_pkt(skb)) {
						/* TSO */
						desc->ufo = 0;
						desc->tso = 1;
					} else if (is_udp_pkt(skb)) {
						/* FO */
						desc->tso = 0;
						desc->ufo = 1;
					}
				} else {
					/* scatter gather, not gso */
					desc->tso = 0;
					desc->ufo = 0;
				}
			} else if (i == (frag_count - 1)) {
				/* last descriptor */
				desc->fsd = 0;
				desc->lsd = 1;
			} else {
				desc->fsd = 0;
				desc->lsd = 0;
			}
			desc->cown = 0;

			if (desc == (struct pse_ts_desc *)last_desc)
				desc = (struct pse_ts_desc *)first_desc;
			else
				desc++;
		}
	}

	wmb();

	/* Enable TS DMA */
	pse_ts_dma_enable(0x1 << ring->ring_id);

	if (!no_free_skb)
		bi->skb = skb; /* link for free skb */

	/* update next_to_use */
	ring->next_to_use += no_of_desc;

	ring->count++;

	if (ring->next_to_use >= ring->ringsz)
		ring->next_to_use -= ring->ringsz;

	spin_unlock(&ring->lock);


	return NETDEV_TX_OK;
};

int pse_send(struct pse_ring *ring, struct sk_buff *skb, u8 pmap)
{
	return __pse_send(ring, skb, pmap, 0, 0, 0);
}
