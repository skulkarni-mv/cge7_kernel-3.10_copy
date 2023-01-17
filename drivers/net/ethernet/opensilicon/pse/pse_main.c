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
static int pse_open(struct net_device *);
static int pse_close(struct net_device *);
static int pse_start_xmit(struct sk_buff *, struct net_device *);
static struct net_device_stats *pse_get_stats(struct net_device *);
static void pse_set_rx_mode(struct net_device *);
static int pse_set_mac(struct net_device *, void *);
static int pse_change_mtu(struct net_device *, int);
static int pse_ioctl(struct net_device *, struct ifreq *, int);

void *pse_base;

void *pse_base_fast;
struct pse_resource *pse_res;
EXPORT_SYMBOL(pse_res);
int pse_hibernation;
EXPORT_SYMBOL(pse_hibernation);
int pse_rx_ring_size = PSE_RX_RING_SIZE_DEFAULT;
int pse_tx_ring_size = PSE_TX_RING_SIZE_DEFAULT;
int pse_pkt_size = PSE_PACKET_SIZE_ALIGN;
struct pse_ring_alloc pse_ring_id[SW_FP_RING_MAX];
int pse_ring_count;

struct net_device *net_dev_array[PSE_MAX_DEV_NUM];
EXPORT_SYMBOL(net_dev_array);

#ifdef PSE_VLAN_SUPPORT
static bool vlan_full;
#endif

int is_pse_dev(struct net_device *dev)
{
	int i;
	for (i = 0; i < PSE_MAX_DEV_NUM; i++)
		if (dev == net_dev_array[i])
			return 1;
	return 0;
}
EXPORT_SYMBOL(is_pse_dev);

void pse_receive_skb(struct sk_buff *skb)
{
	netif_receive_skb(skb);
}

#ifdef PSE_DEBUG
static void dump_packet(struct pse_fs_desc *desc, struct sk_buff *skb)
{
	int i;
	u8 *ptr;

	P_TRACE("<%s>\n", __func__);
	P_TRACE("sdp 0x%.8x sdl %d l4f %d ipf %d\n", desc->sdp, desc->sdl, desc->l4f, desc->ipf);
	P_TRACE("prot %d lsd %d fsd %d eor %d cown %d\n", desc->prot, desc->lsd, desc->fsd, desc->eor, desc->cown);
	P_TRACE("pr 0x%x sp %d tc %d l4_offset %d l4_offset %d\n", desc->pr, desc->sp, desc->tc, desc->l4_offset, desc->ip_offset);

	ptr = skb->data;

	for (i = 0; i < 14; i++) {
		P_TRACE("0x%.2x ", *ptr);
		ptr++;
	}

	P_TRACE("\n");

	for (i = 0; i < 20; i++) {
		P_TRACE("0x%.2x ", *ptr);
		ptr++;
	}

	P_TRACE("\n");
}
#endif

/**
 * pse_receive_packet -
 * @ring:
 * @work_done:
 * @budget:
 *
 * Return PSE_OK on success, PSE_FAIL on failure
 **/
u32 pse_receive_packet(struct pse_ring *ring, u32 *work_done, u32 budget)
{
	struct pse_buffer_info *bi;
	struct pse_fs_desc *desc;
	struct sk_buff *skb;
	struct net_device *dev;
	u32 index, len, cleaned = 0;

	index = ring->next_to_clean;
#if 0
	P_TRACE("<%s> RX ring ID %d, start index %d\n", __func__, ring->ring_id, index);
#endif

	while (cleaned < budget) {
		bi = (ring->bi + index);
		desc = (struct pse_fs_desc *)bi->desc;

		if (!desc->cown) {
			/* no packet to receive */
			goto receive_complete;
		}

		skb = bi->skb;
		bi->skb = NULL;

		if (unlikely(!skb)) {
			P_WARN("No resource to receive packet.\n");
			P_WARN("    bi[%d], desc 0x%.8x cown %d\n",
					index, (u32)desc, desc->cown);

			goto next_desc;
		}

		len = desc->sdl;

		pse_dma_unmap_single(ring->dev->dev.parent, desc->sdp, len, DMA_FROM_DEVICE);
		skb_put(skb, len);
		skb_reserve(skb, NET_IP_ALIGN);
#ifdef PSE_DEBUG
		dump_packet(desc, skb);
#endif
		if (pse_pre_process(skb, desc, ring))
			goto next_desc;

		dev = skb->dev;
#ifdef PSE_SUPPORT_MQ
		skb_record_rx_queue(skb, desc->sp ? (ring->ring_id - PSE_MAX_RX_QUEUE) : ring->ring_id);
#endif
		wmb();

		pse_receive_skb(skb);
		dev->stats.rx_bytes += len;
		dev->stats.rx_packets++;
		ring->count++;
next_desc:
		cleaned++; /* this variable is for resource allocation, so move to here */
		index++;
		if (ring->ringsz == index) {
			/* reach the end of ring */
			index = 0;
		}
	}

receive_complete:
	if (cleaned) {
		/* allocate resource for received buffer */
		pse_alloc_rx_buffer(ring->dev, ring, cleaned);
	}

	ring->next_to_clean = index;

	*work_done = cleaned;

	return PSE_OK;
}

int pse_napi_polling(struct napi_struct *napi, int budget)
{
	struct net_device *dev = napi->dev;
	struct pse_priv *priv = netdev_priv(dev);
	struct pse_resource *res = priv->res;
	struct pse_ring *ring;
	u32 work_done = 0;
	unsigned long flag;

	P_TRACE("<%s>\n", __func__);
	ring = container_of(napi, struct pse_ring, napi);
	pse_receive_packet(ring, &work_done, budget);

	if (work_done < budget) {
		napi_complete(napi);
		pse_fs_dma_enable((0x1 << ring->ring_id));
		/* unmask interrupt */
		spin_lock_irqsave(&res->fs_intr_lock, flag);
		pse_fs_intr_unmask(ring->ring_id);
		spin_unlock_irqrestore(&res->fs_intr_lock, flag);
		P_TRACE("<%s> receive complete\n", __func__);

	}
	pse_fs_dma_enable((0x1 << ring->ring_id));
	return work_done;
}

#if defined(CONFIG_VLAN_8021Q) || defined(CONFIG_VLAN_8021Q_MODULE)
#define PSE_PKT_ADD_SIZE (ETH_HLEN + ETH_FCS_LEN + VLAN_HLEN)
#else
#define PSE_PKT_ADD_SIZE (ETH_HLEN + ETH_FCS_LEN)
#endif
static int pse_open(struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	int weight = pse_rx_ring_size >> 1;
	int i, err;

	if (priv->rx_ring[0] && priv->tx_ring[0])
		goto skip_init_hw;

	/* allocate TX ring */
	err = pse_tx_ring_init(priv, pse_tx_ring_size);
	if (err) {
		pr_err("<%s> (%s) fail to allcoate tx ring.\n",
			__func__, dev->name);
		goto fail_alloc_tx_ring;
	}

	/* allocate RX ring */
	pse_pkt_size = ((dev->mtu + PSE_PKT_ADD_SIZE) > PSE_PACKET_SIZE_ALIGN) ?
					PSE_JUMBO_FRAME_MAX_SIZE : PSE_PACKET_SIZE_ALIGN;

	err = pse_rx_ring_init(priv, pse_rx_ring_size, pse_pkt_size);
	if (err) {
		pr_err("<%s> (%s) fail to allcoate rx ring.\n",
			__func__, dev->name);
		goto fail_alloc_rx_ring;
	}

	pse_ring_init_hw(priv);

	/* set maximum packet length */
	pse_set_max_frame_len(priv->sp, pse_pkt_size);

	for (i = 0; i < PSE_MAX_RX_QUEUE; i++)
		/* NAPI */
		netif_napi_add(dev, &priv->rx_ring[i]->napi,
				pse_napi_polling, weight);

skip_init_hw:
	for (i = 0; i < PSE_MAX_RX_QUEUE; i++)
		napi_enable(&priv->rx_ring[i]->napi);

	/* PHY control start*/
	/**/
	pse_phy_init(priv);
	pse_phy_start(dev);

	netif_carrier_on(dev);
#ifdef PSE_SUPPORT_MQ
	netif_tx_start_all_queues(dev);
#else
	netif_start_queue(dev);
#endif
	set_bit(__LINK_STATE_START, &dev->state);

	for (i = 0; i < PSE_MAX_RX_QUEUE; i++)
		pse_fs_intr_unmask(priv->rx_ring[i]->ring_id);

	/* Disable ts interrupt by default */
	for (i = 0; i < PSE_MAX_TX_QUEUE; i++)
		pse_ts_intr_mask(priv->tx_ring[i]->ring_id);

	pse_port_cfg(priv->sp, true);

	return 0;

fail_alloc_rx_ring:
	for (i = 0; i < PSE_MAX_TX_QUEUE; i++)
		pse_free_tx_ring(priv->tx_ring[i]);
fail_alloc_tx_ring:
	return err;

};

static int pse_close(struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	int i;

	/* mac port disable */
	pse_port_cfg(priv->sp, false);

	for (i = 0; i < PSE_MAX_RX_QUEUE; i++) {
		pse_fs_intr_mask(priv->rx_ring[i]->ring_id);
		napi_disable(&priv->rx_ring[i]->napi);
	}

#ifdef PSE_SUPPORT_MQ
	netif_tx_stop_all_queues(dev);
#else
	netif_stop_queue(dev);
#endif
	netif_carrier_off(dev);

	pse_phy_stop(dev);

	/* DO NOT free ts/fs ring until driver get removed */

	return 0;
};

static int pse_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	struct pse_resource *res = priv->res;
	struct pse_ring *ring;
	int ret;
	unsigned long flag;
#ifdef PSE_SUPPORT_MQ
	int queue;
	struct netdev_queue *txq;
	queue = skb_get_queue_mapping(skb);
	txq = netdev_get_tx_queue(dev, queue);
	ring = priv->tx_ring[queue];
#else
	ring = priv->tx_ring[0]; /* Default tx_ring[0] */
#endif

	ret = pse_send(ring, skb, 0);

	if (ret == NETDEV_TX_OK) {
		dev->stats.tx_bytes += skb->len;
		dev->stats.tx_packets++;
	} else {
		/* should be NETDEV_TX_BUSY */
#ifdef PSE_SUPPORT_MQ
		netif_tx_stop_queue(txq);
#else
		netif_stop_queue(ring->dev);
#endif

		spin_lock_irqsave(&res->ts_intr_lock, flag);
		/* Enable ts interrupt */
		pse_ts_intr_unmask(ring->ring_id);
		spin_unlock_irqrestore(&res->ts_intr_lock, flag);
	}

	return ret;
};

static struct net_device_stats *pse_get_stats(struct net_device *dev)
{
	return &dev->stats;
};

static void pse_set_rx_mode(struct net_device *dev)
{
	struct pse_priv *priv = netdev_priv(dev);
	u32 val;
	val = rd32(MAC_CHECK_CFG);

#if defined(CONFIG_IPV6) || defined(CONFIG_IPV6_MODULE)
	if (priv->sp) {
		val &= ~(0x3 << 4);
		val |= (0x2 << 4); /* MAC 1 is promiscous mode */
	} else {
		val &= ~(0x3 << 2);
		val |= (0x2 << 2); /* MAC 0 is promiscous mode */
	}
#else
	if (dev->flags & IFF_PROMISC) {
		if (priv->sp) {
			val &= ~(0x3 << 4);
			val |= (0x2 << 4); /* MAC 1 is promiscous mode */
		} else {
			val &= ~(0x3 << 2);
			val |= (0x2 << 2); /* MAC 0 is promiscous mode */
		}
	} else {
		if (priv->sp) {
			val &= ~(0x3 << 4);
			val |= (0x1 << 4);
		} else {
			val &= ~(0x3 << 2);
			val |= (0x1 << 2);
		}
	}
#endif
	wr32(val, MAC_CHECK_CFG);

};

static int pse_set_mac(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;
	struct pse_priv *priv;
	struct pse_mac pse_mac;

	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	priv = netdev_priv(dev);
	pse_mac.port = priv->sp;
	pse_mac.index = 0;
	pse_mac_read(&pse_mac);
	memcpy(pse_mac.mac, addr->sa_data, dev->addr_len);
	pse_mac_write(&pse_mac);

	return 0;
}


static int pse_change_mtu(struct net_device *dev, int new_mtu)
{
	struct pse_priv *priv = netdev_priv(dev);
	int max_frame = new_mtu + ETH_HLEN + ETH_FCS_LEN;
	int up = 0;
	int i;

	/* TODO */
	if (max_frame < 64 || max_frame > PSE_JUMBO_FRAME_MAX_SIZE)
		return -EINVAL;

	max_frame = (max_frame > PSE_PACKET_SIZE_ALIGN) ? PSE_JUMBO_FRAME_MAX_SIZE : PSE_PACKET_SIZE_ALIGN;
	pse_set_max_frame_len(priv->sp, max_frame);

	dev->mtu = new_mtu;

	if (netif_running(dev)) {
		pse_port_cfg(priv->sp, false);
		mdelay(500);
		pse_close(dev);
		up = 1;
	}

	pse_pkt_size = max_frame;
	for (i = 0; i < PSE_MAX_RX_QUEUE; i++) {
		if (priv->rx_ring[i]) {
			if (priv->rx_ring[i]->pktsz != pse_pkt_size) {
				/* reset rx buffer packet size */
				priv->rx_ring[i]->pktsz = pse_pkt_size;
				pse_reset_rx_buffer_pktsz(priv->rx_ring[i]);
			}
		}
	}
	if (up)
		pse_open(dev);

	return 0;
}

static int pse_ioctl(struct net_device *dev, struct ifreq *ifr, int cmd)
{
	/* if use PHYLIB, call phy_mii_ioctl() */
	struct pse_priv *priv = netdev_priv(dev);

	if (priv->phy_dev)
		return phy_mii_ioctl(priv->phy_dev, ifr, cmd);

	return -EOPNOTSUPP;
};

#ifdef PSE_VLAN_SUPPORT
static int pse_vlan_rx_add_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct pse_priv *priv = netdev_priv(dev);

	if (!vlan_full && !pse_vlan_used(priv))
		pse_vlan_filter_on_off(priv, true);

	set_bit(vid, priv->active_vlans);

	if (!vlan_full && pse_add_vlan(priv, vid) == PSE_FAIL) {
		/* need be taken care when over 64 tables */
		vlan_full = true;
		pse_vlan_reset();
		pse_vlan_filter_on_off(priv, false);
	}

	return 0;
}

static int pse_vlan_rx_kill_vid(struct net_device *dev, __be16 proto, u16 vid)
{
	struct pse_priv *priv = netdev_priv(dev);

	clear_bit(vid, priv->active_vlans);

	if (!vlan_full) {
		pse_del_vlan(priv, vid);
		if (!pse_vlan_used(priv)) {
			/* if already no vlan, turn off filter */
			pse_vlan_filter_on_off(priv, false);
		}
	}

	return 0;
}
#endif

#ifdef PSE_SUPPORT_MQ
#include <linux/ip.h>
#define BY_DSCP
u16 pse_select_queue(struct net_device *dev, struct sk_buff *skb)
{
	struct pse_priv *priv = netdev_priv(dev);
	int dscp;
	int queue = priv->sp;
#ifdef BY_DSCP
	/* BY DSCP */
	/*
	   DSCP = 0 ...  => Q0
	   DSCP = 8 ...  => Q1
	   DSCP = 16 ... => Q2
	   DSCP = 24 ... => Q3
	   DSCP = 32 ... => Q4
	   DSCP = 40 ... => Q5
	   DSCP = 48 ... => Q6
	   DSCP = 56 ... => Q7
	*/
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		dscp = ip_hdr(skb)->tos & 0xfc;
		dscp = dscp >> 2;
		queue = dscp >> 3;
		break;
	default:
		break;
	}
#endif

	return queue;
}
#endif

static const struct net_device_ops pse_netdev_ops = {
	.ndo_open			= pse_open,
	.ndo_stop			= pse_close,
	.ndo_start_xmit			= pse_start_xmit,
	.ndo_get_stats			= pse_get_stats,
	.ndo_set_rx_mode		= pse_set_rx_mode,
	.ndo_set_mac_address		= pse_set_mac,
	.ndo_change_mtu			= pse_change_mtu,
	.ndo_do_ioctl			= pse_ioctl,
	.ndo_validate_addr		= eth_validate_addr,
#ifdef PSE_VLAN_SUPPORT
	.ndo_vlan_rx_add_vid		= pse_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid		= pse_vlan_rx_kill_vid,
#endif
#ifdef PSE_SUPPORT_MQ
	.ndo_select_queue		= pse_select_queue,
#endif
};

static int pse_probe(struct platform_device *pdev)
{
	struct net_device *dev = NULL;
	struct pse_priv *priv;
	struct pse_resource *res; /* TODO we have to initi pse_resource first */
	struct resource *res_mem, *res_mem_fast, *res_irq;
	struct pse_platform_data *pdata;
	struct pse_mac_data *macd;
	int ret, i;

	pr_info("%s - version %s\n", DRV_STRING, DRV_VERSION);
	pr_info("%s\n", DRV_COPYRIGHT);

	ret = -EINVAL;

	/* general memory */
	res_mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	if (!res_mem) {
		/* TODO debug message */
		goto out;
	}

	res_mem_fast = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res_mem_fast) {
		/* TODO debug message */
		goto out;
	}

	res_irq = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!res_irq) {
		/* TODO debug message */
		goto out;
	}

	ret = -ENOMEM;

	res = kzalloc(sizeof(*res), GFP_KERNEL);

	if (!res) {
		P_ERR("alloc pse_resource fail!");
		goto out;
	}

	pse_res = res;

	res->irq_start = res_irq->start;
	res->irq_end = res_irq->end;
	res->pdev = pdev;

	pse_base = ioremap_nocache(res_mem->start, SZ_4K);
	pse_base_fast = ioremap_nocache(res_mem_fast->start, SZ_4K);

	res->base = pse_base;
	res->base_fast = pse_base_fast;

	if (pse_irq_init(res)) {
		dev_err(&pdev->dev, "request_irq failed\n");
		ret = -EAGAIN;
		kfree(res);
		goto out;
	}

	pse_status_intr_cfg(0x100);

	pdata = pdev->dev.platform_data;

	pse_sys_init(pdata);

	if (pse_mii_init(res)) {
		P_ERR("mii init fail!");
		ret = -EIO;
		kfree(res);
		goto out;
	}

	/* allocate device */
	for (i = 0; i < PSE_MAX_DEV_NUM; i++) {
		macd = pdata->port + i;

		if (!(macd->enable))
			continue;

		dev = alloc_etherdev_mq(
			sizeof(struct pse_priv), PSE_MAX_TX_QUEUE);
		if (!dev) {
			P_ERR("Cannot allocate device (%d)\n", i);
			/* TODO terminate init process and report to user */
		}

		SET_NETDEV_DEV(dev, &pdev->dev);
		net_dev_array[i] = dev;
		/* set MAC address */
		memcpy(dev->dev_addr, default_mac.mac[i].mac, ETH_ALEN);

		dev->netdev_ops = &pse_netdev_ops;
		priv = netdev_priv(dev);
		memset(priv, 0, sizeof(struct pse_priv));

		priv->res = res;
		priv->netdev = dev;
		priv->sp = macd->sp;
		priv->index = i;
		priv->wan_port = macd->wan_port;
		if (macd->has_phy) {
			P_TRACE("MAC port %d has PHY\n", i);
			priv->phy_addr = macd->phy_addr;
			priv->pse_flags = PSE_FLAG_PHY_CONNECTED;
		} else {
			priv->phy_addr = macd->phy_addr;
		}

		pse_set_ethtool_ops(dev);

#ifdef PSE_CHECKSUM_OFFLOAD
		dev->hw_features |= NETIF_F_IP_CSUM | NETIF_F_IPV6_CSUM | NETIF_F_RXCSUM;
#endif
#ifdef PSE_SG_SUPPORT
		dev->hw_features |= NETIF_F_SG;
#endif
#ifdef PSE_TSO_SUPPORT
		if (PSE_TSO_EN_DEFAULT)
			dev->hw_features |= NETIF_F_TSO | NETIF_F_TSO6;
#endif
#ifdef PSE_UFO_SUPPORT
		if (PSE_UFO_EN_DEFAULT)
			dev->hw_features |= NETIF_F_UFO;
#endif
		dev->features |= dev->hw_features;

#ifdef PSE_VLAN_SUPPORT
		dev->vlan_features |= dev->hw_features;
		dev->features |= NETIF_F_HW_VLAN_CTAG_FILTER;
#endif

		/* register device */
		if (register_netdev(dev)) {
			P_ERR("Cannot register device (%d)\n", i);
			SET_NETDEV_DEV(dev, NULL);
			free_netdev(dev);
			/* TODO terminate init process and report to user */
		} else {
			res->ndev[i] = dev;
		}
	}

	platform_set_drvdata(pdev, res);

	pse_proc_init();

	pse_sysfs_init(pdev);

	pse_acp_cfg(true);

	pse_debug_init();

	ret = 0;
out:
	return ret;
}

#ifdef CONFIG_PM
void pse_interrupt_mask(void)
{
	fwr32(0xFFFFFFFF, FS_STATUS_INTR_MASK);
	fwr32(0xFFFFFFFF, FS_STATUS_INTR);
#ifdef PSE_HAS_TS_INTR
	fwr32(0xFFFFFFFF, TS_STATUS_INTR_MASK);
	fwr32(0xFFFFFFFF, TS_STATUS_INTR);
#endif
#ifdef PSE_HAS_STATUS_INTR
	fwr32(0xFFFFFFFF, STATUS_INTR_MASK);
	fwr32(0xFFFFFFFF, STATUS_INTR);
#endif
}

static int pse_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct pse_resource *res = platform_get_drvdata(pdev);
	struct net_device *ndev;
	struct lro_resource *lro_res = &res->lro_res;
	int i;

	pse_interrupt_mask();

	for (i = 0; i < PSE_MAX_DEV_NUM; i++) {
		ndev = res->ndev[i];
		if (ndev) {
			if (!netif_running(ndev))
				continue;
			pse_close(ndev);
		}
	}

	pse_mii_fini(res);
	pse_sys_reset();
	pse_dma_idle();

	for (i = 0; i < SW_FP_RING_MAX; i++)
		pse_ring_id[i].ring_id = -1;

	pse_ring_count = 0;

	/* free FS/TS ring*/
	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		if (res->rx_ring[i]) {
			pse_hibernation = 1;
			pse_free_rx_ring(res->rx_ring[i]);
		}
	}

	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		if (res->tx_ring[i])
			pse_free_tx_ring(res->tx_ring[i]);
	}

	return 0;
}

static int pse_resume(struct platform_device *pdev)
{
	struct pse_priv *priv;
	struct pse_platform_data *pdata;
	struct net_device *ndev;
	struct pse_resource *res = platform_get_drvdata(pdev);
	int i;
	u32 ret;

	pse_interrupt_mask();

	pse_status_intr_cfg(0x100);

	pdata = pdev->dev.platform_data;

	pse_sys_init(pdata);


	if (pse_mii_init(res)) {
		P_ERR("mii init fail!");
		ret = -EIO;
		kfree(res);
		goto out;
	}

	pse_acp_cfg(true);

	for (i = 0; i < PSE_MAX_DEV_NUM; i++) {
		ndev = res->ndev[i];
		if (ndev) {
			if (!netif_running(ndev))
				continue;
			priv = netdev_priv(ndev);
			priv->rx_ring[0] = NULL;
			priv->tx_ring[0] = NULL;
			pse_open(ndev);
		}
	}

	return 0;
out:
	return ret;
}
#else
#define pse_suspend NULL
#define pse_resume NULL
#endif

static int pse_remove(struct platform_device *pdev)
{
	struct net_device *dev;
	struct pse_resource *res;
	int i;

	pse_debug_fini();

	res = platform_get_drvdata(pdev);
	BUG_ON(!res);

	pse_proc_fini();

	pse_sysfs_finit(pdev);
	pse_mii_fini(res);
	pse_irq_fini(res);

	for (i = 0; i < PSE_MAX_DEV_NUM; i++) {
		dev = res->ndev[i];
		if (dev) {
			unregister_netdev(dev);
			free_netdev(dev);
		}
	}
	pse_sys_reset();

	/* keep PSE DMA idle */
	pse_dma_idle();

	/* free FS/TS ring*/
	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		if (pse_res->rx_ring[i])
			pse_free_rx_ring(pse_res->rx_ring[i]);
	}

	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		if (pse_res->tx_ring[i])
			pse_free_tx_ring(pse_res->tx_ring[i]);
	}

	kfree(res);
	platform_set_drvdata(pdev, NULL);
	return 0;
}


static struct platform_driver opv5xc_pse_driver = {
	.driver.name = DRV_NAME,
	.probe = pse_probe,
	.remove = pse_remove,
	.suspend = pse_suspend,
	.resume = pse_resume,
};

module_platform_driver(opv5xc_pse_driver);

MODULE_DESCRIPTION("Open-Silicon OPV5XC Gigabit Ethernet Driver");
MODULE_LICENSE("GPL");

module_param(pse_rx_ring_size, int, 0444);
MODULE_PARM_DESC(pse_rx_ring_size, "RX Ring Size");
module_param(pse_tx_ring_size, int, 0444);
MODULE_PARM_DESC(pse_tx_ring_size, "TX Ring Size");
module_param(pse_pkt_size, int, 0444);
MODULE_PARM_DESC(pse_pkt_size, "Packet Size");

module_param_named(mac0addr, pse_mac_ethaddr[0], charp, 0444);
MODULE_PARM_DESC(mac0addr, "initial MAC address for MAC0");
#if OPV5XC_MAC_MAX > 1
module_param_named(mac1addr, pse_mac_ethaddr[1], charp, 0444);
MODULE_PARM_DESC(mac0addr, "initial MAC address for MAC1");
#endif
#if OPV5XC_MAC_MAX > 2
module_param_named(mac1addr, pse_mac_ethaddr[2], charp, 0444);
MODULE_PARM_DESC(mac0addr, "initial MAC address for MAC2");
#endif
