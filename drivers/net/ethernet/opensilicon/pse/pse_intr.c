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

#define PSE_HAS_TS_INTR
#define PSE_HAS_STATUS_INTR

#if defined(CONFIG_ARCH_OPV5XC_CX4)
static void __iomem *cnx_misc_base_fpga;

/**
 * pse_fs_isr - FS Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t pse_fs_isr(int irq, void *data)
{
	struct pse_resource *res = (struct pse_resource *) data;
	struct pse_ring *ring;
	u32 i, reg;

	P_TRACE("PSE interrupt ID %d\n", irq);

	reg = readl(cnx_misc_base_fpga + 0xE0C);

	P_TRACE("PSE interrupt status %d\n", reg);

	/* TODO check intr status and to get rx ring */
	reg = frd32(FS_STATUS_INTR);

	P_TRACE("FS_STATUS_INTR Reg: 0x%.8x\n", reg);

	reg &= ~frd32(FS_STATUS_INTR_MASK);

	fwr32(reg, FS_STATUS_INTR);

	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		if (reg &  (0x3 << (i << 1))) {
			P_TRACE("to get ring %d\n", i);
			ring = res->rx_ring[i];
			if (NULL == ring) {
				P_ERR("<%s> FS ring %d is NULL!\n", __func__, i);
				P_ERR("<%s> FS_STATUS_INTR 0x%.8x FS_STATUS_INTR_MASK 0x%.8x\n",
					__func__, reg, frd32(FS_STATUS_INTR_MASK));
				continue;
			}

			/* schedule NAPI */
			if (likely(napi_schedule_prep(&ring->napi))) {
				/* mask FS interrupt */
				pse_fs_intr_mask(i);
				P_TRACE("try to schedule napi **\n");
				__napi_schedule(&ring->napi);
			}
		}
	}

	return IRQ_HANDLED;
}

#ifdef PSE_HAS_TS_INTR
/**
 * pse_ts_isr - TS Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t pse_ts_isr(int irq, void *data)
{
	struct pse_resource *res = (struct pse_resource *) data;
	struct pse_ring *ring;
	u32 reg;
	int i;
	struct net_device *dev;
#ifdef PSE_SUPPORT_MQ
	struct netdev_queue *txq;
	int queue;
	struct pse_priv *priv;
#endif

	P_TRACE("PSE interrupt ID %d\n", irq);

	reg = readl(cnx_misc_base_fpga + 0xE0C);

	P_TRACE("PSE interrupt status %d\n", reg);

	reg = frd32(TS_STATUS_INTR);
	P_TRACE("TS_STATUS_INTR Reg: 0x%.8x\n", reg);
	reg &= ~frd32(TS_STATUS_INTR_MASK);
	fwr32(reg, TS_STATUS_INTR);

	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		if (reg &  (0x3 << (i << 1))) {
			ring = res->tx_ring[i];
			if (!ring)
				continue;
			dev = ring->dev;
			if (!dev)
				continue;
#ifdef PSE_SUPPORT_MQ
			priv = netdev_priv(dev);
			queue = priv->sp ? (i - PSE_MAX_TX_QUEUE) : i;
			txq = netdev_get_tx_queue(dev, queue);

			if (netif_tx_queue_stopped(txq)) {
				if (pse_tx_desc_avail(ring, ring->ringsz / 2)) {
					netif_tx_wake_queue(txq);
					pse_ts_intr_mask(i);
				}
			}
#else
			if (netif_queue_stopped(dev)) {
				if (pse_tx_desc_avail(ring, ring->ringsz / 2)) {
					netif_wake_queue(dev);
					pse_ts_intr_mask(i);
				}
			}
#endif
		}
	}

	return IRQ_HANDLED;
}
#endif

#ifdef PSE_HAS_STATUS_INTR
/**
 * pse_status_isr - Status Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
#define PSE_QUEUE_MIB_CNT_MAX	(8)
#define PSE_QUEUE_MAX    8
#define PSE_PORT_MAX 3
#undef DUMP_QOS_MIB
static irqreturn_t pse_status_isr(int irq, void *data)
{
	u32 reg;
	P_TRACE("PSE interrupt ID %d\n", irq);
	reg = frd32(STATUS_INTR);
	P_TRACE("STATUS_INTR Reg: 0x%.8x\n", reg);

	/* TODO: TBD */
#ifdef DUMP_QOS_MIB
	if (reg & 0x100) {
		/* MIB_SAMPLE_INTERVAL */
		int port;
		int j, k;
		int val;
		for (port = 0; port < PSE_PORT_MAX; port++) {
			pr_dbg("port = %d\n", port);
			for (j = 3; j < PSE_QUEUE_MIB_CNT_MAX; j++) {
				pr_cont("%d\t", j);
				for (k = 0; k < PSE_QUEUE_MAX; k++) {
					val =  (k << 9) |
						(j << 4) |
						(port);
					fwr32(val, MIB_CNT_CMD);
					while (val & (1 << 15))
						val = frd32(MIB_CNT_CMD);
					pr_cont("0x%.8x ", frd32(MIB_CNT_3100));
				}
				pr_cont("\n");
			}
		}
	}
#endif
	/* clear interrrupt status */
	fwr32(reg, STATUS_INTR);
	return IRQ_HANDLED;
}
#endif

static int irq_init_fpga(struct pse_resource *res)
{
	u32 irq;
	int err;

	cnx_misc_base_fpga = (void __iomem *)OPV5XC_MISC_BASE_VIRT;

	/* FS */
	fwr32(0xFFFFFFFF, FS_STATUS_INTR);
	irq = res->irq_start;
	err = request_irq(irq, pse_fs_isr, IRQF_SHARED, "pse_fs", res);
	if (err) {
		P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
		goto err_request_irq;
	}
	fwr32(0xFFFFFFFF, FS_STATUS_INTR_MASK);

#ifdef PSE_HAS_TS_INTR
	/* TS */
	fwr32(0xFFFFFFFF, TS_STATUS_INTR);
	irq = res->irq_start + 2;
	err = request_irq(irq, pse_ts_isr, IRQF_SHARED, "pse_ts", res);
	if (err) {
		P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
		goto err_request_irq;
	}
	fwr32(0xFFFFFFFF, TS_STATUS_INTR_MASK);
#endif

#ifdef PSE_HAS_STATUS_INTR
	/* Status */
	fwr32(0xFFFFFFFF, STATUS_INTR);
	irq = res->irq_start + 4;
	err = request_irq(irq, pse_status_isr, IRQF_SHARED, "pse_status", res);
	if (err) {
		P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
		goto err_request_irq;
	}

	fwr32(0xFFFFFFFF, STATUS_INTR_MASK);
#endif

	return 0;

err_request_irq:
	return -1;
}

static void irq_fini_fpga(struct pse_resource *res)
{
	u32 irq;
	/* FS */
	irq = res->irq_start;
	free_irq(irq, res);

#ifdef PSE_HAS_TS_INTR
	/* TS */
	irq = res->irq_start + 2;
	free_irq(irq, res);
#endif

#ifdef PSE_HAS_STATUS_INTR
	/* Status */
	irq = res->irq_start + 4;
	free_irq(irq, res);
#endif
}
#else
/**
 * pse_fs_isr - FS Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t pse_fs_isr(int irq, void *data)
{
	struct pse_resource *res = (struct pse_resource *) data;
	struct pse_ring *ring;
	u32 i, reg;

	P_TRACE("PSE interrupt ID %d\n", irq);

	spin_lock(&res->fs_intr_lock);
	reg = frd32(FS_STATUS_INTR);

	P_TRACE("FS_STATUS_INTR Reg: 0x%.8x\n", reg);

	reg &= ~frd32(FS_STATUS_INTR_MASK);
	reg &= res->fs_intr_group[IRQ_OPV5XC_PPE_FS_DMA_C0 - irq];

	fwr32(reg, FS_STATUS_INTR);
	spin_unlock(&res->fs_intr_lock);

	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		if (reg &  (0x3 << (i << 1))) {
			P_TRACE("to get ring %d\n", i);
			ring = res->rx_ring[i];
			if (NULL == ring) {
				P_ERR("<%s> FS ring %d is NULL!\n", __func__, i);
				P_ERR("<%s> FS_STATUS_INTR 0x%.8x FS_STATUS_INTR_MASK 0x%.8x\n",
					__func__, reg, frd32(FS_STATUS_INTR_MASK));
				continue;
			}

			/* schedule NAPI */
			if (likely(napi_schedule_prep(&ring->napi))) {
				/* mask FS interrupt */
				spin_lock(&res->fs_intr_lock);
				pse_fs_intr_mask(i);
				spin_unlock(&res->fs_intr_lock);
				P_TRACE("try to schedule napi **\n");
				__napi_schedule(&ring->napi);
			}
		}
	}

	return IRQ_HANDLED;
}

#ifdef PSE_HAS_TS_INTR
/**
 * pse_ts_isr - TS Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
static irqreturn_t pse_ts_isr(int irq, void *data)
{
	struct pse_resource *res = (struct pse_resource *) data;
	struct pse_ring *ring;
	u32 reg;
	int i;
	struct net_device *dev;
#ifdef PSE_SUPPORT_MQ
	struct netdev_queue *txq;
	int queue;
	struct pse_priv *priv;
#endif

	P_TRACE("PSE interrupt ID %d\n", irq);

	spin_lock(&res->ts_intr_lock);

	reg = frd32(TS_STATUS_INTR);

	reg &= ~frd32(TS_STATUS_INTR_MASK);

	P_TRACE("TS_STATUS_INTR Reg: 0x%.8x\n", reg);

	reg &= res->ts_intr_group[IRQ_OPV5XC_PPE_TS_DMA_C0 - irq];

	fwr32(reg, TS_STATUS_INTR);

	spin_unlock(&res->ts_intr_lock);

	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		if (reg &  (0x3 << (i << 1))) {
			ring = res->tx_ring[i];
			if (!ring)
				continue;
			dev = ring->dev;
			if (!dev)
				continue;
#ifdef PSE_SUPPORT_MQ
			priv = netdev_priv(dev);
			queue = priv->sp ? (i - PSE_MAX_TX_QUEUE) : i;
			txq = netdev_get_tx_queue(dev, queue);

			if (netif_tx_queue_stopped(txq)) {
				if (pse_tx_desc_avail(ring, ring->ringsz / 2)) {
					netif_tx_wake_queue(txq);
					spin_lock(&res->ts_intr_lock);
					pse_ts_intr_mask(i);
					spin_unlock(&res->ts_intr_lock);
				}
			}
#else
			if (netif_queue_stopped(dev)) {
				if (pse_tx_desc_avail(ring, ring->ringsz / 2)) {
					netif_wake_queue(dev);
					spin_lock(&res->ts_intr_lock);
					pse_ts_intr_mask(i);
					spin_unlock(&res->ts_intr_lock);
				}
			}
#endif
		}
	}

	return IRQ_HANDLED;
}
#endif

#ifdef PSE_HAS_STATUS_INTR
/**
 * pse_status_isr - Status Interrupt Handler
 * @irq: interrupt number
 * @data: pointer to a network interface device structure
 **/
#define PSE_QUEUE_MIB_CNT_MAX	(8)
#define PSE_QUEUE_MAX    8
#define PSE_PORT_MAX 3
#undef DUMP_QOS_MIB
static irqreturn_t pse_status_isr(int irq, void *data)
{
	u32 reg;
	P_TRACE("PSE interrupt ID %d\n", irq);
	reg = frd32(STATUS_INTR);
	P_TRACE("STATUS_INTR Reg: 0x%.8x\n", reg);

	/* TODO: TBD */
#ifdef DUMP_QOS_MIB
	if (reg & 0x100) {
		/* MIB_SAMPLE_INTERVAL */
		int port;
		int j, k;
		int val;
		for (port = 0; port < PSE_PORT_MAX; port++) {
			pr_dbg("port = %d\n", port);
			for (j = 3; j < PSE_QUEUE_MIB_CNT_MAX; j++) {
				pr_cont("%d\t", j);
				for (k = 0; k < PSE_QUEUE_MAX; k++) {
					val =  (k << 9) |
						(j << 4) |
						(port);
					fwr32(val, MIB_CNT_CMD);
					while (val & (1 << 15))
						val = frd32(MIB_CNT_CMD);
					pr_cont("0x%.8x ", frd32(MIB_CNT_3100));
				}
				pr_cont("\n");
			}
		}
	}
#endif
	/* clear interrrupt status */
	fwr32(reg, STATUS_INTR);
	return IRQ_HANDLED;
}
#endif

/* FIXME */
#define STATUS_INTR_OFFSET	(0)
#define LRO_BUF_EMPTY_OFFSET	(1)
#define TS_INTR_OFFSET		(2)
#define LRO_INTR_OFFSET		(6)
#define FS_INTR_OFFSET		(10)

const char *intr_name[] = {
	"OPV5XC_PSE_STATUS",
	"OPV5XC_LRO_BUF_EMPTY",
	"OPV5XC_PSE_TS_DMA_C3",
	"OPV5XC_PSE_TS_DMA_C2",
	"OPV5XC_PSE_TS_DMA_C1",
	"OPV5XC_PSE_TS_DMA_C0",
	"OPV5XC_PSE_LRO_DMA_C3",
	"OPV5XC_PSE_LRO_DMA_C2",
	"OPV5XC_PSE_LRO_DMA_C1",
	"OPV5XC_PSE_LRO_DMA_C0",
	"OPV5XC_PSE_FS_DMA_C3",
	"OPV5XC_PSE_FS_DMA_C2",
	"OPV5XC_PSE_FS_DMA_C1",
	"OPV5XC_PSE_FS_DMA_C0",
};

#define PSE_FS_INTR_MAX		(4)
#define PSE_TS_INTR_MAX		(4)
#define PSE_LRO_INTR_MAX	(4)

/* TODO support mulitiple interrupts for FS/TS/LRO  */
static int irq_init(struct pse_resource *res)
{
	u32 irq, i;
	int err;

	/* FS */
	spin_lock_init(&res->fs_intr_lock);
	fwr32(0xFFFFFFFF, FS_STATUS_INTR);
	irq = res->irq_start + FS_INTR_OFFSET;
	for (i = 0; i < PSE_FS_INTR_MAX; i++) {
		err = request_irq(irq, pse_fs_isr, IRQF_SHARED,
				intr_name[irq - res->irq_start], res);
		if (err) {
			P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
			goto err_request_irq;
		}
		irq++;
	}
	fwr32(0xFFFFFFFF, FS_STATUS_INTR_MASK);

#ifdef PSE_HAS_TS_INTR
	/* TS */
	spin_lock_init(&res->ts_intr_lock);
	fwr32(0xFFFFFFFF, TS_STATUS_INTR);
	irq = res->irq_start + TS_INTR_OFFSET;
	for (i = 0; i < PSE_TS_INTR_MAX; i++) {
		err = request_irq(irq, pse_ts_isr, IRQF_SHARED,
				intr_name[irq - res->irq_start], res);
		if (err) {
			P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
			goto err_request_irq;
		}
		irq++;
	}
	fwr32(0xFFFFFFFF, TS_STATUS_INTR_MASK);
#endif

#ifdef PSE_HAS_STATUS_INTR
	/* Status */
	fwr32(0xFFFFFFFF, STATUS_INTR);
	irq = res->irq_start + STATUS_INTR_OFFSET;
	err = request_irq(irq, pse_status_isr, IRQF_SHARED,
				intr_name[irq - res->irq_start], res);
	if (err) {
		P_ERR("Request_irq fail, interrupt ID: %d\n", irq);
		goto err_request_irq;
	}
	fwr32(0xFFFFFFFF, STATUS_INTR_MASK);
#endif

	return 0;

err_request_irq:
	return -1;
}

static void irq_fini(struct pse_resource *res)
{
	u32 irq, i;

	/* FS */
	irq = res->irq_start + FS_INTR_OFFSET;

	for (i = 0; i < PSE_FS_INTR_MAX; i++) {
		free_irq(irq, res);
		irq++;
	}

#ifdef PSE_HAS_TS_INTR
	/* TS */
	irq = res->irq_start + TS_INTR_OFFSET;

	for (i = 0; i < PSE_TS_INTR_MAX; i++) {
		free_irq(irq, res);
		irq++;
	}
#endif

#ifdef PSE_HAS_STATUS_INTR
	/* Status */
	irq = res->irq_start + STATUS_INTR_OFFSET;
	free_irq(irq, res);
#endif
}
#endif

int pse_irq_init(struct pse_resource *res)
{
#if defined(CONFIG_ARCH_OPV5XC_CX4)
	return irq_init_fpga(res);
#else
	return irq_init(res);
#endif
}

void pse_irq_fini(struct pse_resource *res)
{
#if defined(CONFIG_ARCH_OPV5XC_CX4)
	return irq_fini_fpga(res);
#else
	return irq_fini(res);
#endif
}
