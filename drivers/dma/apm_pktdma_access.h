/**
 *  APM86xxx PktDMA driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * Author: Shasi Pulijala <spulijala@apm.com>
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
 * This is the header file for APM PktDMA Linux device driver.
 *
 */
#ifndef __APM_PKTDMA_ACCESS_H__
#define __APM_PKTDMA_ACCESS_H__

#include <linux/types.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/async_tx.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/proc_fs.h>
#include <linux/of_platform.h>
#include <linux/highmem.h>
#include <linux/spinlock_types.h>
#include <asm/io.h>
#include <linux/errno.h>
#include "apm_pktdma_core.h"
#include "apm_dma_csr.h"
#include <asm/apm_pktdma.h>

#undef APM_PKTDMA_DEBUG
#undef APM_PKTDMA_DRXTX
#undef APM_PKTDMA_DUMP_TX
#undef APM_PKTDMA_DEBUG_XTRA

#define PKTDMA_HDR		"PKTDMA: "

#define PKTDMA_DUMP_MSG(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, PKTDMA_HDR hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
} while(0);

#ifdef APM_PKTDMA_DIAG
#define PKTDMA_DIAG(fmt, ...)		\
		printk(KERN_INFO PKTDMA_HDR fmt "\n", ##__VA_ARGS__);
#else
#define PKTDMA_DIAG(fmt, ...)
#endif

#ifdef APM_PKTDMA_DEBUG
#define PKTDMA_DEBUG(fmt, ...)		\
		printk(KERN_INFO PKTDMA_HDR fmt "\n", ##__VA_ARGS__);
#else
#define PKTDMA_DEBUG(fmt, ...)
#endif

#ifdef APM_PKTDMA_DCSR
#define PKTDMA_DCSR(fmt, ...)		\
		printk(KERN_INFO PKTDMA_HDR fmt "\n", ##__VA_ARGS__);
#else
#define PKTDMA_DCSR(fmt, ...)
#endif

#ifdef APM_PKTDMA_DRXTX
#define PKTDMA_DRXTX(fmt, ...)		\
		printk(KERN_INFO PKTDMA_HDR fmt "\n", ##__VA_ARGS__);
#else
#define PKTDMA_DRXTX(fmt, ...)
#endif

#if 0
#define APM_PKTDMA_DOP_CACHE(fmt, ...)	\
		printk(KERN_INFO PKTDMA_HDR fmt "\n", ##__VA_ARGS__);
#else
#define APM_PKTDMA_DOP_CACHE(fmt, ...)
#endif

#define PKTDMA_ERR(fmt, ...)		\
		printk(KERN_ERR PKTDMA_HDR fmt "\n", ##__VA_ARGS__);

#if !defined(APM_PKTDMA_DUMP_TX)
#define PKTDMA_DEBUG_DUMP(hdr, fmt, ...)
#else
#define PKTDMA_DEBUG_DUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, PKTDMA_HDR hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
	} while(0);
#endif

#define SLOT_NUM_QMMSG		4	/* Need 4 due to 64K page size */
#define QMSG_RSV_NUM		10
struct apm_pktdma_chan_slot {
	struct list_head slot_node;
	struct dma_async_tx_descriptor async_tx;
	u16 idx;
	struct apm_pktdma_chan *chan;
	/* Need 4 operation to support 64K page size as buffer is 16K */
	int msg_cnt;
	u64 sa[SLOT_NUM_QMMSG][PKTDMA_MAX_XOR];
	u64 da[SLOT_NUM_QMMSG][PKTDMA_MAX_XOR];
	u16 len[SLOT_NUM_QMMSG][PKTDMA_MAX_XOR];
	struct apm_pktdma_m2m_params m2m[SLOT_NUM_QMMSG];
};

struct apm_pktdma_chan {
	struct dma_chan common;
	int hw_chid;
	int pending;
	dma_cookie_t completed_cookie;
	spinlock_t lock; /* protects the descriptor slot pool */
	int slots_allocated;
	int slots_total;
	struct list_head all_slots;
	struct apm_pktdma_chan_slot *last_used;
#if defined(CONFIG_APM862xx)
	phys_addr_t dummy_phys; /* Dummy buffer for DMA lesser than 32B */
	u8 dummy[32];
#endif
};

struct pktdma_percpu_data {
	spinlock_t lock;
	struct list_head head;
	struct tasklet_struct rx_tasklet;
};

struct iodma_pdev {
	struct device *device;
	struct platform_device *pdev;

	int irq;
	phys_addr_t csr_base_p;
	void *csr_base;
	void *csr_base_diag;
	void *csr_base_qmi;

	void *percpu_ptr;
	struct tasklet_struct rx_tasklet;
	struct pktdma_q_info qinfo;

	spinlock_t enq_msg_lock;	/* lock for enqueue operation */
#ifdef PKTDMA_OP_CACHE_LIST
	spinlock_t cache_lock;		/* cache lock for operation desc */
#endif
	int poweroff;

	/* Async interface variables */
	struct apm_pktdma_chan chan[PKTDMA_CHID_MAX];
	struct dma_device common;
	struct dma_device common_xor;
#if defined(APM_PKTDMA_DEBUG_XTRA)
	struct apm_pktdma_msg current_send_msg[QMSG_RSV_NUM];
	int cnt_send_msg;
	u64 pktdma_m2m_sent_pkts;
	u64 pktdma_recv_pkts;
#endif
};

extern struct iodma_pdev p_dev;
unsigned long apm_pktdma_msg_enq_lock(void);
void apm_pktdma_msg_enq_unlock(unsigned long flags);
#endif /* __APM_PKTDMA_ACCESS_H__ */
