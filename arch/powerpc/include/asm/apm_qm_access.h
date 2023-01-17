/**
 * AppliedMicro AM862xx QM Driver
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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @file apm_qm_access.h
 *
 * Performance Note about Mailboxes:
 * GMvA:
 *   Mailbox on DDR - not supported
 *   Mailbox on MemQ with cacheable
 *     - 1.2GHz/DDR-1333 IPv4 64B forward ~289Kpps
 *     - Mailbox flush and invalidate hurts performance
 *   Mailbox on MemQ with non-cacheable
 *     - 1.2GHz/DDR-1333 IPv4 64B forward ~335Kpps
 *     - No Mailbox flush and invalidate improves performance
 *
 * KB/GMvB/BM:
 *   Mailbox on DDR coherent
 *     - 1.2GHz/DDR-1333 IPv4 64B forward ~386-396Kpps
 *     - No Mailbox flush and invalidate improves performance.
 *     - L1 of Mailbox as write through.
 *     - L2 of Mailbox as write back.
 *     - This has the benefit of L2 and let's hardware coherent handles
 *       flushes.
 *
 * NOTE: In order to create coherenet DDR, we need dma-reg entry in DTS
 *       for memory remap as coherent.
 */

#ifndef __APM_QM_ACCESS_H__
#define __APM_QM_ACCESS_H__

#include <linux/cpu.h>
#include <linux/slab.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/ipp.h>

#define IOS_INTERWORKING

/* Enable debugging */
#define QM_DBG_ERR_CHK
#define QM_PRINT_ENABLE
#undef DQM_DBG
#undef DQM_DBG2
#undef QM_DBG_STATE
#undef DQM_DBG_WR
#undef DQM_DBG_RD

#ifdef DQM_DBG
#define QM_DBG(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QM_DBG(x, ...)
#endif

#ifdef DQM_DBG2
#define QM_DBG2(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QM_DBG2(x, ...)
#endif

#ifdef QM_PRINT_ENABLE
#define QM_PRINT(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QM_PRINT(x, ...)
#endif

#ifdef QM_DBG_ERR_CHK
#define QM_ERR_CHK(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#define QM_ERR_CHK_DUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
	} while(0);
#else
#define QM_ERR_CHK(x, ...)
#define QM_ERR_CHK_DUMP(hdr, fmt, ...)
#endif

#ifdef DQM_DBG_WR
#define QMWRITE_PRINT(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QMWRITE_PRINT(x, ...)
#endif

#ifdef DQM_DBG_RD
#define QMREAD_PRINT(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QMREAD_PRINT(x, ...)
#endif

#ifdef QM_DBG_STATE
#define QM_STATE_DBG(x, ...)  printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define QM_STATE_DBG(x, ...)
#endif

/* Enable Reporting Errors to Error Queue */
#define APM_QM_ERROR_Q_ENABLE   0

/* Use bit for easy bit-wise test */
#if !defined(QM_MAILBOX_COHERENT)
#define QM_MAILBOX_COHERENT	0x0001
#define QM_MAILBOX_IOCOHERENT	0x0002
#define QM_MAILBOX_CACHEABLE	0x0004
#define QM_MAILBOX_NONCACHEABLE	0x0008
#endif

#if defined(CONFIG_APM862xx)
#undef CONFIG_QM_MAILBOX_DDR
#define CONFIG_QM_MAILBOX_MEMQ
#define CONFIG_QM_MAILBOX_TYPE		QM_MAILBOX_NONCACHEABLE
#undef CONFIG_QM_MAILBOX_FLUSH	
#else
#define CONFIG_QM_MAILBOX_DDR
#undef CONFIG_QM_MAILBOX_MEMQ
#define CONFIG_QM_MAILBOX_TYPE		QM_MAILBOX_COHERENT	
#undef CONFIG_QM_MAILBOX_FLUSH	
#endif

#ifdef IOS_INTERWORKING
#define CONFIG_QM_MAILBOX_MEMQ
#endif

#if defined(CONFIG_QM_MAILBOX_FLUSH)
#define QM_INVALIDATE_MB(x, y)	\
	invalidate_dcache_range((unsigned long) (x), (unsigned long) (y))
#define QM_FLUSH_MB(x, y) \
	flush_dcache_range((unsigned long) (x), (unsigned long) (y))
#else
#define QM_INVALIDATE_MB(x, y)
#define QM_FLUSH_MB(x, y)
#endif

/* Use QM alternative enqueue for better performance but en-queue queue can
 * not be shared with two masters.
 */ 
#undef QM_ALTERNATE_ENQUEUE
#if defined(QM_ALTERNATE_ENQUEUE) && defined(CONFIG_APM_ENET_LRO)
#define QM_NON_ALTERNATE_ENQUEUE_FP
#endif

int apm_qm_wr32(int ip, u32 offset, u32 data);
int apm_qm_rd32(int ip, u32 offset, u32 *data);
void apm_qm_disable_mb_irq(u32 mb_id);
void apm_qm_enable_mb_irq(u32 mb_id);
void apm_qm_enable_critical_irq(u32 mb_id);
int apm_qm_set_mb_affinity(u32 mb_id, u32 core_id);
int apm_qm_shutdown_q(int q_num);
int apm_qm_shutdown(void);
void apm_qm_tasklet_schedule(int mb_id);
int apm_qm_ready(void);

bool apm_qm_mb_irq_enabled(u32 mb_id);
void *MEMALLOC(int size);

#endif /* __APM_QM_ACCESS_H__ */
