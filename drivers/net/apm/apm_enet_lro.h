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
 * APM86xxx Ethernet LRO implementation for APM86xxx SoC.
 */
#ifndef __APM_ENET_LRO_H__
#define __APM_ENET_LRO_H__

#include <asm/apm_qm_core.h>

/* default configuration */
#if defined(LRO_DMA_MULTI_SRC_BUF_TO_SINGLE_DST_BUF)
#define LRO_DMA_MULTI_SRC_BUF
#define LRO_DMA_SINGLE_DST_BUF
#elif defined(LRO_DMA_MULTI_SRC_BUF_TO_SINGLE_DST_MEM)
#define LRO_DMA_MULTI_SRC_BUF
#define LRO_DMA_SINGLE_DST_MEM
#elif defined(LRO_DMA_SINGLE_SRC_BUF_TO_SINGLE_DST_MEM)
#define LRO_DMA_SINGLE_SRC_BUF
#define LRO_DMA_SINGLE_DST_MEM
#else
#error "LRO PKTDMA operation mode undefined"
#endif

#define LRO_MAX_CONN		8
/* Retx on TCP usually based off RTT for local fast networks, maybe 10ms is
 * reasonable? 10ms in microsec
 */
#define LRO_TIME_OUT		10	/* in ms */
#ifdef LRO_DMA_SINGLE_DST_BUF
#define LRO_BUF_SIZE		(16*1024)
#define LRO_ASM_BYTE		(11*1460)
#else
#define LRO_BUF_SIZE		(32*1024)
#define LRO_ASM_BYTE		(22*1460)
#endif
#define ONE_BUF_SIZE		(2*1024)
#define SEG_BUF_SIZE		(2*1024)
#define APM_SEG_PKT_BUF		4096
#define APM_LRO_PKT_BUF		512

struct apm_enet_lro_ctx {
	u32 lro_available;		/* SlimPRO available in SoC */
	u32 init_done;			/* LRO init done */
	u32 enable;			/* Enabled this feature */
	u32 timeout_ms;
	u32 max_byte_cnt;
	struct ipp_lro_qm_sys_wq qm_sys;
	struct ipp_lro_qm_src_fp qm_src;
	struct ipp_lro_qm_dst_fp qm_dst;
};

/* Forward declaration */
struct apm_enet_dev_base;

int apm_enet_lro_enable(struct apm_enet_dev_base *priv, u32 enable);
int apm_enet_lro_set_timeout(struct apm_enet_dev_base *priv, u32 timeoutms);
int apm_enet_lro_set_maxbytecnt(struct apm_enet_dev_base *priv, u32 maxbytecnt);

int apm_enet_lro_init(struct apm_enet_dev_base *priv);
int apm_enet_lro_poll(struct napi_struct *napi, int budget);

int apm_enet_lro_rx_frame(struct apm_qm_msg_desc *rx_msg_desc);

#endif /* __APM_ENET_LRO_H__ */
