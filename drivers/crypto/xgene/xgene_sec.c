/*
 * APM X-Gene SoC Security Core Driver
 *
 * Copyright (c) 2014 Applied Micro Circuits Corporation.
 * All rights reserved. Loc Ho <lho@apm.com>
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
 */

#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <crypto/internal/hash.h>
#include <linux/clk.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/efi.h>
#include <linux/highmem.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/module.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_platform.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/version.h>
#include "xgene_sec_csr.h"
#include "xgene_sec.h"
#include "xgene_sec_tkn.h"
#include "xgene_sec_sa.h"
#include "xgene_sec_alg.h"

/* Enable UIO - xgenesec.uio=1 to enable */
static int crypto_uio;
MODULE_PARM_DESC(crypto_uio, "Enable UIO support (1=enable 0=disable)");
module_param_named(uio, crypto_uio, int, 0444);

struct xgene_sec_ctx *xg_ctx;

#ifdef __AARCH64BE__
#define xgene_sec_cpu_to_le64(msg, count)	\
	do { \
		if (msg) {	\
			int i;	\
			u32 tmp;	\
			for (i = 0; i < (count); i += 2) {	\
				tmp = ((u32 *)(msg))[i];	\
				((u32 *)(msg))[i] = ((u32 *)(msg))[i + 1]; \
				((u32 *)(msg))[i + 1] = tmp;	\
				((u64 *)(msg))[i/2] =	\
					cpu_to_le64(((u64 *)(msg))[i/2]); \
			}	\
		}	\
	} while (0)
#define xgene_sec_le64_to_cpu(msg, count)	\
	do { \
		if (msg) {	\
			int i;	\
			u32 tmp;	\
			for (i = 0; i < (count); i += 2) {	\
				tmp = ((u32 *)(msg))[i];	\
				((u32 *)(msg))[i] = ((u32 *)(msg))[i + 1]; \
				((u32 *)(msg))[i + 1] = tmp;	\
				((u64 *)(msg))[i/2] =	\
					le64_to_cpu(((u64 *)(msg))[i/2]); \
			}	\
		}	\
	} while (0)
#else
#define xgene_sec_cpu_to_le64(msg, count) \
	do {} while (0)
#define xgene_sec_le64_to_cpu(msg, count) \
	do {} while (0)
#endif

#ifdef __AARCH64EB__
#define xgene_ring_msg_le32(word, words) \
	do { \
		int w; \
		for (w = 0; w < words; w++) \
			*(word + w) = cpu_to_le32(*(word + w)); \
	} while (0)
#else
#define xgene_ring_msg_le32(word, words) \
	do {} while (0)
#endif

static void xgene_ring_rd32(struct xgene_sec_ctx *ctx,
			u32 offset, u32 *val)
{
	*val = ioread32(ctx->csr_ring + offset);

	dev_dbg(ctx->dev, "CSR RING RD: 0x%x value: 0x%08X\n", offset, *val);
}

static void xgene_ring_wr32(struct xgene_sec_ctx *ctx,
			u32 offset, u32 val)
{
	iowrite32(val, ctx->csr_ring + offset);

	dev_dbg(ctx->dev, "CSR RING WR: 0x%x value: 0x%08X\n", offset, val);
}

static void xgene_ring_init(struct xgene_ring_info *ring)
{
	u64 addr = ring->dma;

	if (ring->ctx->intf != XGENE_RING_VERSION1) {
		/* setting dequeue irq and enable */
		if (ring->irq > 0) {
			RSTATE_INLINE_SET(ring->state,
					  ring->irq - FIRST_DEQ_IRQ);
			RSTATE_DEQINTEN_SET(ring->state, 1);
		}

		/* setting addr mode = machine physical address */
		RSTATE_QBASE_AM_SET(ring->state, 1);
		RSTATE_MSG_AM_SET(ring->state, 1);

		/* critical region ID */
		RSTATE_CFGCRID_SET(ring->state, 1);
	}

	RSTATE_SELTHRSH_SET(ring->state, 1);
	RSTATE_ACCEPTLERR_SET(ring->state, 1);
	RSTATE_QCOHERENT_SET(ring->state, 1);

	addr >>= 8;
	RSTATE_RINGADDRL_SET(ring->state, addr);
	addr >>= 27;
	RSTATE_RINGADDRH_SET(ring->state, addr);
	RSTATE_RINGSIZE_SET(ring->state, ring->cfgsize);
}

static u32 xgene_get_num_ring_cfg(struct xgene_ring_info *ring)
{
	if (ring->ctx->intf == XGENE_RING_VERSION1)
		return XGENE_NUM_RING_CFG_WORD;
	else
		return XGENE_NUM_RING_CFG_WORD_VER2;
}

static void xgene_ring_set_type(struct xgene_ring_info *ring)
{
	u32 val = ring->is_bufpool ? RING_BUFPOOL : RING_REGULAR;

	if (ring->ctx->intf == XGENE_RING_VERSION1)
		RSTATE_RINGTYPE_SET(ring->state, val);
	else
		RSTATE_RINGTYPE_VER2_SET(ring->state, val);

	if (ring->is_bufpool)
		RSTATE_RINGMODE_SET(ring->state, BUFPOOL_MODE);
}

static void xgene_ring_set_recombbuf(struct xgene_ring_info *ring)
{
	RSTATE_RECOMBBUF_SET(ring->state, 1);

	if (ring->ctx->intf == XGENE_RING_VERSION1) {
		RSTATE_RECOMTIMEOUTL_SET(ring->state, 0xf);
		RSTATE_RECOMTIMEOUTH_SET(ring->state, 0x7);
	} else {
		RSTATE_RECOMTIMEOUT_SET(ring->state, 0x7f);
	}
}

static void xgene_write_ring_state(struct xgene_ring_info *ring)
{
	int i;

	xgene_ring_wr32(ring->ctx, CSR_RING_CONFIG, ring->ring_num);

	for (i = 0; i < xgene_get_num_ring_cfg(ring); i++)
		xgene_ring_wr32(ring->ctx, CSR_RING_WR_BASE + (i * 4),
				ring->state[i]);
}

void xgene_read_ring_state(struct xgene_ring_info *ring)
{
	u32 offset, i;

	xgene_ring_wr32(ring->ctx, CSR_RING_CONFIG, ring->ring_num);
	memset(ring->state, 0, sizeof(u32) * xgene_get_num_ring_cfg(ring));

	if (ring->ctx->intf == XGENE_RING_VERSION1)
		offset = CSR_RING_RD_BASE;
	else
		offset = CSR_RING_RD_BASE_VER2;

	for (i = 0; i < xgene_get_num_ring_cfg(ring); i++)
		xgene_ring_rd32(ring->ctx, offset + (i * 4), &ring->state[i]);
}

static void xgene_clr_ring_state(struct xgene_ring_info *ring)
{
	memset(ring->state, 0, sizeof(u32) * xgene_get_num_ring_cfg(ring));
	xgene_write_ring_state(ring);
}

#ifdef APM_SEC_QMDEBUG
static void xgene_dump_ring_state(struct xgene_ring_info *ring)
{
	u32 addrh, addrl;
	u64 cfgstartaddr;

	if (!ring)
		return;

	xgene_read_ring_state(ring);

	addrh = RSTATE_RINGADDRH_RD(ring->state);
	addrl = RSTATE_RINGADDRL_RD(ring->state);
	cfgstartaddr = (((u64)addrh) << 35) | (addrl << 8);

	pr_info("+ =============\n");
	pr_info("+ Ring: %p\n", ring);
	pr_info("+ QCoherent: %x\n", RSTATE_QCOHERENT_RD(ring->state));
	pr_info("+ CfgStartAddr: 0x%016llx\n", cfgstartaddr);
	pr_info("+ CfgAcceptLErr: %x\n", RSTATE_ACCEPTLERR_RD(ring->state));
	pr_info("+ FP_mode: %x\n", RSTATE_RINGMODE_RD(ring->state));
	pr_info("+ Slots_pending: %x\n", RSTATE_SLOTS_PENDING_RD(ring->state));
	pr_info("+ CfgQSize: %x\n", RSTATE_RINGSIZE_RD(ring->state));
	pr_info("+ CfgEnRecombBuf: %x\n", RSTATE_RECOMBBUF_RD(ring->state));
	pr_info("+ CfgSelThrsh: %x\n", RSTATE_SELTHRSH_RD(ring->state));
	pr_info("+ CfgQType: %x\n", RSTATE_RINGTYPE_RD(ring->state));
	if (ring->ctx->intf != XGENE_RING_VERSION1) {
		pr_info("+ NummsginQ: %x\n", RSTATE_NUMMSGINQ_VER2_RD(ring->state));
		pr_info("+ CfgIntLine: %d\n", RSTATE_INLINE_RD(ring->state));
		pr_info("+ CfgDeqIntEn: %d\n",
			RSTATE_DEQINTEN_RD(ring->state));
		pr_info("+ CfgCRid: %d\n", RSTATE_CFGCRID_RD(ring->state));
		pr_info("+ CfgRecombBufTimeout: %d\n",
			RSTATE_RECOMTIMEOUT_RD(ring->state));
		pr_info("+ Msg_AM: %d\n", RSTATE_MSG_AM_RD(ring->state));
		pr_info("+ QBase_AM: %d\n", RSTATE_QBASE_AM_RD(ring->state));
	} else {
		pr_info("+ NummsginQ: %x\n", RSTATE_NUMMSGINQ_RD(ring->state));
		pr_info("+ Head_ptr: %x\n", RSTATE_HEAD_PTR_RD(ring->state));
		pr_info("+ CfgRecombBufTimeout1: %x\n",
			RSTATE_RECOMTIMEOUTL_RD(ring->state));
		pr_info("+ CfgRecombBufTimeouth: %x\n",
			RSTATE_RECOMTIMEOUTH_RD(ring->state));
	}
}
#endif

static void xgene_set_ring_state(struct xgene_ring_info *ring)
{
	xgene_ring_set_type(ring);

	if (ring->owner == RING_OWNER_SEC)
		xgene_ring_set_recombbuf(ring);

	xgene_ring_init(ring);
	xgene_write_ring_state(ring);
}

static void xgene_set_ring_id(struct xgene_ring_info *ring)
{
	u32 ring_id, ring_id_val;
	u32 ring_id_buf;

	ring_id = (ring->owner << 6) | ring->buf_num;
	ring_id_val = OVERWRITE | (ring_id & GENMASK(9, 0));

	ring_id_buf = (ring->ring_num << 9) & GENMASK(18, 9);
	ring_id_buf |= BUF_EN;
	if (ring->is_bufpool)
		ring_id_buf |= IS_FREE_POOL;

	xgene_ring_wr32(ring->ctx, CSR_RING_ID, ring_id_val);
	xgene_ring_wr32(ring->ctx, CSR_RING_ID_BUF, ring_id_buf);
}

static void xgene_clr_desc_ring_id(struct xgene_ring_info *ring)
{
	u32 ring_id = (ring->owner << 6) | ring->buf_num;
	u32 ring_id_val = OVERWRITE | (ring_id & GENMASK(9, 0));

	xgene_ring_wr32(ring->ctx, CSR_RING_ID, ring_id_val);
	xgene_ring_wr32(ring->ctx, CSR_RING_ID_BUF, 0);
}

static void xgene_setup_ring(struct xgene_ring_info *ring)
{
	u32 size = ring->size;
	u32 i, val;
	u32 addr;

	ring->count = ring->is_bufpool ? size / 16 : size / 32;

	xgene_clr_ring_state(ring);
	xgene_set_ring_state(ring);
	if ((ring->owner != RING_OWNER_CPU)
			|| (ring->ctx->intf == XGENE_RING_VERSION1))
		xgene_set_ring_id(ring);


	if (ring->is_bufpool || ring->owner != RING_OWNER_CPU)
		return;

	for (i = 0; i < ring->count; i++) {
		u32 *msg32 = (u32 *)&ring->msg32[i];
		msg32[RMSG_EMPTY_SLOT_INDEX] = RMSG_EMPTY_SLOT_SIGNATURE;
	}

	if (ring->ctx->intf == XGENE_RING_VERSION1) {
		xgene_ring_rd32(ring->ctx, CSR_RING_NE_INT_MODE, &val);
		val |= (u32) (1 << (31 - ring->buf_num));
		xgene_ring_wr32(ring->ctx, CSR_RING_NE_INT_MODE, val);
		return;
	} 
	/* program interrupt mailbox 0 */
	val = (ring->irq_mbox_dma >> 10);
	addr = CSR_VMID0_INTR_MBOX + (4 * (ring->irq - FIRST_DEQ_IRQ));
	xgene_ring_wr32(ring->ctx, addr, val);
	xgene_ring_rd32(ring->ctx, addr, &val);
}

static void xgene_clear_ring(struct xgene_ring_info *ring)
{
	u32 val;

	if (ring->is_bufpool || ring->owner != RING_OWNER_CPU)
		goto out;

	xgene_ring_rd32(ring->ctx, CSR_RING_NE_INT_MODE, &val);
	val &= ~(u32) (1 << (31 - ring->buf_num));
	xgene_ring_wr32(ring->ctx, CSR_RING_NE_INT_MODE, val);

out:
	xgene_clr_desc_ring_id(ring);
	xgene_clr_ring_state(ring);
}

static void xgene_set_cmd_base(struct xgene_ring_info *ring)
{
	if (ring->ctx->intf == XGENE_RING_VERSION1)
		ring->cmd_base = ring->ctx->csr_cmd +
			((ring->ring_num - START_SEC_RING_NUM) << 6);
	else
		ring->cmd_base = ring->ctx->csr_cmd +
			((ring->ring_num - START_SEC_RING_NUM_VER2) << 13);
}

static void xgene_wr_cmd(struct xgene_ring_info *ring, int count)
{
	int val = 0;

	if (ring->ctx->intf != XGENE_RING_VERSION1) {
		if (ring->irq > 0)
			val = (ring->buf_num << 24) | INTR_CLEAR;
		val |= count & 0x0001FFFF;
		count = val;
	}
	iowrite32(count, ring->cmd);
}

static u16 xgene_dst_ring_num(struct xgene_ring_info *ring)
{
	return ((u16)ring->ctx->intf << 10) | ring->ring_num;
}

static inline u16 xgene_ring_encode_datalen(u32 len)
{
	return len & 0x3FFF;
}

void xgene_sec_rd32(struct xgene_sec_ctx *ctx, u8 block, u32 reg, u32 * data)
{
	void __iomem *reg_offset;

	switch (block) {
	case EIP96_AXI_CSR_BLOCK:
		reg_offset = ctx->eip96_axi_csr + reg;
		break;
	case EIP96_CSR_BLOCK:
		reg_offset = ctx->eip96_csr + reg;
		break;
	case EIP96_CORE_CSR_BLOCK:
		reg_offset = ctx->eip96_core_csr + reg;
		break;
	case SEC_GLB_CTRL_CSR_BLOCK:
		reg_offset = ctx->ctrl_csr + reg;
		break;
	case CLK_RES_CSR_BLOCK:
		reg_offset = ctx->clk_csr + reg;
		break;
	case RI_CTL_BLOCK:
		reg_offset = ctx->ri_ctl_csr + reg;
		break;
	default:
		dev_err(ctx->dev, "Invalid read from block %d offset: %d\n",
			block, reg);
		return;
	}
	*data = readl(reg_offset);
	dev_dbg(ctx->dev, "CSR RD: 0x%p value: 0x%08X\n", reg_offset, *data);
}

void xgene_sec_wr32(struct xgene_sec_ctx *ctx, u8 block, u32 reg, u32 data)
{
	void __iomem *reg_offset;

	switch (block) {
	case EIP96_AXI_CSR_BLOCK:
		reg_offset = ctx->eip96_axi_csr + reg;
		break;
	case EIP96_CSR_BLOCK:
		reg_offset = ctx->eip96_csr + reg;
		break;
	case EIP96_CORE_CSR_BLOCK:
		reg_offset = ctx->eip96_core_csr + reg;
		break;
	case SEC_GLB_CTRL_CSR_BLOCK:
		reg_offset = ctx->ctrl_csr + reg;
		break;
	case CLK_RES_CSR_BLOCK:
		reg_offset = ctx->clk_csr + reg;
		break;
	case RI_CTL_BLOCK:
		reg_offset = ctx->ri_ctl_csr + reg;
		break;
	default:
		dev_err(ctx->dev, "Invalid write to block %d offset %d\n",
			block, reg);
		return;
	}
	dev_dbg(ctx->dev, "CSR WR: 0x%p value: 0x%08X\n", reg_offset, data);
	writel(data, reg_offset);
}

int xgene_sec_init_memram(struct xgene_sec_ctx *ctx)
{
	void __iomem *diagcsr = ctx->diag_csr;
	int try;
	u32 val;

	val = readl(diagcsr + SEC_CFG_MEM_RAM_SHUTDOWN_ADDR);
	if (val == 0) {
		dev_dbg(ctx->dev, "memory already released from shutdown\n");
		return 0;
	}
	dev_dbg(ctx->dev, "Release memory from shutdown\n");
	/* Memory in shutdown. Remove from shutdown. */
	writel(0x0, diagcsr + SEC_CFG_MEM_RAM_SHUTDOWN_ADDR);
	readl(diagcsr + SEC_CFG_MEM_RAM_SHUTDOWN_ADDR);	/* Force a barrier */

	/* Check for at least ~1ms */
	try = 1000;
	do {
		val = readl(diagcsr + SEC_BLOCK_MEM_RDY_ADDR);
		if (val != 0xFFFFFFFF)
			usleep_range(1, 100);
	} while (val != 0xFFFFFFFF && try-- > 0);
	if (try <= 0) {
		dev_err(ctx->dev, "failed to release memory from shutdown\n");
		return -ENODEV;
	}
	return 0;
}

void xgene_sec_hdlr_ctxreg_err(struct xgene_sec_ctx *ctx, u32 ctx_sts)
{
	if (!ctx_sts)
		return;
	if (ctx_sts & E14_MASK)
		dev_err(ctx->dev, "Time out error\n");
	if (ctx_sts & E13_MASK)
		dev_err(ctx->dev, "Pad verify failed\n");
	if (ctx_sts & E12_MASK)
		dev_err(ctx->dev, "Checksum failed\n");
	if (ctx_sts & E11_MASK)
		dev_err(ctx->dev, "SPI Check failed\n");
	if (ctx_sts & E10_MASK)
		dev_err(ctx->dev, "Seq num check/roll over failed\n");
	if (ctx_sts & E9_MASK)
		dev_err(ctx->dev, "Authentication failed\n");
	if (ctx_sts & E8_MASK)
		dev_err(ctx->dev, "TTL/HOP limit underflow\n");
	if (ctx_sts & E7_MASK)
		dev_err(ctx->dev, "Hash input overflow\n");
	if (ctx_sts & E6_MASK)
		dev_err(ctx->dev, "Prohibited Alg\n");
	if (ctx_sts & E5_MASK)
		dev_err(ctx->dev, "Invalid command/mode/alg combination\n");
	if (ctx_sts & E4_MASK)
		dev_err(ctx->dev, "Hash Block size err\n");
	if (ctx_sts & E3_MASK)
		dev_err(ctx->dev, "Crypto Blk size err\n");
	if (ctx_sts & E2_MASK)
		dev_err(ctx->dev, "Too much bypass data in Tkn\n");
	if (ctx_sts & E1_MASK)
		dev_err(ctx->dev, "Unknown tkn command instruction\n");
	if (ctx_sts & E0_MASK)
		dev_err(ctx->dev, "Packet length err\n");
}

void xgene_sec_intr_hdlr(struct xgene_sec_ctx *ctx)
{
	u32 status;

	xgene_sec_rd32(ctx, EIP96_AXI_CSR_BLOCK, CSR_SEC_INT_STS_ADDR, &status);
	if (!status)
		return;
	if (status & EIP96_CORE_MASK)
		dev_err(ctx->dev, "EIP96 error\n");
	if (status & TKN_RD_F2_MASK)
		dev_err(ctx->dev, "token read error\n");
	if (status & CTX_RD_F2_MASK)
		dev_err(ctx->dev, "context read error\n");
	if (status & DATA_RD_F2_MASK)
		dev_err(ctx->dev, "data read error\n");
	if (status & DSTLL_RD_F2_MASK)
		dev_err(ctx->dev, "destination linked list read error\n");
	if (status & TKN_WR_F2_MASK)
		dev_err(ctx->dev, "token write error\n");
	if (status & CTX_WR_F2_MASK)
		dev_err(ctx->dev, "context write error\n");
	if (status & DATA_WR_F2_MASK)
		dev_err(ctx->dev, "data write error\n");
	xgene_sec_rd32(ctx, EIP96_CORE_CSR_BLOCK, IPE_CTX_STAT_ADDR, &status);
	xgene_sec_hdlr_ctxreg_err(ctx, status);
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK, CSR_SEC_INT_STSMASK_ADDR,
		       0xffffffff);
}

void xgene_sec_intr_qmi_hdlr(struct xgene_sec_ctx *ctx)
{
	u32 status;

	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT0_ADDR, &status);
	if (status)
		dev_err(ctx->dev, "FP PB overflow indication: 0x%x\n", status);

	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT1_ADDR, &status);
	if (status)
		dev_err(ctx->dev, "WQ PB overflow indication: 0x%x\n", status);

	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT2_ADDR, &status);
	if (status)
		dev_err(ctx->dev, "FP PB underrun indication: 0x%x\n", status);

	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT3_ADDR, &status);
	if (status)
		dev_err(ctx->dev, "WQ PB underrun indication: 0x%x\n", status);

	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT4_ADDR, &status);
	if (status & SEC_AXIWCMR_DECERR4_MASK)
		dev_err(ctx->dev, "AXI decode error on write master channel\n");
	if (status & SEC_AXIWCMR_SLVERRMASK_MASK)
		dev_err(ctx->dev, "AXI slave error on write master channel\n");
}

void xgene_sec_hdlr_qerr(struct xgene_sec_ctx *ctx, int ring_err_hop, int ring_err)
{
	switch (ring_err) {
	case 0x11:
		/*
		 * Any kind of crypto error (illegal tkn/ctx, tkn length,
		 * bad packet, and etc
		 */
		dev_err(ctx->dev, "token programming with hop %d error\n",
			ring_err_hop);
		break;
	case 0x03:
		dev_err(ctx->dev,
			"out of free pool buffer with hop %d error\n",
			ring_err_hop);
		break;
	case 0x04:
		dev_err(ctx->dev, "AXI read with hop %d error\n", ring_err_hop);
		break;
	case 0x05:
		dev_err(ctx->dev, "AXI write with hop %d error\n", ring_err_hop);
		break;
	case 0x07:
		dev_err(ctx->dev,
			"Invalid Ring message format with hop %d eorr\n",
			ring_err_hop);
		break;
	case 0x06:
		dev_err(ctx->dev,
			"Destination linked list read with hop %d error\n",
			ring_err_hop);
		break;
	case 0x01:
		dev_err(ctx->dev,
			"Not enough entries in destination linked list with "
			"hop %d error\n",
			ring_err_hop);
		break;
	}
}

/*
 * Error Callback Handler
 */
static irqreturn_t xgene_sec_intr_cb(int irq, void *id)
{
	struct xgene_sec_ctx *ctx = id;
	u32 stat = 0;

	/* Determine what causes interrupt */
	xgene_sec_rd32(ctx, SEC_GLB_CTRL_CSR_BLOCK, CSR_GLB_SEC_INT_STS_ADDR,
		       &stat);
	if (stat & EIP96_MASK)
		xgene_sec_intr_hdlr(ctx);	/* EIP96 interrupted */

	if (stat & QMI_MASK)
		xgene_sec_intr_qmi_hdlr(ctx);	/* EIP96 interrupted */

	/* Clean them */
	xgene_sec_wr32(ctx, SEC_GLB_CTRL_CSR_BLOCK, CSR_GLB_SEC_INT_STS_ADDR,
		       stat);

	return IRQ_HANDLED;
}

static void __xgene_delete_ring_one(struct xgene_ring_info *ring)
{
	xgene_clear_ring(ring);

	if (ring->ring_vaddr) {
		dma_free_coherent(ring->ctx->dev, ring->size,
				  ring->ring_vaddr, ring->dma);
		ring->ring_vaddr = NULL;
	}
	if (ring->mbox_dma_vaddr) {
		dma_free_coherent(ring->ctx->dev, ring->size,
				  ring->mbox_dma_vaddr, ring->irq_mbox_dma);
		ring->mbox_dma_vaddr = NULL;
	}
}

static void xgene_sec_deinit_rings(struct xgene_sec_ctx *ctx)
{
	__xgene_delete_ring_one(&ctx->rx_ring);
	__xgene_delete_ring_one(&ctx->tx_ring);
}

static int xgene_get_ring_size(struct xgene_sec_ctx *ctx,
			       enum xgene_ring_cfgsize cfgsize)
{
	int size;

	switch (cfgsize) {
	case RING_CFG_SIZE_512B:
		size = 0x200;
		break;
	case RING_CFG_SIZE_2KB:
		size = 0x800;
		break;
	case RING_CFG_SIZE_16KB:
		size = 0x4000;
		break;
	case RING_CFG_SIZE_64KB:
		size = 0x10000;
		break;
	case RING_CFG_SIZE_512KB:
		size = 0x80000;
		break;
	default:
		dev_err(ctx->dev,
			"Channel %d Unsupported cfg ring size %d\n",
			ctx->index, cfgsize);
		return -EINVAL;
	}

	return size;
}

static int __xgene_create_ring_one(struct xgene_sec_ctx *ctx,
				   struct xgene_ring_info *ring,
				   int irq,
				   enum xgene_ring_cfgsize cfgsize)
{
	ring->ctx = ctx;
	ring->irq = irq;
	ring->cfgsize = cfgsize;
	ring->ring_num = ctx->ring_count++;
	ring->ring_id = (ring->owner << 6) | ring->buf_num;
	ring->size = xgene_get_ring_size(ctx, cfgsize);
	if (ring->size <= 0)
		return ring->size;

	ring->ring_vaddr = NULL;
	ring->mbox_dma_vaddr = NULL;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
	ring->ring_vaddr = dma_zalloc_coherent(ctx->dev, ring->size,
					       &ring->dma, GFP_KERNEL);
#else
	ring->ring_vaddr = kzalloc(ring->size, GFP_KERNEL);
	ring->dma = virt_to_phys(ring->ring_vaddr);
#endif
	if (!ring->ring_vaddr) {
		dev_err(ctx->dev,
			"Channel %d Couldn't allocate memory for ring descriptor "
			"ring id 0x%X ring num %d\n",
			ctx->index, ring->ring_id, ring->ring_num);
		return -ENOMEM;
	}

	if (irq > 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 12, 0)
		ring->mbox_dma_vaddr = dma_zalloc_coherent(ctx->dev,
							   INTR_MBOX_SIZE,
							   &ring->irq_mbox_dma,
							   GFP_KERNEL);
#else
		ring->mbox_dma_vaddr = kzalloc(INTR_MBOX_SIZE, GFP_KERNEL);
		ring->irq_mbox_dma = virt_to_phys(ring->mbox_dma_vaddr);
#endif
		if (!ring->mbox_dma_vaddr) {
			dev_err(ctx->dev,
				"Channel %d Couldn't allocate memory for irq_mb\n",
				ctx->index);
			return -ENOMEM;
		}
	}

	xgene_set_cmd_base(ring);
	ring->cmd = ring->cmd_base + 0x2C;
	xgene_setup_ring(ring);

#ifdef APM_SEC_QMDEBUG
	xgene_dump_ring_state(ring);
#endif
	return 0;
}

static int xgene_create_rings(struct xgene_sec_ctx *ctx)
{
	struct xgene_ring_info *rx_ring = &ctx->rx_ring;
	struct xgene_ring_info *tx_ring = &ctx->tx_ring;
	int ret;

	if (ctx->intf == XGENE_RING_VERSION1)
		ctx->ring_count = START_SEC_RING_NUM;
	else
		ctx->ring_count = START_SEC_RING_NUM_VER2;

	/* Allocate Rx ring */
	rx_ring->owner = RING_OWNER_CPU;
	rx_ring->is_bufpool = false;
	if (ctx->intf == XGENE_RING_VERSION1)
		rx_ring->buf_num = RING_BUFNUM_CPU + ctx->index;
	else
		rx_ring->buf_num = RING_BUFNUM_CPU_VER2 + ctx->index;

	ret = __xgene_create_ring_one(ctx, rx_ring, ctx->rx_ring.irq,
				      RX_XGENE_QSIZE);
	if (ret)
		return ret;

	rx_ring->dst_ring_num = xgene_dst_ring_num(rx_ring);

	dev_dbg(ctx->dev,
		"Chan %d Rx ring id 0x%X num %d desc 0x%p slot count %d "
		"irq %d\n",
		ctx->index, rx_ring->ring_id, rx_ring->ring_num,
		rx_ring->ring_vaddr, rx_ring->count, rx_ring->irq);

	/* Allocate Tx ring */
	tx_ring->owner = RING_OWNER_SEC;
	tx_ring->is_bufpool = false;
	tx_ring->buf_num = RING_BUFNUM_REGULAR + ctx->index;

	ret = __xgene_create_ring_one(ctx, tx_ring, 0, TX_XGENE_QSIZE);
	if (ret)
		return ret;

	tx_ring->dst_ring_num = xgene_dst_ring_num(tx_ring);

	dev_dbg(ctx->dev,
		"Chan %d Tx ring id 0x%X num %d desc 0x%p slot count %d "
		"dest ring id 0x%X\n",
		ctx->index, tx_ring->ring_id, tx_ring->ring_num,
		tx_ring->ring_vaddr, tx_ring->count, tx_ring->dst_ring_num);

	return 0;
}

int xgene_sec_hwinit(struct xgene_sec_ctx *ctx)
{
	u32 dev_info;
	u32 proto_alg;
	u32 val;

	xgene_sec_rd32(ctx, SEC_GLB_CTRL_CSR_BLOCK, CSR_ID_ADDR, &val);
	dev_dbg(ctx->dev, "Security ID: %02d.%02d.%02d\n",
		REV_NO_RD(val), BUS_ID_RD(val), DEVICE_ID_RD(val));

	/* For AXI parameter, leave default priorities */

	/* Enable IRQ for core, EIP96, and XTS blocks, EIP62 */
	xgene_sec_wr32(ctx, SEC_GLB_CTRL_CSR_BLOCK,
		       CSR_GLB_SEC_INT_STSMASK_ADDR,
		       0xFFFFFFFF & ~(QMIMASK_MASK |
			   EIP96MASK_MASK |
			   XTSMASK_MASK | EIP62MASK_MASK));

	/*
	 * Configure RI (Ring Interface) block
	 * Un-mask work queue overflow/underun, free pool overflow/underrun
	 */
	xgene_sec_rd32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIDBGDATA_ADDR, &val);
	xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT0MASK_ADDR, 0x0);
	xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT1MASK_ADDR, 0x0);
	xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT2MASK_ADDR, 0x0);
	xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT3MASK_ADDR, 0x0);
	/* Un-mask AXI write/read errror */
	xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_STSSSQMIINT4MASK_ADDR, 0x0);

	/* Associate FP and WQ to QM1 */
	if (ctx->intf == XGENE_RING_VERSION1) {
		xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_CFGSSQMIFPQASSOC_ADDR,
			       0xFFFFFFFF);
		xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_CFGSSQMIWQASSOC_ADDR,
			       0xFFFFFFFF);
		xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_CFGSSQMIQMHOLD_ADDR,
			       0x00000002);
	} else {
		xgene_sec_wr32(ctx, RI_CTL_BLOCK, SEC_CFGSSQMIQMHOLD_ADDR,
			       0x00000001);
	}

	/* For EIP96 AXI outstanding read and write, leave default */
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK,
		       CSR_AXI_RD_MAX_OUTSTANDING_CFG_ADDR, 0x88880000);
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK,
		       CSR_AXI_WR_MAX_OUTSTANDING_CFG_ADDR, 0x88800000);

	/* For EIP96 AXI, enable error interrupts */
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK, CSR_SEC_INT_STSMASK_ADDR,
		       ~0xFFFFFFFF);

	/* For EIP96, configure CSR_SEC_CRYPTO_CFG_0 */
	xgene_sec_rd32(ctx, EIP96_CSR_BLOCK, CSR_SEC_CRYPTO_CFG_0_ADDR, &val);
	val &= ~TKN_RD_OFFSET_SIZE0_MASK;
	val |= TKN_RD_OFFSET_SIZE0_WR(TKN_RESULT_HDR_MAX_LEN / 4);
	val &= ~TKN_RD_PREFETCH_SIZE0_MASK;
	val |= TKN_RD_PREFETCH_SIZE0_WR(0x8);	/* Set token prefetch to 32B */
	xgene_sec_wr32(ctx, EIP96_CSR_BLOCK, CSR_SEC_CRYPTO_CFG_0_ADDR, val);

	/* For EIP96, configure CSR_SEC_CRYPTO_CFG_1 */
	xgene_sec_rd32(ctx, EIP96_CSR_BLOCK, CSR_SEC_CRYPTO_CFG_1_ADDR, &val);
	val &= ~DIS_CTX_INTERLOCK1_MASK;
	val |= DIS_CTX_INTERLOCK1_WR(0);
	xgene_sec_wr32(ctx, EIP96_CSR_BLOCK, CSR_SEC_CRYPTO_CFG_1_ADDR, val);

	/* For EIP96 core, read version */
	xgene_sec_rd32(ctx, EIP96_CORE_CSR_BLOCK, IPE_DEV_INFO_ADDR, &dev_info);
	xgene_sec_rd32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRC_ALG_EN_ADDR,
		       &proto_alg);
	dev_dbg(ctx->dev, "Core ver %d.%d Proto/Alg: 0x%08X\n",
		MAJOR_REVISION_NUMBER_RD(dev_info),
		MINOR_REVISION_NUMBER_RD(dev_info), proto_alg);

	/* For EIP96, configure context access mode */
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_CTX_CTRL_ADDR,
		       CONTEXT_SIZE_WR(0x36)
		       | SEC_ADDRESS_MODE_WR(0)
		       | SEC_CONTROL_MODE_WR(1));

	/* For EIP96 core, configure control status register */
	xgene_sec_rd32(ctx, EIP96_CORE_CSR_BLOCK, IPE_TKN_CTRL_STAT_ADDR, &val);
	val &= ~OPTIMAL_CONTEXT_UPDATES_MASK;
	val &= ~INTERRUPT_PULSE_OR_LEVEL_MASK;
	val &= ~TIME_OUT_COUNTER_ENABLE_MASK;
	val |= OPTIMAL_CONTEXT_UPDATES_WR(0);
	val |= INTERRUPT_PULSE_OR_LEVEL_WR(1 /* Level interrupt */ );
	val |= TIME_OUT_COUNTER_ENABLE_WR(0);
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_TKN_CTRL_STAT_ADDR, val);

	/* For EIP96 core, setup interrupt */
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_INT_CTRL_STAT_ADDR,
		       INPUT_DMA_ERROR_ENABLE_WR(1)
		       | OUTPUT_DMA_ERROR_ENABLE_WR(1)
		       | PACKET_PROCESSING_ENABLE_WR(1)
		       | PACKET_TIMEOUT_ENABLE_WR(1)
		       | FATAL_ERROR_ENABLE_WR(1)
		       | INTERRUPT_OUTPUT_PIN_ENABLE_WR(1));

	/* For EIP96, seed the PRNG, KEY0, KEY1, and LRSR */
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_SEED_L_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_SEED_H_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_KEY_0_L_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_KEY_0_H_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_KEY_1_L_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_KEY_1_H_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_LFSR_L_ADDR, val);
	get_random_bytes_arch(&val, sizeof(u32));
	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_LFSR_H_ADDR, val);

	xgene_sec_wr32(ctx, EIP96_CORE_CSR_BLOCK, IPE_PRNG_CTRL_ADDR,
		       SEC_ENABLE_F8_WR(1)
		       | AUTO_WR(1)
		       | RESULT_128_WR(1));

	return 0;
}

int xgene_sec_hwstart(struct xgene_sec_ctx *ctx)
{
	/* Start the EIP96 core */
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK, CSR_SEC_CFG_ADDR, GO_MASK);
	return 0;
}

int xgene_sec_hwstop(struct xgene_sec_ctx *ctx)
{
	/* Stop the EIP96 core */
	xgene_sec_wr32(ctx, EIP96_AXI_CSR_BLOCK, CSR_SEC_CFG_ADDR, 0x0);
	return 0;
}

int xgene_sec_hwreset(struct xgene_sec_ctx *ctx)
{
	/* Enable clock for core, EIP62, XTS, EIP96, RI block */
	xgene_sec_wr32(ctx, CLK_RES_CSR_BLOCK, CSR_SEC_CLKEN_ADDR,
		       (SEC_EIP62_CLKEN_MASK |
			SEC_XTS_CLKEN_MASK |
			SEC_EIP96_CLKEN_MASK |
			SEC_AXI_CLKEN_MASK | SEC_CSR_CLKEN_MASK));
	/* Reset core, EIP62, XTS, EIP96, RI block */
	xgene_sec_wr32(ctx, CLK_RES_CSR_BLOCK, CSR_SEC_SRST_ADDR,
		       0xFFFFFFFF & ~(SEC_EIP62_RESET_MASK |
			SEC_XTS_RESET_MASK |
			SEC_EIP96_RESET_MASK |
			SEC_AXI_RESET_MASK | SEC_CSR_RESET_MASK));
	return 0;
}

static int xgene_ring_is_enabled(struct xgene_sec_ctx *ctx)
{
	u32 clkrst_offset, srst_offset;

	if (ctx->intf == XGENE_RING_VERSION1) {
		clkrst_offset = CSR_QM_CLKRST;
		srst_offset = CSR_QM_SRST;
	} else {
		clkrst_offset = CSR_QM_CLKRST_VER2;
		srst_offset = CSR_QM_SRST_VER2;
	}

	if (ioread32(ctx->csr_ring + clkrst_offset) &&
		(!ioread32(ctx->csr_ring + srst_offset)))
		return 0;

	return -ENODEV;
}

static void xgene_sec_rmsg_src_null(void *ext8)
{
	RMSG_NXTBUFDATALENGTH_SET(ext8, XGENE_INVALID_LEN);
}

static void *xgene_sec_lookup_ext8(void *msg, int idx)
{
	switch (idx) {
	case 0:
	default:
		return (struct rmsg_ext8 *) msg + 1;
	case 1:
		return (struct rmsg_ext8 *) msg;
	case 2:
		return (struct rmsg_ext8 *) msg + 3;
	case 3:
		return (struct rmsg_ext8 *) msg + 2;
	}
}

int xgene_sec_rmsg_load_src_single(struct xgene_sec_ctx *ctx,
				   struct scatterlist *src, void *ext8,
				   int *nbytes, dma_addr_t * paddr,
				   int src_offset)
{
	u32 len;
	int rc;

	if (*paddr == 0) {
		rc = dma_map_sg(ctx->dev, src, 1, DMA_TO_DEVICE);
		if (!rc) {
			dev_err(ctx->dev, "dma_map_sg() src error\n");
			return rc;
		}
		*paddr = sg_dma_address(src);
		dma_unmap_sg(ctx->dev, src, 1, DMA_TO_DEVICE);
	}
	RMSG_NXTDATAADDRH_SET(ext8, (u32) (*paddr >> 32));
	RMSG_NXTDATAADDRL_SET(ext8, (u32) *paddr);
	len = sg_dma_len(src) - src_offset;
	if (len < 16 * 1024) {
		if (*nbytes < len) {
			len = *nbytes;
		}
		APMSEC_TXLOG("spage HW 0x%0llX len %d\n", *paddr, len);
		RMSG_NXTBUFDATALENGTH_SET(ext8, xgene_ring_encode_datalen(len));
		*nbytes -= len;
		*paddr = 0;
		return len;
	} else if (len == 16 * 1024) {
		APMSEC_TXLOG("spage HW 0x%0llX len %d\n", *paddr, 16 * 1024);
		RMSG_NXTBUFDATALENGTH_SET(ext8, 0);
		*nbytes -= 16 * 1024;
		*paddr = 0;
		return len;
	} else {
		APMSEC_TXLOG("spage HW 0x%0llX len %d\n", *paddr, 16 * 1024);
		RMSG_NXTBUFDATALENGTH_SET(ext8, 0);
		*nbytes -= 16 * 1024;
		*paddr += 16 * 1024;
		return 16 * 1024;
	}
}

int xgene_sec_load_src_buffers(struct xgene_sec_ctx *ctx,
			       void *msg, void *msgup32,
			       struct scatterlist *src, int nbytes,
			       struct sec_tkn_ctx *tkn)
{
	void *ext_msg_ll8;
	struct rmsg_ext8 *ext_msg;
	dma_addr_t paddr;
	int offset;
	int ell_cnt;
	int ell_bcnt;
	int rc;
	int i;

	if (!nbytes) {
		dev_err(ctx->dev, "Zero length input not supported!\n");
		return -EINVAL;
	}

	/* Load first source buffer addr */
	paddr = 0;
	rc = xgene_sec_rmsg_load_src_single(ctx, src,
					    msg + 8, &nbytes, &paddr,
					    0);
	if (rc < 0)
		return rc;

	if (nbytes == 0)
		return 1;	/* single buffer - 32B msg */

	offset = rc;
	RMSG_NV_SET(msg, 1);		/* More than 1 buffer */

	/* Load 2nd, 3rd, and 4th buffer addr */
	memset(msgup32, 0, 32);
	xgene_sec_rmsg_src_null(xgene_sec_lookup_ext8(msgup32, 1));
	xgene_sec_rmsg_src_null(xgene_sec_lookup_ext8(msgup32, 2));
	for (i = 0; nbytes > 0 && i < 3; i++) {
		if (!paddr) {
			src = sg_next(src);
			offset = 0;
		}

		switch (i) {
		case 0:
			rc = xgene_sec_rmsg_load_src_single(ctx, src,
					xgene_sec_lookup_ext8(msgup32, 0),
					&nbytes, &paddr, offset);
			break;
		case 1:
			rc = xgene_sec_rmsg_load_src_single(ctx, src,
					xgene_sec_lookup_ext8(msgup32, 1),
					&nbytes, &paddr, offset);
			break;
		case 2:
			rc = xgene_sec_rmsg_load_src_single(ctx, src,
					xgene_sec_lookup_ext8(msgup32, 2),
					&nbytes, &paddr, offset);
			break;
		}
		if (rc < 0)
			return rc;
		offset += rc;
	}
	if (nbytes == 0) {
		xgene_sec_rmsg_src_null(xgene_sec_lookup_ext8(msgup32, 3));
		return 2;	/* 2 - 4 buffers - 64B msg */
	}
	/* Load 5th buffer addr */
	if (!paddr) {
		src = sg_next(src);
		offset = 0;
	}
	if (nbytes <= 16 * 1024 && sg_is_last(src)) {
		rc = xgene_sec_rmsg_load_src_single(ctx, src,
					xgene_sec_lookup_ext8(msgup32, 3),
					&nbytes, &paddr, offset);
		if (rc < 0)
			return rc;
		return 2;	/* 5 buffers - 64B msg */
	}

	RMSG_LL_SET(msg, 1);	/* Linked list of buffers 6 or more */

	tkn->src_addr_link = dma_alloc_coherent(ctx->dev,
					sizeof(struct rmsg_ext8) *
					APM_SEC_SRC_LINK_ADDR_MAX,
					&tkn->src_addr_link_paddr,
					GFP_ATOMIC);
	if (!tkn->src_addr_link) {
		dev_err(ctx->dev, "src addr list allocation failed\n");
		return -ENOMEM;
	}
	ext_msg_ll8 = xgene_sec_lookup_ext8(msgup32, 3);
	RMSG_LL_NXTDATAADDRL_SET(ext_msg_ll8, (u32) tkn->src_addr_link_paddr);
	RMSG_LL_NXTDATAADDRH_SET(ext_msg_ll8,
					(u32) (tkn->src_addr_link_paddr >> 32));
	ext_msg = tkn->src_addr_link;
	ell_bcnt = 0;
	ell_cnt = 0;
	for (i = 0; nbytes > 0 && i < APM_SEC_SRC_LINK_ADDR_MAX; i++) {
		/*
		 * Each field of Queue Link List has 16 Bytes:
		 *              B8 - B15: First Buffer
		 *              B0 - B7 : Second Buffer
		 */
		rc = xgene_sec_rmsg_load_src_single(ctx, src,
					&ext_msg[((i % 2) ?
					(i - 1) : (i + 1))],
					&nbytes, &paddr, offset);
		xgene_ring_msg_le32((u32 *) &
				    ext_msg[((i % 2) ? (i - 1) : (i + 1))],
				    sizeof(struct rmsg_ext8) / 4);

		if (rc < 0)
			return rc;
		ell_bcnt += rc;
		ell_cnt++;
		if (!paddr) {
			src = sg_next(src);
			offset = 0;
		} else {
			offset += rc;
		}
	}

	/* Encode the extended link list byte count and link count */
	RMSG_LL_NXTLINKLISTLENGTH_SET(ext_msg_ll8, ell_cnt);
	RMSG_TOTDATALENGTHLINKLISTLSB_SET(msg, (ell_bcnt & 0xFFF));
	RMSG_LL_TOTDATALENGTHLINKLISTMSB_SET(ext_msg_ll8,
				((ell_bcnt & 0xFF000) >> 12));
	if (nbytes == 0)
		return 2;	/* 5 - 16 buffers - 64B msg */

	dev_err(ctx->dev, "source buffer length %d too long error %d",
		nbytes, -EINVAL);

	dma_free_coherent(ctx->dev,
			  sizeof(struct rmsg_ext8) *
			  APM_SEC_SRC_LINK_ADDR_MAX,
			  tkn->src_addr_link, tkn->src_addr_link_paddr);
	tkn->src_addr_link = NULL;

	return -EINVAL;
}

void xgene_sec_rmesg_load_dst_single(struct xgene_sec_ctx *ctx,
				     void *msg, void *ptr, int nbytes)
{
	dma_addr_t paddr;

	paddr = dma_map_single(ctx->dev, ptr, nbytes, DMA_FROM_DEVICE);
	dma_unmap_single(ctx->dev, paddr, nbytes, DMA_FROM_DEVICE);
	APMSEC_TXLOG("dpage HW 0x%0llX len %d\n", paddr, nbytes);
	RMSG_H0INFO_MSBL_SET(msg, (u32) paddr);
	RMSG_H0INFO_MSBH_SET(msg, (u32) (paddr >> 32));
}

int xgene_sec_load_dst_buffers(struct xgene_sec_ctx *ctx,
			       void *msg,
			       struct scatterlist *dst, u32 nbytes,
			       struct sec_tkn_ctx *tkn)
{
	struct rmsg_ext8 *ext_msg;
	dma_addr_t paddr;
	int offset;
	int ell_cnt;
	int rc;
	int i;

	APMSEC_TXLOG("dpage len %d dst len %d\n", nbytes, dst->length);
	if (nbytes == dst->length) {
		/* Single buffer */
		rc = dma_map_sg(ctx->dev, dst, 1, DMA_FROM_DEVICE);
		if (!rc) {
			dev_err(ctx->dev, "dma_map_sg() dst error\n");
			return rc;
		}
		paddr = sg_dma_address(dst);
		dma_unmap_sg(ctx->dev, dst, 1, DMA_FROM_DEVICE);
		RMSG_H0INFO_MSBL_SET(msg, (u32) paddr);
		RMSG_H0INFO_MSBH_SET(msg, (u32) (paddr >> 32));
		return 0;
	}

	tkn->dst_addr_link = dma_alloc_coherent(ctx->dev,
						sizeof(struct rmsg_ext8) *
						APM_SEC_DST_LINK_ADDR_MAX,
						&tkn->dst_addr_link_paddr,
						GFP_ATOMIC);
	if (!tkn->dst_addr_link) {
		dev_err(ctx->dev, "dest addr list allocation failed\n");
		return -ENOMEM;
	}
	RMSG_H0INFO_MSBL_SET(msg, (u32) tkn->dst_addr_link_paddr);
	RMSG_H0INFO_MSBH_SET(msg, (u32) (tkn->dst_addr_link_paddr >> 32));
	ext_msg = tkn->dst_addr_link;
	offset = 0;
	ell_cnt = 0;
	paddr = 0;
	for (i = 0; nbytes > 0 && i < APM_SEC_DST_LINK_ADDR_MAX; i++) {
		/*
		 * Each field of Queue Link List has 16 Bytes:
		 *              B8 - B15: First Buffer
		 *              B0 - B7 : Second Buffer
		 */
		rc = xgene_sec_rmsg_load_src_single(ctx, dst,
						    &ext_msg[((i % 2) ?
						    (i - 1) : (i + 1))],
						    &nbytes, &paddr, offset);
		xgene_ring_msg_le32((u32 *) &
				    ext_msg[((i % 2) ? (i - 1) : (i + 1))],
				    sizeof(struct rmsg_ext8) / 4);

		if (rc < 0)
			return rc;
		ell_cnt++;
		if (!paddr) {
			dst = sg_next(dst);
			offset = 0;
		} else {
			offset += rc;
		}
	}

	/* Encode the extended link list byte count and link count */
	RMSG_LINKEDLIST_LEN_MSB_SET(msg, (ell_cnt & 0xF0) >> 4);
	RMSG_LINKEDLIST_LEN_LSB_SET(msg, ell_cnt);
	/*
	 * Flag linked list destination - SEC CTL = 0x3 bit 0x2 already set
	 * when loading the source pointer.
	 */
	RMSG_SEC_CTL_SET(msg, 0x3);

	if (nbytes == 0)
		return 0;

	dev_err(ctx->dev, "destination buffer length too long\n");

	dma_free_coherent(ctx->dev,
			  sizeof(struct rmsg_ext8) *
			  APM_SEC_DST_LINK_ADDR_MAX,
			  tkn->dst_addr_link, tkn->dst_addr_link_paddr);
	tkn->dst_addr_link = NULL;

	return -EINVAL;
}

int xgene_sec_loadbuffer2rmsg(struct xgene_sec_ctx *ctx,
			      void *msg, void *msgext32, struct sec_tkn_ctx *tkn)
{
	struct crypto_async_request *req = tkn->context;
	struct ablkcipher_request *ablk_req;
	struct ahash_request *ahash_req;
	struct aead_request *aead_req;
	int no_msg = 0;
	int ds;
	int rc;

	switch (crypto_tfm_alg_type(req->tfm)) {
	case CRYPTO_ALG_TYPE_AHASH:
		ahash_req = ahash_request_cast(req);
		rc = xgene_sec_load_src_buffers(ctx, msg, msgext32,
						ahash_req->src,
						ahash_req->nbytes, tkn);
		if (rc <= 0)
			break;
		no_msg = rc;
		ds = crypto_ahash_digestsize(__crypto_ahash_cast
					     (ahash_req->base.tfm));
		xgene_sec_rmesg_load_dst_single(ctx, msg, ahash_req->result,
						ds);
		break;
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
		ablk_req = ablkcipher_request_cast(req);
		rc = xgene_sec_load_src_buffers(ctx, msg, msgext32,
						ablk_req->src,
						ablk_req->nbytes, tkn);
		if (rc <= 0)
			break;
		no_msg = rc;
		rc = xgene_sec_load_dst_buffers(ctx, msg, ablk_req->dst,
						ablk_req->nbytes, tkn);
		break;
	case CRYPTO_ALG_TYPE_AEAD:
		aead_req = container_of(req, struct aead_request, base);
		if (tkn->src_sg)
			rc = xgene_sec_load_src_buffers(ctx, msg, msgext32,
							tkn->src_sg,
							tkn->src_sg_nbytes,
							tkn);
		else
			rc = xgene_sec_load_src_buffers(ctx, msg, msgext32,
							aead_req->src,
							aead_req->cryptlen,
							tkn);
		if (rc <= 0)
			break;
		no_msg = rc;
		rc = xgene_sec_load_dst_buffers(ctx, msg, aead_req->dst,
						tkn->dest_nbytes, tkn);
		break;
	default:
		BUG();
		rc = -EINVAL;
		break;
	}

	return rc < 0 ? rc : no_msg;
}

u64 xgene_sec_encode2hwaddr(u64 paddr)
{
	return paddr >> 4;
}

u64 xgene_sec_decode2hwaddr(u64 paddr)
{
	return paddr << 4;
}

int xgene_sec_queue2hw(struct xgene_sec_session_ctx *session,
		       struct sec_tkn_ctx *tkn)
{
	struct xgene_sec_ctx *ctx = session->ctx;
	struct xgene_ring_info *qinfo = &(ctx->tx_ring);
	struct xgene_ring_info *cpinfo = &(ctx->rx_ring);
	void *msg;
	void *msgext32;
	u64 hwaddr;
	int rc = 0;

	spin_lock_bh(&ctx->txlock);
	msg = &qinfo->msg32[qinfo->qhead];

	memset(msg, 0, 32);
	if (++qinfo->qhead == qinfo->count)
		qinfo->qhead = 0;

	RMSG_C_SET(msg, 1); /* Coherent IO */
	RMSG_H0ENQ_NUM_SET(msg, cpinfo->dst_ring_num);
	RMSG_RTYPE_SET(msg, RING_OWNER_SEC);
	hwaddr = xgene_sec_encode2hwaddr(tkn->result_tkn_hwptr);
	RMSG_H0INFO_LSBL_SET(msg, hwaddr);
	RMSG_H0INFO_LSBH_SET(msg, (hwaddr >> 32));
	RMSG_SEC_CTL_SET(msg, 0x2);

	/* Only used if 64B message */
	msgext32 = (struct rmsg32 *)&qinfo->msg32[qinfo->qhead];

	/* Load src/dest address into Ring message. Will return number of 32B */
	rc = xgene_sec_loadbuffer2rmsg(ctx, msg, msgext32, tkn);
	if (rc <= 0) {
		dev_err(ctx->dev, "operation submitted error %d\n", rc);
		qinfo->qhead--;
		goto done;
	}
	if (rc == 2) {
		if (++qinfo->qhead == qinfo->count)
			qinfo->qhead = 0;
	}

	APMSEC_SADUMP((u32 *) tkn->sa->sa_ptr, tkn->sa->sa_len);
	APMSEC_TKNDUMP(tkn);
	APMSEC_TXLOG("SEC MSG QID %d CQID %d 0x%08X FPQID %d 0x%08X\n",
		     qinfo->ring_id,
		     cpinfo->ring_id, RMSG_H0ENQ_NUM_RD(msg),
		     fpinfo->ring_id, RMSG_FPQNUM_RD(msg));
	APMSEC_TXLOG("SEC MSG data Addr 0x%X.%08X len 0x%08X\n",
		     RMSG_NXTDATAADDRH_RD(msg + 8),
		     RMSG_NXTDATAADDRL_RD(msg + 8),
		     RMSG_NXTBUFDATALENGTH_RD(msg + 8));
	APMSEC_TXLOG("SEC MSG token Addr 0x%X.%08X\n",
		     RMSG_H0INFO_LSBH_RD(msg), RMSG_H0INFO_LSBL_RD(msg));
	APMSEC_TXLOG("SEC MSG dest Addr 0x%X.%08X\n",
		     RMSG_H0INFO_MSBH_RD(msg), RMSG_H0INFO_MSBL_RD(msg));
	APMSEC_QMSGDUMP("SEC RMSG: ", msg, 32);
	if (rc == 2)
		APMSEC_QMSGDUMP("SEC RMSG: ", msgext32, 32);

	xgene_ring_msg_le32((u32 *) msg, 8);
	if (rc == 2)
		xgene_ring_msg_le32((u32 *) msgext32, 8);

	APMSEC_QMSGDUMP("SEC RMSG: ", msg, 32);
	if (rc == 2)
		APMSEC_QMSGDUMP("SEC RMSG: ", msgext32, 32);

	/* Tell Ring HW message queued */
	xgene_wr_cmd(qinfo, rc);
	APMSEC_TXLOG("operation submitted %d 32B msg\n", rc);
	rc = 0;

done:
	spin_unlock_bh(&ctx->txlock);
	return rc;
}

/*
 * SA and Token Management Functions
 */
struct sec_tkn_ctx *xgene_sec_tkn_get(struct xgene_sec_session_ctx *session,
				      u8 * new_tkn)
{
	struct sec_tkn_ctx *tkn;
	unsigned long flags;
	dma_addr_t paddr;
	int tkn_size;

	spin_lock_irqsave(&session->lock, flags);
	if (!list_empty(&session->tkn_cache)) {
		struct list_head *entry = session->tkn_cache.next;
		list_del(entry);
		--session->tkn_cache_cnt;
		tkn = list_entry(entry, struct sec_tkn_ctx, next);
		spin_unlock_irqrestore(&session->lock, flags);
		*new_tkn = 0;
		APMSEC_SATKNLOG("allocate tkn cached 0x%p\n", tkn);
		return tkn;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	*new_tkn = 1;
	tkn_size = session->tkn_max_len;
	tkn = dma_alloc_coherent(session->ctx->dev, tkn_size, &paddr,
				 GFP_ATOMIC);
	if (tkn == NULL)
		goto done;
	memset(tkn, 0, tkn_size);
	tkn->tkn_paddr = paddr;
	tkn->input_tkn_len = session->tkn_input_len;
	tkn->result_tkn_ptr = TKN_CTX_RESULT_TKN_COMPUTE(tkn);
	tkn->result_tkn_hwptr = paddr + TKN_CTX_RESULT_TKN_OFFSET(tkn);
	tkn->context = session;
	APMSEC_SATKNLOG("allocate tkn 0x%p size %d (%d)\n",
			tkn, tkn_size, session->tkn_input_len);
done:
	return tkn;
}

static void xgene_sec_tkn_free_mem(struct device *dev, struct sec_tkn_ctx *tkn)
{

	if (tkn->src_sg) {
		/* Free source scatterlist */
		dma_free_coherent(dev,
				  sizeof(struct scatterlist) *
				  tkn->src_sg_nents,
				  (void *)tkn->src_sg, tkn->src_sg_paddr);
		tkn->src_sg = NULL;
	}
	if (tkn->src_addr_link) {
		/* Free extended Ring source link list */
		dma_free_coherent(dev, sizeof(struct rmsg_ext8) *
				  APM_SEC_SRC_LINK_ADDR_MAX,
				  tkn->src_addr_link, tkn->src_addr_link_paddr);
		tkn->src_addr_link = NULL;
	}
	if (tkn->dst_addr_link) {
		/* Free extended Ring destination link list */
		dma_free_coherent(dev, sizeof(struct rmsg_ext8) *
				  APM_SEC_DST_LINK_ADDR_MAX,
				  tkn->dst_addr_link, tkn->dst_addr_link_paddr);
		tkn->dst_addr_link = NULL;
	}
}

void __xgene_sec_tkn_free(struct xgene_sec_session_ctx *session,
			  struct sec_tkn_ctx *tkn)
{
	xgene_sec_tkn_free_mem(session->ctx->dev, tkn);

	dma_free_coherent(session->ctx->dev, session->tkn_max_len, tkn,
			  tkn->tkn_paddr);
	APMSEC_SATKNLOG("free tkn 0x%p\n", tkn);
}

void xgene_sec_tkn_free(struct xgene_sec_session_ctx *session,
			struct sec_tkn_ctx *tkn)
{
	unsigned long flags;

	/* Free mem before add tkn into cache */
	xgene_sec_tkn_free_mem(session->ctx->dev, tkn);

	spin_lock_irqsave(&session->lock, flags);
	if (session->tkn_cache_cnt < APM_SEC_TKN_CACHE_MAX) {
		++session->tkn_cache_cnt;
		list_add(&tkn->next, &session->tkn_cache);
		spin_unlock_irqrestore(&session->lock, flags);
		APMSEC_SATKNLOG("free tkn cached 0x%p\n", tkn);
		return;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	__xgene_sec_tkn_free(session, tkn);
}

struct sec_sa_item *xgene_sec_sa_get(struct xgene_sec_session_ctx *session)
{
	struct sec_sa_item *sa;
	unsigned long flags;
	dma_addr_t paddr;
	int sa_size;

	spin_lock_irqsave(&session->lock, flags);
	if (!list_empty(&session->sa_cache)) {
		struct list_head *entry = session->sa_cache.next;
		list_del(entry);
		--session->sa_cache_cnt;
		spin_unlock_irqrestore(&session->lock, flags);
		sa = list_entry(entry, struct sec_sa_item, next);
		sa->sa_len = session->sa_len;
		APMSEC_SATKNLOG("allocate sa cached 0x%p aligned 0x%p\n",
				sa, sa->sa_ptr);
		return sa;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	sa_size = sizeof(struct sec_sa_item) + 15 + 8 + session->sa_max_len;
	sa = dma_alloc_coherent(session->ctx->dev, sa_size, &paddr, GFP_ATOMIC);
	if (sa == NULL)
		goto done;
	memset(sa, 0, sa_size);
	sa->sa_paddr = paddr;
	sa->sa_total_len = sa_size;
	sa->sa_len = session->sa_len;
	sa->sa_ptr = SA_PTR_COMPUTE(sa);
	sa->sa_hwptr = paddr + SA_PTR_OFFSET(sa);
	APMSEC_SATKNLOG("allocate sa 0x%p aligned 0x%p size %d\n",
			sa, sa->sa_ptr, sa_size);
done:
	return sa;
}

void __xgene_sec_sa_free(struct xgene_sec_session_ctx *session,
			 struct sec_sa_item *sa)
{
	dma_free_coherent(session->ctx->dev, sa->sa_total_len, sa,
			  sa->sa_paddr);
	APMSEC_SATKNLOG("free sa 0x%p\n", sa);
}

void xgene_sec_sa_free(struct xgene_sec_session_ctx *session,
		       struct sec_sa_item *sa)
{
	unsigned long flags;

	spin_lock_irqsave(&session->lock, flags);
	if (session->sa_cache_cnt < APM_SEC_SA_CACHE_MAX) {
		++session->sa_cache_cnt;
		list_add(&sa->next, &session->sa_cache);
		spin_unlock_irqrestore(&session->lock, flags);
		APMSEC_SATKNLOG("free sa cached 0x%p\n", sa);
		return;
	}
	spin_unlock_irqrestore(&session->lock, flags);

	__xgene_sec_sa_free(session, sa);
}

void xgene_sec_session_init(struct xgene_sec_session_ctx *session)
{
	memset(session, 0, sizeof(*session));
	session->ctx = xg_ctx;
	INIT_LIST_HEAD(&session->tkn_cache);
	INIT_LIST_HEAD(&session->sa_cache);
	spin_lock_init(&session->lock);
}

void xgene_sec_session_free(struct xgene_sec_session_ctx *session)
{
	struct sec_tkn_ctx *tkn;
	struct sec_tkn_ctx *tkn_tmp;
	struct sec_sa_item *sa;
	struct sec_sa_item *sa_tmp;

	list_for_each_entry_safe(sa, sa_tmp, &session->sa_cache, next)
	    __xgene_sec_sa_free(session, sa);
	if (session->sa) {
		__xgene_sec_sa_free(session, session->sa);
		session->sa = NULL;
	}
	INIT_LIST_HEAD(&session->sa_cache);
	list_for_each_entry_safe(tkn, tkn_tmp, &session->tkn_cache, next)
	    __xgene_sec_tkn_free(session, tkn);
	INIT_LIST_HEAD(&session->tkn_cache);
}

int xgene_sec_create_sa_tkn_pool(struct xgene_sec_session_ctx *session,
				 u32 sa_max_len, u32 sa_len,
				 char sa_ib, u32 tkn_len)
{
	int rc = 0;

	session->tkn_max_len = TKN_CTX_SIZE(tkn_len);
	session->tkn_input_len = tkn_len;
	session->sa_len = sa_len;
	session->sa_max_len = sa_max_len;

	if (session->sa == NULL) {
		session->sa = xgene_sec_sa_get(session);
		if (session->sa == NULL)
			rc = -ENOMEM;
	} else {
		session->sa->sa_len = sa_len;
	}
	if (!rc && session->sa_ib == NULL && sa_ib) {
		session->sa_ib = xgene_sec_sa_get(session);
		if (session->sa_ib == NULL)
			rc = -ENOMEM;
	} else if (session->sa_ib) {
		session->sa_ib->sa_len = sa_len;
	}
	return rc;
}

/*
 * Completed operations processing functions
 */
int xgene_sec_tkn_cb(struct sec_tkn_ctx *tkn)
{
	struct xgene_sec_ctx *ctx;
	struct crypto_async_request *req;
	struct xgene_sec_req_ctx *rctx;
	struct sec_tkn_result_hdr *result_tkn;
	struct xgene_sec_session_ctx *session;
	int rc = 0;
	int i;

	int *sa_context;

#if 0
	/* FIXME */
	int esp_nh_padlen = 0;
	int pad_verify_prot;
#endif

	APMSEC_RXLOG("Process completed tkn 0x%p\n", tkn);

	req = tkn->context;
	session = crypto_tfm_ctx(req->tfm);
	sa_context = (u32 *) session->sa->sa_ptr;
	ctx = session->ctx;

	i = atomic_dec_return(&ctx->ring_active);
	if (i < 0) {
		dev_err(ctx->dev, "invalid active %d\n", i);
		BUG();
	}

	result_tkn = TKN_CTX_RESULT_TKN(tkn);
	APMSEC_RXDUMP("Result SW Token ", result_tkn, TKN_RESULT_HDR_MAX_LEN);
	xgene_ring_msg_le32((u32 *) result_tkn, TKN_RESULT_HDR_MAX_LEN / 4);

	if (crypto_tfm_alg_type(req->tfm) == CRYPTO_ALG_TYPE_ABLKCIPHER)
		rctx = ablkcipher_request_ctx(ablkcipher_request_cast(req));
	else if (crypto_tfm_alg_type(req->tfm) == CRYPTO_ALG_TYPE_AHASH)
		rctx = ahash_request_ctx(ahash_request_cast(req));
	else
		rctx = aead_request_ctx(container_of(req,
						     struct aead_request,
						     base));

	if (result_tkn->EXX || result_tkn->E15) {
		if (result_tkn->EXX & (TKN_RESULT_E9 | TKN_RESULT_E10 |
				       TKN_RESULT_E11 | TKN_RESULT_E12 |
				       TKN_RESULT_E13))
			rc = -EBADMSG;
		else
			rc = -ENOSYS;
		dev_err(ctx->dev, "EIP96 hardware error %d\n", rc);
		/* apm_sec_dump_src_dst_buf(req, tkn); - FIXME */
		goto out;
	}
#if 0
	/* FIXME */
	if (result_tkn->H || result_tkn->L || result_tkn->N ||
	    result_tkn->C || result_tkn->B) {
		/*
		 * packet exceeded 1792 bytes, result appended at end
		 * of result data
		 */
		dev_err(ctx->dev, "Unexpected result token with appeded data");
	}

	if (tkn->dest_mem)
		apm_cp_buf2sg(tkn, req);

	pad_verify_prot = tkn->sa->sa_ptr->pad_type;
	if (pad_verify_prot == SA_PAD_TYPE_SSL ||
	    pad_verify_prot == SA_PAD_TYPE_TLS) {
		rc = 0;
	} else {
		esp_nh_padlen = result_tkn->next_hdr_field |
		    (result_tkn->pad_length << 8);
		rc = esp_nh_padlen ? esp_nh_padlen : 0;
	}
#endif

out:
	if (rctx->tkn->flags & (u32) TKN_FLAG_CONTINOUS) {
		/*
		 * HASH: Copy the hash result as inner digest for next
		 * continuous hash operation
		 */
		if (crypto_tfm_alg_type(req->tfm) == CRYPTO_ALG_TYPE_AHASH) {
			memcpy((void *)&sa_context[2],
			       (void *)ahash_request_cast(req)->result,
			       sec_sa_compute_digest_len(session->sa->sa_ptr->
							 hash_alg,
							 SA_DIGEST_TYPE_INNER));
			APMSEC_RXDUMP("PAYLOAD: ",
				(void *)ahash_request_cast(req)->result,
				sec_sa_compute_digest_len(session->sa->
					sa_ptr->hash_alg,
					SA_DIGEST_TYPE_INNER));
		}
	} else {
		xgene_sec_tkn_free(session, tkn);
		rctx->tkn = NULL;
		if (rctx->sa) {
			xgene_sec_sa_free(session, rctx->sa);
			rctx->sa = NULL;
		}
	}

	/* Notify packet completed */
	req->complete(req, rc);
	return 0;
}

static void xgene_sec_bh_tasklet_cb(unsigned long data)
{
#define XGENE_SEC_POLL_BUDGET	64
	struct xgene_sec_ctx *ctx;
	int budget = XGENE_SEC_POLL_BUDGET;
	struct xgene_ring_info *qdesc;
	struct rmsg32 *qbase;
	void *msg32;
	void *msgup32;
	struct sec_tkn_ctx *tkn;
	u32 command = 0;
	u64 paddr;

	ctx = (struct xgene_sec_ctx *)data;

	/* Process pending token */
	spin_lock_bh(&ctx->lock);

	qdesc = &ctx->rx_ring;
	qbase = qdesc->msg32;

	while (budget--) {
		/* Check if actual message available */
		msg32 = &qbase[qdesc->qhead];
		if (unlikely(((u32 *) msg32)[RMSG_EMPTY_SLOT_INDEX]
					== RMSG_EMPTY_SLOT_SIGNATURE))
			break;
		xgene_ring_msg_le32((u32 *) msg32, 8);
		--command;
		if (++qdesc->qhead == qdesc->count)
			qdesc->qhead = 0;
		if (RMSG_NV_MASK(msg32)) {
			/* 64B message */
			msgup32 = (void *)&qbase[qdesc->qhead];
			xgene_ring_msg_le32((u32 *) msgup32, 8);
			--command;
			if (++qdesc->qhead == qdesc->count)
				qdesc->qhead = 0;
		} else {
			msgup32 = NULL;
		}

		/* Handle Ring programming error */
		if (RMSG_ELERR_RD(msg32) | RMSG_LERR_RD(msg32))
			xgene_sec_hdlr_qerr(ctx, RMSG_LEI_RD(msg32),
					    RMSG_ELERR_RD(msg32) |
					    RMSG_LERR_RD(msg32));

		paddr = RMSG_H0INFO_LSBH_RD(msg32) & 0x3F;
		paddr <<= 32;
		paddr |= RMSG_H0INFO_LSBL_RD(msg32);
		paddr = xgene_sec_decode2hwaddr(paddr);
		/* FIXME */
		tkn = __va(TKN_CTX_HWADDR2TKN(paddr));

		/* Process the completed token */
		xgene_sec_tkn_cb(tkn);

		((u32 *) msg32)[RMSG_EMPTY_SLOT_INDEX] =
				RMSG_EMPTY_SLOT_SIGNATURE;
		if (msgup32)
			((u32 *) msgup32)[RMSG_EMPTY_SLOT_INDEX] =
					RMSG_EMPTY_SLOT_SIGNATURE;
	}
	/* Tell Ring HW we processsed x 32B messages */
	dev_dbg(ctx->dev, "processed %d 32B message\n", command);
	xgene_wr_cmd(qdesc, command);

	spin_unlock_bh(&ctx->lock);

	/* Re-enable IRQ */
	enable_irq(ctx->rx_ring.irq);
}

static irqreturn_t xgene_sec_rmsg_isr(int value, void *id)
{
	struct xgene_sec_ctx *ctx = id;
	disable_irq_nosync(ctx->rx_ring.irq);
	tasklet_schedule(&ctx->tasklet);
	return IRQ_HANDLED;
}

/*
 * Request enqueue processing functions
 */
static inline int apm_sec_hw_queue_available(struct xgene_sec_ctx *ctx)
{
	return atomic_read(&ctx->ring_active) >= MAX_SLOT ? 0 : 1;
}

static int xgene_sec_send2hwq(struct crypto_async_request *req)
{
	struct xgene_sec_session_ctx *session;
	struct xgene_sec_ctx *ctx;
	struct xgene_sec_req_ctx *rctx;
	int rc;

	switch (crypto_tfm_alg_type(req->tfm)) {
	case CRYPTO_ALG_TYPE_ABLKCIPHER:
		rctx = ablkcipher_request_ctx(ablkcipher_request_cast(req));
		session =
		    crypto_tfm_ctx(ablkcipher_request_cast(req)->base.tfm);
		break;
	case CRYPTO_ALG_TYPE_AEAD:
		rctx =
		    aead_request_ctx(container_of
				     (req, struct aead_request, base));
		session =
		    crypto_tfm_ctx(container_of
				   (req, struct aead_request, base)->base.tfm);
		break;
	case CRYPTO_ALG_TYPE_AHASH:
		rctx = ahash_request_ctx(ahash_request_cast(req));
		session = crypto_tfm_ctx(ahash_request_cast(req)->base.tfm);
		break;
	default:
		BUG();
		break;
	}
	ctx = session->ctx;
	atomic_inc(&ctx->ring_active);

	rc = xgene_sec_queue2hw(session, rctx->tkn);
	if (rc != 0) {
		dev_err(ctx->dev, "failed submission error 0x%08X\n", rc);
		atomic_dec(&ctx->ring_active);
	} else
		rc = -EINPROGRESS;

	return rc;

}

static int xgene_sec_handle_req(struct xgene_sec_ctx *ctx,
				struct crypto_async_request *req)
{
	int ret = -EAGAIN;

	if (apm_sec_hw_queue_available(ctx))
		ret = xgene_sec_send2hwq(req);

	if (ret == -EAGAIN) {
		unsigned long flags;
		spin_lock_irqsave(&ctx->lock, flags);
		ret = crypto_enqueue_request(&ctx->queue, req);
		spin_unlock_irqrestore(&ctx->lock, flags);
	}
	return ret;
}

static int xgene_sec_process_queue(struct xgene_sec_ctx *ctx)
{
	struct crypto_async_request *req;
	unsigned long flags;
	int err = 0;

	while (apm_sec_hw_queue_available(ctx)) {
		spin_lock_irqsave(&ctx->lock, flags);
		req = crypto_dequeue_request(&ctx->queue);
		spin_unlock_irqrestore(&ctx->lock, flags);

		if (!req)
			break;
		err = xgene_sec_handle_req(ctx, req);
		if (err)
			break;
	}
	return err;
}

int xgene_sec_setup_crypto(struct xgene_sec_ctx *ctx,
			   struct crypto_async_request *req)
{
	int err;

	err = xgene_sec_handle_req(ctx, req);
	if (err)
		return err;

	if (apm_sec_hw_queue_available(ctx) && ctx->queue.qlen)
		err = xgene_sec_process_queue(ctx);
	return err;
}

/*
 * Algorithm registration functions
 */
int xgene_sec_alg_init(struct crypto_tfm *tfm)
{
	struct crypto_alg *alg = tfm->__crt_alg;
	struct xgene_sec_session_ctx *session = crypto_tfm_ctx(tfm);

	xgene_sec_session_init(session);

	if (alg->cra_type == &crypto_ablkcipher_type)
		tfm->crt_ablkcipher.reqsize = sizeof(struct xgene_sec_req_ctx);
	else if (alg->cra_type == &crypto_ahash_type)
		crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
					 sizeof(struct xgene_sec_req_ctx));
	else if (alg->cra_type == &crypto_aead_type)
		tfm->crt_aead.reqsize = sizeof(struct xgene_sec_req_ctx);

	return 0;
}

void xgene_sec_alg_exit(struct crypto_tfm *tfm)
{
	struct xgene_sec_session_ctx *session = crypto_tfm_ctx(tfm);
	xgene_sec_session_free(session);
}

static int xgene_sec_register_alg(struct xgene_sec_ctx *ctx)
{
	struct xgene_sec_alg *alg;
	struct crypto_alg *cipher;
	int rc = 0;
	int i;

	for (i = 0; xgene_sec_alg_tlb[i].type != 0; i++) {
		alg = devm_kzalloc(ctx->dev, sizeof(struct xgene_sec_alg),
				   GFP_KERNEL);
		if (!alg)
			return -ENOMEM;
		alg->type = xgene_sec_alg_tlb[i].type;
		switch (alg->type) {
		case CRYPTO_ALG_TYPE_AHASH:
			alg->u.hash = xgene_sec_alg_tlb[i].u.hash;
			cipher = &alg->u.hash.halg.base;
			break;
		default:
			alg->u.cipher = xgene_sec_alg_tlb[i].u.cipher;
			cipher = &alg->u.cipher;
			break;
		}
		INIT_LIST_HEAD(&cipher->cra_list);
		if (!cipher->cra_init)
			cipher->cra_init = xgene_sec_alg_init;
		if (!cipher->cra_exit)
			cipher->cra_exit = xgene_sec_alg_exit;
		if (!cipher->cra_module)
			cipher->cra_module = THIS_MODULE;
		if (!cipher->cra_module)
			cipher->cra_priority = XGENE_SEC_CRYPTO_PRIORITY;
		switch (alg->type) {
		case CRYPTO_ALG_TYPE_AHASH:
			rc = crypto_register_ahash(&alg->u.hash);
			break;
		default:
			rc = crypto_register_alg(&alg->u.cipher);
			break;
		}
		if (rc) {
			dev_err(ctx->dev,
				"failed to register alg %s error %d\n",
				cipher->cra_name, rc);
			list_del(&alg->entry);
			devm_kfree(ctx->dev, alg);
			return rc;
		}
		list_add_tail(&alg->entry, &ctx->alg_list);
	}
	return rc;
}

static void xgene_sec_unregister_alg(struct xgene_sec_ctx *ctx)
{
	struct xgene_sec_alg *alg, *tmp;

	list_for_each_entry_safe(alg, tmp, &ctx->alg_list, entry) {
		list_del(&alg->entry);
		switch (alg->type) {
		case CRYPTO_ALG_TYPE_AHASH:
			crypto_unregister_ahash(&alg->u.hash);
			break;

		default:
			crypto_unregister_alg(&alg->u.cipher);
			break;
		}
		devm_kfree(ctx->dev, alg);
	}
}

static int xgene_sec_runtime_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct xgene_sec_ctx *ctx = platform_get_drvdata(pdev);

	if (!PTR_ERR(ctx->sec_clk))
		clk_disable_unprepare(ctx->sec_clk);

	return 0;
}

static int xgene_sec_runtime_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct xgene_sec_ctx *ctx = platform_get_drvdata(pdev);
	int ret;

	if (!PTR_ERR(ctx->sec_clk)) {
		ret = clk_prepare_enable(ctx->sec_clk);
		if (ret) {
			dev_err(dev, "clk_enable failed: %d\n", ret);
			return ret;
		}
	}
	return 0;
}


static int xgene_sec_get_resources(struct platform_device *pdev,
				   struct xgene_sec_ctx *ctx)
{
	struct resource *res;
	int rc;

	/* SEC CSR base address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(ctx->dev, "no CSR space\n");
		return -EINVAL;
	}

	ctx->csr = devm_ioremap(ctx->dev, res->start, resource_size(res));
	if (!ctx->csr) {
		dev_err(ctx->dev, "can't map %pR\n", res);
		return -ENOMEM;
	}
	dev_dbg(ctx->dev, "CSR PAddr 0x%016LX VAddr 0x%p size %lld",
		res->start, ctx->csr, resource_size(res));

	/* RING SOC CSR base address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(ctx->dev, "no RING CSR space for SEC block\n");
		return -EINVAL;
	}

	ctx->csr_ring = devm_ioremap(ctx->dev, res->start, resource_size(res));
	if (!ctx->csr_ring) {
		dev_err(ctx->dev, "can't map %pR\n", res);
		return -ENOMEM;
	}
	dev_dbg(ctx->dev, "RING CSR PAddr 0x%016LX VAddr 0x%p size %lld",
		res->start, ctx->csr_ring, resource_size(res));

	/* RING SOC Primary Fabric address */
	res = platform_get_resource(pdev, IORESOURCE_MEM, 2);
	if (!res) {
		dev_err(ctx->dev, "Failed to get Ring Fabric region for SEC block\n");
		return -EINVAL;
	}

	ctx->csr_cmd = devm_ioremap(ctx->dev, res->start, resource_size(res));
	if (!ctx->csr_cmd) {
		dev_err(ctx->dev, "can't map %pR\n", res);
		return -ENOMEM;
	}
	dev_dbg(ctx->dev, "Ring CMD CSR PAddr 0x%016LX VAddr 0x%p size %lld",
		res->start, ctx->csr_cmd, resource_size(res));

	/* Setup IRQ */
	ctx->irq = platform_get_irq(pdev, 0);
	if (ctx->irq <= 0) {
		dev_err(ctx->dev, "no IRQ in DTS\n");
		return -ENODEV;
	}

	rc = request_irq(ctx->irq, xgene_sec_intr_cb, 0, "crypto-err", ctx);
	if (rc != 0) {
		dev_err(ctx->dev,
			"security core can not register for interrupt %d\n",
			ctx->irq);
		return -EINVAL;
	}

	/* Setup IRQ for completion operation */
	if (!crypto_uio) {
		ctx->rx_ring.irq = platform_get_irq(pdev, 1);
		if (ctx->irq <= 0) {
			dev_err(ctx->dev, "no IRQ for complete queue in DTS\n");
			return -ENODEV;
		}
		rc = request_irq(ctx->rx_ring.irq, xgene_sec_rmsg_isr, 0,
				 "crypto", ctx);
		if (rc) {
			dev_err(ctx->dev, "failed to register IRQ %d\n",
				ctx->rx_ring.irq);
			return -EINVAL;
		}
	}

	return 0;
}

#if defined(CONFIG_OF)
static const struct of_device_id xgene_sec_of_device_ids[] = {
	{
		.compatible = "apm,xgene-storm-crypto",
		.data = (void *) XGENE_RING_VERSION1
	},
	{
		.compatible = "apm,xgene-magneto-crypto",
		.data = (void *) XGENE_RING_VERSION2
	},
	{},
};
MODULE_DEVICE_TABLE(of, xgene_sec_of_device_ids);
#endif

static int xgene_sec_probe(struct platform_device *pdev)
{
	const struct of_device_id *of_devid;
	struct device *dev = &pdev->dev;
	struct xgene_sec_ctx *ctx;
	int rc;

	of_devid = of_match_device(xgene_sec_of_device_ids, &pdev->dev);

	ctx = devm_kzalloc(dev, sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		dev_err(dev, "can't allocate security context\n");
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&ctx->alg_list);
	spin_lock_init(&ctx->lock);
	spin_lock_init(&ctx->txlock);
	atomic_set(&ctx->ring_active, 0);
	ctx->dev = dev;
	platform_set_drvdata(pdev, ctx);

	dev_dbg(ctx->dev, "Initialize the security hardware\n");

	/* Setup ring ops */
	ctx->intf = (enum xgene_ring_interface) of_devid->data;

	/* Get resources for SEC and RING SOC */
	rc = xgene_sec_get_resources(pdev, ctx);
	if (rc)
		goto err_hw;

	/* SEC clock */
	ctx->sec_clk = devm_clk_get(dev, NULL);
	if (IS_ERR(ctx->sec_clk) && !efi_enabled(EFI_BOOT)) {
		dev_err(dev, "no clock entry\n");
		rc = PTR_ERR(ctx->sec_clk);
		goto err_hw;
	}

	pm_runtime_enable(&pdev->dev);
	if (!pm_runtime_enabled(&pdev->dev)) {
		rc = xgene_sec_runtime_resume(&pdev->dev);
		if (rc) {
			dev_err(dev, "xgene_sec_runtime_resume failed %d\n",
				rc);
			goto err_hw;
		}
	}

	/* Enable clock before accessing registers */
	if (!IS_ERR(ctx->sec_clk)) {
		rc = clk_prepare_enable(ctx->sec_clk);
		if (rc) {
			dev_err(dev, "clk_prepare_enable failed: %d\n",	rc);
			goto err_hw;
		}
	}

	/* Setup CSR address pointer */
	ctx->clk_csr = ctx->csr + APM_SEC_CLK_RES_CSR_OFFSET;
	ctx->diag_csr = ctx->csr + APM_SEC_GLBL_DIAG_OFFSET;
	ctx->eip96_axi_csr = ctx->csr + APM_EIP96_AXI_CSR_OFFSET;
	ctx->eip96_csr = ctx->csr + APM_EIP96_CSR_OFFSET;
	ctx->eip96_core_csr = ctx->csr + APM_EIP96_CORE_CSR_OFFSET;
	ctx->ctrl_csr = ctx->csr + APM_SEC_GLBL_CTRL_CSR_OFFSET;
	ctx->ri_ctl_csr = ctx->csr + APM_RI_CTL_OFFSET;

	/* Init tasklet for bottom half processing */
	tasklet_init(&ctx->tasklet, xgene_sec_bh_tasklet_cb,
		     (unsigned long)ctx);

	/* Initialize software queue to 1 */
	crypto_init_queue(&ctx->queue, 1);

	/* Take IP out of reset */
	rc = xgene_sec_hwreset(ctx);
	if (rc != 0)
		goto err_hw;

	rc = xgene_ring_is_enabled(ctx);
	if (rc)
		goto err_hw;

	/* Remove Security CSR memory from shutdown */
	rc = xgene_sec_init_memram(ctx);
	if (rc != 0)
		goto err_hw;

	/* Initialize the security hardware */
	rc = xgene_sec_hwinit(ctx);
	if (rc != 0)
		goto err_hw;

	/* Start the security hardware */
	rc = xgene_sec_hwstart(ctx);
	if (rc != 0)
		goto err_hw;

	dev_set_drvdata(dev, ctx);
	xg_ctx = ctx;

	/* RING configuration */
	if (xgene_create_rings(ctx))
		goto err_hw;

	dev->dma_mask = &dev->coherent_dma_mask;
	dev->coherent_dma_mask = DMA_BIT_MASK(64);

	/* Register security algorithms with Linux CryptoAPI */
	if (!crypto_uio) {
		rc = xgene_sec_register_alg(ctx);
		if (rc)
			goto err_reg_alg;
	} else {
		xgene_sec_uio_init(pdev, ctx);
	}

	dev_info(dev, "APM X-Gene SoC security accelerator driver\n");
	return 0;

err_reg_alg:
	xgene_sec_hwstop(ctx);

err_hw:
	if (ctx->irq != 0)
		free_irq(ctx->irq, ctx);
	if (!crypto_uio)
		if (ctx->rx_ring.irq != 0)
			free_irq(ctx->rx_ring.irq, ctx);
	devm_kfree(dev, ctx);
	return rc;
}

static int xgene_sec_remove(struct platform_device *pdev)
{
	struct xgene_sec_ctx *ctx = dev_get_drvdata(&pdev->dev);

	/* Un-register with Linux CryptoAPI */
	if (!crypto_uio)
		xgene_sec_unregister_alg(ctx);
	else
		xgene_sec_uio_deinit(ctx);

	/* Stop hardware */
	xgene_sec_hwstop(ctx);

	dev_dbg(ctx->dev,
		"unloaded APM X-Gene SoC security accelerator driver\n");

	xgene_sec_deinit_rings(ctx);

	pm_runtime_disable(&pdev->dev);
	if (!pm_runtime_status_suspended(&pdev->dev))
		xgene_sec_runtime_suspend(&pdev->dev);

	devm_kfree(&pdev->dev, ctx);

	return 0;
}

static const struct dev_pm_ops xgene_sec_pm_ops = {
#ifdef CONFIG_PM_RUNTIME
	.runtime_suspend = xgene_sec_runtime_suspend,
	.runtime_resume = xgene_sec_runtime_resume,
#endif
};

static struct platform_driver xgene_sec_driver = {
	.driver = {
		.name = "xgene-crypto",
		.owner = THIS_MODULE,
		.pm = &xgene_sec_pm_ops,
		.of_match_table = xgene_sec_of_device_ids,
		},
	.probe = xgene_sec_probe,
	.remove = xgene_sec_remove,
};

module_platform_driver(xgene_sec_driver);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Loc Ho <lho@apm.com>");
MODULE_DESCRIPTION("APM X-Gene SoC security hw accelerator");

