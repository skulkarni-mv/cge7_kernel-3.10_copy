/*
 * Driver for MMC and SSD cards for Cavium OCTEON SOCs.
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2012 Cavium Inc.
 */

#include <linux/platform_device.h>
#include <linux/of_platform.h>
#include <linux/scatterlist.h>
#include <linux/interrupt.h>
#include <linux/of_gpio.h>
#include <linux/blkdev.h>
#include <linux/device.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/clk.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/of.h>

#include <linux/mmc/card.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sd.h>
#include <net/irda/parameters.h>

#include <asm/byteorder.h>
#include <asm/octeon/octeon.h>
#include <asm/octeon/cvmx-mio-defs.h>

#define DRV_NAME	"octeon_mmc"

#define OCTEON_MAX_MMC			4

#define OCT_MIO_NDF_DMA_CFG		0x00
#define OCT_MIO_EMM_DMA_ADR		0x08

#define OCT_MIO_EMM_CFG			0x00
#define OCT_MIO_EMM_SWITCH		0x48
#define OCT_MIO_EMM_DMA			0x50
#define OCT_MIO_EMM_CMD			0x58
#define OCT_MIO_EMM_RSP_STS		0x60
#define OCT_MIO_EMM_RSP_LO		0x68
#define OCT_MIO_EMM_RSP_HI		0x70
#define OCT_MIO_EMM_INT			0x78
#define OCT_MIO_EMM_INT_EN		0x80
#define OCT_MIO_EMM_WDOG		0x88
#define OCT_MIO_EMM_SAMPLE		0x90
#define OCT_MIO_EMM_STS_MASK		0x98
#define OCT_MIO_EMM_RCA			0xa0
#define OCT_MIO_EMM_BUF_IDX		0xe0
#define OCT_MIO_EMM_BUF_DAT		0xe8

struct octeon_mmc_host {
	u64	base;
	u64	ndf_base;
	u64	emm_cfg;
	u64	n_minus_one;  /* OCTEON II workaround location */
	int	last_slot;

	struct semaphore mmc_serializer;
	struct mmc_request	*current_req;
	unsigned int		linear_buf_size;
	void			*linear_buf;
	struct sg_mapping_iter smi;
	int sg_idx;
	bool dma_active;

	struct platform_device	*pdev;
	int global_pwr_gpio;
	bool global_pwr_gpio_low;
	bool dma_err_pending;
	bool need_bootbus_lock;
	bool big_dma_addr;
	bool need_irq_handler_lock;
	spinlock_t irq_handler_lock;
	bool has_ciu3;

	struct octeon_mmc_slot	*slot[OCTEON_MAX_MMC];
};

struct octeon_mmc_slot {
	struct mmc_host         *mmc;	/* slot-level mmc_core object */
	struct octeon_mmc_host	*host;	/* common hw for all 4 slots */

	unsigned int		clock;
	unsigned int		sclock;

	u64			cached_switch;
	u64			cached_rca;

	unsigned int		cmd_cnt; /* sample delay */
	unsigned int		dat_cnt; /* sample delay */

	int			bus_width;
	int			bus_id;
	int			ro_gpio;
	int			cd_gpio;
	int			pwr_gpio;
	bool			cd_gpio_low;
	bool			ro_gpio_low;
	bool			pwr_gpio_low;
};

static int bb_size = 1 << 18;
module_param(bb_size, int, S_IRUGO);
MODULE_PARM_DESC(limit_max_blk,
		 "Size of DMA linearizing buffer (max transfer size).");

static int ddr = 2;
module_param(ddr, int, S_IRUGO);
MODULE_PARM_DESC(ddr,
		 "enable DoubleDataRate clocking:"
		 " 0=no, 1=always, 2=at spi-max-frequency/2");

#if 0
#define octeon_mmc_dbg trace_printk
#else
static inline void octeon_mmc_dbg(const char *s, ...) { }
#endif

static void octeon_mmc_acquire_bus(struct octeon_mmc_host *host)
{
	if (host->need_bootbus_lock) {
		down(&octeon_bootbus_sem);
		/* On cn70XX switch the mmc unit onto the bus. */
		if (OCTEON_IS_MODEL(OCTEON_CN70XX))
			cvmx_write_csr(CVMX_MIO_BOOT_CTL, 0);
	} else {
		down(&host->mmc_serializer);
	}
}

static void octeon_mmc_release_bus(struct octeon_mmc_host *host)
{
	if (host->need_bootbus_lock)
		up(&octeon_bootbus_sem);
	else
		up(&host->mmc_serializer);
}

struct octeon_mmc_cr_type {
	u8 ctype;
	u8 rtype;
};

/*
 * The OCTEON MMC host hardware assumes that all commands have fixed
 * command and response types.  These are correct if MMC devices are
 * being used.  However, non-MMC devices like SD use command and
 * response types that are unexpected by the host hardware.
 *
 * The command and response types can be overridden by supplying an
 * XOR value that is applied to the type.  We calculate the XOR value
 * from the values in this table and the flags passed from the MMC
 * core.
 */
static struct octeon_mmc_cr_type octeon_mmc_cr_types[] = {
	{0, 0},		/* CMD0 */
	{0, 3},		/* CMD1 */
	{0, 2},		/* CMD2 */
	{0, 1},		/* CMD3 */
	{0, 0},		/* CMD4 */
	{0, 1},		/* CMD5 */
	{0, 1},		/* CMD6 */
	{0, 1},		/* CMD7 */
	{1, 1},		/* CMD8 */
	{0, 2},		/* CMD9 */
	{0, 2},		/* CMD10 */
	{1, 1},		/* CMD11 */
	{0, 1},		/* CMD12 */
	{0, 1},		/* CMD13 */
	{1, 1},		/* CMD14 */
	{0, 0},		/* CMD15 */
	{0, 1},		/* CMD16 */
	{1, 1},		/* CMD17 */
	{1, 1},		/* CMD18 */
	{3, 1},		/* CMD19 */
	{2, 1},		/* CMD20 */
	{0, 0},		/* CMD21 */
	{0, 0},		/* CMD22 */
	{0, 1},		/* CMD23 */
	{2, 1},		/* CMD24 */
	{2, 1},		/* CMD25 */
	{2, 1},		/* CMD26 */
	{2, 1},		/* CMD27 */
	{0, 1},		/* CMD28 */
	{0, 1},		/* CMD29 */
	{1, 1},		/* CMD30 */
	{1, 1},		/* CMD31 */
	{0, 0},		/* CMD32 */
	{0, 0},		/* CMD33 */
	{0, 0},		/* CMD34 */
	{0, 1},		/* CMD35 */
	{0, 1},		/* CMD36 */
	{0, 0},		/* CMD37 */
	{0, 1},		/* CMD38 */
	{0, 4},		/* CMD39 */
	{0, 5},		/* CMD40 */
	{0, 0},		/* CMD41 */
	{2, 1},		/* CMD42 */
	{0, 0},		/* CMD43 */
	{0, 0},		/* CMD44 */
	{0, 0},		/* CMD45 */
	{0, 0},		/* CMD46 */
	{0, 0},		/* CMD47 */
	{0, 0},		/* CMD48 */
	{0, 0},		/* CMD49 */
	{0, 0},		/* CMD50 */
	{0, 0},		/* CMD51 */
	{0, 0},		/* CMD52 */
	{0, 0},		/* CMD53 */
	{0, 0},		/* CMD54 */
	{0, 1},		/* CMD55 */
	{0xff, 0xff},	/* CMD56 */
	{0, 0},		/* CMD57 */
	{0, 0},		/* CMD58 */
	{0, 0},		/* CMD59 */
	{0, 0},		/* CMD60 */
	{0, 0},		/* CMD61 */
	{0, 0},		/* CMD62 */
	{0, 0}		/* CMD63 */
};

struct octeon_mmc_cr_mods {
	u8 ctype_xor;
	u8 rtype_xor;
};

static inline void *phys_to_ptr(u64 address)
{
	return (void *)(address | (1ull<<63)); /* XKPHYS */
}

/**
 * Lock a single line into L2. The line is zeroed before locking
 * to make sure no dram accesses are made.
 *
 * @addr   Physical address to lock
 */
static void l2c_lock_line(u64 addr)
{
	char *addr_ptr = phys_to_ptr(addr);
	asm volatile (
		"cache 31, %[line]"	/* Unlock the line */
		:: [line] "m" (*addr_ptr));
}

/**
 * Locks a memory region in the L2 cache
 *
 * @start - start address to begin locking
 * @len - length in bytes to lock
 */
static void l2c_lock_mem_region(u64 start, u64 len)
{
	u64 end;

	/* Round start/end to cache line boundaries */
	end = ALIGN(start + len - 1, CVMX_CACHE_LINE_SIZE);
	start = ALIGN(start, CVMX_CACHE_LINE_SIZE);

	while (start <= end) {
		l2c_lock_line(start);
		start += CVMX_CACHE_LINE_SIZE;
	}
	asm volatile("sync");
}

/**
 * Unlock a single line in the L2 cache.
 *
 * @addr	Physical address to unlock
 *
 * Return Zero on success
 */
static void l2c_unlock_line(u64 addr)
{
	char *addr_ptr = phys_to_ptr(addr);
	asm volatile (
		"cache 23, %[line]"	/* Unlock the line */
		:: [line] "m" (*addr_ptr));
}

/**
 * Unlock a memory region in the L2 cache
 *
 * @start - start address to unlock
 * @len - length to unlock in bytes
 */
static void l2c_unlock_mem_region(u64 start, u64 len)
{
	u64 end;

	/* Round start/end to cache line boundaries */
	end = ALIGN(start + len - 1, CVMX_CACHE_LINE_SIZE);
	start = ALIGN(start, CVMX_CACHE_LINE_SIZE);

	while (start <= end) {
		l2c_unlock_line(start);
		start += CVMX_CACHE_LINE_SIZE;
	}
}

static struct octeon_mmc_cr_mods octeon_mmc_get_cr_mods(struct mmc_command *cmd)
{
	struct octeon_mmc_cr_type *cr;
	u8 desired_ctype, hardware_ctype;
	u8 desired_rtype, hardware_rtype;
	struct octeon_mmc_cr_mods r;

	desired_ctype = desired_rtype = 0;

	cr = octeon_mmc_cr_types + (cmd->opcode & 0x3f);
	hardware_ctype = cr->ctype;
	hardware_rtype = cr->rtype;
	if (cmd->opcode == 56) { /* CMD56 GEN_CMD */
		hardware_ctype = (cmd->arg & 1) ? 1 : 2;
	}

	switch (mmc_cmd_type(cmd)) {
	case MMC_CMD_ADTC:
		desired_ctype = (cmd->data->flags & MMC_DATA_WRITE) ? 2 : 1;
		break;
	case MMC_CMD_AC:
	case MMC_CMD_BC:
	case MMC_CMD_BCR:
		desired_ctype = 0;
		break;
	}

	switch (mmc_resp_type(cmd)) {
	case MMC_RSP_NONE:
		desired_rtype = 0;
		break;
	case MMC_RSP_R1:/* MMC_RSP_R5, MMC_RSP_R6, MMC_RSP_R7 */
	case MMC_RSP_R1B:
		desired_rtype = 1;
		break;
	case MMC_RSP_R2:
		desired_rtype = 2;
		break;
	case MMC_RSP_R3: /* MMC_RSP_R4 */
		desired_rtype = 3;
		break;
	}
	r.ctype_xor = desired_ctype ^ hardware_ctype;
	r.rtype_xor = desired_rtype ^ hardware_rtype;
	return r;
}

static bool octeon_mmc_switch_val_changed(struct octeon_mmc_slot *slot,
					  u64 new_val)
{
	/* Match BUS_ID, HS_TIMING, BUS_WIDTH, POWER_CLASS, CLK_HI, CLK_LO */
	u64 m = 0x3001070fffffffffull;
	return (slot->cached_switch & m) != (new_val & m);
}

static unsigned int octeon_mmc_timeout_to_wdog(struct octeon_mmc_slot *slot,
					       unsigned int ns)
{
	u64 bt = (u64)slot->clock * (u64)ns;
	return (unsigned int)(bt / 1000000000);
}

static irqreturn_t octeon_mmc_interrupt(int irq, void *dev_id)
{
	struct octeon_mmc_host *host = dev_id;
	union cvmx_mio_emm_int emm_int;
	struct mmc_request	*req;
	bool host_done;
	union cvmx_mio_emm_rsp_sts rsp_sts;
	unsigned long flags = 0;

	if (host->need_irq_handler_lock)
		spin_lock_irqsave(&host->irq_handler_lock, flags);
	emm_int.u64 = cvmx_read_csr(host->base + OCT_MIO_EMM_INT);
	req = host->current_req;
	cvmx_write_csr(host->base + OCT_MIO_EMM_INT, emm_int.u64);

	octeon_mmc_dbg("Got interrupt: EMM_INT = 0x%llx\n", emm_int.u64);

	if (!req)
		goto out;

	rsp_sts.u64 = cvmx_read_csr(host->base + OCT_MIO_EMM_RSP_STS);
	octeon_mmc_dbg("octeon_mmc_interrupt  MIO_EMM_RSP_STS 0x%llx\n", rsp_sts.u64);

	if (host->dma_err_pending) {
		host->current_req = NULL;
		host->dma_err_pending = false;
		req->done(req);
		host_done = true;
		goto no_req_done;
	}

	if (!host->dma_active && emm_int.s.buf_done && req->data) {
		unsigned int type = (rsp_sts.u64 >> 7) & 3;
		if (type == 1) {
			/* Read */
			int dbuf = rsp_sts.s.dbuf;
			struct sg_mapping_iter *smi = &host->smi;
			unsigned int data_len = req->data->blksz * req->data->blocks;
			unsigned int bytes_xfered;
			u64 dat = 0;
			int shift = -1;

			/* Auto inc from offset zero */
			cvmx_write_csr(host->base + OCT_MIO_EMM_BUF_IDX, (u64)(0x10000 | (dbuf << 6)));

			for (bytes_xfered = 0; bytes_xfered < data_len;) {
				if (smi->consumed >= smi->length) {
					if (!sg_miter_next(smi))
						break;
					smi->consumed = 0;
				}
				if (shift < 0) {
					dat = cvmx_read_csr(host->base + OCT_MIO_EMM_BUF_DAT);
					shift = 56;
				}

				while (smi->consumed < smi->length && shift >= 0) {
					((u8 *)(smi->addr))[smi->consumed] = (dat >> shift) & 0xff;
					bytes_xfered++;
					smi->consumed++;
					shift -= 8;
				}
			}
			sg_miter_stop(smi);
			req->data->bytes_xfered = bytes_xfered;
			req->data->error = 0;
		} else if (type == 2) {
			/* write */
			req->data->bytes_xfered = req->data->blksz * req->data->blocks;
			req->data->error = 0;
		}
	}
	host_done = emm_int.s.cmd_done || emm_int.s.dma_done ||
		emm_int.s.cmd_err || emm_int.s.dma_err;
	if (host_done && req->done) {
		if (rsp_sts.s.rsp_bad_sts ||
		    rsp_sts.s.rsp_crc_err ||
		    rsp_sts.s.rsp_timeout ||
		    rsp_sts.s.blk_crc_err ||
		    rsp_sts.s.blk_timeout ||
		    rsp_sts.s.dbuf_err) {
			req->cmd->error = -EILSEQ;
		} else {
			req->cmd->error = 0;
		}

		if (host->dma_active && req->data) {
			req->data->error = 0;
			req->data->bytes_xfered = req->data->blocks * req->data->blksz;
			if (!(req->data->flags & MMC_DATA_WRITE) && req->data->sg_len > 1) {
				size_t r = sg_copy_from_buffer(req->data->sg, req->data->sg_len,
						   host->linear_buf, req->data->bytes_xfered);
				WARN_ON(r != req->data->bytes_xfered);
			}
		}
		if (rsp_sts.s.rsp_val) {
			u64 rsp_hi;
			u64 rsp_lo = cvmx_read_csr(host->base + OCT_MIO_EMM_RSP_LO);

			switch (rsp_sts.s.rsp_type) {
			case 1:
			case 3:
				req->cmd->resp[0] = (rsp_lo >> 8) & 0xffffffff;
				req->cmd->resp[1] = 0;
				req->cmd->resp[2] = 0;
				req->cmd->resp[3] = 0;
				break;
			case 2:
				req->cmd->resp[3] = rsp_lo & 0xffffffff;
				req->cmd->resp[2] = (rsp_lo >> 32) & 0xffffffff;
				rsp_hi = cvmx_read_csr(host->base + OCT_MIO_EMM_RSP_HI);
				req->cmd->resp[1] = rsp_hi & 0xffffffff;
				req->cmd->resp[0] = (rsp_hi >> 32) & 0xffffffff;
				break;
			default:
				octeon_mmc_dbg("octeon_mmc_interrupt unhandled rsp_val %d\n",
					       rsp_sts.s.rsp_type);
				break;
			}
			octeon_mmc_dbg("octeon_mmc_interrupt  resp %08x %08x %08x %08x\n",
				       req->cmd->resp[0], req->cmd->resp[1],
				       req->cmd->resp[2], req->cmd->resp[3]);
		}
		if (emm_int.s.dma_err && rsp_sts.s.dma_pend) {
			/* Try to clean up failed DMA */
			union cvmx_mio_emm_dma emm_dma;
			emm_dma.u64 = cvmx_read_csr(host->base + OCT_MIO_EMM_DMA);
			emm_dma.s.dma_val = 1;
			emm_dma.s.dat_null = 1;
			emm_dma.s.bus_id = rsp_sts.s.bus_id;
			cvmx_write_csr(host->base + OCT_MIO_EMM_DMA,
				       emm_dma.u64);
			host->dma_err_pending = true;
			host_done = false;
			goto no_req_done;
		}

		host->current_req = NULL;
		req->done(req);
	}
no_req_done:
	if (host->n_minus_one) {
		l2c_unlock_mem_region(host->n_minus_one, 512);
		host->n_minus_one = 0;
	}
	if (host_done)
		octeon_mmc_release_bus(host);
out:
	if (host->need_irq_handler_lock)
		spin_unlock_irqrestore(&host->irq_handler_lock, flags);
	return IRQ_RETVAL(emm_int.u64 != 0);
}

static void octeon_mmc_switch_to(struct octeon_mmc_slot	*slot)
{
	struct octeon_mmc_host	*host = slot->host;
	struct octeon_mmc_slot	*old_slot;
	union cvmx_mio_emm_switch sw;
	union cvmx_mio_emm_sample samp;

	if (slot->bus_id == host->last_slot)
		goto out;

	if (host->last_slot >= 0) {
		old_slot = host->slot[host->last_slot];
		old_slot->cached_switch = cvmx_read_csr(host->base + OCT_MIO_EMM_SWITCH);
		old_slot->cached_rca = cvmx_read_csr(host->base + OCT_MIO_EMM_RCA);
	}
	cvmx_write_csr(host->base + OCT_MIO_EMM_RCA, slot->cached_rca);
	sw.u64 = slot->cached_switch;
	sw.s.bus_id = 0;
	cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, sw.u64);
	sw.s.bus_id = slot->bus_id;
	cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, sw.u64);

	samp.u64 = 0;
	samp.s.cmd_cnt = slot->cmd_cnt;
	samp.s.dat_cnt = slot->dat_cnt;
	cvmx_write_csr(host->base + OCT_MIO_EMM_SAMPLE, samp.u64);
out:
	host->last_slot = slot->bus_id;
}

static void octeon_mmc_dma_request(struct mmc_host *mmc,
				   struct mmc_request *mrq)
{
	struct octeon_mmc_slot	*slot;
	struct octeon_mmc_host	*host;
	struct mmc_command *cmd;
	struct mmc_data *data;
	union cvmx_mio_emm_int emm_int;
	union cvmx_mio_emm_dma emm_dma;
	union cvmx_mio_ndf_dma_cfg dma_cfg;

	cmd = mrq->cmd;
	if (mrq->data == NULL || mrq->data->sg == NULL || !mrq->data->sg_len ||
	    mrq->stop == NULL || mrq->stop->opcode != MMC_STOP_TRANSMISSION) {
		dev_err(&mmc->card->dev,
			"Error: octeon_mmc_dma_request no data\n");
		cmd->error = -EINVAL;
		if (mrq->done)
			mrq->done(mrq);
		return;
	}

	slot = mmc_priv(mmc);
	host = slot->host;

	/* Only a single user of the bootbus at a time. */
	octeon_mmc_acquire_bus(host);

	octeon_mmc_switch_to(slot);

	data = mrq->data;

	if (data->timeout_ns) {
		cvmx_write_csr(host->base + OCT_MIO_EMM_WDOG,
			       octeon_mmc_timeout_to_wdog(slot, data->timeout_ns));
		octeon_mmc_dbg("OCT_MIO_EMM_WDOG %llu\n",
			       cvmx_read_csr(host->base + OCT_MIO_EMM_WDOG));
	}

	WARN_ON(host->current_req);
	host->current_req = mrq;

	host->sg_idx = 0;

	WARN_ON(data->blksz * data->blocks > host->linear_buf_size);

	if ((data->flags & MMC_DATA_WRITE) && data->sg_len > 1) {
		size_t r = sg_copy_to_buffer(data->sg, data->sg_len,
			 host->linear_buf, data->blksz * data->blocks);
		WARN_ON(data->blksz * data->blocks != r);
	}

	dma_cfg.u64 = 0;
	dma_cfg.s.en = 1;
	dma_cfg.s.rw = (data->flags & MMC_DATA_WRITE) ? 1 : 0;
#ifdef __LITTLE_ENDIAN
	dma_cfg.s.endian = 1;
#endif
	dma_cfg.s.size = ((data->blksz * data->blocks) / 8) - 1;
	if (!host->big_dma_addr) {
		if (data->sg_len > 1)
			dma_cfg.s.adr = virt_to_phys(host->linear_buf);
		else
			dma_cfg.s.adr = sg_phys(data->sg);
	}
	cvmx_write_csr(host->ndf_base + OCT_MIO_NDF_DMA_CFG, dma_cfg.u64);
	octeon_mmc_dbg("MIO_NDF_DMA_CFG: %016llx\n", (unsigned long long)dma_cfg.u64);
	if (host->big_dma_addr) {
		u64 addr;
		if (data->sg_len > 1)
			addr = virt_to_phys(host->linear_buf);
		else
			addr = sg_phys(data->sg);
		cvmx_write_csr(host->ndf_base + OCT_MIO_EMM_DMA_ADR, addr);
		octeon_mmc_dbg("MIO_EMM_DMA_ADR: %016llx\n", (unsigned long long)addr);
	}

	emm_dma.u64 = 0;
	emm_dma.s.bus_id = slot->bus_id;
	emm_dma.s.dma_val = 1;
	emm_dma.s.sector = mmc_card_blockaddr(mmc->card) ? 1 : 0;
	emm_dma.s.rw = (data->flags & MMC_DATA_WRITE) ? 1 : 0;
	if (mmc_card_mmc(mmc->card) ||
	    (mmc_card_sd(mmc->card) && (mmc->card->scr.cmds & SD_SCR_CMD23_SUPPORT)))
		emm_dma.s.multi = 1;
	emm_dma.s.block_cnt = data->blocks;
	emm_dma.s.card_addr = cmd->arg;

	emm_int.u64 = 0;
	emm_int.s.dma_done = 1;
	emm_int.s.cmd_err = 1;
	emm_int.s.dma_err = 1;
	/* Clear the bit. */
	cvmx_write_csr(host->base + OCT_MIO_EMM_INT, emm_int.u64);
	if (!host->has_ciu3)
		cvmx_write_csr(host->base + OCT_MIO_EMM_INT_EN, emm_int.u64);
	host->dma_active = true;

	if ((OCTEON_IS_MODEL(OCTEON_CN6XXX) || OCTEON_IS_MODEL(OCTEON_CNF7XXX)) &&
	    cmd->opcode == MMC_WRITE_MULTIPLE_BLOCK &&
	    (data->blksz * data->blocks) > 1024) {
		host->n_minus_one = dma_cfg.s.adr + (data->blksz * data->blocks) - 1024;
		l2c_lock_mem_region(host->n_minus_one, 512);
	}

	if (mmc->card && mmc_card_sd(mmc->card))
		cvmx_write_csr(host->base + OCT_MIO_EMM_STS_MASK, 0x00b00000ull);
	else
		cvmx_write_csr(host->base + OCT_MIO_EMM_STS_MASK, 0xe4f90080ull);
	cvmx_write_csr(host->base + OCT_MIO_EMM_DMA, emm_dma.u64);
	octeon_mmc_dbg("MIO_EMM_DMA: %llx\n", emm_dma.u64);
}

static void octeon_mmc_request(struct mmc_host *mmc, struct mmc_request *mrq)
{
	struct octeon_mmc_slot	*slot;
	struct octeon_mmc_host	*host;
	struct mmc_command *cmd;
	union cvmx_mio_emm_int emm_int;
	union cvmx_mio_emm_cmd emm_cmd;
	struct octeon_mmc_cr_mods mods;

	cmd = mrq->cmd;

	if (cmd->opcode == MMC_READ_MULTIPLE_BLOCK || cmd->opcode == MMC_WRITE_MULTIPLE_BLOCK) {
		octeon_mmc_dma_request(mmc, mrq);
		return;
	}

	mods = octeon_mmc_get_cr_mods(cmd);

	slot = mmc_priv(mmc);
	host = slot->host;

	/* Only a single user of the bootbus at a time. */
	octeon_mmc_acquire_bus(host);

	octeon_mmc_switch_to(slot);

	WARN_ON(host->current_req);
	host->current_req = mrq;

	emm_int.u64 = 0;
	emm_int.s.cmd_done = 1;
	emm_int.s.cmd_err = 1;
	if (cmd->data) {
		octeon_mmc_dbg("command has data\n");
		if (cmd->data->flags & MMC_DATA_READ) {
			sg_miter_start(&host->smi, mrq->data->sg,
				       mrq->data->sg_len, SG_MITER_ATOMIC | SG_MITER_TO_SG);
		} else {
			struct sg_mapping_iter *smi = &host->smi;
			unsigned int data_len = mrq->data->blksz * mrq->data->blocks;
			unsigned int bytes_xfered;
			u64 dat = 0;
			int shift = 56;
			/* Copy data to the xmit buffer before issuing the command */
			sg_miter_start(smi, mrq->data->sg,
				       mrq->data->sg_len, SG_MITER_FROM_SG);
			/* Auto inc from offset zero, dbuf zero */
			cvmx_write_csr(host->base + OCT_MIO_EMM_BUF_IDX, 0x10000ull);

			for (bytes_xfered = 0; bytes_xfered < data_len;) {
				if (smi->consumed >= smi->length) {
					if (!sg_miter_next(smi))
						break;
					smi->consumed = 0;
				}

				while (smi->consumed < smi->length && shift >= 0) {
					dat |= (u64)(((u8 *)(smi->addr))[smi->consumed]) << shift;
					bytes_xfered++;
					smi->consumed++;
					shift -= 8;
				}
				if (shift < 0) {
					cvmx_write_csr(host->base + OCT_MIO_EMM_BUF_DAT, dat);
					shift = 56;
					dat = 0;
				}
			}
			sg_miter_stop(smi);
		}
		if (cmd->data->timeout_ns) {
			cvmx_write_csr(host->base + OCT_MIO_EMM_WDOG,
				       octeon_mmc_timeout_to_wdog(slot, cmd->data->timeout_ns));
			octeon_mmc_dbg("OCT_MIO_EMM_WDOG %llu\n",
				       cvmx_read_csr(host->base + OCT_MIO_EMM_WDOG));
		}
	} else {
		cvmx_write_csr(host->base + OCT_MIO_EMM_WDOG,
			       ((u64)slot->clock * 850ull) / 1000ull);
		octeon_mmc_dbg("OCT_MIO_EMM_WDOG %llu\n",
			       cvmx_read_csr(host->base + OCT_MIO_EMM_WDOG));
	}
	/* Clear the bit. */
	cvmx_write_csr(host->base + OCT_MIO_EMM_INT, emm_int.u64);
	if (!host->has_ciu3)
		cvmx_write_csr(host->base + OCT_MIO_EMM_INT_EN, emm_int.u64);
	host->dma_active = false;

	emm_cmd.u64 = 0;
	emm_cmd.s.cmd_val = 1;
	emm_cmd.s.ctype_xor = mods.ctype_xor;
	emm_cmd.s.rtype_xor = mods.rtype_xor;
	if (mmc_cmd_type(cmd) == MMC_CMD_ADTC)
		emm_cmd.s.offset = 64 - ((cmd->data->blksz * cmd->data->blocks) / 8);
	emm_cmd.s.bus_id = slot->bus_id;
	emm_cmd.s.cmd_idx = cmd->opcode;
	emm_cmd.s.arg = cmd->arg;
	cvmx_write_csr(host->base + OCT_MIO_EMM_STS_MASK, 0);
	cvmx_write_csr(host->base + OCT_MIO_EMM_CMD, emm_cmd.u64);
	octeon_mmc_dbg("MIO_EMM_CMD: %llx\n", emm_cmd.u64);
}

static void octeon_mmc_reset_bus(struct octeon_mmc_slot *slot, int preserve)
{
	union cvmx_mio_emm_cfg emm_cfg;
	union cvmx_mio_emm_switch emm_switch;
	u64 wdog = 0;

	emm_cfg.u64 = cvmx_read_csr(slot->host->base + OCT_MIO_EMM_CFG);
	if (preserve) {
		emm_switch.u64 = cvmx_read_csr(slot->host->base + OCT_MIO_EMM_SWITCH);
		wdog = cvmx_read_csr(slot->host->base + OCT_MIO_EMM_WDOG);
	}

	/* Restore switch settings */
	if (preserve) {
		emm_switch.s.switch_exe = 0;
		emm_switch.s.switch_err0 = 0;
		emm_switch.s.switch_err1 = 0;
		emm_switch.s.switch_err2 = 0;
		emm_switch.s.bus_id = 0;
		cvmx_write_csr(slot->host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);
		emm_switch.s.bus_id = slot->bus_id;
		cvmx_write_csr(slot->host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);

		slot->cached_switch = emm_switch.u64;

		msleep(10);
		cvmx_write_csr(slot->host->base + OCT_MIO_EMM_WDOG, wdog);
	} else {
		slot->cached_switch = 0;
	}
}

static void octeon_mmc_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct octeon_mmc_slot	*slot;
	struct octeon_mmc_host	*host;
	int bus_width;
	int clock;
	bool ddr_clock;
	int hs_timing;
	int power_class = 10;
	int clk_period;
	int timeout = 2000;
	union cvmx_mio_emm_switch emm_switch;
	union cvmx_mio_emm_rsp_sts emm_sts;

	slot = mmc_priv(mmc);
	host = slot->host;

	/* Only a single user of the bootbus at a time. */
	octeon_mmc_acquire_bus(host);

	octeon_mmc_switch_to(slot);

	octeon_mmc_dbg("Calling set_ios: slot: clk = 0x%x, bus_width = %d\n",
		       slot->clock, slot->bus_width);
	octeon_mmc_dbg("Calling set_ios: ios: clk = 0x%x, vdd = %u, bus_width = %u, power_mode = %u, timing = %u\n",
		       ios->clock, ios->vdd, ios->bus_width, ios->power_mode,
		       ios->timing);
	octeon_mmc_dbg("Calling set_ios: mmc: caps = 0x%x, bus_width = %d\n",
		       mmc->caps, mmc->ios.bus_width);

	/*
	 * Reset the chip on each power off
	 */
	if (ios->power_mode == MMC_POWER_OFF) {
		octeon_mmc_reset_bus(slot, 1);
		if (slot->pwr_gpio >= 0)
			gpio_set_value_cansleep(slot->pwr_gpio,
						slot->pwr_gpio_low);
	} else {
		if (slot->pwr_gpio >= 0)
			gpio_set_value_cansleep(slot->pwr_gpio,
						!slot->pwr_gpio_low);
	}

	switch (ios->bus_width) {
	case MMC_BUS_WIDTH_8:
		bus_width = 2;
		break;
	case MMC_BUS_WIDTH_4:
		bus_width = 1;
		break;
	case MMC_BUS_WIDTH_1:
		bus_width = 0;
		break;
	default:
		octeon_mmc_dbg("unknown bus width %d\n", ios->bus_width);
		bus_width = 0;
		break;
	}

	hs_timing = (ios->timing == MMC_TIMING_MMC_HS);
	ddr_clock = (bus_width && ios->timing >= MMC_TIMING_UHS_DDR50);

	if (ddr_clock)
		bus_width |= 4;

	if (ios->clock) {
		slot->clock = ios->clock;
		slot->bus_width = bus_width;

		clock = slot->clock;

		if (clock > 52000000)
			clock = 52000000;

		clk_period = (octeon_get_io_clock_rate() + clock - 1) / (2 * clock);

		/* until clock-renengotiate-on-CRC is in */
		if (ddr_clock && ddr > 1)
			clk_period *= 2;

		emm_switch.u64 = 0;
		emm_switch.s.hs_timing = hs_timing;
		emm_switch.s.bus_width = bus_width;
		emm_switch.s.power_class = power_class;
		emm_switch.s.clk_hi = clk_period;
		emm_switch.s.clk_lo = clk_period;

		if (!octeon_mmc_switch_val_changed(slot, emm_switch.u64)) {
			octeon_mmc_dbg("No change from 0x%llx mio_emm_switch, returning.\n",
				       emm_switch.u64);
			goto out;
		}

		octeon_mmc_dbg("Writing 0x%llx to mio_emm_wdog\n",
			       ((u64)clock * 850ull) / 1000ull);
		cvmx_write_csr(host->base + OCT_MIO_EMM_WDOG,
			       ((u64)clock * 850ull) / 1000ull);
		octeon_mmc_dbg("Writing 0x%llx to mio_emm_switch\n", emm_switch.u64);

		cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);
		emm_switch.s.bus_id = slot->bus_id;
		cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);
		slot->cached_switch = emm_switch.u64;

		do {
			emm_sts.u64 = cvmx_read_csr(host->base + OCT_MIO_EMM_RSP_STS);
			if (!emm_sts.s.switch_val)
				break;
			udelay(100);
		} while (timeout-- > 0);

		if (timeout <= 0) {
			octeon_mmc_dbg("switch command timed out, status=0x%llx\n",
				       emm_sts.u64);
			goto out;
		}
	}
out:
	octeon_mmc_release_bus(host);
}

static int octeon_mmc_get_ro(struct mmc_host *mmc)
{
	struct octeon_mmc_slot	*slot = mmc_priv(mmc);

	if (slot->ro_gpio >= 0) {
		int pin = gpio_get_value_cansleep(slot->ro_gpio);
		if (pin < 0)
			return pin;
		if (slot->ro_gpio_low)
			pin = !pin;
		return pin;
	} else {
		return -ENOSYS;
	}
}

static int octeon_mmc_get_cd(struct mmc_host *mmc)
{
	struct octeon_mmc_slot	*slot = mmc_priv(mmc);

	if (slot->cd_gpio >= 0) {
		int pin = gpio_get_value_cansleep(slot->cd_gpio);
		if (pin < 0)
			return pin;
		if (slot->cd_gpio_low)
			pin = !pin;
		return pin;
	} else {
		return -ENOSYS;
	}
}

static const struct mmc_host_ops octeon_mmc_ops = {
	.request        = octeon_mmc_request,
	.set_ios        = octeon_mmc_set_ios,
	.get_ro		= octeon_mmc_get_ro,
	.get_cd		= octeon_mmc_get_cd,
};

static void octeon_mmc_set_clock(struct octeon_mmc_slot *slot,
				 unsigned int clock)
{
	struct mmc_host *mmc = slot->mmc;
	clock = min(clock, mmc->f_max);
	clock = max(clock, mmc->f_min);
	slot->clock = clock;
}

static int octeon_mmc_initlowlevel(struct octeon_mmc_slot *slot,
				   int bus_width)
{
	union cvmx_mio_emm_switch emm_switch;
	struct octeon_mmc_host *host = slot->host;

	host->emm_cfg |= 1ull << slot->bus_id;
	cvmx_write_csr(slot->host->base + OCT_MIO_EMM_CFG, host->emm_cfg);
	octeon_mmc_set_clock(slot, 400000);

	/* Program initial clock speed and power */
	emm_switch.u64 = 0;
	emm_switch.s.power_class = 10;
	emm_switch.s.clk_hi = (slot->sclock / slot->clock) / 2;
	emm_switch.s.clk_lo = (slot->sclock / slot->clock) / 2;

	cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);
	emm_switch.s.bus_id = slot->bus_id;
	cvmx_write_csr(host->base + OCT_MIO_EMM_SWITCH, emm_switch.u64);
	slot->cached_switch = emm_switch.u64;

	cvmx_write_csr(host->base + OCT_MIO_EMM_WDOG,
		       ((u64)slot->clock * 850ull) / 1000ull);
	cvmx_write_csr(host->base + OCT_MIO_EMM_STS_MASK, 0xe4f90080ull);
	cvmx_write_csr(host->base + OCT_MIO_EMM_RCA, 1);
	return 0;
}

static int __init octeon_init_slot(struct octeon_mmc_host *host, int id,
				   int bus_width, int max_freq,
				   int ro_gpio, int cd_gpio, int pwr_gpio,
				   bool ro_low, bool cd_low, bool power_low,
				   u32 cmd_skew, u32 dat_skew)
{
	struct mmc_host *mmc;
	struct octeon_mmc_slot *slot;
	u64 clock_period;
	int ret;

	/*
	 * Allocate MMC structue
	 */
	mmc = mmc_alloc_host(sizeof(struct octeon_mmc_slot), &host->pdev->dev);
	if (!mmc) {
		dev_err(&host->pdev->dev, "alloc host failed\n");
		return -ENOMEM;
	}

	slot = mmc_priv(mmc);
	slot->mmc = mmc;
	slot->host = host;
	slot->ro_gpio = ro_gpio;
	slot->cd_gpio = cd_gpio;
	slot->pwr_gpio = pwr_gpio;
	slot->ro_gpio_low = ro_low;
	slot->cd_gpio_low = cd_low;
	slot->pwr_gpio_low = power_low;

	if (slot->ro_gpio >= 0) {
		ret = gpio_request(slot->ro_gpio, "mmc_ro");
		if (ret) {
			dev_err(&host->pdev->dev,
				"Could not request mmc_ro GPIO %d\n",
				slot->ro_gpio);
			return ret;
		}
		gpio_direction_input(slot->ro_gpio);
	}
	if (slot->cd_gpio >= 0) {
		ret = gpio_request(slot->cd_gpio, "mmc_card_detect");
		if (ret) {
			if (slot->ro_gpio >= 0)
				gpio_free(slot->ro_gpio);
			dev_err(&host->pdev->dev, "Could not request mmc_card_detect GPIO %d\n",
				slot->cd_gpio);
			return ret;
		}
		gpio_direction_input(slot->cd_gpio);
	}
	if (slot->pwr_gpio >= 0) {
		ret = gpio_request(slot->pwr_gpio, "mmc_power");
		if (ret) {
			dev_err(&host->pdev->dev,
				"Could not request mmc_power GPIO %d\n",
				slot->pwr_gpio);
			if (slot->ro_gpio >= 0)
				gpio_free(slot->ro_gpio);
			if (slot->cd_gpio)
				gpio_free(slot->cd_gpio);
			return ret;
		}
		octeon_mmc_dbg("%s: Shutting off power to slot %d via gpio %d\n",
			       DRV_NAME, slot->bus_id, slot->pwr_gpio);
		gpio_direction_output(slot->pwr_gpio,
				      slot->pwr_gpio_low);
	}
	/*
	 * Set up host parameters.
	 */
	mmc->ops = &octeon_mmc_ops;
	mmc->f_min = 400000;
	mmc->f_max = max_freq;
	mmc->caps = MMC_CAP_MMC_HIGHSPEED | MMC_CAP_SD_HIGHSPEED |
		    MMC_CAP_8_BIT_DATA | MMC_CAP_4_BIT_DATA |
		    MMC_CAP_ERASE;
	mmc->ocr_avail = MMC_VDD_27_28 | MMC_VDD_28_29 | MMC_VDD_29_30 |
			 MMC_VDD_30_31 | MMC_VDD_31_32 | MMC_VDD_32_33 |
			 MMC_VDD_33_34 | MMC_VDD_34_35 | MMC_VDD_35_36;

	/* post-sdk23 caps */
	mmc->caps |=
		((mmc->f_max >= 12000000) * MMC_CAP_UHS_SDR12) |
		((mmc->f_max >= 25000000) * MMC_CAP_UHS_SDR25) |
		((mmc->f_max >= 50000000) * MMC_CAP_UHS_SDR50) |
		MMC_CAP_CMD23;

	if (host->global_pwr_gpio >= 0)
		mmc->caps |= MMC_CAP_POWER_OFF_CARD;

	/* "1.8v" capability is actually 1.8-or-3.3v */
	if (ddr)
		mmc->caps |= MMC_CAP_UHS_DDR50 | MMC_CAP_1_8V_DDR;

	mmc->max_segs = 64;
	mmc->max_seg_size = host->linear_buf_size;
	mmc->max_req_size = host->linear_buf_size;
	mmc->max_blk_size = 512;
	mmc->max_blk_count = mmc->max_req_size / 512;

	slot->clock = mmc->f_min;
	slot->sclock = octeon_get_io_clock_rate();

	clock_period = 1000000000000ull / slot->sclock; /* period in pS */
	slot->cmd_cnt = (cmd_skew + clock_period / 2) / clock_period;
	slot->dat_cnt = (dat_skew + clock_period / 2) / clock_period;

	slot->bus_width = bus_width;
	slot->bus_id = id;
	slot->cached_rca = 1;

	/* Only a single user of the bootbus at a time. */
	octeon_mmc_acquire_bus(host);
	host->slot[id] = slot;

	octeon_mmc_switch_to(slot);
	/* Initialize MMC Block. */
	octeon_mmc_initlowlevel(slot, bus_width);

	octeon_mmc_release_bus(host);

	ret = mmc_add_host(mmc);
	octeon_mmc_dbg("mmc_add_host returned %d\n", ret);

	return 0;
}

static int octeon_mmc_probe(struct platform_device *pdev)
{
	union cvmx_mio_emm_cfg emm_cfg;
	struct octeon_mmc_host *host;
	struct resource	*res;
	void __iomem *base;
	int mmc_irq[9];
	int i;
	int ret = 0;
	struct device_node *node = pdev->dev.of_node;
	int found = 0;
	bool cn78xx_style;
	u64 t;
	enum of_gpio_flags f;

	host = devm_kzalloc(&pdev->dev, sizeof(*host), GFP_KERNEL);
	if (!host) {
		dev_err(&pdev->dev, "devm_kzalloc failed\n");
		return -ENOMEM;
	}
	spin_lock_init(&host->irq_handler_lock);
	sema_init(&host->mmc_serializer, 1);

	cn78xx_style = of_device_is_compatible(node, "cavium,octeon-7890-mmc");
	if (cn78xx_style) {
		host->need_bootbus_lock = false;
		host->big_dma_addr = true;
		host->need_irq_handler_lock = true;
		host->has_ciu3 = true;
		/*
		 * First seven are the EMM_INT bits 0..6, then two for
		 * the EMM_DMA_INT bits
		 */
		for (i = 0; i < 9; i++) {
			mmc_irq[i] = platform_get_irq(pdev, i);
			if (mmc_irq[i] < 0)
				return mmc_irq[i];

			/* work around legacy u-boot device trees */
			irq_set_irq_type(mmc_irq[i], IRQ_TYPE_EDGE_RISING);
		}
	} else {
		host->need_bootbus_lock = true;
		host->big_dma_addr = false;
		host->need_irq_handler_lock = false;
		host->has_ciu3 = false;
		/* First one is EMM second NDF_DMA */
		for (i = 0; i < 2; i++) {
			mmc_irq[i] = platform_get_irq(pdev, i);
			if (mmc_irq[i] < 0)
				return mmc_irq[i];
		}
	}
	host->last_slot = -1;

	if (bb_size < 512 || bb_size >= (1 << 24))
		bb_size = 1 << 18;
	host->linear_buf_size = bb_size;
	host->linear_buf = devm_kzalloc(&pdev->dev, host->linear_buf_size, GFP_KERNEL);

	if (!host->linear_buf) {
		dev_err(&pdev->dev, "devm_kzalloc failed\n");
		return -ENOMEM;
	}

	host->pdev = pdev;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(&pdev->dev, "Platform resource[0] is missing\n");
		return -ENXIO;
	}
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base))
		return PTR_ERR(base);
	host->base = (u64)base;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!res) {
		dev_err(&pdev->dev, "Platform resource[1] is missing\n");
		ret = -EINVAL;
		goto err;
	}
	base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(base)) {
		ret = PTR_ERR(base);
		goto err;
	}
	host->ndf_base = (u64)base;
	/*
	 * Clear out any pending interrupts that may be left over from
	 * bootloader.
	 */
	t = cvmx_read_csr(host->base + OCT_MIO_EMM_INT);
	cvmx_write_csr(host->base + OCT_MIO_EMM_INT, t);
	if (cn78xx_style) {
		/* Only CMD_DONE, DMA_DONE, CMD_ERR, DMA_ERR */
		for (i = 1; i <= 4; i++) {
			ret = devm_request_irq(&pdev->dev, mmc_irq[i], octeon_mmc_interrupt,
					       0, DRV_NAME, host);
			if (ret < 0) {
				dev_err(&pdev->dev, "Error: devm_request_irq %d\n", mmc_irq[i]);
				goto err;
			}
		}
	} else {
		ret = devm_request_irq(&pdev->dev, mmc_irq[0], octeon_mmc_interrupt,
				       0, DRV_NAME, host);
		if (ret < 0) {
			dev_err(&pdev->dev, "Error: devm_request_irq %d\n", mmc_irq[0]);
			goto err;
		}
	}

	ret = of_get_named_gpio_flags(node, "power-gpios", 0, &f);
	if (ret == -EPROBE_DEFER)
		goto err;

	host->global_pwr_gpio = ret;
	host->global_pwr_gpio_low = (host->global_pwr_gpio >= 0 && f == OF_GPIO_ACTIVE_LOW);

	if (host->global_pwr_gpio >= 0) {
		ret = gpio_request(host->global_pwr_gpio, "mmc global power");
		if (ret) {
			dev_err(&pdev->dev,
				"Could not request mmc global power gpio %d\n",
				host->global_pwr_gpio);
			goto err;
		}
		dev_dbg(&pdev->dev, "Global power on\n");
		gpio_direction_output(host->global_pwr_gpio,
				      !host->global_pwr_gpio_low);
	}

	platform_set_drvdata(pdev, host);

	node = of_get_next_child(pdev->dev.of_node, NULL);
	while (node) {
		int r;
		u32 slot;
		found = 0;

		r = of_property_read_u32(node, "reg", &slot);
		if (!r) {
			int ro_gpio, cd_gpio, pwr_gpio;
			bool ro_low, cd_low, pwr_low;
			u32 bus_width, max_freq, cmd_skew, dat_skew;

			r = of_property_read_u32(node, "cavium,bus-max-width", &bus_width);
			if (r) {
				pr_info("Bus width not found for slot %d\n", slot);
				bus_width = 8;
			} else {
				switch (bus_width) {
				case 1:
				case 4:
				case 8:
					break;
				default:
					bus_width = 8;
					break;
				}
			}

			r = of_property_read_u32(node, "cavium,cmd-clk-skew", &cmd_skew);
			if (r)
				cmd_skew = 0;

			r = of_property_read_u32(node, "cavium,dat-clk-skew", &dat_skew);
			if (r)
				dat_skew = 0;

			r = of_property_read_u32(node, "spi-max-frequency", &max_freq);
			if (r) {
				max_freq = 52000000;
				pr_info("no spi-max-frequency for slot %d, defautling to %d\n",
					slot, max_freq);
			}

			ro_gpio = of_get_named_gpio_flags(node, "wp-gpios", 0, &f);
			ro_low = (ro_gpio >= 0 && f == OF_GPIO_ACTIVE_LOW);
			cd_gpio = of_get_named_gpio_flags(node, "cd-gpios", 0, &f);
			cd_low = (cd_gpio >= 0 && f == OF_GPIO_ACTIVE_LOW);
			pwr_gpio = of_get_named_gpio_flags(node, "power-gpios", 0, &f);
			pwr_low = (pwr_gpio >= 0 && f == OF_GPIO_ACTIVE_LOW);

			ret = octeon_init_slot(host, slot, bus_width, max_freq,
					       ro_gpio, cd_gpio, pwr_gpio,
					       ro_low, cd_low, pwr_low, cmd_skew, dat_skew);
			octeon_mmc_dbg("init slot %d, ret = %d\n", slot, ret);
			if (ret)
				goto err;
		}
		node = of_get_next_child(pdev->dev.of_node, node);
	}

	return ret;

err:
	/* Disable MMC controller */
	emm_cfg.s.bus_ena = 0;
	cvmx_write_csr(host->base + OCT_MIO_EMM_CFG, emm_cfg.u64);

	if (host->global_pwr_gpio >= 0) {
		dev_dbg(&pdev->dev, "Global power off\n");
		gpio_set_value_cansleep(host->global_pwr_gpio,
					host->global_pwr_gpio_low);
		gpio_free(host->global_pwr_gpio);
	}

	return ret;
}

static int octeon_mmc_remove(struct platform_device *pdev)
{
	union cvmx_mio_ndf_dma_cfg ndf_dma_cfg;
	struct octeon_mmc_host *host = platform_get_drvdata(pdev);
	struct octeon_mmc_slot *slot;

	platform_set_drvdata(pdev, NULL);

	if (host) {
		int i;

		/* quench all users */
		for (i = 0; i < OCTEON_MAX_MMC; i++) {
			slot = host->slot[i];
			if (slot)
				mmc_remove_host(slot->mmc);
		}

		/* Reset bus_id */
		ndf_dma_cfg.u64 = cvmx_read_csr(host->ndf_base + OCT_MIO_NDF_DMA_CFG);
		ndf_dma_cfg.s.en = 0;
		cvmx_write_csr(host->ndf_base + OCT_MIO_NDF_DMA_CFG,
			       ndf_dma_cfg.u64);

		for (i = 0; i < OCTEON_MAX_MMC; i++) {
			struct octeon_mmc_slot *slot;
			slot = host->slot[i];
			if (!slot)
				continue;
			/* Free the GPIOs */
			if (slot->ro_gpio >= 0)
				gpio_free(slot->ro_gpio);
			if (slot->cd_gpio >= 0)
				gpio_free(slot->cd_gpio);
			if (slot->pwr_gpio >= 0) {
				gpio_set_value_cansleep(slot->pwr_gpio,
							slot->pwr_gpio_low);
				gpio_free(slot->pwr_gpio);
			}
		}

		if (host->global_pwr_gpio >= 0) {
			dev_dbg(&pdev->dev, "Global power off\n");
			gpio_set_value_cansleep(host->global_pwr_gpio,
						host->global_pwr_gpio_low);
			gpio_free(host->global_pwr_gpio);
		}

		for (i = 0; i < OCTEON_MAX_MMC; i++) {
			slot = host->slot[i];
			if (slot)
				mmc_free_host(slot->mmc);
		}

	}
	return 0;
}

static struct of_device_id octeon_mmc_match[] = {
	{
		.compatible = "cavium,octeon-6130-mmc",
	},
	{
		.compatible = "cavium,octeon-7890-mmc",
	},
	{},
};
MODULE_DEVICE_TABLE(of, octeon_mmc_match);

static struct platform_driver octeon_mmc_driver = {
	.probe		= octeon_mmc_probe,
	.remove		= octeon_mmc_remove,
	.driver		= {
		.name	= DRV_NAME,
		.owner	= THIS_MODULE,
		.of_match_table = octeon_mmc_match,
	},
};

static int __init octeon_mmc_init(void)
{
	int ret;

	octeon_mmc_dbg("calling octeon_mmc_init\n");

	ret = platform_driver_register(&octeon_mmc_driver);
	octeon_mmc_dbg("driver probe returned %d\n", ret);

	if (ret)
		pr_err("%s: Failed to register driver\n", DRV_NAME);

	return ret;
}

static void __exit octeon_mmc_cleanup(void)
{
	/* Unregister MMC driver */
	platform_driver_unregister(&octeon_mmc_driver);
}

module_init(octeon_mmc_init);
module_exit(octeon_mmc_cleanup);

MODULE_AUTHOR("Cavium Inc. <support@caviumn.com>");
MODULE_DESCRIPTION("low-level driver for Cavium OCTEON MMC/SSD card");
MODULE_LICENSE("GPL");
