/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 * Based on Synopsys DesignWare Multimedia Card Interface driver
 * (Based on NXP driver for lpc 31xx)
 *
 * Copyright (C) 2009 NXP Semiconductors
 * Copyright (C) 2009, 2010 Imagination Technologies Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <linux/blkdev.h>
#include <linux/clk.h>
#include <linux/debugfs.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/ioport.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/delay.h>
#include <linux/irq.h>
#include <linux/mmc/host.h>
#include <linux/mmc/mmc.h>
#include <linux/mmc/sdio.h>
#include <linux/bitops.h>
#include <linux/regulator/consumer.h>
#include <linux/workqueue.h>
#include <linux/of.h>
#include <linux/timer.h>
#include <linux/of_gpio.h>

#include <mach/opv5xc.h>

#ifdef CONFIG_MMC_DW_SWITCH_VOL_TPS65911
#include <linux/mfd/tps65910.h>
#include <linux/regulator/machine.h>
#endif
#include <linux/gpio.h>
#include <mach/ixc.h>
#include <mach/dw_mmc.h>
#include <linux/gfp.h>

#include "dw_mmc-opv5xc.h"

#define DW_MCI_USE_PHASE_TUNNING 1
/* #define DW_MCI_USE_PHASE_FORCE_INDEX 1 */
#define DW_MCI_USE_PHASE_INDEX 2
#ifdef CONFIG_MMC_DW_IDMAC
#ifdef CONFIG_ARCH_OPV5XC_ES2
#define DW_MCI_OPV5XC_ACP_SUPPORT 1
#endif
#endif

/* Common flag combinations */
#define DW_MCI_DATA_ERROR_FLAGS	(SDMMC_INT_DRTO | SDMMC_INT_DCRC | \
				 SDMMC_INT_HTO | SDMMC_INT_SBE  | \
				 SDMMC_INT_EBE)
#define DW_MCI_CMD_ERROR_FLAGS	(SDMMC_INT_RTO | SDMMC_INT_RCRC | \
				 SDMMC_INT_RESP_ERR)
#define DW_MCI_ERROR_FLAGS	(DW_MCI_DATA_ERROR_FLAGS | \
				 DW_MCI_CMD_ERROR_FLAGS  | SDMMC_INT_HLE)
#define DW_MCI_SEND_STATUS	1
#define DW_MCI_RECV_STATUS	2
#define DW_MCI_DMA_THRESHOLD	16

#define DW_MCI_FREQ_MAX	200000000	/* unit: HZ */
#define DW_MCI_FREQ_MIN	400000		/* unit: HZ */

#ifdef CONFIG_MMC_DW_IDMAC
#define IDMAC_INT_CLR		(SDMMC_IDMAC_INT_AI | SDMMC_IDMAC_INT_NI | \
				 SDMMC_IDMAC_INT_CES | SDMMC_IDMAC_INT_DU | \
				 SDMMC_IDMAC_INT_FBE | SDMMC_IDMAC_INT_RI | \
				 SDMMC_IDMAC_INT_TI)

struct idmac_desc {
	u32		des0;	/* Control Descriptor */
#define IDMAC_DES0_DIC	BIT(1)
#define IDMAC_DES0_LD	BIT(2)
#define IDMAC_DES0_FD	BIT(3)
#define IDMAC_DES0_CH	BIT(4)
#define IDMAC_DES0_ER	BIT(5)
#define IDMAC_DES0_CES	BIT(30)
#define IDMAC_DES0_OWN	BIT(31)

	u32		des1;	/* Buffer sizes */
#define IDMAC_SET_BUFFER1_SIZE(d, s) \
	((d)->des1 = ((d)->des1 & 0x03ffe000) | ((s) & 0x1fff))

	u32		des2;	/* buffer 1 physical address */

	u32		des3;	/* buffer 2 physical address */
};
#endif /* CONFIG_MMC_DW_IDMAC */

static const u8 tuning_blk_pattern_4bit[] = {
	0xff, 0x0f, 0xff, 0x00, 0xff, 0xcc, 0xc3, 0xcc,
	0xc3, 0x3c, 0xcc, 0xff, 0xfe, 0xff, 0xfe, 0xef,
	0xff, 0xdf, 0xff, 0xdd, 0xff, 0xfb, 0xff, 0xfb,
	0xbf, 0xff, 0x7f, 0xff, 0x77, 0xf7, 0xbd, 0xef,
	0xff, 0xf0, 0xff, 0xf0, 0x0f, 0xfc, 0xcc, 0x3c,
	0xcc, 0x33, 0xcc, 0xcf, 0xff, 0xef, 0xff, 0xee,
	0xff, 0xfd, 0xff, 0xfd, 0xdf, 0xff, 0xbf, 0xff,
	0xbb, 0xff, 0xf7, 0xff, 0xf7, 0x7f, 0x7b, 0xde,
};

static const u8 tuning_blk_pattern_8bit[] = {
	0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00,
	0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc, 0xcc,
	0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff, 0xff,
	0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee, 0xff,
	0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd, 0xdd,
	0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff, 0xbb,
	0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff, 0xff,
	0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee, 0xff,
	0xff, 0xff, 0xff, 0x00, 0xff, 0xff, 0xff, 0x00,
	0x00, 0xff, 0xff, 0xcc, 0xcc, 0xcc, 0x33, 0xcc,
	0xcc, 0xcc, 0x33, 0x33, 0xcc, 0xcc, 0xcc, 0xff,
	0xff, 0xff, 0xee, 0xff, 0xff, 0xff, 0xee, 0xee,
	0xff, 0xff, 0xff, 0xdd, 0xff, 0xff, 0xff, 0xdd,
	0xdd, 0xff, 0xff, 0xff, 0xbb, 0xff, 0xff, 0xff,
	0xbb, 0xbb, 0xff, 0xff, 0xff, 0x77, 0xff, 0xff,
	0xff, 0x77, 0x77, 0xff, 0x77, 0xbb, 0xdd, 0xee,
};

static inline bool dw_mci_fifo_reset(struct dw_mci *host);
static inline bool dw_mci_ctrl_all_reset(struct dw_mci *host);
#ifdef CONFIG_MMC_DW_UHS_I_MODE
static void dw_mci_clock_only_cmd_for_volt_switch(struct dw_mci *host);
#endif
static void dw_mci_clock_only_cmd(struct dw_mci *host);
static void dw_mci_setup_bus(struct dw_mci_slot *slot, bool force_clkinit);

static int gi_start_tuning;
static int recovery_sbe;

#ifdef CONFIG_MMC_DW_SWITCH_VOL_TPS65911
static struct regulator *sd_vdd;

int opv5xc_regulator_disable()
{
	if (regulator_is_enabled(sd_vdd) > 0) {
		regulator_disable(sd_vdd);
		mdelay(500);
	}
	return 0;
}
int opv5xc_regulator_enable()
{
	if (regulator_is_enabled(sd_vdd) == 0)
		regulator_enable(sd_vdd);
	return 0;
}

int opv5xc_set_sd_voltage(int voltage_uv)
{
	if (IS_ERR(sd_vdd))
		return -ENODEV;

	return regulator_set_voltage(sd_vdd, voltage_uv, voltage_uv);
}

int opv5xc_get_sd_voltage(int *voltage_uv)
{
	if (IS_ERR(sd_vdd))
		return -ENODEV;

	*voltage_uv = regulator_get_voltage(sd_vdd);

	return 0;
}

static int opv5xc_regulator_init(void)
{
	sd_vdd = regulator_get(NULL, "sd_vdd");

	if (IS_ERR(sd_vdd)) {
		dev_err(NULL, "Can't get regulator handler!!!\n");
		dev_err(NULL, "Please insert the regulator driver first!!!\n");
	}

	regulator_enable(sd_vdd);
	return 0;
}

static void opv5xc_regulator_release(void)
{
	if (!IS_ERR(sd_vdd))
		regulator_put(sd_vdd);

	sd_vdd = NULL;
}
#endif

#ifdef CONFIG_MMC_DW_SWITCH_VOL_GPIO11
static int switch_vol_pin = 11;

int opv5xc_regulator_disable()
{
	return 0;
}
int opv5xc_regulator_enable()
{
	return 0;
}

int opv5xc_set_sd_voltage(int voltage_uv)
{
	if (voltage_uv == 1800000)
		gpio_set_value(switch_vol_pin, 0);
	else
		gpio_set_value(switch_vol_pin, 1);

	return 0;
}

int opv5xc_get_sd_voltage(int *voltage_uv)
{
	if (gpio_get_value(switch_vol_pin))
		*voltage_uv = 3300000;
	else
		*voltage_uv = 1800000;

	return 0;
}

static int opv5xc_regulator_init(void)
{
	int ret;

	ret = gpio_request(switch_vol_pin, "sd_vol_pin");

	gpio_direction_output(switch_vol_pin, 1);

	if (ret)
		dev_err(NULL, "gpio_request SD voltage pin fail!!!\n");

	return ret;
}

static void opv5xc_regulator_release(void)
{
	gpio_free(switch_vol_pin);
}
#endif

#ifndef CONFIG_MMC_DW_UHS_I_MODE

int opv5xc_regulator_disable(void)
{
	return 0;
}
int opv5xc_regulator_enable(void)
{
	return 0;
}

int opv5xc_set_sd_voltage(int voltage_uv)
{
	voltage_uv = 0; /* avoid warnning */

	return 0;
}

int opv5xc_get_sd_voltage(int *voltage_uv)
{
	*voltage_uv = 3300000;

	return 0;
}

static int opv5xc_regulator_init(void)
{
	return 0;
}

static void opv5xc_regulator_release(void)
{
}
#endif

static bool mci_wait_reset(struct device *dev, struct dw_mci *host)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(500);
	unsigned int ctrl;

	mci_writel(host, CTRL, (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
				SDMMC_CTRL_DMA_RESET));

	/* wait till resets clear */
	do {
		ctrl = mci_readl(host, CTRL);
		if (!(ctrl & (SDMMC_CTRL_RESET | SDMMC_CTRL_FIFO_RESET |
			      SDMMC_CTRL_DMA_RESET)))
			return true;
	} while (time_before(jiffies, timeout));

	if (dev)
		dev_err(dev, "Timeout resetting block (ctrl %#x)\n", ctrl);

	return false;
}

#ifdef CONFIG_DEBUG_FS
static int dw_mci_req_show(struct seq_file *s, void *v)
{
	struct dw_mci_slot *slot = s->private;
	struct mmc_request *mrq;
	struct mmc_command *cmd;
	struct mmc_command *stop;
	struct mmc_data	*data;

	/* Make sure we get a consistent snapshot */
	spin_lock_bh(&slot->host->lock);
	mrq = slot->mrq;

	if (mrq) {
		cmd = mrq->cmd;
		data = mrq->data;
		stop = mrq->stop;

		if (cmd)
			seq_printf(s,
				   "CMD%u(0x%x) flg %x rsp %x %x %x %x err %d\n",
				   cmd->opcode, cmd->arg, cmd->flags,
				   cmd->resp[0], cmd->resp[1], cmd->resp[2],
				   cmd->resp[2], cmd->error);
		if (data)
			seq_printf(s, "DATA %u / %u * %u flg %x err %d\n",
				   data->bytes_xfered, data->blocks,
				   data->blksz, data->flags, data->error);
		if (stop)
			seq_printf(s,
				   "CMD%u(0x%x) flg %x rsp %x %x %x %x err %d\n",
				   stop->opcode, stop->arg, stop->flags,
				   stop->resp[0], stop->resp[1], stop->resp[2],
				   stop->resp[2], stop->error);
	}

	spin_unlock_bh(&slot->host->lock);

	return 0;
}

static int dw_mci_req_open(struct inode *inode, struct file *file)
{
	return single_open(file, dw_mci_req_show, inode->i_private);
}

static const struct file_operations dw_mci_req_fops = {
	.owner		= THIS_MODULE,
	.open		= dw_mci_req_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int dw_mci_regs_show(struct seq_file *s, void *v)
{
	seq_printf(s, "STATUS:\t0x%08x\n", SDMMC_STATUS);
	seq_printf(s, "RINTSTS:\t0x%08x\n", SDMMC_RINTSTS);
	seq_printf(s, "CMD:\t0x%08x\n", SDMMC_CMD);
	seq_printf(s, "CTRL:\t0x%08x\n", SDMMC_CTRL);
	seq_printf(s, "INTMASK:\t0x%08x\n", SDMMC_INTMASK);
	seq_printf(s, "CLKENA:\t0x%08x\n", SDMMC_CLKENA);

	return 0;
}

static int dw_mci_regs_open(struct inode *inode, struct file *file)
{
	return single_open(file, dw_mci_regs_show, inode->i_private);
}

static const struct file_operations dw_mci_regs_fops = {
	.owner		= THIS_MODULE,
	.open		= dw_mci_regs_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static void dw_mci_init_debugfs(struct dw_mci_slot *slot)
{
	struct mmc_host	*mmc = slot->mmc;
	struct dw_mci *host = slot->host;
	struct dentry *root;
	struct dentry *node;

	root = mmc->debugfs_root;
	if (!root)
		return;

	node = debugfs_create_file("regs", S_IRUSR, root, host,
				   &dw_mci_regs_fops);
	if (!node)
		goto err;

	node = debugfs_create_file("req", S_IRUSR, root, slot,
				   &dw_mci_req_fops);
	if (!node)
		goto err;

	node = debugfs_create_u32("state", S_IRUSR, root, (u32 *)&host->state);
	if (!node)
		goto err;

	node = debugfs_create_x32("pending_events", S_IRUSR, root,
				  (u32 *)&host->pending_events);
	if (!node)
		goto err;

	node = debugfs_create_x32("completed_events", S_IRUSR, root,
				  (u32 *)&host->completed_events);
	if (!node)
		goto err;

	return;

err:
	dev_err(&mmc->class_dev, "failed to initialize debugfs for slot\n");
}
#endif /* CONFIG_DEBUG_FS */

static void dw_mci_set_timeout(struct dw_mci *host)
{
	/* timeout (maximum) */
	mci_writel(host, TMOUT, 0xffffffff);
}

static u32 dw_mci_prepare_command(struct mmc_host *mmc, struct mmc_command *cmd)
{
	struct mmc_data	*data;
	struct dw_mci_slot *slot = mmc_priv(mmc);
	const struct dw_mci_drv_data *drv_data = slot->host->drv_data;
	u32 cmdr;
	cmd->error = -EINPROGRESS;

	cmdr = cmd->opcode;

	if (cmd->opcode == MMC_STOP_TRANSMISSION ||
	    cmd->opcode == MMC_GO_IDLE_STATE ||
	    cmd->opcode == MMC_GO_INACTIVE_STATE ||
	    (cmd->opcode == SD_IO_RW_DIRECT &&
	     ((cmd->arg >> 9) & 0x1FFFF) == SDIO_CCCR_ABORT))
		cmdr |= SDMMC_CMD_STOP;
	else
		if (cmd->opcode != MMC_SEND_STATUS && cmd->data)
			cmdr |= SDMMC_CMD_PRV_DAT_WAIT;

	if (cmd->flags & MMC_RSP_PRESENT) {
		/* We expect a response, so set this bit */
		cmdr |= SDMMC_CMD_RESP_EXP;
		if (cmd->flags & MMC_RSP_136)
			cmdr |= SDMMC_CMD_RESP_LONG;
	}

	if (cmd->flags & MMC_RSP_CRC)
		cmdr |= SDMMC_CMD_RESP_CRC;

	data = cmd->data;
	if (data) {
		cmdr |= SDMMC_CMD_DAT_EXP;
		if (data->flags & MMC_DATA_STREAM)
			cmdr |= SDMMC_CMD_STRM_MODE;
		if (data->flags & MMC_DATA_WRITE)
			cmdr |= SDMMC_CMD_DAT_WR;
	}

	if (drv_data && drv_data->prepare_command)
		drv_data->prepare_command(slot->host, &cmdr);

	return cmdr;
}

static u32 dw_mci_prep_stop_abort(struct dw_mci *host, struct mmc_command *cmd)
{
	struct mmc_command *stop;
	u32 cmdr;

	if (!cmd->data)
		return 0;

	stop = &host->stop_abort;
	cmdr = cmd->opcode;
	memset(stop, 0, sizeof(struct mmc_command));

	if (cmdr == MMC_READ_SINGLE_BLOCK ||
	    cmdr == MMC_READ_MULTIPLE_BLOCK ||
	    cmdr == MMC_SEND_TUNING_BLOCK ||
	    cmdr == MMC_SEND_TUNING_BLOCK_HS200 ||
	    cmdr == MMC_WRITE_BLOCK ||
	    cmdr == MMC_WRITE_MULTIPLE_BLOCK) {
		stop->opcode = MMC_STOP_TRANSMISSION;
		stop->arg = 0;
		stop->flags = MMC_RSP_R1B | MMC_CMD_AC;
	} else if (cmdr == SD_IO_RW_EXTENDED) {
		stop->opcode = SD_IO_RW_DIRECT;
		stop->arg |= (1 << 31) | (0 << 28) | (SDIO_CCCR_ABORT << 9) |
			     ((cmd->arg >> 28) & 0x7);
		stop->flags = MMC_RSP_SPI_R5 | MMC_RSP_R5 | MMC_CMD_AC;
	} else {
		return 0;
	}

	cmdr = stop->opcode | SDMMC_CMD_STOP |
		SDMMC_CMD_RESP_CRC | SDMMC_CMD_RESP_EXP;

	return cmdr;
}

static void dw_mci_start_command(struct dw_mci *host,
				 struct mmc_command *cmd, u32 cmd_flags)
{
	host->cmd = cmd;
	dev_vdbg(host->dev,
		 "start command: ARGR=0x%08x CMDR=0x%08x\n",
		 cmd->arg, cmd_flags);

	mci_writel(host, CMDARG, cmd->arg);
	wmb();

	cmd_flags |= SDMMC_CMD_USE_HOLD_REG;

	mci_writel(host, CMD, cmd_flags | SDMMC_CMD_START);
}

static inline void send_stop_abort(struct dw_mci *host, struct mmc_data *data)
{
	struct mmc_command *stop = data->stop ? data->stop : &host->stop_abort;
	dw_mci_start_command(host, stop, host->stop_cmdr);
}

/* DMA interface functions */
static void dw_mci_stop_dma(struct dw_mci *host)
{
	if (host->using_dma) {
		host->dma_ops->stop(host);
		host->dma_ops->cleanup(host);
	}

	/* Data transfer was stopped by the interrupt handler */
	set_bit(EVENT_XFER_COMPLETE, &host->pending_events);
}

static int dw_mci_get_dma_dir(struct mmc_data *data)
{
	if (data->flags & MMC_DATA_WRITE)
		return DMA_TO_DEVICE;
	else
		return DMA_FROM_DEVICE;
}

#ifdef CONFIG_MMC_DW_IDMAC
static void dw_mci_dma_cleanup(struct dw_mci *host)
{
	struct mmc_data *data = host->data;

	if (data)
		if (!data->host_cookie)
			dma_unmap_sg(host->dev,
				     data->sg,
				     data->sg_len,
				     dw_mci_get_dma_dir(data));
}

static void dw_mci_idmac_reset(struct dw_mci *host)
{
	u32 bmod = mci_readl(host, BMOD);
	/* Software reset of DMA */
	bmod |= SDMMC_IDMAC_SWRESET;
	mci_writel(host, BMOD, bmod);
}

static void dw_mci_idmac_stop_dma(struct dw_mci *host)
{
	u32 temp;

	/* Disable and reset the IDMAC interface */
	temp = mci_readl(host, CTRL);
	temp &= ~SDMMC_CTRL_USE_IDMAC;
	temp |= SDMMC_CTRL_DMA_RESET;
	mci_writel(host, CTRL, temp);

	/* Stop the IDMAC running */
	temp = mci_readl(host, BMOD);
	temp &= ~(SDMMC_IDMAC_ENABLE | SDMMC_IDMAC_FB);
	temp |= SDMMC_IDMAC_SWRESET;
	mci_writel(host, BMOD, temp);
}

static void dw_mci_idmac_complete_dma(struct dw_mci *host)
{
	struct mmc_data *data = host->data;

	dev_vdbg(host->dev, "DMA complete\n");

	host->dma_ops->cleanup(host);

	/*
	 * If the card was removed, data will be NULL. No point in trying to
	 * send the stop command or waiting for NBUSY in this case.
	 */
	if (data) {
		set_bit(EVENT_XFER_COMPLETE, &host->pending_events);
		tasklet_schedule(&host->tasklet);
	}
}

static void dw_mci_translate_sglist(struct dw_mci *host, struct mmc_data *data,
				    unsigned int sg_len)
{
	int i;
	struct idmac_desc *desc = host->sg_cpu;

	for (i = 0; i < sg_len; i++, desc++) {
		unsigned int length = sg_dma_len(&data->sg[i]);
		u32 mem_addr = sg_dma_address(&data->sg[i]);

		/* Set the OWN bit and disable interrupts for this descriptor */
		desc->des0 = IDMAC_DES0_OWN | IDMAC_DES0_DIC | IDMAC_DES0_CH;

		/* Buffer length */
		IDMAC_SET_BUFFER1_SIZE(desc, length);

		/* Physical address to DMA to/from */
		desc->des2 = mem_addr;
	}

	/* Set first descriptor */
	desc = host->sg_cpu;
	desc->des0 |= IDMAC_DES0_FD;

	/* Set last descriptor */
	desc = host->sg_cpu + (i - 1) * sizeof(struct idmac_desc);
	desc->des0 &= ~(IDMAC_DES0_CH | IDMAC_DES0_DIC);
	desc->des0 |= IDMAC_DES0_LD;

	wmb();
}

static void dw_mci_idmac_start_dma(struct dw_mci *host, unsigned int sg_len)
{
	u32 temp;

	dw_mci_translate_sglist(host, host->data, sg_len);

	/* Select IDMAC interface */
	temp = mci_readl(host, CTRL);
	temp |= SDMMC_CTRL_USE_IDMAC;
	mci_writel(host, CTRL, temp);

	wmb();

	/* Enable the IDMAC */
	temp = mci_readl(host, BMOD);
	temp |= SDMMC_IDMAC_ENABLE | SDMMC_IDMAC_FB;
	mci_writel(host, BMOD, temp);

	/* Start it running */
	mci_writel(host, PLDMND, 1);
}

static int dw_mci_idmac_init(struct dw_mci *host)
{
	struct idmac_desc *p;
	int i;

	/* Number of descriptors in the ring buffer */
	host->ring_size = PAGE_SIZE / sizeof(struct idmac_desc);

	/* Forward link the descriptor list */
	for (i = 0, p = host->sg_cpu; i < host->ring_size - 1; i++, p++)
		p->des3 = host->sg_dma + (sizeof(struct idmac_desc) * (i + 1));

	/* Set the last descriptor as the end-of-ring descriptor */
	p->des3 = host->sg_dma;
	p->des0 = IDMAC_DES0_ER;

	dw_mci_idmac_reset(host);

	/* Mask out interrupts - get Tx & Rx complete only */
	mci_writel(host, IDSTS, IDMAC_INT_CLR);
	mci_writel(host, IDINTEN, SDMMC_IDMAC_INT_NI | SDMMC_IDMAC_INT_RI |
		   SDMMC_IDMAC_INT_TI);

	/* Set the descriptor base address */
	mci_writel(host, DBADDR, host->sg_dma);
	return 0;
}

static const struct dw_mci_dma_ops dw_mci_idmac_ops = {
	.init = dw_mci_idmac_init,
	.start = dw_mci_idmac_start_dma,
	.stop = dw_mci_idmac_stop_dma,
	.complete = dw_mci_idmac_complete_dma,
	.cleanup = dw_mci_dma_cleanup,
};
#endif /* CONFIG_MMC_DW_IDMAC */

static int dw_mci_pre_dma_transfer(struct dw_mci *host,
				   struct mmc_data *data,
				   bool next)
{
	struct scatterlist *sg;
	unsigned int i, sg_len;

	if (!next && data->host_cookie)
		return data->host_cookie;

	/*
	 * We don't do DMA on "complex" transfers, i.e. with
	 * non-word-aligned buffers or lengths. Also, we don't bother
	 * with all the DMA setup overhead for short transfers.
	 */
	if (data->blocks * data->blksz < DW_MCI_DMA_THRESHOLD)
		return -EINVAL;

	if (data->blksz & 3)
		return -EINVAL;

	for_each_sg(data->sg, sg, data->sg_len, i) {
		if (sg->offset & 3 || sg->length & 3)
			return -EINVAL;
	}

	sg_len = dma_map_sg(host->dev,
			    data->sg,
			    data->sg_len,
			    dw_mci_get_dma_dir(data));
	if (sg_len == 0)
		return -EINVAL;

	if (next)
		data->host_cookie = sg_len;

	return sg_len;
}

static void dw_mci_pre_req(struct mmc_host *mmc,
			   struct mmc_request *mrq,
			   bool is_first_req)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct mmc_data *data = mrq->data;

	if (!slot->host->use_dma || !data)
		return;

	if (data->host_cookie) {
		data->host_cookie = 0;
		return;
	}

	if (dw_mci_pre_dma_transfer(slot->host, mrq->data, 1) < 0)
		data->host_cookie = 0;
}

static void dw_mci_post_req(struct mmc_host *mmc,
			    struct mmc_request *mrq,
			    int err)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct mmc_data *data = mrq->data;

	if (!slot->host->use_dma || !data)
		return;

	if (data->host_cookie)
		dma_unmap_sg(slot->host->dev,
			     data->sg,
			     data->sg_len,
			     dw_mci_get_dma_dir(data));
	data->host_cookie = 0;
}

static void dw_mci_adjust_fifoth(struct dw_mci *host, struct mmc_data *data)
{
#ifdef CONFIG_MMC_DW_IDMAC
	unsigned int blksz = data->blksz;
	const u32 mszs[] = {1, 4, 8, 16, 32, 64, 128, 256};
	u32 fifo_width = 1 << host->data_shift;
	u32 blksz_depth = blksz / fifo_width, fifoth_val;
	u32 msize = 0, rx_wmark = 1, tx_wmark, tx_wmark_invers;
	int idx = (sizeof(mszs) / sizeof(mszs[0])) - 1;

	tx_wmark = (host->fifo_depth) / 2;
	tx_wmark_invers = host->fifo_depth - tx_wmark;

	/*
	 * MSIZE is '1',
	 * if blksz is not a multiple of the FIFO width
	 */
	if (blksz % fifo_width) {
		msize = 0;
		rx_wmark = 1;
		goto done;
	}

	do {
		if (!((blksz_depth % mszs[idx]) ||
		     (tx_wmark_invers % mszs[idx]))) {
			msize = idx;
			rx_wmark = mszs[idx] - 1;
			break;
		}
	} while (--idx > 0);
	/*
	 * If idx is '0', it won't be tried
	 * Thus, initial values are uesed
	 */
done:
	fifoth_val = SDMMC_SET_FIFOTH(msize, rx_wmark, tx_wmark);
	mci_writel(host, FIFOTH, fifoth_val);
#endif
}

static void dw_mci_ctrl_rd_thld(struct dw_mci *host, struct mmc_data *data)
{
	unsigned int blksz = data->blksz;
	u32 blksz_depth, fifo_depth;
	u16 thld_size;

	WARN_ON(!(data->flags & MMC_DATA_READ));

	if (host->timing != MMC_TIMING_MMC_HS200 &&
	    host->timing != MMC_TIMING_UHS_SDR104)
		goto disable;

	blksz_depth = blksz / (1 << host->data_shift);
	fifo_depth = host->fifo_depth;

	if (blksz_depth > fifo_depth)
		goto disable;

	/*
	 * If (blksz_depth) >= (fifo_depth >> 1), should be 'thld_size <= blksz'
	 * If (blksz_depth) <  (fifo_depth >> 1), should be thld_size = blksz
	 * Currently just choose blksz.
	 */
	thld_size = blksz;
	mci_writel(host, CDTHRCTL, SDMMC_SET_RD_THLD(thld_size, 1));
	return;

disable:
	mci_writel(host, CDTHRCTL, SDMMC_SET_RD_THLD(0, 0));
}

static int dw_mci_submit_data_dma(struct dw_mci *host, struct mmc_data *data)
{
	int sg_len;
	u32 temp;

	host->using_dma = 0;

	/* If we don't have a channel, we can't do DMA */
	if (!host->use_dma)
		return -ENODEV;

	sg_len = dw_mci_pre_dma_transfer(host, data, 0);
	if (sg_len < 0) {
		host->dma_ops->stop(host);
		return sg_len;
	}

	host->using_dma = 1;

	dev_vdbg(host->dev,
		 "sd sg_cpu: %#lx sg_dma: %#lx sg_len: %d\n",
		 (unsigned long)host->sg_cpu, (unsigned long)host->sg_dma,
		 sg_len);

	/*
	 * Decide the MSIZE and RX/TX Watermark.
	 * If current block size is same with previous size,
	 * no need to update fifoth.
	 */
	if (host->prev_blksz != data->blksz)
		dw_mci_adjust_fifoth(host, data);

	/* Enable the DMA interface */
	temp = mci_readl(host, CTRL);
	temp |= SDMMC_CTRL_DMA_ENABLE;
	mci_writel(host, CTRL, temp);

	/* Disable RX/TX IRQs, let DMA handle it */
	temp = mci_readl(host, INTMASK);
	temp  &= ~(SDMMC_INT_RXDR | SDMMC_INT_TXDR);
	mci_writel(host, INTMASK, temp);

	host->dma_ops->start(host, sg_len);

	return 0;
}

static void dw_mci_submit_data(struct dw_mci *host, struct mmc_data *data)
{
	u32 temp;

	data->error = -EINPROGRESS;

	WARN_ON(host->data);
	host->sg = NULL;
	host->data = data;

	if (data->flags & MMC_DATA_READ) {
		host->dir_status = DW_MCI_RECV_STATUS;
		dw_mci_ctrl_rd_thld(host, data);
	} else {
		host->dir_status = DW_MCI_SEND_STATUS;
	}

	if (dw_mci_submit_data_dma(host, data)) {
		int flags = SG_MITER_ATOMIC;
		if (host->data->flags & MMC_DATA_READ)
			flags |= SG_MITER_TO_SG;
		else
			flags |= SG_MITER_FROM_SG;

		sg_miter_start(&host->sg_miter, data->sg, data->sg_len, flags);
		host->sg = data->sg;
		host->part_buf_start = 0;
		host->part_buf_count = 0;

		mci_writel(host, RINTSTS, SDMMC_INT_TXDR | SDMMC_INT_RXDR);
		temp = mci_readl(host, INTMASK);
		temp |= SDMMC_INT_TXDR | SDMMC_INT_RXDR;
		mci_writel(host, INTMASK, temp);

		temp = mci_readl(host, CTRL);
		temp &= ~SDMMC_CTRL_DMA_ENABLE;
		mci_writel(host, CTRL, temp);

		/*
		 * Use the initial fifoth_val for PIO mode.
		 * If next issued data may be transfered by DMA mode,
		 * prev_blksz should be invalidated.
		 */
		mci_writel(host, FIFOTH, host->fifoth_val);
		host->prev_blksz = 0;
	} else {
		/*
		 * Keep the current block size.
		 * It will be used to decide whether to update
		 * fifoth register next time.
		 */
		host->prev_blksz = data->blksz;
	}
}

static int mci_send_cmd(struct dw_mci_slot *slot, u32 cmd, u32 arg)
{
	struct dw_mci *host = slot->host;
	unsigned long timeout = jiffies + msecs_to_jiffies(500);
	unsigned int cmd_status = 0;

	mci_writel(host, CMDARG, arg);
	wmb();
	mci_writel(host, CMD, SDMMC_CMD_START | cmd);

	while (time_before(jiffies, timeout)) {
		cmd_status = mci_readl(host, CMD);
		if (!(cmd_status & SDMMC_CMD_START))
			return 0;
	}
	dev_dbg(host->dev, "Timeout sending command (cmd %#x arg %#x status %#x)\n",
		cmd, arg, cmd_status);

	return -ETIMEDOUT;
}

static void dw_mci_inform_ciu(struct dw_mci_slot *slot)
{
	struct dw_mci *host = slot->host;
	unsigned long retry = 10;
	int ret;
	u32 ctrl;

	while (1) {
		ret = mci_send_cmd(slot,
		     SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);
		if (!ret)
			break;
		ctrl = mci_readl(host, CTRL);
		ctrl |= SDMMC_CTRL_RESET;
		mci_writel(host, CTRL, ctrl);

		if (retry-- == 0) {
			dev_dbg(NULL, "Timeout inform CIU\n");
			break;
		} else
			dev_dbg(NULL, "Retry send command\n");
	}
}

static int mci_send_cmd_local(struct dw_mci *host, u32 cmd, u32 arg)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(500);
	unsigned int cmd_status = 0;

	mci_writel(host, CMDARG, arg);
	wmb();
	mci_writel(host, CMD, SDMMC_CMD_START | cmd);

	while (time_before(jiffies, timeout)) {
		cmd_status = mci_readl(host, CMD);
		if (!(cmd_status & SDMMC_CMD_START))
			return 0;
	}
	dev_dbg(NULL, "Timeout sending command (cmd %#x arg %#x status %#x)\n",
		cmd, arg, cmd_status);

	return -ETIMEDOUT;
}

static void dw_mci_clock_only_cmd(struct dw_mci *host)
{
	unsigned long retry = 10;
	int ret;
	u32 ctrl;

	while (1) {
		ret = mci_send_cmd_local(host,
		     SDMMC_CMD_UPD_CLK | SDMMC_CMD_PRV_DAT_WAIT, 0);
		if (!ret)
			break;
		ctrl = mci_readl(host, CTRL);
		ctrl |= SDMMC_CTRL_RESET;
		mci_writel(host, CTRL, ctrl);

		if (retry-- == 0) {
			dev_dbg(NULL, "Timeout inform CIU\n");
			break;
		} else
			dev_dbg(NULL, "Retry send command\n");
	}
}

# ifdef CONFIG_MMC_DW_UHS_I_MODE
static void dw_mci_clock_only_cmd_for_volt_switch(struct dw_mci *host)
{
	unsigned long retry = 10;
	int ret;
	u32 ctrl;

	while (1) {
		ret = mci_send_cmd_local(host,
		     SDMMC_CMD_UPD_CLK | SDMMC_CMD_VOLT_SWITCH, 0);
		if (!ret)
			break;
		ctrl = mci_readl(host, CTRL);
		ctrl |= SDMMC_CTRL_RESET;
		mci_writel(host, CTRL, ctrl);

		if (retry-- == 0) {
			dev_dbg(NULL, "Timeout inform CIU\n");
			break;
		} else
			dev_dbg(NULL, "Retry send command\n");
	}
}
#endif

# ifdef CONFIG_MMC_DW_UHS_I_MODE
int dw_mci_set_voltage(struct mmc_host *host, struct mmc_ios *ios)
{
	int voltage_uv = 0;
	struct dw_mci_slot *slot = mmc_priv(host);
	u32 regs;


	/* disable clock */
	regs = mci_readl(slot->host, CLKENA);
	regs &= ~(0x1 << slot->id);
	mci_writel(slot->host, CLKENA, regs);

	/* inform CIU */
	dw_mci_clock_only_cmd_for_volt_switch(slot->host);

	if (ios->signal_voltage == MMC_SIGNAL_VOLTAGE_180)
		opv5xc_set_sd_voltage(1800000);
	else
		opv5xc_set_sd_voltage(3300000);

	opv5xc_get_sd_voltage(&voltage_uv);
	dev_info(host->mmc, "The SD voltage is %d\n", voltage_uv);

	regs = mci_readl(slot->host, UHS_REG);
	if (ios->signal_voltage == MMC_SIGNAL_VOLTAGE_180)
		regs |= (0x1 << slot->id);
	else
		regs &= ~(0x1 << slot->id);
	mci_writel(slot->host, UHS_REG, regs);
	mdelay(20);

	/* enable clock */
	regs = mci_readl(slot->host, CLKENA);
	regs |= (0x1 << slot->id);
	mci_writel(slot->host, CLKENA, regs);

	/* inform CIU */
	dw_mci_clock_only_cmd_for_volt_switch(slot->host);
	mdelay(2);

	return 0;
}

#ifdef DW_MCI_USE_PHASE_TUNNING

#ifdef DW_MCI_USE_PHASE_FORCE_INDEX
int	dw_mci_execute_tuning(struct mmc_host *host, u32 opcode)
{
	struct dw_mci_slot *slot = mmc_priv(host);

	/* disable clock */
	mci_writel(slot->host, CLKENA, 0);

	/* inform CIU */
	dw_mci_clock_only_cmd(slot->host);

	/* Set Phase */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (DW_MCI_USE_PHASE_INDEX << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);

	mdelay(2);

	/* enable clock */
	mci_writel(slot->host, CLKENA, 1);

	/* inform CIU */
	dw_mci_clock_only_cmd(slot->host);

	return 0;
}
#else /* !DW_MCI_USE_PHASE_FORCE_INDEX */

static unsigned int golden_tuning_pattern[16] = {
	0xFF0FFF00, 0xFFCCC3CC, 0xC33CCCFF, 0xFEFFFEEF,
	0xFFDFFFDD, 0xFFFBFFFB, 0xBFFF7FFF, 0x77F7BDEF,
	0xFFF0FFF0, 0x0FFCCC3C, 0xCC33CCCF, 0xFFEFFFEE,
	0xFFFDFFFD, 0xDFFFBFFF, 0xBBFFF7FF, 0xF77F7BDE,
};

static char c_suitable_phase_a[128]
= {
	0,	/* 0: 000-0000 */
	0,	/* 1: 000-0001 */
	1,	/* 2: 000-0010 */
	0,	/* 3: 000-0011 */
	2,	/* 4: 000-0100 */
	0,	/* 5: 000-0101 */
	1,	/* 6: 000-0110 */
	1,	/* 7: 000-0111 */
	3,	/* 8: 000-1000 */
	0,	/* 9: 000-1001 */

	1,	/* 10: 000-1010 */
	0,	/* 11: 000-1011 */
	2,	/* 12: 000-1100 */
	2,	/* 13: 000-1101 */
	2,	/* 14: 000-1110 */
	1,	/* 15: 000-1111 */
	4,	/* 16: 001-0000 */
	0,	/* 17: 001-0001 */
	1,	/* 18: 001-0010 */
	0,	/* 19: 001-0011 */

	2,	/* 20: 001-0100 */
	0,	/* 21: 001-0101 */
	1,	/* 22: 001-0110 */
	1,	/* 23: 001-0111 */
	3,	/* 24: 001-1000 */
	3,	/* 25: 001-1001 */
	3,	/* 26: 001-1010 */
	0,	/* 27: 001-1011 */
	3,	/* 28: 001-1100 */
	3,	/* 29: 001-1101 */

	2,	/* 30: 001-1110 */
	2,	/* 31: 001-1111 */
	5,	/* 32: 010-0000 */
	0,	/* 33: 010-0001 */
	1,	/* 34: 010-0010 */
	0,	/* 35: 010-0011 */
	2,	/* 36: 010-0100 */
	0,	/* 37: 010-0101 */
	1,	/* 38: 010-0110 */
	1,	/* 39: 010-0111 */

	3,	/* 40: 010-1000 */
	0,	/* 41: 010-1001 */
	1,	/* 42: 010-1010 */
	0,	/* 43: 010-1011 */
	2,	/* 44: 010-1100 */
	2,	/* 45: 010-1101 */
	2,	/* 46: 010-1110 */
	1,	/* 47: 010-1111 */
	4,	/* 48: 011-0000 */
	4,	/* 49: 011-0001 */

	4,	/* 50: 011-0010 */
	0,	/* 51: 011-0011 */
	4,	/* 52: 011-0100 */
	4,	/* 53: 011-0101 */
	1,	/* 54: 011-0110 */
	1,	/* 55: 011-0111 */
	4,	/* 56: 011-1000 */
	4,	/* 57: 011-1001 */
	4,	/* 58: 011-1010 */
	4,	/* 59: 011-1011 */

	3,	/* 60: 011-1100 */
	3,	/* 61: 011-1101 */
	3,	/* 62: 011-1110 */
	2,	/* 63: 011-1111 */
	6,	/* 64: 100-0000 */
	0,	/* 65: 100-0001 */
	1,	/* 66: 100-0010 */
	0,	/* 67: 100-0011 */
	2,	/* 68: 100-0100 */
	0,	/* 69: 100-0101 */

	1,	/* 70: 100-0110 */
	1,	/* 71: 100-0111 */
	3,	/* 72: 100-1000 */
	0,	/* 73: 100-1001 */
	1,	/* 74: 100-1010 */
	0,	/* 75: 100-1011 */
	2,	/* 76: 100-1100 */
	2,	/* 77: 100-1101 */
	2,	/* 78: 100-1110 */
	1,	/* 79: 100-1111 */

	4,	/* 80: 101-0000 */
	0,	/* 81: 101-0001 */
	1,	/* 82: 101-0010 */
	0,	/* 83: 101-0011 */
	2,	/* 84: 101-0100 */
	0,	/* 85: 101-0101 */
	1,	/* 86: 101-0110 */
	1,	/* 87: 101-0111 */
	3,	/* 88: 101-1000 */
	3,	/* 89: 101-1001 */

	3,	/* 90: 101-1010 */
	0,	/* 91: 101-1011 */
	3,	/* 92: 101-1100 */
	3,	/* 93: 101-1101 */
	2,	/* 94: 101-1110 */
	2,	/* 95: 101-1111 */
	5,	/* 96: 110-0000 */
	5,	/* 97: 110-0001 */
	5,	/* 98: 110-0010 */
	0,	/* 99: 110-0011 */

	5,	/* 100: 110-0100 */
	5,	/* 101: 110-0101 */
	1,	/* 102: 110-0110 */
	1,	/* 103: 110-0111 */
	5,	/* 104: 110-1000 */
	5,	/* 105: 110-1001 */
	5,	/* 106: 110-1010 */
	0,	/* 107: 110-1011 */
	2,	/* 108: 110-1100 */
	2,	/* 109: 110-1101 */

	2,	/* 110: 110-1110 */
	1,	/* 111: 110-1111 */
	5,	/* 112: 111-0000 */
	5,	/* 113: 111-0001 */
	5,	/* 114: 111-0010 */
	5,	/* 115: 111-0011 */
	5,	/* 116: 111-0100 */
	5,	/* 117: 111-0101 */
	5,	/* 118: 111-0110 */
	1,	/* 119: 111-0111 */

	4,	/* 120: 111-1000 */
	4,	/* 121: 111-1001 */
	4,	/* 122: 111-1010 */
	4,	/* 123: 111-1011 */
	4,	/* 124: 111-1100 */
	4,	/* 125: 111-1101 */
	3,	/* 126: 111-1110 */
	3,	/* 127: 111-1111 */
};

int dw_mci_find_suitable_phase(unsigned char phase_bits)
{
	phase_bits &= ~(0x1 << 7);

	if (phase_bits >= (0x1 << 7)) {
		dev_err(NULL, "dw_mci_find_suitable_phase: phase_bits invalid\n");
		return 0;
	}

	dev_dbg(NULL, "phase:%d(0x%x)\n", c_suitable_phase_a[phase_bits], phase_bits);

	return c_suitable_phase_a[phase_bits];
}

int	dw_mci_execute_tuning(struct mmc_host *host, u32 opcode)
{
	struct mmc_request mrq = {NULL};
	struct mmc_command cmd = {0};
	struct mmc_data data = {0};
	struct scatterlist sg;
	unsigned int data_buf[64];
	unsigned int retry[64] = {0};
	int len = 64;
	int i = 0, j = 0, phase = 0;
	unsigned char phase_bits = 0;
	struct dw_mci_slot *slot = mmc_priv(host);
	u32 clkena, uhs_reg;
	int ret = 0;

	if (opcode != MMC_SEND_TUNING_BLOCK)
		return 0;

	gi_start_tuning = 1;

	clkena = mci_readl(slot->host, CLKENA);
	uhs_reg = mci_readl(slot->host, UHS_REG);

	dev_dbg(host->mmc, "CLKENA:0x%x\n", clkena);
	dev_dbg(host->mmc, "UHS_REG:0x%x\n", uhs_reg);
	dev_dbg(host->mmc, "execute CMD19 tuning...\n");

	for (i = 0; i <= 7; i++) {

retry_tunning:
		dev_dbg(host->mmc, "execute CMD19 tuning count:%d\n", i);

		memset((unsigned char *)data_buf, 0, 64);

		/* disable clock */
		mci_writel(slot->host, CLKENA, 0);

		/* inform CIU */
		dw_mci_clock_only_cmd(slot->host);

		/* Set Phase */
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (i << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);

		mdelay(2);

		/* enable clock */
		mci_writel(slot->host, CLKENA, 1);

		/* inform CIU */
		dw_mci_clock_only_cmd(slot->host);

		mrq.cmd = &cmd;
		mrq.data = &data;

		cmd.opcode = opcode;
		cmd.arg = 0;

		cmd.flags = MMC_RSP_SPI_R1 | MMC_RSP_R1 | MMC_CMD_ADTC;

		data.blksz = len;
		data.blocks = 1;
		data.flags = MMC_DATA_READ;
		data.sg = &sg;
		data.sg_len = 1;

		sg_init_one(&sg, data_buf, len);

		data.timeout_ns = 0;
		data.timeout_clks = 64;

		mmc_wait_for_req(host, &mrq);

		dev_dbg(host->mmc, "%X %X %X %X\n", data_buf[0], data_buf[1], data_buf[2], data_buf[3]);
		dev_dbg(host->mmc, "%X %X %X %X\n", data_buf[4], data_buf[5], data_buf[6], data_buf[7]);
		dev_dbg(host->mmc, "%X %X %X %X\n", data_buf[8], data_buf[9], data_buf[10], data_buf[11]);
		dev_dbg(host->mmc, "%X %X %X %X\n", data_buf[12], data_buf[13], data_buf[14], data_buf[15]);

		if (cmd.error || data.error || recovery_sbe) {
			recovery_sbe = 0;
			mci_wait_reset(NULL, slot->host);

			/* Restore the old value at FIFOTH register */
			mci_writel(slot->host, FIFOTH, slot->host->fifoth_val);

			mci_writel(slot->host, RINTSTS, 0xFFFFFFFF);
			mci_writel(slot->host, INTMASK, SDMMC_INT_CMD_DONE | SDMMC_INT_DATA_OVER |
				   SDMMC_INT_TXDR | SDMMC_INT_RXDR |
				   DW_MCI_ERROR_FLAGS | SDMMC_INT_CD);
			mci_writel(slot->host, CTRL, SDMMC_CTRL_INT_ENABLE);

			mci_writel(slot->host, CLKENA, clkena);
			mci_writel(slot->host, UHS_REG, uhs_reg);

			dw_mci_clock_only_cmd_for_volt_switch(slot->host);
		} else {
			for (j = 0; j < 16; j++)
				data_buf[j] = cpu_to_be32((u32)data_buf[j]);

			for (j = 0; j < 16; j++) {
				if (data_buf[j] != golden_tuning_pattern[j])
					break;
			}

			if (retry[i] < 10) {
				retry[i]++;
				goto retry_tunning;
			} else {
				if (j >= 16)
					phase_bits |= (0x1 << i);
			}
		}
	}

	if (phase_bits) {
		phase = dw_mci_find_suitable_phase(phase_bits);
	} else {
		dev_err(NULL, "This card doesn't support CMD19. Or ");
		dev_err(NULL, "No suitable phase setting for this card.\n");
		/* The card has problem, it cannot run at DDR50/SDR104.
		 * Set to the SDHC mode to let it works.
		 */
		ret = -1;
		phase = 1;
	}

	/* disable clock */
	mci_writel(slot->host, CLKENA, 0);

	/* inform CIU */
	dw_mci_clock_only_cmd(slot->host);

	/* Set Phase */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (phase << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);

	mdelay(2);

	/* enable clock */
	mci_writel(slot->host, CLKENA, 1);

	/* inform CIU */
	dw_mci_clock_only_cmd(slot->host);

	dev_dbg(host->mmc, "CLKENA:0x%x\n", clkena);
	dev_dbg(host->mmc, "UHS_REG:0x%x\n", uhs_reg);

	gi_start_tuning = 0;

	return ret;
}
#endif /* !DW_MCI_USE_PHASE_FORCE_INDEX */
#endif /* DW_MCI_USE_PHASE_TUNNING */
#endif /* CONFIG_MMC_DW_UHS_I_MODE */

static void dw_mci_setup_bus(struct dw_mci_slot *slot, bool force_clkinit)
{
	struct dw_mci *host = slot->host;
	unsigned int clock = slot->clock;
	u32 div;
	u32 clk_en_a;

	if (!clock) {
		mci_writel(host, CLKENA, 0);

	/* inform CIU */
	dw_mci_inform_ciu(slot);
	} else if (clock != host->current_speed || force_clkinit) {
		div = host->bus_hz / clock;
		if (host->bus_hz % clock && host->bus_hz > clock)
			/*
			 * move the + 1 after the divide to prevent
			 * over-clocking the card.
			 */
			div += 1;

		div = (host->bus_hz != clock) ? DIV_ROUND_UP(div, 2) : 0;

		/* disable clock */
		mci_writel(host, CLKENA, 0);
		mci_writel(host, CLKSRC, 0);

		/* inform CIU */
		dw_mci_inform_ciu(slot);

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		/* Sampling Phase */
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (1 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
		/* Driving Phase */
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
		writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (1 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);

		switch (slot->clock) {
		case 25000000:
			/* Driving Phase */
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (2 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x2 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			div = 1;
			dev_info(host->dev, "SD bus clock set to %d Hz (50 MHz, div = %d)\n", slot->clock, div);
			break;
		case 50000000:
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x2 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			div = 0;
			dev_info(host->dev, "SD bus clock set to %d Hz (50 MHz, div = %d)\n", slot->clock, div);
			break;
		case 100000000:
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x1 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			div = 0;
			dev_info(host->dev, "SD bus clock set to %d Hz (100 MHz, div = %d)\n", slot->clock, div);
			break;
		case 200000000:
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			div = 0;
			dev_info(host->dev, "SD bus clock set to %d Hz (200 MHz, div = %d)\n", slot->clock, div);
			break;
		case 20000000:
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x2 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			div = 2;
			dev_info(host->dev, "SD bus clock set to %d Hz (50 MHz, div = %d)\n", slot->clock, div);
			break;
		default:
			/* Driving Phase */
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x7 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (2 << 11)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
			if (host->bus_hz == 200000000) {
				writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
				dev_info(host->dev, "SD bus clock set to %d Hz (200 MHz, div = %d)\n", slot->clock, div);
			} else if (host->bus_hz == 100000000) {
				writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
				writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x1 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
				dev_info(host->dev, "SD bus clock set to %d Hz (100 MHz, div = %d)\n", slot->clock, div);
			} else {
				writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) & ~(0x3 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
				writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x30) | (0x2 << 6)), OPV5XC_CR_PMU_BASE_VIRT + 0x30);
				dev_info(host->dev, "SD bus clock set to %d Hz (50 MHz, div = %d)\n", slot->clock, div);
			}
			break;
		}
#endif

		/* set clock to desired speed */
		mci_writel(host, CLKDIV, div);

		/* inform CIU */
		dw_mci_inform_ciu(slot);

		/* enable clock; only low power if no SDIO */
		clk_en_a = SDMMC_CLKEN_ENABLE << slot->id;
		mci_writel(host, CLKENA, clk_en_a);

		/* inform CIU */
		dw_mci_inform_ciu(slot);
	}

	host->current_speed = clock;

	/* Set the current slot bus width */
	mci_writel(host, CTYPE, (slot->ctype << slot->id));
}

static void __dw_mci_start_request(struct dw_mci *host,
				   struct dw_mci_slot *slot,
				   struct mmc_command *cmd)
{
	struct mmc_request *mrq;
	struct mmc_data	*data;
	u32 cmdflags;

	mrq = slot->mrq;
	if (host->pdata->select_slot)
		host->pdata->select_slot(slot->id);

	host->cur_slot = slot;
	host->mrq = mrq;

	host->pending_events = 0;
	host->completed_events = 0;
	host->cmd_status = 0;
	host->data_status = 0;
	host->dir_status = 0;

	data = cmd->data;
	if (data) {
		dw_mci_set_timeout(host);
		mci_writel(host, BYTCNT, data->blksz*data->blocks);
		mci_writel(host, BLKSIZ, data->blksz);
	}

	cmdflags = dw_mci_prepare_command(slot->mmc, cmd);

	/* this is the first command, send the initialization clock */
	if (test_and_clear_bit(DW_MMC_CARD_NEED_INIT, &slot->flags))
		cmdflags |= SDMMC_CMD_INIT;

	if (data) {
		dw_mci_submit_data(host, data);
		wmb();
	}

	dw_mci_start_command(host, cmd, cmdflags);

	if (mrq->stop)
		host->stop_cmdr = dw_mci_prepare_command(slot->mmc, mrq->stop);
	else
		host->stop_cmdr = dw_mci_prep_stop_abort(host, cmd);
}

static void dw_mci_start_request(struct dw_mci *host,
				 struct dw_mci_slot *slot)
{
	struct mmc_request *mrq = slot->mrq;
	struct mmc_command *cmd;

	cmd = mrq->sbc ? mrq->sbc : mrq->cmd;
	__dw_mci_start_request(host, slot, cmd);
}

/* must be called with host->lock held */
static void dw_mci_queue_request(struct dw_mci *host, struct dw_mci_slot *slot,
				 struct mmc_request *mrq)
{
	dev_vdbg(&slot->mmc->class_dev, "queue request: state=%d\n",
		 host->state);

	slot->mrq = mrq;

	if (host->state == STATE_IDLE) {
		host->state = STATE_SENDING_CMD;
		dw_mci_start_request(host, slot);
	} else {
		list_add_tail(&slot->queue_node, &host->queue);
	}
}

static void dw_mci_request(struct mmc_host *mmc, struct mmc_request *mrq)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci *host = slot->host;

	WARN_ON(slot->mrq);

	/*
	 * The check for card presence and queueing of the request must be
	 * atomic, otherwise the card could be removed in between and the
	 * request wouldn't fail until another card was inserted.
	 */
	spin_lock_bh(&host->lock);

	if (!test_bit(DW_MMC_CARD_PRESENT, &slot->flags)) {
		spin_unlock_bh(&host->lock);
		mrq->cmd->error = -ENOMEDIUM;
		mmc_request_done(mmc, mrq);
		return;
	}

	dw_mci_queue_request(host, slot, mrq);

	spin_unlock_bh(&host->lock);
}

static void dw_mci_set_ios(struct mmc_host *mmc, struct mmc_ios *ios)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	const struct dw_mci_drv_data *drv_data = slot->host->drv_data;
	u32 regs;

	switch (ios->bus_width) {
	case MMC_BUS_WIDTH_4:
		slot->ctype = SDMMC_CTYPE_4BIT;
		break;
	case MMC_BUS_WIDTH_8:
		slot->ctype = SDMMC_CTYPE_8BIT;
		break;
	default:
		/* set default 1 bit mode */
		slot->ctype = SDMMC_CTYPE_1BIT;
	}

	regs = mci_readl(slot->host, UHS_REG);

	/* DDR mode set */
	if (ios->timing == MMC_TIMING_UHS_DDR50)
		regs |= ((0x1 << slot->id) << 16);
	else
		regs &= ~((0x1 << slot->id) << 16);

	mci_writel(slot->host, UHS_REG, regs);
	slot->host->timing = ios->timing;

	/* inform CIU */
	dw_mci_clock_only_cmd(slot->host);

	/*
	 * Use mirror of ios->clock to prevent race with mmc
	 * core ios update when finding the minimum.
	 */
	slot->clock = ios->clock;

	if (drv_data && drv_data->set_ios)
		drv_data->set_ios(slot->host, ios);

	/* Slot specific timing and width adjustment */
	dw_mci_setup_bus(slot, false);

	switch (ios->power_mode) {
	case MMC_POWER_UP:
		set_bit(DW_MMC_CARD_NEED_INIT, &slot->flags);
		/* Power up slot */
		if (slot->host->pdata->setpower)
			slot->host->pdata->setpower(slot->id, mmc->ocr_avail);
		regs = mci_readl(slot->host, PWREN);
		regs |= (1 << slot->id);
		mci_writel(slot->host, PWREN, regs);
		break;
	case MMC_POWER_OFF:
		/* Power down slot */
		if (slot->host->pdata->setpower)
			slot->host->pdata->setpower(slot->id, 0);
		regs = mci_readl(slot->host, PWREN);
		regs &= ~(1 << slot->id);
		mci_writel(slot->host, PWREN, regs);
		break;
	default:
		break;
	}
}

static int dw_mci_get_ro(struct mmc_host *mmc)
{
	int read_only;
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci_board *brd = slot->host->pdata;

	if (brd->quirks & DW_MCI_QUIRK_INVERTED_WRITE_PROTECT)
		writel(readl(OPV5XC_MISC_BASE_VIRT + 0x700) | (1 << slot->id), OPV5XC_MISC_BASE_VIRT + 0x700);

	/* Use platform get_ro function, else try on board write protect */
	if (slot->quirks & DW_MCI_SLOT_QUIRK_NO_WRITE_PROTECT)
		read_only = 0;
	else if (brd->get_ro)
		read_only = brd->get_ro(slot->id);
	else if (gpio_is_valid(slot->wp_gpio))
		read_only = gpio_get_value(slot->wp_gpio);
	else
		read_only =
			mci_readl(slot->host, WRTPRT) & (1 << slot->id) ? 1 : 0;

	dev_dbg(&mmc->class_dev, "card is %s\n",
		read_only ? "read-only" : "read-write");

	return read_only;
}

static int dw_mci_get_cd(struct mmc_host *mmc)
{
	int present;
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci_board *brd = slot->host->pdata;

	/* Use platform get_cd function, else try onboard card detect */
	if (brd->quirks & DW_MCI_QUIRK_BROKEN_CARD_DETECTION)
		present = 1;
	else if (brd->get_cd)
		present = !brd->get_cd(slot->id);
	else
		present = (mci_readl(slot->host, CDETECT) & (1 << slot->id))
			== 0 ? 1 : 0;

	if (present)
		dev_dbg(&mmc->class_dev, "card is present\n");
	else
		dev_dbg(&mmc->class_dev, "card is not present\n");

	return present;
}

/*
 * Disable lower power mode.
 *
 * Low power mode will stop the card clock when idle.  According to the
 * description of the CLKENA register we should disable low power mode
 * for SDIO cards if we need SDIO interrupts to work.
 *
 * This function is fast if low power mode is already disabled.
 */
static void dw_mci_disable_low_power(struct dw_mci_slot *slot)
{
	struct dw_mci *host = slot->host;
	u32 clk_en_a;
	const u32 clken_low_pwr = SDMMC_CLKEN_LOW_PWR << slot->id;

	clk_en_a = mci_readl(host, CLKENA);

	if (clk_en_a & clken_low_pwr) {
		mci_writel(host, CLKENA, clk_en_a & ~clken_low_pwr);
		mci_send_cmd(slot, SDMMC_CMD_UPD_CLK |
			     SDMMC_CMD_PRV_DAT_WAIT, 0);
	}
}

static void dw_mci_enable_sdio_irq(struct mmc_host *mmc, int enb)
{
	struct dw_mci_slot *slot = mmc_priv(mmc);
	struct dw_mci *host = slot->host;
	u32 int_mask;

	/* Enable/disable Slot Specific SDIO interrupt */
	int_mask = mci_readl(host, INTMASK);
	if (enb) {
		/*
		 * Turn off low power mode if it was enabled.  This is a bit of
		 * a heavy operation and we disable / enable IRQs a lot, so
		 * we'll leave low power mode disabled and it will get
		 * re-enabled again in dw_mci_setup_bus().
		 */
		dw_mci_disable_low_power(slot);

		mci_writel(host, INTMASK,
			   (int_mask | SDMMC_INT_SDIO(slot->id)));
	} else {
		mci_writel(host, INTMASK,
			   (int_mask & ~SDMMC_INT_SDIO(slot->id)));
	}
}


void dw_mci_hw_reset(struct mmc_host *host)
{
	struct dw_mci_slot *slot = mmc_priv(host);

	opv5xc_set_sd_voltage(3300000);
	mdelay(10);

	mci_wait_reset(NULL, slot->host);

	/* Restore the old value at FIFOTH register */
	mci_writel(slot->host, FIFOTH, slot->host->fifoth_val);

	mci_writel(slot->host, RINTSTS, 0xFFFFFFFF);
	mci_writel(slot->host, INTMASK, SDMMC_INT_CMD_DONE | SDMMC_INT_DATA_OVER |
	       SDMMC_INT_TXDR | SDMMC_INT_RXDR |
	       DW_MCI_ERROR_FLAGS | SDMMC_INT_CD);
	mci_writel(slot->host, CTRL, SDMMC_CTRL_INT_ENABLE);
}

static const struct mmc_host_ops dw_mci_ops = {
	.hw_reset		= dw_mci_hw_reset,
	.request		= dw_mci_request,
	.pre_req		= dw_mci_pre_req,
	.post_req		= dw_mci_post_req,
	.set_ios		= dw_mci_set_ios,
	.get_ro			= dw_mci_get_ro,
	.get_cd			= dw_mci_get_cd,
	.enable_sdio_irq	= dw_mci_enable_sdio_irq,
#ifdef CONFIG_MMC_DW_UHS_I_MODE
	.start_signal_voltage_switch	= dw_mci_set_voltage,
#ifdef DW_MCI_USE_PHASE_TUNNING
	.execute_tuning		= dw_mci_execute_tuning,
#endif
#endif
};

static void dw_mci_request_end(struct dw_mci *host, struct mmc_request *mrq)
	__releases(&host->lock)
	__acquires(&host->lock)
{
	struct dw_mci_slot *slot;
	struct mmc_host	*prev_mmc = host->cur_slot->mmc;

	WARN_ON(host->cmd || host->data);

	host->cur_slot->mrq = NULL;
	host->mrq = NULL;
	if (!list_empty(&host->queue)) {
		slot = list_entry(host->queue.next,
				  struct dw_mci_slot, queue_node);
		list_del(&slot->queue_node);
		dev_vdbg(host->dev, "list not empty: %s is next\n",
			 mmc_hostname(slot->mmc));
		host->state = STATE_SENDING_CMD;
		dw_mci_start_request(host, slot);
	} else {
		dev_vdbg(host->dev, "list empty\n");
		host->state = STATE_IDLE;
	}

	spin_unlock(&host->lock);
	mmc_request_done(prev_mmc, mrq);
	spin_lock(&host->lock);
}

static int dw_mci_command_complete(struct dw_mci *host, struct mmc_command *cmd)
{
	u32 status = host->cmd_status;

	host->cmd_status = 0;

	/* Read the response from the card (up to 16 bytes) */
	if (cmd->flags & MMC_RSP_PRESENT) {
		if (cmd->flags & MMC_RSP_136) {
			cmd->resp[3] = mci_readl(host, RESP0);
			cmd->resp[2] = mci_readl(host, RESP1);
			cmd->resp[1] = mci_readl(host, RESP2);
			cmd->resp[0] = mci_readl(host, RESP3);
		} else {
			cmd->resp[0] = mci_readl(host, RESP0);
			cmd->resp[1] = 0;
			cmd->resp[2] = 0;
			cmd->resp[3] = 0;
		}
	}

	if (status & SDMMC_INT_RTO)
		cmd->error = -ETIMEDOUT;
	else if ((cmd->flags & MMC_RSP_CRC) && (status & SDMMC_INT_RCRC))
		cmd->error = -EILSEQ;
	else if (status & SDMMC_INT_RESP_ERR)
		cmd->error = -EIO;
	else
		cmd->error = 0;

	if (cmd->error) {
		/* newer ip versions need a delay between retries */
		if (host->quirks & DW_MCI_QUIRK_RETRY_DELAY)
			mdelay(20);
	}

	return cmd->error;
}

static int dw_mci_data_complete(struct dw_mci *host, struct mmc_data *data)
{
	u32 status = host->data_status;

	if (status & DW_MCI_DATA_ERROR_FLAGS) {
		if (status & SDMMC_INT_DRTO) {
			data->error = -ETIMEDOUT;
		} else if (status & SDMMC_INT_DCRC) {
			data->error = -EILSEQ;
		} else if (status & SDMMC_INT_EBE) {
			if (host->dir_status ==
				DW_MCI_SEND_STATUS) {
				/*
				 * No data CRC status was returned.
				 * The number of bytes transferred
				 * will be exaggerated in PIO mode.
				 */
				data->bytes_xfered = 0;
				data->error = -ETIMEDOUT;
			} else if (host->dir_status ==
					DW_MCI_RECV_STATUS) {
				data->error = -EIO;
			}
		} else {
			/* SDMMC_INT_SBE is included */
			data->error = -EIO;
		}

		if (gi_start_tuning == 0)
			dev_err(host->dev, "data error, status 0x%08x\n", status);

		/*
		 * After an error, there may be data lingering
		 * in the FIFO
		 */
		dw_mci_fifo_reset(host);
	} else {
		data->bytes_xfered = data->blocks * data->blksz;
		data->error = 0;
	}

	return data->error;
}

static void dw_mci_sbe_handler(struct dw_mci *host, struct mmc_data *data, const char *string_loc)
{
	host->cmd = NULL;
	host->data = NULL;
	data->error = -EIO;

	/*
	 * After an error, there may be data lingering
	 * in the FIFO, so reset it - doing so
	 * generates a block interrupt, hence setting
	 * the scatter-gather pointer to NULL.
	 */
	if (host->sg) {
		sg_miter_stop(&host->sg_miter);
		host->sg = NULL;
	}
}

static void dw_mci_tasklet_func(unsigned long priv)
{
	struct dw_mci *host = (struct dw_mci *)priv;
	struct mmc_data	*data;
	struct mmc_command *cmd;
	struct mmc_request *mrq;
	enum dw_mci_state state;
	enum dw_mci_state prev_state;
	unsigned int err;

	spin_lock(&host->lock);

	state = host->state;
	data = host->data;
	mrq = host->mrq;

	do {
		prev_state = state;

		switch (state) {
		case STATE_IDLE:
			break;

		case STATE_SENDING_CMD:
			if (!test_and_clear_bit(EVENT_CMD_COMPLETE,
						&host->pending_events))
				break;

			cmd = host->cmd;
			host->cmd = NULL;
			set_bit(EVENT_CMD_COMPLETE, &host->completed_events);
			err = dw_mci_command_complete(host, cmd);
			if (cmd == mrq->sbc && !err) {
				prev_state = state = STATE_SENDING_CMD;
				__dw_mci_start_request(host, host->cur_slot,
						       mrq->cmd);
				goto unlock;
			}

			if (cmd->data && err) {
				dw_mci_stop_dma(host);
				send_stop_abort(host, data);
				state = STATE_SENDING_STOP;
				break;
			}

			if (!cmd->data || err) {
				dw_mci_request_end(host, mrq);
				goto unlock;
			}

			prev_state = state = STATE_SENDING_DATA;
			/* fall through */

		case STATE_SENDING_DATA:
			if (test_and_clear_bit(EVENT_DATA_ERROR,
					       &host->pending_events)) {
				dw_mci_stop_dma(host);
				send_stop_abort(host, data);
				state = STATE_DATA_ERROR;
				break;
			}

			if (!test_and_clear_bit(EVENT_XFER_COMPLETE,
						&host->pending_events))
				break;

			set_bit(EVENT_XFER_COMPLETE, &host->completed_events);
			prev_state = state = STATE_DATA_BUSY;
			/* fall through */

		case STATE_DATA_BUSY:
			if (!test_and_clear_bit(EVENT_DATA_COMPLETE,
						&host->pending_events)) {
				if (recovery_sbe && gi_start_tuning) {
					dw_mci_sbe_handler(host, data, "STATE_DATA_BUSY");
					dw_mci_request_end(host, host->mrq);
					goto unlock;
				}
				break;
			}

			host->data = NULL;
			set_bit(EVENT_DATA_COMPLETE, &host->completed_events);
			err = dw_mci_data_complete(host, data);

			if (!err) {
				if (!data->stop || mrq->sbc) {
					if (mrq->sbc)
						data->stop->error = 0;
					dw_mci_request_end(host, mrq);
					goto unlock;
				}

				/* stop command for open-ended transfer*/
				if (data->stop)
					send_stop_abort(host, data);
			}

			/*
			 * If err has non-zero,
			 * stop-abort command has been already issued.
			 */
			prev_state = state = STATE_SENDING_STOP;

			/* fall through */

		case STATE_SENDING_STOP:
			if (!test_and_clear_bit(EVENT_CMD_COMPLETE,
						&host->pending_events))
				break;

			/* CMD error in data command */
			if (mrq->cmd->error && mrq->data)
				dw_mci_fifo_reset(host);

			host->cmd = NULL;
			host->data = NULL;

			if (mrq->stop)
				dw_mci_command_complete(host, mrq->stop);
			else
				host->cmd_status = 0;

			dw_mci_request_end(host, mrq);
			goto unlock;

		case STATE_DATA_ERROR:
			if (recovery_sbe && gi_start_tuning) {
				dw_mci_sbe_handler(host, data, "STATE_DATA_ERROR");
				dw_mci_request_end(host, host->mrq);
				goto unlock;
			}

			if (!test_and_clear_bit(EVENT_XFER_COMPLETE,
						&host->pending_events))
				break;

			state = STATE_DATA_BUSY;
			break;
		}
	} while (state != prev_state);

	host->state = state;
unlock:
	spin_unlock(&host->lock);

}

/* push final bytes to part_buf, only use during push */
static void dw_mci_set_part_bytes(struct dw_mci *host, void *buf, int cnt)
{
	memcpy((void *)&host->part_buf, buf, cnt);
	host->part_buf_count = cnt;
}

/* append bytes to part_buf, only use during push */
static int dw_mci_push_part_bytes(struct dw_mci *host, void *buf, int cnt)
{
	cnt = min(cnt, (1 << host->data_shift) - host->part_buf_count);
	memcpy((void *)&host->part_buf + host->part_buf_count, buf, cnt);
	host->part_buf_count += cnt;
	return cnt;
}

/* pull first bytes from part_buf, only use during pull */
static int dw_mci_pull_part_bytes(struct dw_mci *host, void *buf, int cnt)
{
	cnt = min(cnt, (int)host->part_buf_count);
	if (cnt) {
		memcpy(buf, (void *)&host->part_buf + host->part_buf_start,
		       cnt);
		host->part_buf_count -= cnt;
		host->part_buf_start += cnt;
	}
	return cnt;
}

/* pull final bytes from the part_buf, assuming it's just been filled */
static void dw_mci_pull_final_bytes(struct dw_mci *host, void *buf, int cnt)
{
	memcpy(buf, &host->part_buf, cnt);
	host->part_buf_start = cnt;
	host->part_buf_count = (1 << host->data_shift) - cnt;
}

static void dw_mci_push_data16(struct dw_mci *host, void *buf, int cnt)
{
	struct mmc_data *data = host->data;
	int init_cnt = cnt;

	/* try and push anything in the part_buf */
	if (unlikely(host->part_buf_count)) {
		int len = dw_mci_push_part_bytes(host, buf, cnt);
		buf += len;
		cnt -= len;
		if (host->part_buf_count == 2) {
			mci_writew(host, DATA(host->data_offset),
					host->part_buf16);
			host->part_buf_count = 0;
		}
	}
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x1)) {
		while (cnt >= 2) {
			u16 aligned_buf[64];
			int len = min(cnt & -2, (int)sizeof(aligned_buf));
			int items = len >> 1;
			int i;
			/* memcpy from input buffer into aligned buffer */
			memcpy(aligned_buf, buf, len);
			buf += len;
			cnt -= len;
			/* push data from aligned buffer into fifo */
			for (i = 0; i < items; ++i)
				mci_writew(host, DATA(host->data_offset),
						aligned_buf[i]);
		}
	} else
#endif
	{
		u16 *pdata = buf;
		for (; cnt >= 2; cnt -= 2)
			mci_writew(host, DATA(host->data_offset), *pdata++);
		buf = pdata;
	}
	/* put anything remaining in the part_buf */
	if (cnt) {
		dw_mci_set_part_bytes(host, buf, cnt);
		 /* Push data if we have reached the expected data length */
		if ((data->bytes_xfered + init_cnt) ==
		    (data->blksz * data->blocks))
			mci_writew(host, DATA(host->data_offset),
				   host->part_buf16);
	}
}

static void dw_mci_pull_data16(struct dw_mci *host, void *buf, int cnt)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x1)) {
		while (cnt >= 2) {
			/* pull data from fifo into aligned buffer */
			u16 aligned_buf[64];
			int len = min(cnt & -2, (int)sizeof(aligned_buf));
			int items = len >> 1;
			int i;
			for (i = 0; i < items; ++i)
				aligned_buf[i] = mci_readw(host,
						DATA(host->data_offset));
			/* memcpy from aligned buffer into output buffer */
			memcpy(buf, aligned_buf, len);
			buf += len;
			cnt -= len;
		}
	} else
#endif
	{
		u16 *pdata = buf;
		for (; cnt >= 2; cnt -= 2)
			*pdata++ = mci_readw(host, DATA(host->data_offset));
		buf = pdata;
	}
	if (cnt) {
		host->part_buf16 = mci_readw(host, DATA(host->data_offset));
		dw_mci_pull_final_bytes(host, buf, cnt);
	}
}

static void dw_mci_push_data32(struct dw_mci *host, void *buf, int cnt)
{
	struct mmc_data *data = host->data;
	int init_cnt = cnt;

	/* try and push anything in the part_buf */
	if (unlikely(host->part_buf_count)) {
		int len = dw_mci_push_part_bytes(host, buf, cnt);
		buf += len;
		cnt -= len;
		if (host->part_buf_count == 4) {
			mci_writel(host, DATA(host->data_offset),
					host->part_buf32);
			host->part_buf_count = 0;
		}
	}
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x3)) {
		while (cnt >= 4) {
			u32 aligned_buf[32];
			int len = min(cnt & -4, (int)sizeof(aligned_buf));
			int items = len >> 2;
			int i;
			/* memcpy from input buffer into aligned buffer */
			memcpy(aligned_buf, buf, len);
			buf += len;
			cnt -= len;
			/* push data from aligned buffer into fifo */
			for (i = 0; i < items; ++i)
				mci_writel(host, DATA(host->data_offset),
						aligned_buf[i]);
		}
	} else
#endif
	{
		u32 *pdata = buf;
		for (; cnt >= 4; cnt -= 4)
			mci_writel(host, DATA(host->data_offset), *pdata++);
		buf = pdata;
	}
	/* put anything remaining in the part_buf */
	if (cnt) {
		dw_mci_set_part_bytes(host, buf, cnt);
		 /* Push data if we have reached the expected data length */
		if ((data->bytes_xfered + init_cnt) ==
		    (data->blksz * data->blocks))
			mci_writel(host, DATA(host->data_offset),
				   host->part_buf32);
	}
}

static void dw_mci_pull_data32(struct dw_mci *host, void *buf, int cnt)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x3)) {
		while (cnt >= 4) {
			/* pull data from fifo into aligned buffer */
			u32 aligned_buf[32];
			int len = min(cnt & -4, (int)sizeof(aligned_buf));
			int items = len >> 2;
			int i;
			for (i = 0; i < items; ++i)
				aligned_buf[i] = mci_readl(host,
						DATA(host->data_offset));
			/* memcpy from aligned buffer into output buffer */
			memcpy(buf, aligned_buf, len);
			buf += len;
			cnt -= len;
		}
	} else
#endif
	{
		u32 *pdata = buf;
		for (; cnt >= 4; cnt -= 4)
			*pdata++ = mci_readl(host, DATA(host->data_offset));
		buf = pdata;
	}
	if (cnt) {
		host->part_buf32 = mci_readl(host, DATA(host->data_offset));
		dw_mci_pull_final_bytes(host, buf, cnt);
	}
}

static void dw_mci_push_data64(struct dw_mci *host, void *buf, int cnt)
{
	struct mmc_data *data = host->data;
	int init_cnt = cnt;

	/* try and push anything in the part_buf */
	if (unlikely(host->part_buf_count)) {
		int len = dw_mci_push_part_bytes(host, buf, cnt);
		buf += len;
		cnt -= len;

		if (host->part_buf_count == 8) {
			mci_writeq(host, DATA(host->data_offset),
					host->part_buf);
			host->part_buf_count = 0;
		}
	}
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x7)) {
		while (cnt >= 8) {
			u64 aligned_buf[16];
			int len = min(cnt & -8, (int)sizeof(aligned_buf));
			int items = len >> 3;
			int i;
			/* memcpy from input buffer into aligned buffer */
			memcpy(aligned_buf, buf, len);
			buf += len;
			cnt -= len;
			/* push data from aligned buffer into fifo */
			for (i = 0; i < items; ++i)
				mci_writeq(host, DATA(host->data_offset),
						aligned_buf[i]);
		}
	} else
#endif
	{
		u64 *pdata = buf;
		for (; cnt >= 8; cnt -= 8)
			mci_writeq(host, DATA(host->data_offset), *pdata++);
		buf = pdata;
	}
	/* put anything remaining in the part_buf */
	if (cnt) {
		dw_mci_set_part_bytes(host, buf, cnt);
		/* Push data if we have reached the expected data length */
		if ((data->bytes_xfered + init_cnt) ==
		    (data->blksz * data->blocks))
			mci_writeq(host, DATA(host->data_offset),
				   host->part_buf);
	}
}

static void dw_mci_pull_data64(struct dw_mci *host, void *buf, int cnt)
{
#ifndef CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
	if (unlikely((unsigned long)buf & 0x7)) {
		while (cnt >= 8) {
			/* pull data from fifo into aligned buffer */
			u64 aligned_buf[16];
			int len = min(cnt & -8, (int)sizeof(aligned_buf));
			int items = len >> 3;
			int i;
			for (i = 0; i < items; ++i)
				aligned_buf[i] = mci_readq(host,
						DATA(host->data_offset));
			/* memcpy from aligned buffer into output buffer */
			memcpy(buf, aligned_buf, len);
			buf += len;
			cnt -= len;
		}
	} else
#endif
	{
		u64 *pdata = buf;
		for (; cnt >= 8; cnt -= 8)
			*pdata++ = mci_readq(host, DATA(host->data_offset));
		buf = pdata;
	}
	if (cnt) {
		host->part_buf = mci_readq(host, DATA(host->data_offset));
		dw_mci_pull_final_bytes(host, buf, cnt);
	}
}

static void dw_mci_pull_data(struct dw_mci *host, void *buf, int cnt)
{
	int len;

	/* get remaining partial bytes */
	len = dw_mci_pull_part_bytes(host, buf, cnt);
	if (unlikely(len == cnt))
		return;
	buf += len;
	cnt -= len;

	/* get the rest of the data */
	host->pull_data(host, buf, cnt);
}

static void dw_mci_read_data_pio(struct dw_mci *host, bool dto)
{
	struct sg_mapping_iter *sg_miter = &host->sg_miter;
	void *buf;
	unsigned int offset;
	struct mmc_data	*data = host->data;
	int shift = host->data_shift;
	u32 status;
	unsigned int len;
	unsigned int remain, fcnt;

	do {
		if (!sg_miter_next(sg_miter))
			goto done;

		host->sg = sg_miter->piter.sg;
		buf = sg_miter->addr;
		remain = sg_miter->length;
		offset = 0;

		do {
			fcnt = (SDMMC_GET_FCNT(mci_readl(host, STATUS))
					<< shift) + host->part_buf_count;
			len = min(remain, fcnt);
			if (!len)
				break;
			dw_mci_pull_data(host, (void *)(buf + offset), len);
			data->bytes_xfered += len;
			offset += len;
			remain -= len;
		} while (remain);

		sg_miter->consumed = offset;
		status = mci_readl(host, MINTSTS);
		mci_writel(host, RINTSTS, SDMMC_INT_RXDR);
	/* if the RXDR is ready read again */
	} while ((status & SDMMC_INT_RXDR) ||
		 (dto && SDMMC_GET_FCNT(mci_readl(host, STATUS))));

	if (!remain) {
		if (!sg_miter_next(sg_miter))
			goto done;
		sg_miter->consumed = 0;
	}
	sg_miter_stop(sg_miter);
	return;

done:
	sg_miter_stop(sg_miter);
	host->sg = NULL;
	smp_wmb();
	set_bit(EVENT_XFER_COMPLETE, &host->pending_events);
}

static void dw_mci_write_data_pio(struct dw_mci *host)
{
	struct sg_mapping_iter *sg_miter = &host->sg_miter;
	void *buf;
	unsigned int offset;
	struct mmc_data	*data = host->data;
	int shift = host->data_shift;
	u32 status;
	unsigned int len;
	unsigned int fifo_depth = host->fifo_depth;
	unsigned int remain, fcnt;

	do {
		if (!sg_miter_next(sg_miter))
			goto done;

		host->sg = sg_miter->piter.sg;
		buf = sg_miter->addr;
		remain = sg_miter->length;
		offset = 0;

		do {
			fcnt = ((fifo_depth -
				 SDMMC_GET_FCNT(mci_readl(host, STATUS)))
					<< shift) - host->part_buf_count;
			len = min(remain, fcnt);
			if (!len)
				break;
			host->push_data(host, (void *)(buf + offset), len);
			data->bytes_xfered += len;
			offset += len;
			remain -= len;
		} while (remain);

		sg_miter->consumed = offset;
		status = mci_readl(host, MINTSTS);
		mci_writel(host, RINTSTS, SDMMC_INT_TXDR);
	} while (status & SDMMC_INT_TXDR); /* if TXDR write again */

	if (!remain) {
		if (!sg_miter_next(sg_miter))
			goto done;
		sg_miter->consumed = 0;
	}
	sg_miter_stop(sg_miter);
	return;

done:
	sg_miter_stop(sg_miter);
	host->sg = NULL;
	smp_wmb();
	set_bit(EVENT_XFER_COMPLETE, &host->pending_events);
}

static void dw_mci_cmd_interrupt(struct dw_mci *host, u32 status)
{
	if (!host->cmd_status)
		host->cmd_status = status;

	smp_wmb();

	set_bit(EVENT_CMD_COMPLETE, &host->pending_events);
	tasklet_schedule(&host->tasklet);
}

static irqreturn_t dw_mci_interrupt(int irq, void *dev_id)
{
	struct dw_mci *host = dev_id;
	u32 pending;
	int i;

	pending = mci_readl(host, MINTSTS); /* read-only mask reg */

	if (gi_start_tuning == 1) {
		if (pending & (SDMMC_INT_SBE | SDMMC_INT_EBE | SDMMC_INT_HLE |
			SDMMC_INT_DCRC | SDMMC_INT_RCRC | SDMMC_INT_RESP_ERR))
			recovery_sbe = 1;
	} else {
		if (pending & SDMMC_INT_SBE)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_SBE\n");
		if (pending & SDMMC_INT_EBE)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_EBE\n");
		if (pending & SDMMC_INT_HLE)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_HLE\n");
		if (pending & SDMMC_INT_DCRC)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_DCRC\n");
		if (pending & SDMMC_INT_RCRC)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_RCRC\n");
		if (pending & SDMMC_INT_RESP_ERR)
			dev_dbg(host->dev, "dw_mci_interrupt: SDMMC_INT_RESP_ERR\n");
	}

	/*
	 * DTO fix - version 2.10a and below, and only if internal DMA
	 * is configured.
	 */
	if (host->quirks & DW_MCI_QUIRK_IDMAC_DTO) {
		if (!pending &&
		    ((mci_readl(host, STATUS) >> 17) & 0x1fff))
			pending |= SDMMC_INT_DATA_OVER;
	}

	if (pending) {
		if (pending & DW_MCI_CMD_ERROR_FLAGS) {
			mci_writel(host, RINTSTS, DW_MCI_CMD_ERROR_FLAGS);
			host->cmd_status = pending;
			smp_wmb();
			set_bit(EVENT_CMD_COMPLETE, &host->pending_events);
		}

		if (pending & DW_MCI_DATA_ERROR_FLAGS) {
			/* if there is an error report DATA_ERROR */
			mci_writel(host, RINTSTS, DW_MCI_DATA_ERROR_FLAGS);
			host->data_status = pending;
			smp_wmb();
			set_bit(EVENT_DATA_ERROR, &host->pending_events);
			tasklet_schedule(&host->tasklet);
		}

		if (pending & SDMMC_INT_DATA_OVER) {
			mci_writel(host, RINTSTS, SDMMC_INT_DATA_OVER);
			if (!host->data_status)
				host->data_status = pending;
			smp_wmb();
			if (host->dir_status == DW_MCI_RECV_STATUS) {
				if (host->sg != NULL)
					dw_mci_read_data_pio(host, true);
			}
			set_bit(EVENT_DATA_COMPLETE, &host->pending_events);
			tasklet_schedule(&host->tasklet);
		}

		if (pending & SDMMC_INT_RXDR) {
			mci_writel(host, RINTSTS, SDMMC_INT_RXDR);
			if (host->dir_status == DW_MCI_RECV_STATUS && host->sg)
				dw_mci_read_data_pio(host, false);
		}

		if (pending & SDMMC_INT_TXDR) {
			mci_writel(host, RINTSTS, SDMMC_INT_TXDR);
			if (host->dir_status == DW_MCI_SEND_STATUS && host->sg)
				dw_mci_write_data_pio(host);
		}

		if (pending & SDMMC_INT_CMD_DONE) {
			mci_writel(host, RINTSTS, SDMMC_INT_CMD_DONE);
			dw_mci_cmd_interrupt(host, pending);
		}

		if (pending & SDMMC_INT_CD) {
			mci_writel(host, RINTSTS, SDMMC_INT_CD);
			queue_work(host->card_workqueue, &host->card_work);
		}

		/* Handle SDIO Interrupts */
		for (i = 0; i < host->num_slots; i++) {
			struct dw_mci_slot *slot = host->slot[i];
			if (pending & SDMMC_INT_SDIO(i)) {
				mci_writel(host, RINTSTS, SDMMC_INT_SDIO(i));
				mmc_signal_sdio_irq(slot->mmc);
			}
		}

	}

#ifdef CONFIG_MMC_DW_IDMAC
	/* Handle DMA interrupts */
	pending = mci_readl(host, IDSTS);
	if (pending & (SDMMC_IDMAC_INT_TI | SDMMC_IDMAC_INT_RI)) {
		mci_writel(host, IDSTS, SDMMC_IDMAC_INT_TI | SDMMC_IDMAC_INT_RI);
		mci_writel(host, IDSTS, SDMMC_IDMAC_INT_NI);
		host->dma_ops->complete(host);
	}
#endif

	return IRQ_HANDLED;
}

static void dw_mci_work_routine_card(struct work_struct *work)
{
	struct dw_mci *host = container_of(work, struct dw_mci, card_work);
	int i;

	for (i = 0; i < host->num_slots; i++) {
		struct dw_mci_slot *slot = host->slot[i];
		struct mmc_host *mmc = slot->mmc;
		struct mmc_request *mrq;
		int present;

		present = dw_mci_get_cd(mmc);
		while (present != slot->last_detect_state) {
			dev_dbg(&slot->mmc->class_dev, "card %s\n",
				present ? "inserted" : "removed");

			spin_lock_bh(&host->lock);

			/* Card change detected */
			slot->last_detect_state = present;

			/* Mark card as present if applicable */
			if (present != 0)
				set_bit(DW_MMC_CARD_PRESENT, &slot->flags);

			/* Clean up queue if present */
			mrq = slot->mrq;
			if (mrq) {
				if (mrq == host->mrq) {
					host->data = NULL;
					host->cmd = NULL;

					switch (host->state) {
					case STATE_IDLE:
						break;
					case STATE_SENDING_CMD:
						mrq->cmd->error = -ENOMEDIUM;
						if (!mrq->data)
							break;
						/* fall through */
					case STATE_SENDING_DATA:
						mrq->data->error = -ENOMEDIUM;
						dw_mci_stop_dma(host);
						break;
					case STATE_DATA_BUSY:
					case STATE_DATA_ERROR:
						if (mrq->data->error == -EINPROGRESS)
							mrq->data->error = -ENOMEDIUM;
						/* fall through */
					case STATE_SENDING_STOP:
						if (mrq->stop)
							mrq->stop->error = -ENOMEDIUM;
						break;
					}

					dw_mci_request_end(host, mrq);
				} else {
					list_del(&slot->queue_node);
					mrq->cmd->error = -ENOMEDIUM;
					if (mrq->data)
						mrq->data->error = -ENOMEDIUM;
					if (mrq->stop)
						mrq->stop->error = -ENOMEDIUM;

					spin_unlock(&host->lock);
					mmc_request_done(slot->mmc, mrq);
					spin_lock(&host->lock);
				}
			}

			/* Power down slot */
			if (present == 0) {
				clear_bit(DW_MMC_CARD_PRESENT, &slot->flags);

				/* Clear down the FIFO */
				dw_mci_fifo_reset(host);
#ifdef CONFIG_MMC_DW_IDMAC
				dw_mci_idmac_reset(host);
#endif

			}

			spin_unlock_bh(&host->lock);

			present = dw_mci_get_cd(mmc);
		}

		mmc_detect_change(slot->mmc,
			msecs_to_jiffies(host->pdata->detect_delay_ms));
	}
}

#ifdef CONFIG_OF
/* given a slot id, find out the device node representing that slot */
static struct device_node *dw_mci_of_find_slot_node(struct device *dev, u8 slot)
{
	struct device_node *np;
	const __be32 *addr;
	int len;

	if (!dev || !dev->of_node)
		return NULL;

	for_each_child_of_node(dev->of_node, np) {
		addr = of_get_property(np, "reg", &len);
		if (!addr || (len < sizeof(int)))
			continue;
		if (be32_to_cpup(addr) == slot)
			return np;
	}
	return NULL;
}

static struct dw_mci_of_slot_quirks {
	char *quirk;
	int id;
} of_slot_quirks[] = {
	{
		.quirk	= "disable-wp",
		.id	= DW_MCI_SLOT_QUIRK_NO_WRITE_PROTECT,
	},
};

static int dw_mci_of_get_slot_quirks(struct device *dev, u8 slot)
{
	struct device_node *np = dw_mci_of_find_slot_node(dev, slot);
	int quirks = 0;
	int idx;

	/* get quirks */
	for (idx = 0; idx < ARRAY_SIZE(of_slot_quirks); idx++)
		if (of_get_property(np, of_slot_quirks[idx].quirk, NULL))
			quirks |= of_slot_quirks[idx].id;

	return quirks;
}

/* find out bus-width for a given slot */
static u32 dw_mci_of_get_bus_wd(struct device *dev, u8 slot)
{
	struct device_node *np = dw_mci_of_find_slot_node(dev, slot);
	u32 bus_wd = 1;

	if (!np)
		return 1;

	if (of_property_read_u32(np, "bus-width", &bus_wd))
		dev_err(dev, "bus-width property not found, assuming width \
				 as 1\n");
	return bus_wd;
}

/* find the write protect gpio for a given slot; or -1 if none specified */
static int dw_mci_of_get_wp_gpio(struct device *dev, u8 slot)
{
	struct device_node *np = dw_mci_of_find_slot_node(dev, slot);
	int gpio;

	if (!np)
		return -EINVAL;

	gpio = of_get_named_gpio(np, "wp-gpios", 0);

	/* Having a missing entry is valid; return silently */
	if (!gpio_is_valid(gpio))
		return -EINVAL;

	if (devm_gpio_request(dev, gpio, "dw-mci-wp")) {
		dev_warn(dev, "gpio [%d] request failed\n", gpio);
		return -EINVAL;
	}

	return gpio;
}
#else /* CONFIG_OF */
static int dw_mci_of_get_slot_quirks(struct device *dev, u8 slot)
{
	return 0;
}
static u32 dw_mci_of_get_bus_wd(struct device *dev, u8 slot)
{
	return 1;
}
/*
static struct device_node *dw_mci_of_find_slot_node(struct device *dev, u8 slot)
{
	return NULL;
}
*/
static int dw_mci_of_get_wp_gpio(struct device *dev, u8 slot)
{
	return -EINVAL;
}
#endif /* CONFIG_OF */

static int dw_mci_init_slot(struct dw_mci *host, unsigned int id)
{
	struct mmc_host *mmc;
	struct dw_mci_slot *slot;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	int ctrl_id, ret;
	u32 freq[2];
	u8 bus_width;

	mmc = mmc_alloc_host(sizeof(struct dw_mci_slot), host->dev);
	if (!mmc)
		return -ENOMEM;

	slot = mmc_priv(mmc);
	slot->id = id;
	slot->mmc = mmc;
	slot->host = host;
	host->slot[id] = slot;

	slot->quirks = dw_mci_of_get_slot_quirks(host->dev, slot->id);

	mmc->ops = &dw_mci_ops;
	if (of_property_read_u32_array(host->dev->of_node,
				       "clock-freq-min-max", freq, 2)) {
		mmc->f_min = DW_MCI_FREQ_MIN;
		mmc->f_max = DW_MCI_FREQ_MAX;
	} else {
		mmc->f_min = freq[0];
		mmc->f_max = freq[1];
	}

	if (host->pdata->get_ocr)
		mmc->ocr_avail = host->pdata->get_ocr(id);
	else
		mmc->ocr_avail = MMC_VDD_32_33 | MMC_VDD_33_34;

	/*
	 * Start with slot power disabled, it will be enabled when a card
	 * is detected.
	 */
	if (host->pdata->setpower)
		host->pdata->setpower(id, 0);

	if (host->pdata->caps)
		mmc->caps = host->pdata->caps;

	if (host->pdata->pm_caps)
		mmc->pm_caps = host->pdata->pm_caps;

	if (host->dev->of_node) {
		ctrl_id = of_alias_get_id(host->dev->of_node, "mshc");
		if (ctrl_id < 0)
			ctrl_id = 0;
	} else {
		ctrl_id = to_platform_device(host->dev)->id;
	}
	if (drv_data && drv_data->caps)
		mmc->caps |= drv_data->caps[ctrl_id];

	if (host->pdata->caps2)
		mmc->caps2 = host->pdata->caps2;

	if (host->pdata->get_bus_wd)
		bus_width = host->pdata->get_bus_wd(slot->id);
	else if (host->dev->of_node)
		bus_width = dw_mci_of_get_bus_wd(host->dev, slot->id);
	else
		bus_width = 1;

	switch (bus_width) {
	case 8:
		mmc->caps |= MMC_CAP_8_BIT_DATA;
	case 4:
		mmc->caps |= MMC_CAP_4_BIT_DATA;
	}

	if (host->pdata->quirks & DW_MCI_QUIRK_HIGHSPEED)
		mmc->caps |= MMC_CAP_SD_HIGHSPEED | MMC_CAP_MMC_HIGHSPEED;

#ifdef CONFIG_MMC_DW_UHS_I_MODE
	/* support 1.8V voltage */
	mmc->caps |= MMC_CAP_1_8V_DDR;

	/* support UHS mode */
	mmc->caps |= MMC_CAP_UHS_SDR12;
	mmc->caps |= MMC_CAP_UHS_SDR25;
	mmc->caps |= MMC_CAP_UHS_SDR50;
#ifdef CONFIG_ARCH_OPV5XC_ES2
	mmc->caps |= MMC_CAP_UHS_SDR104;
	mmc->caps |= MMC_CAP_UHS_DDR50;
#endif

	/* support hw reset */
	mmc->caps |= MMC_CAP_HW_RESET;

	/* support over 150mA */
	mmc->caps |= MMC_CAP_SET_XPC_180;
	mmc->caps |= MMC_CAP_SET_XPC_300;
	mmc->caps |= MMC_CAP_SET_XPC_330;

	mmc->caps |= MMC_CAP_MAX_CURRENT_200;
	mmc->caps |= MMC_CAP_MAX_CURRENT_400;
	mmc->caps |= MMC_CAP_MAX_CURRENT_600;
	mmc->caps |= MMC_CAP_MAX_CURRENT_800;

#endif

	mmc->caps |= MMC_CAP_CMD23;

	if (host->pdata->blk_settings) {
		mmc->max_segs = host->pdata->blk_settings->max_segs;
		mmc->max_blk_size = host->pdata->blk_settings->max_blk_size;
		mmc->max_blk_count = host->pdata->blk_settings->max_blk_count;
		mmc->max_req_size = host->pdata->blk_settings->max_req_size;
		mmc->max_seg_size = host->pdata->blk_settings->max_seg_size;
	} else {
		/* Useful defaults if platform data is unset. */
#ifdef CONFIG_MMC_DW_IDMAC
		mmc->max_segs = host->ring_size;
		mmc->max_blk_size = 65536;
		mmc->max_blk_count = host->ring_size;
		mmc->max_seg_size = 0x1000;
		mmc->max_req_size = mmc->max_seg_size * mmc->max_blk_count;
#else
		mmc->max_segs = 64;
		mmc->max_blk_size = 65536; /* BLKSIZ is 16 bits */
		mmc->max_blk_count = 512;
		mmc->max_req_size = mmc->max_blk_size * mmc->max_blk_count;
		mmc->max_seg_size = mmc->max_req_size;
#endif /* CONFIG_MMC_DW_IDMAC */
	}

	if (dw_mci_get_cd(mmc))
		set_bit(DW_MMC_CARD_PRESENT, &slot->flags);
	else
		clear_bit(DW_MMC_CARD_PRESENT, &slot->flags);

	slot->wp_gpio = dw_mci_of_get_wp_gpio(host->dev, slot->id);

	ret = mmc_add_host(mmc);
	if (ret)
		goto err_setup_bus;

#ifdef CONFIG_DEBUG_FS
	dw_mci_init_debugfs(slot);
#endif

	/* Card initially undetected */
	slot->last_detect_state = 0;

	return 0;

err_setup_bus:
	mmc_free_host(mmc);
	return -EINVAL;
}

static void dw_mci_cleanup_slot(struct dw_mci_slot *slot, unsigned int id)
{
	/* Shutdown detect IRQ */
	if (slot->host->pdata->exit)
		slot->host->pdata->exit(id);

	/* Debugfs stuff is cleaned up by mmc core */
	mmc_remove_host(slot->mmc);
	slot->host->slot[id] = NULL;
	mmc_free_host(slot->mmc);
}

static void dw_mci_init_dma(struct dw_mci *host)
{
	/* Alloc memory for sg translation */
	host->sg_cpu = dmam_alloc_coherent(host->dev, PAGE_SIZE,
					  &host->sg_dma, GFP_KERNEL);
	if (!host->sg_cpu) {
		dev_err(host->dev, "%s: could not alloc DMA memory\n",
			__func__);
		goto no_dma;
	}

	/* Determine which DMA interface to use */
#ifdef CONFIG_MMC_DW_IDMAC
	host->dma_ops = &dw_mci_idmac_ops;
	dev_info(host->dev, "Using internal DMA controller.\n");
#endif

	if (!host->dma_ops)
		goto no_dma;

	if (host->dma_ops->init && host->dma_ops->start &&
	    host->dma_ops->stop && host->dma_ops->cleanup) {
		if (host->dma_ops->init(host)) {
			dev_err(host->dev, "Unable to initialize DMA Controller.\n");
			goto no_dma;
		}
	} else {
		dev_err(host->dev, "DMA initialization not found.\n");
		goto no_dma;
	}

	host->use_dma = 1;
	return;

no_dma:
	dev_info(host->dev, "Using PIO mode.\n");
	host->use_dma = 0;
	return;
}

static bool dw_mci_ctrl_reset(struct dw_mci *host, u32 reset)
{
	unsigned long timeout = jiffies + msecs_to_jiffies(500);
	u32 ctrl;

	ctrl = mci_readl(host, CTRL);
	ctrl |= reset;
	mci_writel(host, CTRL, ctrl);

	/* wait till resets clear */
	do {
		ctrl = mci_readl(host, CTRL);
		if (!(ctrl & reset))
			return true;
	} while (time_before(jiffies, timeout));

	dev_err(host->dev,
		"Timeout resetting block (ctrl reset %#x)\n",
		ctrl & reset);

	return false;
}

static inline bool dw_mci_fifo_reset(struct dw_mci *host)
{
	/*
	 * Reseting generates a block interrupt, hence setting
	 * the scatter-gather pointer to NULL.
	 */
	if (host->sg) {
		sg_miter_stop(&host->sg_miter);
		host->sg = NULL;
	}

	return dw_mci_ctrl_reset(host, SDMMC_CTRL_FIFO_RESET);
}

static inline bool dw_mci_ctrl_all_reset(struct dw_mci *host)
{
	return dw_mci_ctrl_reset(host,
				 SDMMC_CTRL_FIFO_RESET |
				 SDMMC_CTRL_RESET |
				 SDMMC_CTRL_DMA_RESET);
}

#ifdef CONFIG_OF
static struct dw_mci_of_quirks {
	char *quirk;
	int id;
} of_quirks[] = {
	{
		.quirk	= "broken-cd",
		.id	= DW_MCI_QUIRK_BROKEN_CARD_DETECTION,
	},
};

static struct dw_mci_board *dw_mci_parse_dt(struct dw_mci *host)
{
	struct dw_mci_board *pdata;
	struct device *dev = host->dev;
	struct device_node *np = dev->of_node;
	const struct dw_mci_drv_data *drv_data = host->drv_data;
	int idx, ret;
	u32 clock_frequency;

	pdata = devm_kzalloc(dev, sizeof(*pdata), GFP_KERNEL);
	if (!pdata) {
		dev_err(dev, "could not allocate memory for pdata\n");
		return ERR_PTR(-ENOMEM);
	}

	/* find out number of slots supported */
	if (of_property_read_u32(dev->of_node, "num-slots",
				&pdata->num_slots)) {
		dev_info(dev, "num-slots property not found assuming 1 slot is available\n");
		pdata->num_slots = 1;
	}

	/* get quirks */
	for (idx = 0; idx < ARRAY_SIZE(of_quirks); idx++)
		if (of_get_property(np, of_quirks[idx].quirk, NULL))
			pdata->quirks |= of_quirks[idx].id;

	if (of_property_read_u32(np, "fifo-depth", &pdata->fifo_depth))
		dev_info(dev, "fifo-depth property not found, using \
				value of FIFOTH register as default\n");

	of_property_read_u32(np, "card-detect-delay", &pdata->detect_delay_ms);

	if (!of_property_read_u32(np, "clock-frequency", &clock_frequency))
		pdata->bus_hz = clock_frequency;

	if (drv_data && drv_data->parse_dt) {
		ret = drv_data->parse_dt(host);
		if (ret)
			return ERR_PTR(ret);
	}

	if (of_find_property(np, "keep-power-in-suspend", NULL))
		pdata->pm_caps |= MMC_PM_KEEP_POWER;

	if (of_find_property(np, "enable-sdio-wakeup", NULL))
		pdata->pm_caps |= MMC_PM_WAKE_SDIO_IRQ;

	if (of_find_property(np, "supports-highspeed", NULL))
		pdata->caps |= MMC_CAP_SD_HIGHSPEED | MMC_CAP_MMC_HIGHSPEED;

	if (of_find_property(np, "caps2-mmc-hs200-1_8v", NULL))
		pdata->caps2 |= MMC_CAP2_HS200_1_8V_SDR;

	if (of_find_property(np, "caps2-mmc-hs200-1_2v", NULL))
		pdata->caps2 |= MMC_CAP2_HS200_1_2V_SDR;

	return pdata;
}

#else /* CONFIG_OF */
static struct dw_mci_board *dw_mci_parse_dt(struct dw_mci *host)
{
	return ERR_PTR(-EINVAL);
}
#endif /* CONFIG_OF */

int dw_mci_probe(struct dw_mci *host)
{
	int width, i, ret = 0;
	u32 fifo_size;
	int init_slots = 0;
	struct completion dwmci_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	unsigned int ctrl;

	init_completion(&dwmci_complete);
	/* clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) & ~(1 << 25), OPV5XC_CR_PMU_BASE_VIRT);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 25)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 25)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) | (1 << 25), OPV5XC_CR_PMU_BASE_VIRT);

	do {
		wait_for_completion_timeout(&dwmci_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<25)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		dev_err(host->dev, "Timeout while enabling power for DW MMC\n");
		return -ENODEV;
	}

	opv5xc_regulator_disable();

	ctrl = mci_readl(host, PWREN);
	ctrl |= (0x1 << 0);
	mci_writel(host, PWREN, ctrl);

	opv5xc_regulator_enable();
#endif

	if (!host->pdata) {
		host->pdata = dw_mci_parse_dt(host);
		if (IS_ERR(host->pdata)) {
			dev_err(host->dev, "platform data not available\n");
			return -EINVAL;
		}
	}

	if (!host->pdata->select_slot && host->pdata->num_slots > 1) {
		dev_err(host->dev,
			"Platform data must supply select_slot function\n");
		return -ENODEV;
	}

	host->vmmc = NULL;
	host->bus_hz = host->pdata->bus_hz;

	if (!host->bus_hz) {
		dev_err(host->dev,
			"Platform data must supply bus speed\n");
		ret = -ENODEV;
		goto err_regulator;
	}

	host->quirks = host->pdata->quirks;

	spin_lock_init(&host->lock);
	INIT_LIST_HEAD(&host->queue);

	/*
	 * Get the host data width - this assumes that HCON has been set with
	 * the correct values.
	 */
	i = (mci_readl(host, HCON) >> 7) & 0x7;
	if (!i) {
		host->push_data = dw_mci_push_data16;
		host->pull_data = dw_mci_pull_data16;
		width = 16;
		host->data_shift = 1;
	} else if (i == 2) {
		host->push_data = dw_mci_push_data64;
		host->pull_data = dw_mci_pull_data64;
		width = 64;
		host->data_shift = 3;
	} else {
		/* Check for a reserved value, and warn if it is */
		WARN((i != 1),
		     "HCON reports a reserved host data width!\n"
		     "Defaulting to 32-bit access.\n");
		host->push_data = dw_mci_push_data32;
		host->pull_data = dw_mci_pull_data32;
		width = 32;
		host->data_shift = 2;
	}

	/* Reset all blocks */
	if (!dw_mci_ctrl_all_reset(host))
		return -ENODEV;

#ifdef DW_MCI_OPV5XC_ACP_SUPPORT
	opv5xc_acp_enable(IXC_SDIO);
#endif

	host->dma_ops = host->pdata->dma_ops;
	dw_mci_init_dma(host);

	/* Clear the interrupts for the host controller */
	mci_writel(host, RINTSTS, 0xFFFFFFFF);
	mci_writel(host, INTMASK, 0); /* disable all mmc interrupt first */

	/* Put in max timeout */
	mci_writel(host, TMOUT, 0xFFFFFFFF);

	/*
	 * FIFO threshold settings  RxMark  = fifo_size / 2 - 1,
	 *                          Tx Mark = fifo_size / 2 DMA Size = 8
	 */
	if (!host->pdata->fifo_depth) {
		/*
		 * Power-on value of RX_WMark is FIFO_DEPTH-1, but this may
		 * have been overwritten by the bootloader, just like we're
		 * about to do, so if you know the value for your hardware, you
		 * should put it in the platform data.
		 */
		fifo_size = mci_readl(host, FIFOTH);
		fifo_size = 1 + ((fifo_size >> 16) & 0xfff);
	} else {
		fifo_size = host->pdata->fifo_depth;
	}
	host->fifo_depth = fifo_size;
	host->fifoth_val =
		SDMMC_SET_FIFOTH(0x2, fifo_size / 2 - 1, fifo_size / 2);
	mci_writel(host, FIFOTH, host->fifoth_val);

	/* disable clock to CIU */
	mci_writel(host, CLKENA, 0);
	mci_writel(host, CLKSRC, 0);

	/*
	 * In 2.40a spec, Data offset is changed.
	 * Need to check the version-id and set data-offset for DATA register.
	 */
	host->verid = SDMMC_GET_VERID(mci_readl(host, VERID));
	dev_info(host->dev, "Version ID is %04x\n", host->verid);

	if (host->verid < DW_MMC_240A)
		host->data_offset = DATA_OFFSET;
	else
		host->data_offset = DATA_240A_OFFSET;

	tasklet_init(&host->tasklet, dw_mci_tasklet_func, (unsigned long)host);
	host->card_workqueue = alloc_workqueue("dw-mci-card",
			WQ_MEM_RECLAIM | WQ_NON_REENTRANT, 1);
	if (!host->card_workqueue) {
		ret = -ENOMEM;
		goto err_dmaunmap;
	}
	INIT_WORK(&host->card_work, dw_mci_work_routine_card);
	ret = devm_request_irq(host->dev, host->irq, dw_mci_interrupt,
			       host->irq_flags, "dw-mci", host);
	if (ret)
		goto err_workqueue;

	if (host->pdata->num_slots)
		host->num_slots = host->pdata->num_slots;
	else
		host->num_slots = ((mci_readl(host, HCON) >> 1) & 0x1F) + 1;

	/*
	 * Enable interrupts for command done, data over, data empty, card det,
	 * receive ready and error such as transmit, receive timeout, crc error
	 */
	mci_writel(host, RINTSTS, 0xFFFFFFFF);
	mci_writel(host, INTMASK, SDMMC_INT_CMD_DONE | SDMMC_INT_DATA_OVER |
		   SDMMC_INT_TXDR | SDMMC_INT_RXDR |
		   DW_MCI_ERROR_FLAGS | SDMMC_INT_CD);
	mci_writel(host, CTRL, SDMMC_CTRL_INT_ENABLE); /* Enable mci interrupt */

	dev_info(host->dev, "DW MMC controller at irq %d, "
		 "%d bit host data width, "
		 "%u deep fifo\n",
		 host->irq, width, fifo_size);

	/* We need at least one slot to succeed */
	for (i = 0; i < host->num_slots; i++) {
		ret = dw_mci_init_slot(host, i);
		if (ret)
			dev_dbg(host->dev, "slot %d init failed\n", i);
		else
			init_slots++;
	}

	if (init_slots) {
		dev_info(host->dev, "%d slots initialized\n", init_slots);
	} else {
		dev_dbg(host->dev, "attempted to initialize %d slots, "
					"but failed on all\n", host->num_slots);
		goto err_workqueue;
	}

	if (host->quirks & DW_MCI_QUIRK_IDMAC_DTO)
		dev_info(host->dev, "Internal DMAC interrupt fix enabled.\n");

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* SD Schmitt trigger input enable */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x9c) | (0x1 << 8)), OPV5XC_CR_PMU_BASE_VIRT + 0x9c);
#endif

	return 0;

err_workqueue:
	destroy_workqueue(host->card_workqueue);

err_dmaunmap:
	if (host->use_dma && host->dma_ops->exit)
		host->dma_ops->exit(host);

err_regulator:
	if (host->vmmc)
		regulator_disable(host->vmmc);

	return ret;
}
EXPORT_SYMBOL(dw_mci_probe);

void dw_mci_remove(struct dw_mci *host)
{
	int i;

	mci_writel(host, RINTSTS, 0xFFFFFFFF);
	mci_writel(host, INTMASK, 0); /* disable all mmc interrupt first */

	for (i = 0; i < host->num_slots; i++) {
		dev_dbg(host->dev, "remove slot %d\n", i);
		if (host->slot[i])
			dw_mci_cleanup_slot(host->slot[i], i);
	}

	/* disable clock to CIU */
	mci_writel(host, CLKENA, 0);
	mci_writel(host, CLKSRC, 0);

	/* let the card pwr off. */
	mci_writel(host, PWREN, 0);

	destroy_workqueue(host->card_workqueue);

	if (host->use_dma && host->dma_ops->exit)
		host->dma_ops->exit(host);

	if (host->vmmc)
		regulator_disable(host->vmmc);
}
EXPORT_SYMBOL(dw_mci_remove);



#ifdef CONFIG_PM_SLEEP
/*
 * TODO: we should probably disable the clock to the card in the suspend path.
 */
int dw_mci_suspend(struct dw_mci *host)
{
	opv5xc_regulator_disable();
	return 0;
}
EXPORT_SYMBOL(dw_mci_suspend);

int dw_mci_resume(struct dw_mci *host)
{
	int i, ret;
	struct mmc_host *mmc = host->cur_slot->mmc;
	struct completion dwmci_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;
	unsigned int ctrl;

	init_completion(&dwmci_complete);
	/* clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) & ~(1 << 25), OPV5XC_CR_PMU_BASE_VIRT);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 25)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 25)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) | (1 << 25), OPV5XC_CR_PMU_BASE_VIRT);

	do {
		wait_for_completion_timeout(&dwmci_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<25)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		dev_err(host->mmc, "Timeout while enabling power for DW MMC\n");
		return -ENODEV;
	}

	opv5xc_regulator_disable();

	ctrl = mci_readl(host, PWREN);
	ctrl |= (0x1 << 0);
	mci_writel(host, PWREN, ctrl);

	opv5xc_regulator_enable();

	if (!dw_mci_ctrl_all_reset(host)) {
		ret = -ENODEV;
		return ret;
	}

	if (host->use_dma && host->dma_ops->init)
		host->dma_ops->init(host);

	/*
	 * Restore the initial value at FIFOTH register
	 * And Invalidate the prev_blksz with zero
	 */
	mci_writel(host, FIFOTH, host->fifoth_val);
	host->prev_blksz = 0;

	/* Put in max timeout */
	mci_writel(host, TMOUT, 0xFFFFFFFF);

	mci_writel(host, RINTSTS, 0xFFFFFFFF);
	mci_writel(host, INTMASK, SDMMC_INT_CMD_DONE | SDMMC_INT_DATA_OVER |
		   SDMMC_INT_TXDR | SDMMC_INT_RXDR |
		   DW_MCI_ERROR_FLAGS | SDMMC_INT_CD);
	mci_writel(host, CTRL, SDMMC_CTRL_INT_ENABLE);

	for (i = 0; i < host->num_slots; i++) {
		struct dw_mci_slot *slot = host->slot[i];
		if (!slot)
			continue;
		if (slot->mmc->pm_flags & MMC_PM_KEEP_POWER) {
			dw_mci_set_ios(slot->mmc, &slot->mmc->ios);
			dw_mci_setup_bus(slot, true);
		}
	}

	mmc_resume_card(mmc);
	return 0;
}
EXPORT_SYMBOL(dw_mci_resume);
#endif /* CONFIG_PM_SLEEP */

int dw_mci_shutdown(struct dw_mci *host)
{
	opv5xc_set_sd_voltage(3300000);
	return 0;
}
EXPORT_SYMBOL(dw_mci_shutdown);

static int __init dw_mci_init(void)
{
	pr_info("Synopsys Designware Multimedia Card Interface Driver\n");
	opv5xc_regulator_init();
	return 0;
}

static void __exit dw_mci_exit(void)
{
	opv5xc_regulator_release();
}

late_initcall(dw_mci_init);
module_exit(dw_mci_exit);

MODULE_DESCRIPTION("DW Multimedia Card Interface driver for OpenSilicon OPV5XC");
MODULE_AUTHOR("Open Silicon, Inc.");
MODULE_AUTHOR("NXP Semiconductor VietNam");
MODULE_AUTHOR("Imagination Technologies Ltd");
MODULE_LICENSE("GPL v2");
