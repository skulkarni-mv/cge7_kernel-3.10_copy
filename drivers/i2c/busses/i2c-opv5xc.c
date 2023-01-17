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

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/platform_device.h>

#include <mach/opv5xc.h>

#define DRIVER_NAME	"opv5xc-i2c"

/* Define TWI address offset. */
#define SSP_TWI0_CFG_OFFSET		0x00
#define SSP_TWI0_TIMEOUT_OFFSET		0x04
#define SSP_TWI0_SLAVE_ADDR_OFFSET	0x08
#define SSP_TWI0_WR_DATA_OFFSET		0x0C
#define SSP_TWI0_RD_DATA_OFFSET		0x10
#define SSP_TWI0_INTR_STAT_OFFSET	0x14
#define SSP_TWI0_INTR_EN_OFFSET		0x18
#define SSP_TWI0_OUT_DLY_OFFSET		0x1C
#define SSP_TWI0_HS_CLK_DIV_OFFSET	0x20

#define I2C_BUSERR_FG			0x1
#define I2C_ACTDONE_FG			0x2

#define TWI_EN				BIT(31)
#define TWI_HANDSHAKE_EN		BIT(11)
#define TWI_2ND_NEOF			BIT(9)
#define TWI_1ST_NEOF			BIT(8)
#define TWI_RUN_START			BIT(6)
#define TWI_CMD_SHIFT			4
#define TWI_WD_LEN_SHIFT		2
#define TWI_RD_LEN_SHIFT		0

/* I2C_CLK = PCLK/((TWI_CLK_DIV_H+1)+(TWI_CLK_DIV_L+1))
 * FPGA:    PCLK = 25Mhz
 * SILICON: PCLK = ?
 * TWI_CLKDIV_H = 0x1B (default)
 * TWI_CLKDIV_L = 0x22 (default)
 */
#define I2C_PCLK			25000000

/* 100KHz: 100000; 200KHz: 200000; 300KHz: 300000; 400KHz: 400000 */
#define I2C_CLK				100000

#define I2C_MAX_BYTES_PER_RW		4

#define I2C_STATE_RUNNING		1
#define I2C_STATE_DONE			2
#define I2C_STATE_ERROR			3

enum opv5xc_i2c_cmd_type {
	CNX_I2C_CMD_READ = 0,		/* Write only */
	CNX_I2C_CMD_WRITE = 1,		/* Read only */
	CNX_I2C_CMD_WRITE_READ = 2,	/* Write then Read */
	CNX_I2C_CMD_READ_WRITE = 3,	/* Read then Write */
};

struct opv5xc_i2c_struct {
	wait_queue_head_t wait;

	struct i2c_adapter adapter;
	void __iomem *base;
	int irq;

	int state;			/* see STATE_ */
};

static void i2c_cnx_hw_init(struct opv5xc_i2c_struct *i2c_cnx)
{
	unsigned int u32tmp;
	unsigned int div;

	/* Disable I2C controller */
	writel(0, i2c_cnx->base + SSP_TWI0_CFG_OFFSET);

	/* Check the Reg Dump when testing */
	u32tmp = 0x7f;		/* Timeout value */
	u32tmp |= (1 << 7);	/* Timeout enable */

	/* FIXME: Default high/low period divider setting doesn't
	 * work on latest PROM, we need larger divider to make
	 * I2C work. */
	div = (I2C_PCLK / I2C_CLK - 2) / 2;
#if 1
	u32tmp |= div << 8;		/* Clock low period divider for Fast-Speed mode */
	u32tmp |= div << 20;		/* Clock high period divider for Fast-Speed mode */
#else
	u32tmp |= (0x22 * 4) << 8;	/* Clock low period divider for Fast-Speed mode */
	u32tmp |= (0x1b * 4) << 20;	/* Clock high period divider for Fast-Speed mode */
#endif

	/* Clock divider for High-Speed mode TODO */
	writel(u32tmp, i2c_cnx->base + SSP_TWI0_TIMEOUT_OFFSET);

	/* Enable interrupt */
	writel(I2C_ACTDONE_FG, i2c_cnx->base + SSP_TWI0_INTR_EN_OFFSET);

	/* Clear interrupt status */
	u32tmp = readl(i2c_cnx->base + SSP_TWI0_INTR_STAT_OFFSET);
	u32tmp |= (I2C_ACTDONE_FG | I2C_BUSERR_FG);
	writel(u32tmp, i2c_cnx->base + SSP_TWI0_INTR_STAT_OFFSET);

	/* Output Data Delay */
	u32tmp = readl(i2c_cnx->base + SSP_TWI0_OUT_DLY_OFFSET);
	u32tmp |= 0x4;		/* Default: 0x1 */
	writel(u32tmp, i2c_cnx->base + SSP_TWI0_OUT_DLY_OFFSET);

	/* Enable I2C controller */
	u32tmp = readl(i2c_cnx->base + SSP_TWI0_CFG_OFFSET);
	/* Enable handshake */
	u32tmp |= (0x1 << 11);

	writel(u32tmp | ((unsigned int)1 << 31),
	       i2c_cnx->base + SSP_TWI0_CFG_OFFSET);
}

static irqreturn_t i2c_opv5xc_isr(int irq, void *dev_id)
{
	struct opv5xc_i2c_struct *i2c_cnx = dev_id;
	unsigned long status;

	dev_dbg(&i2c_cnx->adapter.dev, "<%s>\n", __func__);

	status = readl(i2c_cnx->base + SSP_TWI0_INTR_STAT_OFFSET);
	if (!(status & (I2C_BUSERR_FG | I2C_ACTDONE_FG)))
		return IRQ_NONE;
	writel(status, i2c_cnx->base + SSP_TWI0_INTR_STAT_OFFSET);

	if (status & I2C_BUSERR_FG)
		i2c_cnx->state = I2C_STATE_ERROR;
	else {
		/* The bus error interrupt may assert before action done interrupt.
		   If the previouse state is error, this done interrupt just means action finishes.
		   The state must also be error. */
		if (i2c_cnx->state != I2C_STATE_ERROR)
			i2c_cnx->state = I2C_STATE_DONE;
	}

	wake_up(&i2c_cnx->wait);
	return IRQ_HANDLED;
}

static int i2c_opv5xc_xfer(struct i2c_adapter *adapter,
			    struct i2c_msg *msg, int num)
{
	struct opv5xc_i2c_struct *i2c_cnx = i2c_get_adapdata(adapter);
	enum opv5xc_i2c_cmd_type cmd_type;
	int write_len, read_len;
	u8 *write_data, *read_data;
	u32 cfg, data;
	int result, i, j;

	dev_dbg(&adapter->dev, "## Nunmer of msgs: %d\n", num);

	if (num > 2) {
		dev_err(&adapter->dev,
			"hardware does not support more than 2 msgs per transfer\n");
		return -EIO;
	}

	for (i = 0; i < num; i++) {

		dev_dbg(&adapter->dev, "## msg[%d]->addr: 0x%x\n",
				i, msg[i].addr);
		dev_dbg(&adapter->dev, "## msg[%d]->flags: 0x%x\n",
				i, msg[i].flags);
		dev_dbg(&adapter->dev, "## msg[%d]->len: %d\n", i, msg[i].len);
		if (!(msg[i].flags & I2C_M_RD)) {
			for (j = 0; j < msg[i].len; j++)
				dev_dbg(&adapter->dev,
					"## msg[%d]->buf[%d]: 0x%x\n",
					i, j, msg[i].buf[j]);
		}

		if (msg[i].flags & ~I2C_M_RD) {
			dev_err(&adapter->dev,
				"driver does not support msg flags 0x%x\n",
				msg[i].flags);
			return -EIO;
		}
	}

	if (num == 2) {
		if (msg[0].addr != msg[1].addr) {
			dev_err(&adapter->dev,
				"hardware does not support two msgs to different client addresses\n");
			return -EIO;
		}
		if ((msg[0].flags & I2C_M_RD) == (msg[1].flags & I2C_M_RD)) {
			dev_err(&adapter->dev,
				"hardware does not support two msgs in the same direction\n");
			return -EIO;
		}
	}

	if (num == 1) {
		if (msg[0].flags & I2C_M_RD) {
			cmd_type = CNX_I2C_CMD_READ;
			read_len = msg[0].len;
			read_data = msg[0].buf;
			write_len = 0;
			write_data = NULL;
		} else {
			cmd_type = CNX_I2C_CMD_WRITE;
			read_len = 0;
			read_data = NULL;
			write_len = msg[0].len;
			write_data = msg[0].buf;
		}
	} else { /* num == 2 */
		if (msg[0].flags & I2C_M_RD) {
			cmd_type = CNX_I2C_CMD_READ_WRITE;
			read_len = msg[0].len;
			read_data = msg[0].buf;
			write_len = msg[1].len;
			write_data = msg[1].buf;
		} else {
			cmd_type = CNX_I2C_CMD_WRITE_READ;
			read_len = msg[1].len;
			read_data = msg[1].buf;
			write_len = msg[0].len;
			write_data = msg[0].buf;
		}
	}

	dev_dbg(&adapter->dev, "## cmd_type: %d\n", cmd_type);
	dev_dbg(&adapter->dev, "## write_len: %d\n", write_len);
	dev_dbg(&adapter->dev, "## read_len: %d\n", read_len);

	writel(msg[0].addr << 1, i2c_cnx->base + SSP_TWI0_SLAVE_ADDR_OFFSET);

	do {
		cfg = TWI_EN | TWI_HANDSHAKE_EN | TWI_RUN_START |
		      (cmd_type << TWI_CMD_SHIFT);

		if (write_len > I2C_MAX_BYTES_PER_RW) {
			cfg |= (I2C_MAX_BYTES_PER_RW - 1) << TWI_WD_LEN_SHIFT;
			if (cmd_type == CNX_I2C_CMD_READ_WRITE)
				cfg |= TWI_2ND_NEOF;
			else
				cfg |= TWI_1ST_NEOF;
		} else if (write_len)
			cfg |= (write_len - 1) << TWI_WD_LEN_SHIFT;

		if (read_len > I2C_MAX_BYTES_PER_RW) {
			cfg |= (I2C_MAX_BYTES_PER_RW - 1) << TWI_RD_LEN_SHIFT;
			if (cmd_type == CNX_I2C_CMD_WRITE_READ)
				cfg |= TWI_2ND_NEOF;
			else
				cfg |= TWI_1ST_NEOF;
		} else if (read_len)
			cfg |= (read_len - 1) << TWI_RD_LEN_SHIFT;

		if (write_len && (cmd_type != CNX_I2C_CMD_READ_WRITE ||
				  read_len <= I2C_MAX_BYTES_PER_RW)) {

			for (i = 0, data = 0;
			     i < I2C_MAX_BYTES_PER_RW && write_len;
			     i++, write_data++, write_len--)
				data |= (*write_data) << (i * 8);

			dev_dbg(&adapter->dev, "## i2c write data: 0x%08x\n",
					data);
			writel(data, i2c_cnx->base + SSP_TWI0_WR_DATA_OFFSET);
		}

		i2c_cnx->state = I2C_STATE_RUNNING;

		/* Start HW */
		dev_dbg(&adapter->dev, "## i2c config: 0x%08x\n", cfg);
		writel(cfg, i2c_cnx->base + SSP_TWI0_CFG_OFFSET);

		/* Wait for IRQ */
		result = wait_event_timeout(i2c_cnx->wait,
					    i2c_cnx->state != I2C_STATE_RUNNING,
					    10 * HZ);

		if (result == 0) {
			dev_err(&adapter->dev, "operation timeout\n");
			result = -ETIMEDOUT;
			goto xfer_error;
		} else if (i2c_cnx->state != I2C_STATE_DONE) {
			dev_err(&adapter->dev, "i/o error\n");
			result = -EIO;
			goto xfer_error;
		}

		if (read_len && (cmd_type != CNX_I2C_CMD_WRITE_READ ||
				 !write_len)) {

			data = readl(i2c_cnx->base + SSP_TWI0_RD_DATA_OFFSET);
			dev_dbg(&adapter->dev, "## i2c read data: 0x%08x\n",
					data);

			for (i = 0;
			     i < I2C_MAX_BYTES_PER_RW && read_len;
			     i++, read_data++, read_len--)
				*read_data = (data >> (i * 8)) & 0xFF;
		}

	} while (write_len || read_len);

	result = num;
xfer_error:
	writel(0, i2c_cnx->base + SSP_TWI0_CFG_OFFSET);
	return result;
}

static u32 i2c_opv5xc_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static struct i2c_algorithm i2c_opv5xc_algo = {
	.master_xfer = i2c_opv5xc_xfer,
	.functionality = i2c_opv5xc_func,
};

int i2c_opv5xc_suspend(struct platform_device *pdev, pm_message_t state)
{
	return 0;
}

int i2c_opv5xc_resume(struct platform_device *pdev)
{
	struct opv5xc_i2c_struct *i2c_cnx = platform_get_drvdata(pdev);

	i2c_cnx_hw_init(i2c_cnx);
	return 0;
}

static int i2c_opv5xc_probe(struct platform_device *pdev)
{
	struct opv5xc_i2c_struct *i2c_cnx;
	struct resource *res;
	int irq;
	int ret;

	dev_dbg(&pdev->dev, "<%s>\n", __func__);

	i2c_cnx = devm_kzalloc(&pdev->dev, sizeof(*i2c_cnx), GFP_KERNEL);
	if (!i2c_cnx)
		return -ENOMEM;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	i2c_cnx->base = devm_ioremap_resource(&pdev->dev, res);
	if (IS_ERR(i2c_cnx->base))
		return PTR_ERR(i2c_cnx->base);

	irq = platform_get_irq(pdev, 0);
	if (irq < 0) {
		dev_err(&pdev->dev, "can't get irq number\n");
		return -ENOENT;
	}

	ret = opv5xc_enable_peri(OPV5XC_PERI_TWI);
	if (ret)
		return ret;

	/* Setup i2c_cnx driver structure */
	strcpy(i2c_cnx->adapter.name, pdev->name);
	i2c_cnx->adapter.owner = THIS_MODULE;
	i2c_cnx->adapter.algo = &i2c_opv5xc_algo;
	i2c_cnx->adapter.dev.parent = &pdev->dev;
	i2c_cnx->adapter.nr = pdev->id;
	i2c_cnx->irq = irq;

	i2c_cnx_hw_init(i2c_cnx);

	/* Request IRQ */
	ret = devm_request_irq(&pdev->dev, irq, i2c_opv5xc_isr, 0,
			pdev->name, i2c_cnx);
	if (ret) {
		dev_err(&pdev->dev, "can't claim irq %d\n", irq);
		goto err_irq;
	}

	/* Init queue */
	init_waitqueue_head(&i2c_cnx->wait);

	/* Set up adapter data */
	i2c_set_adapdata(&i2c_cnx->adapter, i2c_cnx);

	/* Add I2C adapter */
	ret = i2c_add_numbered_adapter(&i2c_cnx->adapter);
	if (ret < 0) {
		dev_err(&pdev->dev, "registration failed\n");
		goto err_adapter;
	}

	/* Set up platform driver data */
	platform_set_drvdata(pdev, i2c_cnx);

	dev_dbg(&i2c_cnx->adapter.dev, "adapter name: \"%s\"\n",
		i2c_cnx->adapter.name);
	dev_dbg(&i2c_cnx->adapter.dev, "I2C adapter registered\n");

	return 0;		/* Return OK */

err_adapter:
err_irq:
	opv5xc_disable_peri(OPV5XC_PERI_TWI);

	return ret;		/* Return error number */
}

static int i2c_opv5xc_remove(struct platform_device *pdev)
{
	struct opv5xc_i2c_struct *i2c_cnx = platform_get_drvdata(pdev);

	dev_dbg(&i2c_cnx->adapter.dev, "adapter removed\n");

	i2c_del_adapter(&i2c_cnx->adapter);
	platform_set_drvdata(pdev, NULL);

	/* setup chip registers to defaults, i2c disable */
	writel(0, i2c_cnx->base + SSP_TWI0_INTR_EN_OFFSET);
	writel(0, i2c_cnx->base + SSP_TWI0_CFG_OFFSET);

	opv5xc_disable_peri(OPV5XC_PERI_TWI);

	return 0;
}

static struct platform_driver i2c_opv5xc_driver = {
	.probe = i2c_opv5xc_probe,
	.remove = i2c_opv5xc_remove,
	.driver = {
		   .name = DRIVER_NAME,
		   .owner = THIS_MODULE,
		   },
	.suspend = i2c_opv5xc_suspend,
	.resume = i2c_opv5xc_resume,
};

module_platform_driver(i2c_opv5xc_driver);

MODULE_AUTHOR("Open-Silicon");
MODULE_DESCRIPTION("I2C adapter driver for OPV5XC I2C bus");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:" DRIVER_NAME);
