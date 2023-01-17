/*
 * Copyright (C) 2014 Broadcom Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation version 2.
 *
 * This program is distributed "as is" WITHOUT ANY WARRANTY of any
 * kind, whether express or implied; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/delay.h>
#include <linux/i2c.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of_i2c.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

#define CFG_OFFSET                   0x00
#define CFG_RESET_SHIFT              31
#define CFG_EN_SHIFT                 30
#define CFG_M_BITBANGEN_SHIFT        29
#define CFG_M_RETRY_CNT_SHIFT        16
#define CFG_M_RETRY_CNT_MASK         0x0f

#define TIM_CFG_OFFSET               0x04
#define TIM_CFG_MODE_400_SHIFT       31

#define TIM_CFG_2_OFFSET             0xb0

#define M_FIFO_CTRL_OFFSET           0x0c
#define M_FIFO_RX_FLUSH_SHIFT        31
#define M_FIFO_TX_FLUSH_SHIFT        30
#define M_FIFO_RX_CNT_SHIFT          16
#define M_FIFO_RX_CNT_MASK           0x7f
#define M_FIFO_RX_THLD_SHIFT         8
#define M_FIFO_RX_THLD_MASK          0x3f

#define M_BITBANG_CTRL_OFFSET        0x14
#define M_BITBANG_SBM_CLKOUT_EN	     30
#define M_BITBANG_SMB_DATAIN_EN      29
#define M_BITBANG_SMB_DATAOUT_EN     28

#define M_CMD_OFFSET                 0x30
#define M_CMD_START_BUSY_SHIFT       31
#define M_CMD_STATUS_SHIFT           25
#define M_CMD_STATUS_MASK            0x07
#define M_CMD_STATUS_SUCCESS         0x0
#define M_CMD_STATUS_LOST_ARB        0x1
#define M_CMD_STATUS_NACK_ADDR       0x2
#define M_CMD_STATUS_NACK_DATA       0x3
#define M_CMD_STATUS_TIMEOUT         0x4
#define M_CMD_PROTOCOL_SHIFT         9
#define M_CMD_PROTOCOL_MASK          0xf
#define M_CMD_PROTOCOL_BLK_WR        0x7
#define M_CMD_PROTOCOL_BLK_RD        0x8
#define M_CMD_PEC_SHIFT              8
#define M_CMD_RD_CNT_SHIFT           0
#define M_CMD_RD_CNT_MASK            0xff

#define IE_OFFSET                    0x38
#define IE_M_RX_FIFO_FULL_SHIFT      31
#define IE_M_RX_THLD_SHIFT           30
#define IE_M_START_BUSY_SHIFT        28

#define IS_OFFSET                    0x3c
#define IS_M_RX_FIFO_FULL_SHIFT      31
#define IS_M_RX_THLD_SHIFT           30
#define IS_M_START_BUSY_SHIFT        28

#define M_TX_OFFSET                  0x40
#define M_TX_WR_STATUS_SHIFT         31
#define M_TX_DATA_SHIFT              0
#define M_TX_DATA_MASK               0xff

#define M_RX_OFFSET                  0x44
#define M_RX_STATUS_SHIFT            30
#define M_RX_STATUS_MASK             0x03
#define M_RX_PEC_ERR_SHIFT           29
#define M_RX_DATA_SHIFT              0
#define M_RX_DATA_MASK               0xff

#define I2C_TIMEOUT_MESC             100
#define M_TX_RX_FIFO_SIZE            64

enum bus_speed_index {
	I2C_SPD_100K = 0,
	I2C_SPD_400K,
};

struct bcm_iproc_i2c_dev {
	struct device *device;
	int irq;

	void __iomem *base;

	struct i2c_adapter adapter;

	struct completion done;
	int xfer_is_done;
};

static int bcm_iproc_i2c_cfg_speed(struct bcm_iproc_i2c_dev *iproc_i2c);

static void iproc_smbus_block_init(struct bcm_iproc_i2c_dev *iproc_i2c)
{

	unsigned int regval;

	/* Flush Tx, Rx FIFOs. Note we are setting the Rx FIFO threshold to 0.
	 * May be OK since we are setting RX_EVENT and RX_FIFO_FULL interrupts
	 */
	regval = BIT(M_FIFO_RX_FLUSH_SHIFT) | BIT(M_FIFO_TX_FLUSH_SHIFT);

	writel(regval, iproc_i2c->base + M_FIFO_CTRL_OFFSET);

	/* Enable SMbus block. Note, we are setting MASTER_RETRY_COUNT to zero
	 * since there will be only one master
	 */
	regval = BIT(CFG_EN_SHIFT);

	writel(regval, iproc_i2c->base + CFG_OFFSET);

	/* Wait a minimum of 50 Usec, as per SMB hw doc. But we wait longer */
	udelay(100);


	/* Set default clock frequency */
	bcm_iproc_i2c_cfg_speed(iproc_i2c);

	/* Disable intrs */
	regval = 0x0;
	writel(regval, iproc_i2c->base + IE_OFFSET);

	/* Clear intrs (W1TC) */
	regval = readl(iproc_i2c->base + IS_OFFSET);

	writel(regval, iproc_i2c->base + IS_OFFSET);
}

/*
 * Function to ensure that the previous transaction was completed before
 * initiating a new transaction. It can also be used in polling mode to
 * check status of completion of a command
 */
static int iproc_smb_startbusy_wait(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	u32 regval;

	regval = readl(iproc_i2c->base + M_CMD_OFFSET);

	/* Check if an operation is in progress. During probe it won't be.
	 * But when shutdown/remove was called we want to make sure that
	 * the transaction in progress completed
	 */
	if (regval & BIT(M_CMD_START_BUSY_SHIFT)) {
		unsigned int i = 0;

		do {

			udelay(1000); /* Wait for 1 msec */

			i++;

			regval = readl(iproc_i2c->base + M_CMD_OFFSET);

			/* If start-busy bit cleared, exit the loop */
		} while ((regval & BIT(M_CMD_START_BUSY_SHIFT)) && (i < 35));

		if (i >= 35) {
			dev_dbg(iproc_i2c->device,
				"%s: %s START_BUSY bit didn't clear, exiting\n",
				__func__, iproc_i2c->adapter.name);
			return -ETIMEDOUT;

		}

	}

	return 0;
}


static unsigned int smbus0_sda_recovery_count,
	smbus0_sda_failed_count, smbus0_start_busy_count;
static unsigned int smbus1_sda_recovery_count,
	smbus1_sda_failed_count, smbus1_start_busy_count;

/*
 * Function to recover SMB hangs caused stuck master START_BUSY.
 *   Returns  0 if recovery procedure executed successfully.
 *   Returns -1 if recovery failed.
 */
static void iproc_smb_startbusy_recovery(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	unsigned int recovery_count;

	if (iproc_i2c->adapter.nr == 0)
		recovery_count = ++smbus0_start_busy_count;
	else
		recovery_count = ++smbus1_start_busy_count;

	dev_err(iproc_i2c->device, "%s: %s START_BUSY recovery #%d\n",
		__func__, iproc_i2c->adapter.name, recovery_count);

	/* reset the SMBus block, wait a minimum of 50 uSecs and
	 * then re-initialize
	 */
	writel(BIT(CFG_RESET_SHIFT), iproc_i2c->base + CFG_OFFSET);
	udelay(60);

	iproc_smbus_block_init(iproc_i2c);
}

/*
 * Function to recover SMB hang caused by a slave device holding SDA low.
 *   Returns  0 if recovery procedure executed successfully.
 *   Returns -1 if recovery failed.
 */

static int iproc_smb_sda_low_recovery(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	unsigned int bbReg, cfgReg, cfgSave, recovery_count, failedCnt, i;
	int rc = -ETIMEDOUT;


	/* enable bit-bang */
	cfgSave = readl(iproc_i2c->base + CFG_OFFSET);
	cfgReg  = cfgSave;
	cfgReg |= BIT(CFG_M_BITBANGEN_SHIFT);
	writel(cfgReg, iproc_i2c->base + CFG_OFFSET);
	udelay(50);

	/* start with clock and SDA set high */
	bbReg  = readl(iproc_i2c->base + M_BITBANG_CTRL_OFFSET);

	bbReg |= (BIT(M_BITBANG_SBM_CLKOUT_EN) | BIT(M_BITBANG_SMB_DATAOUT_EN));
	writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	udelay(5);   /* should be sufficient for 100 KHz bus */

	/* set up to toggle the clock line with SDA out held high
	 * for 9 cycles
	 */
	for (i = 0; i < 18; i++) {
		/* toggle CLK out */
		if ((bbReg & BIT(M_BITBANG_SBM_CLKOUT_EN)) == 0) {
			/* set clock high */
			bbReg |= BIT(M_BITBANG_SBM_CLKOUT_EN);
		} else {
			/* set clock low  */
			bbReg &= ~BIT(M_BITBANG_SBM_CLKOUT_EN);
		}

		writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
		udelay(5);
	}

	/* check bit 29 -- SMBDAT_IN and make sure SDA not being
	 * held low any more
	 */
	for (i = 0; i < 10; i++) {
		bbReg  = readl(iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
		bbReg &= BIT(M_BITBANG_SMB_DATAIN_EN);

		if (bbReg)
			break;

		udelay(1);
	}

	if (bbReg == 0) {
		/* SDA is still low */
		if (iproc_i2c->adapter.nr == 0)
			failedCnt = ++smbus0_sda_failed_count;
		else
			failedCnt = ++smbus1_sda_failed_count;
		dev_err(iproc_i2c->device, "\n%s: %s SDA release #%d FAILED.\n",
			__func__, iproc_i2c->adapter.name, failedCnt);
	} else {
		if (iproc_i2c->adapter.nr == 0)
			recovery_count = ++smbus0_sda_recovery_count;
		else
			recovery_count = ++smbus1_sda_recovery_count;

		dev_err(iproc_i2c->device, "%s: %s SDA release #%d SUCCESSFUL.\n",
			__func__, iproc_i2c->adapter.name, recovery_count);
		rc = 0;
	}


	/* manually issue a stop by transitioning SDA from low
	 * to high with clock held high
	 */
	bbReg  = readl(iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	bbReg &= ~BIT(M_BITBANG_SBM_CLKOUT_EN);		/* set clock low */
	writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	udelay(2);

	bbReg &= ~BIT(M_BITBANG_SMB_DATAOUT_EN);	/* drop SDA low */
	writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	udelay(2);

	bbReg |= BIT(M_BITBANG_SBM_CLKOUT_EN);		/* set clock high */
	writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	udelay(5);

	bbReg |= BIT(M_BITBANG_SMB_DATAOUT_EN);		/* pull SDA high */
	writel(bbReg, iproc_i2c->base + M_BITBANG_CTRL_OFFSET);
	udelay(2);


	/* disable bit-bang and then re-enable the SMB
	 * with the saved configuration
	 */
	cfgReg  = readl(iproc_i2c->base + CFG_OFFSET);
	cfgReg &= ~BIT(CFG_M_BITBANGEN_SHIFT);
	writel(cfgReg, iproc_i2c->base + CFG_OFFSET);
	udelay(10);

	writel(cfgSave, iproc_i2c->base + CFG_OFFSET);

	return rc;
}


/*
 * Function to recover SMB hang caused by a slave device hold SDA low.
 *   Returns  0 if recovery procedure executed successfully.
 *   Returns -1 if recovery failed.
 */
static int iproc_smb_timeout_recovery(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	unsigned int bbReg, mCmdReg;
	int rc = -ETIMEDOUT;

	/* read bit-bang control.  If SDA low, attempt SDA release recovery */
	bbReg = readl(iproc_i2c->base + M_BITBANG_CTRL_OFFSET);

	if ((bbReg & BIT(M_BITBANG_SMB_DATAIN_EN)) == 0) {
		if (iproc_smb_sda_low_recovery(iproc_i2c) == 0)
			rc = 0;
	}

	/* regardless of whether there was an SDA hang or not,
	 * see if START_BUSY stuck high
	 */
	mCmdReg = readl(iproc_i2c->base + M_CMD_OFFSET);
	if (mCmdReg & BIT(M_CMD_START_BUSY_SHIFT)) {
		/* attempt to recover the bus */
		iproc_smb_startbusy_recovery(iproc_i2c);
		rc = 0;
	}

	return rc;

}

/*
 * Can be expanded in the future if more interrupt status bits are utilized
 */
#define ISR_MASK (1 << IS_M_START_BUSY_SHIFT)

static irqreturn_t bcm_iproc_i2c_isr(int irq, void *data)
{
	struct bcm_iproc_i2c_dev *iproc_i2c = data;
	u32 status = readl(iproc_i2c->base + IS_OFFSET);

	status &= ISR_MASK;

	if (!status)
		return IRQ_NONE;

	writel(status, iproc_i2c->base + IS_OFFSET);
	iproc_i2c->xfer_is_done = 1;
	complete_all(&iproc_i2c->done);

	return IRQ_HANDLED;
}

static int bcm_iproc_i2c_check_status(struct bcm_iproc_i2c_dev *iproc_i2c,
				      struct i2c_msg *msg)
{
	u32 val;

	val = readl(iproc_i2c->base + M_CMD_OFFSET);
	val = (val >> M_CMD_STATUS_SHIFT) & M_CMD_STATUS_MASK;

	switch (val) {
	case M_CMD_STATUS_SUCCESS:
		return 0;

	case M_CMD_STATUS_LOST_ARB:
		dev_err(iproc_i2c->device, "lost bus arbitration\n");
		return -EAGAIN;

	case M_CMD_STATUS_NACK_ADDR:
		dev_dbg(iproc_i2c->device, "NAK addr:0x%02x\n", msg->addr);
		return -ENXIO;

	case M_CMD_STATUS_NACK_DATA:
		dev_err(iproc_i2c->device, "NAK data\n");
		return -ENXIO;

	case M_CMD_STATUS_TIMEOUT:
		dev_err(iproc_i2c->device, "bus timeout\n");
		return -ETIMEDOUT;

	default:
		dev_err(iproc_i2c->device, "unknown error code=%d\n", val);
		return -EIO;
	}
}

static int bcm_iproc_i2c_xfer_single_msg(struct bcm_iproc_i2c_dev *iproc_i2c,
		struct i2c_msg *msg)
{
	int ret, i;
	u8 addr;
	u32 val;
	unsigned long time_left = msecs_to_jiffies(I2C_TIMEOUT_MESC);

	/* need to reserve one byte in the FIFO for the slave address */
	if (msg->len > M_TX_RX_FIFO_SIZE - 1) {
		dev_err(iproc_i2c->device,
			"only support data length up to %u bytes\n",
			M_TX_RX_FIFO_SIZE - 1);
		return -EOPNOTSUPP;
	}

	/* check if bus is busy */
	ret = iproc_smb_startbusy_wait(iproc_i2c);
	if (ret < 0) {
		if (!(msg->flags & I2C_M_RD)) {
			dev_dbg(iproc_i2c->device,
				"%s: Send: %s bus is busy, attempt recovery\n",
				__func__, iproc_i2c->adapter.name);

			iproc_smb_startbusy_recovery(iproc_i2c);
		}
	}

	/* format and load slave address into the TX FIFO */
	addr = msg->addr << 1 | (msg->flags & I2C_M_RD ? 1 : 0);
	writel(addr, iproc_i2c->base + M_TX_OFFSET);

	/* for a write transaction, load data into the TX FIFO */
	if (!(msg->flags & I2C_M_RD)) {
		for (i = 0; i < msg->len; i++) {
			val = msg->buf[i];

			/* mark the last byte */
			if (i == msg->len - 1)
				val |= 1 << M_TX_WR_STATUS_SHIFT;

			writel(val, iproc_i2c->base + M_TX_OFFSET);
		}
	}

	/* mark as incomplete before starting the transaction */
	INIT_COMPLETION(iproc_i2c->done);
	iproc_i2c->xfer_is_done = 0;

	/*
	 * Enable the "start busy" interrupt, which will be triggered after the
	 * transaction is done, i.e., the internal start_busy bit, transitions
	 * from 1 to 0.
	 */
	writel(1 << IE_M_START_BUSY_SHIFT, iproc_i2c->base + IE_OFFSET);

	/*
	 * Now we can activate the transfer. For a read operation, specify the
	 * number of bytes to read
	 */
	val = 1 << M_CMD_START_BUSY_SHIFT;
	if (msg->flags & I2C_M_RD) {
		val |= (M_CMD_PROTOCOL_BLK_RD << M_CMD_PROTOCOL_SHIFT) |
			(msg->len << M_CMD_RD_CNT_SHIFT);
	} else {
		val |= (M_CMD_PROTOCOL_BLK_WR << M_CMD_PROTOCOL_SHIFT);
	}
	writel(val, iproc_i2c->base + M_CMD_OFFSET);

	time_left = wait_for_completion_timeout(&iproc_i2c->done, time_left);

	/* disable all interrupts */
	writel(0, iproc_i2c->base + IE_OFFSET);
	/* read it back to flush the write */
	readl(iproc_i2c->base + IE_OFFSET);

	/* make sure the interrupt handler isn't running */
	synchronize_irq(iproc_i2c->irq);

	if (!time_left && !iproc_i2c->xfer_is_done) {
		dev_err(iproc_i2c->device, "transaction timed out\n");

		/* If the recovery succeeded after an initial failure
		 * return -ECOMM so the caller will know to try again.
		 */
		ret = iproc_smb_timeout_recovery(iproc_i2c);
		if (ret != 0)
			return -ETIMEDOUT;
		else
			return -ECOMM;
	}

	ret = bcm_iproc_i2c_check_status(iproc_i2c, msg);
	if (ret) {
		/* flush both TX/RX FIFOs */
		val = (1 << M_FIFO_RX_FLUSH_SHIFT) |
			(1 << M_FIFO_TX_FLUSH_SHIFT);
		writel(val, iproc_i2c->base + M_FIFO_CTRL_OFFSET);
		return ret;
	}

	/*
	 * For a read operation, we now need to load the data from FIFO
	 * into the memory buffer
	 */
	if (msg->flags & I2C_M_RD) {
		for (i = 0; i < msg->len; i++) {
			msg->buf[i] = (readl(iproc_i2c->base + M_RX_OFFSET) >>
					M_RX_DATA_SHIFT) & M_RX_DATA_MASK;
		}
	}

	return 0;
}

static int bcm_iproc_i2c_xfer(struct i2c_adapter *adapter,
			      struct i2c_msg msgs[], int num)
{
	struct bcm_iproc_i2c_dev *iproc_i2c = i2c_get_adapdata(adapter);
	int ret, i;

	/* go through all messages */
	for (i = 0; i < num; i++) {
		ret = bcm_iproc_i2c_xfer_single_msg(iproc_i2c, &msgs[i]);
		if (ret == -ECOMM) {
			ret = bcm_iproc_i2c_xfer_single_msg(iproc_i2c,
				&msgs[i]);
		}
		if (ret) {
			dev_dbg(iproc_i2c->device, "xfer failed\n");
			return ret;
		}
	}

	return num;
}

static uint32_t bcm_iproc_i2c_functionality(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm bcm_iproc_algo = {
	.master_xfer = bcm_iproc_i2c_xfer,
	.functionality = bcm_iproc_i2c_functionality,
};

static int bcm_iproc_i2c_cfg_speed(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	unsigned int bus_speed;
	u32 val;
	u32 timing_config_2;
	int ret = of_property_read_u32(iproc_i2c->device->of_node,
				       "clock-frequency", &bus_speed);
	if (ret < 0) {
		dev_info(iproc_i2c->device,
			"unable to interpret clock-frequency DT property\n");
		bus_speed = 100000;
	}

	if (bus_speed < 100000) {
		dev_err(iproc_i2c->device, "%d Hz bus speed not supported\n",
			bus_speed);
		dev_err(iproc_i2c->device,
			"valid speeds are 100khz and 400khz\n");
		return -EINVAL;
	} else if (bus_speed < 400000) {
		bus_speed = 100000;
	} else {
		bus_speed = 400000;
	}

	val = readl(iproc_i2c->base + TIM_CFG_OFFSET);
	val &= ~(1 << TIM_CFG_MODE_400_SHIFT);
	val |= (bus_speed == 400000) << TIM_CFG_MODE_400_SHIFT;
	writel(val, iproc_i2c->base + TIM_CFG_OFFSET);

	/*
	 * If selected write the timing high and low values in the
	 * Timing Control 2 register. This will adjust the clock
	 * frequency.
	 */
	ret = of_property_read_u32(iproc_i2c->device->of_node,
				   "timing_config_2", &timing_config_2);
	if (!ret) {
		val = readl(iproc_i2c->base + TIM_CFG_2_OFFSET);
		val &= ~0xffff;
		val |= timing_config_2;
		writel(val, iproc_i2c->base + TIM_CFG_2_OFFSET);
	}

	dev_info(iproc_i2c->device, "bus set to %u Hz\n", bus_speed);

	return 0;
}

static int bcm_iproc_i2c_init(struct bcm_iproc_i2c_dev *iproc_i2c)
{
	u32 val;

	/* put controller in reset */
	val = readl(iproc_i2c->base + CFG_OFFSET);
	val |= 1 << CFG_RESET_SHIFT;
	val &= ~(1 << CFG_EN_SHIFT);
	writel(val, iproc_i2c->base + CFG_OFFSET);

	/* wait 100 usec per spec */
	udelay(100);

	/* bring controller out of reset */
	val &= ~(1 << CFG_RESET_SHIFT);
	writel(val, iproc_i2c->base + CFG_OFFSET);

	/* flush TX/RX FIFOs and set RX FIFO threshold to zero */
	val = (1 << M_FIFO_RX_FLUSH_SHIFT) | (1 << M_FIFO_TX_FLUSH_SHIFT);
	writel(val, iproc_i2c->base + M_FIFO_CTRL_OFFSET);

	/* disable all interrupts */
	writel(0, iproc_i2c->base + IE_OFFSET);

	/* clear all pending interrupts */
	writel(0xffffffff, iproc_i2c->base + IS_OFFSET);

	return 0;
}

static void bcm_iproc_i2c_enable_disable(struct bcm_iproc_i2c_dev *iproc_i2c,
					 bool enable)
{
	u32 val;

	val = readl(iproc_i2c->base + CFG_OFFSET);
	if (enable)
		val |= BIT(CFG_EN_SHIFT);
	else
		val &= ~BIT(CFG_EN_SHIFT);
	writel(val, iproc_i2c->base + CFG_OFFSET);
}

static int bcm_iproc_i2c_probe(struct platform_device *pdev)
{
	int irq, ret = 0;
	struct bcm_iproc_i2c_dev *iproc_i2c;
	struct i2c_adapter *adap;
	struct resource *res;

	iproc_i2c = devm_kzalloc(&pdev->dev, sizeof(*iproc_i2c),
				 GFP_KERNEL);
	if (!iproc_i2c)
		return -ENOMEM;

	platform_set_drvdata(pdev, iproc_i2c);
	iproc_i2c->device = &pdev->dev;
	init_completion(&iproc_i2c->done);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	iproc_i2c->base = devm_ioremap_resource(iproc_i2c->device, res);
	if (IS_ERR(iproc_i2c->base))
		return PTR_ERR(iproc_i2c->base);

	ret = bcm_iproc_i2c_init(iproc_i2c);
	if (ret)
		return ret;

	ret = bcm_iproc_i2c_cfg_speed(iproc_i2c);
	if (ret)
		return ret;

	irq = platform_get_irq(pdev, 0);
	if (irq <= 0) {
		dev_err(iproc_i2c->device, "no irq resource\n");
		return irq;
	}
	iproc_i2c->irq = irq;

	ret = devm_request_irq(iproc_i2c->device, irq, bcm_iproc_i2c_isr, 0,
			       pdev->name, iproc_i2c);
	if (ret < 0) {
		dev_err(iproc_i2c->device, "unable to request irq %i\n", irq);
		return ret;
	}

	bcm_iproc_i2c_enable_disable(iproc_i2c, true);

	adap = &iproc_i2c->adapter;
	i2c_set_adapdata(adap, iproc_i2c);
	strlcpy(adap->name, "Broadcom iProc I2C adapter", sizeof(adap->name));
	adap->algo = &bcm_iproc_algo;
	adap->dev.parent = &pdev->dev;
	adap->dev.of_node = pdev->dev.of_node;

	ret = i2c_add_adapter(adap);
	if (ret) {
		dev_err(iproc_i2c->device, "failed to add adapter\n");
		return ret;
	}

	of_i2c_register_devices(adap);

	dev_info(iproc_i2c->device, "device registered successfully\n");

	smbus0_sda_recovery_count = 0;
	smbus0_sda_failed_count = 0;
	smbus0_start_busy_count = 0;
	smbus1_sda_recovery_count = 0;
	smbus1_sda_failed_count = 0;
	smbus1_start_busy_count = 0;

	return 0;
}

static int bcm_iproc_i2c_remove(struct platform_device *pdev)
{
	struct bcm_iproc_i2c_dev *iproc_i2c = platform_get_drvdata(pdev);

	/* make sure there's no pending interrupt when we remove the adapter */
	writel(0, iproc_i2c->base + IE_OFFSET);
	readl(iproc_i2c->base + IE_OFFSET);
	synchronize_irq(iproc_i2c->irq);

	i2c_del_adapter(&iproc_i2c->adapter);
	bcm_iproc_i2c_enable_disable(iproc_i2c, false);

	return 0;
}

static const struct of_device_id bcm_iproc_i2c_of_match[] = {
	{ .compatible = "brcm,iproc-i2c" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, bcm_iproc_i2c_of_match);

static struct platform_driver bcm_iproc_i2c_driver = {
	.driver = {
		   .name = "bcm-iproc-i2c",
		   .of_match_table = bcm_iproc_i2c_of_match,
		   },
	.probe = bcm_iproc_i2c_probe,
	.remove = bcm_iproc_i2c_remove,
};
module_platform_driver(bcm_iproc_i2c_driver);

MODULE_AUTHOR("Ray Jui <rjui@broadcom.com>");
MODULE_DESCRIPTION("Broadcom iProc I2C Driver");
MODULE_LICENSE("GPL v2");
