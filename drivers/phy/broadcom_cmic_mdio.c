/*
 * Copyright (C) 2015 Broadcom Corporation
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

#include <linux/kernel.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/phy/cmic_mdio.h>

/* get Base address from device tree */

#define CMIC_MIIM_PARAM_BASE			0
#define CMIC_MIIM_PARAM__MIIM_CYCLE_L		31
#define CMIC_MIIM_PARAM__MIIM_CYCLE_R		29
#define CMIC_MIIM_PARAM__MIIM_CYCLE_WIDTH	3
#define CMIC_MIIM_PARAM__MIIM_CYCLE_RESETVALUE	0x0
#define CMIC_MIIM_PARAM__INTERNAL_SEL		25
#define CMIC_MIIM_PARAM__INTERNAL_SEL_WIDTH	1
#define CMIC_MIIM_PARAM__INTERNAL_SEL_L		25
#define CMIC_MIIM_PARAM__INTERNAL_SEL_R		25
#define CMIC_MIIM_PARAM__INTERNAL_SEL_RESETVALUE 0x0
#define CMIC_MIIM_PARAM__BUS_ID_L		24
#define CMIC_MIIM_PARAM__BUS_ID_R		22
#define CMIC_MIIM_PARAM__BUS_ID_WIDTH		3
#define CMIC_MIIM_PARAM__BUS_ID_RESETVALUE	0x0
#define CMIC_MIIM_PARAM__C45_SEL		21
#define CMIC_MIIM_PARAM__C45_SEL_WIDTH		1
#define CMIC_MIIM_PARAM__C45_SEL_L		21
#define CMIC_MIIM_PARAM__C45_SEL_R		21
#define CMIC_MIIM_PARAM__C45_SEL_RESETVALUE	0x0
#define CMIC_MIIM_PARAM__PHY_ID_L		20
#define CMIC_MIIM_PARAM__PHY_ID_R		16
#define CMIC_MIIM_PARAM__PHY_ID_WIDTH		5
#define CMIC_MIIM_PARAM__PHY_ID_RESETVALUE	0x0
#define CMIC_MIIM_PARAM__PHY_DATA_L		15
#define CMIC_MIIM_PARAM__PHY_DATA_R		0
#define CMIC_MIIM_PARAM__PHY_DATA_WIDTH		16
#define CMIC_MIIM_PARAM__PHY_DATA_RESETVALUE	0x0000
#define CMIC_MIIM_PARAM__RESERVED_L		28
#define CMIC_MIIM_PARAM__RESERVED_R		26
#define CMIC_MIIM_PARAM_WIDTH			32
#define CMIC_MIIM_PARAM__WIDTH			32
#define CMIC_MIIM_PARAM_ALL_L			31
#define CMIC_MIIM_PARAM_ALL_R			0
#define CMIC_MIIM_PARAM__ALL_L			31
#define CMIC_MIIM_PARAM__ALL_R			0
#define CMIC_MIIM_PARAM_DATAMASK		0xe3ffffff
#define CMIC_MIIM_PARAM_READMASK		0x00000000
#define CMIC_MIIM_PARAM_RDWRMASK		0x1c000000
#define CMIC_MIIM_PARAM_RESETVALUE		0x00000000

#define CMIC_MIIM_READ_DATA_BASE		0x4
#define CMIC_MIIM_READ_DATA__DATA_L		15
#define CMIC_MIIM_READ_DATA__DATA_R		0
#define CMIC_MIIM_READ_DATA__DATA_WIDTH		16
#define CMIC_MIIM_READ_DATA__DATA_RESETVALUE	0x0000
#define CMIC_MIIM_READ_DATA__RESERVED_L		31
#define CMIC_MIIM_READ_DATA__RESERVED_R		16
#define CMIC_MIIM_READ_DATA_WIDTH		16
#define CMIC_MIIM_READ_DATA__WIDTH		16
#define CMIC_MIIM_READ_DATA_ALL_L		15
#define CMIC_MIIM_READ_DATA_ALL_R		0
#define CMIC_MIIM_READ_DATA__ALL_L		15
#define CMIC_MIIM_READ_DATA__ALL_R		0
#define CMIC_MIIM_READ_DATA_DATAMASK		0x0000ffff
#define CMIC_MIIM_READ_DATA_READMASK		0x0000ffff
#define CMIC_MIIM_READ_DATA_RDWRMASK		0xffff0000
#define CMIC_MIIM_READ_DATA_RESETVALUE		0x0000

#define CMIC_MIIM_ADDRESS_BASE			0x8
#define CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_L	20
#define CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_R	16
#define CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_WIDTH 5
#define CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_RESETVALUE 0x0
#define CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_L	15
#define CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_R	0
#define CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_WIDTH 16
#define CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_RESETVALUE 0x0000
#define CMIC_MIIM_ADDRESS__RESERVED_L		31
#define CMIC_MIIM_ADDRESS__RESERVED_R		21
#define CMIC_MIIM_ADDRESS_WIDTH			21
#define CMIC_MIIM_ADDRESS__WIDTH		21
#define CMIC_MIIM_ADDRESS_ALL_L			20
#define CMIC_MIIM_ADDRESS_ALL_R			0
#define CMIC_MIIM_ADDRESS__ALL_L		20
#define CMIC_MIIM_ADDRESS__ALL_R		0
#define CMIC_MIIM_ADDRESS_DATAMASK		0x001fffff
#define CMIC_MIIM_ADDRESS_READMASK		0x00000000
#define CMIC_MIIM_ADDRESS_RDWRMASK		0xffe00000
#define CMIC_MIIM_ADDRESS_RESETVALUE		0x000000

#define CMIC_MIIM_CTRL_BASE			0xC
#define CMIC_MIIM_CTRL__MIIM_RD_START		1
#define CMIC_MIIM_CTRL__MIIM_RD_START_WIDTH	1
#define CMIC_MIIM_CTRL__MIIM_RD_START_L		1
#define CMIC_MIIM_CTRL__MIIM_RD_START_R		1
#define CMIC_MIIM_CTRL__MIIM_RD_START_RESETVALUE 0x0
#define CMIC_MIIM_CTRL__MIIM_WR_START		0
#define CMIC_MIIM_CTRL__MIIM_WR_START_WIDTH	1
#define CMIC_MIIM_CTRL__MIIM_WR_START_L		0
#define CMIC_MIIM_CTRL__MIIM_WR_START_R		0
#define CMIC_MIIM_CTRL__MIIM_WR_START_RESETVALUE 0x0
#define CMIC_MIIM_CTRL__RESERVED_L		31
#define CMIC_MIIM_CTRL__RESERVED_R		2
#define CMIC_MIIM_CTRL_WIDTH			2
#define CMIC_MIIM_CTRL__WIDTH			2
#define CMIC_MIIM_CTRL_ALL_L			1
#define CMIC_MIIM_CTRL_ALL_R			0
#define CMIC_MIIM_CTRL__ALL_L			1
#define CMIC_MIIM_CTRL__ALL_R			0
#define CMIC_MIIM_CTRL_DATAMASK			0x00000003
#define CMIC_MIIM_CTRL_READMASK			0x00000000
#define CMIC_MIIM_CTRL_RDWRMASK			0xfffffffc
#define CMIC_MIIM_CTRL_RESETVALUE		0x0

#define CMIC_MIIM_STAT_BASE			0x10
#define CMIC_MIIM_STAT__MIIM_OPN_DONE		0
#define CMIC_MIIM_STAT__MIIM_OPN_DONE_WIDTH	1
#define CMIC_MIIM_STAT__MIIM_OPN_DONE_L		0
#define CMIC_MIIM_STAT__MIIM_OPN_DONE_R		0
#define CMIC_MIIM_STAT__MIIM_OPN_DONE_RESETVALUE 0x0
#define CMIC_MIIM_STAT__RESERVED_L		31
#define CMIC_MIIM_STAT__RESERVED_R		1
#define CMIC_MIIM_STAT_WIDTH			1
#define CMIC_MIIM_STAT__WIDTH			1
#define CMIC_MIIM_STAT_ALL_L			0
#define CMIC_MIIM_STAT_ALL_R			0
#define CMIC_MIIM_STAT__ALL_L			0
#define CMIC_MIIM_STAT__ALL_R			0
#define CMIC_MIIM_STAT_DATAMASK			0x00000001
#define CMIC_MIIM_STAT_READMASK			0x00000001
#define CMIC_MIIM_STAT_RDWRMASK			0xfffffffe
#define CMIC_MIIM_STAT_RESETVALUE		0x0

#define MIIM_PARAM_REG  CMIC_MIIM_PARAM_BASE
#define MIIM_PARAM__MIIM_CYCLE_SHIFT	CMIC_MIIM_PARAM__MIIM_CYCLE_R
#define MIIM_PARAM__MIIM_CYCLE_MASK\
	((1 << CMIC_MIIM_PARAM__MIIM_CYCLE_WIDTH) - 1)
#define MIIM_PARAM__INTERNAL_SEL_SHIFT CMIC_MIIM_PARAM__INTERNAL_SEL
#define MIIM_PARAM__INTERNAL_SEL_MASK\
	((1 << CMIC_MIIM_PARAM__INTERNAL_SEL_WIDTH) - 1)
#define MIIM_PARAM__BUS_ID_SHIFT CMIC_MIIM_PARAM__BUS_ID_R
#define MIIM_PARAM__BUS_ID_MASK\
	((1 << CMIC_MIIM_PARAM__BUS_ID_WIDTH) - 1)
#define MIIM_PARAM__C45_SEL_SHIFT	CMIC_MIIM_PARAM__C45_SEL
#define MIIM_PARAM__C45_SEL_MASK\
	((1 << CMIC_MIIM_PARAM__INTERNAL_SEL_WIDTH) - 1)
#define MIIM_PARAM__PHY_ID_SHIFT CMIC_MIIM_PARAM__PHY_ID_R
#define MIIM_PARAM__PHY_ID_MASK\
	((1 << CMIC_MIIM_PARAM__PHY_ID_WIDTH) - 1)
#define MIIM_PARAM__PHY_DATA_SHIFT CMIC_MIIM_PARAM__PHY_DATA_R
#define MIIM_PARAM__PHY_DATA_MASK\
	((1 << CMIC_MIIM_PARAM__PHY_DATA_WIDTH) - 1)

#define MIIM_READ_DATA_REG		CMIC_MIIM_READ_DATA_BASE

#define MIIM_READ_DATA__DATA_SHIFT	CMIC_MIIM_READ_DATA__DATA_R
#define MIIM_READ_DATA__DATA_MASK\
	((1 << CMIC_MIIM_READ_DATA__DATA_WIDTH) - 1)
#define MIIM_ADDRESS_REG		CMIC_MIIM_ADDRESS_BASE
#define MIIM_ADDRESS__CLAUSE_45_DTYPE_SHIFT CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_R
#define MIIM_ADDRESS__CLAUSE_45_DTYPE_MASK\
	((1 << CMIC_MIIM_ADDRESS__CLAUSE_45_DTYPE_WIDTH) - 1)

#define MIIM_ADDRESS__CLAUSE_45_REGADR_SHIFT\
	CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_R
#define MIIM_ADDRESS__CLAUSE_45_REGADR_MASK\
	((1 << CMIC_MIIM_ADDRESS__CLAUSE_45_REGADR_WIDTH) - 1)
#define MIIM_ADDRESS__CLAUSE_22_REGADR_SHIFT	0
#define MIIM_ADDRESS__CLAUSE_22_REGADR_MASK	(0x1F)

#define MIIM_CTRL_REG			CMIC_MIIM_CTRL_BASE
#define MIIM_CTRL__MIIM_RD_START_SHIFT  CMIC_MIIM_CTRL__MIIM_RD_START
#define MIIM_CTRL__MIIM_RD_START_MASK\
	((1 << CMIC_MIIM_CTRL__MIIM_RD_START_WIDTH) - 1)
#define MIIM_CTRL__MIIM_WR_START_SHIFT CMIC_MIIM_CTRL__MIIM_WR_START
#define MIIM_CTRL__MIIM_WR_START_MASK\
	((1 << CMIC_MIIM_CTRL__MIIM_WR_START_WIDTH) - 1)

#define MIIM_STAT_REG			CMIC_MIIM_STAT_BASE
#define MIIM_STAT__MIIM_OPN_DONE_SHIFT CMIC_MIIM_STAT__MIIM_OPN_DONE
#define MIIM_STAT__MIIM_OPN_DONE_MASK\
	((1 << CMIC_MIIM_STAT__MIIM_OPN_DONE_WIDTH) - 1)

/* register bitops */
#define SET_REG_FIELD(reg_value, fshift, fmask, fvalue) (\
	(reg_value) = ((reg_value) & ~((fmask) << (fshift))) |  \
			(((fvalue) & (fmask)) << (fshift)))
#define ISET_REG_FIELD(reg_value, fshift, fmask, fvalue) (\
	(reg_value) = (reg_value) | (((fvalue) & (fmask)) << (fshift)))
#define GET_REG_FIELD(reg_value, fshift, fmask) (\
	(((reg_value) & ((fmask) << (fshift))) >> (fshift)))

#define MIIM_OP_MAX_HALT_USEC	500

enum {
	MIIM_OP_MODE_READ,
	MIIM_OP_MODE_WRITE,
	MIIM_OP_MODE_MAX
};

struct cmicd_miim_cmd {
	int bus_id;
	int int_sel;
	int phy_id;
	int regnum;
	int c45_sel;
	u16 op_mode;
	u16 val;		/* Bidirectional */
};

/**
 * struct cmic_mdio_dev - iProc MDC/MDIO device
 * @dev: pointer to device
 * @base: MDC controller register base pointer
 * @lock: mutex to protect access to the MDC device
 * @is_ready: flag to indicate the driver has been initialized and is ready for
 * use
 */
struct cmic_mdio_dev {
	struct device *dev;
	void __iomem *base;
	struct mutex lock;
	bool is_ready;
};

static struct cmic_mdio_dev cmic_mdio_dev;	/* single controller */

static inline void cmicd_miim_set_op_read(u32 *data, u32 set)
{
	SET_REG_FIELD(*data, MIIM_CTRL__MIIM_RD_START_SHIFT,
		      MIIM_CTRL__MIIM_RD_START_MASK, set);
}

static inline void cmicd_miim_set_op_write(u32 *data, u32 set)
{
	SET_REG_FIELD(*data, MIIM_CTRL__MIIM_WR_START_SHIFT,
		      MIIM_CTRL__MIIM_WR_START_MASK, set);
}

static inline int cmicd_miim_op_done_check(struct cmic_mdio_dev *cmic,
					   bool op_check)
{
	u32 op;
	int usec = MIIM_OP_MAX_HALT_USEC;

	do {
		op = GET_REG_FIELD(readl(cmic->base + MIIM_STAT_REG),
				   MIIM_STAT__MIIM_OPN_DONE_SHIFT,
				   MIIM_STAT__MIIM_OPN_DONE_MASK);
		if (op == op_check)
			break;

		udelay(1);
		usec--;
	} while (usec > 0);

	if ((op != op_check) || !usec) {
		dev_err(cmic->dev, "MIIM_STAT_REG error. op: %d op_check: %d\n",
			 op, op_check);
		return -ETIMEDOUT;
	}
	return op_check;
}

static inline int do_cmicd_miim_op(struct cmic_mdio_dev *cmic, u32 op,
				   u32 param, u32 addr, u16 *value)
{
	u32 val = 0;
	int ret = -ETIMEDOUT;

	if (op >= MIIM_OP_MODE_MAX) {
		dev_err(cmic->dev, "%s : invalid op code %d\n", __func__, op);
		return -EINVAL;
	}

	writel(val, cmic->base + MIIM_CTRL_REG);

	ret = cmicd_miim_op_done_check(cmic, 0);
	if (ret != 0) {
		dev_err(cmic->dev, "cmicd_miim_op_done_check for 0 failed\n");
		goto err;
	}

	writel(param, cmic->base + MIIM_PARAM_REG);
	/* MDIO is a slow bus. Give some time to complete the operation */
	udelay(100);
	writel(addr, cmic->base + MIIM_ADDRESS_REG);
	/* MDIO is a slow bus. Give some time to complete the operation */
	udelay(100);

	val = readl(cmic->base + MIIM_CTRL_REG);

	if (op == MIIM_OP_MODE_READ)
		cmicd_miim_set_op_read(&val, 1);
	else
		cmicd_miim_set_op_write(&val, 1);

	writel(val, cmic->base + MIIM_CTRL_REG);

	ret = cmicd_miim_op_done_check(cmic, 1);
	if (ret != 1) {
		dev_err(cmic->dev, "cmicd_miim_op_done_check for 1 failed\n");
		goto err;
	}

	if (op == MIIM_OP_MODE_READ)
		*value = readl(cmic->base + MIIM_READ_DATA_REG);

	val = readl(cmic->base + MIIM_CTRL_REG);
	if (op == MIIM_OP_MODE_READ)
		cmicd_miim_set_op_read(&val, 0);
	else
		cmicd_miim_set_op_write(&val, 0);

	writel(val, cmic->base + MIIM_CTRL_REG);

	/* Success, ret = 0 */
	ret = cmicd_miim_op_done_check(cmic, 0);
	if (ret != 0) {
		dev_err(cmic->dev, "cmicd_miim_op_done_check for 0 failed\n");
		goto err;
	}

err:
	return ret;
}

static int cmicd_miim_op(struct cmic_mdio_dev *cmic, struct cmicd_miim_cmd *cmd)
{
	u32 miim_param = 0, miim_addr = 0;

	ISET_REG_FIELD(miim_param, MIIM_PARAM__BUS_ID_SHIFT,
		       MIIM_PARAM__BUS_ID_MASK, cmd->bus_id);

	if (cmd->int_sel)
		ISET_REG_FIELD(miim_param, MIIM_PARAM__INTERNAL_SEL_SHIFT,
			       MIIM_PARAM__INTERNAL_SEL_MASK, 1);

	ISET_REG_FIELD(miim_param, MIIM_PARAM__PHY_ID_SHIFT,
		       MIIM_PARAM__PHY_ID_MASK, cmd->phy_id);

	if (cmd->op_mode == MIIM_OP_MODE_WRITE)
		ISET_REG_FIELD(miim_param, MIIM_PARAM__PHY_DATA_SHIFT,
			       MIIM_PARAM__PHY_DATA_MASK, cmd->val);

	if (cmd->c45_sel) {
		ISET_REG_FIELD(miim_param, MIIM_PARAM__C45_SEL_SHIFT,
			       MIIM_PARAM__C45_SEL_MASK, 1);

		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_45_REGADR_SHIFT,
			       MIIM_ADDRESS__CLAUSE_45_REGADR_MASK,
			       cmd->regnum);
		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_45_DTYPE_SHIFT,
			       MIIM_ADDRESS__CLAUSE_45_REGADR_MASK,
			       cmd->regnum >> 16);
	} else {
		ISET_REG_FIELD(miim_addr, MIIM_ADDRESS__CLAUSE_22_REGADR_SHIFT,
			       MIIM_ADDRESS__CLAUSE_22_REGADR_MASK,
			       cmd->regnum);
	}

	return do_cmicd_miim_op(cmic, cmd->op_mode, miim_param, miim_addr,
				&cmd->val);
}

/**
 * cmic_mdio_read() - read from a PHY register through the MDC interface
 *
 * @ext:
 * @claus:
 * @phyadr: MDC PHY address
 * @reg: PHY register address
 * @val: pointer to the memory where data will be stored
 */
u16 cmic_mdio_read(u32 ext, u32 claus, u32 busid, u32 phyadr, u32 reg, u16 *val)
{
	int ret;
	struct cmic_mdio_dev *mdio = &cmic_mdio_dev;
	struct cmicd_miim_cmd cmd = { 0 };

	if (!mdio->is_ready)
		return -ENODEV;

	cmd.bus_id = busid;
	cmd.phy_id = phyadr;
	cmd.regnum = reg;
	cmd.val = 0;

	if (ext == EXTERNAL)
		cmd.int_sel = 0;
	else
		cmd.int_sel = 1;

	if (claus == CLAUS22)
		cmd.c45_sel = 0;
	else
		cmd.c45_sel = 1;

	cmd.op_mode = MIIM_OP_MODE_READ;

	mutex_lock(&mdio->lock);
	ret = cmicd_miim_op(mdio, &cmd);
	mutex_unlock(&mdio->lock);

	*val = cmd.val;

	if (ret)
		dev_err(mdio->dev, "mdio write failed\n");

	return ret;
}
EXPORT_SYMBOL(cmic_mdio_read);

/**
 * cmic_mdio_write() - write to a PHY register through the MDC interface
 *
 * @ext:
 * @claus:
 * @phyadr: MDC PHY address
 * @reg: PHY register address
 * @val: data value to be written to the PHY register
 */
int cmic_mdio_write(u32 ext, u32 claus, u32 busid, u32 phyadr, u32 reg, u16 val)
{
	int ret;
	struct cmic_mdio_dev *mdio = &cmic_mdio_dev;
	struct cmicd_miim_cmd cmd = { 0 };

	if (!mdio->is_ready)
		return -ENODEV;

	cmd.bus_id = busid;
	cmd.phy_id = phyadr;
	cmd.regnum = reg;

	if (ext == EXTERNAL)
		cmd.int_sel = 0;
	else
		cmd.int_sel = 1;

	if (claus == CLAUS22)
		cmd.c45_sel = 0;
	else
		cmd.c45_sel = 1;

	cmd.op_mode = MIIM_OP_MODE_WRITE;
	cmd.val = val;

	mutex_lock(&mdio->lock);
	ret = cmicd_miim_op(mdio, &cmd);
	mutex_unlock(&mdio->lock);

	if (ret)
		dev_err(mdio->dev, "mdio write failed\n");

	return ret;
}
EXPORT_SYMBOL(cmic_mdio_write);

static int cmic_mdio_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct cmic_mdio_dev *mdio = &cmic_mdio_dev;
	struct resource *res;

	dev_dbg(dev, "Broadcom cmic miim mdio controller probe!\n");

	mdio->dev = dev;
	mutex_init(&mdio->lock);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mdio->base = devm_ioremap_resource(dev, res);
	if (IS_ERR(mdio->base))
		return PTR_ERR(mdio->base);

	dev_dbg(dev, "mdio mapped base address:0x%p\n", mdio->base);

	mdio->is_ready = true;

	return 0;
}

static const struct of_device_id cmic_mdio_match_table[] = {
	{.compatible = "brcm,cmic-mdio"},
	{}
};

static struct platform_driver cmic_mdio_driver = {
	.driver = {
		   .name = "cmic-mdio",
		   .of_match_table = cmic_mdio_match_table,
		   .suppress_bind_attrs = true,
		   },
	.probe = cmic_mdio_probe,
};

static int __init cmic_mdio_init(void)
{
	pr_info("Registering CMIC MDIO controller driver\n");
	return platform_driver_register(&cmic_mdio_driver);
}

arch_initcall_sync(cmic_mdio_init);

MODULE_AUTHOR("Broadcom Corporation");
MODULE_DESCRIPTION("Broadcom CMIC MDC/MDIO driver");
MODULE_LICENSE("GPL v2");
