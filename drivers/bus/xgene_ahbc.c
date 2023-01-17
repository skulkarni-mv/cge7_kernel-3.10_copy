/*
 * AppliedMicro X-Gene AHBC Driver
 *
 * Copyright (c) 2013, Applied Micro Circuits Corporation
 * Author: Loc Ho <lho@apm.com>
 * Author: Feng Kan <fkan@apm.com>
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
 */
#include <linux/module.h>
#include <linux/io.h>
#include <linux/of_platform.h>
#include <linux/of_address.h>
#include <linux/memblock.h>
#include <linux/delay.h>
#include <linux/acpi.h>
#include <linux/efi.h>

#define AHBC_DRIVER_VER			"0.1"

/* Mapper CSR Address */
#define AIM_8_SIZE_CTL_ADDR		0x00000104
#define AIM_8_AXI_LO_ADDR		0x00000108
#define AIM_8_AXI_HI_ADDR		0x0000010c

#define ARSB_F8_WR(src)			(((u32)(src)<<23) & 0x03800000)
#define AWSB_F8_WR(src)			(((u32)(src)<<20) & 0x00700000)
#define AIM_AXI_ADDRESS_LO_8_WR(src)	(((u32)(src)) & 0x000fffff)

/* Diagnostic Address */
#define REGSPEC_AHBC_GLBL_DIAG_CSR_I_BASE_ADDR	0x01f2ad000ULL
#define REGSPEC_CFG_MEM_RAM_SHUTDOWN_ADDR	0x00000070
#define REGSPEC_BLOCK_MEM_RDY_ADDR		0x00000074

/* Slave CSR Address */
#define CFG_AMA_MODE_ADDR			0x0000e014
#define  CFG_RD2WR_EN				0x00000002

static struct xgene_ahbc_context {
	void *ahbc_base;		/* AHBC CSR base */
	void *ahbc_io_base;		/* AHBC IO base */
} xgene_ahbc_ctx = { NULL, NULL };

static int xgene_ahbc_iobe = 1;		/* Enable IOB flush feature */
MODULE_PARM_DESC(iobe, "Enable IOB flush feature (1=enable 0=disable)");
module_param_named(iobe, xgene_ahbc_iobe, int, 0444);

static void xgene_ahbc_write(void *base, u32 offset, u32 val)
{
	if (base == NULL)
		return;
	writel_relaxed(val, base + offset);
}

static u32 xgene_ahbc_read(void *base, u32 offset)
{
	if (base == NULL)
		return 0;
	return readl_relaxed(base + offset);
}

static void xgene_ahbc_init_mem(struct platform_device *pdev)
{
	struct xgene_ahbc_context *ctx = platform_get_drvdata(pdev);
	void *ahbc_base = ctx->ahbc_base;
	u32 diag_offset = REGSPEC_AHBC_GLBL_DIAG_CSR_I_BASE_ADDR & 0xFFFF;
	void *diagcsr_base = ahbc_base + diag_offset;
	int timeout;
	u32 val;

	if (ahbc_base == NULL)
		return;

	if (xgene_ahbc_read(diagcsr_base,
		REGSPEC_CFG_MEM_RAM_SHUTDOWN_ADDR) == 0)
		return;

	dev_dbg(&pdev->dev, "AHBC clear memory shutdown\n");
	xgene_ahbc_write(diagcsr_base, REGSPEC_CFG_MEM_RAM_SHUTDOWN_ADDR, 0x00);
	xgene_ahbc_read(diagcsr_base, REGSPEC_CFG_MEM_RAM_SHUTDOWN_ADDR);

	timeout = 5000;
	do {
		val = xgene_ahbc_read(diagcsr_base, REGSPEC_BLOCK_MEM_RDY_ADDR);
		if (val != 0xFFFFFFFF)
			udelay(1);
	} while (val != 0xFFFFFFFF && timeout-- > 0);
	if (timeout <= 0)
		dev_err(&pdev->dev, "AHBC failed to remove RAM out of reset\n");
}

static int xgene_ahbc_hw_init(struct platform_device *pdev)
{
	struct xgene_ahbc_context *ctx = platform_get_drvdata(pdev);
	void *ahbc_base = ctx->ahbc_base;
	phys_addr_t ddr_phy;
	u32 val;

	/**
	 * Set AHBC AIM windows for 4GB regardless of DDR size. This
	 * must map to Kernel memory space.
	 */
	ddr_phy = memblock_start_of_DRAM();
	dev_dbg(&pdev->dev, "Setup AHBC AIM windows DDR 0x%llX\n", ddr_phy);
	xgene_ahbc_write(ahbc_base, AIM_8_SIZE_CTL_ADDR, 0x00000000);
	xgene_ahbc_write(ahbc_base, AIM_8_AXI_LO_ADDR,
			ARSB_F8_WR(1) | AWSB_F8_WR(1) |
			AIM_AXI_ADDRESS_LO_8_WR((u32) ddr_phy));
	xgene_ahbc_write(ahbc_base, AIM_8_AXI_HI_ADDR,
			(u32) ((ddr_phy >> 32) << 20));

	/* Configure IOB flush if enabled */
	val = xgene_ahbc_read(ahbc_base, CFG_AMA_MODE_ADDR);
	if (xgene_ahbc_iobe)
		val |= CFG_RD2WR_EN;
	else
		val &= ~CFG_RD2WR_EN;
	xgene_ahbc_write(ahbc_base, CFG_AMA_MODE_ADDR, val);
	dev_dbg(&pdev->dev, "Setup AHBC IOB flush 0x%08X\n", val);

	return 0;
}

/* Flush all IOB pending transaction
 *
 * This function can be used to flush all transaction on the IOB bus.
 */
int xgene_ahbc_iob_flush(void)
{
	if (xgene_ahbc_iobe && xgene_ahbc_ctx.ahbc_io_base != NULL)
		xgene_ahbc_read(xgene_ahbc_ctx.ahbc_io_base, 0x00);
	return 0;
}
EXPORT_SYMBOL(xgene_ahbc_iob_flush);

static int xgene_ahbc_get_resource(struct platform_device *pdev, int index,
	struct resource *res)
{
#ifdef CONFIG_ACPI
	struct resource *regs;
	if (efi_enabled(EFI_BOOT)) {
		regs = platform_get_resource(pdev, IORESOURCE_MEM, index);
		if (regs == NULL)
			return -ENODEV;
		*res = *regs;
		return 0;
	}
#endif
	return of_address_to_resource(pdev->dev.of_node, index, res);
}

static int __init xgene_ahbc_probe(struct platform_device *pdev)
{
	struct resource res;
	int rc;

#if defined(CONFIG_ACPI)
	/* Skip the ACPI probe if booting via DTS */
	if (!efi_enabled(EFI_BOOT) && pdev->dev.of_node == NULL)
		return -ENODEV;
#endif
	rc = xgene_ahbc_get_resource(pdev, 0, &res);
	if (rc != 0) {
		dev_err(&pdev->dev, "invalid AHBC resource address\n");
		return -ENODEV;
	}
	xgene_ahbc_ctx.ahbc_base = ioremap(res.start, resource_size(&res));
	if (xgene_ahbc_ctx.ahbc_base == NULL) {
		dev_err(&pdev->dev, "can not map resource\n");
		return -ENODEV;
	}

	rc = xgene_ahbc_get_resource(pdev, 1, &res);
	if (rc != 0) {
		dev_err(&pdev->dev, "invalid AHBC IO resource address\n");
		return -ENODEV;
	}
	xgene_ahbc_ctx.ahbc_io_base = ioremap(res.start, resource_size(&res));
	if (xgene_ahbc_ctx.ahbc_io_base == NULL) {
		iounmap(xgene_ahbc_ctx.ahbc_base);
		dev_err(&pdev->dev, "can not map resource\n");
		return -ENODEV;
	}

	platform_set_drvdata(pdev, &xgene_ahbc_ctx);

	/* Initialize the hardware */
	xgene_ahbc_init_mem(pdev);
	xgene_ahbc_hw_init(pdev);

	dev_info(&pdev->dev, "AHBC driver v%s\n", AHBC_DRIVER_VER);

	return 0;
}

static int xgene_ahbc_remove(struct platform_device *pdev)
{
	struct xgene_ahbc_context *ctx = platform_get_drvdata(pdev);

	iounmap(ctx->ahbc_base);
	iounmap(ctx->ahbc_io_base);
	platform_set_drvdata(pdev, NULL);
	return 0;
}

#if defined(CONFIG_PM)
static int xgene_ahbc_suspend(struct platform_device *dev, pm_message_t state)
{
	/* Nothing to do here */
	return 0;
}

static int xgene_ahbc_resume(struct platform_device *pdev)
{
	/* Initialize the hardware */
	xgene_ahbc_init_mem(pdev);
	xgene_ahbc_hw_init(pdev);
	return 0;
}
#endif

static const struct of_device_id xgene_ahbc_match[] = {
	{.compatible = "apm,xgene-ahbc" },
	{},
};
MODULE_DEVICE_TABLE(of, xgene_ahbc_match);

#ifdef CONFIG_ACPI
static const struct acpi_device_id xgene_ahbc_acpi_ids[] = {
        { "APMC0D06", 0 },
        { }
};
MODULE_DEVICE_TABLE(acpi, xgene_ahbc_acpi_ids);
#endif

static struct platform_driver ahbc_driver = {
	.probe = xgene_ahbc_probe,
	.remove = xgene_ahbc_remove,
#if defined(CONFIG_PM)
	.suspend = xgene_ahbc_suspend,
	.resume = xgene_ahbc_resume,
#endif
	.driver = {
		.name = "xgene-ahbc",
		.owner = THIS_MODULE,
		.of_match_table = xgene_ahbc_match,
#ifdef CONFIG_ACPI
		.acpi_match_table = ACPI_PTR(xgene_ahbc_acpi_ids),
#endif
	},
};

static int __init xgene_ahbc_init(void)
{
	return platform_driver_register(&ahbc_driver);
}
subsys_initcall(xgene_ahbc_init);

static void __exit xgene_ahbc_exit(void)
{
	platform_driver_unregister(&ahbc_driver);
}
module_exit(xgene_ahbc_exit);

MODULE_AUTHOR("Loc Ho <lho@apm.com>");
MODULE_DESCRIPTION("X-Gene AHBC driver");
MODULE_LICENSE("GPL");
