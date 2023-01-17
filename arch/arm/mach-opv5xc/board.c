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
#include <linux/platform_device.h>
#include <linux/serial_8250.h>
#include <linux/i2c.h>
#include <linux/dma-mapping.h>
#include <linux/mtd/denali_nand.h>
#include <linux/mmc/host.h>
#include <linux/spi/spi.h>
#include <linux/spi/flash.h>
#include <linux/mtd/mtd.h>
#include <linux/mtd/partitions.h>

#include <linux/proc_fs.h>
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include <asm/mach-types.h>
#include <asm/mach/arch.h>
#include <asm/mach/map.h>
#include <asm/mach/time.h>
#include <linux/irqchip/arm-gic.h>
#include <asm/setup.h>
#include <mach/opv5xc.h>
#include <mach/motherboard.h>
#include <mach/clkdev.h>
#include <mach/pse.h>
#include <mach/dma.h>
#include <mach/dw_mmc.h>
#include <mach/ixc.h>

#if defined(CONFIG_USB_OPV5XC_ACP)
static void opv5xc_usb_acp_init(void);
#endif /* defined(CONFIG_USB_OPV5XC_ACP) */

extern void opv5xc_timer_init(void);
extern struct smp_operations opv5xc_smp_ops;

/* UART */
static struct plat_serial8250_port opv5xc_uart_platform_data[] = {
	{
		.mapbase	= OPV5XC_CR_UART0_BASE,
		.irq		= IRQ_OPV5XC_UART0,
		.flags		= UPF_FIXED_TYPE | UPF_BOOT_AUTOCONF |
				  UPF_IOREMAP,
		.iotype		= UPIO_MEM32,
		.regshift	= 2,
		.uartclk	= 1843200,
		.type		= PORT_16550A,
	},
#if defined(CONFIG_SERIAL_8250_NR_UARTS) && CONFIG_SERIAL_8250_NR_UARTS >= 2
	{
		.mapbase	= OPV5XC_CR_UART1_BASE,
		.irq		= IRQ_OPV5XC_UART1,
		.flags		= UPF_FIXED_TYPE | UPF_BOOT_AUTOCONF |
				  UPF_IOREMAP,
		.iotype		= UPIO_MEM32,
		.regshift	= 2,
		.uartclk	= 1843200,
		.type		= PORT_16550A,
	},
#endif
#if defined(CONFIG_SERIAL_8250_NR_UARTS) && CONFIG_SERIAL_8250_NR_UARTS >= 3
	{
		.mapbase	= OPV5XC_CR_UART2_BASE,
		.irq		= IRQ_OPV5XC_UART2,
		.flags		= UPF_FIXED_TYPE | UPF_BOOT_AUTOCONF |
				  UPF_IOREMAP,
		.iotype		= UPIO_MEM32,
		.regshift	= 2,
		.uartclk	= 1843200,
		.type		= PORT_16550A,
	},
#endif
	{},
};

static struct platform_device opv5xc_serial_device = {
	.name	= "serial8250",
	.id	= PLAT8250_DEV_PLATFORM,
	.dev	= {
		.platform_data	= opv5xc_uart_platform_data,
	},
};

/* USB 3.0 DRD device mode */
#if defined(CONFIG_USB_DWC3) || defined(CONFIG_USB_DWC3_MODULE)
static struct resource opv5xc_usb_dwc3_resources[] = {
	[0] = {
                .start = OPV5XC_S_USB3DRD_BASE,
                .end   = OPV5XC_S_USB3DRD_BASE + SZ_1M - 1,
                .flags = IORESOURCE_MEM,
        },
        [1] = {
                .start = IRQ_OPV5XC_USB3_DRDOTG,
                .flags = IORESOURCE_IRQ,
        },
};

static u64 opv5xc_usb_dwc3_dma_mask = DMA_BIT_MASK(32);
static struct platform_device opv5xc_usb_dwc3_device = {
        .name          = "dwc3-opv5xc",
        .num_resources = ARRAY_SIZE(opv5xc_usb_dwc3_resources),
        .resource      = opv5xc_usb_dwc3_resources,
        .dev           = {
                .dma_mask          = &opv5xc_usb_dwc3_dma_mask,
                .coherent_dma_mask = DMA_BIT_MASK(32),
#ifdef CONFIG_USB_OPV5XC_ACP
		.archdata = {
			.dma_ops = &arm_coherent_dma_ops,
		},
#endif
        },
};
#endif

/* USB 3.0 DRD host mode */
#if defined(CONFIG_USB_OPV5XC_DRD_XHCI) || defined(CONFIG_USB_OPV5XC_DRD_XHCI_MODULE)
static struct resource opv5xc_usb_drd_xhci_resources[] = {
        [0] = {
                .start = OPV5XC_S_USB3DRD_BASE,
                .end   = OPV5XC_S_USB3DRD_BASE + SZ_1M - 1,
                .flags = IORESOURCE_MEM,
        },
        [1] = {
                .start = IRQ_OPV5XC_USB3_DRDOTG,
                .flags = IORESOURCE_IRQ,
        },
};

static u64 opv5xc_usb_drd_xhci_dma_mask = DMA_BIT_MASK(32);
static struct platform_device opv5xc_usb_drd_xhci_device = {
        .name          = "opv5xc-drd-xhci",
        .num_resources = ARRAY_SIZE(opv5xc_usb_drd_xhci_resources),
        .resource      = opv5xc_usb_drd_xhci_resources,
        .dev           = {
                .dma_mask          = &opv5xc_usb_drd_xhci_dma_mask,
                .coherent_dma_mask = DMA_BIT_MASK(32),
#ifdef CONFIG_USB_OPV5XC_ACP
		.archdata = {
			.dma_ops = &arm_coherent_dma_ops,
		},
#endif
        },
};
#endif

/* USB 3.0 host mode */
#if defined(CONFIG_USB_OPV5XC_XHCI)
static struct resource opv5xc_usb_xhci_resources[] = {
        [0] = {
                .start = OPV5XC_S_USB3H_BASE,
                .end   = OPV5XC_S_USB3H_BASE + SZ_1M - 1,
                .flags = IORESOURCE_MEM,
        },
        [1] = {
                .start = IRQ_OPV5XC_USB3_XHCI,
                .flags = IORESOURCE_IRQ,
        },
};

static u64 opv5xc_usb_xhci_dma_mask = DMA_BIT_MASK(32);
static struct platform_device opv5xc_usb_xhci_device = {
        .name          = "opv5xc-xhci",
        .num_resources = ARRAY_SIZE(opv5xc_usb_xhci_resources),
        .resource      = opv5xc_usb_xhci_resources,
        .dev           = {
                .dma_mask          = &opv5xc_usb_xhci_dma_mask,
                .coherent_dma_mask = DMA_BIT_MASK(32),
#ifdef CONFIG_USB_OPV5XC_ACP
		.archdata = {
			.dma_ops = &arm_coherent_dma_ops,
		},
#endif
        },
};
#endif

/* SPI */
#if defined(CONFIG_SPI_OPV5XC) || defined(CONFIG_SPI_OPV5XC_MODULE)
static struct mtd_partition spi_nor_partitions[] = {
	{
		.name		= "uboot",
		.offset		= 0,
		.size		= 0x80000,
		.mask_flags	= MTD_WRITEABLE, /* force read-only */
	},
	{
		.name		= "ubootenv",
		.offset		= 0x80000,
		.size		= 0x10000,
	},
	{
		.name		= "uimage",
		.offset		= 0x90000,
		.size		= 0x400000,
	},
	{
		.name		= "user",
		.offset		= 0x490000,
		.size		= MTDPART_SIZ_FULL,
	}
};

static struct flash_platform_data spi_flash_data = {
	.name = "spi-nor",
	.parts		= spi_nor_partitions,
	.nr_parts	= ARRAY_SIZE(spi_nor_partitions),
};

static struct spi_board_info spi_board_info[] __initdata = {
	[0] = {
		.modalias	= "nor-jedec",
		.max_speed_hz	= 50 * 1000 * 1000,
		.bus_num	= 1,
		.chip_select	= 0,
		.mode		= SPI_MODE_0,
		.platform_data	= &spi_flash_data,
	},
};

static struct resource opv5xc_spi_resource[] = {
	[0] = {
		.start	= OPV5XC_CR_SPI_BASE,
		.end	= OPV5XC_CR_SPI_BASE + SZ_64,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= IRQ_OPV5XC_SPI,
		.end	= IRQ_OPV5XC_SPI,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device opv5xc_spi_device = {
	.name		= "spi-opv5xc",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(opv5xc_spi_resource),
	.resource	= opv5xc_spi_resource,
};

#endif

/* I2C */
#if defined(CONFIG_I2C_OPV5XC) || defined(CONFIG_I2C_OPV5XC_MODULE)
static struct i2c_board_info __initdata opv5xc_i2c0_devs[] = {
	{ I2C_BOARD_INFO("tlv320aic23", 0x1a), },
	{ I2C_BOARD_INFO("max6642", 0x4c), },
};

static struct resource opv5xc_i2c0_resource[] = {
	[0] = {
		.start	= OPV5XC_CR_I2C0_BASE + 0x20,
		.end	= OPV5XC_CR_I2C0_BASE + 0x40,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= IRQ_OPV5XC_I2C0,
		.end	= IRQ_OPV5XC_I2C0,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device opv5xc_i2c0_device = {
	.name		= "opv5xc-i2c",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(opv5xc_i2c0_resource),
	.resource	= opv5xc_i2c0_resource,
};

#ifndef CONFIG_ARCH_OPV5XC_CX4
static struct resource opv5xc_i2c1_resource[] = {
	[0] = {
		.start	= OPV5XC_CR_I2C1_BASE + 0x20,
		.end	= OPV5XC_CR_I2C1_BASE + 0x40,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start	= IRQ_OPV5XC_I2C1,
		.end	= IRQ_OPV5XC_I2C1,
		.flags	= IORESOURCE_IRQ,
	},
};

static struct platform_device opv5xc_i2c1_device = {
	.name		= "opv5xc-i2c",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(opv5xc_i2c1_resource),
	.resource	= opv5xc_i2c1_resource,
};
#endif
#endif /* CONFIG_I2C_OPV5XC */

#ifdef CONFIG_ARCH_OPV5XC_CX4
/* FPGA only provide 8 pins on GPIOA. Remove this in silicon */
#define IRQ_OPV5XC_GPIOA IRQ_OPV5XC_GPIO
#define IRQ_OPV5XC_GPIOB IRQ_OPV5XC_GPIO
#endif

/* GPIO */
static struct resource opv5xc_gpio_resources[] = {
	[0] = {
		.start = OPV5XC_CR_GPIOA_BASE,
		.end   = OPV5XC_CR_GPIOA_BASE + 0x7C,
		.flags = IORESOURCE_MEM,
		.name = "GPIOA",
	},
	[1] = {
		.start = OPV5XC_CR_GPIOB_BASE,
		.end   = OPV5XC_CR_GPIOB_BASE + 0x7C,
		.flags = IORESOURCE_MEM,
		.name = "GPIOB",
	},
	[2] = {
		.start = IRQ_OPV5XC_GPIOA,
		.end   = IRQ_OPV5XC_GPIOA,
		.flags = IORESOURCE_IRQ,
		.name = "GPIOA",
	},
	[3] = {
		.start = IRQ_OPV5XC_GPIOB,
		.end   = IRQ_OPV5XC_GPIOB,
		.flags = IORESOURCE_IRQ,
		.name = "GPIOB",
	},
};

static struct platform_device opv5xc_gpio_device = {
	.name		= "opv5xc-gpio",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(opv5xc_gpio_resources),
	.resource	= opv5xc_gpio_resources,
};

#if defined(CONFIG_OPV5XC_PSE) || defined(CONFIG_OPV5XC_PSE_MODULE)
static struct resource opv5xc_pse_resource[] = {
	[0] = {
		.start  = OPV5XC_CR_PSE_PPE_BASE,
		.end    = OPV5XC_CR_PSE_PPE_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = OPV5XC_S_CFP_BASE,
		.end    = OPV5XC_S_CFP_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[2] = {
#if defined(CONFIG_ARCH_OPV5XC_CX4)
		.start  = IRQ_OPV5XC_FS_DMA,
		.end    = IRQ_OPV5XC_PSE_STAT,
#else
		.start  = IRQ_OPV5XC_PSE_START,
		.end    = IRQ_OPV5XC_PPE_FS_DMA_C0,
#endif
		.flags  = IORESOURCE_IRQ,
	},
};

#ifndef CONFIG_ARCH_OPV5XC_CX4
#define PSE_GIGA
#endif

#ifdef PSE_GIGA
#define PSE_GIGA_MODE	(1)
#define PSE_SPEED	OPV5XC_PSE_SPEED_1000
#else
#define PSE_GIGA_MODE	(0)
#define PSE_SPEED	OPV5XC_PSE_SPEED_100
#endif

static struct pse_platform_data opv5xc_pse_pdata = {
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	.port[0] = {
		.sp = OPV5XC_PSE_PORT_MAC0,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 1,
		.txc_dly = 2,
		.rxc_dly = 2,
		.force_speed = PSE_SPEED,
		.force_duplex = OPV5XC_PSE_DUPLEX_FULL,
		.force_fc_tx = 1,
		.force_fc_rx = 1,
		.has_phy = 0,
		.phy_addr = 0,
	},
#if (1 < OPV5XC_MAC_MAX)
	.port[1] = {
		.sp = OPV5XC_PSE_PORT_MAC1,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 1,
		.txc_dly = 2,
		.rxc_dly = 2,
		.force_speed = PSE_SPEED,
		.force_duplex = OPV5XC_PSE_DUPLEX_FULL,
		.force_fc_tx = 1,
		.force_fc_rx = 1,
		.has_phy = 0,
		.phy_addr = 4,
	},
#endif /* #if (1 < OPV5XC_MAC_MAX) */
#if (2 < OPV5XC_MAC_MAX)
	.port[2] = {
		.sp = OPV5XC_PSE_PORT_MAC2,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 1,
		.txc_dly = 2,
		.rxc_dly = 2,
		.force_speed = PSE_SPEED,
		.force_duplex = OPV5XC_PSE_DUPLEX_FULL,
		.force_fc_tx = 1,
		.force_fc_rx = 1,
		.has_phy = 0,
		.phy_addr = 3,
	},
#endif /* #if (2 < OPV5XC_MAC_MAX) */
#else
	.port[0] = {
		.sp = OPV5XC_PSE_PORT_MAC0,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 1,
		.txc_dly = 1,
		.rxc_dly = 2,
		.has_phy = 0,
		.force_speed = PSE_SPEED,
		.force_duplex = OPV5XC_PSE_DUPLEX_FULL,
		.force_fc_tx = 1,
		.force_fc_rx = 1,
		.phy_addr = 0,
	},
#if (1 < OPV5XC_MAC_MAX)
	.port[1] = {
		.sp = OPV5XC_PSE_PORT_MAC1,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 0,
		.has_phy = 1,
		.phy_addr = 6,
	},
#endif /* #if (1 < OPV5XC_MAC_MAX) */
#if (2 < OPV5XC_MAC_MAX)
	.port[2] = {
		.sp = OPV5XC_PSE_PORT_MAC2,
		.enable = 1,
		.giga_mode = PSE_GIGA_MODE,
		.wan_port = 0,
		.rgmii = 1,
		.txc_dly = 2,
		.rxc_dly = 2,
		.force_speed = PSE_SPEED,
		.force_duplex = OPV5XC_PSE_DUPLEX_FULL,
		.force_fc_tx = 1,
		.force_fc_rx = 1,
		.has_phy = 0,
		.phy_addr = 4,
	},
#endif /* #if (2 < OPV5XC_MAC_MAX) */
#endif
};

struct platform_device opv5xc_device_pse = {
	.name		= "opv5xc-pse",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(opv5xc_pse_resource),
	.resource	= opv5xc_pse_resource,
	.dev		= {
		.platform_data	= &opv5xc_pse_pdata,
		.coherent_dma_mask =  DMA_BIT_MASK(32),
#ifdef CONFIG_OPV5XC_PSE_ACP_SUPPORT
		.archdata = {
			.dma_ops = &arm_coherent_dma_ops,
		},
#endif
	},
};
#endif /* if defined(CONFIG_OPV5XC_PSE) || defined(CONFIG_OPV5XC_PSE_MODULE) */

#if defined(CONFIG_MTD_NAND_DENALI_OPV5XC) || defined(CONFIG_MTD_NAND_DENALI_OPV5XC_MODULE)
/* NAND Flash Controller */
static struct resource opv5xc_denali_resource[] = {
	[0] = {
		.start  = OPV5XC_NFC_CMD_BASE,
		.end    = OPV5XC_NFC_CMD_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = OPV5XC_NFC_CR_BASE,
		.end    = OPV5XC_NFC_CR_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[2] = {
		.start  = IRQ_OPV5XC_NFC,
		.end    = IRQ_OPV5XC_NFC,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct denali_nand_platform_data opv5xc_denali_pdata = {
	.width		= 8,
};

static u64 opv5xc_denali_dmamask = DMA_BIT_MASK(32);
struct platform_device opv5xc_device_denali = {
	.name		= "denali_nand",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(opv5xc_denali_resource),
	.resource	= opv5xc_denali_resource,
	.dev		= {
		.dma_mask		= &opv5xc_denali_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data	= &opv5xc_denali_pdata,
	},
};
#endif /* defined(CONFIG_MTD_NAND_DENALI_OPV5XC) || defined(CONFIG_MTD_NAND_DENALI_OPV5XC_MODULE) */

#if defined(CONFIG_MMC_DW_OPV5XC) || defined(CONFIG_MMC_DW_OPV5XC_MODULE)
/* SD/MMC/SDIO Mass Storage Host Controller - MSHCI0 */
static void opv5xc_dwmci_select_slot(u32 slot_id)
{

}

static int opv5xc_dwmci_get_bus_wd(u32 slot_id)
{
	return 4;
}

static int opv5xc_dwmci_get_ocr(u32 slot_id)
{
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	return MMC_VDD_165_195 |
	    MMC_VDD_20_21 | MMC_VDD_21_22 | MMC_VDD_22_23 | MMC_VDD_23_24 | MMC_VDD_24_25 |
	    MMC_VDD_25_26 | MMC_VDD_26_27 | MMC_VDD_27_28 | MMC_VDD_28_29 | MMC_VDD_29_30 |
	    MMC_VDD_30_31 | MMC_VDD_31_32 | MMC_VDD_32_33 | MMC_VDD_33_34 | MMC_VDD_34_35 |
	    MMC_VDD_35_36;
#else
	return MMC_VDD_32_33 | MMC_VDD_33_34;
#endif
}

static int opv5xc_dwmci_init(u32 slot_id, irq_handler_t handler, void *data)
{
	return 0;
}

static struct resource opv5xc_dwmci_resource[] = {
	[0] = {
		.start  = OPV5XC_SDIO_BASE,
		.end    = OPV5XC_SDIO_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = IRQ_OPV5XC_SDIO,
		.end    = IRQ_OPV5XC_SDIO,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct dw_mci_board opv5xc_dwci_pdata = {
	.num_slots		= 1,
#if defined(CONFIG_ARCH_OPV5XC_ES1)
	.quirks			= DW_MCI_QUIRK_BROKEN_CARD_DETECTION | DW_MCI_QUIRK_INVERTED_WRITE_PROTECT | DW_MCI_QUIRK_HIGHSPEED,
	.bus_hz			= 100 * 1000 * 1000,
#elif defined(CONFIG_ARCH_OPV5XC_ES2)
	.quirks			= DW_MCI_QUIRK_BROKEN_CARD_DETECTION | DW_MCI_QUIRK_HIGHSPEED,
	.bus_hz			= 200 * 1000 * 1000,
#else
	.quirks			= DW_MCI_QUIRK_BROKEN_CARD_DETECTION,
	.bus_hz			= 25 * 1000 * 1000,
#endif
	.detect_delay_ms	= 400,
	.init			= opv5xc_dwmci_init,
	.get_ocr		= opv5xc_dwmci_get_ocr,
	.get_bus_wd		= opv5xc_dwmci_get_bus_wd,
	.select_slot		= opv5xc_dwmci_select_slot,
};

static u64 opv5xc_dwmci_dmamask = DMA_BIT_MASK(32);
struct platform_device opv5xc_device_dwmci0 = {
	.name		= "dw_mmc",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(opv5xc_dwmci_resource),
	.resource	= opv5xc_dwmci_resource,
	.dev		= {
		.dma_mask		= &opv5xc_dwmci_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data	= &opv5xc_dwci_pdata,
	},
};

void __init opv5xc_dwmci_set_platdata(struct dw_mci_board *pd)
{
	struct dw_mci_board *set = &opv5xc_dwci_pdata;

	if (!set->init)
		set->init = opv5xc_dwmci_init;
	if (!set->get_bus_wd)
		set->get_bus_wd = opv5xc_dwmci_get_bus_wd;
	if (!set->select_slot)
		set->select_slot = opv5xc_dwmci_select_slot;
}

/* MSHCI1 */
#ifdef CONFIG_ARCH_OPV5XC_CX4
static void opv5xc_dwmci1_select_slot(u32 slot_id)
{

}

static int opv5xc_dwmci1_get_bus_wd(u32 slot_id)
{
	return 4;
}

static int opv5xc_dwmci1_get_ocr(u32 slot_id)
{
	return MMC_VDD_32_33 | MMC_VDD_33_34;
}

static int opv5xc_dwmci1_init(u32 slot_id, irq_handler_t handler, void *data)
{
	return 0;
}

static struct resource opv5xc_dwmci1_resource[] = {
	[0] = {
		.start  = OPV5XC_SDIO1_BASE,
		.end    = OPV5XC_SDIO1_BASE  SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = IRQ_OPV5XC_SDIO1,
		.end    = IRQ_OPV5XC_SDIO1,
		.flags  = IORESOURCE_IRQ,
	},
};

static struct dw_mci_board opv5xc_dwci1_pdata = {
	.num_slots		= 1,
	.quirks			= DW_MCI_QUIRK_BROKEN_CARD_DETECTION,
	.bus_hz			= 25 * 1000 * 1000,
	.detect_delay_ms	= 400,
	.init			= opv5xc_dwmci1_init,
	.get_ocr		= opv5xc_dwmci1_get_ocr,
	.get_bus_wd		= opv5xc_dwmci1_get_bus_wd,
	.select_slot		= opv5xc_dwmci1_select_slot,
};

static u64 opv5xc_dwmci1_dmamask = DMA_BIT_MASK(32);
struct platform_device opv5xc_device_dwmci1 = {
	.name		= "dw_mmc",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(opv5xc_dwmci1_resource),
	.resource	= opv5xc_dwmci1_resource,
	.dev		= {
		.dma_mask		= &opv5xc_dwmci1_dmamask,
		.coherent_dma_mask	= DMA_BIT_MASK(32),
		.platform_data	= &opv5xc_dwci1_pdata,
	},
};

void __init opv5xc_dwmci1_set_platdata(struct dw_mci_board *pd)
{
	struct dw_mci_board *set = &opv5xc_dwci1_pdata;

	if (!set->init)
		set->init = opv5xc_dwmci1_init;
	if (!set->get_bus_wd)
		set->get_bus_wd = opv5xc_dwmci1_get_bus_wd;
	if (!set->select_slot)
		set->select_slot = opv5xc_dwmci1_select_slot;
}
#endif
#endif /* if defined(CONFIG_MMC_DW_OPV5XC) || defined(CONFIG_MMC_DW_OPV5XC_MODULE) */

#if defined(CONFIG_SND_SOC_OPV5XC_I2S) || defined(CONFIG_SND_SOC_OPV5XC_I2S_MODULE)
static struct resource opv5xc_i2s0_resource[] = {
	[0] = {
		.start  = OPV5XC_CR_I2S0_BASE,
		.end    = OPV5XC_CR_I2S0_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
	[1] = {
		.start  = OPV5XC_I2S_A_BASE,
		.end    = OPV5XC_I2S_A_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
};

static struct platform_device opv5xc_i2s0_device = {
	.name		= "opv5xc-i2s",
	.id		= 0,
	.num_resources	= ARRAY_SIZE(opv5xc_i2s0_resource),
	.resource	= opv5xc_i2s0_resource,
};

static struct resource opv5xc_i2s1_resource[] = {
	[0] = {
		.start	= OPV5XC_CR_I2S1_BASE,
		.end	= OPV5XC_CR_I2S1_BASE + SZ_4K - 1,
		.flags	= IORESOURCE_MEM,
	},
	[1] = {
		.start  = OPV5XC_I2S_B_BASE,
		.end    = OPV5XC_I2S_B_BASE + SZ_4K - 1,
		.flags  = IORESOURCE_MEM,
	},
};

static struct platform_device opv5xc_i2s1_device = {
	.name		= "opv5xc-i2s",
	.id		= 1,
	.num_resources	= ARRAY_SIZE(opv5xc_i2s1_resource),
	.resource	= opv5xc_i2s1_resource,
};

#if defined(CONFIG_SND_SOC_OPV5XC_TLV320AIC23) || defined(CONFIG_SND_SOC_OPV5XC_TLV320AIC23_MODULE)
static struct platform_device opv5xc_tlv320aic23_device = {
	.name   = "opv5xc-tlv320aic23",
};
#endif /* OPV5XC_TLV320AIC23 */

#endif /* OPV5XC_I2S */

#if defined(CONFIG_RTC_DRV_OPV5XC) || defined(CONFIG_RTC_DRV_OPV5XC_MODULE)
static struct resource opv5xc_rtc_resources[] = {
	[0] = {
		.start = OPV5XC_RTC_BASE,
		.end   = OPV5XC_RTC_BASE + PAGE_SIZE - 1,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		.start = IRQ_OPV5XC_RTC,
		.end   = IRQ_OPV5XC_RTC_BAT,
#else
		.start = IRQ_OPV5XC_RTC_BAT,
		.end   = IRQ_OPV5XC_RTC_CTL,
#endif
		.flags = IORESOURCE_IRQ,
	}
};

static struct platform_device opv5xc_rtc_device = {
	.name		= "opv5xc-rtc",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(opv5xc_rtc_resources),
	.resource	= opv5xc_rtc_resources,
};
#endif /* if defined(CONFIG_RTC_DRV_OPV5XC) || defined(CONFIG_RTC_DRV_OPV5XC_MODULE)*/

#ifdef CONFIG_OPV5XC_NITROX_CRYPTO_ENGINE
static struct resource opv5xc_nitrox_resources[] = {
	[0] = {
		.start = OPV5XC_CR_CRYPTO_BASE,
		.end   = OPV5XC_CR_CRYPTO_BASE + PAGE_SIZE - 1,
		.flags = IORESOURCE_MEM,
	},
	[1] = {
		.start = IRQ_OPV5XC_CRYPTO,
		.flags = IORESOURCE_IRQ,
	},
#ifdef CONFIG_OPV5XC_NITROX_WAY_TO_CONTROL_PMU
	[2] = {
		.start	= OPV5XC_CR_PMU_BASE,
		.end	= OPV5XC_CR_PMU_BASE + SZ_8K - 1,
		.flags	= IORESOURCE_MEM,
	},
#endif
};

static struct platform_device opv5xc_nitrox_device = {
	.name		= "nitrox",
	.id		= -1,
	.num_resources	= ARRAY_SIZE(opv5xc_nitrox_resources),
	.resource	= opv5xc_nitrox_resources,
	.dev		= {
		.coherent_dma_mask =  DMA_BIT_MASK(32),
#ifdef CONFIG_OPV5XC_NITROX_HAVE_CRYPTO_ACP
		.archdata = {
			.dma_ops = &arm_coherent_dma_ops,
		},
#endif
	},
};
#endif

static struct platform_device *opv5xc_pdevs[] __initdata = {
	&opv5xc_serial_device,
#if defined(CONFIG_USB_DWC3) || defined(CONFIG_USB_DWC3_MODULE)
        &opv5xc_usb_dwc3_device,
#endif
#if defined(CONFIG_USB_OPV5XC_DRD_XHCI) || defined(CONFIG_USB_OPV5XC_DRD_XHCI_MODULE)
        &opv5xc_usb_drd_xhci_device,
#endif
#if defined(CONFIG_USB_OPV5XC_XHCI)
        &opv5xc_usb_xhci_device,
#endif
#if defined(CONFIG_SPI_OPV5XC) || defined(CONFIG_SPI_OPV5XC_MODULE)
	&opv5xc_spi_device,
#endif
#if defined(CONFIG_I2C_OPV5XC) || defined(CONFIG_I2C_OPV5XC_MODULE)
	&opv5xc_i2c0_device,
#ifndef CONFIG_ARCH_OPV5XC_CX4
	&opv5xc_i2c1_device,
#endif
#endif
	&opv5xc_gpio_device,
#if defined(CONFIG_OPV5XC_PSE) || defined(CONFIG_OPV5XC_PSE_MODULE)
	&opv5xc_device_pse,
#endif
#if defined(CONFIG_MTD_NAND_DENALI_OPV5XC) || defined(CONFIG_MTD_NAND_DENALI_OPV5XC_MODULE)
	&opv5xc_device_denali,
#endif
#if defined(CONFIG_MMC_DW_OPV5XC) || defined(CONFIG_MMC_DW_OPV5XC_MODULE)
	&opv5xc_device_dwmci0,
#ifdef CONFIG_ARCH_OPV5XC_CX4
	&opv5xc_device_dwmci1,
#endif
#endif
#if defined(CONFIG_SND_SOC_OPV5XC_I2S) || defined(CONFIG_SND_SOC_OPV5XC_I2S_MODULE)
	&opv5xc_i2s0_device,
	&opv5xc_i2s1_device,
#if defined(CONFIG_SND_SOC_OPV5XC_TLV320AIC23) || defined(CONFIG_SND_SOC_OPV5XC_TLV320AIC23_MODULE)
	&opv5xc_tlv320aic23_device,
#endif
#endif
#if defined(CONFIG_RTC_DRV_OPV5XC) || defined(CONFIG_RTC_DRV_OPV5XC_MODULE)
	&opv5xc_rtc_device,
#endif
#ifdef CONFIG_OPV5XC_NITROX_CRYPTO_ENGINE
	&opv5xc_nitrox_device,
#endif
};

static struct map_desc opv5xc_io_desc[] __initdata = {
	{
		.virtual	= (unsigned long)OPV5XC_MISC_BASE_VIRT,
		.pfn		= __phys_to_pfn(OPV5XC_MISC_BASE),
		.length		= SZ_256K,
		.type		= MT_DEVICE,
	},
	{
		.virtual	= (unsigned long)OPV5XC_CR_UART0_BASE_VIRT,
		.pfn		= __phys_to_pfn(OPV5XC_CR_UART0_BASE),
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		.length		= SZ_8K,
#else
		.length		= SZ_256K,
#endif
		.type		= MT_DEVICE,
	},
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	{
		.virtual	= (unsigned long)OPV5XC_CR_PMU_BASE_VIRT,
		.pfn		= __phys_to_pfn(OPV5XC_CR_PMU_BASE),
		.length		= SZ_8K,
		.type		= MT_DEVICE,
	},
	{
		.virtual	= (unsigned long)OPV5XC_CR_IXC_BASE_VIRT,
		.pfn		= __phys_to_pfn(OPV5XC_CR_IXC_BASE),
		.length		= SZ_32,
		.type		= MT_DEVICE,
	},
#endif
};

/* */
extern struct ct_desc ct_ca9x4_desc;

struct ct_desc *ct_desc;

static struct ct_desc *ct_descs[] __initdata = {
	&ct_ca9x4_desc,
};

static void __init opv5xc_map_io(void)
{
	iotable_init(opv5xc_io_desc, ARRAY_SIZE(opv5xc_io_desc));
	ct_desc = ct_descs[0];
	ct_desc->map_io();
}

static void __init opv5xc_init_irq(void)
{
	ct_desc->init_irq();
}

#if defined(CONFIG_USB_OPV5XC_ACP)
static void opv5xc_usb_acp_init(void)
{
#if defined(CONFIG_USB_OPV5XC_DRD_XHCI) || defined(CONFIG_USB_OPV5XC_DRD_XHCI_MODULE)
        opv5xc_acp_enable(IXC_USB3DRD);
#endif /* defined(CONFIG_USB_OPV5XC_DRD_XHCI) or defined(CONFIG_USB_OPV5XC_DRD_XHCI_MODULE) */

#if defined(CONFIG_USB_OPV5XC_XHCI)
        opv5xc_acp_enable(IXC_USB3H);
#endif /* defined(CONFIG_USB_OPV5XC_XHCI) */
}
#endif /* defined(CONFIG_USB_OPV5XC_ACP) */

struct proc_dir_entry *opv5xc_proc_dir;
EXPORT_SYMBOL_GPL(opv5xc_proc_dir);
#ifdef CONFIG_DEBUG_FS
struct dentry *opv5xc_debugfs_dir;
EXPORT_SYMBOL_GPL(opv5xc_debugfs_dir);
#endif

static void __init opv5xc_init(void)
{
	u32 reg __maybe_unused;

#ifndef CONFIG_ARCH_OPV5XC_CX4
	opv5xc_clock_init();
#endif

#ifdef CONFIG_PL330_DMA
	opv5xc_gdma_init();
#endif

#if defined(CONFIG_USB_OPV5XC_ACP)
        opv5xc_usb_acp_init();
#endif /* defined(CONFIG_USB_OPV5XC_ACP) */

	platform_add_devices(opv5xc_pdevs, ARRAY_SIZE(opv5xc_pdevs));

#if defined(CONFIG_I2C_OPV5XC) || defined(CONFIG_I2C_OPV5XC_MODULE)
	i2c_register_board_info(0, opv5xc_i2c0_devs, ARRAY_SIZE(opv5xc_i2c0_devs));
#endif

#if defined(CONFIG_SPI_OPV5XC) || defined(CONFIG_SPI_OPV5XC_MODULE)
	spi_register_board_info(spi_board_info, ARRAY_SIZE(spi_board_info));
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* Disable direct SPI flash mapping */
	reg = readl(OPV5XC_MISC_BASE_VIRT + 0x04);
	reg &= ~(0x1 << 16);
	writel(reg, OPV5XC_MISC_BASE_VIRT + 0x04);
#endif
#endif

#ifdef CONFIG_DEBUG_FS
	opv5xc_debugfs_dir = debugfs_create_dir("opv5xc", NULL);
#endif
	opv5xc_proc_dir = proc_mkdir("opv5xc", NULL);

	ct_desc->init_tile();
}

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
void opv5xc_assert_system_reset(char mode, const char *cmd)
{
	u32 reg;

	reg = readl_relaxed(OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	reg &= ~(1 << 0);
	writel_relaxed(reg, OPV5XC_CR_PMU_BASE_VIRT + 0x04);
}
#endif

MACHINE_START(OPV5XC, "OPV5XC-CA9MP")
	.atag_offset	= 0x100,
	.smp		= smp_ops(opv5xc_smp_ops),
	.map_io		= opv5xc_map_io,
	.init_irq	= opv5xc_init_irq,
	.init_time	= opv5xc_timer_init,
	.init_machine	= opv5xc_init,
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	.restart	= opv5xc_assert_system_reset,
#endif
MACHINE_END
