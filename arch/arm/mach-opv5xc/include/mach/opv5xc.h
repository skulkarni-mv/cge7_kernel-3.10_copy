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

#ifndef _OPV5XC_SOC_H
#define _OPV5XC_SOC_H

#ifdef CONFIG_ARCH_OPV5XC_ES1

#define OPV5XC_PCIE_PORT_NR   2
#define OPV5XC_PCIE_DM_BASE		0x80000000
#define OPV5XC_S_PCIE_DM_MEM_BASE	(OPV5XC_PCIE_DM_BASE)			/* PCIe DM Memory Base */
#define OPV5XC_S_PCIE_DM_HOST_BASE	(OPV5XC_PCIE_DM_BASE + 0xB000000)	/* PCIe DM Host Base */
#define OPV5XC_S_PCIE_DM_IO_BASE	(OPV5XC_PCIE_DM_BASE + 0xC000000)	/* PCIe DM IO Space */
#define OPV5XC_S_PCIE_DM_CFG0_BASE	(OPV5XC_PCIE_DM_BASE + 0xD000000)	/* PCIe DM Config Space Type 0 */
#define OPV5XC_S_PCIE_DM_CFG1_BASE	(OPV5XC_PCIE_DM_BASE + 0xE000000)	/* PCIe DM Config Space Type 1 */
#define OPV5XC_PCIE_RC_BASE		0x90000000
#define OPV5XC_S_PCIE_RC_MEM_BASE	(OPV5XC_PCIE_RC_BASE)			/* PCIe RC Memory Base */
#define OPV5XC_S_PCIE_RC_HOST_BASE	(OPV5XC_PCIE_RC_BASE + 0xB000000)	/* PCIe RC Host Base */
#define OPV5XC_S_PCIE_RC_IO_BASE	(OPV5XC_PCIE_RC_BASE + 0xC000000)	/* PCIe RC IO Space */
#define OPV5XC_S_PCIE_RC_CFG0_BASE	(OPV5XC_PCIE_RC_BASE + 0xD000000)	/* PCIe RC Config Space Type 0 */
#define OPV5XC_S_PCIE_RC_CFG1_BASE	(OPV5XC_PCIE_RC_BASE + 0xE000000)	/* PCIe RC Config Space Type 1 */
#define OPV5XC_S_PCIE_BUS_CPU_MEM_OFFSET	0x30000000	/* bus->cpu memory mapping offset 0x8000_0000 - 0x5000_0000 */
#define OPV5XC_S_PCIE_BUS_CPU_IO_OFFSET		0x30000000	/* bus->cpu IO mapping offset	  0x8C00_0000 - 0x5C00_0000	*/

#define OPV5XC_SMC_BASE			0xA0000000	/* Flash Memory */
#define OPV5XC_SDIO_BASE		0xC0000000	/* Mobile Storage Host Controller - MSHCI0 */
#define OPV5XC_SDIO1_BASE		0xC0700000	/* Mobile Storage Host Controller - MSHCI1 */
#define OPV5XC_I2S_A_BASE		0xC0100000	/* I2S Port0 Data Region */
#define OPV5XC_I2S_B_BASE		0xC0200000	/* I2S Port1 Data Region */
#define OPV5XC_CR_SPD_BASE		0xC0300000	/* SPDIF Control Registers */
#define OPV5XC_CR_SMC_BASE		0xC0400000	/* Static Memory Controller (SMC) Control Registers */
#define OPV5XC_NFC_CMD_BASE		0xC0500000	/* NFC Command */
#define OPV5XC_NFC_CR_BASE		0xC0600000	/* NFC Control Registers */
#define OPV5XC_S_SATA_BASE		0xC4000000	/* SATA 2.0 AHCI Controller */
#define OPV5XC_S_USB3H_BASE		0xC5000000	/* USB 3.0 xHCI Host Controller */
#define OPV5XC_S_USB3DRD_BASE		0xC6000000	/* USB 3.0 Dual Mode */
#define OPV5XC_S_CFP_BASE		0xC7000000	/* Crypto Fast Path */

#define OPV5XC_SPI_FLASH_BASE		0xE8000000	/* SPI Serial Flash Memory, 256MB */

#define OPV5XC_CR_IXC_BASE		0xF8000000	/* AXI Bus Fabric */
#define OPV5XC_MISC_BASE		0xF9000000	/* Misc. Register */
#define OPV5XC_CR_DDR_BASE		0xF8C00000	/* DDR3 (Denali Databahn) Memory Controller */
#define OPV5XC_CR_LPI_BASE		0xF8C80000	/* */
#define OPV5XC_CR_SPI_BASE		0xF8100000	/* SPI Control Registers */
#define OPV5XC_CR_I2C0_BASE		0xF8200000	/* I2C Port 0 Control Registers */
#define OPV5XC_CR_I2C1_BASE		0xF9600000	/* I2C Port 1 Control Registers */
#define OPV5XC_CR_UART0_BASE		0xF8300000	/* UART Port 0 Control Registers */
#define OPV5XC_CR_UART1_BASE		0xF8400000	/* UART Port 1 Control Registers */
#define OPV5XC_CR_UART2_BASE		0xF8500000	/* UART Port 2 Control Registers */
#define OPV5XC_CR_GPIOA_BASE		0xF9300000	/* GPIO Port A Control Registers */
#define OPV5XC_CR_GPIOB_BASE		0xF9400000	/* GPIO Port B Control Registers */
#define OPV5XC_CR_PCM_BASE		0xF8600000	/* PCM Port 0/1 Control Registers */
#define OPV5XC_CR_PMU_BASE		0xF9500000	/* Power Management Unit Control Registers */
#define OPV5XC_TIMER_BASE		0xF9100000	/* Timer (external timer) */
#define OPV5XC_RTC_BASE			0xF9200000	/* Real Time Clock (RTC) */

#define OPV5XC_CR_RAID_BASE		0xF8800000	/* RAID XOR Control Registers */
#define OPV5XC_CR_CRYPTO_BASE		0xF9900000	/* Crypto Control Registers */
#define OPV5XC_CR_CFP_BASE		0xC7000000	/* Crypto Fast Path Control Registers */
#define OPV5XC_CR_PSE_PPE_BASE		0xF8900000	/* PSE/PPE Control Registers */
#define OPV5XC_CR_PTP_BASE		0xF8B00000	/* PTP Control Registers */
#define OPV5XC_CR_PHY_SATA_BASE		0xF9B00000	/* SATA PHY Control Registers */
#define OPV5XC_CR_PHY_USB_BASE		0xF9C00000	/* USB PHY Control Registers */
#define OPV5XC_CR_I2S0_BASE		0xF9700000	/* I2S Port 0 Control Registers */
#define OPV5XC_CR_I2S1_BASE		0xF9800000	/* I2S Port 1 Control Registers */
#define OPV5XC_CR_GDMA_BASE		0xF8700000	/* Generic DMA Control Registers */
#define OPV5XC_CR_PWM_BASE		0xF8A00000	/* PWM Control Registers */
#define OPV5XC_CR_PHY_PCIE_BASE		0xF9A00000	/* PCIe PHY Control Registers */
#define OPV5XC_CR_PHY_DDR_BASE		0xF8D00000	/* DDR PHY Control Registers */
#define OPV5XC_CR_CORESIGHT_BASE	0xF8E00000	/* CoreSight Component */
#define OPV5XC_CR_NOC_BASE		0xFFFC0000	/* NOC Control Registers */
#define OPV5XC_BOOT_ROM_BASE		0xFFFF0000	/* BootROM */

/* Static Mappings */
#define OPV5XC_V2T_PERIPH		IOMEM(0xFE000000) /* peripherals static mappings */
#define OPV5XC_CR_UART0_BASE_VIRT	IOMEM(0xFE100000) /* printascii used virtual address*/
#define OPV5XC_CR_PMU_BASE_VIRT		IOMEM(0xFE200000)
#define OPV5XC_MISC_BASE_VIRT		IOMEM(0xFE300000)
#define OPV5XC_CR_IXC_BASE_VIRT		IOMEM(0xFE400000)

#define OPV5XC_CA9MP_BASE		0xC8000000	/* Cortex A9 Private Memory Region */
#define OPV5XC_CA9MP_SCU_BASE		(OPV5XC_CA9MP_BASE)
#define OPV5XC_CA9MP_GIC_CPU_BASE	(OPV5XC_CA9MP_BASE + 0x0100)
#define OPV5XC_CA9MP_GTIMER_BASE	(OPV5XC_CA9MP_BASE + 0x0200)
#define OPV5XC_CA9MP_PTIMER_BASE	(OPV5XC_CA9MP_BASE + 0x0600)
#define OPV5XC_CA9MP_GIC_DIST_BASE	(OPV5XC_CA9MP_BASE + 0x1000)

#define OPV5XC_L2CC_BASE		0xC8800000	/* L2 Cache Controller */

#define MAX_GPIOA_NO			32
#define MAX_GPIOB_NO			32
#define MAX_GPIO_NO			(MAX_GPIOA_NO + MAX_GPIOB_NO)

#elif defined(CONFIG_ARCH_OPV5XC_ES2)	/* ES2 */

#define OPV5XC_PCIE_PORT_NR   2
#define OPV5XC_PCIE_DM_BASE		0x80000000
#define OPV5XC_S_PCIE_DM_MEM_BASE	(OPV5XC_PCIE_DM_BASE)			/* PCIe DM Memory Base */
#define OPV5XC_S_PCIE_DM_HOST_BASE	(OPV5XC_PCIE_DM_BASE + 0xB000000)	/* PCIe DM Host Base */
#define OPV5XC_S_PCIE_DM_IO_BASE	(OPV5XC_PCIE_DM_BASE + 0xC000000)	/* PCIe DM IO Space */
#define OPV5XC_S_PCIE_DM_CFG0_BASE	(OPV5XC_PCIE_DM_BASE + 0xD000000)	/* PCIe DM Config Space Type 0 */
#define OPV5XC_S_PCIE_DM_CFG1_BASE	(OPV5XC_PCIE_DM_BASE + 0xE000000)	/* PCIe DM Config Space Type 1 */
#define OPV5XC_PCIE_RC_BASE		0x90000000
#define OPV5XC_S_PCIE_RC_MEM_BASE	(OPV5XC_PCIE_RC_BASE)			/* PCIe RC Memory Base */
#define OPV5XC_S_PCIE_RC_HOST_BASE	(OPV5XC_PCIE_RC_BASE + 0xB000000)	/* PCIe RC Host Base */
#define OPV5XC_S_PCIE_RC_IO_BASE	(OPV5XC_PCIE_RC_BASE + 0xC000000)	/* PCIe RC IO Space */
#define OPV5XC_S_PCIE_RC_CFG0_BASE	(OPV5XC_PCIE_RC_BASE + 0xD000000)	/* PCIe RC Config Space Type 0 */
#define OPV5XC_S_PCIE_RC_CFG1_BASE	(OPV5XC_PCIE_RC_BASE + 0xE000000)	/* PCIe RC Config Space Type 1 */
#define OPV5XC_S_PCIE_BUS_CPU_MEM_OFFSET	0x0	/* bus->cpu memory mapping offset 0x8000_0000 - 0x8000_0000 */
#define OPV5XC_S_PCIE_BUS_CPU_IO_OFFSET		0x0	/* bus->cpu IO mapping offset	  0x8C00_0000 - 0x8C00_0000	*/

#define OPV5XC_SMC_BASE			0xA0000000	/* Flash Memory */
#define OPV5XC_SDIO_BASE		0xC0000000	/* Mobile Storage Host Controller - MSHCI0 */
#define OPV5XC_I2S_A_BASE		0xC0200000	/* I2S Port0 Data Region */
#define OPV5XC_I2S_B_BASE		0xC0400000	/* I2S Port1 Data Region */
#define OPV5XC_CR_SPD_BASE		0xC0600000	/* SPDIF Control Registers */
#define OPV5XC_CR_SMC_BASE		0xC0800000	/* Static Memory Controller (SMC) Control Registers */
#define OPV5XC_CR_I2S0_BASE		0xC0A00000	/* I2S Port 0 Control Registers */
#define OPV5XC_CR_I2S1_BASE		0xC0C00000	/* I2S Port 1 Control Registers */
#define OPV5XC_NFC_CMD_BASE		0xC0E00000	/* NFC Command */
#define OPV5XC_NFC_CR_BASE		0xC1000000	/* NFC Control Registers */
#define OPV5XC_S_USB3H_BASE		0xC5000000	/* USB 3.0 xHCI Host Controller */
#define OPV5XC_S_USB3DRD_BASE		0xC6000000	/* USB 3.0 Dual Mode */
#define OPV5XC_S_CFP_BASE		0xC7000000	/* Crypto Fast Path */
#define OPV5XC_CA9MP_BASE		0xC8000000	/* Cortex A9 Private Memory Region */
#define OPV5XC_CA9MP_SCU_BASE		(OPV5XC_CA9MP_BASE)
#define OPV5XC_CA9MP_GIC_CPU_BASE	(OPV5XC_CA9MP_BASE + 0x0100)
#define OPV5XC_CA9MP_GTIMER_BASE	(OPV5XC_CA9MP_BASE + 0x0200)
#define OPV5XC_CA9MP_PTIMER_BASE	(OPV5XC_CA9MP_BASE + 0x0600)
#define OPV5XC_CA9MP_GIC_DIST_BASE	(OPV5XC_CA9MP_BASE + 0x1000)
#define OPV5XC_L2CC_BASE		0xC8800000	/* L2 Cache Controller */
#define OPV5XC_CR_NOC_CPU_BASE		0xE7FF0000	/* NOC Control Registers */
#define OPV5XC_CR_NOC_SOC_BASE		0xE7FE0000	/* NOC Control Registers */
#define OPV5XC_SPI_FLASH_BASE		0xE8000000	/* SPI Serial Flash Memory, 256MB */
#define OPV5XC_CR_DDR_BASE		0xF8000000	/* DDR3 (Denali Databahn) Memory Controller */
#define OPV5XC_CR_LPI_BASE		0xF8080000	/* */
#define OPV5XC_CR_I2C0_BASE		0xF8100000	/* I2C Port 0 Control Registers */
#define OPV5XC_CR_IXC_BASE		0xF8200000	/* AXI Bus Fabric */
#define OPV5XC_CR_PCM_BASE		0xF8300000	/* PCM Port 0/1 Control Registers */
#define OPV5XC_CR_PHY_DDR_BASE		0xF8400000	/* DDR PHY Control Registers */
#define OPV5XC_CR_PWM_BASE		0xF8500000	/* PWM Control Registers */
#define OPV5XC_CR_SPI_BASE		0xF8600000	/* SPI Control Registers */
#define OPV5XC_CR_UART0_BASE		0xF8800000	/* UART Port 0 Control Registers */
#define OPV5XC_CR_UART1_BASE		0xF8900000	/* UART Port 1 Control Registers */
#define OPV5XC_CR_UART2_BASE		0xF8A00000	/* UART Port 2 Control Registers */
#define OPV5XC_CR_CRYPTO_BASE		0xF8C00000	/* Crypto Control Registers */
#define OPV5XC_CR_GDMA_BASE		0xF8D00000	/* Generic DMA Control Registers */
#define OPV5XC_CR_CORESIGHT_BASE	0xFC000000	/* CoreSight Component */
#define OPV5XC_CR_GPIOA_BASE		0xFC400000	/* GPIO Port A Control Registers */
#define OPV5XC_CR_GPIOB_BASE		0xFC500000	/* GPIO Port B Control Registers */
#define OPV5XC_CR_PHY_PCIE_BASE		0xFC600000	/* PCIe PHY Control Registers */
#define OPV5XC_CR_PHY_USB_BASE		0xFC700000	/* USB PHY Control Registers */
#define OPV5XC_CR_PMU_BASE		0xFC800000	/* Power Management Unit Control Registers */
#define OPV5XC_CR_I2C1_BASE		0xFC900000	/* I2C Port 1 Control Registers */
#define OPV5XC_CR_PSE_PPE_BASE		0xFCA00000	/* PSE/PPE Control Registers */
#define OPV5XC_CR_PTP_BASE		0xFCB00000	/* PTP Control Registers */
#define OPV5XC_MISC_BASE		0xFCC00000	/* Misc. Register */
#define OPV5XC_RTC_BASE			0xFCE00000	/* Real Time Clock (RTC) */
#define OPV5XC_TIMER_BASE		0xFCF00000	/* Timer (external timer) */
#define OPV5XC_BOOT_ROM_BASE		0xFFFF0000	/* BootROM */

/* Static Mappings */
#define OPV5XC_V2T_PERIPH		IOMEM(0xFE000000) /* peripherals static mappings */
#define OPV5XC_CR_UART0_BASE_VIRT	IOMEM(0xFE100000) /* printascii used virtual address*/
#define OPV5XC_CR_PMU_BASE_VIRT		IOMEM(0xFE200000)
#define OPV5XC_MISC_BASE_VIRT		IOMEM(0xFE300000)
#define OPV5XC_CR_IXC_BASE_VIRT		IOMEM(0xFE400000)

#define MAX_GPIOA_NO			32
#define MAX_GPIOB_NO			32
#define MAX_GPIO_NO			(MAX_GPIOA_NO + MAX_GPIOB_NO)

#else /* CONFIG_ARCH_OPV5XC_CX4 */

#define OPV5XC_PCIE_PORT_NR   1
#define OPV5XC_PCIE_DM_BASE		0xEC000000
/* FIXME Recover the BAR setting for FPGA board */
#define OPV5XC_S_PCIE_DM_MEM_BASE	(OPV5XC_PCIE_DM_BASE)			/* PCIe DM Memory Base */
#define OPV5XC_S_PCIE_DM_IO_BASE	(OPV5XC_PCIE_DM_BASE + 0x3000000)	/* PCIe DM IO Space */
#define OPV5XC_S_PCIE_DM_HOST_BASE	(OPV5XC_PCIE_DM_BASE + 0x4000000)	/* PCIe DM Host Base */
#define OPV5XC_S_PCIE_DM_CFG0_BASE	(OPV5XC_PCIE_DM_BASE + 0x6000000)	/* PCIe DM Config Space Type 0 */
#define OPV5XC_S_PCIE_DM_CFG1_BASE	(OPV5XC_PCIE_DM_BASE + 0x7000000)	/* PCIe DM Config Space Type 1 */
#define OPV5XC_PCIE_RC_BASE		0xF4000000
#define OPV5XC_S_PCIE_RC_MEM_BASE	(OPV5XC_PCIE_RC_BASE)			/* PCIe RC Memory Base */
#define OPV5XC_S_PCIE_RC_IO_BASE	(OPV5XC_PCIE_RC_BASE + 0x3000000)	/* PCIe RC IO Space */
#define OPV5XC_S_PCIE_RC_HOST_BASE	(OPV5XC_PCIE_RC_BASE + 0x4000000)	/* PCIe RC Host Base */
#define OPV5XC_S_PCIE_RC_CFG0_BASE	(OPV5XC_PCIE_RC_BASE + 0x6000000)	/* PCIe RC Config Space Type 0 */
#define OPV5XC_S_PCIE_RC_CFG1_BASE	(OPV5XC_PCIE_RC_BASE + 0x7000000)	/* PCIe RC Config Space Type 1 */
#define OPV5XC_S_PCIE_BUS_CPU_MEM_OFFSET	0x0			/* bus->cpu memory mapping offset 0xEC00_0000 - 0xEC00_0000 */
#define OPV5XC_S_PCIE_BUS_CPU_IO_OFFSET		0x0			/* bus->cpu IO mapping offset     0xEF00_0000 - 0xEF00_0000 */

#define OPV5XC_SMC_BASE			0xFC000000	/* Flash Memory, 32MB */
#define OPV5XC_SDIO_BASE		0xFE000000	/* Mobile Storage Host Controller - MSHCI0 */
#define OPV5XC_SDIO1_BASE		0xFE1C0000	/* Mobile Storage Host Controller - MSHCI1 */
#define OPV5XC_I2S_A_BASE		0xFE040000	/* I2S Port0 Data Region */
#define OPV5XC_I2S_B_BASE		0xFE080000	/* I2S Port1 Data Region */
#define OPV5XC_CR_SPD_BASE		0xFE0C0000	/* SPDIF Control Registers */
#define OPV5XC_CR_SMC_BASE		0xFE100000	/* Static Memory Controller (SMC) Control Registers */
#define OPV5XC_NFC_CMD_BASE		0xFE140000	/* NFC Command */
#define OPV5XC_NFC_CR_BASE		0xFE180000	/* NFC Control Registers */
#define OPV5XC_S_SATA_BASE		0xFE400000	/* SATA 2.0 AHCI Controller */
#define OPV5XC_S_USB3DRD_BASE		0xFE500000	/* USB 3.0 Dual Mode */
#define OPV5XC_S_USB3H_BASE		0xFE600000	/* USB 3.0 xHCI Host Controller */
#define OPV5XC_S_CFP_BASE		0xFE700000	/* Crypto Fast Path */
#define OPV5XC_SPI_FLASH_BASE		0xFE800000	/* SPI Serial Flash Memory, 256MB */

#define OPV5XC_CR_IXC_BASE		0xFF800000	/* AXI Bus Fabric */
#define OPV5XC_MISC_BASE		0xFF840000	/* Misc. Register */
#define OPV5XC_CR_DDR_BASE		0xFF880000	/* DDR3 (Denali Databahn) Memory Controller */
#define OPV5XC_CR_LPI_BASE		0xFF8A0000	/* */
#define OPV5XC_CR_SPI_BASE		0xFF900000	/* SPI Control Registers */
#define OPV5XC_CR_I2C0_BASE		0xFF940000	/* I2C Port 0 Control Registers */
#define OPV5XC_CR_I2C1_BASE		0xFF960000	/* I2C Port 1 Control Registers */
#define OPV5XC_CR_UART0_BASE		0xFF980000	/* UART Port 0 Control Registers */
#define OPV5XC_CR_UART1_BASE		0xFF9C0000	/* UART Port 1 Control Registers */
#define OPV5XC_CR_UART2_BASE		0xFFA00000	/* UART Port 2 Control Registers */
#define OPV5XC_CR_GPIOA_BASE		0xFFA40000	/* GPIO Port A Control Registers */
#define OPV5XC_CR_GPIOB_BASE		0xFFA80000	/* GPIO Port B Control Registers */
#define OPV5XC_CR_PCM_BASE		0xFFAC0000	/* PCM Port 0/1 Control Registers */
#define OPV5XC_CR_PMU_BASE		0xFFB00000	/* Power Management Unit Control Registers */
#define OPV5XC_TIMER_BASE		0xFFB40000	/* Timer (external timer) */
#define OPV5XC_MISC_F1_BASE		0xFFB80000	/* Misc. Register */
#define OPV5XC_RTC_BASE			0xFFBC0000	/* Real Time Clock (RTC) */

#define OPV5XC_CR_RAID_BASE		0xFFC00000	/* RAID XOR Control Registers */
#define OPV5XC_CR_CRYPTO_BASE		0xFFC40000	/* Crypto Control Registers */
#define OPV5XC_CR_CFP_BASE		0xFFC80000	/* Crypto Fast Path Control Registers */
#define OPV5XC_CR_PSE_PPE_BASE		0xFFCC0000	/* PSE/PPE Control Registers */
#define OPV5XC_CR_PTP_BASE		0xFFD00000	/* PTP Control Registers */
#define OPV5XC_CR_PHY_SATA_BASE		0xFFD40000	/* SATA PHY Control Registers */
#define OPV5XC_CR_PHY_USB_BASE		0xFFD80000	/* USB PHY Control Registers */
#define OPV5XC_CR_IXC_F1_BASE		0xFFDC0000
#define OPV5XC_CR_NOC_F1_BASE		0xFFDE0000
#define OPV5XC_CR_I2S0_BASE		0xFFE00000	/* I2S Port 0 Control Registers */
#define OPV5XC_CR_I2S1_BASE		0xFFE40000	/* I2S Port 1 Control Registers */
#define OPV5XC_CR_GDMA_BASE		0xFFE80000	/* Generic DMA Control Registers */
#define OPV5XC_CR_PWM_BASE		0xFFEC0000	/* PWM Control Registers */
#define OPV5XC_CR_PHY_PCIE_BASE		0xFFF00000	/* PCIe PHY Control Registers */
#define OPV5XC_CR_PHY_DDR_BASE		0xFFF40000	/* DDR PHY Control Registers */
#define OPV5XC_CR_CORESIGHT_BASE	0xFFF80000	/* CoreSight Component */
#define OPV5XC_CR_NOC_BASE		0xFFFC0000	/* NOC Control Registers */
#define OPV5XC_BOOT_ROM_BASE		0xFFFF0000	/* BootROM */

/* Tile's peripherals static mappings should start here */
#define OPV5XC_V2T_PERIPH		0xf8000000

/* static mapping */
#define OPV5XC_MISC_BASE_VIRT		IOMEM(0xf8040000)
#define OPV5XC_CR_UART0_BASE_VIRT	IOMEM(0xf8080000)	/* printascii used virtual address*/

/* CA9MP CoreTile */
#define CT_CA9X4_AXIRAM			0x10060000
#define CT_CA9X4_DMC			0x100e0000
#define CT_CA9X4_SMC			0x100e1000
#define CT_CA9X4_SCC			0x100e2000

#define CT_CA9X4_CORESIGHT		0x10200000

#define OPV5XC_CA9MP_BASE		0x1e000000	/* Cortex A9 Private Memory Region */
#define OPV5XC_CA9MP_SCU_BASE		(OPV5XC_CA9MP_BASE)
#define OPV5XC_CA9MP_GIC_CPU_BASE	(OPV5XC_CA9MP_BASE + 0x0100)
#define OPV5XC_CA9MP_GIT_BASE		(OPV5XC_CA9MP_BASE + 0x0200)
#define OPV5XC_CA9MP_PTIMER_BASE	(OPV5XC_CA9MP_BASE + 0x0600)
#define OPV5XC_CA9MP_GIC_DIST_BASE	(OPV5XC_CA9MP_BASE + 0x1000)

#define OPV5XC_L2CC_BASE		0x1e00a000	/* L2 Cache Controller */

#define MAX_GPIOA_NO			4
#define MAX_GPIOB_NO			0
#define MAX_GPIO_NO			(MAX_GPIOA_NO + MAX_GPIOB_NO)

#endif /* CONFIG_ARCH_OPV5XC_ES1 */

#ifndef __ASSEMBLY__
extern struct proc_dir_entry *opv5xc_proc_dir;
#ifdef CONFIG_DEBUG_FS
extern struct dentry *opv5xc_debugfs_dir;
#endif


/* Note: these values correspond to bits in PMU registers */
enum opv5xc_peri {
	OPV5XC_PERI_DMC = 2,
	OPV5XC_PERI_SPI = 3,
	OPV5XC_PERI_TWI = 3,
	OPV5XC_PERI_GDMA = 4,
	OPV5XC_PERI_RTC = 5,
	OPV5XC_PERI_UART = 6,
	OPV5XC_PERI_PWM = 9,
	OPV5XC_PERI_PSE = 11,
	OPV5XC_PERI_PCM = 12,
	OPV5XC_PERI_CRYPTO = 13,
	OPV5XC_PERI_TIMER = 14,
	OPV5XC_PERI_USB_DRD = 15,
	OPV5XC_PERI_USB_HOST = 16,
	OPC5XC_PERI_PCIE_DM = 17,
	OPV5XC_PERI_PCI_RC = 18,
	OPV5XC_PERI_NFC = 19,
	OPV5XC_PERI_I2S0 = 21,
	OPV5XC_PERI_I2S1 = 22,
	OPV5XC_PERI_SPDIF = 23,
	OPV5XC_PERI_PTP = 24,
	OPV5XC_PERI_MMC = 25,
};

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
extern int opv5xc_enable_peri(enum opv5xc_peri peri);
extern void opv5xc_disable_peri(enum opv5xc_peri peri);
#else
static inline int opv5xc_enable_peri(enum opv5xc_peri peri)
{
	return 0;
}
static inline void opv5xc_disable_peri(enum opv5xc_peri peri)
{
}
#endif

#endif

#endif /* _OPV5XC_SOC_H */
