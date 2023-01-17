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

#define IRQ_LOCALTIMER			29
#define IRQ_LOCALWDOG			30

/* Irqs */
#define IRQ_CA9MP_GIC_START		32

#ifdef CONFIG_ARCH_OPV5XC_ES1

#define IRQ_OPV5XC_PMU_DVFS		(IRQ_CA9MP_GIC_START + 0)	/* PMU DVFS, Rising edge */
#define IRQ_OPV5XC_I2C0			(IRQ_CA9MP_GIC_START + 1)	/* I2C Port0, High level */
#define IRQ_OPV5XC_HBN_REQ		(IRQ_CA9MP_GIC_START + 2)	/* */
#define IRQ_OPV5XC_I2S0CNT		(IRQ_CA9MP_GIC_START + 3)	/* */
#define IRQ_OPV5XC_I2S1CNT		(IRQ_CA9MP_GIC_START + 4)	/* */
#define IRQ_OPV5XC_PCM			(IRQ_CA9MP_GIC_START + 5)	/* PCM, High level */
#define IRQ_OPV5XC_SPI			(IRQ_CA9MP_GIC_START + 6)	/* SPI, High level */
#define IRQ_OPV5XC_I2C1			(IRQ_CA9MP_GIC_START + 7)	/* I2C Port1, High level */
#define IRQ_OPV5XC_I2S0			(IRQ_CA9MP_GIC_START + 8)	/* I2S Port0, High level */
#define IRQ_OPV5XC_I2S1			(IRQ_CA9MP_GIC_START + 9)	/* I2S Port1, High level */

#define IRQ_OPV5XC_TIMER1		(IRQ_CA9MP_GIC_START + 11)	/* Timer2, Rising edge */
#define IRQ_OPV5XC_TIMER2		(IRQ_CA9MP_GIC_START + 12)	/* Timer3, Rising edge */
#define IRQ_OPV5XC_TIMER3		(IRQ_CA9MP_GIC_START + 13)	/* Timer3, Rising edge */
#define IRQ_OPV5XC_UART0		(IRQ_CA9MP_GIC_START + 14)	/* UART 0, High level */
#define IRQ_OPV5XC_UART1		(IRQ_CA9MP_GIC_START + 15)	/* UART 1, High level */
#define IRQ_OPV5XC_UART2		(IRQ_CA9MP_GIC_START + 16)	/* UART 2, High level */
#define IRQ_OPV5XC_GPIOA		(IRQ_CA9MP_GIC_START + 17)	/* GPIOA, programmable */
#define IRQ_OPV5XC_GPIOB		(IRQ_CA9MP_GIC_START + 18)	/* GPIOB, programmable */
#define IRQ_OPV5XC_PWM0			(IRQ_CA9MP_GIC_START + 19)	/* PWM tacho 0, High level */
#define IRQ_OPV5XC_PWM1			(IRQ_CA9MP_GIC_START + 20)	/* PWM tacho 1, High level */
#define IRQ_OPV5XC_RTC			(IRQ_CA9MP_GIC_START + 21)	/* RTC CTL, High level */
#define IRQ_OPV5XC_RTC_BAT		(IRQ_CA9MP_GIC_START + 22)	/* RTC Battery, High level */
#define IRQ_OPV5XC_SPDIF		(IRQ_CA9MP_GIC_START + 23)	/* SPDIF, High level */
#define IRQ_OPV5XC_USB3_XHCI		(IRQ_CA9MP_GIC_START + 24)	/* USB 3 Host, High level */
#define IRQ_OPV5XC_USB3_DRDOTG		(IRQ_CA9MP_GIC_START + 25)	/* USB 3 DRD OTG, High level */
#define IRQ_OPV5XC_USB3_DRD0		(IRQ_CA9MP_GIC_START + 26)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD1		(IRQ_CA9MP_GIC_START + 27)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD2		(IRQ_CA9MP_GIC_START + 28)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD3		(IRQ_CA9MP_GIC_START + 29)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_SATA			(IRQ_CA9MP_GIC_START + 30)	/* SATA, High level */

#define IRQ_OPV5XC_RAID			(IRQ_CA9MP_GIC_START + 32)	/* RAID, High level */
#define IRQ_OPV5XC_PCIE1_DEVICE		(IRQ_CA9MP_GIC_START + 33)	/* PCIe1 Device, High level */
#define IRQ_OPV5XC_PCIE1_RC		(IRQ_CA9MP_GIC_START + 34)	/* PCIe1, High level */
#define IRQ_OPV5XC_PCIE0_DEVICE		(IRQ_CA9MP_GIC_START + 35)	/* PCIe0 Device, High level */
#define IRQ_OPV5XC_PCIE0_RC		(IRQ_CA9MP_GIC_START + 36)	/* PCIe0, High level */
#define IRQ_OPV5XC_DMAC_ABORT		(IRQ_CA9MP_GIC_START + 37)	/* Generic DMA Controller Abort, High level */
#define IRQ_OPV5XC_DMAC0		(IRQ_CA9MP_GIC_START + 38)	/* Generic DMA Controller, High level */
#define IRQ_OPV5XC_DMAC1		(IRQ_CA9MP_GIC_START + 39)	/* */
#define IRQ_OPV5XC_DMAC2		(IRQ_CA9MP_GIC_START + 40)	/* */
#define IRQ_OPV5XC_DMAC3		(IRQ_CA9MP_GIC_START + 41)	/* */
#define IRQ_OPV5XC_DMAC4		(IRQ_CA9MP_GIC_START + 42)	/* */
#define IRQ_OPV5XC_DMAC5		(IRQ_CA9MP_GIC_START + 43)	/* */
#define IRQ_OPV5XC_DMAC6		(IRQ_CA9MP_GIC_START + 44)	/* */
#define IRQ_OPV5XC_DMAC7		(IRQ_CA9MP_GIC_START + 45)	/* */
#define IRQ_OPV5XC_DMAC8		(IRQ_CA9MP_GIC_START + 46)	/* */
#define IRQ_OPV5XC_DMAC9		(IRQ_CA9MP_GIC_START + 47)	/* */
#define IRQ_OPV5XC_DMAC10		(IRQ_CA9MP_GIC_START + 48)	/* */
#define IRQ_OPV5XC_DMAC11		(IRQ_CA9MP_GIC_START + 49)	/* */
#define IRQ_OPV5XC_DMAC12		(IRQ_CA9MP_GIC_START + 50)	/* */
#define IRQ_OPV5XC_DMAC13		(IRQ_CA9MP_GIC_START + 51)	/* */
#define IRQ_OPV5XC_DMAC14		(IRQ_CA9MP_GIC_START + 52)	/* */
#define IRQ_OPV5XC_DMAC15		(IRQ_CA9MP_GIC_START + 53)	/* */
#define IRQ_OPV5XC_SDIO			(IRQ_CA9MP_GIC_START + 54)	/* SDIO, High level */
#define IRQ_OPV5XC_CRYPTO		(IRQ_CA9MP_GIC_START + 55)	/* Nitrox (Crypto), High level */
#define IRQ_OPV5XC_NFC			(IRQ_CA9MP_GIC_START + 56)	/* NFC, High level */
#define IRQ_OPV5XC_LPDENY		(IRQ_CA9MP_GIC_START + 57)	/* LP Deny, High level */
#define IRQ_OPV5XC_MCCTL		(IRQ_CA9MP_GIC_START + 58)	/* MC control, High level */
#define IRQ_OPV5XC_SDIO1		(IRQ_CA9MP_GIC_START + 59)	/* SDIO1, High level */
#define IRQ_OPV5XC_EXT0			(IRQ_CA9MP_GIC_START + 60)	/* External Pin0, High level */
#define IRQ_OPV5XC_EXT1			(IRQ_CA9MP_GIC_START + 61)	/* External Pin1, High level */
#define IRQ_OPV5XC_EXT2			(IRQ_CA9MP_GIC_START + 62)	/* External Pin2, High level */
#define IRQ_OPV5XC_EXT3			(IRQ_CA9MP_GIC_START + 63)	/* External Pin3, High level */
#define IRQ_OPV5XC_A9_0			(IRQ_CA9MP_GIC_START + 64)	/* */
#define IRQ_OPV5XC_A9_1			(IRQ_CA9MP_GIC_START + 65)	/* */
#define IRQ_OPV5XC_A9_2			(IRQ_CA9MP_GIC_START + 66)	/* */
#define IRQ_OPV5XC_A9_3			(IRQ_CA9MP_GIC_START + 67)	/* */

#define IRQ_OPV5XC_PTP			(IRQ_CA9MP_GIC_START + 79)	/* PTP, High level */
#define IRQ_OPV5XC_CFP_START		(IRQ_CA9MP_GIC_START + 80)
#define IRQ_OPV5XC_PPE_START		(IRQ_CA9MP_GIC_START + 81)
#define IRQ_OPV5XC_PSE_START		(IRQ_CA9MP_GIC_START + 82)
#define IRQ_OPV5XC_LRO_BUF_EMPTY	(IRQ_CA9MP_GIC_START + 83)
#define IRQ_OPV5XC_PPE_TS_DMA_C3	(IRQ_CA9MP_GIC_START + 84)	/* */
#define IRQ_OPV5XC_PPE_TS_DMA_C2	(IRQ_CA9MP_GIC_START + 85)	/* */
#define IRQ_OPV5XC_PPE_TS_DMA_C1	(IRQ_CA9MP_GIC_START + 86)	/* */
#define IRQ_OPV5XC_PPE_TS_DMA_C0	(IRQ_CA9MP_GIC_START + 87)	/* */
#define IRQ_OPV5XC_PPE_LRO_DMA_C3	(IRQ_CA9MP_GIC_START + 88)	/* */
#define IRQ_OPV5XC_PPE_LRO_DMA_C2	(IRQ_CA9MP_GIC_START + 89)	/* */
#define IRQ_OPV5XC_PPE_LRO_DMA_C1	(IRQ_CA9MP_GIC_START + 90)	/* */
#define IRQ_OPV5XC_PPE_LRO_DMA_C0	(IRQ_CA9MP_GIC_START + 91)	/* */
#define IRQ_OPV5XC_PPE_FS_DMA_C3	(IRQ_CA9MP_GIC_START + 92)	/* */
#define IRQ_OPV5XC_PPE_FS_DMA_C2	(IRQ_CA9MP_GIC_START + 93)	/* */
#define IRQ_OPV5XC_PPE_FS_DMA_C1	(IRQ_CA9MP_GIC_START + 94)	/* */
#define IRQ_OPV5XC_PPE_FS_DMA_C0	(IRQ_CA9MP_GIC_START + 95)	/* */

#endif

#ifdef CONFIG_ARCH_OPV5XC_ES2

#define IRQ_OPV5XC_PMU_DVFS		(IRQ_CA9MP_GIC_START + 0)	/* PMU DVFS, Rising edge */
#define IRQ_OPV5XC_I2C0			(IRQ_CA9MP_GIC_START + 1)	/* I2C Port0, High level */
#define IRQ_OPV5XC_HBN_REQ		(IRQ_CA9MP_GIC_START + 2)	/* */
#define IRQ_OPV5XC_I2S0CNT		(IRQ_CA9MP_GIC_START + 3)	/* */
#define IRQ_OPV5XC_I2S1CNT		(IRQ_CA9MP_GIC_START + 4)	/* */
#define IRQ_OPV5XC_PCM			(IRQ_CA9MP_GIC_START + 5)	/* PCM, High level */
#define IRQ_OPV5XC_SPI			(IRQ_CA9MP_GIC_START + 6)	/* SPI, High level */
#define IRQ_OPV5XC_I2C1			(IRQ_CA9MP_GIC_START + 7)	/* I2C Port1, High level */
#define IRQ_OPV5XC_I2S0			(IRQ_CA9MP_GIC_START + 8)	/* I2S Port0, High level */
#define IRQ_OPV5XC_I2S1			(IRQ_CA9MP_GIC_START + 9)	/* I2S Port1, High level */
#define IRQ_OPV5XC_ZSI_ISI0		(IRQ_CA9MP_GIC_START + 10)	/* ZSI / ISI Port0, High level */
#define IRQ_OPV5XC_TIMER1		(IRQ_CA9MP_GIC_START + 11)	/* Timer2, Rising edge */
#define IRQ_OPV5XC_TIMER2		(IRQ_CA9MP_GIC_START + 12)	/* Timer3, Rising edge */
#define IRQ_OPV5XC_TIMER3		(IRQ_CA9MP_GIC_START + 13)	/* Timer3, Rising edge */
#define IRQ_OPV5XC_UART0		(IRQ_CA9MP_GIC_START + 14)	/* UART 0, High level */
#define IRQ_OPV5XC_UART1		(IRQ_CA9MP_GIC_START + 15)	/* UART 1, High level */
#define IRQ_OPV5XC_UART2		(IRQ_CA9MP_GIC_START + 16)	/* UART 2, High level */
#define IRQ_OPV5XC_GPIOA		(IRQ_CA9MP_GIC_START + 17)	/* GPIOA, programmable */
#define IRQ_OPV5XC_GPIOB		(IRQ_CA9MP_GIC_START + 18)	/* GPIOB, programmable */
#define IRQ_OPV5XC_PWM0			(IRQ_CA9MP_GIC_START + 19)	/* PWM tacho 0, High level */
#define IRQ_OPV5XC_PWM1			(IRQ_CA9MP_GIC_START + 20)	/* PWM tacho 1, High level */
#define IRQ_OPV5XC_RTC			(IRQ_CA9MP_GIC_START + 21)	/* RTC CTL, High level */
#define IRQ_OPV5XC_RTC_BAT		(IRQ_CA9MP_GIC_START + 22)	/* RTC Battery, High level */
#define IRQ_OPV5XC_SPDIF		(IRQ_CA9MP_GIC_START + 23)	/* SPDIF, High level */
#define IRQ_OPV5XC_USB3_XHCI		(IRQ_CA9MP_GIC_START + 24)	/* USB 3 Host, High level */
#define IRQ_OPV5XC_USB3_DRDOTG		(IRQ_CA9MP_GIC_START + 25)	/* USB 3 DRD OTG, High level */
#define IRQ_OPV5XC_USB3_DRD0		(IRQ_CA9MP_GIC_START + 26)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD1		(IRQ_CA9MP_GIC_START + 27)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD2		(IRQ_CA9MP_GIC_START + 28)	/* USB 3 DRD, High level */
#define IRQ_OPV5XC_USB3_DRD3		(IRQ_CA9MP_GIC_START + 29)	/* USB 3 DRD, High level */

#define IRQ_OPV5XC_ZSI_ISI1		(IRQ_CA9MP_GIC_START + 31)	/* ZSI / ISI Port0, High level */

#define IRQ_OPV5XC_PCIE1_DEVICE		(IRQ_CA9MP_GIC_START + 33)	/* PCIe1 Device, High level */
#define IRQ_OPV5XC_PCIE1_RC		(IRQ_CA9MP_GIC_START + 34)	/* PCIe1, High level */
#define IRQ_OPV5XC_PCIE0_DEVICE		(IRQ_CA9MP_GIC_START + 35)	/* PCIe0 Device, High level */
#define IRQ_OPV5XC_PCIE0_RC		(IRQ_CA9MP_GIC_START + 36)	/* PCIe0, High level */
#define IRQ_OPV5XC_DMAC_ABORT		(IRQ_CA9MP_GIC_START + 37)	/* Generic DMA Controller Abort, High level */
#define IRQ_OPV5XC_DMAC0		(IRQ_CA9MP_GIC_START + 38)	/* Generic DMA Controller, High level */
#define IRQ_OPV5XC_DMAC1		(IRQ_CA9MP_GIC_START + 39)	/* */
#define IRQ_OPV5XC_DMAC2		(IRQ_CA9MP_GIC_START + 40)	/* */
#define IRQ_OPV5XC_DMAC3		(IRQ_CA9MP_GIC_START + 41)	/* */
#define IRQ_OPV5XC_DMAC4		(IRQ_CA9MP_GIC_START + 42)	/* */
#define IRQ_OPV5XC_DMAC5		(IRQ_CA9MP_GIC_START + 43)	/* */
#define IRQ_OPV5XC_DMAC6		(IRQ_CA9MP_GIC_START + 44)	/* */
#define IRQ_OPV5XC_DMAC7		(IRQ_CA9MP_GIC_START + 45)	/* */
#define IRQ_OPV5XC_DMAC8		(IRQ_CA9MP_GIC_START + 46)	/* */
#define IRQ_OPV5XC_DMAC9		(IRQ_CA9MP_GIC_START + 47)	/* */
#define IRQ_OPV5XC_DMAC10		(IRQ_CA9MP_GIC_START + 48)	/* */
#define IRQ_OPV5XC_DMAC11		(IRQ_CA9MP_GIC_START + 49)	/* */
#define IRQ_OPV5XC_DMAC12		(IRQ_CA9MP_GIC_START + 50)	/* */
#define IRQ_OPV5XC_DMAC13		(IRQ_CA9MP_GIC_START + 51)	/* */
#define IRQ_OPV5XC_DMAC14		(IRQ_CA9MP_GIC_START + 52)	/* */
#define IRQ_OPV5XC_DMAC15		(IRQ_CA9MP_GIC_START + 53)	/* */
#define IRQ_OPV5XC_SDIO			(IRQ_CA9MP_GIC_START + 54)	/* SDIO, High level */
#define IRQ_OPV5XC_CRYPTO		(IRQ_CA9MP_GIC_START + 55)	/* Nitrox (Crypto), High level */
#define IRQ_OPV5XC_NFC			(IRQ_CA9MP_GIC_START + 56)	/* NFC, High level */
#define IRQ_OPV5XC_LPDENY		(IRQ_CA9MP_GIC_START + 57)	/* LP Deny, High level */
#define IRQ_OPV5XC_MCCTL		(IRQ_CA9MP_GIC_START + 58)	/* MC control, High level */

#define IRQ_OPV5XC_EXT0			(IRQ_CA9MP_GIC_START + 60)	/* External Pin0, High level */
#define IRQ_OPV5XC_EXT1			(IRQ_CA9MP_GIC_START + 61)	/* External Pin1, High level */
#define IRQ_OPV5XC_EXT2			(IRQ_CA9MP_GIC_START + 62)	/* External Pin2, High level */
#define IRQ_OPV5XC_EXT3			(IRQ_CA9MP_GIC_START + 63)	/* External Pin3, High level */
#define IRQ_OPV5XC_A9_0			(IRQ_CA9MP_GIC_START + 64)	/* External abort during a coherence WB, High level */
#define IRQ_OPV5XC_A9_1			(IRQ_CA9MP_GIC_START + 65)	/* Parity output pin from the RAM array for CPU, High level */
#define IRQ_OPV5XC_A9_2			(IRQ_CA9MP_GIC_START + 66)	/* L2CC, High level */
#define IRQ_OPV5XC_A9_3			(IRQ_CA9MP_GIC_START + 67)	/* FPU Data Engine output flag, High level */
#define IRQ_OPV5XC_A9_4			(IRQ_CA9MP_GIC_START + 68)	/* CA9 Core0 PMU, High level */
#define IRQ_OPV5XC_A9_5			(IRQ_CA9MP_GIC_START + 69)	/* CA9 Core1 PMU, High level */
#define IRQ_OPV5XC_A9_6			(IRQ_CA9MP_GIC_START + 70)	/* CA9 Core2 PMU, High level */

#define IRQ_OPV5XC_PTP			(IRQ_CA9MP_GIC_START + 79)	/* Event Interrupt of PTP Status, High level */
#define IRQ_OPV5XC_CFP_START		(IRQ_CA9MP_GIC_START + 80)	/* Event Interrupt of CFP Status, High level */
#define IRQ_OPV5XC_PPE_START		(IRQ_CA9MP_GIC_START + 81)	/* Event Interrupt of PPE Status, High level */
#define IRQ_OPV5XC_PSE_START		(IRQ_CA9MP_GIC_START + 82)	/* Event Interrupt of PSE Status, High level */
#define IRQ_OPV5XC_LRO_BUF_EMPTY	(IRQ_CA9MP_GIC_START + 83)	/* LRO Buffer, High level */

#define IRQ_OPV5XC_PPE_TS_DMA_C2	(IRQ_CA9MP_GIC_START + 85)	/* Descriptor Ring Group2 of TS DMA, High level */
#define IRQ_OPV5XC_PPE_TS_DMA_C1	(IRQ_CA9MP_GIC_START + 86)	/* Descriptor Ring Group1 of TS DMA, High level */
#define IRQ_OPV5XC_PPE_TS_DMA_C0	(IRQ_CA9MP_GIC_START + 87)	/* Descriptor Ring Group0 of TS DMA, High level */

#define IRQ_OPV5XC_PPE_LRO_DMA_C2	(IRQ_CA9MP_GIC_START + 89)	/* Descriptor Ring Group2 of LRO DMA, High level */
#define IRQ_OPV5XC_PPE_LRO_DMA_C1	(IRQ_CA9MP_GIC_START + 90)	/* Descriptor Ring Group1 of LRO DMA, High level */
#define IRQ_OPV5XC_PPE_LRO_DMA_C0	(IRQ_CA9MP_GIC_START + 91)	/* Descriptor Ring Group0 of LRO DMA, High level */

#define IRQ_OPV5XC_PPE_FS_DMA_C2	(IRQ_CA9MP_GIC_START + 93)	/* Descriptor Ring Group2 of FS DMA, High level */
#define IRQ_OPV5XC_PPE_FS_DMA_C1	(IRQ_CA9MP_GIC_START + 94)	/* Descriptor Ring Group1 of FS DMA, High level */
#define IRQ_OPV5XC_PPE_FS_DMA_C0	(IRQ_CA9MP_GIC_START + 95)	/* Descriptor Ring Group0 of FS DMA, High level */

#endif

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)

/*
 * 0        32       64       96      128      160      192
 * |--------|--------|--------|--------|--------|--------|
 *          |<========================>|<===============>|
 *          | OPV5XC physical IRQs       Virtual GPIO IRQs
 *          | (NR_IRQS_OPV5XC)           (NR_IRQS_OPV5XC_GPIO_VIRT)
 *          |
 *          \ IRQ_CA9MP_GIC_START
 */
#define NR_IRQS_OPV5XC			96
#define NR_IRQS_OPV5XC_GPIO_VIRT	64

#ifdef CONFIG_PCI
#include <mach/opv5xc.h>
/*
 * 0        32       64       96      128      160      192
 * |--------|--------|--------|--------|--------|--------|----
 *                                                       |<===
 *                                                        Virtual PCIe IRQs
 *                                                        (OPV5XC_NUM_INTX_IRQS + OPV5XC_NUM_MSI_IRQS)
 */
#define OPV5XC_NUM_INTX_IRQS		4	/* PCIe virtual IRQs */
#ifdef CONFIG_PCI_MSI
#define OPV5XC_NUM_MSI_IRQS		32	/* PCIe MSI virtuql IRQs */
#else
#define OPV5XC_NUM_MSI_IRQS		0	/* PCIe MSI virtuql IRQs */
#endif
#define NR_IRQS_OPV5XC_PCI_VIRT		((OPV5XC_PCIE_PORT_NR * OPV5XC_NUM_INTX_IRQS) + \
					 (OPV5XC_PCIE_PORT_NR * OPV5XC_NUM_MSI_IRQS))
#else
#define NR_IRQS_OPV5XC_PCI_VIRT		0
#endif

#define NR_IRQS				(IRQ_CA9MP_GIC_START +		\
					 NR_IRQS_OPV5XC +		\
					 NR_IRQS_OPV5XC_GPIO_VIRT +	\
					 NR_IRQS_OPV5XC_PCI_VIRT)

#endif

#ifdef CONFIG_ARCH_OPV5XC_CX4

#define IRQ_OPV5XC_UART0		(IRQ_CA9MP_GIC_START + 0)	/* UART 0, High level */
#define IRQ_OPV5XC_UART1		(IRQ_CA9MP_GIC_START + 1)
#define IRQ_OPV5XC_UART2		(IRQ_CA9MP_GIC_START + 2)
#define IRQ_OPV5XC_DMAC0		(IRQ_CA9MP_GIC_START + 3)
#define IRQ_OPV5XC_CRYPTO		(IRQ_CA9MP_GIC_START + 4)
#define IRQ_OPV5XC_PCIE			(IRQ_CA9MP_GIC_START + 5)
#define IRQ_OPV5XC_SATA			(IRQ_CA9MP_GIC_START + 6)
#define IRQ_OPV5XC_USB3_DRDOTG		(IRQ_CA9MP_GIC_START + 7)
#define IRQ_OPV5XC_USB3_XHCI		(IRQ_CA9MP_GIC_START + 8)
#define IRQ_OPV5XC_RAID			(IRQ_CA9MP_GIC_START + 9)
#define IRQ_OPV5XC_SDIO			(IRQ_CA9MP_GIC_START + 10)
#define IRQ_OPV5XC_FS_DMA		(IRQ_CA9MP_GIC_START + 11)
#define IRQ_OPV5XC_LRO_DMA		(IRQ_CA9MP_GIC_START + 12)
#define IRQ_OPV5XC_TS_DMA		(IRQ_CA9MP_GIC_START + 13)
#define IRQ_OPV5XC_LROBUF_EMPTY		(IRQ_CA9MP_GIC_START + 14)
#define IRQ_OPV5XC_PSE_STAT		(IRQ_CA9MP_GIC_START + 15)
#define IRQ_OPV5XC_PPE_STAT		(IRQ_CA9MP_GIC_START + 16)
#define IRQ_OPV5XC_CFP_START		(IRQ_CA9MP_GIC_START + 17)
#define IRQ_OPV5XC_PTP			(IRQ_CA9MP_GIC_START + 18)
#define IRQ_OPV5XC_TIMER1		(IRQ_CA9MP_GIC_START + 19)	/* Timer1, Rising edge */
#define IRQ_OPV5XC_TIMER2		(IRQ_CA9MP_GIC_START + 20)
#define IRQ_OPV5XC_TIMER3		(IRQ_CA9MP_GIC_START + 21)
#define IRQ_OPV5XC_DDRMC		(IRQ_CA9MP_GIC_START + 22)
#define IRQ_OPV5XC_ZSI			(IRQ_CA9MP_GIC_START + 23)
#define IRQ_OPV5XC_ISI			(IRQ_CA9MP_GIC_START + 24)
#define IRQ_OPV5XC_PCM			(IRQ_CA9MP_GIC_START + 25)
#define IRQ_OPV5XC_SPI			(IRQ_CA9MP_GIC_START + 26)
#define IRQ_OPV5XC_I2S0			(IRQ_CA9MP_GIC_START + 27)
#define IRQ_OPV5XC_I2S1			(IRQ_CA9MP_GIC_START + 28)
#define IRQ_OPV5XC_SPDIF		(IRQ_CA9MP_GIC_START + 29)
#define IRQ_OPV5XC_I2C0			(IRQ_CA9MP_GIC_START + 30)
#define IRQ_OPV5XC_PWM0			(IRQ_CA9MP_GIC_START + 31)
#define IRQ_OPV5XC_PWM1			(IRQ_CA9MP_GIC_START + 32)
#define IRQ_OPV5XC_GPIO			(IRQ_CA9MP_GIC_START + 33)
#define IRQ_OPV5XC_NFC			(IRQ_CA9MP_GIC_START + 34)
#define IRQ_OPV5XC_RTC_BAT		(IRQ_CA9MP_GIC_START + 35)
#define IRQ_OPV5XC_RTC_CTL		(IRQ_CA9MP_GIC_START + 36)
#define IRQ_OPV5XC_SDIO1		(IRQ_CA9MP_GIC_START + 37)
#define IRQ_OPV5XC_CT_WAKEUP		(IRQ_CA9MP_GIC_START + 38)

#define NR_IRQS_OPV5XC			(IRQ_CA9MP_GIC_START + 64)
#define NR_IRQS_OPV5XC_GPIO_VIRT	0
#define NR_IRQS				(NR_IRQS_OPV5XC + 128)

#define OPV5XC_NUM_INTX_IRQS		4	/* PCIe virtuql IRQs */
#define OPV5XC_NUM_MSI_IRQS		32	/* PCIe MSI virtuql IRQs */

#endif /* CONFIG_OPV5XC_ES1 */
