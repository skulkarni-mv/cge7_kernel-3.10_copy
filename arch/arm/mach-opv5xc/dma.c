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

#include <linux/amba/bus.h>
#include <linux/amba/pl330.h>
#include <asm/irq.h>
#include <mach/opv5xc.h>
#include <mach/dma.h>

static u8 opv5xc_gdma_peri[] = {
	DMACH_UART0_TX,
	DMACH_UART0_RX,
	DMACH_UART1_TX,
	DMACH_UART1_RX,
	DMACH_UART2_TX,
	DMACH_UART2_RX,
	DMACH_PCM1_RX,
	DMACH_PCM0_RX,
	DMACH_SPI_TX,
	DMACH_SPI_RX,
	DMACH_I2S0_RX,
	DMACH_I2S0_TX,
	DMACH_I2S1_RX,
	DMACH_I2S1_TX,
	DMACH_SPDIF_TX,
	DMACH_PCM0_TX,
	DMACH_PCM1_TX,
};

static struct dma_pl330_platdata opv5xc_gdma_pdata = {
	.nr_valid_peri = ARRAY_SIZE(opv5xc_gdma_peri),
	.peri_id = opv5xc_gdma_peri,
};

#ifdef CONFIG_ARCH_OPV5XC_CX4
#define OPV5XC_GDMA_IRQ {IRQ_OPV5XC_DMAC0}
#else
#define OPV5XC_GDMA_IRQ {IRQ_OPV5XC_DMAC0, IRQ_OPV5XC_DMAC1, \
			 IRQ_OPV5XC_DMAC2, IRQ_OPV5XC_DMAC3, \
			 IRQ_OPV5XC_DMAC4, IRQ_OPV5XC_DMAC5, \
			 IRQ_OPV5XC_DMAC6, IRQ_OPV5XC_DMAC7}
#endif

static AMBA_AHB_DEVICE(opv5xc_gdma, "dma-pl330", 0x00041330,
		OPV5XC_CR_GDMA_BASE, OPV5XC_GDMA_IRQ, &opv5xc_gdma_pdata);

int opv5xc_gdma_init(void)
{
	int ret;

	ret = opv5xc_enable_peri(OPV5XC_PERI_GDMA);
	if (ret)
		return ret;

	dma_cap_set(DMA_MEMCPY, opv5xc_gdma_pdata.cap_mask);
	dma_cap_set(DMA_SLAVE, opv5xc_gdma_pdata.cap_mask);
	dma_cap_set(DMA_CYCLIC, opv5xc_gdma_pdata.cap_mask);
	return amba_device_register(&opv5xc_gdma_device, &iomem_resource);
}
