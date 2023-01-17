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

#ifndef __MACH_DMA_H
#define __MACH_DMA_H

/* GDMA peripherial assigments.
 *
 * Note these are *not* hardware channel numbers.
 * PL330 driver creates dma_channel objects per peripherial, not per hardware
 * channel. Hardware channels (aka "threads" are assigned at channel request
 * time.
 * */

enum dma_ch {
	DMACH_UART0_TX = 0,
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

extern int opv5xc_gdma_init(void);

#endif /* __MACH_DMA_H */
