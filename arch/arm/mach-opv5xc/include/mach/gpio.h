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

#ifndef	_OPV5XC_GPIO_H
#define _OPV5XC_GPIO_H

/* MAX_GPIO_NO is defined in mach/opv5xc.h. Please don't change the header file
 * include oreder. */
#include <mach/opv5xc.h>
#define ARCH_NR_GPIOS		MAX_GPIO_NO

#include <asm-generic/gpio.h>

struct gpio_ctr_regs {
	u32	dout;			/* 0x00 */
	u32	din;			/* 0x04 */
	u32	dir;			/* 0x08 */
	u32	reserved1;
	u32	data_set;		/* 0x10 */
	u32	data_clr;		/* 0x14 */
	u32	reserved2[2];
	u32	int_en;			/* 0x20 */
	u32	int_raw;		/* 0x24 */
	u32	int_stat;		/* 0x28 */
	u32	int_msk;		/* 0x2C */
	u32	int_clr;		/* 0x30 */
	u32	int_trig;		/* 0x34 */
	u32	int_both;		/* 0x38 */
	u32	int_edge;		/* 0x3C */
	u32	bnc_en;			/* 0x40 */
	u32	bnc_prescl;		/* 0x44 */
	u32	reserved3[12];
	u32	bits;			/* 0x78 */
	u32	rev;			/* 0x7C */
};

#define GPIO_OUTPUT_OFFSET		0x00
#define GPIO_INPUT_OFFSET		0x04
#define GPIO_DIR_OFFSET			0x08
#define GPIO_BIT_SET_OFFSET		0x10
#define GPIO_BIT_CLEAR_OFFSET		0x14
#define GPIO_PULL_EN_OFFSET		0x18
#define GPIO_PULL_TYPE_OFFSET		0x1C
#define GPIO_INTR_ENABLE_OFFSET		0x20
#define GPIO_INTR_RAW_STATUS_OFFSET	0x24
#define GPIO_INTR_MASKED_STATUS_OFFSET	0x28
#define GPIO_INTR_MASK_OFFSET		0x2C
#define GPIO_INTR_CLEAR_OFFSET		0x30
#define GPIO_INTR_TRIGGER_METHOD_OFFSET	0x34
#define GPIO_INTR_TRIGGER_BOTH_EDGES_OFFSET	0x38
#define GPIO_INTR_TRIGGER_TYPE_OFFSET	0x3C
#define GPIO_BOUNCE_ENABLE_OFFSET	0x40
#define GPIO_BOUNCE_PRESCALE_OFFSET	0x44
#define GPIO_BITS_OFFSET		0x78
#define GPIO_REV_OFFSET			0x7C

#define gpio_get_value			__gpio_get_value
#define gpio_set_value			__gpio_set_value
#define gpio_cansleep			__gpio_cansleep
#define gpio_to_irq			__gpio_to_irq

#define GPIOA(n)			n
#define GPIOB(n)			(MAX_GPIOA_NO + n)

struct bank_data {
	int	bank;
	int	offset;
};

extern struct gpio gpios_pcm0[4];
extern struct gpio gpios_pcm1[4];
extern struct gpio gpios_i2s0[5];
extern struct gpio gpios_i2s1[5];
extern struct gpio gpios_clko[1];
extern struct gpio gpios_uart1[2];

/* Function prototype */
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
int opv5xc_sharepin_request(unsigned gpio, const char *label);
void opv5xc_sharepin_free(unsigned gpio);
int opv5xc_sharepin_request_array(struct gpio *array, size_t num);
void opv5xc_sharepin_free_array(struct gpio *array, size_t num);
#else
#define opv5xc_sharepin_request(...)
#define opv5xc_sharepin_free(...)
#define opv5xc_sharepin_request_array(...)
#define opv5xc_sharepin_free_array(...)
#endif

struct bank_data opv5xc_get_gpio_bank(unsigned gpio);

#endif /* _OPV5XC_GPIO_H */

