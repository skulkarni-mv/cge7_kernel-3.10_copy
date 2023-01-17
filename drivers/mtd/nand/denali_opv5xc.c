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

#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/mtd/mtd.h>
#include <linux/module.h>
#include <linux/io.h>
#include <linux/irq.h>
#include <linux/proc_fs.h>
#include <linux/debugfs.h>
#include <linux/platform_device.h>
#include <linux/mtd/denali_nand.h>

#include <mach/opv5xc.h>

#include "denali_opv5xc.h"

MODULE_LICENSE("GPL");

/* We define a module parameter that allows the user to override
 * the hardware and decide what timing mode should be used.
 */
#define NAND_DEFAULT_TIMINGS	-1

static int onfi_timing_mode = NAND_DEFAULT_TIMINGS;
module_param(onfi_timing_mode, int, S_IRUGO);
MODULE_PARM_DESC(onfi_timing_mode, "Overrides default ONFI setting."
			" -1 indicates use default timings");

#define DENALI_NAND_NAME    "denali-nand"

/* We define a macro here that combines all interrupts this driver uses into
 * a single constant value, for convenience. */
#define DENALI_IRQ_ALL	(INTR_STATUS__DMA_CMD_COMP | \
			INTR_STATUS__ECC_ERR | \
			INTR_STATUS__PROGRAM_FAIL | \
			INTR_STATUS__LOAD_COMP | \
			INTR_STATUS__PROGRAM_COMP | \
			INTR_STATUS__TIME_OUT | \
			INTR_STATUS__ERASE_FAIL | \
			INTR_STATUS__RST_COMP | \
			INTR_STATUS__ERASE_COMP)

/* indicates whether or not the internal value for the flash bank is
 * valid or not */
#define CHIP_SELECT_INVALID	-1

#define SUPPORT_8BITECC		1

/* This macro divides two integers and rounds fractional values up
 * to the nearest integer value. */
#define CEIL_DIV(X, Y) (((X)%(Y)) ? ((X)/(Y)+1) : ((X)/(Y)))

/* this macro allows us to convert from an MTD structure to our own
 * device context (denali) structure.
 */
#define mtd_to_denali(m) container_of(m, struct denali_nand_info, mtd)

/* These constants are defined by the driver to enable common driver
 * configuration options. */
#define SPARE_ACCESS		0x41
#define MAIN_ACCESS		0x42
#define MAIN_SPARE_ACCESS	0x43

#define DENALI_READ	0
#define DENALI_WRITE	0x100

/* types of device accesses. We can issue commands and get status */
#define COMMAND_CYCLE	0
#define ADDR_CYCLE	1
#define STATUS_CYCLE	2
#define NAND_ECC_ERR	-1

/* this is a helper macro that allows us to
 * format the bank into the proper bits for the controller */
#define BANK(x) ((x) << 24)

/* forward declarations */
static void clear_interrupts(struct denali_nand_info *denali);
static uint32_t wait_for_irq(struct denali_nand_info *denali,
							uint32_t irq_mask);
static void denali_irq_enable(struct denali_nand_info *denali,
							uint32_t int_mask);
static uint32_t read_interrupt_status(struct denali_nand_info *denali);

/* Certain operations for the denali NAND controller use
 * an indexed mode to read/write data. The operation is
 * performed by writing the address value of the command
 * to the device memory followed by the data. This function
 * abstracts this common operation.
*/
static void index_addr(struct denali_nand_info *denali,
				uint32_t address, uint32_t data)
{
	iowrite32(address, denali->flash_mem);
	iowrite32(data, denali->flash_mem + 0x10);
}

/* Perform an indexed read of the device */
static void index_addr_read_data(struct denali_nand_info *denali,
				 uint32_t address, uint32_t *pdata)
{
	iowrite32(address, denali->flash_mem);
	*pdata = ioread32(denali->flash_mem + 0x10);
}

/* We need to buffer some data for some of the NAND core routines.
 * The operations manage buffering that data. */
static void reset_buf(struct denali_nand_info *denali)
{
	denali->buf.head = denali->buf.tail = 0;
}

static void write_byte_to_buf(struct denali_nand_info *denali, uint8_t byte)
{
	BUG_ON(denali->buf.tail >= DENALI_BUF_SIZE);
	denali->buf.buf[denali->buf.tail++] = byte;
}

/* reads the status of the device */
static void read_status(struct denali_nand_info *denali)
{
	uint32_t cmd = 0x0;

	/* initialize the data buffer to store status */
	reset_buf(denali);

	cmd = ioread32(denali->flash_reg + WRITE_PROTECT);
	if (cmd)
		write_byte_to_buf(denali, NAND_STATUS_WP);
	else
		write_byte_to_buf(denali, 0);
}

/* resets a specific device connected to the core */
static void reset_bank(struct denali_nand_info *denali)
{
	uint32_t irq_status = 0;
	uint32_t irq_mask = INTR_STATUS__RST_COMP |
			    INTR_STATUS__TIME_OUT;

	clear_interrupts(denali);

	iowrite32(1 << denali->flash_bank, denali->flash_reg + DEVICE_RESET);

	irq_status = wait_for_irq(denali, irq_mask);

	if (irq_status & INTR_STATUS__TIME_OUT)
		dev_err(denali->dev, "reset bank failed.\n");
}

/* Reset the flash controller */
static uint16_t denali_nand_reset(struct denali_nand_info *denali)
{
	uint32_t i;

	dev_dbg(denali->dev, "%s, Line %d, Function: %s\n",
		       __FILE__, __LINE__, __func__);

	for (i = 0 ; i < denali->max_banks; i++)
		iowrite32(INTR_STATUS__RST_COMP | INTR_STATUS__TIME_OUT,
		denali->flash_reg + INTR_STATUS(i));

	for (i = 0 ; i < denali->max_banks; i++) {
		iowrite32(1 << i, denali->flash_reg + DEVICE_RESET);
		while (!(ioread32(denali->flash_reg +
				INTR_STATUS(i)) &
			(INTR_STATUS__RST_COMP | INTR_STATUS__TIME_OUT)))
			cpu_relax();
		if (ioread32(denali->flash_reg + INTR_STATUS(i)) &
			INTR_STATUS__TIME_OUT)
			dev_dbg(denali->dev,
			"NAND Reset operation timed out on bank %d\n", i);
	}

	for (i = 0; i < denali->max_banks; i++)
		iowrite32(INTR_STATUS__RST_COMP | INTR_STATUS__TIME_OUT,
			denali->flash_reg + INTR_STATUS(i));

	return PASS;
}

/* this routine calculates the ONFI timing values for a given mode and
 * programs the clocking register accordingly. The mode is determined by
 * the get_onfi_nand_para routine.
 */
static void nand_onfi_timing_set(struct denali_nand_info *denali,
								uint16_t mode)
{
	uint16_t Trea[6] = {40, 30, 25, 20, 20, 16};
	uint16_t Trp[6] = {50, 25, 17, 15, 12, 10};
	uint16_t Treh[6] = {30, 15, 15, 10, 10, 7};
	uint16_t Trc[6] = {100, 50, 35, 30, 25, 20};
	uint16_t Trhoh[6] = {0, 15, 15, 15, 15, 15};
	uint16_t Trloh[6] = {0, 0, 0, 0, 5, 5};
	uint16_t Tcea[6] = {100, 45, 30, 25, 25, 25};
	uint16_t Tadl[6] = {200, 100, 100, 100, 70, 70};
	uint16_t Trhw[6] = {200, 100, 100, 100, 100, 100};
	uint16_t Trhz[6] = {200, 100, 100, 100, 100, 100};
	uint16_t Twhr[6] = {120, 80, 80, 60, 60, 60};
	uint16_t Tcs[6] = {70, 35, 25, 25, 20, 15};

	uint16_t TclsRising = 1;
	uint16_t data_invalid_rhoh, data_invalid_rloh, data_invalid;
	uint16_t dv_window = 0;
	uint16_t en_lo, en_hi;
	uint16_t acc_clks;
	uint16_t addr_2_data, re_2_we, re_2_re, we_2_re, cs_cnt;

	dev_dbg(denali->dev, "%s, Line %d, Function: %s\n",
		       __FILE__, __LINE__, __func__);

	en_lo = CEIL_DIV(Trp[mode], CLK_X);
	en_hi = CEIL_DIV(Treh[mode], CLK_X);
#if ONFI_BLOOM_TIME
	if ((en_hi * CLK_X) < (Treh[mode] + 2))
		en_hi++;
#endif

	if ((en_lo + en_hi) * CLK_X < Trc[mode])
		en_lo += CEIL_DIV((Trc[mode] - (en_lo + en_hi) * CLK_X), CLK_X);

	if ((en_lo + en_hi) < CLK_MULTI)
		en_lo += CLK_MULTI - en_lo - en_hi;

	while (dv_window < 8) {
		data_invalid_rhoh = en_lo * CLK_X + Trhoh[mode];

		data_invalid_rloh = (en_lo + en_hi) * CLK_X + Trloh[mode];

		data_invalid =
		    data_invalid_rhoh <
		    data_invalid_rloh ? data_invalid_rhoh : data_invalid_rloh;

		dv_window = data_invalid - Trea[mode];

		if (dv_window < 8)
			en_lo++;
	}

	acc_clks = CEIL_DIV(Trea[mode], CLK_X);

	while (((acc_clks * CLK_X) - Trea[mode]) < 3)
		acc_clks++;

	if ((data_invalid - acc_clks * CLK_X) < 2)
		dev_warn(denali->dev, "%s, Line %d: Warning!\n",
			__FILE__, __LINE__);

	addr_2_data = CEIL_DIV(Tadl[mode], CLK_X);
	re_2_we = CEIL_DIV(Trhw[mode], CLK_X);
	re_2_re = CEIL_DIV(Trhz[mode], CLK_X);
	we_2_re = CEIL_DIV(Twhr[mode], CLK_X);
	cs_cnt = CEIL_DIV((Tcs[mode] - Trp[mode]), CLK_X);
	if (!TclsRising)
		cs_cnt = CEIL_DIV(Tcs[mode], CLK_X);
	if (cs_cnt == 0)
		cs_cnt = 1;

	if (Tcea[mode]) {
		while (((cs_cnt * CLK_X) + Trea[mode]) < Tcea[mode])
			cs_cnt++;
	}

#if MODE5_WORKAROUND
	if (mode == 5)
		acc_clks = 5;
#endif

	/* Sighting 3462430: Temporary hack for MT29F128G08CJABAWP:B */
	if ((ioread32(denali->flash_reg + MANUFACTURER_ID) == 0) &&
		(ioread32(denali->flash_reg + DEVICE_ID) == 0x88))
		acc_clks = 6;

	iowrite32(acc_clks, denali->flash_reg + ACC_CLKS);
	iowrite32(re_2_we, denali->flash_reg + RE_2_WE);
	iowrite32(re_2_re, denali->flash_reg + RE_2_RE);
	iowrite32(we_2_re, denali->flash_reg + WE_2_RE);
	iowrite32(addr_2_data, denali->flash_reg + ADDR_2_DATA);
	iowrite32(en_lo, denali->flash_reg + RDWR_EN_LO_CNT);
	iowrite32(en_hi, denali->flash_reg + RDWR_EN_HI_CNT);
	iowrite32(cs_cnt, denali->flash_reg + CS_SETUP_CNT);
}

/* queries the NAND device to see what ONFI modes it supports. */
static uint16_t get_onfi_nand_para(struct denali_nand_info *denali)
{
	int i;
	/* we needn't to do a reset here because driver has already
	 * reset all the banks before
	 * */
	if (!(ioread32(denali->flash_reg + ONFI_TIMING_MODE) &
		ONFI_TIMING_MODE__VALUE))
		return FAIL;

	for (i = 5; i > 0; i--) {
		if (ioread32(denali->flash_reg + ONFI_TIMING_MODE) &
			(0x01 << i))
			break;
	}

	nand_onfi_timing_set(denali, i);

	/* By now, all the ONFI devices we know support the page cache */
	/* rw feature. So here we enable the pipeline_rw_ahead feature */
	/* iowrite32(1, denali->flash_reg + CACHE_WRITE_ENABLE); */
	/* iowrite32(1, denali->flash_reg + CACHE_READ_ENABLE);  */

	return PASS;
}

static void get_samsung_nand_para(struct denali_nand_info *denali,
							uint8_t device_id)
{
	if (device_id == 0xd3) { /* Samsung K9WAG08U1A */
		/* Set timing register values according to datasheet */
		iowrite32(5, denali->flash_reg + ACC_CLKS);
		iowrite32(20, denali->flash_reg + RE_2_WE);
		iowrite32(12, denali->flash_reg + WE_2_RE);
		iowrite32(14, denali->flash_reg + ADDR_2_DATA);
		iowrite32(3, denali->flash_reg + RDWR_EN_LO_CNT);
		iowrite32(2, denali->flash_reg + RDWR_EN_HI_CNT);
		iowrite32(2, denali->flash_reg + CS_SETUP_CNT);
	}
}

static void get_toshiba_nand_para(struct denali_nand_info *denali, uint8_t device_id)
{
	uint32_t read_register;
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	uint32_t sys_clk_ctrl2 = 0;
#endif
	switch (device_id) {
	case 0xd3:
		iowrite32(0x98, denali->flash_reg + MANUFACTURER_ID);
		iowrite32(1, denali->flash_reg + NUMBER_OF_PLANES);
		iowrite32(64, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(4096, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(232, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		iowrite32(1, denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
		iowrite32(4, denali->flash_reg + ECC_CORRECTION);

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
		sys_clk_ctrl2 = ioread32(OPV5XC_CR_PMU_BASE_VIRT + 0x30);
		sys_clk_ctrl2 &= ~(7 << 24); /* clear bits 24:26 */
		sys_clk_ctrl2 |= (5 << 24); /* NFC clock set to 46.875 MHz */
		iowrite32(sys_clk_ctrl2, (OPV5XC_CR_PMU_BASE_VIRT + 0x30));
#endif

		read_register = ioread32(denali->flash_reg + WE_2_RE);
		read_register &= ~(63 << 0);   /* clear bits 5:0 we_2_re */
		read_register &= ~(63 << 8);   /* clear bits 13:8 twhr2 */
		iowrite32((read_register | (0x3 << 0) | (0x0 << 8)) ,
			denali->flash_reg + WE_2_RE);  /* 3 clock cycles ~ 60ns */

		read_register = ioread32(denali->flash_reg + ADDR_2_DATA);
		read_register &= ~(127 << 0);  /* clear bits 6:0 addr_2_data */
		read_register &= ~(63 << 8);   /* clear bits 13:8 tcwaw */
		iowrite32((read_register | (0x1 << 0) | (0x1 << 8)) ,
			denali->flash_reg + ADDR_2_DATA);      /* 3 clock cycles ~ 60ns */

		read_register = ioread32(denali->flash_reg + RE_2_WE);
		read_register &= ~(63 << 0); /* clear bits 5:0 re_2_we */
		iowrite32((read_register | 0x3),
			denali->flash_reg + RE_2_WE);

		read_register = ioread32(denali->flash_reg + RE_2_RE); /* clear bits 5:0 */
		read_register &= ~(63 << 0); /* clear bits 5:0 re_2_we */
		iowrite32((read_register | 0x0),
			denali->flash_reg + RE_2_RE);

		read_register = ioread32(denali->flash_reg + RDWR_EN_LO_CNT);
		read_register &= ~(31 << 0);
		iowrite32((read_register | 0x3),   /* Trp/Twp is 12ns. Controller clock cycle is 21 ns */
			denali->flash_reg + RDWR_EN_LO_CNT);

		read_register = ioread32(denali->flash_reg + RDWR_EN_HI_CNT);
		read_register &= ~(31 << 0);
		iowrite32((read_register | 0x1),   /* Treh/Tweh is 10ns. Controller clock cycle is 21 ns */
			denali->flash_reg + RDWR_EN_HI_CNT);

		read_register = ioread32(denali->flash_reg + CS_SETUP_CNT);
		read_register &= ~(31 << 0) | ~(63 << 12);     /* Tcs is 20ns. Twb = 100ns (Max value) */
		iowrite32((read_register | (1<<0) | (1 << 12)),
			denali->flash_reg + CS_SETUP_CNT);
		break;
	case 0xd1:
		iowrite32(0x98, denali->flash_reg + MANUFACTURER_ID);
		iowrite32(1, denali->flash_reg + NUMBER_OF_PLANES);
		iowrite32(64, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(2048, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(64, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		iowrite32(1, denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
		break;
	case 0xf1:
		iowrite32(0x98, denali->flash_reg + MANUFACTURER_ID);
		iowrite32(0, denali->flash_reg + NUMBER_OF_PLANES);
		iowrite32(64, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(2048, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(128, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		iowrite32(1, denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
		break;
	default:
		printk(KERN_ERR "Spetra: Unknown Toshiba NAND (Device ID: 0x%x) \
			 Will use default parameter values instead", device_id);
		break;
	}
}

static void get_hynix_nand_para(struct denali_nand_info *denali,
							uint8_t device_id)
{
	uint32_t main_size, spare_size;

	switch (device_id) {
	case 0xD5: /* Hynix H27UAG8T2A, H27UBG8U5A or H27UCG8VFA */
	case 0xD7: /* Hynix H27UDG8VEM, H27UCG8UDM or H27UCG8V5A */
		iowrite32(128, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(4096, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(224, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		main_size = 4096 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		spare_size = 224 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(main_size,
				denali->flash_reg + LOGICAL_PAGE_DATA_SIZE);
		iowrite32(spare_size,
				denali->flash_reg + LOGICAL_PAGE_SPARE_SIZE);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
#if SUPPORT_15BITECC
		iowrite32(15, denali->flash_reg + ECC_CORRECTION);
#elif SUPPORT_8BITECC
		iowrite32(8, denali->flash_reg + ECC_CORRECTION);
#endif
		break;
	default:
		dev_warn(denali->dev,
			"Spectra: Unknown Hynix NAND (Device ID: 0x%x)."
			"Will use default parameter values instead.\n",
			device_id);
	}
}

static void get_micron_nand_para(struct denali_nand_info *denali,
							uint8_t device_id)
{
	uint32_t main_size, spare_size;

	switch (device_id) {
	case 0x68:
		iowrite32(0x2C, denali->flash_reg + MANUFACTURER_ID);
		iowrite32(0x68, denali->flash_reg + DEVICE_ID);
		iowrite32(1, denali->flash_reg + NUMBER_OF_PLANES);
		iowrite32(128, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(8192, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(448, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		iowrite32(1, denali->flash_reg + DEVICES_CONNECTED);

		main_size = 8192 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		spare_size = 448 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(main_size,
			denali->flash_reg + LOGICAL_PAGE_DATA_SIZE);
		iowrite32(spare_size,
			denali->flash_reg + LOGICAL_PAGE_SPARE_SIZE);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
		break;
	case 0x88:
		iowrite32(0x2C, denali->flash_reg + MANUFACTURER_ID);
		iowrite32(0x88, denali->flash_reg + DEVICE_ID);
		iowrite32(1, denali->flash_reg + NUMBER_OF_PLANES);
		iowrite32(256, denali->flash_reg + PAGES_PER_BLOCK);
		iowrite32(8192, denali->flash_reg + DEVICE_MAIN_AREA_SIZE);
		iowrite32(448, denali->flash_reg + DEVICE_SPARE_AREA_SIZE);
		iowrite32(1, denali->flash_reg + DEVICES_CONNECTED);

		main_size = 8192 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		spare_size = 448 *
			ioread32(denali->flash_reg + DEVICES_CONNECTED);
		iowrite32(main_size,
			denali->flash_reg + LOGICAL_PAGE_DATA_SIZE);
		iowrite32(spare_size,
			denali->flash_reg + LOGICAL_PAGE_SPARE_SIZE);
		iowrite32(0, denali->flash_reg + DEVICE_WIDTH);
		break;

	default:
		printk(
			"Spectra: Unknown Micron NAND (Device ID: 0x%x)."
			"Will use default parameter values instead.\n",
			device_id);
	}
}

/* determines how many NAND chips are connected to the controller. Note for
 * Intel CE4100 devices we don't support more than one device.
 */
static void find_valid_banks(struct denali_nand_info *denali)
{
	uint32_t id[denali->max_banks];
	int i;

	denali->total_used_banks = 1;
	for (i = 0; i < denali->max_banks; i++) {
		index_addr(denali, (uint32_t)(MODE_11 | (i << 24) | 0), 0x90);
		index_addr(denali, (uint32_t)(MODE_11 | (i << 24) | 1), 0);
		index_addr_read_data(denali,
				(uint32_t)(MODE_11 | (i << 24) | 2), &id[i]);

		dev_dbg(denali->dev,
			"Return 1st ID for bank[%d]: %x\n", i, id[i]);

		if (i == 0) {
			if (!(id[i] & 0x0ff))
				break; /* WTF? */
		} else {
			if ((id[i] & 0x0ff) == (id[0] & 0x0ff))
				denali->total_used_banks++;
			else
				break;
		}
	}

	dev_dbg(denali->dev,
		"denali->total_used_banks: %d\n", denali->total_used_banks);
}

/*
 * Use the configuration feature register to determine the maximum number of
 * banks that the hardware supports.
 */
static void detect_max_banks(struct denali_nand_info *denali)
{
	uint32_t features = ioread32(denali->flash_reg + FEATURES);

	denali->max_banks = 1 << (features & FEATURES__N_BANKS);
}

static void detect_partition_feature(struct denali_nand_info *denali)
{
	/* For MRST platform, denali->fwblks represent the
	 * number of blocks firmware is taken,
	 * FW is in protect partition and MTD driver has no
	 * permission to access it. So let driver know how many
	 * blocks it can't touch.
	 * */
	if (ioread32(denali->flash_reg + FEATURES) & FEATURES__PARTITION) {
		if ((ioread32(denali->flash_reg + PERM_SRC_ID(1)) &
			PERM_SRC_ID__SRCID) == SPECTRA_PARTITION_ID) {
			denali->fwblks =
			    ((ioread32(denali->flash_reg + MIN_MAX_BANK(1)) &
			      MIN_MAX_BANK__MIN_VALUE) *
			     denali->blksperchip)
			    +
			    (ioread32(denali->flash_reg + MIN_BLK_ADDR(1)) &
			    MIN_BLK_ADDR__VALUE);
		} else
			denali->fwblks = SPECTRA_START_BLOCK;
	} else
		denali->fwblks = SPECTRA_START_BLOCK;
}

static uint16_t denali_nand_timing_set(struct denali_nand_info *denali)
{
	uint16_t status = PASS;
	uint32_t id_bytes[5], addr;
	uint8_t i, maf_id, device_id;

	dev_dbg(denali->dev,
			"%s, Line %d, Function: %s\n",
			__FILE__, __LINE__, __func__);

	/* Use read id method to get device ID and other
	 * params. For some NAND chips, controller can't
	 * report the correct device ID by reading from
	 * DEVICE_ID register
	 * */
	addr = (uint32_t)MODE_11 | BANK(denali->flash_bank);
	index_addr(denali, (uint32_t)addr | 0, 0x90);
	index_addr(denali, (uint32_t)addr | 1, 0);
	for (i = 0; i < 5; i++)
		index_addr_read_data(denali, addr | 2, &id_bytes[i]);
	maf_id = id_bytes[0];
	device_id = id_bytes[1];

	denali->maf_id = maf_id;
	denali->device_id = device_id;

	if (ioread32(denali->flash_reg + ONFI_DEVICE_NO_OF_LUNS) &
		ONFI_DEVICE_NO_OF_LUNS__ONFI_DEVICE) { /* ONFI 1.0 NAND */
		if (FAIL == get_onfi_nand_para(denali))
			return FAIL;
	} else if (maf_id == 0xEC) { /* Samsung NAND */
		get_samsung_nand_para(denali, device_id);
	} else if (maf_id == 0x98) { /* Toshiba NAND */
		get_toshiba_nand_para(denali, device_id);
	} else if (maf_id == 0xAD) { /* Hynix NAND */
		get_hynix_nand_para(denali, device_id);
	} else if (maf_id == 0x2C) { /* Micron NAND */
		get_micron_nand_para(denali, device_id);
	}

	dev_info(denali->dev,
			"Dump timing register values:"
			"acc_clks: %d, re_2_we: %d, re_2_re: %d\n"
			"we_2_re: %d, addr_2_data: %d, rdwr_en_lo_cnt: %d\n"
			"rdwr_en_hi_cnt: %d, cs_setup_cnt: %d\n",
			ioread32(denali->flash_reg + ACC_CLKS),
			ioread32(denali->flash_reg + RE_2_WE),
			ioread32(denali->flash_reg + RE_2_RE),
			ioread32(denali->flash_reg + WE_2_RE),
			ioread32(denali->flash_reg + ADDR_2_DATA),
			ioread32(denali->flash_reg + RDWR_EN_LO_CNT),
			ioread32(denali->flash_reg + RDWR_EN_HI_CNT),
			ioread32(denali->flash_reg + CS_SETUP_CNT));

	find_valid_banks(denali);

	detect_partition_feature(denali);

	/* If the user specified to override the default timings
	 * with a specific ONFI mode, we apply those changes here.
	 */
	if (onfi_timing_mode != NAND_DEFAULT_TIMINGS)
		nand_onfi_timing_set(denali, onfi_timing_mode);

	return status;
}

static void denali_set_intr_modes(struct denali_nand_info *denali,
					uint16_t INT_ENABLE)
{
	dev_dbg(denali->dev, "%s, Line %d, Function: %s\n",
		       __FILE__, __LINE__, __func__);

	if (INT_ENABLE)
		iowrite32(1, denali->flash_reg + GLOBAL_INT_ENABLE);
	else
		iowrite32(0, denali->flash_reg + GLOBAL_INT_ENABLE);
}

/* validation function to verify that the controlling software is making
 * a valid request
 */
static inline bool is_flash_bank_valid(int flash_bank)
{
	return (flash_bank >= 0 && flash_bank < 4);
}

static void denali_irq_init(struct denali_nand_info *denali)
{
	uint32_t int_mask = 0;
	int i;

	/* Disable global interrupts */
	denali_set_intr_modes(denali, false);

	int_mask = DENALI_IRQ_ALL;

	/* Clear all status bits */
	for (i = 0; i < denali->max_banks; ++i)
		iowrite32(0xFFFF, denali->flash_reg + INTR_STATUS(i));

	denali_irq_enable(denali, int_mask);
}

static void denali_irq_cleanup(int irqnum, struct denali_nand_info *denali)
{
	denali_set_intr_modes(denali, false);
	free_irq(irqnum, denali);
}

static void denali_irq_enable(struct denali_nand_info *denali,
							uint32_t int_mask)
{
	int i;

	for (i = 0; i < denali->max_banks; ++i)
		iowrite32(int_mask, denali->flash_reg + INTR_EN(i));
}

/* This function only returns when an interrupt that this driver cares about
 * occurs. This is to reduce the overhead of servicing interrupts
 */
static inline uint32_t denali_irq_detected(struct denali_nand_info *denali)
{
	return read_interrupt_status(denali) & DENALI_IRQ_ALL;
}

/* Interrupts are cleared by writing a 1 to the appropriate status bit */
static inline void clear_interrupt(struct denali_nand_info *denali,
							uint32_t irq_mask)
{
	uint32_t intr_status_reg = 0;

	intr_status_reg = INTR_STATUS(denali->flash_bank);

	iowrite32(irq_mask, denali->flash_reg + intr_status_reg);
}

static void clear_interrupts(struct denali_nand_info *denali)
{
	uint32_t status = 0x0;
	spin_lock_irq(&denali->irq_lock);

	status = read_interrupt_status(denali);
	clear_interrupt(denali, status);

	denali->irq_status = 0x0;
	spin_unlock_irq(&denali->irq_lock);
}

static uint32_t read_interrupt_status(struct denali_nand_info *denali)
{
	uint32_t intr_status_reg = 0;

	intr_status_reg = INTR_STATUS(denali->flash_bank);

	return ioread32(denali->flash_reg + intr_status_reg);
}

/* This is the interrupt service routine. It handles all interrupts
 * sent to this device. Note that on CE4100, this is a shared
 * interrupt.
 */
static irqreturn_t denali_isr(int irq, void *dev_id)
{
	struct denali_nand_info *denali = dev_id;
	uint32_t irq_status = 0x0;
	irqreturn_t result = IRQ_NONE;

	spin_lock(&denali->irq_lock);

	/* check to see if a valid NAND chip has
	 * been selected.
	 */
	if (is_flash_bank_valid(denali->flash_bank)) {
		/* check to see if controller generated
		 * the interrupt, since this is a shared interrupt */
		irq_status = denali_irq_detected(denali);
		if (irq_status != 0) {
			/* handle interrupt */
			/* first acknowledge it */
			clear_interrupt(denali, irq_status);
			/* store the status in the device context for someone
			   to read */
			denali->irq_status |= irq_status;
			/* notify anyone who cares that it happened */
			complete(&denali->complete);
			/* tell the OS that we've handled this */
			result = IRQ_HANDLED;
		}
	}
	spin_unlock(&denali->irq_lock);
	return result;
}
#define BANK(x) ((x) << 24)

static uint32_t wait_for_irq(struct denali_nand_info *denali, uint32_t irq_mask)
{
	unsigned long comp_res = 0;
	uint32_t intr_status = 0;
	bool retry = false;
	unsigned long timeout = msecs_to_jiffies(1000);

	do {
		comp_res =
			wait_for_completion_timeout(&denali->complete, timeout);
		spin_lock_irq(&denali->irq_lock);
		intr_status = denali->irq_status;

		if (intr_status & irq_mask) {
			denali->irq_status &= ~irq_mask;
			spin_unlock_irq(&denali->irq_lock);
			/* our interrupt was detected */
			break;
		} else {
			/* these are not the interrupts you are looking for -
			 * need to wait again */
			spin_unlock_irq(&denali->irq_lock);
			retry = true;
		}
	} while (comp_res != 0);

	if (comp_res == 0) {
		/* timeout */
		pr_err("timeout occurred, status = 0x%x, mask = 0x%x\n",
				intr_status, irq_mask);

		intr_status = 0;
	}
	return intr_status;
}

/* This helper function setups the registers for ECC and whether or not
 * the spare area will be transferred. */
static void setup_ecc_for_xfer(struct denali_nand_info *denali, bool ecc_en,
				bool transfer_spare)
{
	int ecc_en_flag = 0, transfer_spare_flag = 0;

	/* set ECC, transfer spare bits if needed */
	ecc_en_flag = ecc_en ? ECC_ENABLE__FLAG : 0;
	transfer_spare_flag = transfer_spare ? TRANSFER_SPARE_REG__FLAG : 0;

	/* Enable spare area/ECC per user's request. */
	iowrite32(ecc_en_flag, denali->flash_reg + ECC_ENABLE);
	iowrite32(transfer_spare_flag,
			denali->flash_reg + TRANSFER_SPARE_REG);
}

/* sends a pipeline command operation to the controller. See the Denali NAND
 * controller's user guide for more information (section 4.2.3.6).
 */
static int denali_send_pipeline_cmd(struct denali_nand_info *denali,
							bool ecc_en,
							bool transfer_spare,
							int access_type,
							int op)
{
	int status = PASS;
	uint32_t addr = 0x0, cmd = 0x0, page_count = 1, irq_status = 0,
		 irq_mask = 0;

	if (op == DENALI_READ)
		irq_mask = INTR_STATUS__LOAD_COMP;
	else if (op == DENALI_WRITE)
		irq_mask = 0;
	else
		BUG();

	setup_ecc_for_xfer(denali, ecc_en, transfer_spare);

	/* clear interrupts */
	clear_interrupts(denali);

	addr = BANK(denali->flash_bank) | denali->page;

	if (op == DENALI_WRITE && access_type != SPARE_ACCESS) {
		cmd = MODE_01 | addr;
		iowrite32(cmd, denali->flash_mem);
	} else if (op == DENALI_WRITE && access_type == SPARE_ACCESS) {
		/* read spare area */
		cmd = MODE_10 | addr;
		index_addr(denali, (uint32_t)cmd, access_type);

		cmd = MODE_01 | addr;
		iowrite32(cmd, denali->flash_mem);
	} else if (op == DENALI_READ) {
		/* setup page read request for access type */
		cmd = MODE_10 | addr;
		index_addr(denali, (uint32_t)cmd, access_type);

		/* page 33 of the NAND controller spec indicates we should not
		   use the pipeline commands in Spare area only mode. So we
		   don't.
		 */
		if (access_type == SPARE_ACCESS) {
			cmd = MODE_01 | addr;
			iowrite32(cmd, denali->flash_mem);
		} else {
			index_addr(denali, (uint32_t)cmd,
					0x2000 | op | page_count);

			/* wait for command to be accepted
			 * can always use status0 bit as the
			 * mask is identical for each
			 * bank. */
			irq_status = wait_for_irq(denali, irq_mask);

			if (irq_status == 0) {
				dev_err(denali->dev,
						"cmd, page, addr on timeout "
						"(0x%x, 0x%x, 0x%x)\n",
						cmd, denali->page, addr);
				status = FAIL;
			} else {
				cmd = MODE_01 | addr;
				iowrite32(cmd, denali->flash_mem);
			}
		}
	}
	return status;
}

/* helper function that simply writes a buffer to the flash */
static int write_data_to_flash_mem(struct denali_nand_info *denali,
							const uint8_t *buf,
							int len)
{
	uint32_t i = 0, *buf32;

	/* verify that the len is a multiple of 4. see comment in
	 * read_data_from_flash_mem() */
	BUG_ON((len % 4) != 0);

	/* write the data to the flash memory */
	buf32 = (uint32_t *)buf;
	for (i = 0; i < len / 4; i++)
		iowrite32(*buf32++, denali->flash_mem + 0x10);
	return i*4; /* intent is to return the number of bytes read */
}

/* helper function that simply reads a buffer from the flash */
static int read_data_from_flash_mem(struct denali_nand_info *denali,
								uint8_t *buf,
								int len)
{
	uint32_t i = 0, *buf32;

	/* we assume that len will be a multiple of 4, if not
	 * it would be nice to know about it ASAP rather than
	 * have random failures...
	 * This assumption is based on the fact that this
	 * function is designed to be used to read flash pages,
	 * which are typically multiples of 4...
	 */

	BUG_ON((len % 4) != 0);

	/* transfer the data from the flash */
	buf32 = (uint32_t *)buf;
	for (i = 0; i < len / 4; i++)
		*buf32++ = ioread32(denali->flash_mem + 0x10);
	return i*4; /* intent is to return the number of bytes read */
}

/* writes OOB data to the device */
static int write_oob_data(struct mtd_info *mtd, uint8_t *buf, int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	uint32_t irq_status = 0, addr = 0x0, cmd = 0x0;
	uint32_t irq_mask = INTR_STATUS__PROGRAM_COMP |
						INTR_STATUS__PROGRAM_FAIL;
	int status = 0;

	denali->page = page;

	if (denali_send_pipeline_cmd(denali, false, false, SPARE_ACCESS,
							DENALI_WRITE) == PASS) {
		write_data_to_flash_mem(denali, buf, mtd->oobsize);

		/* wait for operation to complete */
		irq_status = wait_for_irq(denali, irq_mask);

		if (irq_status == 0) {
			dev_err(denali->dev, "OOB write failed\n");
			status = -EIO;
		}

		/* We set the device back to MAIN_ACCESS here as I observed
		 * instability with the controller if you do a block erase
		 * and the last transaction was a SPARE_ACCESS. Block erase
		 * is reliable (according to the MTD test infrastructure)
		 * if you are in MAIN_ACCESS.
		 */
		addr = BANK(denali->flash_bank) | denali->page;
		cmd = MODE_10 | addr;
		index_addr(denali, (uint32_t)cmd, MAIN_ACCESS);

	} else {
		dev_err(denali->dev, "unable to send pipeline command\n");
		status = -EIO;
	}
	return status;
}

/* reads OOB data from the device */
static void read_oob_data(struct mtd_info *mtd, uint8_t *buf, int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	uint32_t irq_mask = INTR_STATUS__LOAD_COMP,
			 irq_status = 0, addr = 0x0, cmd = 0x0;

	denali->page = page;

	if (denali_send_pipeline_cmd(denali, false, true, SPARE_ACCESS,
							DENALI_READ) == PASS) {
		read_data_from_flash_mem(denali, buf, mtd->oobsize);

		/* wait for command to be accepted
		 * can always use status0 bit as the mask is identical for each
		 * bank. */
		irq_status = wait_for_irq(denali, irq_mask);

		if (irq_status == 0)
			dev_err(denali->dev, "page on OOB timeout %u\n",
					denali->page);

		/* We set the device back to MAIN_ACCESS here as I observed
		 * instability with the controller if you do a block erase
		 * and the last transaction was a SPARE_ACCESS. Block erase
		 * is reliable (according to the MTD test infrastructure)
		 * if you are in MAIN_ACCESS.
		 */
		addr = BANK(denali->flash_bank) | denali->page;
		cmd = MODE_10 | addr;
		index_addr(denali, (uint32_t)cmd, MAIN_ACCESS);
	}
}

/* this function examines buffers to see if they contain data that
 * indicate that the buffer is part of an erased region of flash.
 */
bool is_erased(uint8_t *buf, int len)
{
	int i = 0;
	for (i = 0; i < len; i++)
		if (buf[i] != 0xFF)
			return false;
	return true;
}
#define ECC_SECTOR_SIZE 512

#define ECC_SECTOR(x)	(((x) & ECC_ERROR_ADDRESS__SECTOR_NR) >> 12)
#define ECC_BYTE(x)	(((x) & ECC_ERROR_ADDRESS__OFFSET))
#define ECC_CORRECTION_VALUE(x) ((x) & ERR_CORRECTION_INFO__BYTEMASK)
#define ECC_ERROR_CORRECTABLE(x) (!((x) & ERR_CORRECTION_INFO__ERROR_TYPE))
#define ECC_ERR_DEVICE(x)	(((x) & ERR_CORRECTION_INFO__DEVICE_NR) >> 8)
#define ECC_LAST_ERR(x)		((x) & ERR_CORRECTION_INFO__LAST_ERR_INFO)
/* programs the controller to either enable/disable DMA transfers */
static void denali_enable_dma(struct denali_nand_info *denali, bool en)
{
	uint32_t reg_val = 0x0;

	if (en)
		reg_val = DMA_ENABLE__FLAG;

	iowrite32(reg_val, denali->flash_reg + DMA_ENABLE);
	ioread32(denali->flash_reg + DMA_ENABLE);
}

/* setups the HW to perform the data DMA */
static void denali_setup_dma(struct denali_nand_info *denali, int op)
{
	uint32_t mode = 0x0;
	const int page_count = 1;
	dma_addr_t addr = denali->buf.dma_buf;

	mode = MODE_10 | BANK(denali->flash_bank);

	/* DMA is a three step process */

	/* 1: 24 INT, 23:16 BurstLength, 15:12 0x2, 11:8 read/write-0/1, 7:0 page
	 * -> interrupt when complete, burst len = 64 bytes
	 */
	index_addr(denali, mode | denali->page,
	(1 << 24) | (0x40 << 16) | 0x2000 | op | page_count);

	/* 2:  Memory address [31:0] */
	index_addr(denali, mode | denali->page, (uint32_t)addr);

	/* 3:  Memory address [63:32] */
	index_addr(denali, mode | denali->page, 0x0);
}

/* writes a page. user specifies type, and this function handles the
 * configuration details. */
static int write_page(struct mtd_info *mtd, struct nand_chip *chip,
			const uint8_t *buf, bool raw_xfer)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	dma_addr_t addr = denali->buf.dma_buf;
	size_t size = denali->mtd.writesize + denali->mtd.oobsize;

	uint32_t irq_status = 0;
	uint32_t irq_mask = INTR_STATUS__DMA_CMD_COMP |
						INTR_STATUS__PROGRAM_FAIL;

	/* if it is a raw xfer, we want to disable ecc, and send
	 * the spare area.
	 * !raw_xfer - enable ecc
	 * raw_xfer - transfer spare
	 */
	setup_ecc_for_xfer(denali, !raw_xfer, raw_xfer);

	/* copy buffer into DMA buffer */
	memcpy(denali->buf.buf, buf, mtd->writesize);

	if (raw_xfer) {
		/* transfer the data to the spare area */
		memcpy(denali->buf.buf + mtd->writesize,
			chip->oob_poi,
			mtd->oobsize);
	}

	dma_sync_single_for_device(denali->dev, addr, size, DMA_TO_DEVICE);

	clear_interrupts(denali);
	denali_enable_dma(denali, true);

	denali_setup_dma(denali, DENALI_WRITE);

	/* wait for operation to complete */
	irq_status = wait_for_irq(denali, irq_mask);

	if (irq_status == 0) {
		dev_err(denali->dev,
				"timeout on write_page (type = %d)\n",
				raw_xfer);
		denali->status =
			(irq_status & INTR_STATUS__PROGRAM_FAIL) ?
			NAND_STATUS_FAIL : PASS;
	}

	denali_enable_dma(denali, false);
	dma_sync_single_for_cpu(denali->dev, addr, size, DMA_TO_DEVICE);

	return 0;
}

/* NAND core entry points */

/* this is the callback that the NAND core calls to write a page. Since
 * writing a page with ECC or without is similar, all the work is done
 * by write_page above.
 * */
static int denali_write_page(struct mtd_info *mtd, struct nand_chip *chip,
				const uint8_t *buf, int oob_required)
{
	/* for regular page writes, we let HW handle all the ECC
	 * data written to the device. */
	return write_page(mtd, chip, buf, false);
}

/* This is the callback that the NAND core calls to write a page without ECC.
 * raw access is similar to ECC page writes, so all the work is done in the
 * write_page() function above.
 */
static int denali_write_page_raw(struct mtd_info *mtd, struct nand_chip *chip,
					const uint8_t *buf, int oob_required)
{
	/* for raw page writes, we want to disable ECC and simply write
	 * whatever data is in the buffer. */
	return write_page(mtd, chip, buf, true);
}

static int denali_write_oob(struct mtd_info *mtd, struct nand_chip *chip,
			    int page)
{
	return write_oob_data(mtd, chip->oob_poi, page);
}

static int denali_read_oob(struct mtd_info *mtd, struct nand_chip *chip,
			   int page)
{
	read_oob_data(mtd, chip->oob_poi, page);

	return 0; /* notify NAND core to send command to
			   NAND device. */
}

static int denali_read_page(struct mtd_info *mtd, struct nand_chip *chip,
			    uint8_t *buf, int oob_required, int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	dma_addr_t addr = denali->buf.dma_buf;
	size_t size = denali->mtd.writesize + denali->mtd.oobsize;

	uint32_t irq_status = 0;
	uint32_t irq_mask = INTR_STATUS__ECC_ERR;
	irq_mask |= INTR_STATUS__DMA_CMD_COMP;

	if (page != denali->page) {
		dev_err(denali->dev, "IN %s: page %d is not \
				equal to denali->page %u, investigate!!",
				__func__, page, denali->page);
		BUG();
	}

	setup_ecc_for_xfer(denali, true, false);

	denali_enable_dma(denali, true);
	dma_sync_single_for_device(denali->dev, addr, size, DMA_FROM_DEVICE);

	clear_interrupts(denali);
	denali_setup_dma(denali, DENALI_READ);

	/* wait for operation to complete */
	irq_status = wait_for_irq(denali, irq_mask);
	while ((irq_status & INTR_STATUS__DMA_CMD_COMP)
		|| (irq_status & INTR_STATUS__ECC_ERR)) {
		break;
	}
	clear_interrupts(denali);

	dma_sync_single_for_cpu(denali->dev, addr, size, DMA_FROM_DEVICE);

	memcpy(buf, denali->buf.buf, mtd->writesize);

	denali_enable_dma(denali, false);

	if (irq_status & INTR_STATUS__ECC_ERR) {
		if (!is_erased(buf, denali->mtd.writesize)) {
			printk(KERN_EMERG "%s: %d irq_status = 0x%x Ecc error occurred on page = 0x%x\n",
			__func__, __LINE__, irq_status, page);
			mtd->ecc_stats.failed++;
		}
	}
	return 0;
}

static int denali_read_page_raw(struct mtd_info *mtd, struct nand_chip *chip,
				uint8_t *buf, int oob_required, int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	dma_addr_t addr = denali->buf.dma_buf;
	size_t size = denali->mtd.writesize + denali->mtd.oobsize;

	uint32_t irq_status = 0;
	uint32_t irq_mask = INTR_STATUS__DMA_CMD_COMP;

	if (page != denali->page) {
		dev_err(denali->dev, "IN %s: page %d is not \
				equal to denali->page %u, investigate!!",
				__func__, page, denali->page);
		BUG();
	}

	setup_ecc_for_xfer(denali, false, true);
	denali_enable_dma(denali, true);

	dma_sync_single_for_device(denali->dev, addr, size, DMA_FROM_DEVICE);

	clear_interrupts(denali);
	denali_setup_dma(denali, DENALI_READ);

	/* wait for operation to complete */
	irq_status = wait_for_irq(denali, irq_mask);

	dma_sync_single_for_cpu(denali->dev, addr, size, DMA_FROM_DEVICE);

	denali_enable_dma(denali, false);

	memcpy(buf, denali->buf.buf, mtd->writesize);
	memcpy(chip->oob_poi, denali->buf.buf + mtd->writesize, mtd->oobsize);

	return 0;
}

static uint8_t denali_read_byte(struct mtd_info *mtd)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	uint8_t result = 0xff;

	if (denali->buf.head < denali->buf.tail)
		result = denali->buf.buf[denali->buf.head++];

	return result;
}

static void denali_select_chip(struct mtd_info *mtd, int chip)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	spin_lock_irq(&denali->irq_lock);
	denali->flash_bank = chip;
	spin_unlock_irq(&denali->irq_lock);
}

static int denali_waitfunc(struct mtd_info *mtd, struct nand_chip *chip)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	int status = denali->status;
	denali->status = 0;

	return status;
}

static void denali_read_buf(struct mtd_info *mtd, u8 *buf, int len)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	if (denali->buf.head + len <= denali->buf.tail) {
		memcpy(buf, &denali->buf.buf[denali->buf.head], len);
		denali->buf.head += len;
	}
	return;
}

static int denali_block_bad(struct mtd_info *mtd, loff_t ofs, int getchip)
{
	int page, chipnr, res = 0, i = 0;
	struct nand_chip *chip = mtd->priv;
	u16 bad;
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	uint8_t oob_buffer_byte;

	if (chip->bbt_options & NAND_BBT_SCANLASTPAGE)
		ofs += mtd->erasesize - mtd->writesize;

	page = (int)(ofs >> chip->page_shift) & chip->pagemask;

	if (getchip) {
		chipnr = (int)(ofs >> chip->chip_shift);

		nand_get_device(chip, mtd, FL_READING);

		/* Select the NAND device */
		chip->select_chip(mtd, chipnr);
	}

	do {
		if (chip->options & NAND_BUSWIDTH_16) {
			chip->cmdfunc(mtd, NAND_CMD_READOOB,
					chip->badblockpos & 0xFE, page);
			bad = cpu_to_le16(chip->read_word(mtd));
			if (chip->badblockpos & 0x1)
				bad >>= 8;
			else
				bad &= 0xFF;
		} else {
			chip->cmdfunc(mtd, NAND_CMD_READOOB, chip->badblockpos, page);
			res = 0;
			oob_buffer_byte = chip->read_byte(mtd); /* get the first byte in the oob area */
			if (denali->maf_id == 0x2C) {	      /* for micron nand */
				if (oob_buffer_byte == 0x00)  /* if the first byte in oob area is 0x00 */
					res = 1;	      /*  consider the block to be bad */
			} else if (denali->maf_id == 0x98) {  /* for toshiba nand */
				if (oob_buffer_byte == 0x00)  /* if the first byte in oob area is 0x00 */
					res = 1;              /*  consider the block to be bad */
			}
		}
		ofs += mtd->writesize;
		page = (int)(ofs >> chip->page_shift) & chip->pagemask;
		i++;
	} while (!res && i < 2 && (chip->bbt_options & NAND_BBT_SCAN2NDPAGE));

	if (getchip)
		nand_release_device(mtd);
	return res;
}

static void denali_erase(struct mtd_info *mtd, int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	uint32_t cmd = 0x0, irq_status = 0;

	/* clear interrupts */
	clear_interrupts(denali);

	/* setup page read request for access type */
	cmd = MODE_10 | BANK(denali->flash_bank) | page;
	index_addr(denali, (uint32_t)cmd, 0x1);

	/* wait for erase to complete or failure to occur */
	irq_status = wait_for_irq(denali, INTR_STATUS__ERASE_COMP |
					INTR_STATUS__ERASE_FAIL);

	denali->status = (irq_status & INTR_STATUS__ERASE_FAIL) ?
						NAND_STATUS_FAIL : PASS;
}

static void denali_cmdfunc(struct mtd_info *mtd, unsigned int cmd, int col,
			   int page)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	uint32_t addr, id;
	int i;
	int timeout = 0x1000;

	switch (cmd) {
	case NAND_CMD_PAGEPROG:
		break;
	case NAND_CMD_STATUS:
		read_status(denali);
		break;
	case NAND_CMD_READID:
		reset_buf(denali);
		addr = (uint32_t)MODE_11 | BANK(denali->flash_bank);
		index_addr(denali, (uint32_t)addr | 0, 0x90);
		index_addr(denali, (uint32_t)addr | 1, col);
		for (i = 0; i < 5; i++) {
			index_addr_read_data(denali,
						(uint32_t)addr | 2,
						&id);
			write_byte_to_buf(denali, id);
		}
		break;
	case NAND_CMD_PARAM:
		reset_buf(denali);
		clear_interrupt(denali, INTR_STATUS__INT_ACT);
		addr = (uint32_t)MODE_11 | BANK(denali->flash_bank);
		index_addr(denali, (uint32_t)addr | 0, cmd);
		index_addr(denali, (uint32_t)addr | 1, col);
		/* wait ready/busy pin to high level */
		while (--timeout) {
			if (read_interrupt_status(denali) & INTR_STATUS__INT_ACT) {
				clear_interrupt(denali, INTR_STATUS__INT_ACT);
		break;
			}
		}
		for (i = 0; i < 256; i++) {
			index_addr_read_data(denali,
						(uint32_t)addr | 2,
						&id);
			write_byte_to_buf(denali, id);
		}
		break;
	case NAND_CMD_READ0:
	case NAND_CMD_SEQIN:
		denali->page = page;
		break;
	case NAND_CMD_RESET:
		reset_bank(denali);
		break;
	case NAND_CMD_READOOB:
		reset_buf(denali);
		memset(denali->buf.buf, 0, DENALI_BUF_SIZE);
		read_oob_data(mtd, denali->buf.buf, page);
		denali->buf.tail += mtd->oobsize;
		break;
	default:
		pr_err(": unsupported command received 0x%x\n", cmd);
		break;
	}
}

/* stubs for ECC functions not used by the NAND core */
static int denali_ecc_calculate(struct mtd_info *mtd, const uint8_t *data,
				uint8_t *ecc_code)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	dev_err(denali->dev,
			"denali_ecc_calculate called unexpectedly\n");
	BUG();
	return -EIO;
}

static int denali_ecc_correct(struct mtd_info *mtd, uint8_t *data,
				uint8_t *read_ecc, uint8_t *calc_ecc)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	dev_err(denali->dev,
			"denali_ecc_correct called unexpectedly\n");
	BUG();
	return -EIO;
}

static void denali_ecc_hwctl(struct mtd_info *mtd, int mode)
{
	struct denali_nand_info *denali = mtd_to_denali(mtd);
	dev_err(denali->dev,
			"denali_ecc_hwctl called unexpectedly\n");
	BUG();
}
/* end NAND core entry points */

/* Initialization code to bring the device up to a known good state */
static int denali_hw_init(struct denali_nand_info *denali)
{
	static void __iomem *misc_base;
	uint32_t val = 0, cnt;
	unsigned long comp_res = 0;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100;

	misc_base = (void __iomem *)OPV5XC_MISC_BASE_VIRT;

	init_completion(&denali->complete);

	/* Follow NFC AUTOCFG test setting */
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* NFC clock disable */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x00) & ~(1 << 19)), OPV5XC_CR_PMU_BASE_VIRT + 0x000);
	/* NFC software reset assert */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 19)), OPV5XC_CR_PMU_BASE_VIRT + 0x004);
	/* NFC software reset deassert */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 19), OPV5XC_CR_PMU_BASE_VIRT + 0x004);
	/* NFC clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT + 0x00) | (1 << 19), OPV5XC_CR_PMU_BASE_VIRT + 0x000);
	/* wait for completion */
	val = 0;

	val = readl(OPV5XC_CR_PMU_BASE_VIRT + 0x0A0);
	writel(val | (1 << 8), OPV5XC_CR_PMU_BASE_VIRT + 0x0A0);
#else
	/* Select IO mux for NFC */
	val = readl(misc_base + 0x10);
	writel(val | (1<<6), misc_base + 0x10);
#endif

	/* Enable NFMC to enable clocks and remove resets */
	val = readl(misc_base + 0x300);
	writel((val | 0x1), misc_base + 0x300);

	if (read_interrupt_status(denali) & INTR_STATUS__RST_COMP)
		clear_interrupt(denali, INTR_STATUS__RST_COMP);

	/* toggling rst_nfmc_n to trigger auto-config again */
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	val = readl(denali->flash_reg + 0x410);
	writel(val | 0x2000, denali->flash_reg + 0x410);
#else
	val = readl(misc_base + 0xE74);
	writel(val|1 , misc_base + 0xE74);
	udelay(10);
	writel(val , misc_base + 0xE74);
#endif

	cnt = 1000;
	while (cnt) {
		if (read_interrupt_status(denali) & INTR_STATUS__RST_COMP) {
			clear_interrupt(denali, INTR_STATUS__RST_COMP);
			break;
		}
		udelay(1000);
		cnt--;
	}
	if (cnt == 0) {
		printk(KERN_ERR "\n: Auto-config not completed!\n");
		return -ENODEV;
	}

	do {
		comp_res = wait_for_completion_timeout(&denali->complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<19)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		printk(KERN_ERR "\n: Timeout while enabling power for NFC\n");
		return -ENODEV;
	}

#ifdef CONFIG_NAND_DENALI_DEBUG
	printk(KERN_DEBUG
			"\nDump device parameters values:\n"
			"------------------------------\n"
			"maufacture: %02x, device: %02x\n"
			"page_sz: %04x, page_spare_sz: %04x\n"
			"onfi_feature: %04x, onfi_opt: %04x\n"
			"dev_no_of_luns: %x\n"
			"#planes: %x, pgs_per_blk: %x, width: %x\n"
			"main_area_sz: %x, spare_area_sz: %x\n"
			"------------------------------\n"
			,
			ioread32(denali->flash_reg + MANUFACTURER_ID),
			ioread32(denali->flash_reg + DEVICE_ID),
			ioread32(denali->flash_reg + LOGICAL_PAGE_DATA_SIZE),
			ioread32(denali->flash_reg + LOGICAL_PAGE_SPARE_SIZE),
			ioread32(denali->flash_reg + ONFI_DEVICE_FEATURES),
			ioread32(denali->flash_reg + ONFI_OPTIONAL_COMMANDS),
			ioread32(denali->flash_reg + ONFI_DEVICE_NO_OF_LUNS),
			ioread32(denali->flash_reg + NUMBER_OF_PLANES) + 1,
			ioread32(denali->flash_reg + PAGES_PER_BLOCK),
			ioread32(denali->flash_reg + DEVICE_WIDTH),
			ioread32(denali->flash_reg + DEVICE_MAIN_AREA_SIZE),
			ioread32(denali->flash_reg + DEVICE_SPARE_AREA_SIZE)
			);
#endif
	iowrite32(2, denali->flash_reg + SPARE_AREA_SKIP_BYTES);
	iowrite32(SPARE_AREA_MARKER__VALUE, denali->flash_reg + SPARE_AREA_MARKER);

	/* tell driver how many bit controller will skip before
	 * writing ECC code in OOB, this register may be already
	 * set by firmware. So we read this value out.
	 * if this value is 0, just let it be.
	 * */
	denali->bbtskipbytes = ioread32(denali->flash_reg +
						SPARE_AREA_SKIP_BYTES);
	detect_max_banks(denali);
	denali_nand_reset(denali);
	iowrite32(RB_PIN_ENABLED__BANK0+RB_PIN_ENABLED__BANK1, denali->flash_reg + RB_PIN_ENABLED);
	iowrite32(CHIP_EN_DONT_CARE__FLAG,
			denali->flash_reg + CHIP_ENABLE_DONT_CARE);

	iowrite32(0xffff, denali->flash_reg + SPARE_AREA_MARKER);

	/* Should set value for these registers when init */
	iowrite32(0, denali->flash_reg + TWO_ROW_ADDR_CYCLES);
	iowrite32(1, denali->flash_reg + ECC_ENABLE);
	denali_nand_timing_set(denali);
	denali_irq_init(denali);

	return 0;
}

/* Althogh controller spec said SLC ECC is forceb to be 4bit,
 * but denali controller in MRST only support 15bit and 8bit ECC
 * correction
 * */
#define ECC_8BITS	14
static struct nand_ecclayout nand_8bit_oob = {
	.eccbytes = 14,
};

#define ECC_15BITS	26
static struct nand_ecclayout nand_15bit_oob = {
	.eccbytes = 26,
};

static struct nand_ecclayout nand_var_oob = {
};

static uint8_t bbt_pattern[] = {'B', 'b', 't', '0' };
static uint8_t mirror_pattern[] = {'1', 't', 'b', 'B' };

static struct nand_bbt_descr bbt_main_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP,
	.offs =	8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = 4,
	.pattern = bbt_pattern,
};

static struct nand_bbt_descr bbt_mirror_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP,
	.offs =	8,
	.len = 4,
	.veroffs = 12,
	.maxblocks = 4,
	.pattern = mirror_pattern,
};

static struct nand_bbt_descr bbt_main_no_bbt_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP
		| NAND_BBT_NO_OOB,
	.len = 4,
	.veroffs = 4,
	.maxblocks = 4,
	.pattern = bbt_pattern
};

static struct nand_bbt_descr bbt_mirror_no_bbt_descr = {
	.options = NAND_BBT_LASTBLOCK | NAND_BBT_CREATE | NAND_BBT_WRITE
		| NAND_BBT_2BIT | NAND_BBT_VERSION | NAND_BBT_PERCHIP
		| NAND_BBT_NO_OOB,
	.len = 4,
	.veroffs = 4,
	.maxblocks = 4,
	.pattern = mirror_pattern
};

/* initialize driver data structures */
void denali_drv_init(struct denali_nand_info *denali)
{
	denali->idx = 0;


	/* the spinlock will be used to synchronize the ISR
	 * with any element that might be access shared
	 * data (interrupt status) */
	spin_lock_init(&denali->irq_lock);

	/* indicate that MTD has not selected a valid bank yet */
	denali->flash_bank = CHIP_SELECT_INVALID;

	/* initialize our irq_status variable to indicate no interrupts */
	denali->irq_status = 0;
}

#define DEBUG_PROC
#ifdef DEBUG_PROC
#include <linux/proc_fs.h>
#include <linux/uaccess.h>

#define PROC_BUFFER_SIZE 10000

char proc_buffer[PROC_BUFFER_SIZE];

struct proc_dir_entry *denali_proc_entry;

void denali_print_data(char *buffer, unsigned int size)
{
	int i;
	int condition = ((size/32)*32);

	printk(KERN_EMERG "Displaying 32 byte aligned data\n");

	for (i = 0; i < condition; i += 32) {
		printk(KERN_EMERG "%2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x \
			       %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x %2x \
			       %2x %2x %2x %2x %2x %2x %2x %2x %2x\n",
			buffer[i], buffer[i+1], buffer[i+2], buffer[i+3],
			buffer[i+4], buffer[i+5], buffer[i+6], buffer[i+7],
			buffer[i+8], buffer[i+9], buffer[i+10], buffer[i+11],
			buffer[i+12], buffer[i+13], buffer[i+14], buffer[i+15],
			buffer[i+16], buffer[i+17], buffer[i+18], buffer[i+19],
			buffer[i+20], buffer[i+21], buffer[i+22], buffer[i+23],
			buffer[i+24], buffer[i+25], buffer[i+26], buffer[i+27],
			buffer[i+28], buffer[i+29], buffer[i+30], buffer[i+31]);
	}
}

void denali_proc_usage(void)
{
	printk(KERN_EMERG "Usage:\n");
	printk(KERN_EMERG "------\n");
	printk(KERN_EMERG "echo erase block <block no> > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo read page <page no> > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo read raw <page no> > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo read oob <page no> > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo write page <page no> `cat data.txt` > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo write raw <page no> `cat data.txt` > /proc/opv5xc/denali_nand\n");
	printk(KERN_EMERG "echo write oob <page no> `cat data.txt` > /proc/opv5xc/denali_nand\n");
}


static ssize_t opv5xc_denali_write_proc(struct file *file, const char __user *buffer,
			   size_t count, loff_t *ppos)
{
	char *ptr = proc_buffer;
	char cmd[10], subcmd[10];
	unsigned int page_blk_no, page;
	struct mtd_info *mtd = (struct mtd_info *) PDE_DATA(file_inode(file));
	struct denali_nand_info *denali = mtd_to_denali(mtd);

	if (count >= PROC_BUFFER_SIZE) {
		printk(KERN_EMERG "Count exceeds, max 10000\n");
		return count;
	}

	memset(proc_buffer, 0, PROC_BUFFER_SIZE);

	if (copy_from_user(proc_buffer, buffer, count)) {
		printk(KERN_EMERG "Copy from user failed\n");
		return -ENOMEM;
	}

	sscanf(proc_buffer, "%10s %10s %d\n", cmd, subcmd, &page_blk_no);
	printk(KERN_EMERG "Cmd: %s Subcmd: %s PageBlockNo: %x\n", cmd, subcmd, page_blk_no);

	denali_select_chip(mtd, 0);

	if (strncmp(cmd, "erase", sizeof(cmd)) == 0) {
		page = denali->pages_per_block * page_blk_no;
		denali->page = page;
		denali_erase(mtd, page);
	} else if (strncmp(cmd, "write", sizeof(cmd)) == 0) {
		denali->page = page_blk_no;

		if (strncmp(subcmd, "page", sizeof(subcmd)) == 0) {
			ptr = strstr(proc_buffer, "page");
			ptr += strlen("page");
			ptr += 4;

			denali_write_page(mtd, &denali->nand, (uint8_t *)ptr, 0);
		} else if (strncmp(subcmd, "raw", sizeof(subcmd)) == 0) {
			ptr = strstr(proc_buffer, "raw");
			ptr += strlen("raw");
			ptr += 4;

			denali_write_page_raw(mtd, &denali->nand, (uint8_t *) ptr, 0);
		} else if (strncmp(subcmd, "oob", sizeof(subcmd)) == 0) {
			ptr = strstr(proc_buffer, "oob");
			ptr += strlen("oob");
			ptr += 4;

			memcpy(denali->nand.oob_poi, ptr, mtd->oobsize);
			denali_write_oob(mtd, &denali->nand, denali->page);
		} else {
			printk(KERN_EMERG "Invalid command\n");
			denali_proc_usage();
		}
	} else if (strncmp(cmd, "read", sizeof(cmd)) == 0) {
		denali->page = page_blk_no;
		memset(proc_buffer, 0, PROC_BUFFER_SIZE);

		if (strncmp(subcmd, "page", sizeof(subcmd)) == 0) {
			denali_read_page(mtd, &denali->nand, (uint8_t *) proc_buffer, 0, page_blk_no);
			denali_print_data(proc_buffer, mtd->writesize);
		} else if (strncmp(subcmd, "raw", sizeof(subcmd)) == 0) {
			denali_read_page_raw(mtd, &denali->nand, (uint8_t *) proc_buffer, 0, page_blk_no);
			denali_print_data(proc_buffer, mtd->writesize);
			denali_print_data(denali->nand.oob_poi, mtd->oobsize);
		} else if (strncmp(subcmd, "oob", sizeof(subcmd)) == 0) {
			denali_read_oob(mtd, &denali->nand, page_blk_no);
			denali_print_data(denali->nand.oob_poi, mtd->oobsize);
		} else {
			printk(KERN_EMERG "Invalid command\n");
			denali_proc_usage();
		}
	} else {
		printk(KERN_EMERG "Invalid command\n");
		denali_proc_usage();
	}
	return count;
}

static int denali_nand_proc_show(struct seq_file *m, void *v)
{
	return 0;
}

static int denali_nand_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, denali_nand_proc_show, NULL);
}

static const struct file_operations opv5xc_denali_fops = {
	.owner		= THIS_MODULE,
	.open		= denali_nand_proc_open,
	.read		= seq_read,
	.write		= opv5xc_denali_write_proc,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

static int __init denali_proc_init(struct mtd_info *mtd)
{
	if (opv5xc_proc_dir == NULL) {
		printk(KERN_INFO "Please Create Proc First\n");
		BUG();
	}
	denali_proc_entry =
		proc_create_data("denali_nand", S_IFREG | S_IRUGO,
				opv5xc_proc_dir, &opv5xc_denali_fops, (void *) mtd);

	return 1;
}
#endif /* DEBUG_PROC */

static int denali_setup(struct denali_nand_info *denali)
{
	int ret;
	u_int32_t addr, timeout, cnt, ecc_lvl;
	u_int32_t i, val;
	uint32_t ecc_lvl_cfg[7]      = {4,  8, 12, 16, 24, 32, 40};
	uint32_t ecc_lvl_chkbytes[7] = {8, 14, 20, 26, 42, 56, 70};
	struct nand_chip *chip = &denali->nand;

	/* Is 32-bit DMA supported? */
	ret = dma_set_mask(denali->dev, DMA_BIT_MASK(32));
	if (ret) {
		pr_err("Spectra: no usable DMA configuration\n");
		return ret;
	}

	denali->buf.buf = kmalloc(DENALI_BUF_SIZE, GFP_KERNEL);
	if (!denali->buf.buf) {
		dev_err(denali->dev, "kmalloc failed: Unable to allocate buffer for DMA\n");
		return -ENOMEM;
	}

	denali->buf.dma_buf = dma_map_single(denali->dev, denali->buf.buf,
					     DENALI_BUF_SIZE,
					     DMA_BIDIRECTIONAL);

	if (dma_mapping_error(denali->dev, denali->buf.dma_buf)) {
		dev_err(denali->dev, "Spectra: failed to map DMA buffer\n");
		return -EIO;
	}
	denali->mtd.dev.parent = denali->dev;
	if (denali_hw_init(denali)) {
		dev_err(denali->dev, "denali_hw_init failed\n");
		return -ENODEV;
	}
	denali_drv_init(denali);

	/* denali_isr register is done after all the hardware
	 * initilization is finished*/
	if (request_irq(denali->irq, denali_isr, IRQF_SHARED,
			DENALI_NAND_NAME, denali)) {
		pr_err("Spectra: Unable to allocate IRQ\n");
		return -ENODEV;
	}

	/* now that our ISR is registered, we can enable interrupts */
	denali_set_intr_modes(denali, true);
	denali->mtd.name = "denali-nand";
	denali->mtd.owner = THIS_MODULE;
	denali->mtd.priv = &denali->nand;

	/* register the driver with the NAND core subsystem */
	denali->nand.select_chip = denali_select_chip;
	denali->nand.cmdfunc = denali_cmdfunc;
	denali->nand.read_byte = denali_read_byte;
	denali->nand.waitfunc = denali_waitfunc;
	denali->nand.read_buf = denali_read_buf;
	denali->nand.block_bad	= denali_block_bad;

	/* scan for NAND devices attached to the controller
	 * this is the first stage in a two step process to register
	 * with the nand subsystem */
	if (nand_scan_ident(&denali->mtd, denali->max_banks, NULL)) {
		ret = -ENXIO;
		goto failed_req_irq;
	}

	/* MTD supported page sizes vary by kernel. We validate our
	 * kernel supports the device here.
	 */
	if (denali->mtd.writesize > NAND_MAX_PAGESIZE + NAND_MAX_OOBSIZE) {
		ret = -ENODEV;
		pr_err("Spectra: device size not supported by this version of MTD.");
		goto failed_req_irq;
	}

	/* support for multi nand
	 * MTD known nothing about multi nand,
	 * so we should tell it the real pagesize
	 * and anything necessery
	 */
	denali->devnum = ioread32(denali->flash_reg + DEVICES_CONNECTED);
	denali->nand.chipsize <<= (denali->devnum - 1);
	denali->nand.page_shift += (denali->devnum - 1);
	denali->nand.bbt_erase_shift += (denali->devnum - 1);
	denali->nand.phys_erase_shift = denali->nand.bbt_erase_shift;
	denali->nand.chip_shift += (denali->devnum - 1);
	denali->mtd.writesize <<= (denali->devnum - 1);
	denali->mtd.oobsize <<= (denali->devnum - 1);
	denali->mtd.erasesize <<= (denali->devnum - 1);
	denali->mtd.size = denali->nand.numchips * denali->nand.chipsize;
	denali->bbtskipbytes *= denali->devnum;

	/* second stage of the NAND scan
	 * this stage requires information regarding ECC and
	 * bad block management. */

	/* skip the scan for now until we have OOB read and write support */
	denali->nand.bbt_options |= NAND_BBT_USE_FLASH;
	denali->nand.bbt_options |= NAND_BBT_NO_OOB;
	denali->nand.options |= NAND_NO_SUBPAGE_WRITE;
	denali->nand.ecc.mode = NAND_ECC_HW_SYNDROME;

	/* Bad block management */
	if (denali->nand.bbt_options & NAND_BBT_NO_OOB) {
		denali->nand.bbt_td = &bbt_main_no_bbt_descr;
		denali->nand.bbt_md = &bbt_mirror_no_bbt_descr;
	} else {
		denali->nand.bbt_td = &bbt_main_descr;
		denali->nand.bbt_md = &bbt_mirror_descr;
	}


	if (ioread32(denali->flash_reg + ONFI_DEVICE_NO_OF_LUNS) &
		ONFI_DEVICE_NO_OF_LUNS__ONFI_DEVICE) {

		timeout = 0x1000;
		reset_buf(denali);
		clear_interrupt(denali, INTR_STATUS__INT_ACT);
		addr = (uint32_t)MODE_11 | BANK(denali->flash_bank);
		index_addr(denali, addr | 0, NAND_CMD_PARAM);
		index_addr(denali, addr | 1, 0);
		/* wait ready/busy pin to high level */
		while (--timeout) {
			if (read_interrupt_status(denali) & INTR_STATUS__INT_ACT) {
				clear_interrupt(denali, INTR_STATUS__INT_ACT);
				break;
			}
		}

		if (timeout) {
			cnt = 0;
			while (1) {
				index_addr_read_data(denali, addr | 2, &ecc_lvl);
				ecc_lvl &= 0xFF;
				if (cnt == 112) {
					if (ecc_lvl != 0xFF) {
						printk(KERN_INFO "found the ecc level(%d) @byte-112\n", ecc_lvl);
						break;
					}
				}
				if (cnt == 800) {
					printk(KERN_INFO "found the ecc level(%d) @byte-800\n", ecc_lvl);
					break;
				}
				cnt++;
			}

			for (i = 0; i < 7; i++) {
				val = ecc_lvl_cfg[i];
				if (val >= ecc_lvl) {
					iowrite32(val, denali->flash_reg + ECC_CORRECTION);

					/*
					* Formula to calculate the number of the ECC check-bytes
					* Sector Size =  512, 2*CEIL[13*n/16]
					* Sector Size = 1024, 2*CEIL[14*n/16]
					* ECC level 4,8,12,16 over 512 and 24, 32, 40 over 1024.
					*/
					nand_var_oob.eccbytes = ecc_lvl_chkbytes[i];
					chip->ecc.layout = &nand_var_oob;
					chip->ecc.bytes = nand_var_oob.eccbytes;
					goto ecc_setup_finish;
					break;
				}
			}
		}
	}



	/* Denali Controller only support 15bit and 8bit ECC in MRST,
	 * so just let controller do 15bit ECC for MLC and 8bit ECC for
	 * SLC if possible.
	 * */
	if (denali->nand.cellinfo & 0xc &&
			(denali->mtd.oobsize > (denali->bbtskipbytes +
			ECC_15BITS * (denali->mtd.writesize /
			ECC_SECTOR_SIZE)))) {
		/* if MLC OOB size is large enough, use 15bit ECC*/
		denali->nand.ecc.strength = 15;
		denali->nand.ecc.layout = &nand_15bit_oob;
		denali->nand.ecc.bytes = ECC_15BITS;
		iowrite32(15, denali->flash_reg + ECC_CORRECTION);
	} else if (denali->mtd.oobsize < (denali->bbtskipbytes +
			ECC_8BITS * (denali->mtd.writesize /
			ECC_SECTOR_SIZE))) {
		pr_err("Your NAND chip OOB is not large enough to \
				contain 8bit ECC correction codes");
		goto failed_req_irq;
	} else {
		denali->nand.ecc.strength = 8;
		denali->nand.ecc.layout = &nand_8bit_oob;
		denali->nand.ecc.bytes = ECC_8BITS;
		iowrite32(8, denali->flash_reg + ECC_CORRECTION);
	}

ecc_setup_finish:

	denali->nand.ecc.bytes *= denali->devnum;
	denali->nand.ecc.strength *= denali->devnum;
	denali->nand.ecc.layout->eccbytes *=
		denali->mtd.writesize / ECC_SECTOR_SIZE;
	denali->nand.ecc.layout->oobfree[0].offset =
		denali->bbtskipbytes + denali->nand.ecc.layout->eccbytes;
	denali->nand.ecc.layout->oobfree[0].length =
		denali->mtd.oobsize - denali->nand.ecc.layout->eccbytes -
		denali->bbtskipbytes;

	/* Let driver know the total blocks number and
	 * how many blocks contained by each nand chip.
	 * blksperchip will help driver to know how many
	 * blocks is taken by FW.
	 * */
	denali->totalblks = denali->mtd.size >>
				denali->nand.phys_erase_shift;
	denali->blksperchip = denali->totalblks / denali->nand.numchips;

	/* These functions are required by the NAND core framework, otherwise,
	 * the NAND core will assert. However, we don't need them, so we'll stub
	 * them out. */
	denali->nand.ecc.calculate = denali_ecc_calculate;
	denali->nand.ecc.correct = denali_ecc_correct;
	denali->nand.ecc.hwctl = denali_ecc_hwctl;

	/* override the default read operations */
	denali->nand.ecc.size = ECC_SECTOR_SIZE * denali->devnum;
	denali->nand.ecc.read_page = denali_read_page;
	denali->nand.ecc.read_page_raw = denali_read_page_raw;
	denali->nand.ecc.write_page = denali_write_page;
	denali->nand.ecc.write_page_raw = denali_write_page_raw;
	denali->nand.ecc.read_oob = denali_read_oob;
	denali->nand.ecc.write_oob = denali_write_oob;
	denali->nand.erase_cmd = denali_erase;

	if (nand_scan_tail(&denali->mtd)) {
		ret = -ENXIO;
		goto failed_req_irq;
	}

	ret = mtd_device_register(&denali->mtd, NULL, 0);
	if (ret) {
		dev_err(denali->dev, "Spectra: Failed to register MTD: %d\n",
				ret);
		goto failed_req_irq;
	}

	denali->pages_per_block = ioread32(denali->flash_reg + PAGES_PER_BLOCK);
#ifdef DEBUG_PROC
	denali_proc_init(&denali->mtd);
#endif /* DEBUG_PROC */
	return 0;

failed_req_irq:
	denali_irq_cleanup(denali->irq, denali);

	return ret;
}

int denali_nand_probe(struct platform_device *pdev)
{
	struct denali_nand_info *denali;
	struct resource *regs;
	struct resource *mem;
	int ret = 0;

	mem = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!mem) {
		printk(KERN_ERR "opv5xc_nand: can't get I/O resource mem\n");
		return -ENXIO;
	}

	regs = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	if (!regs) {
		printk(KERN_ERR "opv5xc_nand: can't get I/O resource mem\n");
		return -ENXIO;
	}

	denali = kzalloc(sizeof(*denali), GFP_KERNEL);
	if (!denali)
		return -ENOMEM;

	denali->dev = &pdev->dev;

	denali->irq = platform_get_irq(pdev, 0);

	denali->flash_mem = ioremap(mem->start, resource_size(mem));
	if (!denali->flash_mem) {
		printk(KERN_ERR "opv5xc_nand: mem ioremap failed\n");
		ret = -EIO;
		goto err_nand_ioremap;
	}
	printk(KERN_DEBUG "denali->flash_mem = 0x%x\n", (unsigned int) denali->flash_mem);

	request_mem_region(mem->start, resource_size(mem), DENALI_NAND_NAME);

	denali->flash_reg = ioremap(regs->start, resource_size(regs));
	if (!denali->flash_reg) {
		printk(KERN_ERR "opv5xc_nand: regs ioremap failed\n");
		ret = -EIO;
		goto err_regs_ioremap;
	}
	printk(KERN_DEBUG "denali->flash_reg = 0x%x\n", (unsigned int) denali->flash_reg);

	request_mem_region(regs->start, resource_size(regs), DENALI_NAND_NAME);

	if (denali_setup(denali)) {
		dev_err(&pdev->dev, "device init failed\n");
		ret = -ENODEV;
		goto err_denali_setup;
	}

	dev_set_drvdata(&pdev->dev, denali);

	return 0;

err_denali_setup:
	iounmap(denali->flash_reg);

err_regs_ioremap:
	iounmap(denali->flash_mem);

err_nand_ioremap:
	kfree(denali->buf.buf);
	kfree(denali);
	return ret;
}

static int __exit denali_nand_remove(struct platform_device *pdev)
{
	struct denali_nand_info *denali = dev_get_drvdata(&pdev->dev);

	nand_release(&denali->mtd);

	denali_irq_cleanup(denali->irq, denali);
	iounmap(denali->flash_reg);
	iounmap(denali->flash_mem);

	dma_unmap_single(denali->dev, denali->buf.dma_buf, DENALI_BUF_SIZE,
			 DMA_BIDIRECTIONAL);
	dev_set_drvdata(&pdev->dev, NULL);
	kfree(denali->buf.buf);
	kfree(denali);
	return 0;
}

int denali_nand_suspend(struct platform_device *pdev, pm_message_t state)
{
	struct denali_nand_info *denali = dev_get_drvdata(&pdev->dev);
	struct nand_chip *chip = (struct nand_chip *) denali->mtd.priv;

	chip->ecc_correction_val = ioread32(denali->flash_reg + ECC_CORRECTION);
	return 0;
}

int denali_nand_resume(struct platform_device *pdev)
{
	struct denali_nand_info *denali = dev_get_drvdata(&pdev->dev);
	struct nand_chip *chip = (struct nand_chip *) denali->mtd.priv;
	struct mtd_info *mtd = &denali->mtd;
	int i;

	denali->flash_bank = 0;
	denali_hw_init(denali);

	denali_set_intr_modes(denali, true);

	/* Check for a chip array */
	for (i = 0; i < denali->max_banks; i++) {
		chip->select_chip(mtd, i);
		/* See comment in nand_get_flash_type for reset */
		chip->cmdfunc(mtd, NAND_CMD_RESET, -1, -1);
		/* Send the command for reading device ID */
		chip->cmdfunc(mtd, NAND_CMD_READID, 0x00, -1);
	}

	iowrite32(chip->ecc_correction_val, denali->flash_reg + ECC_CORRECTION);
	return 0;
}

static struct platform_driver denali_nand_driver = {
	.remove	= __exit_p(denali_nand_remove),
	.driver	= {
		.name		= "denali_nand",
		.owner	= THIS_MODULE,
	},
	.suspend = denali_nand_suspend,
	.resume = denali_nand_resume,
};

static int __init denali_init(void)
{
	return platform_driver_probe(&denali_nand_driver, denali_nand_probe);
}

static void __exit denali_exit(void)
{
	platform_driver_unregister(&denali_nand_driver);
}

module_init(denali_init);
module_exit(denali_exit);
