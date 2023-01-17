/*
 * Copyright (C) 2015, Broadcom Corporation. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/leds-brcm-xgxs.h>
#include <linux/mutex.h>
#include <linux/bitops.h>
#include <linux/ioctl.h>
#include <linux/types.h>


#define DRV_NAME "brcm-xgxs-led"

static const struct of_device_id brcm_led_of_match[] = {
	{.compatible = "brcm,xgxs-led",},
	{ }
};

struct brcm_led_cfg {
	struct class *dev_class;
	struct device *dev;
	void __iomem *reg_base_addr;
	void __iomem *code_ram_base_addr;
	void __iomem *data_ram_base_addr;
	int led_major;
};

static struct brcm_led_cfg led_cfg;

static int bits_per_led = 1;
static int leds_per_port = 1;
static int max_ports = 1;

#define CMIC_LEDUP0_CTRL_OFFSET 0x0
#define LEDUP_SCAN_START_DELAY_MIN 4
#define LEDUP_SCAN_START_DELAY_MAX 9
#define LEDUP_SCAN_INTRA_PORT_DELAY_MIN 1
#define LEDUP_SCAN_INTRA_PORT_DELAY_MAX 3
#define LEDUP_EN_MIN 0
#define LEDUP_EN_MAX 0

#define CMIC_LEDUP0_STATUS_OFFSET 0x4
#define LEDUP_INITIALISING_MIN 9
#define LEDUP_INITIALISING_MAX 9
#define LEDUP_RUNNING_MIN 8
#define LEDUP_RUNNING_MAX 8
#define PROGRAM_COUNTER_MIN 0
#define PROGRAM_COUNTER_MAX 7

#define CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET 0x8
#define SCANCHAIN_ASSEMBLY_ST_ADDR_MIN 0
#define SCANCHAIN_ASSEMBLY_ST_ADDR_MAX 7

#define CMIC_LEDUP0_CLK_PARAMS_OFFSET 0x50
#define REFRESH_CYCLE_PERIOD_MIN 0
#define REFRESH_CYCLE_PERIOD_MAX 31

#define CMIC_LEDUP0_SCANOUT_COUNT_UPPER_OFFSET 0x54
#define SCANOUT_COUNT_UPPER_MIN 0
#define SCANOUT_COUNT_UPPER_MAX 1

#define CMIC_LEDUP0_TM_CONTROL_OFFSET 0x58
#define TM_MIN 0
#define TM_MAX 7

#define CMIC_LEDUP0_CLK_DIV_OFFSET 0x5C
#define LEDCLK_HALF_PERIOD_MIN 0
#define LEDCLK_HALF_PERIOD_MAX 15

/*
 * LED Processor : Host Interface Layout
 *
 * 1) Register Area :
 * *Offset*  3130292827262524 2322212019181716 1514131211100908 0706050403020100
 * (0x00)
 * CTRL:     --------NA------ ------NA-------- ------NA----#### ################
 * (0x04)
 * STATUS:   --------NA------ ------NA-------- ------NA----#### ################
 * (0x08)
 * SCANCHAIN:--------NA------ ------NA-------- ------NA-------- ################
 *
 * ----------------------------Not Used(0x0C..0x4F) ----------------------------
 *
 * (0x50)
 * CLK-PARAM:################ ################ ################ ################
 * (0x54)
 * SCAN-UP:  --------NA------ ------NA-------- ------NA-------- --------------##
 * (0x58)
 * TM:	     --------NA------ ------NA-------- ------NA-------- ################
 * (0x5C)
 * CLK-DIV:  --------NA------ ------NA-------- ################ ################
 *
 *
 * 2) Data Area(1K Space Reserved for 256 Byte Data Area)
 * *Offset*  3130292827262524 2322212019181716 1514131211100908 0706050403020100
 * (0x400)   --------NA------ --------NA------ --------NA------ ##Status:Port0##
 * (0x404)   --------NA------ --------NA------ --------NA------ ##Status:Port0##
 * (0x408)   --------NA------ --------NA------ --------NA------ ##Status:Port1##
 * (0x40C)   --------NA------ --------NA------ --------NA------ ##Status:Port1##
 * ...
 * (0x478)   --------NA------ --------NA------ --------NA------ ##Status:Port31#

 * (0x47C)   --------NA------ --------NA------ --------NA------ ##Status:Port31#
 *
 * (0x480)   --------NA------ --------NA------ --------NA------ ##ScanChainArea#
 * ...
 * (0x4BC)   --------NA------ --------NA------ --------NA------ ##ScanChainArea#
 *
 * (0x4C0)   ##### undesignated so User can use it as Data Area ################
 * ......    ##### Some space can be stolen from ScanChainArea too if less bits
 *           ##### or pulses are used
 * (0x47C)   ##### undesignated so User can use it as Data Area ################
 *
 *
 * Hardware maintains per port status bits like
 * Bit	Meaning		Status=0		Status=1
 * 0	RX		no frames received	frames received
 * 1	TX		no frames transmitted	frames transmitted
 * 2	Collision	no collisions		collisions have occurred
 * [4:3]Speed		00=10 Mbps, 01=100 Mbps, 10=1000 Mbps
 * 5	Duplex		half duplex		full duplex
 * 6	Flow Control	no pause handshake	pause handshake successful
 * 7	Link Up		link down		link up
 * 8	Link Enabled	link disabled		link enabled
 * 9-13	unused
 * 14	False		always 0
 * 15	True		always 1
 *
 *
 * 3) Program Area(1K Space Reserved for 256 Byte Assembly Program)
 * *Offset*  3130292827262524 2322212019181716 1514131211100908 0706050403020100
 * (0x800)   --------NA------ --------NA------ --------NA------ ################
 * (0x804)   --------NA------ --------NA------ --------NA------ ################
 * ......
 * (0xBFC)   --------NA------ --------NA------ --------NA------ ################
 *
 */

static DEFINE_MUTEX(leds_ioctl_lock);

static int brcm_led_init(unsigned char *program, int bytes);

static void field_set32(u32 *reg_val, u8 min_bit , u8 max_bit, u32 field_val)
{
	u32 field_len = (max_bit - min_bit + 1);
	if (field_len < 32) {
		u32 mask = (1 << field_len) - 1;
		*reg_val = (*reg_val & ~(mask << min_bit)) |
				field_val << min_bit;
	} else {
		*reg_val = field_val;
	}
}

static u32 field_get32(u32 reg_val, u8 min_bit , u8 max_bit)
{
	u32 field_val = reg_val >> min_bit;
	u32 field_len = (max_bit - min_bit + 1);
	if (field_len < 32)
		field_val = field_val & ((1 << field_len) - 1);
	return field_val;
}

inline int led_brcm_ioctl_read_ctrl(unsigned long arg)
{
	u32 led_ctrl_read;
	struct led_ctrl led_ctrl_input;
	int ret = 0;

	ret = copy_from_user(&led_ctrl_input, (struct led_ctrl *)arg,
					sizeof(led_ctrl_input));
	if (ret)
		return -EFAULT;

	led_ctrl_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_CTRL_OFFSET);
	if ((led_ctrl_input.mask & ALL_MASK) == ALL_MASK)
		led_ctrl_input.mask = (LEDUP_EN_MASK |
					LEDUP_START_DELAY_MASK |
					LEDUP_INTRA_PORT_DELAY_MASK);
	if (led_ctrl_input.mask & LEDUP_EN_MASK)
		led_ctrl_input.ledup_en = field_get32(led_ctrl_read,
						LEDUP_EN_MIN, LEDUP_EN_MAX);
	if (led_ctrl_input.mask & LEDUP_START_DELAY_MASK)
		led_ctrl_input.ledup_start_delay = field_get32(led_ctrl_read,
					LEDUP_SCAN_START_DELAY_MIN,
					LEDUP_SCAN_START_DELAY_MAX);
	if (led_ctrl_input.mask & LEDUP_INTRA_PORT_DELAY_MASK)
		led_ctrl_input.ledup_intra_port_delay = field_get32(
				led_ctrl_read,
				LEDUP_SCAN_INTRA_PORT_DELAY_MIN,
				LEDUP_SCAN_INTRA_PORT_DELAY_MAX);
	ret = copy_to_user((void *)arg, &led_ctrl_input ,
					sizeof(led_ctrl_input));
	if (ret)
		return -EFAULT;

	return 0;
}

inline int led_brcm_ioctl_write_ctrl(unsigned long arg)
{
	u32 led_ctrl_read;
	struct led_ctrl led_ctrl_input;
	int ret;

	ret = copy_from_user(&led_ctrl_input,
		(struct led_ctrl *)arg, sizeof(led_ctrl_input));
	if (ret)
		return  -EFAULT;

	led_ctrl_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_CTRL_OFFSET);
	if ((led_ctrl_input.mask & ALL_MASK) == ALL_MASK)
		led_ctrl_input.mask = (LEDUP_EN_MASK |
					LEDUP_START_DELAY_MASK |
					LEDUP_INTRA_PORT_DELAY_MASK);
	if (led_ctrl_input.mask & LEDUP_EN_MASK)
		field_set32(&led_ctrl_read, LEDUP_EN_MIN,
				LEDUP_EN_MAX, led_ctrl_input.ledup_en);
	if (led_ctrl_input.mask & LEDUP_START_DELAY_MASK)
		field_set32(&led_ctrl_read, LEDUP_SCAN_START_DELAY_MIN,
				LEDUP_SCAN_START_DELAY_MAX,
				led_ctrl_input.ledup_start_delay);
	if (led_ctrl_input.mask & LEDUP_INTRA_PORT_DELAY_MASK)
		field_set32(&led_ctrl_read,
			LEDUP_SCAN_INTRA_PORT_DELAY_MIN,
			LEDUP_SCAN_INTRA_PORT_DELAY_MAX,
			led_ctrl_input.ledup_intra_port_delay);
	writel(led_ctrl_read,
		led_cfg.reg_base_addr + CMIC_LEDUP0_CTRL_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_read_status(unsigned long arg)
{
	u32 led_status_read;
	struct led_status led_status_input;
	int ret;

	ret = copy_from_user(&led_status_input,
			(struct led_status *)arg, sizeof(led_status_input));
	if (ret)
		return -EFAULT;

	led_status_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_STATUS_OFFSET);
	if ((led_status_input.mask & ALL_MASK) == ALL_MASK)
		led_status_input.mask = (LEDUP_INITIALISING_MASK |
					LEDUP_RUNNING_MASK |
					PROGRAM_COUNTER_MASK);
	if (led_status_input.mask & LEDUP_INITIALISING_MASK)
		led_status_input.ledup_initializing =
			field_get32(led_status_read,
					LEDUP_INITIALISING_MIN,
					LEDUP_INITIALISING_MAX);
	if (led_status_input.mask & LEDUP_RUNNING_MASK)
		led_status_input.ledup_running = field_get32(led_status_read,
							LEDUP_RUNNING_MIN,
							LEDUP_RUNNING_MAX);
	if (led_status_input.mask & PROGRAM_COUNTER_MASK)
		led_status_input.program_counter = field_get32(led_status_read,
							PROGRAM_COUNTER_MIN,
							PROGRAM_COUNTER_MAX);
	ret = copy_to_user((void *)arg, &led_status_input ,
				sizeof(led_status_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_read_scanchain_addr(unsigned long arg)
{
	u32 led_scan_start_read;
	struct led_scan_start led_scan_start_input;
	int ret;

	ret = copy_from_user(&led_scan_start_input,
			(struct led_scan_start *)arg,
			sizeof(led_scan_start_input));
	if (ret)
		return -EFAULT;

	led_scan_start_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET);
	if ((led_scan_start_input.mask & ALL_MASK) == ALL_MASK)
		led_scan_start_input.mask = (SCANCHAIN_ASSEMBLY_ST_ADDR_MASK);
	if (led_scan_start_input.mask & SCANCHAIN_ASSEMBLY_ST_ADDR_MASK)
		led_scan_start_input.scanchain_assembly_st_addr =
			field_get32(led_scan_start_read,
				SCANCHAIN_ASSEMBLY_ST_ADDR_MIN,
				SCANCHAIN_ASSEMBLY_ST_ADDR_MAX);
	ret = copy_to_user((void *)arg, &led_scan_start_input,
				sizeof(led_scan_start_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_write_scanchain_addr(unsigned long arg)
{
	u32 led_scan_start_read;
	struct led_scan_start led_scan_start_input;
	int ret;

	ret = copy_from_user(&led_scan_start_input,
				(struct led_scan_start *)arg,
				sizeof(led_scan_start_input));
	if (ret)
		return -EFAULT;
	led_scan_start_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET);
	if ((led_scan_start_input.mask & ALL_MASK) == ALL_MASK)
		led_scan_start_input.mask = (SCANCHAIN_ASSEMBLY_ST_ADDR_MASK);
	if (led_scan_start_input.mask & SCANCHAIN_ASSEMBLY_ST_ADDR_MASK)
		field_set32(&led_scan_start_read,
			SCANCHAIN_ASSEMBLY_ST_ADDR_MIN,
			SCANCHAIN_ASSEMBLY_ST_ADDR_MAX,
			led_scan_start_input.scanchain_assembly_st_addr);
	writel(led_scan_start_read,
		led_cfg.reg_base_addr +
		CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_read_clk_param(unsigned long arg)
{
	u32 led_clk_params_read;
	struct led_clk_params led_clk_params_input;
	int ret;

	ret = copy_from_user(&led_clk_params_input,
				(struct led_clk_params *)arg,
				sizeof(led_clk_params_input));
	if (ret)
		return -EFAULT;

	led_clk_params_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_CLK_PARAMS_OFFSET);
	if ((led_clk_params_input.mask & ALL_MASK) == ALL_MASK)
		led_clk_params_input.mask = REFRESH_CYCLE_PERIOD_MASK;
	if (led_clk_params_input.mask & REFRESH_CYCLE_PERIOD_MASK)
		led_clk_params_input.refresh_cycle_period =
				field_get32(led_clk_params_read,
						REFRESH_CYCLE_PERIOD_MIN,
						REFRESH_CYCLE_PERIOD_MAX);
	ret = copy_to_user((void *)arg,
			&led_clk_params_input ,
			sizeof(led_clk_params_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_write_clk_param(unsigned long arg)
{
	u32 led_clk_params_read;
	struct led_clk_params led_clk_params_input;
	int ret;

	ret = copy_from_user(&led_clk_params_input,
				(struct led_clk_params *)arg,
				sizeof(led_clk_params_input));
	if (ret)
		return -EFAULT;
	led_clk_params_read = readl(led_cfg.reg_base_addr +
					CMIC_LEDUP0_CLK_PARAMS_OFFSET);
	if ((led_clk_params_input.mask & ALL_MASK) == ALL_MASK)
		led_clk_params_input.mask = REFRESH_CYCLE_PERIOD_MASK;
	if (led_clk_params_input.mask & REFRESH_CYCLE_PERIOD_MASK)
		field_set32(&led_clk_params_read,
				REFRESH_CYCLE_PERIOD_MIN,
				REFRESH_CYCLE_PERIOD_MAX,
				led_clk_params_input.refresh_cycle_period);
	writel(led_clk_params_read,
			led_cfg.reg_base_addr +
			CMIC_LEDUP0_CLK_PARAMS_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_read_scanout_upper(unsigned long arg)
{
	u32 led_scanout_counter_upper_read;
	struct led_scanout_counter_upper led_scanout_counter_upper_input;
	int ret;

	ret = copy_from_user(&led_scanout_counter_upper_input,
			(struct led_scanout_counter_upper *)arg,
			sizeof(led_scanout_counter_upper_input));
	if (ret)
		return -EFAULT;
	led_scanout_counter_upper_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANOUT_COUNT_UPPER_OFFSET);
	if ((led_scanout_counter_upper_input.mask & ALL_MASK) == ALL_MASK)
		led_scanout_counter_upper_input.mask =
						(SCANOUT_COUNT_UPPER_MASK);
	if (led_scanout_counter_upper_input.mask & SCANOUT_COUNT_UPPER_MASK)
		led_scanout_counter_upper_input.scanout_counter_upper =
				field_get32(led_scanout_counter_upper_read,
						SCANOUT_COUNT_UPPER_MIN,
						SCANOUT_COUNT_UPPER_MAX);
	ret = copy_to_user((void *)arg,
			&led_scanout_counter_upper_input,
			sizeof(led_scanout_counter_upper_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_write_scanout_upper(unsigned long arg)
{
	u32 led_scanout_counter_upper_read;
	struct led_scanout_counter_upper led_scanout_counter_upper_input;
	int ret;

	ret = copy_from_user(&led_scanout_counter_upper_input,
			(struct led_scanout_counter_upper *)arg,
			sizeof(led_scanout_counter_upper_input));
	if (ret)
		return -EFAULT;
	led_scanout_counter_upper_read = readl(led_cfg.reg_base_addr +
			CMIC_LEDUP0_SCANOUT_COUNT_UPPER_OFFSET);
	if ((led_scanout_counter_upper_input.mask & ALL_MASK) == ALL_MASK)
		led_scanout_counter_upper_input.mask =
				(SCANOUT_COUNT_UPPER_MASK);
	if (led_scanout_counter_upper_input.mask & SCANOUT_COUNT_UPPER_MASK)
		field_set32(&led_scanout_counter_upper_read,
			SCANOUT_COUNT_UPPER_MIN,
			SCANOUT_COUNT_UPPER_MAX,
			led_scanout_counter_upper_input.scanout_counter_upper);
	writel(led_scanout_counter_upper_read,
		led_cfg.reg_base_addr + CMIC_LEDUP0_SCANOUT_COUNT_UPPER_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_read_tm_control(unsigned long arg)
{
	u32 led_tm_control_read;
	struct led_tm_control led_tm_control_input;
	int ret;

	ret = copy_from_user(&led_tm_control_input,
			(struct led_tm_control *)arg,
			sizeof(led_tm_control_input));
	if (ret)
		return -EFAULT;
	led_tm_control_read = readl(led_cfg.reg_base_addr +
					CMIC_LEDUP0_TM_CONTROL_OFFSET);
	if ((led_tm_control_input.mask & ALL_MASK) == ALL_MASK)
		led_tm_control_input.mask = (TM_MASK);
	if (led_tm_control_input.mask & TM_MASK)
		led_tm_control_input.tm = field_get32(led_tm_control_read,
							TM_MIN,
							TM_MAX);
	ret = copy_to_user((void *)arg,
				&led_tm_control_input ,
				sizeof(led_tm_control_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_write_tm_control(unsigned long arg)
{
	u32 led_tm_control_read;
	struct led_tm_control led_tm_control_input;
	int ret;

	ret = copy_from_user(&led_tm_control_input,
				(struct led_tm_control *)arg,
				sizeof(led_tm_control_input));
	if (ret)
		return -EFAULT;
	led_tm_control_read = readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_TM_CONTROL_OFFSET);
	if ((led_tm_control_input.mask & ALL_MASK) == ALL_MASK)
		led_tm_control_input.mask = (TM_MASK);
	if (led_tm_control_input.mask & TM_MASK)
		field_set32(&led_tm_control_read, TM_MIN, TM_MAX,
				led_tm_control_input.tm);
	writel(led_tm_control_read,
		led_cfg.reg_base_addr + CMIC_LEDUP0_TM_CONTROL_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_read_clk_div(unsigned long arg)
{
	u32 led_clk_div_read;
	struct led_clk_div led_clk_div_input;
	int ret;

	ret = copy_from_user(&led_clk_div_input,
				(struct led_clk_div *)arg,
				sizeof(led_clk_div_input));
	if (ret)
		return -EFAULT;
	led_clk_div_read = readl(led_cfg.reg_base_addr +
					CMIC_LEDUP0_CLK_DIV_OFFSET);
	if ((led_clk_div_input.mask & ALL_MASK) == ALL_MASK)
		led_clk_div_input.mask = (LEDCLK_HALF_PERIOD_MASK);
	if (led_clk_div_input.mask & LEDCLK_HALF_PERIOD_MASK)
		led_clk_div_input.ledclk_half_period =
				field_get32(led_clk_div_read,
						LEDCLK_HALF_PERIOD_MIN,
						LEDCLK_HALF_PERIOD_MAX);
	ret = copy_to_user((void *)arg,
				&led_clk_div_input,
				sizeof(led_clk_div_input));
	if (ret)
		return -EFAULT;
	return 0;
}

inline int led_brcm_ioctl_write_clk_div(unsigned long arg)
{
	u32 led_clk_div_read;
	struct led_clk_div led_clk_div_input;
	int ret;

	ret = copy_from_user(&led_clk_div_input,
				(struct led_clk_div *)arg,
				sizeof(led_clk_div_input));
	if (ret)
		return -EFAULT;
	led_clk_div_read = readl(led_cfg.reg_base_addr +
					CMIC_LEDUP0_CLK_DIV_OFFSET);
	if ((led_clk_div_input.mask & ALL_MASK) == ALL_MASK)
		led_clk_div_input.mask = (LEDCLK_HALF_PERIOD_MASK);
	if (led_clk_div_input.mask & LEDCLK_HALF_PERIOD_MASK)
		field_set32(&led_clk_div_read,
				LEDCLK_HALF_PERIOD_MIN,
				LEDCLK_HALF_PERIOD_MAX,
				led_clk_div_input.ledclk_half_period);
	writel(led_clk_div_read,
		led_cfg.reg_base_addr + CMIC_LEDUP0_CLK_DIV_OFFSET);
	return 0;
}

inline int led_brcm_ioctl_write_prog_area(unsigned long arg)
{
	u32 bytes;
	struct led_program led_program_input;
	int ret;

	ret = copy_from_user(&led_program_input.bytes,
				(struct led_program *)arg,
				sizeof(led_program_input.bytes));
	if (ret)
		return -EFAULT;
	bytes = led_program_input.bytes;
	ret = copy_from_user(&led_program_input,
			(struct led_program *)arg,
			sizeof(led_program_input.bytes) + bytes);
	if (ret)
		return -EFAULT;
	ret = brcm_led_init(&led_program_input.program[0], bytes);
	if (ret)
		return -EIO;
	return 0;
}

inline int led_brcm_ioctl_write_data_area(unsigned long arg)
{
	u32 bytes;
	u32 offset;
	u32 schan_start_val;
	u32 user_safe_data_offset;
	struct led_data led_data_input;
	int ret;

	ret = copy_from_user(&led_data_input.bytes,
				(struct led_data *)arg,
				sizeof(led_data_input.bytes));
	if (ret)
		return -EFAULT;
	bytes = led_data_input.bytes;
	ret = copy_from_user(&led_data_input,
				(struct led_data *)arg,
				sizeof(led_data_input.bytes) + bytes);
	if (ret)
		return -EFAULT;
	schan_start_val = field_get32(readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET),
				SCANCHAIN_ASSEMBLY_ST_ADDR_MIN,
				SCANCHAIN_ASSEMBLY_ST_ADDR_MAX);
	user_safe_data_offset = schan_start_val +
		  ((((leds_per_port * bits_per_led * max_ports) - 1) / 8) + 1);
	for (offset = 0 ; offset < bytes ; offset++) {
		writeb(led_data_input.data[offset],
			led_cfg.data_ram_base_addr +
			((user_safe_data_offset + offset) * 4));
	}
	pr_info("INFO:Updated User Data Bytes:%d @ %x\n",
		bytes , user_safe_data_offset);
	return 0;
}

inline int led_brcm_ioctl_dump_data_prog_area(unsigned long arg)
{
	u32 offset;
	struct led_data_program led_data_program_output;
	int ret;
	for (offset = 0 ; offset < LED_MAX_DATA_AREA_SIZE ; offset++) {
		led_data_program_output.data[offset] = readb(
			led_cfg.data_ram_base_addr + (offset*4));
	}
	for (offset = 0 ; offset < LED_MAX_PROGRAM_AREA_SIZE ; offset++) {
		led_data_program_output.program[offset] = readb(
			led_cfg.code_ram_base_addr + (offset*4));
	}
	ret = copy_to_user((void *)arg,
				&led_data_program_output ,
				sizeof(led_data_program_output));
	if (ret)
		return -EFAULT;
	return 0;
}

static long led_brcm_ioctl(struct file *filep,
				unsigned int cmd, unsigned long arg)
{
	int ret = 0;

	mutex_lock(&leds_ioctl_lock);

	switch (cmd) {
	case LED_IOCTL_READ_CTRL:
		ret = led_brcm_ioctl_read_ctrl(arg);
		break;
	case LED_IOCTL_WRITE_CTRL:
		ret = led_brcm_ioctl_write_ctrl(arg);
		break;
	case LED_IOCTL_READ_STATUS:
		ret = led_brcm_ioctl_read_status(arg);
		break;
	case LED_IOCTL_READ_SCANCHAIN_ASSEMBLY_ST_ADDR:
		ret = led_brcm_ioctl_read_scanchain_addr(arg);
		break;
	case LED_IOCTL_WRITE_SCANCHAIN_ASSEMBLY_ST_ADDR:
		ret = led_brcm_ioctl_write_scanchain_addr(arg);
		break;
	case LED_IOCTL_READ_CLK_PARAMS:
		ret = led_brcm_ioctl_read_clk_param(arg);
		break;
	case LED_IOCTL_WRITE_CLK_PARAMS:
		ret = led_brcm_ioctl_write_clk_param(arg);
		break;
	case LED_IOCTL_READ_SCANOUT_COUNT_UPPER:
		ret = led_brcm_ioctl_read_scanout_upper(arg);
		break;
	case LED_IOCTL_WRITE_SCANOUT_COUNT_UPPER:
		ret = led_brcm_ioctl_write_scanout_upper(arg);
		break;
	case LED_IOCTL_READ_TM_CONTROL:
		ret = led_brcm_ioctl_read_tm_control(arg);
		break;
	case LED_IOCTL_WRITE_TM_CONTROL:
		ret = led_brcm_ioctl_write_tm_control(arg);
		break;
	case LED_IOCTL_READ_CLK_DIV:
		ret = led_brcm_ioctl_read_clk_div(arg);
		break;
	case LED_IOCTL_WRITE_CLK_DIV:
		ret = led_brcm_ioctl_write_clk_div(arg);
		break;
	case LED_IOCTL_WRITE_PROG_AREA:
		ret = led_brcm_ioctl_write_prog_area(arg);
		break;
	case LED_IOCTL_WRITE_DATA_AREA:
		ret = led_brcm_ioctl_write_data_area(arg);
		break;
	case LED_IOCTL_DUMP_DATA_PROGRAM_AREA:
		ret = led_brcm_ioctl_dump_data_prog_area(arg);
		break;
	default:
		ret = -EINVAL;
	}

	mutex_unlock(&leds_ioctl_lock);
	return ret;
}

static const struct file_operations led_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = led_brcm_ioctl,
};

static int brcm_led_init(unsigned char *program, int bytes)
{
	u32 offset;
	u32 schan_start_val;
	u32 led_ctrl_val;

	if (bytes > LED_MAX_PROGRAM_AREA_SIZE)
		return -EINVAL;

	/* Copy User Program to LED processor Program Area */
	for (offset = 0; offset < bytes; offset++)
		writeb(program[offset],
			led_cfg.code_ram_base_addr + (offset * 4));

	/* Just to be safe, Reset Remaining Bytes of Program Area to Zero */
	for (; offset < LED_MAX_PROGRAM_AREA_SIZE; offset++)
		writeb(0x00, led_cfg.code_ram_base_addr + (offset * 4));

	/* Reset LED Process Data Area too (After SchanChain Bytes) */
	schan_start_val = field_get32(readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET),
				SCANCHAIN_ASSEMBLY_ST_ADDR_MIN,
				SCANCHAIN_ASSEMBLY_ST_ADDR_MAX);

	for (offset = schan_start_val; offset < LED_MAX_DATA_AREA_SIZE;
		offset++)
		writeb(0x00, led_cfg.data_ram_base_addr + (offset * 4));

	/* Don't Run Program. User should do it */
	led_ctrl_val = readl(led_cfg.reg_base_addr + CMIC_LEDUP0_CTRL_OFFSET);
	field_set32(&led_ctrl_val, LEDUP_EN_MIN, LEDUP_EN_MAX, 0);
	writel(led_ctrl_val, led_cfg.reg_base_addr + CMIC_LEDUP0_CTRL_OFFSET);
	return 0;
}

static int brcm_led_probe(struct platform_device *pdev)
{
	struct device_node *dn = pdev->dev.of_node;
	const struct of_device_id *match;
	int ret;
	u32 my_leds_per_port;
	u32 my_max_ports;
	u32 my_bits_per_led;
	u32 schan_start_val;

	dev_dbg(&pdev->dev, "BRCM XGXS LED Driver Being probed\n");

	match = of_match_device(brcm_led_of_match, &pdev->dev);
	if (!match) {
		dev_err(&pdev->dev, "can't find DT configuration\n");
		ret = -ENODEV;
		goto err_out;
	}

	if (!of_property_read_u32(dn, "leds-per-port", &my_leds_per_port))
		leds_per_port = my_leds_per_port;

	if (!of_property_read_u32(dn, "max-ports", &my_max_ports))
		max_ports = my_max_ports;

	if (!of_property_read_u32(dn, "bits-per-led", &my_bits_per_led))
		bits_per_led = my_bits_per_led;

	dev_dbg(&pdev->dev, "leds-per-port:%d\n", leds_per_port);
	dev_dbg(&pdev->dev, "max_ports:%d\n", max_ports);
	dev_dbg(&pdev->dev, "bits-per-led:%d\n", bits_per_led);

	led_cfg.reg_base_addr = of_iomap(dn, 0);
	if (!led_cfg.reg_base_addr) {
		dev_err(&pdev->dev, "can't iomap led_regs\n");
		ret = -EIO;
		goto err_unmap_reg_base_addr;
	}

	led_cfg.data_ram_base_addr = of_iomap(dn, 1);
	if (!led_cfg.data_ram_base_addr) {
		dev_err(&pdev->dev, "can't iomap led_data_ram\n");
		ret = -EIO;
		goto err_unmap_data_ram_base_addr;
	}

	led_cfg.code_ram_base_addr = of_iomap(dn, 2);
	if (!led_cfg.code_ram_base_addr) {
		dev_err(&pdev->dev, "can't iomap led_code_ram\n");
		ret = -EIO;
		goto err_unmap_code_ram_base_addr;
	}

	ret = led_cfg.led_major = register_chrdev(0, DRV_NAME, &led_fops);
	if (ret < 0) {
		dev_err(&pdev->dev, "Major number allocation failed");
		goto err_unmap_reg_base_addr;
	}

	led_cfg.dev_class = class_create(THIS_MODULE, "brcm-led");
	if (IS_ERR(led_cfg.dev_class)) {
		ret = PTR_ERR(led_cfg.dev_class);
		dev_err(&pdev->dev, "class create failed: %d\n", ret);
		goto err_drv_unreg;
	}

	led_cfg.dev = device_create(led_cfg.dev_class, NULL,
				MKDEV(led_cfg.led_major, 0), NULL, "brcm-led");
	if (IS_ERR(led_cfg.dev)) {
		dev_err(&pdev->dev, "Device creation failed\n");
		ret = -EFAULT;
		goto err_class_destroy;
	}

	mutex_init(&leds_ioctl_lock);

	/* Start with Empty Program and Data Space */
	brcm_led_init(NULL, 0);

	schan_start_val = field_get32(readl(led_cfg.reg_base_addr +
				CMIC_LEDUP0_SCANCHAIN_ASSEMBLY_ST_ADDR_OFFSET),
				SCANCHAIN_ASSEMBLY_ST_ADDR_MIN,
				SCANCHAIN_ASSEMBLY_ST_ADDR_MAX);
	dev_info(&pdev->dev,
		"BRCM XGXS LED Driver Initialized with Major:%d",
		led_cfg.led_major);
	dev_info(&pdev->dev,
		"INFO:User Program is expected to send max %d bits or pulses\n",
		(leds_per_port * bits_per_led * max_ports));
	dev_info(&pdev->dev, "INFO:Recommended User Safe Data Area:%2X-0xFF\n",
		schan_start_val +
		((((leds_per_port * bits_per_led * max_ports) - 1) / 8) + 1));
	return 0;

err_class_destroy:
	class_destroy(led_cfg.dev_class);

err_drv_unreg:
	unregister_chrdev(led_cfg.led_major, DRV_NAME);

err_unmap_code_ram_base_addr:
	iounmap(led_cfg.code_ram_base_addr);

err_unmap_data_ram_base_addr:
	iounmap(led_cfg.data_ram_base_addr);

err_unmap_reg_base_addr:
	iounmap(led_cfg.reg_base_addr);

err_out:
	return ret;
}

static int brcm_led_remove(struct platform_device *pdev)
{
	device_destroy(led_cfg.dev_class, MKDEV(led_cfg.led_major, 0));
	class_destroy(led_cfg.dev_class);
	unregister_chrdev(led_cfg.led_major, DRV_NAME);

	if (led_cfg.reg_base_addr) {
		iounmap(led_cfg.reg_base_addr);
		led_cfg.reg_base_addr = NULL;
	}
	if (led_cfg.data_ram_base_addr) {
		iounmap(led_cfg.data_ram_base_addr);
		led_cfg.data_ram_base_addr = NULL;
	}
	if (led_cfg.code_ram_base_addr) {
		iounmap(led_cfg.code_ram_base_addr);
		led_cfg.code_ram_base_addr = NULL;
	}
	return 0;
}

static struct platform_driver brcm_led_driver = {
	.driver = {
		.name = DRV_NAME,
		.owner = THIS_MODULE,
		.of_match_table = brcm_led_of_match
	},
	.remove    = brcm_led_remove,
	.probe     = brcm_led_probe,
};

module_platform_driver(brcm_led_driver);

MODULE_AUTHOR("Broadcom");
MODULE_DESCRIPTION("Broadcom XGXS LED Device Driver");
MODULE_LICENSE("GPL");
