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
#ifndef _LEDS_BRCM_XGXS_H
#define _LEDS_BRCM_XGXS_H


#define LED_MAX_PROGRAM_AREA_SIZE 256
#define LED_MAX_DATA_AREA_SIZE 256

#define LED_MAGIC    'l'
/* ioctl() command numbers */
#define LED_CMD_READ_CTRL				0x80
#define LED_CMD_WRITE_CTRL				0x81
#define LED_CMD_READ_STATUS				0x82
#define LED_CMD_READ_SCANCHAIN_ASSEMBLY_ST_ADDR		0x83
#define LED_CMD_WRITE_SCANCHAIN_ASSEMBLY_ST_ADDR	0x84
#define LED_CMD_READ_CLK_PARAMS				0x85
#define LED_CMD_WRITE_CLK_PARAMS			0x86
#define LED_CMD_READ_SCANOUT_COUNT_UPPER		0x87
#define LED_CMD_WRITE_SCANOUT_COUNT_UPPER		0x88
#define LED_CMD_READ_TM_CONTROL				0x89
#define LED_CMD_WRITE_TM_CONTROL			0x8a
#define LED_CMD_READ_CLK_DIV				0x8b
#define LED_CMD_WRITE_CLK_DIV				0x8c

#define LED_CMD_WRITE_PROG_AREA				0x8d
#define LED_CMD_WRITE_DATA_AREA				0x8e
#define LED_CMD_DUMP_DATA_PROGRAM_AREA			0x8f

#define LED_IOCTL_WRITE_PROG_AREA _IOR(LED_MAGIC,			\
					LED_CMD_WRITE_PROG_AREA,	\
					struct led_program)

struct led_program {
	unsigned int bytes;
	unsigned char program[1];
};

#define LED_IOCTL_WRITE_DATA_AREA _IOR(LED_MAGIC,			\
					LED_CMD_WRITE_DATA_AREA,	\
					struct led_data)

struct led_data {
	unsigned int bytes;
	unsigned char data[1];
};

#define LED_IOCTL_DUMP_DATA_PROGRAM_AREA _IOR(LED_MAGIC,	\
			LED_CMD_DUMP_DATA_PROGRAM_AREA,		\
			struct led_data_program)
struct led_data_program {
	unsigned char program[LED_MAX_PROGRAM_AREA_SIZE];
	unsigned char data[LED_MAX_PROGRAM_AREA_SIZE];
};

#define ALL_MASK 0xff

#define LED_IOCTL_READ_CTRL _IOR(LED_MAGIC,		\
				LED_CMD_READ_CTRL,	\
				struct led_ctrl)
#define LED_IOCTL_WRITE_CTRL _IOW(LED_MAGIC,			\
					LED_CMD_WRITE_CTRL,	\
					struct led_ctrl)
#define LEDUP_EN_MASK 0x1
#define LEDUP_START_DELAY_MASK 0x2
#define LEDUP_INTRA_PORT_DELAY_MASK 0x4
struct led_ctrl {
	unsigned int mask;
	unsigned int ledup_en;
	unsigned int ledup_start_delay;
	unsigned int ledup_intra_port_delay;
};

#define LED_IOCTL_READ_STATUS _IOR(LED_MAGIC,			\
					LED_CMD_READ_STATUS,	\
					struct led_status)

#define LEDUP_INITIALISING_MASK 0x1
#define LEDUP_RUNNING_MASK 0x2
#define PROGRAM_COUNTER_MASK 0x4
struct led_status {
	unsigned int mask;
	unsigned int ledup_initializing;
	unsigned int ledup_running;
	unsigned int program_counter;
};
#define LED_IOCTL_READ_SCANCHAIN_ASSEMBLY_ST_ADDR  _IOR(LED_MAGIC,	\
			LED_CMD_READ_SCANCHAIN_ASSEMBLY_ST_ADDR,	\
			struct led_scan_start)
#define LED_IOCTL_WRITE_SCANCHAIN_ASSEMBLY_ST_ADDR  _IOW(LED_MAGIC,	\
			LED_CMD_WRITE_SCANCHAIN_ASSEMBLY_ST_ADDR,	\
			struct led_scan_start)

#define SCANCHAIN_ASSEMBLY_ST_ADDR_MASK 0x1

struct led_scan_start {
	unsigned int mask;
	unsigned int scanchain_assembly_st_addr;
};
#define LED_IOCTL_READ_CLK_PARAMS _IOR(LED_MAGIC,			\
					LED_CMD_READ_CLK_PARAMS,	\
					struct led_clk_params)
#define LED_IOCTL_WRITE_CLK_PARAMS _IOW(LED_MAGIC,			\
					LED_CMD_WRITE_CLK_PARAMS,	\
					struct led_clk_params)

#define REFRESH_CYCLE_PERIOD_MASK 0x1

struct led_clk_params {
	unsigned int mask;
	unsigned int refresh_cycle_period;
};


#define LED_IOCTL_READ_SCANOUT_COUNT_UPPER _IOR(LED_MAGIC,	\
			LED_CMD_READ_SCANOUT_COUNT_UPPER,	\
			struct led_scanout_counter_upper)
#define LED_IOCTL_WRITE_SCANOUT_COUNT_UPPER _IOW(LED_MAGIC,	\
			LED_CMD_WRITE_SCANOUT_COUNT_UPPER,	\
			struct led_scanout_counter_upper)

#define SCANOUT_COUNT_UPPER_MASK 0x1

struct led_scanout_counter_upper {
	unsigned int mask;
	unsigned int scanout_counter_upper;
};

#define LED_IOCTL_READ_TM_CONTROL _IOR(LED_MAGIC,	\
					LED_CMD_READ_TM_CONTROL,	\
					struct led_tm_control)
#define LED_IOCTL_WRITE_TM_CONTROL _IOW(LED_MAGIC,	\
					LED_CMD_WRITE_TM_CONTROL,	\
					struct led_tm_control)
#define TM_MASK 0x1

struct led_tm_control {
	unsigned int mask;
	unsigned int tm;
};

#define LED_IOCTL_READ_CLK_DIV _IOR(LED_MAGIC,			\
					LED_CMD_READ_CLK_DIV,	\
					struct led_clk_div)
#define LED_IOCTL_WRITE_CLK_DIV (_IOW(LED_MAGIC,	\
					LED_CMD_WRITE_CLK_DIV,	\
					struct led_clk_div))

#define LEDCLK_HALF_PERIOD_MASK 0x1

struct led_clk_div {
	unsigned int mask;
	unsigned int ledclk_half_period;
};

#endif
