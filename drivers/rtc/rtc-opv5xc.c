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

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/time.h>
#include <linux/rtc.h>
#include <linux/bcd.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <asm/irq.h>
#include <linux/delay.h>
#include <linux/timer.h>

#include <mach/opv5xc.h>

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
#include "rtc-nvedit.h"
#endif

static struct timer_list opv5xc_rtc_timer;


#define RTC_IS_OPEN             0x01	/* /dev/rtc is in use */
#define RTC_TIMER_ON            0x02

#define RTC_INTR_ALARM          0x20
#define MINUS_30PPM             0x00
#define MINUS_15PPM             0x01
#define MINUS_10PPM             0x02
#define MINUS_0PPM              0x03
#define PLUS_10PPM              0x04
#define PLUS_15PPM              0x05
#define PLUS_30PPM              0x06
#define DEFAULT_PPM             MINUS_0PPM

/* RTC register offset */
#define RTC_CTRL_OFFSET         0x00
#define RTC_INTR_STS_OFFSET     0x04
#define RTC_PTP_CTRL_OFFSET     0x08
#define RTC_NSEC_OFFSET         0x10
#define RTC_SEC_OFFSET          0x14
#define RTC_MIN_OFFSET          0x18
#define RTC_HOUR_OFFSET         0x1C
#define RTC_DAY_OFFSET          0x20
#define RTC_REC_OFFSET          0x24
#define RTC_SEC_ALM_OFFSET      0x30
#define RTC_MIN_ALM_OFFSET      0x34
#define RTC_HOUR_ALM_OFFSET     0x38
#define RTC_DAY_ALM_OFFSET      0x3C
#define RTC_NSEC_UPD_OFFSET     0x40
#define RTC_SEC_UPD_OFFSET      0x44
#define RTC_MIN_UPD_OFFSET      0x48
#define RTC_HOUR_UPD_OFFSET     0x4C
#define RTC_DAY_UPD_OFFSET      0x50
#define PTP_NSEC_FIELD_OFFSET   0x60
#define PTP_SEC_FIELD_OFFSET    0x64
#define PTP_LSB_OFFSET          0x68
#define PTP_MSB_OFFSET          0x6C

/* RTC control register */
#define RTC_ALARM_ENABLE            (1 << 0)
#define RTC_ALARM_SEC_EN            (1 << 1)
#define RTC_ALARM_MIN_EN            (1 << 2)
#define RTC_ALARM_HOUR_EN           (1 << 3)
#define RTC_ALARM_DAY_EN            (1 << 4)
#define RTC_MATCH_ALARM_INTC_EN     (1 << 5)
#define BAT_INTE_LOW                (1 << 6)
#define BAT_ALARM_ENABLE            (1 << 8)
#define BAT_ALARM_SEC_EN            (1 << 9)
#define BAT_ALARM_MIN_EN            (1 << 10)
#define BAT_ALARM_HOUR_EN           (1 << 11)
#define BAT_ALARM_DAY_EN            (1 << 12)
#define BAT_ALARM_MATCH_EN          (1 << 13)
#define RTC_DEFUALT_DIGI_TRIM		(DEFAULT_PPM << 21)
#define RTC_SOFT_RESET              (1 << 24)
#define RTC_ACCESS_CMD              (1 << 28)
#define RTC_ACCESS_DIR_OFFSET       29
#define RTC_ACCESS_MOD_OFFSET       30
#define RTC_ACCESS_AUTO             31
#define RTC_ACCESS_AUTO_EN          (1 << 31)

#define RTC_INTR_CTRL_MASK          (0xF)
#define RTC_INTR_BAT_MASK           (0xF << 8)
#define RTC_INTR_CTRL_BAT_LOW       (1 << 5)
#define RTC_INTR_CTRL_ALARM         (1 << 4)
#define RTC_INTR_BAT_ALARM          (1 << 12)

#define READ_FILE			0
#define WRITE_FILE			1
/*powe saving sate */
#define NO_MODE				0
#define STANDBY_MODE		1
#define MEM_MODE			2
#define DISK_MODE			3
#define ON_MODE				4

static struct resource *opv5xc_rtc_mem;
static void __iomem *opv5xc_rtc_base;
static int opv5xc_rtc_irqno_alarm = NO_IRQ;
static int opv5xc_rtc_irqno_battery = NO_IRQ;
static spinlock_t rtc_lock;

/*static struct rtc_time set_alarm_tm;*/
static struct proc_dir_entry *opv5xc_proc_entry;
static int pm_state;
static struct device *device;

static int opv5xc_rtc_gettime(struct device *dev, struct rtc_time *rtc_tm);
static int opv5xc_rtc_getalarm(struct device *dev, struct rtc_wkalrm *alarm);

/* This function is copy from mktime().
 * mktime() converts Gregorian date to seconds since 1970-01-01 00:00:00,
 * but we just need calculates tatal days since 1970-01-01.
 */
static unsigned long
opv5xc_rtc_mkday(const unsigned int year0, const unsigned int mon0,
	const unsigned int day)
{
	unsigned int mon = mon0 + 1, year = year0 + 1900;

	/* 1..12 -> 3,4,..12,1,2 */
	mon -= 2;
	if ((int)mon <= 0) {
		mon += 12;	/* Puts Feb last since it has leap day */
		year -= 1;
	}

	return ((unsigned long)
		  (year/4 - year/100 + year/400 + 367*mon/12 + day) +
		  year*365 - 719499);
}

#define OPV5XC_RTC_READL(x) readl(opv5xc_rtc_base + x)

static int opv5xc_rtc_read_proc(struct seq_file *m, void *v)
{
	u32 tmp; /* plany, debug */

	seq_printf(m, "RTC_CTRL_OFFSET = %x\n", readl(opv5xc_rtc_base + RTC_CTRL_OFFSET));
	/* Shift out the RTC_BAT intr status */
	tmp = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	tmp &= ~(0x3 << RTC_ACCESS_DIR_OFFSET); /* clear ACESS_DIR and ACESS_MOD */
	tmp |= (RTC_ACCESS_CMD | (0x1 << RTC_ACCESS_MOD_OFFSET));
	writel(tmp, opv5xc_rtc_base + RTC_CTRL_OFFSET);
	seq_printf(m, "RTC_INTR_STS_OFFSET = %x\n", readl(opv5xc_rtc_base + RTC_INTR_STS_OFFSET));

	return 0;
}

static int en_bat_alarm_match;

static ssize_t opv5xc_rtc_write_proc(struct file *file, const char __user *buffer,
		size_t count, loff_t *ppos)
{
	struct rtc_time;
	u32 ctrl;

	dev_dbg(NULL, "enter rtc proc write, char:%s, count:%ud\n",
			buffer, count);

	if (count) {
		if (strncmp(buffer, "reset", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl |= RTC_SOFT_RESET;
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl &= ~(RTC_SOFT_RESET);
			ctrl |= RTC_ACCESS_CMD;
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "b2r", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-auto", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(RTC_ACCESS_AUTO_EN);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-auto", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= RTC_ACCESS_AUTO_EN;
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-bat-alarm-sec", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= (BAT_ALARM_ENABLE | BAT_ALARM_SEC_EN | RTC_ACCESS_CMD);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-bat-alarm-sec", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(BAT_ALARM_ENABLE | BAT_ALARM_SEC_EN);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-bat-alarm-min", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= (BAT_ALARM_ENABLE | BAT_ALARM_MIN_EN | RTC_ACCESS_CMD);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-bat-alarm-min", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(BAT_ALARM_ENABLE | BAT_ALARM_MIN_EN);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-bat-alarm-hour", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= (BAT_ALARM_ENABLE | BAT_ALARM_HOUR_EN | RTC_ACCESS_CMD);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-bat-alarm-hour", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(BAT_ALARM_ENABLE | BAT_ALARM_HOUR_EN);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-bat-alarm-day", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= (BAT_ALARM_ENABLE | BAT_ALARM_DAY_EN | RTC_ACCESS_CMD);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-bat-alarm-day", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(BAT_ALARM_ENABLE | BAT_ALARM_DAY_EN);
			ctrl |= RTC_ACCESS_CMD;
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-rtc-alarm", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl |= (RTC_ALARM_SEC_EN | RTC_ALARM_MIN_EN | RTC_ALARM_DAY_EN | RTC_ALARM_HOUR_EN);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "dis-rtc-alarm", count - 1) == 0) {
			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			ctrl &= ~(RTC_ALARM_SEC_EN | RTC_ALARM_MIN_EN | RTC_ALARM_DAY_EN | RTC_ALARM_HOUR_EN);
			dev_dbg(NULL, "ctrl = %x\n", ctrl);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		} else if (strncmp(buffer, "en-bat-alarm-match", count - 1) == 0) {
			en_bat_alarm_match = 1;
		} else if (strncmp(buffer, "dis-bat-alarm-match", count - 1) == 0) {
			en_bat_alarm_match = 0;
		} else if (strncmp(buffer, "alarm_int_test", count - 1) == 0) {
			while (readl(opv5xc_rtc_base + RTC_SEC_OFFSET) > 50) {
				printk(KERN_INFO "Wait a good moment for test...\n");
				msleep(1000);
			}
			writel(readl(opv5xc_rtc_base + RTC_DAY_OFFSET), opv5xc_rtc_base + RTC_DAY_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_HOUR_OFFSET), opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_MIN_OFFSET), opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_SEC_OFFSET) + 5, opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);

			writel(RTC_INTR_CTRL_ALARM, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);

			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl |= (RTC_ACCESS_CMD | RTC_ALARM_ENABLE | RTC_MATCH_ALARM_INTC_EN);
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
			printk(KERN_INFO "Interrup should occur after 5 seconds...\n");
		} else if (strncmp(buffer, "battery_int_test", count - 1) == 0) {
			while (readl(opv5xc_rtc_base + RTC_SEC_OFFSET) > 50) {
				printk(KERN_INFO "Wait a good moment for test...\n");
				msleep(1000);
			}
			writel(readl(opv5xc_rtc_base + RTC_DAY_OFFSET), opv5xc_rtc_base + RTC_DAY_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_HOUR_OFFSET), opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_MIN_OFFSET), opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
			writel(readl(opv5xc_rtc_base + RTC_SEC_OFFSET) + 5, opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);

			writel(RTC_INTR_BAT_ALARM, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);

			ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
			ctrl |= (RTC_ACCESS_CMD | BAT_ALARM_ENABLE | BAT_ALARM_MATCH_EN |
				(0x3 << RTC_ACCESS_DIR_OFFSET));
			writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
			printk(KERN_INFO "Interrup should occur after 5 seconds...\n");
		}
	}

	return count;
}

static int opv5xc_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, opv5xc_rtc_read_proc, NULL);
}

static const struct file_operations opv5xc_proc_fops = {
	.open		= opv5xc_proc_open,
	.read           = seq_read,
	.write		= opv5xc_rtc_write_proc,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int __init opv5xc_rtc_proc_init(void)
{

	if (opv5xc_proc_dir == NULL) {
		printk(KERN_INFO "Please Create Proc First\n");
		BUG();
	}

	opv5xc_proc_entry = proc_create_data("rtc", S_IFREG | S_IRUGO,
			opv5xc_proc_dir, &opv5xc_proc_fops, NULL);

	return 1;
}

static irqreturn_t opv5xc_rtc_bat_irq_handler(int irq, void *id)
{
	struct rtc_time current_rtc_time;
	unsigned long events = 0;
	u32 status;

	dev_dbg(NULL, "bat alarm interrupt !\n");
	opv5xc_rtc_gettime(device, &current_rtc_time);

	/* Shift out the RTC_BAT intr status */
	status = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	dev_dbg(NULL, "read RTC_CTRL_OFFSET = %x\n", status);
	/* clear ACESS_DIR and ACESS_MOD, disable BAT_ALARM */
	status &= ~((0x3 << RTC_ACCESS_DIR_OFFSET) | BAT_ALARM_ENABLE);
	status |= (RTC_ACCESS_CMD | (0x1 << RTC_ACCESS_MOD_OFFSET));
	dev_dbg(NULL, "write RTC_CTRL_OFFSET = %x\n", status);
	writel(status, opv5xc_rtc_base + RTC_CTRL_OFFSET);

	/* Read RTC_BAT intr status */
	status = readl(opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
	dev_dbg(NULL, "status = %x\n", status);
	if (status) {
		spin_lock(&rtc_lock);
		/* write 1 to clear interrupt status */
		writel(status, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
		spin_unlock(&rtc_lock);
	}

	/* check if Alarm */
	if (status & RTC_INTR_BAT_ALARM)
		events |= RTC_IRQF | RTC_AF;

	/* check if Periodic */
	if (status & RTC_INTR_BAT_MASK)
		events |= RTC_IRQF | RTC_PF;

	dev_dbg(NULL, "events = %lx\n", events);

	return IRQ_HANDLED;
}

static void opv5xc_rtc_timer_func(unsigned long data)
{
	u32 status, ctrl;

	status = readl(opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
	if (status & RTC_INTR_CTRL_BAT_LOW)
		printk(KERN_INFO "RTC Low Battery !!!\n");

	spin_lock(&rtc_lock);
	/* write 1 to clear interrupt status */
	writel(status, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
	spin_unlock(&rtc_lock);

	ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	ctrl |= RTC_ACCESS_CMD;
	ctrl |= BAT_INTE_LOW;
	spin_lock(&rtc_lock);
	writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
	spin_unlock(&rtc_lock);
}

static irqreturn_t opv5xc_rtc_ctrl_irq_handler(int irq, void *id)
{
	struct rtc_device *dev = id;
	struct rtc_time current_rtc_time;
	unsigned long events = 0;
	u32 status, ctrl;

	dev_dbg(NULL, "rtc alarm interrupt !\n");
	opv5xc_rtc_gettime(device, &current_rtc_time);

	status = readl(opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
	dev_dbg(&dev->dev, "status = %x\n", status);
	if (status & RTC_INTR_CTRL_BAT_LOW) {
		opv5xc_rtc_timer.expires = jiffies + 5;
		opv5xc_rtc_timer.function = opv5xc_rtc_timer_func;
		add_timer(&opv5xc_rtc_timer);
		status &= ~RTC_INTR_CTRL_BAT_LOW;
		ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
		ctrl |= RTC_ACCESS_CMD;
		ctrl &= ~BAT_INTE_LOW;
		spin_lock(&rtc_lock);
		writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		spin_unlock(&rtc_lock);
	}
	if (status) {
		spin_lock(&rtc_lock);
		/* write 1 to clear interrupt status */
		writel(status, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
		spin_unlock(&rtc_lock);
	}

	if (status & RTC_INTR_CTRL_ALARM)
		events |= RTC_IRQF | RTC_AF;

	if (status & RTC_INTR_CTRL_MASK)
		events |= RTC_IRQF | RTC_PF;

	dev_dbg(&dev->dev, "events = %lx\n", events);

	rtc_update_irq(dev, 1, events);

	return IRQ_HANDLED;
}

static int opv5xc_rtc_ioctl(struct device *dev, unsigned int cmd,
			     unsigned long arg)
{
	unsigned long ctrl;

	ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);

	dev_dbg(dev, "%s: ctrl = %lx\n", __func__, ctrl);
	switch (cmd) {
	case RTC_AIE_OFF:
		dev_dbg(dev, "opv5xc_rtc_ioctl: disable alarm\n");
		ctrl &= ~RTC_MATCH_ALARM_INTC_EN;
		writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		return 0;
	case RTC_AIE_ON:
		dev_dbg(dev, "opv5xc_rtc_ioctl: enable alarm\n");
		ctrl |= RTC_MATCH_ALARM_INTC_EN;
		writel(ctrl, opv5xc_rtc_base + RTC_CTRL_OFFSET);
		return 0;
	default:
		dev_dbg(dev, "un support ioctl:%ux\n", cmd);
		/*return 0; */
	}
	return -ENOIOCTLCMD;
}

static int opv5xc_rtc_gettime(struct device *dev, struct rtc_time *tm)
{
	unsigned int second, minute, hour, day;
	unsigned long total_second;
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	unsigned long rtc_record;
#endif

	spin_lock(&rtc_lock);

	second = readl(opv5xc_rtc_base + RTC_SEC_OFFSET);
	minute = readl(opv5xc_rtc_base + RTC_MIN_OFFSET);
	hour = readl(opv5xc_rtc_base + RTC_HOUR_OFFSET);
	day = readl(opv5xc_rtc_base + RTC_DAY_OFFSET);
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	rtc_record = readl(opv5xc_rtc_base + RTC_REC_OFFSET);
#endif

	spin_unlock(&rtc_lock);

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	total_second = day * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second + rtc_record;
#else
	total_second = day * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second;
#endif

	rtc_time_to_tm(total_second, tm);

	dev_dbg(dev, "read time %d/%d/%d %d:%d:%d\n",
		 tm->tm_year, tm->tm_mon, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);

	return 0;
}

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
static int opv5xc_rtc_settime(struct device *dev, struct rtc_time *tm)
{
	unsigned int second, minute, hour, day;
	unsigned long rtc_record;
	unsigned long total_second;
	unsigned char write_value[8];

	dev_dbg(dev, "set time %02d.%02d.%02d %02d/%02d/%02d\n",
		 tm->tm_year, tm->tm_mon, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);

	rtc_tm_to_time(tm, &rtc_record);

	spin_lock(&rtc_lock);

	second = readl(opv5xc_rtc_base + RTC_SEC_OFFSET);
	minute = readl(opv5xc_rtc_base + RTC_MIN_OFFSET);
	hour = readl(opv5xc_rtc_base + RTC_HOUR_OFFSET);
	day = readl(opv5xc_rtc_base + RTC_DAY_OFFSET);

	total_second = day * 24 * 60 * 60 + hour * 60 * 60 + minute * 60 + second;
	if (rtc_record >= total_second) {
		rtc_record -= total_second;
		writel(rtc_record, opv5xc_rtc_base + RTC_REC_OFFSET);
		sprintf(write_value, "%8x", (unsigned int)rtc_record);
		spin_unlock(&rtc_lock);

		if (rtcnvet_do_setenv(RTC_LOG_NAME, write_value))
			dev_dbg(dev, "write rtc_rec to flash failed!\n");
	} else {
		spin_unlock(&rtc_lock);
		printk(KERN_ERR "Don't set the time before the RTC time\n");
	}

	return 0;
}
#else /* !CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH */
static int opv5xc_rtc_settime(struct device *dev, struct rtc_time *tm)
{
	dev_dbg(dev, "set time %d/%d/%d %d:%d:%0d\n",
		 tm->tm_year, tm->tm_mon, tm->tm_mday,
		 tm->tm_hour, tm->tm_min, tm->tm_sec);

	spin_lock(&rtc_lock);

	writel(0, opv5xc_rtc_base + RTC_NSEC_UPD_OFFSET);
	writel((unsigned long)(tm->tm_sec), opv5xc_rtc_base + RTC_SEC_UPD_OFFSET);
	writel((unsigned long)(tm->tm_min), opv5xc_rtc_base + RTC_MIN_UPD_OFFSET);
	writel((unsigned long)(tm->tm_hour), opv5xc_rtc_base + RTC_HOUR_UPD_OFFSET);
	writel((unsigned long)(opv5xc_rtc_mkday(tm->tm_year, tm->tm_mon, tm->tm_mday)), opv5xc_rtc_base + RTC_DAY_UPD_OFFSET);

	dev_dbg(dev, "day: %d\n", readl(opv5xc_rtc_base + RTC_DAY_OFFSET));
	dev_dbg(dev, "hour: %d\n", readl(opv5xc_rtc_base + RTC_HOUR_OFFSET));
	dev_dbg(dev, "min: %d\n", readl(opv5xc_rtc_base + RTC_MIN_OFFSET));
	dev_dbg(dev, "sec: %d\n", readl(opv5xc_rtc_base + RTC_SEC_OFFSET));

	spin_unlock(&rtc_lock);

	return 0;
}
#endif /* !CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH */

static int opv5xc_rtc_alarm_irq_enable(struct device *dev, unsigned int enabled)
{
	u32 reg;

	spin_lock(&rtc_lock);
	reg = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	dev_dbg(dev, "%s: reg = %x\n", __func__, reg);
	reg &= ~(RTC_MATCH_ALARM_INTC_EN);
	if (enabled)
		reg |= RTC_MATCH_ALARM_INTC_EN;
	dev_dbg(dev, "%s: reg = %x\n", __func__, reg);
	writel(reg, opv5xc_rtc_base + RTC_CTRL_OFFSET);
	spin_unlock(&rtc_lock);

	return 0;
}

static int opv5xc_rtc_getalarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct rtc_time *alm_tm = &alarm->time;
	unsigned long total_alarm_second, total_alarm_day;
	u32 status, ctrl;
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	unsigned long rtc_record;
#endif

	spin_lock(&rtc_lock);

	alm_tm->tm_sec = readl(opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);
	alm_tm->tm_min = readl(opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
	alm_tm->tm_hour = readl(opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);

	total_alarm_day = readl(opv5xc_rtc_base + RTC_DAY_ALM_OFFSET);
	total_alarm_second = alm_tm->tm_mday * 24 * 60 * 60 + alm_tm->tm_hour * 60 * 60 + alm_tm->tm_min * 60 + alm_tm->tm_sec;
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	rtc_record = readl(opv5xc_rtc_base + RTC_REC_OFFSET);
	total_alarm_second += rtc_record;
#endif
	dev_dbg(dev, "get alarm total sec:%lux\n", total_alarm_second);
	rtc_time_to_tm(total_alarm_second, alm_tm);

	status = readl(opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
	dev_dbg(dev, "interrupt status = %x\n", status);
	alarm->pending = (status & RTC_INTR_CTRL_ALARM) ? 1 : 0;

	ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	alarm->enabled = (ctrl & RTC_MATCH_ALARM_INTC_EN) ? 1 : 0;

	spin_unlock(&rtc_lock);

	dev_dbg(dev, "opv5xc_rtc_getalarm: (%d), %d/%d/%d-%d:%d:"
			"%d\n", alarm->enabled, alm_tm->tm_year,
			alm_tm->tm_mon, alm_tm->tm_mday, alm_tm->tm_hour,
			alm_tm->tm_min, alm_tm->tm_sec);

	return 0;
}

static int opv5xc_rtc_setalarm(struct device *dev, struct rtc_wkalrm *alarm)
{
	struct rtc_time *alm_tm = &alarm->time;
	u32 ctrl;
	unsigned long total_alarm_day;
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	unsigned long total_second, rtc_record;
	struct rtc_time tm;
#endif

	dev_dbg(dev, "opv5xc_rtc_setalarm: (%d), %d/%d/%d %d:%d:"
			"%d\n", alarm->enabled, alm_tm->tm_year & 0xff,
			alm_tm->tm_mon & 0xff, alm_tm->tm_mday & 0xff,
			alm_tm->tm_hour & 0xff, alm_tm->tm_min & 0xff,
			alm_tm->tm_sec);

	spin_lock(&rtc_lock);

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	rtc_tm_to_time(alm_tm, &total_second);
	rtc_record = readl(opv5xc_rtc_base + RTC_REC_OFFSET);
	total_second -= rtc_record;
	rtc_time_to_tm(total_second, &tm);
	alm_tm = &tm;
#endif

	/* Setup RTC alarm register */
	total_alarm_day = opv5xc_rtc_mkday(alm_tm->tm_year, alm_tm->tm_mon, alm_tm->tm_mday);
	dev_dbg(dev, "total_alarm_day = %lu\n", total_alarm_day);
	writel(alm_tm->tm_sec, opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);
	writel(alm_tm->tm_min, opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
	writel(alm_tm->tm_hour, opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);
	writel(total_alarm_day, opv5xc_rtc_base + RTC_DAY_ALM_OFFSET);

	if (en_bat_alarm_match == 0) {
		/* Clear rtc_alarm interrupt */
		writel(RTC_INTR_CTRL_ALARM, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
		alarm->pending = 0;

		/* Enable RTC match alarm interrupt, interrupt will up when sec, min,
		 * hour and day are the same with RTC alarm register(0x30~0x3C).
		 */
		ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
		writel(ctrl | RTC_MATCH_ALARM_INTC_EN,
				opv5xc_rtc_base + RTC_CTRL_OFFSET);
	} else {
		/* Clear rtc_alarm interrupt */
		writel(RTC_INTR_BAT_ALARM, opv5xc_rtc_base + RTC_INTR_STS_OFFSET);
		alarm->pending = 0;

		/* Enable RTC match alarm interrupt, interrupt will up when sec, min,
		 * hour and day are the same with RTC alarm register(0x30~0x3C).
		 */
		ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
		writel(ctrl | BAT_ALARM_ENABLE | BAT_ALARM_MATCH_EN |
			RTC_ACCESS_CMD | (0x3 << RTC_ACCESS_DIR_OFFSET),
			opv5xc_rtc_base + RTC_CTRL_OFFSET);
	}

	alarm->enabled = 1;
	pm_state = ON_MODE;
	spin_unlock(&rtc_lock);

	if (alarm->enabled)
		enable_irq_wake(opv5xc_rtc_irqno_alarm);
	else
		disable_irq_wake(opv5xc_rtc_irqno_alarm);
	return 0;
}

static int opv5xc_rtc_proc(struct device *dev, struct seq_file *seq)
{
#ifdef CONFIG_RTC_DEBUG
	int i;

	seq_printf(seq, "===== REGISTER DUMP =====\n");
	seq_printf(seq, "=========================\n");
	seq_printf(seq, "OFFSET     VALUE ========\n");
	seq_printf(seq, "=========================\n");
	for (i = 0x0; i <= 0x6c; i += 0x4) {
		if (i == 0x28 || i == 0x2C || i == 0x54 || i == 0x58 || i == 0x5C)
			continue;
		seq_printf(seq, "0x%04x%15.8x\n", i, OPV5XC_RTC_READL(i));
	}
#endif
	return 0;
}

static const struct rtc_class_ops opv5xc_rtcops = {
	.ioctl		= opv5xc_rtc_ioctl,
	.read_time	= opv5xc_rtc_gettime,
	.set_time	= opv5xc_rtc_settime,
	.read_alarm	= opv5xc_rtc_getalarm,
	.set_alarm	= opv5xc_rtc_setalarm,
	.proc		= opv5xc_rtc_proc,
	.alarm_irq_enable = opv5xc_rtc_alarm_irq_enable,
};

static char banner[] =
	KERN_INFO "OPV5XC Real Time Clock, (c) 2013 Open-Silicon\n";

static int opv5xc_rtc_probe(struct platform_device *dev)
{
	struct rtc_device *rtc;
	struct resource *res;
	unsigned long ctrl;
	int ret = 0;
#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	unsigned long rtc_rec;
	char *buffer = NULL;
#endif
	struct completion rtc_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

	init_completion(&rtc_complete);

	printk(banner);
	spin_lock_init(&rtc_lock);

	dev_dbg(&dev->dev, "%s: probe=%p\n", __func__, dev);

	/* We only accept one device, and it must have an id of -1 */
	if (dev->id != -1)
		return -ENODEV;

#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) & ~(1 << 5), OPV5XC_CR_PMU_BASE_VIRT);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 5)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 5)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) | (1 << 5), OPV5XC_CR_PMU_BASE_VIRT);

	/* Also have to de-asserted the PTP soft-rst */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 24)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 24)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);

	opv5xc_rtc_irqno_alarm = platform_get_irq(dev, 0);
	opv5xc_rtc_irqno_battery = opv5xc_rtc_irqno_alarm + 1;
#else
	opv5xc_rtc_irqno_battery = platform_get_irq(dev, 0);
	opv5xc_rtc_irqno_alarm = opv5xc_rtc_irqno_battery + 1;
#endif
	do {
		wait_for_completion_timeout(&rtc_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<5)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		printk(KERN_ERR "\n: Timeout while enabling power for RTC \n");
		return -ENODEV;
	}

	if ((opv5xc_rtc_irqno_alarm < 0) || (opv5xc_rtc_irqno_battery < 0)) {
		dev_err(&dev->dev, "no irq for alarm\n");
		return -ENOENT;
	}
	dev_dbg(&dev->dev, "opv5xc_rtc: alarm irq %d\n", opv5xc_rtc_irqno_alarm);
	dev_dbg(&dev->dev, "opv5xc_rtc: battery irq %d\n", opv5xc_rtc_irqno_battery);

	res = platform_get_resource(dev, IORESOURCE_MEM, 0);
	if (res == NULL) {
		dev_err(&dev->dev, "failed to get memory region resource\n");
		return -ENODEV;
	}
	opv5xc_rtc_mem =
		request_mem_region(res->start, res->end - res->start + 1,
				dev->name);
	if (opv5xc_rtc_mem == NULL) {
		dev_err(&dev->dev, "failed to reserve memory region\n");
		ret = -ENOENT;
		goto err_nortc;
	}

	opv5xc_rtc_base = ioremap(res->start, res->end - res->start + 1);
	if (opv5xc_rtc_base == NULL) {
		dev_err(&dev->dev, "failed ioremap()\n");
		ret = -ENOMEM;
		goto err_free;
	}

	/* first, disable RTC and initial RTC alarm registers */
	writel(0, opv5xc_rtc_base + RTC_CTRL_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);

	/* enable RTC and synchronize the RTC_CTL timing stamp with RTC_BAT */
	ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	writel(ctrl | RTC_ACCESS_AUTO_EN | RTC_ACCESS_CMD | RTC_DEFUALT_DIGI_TRIM | BAT_INTE_LOW | RTC_ALARM_ENABLE, opv5xc_rtc_base + RTC_CTRL_OFFSET);

	/* register RTC */
	rtc = rtc_device_register("opv5xc-rtc", &dev->dev, &opv5xc_rtcops, THIS_MODULE);
	if (IS_ERR(rtc)) {
		dev_err(&dev->dev, "cannot attach rtc\n");
		ret = PTR_ERR(rtc);
		goto err_nores;
	}

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	/*
	 * since RTC can't save the hardware time. we need to retrieve the
	 * offset rec from flash.
	 */
	rtcnvet_init();
	rtcnvet_get_env(RTC_LOG_NAME, &buffer);
	if (buffer) {
		rtc_rec = simple_strtoul(buffer, NULL, 16);
		writel(rtc_rec, opv5xc_rtc_base + RTC_REC_OFFSET);
		dev_dbg(&dev->dev, "read from flash value:%s, write to register value:"
						"%lux\n", buffer, rtc_rec);
	}
#endif

	opv5xc_rtc_proc_init();
	device_init_wakeup(&dev->dev, 1);
	platform_set_drvdata(dev, rtc);

	/* Request alarm interrupt for RTC_CTRL and RTC_BAT */
	ret = request_irq(opv5xc_rtc_irqno_battery, opv5xc_rtc_bat_irq_handler, IRQF_DISABLED, "opv5xc-rtc-bat alarm", rtc);
	if (ret) {
		dev_err(&dev->dev,
			"Unable to request interrupt for RTC_BAT (err=%d).\n",
			ret);
		goto err_unreg;
	}

	ret = request_irq(opv5xc_rtc_irqno_alarm, opv5xc_rtc_ctrl_irq_handler, IRQF_DISABLED, "opv5xc-rtc-ctrl alarm", rtc);
	if (ret) {
		dev_err(&dev->dev,
			"Unable to request interrupt for RTC_CTRL (err=%d).\n",
			ret);
		goto err_unreg;
	}

	init_timer(&opv5xc_rtc_timer);

	return 0;

err_unreg:
	rtc_device_unregister(rtc);
err_nores:
	iounmap(opv5xc_rtc_base);
err_free:
	release_resource(opv5xc_rtc_mem);
	kfree(opv5xc_rtc_mem);
err_nortc:
	dev_dbg(&dev->dev, "probe func has something wrong!\n");
	return ret;
}

static int opv5xc_rtc_remove(struct platform_device *dev)
{
	struct rtc_device *rtc = platform_get_drvdata(dev);

	dev_dbg(&dev->dev, "%s: remove=%p\n", __func__, dev);

	free_irq(opv5xc_rtc_irqno_alarm, rtc);
	free_irq(opv5xc_rtc_irqno_battery, rtc);
	remove_proc_entry("rtc", opv5xc_proc_dir);
	platform_set_drvdata(dev, NULL);

	rtc_device_unregister(rtc);

	iounmap(opv5xc_rtc_base);
	release_resource(opv5xc_rtc_mem);
	kfree(opv5xc_rtc_mem);

#ifdef CONFIG_RTC_DRV_OPV5XC_LOG_IN_FLASH
	rtcnvet_exit();
#endif
	del_timer(&opv5xc_rtc_timer);

	return 0;
}

#ifdef CONFIG_PM

static int opv5xc_rtc_suspend(struct platform_device *dev, pm_message_t state)
{
	dev_dbg(&dev->dev, "%s,%s,%d\n", __FILE__, __func__, __LINE__);

	return 0;
}

static int opv5xc_rtc_resume(struct platform_device *dev)
{
	struct completion rtc_complete;
	unsigned long timeout = usecs_to_jiffies(100);
	int counter = 100, val = 0;

	unsigned long ctrl;
	dev_dbg(&dev->dev, "%s,%s,%d\n", __FILE__, __func__, __LINE__);

	init_completion(&rtc_complete);
#if defined(CONFIG_ARCH_OPV5XC_ES1) || defined(CONFIG_ARCH_OPV5XC_ES2)
	/* clock enable */
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) & ~(1 << 5), OPV5XC_CR_PMU_BASE_VIRT);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 5)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 5)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel(readl(OPV5XC_CR_PMU_BASE_VIRT) | (1 << 5), OPV5XC_CR_PMU_BASE_VIRT);

	do {
		wait_for_completion_timeout(&rtc_complete, timeout);
		if (readl(OPV5XC_CR_PMU_BASE_VIRT + 0x10) & (1<<5)) {
			val = 1;
			break;
		}
	} while (counter-- != 0);
	if ((counter == 0) && (val == 0)) {
		printk(KERN_ERR "\n: Timeout while enabling power for RTC \n");
		return -ENODEV;
	}

	/* Also have to de-asserted the PTP soft-rst */
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) & ~(1 << 24)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);
	writel((readl(OPV5XC_CR_PMU_BASE_VIRT + 0x04) | (1 << 24)), OPV5XC_CR_PMU_BASE_VIRT + 0x04);

#endif

	/* first, disable RTC and initial RTC alarm registers */
	writel(0, opv5xc_rtc_base + RTC_CTRL_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_SEC_ALM_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_MIN_ALM_OFFSET);
	writel(0, opv5xc_rtc_base + RTC_HOUR_ALM_OFFSET);

	/* enable RTC and synchronize the RTC_CTL timing stamp with RTC_BAT */
	ctrl = readl(opv5xc_rtc_base + RTC_CTRL_OFFSET);
	writel(ctrl | RTC_ACCESS_AUTO_EN | RTC_ACCESS_CMD | RTC_DEFUALT_DIGI_TRIM | BAT_INTE_LOW | RTC_ALARM_ENABLE, opv5xc_rtc_base + RTC_CTRL_OFFSET);

	return 0;
}

#else
#define opv5xc_rtc_suspend	NULL
#define opv5xc_rtc_resume	NULL
#endif /* CONFIG_PM */

static struct platform_driver opv5xc_rtcdrv = {
	.probe		= opv5xc_rtc_probe,
	.remove		= opv5xc_rtc_remove,
	.suspend	= opv5xc_rtc_suspend,
	.resume		= opv5xc_rtc_resume,
	.driver		= {
		.name		= "opv5xc-rtc",
		.owner		= THIS_MODULE,
	},
};

module_platform_driver(opv5xc_rtcdrv);

MODULE_AUTHOR("Plany Kao <plany.kao@open-silicon.com>");
MODULE_DESCRIPTION("Open-Silicon OPV5XC RTC Driver");
MODULE_LICENSE("GPL");
MODULE_ALIAS("platform:opv5xc-rtc");
