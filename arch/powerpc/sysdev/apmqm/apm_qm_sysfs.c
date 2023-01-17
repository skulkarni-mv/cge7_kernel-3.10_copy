/**
 * AppliedMicro APM862xx SoC QM Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * @file apm_qm_sysfs.c
 *
 * This file implements sysfs interface for APM862xx SoC QM subsystem
 *
 */

#if defined(CONFIG_SYSFS)
#include <linux/slab.h>
#include <linux/stat.h>
#include <asm/apm_qm_sysfs.h>
#include <asm/apm_qm_core.h>
#include <asm/apm_qm_access.h>

#define MAX_MB_IDX	(MAX_MAILBOXS - 1)
#define MIN_MB_IDX	0
#define MSG_NOT_EMPTY_COAL_TAP 0x7

static int coalesce_cnt = 0x4;

static ssize_t apm_qm_coal_intr_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf,
		"--------------------Help------------------------------\n"
		"1.Enable coalescence for a perticular mailbox inturrupt -\n"
		"echo mb_intr <mb_no between 0 - 15> enable\n"
		"2.Enable coalescence for all mailbox inturrupts - \n"
		"echo all enable\n"
		"3.Enable coalescence for a perticular mailbox inturrupt -\n"
		"echo mb_intr <mb_no between 0 - 15> disable\n"
		"4. Disable coalescence for all mailbox inturrupts - \n"
		"echo all disable\n"
		"5. Set coalescence count -\n"
		"echo count <value>\n");
}

int apm_qm_parse_enable(char *str)
{
	int rc;

	if (!strcmp(str, "enable")) {
		printk("\nEnable all mb interrupts coal (%d)\n", coalesce_cnt);
		rc = 0;
	} else if (!strcmp(str, "disable")) {
		printk("\nDisable all mb interrupts coal\n");
		rc = 1;
	} else {
		printk("Wrong option : %s\n", str);
		rc = -1;
	}

	return rc;
}

static ssize_t apm_qm_coal_intr_set(struct device_driver *drv,
				     const char *buf, size_t count)
{
	int ret;
	char *str;
	int intr_no = 0;
	int i;
	int tap;

	str = kzalloc(sizeof(buf), GFP_KERNEL);
	if (!str) {
		printk("%s Failed to allocate memory\n", str);
		return count;
	}

	ret = sscanf(buf, "%s", str);

	if (!strcmp(str, "all")) {
		memset(str, 0, sizeof(str));
		ret = sscanf(buf + 4, "%s", str);

		if ((ret = apm_qm_parse_enable(str)) == -1)
			return count;

		/* Disable coalescence */
		if (ret == 1) {
			tap = 0;
			apm_qm_msg_not_empty_intr_coal_set(tap);
		} else {
			apm_qm_msg_not_empty_intr_coal_set(
					MSG_NOT_EMPTY_COAL_TAP);
			tap = coalesce_cnt;
		}

		for (i = 0; i < 16; i ++)
			apm_qm_mbox_set_coal(i, tap);

	} else if(!strcmp(str, "mb_intr")) {

		sscanf(buf + 7 , "%d", &intr_no);
		memset(str, 0, sizeof(str));
		ret = sscanf(buf + 10, "%s", str);

		if ((ret = apm_qm_parse_enable(str)) == -1)
			return count;

		/* Disable coalescence */
		if (ret == 1) {
			tap = 0;
		} else {
			apm_qm_msg_not_empty_intr_coal_set(
						MSG_NOT_EMPTY_COAL_TAP);
			tap = coalesce_cnt;
		}

		if (intr_no > MAX_MB_IDX || intr_no < MIN_MB_IDX)
			return count;

		apm_qm_mbox_set_coal(intr_no, tap);

	} else if (!strcmp(str, "count")) {
		sscanf(buf + 5, "%d", &i);
		if (i >= 1 && i <= 7)
			coalesce_cnt = i;
	} else {
		printk("Wrong option\n");
	}

        return count;
}

static ssize_t apm_qm_enq_stats_qid_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%d\n", apm_qm_enq_stats_getqid(IP_BLK_QM));
}

static ssize_t apm_qm_enq_stats_qid_set(struct device_driver *drv,
				     const char *buf, size_t count)
{
	u32 qid = 0x0;

	sscanf(buf, "%d", &qid);
	apm_qm_enq_stats_setqid(IP_BLK_QM, qid);

	return count;
}

static ssize_t apm_qm_enq_stats_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%d\n", apm_qm_enq_stats_value(IP_BLK_QM));
}

static ssize_t apm_qm_deq_stats_qid_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%d\n", apm_qm_deq_stats_getqid(IP_BLK_QM));
}

static ssize_t apm_qm_deq_stats_qid_set(struct device_driver *drv,
				     const char *buf, size_t count)
{
	u32 qid = 0x0;

	sscanf(buf, "%d", &qid);
	apm_qm_deq_stats_setqid(IP_BLK_QM, qid);

	return count;
}

static ssize_t apm_qm_deq_stats_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%d\n", apm_qm_deq_stats_value(IP_BLK_QM));
}

static struct driver_attribute apm_qm_sysfs_attrs[] = {
	__ATTR(qm_coalesce, S_IWUGO | S_IRUGO,
		apm_qm_coal_intr_show, apm_qm_coal_intr_set),
	__ATTR(qm_enq_stats_qid, S_IWUGO | S_IRUGO,
		apm_qm_enq_stats_qid_show, apm_qm_enq_stats_qid_set),
	__ATTR(qm_enq_stats, S_IRUGO,
		apm_qm_enq_stats_show, NULL),
	__ATTR(qm_deq_stats_qid, S_IWUGO | S_IRUGO,
		apm_qm_deq_stats_qid_show, apm_qm_deq_stats_qid_set),
	__ATTR(qm_deq_stats, S_IRUGO,
		apm_qm_deq_stats_show, NULL)
};

int apm_qm_add_sysfs(struct device_driver *driver)
{
	int i;
	int err;
	static int added_done = 0;

	if (added_done)
		return 0;

	for (i = 0; i < ARRAY_SIZE(apm_qm_sysfs_attrs); i++) {
		err = driver_create_file(driver, &apm_qm_sysfs_attrs[i]);
		if (err)
			goto fail;
	}

	added_done = 1;

	return 0;
fail:
	while (--i >= 0)
		driver_remove_file(driver, &apm_qm_sysfs_attrs[i]);
	return err;
}

void apm_qm_remove_sysfs(struct device_driver *driver)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(apm_qm_sysfs_attrs); i++)
		driver_remove_file(driver, &apm_qm_sysfs_attrs[i]);
}

#endif /* CONFIG_SYSFS */
