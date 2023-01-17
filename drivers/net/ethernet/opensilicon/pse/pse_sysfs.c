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
#include <linux/init.h>
#include <linux/device.h>
#include <linux/platform_device.h>

#include "pse.h"
#include "pse_sysfs.h"

/* Flow Control */

/* Global Flow Control Input Threshold FC_SET */
static ssize_t help_fc_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FC_CPU_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FC_SET);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FC_RLS);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PORT_FC_IN_SET);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PORT_FC_IN_RLS);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_DROP_SET);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_DROP_RLS);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_ALL_DROP_SET);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_ALL_DROP_RLS);
	return num;
}

static ssize_t fc_set_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_read(&fc_set, &fc_release);
	return sprintf(buf, "%d\n", fc_set);
}

static ssize_t fc_set_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;
	fc_th_read(&fc_set, &fc_release);
	fc_set = simple_strtoul(buf, NULL, 10);
	FC_SET_CHECK(fc_set);
	fc_th_write(fc_set, fc_release);

	return count;
}

/* Global Flow Control Input Threshold FC_RLS */
static ssize_t fc_release_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_read(&fc_set, &fc_release);
	return sprintf(buf, "%d\n", fc_release);
}

static ssize_t fc_release_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;
	fc_th_read(&fc_set, &fc_release);
	fc_release = simple_strtoul(buf, NULL, 10);
	FC_RLS_CHECK(fc_release);
	fc_th_write(fc_set, fc_release);

	return count;
}

/* CPU Port Flow Control */
static ssize_t cpu_fc_en_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "0x%x\n", rd32(CPU_CFG) & 0xffff);
}

static ssize_t cpu_fc_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 fc_en;
	u32 val;

	val = sscanf(buf, "0x%x", &fc_en);
	if (!val) {
		pr_err("%s usage: echo 0xhex > cpu_fc_en\n", __func__);
		return count;
	}
	FC_CPU_EN_CHECK(fc_en);
	val = rd32(CPU_CFG);
	val &= ~(0xffff);
	val |= (u16)fc_en;
	wr32(val, CPU_CFG);
	return count;
}

/* Flow Control Drop Threshold FC_DROP_SET */
static ssize_t fc_drop_set_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_drop_read(&fc_set, &fc_release);
	return sprintf(buf, "%d\n", fc_set);
}

static ssize_t fc_drop_set_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_drop_read(&fc_set, &fc_release);

	fc_set = simple_strtoul(buf, NULL, 10);
	FC_SET_CHECK(fc_set);
	fc_th_drop_write(fc_set, fc_release);

	return count;
}

/* Flow control Drop Threshold FC_DROP_RLS */
static ssize_t fc_drop_release_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_drop_read(&fc_set, &fc_release);

	return sprintf(buf, "%d\n", fc_release);
}

static ssize_t fc_drop_release_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;
	fc_th_drop_read(&fc_set, &fc_release);
	fc_release = simple_strtoul(buf, NULL, 10);
	FC_RLS_CHECK(fc_release);
	fc_th_drop_write(fc_set, fc_release);

	return count;
}

/* Flow Control All Drop Threshold FC_ALL_DROP_SET */
static ssize_t fc_all_drop_set_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_all_drop_read(&fc_set, &fc_release);
	return sprintf(buf, "%d\n", fc_set);
}

static ssize_t fc_all_drop_set_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_all_drop_read(&fc_set, &fc_release);

	fc_set = simple_strtoul(buf, NULL, 10);
	FC_SET_CHECK(fc_set);
	fc_th_all_drop_write(fc_set, fc_release);

	return count;
}

/* Flow control All Drop Threshold FC_DROP_RLS */
static ssize_t fc_all_drop_release_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u16 fc_set;
	u16 fc_release;

	fc_th_all_drop_read(&fc_set, &fc_release);

	return sprintf(buf, "%d\n", fc_release);
}

static ssize_t fc_all_drop_release_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 fc_set;
	u16 fc_release;
	fc_th_all_drop_read(&fc_set, &fc_release);
	fc_release = simple_strtoul(buf, NULL, 10);
	FC_RLS_CHECK(fc_release);
	fc_th_all_drop_write(fc_set, fc_release);

	return count;
}

#define port_fc_show(portname, port, item)				\
static ssize_t								\
portname##_fc_in_##item##_show(struct device *dev,			\
	struct device_attribute *attr, char *buf)			\
{									\
	u16 fc_set;							\
	u16 fc_rls;							\
									\
	fc_th_input_read(port, &fc_set, &fc_rls);			\
	return sprintf(buf, "%d\n", fc_##item);				\
}

#define port_fc_store(portname, port, item)				\
static ssize_t								\
portname##_fc_in_##item##_store(struct device *dev,			\
	struct device_attribute *attr, const char *buf, size_t count)	\
{									\
	u16 fc_set;							\
	u16 fc_rls;							\
									\
	fc_th_input_read(port, &fc_set, &fc_rls);			\
									\
	fc_##item = simple_strtoul(buf, NULL, 10);			\
	PORT_FC_IN_##item##_CHECK(fc_##item);				\
	fc_th_input_write(port, fc_set, fc_rls);			\
									\
	return count;							\
}

#define port_fc(portname, port, item)					\
	port_fc_show(portname, port, item)				\
	port_fc_store(portname, port, item)				\
	static DEVICE_ATTR(portname##_fc_in_##item,			\
			   S_IRUGO | S_IWUSR,				\
			   portname##_fc_in_##item##_show,		\
			   portname##_fc_in_##item##_store);

port_fc(mac0, 0, set);
port_fc(mac0, 0, rls);
port_fc(mac1, 1, set);
port_fc(mac1, 1, rls);
port_fc(cpu, 2, set);
port_fc(cpu, 2, rls);

static DEVICE_ATTR(help_fc, S_IRUGO,
		   help_fc_show, NULL);
static DEVICE_ATTR(fc_set, S_IRUGO | S_IWUSR,
		   fc_set_show, fc_set_store);
static DEVICE_ATTR(fc_rls, S_IRUGO | S_IWUSR,
		   fc_release_show, fc_release_store);
static DEVICE_ATTR(cpu_fc_en, S_IRUGO | S_IWUSR,
		   cpu_fc_en_show, cpu_fc_en_store);
static DEVICE_ATTR(fc_drop_set, S_IRUGO | S_IWUSR,
		   fc_drop_set_show, fc_drop_set_store);
static DEVICE_ATTR(fc_drop_rls, S_IRUGO | S_IWUSR,
		   fc_drop_release_show, fc_drop_release_store);
static DEVICE_ATTR(fc_all_drop_set, S_IRUGO | S_IWUSR,
		   fc_all_drop_set_show, fc_all_drop_set_store);
static DEVICE_ATTR(fc_all_drop_rls, S_IRUGO | S_IWUSR,
		   fc_all_drop_release_show, fc_all_drop_release_store);

static struct attribute *pse_fc_attrs[] = {
		&dev_attr_help_fc.attr,
		&dev_attr_fc_set.attr,
		&dev_attr_fc_rls.attr,
		&dev_attr_mac0_fc_in_set.attr,
		&dev_attr_mac0_fc_in_rls.attr,
		&dev_attr_mac1_fc_in_set.attr,
		&dev_attr_mac1_fc_in_rls.attr,
		&dev_attr_cpu_fc_in_set.attr,
		&dev_attr_cpu_fc_in_rls.attr,
		&dev_attr_cpu_fc_en.attr,
		&dev_attr_fc_drop_set.attr,
		&dev_attr_fc_drop_rls.attr,
		&dev_attr_fc_all_drop_set.attr,
		&dev_attr_fc_all_drop_rls.attr,
		NULL,
};

static struct attribute_group pse_fc_attr_group = {
	.name = "pse_fc",
	.attrs = pse_fc_attrs,
};


/* Shape */

/* PER PORT */
#define port_shape_show(port, item)					\
static ssize_t                                                          \
mac##port##_port_##item##_show(struct device *dev,			\
		     struct device_attribute *attr, char *buf)          \
{                                                                       \
	u8 base_rate;							\
	u8 tx_bw;							\
	u8 bucket_size;							\
	shape_port_read(port, &base_rate, &tx_bw, &bucket_size);	\
	return sprintf(buf, "%d\n", item);				\
}

#define port_shape_store(port, item)					\
static ssize_t                                                          \
mac##port##_port_##item##_store(struct device *dev,			\
	struct device_attribute *attr, const char *buf, size_t count)	\
{                                                                       \
	u8 base_rate;							\
	u8 tx_bw;							\
	u8 bucket_size;							\
	shape_port_read(port, &base_rate, &tx_bw, &bucket_size);	\
	item = simple_strtoul(buf, NULL, 10);				\
	SHAPE_##item##_CHECK(item);					\
	if (memcmp("bucket_size", #item, sizeof("bucket_size")))	\
		bucket_size = get_bucket_size(port, base_rate, tx_bw);	\
	shape_port_write(port, base_rate, tx_bw, bucket_size);		\
	return count;							\
}


#define port_shape(port, item)						\
	port_shape_show(port, item)					\
	port_shape_store(port, item)					\
	static DEVICE_ATTR(port_shape_mac##port##_##item,		\
			   S_IRUGO | S_IWUSR,				\
			   mac##port##_port_##item##_show,		\
			   mac##port##_port_##item##_store);


/* PER QUEUE */
#define queue_shape_show(portname, port, queue, item)				\
static ssize_t									\
queue_shape_##portname##_queue##queue##_##item##_show(struct device *dev,	\
		     struct device_attribute *attr, char *buf)			\
{										\
	u8 base_rate;								\
	u8 tx_bw;								\
	u8 bucket_size;								\
	shape_queue_read(port, queue, &base_rate, &tx_bw, &bucket_size);	\
	return sprintf(buf, "%d\n", item);					\
}

#define queue_shape_store(portname, port, queue, item)				\
static ssize_t									\
queue_shape_##portname##_queue##queue##_##item##_store(struct device *dev,	\
	struct device_attribute *attr, const char *buf, size_t count)		\
{										\
	u8 base_rate;								\
	u8 tx_bw;								\
	u8 bucket_size;								\
	shape_queue_read(port, queue, &base_rate, &tx_bw, &bucket_size);	\
	item = simple_strtoul(buf, NULL, 10);					\
	SHAPE_##item##_CHECK(item);						\
	shape_queue_write(port, queue, base_rate, tx_bw, bucket_size);		\
	return count;								\
}


#define queue_shape(portname, port, queue, item)				\
	queue_shape_show(portname, port, queue, item)				\
	queue_shape_store(portname, port, queue, item)				\
	static DEVICE_ATTR(portname##_queue##queue##_##item,			\
			S_IRUGO | S_IWUSR,					\
			queue_shape_##portname##_queue##queue##_##item##_show,	\
			queue_shape_##portname##_queue##queue##_##item##_store);


#define shape_bucket_size_show(portname, port)					\
static ssize_t									\
portname##_shape_bucket_size_show(struct device *dev,				\
		     struct device_attribute *attr, char *buf)			\
{										\
	u8 bucket_size;								\
	shape_bucket_size_read(port, &bucket_size);				\
	return sprintf(buf, "0x%x\n", bucket_size);				\
}

#define shape_bucket_size_store(portname, port)					\
static ssize_t									\
portname##_shape_bucket_size_store(struct device *dev,				\
	struct device_attribute *attr, const char *buf, size_t count)		\
{										\
	u32 bucket_size;							\
	bucket_size = simple_strtoul(buf, NULL, 10);				\
	SHAPE_BUCKET_SIZE_CHECK(bucket_size);					\
	shape_bucket_size_write(port, bucket_size);				\
	return count;								\
}

#define shape_bucket_size(portname, port)					\
	shape_bucket_size_show(portname, port)					\
	shape_bucket_size_store(portname, port)					\
	static DEVICE_ATTR(portname##_shape_bucket_size,			\
			   S_IRUGO | S_IWUSR,					\
			   portname##_shape_bucket_size_show,			\
			   portname##_shape_bucket_size_store);

static ssize_t shape_two_bucket_size_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	u8 size;
	shape_two_bucket_size_read(&size);
	return sprintf(buf, "%d\n", size);
}

static ssize_t shape_two_bucket_size_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u8 two_bucket_size;
	two_bucket_size = simple_strtoul(buf, NULL, 10);
	if (two_bucket_size != 0)
		two_bucket_size = 1;
	shape_two_bucket_size_write(two_bucket_size);
	return count;
}

static DEVICE_ATTR(two_bucket_size,
		   S_IRUGO | S_IWUSR,
		   shape_two_bucket_size_show, shape_two_bucket_size_store);

int help_shape_show(struct device *dev,
			struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PORT_SHAPE_BASE_RATE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PORT_SHAPE_TX_BW);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PORT_SHAPE_BUCKET_SEL);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_QUE_SHAPE_BASE_RATE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_QUE_SHAPE_TX_BW);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_QUE_SHAPE_BUCKET_SEL);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_SHAPE_TWO_BUCKET_SIZE_SEL);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_SHAPE_CHECK_RESULT);

	return num;
}

port_shape(0, base_rate);
port_shape(0, tx_bw);
port_shape(0, bucket_size);
port_shape(1, base_rate);
port_shape(1, tx_bw);
port_shape(1, bucket_size);

queue_shape(mac0, 0, 0, base_rate);
queue_shape(mac0, 0, 0, tx_bw);
queue_shape(mac0, 0, 0, bucket_size);
queue_shape(mac0, 0, 1, base_rate);
queue_shape(mac0, 0, 1, tx_bw);
queue_shape(mac0, 0, 1, bucket_size);
queue_shape(mac0, 0, 2, base_rate);
queue_shape(mac0, 0, 2, tx_bw);
queue_shape(mac0, 0, 2, bucket_size);
queue_shape(mac0, 0, 3, base_rate);
queue_shape(mac0, 0, 3, tx_bw);
queue_shape(mac0, 0, 3, bucket_size);
queue_shape(mac0, 0, 4, base_rate);
queue_shape(mac0, 0, 4, tx_bw);
queue_shape(mac0, 0, 4, bucket_size);
queue_shape(mac0, 0, 5, base_rate);
queue_shape(mac0, 0, 5, tx_bw);
queue_shape(mac0, 0, 5, bucket_size);
queue_shape(mac0, 0, 6, base_rate);
queue_shape(mac0, 0, 6, tx_bw);
queue_shape(mac0, 0, 6, bucket_size);
queue_shape(mac0, 0, 7, base_rate);
queue_shape(mac0, 0, 7, tx_bw);
queue_shape(mac0, 0, 7, bucket_size);
queue_shape(mac1, 1, 0, base_rate);
queue_shape(mac1, 1, 0, tx_bw);
queue_shape(mac1, 1, 0, bucket_size);
queue_shape(mac1, 1, 1, base_rate);
queue_shape(mac1, 1, 1, tx_bw);
queue_shape(mac1, 1, 1, bucket_size);
queue_shape(mac1, 1, 2, base_rate);
queue_shape(mac1, 1, 2, tx_bw);
queue_shape(mac1, 1, 2, bucket_size);
queue_shape(mac1, 1, 3, base_rate);
queue_shape(mac1, 1, 3, tx_bw);
queue_shape(mac1, 1, 3, bucket_size);
queue_shape(mac1, 1, 4, base_rate);
queue_shape(mac1, 1, 4, tx_bw);
queue_shape(mac1, 1, 4, bucket_size);
queue_shape(mac1, 1, 5, base_rate);
queue_shape(mac1, 1, 5, tx_bw);
queue_shape(mac1, 1, 5, bucket_size);
queue_shape(mac1, 1, 6, base_rate);
queue_shape(mac1, 1, 6, tx_bw);
queue_shape(mac1, 1, 6, bucket_size);
queue_shape(mac1, 1, 7, base_rate);
queue_shape(mac1, 1, 7, tx_bw);
queue_shape(mac1, 1, 7, bucket_size);
queue_shape(cpu, 2, 0, base_rate);
queue_shape(cpu, 2, 0, tx_bw);
queue_shape(cpu, 2, 0, bucket_size);
queue_shape(cpu, 2, 1, base_rate);
queue_shape(cpu, 2, 1, tx_bw);
queue_shape(cpu, 2, 1, bucket_size);
queue_shape(cpu, 2, 2, base_rate);
queue_shape(cpu, 2, 2, tx_bw);
queue_shape(cpu, 2, 2, bucket_size);
queue_shape(cpu, 2, 3, base_rate);
queue_shape(cpu, 2, 3, tx_bw);
queue_shape(cpu, 2, 3, bucket_size);
queue_shape(cpu, 2, 4, base_rate);
queue_shape(cpu, 2, 4, tx_bw);
queue_shape(cpu, 2, 4, bucket_size);
queue_shape(cpu, 2, 5, base_rate);
queue_shape(cpu, 2, 5, tx_bw);
queue_shape(cpu, 2, 5, bucket_size);
queue_shape(cpu, 2, 6, base_rate);
queue_shape(cpu, 2, 6, tx_bw);
queue_shape(cpu, 2, 6, bucket_size);
queue_shape(cpu, 2, 7, base_rate);
queue_shape(cpu, 2, 7, tx_bw);
queue_shape(cpu, 2, 7, bucket_size);
queue_shape(ppe, 3, 0, base_rate);
queue_shape(ppe, 3, 0, tx_bw);
queue_shape(ppe, 3, 0, bucket_size);
queue_shape(ppe, 3, 1, base_rate);
queue_shape(ppe, 3, 1, tx_bw);
queue_shape(ppe, 3, 1, bucket_size);
queue_shape(ppe, 3, 2, base_rate);
queue_shape(ppe, 3, 2, tx_bw);
queue_shape(ppe, 3, 2, bucket_size);
queue_shape(ppe, 3, 3, base_rate);
queue_shape(ppe, 3, 3, tx_bw);
queue_shape(ppe, 3, 3, bucket_size);
queue_shape(ppe, 3, 4, base_rate);
queue_shape(ppe, 3, 4, tx_bw);
queue_shape(ppe, 3, 4, bucket_size);
queue_shape(ppe, 3, 5, base_rate);
queue_shape(ppe, 3, 5, tx_bw);
queue_shape(ppe, 3, 5, bucket_size);
queue_shape(ppe, 3, 6, base_rate);
queue_shape(ppe, 3, 6, tx_bw);
queue_shape(ppe, 3, 6, bucket_size);
queue_shape(ppe, 3, 7, base_rate);
queue_shape(ppe, 3, 7, tx_bw);
queue_shape(ppe, 3, 7, bucket_size);
queue_shape(cfp, 5, 0, base_rate);
queue_shape(cfp, 5, 0, tx_bw);
queue_shape(cfp, 5, 0, bucket_size);
queue_shape(cfp, 5, 1, base_rate);
queue_shape(cfp, 5, 1, tx_bw);
queue_shape(cfp, 5, 1, bucket_size);
queue_shape(cfp, 5, 2, base_rate);
queue_shape(cfp, 5, 2, tx_bw);
queue_shape(cfp, 5, 2, bucket_size);
queue_shape(cfp, 5, 3, base_rate);
queue_shape(cfp, 5, 3, tx_bw);
queue_shape(cfp, 5, 3, bucket_size);
queue_shape(cfp, 5, 4, base_rate);
queue_shape(cfp, 5, 4, tx_bw);
queue_shape(cfp, 5, 4, bucket_size);
queue_shape(cfp, 5, 5, base_rate);
queue_shape(cfp, 5, 5, tx_bw);
queue_shape(cfp, 5, 5, bucket_size);
queue_shape(cfp, 5, 6, base_rate);
queue_shape(cfp, 5, 6, tx_bw);
queue_shape(cfp, 5, 6, bucket_size);
queue_shape(cfp, 5, 7, base_rate);
queue_shape(cfp, 5, 7, tx_bw);
queue_shape(cfp, 5, 7, bucket_size);

static DEVICE_ATTR(help_shape,
		S_IRUGO,
		help_shape_show, NULL);

static struct attribute *pse_shape_attrs[] = {
	&dev_attr_help_shape.attr,
	&dev_attr_port_shape_mac0_base_rate.attr,
	&dev_attr_port_shape_mac0_tx_bw.attr,
	&dev_attr_port_shape_mac0_bucket_size.attr,
	&dev_attr_port_shape_mac1_base_rate.attr,
	&dev_attr_port_shape_mac1_tx_bw.attr,
	&dev_attr_port_shape_mac1_bucket_size.attr,
	&dev_attr_mac0_queue0_base_rate.attr,
	&dev_attr_mac0_queue0_tx_bw.attr,
	&dev_attr_mac0_queue0_bucket_size.attr,
	&dev_attr_mac0_queue1_base_rate.attr,
	&dev_attr_mac0_queue1_tx_bw.attr,
	&dev_attr_mac0_queue1_bucket_size.attr,
	&dev_attr_mac0_queue2_base_rate.attr,
	&dev_attr_mac0_queue2_tx_bw.attr,
	&dev_attr_mac0_queue2_bucket_size.attr,
	&dev_attr_mac0_queue3_base_rate.attr,
	&dev_attr_mac0_queue3_tx_bw.attr,
	&dev_attr_mac0_queue3_bucket_size.attr,
	&dev_attr_mac0_queue4_base_rate.attr,
	&dev_attr_mac0_queue4_tx_bw.attr,
	&dev_attr_mac0_queue4_bucket_size.attr,
	&dev_attr_mac0_queue5_base_rate.attr,
	&dev_attr_mac0_queue5_tx_bw.attr,
	&dev_attr_mac0_queue5_bucket_size.attr,
	&dev_attr_mac0_queue6_base_rate.attr,
	&dev_attr_mac0_queue6_tx_bw.attr,
	&dev_attr_mac0_queue6_bucket_size.attr,
	&dev_attr_mac0_queue7_base_rate.attr,
	&dev_attr_mac0_queue7_tx_bw.attr,
	&dev_attr_mac0_queue7_bucket_size.attr,
	&dev_attr_mac1_queue0_base_rate.attr,
	&dev_attr_mac1_queue0_tx_bw.attr,
	&dev_attr_mac1_queue0_bucket_size.attr,
	&dev_attr_mac1_queue1_base_rate.attr,
	&dev_attr_mac1_queue1_tx_bw.attr,
	&dev_attr_mac1_queue1_bucket_size.attr,
	&dev_attr_mac1_queue2_base_rate.attr,
	&dev_attr_mac1_queue2_tx_bw.attr,
	&dev_attr_mac1_queue2_bucket_size.attr,
	&dev_attr_mac1_queue3_base_rate.attr,
	&dev_attr_mac1_queue3_tx_bw.attr,
	&dev_attr_mac1_queue3_bucket_size.attr,
	&dev_attr_mac1_queue4_base_rate.attr,
	&dev_attr_mac1_queue4_tx_bw.attr,
	&dev_attr_mac1_queue4_bucket_size.attr,
	&dev_attr_mac1_queue5_base_rate.attr,
	&dev_attr_mac1_queue5_tx_bw.attr,
	&dev_attr_mac1_queue5_bucket_size.attr,
	&dev_attr_mac1_queue6_base_rate.attr,
	&dev_attr_mac1_queue6_tx_bw.attr,
	&dev_attr_mac1_queue6_bucket_size.attr,
	&dev_attr_mac1_queue7_base_rate.attr,
	&dev_attr_mac1_queue7_tx_bw.attr,
	&dev_attr_mac1_queue7_bucket_size.attr,
	&dev_attr_cpu_queue0_base_rate.attr,
	&dev_attr_cpu_queue0_tx_bw.attr,
	&dev_attr_cpu_queue0_bucket_size.attr,
	&dev_attr_cpu_queue1_base_rate.attr,
	&dev_attr_cpu_queue1_tx_bw.attr,
	&dev_attr_cpu_queue1_bucket_size.attr,
	&dev_attr_cpu_queue2_base_rate.attr,
	&dev_attr_cpu_queue2_tx_bw.attr,
	&dev_attr_cpu_queue2_bucket_size.attr,
	&dev_attr_cpu_queue3_base_rate.attr,
	&dev_attr_cpu_queue3_tx_bw.attr,
	&dev_attr_cpu_queue3_bucket_size.attr,
	&dev_attr_cpu_queue4_base_rate.attr,
	&dev_attr_cpu_queue4_tx_bw.attr,
	&dev_attr_cpu_queue4_bucket_size.attr,
	&dev_attr_cpu_queue5_base_rate.attr,
	&dev_attr_cpu_queue5_tx_bw.attr,
	&dev_attr_cpu_queue5_bucket_size.attr,
	&dev_attr_cpu_queue6_base_rate.attr,
	&dev_attr_cpu_queue6_tx_bw.attr,
	&dev_attr_cpu_queue6_bucket_size.attr,
	&dev_attr_cpu_queue7_base_rate.attr,
	&dev_attr_cpu_queue7_tx_bw.attr,
	&dev_attr_cpu_queue7_bucket_size.attr,
	&dev_attr_ppe_queue0_base_rate.attr,
	&dev_attr_ppe_queue0_tx_bw.attr,
	&dev_attr_ppe_queue0_bucket_size.attr,
	&dev_attr_ppe_queue1_base_rate.attr,
	&dev_attr_ppe_queue1_tx_bw.attr,
	&dev_attr_ppe_queue1_bucket_size.attr,
	&dev_attr_ppe_queue2_base_rate.attr,
	&dev_attr_ppe_queue2_tx_bw.attr,
	&dev_attr_ppe_queue2_bucket_size.attr,
	&dev_attr_ppe_queue3_base_rate.attr,
	&dev_attr_ppe_queue3_tx_bw.attr,
	&dev_attr_ppe_queue3_bucket_size.attr,
	&dev_attr_ppe_queue4_base_rate.attr,
	&dev_attr_ppe_queue4_tx_bw.attr,
	&dev_attr_ppe_queue4_bucket_size.attr,
	&dev_attr_ppe_queue5_base_rate.attr,
	&dev_attr_ppe_queue5_tx_bw.attr,
	&dev_attr_ppe_queue5_bucket_size.attr,
	&dev_attr_ppe_queue6_base_rate.attr,
	&dev_attr_ppe_queue6_tx_bw.attr,
	&dev_attr_ppe_queue6_bucket_size.attr,
	&dev_attr_ppe_queue7_base_rate.attr,
	&dev_attr_ppe_queue7_tx_bw.attr,
	&dev_attr_ppe_queue7_bucket_size.attr,
	&dev_attr_cfp_queue0_base_rate.attr,
	&dev_attr_cfp_queue0_tx_bw.attr,
	&dev_attr_cfp_queue0_bucket_size.attr,
	&dev_attr_cfp_queue1_base_rate.attr,
	&dev_attr_cfp_queue1_tx_bw.attr,
	&dev_attr_cfp_queue1_bucket_size.attr,
	&dev_attr_cfp_queue2_base_rate.attr,
	&dev_attr_cfp_queue2_tx_bw.attr,
	&dev_attr_cfp_queue2_bucket_size.attr,
	&dev_attr_cfp_queue3_base_rate.attr,
	&dev_attr_cfp_queue3_tx_bw.attr,
	&dev_attr_cfp_queue3_bucket_size.attr,
	&dev_attr_cfp_queue4_base_rate.attr,
	&dev_attr_cfp_queue4_tx_bw.attr,
	&dev_attr_cfp_queue4_bucket_size.attr,
	&dev_attr_cfp_queue5_base_rate.attr,
	&dev_attr_cfp_queue5_tx_bw.attr,
	&dev_attr_cfp_queue5_bucket_size.attr,
	&dev_attr_cfp_queue6_base_rate.attr,
	&dev_attr_cfp_queue6_tx_bw.attr,
	&dev_attr_cfp_queue6_bucket_size.attr,
	&dev_attr_cfp_queue7_base_rate.attr,
	&dev_attr_cfp_queue7_tx_bw.attr,
	&dev_attr_cfp_queue7_bucket_size.attr,
	&dev_attr_two_bucket_size.attr,
	NULL,
};

static struct attribute_group pse_shape_attr_group = {
	.name = "pse_shape",
	.attrs = pse_shape_attrs,
};


/* Police */

#define port_police_show(portname, port, item)				\
static ssize_t                                                          \
portname##_police_##item##_show(struct device *dev,			\
			struct device_attribute *attr, char *buf)	\
{                                                                       \
	u16 out_max_th, out_min_th;					\
	u16 max_p, que_w;						\
	u16 oque_min_th;						\
	u16 queue_en;							\
	u16 inverse;							\
	police_dst_port_read(port, &queue_en, &inverse,			\
			     &out_max_th, &out_min_th,			\
			     &max_p, &que_w, &oque_min_th);		\
	return sprintf(buf, "%d\n", item);				\
}

#define port_police_store(portname, port, item)				\
static ssize_t                                                          \
portname##_police_##item##_store(struct device *dev,			\
	struct device_attribute *attr, const char *buf, size_t count)	\
{                                                                       \
	u16 out_max_th, out_min_th;					\
	u16 max_p, que_w;						\
	u16 oque_min_th;						\
	u16 queue_en;							\
	u16 inverse;							\
	police_dst_port_read(port, &queue_en, &inverse,			\
			     &out_max_th, &out_min_th,			\
			     &max_p, &que_w, &oque_min_th);		\
	item = simple_strtoul(buf, NULL, 10);				\
	POLICE_QUEUE_CHECK(queue_en, out_max_th, out_min_th, max_p,	\
			   que_w, oque_min_th);				\
	police_dst_port_write(port, queue_en, out_max_th, out_min_th,	\
			      max_p, que_w, oque_min_th);		\
	return count;							\
}


#define police_port(portname, port, item)				\
	port_police_show(portname, port, item)				\
	port_police_store(portname, port, item)				\
	static DEVICE_ATTR(portname##_police_##item,			\
			   S_IRUGO | S_IWUSR,				\
			   portname##_police_##item##_show,		\
			   portname##_police_##item##_store);



#define police_port_en_show(portname, port)				\
static ssize_t                                                          \
police_##portname##_en_show(struct device *dev,				\
			 struct device_attribute *attr, char *buf)	\
{                                                                       \
	return sprintf(buf, "%d\n", police_port_en_read(port));		\
}

#define police_port_en_store(portname, port)				\
static ssize_t                                                          \
police_##portname##_en_store(struct device *dev,			\
	struct device_attribute *attr, const char *buf, size_t count)	\
{									\
	u8 enable;							\
	enable = simple_strtoul(buf, NULL, 10);				\
	PSE_ENABLE_CHECK(enable);					\
	police_port_en_write(port, enable);				\
	return count;							\
}


#define police_port_en(portname, port)					\
	police_port_en_show(portname, port)				\
	police_port_en_store(portname, port)				\
	static DEVICE_ATTR(police_##portname##_en,			\
			   S_IRUGO | S_IWUSR,				\
			   police_##portname##_en_show,			\
			   police_##portname##_en_store);

static ssize_t help_police_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int num = 0;

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_RAND_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_QUE_EN);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_GLB_MINTH);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_OQUE_MINTH);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_OUT_MAXTH);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_OUT_MINTH);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_MAX_P);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_QUE_W);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_POLICE_CHECK_RESULT);

	return num;
}

static ssize_t police_glb_min_th_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", police_global_min_th_read());
}

static ssize_t police_glb_min_th_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u16 glb_min_th;
	glb_min_th = simple_strtoul(buf, NULL, 10);
	POLICE_GLB_MIN_TH_CHECK(glb_min_th);
	police_global_min_th_write(glb_min_th);
	return count;
}

static ssize_t police_rand_en_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", police_psudo_rand_generator_read());
}

static ssize_t police_rand_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u8 enable;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	police_psudo_rand_generator_write(enable);
	return count;
}

static DEVICE_ATTR(help_police,
		   S_IRUGO,
		   help_police_show, NULL);

static DEVICE_ATTR(police_glb_min_th,
		   S_IRUGO | S_IWUSR,
		   police_glb_min_th_show, police_glb_min_th_store);

static DEVICE_ATTR(police_rand_en,
		   S_IRUGO | S_IWUSR,
		   police_rand_en_show, police_rand_en_store);

police_port(mac0, 0, queue_en)
police_port(mac0, 0, out_max_th)
police_port(mac0, 0, out_min_th)
police_port(mac0, 0, max_p)
police_port(mac0, 0, que_w)
police_port(mac0, 0, oque_min_th)

police_port(mac1, 1, queue_en)
police_port(mac1, 1, out_max_th)
police_port(mac1, 1, out_min_th)
police_port(mac1, 1, max_p)
police_port(mac1, 1, que_w);
police_port(mac1, 1, oque_min_th);

police_port(cpu, 2, queue_en)
police_port(cpu, 2, out_max_th)
police_port(cpu, 2, out_min_th)
police_port(cpu, 2, max_p)
police_port(cpu, 2, que_w);
police_port(cpu, 2, oque_min_th);

police_port(ppe, 3, queue_en)
police_port(ppe, 3, out_max_th)
police_port(ppe, 3, out_min_th)
police_port(ppe, 3, max_p)
police_port(ppe, 3, que_w);
police_port(ppe, 3, oque_min_th);

police_port(cfp, 5, queue_en)
police_port(cfp, 5, out_max_th)
police_port(cfp, 5, out_min_th)
police_port(cfp, 5, max_p)
police_port(cfp, 5, que_w);
police_port(cfp, 5, oque_min_th);

police_port_en(mac0, 0)
police_port_en(mac1, 1)
police_port_en(cpu, 2)
police_port_en(ppe, 3)
police_port_en(cfp, 5)

static struct attribute *pse_police_attrs[] = {
	&dev_attr_help_police.attr,
	&dev_attr_police_glb_min_th.attr,
	&dev_attr_police_rand_en.attr,
	&dev_attr_police_mac0_en.attr,
	&dev_attr_police_mac1_en.attr,
	&dev_attr_police_cpu_en.attr,
	&dev_attr_police_ppe_en.attr,
	&dev_attr_police_cfp_en.attr,

	&dev_attr_mac0_police_queue_en.attr,
	&dev_attr_mac0_police_out_max_th.attr,
	&dev_attr_mac0_police_out_min_th.attr,
	&dev_attr_mac0_police_max_p.attr,
	&dev_attr_mac0_police_que_w.attr,
	&dev_attr_mac0_police_oque_min_th.attr,

	&dev_attr_mac1_police_queue_en.attr,
	&dev_attr_mac1_police_out_max_th.attr,
	&dev_attr_mac1_police_out_min_th.attr,
	&dev_attr_mac1_police_max_p.attr,
	&dev_attr_mac1_police_que_w.attr,
	&dev_attr_mac1_police_oque_min_th.attr,

	&dev_attr_cpu_police_queue_en.attr,
	&dev_attr_cpu_police_out_max_th.attr,
	&dev_attr_cpu_police_out_min_th.attr,
	&dev_attr_cpu_police_max_p.attr,
	&dev_attr_cpu_police_que_w.attr,
	&dev_attr_cpu_police_oque_min_th.attr,

	&dev_attr_ppe_police_queue_en.attr,
	&dev_attr_ppe_police_out_max_th.attr,
	&dev_attr_ppe_police_out_min_th.attr,
	&dev_attr_ppe_police_max_p.attr,
	&dev_attr_ppe_police_que_w.attr,
	&dev_attr_ppe_police_oque_min_th.attr,

	&dev_attr_cfp_police_queue_en.attr,
	&dev_attr_cfp_police_out_max_th.attr,
	&dev_attr_cfp_police_out_min_th.attr,
	&dev_attr_cfp_police_max_p.attr,
	&dev_attr_cfp_police_que_w.attr,
	&dev_attr_cfp_police_oque_min_th.attr,

	NULL,
};

static struct attribute_group pse_police_attr_group = {
	.name = "pse_police",
	.attrs = pse_police_attrs,
};

static int vlan_vid;

/* output : VLD : WAN_SIE : VLAN_VID : PMAP */
static ssize_t vlan_table_write_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	struct pse_vlan vlan;
	int index, valid, wan, vid, pmap;
	struct pse_vlan;

	sscanf(buf, "%d %d %d %d %d", &index, &valid, &wan, &vid, &pmap);
	VLAN_TABLE_WRITE_CHECK(index, valid, wan, vid, pmap);
	vlan.valid = valid;
	vlan.wan = wan;
	vlan.vid = vid;
	vlan.pmap = pmap;
	pse_vlan_write(&vlan, index);
	return count;
}

static ssize_t vlan_table_lookup_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	vlan_vid = simple_strtoul(buf, NULL, 10);
	VLAN_ID_CHECK(vlan_vid);
	return count;
}

/* output : match or not */
static ssize_t vlan_table_lookup_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	struct pse_vlan vlan;
	int match_index;

	match_index = pse_vlan_lookup(&vlan, vlan_vid);

	if (match_index == PSE_FAIL)
		return sprintf(buf, "Not match\n");
	else
		return sprintf(buf, "match index = %d\n", match_index);
}

static ssize_t unknown_vlan_to_cpu_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(MAC_GLOB_CFG) & (1 << 25)));
}

static ssize_t unknown_vlan_to_cpu_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val, enable;
	enable = simple_strtoul(buf, NULL, 10);
	VLAN_UNKNOWN_VLAN_TO_CPU_CHECK(enable);
	val = rd32(MAC_GLOB_CFG);
	if (enable)
		val |= (1 << 25);
	else
		val &= ~(1 << 25);
	wr32(val, MAC_GLOB_CFG);
	return count;
}


static ssize_t mac0_ingress_check_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(MAC0_CFG) & (1 << 24)));
}

static ssize_t mac0_ingress_check_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_port_ingress_check(0, enable);
	return count;
}

static ssize_t mac1_ingress_check_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(MAC1_CFG) & (1 << 24)));
}

static ssize_t mac1_ingress_check_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_port_ingress_check(1, enable);
	return count;
}

static ssize_t cpu_ingress_check_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(CPU_CFG) & (1 << 24)));
}

static ssize_t cpu_ingress_check_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_port_ingress_check(2, enable);
	return count;
}

static ssize_t help_vlan_table_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_PORT_INGRESS);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_UNKNOWN_VLAN_TO_CPU);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_TABLE_WRITE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_TABLE_LOOKUP);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_CHECK_RESULT);

	return num;
}


static DEVICE_ATTR(help_vlan_table,
		   S_IRUGO,
		   help_vlan_table_show, NULL);

static DEVICE_ATTR(vlan_table_write,
		   S_IWUSR,
		   NULL, vlan_table_write_store);

static DEVICE_ATTR(vlan_table_lookup,
		   S_IRUGO | S_IWUSR,
		   vlan_table_lookup_show, vlan_table_lookup_store);

static DEVICE_ATTR(unknown_vlan_to_cpu,
		   S_IRUGO | S_IWUSR,
		   unknown_vlan_to_cpu_show, unknown_vlan_to_cpu_store);

static DEVICE_ATTR(mac0_ingress_check,
		   S_IRUGO | S_IWUSR,
		   mac0_ingress_check_show, mac0_ingress_check_store);

static DEVICE_ATTR(mac1_ingress_check,
		   S_IRUGO | S_IWUSR,
		   mac1_ingress_check_show, mac1_ingress_check_store);

static DEVICE_ATTR(cpu_ingress_check,
		   S_IRUGO | S_IWUSR,
		   cpu_ingress_check_show, cpu_ingress_check_store);

static struct attribute *pse_vlan_table_attrs[] = {
	&dev_attr_help_vlan_table.attr,
	&dev_attr_vlan_table_write.attr,
	&dev_attr_vlan_table_lookup.attr,
	&dev_attr_unknown_vlan_to_cpu.attr,
	&dev_attr_mac0_ingress_check.attr,
	&dev_attr_mac1_ingress_check.attr,
	&dev_attr_cpu_ingress_check.attr,
	NULL,
};


static struct attribute_group pse_vlan_table_attr_group = {
	.name = "pse_vlan_table",
	.attrs = pse_vlan_table_attrs,
};

static ssize_t help_tc_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TC_ETYPE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TC_DSCP);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TC_TCP_UDP);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TC_CHECK_RESULT);

	return num;
}

static ssize_t tc_etype_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 index;
	u32 etype;
	u32 tc;
	u32 val;

	val = sscanf(buf, "%d 0x%x %d\n", &index, &etype, &tc);
	if (!val) {
		pr_err("%s usage: etype must be 0xhex.\n", __func__);
		return count;
	}
	TC_ETYPE_CHECK(index, etype, tc);
	tc_ethertype(index, etype, tc);

	return count;
}

static ssize_t tc_dscp_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 dscp_index;
	u32 tc;

	sscanf(buf, "%d %d\n", &dscp_index, &tc);
	TC_DSCP_CHECK(dscp_index, tc);
	tc_dscp(dscp_index, tc);

	return count;
}

static ssize_t tc_tcp_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 index, start, stop, tc;

	sscanf(buf, "%d %d %d %d\n", &index, &start, &stop, &tc);
	TC_TCP_UDP_CHECK(index, start, stop, tc);
	tc_tcp_port(index, start, stop, tc);

	return count;
}

static ssize_t tc_udp_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 index, start, stop, tc;

	sscanf(buf, "%d %d %d %d\n", &index, &start, &stop, &tc);
	TC_TCP_UDP_CHECK(index, start, stop, tc);
	tc_udp_port(index, start, stop, tc);

	return count;
}



static DEVICE_ATTR(help_tc,
		   S_IRUGO,
		   help_tc_show, NULL);

static DEVICE_ATTR(tc_etype,
		   S_IWUSR,
		   NULL, tc_etype_store);

static DEVICE_ATTR(tc_dscp,
		   S_IWUSR,
		   NULL, tc_dscp_store);

static DEVICE_ATTR(tc_tcp,
		   S_IWUSR,
		   NULL, tc_tcp_store);

static DEVICE_ATTR(tc_udp,
		   S_IWUSR,
		   NULL, tc_udp_store);

static struct attribute *pse_tc_attrs[] = {
	&dev_attr_help_tc.attr,
	&dev_attr_tc_etype.attr,
	&dev_attr_tc_dscp.attr,
	&dev_attr_tc_tcp.attr,
	&dev_attr_tc_udp.attr,
	NULL,
};

static struct attribute_group pse_tc_attr_group = {
	.name = "pse_tc",
	.attrs = pse_tc_attrs,
};



static ssize_t help_pri_show(struct device *dev,
	struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_REGEN_USER_PRI);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_DMAC_TC_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_TCP_TC_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_UDP_TC_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_DSCP_TC_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_VLAN_TC_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_ETHER_TC_EN);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_PORT_TC);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_SCH_MODE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_SCH_MINBW);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_QUEUE_WEIGHT);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_QUEUE_RING_ID);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_PRI_CHECK_RESULT);

	return num;
}

static ssize_t pri_regen_user_pri_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_REGEN_USER_PRI_EN_CHECK(port, enable);
	tc_cfg_regen_user_pri(port, enable);
	return count;
}

static ssize_t pri_port_tc_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port;
	u32 tc;

	sscanf(buf, "%d %d\n", &port, &tc);
	PRI_PORT_TC_CHECK(port, tc);
	tc_port(port, tc);
	return count;
}

static ssize_t pri_dmac_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_DMAC_TC_EN_CHECK(port, enable);
	tc_cfg_dmac(port, enable);
	return count;
}

static ssize_t pri_tcp_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_TCP_TC_EN_CHECK(port, enable);
	tc_cfg_tcp(port, enable);
	return count;
}

static ssize_t pri_udp_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_UDP_TC_EN_CHECK(port, enable);
	tc_cfg_udp(port, enable);
	return count;
}

static ssize_t pri_dscp_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_DSCP_TC_EN_CHECK(port, enable);
	tc_cfg_dscp(port, enable);
	return count;
}

static ssize_t pri_vlan_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_VLAN_TC_EN_CHECK(port, enable);
	tc_cfg_vlan(port, enable);
	return count;
}

static ssize_t pri_ethertype_tc_en_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PRI_ETHERTYPE_TC_EN_CHECK(port, enable);
	tc_cfg_ethertype(port, enable);
	return count;
}

static ssize_t pri_sch_mode_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, mode;

	sscanf(buf, "%d %d\n", &port, &mode);
	PRI_SCH_MODE_CHECK(port, mode);
	tx_sch_mode(port, mode);
	return count;
}

static ssize_t pri_sch_minbw_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, bw;

	sscanf(buf, "%d %d\n", &port, &bw);
	PRI_SCH_MINBW_CHECK(port, bw);
	tx_sch_min_bw(port, bw);
	return count;
}

static ssize_t pri_queue_weight_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, queue, weight;

	sscanf(buf, "%d %d %d\n", &port, &queue, &weight);
	PRI_QUEUE_WEIGHT_CHECK(port, queue, weight);
	tx_sch_weight(port, queue, weight);
	return count;
}

static ssize_t pri_queue_ring_id_store(struct device *dev,
	struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, queue, ring_id;

	sscanf(buf, "%d %d %d\n", &port, &queue, &ring_id);
	PRI_QUEUE_RING_ID_CHECK(port, queue, ring_id);
	tc_to_ring(port, queue, ring_id);
	return count;
}

static DEVICE_ATTR(help_pri,
		   S_IRUGO,
		   help_pri_show, NULL);

static DEVICE_ATTR(pri_regen_user_pri_en,
		   S_IWUSR,
		   NULL, pri_regen_user_pri_en_store);

static DEVICE_ATTR(pri_port_tc,
		   S_IWUSR,
		   NULL, pri_port_tc_store);

static DEVICE_ATTR(pri_dmac_tc_en,
		   S_IWUSR,
		   NULL, pri_dmac_tc_en_store);

static DEVICE_ATTR(pri_tcp_tc_en,
		   S_IWUSR,
		   NULL, pri_tcp_tc_en_store);

static DEVICE_ATTR(pri_udp_tc_en,
		   S_IWUSR,
		   NULL, pri_udp_tc_en_store);

static DEVICE_ATTR(pri_dscp_tc_en,
		   S_IWUSR,
		   NULL, pri_dscp_tc_en_store);

static DEVICE_ATTR(pri_vlan_tc_en,
		   S_IWUSR,
		   NULL, pri_vlan_tc_en_store);

static DEVICE_ATTR(pri_ethertype_tc_en,
		   S_IWUSR,
		   NULL, pri_ethertype_tc_en_store);

static DEVICE_ATTR(pri_sch_mode,
		   S_IWUSR,
		   NULL, pri_sch_mode_store);

static DEVICE_ATTR(pri_sch_minbw,
		   S_IWUSR,
		   NULL, pri_sch_minbw_store);

static DEVICE_ATTR(pri_queue_weight,
		   S_IWUSR,
		   NULL, pri_queue_weight_store);

static DEVICE_ATTR(pri_queue_ring_id,
		   S_IWUSR,
		   NULL, pri_queue_ring_id_store);

static struct attribute *pse_pri_attrs[] = {
	&dev_attr_help_pri.attr,
	&dev_attr_pri_regen_user_pri_en.attr,
	&dev_attr_pri_port_tc.attr,
	&dev_attr_pri_dmac_tc_en.attr,
	&dev_attr_pri_tcp_tc_en.attr,
	&dev_attr_pri_udp_tc_en.attr,
	&dev_attr_pri_dscp_tc_en.attr,
	&dev_attr_pri_vlan_tc_en.attr,
	&dev_attr_pri_ethertype_tc_en.attr,
	&dev_attr_pri_sch_mode.attr,
	&dev_attr_pri_sch_minbw.attr,
	&dev_attr_pri_queue_weight.attr,
	&dev_attr_pri_queue_ring_id.attr,
	NULL,
};

static struct attribute_group pse_pri_attr_group = {
	.name = "pse_pri",
	.attrs = pse_pri_attrs,
};

static ssize_t help_mac_table_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_TABLE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_HASH_TABLE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_HASH_ALGO);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_TABLE_CHECK_RESULT);

	return num;
}

static ssize_t mac_table_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int i;
	u32 port, index, priority;
	u32 mac_u32[6];
	struct pse_mac mac;

	if (strchr(buf, '-')) {
		sscanf(buf, "%d %d %x-%x-%x-%x-%x-%x %d\n", &port, &index,
		&mac_u32[0], &mac_u32[1], &mac_u32[2], &mac_u32[3], &mac_u32[4], &mac_u32[5], &priority);

	} else if (strchr(buf, ':')) {
		sscanf(buf, "%d %d %x:%x:%x:%x:%x:%x %d\n", &port, &index,
		&mac_u32[0], &mac_u32[1], &mac_u32[2], &mac_u32[3], &mac_u32[4], &mac_u32[5], &priority);

	} else {
		printk(HELP_MAC_ADDRESS);
		return count;
	}

	MAC_TABLE_CHECK(port, index, mac_u32, priority);
	mac.port = port;
	mac.index = index;
	mac.priority = priority;
	for (i = 0; i < 6; i++)
		mac.mac[i] = mac_u32[i];

	pse_mac_write(&mac);
	return count;
}

static ssize_t mac_hash_table_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	int i;
	u32 port;
	u32 mac_u32[6];
	struct pse_mac mac;

	if (strchr(buf, '-')) {
		sscanf(buf, "%d %x-%x-%x-%x-%x-%x\n", &port,
		&mac_u32[0], &mac_u32[1], &mac_u32[2], &mac_u32[3], &mac_u32[4], &mac_u32[5]);

	} else if (strchr(buf, ':')) {
		sscanf(buf, "%d %x:%x:%x:%x:%x:%x\n", &port,
		&mac_u32[0], &mac_u32[1], &mac_u32[2], &mac_u32[3], &mac_u32[4], &mac_u32[5]);
	} else {
		printk(HELP_MAC_ADDRESS);
		return count;
	}

	MAC_HASH_TABLE_CHECK(port, mac_u32);
	mac.index = 0;
	mac.priority = 0;
	mac.port = port;
	for (i = 0; i < 6; i++)
		mac.mac[i] = mac_u32[i];

	pse_mac_hash_write_by_lookup(&mac);
	return count;
}

static ssize_t mac_hash_algo_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 algo;

	sscanf(buf, "%d\n", &algo);
	MAC_HASH_ALGO_CHECK(algo);
	pse_mac_hash(algo);
		return count;
}


static DEVICE_ATTR(help_mac_table,
		   S_IRUGO,
		   help_mac_table_show, NULL);

static DEVICE_ATTR(mac_table,
		   S_IWUSR,
		   NULL, mac_table_store);

static DEVICE_ATTR(mac_hash_table,
		   S_IWUSR,
		   NULL, mac_hash_table_store);

static DEVICE_ATTR(mac_hash_algo,
		   S_IWUSR,
		   NULL, mac_hash_algo_store);

static struct attribute *pse_mac_table_attrs[] = {
	&dev_attr_help_mac_table.attr,
	&dev_attr_mac_table.attr,
	&dev_attr_mac_hash_table.attr,
	&dev_attr_mac_hash_algo.attr,
	NULL,
};

static struct attribute_group pse_mac_table_attr_group = {
	.name = "pse_mac_table",
	.attrs = pse_mac_table_attrs,
};

static ssize_t help_cs_offload_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_CS_OFFLOAD_FS);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_CS_OFFLOAD_TS);

	return num;
}

static ssize_t cs_offload_fs_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(MAC_GLOB_EXT) & (1 << 23)));
}

static ssize_t cs_offload_fs_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(MAC_GLOB_EXT);
	if (enable)
		val |= (1 << 23);
	else
		val &= ~(1 << 23);
	wr32(val, MAC_GLOB_EXT);
	return count;
}

static ssize_t cs_offload_ts_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(MAC_GLOB_EXT) & (1 << 22)));
}

static ssize_t cs_offload_ts_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(MAC_GLOB_EXT);
	if (enable)
		val |= (1 << 22);
	else
		val &= ~(1 << 22);
	wr32(val, MAC_GLOB_EXT);
	return count;
}

extern int ufo_cs_enable;
static ssize_t ufo_cs_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	ufo_cs_enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(ufo_cs_enable);
	return count;
}

static DEVICE_ATTR(help_cs_offload,
		   S_IRUGO,
		   help_cs_offload_show, NULL);

static DEVICE_ATTR(cs_offload_fs,
		   S_IRUGO | S_IWUSR,
		   cs_offload_fs_show, cs_offload_fs_store);

static DEVICE_ATTR(cs_offload_ts,
		   S_IRUGO | S_IWUSR,
		   cs_offload_ts_show, cs_offload_ts_store);

static DEVICE_ATTR(ufo_cs_enable,
		   S_IRUGO | S_IWUSR,
		   NULL, ufo_cs_enable_store);

static struct attribute *pse_cs_offload_attrs[] = {
	&dev_attr_help_cs_offload.attr,
	&dev_attr_cs_offload_fs.attr,
	&dev_attr_cs_offload_ts.attr,
	&dev_attr_ufo_cs_enable.attr,
	NULL,
};

static struct attribute_group pse_cs_offload_attr_group = {
	.name = "pse_cs_offload",
	.attrs = pse_cs_offload_attrs,
};

static ssize_t help_fs_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FS_STATUS_INTR_MASK);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FS_RING_DMA_CTRL);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FS_TIMEOUT_TIME);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_LRO_TIMEOUT_TIME);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_FS_RING_CHECK);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_LRO_RING_CHECK);
	return num;
}

static ssize_t fs_timeout_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", (rd32(FS_DMA_TIMEOUT) & 0xfff));
}

static ssize_t fs_timeout_time_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 time, val;

	sscanf(buf, "%d", &time);
	FS_TIMEOUT_TIME_CHECK(time);
	val = rd32(FS_DMA_TIMEOUT);
	val &= ~(0xfff);
	val |= time;
	wr32(val, FS_DMA_TIMEOUT);
	return count;
}

static ssize_t lro_timeout_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{

	return sprintf(buf, "%d\n", ((rd32(FS_DMA_TIMEOUT) >> 16) & 0xfff));
}

static ssize_t lro_timeout_time_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 time, val;

	sscanf(buf, "%d", &time);
	FS_TIMEOUT_TIME_CHECK(time);
	val = rd32(FS_DMA_TIMEOUT);
	val &= ~(0xfff << 16);
	val |= (time << 16);
	wr32(val, FS_DMA_TIMEOUT);
	return count;
}

static ssize_t fs_ring_dma_ctrl_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val;

	sscanf(buf, "%x\n", &val);

	wr32(val, FS_DMA_CTRL);

	return count;
}

static ssize_t fs_status_intr_mask_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val;

	sscanf(buf, "%x\n", &val);

	fwr32(val, FS_STATUS_INTR_MASK);

	return count;
}

static ssize_t lro_ring_check_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(FS_RING_STA) & (1 << 21)));
}

static ssize_t lro_ring_check_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(FS_RING_STA);
	if (enable)
		val |= (1 << 21);
	else
		val &= ~(1 << 21);

	wr32(val, FS_RING_STA);
	return count;
}

static ssize_t fs_ring_check_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", !!(rd32(FS_RING_STA) & (1 << 20)));
}

static ssize_t fs_ring_check_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(FS_RING_STA);
	if (enable)
		val |= (1 << 20);
	else
		val &= ~(1 << 20);

	wr32(val, FS_RING_STA);
	return count;
}

static DEVICE_ATTR(help_fs,
		   S_IRUGO,
		   help_fs_show, NULL);

static DEVICE_ATTR(fs_ring_dma_ctrl,
		   S_IWUSR,
		   NULL, fs_ring_dma_ctrl_store);

static DEVICE_ATTR(fs_status_intr_mask,
		   S_IWUSR,
		   NULL, fs_status_intr_mask_store);

static DEVICE_ATTR(fs_timeout_time,
		   S_IRUGO | S_IWUSR,
		   fs_timeout_time_show, fs_timeout_time_store);

static DEVICE_ATTR(lro_timeout_time,
		   S_IRUGO | S_IWUSR,
		   lro_timeout_time_show, lro_timeout_time_store);

static DEVICE_ATTR(lro_ring_check,
		   S_IRUGO | S_IWUSR,
		   lro_ring_check_show, lro_ring_check_store);

static DEVICE_ATTR(fs_ring_check,
		   S_IRUGO | S_IWUSR,
		   fs_ring_check_show, fs_ring_check_store);

static struct attribute *pse_fs_dma_timeout_attrs[] = {
	&dev_attr_help_fs.attr,
	&dev_attr_fs_ring_dma_ctrl.attr,
	&dev_attr_fs_status_intr_mask.attr,
	&dev_attr_fs_timeout_time.attr,
	&dev_attr_lro_timeout_time.attr,
	&dev_attr_lro_ring_check.attr,
	&dev_attr_fs_ring_check.attr,
	NULL,
};

static struct attribute_group pse_fs_dma_timeout_attr_group = {
	.name = "pse_fs_dma_timeout",
	.attrs = pse_fs_dma_timeout_attrs,
};

static ssize_t help_delay_intr_show(struct device *dev,
				struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAX_PEND_INT_CNT);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAX_PEND_TIME);

	return num;
}

static ssize_t max_pend_int_cnt_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", rd32(DELAY_INTR_CFG) >> 8);
}

static ssize_t max_pend_int_cnt_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 cnt;
	u32 val;
	cnt = simple_strtoul(buf, NULL, 10);
	DELAY_MAX_PEND_INT_CNT_CHECK(cnt);
	cnt &= 0xff;
	val = rd32(DELAY_INTR_CFG);
	val &= ~(0xff << 8);
	val |= cnt << 8;
	wr32(val, DELAY_INTR_CFG);

	return count;
}

static ssize_t max_pend_time_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", rd32(DELAY_INTR_CFG) & 0xff);
}

static ssize_t max_pend_time_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 time;
	u32 val;
	time = simple_strtoul(buf, NULL, 10);
	DELAY_MAX_PEND_TIME_CHECK(time);
	time &= 0xff;
	val = rd32(DELAY_INTR_CFG);
	val &= ~0xff;
	val |= time;
	wr32(val, DELAY_INTR_CFG);
	return count;
}

static DEVICE_ATTR(help_delay_intr,
		   S_IRUGO,
		   help_delay_intr_show, NULL);

static DEVICE_ATTR(max_pend_int_cnt,
		   S_IRUGO | S_IWUSR,
		   max_pend_int_cnt_show, max_pend_int_cnt_store);

static DEVICE_ATTR(max_pend_time,
		   S_IRUGO | S_IWUSR,
		   max_pend_time_show, max_pend_time_store);

static struct attribute *pse_delay_intr_attrs[] = {
	&dev_attr_help_delay_intr.attr,
	&dev_attr_max_pend_int_cnt.attr,
	&dev_attr_max_pend_time.attr,
	NULL,
};

static struct attribute_group pse_delay_intr_attr_group = {
	.name = "pse_delay_intr",
	.attrs = pse_delay_intr_attrs,
};

static ssize_t help_port_cfg_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_BLOCKING_STATE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_BCS_BC_PKT_EN);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_PROMISC_MODE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_MYMAC_ONLY);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_BLOCK_MODE);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_RES_MC_FLT);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_ACCEPT_CRC_PKT);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_RX_BCS_RATE);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_COL_MODE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_BP_MODE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_JAM_NO);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_BKOFF_MODE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_MAC_BP_EN);

	return num;
}

static ssize_t promisc_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_PROMISC_MODE_CHECK(port, enable);
	pse_promisc_mode(port, enable);
	return count;
}

static ssize_t my_mac_only_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_MYMAC_ONLY_CHECK(port, enable);
	pse_my_mac_only(port, enable);
	return count;
}

static ssize_t blocking_state_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_BLOCKING_STATE_CHECK(port, enable);
	pse_port_blocking_state(port, enable);
	return count;
}

static ssize_t block_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_BLOCK_MODE_CHECK(port, enable)
	pse_port_block_mode(port, enable);
	return count;
}

static ssize_t skip_l2_lookup_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	pse_port_skip_l2_lookup(port, enable);
	return count;
}


static ssize_t res_mc_flt_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_res_mc_flt(enable);
	return count;
}

static ssize_t accept_crc_pkt_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_accept_crc_pkt(enable);
	return count;
}

static ssize_t broadcast_storm_rate_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_STORM_RATE_EN_CHECK(port, enable);
	pse_port_broadcast_storm_rate_control(port, enable);
	return count;
}

static ssize_t rx_broadcast_storm_rate_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 rate;

	sscanf(buf, "%d\n", &rate);
	PORT_CFG_RX_BCS_RATE_CHECK(rate);
	pse_rx_broadcast_storm_rate(rate);
	return count;
}

static ssize_t col_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 mode;

	sscanf(buf, "%d\n", &mode);
	MAC_GLOB_CFG_COL_MODE_CHECK(mode);
	pse_col_mode(mode);
	return count;
}

static ssize_t bp_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 mode;

	sscanf(buf, "%d\n", &mode);
	MAC_GLOB_CFG_BP_MODE_CHECK(mode);
	pse_bp_mode(mode);
	return count;
}

static ssize_t jam_no_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 no;

	sscanf(buf, "%d\n", &no);
	MAC_GLOB_CFG_JAM_NO_CHECK(no);
	pse_jam_no(no);
	return count;
}

static ssize_t bkoff_mode_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 mode;

	sscanf(buf, "%d\n", &mode);
	MAC_GLOB_CFG_BKOFF_MODE_CHECK(mode);
	pse_bkoff_mode(mode);
	return count;
}

static ssize_t bp_en_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 port, enable;

	sscanf(buf, "%d %d\n", &port, &enable);
	PORT_CFG_BP_EN_CHECK(port, enable);
	pse_port_bp_enable(port, enable);
	return count;
}

static DEVICE_ATTR(help_port_cfg,
		   S_IRUGO,
		   help_port_cfg_show, NULL);

static DEVICE_ATTR(promisc_mode,
		   S_IWUSR,
		   NULL, promisc_mode_store);

static DEVICE_ATTR(my_mac_only,
		   S_IWUSR,
		   NULL, my_mac_only_store);

static DEVICE_ATTR(blocking_state,
		   S_IWUSR,
		   NULL, blocking_state_store);

static DEVICE_ATTR(block_mode,
		   S_IWUSR,
		   NULL, block_mode_store);

static DEVICE_ATTR(skip_l2_lookup,
		   S_IWUSR,
		   NULL, skip_l2_lookup_store);

static DEVICE_ATTR(res_mc_flt,
		   S_IWUSR,
		   NULL, res_mc_flt_store);

static DEVICE_ATTR(accept_crc_pkt,
		   S_IWUSR,
		   NULL, accept_crc_pkt_store);

static DEVICE_ATTR(broadcast_storm_rate_en,
		   S_IWUSR,
		   NULL, broadcast_storm_rate_en_store);

static DEVICE_ATTR(rx_broadcast_storm_rate,
		   S_IWUSR,
		   NULL, rx_broadcast_storm_rate_store);

static DEVICE_ATTR(col_mode,
		   S_IWUSR,
		   NULL, col_mode_store);

static DEVICE_ATTR(bp_mode,
		   S_IWUSR,
		   NULL, bp_mode_store);

static DEVICE_ATTR(jam_no,
		   S_IWUSR,
		   NULL, jam_no_store);

static DEVICE_ATTR(bkoff_mode,
		   S_IWUSR,
		   NULL, bkoff_mode_store);

static DEVICE_ATTR(bp_en,
		   S_IWUSR,
		   NULL, bp_en_store);

static struct attribute *pse_port_cfg_attrs[] = {
	&dev_attr_help_port_cfg.attr,
	&dev_attr_promisc_mode.attr,
	&dev_attr_my_mac_only.attr,
	&dev_attr_blocking_state.attr,
	&dev_attr_block_mode.attr,
	&dev_attr_skip_l2_lookup.attr,
	&dev_attr_res_mc_flt.attr,
	&dev_attr_accept_crc_pkt.attr,
	&dev_attr_broadcast_storm_rate_en.attr,
	&dev_attr_rx_broadcast_storm_rate.attr,
	&dev_attr_col_mode.attr,
	&dev_attr_bp_mode.attr,
	&dev_attr_jam_no.attr,
	&dev_attr_bkoff_mode.attr,
	&dev_attr_bp_en.attr,
	NULL,
};

static struct attribute_group pse_port_cfg_attr_group = {
	.name = "pse_port_cfg",
	.attrs = pse_port_cfg_attrs,
};

static ssize_t help_vlan_cfg_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_S_NEIGHBOR);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_S_COMPONENT);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_STAG_ETYPE);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_VLAN_WAN_PORT);

	return num;
}

static ssize_t stag_etype_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 etype;

	sscanf(buf, "0x%x\n", &etype);
	PSE_STAG_ETYPE_CHECK(etype);
	pse_stag_etype_cfg(etype);
	return count;
}

static ssize_t wan_port_mac0_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_wan_port_mac0_cfg(enable);
	return count;
}

static ssize_t wan_port_mac1_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_wan_port_mac1_cfg(enable);
	return count;
}

static ssize_t wan_port_cpu_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_wan_port_cpu_cfg(enable);
	return count;
}


static ssize_t s_neighbor_cpu_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_s_neighbor_cpu_cfg(enable);
	return count;
}

static ssize_t s_neighbor_mac1_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_s_neighbor_mac1_cfg(enable);
	return count;
}

static ssize_t s_neighbor_mac0_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_s_neighbor_mac0_cfg(enable);
	return count;
}

static ssize_t s_component_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	pse_s_component_cfg(enable);
	return count;
}

static DEVICE_ATTR(help_vlan_cfg,
		   S_IRUGO,
		   help_vlan_cfg_show, NULL);

static DEVICE_ATTR(stag_etype,
		   S_IWUSR,
		   NULL, stag_etype_store);

static DEVICE_ATTR(wan_port_mac0, S_IWUSR, NULL, wan_port_mac0_store);
static DEVICE_ATTR(wan_port_mac1, S_IWUSR, NULL, wan_port_mac1_store);
static DEVICE_ATTR(wan_port_cpu, S_IWUSR, NULL, wan_port_cpu_store);

static DEVICE_ATTR(s_neighbor_cpu,
		   S_IWUSR,
		   NULL, s_neighbor_cpu_store);

static DEVICE_ATTR(s_neighbor_mac1,
		   S_IWUSR,
		   NULL, s_neighbor_mac1_store);

static DEVICE_ATTR(s_neighbor_mac0,
		   S_IWUSR,
		   NULL, s_neighbor_mac0_store);

static DEVICE_ATTR(s_component,
		   S_IWUSR,
		   NULL, s_component_store);

static struct attribute *pse_vlan_cfg_attrs[] = {
	&dev_attr_help_vlan_cfg.attr,
	&dev_attr_stag_etype.attr,
	&dev_attr_wan_port_mac0.attr,
	&dev_attr_wan_port_mac1.attr,
	&dev_attr_wan_port_cpu.attr,
	&dev_attr_s_neighbor_cpu.attr,
	&dev_attr_s_neighbor_mac1.attr,
	&dev_attr_s_neighbor_mac0.attr,
	&dev_attr_s_component.attr,
	NULL,
};

static struct attribute_group pse_vlan_cfg_attr_group = {
	.name = "pse_vlan_cfg",
	.attrs = pse_vlan_cfg_attrs,
};

static ssize_t help_test_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TEST_MAC0_INTLB);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TEST_MAC0_EXTLB);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TEST_MAC1_INTLB);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TEST_MAC1_EXTLB);

	return num;
}

static ssize_t mac0_int_loopback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(CLK_SKEW_CTRL);
	if (enable)
		reg |= (1 << 1);
	else
		reg &= ~(1 << 1);
	wr32(reg, CLK_SKEW_CTRL);
	return count;
}

static ssize_t mac1_int_loopback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(CLK_SKEW_CTRL);
	if (enable)
		reg |= (1 << 9);
	else
		reg &= ~(1 << 9);
	wr32(reg, CLK_SKEW_CTRL);
	return count;
}

static ssize_t mac0_ext_loopback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(CLK_SKEW_CTRL);
	if (enable)
		reg |= (1 << 0);
	else
		reg &= ~(1 << 0);
	wr32(reg, CLK_SKEW_CTRL);
	return count;
}

static ssize_t mac1_ext_loopback_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(CLK_SKEW_CTRL);
	if (enable)
		reg |= (1 << 8);
	else
		reg &= ~(1 << 8);
	wr32(reg, CLK_SKEW_CTRL);
	return count;
}

static ssize_t mac0_rxc_dly_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val;
	u32 reg;
	val = simple_strtoul(buf, NULL, 10);

	reg = rd32(CLK_SKEW_CTRL);
	reg &= ~(0x03 << (4 + (0 << 3))); /* clear mac_rxc_dly */
	reg |= (val << (4 + (0 << 3)));
	wr32(reg, CLK_SKEW_CTRL);

	return count;
}

static ssize_t mac1_rxc_dly_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val;
	u32 reg;
	val = simple_strtoul(buf, NULL, 10);

	reg = rd32(CLK_SKEW_CTRL);
	reg &= ~(0x03 << (4 + (1 << 3))); /* clear mac_rxc_dly */
	reg |= (val << (4 + (1 << 3)));
	wr32(reg, CLK_SKEW_CTRL);

	return count;
}

static DEVICE_ATTR(help_test,
		   S_IRUGO,
		   help_test_show, NULL);

static DEVICE_ATTR(mac0_int_loopback,
		   S_IWUSR,
		   NULL, mac0_int_loopback_store);

static DEVICE_ATTR(mac1_int_loopback,
		   S_IWUSR,
		   NULL, mac1_int_loopback_store);

static DEVICE_ATTR(mac0_ext_loopback,
		   S_IWUSR,
		   NULL, mac0_ext_loopback_store);

static DEVICE_ATTR(mac1_ext_loopback,
		   S_IWUSR,
		   NULL, mac1_ext_loopback_store);

static DEVICE_ATTR(mac0_rxc_dly,
		   S_IWUSR,
		   NULL, mac0_rxc_dly_store);

static DEVICE_ATTR(mac1_rxc_dly,
		   S_IWUSR,
		   NULL, mac1_rxc_dly_store);

static struct attribute *pse_test_attrs[] = {
	&dev_attr_help_test.attr,
	&dev_attr_mac0_int_loopback.attr,
	&dev_attr_mac1_int_loopback.attr,
	&dev_attr_mac0_ext_loopback.attr,
	&dev_attr_mac1_ext_loopback.attr,
	&dev_attr_mac0_rxc_dly.attr,
	&dev_attr_mac1_rxc_dly.attr,
	NULL,
};

static struct attribute_group pse_test_attr_group = {
	.name = "pse_test",
	.attrs = pse_test_attrs,
};

static ssize_t help_eee_show(struct device *dev,
		struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_RX_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_TX_EN);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_LPI_REQUEST_MODE);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_CHECK_TIME);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_WAKE_TIME);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_GATE_CYCLE);

	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_REALTEK_CRS_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_REALTEK_MAC_MODE_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_EEE_REALTEK_RXC_STOP_EN);

	return num;
}

static ssize_t eee_check_time_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 time;
	u32 reg;

	sscanf(buf, "%d\n", &time);
	EEE_CHECK_TIME_CHECK(time);
	reg = rd32(EEE_CFG);
	reg &= ~(0x0f << 24);
	reg |= (time & 0x0f) << 24;
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_wake_time_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 time;
	u32 reg;

	sscanf(buf, "%d\n", &time);
	EEE_WAKE_TIME_CHECK(time);
	reg = rd32(EEE_CFG);
	reg &= ~(0xff << 16);
	reg |= (time & 0xff) << 16;
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_gate_cycle_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 cycle;
	u32 reg;

	sscanf(buf, "%d\n", &cycle);
	EEE_GATE_CYCLE_CHECK(cycle);
	reg = rd32(EEE_CFG);
	reg &= ~(0xff << 8);
	reg |= (cycle & 0xff) << 8;
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_rx1_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(EEE_CFG);
	if (enable)
		reg |= (1 << 3);
	else
		reg &= ~(1 << 3);
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_tx1_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(EEE_CFG);
	if (enable)
		reg |= (1 << 2);
	else
		reg &= ~(1 << 2);
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_rx0_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(EEE_CFG);
	if (enable)
		reg |= (1 << 1);
	else
		reg &= ~(1 << 1);
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t eee_tx0_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 reg;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	reg = rd32(EEE_CFG);
	if (enable)
		reg |= (1 << 0);
	else
		reg &= ~(1 << 0);
	wr32(reg, EEE_CFG);

	return count;
}

static ssize_t lpi_request_tx1_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 mode;
	u32 reg;

	sscanf(buf, "%d\n", &mode);
	EEE_LPI_REQUEST_MODE_CHECK(mode);
	reg = rd32(EEE_CTRL);
	reg &= ~(0x03 << 4);
	reg |= ((mode & 0x03) << 4);
	wr32(reg, EEE_CTRL);

	return count;
}

static ssize_t lpi_request_tx0_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 mode;
	u32 reg;

	sscanf(buf, "%d\n", &mode);
	EEE_LPI_REQUEST_MODE_CHECK(mode);
	reg = rd32(EEE_CTRL);
	reg &= ~(0x03 << 0);
	reg |= ((mode & 0x03) << 0);
	wr32(reg, EEE_CTRL);

	return count;
}

#ifdef CONFIG_REALTEK_PHY
extern int rtl8211_EEE_mode(struct phy_device *phydev, int mode);
extern int rtl8211_EEE_CRS_Enable(struct phy_device *phydev, bool enable);
extern int rtl8211_EEE_RXC_STOP_Enable(struct phy_device *phydev, bool enable);

static ssize_t realtek_phy_eee_mac_mode_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
#define EEE_MAC_MODE 0
#define EEE_PHY_MODE 1

	u32 enable;
	struct net_device *netdev;
	struct phy_device *phydev;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	netdev = pse_res->ndev[1];
	phydev = netdev->phydev;
	if (phydev) {
		if (enable)
			rtl8211_EEE_mode(phydev, EEE_MAC_MODE);
		else
			rtl8211_EEE_mode(phydev, EEE_PHY_MODE);
	}
	return count;
}

static ssize_t realtek_phy_eee_rxc_stop_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	struct net_device *netdev;
	struct phy_device *phydev;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	netdev = pse_res->ndev[1];
	phydev = netdev->phydev;
	if (phydev)
		rtl8211_EEE_RXC_STOP_Enable(phydev, enable);

	return count;
}

static ssize_t realtek_phy_eee_crs_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	struct net_device *netdev;
	struct phy_device *phydev;

	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	netdev = pse_res->ndev[1];
	phydev = netdev->phydev;
	if (phydev)
		rtl8211_EEE_CRS_Enable(phydev, enable);

	return count;
}
#endif

static DEVICE_ATTR(help_eee,
		   S_IRUGO,
		   help_eee_show, NULL);

static DEVICE_ATTR(eee_check_time,
		   S_IWUSR,
		   NULL, eee_check_time_store);

static DEVICE_ATTR(eee_wake_time,
		   S_IWUSR,
		   NULL, eee_wake_time_store);

static DEVICE_ATTR(eee_gate_cycle,
		   S_IWUSR,
		   NULL, eee_gate_cycle_store);

static DEVICE_ATTR(eee_rx1_enable,
		   S_IWUSR,
		   NULL, eee_rx1_enable_store);

static DEVICE_ATTR(eee_tx1_enable,
		   S_IWUSR,
		   NULL, eee_tx1_enable_store);

static DEVICE_ATTR(eee_rx0_enable,
		   S_IWUSR,
		   NULL, eee_rx0_enable_store);

static DEVICE_ATTR(eee_tx0_enable,
		   S_IWUSR,
		   NULL, eee_tx0_enable_store);

static DEVICE_ATTR(lpi_request_tx1,
		   S_IWUSR,
		   NULL, lpi_request_tx1_store);

static DEVICE_ATTR(lpi_request_tx0,
		   S_IWUSR,
		   NULL, lpi_request_tx0_store);

#ifdef CONFIG_REALTEK_PHY
static DEVICE_ATTR(realtek_phy_eee_mac_mode_enable,
		   S_IWUSR,
		   NULL, realtek_phy_eee_mac_mode_enable_store);

static DEVICE_ATTR(realtek_phy_eee_rxc_stop_enable,
		   S_IWUSR,
		   NULL, realtek_phy_eee_rxc_stop_enable_store);

static DEVICE_ATTR(realtek_phy_eee_crs_enable,
		   S_IWUSR,
		   NULL, realtek_phy_eee_crs_enable_store);
#endif

static struct attribute *pse_eee_attrs[] = {
	&dev_attr_help_eee.attr,
	&dev_attr_eee_check_time.attr,
	&dev_attr_eee_wake_time.attr,
	&dev_attr_eee_gate_cycle.attr,

	&dev_attr_eee_rx1_enable.attr,
	&dev_attr_eee_tx1_enable.attr,
	&dev_attr_eee_rx0_enable.attr,
	&dev_attr_eee_tx0_enable.attr,

	&dev_attr_lpi_request_tx1.attr,
	&dev_attr_lpi_request_tx0.attr,
#ifdef CONFIG_REALTEK_PHY
	&dev_attr_realtek_phy_eee_mac_mode_enable.attr,
	&dev_attr_realtek_phy_eee_rxc_stop_enable.attr,
	&dev_attr_realtek_phy_eee_crs_enable.attr,
#endif

	NULL,
};

static struct attribute_group pse_eee_attr_group = {
	.name = "pse_eee",
	.attrs = pse_eee_attrs,
};

static ssize_t help_lro_cfg_show(struct device *dev,
				   struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TS_UFO_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_TS_TSO_EN);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_DF_BIT_CFG);

	return num;
}

static ssize_t ts_tso_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(LSO_CFG);
	val &= ~0x01;
	if (enable)
		val |= 0x1;
	wr32(val, LSO_CFG);
	return count;
}

static ssize_t ts_ufo_enable_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(LSO_CFG);
	val &= ~0x02;
	if (enable)
		val |= 0x2;
	wr32(val, LSO_CFG);
	return count;
}

static ssize_t df_bit_cfg_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 enable;
	u32 val;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	val = rd32(LSO_CFG);
	val &= ~0x04;
	if (enable)
		val |= 0x4;
	wr32(val, LSO_CFG);
	return count;
}


static DEVICE_ATTR(help_lro_cfg,
		   S_IRUGO,
		   help_lro_cfg_show, NULL);

static DEVICE_ATTR(ts_tso_enable,
		   S_IWUSR,
		   NULL, ts_tso_enable_store);

static DEVICE_ATTR(ts_ufo_enable,
		   S_IWUSR,
		   NULL, ts_ufo_enable_store);

static DEVICE_ATTR(df_bit_cfg,
		   S_IWUSR,
		   NULL, df_bit_cfg_store);

static struct attribute *pse_lro_lso_attrs[] = {
	&dev_attr_help_lro_cfg.attr,
	&dev_attr_ts_tso_enable.attr,
	&dev_attr_ts_ufo_enable.attr,
	&dev_attr_df_bit_cfg.attr,
	NULL,
};


static struct attribute_group pse_lro_lso_attr_group = {
	.name = "pse_lro_lso",
	.attrs = pse_lro_lso_attrs,
};

static ssize_t help_mib_show(struct device *dev,
			     struct device_attribute *attr, char *buf)
{
	int num = 0;
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_SAMPLE_INTERVAL);
	num += snprintf(buf + num, PAGE_SIZE - num, "%s", HINT_SHOW_QUEUE_MIB);

	return num;
}

static ssize_t sample_interval_store(struct device *dev,
				     struct device_attribute *attr,
				     const char *buf, size_t count)
{
	u32 interval;
	sscanf(buf, "%d\n", &interval);
	MIB_SAMPLE_INTERVAL_CHECK(interval);
	fwr32(interval, MIB_CNT_CFG);
	return count;
}

static ssize_t show_queue_mib_store(struct device *dev,
				    struct device_attribute *attr,
				    const char *buf, size_t count)
{
	u32 mask;
	u32 enable;
	enable = simple_strtoul(buf, NULL, 10);
	PSE_ENABLE_CHECK(enable);
	mask = frd32(STATUS_INTR_MASK);
	if (enable)
		mask &= ~0x100;
	else
		mask |= 0x100;
	fwr32(mask, STATUS_INTR_MASK);
	return count;
}

static DEVICE_ATTR(help_mib,
		   S_IRUGO,
		   help_mib_show, NULL);

static DEVICE_ATTR(sample_interval,
		   S_IWUSR,
		   NULL, sample_interval_store);

static DEVICE_ATTR(show_queue_mib,
		   S_IWUSR,
		   NULL, show_queue_mib_store);

static struct attribute *pse_mib_attrs[] = {
	&dev_attr_help_mib.attr,
	&dev_attr_sample_interval.attr,
	&dev_attr_show_queue_mib.attr,
	NULL,
};

static struct attribute_group pse_mib_attr_group = {
	.name = "pse_mib",
	.attrs = pse_mib_attrs,
};

/* this is for tx segment offset test
   modprobe pse
   ifconfig eth1 up
   echo len offset > segment_tx_header
   ex :
   for i in `seq 0 1 10`; do echo 42 "$i" > segment_tx_header; sleep 1; done
   Use wireshark to monitor
 */
static ssize_t segment_tx_header_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *netdev = pse_res->ndev[1]; /* eth1 */
	u8 *header_ptr = NULL;
	int i;
	u32 header_offset = 0;
	u32 header_len = 0;

	struct sk_buff *skb;
	sscanf(buf, "%d %d\n", &header_len, &header_offset);
	pr_info("start segment tx header test\n");
	header_ptr = kmalloc(4096, GFP_KERNEL);
	if (!header_ptr)
		goto exit;

	/* start to test */
	pr_info("header_ptr = %p\n", header_ptr);

	/* Only Header */
	pr_info("header_len = %d\n", header_len);
	pr_info("header_offset = %d\n", header_offset);
	for (i = 0; i < 4096; i++)
		header_ptr[i] = i % 0xff;

	skb = alloc_skb(0, GFP_KERNEL);
	skb->data = header_ptr + header_offset;

	memset(skb->data, 0xff , 6);
	memset(skb->data + 6, 0x00 , 8);
	skb->len = header_len;
	netdev->netdev_ops->ndo_start_xmit(skb, netdev);
exit:
	return count;
}


/* ex :
   for i in `seq 0 1 10`; do echo 42 "$i" > segment_tx_payload0; sleep 1; done
 */
static ssize_t segment_tx_payload0_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	struct net_device *netdev = pse_res->ndev[1]; /* eth1 */
	struct page *payload0_page = NULL;
	int i;
	u32 payload0_offset = 0;
	u32 payload0_len = 0;
	u8 *ptr;

	struct sk_buff *skb;

	sscanf(buf, "%d %d\n", &payload0_len, &payload0_offset);

	pr_info("start segment tx payload test\n");

	payload0_page = alloc_page(GFP_KERNEL);
	if (!payload0_page)
		goto exit;

	/* start to test */
	pr_info("payload0_ptr = %p\n", page_address(payload0_page));


	ptr = page_address(payload0_page);
	for (i = 0; i < 4096; i++)
		ptr[i] = i % 0xff;

	/* Payload0 */
	pr_info("payload0_len = %d\n", payload0_len);
	pr_info("payload0_offset = %d\n", payload0_offset);

	skb = alloc_skb(1500, GFP_KERNEL);

	/* fix Header */
	skb->len = 42;

	memset(skb->data, 0xff, 6);
	memset(skb->data + 6, 0x00 , 8);

	memset(skb->data + 14, 0xaa, 42-14);
	skb_shinfo(skb)->nr_frags = 1;
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		skb_frag_t *frag = &skb_shinfo(skb)->frags[i];

		frag->page.p              = payload0_page;
		frag->page_offset         = payload0_offset;
		frag->size = payload0_len;
		skb->data_len += payload0_len;
		skb->len += payload0_len;
	}
	netdev->netdev_ops->ndo_start_xmit(skb, netdev);

exit:
	return count;
}


static DEVICE_ATTR(segment_tx_header,
		   S_IWUSR,
		   NULL, segment_tx_header_store);

static DEVICE_ATTR(segment_tx_payload0,
		   S_IWUSR,
		   NULL, segment_tx_payload0_store);

static struct attribute *pse_segment_tx_attrs[] = {
	&dev_attr_segment_tx_header.attr,
	&dev_attr_segment_tx_payload0.attr,
	NULL,
};

static struct attribute_group pse_segment_tx_attr_group = {
	.name = "pse_segment_tx",
	.attrs = pse_segment_tx_attrs,
};

#if defined(PSE_DEBUG)
void pse_debug_level_cfg(int level);
int pse_debug_level(void);

static ssize_t debug_level_store(struct device *dev,
		struct device_attribute *attr, const char *buf, size_t count)
{
	u32 val;

	sscanf(buf, "%d", &val);

	if (0x3 < val)
		return -EINVAL;

	pse_debug_level_cfg(val);
	return count;
}

static ssize_t debug_level_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", pse_debug_level());
}

static DEVICE_ATTR(debug_level, S_IRUGO | S_IWUSR, debug_level_show, debug_level_store);

static struct attribute *pse_debug_attrs[] = {
	&dev_attr_debug_level.attr,
	NULL,
};

static struct attribute_group pse_debug_attr_group = {
	.name = "pse_debug",
	.attrs = pse_debug_attrs,
};
#endif

int pse_sysfs_init(struct platform_device *pdev)
{

	int ret;

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_fc_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create pse_fc sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_shape_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create pse_shape sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_police_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create pse_police sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_vlan_table_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create vlan_table sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_tc_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create tc sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_pri_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create pri sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_mac_table_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create mac table sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_cs_offload_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create cs offload sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_fs_dma_timeout_attr_group);
	if (ret)
		dev_warn(&pdev->dev, "failed to create fs dma timeout sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_delay_intr_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create delay interrupt sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_port_cfg_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create port cfg sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_vlan_cfg_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create vlan cfg sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_test_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create test sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_eee_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create eee sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_lro_lso_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create lso_lro sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_mib_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create mib sysfs files\n");

	ret = sysfs_create_group(&pdev->dev.kobj, &pse_segment_tx_attr_group);

	if (ret)
		dev_warn(&pdev->dev, "failed to create segment tx files\n");

#if defined(PSE_DEBUG)
	if (sysfs_create_group(&pdev->dev.kobj, &pse_debug_attr_group))
		dev_warn(&pdev->dev, "failed to create pse debug sysfs files\n");
#endif

	return 0;
}

int pse_sysfs_finit(struct platform_device *pdev)
{
	sysfs_remove_group(&pdev->dev.kobj, &pse_fc_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_shape_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_police_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_vlan_table_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_tc_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_pri_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_mac_table_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_cs_offload_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_fs_dma_timeout_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_delay_intr_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_port_cfg_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_vlan_cfg_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_test_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_eee_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_lro_lso_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_mib_attr_group);
	sysfs_remove_group(&pdev->dev.kobj, &pse_segment_tx_attr_group);
#if defined(PSE_DEBUG)
	sysfs_remove_group(&pdev->dev.kobj, &pse_debug_attr_group);
#endif
	return 0;
}
