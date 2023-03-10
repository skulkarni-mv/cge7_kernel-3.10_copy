/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
*******************************************************************************/
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/capability.h>
#include <linux/kernel.h>
#include <linux/platform_device.h>
#include <linux/netdevice.h>

#include <msApiTypes.h>
#include "mv802_3.h"
#include "mv_switch.h"
#include "mv_phy.h"


static ssize_t mv_switch_help(char *buf)
{
	int off = 0;

	off += scnprintf(buf + off, PAGE_SIZE, "cat help                            - show this help\n");
	off += scnprintf(buf + off, PAGE_SIZE, "cat stats                           - show statistics for switch all ports info\n");
	off += scnprintf(buf + off, PAGE_SIZE, "cat status                          - show switch status\n");
	off += scnprintf(buf + off, PAGE_SIZE, "cat atu_show                        - show switch MAC Table\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p grp        > port_add        - map switch port to a network device\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p            > port_del        - unmap switch port from a network device\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p r t   > reg_r                - read switch register.  t: 1-phy, 2-port, 3-global, 4-global2, 5-smi\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p r t v > reg_w                - write switch register. t: 1-phy, 2-port, 3-global, 4-global2, 5-smi\n");
#ifdef CONFIG_MV_SW_PTP
	off += scnprintf(buf + off, PAGE_SIZE, "echo p r t   > ptp_reg_r            - read ptp register.  p: 15-PTP Global, 14-TAI Global, t: not used\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p r t v > ptp_reg_w            - write ptp register. p: 15-PTP Global, 14-TAI Global, t: not used\n");
#endif
	off += scnprintf(buf + off, PAGE_SIZE, "echo p en    > power_set            - set port power state.\n");
	off += scnprintf(buf + off, PAGE_SIZE, "echo p       > power_get	    - get port power state\n");
	off += scnprintf(buf + off, PAGE_SIZE, "\ten: 0-down, 1-up\n");

	return off;
}

static ssize_t mv_switch_show(struct device *dev, struct device_attribute *attr, char *buf)
{
	const char *name = attr->attr.name;
	int off = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!strcmp(name, "stats"))
		mv_switch_stats_print();
	else if (!strcmp(name, "status"))
		mv_switch_status_print();
	else if (!strcmp(name, "atu_show"))
		mv_switch_atu_print();
	else
		off = mv_switch_help(buf);

	return off;
}

static ssize_t mv_switch_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	const char      *name = attr->attr.name;
	unsigned long   flags;
	int             err, port, reg, type, state;
	unsigned int    v;
	MV_U16          val;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Read arguments */
	err = port = reg = type = val = 0;
	sscanf(buf, "%d %d %d %x", &port, &reg, &type, &v);

	local_irq_save(flags);
	if (!strcmp(name, "reg_r")) {
		err = mv_switch_reg_read(port, reg, type, &val);
	} else if (!strcmp(name, "reg_w")) {
		val = (MV_U16)v;
		err = mv_switch_reg_write(port, reg, type, v);
#ifdef CONFIG_MV_SW_PTP
	} else if (!strcmp(name, "ptp_reg_r")) {
		err = mv_switch_ptp_reg_read(port, reg, &val);
	} else if (!strcmp(name, "ptp_reg_w")) {
		val = (MV_U16)v;
		err = mv_switch_ptp_reg_write(port, reg, val);
#endif
	} else if (!strcmp(name, "power_set")) {
		state = reg;
		err = mv_phy_port_power_state_set(port, state != 0);
		mvOsPrintf(" - %s, set port(%d) power %s!\n",
			err == 0 ? "SUCCESS" : "FAILED", port, state == 0 ? "off" : "on");
		goto out;
	} else if (!strcmp(name, "power_get")) {
		GT_BOOL state;
		err = mv_phy_port_power_state_get(port, &state);
		mvOsPrintf("- %s, port(%d) power is %s!\n",
			err == 0 ? "SUCCESS" : "FAILED", port, state == GT_FALSE ? "off" : "on");
		goto out;
	}
	printk(KERN_ERR "switch register access: type=%d, port=%d, reg=%d", type, port, reg);

	if (err)
		printk(KERN_ERR " - FAILED, err=%d\n", err);
	else
		printk(KERN_ERR " - SUCCESS, val=0x%04x\n", val);

out:
	local_irq_restore(flags);

	return err ? -EINVAL : len;
}

static ssize_t mv_switch_netdev_store(struct device *dev, struct device_attribute *attr, const char *buf, size_t len)
{
	const char      *name = attr->attr.name;
	int             err = 0, port = 0, group;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Read arguments */
	sscanf(buf, "%d %d", &port, &group);


	if (!strcmp(name, "port_add"))
		err = mv_switch_port_add(port, group);
	else if (!strcmp(name, "port_del"))
		err = mv_switch_port_del(port);

	if (err)
		printk(KERN_ERR " - FAILED, err=%d\n", err);
	else
		printk(KERN_ERR " - SUCCESS\n");

	return err ? -EINVAL : len;
}

static DEVICE_ATTR(reg_r,       S_IWUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(reg_w,       S_IWUSR, mv_switch_show, mv_switch_store);
#ifdef CONFIG_MV_SW_PTP
static DEVICE_ATTR(ptp_reg_r,   S_IWUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(ptp_reg_w,   S_IWUSR, mv_switch_show, mv_switch_store);
#endif
static DEVICE_ATTR(status,      S_IRUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(stats,       S_IRUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(help,        S_IRUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(port_add,    S_IWUSR, mv_switch_show, mv_switch_netdev_store);
static DEVICE_ATTR(port_del,    S_IWUSR, mv_switch_show, mv_switch_netdev_store);
static DEVICE_ATTR(atu_show,    S_IRUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(power_set,   S_IWUSR, mv_switch_show, mv_switch_store);
static DEVICE_ATTR(power_get,   S_IWUSR, mv_switch_show, mv_switch_store);


static struct attribute *mv_switch_attrs[] = {
	&dev_attr_reg_r.attr,
	&dev_attr_reg_w.attr,
#ifdef CONFIG_MV_SW_PTP
	&dev_attr_ptp_reg_r.attr,
	&dev_attr_ptp_reg_w.attr,
#endif
	&dev_attr_status.attr,
	&dev_attr_stats.attr,
	&dev_attr_help.attr,
	&dev_attr_port_add.attr,
	&dev_attr_port_del.attr,
	&dev_attr_atu_show.attr,
	&dev_attr_power_set.attr,
	&dev_attr_power_get.attr,
	NULL
};

static struct attribute_group mv_switch_group = {
	.name = "mv_switch",
	.attrs = mv_switch_attrs,
};

int mv_switch_sysfs_init(void)
{
	int err;
	struct device *pd;

	pd = &platform_bus;
	err = sysfs_create_group(&pd->kobj, &mv_switch_group);
	if (err)
		pr_err("Init sysfs group %s failed %d\n", mv_switch_group.name, err);

	return err;
}

module_init(mv_switch_sysfs_init);

MODULE_AUTHOR("Dima Epshtein");
MODULE_DESCRIPTION("sysfs for Marvell switch");
MODULE_LICENSE("GPL");
