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
#include <linux/platform_device.h>
#include <linux/netdevice.h>

#include "mv_eth_sysfs.h"
#include "gbe/mvPp2Gbe.h"
#include "mv_netdev.h"


static ssize_t mv_pp2_help(char *b)
{
	int o = 0; /* buffer offset */
	int s = PAGE_SIZE; /* buffer size */

	o += scnprintf(b+o, s-o, "cat                              txRegs          - show global TX registers\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq]             > pTxqCounters  - show TXQ Counters for port <p/txp/txq> where <txq> range [0..7]\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq]             > pTxqRegs      - show TXQ registers for port <p/txp/txq> where <txq> range [0..7]\n");
	o += scnprintf(b+o, s-o, "echo [txq]                       > gTxqRegs      - show TXQ registers for global <txq> range [0..255]\n");
	o += scnprintf(b+o, s-o, "echo [cpu]                       > aggrTxqRegs   - show Aggregation TXQ registers for <cpu> range [0..max]\n");
	o += scnprintf(b+o, s-o, "echo [cpu] [v]                   > aggrTxqShow   - show aggregated TXQ descriptors ring for <cpu>.\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq] [v]         > txqShow       - show TXQ descriptors ring for <p/txp/txq>. v: 0-brief, 1-full\n");
	o += scnprintf(b+o, s-o, "echo [p] [hex]                   > txFlags       - set TX flags. bits: 0-no_pad, 1-mh, 2-hw_cmd\n");
	o += scnprintf(b+o, s-o, "echo [p] [hex]                   > txMH          - set 2 bytes of Marvell Header for transmit\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq] [cpu]       > txqDef        - set default <txp/txq> for packets sent to port <p> by <cpu>\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq] [v]         > txqSize       - set TXQ size <v> for <p/txp/txq>.\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq] [hwf] [swf] > txqLimit      - set HWF <hwf> and SWF <swf> limits for <p/txp/txq>.\n");
	o += scnprintf(b+o, s-o, "echo [p] [txp] [txq] [v]         > txqChunk      - set SWF request chunk [v] for <p/txp/txq>\n");
#ifdef CONFIG_MV_PP2_TXDONE_IN_HRTIMER
	o += scnprintf(b+o, s-o, "echo [period]                    > txPeriod      - set Tx Done high resolution timer period\n");
	o += scnprintf(b+o, s-o, "				     [period]: period range is [%lu, %lu], unit usec\n",
		MV_PP2_HRTIMER_PERIOD_MIN, MV_PP2_HRTIMER_PERIOD_MAX);
#endif
	return o;
}

static ssize_t mv_pp2_show(struct device *dev,
				  struct device_attribute *attr, char *buf)
{
	const char      *name = attr->attr.name;
	int             off = 0;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (!strcmp(name, "txRegs"))
		mvPp2TxRegs();
	else
		off = mv_pp2_help(buf);

	return off;
}

static ssize_t mv_pp2_tx_hex_store(struct device *dev,
				struct device_attribute *attr, const char *buf, size_t len)
{
	const char      *name = attr->attr.name;
	int             err;
	unsigned int    p, v;
	unsigned long   flags;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Read port and value */
	err = p = v;
	sscanf(buf, "%d %x", &p, &v);

	local_irq_save(flags);

	if (!strcmp(name, "txFlags")) {
		err = mv_pp2_ctrl_tx_flag(p, MV_ETH_TX_F_NO_PAD, v & 0x1);
		err = mv_pp2_ctrl_tx_flag(p, MV_ETH_TX_F_MH, v & 0x2);
		err = mv_pp2_ctrl_tx_flag(p, MV_ETH_TX_F_HW_CMD, v & 0x4);
	} else if (!strcmp(name, "txMH")) {
		err = mv_pp2_eth_ctrl_tx_mh(p, MV_16BIT_BE((u16)v));
	} else {
		err = 1;
		printk(KERN_ERR "%s: illegal operation <%s>\n", __func__, attr->attr.name);
	}
	local_irq_restore(flags);

	if (err)
		printk(KERN_ERR "%s: error %d\n", __func__, err);

	return err ? -EINVAL : len;
}

static ssize_t mv_pp2_txq_store(struct device *dev,
				   struct device_attribute *attr, const char *buf, size_t len)
{
	const char      *name = attr->attr.name;
	int             err;
	unsigned int    p, v, a, b, c;
	unsigned long   flags;

	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Read port and value */
	err = p = v = a = b = c = 0;
	sscanf(buf, "%d %d %d %d %d", &p, &v, &a, &b, &c);

	local_irq_save(flags);

	if (!strcmp(name, "txqDef")) {
		err = mv_pp2_ctrl_txq_cpu_def(p, v, a, b);
	} else if (!strcmp(name, "txqShow")) {
		mvPp2TxqShow(p, v, a, b);
	}  else if (!strcmp(name, "aggrTxqShow")) {
		mvPp2AggrTxqShow(p, v);
	} else if (!strcmp(name, "gTxqRegs")) {
		mvPp2PhysTxqRegs(p);
	} else if (!strcmp(name, "pTxqRegs")) {
		mvPp2PortTxqRegs(p, v, a);
	} else if (!strcmp(name, "pTxqCounters")) {
		mvPp2V1TxqDbgCntrs(p, v, a);
	} else if (!strcmp(name, "aggrTxqRegs")) {
		mvPp2AggrTxqRegs(p);
	} else if (!strcmp(name, "txqSize")) {
		mv_pp2_ctrl_txq_size_set(p, v, a, b);
	} else if (!strcmp(name, "txqLimit")) {
		/* last param is ignored in ppv2.0 */
		mv_pp2_ctrl_txq_limits_set(p, v, a, b, c);
	} else if (!strcmp(name, "txqChunk")) {
		mv_pp2_ctrl_txq_chunk_set(p, v, a, b);
	} else if (!strcmp(name, "txPeriod")) {
#ifdef CONFIG_MV_PP2_TXDONE_IN_HRTIMER
		mv_pp2_tx_done_hrtimer_period_set(p);
#endif
	} else {
		err = 1;
		printk(KERN_ERR "%s: illegal operation <%s>\n", __func__, attr->attr.name);
	}

	local_irq_restore(flags);

	if (err)
		printk(KERN_ERR "%s: error %d\n", __func__, err);

	return err ? -EINVAL : len;
}

static DEVICE_ATTR(help,         S_IRUSR, mv_pp2_show, NULL);
static DEVICE_ATTR(txRegs,       S_IRUSR, mv_pp2_show, NULL);
static DEVICE_ATTR(aggrTxqRegs,  S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(pTxqCounters, S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(txqShow,      S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(gTxqRegs,     S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(pTxqRegs,     S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(aggrTxqShow,  S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(txqDef,       S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(txqSize,      S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(txqLimit,     S_IWUSR, NULL, mv_pp2_txq_store);
static DEVICE_ATTR(txqChunk,     S_IWUSR, NULL, mv_pp2_txq_store);
#ifdef CONFIG_MV_PP2_TXDONE_IN_HRTIMER
static DEVICE_ATTR(txPeriod,     S_IWUSR, NULL, mv_pp2_txq_store);
#endif
static DEVICE_ATTR(txFlags,      S_IWUSR, NULL, mv_pp2_tx_hex_store);
static DEVICE_ATTR(txMH,         S_IWUSR, NULL, mv_pp2_tx_hex_store);

static struct attribute *mv_pp2_tx_attrs[] = {
	&dev_attr_txqDef.attr,
	&dev_attr_pTxqCounters.attr,
	&dev_attr_aggrTxqRegs.attr,
	&dev_attr_help.attr,
	&dev_attr_txRegs.attr,
	&dev_attr_txqShow.attr,
	&dev_attr_gTxqRegs.attr,
	&dev_attr_pTxqRegs.attr,
	&dev_attr_aggrTxqShow.attr,
	&dev_attr_txqSize.attr,
	&dev_attr_txqLimit.attr,
	&dev_attr_txqChunk.attr,
#ifdef CONFIG_MV_PP2_TXDONE_IN_HRTIMER
	&dev_attr_txPeriod.attr,
#endif
	&dev_attr_txFlags.attr,
	&dev_attr_txMH.attr,
	NULL
};

static struct attribute_group mv_pp2_tx_group = {
	.name = "tx",
	.attrs = mv_pp2_tx_attrs,
};

int mv_pp2_tx_sysfs_init(struct kobject *gbe_kobj)
{
	int err;

	err = sysfs_create_group(gbe_kobj, &mv_pp2_tx_group);
	if (err)
		pr_err("sysfs group %s failed %d\n", mv_pp2_tx_group.name, err);

	return err;
}

int mv_pp2_tx_sysfs_exit(struct kobject *gbe_kobj)
{
	sysfs_remove_group(gbe_kobj, &mv_pp2_tx_group);

	return 0;
}

