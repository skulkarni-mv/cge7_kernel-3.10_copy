/*******************************************************************************
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
#include <linux/of.h>
#include <linux/of_mdio.h>
#include <linux/of_platform.h>
#include "mvOs.h"


struct mii_bus *bus;
int read_val;
int write_val;
int memio_val;

static int mv88e6xxx_reg_wait_ready(struct mii_bus *bus, int sw_addr)
{
	int ret;
	int i;

	for (i = 0; i < 16; i++) {
		ret = mdiobus_read(bus, sw_addr, 0);
		if (ret < 0)
			return ret;

		if ((ret & 0x8000) == 0)
			return 0;
	}

	return -ETIMEDOUT;
}


int __mv88e6xxx_reg_read2(struct mii_bus *bus, int sw_addr, int addr, int reg)
{
	int ret;

	if (sw_addr == 0)
		return mdiobus_read(bus, addr, reg);

	/* Wait for the bus to become free. */
	ret = mv88e6xxx_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	/* Transmit the read command. */
	ret = mdiobus_write(bus, sw_addr, 0, 0x9800 | (addr << 5) | reg);
	if (ret < 0)
		return ret;

	/* Wait for the read command to complete. */
	ret = mv88e6xxx_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	/* Read the data. */
	ret = mdiobus_read(bus, sw_addr, 1);
	if (ret < 0)
		return ret;

	return ret & 0xffff;
}

int mv88e6xxx_reg_read2(int addr, int reg)
{

	int ret;
	ret = __mv88e6xxx_reg_read2(bus,
				0x1f, addr, reg);

	return ret;
}


int __mv88e6xxx_reg_write2(struct mii_bus *bus, int sw_addr, int addr,
			   int reg, u16 val)
{
	int ret;

	if (sw_addr == 0)
		return mdiobus_write(bus, addr, reg, val);

	/* Wait for the bus to become free. */
	ret = mv88e6xxx_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	/* Transmit the data to write. */
	ret = mdiobus_write(bus, sw_addr, 1, val);
	if (ret < 0)
		return ret;

	/* Transmit the write command. */
	ret = mdiobus_write(bus, sw_addr, 0, 0x9400 | (addr << 5) | reg);
	if (ret < 0)
		return ret;

	/* Wait for the write command to complete. */
	ret = mv88e6xxx_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	return 0;
}


int mv88e6xxx_reg_write2(int addr, int reg, u16 val)
{
	int ret;

	ret = __mv88e6xxx_reg_write2(bus,
				     0x1f, addr, reg, val);

	return ret;
}


static ssize_t mv_switch_read(struct device *dev,
			      struct device_attribute *attr, char *buf)
{
	const char *name = attr->attr.name;
	if (!strcmp(name, "memio_read"))
		sprintf(buf, "%x", memio_val);
	else
		if (!strcmp(name, "mii_read"))
			sprintf(buf, "%x", read_val);
		else
			sprintf(buf, "%x", write_val);

	return strlen(buf);
}

static ssize_t mv_switch_write(struct device *dev,
			       struct device_attribute *attr, const char *buf,
			       size_t len)
{
	const char *name = attr->attr.name;
	int addr = 0, reg = 0;
	u16 val = 0;

	if (!strcmp(name, "memio_read")) {
		sscanf(buf, "%x", &addr);
		memio_val = MV_MEMIO32_READ(addr);
	} else {
		if (!strcmp(name, "mii_read")) {
			sscanf(buf, "%x %x", &addr, &reg);
			read_val = mv88e6xxx_reg_read2(addr, reg);
		} else {
			sscanf(buf, "%x %x %hx", &addr, &reg, &val);
			write_val = mv88e6xxx_reg_write2(addr, reg, val);
		}
	}

	return len;
}

static int mv_switch_reg_wait_ready(struct mii_bus *bus, int sw_addr)
{
	int ret;
	int i;

	for (i = 0; i < 16; i++) {
		ret = mdiobus_read(bus, sw_addr, 0);
		if (ret < 0)
			return ret;

		if ((ret & 0x8000) == 0)
			return 0;
	}

	return -ETIMEDOUT;
}

static int mv_switch_probe(struct platform_device *pdev)
{
	struct device_node *np = pdev->dev.of_node;
	struct device_node *mdio;
	int sw_addr = 0x1f;
	int addr = 0x10;
	int reg = 0x03;
	int ret = 0;

	mdio = of_parse_phandle(np, "mv_switch,mii-bus", 0);
	if (!mdio)
		return -EINVAL;

	bus = of_mdio_find_bus(mdio);
	if (!bus)
		return -EINVAL;

	/* Wait for the bus to become free. */
	ret = mv_switch_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	/* Transmit the read command. */
	ret = mdiobus_write(bus, sw_addr, 0, 0x9800 | (addr << 5) | reg);
	if (ret < 0)
		return ret;

	/* Wait for the read command to complete. */
	ret = mv_switch_reg_wait_ready(bus, sw_addr);
	if (ret < 0)
		return ret;

	/* Read the data. */
	ret = mdiobus_read(bus, sw_addr, 1);
	if (ret < 0)
		return ret;
	ret &= 0xffff;

	pr_debug("Initialized Marvell Switch Driver: %x\n", ret);

	return 0;
}

static DEVICE_ATTR(mii_read,  S_IRUSR | S_IWUSR, mv_switch_read,
		   mv_switch_write);
static DEVICE_ATTR(mii_write, S_IRUSR | S_IWUSR, mv_switch_read,
		   mv_switch_write);
static DEVICE_ATTR(memio_read,  S_IRUSR | S_IWUSR, mv_switch_read,
		   mv_switch_write);

static struct attribute *mv_switch_attrs[] = {
	&dev_attr_mii_read.attr,
	&dev_attr_mii_write.attr,
	&dev_attr_memio_read.attr,
	NULL
};

static struct attribute_group mv_switch_group = {
	.name = "mv_switch_mdio",
	.attrs = mv_switch_attrs,
};



/* TBD
*/

static int mv_switch_remove(struct platform_device *pdev)
{
	pr_debug("Removing Marvell Switch Driver\n");
	/* unload */

	return 0;
}


/* TBD
 */

static void mv_switch_shutdown(struct platform_device *pdev)
{
	pr_debug("Shutting Down Marvell Switch Driver\n");
}

static const struct of_device_id mv_switch_of_match_table[] = {
	{ .compatible = "marvell,switch", },
	{}
};
MODULE_DEVICE_TABLE(of, mv_switch_of_match_table);

static struct platform_driver mv_switch_driver = {
	.probe		= mv_switch_probe,
	.remove		= mv_switch_remove,
	.shutdown	= mv_switch_shutdown,
	.driver = {
		.name	= "mv_switch",
		.owner	= THIS_MODULE,
		.of_match_table	= mv_switch_of_match_table,
	},
};


int __init mv_switch_mdio_init(void)
{
	int err;
	struct device *pd;
	int rc;

	rc = platform_driver_register(&mv_switch_driver);
	if (rc)
		return rc;

	pd = &platform_bus;
	err = sysfs_create_group(&pd->kobj, &mv_switch_group);
	if (err)
		pr_err("Init sysfs group %s failed %d\n",
			mv_switch_group.name, err);

	return err;
}

late_initcall(mv_switch_mdio_init);

MODULE_AUTHOR("Claes and Roman");
MODULE_DESCRIPTION("sysfs and driver for Marvell mdio switch");
MODULE_LICENSE("GPL");
