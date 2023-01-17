/* Applied Micro experiment PHY Driver
 *
 * Copyright (c) 2015, Applied Micro Circuits Corporation
 * Authors: Quan Nguyen <qnguyen@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/unistd.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/phy.h>
#include <linux/marvell_phy.h>
#include <linux/of.h>

#include <asm/io.h>
#include <asm/irq.h>
#include <asm/uaccess.h>

#define MII_PHY_PAGE            22

#define MII_IEVENT                0x13
#define MII_IEVENT_CLEAR          0x0000

#define MII_IMASK                 0x12
#define MII_IMASK_INIT            0x6400
#define MII_IMASK_CLEAR           0x0000

#define PHY_ID_88E1548L         0x01410eb1
#define PHY_ID_MASK             0xfffffff0

#define PHY_88E1548L_DLY        10 /* ms */
#define PHY_88E1548L_TIMEOUT    10 /* seconds */
#define MII_PHY_STATUS            0x11
#define MII_PHY_STATUS_1000       0x8000
#define MII_PHY_STATUS_100        0x4000
#define MII_PHY_STATUS_SPD_MASK   0xc000
#define MII_PHY_STATUS_FULLDUPLEX 0x2000
#define MII_PHY_STATUS_RESOLVED   0x0800
#define MII_PHY_STATUS_LINK       0x0400

enum {
	SGMII_PHY_COPPER_MODE = 0,
	SGMII_PHY_SFP_MODE,
	SGMII_PHY_AUTO_MODE,
	SGMII_PHY_MAX_MODE,
};

struct xgene_enet_phy_priv {
	struct device_attribute sgmii_phy_mode_attr;
	char sgmii_phy_mode_attr_name[20];
	int sgmii_phy_mode;
	struct phy_device *phydev;
};

/* xgene_enet_phy_page_read_status
 *
 * Generic status code does not detect Fiber correctly!
 * Description:
 *   Check the link, then figure out the current state
 *   by comparing what we advertise with what the link partner
 *   advertises.  Start by checking the gigabit possibilities,
 *   then move on to 10/100.
 */
static int xgene_enet_phy_page_read_status(struct phy_device *phydev)
{
	int adv;
	int err;
	int lpa;
	int status = 0;

	/* Update the link, but return if there
	 * was an error */
	err = genphy_update_link(phydev);
	if (err)
		return err;

	if (AUTONEG_ENABLE == phydev->autoneg) {
		status = phy_read(phydev, MII_PHY_STATUS);
		if (status < 0)
			return status;

		lpa = phy_read(phydev, MII_LPA);
		if (lpa < 0)
			return lpa;

		adv = phy_read(phydev, MII_ADVERTISE);
		if (adv < 0)
			return adv;

		lpa &= adv;

		if (status & MII_PHY_STATUS_FULLDUPLEX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		status = status & MII_PHY_STATUS_SPD_MASK;
		phydev->pause = phydev->asym_pause = 0;

		switch (status) {
		case MII_PHY_STATUS_1000:
			phydev->speed = SPEED_1000;
			break;

		case MII_PHY_STATUS_100:
			phydev->speed = SPEED_100;
			break;

		default:
			phydev->speed = SPEED_10;
			break;
		}

		if (phydev->duplex == DUPLEX_FULL) {
			phydev->pause = lpa & LPA_PAUSE_CAP ? 1 : 0;
			phydev->asym_pause = lpa & LPA_PAUSE_ASYM ? 1 : 0;
		}
	} else {
		int bmcr = phy_read(phydev, MII_BMCR);

		if (bmcr < 0)
			return bmcr;

		if (bmcr & BMCR_FULLDPLX)
			phydev->duplex = DUPLEX_FULL;
		else
			phydev->duplex = DUPLEX_HALF;

		if (bmcr & BMCR_SPEED1000)
			phydev->speed = SPEED_1000;
		else if (bmcr & BMCR_SPEED100)
			phydev->speed = SPEED_100;
		else
			phydev->speed = SPEED_10;

		phydev->pause = phydev->asym_pause = 0;
	}

	return 0;
}

static int xgene_enet_phy_read_status(struct phy_device *phydev)
{
	int phy_addr0_2 = phydev->addr;
	int phy_addr1_3 = phy_addr0_2 + 1;
	int status = 0;
	struct xgene_enet_phy_priv *priv = NULL;
	int check_media = 0;
	int copper_link = 0, fiber_link = 0;

	priv = phydev->priv;
	check_media = priv->sgmii_phy_mode;

	if (check_media == SGMII_PHY_AUTO_MODE) {
		phydev->addr = phy_addr1_3;
		/* read copper link */
		phy_write(phydev, MII_PHY_PAGE, 0); /* copper page */
		copper_link = phy_read(phydev, 1) & 0x04;

		/* read fiber link */
		phy_write(phydev, MII_PHY_PAGE, 1); /* fiber page */
		fiber_link = phy_read(phydev, 1) & 0x04;

		if (copper_link)
			check_media = SGMII_PHY_COPPER_MODE;
		else if (fiber_link)
			check_media = SGMII_PHY_SFP_MODE;
		else
			check_media = SGMII_PHY_COPPER_MODE;
	}

	phydev->addr = phy_addr1_3;
	if (check_media == SGMII_PHY_COPPER_MODE)
		phy_write(phydev, MII_PHY_PAGE, 0); /* copper page */
	else if (check_media == SGMII_PHY_SFP_MODE)
		phy_write(phydev, MII_PHY_PAGE, 1); /* fiber page */
	status = xgene_enet_phy_page_read_status(phydev);

	/* restore default phy address and page */
	phydev->addr = phy_addr0_2;
	phy_write(phydev, MII_PHY_PAGE, 1); /* sgmii page */
	return status;
}


static int xgene_enet_phy_config_aneg(struct phy_device *phydev)
{
	int err;
	int phy_addr0_2 = phydev->addr;
	int phy_addr1_3 = phy_addr0_2 + 1;
	u32 bmcr = 0;

printk("%s:%d\n",__func__,__LINE__);
	phydev->addr = phy_addr1_3;
	err = phy_write(phydev, MII_PHY_PAGE, 1); /* fiber page */
	bmcr = phy_read(phydev, MII_BMCR);
	err = phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
	if (err < 0)
		return err;
	err = genphy_config_aneg(phydev);

	phydev->addr = phy_addr1_3;
	err = phy_write(phydev, MII_PHY_PAGE, 0); /* copper page */

	bmcr = phy_read(phydev, MII_BMCR);
	err = phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
	if (err < 0)
		return err;
	err = genphy_config_aneg(phydev);

	phydev->addr = phy_addr0_2;
	err = phy_write(phydev, MII_PHY_PAGE, 1); /* sgmii page */
	err = phy_write(phydev, MII_BMCR, BMCR_RESET);
	bmcr = phy_read(phydev, MII_BMCR);
	err = phy_write(phydev, MII_BMCR, bmcr | BMCR_RESET);
	if (err < 0)
		return err;
	err = genphy_config_aneg(phydev);

	/* default read to SGMII port */
	phydev->addr = phy_addr0_2;
	err = phy_write(phydev, MII_PHY_PAGE, 1); /* sgmii page */
	return 0;
}

/* Marvell 88E1548L PHY mode config */
ssize_t xgene_enet_phy_sgmii_phy_mode_show(struct device *dev,
			      struct device_attribute *attr,
			      char *buf)
{
	struct xgene_enet_phy_priv *priv = container_of(attr, struct xgene_enet_phy_priv,
						   sgmii_phy_mode_attr);
	switch(priv->sgmii_phy_mode) {
	case SGMII_PHY_COPPER_MODE:
		sprintf(buf, "copper\n");
		break;
	case SGMII_PHY_SFP_MODE:
		sprintf(buf, "sfp\n");
		break;
	case SGMII_PHY_AUTO_MODE:
		sprintf(buf, "auto\n");
		break;
	default:
		sprintf(buf, "unknown\n");
		break;
	}

	return strlen(buf);
}

ssize_t xgene_enet_phy_sgmii_phy_mode_store(struct device *dev,
			     struct device_attribute *attr,
			     const char *buf, size_t count)
{
	struct xgene_enet_phy_priv *priv = container_of(attr, struct xgene_enet_phy_priv,
						   sgmii_phy_mode_attr);
	struct phy_device *phydev = priv->phydev;
	struct net_device *ndev = phydev->attached_dev;
	u32 data;
	int phy_addr0_2 = phydev->addr;
	int phy_addr1_3 = phy_addr0_2 + 1;
	int err = 0;

	if (strcmp(buf,"copper\n") == 0)
		priv->sgmii_phy_mode = SGMII_PHY_COPPER_MODE;
	else if (strcmp(buf,"sfp\n") == 0)
		priv->sgmii_phy_mode = SGMII_PHY_SFP_MODE;
	else if (strcmp(buf,"auto\n") == 0)
		priv->sgmii_phy_mode = SGMII_PHY_AUTO_MODE;
	else
		return -EINVAL;

	printk("set %s SGMII PHY mode to %s\n", ndev->name,
		priv->sgmii_phy_mode == SGMII_PHY_COPPER_MODE ? "copper":
		priv->sgmii_phy_mode == SGMII_PHY_SFP_MODE ? "sfp":
		priv->sgmii_phy_mode == SGMII_PHY_AUTO_MODE ? "auto":
		"unknown");
	/**
 	 * Mode selection
 	 * port 1 & 3: QSGMII(System mode) to Auto Media Detect Copper/1000BASE-X or Copper/100BASE-FX
 	 */
	phydev->addr = phy_addr1_3;
	err = phy_write(phydev, MII_PHY_PAGE, 18); // select page 18
	if (err)
		goto error_exit;
	data = phy_read(phydev, 20);
	if (data < 0) {
		err = -EIO;
		goto error_exit;
	}
	data &= (~7);
	switch(priv->sgmii_phy_mode) {
	case SGMII_PHY_COPPER_MODE:
		data |= 0x8000;
		break;
	case SGMII_PHY_SFP_MODE:
		data |= 0x8002;
		break;
	case SGMII_PHY_AUTO_MODE:
		data |= 0x8007;
		break;
	default:
		data |= 0x8007;
		break;
	}
	err = phy_write(phydev, 20, data);
	if (err)
		goto error_exit;

	phydev->addr = phy_addr0_2;
	return count;

error_exit:
	phydev->addr = phy_addr0_2;
	return err;
}

static int xgene_enet_phy_config_init(struct phy_device *phydev)
{
	struct xgene_enet_phy_priv *priv = NULL;
	int err = 0;
printk("%s:%d: APM PHY INIT\n",__func__,__LINE__);
	priv = kmalloc(sizeof(struct xgene_enet_phy_priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	phydev->priv = priv;
	priv->phydev = phydev;

	memset(priv->sgmii_phy_mode_attr_name, 0,
			sizeof(priv->sgmii_phy_mode_attr_name));
	memset(&priv->sgmii_phy_mode_attr, 0,
			sizeof(priv->sgmii_phy_mode_attr));

	sprintf(priv->sgmii_phy_mode_attr_name, "sgmii_phy_mode");
	priv->sgmii_phy_mode_attr.attr.name = priv->sgmii_phy_mode_attr_name;
	priv->sgmii_phy_mode_attr.attr.mode = S_IRUGO | S_IWUSR;
	priv->sgmii_phy_mode_attr.store = xgene_enet_phy_sgmii_phy_mode_store;
	priv->sgmii_phy_mode_attr.show = xgene_enet_phy_sgmii_phy_mode_show;
	sysfs_attr_init(&priv->sgmii_phy_mode_attr);

	priv->sgmii_phy_mode = SGMII_PHY_AUTO_MODE;

	err = device_create_file(&phydev->attached_dev->dev, &priv->sgmii_phy_mode_attr);
	if (err)
		return err;
	return 0;
}
static int xgene_enet_phy_ack_interrupt(struct phy_device *phydev)
{
	int err;

printk("%s:%d\n",__func__,__LINE__);
	/* Clear the interrupts by reading the reg */
	err = phy_read(phydev, MII_IEVENT);

	if (err < 0)
		return err;

	return 0;
}

static int xgene_enet_phy_config_intr(struct phy_device *phydev)
{
	int err;
printk("%s:%d\n",__func__,__LINE__);
	if (phydev->interrupts == PHY_INTERRUPT_ENABLED)
		err = phy_write(phydev, MII_IMASK, MII_IMASK_INIT);
	else
		err = phy_write(phydev, MII_IMASK, MII_IMASK_CLEAR);

	return err;
}

static struct phy_driver xgene_enet_phy_drivers[] = {
	{
		/* not a generic one - just for Cisco_p0c board */
		.phy_id = PHY_ID_88E1548L,
		.phy_id_mask = PHY_ID_MASK,
		.name = "APM PHY 88E1548L",
		.features = PHY_BASIC_FEATURES,
		.flags = PHY_POLL,
		.config_init = &xgene_enet_phy_config_init,
		.config_aneg = &xgene_enet_phy_config_aneg,
		.read_status = &xgene_enet_phy_read_status,
		.ack_interrupt = &xgene_enet_phy_ack_interrupt,
		.config_intr = &xgene_enet_phy_config_intr,
		.driver = { .owner = THIS_MODULE },
	},
};

static int __init xgene_enet_phy_init(void)
{
printk("%s:%d\n",__func__,__LINE__);
        return phy_drivers_register(xgene_enet_phy_drivers,
                 ARRAY_SIZE(xgene_enet_phy_drivers));
}

static void __exit xgene_enet_phy_exit(void)
{
printk("%s:%d\n",__func__,__LINE__);
        phy_drivers_unregister(xgene_enet_phy_drivers,
                 ARRAY_SIZE(xgene_enet_phy_drivers));
}

subsys_initcall(xgene_enet_phy_init);
module_exit(xgene_enet_phy_exit);

static struct mdio_device_id __maybe_unused xgene_enet_phy_tbl[] = {
        { PHY_ID_88E1548L, PHY_ID_MASK },
        { }
};

MODULE_DEVICE_TABLE(mdio, xgene_enet_phy_tbl);

