/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Mahesh Pujara <mpujara@apm.com>
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
 * @file apm_enet_eee.c
 *
 * This file implements sysfs interface for Energy Efficient Ethernet
 * functionality of APM862xx SoC Ethernet subsystem
 *
 */

#ifdef CONFIG_SYSFS
#include <asm/ipp.h>
#include <linux/stat.h>
#include "apm_enet_eee.h"
#include "apm_cle_cfg.h"

static u32 wol_port;

static ssize_t apm_enet_eee_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "echo <port> <0|1> to enable/disable EEE mode\n");
}

static ssize_t apm_enet_eee_set(struct device_driver *drv,
				const char *buf, size_t count)
{
	int ret;
	int port;
	u32 data;
	struct net_device *ndev;
	struct apm_enet_dev_base *priv_dev;
	struct apm_data_priv *priv;
	u32 enable_eee;

	ret = sscanf(buf, "%d %d", &port, &enable_eee);
	if (ret != 2) {
		printk(KERN_ERR "echo <port> <0|1>\n");
		return count;
	}

	if (port > MAX_PORTS) {
		printk(KERN_ERR "Invalid port\n");
		return count;
	}

	ndev = find_netdev(port);
	if (ndev == NULL) {
		printk(KERN_ERR "Couldn't get net device\n");
		return count;
	}

	priv_dev = netdev_priv(ndev);
	if (priv_dev == NULL) {
		printk(KERN_ERR "Couldn't get device\n");
		return count;
	}

	priv = &priv_dev->priv;
	if (enable_eee) {
		printk(KERN_INFO "ETH%d enable EEE mode\n", port);
		if (port == 0) {
			/* use defaults for now */
			apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_TW_TIMER_0,
					&data);
			ENET_DEBUG("EEE_TW_TIMER_0 0x%08x\n", data);

			/* use defaults for now */
			apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL,
					EEE_LPI_WAIT_PATTERNS_0, &data);
			ENET_DEBUG("EEE_LPI_WAIT_PATTERNS_0 0x%08x\n", data);

			apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0,
					&data);
			/* use default cfg_lpi_clk_stop_after_ncycles for now */
			data  = EEE_REG_CFG_LPI_CLK_STOPPABLE |
				EEE_REG_CFG_LPI_MODE |
				0x804;  /* 16.5us based on 125Mhz clock */
			apm_enet_wr32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0,
					data);
			apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0,
					&data);
			ENET_DEBUG("EEE_REG_0 0x%08x\n", data);
		} else {
			apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_1,
					&data);
			/* use default cfg_lpi_clk_stop_after_ncycles for now */
			data |= EEE_REG_CFG_LPI_CLK_STOPPABLE;
			data |= EEE_REG_CFG_LPI_MODE;
			apm_enet_wr32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_1,
					data);
			ENET_DEBUG("EEE_REG_0 0x%08x\n", data);
		}
	} else {
		printk(KERN_INFO "ETH%d disable EEE mode\n", port);
		apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0, &data);
		data &= ~EEE_REG_CFG_LPI_CLK_STOPPABLE;
		data &= ~EEE_REG_CFG_LPI_MODE;
		apm_enet_wr32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0, data);
		apm_enet_rd32(priv, BLOCK_ETH_MAC_GBL, EEE_REG_0, &data);
		ENET_DEBUG("EEE_REG_0 0x%08x\n", data);
        }
        return count;
}

static ssize_t apm_enet_miiwrite_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "echo <port> <phy> <reg> <data>\n");
}

static ssize_t apm_enet_miiwrite_set(struct device_driver *drv,
				     const char *buf, size_t count)
{
	int ret;
	int port, phy, reg;
	u32 data;
	struct net_device *ndev;
	struct apm_enet_dev_base *priv_dev;
	struct apm_data_priv *priv;

	ret = sscanf(buf, "%d %d %d %d", &port, &phy, &reg, &data);
	if (ret != 4) {
		printk(KERN_ERR "echo <port> <phy> <reg> <data>\n");
		return count;
	}

	if (port > MAX_PORTS) {
		printk(KERN_ERR "Invalid port\n");
		return count;
	}

	ndev = find_netdev(port);
	if (ndev == NULL) {
		printk(KERN_ERR "Couldn't get net device\n");
		return count;
	}

	priv_dev = netdev_priv(ndev);
	if (priv_dev == NULL) {
		printk(KERN_ERR "Couldn't get device\n");
		return count;
	}

	priv = &priv_dev->priv;

	apm_genericmiiphy_write(priv, (u8)phy, (u8)reg, data);

        return count;
}

static ssize_t apm_enet_miiread_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "echo <port> <phy> <reg>\n");
}

static ssize_t apm_enet_miiread_set(struct device_driver *drv,
				    const char *buf, size_t count)
{
	int ret;
	int port, phy, reg;
	u32 data;
	struct net_device *ndev;
	struct apm_enet_dev_base *priv_dev;
	struct apm_data_priv *priv;

	ret = sscanf(buf, "%d %d %d", &port, &phy, &reg);

	if (ret != 3) {
		printk(KERN_ERR "echo <port> <phy> <reg>\n");
		return count;
	}

	if (port > MAX_PORTS) {
		printk(KERN_ERR "Invalid port\n");
		return count;
	}

	ndev = find_netdev(port);
	if (ndev == NULL) {
		printk(KERN_ERR "Couldn't get net device\n");
		return count;
	}

	priv_dev = netdev_priv(ndev);
	if (priv_dev == NULL) {
		printk(KERN_ERR "Couldn't get device\n");
		return count;
	}

	priv = &priv_dev->priv;

	apm_genericmiiphy_read(priv, (u8)phy, (u8)reg, &data);
        return count;
}

static ssize_t apm_enet_miidump_show(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "echo <port> <phy>\n");
}

static ssize_t apm_enet_miidump_set(struct device_driver *drv,
				    const char *buf, size_t count)
{
	int ret;
	int port, phy, reg;
	u32 data;
	struct net_device *ndev;
	struct apm_enet_dev_base *priv_dev;
	struct apm_data_priv *priv;

	ret = sscanf(buf, "%d %d", &port, &phy);
	if (ret != 2) {
		printk(KERN_ERR "echo <port> <phy>\n");
		return count;
	}

	if (port > MAX_PORTS) {
		printk(KERN_ERR "Invalid port\n");
		return count;
	}

	ndev = find_netdev(port);
	if (ndev == NULL) {
		printk(KERN_ERR "Couldn't get net device\n");
		return count;
	}

	priv_dev = netdev_priv(ndev);
	if (priv_dev == NULL) {
		printk(KERN_ERR "Couldn't get device\n");
		return count;
	}

	priv = &priv_dev->priv;

	for (reg = 0; reg < 32; reg++)
		apm_genericmiiphy_read(priv, (u8)phy, (u8)reg, &data);

        return count;
}

static ssize_t apm_enet_wolport_show(struct device_driver *drv, char *buf)
{
        return sprintf(buf, "%d\n", wol_port);
}

static ssize_t apm_enet_wolport_set(struct device_driver *drv,
				    const char *buf, size_t count)
{
	u32 val;
	u8 wol_portid = 0;

	sscanf(buf, "%d", &val);
	wol_port = (unsigned short)val;

	/* Send WoL Port to iPP */
	val = ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
				IPP_SEND_WOL_PORT_VAR,
				wol_portid,
				IPP_MSG_CONTROL_URG_BIT, wol_port);
	val |= apm_preclass_set_wol_port(0, wol_portid, wol_port);
	ENET_DEBUG("Updating WoL Port to %d - %s\n", wol_port,
			val == APM_RC_OK ? "Success" : "Failed");
	return count;
}

static struct driver_attribute apm_enet_attrs[] = {
	__ATTR(eee, S_IWUGO | S_IRUGO,
		apm_enet_eee_show, apm_enet_eee_set),
	__ATTR(mii_write, S_IWUGO | S_IRUGO,
		apm_enet_miiwrite_show, apm_enet_miiwrite_set),
	__ATTR(mii_read, S_IWUGO | S_IRUGO,
		apm_enet_miiread_show, apm_enet_miiread_set),
	__ATTR(mii_dump, S_IWUGO | S_IRUGO,
		apm_enet_miidump_show, apm_enet_miidump_set),
	__ATTR(wol_port, S_IWUGO | S_IRUGO,
		apm_enet_wolport_show, apm_enet_wolport_set),
};

int apm_enet_add_sysfs(struct device_driver *driver)
{
	int i;
	int err;
	static int added_done = 0;

	if (added_done)
		return 0;

	for (i = 0; i < ARRAY_SIZE(apm_enet_attrs); i++) {
		err = driver_create_file(driver, &apm_enet_attrs[i]);
		if (err)
			goto fail;
	}

	wol_port = UDP_DEFAULT_WOL_PORT;
	added_done = 1;

	return 0;
fail:
	while (--i >= 0)
		driver_remove_file(driver, &apm_enet_attrs[i]);
	return err;
}

void apm_enet_remove_sysfs(struct device_driver *driver)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(apm_enet_attrs); i++)
		driver_remove_file(driver, &apm_enet_attrs[i]);
}

#endif /* CONFIG_SYSFS */
