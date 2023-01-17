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

#include "pse.h"
#include "pse_common.h"
#include "pse_mac.h"

/* MAC_CHECK_CMD */
#define	HASH_INDEX_OFFSET	(22)
#define START_OFFSET		(15)
#define	CMD_OFFSET		(12)
#define	HIT_BIT_OFFSET		(11)
#define	PORT_OFFSET		(0)

#define	HIT_BIT_MASK	(0x1 << HIT_BIT_OFFSET)
#define	START_MASK	(0x1 << START_OFFSET)

/* MAC_CHECK_CTRL1 */
#define MY_MAC_PRI_OFFSET	(0)

/* mac_to_ctrl_reg - transfer struct pse_mac to MAC check control register
 * @ptr: pointer to pse_mac structure
 */
static void mac_to_ctrl_reg(struct pse_mac *ptr)
{
	u32 val;

	/* MAC_CHECK_CTRL0 */
	val = (ptr->mac[0] << 24) | (ptr->mac[1] << 16)
		| (ptr->mac[2] << 8)
		| (ptr->mac[3]);
	wr32(val, MAC_CHECK_CTRL0);

	/* MAC_CHECK_CTRL1 */
	val = (ptr->mac[4] << 24) | (ptr->mac[5] << 16)
		| (ptr->priority << MY_MAC_PRI_OFFSET);

	wr32(val, MAC_CHECK_CTRL1);

	/* MAC_CHECK_CMD */
	val =  (ptr->index << HASH_INDEX_OFFSET)
		| (ptr->port & 0x7);
	wr32(val, MAC_CHECK_CMD);
}

/* mac_from_ctrl_reg - transfer MAC check control register to struct pse_mac
 * @ptr: pointer to pse_mac structure
 */
static void mac_from_ctrl_reg(struct pse_mac *ptr)
{
	u32 val;

	/* MAC_CHECK_CTRL0 */
	val = rd32(MAC_CHECK_CTRL0);
	ptr->mac[0] = (val >> 24) & 0xFF;
	ptr->mac[1] = (val >> 16) & 0xFF;
	ptr->mac[2] = (val >> 8) & 0xFF;
	ptr->mac[3] = (val) & 0xFF;

	/* MAC_CHECK_CTRL1 */
	val = rd32(MAC_CHECK_CTRL1);
	ptr->mac[4] = (val >> 24) & 0xFF;
	ptr->mac[5] = (val >> 16) & 0xFF;
	ptr->priority = ((val >> MY_MAC_PRI_OFFSET) & 0x7);
}

#define MAC_CMD_READ_MASK	(0 << CMD_OFFSET)
#define MAC_CMD_WRITE_MASK	(1 << CMD_OFFSET)
#define MAC_CMD_READ_HIT_BY_LOOKUP_MASK		(2 << CMD_OFFSET)
#define MAC_CMD_WRITE_HIT_BY_LOOKUP_MASK	(3 << CMD_OFFSET)
#define MAC_CMD_READ_HIT_BY_INDEX_MASK		(4 << CMD_OFFSET)
#define MAC_CMD_WRITE_HIT_BY_INDEX_MASK		(5 << CMD_OFFSET)

/* pse_mac_write -
 * @ptr: pointer to pse_mac structure
 */
int pse_mac_write(struct pse_mac *ptr)
{
	u32 val;

	switch (ptr->port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		if (1 < ptr->index)
			return -1;
		break;
	case OPV5XC_PSE_PORT_CPU:
		if (7 < ptr->index)
			return -1;
		break;
	default:
		return -1;
	}

	mac_to_ctrl_reg(ptr);

	val = rd32(MAC_CHECK_CMD);
	val |= (MAC_CMD_WRITE_MASK | START_MASK);

	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	return PSE_OK;
}

/* pse_mac_read -
 * @ptr: pointer to pse_mac structure
 */
int pse_mac_read(struct pse_mac *ptr)
{
	u32 val;

	mac_to_ctrl_reg(ptr);

	val = rd32(MAC_CHECK_CMD);
	val |= (MAC_CMD_READ_MASK | START_MASK);
	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	mac_from_ctrl_reg(ptr);

	return PSE_OK;
}

void pse_mac_hash(enum pse_mac_hash_algo cfg)
{
	u32 val;
	val = rd32(MAC_CHECK_CFG);
	val &= ~0x03;
	val |= cfg;
	wr32(val, MAC_CHECK_CFG);
}

/* pse_mac_hash_write -
 * @ptr: pointer to pse_mac structure
 */
int pse_mac_hash_write_by_lookup(struct pse_mac *ptr)
{
	u32 val;

	switch (ptr->port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		return -1;
	}

	mac_to_ctrl_reg(ptr);

	val = rd32(MAC_CHECK_CMD);
	val |= (1 << 11);
	val |= (MAC_CMD_WRITE_HIT_BY_LOOKUP_MASK | START_MASK);

	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	return PSE_OK;
}

int pse_mac_hash_read_by_lookup(struct pse_mac *ptr)
{
	u32 val;

	switch (ptr->port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		return -1;
	}

	mac_to_ctrl_reg(ptr);

	val = rd32(MAC_CHECK_CMD);
	val |= (MAC_CMD_READ_HIT_BY_LOOKUP_MASK | START_MASK);

	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	return !!(val & HIT_BIT_MASK);
}


/* pse_mac_hash_read
 *
 * @port: 0:MAC 0, 1:MAC 1, 2:CPU, 4: MAC 2
 * @index: to do traffic class check
 *
 * pse_mac_hash_read support MAC port and CPU port
 */
int pse_mac_hash_read_by_index(int port, int index)
{
	u32 val;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		return -1;
	}

	if (511 < index)
		return -1;

	val = (index << 22)
		| MAC_CMD_READ_HIT_BY_INDEX_MASK | START_MASK
		| port;
	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	return !!(val & HIT_BIT_MASK);
}

int pse_mac_hash_write_by_index(int port, int index)
{
	u32 val;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		return -1;
	}

	if (511 < index)
		return -1;

	val = (index << 22) | MAC_CMD_WRITE_HIT_BY_INDEX_MASK | START_MASK
		| port | (1 << 11);

	wr32(val, MAC_CHECK_CMD);

	/* wait for command complete */
	do {
		val = rd32(MAC_CHECK_CMD);
	} while ((val & START_MASK));

	return 0;
}
