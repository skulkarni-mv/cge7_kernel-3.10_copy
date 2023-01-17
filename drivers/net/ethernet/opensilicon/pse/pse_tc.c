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
#include "pse_tc_cmd.h"

/* tc_cfg_* - configure traffic class check by *
 *
 * @ port: 0:MAC 0, 1:MAC 1, 2:CPU, 4: MAC 2
 * @ enable: to do traffic class check
 *
 * tc_cfg_* support MAC port and CPU port
 */

/* Ethernet Type */
TC_CFG_FUNC(ethertype);
/* VLAN */
TC_CFG_FUNC(vlan);
/* DSCP */
TC_CFG_FUNC(dscp);
/* UDP port range */
TC_CFG_FUNC(udp);
/* TCP port range */
TC_CFG_FUNC(tcp);
/* DMAC (refer to MAC check table) */
TC_CFG_FUNC(dmac);
/*  Regenerate user priority in TX priority tag */
TC_CFG_FUNC(regen_user_pri);

/* tc_to_ring - assign FS descriptor ring by traffic class
 *
 * @port: 0:MAC 0, 1:MAC 1, 4: MAC 2
 * @tc: traffic class
 * @ring: ring ID.
 *
 * tc_to_ring only support MAC port
 */
int tc_to_ring(u8 port, u8 tc, u8 ring)
{
	u32 val, offset;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		/* TODO debug message */
		return -1;
	}

	if (OPV5XC_PSE_NR_TC <= tc) {
		/* TODO debug message */
		return -1;
	}

	if (OPV5XC_PSE_NR_RING <= ring) {
		/* TODO debug message */
		return -1;
	}

	/* read port priority setting */
	PRI_CMD_READ();

	/* assign ring for traffic class */
	val = rd32(PORT_PRI_RING);
	offset = ((7 - tc) << 2);

	val &= ~(0xf << offset);
	val |= (ring << offset);

	wr32(val, PORT_PRI_RING);

	/* issue write command */
	PRI_CMD_WRITE();

	return 0;
};

/* tc_port - assign traffic class by physical port.
 *
 * @port: 0:MAC 0, 1:MAC 1, 2:CPU, 4: MAC 2
 * @tc: traffic class
 *
 * tc_port only support MAC port and CPU port.
 */
int tc_port(u8 port, u8 tc)
{
	u32 val;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1:
	case OPV5XC_PSE_PORT_MAC2: case OPV5XC_PSE_PORT_CPU:
		break;
	default:
		/* TODO debug message */
		return -1;
	}

	if (OPV5XC_PSE_NR_TC <= tc) {
		/* TODO debug message */
		return -1;
	}

	/* read port priority setting */
	PRI_CMD_READ();

	/* configure tc */
	val = rd32(PORT_PRI_CTRL);
	val &= ~(0xf << 24);
	val |= (tc << 24);
	wr32(val, PORT_PRI_CTRL);

	/* issue write command */
	PRI_CMD_WRITE();

	return 0;
};

#define PSE_ETHER_TYPE_PRI_INDEX_MAX (3)
/* tc_ethertype - assign traffic class by Ethernet type.
 *
 * @index: 0~3. PSE support 4 Ethertype.
 * @type: Ethernet type
 * @tc: traffic class
 */
int tc_ethertype(u8 index, u16 type, u8 tc)
{
	u32 val;

	if (PSE_ETHER_TYPE_PRI_INDEX_MAX < index) {
		/* TODO debug message */
		return -1;
	}

	if (OPV5XC_PSE_NR_TC <= tc) {
		/* TODO debug message */
		return -1;
	}

	val = (type << 16) | PRI_START_MASK | PRI_CMD_WRITE_MASK | (tc << 9) | index;
	wr32(val, ETYPE_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(ETYPE_PRI_CMD);

	return 0;
};

int tc_ethertype_read(u8 index, u16 *type, u8 *tc)
{
	u32 val;

	if (PSE_ETHER_TYPE_PRI_INDEX_MAX < index) {
		/* TODO debug message */
		return -1;
	}

	val = PRI_START_MASK | PRI_CMD_READ_MASK | index;
	wr32(val, ETYPE_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(ETYPE_PRI_CMD);

	*type = val >> 16;
	*tc = (val >> 9) & 0x07;

	return 0;
};


#define PSE_DSCP_PRI_INDEX_MAX (63)
/* tc_dscp - assign traffic class by DSCP.
 *
 * @dscp: 0~63. DSCP value
 * @tc: traffic class
 */
int tc_dscp(u8 dscp_index, u8 tc)
{
	u32 val;

	if (PSE_DSCP_PRI_INDEX_MAX < dscp_index) {
		/* TODO debug message */
		return -1;
	}

	if (OPV5XC_PSE_NR_TC <= tc) {
		/* TODO debug message */
		return -1;
	}

	val = PRI_START_MASK | PRI_CMD_WRITE_MASK
		| (tc << 9) | dscp_index;

	wr32(val, DSCP_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(DSCP_PRI_CMD);

	return 0;
};

int tc_dscp_read(u8 dscp_index, u8 *tc)
{
	u32 val;

	if (PSE_DSCP_PRI_INDEX_MAX < dscp_index) {
		/* TODO debug message */
		return -1;
	}

	val = PRI_START_MASK | PRI_CMD_READ_MASK
		| dscp_index;

	wr32(val, DSCP_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(DSCP_PRI_CMD);

	*tc = (val >> 9) & 0x07;
	return 0;
};

#define PSE_L4_PORT_PRI_INDEX_MAX (3)
/*
 * tc_l4_port - assign traffic class by layer 4 port range.
 *
 * @index: 0~3. PSE support 4 port range.
 * @start: start of L4 port.
 * @end: end of L4 port.
 * @tc: traffic class
 */
static int tc_l4_port(u8 index, u16 start, u16 end, u8 tc, bool tcp)
{
	u32 val;

	if (PSE_L4_PORT_PRI_INDEX_MAX < index) {
		/* TODO debug message */
		return -1;
	}

	val = (start << 16) | end;
	wr32(val, L4_PORT_RANGE);

	val = PRI_START_MASK | PRI_CMD_WRITE_MASK
		| (tc << 9)
		| (tcp << 7)
		| index;

	wr32(val, L4_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(L4_PRI_CMD);

	return 0;
};

static int tc_l4_port_read(u8 index, u16 *start, u16 *end, u8 *tc, bool tcp)
{
	u32 val;

	if (PSE_L4_PORT_PRI_INDEX_MAX < index) {
		/* TODO debug message */
		return -1;
	}

	val = PRI_START_MASK | PRI_CMD_READ_MASK
		| (tcp << 7)
		| index;

	wr32(val, L4_PRI_CMD);

	while (val & PRI_START_MASK)
		val = rd32(L4_PRI_CMD);

	*tc = (val >> 9) & 0x0f;
	val = rd32(L4_PORT_RANGE);
	*start = (val >> 16);
	*end = val;
	return 0;
};

/* tc_tcp_port - assign traffic class by TCP port range.
 *
 * @index: 0~3. PSE support 4 port range.
 * @start: start of L4 port.
 * @end: end of L4 port.
 * @tc: traffic class
 */
int tc_tcp_port(u8 index, u16 start, u16 end, u8 tc)
{
	return tc_l4_port(index, start, end, tc, true);
};

int tc_tcp_port_read(u8 index, u16 *start, u16 *end, u8 *tc)
{
	return tc_l4_port_read(index, start, end, tc, true);
};

/* tc_udp_port - assign traffic class by UDP port range.
 *
 * @index: 0~3. PSE support 4 port range.
 * @start: start of L4 port.
 * @end: end of L4 port.
 * @tc: traffic class
 */
int tc_udp_port(u8 index, u16 start, u16 end, u8 tc)
{
	return tc_l4_port(index, start, end, tc, false);
};

int tc_udp_port_read(u8 index, u16 *start, u16 *end, u8 *tc)
{
	return tc_l4_port_read(index, start, end, tc, false);
};
