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

/* tx_sch_mode
 *
 * @port: egress port.
 * @mode: 0~7. 0:strict priority, 1~6: mixed, 7:WRR
 *
 * tx_sch_mode support MAC ports, CPU, PPE and CFP port
 */
int tx_sch_mode(u8 port, u8 mode)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	if (7 < mode) {
		/* TODO debug message */
		return -1;
	}

	PRI_CMD_READ();

	val = rd32(PORT_PRI_CTRL);
	val &= ~(0x7 << 15);
	val |= (mode << 15);
	wr32(val, PORT_PRI_CTRL);

	PRI_CMD_WRITE();

	return 0;
};

/* tx_sch_min_bw
 *
 * @port: egress port.
 * @bw: 0~10. bandwidth is (64kbps * 2^bw)
 *
 * tx_sch_min_bw support MAC ports, CPU, PPE and CFP port
 */
int tx_sch_min_bw(u8 port, u8 bw)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	if (10 < bw) {
		/* TODO debug message */
		return -1;
	}

	PRI_CMD_READ();

	val = rd32(PORT_PRI_CTRL);
	val &= ~(0xf << 11);
	val |= (bw << 11);
	wr32(val, PORT_PRI_CTRL);

	PRI_CMD_WRITE();

	return 0;
};

/* tx_sch_weight
 *
 * @port: egress port.
 * @tc: traffic class
 * @weight: 0~4. weight is (2^weight)
 *
 * tx_sch_weight support MAC ports, CPU, PPE and CFP port
 */
int tx_sch_weight(u8 port, u8 tc, u8 weight)
{
	u32 val, offset;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	if (OPV5XC_PSE_NR_TC <= tc) {
		/* TODO debug message */
		return -1;
	}

	if (4 < weight) {
		/* TODO debug message */
		return -1;
	}

	offset = ((7 - tc) << 2);
	PRI_CMD_READ();

	val = rd32(PORT_PRI_WEIGHT);
	val &= ~(0x7 << offset);
	val |= (weight << offset);
	wr32(val, PORT_PRI_WEIGHT);

	PRI_CMD_WRITE();

	return 0;
};
