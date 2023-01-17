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

#ifndef _PSE_TC_CMD_H_
#define _PSE_TC_CMD_H_


#define PRI_START_MASK		(0x1 << 15)
#define PRI_CMD_READ_MASK	(0x0 << 14)
#define PRI_CMD_WRITE_MASK	(0x1 << 14)

#define PRI_CMD_READ() \
{ \
	val = PRI_START_MASK | PRI_CMD_READ_MASK | (port); \
	wr32(val, PORT_PRI_CMD); \
	while (val & PRI_START_MASK) { \
		val = rd32(PORT_PRI_CMD); \
	} \
};

#define PRI_CMD_WRITE() \
{ \
	val = PRI_START_MASK | PRI_CMD_WRITE_MASK | (port); \
	wr32(val, PORT_PRI_CMD); \
	while (val & PRI_START_MASK) { \
		val = rd32(PORT_PRI_CMD); \
	} \
};


#define tc_cfg_mask_ethertype	(0x1 << 18)
#define tc_cfg_mask_vlan	(0x1 << 19)
#define tc_cfg_mask_dscp	(0x1 << 20)
#define tc_cfg_mask_udp		(0x1 << 21)
#define tc_cfg_mask_tcp		(0x1 << 22)
#define tc_cfg_mask_dmac	(0x1 << 23)
#define tc_cfg_mask_regen_user_pri	(0x1 << 31)

#define TC_CFG_FUNC(type) \
int tc_cfg_##type(u8 port, bool enable)  \
{ \
	u32 val; \
	switch (port) { \
	case OPV5XC_PSE_PORT_MAC0: case OPV5XC_PSE_PORT_MAC1: \
	case OPV5XC_PSE_PORT_CPU: case OPV5XC_PSE_PORT_MAC2: \
		break; \
	default: \
		return -1; \
	} \
	/* read port priority setting */ \
	PRI_CMD_READ(); \
	val = rd32(PORT_PRI_CTRL); \
	if (enable) \
		val |= tc_cfg_mask_##type; \
	else \
		val &= ~tc_cfg_mask_##type; \
	wr32(val, PORT_PRI_CTRL); \
	/* issue write command */ \
	PRI_CMD_WRITE(); \
	return 0; \
};

#endif /* _PSE_TC_CMD_H_ */
