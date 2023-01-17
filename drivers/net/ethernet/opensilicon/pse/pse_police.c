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


int police_port_en_write(u8 port, bool enable)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	val = rd32(POLICE_CFG);

	if (enable)
		val |= (0x1 << port);
	else
		val &= ~(0x1 << port);

	wr32(val, POLICE_CFG);

	return 0;
};

bool police_port_en_read(u8 port)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return false;

	val = rd32(POLICE_CFG);
	return val & (0x01 << port) ? true : false;
}

int police_psudo_rand_generator_write(bool enable)
{
	u32 val;

	val = rd32(POLICE_CFG);

	if (enable)
		val |= (0x1 << 6);
	else
		val &= ~(0x1 << 6);

	wr32(val, POLICE_CFG);

	return 0;
};

bool police_psudo_rand_generator_read(void)
{
	u32 val;

	val = rd32(POLICE_CFG);

	return val & (0x01 << 6) ? true : false;

};

int police_global_min_th_write(u16 th)
{
	u32 val;

	val = rd32(POLICE_CFG);

	val &= ~(0xfff << 16);
	val |= (th << 16);

	wr32(val, POLICE_CFG);

	return 0;
};

u16 police_global_min_th_read(void)
{
	u32 val;

	val = rd32(POLICE_CFG);
	return (u16)(val >> 16);

};

#define CMD_READ() \
{ \
	val = CMD_START_MASK | CMD_READ_MASK | (port); \
	wr32(val, POLICE_CMD); \
	while (val & CMD_START_MASK) \
		val = rd32(POLICE_CMD); \
};

int police_dst_port_write(u8 port, u16 queue_en, u16 max, u16 min,
			u16 probability, u16 weight, u16 min_oq)
{
	u32 val;
	u32 police_cmd;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	CMD_READ();
	police_cmd = val;

	val = (max << 16) | min;
	wr32(val, POLICER_RED_TH);

	val = (probability << 16) | weight;
	wr32(val, POLICER_RED_FACTOR);

	val = min_oq << 16;
	wr32(val, POLICE_OQUE_TH);

	val = police_cmd;

	/* recalculate POLICE_INVERSE */
	val &= ~(0x0FFF0000);
	val |= (u16)(4096 / (max - min)) << 16;


	val &= ~(0x00000FF0);
	val |= queue_en << 4;

	val |= CMD_START_MASK | CMD_WRITE_MASK;
	wr32(val, POLICE_CMD);

	while (val & CMD_START_MASK)
		val = rd32(POLICE_CMD);

	return 0;
};

int police_dst_port_read(u8 port, u16 *queue_en, u16 *inverse,
			 u16 *max, u16 *min,
			 u16 *probability, u16 *weight, u16 *min_oq)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	CMD_READ();

	*queue_en = (u16)((val >> 4) & 0xff);
	*inverse = (u16)(val >> 16);

	*max = (u16)((rd32(POLICER_RED_TH) >> 16) & 0x7FF);
	*min = (u16)(rd32(POLICER_RED_TH) & 0x7FF);

	*probability = (u16)((rd32(POLICER_RED_FACTOR) >> 16) & 0xFFF);
	*weight = (u16)(rd32(POLICER_RED_FACTOR) & 0xFFF);

	*min_oq = (u16)(rd32(POLICE_OQUE_TH) >> 16 & 0x7FF);

	return 0;
};
