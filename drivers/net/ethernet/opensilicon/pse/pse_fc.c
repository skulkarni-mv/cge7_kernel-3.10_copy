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

/* fc_th_write - configure flow control threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_write(u16 set, u16 release)
{
	u32 val;

	val = (set << 16) | release;

	wr32(val, FC_TH);

	return 0;
};

/* fc_th_read - configure flow control threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_read(u16 *set, u16 *release)
{
	u32 val;

	val = rd32(FC_TH);

	*set = (u16) ((val >> 16) & 0x7FF);
	*release = (u16) (val & 0x7FF);

	return 0;
};

/* fc_drop_th_write - configure flow control drop threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_drop_write(u16 set, u16 release)
{
	u32 val;

	val = (set << 16) | release;
	wr32(val, FC_DROP_TH);


	return 0;
};

/* fc_drop_th_read - read flow control drop threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_drop_read(u16 *set, u16 *release)
{
	u32 val;

	val = rd32(FC_DROP_TH);

	*set = (u16)((val >> 16) & 0x7FF);
	*release = (u16)(val & 0x7FF);

	return 0;
};

/* fc_th_all_drop - configure flow control all drop threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_all_drop_write(u16 set, u16 release)
{
	u32 val;

	val = (set << 16) | release;

	wr32(val, FC_ALL_DROP_TH);
	return 0;
};

/* fc_th_all_drop_read - read flow control all drop threshold.
 *
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_all_drop_read(u16 *set, u16 *release)
{
	u32 val;

	val = rd32(FC_ALL_DROP_TH);

	*set = (u16)((val >> 16) & 0x7FF);
	*release = (u16)(val & 0x7FF);

	return 0;
};


/* fc_th_input_write - configure flow control inupt threshold.
 *
 * @port: port
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_input_write(u8 port, u16 set, u16 release)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	val = (set << 16) | release;

	wr32(val, FC_INPUT_TH);

	val = CMD_START_MASK | CMD_WRITE_MASK
		| port;

	wr32(val, FC_INPUT_CMD);

	while (val & CMD_START_MASK)
		val = rd32(FC_INPUT_CMD);

	return 0;
};

/* fc_th_input_read - read flow control inupt threshold.
 *
 * @port: port
 * @set: set threshold.
 * @release: release threshold.
 */
int fc_th_input_read(u8 port, u16 *set, u16 *release)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	val = CMD_START_MASK | CMD_READ_MASK | port;

	wr32(val, FC_INPUT_CMD);

	while (val & CMD_START_MASK)
		val = rd32(FC_INPUT_CMD);

	val = rd32(FC_INPUT_TH);
	*set = (u16)((val >> 16) & 0x7FF);
	*release = (u16)(val & 0x7FF);

	return 0;
};
