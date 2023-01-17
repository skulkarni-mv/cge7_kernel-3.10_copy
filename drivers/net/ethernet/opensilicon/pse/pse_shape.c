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


#define PSE_SHAPE_BASE_MAX	2
#define PSE_SHAPE_BW_MAX	127
#define PSE_SHAPE_QUEUE_MAX	(OPV5XC_PSE_NR_TC - 1)
#define PSE_SHAPE_BUCK_SEL_MAX	16

#define RECOMMAND_BUCKET_SIZE	1600
#define RECOMMAND_BUCKET_SIZE_JUMBO_FRAME (10*1024)

/* FOR ES2,
   bucket size affect
   1. scheduler when port shape
   2. packet easy to drop in high priority queue (RED)

   We need to adjust BUCKET SIZE according to tx bandwidth,
   suggest bucket size = 1.6K bytes, if normal packets
   suggest bucket size = 10K bytes, if jumbo frame

   bucket_size = (bw * base_rate) / 8 / 2^N

   ex :
	shape at 200Mbps
	bucket size  = 200Mbps / 8 / 2^N, need >= 1.6k Bytes

	N = 13, bucket size = 3.2K bytes
	N = 14, bucket size = 1.6K bytes
	choose N = 14
*/

int get_bucket_size(u8 port, u8 base, u8 bw)
{
	u32 tx_bw = 0;
	u8 i = 0;
	u32 recommand_bucket_size;

	if (bw == 0) /* disable SHAPE*/
		return 3; /* return default value */

	switch (base) {
	case 0:
		/* 64 kbps */
		tx_bw = bw * 64 * 1024;
		break;
	case 1:
		/* 1 Mbps */
		tx_bw = bw * 1 * 1024 * 1024;
		break;
	case 2:
		/* 10 Mbps */
		tx_bw = bw * 10 * 1024 * 1024;
		break;
	}

	tx_bw = tx_bw >> 3; /* bit per second -> Byte per second */

	if (((rd32(PHY_AUTO_ADDR) >> (26 + 2*port)) & 0x03) == 3) {
		/* jumbo frame */
		recommand_bucket_size = RECOMMAND_BUCKET_SIZE_JUMBO_FRAME;
	} else {
		recommand_bucket_size = RECOMMAND_BUCKET_SIZE;
	}

	for (i = 0; i <= PSE_SHAPE_BUCK_SEL_MAX; i++) {
		if ((tx_bw >> i) < recommand_bucket_size) {
			i = i - 1;
			break;
		}
		if (i == PSE_SHAPE_BUCK_SEL_MAX)
			break;
	}

	return i;
}

/* shape_port_write - configure shape function on MAC port.
 *
 * @port: MAC port. MAC port 0 or MAC port 1
 * @base: base rate.  64 kbps, 1 Mbps, 10 Mbps.
 * @bw: bandwidth. 0: disable. 1~127: bandwith is (base*bw)
 * @bucket_size : 0~16
 */
int shape_port_write(u8 port, u8 base, u8 bw, u8 bucket_size)
{
	u32 val, offset_bw, offset_base;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		offset_bw = 8;
		offset_base = 0;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		offset_bw = 16;
		offset_base = 2;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		offset_bw = 24;
		offset_base = 4;
		break;
	default:
		/* TODO debug message */
		return -1;
	}

	if (PSE_SHAPE_BASE_MAX < base)
		return -1;

	if (PSE_SHAPE_BW_MAX < bw)
		return -1;

	val = rd32(PORT_SHAPE_CFG);
	val &= ~(0x7F << offset_bw);
	val &= ~(0x3 << offset_base);
	val |= (bw << offset_bw);
	val |= (base << offset_base);
	wr32(val, PORT_SHAPE_CFG);

	shape_bucket_size_write(port, bucket_size);

	return 0;
};

/* shape_port_read - read shape function on MAC port.
 *
 * @port: MAC port. MAC port 0 or MAC port 1
 * @base: address to store base rate.
 * @bw: address to store bandwidth.
 * @bucket_size
 */
int shape_port_read(u8 port, u8 *base, u8 *bw, u8 *bucket_size)
{
	u32 val, offset_bw, offset_base;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		offset_bw = 8;
		offset_base = 0;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		offset_bw = 16;
		offset_base = 2;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		offset_bw = 24;
		offset_base = 4;
		break;
	default:
		/* TODO debug message */
		return -1;
	}

	val = rd32(PORT_SHAPE_CFG);

	*base = (u8)((val >> offset_base) & 0x03);
	*bw = (u8)((val >> offset_bw) & 0x7F);

	shape_bucket_size_read(port, bucket_size);
	return 0;
};

/* shape_queue_write - configure shape function on MAC port.
 *
 * @port: shape port. MAC port 0, MAC port 1, CPU, PPE or CFP port.
 * @queue: queue number
 * @base: base rate.  64 kbps, 1 Mbps, 10 Mbps.
 * @bw: bandwidth. 1~127
 */
int shape_queue_write(u8 port, u8 queue, u8 base, u8 bw, u8 bucket_size)
{
	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	if (PSE_SHAPE_QUEUE_MAX < queue)
		return -1;

	if (PSE_SHAPE_BASE_MAX < base)
		return -1;

	if (PSE_SHAPE_BW_MAX < bw)
		return -1;

	if (PSE_SHAPE_BUCK_SEL_MAX < bucket_size)
		return -1;

	val = (bw << 18) | (base << 16) | (bucket_size << 7)
		| (CMD_START_MASK) | (CMD_WRITE_MASK)
		| (queue << 4)
		| port;


	wr32(val, QUEUE_SHAPE_CMD);

	while (val & CMD_START_MASK)
		val = rd32(QUEUE_SHAPE_CMD);


	return 0;
};

/* shape_queue_read - read shape function on MAC port.
 *
 * @port: shape port. MAC port 0, MAC port 1, CPU, PPE or CFP port.
 * @queue: queue number
 * @base: address to store base rate.
 * @bw: address to store bandwidth.
 */
int shape_queue_read(u8 port, u8 queue, u8 *base, u8 *bw, u8 *bucket_size)
{

	u32 val;

	if (OPV5XC_PSE_PORT_CFP < port)
		return -1;

	if (PSE_SHAPE_QUEUE_MAX < queue)
		return -1;

	val =  (CMD_START_MASK)
		| (CMD_READ_MASK)
		| (queue << 4)
		| port;

	wr32(val, QUEUE_SHAPE_CMD);

	while (val & CMD_START_MASK)
		val = rd32(QUEUE_SHAPE_CMD);

	*base = (u8)((val >> 16) & 0x03);
	*bw = (u8)((val >> 18) & 0x7F);
	*bucket_size = (u8)((val >> 7) & 0x1F);
	return 0;
};


/* shape_bucket_size_write - set shape bucket size on MAC port.
 *
 * @port: shape port. MAC port 0, MAC port 1, MAC port 2
 * @size:
 */
int shape_bucket_size_write(u8 port, u8 size)
{
	u32 val;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		break;
	case OPV5XC_PSE_PORT_MAC1:
		break;
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		/* TODO debug message */
		return -1;
	}
	if (size > 16) {
		/* TODO debug message */
		return -1;
	}

	val = rd32(PRIO_BUCKET_SIZE);
	val &= ~(0x1f << (port*5));
	val |= size << (port*5);

	wr32(val, PRIO_BUCKET_SIZE);
	return 0;
};

/* shape_bucket_size_read - read shape bucket size on MAC port.
 *
 * @port: shape port. MAC port 0, MAC port 1, MAC port 2
 * @size:
 */
int shape_bucket_size_read(u8 port, u8 *size)
{
	u32 val;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		break;
	case OPV5XC_PSE_PORT_MAC1:
		break;
	case OPV5XC_PSE_PORT_MAC2:
		break;
	default:
		/* TODO debug message */
		return -1;
	}

	val = rd32(PRIO_BUCKET_SIZE);
	*size = (u8)((val >> (port*5)) & 0x1f);

	return 0;
};

/* shape_two_bucket_size_write - choose one or two bucket size
 *
 * @size: 0 : One bucket size
 *        1 : Two bucket size
 */
int shape_two_bucket_size_write(u8 size)
{
	u32 val;

	if (size != 0)
		size = 1;

	val = rd32(MAC_GLOB_EXT);
	val &= ~(1 << 5);
	val |= size << 5;

	wr32(val, MAC_GLOB_EXT);
	return 0;
};

/* shape_two_bucket_size_read
 *
 * @size: 0 : One bucket size
 *        1 : Two bucket size
 */
int shape_two_bucket_size_read(u8 *size)
{
	u32 val;

	val = rd32(MAC_GLOB_EXT);
	*size = (val & 0x20) ? 1 : 0;

	return 0;
};
