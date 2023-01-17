/**
 * AppliedMicro APM86xxx SoC IPv4 Forward Offload Classifier Driver Header
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Ravi Patel <rapatel@apm.com>
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
 * @file apm_cle_ifo.h
 *
 * This file declares Classifier APIs and macros in use by IPv4 Forward Offload driver.
 *
 */

#include <linux/netdevice.h>

int apm_mkarp_ipv4_forward(struct neighbour *n);
void apm_rmarp_ipv4_forward(struct neighbour *n);
void apm_flarp_ipv4_forward(struct net_device *dev);
int apm_mkroute_ipv4_forward(struct sk_buff *skb, struct rtable *rth);
void apm_rmroute_ipv4_forward(struct rtable *rth);
void apm_flroute_ipv4_forward(struct net_device *dev);
int apm_ipv4fwd_offload_cmd(struct net_device *dev, char *cmdline, int update);
int apm_ipv4fwd_offload_enable(struct net_device *dev);
void apm_ipv4fwd_offload_setqid(u8 iport, u8 offloader_rx_qid);
int apm_ipv4fwd_offload_init(int iport);
