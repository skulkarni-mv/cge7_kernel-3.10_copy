/**
 * AppliedMicro APM86xxx SoC IPv4 NAT Offload Classifier Driver Header
 *
 * Copyright (c) 2012 Applied Micro Circuits Corporation.
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
 * @file apm_cle_ino.h
 *
 * This file declares Classifier APIs and macros in use by IPv4 NAT Offload driver.
 *
 */

#include <linux/netdevice.h>
#include <net/netfilter/nf_nat.h>

int apm_mkarp_ipv4_nat(struct neighbour *n);
void apm_rmarp_ipv4_nat(struct neighbour *n);
void apm_flarp_ipv4_nat(struct net_device *dev);
int apm_mkroute_ipv4_nat(struct sk_buff *skb, struct rtable *rth);
void apm_rmroute_ipv4_nat(struct rtable *rth);
void apm_flroute_ipv4_nat(struct net_device *dev);
int apm_mknat_ipv4_nat(struct nf_conn *ct);
void apm_rmnat_ipv4_nat(struct nf_conn *ct);
int apm_ipv4nat_offload_cmd(struct net_device *dev, char *cmdline, int update);
int apm_ipv4nat_offload_enable(struct net_device *dev);
void apm_ipv4nat_offload_setqid(u8 iport, u8 offloader_rx_qid);
