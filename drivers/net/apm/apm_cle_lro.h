/**
 * AppliedMicro APM86xxx SoC LRO Classifier Driver Header
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
 * @file apm_cle_lro.h
 *
 * This file declares Classifier APIs and macros in use by LRO Ethernet driver.
 *
 */

#include "apm_enet_access.h"

#define MASK_LRO_ENET_PORT 0xFF
#define LRO_DBPTR_PER_CONN 12

int apm_mktcp_connection(struct sock *sk);
int apm_rmtcp_connection(struct sock *sk);
int apm_ipp_lro_offload_cmd(struct net_device *dev, char *cmdline, int update);
int apm_ipp_lro_offload_enable(struct net_device *dev);
