/*
 * APM86xxx SlimPRO IPv4 Forward Offload cDriver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Loc Ho <lho@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This module configures the SlimPRO to handle IPv4 forward offload with
 * packet from APM86xxx SoC Ethernet ports.
 *
 */
#include <asm/apm_slimpro_offload.h>
#include "apm_enet_access.h"

#ifdef CONFIG_APM_ENET_SLIMPRO_IPFW

#define SLIMPRO_IPFWID			"SlimPRO IPFW: "

static int apm_enet_slimpro_ipfw_cle_deinit(struct apm_enet_dev_base *priv);
static int apm_enet_slimpro_ipfw_cle_init(struct apm_enet_dev_base *priv);

int apm_enet_slimpro_ipfw_init(struct apm_enet_dev_base *priv)
{
	struct slimpro_ipfw_ctx *ctx = &priv->slimpro_ipfw;

	ctx->enable = 0;
	apm_enet_slimpro_ipfw_enable(priv, 1);

	printk(KERN_INFO "APM86xxx Ethernet SlimPRO IP forward initialized\n");
	return 0;
}

static int apm_enet_slimpro_ipfw_send_ipaddr(struct apm_enet_dev_base *priv)
{
	struct slimpro_ipfw_ctx *ctx = &priv->slimpro_ipfw;
	u32 dat[2];
	int rc;

	dat[0] = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_NET_OFFLOAD_TYPE,
					IPP_NATOFFLOAD_IP4ADDR, 0, 0);
	dat[1] = ctx->ipfw_ipaddr;
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, dat, sizeof(dat), NULL);
	if (rc) {
		printk(KERN_ERR SLIMPRO_IPFWID "Fail to send IP Address\n");
		return rc;
	}
	return rc;
}

int apm_enet_slimpro_ipfw_set_ipaddr(struct apm_enet_dev_base *priv,
				u32 ipaddr)
{
	struct slimpro_ipfw_ctx *ctx = &priv->slimpro_ipfw;

	apm_enet_slimpro_ipfw_cle_deinit(priv);
	ctx->ipfw_ipaddr = ipaddr;
	apm_enet_slimpro_ipfw_send_ipaddr(priv);
	apm_enet_slimpro_ipfw_cle_init(priv);
	return 0;
}

static int apm_enet_slimpro_ipfw_send_mac(struct apm_enet_dev_base *priv)
{
	struct slimpro_ipfw_ctx *ctx = &priv->slimpro_ipfw;
	int rc;
	struct ipp_net_offload_mac *mac = kzalloc(sizeof(struct ipp_net_offload_mac), GFP_ATOMIC);

	mac->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_NET_OFFLOAD_TYPE,
					IPP_NATOFFLOAD_IP4MAC, 0, 0);
	memcpy(mac->addr, ctx->ipfw_mac, ETH_ALEN);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, mac, sizeof(*mac), NULL);
	if (rc) {
		printk(KERN_ERR SLIMPRO_IPFWID "Fail to send MAC Address\n");
		return rc;
	}
	return rc;
}

int apm_enet_slimpro_ipfw_set_mac(struct apm_enet_dev_base *priv, u8 *mac)
{
	struct slimpro_ipfw_ctx *ctx = &priv->slimpro_ipfw;

	apm_enet_slimpro_ipfw_cle_deinit(priv);
	memcpy(ctx->ipfw_mac, mac, 6);
	apm_enet_slimpro_ipfw_send_mac(priv);
	apm_enet_slimpro_ipfw_cle_init(priv);
	return 0;
}

static int apm_enet_slimpro_ipfw_cle_init(struct apm_enet_dev_base *priv)
{
	/* FIXME */
	return 0;
}

static int apm_enet_slimpro_ipfw_cle_deinit(struct apm_enet_dev_base *priv)
{
	/* FIXME */
	return 0;
}

int apm_enet_slimpro_ipfw_enable(struct apm_enet_dev_base *priv, u32 enable)
{
	/* Enable or disable IPFW */
	if (priv->slimpro_ipfw.enable == enable)
		return 0;
	priv->slimpro_ipfw.enable = enable;
	if (enable) {
		/* Query for MAC address */
		/* FIXME - if mac available, then do this */

		/* Configure the classifier */
		apm_enet_slimpro_ipfw_send_ipaddr(priv);
		apm_enet_slimpro_ipfw_send_mac(priv);
		apm_enet_slimpro_ipfw_cle_init(priv);
	} else {
		apm_enet_slimpro_ipfw_cle_deinit(priv);
	}
	return 0;
}
#endif
