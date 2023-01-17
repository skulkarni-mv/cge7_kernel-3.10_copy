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

extern struct net_device *net_dev_array[PSE_MAX_DEV_NUM];

/* FIXME */
static struct net_device *get_dev(struct pse_fs_desc *desc, struct pse_ring *ring)
{
	switch (desc->sp) {
	case OPV5XC_PSE_PORT_MAC0:
	case OPV5XC_PSE_PORT_MAC1:
		return net_dev_array[desc->sp];
	case OPV5XC_PSE_PORT_MAC2:
		return net_dev_array[2];
	default:
		break;
	}

	return NULL;
}

static bool pse_support_ip_chksum(int prot)
{
	return  (prot == 0) ||
		(prot == 1) ||
		(prot == 2) ||
		(prot == 3);
}

static bool pse_support_l4_chksum(int prot)
{
	return  (prot == 1) ||
		(prot == 2) ||
		(prot == 5) ||
		(prot == 6) ||
		(prot == 13) ||
		(prot == 14);
}

bool pse_hw_checksum_valid(struct pse_fs_desc *desc, struct sk_buff *skb)
{
	bool ip_chksum_valid = false;
	bool l4_chksum_valid = false;

	if (pse_support_ip_chksum(desc->prot) && !desc->ipf)
		ip_chksum_valid = true;

	if (pse_support_l4_chksum(desc->prot) && !desc->l4f)
		l4_chksum_valid = true;

	if (ip_chksum_valid && l4_chksum_valid)
		return true;

	return false;
}
EXPORT_SYMBOL(pse_hw_checksum_valid);

int pse_pre_process(struct sk_buff *skb, struct pse_fs_desc *desc, struct pse_ring *ring)
{
	struct net_device *dev;

	dev = get_dev(desc, ring);

	if (NULL == dev)
		goto error;

	skb->protocol = eth_type_trans(skb, dev);

	skb->ip_summed = CHECKSUM_NONE;

	if ((dev->features & NETIF_F_RXCSUM) &&
	    pse_hw_checksum_valid(desc, skb))
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	return 0;
error:
	dev_kfree_skb_any(skb);
	return -1;
}
