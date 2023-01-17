/**
 * AppliedMicro APM86xxx SoC Ethernet Offload Driver Interface Header
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
 * @file apm_enet_offload.h
 *
 * This file defines offload functions for APM86xxx SoC Ethernet subsystem
 *
 **
 */

#ifndef __APM_ENET_OFFLOAD_H__
#define __APM_ENET_OFFLOAD_H__

#include "apm_enet_access.h"
#ifdef CONFIG_APM_ENET_INO
#include "apm_cle_ino.h"
#endif

#define INVALID_16BIT_INDEX 0xFFFF
#define INVALID_32BIT_INDEX 0xFFFFFFFF
#define INVALID_LIST_HEAD(h) (!((h)->next && (h)->prev))

/* Offload Ingress & Egress Port Number Key */
#define OFFLOAD_IPN(i) (0x49504E30 | (i))
#define OFFLOAD_EPN(e) (0x45504E30 | (e))
#define OFFLOAD_KEY_SIZE 3

#define APM_RC_MISS 1

#define apm_cle_lock(flags) spin_lock_irqsave(&apm_ethoffload_ops.cle_lock, flags)
#define apm_cle_unlock(flags) spin_unlock_irqrestore(&apm_ethoffload_ops.cle_lock, flags)

/* Define Common macro for IPv4 Forward Offload, IPv4 NAT Offload, etc.*/
#if defined(CONFIG_CLE_BRIDGE) || \
	defined(CONFIG_APM_IPV4_OFFLOAD) || \
	defined(CONFIG_APM_QOS)

#define CONFIG_APM_ENET_OFFLOAD

enum apm_enet_offload_type {
	APM_BRIDGE_OFFLOAD = 0,
	APM_IPV4FWD_OFFLOAD,
	APM_IPV4NAT_OFFLOAD,
	APM_QOS_SUPPORT,
};
#endif

#ifdef CONFIG_APM_IPV4_OFFLOAD
enum apm_ipv4nat_offload_type {
	APM_IPV4NAT_OFFLOAD_SNAT = 0,
	APM_IPV4NAT_OFFLOAD_DNAT,
	APM_IPV4NAT_OFFLOAD_SNAT_IP,
	APM_IPV4NAT_OFFLOAD_DNAT_IP,
	APM_IPV4NAT_OFFLOAD_MAX,
};

#define APM_IPV4NAT_OFFLOAD_XNAT_MASK 0x1
#define APM_IPV4NAT_OFFLOAD_XNAT_IP_MASK 0x2

struct apm_ipv4fwd_info {
	struct list_head rt_head;
	u8  rt_mac[8];
	u8  rt_mac_cle[2][8];
	u32 eport;
	union {
		u32 iport;
		u16 iport_cle[2];
	};
	union {
		u32 ref_count;
		u16 ref_count_cle[2];
	};
} __attribute__ ((packed));

struct apm_ipv4rth_info {
	u32 eport;
	u32 iport;
	u32 ref_count;
} __attribute__ ((packed));

#ifdef CONFIG_APM_ENET_INO
struct apm_ipv4nat_info {
	__be32 src_ip;
	__be32 dst_ip;
	__be16 src_l4;
	__be16 dst_l4;
	__be32 rt_gateway;
	u8 rt_mac[8];
	u32 eport;
	u32 iport;
	u32 avl_index;
	u32 dbptr_index;
	__be32 nf_l3;
	__be16 nf_l4;
	enum apm_ipv4nat_offload_type type;
	enum ip_conntrack_dir dir;
} __attribute__ ((packed));
#endif
#endif

struct apm_enet_offload_list {
        struct list_head node;
	u32 key[OFFLOAD_KEY_SIZE];
	union {
		u32 index;
		u16 index_cle[2];
	};
	union {
		void *tail;
#ifdef CONFIG_APM_IPV4_OFFLOAD
		struct apm_ipv4fwd_info *ipv4fwd;
		struct apm_ipv4rth_info *ipv4rth;
#ifdef CONFIG_APM_ENET_INO
		struct apm_ipv4nat_info *ipv4nat;
#endif
#endif
	};
} __attribute__ ((packed));

struct apm_index_list {
        struct list_head node;
	u32 index;
};

struct apm_ethoffload_mode {
	char *name;
};

struct apm_ethoffload_driver {
	char *name;
	unsigned int internal_port;
};

enum apm_ethoffload {
	ETHOFFLOAD_DEFAULT = 0,
#ifdef CONFIG_APM_ENET_IFO
	ETHOFFLOAD_IPV4FWD,
#endif
#ifdef CONFIG_APM_ENET_INO
	ETHOFFLOAD_IPV4NAT,
#endif
#ifdef CONFIG_APM_ENET_LRO
	ETHOFFLOAD_IPP_LRO,
#endif
#ifdef CONFIG_APM_ENET_QOS
	/* Set the value ETHSUPPORT_QOS corresponds to the value APM_QOS_SUPPORT at user space */
	ETHSUPPORT_QOS = 4,
#endif
	ETHOFFLOAD_MAX
};

enum apm_ethoffload_interface {
	CLE_EXT_PORT0 = 0,
	CLE_EXT_PORT1,
	CLE_EXT_PORT2,
	CLE_EXT_PORT3,
	CLE_INT_PORT0,
	CLE_INT_PORT1,
#ifndef CONFIG_APM862xx
	CLE_INT_PORT2,
	CLE_INT_PORT3,
#endif
	CLE_MAX_PORTS
};

#define ETH_ANY_PORT(p) (((p) >= CLE_EXT_PORT0) && ((p) < CLE_MAX_PORTS))
#define ETH_EXT_PORT(p) (((p) >= CLE_EXT_PORT0) && ((p) < CLE_INT_PORT0))
#define ETH_INT_PORT(p) (((p) >= CLE_INT_PORT0) && ((p) < CLE_MAX_PORTS))
#define ETH_ANY_PORT_ERR(p) (!ETH_ANY_PORT(p))
#define ETH_EXT_PORT_ERR(p) (!ETH_EXT_PORT(p))
#define ETH_INT_PORT_ERR(p) (!ETH_INT_PORT(p))
#define CLE_INT_PORT(p) ((p) - CLE_INT_PORT0)
#define CID_INT_PORT(p) (PID2CID[CLE_INT_PORT(p)])

extern struct ethoffload_ops apm_ethoffload_ops;

static inline int apm_put_index(struct list_head *head, u32 index)
{
	struct apm_index_list *entry;

	if (INVALID_LIST_HEAD(head))
		return -EINVAL;

	entry = kmalloc(sizeof (struct apm_index_list),
			GFP_KERNEL | __GFP_ZERO);

	if (entry == NULL)
		return -ENOMEM;

	entry->index = index;
	list_add(&entry->node, head);

	return APM_RC_OK;
}

static inline int apm_get_index(struct list_head *head, u32 *index)
{
	struct apm_index_list *entry;

	if (INVALID_LIST_HEAD(head) || list_empty(head))
		return -EINVAL;

	entry = list_first_entry(head, struct apm_index_list, node);

	if (entry == NULL)
		return -EINVAL;

	*index = entry->index;
	list_del(&entry->node);
	kfree(entry);

	return APM_RC_OK;

}

static inline struct apm_enet_offload_list *
	apm_find_enet_offload_entry(struct list_head *head, u32 *key)
{
	struct apm_enet_offload_list *entry;

	list_for_each_entry(entry, head, node) {
		if (memcmp(entry->key, key, sizeof(entry->key)) == 0) {
			return entry;
		}
	}

	return NULL;
}

static inline struct apm_enet_offload_list *
	apm_add_enet_offload_entry(struct list_head *head, u32 *key, u32 tail_size)
{
	struct apm_enet_offload_list *entry;

	if (key == NULL || head == NULL || INVALID_LIST_HEAD(head))
		return NULL;

	entry = kmalloc(sizeof (struct apm_enet_offload_list) + tail_size,
			GFP_KERNEL | __GFP_ZERO);

	if (entry == NULL)
		return NULL;

	memcpy(entry->key, key, sizeof(entry->key));
	entry->index = INVALID_32BIT_INDEX;
	if (tail_size)
		entry->tail = &entry[1];
	list_add(&entry->node, head);

	return entry;
}

static inline void apm_del_enet_offload_entry(struct apm_enet_offload_list *entry)
{
	list_del(&entry->node);
	kfree(entry);
}

#ifdef CONFIG_APM_ENET_OFFLOAD
int apm_enet_offload_set_mac(struct apm_enet_dev_base *priv_dev);
int apm_enet_offload_set_bufdatalen(struct apm_enet_dev_base *priv_dev);
int apm_enet_offload_init(struct apm_enet_dev_base *priv_dev);
#endif

extern struct net_device *offload_ndev[CLE_MAX_PORTS];
int apm_inet_switch(struct apm_enet_dev_base *priv_dev, enum apm_ethoffload offload);
int apm_inet_offload_ndev_is_internal(struct net_device *ndev);
int apm_inet_offload_ndev_to_index(struct net_device *ndev);
int apm_inet_offload_ndev_name_to_index(char *name);
int apm_inet_offload_ifindex_to_index(int ifindex);
#endif /* __APM_ENET_OFFLOAD_H__ */
