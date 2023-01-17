/**
 * AppliedMicro APM86xxx SoC Ethernet Offload Driver Interface
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
 * @file apm_enet_offload.c
 *
 * Offload functions for APM86xxx SOC Ethernet Subsystem
 *
 **
 */

#include <net/ip.h>
#include <asm/apm_slimpro_offload.h>
#include "apm_enet_offload.h"
#include "apm_cle_mgr.h"
#ifdef CONFIG_CLE_BRIDGE
#include "apm_cle_bridge.h"
#endif
#ifdef CONFIG_APM_ENET_IFO
#include "apm_cle_ifo.h"
#endif
#ifdef CONFIG_APM_ENET_INO
#include "apm_cle_ino.h"
#endif
#ifdef CONFIG_APM_ENET_LRO
#include "apm_cle_lro.h"
#endif
#ifdef CONFIG_APM_ENET_QOS
#include "apm_cle_qos.h"
#endif
#include <linux/module.h>

#define NETOFFLOADID			"Net Offload: "

/* Pointer to APM & non-APM Ethernet net_device structure for offload */
struct net_device *offload_ndev[CLE_MAX_PORTS];

static unsigned char skb_enq_index;
static unsigned char skb_dq_index;
static struct sk_buff *skb_q[1 << (sizeof(unsigned char) * BITS_PER_BYTE)];

static struct apm_ethoffload_mode apm_ethoffload_mode[ETHOFFLOAD_MAX] = {
	[ETHOFFLOAD_DEFAULT]		= { CLE_PTREE_DEFAULT },
#ifdef CONFIG_APM_ENET_IFO
	[ETHOFFLOAD_IPV4FWD]		= { CLE_PTREE_IPV4FWD },
#endif
#ifdef CONFIG_APM_ENET_INO
	[ETHOFFLOAD_IPV4NAT]		= { CLE_PTREE_IPV4NAT },
#endif
#ifdef CONFIG_APM_ENET_LRO
	[ETHOFFLOAD_IPP_LRO]		= { CLE_PTREE_IPP_LRO },
#endif
#ifdef CONFIG_APM_ENET_QOS
	[ETHSUPPORT_QOS]                = { CLE_PTREE_QOS },
#endif
};

#define SUPPORT_EXTERNAL_INTERFACES

static struct apm_ethoffload_driver apm_ethoffload_driver[CLE_MAX_PORTS] = {
	[0] = { APM86XXX_ENET_DRIVER_NAME, 1 },
#ifdef SUPPORT_EXTERNAL_INTERFACES
	[1] = { "e1000e", 0 },
	[2] = { "ath_pci", 0 },
#endif
};

static void apm_ethoffload_usage(void)
{
	printk("\nUsage: To Disable Offload method, run following command\n");
	printk("echo %s > offload\n", CLE_PTREE_DEFAULT);
#ifdef CONFIG_APM_ENET_IFO
	printk("\nUsage: To Enable IPv4 Forward Offload method, run following command\n");
	printk("echo %s > offload\n", CLE_PTREE_IPV4FWD);
	printk("\nUsage: To Add IPv4 Forward Offload entry, run following command\n");
	printk("echo %s add <src ip> <dst ip> <gwy ip> <out interface>"
			" > offload\n", CLE_PTREE_IPV4FWD);
	printk("\nUsage: To Delete IPv4 Forward Offload entry, run following command\n");
	printk("echo %s del <src ip> <dst ip> <gwy ip> <out interface>"
			" > offload\n", CLE_PTREE_IPV4FWD);
	printk("\nUsage: To Show IPv4 Forward Offload route entries, run following command\n");
	printk("echo %s show route [out interface] > offload\n",
			CLE_PTREE_IPV4FWD);
	printk("\nUsage: To Show IPv4 Forward Offload arp entries, run following command\n");
	printk("echo %s show arp [out interface] > offload\n",
			CLE_PTREE_IPV4FWD);
#endif
#ifdef CONFIG_APM_ENET_INO
	printk("\nUsage: To Enable IPv4 NAT Offload method, run following command\n");
	printk("echo %s > offload\n", CLE_PTREE_IPV4NAT);
	printk("\nUsage: To Add IPv4 NAT Offload entry, run following command\n");
	printk("echo %s add <snat | dnat | snat_ip | dnat_ip> <src ip> <dst ip> <src l4> <dst l4> "
			"<reply src ip> <reply dst ip> <reply src l4> <reply dst l4>"
			" > offload\n", CLE_PTREE_IPV4NAT);
	printk("\nUsage: To Delete IPv4 NAT Offload entry, run following command\n");
	printk("echo %s del <snat | dnat | snat_ip | dnat_ip> <src ip> <dst ip> <src l4> <dst l4> "
			"<reply src ip> <reply dst ip> <reply src l4> <reply dst l4>"
			" > offload\n", CLE_PTREE_IPV4NAT);
	printk("\nUsage: To Show IPv4 NAT Offload route entries, run following command\n");
	printk("echo %s show route [out interface] > offload\n",
			CLE_PTREE_IPV4NAT);
	printk("\nUsage: To Show IPv4 NAT Offload arp entries, run following command\n");
	printk("echo %s show arp [out interface] > offload\n",
			CLE_PTREE_IPV4NAT);
	printk("\nUsage: To Show IPv4 NAT Offload nat entries, run following command\n");
	printk("echo %s show nat > offload\n",
			CLE_PTREE_IPV4NAT);
	printk("\nNotes: src l4 is 16bit source port & dst l4 is 16bit destination port for TCP, UDP, DCCP, SCTP proto\n"
			"       src l4 is 16 bit ICMP ID for ICMP proto, dst l4 will be ignored\n"
			"       src l4 is 16 bit Key for GRE proto, dst l4 will be ignored\n"
	);
#endif
#ifdef CONFIG_APM_ENET_LRO
	printk("\nUsage: To Enable IPP LRO method, run following command\n");
	printk("echo %s > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Add IPP LRO route, run following command\n");
	printk("echo %s add route <src ip> <dst ip> <src port> <dst port>"
			" > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Add IPP LRO entry, run following command\n");
	printk("echo %s add entry <src ip> <dst ip> <src port> <dst port>"
			" > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Delete IPP LRO route, run following command\n");
	printk("echo %s del route <src ip> <dst ip> <src port> <dst port>"
			" > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Delete IPP LRO entry, run following command\n");
	printk("echo %s del entry <src ip> <dst ip> <src port> <dst port>"
			" > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Show IPP LRO routes, run following command\n");
	printk("echo %s show route > offload\n", CLE_PTREE_IPP_LRO);
	printk("\nUsage: To Show IPP LRO entries, run following command\n");
	printk("echo %s show entry > offload\n", CLE_PTREE_IPP_LRO);
#endif
}

static ssize_t apm_ethoffload_store(struct net_device *dev, const char *buf, size_t len)
{
	int iport = apm_inet_offload_ndev_to_index(dev);
	struct apm_enet_dev_base *priv_dev;
	int i;
	char strbuf[128];
	size_t ret = -EINVAL;
	int update = -1;

	if (len > 128 || ETH_INT_PORT_ERR(iport))
		goto _ret_ethoffload_store;

	if (apm_find_ptree_config(CLE_INT_PORT(iport), CLE_PTREE_DEFAULT) == NULL) {
		printk("%s interface is down\n", dev->name);
		goto _ret_ethoffload_store;
	}

	priv_dev = netdev_priv(dev);
	ret = len;
	memcpy(strbuf, buf, len);
	strbuf[len-1] = '\0';

	for (i = 0; i < ETHOFFLOAD_MAX; i++) {
		if (strncmp(strbuf, apm_ethoffload_mode[i].name,
				strlen(apm_ethoffload_mode[i].name)))
			continue;

		if (len == (strlen(apm_ethoffload_mode[i].name) + 1)) {
			if (priv_dev->ethoffload == i)
				update = 2;
			else
				update = 1;
		} else {
			update = 0;
		}

		break;
	}

	if (update < 0) {
		printk("Invalid offload command\n");
		apm_ethoffload_usage();
		goto _ret_ethoffload_store;
	} else if (update > 1) {
		printk("Offload Type un-changed\n");
		goto _ret_ethoffload_store;
	}

	switch (i) {
#ifdef CONFIG_APM_ENET_IFO
		case ETHOFFLOAD_IPV4FWD:
			ENET_DEBUG_OFFLOAD("ETHOFFLOAD_IPV4FWD\n");
			apm_ipv4fwd_offload_cmd(dev, strbuf, update);
			break;
#endif
#ifdef CONFIG_APM_ENET_INO
		case ETHOFFLOAD_IPV4NAT:
			ENET_DEBUG_OFFLOAD("ETHOFFLOAD_IPV4NAT\n");
			apm_ipv4nat_offload_cmd(dev, strbuf, update);
			break;
#endif
#ifdef CONFIG_APM_ENET_LRO
		case ETHOFFLOAD_IPP_LRO:
			ENET_DEBUG_OFFLOAD("ETHOFFLOAD_IPP_LRO\n");
			apm_ipp_lro_offload_cmd(dev, strbuf, update);
			break;
#endif
#ifdef CONFIG_APM_ENET_QOS
		case ETHSUPPORT_QOS:
			ENET_DEBUG_OFFLOAD("ETHSUPPORT_QOS\n");
			apm_inet_switch(priv_dev, ETHSUPPORT_QOS);
			break;
#endif
		case ETHOFFLOAD_DEFAULT:
		default:
			ENET_DEBUG_OFFLOAD("ETHOFFLOAD_DEFAULT\n");
			apm_inet_switch(priv_dev, ETHOFFLOAD_DEFAULT);
	}

_ret_ethoffload_store:
	return ret;
}

static ssize_t apm_ethoffload_show(struct net_device *dev, char *buf)
{
	struct apm_enet_dev_base *priv_dev = netdev_priv(dev);
	char *s = buf;
	int i;

	for (i = 0; i < ETHOFFLOAD_MAX; i++) {
		if (priv_dev->ethoffload == i)
			s += sprintf(s, "[%s] ", apm_ethoffload_mode[i].name);
		else
			s += sprintf(s, "%s ", apm_ethoffload_mode[i].name);
	}

	*(s-1) = '\n'; /* convert the last space to a newline */

	return (s - buf);
}

#ifdef CONFIG_APM_ENET_OFFLOAD
static int apm_ethoffload_perform(unsigned int internal_eport, void *data, unsigned int data_len)
{
	struct apm_qm_msg32 *imsg = (struct apm_qm_msg32 *)data;
	struct ipv4_frwd_hdr {
		u16 da16;
		u32 da32;
		u16 sa16;
		u32 sa32;
		u8  res[10];
		u8  ttl;
		u8  protocol;
		__be16 checksum;
		__be32 saddr;
		__be32 daddr;
		union {
			/* Add other protocols here. */
			__be32 all;
			struct {
				__be16 sport;
				__be16 dport;
			} tuds; /* TCP UDP DCCP SCTP */
			struct {
				u_int8_t type, code;
				__be16 checksum;
			} icmp;
			struct {
				__be16 key;
				__be16 proto;
			} gre;
		};
	} __attribute__ ((packed));
	struct ipv4_frwd_hdr *skb_data, *mac_data;

	struct apm_qm_msg16 *imsg16 = &imsg->msg16;
	struct apm_qm_msg_up8 *imsgup8_1 = &imsg->msgup8_1;
	struct sk_buff *skb = (struct sk_buff *)imsg16->UserInfo;
	u32 eport = internal_eport | (u32)(imsgup8_1->DR << 1) | imsgup8_1->SZ;
	struct net_device *endev = offload_ndev[eport];
	int i;

	switch (imsgup8_1->H0FPSel) {
#ifdef CONFIG_CLE_BRIDGE
	case APM_BRIDGE_OFFLOAD:
		endev->netdev_ops->ndo_start_xmit(skb, endev);
		for (i = 0; i < endev->num_tx_queues; i++) {
			struct netdev_queue *txq = netdev_get_tx_queue(endev, i);

			txq->trans_start = jiffies;
		}
		break;
#endif
#ifdef CONFIG_APM_IPV4_OFFLOAD
	case APM_IPV4NAT_OFFLOAD:
	{
		enum apm_ipv4nat_offload_type type = imsgup8_1[1].H0FPSel;
		skb_data = (struct ipv4_frwd_hdr *) skb->data;
		if (type == APM_IPV4NAT_OFFLOAD_SNAT) {
			/* Setting SRC IP with SNAT NF IP Address */
			skb_data->saddr = imsgup8_1[1].H0Info_lsb;
			/* Setting SRC L4 with SNAT NF L4 */
			skb_data->tuds.sport = (imsgup8_1[1].H0Enq_Num << 8) | imsgup8_1[1].H0Info_msb;
		} else if (type == APM_IPV4NAT_OFFLOAD_DNAT) {
			/* Setting DST IP with DNAT IP Address */
			skb_data->daddr = imsgup8_1[1].H0Info_lsb;
			/* Setting SRC L4 with SNAT NF L4 */
			skb_data->tuds.dport = (imsgup8_1[1].H0Enq_Num << 8) | imsgup8_1[1].H0Info_msb;
		} else if (type == APM_IPV4NAT_OFFLOAD_SNAT_IP) {
			/* Setting SRC IP with SNAT NF IP Address */
			skb_data->saddr = imsgup8_1[1].H0Info_lsb;
		} else if (type == APM_IPV4NAT_OFFLOAD_DNAT_IP) {
			/* Setting DST IP with DNAT IP Address */
			skb_data->daddr = imsgup8_1[1].H0Info_lsb;
		}
	}
	case APM_IPV4FWD_OFFLOAD:
		skb_data = (struct ipv4_frwd_hdr *) skb->data;
		mac_data = (struct ipv4_frwd_hdr *) endev->dev_addr;
		/* Setting DA with gateway's MAC address */
		skb_data->da16 = ((u16)(imsgup8_1->H0Enq_Num << 8) | imsgup8_1->H0Info_msb);
		skb_data->da32 = imsgup8_1->H0Info_lsb;
		/* Setting SA as interface 'port' MAC Address */
		skb_data->sa16 = (u16)mac_data->da16;
		skb_data->sa32 = (u32)mac_data->da32;
		/* Decrementing TTL by 1*/
		skb_data->ttl--;

		if (internal_eport) {
			struct apm_qm_msg_desc emsg_desc;
			struct apm_qm_msg32 emsg;
			struct apm_qm_msg16 *emsg16 = &emsg.msg16;
			struct apm_qm_msg_up8 *emsgup8_1 = &emsg.msgup8_1;
			struct apm_enet_dev_base *epriv_dev = netdev_priv(endev);
#if !defined(CONFIG_SMP) || defined(SMP_LOAD_BALANCE)
			emsg_desc.qid = epriv_dev->qm_queues[apm_processor_id()].default_tx_qid;
#else
			emsg_desc.qid = epriv_dev->qm_queues[0].default_tx_qid;
#endif
#ifdef CONFIG_APM862xx
			if (unlikely(skb_data->protocol != IPPROTO_TCP &&
					skb_data->protocol != IPPROTO_UDP))
				ip_send_check((struct iphdr *)&skb_data->res[2]);
#endif
			if (!netif_carrier_ok(endev) || netif_queue_stopped(endev)) {
				kfree_skb(skb);
				return -1;
			}
			memset(&emsg, 0, sizeof(emsg));
			emsg16->BufDataLen = imsg16->BufDataLen - 4;
			emsg16->FPQNum = imsg16->FPQNum;
			emsg16->DataAddrMSB = imsg16->DataAddrMSB;
			emsg16->DataAddrLSB = imsg16->DataAddrLSB;
			emsg16->C = apm_enet_pkt_iscoherent();
			emsg16->UserInfo = imsg16->UserInfo;

			/* HR = 1 HE = 1 H0Enq_Num = QM_RSV_UNCONFIG_COMP_Q = 250 */
			/* H0Info_msb = 0x18 (TYPE_SEL_WORK_MSG << 4 | TSO_INS_CRC_ENABLE << 3) */
			/* H0Info_lsb = 0x0140E145 (Enable IPProto Checksum, EthHdr 14, IPHdr 5, TCPHdr 5) */
			*(u64 *)(emsgup8_1) = 0x0300FA180140E145LL;
			emsg_desc.msg = &emsg;
#if defined(CONFIG_NOT_COHERENT_CACHE)
			flush_dcache_range((u32) skb_data, (u32) skb_data + 32);
#endif
			apm_qm_push_msg(&emsg_desc);
			++epriv_dev->stats.tx_packets;
			epriv_dev->stats.tx_bytes += data_len;
		} else {
			ip_send_check((struct iphdr *)&skb_data->res[2]);
#if defined(CONFIG_NOT_COHERENT_CACHE)
			flush_dcache_range((u32) skb_data, (u32) skb_data + 32);
#endif
			endev->netdev_ops->ndo_start_xmit(skb, endev);
			for (i = 0; i < endev->num_tx_queues; i++) {
				struct netdev_queue *txq = netdev_get_tx_queue(endev, i);

				txq->trans_start = jiffies;
			}
		}
		break;
#endif /* CONFIG_APM_IPV4_OFFLOAD */
	}

	return 0;
}

static int apm_ethoffload_check(void *data, unsigned int data_len, unsigned int bufdatalen)
{
	struct apm_qm_msg32 *imsg = (struct apm_qm_msg32 *)data;
	struct apm_qm_msg_up8 *imsgup8_1 = &imsg->msgup8_1;
	u32 eport = (u32)(imsgup8_1->DR << 1) | imsgup8_1->SZ;
	struct net_device *endev = offload_ndev[eport];
	struct apm_qm_msg16 *imsg16 = &imsg->msg16;
	struct sk_buff *tmp_skb = (struct sk_buff *)imsg16->UserInfo;
	u16 queue_id;
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 fmsg;
	phys_addr_t phy_addr;
	unsigned char next_skb_enq_index;

	if (!netif_carrier_ok(endev) || netif_queue_stopped(endev)) {
		queue_id = imsg16->FPQNum;

		fp_msg_desc.msg = &fmsg;
		fp_msg_desc.qid = queue_id;
		fp_msg_desc.mb_id = queue_id;

		phy_addr = virt_to_phys(tmp_skb->data);

		/* Program individual WORD to avoid use of memzero */
		((u32 *) &fmsg)[0] = apm_enet_pkt_iscoherent() << 23 |
			(bufdatalen << 8) |
			(u32) (phy_addr >> 32);
		((u32 *) &fmsg)[1] = (u32) phy_addr;
		((u32 *) &fmsg)[2] = APM_QM_ETH_RTYPE << 24 | queue_id;
		((u32 *) &fmsg)[3] = (u32) tmp_skb;

		/* Fill with the new buffer address */
		if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
			kfree_skb(tmp_skb);
			printk(KERN_ERR "Can not replenish FP buffer\n");
			return -1;
		}

		if (imsg16->NV) {
			struct apm_qm_msg_ext8 *ext_msg = (struct apm_qm_msg_ext8 *) &imsg[1];
			int i;

			bufdatalen = apm_qm_encode_bufdatalen((u16) APM_ENET_PKT_NXTBUF_SIZE);
			queue_id = ext_msg[1].NxtFPQNum;
			fp_msg_desc.qid = queue_id;
			fp_msg_desc.mb_id = queue_id;

			/* Handle Multiple fragment */
			for (i = 0; i < 4; i++) {
				struct page *tmp_page;
				void *data;
				if (!apm_qm_nxtbufdatalen_is_valid(ext_msg[i].NxtBufDataLength))
					break;

				phy_addr = (((u64) ext_msg[i].NxtDataAddrMSB << 32) | ext_msg[i].NxtDataAddrLSB);
				data = phys_to_virt(phy_addr);
				tmp_page = virt_to_page(data);

				/* Program individual WORD to avoid use of memzero */
				((u32 *) &fmsg)[0] = apm_enet_pkt_iscoherent() << 23 |
					(bufdatalen << 8) |
					(u32) (ext_msg[i].NxtDataAddrMSB);
				((u32 *) &fmsg)[1] = (u32) ext_msg[i].NxtDataAddrLSB;
				((u32 *) &fmsg)[2] = APM_QM_ETH_RTYPE << 24 | queue_id;
				((u32 *) &fmsg)[3] = (u32) tmp_page;

				/* Fill with the new buffer address */
				if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
					free_page((u32)page_address(tmp_page));
					printk(KERN_ERR "Can not replenish Next FP buffer\n");
					return -1;
				}
			}
		}

		return 0;
	}

	skb_put(tmp_skb, data_len);

	next_skb_enq_index = skb_enq_index + 1;
	if (next_skb_enq_index != skb_dq_index) {
		skb_q[skb_enq_index] = skb_get(tmp_skb);
		skb_enq_index = next_skb_enq_index;
	}

	apm_ethoffload_perform(0, data, 0);

	tmp_skb = skb_q[skb_dq_index];

	if (skb_shared(tmp_skb))
		return 1;

	tmp_skb->tail = 0;
	tmp_skb->len = 0;
	queue_id = imsg16->FPQNum;

	fp_msg_desc.msg = &fmsg;
	fp_msg_desc.qid = queue_id;
	fp_msg_desc.mb_id = queue_id;

	phy_addr = virt_to_phys(tmp_skb->data);

	/* Program individual WORD to avoid use of memzero */
	((u32 *) &fmsg)[0] = apm_enet_pkt_iscoherent() << 23 |
		(bufdatalen << 8) |
		(u32) (phy_addr >> 32);
	((u32 *) &fmsg)[1] = (u32) phy_addr;
	((u32 *) &fmsg)[2] = APM_QM_ETH_RTYPE << 24 | queue_id;
	((u32 *) &fmsg)[3] = (u32) tmp_skb;

	/* Fill with the new buffer address */
	if (unlikely((apm_qm_fp_dealloc_buf(&fp_msg_desc)) != 0)) {
		kfree_skb(tmp_skb);
		printk(KERN_ERR "Can not replenish FP buffer\n");
		return -1;
	}

	skb_dq_index++;
	return 0;
}

int apm_enet_offload_set_mac(struct apm_enet_dev_base *priv_dev)
{
	int rc;
	struct ipp_net_offload_mac *mac = &priv_dev->offload.mac;

	memcpy(mac->addr, priv_dev->ndev->dev_addr, ETH_ALEN);
	mac->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_NET_OFFLOAD_TYPE,
			IPP_NET_OFFLOAD_MAC, priv_dev->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, mac, sizeof(*mac), NULL);

	if (rc) {
		printk(KERN_ERR NETOFFLOADID
			"Fail to send MAC Address to SlimPRO for port %d\n",
			priv_dev->port_id);
		rc = -EIO;
	}

	return 0;
}

int apm_enet_offload_set_bufdatalen(struct apm_enet_dev_base *priv_dev)
{
	int rc;
	struct ipp_net_offload_bufdatalen *bufdatalen = &priv_dev->offload.bufdatalen;

	bufdatalen->val = apm_qm_encode_bufdatalen(HW_MTU(priv_dev->ndev->mtu));

	ENET_DEBUG_OFFLOAD(NETOFFLOADID "ENET %d\n"
		"ETH Free Pool Buffer ENC_LEN %08x\n",
		priv_dev->port_id,
		bufdatalen->val);

	bufdatalen->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_NET_OFFLOAD_TYPE,
			IPP_NET_OFFLOAD_BUFDATALEN, priv_dev->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, bufdatalen,
				sizeof(*bufdatalen), NULL);

	if (rc) {
		printk(KERN_ERR NETOFFLOADID
			"Fail to send bufdatalen to SlimPRO for port %d\n",
			priv_dev->port_id);
		rc = -EIO;
	}

	return 0;
}

static int apm_enet_offload_get_queue(struct apm_enet_dev_base *priv_dev)
{
	int rc = 0;
	struct slimpro_queue *slimpro_q;
#ifdef CONFIG_SMP
	u32 core = 0;
#else
	u32 core = apm_processor_id();
#endif

	/* Allocate SlimPRO Rx work queue */
	slimpro_q = slimpro_queue_request(NULL);
	if (slimpro_q == NULL) {
		rc = -ENODEV;
		printk(KERN_ERR NETOFFLOADID
			"Failed to retrieve SlimPRO offload work queue\n");
		goto done;
	}

	priv_dev->offload.qm.offloader_rx_qid = slimpro_q->wqid;
	priv_dev->offload.qm.offloader_rx_mbid = slimpro_q->mbox;
	priv_dev->offload.qm.offloader_rx_pbn = slimpro_q->pbn;

	priv_dev->offload.qm.eth_tx_qid = priv_dev->qm_queues[core].hw_tx_qid;
	priv_dev->offload.qm.eth_tx_mbid = priv_dev->qm_queues[core].hw_tx_mbid;
	priv_dev->offload.qm.eth_tx_pbn = priv_dev->qm_queues[core].hw_tx_pbn;

	ENET_DEBUG_OFFLOAD(NETOFFLOADID "ENET %d\n"
		"Offloader RX QID %d MBID %d PBN %d\n"
		"ETH TX QID %d MBID %d PBN %d\n",
		priv_dev->port_id,
		priv_dev->offload.qm.offloader_rx_qid,
		priv_dev->offload.qm.offloader_rx_mbid,
		priv_dev->offload.qm.offloader_rx_pbn,
		priv_dev->offload.qm.eth_tx_qid,
		priv_dev->offload.qm.eth_tx_mbid,
		priv_dev->offload.qm.eth_tx_pbn);

	priv_dev->offload.init_done = 1;

done:
	return rc;
}

static int apm_enet_offload_set_queue(struct apm_enet_dev_base *priv_dev)
{
	int rc;
	struct ipp_net_offload_qm *qm = &priv_dev->offload.qm;

#ifdef CONFIG_APM_ENET_IFO
	if (priv_dev->offload.offload_available & IPP_IPV4FWD_OFFLOAD_FW_MASK)
		apm_ipv4fwd_offload_setqid(priv_dev->port_id,
			priv_dev->offload.qm.offloader_rx_qid);
#endif

	qm->cmd = IPP_ENCODE_NETDATA_CTRL_WORD(IPP_NETDATA_NET_OFFLOAD_TYPE,
			IPP_NET_OFFLOAD_QM, priv_dev->port_id, 0);
	rc = ipp_send_data_msg(IPP_NETDATA_HDLR, qm, sizeof(*qm), NULL);

	if (rc) {
		printk(KERN_ERR NETOFFLOADID
			"Fail to send QM Info to SlimPRO for port %d\n",
			priv_dev->port_id);
		rc = -EIO;
	}

	return 0;
}

int apm_enet_offload_init(struct apm_enet_dev_base *priv_dev)
{
	struct apm_enet_offload_ctx *offload_ctx = &priv_dev->offload;

	if (offload_ctx->enable)
		goto _ret_enet_offload_init;

	if (offload_ctx->init_done)
		goto _ret_enet_offload_set_queue;

	if (apm_enet_offload_set_mac(priv_dev) != 0)
		goto _ret_enet_offload_init;

	if (apm_enet_offload_set_bufdatalen(priv_dev) != 0)
		goto _ret_enet_offload_init;

	if (apm_enet_offload_get_queue(priv_dev) != 0)
		goto _ret_enet_offload_init;

_ret_enet_offload_set_queue:
	if (apm_enet_offload_set_queue(priv_dev) != 0)
		goto _ret_enet_offload_init;

	offload_ctx->enable = 1;

	printk(KERN_INFO "APM86xxx Net Offload initialized for %s interface\n",
		priv_dev->ndev->name);

_ret_enet_offload_init:
	return 0;
}
#endif /* CONFIG_APM_ENET_OFFLOAD */

#ifdef CONFIG_APM_IPV4_OFFLOAD
int apm_make_ipv4_arp_offload(struct neighbour *n)
{
	int rc = APM_RC_OK;
#ifdef CONFIG_APM_ENET_IFO
	rc |= apm_mkarp_ipv4_forward(n);
#endif
#ifdef CONFIG_APM_ENET_INO
	rc |= apm_mkarp_ipv4_nat(n);
#endif
	return rc;
}

void apm_remove_ipv4_arp_offload(struct neighbour *n)
{
#ifdef CONFIG_APM_ENET_IFO
	if (apm_ethoffload_ops.ifo_arp_cache_entries ||
		apm_ethoffload_ops.ifo_arp_unuse_entries)
		apm_rmarp_ipv4_forward(n);
#endif
#ifdef CONFIG_APM_ENET_INO
	if (apm_ethoffload_ops.ino_arp_cache_entries ||
		apm_ethoffload_ops.ino_arp_unuse_entries)
		apm_rmarp_ipv4_nat(n);
#endif
}

void apm_flush_ipv4_arp_offload(struct net_device *dev)
{
#ifdef CONFIG_APM_ENET_IFO
	if (apm_ethoffload_ops.ifo_arp_cache_entries ||
		apm_ethoffload_ops.ifo_arp_unuse_entries)
		apm_flarp_ipv4_forward(dev);
#endif
#ifdef CONFIG_APM_ENET_INO
	if (apm_ethoffload_ops.ino_arp_cache_entries ||
		apm_ethoffload_ops.ino_arp_unuse_entries)
		apm_flarp_ipv4_nat(dev);
#endif
}

int apm_make_ipv4_route_offload(struct sk_buff *skb, struct rtable *rth)
{
	int rc = APM_RC_OK;
#ifdef CONFIG_APM_ENET_IFO
	rc |= apm_mkroute_ipv4_forward(skb, rth);
#endif
#ifdef CONFIG_APM_ENET_INO
	rc |= apm_mkroute_ipv4_nat(skb, rth);
#endif
	return rc;
}

void apm_remove_ipv4_route_offload(struct rtable *rth)
{
#ifdef CONFIG_APM_ENET_IFO
	if (apm_ethoffload_ops.ifo_route_cache_entries ||
		apm_ethoffload_ops.ifo_route_unuse_entries)
		apm_rmroute_ipv4_forward(rth);
#endif
#ifdef CONFIG_APM_ENET_INO
	if (apm_ethoffload_ops.ino_route_cache_entries ||
		apm_ethoffload_ops.ino_route_unuse_entries)
		apm_rmroute_ipv4_nat(rth);
#endif
}

void apm_flush_ipv4_route_offload(struct net_device *dev)
{
#ifdef CONFIG_APM_ENET_IFO
	if (apm_ethoffload_ops.ifo_route_cache_entries ||
		apm_ethoffload_ops.ifo_route_unuse_entries)
		apm_flroute_ipv4_forward(dev);
#endif
#ifdef CONFIG_APM_ENET_INO
	if (apm_ethoffload_ops.ino_route_cache_entries ||
		apm_ethoffload_ops.ino_route_unuse_entries)
		apm_flroute_ipv4_nat(dev);
#endif
}
#endif /* CONFIG_APM_IPV4_OFFLOAD */

struct ethoffload_ops apm_ethoffload_ops = {
	.signature = AMCC_ENET_SIGNATURE,
	.ethoffload_interfaces_mask = 0,
	.ethoffload_interfaces = 0,
	.store_offload = apm_ethoffload_store,
	.show_offload = apm_ethoffload_show,
#ifdef CONFIG_APM_ENET_LRO
	.make_tcp_connection_offload = apm_mktcp_connection,
	.remove_tcp_connection_offload = apm_rmtcp_connection,
	.tcp_connection_entries = 0,
#endif
#ifdef CONFIG_APM_ENET_OFFLOAD
	/*
	 * Encoding Format (common) for any Ethernet Offload
	 *
	 * If HR0 bit is set
	 * H0DR:H0SZ (2 bits) specifies any of 4 egress Internal ENET port
	 * If HR0 bit is not set
	 * H0DR:H0SZ (2 bits) specifies any of 4 egress LAC<->External Non-ENET port (PCIE, USB)
	 *
	 * If HR1 bit is set
	 * H1DR:H1SZ (2 bits) specifies any of 4 ingress Internal ENET port
	 * If HR1 bit is not set
	 * H1DR:H1SZ (2 bits) specifies any of 4 ingress LAC<->External Non-ENET port (PCIE, USB)
	 *
	 * If HE0 bit is set offload enabled
	 * If HE0 bit is not set offload not enabled
	 *
	 * If HE1 bit is set VLAN is present
	 * If HE1 bit is not set VLAN is not present
	 *
	 * H0FPSel (4 bits) specifies offload to perform
	 * 0. Bridge
	 * 1. IPv4 Forward
	 * 2. IPv4 NAT
	 * 3. to 15. For Future NET offload support
	 *
	 * Following (100 bits) feilds will be used by Ethernet Offload methods
	 * H0Enq_Num (8 bits) H0Info_msb (8 bits) H0Info_lsb (32 bits)
	 * H1Enq_Num (8 bits) H1Info_msb (8 bits) H1Info_lsb (32 bits)
	 * H1FPSel (4 bits)
	 *
	 */
#ifdef CONFIG_CLE_BRIDGE
	.add_bridge_port_offload = apm_addbr_port,
	.del_bridge_port_offload = apm_delbr_port,
	.add_bridge_fdb_offload = apm_addbr_fdb,
	.del_bridge_fdb_offload = apm_delbr_fdb,
#endif
#ifdef CONFIG_APM_IPV4_OFFLOAD
	.make_ipv4_arp_offload = apm_make_ipv4_arp_offload,
	.remove_ipv4_arp_offload = apm_remove_ipv4_arp_offload,
	.flush_ipv4_arp_offload = apm_flush_ipv4_arp_offload,
	{
		.ipv4_arp_cache_entries = 0,
	},
	.make_ipv4_route_offload = apm_make_ipv4_route_offload,
	.remove_ipv4_route_offload = apm_remove_ipv4_route_offload,
	.flush_ipv4_route_offload = apm_flush_ipv4_route_offload,
	{
		.ipv4_route_cache_entries = 0,
	},
#endif
#ifdef CONFIG_APM_ENET_IFO
	/*
	 * Encoding Format common for IPv4 Forward & IPv4 NAT Offload
	 *
	 * DST MAC Address (40 bits) from Byte 0 to byte 5 formed with
	 * H0Enq_Num (8 bits) H0Info_msb (8 bits) H0Info_lsb (32 bits)
	 */
	{
		.ifo_arp_cache_entries = 0,
	},
	.ifo_arp_unuse_entries = 0,
	{
		.ifo_route_cache_entries = 0,
	},
	.ifo_route_unuse_entries = 0,
#endif
#ifdef CONFIG_APM_ENET_INO
	/*
	 * Encoding Format for IPv4 NAT Offload
	 *
	 * DST MAC Address (40 bits) from Byte 0 to byte 5 formed with
	 * H0Enq_Num (8 bits) H0Info_msb (8 bits) H0Info_lsb (32 bits)
	 *
	 * NAT Port (16 bits) Byte 0 - Byte 1 formed with
	 * H1Enq_Num (8 bits) H1Info_msb (8 bits)
	 *
	 * NAT IP Address (32 bits) formed with H1Info_lsb (32 bits)

	 * H1FPSel (4 bits) specifies NAT offload Type to perform
	 * 0. SNAT
	 * 1. DNAT
	 * 2. to 15. For Future NAT offload Type support
	 *
	 */
	.make_ipv4_nat_offload = apm_mknat_ipv4_nat,
	.remove_ipv4_nat_offload = apm_rmnat_ipv4_nat,
	{
		.ino_arp_cache_entries = 0,
	},
	.ino_arp_unuse_entries = 0,
	{
		.ino_route_cache_entries = 0,
	},
	.ino_nat_unuse_entries = 0,
#endif
#ifdef CONFIG_APM_ENET_QOS
/*
	define the operation for QOS
	HW QoS expects to make action from user space, not be called within kernel space.
	Therefore, the operation should be reflexed to ENET IOCTL and user_space CLE+QM/TM libs.
	This is for reservation
*/
#endif
	.check_offload = apm_ethoffload_check,
	.perform_offload = apm_ethoffload_perform,
#endif /* CONFIG_APM_ENET_OFFLOAD */
};
EXPORT_SYMBOL(apm_ethoffload_ops);

int apm_inet_switch(struct apm_enet_dev_base *priv_dev, enum apm_ethoffload offload)
{
	u32 iport = priv_dev->port_id;
	struct apm_data_priv *priv = &priv_dev->priv;
	/* Let MAC do not receive any more packet from PHY */
	apm_gmac_rx_disable(priv);
	/* Let CPU delay to make sure CSR is stable */
	mdelay(100);
	/* Do context switching */
	int rc = apm_preclass_switch_tree(iport, apm_ethoffload_mode[offload].name, 0);
	/* Let CPU delay to make sure CLE and ENET CSR are stable */
	mdelay(100);
	/* Let MAC continue to receive packet from PHY */
	apm_gmac_rx_enable(priv);

	if (rc == APM_RC_OK)
		priv_dev->ethoffload = offload;

	return rc;
}

int apm_inet_offload_ndev_is_internal(struct net_device *ndev)
{
	int rc = -1;

	if (ndev &&
		ndev->dev.parent &&
		ndev->dev.parent->driver &&
		ndev->dev.parent->driver->name) {

		int i;
		const char *name = ndev->dev.parent->driver->name;
		int len = strlen(name);

		for (i = 0; apm_ethoffload_driver[i].name != NULL; i++) {
			if (strncmp(apm_ethoffload_driver[i].name, name, len) == 0) {
				rc = apm_ethoffload_driver[i].internal_port;
				break;
			}
		}
	}

	return rc;
}

int apm_inet_offload_ndev_to_index(struct net_device *ndev)
{
	int i;

	for (i = 0; i < CLE_MAX_PORTS; i++) {
		if (offload_ndev[i] &&
				offload_ndev[i] == ndev)
			return i;
	}

	return -1;
}

int apm_inet_offload_ndev_name_to_index(char *name)
{
	int i;

	for (i = 0; i < CLE_MAX_PORTS; i++) {
		if (offload_ndev[i] &&
				strncmp(offload_ndev[i]->name, name, IFNAMSIZ) == 0)
			return i;
	}

	return -1;
}

int apm_inet_offload_ifindex_to_index(int ifindex)
{
	int i;

	for (i = 0; i < CLE_MAX_PORTS; i++) {
		if (offload_ndev[i] &&
				offload_ndev[i]->ifindex == ifindex)
			return i;
	}

	return -1;
}

int apm_inet_offload_register_netdev(struct net_device *ndev)
{
	int i, rc = -1;
	int internal_port;

	if ((i = apm_inet_offload_ndev_to_index(ndev)) != -1)
		goto _skip_offload_register_netdev;

	if ((internal_port = apm_inet_offload_ndev_is_internal(ndev)) == -1)
		goto _ret_offload_register_netdev;

	if (internal_port) {
		struct apm_enet_dev_base *priv_dev = netdev_priv(ndev);

		i = CLE_INT_PORT0 + priv_dev->port_id;
		priv_dev->in_poll_rx_msg_desc.is_msg16 = 0;
		goto _ndev_offload_register_netdev;
	}

	for (i = CLE_EXT_PORT0; i < CLE_INT_PORT0; i++) {
		if (!offload_ndev[i])
			break;
	}

	if (i == CLE_INT_PORT0)
		goto _ret_offload_register_netdev;

_ndev_offload_register_netdev:
	offload_ndev[i] = ndev;
	SET_ETHOFFLOAD_OPS(ndev, &apm_ethoffload_ops);
	apm_ethoffload_ops.ethoffload_interfaces++;
	apm_ethoffload_ops.ethoffload_interfaces_mask |= (1 << i);

_skip_offload_register_netdev:
	rc = 0;
	printk(KERN_INFO "%s %s registered as APM INET Offload port %d\n",
		ndev->dev.parent->driver->name, ndev->name, i);

_ret_offload_register_netdev:
	return rc;
}
EXPORT_SYMBOL(apm_inet_offload_register_netdev);

void apm_inet_offload_unregister_netdev(struct net_device *ndev)
{
	int i = apm_inet_offload_ndev_to_index(ndev);

	if (i == -1)
		return;

	offload_ndev[i] = NULL;
	SET_ETHOFFLOAD_OPS(ndev, NULL);
	apm_ethoffload_ops.ethoffload_interfaces--;
	apm_ethoffload_ops.ethoffload_interfaces_mask &= ~(1 << i);

	printk(KERN_INFO "%s %s unregistered as APM INET Offload port %d\n",
		ndev->dev.parent->driver->name, ndev->name, i);
}
EXPORT_SYMBOL(apm_inet_offload_unregister_netdev);

/**
 * netdev event handler
 */
static int apm_inet_offload_ndev_event(struct notifier_block *this,
		unsigned long event, void *ptr)
{
	struct net_device *ndev = ptr;

	if (event == NETDEV_REGISTER) {
		/* Register ndev to allow INET Offload for the ndev driver,
		 * if present in apm_ethoffload_driver name list
		 */
		if (ndev &&
			ndev->dev.parent &&
			ndev->dev.parent->driver &&
			ndev->dev.parent->driver->name) {
			apm_inet_offload_register_netdev(ndev);
		}
	}

	return 0;
}

static struct notifier_block apm_inet_offload_ndev_notifier = {
	.notifier_call = apm_inet_offload_ndev_event
};

static int __init apm_inet_offload_init(void)
{
	int rc;

	skb_enq_index = 0;
	skb_dq_index = 0;
	memset(skb_q, 0, sizeof(skb_q));

	spin_lock_init(&apm_ethoffload_ops.cle_lock);
	rc = register_netdevice_notifier(&apm_inet_offload_ndev_notifier);

	return rc;
}

static void __exit apm_inet_offload_exit(void)
{
}

module_init(apm_inet_offload_init);
module_exit(apm_inet_offload_exit);

MODULE_AUTHOR("Ravi Patel <rapatel@apm.com>");
MODULE_DESCRIPTION("APM86xxx SoC INET Offload driver");
MODULE_LICENSE("GPL");
