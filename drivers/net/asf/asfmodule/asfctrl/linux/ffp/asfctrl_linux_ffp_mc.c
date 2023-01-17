/**************************************************************************
 * Copyright 2010-2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_ffp_mc.c
 *
 * Description: Control module for Configuring ASF and integrating it with
 * Control plane
 *
 * Authors:	Sridhar Pothuganti <sridhar.pothuganti@freescale.com>
 *
 */
/*
 * History
 *  Version     Date         Author              Change Description
 *  1.0        10/10/2014    Sridhar Pothuganti  Initial Development
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/inetdevice.h>
#include <net/dst.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/dst.h>
#include <net/netfilter/nf_conntrack_extend.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <linux/netfilter/nf_conntrack_tcp.h>
#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter_ipv6/ip6_tables.h>
#include <linux/netfilter/nf_conntrack_common.h>
#include <net/route.h>
#include <net/ip6_route.h>
#include <net/ipv6.h>

#include "../../../asfffp/driver/asf.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "asfctrl.h"

typedef struct asf_mcast_work_s {
	struct work_struct	data;	/* work queue data */
	ASFFFPFlowTuple_t	touple;	/* Actual message  */
} asf_mcast_work_t;

void asfctrl_multicast_forward_flow_delete_wq(struct work_struct *work);
int asfctrl_multicast_forward_flow_create(struct sk_buff *skb);
void asfctrl_multicast_forward_flow_delete(ASFFFPFlowTuple_t touple);
ASF_void_t asfctrl_fnMultCastFlowValidate(ASF_uint32_t ulVSGId,
			ASFFFPFlowValidateCbInfo_t *pInfo);

extern uint32_t asf_ffp_udp_tmout;

int asfctrl_multicast_forward_flow_create(struct sk_buff *skb)
{
	struct iphdr *iph_t;
	ASFFFPCreateFlowsInfo_t cmd;
	int x_hh_len = 0;
	struct net_device *dev = NULL;
	struct net *net = NULL;
	int result = 0;
	bool bIPsecIn = 0, bIPsecOut = 0;
	bool pf_ipv6 = false;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	struct flowi fl_out;
#endif

	skb_set_network_header(skb, x_hh_len);
	iph_t = ip_hdr(skb);

	memset(&cmd, 0, sizeof(cmd));

	cmd.flow1.tuple.ucProtocol = iph_t->protocol;
	cmd.flow1.tuple.ulDestIp = iph_t->daddr;
	cmd.flow1.tuple.ulSrcIp = iph_t->saddr;
	cmd.flow1.tuple.bIPv4OrIPv6 = false;

	cmd.flow2.tuple.ucProtocol = iph_t->protocol;
	cmd.flow2.tuple.ulDestIp = iph_t->saddr;
	cmd.flow2.tuple.ulSrcIp = iph_t->daddr;
	cmd.flow2.tuple.bIPv4OrIPv6 =  false;

	cmd.flow2.bNAT = 0;
	cmd.flow1.bNAT = 0;

	cmd.ASFWInfo = NULL;
	cmd.configIdentity.ulConfigMagicNumber = asfctrl_vsg_config_id[ASF_DEF_VSG];
	cmd.configIdentity.l2blobConfig.ulL2blobMagicNumber = asfctrl_vsg_l2blobconfig_id[ASF_DEF_VSG];

	cmd.flow1.ulZoneId = ASF_DEF_ZN_ID;

	cmd.flow1.ulInacTimeout = asf_ffp_udp_tmout;

#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		memset(&fl_out, 0, sizeof(fl_out));
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl_out.proto = iph_t->protocol;
		fl_out.fl4_dst = iph_t->daddr;
		fl_out.fl4_src = iph_t->saddr;
		fl_out.fl4_tos = 0;
		#else
		fl_out.flowi_proto = iph_t->protocol;
		fl_out.u.ip4.daddr = iph_t->daddr;
		fl_out.u.ip4.saddr = iph_t->saddr;
		fl_out.flowi_tos = 0;
		#endif

		dev = dev_get_by_name(&init_net, "lo");
		net = dev_net(dev);

		/*TBD:Need to get proper VSGID*/
		result = fn_ipsec_get_flow4(ASF_DEF_VSG, &bIPsecIn, &bIPsecOut,
			&(cmd.flow1.ipsecInInfo), net, fl_out, pf_ipv6);
		if (result) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow 1");
			dev_put(dev);
			return result;
		}
		dev_put(dev);
	}
#endif
	cmd.flow1.bIPsecIn = bIPsecIn ? 1 : 0;
	cmd.flow1.bIPsecOut = bIPsecOut ? 1 : 0;
	if (!bIPsecOut)	{
		ASFCTRL_INFO("ASF IpSecOut not offloadable, no need to create flow\r\n");
		return ASF_FAILURE;
	}

	/* Fill the command for flow 2 */
	cmd.flow2.ulZoneId = ASF_DEF_ZN_ID;

	cmd.flow2.ulInacTimeout = asf_ffp_udp_tmout;

	cmd.flow2.bIPsecIn = 0;
	cmd.flow2.bIPsecOut = 0;

	if (ASFFFPRuntime(ASF_DEF_VSG,
			 ASF_FFP_CREATE_FLOWS,
			 &cmd, sizeof(cmd), NULL, 0) ==
					ASFFFP_RESPONSE_SUCCESS) {
		/* Flow created successfully. populate the L2 info*/
		ASFCTRL_INFO("Flow created successfully in ASF");
	} else {
		/* Error hanling */
		ASFCTRL_WARN("Flow creation failure in ASF");
	}

	ASFCTRL_FUNC_EXIT;
	return 0;
}

void multicast_ct_refresh(ASFFFPFlowTuple_t *pTouple)
{
	asf_mcast_work_t *pWork;

	pWork = kzalloc (sizeof(asf_mcast_work_t), GFP_ATOMIC);

	if (!pWork) {
		ASFCTRL_WARN("Unable to allocate memory for asf_mcast_work_t\r\n");
		return;
	}

	memcpy(&(pWork->touple), pTouple, sizeof(pWork->touple));
	INIT_WORK(&(pWork->data), asfctrl_multicast_forward_flow_delete_wq);
	schedule_work(&(pWork->data));
}
EXPORT_SYMBOL(multicast_ct_refresh);

void asfctrl_multicast_forward_flow_delete_wq(struct work_struct *pWork)
{
	asf_mcast_work_t	*pMcastwork = (asf_mcast_work_t *) pWork;
	ASFFFPFlowTuple_t 	touple;

	memcpy(&touple, &(pMcastwork->touple), sizeof(touple));
	kfree(pMcastwork);
	ASFCTRL_INFO("The process is \"%s\" (pid %i)\n", current->comm, current->pid);

	asfctrl_multicast_forward_flow_delete(touple);
}

void asfctrl_multicast_forward_flow_delete(ASFFFPFlowTuple_t touple)
{
	ASFFFPDeleteFlowsInfo_t cmd;

	memset(&cmd, 0, sizeof(cmd));

	cmd.tuple.ucProtocol = touple.ucProtocol;
	cmd.tuple.ulDestIp = touple.ulDestIp;
	cmd.tuple.ulSrcIp = touple.ulSrcIp;
	cmd.tuple.bIPv4OrIPv6 =  0;
	cmd.tuple.usDestPort =  0;
	cmd.tuple.usSrcPort = 0;
	cmd.ulZoneId = 0;

	if (ASFFFPRuntime(0,
		ASF_FFP_DELETE_FLOWS,
		&cmd, sizeof(cmd), NULL, 0) ==
		ASFFFP_RESPONSE_SUCCESS) {
			ASFCTRL_INFO("Multicast Flow deleted successfully");
	} else {
		ASFCTRL_INFO("Multicast Flow deletion failure");
	}

}
EXPORT_SYMBOL(asfctrl_multicast_forward_flow_delete);

ASF_void_t asfctrl_fnMultCastFlowValidate(ASF_uint32_t ulVSGId,
			ASFFFPFlowValidateCbInfo_t *pInfo)
{

	bool	bIPv6;
	bool bIPsecIn = 0, bIPsecOut = 0;
	struct flowi fl_out;
	struct net_device *dev = NULL;
	struct net *net = NULL;
	int	result;

	ASFCTRL_FUNC_ENTRY;

	bIPv6 = pInfo->tuple.bIPv4OrIPv6 == 1 ? true : false;

	ASFFFPUpdateFlowParams_t cmd;

	memset(&cmd, 0, sizeof(cmd));

	cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;
	cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
	cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
	cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;

	cmd.ulZoneId = ASF_DEF_ZN_ID;

	cmd.bFFPConfigIdentityUpdate = 1;
	cmd.bDrop = 0;

	cmd.u.fwConfigIdentity.ulConfigMagicNumber = asfctrl_vsg_config_id[ulVSGId];

#ifdef ASF_INGRESS_MARKER
	if (pASFCbFnQosMarker_p) {
		cmd.mkinfo.uciDscp = pASFCbFnQosMarker_p(
			&cmd.tuple.ulSrcIp,
			&cmd.tuple.ulDestIp,
			cmd.tuple.usSrcPort,
			cmd.tuple.usDestPort,
			cmd.tuple.ucProtocol,
			bIPv6);
	} else
		cmd.mkinfo.uciDscp = ASF_QM_NULL_DSCP;
#endif
	if (ASFFFPRuntime(ASF_DEF_VSG,
		ASF_FFP_MODIFY_FLOWS,
		&cmd, sizeof(cmd), NULL, 0) ==
		ASFFFP_RESPONSE_SUCCESS) {
			ASFCTRL_INFO("Flow modified successfully");
	} else {
			ASFCTRL_ERR("Flow modification failure");
	}
#ifdef ASFCTRL_IPSEC_FP_SUPPORT
	if (fn_ipsec_get_flow4) {
		ASFFFPIpsecInfo_t ipsecInInfo;

		memset(&cmd, 0, sizeof(cmd));

		memset(&fl_out, 0, sizeof(fl_out));
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl_out.proto = pInfo->tuple.ucProtocol;
		fl_out.fl4_dst = pInfo->tuple.ulDestIp;
		fl_out.fl4_src = pInfo->tuple.ulSrcIp;
		fl_out.fl4_tos = 0;
		#else
		fl_out.flowi_proto = pInfo->tuple.ucProtocol;
		fl_out.u.ip4.daddr = pInfo->tuple.ulDestIp;
		fl_out.u.ip4.saddr = pInfo->tuple.ulSrcIp;
		fl_out.flowi_tos = 0;
		#endif

		dev = dev_get_by_name(&init_net, "lo");
		net = dev_net(dev);

		/*TBD:Need to get proper VSGID*/
		result = fn_ipsec_get_flow4(ASF_DEF_VSG, &bIPsecIn, &bIPsecOut,
			&ipsecInInfo, net, fl_out, bIPv6);
		if (result || !bIPsecOut) {
			ASFCTRL_INFO("IPSEC Not Offloadable for flow");
			dev_put(dev);
			goto delete_flow;
		}
		dev_put(dev);

		cmd.tuple.ulDestIp = pInfo->tuple.ulDestIp;
		cmd.tuple.ulSrcIp = pInfo->tuple.ulSrcIp;
		cmd.tuple.bIPv4OrIPv6 = bIPv6 == true ? 1 : 0;
		cmd.u.ipsec.ipsecInfo = ipsecInInfo;
		cmd.tuple.ucProtocol = pInfo->tuple.ucProtocol;

		cmd.bIPsecConfigIdentityUpdate = 1;

		cmd.u.ipsec.bIPsecIn = bIPsecIn ? 1 : 0;
		cmd.u.ipsec.bIPsecOut = bIPsecOut ? 1 : 0;
		cmd.u.ipsec.bIn = cmd.u.ipsec.bOut = 1;
		cmd.ulZoneId = ASF_DEF_ZN_ID;

		ASFCTRL_INFO("Configured tunnel ID is %d ",
			ipsecInInfo.outContainerInfo.ulTunnelId);
		if (ASFFFPRuntime(ASF_DEF_VSG,
			ASF_FFP_MODIFY_FLOWS,
			&cmd, sizeof(cmd), NULL, 0) ==
			ASFFFP_RESPONSE_SUCCESS) {
			ASFCTRL_INFO("Flow modified successfully");
		} else {
			ASFCTRL_WARN("Flow modification failure");
		}
	}
#endif
	return;
delete_flow:
	multicast_ct_refresh(&cmd.tuple);
}
EXPORT_SYMBOL(asfctrl_fnMultCastFlowValidate);
