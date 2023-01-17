/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_linux_ipsec.c
 *
 * Added Support for ipsec configuration information offloading
 * from Linux to ASF.
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *		Sandeep Malik <b02416@freescale.com>
 *
 */
/*
 *  History
 *  Version	Date		Author			Change Description
 *  0.1	29/07/2010    Hemant Agrawal		Initial Development
 *  1.0	29/09/2010    Sandeep Malik		Linux Integration
*/
/***************************************************************************/
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/route.h>
#ifdef ASF_IPV6_FP_SUPPORT
#include <net/ip6_route.h>
#endif
#include <net/xfrm.h>
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif

#include "../../../asfipsec/driver/ipsfpapi.h"
#include "../../../asfffp/driver/asfcmn.h"
#include "../ffp/asfctrl.h"
#include "asfctrl_linux_ipsec_hooks.h"

#define ASFCTRL_LINUX_IPSEC_VERSION	"1.0.0"
#define ASFCTRL_LINUX_IPSEC_DESC 	"ASF Linux-IPsec Integration Driver"

/** \brief	Driver's license
 *  \details	Dual BSD/GPL
 *  \ingroup	Linux_module
 */
MODULE_LICENSE("Dual BSD/GPL");
/** \brief	Module author
 *  \ingroup	Linux_module
 */
MODULE_AUTHOR("Freescale Semiconductor, Inc");
/** \brief	Module description
 *  \ingroup	Linux_module
 */
MODULE_DESCRIPTION(ASFCTRL_LINUX_IPSEC_DESC);

module_param(bRedSideFragment, bool, 0444);
MODULE_PARM_DESC(bRedSideFragment, "Bool - Whether ASF-IPsec "\
	"RED Side Fragmentation is Enabled");

module_param(bAntiReplayCheck, bool, 0444);
MODULE_PARM_DESC(bAntiReplayCheck, "Bool - Whether ASF-IPsec "\
	"Anti Replay Check is Enabled");

module_param(bVolumeBasedExpiry, bool, 0444);
MODULE_PARM_DESC(bVolumeBasedExpiry, "Bool - Whether ASF-IPsec "\
	"volume-based SA Expiry is Enabled");

module_param(bPacketBasedExpiry, bool, 0444);
MODULE_PARM_DESC(bPacektBasedExpiry, "Bool - Whether ASF-IPsec "\
	"Packet-based SA Expiry is Enabled");

#define ASFCTRL_IPSEC_SEND_TO_LINUX

/* Global Variables */
ASFIPSecCap_t g_ipsec_cap;
uint32_t asfctrl_vsg_ipsec_cont_magic_id;
uint32_t asfctrl_max_sas = SECFP_MAX_SAS;
uint32_t asfctrl_max_policy_cont = ASFCTRL_MAX_SPD_CONTAINERS;
bool bRedSideFragment = ASF_TRUE;
bool bAntiReplayCheck = ASF_TRUE;
bool bVolumeBasedExpiry = ASF_FALSE;
bool bPacketBasedExpiry = ASF_FALSE;

struct asf_ipsec_callbackfn_s asf_sec_fns = {
		asfctrl_xfrm_enc_hook,
		asfctrl_xfrm_dec_hook,
		NULL,
		asfctrl_xfrm_encrypt_n_send,
		asfctrl_xfrm_decrypt_n_send
};
/* function_prototypes */


ASF_void_t asfctrl_ipsec_fn_NoInSA(ASF_uint32_t ulVsgId,
				ASFBuffer_t *Buffer,
				genericFreeFn_f pFreeFn,
				ASF_void_t *freeArg,
				ASF_uint32_t ulCommonInterfaceId)
{
	struct sk_buff  *skb;
	int bVal = in_softirq();
	ASFCTRL_FUNC_TRACE;
	if (!bVal)
		local_bh_disable();

	skb = AsfBuf2Skb(Buffer);
#ifdef ASFCTRL_IPSEC_SEND_TO_LINUX
	ASFCTRL_INFO("Sending packet UP ");
	/* Send it to for normal path handling */
	ASFCTRL_netif_receive_skb(skb);
#else
	ASFCTRL_WARN("NO IN SA Found Drop packet");
	pFreeFn(Buffer.nativeBuffer);
#endif

	if (!bVal)
		local_bh_enable();
}

#ifdef ASF_MULTICAST_TERMINATION_SUPPORT
void asfctrl_ipsec_fn_Multicast_NoOutSA(ASFFFPFlowTuple_t touple, struct sk_buff  *skb)
{
	struct xfrm_policy *pol_out;
	struct flowi fl_out;
	struct net_device *dev = NULL;
	struct net *net = NULL;
	int i = 0;
	struct xfrm_state *x;
	xfrm_address_t *remote;
	xfrm_address_t *local;
	xfrm_address_t tmp;
	int error;

	ASFCTRL_FUNC_ENTRY;

	/*TODO: IPv6 need to be done*/

	memset(&fl_out, 0, sizeof(fl_out));
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	fl_out.proto = touple.ucProtocol;
	fl_out.fl4_dst = touple.ulDestIp;
	fl_out.fl4_src = touple.ulSrcIp;
	fl_out.fl4_tos = 0;
	#else
	fl_out.flowi_proto = touple.ucProtocol;
	fl_out.u.ip4.daddr = touple.ulDestIp;
	fl_out.u.ip4.saddr = touple.ulSrcIp;
	fl_out.flowi_tos = 0;
	#endif

	dev = dev_get_by_name(&init_net, "lo");
	net = dev_net(dev);

	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	pol_out = xfrm_policy_check_flow(net, &fl_out, AF_INET, FLOW_DIR_OUT);
	#else
	pol_out = __xfrm_policy_lookup(net, &fl_out, AF_INET, FLOW_DIR_OUT);
	#endif

	if (IS_ERR_OR_NULL(pol_out)) {
		ASFCTRL_INFO("xfrm policy not found for saddr:%lu(%pI4) daddr:%lu(%pI4) \r\n", touple.ulSrcIp, &(touple.ulSrcIp) , touple.ulDestIp, &(touple.ulDestIp));
		goto drop;
	}

	i = 0;
	struct xfrm_tmpl *tmpl = &pol_out->xfrm_vec[i];
	remote = &tmpl->id.daddr;
	local = &tmpl->saddr;

	if (xfrm_addr_any(local, tmpl->encap_family)) {
		error = xfrm_get_saddr(net, &tmp, remote, tmpl->encap_family);
		if (error)
			goto drop;
		local = &tmp;
	}

	x = xfrm_state_find(remote, local, &fl_out, tmpl, pol_out, &error, AF_INET);
	if (x && !x->asf_sa_cookie) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		error = asfctrl_xfrm_enc_hook(NULL, x, NULL, skb->iif);
#else
		error = asfctrl_xfrm_enc_hook(NULL, x, NULL, skb->skb_iif);
#endif
		if (error) {
			ASFCTRL_INFO("asfctrl_xfrm_enc_hook returned error(%d) for saddr:%lu(%pI4) daddr:%lu(%pI4) \r\n", error, touple.ulSrcIp, &(touple.ulSrcIp) , touple.ulDestIp, &(touple.ulDestIp));
			goto drop;
		}

		error = asfctrl_xfrm_encrypt_n_send(skb, x);
		if (error) {
			ASFCTRL_INFO("asfctrl_xfrm_encrypt_n_send returned error(%d) for saddr:%lu(%pI4) daddr:%lu(%pI4) \r\n", error, touple.ulSrcIp, &(touple.ulSrcIp) , touple.ulDestIp, &(touple.ulDestIp));
			goto drop;
		}
	} else {
		ASFCTRL_INFO("No SA to offload for saddr:%lu(%pI4) daddr:%lu(%pI4) \r\n", touple.ulSrcIp, &(touple.ulSrcIp) , touple.ulDestIp, &(touple.ulDestIp));
		goto drop;
	}
	return;
drop:
	multicast_ct_refresh(&touple);
	kfree_skb(skb);
}
#endif

ASF_void_t asfctrl_ipsec_fn_NoOutSA(ASF_uint32_t ulVsgId,
				ASFFFPFlowTuple_t *tuple,
				ASFBuffer_t *Buffer,
				genericFreeFn_f pFreeFn,
				ASF_void_t   *freeArg,
				ASF_uchar8_t bSPDContainerPresent,
				ASF_uchar8_t bRevalidate)
{
	struct sk_buff  *skb;
	struct iphdr *iph;
	int bVal = in_softirq();

	if (!bVal)
		local_bh_disable();

	ASFCTRL_FUNC_ENTRY;

	skb = AsfBuf2Skb(Buffer);
	iph = ip_hdr(skb);

#ifdef ASFCTRL_IPSEC_SEND_TO_LINUX
	/* Send the packet up for normal path IPsec processing
		(after the NAT) has to be special function */
#ifdef ASF_IPV6_FP_SUPPORT
	if (iph->version == 4) {
#endif
#ifdef ASF_MULTICAST_TERMINATION_SUPPORT
	if (ipv4_is_multicast(iph->daddr)) {
		ASFFFPFlowTuple_t touple;
		memset(&touple, 0 , sizeof(ASFFFPFlowTuple_t));

		touple.bIPv4OrIPv6 = 0;
		touple.ulSrcIp = iph->saddr;
		touple.ulDestIp = iph->daddr;
		touple.ucProtocol = iph->protocol;

		asfctrl_ipsec_fn_Multicast_NoOutSA(touple, skb);
		goto out;
	}
#endif
#if 0
	if (inet_addr_type(dev_net(skb_dst(skb)->dev),
		iph->saddr) == RTN_LOCAL) {
		struct flowi fl;
		struct rtable *rt = skb_rtable(skb);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		int ret;
#endif

		/* Now look for termination route */
		memset(&fl, 0, sizeof(fl));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		fl.nl_u.ip4_u.daddr = iph->daddr;
		ret = ip_route_output_key(&init_net, &rt, &fl);
		if (ret || !rt) {
#else
		fl.u.ip4.daddr = iph->daddr;
		rt = ip_route_output_key(&init_net, &fl.u.ip4);
		if (IS_ERR(rt)) {
#endif
			ASFCTRL_INFO("Route not found for dst %x ",
				iph->daddr);
			goto drop;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
		skb_dst_set(skb, &rt->u.dst);
#else
		skb_dst_set(skb, &rt->dst);
#endif
		skb->dev = skb_dst(skb)->dev;
	} else
#endif
	{
		if (0 != ip_route_input(skb, iph->daddr,
				iph->saddr, 0, skb->dev)) {
			ASFCTRL_INFO("Route not found for dst %x ",
			iph->daddr);
			goto drop;
		}
	}
	ASFCTRL_INFO("Route found for dst %x ", iph->daddr);

	skb->pkt_type = PACKET_HOST;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	skb->iif = skb->dev->ifindex;
#else
	skb->skb_iif = skb->dev->ifindex;
#endif
	ASFCTRL_INFO("NO OUT SA Found Sending Packet Up");
#ifdef ASFCTRL_TERM_FP_SUPPORT
	if (skb->mapped) {
		struct sk_buff *nskb;
		/* Allocate new skb from kernel pool */
		nskb = skb_copy(skb, GFP_ATOMIC);
		if (!nskb)
			goto drop;

		nskb->mapped = 0;
		nskb->gianfar_destructor = 0;
		ip_forward(nskb);
		goto drop;
	} else
#endif
		ip_forward(skb);
#ifdef ASF_IPV6_FP_SUPPORT
	} else {
		ip6_route_input(skb);
		if (!skb_dst(skb)) {
			ASFCTRL_INFO("Route not found for dst");
			goto drop;
		}
		skb->pkt_type = PACKET_HOST;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
		skb->iif = skb->dev->ifindex;
#else
		skb->skb_iif = skb->dev->ifindex;
#endif
		ASFCTRL_INFO("NO OUT SA Found Sending Packet Up");
		ip6_forward(skb);
	}
#endif
	goto out;
#else
	ASFCTRL_WARN("NO OUT SA Found Drop packet");
#endif
drop:
	pFreeFn(Buffer->nativeBuffer);
out:
	if (bRevalidate)
		ASFCTRL_DBG("Revalidation is required");

	if (!bVal)
		local_bh_enable();

	return;
}

ASF_void_t asfctrl_ipsec_fn_VerifySPD(ASF_uint32_t ulVSGId,
					ASF_uint32_t ulInSPDContainerIndex,
					ASF_uint32_t ulMagicNumber,
					ASF_uint32_t ulSPI,
					ASF_uint8_t ucProtocol,
					ASF_IPAddr_t DestAddr,
					ASFBuffer_t *Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t    *freeArg,
					ASF_uchar8_t bRevalidate,
					ASF_uint32_t ulCommonInterfaceId)
{
	struct sk_buff *skb, *skb1;
	struct sk_buff *pOutSkb = NULL;
	struct xfrm_state *x;
	struct net *net;
	struct iphdr *iph;
	xfrm_address_t daddr;
	unsigned short family;
	int bVal = in_softirq();
	if (!bVal)
		local_bh_disable();

	skb = AsfBuf2Skb(Buffer);
	iph = ip_hdr(skb);
	ASFCTRL_DBG("DestAddr %x protocol %x SPI %x",
			DestAddr.ipv4addr, ucProtocol, ulSPI);

#ifdef ASFCTRL_IPSEC_SEND_TO_LINUX
	if (!skb->dev) {
		if (skb_dst(skb))
			skb->dev = skb_dst(skb)->dev;
		else
			ASFCTRL_WARN("No Dev pointer!!");
	}
#ifdef ASFCTRL_TERM_FP_SUPPORT
	if (skb->mapped) {
		struct sk_buff *nskb;
		/* Allocate new skb from kernel pool */
		nskb = skb_copy(skb, GFP_ATOMIC);
		if (unlikely(!nskb)) {
			goto drop;
		} else {
			if (skb_shinfo(skb)->frag_list) {
				struct sk_buff *frag, *frag1;
				frag = skb_shinfo(skb)->frag_list;
				while (frag) {
					frag1 = frag->next;
					frag->next = NULL;
					pFreeFn(frag);
					frag = frag1;
				}
				skb_shinfo(skb)->frag_list = NULL;
				pFreeFn(skb);
			} else
				pFreeFn(Buffer->nativeBuffer);

			skb = nskb;
			Buffer->nativeBuffer = skb;
			pFreeFn = (genericFreeFn_f)kfree_skb;
		}
		skb->mapped = 0;
		skb->gianfar_destructor = 0;
	}
#endif
	/*1.  find the SA (xfrm pointer) on the basis of SPI,
	 * protcol, dest Addr */
	net = dev_net(skb->dev);
	pOutSkb = skb;
#ifdef ASF_IPV6_FP_SUPPORT
	if (DestAddr.bIPv4OrIPv6) {
		memcpy(daddr.a6, DestAddr.ipv6addr, 16);
		family = AF_INET6;
	} else {
#endif
		daddr.a4 = (DestAddr.ipv4addr);
		family = AF_INET;
#ifdef ASF_IPV6_FP_SUPPORT
	}
	if ((iph->version == 6) && (skb_shinfo(skb)->frag_list))
		asfIpv6MakeFragment(skb, &pOutSkb);
#endif
	if (skb_shinfo(skb)->frag_list) {
		struct sk_buff *tmp_skb = skb_shinfo(skb)->frag_list;
		while (tmp_skb) {
			skb->len += tmp_skb->len;
			skb->data_len +=  tmp_skb->len;
			tmp_skb = tmp_skb->next;
		}
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
	x = xfrm_state_lookup(net, 0, &daddr, ulSPI, ucProtocol, family);
#else
	x = xfrm_state_lookup(net, &daddr, ulSPI, ucProtocol, family);
#endif
	if (unlikely(x == NULL)) {
		ASFCTRL_WARN("Unable to retrive SA");
		pFreeFn(Buffer->nativeBuffer);
		goto fnexit;
	}
	{
		struct xfrm_policy *xp = 0;
		if (asfctrl_ipsec_get_policy(pOutSkb, IN_SA, &xp) < 0) {
			pFreeFn(Buffer->nativeBuffer);
			goto out;
		}
		if (xp)
			asfctrl_map_pol_insa(x, xp);
	}
	while (pOutSkb) {
		skb1 = pOutSkb;
		pOutSkb = pOutSkb->next;
		skb1->next = NULL;
		/*2. Set the sec_path security context into the skb */
		/* Allocate new secpath or COW existing one. */
		if (!skb1->sp || atomic_read(&skb1->sp->refcnt) != 1) {
			struct sec_path *sp;

			sp = secpath_dup(skb1->sp);
			if (!sp) {
				/* Drop the packet */
				pFreeFn(Buffer->nativeBuffer);
				goto fnexit;
			}
			if (skb1->sp)
				secpath_put(skb1->sp);
			skb1->sp = sp;
		}

		/*fill the details of secpath */
		skb1->sp->xvec[skb1->sp->len++] = x;

		if (skb1 != skb) {
			xfrm_state_hold(x);
			skb_set_tail_pointer(skb1, skb1->len);
		} else
			skb_set_tail_pointer(skb1, skb_headlen(skb1));
		/*3. send the packet to slow path */
		ASFCTRL_netif_receive_skb(skb1);
		ASFCTRL_WARN(" sent the packet to slow path");
	}

	goto out;
#else
	ASFCTRL_WARN("VerifySPD Fail Found Drop packet");
#endif
#ifdef ASFCTRL_TERM_FP_SUPPORT
drop:
#endif
	pFreeFn(Buffer->nativeBuffer);
out:
	if (bRevalidate)
		ASFCTRL_DBG("Revalidation is required");

fnexit:
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_void_t asfctrl_ipsec_fn_SeqNoOverFlow(ASF_uint32_t ulVSGId,
					ASF_uint32_t ulTunnelId,
					ASF_uint32_t ulSPI,
					ASF_uint8_t ucProtocol,
					ASF_IPAddr_t  DestAddr)
{
	struct xfrm_state *x;
	xfrm_address_t daddr;
	unsigned short family;
	int bVal = in_softirq();

	ASFCTRL_FUNC_TRACE;

	if (!bVal)
	local_bh_disable();

	ASFCTRL_WARN("Sequence Number Overflow\n");

	 /*1. find the SA (xfrm pointer) on the basis of SPI,
	 * protcol, dest Addr */

	family = AF_INET;
	daddr.a4 = (DestAddr.ipv4addr);

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
	x = xfrm_state_lookup(&init_net, 0, &daddr, ulSPI, ucProtocol, family);
#else
	x = xfrm_state_lookup(&init_net, &daddr, ulSPI, ucProtocol, family);
#endif
	if (unlikely(!x)) {
		ASFCTRL_INFO("Unable to get SA SPI=0x%x, dest=0x%x",
		ulSPI, daddr.a4);
		goto back;
	}
	if (unlikely(x->km.state != XFRM_STATE_VALID)) {
		ASFCTRL_INFO("Invalid SA SPI=0x%x, dest=0x%x",
		ulSPI, daddr.a4);
		goto back;
	}

	x->km.dying = 1;

	km_state_expired(x, 0, 0);
back:
	if (!bVal)
		local_bh_enable();
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_ipsec_fn_PeerGatewayChange(ASF_uint32_t ulVSGId,
					ASF_uint32_t ulInSPDContainerIndex,
					ASF_uint32_t ulSPI,
					ASF_uint8_t  ucProtocol,
					ASF_IPAddr_t OldDstAddr,
					ASF_IPAddr_t NewDstAddr,
					ASF_uint16_t usOldPort,
					ASF_uint16_t usNewPort)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_ipsec_fn_audit_log(ASFLogInfo_t *pIPSecV4Info)
{
	int bVal = in_softirq();
	if (!bVal)
		local_bh_disable();

	/* Filling the Loging message fields, IPSec module specific fileds  */
	ASFCTRL_FUNC_TRACE;

	ASFCTRL_TRACE("%s-SA, SPI=0x%x, Proto=%d, "\
			"Dst IPAddr= 0x%x,  Src IPAddr= 0x%x PathMTU=%d,",
		XFRM_DIR(pIPSecV4Info->u.IPSecInfo.ucDirection),
		pIPSecV4Info->u.IPSecInfo.ulSPI,
		pIPSecV4Info->u.IPSecInfo.ucProtocol,
		pIPSecV4Info->u.IPSecInfo.Address.dstIP.ipv4addr,
		pIPSecV4Info->u.IPSecInfo.Address.srcIP.ipv4addr,
		pIPSecV4Info->u.IPSecInfo.ulPathMTU);

	ASFCTRL_TRACE("Msg (%d)= %s", pIPSecV4Info->ulMsgId,
		pIPSecV4Info->aMsg ? pIPSecV4Info->aMsg : "null");

	/*pIPSecV4Info->u.IPSecInfo.ulSeqNumber*/
	ASFCTRL_TRACE("Num of Pkts = %u\nNumof Bytes = %u",
		pIPSecV4Info->u.IPSecInfo.ulNumOfPktsProcessed,
		pIPSecV4Info->u.IPSecInfo.ulNumOfBytesProcessed);

	if (!bVal)
		local_bh_enable();
	return;
}

/*If the policy offload fails, need to reset the cookie in the
 * linux do we need it for the sync-SMP mode of ASF-Linux */
ASF_void_t asfctrl_ipsec_fn_Config(ASF_uint32_t ulVSGId,
				ASF_uint32_t Cmd,
				ASF_uint32_t Response,
				ASF_void_t  *pRequestIdentifier,
				ASF_uint32_t ulRequestIdentifierLen,
				ASF_uint32_t ulResult)
{
	int bVal = in_softirq();
	struct xfrm_policy *xp = (struct xfrm_policy *)pRequestIdentifier;

	ASFCTRL_FUNC_TRACE;
	if (!bVal)
		local_bh_disable();

	if (Response != T_SUCCESS) {
		if (Cmd == ASF_IPSEC_CONFIG_ADD_OUTSPDCONTAINER) {
			free_container_index(xp, ASF_OUT_CONTANER_ID);
		} else if (Cmd == ASF_IPSEC_CONFIG_ADD_INSPDCONTAINER) {
			free_container_index(xp, ASF_IN_CONTANER_ID);
		};
	}
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_void_t asfctrl_ipsec_fn_RefreshL2Blob(ASF_uint32_t ulVSGId,
				ASF_uint32_t ultunnelId,
				ASF_uint32_t ulOutSPDContainerIndex,
				ASF_uint32_t ulOutSPDmagicNumber,
				ASF_IPSecTunEndAddr_t *address,
				ASF_uint32_t ulSPI,
				ASF_uint8_t  ucProtocol)
{
	struct sk_buff *skb;
	int bVal = in_softirq();
	ASFCTRL_FUNC_TRACE;
	if (!bVal)
		local_bh_disable();
	/* Generate Dummy packet */
	skb = ASFCTRLKernelSkbAlloc(1024, GFP_ATOMIC);
	if (skb) {
		struct iphdr *iph;
		ASF_uint32_t *pData;
		ASFIPSecRuntimeModOutSAArgs_t *pSAData;
		static unsigned short IPv4_IDs[NR_CPUS];
		struct flowi fl = {};
#ifdef ASF_IPV6_FP_SUPPORT
		if (address->IP_Version == 4) {
#endif
			struct rtable *rt;
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			fl.nl_u.ip4_u.daddr = address->dstIP.ipv4addr;
			fl.nl_u.ip4_u.saddr = address->srcIP.ipv4addr;
			fl.proto = IPPROTO_ICMP;

			if (ip_route_output_key(&init_net, &rt, &fl)) {
		#else
			fl.u.ip4.daddr = address->dstIP.ipv4addr;
			fl.u.ip4.saddr = address->srcIP.ipv4addr;
			fl.u.flowi4_oif = 0;
			fl.u.flowi4_flags = FLOWI_FLAG_ANYSRC;

			rt = ip_route_output_key(&init_net, &fl.u.ip4);
			if (IS_ERR(rt)) {
		#endif
				ASFCTRL_DBG("\n Route not found for dst %x\n",\
							address->dstIP.ipv4addr);
				ASFCTRLKernelSkbFree(skb);
				goto out;
			}

		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			skb_dst_set(skb, &(rt->u.dst));
		#else
			skb_dst_set(skb, &(rt->dst));
		#endif
			ASFCTRL_DBG("Route found for dst %x ",
						address->dstIP.ipv4addr);
			skb->dev = skb_dst(skb)->dev;
			ASFCTRL_DBG("skb->devname: %s", skb->dev->name);
			skb_reserve(skb, LL_RESERVED_SPACE(skb->dev));
			skb_reset_network_header(skb);
			skb_put(skb, sizeof(struct iphdr));
			iph = ip_hdr(skb);
			iph->version = 5;
			iph->ihl = 5;
			iph->ttl = 1;
			iph->id = IPv4_IDs[smp_processor_id()]++;
			iph->tos = 0;
			iph->frag_off = 0;
			iph->saddr = (address->srcIP.ipv4addr);
			iph->daddr = (address->dstIP.ipv4addr);
			iph->protocol = ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB;
			skb->protocol = htons(ETH_P_IP);
#ifdef ASF_IPV6_FP_SUPPORT
		} else if (address->IP_Version == 6) {
			struct dst_entry *dst;
			struct ipv6hdr *ipv6h;
		#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
			memcpy(fl.fl6_src.s6_addr32,
					address->srcIP.ipv6addr, 16);
			memcpy(fl.fl6_dst.s6_addr32,
					address->dstIP.ipv6addr, 16);
			fl.proto = IPPROTO_ICMPV6;
			dst = ip6_route_output(&init_net, NULL, &fl);
		#else
			memcpy(fl.u.ip6.saddr.s6_addr,
					address->srcIP.ipv6addr, 16);
			memcpy(fl.u.ip6.daddr.s6_addr,
					address->dstIP.ipv6addr, 16);
			fl.u.__fl_common.flowic_proto = IPPROTO_ICMPV6;
			dst = ip6_route_output(&init_net, NULL, &fl.u.ip6);
		#endif
			if (!dst || dst->error)	{
				ASFCTRL_DBG("\n Route not found for dst %x"\
						"skb->dst: 0x%x",
						address->dstIP.ipv6addr,
						skb_dst(skb));
				ASFCTRLKernelSkbFree(skb);
				goto out;
			}

			skb_dst_set(skb, dst);
			ASFCTRL_DBG("Route found for dst %x ",
					address->dstIP.ipv4addr);
			skb->dev = skb_dst(skb)->dev;
			ASFCTRL_DBG("devname is skb->devname: %s ",
					skb->dev->name);
			skb_reserve(skb, LL_RESERVED_SPACE(skb->dev));
			skb_reset_network_header(skb);
			skb_put(skb, sizeof(struct ipv6hdr));
			ipv6h = ipv6_hdr(skb);

			ipv6h->version = 5;
			ipv6h->priority = 0;
			ipv6h->payload_len =
				(sizeof(ASFIPSecRuntimeModOutSAArgs_t));
			memset(ipv6h->flow_lbl , 0, 3);
			ipv6h->hop_limit = 1;
			memcpy(ipv6h->saddr.s6_addr32,
				address->srcIP.ipv6addr, 16);
			memcpy(ipv6h->daddr.s6_addr32,
				address->dstIP.ipv6addr, 16);

			ipv6h->nexthdr = ASFCTRL_IPPROTO_DUMMY_IPSEC_L2BLOB;
			skb->protocol = htons(ETH_P_IPV6);
			skb_set_transport_header(skb, sizeof(struct ipv6hdr));
			IP6CB(skb)->nhoff = offsetof(struct ipv6hdr, nexthdr);

		}
#endif
		pData = (ASF_uint32_t *)skb_put(skb,
				sizeof(ASF_uint32_t) +
				sizeof(ASFIPSecRuntimeModOutSAArgs_t));
		*pData++ = ulVSGId;
		pSAData = (ASFIPSecRuntimeModOutSAArgs_t *)pData;
		pSAData->ulTunnelId = ultunnelId;
		memcpy(&pSAData->DestAddr,
			&address->dstIP, sizeof(ASF_IPAddr_t));
		pSAData->ulSPDContainerIndex =  ulOutSPDContainerIndex;
		pSAData->ulSPDContainerMagicNumber = ulOutSPDmagicNumber;
		pSAData->ucProtocol = ucProtocol;
		pSAData->ulSPI = ulSPI;
		pSAData->ucChangeType = 2;
		pSAData->u.ulMtu  = skb->dev->mtu;
		ASFCTRL_DBG("MTU is %d", skb->dev->mtu);

		asfctrl_skb_mark_dummy(skb);
		asf_ip_send(skb);
	}
out:
	if (!bVal)
		local_bh_enable();
	return;
}

ASF_void_t asfctrl_ipsec_fn_DPDAlive(ASF_uint32_t ulVSGId,
				ASF_uint32_t ulTunnelId,
				ASF_uint32_t ulSPI,
				ASF_uint8_t ucProtocol,
				ASF_IPAddr_t DestAddr,
				ASF_uint32_t ulSPDContainerIndex)
{
	ASFCTRL_FUNC_TRACE;
	return;
}


ASF_void_t asfctrl_ipsec_fn_NoOutFlowFound(ASF_uint32_t ulVSGId,
					ASF_IPAddr_t srcAddr,
					ASF_IPAddr_t destAddr,
					ASF_uint8_t  ucProtocol,
					ASF_uint16_t srcPort,
					ASF_uint16_t destPort,
					ASFBuffer_t *Buffer,
					genericFreeFn_f pFreeFn,
					ASF_void_t *freeArg)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_ipsec_fn_VSGMappingNotFound(
				ASF_uint32_t ulCommonInterfaceid,
				ASFFFPFlowTuple_t tuple,
				ASFBuffer_t *Buffer,
				genericFreeFn_f pFreeFn,
				ASF_void_t *freeArg)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t  asfctrl_ipsec_fn_InterfaceInfoNotFound(ASFFFPFlowTuple_t tuple,
						ASFBuffer_t *Buffer,
						genericFreeFn_f pFreeFn,
						ASF_void_t *freeArg)
{
	ASFCTRL_FUNC_TRACE;
	return;
}


ASF_void_t asfctrl_ipsec_fn_Runtime(ASF_uint32_t ulVSGId,
				ASF_uint32_t Cmd,
				ASF_void_t  *pRequestIdentifier,
				ASF_uint32_t ulRequestIdentifierLen,
				ASF_void_t  *pResult,
				ASF_uint32_t ulResultLen)
{
	ASFCTRL_FUNC_TRACE;
	return;
}

ASF_void_t asfctrl_ipsec_fn_SAExpired(ASF_uint32_t ulVSGId,
			ASF_uint32_t ulSPDContainerIndex,
			ASF_uint32_t ulSPI,
			ASF_uint8_t ucProtocol,
			ASF_IPAddr_t DestAddr,
			ASF_uchar8_t bHardExpiry,
			ASF_uchar8_t bOutBound)
{
	struct xfrm_state *x;
	xfrm_address_t daddr;
	unsigned short family;
	int bVal = in_softirq();
	if (!bVal)
		local_bh_disable();

	ASFCTRL_FUNC_TRACE;
	ASFCTRL_WARN("SA Expired (dir=%d) hard=%d for SPI = 0x%x",
		bOutBound, bHardExpiry, ulSPI);

	/*1.  find the SA (xfrm pointer) on the basis of SPI,
	 * protcol, dest Addr */

	if (DestAddr.bIPv4OrIPv6) {
		family = AF_INET6;
		memcpy(daddr.a6, DestAddr.ipv6addr, 16);
	} else {
		family = AF_INET;
		daddr.a4 = (DestAddr.ipv4addr);
	}
#if (LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 34))
	x = xfrm_state_lookup(&init_net, 0, &daddr, ulSPI, ucProtocol, family);
#else
	x = xfrm_state_lookup(&init_net, &daddr, ulSPI, ucProtocol, family);
#endif
	if (unlikely(!x)) {
		ASFCTRL_INFO("Unable to get SA SPI=0x%x, dest=0x%x",
				ulSPI, daddr.a4);
		goto back;
	}
	if (unlikely(x->km.state != XFRM_STATE_VALID)) {
		ASFCTRL_INFO("Invalid SA SPI=0x%x, dest=0x%x",
				ulSPI, daddr.a4);
		goto back;
	}

	x->km.dying = 1;

	if (bHardExpiry) {
		x->km.state = XFRM_STATE_EXPIRED;
		km_state_expired(x, 1, 0);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
	tasklet_hrtimer_start(&x->timer, ktime_set(0, 0),
				HRTIMER_MODE_REL);
#else
	tasklet_hrtimer_start(&x->mtimer, ktime_set(0, 0),
				HRTIMER_MODE_REL);
#endif
	} else
		km_state_expired(x, 0, 0);
back:
	if (!bVal)
		local_bh_enable();
	return;
}


ASF_void_t asfctrl_ipsec_l2blob_update_fn(struct sk_buff *skb,
					ASF_uint32_t hh_len,
					ASF_uint16_t ulDeviceID)
{
	ASFIPSecRuntimeModOutSAArgs_t *pSAData;
	ASF_uint32_t ulVSGId;
	ASF_void_t *pData;
	struct iphdr *iph;

	ASFCTRL_FUNC_TRACE;

	iph = (struct iphdr *)(skb->data + hh_len);

#ifdef ASF_IPV6_FP_SUPPORT
	if (skb->protocol == ETH_P_IPV6)
		pData = skb->data + hh_len + sizeof(struct ipv6hdr);
	else
#endif
	pData = skb->data + hh_len + (iph->ihl * 4);

	ulVSGId = *(ASF_uint32_t *)pData;

	pSAData = (ASFIPSecRuntimeModOutSAArgs_t *)((ASF_uchar8_t *)pData + 4);

	if (pSAData->ucChangeType == ASFIPSEC_UPDATE_MTU) {
		ASFIPSecRuntime(ulVSGId, ASF_IPSEC_RUNTIME_MOD_OUTSA, pSAData,
			sizeof(ASFIPSecRuntimeModOutSAArgs_t), NULL, 0);
	}

	pSAData->ucChangeType = ASFIPSEC_UPDATE_L2BLOB;
	pSAData->u.l2blob.ulDeviceID = ulDeviceID;
	pSAData->u.l2blob.ulL2BlobLen =  hh_len;
	memcpy(&pSAData->u.l2blob.l2blob, skb->data,
			pSAData->u.l2blob.ulL2BlobLen);
#ifdef CONFIG_VLAN_8021Q
	if (vlan_tx_tag_present(skb)) {
		pSAData->u.l2blob.bTxVlan = 1;
		pSAData->u.l2blob.usTxVlanId = (vlan_tx_tag_get(skb)
							| VLAN_TAG_PRESENT);
	} else
#endif
		pSAData->u.l2blob.bTxVlan = 0;
	pSAData->u.l2blob.bUpdatePPPoELen = 0;
	pSAData->u.l2blob.ulL2blobMagicNumber =
		asfctrl_vsg_l2blobconfig_id[ulVSGId];
	ASFIPSecRuntime(ulVSGId, ASF_IPSEC_RUNTIME_MOD_OUTSA, pSAData,
			sizeof(ASFIPSecRuntimeModOutSAArgs_t), NULL, 0);
	return;
}

int asfctrl_ipsec_get_policy4(struct sk_buff *skb, int dir, struct xfrm_policy **pol)
{
	int err = 0;
	struct net *net;
	struct iphdr *iph = ip_hdr(skb);
	struct flowi fl;
	__be16 *ports = (__be16 *) (skb_network_header(skb) + iph->ihl * 4);

	ASFCTRL_FUNC_TRACE;
	if (skb->dev)
		net = dev_net(skb->dev);
	else
		net = dev_net(skb_dst(skb)->dev);

	memset(&fl, 0, sizeof(struct flowi));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	fl.proto = iph->protocol;
	fl.fl4_dst = iph->daddr;
	fl.fl4_src = iph->saddr;
	fl.fl4_tos = iph->tos;
	fl.iif = skb->iif;
	fl.fl_ip_sport = ports[0];
	fl.fl_ip_dport = ports[1];
#else
	fl.u.ip4.fl4_sport = ports[0];
	fl.u.ip4.fl4_dport = ports[1];
	fl.flowi_proto = iph->protocol;
	fl.u.ip4.daddr = iph->daddr;
	fl.u.ip4.saddr = iph->saddr;
	fl.flowi_tos = iph->tos;
	fl.flowi_iif = skb->skb_iif;
#endif

	ASFCTRL_DBG("\nflow info:\n");
	ASFCTRL_DBG("\n src addr %x dst addr %x\n", fl.u.ip4.saddr, fl.u.ip4.daddr);
	ASFCTRL_DBG("\n src port %d, dst port %d proto %d tos %d iif %d\n",
	fl.u.ip4.fl4_sport, fl.u.ip4.fl4_dport, fl.flowi_proto, fl.flowi_tos, fl.flowi_iif);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        *pol = __xfrm_policy_lookup(net, &fl, AF_INET, dir);
#else
        *pol = xfrm_policy_check_flow(net, &fl, AF_INET, dir);
#endif
	if (IS_ERR_OR_NULL(*pol)) {
		ASFCTRL_DBG("\nPolicy Not Found");
		return -EINVAL;
	}
	ASFCTRL_DBG("\nxfrm policy - net = %x, pol =%x", net, *pol);

	err = is_policy_offloadable(*pol);
	if (err)
		err = -EINVAL;

	return err;
}

int asfctrl_ipsec_get_policy6(struct sk_buff *skb, int dir, struct xfrm_policy **pol)
{
	int err = 0;
	struct net *net;
	struct ipv6hdr *hdr = ipv6_hdr(skb);
	struct flowi fl;
	u16 offset = skb_network_header_len(skb);
	const unsigned char *nh = skb_network_header(skb);
	__be16 *ports = (__be16 *)(nh + offset);

ASFCTRL_FUNC_TRACE;
	if (skb->dev)
		net = dev_net(skb->dev);
	else
		net = dev_net(skb_dst(skb)->dev);

	memset(&fl, 0, sizeof(struct flowi));
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 36)
	ipv6_addr_copy(&fl.fl6_dst, &hdr->daddr);
	ipv6_addr_copy(&fl.fl6_src, &hdr->saddr);

	fl.proto = hdr->nexthdr;
	fl.fl6_flowlabel = hdr->flow_lbl;
	fl.iif = skb->iif;

	fl.fl_ip_sport = ports[0];
	fl.fl_ip_dport = ports[1];
#else
	ipv6_addr_copy(&fl.u.ip6.daddr, &hdr->daddr);
	ipv6_addr_copy(&fl.u.ip6.saddr, &hdr->saddr);

	fl.flowi_proto = hdr->nexthdr;
	fl.flowi_tos = ((hdr->priority << 4) | (hdr->flow_lbl[0] >> 4));
	fl.flowi_iif = skb->skb_iif;

	fl.u.ip6.fl6_sport = ports[0];
	fl.u.ip6.fl6_dport = ports[1];
#endif

	ASFCTRL_DBG("\nflow info:\n");
	ASFCTRL_DBG("\n src addr %x dst addr %x\n", fl.u.ip4.saddr, fl.u.ip4.daddr);
	ASFCTRL_DBG("\n src port %d, dst port %d proto %d tos %d iif %d\n",
	fl.u.ip4.fl4_sport, fl.u.ip4.fl4_dport, fl.flowi_proto, fl.flowi_tos, fl.flowi_iif);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
        *pol = __xfrm_policy_lookup(net, &fl, AF_INET6, dir);
#else
        *pol = xfrm_policy_check_flow(net, &fl, AF_INET6, dir);
#endif

	ASFCTRL_DBG("xfrm policy - net = %x, pol =%x", net, *pol);
	if (IS_ERR_OR_NULL(*pol)) {
		ASFCTRL_DBG("\nPolicy Not Found");
		return -EINVAL;
	}

	err = is_policy_offloadable(*pol);
	if (err)
		err = -EINVAL;

	return err;
}

int asfctrl_ipsec_get_policy(struct sk_buff *skb, int dir, struct xfrm_policy **pol)
{
	struct iphdr *iph = ip_hdr(skb);

	if (iph->version == 4)
		return asfctrl_ipsec_get_policy4(skb, dir, pol);
	else
		return asfctrl_ipsec_get_policy6(skb, dir, pol);
}

void asfctrl_ipsec_update_vsg_magic_number(ASF_uint32_t ulVSGId)
{
	ASFIPSecUpdateVSGMagicNumber_t VSGMagicInfo;
	ASFCTRL_FUNC_TRACE;
	VSGMagicInfo.ulVSGId = ulVSGId;
	VSGMagicInfo.ulVSGMagicNumber = asfctrl_vsg_config_id[ulVSGId];
	VSGMagicInfo.ulL2blobMagicNumber = asfctrl_vsg_l2blobconfig_id[ulVSGId];
	ASFIPSecUpdateVSGMagicNumber(&VSGMagicInfo);
	return ;
}

int asfctrl_ipsec_get_flow_info_fn(uint32_t ulVSGId, bool *ipsec_in,
				bool *ipsec_out,
				ASFFFPIpsecInfo_t *ipsecInInfo,
				struct net *net,
				struct flowi fl, bool bIsIpv6)
{
	struct xfrm_policy *pol_out = 0, *pol_in = 0;
	int err = 0;
	ASFFFPIpsecContainerInfo_t *outInfo;
	ASFFFPIpsecContainerInfo_t *inInfo;

	ASFCTRL_FUNC_TRACE;
	*ipsec_in = ASF_FALSE;
	*ipsec_out = ASF_FALSE;
#ifdef ASF_IPV6_FP_SUPPORT
	if (bIsIpv6) {
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
		pol_out = __xfrm_policy_lookup(net, &fl, AF_INET6, FLOW_DIR_OUT);
		pol_in = __xfrm_policy_lookup(net, &fl, AF_INET6, FLOW_DIR_IN);
#else
		pol_out = xfrm_policy_check_flow(net, &fl, AF_INET6, FLOW_DIR_OUT);
		pol_in = xfrm_policy_check_flow(net, &fl, AF_INET6, FLOW_DIR_IN);
#endif
	} else {
#endif
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
		pol_out = __xfrm_policy_lookup(net, &fl, AF_INET, FLOW_DIR_OUT);
		pol_in = __xfrm_policy_lookup(net, &fl, AF_INET, FLOW_DIR_IN);
#else
		pol_out = xfrm_policy_check_flow(net, &fl, AF_INET, FLOW_DIR_OUT);
		pol_in = xfrm_policy_check_flow(net, &fl, AF_INET, FLOW_DIR_IN);
#endif
#ifdef ASF_IPV6_FP_SUPPORT
	}
#endif

	ASFCTRL_DBG("xfrm policy - net = %x pol_out=%x, pol_in=%x",
			net, pol_out, pol_in);
	if (!IS_ERR_OR_NULL(pol_out)) {
		err = is_policy_offloadable(pol_out);
		if (err)
			goto ret_err;
		outInfo = &(ipsecInInfo->outContainerInfo);
		*ipsec_out = ASF_TRUE;
		outInfo->ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		outInfo->ulSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		outInfo->ulSPDContainerId = pol_out->asf_cookie - 1;
		outInfo->ulCSAMagicNumber = 0;
		outInfo->configIdentity.ulVSGConfigMagicNumber =
					asfctrl_vsg_config_id[ulVSGId];
		outInfo->configIdentity.ulTunnelConfigMagicNumber =
					ASF_DEF_IPSEC_TUNNEL_MAGIC_NUM;
		outInfo->bControlPathPkt = ASF_FALSE;
		ASFCTRL_DBG("vsg id %d magicnum %d contId %d",
				outInfo->configIdentity.ulVSGConfigMagicNumber,
				outInfo->ulSPDMagicNumber,
				outInfo->ulSPDContainerId);
		/* Invalidate the SA info as 0 is a valid index */
		ipsecInInfo->outSAInfo.ulSAIndex = SECFP_MAX_SAS;
		ipsecInInfo->outSAInfo.ulSAMagicNumber = -1;
	}
	if (!IS_ERR_OR_NULL(pol_in)) {
		err = is_policy_offloadable(pol_in);
		if (err)
			goto ret_err;
		inInfo = &(ipsecInInfo->inContainerInfo);
		*ipsec_in = ASF_TRUE;
		inInfo->ulTunnelId = ASF_DEF_IPSEC_TUNNEL_ID;
		inInfo->ulSPDMagicNumber = asfctrl_vsg_ipsec_cont_magic_id;
		inInfo->ulSPDContainerId = pol_in->asf_cookie - 1;
		inInfo->configIdentity.ulVSGConfigMagicNumber =
					asfctrl_vsg_config_id[ulVSGId];
		inInfo->configIdentity.ulTunnelConfigMagicNumber =
					ASF_DEF_IPSEC_TUNNEL_MAGIC_NUM;
		inInfo->bControlPathPkt = ASF_FALSE;
		ASFCTRL_DBG("vsg id %d magicnum %d contId %d",
				inInfo->configIdentity.ulVSGConfigMagicNumber,
				inInfo->ulSPDMagicNumber,
				inInfo->ulSPDContainerId);

	}
	ASFCTRL_DBG("IPSEC : In =%d, Out =%d", *ipsec_in, *ipsec_out);
ret_err:
	return err;
}

static int __init asfctrl_linux_ipsec_init(void)
{
	ASFIPSecCbFn_t Fnptr;
	ASFCap_t  asf_cap;
	ASFIPSecInitConfigIdentity_t  confId;
	unsigned int *ulVSGMagicNumber;
	unsigned int *ulVSGL2blobMagicNumber;
	unsigned int **ulTunnelMagicNumber;
	int i, j;

	ASFGetCapabilities(&asf_cap);
	if (!asf_cap.func.bIPsec) {
		ASFCTRL_ERR("IPSEC Not supported in ASF");
		return -EPERM;
	}

	ASFIPSecSetNotifyPreference(ASF_ASYNC_RESPONSE);

	ASFIPSecGetCapabilities(&g_ipsec_cap);

	if (!g_ipsec_cap.bBufferHomogenous) {
		/* Hetrogenous */
		ASFCTRL_ERR("Hetrogeneous buffers not supported\r\n");
		return -EINVAL;
	}
	ulVSGMagicNumber = kzalloc(sizeof(unsigned int *) * ASF_MAX_VSGS,
				GFP_KERNEL);
	ulVSGL2blobMagicNumber =
		kzalloc(sizeof(unsigned int *) * ASF_MAX_VSGS, GFP_KERNEL);
	ulTunnelMagicNumber = kzalloc(sizeof(unsigned int *) * ASF_MAX_VSGS,
				GFP_KERNEL);
	for (i = 0; i < ASF_MAX_VSGS; i++)
		ulTunnelMagicNumber[i] = kzalloc(sizeof(unsigned int) *
			ASF_MAX_TUNNEL, GFP_KERNEL);
	/* If ASF supports less than what our arrays are designed for */
	if (g_ipsec_cap.ulMaxSupportedIPSecSAs < SECFP_MAX_SAS)
		asfctrl_max_sas = g_ipsec_cap.ulMaxSupportedIPSecSAs;

	if (g_ipsec_cap.ulMaxSPDContainers < ASFCTRL_MAX_SPD_CONTAINERS)
		asfctrl_max_policy_cont = g_ipsec_cap.ulMaxSPDContainers;

	asfctrl_vsg_ipsec_cont_magic_id = jiffies;
	/* Updating the existing Config ID in ASF IPSEC */
	confId.ulMaxVSGs = ASF_MAX_VSGS;
	confId.ulMaxTunnels = ASF_MAX_TUNNEL;
	for (i = 0; i < ASF_MAX_VSGS; i++) {
		ulVSGMagicNumber[i] = asfctrl_vsg_config_id[i];
		ulVSGL2blobMagicNumber[i] = asfctrl_vsg_l2blobconfig_id[i];
		for (j = 0; j < ASF_MAX_TUNNEL; j++)
			ulTunnelMagicNumber[i][j] =
				ASF_DEF_IPSEC_TUNNEL_MAGIC_NUM;
	}
	confId.pulVSGMagicNumber = ulVSGMagicNumber;
	confId.pulVSGL2blobMagicNumber = ulVSGL2blobMagicNumber;
	confId.pulTunnelMagicNumber = ulTunnelMagicNumber;

	ASFIPSecInitConfigIdentity(&confId);

	kfree(ulVSGMagicNumber);
	kfree(ulVSGL2blobMagicNumber);
	for (i = 0; i < ASF_MAX_VSGS; i++)
		kfree(ulTunnelMagicNumber[i]);
	kfree(ulTunnelMagicNumber);

	register_ipsec_offload_hook(&asf_sec_fns);
	asfctrl_ipsec_km_register();

	Fnptr.pFnNoInSA  = asfctrl_ipsec_fn_NoInSA;
	Fnptr.pFnNoOutSA = asfctrl_ipsec_fn_NoOutSA;
	Fnptr.pFnVerifySPD = asfctrl_ipsec_fn_VerifySPD;
	Fnptr.pFnRefreshL2Blob = asfctrl_ipsec_fn_RefreshL2Blob;
	Fnptr.pFnDPDAlive = asfctrl_ipsec_fn_DPDAlive;
	Fnptr.pFnSeqNoOverFlow = asfctrl_ipsec_fn_SeqNoOverFlow;
	Fnptr.pFnPeerChange = asfctrl_ipsec_fn_PeerGatewayChange;
	Fnptr.pFnAuditLog = asfctrl_ipsec_fn_audit_log;
	Fnptr.pFnNoOutFlow = asfctrl_ipsec_fn_NoOutFlowFound;
	Fnptr.pFnConfig = asfctrl_ipsec_fn_Config;
	Fnptr.pFnRuntime = asfctrl_ipsec_fn_Runtime;
	Fnptr.pFnVSGMap = asfctrl_ipsec_fn_VSGMappingNotFound;
	Fnptr.pFnIfaceNotFound = asfctrl_ipsec_fn_InterfaceInfoNotFound;
	if (bPacketBasedExpiry || bVolumeBasedExpiry)
		Fnptr.pFnSAExpired = asfctrl_ipsec_fn_SAExpired;
	else
		Fnptr.pFnSAExpired = NULL;

	ASFIPSecRegisterCallbacks(&Fnptr);

	asfctrl_register_ipsec_func(asfctrl_ipsec_get_flow_info_fn,
				asfctrl_ipsec_l2blob_update_fn,
				asfctrl_ipsec_update_vsg_magic_number);
	init_container_indexes(ASF_TRUE);
	init_sa_indexes(ASF_TRUE);
	ASFCTRL_DBG("ASF Control Module - IPsec Loaded\n");
	return 0;
}


static void __exit asfctrl_linux_ipsec__exit(void)
{
	ASFIPSecCbFn_t Fnptr;
	memset(&Fnptr, 0, sizeof(ASFIPSecCbFn_t));
	ASFIPSecRegisterCallbacks(&Fnptr);
	asfctrl_register_ipsec_func(NULL, NULL, NULL);
	asfctrl_ipsec_km_unregister();
	unregister_ipsec_offload_hook();
	ASFIPSecFlushContainers(ASF_DEF_VSG, ASF_DEF_IPSEC_TUNNEL_ID);
	ASFCTRL_DBG("ASF Control Module - IPsec Unloaded\n");
}

module_init(asfctrl_linux_ipsec_init);
module_exit(asfctrl_linux_ipsec__exit);
