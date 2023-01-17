/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfipv6core.c
 *
 * Description: Main module for ASF Core initialization and Firewall Handling.
 *
 * Authors:	Arun Pathak <B33046@freescale.com>
 *
 */
/******************************************************************************/

#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/io.h>
#include <net/xfrm.h>
#ifdef ASF_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "gplcode.h"
#include "asf.h"
#include "asfcmn.h"
#include "asfipsec.h"
#include "asfparry.h"
#include "asfmpool.h"
#include "asftmr.h"
#include "asfreasm.h"
#include "asfpvt.h"
#include "asftcp.h"
#include "asfipv6pvt.h"
#ifdef CONFIG_DPA
#include <dpa1p8/dpaa_eth.h>
#include <dpa1p8/dpaa_eth_common.h>
#endif

#define ASF_DO_INC_CHECKSUM

int ffp_ipv6_max_flows = ASF_FFP_IPV6_MAX_FLOWS;
int ffp_ipv6_hash_buckets = ASF_FFP_IPV6_MAX_HASH_BKT;

ptrIArry_tbl_t ffp_ipv6_ptrary;
ffp_bucket_t *ffp_ipv6_flow_table;

static unsigned int  ffp_ipv6_flow_pool_id = -1;

unsigned long asf_ffp_ipv6_hash_init_value;
EXPORT_SYMBOL(asf_ffp_ipv6_hash_init_value);


static int asf_ffp_ipv6_init_flow_table(void);
static void asf_ffp_ipv6_destroy_flow_table(void);
static inline void ffp_copy_flow_stats(ffp_flow_t *flow, ASFFFPFlowStats_t *stats)
{
	if (flow) {
		stats->ulInPkts = htonl(flow->stats.ulInPkts);
		stats->ulOutPkts = htonl(flow->stats.ulOutPkts);
		stats->ulInBytes = htonl(flow->stats.ulInBytes);
		stats->ulOutBytes = htonl(flow->stats.ulOutBytes);
	} else
		memset(stats, 0, sizeof(*stats));
}



ffp_flow_t *ffp_ipv6_flow_alloc(void)
{
	char bHeap;
	ffp_flow_t	*flow;
	ASFFFPGlobalStats_t	*gstats = asfPerCpuPtr(asf_gstats,
						smp_processor_id());

	flow = (ffp_flow_t *)  asfGetNode(ffp_ipv6_flow_pool_id, &bHeap);
	if (flow) {
		/*memset(flow, 0, sizeof(*flow)); */
		gstats->ulFlowAllocs++;
		flow->bHeap = bHeap;
	} else
		gstats->ulFlowAllocFailures++;

	return flow;
}

void ffp_ipv6_flow_free(ffp_flow_t *flow)
{
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats,
					smp_processor_id());
	asfReleaseNode(ffp_ipv6_flow_pool_id, flow, flow->bHeap);
	gstats->ulFlowFrees++;
}

#define flow_list_for_each(pos, head) \
for (pos = (head)->pNext; prefetch(pos->pNext), pos != (head); \
			pos = pos->pNext)

inline ffp_flow_t *asf_ffp_ipv6_flow_lookup_in_bkt(
				ASF_IPv6Addr_t *sip, ASF_IPv6Addr_t *dip,
				unsigned long ports, unsigned char protocol,
				unsigned long vsg, unsigned long szone,
				ffp_flow_t *pHead)
{
	ffp_flow_t      *flow;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
		if (!(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6SrcIp), (struct in6_addr *)sip))
		&& !(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6DestIp), (struct in6_addr *)dip))
		&& (flow->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		&& (flow->ucProtocol == protocol)
		&& (flow->ulZoneId == szone)
		&& (flow->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
			) {
			return flow;
		}
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_debug("Max (%u) scanned ... aborting search!\n", SEARCH_MAX_PER_BUCKET);
			return NULL;
		}
#endif
	}
	return NULL;
}

ffp_flow_t *asf_ffp_ipv6_flow_lookup_in_bkt_ex(ASFFFPFlowTuple_t *tuple,
				unsigned long ulVsgId,
				unsigned long ulZoneId,
				ffp_flow_t *pHead)
{
	return asf_ffp_ipv6_flow_lookup_in_bkt((ASF_IPv6Addr_t *)(tuple->ipv6SrcIp),
					(ASF_IPv6Addr_t *)(tuple->ipv6DestIp),
					(tuple->usSrcPort << 16)|tuple->usDestPort,
					tuple->ucProtocol,
					ulVsgId, ulZoneId, pHead);
}

/*
 * Lookups through the flows to find matching entry.
 * The argument 'head' is head of circular list (actually bucket ponter).
 */
static inline ffp_flow_t  *asf_ffp_ipv6_flow_lookup(
					ASF_IPv6Addr_t *sip, ASF_IPv6Addr_t *dip, unsigned int ports,
					unsigned long vsg, unsigned long szone, unsigned char protocol, unsigned long *pHashVal)
{
	ffp_flow_t *flow, *pHead;
#ifdef ASF_DEBUG
	unsigned long ulCount = 0;
#endif

	*pHashVal = ASFFFPIPv6ComputeFlowHash1(sip, dip, ports, vsg,
					szone, asf_ffp_ipv6_hash_init_value);


	pHead = (ffp_flow_t *) asf_ffp_ipv6_bucket_by_hash(*pHashVal);

	for (flow = pHead->pNext; flow != pHead; flow = flow->pNext) {
		if (!(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6SrcIp), (struct in6_addr *)sip))
		&& !(_ipv6_addr_cmp((struct in6_addr *)&(flow->ipv6DestIp), (struct in6_addr *)dip))
		&& (flow->ulPorts == ports)
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		&& (flow->ucProtocol == protocol)
		&& (flow->ulZoneId == szone)
		&& (flow->ulVsgId == vsg)
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		) {
			return flow;
		}
#ifdef ASF_DEBUG
		ulCount++;
		if (ulCount >= SEARCH_MAX_PER_BUCKET) {
			asf_debug("Max (%u) scanned in bucket (%d)"\
			"... aborting search!\n",
			SEARCH_MAX_PER_BUCKET, FFP_IPV6_HINDEX(*pHashVal));
			return NULL;
		}
#endif
	}
	return NULL;
}

ffp_flow_t *asf_ffp_ipv6_flow_lookup_by_tuple(ASFFFPFlowTuple_t *tpl,
			unsigned long ulVsgId,
			unsigned long ulZoneId,
			unsigned long *pHashVal)
{
	return asf_ffp_ipv6_flow_lookup((ASF_IPv6Addr_t *)(tpl->ipv6SrcIp),
				(ASF_IPv6Addr_t *)(tpl->ipv6DestIp),
				(tpl->usSrcPort << 16)|tpl->usDestPort,
				ulVsgId, ulZoneId, tpl->ucProtocol, pHashVal);
}

void ffp_ipv6_flow_free_rcu(struct rcu_head *rcu)
{
	ffp_flow_t *flow = (ffp_flow_t *) rcu;
	ffp_ipv6_flow_free(flow);
}

static inline void asfFfpSendLogEx(ffp_flow_t *flow, unsigned long ulMsgId, ASF_uchar8_t *aMsg, unsigned long ulHashVal)
{
	if (ffpCbFns.pFnAuditLog) {
		ASFLogInfo_t        li;
		li.ulVSGId = flow->ulVsgId;
		li.ulMsgId = ulMsgId;
		li.aMsg = aMsg;
		li.u.fwInfo.tuple.ulSrcIp = flow->ulSrcIp;
		li.u.fwInfo.tuple.ulDestIp = flow->ulDestIp;
		/*--- Test next Two lines (for endianness also) ---*/
		li.u.fwInfo.tuple.usSrcPort = *(ASF_uint16_t *) ((ASF_uchar8_t *) &flow->ulPorts);
		li.u.fwInfo.tuple.usDestPort = *(ASF_uint16_t *) ((ASF_uchar8_t *) &flow->ulPorts + 2);
		li.u.fwInfo.tuple.ucProtocol = flow->ucProtocol;
		li.u.fwInfo.ulZoneId = flow->ulZoneId;
		li.u.fwInfo.ulHashVal = ulHashVal;
		ffpCbFns.pFnAuditLog(&li);
	}
}

static inline void asfFfpSendLog(ffp_flow_t *flow, unsigned long ulMsgId, unsigned long ulHashVal)
{
	return asfFfpSendLogEx(flow, ulMsgId, (ASF_uchar8_t *) "", ulHashVal);
}
#ifdef CONFIG_DPA
ASF_uint32_t ASFFFPIPv6ProcessAndSendFD(
			ASFNetDevEntry_t *anDev,
			ASFBuffer_t *abuf)
{
	struct ipv6hdr		*ip6h;
	ffp_flow_t		*flow;
	unsigned long		ulHashVal = abuf->pAnnot->hr_hilo.loHash;
	unsigned short int	trhlen;
	int			L2blobRefresh = 0;
	unsigned int            retryCount = 0, err = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int			bSpecialIndication = 0,
				bFlowValidate = 0;
	unsigned int		ulTcpState = 0;
	unsigned int		fragCnt;
	asf_vsg_info_t		*vsgInfo;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ASFFFPVsgStats_t	*vstats;
	ASFFFPFlowStats_t	*flow_stats;
	unsigned long		ulOrgSeqNum = 0, ulOrgAckNum = 0, ulLogId;
	int			iRetVal;
	struct tcphdr		*ptcph = NULL;
#endif
	unsigned int		*ptrhdrOffset;
	unsigned char		nexthdr;
	unsigned int		exthdrsize = 0;
	unsigned char		*pL4hdr;
	unsigned char		bSendOut  = 0;
	u8			*txdata;
	dma_addr_t		addr;
	struct dpa_priv_s	*priv;
	struct dpa_bp		*dpa_bp;
	struct qm_fd		*tx_fd;
	u32			data_len;
	t_FmPrsResult *pParse = &abuf->pAnnot->parse_result;
#ifdef ASF_EGRESS_QOS
	struct ipv6_redef	*hdr;
#endif

	ACCESS_XGSTATS();
	data_len = abuf->len + pParse->ip_off[0];
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + anDev->ulVSGId;
	vstats->ulInPkts++;
#endif
	ip6h = (struct ipv6hdr *)abuf->iph;
#ifdef ASF_EGRESS_QOS
	hdr = (struct ipv6_redef *)ip6h;
#endif
	abuf->pCsum = NULL;

#ifdef ASF_DEBUG_FRAME
	asf_print(" Pkt ip6h->payload_len = %d", ip6h->payload_len);
	hexdump((void *)ip6h - 14, ip6h->payload_len + sizeof(struct ipv6hdr) + 14);
#endif

	pL4hdr = (unsigned char *)ip6h + sizeof(struct ipv6hdr);

	/* Traverse IPv6 extension headers */
	nexthdr = ip6h->nexthdr;

	/* Hop-by-Hop header */
	if (unlikely(nexthdr == NEXTHDR_HOP)) {

		/* Only hop-by-hop extension header with only Jumboigram optiohn sippoted */
		/* rest will given to  Linux */

		/* jumbograms + extra options  */
		if (pL4hdr[1] != 0)
			return ASF_RTS;

		/* Is jumbograms ? */
		if (pL4hdr[2] != IPV6_TLV_JUMBO)
			return ASF_RTS;

		/* jumbograms lenght should be 4 */
		if (pL4hdr[3] != 4)
			return ASF_RTS;

		/* jumbograms option paylaod value */
		if (ntohs(*(unsigned int *)(&pL4hdr[4])) > ip6h->payload_len)
			goto drop_pkt;

		/* Process hop by hop IP options, esp for JUMBOGRAM option */
		nexthdr = pL4hdr[0];

		exthdrsize += (pL4hdr[1] + 1) << 3;

		pL4hdr += exthdrsize;
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	/* Fragment header */
	if (unlikely(nexthdr == NEXTHDR_FRAGMENT)) {
		struct frag_hdr *fhdr;
		fhdr =  (struct frag_hdr *)pL4hdr;
		fragCnt = 0;

		/* Do we need this check ? */
		if (unlikely((fhdr->frag_off) & htons(0xFFF9))) {
			struct sk_buff *skb;

			abuf->bbuffInDomain = ASF_TRUE;
			skb = asf_abuf_to_skb(abuf);

			skb_set_transport_header(skb, pL4hdr -
						(unsigned char *)ip6h);
			abuf->nativeBuffer = asfIpv4Defrag(anDev->ulVSGId, skb,
						NULL, NULL, NULL, &fragCnt);
			if (!(abuf->nativeBuffer)) {
				asf_debug("Skb absorbed for re-assembly \r\n");
				return ASF_DONE;
			}

			/* update skb */
			skb = (struct sk_buff *)abuf->nativeBuffer;
			skb_reset_network_header(skb);
			ip6h = (struct ipv6hdr *)skb_network_header(skb);
			if (ip6h->nexthdr == NEXTHDR_HOP) {
				struct ipv6_opt_hdr *hophdr;
				skb_set_transport_header(skb,
						sizeof(struct ipv6hdr));
				hophdr = (struct ipv6_opt_hdr *)
						skb_transport_header(skb);
				exthdrsize = (hophdr->hdrlen + 1) << 3;
				nexthdr = hophdr->nexthdr;
			} else {
				exthdrsize = 0;
				nexthdr = ip6h->nexthdr;
			}
			pL4hdr = skb->data + sizeof(struct ipv6hdr)
								+ exthdrsize;
			/* make an abuf out of head skb; this buffer should not
			   go through another asf_abuf_to_skb - ok because
			   abuf.nativebuffer is already populated */
			asf_skb_to_abuf(abuf, anDev);
			/* Update pParse pointer to HEAD aBuf */
			pParse = &abuf->pAnnot->parse_result;
			/* Do we require to update ipv6h? not sure now */
			/* Assuming that Transport Header is
			   included in Head Fragment */
			abuf->frag_list = 1;
		} else {
			nexthdr = fhdr->nexthdr;
			exthdrsize += sizeof(struct frag_hdr);
			pL4hdr += sizeof(struct frag_hdr);
		}
	}
#endif

#ifdef ASF_IPSEC_FP_SUPPORT
	/* ESP header */
	if (nexthdr == NEXTHDR_ESP ||
		nexthdr == NEXTHDR_AUTH) {
		/* Give packet to ASF IPSec */
		if (pFFPIPSecIn) {
asf_debug("calling pFFPIPSecIn");
			abuf->ulVSGId = anDev->ulVSGId;
			abuf->ulZoneId = anDev->ulZoneId;
			abuf->ulCommonInterfaceId = anDev->ulCommonInterfaceId;

			if (pFFPIPSecIn(abuf, ASF_BUF_FMT_ABUF, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) == 0) {
				return ASF_DONE;
			} else{
				/*skb_recycle(skb);*/
				asf_dec_skb_buf_count(abuf->nativeBuffer);
			}
		} else {
			XGSTATS_INC(NonTcpUdpPkts);
			goto ret_pkt_to_stk;
		}
	}
#endif

	if (unlikely((nexthdr != NEXTHDR_TCP) &&
		(nexthdr != NEXTHDR_UDP))) {
		/* Dont process non TCP/UDP packets */
		/* return packet to linux stack */
		asf_debug(" Non TCP/UDP packets, return packet to linux stack");
		goto ret_pkt_to_stk;
	}
	if (nexthdr == NEXTHDR_UDP) {
		struct udphdr *udph = (struct udphdr *)pL4hdr;
		u16 ussrcprt = udph->source;
		u16 usdstprt = udph->dest;

		if (ussrcprt == ASF_IKE_NAT_FLOAT_PORT
				|| ussrcprt == ASF_IKE_SERVER_PORT
				|| usdstprt == ASF_IKE_SERVER_PORT
				|| usdstprt == ASF_IKE_NAT_FLOAT_PORT) {
			asf_debug("\n returning IKE packet to STK");
			goto ret_pkt_to_stk;
		}
	}

	ptrhdrOffset = (unsigned int *)pL4hdr;


	flow = asf_ffp_ipv6_flow_lookup((ASF_IPv6Addr_t *)&(ip6h->saddr), (ASF_IPv6Addr_t *)&(ip6h->daddr),
					*ptrhdrOffset/* ports*/, (unsigned long)anDev->ulVSGId,
					(unsigned long)anDev->ulZoneId, nexthdr, &ulHashVal);
	asf_debug("ASF: %s Hash(%x:%x:%x:%x:%x:%x:%x:%x, %x:%x:%x:%x:%x:%x:%x:%x, 0x%lx, %d, %d)"\
		" = 0x%08lx (hindex %lx) (hini 0x%lx) => %s\n",
		anDev->ndev->name,
		PRINT_IPV6_OTH(ip6h->saddr), PRINT_IPV6_OTH(ip6h->daddr), *ptrhdrOffset,
		nexthdr, anDev->ulVSGId, ulHashVal, FFP_IPV6_HINDEX(ulHashVal),
		asf_ffp_ipv6_hash_init_value, flow ? "FOUND" : "NOT FOUND");

#if 0
#ifdef ASF_IPSEC_FP_SUPPORT
	if (pIpsecOpaque) {
		if (pFFPIpsecInVerify(anDev->ulVSGId, skb,
			anDev->ulCommonInterfaceId,
			(flow && flow->bIPsecIn) ? &flow->ipsecInfo : NULL,
			pIpsecOpaque) != 0) {
			asf_warn("IPSEC InVerify Failed\n");
			return ASF_DONE;
		}
	}
#endif
#endif
	if (unlikely(!flow)) {
		asf_debug("ret_pkt_to_stk in no flow case");
		XGSTATS_INC(NoFlow);
		goto ret_pkt_to_stk;
	}


	if (unlikely(ip6h->hop_limit <= 1)) {
		asf_debug("flow = 0x%p ip6h->version %d ip6h->hop_limit %d\n",
			flow, ip6h->version, ip6h->hop_limit);
		/* Drop the packet */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulErrTTL++;
#endif
		goto drop_pkt;
	}


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulInPktFlowMatches++;
	vstats->ulInPktFlowMatches++;
	XGSTATS_INC(Condition1);

	flow_stats = &flow->stats;
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vsgInfo = asf_ffp_get_vsg_info_node(anDev->ulVSGId);
	if (vsgInfo) {
		if (vsgInfo->configIdentity.ulConfigMagicNumber !=
			flow->configIdentity.ulConfigMagicNumber) {
			asf_print("Calling flow validate %d != %d",
			vsgInfo->configIdentity.ulConfigMagicNumber,

			flow->configIdentity.ulConfigMagicNumber);
			bFlowValidate = 1;
		}
		/* L2blob refersh handling for the possible change in the l2blob */

		if ((!flow->bIPsecOut) &&
			(vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber !=
			flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)) {

			if (!flow->configIdentity.l2blobConfig.bl2blobRefreshSent) {
				flow->configIdentity.l2blobConfig.ulOldL2blobJiffies = jiffies;
				flow->configIdentity.l2blobConfig.bl2blobRefreshSent = 1;
			}

			if (time_after(jiffies ,
				flow->configIdentity.l2blobConfig.ulOldL2blobJiffies +
				ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT)) {
				L2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
				goto gen_indications;
			}

			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
		}
	}

#endif
	/* general purpose flag. This gets set when TCP connection is
	 * completed and we are waiting for FNP to delete flows. This
	 * flag is also used in firewall case*/
	if (flow->bDrop) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (bFlowValidate)
			goto gen_indications;
#endif
		XGSTATS_INC(bDropPkts);
		asf_debug("dropping packet as bDrop is set\n");
		goto drop_pkt;
	}

	if (nexthdr == NEXTHDR_UDP) {
		XGSTATS_INC(UdpPkts);
	} else { /* This is TCP case */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		int     optlen;
		unsigned short  tcp_data_len;
		ffp_flow_t      *oth_flow;
#endif

		XGSTATS_INC(TcpPkts);
		trhlen = (unsigned short)((*(ptrhdrOffset + 3) &
						0xf0000000) >> 28) * 4;
		/* Invalid length check
		   Length indicated in IPhdr - header length < expected transport header length
		   Length as indicated in skb - ip hder - ethernet header < expected transport header length
		*/
		if (((ip6h->payload_len - (exthdrsize)) < trhlen)) {
			/* Need to add code for TCP */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpProtoHdr++;
#endif
			XGSTATS_INC(TcpHdrLenErr);
			asfFfpSendLog(flow, ASF_LOG_ID_INVALID_TCP_HDRLEN, ulHashVal);
			goto drop_pkt;
		}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		ptcph = (struct tcphdr *) ptrhdrOffset;
		/*optlen = ptcph->doff*4-20; */

		/* if (flow->bTcpTimeStamp && ((optlen = ptcph->doff*4-20) > 0)) */
		optlen = trhlen - 20;
		if (flow->bTcpTimeStampCheck && (optlen > 0)) {
			unsigned char *tcpopt;
			tcpopt = ((unsigned char *) (ptcph)) + 20;
			iRetVal = asfTcpProcessOptions(flow, tcpopt, optlen);
			if (iRetVal < 0) {
				asf_debug("invalid timestamp\n");
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpTimeStampErr);
				goto drop_pkt;
			}
		}

		oth_flow = ffp_ipv6_flow_by_id(&flow->other_id);
		if (!oth_flow) {
			asf_debug("other flow is not found!! strange!!\n");
			goto drop_pkt;
		}

		tcp_data_len = ip6h->payload_len - exthdrsize + trhlen;
		asf_debug_l2("TCP_STATE_PROC: tcp_data_len = %d\n", tcp_data_len);

		if (flow->bTcpOutOfSeqCheck) {
			ulLogId = asfTcpCheckForOutOfSeq(flow, oth_flow, ptcph,
						tcp_data_len, vsgInfo);
			if (unlikely(ulLogId != ASF_LOG_ID_DUMMY)) {
				asf_debug("out of seq check failed!\n");
				asfFfpSendLog(flow, ulLogId, ulHashVal);
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpOutOfSequenceErr);
				if (vsgInfo->bDropOutOfSeq)
					goto drop_pkt;
			}
		}
		asf_debug_l2("TCP_STATE_PROC: out of sequence checks finished!\n");

		ulOrgSeqNum = ntohl(ptcph->seq);
		ulOrgAckNum = ntohl(ptcph->ack_seq);
		asfTcpApplyDelta(flow, oth_flow, ptcph, ulOrgSeqNum, ulOrgAckNum);
		asf_debug_l2("TCP_STATE_PROC: applied delta to the packet\n");

		asfTcpUpdateState(flow, ulOrgSeqNum, ulOrgAckNum, ptcph, tcp_data_len);
		asf_debug_l2("TCP_STATE_PROC: updated current TCP state in the flow\n");
		iRetVal = asfTcpProcess(flow, oth_flow, ptcph);
		if (iRetVal < 0) {
			asf_debug("asfTcpProcess returned failure!\n");
			gstats->ulErrIpProtoHdr++;
			XGSTATS_INC(TcpProcessErr);
			goto drop_pkt;
		} else if (iRetVal == 1) {
			asf_debug("TCP_STATE_PROC: %s packet .. send InacRefresh indication\n",
				  ptcph->fin ? "FIN" : "RST");
			ulTcpState = (ptcph->fin) ? ASF_FFP_TCP_STATE_FIN_RCVD : ASF_FFP_TCP_STATE_RST_RCVD;
			bSpecialIndication = 1;
		} else if (iRetVal == 2) {
			ulTcpState = ASF_FFP_TCP_STATE_FIN_COMP;
			bSpecialIndication = 1;
		}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		asf_debug_l2("TCP state processing is done!\n");
	}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	flow_stats->ulInPkts++;
	/* Only timer based L2 blob refresh  is supported in current release */
	if (asf_l2blob_refresh_npkts &&
		(flow_stats->ulInPkts % asf_l2blob_refresh_npkts) == 0) {
		asf_debug_l2("Decided to send L2Blob refresh ind based on npkts\n");
		if (!L2blobRefresh)
			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
	}
	flow->ulLastPktInAt = jiffies;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

#ifdef ASF_INGRESS_MARKER
	if (ASF_QM_NULL_DSCP != flow->mkinfo.uciDscp)
		hdr->tc = flow->mkinfo.uciDscp;
#endif
	if (!flow->bIPsecOut &&
		(flow->l2blob_len == 0)) {
		asf_debug("Generating L2blob Indication as L2blob Not found!\n");
		L2blobRefresh = ASF_L2BLOB_REFRESH_RET_PKT_STK;
		XGSTATS_INC(BlankL2blobInd);
		goto gen_indications;
	}


	/* ??????????? UNDER CONSTRUCTION */
	if (flow->bNat) {
		XGSTATS_INC(NatPkts);
		asf_debug_l2("applying NAT\n");
		/* Update IP Checksum also */
		if (ipv6_addr_cmp((struct in6_addr *)&(ip6h->saddr), (struct in6_addr *)&(flow->ipv6SrcNATIp)))
			ipv6_addr_copy((struct in6_addr *)&(ip6h->saddr), (struct in6_addr *)&(flow->ipv6SrcNATIp));
		if (ipv6_addr_cmp((struct in6_addr *)&(ip6h->daddr), (struct in6_addr *)&(flow->ipv6DestNATIp)))
			ipv6_addr_copy((struct in6_addr *)&(ip6h->daddr), (struct in6_addr *)&(flow->ipv6DestNATIp));

		*ptrhdrOffset = flow->ulNATPorts;

#ifdef ASF_DO_INC_CHECKSUM
		/* Hardware does not handle this, so we do incremental checksum */
		if (nexthdr == NEXTHDR_UDP) {
			abuf->pCsum = ((unsigned short int *) ptrhdrOffset) + 3;
		} else { /*if (iph->protocol == IPPROTO_TCP) */
			abuf->pCsum = ((unsigned short int *) ptrhdrOffset) + 8;
		}

#if 0
		/* Under construction */
		asf_proto_csum_replace4(abuf.pCsum,
			flow->iv6SrcIp, flow->ulSrcNATIp);
		asf_proto_csum_replace4(abuf.pCsum,
			flow->iDestIp, flow->ulDestNATIp);
		asf_proto_csum_replace4(abuf.pCsum,
			flow->ulPorts, flow->ulNATPorts);
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		/* TCP delta checsum handling */
		if (nexthdr == NEXTHDR_TCP) {
			if (ulOrgSeqNum != ntohl(ptcph->seq))
				asf_proto_csum_replace4(abuf->pCsum,
					htonl(ulOrgSeqNum),
					ptcph->seq);

			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				asf_proto_csum_replace4(abuf->pCsum,
					htonl(ulOrgAckNum),
					ptcph->ack_seq);
		}
#endif

#else /* ASF_DO_INC_CHECKSUM */
		if (nexthdr == NEXTHDR_TCP)
			abuf->pCsum = ((u16 *)ptrhdrOffset) + 8;
		else if (nexthdr == NEXTHDR_UDP)
			abuf->pCsum = ((u16 *)ptrhdrOffset) + 3;
#endif
	} else {

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef ASF_DO_INC_CHECKSUM
		/* TCP delta checsum handling */
		if (nexthdr == NEXTHDR_TCP) {
			abuf->pCsum = ((unsigned short int *) ptrhdrOffset) + 8;

			if (ulOrgSeqNum != ntohl(ptcph->seq))
				asf_proto_csum_replace4(abuf->pCsum,
					htonl(ulOrgSeqNum),
					ptcph->seq);

			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				asf_proto_csum_replace4(abuf->pCsum,
					htonl(ulOrgAckNum),
					ptcph->ack_seq);
		}
#else
		if (nexthdr == NEXTHDR_TCP)
			abuf->pCsum = ((u16 *)ptrhdrOffset) + 8;
		else if (nexthdr == NEXTHDR_UDP)
			abuf->pCsum = ((u16 *)ptrhdrOffset) + 3;
#endif
#endif

	}

#ifdef ASF_IPSEC_FP_SUPPORT
	if (flow->bIPsecOut) {
		if (pFFPIPSecOut) {
			struct sk_buff *skb;
			abuf->bbuffInDomain = ASF_TRUE;
			skb = asf_abuf_to_skb(abuf);
			skb_set_transport_header(skb, pL4hdr - (unsigned char *)ip6h);
			if (pFFPIPSecOut(anDev->ulVSGId,
				skb, ASF_BUF_FMT_SKBUFF, &flow->ipsecInfo) == 0) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulOutBytes += skb->len;
				flow_stats->ulOutBytes += skb->len;
				vstats->ulOutBytes += skb->len;

				gstats->ulOutPkts++;
				vstats->ulOutPkts++;
				flow_stats->ulOutPkts++;
#endif
				return ASF_DONE;
			}
			skb_recycle(skb);
			goto ret_pkt_to_stk;
		}
		goto drop_pkt;
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/
	asf_debug_l2("attempting to xmit the packet\n");
	/*skb_set_network_header(skb, hh_len); */
	if (unlikely(abuf->frag_list)) {
		/* Handle frag list */
		struct sk_buff *pSkb;
		struct sk_buff *skb = (struct sk_buff *)
						abuf->nativeBuffer;
		skb_set_transport_header(skb, pL4hdr - (unsigned char *)ip6h);
		/* This is tricky */
		asfIpv6MakeFragment(skb, &pSkb);
		skb = pSkb;
		do {
			struct sk_buff *pTempSkb;
			unsigned int tunnel_hdr_len = 0;

			pTempSkb = skb->next;
			asf_debug("Next skb = 0x%x\r\n", pTempSkb);
			skb->next = NULL;
			ip6h = ipv6_hdr(skb);
			skb->pkt_type = PACKET_FASTROUTE;
			asf_set_queue_mapping(skb, hdr->tc);

			ip6h->hop_limit--;

			skb->data -= flow->l2blob_len;
			skb->dev = flow->odev;

			asfCopyWords((unsigned int *)skb->data,
					(unsigned int *)flow->l2blob,
					flow->l2blob_len);

			if (flow->bIP6IP4Out) {
				struct iphdr *iph =
					(struct iphdr *)skb_network_header(skb);
				iph -= 1;
				iph->tot_len = skb->len + sizeof(struct iphdr);

				if (iph->ttl <= 1)
					iph->ttl = ip6h->hop_limit;

				if (iph->tos == 0)
					iph->tos = ip6h->priority;

				iph->check = 0;
				iph->check = ip_fast_csum((unsigned char *)iph,
								iph->ihl);

				tunnel_hdr_len = sizeof(struct iphdr);
			}

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (flow->bPPPoE) {
				/* PPPoE packet.. Set Payload
				   length in PPPoE header */
				*((short *)&(skb->data[(flow->l2blob_len -
				tunnel_hdr_len)-4])) =
					htons(skb->len + tunnel_hdr_len + 2);
			}

#endif
			skb->len += flow->l2blob_len;

			asf_debug("skb->network_header = 0x%x,"
				" skb->transport_header = 0x%x\r\n",
					skb_network_header(skb),
					skb_transport_header(skb));
			asf_debug("Transmitting  buffer = 0x%x dev->index = %d"
						"\r\n", skb, skb->dev->ifindex);
			priv  = netdev_priv(skb->dev);
			dpa_bp = priv->dpa_bp;
			PER_CPU_BP_COUNT(dpa_bp)--;

			bSendOut = 1;
			if (asfDevHardXmit(skb->dev, skb) != 0) {
				asf_debug("Error in transmit: "
						"Should not happen\r\n");
				ASFSkbFree(skb);
			}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulOutPkts++;
			vstats->ulOutPkts++;
			flow_stats->ulOutPkts++;
			gstats->ulOutBytes += skb->len;
			flow_stats->ulOutBytes += skb->len;
			vstats->ulOutBytes += skb->len;
#endif
			skb = pTempSkb;
		} while (skb);

		goto gen_indications;
	}
	/* Handling for Normal packets */
	do {
		ip6h = (struct ipv6hdr *)abuf->iph;
		ip6h->hop_limit--;

		txdata = (u8 *)ip6h - flow->l2blob_len;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (flow->bPPPoE) {
			/* PPPoE packet.. Set Payload length in PPPoE header */
			*((short *)&(txdata[pParse->ip_off[0] - 2])) =
					(short)data_len - pParse->ip_off[0];
		}
#endif

		/* dma map data buffer */
		priv = netdev_priv(flow->odev);
		dpa_bp = priv->dpa_bp;
		addr = dma_map_single(dpa_bp->dev, abuf->pAnnot,
				dpa_bp->size, DMA_TO_DEVICE);
		if (unlikely(addr == 0)) {
			asf_debug("xmit dma_map Error\n");
			goto drop_pkt;
		}

		/*Reusing unused annotation's (reserved ) area as TX_FD
		As per current implementation, parse result is not in use for TX_FD
		but in future if parse results need to be placed in TX_FD then TX_FD
		will be written at some other memory location*/

		tx_fd  = (struct qm_fd *)&(abuf->pAnnot->reserved[ASF_RX_RESERVED_AREA_OFFSET]);
		*(u32 *)tx_fd = 0; /* Resetting the unused area */
		tx_fd->bpid = dpa_bp->bpid;
		tx_fd->addr_hi = upper_32_bits(addr);
		tx_fd->addr_lo = lower_32_bits(addr);
		/* Only Contiguous Frame Handling for now */
		tx_fd->format = qm_fd_contig;
		/* if L2 header on egress is make sure that enough
			headroom exists.
		*/
		tx_fd->offset = (uintptr_t)ip6h - (uintptr_t)abuf->pAnnot - flow->l2blob_len;
		if (txdata >= (u8 *)abuf->ethh)
			tx_fd->length20 = data_len -
				((txdata - (u8 *)abuf->ethh) & 0xfffff);
		else
			tx_fd->length20 = data_len +
				(((u8 *)abuf->ethh - txdata) & 0xfffff);

		/* Indicate to Recycle Buffer */
		tx_fd->cmd = FM_FD_CMD_FCO;
		asf_debug("tx on fqid %d\n",
				priv->egress_fqs[smp_processor_id()]->fqid);

		asf_debug_l2("copy l2blob to packet (blob_len %d)\n",
							flow->l2blob_len);
		asfCopyWords((unsigned int *)txdata,
			(unsigned int *)flow->l2blob, flow->l2blob_len);

		if (flow->bIP6IP4Out) {
			struct iphdr *iph = (struct iphdr *)ip6h;
			iph -= 1;
			iph->tot_len = data_len + sizeof(struct iphdr)
						- pParse->ip_off[0];
			if (iph->tot_len > flow->pmtu - flow->l2blob_len) {
				struct sk_buff *skb =
				(struct sk_buff *)asf_abuf_to_skb(abuf);
				skb_set_transport_header(skb, pL4hdr -
					(unsigned char *)ip6h);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 32)
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0,
				iph->tot_len - 2 * (sizeof(struct iphdr)));
#else
				icmpv6_send(skb, ICMPV6_PKT_TOOBIG, 0,
				iph->tot_len - 2 * (sizeof(struct iphdr)), skb->dev);
#endif
				goto drop_pkt_1;
			}
			if (iph->ttl <= 1)
				iph->ttl = ip6h->hop_limit;

			if (iph->tos == 0)
				iph->tos = ip6h->priority;

			iph->check = 0;
			iph->check =
				ip_fast_csum((unsigned char *)iph, iph->ihl);
		}

		do {
#ifdef ASF_QOS
			err = asf_qos_fd_handling(abuf, flow->odev,
					hdr->tc, &flow->tc_filter_res);
#else
			err = qman_enqueue(priv->egress_fqs[smp_processor_id()],
					tx_fd, 0);
#endif
			if (err == 0)
				break;
			if (++retryCount == ASF_MAX_TX_RETRY_CNT) {
				XGSTATS_INC(DevXmitErr);
				asf_err("qman_enque Error\n");
				/* dma_unmap_single(dpa_bp->dev, qm_fd_addr(tx_fd),
				dpa_bp->size, DMA_TO_DEVICE);*/
				goto drop_pkt;
			}
			__delay(50);
		} while (1);
		bSendOut = 1;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulOutBytes += tx_fd->length20;
		flow_stats->ulOutBytes += tx_fd->length20;
		vstats->ulOutBytes += tx_fd->length20;

		gstats->ulOutPkts++;
		vstats->ulOutPkts++;
		flow_stats->ulOutPkts++;
#endif
	} while (0);

gen_indications:
	/* skip all other indications if flow_end indication is going to be sent */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (bSpecialIndication) {
		/*XGSTATS_INC(FlowSpecialInd);*/
		if (ffpCbFns.pFnFlowTcpSpecialPkts) {
			ASFFFPFlowSpecialPacketsInfo_t  ind;
			ffp_flow_t		      *oth_flow;

			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.tuple.bIPv4OrIPv6 = 1;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
			ind.ulTcpState = ulTcpState;

			oth_flow = ffp_ipv6_flow_by_id(&flow->other_id);

			ffp_copy_flow_stats(flow, &ind.flow_stats);
			if (oth_flow)
				ffp_copy_flow_stats(oth_flow, &ind.other_stats);
			else
				memset(&ind.other_stats, 0, sizeof(ind.other_stats));

			ffpCbFns.pFnFlowTcpSpecialPkts(anDev->ulVSGId, &ind);
		}
	}
	/* FlowValidate indicaion */
	if (bFlowValidate) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowValidate) {
			ASFFFPFlowValidateCbInfo_t  ind;

			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.tuple.bIPv4OrIPv6 = 1;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo =
			(ASF_uint8_t *)flow->as_flow_info;
			ffpCbFns.pFnFlowValidate(anDev->ulVSGId, &ind);
		}

		/* This need cosideration, SKB leak is here */
		if (flow->bDrop) {
			XGSTATS_INC(bDropPkts);
			asf_debug("dropping packet as"\
					"bDrop is set\n");
			if (0 == bSendOut)
				goto drop_pkt;
			else
				goto drop_pkt_1;
		}
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	if (L2blobRefresh) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowRefreshL2Blob) {
			ASFFFPFlowL2BlobRefreshCbInfo_t  ind;

			ipv6_addr_copy((struct in6_addr *)&(ind.flowTuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.flowTuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.flowTuple.bIPv4OrIPv6 = 1;
			ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
			ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
			ind.flowTuple.ucProtocol = flow->ucProtocol;

			if (flow->bNat) {
				ipv6_addr_copy((struct in6_addr *)&(ind.packetTuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcNATIp));
				ipv6_addr_copy((struct in6_addr *)&(ind.packetTuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestNATIp));
				ind.packetTuple.bIPv4OrIPv6 = 1;
				ind.packetTuple.usSrcPort = (flow->ulNATPorts >> 16);
				ind.packetTuple.usDestPort = flow->ulNATPorts&0xffff;
				ind.packetTuple.ucProtocol = flow->ucProtocol;
			} else
				ind.packetTuple	= ind.flowTuple;

			ind.ulZoneId = flow->ulZoneId;

			ind.ulHashVal = ulHashVal;

			ind.Buffer.linearBuffer.buffer = NULL;
			ind.Buffer.linearBuffer.ulBufLen = 0;
			ind.Buffer.nativeBuffer = NULL;

			ind.ASFwInfo = NULL;

			XGSTATS_INC(PktCtxL2blobInd);
			ffpCbFns.pFnFlowRefreshL2Blob(anDev->ulVSGId, &ind);
		}

		switch (L2blobRefresh) {
		case ASF_L2BLOB_REFRESH_RET_PKT_STK:
				goto ret_pkt_to_stk;
		case ASF_L2BLOB_REFRESH_DROP_PKT:
				goto drop_pkt;
				break;
		default:
				break;
		}

	}

	return ASF_DONE;
drop_pkt:
	asf_debug_l2("drop_pkt LABEL\n");
	/* TODO: we may have to iterate through frag_list and free all of them*/
	/* TODO: ensure all fragments are also dropped. and return STOLEN
	 always return stolen?? */
	if (unlikely(abuf->frag_list))
		ASF_SKB_FREE_FUNC(abuf->nativeBuffer);
	else
		asf_abuf_release(abuf);

drop_pkt_1:
	return ASF_DONE;
ret_pkt_to_stk:
	if (unlikely(abuf->frag_list)) {
		/* Handle frag list */
		struct sk_buff *skb = (struct sk_buff *)
					abuf->nativeBuffer;
		struct sk_buff *pSkb;

		skb_set_transport_header(skb,
			pL4hdr - (unsigned char *)ip6h);

		XGSTATS_INC(FragAndXmit);
		/* This is tricky */
		asfIpv6MakeFragment(skb, &pSkb);

		while (pSkb) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulPktsToFNP++;
#endif
			skb = pSkb;
			pSkb = pSkb->next;
			skb->next = NULL;
			asf_dec_skb_buf_count(skb);
			ASF_netif_receive_skb(skb);
		}
		return ASF_DONE;

	}
	return ASF_RTS;
}
EXPORT_SYMBOL(ASFFFPIPv6ProcessAndSendFD);
#endif

ASF_uint32_t ASFFFPIPv6ProcessAndSendPkt(
				ASF_uint32_t    ulVsgId,
				ASF_uint32_t    ulCommonInterfaceId,
				ASFBuffer_t     *Buffer,
				genericFreeFn_t pFreeFn,
				ASF_void_t      *freeArg,
				ASF_void_t      *pIpsecOpaque
				/* pass this to VPN In Hook */
				)
{
	struct ipv6hdr		*ip6h;
	ffp_flow_t		*flow;
	unsigned long		ulHashVal;
	unsigned short int	trhlen;
	unsigned short int      *q;
	int			L2blobRefresh = 0;
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	int			bSpecialIndication = 0,
				FlowValidate = 0;
	unsigned int		ulTcpState = 0;
	unsigned int		fragCnt;
	asf_vsg_info_t		*vsgInfo;
	ASFFFPGlobalStats_t     *gstats = asfPerCpuPtr(asf_gstats, smp_processor_id());
	ASFFFPVsgStats_t	*vstats;
	ASFFFPFlowStats_t	*flow_stats;
	unsigned long		ulOrgSeqNum = 0, ulOrgAckNum = 0, ulLogId;
	int			iRetVal;
	struct tcphdr		*ptcph = NULL;
#endif
	unsigned int       *ptrhdrOffset;
	unsigned long		ulZoneId;
	struct sk_buff		*skb;
	ASFNetDevEntry_t	*anDev;
	unsigned char		nexthdr;
	unsigned int		exthdrsize = 0;
	unsigned int pkt_len = 0;
#ifdef ASF_EGRESS_QOS
	struct ipv6_redef	*hdr;
#endif
#ifndef ASF_QOS
	struct netdev_queue *txq;
	struct net_device       *netdev;
#endif
#ifdef CONFIG_DPA
	struct dpa_priv_s       *priv;
	struct dpa_bp		*dpa_bp;
#endif

	ACCESS_XGSTATS();

	skb = (struct sk_buff *) Buffer->nativeBuffer;
#ifdef CONFIG_DPA
	priv  = netdev_priv(skb->dev);
	dpa_bp = priv->dpa_bp;
#endif

	anDev = ASFCiiToNetDev(ulCommonInterfaceId);

	if (unlikely(!anDev)) {
		asf_debug("CII %u doesn't appear to be valid\n",
			ulCommonInterfaceId);
		pFreeFn(skb);
		return ASF_RTS;
	}

	ulZoneId = anDev->ulZoneId;

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vstats = asfPerCpuPtr(asf_vsg_stats, smp_processor_id()) + ulVsgId;
	vstats->ulInPkts++;
#endif
	ip6h = ipv6_hdr(skb);
#ifdef ASF_EGRESS_QOS
	hdr = (struct ipv6_redef *)ip6h;
#endif

#ifdef ASF_DEBUG_FRAME
	asf_print(" Pkt (%x) skb->len = %d, ip6h->payload_len = %d",
		pIpsecOpaque, skb->len, ip6h->payload_len);
	hexdump(skb->data - 14, skb->len + 14);
#endif

	if (unlikely(ip6h->version != 6)) {
		asf_debug("Bad iph-version =%d", ip6h->version);
		goto drop_pkt;
	}

	/* IP packet need to be set in SKB */



	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	pkt_len = ip6h->payload_len;

	/* Traverse IPv6 extension headers */

	nexthdr = ip6h->nexthdr;

	if (unlikely(nexthdr == NEXTHDR_HOP)) {

		/* Only hop-by-hop extension header with only Jumboigram optiohn sippoted */
		/* rest will given to  Linux */

		/* jumbograms + extra options  */
		if (skb_transport_header(skb)[1] != 0)
			return ASF_RTS;



		/* Is jumbograms ? */
		if (skb_transport_header(skb)[2] != IPV6_TLV_JUMBO)
			return ASF_RTS;


		/* jumbograms lenght should be 4 */
		if (skb_transport_header(skb)[3] != 4)
			return ASF_RTS;


		pkt_len = ntohs(*(unsigned int *)(&skb_transport_header(skb)[4]));

		if (pkt_len > skb->len - sizeof(struct ipv6hdr))
			goto drop_pkt;


		/* Process hop by hop IP options, esp for JUMBOGRAM option */

		nexthdr = skb_transport_header(skb)[0];

		exthdrsize += (skb_transport_header(skb)[1] + 1) << 3;

		skb_set_transport_header(skb, sizeof(struct ipv6hdr) + exthdrsize);

	}

	if ((skb_shinfo(skb)->frag_list == NULL) &&
		 unlikely((skb->len < pkt_len + sizeof(struct ipv6hdr)))) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulErrIpHdr++;
#endif
		goto drop_pkt;
	}

	if (skb_shinfo(skb)->frag_list == NULL)
		skb->len = pkt_len + sizeof(struct ipv6hdr);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (unlikely(nexthdr == NEXTHDR_FRAGMENT)) {
		struct frag_hdr *fhdr;
		fhdr =  (struct frag_hdr *)skb_transport_header(skb);
		fragCnt = 1;

		/* Do we need this check ? */
		if (unlikely((fhdr->frag_off) & htons(0xFFF9))) {
			skb = asfIpv4Defrag(ulVsgId, skb, NULL, NULL, NULL, &fragCnt);
			if (!(skb)) {
				asf_debug("Skb absorbed for re-assembly \r\n");
				return ASF_DONE;
			}
			skb_reset_network_header(skb);
			ip6h = (struct ipv6hdr *)skb_network_header(skb);
			if (ip6h->nexthdr == NEXTHDR_HOP) {
				struct ipv6_opt_hdr *hophdr;
				skb_set_transport_header(skb,
						sizeof(struct ipv6hdr));
				hophdr = (struct ipv6_opt_hdr *)
						skb_transport_header(skb);
				exthdrsize = (hophdr->hdrlen + 1) << 3;
				nexthdr = hophdr->nexthdr;
			} else {
				exthdrsize = 0;
				nexthdr = ip6h->nexthdr;
			}
			skb_set_transport_header(skb, exthdrsize +
						sizeof(struct ipv6hdr));
		} else {
			nexthdr = fhdr->nexthdr;
			exthdrsize += sizeof(struct frag_hdr);
			skb_set_transport_header(skb, sizeof(struct frag_hdr));
		}
	}
#endif
#ifdef ASF_IPSEC_FP_SUPPORT
	if (nexthdr == NEXTHDR_ESP || nexthdr == NEXTHDR_AUTH) {
		/* Give packet to ASF IPSec */
		if (pFFPIPSecIn) {
			if (pFFPIPSecIn(skb, ASF_BUF_FMT_SKBUFF, 0, anDev->ulVSGId,
				anDev->ulCommonInterfaceId) == 0) {
				return ASF_DONE;
			}
		} else {
			XGSTATS_INC(NonTcpUdpPkts);
			return ASF_RTS;
		}
	}
	if (nexthdr == NEXTHDR_UDP) {
		struct udphdr *udph =
			(struct udphdr *)skb_transport_header(skb);

		u16 ussrcprt = udph->source;
		u16 usdstprt = udph->dest;

		if (ussrcprt == ASF_IKE_NAT_FLOAT_PORT
				|| ussrcprt == ASF_IKE_SERVER_PORT
				|| usdstprt == ASF_IKE_SERVER_PORT
				|| usdstprt == ASF_IKE_NAT_FLOAT_PORT) {
			asf_debug("\n returning IKE packet to STK");
			return ASF_RTS;
		}
	}

#endif


	if (unlikely((nexthdr != NEXTHDR_TCP) &&
		(nexthdr != NEXTHDR_UDP))) {
#ifdef ASF_IPSEC_FP_SUPPORT
			if (pIpsecOpaque && pFFPIpsecInVerify) {
				pFFPIpsecInVerify(ulVsgId, (void *)skb, ASF_BUF_FMT_SKBUFF,
				anDev->ulCommonInterfaceId, NULL, pIpsecOpaque);
				return ASF_DONE;
			}
#endif
		/* Dont process non TCP/UDP packets */
		/* return packet to linux stack */
		return ASF_RTS;
	}


	ptrhdrOffset = (unsigned int *)((unsigned char *) skb_transport_header(skb));

	flow = asf_ffp_ipv6_flow_lookup((ASF_IPv6Addr_t *)&(ip6h->saddr), (ASF_IPv6Addr_t *)&(ip6h->daddr),
					*ptrhdrOffset/* ports*/, ulVsgId,
					ulZoneId, nexthdr, &ulHashVal);


	asf_debug("ASF: %s Hash(%x:%x:%x:%x:%x:%x:%x:%x, %x:%x:%x:%x:%x:%x:%x:%x, 0x%lx, %d, %d)"\
		" = %lx (hindex %lx) (hini 0x%lx) => %s\n",
		skb->dev->name,
		PRINT_IPV6_OTH(ip6h->saddr), PRINT_IPV6_OTH(ip6h->daddr), *ptrhdrOffset,
		nexthdr, ulVsgId, ulHashVal, FFP_IPV6_HINDEX(ulHashVal),
		asf_ffp_ipv6_hash_init_value, flow ? "FOUND" : "NOT FOUND");


#ifdef ASF_IPSEC_FP_SUPPORT
	if (pIpsecOpaque) {
		if (pFFPIpsecInVerify(ulVsgId, (void *)skb, ASF_BUF_FMT_SKBUFF,
			anDev->ulCommonInterfaceId,
			(flow && flow->bIPsecIn) ? &flow->ipsecInfo : NULL,
			pIpsecOpaque) != 0) {
			asf_warn("IPSEC InVerify Failed\n");
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			if (flow)
				FlowValidate = ASF_FLOWVALIDATE_NORAMAL;
#endif
			goto gen_indications;
		}
	}
#endif

	if (unlikely(!flow)) {
		if (unlikely(skb_shinfo(skb)->frag_list)) {
			/* Handle frag list */
			struct sk_buff *pSkb;

			/* This is tricky */
			asfIpv6MakeFragment(skb, &pSkb);

			while (pSkb) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulPktsToFNP++;
#endif
				skb = pSkb;
				pSkb = pSkb->next;
				skb->next = NULL;
#ifdef CONFIG_DPA
				asf_dec_skb_buf_count(skb);
#endif
				ASF_netif_receive_skb(skb);
			}
			return ASF_DONE;

		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
				gstats->ulPktsToFNP++;
#endif
		/* return skb to Linux stack */
		return ASF_RTS;
	}


	if (unlikely(ip6h->hop_limit <= 1)) {
		/* Drop the packet */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulErrTTL++;
#endif
		goto drop_pkt;
	}


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	gstats->ulInPktFlowMatches++;
	vstats->ulInPktFlowMatches++;
	XGSTATS_INC(Condition1);

	flow_stats = &flow->stats;
#endif

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	vsgInfo = asf_ffp_get_vsg_info_node(ulVsgId);
	if (vsgInfo) {
		if (vsgInfo->configIdentity.ulConfigMagicNumber !=
			flow->configIdentity.ulConfigMagicNumber) {
			asf_print("Calling flow validate %d != %d",
			vsgInfo->configIdentity.ulConfigMagicNumber,

			flow->configIdentity.ulConfigMagicNumber);
			FlowValidate = ASF_FLOWVALIDATE_NORAMAL;
		}
		/* L2blob refersh handling for the possible change in the l2blob */

		if ((!flow->bIPsecOut) &&
			(vsgInfo->configIdentity.l2blobConfig.ulL2blobMagicNumber !=
			flow->configIdentity.l2blobConfig.ulL2blobMagicNumber)) {

			if (!flow->configIdentity.l2blobConfig.bl2blobRefreshSent) {
				flow->configIdentity.l2blobConfig.ulOldL2blobJiffies = jiffies;
				flow->configIdentity.l2blobConfig.bl2blobRefreshSent = 1;
			}

			if (time_after(jiffies ,
				flow->configIdentity.l2blobConfig.ulOldL2blobJiffies +
				ASF_MAX_OLD_L2BLOB_JIFFIES_TIMEOUT)) {
				L2blobRefresh = ASF_L2BLOB_REFRESH_DROP_PKT;
				goto gen_indications;
			}

			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
		}
	}

#endif
	/* general purpose flag. This gets set when TCP connection is
	 * completed and we are waiting for FNP to delete flows. This
	 * flag is also used in firewall case*/
	if (flow->bDrop) {
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		if (FlowValidate) {
			FlowValidate = ASF_FLOWVALIDATE_INVALIDFLOW;
			goto gen_indications;
		}
#endif
		XGSTATS_INC(bDropPkts);
		asf_debug("dropping packet as bDrop is set\n");
		goto drop_pkt;
	}
	q = (unsigned short *)  ptrhdrOffset;
	if (nexthdr == NEXTHDR_UDP) {
		XGSTATS_INC(UdpPkts);
		if (((skb->len - (exthdrsize + sizeof(struct ipv6hdr))) < 8) ||
			(ntohs(*(q + 2)) > (skb->len - (exthdrsize + sizeof(struct ipv6hdr))))) {
				/* Udp header length is invalid */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpProtoHdr++;
#endif
			asfFfpSendLog(flow, ASF_LOG_ID_INVALID_UDP_HDRLEN, ulHashVal);
			goto drop_pkt;
		}
	} else { /* This is TCP case */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		int     optlen;
		unsigned short  tcp_data_len;
		ffp_flow_t      *oth_flow;
#endif

		XGSTATS_INC(TcpPkts);
		trhlen = (unsigned short)((*(ptrhdrOffset + 3) &
						0xf0000000) >> 28) * 4;
		/* Invalid length check
		   Length indicated in IPhdr - header length < expected transport header length
		   Length as indicated in skb - ip hder - ethernet header < expected transport header length
		*/
		if (((skb->len - (exthdrsize + sizeof(struct ipv6hdr))) < trhlen)) {
			/* Need to add code for TCP */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
			gstats->ulErrIpProtoHdr++;
#endif
			XGSTATS_INC(TcpHdrLenErr);
			asfFfpSendLog(flow, ASF_LOG_ID_INVALID_TCP_HDRLEN, ulHashVal);
			goto drop_pkt;
		}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		ptcph = (struct tcphdr *) ptrhdrOffset;
		/*optlen = ptcph->doff*4-20; */

		/* if (flow->bTcpTimeStamp && ((optlen = ptcph->doff*4-20) > 0)) */
		optlen = trhlen - 20;
		if (flow->bTcpTimeStampCheck && (optlen > 0)) {
			unsigned char *tcpopt;
			tcpopt = ((unsigned char *) (ptcph)) + 20;
			iRetVal = asfTcpProcessOptions(flow, tcpopt, optlen);
			if (iRetVal < 0) {
				asf_debug("invalid timestamp\n");
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpTimeStampErr);
				goto drop_pkt;
			}
		}

		oth_flow = ffp_ipv6_flow_by_id(&flow->other_id);
		if (!oth_flow) {
			asf_debug("other flow is not found!! strange!!\n");
			goto drop_pkt;
		}

		tcp_data_len = skb->len - (exthdrsize + sizeof(struct ipv6hdr) + trhlen);
		asf_debug_l2("TCP_STATE_PROC: tcp_data_len = %d\n", tcp_data_len);

		if (flow->bTcpOutOfSeqCheck) {
			ulLogId = asfTcpCheckForOutOfSeq(flow, oth_flow, ptcph,
						tcp_data_len, vsgInfo);
			if (unlikely(ulLogId != ASF_LOG_ID_DUMMY)) {
				asf_debug("out of seq check failed!\n");
				asfFfpSendLog(flow, ulLogId, ulHashVal);
				gstats->ulErrIpProtoHdr++;
				XGSTATS_INC(TcpOutOfSequenceErr);
				if (vsgInfo->bDropOutOfSeq)
					goto drop_pkt;
			}
		}
		asf_debug_l2("TCP_STATE_PROC: out of sequence checks finished!\n");

		ulOrgSeqNum = ntohl(ptcph->seq);
		ulOrgAckNum = ntohl(ptcph->ack_seq);
		asfTcpApplyDelta(flow, oth_flow, ptcph, ulOrgSeqNum, ulOrgAckNum);
		asf_debug_l2("TCP_STATE_PROC: applied delta to the packet\n");

		asfTcpUpdateState(flow, ulOrgSeqNum, ulOrgAckNum, ptcph, tcp_data_len);
		asf_debug_l2("TCP_STATE_PROC: updated current TCP state in the flow\n");
		iRetVal = asfTcpProcess(flow, oth_flow, ptcph);
		if (iRetVal < 0) {
			asf_debug("asfTcpProcess returned failure!\n");
			gstats->ulErrIpProtoHdr++;
			XGSTATS_INC(TcpProcessErr);
			goto drop_pkt;
		} else if (iRetVal == 1) {
			asf_debug("TCP_STATE_PROC: %s packet .. send InacRefresh indication\n",
				  ptcph->fin ? "FIN" : "RST");
			ulTcpState = (ptcph->fin) ? ASF_FFP_TCP_STATE_FIN_RCVD : ASF_FFP_TCP_STATE_RST_RCVD;
			bSpecialIndication = 1;
		} else if (iRetVal == 2) {
			ulTcpState = ASF_FFP_TCP_STATE_FIN_COMP;
			bSpecialIndication = 1;
		}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */
		asf_debug_l2("TCP state processing is done!\n");
	}
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	flow_stats->ulInPkts++;
/* Only timer based L2 blob refresh  is supported in current release */
	if (asf_l2blob_refresh_npkts &&
		(flow_stats->ulInPkts % asf_l2blob_refresh_npkts) == 0) {
		asf_debug_l2("Decided to send L2Blob refresh ind based on npkts\n");
		if (!L2blobRefresh)
			L2blobRefresh = ASF_L2BLOB_REFRESH_NORMAL;
	}
	flow->ulLastPktInAt = jiffies;
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

#ifdef ASF_INGRESS_MARKER
	if (ASF_QM_NULL_DSCP != flow->mkinfo.uciDscp)
		hdr->tc = flow->mkinfo.uciDscp;
#endif

	if (!flow->bIPsecOut &&
		(flow->l2blob_len == 0)) {
		asf_debug("Generating L2blob Indication as L2blob Not found!\n");
		L2blobRefresh = ASF_L2BLOB_REFRESH_RET_PKT_STK;
		goto gen_indications;
	}


	if (flow->bNat) {
		XGSTATS_INC(NatPkts);
		asf_debug_l2("applying NAT\n");
		/* Update IP Checksum also */
		if (_ipv6_addr_cmp((struct in6_addr *)&(ip6h->saddr), (struct in6_addr *)&(flow->ipv6SrcNATIp)))
			ipv6_addr_copy((struct in6_addr *)&(ip6h->saddr), (struct in6_addr *)&(flow->ipv6SrcNATIp));

		if (_ipv6_addr_cmp((struct in6_addr *)&(ip6h->daddr), (struct in6_addr *)&(flow->ipv6DestNATIp)))
			ipv6_addr_copy((struct in6_addr *)&(ip6h->daddr), (struct in6_addr *)&(flow->ipv6DestNATIp));


		*ptrhdrOffset = flow->ulNATPorts;

#ifdef ASF_DO_INC_CHECKSUM
		/* Hardware does not handle this, so we do incremental checksum */
		if (nexthdr == NEXTHDR_UDP) {
			q = ((unsigned short int *) ptrhdrOffset) + 3;
		} else { /*if (iph->protocol == IPPROTO_TCP) */
			q = ((unsigned short int *) ptrhdrOffset) + 8;
		}


#if (ASF_FEATURE_OPTION > ASF_MINIMUM)

		/* TCP delta checsum handling */
		if (nexthdr == NEXTHDR_TCP) {
			if (ulOrgSeqNum != ntohl(ptcph->seq))
				inet_proto_csum_replace4(q, skb,
					htonl(ulOrgSeqNum),
					ptcph->seq, 1);

			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				inet_proto_csum_replace4(q, skb,
					htonl(ulOrgAckNum),
					ptcph->ack_seq, 1);
		}
#endif

#else /* ASF_DO_INC_CHECKSUM */
		skb->ip_summed = CHECKSUM_PARTIAL;
		if (nexthdr == NEXTHDR_TCP)
			tcp_hdr(skb)->check = 0;
		else if (nexthdr == NEXTHDR_UDP)
			udp_hdr(skb)->check = 0;
#endif
	} else {

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
#ifdef ASF_DO_INC_CHECKSUM
		/* TCP delta checsum handling */
		if (nexthdr == NEXTHDR_TCP) {
			q = ((unsigned short int *) ptrhdrOffset) + 8;

			if (ulOrgSeqNum != ntohl(ptcph->seq))
				inet_proto_csum_replace4(q, skb,
					htonl(ulOrgSeqNum),
					ptcph->seq, 1);

			if (ulOrgAckNum != ntohl(ptcph->ack_seq))
				inet_proto_csum_replace4(q, skb,
					htonl(ulOrgAckNum),
					ptcph->ack_seq, 1);
		}
#else
		skb->ip_summed = CHECKSUM_PARTIAL;

		if (nexthdr == NEXTHDR_TCP)
			tcp_hdr(skb)->check = 0;
		else if (nexthdr == NEXTHDR_UDP)
			udp_hdr(skb)->check = 0;

#endif
#endif

	}

#ifdef ASF_IPSEC_FP_SUPPORT
	if (flow->bIPsecOut) {
		if (pFFPIPSecOut) {
			if (pFFPIPSecOut(ulVsgId,
				skb, ASF_BUF_FMT_SKBUFF, &flow->ipsecInfo) == 0) {
				goto gen_indications;
			} else
				return ASF_RTS;
		}
		goto drop_pkt;
	}
#endif /*ASF_IPSEC_FP_SUPPORT*/
	asf_debug_l2("attempting to xmit the packet\n");
	/*skb_set_network_header(skb, hh_len); */

	if (unlikely(skb_shinfo(skb)->frag_list)) {
		/* Handle frag list */
		struct sk_buff *pSkb;

		/* This is tricky */
		asfIpv6MakeFragment(skb, &pSkb);

		skb = pSkb;
	}

	do {
		struct sk_buff *pTempSkb;
		unsigned int tunnel_hdr_len = 0;

		pTempSkb = skb->next;
		asf_debug("Next skb = 0x%x\r\n", pTempSkb);
		skb->next = NULL;

		ip6h = ipv6_hdr(skb);

		skb->pkt_type = PACKET_FASTROUTE;
		asf_set_queue_mapping(skb, hdr->tc);

		/* make following unconditional*/
		if (flow->bVLAN)
			skb->vlan_tci = flow->tx_vlan_id;
		else
			skb->vlan_tci = 0;

		ip6h->hop_limit--;

		skb->data -= flow->l2blob_len;

#if 0 /* No need for this check */
		if (pSkb->data < pSkb->head) {
				asf_debug("SKB's head > data ptr .. UNDER PANIC!!!\n");
				ASFSkbFree(pSkb);
			continue;
		}
#endif

		skb->dev = flow->odev;


		asfCopyWords((unsigned int *)skb->data, (unsigned int *)flow->l2blob, flow->l2blob_len);

		if (flow->bIP6IP4Out) {
			struct iphdr *iph = (struct iphdr *)skb_network_header(skb);
			iph -= 1;
			iph->tot_len = skb->len + sizeof(struct iphdr);

			if (iph->ttl <= 1)
				iph->ttl = ip6h->hop_limit;

			if (iph->tos == 0)
				iph->tos = ip6h->priority;

			iph->check = 0;
			iph->check = ip_fast_csum((unsigned char *)iph, iph->ihl);

			tunnel_hdr_len = sizeof(struct iphdr);
		}

		if (flow->bPPPoE) {
			/* PPPoE packet.. Set Payload length in PPPoE header */
			*((short *)&(skb->data[(flow->l2blob_len - tunnel_hdr_len)-4])) = htons(skb->len + tunnel_hdr_len + 2);
		}

		skb->len += flow->l2blob_len;

		asf_debug("skb->network_header = 0x%x, skb->transport_header = 0x%x\r\n",
			  skb_network_header(skb), skb_transport_header(skb));
		asf_debug("Transmitting  buffer = 0x%x dev->index = %d\r\n",
			  skb, skb->dev->ifindex);

#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulOutBytes += skb->len;
		flow_stats->ulOutBytes += skb->len;
		vstats->ulOutBytes += skb->len;
#endif

#ifdef CONFIG_DPA
		if (skb->cb[BUF_INDOMAIN_INDEX])
			PER_CPU_BP_COUNT(dpa_bp)--;
#endif
#ifdef ASF_QOS
		/* Enqueue the packet in Linux QoS framework */
		asf_qos_handling(skb, &flow->tc_filter_res);
#else
		txq = netdev_get_tx_queue(skb->dev, skb->queue_mapping);
		netdev = skb->dev;
		if (asfDevHardXmit(skb->dev, skb) != 0) {
			asf_warn("Error in transmit: Should not happen\r\n");
			ASFSkbFree(skb);
		} else
			netdev->trans_start = txq->trans_start = jiffies;
#endif
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
		gstats->ulOutPkts++;
		vstats->ulOutPkts++;
		flow_stats->ulOutPkts++;
#endif

		skb = pTempSkb;
	} while (skb);

gen_indications:
	/* skip all other indications if flow_end indication is going to be sent */
#if (ASF_FEATURE_OPTION > ASF_MINIMUM)
	if (bSpecialIndication) {
		/*XGSTATS_INC(FlowSpecialInd);*/
		if (ffpCbFns.pFnFlowTcpSpecialPkts) {
			ASFFFPFlowSpecialPacketsInfo_t  ind;
			ffp_flow_t		      *oth_flow;

			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.tuple.bIPv4OrIPv6 = 1;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo = (ASF_uint8_t *)flow->as_flow_info;
			ind.ulTcpState = ulTcpState;

			oth_flow = ffp_ipv6_flow_by_id(&flow->other_id);

			ffp_copy_flow_stats(flow, &ind.flow_stats);
			if (oth_flow)
				ffp_copy_flow_stats(oth_flow, &ind.other_stats);
			else
				memset(&ind.other_stats, 0, sizeof(ind.other_stats));

			ffpCbFns.pFnFlowTcpSpecialPkts(ulVsgId, &ind);
		}
	}
	/* FlowValidate indicaion */
	if (FlowValidate) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowValidate) {
			ASFFFPFlowValidateCbInfo_t  ind;

			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.tuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.tuple.bIPv4OrIPv6 = 1;
			ind.tuple.usSrcPort = (flow->ulPorts >> 16);
			ind.tuple.usDestPort = flow->ulPorts&0xffff;
			ind.tuple.ucProtocol = flow->ucProtocol;
			ind.ulZoneId = flow->ulZoneId;
			ind.ulHashVal = htonl(ulHashVal);

			ind.ASFwInfo =
			(ASF_uint8_t *)flow->as_flow_info;
			ffpCbFns.pFnFlowValidate(ulVsgId, &ind);
		}

		switch (FlowValidate) {
		case ASF_FLOWVALIDATE_NORAMAL:
			break;
		case ASF_FLOWVALIDATE_INVALIDFLOW:
			XGSTATS_INC(bDropPkts);
			asf_debug("dropping packet as"\
					"bDrop is set\n");
			goto drop_pkt;
		default:
			break;
		}
	}
#endif /* (ASF_FEATURE_OPTION > ASF_MINIMUM) */

	if (L2blobRefresh) {
		if (!flow->bDeleted && ffpCbFns.pFnFlowRefreshL2Blob) {
			ASFFFPFlowL2BlobRefreshCbInfo_t  ind;

			ipv6_addr_copy((struct in6_addr *)&(ind.flowTuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcIp));
			ipv6_addr_copy((struct in6_addr *)&(ind.flowTuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestIp));
			ind.flowTuple.bIPv4OrIPv6 = 1;
			ind.flowTuple.usSrcPort = (flow->ulPorts >> 16);
			ind.flowTuple.usDestPort = flow->ulPorts&0xffff;
			ind.flowTuple.ucProtocol = flow->ucProtocol;

			if (flow->bNat) {
				ipv6_addr_copy((struct in6_addr *)&(ind.packetTuple.ipv6SrcIp), (struct in6_addr *)&(flow->ipv6SrcNATIp));
				ipv6_addr_copy((struct in6_addr *)&(ind.packetTuple.ipv6DestIp), (struct in6_addr *)&(flow->ipv6DestNATIp));
				ind.packetTuple.bIPv4OrIPv6 = 1;
				ind.packetTuple.usSrcPort = (flow->ulNATPorts >> 16);
				ind.packetTuple.usDestPort = flow->ulNATPorts&0xffff;
				ind.packetTuple.ucProtocol = flow->ucProtocol;
			} else
				ind.packetTuple	= ind.flowTuple;

			ind.ulZoneId = flow->ulZoneId;

			ind.ulHashVal = ulHashVal;

			ind.Buffer.linearBuffer.buffer = NULL;
			ind.Buffer.linearBuffer.ulBufLen = 0;
			ind.Buffer.nativeBuffer = NULL;

			ind.ASFwInfo = NULL;

			XGSTATS_INC(PktCtxL2blobInd);
			ffpCbFns.pFnFlowRefreshL2Blob(ulVsgId, &ind);
		}

		switch (L2blobRefresh) {
		case ASF_L2BLOB_REFRESH_RET_PKT_STK:
			 return ASF_RTS;
		case ASF_L2BLOB_REFRESH_DROP_PKT:
				goto drop_pkt;
				break;
		default:
				break;
		}

	}

	return ASF_DONE;
drop_pkt:
	asf_debug_l2("drop_pkt LABEL\n");
	/* TODO: we may have to iterate through frag_list and free all of them*/
	/* TODO: ensure all fragments are also dropped. and return STOLEN
	 always return stolen?? */
	pFreeFn(skb);
	return ASF_DONE;
}
EXPORT_SYMBOL(ASFFFPIPv6ProcessAndSendPkt);


/*
 * Initialization
 */
static int asf_ffp_ipv6_init_flow_table()
{
	ptrIArry_nd_t   *node;
#ifdef ASF_FFP_USE_SRAM
	dma_addr_t      addr;
#endif
	int		i;
	unsigned int	max_num;

	/* 10% of actual max value */
	max_num = ffp_ipv6_max_flows/20;
	get_random_bytes(&asf_ffp_ipv6_hash_init_value, sizeof(asf_ffp_ipv6_hash_init_value));

	if (asfCreatePool("FfpIPv6Flow", max_num,
			  max_num, (max_num/2),
			  sizeof(ffp_flow_t),
			  &ffp_ipv6_flow_pool_id) != 0) {
		asf_err("failed to initialize ffpipv6_flow_pool\n");
		return -ENOMEM;
	}

	asf_print("Initializing pointer array!\n");
	/* initialize pointer array */
	node = kzalloc((sizeof(ptrIArry_nd_t)*ffp_ipv6_max_flows), GFP_KERNEL);

	if (NULL == node)
		return -ENOMEM;

	ptrIArray_setup(&ffp_ipv6_ptrary, node, ffp_ipv6_max_flows, 1);

	/* allocate hash table */
#ifdef ASF_FFP_USE_SRAM
	addr = (unsigned long)(ASF_FFP_SRAM_BASE);
	ffp_ipv6_flow_table = (ffp_bucket_t *) ioremap_flags(addr,
			(sizeof(ffp_buc
et_t) * ffp_ipv6_hash_buckets),
			PAGE_KERNEL | _PAGE_COHERENT);
#else
	ffp_ipv6_flow_table = kzalloc((sizeof(ffp_bucket_t) * ffp_ipv6_hash_buckets),
					GFP_KERNEL);
#endif
	if (NULL == ffp_ipv6_flow_table) {
		asf_err("Unable to allocate memory for ffpipv6_flow_table");
		ptrIArray_cleanup(&ffp_ipv6_ptrary);
		return -ENOMEM;
	}

	for (i = 0; i < ffp_ipv6_hash_buckets; i++) {
		spin_lock_init(&ffp_ipv6_flow_table[i].lock);
		/* initialize circular list */
		ffp_ipv6_flow_table[i].pNext = (ffp_flow_t *) &ffp_ipv6_flow_table[i];
		ffp_ipv6_flow_table[i].pPrev = ffp_ipv6_flow_table[i].pNext;
	}
	return 0;
}

void asf_ffp_ipv6_cleanup_all_flows(void)
{
	int i;
	ffp_bucket_t    *bkt;
	ffp_flow_t      *head, *flow, *temp;

	for (i = 0; i < ffp_ipv6_hash_buckets; i++) {
		bkt = &ffp_ipv6_flow_table[i];
		head = (ffp_flow_t *)  bkt;
		spin_lock_bh(&bkt->lock);
		flow = head->pNext;
		rcu_assign_pointer(head->pNext, head);
		rcu_assign_pointer(head->pPrev, head);
		spin_unlock_bh(&bkt->lock);

		/* Now the list is detached from the bucket */
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			if (temp->pL2blobTmr)
				asfTimerStop(ASF_FFP_BLOB_TMR_ID, 0, temp->pL2blobTmr);

			if (temp->pInacRefreshTmr)
				asfTimerStop(ASF_FFP_INAC_REFRESH_TMR_ID, 0, temp->pInacRefreshTmr);

			ptrIArray_delete(&ffp_ipv6_ptrary, temp->id.ulArg1, ffp_ipv6_flow_free_rcu);
		}
	}
}
static void asf_ffp_ipv6_destroy_all_flows(void)
{
	int i;
	ffp_flow_t	*head, *flow, *temp;

	for (i = 0; i < ffp_ipv6_hash_buckets; i++) {
		head = (ffp_flow_t *) &ffp_ipv6_flow_table[i];
		flow = head->pNext;
		while (flow != head) {
			temp = flow;
			flow = flow->pNext;
			asfTimerFreeNodeMemory(temp->pL2blobTmr);
			asfTimerFreeNodeMemory(temp->pInacRefreshTmr);
			if (temp->bHeap)
				kfree(temp);
		}
	}
}
static void asf_ffp_ipv6_destroy_flow_table()
{
	/*asf_ffp_cleanup_all_flows(); */
	asf_ffp_ipv6_destroy_all_flows();

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	asf_debug("DestroyPool FlowPool\n");
	if (asfDestroyPool(ffp_ipv6_flow_pool_id) != 0)
		asf_debug("failed to destroy flow mpool\n");

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();

	/* free the table bucket array */
#ifdef ASF_FFP_USE_SRAM
		iounmap((unsigned long *)(ffp_flow_table));
#else
		kfree(ffp_ipv6_flow_table);
#endif

	/* destroy the pointer array */
	ptrIArray_cleanup(&ffp_ipv6_ptrary);

	asf_debug("Waiting for all CPUs to finish existing RCU callbacks!\n");
	synchronize_rcu();
}


int asf_ffp_ipv6_init(void)
{
	int err;

	asf_print("Initializing IPv6 Flow Table\n");
	err = asf_ffp_ipv6_init_flow_table();
	if (err) {
		asf_ffp_ipv6_destroy_flow_table();
		return err;
	}
	return 0;
}


void asf_ffp_ipv6_exit(void)
{
	asf_print("Destroying existing IPv6 flow table!\n");
	asf_ffp_ipv6_destroy_flow_table();
}
