/**************************************************************************
 * Copyright 2014, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfmcastnapi.h
 *
 * Description: NAPI infra for OSPF packet packet processing in ASF
 *
 * Authors:	Sridhar Pothuganti <sridhar.pothuganti@freescale.com>
 *
 */
/* History
 *  Version	Date		Author			Change Description
 *    1.0	04/04/2014	Sridhar Pothuganti	Initial Development
 *
*/
/****************************************************************************/

#ifndef __ASF_MCAST_NAPI_H
#define __ASF_MCAST_NAPI_H
typedef struct asf_mcast_napi_skb_list {
	struct  sk_buff *skb;
	char bHeap;
	struct list_head list;
} asf_mcast_napi_skb_list_t;

int  asf_mcast_napi_init(void);
void asf_mcast_napi_deinit(void);
int  asf_mcast_napi_send_packet(struct sk_buff *skb);
int  asf_mcast_napi_poll(struct napi_struct *napi, int budget);
void asf_mcast_dplane_cpumask_init(void);

#define ASF_MCAST_NAPI_BUDGET	32
#define ASF_MAX_NAPI_SKB_NODES	200

#endif
