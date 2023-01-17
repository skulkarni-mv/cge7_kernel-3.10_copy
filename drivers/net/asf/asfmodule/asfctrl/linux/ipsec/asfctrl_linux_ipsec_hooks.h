/**************************************************************************
 * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * Author:	Sandeep Malik <Sandeep.Malik@freescale.com>
 *		Hemant Agrawal <hemant@freescale.com>
 *
*/
/* History
*  Version	Date		Author		Change Description
*
*/

/***************************************************************************/

#ifndef _IPSEC_HOOKS_H
#define _IPSEC_HOOKS_H
#include <net/xfrm.h>

struct algo_info {
	const char *alg_name;
	int alg_type;
};

enum alg_type {
	ENCRYPTION = 0,
	AUTHENTICATION,
	INVALID
};

#define OUT_SA	1
#define IN_SA	0
#define ASFCTRL_MAX_SPD_CONTAINERS 300

#define ASF_DEF_IPSEC_TUNNEL_ID 0
#define ASF_DEF_IPSEC_TUNNEL_MAGIC_NUM 1
#define ASF_MAX_TUNNEL		64

#define ASF_IN_CONTANER_ID 	0
#define ASF_OUT_CONTANER_ID 	1
#define MAX_POLICY_CONT_ID 	2

#define ASFCTRL_DEF_PMTU 1500
#define MAX_AUTH_ENC_ALGO	9
#define MAX_ALGO_TYPE		2

#define XFRM_DIR(dir) ((dir == 0) ? "IN" : ((dir == 1) ? "OUT" : "FWD"))

void init_container_indexes(bool init);
void init_sa_indexes(bool init);
int free_container_index(struct xfrm_policy *xp, int cont_dir);
int is_policy_offloadable(struct xfrm_policy *xp);

int asfctrl_xfrm_encrypt_n_send(struct sk_buff *skb, struct xfrm_state *xfrm);

int asfctrl_xfrm_decrypt_n_send(struct sk_buff *skb, struct xfrm_state *xfrm);

int asfctrl_xfrm_dec_hook(
		struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl,
		int ifindex);
int asfctrl_xfrm_enc_hook(
		struct xfrm_policy *xp,
		struct xfrm_state *xfrm,
		struct flowi *fl,
		int ifindex);

#ifdef ASFCTRL_IPSEC_DEBUG
void asfctrl_xfrm_dump_tmpl(struct xfrm_tmpl *t);
void asfctrl_xfrm_dump_policy(struct xfrm_policy *xp, u8 dir);
void asfctrl_xfrm_dump_state(struct xfrm_state *xfrm);
#endif

void asfctrl_ipsec_km_unregister(void);
int asfctrl_ipsec_km_register(void);

extern uint32_t asfctrl_vsg_ipsec_cont_magic_id;
extern uint32_t asfctrl_max_sas;
extern uint32_t asfctrl_max_policy_cont;
extern bool bRedSideFragment;
extern bool bAntiReplayCheck;
extern bool bVolumeBasedExpiry;
extern bool bPacketBasedExpiry;

extern void  register_ipsec_offload_hook(struct asf_ipsec_callbackfn_s *);
extern void unregister_ipsec_offload_hook(void);

extern int ip_forward(struct sk_buff *);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 32)
extern struct xfrm_policy *xfrm_policy_check_flow(struct net *, struct flowi *,
					u16, u8);
#else
extern struct xfrm_policy *__xfrm_policy_lookup(struct net *, struct flowi *,
					u16, u8);
#endif
extern void xfrm_state_policy_mapping(struct xfrm_state *xfrm,
						struct policy_list *pol_lst);

int asfctrl_ipsec_get_policy4(struct sk_buff *skb, int dir,
					struct xfrm_policy **pol);
int asfctrl_ipsec_get_policy6(struct sk_buff *skb, int dir,
					struct xfrm_policy **pol);
int asfctrl_ipsec_get_policy(struct sk_buff *skb, int dir,
					struct xfrm_policy **pol);
int asfctrl_map_pol_insa(struct xfrm_state *xfrm, struct xfrm_policy *xp);
int asfctrl_map_pol_outsa(struct xfrm_state *xfrm, struct xfrm_policy *xp);
#endif
