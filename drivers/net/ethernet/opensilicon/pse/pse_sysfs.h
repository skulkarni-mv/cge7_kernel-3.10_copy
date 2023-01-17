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

#ifndef _PSE_SYSFS_H_
#define _PSE_SYSFS_H_

#define MODEL	"opv5xc"

/* Common variable */
#define DISABLE		0
#define ENABLE		1
#define MAC0_PORT	0
#define MAC1_PORT	1
#define CPU_PORT	2
#define PPE_PORT	3
#define MAC2_PORT	4
#define CFP_PORT	5
#define PMAP_MAC0_PORT	1
#define PMAP_MAC1_PORT	2
#define PMAP_CPU_PORT	4
#define PMAP_MAC2_PORT	8
#define TC_MIN		0
#define TC_MAX		7

#define ENABLE_CHECK(enable)						\
	((enable != ENABLE) && (enable != DISABLE))
#define TC_CHECK(tc) ((tc < TC_MIN) || (tc > TC_MAX))

#define HELP_ENABLE							\
	"Available option:\n"						\
	"\t< 0: disable, 1: enable >\n"

#define HELP_TC								\
	"Available traffic class:\n"					\
	"\t< 0: Queue 1 (default), 1: Queue 0, 2: Queue 2\n"		\
	"\t, 3: Queue 3, 4: Queue 4, 5: Queue 5, "			\
	"6: Queue 6, 7: Queue 7 >\n"

#define PSE_ENABLE_CHECK(enable) {					\
	if (ENABLE_CHECK(enable)) {					\
		printk(HELP_ENABLE);					\
		return count;						\
	}								\
}


/* pse_FC */
#define FC_SET_MIN	0
#define FC_SET_MAX	2047
#define FC_RLS_MIN	0
#define FC_RLS_MAX	2047
#define FC_CPU_EN_MIN	0
#define FC_CPU_EN_MAX	65535

#define HINT_FC_CPU_EN							\
	"\n**************** CPU port flow control  *****************\n"	\
	"ex: echo \"enable\" > cpu_fc_en\n"HELP_FC_CPU_EN

#define HINT_FC_SET							\
	"\n************** Flow control set threshold ***************\n"	\
	"ex: echo \"val\" > fc_set\n"HELP_FC_SET

#define HINT_FC_RLS							\
	"\n************ Flow control release threshold *************\n"	\
	"ex: echo \"val\" > fc_rls\n"HELP_FC_RLS

#define HINT_PORT_FC_IN_SET						\
	"\n*********** Flow control input set threshold ************\n"	\
	"ex: echo \"val\" > mac0_fc_in_set\n"HELP_PORT_FC_IN_SET

#define HINT_PORT_FC_IN_RLS						\
	"\n********* Flow control input release threshold **********\n"	\
	"ex: echo \"val\" > mac0_fc_in_rls\n"HELP_PORT_FC_IN_RLS

#define HINT_DROP_SET							\
	"\n************** MAC port drop set threshold **************\n"	\
	"ex: echo \"val\" > fc_drop_set\n"HELP_DROP_SET

#define HINT_DROP_RLS							\
	"\n*********** MAC port drop release threshold *************\n"	\
	"ex: echo \"val\" > fc_drop_rls\n"HELP_DROP_RLS

#define HINT_ALL_DROP_SET						\
	"\n************* All port drop set threshold ***************\n"	\
	"ex: echo \"val\" > fc_all_drop_set\n"HELP_ALL_DROP_SET

#define HINT_ALL_DROP_RLS						\
	"\n*********** All port drop release threshold *************\n"	\
	"ex: echo \"val\" > fc_all_drop_rls\n"HELP_ALL_DROP_RLS

#define HELP_FC_CPU_EN							\
	"Available CPU port flow control:\n"				\
	"\t0: Disable\n\t1: Enable\n"					\
	"\t\tBit[0] for TS Ring0\n\t\tBit[1] for TS Ring1\n"		\
	"\t\t...\n\t\tBit[15] for TS Ring15\n"

#define HELP_FC_SET							\
	"Available flow control set threshold:\n"			\
	"\t< 0 ~ 2047: set >\n"

#define HELP_FC_RLS							\
	"Available flow control release threshold:\n"			\
	"\t< 0 ~ 2047: release >\n"

#define HELP_PORT_FC_IN_SET						\
	"Available flow control input set threshold:\n"			\
	"\t< 0 ~ 2047: set >\n"

#define HELP_PORT_FC_IN_RLS						\
	"Available flow control input release threshold:\n"		\
	"\t< 0 ~ 2047: release >\n"

#define HELP_DROP_SET							\
	"Available MAC port drop set threshold:\n"			\
	"\t< 0 ~ 2047: set >\n"

#define HELP_DROP_RLS							\
	"Available MAC port drop release threshold:\n"			\
	"\t< 0 ~ 2047: release >\n"

#define HELP_ALL_DROP_SET						\
	"Available all port drop set threshold:\n"			\
	"\t< 0 ~ 2047: set >\n"

#define HELP_ALL_DROP_RLS						\
	"Available all port drop release threshold:\n"			\
	"\t< 0 ~ 2047: release >\n"

#define FC_SET_CHECK(set) {						\
	if ((set < FC_SET_MIN) || (set > FC_SET_MAX)) {			\
		printk(HELP_FC_SET);					\
			return count;					\
	}								\
}

#define FC_RLS_CHECK(rls) {						\
	if ((rls < FC_RLS_MIN) || (rls > FC_RLS_MAX)) {			\
		printk(HELP_FC_RLS);					\
			return count;					\
	}								\
}

#define FC_CPU_EN_CHECK(val) {						\
	if ((val < FC_CPU_EN_MIN) || (val > FC_CPU_EN_MAX)) {		\
		printk(HELP_FC_CPU_EN);					\
			return count;					\
	}								\
}

#define PORT_FC_IN_set_CHECK(set) {					\
	if ((set < FC_SET_MIN) || (set > FC_SET_MAX)) {			\
		printk(HELP_PORT_FC_IN_SET);				\
			return count;					\
	}								\
}

#define PORT_FC_IN_rls_CHECK(rls) {					\
	if ((rls < FC_RLS_MIN) || (rls > FC_RLS_MAX)) {			\
		printk(HELP_PORT_FC_IN_RLS);				\
			return count;					\
	}								\
}

/* PSE Shape */
#define SHAPE_BASE_RATE_MIN		0
#define SHAPE_BASE_RATE_MAX		2
#define SHAPE_TX_BW_MIN			0
#define SHAPE_TX_BW_MAX			127
#define SHAPE_BUCKET_SIZE_SEL_MIN	0
#define SHAPE_BUCKET_SIZE_SEL_MAX	16

#define HINT_PORT_SHAPE_BASE_RATE					\
	"\n******************** Port base rate *********************\n"	\
	"ex: echo \"base\" > port_shape_mac0_base_rate\n"HELP_SHAPE_BASE_RATE

#define HINT_PORT_SHAPE_TX_BW						\
	"\n******************* Port Tx_bandwidth *******************\n"	\
	"ex: echo \"tx_bw\" > port_shape_mac0_tx_bw\n"HELP_SHAPE_TX_BW

#define HINT_PORT_SHAPE_BUCKET_SEL					\
	"\n********** Maximum bucket size select per port **********\n"	\
	"ex: echo \"bucket_sel\" > port_shape_mac0_bucket_size\n"	\
	HELP_SHAPE_BUCKET_SEL

#define HINT_QUE_SHAPE_BASE_RATE					\
	"\n******************* Queue base_rate *********************\n"	\
	"ex: echo \"base\" > mac0_queue0_base_rate\n"HELP_SHAPE_BASE_RATE

#define HINT_QUE_SHAPE_TX_BW						\
	"\n****************** Queue Tx_bandwidth *******************\n"	\
	"ex: echo \"tx_bw\" > mac0_queue0_tx_bw\n"HELP_SHAPE_TX_BW

#define HINT_QUE_SHAPE_BUCKET_SEL					\
	"\n********** Maximum bucket size select per queue *********\n" \
	"ex: echo \"bucket_sel\" > mac0_queue0_bucket_size\n"		\
	HELP_SHAPE_BUCKET_SEL

#define HINT_SHAPE_TWO_BUCKET_SIZE_SEL					\
	"\n********** select one or two bucket size  ***************\n"	\
	"ex: echo \"two_bucket_size\" > shape_two_bucket_size\n"	\
	HELP_SHAPE_TWO_BUCKET_SIZE_SEL

#define HINT_SHAPE_CHECK_RESULT						\
	"\n******************** Check result ***********************\n"	\
	"cat /proc/"MODEL"/pse/shape\n"

#define HELP_SHAPE_BASE_RATE						\
	"Available base rate:\n"					\
	"\t< 0: 64 kbps, 1: 1M bps, 2: 10 Mbps >\n"

#define HELP_SHAPE_TX_BW						\
	"Available tx bandwidth:\n"					\
	"\t< 0: Disable rate limit contorl"				\
	", 1-127: Bandwidth = N x base_rate >\n"

#define HELP_SHAPE_BUCKET_SEL						\
	"Available bucket size select\n"				\
	"\t< 0: Queue TX bandwidth/1"					\
	", 1: Queue TX bandwidth/2"					\
	", 2: Queue TX bandwidth/4\n"					\
	"\t, 3: Queue TX bandwidth/8"					\
	", ..."								\
	", 16: Queue TX bandwidth/65536 >\n"

#define HELP_SHAPE_TWO_BUCKET_SIZE_SEL					\
	"Available two_bucket_size\n"					\
	"\t< 0: One bucket size"					\
	", 1: Two bucket size >\n"

#define SHAPE_base_rate_CHECK(base_rate) {				\
	if ((base_rate < SHAPE_BASE_RATE_MIN) ||			\
		(base_rate > SHAPE_BASE_RATE_MAX)) {			\
		printk(HELP_SHAPE_BASE_RATE);				\
		return count;						\
	}								\
}

#define SHAPE_tx_bw_CHECK(tx_bw) {					\
	if ((tx_bw < SHAPE_TX_BW_MIN) || (tx_bw > SHAPE_TX_BW_MAX)) {	\
		printk(HELP_SHAPE_TX_BW);				\
		return count;						\
	}								\
}

#define SHAPE_bucket_size_CHECK(bucket_size) {				\
	if ((bucket_size < SHAPE_BUCKET_SIZE_SEL_MIN) ||			\
	    (bucket_size > SHAPE_BUCKET_SIZE_SEL_MAX)) {		\
		printk(HELP_SHAPE_BUCKET_SEL);				\
		return count;						\
	}								\
}

#define SHAPE_BUCKET_SIZE_CHECK(sel) {					\
	if ((sel < SHAPE_BUCKET_SIZE_SEL_MIN) ||			\
		(sel > SHAPE_BUCKET_SIZE_SEL_MAX)) {			\
		printk(HELP_SHAPE_BUCKET_SEL);				\
		return count;						\
	}								\
}


/* PSE Police */
#define POLICE_QUE_EN_MIN	0
#define POLICE_QUE_EN_MAX	255
#define POLICE_MAX_P_MIN	1
#define POLICE_MAX_P_MAX	4095
#define POLICE_QUE_W_MIN	1
#define POLICE_QUE_W_MAX	4095
#define POLICE_GLB_MINTH_MIN	0
#define POLICE_GLB_MINTH_MAX	2047
#define POLICE_OUT_MAXTH_MIN	0
#define POLICE_OUT_MAXTH_MAX	2047
#define POLICE_OUT_MINTH_MIN	0
#define POLICE_OUT_MINTH_MAX	2047
#define POLICE_OQUE_MINTH_MIN	0
#define POLICE_OQUE_MINTH_MAX	2047

#define HINT_POLICE_RAND_EN						\
	"\n************* Psudo random generator enable *************\n"	\
	"ex: echo \"enable\" > police_rand_en\n"HELP_POLICE_RAND_EN

#define HINT_POLICE_EN							\
	"\n**************** Police function enable *****************\n"	\
	"ex: echo \"enable\" > police_mac0_en\n"HELP_POLICE_EN

#define HINT_POLICE_QUE_EN						\
	"\n*********** Police function enable per queue ************\n"	\
	"ex: echo \"enable\" > mac0_police_queue_en\n"HELP_POLICE_QUE_EN

#define HINT_POLICE_GLB_MINTH						\
	"\n***************** Global queue mininum ******************\n"	\
	"ex: echo \"glb_min_th\" > police_glb_min_th\n"HELP_POLICE_GLB_MINTH

#define HINT_POLICE_OQUE_MINTH						\
	"\n************* Police output queue threshold *************\n"	\
	"ex: echo \"oque_min_th\" > mac0_police_oque_min_th\n"		\
	HELP_POLICE_OQUE_MINTH

#define HINT_POLICE_OUT_MAXTH						\
	"\n***** Police output queue maximum threshold for RED *****\n"	\
	"ex: echo \"out_max_th\" > mac0_police_out_max_th\n"		\
	HELP_POLICE_OUT_MAXTH

#define HINT_POLICE_OUT_MINTH						\
	"\n***** Police output queue minimum threshold for RED *****\n"	\
	"ex: echo \"out_min_th\" > mac0_police_out_min_th\n"		\
	HELP_POLICE_OUT_MINTH

#define HINT_POLICE_MAX_P						\
	"\n************* Maximum probability for RED ***************\n"	\
	"ex: echo \"max_p\" > mac0_police_max_p\n"HELP_POLICE_MAX_P

#define HINT_POLICE_QUE_W						\
	"\n***************** Queue weight for RED ******************\n"	\
	"ex: echo \"que_w\" > mac0_police_que_w\n"HELP_POLICE_QUE_W

#define HINT_POLICE_CHECK_RESULT					\
	"\n******************** Check result ***********************\n"	\
	"cat /proc/"MODEL"/pse/police\n"

#define HELP_POLICE_RAND_EN						\
	"Available psudo random generator enable:\n"			\
	"\t< 0: disable, 1: enable >\n"

#define HELP_POLICE_EN							\
	"Available police function enable:\n"				\
	"\t< 0: disable, 1: enable >\n"

#define HELP_POLICE_QUE_EN						\
	"Available police function enable per queue:\n"			\
	"\t< 0: disable, 1: enable >\n"					\
	"\tBit 0 for queue0, bit1 for queue1, ..., and bit7 for queue7.\n"

#define HELP_POLICE_GLB_MINTH						\
	"Available global queue minimum threshold\n"			\
	"\t< 0 ~ 2047: glb_min_th >\n"

#define HELP_POLICE_OQUE_MINTH						\
	"Available police output queue threshold\n"			\
	"\t< 0 ~ 2047: oque_min_th >\n"

#define HELP_POLICE_OUT_MAXTH						\
	"Available Output queue maximun threshold for RED:\n"		\
	"\t< 0 ~ 2047: out_max_th >\n"

#define HELP_POLICE_OUT_MINTH						\
	"Available Output queue minimun threshold for RED:\n"		\
	"\t< 0 ~ 2047: out_min_th >\n"

#define HELP_POLICE_MAX_P						\
	"Available maxiumum probability for RED\n"			\
	"\t< 0 < N < 4095: Probability is N/4096 >\n"

#define HELP_POLICE_QUE_W						\
	"Available queue weight for RED\n"				\
	"\t< 0 < N < 4096: Weight is N/4096 >\n"

#define POLICE_GLB_MIN_TH_CHECK(glb_min_th) {				\
	if ((glb_min_th < POLICE_GLB_MINTH_MIN) ||			\
		(glb_min_th > POLICE_GLB_MINTH_MAX)) {			\
		printk(HELP_POLICE_GLB_MINTH);				\
		return count;						\
	}								\
}

#define POLICE_QUEUE_CHECK(queue_en, out_max_th, out_min_th, max_p,	\
					que_w, oque_min_th) {		\
	if ((queue_en < POLICE_QUE_EN_MIN) ||				\
		(queue_en > POLICE_QUE_EN_MAX)) {			\
		printk(HELP_POLICE_QUE_EN);				\
		return count;						\
	}								\
	if ((out_max_th < POLICE_OUT_MAXTH_MIN) ||			\
		(out_max_th > POLICE_OUT_MAXTH_MAX)) {			\
		printk(HELP_POLICE_OUT_MAXTH);				\
		return count;						\
	}								\
	if ((out_min_th < POLICE_OUT_MINTH_MIN) ||			\
		(out_min_th > POLICE_OUT_MINTH_MAX)) {			\
		printk(HELP_POLICE_OUT_MINTH);				\
		return count;						\
	}								\
	if ((max_p < POLICE_MAX_P_MIN) || (max_p > POLICE_MAX_P_MAX)) {	\
		printk(HELP_POLICE_MAX_P);				\
		return count;						\
	}								\
	if ((que_w < POLICE_QUE_W_MIN) || (que_w > POLICE_QUE_W_MAX)) {	\
		printk(HELP_POLICE_QUE_W);				\
		return count;						\
	}								\
	if ((oque_min_th < POLICE_OQUE_MINTH_MIN) ||			\
		(oque_min_th > POLICE_OQUE_MINTH_MAX)) {		\
		printk(HELP_POLICE_OQUE_MINTH);				\
		return count;						\
	}								\
	if (out_max_th <= out_min_th) {					\
		printk("\nThe out_max_th must be bigger than out_min_th.\n");\
		return count;						\
	}								\
}

/* PSE VLAN */
#define VLAN_INDEX_MIN		0
#define VLAN_INDEX_MAX		63
#define VLAN_ID_MIN		0
#define VLAN_ID_MAX		4095

#define HINT_VLAN_PORT_INGRESS						\
	"\n************* MAC0, MAC1, CPU ingress check *************\n"	\
	"ex: echo \"enable\" > mac_ingress_check\n"HELP_VLAN_PORT_INGRESS

#define HINT_VLAN_UNKNOWN_VLAN_TO_CPU					\
	"\n***************** Unknown VLAN to CPU *******************\n"	\
	"ex: echo \"enable\" > unknown_vlan_to_cpu\n"			\
	HELP_VLAN_UNKNOWN_VLAN_TO_CPU

#define HINT_VLAN_TABLE_WRITE						\
	"\n****************** Program vlan table *******************\n"	\
	"ex: echo \"index valid wan_side vid pmap\" > vlan_table_write\n"\
	HELP_VLAN_INDEX							\
	HELP_VLAN_VALID							\
	HELP_VLAN_WAN_SIDE						\
	HELP_VLAN_ID							\
	HELP_VLAN_PMAP

#define HINT_VLAN_TABLE_LOOKUP						\
	"\n******************* Lookup vlan table *******************\n"	\
	"if you like to lookup: vid = 20\n"				\
	"echo 20 > vlan_table_lookup\n"					\
	"cat vlan_table_lookup\n"					\
	"match index = 5 or Not match\n"

#define HINT_VLAN_CHECK_RESULT						\
	"\n******************** Check result ***********************\n"	\
	"cat /proc/"MODEL"/pse/vlan\n"

#define HELP_VLAN_PORT_INGRESS						\
	"Available port ingress enable:\n"				\
	"\t< 0: disable, 1: enable >\n"

#define HELP_VLAN_UNKNOWN_VLAN_TO_CPU					\
	"Available unknown VLAN to CPU enable:\n"			\
	"\t< 0: Discard"						\
	", 1: Redirect the frame received to CPU port >\n"

#define HELP_VLAN_INDEX							\
	"Available VLAN index:\n"					\
	"\t< 0: index 0, 1: index 1, ..., 63: index 63 >\n"

#define HELP_VLAN_VALID							\
	"Available VLAN valid:\n"					\
	"\t< 0: Un-valid entry, 1: Valid entry >\n"

#define HELP_VLAN_WAN_SIDE						\
	"Available WAN side:\n"						\
	"\t< 0: VLAN belongs to LAN side."				\
	", 1: VLAN belongs to WAN side. >\n"

#define HELP_VLAN_ID							\
	"Available VLAN ID:\n"						\
	"\t< 0 ~ 4095: vlan id >\n"

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define HELP_VLAN_PMAP							\
	"Available VLAN pmap:\n"					\
	"\t< 1: mac0, 2: mac1, 4: cpu, 8: mac2 >\n"
#else
#define HELP_VLAN_PMAP							\
	"Available VLAN pmap:\n"					\
	"\t< 1: mac0, 2: mac1, 4: cpu >\n"
#endif

#define VLAN_INDEX_RANGE_CHECK(index)					\
	((index < VLAN_INDEX_MIN) || (index > VLAN_INDEX_MAX))

#define VLAN_ID_RANGE_CHECK(vid)					\
	((vid < VLAN_ID_MIN) || (vid > VLAN_ID_MAX))

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define PMAP_RANGE_CHECK(port)						\
	((port < PMAP_MAC0_PORT) ||					\
	(port > (PMAP_MAC0_PORT + PMAP_MAC1_PORT + PMAP_CPU_PORT + PMAP_MAC2_PORT)))
#else
#define PMAP_RANGE_CHECK(port)						\
	((port < PMAP_MAC0_PORT) ||					\
	(port > (PMAP_MAC0_PORT + PMAP_MAC1_PORT + PMAP_CPU_PORT)))
#endif

#define VLAN_UNKNOWN_VLAN_TO_CPU_CHECK(enable) {			\
	if (ENABLE_CHECK(enable)) {					\
		printk(HELP_VLAN_UNKNOWN_VLAN_TO_CPU);			\
		return count;						\
	}								\
}

#define VLAN_ID_CHECK(vid) {						\
	if (VLAN_ID_RANGE_CHECK(vid)) {					\
		printk(HELP_VLAN_ID);					\
		return count;						\
	}								\
}

#define VLAN_TABLE_WRITE_CHECK(index, valid, wan, vid, pmap) {		\
	if (VLAN_INDEX_RANGE_CHECK(index) || ENABLE_CHECK(valid) ||	\
		ENABLE_CHECK(wan) || VLAN_ID_RANGE_CHECK(vid) ||	\
		PMAP_RANGE_CHECK(pmap)) {				\
		printk(HINT_VLAN_TABLE_WRITE);				\
		printk(HELP_VLAN_INDEX);				\
		printk(HELP_VLAN_VALID);				\
		printk(HELP_VLAN_WAN_SIDE);				\
		printk(HELP_VLAN_ID);					\
		printk(HELP_VLAN_PMAP);					\
		return count;						\
	}								\
}


/* PSE TC */
#define TC_ETYPE_INDEX_MIN	0
#define TC_ETYPE_INDEX_MAX	3
#define TC_ETYPE_MIN		0
#define TC_ETYPE_MAX		65535
#define TC_DSCP_INDEX_MIN	0
#define TC_DSCP_INDEX_MAX	63
#define TC_TCP_UDP_INDEX_MIN	0
#define TC_TCP_UDP_INDEX_MAX	3
#define TC_PORT_MIN		0
#define TC_PORT_MAX		65535

#define HINT_TC_ETYPE							\
	"\n****************** Etype traffic class ******************\n"	\
	"ex: echo \"index etype tc\" > tc_etype\n"			\
	HELP_ETYPE_INDEX						\
	HELP_ETYPE							\
	HELP_TC

#define HINT_TC_DSCP							\
	"\n***************** DSCP traffic classs *******************\n"	\
	"ex: echo \"index tc\" > tc_dscp\n"				\
	HELP_DSCP_INDEX							\
	HELP_TC

#define HINT_TC_TCP_UDP							\
	"\n************ TCP and UDP port trafffic class ************\n"	\
	"ex: echo \"index start_port stop_port tc\" > tc_tcp\n"		\
	"ex: echo \"index start_port stop_port tc\" > tc_udp\n"		\
	HELP_TCP_UDP_INDEX						\
	HELP_PORT							\
	HELP_TC

#define HINT_TC_CHECK_RESULT						\
	"\n********************* Check result **********************\n"	\
	"cat /proc/"MODEL"/pse/tc\n"

#define HELP_ETYPE_INDEX						\
	"Available ethernet type index:\n"				\
	"\t< 0: EType0, 1: EType1, 2: EType2, 3: EType3 >\n"

#define HELP_ETYPE							\
	"Available ethernet type:\n"					\
	"\t< 0x0800: IPv4, 0x86dd: IPv6, 0x8863: PPPoE Dis"		\
	"\t0x8864: PPPoE Sess, ..., 0x8100: VLAN >\n"

#define HELP_DSCP_INDEX							\
	"Available DSCP index:\n"					\
	"\t< 0: DSCP0, 1: DSCP1,  ..., 63: DSCP63 >\n"

#define HELP_TCP_UDP_INDEX						\
	"Availabe TCP and UDP index\n"					\
	"\t< 0: Port range 0, 1: Port range 1, "			\
	", 2: Port range 2, 3: Port range 3 >\n"

#define HELP_PORT							\
	"Available port number:\n"					\
	"\t< 0 ~ 65535: port, "						\
	"start port <= end port >\n"

#define ETYPE_INDEX_CHECK(index)					\
	((index < TC_ETYPE_INDEX_MIN) || (index > TC_ETYPE_INDEX_MAX))

#define ETYPE_CHECK(etype)						\
	((etype < TC_ETYPE_MIN) || (etype > TC_ETYPE_MAX))

#define DSCP_INDEX_CHECK(index)						\
	((index < TC_DSCP_INDEX_MIN) || (index > TC_DSCP_INDEX_MAX))

#define TCP_UDP_INDEX_CHECK(index)					\
	((index < TC_TCP_UDP_INDEX_MIN) || (index > TC_TCP_UDP_INDEX_MAX))

#define TCP_UDP_PORT_CHECK(start, stop)					\
	((start < TC_PORT_MIN) || (start > TC_PORT_MAX) ||		\
	(stop < TC_PORT_MIN) || (stop > TC_PORT_MAX) ||			\
	(start > stop))

#define TC_ETYPE_CHECK(index, etype, tc) {				\
	if (ETYPE_INDEX_CHECK(index) || ETYPE_CHECK(etype) ||		\
					TC_CHECK(tc)) {			\
		printk(HINT_TC_ETYPE);					\
		return count;						\
	}								\
}
#define TC_DSCP_CHECK(index, tc) {					\
	if (DSCP_INDEX_CHECK(index) || TC_CHECK(tc)) {			\
		printk(HINT_TC_DSCP);					\
		return count;						\
	}								\
}
#define TC_TCP_UDP_CHECK(index, start, stop, tc) {			\
	if (TCP_UDP_INDEX_CHECK(index) ||				\
		TCP_UDP_PORT_CHECK(start, stop) || TC_CHECK(tc)) {	\
		printk(HINT_TC_TCP_UDP);				\
		return count;						\
	}								\
}

/* PSE Pri */
#define PRI_MAC_PORT_MIN	MAC0_PORT
#define PRI_MAC_PORT_MAX	CFP_PORT
#define PRI_SCH_MODE_MIN	0
#define PRI_SCH_MODE_MAX	7
#define PRI_SCH_MINBW_MIN	0
#define PRI_SCH_MINBW_MAX	10
#define PRI_QUEUE_MIN		0
#define PRI_QUEUE_MAX		7
#define PRI_WEIGHT_MIN		0
#define PRI_WEIGHT_MAX		4
#define PRI_RING_ID_MIN		0
#define PRI_RING_ID_MAX		15

#define HINT_PRI_REGEN_USER_PRI						\
	"\n****** Regenerate user priority in TX priority tag ******\n"	\
	"ex: echo \"port enable\" > pri_regen_user_pri_en\n"		\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_DMAC_TC_EN						\
	"\n**************** DMAC traffic class check ***************\n"	\
	"ex: echo \"port enable\" > pri_dmac_tc_en\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_TCP_TC_EN						\
	"\n************* TCP packet traffic class check ************\n"	\
	"ex: echo \"port enable\" > pri_tcp_tc_en\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_UDP_TC_EN						\
	"\n************* UDP packet traffic class check ************\n"	\
	"ex: echo \"port enable\" > pri_udp_tc_en\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_DSCP_TC_EN						\
	"\n************** IP DSCP traffic class check **************\n"	\
	"ex: echo \"port enable\" > pri_dscp_tc_en\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_VLAN_TC_EN						\
	"\n**************** VLAN traffic class check ***************\n"	\
	"ex: echo \"port enable\" > pri_vlan_tc_en\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_ETHER_TC_EN						\
	"\n************ Ethernet type traffic class check **********\n"	\
	"ex: echo \"port enable\" > pri_ethertype_tc_en\n"		\
	HELP_MAC_TABLE_PORT						\
	HELP_ENABLE

#define HINT_PRI_PORT_TC						\
	"\n****************** Port traffic class *******************\n"	\
	"ex: echo \"port tc\" > pri_port_tc\n"				\
	HELP_MAC_TABLE_PORT						\
	HELP_TC

#define HINT_PRI_SCH_MODE						\
	"\n******************** Scheduling mode ********************\n"	\
	"ex: echo \"port mode\" > pri_sch_mode\n"			\
	HELP_ALL_PORT							\
	HELP_SCH_MODE

#define HINT_PRI_SCH_MINBW						\
	"\n************* Minimum bandwidth of scheduler ************\n"	\
	"ex: echo \"port bw\" > pri_sch_minbw\n"			\
	HELP_ALL_PORT							\
	HELP_SCH_MINBW

#define HINT_PRI_QUEUE_WEIGHT						\
	"\n****************** Priority queue weight ****************\n"	\
	"ex: echo \"port queue weight\" > pri_queue_weight\n"		\
	HELP_ALL_PORT							\
	HELP_QUEUE							\
	HELP_WEIGHT

#define HINT_PRI_QUEUE_RING_ID						\
	"\n****************** Priority queue ring ******************\n"	\
	"ex: echo \"port queue ring_id\" > pri_queue_ring_id\n"		\
	HELP_ALL_PORT							\
	HELP_QUEUE							\
	HELP_RING_ID

#define HINT_PRI_CHECK_RESULT						\
	"\n******************** check result ***********************\n"	\
	"cat /proc/"MODEL"/pse/pri\n"

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define HELP_ALL_PORT							\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port, 2: cpu port\n"			\
	"\t, 3: ppe port, 4: mac2 port, 5: cfp port >\n"
#else
#define HELP_ALL_PORT							\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port, 2: cpu port\n"			\
	"\t, 3: ppe port, 5: cfp port >\n"
#endif

#define HELP_SCH_MODE							\
	"Available scheduling mode:\n"					\
	"\t< 0: Strict priority, Q7 > Q6 ... > Q0 > Q1\n"		\
	"\t, 1 <= N <= 6: Mixed mode\n"					\
	"\t\tN = 1, Q7 > ... > Q2 > WRR(Q1, ..., Q0) for 8Q\n"		\
	"\t\tN = 6, Q7 > WRR(Q6, ..., Q0) for 8Q\n"			\
	"\t, 7: WRR(Q7, Q6, ..., Q1, Q0) >\n"

#define HELP_SCH_MINBW							\
	"Availbe ninmum bandwidth of scheduler:\n"			\
	"\t< Rate  = 64 Kbps x 2^N, where N = 0 - 10 >\n"

#define HELP_QUEUE							\
	"Available queue:\n"						\
	"\t< 0: Queue 0, 1: Queue 1, ..., 7: Queue 7 >\n"

#define HELP_WEIGHT							\
	"Available weight:\n"						\
	"\t< 0: Weight = 1, 1: Weight = 2, 2: Weight = 4\n"		\
	"\t, 3: Weight = 8, 4: Weight = 16 >\n"

#define HELP_RING_ID							\
	"Available ring_id:\n"						\
	"\t< 0: Ring 0, 1: Ring 1, ..., 15: Ring 15 >\n"

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define MAC_PORT_CHECK(port)						\
	((port < PRI_MAC_PORT_MIN) || (port > PRI_MAC_PORT_MAX))
#else
#define MAC_PORT_CHECK(port)						\
	(((port < PRI_MAC_PORT_MIN) || (port > PRI_MAC_PORT_MAX)) ||	\
	(port == MAC2_PORT))
#endif

#define SCH_MODE_CHECK(mode)						\
	((mode < PRI_SCH_MODE_MIN) || (mode > PRI_SCH_MODE_MAX))

#define SCH_MINBW_CHECK(bw)						\
	((bw < PRI_SCH_MINBW_MIN) || (bw > PRI_SCH_MINBW_MAX))

#define QUEUE_CHECK(queue)						\
	((queue < PRI_QUEUE_MIN) || (queue > PRI_QUEUE_MAX))

#define WEIGHT_CHECK(weight)						\
	((weight < PRI_WEIGHT_MIN) || (weight > PRI_WEIGHT_MAX))

#define RING_ID_CHECK(ring_id)						\
	((ring_id < PRI_RING_ID_MIN) || (ring_id > PRI_RING_ID_MAX))

#define PRI_REGEN_USER_PRI_EN_CHECK(port, enable) {			\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_REGEN_USER_PRI);			\
		return count;						\
	}								\
}

#define PRI_DMAC_TC_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_DMAC_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_TCP_TC_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_TCP_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_UDP_TC_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_UDP_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_DSCP_TC_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_DSCP_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_VLAN_TC_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_VLAN_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_ETHERTYPE_TC_EN_CHECK(port, enable) {			\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		ENABLE_CHECK(enable)) {					\
		printk(HINT_PRI_ETHER_TC_EN);				\
		return count;						\
	}								\
}

#define PRI_PORT_TC_CHECK(port, tc) {					\
	if (MAC_PORT_CHECK(port) || MAC_TABLE_PORT_CHECK(port) ||	\
		TC_CHECK(tc)) {						\
		printk(HINT_PRI_PORT_TC);				\
		return count;						\
	}								\
}

#define PRI_SCH_MODE_CHECK(port, mode) {				\
	if (MAC_PORT_CHECK(port) || SCH_MODE_CHECK(mode)) {		\
		printk(HINT_PRI_SCH_MODE);				\
		return count;						\
	}								\
}

#define PRI_SCH_MINBW_CHECK(port, bw) {					\
	if (MAC_PORT_CHECK(port) || SCH_MINBW_CHECK(bw)) {		\
		printk(HINT_PRI_SCH_MINBW);				\
		return count;						\
	}								\
}

#define PRI_QUEUE_WEIGHT_CHECK(port, queue, weight) {			\
	if (MAC_PORT_CHECK(port) || QUEUE_CHECK(queue) ||		\
				WEIGHT_CHECK(weight)) {			\
		printk(HINT_PRI_QUEUE_WEIGHT);				\
		return count;						\
	}								\
}

#define PRI_QUEUE_RING_ID_CHECK(port, queue, ring_id) {			\
	if (MAC_PORT_CHECK(port) || QUEUE_CHECK(queue) ||		\
				RING_ID_CHECK(ring_id)) {		\
		printk(HINT_PRI_QUEUE_RING_ID);				\
		return count;						\
	}								\
}


/* PSE MAC Table */
#define MAC_PORT_INDEX_MIN	0
#define MAC_PORT_INDEX_MAX	1
#define CPU_PORT_INDEX_MIN	0
#define CPU_PORT_INDEX_MAX	7
#define MAC_PRIORITY_MIN	0
#define MAC_PRIORITY_MAX	7
#define MAC_HASH_ALGO_MIN	0
#define MAC_HASH_ALGO_MAX	2

#define HINT_MAC_TABLE							\
	"\n*********************** MAC Table ***********************\n"	\
	"ex: echo \"port index mac_addr priority\" > mac_table\n"	\
	HELP_MAC_TABLE_PORT						\
	HELP_MAC_TABLE_INDEX						\
	HELP_MAC_ADDRESS						\
	HELP_MAC_PRIORITY

#define HINT_MAC_HASH_TABLE						\
	"\n********************* MAC hash table ********************\n"	\
	"ex: echo \"port mac_addr\" > mac_hash_table\n"			\
	HELP_MAC_TABLE_PORT						\
	HELP_MAC_ADDRESS

#define HINT_MAC_HASH_ALGO						\
	"\n************* MAC address hashing algorithm *************\n"	\
	"ex: echo \"algo\" > mac_hash_algo\n"				\
	HELP_MAC_HASH_ALGO

#define HINT_MAC_TABLE_CHECK_RESULT					\
	"\n******************* check result ************************\n"	\
	"cat /proc/"MODEL"/pse/mac_table\n"				\
	"cat /proc/"MODEL"/pse/mac_hash_table\n"

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define HELP_MAC_TABLE_PORT						\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port, 2: cpu port, 4: mac2 port >\n"
#else
#define HELP_MAC_TABLE_PORT						\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port, 2: cpu port >\n"
#endif

#define HELP_MAC_TABLE_INDEX						\
	"Available MAC table index:\n"					\
	"\t< For CPU port, the index range is from 0 to 7.\n"		\
	"\t, For MAC port, the index range is from 0 to 1. >\n"

#define HELP_MAC_PRIORITY						\
	"Available MAC priority:\n"					\
	"\t< 0-15: MAC priority >\n"

#define HELP_MAC_ADDRESS						\
	"Available MAC address:\n"					\
	"\t< 00:11:22:33:44:55 or 00-11-22-33-44-55 >\n"

#define HELP_MAC_HASH_ALGO						\
	"Available MAC hash algorithm:\n"				\
	"\t< 0: direct mode, 1: XOR hash, 2: CRC-16 hash >\n"

#define MAC_TABLE_PORT_CHECK(port)					\
	((PPE_PORT == port) || (CFP_PORT == port))

#define MAC_TABLE_INDEX_CHECK(port, index)				\
	(((port == CPU_PORT) && ((index < CPU_PORT_INDEX_MIN) ||	\
		(index > CPU_PORT_INDEX_MAX))) ||			\
	 ((port != CPU_PORT) && ((index < MAC_PORT_INDEX_MIN) ||	\
		(index > MAC_PORT_INDEX_MAX)))				\
	)

#define MAC_PRIORITY_CHECK(pri)						\
	((pri < MAC_PRIORITY_MIN) || (pri > MAC_PRIORITY_MAX))

#define MAC_TABLE_CHECK(port, index, mac_u32, pri) {			\
	if (MAC_PORT_CHECK(port) ||					\
		MAC_TABLE_PORT_CHECK(port) ||				\
		MAC_TABLE_INDEX_CHECK(port, index) ||			\
		MAC_PRIORITY_CHECK(pri)) {				\
		printk(HINT_MAC_TABLE);					\
		return count;						\
	}								\
}

#define MAC_HASH_TABLE_CHECK(port, mac_u32) {				\
	if (MAC_PORT_CHECK(port) ||					\
		MAC_TABLE_PORT_CHECK(port)) {				\
		printk(HINT_MAC_HASH_TABLE);				\
		return count;						\
	}								\
}

#define MAC_HASH_ALGO_CHECK(algo) {					\
	if ((algo < MAC_HASH_ALGO_MIN) || (algo > MAC_HASH_ALGO_MAX)) { \
		printk(HELP_MAC_HASH_ALGO);				\
		return count;						\
	}								\
}


/* PSE CS Offload */
#define HINT_CS_OFFLOAD_FS						\
	"\n*************** From PSE checksum check ****************\n"	\
	"ex: echo \"enable\" > cs_offload_fs\n"HELP_ENABLE

#define HINT_CS_OFFLOAD_TS						\
	"\n************** To PSE checksum generation **************\n"	\
	"ex: echo \"enable\" > cs_offload_ts\n"HELP_ENABLE


/* PSE FS DMA */
#define FS_TIMEOUT_TIME_MIN	0
#define FS_TIMEOUT_TIME_MAX	600

#define HINT_FS_STATUS_INTR_MASK					\
	"\n********* Interrupt mask of the interupt status *********\n"	\
	"ex: echo \"mask\" > fs_status_intr_mask\n"HELP_FS_STATUS_INTR_MASK

#define HINT_FS_RING_DMA_CTRL						\
	"\n****************** From PSE DMA enable ******************\n"	\
	"ex: echo \"mask\" > fs_ring_dma_ctrl\n"HELP_FS_RING_DMA_CTRL

#define HINT_FS_TIMEOUT_TIME						\
	"\n*** The Interval of Time Out For FS No Descriptor Buffers ***\n" \
	"ex: echo \"time\" > fs_timeout_time\n"HELP_FS_TIMEOUT_TIME

#define HINT_LRO_TIMEOUT_TIME						\
	"\n** The Interval of Time Out For LRO No Header or Payload Buffers **\n" \
	"ex: echo \"time\" > lro_timeout_time\n"HELP_FS_TIMEOUT_TIME

#define HINT_FS_RING_CHECK						\
	"\n**************** Check FS Descripor Rings ***************\n" \
	"ex: echo \"enable\" > fs_ring_check\n"HELP_ENABLE

#define HINT_LRO_RING_CHECK						\
	"\n*************** Check LRO Descripor Rings ***************\n" \
	"ex: echo \"enable\" > lro_ring_check\n"HELP_ENABLE

#define HELP_FS_STATUS_INTR_MASK					\
	"There are up to 32 bits:\n"					\
	"\t< 0: unmask, 1: mask >\n"

#define HELP_FS_RING_DMA_CTRL						\
	"There are up to 16 FS Descriptor rings:\n"			\
	"\t< 0: disable, 1: enable >\n"

#define HELP_FS_TIMEOUT_TIME						\
	"Available interval of timeout:\n"				\
	"\t< 0: disable, 1 <= N <= 600, unit second >\n"

#define FS_TIMEOUT_TIME_CHECK(time) {					\
	if ((time < FS_TIMEOUT_TIME_MIN) ||				\
		(time > FS_TIMEOUT_TIME_MAX)) {				\
		printk(HELP_FS_TIMEOUT_TIME);				\
		return count;						\
	}								\
}


/* PSE Delay intr */
#define DELAY_MAX_PEND_INT_CNT_MIN	0
#define DELAY_MAX_PEND_INT_CNT_MAX	255
#define DELAY_MAX_PEND_TIME_MIN		0
#define DELAY_MAX_PEND_TIME_MAX		255

#define HINT_MAX_PEND_INT_CNT						\
	"\n********* Maximum number of pending interrupts **********\n"	\
	"ex: echo \"num\" > max_pend_int_cnt\n"HELP_MAX_PEND_INT_CNT

#define HINT_MAX_PEND_TIME						\
	"\n******* Maximum pending time between interrupts *********\n"	\
	"ex: echo \"time\" > max_pend_time\n"HELP_MAX_PEND_TIME

#define HELP_MAX_PEND_INT_CNT						\
	"Available maximun number of pending interrupts\n"		\
	"\t< 0 ~ 255: max_pend_int_cnt >\n"

#define HELP_MAX_PEND_TIME						\
	"Available maximum pending time between interrupts\n"		\
	"\t< 0 ~ 255: max_pend_time >\n"

#define DELAY_MAX_PEND_INT_CNT_CHECK(cnt) {				\
	if ((cnt < DELAY_MAX_PEND_INT_CNT_MIN) ||			\
		(cnt > DELAY_MAX_PEND_INT_CNT_MAX)) {			\
		printk(HELP_MAX_PEND_INT_CNT);				\
		return count;						\
	}								\
}

#define DELAY_MAX_PEND_TIME_CHECK(time) {				\
	if ((time < DELAY_MAX_PEND_TIME_MIN) ||				\
		(time > DELAY_MAX_PEND_TIME_MAX)) {			\
		printk(HELP_MAX_PEND_TIME);				\
		return count;						\
	}								\
}


/* PSE Port cfg */
#define PORT_CFG_RX_BCS_RATE_MIN	0
#define PORT_CFG_RX_BCS_RATE_MAX	10

#define HINT_MAC_PROMISC_MODE						\
	"\n********************** Promisc mode *********************\n"	\
	"ex: echo \"port enable\" > promisc_mode\n"			\
	HELP_MAC_PORT_CFG						\
	HELP_PROMISC_MODE

#define HINT_MAC_MYMAC_ONLY						\
	"\n********************** My MAC only **********************\n"	\
	"ex: echo \"port enable\" > my_mac_only\n"			\
	HELP_MAC_PORT_CFG						\
	HELP_MYMAC_ONLY

#define HINT_MAC_BLOCK_MODE						\
	"\n********************* Blocking mode *********************\n"	\
	"ex: echo \"port enable\" > block_mode\n"			\
	HELP_MAC_PORT_CFG						\
	HELP_BLOCK_MODE

#define HINT_MAC_BLOCKING_STATE						\
	"\n********************* Blocking state ********************\n"	\
	"ex: echo \"port enable\" > blocking_state\n"			\
	HELP_MAC_PORT_CFG						\
	HELP_ENABLE

#define HINT_MAC_BCS_BC_PKT_EN						\
	"\n*** broadcast packet in broadcast storm rate control ****\n"	\
	"ex: echo \"port enable\" > broadcast_storm_rate_en\n"		\
	HELP_MAC_PORT_CFG						\
	HELP_ENABLE

#define HINT_RES_MC_FLT							\
	"\n********* Reserved multicast address filtering **********\n"	\
	"ex: echo \"enable\" > res_mc_flt\n"HELP_RES_MC_FLT

#define HINT_ACCEPT_CRC_PKT						\
	"\n************ Forward CRC error packet to CPU ************\n"	\
	"ex: echo \"enable\" > accept_crc_pkt\n"HELP_ACCEPT_CRC_PKT

#define HINT_RX_BCS_RATE						\
	"\n**************** RX broadcast storm rate ****************\n"	\
	"ex: echo \"rate\" > rx_broadcast_storm_rate\n"HELP_RX_BCS_RATE

#define HINT_COL_MODE							\
	"\n******************* Collision control *******************\n" \
	"ex: echo \"mode\" > col_mode\n"HELP_COL_MODE

#define HINT_BP_MODE							\
	"\n******************* Backpressure mode *******************\n" \
	"ex: echo \"mode\" > bp_mode\n"HELP_BP_MODE

#define HINT_JAM_NO							\
	"\n******** Numbers of consecutive backpressure jam ********\n" \
	"ex: echo \"num\" > jam_no\n"HELP_JAM_NO

#define HINT_BKOFF_MODE							\
	"\n**************** Collision backoff timer ****************\n" \
	"ex: echo \"mode\" > bkoff_mode\n"HELP_BKOFF_MODE

#define HINT_MAC_BP_EN							\
	"\n***************** Backpressure control ******************\n" \
	"ex: echo \"port enable\" > bp_en\n"				\
	HELP_MAC_PORT_CFG						\
	HELP_ENABLE

#define HELP_PROMISC_MODE						\
	"Available promiscuous mode:\n"					\
	"\t< 0: disable, 1: enable, MY_MAC_ONLY is not effect >\n"

#define HELP_MYMAC_ONLY							\
	"Available MYMAC only:\n"					\
	"\t< 0: My MAC or BC or MAC Hash Hit packet\n"			\
	"\t, 1: Only My MAC or BC packets >\n"

#define HELP_BLOCK_MODE							\
	"Available block mode:\n"					\
	"\t< 0: Redirect all frames to the CPU\n"			\
	"\t, 1: Redirect only BPDU frames to the CPU >\n"

#define HELP_RES_MC_FLT							\
	"Available reserved multicast address filtering:\n"		\
	"\t< 0: Forward, 1: Discard >\n"

#define HELP_ACCEPT_CRC_PKT						\
	"Available forward CRC error packet to CPU:\n"			\
	"\t< 0: Drop frames with CRC error\n"				\
	"\t, 1: Redirect frames with CRC error to the CPU >\n"

#define HELP_RX_BCS_RATE						\
	"Available RX broadcast storm rate:\n"				\
	"\t< Rate = 64 Kbps x 2^N, where N = 0-10 >\n"

#define HELP_COL_MODE							\
	"Available Collision Control mode:\n"				\
	"\t< 0: Never drop a frame due to collisions\n"			\
	"\t, 1: Excessive collision limit = 1\n"			\
	"\t, 2: Excessive collision limit = 2\n"			\
	"\t, 3: Excessive collision limit = 16 >\n"

#define HELP_BP_MODE							\
	"Available Backpressure mode:\n"				\
	"\t< 0: Disable backpressure\n"					\
	"\t, 1: Smart backpressure, the jam number is set by JAM_NO\n"	\
	"\t, 2: Jam all incoming packets until backpressure condition release\n" \
	"\t, 3: Force carrier HIGH to do backpressure >\n"

#define HELP_JAM_NO							\
	"Available numbers of consecutive backpressure jam fragments:\n" \
	"\t< 0 <= N <= 15 >\n"

#define HELP_BKOFF_MODE							\
	"Available Collision backoff timer:\n"				\
	"\t< 0: Re-transmit immedidately after collision\n"		\
	"\t, 1-6: Backoff range from 0 to 2(N - 1)\n"			\
	"\t, 7: Backoff according to IEEE Std. 802.3 >\n"

#define HELP_BP_EN							\
	"Available Backpressure Control:\n"				\
	"\t< 0: Disable, 1: Enable >\n"

#define MAC_GLOB_CFG_COL_MODE_CHECK(mode) {				\
	if ((mode < 0) || (mode > 3)) {					\
		printk(HINT_COL_MODE);					\
		return count;						\
	}								\
}

#define MAC_GLOB_CFG_BP_MODE_CHECK(mode) {				\
	if ((mode < 0) || (mode > 3)) {					\
		printk(HINT_BP_MODE);					\
		return count;						\
	}								\
}

#define MAC_GLOB_CFG_JAM_NO_CHECK(no) {					\
	if ((no < 0) || (no > 15)) {					\
		printk(HINT_JAM_NO);					\
		return count;						\
	}								\
}

#define MAC_GLOB_CFG_BKOFF_MODE_CHECK(no) {				\
	if ((no < 0) || (no > 7)) {					\
		printk(HINT_BKOFF_MODE);				\
		return count;						\
	}								\
}

#define PORT_CFG_BP_EN_CHECK(port, enable) {				\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_BP_EN);					\
		return count;						\
	}								\
}

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define HELP_MAC_PORT_CFG						\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port, 4: mac2 port >\n"
#else
#define HELP_MAC_PORT_CFG						\
	"Available port:\n"						\
	"\t< 0: mac0 port, 1: mac1 port >\n"
#endif

#define RX_BCS_RATE_CHECK(rate)						\
	((rate < PORT_CFG_RX_BCS_RATE_MIN) || (rate > PORT_CFG_RX_BCS_RATE_MAX))

#ifdef CONFIG_ARCH_OPV5XC_ES2
#define MAC_PORT_CFG_CHECK(port)					\
	((port != MAC0_PORT) && (port != MAC1_PORT) && (port != MAC2_PORT))
#else
#define MAC_PORT_CFG_CHECK(port)					\
	((port != MAC0_PORT) && (port != MAC1_PORT))
#endif

#define PORT_CFG_PROMISC_MODE_CHECK(port, enable) {			\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_PROMISC_MODE);				\
		return count;						\
	}								\
}

#define PORT_CFG_MYMAC_ONLY_CHECK(port, enable) {			\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_MYMAC_ONLY);				\
		return count;						\
	}								\
}

#define PORT_CFG_BLOCKING_STATE_CHECK(port, enable) {			\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_BLOCKING_STATE);			\
		return count;						\
	}								\
}

#define PORT_CFG_BLOCK_MODE_CHECK(port, enable) {			\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_BLOCK_MODE);				\
		return count;						\
	}								\
}

#define PORT_CFG_STORM_RATE_EN_CHECK(port, enable) {			\
	if (MAC_PORT_CFG_CHECK(port) || ENABLE_CHECK(enable)) {		\
		printk(HINT_MAC_BCS_BC_PKT_EN);				\
		return count;						\
	}								\
}

#define PORT_CFG_RX_BCS_RATE_CHECK(rate) {				\
	if (RX_BCS_RATE_CHECK(rate)) {					\
		printk(HELP_RX_BCS_RATE);				\
		return count;						\
	}								\
}


/* PSE VLAN config */
#define VLAN_ETYPE_MIN	0
#define VLAN_ETYPE_MAX	65535
#define HINT_VLAN_S_NEIGHBOR						\
	"\n************** S Neighbor MAC0, MAC1, CPU ***************\n"	\
	"ex: echo \"neighbor\" > s_neighbor_mac0\n"HELP_S_NEIGHBOR

#define HINT_VLAN_S_COMPONENT						\
	"\n********************** S Component **********************\n"	\
	"ex: echo \"component\" > s_component\n"HELP_S_COMPONENT

#define HINT_VLAN_STAG_ETYPE						\
	"\n*********************** Stag etype **********************\n"	\
	"ex: echo \"etype\" > stag_etype\n"HELP_STAG_ETYPE

#define HINT_VLAN_WAN_PORT						\
	"\n******** A port map to set which port is WAN port *******\n"	\
	"ex: echo \"wan\" > wan_port_mac0\n"HELP_WPMAP

#define HELP_S_NEIGHBOR							\
	"Available neighbor option:\n"					\
	"\t< 0: C-Neighbor, 1: S-Neighbor >\n"

#define HELP_S_COMPONENT						\
	"Available component option:\n"					\
	"\t< 0: C component, 1: S component >\n"

#define HELP_STAG_ETYPE							\
	"Available stag etype:\n"					\
	"\t< 0x0000 ~ 0xffff: etype >\n"

#define HELP_WPMAP							\
	"Available component option:\n"					\
	"\t< 0: LAN port, 1: WAN port >\n"

#define PSE_STAG_ETYPE_CHECK(etype) {					\
	if ((etype < VLAN_ETYPE_MIN) || (etype > VLAN_ETYPE_MAX)) {	\
		printk(HELP_STAG_ETYPE);				\
		return count;						\
	}								\
}


/* PSE Test */
#define HINT_TEST_MAC0_INTLB						\
	"\n************** MAC0 internal loopback test **************\n"	\
	"ex: echo \"enable\" > mac0_int_loopback\n"HELP_ENABLE

#define HINT_TEST_MAC0_EXTLB						\
	"\n************** MAC0 external loopback test **************\n"	\
	"ex: echo \"enable\" > mac0_ext_loopback\n"HELP_ENABLE

#define HINT_TEST_MAC1_INTLB						\
	"\n************** MAC1 internal loopback test **************\n"	\
	"ex: echo \"enable\" > mac1_int_loopback\n"HELP_ENABLE

#define HINT_TEST_MAC1_EXTLB						\
	"\n************** MAC1 external loopback test **************\n"	\
	"ex: echo \"enable\" > mac1_ext_loopback\n"HELP_ENABLE


/* PSE EEE */
#define EEE_CHECK_TIME_MIN		0
#define EEE_CHECK_TIME_MAX		15
#define EEE_WAKE_TIME_MIN		0
#define EEE_WAKE_TIME_MAX		255
#define EEE_GATE_CYCLE_MIN		0
#define EEE_GATE_CYCLE_MAX		255
#define EEE_LPI_REQUEST_MODE_MIN	0
#define EEE_LPI_REQUEST_MODE_MAX	2

#define HINT_EEE_RX_EN							\
	"\n************ EEE function of RX MAC0 or MAC1 ************\n"	\
	"ex: echo \"enable\" > eee_rx0_enable\n"HELP_ENABLE

#define HINT_EEE_TX_EN							\
	"\n************ EEE function of TX MAC0 or MAC1 ************\n"	\
	"ex: echo \"enable\" > eee_tx0_enable\n"HELP_ENABLE

#define HINT_EEE_LPI_REQUEST_MODE					\
	"\n********************** Report mode **********************\n"	\
	"ex: echo \"mode\" > lpi_request_tx0\n"HELP_LPI_REQUEST_MODE

#define HINT_EEE_CHECK_TIME						\
	"\n****************** Transmit check time ******************\n"	\
	"ex: echo \"time\" > eee_check_time\n"HELP_CHECK_TIME

#define HINT_EEE_WAKE_TIME						\
	"\n****************** Transmit wake time *******************\n"	\
	"ex: echo \"time\" > eee_wake_time\n"HELP_WAKE_TIME

#define HINT_EEE_GATE_CYCLE						\
	"\n*********************** Gate cycle **********************\n"	\
	"ex: echo \"time\" > eee_gate_cycle\n"HELP_GATE_CYCLE

#define HINT_EEE_REALTEK_CRS_EN						\
	"\n************** realtek phy eee crs enable ***************\n"	\
	"ex: echo \"enable\" > realtek_phy_eee_crs_enable\n"HELP_ENABLE

#define HINT_EEE_REALTEK_MAC_MODE_EN					\
	"\n************ realtek phy eee mac mode enable ************\n"	\
	"ex: echo \"enable\" > realtek_phy_mac_mode_enable\n"HELP_ENABLE

#define HINT_EEE_REALTEK_RXC_STOP_EN					\
	"\n************* realtek phy eee rxc stop enable ***********\n"	\
	"ex: echo \"enable\" > realtek_phy_rxc_stop_enable\n"HELP_ENABLE

#define HELP_LPI_REQUEST_MODE						\
	"Available request TX LPI mode\n"				\
	"\t< 0: Normal or force to leave LPI"				\
	", 1: Force to enter LPI\n"					\
	"\t, 2: Enter or leave LPI automatically >\n"

#define HELP_CHECK_TIME							\
	"Available transmit check time:\n"				\
	"\t< 0 ~ 15, N: 1 * (2^N) ms >\n"

#define HELP_WAKE_TIME							\
	"Available transmit wake time:\n"				\
	"\t< 0 ~ 255, N: 21 + (N) * 2 us >\n"

#define HELP_GATE_CYCLE							\
	"Available gate cycle:\n"					\
	"\t< 0 ~ 255, 0: Disable, N: 9 + (N-1) * 2 cycles >\n"

#define EEE_CHECK_TIME_CHECK(time) {					\
	if ((time < EEE_CHECK_TIME_MIN) ||				\
		(time > EEE_CHECK_TIME_MAX)) {				\
		printk(HELP_CHECK_TIME);				\
		return count;						\
	}								\
}

#define EEE_WAKE_TIME_CHECK(time) {					\
	if ((time < EEE_WAKE_TIME_MIN) ||				\
		(time > EEE_WAKE_TIME_MAX)) {				\
		printk(HELP_WAKE_TIME);					\
		return count;						\
	}								\
}

#define EEE_GATE_CYCLE_CHECK(cycle) {					\
	if ((cycle < EEE_GATE_CYCLE_MIN) ||				\
		(cycle > EEE_GATE_CYCLE_MAX)) {				\
		printk(HELP_GATE_CYCLE);				\
		return count;						\
	}								\
}

#define EEE_LPI_REQUEST_MODE_CHECK(mode) {				\
	if ((mode < EEE_LPI_REQUEST_MODE_MIN) ||			\
			(mode > EEE_LPI_REQUEST_MODE_MAX)) {		\
		printk(HELP_LPI_REQUEST_MODE);				\
		return count;						\
	}								\
}


/* PSE LRO Cfg */
#define HINT_TS_UFO_EN							\
	"\n******************** TS UFO function ********************\n"	\
	"ex: echo \"enable\" > ts_ufo_en\n"HELP_ENABLE

#define HINT_TS_TSO_EN							\
	"\n******************** TS TSO function ********************\n"	\
	"ex: echo \"enable\" > ts_tso_en\n"HELP_ENABLE

#define HINT_DF_BIT_CFG							\
	"\n******** DF bit value of IPv4 after LSO for UFO *********\n"	\
	"ex: echo \"enable\" > df_bit_cfg\n"HELP_ENABLE


/* PSE MIB */
#define MIB_SAMPLE_INTERVAL_MIN	1
#define MIB_SAMPLE_INTERVAL_MAX	600

#define HINT_SAMPLE_INTERVAL						\
	"\n******************** Sample interval ********************\n"	\
	"ex: echo \"interval\" > sample_interval\n"HELP_SAMPLE_INTERVAL

#define HINT_SHOW_QUEUE_MIB						\
	"\n******************** Show queue mib *********************\n"	\
	"ex: echo \"enable\" > show_queue_mib\n"HELP_ENABLE

#define HELP_SAMPLE_INTERVAL						\
	"Available sample interval:\n"					\
	"\t< 1 <= N <= 600, unit second >\n"

#define MIB_SAMPLE_INTERVAL_CHECK(interval) {				\
	if ((interval < MIB_SAMPLE_INTERVAL_MIN) ||			\
		(interval > MIB_SAMPLE_INTERVAL_MAX)) {			\
		printk(HELP_SAMPLE_INTERVAL);				\
		return count;						\
	}								\
}

#endif /* _PSE_SYSFS_H_ */
