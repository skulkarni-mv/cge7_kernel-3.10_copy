/**
 * AppliedMicro APM862xxx QM Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Keyur Chudgar <kchudgar@apm.com>
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
 * @file apm_qm_core.h
 *
 * QM Queue Allocation Design:
 *  QID 0         - For error
 *  QID 1 - 4     - For U-Boot on CPU0
 *  QID 5 - 8     - For U-Boot on CPU1 (if required) 
 *  QID 9 - 250   - For Linux 
 *  QID 251 - 254 - For QM-lite in context of Wake-ON-LAN feature
 * 
 * QM Inbound Mailbox Design:
 *  Mailbox 0 - 7 - For CPU0
 *  Mailbox 0 - 7 - For CPU1 
 *
 * QM Outbound Mailbox Design:
 *  Mailbox 0 - 7 - For CPU0
 *  Mailbox 0 - 7 - For CPU1 
 *
 * SlimPRO PBN Design:
 *  PBN 0         - For normal work queue
 *  PBN 1         - For WoL work queue
 *
 * Ethernet PBN Design:
 *  PBN 0 - 7    - For normal work queue on ETH0
 *  PBN 7 - 15   - For normal work queue on ETH1
 *  PBN 16	 - For QM-lite WoL work queue from SlimPRO 
 *  PBN 0x20 - 0x27 - For FP used by ETH0 
 *  PBN 0x28 - 0x29 - For FP used by ETH1 
 *  PBN 0x30 - 0x31 - For QM-lite FP used by ETH0
 *
 * All others PBN Design:
 *  Allocate from low to high on CPU0
 *  Allocate from high to low on CPU1
 *  NOTE: It is assumed that the distribution of PBN does not crossed in AMP 
 *        mode.
 *    
 */

#ifndef __APM_QM_CORE_H__
#define __APM_QM_CORE_H__

#include <asm/apm_qm_access.h>

#define QM_BASE_ADDR		qm_fabric_vaddr
#define QML_BASE_ADDR		qml_fabric_vaddr
#define QBASE_ADDR_QID_MASK	6
#define MAX_CPU_CORES		2
#define MAX_32B_MAIL_SLOTS 	8 
#define MAX_16B_MAIL_SLOTS 	8 

#define PPC_FP_MB_PBN_OFFSET	0x20

#define QML_B_ADDR_QID(x) 	((void *) ((unsigned long) QML_BASE_ADDR | (x << QBASE_ADDR_QID_MASK)))
#define QM_B_ADDR_QID(x) 	((void *) ((unsigned long) QM_BASE_ADDR | (x << QBASE_ADDR_QID_MASK)))
#ifdef QM_ALTERNATE_ENQUEUE
#define QM_ENQ_B_ADDR_QID(x) 	((void *) ((unsigned long) QM_BASE_ADDR | (x << QBASE_ADDR_QID_MASK) | 0x2C))
#endif
#define DEC_OFFSET		0x3c
#define QM_B_ADDR_DEC	 	((void *) ((unsigned long) QM_BASE_ADDR | DEC_OFFSET))
#define PPC_SLAVE_ID		0xFF
#define SLAVE_ID_SHIFT		6
#define PPC_SLAVE_SHIFT		9
#define DEC_PBN_SHIFT		3
#define QM_DEC_MSG_VAL(pbn, dec) ((PPC_SLAVE_ID << PPC_SLAVE_SHIFT) | (pbn << DEC_PBN_SHIFT) | dec)

/* QM lite queues */
#define WQ_SZ_32B     		1

#define APM_QM_MBID_SHIFT	5
#define APM_QM_SLOTID_SHIFT	2

#define TOTAL_SLOTS		8
#define TOTAL_SLOTS_16BYTE_MSG	8
#define TOTAL_SLOTS_32BYTE_MSG	8
#define TOTAL_SLOTS_64BYTE_MSG	4

#define SIZE_64_MSG		3
#define SIZE_32_MSG		2
#define SIZE_16_MSG		1

#define MAX_MAILBOXS		16
#define ENQUE_MAIL_BOXES	16
#define DQ_MAIL_BOXES		16
#define FP_MAIL_BOXES		16

enum apm_qm_rtype {
	APM_QM_NON_RTYPE = 0,
	APM_QM_ETH_RTYPE,
	APM_QM_SEC_RTYPE,
	APM_QM_DMA_RTYPE,
	APM_QM_CLASS_RTYPE,
	APM_QM_VENET_RTYPE,
	APM_QM_PPC_RTYPE,
	APM_QM_WOL_RTYPE,
	APM_QM_LRO_RTYPE,
	APM_QM_CONS_RTYPE,
	APM_QM_DOG_RTYPE,
	APM_QM_UNUSE3_RTYPE,
	APM_QM_UNUSE2_RTYPE,
	APM_QM_UNUSE1_RTYPE,
	APM_QM_UNUSE0_RTYPE,
	MB_INVALID_RTYPE
};

#define EMPTY_SLOT		0x22222222

#define APM_QM_MAX_RTYPE	64

#define CORE0			0
#define CORE1			1
#define MAX_CORES		2

#if defined(CONFIG_SLAB_HW)	/* disable error queue if HW based buff pool */
#define ERR_QUEUE_ID	        0
#else
#define ERR_QUEUE_ID	        255 
#endif
#define QM_MAX_QUEUES		256
#define QM_QID_MASK             0xFF

/*  QML Queues used by Enet and SlimPRO for WoL */
#define DSLEEP_ENET_TX_Q    	252	/* SlimPRO work queue for WoL */
#define DSLEEP_ENET_RX_FP_Q 	253	/* SlimPRO free pool queue for WoL */
#define DSLEEP_ENET_RX_Q    	254	/* Ethernet work queue for WoL */
#define DSLEEP_ENET_RX_FQ_TO_DDR 251	/* Intermediate queue in WoL for lossless */

#define DSLEEP_ENET_RX_FP_PBN	0x30	/* ETH PBN 0x30 reserved for WoL */
#define DSLEEP_ENET_RX_FQ_TO_DDR_PBN 0x31 /* ETH PBN 0x31 reserved for WoL lossless */

#define QM_RSV_UNCONFIG_COMP_Q	250
#define QM_RSV_UNCONFIG_FUTURE	249

#define QM_RSV_QUEUES		8	/* Reserved Qs 249 to 254, 0 and 255 */
#define QM_AVL_QUEUES		(QM_MAX_QUEUES - QM_RSV_QUEUES)	/* Available Qs */

/* For AMP Core 0 */
#define QM_START_QID_CORE0	1
#define QM_END_QID_CORE0	(QM_AVL_QUEUES / 2)

/* For AMP Core 1 */
#define QM_START_QID_CORE1	(1 + (QM_AVL_QUEUES / 2))
#define QM_END_QID_CORE1	(QM_AVL_QUEUES - 1)

#define MAX_DELAY_CNT   	10000

#define DIR_INGRESS		0
#define DIR_EGRESS		1

#define ENABLE_VQ		1
#define DRR_CREDIT_GRAN		4500

enum apm_qm_arb_type {
	NO_ARB,
	SP_ARB,
	DRR_ARB,
	AVB_ARB,
};

/* QM/QM-lite queues start at 0x1000 offset*/
#define QMI_ETH_IPP_INGRESS_FP_ADDR	0x00401000
#define QMI_ETH_IPP_INGRESS_WQ_ADDR	0x00401200
#define QMI_ETH_IPP_EGRESS_WQ_ADDR      0x00401400
#define QMI_ETH_IPP_FREE_POOL_ADDR	0x00401600
#define QMI_UPPER_ADDR_NIBBLE	        0xD

/* QM return codes */
#define QM_ERR				-1
#define QM_OK				0

/* Check for mailbox available before writing msg */
#define CONFIG_MB_CHECK_TX_MSG

extern void *qm_fabric_vaddr;
extern void *qml_fabric_vaddr;
extern u64 qm_enq_mbox_paddr; 
extern void *qm_enq_mbox_vaddr; 
extern u32 qm_enq_mbox_size; 
extern u64 qm_dq_mbox_paddr;
extern void *qm_dq_mbox_vaddr;
extern u32 qm_dq_mbox_size;
extern u64 qm_fp_mbox_paddr;
extern void *qm_fp_mbox_vaddr;
extern u32 qm_fp_mbox_size;

/* Prefetch buffer slave ids */
/* NOTE: Update qm_cfg_slave_id in apm/qm/linux/apm_qm_cfg.h accordingly */
enum apm_qm_slave_id {
	PB_SLAVE_ID_DMA,
	PB_SLAVE_ID_OCMM,
	PB_SLAVE_ID_SEC,
	PB_SLAVE_ID_CLASS,
	PB_SLAVE_ID_IPP,
	PB_SLAVE_ID_ETH,
	PB_SLAVE_ID_RES6,
	PB_SLAVE_ID_RES7,
	PB_SLAVE_ID_ETHX,
	PB_SLAVE_ID_RES9,
	PB_SLAVE_ID_RESA,
	PB_SLAVE_ID_RESB,
	PB_SLAVE_ID_RESC,
	PB_SLAVE_ID_RESD,
	PB_SLAVE_ID_RESE,
	PB_SLAVE_ID_PPC,
	MAX_SLAVES,
};

/* NOTE: Update qm_cfg_ip in apm/qm/linux/apm_qm_cfg.h accordingly */
enum apm_qm_ip {
	IP_BLK_UNKNOWN,
	IP_BLK_QM,
	IP_BLK_QML,
	IP_BLK_IPP_QML,
};

/* NOTE: Update qm_cfg_dev_ip in apm/qm/linux/apm_qm_cfg.h accordingly */
enum apm_qm_dev_ip {
	IP_PPC0,
	IP_PPC1,
	IP_ETH0,
	IP_ETH1,
	IP_ETH2,
	IP_ETH3,
	IP_IPP,
	IP_DMA,
	IP_SEC,
	IP_OCMM,
	IP_CLASS,
	IP_MAX,
};

enum apm_qm_qtype {
	QUEUE_DISABLED,
	P_QUEUE,
	FREE_POOL,
	V_QUEUE,
};

enum apm_qm_msg_size {
	MSG_16B,
	MSG_32B,
	MSG_64B
};

enum apm_qm_fp_mode {
	MSG_NO_CHANGE,
	ROUND_ADDR,
	REDUCE_LEN,
	CHANGE_LEN
};

enum apm_qm_qsize {
	SIZE_512B,
	SIZE_2KB,
	SIZE_16KB,
	SIZE_64KB,
	SIZE_512KB,
};

enum apm_qm_notify_ppc {
	NO_NOTIFY,
	NOTIFY_CPU0,
	NOTIFY_CPU1,
	NOTIFY_BOTH,
};

/* LErr(3b) Decoding */
enum apm_qm_lerr {
        QM_NO_ERR,
        QM_MSG_SIZE_ERR,
        QM_HOP_COUNT_ERR,
        QM_VQ_ENQ_ERR,
        QM_DISABLEDQ_ENQ_ERR,
        QM_Q_OVERFLOW_ERR,
        QM_ENQUEUE_ERR,
        QM_DEQUEUE_ERR,
};

/* Userinfo encodings for LERR code 6 */

/* err[2:0] Encoding */
#define QM_AXI_READ_ERR             0  /* AXI error on read from PPC mailbox */ 
#define QM_AXI_ENQ_VQ_ERR           3  /* Alternate enq cmd to a VQ */
#define QM_AXI_ENQ_DQ_ERR           4  /* Alternate enq cmd to a Disabled Q */
#define QM_AXI_ENQ_OVERFLOWQ_ERR    5  /* Alternate enq cmd overfills a Q  */

/* cmd_acr_enq_err[1:0] Encoding  */
enum apm_qm_enq_err {
        QM_NO_AXI_ERR,
        QM_AXI_SLAVE_ERR,  /* AXI slave error on PPC mailbox read   */
        QM_AXI_DECODE_ERR, /* AXI decode error on PPC mailbox read  */
};

/* Userinfo encodings for LERR code 7 */
#define QM_CHILD_VQ_ERR  6     /* VQ was assigned as a child of another VQ  */
#define QM_DEQUEUE_DQ    7     /* dequeue was requested from a disabled PQ */

/*
 * @struct  apm_qm_raw_qstate
 * @brief   This structure represents raw queue state (pq or fp or vq)
 **
 */
struct apm_qm_raw_qstate {
	u32 w0;
	u32 w1;
	u32 w2;
	u32 w3;
#if !defined(CONFIG_APM862xx)
	u32 w4;
#endif
};

/*
 * @struct  apm_qm_vqstate
 * @brief   This structure represents virtual queue state (vq)
 */
struct apm_qm_vqstate {
#if !defined(CONFIG_APM862xx)
	/* word */
	u32 reserved		: 26;
	u32 queue_dom		: 2; /* Not used */
	u32 allowed_dom		: 4;
#endif
	/* word */
	u32 cfgqtype 		: 2; /* queue type, refer mb_q_type */
	u32 cfgselthrsh 	: 3; /*  associated threshold set */
	u32 q0_sel              : 8; 
	u32 q0reqvld            : 1; 
	u32 q0txallowed         : 1; 
	u32 q0selarb            : 2;
	u32 q1_sel              : 8; 
	u32 q1reqvld            : 1; 
	u32 q1txallowed         : 1;
	u32 q1selarb            : 2;
	u32 q2_sel_3b           : 3; 
	/* word */
	u32 q2_sel_5b           : 5;
	u32 q2reqvld            : 1; 
	u32 q2txallowed         : 1;
	u32 q2selarb            : 2;
	u32 q3_sel              : 8; 
	u32 q3reqvld            : 1; 
	u32 q3txallowed         : 1; 
	u32 q3selarb            : 2;
	u32 q4_sel              : 8; 
	u32 q4reqvld            : 1; 
	u32 q4txallowed         : 1;
	u32 q4selarb_hi         : 1;
	/* word */
	u32 q4selarb_lo         : 1;
	u32 q5_sel              : 8; 
	u32 q5reqvld            : 1; 
	u32 q5txallowed         : 1; 
	u32 q5selarb            : 2;
	u32 q6_sel              : 8; 
	u32 q6reqvld            : 1; 
	u32 q6txallowed         : 1; 
	u32 q6selarb            : 2;
	u32 q7_sel_7b           : 7; 
	/* word */
	u32 q7_sel_1b           : 1; 
	u32 q7reqvld            : 1; 
	u32 q7txallowed         : 1; 
	u32 q7selarb            : 2;
	u32 rid 		: 3; /* current region id of queue fill level */
	u32 ppc_notify 		: 2; /* see mb_notify_ppc  */
	u32 cfgcrid 		: 1; /* critical rid config */
	u32 cfgnotifyqne 	: 1; /* enable queue not empty interrupt */
	u32 cfgsaben 		: 1; /* enable SAB broadcasting */
	u32 rsvd                : 1;
	u32 nummsg 		: 18; 
};

/*
 * @struct  apm_qm_pqstate
 * @brief   This structure represents physical queue state (pq or fp)
 */
struct apm_qm_pqstate {
#if !defined(CONFIG_APM862xx)
	/* word */
	u32 reserved		: 26;
	u32 queue_dom		: 2;
	u32 allowed_dom		: 4;
#endif
	/* word */
	u32 cfgqtype 		: 2; /* queue type, refer mb_q_type */
	u32 cfgselthrsh 	: 3; /*  associated threshold set */
	u32 qstatelock 		: 1;
	u32 cfgqsize 		: 3; /* queue size, see mb_q_size */
	u32 fp_mode 		: 3; /* free pool mode */
	u32 cfgacceptlerr 	: 1; 
#if !defined(CONFIG_APM862xx)
	u32 reserved_0 		: 14; 
	u32 slot_pending	: 5;
#else
	u32 reserved_0 		: 15; 
	u32 cfgstartaddr_hi 	: 4; /* msb 4 bits from 28 bit address */
#endif
	/* word */
#if !defined(CONFIG_APM862xx)
	u32 reserved_1_lo	: 4;
	u32 cfgstartaddr_hi 	: 4; /* msb 4 bits from 28 bit address */
	u32 cfgstartaddr_lo 	: 24; /* lsb 24 bits from 28 bit address */
#else
	u32 cfgstartaddr_lo 	: 24; /* lsb 24 bits from 28 bit address */
	u32 reserved_1 		: 8;
#endif
	/* word */
#if !defined(CONFIG_APM862xx)
	u32 qcoherent 		: 1;
#else
	u32 reserved_2 		: 1;
#endif
	u32 headptr 		: 15; 
	u32 nummsg 		: 16; 
	/* word */
#if !defined(CONFIG_APM862xx)
	u32 not_insert_dom	: 1;
	u32 reserved_3 		: 4;
#else
	u32 reserved_3 		: 5;
#endif
	u32 rid 		: 3; /* current region id of queue fill level */
	u32 ppc_notify 		: 2; /* see mb_notify_ppc  */
	u32 cfgcrid 		: 1; /* critical rid config */
	u32 cfgnotifyqne 	: 1; /* enable queue not empty interrupt */
	u32 cfgsaben 		: 1; /* enable SAB broadcasting */
	u32 cfgtmvq 		: 8; /* parent vq */
	u32 cfgtmvqen 		: 1; /* enable pq to belong to vq */
#if !defined(CONFIG_APM862xx)
	u32 resize_done		: 1;
	u32 resize_start	: 1;
	u32 resize_qid		: 8;
#else
	u32 reserved_4 		: 10;
#endif
}__attribute__ ((packed));

/*
 * @struct  apm_qm_qstate
 * @brief   This structure represents per queue state database
 */
struct apm_qm_qstate {
	u8 ip_blk;		/**< which ip block this queue belongs to (QM or QM light) */
	u8 valid;		/**< 1 if configured else 0 */
	u16 q_id;		/**< queue id */
	u8 mb_id;		/**< mailbox id, used for ingress only */
	u8 slave_id;		/**< prefetch mgr slave id */
	u8 pbn;			/**< prefetch buffer number */
	u8 q_type;		/**< queue type, see mb_q_type */
	u8 msg_size;		/**< message size supported for this queue */
	u8 vqen;		/**< Virtual Queue enable/disable */
	int parent_vqid; 	/**< parent qid, if this pq belongs to any vq */
	u8 ppc_notify; 		/**< 	
				0: Notification not required by PPC,
				1: Notify CPU 0 only,
				2: Notify CPU 1 only,
				3: Notify both CPUs */
	u8 q_size; 		/**< 0: 2KB, 1: 16KB, 2: 64KB, 3: 512KB */
	u32 q_start_addr; 	/**< 28 bit, 256 byte aligned  start addr */ 
	u8 fp_mode; 		/**< handle addr and len of buf, refer 
				     mb_fp_mode 
				0: No modification to message,
				1: Round the start address down to an address 
				   boundary consistant with the size of the buf
				2: Reduce the BufDataLen field according to 
				   BufSize - DataAddr(LSBs).
				3: Change the BufDataLen field to indicate the 
				   BufSize (zero it out to indicate the maximum
				   value). */
	u8 thr_set;		/**< configured threshold set (one of eight thresholds) */
	u32 nummsgs;		/**< Number of messages in the queue */  
	u8 rid;			/**< Current region ID of the queue */   
	u8 q_not_empty_intr;	/**< Enable/disable queue not empty interrupt */   
	u8 direction;		/**< 0: ingress, 1: egress */
	u8 cfgsaben;		/**< Enable broadcasting of information on sab bus */		 
	u8 src_ip_blk;		/**< Requested by IP block */
	u8 ppc_id;		/**< Destination IP block */
	u8 pq_sel[8];           /**< PQs to be added to VQ */
	u8 q_sel_arb[8]; 	/**< For VQ only, select queue arbitration policy:
				   0: This queue is not enabled for dequeue
				1: strict priority
				2: WRR priority
				3: AVB arbitration */
	u8 shape_rate[8];	/**< Shaping rate in case of AVB ARB,
				     Weight for DRR ARB and not used
				     for SP ARB */	
	u8 *startptr;		/**< For alternative enqueue */
	u8 *tailptr;
	u8 *lastptr;
	u8 *endptr;

	u32 msg_stat;		/**< Statistic for enqueue or dequeue */
	u32 pending_dealloc;	/**< Pending de-allocate msg to send for FP */
	u32 pending_compl;	/**< Pending de-allocate msg to send for completion message */
} __attribute__ ((packed)); 

/* QM messages */

/*
 * @struct  apm_qm_msg16
 * @brief   This structure represents 16 byte QM message format
 */
struct apm_qm_msg16 {
	u32 srcDomID 	: 8;
	u32 C 		: 1;
	u32 BufDataLen 	: 15;
	u32 DataAddrMSB : 8;

	u32 DataAddrLSB;

	u32 HL 		: 1;
	u32 LErr 	: 3;
	u32 RType 	: 4;
	u32 PV 		: 1;
	u32 SB 		: 1;
	u32 HB 		: 1;
	u32 PB 		: 1;
	u32 LL 		: 1;
	u32 NV 		: 1;
	u32 HC 		: 2;
#if !defined(CONFIG_APM862xx)
	u32 ELErr	: 2;
#else
	u32 Rv 		: 2;
#endif
	u32 FPQNum 	: 14;

	u32 UserInfo;
}__attribute__ ((packed)); 

/*
 * @struct  apm_qm_msg_up8
 * @brief   This structure represents 8 byte portion of QM message format
 */
struct apm_qm_msg_up8 {
	u32 H0FPSel 	: 6;
	u32 HR 		: 1;
	u32 HE 		: 1;
	u32 DR 		: 1;
	u32 SZ 		: 1;
	u32 H0Enq_Num 	: 14;
	u32 H0Info_msb 	: 8;

	u32 H0Info_lsb  : 32;

}__attribute__ ((packed)); 

/*
 * @struct  apm_qm_msg_ext8
 * @brief   This structure represents 8 byte portion of QM extended (64B)
 *	    message format
 *
 */
struct apm_qm_msg_ext8 {
	u32 NxtFPQNum		:8;
	u32 Rv1			:1;
	u32 NxtBufDataLength	:15;
	u32 Rv2			:4;
	u32 NxtDataAddrMSB	:4;
	u32 NxtDataAddrLSB;
}__attribute__ ((packed));

/*
 * @struct  apm_qm_msg32
 * @brief   This structure represents 32 byte QM message format
 */
struct apm_qm_msg32 {
	struct apm_qm_msg16 msg16;
	struct apm_qm_msg_up8 msgup8_1;
	struct apm_qm_msg_up8 msgup8_2;
}__attribute__ ((packed));

/*
 * @struct  apm_qm_msg64
 * @brief   This structure represents 64 byte QM message format
 */
struct apm_qm_msg64 {
	struct apm_qm_msg32 msg32_1;
	struct apm_qm_msg32 msg32_2;
}__attribute__ ((packed));

/*
 * @struct  apm_qm_mailbox_ctxt
 * @brief   This structure contains mailbox context information
 */
struct apm_qm_mailbox_ctxt {
	/* Variable used for dequeue */
	struct apm_qm_msg32 *cur_ptr; 
	struct apm_qm_msg32 *first_ptr;
	struct apm_qm_msg32 *last_ptr;

	/* Variable used for enqueue */
	u32 slot : 8; 	
	u32 total_slot : 8; 
	u32 last_slot : 8; 
} __attribute__ ((packed));

/*
 * @struct  apm_qm_mailbox
 * @brief   This structure represents a work queue mailbox 
 */
struct apm_qm_mailbox {
	struct apm_qm_msg32 mailslots[MAX_32B_MAIL_SLOTS]; 
};

struct apm_qm_fp_mailbox_ctxt {
	/* Variable used for dequeue */
	struct apm_qm_msg16 *cur_ptr; 
	struct apm_qm_msg16 *first_ptr;
	struct apm_qm_msg16 *last_ptr;

	/* Variable used for enqueue */
	u32 slot : 8; 	
	u32 total_slot : 8; 
	u32 last_slot : 8; 
} __attribute__ ((packed));

/*
 * @struct  apm_qm_fp_mailbox
 * @brief   This structure represents a free pool mailbox 
 */
struct apm_qm_fp_mailbox {
	struct apm_qm_msg16 mailslots[MAX_16B_MAIL_SLOTS]; 
};

/*
 * @struct  apm_qm_msg_desc
 * @brief   This structure represents a QM msg descriptor
 */
struct apm_qm_msg_desc {
	u32 qid : 16; 	  /**< destination QID to send message to */
	u32 mb_id : 8; 	  /**< mailbox id to push/pull this message to/from */
	u32 is_msg16 : 8; /**< set this to get 1st 16 bytes message */
	void *msg;	  /**< Pointer to message */
} __attribute__ ((packed));

/*
 * @struct  apm_qm_qalloc
 * @brief   This structure contains info about allocating queues for IP blocks
 */
struct apm_qm_qalloc {
	u8 qm_ip_blk;		/**< 1: QM or 2: QM lite */
	u8 ip_blk;		/**< Requesting (source) IP block */
	u8 ppc_id;		/**< Destination IP block */
	u8 q_type;		/**< 0: PQ, 1: VQ, 2: FP */
	u32 q_count;		/**< Number of queues to allocate */
	u8 vqen; 		/**< Enable this PQ to be part of the VQ */
	u32 parent_vq;		/**< If need to attach VQ to PQs, provide VQ */
	u8 direction;		/**< 0: Ingress, 1: Egress */
	u32 qaddr;		/**< Start Address of queue */
	u8 qsize;		/**< Size of queue to be created */
	u8 thr_set;		/**< Queue threshold set to be used */
	u8 en_fill_chk;		/**< Enable queue fill check on this queue */
	u8 q_sel_arb[8];        /**< Arbitration mechanism for VQ */
	u8 pq_sel[8];           /**< PQs to be added to VQ */
	u8 shape_rate[8];       /**< Shaping rate in case of AVB ARB,
				     Weight for DRR ARB and not used
				     for SP ARB */
	struct apm_qm_qstate *qstates;	/**< Store queue states here */
};

/* QM callback function type */
typedef int (*apm_qm_msg_fn_ptr) (struct apm_qm_msg_desc *msg_desc);

/* API declarations */

/**
 * @brief   Decode buffer length from BufDataLen
 * @param   bufdatalen Encoded buffer data length field
 * @return  Decoded value of buffer length
 */
static inline u16 apm_qm_decode_buflen(u16 bufdatalen)
{
	switch (bufdatalen & 0x7000) {
	case 0x7000:
		return 0x100;
	case 0x6000:
		return 0x400;
	case 0x5000:
		return 0x800;
	case 0x4000:
		return 0x1000;
	default:
		return 0x4000;
	};
}

/**
 * @brief   Decode data length from BufDataLen
 * @param   bufdatalen Encoded buffer data length field
 * @return  Decoded value of data length
 */
static inline u32 apm_qm_decode_datalen(u16 bufdatalen)
{	
	switch (bufdatalen & 0x7000) {
	case 0x7000:
		return bufdatalen & 0xFF ? bufdatalen & 0xFF : 0x100;
	case 0x6000:
		return bufdatalen & 0x3FF ? bufdatalen & 0x3FF : 0x400;
	case 0x5000:
		return bufdatalen & 0x7FF ? bufdatalen & 0x7FF : 0x800;
	case 0x4000:
		return bufdatalen & 0xFFF ? bufdatalen & 0xFFF : 0x1000;
	default:
		return bufdatalen & 0x3FFF ? bufdatalen & 0x3FFF : 0x4000;
	};
}

/**
 * @brief   Decrement datalen in BufDataLen
 * @param   Encoded value of buffer data length field
 * @param   Less data from datalen
 * @param   Update datalen with original datalen
 * @return  Encoded value of buffer data length field 
 */
static inline u16 apm_qm_less_bufdatalen(u16 bufdatalen, u16 less, u32 *datalen)
{
	u16 mask;
	u16 final_datalen;

	switch ((bufdatalen >> 12) & 0x7) {
	case 7:
		mask = 0xFF;
		break;
	case 6:
		mask = 0x3FF;
		break;
	case 5:
		mask = 0x7FF;
		break;
	case 4:
		mask = 0xFFF;
		break;
	default:
		mask = 0x3FFF;
		break;
	};

	final_datalen = *datalen = (bufdatalen & mask) ? (bufdatalen & mask) : (mask + 1);
	final_datalen = (final_datalen > less) ? (final_datalen - less) : 0;
	bufdatalen = (bufdatalen & ~mask) | final_datalen;

	return bufdatalen;
}

/**
 * @brief   Encode buffer length and data length to BufDataLen
 * @param   len Data length or Buffer length
 * @return  Encoded value of buffer data length field
 */
static inline u16 apm_qm_encode_bufdatalen(u32 len)
{
	if (len <= 0x100) {
		return (0x7 << 12) | (len & 0xFF);
	} else if (len <= 0x400) {
		return (0x6 << 12) | (len & 0x3FF);
	} else if (len <= 0x800) {
		return (0x5 << 12) | (len & 0x7FF);
	} else if (len <= 0x1000) {
		return (0x4 << 12) | (len & 0xFFF);
	} else if (len < 0x4000) {
		return len & 0x3FFF;
	} else {
		return 0;
	}
}

/**
 * @brief   Encode data length to BufDataLen assuming maximum buffer size
 * @param   len Data length 
 * @return  Encoded value of buffer data length field
 */
static inline u16 apm_qm_encode_datalen(u32 len)
{
	return len & 0x3FFF;
}

/**
 * @brief   Check if next buffer data length field is valid.
 * @param   nxtbufdatalen Next buffer data length field of a Extended Message
 * @return  0 - success or -1 - failure
 */
static inline int apm_qm_nxtbufdatalen_is_valid(u16 nxtbufdatalen)
{
	return nxtbufdatalen == 0x7800 ? 0 : 1;
}

/**
 * @brief   Initialize Error Q
 * @param   PowerPC Processor ID to which error Q will interrupt
 * @return  0 - success or -1 - failure
 */
int apm_qm_init_errq(int ppc_id);

/**
 * @brief   Initialize QM HW block
 * @param   no_of_queues Number of queues to initialize
 * @return  0 - success or -1 - failure
 */
int apm_qm_init_queue(int no_of_queues);

/**
 * @brief   Return the current qstate configuration without talking to QM HW
 * @param   q_num Queue number
 * 	    qstate Pointer to queue state structure for this queue
 * @return  0 - success or -1 - failure
 */
int apm_qm_qstate_rd_cfg(int q_num, struct apm_qm_qstate *qstate);

/**
 * @brief   Reads the state of the given queue number from QM
 * @param   ip QM or QM light
 * 	    q_num Queue number 
 *          qstate Pointer to queue state structure for this queue
 * @return  0 - success or -1 - failure
 */
int apm_qm_qstate_rd(int ip, int q_num, struct apm_qm_qstate *qstate);

/**
 * @brief   Writes the state of the given queue number to QM
 * @param   qstate Pointer to queue state structure for this queue
 * @return  0 - success or -1 - failure
 */
int apm_qm_qstate_wr(struct apm_qm_qstate *qstate);

int apm_qm_vqstate_wr(struct apm_qm_qstate *qstate);
/**
 * @brief   Reads the state of the given queue number from QM in RAW format
 * @param   ip QM or QM light
 * 	    q_num Queue number to read the state for
 *          raw_qstate Pointer to queue state structure for this queue
 * @return  0 - success or -1 - failure
 */
int apm_qm_raw_qstate_rd(int ip, int q_num, struct apm_qm_raw_qstate *raw_q);

/**
 * @brief   Writes the state of the given queue number in QM in RAW format
 * @param   ip QM or QM light
 * 	    q_num Queue number to write the state for
 *          raw_qstate Pointer to queue state structure for this queue
 * @return  0 - success or -1 - failure
 */
int apm_qm_raw_qstate_wr(int ip, int q_num, struct apm_qm_raw_qstate *raw_q);

/**
 * @brief   Enqueues (Pushes) the message to mailbox on given QML queue
 * @param   msg_desc Descriptor of the message to push
 * @return  0 - success or -1 - failure
 */
int apm_qml_push_msg(struct apm_qm_msg_desc *msg_desc);

/**
 * @brief   Enqueues (Pushes) the message to mailbox on given QM queue
 * @param   msg_desc Descriptor of the message to push
 * @return  0 - success or -1 - failure
 */
int apm_qm_push_msg(struct apm_qm_msg_desc *msg_desc);

/**
 * @brief   Gives the userinfo from completion queue
 * @param   mb_id Mailbox ID
 * @return  userinfo - success or -1 - failure
 */
int apm_qm_pull_comp_msg(u32 mb_id);

/**
 * @brief   Gives the userinfo from completion queue but notify QM in batch
 * @param   mb_id Mailbox ID
 * @return  userinfo - success or -1 - failure
 */
int apm_qm_pull_comp_msg2(u32 mb_id);

/**
 * @brief   Explicit notify QM if any pending decrement due to batch notify
 * @param   mb_id Mailbox ID
 * @return  userinfo - success or -1 - failure
 */
int apm_qm_pull_comp_flush(u32 mb_id);

/**
 * @brief   Dequeues (Pulls) the message from mailbox on given queue
 * @param   msg_desc Descriptor of the message to pull
 * @return  0 - success or -1 - failure
 */
int apm_qm_pull_msg(struct apm_qm_msg_desc *msg_desc);

/**
 * @brief   Deallocates buffer to given QML buffer pool 
 * @param   msg_desc Descriptor of the msg (containing buffer to deallocate)
 * @return  0 - success or -1 - failure
 * NOTE: This function can be routed to alternative enqueue version or non-
 *       alternative enqueue version depends if alternative enqueue is
 *       enabled or not.
 */
int apm_qml_fp_dealloc_buf(struct apm_qm_msg_desc *msg_desc);

#if defined(QM_NON_ALTERNATE_ENQUEUE_FP)
/**
 * @brief   Deallocates buffer to given buffer pool 
 * @param   msg_desc Descriptor of the msg (containing buffer to deallocate)
 * @return  0 - success or -1 - failure
 * NOTE: This function always use normal enqueue for free pool.
 */
int apm_qm_fp_dealloc_buf_non_alt(struct apm_qm_msg_desc *msg_desc);
#endif

/**
 * @brief   Deallocates buffer to given buffer pool 
 * @param   msg_desc Descriptor of the msg (containing buffer to deallocate)
 * @return  0 - success or -1 - failure
 */
int apm_qm_fp_dealloc_buf(struct apm_qm_msg_desc *msg_desc);
int apm_qm_fp_dealloc_flush(int qid);

/**
 * @brief   Allocate buffer to given buffer pool 
 * @param   msg_desc Descriptor of the msg (containing buffer to allocate)
 * @return  0 - success or -1 - failure
 */
int apm_qm_fp_alloc_buf(struct apm_qm_msg_desc *msg_desc);

/**
 * @brief   Dequeues (Pulls) the message from QML queue
 * @param   msg Descriptor of the message to pull
 * @return  0 - success or -1 - failure
 */
int apm_qml_pull_msg(struct apm_qm_msg32 *msg);

/**
 * @brief   Unregister QM callback function for given RTYPE
 * @param   rtype RTYPE for which to register callback
 * @return  0 - success or -1 - failure
 */
int apm_qm_msg_rx_unregister(u32 rtype);

/**
 * @brief   Register QM callback function for given RTYPE
 * @param   rtype RTYPE for which to register callback
 *	    fn_ptr Callback function pointer
 * @return  0 - success or -1 - failure
 */
int apm_qm_msg_rx_register(u32 rtype, apm_qm_msg_fn_ptr fn_ptr);

/**
 * @brief   Unregister direct QM callback function for given Mail box
 * @param   mbidx Mailbox index
 * @return  0 - success or -1 - failure
 */
int apm_qm_mailbox_rx_unregister(u32 mbidx);

/**
 * @brief   Register direct QM callback function for given Mail box
 * @param   mbidx Mailbox index
 * @param   fn_ptr Callback function pointer
 * @return  0 - success or -1 - failure
 */
int apm_qm_mailbox_rx_register(u32 mbidx, apm_qm_msg_fn_ptr fn_ptr);

/**
 * @brief   Parse the exact for the Error Message received on Errro Queue
 * @param   err_msg_desc - Descriptor of the Error msg 
 * @return  None
 */
void apm_qm_parse_error(struct apm_qm_msg_desc *err_msg_desc);

/**
 * @brief   Return queues to given IP blocks
 * @param   qalloc Structure filled up with queue allocation information for QM driver
 * @return  0 - success or -1 - failure
 */
int apm_qm_alloc_q(struct apm_qm_qalloc *qalloc);
int apm_qm_free_q(int qid, int mbid, int ppc_id, int ip_blk, 
		int fp_pbn, int pbn);

/**
 * @brief   Return Virtual queue to given IP blocks
 * @param   qalloc Structure filled up with queue allocation information
 *		for QM driver
 * @return  0 - success or -1 - failure
 */
int apm_qm_alloc_vq(struct apm_qm_qalloc *qalloc, u32 qid);

/**
 * @brief   Return completion queue for current PPC
 * @param   ip_blk IP block to get completion queue for
 *	    ppc_id Which power pc the completion queue belongs to
 * @return  0 - success or -1 - failure
 */
struct apm_qm_qstate *apm_qm_get_compl_queue(int ip_blk, int ppc_id);

/**
 * @brief   Return completion queue size for ip block
 * @param   ip_blk IP block to get completion queue for
 *          ppc_id Which power pc the completion queue belongs to
 * @return  actual size in bytes
 */
u32 apm_qm_get_compl_queue_size(int ip_blk, int ppc_id);

/**
 * @brief   Configure completion queues 
 * @param   None
 * @return  None
 */
int apm_qm_config_compl_queues(void);

/**
 * @brief   Configure prefetch buffer table
 * @param   ip	QM or QM lite IP to configure the pbn for
 *	    slv_id PBN Slave ID 
 *	    pbn prefetch buffer number to configure
 *	    qnum Queue number to configure PBN for
 *	    is_fp Is it free queue or not
 * @return  None
 */
int apm_qm_pb_config(int ip, int slv_id, int pbn, int qnum, u8 is_fp, u8 is_vq);

u32 apm_qm_pb_get(int ip, int slv_id, int pbn);
u32 apm_qm_pb_set(int ip, int slv_id, int pbn, u32 pbn_buf);
int apm_qm_pb_disable(int ip, int slv_id, int pbn, int qnum);
int apm_qm_pb_overwrite(int ip, int slv_id, int pbn, int qnum, u8 is_fp);
u32 apm_qm_pb_get(int ip, int slv_id, int pbn);
int apm_qm_pb_clr(int ip, int slv_id, int pbn);
int apm_qm_enq_stats_setqid(int ip, u32 qid);
u32 apm_qm_enq_stats_getqid(int ip);
u32 apm_qm_enq_stats_value(int ip);
int apm_qm_deq_stats_setqid(int ip, u32 qid);
u32 apm_qm_deq_stats_getqid(int ip);
u32 apm_qm_deq_stats_value(int ip);
void apm_qm_set_enq_mbox_addr(u32 coherent, u64 paddr);
void apm_qm_set_dq_mbox_addr(u32 coherent, u64 paddr);
void apm_qm_set_fp_mbox_addr(u32 coherent, u64 paddr);
int apm_qm_alloc_mbox(void);
int apm_qm_cstate_rd(u32 qid, u32 * cstate);
int apm_qm_cstate_wr(u32 qid, u32 cstate[2]);
int apm_qm_get_vq(u32 ip_blk);
int apm_qm_alt_enqueue_enable(void);
int apm_qm_irq_err(void);

int apm_qm_is_pbn_valid(u32 qid);
void apm_qm_clr_pbn_valid(u32 qid);
int apm_qm_mb2qid(int mb);
int apm_qm_qid2mb(int qid);
	
void apm_qm_set_mboxes(u32 maxboxes, u32 startboxes);
u32 apm_qm_get_start_mboxes(void);
u32 apm_qm_get_max_mboxes(void);
void apm_qm_set_qid(u32 fqid, u32 sqid, u32 maxqid, u32 maxclrqid);
u32 apm_qm_get_first_qid(void);
u32 apm_qm_get_start_qid(void);
u32 apm_qm_get_max_qid(void);
u32 apm_qm_get_max_clr_qid(void);
void apm_qm_set_smp(u8 is_smp);
u8 apm_qm_get_smp(void);
void apm_qm_set_noqml(u8 is_noqml);
u8 apm_qm_get_noqml(void);
void apm_qm_msg_not_empty_intr_coal_set(int tap);
int apm_qm_mbox_set_coal(int mbox_id, int tap);

/* Mailbox SoftIRQ Context */
struct apm_qm_mb_tasklet {
	u32 mailbox;
	u32 queue;
	u32 core;
	void *ctx;
	void *tasklet;	/* OS specific structure */
};

int apm_qm_mb_tasklet_unregister(struct apm_qm_mb_tasklet *handler);
int apm_qm_mb_tasklet_register(u32 mailbox, u32 queue, u32 core, void *ctx,
			       void (*func)(unsigned long));
int apm_qm_indirect_access_lock(int lock);
int apm_qm_enable_hwirq(int ip, u32 msk);
int apm_qm_update_tm_timer(int ip, u32 val);

/* Core-to-Core Messaging queues */
#define QM_HI_OFFSET     (0)
#define QM_LO_OFFSET     (1)
#define QM_VIRT_OFFSET   (2)
/* PPC1 -> PPC0 queues */
#define QM_10_MSG_BASE_QID (200)
#define QM_10_MSG_H_QID (QM_10_MSG_BASE_QID + QM_HI_OFFSET) /* High priority */
#define QM_10_MSG_L_QID (QM_10_MSG_BASE_QID + QM_LO_OFFSET) /* Low priority  */
#define QM_10_MSG_VQID  (QM_10_MSG_BASE_QID + QM_VIRT_OFFSET) /* Virtual Queue */

/* PPC0 -> PPC1 queues */
#define QM_01_MSG_BASE_QID (210)
#define QM_01_MSG_H_QID (QM_01_MSG_BASE_QID + QM_HI_OFFSET) /* High priority */
#define QM_01_MSG_L_QID (QM_01_MSG_BASE_QID + QM_LO_OFFSET) /* Low priority  */
#define QM_01_MSG_VQID  (QM_01_MSG_BASE_QID + QM_VIRT_OFFSET) /* Virtual Queue */

void apm_qm_c2c_msg_q_create_queues(void);

/* Queue thresholds: core-to-core VQs are composed of 512 elements */
#define QM_LO_THR  (50)
#define QM_MID_THR (150)
#define QM_HI_THR  (300)

void apm_qm_c2c_msg_wait_fc(unsigned int threshold);

int apm_qm_get_ib_mb(int ppcx, int ip_blk);

#endif /* __APM_QM_CORE_H__ */
