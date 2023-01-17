/**
 * AppliedMicro AM86xxx QM Driver
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
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
 * @file apm_qm_core.c
 *
 */

#include <linux/module.h>
#include <linux/delay.h>
#include <linux/random.h>
#include <asm/io.h>
#include <asm/apm_qm_access.h>
#include <asm/apm_qm_core.h>
#include <asm/apm_qm_csr.h>
#include <asm/apm_ipp_csr.h>

/* enqueue for work queue and free pool */
struct apm_qm_mailbox_ctxt mb_enq_mbox_ctxt[ENQUE_MAIL_BOXES];
/* dequeue for work queue (pq or vq) */
struct apm_qm_mailbox_ctxt mb_dq_mbox_ctxt[DQ_MAIL_BOXES];
/* dequeue for free pool */
struct apm_qm_fp_mailbox_ctxt mb_fp_mbox_ctxt[FP_MAIL_BOXES];

/* pointer to maibox for enqueue for work queue and free pool */
struct apm_qm_mailbox *enq_mboxes;
/* pointer to maibox for dequeue for work queue (pq or vq) */
struct apm_qm_mailbox *dq_mboxes;
/* pointer to maibox for dequeue for free pool */
struct apm_qm_fp_mailbox *fp_mboxes;

/* global queue configuration table */
extern struct apm_qm_qstate mb_cfg_pqs[];
extern u32 qml_ipp_csr_addr;
extern void *queue_baddr;
extern u64 queue_baddr_p;
extern u64 queue_eaddr_p;

struct qm_core_info {
	u32 max_qid;
	u32 max_clr_qid;
	u32 first_qid;
	u32 start_qid;
	u32 start_mboxes;
	u32 max_mboxes;
	u8 is_smp;
	u8 is_noqml;
} qm_cinfo;

/* QM message callback function table */
apm_qm_msg_fn_ptr qm_cb_fn_table[APM_QM_MAX_RTYPE];
apm_qm_msg_fn_ptr qm_mailbox_fn_table[APM_QM_MAX_RTYPE];

/* Completion queues for PPCx inbound:
	ETHx to PPC0/PPC1
	SEC to PPC0/PPC1
	All other to PPC0/PPC1
*/
#define GEN_TO_PPC0_COMP_MB  7
#define GEN_TO_PPC1_COMP_MB  14
#define GEN_TO_PPC0_COMP_QID 120
#define GEN_TO_PPC1_COMP_QID 153

#if defined(BOOTLOADER)
#define APM_QM_NO_COMP_QID		(IP_ETH3+1)
static struct apm_qm_qstate comp_qstate[1][APM_QM_NO_COMP_QID];
#else
#define APM_QM_NO_COMP_QID		IP_MAX
static struct apm_qm_qstate comp_qstate[MAX_CORES][APM_QM_NO_COMP_QID];
#endif

/* Queue to mailbox and mailbox to queue mappings */
static u32 q_to_mb[QM_MAX_QUEUES];	/* for outbound */
u32 mb_to_q[MAX_MAILBOXS];		/* for inbound */
static u16 ib_mbox_used[MAX_MAILBOXS];	/* Flag indicates mail box used already */
static u32 ib_mb_pending_chk[MAX_MAILBOXS]; /* # check where message pending */
static u32 ip_to_slvid[IP_MAX]; 	/* IP block to slave ID mapping */
static u32 pbn_valid[QM_MAX_QUEUES];
static u16 free_qid[QM_MAX_QUEUES];     /* Available QID */
static int free_qid_idx;		/* Slot for next available QID */
static u32 dq_fp_ip_to_mb[MAX_SLAVES];  /* Mailbox used to deq msg from IP blk (FQ) */
static u16 ip_pbn_wq_msk[IP_MAX]; 	/* Bit mask indicates available WQ PBN */
static u16 ip_pbn_wq_act[IP_MAX]; 	/* Bit mask indicates in use WQ PBN */
static u16 ip_pbn_fq_msk[IP_MAX]; 	/* Bit mask indicates available FP PBN */
static u16 ip_pbn_fq_act[IP_MAX]; 	/* Bit mask indicates in use FP PBN */

struct apm_qm_qstate *queue_states;
#if !defined(BOOTLOADER)
struct apm_qm_raw_qstate *q_raw_states;
#endif

int apm_qm_is_pbn_valid(u32 qid)
{
	return pbn_valid[qid];
}

void apm_qm_clr_pbn_valid(u32 qid)
{
	pbn_valid[qid] = 0;
}

int apm_qm_mb2qid(int mb)
{
	return mb_to_q[mb];
}

int apm_qm_qid2mb(int qid)
{
	return q_to_mb[qid];
}

void apm_qm_set_qid(u32 fqid, u32 sqid, u32 maxqid, u32 maxclrqid)
{
	qm_cinfo.first_qid = fqid;
	qm_cinfo.start_qid = sqid;
	qm_cinfo.max_qid = maxqid;
	qm_cinfo.max_clr_qid = maxclrqid;
}

u32 apm_qm_get_max_qid(void)
{
	return qm_cinfo.max_qid;
}

u32 apm_qm_get_max_clr_qid(void)
{
	return qm_cinfo.max_clr_qid;
}

u32 apm_qm_get_first_qid(void)
{
	return qm_cinfo.first_qid;
}

u32 apm_qm_get_start_qid(void)
{
	return qm_cinfo.start_qid;
}

void apm_qm_set_mboxes(u32 maxboxes, u32 startboxes)
{
	qm_cinfo.max_mboxes = maxboxes;
	qm_cinfo.start_mboxes = startboxes;
}

u32 apm_qm_get_max_mboxes(void)
{
	return qm_cinfo.max_mboxes;
}

u32 apm_qm_get_start_mboxes(void)
{
	return qm_cinfo.start_mboxes;
}

void apm_qm_set_smp(u8 is_smp)
{
	qm_cinfo.is_smp = is_smp;
}

u8 apm_qm_get_smp(void)
{
	return qm_cinfo.is_smp;
}

void apm_qm_set_noqml(u8 is_noqml)
{
	qm_cinfo.is_noqml = is_noqml;
}

u8 apm_qm_get_noqml(void)
{
	return qm_cinfo.is_noqml;
}

static int __apm_qm_dp_enabled(void)
{
	return apm86xxx_is_dp_mode();
}

static int __apm_qm_pb_cmd(int ip, u32 pbm_addr, u32 *buf, int read)
{
	int rc;

	if (!__apm_qm_dp_enabled()) {
		apm_qm_wr32(ip, CSR_PBM_ADDR, pbm_addr);
		apm_qm_rd32(ip, CSR_PBM_ADDR, &pbm_addr); /* Force barrier */
		if (read) {
			apm_qm_rd32(ip, CSR_PBM_BUF_RD_ADDR, buf);
		} else {
			apm_qm_wr32(ip, CSR_PBM_BUF_WR_ADDR, *buf);
			apm_qm_rd32(ip, CSR_PBM_BUF_WR_ADDR, buf);
		}
		return 0;
	}

	/* Read/Write via SlimPRO interface */
	rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_PB, IPP_DP_RES_QM, read,
				pbm_addr, buf);
	if (rc != 0) {
		QM_DBG("QM PB cmd failed error %d\n", rc);
	} else {
#if defined(DQM_DBG)
		if (!read) {
			u32 tmp;
			rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_PB, IPP_DP_RES_QM,
					1, pbm_addr, &tmp);
			if (rc != 0)
				QM_DBG("QM PB cmd failed error %d\n", rc);
			else if ((tmp & 0x3FFFF) != (*buf & 0x3FFFF))
				QM_DBG("QM PB cmd failed data mismatch "
					"0x%08X != 0x%08X\n", *buf, tmp);
		}
#endif
	}
	return rc;
}

static int __apm_qm_qstate_cmd(int ip, u32 qid, u32 *buf, int read)
{
	int rc;

	if (!__apm_qm_dp_enabled()) {
		apm_qm_wr32(ip, CSR_QSTATE_ADDR, qid);
		apm_qm_rd32(ip, CSR_QSTATE_ADDR, &qid); /* Force barrier */
		if (!read) {
			apm_qm_wr32(ip, CSR_QSTATE_WR_0_ADDR, buf[0]);
			apm_qm_wr32(ip, CSR_QSTATE_WR_1_ADDR, buf[1]);
			apm_qm_wr32(ip, CSR_QSTATE_WR_2_ADDR, buf[2]);
			apm_qm_wr32(ip, CSR_QSTATE_WR_3_ADDR, buf[3]);
#if !defined(CONFIG_APM862xx)
			apm_qm_wr32(ip, CSR_QSTATE_WR_4_ADDR, buf[4]);
#endif
		}
		apm_qm_rd32(ip, CSR_QSTATE_RD_0_ADDR, &buf[0]);
		apm_qm_rd32(ip, CSR_QSTATE_RD_1_ADDR, &buf[1]);
		apm_qm_rd32(ip, CSR_QSTATE_RD_2_ADDR, &buf[2]);
		apm_qm_rd32(ip, CSR_QSTATE_RD_3_ADDR, &buf[3]);
#if !defined(CONFIG_APM862xx)
		apm_qm_rd32(ip, CSR_QSTATE_RD_4_ADDR, &buf[4]);
#endif
		return 0;
	}

	/* Read/Write via SlimPRO interface */
	QM_DBG("QM QState %s QID %d\n", read ? "RD" : "WR", qid);
	rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_QSTATE, IPP_DP_RES_QM, read,
				qid, buf);
	if (rc != 0) {
		QM_DBG("QM QState cmd failed error %d\n", rc);
	} else {
#if defined(DQM_DBG)
		if (!read) {
			u32 tmp[5];
			rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_QSTATE,
				IPP_DP_RES_QM, 1, qid, tmp);
			if (rc != 0) {
				QM_DBG("QM QState cmd failed error %d\n", rc);
			} else if (memcmp(tmp, buf, 5*4) != 0) {
				QM_DBG("QM QState cmd failed data mismatch\n");
			}
		}
#endif
	}
	return rc;
}

static int __apm_qm_cstate_cmd(int ip, u32 qid, u32 *buf, int read)
{
	int rc;

	if (!__apm_qm_dp_enabled()) {
		apm_qm_wr32(ip, CSR_QSTATE_ADDR, qid);
		apm_qm_rd32(ip, CSR_QSTATE_ADDR, &qid); /* Force barrier */
		if (!read) {
			apm_qm_wr32(ip, CSR_CSTATE_WR_0_ADDR, buf[0]);
			apm_qm_wr32(ip, CSR_CSTATE_WR_1_ADDR, buf[1]);
		}
		apm_qm_rd32(ip, CSR_CSTATE_RD_0_ADDR, &buf[0]);
		apm_qm_rd32(ip, CSR_CSTATE_RD_1_ADDR, &buf[1]);
		return 0;
	}

	/* Read/Write via SlimPRO interface */
	rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_CSTATE, IPP_DP_RES_QM, read,
				qid, buf);
	if (rc != 0) {
		QM_DBG("QM CState cmd failed error %d\n", rc);
	} else {
#if defined(DQM_DBG)
		if (!read) {
			u32 tmp[2];
			rc = apm86xxx_dp_qm(IPP_DP_CMD_QM_CSTATE,
				IPP_DP_RES_QM, 1, qid, tmp);
			if (rc != 0)
				QM_DBG("QM CState cmd failed error %d\n", rc);
			else if (memcmp(tmp, buf, 2*4) != 0)
				QM_DBG("QM CState cmd failed data mismatch\n");
		}
#endif
	}
	return rc;
}

u32 apm_qm_pb_get(int ip, int slv_id, int pbn)
{
	u32 pbn_buf = 0;
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_buf, 1);
	apm_qm_indirect_access_lock(0);
	QM_DBG("PBN RD Addr: 0x%08X val: 0x%08X\n", val, pbn_buf);

	return pbn_buf;
}

u32 apm_qm_pb_set(int ip, int slv_id, int pbn, u32 pbn_buf)
{
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	QM_DBG("PBN WR Addr: 0x%08X val: 0x%08X\n", val, pbn_buf);
	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_buf, 0);
	apm_qm_indirect_access_lock(0);

	return pbn_buf;
}

int apm_qm_pb_disable(int ip, int slv_id, int pbn, int qnum)
{
	u32 pbn_buf = (1 << 31);
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	QM_DBG("PBN WR Addr: 0x%08X val: %x\n", val, pbn_buf);
	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_buf, 0);
	apm_qm_indirect_access_lock(0);
	pbn_valid[qnum] = 0;

	return 0;
}

int apm_qm_pb_clr(int ip, int slv_id, int pbn)
{
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;
	u32 pbn_val;
	int enabled;

	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_val, 1);
	/* Check if clear required? */
	if (!(pbn_val & (0x0000000F | 0x00038000))) {
		apm_qm_indirect_access_lock(0);
		return 0;
	}
	/* Disable first */
	enabled = pbn_val & (1 << 14);
	pbn_val &= ~(1 << 14);
	__apm_qm_pb_cmd(ip, val, &pbn_val, 0);
	/* Clear it out next */
	pbn_val |= (1 << 31);
	pbn_val &= ~0x0000000F;	/* Clear num msgs in buffer */
	pbn_val &= ~0x00038000;	/* Clear slot number */
	__apm_qm_pb_cmd(ip, val, &pbn_val, 0);
	/* Re-enable it */
	if (enabled) {
		pbn_val |= (1 << 14);
		__apm_qm_pb_cmd(ip, val, &pbn_val, 0);
	}
	QM_DBG("PBN WR Addr: 0x%08X val: %x\n", val, pbn_val);
	apm_qm_indirect_access_lock(0);
	return 0;
}
EXPORT_SYMBOL(apm_qm_pb_clr);

int apm_qm_pb_overwrite(int ip, int slv_id, int pbn, int qnum, u8 is_fp)
{
	u32 pbn_buf = 0;
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	pbn_buf |= ((1 << 31) | (qnum << 4) | (is_fp << 13) | (1 << 14) | 0x4);
	QM_DBG("PBN WR Addr: 0x%08X val: 0x%08X\n", val, pbn_buf);
	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_buf, 0);
	apm_qm_indirect_access_lock(0);
	pbn_valid[qnum] = 1;

	return 0;
}

int apm_qm_pb_config(int ip, int slv_id, int pbn, int qnum, u8 is_fp, u8 is_vq)
{
	u32 pbn_buf = 0;
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	pbn_buf |= ((qnum << 4) | (is_fp << 13) | (is_vq << 12) | (1 << 14));
	QM_DBG("Configure PBN WR Addr: 0x%08X val: 0x%08X\n", val, pbn_buf);
	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, &pbn_buf, 0);
	apm_qm_indirect_access_lock(0);
	pbn_valid[qnum] = 1;
	return 0;
}
EXPORT_SYMBOL(apm_qm_pb_config);

int apm_qm_pb_cfg_rd(int ip, int slv_id, int pbn, u32 *pbn_val)
{
	u32 val = (slv_id << SLAVE_ID_SHIFT) | pbn;

	apm_qm_indirect_access_lock(1);
	__apm_qm_pb_cmd(ip, val, pbn_val, 1);
	apm_qm_indirect_access_lock(0);
	QM_DBG("Configure PBN RD Addr: 0x%08X val: 0x%08X\n", val, *pbn_val);

	return 0;
}

int apm_qm_enq_stats_setqid(int ip, u32 qid)
{
	u32 val = 0x0;

	apm_qm_rd32(ip, CSR_QM_STATS_CFG_ADDR, &val);
	val = QID_ENQ_COUNTER_F2_SET(val, qid);
	if (!apm86xxx_is_dp_mode())
		apm_qm_wr32(ip, CSR_QM_STATS_CFG_ADDR, val);
	else    /* Write via SlimPRO interface */
		apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
				CSR_QM_STATS_CFG_ADDR, val);
	return 0;
}

u32 apm_qm_enq_stats_getqid(int ip)
{
	u32 val = 0x0;
	apm_qm_rd32(ip, CSR_QM_STATS_CFG_ADDR, &val);
	return QID_ENQ_COUNTER_F2_RD(val);
}

u32 apm_qm_enq_stats_value(int ip)
{
	u32 val = 0x0;

	apm_qm_rd32(ip, CSR_ENQ_STATISTICS_ADDR, &val);
	return val;
}

int apm_qm_deq_stats_setqid(int ip, u32 qid)
{
	u32 val = 0x0;

	apm_qm_rd32(ip, CSR_QM_STATS_CFG_ADDR, &val);
	val = QID_DEQ_COUNTER_F2_SET(val, qid);
	if (!apm86xxx_is_dp_mode())
		apm_qm_wr32(ip, CSR_QM_STATS_CFG_ADDR, val);
	else    /* Write via SlimPRO interface */
		apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
				CSR_QM_STATS_CFG_ADDR, val);
	return 0;
}

u32 apm_qm_deq_stats_getqid(int ip)
{
	u32 val = 0x0;

	apm_qm_rd32(ip, CSR_QM_STATS_CFG_ADDR, &val);
	return QID_DEQ_COUNTER_F2_RD(val);
}

u32 apm_qm_deq_stats_value(int ip)
{
	u32 val = 0x0;

	apm_qm_rd32(ip, CSR_DEQ_STATISTICS_ADDR, &val);
	return val;
}

int apm_qm_raw_qstate_rd(int ip, int q_num, struct apm_qm_raw_qstate *raw_q)
{
	int rc = 0;
	u32 queue_id = 0;

	if (q_num < 0 || q_num > 255) {
		QM_PRINT("Queue number is not valid\n");
		return -1;
	}

	queue_id = QNUMBER_F2_SET(queue_id, q_num);
	apm_qm_indirect_access_lock(1);
	__apm_qm_qstate_cmd(ip, queue_id, (u32 *) raw_q, 1);
#if !defined(CONFIG_APM862xx)
	QM_STATE_DBG("QState RD QID %d 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X\n",
		queue_id,
		raw_q->w0, raw_q->w1, raw_q->w2, raw_q->w3, raw_q->w4);
#else
	QM_STATE_DBG("QState RD QID %d 0x%08X 0x%08X 0x%08X 0x%08X\n",
		queue_id, raw_q->w0, raw_q->w1, raw_q->w2, raw_q->w3);
#endif
	apm_qm_indirect_access_lock(0);

	return rc;
}

int apm_qm_get_qstate_msgcnt(int qid, u32 *count)
{
	u32 qaddr;
	u32 val[5] = {'\0'};

#if defined(CONFIG_APM862xx)
	qaddr = QNUMBER_F2_WR(qid);
#else
	qaddr = QNUMBER_WR(qid);
#endif
	apm_qm_indirect_access_lock(1);
	__apm_qm_qstate_cmd(IP_BLK_QM, qaddr, val, 1);
	apm_qm_indirect_access_lock(0);
	*count = val[3] & 0xFFFF;
	return 0;
}

int apm_qm_qstate_rd_cfg(int q_num, struct apm_qm_qstate *qstate)
{
	if (q_num < 0 || q_num > QM_MAX_QUEUES)
		return -1;

	memcpy(qstate, &queue_states[q_num], sizeof(struct apm_qm_qstate));
	return 0;
}

int apm_qm_qstate_rd(int ip, int q_num, struct apm_qm_qstate *qstate)
{
	int rc = 0;
	struct apm_qm_pqstate pq;
	struct apm_qm_qstate *q_sw_state = &queue_states[q_num];

	memset((void *)&pq, 0, sizeof(pq));

	if ((!q_sw_state->valid) || (q_sw_state->q_type == QUEUE_DISABLED)) {
		QM_PRINT("Queue config is not valid\n");
		return -1;
	}

	if (q_num < 0 || q_num > 255) {
		QM_PRINT("Queue number is not valid\n");
		return -1;
	}

	rc = apm_qm_raw_qstate_rd(ip, q_num, (struct apm_qm_raw_qstate *) &pq);
	if (rc) {
		return rc;
	}

	/* fill infor from hw state */
	qstate->q_type = pq.cfgqtype;
	qstate->thr_set = pq.cfgselthrsh;
	qstate->fp_mode = pq.fp_mode;
	qstate->q_size = pq.cfgqsize;
	qstate->q_start_addr = (pq.cfgstartaddr_hi << 24) | pq.cfgstartaddr_lo;
	qstate->nummsgs = pq.nummsg;
	qstate->rid = pq.rid;
	qstate->cfgsaben = pq.cfgsaben;
	qstate->ppc_notify = pq.ppc_notify;

	/* fill info from sw state */
	qstate->q_id = q_sw_state->q_id;
	qstate->ip_blk = q_sw_state->ip_blk;
	qstate->valid = q_sw_state->valid;
	qstate->mb_id = q_sw_state->mb_id;
	qstate->slave_id = q_sw_state->slave_id;
	qstate->pbn = q_sw_state->pbn;
	qstate->direction = q_sw_state->direction;
	qstate->msg_stat = q_sw_state->msg_stat;
#if defined(CONFIG_APM_QOS)
	qstate->parent_vqid = pq.cfgtmvq;
	qstate->vqen = pq.cfgtmvqen;
	if (qstate->q_type == V_QUEUE) {
		struct apm_qm_vqstate *vq = (struct apm_qm_vqstate *)&pq;
		qstate->pq_sel[0] = vq->q0_sel;
		qstate->pq_sel[1] = vq->q1_sel;
		qstate->pq_sel[2] = (vq->q2_sel_3b << 5) | vq->q2_sel_5b;
		qstate->pq_sel[3] = vq->q3_sel;
		qstate->pq_sel[4] = vq->q4_sel;
		qstate->pq_sel[5] = vq->q5_sel;
		qstate->pq_sel[6] = vq->q6_sel;
		qstate->pq_sel[7] = (vq->q7_sel_7b << 1) | vq->q7_sel_1b;
		qstate->q_sel_arb[0] = vq->q0selarb;
		qstate->q_sel_arb[1] = vq->q1selarb;
		qstate->q_sel_arb[2] = vq->q2selarb;
		qstate->q_sel_arb[3] = vq->q3selarb;
		qstate->q_sel_arb[4] = (vq->q4selarb_hi << 1) | vq->q4selarb_lo;
		qstate->q_sel_arb[5] = vq->q5selarb;
		qstate->q_sel_arb[6] = vq->q6selarb;
		qstate->q_sel_arb[7] = vq->q7selarb;
	}
#endif

	return rc;
}

int apm_qm_raw_qstate_wr(int qm_blk_id, int q_num,
			struct apm_qm_raw_qstate *raw_q)
{
	u32 queue_id = 0;

	if (q_num < 0 || q_num > 255) {
		QM_PRINT("Queue ID %d not valid in cfg write\n", q_num);
		return -1;
	}

	/* write queue number */
	queue_id = QNUMBER_F2_SET(queue_id, q_num);
	apm_qm_indirect_access_lock(1);
	__apm_qm_qstate_cmd(qm_blk_id, queue_id, (u32 *) raw_q, 0);
#if !defined(CONFIG_APM862xx)
	QM_STATE_DBG("QState WR QID %d 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X\n",
		queue_id,
		raw_q->w0, raw_q->w1, raw_q->w2, raw_q->w3, raw_q->w4);
#else
	QM_STATE_DBG("QState WR QID %d 0x%08X 0x%08X 0x%08X 0x%08X\n",
		queue_id, raw_q->w0, raw_q->w1, raw_q->w2, raw_q->w3);
#endif
	apm_qm_indirect_access_lock(0);

	return 0;
}
EXPORT_SYMBOL(apm_qm_qstate_wr);

int apm_qm_cpu2domain(void)
{
	int cpuid = mfspr(SPRN_PIR);

	switch (cpuid) {
	case 0:
	default:
		return 0x02;
	case 1:
		return 0x03;
	}
}

int apm_qm_cpu2domain_allowed(void)
{
	int cpuid = mfspr(SPRN_PIR);

	switch (cpuid) {
	case 0:
	default:
		return 0x04;
	case 1:
		return 0x08;
	}
}

int apm_qm_qstate_wr(struct apm_qm_qstate *qstate)
{
	struct apm_qm_pqstate pq;
	int rc = 0;
	u8 *qaddr = NULL;
	u32 q_size = 0;
	u64 qaddr_phy;
	u32 mem_size;
	int q_num = qstate->q_id;
	u8 q_allocated = 0;

	memset(&pq, 0, sizeof(pq));

	if (q_num < 0 || q_num > 255) {
		QM_PRINT("Queue number not valid in cfg write: 0x%x\n", q_num);
		return -1;
	}

	if ((!qstate->valid) || (qstate->q_type == QUEUE_DISABLED)) {
		QM_PRINT("Queue config not valid in cfg write\n");
		return -1;
	}

	if (qstate->ip_blk != IP_BLK_QML && qstate->ip_blk != IP_BLK_QM) {
		QM_PRINT("Invalid Block ID in cfg write: %d\n", qstate->ip_blk);
		return -1;
	}

	if (qstate->ip_blk != IP_BLK_QML) {
		if (qstate->direction) { /* egress direction */
			QM_DBG("Using MB %d PBN %d queue %d IP %d slave %d "
				"in EGRESS\n",
				qstate->mb_id, qstate->pbn, q_num,
				qstate->src_ip_blk, qstate->slave_id);
			q_to_mb[q_num] = qstate->mb_id;
		} else if (qstate->slave_id == PB_SLAVE_ID_PPC &&
			   qstate->q_type == FREE_POOL) {
			QM_DBG("Using MB %d PBN %d queue %d IP %d slave %d "
				"in Free Pool PPC\n",
				qstate->mb_id, qstate->pbn, q_num,
				qstate->src_ip_blk, qstate->slave_id);
			q_to_mb[q_num] = qstate->mb_id;
			mb_to_q[qstate->mb_id] = q_num;
		} else {
			QM_DBG("Using MB %d PBN %d queue %d IP %d slave %d "
				"in INGRESS\n",
				qstate->mb_id, qstate->pbn, q_num,
				qstate->src_ip_blk, qstate->slave_id);
			if (qstate->vqen == ENABLE_VQ) {
				mb_to_q[qstate->mb_id] = qstate->parent_vqid;
			} else {
				mb_to_q[qstate->mb_id] = q_num;
				q_to_mb[q_num] = qstate->mb_id;
			}
		}
	}

	/* Configure domain protection field */
#if !defined(CONFIG_APM862xx)
	if (apm86xxx_is_dp_mode()) {
		pq.queue_dom = apm_qm_cpu2domain();
		pq.allowed_dom = apm_qm_cpu2domain_allowed();
		pq.not_insert_dom = 0;
	} else {
		pq.queue_dom = 0x0;
		pq.allowed_dom = 0xF;
		pq.not_insert_dom = 0x1;
	}
#endif

	pq.cfgqtype = qstate->q_type;
	pq.cfgselthrsh = qstate->thr_set;
	pq.cfgqsize = qstate->q_size;
	pq.fp_mode = qstate->fp_mode;
	/*
	 * u-boot does not use alternate enqueue method, in which queues
	 * are non-cacheable. It uses mailbox based approach in which queues
	 * are cacheable. So, for bootloader enable queue-coherency always.
	 */
#if !defined(CONFIG_APM862xx)
#ifdef BOOTLOADER
	pq.qcoherent = 1;
#endif
#endif
	/* Ethernet can generate LError for fragment packet (checksum error),
           we must allow the queue to accept message with non-zero LErr. */
	pq.cfgacceptlerr = 1;
	switch (qstate->q_size) {
	case SIZE_512B:
		q_size = 512;
		break;
	case SIZE_2KB:
		q_size = 2 * 1024;
		break;
	case SIZE_16KB:
		q_size = 16 * 1024;
		break;
	case SIZE_64KB:
		q_size = 64 * 1024;
		break;
	case SIZE_512KB:
		q_size = 512 * 1024;
		break;
	default:
		QM_PRINT("Invalid queue size cfg write %d\n", qstate->q_size);
		return -1;
	}

	/* if its a free queue, ask QM to set len to 0 when dealloc */
	if (qstate->q_type == FREE_POOL)
		pq.fp_mode = 0x3;	/* FIXME, replace with enum once tested */

	if (qstate->q_start_addr != 0) { /* QM queues statically & dynamically allocated to reside in DRAM */
		switch (qstate->q_type) {
		case FREE_POOL:
			qaddr_phy = QMI_ETH_IPP_INGRESS_FP_ADDR;
			break;
		case P_QUEUE:
			if (qstate->direction) /* Egress */
				qaddr_phy = QMI_ETH_IPP_EGRESS_WQ_ADDR;
			else
				qaddr_phy = QMI_ETH_IPP_INGRESS_WQ_ADDR;
			break;
		default:
			QM_PRINT("Invalid queue type in QM/QML queue config\n");
			return -1;
		}

		qstate->q_start_addr = qaddr_phy >> 8; /* 256 byte aligned */
		pq.cfgstartaddr_hi = QMI_UPPER_ADDR_NIBBLE;
	} else { /* QM queues dynamically allocated to reside in DDR */
		if (((qstate->slave_id == PB_SLAVE_ID_PPC &&
		     qstate->q_type == FREE_POOL) || qstate->direction == 1)
		     && queue_baddr != 0) {
			/* Alternative enqueue requires non-cachable memory */
			if ((queue_baddr_p + q_size) >  queue_eaddr_p) {
				QM_PRINT("Not enough memory to "
					"allocate queue\n");
				return -1;
			}

			qaddr_phy = queue_baddr_p;
			qstate->q_start_addr = qaddr_phy >> 8; /* 256 byte aligned */
			qstate->startptr = queue_baddr;
			qstate->tailptr = queue_baddr;
			qstate->endptr = queue_baddr + q_size;
			if (qstate->q_type == FREE_POOL)
				qstate->lastptr = queue_baddr + q_size - 16;
			else
				qstate->lastptr = queue_baddr + q_size - 32;
			pq.cfgstartaddr_hi = (queue_baddr_p >> 32) & 0xF;
			queue_baddr += q_size;
			queue_baddr_p += q_size;
			q_allocated = 1;
		}
		if (q_allocated == 0) {
			u8 *qaddr_aligned = NULL;
			u32 tmp_qaddr;

			mem_size = q_size + 512;
			qaddr = (u8 *) MEMALLOC(mem_size);
			if (qaddr == NULL) {
				QM_PRINT("Could not allocate memory for queue\n");
				return -1;
			}

			qaddr_aligned = qaddr + 256;
			tmp_qaddr = (u32) qaddr_aligned;
			tmp_qaddr &= 0xFFFFFF00; /* queue addresses 256 byte
						    aligned */
			qaddr_phy = (u64)((unsigned long)virt_to_phys((u32 *)tmp_qaddr));
			qstate->q_start_addr = qaddr_phy >> 8; /* 256 byte
								aligned */
			pq.cfgstartaddr_hi = (qaddr_phy >> 32) & 0xF;
			QM_DBG("Queue PAddr 0x%llx VAddr %x\n",
				qaddr_phy, tmp_qaddr);
		}
	}

	pq.cfgstartaddr_lo = qstate->q_start_addr & 0xFFFFFF;
	pq.ppc_notify = qstate->ppc_notify;
	pq.cfgnotifyqne = qstate->q_not_empty_intr;
	pq.cfgsaben = qstate->cfgsaben;
	if (qstate->q_type == P_QUEUE) {
		pq.cfgtmvq = qstate->parent_vqid;
		pq.cfgtmvqen = qstate->vqen;
	}

	rc = apm_qm_raw_qstate_wr(qstate->ip_blk,
				  q_num, (struct apm_qm_raw_qstate *) &pq);
	if (rc) {
		return rc;
	}

	/* copy software queue state */
	memcpy(&queue_states[qstate->q_id], qstate,
		sizeof(struct apm_qm_qstate));
	queue_states[qstate->q_id].msg_stat = 0;

	return rc;
}

int apm_qm_cstate_wr(u32 qid, u32 cstate[2])
{
	u32 queue_id = 0;
	int rc = 0;

	if (qid < 0 || qid > 255) {
		QM_PRINT("Queue number not valid in cfg write: 0x%x\n", qid);
		return -1;
	}

	/* write queue number */
	queue_id = QNUMBER_F2_SET(queue_id, qid);
	QM_DBG("CState WR QID %d 0x%08X 0x%08X\n",
		queue_id, cstate[0], cstate[1]);
	apm_qm_indirect_access_lock(1);
	__apm_qm_cstate_cmd(IP_BLK_QM, queue_id, cstate, 0);
	apm_qm_indirect_access_lock(0);

	return rc;
}

int apm_qm_cstate_rd(u32 qid, u32 *cstate)
{
	u32 queue_id = 0;
	int rc = 0;

	if (qid < 0 || qid > 255) {
		QM_PRINT("Queue number not valid in cfg write: 0x%x\n", qid);
		return -1;
	}

	/* write queue number */
	queue_id = QNUMBER_F2_SET(queue_id, qid);
	apm_qm_indirect_access_lock(1);
	__apm_qm_cstate_cmd(IP_BLK_QM, queue_id, cstate, 1);
	QM_DBG("CState RD QID %d 0x%08X 0x%08X\n",
		queue_id, cstate[0], cstate[1]);
	apm_qm_indirect_access_lock(0);

	return rc;
}

int apm_qm_vqstate_wr(struct apm_qm_qstate *qstate)
{
	struct apm_qm_vqstate vq;
	int rc = 0, q_num = qstate->q_id, i;
	u32 cstate[2] = {0};

	memset(&vq, 0, sizeof(vq));

	if (q_num < 0 || q_num > 255) {
		QM_PRINT("Queue number not valid in cfg write: 0x%x\n", q_num);
		return -1;
	}

	if ((!qstate->valid) || (qstate->q_type != V_QUEUE)) {
		QM_PRINT("Virtual queue config not valid in cfg write\n");
		return -1;
	}

	if (qstate->ip_blk != IP_BLK_QM) {
		QM_PRINT("Invalid Block ID in cfg write for VQ: %d\n",
			 qstate->ip_blk);
		return -1;
	}

	vq.cfgqtype = qstate->q_type;
	vq.cfgselthrsh = qstate->thr_set;
	vq.q0_sel = qstate->pq_sel[0];
	vq.q0selarb = qstate->q_sel_arb[0];
	if (qstate->q_sel_arb[0] == DRR_ARB)
		vq.q0txallowed = 1;
	vq.q1_sel = qstate->pq_sel[1];
	vq.q1selarb = qstate->q_sel_arb[1];
	if (qstate->q_sel_arb[1] == DRR_ARB)
		vq.q1txallowed = 1;
	vq.q2_sel_3b = qstate->pq_sel[2] >> 5;
	vq.q2_sel_5b = qstate->pq_sel[2] & 0x1F;
	vq.q2selarb = qstate->q_sel_arb[2];
	if (qstate->q_sel_arb[2] == DRR_ARB)
		vq.q2txallowed = 1;
	vq.q3_sel = qstate->pq_sel[3];
	vq.q3selarb = qstate->q_sel_arb[3];
	if (qstate->q_sel_arb[3] == DRR_ARB)
		vq.q3txallowed = 1;
	vq.q4_sel = qstate->pq_sel[4];
	vq.q4selarb_hi = qstate->q_sel_arb[4] >> 1;
	if (qstate->q_sel_arb[4] == DRR_ARB)
		vq.q4txallowed = 1;
	vq.q4selarb_lo = qstate->q_sel_arb[4] & 1;
	vq.q5_sel = qstate->pq_sel[5];
	vq.q5selarb = qstate->q_sel_arb[5];
	if (qstate->q_sel_arb[5] == DRR_ARB)
		vq.q5txallowed = 1;
	vq.q6_sel = qstate->pq_sel[6];
	vq.q6selarb = qstate->q_sel_arb[6];
	if (qstate->q_sel_arb[6] == DRR_ARB)
		vq.q6txallowed = 1;
	vq.q7_sel_7b = qstate->pq_sel[7] >> 1;
	vq.q7_sel_1b = qstate->pq_sel[7] & 1;
	vq.q7selarb = qstate->q_sel_arb[7];
	if (qstate->q_sel_arb[7] == DRR_ARB)
		vq.q7txallowed = 1;
	vq.ppc_notify = qstate->ppc_notify;
	vq.cfgnotifyqne = qstate->q_not_empty_intr;

	/* Configure domain protection field. For VQ, allow for all and
           use the original message domain */
#if !defined(CONFIG_APM862xx)
	vq.allowed_dom = 0xF;
#endif

	rc = apm_qm_raw_qstate_wr(qstate->ip_blk,
				  q_num, (struct apm_qm_raw_qstate *)&vq);
#if defined(CONFIG_APM_QOS)
	/* Assign mapping b/w mailbox and queue. Or it will lead to issue of
	 * NULL context */
	mb_to_q[qstate->mb_id] = qstate->q_id;
#endif
	if (rc) {
		return rc;
	}

	/* copy software queue state */
	memcpy(&queue_states[qstate->q_id], qstate,
			sizeof (struct apm_qm_qstate));

	if (qstate->q_sel_arb[0] == SP_ARB)
		goto exit;

	/* Update Credit Ram State for each of PQ */
	for (i = 0; i < 8; i++) {
		QM_DBG("q_sel_arb[%d] = %d, pq_sel[%d] = %d rate/weight[%d] = %d\n",
			 i, qstate->q_sel_arb[i], i,  qstate->pq_sel[i], i, qstate->shape_rate[i]);
		if (qstate->q_sel_arb[i] == DRR_ARB) {
			u32 credit = qstate->shape_rate[i] * DRR_CREDIT_GRAN;
			cstate[0] = credit >> 10;
			cstate[1] = ((credit & 0X3FF) << 22) |
					(credit & 0X3FFFFF);
			QM_DBG("Credit: %d\n", credit);
			QM_DBG("Writing Cstate for pq_sel[%d]:%d - cstate[0]:0x%x, cstate[1]:0x%x\n", i, qstate->pq_sel[i], cstate[0], cstate[1]);
		} else if (qstate->q_sel_arb[i] == AVB_ARB) {
			u32 slope = qstate->shape_rate[i];
			cstate[0] |= slope >> 4 ;
			cstate[1] |= (slope & 0xf) << 28;
			QM_DBG("Writing Cstate for pq_sel[%d]:%d - cstate[0]:0x%x, cstate[1]:0x%x \n", i, qstate->pq_sel[i], cstate[0], cstate[1]);
		} else {
			continue;
		}
		apm_qm_cstate_wr(qstate->pq_sel[i], cstate);
		cstate[0] = cstate[1] = 0;
	}

	/* Update Credit Ram State for each of PQ */
	apm_qm_cstate_wr(qstate->q_id, cstate);

exit:
	return rc;
}
EXPORT_SYMBOL(apm_qm_vqstate_wr);

int apm_qm_config_qstate(int no_of_queues)
{
	struct apm_qm_qstate *qstate = NULL;
	int i, is_fp = 0, rc = 0, is_vq;

	QM_DBG("Configure static queues: %d\n", no_of_queues);
	/* configure QM */
	for (i = 0; i < no_of_queues; i++) {
		qstate = &mb_cfg_pqs[i];
		if (qstate->ip_blk == IP_BLK_QML && qm_cinfo.is_noqml) {
			/* Skip QM Lite configuration if hardware not
				available */
			continue;
		}
		if ((rc = apm_qm_qstate_wr(qstate)) != 0) {
			QM_PRINT("Error in queue configuration error %d\n",
				rc);
			break;
		}
		is_fp = ((qstate->q_type == FREE_POOL) ? 1 : 0);
		is_vq = ((qstate->q_type == V_QUEUE) ? 1 : 0);
		apm_qm_pb_config(qstate->ip_blk, qstate->slave_id, qstate->pbn,
				qstate->q_id, is_fp, is_vq);
	}

	return rc;
}

static void apm_qm_pbn_init(void)
{
	memset(ip_pbn_wq_msk, 0, sizeof(ip_pbn_wq_msk));
	memset(ip_pbn_wq_act, 0, sizeof(ip_pbn_wq_act));
	memset(ip_pbn_fq_msk, 0, sizeof(ip_pbn_fq_msk));
	memset(ip_pbn_fq_act, 0, sizeof(ip_pbn_fq_act));

	/* PPC0/1 PBN as shared */
	ip_pbn_wq_msk[IP_PPC0] = 0xFFFF;
	ip_pbn_fq_msk[IP_PPC0] = 0xFFFF;
	ip_pbn_wq_msk[IP_PPC1] = 0xFFFF;	/* NOT used */
	ip_pbn_fq_msk[IP_PPC1] = 0xFFFF;	/* NOT used */

	/* DMA PBN */
	ip_pbn_wq_msk[IP_DMA] = 0x000F;
	ip_pbn_fq_msk[IP_DMA] = 0x00FF;

	/* ETH 0 PBN */
	ip_pbn_wq_msk[IP_ETH0] = 0x00FF;
	ip_pbn_fq_msk[IP_ETH0] = 0x00FF;

	/* ETH 1 PBN */
	ip_pbn_wq_msk[IP_ETH1] = 0xFF00;	/* 0x10 is for QM-lite */
	ip_pbn_fq_msk[IP_ETH1] = 0xFF00;	/* 0x30 and 0x31 for QM-lite */

	/* ETH 2 PBN */
	ip_pbn_wq_msk[IP_ETH2] = 0x00FF;
	ip_pbn_fq_msk[IP_ETH2] = 0x00FF;

	/* ETH 3 PBN */
	ip_pbn_wq_msk[IP_ETH3] = 0xFF00;	/* 0x10 is for QM-lite */
	ip_pbn_fq_msk[IP_ETH3] = 0xFF00;	/* 0x30 and 0x31 for QM-lite */

	/* SEC PBN */
	ip_pbn_wq_msk[IP_SEC] = 0x0003;
	ip_pbn_fq_msk[IP_SEC] = 0x00FF;

	/* OCMM PBN */
	ip_pbn_wq_msk[IP_OCMM] = 0x0007;
	ip_pbn_fq_msk[IP_OCMM] = 0x0007;

	/* CLE PBN */
	ip_pbn_wq_msk[IP_CLASS] = 0x0001;
	ip_pbn_fq_msk[IP_CLASS] = 0x00FF;

	/* SlimPRO PBN */
	ip_pbn_wq_msk[IP_IPP] = 0x0001;		/* Work QID 0x1 for QM-lite */
	ip_pbn_fq_msk[IP_IPP] = 0x00FF;		/* Free PBN 0x28 for QM-lite */
}

int apm_qm_get_ib_mb(int ppcx, int ip_blk)
{
	int idx;

#ifndef IOS_INTERWORKING
	int found = 0;

	for (idx = qm_cinfo.start_mboxes;
		idx < qm_cinfo.start_mboxes + qm_cinfo.max_mboxes;
		idx++) {
		/* Check if this slot is in use */
		if (!ib_mbox_used[idx]) {
			/* If empty lets use it */
			ib_mbox_used[idx] = ip_blk | 0x8000;
			found = 1;
			break;
		}
	}

	if (!found)
		QM_DBG("Error: Inbound mailbox slots all taken\n");
#else
	/* Use mostly for completion queue */
	/* When interworking with IOS, use fixed values for MBOXes */
	switch (ip_blk) {
	case IP_PPC0:
	case IP_PPC1:
		idx = ppcx * 8 + 1;
		break;
	case IP_ETH0:
	case IP_ETH1:
		idx = ppcx * 8 + 2;		/* for completion */
		if (!ib_mbox_used[idx])
			break;
		idx = ppcx * 8 + 3;		/* for work queue */
		if (!ib_mbox_used[idx])
			break;
		idx = ppcx * 8 + 4;		/* for work queue */
		break;
	case IP_IPP:
		idx = ppcx * 8 + 5;
		break;
	case IP_SEC:
		idx = ppcx * 8 + 6;
		break;
	case IP_CLASS:
	case IP_DMA:
		idx = ppcx * 8 + 7;
		break;
	case IP_OCMM:
	default:
		idx = ppcx * 8 + 0; /* For QM-lite dequeue msg */
		break;
	}
	if (ib_mbox_used[idx]) {
		QM_DBG("Inbound mail box already used %d ppcx %d ip blk %d\n",
			idx, ppcx, ip_blk);
	}
	ib_mbox_used[idx] = 1;
#endif
	return idx;
}

int apm_qm_get_ib_pbn(int ppcx, int ip_blk, int ibmbox)
{
	/* PBN is same as mail box */
	if (ip_pbn_wq_msk[IP_PPC0] & (1 << ibmbox)) {
		if (!(ip_pbn_wq_act[IP_PPC0] & (1 << ibmbox))) {
			ip_pbn_wq_act[IP_PPC0] |= (1 << ibmbox);
			return ibmbox;
		}
	}

	/* Out of PPC PBN */
	QM_ERR_CHK("Out of PPC QM PBN for CPU %d IP %d\n", ppcx, ip_blk);
	return -1;
}

int apm_qm_free_ib_pbn(int ppcx, int ip_blk, int ibmbox)
{
	/* PBN is same as mail box */
	if (ip_pbn_wq_msk[IP_PPC0] & (1 << ibmbox)) {
		if (ip_pbn_fq_act[IP_PPC0] & (1 << ibmbox)) {
			ip_pbn_fq_act[IP_PPC0] &= ~(1 << ibmbox);
			return 0;
		}
	}
	return -1;
}

int apm_qm_get_fp_pbn(int ppcx, int ip_blk)
{
	int i;

	/* FP PBN for PPC are shared */
	if (ip_blk == IP_PPC1)
		ip_blk = IP_PPC0;

	if (ppcx == 0) {
		/* Search for a free PBN for this IP block */
		for (i = 0; i <= 31; i++) {
			if (ip_pbn_fq_msk[ip_blk] & (1 << i) &&
			    !(ip_pbn_fq_act[ip_blk] & (1 << i))) {
				/* We found a free PBN */
				ip_pbn_fq_act[ip_blk] |= (1 << i);
				return i + 0x20;
			}
		}
	} else {
		/* Search for a free PBN for this IP block */
		for (i = 31; i >= 0; i--) {
			if (ip_pbn_fq_msk[ip_blk] & (1 << i) &&
			    !(ip_pbn_fq_act[ip_blk] & (1 << i))) {
				/* We found a free PBN */
				ip_pbn_fq_act[ip_blk] |= (1 << i);
				return i + 0x20;
			}
		}
	}
	/* Out of PBN */
	QM_ERR_CHK("Out of QM FP PBN for CPU %d IP %d\n", ppcx, ip_blk);
	return -1;
}

int apm_qm_free_fp_pbn(int ip_blk, int pbn)
{
	int pbn_bit = pbn - 0x20;

	/* FP PBN for PPC are shared */
	if (ip_blk == IP_PPC1)
		ip_blk = IP_PPC0;

	if (ip_pbn_fq_msk[ip_blk] & (1 << pbn_bit)) {
		ip_pbn_fq_act[ip_blk] &= ~(1 << pbn_bit);
		return 0;
	} else {
		return -1;
	}
}

int apm_qm_get_ob_mb(int ppcx, int ip_blk)
{
	switch (ip_blk) {
	case IP_PPC0:
	case IP_PPC1:
		return ppcx * 8 + 1;
	case IP_ETH0:
	case IP_ETH1:
	case IP_ETH2:
	case IP_ETH3:
		return ppcx * 8 + 2;
	case IP_IPP:
		return ppcx * 8 + 3;
	case IP_DMA:
		return ppcx * 8 + 4;
	case IP_SEC:
		return ppcx * 8 + 5;
	case IP_CLASS:
		return ppcx * 8 + 6;
	case IP_OCMM:	/* All other */
	default:
		return ppcx * 8 + 0;
	/* NOTE: 1 remaining outbound mailbox per core */
	}
}

int apm_qm_get_ob_pbn(int ppcx, int ip_blk)
{
	int i;

	if (ip_blk == IP_PPC0) {
		/* Search for a free PBN for this IP block */
		for (i = 0; i <= 31; i++) {
			if (ip_pbn_wq_msk[ip_blk] & (1 << i) &&
			    !(ip_pbn_wq_act[ip_blk] & (1 << i))) {
			    /* We found a PBN */
			    ip_pbn_wq_act[ip_blk] |= (1 << i);
			    return i;
			}
		}
		/* Out of PBN */
		QM_ERR_CHK("Out of QM PBN for CPU %d IP %d\n", ppcx, ip_blk);
		return -1;
	} else if (ip_blk == IP_PPC1) {
		/* PBN for PPC are shared */
		ip_blk = IP_PPC0;
		/* Search for a free PBN for this IP block */
		for (i = 31; i >= 0; i--) {
			if (ip_pbn_wq_msk[ip_blk] & (1 << i) &&
			    !(ip_pbn_wq_act[ip_blk] & (1 << i))) {
			    /* We found a free PBN */
			    ip_pbn_wq_act[ip_blk] |= (1 << i);
			    return i;
			}
		}
		/* Out of PBN */
		QM_ERR_CHK("Out of QM PBN for CPU %d IP %d\n", ppcx, ip_blk);
		return -1;
	}
	/* Select non-CPU IP PBN */
	if (ppcx == 0) {
		/* Search for a free PBN for this IP block */
		for (i = 0; i <= 31; i++) {
			if (ip_pbn_wq_msk[ip_blk] & (1 << i) &&
				!(ip_pbn_wq_act[ip_blk] & (1 << i))) {
				/* We found a PBN */
				ip_pbn_wq_act[ip_blk] |= (1 << i);
				return i;
			}
		}
	} else {
		/* Search for a free PBN for this IP block */
		for (i = 31; i >= 0; i--) {
			if (ip_pbn_wq_msk[ip_blk] & (1 << i) &&
			    !(ip_pbn_wq_act[ip_blk] & (1 << i))) {
			    /* We found a free PBN */
			    ip_pbn_wq_act[ip_blk] |= (1 << i);
			    return i;
			}
		}
	}
	/* Out of PBN */
	QM_ERR_CHK("Out of QM PBN for CPU %d IP %d\n", ppcx, ip_blk);
	return -1;
}

int apm_qm_free_ob_pbn(int ppcx, int ip_blk, int pbn)
{
	int i;

	if (ip_blk == IP_PPC0 || ip_blk == IP_PPC1) {
		if (ip_pbn_wq_msk[IP_PPC0] & (1 << pbn)) {
			ip_pbn_wq_act[IP_PPC0] &= ~(1 << pbn);
			return i;
		}
		return 0;
	}
	/* Select non-CPU IP PBN */
	if (ip_pbn_wq_msk[ip_blk] & (1 << pbn))
		ip_pbn_wq_act[ip_blk] &= ~(1 << pbn);
	return 0;
}

void apm_qm_set_enq_mbox_addr(u32 coherent, u64 paddr)
{
	u32 data = 0;
	u32 reg;

	if (coherent)
		data = 0x80000000;

	/* NOTE: We do check ensure domain protection enabled */
	data |= (u32)(paddr >> 10);
	apm_qm_rd32(IP_BLK_QM, CSR_ENQ_BASE_A_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_ENQ_BASE_A_ADDR, data);
	data += 3;
	apm_qm_rd32(IP_BLK_QM, CSR_ENQ_BASE_B_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_ENQ_BASE_B_ADDR, data);
}

void apm_qm_set_dq_mbox_addr(u32 coherent, u64 paddr)
{
	u32 data = 0;
	u32 reg;

	if (coherent)
		data = 0x80000000;

#if defined(CONFIG_APM862xx)
	data |= (u32)(paddr >> 12);
	apm_qm_wr32(IP_BLK_QM, CSR_PPC_MBOX_BASE_ADDR, data);
#else
	/* NOTE: We do check ensure domain protection enabled */
	data |= (u32)(paddr >> 10);
	apm_qm_rd32(IP_BLK_QM, CSR_PPC_MBOX_BASE_A_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_PPC_MBOX_BASE_A_ADDR, data);
	data += 3;
	apm_qm_rd32(IP_BLK_QM, CSR_PPC_MBOX_BASE_B_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_PPC_MBOX_BASE_B_ADDR, data);
#endif
}

void apm_qm_set_fp_mbox_addr(u32 coherent, u64 paddr)
{
	u32 data = 0;
	u32 reg;

	if (coherent)
		data = 0x80000000;

#if defined(CONFIG_APM862xx)
	data |= (u32)(paddr >> 12);
	apm_qm_wr32(IP_BLK_QM, CSR_PPC_FPOOL_BASE_ADDR, data);
#else
	/* NOTE: We do check ensure domain protection enabled */
	data |= (u32)(paddr >> 9);
	apm_qm_rd32(IP_BLK_QM, CSR_PPC_FPOOL_BASE_A_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_PPC_FPOOL_BASE_A_ADDR, data);
	data += 3;
	apm_qm_rd32(IP_BLK_QM, CSR_PPC_FPOOL_BASE_B_ADDR, &reg);
	if (reg != data)
		apm_qm_wr32(IP_BLK_QM, CSR_PPC_FPOOL_BASE_B_ADDR, data);
#endif
}

int apm_qm_alloc_mbox(void)
{
	struct apm_qm_msg32 *mb_slot_ptr;
	struct apm_qm_msg32 *cur_slot_ptr;
	u32 *slot_ptr;
	u8 j;
	u8 i;

	enq_mboxes = (struct apm_qm_mailbox *) qm_enq_mbox_vaddr;
	dq_mboxes = (struct apm_qm_mailbox *) qm_dq_mbox_vaddr;
	fp_mboxes = (struct apm_qm_fp_mailbox *) qm_fp_mbox_vaddr;

	/* assign invalid RType to all slots in all mailboxes */
	for (i = qm_cinfo.start_mboxes;
		i < qm_cinfo.start_mboxes + qm_cinfo.max_mboxes; i++) {
		/* for all mailboxes */
		mb_slot_ptr = (struct apm_qm_msg32 *) &dq_mboxes[i];
		/* for all slots in given mailbox */
		for (j = 0; j < TOTAL_SLOTS_32BYTE_MSG; j++) {
			cur_slot_ptr = mb_slot_ptr + j;
			QM_INVALIDATE_MB(cur_slot_ptr,
					(u8 *) (cur_slot_ptr + 1));
			slot_ptr = (u32 *) cur_slot_ptr;
			slot_ptr[2] = EMPTY_SLOT; /* Initially all slots are empty */
			QM_FLUSH_MB(cur_slot_ptr,
					(u8 *) (cur_slot_ptr + 1));
		}
	}

	/*configure enqeue mailboxes */
	for (i = 0; i < ENQUE_MAIL_BOXES; i++) {
		mb_enq_mbox_ctxt[i].first_ptr = &enq_mboxes[i].mailslots[0];
		mb_enq_mbox_ctxt[i].last_ptr = &enq_mboxes[i].mailslots[TOTAL_SLOTS_32BYTE_MSG-1];
		mb_enq_mbox_ctxt[i].cur_ptr = mb_enq_mbox_ctxt[i].first_ptr;
		mb_enq_mbox_ctxt[i].slot = 0;
		mb_enq_mbox_ctxt[i].last_slot = TOTAL_SLOTS_32BYTE_MSG - 1;
		mb_enq_mbox_ctxt[i].total_slot = TOTAL_SLOTS_32BYTE_MSG;
	}

	/* configure work queue dequeue mailboxes */
	for (i = 0; i < DQ_MAIL_BOXES; i++) {
		mb_dq_mbox_ctxt[i].first_ptr = &dq_mboxes[i].mailslots[0];
		mb_dq_mbox_ctxt[i].last_ptr = &dq_mboxes[i].mailslots[TOTAL_SLOTS_32BYTE_MSG-1];
		mb_dq_mbox_ctxt[i].cur_ptr = mb_dq_mbox_ctxt[i].first_ptr;
		mb_dq_mbox_ctxt[i].slot = 0;
		mb_dq_mbox_ctxt[i].last_slot = TOTAL_SLOTS_32BYTE_MSG - 1;
		mb_dq_mbox_ctxt[i].total_slot = TOTAL_SLOTS_32BYTE_MSG;
	}

	/* configure free queue dequeue mailboxes */
	for (i = 0; i < FP_MAIL_BOXES; i++) {
		mb_fp_mbox_ctxt[i].first_ptr = &fp_mboxes[i].mailslots[0];
		mb_fp_mbox_ctxt[i].last_ptr = &fp_mboxes[i].mailslots[TOTAL_SLOTS_16BYTE_MSG-1];
		mb_fp_mbox_ctxt[i].cur_ptr = mb_fp_mbox_ctxt[i].first_ptr;
		mb_fp_mbox_ctxt[i].slot = 0;
		mb_fp_mbox_ctxt[i].last_slot = TOTAL_SLOTS_16BYTE_MSG - 1;
		mb_fp_mbox_ctxt[i].total_slot = TOTAL_SLOTS_16BYTE_MSG;
	}

	/* initialize mailbox assignments */
	for (i = 0; i < MAX_SLAVES; i++) {
		dq_fp_ip_to_mb[i] = i;
	}

	return 0;
}

int apm_qm_mailbox_rx_unregister(u32 mbidx)
{
	if (mbidx > MAX_MAILBOXS)
		return -1;
	qm_mailbox_fn_table[mbidx] = NULL;
	return 0;
}

int apm_qm_mailbox_rx_register(u32 mbidx, apm_qm_msg_fn_ptr fn_ptr)
{
	if (mbidx > MAX_MAILBOXS || fn_ptr == NULL)
		return -1;
	else if (qm_mailbox_fn_table[mbidx] != NULL)
		return -1;

        qm_mailbox_fn_table[mbidx] = fn_ptr;
        return 0;
}

int apm_qm_msg_rx_unregister(u32 rtype)
{
        if (rtype >= APM_QM_MAX_RTYPE) {
                QM_PRINT("Unsupported rtype number %d\n", rtype);
                return -1;
	} else if (qm_cb_fn_table[rtype] == NULL) {
                QM_PRINT("RType never registered before%d\n", rtype);
                return -1;
	}

        qm_cb_fn_table[rtype] = NULL;

	return 0;
}

int apm_qm_msg_rx_register(u32 rtype, apm_qm_msg_fn_ptr fn_ptr)
{
        if (rtype >= APM_QM_MAX_RTYPE) {
                QM_PRINT("Unsupported rtype number %d\n", rtype);
                return -1;
        } else if (fn_ptr == NULL) {
                QM_PRINT("fn_ptr can't be NULL in QM callback register\n");
                return -1;
        } else if (qm_cb_fn_table[rtype] != NULL) {
                QM_PRINT("rtype [%d] already registered.\n",rtype);
                return -1;
        }

        /* register call back */
        qm_cb_fn_table[rtype] = fn_ptr;

        return 0;
}

int apm_qm_qid_id_init(int sqid, int eqid)
{
	int i;

	free_qid_idx = 0;
	for (i = eqid; i >= sqid; i--) {
		if (free_qid_idx >= sizeof(free_qid)/sizeof(free_qid[0])) {
			QM_PRINT("QID range too large\n");
			goto done_init_qid;
		}
		free_qid[free_qid_idx++] = i;
	}

done_init_qid:
	free_qid_idx--;
	return 0;
}

int apm_qm_qid_get(void)
{
	if (free_qid_idx < 0) {
		QM_PRINT("Out of QID\n");
		return -1;
	}
	return free_qid[free_qid_idx--];
}

int apm_qm_qid_free(int qid)
{
	if (qid < qm_cinfo.start_qid || qid > qm_cinfo.max_qid)
		return -1;
	free_qid[++free_qid_idx] = qid;
	return 0;
}

int apm_qm_create_compl_queue(struct apm_qm_qstate *qstate, int ppcx, int ip,
				int desc_size)
{
	int rc = 0;

	memset(qstate, 0, sizeof(*qstate));
	qstate->src_ip_blk = IP_PPC0 + ppcx;
	qstate->ip_blk = IP_BLK_QM;
	qstate->ppc_id = ppcx;
	qstate->valid = 1;
	qstate->q_size = SIZE_16KB;
	qstate->q_type = P_QUEUE;
	qstate->msg_size = MSG_32B;
	qstate->q_size = desc_size;
	qstate->thr_set = 1;
        if (ppcx == 0 && ip == 0) {
            QM_DBG2("*** QM create Queue PPC0, size = %u\n", desc_size);
            qstate->q_id = GEN_TO_PPC0_COMP_QID;
            qstate->mb_id = GEN_TO_PPC0_COMP_MB;
            qstate->slave_id = PB_SLAVE_ID_PPC;
            qstate->pbn = GEN_TO_PPC0_COMP_MB;
            if (mfspr(SPRN_PIR) == 1) {
                return 0;
            }
        } else if (ppcx == 1 && ip == 1) {
            QM_DBG2("*** QM create Queue PPC1, size = %u\n", desc_size);
            qstate->q_id = GEN_TO_PPC1_COMP_QID;
            qstate->mb_id = GEN_TO_PPC1_COMP_MB;
            qstate->slave_id = PB_SLAVE_ID_PPC;
            qstate->pbn = GEN_TO_PPC1_COMP_MB;
            if (mfspr(SPRN_PIR) == 0) {
                return 0;
            }
        } else {
            qstate->q_id = apm_qm_qid_get();
            qstate->mb_id = apm_qm_get_ib_mb(ppcx, ip);
            qstate->slave_id = PB_SLAVE_ID_PPC;
            qstate->pbn = apm_qm_get_ib_pbn(ppcx, ip, qstate->mb_id);
        }
	if (qstate->q_id < 0) {
		QM_PRINT("Out of QID (%d %d)\n", ppcx, ip);
		return -1;
	}
	if ((rc = apm_qm_qstate_wr(qstate)) != 0) {
		QM_PRINT("Unable to configure completion queue state (%d %d) "
			"error %d\n", ppcx, ip, rc);
		return rc;
	}
	if ((rc = apm_qm_pb_config(qstate->ip_blk, qstate->slave_id,
			qstate->pbn, qstate->q_id, 0, 0)) != 0) {
		QM_PRINT("Unable to configure completion queue PBN (%d %d) "
			"error %d\n", ppcx, ip, rc);
		return rc;
	}
	/* Also reset the slot and num message in PBN */
	apm_qm_pb_clr(qstate->ip_blk, qstate->slave_id, qstate->pbn);

	return 0;
}

/* :CD: move this to platform specific */
int apm_qm_config_compl_queues(void)
{
	int rc = 0;

	memset(comp_qstate, 0, sizeof(comp_qstate));

	/* Configure Ethx to PPC0 completion queue */
	if (qm_cinfo.is_smp || mfspr(SPRN_PIR) == 0) {
		QM_DBG("Creating PPC0 completion queue for ETH0/1\n");
		rc = apm_qm_create_compl_queue(&comp_qstate[0][IP_ETH0],
				0, IP_ETH0, SIZE_16KB);
		if (rc != 0)
			return rc;
		/* Same completion for both Ethernet */
		comp_qstate[0][IP_ETH1] = comp_qstate[0][IP_ETH0];
		comp_qstate[0][IP_ETH2] = comp_qstate[0][IP_ETH0];
		comp_qstate[0][IP_ETH3] = comp_qstate[0][IP_ETH0];
		QM_DBG("PPC0 completion QID %d MB %d\n",
			comp_qstate[0][IP_ETH0].q_id,
			comp_qstate[0][IP_ETH0].mb_id);
	}

#if !defined(BOOTLOADER)
	/* Configure Ethx to PPC1 completion queue */
	if (qm_cinfo.is_smp || mfspr(SPRN_PIR) == 1) {
		QM_DBG("Creating PPC1 completion queue for ETH0/1\n");
		rc = apm_qm_create_compl_queue(&comp_qstate[1][IP_ETH0],
				1, IP_ETH0, SIZE_16KB);
		if (rc != 0)
			return rc;
		/* Same completion for both Ethernet */
		comp_qstate[1][IP_ETH1] = comp_qstate[1][IP_ETH0];
		QM_DBG("PPC1 completion QID %d MB %d\n",
			comp_qstate[1][IP_ETH0].q_id,
			comp_qstate[1][IP_ETH0].mb_id);
	}

	/* Configure SEC to PPC0 completion queue */
	if (qm_cinfo.is_smp || mfspr(SPRN_PIR) == 0) {
		QM_DBG("Creating PPC0 completion queue for SEC\n");
		rc = apm_qm_create_compl_queue(&comp_qstate[0][IP_SEC],
				0, IP_SEC, SIZE_64KB);
		if (rc != 0)
			return rc;
		QM_DBG("PPC0 SEC completion QID %d MB %d\n",
			comp_qstate[0][IP_SEC].q_id,
			comp_qstate[0][IP_SEC].mb_id);
	}

	/* Configure SEC to PPC1 completion queue */
	if (qm_cinfo.is_smp || mfspr(SPRN_PIR) == 1) {
		QM_DBG("Creating PPC1 completion queue for SEC\n");
		rc = apm_qm_create_compl_queue(&comp_qstate[1][IP_SEC],
				1, IP_SEC, SIZE_64KB);
		if (rc != 0)
			return rc;
		QM_DBG("PPC1 SEC completion QID %d MB %d\n",
			comp_qstate[1][IP_SEC].q_id,
			comp_qstate[1][IP_SEC].mb_id);
	}

	/* Configure all others to PPC0 completion queue */
        QM_DBG("Creating PPC0 completion queue for all others\n");
        rc = apm_qm_create_compl_queue(&comp_qstate[0][IP_PPC0],
                        0, IP_PPC0, SIZE_64KB);
        if (rc != 0)
                return rc;
        QM_DBG("PPC0 all others completion QID %d MB %d\n",
                comp_qstate[0][IP_PPC0].q_id,
                comp_qstate[0][IP_PPC0].mb_id);

	/* Configure all others to PPC1 completion queue */
        QM_DBG("Creating PPC1 completion queue for all others\n");
        rc = apm_qm_create_compl_queue(&comp_qstate[1][IP_PPC1],
                        1, IP_PPC1, SIZE_64KB);
        if (rc != 0)
                return rc;
        QM_DBG("PPC1 all others completion QID %d MB %d\n",
                comp_qstate[1][IP_PPC1].q_id,
                comp_qstate[1][IP_PPC1].mb_id);
#endif
	return rc;
}

int apm_qm_queue_clr(int sqid, int eqid)
{
	struct apm_qm_raw_qstate raw_qstate;
	struct apm_qm_pqstate *pq;
	int i;

	memset(&raw_qstate, 0, sizeof(struct apm_qm_raw_qstate));
	pq = (struct apm_qm_pqstate *) &raw_qstate;

	/* Configure domain protection field */
#if !defined(CONFIG_APM862xx)
	pq->queue_dom = 0x0;
	pq->allowed_dom = 0xF;
	pq->not_insert_dom = 0x1;
#endif
	for (i = sqid; i < eqid; i++) {
		apm_qm_raw_qstate_wr(IP_BLK_QM, i, &raw_qstate);
	}
	return 0;
}

int apm_qm_init_queue(int no_of_queues)
{
	u32 i;
	int rc = 0;

	/* QM INIT */
#if !defined(BOOTLOADER)
	q_raw_states = MEMALLOC(QM_MAX_QUEUES * sizeof(struct apm_qm_raw_qstate));
	memset(q_raw_states, 0, QM_MAX_QUEUES * sizeof(struct apm_qm_raw_qstate));
#endif
	queue_states = MEMALLOC(QM_MAX_QUEUES * sizeof(struct apm_qm_qstate));
	memset(queue_states, 0, QM_MAX_QUEUES * sizeof(struct apm_qm_qstate));

	for (i = 0; i < QM_MAX_QUEUES; i++) {
		queue_states[i].q_id = i;
		pbn_valid[i] = 0;
		q_to_mb[i] = 0;
	}
	for (i = 0; i < MAX_MAILBOXS; i++) {
		mb_to_q[i] = 0;
		ib_mbox_used[i] = 0;
		ib_mb_pending_chk[i] = 0;
	}

	/* initialize mailbox assignments */
	for (i = 0; i < IP_MAX; i++) {
		switch(i) {
		case IP_PPC0:
			ip_to_slvid[i] = PB_SLAVE_ID_PPC;
			break;
		case IP_PPC1:
			ip_to_slvid[i] = PB_SLAVE_ID_PPC;
			break;
		case IP_ETH0:
			ip_to_slvid[i] = PB_SLAVE_ID_ETH;
			break;
		case IP_ETH1:
			ip_to_slvid[i] = PB_SLAVE_ID_ETH;
			break;
		case IP_ETH2:
			ip_to_slvid[i] = PB_SLAVE_ID_ETHX;
			break;
		case IP_ETH3:
			ip_to_slvid[i] = PB_SLAVE_ID_ETHX;
			break;
		case IP_DMA:
			ip_to_slvid[i] = PB_SLAVE_ID_DMA;
			break;
		case IP_SEC:
			ip_to_slvid[i] = PB_SLAVE_ID_SEC;
			break;
		case IP_OCMM:
			ip_to_slvid[i] = PB_SLAVE_ID_OCMM;
			break;
		case IP_CLASS:
			ip_to_slvid[i] = PB_SLAVE_ID_CLASS;
			break;
		case IP_IPP:
			ip_to_slvid[i] = PB_SLAVE_ID_IPP;
			break;
		}
	}

#ifndef IOS_INTERWORKING
	/* Clear all HW queue state in case they were not de-activated */
	apm_qm_queue_clr(qm_cinfo.first_qid, qm_cinfo.max_clr_qid);
#endif
	apm_qm_qid_id_init(qm_cinfo.start_qid, qm_cinfo.max_qid);
	apm_qm_pbn_init();
        apm_qm_config_compl_queues();
#ifndef IOS_INTERWORKING
	/* configure static queue descriptors (mainly QM-lite queues) */
	if ((rc = apm_qm_config_qstate(no_of_queues)) != 0) {
		QM_PRINT("Error in config static queue database\n");
		return rc;
	}

	/* Enable QPcore and assign error queue from Core 0 */
	if (qm_cinfo.is_smp || mfspr(SPRN_PIR) == 0)
		if ((rc = apm_qm_init_errq(0)) != 0)
			QM_PRINT("Error in apm_qm_init_errq\n");
#else
        apm_qm_c2c_msg_q_create_queues();
#endif
	return rc;
}

struct apm_qm_qstate *apm_qm_get_compl_queue(int ip_blk, int ppc_id)
{
#if defined(BOOTLOADER)
	ppc_id = 0;
#endif
	switch (ip_blk) {
	case IP_ETH0:
	case IP_ETH1:
	case IP_ETH2:
	case IP_ETH3:
	case IP_SEC:
		return &comp_qstate[ppc_id][ip_blk];
	default:	/* General complete queue for all other IP's */
		return &comp_qstate[ppc_id][IP_PPC0 + ppc_id];
	}
}

u32 apm_qm_get_compl_queue_size(int ip_blk, int ppc_id)
{
	u32 ret = 0 , q_size = 0;
#if defined(BOOTLOADER)
	ppc_id = 0;
#endif
	switch (ip_blk) {
	case IP_ETH0:
	case IP_ETH1:
	case IP_ETH2:
	case IP_ETH3:
	case IP_SEC:
		ret = comp_qstate[ppc_id][ip_blk].q_size;
		break;
	default:	/* General complete queue for all other IP's */
		ret = comp_qstate[ppc_id][IP_PPC0 + ppc_id].q_size;
		break;
	}

	switch (ret) {
	case SIZE_512B:
		q_size = 512;
		break;
	case SIZE_2KB:
		q_size = 2 * 1024;
		break;
	case SIZE_16KB:
		q_size = 16 * 1024;
		break;
	case SIZE_64KB:
		q_size = 64 * 1024;
		break;
	case SIZE_512KB:
		q_size = 512 * 1024;
		break;
	}
	return q_size;
}

int apm_qm_alloc_q(struct apm_qm_qalloc *qalloc)
{
	int rc = 0, is_fp = 0;
	struct apm_qm_qstate *qstate = qalloc->qstates;
	int i, qid;

	/* configure queue state */
	for (i = 0; i < qalloc->q_count; i++) {
                if (qstate->q_id == 0) {
		    qid = apm_qm_qid_get();
                } else {
                    qid = qstate->q_id;
                }
		if (qid < 0) {
			QM_PRINT("Not enough queues available\n");
			return -1;
		}

		qstate->src_ip_blk = qalloc->ip_blk;
		qstate->ip_blk = qalloc->qm_ip_blk;
		qstate->ppc_id = qalloc->ppc_id;
		qstate->valid = 1;
		qstate->q_type = qalloc->q_type;
		qstate->q_start_addr = qalloc->qaddr;
		qstate->q_size = qalloc->qsize;
		qstate->thr_set = qalloc->thr_set;
		qstate->direction = qalloc->direction;
		qstate->q_id = qid;
		qstate->parent_vqid = qalloc->parent_vq;
		if (qalloc->vqen == ENABLE_VQ) {
			qstate->vqen = qalloc->vqen;
			qstate->parent_vqid = qalloc->parent_vq;
		}
#ifdef QM_DEBUG
		if (qstate->vqen)
			QM_PRINT("Parent VQID %d\n", qstate->parent_vqid);
#endif

		/* mailbox assignment */
		if (qalloc->direction) { /* Egress direction */
			qstate->mb_id = apm_qm_get_ob_mb(qalloc->ppc_id,
							qalloc->ip_blk);
			if (qstate->vqen != ENABLE_VQ)
				qstate->slave_id = ip_to_slvid[qalloc->ip_blk];
		} else { /* Ingress direction */
			qstate->mb_id = apm_qm_get_ib_mb(qalloc->ppc_id,
							qalloc->ip_blk);
			if (qstate->vqen != ENABLE_VQ)
				qstate->slave_id = PB_SLAVE_ID_PPC;
		}

		/* Prefetch buffer number assignment */
		if (qalloc->q_type == FREE_POOL) {
			qstate->pbn = apm_qm_get_fp_pbn(qalloc->ppc_id,
						qalloc->ip_blk);
			is_fp = 1;
		} else if (qstate->vqen != ENABLE_VQ) {
			if (qalloc->direction) /* Egress direction */
				qstate->pbn = apm_qm_get_ob_pbn(
						qalloc->ppc_id, qalloc->ip_blk);

			else /* PBN is same as MB */
				qstate->pbn = apm_qm_get_ib_pbn(
						qalloc->ppc_id, qalloc->ip_blk,
						qstate->mb_id);
		}

		/* PPC is enqueuing and wants to check fill status interrupt */
		if (qalloc->direction && qalloc->en_fill_chk) {
			qstate->ppc_notify = qalloc->ppc_id + 1; /* trigger interrupt to this PPC */
			qstate->cfgsaben = 1;
		}

		if ((rc = apm_qm_qstate_wr(qstate)) != 0) {
			QM_PRINT("Unable to write queue state error %d\n", rc);
			break;
		}

		QM_DBG("PQueue configuration\n");
		QM_DBG("    IP blk: %d\n", qstate->ip_blk);
		QM_DBG("  Slave ID: %d\n", qstate->slave_id);
		QM_DBG("       PBN: %d\n", qstate->pbn);
		QM_DBG("  Queue ID: %d\n", qstate->q_id);
		QM_DBG("     MB ID: %d\n", qstate->mb_id);
		QM_DBG("Queue Type: %d\n", qstate->q_type);

		if ((rc = apm_qm_pb_config(qstate->ip_blk, qstate->slave_id,
				  qstate->pbn, qstate->q_id, is_fp, 0)) != 0) {
			QM_PRINT("Unable to write PBN error %d\n", rc);
			break;
		}

		qstate++;
	}

	return rc;
}

int apm_qm_free_q(int qid, int mbid, int ppc_id, int ip_blk, int fp_pbn, int pbn)
{
	apm_qm_qid_free(qid);
	if (mbid >= 0)
		ib_mbox_used[mbid] = 0;
	if (fp_pbn >= 0x20)
		apm_qm_free_fp_pbn(ip_blk, fp_pbn);
	if (pbn >= 0) {
		if (ip_blk == IP_PPC0 || ip_blk == IP_PPC1)
			apm_qm_free_ib_pbn(ppc_id, ip_blk, pbn);
		else
			apm_qm_free_ob_pbn(ppc_id, ip_blk, pbn);
	}
	return 0;
}

int apm_qm_get_vq(u32 ip_blk)
{
	int qid = apm_qm_qid_get();

	if (qid < 0) {
		QM_PRINT("QM virtual queue id not available\n");
		return -1;
	}
	return qid;
}

int apm_qm_alloc_vq(struct apm_qm_qalloc *qalloc, u32 qid)
{
	struct apm_qm_qstate *qstate = qalloc->qstates;
	int rc = 0, j, is_fp = 0;

	if (qid > qm_cinfo.max_qid || qalloc->q_count != 1) {
		QM_PRINT("QM virtual queue not available\n");
		return -1;
	} else if (qalloc->q_type != V_QUEUE) {
		QM_PRINT("Invalid parameter for VQ config\n");
		return -1;
	}

	/* configure queue state */
	qstate->src_ip_blk = qalloc->ip_blk;
	qstate->ip_blk = qalloc->qm_ip_blk;
	qstate->ppc_id = qalloc->ppc_id;
	qstate->valid = 1;
	qstate->q_type = qalloc->q_type;
	qstate->q_start_addr = qalloc->qaddr;
	qstate->q_size = qalloc->qsize;
	qstate->thr_set = qalloc->thr_set;
	qstate->direction = qalloc->direction;
	qstate->q_id = qid;
	qstate->parent_vqid = qalloc->parent_vq;
	qstate->vqen = qalloc->vqen;

	memcpy(qstate->pq_sel, qalloc->pq_sel, sizeof(qstate->pq_sel));
	memcpy(qstate->q_sel_arb, qalloc->q_sel_arb,
		sizeof(qstate->q_sel_arb));
	memcpy(qstate->shape_rate, qalloc->shape_rate,
		sizeof(qstate->shape_rate));

	/* mailbox assignment */
	if (qalloc->direction) { /* Egress direction */
		qstate->mb_id = apm_qm_get_ob_mb(qalloc->ppc_id,
						qalloc->ip_blk);
		qstate->slave_id = ip_to_slvid[qalloc->ip_blk];
	} else { /* Ingress direction */
		qstate->mb_id = apm_qm_get_ib_mb(qalloc->ppc_id,
						qalloc->ip_blk);
		qstate->slave_id = PB_SLAVE_ID_PPC;
	}

	/* Prefetch buffer number assignment */
	if (qalloc->q_type == FREE_POOL) {
		qstate->pbn = apm_qm_get_fp_pbn(qalloc->ppc_id,
					qalloc->ip_blk);
		is_fp = 1;
	} else {
		if (qalloc->direction) /* Egress direction */
			qstate->pbn = apm_qm_get_ob_pbn(
					qalloc->ppc_id, qalloc->ip_blk);
		else
			qstate->pbn = apm_qm_get_ib_pbn(
					qalloc->ppc_id, qalloc->ip_blk,
					qstate->mb_id);
	}

	if ((rc = apm_qm_vqstate_wr(qstate)) != 0) {
		QM_PRINT("Error in queue configuration\n");
		return rc;
	}

	QM_DBG("Virtual Queue configuration\n");
	QM_DBG("    IP blk: %d\n", qstate->ip_blk);
	QM_DBG("  Slave ID: %d\n", qstate->slave_id);
	QM_DBG("       PBN: %d\n", qstate->pbn);
	QM_DBG("  Queue ID: %d\n", qstate->q_id);
	QM_DBG("     MB ID: %d\n", qstate->mb_id);
	QM_DBG("Queue Type: %d\n", qstate->q_type);

	for (j = 0; j < 8; j++)
		QM_DBG("PQ_SEL[%d] %d Q_SEL_ARB[%d] %d RATE[%d] %d\n",
			 j, qstate->pq_sel[j], j, qstate->q_sel_arb[j],
			 j, qstate->shape_rate[j]);

	if ((rc = apm_qm_pb_config(qstate->ip_blk, qstate->slave_id,
				  qstate->pbn, qstate->q_id, is_fp, 1)) != 0) {
		QM_PRINT("Unable to configure virtual queue PBN error %d\n",
			rc);
		return rc;
	}
	return rc;
}

inline int apm_qm_pull_comp_msg(u32 mb_id)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	struct apm_qm_msg16 *msg16;
	u32 *slot_ptr;
	u32 uinfo;
	int NV;

	slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
	QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

	/* Check signature to determine if slot has a valid message */
	if (slot_ptr[2] == EMPTY_SLOT)
		return -1;

	msg16 = (struct apm_qm_msg16 *) slot_ptr;
	NV = msg16->NV;
	uinfo = msg16->UserInfo;

	QM_DBG2("Completion QM msg mailbox %d slot 0x%p\n",
		mb_id, mb_dq_mbox_ctxt[mb_id].cur_ptr);

	/* Mark slot empty */
	slot_ptr[2] = EMPTY_SLOT;
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	/* Update queue statistic */
#if defined(DQM_DBG)
	++queue_states[mb_to_q[mb_id]].msg_stat;
#endif
	/* Move pointer to next slot. */
	if (mb_dq_mbox_ctxt[mb_id].cur_ptr == mb_dq_mbox_ctxt[mb_id].last_ptr)
		mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
	else
		mb_dq_mbox_ctxt[mb_id].cur_ptr++;

	if (!NV) {
		/* Tell QM to move to next slot */
		out_be32((u32 *) QM_B_ADDR_DEC, QM_DEC_MSG_VAL(mb_id, 1));
	} else {
		/* For 64B message, clean the 2nd half slot */
		slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
		QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);
		slot_ptr[2] = EMPTY_SLOT;
		QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

		/* Move pointer to next slot */
		if (mb_dq_mbox_ctxt[mb_id].cur_ptr ==
					mb_dq_mbox_ctxt[mb_id].last_ptr)
			mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
		else
			mb_dq_mbox_ctxt[mb_id].cur_ptr++;

		/* Tell QM to move to next slot */
		out_be32((u32 *) QM_B_ADDR_DEC, QM_DEC_MSG_VAL(mb_id, 2));
	}

	return uinfo;
}

#define APM_QM_PENDING_COMPL		4
inline int apm_qm_pull_comp_msg2(u32 mb_id)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	struct apm_qm_msg16 *msg16;
	u32 *slot_ptr;
	u32 uinfo;
	int NV;

	slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
	QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

	/* Check signature to determine if slot has a valid message */
	if (slot_ptr[2] == EMPTY_SLOT)
		return -1;

	msg16 = (struct apm_qm_msg16 *) slot_ptr;
	NV = msg16->NV;
	uinfo = msg16->UserInfo;

	QM_DBG2("Completion QM msg mailbox %d slot 0x%p\n",
		mb_id, mb_dq_mbox_ctxt[mb_id].cur_ptr);

	/* Mark slot empty */
	slot_ptr[2] = EMPTY_SLOT;
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	/* Update queue statistic */
#if defined(DQM_DBG)
	++queue_states[mb_to_q[mb_id]].msg_stat;
#endif
	/* Move pointer to next slot */
	if (mb_dq_mbox_ctxt[mb_id].cur_ptr == mb_dq_mbox_ctxt[mb_id].last_ptr)
		mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
	else
		mb_dq_mbox_ctxt[mb_id].cur_ptr++;

	if (!NV) {
		/* Tell QM to move to next slot */
		queue_states[mb_to_q[mb_id]].pending_compl++;
	} else {
		/* For 64B message, clean the 2nd half slot */
		slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
		QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);
		slot_ptr[2] = EMPTY_SLOT;
		QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

		/* Move pointer to next slot */
		if (mb_dq_mbox_ctxt[mb_id].cur_ptr ==
					mb_dq_mbox_ctxt[mb_id].last_ptr)
			mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
		else
			mb_dq_mbox_ctxt[mb_id].cur_ptr++;

		queue_states[mb_to_q[mb_id]].pending_compl += 2;
	}
	if (queue_states[mb_to_q[mb_id]].pending_compl >=
						APM_QM_PENDING_COMPL) {
		/* Tell QM to move to next slot */
		out_be32((u32 *) QM_B_ADDR_DEC,
			QM_DEC_MSG_VAL(mb_id, APM_QM_PENDING_COMPL));
		queue_states[mb_to_q[mb_id]].pending_compl -=
						APM_QM_PENDING_COMPL;
	}
	return uinfo;
}

int apm_qm_pull_comp_flush(u32 mb_id)
{
	struct apm_qm_qstate *qstate = &queue_states[mb_to_q[mb_id]];

	while (qstate->pending_compl) {
		if (qstate->pending_compl < APM_QM_PENDING_COMPL) {
			*(u32 *)QM_B_ADDR_DEC =
				QM_DEC_MSG_VAL(mb_id, qstate->pending_compl);
			qstate->pending_compl = 0;
			return 0;
		} else {
			*(u32 *)QM_B_ADDR_DEC =
				QM_DEC_MSG_VAL(mb_id, APM_QM_PENDING_COMPL);
			qstate->pending_compl -= APM_QM_PENDING_COMPL;
		}
	}
	return 0;
}

int apm_qm_pull_msg(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	u8 mb_id = msg_desc->mb_id;
	volatile u32 *slot_ptr;
	u32 *temp;

	slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
	QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

	/* Check if slot has a message */
	if (slot_ptr[2] == EMPTY_SLOT)
		return -1;

	/* Copy out the message */
	temp = (u32 *) msg_desc->msg;
	if (msg_desc->is_msg16) {
		memcpy(temp, (const void*)slot_ptr, 16);
	} else {
		memcpy(temp, (const void*)slot_ptr, 32);
	}

	QM_DBG2("Pull QM msg mailbox %d slot 0x%p\n",
		mb_id, mb_dq_mbox_ctxt[mb_id].cur_ptr);

	/* Move pointer to next slot */
	if (mb_dq_mbox_ctxt[mb_id].cur_ptr == mb_dq_mbox_ctxt[mb_id].last_ptr)
		mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
	else
		mb_dq_mbox_ctxt[mb_id].cur_ptr++;

	/* Mark slot empty */
	slot_ptr[2] = EMPTY_SLOT;
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	/* Update queue statistic */
#if defined(DQM_DBG)
	++queue_states[mb_to_q[mb_id]].msg_stat;
#endif
	/* Do not remove this statement as this variable is cached in L2 and
           more efficient than the NV test in next statement. */
	if (msg_desc->is_msg16) {
		/* Tell QM to move to next slot */
		*(u32 *) QM_B_ADDR_DEC = QM_DEC_MSG_VAL(mb_id, 1);
		return 0;
	}

	if (!((struct apm_qm_msg16 *) msg_desc->msg)->NV) {
		/* Tell QM to move to next slot */
		*(u32 *) QM_B_ADDR_DEC = QM_DEC_MSG_VAL(mb_id, 1);
	} else {
		/* For 64B message, read out 2nd half slot */
		slot_ptr = (u32 *) mb_dq_mbox_ctxt[mb_id].cur_ptr;
		QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

		temp += 8;
		memcpy(temp, (const void*)slot_ptr, 32);

		/* Move pointer to next slot */
		if (mb_dq_mbox_ctxt[mb_id].cur_ptr ==
					mb_dq_mbox_ctxt[mb_id].last_ptr)
			mb_dq_mbox_ctxt[mb_id].cur_ptr =
					mb_dq_mbox_ctxt[mb_id].first_ptr;
		else
			mb_dq_mbox_ctxt[mb_id].cur_ptr++;

		/* Mark 2nd slot empty */
		slot_ptr[2] = EMPTY_SLOT;
		QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

		/* Tell QM to move to next slot */
		*(u32 *) QM_B_ADDR_DEC = QM_DEC_MSG_VAL(mb_id, 2);
	}
	return 0;
}

#if defined(QM_ALTERNATE_ENQUEUE)
int apm_qm_enable_alt_dq(int pbn)
{
	u32 val;
	val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_PPC, pbn);
	val &= ~(1 << 14);
	apm_qm_pb_set(IP_BLK_QM, PB_SLAVE_ID_PPC, pbn, val);
	return 0;
}

int apm_qm_pull_msg_alt(struct apm_qm_msg_desc *desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	u8 qid = desc->qid;
	struct apm_qm_qstate *qstate = &queue_states[qid];
	u32 *tailptr = (u32 *) qstate->tailptr;
	u32 *msg = desc->msg;
	struct apm_qm_msg16 *msg16 = (struct apm_qm_msg16 *) msg;

	/* Pull the message out */
	if (tailptr[2] == EMPTY_SLOT)
		return -1;
	memcpy(msg, tailptr, 32);

	QM_DBG2("Pull QM msg queue %d pointer 0x%p %dB\n",
		qid, tailptr, msg16->NV ? 64 : 32);

	/* Adjust tail pointer.
           This version is more efficient than have else statement. */
	qstate->tailptr += 32;
	if (qstate->tailptr == qstate->endptr)
		qstate->tailptr = qstate->startptr;

	/* Update queue statistic */
#if defined(DQM_DBG)
	++qstate->msg_stat;
#endif
	tailptr[2] = EMPTY_SLOT;
	if (!msg16->NV) {
		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = -1;
	} else {
		tailptr = (u32 *) qstate->tailptr;
		memcpy(msg + 8, tailptr, 32);
		tailptr[2] = EMPTY_SLOT;

		/* Adjust tail pointer.
                   This version is more efficient than have else statement. */
		qstate->tailptr += 32;
		if (qstate->tailptr == qstate->endptr)
			qstate->tailptr = qstate->startptr;

		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = -2;
	}
	return 0;
}
#endif

int apm_qml_push_msg(struct apm_qm_msg_desc *msg_desc)
{
	return 0;
}

#if defined(QM_NON_ALTERNATE_ENQUEUE_FP)
int apm_qm_fp_dealloc_buf_non_alt(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	volatile u32 *slot_ptr;
	u32 *temp;
	u32 mb_desc = 0;
	volatile struct apm_qm_msg32 *mb_slot_ptr;
	u8 mb_id = q_to_mb[msg_desc->qid];

	temp = (u32 *) msg_desc->msg;

	mb_slot_ptr = (struct apm_qm_msg32 *) &enq_mboxes[mb_id];
	mb_slot_ptr += mb_enq_mbox_ctxt[mb_id].slot;
	slot_ptr = (u32 *) mb_slot_ptr;

#ifdef CONFIG_MB_CHECK_TX_MSG
	if (mb_enq_mbox_ctxt[mb_id].slot == 0) {
		static u32 enq_csr_lookup[16] = {
			CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR,
			CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR,
			CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR,
			CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR };
		static u32 st_byte_lookup[16] = {
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8 };
		/* check mailbox status after enq */
		u32 val, status_byte;
		/* wait for QM to be done reading the message from mailbox */
		while (1) {
			apm_qm_rd32(IP_BLK_QM, enq_csr_lookup[mb_id], &val);
			status_byte = val >> st_byte_lookup[mb_id];
			if (!(status_byte & (0x1 << 7)))
				break;
		}
	}
#endif
	/* write message in the current slot */
	memcpy((void *)slot_ptr, temp, 16);

	QM_FLUSH_MB(slot_ptr, (u8 *) slot_ptr + 16);

	QM_DBG2("Dealloc QM msg queue %d mailbox %d slot %d\n",
		msg_desc->qid, mb_id, mb_enq_mbox_ctxt[mb_id].slot);

        /* prepare data to write to qm base address */
	mb_desc = (mb_id << APM_QM_MBID_SHIFT) |
			(mb_enq_mbox_ctxt[mb_id].slot << APM_QM_SLOTID_SHIFT) |
								 SIZE_16_MSG;
	/* Move pointer to next slot.
           This version is more efficient than have else statement. */
	mb_enq_mbox_ctxt[mb_id].slot++;
	if (mb_enq_mbox_ctxt[mb_id].slot == mb_enq_mbox_ctxt[mb_id].total_slot)
		mb_enq_mbox_ctxt[mb_id].slot = 0;

	/* Tell QM */
	out_be32((u32 *) QM_B_ADDR_QID(msg_desc->qid), mb_desc);

	return 0;
}
#endif

#ifdef QM_ALTERNATE_ENQUEUE
int apm_qm_push_msg(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	struct apm_qm_msg16 *msg16 = (struct apm_qm_msg16 *) msg_desc->msg;
	u8 qid = msg_desc->qid;
	u8 *tailptr = queue_states[qid].tailptr;
	struct apm_qm_qstate *qstate = &queue_states[qid];
	u32 *temp;

	msg16->HC = 1;

	/* Write message at tail pointer of the queue descriptor */
	temp = (u32 *) msg_desc->msg;
        QM_DBG2("qid = %u, tailptr = 0x%p, temp = 0x%p", qid, tailptr, temp);
	memcpy(tailptr, temp, 32);
	QM_FLUSH_MB(tailptr, tailptr + 32);

	QM_DBG2("Push QM msg queue %d pointer 0x%p %dB\n",
		qid, tailptr, msg16->NV ? 64 : 32);

	/* Adjust tail pointer.
           This version is more efficient than have else statement. */
	qstate->tailptr += 32;
	if (qstate->tailptr == qstate->endptr)
		qstate->tailptr = qstate->startptr;

	/* Update queue statistic */
#if defined(DQM_DBG)
	++qstate->msg_stat;
#endif

	if (!msg16->NV) {
		/* Tell QM we read out 32B */
		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = 1;
	} else {
		/* For 64B message, write out remaining */
		tailptr = qstate->tailptr;

		/* Write remaining message at tail pointer */
		temp += 8;
		memcpy(tailptr, temp, 32);
		QM_FLUSH_MB(tailptr, tailptr + 32);

		/* Adjust tail pointer.
		   This version is more efficient than have else statement. */
		qstate->tailptr += 32;
		if (qstate->tailptr == qstate->endptr)
			qstate->tailptr = qstate->startptr;

		/* Tell QM we wrote 64 byte message */
		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = 2;
	}
	return 0;
}

int apm_qm_fp_dealloc_buf(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	u8 qid = msg_desc->qid;
	void *tailptr = queue_states[qid].tailptr;
	struct apm_qm_qstate *qstate = &queue_states[qid];
	struct apm_qm_msg16 *msg16 = (struct apm_qm_msg16 *) msg_desc->msg;

	msg16->HC = 1;

	/* Write message at tail pointer. */
	memcpy(tailptr, msg16, 16);
	QM_FLUSH_MB(tailptr, (u8 *) tailptr + 16);

	QM_DBG2("Dealloc QM msg queue %d pointer 0x%p %dB\n",
		qid, tailptr, msg16->NV ? 64 : 32);

	/* Adjust tail pointer.
	   This version is more efficient than have else statement. */
	qstate->tailptr += 16;
	if (qstate->tailptr == qstate->endptr)
		qstate->tailptr = qstate->startptr;

	/* Tell QM we wrote 32B */
#ifdef APM_QM_FP_DEALLOC_CACHE
	/*
	 * This section causes a cache hit and slow down the
	 * mb enq, so need to find a better mechanism
	 */
	#define APM_QM_FP_DEALLOC_CACHE		6
	if (++qstate->pending_dealloc >= APM_QM_FP_DEALLOC_CACHE) {
		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = APM_QM_FP_DEALLOC_CACHE;
		qstate->pending_dealloc -= APM_QM_FP_DEALLOC_CACHE;
	}
#else
	*(u32 *)QM_ENQ_B_ADDR_QID(qid) = 1;
#endif
	return 0;
}

int apm_qm_fp_dealloc_flush(int qid)
{
	struct apm_qm_qstate *qstate = &queue_states[qid];

	if (qstate->pending_dealloc) {
		*(u32 *)QM_ENQ_B_ADDR_QID(qid) = qstate->pending_dealloc;
		qstate->pending_dealloc = 0;
		asm volatile("msync");
	}
	return 0;
}

#else
int apm_qm_push_msg(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	volatile u32 *slot_ptr;
	u32 *temp;
	u32 mb_desc, cur_slot, init_slot;
	u8 mb_id = q_to_mb[msg_desc->qid];
#if defined (CONFIG_MB_CHECK_TX_MSG)
	int wait_required;
#endif
	volatile struct apm_qm_msg32 *mb_slot_ptr;
	struct apm_qm_msg32 *msg = (struct apm_qm_msg32 *) msg_desc->msg;

	temp = (u32 *) msg_desc->msg;
	cur_slot = mb_enq_mbox_ctxt[mb_id].slot;
	QM_DBG2("Push QM msg queue %d mailbox %d slot %d\n",
		msg_desc->qid, mb_id, cur_slot);

#ifdef CONFIG_MB_CHECK_TX_MSG
	if (msg->msg16.NV &&
	    cur_slot == mb_enq_mbox_ctxt[mb_id].last_slot)
		wait_required = 1;
	else
		wait_required = 0;

	if (cur_slot == 0 || wait_required) {
		static u32 enq_csr_lookup[16] = {
			CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR,
			CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR,
			CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR,
			CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR };
		static u32 st_byte_lookup[16] = {
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8 };
		/* check mailbox status after enq */
		u32 val, status_byte;
		while (1) {
			apm_qm_rd32(IP_BLK_QM, enq_csr_lookup[mb_id], &val);
			status_byte = val >> st_byte_lookup[mb_id];
			if (cur_slot == 0) {
				if (!((status_byte >> (7 - 7)) & 0x1))
					break;
			} else {
				if (!((status_byte >> (7 - 6)) & 0x1))
					break;
			}
		}
	}
#endif

	init_slot = cur_slot;
	mb_slot_ptr = (struct apm_qm_msg32 *) &enq_mboxes[mb_id];
	mb_slot_ptr += cur_slot;
	slot_ptr = (u32 *) mb_slot_ptr;

	/* write message in the current slot */
	slot_ptr[0] = temp[0];
	slot_ptr[1] = temp[1];
	slot_ptr[2] = temp[2];
	slot_ptr[3] = temp[3];
	slot_ptr[4] = temp[4];
	slot_ptr[5] = temp[5];
	slot_ptr[6] = temp[6];
	slot_ptr[7] = temp[7];
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

	/* adjust current slot.
	   This version is more efficient than have else statement. */
	mb_enq_mbox_ctxt[mb_id].slot++;
	if (mb_enq_mbox_ctxt[mb_id].slot == mb_enq_mbox_ctxt[mb_id].total_slot)
		mb_enq_mbox_ctxt[mb_id].slot = 0;

	/* prepare qm base address to write to */
	if (!msg->msg16.NV) {
		/* prepare data to write to qm base address */
		mb_desc = (mb_id << APM_QM_MBID_SHIFT) |
				(init_slot << APM_QM_SLOTID_SHIFT) |
				SIZE_32_MSG;
	} else {
		cur_slot = mb_enq_mbox_ctxt[mb_id].slot;
		mb_slot_ptr = (struct apm_qm_msg32 *) &enq_mboxes[mb_id];
		mb_slot_ptr += cur_slot;
		slot_ptr = (u32 *) mb_slot_ptr;

		/* adjust current slot .
		   This version is more efficient than have else statement. */
		mb_enq_mbox_ctxt[mb_id].slot++;
		if (mb_enq_mbox_ctxt[mb_id].slot ==
					mb_enq_mbox_ctxt[mb_id].total_slot)
			mb_enq_mbox_ctxt[mb_id].slot = 0;

		/* write remaining 32 byte message in the next slot */
		slot_ptr[0] = temp[8];
		slot_ptr[1] = temp[9];
		slot_ptr[2] = temp[10];
		slot_ptr[3] = temp[11];
		slot_ptr[4] = temp[12];
		slot_ptr[5] = temp[13];
		slot_ptr[6] = temp[14];
		slot_ptr[7] = temp[15];
		QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 32);

		/* prepare data to write to qm base address */
		mb_desc = (mb_id << APM_QM_MBID_SHIFT) |
				(init_slot << APM_QM_SLOTID_SHIFT) |
				SIZE_64_MSG;
	}

	/* Update queue statistic */
#if defined(DQM_DBG)
	++queue_states[msg_desc->qid].msg_stat;
#endif
	/* Tell QM */
	out_be32((u32 *) QM_B_ADDR_QID(msg_desc->qid), mb_desc);
	return 0;
}

int apm_qm_fp_dealloc_buf(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	volatile u32 *slot_ptr;
	u32 *temp;
	u32 mb_desc = 0;
	volatile struct apm_qm_msg32 *mb_slot_ptr;
	u8 mb_id = q_to_mb[msg_desc->qid];

	temp = (u32 *) msg_desc->msg;

	mb_slot_ptr = (struct apm_qm_msg32 *) &enq_mboxes[mb_id];
	mb_slot_ptr += mb_enq_mbox_ctxt[mb_id].slot;
	slot_ptr = (u32 *) mb_slot_ptr;

#ifdef CONFIG_MB_CHECK_TX_MSG
	if (mb_enq_mbox_ctxt[mb_id].slot == 0) {
		static u32 enq_csr_lookup[16] = {
			CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR, CSR_ENQ_STATUS_0_ADDR,
			CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR, CSR_ENQ_STATUS_1_ADDR,
			CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR, CSR_ENQ_STATUS_2_ADDR,
			CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR, CSR_ENQ_STATUS_3_ADDR };
		static u32 st_byte_lookup[16] = {
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8,
			(3 - 0) * 8, (3 - 1) * 8, (3 - 2) * 8, (3 - 3) * 8 };
		/* check mailbox status after enq */
		u32 val, status_byte;
		/* wait for QM to be done reading the message from mailbox */
		while (1) {
			apm_qm_rd32(IP_BLK_QM, enq_csr_lookup[mb_id], &val);
			status_byte = val >> st_byte_lookup[mb_id];
			if (!(status_byte & (0x1 << 7)))
				break;
		}
	}
#endif
	/* write message in the current slot */
	slot_ptr[0] = temp[0];
	slot_ptr[1] = temp[1];
	slot_ptr[2] = temp[2];
	slot_ptr[3] = temp[3];
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	QM_DBG2("Dealloc QM msg queue %d mailbox %d slot %d\n",
		msg_desc->qid, mb_id, mb_enq_mbox_ctxt[mb_id].slot);

        /* prepare data to write to qm base address */
	mb_desc = (mb_id << APM_QM_MBID_SHIFT) |
			(mb_enq_mbox_ctxt[mb_id].slot << APM_QM_SLOTID_SHIFT) |
								 SIZE_16_MSG;
	/* Move pointer to next slot.
	   This version is more efficient than have else statement. */
	mb_enq_mbox_ctxt[mb_id].slot++;
	if (mb_enq_mbox_ctxt[mb_id].slot == mb_enq_mbox_ctxt[mb_id].total_slot)
		mb_enq_mbox_ctxt[mb_id].slot = 0;

	/* Tell QM */
	out_be32((u32 *) QM_B_ADDR_QID(msg_desc->qid), mb_desc);

	return 0;
}

int apm_qm_fp_dealloc_flush(int qid)
{
	return 0;
}
#endif

int apm_qml_fp_dealloc_buf(struct apm_qm_msg_desc *msg_desc)
{
	volatile u32 *slot_ptr;
	u32 *temp;
	u32 mb_desc = 0;
	u8 mb_id = apm_qm_get_ib_mb(0, IP_MAX);	/* IP_MAX for default */
	volatile struct apm_qm_msg32 *mb_slot_ptr;

	/* Check if QML hardware available */
	if (qm_cinfo.is_noqml)
		return -1;

	temp = (u32 *) msg_desc->msg;

	mb_slot_ptr = (struct apm_qm_msg32 *) &enq_mboxes[mb_id];
	mb_slot_ptr += mb_enq_mbox_ctxt[mb_id].slot;
	slot_ptr = (u32 *) mb_slot_ptr;

	/* write message in the current slot */
	*slot_ptr++ = *temp++; *slot_ptr++ = *temp++;
	*slot_ptr++ = *temp++; *slot_ptr++ = *temp++;

	/* prepare data to write to qm base address */
	mb_desc = (mb_id << APM_QM_MBID_SHIFT) |
			(mb_enq_mbox_ctxt[mb_id].slot << APM_QM_SLOTID_SHIFT) |
								 SIZE_16_MSG;
	mb_enq_mbox_ctxt[mb_id].slot++;
	if (mb_enq_mbox_ctxt[mb_id].slot == mb_enq_mbox_ctxt[mb_id].total_slot)
		mb_enq_mbox_ctxt[mb_id].slot = 0;

	*(u32 *)QML_B_ADDR_QID(msg_desc->qid) = mb_desc;

	return 0;
}

int apm_qm_fp_alloc_buf(struct apm_qm_msg_desc *msg_desc)
{
	/* NOTE: This function had been optimized. If you change anything,
                 re-test via IPv4 forwarding with 64B message */
	u8 mb_id = msg_desc->mb_id;
	volatile u32 *slot_ptr;
	u32 *temp;
	u8 pbn = mb_id + PPC_FP_MB_PBN_OFFSET;

	slot_ptr = (u32 *) mb_fp_mbox_ctxt[mb_id].cur_ptr;
	QM_INVALIDATE_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	/* Make sure there is a message to read */
	if (slot_ptr[2] == EMPTY_SLOT) {
		/* message slot is empty */
		QM_DBG2("No msg to dequeue from free pool queue %d\n",
			msg_desc->qid);
		return -1;
	}

	/* read message from the current slot */
	temp = (u32 *) msg_desc->msg;
	memcpy(temp, (const void *)slot_ptr, 16);

	/* Move to next slot */
	if (mb_fp_mbox_ctxt[msg_desc->mb_id].cur_ptr ==
				mb_fp_mbox_ctxt[msg_desc->mb_id].last_ptr)
		mb_fp_mbox_ctxt[msg_desc->mb_id].cur_ptr =
				mb_fp_mbox_ctxt[msg_desc->mb_id].first_ptr;
	else
		mb_fp_mbox_ctxt[msg_desc->mb_id].cur_ptr++;

	/* Clear slot marker */
	slot_ptr[2] = EMPTY_SLOT;
	QM_FLUSH_MB((void *) slot_ptr, (u8 *) slot_ptr + 16);

	/* Decrement number of messages in this slave id and PBN */
	*(u32 *)QM_B_ADDR_DEC = QM_DEC_MSG_VAL(pbn, 1);

	return 0;
}

int apm_qml_pull_msg(struct apm_qm_msg32 *msg)
{
        u32 cnt = 0, val = 0;
        u32 *temp;

	/* Check if QML hardware available */
	if (qm_cinfo.is_noqml)
		return -1;

        val = WQ_BID_SET(val, apm_qm_get_ib_pbn(0, IP_MAX, 0));
        val = WQ_MSG_SIZE_SET(val, WQ_SZ_32B);
        val = WQ_FETCH_SET(val, 1);
	/* fetch message now */
        apm_qm_wr32(IP_BLK_IPP_QML, MPA_QMI_WQ_CTL_ADDR, val);

        /* check for message available */
        while (1) {
                apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_CTL_ADDR, &val);
                if (!WQ_FETCH_RD(val))
                        break;
                if (cnt++ > MAX_DELAY_CNT) {
                        return -1;
                }
        }

        /* message is available, read it */
        temp = (u32 *) msg;

        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG0_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG1_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG2_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG3_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG4_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG5_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG6_ADDR, temp);
	temp++;
        apm_qm_rd32(IP_BLK_IPP_QML, MPA_QMI_WQ_MSG7_ADDR, temp);

        return 0;
}

/*
 * Parse the exact for the Error Message received on Error Queue
 *
 */
void apm_qm_parse_error(struct apm_qm_msg_desc *err_msg_desc)
{
        struct apm_qm_msg32 *msg = (struct apm_qm_msg32 *) err_msg_desc->msg;
	struct apm_qm_msg16 *msg16 = &msg->msg16;
	u8 err = 0, cmd_acr_enq_err = 0, cmd_acr_enq_qid = 0, deq_slot_num = 0;
        u16 deq_slvid_pbn = 0;

        QM_ERR_CHK("QM Error LErr[%d] for Qid[%d] \n",
                   msg16->LErr, err_msg_desc->qid);

        switch(msg16->LErr) {
        case QM_MSG_SIZE_ERR:
                QM_ERR_CHK("Msg Size Error for Enqueue on Queue %d \n",
                           err_msg_desc->qid);
                break;
        case QM_HOP_COUNT_ERR:
                QM_ERR_CHK("Hop count error. QM received a message with"
                           "a hop count of 3 for Queue %d \n",
                           err_msg_desc->qid);
                break;
        case QM_VQ_ENQ_ERR:
                QM_ERR_CHK("Enqueue on Virtual Queue %d \n",
                           err_msg_desc->qid);
                break;
        case QM_DISABLEDQ_ENQ_ERR:
                QM_ERR_CHK("Enqueue on disabled Queue %d \n",
                           err_msg_desc->qid);
                break;
        case QM_Q_OVERFLOW_ERR:
                QM_ERR_CHK("Queue %d overflow, message send to"
                           "Error Queue \n",
                           err_msg_desc->qid);
                break;
        case QM_ENQUEUE_ERR:
                cmd_acr_enq_qid = (msg16->UserInfo & QM_QID_MASK);
                cmd_acr_enq_err = ((msg16->UserInfo >> 22) & 0X2);
                err = ((msg16->UserInfo >> 29) & 0X7);
                QM_ERR_CHK("Enqueue Erro on Qid[%d]\n", cmd_acr_enq_qid);
                switch(err) {
                case QM_AXI_READ_ERR:
                        QM_ERR_CHK("AXI error on read from PPC "
                                   "mailbox: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                        break;
                case QM_AXI_ENQ_VQ_ERR:
                        QM_ERR_CHK("Alternate Enqueue Command to a"
                                   "Virtual Queue: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                        break;
                case QM_AXI_ENQ_DQ_ERR:
                        QM_ERR_CHK("Alternate Enqueue Command to a"
                                   "Disabled Queue: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                        break;
                case QM_AXI_ENQ_OVERFLOWQ_ERR:
                        QM_ERR_CHK("Alternate Enqueue Command "
                                   "overfills Queue: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                        break;

                }
                if (cmd_acr_enq_err == QM_AXI_SLAVE_ERR)
                        QM_ERR_CHK("AXI slave error on PPC mailbox"
                                   "read: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                else if (cmd_acr_enq_err == QM_AXI_SLAVE_ERR)
                        QM_ERR_CHK("AXI decode error on PPC mailbox"
                                       "read: Qid[%d]\n",
                                   cmd_acr_enq_qid);
                break;
        case QM_DEQUEUE_ERR:
                err = ((msg16->UserInfo >> 29) & 0X7);
                deq_slvid_pbn = ((msg16->UserInfo >> 3) & 0XFF3);
                deq_slot_num = (msg16->UserInfo & 0x7);
                QM_ERR_CHK("Dequeue Error for deq_slot_num :%d and \n"
                           "deq_slvid_pbn: %d",
                           deq_slot_num, deq_slvid_pbn);
                if (err ==  QM_CHILD_VQ_ERR)
                        QM_ERR_CHK("VQ was assigned as a child of another"
                                   "VQ, deq_slot_num :%d and \n"
                                   "deq_slvid_pbn: %d",
                                   deq_slot_num, deq_slvid_pbn);
                else if (err == QM_DEQUEUE_DQ)
                        QM_ERR_CHK("A dequeue was requested from a"
                                   "disabled PQ, deq_slot_num :%d and \n"
                                   "deq_slvid_pbn: %d",
                                   deq_slot_num, deq_slvid_pbn);
                break;
        default:
                QM_ERR_CHK("Unknown Error \n");
                break;
        }
        return;
}

int apm_qm_alt_enqueue_enable(void)
{
#if defined(QM_ALTERNATE_ENQUEUE)
	return 1;
#else
	return 0;
#endif
}

int apm_qm_irq_err(void)
{
	struct apm_qm_raw_qstate qinfo;
	u32 status;
	u32 pbm_err;
	u32 msgrd_err;
	int i;

	apm_qm_rd32(IP_BLK_QM, QM_INTERRUPT_ADDR, &status);
	QM_ERR_CHK("QM error interrupt status 0x%08X\n", status);
	apm_qm_rd32(IP_BLK_QM, CSR_PBM_ERRINF_ADDR, &pbm_err);
	QM_ERR_CHK("QM CSR PBM ERRINF (0x%X) value 0x%08X\n",
		CSR_PBM_ERRINF_ADDR, pbm_err);
	apm_qm_rd32(IP_BLK_QM, CSR_MSGRD_ERRINF_ADDR, &msgrd_err);
	QM_ERR_CHK("QM CSR MSGRD ERRINF (0x%X) value 0x%08X\n",
		 CSR_MSGRD_ERRINF_ADDR, msgrd_err);

	apm_qm_raw_qstate_rd(IP_BLK_QM, msgrd_err & 0xFF, &qinfo);
	QM_ERR_CHK("QID %d stat %d\n", msgrd_err & 0xFF,
		queue_states[msgrd_err & 0xFF].msg_stat);
	QM_ERR_CHK_DUMP("QSTATE ", &qinfo, sizeof(qinfo));

	for (i = 0; i < DQ_MAIL_BOXES; i++) {
		u32 val;
		apm_qm_indirect_access_lock(1);
		__apm_qm_pb_cmd(IP_BLK_QM,
				(PB_SLAVE_ID_PPC << 6) | i, &val, 1);
		apm_qm_indirect_access_lock(0);
		QM_ERR_CHK("QM CSR 0x10 mailbox %d value 0x%08X slot %d\n",
			i, val, mb_dq_mbox_ctxt[i].slot);
	}

	apm_qm_wr32(IP_BLK_QM, QM_INTERRUPT_ADDR, status);
	return 0;
}

#define MAX_COAL_TAP 0x7
#define MIN_COAL_TAP 0x0

/* This will programe CSR_PBM_COAL's qne_ctick_sel bits which sets a
 * tap selects for queue not empty interrupt.
 */
void apm_qm_msg_not_empty_intr_coal_set(int tap)
{
	u32 val;

	apm_qm_indirect_access_lock(1);
	apm_qm_rd32(IP_BLK_QM, CSR_PBM_COAL_ADDR, &val);
	val |= QNE_CTICK_SEL_WR(tap);
	if (!apm86xxx_is_dp_mode())
		apm_qm_wr32(IP_BLK_QM, CSR_PBM_COAL_ADDR, val);
	else
		apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
				CSR_PBM_COAL_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_PBM_COAL_ADDR, val);
	/* Reback to force barrier */
	apm_qm_rd32(IP_BLK_QM, CSR_PBM_COAL_ADDR, &val);
	apm_qm_indirect_access_lock(0);
}

/* If tap is zero then coalescence is off */
int apm_qm_mbox_set_coal(int mbox_id, int tap)
{
	u32 val;

	if (tap > MAX_COAL_TAP || tap < MIN_COAL_TAP)
		return -1;

	apm_qm_indirect_access_lock(1);
	if (mbox_id <= 7)
		apm_qm_rd32(IP_BLK_QM, CSR_PBM_CTICK0_ADDR, &val);
	else
		apm_qm_rd32(IP_BLK_QM, CSR_PBM_CTICK1_ADDR, &val);
	switch (mbox_id) {
	case 0:
		val = MBOX00_SET(val, tap);
		break;
	case 1:
		val = MBOX10_SET(val, tap);
		break;
	case 2:
		val = MBOX20_SET(val, tap);
		break;
	case 3:
		val = MBOX30_SET(val, tap);
		break;
	case 4:
		val = MBOX40_SET(val, tap);
		break;
	case 5:
		val = MBOX50_SET(val, tap);
		break;
	case 6:
		val = MBOX60_SET(val, tap);
		break;
	case 7:
		val = MBOX70_SET(val, tap);
		break;
	case 8:
		val = MBOX81_SET(val, tap);
		break;
	case 9:
		val = MBOX91_SET(val, tap);
		break;
	case 10:
		val = MBOX101_SET(val, tap);
		break;
	case 11:
		val = MBOX111_SET(val, tap);
		break;
	case 12:
		val = MBOX121_SET(val, tap);
		break;
	case 13:
		val = MBOX131_SET(val, tap);
		break;
	case 14:
		val = MBOX141_SET(val, tap);
		break;
	case 15:
		val = MBOX151_SET(val, tap);
		break;
	default:
		apm_qm_indirect_access_lock(0);
		QM_ERR_CHK("%s: Wrong mail box id: %d\n", __func__, mbox_id);
		return -1;
	}
	if (!apm86xxx_is_dp_mode()) {
		if (mbox_id <= 7)
			apm_qm_wr32(IP_BLK_QM, CSR_PBM_CTICK0_ADDR, val);
		else
			apm_qm_wr32(IP_BLK_QM, CSR_PBM_CTICK1_ADDR, val);
	} else {
		if (mbox_id <= 7)
			apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
					CSR_PBM_CTICK0_ADDR, val);
		else
			apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
					CSR_PBM_CTICK1_ADDR, val);
	}
	/* Reback to force barrier */
	apm_qm_rd32(IP_BLK_QM, CSR_PBM_CTICK0_ADDR, &val);
	apm_qm_rd32(IP_BLK_QM, CSR_PBM_CTICK1_ADDR, &val);
	apm_qm_indirect_access_lock(0);

	return 0;
}

int __apm_qm_indirect_access_lock(int lock)
{
        return 0;
}
int apm_qm_indirect_access_lock(int lock)
        __attribute((weak, alias("__apm_qm_indirect_access_lock")));

int apm_qm_enable_hwirq(int ip, u32 msk)
{
	if (!apm86xxx_is_dp_mode())
		apm_qm_wr32(ip, QM_INTERRUPTMASK_ADDR, msk);
	else
		apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
				QM_INTERRUPTMASK_ADDR, msk);
	return 0;
}

int apm_qm_update_tm_timer(int ip, u32 val)
{
	if (!apm86xxx_is_dp_mode())
		apm_qm_wr32(ip, CSR_CU_TIMER_ADDR, val);
	else
		apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_QM, 0,
				CSR_CU_TIMER_ADDR, val);
	return 0;
}

static void
apm_qm_c2c_msg_q_drain(void)
{
    struct apm_qm_msg_desc msg_desc;
    struct apm_qm_msg64 msg;
    printk("Drain Core0->1 queue");
    memset(&msg_desc, 0, sizeof(msg_desc));
    msg_desc.mb_id = apm_qm_get_ib_mb(1, IP_PPC1);
    msg_desc.msg = &msg;
    while (apm_qm_pull_msg(&msg_desc) == 0) {
        printk(".");
    };
    printk("\n");
}

static void apm_qm_c2c_msg_tasklet(unsigned long data)
{
    struct apm_qm_msg_desc msg_desc;
    struct apm_qm_msg64 msg;
    struct apm_qm_msg16 *msg16;
    memset(&msg_desc, 0, sizeof(msg_desc));
    msg_desc.mb_id = apm_qm_get_ib_mb(1, IP_PPC1);
    msg_desc.msg = &msg;
    msg_desc.is_msg16 = 0;
    while (apm_qm_pull_msg(&msg_desc) == 0) {
        msg16 = &msg.msg32_1.msg16;
        if (qm_cb_fn_table[msg16->RType]) {
            (*qm_cb_fn_table[msg16->RType])(&msg_desc);
        } else {
            printk(KERN_INFO "No callback registered for Rtype %d\n",
                   msg16->RType);
        }
    }
    apm_qm_enable_mb_irq(apm_qm_get_ib_mb(1, IP_PPC1));
}

void apm_qm_c2c_msg_q_create_queues(void)
{
    int mb_10, mb_01;
    mb_10 = apm_qm_get_ib_mb(0, IP_PPC0);
    mb_01 = apm_qm_get_ib_mb(1, IP_PPC1);

    printk("mb_01 = %u, mb_10 = %u\n", mb_01, mb_10);
    /* All configured in IOS */
    q_to_mb[QM_10_MSG_H_QID] = mb_10;
    q_to_mb[QM_10_MSG_L_QID] = mb_10;
    q_to_mb[QM_10_MSG_VQID] = mb_10;

    q_to_mb[QM_01_MSG_H_QID] = mb_01;
    q_to_mb[QM_01_MSG_L_QID] = mb_01;
    q_to_mb[QM_01_MSG_VQID] = mb_01;

    mb_to_q[mb_01] = QM_01_MSG_VQID;
    /* Drain all messages */
    apm_qm_disable_mb_irq(mb_01);
    apm_qm_mb_tasklet_register(mb_01, QM_01_MSG_VQID, 1, NULL,
                               apm_qm_c2c_msg_tasklet);
    apm_qm_c2c_msg_q_drain();
    apm_qm_pb_clr(IP_BLK_QM, PB_SLAVE_ID_PPC, mb_01);
    apm_qm_enable_mb_irq(mb_01);

}

void apm_qm_c2c_msg_wait_fc(unsigned int threshold)
{
    struct apm_qm_raw_qstate vqs;
    unsigned int n_msgs = threshold + 1;
    u32 qid;

    while (1) {
        apm_qm_raw_qstate_rd(IP_BLK_QM, QM_10_MSG_VQID, &vqs);
        apm_qm_rd32(IP_BLK_QM, CSR_QSTATE_ADDR, &qid);

        while (qid != QM_10_MSG_VQID) {
            msleep(get_random_int()%5);
            apm_qm_raw_qstate_rd(IP_BLK_QM, QM_10_MSG_VQID, &vqs);
            apm_qm_rd32(IP_BLK_QM, CSR_QSTATE_ADDR, &qid);
        }

        n_msgs = (vqs.w4 & 0x3FFFF);
        if (n_msgs < threshold) {
            break;
        }
        msleep(5);
    }
}
