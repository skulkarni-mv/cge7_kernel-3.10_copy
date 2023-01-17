/**
 * AppliedMicro AM862xx QM Driver
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
 * @file apm_qm_access.c
 **
 */
#include <linux/of_platform.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/interrupt.h>
#include <linux/clk.h>
#include <linux/proc_fs.h>
#include <linux/dma-mapping.h>
#include <asm/apm_qm_csr.h>
#include <asm/apm_qm_access.h>
#include <asm/apm_qm_utils.h>
#include <asm/apm_qm_core.h>
#include <asm/apm_qml_csr.h>
#ifdef CONFIG_SYSFS
#include <asm/apm_qm_sysfs.h>
#endif
#include <asm/ipp.h>
#include <asm/apm86xxx_pm.h>
#include <asm/cacheflush.h>
#if defined(CONFIG_APM86xxx_SHMEM)
#include <asm/apm_shm.h>
#endif
#include <asm/apm_ipp_csr.h>

#define APM_QM_DRIVER_VERSION	"0.1"
#define APM_QM_DRIVER_NAME	"apm_qm_tm"
#define APM_QM_DRIVER_STRING	"APM QM-TM Driver"
#define PFX			"APMQM: "

#define RES_SIZE(r)	((r)->end - (r)->start + 1)

static int ready;

/* QM CSR address */
u64 qm_csr_paddr;
void *qm_csr_vaddr;
u64 qm_fabric_paddr;
void *qm_fabric_vaddr;

/* Mailbox address */
u64 qm_mailbox_paddr;
u32 qm_mailbox_type;
u64 qm_enq_mbox_paddr;
void *qm_enq_mbox_vaddr;
u32 qm_enq_mbox_size;
u64 qm_dq_mbox_paddr;
void *qm_dq_mbox_vaddr;
u32 qm_dq_mbox_size;
u64 qm_fp_mbox_paddr;
void *qm_fp_mbox_vaddr;
u32 qm_fp_mbox_size;

/* Memory location for queue descriptor */
void *queue_baddr;		/* DDR location if NULL */
u64 queue_baddr_p;
u64 queue_eaddr_p;
u32 queue_memsize;
dma_addr_t queue_dma;

/* QM lite CSR address */
u64 qml_csr_paddr;
void *qml_csr_vaddr;
u64 qml_fabric_paddr;
void *qml_fabric_vaddr;
u64 qml_ipp_csr_paddr;
void *qml_ipp_csr_vaddr;

extern u32 mb_to_q[QM_MAX_QUEUES];
extern apm_qm_msg_fn_ptr qm_cb_fn_table[APM_QM_MAX_RTYPE];
extern apm_qm_msg_fn_ptr qm_mailbox_fn_table[APM_QM_MAX_RTYPE];
extern struct apm_qm_qstate *queue_states;
extern struct apm_qm_raw_qstate *q_raw_states;

u8 err_qid;	/* Updated in apm_qm_init_errq */

u32 irq_mb_map[MAX_MAILBOXS];
u32 mb_to_irq_map[MAX_MAILBOXS];
static bool mb_irq_ena[MAX_MAILBOXS];

struct apm_qm_mb_tasklet *apm_qm_mb_tasklet_table[MAX_MAILBOXS];

/* global queue configuration table */
struct apm_qm_qstate mb_cfg_pqs[] = { };

int apm_qm_ready()
{
	return ready;
}

/* QM raw register read/write routine */
inline int apm_qm_wr32(int ip, u32 offset, u32 data)
{
	void *csr_base;
	void *addr;

	if (ip == IP_BLK_QM) {
		csr_base = qm_csr_vaddr;
	} else if (ip == IP_BLK_QML) {
		if (apm_qm_get_noqml()) {
			printk(KERN_ERR
				"Accessing non-existent QM lite hardware\n");
			return -ENODEV;
		}
		csr_base = qml_csr_vaddr;
	} else if (ip == IP_BLK_IPP_QML) {
		if (apm_qm_get_noqml()) {
			printk(KERN_ERR
				"Accessing non-existent QM lite hardware\n");
			return -ENODEV;
		}
		csr_base = qml_ipp_csr_vaddr;
	} else {
		QM_ERR_CHK("Invalid IP block in QM reg write: %d %s %d\n", ip,
			__FILE__, __LINE__);
		return -1;
	}

	addr = (u8 *) csr_base + offset;

#ifdef QM_DEBUG
	if (ip == IP_BLK_IPP_QML) {
		if (offset > 0x240) {
			QM_ERR_CHK("Invalid offset in iPP QML CSR reg "
				"write: %x %s %d\n", offset, __FILE__, __LINE__);
			return -1;
		}
	}

	if (offset > CSR_PPC_SAB7_ADDR) {
		QM_ERR_CHK("Invalid offset in QM reg write: %x %s %d\n",
			offset, __FILE__, __LINE__);
		return -1;
        }
#endif
	QMWRITE_PRINT("Write addr 0x%p data 0x%08X\n", addr, data);
	out_be32((void __iomem *) addr, data);
	return 0;
}

inline int apm_qm_rd32(int ip, u32 offset, u32 *data)
{
	void *csr_base;
	void *addr;

	if (ip == IP_BLK_QM) {
		csr_base = qm_csr_vaddr;
	} else if (ip == IP_BLK_QML) {
		if (apm_qm_get_noqml()) {
			printk(KERN_ERR
				"Accessing non-existent QM lite hardware\n");
			return -ENODEV;
		}
		csr_base = qml_csr_vaddr;
	} else if (ip == IP_BLK_IPP_QML) {
		if (apm_qm_get_noqml()) {
			printk(KERN_ERR
				"Accessing non-existent QM lite hardware\n");
			return -ENODEV;
		}
		csr_base = qml_ipp_csr_vaddr;
	} else {
		QM_ERR_CHK("Invalid IP block in QM reg read: %d %s %d\n", ip,
			__FILE__, __LINE__);
		return -1;
	}

	addr = (u8 *) csr_base + offset;
#ifdef QM_DEBUG
	if (ip == IP_BLK_IPP_QML) {
		if (offset > 0x240) {
			QM_ERR_CHK("Invalid offset in iPP QML CSR reg read: %x %s %d\n",
				offset, __FILE__, __LINE__);
			return -1;
		}
	}

	if (offset > CSR_PPC_SAB7_ADDR) {
		QM_ERR_CHK("Invalid offset in QM reg read: %x %s %d\n",
			offset, __FILE__, __LINE__);
		return -1;
	}
#endif
	*data = in_be32((void __iomem *) addr);
	QMREAD_PRINT("Read addr 0x%x data 0x%x\n", addr, *data);

        return 0;
}

static int apm_qm_driver_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int apm_qm_driver_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t apm_qm_driver_read(struct file *file, char __user *buf,
					size_t count, loff_t *ppos)
{
	return 0;
}

static ssize_t apm_qm_driver_write(struct file *file, const char __user *buf,
					size_t count, loff_t *ppos)
{
	#define CMD_DUMP_ETHERNET_PBN	'0'
	#define CMD_DUMP_SLIMPRO_PBN	'1'
	#define CMD_READ_QM_CSR		'2'
	#define CMD_QM_QUEUE_STATE	'3'
	#define CMD_SEND_QM_MSG		'4'
	#define CMD_RECV_QM_MSG		'5'
	#define CMD_QML_QUEUE_STATE	'6'
	#define CMD_CREATE_QM_Q0	'7'
	#define CMD_CREATE_QM_Q1	'8'

	struct apm_qm_qstate qstate = {0};
	struct apm_qm_qalloc qm_qalloc = {0};
	struct apm_qm_msg64 *msg64 = (struct apm_qm_msg64 *)
		"This is verbose 64 Byte loopback message sent & "
		"received by CPU.";
	int qid;
	int i;
	int pbn_val;
	u32 val;
	u32 reg_offset;
	int len = count;

	switch (*buf) {
	case CMD_DUMP_ETHERNET_PBN:
		printk(KERN_INFO "Dumping ETH0/1 PBN:\n");
		for (i = 0; i < 16; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH, i);
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				i, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
				pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping ETH0/1 Free Pool PBN:\n");
		for (i = 0; i < 17; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH,
					(i + 0x20));
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				(i + 0x20), pbn_val & 0xF,
				(pbn_val >> 4) & 0xFF, pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
#if !defined(CONFIG_APM862xx)
		printk(KERN_INFO "Dumping ETH2/3 PBN:\n");
		for (i = 0; i < 16; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETHX, i);
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				i, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
				pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping ETH2/3 Free Pool PBN:\n");
		for (i = 0; i < 17; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETHX,
					(i + 0x20));
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				(i + 0x20), pbn_val & 0xF,
				(pbn_val >> 4) & 0xFF, pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
#endif
		printk(KERN_INFO "Dumping Ethernet QM-lite Free Pool PBN:\n");
		for (i = 0; i < 17; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QML, PB_SLAVE_ID_ETH,
					(i + 0x20));
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				(i + 0x20), pbn_val & 0xF,
				(pbn_val >> 4) & 0xFF, pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping Ethernet PBN info WoL queues:\n");
		pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_ETH, 0x10);
		printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
			"FP: %d PBN enabled: %d\n",
			0x10, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
			pbn_val >> (31 - 19) & 1,
			pbn_val >> (31 - 17) & 0x1);
		pbn_val = apm_qm_pb_get(IP_BLK_QML, PB_SLAVE_ID_ETH, 0x10);
		printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
			"FP: %d PBN enabled: %d\n",
			0x10, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
			pbn_val >> (31 - 19) & 1,
			pbn_val >> (31 - 17) & 0x1);
		break;
	case CMD_DUMP_SLIMPRO_PBN:
		printk(KERN_INFO "Dumping SlimPRO PBN:\n");
		for (i = 0; i < 2; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_IPP, i);
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				i, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
				pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping SlimPRO PBN free queues:\n");
		for (i = 0; i < 9; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QM, PB_SLAVE_ID_IPP,
					(i + 0x20));
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				(i + 0x20), pbn_val & 0xF,
				(pbn_val >> 4) & 0xFF, pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping SlimPRO PBN WoL:\n");
		for (i = 0; i < 2; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QML, PB_SLAVE_ID_IPP, i);
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				i, pbn_val & 0xF, (pbn_val >> 4) & 0xFF,
				pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		printk(KERN_INFO "Dumping SlimPRO PBN WoL free queues:\n");
		for (i = 0; i < 9; i++) {
			pbn_val = apm_qm_pb_get(IP_BLK_QML, PB_SLAVE_ID_IPP,
					(i + 0x20));
			printk(KERN_INFO "PBN: %d Num of msgs: %d QID: %d "
				"FP: %d PBN enabled: %d\n",
				(i + 0x20), pbn_val & 0xF,
				(pbn_val >> 4) & 0xFF, pbn_val >> (31 - 19) & 1,
				pbn_val >> (31 - 17) & 0x1);
		}
		break;
	case CMD_READ_QM_CSR:
		buf++; /* skip space */
		buf++; /* get reg offset */
		reg_offset = (u32) (*buf - 48);
		buf++;
		reg_offset = (reg_offset * 100) + ((int) (*buf - 48) * 10);
		buf++;
		reg_offset = reg_offset + (int) (*buf - 48);
		apm_qm_rd32(IP_BLK_QM, reg_offset, &val);
		printk(KERN_INFO "QM register 0x%x value 0x%08X\n",
			reg_offset, val);
		break;
	case CMD_QM_QUEUE_STATE:
		buf += 2; /* Skip command and space */
		len--;
		qid = 0;
		while (len) {
			if (!(*buf >= '0' && *buf <= '9'))
				break;
			qid *= 10;
			qid += *buf - '0';
			len--;
			buf++;
		}
		printk(KERN_INFO "Reading QM queue state QID: %d\n", qid);
		apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
		dump_qstate(&qstate);
		val = apm_qm_pb_get(IP_BLK_QM, qstate.slave_id, qstate.pbn);
		printk(KERN_INFO "QM PBN 0x%08X\n", val);
		break;
	case CMD_QML_QUEUE_STATE:
		buf += 2; /* Skip command and space */
		len--;
		qid = 0;
		while (len) {
			if (!(*buf >= '0' && *buf <= '9'))
				break;
			qid *= 10;
			qid += *buf - '0';
			len--;
			buf++;
		}
		printk(KERN_INFO "Reading QML queue state QID: %d\n", qid);
		apm_qm_qstate_rd(IP_BLK_QML, qid, &qstate);
		dump_qstate(&qstate);
		break;
	case CMD_SEND_QM_MSG:
		buf += 2; /* Skip command and space */
		len--;
		qid = 0;
		while (len) {
			if (!(*buf >= '0' && *buf <= '9'))
				break;
			qid *= 10;
			qid += *buf - '0';
			len--;
			buf++;
		}
		printk(KERN_INFO "Sending msg on queue for core 0: %d\n", qid);
		apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
		apm_qm_send_msg_util(qid, qstate.mb_id, msg64);
		break;
	case CMD_RECV_QM_MSG:
		buf += 2; /* Skip command and space */
		len--;
		qid = 0;
		while (len) {
			if (!(*buf >= '0' && *buf <= '9'))
				break;
			qid *= 10;
			qid += *buf - '0';
			len--;
			buf++;
		}
		printk(KERN_INFO "Receiving msg from queue: %d\n", qid);
		apm_qm_qstate_rd(IP_BLK_QM, qid, &qstate);
		apm_qm_rx_msg_util(qid, qstate.mb_id);
		break;
	case CMD_CREATE_QM_Q0:
		/* Allocate egress work queue for PPC0 to PPC0 */
		qm_qalloc.qstates = &qstate;
		qm_qalloc.qm_ip_blk = IP_BLK_QM;
		qm_qalloc.ip_blk = IP_PPC0;
		qm_qalloc.ppc_id = 0;
		qm_qalloc.q_type = P_QUEUE;
		qm_qalloc.q_count = 1;
		qm_qalloc.direction = DIR_EGRESS;
		qm_qalloc.qsize = SIZE_16KB;
		qm_qalloc.thr_set = 1;

		if (apm_qm_alloc_q(&qm_qalloc)) {
			printk(KERN_INFO "Error allocating ingress work queue\n");
	        } else {
			printk(KERN_INFO "Created queue with qid: %d, mbid: %d\n",
				qstate.q_id, qstate.mb_id);
			dump_qstate(&qstate);
		}
		break;
	case CMD_CREATE_QM_Q1:
		/* Allocate egress work queue for PPC1 to PPC0 */
		qm_qalloc.qstates = &qstate;
		qm_qalloc.qm_ip_blk = IP_BLK_QM;
		qm_qalloc.ip_blk = IP_PPC0;
		qm_qalloc.ppc_id = 1;
		qm_qalloc.q_type = P_QUEUE;
		qm_qalloc.q_count = 1;
		qm_qalloc.direction = DIR_EGRESS;
		qm_qalloc.qsize = SIZE_16KB;
		qm_qalloc.thr_set = 1;

		if (apm_qm_alloc_q(&qm_qalloc)) {
			printk(KERN_INFO "Error allocating ingress work queue\n");
	        } else {
			printk(KERN_INFO "Created queue with qid: %d, mbid: %d\n",
				qstate.q_id, qstate.mb_id);
			dump_qstate(&qstate);
		}
		break;
	default:
		printk(KERN_INFO "QM util help\n");
		printk(KERN_INFO "To dump PBN of ETH: echo '%c'\n",
			CMD_DUMP_ETHERNET_PBN);
		printk(KERN_INFO "To dump PBN of iPP: echo '%c'\n",
			CMD_DUMP_SLIMPRO_PBN);
		printk(KERN_INFO "To read QM CSR: echo '%c <addr>'\n",
			CMD_READ_QM_CSR);
		printk(KERN_INFO "To dump QM queue state: echo '%c <QID>'\n",
			CMD_QM_QUEUE_STATE);
		printk(KERN_INFO "To send QM queue msg: echo '%c <QID>'\n",
			CMD_SEND_QM_MSG);
		printk(KERN_INFO "To receive QM queue msg: echo '%c <QID>'\n",
			CMD_RECV_QM_MSG);
		printk(KERN_INFO "To dump QML queue state: echo '%c <QID>'\n",
			CMD_QML_QUEUE_STATE);
		printk(KERN_INFO "To create Core0 -> Core0 queue: echo '%c'\n",
			CMD_CREATE_QM_Q0);
		printk(KERN_INFO "To create Core1 -> Core0 queue: echo '%c'\n",
			CMD_CREATE_QM_Q1);
		break;
	}
	return count;
}

static long apm_qm_driver_ioctl(struct file *file,
				u32 cmd, unsigned long arg)
{
	return 0;
}

irqreturn_t apm_qm_sab_int(int value, void *id)
{
	printk(KERN_ERR "QM SAB interrupt occured\n");
	return IRQ_HANDLED;
}

irqreturn_t apm_qm_sys_int(int value, void *id)
{
	apm_qm_irq_err();
	return IRQ_HANDLED;
}

irqreturn_t apm_qm_msg_int(int value, void *id)
{
	struct apm_qm_msg64 msg;
	struct apm_qm_msg16 *msg16;
	struct apm_qm_msg_desc msg_desc;
	u32 mb_id = *(u32 *) id; /* this will be mailbox number */

	QM_DBG2("QM Mailbox ISR %d\n", mb_id);

	msg_desc.msg = &msg;

	/* retrieve message */
	msg_desc.mb_id = mb_id;
	msg_desc.qid = mb_to_q[mb_id];

	/* Check for direct de-queue callback function first */
	if (qm_mailbox_fn_table[mb_id]) {
		(qm_mailbox_fn_table[mb_id])(&msg_desc);
		return IRQ_HANDLED;
	}

	if (apm_qm_mb_tasklet_table[mb_id]) {
		apm_qm_tasklet_schedule(mb_id);
		return IRQ_HANDLED;
	}

	msg16 = &msg.msg32_1.msg16;

	/* Non-direct de-queue - legacy method */
	QM_DBG2("Get msg MB %d QID %d\n", msg_desc.mb_id, msg_desc.qid);
	msg_desc.is_msg16 = 0;
	if (apm_qm_pull_msg(&msg_desc) == -1) {
		/* Return if invalid interrupt */
		QM_DBG2("QM IRQ without QM message MB %d QID %d\n",
			msg_desc.mb_id, msg_desc.qid);
		return IRQ_HANDLED;
	}

	QM_DBG2("Message RTYPE %d\n", msg16->RType);
#if !defined CONFIG_SLAB_HW
	if (msg_desc.qid == err_qid) {
		QM_DBG("QM Error: Msg Rx Err QID %d RType %d\n",
			msg_desc.qid, msg16->RType);
		print_hex_dump(KERN_INFO, "Err q MSG: ", DUMP_PREFIX_ADDRESS,
			16, 4, msg16, msg16->NV ? 64 : 32, 1);
		apm_qm_parse_error(&msg_desc);
		return IRQ_HANDLED;
	}
#endif
	/* call registered callback for this rtype else discard */
	if (qm_cb_fn_table[msg16->RType]) {
		(*qm_cb_fn_table[msg16->RType])(&msg_desc);
	} else {
		printk(KERN_INFO "No callback registered for Rtype %d\n",
			msg16->RType);
		printk(KERN_INFO "Message received QID %d MBID %d\n",
			msg_desc.qid, msg_desc.mb_id);
		print_hex_dump(KERN_INFO, "READ MSG ", DUMP_PREFIX_ADDRESS,
				16, 4, msg_desc.msg, 32, 1);
        }
	return IRQ_HANDLED;
}

void *MEMALLOC(int size)
{
	return kmalloc(size, GFP_ATOMIC);
}

static void apm_qm_flush_mbox(void *enq_mbox_vaddr, u32 enq_mbox_size,
			void *dq_mbox_vaddr, u32 dq_mbox_size,
			void *fp_mbox_vaddr, u32 fp_mbox_size)
{
	memset(enq_mbox_vaddr, 0, enq_mbox_size);
	flush_dcache_range((unsigned long) enq_mbox_vaddr,
			(unsigned long) enq_mbox_vaddr + enq_mbox_size);
	memset(dq_mbox_vaddr, 0, dq_mbox_size);
	flush_dcache_range((unsigned long) dq_mbox_vaddr,
			(unsigned long) dq_mbox_vaddr + dq_mbox_size);
	memset(fp_mbox_vaddr, 0, fp_mbox_size);
	flush_dcache_range((unsigned long) fp_mbox_vaddr,
			(unsigned long) fp_mbox_vaddr + fp_mbox_size);
}

int apm_qm_config_set(struct platform_device *pdev)
{
	int rc = 0;
	int inum = 0, i = 0, j = 0;
	struct device_node *np = pdev->dev.of_node;
	struct resource	   res;
	u32 csr_addr_size;
	u32 qm_fabric_size;
	u32 qml_fabric_size;
	u32 qml_ipp_csr_size;
	u32 qm_mailbox_size;
	u32 *maxq;
	u32 *qstart;
	u32 *qfirst;
	u32 *maxmbs;
	u32 maxq_len;
	u32 qstart_len;
	u32 maxmbs_len;
	int mb_cfg_type;
	int mb_in_memc;

	/* Retrieve QM CSR register address and size */
	rc = of_address_to_resource(np, 0, &res);
	if (rc)
		return -ENODEV;

	qm_csr_paddr = res.start;
	csr_addr_size = RES_SIZE(&res);
	qm_csr_vaddr = ioremap_nocache(qm_csr_paddr, csr_addr_size);
	QM_DBG("QM CSR PADDR 0x%010llx size %d VADDR 0x%p\n",
		qm_csr_paddr, csr_addr_size, qm_csr_vaddr);

	if (!qm_csr_vaddr) {
		printk(KERN_ERR "Failed to ioremap QM CSR region\n");
		return -ENODEV;
	}
	if ((num_online_cpus() > 1) || !mfspr(SPRN_PIR)) {
		/* Bring QM CSR memory out of shutdown */
		rc = apm86xxx_disable_mem_shutdown((u32 __iomem *)(qm_csr_vaddr+
						APM_GLBL_DIAG_OFFSET+
						QM_CFG_MEM_RAM_SHUTDOWN_ADDR),
						QMTM_F2_MASK);
		if (rc) {
			printk(KERN_ERR "Failed to bring QM CSR RAM"
			       "out of shutdown\n");
			return -ENODEV;
		}
	}
	/* Retrieve Primary Fabric address and size */
	rc = of_address_to_resource(np, 1, &res);
	if (rc)
		return -ENODEV;

	qm_fabric_paddr = res.start;
	qm_fabric_size = RES_SIZE(&res);
	qm_fabric_vaddr = ioremap_nocache(qm_fabric_paddr, qm_fabric_size);
	QM_DBG("QM fabric PADDR 0x%010llx size %d VADDR 0x%p\n",
		qm_fabric_paddr, qm_fabric_size, qm_fabric_vaddr);

	/* Retrieve mailbox address and size */
	rc = of_address_to_resource(np, 2, &res);
	if (rc || RES_SIZE(&res) <= 0) {
		printk(KERN_ERR "resource for QM mailbox invalid\n");
		return -ENODEV;
	}

	qm_mailbox_paddr = res.start;
	qm_mailbox_size = RES_SIZE(&res);
	qm_enq_mbox_size = ((qm_mailbox_size * 2) / 5);
	qm_dq_mbox_size = (qm_enq_mbox_size);
	qm_fp_mbox_size = (qm_enq_mbox_size / 2);

#if defined(CONFIG_QM_MAILBOX_MEMQ)
	mb_cfg_type = QM_MAILBOX_NONCACHEABLE;
	mb_in_memc = 1;
#else
	mb_cfg_type = QM_MAILBOX_COHERENT;
	mb_in_memc = 0;
#endif

	if (apm86xxx_is_dp_mode()) {
		/* Domain protection requires QM mailbox located in MemC */
		mb_cfg_type = QM_MAILBOX_NONCACHEABLE;
		mb_in_memc = 1;
	}

	if (mb_in_memc) {
		/* QM Mailbox located in OCM */
		if (mb_cfg_type & QM_MAILBOX_COHERENT) {
			qm_enq_mbox_paddr = qm_mailbox_paddr;
			qm_enq_mbox_vaddr = ioremap_prot(qm_enq_mbox_paddr,
					qm_enq_mbox_size, _PAGE_COHERENT);
			qm_dq_mbox_paddr = qm_enq_mbox_paddr +
						qm_enq_mbox_size;
			qm_dq_mbox_vaddr = ioremap_prot(qm_dq_mbox_paddr,
					qm_dq_mbox_size, _PAGE_COHERENT);
			qm_fp_mbox_paddr = qm_dq_mbox_paddr + qm_dq_mbox_size;
			qm_fp_mbox_vaddr = ioremap_prot(qm_fp_mbox_paddr,
					qm_fp_mbox_size, _PAGE_COHERENT);
			qm_mailbox_type = QM_MAILBOX_COHERENT;
			printk(KERN_INFO PFX
				"QM Mailboxes located on coherent MemQ\n");
		} else if (mb_cfg_type & QM_MAILBOX_CACHEABLE) {
			qm_enq_mbox_paddr = qm_mailbox_paddr;
			qm_enq_mbox_vaddr = ioremap(qm_enq_mbox_paddr,
						qm_enq_mbox_size);
			qm_dq_mbox_paddr = qm_enq_mbox_paddr + qm_enq_mbox_size;
			qm_dq_mbox_vaddr = ioremap(qm_dq_mbox_paddr,
						qm_dq_mbox_size);
			qm_fp_mbox_paddr = qm_dq_mbox_paddr + qm_dq_mbox_size;
			qm_fp_mbox_vaddr = ioremap(qm_fp_mbox_paddr,
						qm_fp_mbox_size);
			qm_mailbox_type = QM_MAILBOX_CACHEABLE;
			printk(KERN_INFO PFX
				"QM Mailboxes located on cacheable MemQ\n");
		} else {
			qm_enq_mbox_paddr = qm_mailbox_paddr;
			qm_enq_mbox_vaddr = ioremap_nocache(qm_enq_mbox_paddr,
						qm_enq_mbox_size);
			qm_dq_mbox_paddr = qm_enq_mbox_paddr +
						qm_enq_mbox_size;
			qm_dq_mbox_vaddr = ioremap_nocache(qm_dq_mbox_paddr,
						qm_dq_mbox_size);
			qm_fp_mbox_paddr = qm_dq_mbox_paddr + qm_dq_mbox_size;
			qm_fp_mbox_vaddr = ioremap_nocache(qm_fp_mbox_paddr,
						qm_fp_mbox_size);
			qm_mailbox_type = QM_MAILBOX_NONCACHEABLE;
			printk(KERN_INFO PFX
				"QM Mailboxes located on non-cacheable MemQ\n");
		}
	} else {
		/* QM Mailbox located in DDR */
		u32 *val;
		u32 val_len;
		val = (u32 *) of_get_property(np, "mb-dma-reg", &val_len);
		if (val == NULL)
			val = (u32 *) of_get_property(np, "dma-reg", &val_len);
		if (val == NULL || val_len < 3 ||
			!(val[0] | val[1]) || !val[2]) {
			/* Create mailboxes in DDR using malloc */
			qm_enq_mbox_vaddr = MEMALLOC(qm_enq_mbox_size * 2);
			qm_enq_mbox_vaddr = (void *) ((unsigned long)
				qm_enq_mbox_vaddr + qm_enq_mbox_size);
			qm_enq_mbox_vaddr = (void *) ((unsigned long)
				qm_enq_mbox_vaddr & ~(qm_enq_mbox_size - 1));
			qm_enq_mbox_paddr = virt_to_phys(qm_enq_mbox_vaddr);
			if (qm_enq_mbox_vaddr == 0x0) {
				QM_PRINT("Unable to allocate EQ mailboxes\n");
				return -1;
			}
			qm_dq_mbox_vaddr = MEMALLOC(qm_dq_mbox_size * 2);
			qm_dq_mbox_vaddr = (void *) ((unsigned long)
				qm_dq_mbox_vaddr + qm_dq_mbox_size);
			qm_dq_mbox_vaddr = (void *) ((unsigned long)
				qm_dq_mbox_vaddr & ~(qm_dq_mbox_size - 1));
			qm_dq_mbox_paddr = virt_to_phys(qm_dq_mbox_vaddr);
			if (qm_dq_mbox_vaddr == 0x0) {
				QM_PRINT("Unable to allocate DQ mailboxes\n");
				return -1;
			}

			qm_fp_mbox_vaddr = MEMALLOC(qm_fp_mbox_size * 2);
			qm_fp_mbox_vaddr = (void *) ((unsigned long)
				qm_fp_mbox_vaddr + qm_fp_mbox_size);
			qm_fp_mbox_vaddr = (void *) ((unsigned long)
				qm_fp_mbox_vaddr & ~(qm_fp_mbox_size - 1));
			qm_fp_mbox_paddr = virt_to_phys(qm_fp_mbox_vaddr);
			if (qm_fp_mbox_vaddr == 0x0) {
				QM_PRINT("Unable to allocate FQ mailboxes\n");
				return -1;
			}
			if (CONFIG_QM_MAILBOX_TYPE & QM_MAILBOX_COHERENT) {
				qm_mailbox_type = QM_MAILBOX_COHERENT;
				printk(KERN_INFO PFX "QM Mailboxes located "
					"on coherent DDR\n");
			} else if (CONFIG_QM_MAILBOX_TYPE &
						QM_MAILBOX_CACHEABLE) {
				qm_mailbox_type = QM_MAILBOX_CACHEABLE;
				printk(KERN_INFO PFX "QM Mailboxes located "
					"on cacheable DDR\n");
			} else {
				qm_mailbox_type = QM_MAILBOX_NONCACHEABLE;
				printk(KERN_INFO PFX "QM Mailboxes located "
					"on non-cacheable DDR\n");
			}
		} else {
			qm_mailbox_paddr = (((u64)val[0]) << 32) | val[1];
			qm_mailbox_size = val[2];
			if (qm_mailbox_size > (16 * 1024))
				qm_mailbox_paddr += qm_mailbox_size -
							(16 * 1024);
			qm_mailbox_size = (16 * 1024);

			qm_enq_mbox_paddr = qm_mailbox_paddr;
			qm_enq_mbox_size = qm_mailbox_size / 4;
			if (CONFIG_QM_MAILBOX_TYPE & QM_MAILBOX_COHERENT) {
				qm_mailbox_type = QM_MAILBOX_COHERENT;
				qm_enq_mbox_vaddr = ioremap_prot(
					qm_enq_mbox_paddr, qm_enq_mbox_size,
					_PAGE_COHERENT);
				printk(KERN_INFO PFX "QM Mailboxes located "
					"on coherent DDR\n");
			} else {
				qm_mailbox_type = QM_MAILBOX_NONCACHEABLE;
				qm_enq_mbox_vaddr = ioremap_nocache(
					qm_enq_mbox_paddr, qm_enq_mbox_size);
				printk(KERN_INFO PFX "QM Mailboxes located "
					"on nonc-cacheable DDR\n");
			}
			qm_dq_mbox_paddr = qm_enq_mbox_paddr + qm_enq_mbox_size;
			qm_dq_mbox_size = qm_mailbox_size / 4;
			if (CONFIG_QM_MAILBOX_TYPE & QM_MAILBOX_COHERENT)
				qm_dq_mbox_vaddr = ioremap_prot(
					qm_dq_mbox_paddr, qm_dq_mbox_size,
					_PAGE_COHERENT);
			else
				qm_dq_mbox_vaddr = ioremap_nocache(
					qm_dq_mbox_paddr, qm_dq_mbox_size);

			qm_fp_mbox_paddr = qm_dq_mbox_paddr + qm_dq_mbox_size;
			qm_fp_mbox_size = qm_mailbox_size / 4;
			if (CONFIG_QM_MAILBOX_TYPE & QM_MAILBOX_COHERENT)
				qm_fp_mbox_vaddr = ioremap_prot(
					qm_fp_mbox_paddr, qm_fp_mbox_size,
					_PAGE_COHERENT);
			else
				qm_fp_mbox_vaddr = ioremap_nocache(
					qm_fp_mbox_paddr, qm_fp_mbox_size);
		}
	}

	maxmbs = (u32 *) of_get_property(np, "maxmboxes", &maxmbs_len);

	if (maxmbs == NULL || maxmbs_len < sizeof(u32))
		apm_qm_set_mboxes(16, 0);
	else if (*maxmbs == 16)
		apm_qm_set_mboxes(*maxmbs, 0);
	else
		apm_qm_set_mboxes(*maxmbs, 8 * mfspr(SPRN_PIR));

	apm_qm_flush_mbox(
		(u8 *) qm_enq_mbox_vaddr +
			32*TOTAL_SLOTS_32BYTE_MSG*apm_qm_get_start_mboxes(),
			(apm_qm_get_max_mboxes()-apm_qm_get_start_mboxes())
				*32*TOTAL_SLOTS_32BYTE_MSG,
		(u8 *) qm_dq_mbox_vaddr +
			32*TOTAL_SLOTS_32BYTE_MSG*apm_qm_get_start_mboxes(),
			(apm_qm_get_max_mboxes()-apm_qm_get_start_mboxes())
				*32*TOTAL_SLOTS_32BYTE_MSG,
		(u8 *) qm_fp_mbox_vaddr +
			16*TOTAL_SLOTS_16BYTE_MSG*apm_qm_get_start_mboxes(),
			(apm_qm_get_max_mboxes()-apm_qm_get_start_mboxes())
				*16*TOTAL_SLOTS_16BYTE_MSG);

	QM_DBG("QM MBox Type %d PADDR 0x%010llx size %d ENQ ADDR 0x%p "
		"DEQ ADDR 0x%p FP ADDR 0x%p\n",
		qm_mailbox_type, qm_mailbox_paddr, qm_mailbox_size,
		qm_enq_mbox_vaddr, qm_dq_mbox_vaddr, qm_fp_mbox_vaddr);

	/* configure mailboxes */
	apm_qm_alloc_mbox();

	apm_qm_set_enq_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_enq_mbox_paddr);
	apm_qm_set_dq_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_dq_mbox_paddr);
	apm_qm_set_fp_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_fp_mbox_paddr);

	queue_baddr_p = 0;
	queue_baddr   = 0;
	queue_memsize = 0;
#if defined(QM_ALTERNATE_ENQUEUE)
	{
		u32 *val;
		u32 val_len;
		val = (u32 *) of_get_property(np, "dma-reg", &val_len);
		if (val == NULL || val_len < 3) {
			printk(KERN_ERR "No DTS dma-reg\n");
			return -ENODEV;
		}
		queue_baddr_p   = val[0];
		queue_baddr_p <<= 32;
		queue_baddr_p  |= val[1];
		queue_memsize = val[2] - (16 * 1024);
		queue_eaddr_p = queue_baddr_p + queue_memsize;
		queue_baddr = ioremap_nocache(queue_baddr_p, queue_memsize);
	}
#endif

	/* Check and skip QM lite init if hardware not available */
	if (apm_qm_get_noqml()) {
		qml_fabric_paddr = 0;
		qml_fabric_size = 0;
		qml_fabric_vaddr = 0;
		qml_csr_paddr = 0;
		qml_csr_vaddr = 0;
		qml_ipp_csr_paddr = 0;
		qml_ipp_csr_size = 0;
		qml_ipp_csr_vaddr = 0;
		goto skip_qml;
	}

	/* Retrieve QM lite Fabric address and size */
	rc = of_address_to_resource(np, 3, &res);
	if (rc)
		return -ENODEV;

	qml_fabric_paddr = res.start;
	qml_fabric_size = RES_SIZE(&res);
	qml_fabric_vaddr = ioremap_nocache(qml_fabric_paddr, csr_addr_size);
	QM_DBG("QM-lite Fabric PADDR 0x%010llx size %d VADDR 0x%p\n",
		qml_fabric_paddr, qml_fabric_size, qml_fabric_vaddr);

	/* Retrieve QM lite CSR register address and size */
	rc = of_address_to_resource(np, 4, &res);
	if (rc)
		return -ENODEV;

	qml_csr_paddr = res.start;
	csr_addr_size = RES_SIZE(&res);
	qml_csr_vaddr = ioremap_nocache(qml_csr_paddr, csr_addr_size);
	QM_DBG("QM-lite CSR PADDR 0x%010llx size %d VADDR 0x%p\n",
		qml_csr_paddr, csr_addr_size, qml_csr_vaddr);

	/* Retrieve QM lite iPP CSR register address and size */
	rc = of_address_to_resource(np, 5, &res);
	if (rc)
		return -ENODEV;

	qml_ipp_csr_paddr = res.start;
	qml_ipp_csr_size = RES_SIZE(&res);
	qml_ipp_csr_vaddr = ioremap_nocache(qml_ipp_csr_paddr, qml_ipp_csr_size);
	QM_DBG("QM-lite iPP CSR PADDR 0x%010llx size %d VADDR 0x%p\n",
		qml_ipp_csr_paddr, qml_ipp_csr_size, qml_ipp_csr_vaddr);

skip_qml:
	/* get interrupts */
	if (apm_qm_get_smp() || !mfspr(SPRN_PIR)) { /* error irq will be handled by core 0 only */

		/* get error interrupt */
		inum = of_irq_to_resource(np, i, NULL);
		if (inum == NO_IRQ) {
			printk(KERN_ERR "Failed to map system interrupt QM Err\n");
		} else {
			rc = request_irq(inum, apm_qm_sys_int, 0, "QM-Err", NULL);
			if (rc) {
				printk(KERN_ERR
					"Could not register for IRQ %d\n", inum);
				return rc;
			} else {
				QM_DBG("Registered error IRQ %d\n", inum);
			}
		}
		i++;

		/* get SAB event interrupt */
		inum = of_irq_to_resource(np, i, NULL);
		if (inum == NO_IRQ) {
			printk(KERN_ERR "Failed to map SAB interrupt\n");
		} else {
			rc = request_irq(inum, apm_qm_sab_int, 0, "QM-SAB", NULL);
			if (rc) {
				printk(KERN_ERR
					"Could not register for IRQ %d\n", inum);
				return rc;
			} else {
				QM_DBG("Registered sab IRQ %d\n", inum);
			}
		}
		i++;
	}

/* :CD: No need to use SMP or AMP, just read resources from DTS */
	if (!apm_qm_get_smp()) {
		for (j = 0; j < apm_qm_get_max_mboxes(); j++) {
			irq_mb_map[j] = j + apm_qm_get_start_mboxes();
		}
	} else {
		for (j = 0; j < apm_qm_get_max_mboxes(); j++) {
			irq_mb_map[j] = j;
		}
	}

	j = 0;
	/* get mailbox interrupts */
	while (1) {
		inum = of_irq_to_resource(np, i, NULL);
		if (inum != NO_IRQ) {
			QM_DBG("Cfg QM Mailbox %d Interrupt %d userval %d\n",
				j, inum, irq_mb_map[j]);

			rc = request_irq(inum, apm_qm_msg_int, 0, "QM-mailbox",
						(void *) &irq_mb_map[j]);
			if (rc) {
				printk(KERN_ERR
					"Could not register IRQ %d\n", inum);
				return rc;
			} else {
				if (!apm_qm_get_smp()) {
					mb_to_irq_map[j + (8 * mfspr(SPRN_PIR))] = inum;
				} else {
					mb_to_irq_map[j] = inum;
				}
				j++;
			}
		} else {
			break;
		}
		i++;
	}
        for (i = 1; i < MAX_MAILBOXS; i++) {
		mb_irq_ena[i] = 1;
	}
	/* Enable QM mailbox interrupts and deq axi error interrupt */
	apm_qm_enable_hwirq(IP_BLK_QM,
		~(PBM_DEC_ERRORMASK_MASK |
#if !defined(CONFIG_APM862xx)
		ACR_FIFO_CRITICALMASK_MASK |
#endif
		DEQ_AXI_ERRORMASK_MASK) |
		QPCORE_ACR_ERRORMASK_MASK);

	maxq = (u32 *) of_get_property(np, "maxqid", &maxq_len);
	if (maxq == NULL || maxq_len < sizeof(u32)) {
		printk(KERN_ERR "Unable to retrive Max Queue value from DTS\n");
		return -EINVAL;
	}

	/* Retrieve first and start (usable) QID - first QID is used for
	   suspend and resume */
	qstart = (u32 *) of_get_property(np, "qstart", &qstart_len);
        if (qstart == NULL || qstart_len < sizeof(u32)) {
		printk(KERN_ERR "Unable to retrive start of queue value from DTS\n");
		return -EINVAL;
	}
	qfirst = (u32 *) of_get_property(np, "qfirst", &qstart_len);
	if (qfirst == NULL || qstart_len < sizeof(u32))
		apm_qm_set_qid(*qfirst, *qfirst, *maxq, *maxq);
	else
		apm_qm_set_qid(*qfirst, *qstart, *maxq, *maxq);

	return rc;
}

int apm_qm_init_errq(int ppc_id)
{
	int rc = 0;
	u32 val;
	struct apm_qm_qalloc eth_qalloc;
	struct apm_qm_qstate enet_qstates;

	QM_DBG("Configure QM error queue using OCM mailbox\n");

	/* program threshold set 1 and all hysteresis */
	apm_qm_wr32(IP_BLK_QM, CSR_THRESHOLD0_SET1_ADDR, 100);
	apm_qm_wr32(IP_BLK_QM, CSR_THRESHOLD1_SET1_ADDR, 200);
	apm_qm_wr32(IP_BLK_QM, CSR_HYSTERESIS_ADDR, 0xFFFFFFFF);

	/* create error queue */
	memset(&eth_qalloc, 0, sizeof(struct apm_qm_qalloc));
	memset(&enet_qstates, 0, sizeof(struct apm_qm_qstate));
	eth_qalloc.qstates = &enet_qstates;
	eth_qalloc.qm_ip_blk = IP_BLK_QM;
	eth_qalloc.ip_blk = IP_OCMM; /* using OCM MB for now */
	eth_qalloc.ppc_id = ppc_id;  /* currently all err msgs go to core 0 */
	eth_qalloc.q_type = P_QUEUE;
	eth_qalloc.q_count = 1;
	eth_qalloc.direction = DIR_INGRESS;
	eth_qalloc.qsize = SIZE_16KB;
	eth_qalloc.thr_set = 1;

	if ((rc = apm_qm_alloc_q(&eth_qalloc)) != 0) {
		printk(KERN_ERR "Error allocating error queue\n");
		return rc;
	}

	err_qid = enet_qstates.q_id;

	/* Enable QPcore and assign error queue */
	val = 0;
	val = ENABLE_F6_SET(val, 1);
#if defined(CONFIG_APM862xx)
	val = ERROR_QID_F2_SET(val, err_qid);
	val = ERROR_QUEUE_ENABLE_F2_SET(val, APM_QM_ERROR_Q_ENABLE);
#endif
	apm_qm_wr32(IP_BLK_QM, CSR_QM_CONFIG_ADDR, val);
	/* Enable QM lite if hardware available */
	if (!apm_qm_get_noqml())
		apm_qm_wr32(IP_BLK_QML, CSR_QM_CONFIG_ADDR, val);

#if !defined(CONFIG_APM862xx)
	val = 0;
	val = UNEXPECTED_EN_SET(val, APM_QM_ERROR_Q_ENABLE);
	val = UNEXPECTED_QID_SET(val, err_qid);
	val = EXPECTED_EN_SET(val, APM_QM_ERROR_Q_ENABLE);
	val = EXPECTED_QID_SET(val, err_qid);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_0_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_1_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_2_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_3_ERRQ_ADDR, val);
	if (!apm_qm_get_noqml()) {
		apm_qm_wr32(IP_BLK_QML, CSR_DOM_0_ERRQ_ADDR, val);
		apm_qm_wr32(IP_BLK_QML, CSR_DOM_1_ERRQ_ADDR, val);
		apm_qm_wr32(IP_BLK_QML, CSR_DOM_2_ERRQ_ADDR, val);
		apm_qm_wr32(IP_BLK_QML, CSR_DOM_3_ERRQ_ADDR, val);
	}
#endif
	mb();

	return rc;
}

int apm_qm_mb_tasklet_register(u32 mailbox, u32 queue, u32 core, void *ctx,
					void (*func)(unsigned long))
{
	int rc = -1;
	struct apm_qm_mb_tasklet *handler;

	if (mailbox < 0 || mailbox > MAX_MAILBOXS) {
		QM_PRINT("Mailbox %d out of range\n", mailbox);
		goto _ret_qm_mb_tasklet_register;
	} else if (apm_qm_mb_tasklet_table[mailbox]) {
		QM_PRINT("Mailbox %d handler already registered\n", mailbox);
		goto _ret_qm_mb_tasklet_register;
	}

	handler = kmalloc(sizeof(struct apm_qm_mb_tasklet) +
			sizeof(struct tasklet_struct), GFP_KERNEL);
	if (handler == NULL) {
		QM_PRINT("Mailbox %d tasklet handler allocation failed\n", mailbox);
		goto _ret_qm_mb_tasklet_register;
	}

	handler->mailbox = mailbox;
	handler->queue = queue;
	handler->core = core;
	handler->ctx = ctx;
	handler->tasklet = (void *) ((u8 *) handler +
				sizeof(struct apm_qm_mb_tasklet));
	tasklet_init(handler->tasklet, func, (unsigned long) handler);
	apm_qm_mb_tasklet_table[mailbox] = handler;
	rc = 0;

_ret_qm_mb_tasklet_register:
	return rc;
}
EXPORT_SYMBOL(apm_qm_mb_tasklet_register);

int apm_qm_mb_tasklet_unregister(struct apm_qm_mb_tasklet *handler)
{
	int rc = -1;
	u32 mailbox;

	if (handler == NULL) {
		QM_PRINT("Mailbox tasklet handler is NULL\n");
		goto _ret_qm_mb_tasklet_unregister;
	}

	mailbox = handler->mailbox;
	if (mailbox < 0 || mailbox > MAX_MAILBOXS) {
		QM_PRINT("Mailbox %d out of range\n", mailbox);
		goto _ret_qm_mb_tasklet_unregister;
	} else if (apm_qm_mb_tasklet_table[mailbox] == NULL) {
		QM_PRINT("Mailbox %d handler never registered\n", mailbox);
		goto _ret_qm_mb_tasklet_unregister;
	}

	tasklet_kill((struct tasklet_struct *) handler->tasklet);
	kfree(handler);
	apm_qm_mb_tasklet_table[mailbox] = NULL;
	rc = 0;

_ret_qm_mb_tasklet_unregister:
	return rc;
}

void apm_qm_tasklet_schedule(int mb_id)
{
        if (!apm_qm_mb_tasklet_table[mb_id]) {
        return;
        }
	apm_qm_disable_mb_irq(mb_id);
	tasklet_schedule((struct tasklet_struct *)
			apm_qm_mb_tasklet_table[mb_id]->tasklet);
}

static inline int apm_ppc_rx_msg(struct apm_qm_msg_desc *msg_desc)
{
	struct apm_qm_msg16 *msg = msg_desc->msg;

	printk(KERN_INFO "APM_QM_PPC_RTYPE Message received QID %d MBID %d\n",
		msg_desc->qid, msg_desc->mb_id);
	print_hex_dump(KERN_INFO, "READ MSG ", DUMP_PREFIX_ADDRESS,
		16, 4, msg, msg->NV ? 64 : 32, 1);

	return 0;
}

struct file_operations apm_qm_driver_fops = {
	.owner = THIS_MODULE,
	.open = apm_qm_driver_open,
	.release = apm_qm_driver_release,
	.read = apm_qm_driver_read,
	.write = apm_qm_driver_write,
	.unlocked_ioctl = apm_qm_driver_ioctl,
};

static int  apm_qm_probe(struct platform_device *pdev)
{
	int rc = 0;
	struct proc_dir_entry *entry;
	struct clk *clk;
	u32 val;
	int reset_qm = 0;
	int reset_qml = 0;

	printk(KERN_INFO "%s v%s\n", APM_QM_DRIVER_STRING,
	       APM_QM_DRIVER_VERSION);

#ifdef CONFIG_SMP
	apm_qm_set_smp(1);
#else
	apm_qm_set_smp(0);
#endif

	/* Bring IP out of reset and enable clock if not already.
	 * AMP mode requires locking
	 */
	apm_qm_indirect_access_lock(1);
	rc = apm86xxx_read_scu_reg(SCU_CLKEN_ADDR, &val);
	if (rc != 0) {
		apm_qm_indirect_access_lock(0);
		printk(KERN_ERR "QM: Failed to read SCU register %d\n", rc);
		return -ENODEV;
	}
	/* Use QMLite to determine if reset is required as it is not
	   used by U-Boot */
	if (val & QMLITE_F1_MASK) {
		reset_qm = 0;
		reset_qml = 0;
	}

	/* reset QM */
	if (reset_qm) {
		clk = clk_get(&pdev->dev, "qm-tm");
		if (IS_ERR(clk)) {
			printk(KERN_ERR "clk_get qm-tm failed\n");
			return -ENODEV;
		}
		clk_enable(clk);
	}
	if (!is_apm86xxx_lite() && reset_qml) {
		clk = clk_get(&pdev->dev, "qml");
		if (IS_ERR(clk)) {
			printk(KERN_ERR "clk_get qml failed\n");
			return -ENODEV;
		}
		/* disable and enable clock/reset */
		clk_enable(clk);
	}
	apm_qm_indirect_access_lock(0);

	/* Detect if QM lite available */
	if (is_apm86xxx_lite())
		apm_qm_set_noqml(1);
	else if (apm_qm_get_smp())
		apm_qm_set_noqml(0);
	else if (mfspr(SPRN_PIR) == 0)
		apm_qm_set_noqml(0);
	else
		apm_qm_set_noqml(1);

	rc = apm_qm_config_set(pdev);

	if (rc) {
		printk(KERN_ERR "apm_qm_config_set failed\n");
		return -1;
	}

	memset(&apm_qm_mb_tasklet_table, 0, sizeof(apm_qm_mb_tasklet_table));
	if (!apm_qm_get_noqml()) {
		/* Configure QML QID Remap table */
		val = QID00_WR(DSLEEP_ENET_RX_FP_Q) |
			QID10_WR(DSLEEP_ENET_RX_Q)  |
			QID20_WR(DSLEEP_ENET_TX_Q);
		apm_qm_wr32(IP_BLK_QML, CSR_QML_REMAP0_ADDR, val);
	}
#if defined(CONFIG_APM_QOS)
	/* Set slope to achieve preferred shaping affect on AVB */
	/* 3900 ==> shape to 500Kbps */
	/* 1850 ==> shape to 1000Kbps */
	val = INIT_F2_WR(1850);
#else
	val = INIT_F2_WR(249);
#endif
	apm_qm_update_tm_timer(IP_BLK_QM, val);
	apm_qm_rd32(IP_BLK_QM, CSR_CU_TIMER_ADDR, &val);
	QM_DBG("CSR_CU_TIMER: %d\n", val);

	/* configure and initialize QM block */
	apm_qm_init_queue(ARRAY_SIZE(mb_cfg_pqs));

	QM_DBG("Creating proc entry\n");
	entry = proc_create(APM_QM_DRIVER_NAME, 0644, NULL, &apm_qm_driver_fops);
	if (entry == NULL) {
		printk(KERN_ERR PFX " init failed\n");
		return -1;
	}
#if defined(CONFIG_SYSFS)
	apm_qm_add_sysfs(pdev->dev.driver);
#endif
	/* Register QM callback function for PPC */
	apm_qm_msg_rx_register(APM_QM_PPC_RTYPE, apm_ppc_rx_msg);

	ready = 1;
	return rc;
}

void apm_qm_disable_mb_irq(u32 mb_id)
{
	mb_irq_ena[mb_id] = 0;
	disable_irq_nosync(mb_to_irq_map[mb_id]);
}
EXPORT_SYMBOL(apm_qm_disable_mb_irq);

void apm_qm_enable_mb_irq(u32 mb_id)
{
	enable_irq(mb_to_irq_map[mb_id]);
	mb_irq_ena[mb_id] = 1;
}
EXPORT_SYMBOL(apm_qm_enable_mb_irq);

bool apm_qm_mb_irq_enabled(u32 mb_id)
{
	return mb_irq_ena[mb_id];
}
EXPORT_SYMBOL(apm_qm_mb_irq_enabled);

int apm_qm_set_mb_affinity(u32 mb_id, u32 core_id)
{
	int rc;
	if ((rc = irq_set_affinity(mb_to_irq_map[mb_id],
				cpumask_of(core_id))) != 0) {
		printk(KERN_ERR "Error %d in irq_set_affinity\n", rc);
	}
	return rc;
}

#if !defined(CONFIG_SMP) && defined(CONFIG_APM86xxx_SHMEM)
int apm_qm_indirect_access_lock(int lock)
{
	if (lock)
		atomic_cpu_lock();
	else
		atomic_cpu_unlock();
	return 0;
}
#endif

static int apm_qm_remove(struct platform_device *pdev)
{
	remove_proc_entry(APM_QM_DRIVER_NAME, NULL);
#if defined(CONFIG_SYSFS)
	apm_qm_remove_sysfs(pdev->dev.driver);
#endif
	printk(KERN_NOTICE PFX "Unloaded %s...\n", APM_QM_DRIVER_STRING);
	return 0;
}

#ifdef CONFIG_PM
static int apm_qm_of_suspend(struct platform_device *pdev, pm_message_t state)
{
	int i;
	int rc = 0;

	printk(KERN_INFO "QM suspend...\n");

	if ((!suspending_to_deepsleep()) || (!apm_qm_get_smp() && (mfspr(SPRN_PIR))))
		return rc;

	printk(KERN_INFO "Saving QM states...\n");
	/* save QM states for all queues */
	for (i = 0; i < QM_MAX_QUEUES; i++) {
		rc = apm_qm_raw_qstate_rd(IP_BLK_QM, i, &q_raw_states[i]);
		if (rc != 0) {
			printk(KERN_ERR "Error reading QM queue %d\n", i);
			return -1;
		}
	}

	printk(KERN_INFO "Disable QM QPcore...\n");
	/* Disable QM QPcore */
	apm_qm_wr32(IP_BLK_QM, CSR_QM_CONFIG_ADDR, 0);

	return rc;
}

static int apm_qm_of_resume(struct platform_device *pdev)
{
	int i;
	u32 val = 0;
	int is_fp = 0;
	int is_vq = 0;
	struct apm_qm_qstate *qstate;
	int rc = 0;

	printk(KERN_INFO "QM resume...\n");

	if (!resumed_from_deepsleep())
		return rc;

	printk(KERN_INFO "Restoring QM states from %d to %d...\n",
		apm_qm_get_first_qid(), apm_qm_get_max_qid());
	/* Restore PBN state */
	for (i = apm_qm_get_first_qid(); i <= apm_qm_get_max_qid(); i++) {
		apm_qm_raw_qstate_wr(IP_BLK_QM, i, &q_raw_states[i]);
		if (apm_qm_is_pbn_valid(i)) {
			qstate = &queue_states[i];
			is_fp = ((qstate->q_type == FREE_POOL) ? 1 : 0);
			is_vq = ((qstate->q_type == V_QUEUE) ? 1 : 0);
			if (is_fp) {
				apm_qm_pb_overwrite(qstate->ip_blk,
							qstate->slave_id,
							qstate->pbn,
							qstate->q_id,
							is_fp);
			} else {
				apm_qm_pb_config(qstate->ip_blk,
						qstate->slave_id,
						qstate->pbn,
						qstate->q_id,
						is_fp, is_vq);
			}
		}
	}

	/* Reset mailbox counters */
	apm_qm_alloc_mbox();

	/* Re-program QM mailbox base address to QM */
	apm_qm_set_enq_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_enq_mbox_paddr);
	apm_qm_set_dq_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_dq_mbox_paddr);
	apm_qm_set_fp_mbox_addr(qm_mailbox_type <= QM_MAILBOX_IOCOHERENT ? 1 : 0,
			qm_fp_mbox_paddr);

	if (!apm_qm_get_smp() && mfspr(SPRN_PIR))	/* For AMP1, this is it */
		return rc;

	printk(KERN_INFO "Enable QM QPcore...\n");

	/* Enable QPcore and assign error queue */
	val = ENABLE_F6_SET(val, 1);
#if defined(CONFIG_APM862xx)
	val = ERROR_QID_F2_SET(val, ERR_QUEUE_ID);
	val = ERROR_QUEUE_ENABLE_F2_SET(val, APM_QM_ERROR_Q_ENABLE);
#endif
	apm_qm_wr32(IP_BLK_QM, CSR_QM_CONFIG_ADDR, val);

#if !defined(CONFIG_APM862xx)
	val = 0;
	val = UNEXPECTED_EN_SET(val, APM_QM_ERROR_Q_ENABLE);
	val = UNEXPECTED_QID_SET(val, ERR_QUEUE_ID);
	val = EXPECTED_EN_SET(val, APM_QM_ERROR_Q_ENABLE);
	val = EXPECTED_QID_SET(val, ERR_QUEUE_ID);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_0_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_1_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_2_ERRQ_ADDR, val);
	apm_qm_wr32(IP_BLK_QM, CSR_DOM_3_ERRQ_ADDR, val);
#endif

	/* Enable QM mailbox interrupts and deq axi error interrupt */
	apm_qm_wr32(IP_BLK_QM, QM_INTERRUPTMASK_ADDR, 0x00000005);

	mb();
	return rc;
}
#endif

int apm_qm_shutdown_q(int q_num)
{
	struct apm_qm_raw_qstate raw_qstate = {0, 0, 0, 0};
	struct apm_qm_qstate *qstate;

	if (q_num < 0 || q_num >= QM_MAX_QUEUES) {
		QM_PRINT("Queue number is not valid\n");
			return -1;
	}

	qstate = &queue_states[q_num];

	if (qstate->valid && apm_qm_is_pbn_valid(qstate->q_id)) {
		QM_DBG("Disable QID %d slave id %d pbn %d\n",
			qstate->q_id, qstate->slave_id, qstate->pbn);

		apm_qm_pb_disable(qstate->ip_blk, qstate->slave_id,
				qstate->pbn, qstate->q_id);
		apm_qm_raw_qstate_wr(IP_BLK_QM, qstate->q_id, &raw_qstate);
		qstate->valid = 0;
	}

	return 0;
}

int apm_qm_shutdown(void)
{
#if !defined(CONFIG_SMP) && defined(CONFIG_APM862xx)
	struct apm_qm_raw_qstate raw_qstate;
	int i;
	struct apm_qm_qstate *qstate;

	printk(KERN_INFO "QM shutdown starts...\n");

	memset(&raw_qstate, 0, sizeof(struct apm_qm_raw_qstate));
	for (i = apm_qm_get_first_qid(); i <= apm_qm_get_max_qid(); i++) {
		qstate = &queue_states[i];
		if (apm_qm_is_pbn_valid(i)) {
			QM_DBG("Disable QID %d slave id %d pbn %d\n",
				qstate->q_id, qstate->slave_id, qstate->pbn);

			apm_qm_pb_disable(qstate->ip_blk, qstate->slave_id,
				qstate->pbn, qstate->q_id);
			apm_qm_raw_qstate_wr(IP_BLK_QM, i, &raw_qstate);
			apm_qm_clr_pbn_valid(i);
		}

	}

	printk(KERN_INFO "QM shutdown end...\n");
#endif
	ready = 0;
	return 0;
}
EXPORT_SYMBOL(apm_qm_shutdown);

static struct of_device_id apm_qm_match[] = {
	{ .compatible	= "mb-qmtm", },
	{ .compatible	= "apm,mb-qmtm", },
	{ },
};

static struct platform_driver apm_qm_driver = {
	.driver.name		= "apm-qmtm",
	.driver.of_match_table	= apm_qm_match,
	.probe		= apm_qm_probe,
	.remove		= apm_qm_remove,
#ifdef CONFIG_PM
	.suspend = apm_qm_of_suspend,
	.resume = apm_qm_of_resume,
#endif
};

static int __init apm_qm_driver_init(void)
{
	return platform_driver_register(&apm_qm_driver);
}

static void __exit apm_qm_driver_cleanup(void)
{
	platform_driver_unregister(&apm_qm_driver);
}

subsys_initcall(apm_qm_driver_init);
module_exit(apm_qm_driver_cleanup);

EXPORT_SYMBOL(apm_qm_pull_comp_msg);
EXPORT_SYMBOL(apm_qm_push_msg);
EXPORT_SYMBOL(apm_qm_pb_set);
EXPORT_SYMBOL(apm_qm_msg_rx_register);
EXPORT_SYMBOL(apm_qm_msg_rx_unregister);
EXPORT_SYMBOL(apm_qm_raw_qstate_rd);
EXPORT_SYMBOL(apm_qm_fp_alloc_buf);
EXPORT_SYMBOL(apm_qm_pb_get);
EXPORT_SYMBOL(apm_qm_fp_dealloc_buf);
EXPORT_SYMBOL(apm_qm_pull_msg);
EXPORT_SYMBOL(apm_qm_qstate_rd);
EXPORT_SYMBOL(apm_qm_pull_comp_flush);
EXPORT_SYMBOL(apm_qm_pull_comp_msg2);
EXPORT_SYMBOL(apm_qm_get_compl_queue);
EXPORT_SYMBOL(apm_qm_mailbox_rx_register);
EXPORT_SYMBOL(apm_qm_mailbox_rx_unregister);
EXPORT_SYMBOL(apm_qm_alloc_q);
EXPORT_SYMBOL(apm_qm_free_q);
EXPORT_SYMBOL(apm_qm_get_vq);
EXPORT_SYMBOL(apm_qm_alloc_vq);
EXPORT_SYMBOL(apm_qm_fp_dealloc_flush);
EXPORT_SYMBOL(apm_qm_alt_enqueue_enable);
EXPORT_SYMBOL(apm_qm_qid2mb);
EXPORT_SYMBOL(apm_qm_ready);
EXPORT_SYMBOL(apm_qm_c2c_msg_wait_fc);

MODULE_VERSION(APM_QM_DRIVER_VERSION);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Keyur Chudgar <kchudgar@apm.com>");
MODULE_DESCRIPTION("APM QM/TM driver");
