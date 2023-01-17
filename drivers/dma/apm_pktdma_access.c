/**
 * Applied Micro APM86xxx SoC PktDMA Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * Author: Shasi Pulijala <spulijala@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * This file contains Linux platform specific PktDMA driver code for APM86xxx
 * SoC.
 *
 */
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/clk.h>
#include <linux/mempool.h>
#include <asm/uaccess.h>
#include <asm/ipp.h>
#include <asm/apm86xxx_pm.h>
#include <asm/apm86xxx_soc.h>
#include <asm/apm_qm_cfg.h>

#include "apm_pktdma_access.h"
#include "apm_dma_csr.h"
#include "apm_pktdma_core.h"

#define RES_SIZE(r)	((r)->end - (r)->start + 1)

mempool_t *op_slab_pool;
mempool_t *opnode_slab_pool;
struct kmem_cache *op_slab_cache;
struct kmem_cache *opnode_slab_cache;

struct iodma_pdev p_dev;

struct apm_iodma_user_context {
	dma_async_tx_callback callback;
	void *callback_param;
};

int apm_pktdma_read_reg(u32 offset, u32 *data)
{
	*data = in_be32((void __iomem *) ((u8 *) p_dev.csr_base + offset));
	PKTDMA_DCSR("CSR RD: 0x%p Data: 0x%08X",
		(u8 *) p_dev.csr_base + offset, *data);
	return 0;
}

int apm_pktdma_read_diag_reg(u32 offset, u32 *data)
{
	*data = in_be32((void __iomem *) ((u8 *) p_dev.csr_base_diag + offset));
	PKTDMA_DCSR("CSR RD: 0x%p Data: 0x%08X",
	       (u8 *) p_dev.csr_base_diag + offset, *data);
	return 0;
}

int apm_pktdma_read_qmi_reg(u32 offset, u32 *data)
{
	*data = in_be32((void __iomem *) ((u8 *) p_dev.csr_base_qmi + offset));
	PKTDMA_DCSR("CSR RD: 0x%p Data: 0x%08X",
		    (u8 *) p_dev.csr_base_qmi + offset, *data);
	return 0;
}

int apm_pktdma_write_qmi_reg(u32 offset, u32 data)
{
	PKTDMA_DCSR("CSR WR: 0x%p Data: 0x%08X",
		    (u8 *) p_dev.csr_base_qmi + offset, data);
	out_be32((void __iomem *) ((u8 *) p_dev.csr_base_qmi + offset), data);
	return 0;
}

int apm_pktdma_write_reg(u32 offset, u32 data)
{
	PKTDMA_DCSR("CSR WR: 0x%p Data: 0x%08X",
	       (u8 *) p_dev.csr_base + offset, data);
	out_be32((void __iomem *) ((u8 *) p_dev.csr_base + offset), data);
	return 0;
}

int apm_pktdma_write_diag_reg(u32 offset, u32 data)
{
	PKTDMA_DCSR("CSR WR: 0x%p Data: 0x%08X",
		    (u8 *) p_dev.csr_base_diag + offset, data);
	out_be32((void __iomem *) ((u8 *) p_dev.csr_base_diag + offset), data);
	return 0;
}

/**
 * Operation Management Functions
 */
struct iodma_op_state *apm_pktdma_op_get(void)
{
	struct iodma_op_state *op;
#ifdef PKTDMA_OP_CACHE_LIST
	unsigned long flags;

	spin_lock_irqsave(&p_dev.cache_lock, flags);
	if (!list_empty(&p_dev.qinfo.op_cache)) {
		struct list_head *entry = p_dev.qinfo.op_cache.next;
		list_del(entry);
		op = list_entry(entry, struct iodma_op_state, next);
		--p_dev.qinfo.op_cache_cnt;
		APM_PKTDMA_DOP_CACHE("allocate op cached 0x%p", op);
#if defined(APM_PKTDMA_DEBUG)
		op->signature = PKTDMA_OP_SIGN;
#endif
		spin_unlock_irqrestore(&p_dev.cache_lock, flags);
		return op;
	}
	spin_unlock_irqrestore(&p_dev.cache_lock, flags);
#endif
        op = mempool_alloc(op_slab_pool, GFP_KERNEL);
	if (op == NULL)
		goto done;
#if defined(APM_PKTDMA_DEBUG)
	op->signature = PKTDMA_OP_SIGN;
#endif
	APM_PKTDMA_DOP_CACHE("allocate op 0x%p", op);
done:
	return op;
}

void apm_pktdma_op_free(struct iodma_op_state *op)
{
#ifdef PKTDMA_OP_CACHE_LIST
	unsigned long flags;

#if defined(APM_PKTDMA_DEBUG)
	if (op->signature != PKTDMA_OP_SIGN) {
		printk(KERN_ERR "PktDMA free invalid operation state 0x%p\n",
			op);
		return;
	}
#endif

	if (p_dev.qinfo.op_cache_cnt >= APM_PKTDMA_OP_CACHE_MAX) {
		APM_PKTDMA_DOP_CACHE("free op 0x%p", op);
#if defined(APM_PKTDMA_DEBUG)
		op->signature = 0;
#endif
                mempool_free(op, op_slab_pool);
		return;
	}

	spin_lock_irqsave(&p_dev.cache_lock, flags);
#if defined(APM_PKTDMA_DEBUG)
	op->signature = 0;
#endif
	++p_dev.qinfo.op_cache_cnt;
	list_add(&op->next, &p_dev.qinfo.op_cache);
	APM_PKTDMA_DOP_CACHE("free op cached 0x%p", op);
	spin_unlock_irqrestore(&p_dev.cache_lock, flags);
#else
#if defined(APM_PKTDMA_DEBUG)
	if (op->signature != PKTDMA_OP_SIGN) {
		printk(KERN_ERR "PktDMA free invalid operation state 0x%p\n",
			op);
		return;
	}
#endif

	APM_PKTDMA_DOP_CACHE("free op 0x%p", op);
        mempool_free(op, op_slab_pool);
#endif
}

unsigned long apm_pktdma_msg_enq_lock(void)
{
	unsigned long flags;
	spin_lock_irqsave(&p_dev.enq_msg_lock, flags);
	return flags;
}

void apm_pktdma_msg_enq_unlock(unsigned long flags)
{
	spin_unlock_irqrestore(&p_dev.enq_msg_lock, flags);
}

static struct rb_root pktdma_ops_root;

static spinlock_t pktdma_ops_lock;
static int current_op_index = 0;
static struct timer_list pktdma_ops_timer;


struct pktdma_op_node {
    struct rb_node node;
    int index;
    void *op;
    apm_free_cb f_cb;
    struct timeval ts;
};

void* apm_pktdma_find_op(int val)
{
    struct rb_node *node;
    struct pktdma_op_node *op_node = NULL;
    unsigned long flags = 0;
    void* op = NULL;
    spin_lock_irqsave(&pktdma_ops_lock, flags);
    node = pktdma_ops_root.rb_node;
    while (node) {
        op_node = container_of(node, struct pktdma_op_node, node);
        if (op_node->index == val) {
            op = op_node->op;
            rb_erase(&op_node->node, &pktdma_ops_root);
            kmem_cache_free(opnode_slab_cache, op_node);
            break;
        }
        if (val < op_node->index) {
            node = node->rb_left;
        } else if (val > op_node->index) {
            node = node->rb_right;
        }
    }
    spin_unlock_irqrestore(&pktdma_ops_lock, flags);
    return op;
}

int apm_pktdma_add_op(void* op, apm_free_cb f_cb)
{
    struct pktdma_op_node* new_node = NULL;
    struct rb_node **new, *parent = NULL;
    unsigned long flags = 0;

    new_node = kmem_cache_alloc(opnode_slab_cache, GFP_KERNEL);
    if (!new_node) {
        return 0;
    }
    memset(new_node, 0, sizeof(*new_node));
    new_node->op = op;
    spin_lock_irqsave(&pktdma_ops_lock, flags);
    if (current_op_index == 0x0FFFFFFF) {
        current_op_index = 0;
    }
    new_node->f_cb = f_cb;
    do_gettimeofday(&(new_node->ts));
    new_node->index = ++current_op_index;
    new= &(pktdma_ops_root.rb_node);
    while (*new) {
        struct pktdma_op_node* op_node = container_of(*new, struct pktdma_op_node, node);
        parent = *new;
        if (new_node->index < op_node->index) {
            new = &((*new)->rb_left);
        } else if (new_node->index > op_node->index) {
            new = &((*new)->rb_right);
        }
    }
    rb_link_node(&new_node->node, parent, new);
    rb_insert_color(&new_node->node, &pktdma_ops_root);
    spin_unlock_irqrestore(&pktdma_ops_lock, flags);
    return (new_node->index);
}

void apm_pktdma_purge_ops (void)
{
    struct rb_node *n,*nn;
    unsigned long flags = 0;
    struct timeval now;

    n = rb_first(&pktdma_ops_root);
    do_gettimeofday(&now);

    spin_lock_irqsave(&pktdma_ops_lock, flags);
    while(n) {
        u64 elapsed_msecs;
        struct pktdma_op_node* op_node = container_of(n, struct pktdma_op_node, node);
        nn = rb_next(n);
        elapsed_msecs = (timeval_to_ns(&now) - timeval_to_ns(&op_node->ts));
        do_div(elapsed_msecs, NSEC_PER_SEC/1000);
        if (elapsed_msecs > 60000) {
            rb_erase(&op_node->node, &pktdma_ops_root);
            kmem_cache_free(opnode_slab_cache, op_node);
        }
        n = nn;
    }
    spin_unlock_irqrestore(&pktdma_ops_lock, flags);
}

void pktdma_ops_timer_cb (unsigned long data)
{
    int ret;
    apm_pktdma_purge_ops();
    ret = mod_timer(&pktdma_ops_timer, jiffies + msecs_to_jiffies(1000));
}

void apm_pktdma_op_list_init (void)
{
    int ret;
    pktdma_ops_root = RB_ROOT;
    opnode_slab_cache = kmem_cache_create("opnode slab cache",
                                      sizeof(struct pktdma_op_node),
                                      0,
                                      SLAB_HWCACHE_ALIGN,
                                      NULL);
    setup_timer(&pktdma_ops_timer, pktdma_ops_timer_cb, 0);
    ret = mod_timer(&pktdma_ops_timer, jiffies + msecs_to_jiffies(1000));
    spin_lock_init(&pktdma_ops_lock);
}

extern apm_qm_msg_fn_ptr qm_cb_fn_table[APM_QM_MAX_RTYPE];
static void apm_pktdma_bh_tasklet_cb(unsigned long data)
{
	struct apm_qm_mb_tasklet *pktdma_data;
	struct apm_pktdma_msg_done comp_msg;
	struct apm_qm_msg_desc desc;
	struct iodma_op_state *op;

        memset(&comp_msg, 0, sizeof(comp_msg));
        memset(&desc, 0, sizeof(desc));
	pktdma_data = (struct apm_qm_mb_tasklet *) data;

	desc.is_msg16 = 0;
	desc.msg = &comp_msg;
	desc.mb_id = pktdma_data->mailbox;
	desc.qid = pktdma_data->queue;

	while (apm_qm_pull_msg(&desc) != -1) {
                struct apm_qm_msg64 *msg = NULL;
                struct apm_qm_msg16 *msg16;
                msg = (struct apm_qm_msg64 *)desc.msg;
                msg16 = &msg->msg32_1.msg16;
		op = apm_pktdma_find_op(comp_msg.dmsg1_2.uinfo);
		if (likely(op)) {
			op->dmsg = &comp_msg;
#if defined(APM_PKTDMA_DEBUG_XTRA)
			p_dev.pktdma_recv_pkts++;
#endif
			apm_pktdma_op_cb(op);
		} else {
			PKTDMA_ERR("Null ctx from QMsg for index %x", comp_msg.dmsg1_2.uinfo);
		}
                memset(&comp_msg, 0, sizeof(comp_msg));
	}

	apm_qm_enable_mb_irq(desc.mb_id);
}

int apm_pktdma_get_fp(struct apm_pktdma_buf_info *fp_buf)
{
	struct apm_qm_msg_desc msg_desc;
	struct apm_qm_msg16 msg;
	int rc;
	u32 core_id = apm_processor_id();

	if (p_dev.qinfo.queues[core_id].ppc_fpid <= 0) {
		return -ENODEV;
	}
	msg_desc.msg = &msg;
	msg_desc.mb_id = p_dev.qinfo.queues[core_id].ppc_fpmbid;
	msg_desc.qid = p_dev.qinfo.queues[core_id].ppc_fpid;
	PKTDMA_DRXTX("Retrieve FP PPC QID %d MID %d",
		msg_desc.qid, msg_desc.mb_id);
	rc = apm_qm_fp_alloc_buf(&msg_desc);
	if (rc) {
		PKTDMA_ERR("Failed to allocate FP buffer QID %d error %d",
			msg_desc.qid, rc);
		return rc;
	}
	if (msg.DataAddrMSB == 0 && msg.DataAddrLSB == 0) {
		PKTDMA_ERR("FP returned NULL pointer");
		return -ENOMEM;
	}
	PKTDMA_DRXTX("FP buffer PADDR 0x%02X.%08X len %d",
		msg.DataAddrMSB, msg.DataAddrLSB, msg.BufDataLen);

	/* Convert to virtual address in Linux */
	fp_buf->addr = phys_to_virt(MAKE64(msg.DataAddrMSB, msg.DataAddrLSB));
	fp_buf->fp_id = msg.FPQNum;
	fp_buf->datalen = msg.BufDataLen;

	return 0;
}
EXPORT_SYMBOL(apm_pktdma_get_fp);

int apm_pktdma_init_pool(int queue_id, int size, int no_of_buffs)
{
	struct apm_qm_msg_desc fp_msg_desc;
	struct apm_qm_msg16 msg;
	void *data_addr;
	u64 phy_addr;
	int i;

	fp_msg_desc.msg = &msg;
	fp_msg_desc.qid = queue_id;

	memset(&msg, 0, sizeof(msg));
	msg.BufDataLen = apm_pktdma_buf_len_set(size);
	msg.FPQNum = queue_id;
	msg.C = apm_pktdma_is_coherent();
	for (i = 0; i < no_of_buffs; i++) {
		/* Due to buffer used for link list mode of QM,
		   buffer musts be 16B aligned. As Linux is 32B aligned,
		   we can just use actual buffer size */
		data_addr = kzalloc(size, GFP_KERNEL);
		if (!data_addr) {
			PKTDMA_ERR("Failed to allocate buffer size %d", size);
			return -ENOMEM;
		}
		phy_addr = virt_to_phys(data_addr);
		msg.UserInfo = (unsigned long) data_addr;
#if defined(CONFIG_NOT_COHERENT_CACHE)
		invalidate_dcache_range((u32)data_addr,
					 (u32) data_addr + size);
#endif
		msg.DataAddrMSB = HIDWORD(phy_addr);
		msg.DataAddrLSB = LODWORD(phy_addr);

		/* Push buffer into HW free pool */
		if (apm_qm_fp_dealloc_buf(&fp_msg_desc) != 0) {
			PKTDMA_ERR(KERN_ERR "Can't fill FP ID %d", queue_id);
			return -EINVAL;
		}
	}
	return 0;
}

#define MAX_LOOP_POLL_TIMEMS	500
#define MAX_LOOP_POLL_CNT	10
#define ACCESS_DELAY_TIMEMS	(MAX_LOOP_POLL_TIMEMS / MAX_LOOP_POLL_CNT)

void apm_pktdma_get_total_chan(struct dma_chan_info *ch_info)
{
	int i;

	ch_info->max_chan =  p_dev.qinfo.tx_ch_cnt;
	for (i = 0; i < ch_info->max_chan; i++) {
		ch_info->chan_en[i] = p_dev.qinfo.chan[i];
                if (p_dev.qinfo.tx_q[ch_info->chan_en[i]].tx_max_slot[0] == 0) {
                    /* if no slots are available, channel is reserved */
		    ch_info->chan_rsvd[i] = 1;
                } else {
                    if (p_dev.qinfo.tx_q[i].slot_rsvd >=
                            (PKTDMA_MAX_OPS_EXT + PKTDMA_MAX_OPS_INT))
                            ch_info->chan_rsvd[i] = 1;
                    else
                            ch_info->chan_rsvd[i] = 0;
                }
	}
}
EXPORT_SYMBOL(apm_pktdma_get_total_chan);

int apm_pktdma_chan2qid(int chid, int cos)
{
	if (chid >= p_dev.qinfo.tx_ch_cnt || cos >= APM_PKTDMA_NUM_COS)
		return 0;
	return p_dev.qinfo.tx_q[chid].tx_qid[cos];
}
EXPORT_SYMBOL(apm_pktdma_chan2qid);

static int apm_pktdma_tx_qconfig(void)
{
	struct apm_qm_qstate *qstates;
	struct apm_qm_qalloc qalloc;
	int num_chan;
	int i;
	int j;
	int rc;

	memset(&qalloc, 0, sizeof(struct apm_qm_qalloc));

	if (p_dev.qinfo.no_tm) {
		num_chan = p_dev.qinfo.tx_ch_cnt;
		qstates = kzalloc(num_chan * sizeof(struct apm_qm_qstate),
				GFP_KERNEL);
		if (qstates == NULL) {
			PKTDMA_ERR("Unable to allocate memory for queue "
				"states");
			return -ENOMEM;
		}
		memset(qstates, 0, num_chan * sizeof(struct apm_qm_qstate));
		qalloc.qstates = qstates;
		qalloc.qm_ip_blk = IP_BLK_QM;
		qalloc.ip_blk = IP_DMA;
		qalloc.q_type = P_QUEUE;
		qalloc.q_count = num_chan;
		qalloc.direction = DIR_EGRESS;
		qalloc.qsize = SIZE_64KB;
#ifdef CONFIG_SMP
		qalloc.ppc_id = 0;
#else
		qalloc.ppc_id = apm_processor_id();
#endif
		qalloc.thr_set = 1;

		if ((rc = apm_qm_alloc_q(&qalloc)) != 0) {
			PKTDMA_ERR("Unable to allocate egress work queues "
				"for PKTDMA error %d", rc);
			kfree(qstates);
			return -EINVAL;
		}

		for (i = 0; i < p_dev.qinfo.tx_ch_cnt; i++) {
			struct pktdma_chan_qid *qcfg;

			if (p_dev.qinfo.chan[i] >= PKTDMA_CHID_MAX)
				continue;
			/* Clear QM and PktDMA PBN */
			apm_pktdma_pbn_clr(qstates[i].slave_id, qstates[i].pbn);

			qcfg = &p_dev.qinfo.tx_q[p_dev.qinfo.chan[i]];
			for (j = 0; j < APM_PKTDMA_NUM_COS; j++) {
				int slot_rsvd;

				qcfg->tx_qid[j] = qstates[i].q_id;
				slot_rsvd = qcfg->slot_rsvd;
				slot_rsvd -= PKTDMA_MAX_OPS_INT;
				qcfg->tx_max_slot[j] = PKTDMA_MAX_OPS_EXT -
							slot_rsvd;
				atomic_set(&qcfg->tx_inflight[j], 0);
				PKTDMA_DEBUG("Channel %d COS %d QID %d slot %d",
					p_dev.qinfo.chan[i], j,
					qcfg->tx_qid[j], qcfg->tx_max_slot[j]);
			}
		}
		kfree(qstates);
		return 0;
	}

	/* TM configuration */
	qstates = kzalloc(sizeof(struct apm_qm_qstate), GFP_KERNEL);
	if (qstates == NULL) {
		PKTDMA_ERR("Unable to allocate memory for queue states");
		return -ENOMEM;
	}

	for (j = 0; j < p_dev.qinfo.tx_ch_cnt; j++) {
		struct pktdma_chan_qid *qcfg;

		qcfg = &p_dev.qinfo.tx_q[p_dev.qinfo.chan[j]];

		qalloc.qstates = qstates;
		qalloc.qm_ip_blk = IP_BLK_QM;
		qalloc.ip_blk = IP_DMA;
#ifdef CONFIG_SMP
		qalloc.ppc_id = 0;
#else
		qalloc.ppc_id = apm_processor_id();
#endif
		qalloc.q_count = 1;
		qalloc.direction = DIR_EGRESS;
		qalloc.qsize = SIZE_64KB;
		qalloc.thr_set = 1;

		/* Retrieve a VQ id */
		qcfg->tx_vqid = apm_qm_get_vq(IP_DMA);
		PKTDMA_DEBUG("Channel %d TM VQID %d Alg %d",
			p_dev.qinfo.chan[j], qcfg->tx_vqid, qcfg->tx_vqid_alg);

		/* Create children PQs */
		qalloc.q_type    = QM_CFG_QTYPE_PQ;
		qalloc.parent_vq = qcfg->tx_vqid;
		qalloc.vqen      = 1;
		for (i = 0; i < APM_PKTDMA_NUM_COS; i++) {
			int slot_rsvd;

			memset(qstates, 0, sizeof(struct apm_qm_qstate));
			if ((rc = apm_qm_alloc_q(&qalloc)) != 0) {
				PKTDMA_ERR(KERN_ERR
					"could not allocate child PQ error %d",
					rc);
				kfree(qstates);
				return rc;
			}
			/* Clear QM and PktDMA PBN */
			apm_pktdma_pbn_clr(qstates->slave_id, qstates->pbn);

			qcfg->tx_qid[i] = qstates->q_id;
			slot_rsvd = qcfg->slot_rsvd;
			slot_rsvd -= PKTDMA_MAX_OPS_INT;
			qcfg->tx_max_slot[j] = PKTDMA_MAX_OPS_EXT - slot_rsvd;
			atomic_set(&qcfg->tx_inflight[i], 0);
			PKTDMA_DEBUG("Channel %d COS %d QID %d slot %d",
				p_dev.qinfo.chan[i], j,
				qcfg->tx_qid[i], qcfg->tx_max_slot[i]);
		}

		/* Create parent VQ */
		qalloc.q_type    = QM_CFG_QTYPE_VQ;
		qalloc.parent_vq = 0;
		qalloc.vqen      = 0;
		for (i = 0; i < 8; i++) {
			if (i >= APM_PKTDMA_NUM_COS) {
				/* Unused entry must be the VQ id */
				qalloc.pq_sel[i] = qcfg->tx_vqid;
				continue;
			}
			qalloc.pq_sel[i] = qcfg->tx_qid[i];
			qalloc.q_sel_arb[i] = qcfg->tx_vqid_alg;
			qalloc.shape_rate[i] = qcfg->tx_qid_param[i];
			PKTDMA_DEBUG("TM PQ %d Param %d",
				qcfg->tx_qid[i], qcfg->tx_qid_param[i]);
		}

		memset(qstates, 0, sizeof(struct apm_qm_qstate));
		rc = apm_qm_alloc_vq(&qalloc, qcfg->tx_vqid);
		if (rc != 0) {
			PKTDMA_ERR("could not allocate VQ");
			kfree(qstates);
			return rc;
		}
	}
	kfree(qstates);
	return 0;
}

static inline int apm_pktdma_cpuid2ip(int cpuid)
{
	if (cpuid == 0)
		return IP_PPC0;
	return IP_PPC1;
}

static int apm_pktdma_qconfig(void)
{
	struct apm_qm_qstate *qstate;
	struct apm_qm_qalloc qalloc;
	int err;
	int i;

	memset(&qalloc, 0, sizeof(struct apm_qm_qalloc));

	/* Allocate tx queues for PKTDMA Channels */
	err = apm_pktdma_tx_qconfig();
	if (err)
		return err;

	qstate = kmalloc(sizeof(struct apm_qm_qstate), GFP_KERNEL);
	if (qstate == NULL) {
		PKTDMA_ERR("Can not allocate memory for queues state");
		return -ENOMEM;
	}
	/* Allocate egress work queue for PktDMA */
	for (i = 0; i < MAX_CORES; i++) {
		struct apm_qm_qstate *tmp_qstate;
		struct pktdma_queue_ids *dmaq = &p_dev.qinfo.queues[i];

		if (!dmaq->valid)
			continue;
		/* Allocate ingress completion queue for PktDMA */
		tmp_qstate = apm_qm_get_compl_queue(IP_DMA, i);
		dmaq->comp_qid = tmp_qstate->q_id;
		dmaq->comp_mb = tmp_qstate->mb_id;
#ifdef CONFIG_SMP
		apm_qm_set_mb_affinity(dmaq->comp_mb, i);
#endif
		/* Allocate free pool for PktDMA */
		memset(qstate, 0, sizeof(*qstate));
		qalloc.qm_ip_blk = IP_BLK_QM;
		qalloc.ip_blk = IP_DMA;
		qalloc.ppc_id = i;
		qalloc.q_type = FREE_POOL;
		qalloc.q_count = 1;
		qalloc.direction = DIR_EGRESS;
		qalloc.qsize = SIZE_64KB;
		qalloc.qstates = qstate;

		if ((err = apm_qm_alloc_q(&qalloc)) != 0) {
			PKTDMA_ERR("Unable to allocate free pool");
			return -EINVAL;
		}

		dmaq->rx_fp_qid = qstate->q_id;
		dmaq->rx_fp_pbn = qstate->pbn - 0x20;
		/* Clear QM and PktDMA PBN */
		apm_pktdma_pbn_clr(qstate->slave_id, qstate->pbn);

#if !defined(CONFIG_APM867xx)
		/* Allocate free pool processor
                   NOTE: Free pool for processor under PktDMA is only
                         required for AMP mode. */
		memset(qstate, 0, sizeof(*qstate));
		qalloc.qm_ip_blk = IP_BLK_QM;
		qalloc.ip_blk = apm_pktdma_cpuid2ip(i);
		qalloc.ppc_id = i;
		qalloc.q_type = FREE_POOL;
		qalloc.q_count = 1;
		qalloc.direction = DIR_INGRESS;
		qalloc.qsize = SIZE_64KB;
		qalloc.qstates = qstate;
		if ((err = apm_qm_alloc_q(&qalloc)) != 0) {
			PKTDMA_ERR("Unable to allocate free pool");
			return -EINVAL;
		}

		dmaq->ppc_fpid = qstate->q_id;
		dmaq->ppc_fpmbid = qstate->mb_id;
#else
		dmaq->ppc_fpid = 0;	/* Invalid QID */
		dmaq->ppc_fpmbid = 0;
#endif

		PKTDMA_DEBUG("CPU%d CQID %d CMID %d FP QID %d DMA FP: PBN %d"
				" PPC FPID %d PPC MBID %d",
			i, dmaq->comp_qid, dmaq->comp_mb, dmaq->rx_fp_qid,
			dmaq->rx_fp_pbn, dmaq->ppc_fpid, dmaq->ppc_fpmbid);
	}

	return 0;
}

static int apm_pktdma_fpool_init(void)
{
	int i, rc;

	for (i = 0; i < MAX_CORES; i++) {
		struct pktdma_queue_ids *queue = &p_dev.qinfo.queues[i];

		if (!queue->valid)
			continue;
		PKTDMA_DEBUG("Initialize Rx free pool QID %d",
				queue->rx_fp_qid);
		rc = apm_pktdma_init_pool(queue->rx_fp_qid,
					  FREE_POOL_DMA_BUFFER_SIZE,
					  FREE_POOL_DMA_BUFFER_NUM);
		if (rc) {
			PKTDMA_ERR("Failed to initialize free pool QID %d",
				queue->rx_fp_qid);
			return -EINVAL;
		}

		if (queue->ppc_fpid > 0) {
			PKTDMA_DEBUG("Initialize PPC free pool QID %d",
					queue->ppc_fpid);
			rc = apm_pktdma_init_pool(queue->ppc_fpid,
					  FREE_POOL_PPC_BUFFER_SIZE,
					  FREE_POOL_DMA_BUFFER_NUM);
			if (rc) {
				PKTDMA_ERR(
					"Failed to initalize free pool QID %d",
					queue->ppc_fpid);
				return -EINVAL;
			}
		}

	}

	return 0;
}

static int apm_pktdma_is_enable(void)
{
	u32 data;

	apm_pktdma_read_reg(DMA_GCR_ADDR, &data);
	return PKTDMA_EN_RD(data) ? 1 : 0;
}

static int apm_pktdma_enable_clk(void)
{
	struct clk *clk;

	/* Reset PktDMA */
	clk = clk_get(NULL, "pktdma");
	if (IS_ERR(clk)) {
		PKTDMA_ERR("failed to get pktdma clock device");
		return -ENODEV;
	}
	clk_enable(clk);

	return 0;
}

/**
 * Linux Async Functions
 */
#define to_pktdma_chan(chan) container_of(chan, struct apm_pktdma_chan, common)
#define tx_to_ptkdma_slot(tx) \
	container_of(tx, struct apm_pktdma_chan_slot, async_tx)
#define ASYNC_TOTAL_SLOT	(PKTDMA_MAX_OPS_INT/2) /* each slot is 64B */

static int apm_pktdma_hdl_done(struct apm_pktdma_op_result *pktdma_result)
{
	struct apm_pktdma_chan_slot *desc;

	if (pktdma_result->err) {
		printk(KERN_ERR "PktDMA operation error 0x%08X\n",
			pktdma_result->err);
	}
	desc = (struct apm_pktdma_chan_slot *) pktdma_result->ctx;
	if (--desc->msg_cnt == 0) {
		desc->chan->completed_cookie = desc->async_tx.cookie;
		if (desc->async_tx.callback)
			desc->async_tx.callback(desc->async_tx.callback_param);
		desc->async_tx.cookie = -EPERM;
	}
	return 0;
}

static int apm_pktdma_hdl_done_xor(struct apm_pktdma_op_result *pktdma_result)
{
	struct apm_pktdma_chan_slot *desc;

	if (pktdma_result->err) {
		printk(KERN_ERR "PktDMA operation error 0x%08X\n",
			pktdma_result->err);
	}
	desc = (struct apm_pktdma_chan_slot *) pktdma_result->ctx;
	if (--desc->msg_cnt == 0) {
		desc->chan->completed_cookie = desc->async_tx.cookie;
		if (desc->async_tx.callback)
			desc->async_tx.callback(desc->async_tx.callback_param);
		desc->async_tx.cookie = -EPERM;
	}
	return 0;
}

static dma_cookie_t apm_pktdma_desc_assign_cookie(struct apm_pktdma_chan *chan,
				struct apm_pktdma_chan_slot *desc)
{
	dma_cookie_t cookie = chan->common.cookie;
	cookie++;
	if (cookie < 0)
		cookie = 1;
	chan->common.cookie = desc->async_tx.cookie = cookie;
	return cookie;
}

static dma_cookie_t apm_pktdma_tx_submit(struct dma_async_tx_descriptor *tx)
{
	struct apm_pktdma_chan_slot *desc = tx_to_ptkdma_slot(tx);
	struct apm_pktdma_chan *pkt_chan = to_pktdma_chan(tx->chan);
	dma_cookie_t cookie;
	int ret = 0;
	int i;

	spin_lock_bh(&pkt_chan->lock);
	cookie = apm_pktdma_desc_assign_cookie(pkt_chan, desc);
	PKTDMA_DRXTX("Issuing m2m 0x%p msg cnt %d", desc, desc->msg_cnt);
	for (i = 0; i < desc->msg_cnt; i++) {
		PKTDMA_DRXTX("Issuing m2m 0x%p len %d",
			tx, desc->m2m[i].byte_count[0]);
		ret = apm_pktdma_m2m(&desc->m2m[i], 0);
	}
	spin_unlock_bh(&pkt_chan->lock);
	if (ret < 0) {
		PKTDMA_ERR("m2m_xfer error %d", ret);
		return ret;
	}
	return cookie;
}

/**
 * apm_pktdma_alloc_resources -  returns the number of allocated descriptors
 * @chan - allocate descriptor resources for this channel
 *
 */
static int apm_pktdma_alloc_resources(struct dma_chan *chan)
{
	struct apm_pktdma_chan *pkt_chan;
	struct apm_pktdma_chan_slot *slot;
	int idx;

	pkt_chan = to_pktdma_chan(chan);

	/* Allocate descriptor slots */
	do {
		idx = pkt_chan->slots_allocated;
		if (idx == pkt_chan->slots_total)
			break;

		slot = kzalloc(sizeof(*slot), GFP_KERNEL);
		if (!slot) {
			printk(KERN_INFO "PktDMA channel only initialized"
				" %d descriptor slots", idx);
			break;
		}
		dma_async_tx_descriptor_init(&slot->async_tx, chan);
		slot->async_tx.tx_submit = apm_pktdma_tx_submit;
		slot->async_tx.cookie = -EPERM;
		slot->idx = idx;
		slot->chan = pkt_chan;

		spin_lock_bh(&pkt_chan->lock);
		pkt_chan->slots_allocated++;
		list_add_tail(&slot->slot_node, &pkt_chan->all_slots);
		spin_unlock_bh(&pkt_chan->lock);
	} while (pkt_chan->slots_allocated < ASYNC_TOTAL_SLOT);

	if (idx && !pkt_chan->last_used)
		pkt_chan->last_used = list_entry(pkt_chan->all_slots.next,
					struct apm_pktdma_chan_slot,
					slot_node);

	PKTDMA_DEBUG("allocated %d descriptor slots last_used 0x%p",
		pkt_chan->slots_allocated, pkt_chan->last_used);

	return (idx > 0) ? idx : -ENOMEM;
}

static void apm_pktdma_free_resources(struct dma_chan *chan)
{
	struct apm_pktdma_chan *pkt_chan = to_pktdma_chan(chan);
	struct apm_pktdma_chan_slot *iter, *_iter;

	spin_lock_bh(&pkt_chan->lock);
	list_for_each_entry_safe_reverse(
		iter, _iter, &pkt_chan->all_slots, slot_node) {
		list_del(&iter->slot_node);
		kfree(iter);
		pkt_chan->slots_allocated--;
	}
	pkt_chan->last_used = NULL;

	PKTDMA_DEBUG("%s slots_allocated %d\n",
		__func__, pkt_chan->slots_allocated);
	spin_unlock_bh(&pkt_chan->lock);
}

/**
 * ppro_iodma_tx_status - poll the status of an ADMA transaction
 * @chan: ADMA channel handle
 * @cookie: ADMA transaction identifier
 * @txstate: a holder for the current state of the channel
 */
static enum dma_status apm_pktdma_tx_status(struct dma_chan *chan,
			dma_cookie_t cookie, struct dma_tx_state *txstate)
{
	struct apm_pktdma_chan *pkt_chan = to_pktdma_chan(chan);
	dma_cookie_t last_used;
	dma_cookie_t last_complete;
	enum dma_status ret;

	last_used = chan->cookie;
	last_complete = pkt_chan->completed_cookie;

	if (txstate) {
		txstate->last = last_complete;
		txstate->used = last_used;
		txstate->residue = 0;
	}

	ret = dma_async_is_complete(cookie, last_complete, last_used);
	if (ret == DMA_SUCCESS)
		return ret;

	last_used = chan->cookie;
	last_complete = pkt_chan->completed_cookie;

	if (txstate) {
		txstate->last = last_complete;
		txstate->used = last_used;
		txstate->residue = 0;
	}

	return dma_async_is_complete(cookie, last_complete, last_used);
}

/**
 * apm_iodma_issue_pending - flush all pending descriptors to h/w
 */
static void apm_pktdma_issue_pending(struct dma_chan *chan)
{
	/* stub function */
}

static struct apm_pktdma_chan_slot *apm_pktdma_chan_get_slot(
		struct apm_pktdma_chan *chan)
{
	struct apm_pktdma_chan_slot *slot;

	if (chan->last_used->async_tx.cookie != -EPERM)
		return NULL;
	slot = chan->last_used;
	if (chan->last_used->slot_node.next == &chan->all_slots)
		chan->last_used = list_entry(chan->all_slots.next,
					struct apm_pktdma_chan_slot,
					slot_node);
	else
		chan->last_used = list_entry(chan->last_used->slot_node.next,
					struct apm_pktdma_chan_slot,
					slot_node);
	slot->async_tx.cookie = -EBUSY;
	return slot;
}

static struct dma_async_tx_descriptor *apm_pktdma_prep_memcpy(
		struct dma_chan *chan, dma_addr_t dest, dma_addr_t src,
		size_t len, unsigned long flags)
{
	struct apm_pktdma_chan *pkt_chan = to_pktdma_chan(chan);
	struct apm_pktdma_chan_slot *slot;
	int i;

	spin_lock_bh(&pkt_chan->lock);
	slot = apm_pktdma_chan_get_slot(pkt_chan);
	if (slot == NULL) {
		spin_unlock_bh(&pkt_chan->lock);
		printk(KERN_ERR "channel %d unable to get slot\n",
			chan->chan_id);
		return NULL;
	}

	slot->msg_cnt = 1;
	slot->m2m[0].chid = pkt_chan->hw_chid;
	slot->m2m[0].cos = IODMA_DEFAULT_COS;
	slot->m2m[0].sg_count = 1;
	slot->m2m[0].sa = slot->sa[0];
	slot->m2m[0].da = slot->da[0];
	slot->m2m[0].byte_count = slot->len[0];
	slot->m2m[0].cb = apm_pktdma_hdl_done;
	slot->m2m[0].context = slot;
	slot->m2m[0].fby = 0;
	slot->async_tx.flags = flags;
	for (i = 0; len && i < PKTDMA_MAX_XOR; i++) {
#if defined(CONFIG_APM862xx)
		if (len < 32) {
			void *vsrc = phys_to_virt(src);
			void *vdst = phys_to_virt(dest);
			memcpy(vdst, vsrc, len);
			/* Schedule a dump DMA */
			src = pkt_chan->dummy_phys;
			dest = pkt_chan->dummy_phys;
			len = 32;
		}
#endif
		slot->sa[0][i] = src;
		if (len <= IODMA_MAX_BUF_SIZE) {
			slot->len[0][i] = len;
			slot->da[0][0] = dest;	/* Gather op, need to set once */
			break;
		}
		slot->len[0][i] = IODMA_MAX_BUF_SIZE;
		++slot->m2m[0].sg_count;
		len -= IODMA_MAX_BUF_SIZE; /* Max size of a buffer */
		src += IODMA_MAX_BUF_SIZE;
	}
	if (slot->m2m[0].sg_count > 1)
		slot->m2m[0].m2m_mode = IODMA_GATHER;
	else
		slot->m2m[0].m2m_mode = IODMA_COPY;
	spin_unlock_bh(&pkt_chan->lock);
	return &slot->async_tx;
}

static struct dma_async_tx_descriptor *apm_pktdma_prep_xor(
			struct dma_chan *chan, dma_addr_t dest,
			dma_addr_t *src, unsigned int src_cnt, size_t len,
			unsigned long flags)
{
	struct apm_pktdma_chan *pkt_chan = to_pktdma_chan(chan);
	struct apm_pktdma_chan_slot *slot;
	int offset;
	int i;
	int j;

	if (unlikely(!len))
		return NULL;
	BUG_ON(unlikely(len > (IODMA_MAX_BUF_SIZE*SLOT_NUM_QMMSG)));

	spin_lock_bh(&pkt_chan->lock);
	slot = apm_pktdma_chan_get_slot(pkt_chan);
	if (slot == NULL) {
		spin_unlock_bh(&pkt_chan->lock);
		/* As this is not a fatal error due to upper layer retry,
		   wrap around debug macro */
		PKTDMA_DEBUG("channel %d unable to get slot", chan->chan_id);
		return NULL;
	}

	offset = 0;
	PKTDMA_DRXTX("xor prep 0x%p len %d", slot, len);
	for (i = 0; i < SLOT_NUM_QMMSG && len > 0; i++) {
		struct apm_pktdma_m2m_params *m2m = &slot->m2m[i];
		m2m->chid = pkt_chan->hw_chid;
		m2m->cos = IODMA_DEFAULT_COS;
		m2m->sg_count = 0;
		m2m->sa = &slot->sa[i][0];
		m2m->da = &slot->da[i][0];
		m2m->byte_count = &slot->len[i][0];
		m2m->cb = apm_pktdma_hdl_done_xor;
		m2m->context = slot;
		slot->async_tx.flags = flags;
		slot->da[i][0] = dest + offset;
		for (j = 0; j < PKTDMA_MAX_XOR && j < src_cnt; j++) {
			slot->sa[i][j] = src[j] + offset;
			if (len > IODMA_MAX_BUF_SIZE)
				slot->len[i][j] = IODMA_MAX_BUF_SIZE;
			else
				slot->len[i][j] = len;
			++m2m->sg_count;
		}
		m2m->m2m_mode = IODMA_GATHER;
		/* Setting XOR FBY Params */
		m2m->fb.fb_type = DMA_FBY_XOR_2SRC + src_cnt - 2;
		m2m->fby = 1;

		if (len <= IODMA_MAX_BUF_SIZE)
			break;
		len -= IODMA_MAX_BUF_SIZE;
		offset += IODMA_MAX_BUF_SIZE;
	}
	slot->msg_cnt = i + 1;
	PKTDMA_DRXTX("xor prep 0x%p msg cnt %d", slot, slot->msg_cnt);

	spin_unlock_bh(&pkt_chan->lock);

	return &slot->async_tx;
}

#ifdef CONFIG_PM
static int apm_pktdma_suspend(struct platform_device * dev, pm_message_t state)
{

	if (state.event & PM_EVENT_FREEZE) {
		/* To hibernate */
	} else if (state.event & PM_EVENT_SUSPEND) {
		p_dev.poweroff = 1;
		/* To suspend */
	} else if (state.event & PM_EVENT_RESUME) {
		/* To resume */
	} else if (state.event & PM_EVENT_RECOVER) {
		/* To recover from enter suspend failure */
	}

	PKTDMA_ERR("PKTDMA Suspend...");
	return 0;
}

static int apm_pktdma_resume(struct platform_device* dev)
{
	int rc = 0;

	if (!resumed_from_deepsleep())
		return rc;

	if (p_dev.poweroff) {
		/* Reset the PKTDMA hardware */
		rc = apm_pktdma_enable_clk(); /* Re-enable clock */
		if (rc != 0) {
			PKTDMA_ERR("PKTDMA HW Reset failed after powerdown");
			goto err;
		}
		/* Initialize the PKTDMA hardware */
		rc = apm_pktdma_enable_hw();
		if (rc != 0) {
			PKTDMA_ERR("PKTDMA HW Init failed after powerdown");
			goto err;
		}

		p_dev.poweroff = 0;
		PKTDMA_ERR("PKTDMA Resumed");
	}
err:
	return rc;
}
#else
#define apm_pktdma_suspend NULL
#define apm_pktdma_resume NULL
#endif /* CONFIG_PM */

irqreturn_t apm_pktdma_irq(int value, void *id)
{
	apm_pktdma_chk_error();
	return IRQ_HANDLED;
}


static int apm_pktdma_driver_debug_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int apm_pktdma_driver_debug_release(struct inode *inode, struct file *file)
{
	return 0;
}

static int apm_pktdma_driver_debug_write(struct file *file, const char __user
		*user_data, size_t size, loff_t *offset)
{
#if defined(APM_PKTDMA_DEBUG_XTRA)
	int i;
#endif
	switch(*user_data) {
		case 'v':
			printk(KERN_INFO "\nPktDMA Test Driver v0.01\n");
			return size;
#if defined(APM_PKTDMA_DEBUG_XTRA)
		case '1':
			/* Dump Recent QM messages */
			apm_pktdma_dump_qmsges();
			return size;
		case '2':
			printk("Messages Stats:\n");
			printk("DMA Msgs Sent out:%lld\n", p_dev.pktdma_m2m_sent_pkts);
			printk("DMA Compl msges rec:%lld\n", p_dev.pktdma_recv_pkts);
			return size;
		case '3':
			/* Clear stats */
			p_dev.pktdma_m2m_sent_pkts = 0;
			p_dev.pktdma_recv_pkts = 0;
			for (i = 0; i < QMSG_RSV_NUM; i++)
				memset(&p_dev.current_send_msg[i], 0, 64);
			p_dev.cnt_send_msg = 0;
			return size;
#else
		default:
			printk("PKTDMA Extra DEbug is not enable:"
				"Enable APM_PKTDMA_DEBUG_XTRA\n");
			return size;
#endif

	}
	return size;
}
struct file_operations apm_pktdma_driver_debug_fops = {
	.owner		= THIS_MODULE,
	.open		= apm_pktdma_driver_debug_open,
	.release	= apm_pktdma_driver_debug_release,
	.write		= apm_pktdma_driver_debug_write,
};

static int apm_pktdma_of_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct device_node *np = pdev->dev.of_node;
	struct dma_device *dma_dev;
	struct apm_pktdma_chan *chan;
	struct resource	res;
	const u32 *ch_info;
	const u32 *tm_info;
	const u32 *tm_param_info;
	const u32 *slot_rsvd;
	int tm_info_len;
	int tm_param_info_len;
	int chan_id;
	int end_chan;
	int rc, i;
	u32 len;
	u32 data;
	struct proc_dir_entry *entry;
#ifndef CONFIG_SMP
	u32 core_id = apm_processor_id();
#endif

	memset(&p_dev, 0, sizeof(p_dev));

	dev_set_drvdata(dev, &p_dev);
	p_dev.pdev = pdev;
	p_dev.device = dev;

	/* Determine if XOR and TM features supported */
	p_dev.qinfo.no_xor = (is_apm86xxx_lite() || is_apm867xx()) ? 1 : 0;
	p_dev.qinfo.no_tm = is_apm86xxx_lite() ? 1 : 0;

	rc = of_address_to_resource(np, 0, &res);
	if (rc) {
		PKTDMA_ERR("No resource in DTS");
		return -ENODEV;
	}
	p_dev.csr_base_p = res.start;

	/* Remap dma register region */
	p_dev.csr_base = ioremap_nocache(p_dev.csr_base_p, RES_SIZE(&res));
	p_dev.csr_base_diag = p_dev.csr_base + APM_IODMA_GLBL_DIAG_CSR_OFFSET;
	p_dev.csr_base_qmi = p_dev.csr_base + APM_IODMA_QMI_SLAVE_OFFSET;
	PKTDMA_DEBUG("CSR PAddr 0x%02X.%08X VAddr 0x%p size %lld",
		     HIDWORD(res.start), LODWORD(res.start),
		     p_dev.csr_base, RES_SIZE(&res));

	/* Retrieve channel available */
	ch_info = of_get_property(np, "ch-info", &len);
	if (!ch_info) {
		PKTDMA_ERR("No channel info in DTS");
		rc = -EINVAL;
		goto err;
	}
	p_dev.qinfo.tx_ch_cnt = len / 4;

	/* Retrieve channel reserve slot for use by SlimPRO */
	slot_rsvd = of_get_property(np, "slot-rsvd", &len);
	if (slot_rsvd && len != (4 * p_dev.qinfo.tx_ch_cnt)) {
		slot_rsvd = NULL;
		printk(KERN_INFO "slot-rsvd mismatch with channel info\n");
	}

	/* Retrieve TM info*/
	tm_info = of_get_property(np, "tm", &tm_info_len);
	tm_param_info = of_get_property(np, "tm-param", &tm_param_info_len);
	if (!tm_info || !tm_param_info) {
		p_dev.qinfo.no_tm = 1;	/* Assume non-TM configuration */
	} else if (tm_info_len != 4*p_dev.qinfo.tx_ch_cnt) {
		PKTDMA_ERR("TM DTS setting mismatch");
		p_dev.qinfo.no_tm = 1;	/* Assume non-TM configuration */
	} else if (tm_param_info_len !=
				APM_PKTDMA_NUM_COS*4*p_dev.qinfo.tx_ch_cnt) {
		PKTDMA_ERR("TM parameter DTS setting mismatch");
		p_dev.qinfo.no_tm = 1;	/* Assume non-TM configuration */
	}

	/* Setup queue configuration from DTS */
	for (i = 0; i < p_dev.qinfo.tx_ch_cnt; i++) {
		struct pktdma_chan_qid *qcfg;
		int j;

		if (ch_info[i] >= PKTDMA_CHID_MAX)
			continue;
		p_dev.qinfo.chan[i] = ch_info[i];
		qcfg = &p_dev.qinfo.tx_q[ch_info[i]];
		qcfg->valid = 1;
		qcfg->slot_rsvd = slot_rsvd ? slot_rsvd[i] : 0;
		if (!p_dev.qinfo.no_tm) {
			/* Retrieve TM configuration */
			qcfg->tx_vqid_alg = tm_info[i];
			for (j = 0; j < APM_PKTDMA_NUM_COS; j++)
				qcfg->tx_qid_param[j] =
					tm_param_info[i*APM_PKTDMA_NUM_COS+j];
		}
	}

	/* Determine number of processor */
#ifdef CONFIG_SMP
	for (i = 0; i < MAX_CORES; i++)
		p_dev.qinfo.queues[i].valid = 1;
#else
	p_dev.qinfo.queues[core_id].valid = 1;
#endif

	/* Enable IP */
	rc = apm_pktdma_enable_clk();
	if (rc) {
		PKTDMA_ERR("Clk enable failed");
		goto err;
	}
	if (!apm_pktdma_is_enable())
		apm_pktdma_enable_hw();

	data = 0;
	apm_pktdma_read_reg(DMA_IPBRR_ADDR, &data);
	PKTDMA_DEBUG("PktDMA Identification: %02d.%02d.%02d",
		     REV_NO_RD(data), BUS_ID_RD(data), DEVICE_ID_RD(data));

	/* Configure Pkt DMA queue */
	if ((rc = apm_pktdma_qconfig()))
		goto err;

	PKTDMA_DEBUG("Configure free pool");
	rc = apm_pktdma_fpool_init();
	if (rc)
		goto err;

#ifdef PKTDMA_OP_CACHE_LIST
	INIT_LIST_HEAD(&p_dev.qinfo.op_cache);
	spin_lock_init(&p_dev.cache_lock);
#endif
	spin_lock_init(&p_dev.enq_msg_lock);

	/* Register Linux Async DMA for memcpy channel only */
	dma_dev = &p_dev.common;
	INIT_LIST_HEAD(&dma_dev->channels);
	dma_cap_set(DMA_MEMCPY, dma_dev->cap_mask);

	/* Create async channels */
	dma_dev->chancnt = 0;
	chan_id = p_dev.qinfo.chan[0];
	end_chan = p_dev.qinfo.chan[p_dev.qinfo.tx_ch_cnt-1];
	for ( ; chan_id <= end_chan; chan_id++) {
		if (chan_id == 0 && p_dev.qinfo.no_xor == 0)
			continue;
		if (p_dev.qinfo.tx_q[chan_id].slot_rsvd >= PKTDMA_MAX_OPS_INT)
			continue;
		if ((chan = kzalloc(sizeof(*chan), GFP_KERNEL)) == NULL) {
			rc = -ENOMEM;
			goto err;
		}
		list_add_tail(&chan->common.device_node, &dma_dev->channels);
		/* Map channel's device to dma device */
		chan->common.device = dma_dev;
		chan->hw_chid = chan_id;
		spin_lock_init(&chan->lock);
		INIT_LIST_HEAD(&chan->all_slots);
		chan->slots_total = ASYNC_TOTAL_SLOT -
					p_dev.qinfo.tx_q[chan_id].slot_rsvd/2;
#if defined(CONFIG_APM862xx)
		chan->dummy_phys = virt_to_phys(chan->dummy);
#endif
		PKTDMA_DEBUG("Adding memcpy channel %d slot %d",
			chan_id, chan->slots_total);
		++dma_dev->chancnt;
	}
	/* Set base and prep routines */
	dma_dev->device_alloc_chan_resources = apm_pktdma_alloc_resources;
	dma_dev->device_free_chan_resources = apm_pktdma_free_resources;
	dma_dev->device_tx_status = apm_pktdma_tx_status;
	dma_dev->device_issue_pending = apm_pktdma_issue_pending;
	if (dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask))
		dma_dev->device_prep_dma_memcpy = apm_pktdma_prep_memcpy;
	dma_dev->dev = &pdev->dev;
	dma_dev->copy_align = 0;

	rc = dma_async_device_register(dma_dev);
	if (rc != 0) {
		PKTDMA_ERR("Unable to register with DMA Async error 0x%08X",
			rc);
		goto err;
	}

	/* Now, add in XOR as this only works for channel 0 on APM86xxx */
	if (!p_dev.qinfo.no_xor) {
		dma_dev = &p_dev.common_xor;
		INIT_LIST_HEAD(&dma_dev->channels);
		dma_cap_set(DMA_XOR, dma_dev->cap_mask);
		dma_cap_set(DMA_MEMCPY, dma_dev->cap_mask);

		/* Create async channels */
		dma_dev->chancnt = 0;
		chan_id = p_dev.qinfo.chan[0];
		end_chan = p_dev.qinfo.chan[p_dev.qinfo.tx_ch_cnt-1];
		for ( ; chan_id <= end_chan; chan_id++) {
			if (chan_id != PKDTMA_XOR_CHAN) {
				PKTDMA_DEBUG("Skip XOR channel %d", chan_id);
				continue;
			}
			if (p_dev.qinfo.tx_q[chan_id].slot_rsvd >=
							PKTDMA_MAX_OPS_INT)
				continue;
			chan = kzalloc(sizeof(*chan), GFP_KERNEL);
			if (chan == NULL) {
				rc = -ENOMEM;
				goto err;
			}
			list_add_tail(&chan->common.device_node,
					&dma_dev->channels);
			/* Map channel's device to dma device */
			chan->common.device = dma_dev;
			chan->hw_chid = chan_id;
			spin_lock_init(&chan->lock);
			INIT_LIST_HEAD(&chan->all_slots);
			chan->slots_total = ASYNC_TOTAL_SLOT -
					p_dev.qinfo.tx_q[chan_id].slot_rsvd/2;
			/* For XOR with page size 64K, we need 4 slots. Or,
			   in case the buffer is more than 16K */
			chan->slots_total /= 4;
#if defined(CONFIG_APM862xx)
			chan->dummy_phys = virt_to_phys(chan->dummy);
#endif
			PKTDMA_DEBUG("Adding XOR channel %d slot %d",
				chan_id, chan->slots_total);
			++dma_dev->chancnt;
		}
		/* Set base and prep routines */
		dma_dev->device_alloc_chan_resources =
					apm_pktdma_alloc_resources;
		dma_dev->device_free_chan_resources =
					apm_pktdma_free_resources;
		dma_dev->device_tx_status = apm_pktdma_tx_status;
		dma_dev->device_issue_pending = apm_pktdma_issue_pending;
		if (dma_has_cap(DMA_MEMCPY, dma_dev->cap_mask)) {
			dma_dev->device_prep_dma_memcpy = apm_pktdma_prep_memcpy;
			dma_dev->copy_align = 0;
		}
		if (dma_has_cap(DMA_XOR, dma_dev->cap_mask)) {
			dma_dev->device_prep_dma_xor = apm_pktdma_prep_xor;
			dma_dev->max_xor = PKTDMA_MAX_XOR;
			dma_dev->xor_align = 0;
		}
		dma_dev->dev = &pdev->dev;
		rc = dma_async_device_register(dma_dev);
		if (rc != 0) {
			PKTDMA_ERR("Unable to register with DMA Async "
				"error 0x%08X", rc);
			goto err;
		}
	}

#ifdef CONFIG_SMP
	for (i = 0; i < MAX_CORES; i++)
		apm_qm_mb_tasklet_register(p_dev.qinfo.queues[i].comp_mb,
			p_dev.qinfo.queues[i].comp_qid,
			i, &p_dev, apm_pktdma_bh_tasklet_cb);
#else
	apm_qm_mb_tasklet_register(p_dev.qinfo.queues[core_id].comp_mb,
			p_dev.qinfo.queues[core_id].comp_qid,
			core_id, &p_dev, apm_pktdma_bh_tasklet_cb);
#endif

	/* Register for PktDMA interrupt */
	p_dev.irq = of_irq_to_resource(np, 0, NULL);
	if (p_dev.irq != NO_IRQ) {
		rc = request_irq(p_dev.irq, apm_pktdma_irq, 0, "PktDMA", NULL);
		if (rc != 0) {
			PKTDMA_ERR("Unable to register IRQ %d error %d",
				p_dev.irq, rc);
		} else {
			/* Enable PktDMA interrupt */
			apm_pktdma_write_reg(DMA_INTMASK_ADDR, 0x00000000);
		}
	}

#if defined(APM_PKTDMA_DEBUG_XTRA)
	for (i = 0; i < QMSG_RSV_NUM; i++)
		memset(&p_dev.current_send_msg[i], 0, 64);
	p_dev.cnt_send_msg = 0;
	p_dev.pktdma_m2m_sent_pkts = 0;
	p_dev.pktdma_recv_pkts = 0;
#endif
        op_slab_cache = kmem_cache_create("PktDma Op cache",
                                          sizeof(struct iodma_op_state) +
                                          sizeof(struct apm_iodma_user_context),
                                          0,
                                          SLAB_HWCACHE_ALIGN,
                                          NULL);
        op_slab_pool = mempool_create(1024,
                                      mempool_alloc_slab,
                                      mempool_free_slab,
                                      op_slab_cache);

        apm_pktdma_op_list_init();
	entry = proc_create("apm_pktdma", 0644, NULL, &apm_pktdma_driver_debug_fops);
        if (entry == NULL)
                printk(KERN_ERR " PktDMA proc entry creation failed\n");
	printk("PktDMA %sdriver registered%s",
		p_dev.qinfo.no_tm ? "" : "TM ",
		p_dev.qinfo.no_xor ? " without XOR" : "");
	return rc;

err:
	iounmap(p_dev.csr_base);
	return rc;
}

static int apm_pktdma_of_remove(struct platform_device *dev)
{
	struct iodma_pdev *pdev = platform_get_drvdata(dev);

	dma_async_device_unregister(&pdev->common);
	iounmap(p_dev.csr_base);
	return 0;
}

static struct of_device_id apm_pktdma_match[] = {
	{ .compatible	= "apm-pktdma", },
	{ .compatible	= "apm,apm86xxx-pktdma", },
	{ },
};

static struct platform_driver apm_pktdma_driver = {
	.driver = {
		.name		= "apm-pktdma",
		.of_match_table	= apm_pktdma_match,
	},
	.probe		= apm_pktdma_of_probe,
	.remove		= apm_pktdma_of_remove,
#if defined(CONFIG_PM)
	.suspend	= apm_pktdma_suspend,
	.resume		= apm_pktdma_resume,
#endif
};

int __init apm_pktdma_init(void)
{
	platform_driver_register(&apm_pktdma_driver);
	return 0;
}

static void __exit apm_pktdma_exit(void)
{
	platform_driver_unregister(&apm_pktdma_driver);
}

EXPORT_SYMBOL(apm_pktdma_m2m_xfer);
EXPORT_SYMBOL(apm_pktdma_p2m_xfer);
EXPORT_SYMBOL(apm_pktdma_m2b_xfer);

subsys_initcall(apm_pktdma_init);
module_exit(apm_pktdma_exit);

MODULE_AUTHOR("Shasi Pulijala <spulijala@apm.com>");
MODULE_DESCRIPTION("APM86xxx PktDMA device driver");
MODULE_LICENSE("GPL");
