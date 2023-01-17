/**
 *  APM86xxx PktDMA driver
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
 * This is the core runtime/config file for PktDMA core driver.
 *
 */
#include "apm_pktdma_access.h"

u16 apm_buf_len_result(u16 msg_len)
{
	if (msg_len & 0xFFF)
		return msg_len & 0xFFF;
	if (msg_len == 0x7000)
		return 256;
	else if (msg_len == 0x6000)
		return 1024;
	else if (msg_len == 0x5000)
		return 2048;
	else if (msg_len == 0x4000)
		return 4096;
	else if (msg_len == 0x0000)
		return 16384;
	else
		return msg_len;
}

int apm_pktdma_is_coherent(void)
{
#if !defined(CONFIG_NOT_COHERENT_CACHE) || defined(CONFIG_APM86xxx_IOCOHERENT)
	return 1;
#else
	return 0;
#endif
}

void apm_pktdma_flush_src(void *saddr, int byte_cnt)
{
	PKTDMA_DRXTX("flushing src addr %p bytes %d", saddr, byte_cnt);
	flush_dcache_range((u32) saddr, (u32) saddr + byte_cnt);
}
EXPORT_SYMBOL(apm_pktdma_flush_src);

void apm_pktdma_flush_dest(void *daddr, int byte_cnt)
{
	PKTDMA_DRXTX("byte cnt used to flush dst %d", byte_cnt);
	flush_dcache_range((u32) daddr, (u32) daddr + byte_cnt);
}
EXPORT_SYMBOL(apm_pktdma_flush_dest);

void apm_pktdma_invalidate_dest(void *daddr, int byte_cnt)
{
	PKTDMA_DRXTX("byte cnt used to invalidate dst %d", byte_cnt);
	invalidate_dcache_range((u32) daddr, (u32) daddr + byte_cnt);
}
EXPORT_SYMBOL(apm_pktdma_invalidate_dest);

#if defined(CONFIG_APM862xx)
void apm_pktdma_err_log(int err, int flby_err)
{
	/* NOTE: flby_err no appliable to APM862xx */
	switch (err) {
	case ERR_MSG_AXI:
		PKTDMA_ERR("AXI error reading Src/Dst addr from the link list");
		break;
	case ERR_BAD_MSG:
		PKTDMA_ERR("HE0 bit is not set on incoming message");
		break;
	case ERR_READ_DATA_AXI:
		PKTDMA_ERR("AXI error reading data");
		break;
	case ERR_WRITE_DATA_AXI:
		PKTDMA_ERR("AXI error writing data");
		break;
	case CRC_ERR:
		/* PKTDMA_ERR("CRC error"); */
		break;
	case CHK_ERR:
		/* PKTDMA_ERR("Checksum error"); */
		break;
	default:
		PKTDMA_ERR("No error set");
		break;
	}
}
#else
void apm_pktdma_err_log(int err, int flby_err)
{
	if (flby_err) {
		/* Checksum/CRC Errors*/
		switch (err) {
		case CRC_ERR:
			/* PKTDMA_ERR("CRC error"); */
			break;
		case CHK_ERR:
			/* PKTDMA_ERR("Checksum error"); */
			break;
		default:
			PKTDMA_ERR("No error set");
			break;
		}
		return;
	}
	switch (err) {
	case ERR_MSG_AXI:
		PKTDMA_ERR("AXI Error reading Src/Dst addr from the link list");
		break;
	case ERR_BAD_MSG:
		PKTDMA_ERR("HE0 bit is not set on incoming message");
		break;
	case ERR_READ_DATA_AXI:
		PKTDMA_ERR("AXI error reading data");
		break;
	case ERR_WRITE_DATA_AXI:
		PKTDMA_ERR("AXI error writing data");
		break;
	case ERR_FBP_TIMEOUT:
		PKTDMA_ERR("Timeout on free pool buffer fetch");
		break;
	case ERR_SCT_GAT_LEN:
		PKTDMA_ERR("Gather and Scatter not same data length");
		break;
	default:
		PKTDMA_ERR("No error set");
		break;
	}
}
#endif

int apm_pktdma_get_num_buffs(struct apm_pktdma_msg_done *comp_msg)
{
	struct apm_dma_msg1_2 *dmsg1_2 = &comp_msg->dmsg1_2;
	union list_msg_data *list_msg;
	int num_buffs;
	int i;

	if (!dmsg1_2->NV)
		return 1;

	list_msg = &comp_msg->done_list_msg_data;
	if (dmsg1_2->LL) {
		if (!list_msg->desc.src_gr_5.linksize) {
			PKTDMA_ERR("Linksize is zero while LL bit is %d",
				dmsg1_2->LL);
			return 1;
		}
		return 4 + list_msg->desc.src_gr_5.linksize;
	}

	num_buffs = 1;
	i = 0;

	if (!list_msg->src_list[i].next_data_len) {
		PKTDMA_ERR("Next data len is zero while NV is %d",
			dmsg1_2->NV);
		return 1;
	}
	while (list_msg->src_list[i].next_data_len != 0x7800) {
		i++;
		if (++num_buffs == 5)
			break;
	}
	return num_buffs;
}

void apm_pktdma_fpbuff_get_single(struct apm_pktdma_msg_done *comp_msg,
				 struct fp_info *fp)
{
	struct apm_dma_msg1_2 *dmsg1_2 = &comp_msg->dmsg1_2;

	fp->fp_id = dmsg1_2->FPQNum;
	fp->fp_dest_address = phys_to_virt(MAKE64(dmsg1_2->addr_hi,
						dmsg1_2->addr_lo));
	fp->fp_dlength = apm_buf_len_result(dmsg1_2->data_len);
}

struct sg_list_attr *apm_pktdma_fpbuff_get_mul(
				struct apm_pktdma_msg_done *comp_msg,
				struct fp_info *fp, u8 num_buffs)
{
	struct apm_dma_msg1_2 *dmsg1_2 = &comp_msg->dmsg1_2;
	struct sg_list_attr *buf_ptr = NULL;
	union list_msg_data *list_msg = &comp_msg->done_list_msg_data;
	int i, j;

	if (!dmsg1_2->LL) {
		for (i = 0, j = 1; i < (num_buffs - 1); i++, j++) {
			fp[j].fp_dest_address = phys_to_virt(
				MAKE64(list_msg->src_list[i].next_addr_hi,
					list_msg->src_list[i].next_addr_lo));
			fp[j].fp_id = list_msg->src_list[i].next_fpq_id;
			fp[j].fp_dlength = apm_buf_len_result(
					list_msg->src_list[i].next_data_len);
		}
	} else {
		buf_ptr = (struct sg_list_attr *) phys_to_virt(
				MAKE64(list_msg->desc.src_gr_5.ptr_to_src_hi,
				list_msg->desc.src_gr_5.ptr_to_src_lo));
		PKTDMA_DRXTX("linked list ptr 0x%08X", (u32) buf_ptr);
		for (i = 0, j = 1; i < 3; i++, j++) {
			fp[j].fp_dest_address = phys_to_virt(
				MAKE64(list_msg->desc.list_ll[i].next_addr_hi,
				       list_msg->desc.list_ll[i].next_addr_lo));
			fp[j].fp_id = list_msg->desc.list_ll[i].next_fpq_id;
			fp[j].fp_dlength = apm_buf_len_result(
				list_msg->desc.list_ll[i].next_data_len);
		}
		for ( i = 0, j = 4; i < (num_buffs - 4); i++, j++) {
			fp[j].fp_dest_address = phys_to_virt(
				MAKE64(buf_ptr[i].next_addr_hi,
					buf_ptr[i].next_addr_lo));
			fp[j].fp_id = buf_ptr[i].next_fpq_id;
			fp[j].fp_dlength = apm_buf_len_result(
				buf_ptr[i].next_data_len);
		}

	}
	return buf_ptr;
}

/**
 * Operation Completion Callback Handler
 *
 */
int apm_pktdma_op_cb_all(struct iodma_op_state *op_st)
{
	struct apm_pktdma_msg_done *dmsg = op_st->dmsg;
	struct apm_dma_msg1_2 *dmsg1_2 = &dmsg->dmsg1_2;
	struct apm_pktdma_op_result *comp_resp = &op_st->result;
	struct sg_list_attr *buf_ptr = NULL;
	int ret = 0;
	int num_buffs;
	int fp_num_refill = 0;

	comp_resp->fp = NULL;
	comp_resp->err = dmsg1_2->LErr;
	if (dmsg1_2->LErr) {
		apm_pktdma_err_log(dmsg1_2->LErr, 0);
#if defined (CONFIG_APM862xx)
		if (dmsg1_2->LErr < 5)
			goto cb_fin;	/* Critical error */
#else
		if (!dmsg1_2->EL_Err)
			goto cb_fin;	/* Critical error */
#endif
	}

	if (op_st->cb_compl_msg) {
		comp_resp->comp_msg = dmsg;
	} else {
		num_buffs = apm_pktdma_get_num_buffs(dmsg);
		PKTDMA_DRXTX("number of buffers return = %d", num_buffs);
		comp_resp->fp = kzalloc(num_buffs * sizeof(struct fp_info),
					GFP_KERNEL);
		if (!comp_resp->fp) {
			PKTDMA_ERR("out of memory for Dest buff table!!");
			return -ENOMEM;
		}
		apm_pktdma_fpbuff_get_single(dmsg, comp_resp->fp);
		if (dmsg1_2->NV && (num_buffs > 1)) {
			buf_ptr = apm_pktdma_fpbuff_get_mul(dmsg,
					comp_resp->fp, num_buffs);
		}
#ifdef APM_PKTDMA_DEBUG
		{
		int i;
		for (i = 0; i < num_buffs; i++) {
			PKTDMA_DRXTX("returned data buf: 0x%p, date len: %d",
				comp_resp->fp[i].fp_dest_address,
				comp_resp->fp[i].fp_dlength);
		}
		}
#endif
		fp_num_refill = dmsg1_2->LL ? (num_buffs + 1) : num_buffs;
		comp_resp->num_fp = num_buffs;
		if (op_st->fby_gen) {
			comp_resp->crc = dmsg->dmsg3.crc_result;
			comp_resp->checksum = dmsg->dmsg4.checksum_res;
		}
	}


cb_fin:
	if (op_st->result.cb) {
		op_st->result.cb(comp_resp);
	}

	if (op_st->src_ptr) {
		PKTDMA_DEBUG("freeing gather_ptr %p", op_st->src_ptr);
		kfree(op_st->src_ptr);
	}

	/* Replenish the free pool buffers */
	if (fp_num_refill) {
		if (buf_ptr)
			kfree(buf_ptr);
		PKTDMA_DRXTX("FP ID %d refill %d buffer",
				comp_resp->fp->fp_id, fp_num_refill);
		apm_pktdma_init_pool(comp_resp->fp->fp_id,
				FREE_POOL_DMA_BUFFER_SIZE, fp_num_refill);
		kfree(comp_resp->fp);
	}

	apm_pktdma_op_free(op_st);

	return ret;
}

int apm_pktdma_op_cb_dest_mem(struct iodma_op_state *op_st)
{
	struct apm_dma_msg1_2 *dmsg1_2 = &op_st->dmsg->dmsg1_2;
	struct apm_pktdma_op_result *comp_resp = &op_st->result;

	if (op_st->src_ptr) {
		PKTDMA_DRXTX("freeing gather_ptr %p", op_st->src_ptr);
		kfree(op_st->src_ptr);
	}

	if (op_st->dest_ptr) {
		PKTDMA_DRXTX("freeing scatter ptr %p", op_st->dest_ptr);
		kfree(op_st->dest_ptr);
	}

	if ((comp_resp->err = dmsg1_2->LErr)) {
		PKTDMA_DUMP_MSG("DMA Err Msg", op_st->dmsg, dmsg1_2->NV ? 64 : 32);
		apm_pktdma_err_log(dmsg1_2->LErr, 0);
	}

	if (op_st->result.cb)
		op_st->result.cb(comp_resp);

	apm_pktdma_op_free(op_st);

	return 0;
}

int apm_pktdma_op_cb(struct iodma_op_state *op_st)
{
	if (op_st->chk_slot) {
		atomic_sub(op_st->chk_slot,
			&op_st->chqid->tx_inflight[op_st->cos]);
	}

	switch (op_st->major_opcode) {
	case MEM_TO_MEM:
	case PKT_TO_MEM:
		return apm_pktdma_op_cb_dest_mem(op_st);
	default:
		return apm_pktdma_op_cb_all(op_st);
	}
}

void apm_pktdma_flyby_set(struct apm_pktdma_flyby_info *fb,
		       struct apm_pktdma_msg *dma_msg)
{
	struct apm_dma_msg_4 *msg4 = &dma_msg->msg4;
	struct apm_dma_msg_3 *msg3 = &dma_msg->msg3;

	msg4->FBY = fb->fb_type;
	msg4->GN = fb->fb_gen_check;
	msg4->SD = fb->fb_seed_chksum;
	msg3->var_data.to_buf_fby.crc_chk_byte_cnt = fb->fb_byte_count;
	if (msg4->SD)
		msg4->var_data.fby.crc_chk_seed = fb->fb_seed_chksum;
}

u16 apm_pktdma_buf_len_set(u16 len)
{
	/* Set length for buffer mode pointer */
	if (len > 16384) {
		PKTDMA_ERR("Input Length more than the max limit");
		return 0;
	}

	if (len < 256) {
		return len | 0x7000;
	} else if (len == 256) {
		return 0x7000;
	} else if (len < 1024) {
		return len | 0x6000;
	} else if (len == 1024) {
		return 0x6000;
	} else if (len < 2048) {
		return len | 0x5000;
	} else if (len == 2048) {
		return 0x5000;
	} else if (len < 4096) {
		return len | 0x4000;
	} else if (len == 4096) {
		return 0x4000;
	} else if (len < 16384) {
		return len;
	} else if (len == 16384) {
		return 0x0;
	} else {
		return 0x0;
	}
}

u16 apm_pktdma_len_set(u16 len)
{
	/* Set length for memory mode pointer */
#if defined(CONFIG_APM862xx)
	if (len < 32 || len > (16 * 1024)) {
		PKTDMA_ERR("Illegal Length:%d for a Single"
				"buffer transfer", len);
		BUG();
	}
#endif
	if (len < 16*1024) {
		return len;
	} else if (len == 16*1024) {
		return 0;
	}
	return 0;
}

void apm_pktdma_qmesg_load_single_dst(struct apm_pktdma_msg *dma_msg,
				      u64 da)
{
	dma_msg->msg3.var_data.dst_m2m.dest_addr_hi = (u8) (da >> 32);
	dma_msg->msg3.var_data.dst_m2m.dest_addr_lo = (u32) da;
}

static int apm_pktdma_qmesg_load_dst_mul(struct apm_pktdma_msg *dma_msg,
			 u64 *da, u16 *len, u8 sg_count,
			 struct iodma_op_state *op, u16 *total_len)
{
	u16 byte_count = 0;
	struct sg_list_attr *dst_ptr;
	int i;
	u64 phys_dst_ptr;

	dst_ptr = kzalloc(sg_count * sizeof(struct sg_list_attr) + 15,
			GFP_KERNEL);
	if (dst_ptr == NULL)
		return -ENOMEM;
	op->dest_ptr = dst_ptr;
	dst_ptr = (void *) PKTDMA_ALIGN_PTR(dst_ptr);
	PKTDMA_DRXTX("dest ptr:0x%p,  dest ptr aligned:0x%p",
		     op->dest_ptr, dst_ptr);
	for (i = 0; i < sg_count; i++) {
		dst_ptr[i].next_addr_hi = (u8) (da[i] >> 32);
		dst_ptr[i].next_addr_lo = (u32) da[i];
		dst_ptr[i].next_data_len = apm_pktdma_len_set(len[i]);
		byte_count += len[i];
	}
#ifdef CONFIG_NOT_COHERENT_CACHE
	flush_dcache_range((u32) dst_ptr, (u32) dst_ptr + sg_count *
			sizeof(struct sg_list_attr));
#endif
	phys_dst_ptr = __pa(dst_ptr);
	dma_msg->msg3.var_data.scatter_m2m.dst_ptr = (u32) (phys_dst_ptr >> 4);
	dma_msg->msg3.var_data.scatter_m2m.linksize = sg_count;

	PKTDMA_DEBUG_DUMP("linked list for Dest", dst_ptr, sg_count * 8);
	*total_len = byte_count;
	return 0;
}

void apm_pktdma_qmesg_load_single_src(struct apm_pktdma_msg *dma_msg,
				      u64 sa, u16 len, u8 fp_id)
{
	dma_msg->msg1_2.addr_hi = (u8) (sa >> 32);
	dma_msg->msg1_2.addr_lo = (u32) sa;
	if (fp_id) {
		dma_msg->msg1_2.FPQNum = fp_id;
		dma_msg->msg1_2.data_len = len;
	} else {
		dma_msg->msg1_2.data_len = apm_pktdma_len_set(len);
	}
}

static int apm_pktdma_qmesg_load_src_mul(struct apm_pktdma_msg *dma_msg,
					u64 *sa, u16 *len, u8 *fp_id,
					u8 sg_count, struct iodma_op_state *op)
{
	int i, j, count;
	u32 total_linklist_bytecount = 0;
	struct sg_list_attr *gather_ptr;

	if (fp_id)
		apm_pktdma_qmesg_load_single_src(dma_msg,sa[0],len[0],fp_id[0]);
	else
		apm_pktdma_qmesg_load_single_src(dma_msg, sa[0], len[0], 0);

	dma_msg->msg1_2.NV = 1;
	if (sg_count <= 5) {
		for (i = 1, j = 0; i < sg_count; i++, j++) {
			if (fp_id) {
				dma_msg->list_msg_data.src_list[j].next_fpq_id =
						fp_id[i];
				dma_msg->list_msg_data.src_list[j].
						next_data_len = len[i];
			} else {
				dma_msg->list_msg_data.src_list[j].
						next_data_len =
						apm_pktdma_len_set(len[i]);
			}
			dma_msg->list_msg_data.src_list[j].next_addr_hi =
					(u8) (sa[i] >> 32);
			dma_msg->list_msg_data.src_list[j].next_addr_lo =
					(u32) sa[i];
			PKTDMA_DRXTX("Src address 0x%08X src len %d for %d",
				dma_msg->list_msg_data.src_list[j].next_addr_lo,
				len[i], i);
		}
		if (sg_count < 5)
			/* Marking the entry as invalid */
			dma_msg->list_msg_data.src_list[j].next_data_len = 0x7800;
	} else {
		u64 phy;

		dma_msg->msg1_2.LL = 1;
		for (i = 1, j = 0; i < 4; i++, j++) {
			if (fp_id) {
				dma_msg->list_msg_data.desc.list_ll[j].next_fpq_id =
						fp_id[i];
				dma_msg->list_msg_data.desc.list_ll[j].
						next_data_len = len[i];
			} else {
				dma_msg->list_msg_data.desc.list_ll[j].
						next_data_len =
						apm_pktdma_len_set(len[i]);
			}
			dma_msg->list_msg_data.desc.list_ll[j].next_addr_hi =
					(u8) (sa[i] >> 32);
			dma_msg->list_msg_data.desc.list_ll[j].next_addr_lo =
					(u32) sa[i];
		}
		count = sg_count - 4;
		if (count >= 256) {
			PKTDMA_ERR("Exceeding the link size");
			count = 0;
			return -EINVAL;
		}
		gather_ptr = kzalloc(count * sizeof(struct sg_list_attr) + 15,
				GFP_KERNEL);
		if (gather_ptr == NULL) {
			PKTDMA_ERR("Buffer descriptor allocation failed");
			return -ENOMEM;
		}
		op->src_ptr = gather_ptr;
		gather_ptr = (void *) PKTDMA_ALIGN_PTR(gather_ptr);
		for (j = 0, i = 4; i < sg_count; i++, j++) {
			gather_ptr[j].next_addr_hi = (u8) (sa[i] >> 32);
			gather_ptr[j].next_addr_lo = (u32) sa[i];
			if (fp_id) {
				gather_ptr[j].next_fpq_id = fp_id[i];
				gather_ptr[j].next_data_len = len[i];
				total_linklist_bytecount += len[i];
			} else {
				gather_ptr[j].next_data_len =
						apm_pktdma_len_set(len[i]);
				total_linklist_bytecount += len[i];
			}
		}
#ifdef CONFIG_NOT_COHERENT_CACHE
		flush_dcache_range((u32) gather_ptr, (u32) gather_ptr + (count *
			sizeof(struct sg_list_attr)));
#endif
		dma_msg->list_msg_data.desc.src_gr_5.linksize = count;
		dma_msg->list_msg_data.desc.src_gr_5.total_length_link =
				total_linklist_bytecount;
		phy = __pa(gather_ptr);
		dma_msg->list_msg_data.desc.src_gr_5.ptr_to_src_hi =
				(u8) (phy >> 32);
		dma_msg->list_msg_data.desc.src_gr_5.ptr_to_src_lo = (u32) phy;
	}
	return 0;
}

int apm_pktdma_p2m(struct apm_pktdma_p2m_params *iodma_p2m, int chk_slot)
{
	/* NOTE: De-allocate for m2b after getting completion message */
	struct apm_pktdma_msg dma_msg;
	struct apm_qm_msg_desc send_msg;
	struct apm_dma_msg1_2 *msg1_2 = &dma_msg.msg1_2;
	struct apm_dma_msg_3 *msg3 = &dma_msg.msg3;
	struct apm_dma_msg_4 *msg4 = &dma_msg.msg4;
	struct iodma_op_state *op = NULL;
	unsigned long flags = 0;
	struct pktdma_chan_qid *chq = &p_dev.qinfo.tx_q[iodma_p2m->chid];
	int rc;

	memset(&dma_msg, 0, sizeof(dma_msg));
	memset(&send_msg, 0, sizeof(send_msg));

	/* Get a new op*/
	op = apm_pktdma_op_get();
	if (!op) {
		PKTDMA_ERR("Out of memory for PktDMA operation");
		return -ENOMEM;
	}
	op->src_ptr = NULL;
	op->dest_ptr = NULL;
	op->result.cb = iodma_p2m->cb;
	op->result.ctx = iodma_p2m->context;
	op->major_opcode = PKT_TO_MEM;
	op->dmsg = NULL;
	/* Set common params im2m_moden msg */
	msg1_2->coherent_read = apm_pktdma_is_coherent();
	msg1_2->RType = APM_QM_DMA_RTYPE;
	msg1_2->uinfo = (u32)(unsigned long) op;
	msg3->HE = 1;
	/* Set to Host QID for Completion messages */
	msg3->H0Enq_Num = p_dev.qinfo.queues[apm_processor_id()].comp_qid;
	msg3->HR = 1;
	msg4->BD = 0;
	switch (iodma_p2m->p2m_mode) {
	case IODMA_COPY:
	default:
		msg3->DR = 1; /* Set if H0info is Dst Pointer - S */
		apm_pktdma_qmesg_load_single_src(&dma_msg,
				*iodma_p2m->fp_sa, *iodma_p2m->byte_count,
				*iodma_p2m->fp_id);
		apm_pktdma_qmesg_load_single_dst(&dma_msg,
				*iodma_p2m->da);
		PKTDMA_DEBUG("printing sa in p2m 0x%08X",
				(u32)*iodma_p2m->fp_sa);
		PKTDMA_DEBUG("printing da in p2m 0x%08X",
				(u32)*iodma_p2m->da);
		break;
	case IODMA_SCATTER:
		{
		u16 total_len;
		msg4->SC = 1;
		/* msg3->DR = 0; */	/* Set if H0info is Dst Pointer - S */
		if (apm_pktdma_qmesg_load_dst_mul(&dma_msg,
				iodma_p2m->da, iodma_p2m->byte_count,
				iodma_p2m->sg_count, op, &total_len) == 0) {
			rc = -ENOMEM;
			goto err;
		}
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_p2m->fp_sa,
				total_len, *iodma_p2m->fp_id);
		}
		break;
	case IODMA_GATHER:
		memset(((u8 *) &dma_msg) + 32, 0, 32);
		msg3->DR = 1; /* Set if H0info is Dst Pointer - S */
		apm_pktdma_qmesg_load_src_mul(&dma_msg, iodma_p2m->fp_sa,
					       iodma_p2m->byte_count,
					       iodma_p2m->fp_id,
					       iodma_p2m->sg_count, op);
		apm_pktdma_qmesg_load_single_dst(&dma_msg, *iodma_p2m->da);
		break;
	}

#if defined(APM_PKTDMA_DEBUG)
	if (iodma_p2m->cos < IODMA_MIN_COS || iodma_p2m->cos > IODMA_MAX_COS)
		PKTDMA_DEBUG("COS out of range %d", iodma_p2m->cos);
#endif
	send_msg.qid = chq->tx_qid[iodma_p2m->cos];
	send_msg.msg = &dma_msg;

	/* Check if slot available after NV is set */
	if (chk_slot) {
		if (!atomic_add_unless(&chq->tx_inflight[iodma_p2m->cos],
					1, chq->tx_max_slot[iodma_p2m->cos])) {
			/* Out of descriptor slot */

			rc = -ENOMEM;
			goto err;
		}
		if (msg1_2->NV) {
			if (!atomic_add_unless(
					&chq->tx_inflight[iodma_p2m->cos],
					1, chq->tx_max_slot[iodma_p2m->cos])) {
				/* Out of descriptor slot */
				atomic_dec(&chq->tx_inflight[iodma_p2m->cos]);
				rc = -ENOMEM;
				goto err;
			}
			op->chk_slot = 2;
		} else {
			op->chk_slot = 1;
		}
		op->cos = iodma_p2m->cos;
		op->chqid = chq;
	} else {
		op->chk_slot = 0;
	}

#ifdef APM_PKTDMA_DRXTX
	PKTDMA_DEBUG_DUMP("P2M Byte Message", &dma_msg, msg1_2->NV ? 64 : 32);
#endif
	PKTDMA_DEBUG("B2M CQID %d EQID %d len %d",
		    msg3->H0Enq_Num, send_msg.qid, msg1_2->data_len);
	flags = apm_pktdma_msg_enq_lock();
#if defined(APM_PKTDMA_DEBUG_XTRA)
	memcpy(&p_dev.current_send_msg[p_dev.cnt_send_msg++],
	       &dma_msg, msg1_2->NV ? 64 : 32);
	       if (p_dev.cnt_send_msg == QMSG_RSV_NUM)
		       p_dev.cnt_send_msg = 0;
#endif
	apm_qm_push_msg(&send_msg);
	apm_pktdma_msg_enq_unlock(flags);
	return 0;

err:
	apm_pktdma_op_free(op);
	return rc;
}

int apm_pktdma_p2m_xfer(struct apm_pktdma_p2m_params *iodma_p2m)
{
	return apm_pktdma_p2m(iodma_p2m, 1);
}

int apm_pktdma_m2b(struct apm_pktdma_m2b_params *iodma_m2b, int chk_slot)
{
	/* NOTE: De-allocate for m2b after getting completion message */
	struct apm_pktdma_msg dma_msg;
	struct apm_qm_msg_desc send_msg;
	struct apm_dma_msg1_2 *msg1_2 = &dma_msg.msg1_2;
	struct apm_dma_msg_3 *msg3 = &dma_msg.msg3;
	struct apm_dma_msg_4 *msg4 = &dma_msg.msg4;
	struct iodma_op_state *op = NULL;
	unsigned long flags;
	struct pktdma_chan_qid *chq = &p_dev.qinfo.tx_q[iodma_m2b->chid];
	int rc;

	memset(&dma_msg, 0, sizeof(dma_msg));
	memset(&send_msg, 0, sizeof(send_msg));

	/* Get a new op */
	op = apm_pktdma_op_get();
	if (!op) {
		PKTDMA_ERR("Out of memory for PktDMA operation");
		return -ENOMEM;
	}
	op->src_ptr = NULL;
	op->dest_ptr = NULL;
	op->dmsg = NULL;
	op->result.cb = iodma_m2b->cb;
	op->result.ctx = iodma_m2b->context;
	op->result.crc = op->result.checksum = 0;
	op->major_opcode = MEM_TO_BUFF;
	op->cos = iodma_m2b->cos;
	op->chqid = chq;
	op->cb_compl_msg = iodma_m2b->cb_compl_msg ? 1 : 0;
	op->fby_gen = 0;
	/*set common params im2m_moden msg */
	msg1_2->coherent_read = apm_pktdma_is_coherent(); /* set the Coherent bit */
	msg1_2->RType = APM_QM_DMA_RTYPE;
	msg1_2->uinfo = (u32) (unsigned long) op;
	msg3->HE = 1;
	msg3->H0Enq_Num = p_dev.qinfo.queues[apm_processor_id()].comp_qid;
	/*Set to Host QID for Completion messages */
	msg3->DR = 0; /* Set if H0info is Dst Pointer - S */
	msg4->BD = 1;
	if (op->cb_compl_msg) /* FIXME */
		msg3->H0FPSel = iodma_m2b->cross_pbn;
	else
		msg3->H0FPSel = p_dev.qinfo.queues[apm_processor_id()].rx_fp_pbn;

	/*send direct mode msg */
	switch (iodma_m2b->m2b_mode) {
	case IODMA_COPY:
	default:
		PKTDMA_DRXTX("Executing IODMA m2b direct mode operation.");
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_m2b->sa,
				*iodma_m2b->byte_count, 0);
		break;
	case IODMA_GATHER:
		memset(((u8 *) &dma_msg) + 32, 0, 32);
		apm_pktdma_qmesg_load_src_mul(&dma_msg, iodma_m2b->sa,
					       iodma_m2b->byte_count,
					       NULL, iodma_m2b->sg_count,
					       op);
		break;
	}

	if (iodma_m2b->fby) {
		if ((iodma_m2b->fb.fb_type <= DMA_FBY_NONE) ||
				   (iodma_m2b->fb.fb_type > DMA_FBY_XOR_5SRC)) {
			PKTDMA_ERR("Unsupported FBY Operation in buf dest");
			apm_pktdma_op_free(op);
			return -ENODEV;
		}
		/* Check if XOR hardware available */
		if (iodma_m2b->fb.fb_type >= DMA_FBY_XOR_2SRC &&
			iodma_m2b->fb.fb_type <= DMA_FBY_XOR_5SRC) {
			if (iodma_m2b->chid != PKDTMA_XOR_CHAN ||
						 p_dev.qinfo.no_xor) {
				apm_pktdma_op_free(op);
				PKTDMA_ERR("Unsupported XOR operation in buf dest");
				return -ENODEV;
			} else {
				msg4->FBY = iodma_m2b->fb.fb_type;
			}
		} else {
			apm_pktdma_flyby_set(&iodma_m2b->fb, &dma_msg);
			op->fby_gen = 1;
		}
	}

	PKTDMA_DRXTX("free pool id mapped %d", msg3->H0FPSel);

#if defined(APM_PKTDMA_DEBUG)
	if (iodma_m2b->cos < IODMA_MIN_COS || iodma_m2b->cos > IODMA_MAX_COS)
		PKTDMA_DEBUG("COS out of range %d", iodma_m2b->cos);
#endif
	send_msg.qid = chq->tx_qid[iodma_m2b->cos];
	send_msg.msg = &dma_msg;

	/* Check if slot available after NV is set */
	if (chk_slot) {
		if (!atomic_add_unless(&chq->tx_inflight[iodma_m2b->cos],
					1, chq->tx_max_slot[iodma_m2b->cos])) {
			/* Out of descriptor slot */
			rc = -ENOMEM;
			goto err;
		}
		if (msg1_2->NV) {
			if (!atomic_add_unless(
					&chq->tx_inflight[iodma_m2b->cos],
					1, chq->tx_max_slot[iodma_m2b->cos])) {
				/* Out of descriptor slot */
				atomic_dec(&chq->tx_inflight[iodma_m2b->cos]);
				rc = -ENOMEM;
				goto err;
			}
			op->chk_slot = 2;
		} else {
			op->chk_slot = 1;
		}
	} else {
		op->chk_slot = 0;
	}

#ifdef APM_PKTDMA_DRXTX
	PKTDMA_DEBUG_DUMP("M2B Send Message", &dma_msg, msg1_2->NV ? 64 : 32);
#endif
	PKTDMA_DRXTX("CQID %d EQID %d len %d",
	       msg3->H0Enq_Num, send_msg.qid, msg1_2->data_len);
	flags = apm_pktdma_msg_enq_lock();
#if defined(APM_PKTDMA_DEBUG_XTRA)
	memcpy(&p_dev.current_send_msg[p_dev.cnt_send_msg++],
	       &dma_msg, msg1_2->NV ? 64 : 32);
	if (p_dev.cnt_send_msg == QMSG_RSV_NUM)
	       p_dev.cnt_send_msg = 0;
#endif
	apm_qm_push_msg(&send_msg);
	apm_pktdma_msg_enq_unlock(flags);
	return 0;

err:
	apm_pktdma_op_free(op);
	return -EINVAL;
}

int apm_pktdma_m2b_xfer(struct apm_pktdma_m2b_params *iodma_m2b)
{
	return apm_pktdma_m2b(iodma_m2b, 1);
}
#if defined (CONFIG_APM862xx)
static int apm_pktdma_stride_not_aligned(u64 sa, u64 da,
				struct stride_info *str, u16 byte_count,
				 u64 *new_sa, u16 *new_byte_cnt)
{
	u32 *saddr, *daddr;
	u16 str_frst_copy, str_size;
	int num_copies = 0;
	int len = byte_count;
	u32 *str_sa;

	str_frst_copy = (str->src_str_1_sz <= str->dst_str_1_sz)
			 ? str->src_str_1_sz : str->dst_str_1_sz;
	str_size = (str->src_str_sz <= str->dst_str_sz) ?
			str->src_str_sz : str->dst_str_sz;
	len -= str_frst_copy;
	num_copies = len / (str_size + str->dst_str_dis);
	num_copies--;
	if (((num_copies * str->dst_str_sz) + str_frst_copy) % 16 != 0) {
		printk(KERN_DEBUG PKTDMA_HDR "Stride data not aligned\n");
		saddr = (u32 *)phys_to_virt(sa);
		daddr = (u32 *)phys_to_virt(da);

		str_sa = kzalloc((byte_count +
				(str->src_str_sz + str->src_str_dis)), GFP_KERNEL);
		if (!str_sa)
			return -ENOMEM;
		memcpy(str_sa, saddr, byte_count);
		*new_sa = __pa(str_sa);
		*new_byte_cnt = byte_count + (str->src_str_sz + str->src_str_dis);
		return 1;
	}

	return 0;
}
#endif
int apm_pktdma_m2m(struct apm_pktdma_m2m_params *iodma_m2m, int chk_slot)
{
	struct apm_pktdma_msg dma_msg;
	struct apm_qm_msg_desc send_msg;
	struct apm_dma_msg1_2 *msg1_2 = &dma_msg.msg1_2;
	struct apm_dma_msg_3 *msg3 = &dma_msg.msg3;
	struct apm_dma_msg_4 *msg4 = &dma_msg.msg4;
	struct iodma_op_state *op = NULL;
	u16 total_len;
	unsigned long flags;
	struct pktdma_chan_qid *chq = &p_dev.qinfo.tx_q[iodma_m2m->chid];

	memset(&dma_msg, 0, sizeof(dma_msg));
	memset(&send_msg, 0, sizeof(send_msg));

	/* Get a new op */
	op = apm_pktdma_op_get();
	if (!op) {
		PKTDMA_ERR("Out of memory for PktDMA operation");
		return -ENOMEM;
	}
	op->dmsg = NULL;
	op->src_ptr = NULL;
	op->dest_ptr = NULL;
	op->result.cb = iodma_m2m->cb;
	op->result.ctx = iodma_m2m->context;
	op->major_opcode = MEM_TO_MEM;

	/* Set common params m2m_moden msg */
	msg1_2->coherent_read = apm_pktdma_is_coherent(); /* Coherent bit? */
	msg1_2->RType = APM_QM_DMA_RTYPE;
	msg1_2->uinfo = (u32) apm_pktdma_add_op(op, (void *)apm_pktdma_op_free);
	msg3->HE = 1;
	/* Set to Host QID for Completion messages */
	msg3->H0Enq_Num = p_dev.qinfo.queues[apm_processor_id()].comp_qid;
	/* send direct mode msg */
	switch (iodma_m2m->m2m_mode) {
	case IODMA_COPY:
	default:
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_m2m->sa,
				*iodma_m2m->byte_count, 0);
		apm_pktdma_qmesg_load_single_dst(&dma_msg, *iodma_m2m->da);
		msg3->DR = 1; /* Set if H0info is Dst Pointer - S */
		PKTDMA_DRXTX("PADDR SRC: 0x%010llx PADDR DEST: 0x%010llx",
				*iodma_m2m->sa, *iodma_m2m->da);
		break;
	case IODMA_GATHER:
		memset(((u8 *) &dma_msg) + 32, 0, 32);
		msg3->DR = 1; /* Set if H0info is Dst Pointer - S */
		apm_pktdma_qmesg_load_src_mul(&dma_msg, iodma_m2m->sa,
					       iodma_m2m->byte_count,
					       NULL, iodma_m2m->sg_count,
					       op);
		PKTDMA_DRXTX("PADDR DEST: 0x%010llx", *iodma_m2m->da);
		apm_pktdma_qmesg_load_single_dst(&dma_msg, *iodma_m2m->da);
		if (iodma_m2m->fby) {
			if ((iodma_m2m->fb.fb_type < DMA_FBY_XOR_2SRC) ||
						  (iodma_m2m->fb.fb_type > DMA_FBY_XOR_5SRC)) {
				PKTDMA_ERR("Unsupported FBY Operation in mem dest");
				apm_pktdma_op_free(op);
                                apm_pktdma_find_op(msg1_2->uinfo);
				return -ENODEV;
			}
			if (iodma_m2m->chid != PKDTMA_XOR_CHAN || p_dev.qinfo.no_xor) {
				apm_pktdma_op_free(op);
                                apm_pktdma_find_op(msg1_2->uinfo);
				PKTDMA_ERR("Unsupported XOR operation in mem dest");
				return -ENODEV;
			}
			msg4->FBY = iodma_m2m->fb.fb_type;
		}
		break;
	case IODMA_SCATTER:
		/* msg3->DR = 0; */	/* Set if H0info is Dst Pointer - S */
		msg4->SC = 1;
		apm_pktdma_qmesg_load_dst_mul(&dma_msg, iodma_m2m->da,
				iodma_m2m->byte_count,
				iodma_m2m->sg_count, op, &total_len);
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_m2m->sa,
				total_len, 0);
		break;
	case IODMA_GATHER_SCATTER:
		memset(((u8 *) &dma_msg) + 32, 0, 32);
		/* msg3->DR = 0; */
		msg4->SC = 1;
		apm_pktdma_qmesg_load_src_mul(&dma_msg, iodma_m2m->sa,
					       iodma_m2m->byte_count,
					       NULL, iodma_m2m->sg_count,
					       op);
		apm_pktdma_qmesg_load_dst_mul(&dma_msg, iodma_m2m->da,
				iodma_m2m->byte_count,
				iodma_m2m->sg_count, op, &total_len);
		break;
	case IODMA_STRIDE:
#if defined (CONFIG_APM862xx)
		{
			u64 new_sa = 0;
			u16 new_byte_cnt = 0;

			/* Striding Bug Workaround for Green Mamba */
			if (apm_pktdma_stride_not_aligned(*iodma_m2m->sa,
					*iodma_m2m->sa, &iodma_m2m->str,
					*iodma_m2m->byte_count, &new_sa,
					&new_byte_cnt)) {
				apm_pktdma_qmesg_load_single_src(&dma_msg,
						new_sa, new_byte_cnt, 0);
			} else  {
				apm_pktdma_qmesg_load_single_src(&dma_msg,
						*iodma_m2m->sa,
						*iodma_m2m->byte_count, 0);
			}
		}
#else
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_m2m->sa,
						*iodma_m2m->byte_count, 0);
#endif
		msg3->DR = 1; /* Set if H0info is Dst Pointer - S */
		msg4->ST = 1;
		apm_pktdma_qmesg_load_single_dst(&dma_msg, *iodma_m2m->da);
		msg4->var_data.str_op.dst_str_dis =
				iodma_m2m->str.dst_str_dis;
		msg4->var_data.str_op.dst_str_sz =
				iodma_m2m->str.dst_str_sz;
		msg4->var_data.str_op.dst_str_1_sz =
				iodma_m2m->str.dst_str_1_sz;
		msg4->var_data.str_op.src_str_dis =
				iodma_m2m->str.src_str_dis;
		msg4->var_data.str_op.src_str_sz =
				iodma_m2m->str.src_str_sz;
		msg4->var_data.str_op.src_str_1_sz =
				iodma_m2m->str.src_str_1_sz;
		PKTDMA_DRXTX("PADDR SRC: 0x%010llx PADDR DEST: 0x%010llx",
			*iodma_m2m->sa, *iodma_m2m->da);
		break;
	}

#if defined(APM_PKTDMA_DEBUG)
	if (iodma_m2m->cos < IODMA_MIN_COS || iodma_m2m->cos > IODMA_MAX_COS)
		PKTDMA_DEBUG("COS out of range %d", iodma_m2m->cos);
#endif
	send_msg.qid = chq->tx_qid[iodma_m2m->cos];
	send_msg.msg = &dma_msg;

	/* Check if slot available after NV is set */
	if (chk_slot) {
		if (!atomic_add_unless(&chq->tx_inflight[iodma_m2m->cos],
					1, chq->tx_max_slot[iodma_m2m->cos])) {
			/* Out of descriptor slot */
			PKTDMA_ERR("iodma-m2m-cos = %d, max_slot = %d\n",
			       iodma_m2m->cos, chq->tx_max_slot[iodma_m2m->cos]);
			apm_pktdma_op_free(op);
                        apm_pktdma_find_op(msg1_2->uinfo);
			PKTDMA_ERR("out of DMA descriptor");
			return -ENOMEM;
		}
		if (msg1_2->NV) {
			if (!atomic_add_unless(
					&chq->tx_inflight[iodma_m2m->cos],
					1, chq->tx_max_slot[iodma_m2m->cos])) {
				/* Out of descriptor slot */
				atomic_dec(&chq->tx_inflight[iodma_m2m->cos]);
				apm_pktdma_op_free(op);
                                apm_pktdma_find_op(msg1_2->uinfo);
				PKTDMA_ERR("out of DMA descriptor");
				return -ENOMEM;
			}
			op->chk_slot = 2;
		} else {
			op->chk_slot = 1;
		}
		op->cos = iodma_m2m->cos;
		op->chqid = chq;
	} else {
		op->chk_slot = 0;
	}

#ifdef APM_PKTDMA_DRXTX
	PKTDMA_DEBUG_DUMP("M2M Byte Message ", &dma_msg, msg1_2->NV ? 64 : 32);
#endif
	PKTDMA_DRXTX("CQID %d EQID %d len %d",
		msg3->H0Enq_Num, send_msg.qid, msg1_2->data_len);

	flags = apm_pktdma_msg_enq_lock();
#if defined(APM_PKTDMA_DEBUG_XTRA)
	memcpy(&p_dev.current_send_msg[p_dev.cnt_send_msg++],
	       &dma_msg, msg1_2->NV ? 64 : 32);
	if (p_dev.cnt_send_msg == QMSG_RSV_NUM)
	       p_dev.cnt_send_msg = 0;
	p_dev.pktdma_m2m_sent_pkts++;
#endif
	apm_qm_push_msg(&send_msg);
	apm_pktdma_msg_enq_unlock(flags);
	return 0;
}

int apm_pktdma_m2m_xfer(struct apm_pktdma_m2m_params *iodma_m2m)
{
	return apm_pktdma_m2m(iodma_m2m, 1);
}

int apm_pktdma_p2b(struct apm_pktdma_p2b_params *iodma_p2b, int chk_slot)
{
	/* NOTE: De-allocate for p2b after getting completion message */
	struct apm_pktdma_msg dma_msg;
	struct apm_qm_msg_desc send_msg;
	struct apm_dma_msg1_2 *msg1_2 = &dma_msg.msg1_2;
	struct apm_dma_msg_3 *msg3 = &dma_msg.msg3;
	struct apm_dma_msg_4 *msg4 = &dma_msg.msg4;
	struct iodma_op_state *op = NULL;
	unsigned long flags;
	struct pktdma_chan_qid *chq = &p_dev.qinfo.tx_q[iodma_p2b->chid];
	int rc;

	memset(&dma_msg, 0, sizeof(dma_msg));
	memset(&send_msg, 0, sizeof(send_msg));

	op = apm_pktdma_op_get();
	if (!op) {
		PKTDMA_ERR("Out of memory for PktDMA operation");
		return -ENOMEM;
	}
	op->result.cb = iodma_p2b->cb;
	op->result.ctx = iodma_p2b->context;
	op->major_opcode = PKT_TO_BUFF;

	/* set common params m2m_modem msg */
	msg1_2->coherent_read = apm_pktdma_is_coherent(); /* set the Coherent bit */
	msg1_2->RType = APM_QM_DMA_RTYPE;
	msg1_2->uinfo = (u32) (unsigned long) op;
	msg3->HE = 1;
	msg3->HR = 1;
	msg3->H0Enq_Num = p_dev.qinfo.queues[apm_processor_id()].comp_qid;
	/* Set to Host QID for Completion messages */
	msg4->BD = 1;
	msg3->H0FPSel = p_dev.qinfo.queues[apm_processor_id()].rx_fp_pbn;

	switch (iodma_p2b->p2b_mode) {
	case IODMA_COPY:
	default:
		apm_pktdma_qmesg_load_single_src(&dma_msg, *iodma_p2b->fp_sa,
				*iodma_p2b->byte_count, *iodma_p2b->fp_id);
		break;
	case IODMA_GATHER:
		apm_pktdma_qmesg_load_src_mul(&dma_msg, iodma_p2b->fp_sa,
				iodma_p2b->byte_count, iodma_p2b->fp_id,
				iodma_p2b->sg_count, op);
		break;
	}

	if (iodma_p2b->fby) {
		PKTDMA_DEBUG("Setting CRC and Checksum params");
		apm_pktdma_flyby_set(&iodma_p2b->fb, &dma_msg);
		op->fby_gen = iodma_p2b->fb.fb_type <= DMA_FBY_CHKSUM ? 1 : 0;
	}
	PKTDMA_DEBUG("free pool id mapped %d", msg3->H0FPSel);

	PKTDMA_DEBUG_DUMP("P2B Byte Message",
			(void *) &dma_msg, msg1_2->NV ? 64 : 32);
#if defined(APM_PKTDMA_DEBUG)
	if (iodma_p2b->cos < IODMA_MIN_COS || iodma_p2b->cos > IODMA_MAX_COS)
		PKTDMA_DEBUG("COS out of range %d", iodma_p2b->cos);
#endif
	send_msg.qid = p_dev.qinfo.tx_q[iodma_p2b->chid].tx_qid[iodma_p2b->cos];
	send_msg.msg = &dma_msg;

	/* Check if slot available after NV is set */
	if (chk_slot) {
		if (!atomic_add_unless(&chq->tx_inflight[iodma_p2b->cos],
					1, chq->tx_max_slot[iodma_p2b->cos])) {
			/* Out of descriptor slot */
			rc = -ENOMEM;
			goto err;
		}
		if (msg1_2->NV) {
			if (!atomic_add_unless(
					&chq->tx_inflight[iodma_p2b->cos],
					1, chq->tx_max_slot[iodma_p2b->cos])) {
				/* Out of descriptor slot */
				atomic_dec(&chq->tx_inflight[iodma_p2b->cos]);
				rc = -ENOMEM;
				goto err;
			}
			op->chk_slot = 2;
		} else {
			op->chk_slot = 1;
		}
		op->cos = iodma_p2b->cos;
		op->chqid = chq;
	} else {
		op->chk_slot = 0;
	}

	PKTDMA_DEBUG("CQID %d EQID %d len %d",
		    msg3->H0Enq_Num, send_msg.qid, msg1_2->data_len);
	flags = apm_pktdma_msg_enq_lock();
#if defined(APM_PKTDMA_DEBUG_XTRA)
	memcpy(&p_dev.current_send_msg[p_dev.cnt_send_msg++],
	       &dma_msg, msg1_2->NV ? 64 : 32);
	if (p_dev.cnt_send_msg == QMSG_RSV_NUM)
	       p_dev.cnt_send_msg = 0;
#endif
	apm_qm_push_msg(&send_msg);
	apm_pktdma_msg_enq_unlock(flags);
	return 0;

err:
	apm_pktdma_op_free(op);
	return -ENOMEM;
}

int apm_pktdma_p2b_xfer(struct apm_pktdma_p2b_params *iodma_p2b)
{
	return apm_pktdma_p2b(iodma_p2b, 1);
}

void apm_pktdma_chk_error(void)
{
	u32 val;

	apm_pktdma_read_reg(DMA_INT_ADDR, &val);
	if (val & MSG_SRC_INT_MASK)
		PKTDMA_ERR("HFB reading source link addr error 0x%08X", val);
	if (val & MSG_DST_INT_MASK)
		PKTDMA_ERR("HFB reading destination link addr error 0x%08X",
			val);
	if (val & BAD_MSG_MASK)
		PKTDMA_ERR("QM message HE0 not set error 0x%08X", val);
	if (val & RD_ERR_INT_MASK)
		PKTDMA_ERR("HBF bus read error 0x%08X", val);
	if (val & WR_ERR_INT_MASK)
		PKTDMA_ERR("HBF bus write error 0x%08X", val);
	if (val & RD_TIMEO_INT_MASK)
		PKTDMA_ERR("Read time out error 0x%08X", val);
	if (val & WR_TIMEO_INT_MASK)
		PKTDMA_ERR("Write time out error 0x%08X", val);
	if (val & RFIFO_OVF_INT_MASK)
		PKTDMA_ERR("Read FIFO over flow error 0x%08X", val);
	if (val & WFIFO_OVF_INT_MASK)
		PKTDMA_ERR("Write FIFO over flow error 0x%08X", val);
	if (val & FPB_TIMEO_INT_MASK)
		PKTDMA_ERR("Free pool time out error 0x%08X", val);
	if (val & GS_ERR_INT_MASK)
		PKTDMA_ERR("Gather scatter not same size error 0x%08X", val);
	if (val & BAD_DOM_ID_INT_MASK)
		PKTDMA_ERR("Invalid domain ID for free pool size error 0x%08X",
			val);
	apm_pktdma_write_reg(DMA_INT_ADDR, 0xFFFFFFFF);
}

int apm_pktdma_fp_pb_flush(int pbn)
{
	#define MAX_LOOP_POLL_CNT		100
	u32 fp_buffer_reg, max_pbn;
	u32 no_fp;
	u32 data = 0;
	u32 j, buf_addr;
	int count, rc;

	if (pbn <= 7) {
		fp_buffer_reg = DMA_STSSSQMIFPBUFFER1_ADDR;
		max_pbn = 0;
	} else if (pbn <= 17) {
		fp_buffer_reg = DMA_STSSSQMIFPBUFFER2_ADDR;
		max_pbn = 8;
	}
	else {
		PKTDMA_ERR("Error: Invalid FP PBN: %d \n", pbn);
		return -1;
	}

	rc = apm_pktdma_read_qmi_reg(fp_buffer_reg, &data);
	no_fp = ((data >> ((pbn - max_pbn) * 3))  & 0x7);
	PKTDMA_DEBUG("pbn %d pbn_data 0x%08X max_pbn %d no_fp %d",
		pbn, data, max_pbn, no_fp);

	for (j = 0; j < (no_fp * 4) ; j++) {
		count = 0;
		buf_addr = j % 4;
		data = DMA_PBID_WR(pbn + 0x20) | DMA_NACK_WR(1);
		if (buf_addr == 3) {
			data |= DMA_LAST_WR(1) | DMA_POP_WR(1) |DMA_READ_WR(0);
		} else {
			data |= DMA_LAST_WR(0) | DMA_POP_WR(0) |DMA_READ_WR(1);
		}
		data |= DMA_BUFFERADDR_WR(buf_addr) | DMA_PUSH_WR(0) |
				DMA_WRITE_WR(0);

		PKTDMA_DEBUG("J %d data 0x%08X", j, data);

		udelay(1000);
		rc = apm_pktdma_write_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR, data);
		while(1) {
			rc = apm_pktdma_read_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR,
							&data);
			if (!DMA_NACK_RD(data))
				break;

			udelay(1000);
			if (count++ > MAX_LOOP_POLL_CNT) {
				printk(KERN_ERR "DMA PBN flush failed\n");
				goto exit;
			}
		}
		/* Read the data from PBN, We dont care though */
		rc = apm_pktdma_read_qmi_reg(DMA_STSSSQMIDBGDATA_ADDR, &data);
		PKTDMA_DEBUG("PBN Data 0x%08X", data);
	}
exit:
	rc = apm_pktdma_read_qmi_reg(fp_buffer_reg, &data);
	no_fp = ((data >> (max_pbn - pbn)) & 0x7);
	PKTDMA_DEBUG("After flush pbn %d pbn_data 0x%08X max_pbn %d no_fp %d\n",
		pbn, data, max_pbn, no_fp);
	return no_fp;
}

int apm_pktdma_get_pb_cnt(int pbn)
{
	u32 val;

	if (pbn < (0x20 + 8)) {
		apm_pktdma_read_qmi_reg(DMA_STSSSQMIFPBUFFER1_ADDR, &val);
	} else {
		apm_pktdma_read_qmi_reg(DMA_STSSSQMIFPBUFFER2_ADDR, &val);
		pbn -= 8;
	}
	return (val >> ((pbn-0x20) * 3)) & 0x7;
}

void apm_pktdma_qmi_read_pb_msg(u32 pbn, u32 addroffset, u32 last, u32 *msg)
{
	u32 data = 0;

	data = DMA_PBID_SET(data, pbn);
#ifdef CONFIG_APM862xx
	data = DMA_READ_SET(data, 1);
#else /* CONFIG_APM867xx || CONFIG_APM866xx || CONFIG_APM862xxvB*/
	data = DMA_READ_SET(data, 1);
#endif

	data = DMA_NACK_SET(data, 1);
	data = DMA_BUFFERADDR_SET(data, addroffset);
	data = DMA_LAST_SET(data, last);

	apm_pktdma_write_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR, data);

	/* wait for the request completion */
	do {
		apm_pktdma_read_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR, &data);
	} while (DMA_NACK_RD(data) != 0);

	/* read the 32 bit data from STSSSQMIDBGDATA register */
	apm_pktdma_read_qmi_reg(DMA_STSSSQMIDBGDATA_ADDR, msg);
}

void apm_pktdma_qmi_pop_pb_msg(u32 pbn, u32 addroffset, u32 last, u32 *msg)
{
	u32 data = 0;

	data = DMA_PBID_SET(data, pbn);
	data = DMA_POP_SET(data, 1);
	data = DMA_NACK_SET(data, 1);
	data = DMA_BUFFERADDR_SET(data, addroffset);
	data = DMA_LAST_SET(data, last);

	apm_pktdma_write_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR, data);

	/* wait for the request completion */
	do {
		apm_pktdma_read_qmi_reg(DMA_CFGSSQMIDBGCTRL_ADDR, &data);
	} while (DMA_NACK_RD(data) != 0);

	/* read the 32 bit data from STSSSQMIDBGDATA register */
	apm_pktdma_read_qmi_reg(DMA_STSSSQMIDBGDATA_ADDR, msg);
}

int apm_pktdma_pbn_clr(int slave_id, int pbn)
{
	int no_buf;
	u32 word0;
	u32 word1;
	u32 word2;
	u32 word3;
	u32 val;
	int pbn_enabled;

	PKTDMA_DEBUG("Draining pbn %d", pbn);

	/* Disable queue pre-fetch buffer to not push message */
	val = apm_qm_pb_get(IP_BLK_QM, slave_id, pbn);
	pbn_enabled = val & (1 << 14);
	val &= ~(1 << 14);	/* Disable pre-fetch buffer pushing */
	apm_qm_pb_set(IP_BLK_QM, slave_id, pbn, val);

	/* Wait for any in-service to finish */
	do {
		val = apm_qm_pb_get(IP_BLK_QM, slave_id, pbn);
	} while (val & (1<<18));

	if (pbn < 0x20) {
		/* Non-free pool queue */
		apm_pktdma_write_qmi_reg(DMA_CFGSSQMIWQBUFFER_ADDR, 1 << pbn);
		do {
			apm_pktdma_read_qmi_reg(DMA_CFGSSQMIWQBUFFER_ADDR,
						&val);
		} while (val & (1 << pbn));
	} else {
		/* Now drain the ETH pre-fetch free pool buffer */
		no_buf = apm_pktdma_get_pb_cnt(pbn);
		/* Setup QM side to match to avoid QM error interrupt */
		val = apm_qm_pb_get(IP_BLK_QM, slave_id, pbn);
		val |= (1 << 31);
		val &= ~0xF;
		val |= (no_buf+1) & 0xF;
		apm_qm_pb_set(IP_BLK_QM, slave_id, pbn, val);
		PKTDMA_DEBUG("Draining pbn %d count %d", pbn, no_buf);
		while (no_buf > 0)  {
			apm_pktdma_qmi_read_pb_msg(pbn, 0, 0, &word3);
			apm_pktdma_qmi_read_pb_msg(pbn, 1, 0, &word2);
			apm_pktdma_qmi_read_pb_msg(pbn, 2, 0, &word1);
			apm_pktdma_qmi_pop_pb_msg(pbn, 3, 1, &word0);
			no_buf = apm_pktdma_get_pb_cnt(pbn);
		}
	}

	/* Clear PBN on the QM side */
	apm_qm_pb_clr(IP_BLK_QM, slave_id, pbn);

	if (pbn_enabled) {
		val = apm_qm_pb_get(IP_BLK_QM, slave_id, pbn);
		val |= 1 << 14;
		apm_qm_pb_set(IP_BLK_QM, slave_id, pbn, val);
	}
	return 0;
}

int apm_pktdma_enable_hw(void)
{
	u32 data;

	/* Enable engine */
	apm_pktdma_read_reg(DMA_GCR_ADDR, &data);
	data |= PKTDMA_EN_WR(1);
	data |= (DMA_QUEUE_MASK + DMA_OUTSTANDING_MASK);
	apm_pktdma_write_reg(DMA_GCR_ADDR, data);

	return 0;
}

#if defined(APM_PKTDMA_DEBUG_XTRA)
void apm_pktdma_diag_dump(void)
{
	int i;
	u32 val;

	apm_pktdma_read_reg(DMA_GCR_ADDR, &val);
	PKTDMA_DEBUG("DMA_GCR_ADDR 0x%08X", val);
	PKTDMA_DEBUG("DIAG register");
	apm_pktdma_write_diag_reg(0x44, 0x10);
	for (i = 0; i < 128; i++) {
		apm_pktdma_write_diag_reg(0, i * 2);
		apm_pktdma_read_diag_reg(0x58, &val);
		if (i > 46 && i < 96 && val == 0) {
			int j;

			for (j = 0; j < 20; j++) {
				udelay(1);
				apm_pktdma_read_diag_reg(0x58, &val);
				if (val)
					break;
			}
		}
		PKTDMA_DEBUG("DIAG[0x%02X] value 0x%08X", i, val);
	}
}

void apm_pktdma_qmi_dump(void)
{
	int i;

	PKTDMA_DEBUG("PktDMA QMI register");
	for (i = 0; i < 0x95; i += 4) {
		u32 val;
		apm_pktdma_read_qmi_reg(i, &val);
		PKTDMA_DEBUG("QMI[0x%X] value 0x%08X", i, val);
	}
}

void apm_pktdma_dump_qmsges(void)
{

	int i;
	for (i = 0; i < QMSG_RSV_NUM; i++) {
		PKTDMA_DEBUG("dma qm msg %d", i);
#ifdef APM_PKTDMA_DRXTX
		PKTDMA_DEBUG_DUMP("DMA Byte Message ",
				  &p_dev.current_send_msg[i], 64);
#endif
	}
	return;
}
#endif
