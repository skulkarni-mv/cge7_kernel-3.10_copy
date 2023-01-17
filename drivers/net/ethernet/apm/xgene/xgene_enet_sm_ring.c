/* Applied Micro X-Gene SoC Ethernet Driver
 *
 * Copyright (c) 2014, Applied Micro Circuits Corporation
 * Authors: Iyappan Subramanian <isubramanian@apm.com>
 *	    Ravi Patel <rapatel@apm.com>
 *	    Keyur Chudgar <kchudgar@apm.com>
 *          Hrishikesh Karanjikar <hkaranjikar@apm.com>
 *
 * This program is free software; you can redistribute  it and/or modify it
 * under  the terms of  the GNU General  Public License as published by the
 * Free Software Foundation;  either version 2 of the  License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/of_platform.h>
#include "xgene_enet_main.h"
#include "xgene_enet_sm_ring.h"

static struct xgene_enet_desc_info desc_info[MAX_DESC_INFO_INDEX] = {
	[USERINFO] = {0, USERINFO_POS, USERINFO_LEN},
	[FPQNUM] = {0, FPQNUM_POS, FPQNUM_LEN},
	[STASH] = {0, STASH_POS, STASH_LEN},
	[DATAADDR] = {1, DATAADDR_POS, DATAADDR_LEN},
	[BUFDATALEN] = {1, BUFDATALEN_POS, BUFDATALEN_LEN},
	[BUFLEN] = {1, BUFLEN_POS, BUFLEN_LEN},
	[COHERENT] = {1, COHERENT_POS, COHERENT_LEN},
	[LL_LSB] = {2, LL_LSB_POS, LL_LSB_LEN},
	[TCPHDR] = {3, TCPHDR_POS, TCPHDR_LEN},
	[IPHDR] = {3, IPHDR_POS, IPHDR_LEN},
	[ETHHDR] = {3, ETHHDR_POS, ETHHDR_LEN},
	[EC] = {3, EC_POS, EC_LEN},
	[ET] = {3, ET_POS, ET_LEN},
	[IS] = {3, IS_POS, IS_LEN},
	[IC] = {3, IC_POS, IC_LEN},
	[TYPESEL] = {3, TYPESEL_POS, TYPESEL_LEN},
	[HENQNUM] = {3, HENQNUM_POS, HENQNUM_LEN},
	[ELERR] = {0, ELERR_POS, ELERR_LEN},
	[LERR] = {0, LERR_POS, LERR_LEN},
	[NV] = {0, NV_POS, NV_LEN},
	[LL] = {0, LL_POS, LL_LEN},
};

static inline void set_desc(struct xgene_enet_desc *desc, enum desc_info_index index,
		     u64 val)
{
	u8 word_index = desc_info[index].word_index;
	u8 start_bit = desc_info[index].start_bit;
	u8 len = desc_info[index].len;


	u64 mask = GENMASK_ULL((start_bit + len - 1), start_bit);
	((u64 *)desc)[word_index] = (((u64 *)desc)[word_index] & ~mask)
	    | (((u64) val << start_bit) & mask);
}

static inline u64 get_desc(struct xgene_enet_desc *desc, enum desc_info_index index)
{
	u8 word_index = desc_info[index].word_index;
	u8 start_bit = desc_info[index].start_bit;
	u8 len = desc_info[index].len;

	u64 mask = GENMASK_ULL((start_bit + len - 1), start_bit);
	return (((u64 *)desc)[word_index] & mask) >> start_bit;
}

static void set_addr_and_len(void *desc, u8 index,
	       		     dma_addr_t addr, u32 len)
{
	if (len == BUFLEN_16K)
		len = 0;
	((u64 *)desc)[index] = (addr & DATAADDR_MASK) |
	       	(((u64)len << BUFDATALEN_POS) & BUFDATALEN_MASK);
}

static inline void xgene_enet_ring_init(u32 *ring_cfg, u64 addr,
					enum xgene_enet_ring_cfgsize cfgsize,
					int irq)
{
	ring_cfg[4] |= ((u32) 1 << SELTHRSH_POS)
	    & CREATE_MASK(SELTHRSH_POS, SELTHRSH_LEN);
	ring_cfg[3] |= ((u32) 1 << ACCEPTLERR_POS)
	    & CREATE_MASK(ACCEPTLERR_POS, ACCEPTLERR_LEN);
	ring_cfg[2] |= ((u32) 1 << QCOHERENT_POS)
	    & CREATE_MASK(QCOHERENT_POS, QCOHERENT_LEN);

	addr >>= 8;
	ring_cfg[2] |= (addr << RINGADDRL_POS)
	    & CREATE_MASK_ULL(RINGADDRL_POS, RINGADDRL_LEN);
	addr >>= RINGADDRL_LEN;
	ring_cfg[3] |= addr & CREATE_MASK_ULL(RINGADDRH_POS, RINGADDRH_LEN);
	ring_cfg[3] |= ((u32) cfgsize << RINGSIZE_POS)
	    & CREATE_MASK(RINGSIZE_POS, RINGSIZE_LEN);
}

static inline void xgene_enet_ring_set_type(u32 *ring_cfg, u8 is_bufpool)
{
	u8 val = is_bufpool ? RING_BUFPOOL : RING_REGULAR;
	ring_cfg[4] |= ((u32) val << RINGTYPE_POS)
	    & CREATE_MASK(RINGTYPE_POS, RINGTYPE_LEN);

	if (is_bufpool) {
		ring_cfg[3] |= ((u32) BUFPOOL_MODE << RINGMODE_POS)
		    & CREATE_MASK(RINGMODE_POS, RINGMODE_LEN);
	}
}

static inline void xgene_enet_ring_set_recombbuf(u32 *ring_cfg)
{
	ring_cfg[3] |= ((u32) 1 << RECOMBBUF_POS)
	    & CREATE_MASK(RECOMBBUF_POS, RECOMBBUF_LEN);
	ring_cfg[3] |= ((u32) 0xf << RECOMTIMEOUTL_POS)
	    & CREATE_MASK(RECOMTIMEOUTL_POS, RECOMTIMEOUTL_LEN);
	ring_cfg[4] |= (u32) 0x7
	    & CREATE_MASK(RECOMTIMEOUTH_POS, RECOMTIMEOUTH_LEN);
}

static inline void xgene_enet_ring_wr32(struct xgene_enet_desc_ring *ring,
					u32 offset, u32 data)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	iowrite32(data, pdata->ring_csr_addr + offset);
}

static inline void xgene_enet_ring_rd32(struct xgene_enet_desc_ring *ring,
					u32 offset, u32 *data)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	*data = ioread32(pdata->ring_csr_addr + offset);
}

static void xgene_enet_write_ring_state(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	int i;

	xgene_enet_ring_wr32(ring, CSR_RING_CONFIG, ring->num);
	for (i = 0; i < pdata->ring_ops.num_ring_cfg; i++) {
		xgene_enet_ring_wr32(ring, CSR_RING_WR_BASE + (i * 4),
				     ring->state[i]);
	}
}

static void xgene_enet_read_ring_state(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);
	int i;

	xgene_enet_ring_wr32(ring, CSR_RING_CONFIG, ring->num);
	memset(ring->state, 0, sizeof(u32) * pdata->ring_ops.num_ring_cfg);
	for (i = 0; i < pdata->ring_ops.num_ring_cfg; i++) {
		xgene_enet_ring_rd32(ring, CSR_RING_RD_BASE + (i * 4),
				     &ring->state[i]);
	}
}

static void xgene_enet_clr_ring_state(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);

	memset(ring->state, 0, sizeof(u32) * pdata->ring_ops.num_ring_cfg);
	xgene_enet_write_ring_state(ring);
}

extern u32 xgene_get_ring_state(u32 state, u8 start_bit, u8 len);

static void xgene_get_ring_info(struct xgene_enet_desc_ring *ring,
                                struct xgene_enet_ring_info *info)
{
        u32 s1;

        xgene_enet_read_ring_state(ring);

        s1 = ring->state[1];

        info->headptr = xgene_get_ring_state(s1, HEAD_PTR_POS, HEAD_PTR_LEN);
        info->nummsginq = xgene_get_ring_state(s1, NUMMSGINQ_POS, NUMMSGINQ_LEN);
}

static void xgene_dump_ring_state(struct xgene_enet_desc_ring *ring)
{
	u32 s0, s1, s2, s3, s4;
	u32 qcoherent, addrh, addrl;
	u64 cfgstartaddr;
	u32 nummsginq, slots_pending, headptr;
	u32 cfgqsize, cfgacceptlerr, fp_mode;
	u32 cfgenrecombbuf, cfgrecombbuftimeoutl, cfgrecombbuftimeouth;
	u32 cfgselthrsh, cfgqtype;

	if(!ring)
		return;

	xgene_enet_read_ring_state(ring);

	s0 = ring->state[0];
	s1 = ring->state[1];
	s2 = ring->state[2];
	s3 = ring->state[3];
	s4 = ring->state[4];

	headptr = xgene_get_ring_state(s1, HEAD_PTR_POS, HEAD_PTR_LEN);
	nummsginq = xgene_get_ring_state(s1, NUMMSGINQ_POS, NUMMSGINQ_LEN);
	qcoherent = xgene_get_ring_state(s2, QCOHERENT_POS, QCOHERENT_LEN);
	addrh = xgene_get_ring_state(s3, RINGADDRH_POS, RINGADDRH_LEN);
	addrl = xgene_get_ring_state(s2, RINGADDRL_POS, RINGADDRL_LEN);
	cfgstartaddr = (((u64)addrh) << 35) | (addrl << 8);
	cfgqsize = xgene_get_ring_state(s3, RINGSIZE_POS, RINGSIZE_LEN);
	cfgacceptlerr = xgene_get_ring_state(s3, ACCEPTLERR_POS,
			ACCEPTLERR_LEN);
	fp_mode = xgene_get_ring_state(s3, RINGMODE_POS, RINGMODE_LEN);
	slots_pending = xgene_get_ring_state(s3, SLOTS_PENDING_POS,
			SLOTS_PENDING_LEN);
	cfgenrecombbuf = xgene_get_ring_state(s3, RECOMBBUF_POS, RECOMBBUF_LEN);
	cfgrecombbuftimeoutl = xgene_get_ring_state(s3, RECOMTIMEOUTL_POS,
				     RECOMTIMEOUTL_LEN);
	cfgrecombbuftimeouth = xgene_get_ring_state(s4, RECOMTIMEOUTH_POS,
				     RECOMTIMEOUTH_LEN);
	cfgselthrsh = xgene_get_ring_state(s4, SELTHRSH_POS, SELTHRSH_LEN);
	cfgqtype = xgene_get_ring_state(s4, RINGTYPE_POS, RINGTYPE_LEN);

#ifdef ENET_DEBUG
	pr_info("+ =============\n");
	pr_info("+ Ring: %p\n", ring);
	pr_info("+ Headptr: %d\n", headptr);
	pr_info("+ NummsginQ: %x\n", nummsginq);
	pr_info("+ QCoherent: %x\n", qcoherent);
	pr_info("+ CfgStartAddr: 0x%016llx\n", cfgstartaddr);
	pr_info("+ CfgAcceptLErr: %x\n", cfgacceptlerr);
	pr_info("+ FP_mode: %x\n", fp_mode);
	pr_info("+ Slots_pending: %x\n", slots_pending);
	pr_info("+ CfgQSize: %x\n", cfgqsize);
	pr_info("+ CfgEnRecombBuf: %x\n", cfgenrecombbuf);
	pr_info("+ CfgRecombBufTimeout1: %x\n", cfgrecombbuftimeoutl);
	pr_info("+ CfgRecombBufTimeouth: %x\n", cfgrecombbuftimeouth);
	pr_info("+ CfgSelThrsh: %x\n", cfgselthrsh);
	pr_info("+ CfgQType: %x\n", cfgqtype);
#endif
}

static void xgene_enet_set_ring_state(struct xgene_enet_desc_ring *ring)
{
	xgene_enet_ring_set_type(ring->state, ring->is_bufpool);

	if (ring->owner == RING_OWNER_ETH0)
		xgene_enet_ring_set_recombbuf(ring->state);

	xgene_enet_ring_init(ring->state, ring->dma, ring->cfgsize, ring->irq);
	xgene_enet_write_ring_state(ring);

	xgene_dump_ring_state(ring);
}

static u16 xgene_enet_get_ring_num(struct xgene_enet_pdata *pdata)
{
	return pdata->ring_num++;
}

static void xgene_enet_set_ring_id(struct xgene_enet_desc_ring *ring)
{
	u32 ring_id, ring_id_val;
	u32 ring_id_buf;

	ring_id = (ring->owner << 6) | ring->buf_num;
	ring_id_val = OVERWRITE | (ring_id & GENMASK(9, 0));

	ring_id_buf = (ring->num << 9) & GENMASK(18, 9);
	ring_id_buf |= BUF_EN;
	if (ring->is_bufpool)
		ring_id_buf |= IS_FREE_POOL;

	xgene_enet_ring_wr32(ring, CSR_RING_ID, ring_id_val);
	xgene_enet_ring_wr32(ring, CSR_RING_ID_BUF, ring_id_buf);
}

static void xgene_enet_clr_desc_ring_id(struct xgene_enet_desc_ring *ring)
{
	u32 ring_id = (ring->owner << 6) | ring->buf_num;
	u32 ring_id_val = OVERWRITE | (ring_id & GENMASK(9, 0));

	xgene_enet_ring_wr32(ring, CSR_RING_ID, ring_id_val);
	xgene_enet_ring_wr32(ring, CSR_RING_ID_BUF, 0);
}

static struct xgene_enet_desc_ring *xgene_enet_setup_ring(
					struct xgene_enet_desc_ring *ring)
{
	u32 size = ring->size;
	u32 i, data;

	ring->slots = ring->is_bufpool ? size / 16 : size / 32;

	xgene_enet_clr_ring_state(ring);
	xgene_enet_set_ring_state(ring);
	xgene_enet_set_ring_id(ring);

	if (ring->is_bufpool || ring->owner != RING_OWNER_CPU)
		goto out;

	for (i = 0; i < ring->slots; i++) {
		u64 *desc = (u64 *)&ring->desc[i];
		desc[EMPTY_SLOT_INDEX] = EMPTY_SLOT;
	}

	xgene_enet_ring_rd32(ring, CSR_RING_NE_INT_MODE, &data);
	data |= (u32) (1 << (31 - ring->buf_num));
	xgene_enet_ring_wr32(ring, CSR_RING_NE_INT_MODE, data);

out:
	return ring;
}

static void xgene_enet_clear_ring(struct xgene_enet_desc_ring *ring)
{
	u32 data;

	if (ring->is_bufpool || ring->owner != RING_OWNER_CPU)
		goto out;

	xgene_enet_ring_rd32(ring, CSR_RING_NE_INT_MODE, &data);
	data &= ~(u32) (1 << (31 - ring->buf_num));
	xgene_enet_ring_wr32(ring, CSR_RING_NE_INT_MODE, data);

out:
	xgene_enet_clr_desc_ring_id(ring);
	xgene_enet_clr_ring_state(ring);
}

static const struct pbn_errata_table fp_pbn_errata[] = {
	{0, 0, 0, 4, 0, 0, 0, 0},
	{0, 0, 5, 9, 0, 0, 0, 0},
	{0, 0, 10, 14, 0, 0, 0, 0},
	{0, 0, 15, 19, 0, 0, 0, 0},
	{0, 0, 20, 24, 0, 0, 0, 0},
	{0, 0, 25, 29, 0, 0, 0, 0},
	{0, 1, 30, 31, 0, 2, 2, 0},
	{1, 0, 3, 7, 0, 0, 0, 0}
};

static const struct pbn_errata_table wq_pbn_errata[] = {
	{0, 0, 0, 4, 8, 8, 5, 0},
	{0, 0, 9, 12, 16, 17, 4, 0},
	{0, 0, 18, 20, 24, 26, 3, 0},
	{0, 1, 27, 28, 0, 3, 2, 0},
	{1, 1, 4, 4, 8, 12, 1, 0},
	{1, 1, 16, 20, 24, 24, 5, 0},
	{1, 2, 25, 28, 0, 1, 4, 0},
	{2, 2, 2, 4, 8, 10, 3, 0}
};

static void xgene_enet_clear_pb(struct xgene_enet_desc_ring *ring)
{
	u32 nummsg = 0, data = 0, count = 0, val = 0, val1 = 0;
	u32 reg_offset = 0, start_bit = 0, end_bit = 0;
	u32 reg_offset1 = 0, start_bit1 = 0, end_bit1 = 0;
	u32 shift_width = 0, buf_num = ring->buf_num - 0x20;
	struct xgene_enet_pdata *pdata;
	pdata = netdev_priv(ring->ndev);

	/* Implementation as per bug no 43761 */
	if (ring->is_bufpool) {
		reg_offset = (sizeof(u32) * fp_pbn_errata[buf_num].reg_offset);
		reg_offset += ENET_STSSSQMIFPNUMENTRIES0;

		reg_offset1 = (sizeof(u32) * fp_pbn_errata[buf_num].reg_offset1);
		reg_offset1 += ENET_STSSSQMIFPNUMENTRIES0;

		start_bit = fp_pbn_errata[buf_num].start_bit;
		end_bit = fp_pbn_errata[buf_num].end_bit;
		
		start_bit1 = fp_pbn_errata[buf_num].start_bit1;
		end_bit1 = fp_pbn_errata[buf_num].end_bit1;

		shift_width = fp_pbn_errata[buf_num].shift_width;
	} else {
		reg_offset = (sizeof(u32) * wq_pbn_errata[buf_num].reg_offset);
		reg_offset += ENET_STSSSQMIWQNUMENTRIES0;

		reg_offset1 = (sizeof(u32) * wq_pbn_errata[buf_num].reg_offset1);
		reg_offset1 += ENET_STSSSQMIWQNUMENTRIES0;

		start_bit = wq_pbn_errata[buf_num].start_bit;
		end_bit = wq_pbn_errata[buf_num].end_bit;
		
		start_bit1 = wq_pbn_errata[buf_num].start_bit1;
		end_bit1 = wq_pbn_errata[buf_num].end_bit1;

		shift_width = wq_pbn_errata[buf_num].shift_width;
	}

	pdata->enet_rd_wr_ops.rd_ring_if(pdata,	reg_offset, &val);
	pdata->enet_rd_wr_ops.rd_ring_if(pdata,	reg_offset1, &val1);

	if (shift_width) {
		nummsg = (((val1 & GENMASK(end_bit1, start_bit1))
				>> start_bit1) << shift_width) |
				((val & GENMASK(end_bit, start_bit))
				>> start_bit);
	} else {
		nummsg = (val & GENMASK(end_bit, start_bit)) >> start_bit;
	}

        PBID(&data, ring->buf_num);
        BUFFERADDR(&data, 3);
        data |= POP;
        data |= NACK;
        data |= LAST;

        while (nummsg--)  {
		pdata->enet_rd_wr_ops.wr_ring_if(pdata,
				ENET_CFGSSQMIDBGCTRL_ADDR, data);

		/* wait for the request completion */
		do {
			pdata->enet_rd_wr_ops.rd_ring_if(pdata,
					ENET_CFGSSQMIDBGCTRL_ADDR, &val);
		} while (((NACK & val) != 0) && (count++ < 200000));

		if (count >= 200000)
			pr_err("+Failed to pop PB\n");

		pdata->enet_rd_wr_ops.rd_ring_if(pdata,
				ENET_CFGSSQMIDBGDATA_ADDR, &val);
        }

	xgene_enet_clr_desc_ring_id(ring);
	xgene_enet_set_ring_id(ring);
}

static void set_cmd_base(struct xgene_enet_desc_ring *ring)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);

	ring->cmd_base = pdata->ring_cmd_addr +
	       		 ((ring->num % pdata->total_rings) << 6);
}

static void wr_cmd(struct xgene_enet_desc_ring *ring, int count)
{
	iowrite32(count, ring->cmd);
}

static inline u32 ring_len(struct xgene_enet_desc_ring *ring)
{
	void *cmd_base = ring->cmd_base;
	return (ioread32(&(((u32 *)cmd_base)[1])) & 0x1fffe) >> 1;
}

struct xgene_ring_ops xgene_sm_ring_ops = {
	.type = XGENE_SM_RING_3,
	.num_ring_cfg = 5,
	//.num = 0,
	.setup = xgene_enet_setup_ring,
	.clear = xgene_enet_clear_ring,
	.get_num = xgene_enet_get_ring_num,
	.set_desc = set_desc,
	.get_desc = get_desc,
	.set_addr_and_len = set_addr_and_len,
	.set_cmd_base = set_cmd_base,
	.wr_cmd = wr_cmd,
	.len = ring_len,
	.dump_ring_state = xgene_dump_ring_state,
	.get_ring_info = xgene_get_ring_info,
	.clear_pb = xgene_enet_clear_pb,
	.ring_csr_rd = xgene_enet_ring_rd32,
	.ring_csr_wr = xgene_enet_ring_wr32
};
