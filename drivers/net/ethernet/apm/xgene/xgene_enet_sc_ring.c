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
#include "xgene_enet_sc_ring.h"

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
	[AM] = {0, AM_POS, AM_LEN},
};

static void set_desc(struct xgene_enet_desc *desc, enum desc_info_index index,
		     u64 val)
{
	u8 word_index = desc_info[index].word_index;
	u8 start_bit = desc_info[index].start_bit;
	u8 len = desc_info[index].len;
	u64 mask = GENMASK_ULL((start_bit + len - 1), start_bit);

	((u64 *)desc)[word_index] = (((u64 *)desc)[word_index] & ~mask)
	    | (((u64) val << start_bit) & mask);
}

static u64 get_desc(struct xgene_enet_desc *desc, enum desc_info_index index)
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

static void xgene_enet_ring_init(u32 *ring_cfg, u64 addr,
					enum xgene_enet_ring_cfgsize cfgsize,
					int irq)
{
	/* setting dequeue irq and enable */
	if (irq > 0) {
		ring_cfg[0] |= ((irq - FIRST_DEQ_IRQ) << INTLINE_POS)
			& CREATE_MASK(INTLINE_POS, INTLINE_LEN);
		ring_cfg[3] |= BIT(DEQINTEN_POS);
	}

	/* setting addr mode = machine physical address */
	ring_cfg[5] |= BIT(QBASE_AM_POS);
	ring_cfg[5] |= BIT(MSG_AM_POS);

	/* critical region ID */
	ring_cfg[0] |= ((1 << CFGCRID_POS) & 
			CREATE_MASK(CFGCRID_POS, CFGCRID_LEN));

	ring_cfg[4] |= ((u32) 1 << SC_SELTHRSH_POS)
	    & CREATE_MASK(SC_SELTHRSH_POS, SC_SELTHRSH_LEN);
	ring_cfg[3] |= ((u32) 1 << ACCEPTLERR_POS)
	    & CREATE_MASK(ACCEPTLERR_POS, ACCEPTLERR_LEN);

	ring_cfg[2] |= ((u32) 1 << QCOHERENT_POS)
	    & CREATE_MASK(QCOHERENT_POS, QCOHERENT_LEN);

	addr >>= 8;
	ring_cfg[2] |= (addr << RINGADDRL_POS)
			& CREATE_MASK_ULL(RINGADDRL_POS, RINGADDRL_LEN);
	addr >>= 27;
	ring_cfg[3] |= addr & CREATE_MASK_ULL(RINGADDRH_POS, RINGADDRH_LEN);
	ring_cfg[3] |= ((u32) cfgsize << RINGSIZE_POS)
	    & CREATE_MASK(RINGSIZE_POS, RINGSIZE_LEN);
}

static void xgene_enet_ring_set_type(u32 *ring_cfg, u8 is_bufpool)
{
	u8 val = is_bufpool ? RING_BUFPOOL : RING_REGULAR;

	ring_cfg[4] |= ((u32) val << SC_RINGTYPE_POS)
	    & CREATE_MASK(SC_RINGTYPE_POS, SC_RINGTYPE_LEN);

	if (is_bufpool) {
		ring_cfg[3] |= ((u32) BUFPOOL_MODE << RINGMODE_POS)
		    & CREATE_MASK(RINGMODE_POS, RINGMODE_LEN);
	}
}

static void xgene_enet_ring_set_recombbuf(u32 *ring_cfg)
{
	ring_cfg[3] |= ((u32) 1 << RECOMBBUF_POS)
	    & CREATE_MASK(RECOMBBUF_POS, RECOMBBUF_LEN);
	ring_cfg[4] |= (u32) 0x7f
	    & CREATE_MASK(RECOMTIMEOUT_POS, RECOMTIMEOUT_LEN);
}

static void xgene_enet_ring_wr32(struct xgene_enet_desc_ring *ring,
					u32 offset, u32 data)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);

	iowrite32(data, pdata->ring_csr_addr + offset);
}

static void xgene_enet_ring_rd32(struct xgene_enet_desc_ring *ring,
					u32 offset, u32 *data)
{
	struct xgene_enet_pdata *pdata = netdev_priv(ring->ndev);

	*data = ioread32(pdata->ring_csr_addr + offset);
}

static void xgene_enet_qm_write(struct xgene_enet_pdata *pdata,
					u32 offset, u32 data)
{
	iowrite32(data, pdata->ring_csr_addr + offset);
}

static void xgene_enet_qm_read(struct xgene_enet_pdata *pdata,
					u32 offset, u32 *data)
{
	*data = ioread32(pdata->ring_csr_addr + offset);
}

int xgene_qmtm_enable(struct xgene_enet_pdata *pdata)
{
	u32 val;
	u32 counter = 1000;
	u32 clk_offset, rst_offset;

	if (pdata->intf == XGENE_MN_MENET
	|| pdata->intf == XGENE_MN_RGMII1
	|| pdata->intf == XGENE_MN_SGENET_0
	|| pdata->intf == XGENE_MN_SGENET_1) {
		clk_offset = CSR_QM_CLKRST - 0x200;
		rst_offset = CSR_QM_SRST - 0x200;
	} else {
		clk_offset = CSR_QM_CLKRST;
		rst_offset = CSR_QM_SRST;
	}

	xgene_enet_qm_write(pdata, rst_offset, 0x3);
	xgene_enet_qm_write(pdata, clk_offset, 0x3);
	xgene_enet_qm_write(pdata, rst_offset, 0x0);

	/* Bring up memory */
	xgene_enet_qm_write(pdata, CSR_QM_MEM_RAM_SHUTDOWN, 0);
	usleep_range(1000, 1100);	/* wait 1 ms for completion */
	xgene_enet_qm_read(pdata, CSR_QM_MEM_RAM_SHUTDOWN, &val);
	if (val == 0xffffffff) {
		netdev_err(pdata->ndev,
			   "Failed to release memory from shutdown\n");
		return -ENODEV;
	}

	do {
		xgene_enet_qm_read(pdata, CSR_QM_MEM_RDY, &val);
		if (counter-- == 0) {
			netdev_err(pdata->ndev,
				"Memory is not ready yet\n");
			return -ENODEV;
		}
	} while (val != 0xffffffff);

	return 0;
}

int xgene_qmtm_set_coleascing(struct xgene_enet_pdata *pdata)
{
        /* program all interrupt coleasing registers */
        xgene_enet_qm_write(pdata, CSR_PBM_COAL, 0x7000ffff);
        xgene_enet_qm_write(pdata, CSR_CTICK0, 0x77777777);
        xgene_enet_qm_write(pdata, CSR_CTICK1, 0x77777777);
        xgene_enet_qm_write(pdata, CSR_CTICK2, 0x77777777);
        xgene_enet_qm_write(pdata, CSR_CTICK3, 0x77777777);
        
        /* program all threshold sets and all hysteresis */
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET0, 4);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET0, 8);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET1, 16);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET1, 64);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET2, 64);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET2, 128);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET3, 256);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET3, 512);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET4, 512);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET4, 1024);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET5, 1024);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET5, 1536);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET6, 2048);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET6, 3072);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD0_SET7, 4096);
        xgene_enet_qm_write(pdata, CSR_THRESHOLD1_SET7, 12288);
        xgene_enet_qm_write(pdata, CSR_HYSTERESIS, 0x08FFFFFF);

	return 0;
}

static void xgene_enet_write_ring_state(struct xgene_enet_desc_ring *ring)
{
	int i;

	xgene_enet_ring_wr32(ring, CSR_RING_CONFIG, ring->num);
	for (i = 0; i < NUM_RING_CONFIG; i++) {
		xgene_enet_ring_wr32(ring, CSR_RING_WR_BASE + (i * 4),
				     ring->state[i]);
	}
}

static void xgene_enet_read_ring_state(struct xgene_enet_desc_ring *ring)
{
	int i;

	xgene_enet_ring_wr32(ring, CSR_RING_CONFIG, ring->num);
	memset(ring->state, 0, sizeof(u32) * NUM_RING_CONFIG);
	for (i = 0; i < NUM_RING_CONFIG; i++) {
		xgene_enet_ring_rd32(ring, SC_CSR_RING_RD_BASE + (i * 4),
				     &ring->state[i]);
	}
}

static void xgene_enet_clr_ring_state(struct xgene_enet_desc_ring *ring)
{
	memset(ring->state, 0, sizeof(u32) * NUM_RING_CONFIG);
	xgene_enet_write_ring_state(ring);
}

u64 xgene_get_ring_state(u32 state, u8 start_bit, u8 len)
{
	u32 mask = GENMASK((start_bit + len - 1), start_bit);

	return (state & mask) >> start_bit;
}

static void xgene_get_ring_info(struct xgene_enet_desc_ring *ring,
				struct xgene_enet_ring_info *info)
{
	u32 s1;

	xgene_enet_read_ring_state(ring);

	s1 = ring->state[1];

	info->headptr = xgene_get_ring_state(s1, HEAD_PTR_POS, HEAD_PTR_LEN);
	info->nummsginq = xgene_get_ring_state(s1, SC_NUMMSGINQ_POS, SC_NUMMSGINQ_LEN);
}

static void xgene_dump_ring_state(struct xgene_enet_desc_ring *ring)
{
	u32 s0, s1, s2, s3, s4, s5;
	u32 cfgintline, cfgcrid, cfgdeqinten, qcoherent, addrh, addrl;
	u64 cfgstartaddr;
	u32 nummsginq, slots_pending, headptr;
	u32 cfgqsize, cfgacceptlerr, fp_mode;
	u32 cfgenrecombbuf, cfgrecombbuftimeout;
	u32 cfgselthrsh, cfgqtype;
	u32 msg_am, qbase_am;

	xgene_enet_read_ring_state(ring);

	s0 = ring->state[0];
	s1 = ring->state[1];
	s2 = ring->state[2];
	s3 = ring->state[3];
	s4 = ring->state[4];
	s5 = ring->state[5];

	cfgintline = xgene_get_ring_state(s0, INTLINE_POS, INTLINE_LEN);
	cfgcrid = xgene_get_ring_state(s0, CFGCRID_POS, CFGCRID_LEN);
	headptr = xgene_get_ring_state(s1, HEAD_PTR_POS, HEAD_PTR_LEN);
	nummsginq = xgene_get_ring_state(s1, SC_NUMMSGINQ_POS, SC_NUMMSGINQ_LEN);
	cfgdeqinten = xgene_get_ring_state(s3, DEQINTEN_POS, DEQINTEN_LEN);
	qcoherent = xgene_get_ring_state(s2, QCOHERENT_POS, QCOHERENT_LEN);
	addrh = xgene_get_ring_state(s3, RINGADDRH_POS, RINGADDRH_LEN);
	addrl = xgene_get_ring_state(s2, RINGADDRL_POS, RINGADDRL_LEN);
	cfgstartaddr = (((u64)addrh) << 35) | (addrl << 8);
	cfgqsize = xgene_get_ring_state(s3, RINGSIZE_POS, RINGSIZE_LEN);
	cfgacceptlerr = xgene_get_ring_state(s3, ACCEPTLERR_POS, ACCEPTLERR_LEN);
	fp_mode = xgene_get_ring_state(s3, RINGMODE_POS, RINGMODE_LEN);
	slots_pending = xgene_get_ring_state(s3, SLOTS_PENDING_POS, SLOTS_PENDING_LEN);
	cfgenrecombbuf = xgene_get_ring_state(s3, RECOMBBUF_POS, RECOMBBUF_LEN);
	cfgrecombbuftimeout = xgene_get_ring_state(s4, RECOMTIMEOUT_POS,
					     RECOMTIMEOUT_LEN);
	cfgselthrsh = xgene_get_ring_state(s4, SC_SELTHRSH_POS, SC_SELTHRSH_LEN);
	cfgqtype = xgene_get_ring_state(s4, SC_RINGTYPE_POS, SC_RINGTYPE_LEN);
	msg_am = xgene_get_ring_state(s5, MSG_AM_POS, MSG_AM_LEN);
	qbase_am = xgene_get_ring_state(s5, QBASE_AM_POS, QBASE_AM_LEN);

#ifdef ENET_DEBUG
	pr_info("+ =============\n");
	//pr_info("+ Ring: %p\n", ring);
	//pr_info("+ CfgIntLine: %d\n", cfgintline);
	//pr_info("+ Headptr: %d\n", headptr);
	pr_info("+ NummsginQ: %d\n", nummsginq);
#if 0
	pr_info("+ CfgDeqIntEn: %d\n", cfgdeqinten);
	pr_info("+ CfgCRid: %d\n", cfgcrid);
	pr_info("+ QCoherent: %d\n", qcoherent);
	pr_info("+ CfgStartAddr: 0x%016llx\n", cfgstartaddr);
	pr_info("+ CfgAcceptLErr: %d\n", cfgacceptlerr);
	pr_info("+ FP_mode: %d\n", fp_mode);
	pr_info("+ Slots_pending: %d\n", slots_pending);
	pr_info("+ CfgQSize: %d\n", cfgqsize);
	pr_info("+ CfgEnRecombBuf: %d\n", cfgenrecombbuf);
	pr_info("+ CfgRecombBufTimeout: %d\n", cfgrecombbuftimeout);
	pr_info("+ CfgSelThrsh: %d\n", cfgselthrsh);
	pr_info("+ CfgQType: %d\n", cfgqtype);
	pr_info("+ Msg_AM: %d\n", msg_am);
	pr_info("+ QBase_AM: %d\n", qbase_am);
#endif
#endif
}

static void xgene_enet_set_ring_state(struct xgene_enet_desc_ring *ring)
{
	xgene_enet_ring_set_type(ring->state, ring->is_bufpool);

	if (ring->owner == RING_OWNER_ETH0 || ring->owner == RING_OWNER_ETH1)
		xgene_enet_ring_set_recombbuf(ring->state);

	/* FIXME: clean: just pass ring as parameter */
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
	u32 addr;

	ring->slots = ring->is_bufpool ? size / 16 : size / 32;

	if (ring->is_bufpool || ring->owner != RING_OWNER_CPU)
		goto out;

	for (i = 0; i < ring->slots; i++) {
		u64 *desc = (u64 *)&ring->desc[i];
		desc[EMPTY_SLOT_INDEX] = EMPTY_SLOT;
	}

	/* program interrupt mailbox 0 */
	data = (ring->irq_mbox_dma >> 10);

	addr = CSR_VMID0_INTR_MBOX + (4 * (ring->irq - FIRST_DEQ_IRQ));
	xgene_enet_ring_wr32(ring, addr, data);
	xgene_enet_ring_rd32(ring, addr, &data);
	//xgene_enet_ring_wr32(ring, CSR_VMID0_INTR_MBOX, data);
	//xgene_enet_ring_rd32(ring, CSR_VMID0_INTR_MBOX, &data);

out:
	xgene_enet_clr_ring_state(ring);
	xgene_enet_set_ring_state(ring);
	if (ring->owner != RING_OWNER_CPU)
		xgene_enet_set_ring_id(ring);

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
	{0, 0, 0, 5, 0, 0, 0, 1},
	{0, 0, 8, 12, 0, 0, 0, 1},
	{0, 0, 16, 20, 0, 0, 0, 1},
	{0, 0, 24, 28, 0, 0, 0, 1},
	{1, 0, 0, 5, 0, 0, 0, 1},
	{1, 0, 8, 12, 0, 0, 0, 1},
	{1, 0, 16, 20, 0, 0, 0, 1},
	{1, 0, 24, 28, 0, 0, 0, 1},
	{2, 0, 0, 5, 0, 0, 0, 1},
	{2, 0, 8, 12, 0, 0, 0, 1},
	{2, 0, 16, 20, 0, 0, 0, 1},
	{2, 0, 24, 28, 0, 0, 0, 1},
	{3, 0, 0, 5, 0, 0, 0, 1},
	{3, 0, 8, 12, 0, 0, 0, 1},
	{3, 0, 16, 20, 0, 0, 0, 1},
	{3, 0, 24, 28, 0, 0, 0, 1},
	{0, 0, 0, 5, 0, 0, 0, 0},
	{0, 0, 8, 12, 0, 0, 0, 0},
	{0, 0, 16, 20, 0, 0, 0, 0},
	{0, 0, 24, 28, 0, 0, 0, 0},
	{1, 0, 0, 5, 0, 0, 0, 0},
	{1, 0, 8, 12, 0, 0, 0, 0},
	{1, 0, 16, 20, 0, 0, 0, 0},
	{1, 0, 24, 28, 0, 0, 0, 0},
	{2, 0, 0, 5, 0, 0, 0, 0},
	{2, 0, 8, 12, 0, 0, 0, 0},
	{2, 0, 16, 20, 0, 0, 0, 0},
	{2, 0, 24, 28, 0, 0, 0, 0},
	{3, 0, 0, 5, 0, 0, 0, 0},
	{3, 0, 8, 12, 0, 0, 0, 0},
	{3, 0, 16, 20, 0, 0, 0, 0},
	{3, 0, 24, 28, 0, 0, 0, 0}
};

static const struct pbn_errata_table wq_pbn_errata[] = {
	{0, 0, 0, 4, 8, 8, 5, 0},
	{0, 0, 16, 20, 24, 24, 5, 0},
	{1, 0, 0, 4, 8, 8, 5, 0},
	{1, 0, 16, 20, 24, 24, 5, 0},
	{0, 0, 0, 4, 8, 8, 5, 1},
	{0, 0, 16, 20, 24, 24, 5, 1},
	{1, 0, 0, 4, 8, 8, 5, 1},
	{1, 0, 16, 20, 24, 24, 5, 1}
};

static void xgene_enet_clear_pb(struct xgene_enet_desc_ring *ring)
{
	u32 nummsg = 0, data = 0, count = 0, val = 0, val1 = 0;
	u32 reg_offset = 0, start_bit = 0, end_bit = 0;
	u32 reg_offset1 = 0, start_bit1 = 0, end_bit1 = 0;
	u32 shift_width = 0, qmlite_hold_en = 0, buf_num = ring->buf_num - 0x20;
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
		qmlite_hold_en = fp_pbn_errata[buf_num].qmlite_hold_en;
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
		qmlite_hold_en = wq_pbn_errata[buf_num].qmlite_hold_en;
	}

	if (qmlite_hold_en == 1) {
		/* Read QML hold enable signal and clear it */
		pdata->enet_rd_wr_ops.rd_ring_if(pdata,
				ENET_CFGSSQMIQMHOLD_ADDR, &data);
		data &= ~QMLITE_HOLD_EN;
		pdata->enet_rd_wr_ops.wr_ring_if(pdata,
				ENET_CFGSSQMIQMHOLD_ADDR, data);
	}

	/* Read the no of messages in prefetch buffer */
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

	//FIXME: think of doing this in a better way
#if 0
	ring->cmd_base = pdata->ring_cmd_addr +
	       		 ((ring->num % pdata->total_rings) << 13);
#else
	ring->cmd_base = pdata->ring_cmd_addr +
	       		 ((ring->num - pdata->ring_start) << 13);
#endif
}

static void wr_cmd(struct xgene_enet_desc_ring *ring, int count)
{
	u32 data = 0;

	if (ring->irq > 0)
		data = ((ring->irq - FIRST_DEQ_IRQ) << 24) | INTR_CLEAR;
	data |= count & GENMASK(16, 0);

	iowrite32(data, ring->cmd);
}

static inline u32 ring_len(struct xgene_enet_desc_ring *ring)
{
	void *cmd_base = ring->cmd_base;
	return (ioread32(&(((u32 *)cmd_base)[1])) & 0x1ffff);
}

struct xgene_ring_ops xgene_sc_ring_ops = {
	.type = XGENE_SC_RING,
	.num_ring_cfg = 6,
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

EXPORT_SYMBOL(xgene_qmtm_set_coleascing);
