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

#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/io.h>
#include "pse.h"

#define PROC_DIR	"pse"
#define PROC_REG	"reg"
#define PROC_REG_INTR	"reg_intr"
#define PROC_MIB	"mib"
#define PROC_MIB_MAC0_QUEUE	"mib_mac0_queue"
#define PROC_MIB_MAC1_QUEUE	"mib_mac1_queue"
#define PROC_MIB_CPU_QUEUE	"mib_cpu_queue"
#define PROC_MIB_PPE_QUEUE	"mib_ppe_queue"
#define PROC_MIB_CFP_QUEUE	"mib_cfp_queue"
#define PROC_MIB_MAC0_QUEUE_INTERVAL	"mib_mac0_queue_interval"
#define PROC_MIB_MAC1_QUEUE_INTERVAL	"mib_mac1_queue_interval"
#define PROC_MIB_CPU_QUEUE_INTERVAL	"mib_cpu_queue_interval"
#define PROC_MIB_PPE_QUEUE_INTERVAL	"mib_ppe_queue_interval"
#define PROC_MIB_CFP_QUEUE_INTERVAL	"mib_cfp_queue_interval"
#define PROC_PRI	"pri"
#define PROC_FS_RING	"fs_ring"
#define PROC_TS_RING	"ts_ring"
#define PROC_FS_DESC	"fs_desc"
#define PROC_TS_DESC	"ts_desc"
#define PROC_MAC_TABLE  "mac_table"
#define PROC_FLOW_CONTROL	"flow_control"
#define PROC_SHAPE	"shape"
#define PROC_POLICE	"police"
#define PROC_VLAN	"vlan"
#define PROC_TC		"tc"
#define PROC_MAC_HASH_TABLE "mac_hash_table"
#define PROC_REALTEK_PHY "realtek_phy_eee"
#define PROC_LRO_RING	"lro_ring"
#define PROC_LRO_DESC	"lro_desc"
#define PROC_LRO_HEADER_DESC	"lro_header_desc"
#define PROC_LRO_PAYLOAD_DESC	"lro_payload_desc"
#define PROC_PRSTAT	"prstat"
#define PROC_SLOTSTAT	"slotstat"
#define PROC_INTERNAL_DEBUG_REG	"reg_dbg"
#define PROC_PSE_STATUS "pse_status"
#define PROC_PSE_EEE "eee"

struct pse_proc_entry {
	char *name;             /* entry name */
	mode_t mode;            /* mode */
	const struct file_operations *fops;
};

static struct proc_dir_entry *pse_proc_dir;

static int pse_reg(struct seq_file *m, void *p)
{
	u32 val;

	seq_printf(m, "######################## Register Set 0 ########################\n");
	seq_printf(m, "\n");
	seq_printf(m, "PHY_CTRL           0x%.8x \t", rd32(PHY_CTRL));
	seq_printf(m, "PHY_AUTO_ADDR      0x%.8x\n", rd32(PHY_AUTO_ADDR));
	seq_printf(m, "MAC_GLOB_CFG       0x%.8x\n", rd32(MAC_GLOB_CFG));
	seq_printf(m, "MAC0_CFG           0x%.8x \tMAC1_CFG           0x%.8x\n", rd32(MAC0_CFG), rd32(MAC1_CFG));
	seq_printf(m, "MAC2_CFG           0x%.8x\n", rd32(MAC2_CFG));
	seq_printf(m, "CPU_CFG            0x%.8x\n", rd32(CPU_CFG));
	seq_printf(m, "PPE_PORT_CFG       0x%.8x \tCFP_CFG            0x%.8x\n", rd32(PPE_PORT_CFG), rd32(CFP_CFG));
	seq_printf(m, "\n");
	seq_printf(m, "POLICE_CFG         0x%.8x\n", rd32(POLICE_CFG));
	seq_printf(m, "TC_CTRL            0x%.8x\n", rd32(TC_CTRL));
	seq_printf(m, "PORT_SHAPE_CFG     0x%.8x\n", rd32(PORT_SHAPE_CFG));
	seq_printf(m, "MAC_CHECK_CFG      0x%.8x\n", rd32(MAC_CHECK_CFG));
	seq_printf(m, "VLAN_CFG           0x%.8x\n", rd32(VLAN_CFG));

	seq_printf(m, "EEE_CFG            0x%.8x \tEEE_CTRL           0x%.8x\n", rd32(EEE_CFG), rd32(EEE_CTRL));
	seq_printf(m, "\n");
	seq_printf(m, "SRAM_TEST          0x%.8x\n", rd32(SRAM_TEST));
	seq_printf(m, "\n");
	seq_printf(m, "MEM_QUEUE_STATUS0  0x%.8x \tMEM_QUEUE_STATUS1  0x%.8x\n", rd32(MEM_QUEUE_STATUS0), rd32(MEM_QUEUE_STATUS1));
	seq_printf(m, "POLICE_RAND_FACTOR 0x%.8x \tPOLICE_OQUE_TH     0x%.8x\n", rd32(POLICE_RAND_FACTOR), rd32(POLICE_OQUE_TH));
	seq_printf(m, "PRIO_BUCKET_SIZE   0x%.8x\n", rd32(PRIO_BUCKET_SIZE));
	seq_printf(m, "CLK_SKEW_CTRL      0x%.8x\n", rd32(CLK_SKEW_CTRL));
	seq_printf(m, "MAC_GLOB_EXT       0x%.8x\n", rd32(MAC_GLOB_EXT));
	seq_printf(m, "TEST_MODE0         0x%.8x \tTEST_MODE1         0x%.8x\n", rd32(TEST_MODE0), rd32(TEST_MODE1));
	seq_printf(m, "\n");
	seq_printf(m, "DMA_RING_CTRL      0x%.8x \tDMA_RING_CFG       0x%.8x\n", rd32(DMA_RING_CTRL), rd32(DMA_RING_CFG));
	seq_printf(m, "DELAY_INTR_CFG     0x%.8x\n", rd32(DELAY_INTR_CFG));
	seq_printf(m, "TS_DMA_CTRL        0x%.8x\n", rd32(TS_DMA_CTRL));
	seq_printf(m, "FS_RING_STA        0x%.8x\n", rd32(FS_RING_STA));
	seq_printf(m, "FS_DMA_CTRL        0x%.8x\n", rd32(FS_DMA_CTRL));
	seq_printf(m, "FS_DMA_TIMEOUT     0x%.8x\n", rd32(FS_DMA_TIMEOUT));
	seq_printf(m, "\n");

	seq_printf(m, "FS_DMA_NODESC_DROP_CNT   0x%.8x\n", rd32(FS_DMA_NODESC_DROP_CNT));
	seq_printf(m, "LRO_DMA_NODHDR_DROP_CNT  0x%.8x\n", rd32(LRO_DMA_NODHDR_DROP_CNT));
	seq_printf(m, "LRO_DMA_NODPAY_DROP_CNT  0x%.8x\n", rd32(LRO_DMA_NODPAY_DROP_CNT));
	seq_printf(m, "\n");

	seq_printf(m, "LRO_USED_HDR_CNT  0x%.8x\n", rd32(LRO_USED_HDR_CNT));
	seq_printf(m, "LRO_USED_PAY_CNT  0x%.8x\n", rd32(LRO_USED_PAY_CNT));
	seq_printf(m, "LRO_BACK_HDR_CNT  0x%.8x\n", rd32(LRO_BACK_HDR_CNT));
	seq_printf(m, "LRO_BACK_PAY_CNT  0x%.8x\n", rd32(LRO_BACK_PAY_CNT));
	seq_printf(m, "LRO_POOL_HDR_PAY_CNT  0x%.8x\n", frd32(LRO_POOL_HDR_PAY_CNT));
	seq_printf(m, "\n");

	seq_printf(m, "LRO_CFG            0x%.8x\n", rd32(LRO_CFG));
	seq_printf(m, "LRO_PAGE_SEG_SIZE  0x%.8x\n", rd32(LRO_PAGE_SEG_SIZE));
	seq_printf(m, "LRO_DMA_CTRL       0x%.8x\n", rd32(LRO_DMA_CTRL));
	seq_printf(m, "LRO_BUF_DMA_CTRL   0x%.8x\n", rd32(LRO_BUF_DMA_CTRL));

	val = (0x1 << 15); /* read header */
	wr32(val, LRO_BUF_DESC_ACCESS);
	while (val & (0x1 << 15))
		val = rd32(LRO_BUF_DESC_ACCESS);
	seq_printf(m, "LRO_BUF_DESC_BASE(H)   0x%.8x \tLRO_BUF_DESC_PTR(H)    0x%.8x\n", rd32(LRO_BUF_DESC_BASE), rd32(LRO_BUF_DESC_PTR));

	val = ((0x1 << 15) | 0x1); /* read header */
	wr32(val, LRO_BUF_DESC_ACCESS);
	while (val & (0x1 << 15))
		val = rd32(LRO_BUF_DESC_ACCESS);
	seq_printf(m, "LRO_BUF_DESC_BASE(P)   0x%.8x \tLRO_BUF_DESC_PTR(P)    0x%.8x\n", rd32(LRO_BUF_DESC_BASE), rd32(LRO_BUF_DESC_PTR));

	seq_printf(m, "LRO_POLL_CFG       0x%.8x\n", rd32(LRO_POLL_CFG));
	seq_printf(m, "LRO_POLL_BASE      0x%.8x\n", rd32(LRO_POLL_BASE));
	seq_printf(m, "LRO_POLL_INDEX     0x%.8x\n", rd32(LRO_POLL_INDEX));
	seq_printf(m, "LRO_POLL_REF_CNT   0x%.8x\n", rd32(LRO_POLL_REF_CNT));
	seq_printf(m, "LSO_CFG            0x%.8x\n", rd32(LSO_CFG));
	seq_printf(m, "\n");

	seq_printf(m, "TS_DMA_STA         0x%.8x \tFS_DMA_STA         0x%.8x\n", rd32(TS_DMA_STA), rd32(FS_DMA_STA));
	seq_printf(m, "FUNC_STA           0x%.8x\n", rd32(FUNC_STA));
	seq_printf(m, "VERSION_NUM        0x%.8x\n", rd32(VERSION_NUM));

	return 0;
}

static int pse_reg_intr(struct seq_file *m, void *p)
{
	seq_printf(m, "######################## Register (Interrupt) ########################\n");
	seq_printf(m, "\n");
	seq_printf(m, "STATUS_INTR              0x%.8x\n", frd32(STATUS_INTR));
	seq_printf(m, "STATUS_INTR_MASK         0x%.8x\n", frd32(STATUS_INTR_MASK));
	seq_printf(m, "FS_STATUS_INTR           0x%.8x\n", frd32(FS_STATUS_INTR));
	seq_printf(m, "FS_STATUS_INTR_MASK      0x%.8x\n", frd32(FS_STATUS_INTR_MASK));

	seq_printf(m, "TS_STATUS_INTR           0x%.8x\n", frd32(TS_STATUS_INTR));
	seq_printf(m, "TS_STATUS_INTR_MASK      0x%.8x\n", frd32(TS_STATUS_INTR_MASK));

	seq_printf(m, "LRO_STATUS_INTR          0x%.8x\n", frd32(LRO_STATUS_INTR));
	seq_printf(m, "LRO_STATUS_INTR_MASK     0x%.8x\n", frd32(LRO_STATUS_INTR_MASK));

	seq_printf(m, "LRO_BUF_STATUS_INTR      0x%.8x\n", frd32(LRO_BUF_STATUS_INTR));
	seq_printf(m, "LRO_BUF_STATUS_INTR_MASK 0x%.8x\n", frd32(LRO_BUF_STATUS_INTR_MASK));

	seq_printf(m, "\n");

	return 0;
}

static int pse_fs_ring(struct seq_file *m, void *p)
{
	u32 i, val;
	struct pse_resource *res = pse_res;
	struct pse_ring *ring;

	seq_puts(m, "######################## FS Ring  ########################\n");

	val = rd32(DMA_RING_CTRL);

	seq_puts(m, "Multiple Ring: ");

	if (val & 0x1)
		seq_puts(m, "Enable\n");
	else
		seq_puts(m, "Disable\n");

	for (i = 0; i < 16; i++) {
		val = (0x1 << 15) | i;
		wr32(val, FS_DESC_ACCESS);
		while (val & (0x1 << 15))
			val = rd32(FS_DESC_ACCESS);

		seq_printf(m, "Ring %d\n", i);
		seq_printf(m, "\tintr_group %d, base 0x%.8x, ptr 0x%.8x, idx %d\n",
			(val >> 4) & 0x3,
			rd32(FS_DESC_BASE), rd32(FS_DESC_PTR),
			(rd32(FS_DESC_PTR)-rd32(FS_DESC_BASE))>>5);

	}

	seq_puts(m, "\n");

	seq_puts(m, "FS Ring Stats\n");
	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		ring = res->rx_ring[i];
		if (!ring)
			continue;

		seq_printf(m, "\tRing %d, Ring Sz %d, next_to_use=%d, next_to_clean=%d\n",
			i, ring->ringsz, ring->next_to_use, ring->next_to_clean);
	}

	return 0;
}

static int pse_ts_ring(struct seq_file *m, void *p)
{
	u32 i, val;
	struct pse_resource *res = pse_res;
	struct pse_ring *ring;

	seq_puts(m, "######################## TS Ring  ########################\n");

	val = rd32(DMA_RING_CTRL);

	seq_puts(m, "Multiple Ring: ");
	if (val & (0x1 << 16))
		seq_puts(m, "Enable\n");
	else
		seq_puts(m, "Disable\n");


	for (i = 0; i < 16; i++) {
		val = (0x1 << 15) | i;
		wr32(val, TS_DESC_ACCESS);
		while (val & (0x1 << 15))
			val = rd32(TS_DESC_ACCESS);

		seq_printf(m, "Ring %d\n", i);
		seq_printf(m, "\tintr_group %d, base 0x%.8x, ptr 0x%.8x\n",
			(val >> 4) & 0x3, rd32(TS_DESC_BASE), rd32(TS_DESC_PTR));

	}

	seq_puts(m, "\n");

	seq_puts(m, "TS Ring Stats\n");
	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		ring = res->tx_ring[i];
		if (!ring)
			continue;
		seq_printf(m, "\tRing %d, Tx count %lu, Ring Sz %d\n", i, ring->count, ring->ringsz);
	}

	return 0;
}

static int pse_fs_desc(struct seq_file *m, void *p)
{
	struct pse_resource *res = pse_res;
	struct pse_ring *ring;
	struct pse_buffer_info *bi;
	u32 *ptr;

	int i, j, ringsz;

	seq_puts(m, "######################## FS Descriptor ########################\n");

	for (i = 0; i < PSE_MAX_FS_RING_NUM; i++) {
		ring = res->rx_ring[i];

		if (!ring)
			continue;

		seq_printf(m, "FS Descriptor Ring %.3d\n", i);

		ringsz = ring->ringsz;


		for (j = 0; j < ringsz; j++) {
			bi = (ring->bi + j);
			ptr = (u32 *) bi->desc;
			seq_printf(m,
				"\t<%.3d> 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
				j, *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4));
		}
	}

	return 0;
}

static int pse_ts_desc(struct seq_file *m, void *p)
{
	struct pse_resource *res = pse_res;
	struct pse_ring *ring;
	struct pse_buffer_info *bi;
	u32 *ptr;

	int i, j, ringsz;

	seq_puts(m, "######################## TS Descriptor ########################\n");

	for (i = 0; i < PSE_MAX_TS_RING_NUM; i++) {
		ring = res->tx_ring[i];

		if (!ring)
			continue;


		seq_printf(m, "TS Descriptor Ring %.3d\n", i);

		ringsz = ring->ringsz;


		for (j = 0; j < ringsz; j++) {
			bi = (ring->bi + j);
			ptr = (u32 *) bi->desc;
			seq_printf(m,
				"\t<%.3d> 0x%.8x 0x%.8x 0x%.8x 0x%.8x 0x%.8x\n",
				j, *ptr, *(ptr + 1), *(ptr + 2), *(ptr + 3), *(ptr + 4));
		}
	}

	return 0;
}

#define pse_pri_port(portname, port)	\
static void pse_pri_##portname(struct seq_file *m)	\
{							\
	u32 val;					\
							\
	seq_printf(m, "%s Port:\n", #portname);		\
	val = (0x1 << 15) | (port);			\
	wr32(val, PORT_PRI_CMD);			\
							\
	while (val & (0x1 << 15))			\
		val = rd32(PORT_PRI_CMD);		\
							\
	val = rd32(PORT_PRI_CTRL);			\
	seq_printf(m, "regen:%d port:%d dmac:%d tcp:%d udp:%d dscp:%d vlan:%d ether:%d sch_mode:%d sch_minbw:%d\n",	\
		val >> 31, (val >> 24) & 0xf,					\
		(val >> 23) & 0x1, (val >> 22) & 0x1, (val >> 21) & 0x1,	\
		(val >> 20) & 0x1, (val >> 19) & 0x1, (val >> 18) & 0x1,	\
		(val >> 15) & 0x07, (val >> 11) & 0x0f);			\
										\
	val = rd32(PORT_PRI_WEIGHT);						\
	seq_printf(m, "Q0_W:%d, Q1_W:%d, Q2_W:%d, Q3_W:%d, Q4_W:%d, Q5_W:%d, Q6_W:%d, Q7_W:%d\n",	\
		       val >> 28, (val >> 24) & 0x7, (val >> 20) & 0x7, (val >> 16) & 0x7,		\
		       (val >> 12) & 0x7, (val >> 8) & 0x7, (val >> 4) & 0x7,  (val >> 0) & 0x7);	\
										\
	val = rd32(PORT_PRI_RING);						\
	seq_printf(m, "Q0=>R%d, Q1=>R%d, Q2=>R%d, Q3=>R%d, Q4=>R%d, Q5=>R%d, Q6=>R%d, Q7=>R%d\n",	\
		val >> 28, (val >> 24) & 0xf, (val >> 20) & 0xf, (val >> 16) & 0xf,			\
		(val >> 12) & 0xf, (val >> 8) & 0xf, (val >> 4) & 0xf,	(val >> 0) & 0xf);		\
	seq_puts(m, "\n");							\
}

pse_pri_port(mac0, 0);
pse_pri_port(mac1, 1);
pse_pri_port(cpu, 2);
pse_pri_port(ppe, 3);
pse_pri_port(cfp, 5);

static int pse_pri(struct seq_file *m, void *p)
{

	seq_puts(m, "######################## Priority  ########################\n");

	pse_pri_mac0(m);
	pse_pri_mac1(m);
	pse_pri_cpu(m);
	pse_pri_ppe(m);
	pse_pri_cfp(m);

	return 0;
}

#ifdef CONFIG_ARCH_OPV5XC_ES1
#define PSE_PORT_MAX	(4)
#else
#define PSE_PORT_MAX	(5)
#endif
#define PSE_QUEUE_MAX    8
#define PSE_GEN_MIB_CNT_MAX	(14)
u8 *pse_mib_cnt_general[] = {
	"RXOKPKT       ", /* 0 */
	"RXOKBYTE      ", /* 1 */
	"RXRUNT        ", /* 2 */
	"RXOVERSIZE    ", /* 3 */
	"RXNOBUF       ", /* 4 */
	"RXCRC         ", /* 5 */
	"RXARL         ", /* 6 */
	"RXVLAN_INGRESS", /* 7 */
	"???           ", /* 8 */
	"RXRATE        ", /* 9 */
	"RXPAUSE       ", /* 10 */
	"TXOKPKT       ", /* 11 */
	"TXOKBYTE      ", /* 12 */
	"TXPAUSE       ", /* 13 */
};

#define PSE_QUEUE_MIB_CNT_MAX	(8)
u8 *pse_mib_cnt_queue[] = {
	"running packet count of emitted packets",	/* 0 */
	"running byte count of emitted packets",	/* 1 */
	"running packet count of dropped packets",	/* 2 */
	"interval packet count of emitted packets",	/* 3 */
	"interval byte count of emitted packets",	/* 4 */
	"interval packet count of dropped packets",	/* 5 */
	"interval peak queue occupancy in packet",	/* 6 */
	"interval peak queue occupancy in page (128bytes)",	/* 7 */
};

static int pse_mib(struct seq_file *m, void *p)
{
	int i, j;
	u32 val;

	seq_puts(m, "####################### MIB Counter #######################\n");
	seq_puts(m, "\n");

	/* To read all with clear */
	val = ((0x1 << 15)
		| (0x1 << 13)
		| (8 << 9));

	fwr32(val, MIB_CNT_CMD);

	while (val & (0x1 << 15))
		val = frd32(MIB_CNT_CMD);

	seq_puts(m, "\t\tPort 0\t\tPort 1\t\tCPU\n");

	for (j = 0; j < PSE_GEN_MIB_CNT_MAX; j++) {
		val = frd32(MIB_CNT_CMD);
		val &= ~(0x1F << 4);
		val |= (j << 4);
		fwr32(val, MIB_CNT_CMD);
		seq_printf(m, "%s\t", pse_mib_cnt_general[j]);
		for (i = 0; i < PSE_PORT_MAX; i++) {
			if ((3 == i)) /* no PPE and MAC2  */
				break;
			val = frd32(MIB_CNT_CMD);
			val &= ~(0xF);
			val |= i; /* port */
			fwr32(val, MIB_CNT_CMD);
			seq_printf(m, "0x%.8x \t", frd32(MIB_CNT_3100));
		}
		seq_puts(m, "\n");

	}

	seq_puts(m, "\n");

	return 0;
}

#define pse_mib_queue(portname, port)					\
static int pse_mib_##portname##_queue(struct seq_file *m, void *p)      \
{									\
	int j, k;							\
	u32 val;							\
									\
	seq_printf(m, "####################### MIB %s Queue Counter #######################\n", #portname);	\
	seq_puts(m, "\n");						\
									\
	for (j = 0; j < PSE_QUEUE_MIB_CNT_MAX; j++) {			\
		seq_printf(m, "%d : %s\n", j, pse_mib_cnt_queue[j]);	\
	}								\
	seq_puts(m, "\n");						\
	seq_puts(m, "\t");						\
	for (k = 0; k < PSE_QUEUE_MAX; k++) {				\
		seq_printf(m, "Queue%d     ", k);			\
	}								\
	seq_puts(m, "\n");						\
	for (j = 0; j < PSE_QUEUE_MIB_CNT_MAX; j++) {			\
		seq_printf(m, "%d\t", j);				\
									\
		for (k = 0; k < PSE_QUEUE_MAX; k++) {			\
			val =	(1 << 15) |				\
				(3 << 13) |				\
				(k << 9) |				\
				(j << 4) |				\
				(port);					\
			fwr32(val, MIB_CNT_CMD);			\
									\
			while (val & (1 << 15))				\
				val = frd32(MIB_CNT_CMD);		\
			seq_printf(m, "0x%.8x ", frd32(MIB_CNT_3100));	\
		}							\
		seq_puts(m, "\n");					\
	}								\
	seq_puts(m, "\n");						\
	return 0;							\
}

pse_mib_queue(mac0, 0);
pse_mib_queue(mac1, 1);
pse_mib_queue(cpu, 2);
pse_mib_queue(ppe, 3);
pse_mib_queue(cfp, 5);

#define pse_mib_queue_interval(portname, port)					\
static int pse_mib_##portname##_queue_interval(struct seq_file *m, void *p)      \
{									\
	int j, k;							\
	u32 val;							\
									\
	seq_printf(m, "####################### MIB %s Queue Interval Counter #######################\n", #portname);     \
	seq_puts(m, "\n");						\
									\
	for (j = 0; j < PSE_QUEUE_MIB_CNT_MAX; j++) {			\
		seq_printf(m, "%d : %s\n", j, pse_mib_cnt_queue[j]);	\
	}								\
	seq_puts(m, "\n");						\
	seq_puts(m, "\t");						\
	for (k = 0; k < PSE_QUEUE_MAX; k++) {				\
		seq_printf(m, "Queue%d     ", k);			\
	}								\
	seq_puts(m, "\n");						\
	for (j = 3; j < PSE_QUEUE_MIB_CNT_MAX; j++) {			\
		seq_printf(m, "%d\t", j);				\
									\
		for (k = 0; k < PSE_QUEUE_MAX; k++) {			\
			val = (k << 9) |				\
				(j << 4) |				\
				(port);					\
			fwr32(val, MIB_CNT_CMD);			\
									\
			while (val & (1 << 15))				\
				val = frd32(MIB_CNT_CMD);		\
			seq_printf(m, "0x%.8x ", frd32(MIB_CNT_3100));	\
		}							\
		seq_puts(m, "\n");					\
	}								\
	seq_puts(m, "\n");						\
	return 0;							\
}

pse_mib_queue_interval(mac0, 0);
pse_mib_queue_interval(mac1, 1);
pse_mib_queue_interval(cpu, 2);
pse_mib_queue_interval(ppe, 3);
pse_mib_queue_interval(cfp, 5);

static int pse_mac_table(struct seq_file *m, void *p)
{
	struct pse_mac mac;
	int i, j;

	for (i = 0; i < 3; i++) {
		mac.port = i;
		if (i == 2) {
			/* CPU port, support 8 MY_MACS */
			seq_puts(m, "CPU Port\n");
			for (j = 0; j < 8; j++) {
				mac.index = j;
				pse_mac_read(&mac);
				seq_printf(m,
					"index = %d mac_addr = %.2x-%.2x-%.2x-%.2x-%.2x-%.2x priority = %d\n",
					j, mac.mac[0], mac.mac[1], mac.mac[2],
					mac.mac[3], mac.mac[4], mac.mac[5], mac.priority);
			}
		} else {
			/* MAC port, support 2 MY_MACS */
			seq_printf(m, "MAC%d Port\n", i);
			for (j = 0; j < 2; j++) {
				mac.index = j;
				pse_mac_read(&mac);
				seq_printf(m,
					"index = %d mac_addr = %.2x-%.2x-%.2x-%.2x-%.2x-%.2x priority = %d\n",
					j, mac.mac[0], mac.mac[1], mac.mac[2],
					mac.mac[3], mac.mac[4], mac.mac[5], mac.priority);
			}
		}
	}
	return 0;
}

static int pse_flow_control(struct seq_file *m, void *p)
{
	u16 fc_set;
	u16 fc_release;

	seq_puts(m, "####################### Flow Control #######################\n");
	seq_puts(m, "\t\t\tFC_SET\t\tFC_RELEASE\n");
	fc_th_read(&fc_set, &fc_release);

	seq_printf(m, "FC_THRS\t\t\t%d\t\t%d\n", fc_set, fc_release);

	fc_th_input_read(0, &fc_set, &fc_release);
	seq_printf(m, "MAC0 FC_IN_THRS\t\t%d\t\t%d\n", fc_set, fc_release);
	fc_th_input_read(1, &fc_set, &fc_release);
	seq_printf(m, "MAC1 FC_IN_THRS\t\t%d\t\t%d\n", fc_set, fc_release);
	fc_th_input_read(2, &fc_set, &fc_release);
	seq_printf(m, "CPU FC_IN_THRS\t\t%d\t\t%d\n", fc_set, fc_release);

	fc_th_drop_read(&fc_set, &fc_release);
	seq_printf(m, "FC_DROP_SET\t\t%d\t\t%d\n", fc_set, fc_release);
	fc_th_all_drop_read(&fc_set, &fc_release);
	seq_printf(m, "FC_ALL_DROP_SET\t\t%d\t\t%d\n", fc_set, fc_release);

	return 0;
}

static int pse_shape(struct seq_file *m, void *p)
{
	u8 base;
	u8 bw;
	int i;
	int base_rate_k[3] = {64, 1*1000, 10*1000};
	u8 size;

	seq_puts(m, "####################### SHAPE  #######################\n");

	shape_two_bucket_size_read(&size);
	seq_printf(m, "%s bucket size\n", (size == 0) ? "one" : "two");

	seq_puts(m, "\nSHAPE RATE\n");
	seq_puts(m, "\t\t\tBase Rate\tN\tbucket size\t\tTX Bandwidth\n");
	shape_port_read(0, &base, &bw, &size);
	seq_printf(m, "MAC0 Port Shape\t\t%d\t\t%d\t\t%d\t\t%d Kbps\n", base, bw, size, base_rate_k[base]*bw);
	shape_port_read(1, &base, &bw, &size);
	seq_printf(m, "MAC1 Port Shape\t\t%d\t\t%d\t\t%d\t\t%d Kbps\n", base, bw, size, base_rate_k[base]*bw);

	for (i = 0; i < 8; i++) {
		shape_queue_read(0, i, &base, &bw, &size);
		seq_printf(m, "MAC0 Queue%d Shape\t%d\t\t%d\t\t%d\t\t%d Kbps\n", i, base, bw, size, base_rate_k[base]*bw);
	}
	for (i = 0; i < 8; i++) {
		shape_queue_read(1, i, &base, &bw, &size);
		seq_printf(m, "MAC1 Queue%d Shape\t%d\t\t%d\t\t%d\t\t%d Kbps\n", i, base, bw, size, base_rate_k[base]*bw);
	}
	for (i = 0; i < 8; i++) {
		shape_queue_read(2, i, &base, &bw, &size);
		seq_printf(m, "CPU Queue%d Shape\t%d\t\t%d\t\t%d\t\t%d Kbps\n", i, base, bw, size, base_rate_k[base]*bw);
	}
	for (i = 0; i < 8; i++) {
		shape_queue_read(3, i, &base, &bw, &size);
		seq_printf(m, "PPE Queue%d Shape\t%d\t\t%d\t\t%d\t\t%d Kbps\n", i, base, bw, size, base_rate_k[base]*bw);
	}
	for (i = 0; i < 8; i++) {
		shape_queue_read(5, i, &base, &bw, &size);
		seq_printf(m, "CFP Queue%d Shape\t%d\t\t%d\t\t%d\t\t%d Kbps\n", i, base, bw, size, base_rate_k[base]*bw);
	}

	return 0;
}


static int pse_police(struct seq_file *m, void *p)
{
	u16 max, min, probability, weight, min_oq, inverse, queue_en;

	seq_printf(m, "####################### POLICE  #######################\n");

	seq_printf(m, "MAC0 : %s\n", police_port_en_read(0) ? "enable" : "disable");
	seq_printf(m, "MAC1 : %s\n", police_port_en_read(1) ? "enable" : "disable");
	seq_printf(m, "CPU  : %s\n", police_port_en_read(2) ? "enable" : "disable");
	seq_printf(m, "PPE  : %s\n", police_port_en_read(3) ? "enable" : "disable");
	seq_printf(m, "CFP  : %s\n", police_port_en_read(5) ? "enable" : "disable");

	seq_printf(m, "Psuedo Random Generator  : %s\n", police_psudo_rand_generator_read() ? "enable" : "disable");
	seq_printf(m, "Global Queue Min Threshold  : %d\n", police_global_min_th_read());
	seq_printf(m, "\n\n");
	seq_printf(m, "\tQUEUE_EN\tINVERSE\t\tOUT_MAXTH\tOUT_MINTH\tMAX_P\t\tQUE_W\t\tOQUE_MINTH\n");
	police_dst_port_read(0, &queue_en, &inverse, &max, &min, &probability, &weight, &min_oq);
	seq_printf(m, "MAC0 \t0x%x\t\t0x%x\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", queue_en, inverse, max, min, probability, weight, min_oq);
	police_dst_port_read(1, &queue_en, &inverse, &max, &min, &probability, &weight, &min_oq);
	seq_printf(m, "MAC1 \t0x%x\t\t0x%x\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", queue_en, inverse, max, min, probability, weight, min_oq);
	police_dst_port_read(2, &queue_en, &inverse, &max, &min, &probability, &weight, &min_oq);
	seq_printf(m, "CPU \t0x%x\t\t0x%x\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", queue_en, inverse, max, min, probability, weight, min_oq);
	police_dst_port_read(3, &queue_en, &inverse, &max, &min, &probability, &weight, &min_oq);
	seq_printf(m, "PPE \t0x%x\t\t0x%x\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", queue_en, inverse, max, min, probability, weight, min_oq);
	police_dst_port_read(5, &queue_en, &inverse, &max, &min, &probability, &weight, &min_oq);
	seq_printf(m, "CFP \t0x%x\t\t0x%x\t\t%d\t\t%d\t\t%d\t\t%d\t\t%d\n", queue_en, inverse, max, min, probability, weight, min_oq);

	return 0;
}

static int pse_vlan(struct seq_file *m, void *p)
{
	struct pse_vlan vlan;
	int i;

	seq_printf(m, "####################### VLAN  #######################\n\n");

	seq_printf(m, "UNKNOWN_VLAN_TOCPU : %s\n", !!(rd32(MAC_GLOB_CFG) & (1 << 25)) ? "enable" : "disable");
	seq_printf(m, "MAC0 INGRESS_CHECK : %s\n", !!(rd32(MAC0_CFG) & (1 << 24)) ? "enable" : "disable");
	seq_printf(m, "MAC1 INGRESS_CHECK : %s\n", !!(rd32(MAC1_CFG) & (1 << 24)) ? "enable" : "disable");
	seq_printf(m, "CPU  INGRESS_CHECK : %s\n", !!(rd32(CPU_CFG) & (1 << 24)) ? "enable" : "disable");

	seq_printf(m, "\n\n");
	seq_printf(m, "index\tValid\tWAN\tVID\tPMAP\n");

	for (i = 0; i < PSE_VLAN_MAX; i++) {
		pse_vlan_read(&vlan, i);
		seq_printf(m, "%d\t%d\t%d\t%d\t0x%x\n", i, vlan.valid, vlan.wan, vlan.vid, vlan.pmap);
	}

	return 0;
}

static int pse_tc(struct seq_file *m, void *p)
{
	u16 type;
	u8 tc;
	int i;
	u16 port_start, port_end;

	seq_puts(m, "####################### Traffic Class  #######################\n\n");

	seq_puts(m, "ether type\n");

	for (i = 0; i < 4; i++) {
		tc_ethertype_read(i, &type, &tc);
		seq_printf(m, "index %d : type = 0x%.4x tc = %d\n", i, type, tc);
	}

	seq_puts(m, "\ndscp\n");
	for (i = 0; i < 64; i++) {
		tc_dscp_read(i, &tc);
		seq_printf(m, "dscp %.2d : tc = %d\t", i, tc);
		if ((i % 4) == 3)
			seq_puts(m, "\n");
	}
	seq_puts(m, "\ntcp\n");
	for (i = 0; i < 4; i++) {
		tc_tcp_port_read(i, &port_start, &port_end, &tc);
		seq_printf(m, "index %d : port_start = %d port_end = %d tc = %d\n", i, port_start, port_end, tc);
	}

	seq_puts(m, "\nudp\n");
	for (i = 0; i < 4; i++) {
		tc_udp_port_read(i, &port_start, &port_end, &tc);
		seq_printf(m, "index %d : port_start = %d port_end = %d tc = %d\n", i, port_start, port_end, tc);
	}

	return 0;
}

static int pse_mac_hash_table(struct seq_file *m, void *p)
{
	bool hash_hit;
	int i, j, hash_count;

	for (i = 0; i < 2; i++) {
		hash_count = 0;
		for (j = 0; j < 512; j++) {
			hash_hit = pse_mac_hash_read_by_index(i, j);
			if (hash_hit) {
				seq_printf(m, "port = %d, index = %d, hash hit = %d\n", i, j, hash_hit);
				hash_count++;
			}
		}
		if (hash_count == 0)
			seq_printf(m, "port%d , hash table empty\n", i);
	}
	return 0;
}

int realtek_phy_read_mmd(struct phy_device *phydev, int device, int reg)
{
#define REALTEK_MCAR		0x0d
#define REALTEK_MAADR		0x0e
#define MMD_ADDRESS_MODE	(00 << 14)
#define MMD_DATA_MODE		(01 << 14)

	phy_write(phydev, REALTEK_MCAR, MMD_ADDRESS_MODE | device);
	phy_write(phydev, REALTEK_MAADR, reg);
	phy_write(phydev, REALTEK_MCAR, MMD_DATA_MODE | device);
	return phy_read(phydev, REALTEK_MAADR);
}

static int pse_realtek_phy(struct seq_file *m, void *p)
{
	struct net_device *dev;
	struct phy_device *phydev;

	dev = pse_res->ndev[1];
	phydev = dev->phydev;
	if (phydev) {
		seq_printf(m, "PC1R(device 3, addr 0x01) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 3, 0x00));
		seq_printf(m, "PS1R(device 3, addr 0x01) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 3, 0x01));
		seq_printf(m, "EEECR(device 3, addr 0x14) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 3, 0x14));
		seq_printf(m, "EEEWER(device 3, addr 0x16) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 3, 0x16));
		seq_printf(m, "EEEAR(device 7, addr 0x3c) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 7, 0x3c));
		seq_printf(m, "EEELPAR(device 7, addr 0x3d) = 0x%.4x\n",
			       realtek_phy_read_mmd(phydev, 7, 0x3d));
	}
	return 0;
}

static int pse_reg_dbg(struct seq_file *m, void *p)
{
	int i;

	for (i = 0x1D0; i <= 0x1FC; i += 4)
		seq_printf(m, "offset 0x%.4x:   0x%.8x\n", i, rd32(i));

	for (i = 0x300; i <= 0x31C; i += 4)
		seq_printf(m, "offset 0x%.4x:   0x%.8x\n", i, rd32(i));

	for (i = 0x450; i <= 0x4BC; i += 4)
		seq_printf(m, "offset 0x%.4x:   0x%.8x\n", i, frd32(i));

	return 0;
}

static int pse_status(struct seq_file *m, void *p)
{
	int use_page_cnt = rd32(MEM_QUEUE_STATUS0) & 0x7FF;

	seq_puts(m, "PSE STATUS : ");
	if (use_page_cnt == 0)
		seq_puts(m, "idle\n");
	else
		seq_puts(m, "busy\n");

	seq_printf(m, "PSE register offset 0x0AC[10:0] = 0x%x\n", use_page_cnt);
	return 0;
}

static int pse_eee(struct seq_file *m, void *p)
{
	int reg;

	reg = rd32(EEE_CFG);
	seq_printf(m, "EEE_RX1_ENABLE: %d\n", reg & 0x08 ? 1 : 0);
	seq_printf(m, "EEE_TX1_ENABLE: %d\n", reg & 0x04 ? 1 : 0);
	seq_printf(m, "EEE_RX0_ENABLE: %d\n", reg & 0x02 ? 1 : 0);
	seq_printf(m, "EEE_TX0_ENABLE: %d\n", reg & 0x01 ? 1 : 0);

	reg = rd32(EEE_CTRL);
	seq_printf(m, "LPI_REQUEST_TX1: %d\n", (reg >> 4) & 0x03);
	seq_printf(m, "LPI_REQUEST_TX0: %d\n", reg & 0x03);

	seq_printf(m, "LPI_ASSERT_RX1: %s\n", reg & (1 << 7) ? "LPI mode" : "NOT LPI mode");
	seq_printf(m, "LPI_ASSERT_TX1: %s\n", reg & (1 << 6) ? "LPI mode" : "NOT LPI mode");
	seq_printf(m, "LPI_ASSERT_RX0: %s\n", reg & (1 << 3) ? "LPI mode" : "NOT LPI mode");
	seq_printf(m, "LPI_ASSERT_TX0: %s\n", reg & (1 << 2) ? "LPI mode" : "NOT LPI mode");

	return 0;
}


#define PSE_SEQ_FOPS(name) \
static int seq_pse_##name(struct inode *inode, struct file *file) { return single_open(file, pse_##name, NULL); } \
static const struct file_operations fops_pse_##name = { \
	.owner = THIS_MODULE, .open = seq_pse_##name, .read = seq_read, \
	.llseek = seq_lseek, .release = single_release \
};

PSE_SEQ_FOPS(reg);
PSE_SEQ_FOPS(reg_intr);
PSE_SEQ_FOPS(fs_ring);
PSE_SEQ_FOPS(ts_ring);
PSE_SEQ_FOPS(fs_desc);
PSE_SEQ_FOPS(ts_desc);
PSE_SEQ_FOPS(pri);
PSE_SEQ_FOPS(mib);
PSE_SEQ_FOPS(mib_mac0_queue);
PSE_SEQ_FOPS(mib_mac1_queue);
PSE_SEQ_FOPS(mib_cpu_queue);
PSE_SEQ_FOPS(mib_ppe_queue);
PSE_SEQ_FOPS(mib_cfp_queue);
PSE_SEQ_FOPS(mib_mac0_queue_interval);
PSE_SEQ_FOPS(mib_mac1_queue_interval);
PSE_SEQ_FOPS(mib_cpu_queue_interval);
PSE_SEQ_FOPS(mib_ppe_queue_interval);
PSE_SEQ_FOPS(mib_cfp_queue_interval);
PSE_SEQ_FOPS(mac_table);
PSE_SEQ_FOPS(flow_control);
PSE_SEQ_FOPS(shape);
PSE_SEQ_FOPS(police);
PSE_SEQ_FOPS(vlan);
PSE_SEQ_FOPS(tc);
PSE_SEQ_FOPS(mac_hash_table);
PSE_SEQ_FOPS(realtek_phy);
PSE_SEQ_FOPS(reg_dbg);
PSE_SEQ_FOPS(status);
PSE_SEQ_FOPS(eee);


static struct pse_proc_entry pse_proc[] = {
	{PROC_REG, S_IFREG | S_IRUGO, &fops_pse_reg},
	{PROC_REG_INTR, S_IFREG | S_IRUGO, &fops_pse_reg_intr},
	{PROC_FS_RING, S_IFREG | S_IRUGO, &fops_pse_fs_ring},
	{PROC_TS_RING, S_IFREG | S_IRUGO, &fops_pse_ts_ring},
	{PROC_FS_DESC, S_IFREG | S_IRUGO, &fops_pse_fs_desc},
	{PROC_TS_DESC, S_IFREG | S_IRUGO, &fops_pse_ts_desc},
	{PROC_PRI, S_IFREG | S_IRUGO, &fops_pse_pri},
	{PROC_MIB, S_IFREG | S_IRUGO, &fops_pse_mib},
	{PROC_MIB_MAC0_QUEUE, S_IFREG | S_IRUGO, &fops_pse_mib_mac0_queue},
	{PROC_MIB_MAC1_QUEUE, S_IFREG | S_IRUGO, &fops_pse_mib_mac1_queue},
	{PROC_MIB_CPU_QUEUE, S_IFREG | S_IRUGO, &fops_pse_mib_cpu_queue},
	{PROC_MIB_PPE_QUEUE, S_IFREG | S_IRUGO, &fops_pse_mib_ppe_queue},
	{PROC_MIB_CFP_QUEUE, S_IFREG | S_IRUGO, &fops_pse_mib_cfp_queue},
	{PROC_MIB_MAC0_QUEUE_INTERVAL, S_IFREG | S_IRUGO, &fops_pse_mib_mac0_queue_interval},
	{PROC_MIB_MAC1_QUEUE_INTERVAL, S_IFREG | S_IRUGO, &fops_pse_mib_mac1_queue_interval},
	{PROC_MIB_CPU_QUEUE_INTERVAL, S_IFREG | S_IRUGO, &fops_pse_mib_cpu_queue_interval},
	{PROC_MIB_PPE_QUEUE_INTERVAL, S_IFREG | S_IRUGO, &fops_pse_mib_ppe_queue_interval},
	{PROC_MIB_CFP_QUEUE_INTERVAL, S_IFREG | S_IRUGO, &fops_pse_mib_cfp_queue_interval},
	{PROC_MAC_TABLE, S_IFREG | S_IRUGO, &fops_pse_mac_table},
	{PROC_FLOW_CONTROL, S_IFREG | S_IRUGO, &fops_pse_flow_control},
	{PROC_SHAPE, S_IFREG | S_IRUGO, &fops_pse_shape},
	{PROC_POLICE, S_IFREG | S_IRUGO, &fops_pse_police},
	{PROC_VLAN, S_IFREG | S_IRUGO, &fops_pse_vlan},
	{PROC_TC, S_IFREG | S_IRUGO, &fops_pse_tc},
	{PROC_MAC_HASH_TABLE, S_IFREG | S_IRUGO, &fops_pse_mac_hash_table},
	{PROC_REALTEK_PHY, S_IFREG | S_IRUGO, &fops_pse_realtek_phy},
	{PROC_INTERNAL_DEBUG_REG, S_IFREG | S_IRUGO, &fops_pse_reg_dbg},
	{PROC_PSE_STATUS, S_IFREG | S_IRUGO, &fops_pse_status},
	{PROC_PSE_EEE, S_IFREG | S_IRUGO, &fops_pse_eee},
	{NULL, 0, NULL}
};

static int pse_proc_create_entries(struct proc_dir_entry *dir,
		struct pse_proc_entry *pe)
{
	struct proc_dir_entry *tmp;

	while (pe->name) {
		tmp = proc_create_data(pe->name, pe->mode, dir, pe->fops, NULL);

		if (!tmp)
			return -1;

		pe++;
	}

	return 0;
}

int pse_proc_init(void)
{
	pse_proc_dir = proc_mkdir(PROC_DIR, opv5xc_proc_dir);

	if (pse_proc_dir)
		pse_proc_create_entries(pse_proc_dir, pse_proc);

	return 0;
}

static int pse_proc_remove_entries(struct proc_dir_entry *dir,
		struct pse_proc_entry *pe)
{
	while (pe->name) {
		remove_proc_entry(pe->name, dir);
		pe++;
	}

	return 0;
}

int pse_proc_fini(void)
{
	if (pse_proc_dir) {
		pse_proc_remove_entries(pse_proc_dir, pse_proc);

		remove_proc_entry(PROC_DIR, opv5xc_proc_dir);

		pse_proc_dir = NULL;
	}
	return 0;
}
