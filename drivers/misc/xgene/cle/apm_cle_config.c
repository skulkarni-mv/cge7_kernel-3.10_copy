/*
 * AppliedMicro APM88xxxx CLE Engine Configuration Driver
 *
 * Copyright (c) 2013 Applied Micro Circuits Corporation.
 * Ravi Patel <rapatel@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * @file apm_cle_config.c
 *
 * This file implements Configuration APIs for
 * AppliedMicro APM88xxxx SoC Classifier module.
 */

#include <linux/err.h>
#include <linux/clk.h>
#include <linux/slab.h>
#include <misc/xgene/cle/apm_cle_config.h>
#include <misc/xgene/cle/apm_preclass_data.h>
#include <misc/xgene/cle/apm_cle_mgr.h>
#include <linux/proc_fs.h>

static struct ptree_kn kn[MAX_RX_QUEUES];
static struct apm_cle_dbptr dbptr[MAX_RX_QUEUES];
#define MADDR_PER_GROUP 4	/* As per allocation method - Constant */
#define PTREE_PER_GROUP 3	/* As per allocation method - Constant */
#define PTREE_GROUPS(m) \
	((m + APM_SYS_MACADDR + (MADDR_PER_GROUP - 1)) / MADDR_PER_GROUP)
#define PTREE_ALLOCS(m) \
	(PTREE_GROUPS(m) * PTREE_PER_GROUP)

enum enode_index {
	AVL = 0,	/* Decision Node for AVL Search BOTH_BYTES */
	ALN,		/* Last Node for AVL Search FIRST_BYTE */
	S07,		/* SRC Port % 8 = 0, 1, 2, 3, 4, 5, 6, 7 */
	D07,		/* DST Port % 8 = 0, 1, 2, 3, 4, 5, 6, 7 */
	D76,		/* DST Port % 8 = 7, 0, 1, 2, 3, 4, 5, 6 */
	D65,		/* DST Port % 8 = 6, 7, 0, 1, 2, 3, 4, 5 */
	D54,		/* DST Port % 8 = 5, 6, 7, 0, 1, 2, 3, 4 */
	D43,		/* DST Port % 8 = 4, 5, 6, 7, 0, 1, 2, 3 */
	D32,		/* DST Port % 8 = 3, 4, 5, 6, 7, 0, 1, 2 */
	D21,		/* DST Port % 8 = 2, 3, 4, 5, 6, 7, 0, 1 */
	D10,		/* DST Port % 8 = 1, 2, 3, 4, 5, 6, 7, 0 */
	MLN,		/* Last Node for MAC PTREE_GROUPS */
	MKN,		/* Key Node for MAC PTREE_GROUPS */
};

#undef M
#define M (PTREE_ALLOCS(0) + MLN)

/*
 * Macro for getting relative node location from snptr for mac address
 * index i and mac short position p (0 1 2)
 */
#define MAC_NODE(i, p) ((PTREE_PER_GROUP * (i / MADDR_PER_GROUP)) + p)
/*
 * Macro for getting relative branch location from snptr for mac address
 * index i and mac short position p (0 1 2)
 */
#define MAC_BRANCH(i, p) ((i * 2) % (MADDR_PER_GROUP * 2))

/*
 * Single ptree group branch which serves to allow MADDR_PER_GROUP
 * mac addresses.  For single ptree group it requires PTREE_PER_GROUP
 * 8W-Decision Patricia Nodes.  All these ptree groups are cascaded to serve
 * mulitple of MADDR_PER_GROUP mac addresses. Total ptree groups is formulated
 * by PTREE_GROUPS macro based on m mac addresses. Total 8W-Decision Patricia
 * Nodes is formulated by PTREE_ALLOCS macro based on m mac addresses
 */
static struct ptree_branch branch[] = {
	{ 0xffff, 0, NEQT, PTREE_ALLOC(1),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr00 byte [0:1] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(2),  0, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr01 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(1),   EW_BRANCH(2),  2, 1, JMP_REL, JMP_FW },	/* MACAddr01 byte [0:1] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(4),  0, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr02 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(1),   EW_BRANCH(4),  2, 1, JMP_REL, JMP_FW },	/* MACAddr02 byte [0:1] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(6),  0, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr03 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(1),   EW_BRANCH(6),  2, 1, JMP_REL, JMP_FW },	/* MACAddr03 byte [0:1] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(3),   EW_BRANCH(0),  0, 0, JMP_REL, JMP_BW },	/* Jump to check next MACAddr byte [0:1] or LN */

	{ 0xffff, 0, NEQT, PTREE_ALLOC(2),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr00 byte [2:3] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(2),  2, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr01 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(2),   EW_BRANCH(2),  2, 1, JMP_REL, JMP_FW },	/* MACAddr01 byte [2:3] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(4),  2, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr02 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(2),   EW_BRANCH(4),  2, 1, JMP_REL, JMP_FW },	/* MACAddr02 byte [2:3] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(6),  2, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr03 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(2),   EW_BRANCH(6),  2, 1, JMP_REL, JMP_FW },	/* MACAddr03 byte [2:3] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(3),   EW_BRANCH(0),  2, 0, JMP_REL, JMP_BW },	/* Jump to check next MACAddr byte [0:1] or LN */

	{ 0xffff, 0, NEQT, PTREE_ALLOC(M),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr00 byte [4:5] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(2),  4, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr01 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(M),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr01 byte [4:5] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(4),  4, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr02 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(M),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr02 byte [4:5] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(0),   EW_BRANCH(6),  4, 0, JMP_REL, JMP_BW },	/* Jump to check MACAddr03 byte [0:1] */
	{ 0xffff, 0, NEQT, PTREE_ALLOC(M),   EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* MACAddr03 byte [4:5] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(3),   EW_BRANCH(0),  4, 0, JMP_REL, JMP_BW },	/* Jump to check next MACAddr byte [0:1] or LN */
};

static struct ptree_branch branch_E[] = {
	/* AVL */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(AVL), EW_BRANCH(1),  2, 0, JMP_REL, JMP_FW },	/* AVL MACAddr byte [0:1] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(AVL), EW_BRANCH(2),  2, 0, JMP_REL, JMP_FW },	/* AVL MACAddr byte [2:3] */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(ALN), EW_BRANCH(0),  2, 0,       0,      0 },	/* AVL MACAddr byte [4:5] */

	/* ALN */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(0),  0, 0,       0,      0 },	/* Last Node for AVL Search */

	/* S07 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(D07), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 0 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(D76), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 1 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(D65), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 2 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(D54), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 4 = 3 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(D43), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 4 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(D32), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 5 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(D21), EW_BRANCH(0),  2, 1, JMP_REL, JMP_FW },	/* SRC Port % 8 = 6 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(D10), EW_BRANCH(0),  2, 0, JMP_REL, JMP_FW },	/* SRC Port % 8 = 7 */

	/* D07 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 0 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 1 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 2 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 3 -> Flow ID 3 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 4 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 5 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 6 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 7 */

	/* D76 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 0 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 1 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 2 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 2 -> Flow ID 3 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 4 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 5 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 6 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 7 */

	/* D65 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 0 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 1 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 2 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 1 -> Flow ID 3 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 4 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 5 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 6 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 7 */

	/* D54 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 0 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 1 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 2 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 0 -> Flow ID 3 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 4 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 5 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 6 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 7 */

	/* D43 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 0 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 1 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 2 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 7 -> Flow ID 3 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 4 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 5 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 6 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 7 */

	/* D32 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 0 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 1 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 2 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 6 -> Flow ID 3 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 4 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 5 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 6 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 7 */

	/* D21 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 0 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 1 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 4 -> Flow ID 2 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 5 -> Flow ID 3 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 4 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 5 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 6 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 7 */

	/* D10 */
	{ 0xfff8, 1,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(0),  0, 1,       0,      0 },	/* DST Port % 8 = 1 -> Flow ID 0 */
	{ 0xfff8, 2,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(1),  0, 1,       0,      0 },	/* DST Port % 8 = 2 -> Flow ID 1 */
	{ 0xfff8, 3,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(2),  0, 1,       0,      0 },	/* DST Port % 8 = 3 -> Flow ID 2 */
	{ 0xfff8, 4,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(3),  0, 1,       0,      0 },	/* DST Port % 4 = 4 -> Flow ID 3 */
	{ 0xfff8, 5,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(4),  0, 1,       0,      0 },	/* DST Port % 8 = 5 -> Flow ID 4 */
	{ 0xfff8, 6,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(5),  0, 1,       0,      0 },	/* DST Port % 8 = 6 -> Flow ID 5 */
	{ 0xfff8, 7,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(6),  0, 1,       0,      0 },	/* DST Port % 8 = 7 -> Flow ID 6 */
	{ 0xfff8, 0,  EQT, PTREE_ALLOC(MLN), EW_BRANCH(7),  0, 0,       0,      0 },	/* DST Port % 8 = 0 -> Flow ID 7 */

	/* MLN */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(0),  0, 0,       0,      0 },	/* Last Node allowing FlowID 0 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(1),  0, 0,       0,      0 },	/* Last Node allowing FlowID 1 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(2),  0, 0,       0,      0 },	/* Last Node allowing FlowID 2 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(3),  0, 0,       0,      0 },	/* Last Node allowing FlowID 3 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(4),  0, 0,       0,      0 },	/* Last Node allowing FlowID 4 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(5),  0, 0,       0,      0 },	/* Last Node allowing FlowID 5 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(6),  0, 0,       0,      0 },	/* Last Node allowing FlowID 6 */
	{ 0xffff, 0,  EQT, PTREE_ALLOC(MKN), KEY_INDEX(7),  0, 0,       0,      0 },	/* Last Node allowing FlowID 7 */
};

static struct ptree_dn dn[] = {
	{ START_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8,  &branch[0] },	/* Check for MACAddr00-03 byte [0:1] */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8,  &branch[8] },	/* Check for MACAddr00-03 byte [2:3] */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch[16] },	/* Check for MACAddr00-03 byte [4:5] */
};

static struct ptree_dn dn_E[] = {
	{ START_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 3,  &branch_E[0] },	/* AVL MACAddr byte [0:5] */
	{ LAST_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 1,  &branch_E[3] },	/* Last Node for AVL Search */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8,  &branch_E[4] },	/* SRC Port % 8 = 0-7 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[12] },	/* DST Port % 8 = 0-7 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[20] },	/* DST Port % 8 = 7-6 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[28] },	/* DST Port % 8 = 6-5 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[36] },	/* DST Port % 8 = 5-4 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[44] },	/* DST Port % 8 = 4-3 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[52] },	/* DST Port % 8 = 3-2 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[60] },	/* DST Port % 8 = 2-1 */
	{ INTERIM_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[68] },	/* DST Port % 8 = 1-0 */
	{ LAST_NODE,	DBPTR_DROP(0), AVL_SEARCH(NO_BYTE),    0, 0, 0, 8, &branch_E[76] },	/* Last Node for FlowID 0-7 */
};

static struct ptree_node node[] = {
	{ PTREE_ALLOC(0),   EWDN, 0, (struct ptree_dn*)&dn[0] },
	{ PTREE_ALLOC(1),   EWDN, 0, (struct ptree_dn*)&dn[1] },
	{ PTREE_ALLOC(2),   EWDN, 0, (struct ptree_dn*)&dn[2] },
};

static struct ptree_node node_E[] = {
	{ PTREE_ALLOC(AVL), EWDN, 0, (struct ptree_dn*)&dn_E[AVL] },
	{ PTREE_ALLOC(ALN), EWDN, 0, (struct ptree_dn*)&dn_E[ALN] },
	{ PTREE_ALLOC(S07), EWDN, 0, (struct ptree_dn*)&dn_E[S07] },
	{ PTREE_ALLOC(D07), EWDN, 0, (struct ptree_dn*)&dn_E[D07] },
	{ PTREE_ALLOC(D76), EWDN, 0, (struct ptree_dn*)&dn_E[D76] },
	{ PTREE_ALLOC(D65), EWDN, 0, (struct ptree_dn*)&dn_E[D65] },
	{ PTREE_ALLOC(D54), EWDN, 0, (struct ptree_dn*)&dn_E[D54] },
	{ PTREE_ALLOC(D43), EWDN, 0, (struct ptree_dn*)&dn_E[D43] },
	{ PTREE_ALLOC(D32), EWDN, 0, (struct ptree_dn*)&dn_E[D32] },
	{ PTREE_ALLOC(D21), EWDN, 0, (struct ptree_dn*)&dn_E[D21] },
	{ PTREE_ALLOC(D10), EWDN, 0, (struct ptree_dn*)&dn_E[D10] },
	{ PTREE_ALLOC(MLN), EWDN, 0, (struct ptree_dn*)&dn_E[MLN] },
	{ PTREE_ALLOC(MKN),   KN, 0,     (struct ptree_kn*)&kn[0] },
	{ PTREE_ALLOC(MKN),   KN, 1,     (struct ptree_kn*)&kn[1] },
	{ PTREE_ALLOC(MKN),   KN, 2,     (struct ptree_kn*)&kn[2] },
	{ PTREE_ALLOC(MKN),   KN, 3,     (struct ptree_kn*)&kn[3] },
	{ PTREE_ALLOC(MKN),   KN, 4,     (struct ptree_kn*)&kn[4] },
	{ PTREE_ALLOC(MKN),   KN, 5,     (struct ptree_kn*)&kn[5] },
	{ PTREE_ALLOC(MKN),   KN, 6,     (struct ptree_kn*)&kn[6] },
	{ PTREE_ALLOC(MKN),   KN, 7,     (struct ptree_kn*)&kn[7] },
};

const u8 apm_usr_macmask[ETH_ALEN + 2] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

const u8 apm_sys_macmask[APM_SYS_MACADDR][ETH_ALEN + 2] = {
	[ETHERNET_MACADDR]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	[BROADCAST_MACADDR] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	[UNICAST_MACADDR]   = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff},
	[MULTICAST_MACADDR] = {0xfe, 0xff, 0xff, 0xff, 0xff, 0xff},
};

const u8 apm_sys_macaddr[APM_SYS_MACADDR][ETH_ALEN + 2] = {
	[ETHERNET_MACADDR]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	[BROADCAST_MACADDR] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
	[UNICAST_MACADDR]   = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	[MULTICAST_MACADDR] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00},
};

unsigned int default_rx_dbptr[MAX_CLE_PORTS];

struct apm_ptree_config_list {
	struct list_head node;
	char ptree_id[CLE_PTREE_ID_SIZE];
	struct apm_ptree_config ptree_config;
};

static struct list_head apm_ptree_config_head[MAX_CLE_PORTS] = {{0}};

struct xgene_enet_cle *apm_cle_init(u32 port_id)
{
        struct xgene_enet_cle *cle_cfg = NULL;

        static int init_list_head_done = 0;
        if (!init_list_head_done) {
                int i;

                for (i = 0; i < MAX_CLE_PORTS; i++)
                        INIT_LIST_HEAD(&apm_ptree_config_head[i]);
                init_list_head_done = 1;
        }	
	cle_cfg = kmalloc(sizeof(struct xgene_enet_cle), GFP_KERNEL);
        if (!cle_cfg) {
                PCLS_ERR("Could not allocate cle\n");
                goto cerr;
        }

        return cle_cfg;
cerr:
        if (cle_cfg)
                kfree(cle_cfg);
        return NULL;
}

int apm_preclass_update_mac(u8 port_id, enum apm_macaddr_type type,
		u8 index, const u8 *macmask, const u8 *macaddr)
{
	int rc = APM_RC_OK;
	struct apm_ptree_config *ptree_config;
	int i;
	u32 base_node_ptr;

	ptree_config = apm_find_ptree_config(port_id, CLE_PTREE_DEFAULT);
	if (!ptree_config) {
		rc = APM_RC_ERROR;
		goto _ret_preclass_update_mac;
	}

#ifdef APM_UNICAST_MACADDR_CHECK_IN_PTREE
	if (type == TYPE_SYS_MACADDR) {
		if (index >= APM_SYS_MACADDR) {
			PCLS_ERR("SYS_MACADDR index %d out-of-range\n", index);
			rc = APM_RC_ERROR;
			goto _ret_preclass_update_mac;
		}
		index += APM_MAX_UNICAST_MACADDR;
	} else {
		if (index >= APM_MAX_UNICAST_MACADDR) {
			PCLS_ERR("USR_MACADDR index %d out-of-range\n", index);
			rc = APM_RC_ERROR;
			goto _ret_preclass_update_mac;
		}
	}
#endif

	base_node_ptr = ptree_config->start_node_ptr;

	for (i = 0; i < 3; i++) {
		struct ptree_branch pbranch;

		memset(&pbranch, 0, sizeof(pbranch));
		pbranch.mask = (macaddr == NULL) ? 0xffff :
			((u16)macmask[2 * i] << 8) | macmask[(2 * i) + 1];
		pbranch.data = (macaddr == NULL) ? 0x0000 :
			((u16)macaddr[2 * i] << 8) | macaddr[(2 * i) + 1];
		pbranch.operation = (macaddr == NULL ? NEQT : EQT);
		rc |= apm_set_ptree_node_branch(port_id,
			base_node_ptr + MAC_NODE(index, i),
			0, MAC_BRANCH(index, i), &pbranch, SET_BRANCH_MDO);
	}

_ret_preclass_update_mac:
	return rc;
}

int apm_preclass_switch_tree(u8 port_id, char *ptree_id)
{
	int rc;
	struct apm_ptree_config *ptree_config;

	PCLS_DBG("Switch Tree for port %d with ptree %s\n",
		port_id, ptree_id);

	ptree_config = apm_find_ptree_config(port_id, ptree_id);
	if (ptree_config == NULL) {
		PCLS_ERR("Patricia Tree %s Configuration absent for "
			"port %d\n", ptree_id, port_id);
		return APM_RC_ERROR;
	}

	if ((rc = apm_set_sys_ptree_config(port_id, ptree_config)
			!= APM_RC_OK)) {
		PCLS_ERR("Preclass Switch to %s Tree error %d \n",
			ptree_id, rc);
		return rc;
	}
	return rc;
}

static struct apm_ptree_config_list *apm_find_ptree_config_entry(u8 port,
		char *ptree_id)
{
	struct apm_ptree_config_list *entry;

	if (ptree_id == NULL || ptree_id[0] == '\0' ||
			apm_ptree_config_head[port].next == NULL ||
			apm_ptree_config_head[port].prev == NULL)
		return NULL;

	list_for_each_entry(entry, &apm_ptree_config_head[port], node) {
		if (strncmp(entry->ptree_id, ptree_id, CLE_PTREE_ID_SIZE) == 0) {
			return entry;
		}
	}

	return NULL;
}

struct apm_ptree_config *apm_find_ptree_config(u8 port, char *ptree_id)
{
	struct apm_ptree_config_list *entry;

	entry = apm_find_ptree_config_entry(port, ptree_id);

	if (entry)
		return &entry->ptree_config;

	return NULL;
}

struct apm_ptree_config *apm_add_ptree_config(u8 port, char *ptree_id)
{
	struct apm_ptree_config_list *entry;

	if (ptree_id == NULL || ptree_id[0] == '\0')
		return NULL;

	entry = apm_find_ptree_config_entry(port, ptree_id);

	if (entry == NULL) {
		entry = kmalloc(sizeof (struct apm_ptree_config_list),
			GFP_KERNEL);

		if (entry == NULL)
			return NULL;

		strncpy(entry->ptree_id, ptree_id, CLE_PTREE_ID_SIZE);
		list_add(&entry->node, &apm_ptree_config_head[port]);
		entry->ptree_config.start_node_ptr = SYSTEM_START_NODE;
		entry->ptree_config.start_pkt_ptr = 0;
		entry->ptree_config.default_result = DEFAULT_DBPTR;
		entry->ptree_config.start_parser = 1;
		entry->ptree_config.max_hop = 0;
	}

	return &entry->ptree_config;
}

int apm_del_ptree_config(u8 port, char *ptree_id)
{
	struct apm_ptree_config_list *entry;

	entry = apm_find_ptree_config_entry(port, ptree_id);

	if (entry) {
		list_del(&entry->node);
		kfree(entry);
		return 0;
	}

	return -EINVAL;
}

#ifdef PTREE_MANAGER
char *apm_get_sys_ptree_id(u8 port)
{
	struct apm_ptree_config_list *entry;
	struct apm_ptree_config ptree_config;

	if (apm_ptree_config_head[port].next == NULL ||
			apm_ptree_config_head[port].prev == NULL)
		return NULL;

	if (apm_get_sys_ptree_config(port, &ptree_config))
		return NULL;

	list_for_each_entry(entry, &apm_ptree_config_head[port], node) {
		if (entry->ptree_config.start_node_ptr == ptree_config.start_node_ptr) {
			return entry->ptree_id;
		}
	}

	return NULL;
}
#endif

/* Pre-Classifier Configuration initialization */
struct xgene_enet_cle_ptree *apm_preclass_init(u8 port_id, u16 *rx_dstqid, u16 *rx_fpsel)
{
	int i, rc;
	struct apm_ptree_config *ptree_config;
	struct xgene_enet_cle_ptree *ptree_cfg = NULL;
	u32 ptree_groups;
	u32 ptree_allocs;
#ifdef APM_UNICAST_MACADDR_CHECK_IN_PTREE
	u32 mac_entries = APM_MAX_UNICAST_MACADDR;
#else
	u32 mac_entries = 0;
#endif
	u32 index, mask, data;
	memset(&dbptr, 0, sizeof(dbptr));
	memset(&kn, 0, sizeof(kn));

	ptree_config = apm_add_ptree_config(port_id, CLE_PTREE_DEFAULT);
	if (ptree_config == NULL) {
		PCLS_ERR("Add Patricia Tree Default Configuration error for "
			"port %d\n", port_id);
		return NULL;
	}

	PCLS_DBG("Create Preclassifier DB entries for Ping Tree port %d\n",
		port_id);

	ptree_groups = PTREE_GROUPS(mac_entries);
	ptree_allocs = PTREE_ALLOCS(mac_entries);

	if (port_id == CLE_ENET_0 || port_id == CLE_ENET_2)
                apm_gbl_cle_wr32(PID2CID[port_id], PORTNUM0_ADDR, 0);
	else if (port_id == CLE_ENET_1 || port_id == CLE_ENET_3)
                apm_gbl_cle_wr32(PID2CID[port_id], PORTNUM1_ADDR, 1);

	if (port_id == CLE_ENET_4) {
		branch[7].operation = NEQT;
		branch[15].operation = NEQT;
		branch[23].operation = NEQT;
	} else {
		branch[7].operation = EQT;
		branch[15].operation = EQT;
		branch[23].operation = EQT;
	}

	switch (MAX_RX_QUEUES) {
		case 0:
		case 1:
			mask = 0xffff;
			break;
		case 2:
		case 3:
			mask = 0xfffe;
			break;
		case 4:
		case 5:
		case 6:
		case 7:
			mask = 0xfffc;
			break;
		case 8:
		default:
			mask = 0xfff8;
	};

	/* Clear Mask, Data and Operations for all branches for SRC Port */
	for (i = 0; i < 8; i++) {
		branch_E[4 + i].mask = 0xffff;
		branch_E[4 + i].data = 0;
		branch_E[4 + i].operation = NEQT;
	}

	/* Clear Mask, Data and Operations for all branches for DST Port */
	for (i = 0; i < 64; i++) {
		branch_E[12 + i].mask = 0xffff;
		branch_E[12 + i].data = 0;
		branch_E[12 + i].operation = NEQT;
	}

	/*
	 * Update Mask, Data and Operations based on number of queues
	 * for SRC Port
	 */
	for (i = 0; i < MAX_RX_QUEUES; i++) {
		branch_E[4 + i].mask = mask;
		branch_E[4 + i].data = i;
		branch_E[4 + i].operation = EQT;
	}

	/*
	 * Update Mask, Data and Operations based on number of queues
	 * for DST Port
	 */
	for (i = 0; i < MAX_RX_QUEUES * MAX_RX_QUEUES; i++) {
		index = 12 + (8 * (i / MAX_RX_QUEUES)) + (i % MAX_RX_QUEUES);
		data = (i - (i / MAX_RX_QUEUES)) % MAX_RX_QUEUES;
		branch_E[index].mask = mask;
		branch_E[index].data = data;
		branch_E[index].operation = EQT;
	}

	/*
	 * Update MAC matching next_node_index with PTREE_ALLOC(index)
	 * of last node. Only identify Source Port and Destination Port
	 * for our MAC Address
	 */
	branch[16].next_packet_pointer = 30;
	branch[16].next_node_index = PTREE_ALLOC(ptree_allocs + S07);
	branch[18].next_node_index = PTREE_ALLOC(ptree_allocs + MLN);
	branch[20].next_node_index = PTREE_ALLOC(ptree_allocs + MLN);
	branch[22].next_node_index = PTREE_ALLOC(ptree_allocs + MLN);

	for (i = 0; i < ptree_groups; i++) {
		if ((rc = apm_ptree_alloc(port_id, ARRAY_SIZE(node),
				0, node, NULL, ptree_config)) !=
				APM_RC_OK) {
			PCLS_ERR("Preclass init error %d \n", rc);
			return NULL;
		}

		/*
		 * Once allocated, update MAC matching next_node_index with
		 * absolute index of last node
		 */
		if (i == 0) {
			branch[16].next_packet_pointer = 2;
			branch[16].next_node_index =
				ptree_config->start_node_ptr
				+ ptree_allocs + MLN;
			branch[18].next_node_index =
				ptree_config->start_node_ptr
				+ ptree_allocs + MLN;
			branch[20].next_node_index =
				ptree_config->start_node_ptr
				+ ptree_allocs + MLN;
			branch[22].next_node_index =
				ptree_config->start_node_ptr
				+ ptree_allocs + MLN;
		}
	}

	for (i = 0; i < MAX_RX_QUEUES; i++) {
		u16 dstqid;

		dbptr[i].index = DBPTR_ALLOC(CLE_DB_INDEX + i);
#ifdef APM_ENET_QM_LOOPBACK
		/* Not support APM_ENET_QM_LOOPBACK */
#else
		/*
		 * stashing table
		 * 0- no, 1- 1st buffer, 2- entire packet, 3- 64 bytes
		 */
		dbptr[i].stash = 0x1;
		if (rx_dstqid[i])
			dstqid = rx_dstqid[i];
		else
			dstqid = rx_dstqid[0];
		if (rx_fpsel[i])
			dbptr[i].fpsel = rx_fpsel[i] - 0x20;
		else
			dbptr[i].fpsel = rx_fpsel[0] - 0x20;
#endif
		dbptr[i].dstqidL = dstqid & 0x7f;
		dbptr[i].dstqidH = (dstqid >> 7) & 0x1f;

		/* JUMBO_FRAME is not supported yet */
		dbptr[i].nxtfpsel = 0;

		/* Report Rx timestamp in H1Info */
		/* dbptr[i].cle_insert_timestamp = 1; */

		kn[i].priority = 2;
		kn[i].result_pointer = DBPTR_ALLOC(CLE_DB_INDEX + i);
	}

	/* Allocate the last node and key node */
	PCLS_DBG("Create Patricia Tree Nodes for Ping Tree\n");
	if ((rc = apm_ptree_alloc(port_id, ARRAY_SIZE(node_E) - 8 + MAX_RX_QUEUES,
			ARRAY_SIZE(dbptr), node_E, dbptr, ptree_config)) !=
			APM_RC_OK) {
		PCLS_ERR("Preclass init error %d for port %d\n", rc, port_id);
		return NULL;
	}

	default_rx_dbptr[port_id] = ptree_config->start_dbptr;

	/*
	 * Once all nodes are allocated, update snptr and max_hop with
	 * correct value
	 */
	ptree_config->start_node_ptr -= ptree_allocs;
	ptree_config->max_hop += (ptree_allocs * 8);
	ptree_config->default_result = DFCLSRESDBPRIORITY0_WR(1) |
					DFCLSRESDBPTR0_WR(START_DB_INDEX);

	ptree_cfg = kmalloc(sizeof(struct xgene_enet_cle_ptree), GFP_KERNEL);
	if (!ptree_cfg) {
		PCLS_ERR("Could not allocate ptree\n");
		goto perr;
	}

	return ptree_cfg;
perr:
        if (ptree_cfg)
                kfree(ptree_cfg);

        return NULL;
}
