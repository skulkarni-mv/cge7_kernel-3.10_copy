/**
 * AppliedMicro APM86xxx SoC Classifier Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Mahesh Pujara <mpujara@apm.com>
 *                      Ravi Patel <rapatel@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * @file apm_preclass_api.c
 *
 * This file iplements APIs for APM86xxx SoC Classifier Parser module.
 *
 */

#include "apm_preclass_data.h"
#include "apm_preclass_base.h"

#define APM_RET_IVP APM_RC_INVALID_PARM

/* global data */
/* apm_cle_system_id & apm_cle_systems used for CLE resource division for AMP */
u8 apm_cle_system_id;	/* Needs to be updated by BootLoader and OS */
u8 apm_cle_systems;	/* Needs to be updated by BootLoader and OS */
int apm_preclass_init_state[MAX_CLE_ENGINE] = {0};
#ifdef CLE_SHADOW
static int ptree_shadow_done[MAX_CLE_ENGINE] = {0};
static struct apm_ptree_node sys_ptree_node[MAX_CLE_ENGINE][MAX_NODE_ENTRIES];
static struct apm_cle_dbptr sys_cle_dbptr[MAX_CLE_ENGINE][MAX_DB_ENTRIES];
#endif
struct apm_preclass_state sys_preclass_state[MAX_CLE_ENGINE];
struct apm_ptree_config sys_ptree_config[MAX_CLE_PORTS];
#ifdef CLE_MANAGER
int apm_cle_mgr_init(u32 cid);
#endif

#ifdef CONFIG_APM862xx
u32 PID2CID[MAX_CLE_PORTS] = {
	CLE_0,
	CLE_0,
	CLE_0
};
u32 PORTIDX[MAX_CLE_PORTS] = {
	CLE_INLINE_PORT0,
	CLE_INLINE_PORT1,
	CLE_LAC_PORT
};
u32 CLEBASEPORTID[MAX_CLE_ENGINE] = {
	CLE_ENET_0
};
u32 CLEPORTS[MAX_CLE_ENGINE] = {
	3
};
#else
u32 PID2CID[MAX_CLE_PORTS] = {
	CLE_0,
	CLE_0,
	CLE_1,
	CLE_1,
	CLE_1
};
u32 PORTIDX[MAX_CLE_PORTS] = {
	CLE_INLINE_PORT0,
	CLE_INLINE_PORT1,
	CLE_INLINE_PORT0,
	CLE_INLINE_PORT1,
	CLE_LAC_PORT
};
u32 CLEBASEPORTID[MAX_CLE_ENGINE] = {
	CLE_ENET_0,
	CLE_ENET_2
};
u32 CLEPORTS[MAX_CLE_ENGINE] = {
	2,
	3
};
#endif

static void shift_left_be(u32 *data, u32 bit_index, u32 bit_length, u32 shift)
{
	while (shift > 0 && bit_index > 0) {
		u32 long_end = (bit_index + bit_length - 1) / 32;
		u32 long_index = (bit_index - 1) / 32;
		u32 long_bit_index = ((bit_index - 1) % 32);
		u32 long_bit_mask = 0xffffffff >> long_bit_index;
		u32 long_bit_end_index = ((bit_index + bit_length) % 32);
		u32 long_bit_end_mask = 0xffffffff <<
			(32 - (long_bit_end_index ? long_bit_end_index : 32));
		u32 i;

		if (long_index == long_end) {
			data[long_index] = (data[long_index] &
				~(long_bit_mask & long_bit_end_mask)) |
				((data[long_index] &
				(long_bit_mask & long_bit_end_mask)) << 1);
		} else {
			data[long_index] = (data[long_index] & ~long_bit_mask) |
				((data[long_index] << 1) & long_bit_mask);

			for (i = long_index; i < long_end; i++) {

				if (i > long_index)
					data[i] <<= 1;

				data[i] = (data[i] & ~1) | (data[i + 1] >> 31);
			}

			data[long_end] = (data[long_end] & ~long_bit_end_mask) |
				((data[long_end] << 1) & long_bit_end_mask);
		}

		bit_index--;
		shift--;
	}
}

#ifndef CLE_SHADOW
static void shift_right_be(u32 *data, u32 data_length, u32 bit_index,
				u32 bit_length, u32 shift)
{
	bit_length = (bit_index + 1) < bit_length ? (bit_index + 1) : bit_length;

	while (shift > 0 && bit_index < ((data_length * 8) - 1)) {
		u32 long_end = (bit_index - bit_length + 1) / 32;
		u32 long_index = (bit_index + 1) / 32;
		u32 long_bit_index = ((bit_index + 1) % 32);
		u32 long_bit_mask = 0xffffffff << (31 - long_bit_index);
		u32 long_bit_end_index = ((bit_index - bit_length + 1) % 32);
		u32 long_bit_end_mask = 0xffffffff >> long_bit_end_index;
		u32 i;

		if (long_index == long_end) {
			data[long_index] = (data[long_index] &
				~(long_bit_mask & long_bit_end_mask)) |
				((data[long_index] &
				(long_bit_mask & long_bit_end_mask)) >> 1);
		} else {
			data[long_index] = (data[long_index] & ~long_bit_mask) |
				((data[long_index] >> 1) & long_bit_mask);

			for (i = long_index; i > long_end; i--) {

				if (i < long_index)
					data[i] >>= 1;

				data[i] = (data[i] & ~0x80000000) |
						(data[i - 1] << 31);
			}

			data[long_end] = (data[long_end] & ~long_bit_end_mask) |
				((data[long_end] & long_bit_end_mask) >> 1);
		}

		bit_index++;
		shift--;
	}
}
#endif

static void apm_ptree_node_struct_to_reg(void *data)
{
	u32 i;
	int shift;
	u32 *regs = (u32 *)data;
	struct apm_ptree_node *node = (struct apm_ptree_node *)data;

	switch (node->type) {
	case EIGHT_WAY_NODE:
#ifdef CONFIG_APM862xx
		shift = 5 - PAD_SIZE;
		shift_left_be(regs, 8, 17, shift);
		shift += 2;
#else
		shift = 6 - (PAD_SIZE / 5);
		shift_left_be(regs, 8 + ((PAD_SIZE * 4) / 5), 18, shift);
		shift += 1;
#endif
		for (i = 0; i < 8; i++) {
			shift += 5;
#ifdef CONFIG_APM862xx
			shift_left_be(regs, (64 * i) + 32, 59, shift);
#else
			shift_left_be(regs, (64 * i) + 32 + ((PAD_SIZE * 4) / 5), 59, shift);
#endif
		}
		break;

#ifdef CONFIG_APM862xx
	case FOUR_WAY_NODE1_ONLY:
	case FOUR_WAY_NODE2_ONLY:
	case FOUR_WAY_NODE_BOTH:
	{
		u32 j;
		shift = 0 - PAD_SIZE;
		for (j = 0; j < 2; j++) {
			shift += 5;
			shift_left_be(regs, (280 * j) + 8, 17, shift);
			shift += 2;
			for (i = 0; i < 4; i++) {
				shift += 5;
				shift_left_be(regs,
					((64 * i) + (280 * j) + 32), 59, shift);
			}
		}
		break;
	}
#endif

	case KEY_NODE:
#ifdef CONFIG_APM862xx
		shift = 2 - PAD_SIZE;
#else
		shift = 3 - (PAD_SIZE / 5);
#endif
		for (i = 0; i < 32; i++) {
			shift += 3;
#ifdef CONFIG_APM862xx
			shift_left_be(regs, (16 * i) + 8, 13, shift);
#else
			shift_left_be(regs, (16 * i) + 8 + ((PAD_SIZE * 4) / 5), 13, shift);
#endif
		}
	}
}

#ifndef CLE_SHADOW
static void apm_ptree_node_reg_to_struct(void *data)
{
	u32 i;
	int shift;
	u32 *regs = (u32 *)data;
	struct apm_ptree_node *node = (struct apm_ptree_node *)data;
	u32 size = SIZE_PER_PTREE_NODE_STRUCT;

	switch (node->type) {
	case EIGHT_WAY_NODE:
#ifdef CONFIG_APM862xx
		shift = 52 - PAD_SIZE;
#else
		shift = 52 - (PAD_SIZE / 5);
#endif
		for (i = 0; i < 8; i++) {
			shift -= 5;
			shift_right_be(regs, size, 491 + PAD_SIZE - (59 * i), 59, shift);
		}
#ifdef CONFIG_APM862xx
		shift -= 7;
		shift_right_be(regs, size, 19 + PAD_SIZE, 17, shift);
#else
		shift -= 6;
		shift_right_be(regs, size, 19 + PAD_SIZE, 18, shift);
#endif
		break;

#ifdef CONFIG_APM862xx
	case FOUR_WAY_NODE1_ONLY:
	case FOUR_WAY_NODE2_ONLY:
	case FOUR_WAY_NODE_BOTH:
	{
		u32 j;
		shift = 59 - PAD_SIZE;
		for (j = 0; j < 2; j++) {
			for (i = 0; i < 4; i++) {
				shift -= 5;
				shift_right_be(regs, size,
					(508 + PAD_SIZE - (59 * i) - (253 * j)), 59, shift);
			}
			shift -= 7;
			shift_right_be(regs, size, 272 + PAD_SIZE - (253 * j), 17, shift);
		}
		break;
	}
#endif

	case KEY_NODE:
#ifdef CONFIG_APM862xx
		shift = 101 - PAD_SIZE;
#else
		shift = 102 - (PAD_SIZE / 5);
#endif
		for (i = 0; i < 32; i++) {
			shift -= 3;
#ifdef CONFIG_APM862xx
			shift_right_be(regs, size, 418 + PAD_SIZE - (13 * i), 13, shift);
#else
			shift_right_be(regs, size, 417 + PAD_SIZE - (13 * i), 13, shift);
#endif
		}
	}
}
#endif

int apm_preclassify_init(u32 cid)
{
	int rc = APM_RC_OK;
	int i;
	struct apm_cle_dbptr dbptr;

	if (apm_preclass_init_state[cid]) {
		PCLS_DBG("Pre-classifier global s/w "
			"config already done \n");
		rc = APM_RC_FATAL;
		goto _ret_preclassify_init;
	}

	memset(&sys_preclass_state[cid], 0, sizeof(sys_preclass_state[cid]));
	for (i = 0; i < CLEPORTS[cid]; i++) {
		sys_preclass_state[cid].start_engine[i] = PARSER_HALT0_MASK;
		memset(&sys_ptree_config[CLEBASEPORTID[cid] + i], 0,
			sizeof(sys_ptree_config[CLEBASEPORTID[cid] + i]));
		sys_ptree_config[i].start_engine = PARSER_HALT0_MASK;
	}
	memset(&dbptr, 0, sizeof(dbptr));
	dbptr.index = START_DB_INDEX;
	dbptr.drop = 1;
	rc = apm_set_cle_dbptr(CLEBASEPORTID[cid], &dbptr);
#ifdef CLE_MANAGER
	rc |= apm_cle_mgr_init(cid);
#endif
	apm_preclass_init_state[cid] = 1;

_ret_preclassify_init:
	return rc;
}

#ifdef CLE_SHADOW
static inline void apm_ptree_shadow_init(u32 cid)
{
	if (!ptree_shadow_done[cid]) {
		memset(&sys_ptree_node[cid], 0,
			sizeof(sys_ptree_node[cid]));
		memset(&sys_cle_dbptr[cid], 0,
			sizeof(sys_cle_dbptr[cid]));
		ptree_shadow_done[cid] = 1;
	}
}

struct apm_ptree_node *get_shadow_ptree_nodes(u32 port)
{
	return &sys_ptree_node[PID2CID[port]][0];
}

struct apm_cle_dbptr *get_shadow_cle_dbptrs(u32 port)
{
	return &sys_cle_dbptr[PID2CID[port]][0];
}
#endif

int apm_set_ptree_node(u8 port, u8 node_index, struct apm_ptree_node *node)
{
	int rc;

#ifdef CLE_SHADOW
	apm_ptree_shadow_init(PID2CID[port]);

	memcpy(&sys_ptree_node[PID2CID[port]][node_index], node,
		sizeof(struct apm_ptree_node));
#endif

	apm_ptree_node_struct_to_reg(node);
	rc = apm_preclass_ptram_write(port, node_index, (u32 *)node);

	return rc;
}

int apm_get_ptree_node(u8 port, u8 node_index, struct apm_ptree_node *node)
{
	int rc = APM_RC_OK;

#ifdef CLE_SHADOW
	apm_ptree_shadow_init(PID2CID[port]);

	memcpy(node, &sys_ptree_node[PID2CID[port]][node_index],
		sizeof(struct apm_ptree_node));
#else
	rc = apm_preclass_ptram_read(port, node_index, (u32 *)node);
	apm_ptree_node_reg_to_struct(node);
#endif

	return rc;
}

int apm_set_cle_dbptr(u32 port, struct apm_cle_dbptr *dbptr)
{
	int rc;
	u32 index;

#ifdef CLE_DEBUG
	if (dbptr == NULL) {
		PCLS_DBG("Null dbptr pointer \n");
		return APM_RC_INVALID_PARM;
	}
#endif

	index = dbptr->index;
	/* Making sure RAM is not written with unintended value */
	dbptr->index = 0;
	rc = apm_preclass_cldb_write(port, index, (u32 *)dbptr);

#ifdef CLE_SHADOW
	apm_ptree_shadow_init(PID2CID[port]);

	/* index field Will be used for cle_dbptr validity by user */
	dbptr->index = 1;
	memcpy(&sys_cle_dbptr[PID2CID[port]][index], dbptr,
		sizeof(struct apm_cle_dbptr));
#endif

	/* Putting back the index vaule */
	dbptr->index = index;

	return rc;
}

int apm_get_cle_dbptr(u32 port, struct apm_cle_dbptr *dbptr)
{
	int rc = APM_RC_OK;
	u32 index;

#ifdef CLE_DEBUG
	if (dbptr == NULL) {
		PCLS_DBG("Null dbptr pointer \n");
		return APM_RC_INVALID_PARM;
	}
#endif

	index = dbptr->index;

#ifdef CLE_SHADOW
	apm_ptree_shadow_init(PID2CID[port]);

	memcpy(dbptr, &sys_cle_dbptr[PID2CID[port]][index],
		sizeof(struct apm_cle_dbptr));
#else
	dbptr->index = 0;
	rc = apm_preclass_cldb_read(port, index, (u32 *)dbptr);
#endif

	return rc;
}

#ifdef CLE_NODE_DEBUG
void apm_ptree_dump(const char *func, int line, struct apm_ptree_node *node)
{
	int i;
	struct apm_ptree_ewdn *ewdn;
#ifdef CONFIG_APM862xx
	int j, s, e;
	struct apm_ptree_fwdn *fwdn;
#endif
	struct apm_ptree_branch branch;

	CLE_NODE_DBG("%s: %d:\n", func, line);
	switch(node->type) {
	case EIGHT_WAY_NODE:
		memset(&branch, 0, sizeof(branch));
		ewdn = &node->entry.ewdn;
		CLE_NODE_DBG(" EW: Type %d "
				"RPtr %d SBSt %d BySt %d HdSt %d Last %d CorC %d"
				"\n", node->type, ewdn->result_pointer,
				ewdn->search_byte_store, ewdn->byte_store,
				ewdn->header_length_store, ewdn->last_node,
				ewdn->extension);
		for (i = 0; i < 8; i++) {
			struct apm_ptree_branch *branch = &ewdn->branch[i];

			if (memcmp(branch, &branch, sizeof(branch)))
				CLE_NODE_DBG("  %d: VBit %d Mask %04x Data %04x OTyp %d "
					"%s %3d,%d JRel %d JBkw %d NPOf %d\n",
					i, branch->valid, branch->mask, branch->data,
					branch->operation,
					(ewdn->last_node ? "KNIn" : "NNBr"),
					branch->next_node_branch & DN_NN_SIZE,
					(ewdn->last_node ?
					((branch->next_node_branch & KN_NN_MASK) >> KN_NN_SHIFT) :
					((branch->next_node_branch & DN_NN_MASK) >> DN_NN_SHIFT)),
					branch->jump_rel, branch->jump_bw,
					branch->next_packet_pointer - ((!branch->jump_rel) * 4));
		}
		break;

#ifdef CONFIG_APM862xx
	case FOUR_WAY_NODE1_ONLY:
	case FOUR_WAY_NODE2_ONLY:
	case FOUR_WAY_NODE_BOTH:
		memset(&branch, 0, sizeof(branch));
		s = (!(node->type & 0x1));
		e = (((node->type & 0x2) >> 1) + 1);
		for (j = s; j < e; j++) {
			fwdn = &node->entry.fwdn[j];
			CLE_NODE_DBG("FW%d: Type %d "
					"RPtr %d SBSt %d BySt %d HdSt %d Last %d CorC %d"
					"\n", j, node->type, fwdn->result_pointer,
					fwdn->search_byte_store, fwdn->byte_store,
					fwdn->header_length_store, fwdn->last_node,
					fwdn->extension);
			for (i = 0; i < 4; i++) {
				struct apm_ptree_branch *branch = &fwdn->branch[i];

				if (memcmp(branch, &branch, sizeof(branch)))
					CLE_NODE_DBG("  %d: VBit %d Mask %04x Data %04x OTyp %d "
						"%s %3d,%d JRel %d JBkw %d NPOf %d\n",
						i, branch->valid, branch->mask, branch->data,
						branch->operation,
						(fwdn->last_node ? "KNIn" : "NNBr"),
						branch->next_node_branch & DN_NN_SIZE,
						(fwdn->last_node ?
						((branch->next_node_branch & KN_NN_MASK) >> KN_NN_SHIFT) :
						((branch->next_node_branch & DN_NN_MASK) >> DN_NN_SHIFT)),
						branch->jump_rel, branch->jump_bw,
						branch->next_packet_pointer - ((!branch->jump_rel) * 4));
			}
		}
		break;
#endif

	case KEY_NODE:
		CLE_NODE_DBG(" KN: Type %d\n", node->type);
		for (i = 0; i < KEYNODE_COUNT; i++) {
#ifdef CONFIG_APM862xx
			struct apm_ptree_kn *kn = &node->entry.kn[KEYNODE_INDEX - i];
#else
			struct apm_ptree_kn *kn = &node->entry.kn[i];
#endif
			if (kn->result_pointer || kn->priority)
				CLE_NODE_DBG(" %2d: Prio %d RPtr %d\n",
						i, kn->priority, kn->result_pointer);
		}
		break;
	}
}
#endif

void apm_ptree_set_data(void *data,
		       struct ptree_node *pnode,
		       u8 set_type)
{
	u8 index = pnode->location;
	int i;
	struct apm_ptree_node *node;
	struct apm_ptree_ewdn *ewdn;
#ifdef CONFIG_APM862xx
	struct apm_ptree_fwdn *fwdn;
#endif
	struct apm_ptree_kn *apkn;
	struct ptree_dn *dn;
	struct ptree_kn *kn;

	node = (struct apm_ptree_node *)data;

	PCLS_DBG("pnode->type[%d] \n", pnode->type);

	if (!data) {
		PCLS_DBG("Invalid data pointer");
		return;
	}

#ifdef CLE_DEBUG
	for (i = 0; i < REGS_PER_PTREE_NODE; i++) {
		PCLS_DBG("data[%d] is 0X%08x \t", i, ((u32 *)data)[i]);
	}
	PCLS_DBG(" \n");
#endif

	switch(pnode->type) {
	case EWDN:
		if (set_type)
			node->type = set_type & DN_TYPE_SIZE;
		dn = (struct ptree_dn *)pnode->data;
		ewdn = &node->entry.ewdn;
		ewdn->result_pointer = dn->result_pointer & DN_DEFPTR_SIZE;
		ewdn->search_byte_store = dn->search_byte_store & DN_SEARCHB_SIZE;
		ewdn->byte_store = dn->byte_store & DN_BYTE_SIZE;
		ewdn->header_length_store = dn->header_length_store & DN_HDRL_SIZE;
		ewdn->last_node = dn->node_position & DN_LN_SIZE;
		ewdn->extension = dn->extension & DN_EXTENSION_SIZE;
		CLE_NODE_DBG(" EW: Type %d "
				"RPtr %d SBSt %d BySt %d HdSt %d Last %d CorC %d"
				"\n", node->type, ewdn->result_pointer,
				ewdn->search_byte_store, ewdn->byte_store,
				ewdn->header_length_store, ewdn->last_node,
				ewdn->extension);
		for (i = 0; i < dn->num; i++) {
			struct apm_ptree_branch *branch = &ewdn->branch[i];
			struct ptree_branch *pbranch = &dn->branch[i];
			branch->valid = pbranch->valid & DN_VALID_SIZE;
			branch->mask = pbranch->mask & DN_MASK_SIZE;
			branch->data = pbranch->data & DN_MASK_SIZE;
			branch->operation = pbranch->operation & DN_OP_SIZE;
			branch->next_node_branch =
				((pbranch->next_node_index & DN_NN_SIZE) |
				((pbranch->next_node_loc & 0x1F) << 7)) & DN_NNP_SIZE;
			branch->jump_rel =
				pbranch->jump_rel & DN_JREL_SIZE;
			branch->jump_bw =
				pbranch->jump_bw & DN_JBW_SIZE;
			CLE_NODE_DBG("  %d: VBit %d Mask %04x Data %04x OTyp %d "
					"%s %3d%s,%d JRel %d JBkw %d NPOf %d\n",
					i, branch->valid, branch->mask, branch->data,
					branch->operation,
					(ewdn->last_node ? "KNIn" : "NNBr"),
					pbranch->next_node_index,
#ifdef CONFIG_APM862xx
					((pbranch->next_node_loc & !ewdn->last_node) ? ".1" : ""),
					(pbranch->next_node_loc >> !ewdn->last_node),
#else
					"",
					pbranch->next_node_loc,
#endif
					branch->jump_rel, branch->jump_bw,
					pbranch->next_packet_pointer);
#ifdef CARBON_MODEL
			branch->next_packet_pointer =
				(pbranch->next_packet_pointer +
					((!branch->jump_rel) * 4)) & DN_NBP_SIZE;
#else
			branch->next_packet_pointer =
				pbranch->next_packet_pointer & DN_NBP_SIZE;
#endif
		}
		break;

#ifdef CONFIG_APM862xx
	case FWDN:
		if (set_type)
			node->type = set_type & DN_TYPE_SIZE;
		dn = (struct ptree_dn *)pnode->data;
		fwdn = &node->entry.fwdn[index];
		fwdn->result_pointer = dn->result_pointer & DN_DEFPTR_SIZE;
		fwdn->search_byte_store = dn->search_byte_store & DN_SEARCHB_SIZE;
		fwdn->byte_store = dn->byte_store & DN_BYTE_SIZE;
		fwdn->header_length_store = dn->header_length_store & DN_HDRL_SIZE;
		fwdn->last_node = dn->node_position & DN_LN_SIZE;
		fwdn->extension = dn->extension & DN_EXTENSION_SIZE;
		CLE_NODE_DBG("FW%d: Type %d "
				"RPtr %d SBSt %d BySt %d HdSt %d Last %d CorC %d"
				"\n", index, node->type, fwdn->result_pointer,
				fwdn->search_byte_store, fwdn->byte_store,
				fwdn->header_length_store, fwdn->last_node,
				fwdn->extension);
		for (i = 0; i < dn->num; i++) {
			struct apm_ptree_branch *branch = &fwdn->branch[i];
			struct ptree_branch *pbranch = &dn->branch[i];
			branch->valid = pbranch->valid & DN_VALID_SIZE;
			branch->mask = pbranch->mask & DN_MASK_SIZE;
			branch->data = pbranch->data & DN_MASK_SIZE;
			branch->operation = pbranch->operation & DN_OP_SIZE;
			branch->next_node_branch =
				((pbranch->next_node_index & DN_NN_SIZE) |
				((pbranch->next_node_loc & 0x1F) << 7)) & DN_NNP_SIZE;
			branch->jump_rel =
				pbranch->jump_rel & DN_JREL_SIZE;
			branch->jump_bw =
				pbranch->jump_bw & DN_JBW_SIZE;
			CLE_NODE_DBG("  %d: VBit %d Mask %04x Data %04x OTyp %d "
					"%s %3d%s,%d JRel %d JBkw %d NPOf %d\n",
					i, branch->valid, branch->mask, branch->data,
					branch->operation,
					(fwdn->last_node ? "KNIn" : "NNBr"),
					pbranch->next_node_index,
					((pbranch->next_node_loc & !fwdn->last_node) ? ".1" : ""),
					(pbranch->next_node_loc >> !fwdn->last_node),
					branch->jump_rel, branch->jump_bw,
					pbranch->next_packet_pointer);
#ifdef CARBON_MODEL
			branch->next_packet_pointer =
				(pbranch->next_packet_pointer +
					((!branch->jump_rel) * 4)) & DN_NBP_SIZE;
#else
			branch->next_packet_pointer =
				pbranch->next_packet_pointer & DN_NBP_SIZE;
#endif
		}
		break;
#endif

	case KN:
		if (set_type)
			node->type = set_type & DN_TYPE_SIZE;
		kn = (struct ptree_kn *)pnode->data;
#ifdef CONFIG_APM862xx
		apkn = &node->entry.kn[KEYNODE_INDEX - index];
#else
		apkn = &node->entry.kn[index];
#endif
		apkn->priority = kn->priority & KN_PRI_SIZE;
		apkn->result_pointer = kn->result_pointer & KN_PTR_SIZE;

		CLE_NODE_DBG(" KN: Type %d\n", node->type);
		CLE_NODE_DBG(" %2d: Prio %d RPtr %d\n",
				index, apkn->priority, apkn->result_pointer);
		break;
	}
}

int apm_ptree_node_config(u8 port, struct ptree_node *node)
{
	int rc = APM_RC_OK;
	u32 data[LONG_PER_PTREE_NODE_STRUCT];
	u32 node_index = node->index;
	struct apm_preclass_state *pcs;
	struct apm_preclass_node_state *pns;
	u32 cid = PID2CID[port];

	pcs = &sys_preclass_state[cid];
	pns = &sys_preclass_state[cid].node_state[node_index];

	if (!apm_preclass_init_state[cid])
		apm_preclassify_init(cid);

	if (node->type == EWDN) { /* 8-way node */
		memset(data, 0, sizeof(data));

		/* check if this is the first config for this entry */
		if (!pns->type) {
			/* config + set type in hw */
			apm_ptree_set_data(data, node, EIGHT_WAY_NODE);
			/* set type */
			pns->type = EWDN;
			/* set location mask */
			pns->config_mask = 1;

			pcs->ewdn_count++;
		/* check if its the same type of node */
		} else if (pns->type == node->type) {
			/* check if the entry is already configured */
			if (pns->config_mask) {
				/* prompt for reconfig */
				PCLS_PRNT("8 way node entry %d reconfig "
					"detected !!\n", node_index);
			} else {
				/* set location mask */
				pns->config_mask = 1;
			}
			/* always write everything */
			apm_ptree_set_data(data, node, EIGHT_WAY_NODE);
		/* This is a reconfig of a different type
		   (can allow for EWDN only) */
		} else {
			/* prompt for new type config */
			PCLS_PRNT("Node entry %d reconfig with new "
				"type detected !!\n", node_index);
			apm_ptree_set_data(data, node, EIGHT_WAY_NODE);

			if (pns->type == KN)
				pcs->kn_count--;
#ifdef CONFIG_APM862xx
			else
				pcs->fwdn_count--;
#endif

			/* set type */
			pns->type = EWDN;
			/* set location mask */
			pns->config_mask = 1;

			pcs->ewdn_count++;
		}

#ifdef CONFIG_APM862xx
	} else if (node->type == FWDN) { /* 4-way node */
		/* set specific fields of data array from node */
		/* based upon location, update the corresponding data
		   array check if this is the first config for this
		   entry */
		if (!pns->type) {

			PCLS_DBG("node type[%d], location[%d] \n",
				node->type, node->location);

			memset(data, 0, sizeof(data));

			/* config + set type in hw */
			if (node->location)
				apm_ptree_set_data(data, node,
					FOUR_WAY_NODE2_ONLY);
			else
				apm_ptree_set_data(data, node,
					FOUR_WAY_NODE1_ONLY);
			/* set type */
			pns->type = FWDN;
			/* set location mask */
			pns->config_mask |= 1 << node->location;

			pcs->fwdn_count++;

		/* check if its the same type of node */
		} else if (pns->type == node->type) {

			PCLS_DBG("node type[%d], location[%d] \n",
				node->type, node->location);

			/* needs read modify write */
			rc = apm_get_ptree_node(port, node_index,
				(struct apm_ptree_node *)data);

			/* check if the entry is already configured */
			if ((pns->config_mask >> node->location) & 1) {

				/* prompt for reconfig */
				PCLS_PRNT("4 way decision node "
					"entry %d location %d reconfig "
					"detected !!\n",
					node_index,node->location);
				/* config with no node type update */
				apm_ptree_set_data(data,node,0);
			} else {
				/* set location mask */
				pns->config_mask |= 1 << node->location;

				PCLS_DBG("node type[%d], location[%d] \n",
					node->type, node->location);

				/* config with node type update */
				apm_ptree_set_data(data, node,
					FOUR_WAY_NODE_BOTH);
					pcs->fwdn_count++;
			}
		}
#endif

	} else { /* Key node */
		/* check if this is the first config for this entry */
		if (!pns->type) {
			memset(data, 0, sizeof(data));
			/* config + set type in hw */
			apm_ptree_set_data(data,node,KEY_NODE);
			/* set type */
			pns->type = KN;
			/* set location mask */
			pns->config_mask |= 1 << node->location;

			pcs->kn_count++;
		} else if (pns->type == node->type) {
			/* check if its the same type of node */
			/* check if the entry is already configured */
			if ((pns->config_mask >> node->location) & 1) {
				/* prompt for reconfig */
				PCLS_PRNT("Key node entry %d "
					"location %d reconfig detected !!\n",
					node_index, node->location);
			} else {
				/* set location mask */
				pns->config_mask |= 1 << node->location;
			}

			/* needs read modify write */
			rc = apm_get_ptree_node(port, node_index,
				(struct apm_ptree_node *)data);

			/* config */
			apm_ptree_set_data(data,node,0);

			pcs->kn_count++;
		}
	}

	rc |= apm_set_ptree_node(port, node_index,
			(struct apm_ptree_node *)data);

	return rc;
}

static void apm_set_ptree_node_branch_from_pbranch(struct apm_ptree_branch *branch,
		struct ptree_branch *pbranch, u32 set_branch_field)
{
	if (set_branch_field & SET_BRANCH_VALID)
		branch->valid = pbranch->valid & DN_VALID_SIZE;
	if (set_branch_field & SET_BRANCH_MASK)
		branch->mask = pbranch->mask & DN_MASK_SIZE;
	if (set_branch_field & SET_BRANCH_DATA)
		branch->data = pbranch->data & DN_MASK_SIZE;
	if (set_branch_field & SET_BRANCH_OPERATION)
		branch->operation = pbranch->operation & DN_OP_SIZE;
	if (set_branch_field & SET_BRANCH_NNBR)
		branch->next_node_branch =
			((pbranch->next_node_index & DN_NN_SIZE) |
			((pbranch->next_node_loc & 0x1F) << 7)) & DN_NNP_SIZE;
	if (set_branch_field & SET_BRANCH_JUMP_REL)
		branch->jump_rel = pbranch->jump_rel & DN_JREL_SIZE;
	if (set_branch_field & SET_BRANCH_JUMP_BW)
		branch->jump_bw = pbranch->jump_bw & DN_JBW_SIZE;
#ifdef CARBON_MODEL
	if (set_branch_field & SET_BRANCH_NPPTR)
		branch->next_packet_pointer =
			pbranch->next_packet_pointer ?
			(pbranch->next_packet_pointer + 4) & DN_NBP_SIZE : 0;
#else
	if (set_branch_field & SET_BRANCH_NPPTR)
		branch->next_packet_pointer =
			pbranch->next_packet_pointer & DN_NBP_SIZE;
#endif
}

int apm_set_ptree_node_branch(u8 port, u8 node_index,
			u8 sub_node, u8 branch_index,
			struct ptree_branch *pbranch,
			u32 set_branch_field)
{
	int rc = APM_RC_INVALID_PARM;
	struct apm_preclass_node_state *pns;
	struct apm_ptree_node node;
	struct apm_ptree_branch *branch;

	pns = &sys_preclass_state[PID2CID[port]].node_state[node_index];

	switch (pns->type) {
	case EWDN:
		if (branch_index < 8) {
			rc = apm_get_ptree_node(port, node_index, &node);
			branch = &node.entry.ewdn.branch[branch_index];
			apm_set_ptree_node_branch_from_pbranch(branch, pbranch, set_branch_field);
			CLE_PTREE_DUMP(&node);
			rc |= apm_set_ptree_node(port, node_index, &node);
		} else {
			PCLS_PRNT("Invalid branch number for EWDN\n");
		}
		break;

#ifdef CONFIG_APM862xx
	case FWDN:
		if (sub_node < 2 && branch_index < 4) {
			rc = apm_get_ptree_node(port, node_index, &node);
			branch = &node.entry.fwdn[sub_node].branch[branch_index];
			apm_set_ptree_node_branch_from_pbranch(branch, pbranch, set_branch_field);
			CLE_PTREE_DUMP(&node);
			rc |= apm_set_ptree_node(port, node_index, &node);
		} else {
			PCLS_PRNT("Invalid sub_node or branch number for FWDN\n");
		}
		break;
#endif

	case KN:
		PCLS_PRNT("Entry [%d] is a key node, cannot "
				"configure a branch \n", node_index);
		break;

	default:
		PCLS_PRNT("Node type unknown for entry [%d], "
			"configure it first \n", node_index);
	}

	return rc;
}

int apm_clear_ptree_node_type(u8 port, u8 node_index)
{
	int rc;
	struct apm_ptree_node node;

#ifdef CLE_DEBUG
	if (port > MAX_CLE_PORTS) {
		PCLS_DBG("Invalid port number \n");
		return APM_RC_INVALID_PARM;
	}
#endif
	/* read node */
	rc = apm_get_ptree_node(port, node_index, &node);
	/* clear node type in node */
	node.type = 0;
	/* write back */
	rc |= apm_set_ptree_node(port, node_index, &node);
	/* update state */
	sys_preclass_state[PID2CID[port]].node_state[node_index].type = 0;
	return rc;
}

int apm_get_preclass_state(u8 port, struct apm_preclass_state *preclass_state)
{
	int rc = APM_RC_OK;

#ifdef CLE_DEBUG
	if (preclass_state == NULL) {
		PCLS_DBG("Null preclass_state pointer \n");
		return APM_RC_INVALID_PARM;
	}
	if (port > MAX_CLE_PORTS) {
		PCLS_DBG("Invalid port number \n");
		return APM_RC_INVALID_PARM;
	}
#endif
	memcpy(preclass_state, &sys_preclass_state[PID2CID[port]],
		sizeof(struct apm_preclass_state));
	return rc;
}

int apm_set_sys_ptree_config(u8 port,
			struct apm_ptree_config *ptree_config)
{
	int rc = APM_RC_OK;
	u32 data;
	u32 snptr_addr = 0;
	u32 spptr_addr = 0;
	u32 dbptr_addr = 0;
	u32 parser_ctl_addr = 0;
	u32 maxhop_addr = 0;
	u32 cid = PID2CID[port];

	switch (PORTIDX[port]) {
	case CLE_INLINE_PORT0:
		snptr_addr = SNPTR0_ADDR;
		spptr_addr = SPPTR0_ADDR;
		dbptr_addr = DFCLSRESDBPTR0_ADDR;
		parser_ctl_addr = PARSER_CTL0_ADDR;
		maxhop_addr = TMAXHOP0_ADDR;
		break;
	case CLE_INLINE_PORT1:
		snptr_addr = SNPTR1_ADDR;
		spptr_addr = SPPTR1_ADDR;
		dbptr_addr = DFCLSRESDBPTR1_ADDR;
		parser_ctl_addr = PARSER_CTL1_ADDR;
		maxhop_addr = TMAXHOP1_ADDR;
		break;
	case CLE_LAC_PORT:
		snptr_addr = SNPTR2_ADDR;
		spptr_addr = SPPTR2_ADDR;
		dbptr_addr = DFCLSRESDBPTR2_ADDR;
		parser_ctl_addr = PARSER_CTL2_ADDR;
		maxhop_addr = TMAXHOP2_ADDR;
		break;
	default:
		PCLS_ERR("Invalid port number %d\n", port);
		return APM_RC_INVALID_PARM;
	}

	if (!apm_preclass_init_state[cid])
		apm_preclassify_init(cid);

	if (ptree_config != NULL) {
		/* update default config */
		ptree_config->start_engine &= PARSER_HALT0_MASK;
		memcpy(&sys_ptree_config[port], ptree_config,
			sizeof(struct apm_ptree_config));
	}

	PCLS_PRNT("Configuring start node ptr [%d] "
		"start packet ptr [%d] max hop [%d] "
		"start engine %d for port %d\n",
		sys_ptree_config[port].start_node_ptr,
		sys_ptree_config[port].start_pkt_ptr,
		sys_ptree_config[port].max_hop,
		sys_ptree_config[port].start_engine, port);

	/* snptr */
	data = SNPTR0_WR(sys_ptree_config[port].start_node_ptr);
	rc = apm_gbl_cle_wr32(cid, snptr_addr, data);

	/* spptr */
	data = SPPTR0_WR(sys_ptree_config[port].start_pkt_ptr);
#ifdef CARBON_MODEL  /* FIXME */
	data = data + 4;
#endif
	rc |= apm_gbl_cle_wr32(cid, spptr_addr, data);

	/* Assign Default Classification DB Ptr */
	data = (DFCLSRESDBPRIORITY0_MASK &
		sys_ptree_config[port].default_result) |
		(DFCLSRESDBPTR0_MASK &
		sys_ptree_config[port].default_result);
	rc |= apm_gbl_cle_wr32(cid, dbptr_addr, data);
	PCLS_PRNT("Assign Default Classification Priority %d DB Ptr %d\n",
		DFCLSRESDBPRIORITY0_RD(data), DFCLSRESDBPTR0_RD(data));

	/* set engine state */
	if (sys_preclass_state[cid].start_engine[PORTIDX[port]] !=
			sys_ptree_config[port].start_engine) {
		rc |= apm_gbl_cle_rd32(cid, parser_ctl_addr, &data);
		data = PARSER_HALT0_SET(data, sys_ptree_config[port].start_engine);
		rc |= apm_gbl_cle_wr32(cid, parser_ctl_addr, data);
		sys_preclass_state[cid].start_engine[PORTIDX[port]] =
			sys_ptree_config[port].start_engine;
	}

	/* Tree Max Hops */
	data = TMAXHOP0_WR(sys_ptree_config[port].max_hop);
	rc |= apm_gbl_cle_wr32(cid, maxhop_addr, data);

	return rc;
}

int apm_get_sys_ptree_config(u8 port,
				struct apm_ptree_config *ptree_config)
{
	int rc = APM_RC_OK;

#ifdef CLE_DEBUG
	if (port > MAX_CLE_PORTS) {
		PCLS_DBG("Invalid port number \n");
		return APM_RC_INVALID_PARM;
	}
	if (ptree_config  == NULL) {
		PCLS_DBG("Null ptree_config pointer \n");
		return APM_RC_INVALID_PARM;
	}
#endif
	memcpy(ptree_config, &sys_ptree_config[port],
	       sizeof(struct apm_ptree_config));
	return rc;
}

int apm_preclass_start_stop(u8 port, u32 state)
{
	int rc = APM_RC_OK;
	u32 data;
	u32 parser_ctl_addr = 0;
	u32 cid = PID2CID[port];

	switch (PORTIDX[port]) {
	case CLE_INLINE_PORT0:
		parser_ctl_addr = PARSER_CTL0_ADDR;
		break;
	case CLE_INLINE_PORT1:
		parser_ctl_addr = PARSER_CTL1_ADDR;
		break;
	case CLE_LAC_PORT:
		parser_ctl_addr = PARSER_CTL2_ADDR;
		break;
	default:
		PCLS_ERR("Invalid port number %d\n", port);
		return APM_RC_INVALID_PARM;
	}

	if (!apm_preclass_init_state[cid])
		apm_preclassify_init(cid);

	/* set engine state */
	if (sys_preclass_state[cid].start_engine[PORTIDX[port]] !=
			PARSER_HALT0_WR(state)) {
		rc |= apm_gbl_cle_rd32(cid, parser_ctl_addr, &data);
		data = PARSER_HALT0_SET(data, state);
		rc |= apm_gbl_cle_wr32(cid, parser_ctl_addr, data);
		sys_preclass_state[cid].start_engine[PORTIDX[port]] =
			PARSER_HALT0_WR(state);
	}

	PCLS_DBG("%s preclassification engine for port %d \n",
		(state ? "Starting" : "Stopping"), port);

	return rc;
}

int apm_get_preclass_trace(u8 port, struct apm_preclass_trace *preclass_trace)
{
	int i, rc = APM_RC_OK;
	u32 data = 0;
	u32 cid = PID2CID[port];

	switch (PORTIDX[port]) {
	case CLE_INLINE_PORT0:
		rc |= apm_gbl_cle_rd32(cid, LSTNVST0_ADDR, &data);
		preclass_trace->last_node_visited = LSTNVST0_RD(data);

		for (i = 0; i< MAX_LAST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32(cid, LSTTRCNVST0_0_ADDR + (i<<2),
					&data);
			preclass_trace->last_visited_node_trace[i] =
							LTRCNVST0_RD(data);
		}
		for (i = 0; i< MAX_FIRST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32(cid, FTRCNVST0_0_ADDR + (i<<2),
					&data);
			preclass_trace->first_visited_node_trace[i] =
							FTRCNVST0_RD(data);
		}
		break;

	case CLE_INLINE_PORT1:

		rc |= apm_gbl_cle_rd32(cid, LSTNVST1_ADDR, &data);
		preclass_trace->last_node_visited = LSTNVST1_RD(data);

		for (i = 0; i< MAX_LAST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32(cid, LSTTRCNVST1_0_ADDR + (i<<2),
					&data);
			preclass_trace->last_visited_node_trace[i] =
							LTRCNVST1_RD(data);
		}
		for (i = 0; i< MAX_FIRST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32(cid, FTRCNVST1_0_ADDR + (i<<2),
					&data);
			preclass_trace->first_visited_node_trace[i] =
							FTRCNVST1_RD(data);
		}
		break;

	case CLE_LAC_PORT:
		rc |= apm_gbl_cle_rd32(cid, LSTNVST2_ADDR, &data);
		preclass_trace->last_node_visited = LSTNVST2_RD(data);

		for (i = 0; i< MAX_LAST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32 (cid, LSTTRCNVST2_0_ADDR + (i<<2),
					       &data);
			preclass_trace->last_visited_node_trace[i] =
							LTRCNVST2_RD(data);
		}
		for (i = 0; i< MAX_FIRST_NODES_TRACE; i++) {
			rc |= apm_gbl_cle_rd32 (cid, FTRCNVST2_0_ADDR + (i<<2),
					       &data);
			preclass_trace->first_visited_node_trace[i] =
							FTRCNVST2_RD(data);
		}
		break;

	default:
		break;
	}
	return rc;
}

int apm_preclass_wol_mode(int enable)
{
	int rc;
	u32 snptr;
	rc = apm_gbl_cle_rd32(0, SNPTR0_ADDR, &snptr);
	snptr = WOL_MODE0_SET(snptr, enable);
	rc |= apm_gbl_cle_wr32(0, SNPTR0_ADDR, snptr);
	return rc;
}
