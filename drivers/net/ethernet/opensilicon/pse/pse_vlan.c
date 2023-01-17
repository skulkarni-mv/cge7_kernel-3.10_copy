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

#include "pse.h"
#include "pse_vlan.h"
#include "pse_common.h"

#define VALID_OFFSET		(31)
#define WAN_SIDE_OFFSET		(30)
#define VID_OFFSET		(16)
#define PMAP_OFFSET		(0)

/* pse_vlan_to_ctrl_reg - transfer struct _pse_vlan to VLAN control register
 * @vlan: pointer to PSE VLAN structure
 */
static void pse_vlan_to_ctrl_reg(struct pse_vlan *vlan)
{
	u32 val;

	val = ((vlan->valid & 0x1) << VALID_OFFSET)
		| ((vlan->wan & 0x1) << WAN_SIDE_OFFSET)
		| ((vlan->vid & 0xFFF) << VID_OFFSET)
		| ((vlan->pmap & 0x1F) << PMAP_OFFSET);

	wr32(val, VLAN_CTRL);
}

/* pse_vlan_from_ctrl_reg - transfer VLAN control register to struct _pse_vlan
 * @vlan: pointer to PSE VLAN structure
 */
static void pse_vlan_from_ctrl_reg(struct pse_vlan *vlan)
{
	u32 val;

	val = rd32(VLAN_CTRL);

	vlan->valid = (val >> VALID_OFFSET);
	vlan->wan = (0x1 & (val >> WAN_SIDE_OFFSET));
	vlan->vid = (0xFFF & (val >> VID_OFFSET));
	vlan->pmap = (0x1F & (val >> PMAP_OFFSET));
}

#define MASK_VLAN_LOOKUP_MATCH	(0x1 << 10)
#define MASK_VLAN_CMD_COMPLETE	(0x1 << 9)
#define MASK_VLAN_LOOKUP_CMD	(0x1 << 8)
#define MASK_VLAN_READ_CMD	(0x1 << 7)
#define MASK_VLAN_WRITE_CMD	(0x1 << 6)


/* pse_vlan_read - read VLAN entry
 * @vlan: pointer to vlan structure
 * @index: index of VLAN entry
 */
int pse_vlan_read(struct pse_vlan *vlan, u32 index)
{
	u32 val;

	/* sainty check */
	if (index >= PSE_VLAN_MAX)
		return PSE_FAIL;

	val = index | MASK_VLAN_READ_CMD;

	wr32(val, VLAN_CMD);

	/* wait for command complete */
	while (!(val & MASK_VLAN_CMD_COMPLETE))
		val = rd32(VLAN_CMD);

	pse_vlan_from_ctrl_reg(vlan);

	return PSE_OK;
}

/* pse_vlan_write - write VLAN entry
 * @vlan: pointer to vlan structure
 * @index: index of VLAN entry
 */
int pse_vlan_write(struct pse_vlan *vlan, u32 index)
{
	u32 val;

	/* sainty check */
	if (index >= PSE_VLAN_MAX)
		return PSE_FAIL;

	pse_vlan_to_ctrl_reg(vlan);

	/* issue command */
	val = index | MASK_VLAN_WRITE_CMD;
	wr32(val, VLAN_CMD);

	/* wait for command complete */
	while (!(val & MASK_VLAN_CMD_COMPLETE))
		val = rd32(VLAN_CMD);

	return PSE_OK;
}

/* pse_vlan_lookup -
 * @vlan
 * @vid: VLAN ID
 * return  : index
 */
int pse_vlan_lookup(struct pse_vlan *vlan, u16 vid)
{
	u32 val;

	/* just fill VLAN ID */
	memset(vlan, 0, sizeof(struct pse_vlan));
	vlan->vid = (vid & 0xFFF);

	pse_vlan_to_ctrl_reg(vlan);

	/* issue command */
	val = MASK_VLAN_LOOKUP_CMD;
	wr32(val, VLAN_CMD);

	/* wait for command complete */
	while (!(val & MASK_VLAN_CMD_COMPLETE))
		val = rd32(VLAN_CMD);

	/* if found, update to struct _pse_vlan */
	if (val & MASK_VLAN_LOOKUP_MATCH) {
		pse_vlan_from_ctrl_reg(vlan);
		return val&0x3F;
	}

	/* not found */
	return PSE_FAIL;
}


/**
 * pse_vlan_reset - clear all VLAN configuration
 **/
void pse_vlan_reset(void)
{
	int i;
	struct pse_vlan vlan;

	memset(&vlan, 0, sizeof(struct pse_vlan));

	for (i = 0; i < PSE_VLAN_MAX; i++)
		pse_vlan_write(&vlan, i);

}

#define STAG_ETYPE_OFFSET	(16)
#define WPMAP_OFFSET		(8)
#define S_NEIGHBOR_CPU_OFFSET	(6)
#define S_NEIGHBOR_MAC1_OFFSET	(5)
#define S_NEIGHBOR_MAC0_OFFSET	(4)
#define S_COMPONENT_OFFSET	(1)

void pse_stag_etype_cfg(u16 etype)
{
	u32 val;

	val = rd32(VLAN_CFG);
	val &= ~(0xffff << STAG_ETYPE_OFFSET);
	val |= etype << STAG_ETYPE_OFFSET;
	wr32(val, VLAN_CFG);
}

void pse_wan_port_mac0_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x1 << WPMAP_OFFSET);
	else
		val &= ~(0x1 << WPMAP_OFFSET);

	wr32(val, VLAN_CFG);
}

void pse_wan_port_mac1_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x2 << WPMAP_OFFSET);
	else
		val &= ~(0x2 << WPMAP_OFFSET);

	wr32(val, VLAN_CFG);

}

void pse_wan_port_cpu_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x4 << WPMAP_OFFSET);
	else
		val &= ~(0x4 << WPMAP_OFFSET);

	wr32(val, VLAN_CFG);
}


void pse_s_neighbor_cpu_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x1 << S_NEIGHBOR_CPU_OFFSET);
	else
		val &= ~(0x1 << S_NEIGHBOR_CPU_OFFSET);

	wr32(val, VLAN_CFG);
}

void pse_s_neighbor_mac1_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x1 << S_NEIGHBOR_MAC1_OFFSET);
	else
		val &= ~(0x1 << S_NEIGHBOR_MAC1_OFFSET);

	wr32(val, VLAN_CFG);
}

void pse_s_neighbor_mac0_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x1 << S_NEIGHBOR_MAC0_OFFSET);
	else
		val &= ~(0x1 << S_NEIGHBOR_MAC0_OFFSET);

	wr32(val, VLAN_CFG);
}

void pse_s_component_cfg(bool en)
{
	u32 val;

	val = rd32(VLAN_CFG);
	if (en)
		val |= (0x1 << S_COMPONENT_OFFSET);
	else
		val &= ~(0x1 << S_COMPONENT_OFFSET);

	wr32(val, VLAN_CFG);
}


int pse_vlan_get_free_index(void)
{
	int i;
	struct pse_vlan vlan;

	memset(&vlan, 0, sizeof(struct pse_vlan));

	for (i = 0; i < PSE_VLAN_MAX; i++) {
		pse_vlan_read(&vlan, i);
		if (!vlan.valid)
			break;
	}

	if (i == PSE_VLAN_MAX)
		return PSE_FAIL;
	else
		return i;
}

int pse_add_vlan(struct pse_priv *priv, u16 vid)
{
	int index;
	struct pse_vlan vlan;
	/* search if the vid already in the table */
	index = pse_vlan_lookup(&vlan, vid);
	if (index == PSE_FAIL) {
		/* not found */
		index = pse_vlan_get_free_index();
		if (index == PSE_FAIL) {
			/* no free table */
			return PSE_FAIL;
		}
	}

	vlan.valid = 1;
	vlan.vid = vid;

	switch (priv->sp) {
	case OPV5XC_PSE_PORT_MAC0:
		vlan.pmap |= OPV5XC_PSE_PMAP_MAC0;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		vlan.pmap |= OPV5XC_PSE_PMAP_MAC1;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		vlan.pmap |= OPV5XC_PSE_PMAP_MAC2;
		break;
	default:
		/* TODO warning message */
		return PSE_FAIL;
	}

	vlan.pmap |= OPV5XC_PSE_PMAP_CPU;
	pse_vlan_write(&vlan, index);

	return PSE_OK;
}


int pse_del_vlan(struct pse_priv *priv, u16 vid)
{
	int index;
	struct pse_vlan vlan;

	index = pse_vlan_lookup(&vlan, vid);

	if (index == PSE_FAIL) {
		/* not found */
		return PSE_FAIL;
	}
	/* found */
	vlan.pmap &= ~(1 << priv->sp);

	if (OPV5XC_PSE_PORT_CPU == (vlan.pmap & PSE_VLAN_PMAP_ALL))
		memset(&vlan, 0, sizeof(struct pse_vlan));

	pse_vlan_write(&vlan, index);
	return PSE_OK;
}


bool pse_vlan_used(struct pse_priv *priv)
{
	u16 vid;

	for_each_set_bit(vid, priv->active_vlans, VLAN_N_VID)
		return true;
	return false;
}

int pse_vlan_ingress_check(u8 port, bool en)
{
#define PSE_VLAN_INGRESS_CHECK_MASK (0x1 << 24)
	u32 val, offset;

	switch (port) {
	case OPV5XC_PSE_PORT_MAC0:
		offset = MAC0_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC1:
		offset = MAC1_CFG;
		break;
	case OPV5XC_PSE_PORT_MAC2:
		offset = MAC2_CFG;
		break;
	default:
		return PSE_FAIL;
	}

	val = rd32(offset);
	if (en)
		val |= PSE_VLAN_INGRESS_CHECK_MASK;
	else
		val &= ~PSE_VLAN_INGRESS_CHECK_MASK;
	wr32(val, offset);
	return PSE_OK;
}

int pse_vlan_unknown_to_cpu(u8 port, bool en)
{
	u32 val, mask;

	val = rd32(MAC_GLOB_CFG);

#if defined(CONFIG_OPV5XC_PSE_ES1)
	if (OPV5XC_PSE_PORT_MAC0 == port)
		mask = (0x1 << 25);
	else
		mask = (0x1 << 26);
#else
	mask = (0x1 << 25);
#endif

	if (en)
		val |= mask;
	else
		val &= ~mask;

	wr32(val, MAC_GLOB_CFG);
	return PSE_OK;
}

void pse_vlan_filter_on_off(struct pse_priv *priv, bool filter_on)
{
	if (filter_on) { /* enable VLAN receive filtering */
		/* disable unknown vlan to cpu */
		pse_vlan_unknown_to_cpu(priv->sp, false);
		/* enable VLAN ingress check */
		pse_vlan_ingress_check(priv->sp, true);
	} else { /* disable VLAN receive filtering */
		/* enable unknown vlan to cpu */
		pse_vlan_unknown_to_cpu(priv->sp, true);
		/* disable VLAN ingress check */
		pse_vlan_ingress_check(priv->sp, false);
	}
}
