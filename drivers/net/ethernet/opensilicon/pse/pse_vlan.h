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

#ifndef _PSE_VLAN_H_
#define _PSE_VLAN_H_


#define PSE_VLAN_PMAP_ALL \
	(OPV5XC_PSE_PORT_CPU | OPV5XC_PSE_PMAP_MAC0 \
		| OPV5XC_PSE_PMAP_MAC1 | OPV5XC_PSE_PMAP_MAC2)

struct pse_vlan {
	u32 pmap:5;
	u32:11;
	u32 vid:12;
	u32:2;
	u32 wan:1;
	u32 valid:1;
};

void pse_vlan_reset(void);
int pse_vlan_lookup(struct pse_vlan *vlan, u16 vid);
int pse_vlan_write(struct pse_vlan *vlan, u32 index);
int pse_vlan_read(struct pse_vlan *vlan, u32 index);
int pse_vlan_get_free_index(void);
void pse_stag_etype_cfg(u16 etype);
void pse_wan_port_mac0_cfg(bool en);
void pse_wan_port_mac1_cfg(bool en);
void pse_wan_port_cpu_cfg(bool en);
void pse_s_neighbor_cpu_cfg(bool en);
void pse_s_neighbor_mac1_cfg(bool en);
void pse_s_neighbor_mac0_cfg(bool en);
void pse_s_component_cfg(bool en);

#define PSE_VLAN_MAX	(64)

#endif /* _PSE_VLAN_H_ */
