/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or on the worldwide web
at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.
*******************************************************************************/
/*  mv_switch.h */

#ifndef LINUX_MV_SWITCH_H
#define LINUX_MV_SWITCH_H

#define MV_SWITCH_SOHO_NAME	"mv_soho_switch"

struct mv_switch_pdata {
	int			index;
	int			phy_addr;
	int			gbe_port;
	int			switch_cpu_port;
	unsigned int		tag_mode;
	unsigned int		preset;
	int			vid;
	unsigned int		port_mask;
	unsigned int		connected_port_mask;
	unsigned int		forced_link_port_mask;
	unsigned int		mtu;
	unsigned int		smi_scan_mode;
	int			qsgmii_module;
	int			gephy_on_port;
	int			rgmiia_on_port;
	int			switch_irq;
	int			is_speed_2000;
	int			rgmii_rx_timing_delay;
	int			rgmii_tx_timing_delay;
};



#endif  /* LINUX_MV_SWITCH_H */
