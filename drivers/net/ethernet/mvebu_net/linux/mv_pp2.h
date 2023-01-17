/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.

*******************************************************************************/
/*  mv_pp2.h */

#ifndef LINUX_MV_PP2_H
#define LINUX_MV_PP2_H

#define MV_PP2_PORT_NAME	"mv_pp2_port"

/* valid values for flags */
#define MV_PP2_PDATA_F_SGMII		0x1 /* MAC connected to PHY via SGMII, PCS block is active */
#define MV_PP2_PDATA_F_RGMII		0x2 /* MAC connected to PHY via RGMII */
#define MV_PP2_PDATA_F_LB		0x4 /* This port is serve as LoopBack port */
#define MV_PP2_PDATA_F_LINUX_CONNECT	0x8 /* This port is connected to Linux */

struct mv_pp2_pdata {

	/* Global parameters common for all ports */
	unsigned int  tclk;
	int           max_port;

	/* Controller Model (Device ID) and Revision */
	unsigned int  ctrl_model;
	unsigned int  ctrl_rev;

	/* Per port parameters */
	unsigned int  cpu_mask;
	int           mtu;

	/* Whether a PHY is present, and if yes, at which address. */
	int      phy_addr;

	/* Use this MAC address if it is valid */
	u8       mac_addr[6];

	/*
	* If speed is 0, autonegotiation is enabled.
	*   Valid values for speed: 0, SPEED_10, SPEED_100, SPEED_1000.
	*   Valid values for duplex: DUPLEX_HALF, DUPLEX_FULL.
	*/
	int      speed;
	int      duplex;

	int	     is_sgmii;
	int	     is_rgmii;

	/* port interrupt line number */
	int		 irq;

	/*
	* How many RX/TX queues to use.
	*/
	int      rx_queue_count;
	int      tx_queue_count;

	/*
	* Override default RX/TX queue sizes if nonzero.
	*/
	int      rx_queue_size;
	int      tx_queue_size;

	unsigned int flags;
};


#endif  /* LINUX_MV_PP2_H */
