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
/*  mv_neta.h */

#ifndef LINUX_MV_NETA_H
#define LINUX_MV_NETA_H

#define MV_NETA_PORT_NAME	"mv_neta_port"
struct mv_neta_pdata {
	/* Global parameters common for all ports */
	unsigned int  tclk;
	unsigned int  pclk;
	int           max_port;
	int           max_cpu;
	unsigned int  ctrl_model;
	unsigned int  ctrl_rev;

	/* Per port parameters */
	unsigned int  cpu_mask;
	int           mtu;

	/* Whether a PHY is present, and if yes, at which address. */
	int      phy_addr;

	/* Maximum packet size for L4 checksum generation */
	int      tx_csum_limit;

	/* Use this MAC address if it is valid */
	u8       mac_addr[6];

	/*
	* If speed is 0, autonegotiation is enabled.
	*   Valid values for speed: 0, SPEED_10, SPEED_100, SPEED_1000.
	*   Valid values for duplex: DUPLEX_HALF, DUPLEX_FULL.
	*/
	int      speed;
	int      duplex;

	/* Port configuration: indicates if this port is LB, and if PCS block is active */
	int     lb_enable;
	int     is_sgmii;
	int     is_rgmii;

	/* port interrupt line number */
	int     irq;

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
	/* PNC TCAM size*/
#ifdef CONFIG_MV_ETH_PNC
	unsigned int pnc_tcam_size;
#endif
};


#endif  /* LINUX_MV_NETA_H */
