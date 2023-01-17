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

#ifndef __XGENE_ENET_SC_RING_H__
#define __XGENE_ENET_SC_RING_H__

#include "xgene_enet_main.h"

struct xgene_enet_pdata;

#define CSR_VMID0_INTR_MBOX	0x270

/* FIXME: tmp defines */
#define CSR_QM_CONFIG		0x0004
#define CSR_QM_CLKRST		0xc208
#define CSR_QM_SRST		0xc200
#define CSR_QM_GLOBAL_DIAG	0xd000
#define CSR_QM_MEM_RAM_SHUTDOWN	0xd070
#define CSR_QM_MEM_RDY		0xd074
#define CSR_PBM_COAL		0x0014
#define CSR_CTICK0		0x0018
#define CSR_CTICK1		0x001c
#define CSR_CTICK2		0x0020
#define CSR_CTICK3		0x0024
#define CSR_THRESHOLD0_SET0	0x0028
#define CSR_THRESHOLD1_SET0	0x002c
#define CSR_THRESHOLD0_SET1	0x0030
#define CSR_THRESHOLD1_SET1	0x0034
#define CSR_THRESHOLD0_SET2	0x0038
#define CSR_THRESHOLD1_SET2	0x003c
#define CSR_THRESHOLD0_SET3	0x0040
#define CSR_THRESHOLD1_SET3	0x0044
#define CSR_THRESHOLD0_SET4	0x0048
#define CSR_THRESHOLD1_SET4	0x004c
#define CSR_THRESHOLD0_SET5	0x0050
#define CSR_THRESHOLD1_SET5	0x0054
#define CSR_THRESHOLD0_SET6	0x0058
#define CSR_THRESHOLD1_SET6	0x005c
#define CSR_THRESHOLD0_SET7	0x0060
#define CSR_THRESHOLD1_SET7	0x0064
#define CSR_HYSTERESIS		0x0068

#define QM_ENABLE		BIT(31)
#define SC_CSR_RING_RD_BASE	0x00000088

#define INTR_MBOX_SIZE		1024
#define INTR_CLEAR		BIT(23)
#define FIRST_DEQ_IRQ		128

/* Ring configuration fields */
#define MSG_AM_POS		10
#define MSG_AM_LEN		1
#define QBASE_AM_POS		11
#define QBASE_AM_LEN		1
#define INTLINE_POS		24
#define INTLINE_LEN		5
#define SC_NUMMSGINQ_POS	0
#define SC_NUMMSGINQ_LEN	17
#define SLOTS_PENDING_POS	9
#define SLOTS_PENDING_LEN	8
#define CFGCRID_POS		29
#define CFGCRID_LEN		3
#define SC_SELTHRSH_POS		7
#define SC_SELTHRSH_LEN		3
#define SC_RINGTYPE_POS		23
#define SC_RINGTYPE_LEN		2
#define DEQINTEN_POS		29
#define DEQINTEN_LEN		1
#define RECOMTIMEOUT_POS	0
#define RECOMTIMEOUT_LEN	7

/* descriptor fields */
#define AM_POS				54
#define AM_LEN				1
;

int xgene_qmtm_enable(struct xgene_enet_pdata *pdata);

extern struct xgene_ring_ops xgene_sc_ring_ops;

#endif /* __XGENE_ENET_SC_RING_H__ */
