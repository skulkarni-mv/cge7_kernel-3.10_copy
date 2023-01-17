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

#ifndef __XGENE_ENET_HW_H__
#define __XGENE_ENET_HW_H__

#include "xgene_enet_main.h"

struct xgene_enet_pdata;

/* Constants for indirect registers */
#define MAC_ADDR_REG_OFFSET		0x0
#define MAC_COMMAND_REG_OFFSET		0x4
#define MAC_WRITE_REG_OFFSET		0x8
#define MAC_READ_REG_OFFSET		0xc	
#define MAC_COMMAND_DONE_REG_OFFSET	0x10

#define STAT_ADDR_REG_OFFSET		0x0
#define STAT_COMMAND_REG_OFFSET		0x4
#define STAT_WRITE_REG_OFFSET		0x8
#define STAT_READ_REG_OFFSET		0xc
#define STAT_COMMAND_DONE_REG_OFFSET	0x10

/* Address PE_MCXMAC  Registers */
#define MII_MGMT_CONFIG_ADDR		0x00000020
#define MII_MGMT_COMMAND_ADDR		0x00000024
#define MII_MGMT_ADDRESS_ADDR		0x00000028
#define MII_MGMT_CONTROL_ADDR		0x0000002c
#define MII_MGMT_STATUS_ADDR		0x00000030
#define MII_MGMT_INDICATORS_ADDR	0x00000034

#define CREATE_MASK(pos, len)		GENMASK(pos+len-1, pos)
#define CREATE_MASK_ULL(pos, len)	GENMASK_ULL(pos+len-1, pos)

//#define IS_FP(x) ((x & 0x0020) ? 1 : 0)

#define CSR_RING_ID		0x00000008
#define OVERWRITE		BIT(31)
#define IS_FREE_POOL		BIT(20)
#define BUF_EN			BIT(21)
#define CSR_RING_ID_BUF		0x0000000c
#define CSR_RING_NE_INT_MODE	0x0000017c
#define CSR_RING_CONFIG		0x0000006c
#define CSR_RING_WR_BASE	0x00000070
#define CSR_RING_RD_BASE	0x00000084
#define NUM_RING_CONFIG		6
#define BUFPOOL_MODE		3

//#define RING_BUFNUM(q)		(q->id & 0x003F)
//#define RING_OWNER(q)		((q->id & 0x03C0) >> 6)
#define BUF_LEN_CODE_2K		0x5000

#define HEAD_PTR_POS		17
#define HEAD_PTR_LEN		15
#define ACCEPTLERR_POS		19
#define ACCEPTLERR_LEN		1
#define QCOHERENT_POS		4
#define QCOHERENT_LEN		1
#define RINGADDRL_POS		5
#define RINGADDRL_LEN		27
#define RINGADDRH_POS		0
#define RINGADDRH_LEN		7
#define RINGSIZE_POS		23
#define RINGSIZE_LEN		3
#define RINGMODE_POS		20
#define RINGMODE_LEN		3
#define RECOMBBUF_POS		27
#define RECOMBBUF_LEN		1
#define NUMMSGINQ_POS		1
#define NUMMSGINQ_LEN		16

#define USERINFO_POS			0
#define USERINFO_LEN			32
#define FPQNUM_POS			32
#define FPQNUM_LEN			12
#define STASH_POS			52
#define STASH_LEN			2
#define BUFDATALEN_POS			48
#define BUFDATALEN_LEN			12
#define BUFLEN_POS			60
#define BUFLEN_LEN			3
#define DATAADDR_POS			0
#define DATAADDR_LEN			42
#define COHERENT_POS			63
#define COHERENT_LEN			1
#define LL_LSB_POS			48
#define LL_LSB_LEN			12
#define HENQNUM_POS			48
#define HENQNUM_LEN			12
#define TYPESEL_POS			44
#define TYPESEL_LEN			4
#define ETHHDR_POS			12
#define ETHHDR_LEN			8
#define IC_POS				35	/* Insert CRC */
#define IC_LEN				1
#define TCPHDR_POS			0
#define TCPHDR_LEN			6
#define IPHDR_POS			6
#define IPHDR_LEN			5
#define EC_POS				22	/* Enable checksum */
#define EC_LEN				1
#define ET_POS				23	/* Enable TSO */
#define ET_LEN				1
#define IS_POS				24	/* IP protocol select */
#define IS_LEN				1
#define ELERR_POS			46
#define ELERR_LEN			2
#define LERR_POS			60
#define LERR_LEN			3
#define NV_POS				50
#define NV_LEN				1
#define LL_POS				51
#define LL_LEN				1

#define SELTHRSH_POS		3
#define SELTHRSH_LEN		3
#define RINGTYPE_POS		19
#define RINGTYPE_LEN		2
#define RECOMTIMEOUTL_POS	28
#define RECOMTIMEOUTL_LEN	3
#define RECOMTIMEOUTH_POS	0
#define RECOMTIMEOUTH_LEN	2

#define TSO_BUF_POS		48
#define TSO_BUF_LEN		14
#define LL_INFO_POS		48
#define LL_INFO_LEN		16
#define LAST_BUFFER		(0x7800ULL << BUFDATALEN_POS)

#define DATAADDR_MASK	CREATE_MASK_ULL(DATAADDR_POS, DATAADDR_LEN)
#define BUFDATALEN_MASK	CREATE_MASK_ULL(BUFDATALEN_POS, 15)

struct xgene_enet_desc {
	u64 m0;
	u64 m1;
	u64 m2;
	u64 m3;
};

struct xgene_enet_desc16 {
	u64 m0;
	u64 m1;
};

enum xgene_enet_ring_cfgsize {
	RING_CFGSIZE_512B,
	RING_CFGSIZE_2KB,
	RING_CFGSIZE_16KB,
	RING_CFGSIZE_64KB,
	RING_CFGSIZE_512KB,
	RING_CFGSIZE_INVALID
};

enum xgene_enet_ring_type {
	RING_DISABLED,
	RING_REGULAR,
	RING_BUFPOOL
};

enum xgene_enet_ring_owner {
	RING_OWNER_ETH0,
	RING_OWNER_ETH1,
	RING_OWNER_ETH2,
	RING_OWNER_CPU = 15,
	RING_OWNER_INVALID
};

enum xgene_enet_ring_bufnum {
	RING_BUFNUM_REGULAR = 0x0,
	RING_BUFNUM_BUFPOOL = 0x20,
	RING_BUFNUM_INVALID
};

enum desc_info_index {
	USERINFO,
	FPQNUM,
	STASH,
	DATAADDR,
	BUFDATALEN,
	BUFLEN,
	COHERENT,
	LL_LSB,
	TCPHDR,
	IPHDR,
	ETHHDR,
	EC,
	ET,
	IS,
	IC,
	TYPESEL,
	HENQNUM,
	ELERR,
	LERR,
	NV,
	LL,
	AM,
	MAX_DESC_INFO_INDEX
};

struct xgene_enet_desc_info {
	u8 word_index;
	u8 start_bit;
	u8 len;
};

extern struct xgene_ring_ops xgene_sm_ring_ops;

#endif /* __XGENE_ENET_HW_H__ */
