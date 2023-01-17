/*
 * APM X-Gene SoC Security Driver
 *
 * Copyright (c) 2014 Applied Micro Circuits Corporation.
 * All rights reserved. Loc Ho <lho@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This file defines the private crypto driver structure and messaging
 * format of the security hardware.
 */
#ifndef __XGENE_SEC_H__
#define __XGENE_SEC_H__

#include <linux/interrupt.h>
#include <linux/platform_device.h>
#include <linux/uio_driver.h>

#undef APM_SEC_TXDEBUG
#undef APM_SEC_RXDEBUG
#undef APM_SEC_SATKNDEBUG
#undef APM_SEC_QMDEBUG

/* Debugging Macro */
#define APMSEC_HDR		"XGSEC: "

#if !defined(APM_SEC_TXDEBUG)
# define APMSEC_TXLOG(fmt, ...)
# define APMSEC_TXDUMP(hdr, d, l)
#else
# define APMSEC_TXLOG(fmt, ...)		\
	do { \
		printk(KERN_INFO APMSEC_HDR fmt, ##__VA_ARGS__); \
	} while(0);
# define APMSEC_TXDUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, APMSEC_HDR hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
} while(0);
#endif

#if !defined(APM_SEC_RXDEBUG)
# define APMSEC_RXLOG(fmt, ...)
# define APMSEC_RXDUMP(hdr, d, l)
#else
# define APMSEC_RXLOG(fmt, ...)		\
	do { \
		printk(KERN_INFO APMSEC_HDR fmt, ##__VA_ARGS__); \
	} while(0);
# define APMSEC_RXDUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, APMSEC_HDR hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
	} while(0);
#endif

#if !defined(APM_SEC_SATKNDEBUG)
# define APMSEC_SATKNLOG(fmt, ...)
# define APMSEC_SADUMP(s, l)
# define APMSEC_TKNDUMP(t)
#else
# define APMSEC_SATKNLOG(fmt, ...)	\
	do { \
		printk(KERN_INFO APMSEC_HDR fmt, ##__VA_ARGS__); \
	} while(0);
# define APMSEC_SADUMP(s, l) 		sec_sa_dump((s), (l))
# define APMSEC_TKNDUMP(t)		sec_tkn_dump((t))
#endif

#if !defined(APM_SEC_QMDEBUG)
# define APMSEC_QMSGDUMP(hdr, d, l)
#else
# define APMSEC_QMSGDUMP(hdr, d, l)	\
	do { \
		print_hex_dump(KERN_INFO, APMSEC_HDR hdr, \
			DUMP_PREFIX_ADDRESS, 16, 4,  d, l, 1); \
	} while(0);
#endif

#define APM_SEC_GLBL_CTRL_CSR_OFFSET	0x0000
#define APM_XTS_AXI_CSR_OFFSET		0x1000
#define APM_XTS_CSR_OFFSET		0x1800
#define APM_XTS_CORE_CSR_OFFSET		0x2000
#define APM_EIP96_AXI_CSR_OFFSET	0x2800
#define APM_EIP96_CSR_OFFSET		0x3000
#define APM_EIP96_CORE_CSR_OFFSET	0x3800
#define	APM_EIP62_AXI_CSR_OFFSET	0x4000
#define APM_EIP62_CSR_OFFSET		0x4800
#define APM_EIP62_CORE_CSR_OFFSET	0x5000
#define	APM_RI_CTL_OFFSET		0x9000
#define APM_SEC_CLK_RES_CSR_OFFSET	0xC000
#define APM_SEC_GLBL_DIAG_OFFSET	0XD000
#define	APM_SEC_AXI_SLAVE_SHIM_OFFSET	0xE000
#define APM_SEC_AXI_MASTER_SHIM_OFFSET  0xF000

#define SEC_GLB_CTRL_CSR_BLOCK		1
#define XTS_AXI_CSR_BLOCK		2
#define XTS_CSR_BLOCK			3
#define XTS_CORE_CSR_BLOCK		4
#define EIP96_AXI_CSR_BLOCK		5
#define EIP96_CSR_BLOCK			6
#define EIP96_CORE_CSR_BLOCK		7
#define EIP62_AXI_CSR_BLOCK		8
#define EIP62_CSR_BLOCK			9
#define EIP62_CORE_CSR_BLOCK		10
#define	RI_CTL_BLOCK			11
#define	CLK_RES_CSR_BLOCK		12
#define AXI_SLAVE_SHIM_BLOCK		13
#define AXI_MASTER_SHIM_BLOCK		14

#define NUM_FREEPOOL			8
#define MAX_SLOT			1024
/* Total number of extra linked buffer */
#define APM_SEC_SRC_LINK_ADDR_MAX	(255-4)
#define APM_SEC_DST_LINK_ADDR_MAX	(255)
#define APM_SEC_TKN_CACHE_MAX		(MAX_SLOT / 4)
#define APM_SEC_SA_CACHE_MAX		(MAX_SLOT / 4)

#define TX_XGENE_QSIZE			RING_CFG_SIZE_64KB
#define RX_XGENE_QSIZE			RING_CFG_SIZE_64KB
#define FP_XGENE_QSIZE			RING_CFG_SIZE_64KB

#define START_SEC_RING_NUM		640
#define START_SEC_RING_NUM_VER2		384
#define XGENE_MAX_CHANNEL		1
#define XGENE_SLOT_PER_CHANNEL		64
#define XGENE_32B_MSG_CNT_PER_SLOT	32
#define XGENE_CHANNEL_BUDGET		2048

#define RING_BUFNUM_CPU			0x1C
#define RING_BUFNUM_CPU_VER2		0x18
#define RING_BUFNUM_REGULAR		0x0
#define RING_BUFNUM_BUFPOOL		0x20
#define RING_OWNER_SEC			0x5
#define RING_OWNER_CPU			0xF

#define XGENE_NUM_RING_CFG_WORD		5
#define XGENE_NUM_RING_CFG_WORD_VER2	6

#define XGENE_SINGLE_BUFFER_BYTE_CNT	0x4000		/* 16 KB */

#define XGENE_INVALID_LEN		0x7800

/* Diagnostic CSR register and bit definitions */
#define CFG_MEM_RAM_SHUTDOWN		0x70
#define BLOCK_MEM_RDY			0x74

/* Descriptor ring lower 32B message format - W0 */
#define RMSG_USERINFO_RD(m)		(((u32 *) (m))[0])
#define RMSG_USERINFO_SET(m, v)		(((u32 *) (m))[0] = (v))

/* Descriptor ring lower 32B message format - W1 */
#define RMSG_HL_MASK(m)			(((u32 *) (m))[1] & BIT(31))
#define RMSG_LERR_RD(m)			((((u32 *) (m))[1] & 0x70000000) >> 28)
#define RMSG_RTYPE_RD(m)		((((u32 *) (m))[1] & 0x0F000000) >> 24)
#define RMSG_RTYPE_SET(m, v)		\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x0F000000) | \
			(((v) << 24) & 0x0F000000))
#define RMSG_IN_MASK(m)			(((u32 *) (m))[1] & BIT(23))
#define RMSG_RV_MASK(m)			(((u32 *) (m))[1] & BIT(22))
#define RMSG_HB_MASK(m)			(((u32 *) (m))[1] & BIT(21))
#define RMSG_PB_MASK(m)			(((u32 *) (m))[1] & BIT(20))
#define RMSG_LL_MASK(m)			(((u32 *) (m))[1] & BIT(19))
#define RMSG_LL_SET(m, v)		\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~BIT(19)) | \
			(((v) << 19) & BIT(19)))
#define RMSG_NV_MASK(m)			(((u32 *) m)[1] & BIT(18))
#define RMSG_NV_SET(m, v)		\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~BIT(18)) | \
			(((v) << 18) & BIT(18)))
#define RMSG_LEI_RD(m)			((((u32 *) (m))[1] & 0x00030000) >> 16)
#define RMSG_ELERR_RD(m)		((((u32 *) (m))[1] & 0x0000C000) >> 14)
#define RMSG_RV2_RD(m)			((((u32 *) (m))[1] & 0x00003000) >> 12)
#define RMSG_FPQNUM_RD(m)		(((u32 *) (m))[1] & 0x00000FFF)
#define RMSG_FPQNUM_SET(m, v)		\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x00000FFF) | \
			((v) & 0x00000FFF))

/* Descriptor ring lower 32B message format - W2 */
#define RMSG_DATAADDRL_RD(m)		(((u32 *) (m))[2])
#define RMSG_DATAADDRL_SET(m, v)	(((u32 *) (m))[2] = (v))

/* Descriptor ring lower 32B message format - W3 */
#define RMSG_C_MASK(m)			(((u32 *) m)[3] & BIT(31))
#define RMSG_C_SET(m, v)		\
	(((u32 *) m)[3] = (((u32 *) m)[3] & ~BIT(31)) | \
			(((v) << 31) & BIT(31)))
#define RMSG_BUFDATALEN_RD(m)		((((u32 *) m)[3] & 0x7FFF0000) >> 16)
#define RMSG_BUFDATALEN_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x7FFF0000) | \
			(((v) << 16) & 0x7FFF0000))
#define RMSG_RV6_RD(m)			((((u32 *) (m))[3] & 0x0000FC00) >> 10)
#define RMSG_DATAADDRH_RD(m)		(((u32 *) (m))[3] & 0x3FF)
#define RMSG_DATAADDRH_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x3FF) | ((v) & 0x3FF))

/* Descriptor ring lower 32B message format - W4 */
#define RMSG_H0INFO_MSBL_SET(m, v)	(((u32 *) (m))[4] = (v))
#define RMSG_H0INFO_MSBL_RD(m)		(((u32 *) (m))[4])
#define RMSG_BD_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00000001) | \
			((v) & 0x00000001))
#define RMSG_SD_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00000002) | \
			((v << 1) & 0x00000002))
#define RMSG_FBY_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x000000F0) | \
			(((v) << 4) & 0x000000F0))
#define RMSG_MULTI0_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x0000FF00) | \
			(((v) << 8) & 0x0000FF00))
#define RMSG_MULTI1_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00FF0000) | \
			(((v) << 16) & 0x00FF0000))
#define RMSG_MULTI2_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0xFF000000) | \
			(((v) << 24) & 0xFF000000))
#define RMSG_CRCSEEDL_SET(m, v)		\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0xFFFFFF00) | \
			(((v) << 8) & 0xFFFFFF00))

/* Descriptor ring lower 32B message format - W5 */
#define RMSG_DR_SET(m, v)		\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x20000000) | \
			(((v) << 29) & 0x20000000))
#define RMSG_TOTDATALENGTHLINKLISTLSB_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x0FFF0000) | \
			(((v) << 16) & 0x0FFF0000))
#define RMSG_H0INFO_MSBH_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x00000FFF) | \
		((v) & 0x0000FFFF))
#define RMSG_H0INFO_MSBH_RD(m)		(((u32 *) (m))[5] & 0x00000FFF)
#define RMSG_LINKEDLIST_LEN_MSB_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5]) | \
			((v << 12) & 0x0000F000))
#define RMSG_MULTI3_SET(m, v)		\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x000000FF) | \
			(((v)) & 0x000000FF))
#define RMSG_MULTI4_SET(m, v)		\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x0000FF00) | \
			(((v) << 8) & 0x0000FF00))
#define RMSG_CRCSEEDH_SET(m, v)		\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x000000FF) | \
			(((v)) & 0x000000FF))

/* Descriptor ring lower 32B message format - W6 */
#define RMSG_CRCBYTECNT_SET(m, v)	\
	(((u32 *) (m))[6] = (((u32 *) (m))[6] & ~0x0000FFFF) | \
			((v) & 0x0000FFFF))
#define RMSG_CRC3_RESULT_RD(m)		(((u32 *) (m))[6])
#define RMSG_H0INFO_LSBL_RD(m)		(((u32 *) (m))[6])
#define RMSG_H0INFO_LSBL_SET(m, v)	(((u32 *) (m))[6] = (v))

/* Descriptor ring lower 32B message format - W7 */
#define RMSG_H0FPSEL_RD(m, v)		((((u32 *) (m))[7] & 0xF0000000) >> 27)
#define RMSG_H0ENQ_NUM_SET(m, v)	\
	(((u32 *) (m))[7] = (((u32 *) (m))[7] & ~0x0FFF0000) | \
			(((v) << 16) & 0x0FFF0000))
#define RMSG_H0ENQ_NUM_RD(m)		((((u32 *) (m))[7] & 0x0FFF0000) >> 16)
#define RMSG_H0INFO_LSBH_SET(m, v)	\
	(((u32 *) (m))[7] = (((u32 *) (m))[7] & ~0x0000FFFF) | \
			((v) & 0x0000FFFF))
#define RMSG_H0INFO_LSBH_RD(m)	(((u32 *) (m))[7] & 0x0000FFFF)
#define RMSG_LINKEDLIST_LEN_LSB_SET(m, v)	\
	(((u32 *) (m))[7] = (((u32 *) (m))[7]) | \
			((v << 6) & 0x000003C0))
#define RMSG_SEC_CTL_SET(m, v)		\
	(((u32 *) (m))[7] = (((u32 *) (m))[7] & ~0x0000C000) | \
			((v << 14) & 0x0000C000))
#define RMSG_LINK_SIZE_SET(m, v)	\
	(((u32 *) (m))[7] = (((u32 *) (m))[7] & ~0x0000FF00) | \
			(((v) << 8) & 0x0000FF00))

/* Descriptor ring empty slot software signature */
#define RMSG_EMPTY_SLOT_INDEX		7
#define RMSG_EMPTY_SLOT_SIGNATURE	0x22222222
#define RMSG_IS_EMPTY_SLOT(m)		\
	(((u32 *) (m))[RMSG_EMPTY_SLOT_INDEX] == RMSG_EMPTY_SLOT_SIGNATURE)
#define RMSG_SET_EMPTY_SLOT(m)		\
	(((u32 *) (m))[RMSG_EMPTY_SLOT_INDEX] = RMSG_EMPTY_SLOT_SIGNATURE)

/* Descriptor ring extended entry format */
#define RMSG_NXTDATAADDRL_RD(m)		(((u32 *) (m))[0])
#define RMSG_NXTDATAADDRL_SET(m, v)	(((u32 *) (m))[0] = (v))
#define RMSG_NXTBUFDATALENGTH_RD(m)	((((u32 *) (m))[1] & 0x7FFF0000) >> 16)
#define RMSG_NXTBUFDATALENGTH_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x7FFF0000) | \
			(((v) << 16) & 0x7FFF0000))
#define RMSG_NXTFPQNUM_RD(m)		((((u32 *) (m))[1] & 0x0000F000) >> 12)
#define RMSG_NXTFPQNUM_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x0000F000) | \
			(((v) << 12) & 0x0000F000))
#define RMSG_NXTDATAADDRH_RD(m)		(((u32 *) (m))[1] & 0x000003FF)
#define RMSG_NXTDATAADDRH_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) m)[1] & ~0x000003FF) | \
			((v) & 0x000003FF))

/* Descriptor ring extended entry format for LinkedList*/
#define RMSG_LL_NXTDATAADDRL_RD(m)	(((u32 *) (m))[0])
#define RMSG_LL_NXTDATAADDRL_SET(m, v)	(((u32 *) (m))[0] = (v))
#define RMSG_LL_TOTDATALENGTHLINKLISTMSB_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[5] & ~0xFF000000) | \
			(((v) << 24) & 0xFF000000))
#define RMSG_LL_NXTLINKLISTLENGTH_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[5] & ~0x00FF0000) | \
			(((v) << 16) & 0x00FF0000))
#define RMSG_LL_NXTFPQNUM_RD(m)		((((u32 *) (m))[1] & 0x0000F000) >> 12)
#define RMSG_LL_NXTFPQNUM_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x0000F000) | \
			(((v) << 12) & 0x0000F000))
#define RMSG_LL_NXTDATAADDRH_RD(m)	(((u32 *) (m))[1] & 0x000003FF)
#define RMSG_LL_NXTDATAADDRH_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) m)[1] & ~0x000003FF) | \
			((v) & 0x000003FF))

/* Descriptor ring upper 32B message for extended format - W2/W3 */
#define RMSG_NXTDATAPTRL_SET(m, v)	(((u32 *) (m))[4] = (v))
#define RMSG_TOTDATALENGTHLINKLISTMSB_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0xFF000000) | \
			(((v) << 24) & 0xFF000000))
#define RMSG_NXTLINKLISTLENGTH_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x00FF0000) | \
			(((v) << 16) & 0x00FF0000))
#define RMSG_NXTFPQNUM2_SET(m, v)		\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x0000F000) | \
			(((v) << 12) & 0x0000F000))
#define RMSG_NXTDATAPTRH_SET(m, v)		\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x000003FF) | \
			((v) & 0x000003FF))

#define FLAG_SRC_LINKLIST_ACTIVE	0x0001
#define FLAG_DST_LINKLIST_ACTIVE	0x0002
#define FLAG_DSTSRC_LIST_ACTIVE		0x0004
#define FLAG_P_ACTIVE			0x0008
#define FLAG_Q_ACTIVE			0x0010
#define FLAG_SG_ACTIVE			0x0020
#define FLAG_FLYBY_ACTIVE		0x0040
#define FLAG_UNMAP_FIRST_DST		0x0080
#define FLAG_UNMAP_SECOND_DST		0x0100
#define FLAG_SLOT_IN_USE		0x0200

/* Ring configuration related Macro */
#define GENMASK(h, l)		(((U32_C(1) << ((h) - (l) + 1)) - 1) << (l))
#define GENMASK_ULL(h, l)	(((U64_C(1) << ((h) - (l) + 1)) - 1) << (l))

#define CREATE_MASK(pos, len)		GENMASK(pos + len - 1, pos)
#define CREATE_MASK_ULL(pos, len)	GENMASK_ULL(pos + len - 1, pos)

#define CSR_RING_ID			0x00000008
#define OVERWRITE			BIT(31)
#define IS_FREE_POOL			BIT(20)
#define BUF_EN				BIT(21)
#define CSR_RING_ID_BUF			0x0000000c
#define CSR_RING_NE_INT_MODE		0x0000017c
#define CSR_RING_CONFIG			0x0000006c
#define CSR_RING_WR_BASE		0x00000070
#define CSR_RING_RD_BASE		0x00000084
#define NUM_RING_CONFIG			6
#define BUFPOOL_MODE			3

/* Ring configuration fields */
#define RSTATE_INLINE_RD(m)		((((u32 *) (m))[0] & 0x1F000000) >> 24)
#define RSTATE_INLINE_SET(m, v)		\
	(((u32 *) (m))[0] = (((u32 *) (m))[0] & ~0x1F000000) | \
			(((v) << 24) & 0x1F000000))
#define RSTATE_CFGCRID_RD(m)		((((u32 *) (m))[0] & 0xE0000000) >> 29)
#define RSTATE_CFGCRID_SET(m, v)	\
	(((u32 *) (m))[0] = (((u32 *) (m))[0] & ~0xE0000000) | \
			(((v) << 29) & 0xE0000000))
#define RSTATE_NUMMSGINQ_VER2_RD(m)	(((u32 *) (m))[1] & 0x0003FFFF)
#define RSTATE_NUMMSGINQ_VER2_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x0003FFFF) | \
			((v) & 0x0003FFFF))
#define RSTATE_HEAD_PTR_RD(m)		((((u32 *) (m))[1] & 0xFFFE0000) >> 17)
#define RSTATE_HEAD_PTR_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0xFFFE0000) | \
			(((v) << 17) & 0xFFFE0000))
#define RSTATE_NUMMSGINQ_RD(m)		((((u32 *) (m))[1] & 0x0001FFFE) >> 1)
#define RSTATE_NUMMSGINQ_SET(m, v)	\
	(((u32 *) (m))[1] = (((u32 *) (m))[1] & ~0x0001FFFE) | \
			(((v) << 1) & 0x0001FFFE))
#define RSTATE_QCOHERENT_RD(m)		((((u32 *) (m))[2] & 0x00000010) >> 4)
#define RSTATE_QCOHERENT_SET(m, v)	\
	(((u32 *) (m))[2] = (((u32 *) (m))[2] & ~0x00000010) | \
			(((v) << 4) & 0x00000010))
#define RSTATE_RINGADDRL_RD(m)		((((u32 *) (m))[2] & 0xFFFFFFE0) >> 5)
#define RSTATE_RINGADDRL_SET(m, v)	\
	(((u32 *) (m))[2] = (((u32 *) (m))[2] & ~0xFFFFFFE0) | \
			(((v) << 5) & 0xFFFFFFE0))
#define RSTATE_RINGADDRH_RD(m)		(((u32 *) (m))[3] & 0x0000007F)
#define RSTATE_RINGADDRH_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x0000007F) | \
			((v) & 0x0000007F))
#define RSTATE_SLOTS_PENDING_RD(m)	((((u32 *) (m))[3] & 0x0001FE00) >> 9)
#define RSTATE_SLOTS_PENDING_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x0001FE00) | \
			(((v) << 9) & 0x0001FE00))
#define RSTATE_ACCEPTLERR_RD(m)		((((u32 *) (m))[3] & 0x00080000) >> 19)
#define RSTATE_ACCEPTLERR_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x00080000) | \
			(((v) << 19) & 0x00080000))
#define RSTATE_RINGMODE_RD(m)		((((u32 *) (m))[3] & 0x00700000) >> 20)
#define RSTATE_RINGMODE_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x00700000) | \
			(((v) << 20) & 0x00700000))
#define RSTATE_RINGSIZE_RD(m)		((((u32 *) (m))[3] & 0x03800000) >> 23)
#define RSTATE_RINGSIZE_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x03800000) | \
			(((v) << 23) & 0x03800000))
#define RSTATE_RECOMBBUF_RD(m)		((((u32 *) (m))[3] & 0x08000000) >> 27)
#define RSTATE_RECOMBBUF_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x08000000) | \
			(((v) << 27) & 0x08000000))
#define RSTATE_RECOMTIMEOUTL_RD(m)	((((u32 *) (m))[3] & 0x70000000) >> 28)
#define RSTATE_RECOMTIMEOUTL_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x70000000) | \
			(((v) << 28) & 0x70000000))
#define RSTATE_DEQINTEN_RD(m)		((((u32 *) (m))[3] & 0x20000000) >> 29)
#define RSTATE_DEQINTEN_SET(m, v)	\
	(((u32 *) (m))[3] = (((u32 *) (m))[3] & ~0x20000000) | \
			(((v) << 29) & 0x20000000))
#define RSTATE_RECOMTIMEOUTH_RD(m)	(((u32 *) (m))[4] & 0x00000003)
#define RSTATE_RECOMTIMEOUTH_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00000003) | \
			((v) & 0x00000003))
#define RSTATE_SELTHRSH_RD(m)		((((u32 *) (m))[4] & 0x00000038) >> 3)
#define RSTATE_SELTHRSH_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00000038) | \
			(((v) << 3) & 0x00000038))
#define RSTATE_SELTHRSH_VER2_RD(m)	((((u32 *) (m))[4] & 0x00000380) >> 7)
#define RSTATE_SELTHRSH_VER2_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00000380) | \
			(((v) << 7) & 0x00000380))
#define RSTATE_RINGTYPE_RD(m)		((((u32 *) (m))[4] & 0x00180000) >> 19)
#define RSTATE_RINGTYPE_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x00180000) | \
			(((v) << 19) & 0x00180000))
#define RSTATE_RINGTYPE_VER2_RD(m)	((((u32 *) (m))[4] & 0x01800000) >> 23)
#define RSTATE_RINGTYPE_VER2_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x01800000) | \
			(((v) << 23) & 0x01800000))
#define RSTATE_RECOMTIMEOUT_RD(m)	(((u32 *) (m))[4] & 0x0000007F)
#define RSTATE_RECOMTIMEOUT_SET(m, v)	\
	(((u32 *) (m))[4] = (((u32 *) (m))[4] & ~0x0000007F) | \
			((v) & 0x0000007F))
#define RSTATE_MSG_AM_RD(m)	((((u32 *) (m))[5] & 0x00000400) >> 10)
#define RSTATE_MSG_AM_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x00000400) | \
			(((v) << 10) & 0x00000400))
#define RSTATE_QBASE_AM_RD(m)	((((u32 *) (m))[5] & 0x00000800) >> 11)
#define RSTATE_QBASE_AM_SET(m, v)	\
	(((u32 *) (m))[5] = (((u32 *) (m))[5] & ~0x00000800) | \
			(((v) << 11) & 0x00000800))

#define CSR_VMID0_INTR_MBOX	0x270

#define CSR_QM_CONFIG		0x0004
#define CSR_QM_CLKRST		0xc208
#define CSR_QM_SRST		0xc200
#define CSR_QM_CLKRST_VER2	0xc008
#define CSR_QM_SRST_VER2	0xc000
#define CSR_QM_GLOBAL_DIAG	0xd000
#define CSR_QM_MEM_RAM_SHUTDOWN	0xd070
#define CSR_QM_MEM_RDY		0xd074
#define CSR_THRESHOLD0_SET1	0x0030
#define CSR_THRESHOLD1_SET1	0x0034
#define CSR_HYSTERESIS		0x0068
#define QM_ENABLE		BIT(31)
#define CSR_RING_RD_BASE_VER2	0x00000088

#define INTR_MBOX_SIZE		1024
#define INTR_CLEAR		BIT(23)
#define FIRST_DEQ_IRQ		128

struct rmsg_ext8 {
	u32 w0;
	u32 w1;
} __attribute__((packed));

struct rmsg16 {
	u64 m0;
	u64 m1;
} __attribute__((packed));

struct rmsg32 {
	u64 m0;
	u64 m1;
	u64 m2;
	u64 m3;
} __attribute__((packed));

enum xgene_ring_interface {
	XGENE_RING_VERSION2,
	XGENE_RING_VERSION1
};

enum xgene_ring_type {
	RING_DISABLED,
	RING_REGULAR,
	RING_BUFPOOL
};

enum xgene_ring_cfgsize {
	RING_CFG_SIZE_512B,
	RING_CFG_SIZE_2KB,
	RING_CFG_SIZE_16KB,
	RING_CFG_SIZE_64KB,
	RING_CFG_SIZE_512KB,
	RING_CFG_SIZE_INVALID
};

struct xgene_ring_info {
	struct xgene_sec_ctx *ctx;
	u16 ring_id;
	u16 ring_num;
	u16 irq;
	u16 qhead;
	u16 count;
	u32 size;
	bool is_bufpool;
	u32 owner;
	u8 buf_num;
	u16 dst_ring_num;
	dma_addr_t dma;
	void *mbox_dma_vaddr;
	dma_addr_t irq_mbox_dma;
	enum xgene_ring_cfgsize cfgsize;
	u32 state[NUM_RING_CONFIG];
	u32 num_ring_cfg;
	void __iomem *cmd;
	void __iomem *cmd_base;
	union {
		void *ring_vaddr;
		struct rmsg16 *msg16;
		struct rmsg32 *msg32;
	};
};

struct xgene_sec_ctx {
	struct device *dev;
	struct list_head alg_list;
	struct crypto_queue queue;
	struct clk *sec_clk;
	struct xgene_ring_info tx_ring;
	struct xgene_ring_info rx_ring;
	atomic_t ring_active;
	void __iomem *csr_ring;
	void __iomem *csr_cmd;
	int ring_count;
	int index;
	enum xgene_ring_interface intf;
	spinlock_t lock;
	spinlock_t txlock;
	struct tasklet_struct tasklet;

	int irq;
	void __iomem *csr;
	void __iomem *ctrl_csr;
	void __iomem *clk_csr;
	void __iomem *diag_csr;
	void __iomem *eip96_axi_csr;
	void __iomem *eip96_csr;
	void __iomem *eip96_core_csr;
	void __iomem *ri_ctl_csr;

	/* User IO variables */
	struct uio_info uioinfo;
	int mmap_noncache_max_idx;
	unsigned long flags;
	void *tknsa_array;
	void *buf_array;
};

struct xgene_sec_session_ctx {
	struct xgene_sec_ctx *ctx;
	struct sec_sa_item *sa;	/* Allocate outbound SA */
	struct sec_sa_item *sa_ib;	/* Allocate inbound SA if needed */

	spinlock_t lock;
	struct list_head tkn_cache;
	u32 tkn_cache_cnt;
	u16 tkn_max_len;
	u16 tkn_input_len;
	struct list_head sa_cache;
	u32 sa_cache_cnt;
	u16 sa_len;
	u16 sa_max_len;

#if 0
	/* FIXME */
	int sa_flush_done;
	u16 pad_block_size;	/* For ESP offload */
	u16 encap_uhl;		/* For ESP offload - ENCAP UDP header length */
#endif
};

extern struct xgene_sec_ctx *xg_ctx;

void xgene_read_ring_state(struct xgene_ring_info *ring);
int xgene_sec_init_memram(struct xgene_sec_ctx *ctx);
int xgene_sec_hwreset(struct xgene_sec_ctx *ctx);
int xgene_sec_hwinit(struct xgene_sec_ctx *ctx);
int xgene_sec_hwstart(struct xgene_sec_ctx *ctx);
int xgene_sec_hwstop(struct xgene_sec_ctx *ctx);
int xgene_sec_qconfig(struct xgene_sec_ctx *ctx);
void xgene_sec_intr_hdlr(struct xgene_sec_ctx *ctx);
void xgene_sec_hdlr_qerr(struct xgene_sec_ctx *ctx,
			 int ring_err_hop, int ring_err);

void xgene_sec_wr32(struct xgene_sec_ctx *ctx, u8 block, u32 reg, u32 data);
void xgene_sec_rd32(struct xgene_sec_ctx *ctx, u8 block, u32 reg, u32 * data);

int xgene_sec_create_sa_tkn_pool(struct xgene_sec_session_ctx *session,
				 u32 sa_max_len, u32 sa_len,
				 char sa_ib, u32 tkn_len);
void xgene_sec_free_sa_tkn_pool(struct xgene_sec_session_ctx *session);
struct sec_tkn_ctx *xgene_sec_tkn_get(struct xgene_sec_session_ctx *session,
				      u8 * new_tkn);
void xgene_sec_tkn_free(struct xgene_sec_session_ctx *session,
			struct sec_tkn_ctx *tkn);
struct sec_sa_item *xgene_sec_sa_get(struct xgene_sec_session_ctx *session);
void xgene_sec_sa_free(struct xgene_sec_session_ctx *session,
		       struct sec_sa_item *sa);

void xgene_sec_session_init(struct xgene_sec_session_ctx *session);
void xgene_sec_session_free(struct xgene_sec_session_ctx *session);

int xgene_sec_setup_crypto(struct xgene_sec_ctx *ctx,
			   struct crypto_async_request *req);
int xgene_sec_queue2hw(struct xgene_sec_session_ctx *session,
		       struct sec_tkn_ctx *tkn);
int xgene_sec_loadbuffer2rmsg(struct xgene_sec_ctx *ctx,
			      void *msg, void *msgext32,
			      struct sec_tkn_ctx *tkn);

void xgene_sec_rmesg_load_dst_single(struct xgene_sec_ctx *ctx,
				     void *msg, void *ptr, int nbytes);
u64 xgene_sec_encode2hwaddr(u64 hwaddr);
u64 xgene_sec_decode2hwaddr(u64 hwaddr);

int xgene_sec_uio_init(struct platform_device *pdev, struct xgene_sec_ctx *ctx);
int xgene_sec_uio_deinit(struct xgene_sec_ctx *ctx);


#endif
