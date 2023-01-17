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

#ifndef _PSE_REG_H_
#define _PSE_REG_H_

/* Following PSE Register Offset is PSE Design Spec. VA10 */

/* The base address of PSE register is 0x70000000 (physical address) */

/* PSE Registers */

/* General and DMA */

#define PHY_CTRL		(0x000)	/* PHY Control */
#define PHY_AUTO_ADDR		(0x004)	/* Auto-Polling PHY Address */

#define MAC_GLOB_CFG		(0x008)	/* MAC Global Configuration */

#define MAC0_CFG		(0x00C)	/* MAC0 Configuration */
#define MAC1_CFG		(0x010)	/* MAC1 Configuration */
#define CPU_CFG			(0x014)	/* CPU Port Configuration */
#define MAC2_CFG		(0x018)	/* MAC2 Port Configuration */
#define PPE_PORT_CFG		(0x01C)	/* PPE Port Configuration */
#define CFP_CFG			(0x020)	/* CFP Port Configuration */

#define PORT_PRI_CMD		(0x024)	/* Port Priority Command */
#define PORT_PRI_CTRL		(0x028)	/* Port Priority Control */
#define PORT_PRI_WEIGHT		(0x02C)	/* Port Priority Weight */
#define PORT_PRI_RING		(0x030)	/* Port Priority Weight */

#define ETYPE_PRI_CMD		(0x034)	/* Ethernet Type Priority Command */
#define DSCP_PRI_CMD		(0x038)	/* DSCP Priority Command */
#define L4_PRI_CMD		(0x03C)	/* L4 Priority Command */
#define L4_PORT_RANGE		(0x040)	/* L4 Port Range */

#define POLICE_CFG		(0x044) /* Policer Configuration */
#define POLICE_CMD		(0x048) /* Policer Command */

#define POLICER_RED_TH		(0x04C) /* Policer RED Threshold */
#define POLICER_RED_FACTOR	(0x050) /* Policer RED Factor */

#define TC_CTRL			(0x054)	/* Traffic Class Control */
#define PORT_SHAPE_CFG		(0x058)	/* Port Shape Configure */
#define QUEUE_SHAPE_CMD		(0x05C)	/* Queue Shape Command */
#define FC_TH			(0x060)	/* Flow Control Threshold */
#define FC_INPUT_CMD		(0x064)	/* Flow Control Input Command */
#define FC_INPUT_TH		(0x068)	/* Flow Control Input Threshold */
#define FC_DROP_TH		(0x06C)	/* Flow Control Drop Threshold */
#define FC_ALL_DROP_TH		(0x070)	/* Flow Control All Drop Threshold */

#define MAC_CHECK_CFG		(0x080)	/* MAC check Configuration */
#define MAC_CHECK_CMD		(0x084)	/* MAC check Command */
#define MAC_CHECK_CTRL0		(0x088)	/* MAC check Control 0 */
#define MAC_CHECK_CTRL1		(0x08C)	/* MAC check Control 1 */

#define VLAN_CFG		(0x090)	/* VLAN Configuration */
#define VLAN_CMD		(0x094)	/* VLAN Check Command */
#define VLAN_CTRL		(0x098)	/* VLAN Check Control */

#define EEE_CFG			(0x0A0)	/* EEE Configuration */
#define EEE_CTRL		(0x0A4)	/* EEE Control */

#define SRAM_TEST		(0x0A8)	/* SRAM Self Test */

#define MEM_QUEUE_STATUS0	(0x0AC)	/* Memory Queue Status 0 */
#define MEM_QUEUE_STATUS1	(0x0B0)	/* Memory Queue Status 1 */

#define POLICE_RAND_FACTOR	(0x0B4) /* Police Random Factor */
#define POLICE_OQUE_TH		(0x0B8) /* Police Output Queue Threshold */
#define PRIO_BUCKET_SIZE	(0x0BC) /* Port Shape Bucket Size */

#define CLK_SKEW_CTRL		(0x0F0)	/* Clock Skew Control */

#define MAC_GLOB_EXT		(0x0F4)	/* MAC Global Configuration Extention */
#define TEST_MODE0		(0x0F8)	/* Test Mode 0 */
#define TEST_MODE1		(0x0FC)	/* Test Mode 1 */

/* PSE DMA Registers */
#define DMA_RING_CTRL		(0x100)	/* DMA Ring Control */
#define DMA_RING_CFG		(0x104)	/* DMA Ring Configuration */
#define DELAY_INTR_CFG		(0x108)	/* Delayed Interrupt Configuration */

#define TS_DMA_CTRL		(0x110)	/* TS DMA Control */
#define TS_DESC_ACCESS		(0x114)	/* TS Descriptor Access */
#define TS_DESC_PTR		(0x118)	/* TS Descriptor Pointer */
#define TS_DESC_BASE		(0x11C)	/* TS Descriptor Base Pointer */

#define FS_RING_STA		(0x13C) /* FS Ring Status */
#define FS_DMA_CTRL		(0x140)	/* FS DMA Control */
#define FS_DESC_ACCESS		(0x144)	/* FS Descriptor Access */
#define FS_DESC_PTR		(0x148)	/* FS Descriptor Pointer */
#define FS_DESC_BASE		(0x14C)	/* FS Descriptor Base Pointer */

#define FS_DMA_TIMEOUT          (0x150) /* FS DMA Time Out */

#define FS_DMA_NODESC_DROP_CNT  (0x154) /* FS DMA No Descriptor Drop Packet Count */
#define LRO_DMA_NODHDR_DROP_CNT (0x158) /* LRO DMA No Header Buffer Drop Packet Count */
#define LRO_DMA_NODPAY_DROP_CNT (0x15C) /* LRO DMA No Payload Buffer Drop Packet Count */

#define LRO_USED_HDR_CNT (0x160)
#define LRO_USED_PAY_CNT (0x164)
#define LRO_BACK_HDR_CNT (0x168)
#define LRO_BACK_PAY_CNT (0x16C)

/* LRO Register */
#define LRO_CFG			(0x170)	/* LRO Configuration */
#define LRO_PAGE_SEG_SIZE	(0x174) /* LRO Page and Segment Size */
#define LRO_DMA_CTRL		(0x180)	/* LRO DMA Control */
#define LRO_DESC_ACCESS		(0x184)	/* LRO Descriptor Access */
#define LRO_DESC_PTR		(0x188)	/* LRO Descriptor Pointer */
#define LRO_DESC_BASE		(0x18C)	/* LRO Descriptor Base Pointer */

#define LRO_BUF_DMA_CTRL	(0x190)	/* LRO Buffer DMA Control */
#define LRO_BUF_DESC_ACCESS	(0x194)	/* LRO Buffer Descriptor Access */
#define LRO_BUF_DESC_PTR	(0x198)	/* LRO Buffer Descriptor Pointer */
#define LRO_BUF_DESC_BASE	(0x19C)	/* LRO Buffer Descriptor Base Pointer */

#define LRO_POLL_CFG		(0x1A0)
#define LRO_POLL_BASE		(0x1A4)
#define LRO_POLL_INDEX		(0x1A8)
#define LRO_POLL_REF_CNT	(0x1AC)

#define LSO_CFG			(0x1B0)	/* LSO Configuration */

#define TS_DMA_STA		(0x1F0)	/* TS DMA Staus */
#define FS_DMA_STA		(0x1F4)	/* TS DMA Staus */
#define FUNC_STA		(0x1F8)	/* Function Staus */

#define VERSION_NUM		(0x1FC)	/* Version Number */

/* Interrupt and MIB */

#define STATUS_INTR		(0x400)	/* Status Interrupt */
#define STATUS_INTR_MASK	(0x404)	/* Status Interrupt Mask */
#define TS_STATUS_INTR		(0x408)	/* TS Status Interrupt */
#define TS_STATUS_INTR_MASK	(0x40C)	/* TS Status Interrupt Mask */
#define FS_STATUS_INTR		(0x410)	/* FS Status Interrupt */
#define FS_STATUS_INTR_MASK	(0x414)	/* FS Status Interrupt Mask */
#define LRO_STATUS_INTR		(0x418)	/* LRO Status Interrupt */
#define LRO_STATUS_INTR_MASK	(0x41C)	/* LRO Status Interrupt Mask*/

#define LRO_BUF_STATUS_INTR	(0x420)	/* LRO Buffer Status Interrupt */
#define LRO_BUF_STATUS_INTR_MASK (0x424)/* LRO Buffer Status Interrupt Mask */

#define MIB_CNT_CFG		(0x440)	/* MIB Counter Configuration */
#define MIB_CNT_CMD		(0x444)	/* MIB Counter Command */

#define MIB_CNT_4732		(0x448)	/* MIB Count bit[47:32] */
#define MIB_CNT_3100		(0x44C)	/* MIB Count bit[31:00] */

#define LRO_POOL_HDR_PAY_CNT	(0x488)	/* bit[6:4] lro_pool_hdrcnt[2:0] , bit[2:0] lro_pool_paycnt[2:0] */

#define CMD_START_MASK	(0x1 << 15)
#define CMD_READ_MASK	(0x0 << 14)
#define CMD_WRITE_MASK	(0x1 << 14)

#endif /* _PSE_REG_H_ */
