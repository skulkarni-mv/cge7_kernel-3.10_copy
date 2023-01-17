/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Keyur Chudgar <kchudgar@apm.com>
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
 * @file apm_enet_mac.h
 *
 * Header file for MAC, RGMII and Statistics blocks of Ethernet.
 *
 */

#ifndef __APM_ENET_MAC_H__
#define __APM_ENET_MAC_H__

/* ===== APM MAC definitions =====*/

#define ENET_MAX_MTU		PKTSIZE
#define IPV4_HDR_SIZE		20
#define IPV6_HDR_SIZE		40
#define IPV6_ADDR_LEN	    	16
#define MAX_ERR_LOG		10
#define PHY_ADDR		1
#define PHY_ADDR1		2
#define READ_CMD		0
#define WRITE_CMD		1
#define MAX_CMD			2

#define INTF_BYTE_MODE		2
#define INTF_NIBBLE_MODE	1

#define ENET_ALIGN_PTR16(x)	(((unsigned long) (x) + 15) & ~0xF)
#define ETH_R_TYPE		1
#if defined(CONFIG_APM862xx)
#define MAX_PORTS		2
#else
#define MAX_PORTS		4
#endif
#define MAX_CORES		2
#define GIGE_PORT0		0
#define GIGE_PORT1		1

#define MAX_LOOP_POLL_CNT	10
#define MAX_LOOP_POLL_TIMEMS	500
#define ACCESS_DELAY_TIMEMS	(MAX_LOOP_POLL_TIMEMS / MAX_LOOP_POLL_CNT)

/* TSO Parameters */
#define TSO_ENABLE		1
#define TSO_ENABLE_MASK		1
#define TSO_CHKSUM_ENABLE	1
#define TSO_INS_CRC_ENABLE	1
#define TSO_IPPROTO_TCP		1
#define TSO_IPPROTO_UDP		0
#define TSO_IP_HLEN_MASK	0X3F
#define TSO_TCP_HLEN_MASK	0X3F
#define TSO_ETH_HLEN_MASK	0XFF
#define TSO_MSS_SZ0		0    /* Default size 64B   */
#define TSO_MSS_SZ1		1    /* Default size 256B  */
#define TSO_MSS_SZ2		2    /* Default size 1024B */
#define TSO_MSS_SZ3		3    /* Default size 1518B */
#define TSO_MSS_MASK		0X3  /* 2b */
#define DEFAULT_TCP_MSS		1448 /* Default TCP suggested MSS is 536 */

/* TYPE_SEL for Ethernt egress message */
#define TYPE_SEL_TIMESTAMP_MSG	0
#define TYPE_SEL_WORK_MSG	1

/* Blocks for defined regions */
#define BLOCK_ETH_MAC			1
#define BLOCK_ETH_STATS			2
#define BLOCK_ETH_GBL			3
#define BLOCK_ETH_FFDIV			4
#define BLOCK_ETH_MAC_GBL		5
#define BLOCK_ETH_PTP			6
#define BLOCK_ETH_UNISEC		7
#define BLOCK_ETH_DIAG			8
#define BLOCK_ETH_QMI_SLAVE		9
#define BLOCK_ETH_MACIP_IND		10
#define BLOCK_RGMII			11
#define BLOCK_ETH_INTPHY		12
#define BLOCK_ETH_EXTPHY		13
#define BLOCK_ETH_MAX			14

/* Indirect Address mode */
#define BLOCK_ETH_MAC_OFFSET		0x0
#define BLOCK_ETH_STATS_OFFSET		0x14

/* Direct Adress mode */
#define ETH_DIR_GLOBAL_BASE		0xddd8a0800
#define BLOCK_ETH_FFDIV_OFFSET		0X0	/* 0xd.dd8a08xx */
#define BLOCK_ETH_PTP_OFFSET		0X800	/* 0xd.dd8a10xx */
#define BLOCK_ETH_UNISEC_OFFSET		0X1000	/* 0xd.dd8a18xx */
#define BLOCK_ETH_GBL_OFFSET		0X1800	/* 0xd.dd8a20xx */
#define BLOCK_ETH_MAC_GBL_OFFSET	0X2000	/* 0xd.dd8a28xx */
#define BLOCK_ETH_DIAG_OFFSET		0X6800	/* 0xd.dd8a70xx */
#define BLOCK_ETH_QMI_SLAVE_OFFSET	0X7000	/* 0xd.dd8a78xx */

/* Constants for indirect registers */
#define MAC_ADDR_REG_OFFSET		0
#define MAC_COMMAND_REG_OFFSET		4
#define MAC_WRITE_REG_OFFSET		8
#define MAC_READ_REG_OFFSET		12
#define MAC_COMMAND_DONE_REG_OFFSET	16

#define STAT_ADDR_REG_OFFSET		0
#define STAT_COMMAND_REG_OFFSET		4
#define STAT_WRITE_REG_OFFSET		8
#define STAT_READ_REG_OFFSET		12
#define STAT_COMMAND_DONE_REG_OFFSET	16

#define MAX_LOOP_POLL_TIMEMS		500
#define MAX_LOOP_POLL_CNT		10
#define ACCESS_DELAY_TIMEMS	(MAX_LOOP_POLL_TIMEMS / MAX_LOOP_POLL_CNT)

#define DRV_VERSION			"1.0"

#if 0
#define PCM_LOOPBACK
#endif

#define HW_MTU(m) ((m) + 14 + 4 + 4 /* MAC + VLAN + CRC */)
#define SPEED_0		 	0xffff
#define SPEED_10	    	10
#define SPEED_100	     	100
#define SPEED_1000	     	1000
#define HALF_DUPLEX	     	1
#define FULL_DUPLEX	     	2
#define  PHY_MODE_RGMII		0
#define  PHY_MODE_SGMII		1


/* ===== MII definitions ===== */

#define MII_CRC_LEN		0x4	/* CRC length in bytes */
#define MII_ETH_MAX_PCK_SZ      (ETHERMTU + SIZEOF_ETHERHEADER          \
				 + MII_CRC_LEN)
#define MII_MAX_PHY_NUM		0x20	/* max number of attached PHYs */
#define MII_MAX_REG_NUM         0x20    /* max number of registers */

#define MII_CTRL_REG		0x0	/* Control Register */
#define MII_STAT_REG		0x1	/* Status Register */
#define MII_PHY_ID1_REG		0x2	/* PHY identifier 1 Register */
#define MII_PHY_ID2_REG		0x3	/* PHY identifier 2 Register */
#define MII_AN_ADS_REG		0x4	/* Auto-Negotiation 	  */
					/* Advertisement Register */
#define MII_AN_PRTN_REG		0x5	/* Auto-Negotiation 	    */
					/* partner ability Register */
#define MII_AN_EXP_REG		0x6	/* Auto-Negotiation   */
					/* Expansion Register */
#define MII_AN_NEXT_REG		0x7	/* Auto-Negotiation 	       */
					/* next-page transmit Register */

#define MII_AN_PRTN_NEXT_REG	0x8  /* Link partner received next page */
#define MII_MASSLA_CTRL_REG	0x9  /* MATER-SLAVE control register */
#define MII_MASSLA_STAT_REG	0xa  /* MATER-SLAVE status register */
#define MII_EXT_STAT_REG	0xf  /* Extented status register */

/* MII control register bit  */

#define MII_CR_1000		0x0040		/* 1 = 1000mb when
						   MII_CR_100 is also 1 */
#define MII_CR_COLL_TEST	0x0080		/* collision test */
#define MII_CR_FDX		0x0100		/* FDX =1, half duplex =0 */
#define MII_CR_RESTART		0x0200		/* restart auto negotiation */
#define MII_CR_ISOLATE		0x0400		/* isolate PHY from MII */
#define MII_CR_POWER_DOWN	0x0800		/* power down */
#define MII_CR_AUTO_EN		0x1000		/* auto-negotiation enable */
#define MII_CR_100		0x2000		/* 0 = 10mb, 1 = 100mb */
#define MII_CR_LOOPBACK		0x4000		/* 0 = normal, 1 = loopback */
#define MII_CR_RESET		0x8000		/* 0 = normal, 1 = PHY reset */
#define MII_CR_NORM_EN		0x0000		/* just enable the PHY */
#define MII_CR_DEF_0_MASK       0xca7f          /* they must return zero */
#define MII_CR_RES_MASK       	0x003f          /* reserved bits,return zero */

/* MII Status register bit definitions */

#define MII_SR_LINK_STATUS	0x0004       	/* link Status -- 1 = link */
#define MII_SR_AUTO_SEL		0x0008       	/* auto speed select capable */
#define MII_SR_REMOTE_FAULT     0x0010      	/* Remote fault detect */
#define MII_SR_AUTO_NEG         0x0020      	/* auto negotiation complete */
#define MII_SR_EXT_STS		0x0100		/* extended sts in reg 15 */
#define MII_SR_T2_HALF_DPX	0x0200		/* 100baseT2 HD capable */
#define MII_SR_T2_FULL_DPX	0x0400		/* 100baseT2 FD capable */
#define MII_SR_10T_HALF_DPX     0x0800     	/* 10BaseT HD capable */
#define MII_SR_10T_FULL_DPX     0x1000    	/* 10BaseT FD capable */
#define MII_SR_TX_HALF_DPX      0x2000    	/* TX HD capable */
#define MII_SR_TX_FULL_DPX      0x4000     	/* TX FD capable */
#define MII_SR_T4               0x8000    	/* T4 capable */
#define MII_SR_ABIL_MASK        0xff80    	/* abilities mask */
#define MII_SR_EXT_CAP          0x0001    	/* extended capabilities */
#define MII_SR_SPEED_SEL_MASK 	0xf800           /* Mask to extract just speed
                                                  * capabilities  from status
                                                  * register.
                                                  */

/*  MII ID2 register bit mask */

#define MII_ID2_REVISON_MASK    0x000f
#define MII_ID2_MODE_MASK       0x03f0

/* MII AN advertisement Register bit definition */

#define MII_ANAR_10TX_HD        0x0020
#define MII_ANAR_10TX_FD        0x0040
#define MII_ANAR_100TX_HD       0x0080
#define MII_ANAR_100TX_FD       0x0100
#define MII_ANAR_100T_4         0x0200
#define MII_ANAR_PAUSE          0x0400
#define MII_ANAR_ASM_PAUSE      0x0800
#define MII_ANAR_REMORT_FAULT   0x2000
#define MII_ANAR_NEXT_PAGE      0x8000
#define MII_ANAR_PAUSE_MASK     0x0c00

/* MII Link Code word  bit definitions */

#define MII_BP_FAULT	0x2000       	/* remote fault */
#define MII_BP_ACK	0x4000       	/* acknowledge */
#define MII_BP_NP	0x8000       	/* nexp page is supported */

/* MII Next Page bit definitions */

#define MII_NP_TOGGLE	0x0800       	/* toggle bit */
#define MII_NP_ACK2	0x1000       	/* acknowledge two */
#define MII_NP_MSG	0x2000       	/* message page */
#define MII_NP_ACK1	0x4000       	/* acknowledge one */
#define MII_NP_NP	0x8000       	/* nexp page will follow */

/* MII Expansion Register bit definitions */

#define MII_EXP_FAULT	0x0010       	/* parallel detection fault */
#define MII_EXP_PRTN_NP	0x0008       	/* link partner next-page able */
#define MII_EXP_LOC_NP	0x0004       	/* local PHY next-page able */
#define MII_EXP_PR	0x0002       	/* full page received */
#define MII_EXP_PRT_AN	0x0001       	/* link partner auto negotiation able */

/* MII Master-Slave Control register bit definition */

#define MII_MASSLA_CTRL_1000T_HD    0x100
#define MII_MASSLA_CTRL_1000T_FD    0x200
#define MII_MASSLA_CTRL_PORT_TYPE   0x400
#define MII_MASSLA_CTRL_CONFIG_VAL  0x800
#define MII_MASSLA_CTRL_CONFIG_EN   0x1000

/* MII Master-Slave Status register bit definition */

#define MII_MASSLA_STAT_LP1000T_HD  0x400
#define MII_MASSLA_STAT_LP1000T_FD  0x800
#define MII_MASSLA_STAT_REMOTE_RCV  0x1000
#define MII_MASSLA_STAT_LOCAL_RCV   0x2000
#define MII_MASSLA_STAT_CONF_RES    0x4000
#define MII_MASSLA_STAT_CONF_FAULT  0x8000

/* MII Extented Status register bit definition */

#define MII_EXT_STAT_1000T_HD       0x1000
#define MII_EXT_STAT_1000T_FD       0x2000
#define MII_EXT_STAT_1000X_HD       0x4000
#define MII_EXT_STAT_1000X_FD       0x8000

/* technology ability field bit definitions */

#define MII_TECH_10BASE_T	0x0020	/* 10Base-T */
#define MII_TECH_10BASE_FD	0x0040	/* 10Base-T Full Duplex */
#define MII_TECH_100BASE_TX	0x0080	/* 100Base-TX */
#define MII_TECH_100BASE_TX_FD	0x0100	/* 100Base-TX Full Duplex */
#define MII_TECH_100BASE_T4	0x0200	/* 100Base-T4 */

#define MII_TECH_PAUSE		0x0400  /* PAUSE */
#define MII_TECH_ASM_PAUSE	0x0800  /* Asym pause */
#define MII_TECH_PAUSE_MASK	0x0c00

#define MII_ADS_TECH_MASK	0x1fe0	/* technology abilities mask */
#define MII_TECH_MASK		MII_ADS_TECH_MASK
#define MII_ADS_SEL_MASK	0x001f	/* selector field mask */

#define MII_AN_FAIL             0x10    /* auto-negotiation fail */
#define MII_STAT_FAIL           0x20    /* errors in the status register */
#define MII_PHY_NO_ABLE     	0x40    /* the PHY lacks some abilities */

/* MII management frame structure */

#define MII_MF_PREAMBLE		0xffffffff	/* preamble pattern */
#define MII_MF_ST		0x1		/* start of frame pattern */
#define MII_MF_OP_RD		0x2		/* read operation pattern */
#define MII_MF_OP_WR		0x1		/* write operation pattern */

#define MII_MF_PREAMBLE_LEN	0x20		/* preamble lenght in bit */
#define MII_MF_ST_LEN		0x2		/* start frame lenght in bit */
#define MII_MF_OP_LEN		0x2		/* op code lenght in bit */
#define MII_MF_ADDR_LEN		0x5		/* PHY addr lenght in bit */
#define MII_MF_REG_LEN		0x5		/* PHY reg lenght in bit */
#define MII_MF_TA_LEN		0x2		/* turnaround lenght in bit */
#define MII_MF_DATA_LEN		0x10		/* data lenght in bit */

/* defines related to the PHY device */

#define MII_PHY_PRE_INIT    	0x0001          /* PHY info pre-initialized */
#define MII_PHY_AUTO        	0x0010          /* auto-negotiation allowed */
#define MII_PHY_TBL         	0x0020          /* use negotiation table */
#define MII_PHY_100         	0x0040          /* PHY may use 100Mbit speed */
#define MII_PHY_10          	0x0080          /* PHY may use 10Mbit speed */
#define MII_PHY_FD          	0x0100          /* PHY may use full duplex */
#define MII_PHY_HD          	0x0200          /* PHY may use half duplex */
#define MII_PHY_ISO		0x0400          /* isolate all PHYs */
#define MII_PHY_PWR_DOWN    	0x0800          /* power down mode */
#define MII_PHY_DEF_SET		0x1000		/* set a default mode */
#define MII_ALL_BUS_SCAN	0x2000		/* scan the all bus */
#define MII_PHY_MONITOR		0x4000		/* monitor the PHY's status */
#define MII_PHY_INIT		0x8000		/* PHY info initialized */
#define MII_PHY_1000T_FD	0x10000		/* PHY may use 1000-T full duplex */
#define MII_PHY_1000T_HD	0x20000		/* PHY mau use 1000-T half duplex */
#define MII_PHY_TX_FLOW_CTRL	0x40000		/* Transmit flow control */
#define MII_PHY_RX_FLOW_CTRL	0x80000		/* Receive flow control */
#define MII_PHY_GMII_TYPE	0x100000        /* GMII = 1, MII = 0 */
#define MII_PHY_ISO_UNAVAIL	0x200000        /* ctrl reg isolate func not available */

/* miscellaneous defines */

#define MII_PHY_DEF_DELAY   300             /* max delay before link up, etc. */
#define MII_PHY_NO_DELAY    0x0		    /* do not delay */
#define MII_PHY_NULL        0xff            /* PHY is not present */
#define MII_PHY_DEF_ADDR    0x0             /* default PHY's logical address */

#define MII_PHY_LINK_UNKNOWN	0x0       /* link method - Unknown */
#define MII_PHY_LINK_AUTO	0x1       /* link method - Auto-Negotiation */
#define MII_PHY_LINK_FORCE	0x2       /* link method - Force link */

/*
 * these values may be used in the default phy mode field of the load
 * string, since that is used to force the operating mode of the PHY
 * in case any attempt to establish the link failed.
 */

#define PHY_10BASE_T            0x00     /* 10 Base-T */
#define PHY_10BASE_T_FDX        0x01     /* 10 Base Tx, full duplex */
#define PHY_100BASE_TX          0x02     /* 100 Base Tx */
#define PHY_100BASE_TX_FDX      0x03     /* 100 Base TX, full duplex */
#define PHY_100BASE_T4          0x04     /* 100 Base T4 */
#define PHY_AN_ENABLE          	0x05     /* re-enable auto-negotiation */


#define MII_AN_TBL_MAX		20	/* max number of entries in the table */

/* allowed PHY's speeds */
#define MII_1000MBS         1000000000      /* bits per sec */
#define MII_100MBS          100000000       /* bits per sec */
#define MII_10MBS           10000000        /* bits per sec */

/* ===== Realtek PHY definitions ===== */

#define PHY_SPEED_RES   		3
#define PHY_SPEED_1000  		2
#define PHY_SPEED_100   		1
#define PHY_SPEED_10    		0
#define RTL_PHYSR_ADR			0X11
#define RTL_PHYSR_SPEED_RD(src)    	(((src) & 0x0000C000) >> 14)
#define RTL_PHYSR_LINK_RD(src)    	(((src) & 0x00000400) >> 10)

/* LErr Decoding */
#if defined (CONFIG_APM862xx)
enum apm_enet_lerr {
	ENET_NO_ERR = 0,	    /**< No Error */
	ENET_AXI_WR_ERR = 1,	    /**< AXI write data error due to RSIF */
	ENET_ING_CRC_ERR = 2,	    /**< Rx packet had CRC */
	ENET_AXI_RD_ERR = 3,	    /**< AXI read data error when processing
				       a work message in TSIF */
	ENET_LL_RD_ERR = 4,	    /**< AXI Link List read error when
				       processing a work message in TSIF */
	ENET_ING_ERR = 5,	    /**< Rx packet had ingress processing
				       error */
	ENET_CHKSUM_ERR	= 5,	    /**< Checksum error */
	ENET_BAD_MSG_ERR = 6,	    /**< Bad message to subsytem */
	ENET_MISC_ERR = 7,	    /**< Other ingress processing error */
	ENET_MAC_TRUNC_ERR = 7,	    /**< MAX truncated */
	ENET_MAC_LEN_ERR = 8,	    /**< Packet length error */
	ENET_PKT_LESS64_ERR = 9,    /**< MAC length lesser than 64B */
	ENET_MAC_OVERRUN_ERR = 10,  /**< FIFO overrun on ingress */
	ENET_UNISEC_CHKSUM_ERR = 11, /**< Rx pacekt checksum error */
	ENET_UNISEC_LEN_ERR = 12,   /**< Rx pkt length mismatch QM message */
	ENET_UNISEC_ICV_ERR = 13,   /**< Rx pkt ICV error */
	ENET_UNISEC_PROTO_ERR = 14, /**< Rx pkt protocol field mismatch */
	ENET_FP_TIMEOUT_ERR = 15    /**< Free pool buffer timeout */
};
#else
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
enum apm_enet_lerr {
	ENET_NO_ERR = 0,	    /**< No Error */
	ENET_AXI_WR_ERR = 1,	    /**< AXI write data error due to RSIF */
	ENET_ING_CRC_ERR = 16,	    /**< Rx packet had CRC */
	ENET_AXI_RD_ERR = 3,	    /**< AXI read data error when processing
				       a work message in TSIF */
	ENET_LL_RD_ERR = 4,	    /**< AXI Link List read error when
				       processing a work message in TSIF */
	ENET_ING_ERR = 5,	    /**< Rx packet had ingress processing
				       error */
	ENET_CHKSUM_ERR	= 17,	    /**< Checksum error */
	ENET_BAD_MSG_ERR = 6,	    /**< Bad message to subsytem */
	ENET_MISC_ERR = 7,	    /**< Other ingress processing error */
	ENET_MAC_TRUNC_ERR = 18,	    /**< MAX truncated */
	ENET_MAC_LEN_ERR = 19,	    /**< Packet length error */
	ENET_PKT_LESS64_ERR = 20,    /**< MAC length lesser than 64B */
	ENET_MAC_OVERRUN_ERR = 21,  /**< FIFO overrun on ingress */
	ENET_UNISEC_CHKSUM_ERR = 22, /**< Rx pacekt checksum error */
	ENET_UNISEC_LEN_ERR = 23,   /**< Rx pkt length mismatch QM message */
	ENET_UNISEC_ICV_ERR = 24,   /**< Rx pkt ICV error */
	ENET_UNISEC_PROTO_ERR = 25, /**< Rx pkt protocol field mismatch */
	ENET_FP_TIMEOUT_ERR = 15    /**< Free pool buffer timeout */
};
#endif
#endif

	/* Ethernet private structure */
struct apm_data_priv {
	u32 mac_base_addr_v;	    /**< Virtual base addr of MAC */
	u32 stats_base_addr_v;	    /**< Virtual base addr of STAT */
	u32 eth_gbl_base_addr_v;    /**< Virtual base addr of ENET Global */
	u32 eth_ffdiv_base_addr_v;  /**< Virtual base addr of FFDIV  */
	u32 mac_gbl_base_addr_v;    /**< Virtual base addr of MAC Global*/
	u32 eth_ptp_base_addr_v;    /**< Virtual base addr of PTP*/
	u32 eth_unisec_base_addr_v; /**< Virtual base addr of ENET UNISEC*/
	u32 eth_diag_base_addr_v;   /**< Virtual base addr of DIAG */
	u32 eth_qmi_base_addr_v;    /**< Virtual base addr of ENET QMI*/
	u32 enet_mii_base_addr_v;   /**< Virtual base addr of ENET MII*/
	u64 paddr_base;		    /**< Base physical address of device */
	u32 vaddr_base;		    /**< Base Virtual address for the device */
	u64 ppaddr_base;	    /**< Per port physical address of device */
	u32 vpaddr_base;	    /**< Per port Virtual address of device */

	u32 phy_addr;		    /**< Virtual address for PHY */
	u32 port;		    /**< Port Id */
	u32 speed;		    /**< Forced Link Speed */
	u32 phy_mode;		    /**< PHY mode */
	u32 crc;		    /**< CRC enable / disable */

	/* Register read/write function pointers */
	int (*enet_write32)(struct apm_data_priv *priv, u8 block_id,
			    u32 reg_offset, u32 value);
	int (*enet_read32)(struct apm_data_priv *priv, u8 block_id,
			   u32 reg_offset, u32 *value);
};

/* Generic read/write APIs */
static inline int apm_emac_read32(struct apm_data_priv *priv, u8 block_id,
				 u32 reg_offset, u32 *value)
{
	return (*(priv->enet_read32))(priv, block_id, reg_offset, value);
}

static inline int apm_emac_write32(struct apm_data_priv *priv, u8 block_id,
				  u32 reg_offset, u32 value)
{
	return (*(priv->enet_write32))(priv, block_id, reg_offset, value);
}

/* Statistics related variables */

/* Normal TX/RX Statistics */
struct apm_emac_stats {
	u64 rx_packets;
	u64 rx_bytes;
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets_csum;
	u64 tx_packets_csum;
	u64 pkts_handled;
	u64 data_len_err;
	short tx_err_log[MAX_ERR_LOG];
	short rx_err_log[MAX_ERR_LOG];
};

/* Error TX/RX Statistics */
struct apm_emac_error_stats {
	/* Software RX Errors */
	u64 rx_dropped_stack;
	u64 rx_dropped_error;
	u64 rx_dropped_mtu;

	/* HW reported RX errors */
	u64 rx_hw_errors;
	u64 rx_hw_overrun;
	u64 rx_hw_bad_packet;
	u64 rx_bd_bad_fcs;

	/* EMAC IRQ reported RX errors */
	u64 rx_parity;
	u64 rx_fifo_overrun;
	u64 rx_overrun;
	u64 rx_bad_packet;
	u64 rx_bus_err;

	/* Software TX Errors */
	u64 tx_dropped;
	/* HW reported TX errors */
	u64 tx_hw_errors;
	u64 tx_hw_bad_fcs;
	u64 tx_hw_underrun;

	/* EMAC IRQ reported TX errors */
	u64 tx_parity;
	u64 tx_underrun;
	u64 tx_errors;
	u64 tx_bus_err;
};

/**
 * @struct  eth_frame_stats
 * @brief   This is the transmit and receive frames combine statistics
 **
 */
struct eth_frame_stats {
	u32 c_64B_frames;	/**< Tx & Rx 64 Byte	Frame Counter */
	u32 c_65_127B_frames;	/**< Tx & Rx 65 to 127 Byte Frame Counter */
	u32 c_128_255B_frames;	/**< Tx & Rx 128 to 255 Byte Frame Counter */
	u32 c_256_511B_frames;	/**< Tx & Rx 256 to 511 Byte Frame Counter */
	u32 c_512_1023B_frames;	/**< Tx & Rx 512 to 1023 Byte Frame Counter */
	u32 c_1024_1518B_frames;/**< Tx & Rx 1024 to 1518 Byte Frame Counter */
	u32 c_1519_1522B_frames;/**< Tx & Rx 1519 to 1522 Byte Frame Counter */
};

/**
 * @struct  eth_rx_stats
 * @brief   This is the receive frames statistics
 **
 */
struct eth_rx_stat {
	u32 rx_byte_count;	/**< Receive Byte Counter */
	u32 rx_packet_count;	/**< Receive Packet Counter */
	u32 rx_fcs_err_count;	/**< Receive FCS Error Counter */
	u32 rx_multicast_pkt_count;	/**< Receive Multicast Packet Counter */
	u32 rx_broadcast_pkt_count;	/**< Receive Broadcast Packet Counter */
	u32 rx_cntrl_frame_pkt_count;	/**< Rx Control Frame Packet Counter */
	u32 rx_pause_frame_pkt_count;	/**< Rx Pause Frame Packet Counter */
	u32 rx_unknown_op_pkt_count;	/**< Rx Unknown Opcode Packet Counter */
	u32 rx_alignment_err_pkt_count;	/**< Rx Alignment Err Packet Counter */
	u32 rx_frm_len_err_pkt_count;	/**< Rx Frame Len Err Packet Counter */
	u32 rx_code_err_pkt_count;	/**< Rx Code Error Packet Counter */
	u32 rx_carrier_sense_err_pkt_count;	/**< Rx Carrier Sense Err Pkt*/
	u32 rx_undersize_pkt_count;	/**< Receive Undersize Packet Counter */
	u32 rx_oversize_pkt_count;	/**< Receive Oversize Packet Counter */
	u32 rx_fragment_count;	/**< Receive Fragment Counter */
	u32 rx_jabber_count;	/**< Receive Jabber Counter */
	u32 rx_drop_pkt_count;	/**< Receive Drop Packet Counter */
};

/**
 * @struct  eth_tx_stats
 * @brief   This is the transmit frames statistics
 **
 */
struct eth_tx_stats {
	u32 tx_byte_count;		/**< Tx Byte cnt */
	u32 tx_pkt_count;		/**< Tx pkt cnt */
	u32 tx_multicast_pkt_count;	/**< Tx Multicast Pkt cnt */
	u32 tx_broadcast_pkt_count;	/**< Tx Broadcast pkt cnt */
	u32 tx_pause_frame_count;	/**< Tx Pause Control Frame cnt */
	u32 tx_deferral_pkt_count;	/**< Tx Deferral pkt cnt */
	u32 tx_exesiv_def_pkt_count;	/**< Tx Excessive Deferral pkt cnt */
	u32 tx_single_coll_pkt_count;	/**< Tx Single Collision pkt cnt */
	u32 tx_multi_coll_pkt_count;	/**< Tx Multiple Collision pkt cnt */
	u32 tx_late_coll_pkt_count;	/**< Tx Late Collision pkt cnt */
	u32 tx_exesiv_coll_pkt_count;	/**< Tx Excessive Collision pkt cnt */
	u32 tx_toll_coll_pkt_count;	/**< Tx Toll Collision pkt cnt */
	u32 tx_pause_frm_hon_count;	/**< Tx Pause Frame Honored cnt */
	u32 tx_drop_frm_count;		/**< Tx Drop Frame cnt */
	u32 tx_jabber_frm_count;	/**< Tx Jabber Frame cnt */
	u32 tx_fcs_err_frm_count;	/**< Tx FCS Error Frame cnt */
	u32 tx_control_frm_count;	/**< Tx Control Frame cnt */
	u32 tx_oversize_frm_count;	/**< Tx Oversize Frame cnt */
	u32 tx_undersize_frm_count;	/**< Tx Undersize Frame cnt */
	u32 tx_fragments_frm_count;	/**< Tx Fragments Frame cnt */
};

/**
 * @struct  eth_brief_stats
 * @brief   This is the brief statistics counts for Ethernet device
 **
 */
struct eth_brief_stats {
	u32 rx_byte_count;		/**< Receive Byte Counter */
	u32 rx_packet_count;		/**< Receive Packet Counter */
	u32 rx_drop_pkt_count;		/**< Receive Drop Packet Counter */
	u32 tx_byte_count;		/**< Transmit Byte Counter */
	u32 tx_pkt_count;		/**< Transmit Packet Counter */
	u32 tx_drop_frm_count;		/**< Transmit Drop Packet Counter */
};

/**
 * @struct  eth_detailed_stats
 * @brief   This is the detailed statistics counts for Ethernet device
 **
 */
struct eth_detailed_stats {
	struct eth_frame_stats eth_combined_stats;
					/**< Tx, Rx combined stats */
	struct eth_rx_stat rx_stats;	/**< Rx statistics */
	struct eth_tx_stats tx_stats;	/**< Tx statistics */
};

/* SGMII related functions */
#define INT_PHY_ADDR	0x1E
#define apm_miiphy_write(priv, reg, data) \
	apm_genericmiiphy_write(priv, INT_PHY_ADDR, reg, data)
#define apm_miiphy_read(prive, reg, data) \
	apm_genericmiiphy_read(priv, INT_PHY_ADDR, reg, data)

/**
 * @brief   This function reads from the MII Manangement registers
 * @param   priv Ethernet private structure
 *	    phy_id Which phy_addr to use
 *	    reg	   Which register to read
 *	    data   Read value copied to this variable
 * @return  0 - success or -1 - failure
 **
 */
int apm_genericmiiphy_read(struct apm_data_priv *priv, u8 phy_id,
			   unsigned char reg, u32 *data);
/**
 * @brief   This function writes to the MII Management registers
 * @param   priv Ethernet private structure
 *	    phy_id Which phy_addr to use
 *	    reg	   Which register to write
 *	    data   Value to be written
 * @return  0 - success or -1 - failure
 **
 */
int apm_genericmiiphy_write(struct apm_data_priv *priv, u8 phy_id,
			    unsigned char reg, u32 data);

/* MAC related APIs */


/**
 * @brief   This function writes into Ethernet CSR
 * @param   priv MAC private stucture
 * @param   block_id  CSR block id within Ethernet
 * @param   reg_offset	Register offset to write
 * @return  value  value to be written
 **
 */
int apm_enet_wr32(struct apm_data_priv *priv, u8 block_id,
		u32 reg_offset, u32 value);

/**
 * @brief   This function reads Ethernet CSR
 * @param   priv MAC private stucture
 * @param   block_id  CSR block id within Ethernet
 * @param   reg_offset	Register offset to read
 * @return  value  Pointer to value
 **
 */
int apm_enet_rd32(struct apm_data_priv *priv, u8 block_id,
		 u32 reg_offset, u32 *value);

/**
 * @brief   This function Enables/Disables Loopback mode in MAC
 * @param   priv MAC private stucture
 * @param   loopback 0 Put it in normal operation
 *			     1 Put it in Loopback operation
 * @return  None
 * @note    Configures the MAC transmit output to be looped back to the
 *		MAC receive input or send it out to TX interface.
 **
 */
void apm_gmac_loopback(struct apm_data_priv *priv, u8 loopback);

/**
 * @brief   This function Enables/Disables Loopback mode in the RGMII MAC
 * @param   priv MAC private stucture
 * @param   loopback 0 Put it in normal operation
 *		     1 Put it in Loopback operation
 * @return  None
 * @note    Configures the MAC transmit output to be looped back to the
 *	    MAC receive input or send it out to TX interface.
 **
 */
void apm_gmac_rgmii_loopback(struct apm_data_priv *priv, u8 loopback);

/**
 * @brief   This function detects receive side flow control enable of MAC
 * @param   priv MAC private stucture
 * @return  0 - success or -1 - failure
 **
 */
int apm_gmac_is_rx_flow_control(struct apm_data_priv *priv);

/**
 * @brief   This function detects Transmit side flow control enable of MAC
 * @param   priv MAC private stucture
 * @return  0 - success or -1 - failure
 **
 */
int apm_gmac_is_tx_flow_control(struct apm_data_priv *priv);

/**
 * @brief   This function Enables/Disables Receive side flow control of MAC
 * @param   priv MAC private stucture
 * @param   enable -	0 Disable Receive side flow control
 *			1 Enable Receive side flow control
 * @return  None
 * @note    Enabling Receive side flow control will cause receive MAC
 *	    control to detect and act on PAUSE Flow Control frames.
 *	    Disabling Receive side flow control will cause the Receive MAC
 *	    Control to ignore PAUSE Flow Control frames
 **
 */
void apm_gmac_rx_flow_control(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function Enables/Disables Transmit side flow control of MAC
 * @param   priv MAC private stucture
 * @param   enable  0 Disable Transmit side flow control
 *		     1 Enable Transmit side flow control
 * @return  0 - success or -1 - failure
 * @note    Enabling Transmit side flow control will allow the PETMC
 *	    Transmit MAC Control to send PAUSE Flow Control frames when
 *	    requested by the system. Disabling Transmit side flow control
 *	    will prevent the Transmit MAC Control from sending Flow
 *	    Control frames.
 **
*/
void apm_gmac_tx_flow_control(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function determine if Receive interface of MAC enabled
 * @param   priv MAC private stucture
 * @return  1 if enabled. Otherwise, 0.
 **
 */
int apm_gmac_is_rx_enable(struct apm_data_priv *priv);

/**
 * @brief   This function Enables Receive interface of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    Enabling MAC Receive interface will allow the MAC
 *	    to receive frames from the PHY. Disabling MAC Receive
 *	    interface will prevent the reception of frames.
 **
 */
void apm_gmac_rx_enable(struct apm_data_priv *priv);

/**
 * @brief   This function Disables Receive interface of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    Disabling MAC Receive interface will prevent the reception of
 *	    frames.
 **
 */
void apm_gmac_rx_disable(struct apm_data_priv *priv);

/**
 * @brief   This function Enables Transmit interface of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    Enabling MAC Transmit interface will allow the MAC to transmit
 *	    frames from the system. Disabling MAC Transmit interface will
 *	    prevent the transmission of frames.
 **
 */
void apm_gmac_tx_enable(struct apm_data_priv *priv);

/**
 * @brief   This function Disables Transmit interface of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    Disabling MAC Transmit interface will prevent the transmission
 *	    of frames.
 **
 */
void apm_gmac_tx_disable(struct apm_data_priv *priv);

/**
 * @brief   This function sets the preamble length of the packet
 * @param   priv MAC private stucture
 * @param   preamble_length Preamble Length to be set
 * @return  None
 * @note    It sets the length of the preamble field of the packet, in bytes
 **
*/
void apm_gmac_set_preamble_length(struct apm_data_priv *priv, u8 length);

/**
 * @brief   This function sets the interface mode
 * @param   priv MAC private stucture
 * @param   intf_mode Type of interface
 *		1  Nibble Mode (10/100 Mbps MII/RMII/SMII,...)
 *		2  Byte Mode (1000 Mbps GMII/TBI)
 * @return  None
 * @note    It sets the type of interface the MAC is connected to.
 **
 */
void apm_gmac_set_intf_mode(struct apm_data_priv *priv, u8 intf_mode);


/**
 * @brief   This function gets the interface mode
 * @param   priv MAC private stucture
  *
 * @return  Interface type
 * @note    It gets the type of interface the MAC is connected to.
 **
 */
int  apm_gmac_get_intf_mode(struct apm_data_priv *priv);

/**
 * @brief   This function enables/disables the huge frame support
 * @param   priv MAC private stucture
 * @param   enable Enable/Disable the huge frame support
 *		0  Disable
 *		1  Enable
 * @return  None
 * @note    Enabling it allows frames longer than the MAXIMUM FRAME LENGTH
 *	    to be transmitted and received. Disable it to have the MAC
 *	    limit the length of frames at the MAXIMUM FRAME LENGTH value.
 **
 */
void apm_gmac_huge_frame_enable(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function enables/disables the length field checking in MAC
 * @param   priv MAC private stucture
 * @param   enable Enable/Disable the len field checking
 *		0  Disable
 *		1  Enable
 * @return  None
 * @note    Enabling it will cause the MAC to check the frame<92>s length
 *	    field to ensure it matches the actual data field length.
 *	    Disable it if no length field checking is desired.
 **
 */
void apm_gmac_len_field_check_enable(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function enables/disables the padding and crc of the frames
 * @param   priv MAC private stucture
 * @param   enable Enable/Disable
 *		0  Disable
 *		1  Enable
 * @return  None
 * @note    Enabling it will cause the MAC to pad all short frames and
 *	    append a CRC to every frame whether or not padding was
 *	    required. Disable it if frames presented to the MAC have a
 *	    valid length and contain a CRC.
 **
 */
void apm_gmac_pad_crc_enable(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function returns pad crc mode set.
 * @param   priv MAC private stucture
 * @return  Pad CRC bit value
 *
 **
 */
int  apm_gmac_get_pad_crc_mode(struct apm_data_priv *priv);

/**
 * @brief   This function enables/disables the crc to be appended to the frames
 * @param   priv MAC private stucture
 * @param   enable Enable/Disable
 *		0  Disable
 *		1  Enable
 * @return  None
 * @note    Enabling it will cause the MAC append a CRC to all frames.
 *	    Disable it if frames presented to the MAC have a valid length
 *	    and contain a valid CRC. If the PAD/CRC ENABLE is set, CRC
 *	    ENABLE is ignored. Only either CRC enable field or PAD/CRC enable
 *	    field can be enabled.
 **
 */
void apm_gmac_crc_enable(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function returns crc mode set.
 * @param   priv MAC private stucture
 * @return  CRC bit value
 *
 **
 */
int  apm_gmac_get_crc_mode(struct apm_data_priv *priv);

/**
 * @brief   This function enables/disables the MAC to work in full-duplex mode
 * @param   priv MAC private stucture
 * @param    enable Enable/Disable
 *		0  Disable
 *		1  Enable
 * @return  None
 * @note    Enabling it will cause the MAC to work in full-duplex mode.
 *	    Disabling it will cause MAC to work in Half-Duplex mode.
 **
 */
void apm_gmac_full_duplex_enable(struct apm_data_priv *priv, u8 enable);

/**
 * @brief   This function gets the MAC full-duplex mode
 * @param   priv MAC private stucture
 * @return  0 - success or -1 - failure
 **
 */
int apm_gmac_get_full_duplex_mode(struct apm_data_priv *priv);

/**
 * @brief   This function configures the Minimum InterFrameGap in terms of bits
 * @param   priv MAC private stucture
 * @param   min_ifg Minimum Inter Frame Gap in terms of bits
 * @return  None
 **
 */
void apm_gmac_set_min_ipg(struct apm_data_priv *priv, u16 min_ifg);

/**
 * @brief   Set InterFrameGap in terms of bits
 * @param   priv MAC private stucture
 * @param   ifg Inter Frame Gap in terms of bits
 * @return  None
 *
 */
void apm_gmac_set_ipg(struct apm_data_priv *priv, u16 ipg);

/**
 * @brief   This function configures the Managment clock frequency
 * @param   priv MAC private stucture
 * @param   clk_sel Managment clk freq encoding value
 *		    0 = Source Clock divided by 4
 *		    1 = Source Clock divided by 4
 *		    2 = Source Clock divided by 6
 *		    3 = Source Clock divided by 8
 *		    4 = Source Clock divided by 10
 *		    5 = Source Clock divided by 14
 *		    6 = Source Clock divided by 20
 *		    7 = Source Clock divided by 28
 * @return  None
 **
 */
void apm_gmac_set_mgnt_clock(struct apm_data_priv *priv, u8 clk_sel);

/**
 * @brief   This function resets the TX part of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    It will put the PETMC Transmit MAC Control block in reset.
 *	    This block multiplexes data and Control frame transfers. It
 *	    also responds to XOFF PAUSE Control frames. It will also put
 *	    the PETFN Transmit Function block in reset, which performs the
 *	    frame transmission protocol.
 **
 */
void apm_gmac_tx_reset(struct apm_data_priv *priv);

/**
 * @brief   This function resets the RX part of MAC
 * @param   priv MAC private stucture
 * @return  None
 * @note    It will put Receive MAC Control block in reset. This block
 *	    detects Control frames and contains the pause timers. It will
 *	    also put the Receive Function block in reset. This block
 *	    performs the receive frame protocol.
 **
 */
void apm_gmac_rx_reset(struct apm_data_priv *priv);

/**
 * @brief   This function resets the entire part of MAC
            and minimal init for phy access
 * @param   priv MAC private stucture
 * @return  None
 * @note    It will put both Transmit and Receive MAC Control block
            in reset and then init.
 **
 */
void apm_gmac_reset(struct apm_data_priv *priv);

/**
 * @brief   This function reset the PHY
            and minimal init for phy access
 * @param   priv MAC private stucture
 * @return  None
 */
void apm_gmac_phy_reset(struct apm_data_priv *priv);

/**
 * @brief   This function checks if auto-neg is completed for the PHY
 * @param   priv MAC private stucture
 * @return  1: Yes 0: No
 */
int apm_gmac_phy_autoneg_done(struct apm_data_priv *priv);

/**
 * @brief   This function initializes the PHY
            and minimal init for phy access
 * @param   priv MAC private stucture
 * @param   force flag to force particular speed
 * @param   full_duplex flag to force full duplex (only used when force=TRUE)
 * @param   speed speed to force (only used when force=TRUE)
 * @return  None
 */
void apm_gmac_phy_init(struct apm_data_priv *priv,
			int force,
			int full_duplex,
			int speed);

/**
 * @brief   This function initializes the MAC
 * @param   priv Private structure of MAC
 * @param   dev_addr MAC address
 * @param   The gmac init link speed (i.e. 10 or 100 or 1000 Mbps)
 * @param   Maximum transmission unit
 * @param   CRC enable/disable
 * @return  0 - success or -1 - failure
 **
 */
int apm_gmac_init(struct apm_data_priv *priv, unsigned char *dev_addr, int speed, int mtu, int crc, int reset_mac);

/**
 * @brief   This function changed the MTU of given interface
 * @param   priv MAC private stucture
 * @param   new_mtu New MTU value to set
 * @return  None
 * @note    Used to modify the MTU of given interface
 **
 */
void apm_gmac_change_mtu(struct apm_data_priv *priv, u32 new_mtu);

/**
 * @brief   Retrieve PHY link mode
 * @param   priv MAC private stucture
 * @return  0 - link down or non-zero link okay
 **
 */
void apm_gmac_phy_link_mode(struct apm_data_priv *priv, u32 *speed, u32 *state);

/**
 * @brief   Enable PHY auto scanning for link status
 * @param   priv Device structure of MAC
 * @param   enable 0 for disable or 1 for enable
 * @return  None
 **
 */
int apm_gmac_phy_enable_scan_cycle(struct apm_data_priv *priv, int enable);

/**
 * @brief   This function configures the MAC address of given MAC device
 * @param   priv MAC private stucture
 * @param   mac_addr_hi Higher 4 octects of MAC address
 *	    mac_addr_lo Lower 2 octects of MAC address
 * @return  None.
 **
 */
void apm_gmac_set_gmac_addr(struct apm_data_priv *priv,
			unsigned char *dev_addr);

/* Statistics related functions */

/**
 * @brief   This function returns the brief statistics counts for the device
 * @param   priv Device structure of MAC
 * @param   brief_stats Brief statistics structure to be filled
 * @return  None
 **
 */
void apm_enet_get_brief_stats(struct apm_data_priv *priv,
				struct eth_brief_stats *brief_stats);
/**
 * @brief   This function returns detailed statistics counts for the device
 * @param   priv Device structure of MAC
 * @param   detailed_stats Detailed statistics structure to be filled up
 * @return  None
 **
 */
void apm_enet_get_detailed_stats(struct apm_data_priv *priv,
				struct eth_detailed_stats *detailed_stats);
/**
 * @brief   This function returns tx rx combined statistics counts
 * @param   priv Device structure of MAC
 * @param   eth_frame_stats Tx Rx stats structure to be filled up
 * @return  None
 **
 */
void apm_enet_get_tx_rx_stats(struct apm_data_priv *priv,
				struct eth_frame_stats *eth_tx_rx_stats);
/**
 * @brief   This function returns rx statistics counts for the device
 * @param   priv Device structure of MAC
 * @param   eth_rx_stats Rx stats structure to be filled up
 * @return  None
 **
 */
void apm_enet_get_rx_stats(struct apm_data_priv *priv,
			struct eth_rx_stat *rx_stat);

/**
 * @brief   This function returns tx statistics counts for the device
 * @param   priv Device structure of MAC
 * @param   tx_stats Tx stats structure to be filled up
 * @return  None
 **
 */
void apm_enet_get_tx_stats(struct apm_data_priv *priv,
			struct eth_tx_stats *tx_stats);

/**
 * @brief   This function programs the TCP mss
 * @param   priv Device structure of MAC
 * @param   mss TCP segmentation size
 * @return  None
 **
 */
int apm_enet_change_mss(struct apm_data_priv *priv, int mss);

int apm_enet_mdio_res_lock(struct apm_data_priv *priv, int lock);

#endif	/* __APM_ENET_MAC_H__ */
