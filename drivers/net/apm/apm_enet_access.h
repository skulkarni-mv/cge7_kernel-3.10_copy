/**
 * AppliedMicro APM862xx SoC Ethernet Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Keyur Chudgar <kchudgar@amcc.com>
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
 * @file apm_enet_access.h
 *
 * This file defines access layer for APM862xx SoC Ethernet driver
 *
 */

#ifndef __APM_ENET_ACCESS_H_
#define __APM_ENET_ACCESS_H_

#include <linux/netdevice.h>
#include <asm/apm_qm_core.h>
#include "apm_enet_qm_cfg.h"
#include "apm_enet_mac.h"
#include "apm_enet_misc.h"
#include "apm_enet_tools.h"
#include "apm_enet_csr.h"
#include "apm_enet_ioctl.h"
#include "apm_enet_eee.h"
#include "apm_cle_csr.h"
#include "apm_enet_slimpro_ipfw.h"
#ifdef CONFIG_APM_ENET_QOS
#include "apm_enet_qos.h"
#endif /* CONFIG_APM_ENET_QOS */

#define APM86XXX_ENET_DRIVER_NAME "apm86xxx-enet"
/*
 *  Driver Debug Modes
 */

/* Define to enable ENET driver error reporting */
#define ENET_DBG_ERR
/* Enable for configuration debugging */
#undef ENET_DBG
/* Define to enable queue info debugging */
#undef ENET_Q_DBG
/* Define to enable PHY debugging log */
#undef PHY_DEBUG
/* Define to enable RX log */
#undef ENET_DBGRX
/* Define to enable TX log */
#undef ENET_DBGTX
/* Define to enable RX/TX general log */
#undef ENET_DBGRXTX
/* Define to enable extra error checking */
#define ENET_CHK
/* Define to dump RX/TX packet */
#undef ENET_DUMP_PKT
/* Define to dump QM message */
#undef ENET_DBG_QMSG
/* Define to enable TSO debugging */
#undef ENET_DBG_TSO
/* Define to enable HW buffer pool  debugging */
#undef HW_POOL_DBG
/* Define to enable inline secutiry debugging */
#undef ENET_DBG_SEC
/* Define to enable ENET CSR read debugging */
#undef ENET_DBG_RD
/* Define to enable ENET CSR write debugging */
#undef ENET_DBG_WR
/* Define to enable ENET Offload messages */
#undef ENET_DBG_OFFLOAD
/* Define to debug LRO */
#undef ENET_DBG_LRO
/* Define to debug QoS */
#define ENET_DBG_QOS

/*
 *   Driver operating Modes
 */
#undef SMP_LOAD_BALANCE

/* The TX checksum from Linux to IOS was sometimes not calculated properly
   The test was "ftp connect" to this Linux. Always the same few
   packets would have the checksum wrong (it was neither
   zeroed out nor correct */
#if 0
/* Define to enable IPv4 TX check sum offload */
#define IPV4_TX_CHKSUM
/* Define to enable IPv4 RX check sum offload */
#define IPV4_RX_CHKSUM
#else
#undef IPV4_TX_CHKSUM
#undef IPV4_RX_CHKSUM
#endif
/* Define to enable TCP segmentation offload */
#if !defined(CONFIG_APM862xx)
#define IPV4_TSO		/* require IPV4_TX_CHKSUM & IPV4_RX_CHKSUM */
#else
#undef IPV4_TSO
#endif

/* Define to enable ENET Link IRQ */
#if defined(CONFIG_APM862xx)
#undef ENET_LINK_IRQ
#else
#undef ENET_LINK_IRQ
#endif

/* Define to enable Ethernet Error interrupt support */
#define INT_SUPPORT
/* Define to enable Ethernet Error handler */
#undef INT_ENABLE
/* Define to enable driver loopback mode */
#undef DRIVER_LOOPBACK
/* Define to enable Ethernet MAC loopback mode */
#undef APM_ENET_MAC_LOOPBACK
/* Define to disable completion message notification */
#undef NOTIFICATION_OFF
/* Define to enable buffer pool */
#undef CONFIG_DRIVER_POOL
/* Define to enable packet drop in driver */
#undef DRIVER_DROP
#define CONFIG_NAPI

#undef CONFIG_PAGE_POOL

#undef CONFIG_NET_PROTO

#ifdef CONFIG_SLAB_HW
#define NOTIFICATION_OFF
#endif

#ifdef ENET_DUMP_PKT
#define ENET_DUMP(m, b, l)	print_hex_dump(KERN_INFO, m, \
				DUMP_PREFIX_ADDRESS, 16, 4, b, l, 1);
#else
#define ENET_DUMP(m, b, l)
#endif

#ifdef ENET_DBG_QMSG
#define ENET_QMSG(m, b, l)	print_hex_dump(KERN_INFO, m, \
				DUMP_PREFIX_ADDRESS, 16, 4, b, l, 1);
#else
#define ENET_QMSG(m, b, l)
#endif

#ifdef PHY_DEBUG
#define PHY_PRINT(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define PHY_PRINT(x, ...)
#endif

#ifdef ENET_Q_DBG
#define ENET_DBG_Q(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DBG_Q(x, ...)
#endif

#ifdef APM_ENET_BUF_DEBUG
#define BUFPRINT(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define BUFPRINT(x, ...)
#endif

#ifdef ENET_DBG_TSO
#define ENET_DEBUG_TSO(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_TSO(x, ...)
#endif

#ifdef ENET_DBG_SEC
#define ENET_DEBUG_SEC(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_SEC(x, ...)
#endif

#ifdef HW_POOL_DBG
#define DEBG_HW_POOL(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define DEBG_HW_POOL(x, ...)
#endif

#ifdef ENET_DBG
#define ENET_DEBUG(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUG(x, ...)
#endif

#ifdef ENET_DBGTX
#define ENET_DEBUGTX(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUGTX(x, ...)
#endif

#ifdef ENET_DBGRX
#define ENET_DEBUGRX(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUGRX(x, ...)
#endif

#ifdef ENET_DBGRXTX
#define ENET_DEBUGRXTX(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUGRXTX(x, ...)
#endif

#ifdef ENET_DBG_ERR
#define ENET_DEBUG_ERR(x, ...)	printk(KERN_ERR x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_ERR(x, ...)
#endif

#ifdef ENET_DBG_RD
#define ENET_DEBUG_RD(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_RD(x, ...)
#endif

#ifdef ENET_DBG_WR
#define ENET_DEBUG_WR(x, ...)	printk(KERN_INFO x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_WR(x, ...)
#endif

#ifdef ENET_DBG_OFFLOAD
#define ENET_DEBUG_OFFLOAD(x, ...)	printk(x, ##__VA_ARGS__)
#define ENET_ERROR_OFFLOAD(x, ...)	printk(KERN_ERR x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_OFFLOAD(x, ...)
#define ENET_ERROR_OFFLOAD(x, ...)
#endif

#if defined(ENET_DBG_LRO)
#define ENET_DEBUG_LRO(x, ...)		printk(x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_LRO(x, ...)
#endif

#if defined(ENET_DBG_QOS)
#define ENET_DEBUG_QOS(x, ...)		printk(x, ##__VA_ARGS__)
#else
#define ENET_DEBUG_QOS(x, ...)
#endif

/* SKB reserve size */
#define APM_ENET_SKB_RESERVE_SIZE	(CONFIG_APM_NET_SKB_HEADROOM + NET_IP_ALIGN)

#define APM_ENET_MIN_MTU		64
#define APM_ENET_DEFAULT_MTU		1536
#define APM_ENET_MAX_MTU		10000

/* Note: PKT_BUF_SIZE & PKT_NXTBUF_SIZE has to be one of the following:
 * 256, 1K, 2K, 4K, 16K for ethernet to work with optimum performance.
 */
#define APM_ENET_PKT_BUF_SIZE		2048
#define APM_ENET_PKT_NXTBUF_SIZE	4096

#define MAX_DEVICE_NAME_SIZE		20
/* NAPI parameters */
#define APM_ENET_NAPI_WEIGHT		16
#define APM_ENET_MAX_FRAG		259	/* 4 + 255 LL Buffer */

#ifdef CONFIG_APM_ENET_LRO
#include "apm_enet_lro.h"
#endif /* CONFIG_APM_ENET_LRO */

#ifdef CONFIG_SLAB_HW
#define APM_NO_PKT_BUF		256	  /* Default buffer count unless
					     override via dts */
#define HW_SKB_HEADROOM		128
#elif defined (CONFIG_APM_QOS)
/* APM QoS sets queues as AVB. On congestion state, there is chance of
 * lost packet. Slightly increase room for more packets */
#define APM_NO_PKT_BUF		96	  /* Default buffer count unless
					     override via dts */
#else
#define APM_NO_PKT_BUF		64	  /* Default buffer count unless
					     override via dts */
#endif
#define APM_HW_PKT_BUF		64
#define IPP_PKT_BUF_SIZE	256

#define apm_processor_id()	mfspr(SPRN_PIR)
#define RES_SIZE(r)		((r)->end - (r)->start + 1)

#define get_port_id(ndev) \
		(u32)(((struct apm_enet_dev_base *)netdev_priv(ndev))->port_id)


#define FREE_SKB(skb) dev_kfree_skb_any(skb)

/* Hardware capability and feature flags */
#define FLAG_RX_CSUM_ENABLED 	(1 << 0)

/* For EEE CSR untill header file is fixed */
#define EEE_REG_0                                                    0x00000800
#define EEE_TW_TIMER_0                                               0x00000804
#define EEE_LPI_WAIT_PATTERNS_0                                      0x00000808
#define EEE_REG_1                                                    0x00001000
#define EEE_TW_TIMER_1                                               0x00001004
#define EEE_LPI_WAIT_PATTERNS_1                                      0x00001008
#define EEE_REG_CFG_LPI_MODE                                         0x80000000
#define EEE_REG_CFG_LPI_CLK_STOPPABLE                                0x40000000

#ifdef CONFIG_PM
/* List for storing Ethernet RX MSG before going to suspend */
struct apm_enet_rx_desc {
	struct list_head node;
	struct apm_qm_msg64 msg;
};
#endif

/* define Enet system struct */
struct apm_enet_dev {
	int refcnt;
	int enet_config_done;
	int is_smp;
	int master_cfg;
	u8 apm_preclass_init_done[MAX_PORTS];
	struct timer_list link_poll_timer;
#ifdef PKT_LOSSLESS_WOL
	int wol_qid;
#endif
	int ipp_loaded;
	int ipp_hw_mtu;
};

#define APM_ENET_PM_FLAG_WOL		0x0001
#define APM_ENET_PM_FLAG_CLKGATED	0x0002
#define APM_ENET_PM_FLAG_PWROFF		0x0004
#define APM_ENET_PM_FLAG_PENDINGCLKGATE	0x0008
#define APM_ENET_PM_FLAG_PENDINGCLKEN	0x0010

/* Max limit for Unicast MAC Address filtering */
#define APM_MAX_UNICAST_MACADDR 16

/* Max limit for Multicast MAC Address filtering */
#define APM_MAX_MULTICAST_MACADDR 64

#ifdef CONFIG_INET_OFFLOAD
struct apm_enet_offload_ctx {
	u32 offload_available;		/* SlimPRO available in SoC */
	u32 init_done;			/* Net Offload init done */
	u32 enable;			/* Enabled this feature */
	struct ipp_net_offload_qm qm;
	struct ipp_net_offload_mac mac;
	struct ipp_net_offload_bufdatalen bufdatalen;
};
#endif /* CONFIG_INET_OFFLOAD */

/* List type */
#define UNICAST_LIST		1
#define MULTICAST_LIST		2

struct avl_entry {
	struct	list_head	list;
	unsigned char		addr[6];
	/* Flag type */
#define	AVL_MARK_DEL		1
#define	AVL_MARK_PRESENT	2
	int			flag;
};

/*
 * @struct  apm_enet_dev_base
 * @brief   This is the base private structure assigned in netdev
 *
 */
struct apm_enet_dev_base {
	struct net_device *ndev;
	struct mii_bus *mdio_bus;
	struct phy_device *phy_dev;
	int phy_link;
	int phy_speed;
	int phy_speed_wka_count;
	int phy_link_wka_count;
	struct platform_device *_pdev;
	struct device_node *node;
#ifdef CONFIG_NAPI
	struct napi_struct napi;
#endif
	unsigned int port_id;
	struct apm_emac_stats stats;
	struct apm_emac_error_stats estats;
	struct net_device_stats nstats;
	struct eth_detailed_stats hw_stats;
	struct apm_data_priv priv;
	char *dev_name;
	struct apm_qm_msg_desc in_poll_rx_msg_desc;
	struct apm_qm_msg32 in_poll_rx_msg;
	u32 features;
	unsigned int flags;
	int uc_count;
	struct eth_queue_ids qm_queues[MAX_CORES];
	u32 rx_buff_cnt;
	u32 tx_cqt_low;
	u32 tx_cqt_hi;
	int hdr_rsvd;
	int ipg;	/* non-zero require set */
	int mss;	/* TSO mss */
	struct timer_list q_poll_timer;
	u8 irq_en;
	u8 q_poll_timer_status;
	u8 pb_enabled;
	u8  pm_intf_restart;
	u32 pm_save_rx_enabled;	/* MAC RX enable flag before deep sleep */
	u32 pm_flags;
#ifdef ENET_LINK_IRQ
	u32 link_status;
#endif
#ifdef CONFIG_INET_OFFLOAD
	u32 ethoffload;
	struct apm_enet_offload_ctx offload;
#ifdef CONFIG_APM_ENET_LRO
	struct apm_enet_lro_ctx	lro;
#endif
#endif
#ifdef CONFIG_APM_ENET_SLIMPRO_IPFW
	struct slimpro_ipfw_ctx slimpro_ipfw;
#endif
#ifdef CONFIG_APM_ENET_QOS
	struct apm_enet_qos_ctx qos;
#endif
#ifdef CONFIG_PM
	struct list_head head;
#endif
	/* Use combination of below
	 *  wka_flag = 1 to use MDIO re-read
	 *  wka_flag = 2 to use speed and link re-consideration
	 */
	u32 wka_flag;

	struct list_head mcast_avl_head;
	struct list_head ucast_avl_head;
};

#define Q_POLL_TIMER_OFF	0
#define Q_POLL_TIMER_ON		1
#define Q_POLL_TIMER_STOP	2

/*
 * @struct  apm_data_enet_dev
 * @brief   Private info for ethernet interface
 *
 */
struct apm_data_enet_dev {
	struct apm_enet_dev_base dev_base;
	struct platform_device *pdev;
	unsigned int enet_err_irq;
	unsigned int enet_mac_err_irq;
	unsigned int enet_qmi_err_irq;
	unsigned int hw_config;
};

/*
 * @struct  apm_enet_msg_ext8
 * @brief   This structure represents 8 byte portion of QM extended (64B)
 *	    message format
 *
 */
struct apm_enet_msg_ext8 {
	u32 NxtFPQNum		:8;
	u32 Rv1			:1;
	u32 NxtBufDataLength	:15;
	u32 Rv2			:4;
	u32 NxtDataAddrMSB	:4;
	u32 NxtDataAddrLSB;
}__attribute__ ((packed));

/*
 * @brief   This function returns the port if for given device name.
 * @return  Port Id.
 *
 */
unsigned int find_port(char *device);

/*
 * @brief   This function returns net_device for given port.
 * @return  struct net_device.
 *
 */
struct net_device *find_netdev(int port_id);

/*
 * @brief   This function returns eth_queue_ids for given port and core
 * @return  struct eth_queue_ids
 *
 */
struct eth_queue_ids *find_ethqids(int port_id, int core_id);

/*
 * @brief   This function returns the port if for given device name.
 * @return  Port Id.
 *
 */
static inline struct apm_data_priv *get_priv(void *dev_handle)
{
        struct net_device *ndev = (struct net_device *) dev_handle;
        struct apm_enet_dev_base *pdev = netdev_priv(ndev);
        return &pdev->priv;
}

void apm_enet_set_qidctx(int qid, struct apm_enet_dev_base *priv_dev);
struct apm_enet_dev_base *apm_enet_get_qidctx(int qid);

/*
 * @brief   This function implements IOCTL interface for Ethernet driver.
 * @param   *ndev - Pointer to network device structure
 * @param   *rq - Pointer to interface request structure
 * @param   cmd - IOCTL command.
 * @return  0 - success or -1 - failure
 *
 */
int apm_enet_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd);

int send_snmp_param(void);
int send_netbios_param(void);

static inline int apm_enet_pkt_iscoherent(void)
{
#if defined(CONFIG_APM86xxx_IOCOHERENT)
	return 1;
#elif !defined(CONFIG_NOT_COHERENT_CACHE) && !defined(FAM_BUF_POOL)
	return 1;
#else
	return 0;
#endif
}

int apm_enet_is_smp(void);

#endif /* __APM_ENET_ACCESS_H_ */
