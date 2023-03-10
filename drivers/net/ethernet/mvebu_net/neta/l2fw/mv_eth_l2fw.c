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

#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/interrupt.h>

#ifdef CONFIG_MV_INCLUDE_XOR
#include "xor/mvXor.h"
#include "xor/mvXorRegs.h"
#include "mv_hal_if/mvSysXorApi.h"
#endif /* CONFIG_MV_INCLUDE_XOR */

#include "mvOs.h"
#include "mv_eth_l2fw.h"
#include "gbe/mvNeta.h"
#include "gbe/mvNetaRegs.h"
#include "mvDebug.h"
#ifdef CONFIG_ARCH_MVEBU
#include "mvNetConfig.h"
#else /* CONFIG_ARCH_MVEBU */
#include "ctrlEnv/mvCtrlEnvLib.h"
#endif /* CONFIG_ARCH_MVEBU */

#include "gbe/mvNeta.h"

#ifdef CONFIG_MV_ETH_L2SEC
#include "mv_eth_l2sec.h"
#endif

static int numHashEntries;

struct sk_buff *mv_eth_pool_get(struct bm_pool *pool);

static int mv_eth_ports_l2fw_num;

static L2FW_RULE **l2fw_hash = NULL;

static MV_U32 l2fw_jhash_iv;

#ifdef CONFIG_MV_INCLUDE_XOR
static MV_XOR_DESC *eth_xor_desc;
static MV_LONG      eth_xor_desc_phys_addr;
#endif /* CONFIG_MV_INCLUDE_XOR */

struct eth_port_l2fw **mv_eth_ports_l2fw;
static inline int       mv_eth_l2fw_rx(struct eth_port *pp, int rx_todo, int rxq);
static inline MV_STATUS mv_eth_l2fw_tx(struct sk_buff *skb, struct eth_port *pp, int withXor,
									   struct neta_rx_desc *rx_desc);


static L2FW_RULE *l2fw_lookup(MV_U32 srcIP, MV_U32 dstIP)
{
	MV_U32 hash;
	L2FW_RULE *rule;

	hash = mv_jhash_3words(srcIP, dstIP, (MV_U32) 0, l2fw_jhash_iv);
	hash &= L2FW_HASH_MASK;
	rule = l2fw_hash[hash];

#ifdef CONFIG_MV_ETH_L2FW_DEBUG
	if (rule)
		printk(KERN_INFO "rule is not NULL in %s\n", __func__);
	else
		printk(KERN_INFO "rule is NULL in %s\n", __func__);
#endif
	while (rule) {
		if ((rule->srcIP == srcIP) && (rule->dstIP == dstIP))
			return rule;

		rule = rule->next;
	}

	return NULL;
}

void l2fw_show_numHashEntries(void)
{
	mvOsPrintf("number of Hash Entries is %d \n", numHashEntries);

}


void l2fw_flush(void)
{
	MV_U32 i = 0;
	mvOsPrintf("\nFlushing L2fw Rule Database: \n");
	mvOsPrintf("*******************************\n");
	for (i = 0; i < L2FW_HASH_SIZE; i++)
		l2fw_hash[i] = NULL;
	numHashEntries = 0;
}


void l2fw_rules_dump(void)
{
	MV_U32 i = 0;
	L2FW_RULE *currRule;
	MV_U8	  *srcIP, *dstIP;

	mvOsPrintf("\nPrinting L2fw Rule Database: \n");
	mvOsPrintf("*******************************\n");

	for (i = 0; i < L2FW_HASH_SIZE; i++) {
		currRule = l2fw_hash[i];
		srcIP = (MV_U8 *)&(currRule->srcIP);
		dstIP = (MV_U8 *)&(currRule->dstIP);

		while (currRule != NULL) {
			mvOsPrintf("%u.%u.%u.%u->%u.%u.%u.%u     out port=%d (hash=%x)\n",
				MV_IPQUAD(srcIP), MV_IPQUAD(dstIP),
				currRule->port, i);
			currRule = currRule->next;
		}
	}

}

void l2fw_ports_dump(void)
{
	MV_U32 rx_port = 0;
	struct eth_port_l2fw *ppl2fw;

	mvOsPrintf("\nPrinting L2fw ports Database:\n");
	mvOsPrintf("*******************************\n");

	for (rx_port = 0; rx_port < mv_eth_ports_l2fw_num; rx_port++) {
		ppl2fw = mv_eth_ports_l2fw[rx_port];
		mvOsPrintf("rx_port=%d cmd = %d tx_port=%d lookup=%d xor_threshold = %d\n",
				rx_port, ppl2fw->cmd, ppl2fw->txPort, ppl2fw->lookupEn, ppl2fw->xorThreshold);

	}
}


MV_STATUS l2fw_add(MV_U32 srcIP, MV_U32 dstIP, int port)
{
	L2FW_RULE *l2fw_rule;
	MV_U8	  *srcIPchr, *dstIPchr;

	MV_U32 hash = mv_jhash_3words(srcIP, dstIP, (MV_U32) 0, l2fw_jhash_iv);
	hash &= L2FW_HASH_MASK;
	if (numHashEntries == L2FW_HASH_SIZE) {
		printk(KERN_INFO "cannot add entry, hash table is full, there are %d entires \n", L2FW_HASH_SIZE);
		return MV_ERROR;
	}

	srcIPchr = (MV_U8 *)&(srcIP);
	dstIPchr = (MV_U8 *)&(dstIP);

#ifdef CONFIG_MV_ETH_L2FW_DEBUG
	mvOsPrintf("srcIP=%x dstIP=%x in %s\n", srcIP, dstIP, __func__);
	mvOsPrintf("srcIp = %u.%u.%u.%u in %s\n", MV_IPQUAD(srcIPchr), __func__);
	mvOsPrintf("dstIp = %u.%u.%u.%u in %s\n", MV_IPQUAD(dstIPchr), __func__);
#endif

	l2fw_rule = l2fw_lookup(srcIP, dstIP);
	if (l2fw_rule) {
		/* overwite port */
		l2fw_rule->port = port;
		return MV_OK;
	}

	l2fw_rule = (L2FW_RULE *)mvOsMalloc(sizeof(L2FW_RULE));
	if (!l2fw_rule) {
		mvOsPrintf("%s: OOM\n", __func__);
		return MV_FAIL;
	}
#ifdef CONFIG_MV_ETH_L2FW_DEBUG
	mvOsPrintf("adding a rule to l2fw hash in %s\n", __func__);
#endif
	l2fw_rule->srcIP = srcIP;
	l2fw_rule->dstIP = dstIP;
	l2fw_rule->port = port;

	l2fw_rule->next = l2fw_hash[hash];
	l2fw_hash[hash] = l2fw_rule;
	numHashEntries++;
    return MV_OK;
}


#ifdef CONFIG_MV_INCLUDE_XOR
static void dump_xor(void)
{
	mvOsPrintf(" CHANNEL_ARBITER_REG %08x\n",
		MV_REG_READ(XOR_CHANNEL_ARBITER_REG(1)));
	mvOsPrintf(" CONFIG_REG          %08x\n",
		MV_REG_READ(XOR_CONFIG_REG(1, XOR_CHAN(0))));
	mvOsPrintf(" ACTIVATION_REG      %08x\n",
		MV_REG_READ(XOR_ACTIVATION_REG(1, XOR_CHAN(0))));
	mvOsPrintf(" CAUSE_REG           %08x\n",
		MV_REG_READ(XOR_CAUSE_REG(1)));
	mvOsPrintf(" MASK_REG            %08x\n",
		MV_REG_READ(XOR_MASK_REG(1)));
	mvOsPrintf(" ERROR_CAUSE_REG     %08x\n",
		MV_REG_READ(XOR_ERROR_CAUSE_REG(1)));
	mvOsPrintf(" ERROR_ADDR_REG      %08x\n",
		MV_REG_READ(XOR_ERROR_ADDR_REG(1)));
	mvOsPrintf(" NEXT_DESC_PTR_REG   %08x\n",
		MV_REG_READ(XOR_NEXT_DESC_PTR_REG(1, XOR_CHAN(0))));
	mvOsPrintf(" CURR_DESC_PTR_REG   %08x\n",
		MV_REG_READ(XOR_CURR_DESC_PTR_REG(1, XOR_CHAN(0))));
	mvOsPrintf(" BYTE_COUNT_REG      %08x\n\n",
		MV_REG_READ(XOR_BYTE_COUNT_REG(1, XOR_CHAN(0))));
	mvOsPrintf("  %08x\n\n", XOR_WINDOW_CTRL_REG(1, XOR_CHAN(0))) ;
		mvOsPrintf(" XOR_WINDOW_CTRL_REG      %08x\n\n",
		MV_REG_READ(XOR_WINDOW_CTRL_REG(1, XOR_CHAN(0)))) ;
}
#endif


static int mv_eth_poll_l2fw(struct napi_struct *napi, int budget)
{
	int rx_done = 0;
	MV_U32 causeRxTx;
	struct eth_port *pp = MV_ETH_PRIV(napi->dev);

	STAT_INFO(pp->stats.poll[smp_processor_id()]++);

	/* Read cause register */
	causeRxTx = MV_REG_READ(NETA_INTR_NEW_CAUSE_REG(pp->port)) &
	    (MV_ETH_MISC_SUM_INTR_MASK | MV_ETH_TXDONE_INTR_MASK |
		 MV_ETH_RX_INTR_MASK);

	if (causeRxTx & MV_ETH_MISC_SUM_INTR_MASK) {
		MV_U32 causeMisc;

		/* Process MISC events - Link, etc ??? */
		causeRxTx &= ~MV_ETH_MISC_SUM_INTR_MASK;
		causeMisc = MV_REG_READ(NETA_INTR_MISC_CAUSE_REG(pp->port));

		if (causeMisc & NETA_CAUSE_LINK_CHANGE_MASK)
			mv_eth_link_event(pp, 1);
		MV_REG_WRITE(NETA_INTR_MISC_CAUSE_REG(pp->port), 0);
	}

	causeRxTx |= pp->cpu_config[smp_processor_id()]->causeRxTx;
#ifdef CONFIG_MV_NETA_TXDONE_ISR
	if (causeRxTx & MV_ETH_TXDONE_INTR_MASK) {
		/* TX_DONE process */

		mv_eth_tx_done_gbe(pp,
				(causeRxTx & MV_ETH_TXDONE_INTR_MASK));

		causeRxTx &= ~MV_ETH_TXDONE_INTR_MASK;
	}
#endif /* CONFIG_MV_NETA_TXDONE_ISR */

#if (CONFIG_MV_ETH_RXQ > 1)
	while ((causeRxTx != 0) && (budget > 0)) {
		int count, rx_queue;

		rx_queue = mv_eth_rx_policy(causeRxTx);
		if (rx_queue == -1)
			break;

		count = mv_eth_l2fw_rx(pp, budget, rx_queue);
		rx_done += count;
		budget -= count;
		if (budget > 0)
			causeRxTx &=
			 ~((1 << rx_queue) << NETA_CAUSE_RXQ_OCCUP_DESC_OFFS);
	}
#else
	rx_done = mv_eth_l2fw_rx(pp, budget, CONFIG_MV_ETH_RXQ_DEF);
	budget -= rx_done;
#endif /* (CONFIG_MV_ETH_RXQ > 1) */


	if (budget > 0) {
		unsigned long flags;
		causeRxTx = 0;

		napi_complete(napi);
		STAT_INFO(pp->stats.poll_exit[smp_processor_id()]++);

		local_irq_save(flags);
		MV_REG_WRITE(NETA_INTR_NEW_MASK_REG(pp->port),
			(MV_ETH_MISC_SUM_INTR_MASK | MV_ETH_TXDONE_INTR_MASK |
				  MV_ETH_RX_INTR_MASK));

		local_irq_restore(flags);
	}
	pp->cpu_config[smp_processor_id()]->causeRxTx = causeRxTx;

	return rx_done;
}


void mv_eth_set_l2fw(struct eth_port_l2fw *ppl2fw, int cmd, int rx_port, int tx_port)
{
	struct eth_port *pp;
	struct net_device *dev;
	int group;

#ifndef CONFIG_MV_ETH_L2SEC
	if (cmd == CMD_L2FW_CESA) {
		mvOsPrintf("Invalid command (%d) - Ipsec is not defined (%s)\n", cmd, __func__);
		return;
	}
#endif
	pp = mv_eth_ports[rx_port];
	if (!pp) {
		mvOsPrintf("pp is NULL in setting L2FW (%s)\n", __func__);
		return;
	}

	dev = pp->dev;
	if (dev == NULL) {
		mvOsPrintf("device is NULL in setting L2FW (%s)\n", __func__);
		return;
	}
	if (!test_bit(MV_ETH_F_STARTED_BIT, &(pp->flags))) {
		mvOsPrintf("Device is down for port=%d ; MV_ETH_F_STARTED_BIT is not set in %s\n", rx_port, __func__);
		mvOsPrintf("Cannot set to L2FW mode in %s\n", __func__);
		return;
	}

	if (cmd == ppl2fw->cmd) {
		ppl2fw->txPort = tx_port;
		return;
	}

	if ((cmd != CMD_L2FW_DISABLE) && (ppl2fw->cmd != CMD_L2FW_DISABLE) && (ppl2fw->cmd != CMD_L2FW_LAST)) {
		ppl2fw->txPort = tx_port;
		ppl2fw->cmd	= cmd;
		return;
	}

	/*TODO disconnect from linux in case that command != 0, connact back if cmd == 0
	 use netif_carrier_on/netif_carrier_off
	 netif_tx_stop_all_queues/netif_tx_wake_all_queues
	*/

	ppl2fw->txPort = tx_port;
	ppl2fw->cmd	= cmd;

	for (group = 0; group < CONFIG_MV_ETH_NAPI_GROUPS; group++) {
		if (test_bit(MV_ETH_F_STARTED_BIT, &(pp->flags)))
			napi_disable(pp->napiGroup[group]);

		netif_napi_del(pp->napiGroup[group]);

		if (cmd == CMD_L2FW_DISABLE)
			netif_napi_add(dev, pp->napiGroup[group], mv_eth_poll, pp->weight);
		else
			netif_napi_add(dev, pp->napiGroup[group], mv_eth_poll_l2fw, pp->weight);

		if (test_bit(MV_ETH_F_STARTED_BIT, &(pp->flags)))
			napi_enable(pp->napiGroup[group]);
	}

}

inline unsigned char *l2fw_swap_mac(unsigned char *buff)
{
	MV_U16 *pSrc;
	int i;
	MV_U16 swap;
	pSrc = (MV_U16 *)(buff + MV_ETH_MH_SIZE);

	for (i = 0; i < 3; i++) {
		swap = pSrc[i];
		pSrc[i] = pSrc[i+3];
		pSrc[i+3] = swap;
		}

	return  buff;
}

inline void l2fw_copy_mac(unsigned char *rx_buff, unsigned char *tx_buff)
{
	/* copy 30 bytes (start after MH header) */
	/* 12 for SA + DA */
	/* 18 for the rest */
	MV_U16 *pSrc;
	MV_U16 *pDst;
	int i;
	pSrc = (MV_U16 *)(rx_buff);
	pDst = (MV_U16 *)(tx_buff);

	/* swap mac SA and DA */
	for (i = 0; i < 3; i++) {
		pDst[i]   = pSrc[i+3];
		pDst[i+3] = pSrc[i];
		}
	for (i = 6; i < 15; i++)
		pDst[i] = pSrc[i];
}

inline void l2fw_copy_and_swap_mac(unsigned char *rx_buff, unsigned char *tx_buff)
{
	MV_U16 *pSrc;
	MV_U16 *pDst;
	int i;

	pSrc = (MV_U16 *)(rx_buff);
	pDst = (MV_U16 *)(tx_buff);
	for (i = 0; i < 3; i++) {
		pDst[i]   = pSrc[i+3];
		pDst[i+3] = pSrc[i];
	}
}

static inline struct sk_buff *eth_l2fw_copy_packet_withoutXor(struct eth_port *pp, struct sk_buff *skb,
								struct neta_rx_desc *rx_desc)
{
	MV_U8 *pSrc;
	MV_U8 *pDst;
	struct bm_pool *pool;
	struct sk_buff *skb_new;
	int bytes = rx_desc->dataSize - MV_ETH_MH_SIZE;
	int pool_id = NETA_RX_GET_BPID(rx_desc);

	mvOsCacheInvalidate(pp->dev->dev.parent, skb->data, bytes);

	pool = &mv_eth_pool[pool_id];
	skb_new = mv_eth_pool_get(pool);
	if (!skb_new) {
		mvOsPrintf("skb == NULL in %s\n", __func__);
		return NULL;
	}
	pSrc = skb->data + MV_ETH_MH_SIZE;
	pDst = skb_new->data + MV_ETH_MH_SIZE;

	memcpy(pDst+12, pSrc+12, bytes - 12);
	l2fw_copy_and_swap_mac(pSrc, pDst);
	mvOsCacheFlush(NULL, skb->data, bytes);

	return skb_new;
}

#ifdef CONFIG_MV_INCLUDE_XOR
static inline struct sk_buff *eth_l2fw_copy_packet_withXor(struct eth_port *pp, struct sk_buff *skb,
							struct neta_rx_desc *rx_desc)
{
	struct sk_buff *skb_new = NULL;
	struct bm_pool *pool;
	unsigned int bufPhysAddr;
	MV_U8 *pSrc;
	MV_U8 *pDst;
	int pool_id = NETA_RX_GET_BPID(rx_desc);
	int  bytes = rx_desc->dataSize - MV_ETH_MH_SIZE;

	pool = &mv_eth_pool[pool_id];
	skb_new = mv_eth_pool_get(pool);
	if (!skb_new) {
		mvOsPrintf("skb == NULL in %s\n", __func__);
		return NULL;
	}

	/* sync between giga and XOR to avoid errors (like checksum errors in TX)
	   when working with IOCC */

	mvOsCacheIoSync(pp->dev->dev.parent);

	bufPhysAddr =  virt_to_phys(skb->data);
	eth_xor_desc->srcAdd0    = bufPhysAddr + skb_headroom(skb) + MV_ETH_MH_SIZE + 30;
	bufPhysAddr =  virt_to_phys(skb_new->data);
	eth_xor_desc->phyDestAdd = bufPhysAddr + skb_headroom(skb_new) + MV_ETH_MH_SIZE + 30;

	eth_xor_desc->byteCnt    = bytes - 30;

	eth_xor_desc->phyNextDescPtr = 0;
	eth_xor_desc->status         = BIT31;
	/* we had changed only the first part of eth_xor_desc, so flush only one
	 line of cache */
	mvOsCacheLineFlush(pp->dev->dev.parent, eth_xor_desc);
	MV_REG_WRITE(XOR_NEXT_DESC_PTR_REG(1, XOR_CHAN(0)), eth_xor_desc_phys_addr);

	MV_REG_WRITE(XOR_ACTIVATION_REG(1, XOR_CHAN(0)), XEXACTR_XESTART_MASK);

	mvOsCacheLineInv(pp->dev->dev.parent, skb->data);
	pSrc = skb->data + MV_ETH_MH_SIZE;
	pDst = skb_new->data + MV_ETH_MH_SIZE;
	l2fw_copy_mac(pSrc, pDst);
	mvOsCacheLineFlush(pp->dev->dev.parent, skb->data);

	return skb_new;
}

void setXorDesc(void)
{
	unsigned int mode;
	eth_xor_desc = mvOsMalloc(sizeof(MV_XOR_DESC) + XEXDPR_DST_PTR_DMA_MASK + 32);
	eth_xor_desc = (MV_XOR_DESC *)MV_ALIGN_UP((MV_U32)eth_xor_desc, XEXDPR_DST_PTR_DMA_MASK+1);
	eth_xor_desc_phys_addr = mvOsIoVirtToPhys(NULL, eth_xor_desc);
	mvSysXorInit();

	mode = MV_REG_READ(XOR_CONFIG_REG(1, XOR_CHAN(0)));
	mode &= ~XEXCR_OPERATION_MODE_MASK;
	mode |= XEXCR_OPERATION_MODE_DMA;
	MV_REG_WRITE(XOR_CONFIG_REG(1, XOR_CHAN(0)), mode);

    MV_REG_WRITE(XOR_NEXT_DESC_PTR_REG(1, XOR_CHAN(0)), eth_xor_desc_phys_addr);
	dump_xor();
	/* TODO mask xor intterupts*/
}

static inline int xorReady(void)
{
	int timeout = 0;

	while (!(MV_REG_READ(XOR_CAUSE_REG(1)) & XOR_CAUSE_DONE_MASK(XOR_CHAN(0)))) {
		if (timeout > 0x100000) {
			mvOsPrintf("XOR timeout\n");
			return 0;
			}
		timeout++;
	}

	/* Clear int */
	MV_REG_WRITE(XOR_CAUSE_REG(1), ~(XOR_CAUSE_DONE_MASK(XOR_CHAN(0))));

	return 1;
}
#endif /* CONFIG_MV_INCLUDE_XOR */


void l2fw(int cmd, int rx_port, int tx_port)
{
	struct eth_port_l2fw *ppl2fw;
	int max_port = CONFIG_MV_ETH_PORTS_NUM - 1;

	ppl2fw = mv_eth_ports_l2fw[rx_port];

	if ((cmd < CMD_L2FW_DISABLE) || (cmd > CMD_L2FW_LAST)) {
		mvOsPrintf("Error: invalid command %d\n", cmd);
		return;
	}

	if ((rx_port > max_port) || (rx_port < 0)) {
		mvOsPrintf("Error: invalid rx port %d\n", rx_port);
		return;
	}

	if ((tx_port > max_port) || (tx_port < 0)) {
		mvOsPrintf("Error: invalid tx port %d\n", tx_port);
		return;
	}

	pr_info("cmd=%d rx_port=%d tx_port=%d in %s\n", cmd, rx_port, tx_port, __func__);

	mv_eth_set_l2fw(ppl2fw, cmd, rx_port, tx_port);
}

#ifdef CONFIG_MV_INCLUDE_XOR
void l2fw_xor(int rx_port, int threshold)
{
	int max_port = CONFIG_MV_ETH_PORTS_NUM - 1;

	if (rx_port > max_port) {
		mvOsPrintf("Error: invalid rx port %d\n", rx_port);
		return;
	}

	mvOsPrintf("setting port %d threshold to %d in %s\n", rx_port, threshold, __func__);
	mv_eth_ports_l2fw[rx_port]->xorThreshold = threshold;
}
#endif /* CONFIG_MV_INCLUDE_XOR */

void l2fw_lookupEn(int rx_port, int enable)
{
	int max_port = CONFIG_MV_ETH_PORTS_NUM - 1;

	if (rx_port > max_port) {
		mvOsPrintf("Error: invalid rx port %d\n", rx_port);
		return;
	}
	mvOsPrintf("setting port %d lookup mode to %s in %s\n", rx_port, (enable == 1) ? "enable" : "disable", __func__);
	mv_eth_ports_l2fw[rx_port]->lookupEn = enable;
}

void l2fw_stats(void)
{
	int i;
	for (i = 0; i < CONFIG_MV_ETH_PORTS_NUM; i++) {
		mvOsPrintf("number of errors in port[%d]=%d\n", i, mv_eth_ports_l2fw[i]->statErr);
		mvOsPrintf("number of drops  in port[%d]=%d\n", i, mv_eth_ports_l2fw[i]->statDrop);
	}
#ifdef CONFIG_MV_ETH_L2SEC
	mv_l2sec_stats();
#endif
}

static inline MV_STATUS mv_eth_l2fw_tx(struct sk_buff *skb, struct eth_port *pp, int withXor,
									   struct neta_rx_desc *rx_desc)
{
	struct neta_tx_desc *tx_desc;
	u32 tx_cmd = 0;
	struct tx_queue *txq_ctrl;
	unsigned long flags = 0;
	int pool_id;

	/* assigning different txq for each rx port , to avoid waiting on the
	same txq lock when traffic on several rx ports are destined to the same
	outgoing interface */
	int txq = pp->cpu_config[smp_processor_id()]->txq;

	txq_ctrl = &pp->txq_ctrl[pp->txp * CONFIG_MV_ETH_TXQ + txq];

	mv_eth_lock(txq_ctrl, flags);

	if (txq_ctrl->txq_count >= mv_ctrl_txdone)
		mv_eth_txq_done(pp, txq_ctrl);
	/* Get next descriptor for tx, single buffer, so FIRST & LAST */
	tx_desc = mv_eth_tx_desc_get(txq_ctrl, 1);
	if (tx_desc == NULL) {

		mv_eth_unlock(txq_ctrl, flags);

		/*read_unlock(&pp->rwlock);*/
		/* No resources: Drop */
		pp->dev->stats.tx_dropped++;
#ifdef CONFIG_MV_INCLUDE_XOR
		if (withXor)
			xorReady();
#endif /* CONFIG_MV_INCLUDE_XOR */
		return MV_DROPPED;
	}
	txq_ctrl->txq_count++;

	/* Get pool_id */
	pool_id = NETA_RX_GET_BPID(rx_desc);

#ifdef CONFIG_MV_ETH_BM_CPU
	if (MV_NETA_BM_CAP()) {
		tx_cmd |= NETA_TX_BM_ENABLE_MASK | NETA_TX_BM_POOL_ID_MASK(pool_id);
		txq_ctrl->shadow_txq[txq_ctrl->shadow_txq_put_i] = (u32) NULL;
	} else {
		txq_ctrl->shadow_txq[txq_ctrl->shadow_txq_put_i] = (u32) skb;
	}
#else
	txq_ctrl->shadow_txq[txq_ctrl->shadow_txq_put_i] = (u32) skb;
#endif /* CONFIG_MV_ETH_BM_CPU */

	mv_eth_shadow_inc_put(txq_ctrl);

	tx_desc->command = tx_cmd | NETA_TX_L4_CSUM_NOT |
		NETA_TX_FLZ_DESC_MASK | NETA_TX_F_DESC_MASK
		| NETA_TX_L_DESC_MASK |
		NETA_TX_PKT_OFFSET_MASK(NET_SKB_PAD + MV_ETH_MH_SIZE);

	tx_desc->dataSize    = rx_desc->dataSize - MV_ETH_MH_SIZE;
	tx_desc->bufPhysAddr = virt_to_phys(skb->head);

	mv_eth_tx_desc_flush(pp, tx_desc);

#ifdef CONFIG_MV_INCLUDE_XOR
	if (withXor) {
		if (!xorReady()) {
			mvOsPrintf("MV_DROPPED in %s\n", __func__);

			mv_eth_unlock(txq_ctrl, flags);

			/*read_unlock(&pp->rwlock);*/
			return MV_DROPPED;
		}
	}
#endif /* CONFIG_MV_INCLUDE_XOR */
	mv_neta_wmb();
	mvNetaTxqPendDescAdd(pp->port, pp->txp, txq, 1);

	mv_eth_unlock(txq_ctrl, flags);

	return MV_OK;
}


static inline int mv_eth_l2fw_rx(struct eth_port *pp, int rx_todo, int rxq)
{
	struct eth_port  *new_pp;
	L2FW_RULE *l2fw_rule;
	MV_NETA_RXQ_CTRL *rx_ctrl = pp->rxq_ctrl[rxq].q;
	int rx_done, rx_filled;
	struct neta_rx_desc *rx_desc;
	u32 rx_status = MV_OK;
	struct sk_buff *skb, *skb_new = NULL;
	struct bm_pool *pool;
	MV_STATUS status = MV_OK;
	struct eth_port_l2fw *ppl2fw = mv_eth_ports_l2fw[pp->port];
	MV_IP_HEADER *pIph = NULL;
	MV_U8 *pData;
	int	ipOffset;
	int pool_id, bytes;

	rx_done = mvNetaRxqBusyDescNumGet(pp->port, rxq);
	mvOsCacheIoSync(pp->dev->dev.parent);
	if (rx_todo > rx_done)
		rx_todo = rx_done;
	rx_done = 0;
	rx_filled = 0;

	/* Fairness NAPI loop */
	while (rx_done < rx_todo) {
#ifdef CONFIG_MV_ETH_RX_DESC_PREFETCH
		rx_desc = mv_eth_rx_prefetch(pp, rx_ctrl, rx_done, rx_todo);
		if (!rx_desc)
			printk(KERN_INFO "rx_desc is NULL in %s\n", __func__);
#else
		rx_desc = mvNetaRxqNextDescGet(rx_ctrl);
		mvOsCacheLineInv(pp->dev->dev.parent, rx_desc);
		prefetch(rx_desc);
#endif /* CONFIG_MV_ETH_RX_DESC_PREFETCH */

		rx_done++;
		rx_filled++;

		skb = (struct sk_buff *)rx_desc->bufCookie;
		if (!skb) {
			pr_err("%s: skb is NULL, rx_done=%d\n", __func__, rx_done);
			return rx_done;
		}

		pool_id = NETA_RX_GET_BPID(rx_desc);
		pool = &mv_eth_pool[pool_id];
		rx_status = rx_desc->status;
		if (((rx_status & NETA_RX_FL_DESC_MASK) != NETA_RX_FL_DESC_MASK) ||
			(rx_status & NETA_RX_ES_MASK)) {
			STAT_ERR(pp->stats.rx_error++);

			if (pp->dev)
				pp->dev->stats.rx_errors++;

			mv_eth_rxq_refill(pp, rxq, pool, skb, rx_desc);
			continue;
		}

		bytes = rx_desc->dataSize - (MV_ETH_CRC_SIZE + MV_ETH_MH_SIZE);

		pData = skb->head + NET_SKB_PAD;

#ifdef CONFIG_MV_ETH_PNC
		if (MV_NETA_PNC_CAP()) {
			ipOffset = NETA_RX_GET_IPHDR_OFFSET(rx_desc);
		} else {
			if (NETA_RX_IS_VLAN(rx_desc))
				ipOffset = MV_ETH_MH_SIZE + sizeof(MV_802_3_HEADER) + MV_VLAN_HLEN;
			else
				ipOffset = MV_ETH_MH_SIZE + sizeof(MV_802_3_HEADER);
		}
#else
		if (NETA_RX_IS_VLAN(rx_desc))
			ipOffset = MV_ETH_MH_SIZE + sizeof(MV_802_3_HEADER) + MV_VLAN_HLEN;
		else
			ipOffset = MV_ETH_MH_SIZE + sizeof(MV_802_3_HEADER);
#endif

		pIph = (MV_IP_HEADER *)(pData + ipOffset);
		if (pIph == NULL) {
			printk(KERN_INFO "pIph==NULL in %s\n", __func__);
			continue;
		}
#ifdef CONFIG_MV_ETH_L2FW_DEBUG
		if (pIph) {
			MV_U8 *srcIP, *dstIP;
			srcIP = (MV_U8 *)&(pIph->srcIP);
			dstIP = (MV_U8 *)&(pIph->dstIP);
			printk(KERN_INFO "%u.%u.%u.%u->%u.%u.%u.%u in %s\n", MV_IPQUAD(srcIP), MV_IPQUAD(dstIP), __func__);
			printk(KERN_INFO "0x%x->0x%x in %s\n", pIph->srcIP, pIph->dstIP, __func__);
		} else
			printk(KERN_INFO "pIph is NULL in %s\n", __func__);
#endif

		if (ppl2fw->lookupEn) {
			l2fw_rule = l2fw_lookup(pIph->srcIP, pIph->dstIP);

			if (!l2fw_rule) {

#ifdef CONFIG_MV_ETH_L2FW_DEBUG
				printk(KERN_INFO "l2fw_lookup() failed in %s\n", __func__);
#endif

				new_pp  = mv_eth_ports[ppl2fw->txPort];
			} else
				new_pp  = mv_eth_ports[l2fw_rule->port];
		} else
			new_pp  = mv_eth_ports[ppl2fw->txPort];

		switch (ppl2fw->cmd) {
		case CMD_L2FW_AS_IS:
			status = mv_eth_l2fw_tx(skb, new_pp, 0, rx_desc);
			break;

		case CMD_L2FW_SWAP_MAC:
			mvOsCacheLineInv(pp->dev->dev.parent, skb->head + NET_SKB_PAD);
			l2fw_swap_mac(skb->data);
			mvOsCacheLineFlush(pp->dev->dev.parent, skb->head + NET_SKB_PAD);
			status = mv_eth_l2fw_tx(skb, new_pp, 0, rx_desc);
			break;

		case CMD_L2FW_COPY_SWAP:
#ifdef CONFIG_MV_INCLUDE_XOR
			if (bytes >= ppl2fw->xorThreshold) {
				skb_new = eth_l2fw_copy_packet_withXor(pp, skb, rx_desc);
				pr_err("%s: xor is not supported\n", __func__);
			} else
#endif /* CONFIG_MV_INCLUDE_XOR */
			{
				skb_new = eth_l2fw_copy_packet_withoutXor(pp, skb, rx_desc);
				if (skb_new)
					status = mv_eth_l2fw_tx(skb, new_pp, 0, rx_desc);
				else
					status = MV_ERROR;
			}
			break;
#ifdef CONFIG_MV_ETH_L2SEC
		case CMD_L2FW_CESA:
			status = mv_l2sec_handle_esp(pkt, rx_desc, new_pp, pp->port);
			break;
#endif
		default:
			pr_err("WARNING:in %s invalid mode %d for rx port %d\n",
				__func__, ppl2fw->cmd, pp->port);
			mv_eth_rxq_refill(pp, rxq, pool, skb, rx_desc);
		} /*of switch*/

		if (status == MV_OK) {
			if (mv_eth_pool_bm(pool)) {
				/* BM - no refill */
				mvOsCacheLineInv(pp->dev->dev.parent, rx_desc);
			} else {
				if (mv_eth_refill(pp, rxq, pool, rx_desc)) {
					printk(KERN_ERR "%s: Linux processing - Can't refill\n", __func__);
					atomic_inc(&pp->rxq_ctrl[rxq].missed);
				}
			}
			/* we do not need the pkt , we do not do anything with it*/
			if  (ppl2fw->cmd == CMD_L2FW_COPY_SWAP)
				mv_eth_pool_put(pool, skb);

			continue;

		} else if (status == MV_DROPPED) {
			ppl2fw->statDrop++;
			mv_eth_rxq_refill(pp, rxq, pool, skb, rx_desc);
			if (ppl2fw->cmd == CMD_L2FW_COPY_SWAP)
				mv_eth_pool_put(pool, skb_new);

			continue;

		} else if (status == MV_ERROR) {
			ppl2fw->statErr++;
			mv_eth_rxq_refill(pp, rxq, pool, skb, rx_desc);
		}


	} /* of while */

	/* Update RxQ management counters */
	mv_neta_wmb();
	mvNetaRxqDescNumUpdate(pp->port, rxq, rx_done, rx_filled);

	return rx_done;
}

int mv_l2fw_init(void)
{
	int size, port;
	MV_U32 bytes;
	MV_U32 regVal;
	mv_eth_ports_l2fw_num = MV_ETH_MAX_PORTS; /* mvCtrlEthMaxPortGet();*/
	mvOsPrintf("in %s: mv_eth_ports_l2fw_num=%d\n", __func__, mv_eth_ports_l2fw_num);

	size = mv_eth_ports_l2fw_num * sizeof(struct eth_port_l2fw *);
	mv_eth_ports_l2fw = mvOsMalloc(size);
	if (!mv_eth_ports_l2fw)
		goto oom;
	memset(mv_eth_ports_l2fw, 0, size);
	for (port = 0; port < mv_eth_ports_l2fw_num; port++) {
		mv_eth_ports_l2fw[port] =
			mvOsMalloc(sizeof(struct eth_port_l2fw));
		if (!mv_eth_ports_l2fw[port])
			goto oom1;
		mv_eth_ports_l2fw[port]->cmd    = CMD_L2FW_LAST/*CMD_L2FW_DISABLE*/;
		mv_eth_ports_l2fw[port]->txPort = -1;
		mv_eth_ports_l2fw[port]->lookupEn = 0;
		mv_eth_ports_l2fw[port]->xorThreshold = XOR_THRESHOLD_DEF;
		mv_eth_ports_l2fw[port]->statErr = 0;
		mv_eth_ports_l2fw[port]->statDrop = 0;
	}

	bytes = sizeof(L2FW_RULE *) * L2FW_HASH_SIZE;
	l2fw_jhash_iv = mvOsRand();

	l2fw_hash = (L2FW_RULE **)mvOsMalloc(bytes);
	if (l2fw_hash == NULL) {
		mvOsPrintf("l2fw hash: not enough memory\n");
		return MV_NO_RESOURCE;
	}

	mvOsMemset(l2fw_hash, 0, bytes);

	mvOsPrintf("L2FW hash init %d entries, %d bytes\n", L2FW_HASH_SIZE, bytes);
	regVal = 0;
#ifdef CONFIG_MV_ETH_L2SEC
	mv_l2sec_cesa_init();
#endif

#ifdef CONFIG_MV_INCLUDE_XOR
	setXorDesc();
#endif
	return 0;
oom:
	mvOsPrintf("%s: out of memory in L2FW initialization\n", __func__);
oom1:
	mvOsFree(mv_eth_ports_l2fw);
	return -ENOMEM;

}
