/* AppliedMicro X-Gene SoC Ethernet Debug Utility
 *
 * Copyright (c) 2014 Applied Micro Circuits Corporation.
 * Authers: Hrishikesh Karanjikar <hkaranjikar@apm.com>
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/mii.h>
#include <linux/phy.h>
#include "xgene_enet_main.h"
#include "xgene_enet_sc_ring.h"
#include "xgene_enet_gmac.h"
#include "xgene_enet_xgmac.h"

#define XGENE_ENET_DEBUG_UTIL_NAME "xgene_enet"

enum xgene_enet_debug_util_blocks {
	XGENE_ENET_GLOBAL_CSR,
	XGENE_ENET_GLOBAL_RING_IF,
	XGENE_ENET_GLOBAL_CLKRST_CSR,
	XGENE_ENET_GLOBAL_DIAG_CSR,
	XGENE_ENET_BLOCK_MAC,
	XGENE_ENET_BLOCK_STATS,
	XGENE_ENET_BLOCK_MAC_CSR,
	XGENE_ENET_BLOCK_RX_RING_MEMORY,
	XGENE_ENET_BLOCK_TX_RING_MEMORY,
	XGENE_ENET_BLOCK_CP_RING_MEMORY,
	XGENE_ENET_BLOCK_BUF_POOL_MEMORY,
	XGENE_ENET_BLOCK_RING_CSR,
	XGENE_ENET_BLOCK_MAX
};

enum xgene_enet_debug_util_debug_cmd {
	XGENE_ENET_DEBUG_UTIL_READ_CMD,
	XGENE_ENET_DEBUG_UTIL_WRITE_CMD
};

static void xgene_enet_debug_util_write_help(void)
{
	pr_info( "echo"
		" <eth_dev_name> <command> <block> <reg> <value> > /proc/%s\n\n"
		" where eth_dev_name: eth0, eth1, etc...\n"
		"    command:\n"
		" \t 0 for read\n"
		" \t 1 for write\n"
		"   block ID:\n"
		" \t 0 ETH CSR\n"
		" \t 1 ETH RING IF\n"
		" \t 2 ETH CLKRST CSR\n"
		" \t 3 ETH DIAG CSR\n"
		" \t 4 MCX/AGX MAC\n"
		" \t 5 MCX/AXG STATS\n"
		" \t 6 MCX/AGX MAC CSR\n"
		" \t 7 RX RING MEMORY\n"
		" \t 8 TX RING MEMORY\n"
		" \t 9 CP RING MEMORY\n"
		" \t10 BUF POOL MEMORY\n"
		" \t11 RING CSR\n\n"
		"        reg is register offset in hex\n"
		"      value is value to write in hex\n",
		XGENE_ENET_DEBUG_UTIL_NAME);
}

static ssize_t xgene_enet_debug_util_read(struct file *file,
		char __user * buf, size_t count, loff_t *ppos)
{
	xgene_enet_debug_util_write_help();
	return 0;
}

static void xgene_enet_debug_util_rd_reg(struct xgene_enet_pdata *pdata, 
			enum xgene_enet_debug_util_blocks block_id, u32 reg)
{
	u32 value = 0;
	struct xgene_enet_desc_ring *rx_ring = pdata->rx_ring[0]; /* TODO */
	struct xgene_enet_desc_ring *tx_ring = pdata->tx_ring[reg];
	struct xgene_enet_desc_ring *cp_ring = tx_ring->cp_ring;
	struct xgene_enet_desc_ring *buf_pool = pdata->rx_ring[0]->buf_pool; /* TODO */

	switch (block_id) {
		case XGENE_ENET_GLOBAL_CSR:
			pdata->enet_rd_wr_ops.rd_enet_csr(pdata, reg, &value);
			break;

		case XGENE_ENET_GLOBAL_RING_IF:
			pdata->enet_rd_wr_ops.rd_ring_if(pdata, reg, &value);
			break;

		case XGENE_ENET_GLOBAL_CLKRST_CSR:
			pdata->enet_rd_wr_ops.rd_clkrst_csr(pdata, reg, &value);
			break;

		case XGENE_ENET_GLOBAL_DIAG_CSR:
			pdata->enet_rd_wr_ops.rd_diag_csr(pdata, reg, &value);
			break;

		case XGENE_ENET_BLOCK_MAC:
			pdata->enet_rd_wr_ops.rd_mac(pdata, reg, &value);
			break;

		case XGENE_ENET_BLOCK_STATS:
			pdata->enet_rd_wr_ops.rd_stats(pdata, reg, &value);
			break;

		case XGENE_ENET_BLOCK_MAC_CSR:
			pdata->enet_rd_wr_ops.rd_mac_csr(pdata, reg, &value);
			break;

		case XGENE_ENET_BLOCK_RX_RING_MEMORY:
			if (rx_ring && pdata->ring_ops.dump_ring_state)
				pdata->ring_ops.dump_ring_state(rx_ring);
			break;
		
		case XGENE_ENET_BLOCK_TX_RING_MEMORY:
			if (tx_ring && pdata->ring_ops.dump_ring_state)
				pdata->ring_ops.dump_ring_state(tx_ring); 
			break;

		case XGENE_ENET_BLOCK_CP_RING_MEMORY:
			if (cp_ring && pdata->ring_ops.dump_ring_state)
				pdata->ring_ops.dump_ring_state(cp_ring); 
			break;

		case XGENE_ENET_BLOCK_BUF_POOL_MEMORY:
			if (buf_pool && pdata->ring_ops.dump_ring_state)
				pdata->ring_ops.dump_ring_state(buf_pool);
			break;

		case XGENE_ENET_BLOCK_RING_CSR:
			if (rx_ring)
				pdata->ring_ops.ring_csr_rd(rx_ring, reg,
						&value);
			break;

		default:
			break;
	}

	pr_info("\n Value = 0X%x \n", value);
}

static void xgene_enet_debug_util_wr_reg(struct xgene_enet_pdata *pdata,
		enum xgene_enet_debug_util_blocks block_id, u32 reg, u32 value)
{
	switch (block_id) {
		case XGENE_ENET_GLOBAL_CSR:
			pdata->enet_rd_wr_ops.wr_enet_csr(pdata, reg, value);
			break;

		case XGENE_ENET_GLOBAL_RING_IF:
			pdata->enet_rd_wr_ops.wr_ring_if(pdata, reg, value);
			break;

		case XGENE_ENET_GLOBAL_CLKRST_CSR:
			pdata->enet_rd_wr_ops.wr_clkrst_csr(pdata, reg, value);
			break;

		case XGENE_ENET_GLOBAL_DIAG_CSR:
			pdata->enet_rd_wr_ops.wr_diag_csr(pdata, reg, value);
			break;

		case XGENE_ENET_BLOCK_MAC:
			pdata->enet_rd_wr_ops.wr_mac(pdata, reg, value);
			break;

		case XGENE_ENET_BLOCK_MAC_CSR:
			pdata->enet_rd_wr_ops.wr_mac_csr(pdata, reg, value);
			break;

		case XGENE_ENET_BLOCK_RING_CSR:
			if (pdata->rx_ring[0])
				pdata->ring_ops.ring_csr_wr(pdata->rx_ring[0], reg,
						value);
			break;

		default:
			pr_info("\n This block is read only. \n");
			break;
	}
}

static ssize_t xgene_enet_debug_util_write(struct file *file, 
		const char __user *buf,
		size_t count, loff_t *ppos)
{
	u32 cmd, value = 0;
	u32 reg_offset;
	u32 block_id;
	char *buffer = (char *)buf;
	char *tok;
	struct net_device *ndev;
	struct xgene_enet_pdata *pdata;

	if ((tok = strsep(&buffer, " ")) == NULL) {
		goto ret_on_err;
 	}
	ndev = dev_get_by_name(&init_net, tok);
	
	if (ndev == NULL) {
        	pr_err("Invalid Eth Device\n");
		goto ret_on_err;
	}
	pdata = netdev_priv(ndev);

	if ((tok = strsep(&buffer, " ")) == NULL) {
		goto ret_on_err;
 	}
	cmd = simple_strtol(tok, NULL, 10);

        if (cmd < XGENE_ENET_DEBUG_UTIL_READ_CMD || 
			cmd > XGENE_ENET_DEBUG_UTIL_WRITE_CMD) {
        	pr_err("Invalid Command\n");
		goto ret_on_err;
        }

	if ((tok = strsep(&buffer, " ")) == NULL) {
		goto ret_on_err;
 	}
	block_id = simple_strtol(tok, NULL, 10);

        if (block_id < XGENE_ENET_GLOBAL_CSR || 
			block_id >= XGENE_ENET_BLOCK_MAX) {
                pr_err("Invalid Block\n ");
		goto ret_on_err;
        }

	if ((tok = strsep(&buffer, " ")) == NULL) {
		goto ret_on_err;
 	}
	reg_offset = simple_strtol(tok, NULL, 16);

	if (cmd == XGENE_ENET_DEBUG_UTIL_WRITE_CMD) {
		if ((tok = strsep(&buffer, " ")) == NULL) {
			goto ret_on_err;
		}
		value = simple_strtol(tok, NULL, 16);
	}

	switch (cmd) {
		case XGENE_ENET_DEBUG_UTIL_READ_CMD:
			xgene_enet_debug_util_rd_reg(pdata, block_id, 
					reg_offset);
			break;

		case XGENE_ENET_DEBUG_UTIL_WRITE_CMD:
			xgene_enet_debug_util_wr_reg(pdata, block_id,
					reg_offset, value);
			break;
	}
	return count;

ret_on_err:
	xgene_enet_debug_util_write_help();
	return count;
}

const struct file_operations xgene_enet_debug_util_fops = {
	.owner = THIS_MODULE,
	.read = xgene_enet_debug_util_read,
	.write = xgene_enet_debug_util_write,
};

static int __init xgene_enet_debug_util_init(void)
{
	if (!proc_create(XGENE_ENET_DEBUG_UTIL_NAME, 0, NULL,
				&xgene_enet_debug_util_fops)) {
		pr_err("%s init failed\n", XGENE_ENET_DEBUG_UTIL_NAME);
		return -1;
	}
	return 0;
}

static void __exit xgene_enet_debug_util_exit(void)
{
	remove_proc_entry(XGENE_ENET_DEBUG_UTIL_NAME, NULL);
}

module_init(xgene_enet_debug_util_init);
module_exit(xgene_enet_debug_util_exit);

MODULE_DESCRIPTION("AppliedMicro X-Gene SoC Ethernet Driver Debug Utility");
MODULE_AUTHOR("Hrishikesh Karanjikar <hkaranjikar@apm.com>");
MODULE_LICENSE("GPL");
