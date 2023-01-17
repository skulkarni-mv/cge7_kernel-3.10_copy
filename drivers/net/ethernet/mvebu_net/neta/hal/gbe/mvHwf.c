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

#include "mvCommon.h"		/* Should be included before mvSysHwConfig */
#include "mvTypes.h"
#include "mvDebug.h"
#include "mvOs.h"
#include "mvNeta.h"
#include "bm/mvBm.h"

/*#define HWF_DBG mvOsPrintf*/
#define HWF_DBG(X...)

/*******************************************************************************
* mvNetaHwfInit - Init HWF registers of the port
* DESCRIPTION:
*
* INPUT:
*       int			port - NETA port number
*
* RETURN:   MV_STATUS
*               MV_OK - Success, Others - Failure
*
* NOTE:
*******************************************************************************/
MV_STATUS mvNetaHwfInit(int port)
{
	int					p, txp;
	MV_U32				regVal;
	MV_NETA_PORT_CTRL	*pPortCtrl;

	if ((port < 0) || (port >= mvNetaHalData.maxPort)) {
		mvOsPrintf("%s: port %d is out of range\n", __func__, port);
		return MV_OUT_OF_RANGE;
	}

	pPortCtrl = mvNetaPortHndlGet(port);
	if (pPortCtrl == NULL) {
		mvOsPrintf("%s: port %d is not initialized\n", __func__, port);
		return MV_FAIL;
	}

	/* Set TX Port base addresses */
	for (p = 0; p < mvNetaHalData.maxPort; p++) {
		pPortCtrl = mvNetaPortHndlGet(p);
		if (pPortCtrl == NULL)
			continue;

		for (txp = 0; txp < pPortCtrl->txpNum; txp++) {
			regVal = MV_REG_READ(NETA_HWF_TXP_CFG_REG(port, (p + txp)));
			regVal &= ~NETA_TXP_BASE_ADDR_MASK(p + txp);
			regVal |= ((NETA_TX_REG_BASE(p, txp) >> 10) << NETA_TXP_BASE_ADDR_OFFS(p + txp));
			MV_REG_WRITE(NETA_HWF_TXP_CFG_REG(port, (p + txp)), regVal);
		}
	}
	/* Init HWF RX Control register */
	regVal = NETA_GEM_PID_SRC_FLOW_ID;
	MV_REG_WRITE(NETA_HWF_RX_CTRL_REG(port), regVal);

	/* Set Small TX Gap */
	MV_REG_WRITE(NETA_HWF_TX_GAP_REG(port), NETA_HWF_SMALL_TX_GAP_MASK);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfBmPoolsSet - Set short and long pools to be used by HWF of the port
 *
 * INPUT:
 *       int        port	- port number
 *       int        short_pool	- BM pool for short buffers
 *       int        long_pool	- BM pool for long buffers
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 *******************************************************************************/
MV_STATUS mvNetaHwfBmPoolsSet(int port, int short_pool, int long_pool)
{
	MV_U32 regVal;

	regVal = MV_REG_READ(NETA_HWF_RX_CTRL_REG(port));

	regVal &= ~NETA_HWF_LONG_POOL_MASK;
	regVal |= NETA_HWF_LONG_POOL_ID(long_pool);

	regVal &= ~NETA_HWF_SHORT_POOL_MASK;
	regVal |= NETA_HWF_SHORT_POOL_ID(short_pool);

	MV_REG_WRITE(NETA_HWF_RX_CTRL_REG(port), regVal);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfEnable - Enable / Disable HWF of the port
 * DESCRIPTION:
 *
 * INPUT:
 *       int        port   - port number
 *       int        enable - 0 - disable, 1 - enable
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfEnable(int port, int enable)
{
	MV_U32 regVal;

	regVal = MV_REG_READ(NETA_HWF_RX_CTRL_REG(port));
	if (enable)
		regVal |= NETA_HWF_ENABLE_MASK;
	else
		regVal &= ~NETA_HWF_ENABLE_MASK;

	MV_REG_WRITE(NETA_HWF_RX_CTRL_REG(port), regVal);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfTxqInit - Set TXQ base address and size, set default Drop configuration
 * DESCRIPTION:
 *
 * INPUT:
 *       int        rx_port:            RX port number
 *       int        tx_port, txp, txq:  port, TCONT and TXQ numbers
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfTxqInit(int tx_port, int txp, int txq)
{
	MV_U32				regVal;
	MV_NETA_PORT_CTRL	*pPortCtrl;
	MV_NETA_QUEUE_CTRL	*pQueueCtrl;
	int					port, dropThresh;

	pPortCtrl = mvNetaPortHndlGet(tx_port);
	if (pPortCtrl == NULL) {
		mvOsPrintf("%s: port %d is not initialized\n", __func__, tx_port);
		return MV_NOT_INITIALIZED;
	}

	pQueueCtrl = &pPortCtrl->pTxQueue[txp * CONFIG_MV_ETH_TXQ + txq].queueCtrl;

	if (pQueueCtrl->pFirst == NULL) {
		mvOsPrintf("%s: tx_port=%d, txp=%d, txq=%d is not initialized\n",
					__func__, tx_port, txp, txq);
		return MV_NOT_INITIALIZED;
	}

	for (port = 0; port < mvNetaHalData.maxPort; port++) {

		pPortCtrl = mvNetaPortHndlGet(port);
		if (pPortCtrl == NULL)
			continue;

		regVal = NETA_HWF_TX_PORT_MASK(tx_port + txp) | NETA_HWF_TXQ_MASK(txq);
		MV_REG_WRITE(NETA_HWF_TX_PTR_REG(port), regVal);
		MV_REG_WRITE(NETA_HWF_TXQ_BASE_REG(port), pQueueCtrl->descBuf.bufPhysAddr);
		MV_REG_WRITE(NETA_HWF_TXQ_SIZE_REG(port), pQueueCtrl->lastDesc + 1);

		dropThresh = (CONFIG_MV_ETH_HWF_TXQ_DROP * (pQueueCtrl->lastDesc + 1)) / 100;
		regVal = (dropThresh << NETA_YELLOW_DROP_THRESH_OFFS) |
			    (CONFIG_MV_ETH_HWF_TXQ_DROP_RND << NETA_YELLOW_DROP_RND_GEN_OFFS);

		MV_REG_WRITE(NETA_HWF_DROP_TH_REG(port), regVal);
	}
	return MV_OK;
}

MV_STATUS mvNetaHwfTxqNextIndexGet(int port, int tx_port, int txp, int txq, int *val)
{
	MV_U32				regVal;

	regVal = NETA_HWF_TX_PORT_MASK(tx_port + txp) | NETA_HWF_TXQ_MASK(txq) | NETA_HWF_REG_MASK(3);
	MV_REG_WRITE(NETA_HWF_TX_PTR_REG(port), regVal);

	regVal = MV_REG_READ(NETA_HWF_MEMORY_REG(port));
	if (val)
		*val = (int)((regVal >> 16) & 0x3fff);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfTxqEnable - Enable / Disable HWF from the rx_port to tx_port/txp/txq
 * DESCRIPTION:
 *
 * INPUT:
 *       int        rx_port:            RX port number
 *       int        tx_port, txp, txq:  port, TCONT and TXQ numbers
 *       int        enable:             0 - disable, 1 - enable
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfTxqEnable(int port, int tx_port, int txp, int txq, int enable)
{
	MV_U32 regVal;

	/* Enable HWF for each TXQ */
	regVal = NETA_HWF_TX_PORT_MASK(tx_port + txp) | NETA_HWF_TXQ_MASK(txq);
	MV_REG_WRITE(NETA_HWF_TX_PTR_REG(port), regVal);

	MV_REG_WRITE(NETA_HWF_TXQ_ENABLE_REG(port), enable << NETA_HWF_TXQ_ENABLE_BIT);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfTxqDropSet - Set HWF drop threshold
 * DESCRIPTION:
 *
 * INPUT:
 *       int        rx_port:            RX port number
 *       int        tx_port, txp, txq:  port, TCONT and TXQ numbers
 *       int        thresh, bits		drop configuration
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfTxqDropSet(int port, int tx_port, int txp, int txq, int thresh, int bits)
{
	MV_U32 regVal, dropThresh;
	MV_NETA_PORT_CTRL *pPortCtrl;
	MV_NETA_QUEUE_CTRL *pQueueCtrl;

	pPortCtrl = mvNetaPortHndlGet(tx_port);
	if (pPortCtrl == NULL)
		return MV_FAIL;

	pQueueCtrl = &pPortCtrl->pTxQueue[txp * CONFIG_MV_ETH_TXQ + txq].queueCtrl;
	if (pQueueCtrl->pFirst == NULL)
		return MV_FAIL;

	/* Set HWF Drop parameters for specific TXQ */
	regVal = NETA_HWF_TX_PORT_MASK(tx_port + txp) | NETA_HWF_TXQ_MASK(txq);
	MV_REG_WRITE(NETA_HWF_TX_PTR_REG(port), regVal);

	dropThresh = (thresh * (pQueueCtrl->lastDesc + 1)) / 100;
	regVal = (dropThresh << NETA_YELLOW_DROP_THRESH_OFFS) | (bits << NETA_YELLOW_DROP_RND_GEN_OFFS);

	MV_REG_WRITE(NETA_HWF_DROP_TH_REG(port), regVal);

	return MV_OK;
}

/*******************************************************************************
 * mvNetaHwfMhSrcSet - Select MH source on TX during HWF (PNC or field in
 * 			HWF RX control register.
 * DESCRIPTION:
 *
 * INPUT:
 *       int        port;	port number
 *       int        mh_src; 0 - register field, 1 - PNC result info bits
 *
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfMhSrcSet(int port, MV_NETA_HWF_MH_SRC mh_src)
{
	MV_U32	regVal;

	regVal = MV_REG_READ(NETA_HWF_RX_CTRL_REG(port));

	switch (mh_src) {

	case MV_NETA_HWF_MH_REG:
		regVal &= ~NETA_MH_SRC_PNC_MASK;
		break;

	case MV_NETA_HWF_MH_PNC:
		regVal |= NETA_MH_SRC_PNC_MASK;
		break;

	default:
		mvOsPrintf("port=%d: Unexpected HWF MH source = %d value\n", port, mh_src);
		return MV_BAD_PARAM;
	}
	MV_REG_WRITE(NETA_HWF_RX_CTRL_REG(port), regVal);
	return MV_OK;

}

/*******************************************************************************
 * mvNetaHwfMhSelSet - Set MH value on TX during HWF.
 *
 * DESCRIPTION:
 *
 * INPUT:
 *       int        port;		port number
 *       int        mh_sel_nask;	use the following values as mask
 *					NETA_MH_DONT_CHANGE
 *					NETA_MH_REPLACE_GPON_HDR
 *					NETA_MH_REPLACE_MH_REG(r)
 * RETURN:   MV_STATUS
 *               MV_OK - Success, Others - Failure
 *
 * NOTE:
 *******************************************************************************/
MV_STATUS mvNetaHwfMhSelSet(int port, MV_U8 mh_sel_mask)
{
	MV_U32	regVal;

	regVal = MV_REG_READ(NETA_HWF_RX_CTRL_REG(port));
	regVal &= ~NETA_MH_SEL_MASK;
	regVal |= (mh_sel_mask & NETA_MH_SEL_MASK);

	MV_REG_WRITE(NETA_HWF_RX_CTRL_REG(port), regVal);
	return MV_OK;
}
