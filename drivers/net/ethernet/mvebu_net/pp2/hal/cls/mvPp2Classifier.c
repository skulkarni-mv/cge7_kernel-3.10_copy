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
#include "mvPp2Classifier.h"

int mvPp2ClassifierDefInit()
{

	if (mvPp2ClsInit())
		return MV_ERROR;

#ifdef CONFIG_MV_ETH_PP2_CLS2
	if (mvPp2ClsC2Init())
		return MV_ERROR;
#endif /* CONFIG_MV_ETH_PP2_CLS2 */

#ifdef CONFIG_MV_ETH_PP2_CLS3
	if (mvPp2ClsC3Init())
		return MV_ERROR;
#endif /* CONFIG_MV_ETH_PP2_CLS3 */

#ifdef CONFIG_MV_ETH_PP2_CLS4
	mvPp2ClsC4HwClearAll();
#endif /* CONFIG_MV_ETH_PP2_CLS2 */

#ifdef CONFIG_MV_ETH_PP2_CLS_MC
	mvPp2McHwClearAll();
#endif /* CONFIG_MV_ETH_PP2_CLS_MC */

	return MV_OK;
}



