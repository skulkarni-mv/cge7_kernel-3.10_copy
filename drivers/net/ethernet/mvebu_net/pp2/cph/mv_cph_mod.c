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
********************************************************************************/
/********************************************************************************
* mv_cph_mod.c
*
* DESCRIPTION: Marvell CPH(CPH Packet Handler) module definition
*
* DEPENDENCIES:
*               None
*
* CREATED BY:   VictorGu
*
* DATE CREATED: 22Jan2013
*
* FILE REVISION NUMBER:
*               Revision: 1.0
*
*
*******************************************************************************/
#include <linux/module.h>
#include <linux/moduleparam.h>

#include "mv_cph_header.h"

#define CPH_MODULE_VERSION  "22-Jan-2013"
#define CPH_MODULE_DESC     "Marvell CPU Packet Handler Module"

/******************************************************************************
* cph_mod_exit()
* _____________________________________________________________________________
*
* DESCRIPTION: Exit from CPH module
*
* INPUTS:
*       None.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       None.
*******************************************************************************/
static void __exit cph_mod_exit(void)
{
	cph_dev_shutdown();
}

/******************************************************************************
* cph_mod_init()
* _____________________________________________________________________________
*
* DESCRIPTION: Initialize CPH module
*
* INPUTS:
*       None.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
static int __init cph_mod_init(void)
{
	if (cph_dev_init() != 0) {
		pr_err("\nCPH module initialization failed\n\n");
		return MV_ERROR;
	}

	/* pr_info("\nCPH module inserted - %s\n\n", CPH_MODULE_VERSION); */

	return MV_OK;
}

device_initcall_sync(cph_mod_init);

module_exit(cph_mod_exit);

MODULE_AUTHOR("Victor Gu");
MODULE_VERSION(CPH_MODULE_VERSION);
MODULE_DESCRIPTION(CPH_MODULE_DESC);
MODULE_LICENSE("GPL");
