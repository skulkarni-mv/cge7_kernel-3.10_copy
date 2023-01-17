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
* mv_cph_dev.h
*
* DESCRIPTION: Marvell CPH(CPH Packet Handler) char device definition
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
#ifndef _MV_CPH_DEV_H_
#define _MV_CPH_DEV_H_

#ifdef __cplusplus
extern "C" {
#endif


#define MV_CPH_DEVICE_NAME  "cph"
#define MV_CPH_IOCTL_MAGIC  ('C')

/******************************************************************************
* Function Declaration
******************************************************************************/
/******************************************************************************
* cph_dev_setup()
* _____________________________________________________________________________
*
* DESCRIPTION: Setup device
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
int cph_dev_setup(void);

/******************************************************************************
* cph_dev_shutdown()
* _____________________________________________________________________________
*
* DESCRIPTION: Initialize CPH device
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
int  cph_dev_init(void);

/******************************************************************************
* cph_dev_shutdown()
* _____________________________________________________________________________
*
* DESCRIPTION: Shutdown CPH device
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
void cph_dev_shutdown(void);


#ifdef __cplusplus
}
#endif

#endif /* _MV_CPH_DEV_H_ */
