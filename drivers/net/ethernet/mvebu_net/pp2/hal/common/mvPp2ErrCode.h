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

#ifndef __MV_PP2_ERR_CODE_H__
#define __MV_PP2_ERR_CODE_H__

#define  MV_ERR_CODE_BASE						0x80000000
#define  MV_PP2_ERR_CODE_BASE					(MV_ERR_CODE_BASE | 0x00001000)


#define  MV_PP2_PRS						(MV_PP2_ERR_CODE_BASE | 0x00000100)
#define  MV_PP2_CLS						(MV_PP2_ERR_CODE_BASE | 0x00000200)
#define  MV_PP2_CLS2						(MV_PP2_ERR_CODE_BASE | 0x00000400)
#define  MV_PP2_CLS3						(MV_PP2_ERR_CODE_BASE | 0x00000800)
#define  MV_PP2_CLS4						(MV_PP2_ERR_CODE_BASE | 0x00000800)


/*****************************************************************************



			    E R R O R   C O D E S


*****************************************************************************/
/* #define MV_OK 0  define in mvTypes*/
#define EQUALS 0
#define NOT_EQUALS 1

/* PRS error codes */
#define  MV_PRS_ERR						(MV_PP2_PRS | 0x00)
#define  MV_PRS_OUT_OF_RAGE					(MV_PP2_PRS | 0x01)
#define  MV_PRS_NULL_POINTER					(MV_PP2_PRS | 0x02)

/* CLS error codes */
#define  MV_CLS_ERR						(MV_PP2_CLS | 0x00)
#define  MV_CLS_OUT_OF_RAGE					(MV_PP2_CLS | 0x01)

/* CLS2 error codes */
#define  MV_CLS2_ERR						(MV_PP2_CLS2 | 0x00)
#define  MV_CLS2_OUT_OF_RAGE					(MV_PP2_CLS2 | 0x01)
#define  MV_CLS2_NULL_POINTER					(MV_PP2_CLS2 | 0x02)
#define  MV_CLS2_RETRIES_EXCEEDED				(MV_PP2_CLS2 | 0x03)

/* CLS3 error codes */
#define  MV_CLS3_ERR						(MV_PP2_CLS3 | 0x00)
#define  MV_CLS3_OUT_OF_RAGE					(MV_PP2_CLS3 | 0x01)
#define  MV_CLS3_NULL_POINTER					(MV_PP2_CLS3 | 0x02)
#define  MV_CLS3_RETRIES_EXCEEDED				(MV_PP2_CLS3 | 0x03)
#define  MV_CLS3_SW_INTERNAL					(MV_PP2_CLS3 | 0x04)

/* CLS4 error codes */
#define  MV_CLS4_ERR						(MV_PP2_CLS4 | 0x00)
#define  MV_CLS4_OUT_OF_RAGE					(MV_PP2_CLS4 | 0x01)
#define  MV_CLS4_NULL_POINTER					(MV_PP2_CLS4 | 0x02)
#define  MV_CLS4_RETRIES_EXCEEDED				(MV_PP2_CLS4 | 0x03)

#endif /* __MV_PP2_ERR_CODE_H__ */
