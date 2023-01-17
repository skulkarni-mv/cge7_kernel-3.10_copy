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

#ifndef __INCmvDebugh
#define __INCmvDebugh

/* includes */
#include "mvTypes.h"

typedef enum {
	MV_MODULE_INVALID = -1,
	MV_MODULE_ETH = 0,
	MV_MODULE_IDMA,
	MV_MODULE_XOR,
	MV_MODULE_TWASI,
	MV_MODULE_MGI,
	MV_MODULE_USB,
	MV_MODULE_CESA,

	MV_MODULE_MAX
} MV_MODULE_ID;

/* Define generic flags useful for most of modules */
#define MV_DEBUG_FLAG_ALL   (0)
#define MV_DEBUG_FLAG_INIT  (1 << 0)
#define MV_DEBUG_FLAG_RX    (1 << 1)
#define MV_DEBUG_FLAG_TX    (1 << 2)
#define MV_DEBUG_FLAG_ERR   (1 << 3)
#define MV_DEBUG_FLAG_TRACE (1 << 4)
#define MV_DEBUG_FLAG_DUMP  (1 << 5)
#define MV_DEBUG_FLAG_CACHE (1 << 6)
#define MV_DEBUG_FLAG_IOCTL (1 << 7)
#define MV_DEBUG_FLAG_STATS (1 << 8)

extern MV_U32 mvDebug;
extern MV_U32 mvDebugModules[MV_MODULE_MAX];

#ifdef MV_DEBUG
# define MV_DEBUG_PRINT(module, flags, msg)     mvOsPrintf(msg)
# define MV_DEBUG_CODE(module, flags, code)     code
#elif defined(MV_RT_DEBUG)
# define MV_DEBUG_PRINT(module, flags, msg)			\
do {								\
	if ((mvDebug & (1<<(module))) &&			\
	    ((mvDebugModules[(module)] & (flags)) == (flags)))	\
		mvOsPrintf(msg)					\
} while (0)
# define MV_DEBUG_CODE(module, flags, code)			\
do {								\
	if ((mvDebug & (1<<(module))) &&			\
	    ((mvDebugModules[(module)] & (flags)) == (flags)))	\
		(code)						\
} while (0)
#else
# define MV_DEBUG_PRINT(module, flags, msg)
# define MV_DEBUG_CODE(module, flags, code)
#endif

/* typedefs */

/*  time measurement structure used to check how much time pass between
 *  two points
 */
typedef struct {
	char name[20];		/* name of the entry */
	unsigned long begin;	/* time measured on begin point */
	unsigned long end;	/* time measured on end point */
	unsigned long total;	/* Accumulated time */
	unsigned long left;	/* The rest measurement actions */
	unsigned long count;	/* Maximum measurement actions */
	unsigned long min;	/* Minimum time from begin to end */
	unsigned long max;	/* Maximum time from begin to end */
} MV_DEBUG_TIMES;

/* mvDebug.h API list */

/****** Error Recording ******/

/* Dump memory in specific format:
 * address: X1X1X1X1 X2X2X2X2 ... X8X8X8X8
 */
void mvDebugMemDump(void *addr, int size, int access);

void mvDebugPrintBufInfo(BUF_INFO *pBufInfo, int size, int access);

void mvDebugPrintPktInfo(MV_PKT_INFO *pPktInfo, int size, int access);

void mvDebugPrintIpAddr(MV_U32 ipAddr);

void mvDebugPrintMacAddr(const MV_U8 *pMacAddr);

/**** There are three functions deals with MV_DEBUG_TIMES structure ****/

/* Reset MV_DEBUG_TIMES entry */
void mvDebugResetTimeEntry(MV_DEBUG_TIMES *pTimeEntry, int count, char *name);

/* Update MV_DEBUG_TIMES entry */
void mvDebugUpdateTimeEntry(MV_DEBUG_TIMES *pTimeEntry);

/* Print out MV_DEBUG_TIMES entry */
void mvDebugPrintTimeEntry(MV_DEBUG_TIMES *pTimeEntry, MV_BOOL isTitle);

/******** General ***********/

/* Change value of mvDebugPrint global variable */

void mvDebugInit(void);
void mvDebugModuleEnable(MV_MODULE_ID module, MV_BOOL isEnable);
void mvDebugModuleSetFlags(MV_MODULE_ID module, MV_U32 flags);
void mvDebugModuleClearFlags(MV_MODULE_ID module, MV_U32 flags);

#endif /* __INCmvDebug.h */
