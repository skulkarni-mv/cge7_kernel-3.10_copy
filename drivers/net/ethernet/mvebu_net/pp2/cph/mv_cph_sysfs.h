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
* mv_cph_sysfs.h
*
* DESCRIPTION: Marvell CPH(CPH Packet Handler) sysfs command definition
*
* DEPENDENCIES:
*               None
*
* CREATED BY:   VictorGu
*
* DATE CREATED: 11Dec2011
*
* FILE REVISION NUMBER:
*               Revision: 1.1
*
*
*******************************************************************************/
#ifndef _MV_CPH_SYSFS_H_
#define _MV_CPH_SYSFS_H_

#ifdef __cplusplus
extern "C" {
#endif

#define CPH_SYSFS_FIELD_MAX_LEN   (32)
#define CPH_SYSFS_FIELD_MAX_ENTRY (64)


/* Common DB structure for entries
------------------------------------------------------------------------------*/
struct CPH_SYSFS_RULE_T {
	int  max_entry_num;
	int  entry_num;
	int  entry_size;
	void  *entry_ara;
} ;

/* Parsing filed entry
------------------------------------------------------------------------------*/
struct CPH_SYSFS_PARSE_T {
	char                  name[CPH_SYSFS_FIELD_MAX_LEN+1];
	enum CPH_APP_PARSE_FIELD_E parse_bm;
	struct CPH_APP_PARSE_T       parse_key;
};

/* Modification filed entry
------------------------------------------------------------------------------*/
struct CPH_SYSFS_MOD_T {
	char                  name[CPH_SYSFS_FIELD_MAX_LEN+1];
	enum CPH_APP_MOD_FIELD_E   mod_bm;
	struct CPH_APP_MOD_T         mod_value;
};

/* Forwarding filed entry
------------------------------------------------------------------------------*/
struct CPH_SYSFS_FRWD_T {
	char                  name[CPH_SYSFS_FIELD_MAX_LEN+1];
	enum CPH_APP_FRWD_FIELD_E  frwd_bm;
	struct CPH_APP_FRWD_T        frwd_value;
};


int cph_sysfs_init(void);
void cph_sysfs_exit(void);

#ifdef __cplusplus
}
#endif

#endif /* _MV_CPH_SYSFS_H_ */
