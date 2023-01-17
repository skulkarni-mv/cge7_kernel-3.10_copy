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
* mv_cph_infra.c
*
* DESCRIPTION: Include user space infrastructure modules definitions
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
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/if_vlan.h>
#include <net/ip.h>
#include <net/ipv6.h>

#include "mv_cph_header.h"

/******************************************************************************
* Variable Definition
******************************************************************************/
char g_cph_unknown_str[] = "<unknown>";

/******************************************************************************
* Function Definition
******************************************************************************/
/******************************************************************************
* mindex_tpm_src_to_app_port()
*
* DESCRIPTION:Convert TPM source port to application UNI port
*
* INPUTS:
*       src_port    - TPM source port
*
* OUTPUTS:
*       Application UNI port index
*
* RETURNS:
*       On success, the function returns application UNI port index.
*       On error return invalid application UNI port index.
*******************************************************************************/
enum MV_APP_ETH_PORT_UNI_E mindex_tpm_src_to_app_port(enum tpm_src_port_type_t src_port)
{
	enum MV_APP_ETH_PORT_UNI_E app_port = MV_APP_ETH_PORT_INVALID;

	/* Should modify below code in case support more than four UNI ports */
	if (src_port <= TPM_SRC_PORT_UNI_3)
		app_port = MV_APP_ETH_PORT_INDEX_MIN + (src_port - TPM_SRC_PORT_UNI_0);

	return app_port;
}

/******************************************************************************
* mindex_mh_to_app_llid()
*
* DESCRIPTION:Convert Marvell header to application LLID
*
* INPUTS:
*       mh  - Marvell header
*
* OUTPUTS:
*       Application LLID
*
* RETURNS:
*       On success, the function returns application LLID.
*       On error return invalid application LLID.
*******************************************************************************/
enum MV_TCONT_LLID_E mindex_mh_to_app_llid(unsigned short mh)
{
	enum MV_TCONT_LLID_E llid       = MV_TCONT_LLID_INVALID;
	unsigned char           llid_index = 0;

	llid_index = (mh >> 8) & 0x0f;

	if (llid_index > 0) {
		if (0x0f == llid_index) {
			llid = MV_TCONT_LLID_BROADCAST;
		} else {
			llid = llid_index - 1;
			if (llid > MV_TCONT_LLID_7)
				llid = MV_TCONT_LLID_INVALID;
		}
	}

	return llid;
}

/******************************************************************************
* mtype_get_digit_num()
*
* DESCRIPTION:Convert character string to digital number
*
* INPUTS:
*       str   - Character string
*
* OUTPUTS:
*       None
*
* RETURNS:
*       Digital numbe
*******************************************************************************/
unsigned int mtype_get_digit_num(const char  *str)
{
	unsigned int  val = 0;

	if ((str[1] == 'x') || (str[1] == 'X'))
		sscanf(&str[2], "%x", &val);
	else
		val = simple_strtoul(str, NULL, 10);

	return val;
}

/******************************************************************************
* mtype_lookup_enum_str()
* _____________________________________________________________________________
*
* DESCRIPTION:lookup enum string according to enum value
*
* INPUTS:
*       p_enum_array   - Pointer to enum array
*       enum_value     - The enum value to be matched
*
* OUTPUTS:
*       None
*
* RETURNS:
*       Enum string
*******************************************************************************/
char *mtype_lookup_enum_str(struct MV_ENUM_ARRAY_T *p_enum_array, int enum_value)
{
	int idx;

	for (idx = 0; idx < p_enum_array->enum_num; idx++) {
		if (enum_value == p_enum_array->enum_array[idx].enum_value)
			return p_enum_array->enum_array[idx].enum_str;
	}
	return g_cph_unknown_str;
}

/******************************************************************************
* mutils_is_frwd_broadcast_packet()
* _____________________________________________________________________________
*
* DESCRIPTION:Check whether packet is directly forwarded broadcast one
*
* INPUTS:
*       data   - packet data
*
* OUTPUTS:
*       None
*
* RETURNS:
*       TRUE: broadcast packet, FALSE:none broadcast packet
*******************************************************************************/
bool mutils_is_frwd_broadcast_packet(char *data)
{
	char bc_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
	char *p_data;

	p_data = data + MV_ETH_MH_SIZE;

	if (!memcmp(p_data, &bc_mac[0], sizeof(bc_mac)))
		return TRUE;
	else
		return FALSE;
}
