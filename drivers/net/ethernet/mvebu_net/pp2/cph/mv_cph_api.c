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
/*******************************************************************************
* mv_cph_api.c
*
* DESCRIPTION: Marvell CPH(CPH Packet Handler) API definition
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
#include <linux/module.h>
#include <linux/version.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>
#include <linux/poll.h>
#include <linux/clk.h>
#include <linux/fs.h>
#include <linux/vmalloc.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/miscdevice.h>

#include "mv_cph_header.h"


/******************************************************************************
* Variable Definition
******************************************************************************/


/******************************************************************************
* Function Definition
******************************************************************************/
/******************************************************************************
* cph_set_complex_profile()
* _____________________________________________________________________________
*
* DESCRIPTION: Set TPM complex profile ID
*
* INPUTS:
*       profile_id   - TPM complex profile ID
*       active_port  - Active WAN port
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_set_complex_profile(enum tpm_eth_complex_profile_t profile_id, enum MV_APP_GMAC_PORT_E active_port)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_set_complex_profile(profile_id, active_port);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_app_set_complex_profile");

	return rc;
}
EXPORT_SYMBOL(cph_set_complex_profile);

/******************************************************************************
* cph_set_feature_flag()
* _____________________________________________________________________________
*
* DESCRIPTION: Enable or disable feature support in CPH
*
* INPUTS:
*       feature - CPH supported features
*       state   - Enable or disable this feature in CPH
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_set_feature_flag(enum CPH_APP_FEATURE_E feature, bool state)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_set_feature_flag(feature, state);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "fail to call cph_app_set_feature_flag");

	return rc;
}
EXPORT_SYMBOL(cph_set_feature_flag);

/******************************************************************************
* cph_add_app_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Add CPH rule
*
* INPUTS:
*       parse_bm   - Parsing bitmap
*       parse_key  - Parsing key
*       mod_bm     - Modification bitmap
*       mod_value  - Modification value
*       frwd_bm    - Forwarding bitmap
*       frwd_value - Forwarding value
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_add_app_rule(
	enum CPH_APP_PARSE_FIELD_E parse_bm,
	struct CPH_APP_PARSE_T      *parse_key,
	enum CPH_APP_MOD_FIELD_E   mod_bm,
	struct CPH_APP_MOD_T        *mod_value,
	enum CPH_APP_FRWD_FIELD_E  frwd_bm,
	struct CPH_APP_FRWD_T       *frwd_value)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_add_rule(parse_bm, parse_key, mod_bm, mod_value, frwd_bm, frwd_value);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_app_add_rule");

	return rc;
}
EXPORT_SYMBOL(cph_add_app_rule);

/******************************************************************************
* cph_del_app_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Delete CPH rule
*
* INPUTS:
*       parse_bm   - Parsing bitmap
*       parse_key  - Parsing key
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_del_app_rule(
	enum CPH_APP_PARSE_FIELD_E parse_bm,
	struct CPH_APP_PARSE_T      *parse_key)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_del_rule(parse_bm, parse_key);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_app_del_rule");

	return rc;
}
EXPORT_SYMBOL(cph_del_app_rule);

/******************************************************************************
* cph_update_app_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Update CPH rule
*
* INPUTS:
*       parse_bm   - Parsing bitmap
*       parse_key  - Parsing key
*       mod_bm     - Modification bitmap
*       mod_value  - Modification value
*       frwd_bm    - Forwarding bitmap
*       frwd_value - Forwarding value
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_update_app_rule(
	enum CPH_APP_PARSE_FIELD_E parse_bm,
	struct CPH_APP_PARSE_T      *parse_key,
	enum CPH_APP_MOD_FIELD_E   mod_bm,
	struct CPH_APP_MOD_T        *mod_value,
	enum CPH_APP_FRWD_FIELD_E  frwd_bm,
	struct CPH_APP_FRWD_T       *frwd_value)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_update_rule(parse_bm, parse_key, mod_bm, mod_value, frwd_bm, frwd_value);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_app_update_rule");

	return rc;
}
EXPORT_SYMBOL(cph_update_app_rule);

/******************************************************************************
* cph_get_app_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Get CPH rule
*
* INPUTS:
*       parse_bm   - Parsing bitmap
*       parse_key  - Parsing key
*
* OUTPUTS:
*       mod_bm     - Modification bitmap
*       mod_value  - Modification value
*       frwd_bm    - Forwarding bitmap
*       frwd_value - Forwarding value
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_get_app_rule(
	enum CPH_APP_PARSE_FIELD_E parse_bm,
	struct CPH_APP_PARSE_T      *parse_key,
	enum CPH_APP_MOD_FIELD_E  *mod_bm,
	struct CPH_APP_MOD_T        *mod_value,
	enum CPH_APP_FRWD_FIELD_E *frwd_bm,
	struct CPH_APP_FRWD_T       *frwd_value)
{
	MV_STATUS rc = MV_OK;

	rc = cph_app_get_rule(parse_bm, parse_key, mod_bm, mod_value, frwd_bm, frwd_value);
	if (rc != MV_OK)
		MV_CPH_PRINT(CPH_DEBUG_LEVEL, "fail to call cph_app_get_rule\n");

	return rc;
}
EXPORT_SYMBOL(cph_get_app_rule);

/******************************************************************************
* cph_add_flow_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Sets flow mapping rule
*
* INPUTS:
*       cph_flow - VLAN ID, 802.1p value, pkt_fwd information.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
int cph_add_flow_rule(struct CPH_FLOW_ENTRY_T *cph_flow)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_add_rule(cph_flow);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_add_rule");

	return rc;
}
EXPORT_SYMBOL(cph_add_flow_rule);

/******************************************************************************
* cph_del_flow_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Deletes flow mapping rule
*
* INPUTS:
*       cph_flow - VLAN ID, 802.1p value, pkt_fwd information.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
int cph_del_flow_rule(struct CPH_FLOW_ENTRY_T *cph_flow)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_del_rule(cph_flow);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_del_rule");

	return rc;
}
EXPORT_SYMBOL(cph_del_flow_rule);

/******************************************************************************
* cph_get_flow_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Gets flow mapping rule for tagged frames.
*
* INPUTS:
*       cph_flow - Input vid, pbits, dir
*
* OUTPUTS:
*       cph_flow - output packet forwarding information, including GEM port,
*                   T-CONT, queue and packet modification for VID, P-bits.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
int cph_get_flow_rule(struct CPH_FLOW_ENTRY_T *cph_flow)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_get_rule(cph_flow);
	if (rc != MV_OK)
		MV_CPH_PRINT(CPH_DEBUG_LEVEL, "fail to call cph_flow_get_rule\n");

	return rc;
}
EXPORT_SYMBOL(cph_get_flow_rule);

/******************************************************************************
* cph_clear_flow_rule()
* _____________________________________________________________________________
*
* DESCRIPTION: Clears all flow mapping rules
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
int cph_clear_flow_rule(void)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_clear_rule();
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_clear_rule");

	return rc;
}
EXPORT_SYMBOL(cph_clear_flow_rule);

/******************************************************************************
* cph_clear_flow_rule_by_mh()
* _____________________________________________________________________________
*
* DESCRIPTION: Clears flow mapping rules by MH
*
* INPUTS:
*       mh   -  Marvell header.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
int cph_clear_flow_rule_by_mh(unsigned short mh)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_clear_rule_by_mh(mh);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_clear_rule_by_mh");

	return rc;
}

/******************************************************************************
* cph_set_flow_dscp_map()
* _____________________________________________________________________________
*
* DESCRIPTION: Sets DSCP to P-bits mapping rules
*
* INPUTS:
*       dscp_map  - DSCP to P-bits mapping rules.
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
int cph_set_flow_dscp_map(struct CPH_DSCP_PBITS_T *dscp_map)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_set_dscp_map(dscp_map);
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_set_dscp_map");

	return rc;
}
EXPORT_SYMBOL(cph_set_flow_dscp_map);

/******************************************************************************
* cph_del_flow_dscp_map()
* _____________________________________________________________________________
*
* DESCRIPTION: Deletes DSCP to P-bits mapping rules
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
int cph_del_flow_dscp_map(void)
{
	MV_STATUS rc = MV_OK;

	rc = cph_flow_del_dscp_map();
	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_flow_del_dscp_map");

	return rc;
}
EXPORT_SYMBOL(cph_del_flow_dscp_map);

/*******************************************************************************
**
** cph_get_tcont_state
** ___________________________________________________________________________
**
** DESCRIPTION: The function get T-CONT state
**
** INPUTS:
**   tcont - T-CONT
**
** OUTPUTS:
**   None.
**
** RETURNS:
**   state - State of T-CONT, enabled or disabled.
**
*******************************************************************************/
bool cph_get_tcont_state(unsigned int tcont)
{
	return cph_db_get_tcont_state(tcont);
}
EXPORT_SYMBOL(cph_get_tcont_state);

/*******************************************************************************
**
** cph_set_tcont_state
** ___________________________________________________________________________
**
** DESCRIPTION: The function sets T-CONT state in mv_cust
**
** INPUTS:
**   tcont - T-CONT
**   state - State of T-CONT, enabled or disabled.
**
** OUTPUTS:
**   None.
**
** RETURNS:
**  On success, the function returns (MV_OK). On error different types are
**  returned according to the case.
**
*******************************************************************************/
int cph_set_tcont_state(unsigned int tcont, bool state)
{
	return cph_db_set_tcont_state(tcont, state);
}
EXPORT_SYMBOL(cph_set_tcont_state);

/******************************************************************************
* Function Definition
******************************************************************************/
/******************************************************************************
* cph_set_port_func()
* _____________________________________________________________________________
*
* DESCRIPTION: Set CPH port Rx/Tx func
*
* INPUTS:
*       port          - physical port ID
*       dir            - Rx(0)  Tx(1)
*       enable      - disable(0)  enable(1)
*
* OUTPUTS:
*       None.
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_set_port_func(int port, enum CPH_RX_TX_E dir, bool enable)
{
	MV_STATUS rc = MV_OK;

	if (CPH_DIR_RX == dir) {
		if (enable)
			mv_pp2_rx_special_proc_func(port, cph_rx_func);
		else
			mv_pp2_rx_special_proc_func(port, NULL);
	} else if (CPH_DIR_TX == dir) {
		if (enable)
			mv_pp2_tx_special_check_func(port, cph_tx_func);
		else
			mv_pp2_tx_special_check_func(port, NULL);
	} else {
		if (enable) {
			mv_pp2_rx_special_proc_func(port, cph_rx_func);
			mv_pp2_tx_special_check_func(port, cph_tx_func);
		} else {
			mv_pp2_rx_special_proc_func(port, NULL);
			mv_pp2_tx_special_check_func(port, NULL);
		}
	}

	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_set_port_func");

	return rc;
}
EXPORT_SYMBOL(cph_set_port_func);

/******************************************************************************
* Function Definition
******************************************************************************/
/******************************************************************************
* cph_get_port_func()
* _____________________________________________________________________________
*
* DESCRIPTION: Set CPH port Rx/Tx func
*
* INPUTS:
*       port              - physical port ID
*
* OUTPUTS:
*       rx_enable      - disable(0)  enable(1)
*       tx_enable      - disable(0)  enable(1)
*
* RETURNS:
*       On success, the function returns MV_OK.
*       On error returns error code accordingly.
*******************************************************************************/
MV_STATUS cph_get_port_func(int port, bool *rx_enable, bool *tx_enable)
{
	MV_STATUS rc = MV_OK;
	struct eth_port *pp = mv_pp2_port_by_id(port);

	if (!pp)
		return MV_BAD_PARAM;

	if (pp->rx_special_proc)
		*rx_enable = true;
	else
		*rx_enable = false;

	if (pp->tx_special_check)
		*tx_enable = true;
	else
		*tx_enable = false;

	CHECK_API_RETURN_AND_LOG_ERROR(rc, "Fail to call cph_get_port_func");

	return rc;
}
EXPORT_SYMBOL(cph_get_port_func);
