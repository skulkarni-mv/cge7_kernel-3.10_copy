/*
 * APM86xxx CLE Configuration Header
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * Ravi Patel <rapatel@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 * @file apm_cle_mgr.h
 *
 * This header declares Management APIs and macros for
 * APM86xxx SoC Classifier module.
 */

#ifndef _APM_CLE_MGR_H_
#define _APM_CLE_MGR_H_

#include "apm_preclass_data.h"
#ifdef AVL_MANAGER
#include "apm_avl_api.h"
#endif /* AVL_MANAGER */

/* Result/DB entry Related */
#define DBPTR_INDEX(p)		((0x0000 << 16) | ((p) & 0x03ff))
#define DBPTR_ALLOC(p)		((0x0001 << 16) | ((p) & 0x03ff))
#define DBPTR_DROP(p)		(0x0002 << 16)
#define DBPTR_AFLAG(p)		((0x0001 << 16) & ((p) << 16))

/* Parser Node Related	*/
#define PTREE_INDEX(p)		((0x0000 << 16) | ((p) & 0x7f))
#define PTREE_ALLOC(p)		((0x0001 << 16) | ((p) & 0x7f))
#define PTREE_AFLAG(p)		((0x0001 << 16) & ((p) << 16))

#ifdef ROLLBACK_MANAGER
/** Saved CLE MGR status before being activity from user-space */
struct apm_cle_mgr_saved_stat
{
	u32 us_action_trigged;
	u32 node_alloc_index;
	u32 dbptr_alloc_index;
};
#endif

/**
 * @brief   Pre-check the Patricia Tree node before prepare node to check
 * @param   port - GE Port number
 * @param   node - Pointer to Node configurations
 * @return  APM_RC_OK or APM_RC_INVALID_PARM
 */
int apm_ptree_node_precheck(u8 port, struct ptree_node *node);

/**
 * @brief   Pre-check the Patricia Tree branch before prepare node to check
 * @param   port - GE Port number
 * @param   node - Pointer to Node configurations
 * @return  APM_RC_OK or APM_RC_INVALID_PARM
 */
int apm_ptree_branch_precheck(u8 port, struct ptree_node *node);

/**
 * @brief   Check the Patricia Tree node after prepare node
 * @param   port - GE Port number
 * @param   node - Pointer to Node configurations
 * @param   pass_aflag - To allow variable with ALLOC flag or not
 * @return  APM_RC_OK or APM_RC_INVALID_PARM
 */
int apm_ptree_node_check(u8 port, struct ptree_node *node, u32 pass_aflag);

/**
 * @brief   Patricia tree node dst_node preparation routine from folloing params.
 * @param   Classifier Engine id 0/1
 * @param   remove_aflag - To remove ALLOC flags or not in node / dbptr
 * @param   dst_node - To prepare Patricia tree node dst_node.
 * @param   dst_dn - Set the dst_node->data to point to dst_dn
 *          after preparing ptree_dn
 * @param   dst_kn - Set the dst_node->data to point to dst_kn
 *          after preparing ptree_kn
 * @param   dst_branch - Set the DN's dst_node->data->branch to point to
 *          dst_branch after preparing ptree_branch for that DN
 * @param   src_node - From the source Patricia tree node
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
void apm_ptree_node_prepare(u32 cid, u32 remove_aflag,
			struct ptree_node *dst_node,
			struct ptree_dn *dst_dn,
			struct ptree_kn *dst_kn,
			struct ptree_branch *dst_branch,
			struct ptree_node *src_node);

/**
 * @brief   Patricia tree node allocation & configuration routine. It calls
 *          apm_ptree_node_config API to configure individual
 *          Patricia Tree nodes and it also calls apm_set_cle_dbptr to
 *          configure individual database result entry associated with the
 *          Patricia Tree.
 * @param   port - GE Port number (0 to 3 for GE MAC and 8 for 10 GE MAC).
 * @param   ptnodes - Number of Patricia Tree nodes to be configured.
 * @param   dbptrs - Number of database result entry.
 * @param   node - Start address of Patricia tree nodes
 *          entry structure pointer
 * @param   dbptr - Start address of Patricia tree database
 *          result structure pointer
 * @param   ptree_config - Puts the start node index and start DB result pointer
 *          in ptree_config
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
int apm_ptree_alloc(u8 port, u8 ptnodes, u16 dbptrs,
		   struct ptree_node *node,
		   struct apm_cle_dbptr *dbptr,
		   struct apm_ptree_config *ptree_config);

#ifdef ROLLBACK_MANAGER
/**
 * @brief   Patricia tree clearing all tailing resource routine.
 *          Function is targeted to use with APM QoS effective on the
 *          tailing resource.
 * @param   port - GE Port number (0 to 3 for GE MAC and 8 for 10 GE MAC).
 * @return  APM_RC_OK
 *
 */
int apm_cle_mgr_init_ext(int cid);

/**
 * @brief   Patricia tree node rollback routine. Once calling apm_ptree_alloc,
 *          an area within ptree is occupied and is reflexed as
 *          {ptree_config.start_node_ptr, node_alloc_index} for each CID.
 *          User-space program may wish to override that area to make new effect
 *          (e.g. multiple commit rules of APM_QOS). This function rollbacks to
 *          the state before that last apm_ptree_alloc.
 * @param   port - GE Port number (0 to 3 for GE MAC and 8 for 10 GE MAC).
 * @param   ptree_config - Gets the start node index and start DB result pointer
 *          in ptree_config to do rollback
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
int apm_ptree_rollback(u8 port,
					struct apm_ptree_config *ptree_config);
#endif

#ifdef AVL_MANAGER
/**
 * @brief   Check the AVL node after prepare node
 * @param   port - GE Port number
 * @param   node - Pointer to Node configurations
 * @param   pass_aflag - To allow variable with ALLOC flag or not
 * @return  APM_RC_OK or APM_RC_INVALID_PARM
 */
int apm_avl_node_check(u8 port, struct avl_node *node, u32 pass_aflag);

/**
 * @brief   AVL Engine node dst_node preparation routine from folloing params.
 * @param   Classifier Engine id 0/1
 * @param   remove_aflag - To remove ALLOC flags or not in node / dbptr
 * @param   dst_node - To prepare AVL Node dst_node.
 * @param   src_node - From the source AVL Node
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
void apm_avl_node_prepare(u32 cid, u32 remove_aflag,
			struct avl_node *dst_node,
			struct avl_node *src_node);

/**
 * @brief   AVL Engine node allocation & configuration routine. It calls
 *          apm_cle_avl_add_node API to configure individual
 *          AVL nodes and it also calls apm_set_cle_dbptr to
 *          configure individual database result entry associated with the
 *          AVL Node.
 * @param   port - GE Port number (0 to 3 for GE MAC and 8 for 10 GE MAC).
 * @param   avlnodes - Number of AVL nodes to be configured.
 * @param   dbptrs - Number of database result entry.
 * @param   node - Start address of AVL nodes
 *          entry structure pointer
 * @param   dbptr - Start address of AVL node database
 *          result structure pointer
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
int apm_avl_alloc(u8 port, u16 avlnodes, u16 dbptrs,
		   struct avl_node *node,
		   struct apm_cle_dbptr *dbptr);
#endif /* AVL_MANAGER */

#ifdef DBPTR_MANAGER
/**
 * @brief   Check the Result Pointer after prepare dbptr
 * @param   port - GE Port number
 * @param   dbptr - Pointer to Result Pointer configurations
 * @param   pass_aflag - To allow variable with ALLOC flag or not
 * @return  APM_RC_OK or APM_RC_INVALID_PARM
 */
int apm_dbptr_check(u8 port, struct apm_cle_dbptr *dbptr, u32 pass_aflag);

/**
 * @brief   Result Pointer dst_dbptr preparation routine from folloing params.
 * @param   Classifier Engine id 0/1
 * @param   remove_aflag - To remove ALLOC flags or not in dbptr
 * @param   dst_dbptr - To prepare Result Pointer dst_dbptr.
 * @param   src_dbptr - From the source esult Pointer
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
void apm_dbptr_prepare(u32 cid, u32 remove_aflag,
			struct apm_cle_dbptr *dst_dbptr,
			struct apm_cle_dbptr *src_dbptr);

/**
 * @brief   Result Pointer allocation & configuration routine. It calls
 *          apm_set_cle_dbptr API to configure individual
 *          Result Pointer.
 * @param   port - GE Port number (0 to 3 for GE MAC and 8 for 10 GE MAC).
 * @param   dbptrs - Number of database result entry.
 * @param   dbptr - Start address of AVL node database
 *          result structure pointer
 * @return  APM_RC_OK or APM_RC_ERROR
 *
 */
int apm_dbptr_alloc(u8 port, u16 dbptrs, struct apm_cle_dbptr *dbptr);
#endif /* DBPTR_MANAGER */

#endif	/* _APM_CLE_MGR_H_  */
