/*
 * APM 86xxx QM Utility Header File
 *
 * Copyright (c) 2011, Applied Micro Circuits Corporation
 * Author: Loc Ho <lho@apm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 *
 */
#include <asm/apm_qm_core.h>

void dump_qstate(struct apm_qm_qstate *qstate);
int apm_qm_rx_msg_util(int qid, int mbid);
int apm_qm_send_msg_util(int qid, int mbid, struct apm_qm_msg64 *msg64);
int apm_qm_dealloc_buf_util(int qid, int mbid);
int apm_qm_alloc_buf_util(int qid, int mbid);

