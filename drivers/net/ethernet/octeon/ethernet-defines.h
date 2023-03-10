/**********************************************************************
 * Author: Cavium, Inc.
 *
 * Contact: support@cavium.com
 * This file is part of the OCTEON SDK
 *
 * Copyright (c) 2003-2012 Cavium, Inc.
 *
 * This file is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, Version 2, as
 * published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but
 * AS-IS and WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE, TITLE, or
 * NONINFRINGEMENT.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this file; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 * or visit http://www.gnu.org/licenses/.
 *
 * This file may also be available under a different license from Cavium.
 * Contact Cavium, Inc. for more information
 **********************************************************************/

/*
 * A few defines are used to control the operation of this driver:
 *  USE_SKBUFFS_IN_HW
 *      Tells the driver to populate the packet buffers with kernel skbuffs.
 *      This allows the driver to receive packets without copying them. It also
 *      means that 32bit userspace can't access the packet buffers.
 *  USE_HW_TCPUDP_CHECKSUM
 *      Controls if the Octeon TCP/UDP checksum engine is used for packet
 *      output. If this is zero, the kernel will perform the checksum in
 *      software.
 *  USE_ASYNC_IOBDMA
 *      Use asynchronous IO access to hardware. This uses Octeon's asynchronous
 *      IOBDMAs to issue IO accesses without stalling. Set this to zero
 *      to disable this. Note that IOBDMAs require CVMSEG.
 *  REUSE_SKBUFFS_WITHOUT_FREE
 *      Allows the TX path to free an skbuff into the FPA hardware pool. This
 *      can significantly improve performance for forwarding and bridging, but
 *      may be somewhat dangerous. Checks are made, but if any buffer is reused
 *      without the proper Linux cleanup, the networking stack may have very
 *      bizarre bugs.
 */
#ifndef __ETHERNET_DEFINES_H__
#define __ETHERNET_DEFINES_H__

#define OCTEON_ETHERNET_VERSION "2.0"

/* FAU */
#define FAU_REG_END (2048)

/* FPA defines */
#define FPA_WQE_POOL_SIZE (1 * CVMX_CACHE_LINE_SIZE)
#define FPA_PACKET_POOL_SIZE (16 * CVMX_CACHE_LINE_SIZE)
#define FPA_OUTPUT_BUFFER_POOL_SIZE (8 * CVMX_CACHE_LINE_SIZE)

/* TODO: replace this */
#define CVMX_SCR_SCRATCH (0)

#define USE_SKBUFFS_IN_HW           1
#ifdef CONFIG_NETFILTER
#define REUSE_SKBUFFS_WITHOUT_FREE  0
#else
#define REUSE_SKBUFFS_WITHOUT_FREE  1
#endif

#define USE_HW_TCPUDP_CHECKSUM      1

/* Enable Random Early Dropping under load */
#define USE_RED                     1

/*
 * The rules under PREEMPT_RT change with respect to how NAPI runs
 * under preempt.  To use IOBDMA, preemption must be disabled, but
 * that's not the case with NAPI and other things under PREEMPT_RT.
 * The whole idea of PREEMPT_RT is to reduce preemptable regions, and
 * you would basically have to make large sections of code
 * unpreemptable to make IOBDMA work properly under PREEMPT_RT.  So
 * just disable it.
 */
#ifdef CONFIG_PREEMPT_RT_BASE
#define USE_ASYNC_IOBDMA            0
#else
#define USE_ASYNC_IOBDMA            1
#endif

/*
 * Allow SW based preamble removal at 10Mbps to workaround PHYs giving
 * us bad preambles.
 */
#define USE_10MBPS_PREAMBLE_WORKAROUND 1
/*
 * Use this to have all FPA frees also tell the L2 not to write data
 * to memory.
 */
#define DONT_WRITEBACK(x)           (x)
/* Use this to not have FPA frees control L2 */
/*#define DONT_WRITEBACK(x)         0   */

/* Maximum number of SKBs to try to free per xmit packet. */
#define MAX_OUT_QUEUE_DEPTH 1000

#define FAU_NUM_PACKET_BUFFERS_TO_FREE (FAU_REG_END - sizeof(u32))

#define TOTAL_NUMBER_OF_PORTS       (CVMX_PIP_NUM_INPUT_PORTS+1)


#endif /* __ETHERNET_DEFINES_H__ */
