/* Copyright 2014-2015 Freescale Semiconductor Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *	 notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *	 notice, this list of conditions and the following disclaimer in the
 *	 documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *	 names of its contributors may be used to endorse or promote products
 *	 derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM	dpaa2_eth

#if !defined(_DPAA2_ETH_TRACE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _DPAA2_ETH_TRACE_H

#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include "dpaa2-eth.h"
#include <linux/tracepoint.h>

#define TR_FMT "[%s] fd: addr=0x%llx, len=%u, off=%u"
/* trace_printk format for raw buffer event class */
#define TR_BUF_FMT "[%s] vaddr=%p size=%zu dma_addr=%pad map_size=%zu bpid=%d"

/* This is used to declare a class of events.
 * individual events of this type will be defined below.
 */

/* Store details about a frame descriptor */
DECLARE_EVENT_CLASS(dpaa2_eth_fd,
		    /* Trace function prototype */
		    TP_PROTO(struct net_device *netdev,
			     const struct dpaa2_fd *fd),

		    /* Repeat argument list here */
		    TP_ARGS(netdev, fd),

		    /* A structure containing the relevant information we want
		     * to record. Declare name and type for each normal element,
		     * name, type and size for arrays. Use __string for variable
		     * length strings.
		     */
		    TP_STRUCT__entry(
				     __field(u64, fd_addr)
				     __field(u32, fd_len)
				     __field(u16, fd_offset)
				     __string(name, netdev->name)
		    ),

		    /* The function that assigns values to the above declared
		     * fields
		     */
		    TP_fast_assign(
				   __entry->fd_addr = dpaa2_fd_get_addr(fd);
				   __entry->fd_len = dpaa2_fd_get_len(fd);
				   __entry->fd_offset = dpaa2_fd_get_offset(fd);
				   __assign_str(name, netdev->name);
		    ),

		    /* This is what gets printed when the trace event is
		     * triggered.
		     */
		    /* TODO: print the status using __print_flags() */
		    TP_printk(TR_FMT,
			      __get_str(name),
			      __entry->fd_addr,
			      __entry->fd_len,
			      __entry->fd_offset)
);

/* Now declare events of the above type. Format is:
 * DEFINE_EVENT(class, name, proto, args), with proto and args same as for class
 */

/* Tx (egress) fd */
DEFINE_EVENT(dpaa2_eth_fd, dpaa2_tx_fd,
	     TP_PROTO(struct net_device *netdev,
		      const struct dpaa2_fd *fd),

	     TP_ARGS(netdev, fd)
);

/* Rx fd */
DEFINE_EVENT(dpaa2_eth_fd, dpaa2_rx_fd,
	     TP_PROTO(struct net_device *netdev,
		      const struct dpaa2_fd *fd),

	     TP_ARGS(netdev, fd)
);

/* Tx confirmation fd */
DEFINE_EVENT(dpaa2_eth_fd, dpaa2_tx_conf_fd,
	     TP_PROTO(struct net_device *netdev,
		      const struct dpaa2_fd *fd),

	     TP_ARGS(netdev, fd)
);

/* Log data about raw buffers. Useful for tracing DPBP content. */
TRACE_EVENT(dpaa2_eth_buf_seed,
	    /* Trace function prototype */
	    TP_PROTO(struct net_device *netdev,
		     /* virtual address and size */
		     void *vaddr,
		     size_t size,
		     /* dma map address and size */
		     dma_addr_t dma_addr,
		     size_t map_size,
		     /* buffer pool id, if relevant */
		     uint16_t bpid),

	    /* Repeat argument list here */
	    TP_ARGS(netdev, vaddr, size, dma_addr, map_size, bpid),

	    /* A structure containing the relevant information we want
	     * to record. Declare name and type for each normal element,
	     * name, type and size for arrays. Use __string for variable
	     * length strings.
	     */
	    TP_STRUCT__entry(
			     __field(void *, vaddr)
			     __field(size_t, size)
			     __field(dma_addr_t, dma_addr)
			     __field(size_t, map_size)
			     __field(uint16_t, bpid)
			     __string(name, netdev->name)
	    ),

	    /* The function that assigns values to the above declared
	     * fields
	     */
	    TP_fast_assign(
			   __entry->vaddr = vaddr;
			   __entry->size = size;
			   __entry->dma_addr = dma_addr;
			   __entry->map_size = map_size;
			   __entry->bpid = bpid;
			   __assign_str(name, netdev->name);
	    ),

	    /* This is what gets printed when the trace event is
	     * triggered.
	     */
	    /* TODO: print the status using __print_flags() */
	    TP_printk(TR_BUF_FMT,
		      __get_str(name),
		      __entry->vaddr,
		      __entry->size,
		      &__entry->dma_addr,
		      __entry->map_size,
		      __entry->bpid)
);

/* If only one event of a certain type needs to be declared, use TRACE_EVENT().
 * The syntax is the same as for DECLARE_EVENT_CLASS().
 */

#endif /* _DPAA2_ETH_TRACE_H */

/* This must be outside ifdef _DPAA2_ETH_TRACE_H */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE	dpaa2-eth-trace
#include <trace/define_trace.h>
