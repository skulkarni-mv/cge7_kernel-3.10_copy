/* Copyright 2013-2014 Freescale Semiconductor Inc.
 *
 * Interface of the I/O services to send MC commands to the MC hardware
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the above-listed copyright holders nor the
 *       names of any contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef _FSL_MC_SYS_H
#define _FSL_MC_SYS_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/completion.h>
#include <linux/mutex.h>
#include <linux/spinlock.h>

/**
 * Bit masks for a MC I/O object (struct fsl_mc_io) flags
 */
#define FSL_MC_IO_ATOMIC_CONTEXT_PORTAL	0x0001

struct fsl_mc_resource;
struct mc_command;

/**
 * struct fsl_mc_io - MC I/O object to be passed-in to mc_send_command()
 * @dev: device associated with this Mc I/O object
 * @flags: flags for mc_send_command()
 * @portal_size: MC command portal size in bytes
 * @portal_phys_addr: MC command portal physical address
 * @portal_virt_addr: MC command portal virtual address
 * @dpmcp_dev: pointer to the DPMCP device associated with the MC portal.
 * @mc_command_done_irq_armed: Flag indicating that the MC command done IRQ
 * is currently armed.
 * @mc_command_done_completion: Completion variable to be signaled when an MC
 * command sent to the MC fw is completed.
 *
 * Fields are only meaningful if the FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag is not
 * set:
 * @mutex: Mutex to serialize mc_send_command() calls that use the same MC
 * portal, if the fsl_mc_io object was created with the
 * FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag off. mc_send_command() calls for this
 * fsl_mc_io object must be made only from non-atomic context.
 * @mc_command_done_completion: Linux completion variable to be signaled
 * when a DPMCP command completion interrupts is received.
 * @mc_command_done_irq_armed: Boolean flag that indicates if interrupts have
 * been successfully configured for the corresponding DPMCP object.
 * @ dpmcp_isr_mc_handle: MC handle to be used to send the command to clear
 * DPMCP command completion interrupts. (We need as separate MC handle that
 * was opened using the portal that will be used to send the clear interrupt
 * command).
 *
 * Fields are only meaningful if the FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag is
 * set:
 * @spinlock: Spinlock to serialize mc_send_command() calls that use the same MC
 * portal, if the fsl_mc_io object was created with the
 * FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag on. mc_send_command() calls for this
 * fsl_mc_io object can be made from atomic or non-atomic context.
 */
struct fsl_mc_io {
	struct device *dev;
	uint16_t flags;
	uint16_t portal_size;
	phys_addr_t portal_phys_addr;
	void __iomem *portal_virt_addr;
	struct fsl_mc_device *dpmcp_dev;
	union {
		/*
		 * These fields are only meaningful if the
		 * FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag is not set
		 */
		struct {
			struct mutex mutex; /* serializes mc_send_command() */
			struct completion mc_command_done_completion;
			bool mc_command_done_irq_armed;
			uint16_t dpmcp_isr_mc_handle;
		};

		/*
		 * This field is only meaningful if the
		 * FSL_MC_IO_ATOMIC_CONTEXT_PORTAL flag is set
		 */
		spinlock_t spinlock;	/* serializes mc_send_command() */
	};
};

int __must_check fsl_create_mc_io(struct device *dev,
				  phys_addr_t mc_portal_phys_addr,
				  uint32_t mc_portal_size,
				  struct fsl_mc_device *dpmcp_dev,
				  uint32_t flags, struct fsl_mc_io **new_mc_io);

void fsl_destroy_mc_io(struct fsl_mc_io *mc_io);

int fsl_mc_io_set_dpmcp(struct fsl_mc_io *mc_io,
			struct fsl_mc_device *dpmcp_dev);

void fsl_mc_io_unset_dpmcp(struct fsl_mc_io *mc_io);

int fsl_mc_io_setup_dpmcp_irq(struct fsl_mc_io *mc_io);

int mc_send_command(struct fsl_mc_io *mc_io, struct mc_command *cmd);

#endif /* _FSL_MC_SYS_H */
