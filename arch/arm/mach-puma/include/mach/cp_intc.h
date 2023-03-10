/*
 * Copyright (C) 2010 Wind River Systems, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef __ASM_HARDWARE_CP_INTC_H
#define __ASM_HARDWARE_CP_INTC_H

#define CP_INTC_REV			            0x00
#define CP_INTC_CTRL			        0x04
#define CP_INTC_HOST_CTRL		        0x0C
#define CP_INTC_GLOBAL_ENABLE		    0x10
#define CP_INTC_GLOBAL_NESTING_LEVEL	0x1C
#define CP_INTC_SYS_STAT_IDX_SET	    0x20
#define CP_INTC_SYS_STAT_IDX_CLR	    0x24
#define CP_INTC_SYS_ENABLE_IDX_SET	    0x28
#define CP_INTC_SYS_ENABLE_IDX_CLR	    0x2C
#define CP_INTC_GLOBAL_WAKEUP_ENABLE	0x30
#define CP_INTC_HOST_ENABLE_IDX_SET	    0x34
#define CP_INTC_HOST_ENABLE_IDX_CLR	    0x38
#define CP_INTC_PACING_PRESCALE		    0x40
#define CP_INTC_VECTOR_BASE		        0x50
#define CP_INTC_VECTOR_SIZE		        0x54
#define CP_INTC_VECTOR_NULL		        0x58
#define CP_INTC_PRIO_IDX		        0x80
#define CP_INTC_PRIO_VECTOR		        0x84
#define CP_INTC_SECURE_ENABLE		    0x90
#define CP_INTC_SECURE_PRIO_IDX		    0x94


#define CP_INTC_PACING_PARAM(n)		(0x0100 + (n << 4))
#define CP_INTC_PACING_DEC(n)		(0x0104 + (n << 4))
#define CP_INTC_PACING_MAP(n)		(0x0108 + (n << 4))
#define CP_INTC_SYS_RAW_STAT(n)		(0x0200 + (n << 2))
#define CP_INTC_SYS_STAT_CLR(n)		(0x0280 + (n << 2))
#define CP_INTC_SYS_ENABLE_SET(n)	(0x0300 + (n << 2))
#define CP_INTC_SYS_ENABLE_CLR(n)	(0x0380 + (n << 2))
#define CP_INTC_CHAN_MAP(n)		    (0x0400 + (n << 2))
#define CP_INTC_HOST_MAP(n)		    (0x0800 + (n << 2))
#define CP_INTC_HOST_PRIO_IDX(n)	(0x0900 + (n << 2))
#define CP_INTC_SYS_POLARITY(n)		(0x0D00 + (n << 2))
#define CP_INTC_SYS_TYPE(n)		    (0x0D80 + (n << 2))
#define CP_INTC_WAKEUP_ENABLE(n)	(0x0E00 + (n << 2))
#define CP_INTC_DEBUG_SELECT(n)		(0x0F00 + (n << 2))
#define CP_INTC_SYS_SECURE_ENABLE(n)	(0x1000 + (n << 2))
#define CP_INTC_HOST_NESTING_LEVEL(n)	(0x1100 + (n << 2))
#define CP_INTC_HOST_ENABLE(n)		(0x1500 + (n << 2))
#define CP_INTC_HOST_PRIO_VECTOR(n)	(0x1600 + (n << 2))
#define CP_INTC_VECTOR_ADDR(n)		(0x2000 + (n << 2))



#endif	/* __ASM_HARDWARE_CP_INTC_H */
