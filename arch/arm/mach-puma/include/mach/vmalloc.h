/*
 * Copyright (C) 2011 Ericsson
 * Copyright (C) 2014 MontaVista Software, LLC.
 * (Modified by Niyas Ahamed Mydeen <nmydeen@mvista.com>
 * for MontaVista Software, LLC.)
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
#ifndef __ASM_ARCH_VMALLOC_H
#define __ASM_ARCH_VMALLOC_H

/* Below MACRO is no more needed for 3.10 */
#ifndef VMALLOC_END
/* 1GB of kernel virtual address space reserved for memories and ioremapping */
/*#define VMALLOC_END    (PAGE_OFFSET + 0x40000000)*/
#endif

#endif /* __ASM_ARCH_VMALLOC_H */
