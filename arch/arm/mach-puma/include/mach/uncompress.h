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



/*
 * This does not append a newline
 */

#include <linux/types.h>
#include <linux/serial_reg.h>
#include "io.h"

static void putc(int c)
{
        volatile u32 * uart = 0;

        uart = (volatile u32 *)(PUMA_UART0_BASE);

        /*
         * Now, xmit each character
         */
        while (!(uart[UART_LSR] & UART_LSR_THRE))
                barrier();
        uart[UART_TX] = c;

        return;
}

static inline void flush(void)
{
}

/*
 * nothing to do
 */
#define arch_decomp_setup()
#define arch_decomp_wdog()
