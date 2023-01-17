/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#ifndef __OSI_DEBUG_H__
#define __OSI_DEBUG_H__
int osi_seq_printf(struct seq_file *m, char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
	if (m) {
		/* What the statements below do is the same as
		 * what seq_printf() does.
		 */
		int len;

		if (m->count < m->size) {
			len = vsnprintf(
					m->buf + m->count,
					m->size - m->count,
					fmt,
					args);
			if (m->count + len < m->size)
				m->count += len;

			goto complete;
		}

		m->size = m->count;
		return -1;
	}
	else
		return vprintk(fmt, args);

complete:
	va_end(args);
	return 0;
}
#endif
