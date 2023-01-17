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

/* Linux PSE Ethernet Driver debug header file */
#ifndef _PSE_DEBUG_H_
#define _PSE_DEBUG_H_


#define PSE_DEBUG /* FIXME: undefine for release version */
 #undef PSE_DEBUG

#ifdef PSE_DEBUG
int pse_debug_level(void);

enum _debug_level {
	DEBUG_LEVEL_TRACE = 0,
	DEBUG_LEVEL_DEBUG,
	DEBUG_LEVEL_INFO,
	DEBUG_LEVEL_WARNING,
	DEBUG_LEVEL_ERROR,
};


#define DEBUG_ON(level) (DEBUG_LEVEL_##level >= pse_debug_level())
#define DPRINT(level, fmt, args...) { \
		if (DEBUG_LEVEL_##level >= pse_debug_level()) \
			printk(fmt, ##args); \
	}

#else
#define DEBUG_ON(level) (0)
#define DPRINT(level, fmt, args...) do {} while (0)
#endif /* PSE_DEBUG */

#define DEBUG_ON_ERR (DEBUG_ON(ERR))
#define DEBUG_ON_WARN (DEBUG_ON(WARN))
#define DEBUG_ON_INFO (DEBUG_ON(INFO))
#define DEBUG_ON_DBG (DEBUG_ON(DEBUG))
#define DEBUG_ON_TRACE (DEBUG_ON(TRACE))
#define P_ERR(fmt, args...) DPRINT(ERROR, fmt, ## args);
#define P_WARN(fmt, args...) DPRINT(WARNING, fmt, ## args);
#define P_INFO(fmt, args...) DPRINT(INFO, fmt, ## args);
#define P_DBG(fmt, args...) DPRINT(DEBUG, fmt, ## args);
#define P_TRACE(fmt, args...) DPRINT(TRACE, fmt, ## args);
#endif  /* #define _PSE_DEBUG_H_ */
