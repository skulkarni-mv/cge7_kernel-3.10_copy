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

#ifndef _OPV5XC_TIMEX_H
#define _OPV5XC_TIMEX_H

#define CLOCK_TICK_RATE		25000000

#define TM1_COUNT_OFFSET	0x00
#define TM1_RELOAD_OFFSET	0x04
#define TM1_MATCH1_OFFSET	0x08
#define TM1_MATCH2_OFFSET	0x0C

#define TM2_COUNT_OFFSET	0x10
#define TM2_RELOAD_OFFSET	0x14
#define TM2_MATCH1_OFFSET	0x18
#define TM2_MATCH2_OFFSET	0x1C

#define TM3_COUNT_OFFSET	0x20
#define TM3_RELOAD_OFFSET	0x24
#define TM3_MATCH1_OFFSET	0x28
#define TM3_MATCH2_OFFSET	0x2C

#define TM_CTRL_OFFSET		0x30
#define TM_INTR_STATUS_OFFSET	0x34
#define TM_INTR_MASK_OFFSET	0x38
#define TM_REV_OFFSET		0x3C

#define FTM_COUNT_LO_OFFSET	0x40
#define FTM_COUNT_HI_OFFSET	0x44
#define FTM_CTRL_OFFSET		0x48

/* TM_CTRL */
#define TM1_ENABLE	(1 << 0)
#define TM1_CR		(1 << 1)
#define TM1_OF_ENABLE	(1 << 2)
#define TM1_UPDATE	(1 << 3)
#define TM2_ENABLE	(1 << 4)
#define TM2_CR		(1 << 5)
#define TM2_OF_ENABLE	(1 << 6)
#define TM2_UPDATE	(1 << 7)
#define TM3_ENABLE	(1 << 8)
#define TM3_CR		(1 << 9)
#define TM3_OF_ENABLE	(1 << 10)
#define TM3_UPDATE	(1 << 11)

/* TM_INTR_STATUS */
#define TM1_MATCH1	(1 << 0)
#define TM1_MATCH2	(1 << 1)
#define TM1_OF		(1 << 2)
#define TM2_MATCH1	(1 << 3)
#define TM2_MATCH2	(1 << 4)
#define TM2_OF		(1 << 5)
#define TM3_MATCH1	(1 << 6)
#define TM3_MATCH2	(1 << 7)
#define TM3_OF		(1 << 8)

/* TM_INTR_MASK */
#define TM1_MATCH1_MASK	(1 << 0)
#define TM1_MATCH2_MASK	(1 << 1)
#define TM1_OF_MASK	(1 << 2)
#define TM2_MATCH1_MASK	(1 << 3)
#define TM2_MATCH2_MASK	(1 << 4)
#define TM2_OF_MASK	(1 << 5)
#define TM3_MATCH1_MASK	(1 << 6)
#define TM3_MATCH2_MASK	(1 << 7)
#define TM3_OF_MASK	(1 << 8)

/* FTM_CTRL */
#define FT_RESET	(1 << 0)
#define FT_RUN		(1 << 1)
#define FT_STROBE	(1 << 2)

#endif /* _OPV5XC_TIMEX_H */
