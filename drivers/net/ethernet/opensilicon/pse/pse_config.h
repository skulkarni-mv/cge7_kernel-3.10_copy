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

#ifndef _PSE_CONFIG_H_
#define _PSE_CONFIG_H_

#include "pse_vlan.h"

#define DEFAULT_VID (0)

#define DEFAULT_MAC_0	{0x00, 0x01, 0x01, 0x02, 0x03, 0x00}
#define DEFAULT_MAC_1	{0x00, 0x01, 0x01, 0x02, 0x03, 0x01}
#define DEFAULT_MAC_2	{0x00, 0x01, 0x01, 0x02, 0x03, 0x02}

extern struct pse_vlan default_vlan;
extern struct pse_mac_table_data default_mac;
extern char *pse_mac_ethaddr[OPV5XC_MAC_MAX];

#endif /* _PSE_CONFIG_H_ */
