/**
 * AppliedMicro APM86xxx SoC QOS Classifier Driver Header
 *
 * Copyright (c) 2011 Applied Micro Circuits Corporation.
 * All rights reserved. Khuong Dinh <kdinh@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the
 * GNU General Public License for more details.
 *
 * @file apm_cle_qos.h
 *
 * This file declares Classifier APIs and macros in use by QOS Ethernet driver.
 *
 */
#ifndef _APM_CLE_QOS_H_
#define _APM_CLE_QOS_H_

#define MIN_CLASS_RATE 1000
#define DEFAULT_CLASS_RATE 800
#define CT_CLE_PTREE "ctcle"

#include "apm_enet_access.h"

enum {
	DROP = 0,
	ACCEPT,
};

int apm_qos_enable(struct net_device *dev);

#endif /* _APM_CLE_QOS_H_ */
