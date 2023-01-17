/**
 * AppliedMicro APM86xxx SoC Ethernet QOS Driver
 *
 * Copyright (c) 2012 Applied Micro Circuits Corporation.
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
 * APM86xxx Ethernet QOS implementation for APM86xxx SoC.
 */
#ifndef __APM_ENET_QOS_H__
#define __APM_ENET_QOS_H__

#include <asm/apm_qm_core.h>
#include "apm_cle_qos.h"

/* Declaration */

struct apm_enet_qos_ctx {
	u32 init_done;                  /* QOS init done */
	u32 enable;                     /* Enabled this feature */
	struct apm_qos_param qos_cfg;
};

/* Forward declaration */
struct apm_enet_dev_base;

int apm_enet_qos_init(struct apm_enet_dev_base *priv);
int apm_enet_qos_enable(struct apm_enet_dev_base *priv, u32 enable);

#endif /* __APM_ENET_QOS_H__ */
