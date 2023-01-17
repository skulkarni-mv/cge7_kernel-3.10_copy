/**
 * AppliedMicro AM862xx QM Driver
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Pranavkumar Sawargaonkar <psawargaonkar@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * @file apm_qm_sysfs.h
 **
 */

#ifndef __APM_QM_SYSFS_H__
#define __APM_QM_SYSFS_H__
#include <asm/apm_qm_access.h>
#include <linux/device.h>

#if defined(CONFIG_SYSFS)
int apm_qm_add_sysfs(struct device_driver *driver);
void apm_qm_remove_sysfs(struct device_driver *driver);
#endif

#endif /* __APM_QM_SYSFS_H__ */
