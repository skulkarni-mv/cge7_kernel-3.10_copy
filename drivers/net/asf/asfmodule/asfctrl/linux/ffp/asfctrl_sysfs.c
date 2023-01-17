/**************************************************************************
 * Copyright 2010-2011, Freescale Semiconductor, Inc. All rights reserved.
 ***************************************************************************/
/*
 * File:	asfctrl_sysfs.c
 *
 * Description: SysFS interface for configuring the ASF Control Module
 *
 * Authors:	Hemant Agrawal <hemant@freescale.com>
 *
 */
/*
 * History
*  Version     Date         Author              Change Description
*  1.0        10/09/2010    Hemant Agrawal      Initial Development
*/
/***************************************************************************/
#include <linux/kernel.h>
#include <linux/string.h>

#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/if_vlan.h>
#include <linux/if_arp.h>
#include <linux/sysctl.h>
#ifdef ASFCTRL_TERM_FP_SUPPORT
#include <linux/if_pmal.h>
#endif
#include "../../../asfffp/driver/asf.h"
#include "asfctrl.h"

extern ASFCap_t  g_cap;
extern ASFFFPCap_t  g_fw_cap;


static ssize_t asfctrl_status_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ASFGetStatus());
}



static ssize_t asfctrl_version_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	ASF_uint8_t version[64];

	ASFGetAPIVersion(version);

	return sprintf(buf, "%s\n", version);
}


static ssize_t asfctrl_vsg_mode_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	int vsg, ret;
	ASF_Modes_t mode;
	ASF_Functions_t funcs;

	for (vsg = 0; vsg < g_cap.ulNumVSGs; vsg++) {
		ret = ASFGetVSGMode(vsg , &mode);
		if (ASF_SUCCESS != ret)
			continue;
		ret = ASFGetVSGFunctions(vsg, &funcs);
		if (ASF_SUCCESS != ret)
			continue;
		pr_info("vsg=%d, mode=%d, funcs=%d\n",
			vsg, mode , funcs.bIPsec);
	}
	return 1;
}


static ssize_t asfctrl_vsg_mode_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int vsg = -1, ret;
	unsigned int mode = 0;
	ASF_Functions_t funcs;
	int bipsec = -1;

	sscanf(buf, "vsg=%d mode=%u ipsec=%d", &vsg, &mode, &bipsec);

	if (-1 == vsg) {
		ASFCTRL_ERR("Wrong command format: \
			usage vsg=X mode=Y bipsec=Z");
		return count;
	}

	ret = ASFSetVSGMode(vsg, mode);

	if (ASF_SUCCESS != ret) {
		ASFCTRL_ERR("Error setting in vsg mode");
		return -EINVAL;
	}

	if (-1 == bipsec)
		return count;

	funcs.bIPsec = 1;

	switch (bipsec) {
	case ASFCTRL_TRUE:
		ASFEnableVSGFunctions(vsg, funcs);
		break;
	case ASFCTRL_FALSE:
		ASFDisableVSGFunctions(vsg, funcs);
		break;
	default:
		ASFCTRL_ERR("Wrong value of bipsec");
		break;
	}

	return count;
}

static ssize_t asfctrl_enable_show(struct kobject *kobj,
				struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", ASFGetStatus());;
}


static ssize_t asfctrl_enable_store(struct kobject *kobj,
				struct kobj_attribute *attr,
				const char *buf, size_t count)
{
	int enable;

	sscanf(buf, "%d", &enable);

	switch (enable) {
	case ASFCTRL_TRUE:
		ASFDeploy();
		break;
	case ASFCTRL_FALSE:
		ASFRemove();
		break;
	}

	return count;
}


static struct kobj_attribute asfctrl_enable_attr = \
	__ATTR(asfctrl_enable, 0644,
		asfctrl_enable_show, asfctrl_enable_store);


static struct kobj_attribute asfctrl_vsg_mode_attr = \
	__ATTR(asfctrl_vsg_mode, 0644,
		asfctrl_vsg_mode_show, asfctrl_vsg_mode_store);

static struct kobj_attribute asfctrl_version_attr = \
	__ATTR(asfctrl_version, 0444,
		asfctrl_version_show, NULL);

static struct kobj_attribute asfctrl_status_attr = \
	__ATTR(asfctrl_status, 0444,
		asfctrl_status_show, NULL);


struct kobject *asfctrl_kobj;
EXPORT_SYMBOL_GPL(asfctrl_kobj);

static struct attribute *asfctrl_attrs[] = {
	&asfctrl_enable_attr.attr,
	&asfctrl_vsg_mode_attr.attr,
	&asfctrl_version_attr.attr,
	&asfctrl_status_attr.attr,
	NULL
};

static struct attribute_group asfctrl_attr_group = {
	.attrs = asfctrl_attrs,
};



int asfctrl_sysfs_init(void)
{
	int error;

	asfctrl_kobj = kobject_create_and_add("asfctrl", NULL);
	if (!asfctrl_kobj) {
		error = -ENOMEM;
		goto exit;
	}

	error = sysfs_create_group(asfctrl_kobj, &asfctrl_attr_group);
	if (error)
		goto asfctrl_attr_exit;

	return 0;

asfctrl_attr_exit:
	kobject_put(asfctrl_kobj);
exit:
	return error;
}

int asfctrl_sysfs_exit(void)
{
	sysfs_remove_group(asfctrl_kobj, &asfctrl_attr_group);
	kobject_put(asfctrl_kobj);
	return 0;
}
