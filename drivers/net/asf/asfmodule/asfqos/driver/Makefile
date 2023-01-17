#/**************************************************************************
# * Copyright 2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */

include $(srctree)/drivers/net/asf/asfmodule/asfconfig.mk

ifeq ($(CONFIG_DPA), y)
	obj-y := asfqos_sysfs.o asfqosapi_dpa.o
else
	obj-y := asfqos_sysfs.o asfqosapi.o
endif
