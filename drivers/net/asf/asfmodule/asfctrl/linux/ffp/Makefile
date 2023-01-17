#/**************************************************************************
#  * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# * Authors:	Hemant Agrawal <hemant@freescale.com>
# *
# */
include $(srctree)/drivers/net/asf/asfmodule/asfconfig.mk

obj-y := asfctrl_sysfs.o \
             asfctrl_linux.o \
	     asfctrl_linux_ffp.o

ifeq ($(ASF_MULTICAST_TERMINATION_SUPPORT), y)
obj-y += asfctrl_linux_ffp_mc.o
endif
