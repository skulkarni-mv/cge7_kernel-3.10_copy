#/**************************************************************************
# * Copyright 2010-2012, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */
include $(srctree)/drivers/net/asf/asfmodule/asfconfig.mk
obj-y := \
	ipsecfp.o \
	ipsfpapi.o \
	ipsecproc.o \
	ipsecfp_ah.o \
	ipsecfp_innerapi.o

obj-$(CONFIG_ASF_SEC3x) += ipsecfp_sec3x.o
obj-$(CONFIG_ASF_SEC4x) += ipsecfp_sec4x.o
obj-$(CONFIG_ASF_SEC4x) += ipsecfp_ah.o
obj-$(CONFIG_DPA) += ipsecfp_qman.o