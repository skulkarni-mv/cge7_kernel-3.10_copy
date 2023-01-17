#/**************************************************************************
# * Copyright 2010-2013, Freescale Semiconductor, Inc. All rights reserved.
# ***************************************************************************/
#/*
# * File:	Makefile
# *
# */
include $(srctree)/drivers/net/asf/asfmodule/asfconfig.mk
obj-y := asfproc.o \
	    asfparry.o \
	    asfmpool.o \
	    asftmr.o \
	    asftcp.o \
	    asfreasm.o \
	    asfcore.o \
	    asfpktdump.o \
	    asficmpsend.o \
	    gplcode.o

ifeq ($(ASF_MULTICAST_TERMINATION_SUPPORT), y)
obj-y += asfmcastnapi.o
endif

ifeq ($(CONFIG_ASF_IPV6), y)
obj-y += asfipv6core.o
endif
