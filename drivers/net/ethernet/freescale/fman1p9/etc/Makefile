#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y           += -DVERSION=\"\"
#
#Include netcomm SW specific definitions

include $(srctree)/drivers/net/ethernet/freescale/fman1p9/ncsw_config.mk

obj-y		+= fsl-ncsw-etc.o

fsl-ncsw-etc-objs	:= mm.o memcpy.o sprint.o list.o error.o
