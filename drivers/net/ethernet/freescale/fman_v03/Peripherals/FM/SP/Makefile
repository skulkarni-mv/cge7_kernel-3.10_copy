#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y           += -DVERSION=\"\"
#
#Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/fman_v03/ncsw_config.mk

NCSW_FM_INC = $(srctree)/drivers/net/ethernet/freescale/fman_v03/Peripherals/FM/inc

ccflags-y += -I$(NCSW_FM_INC)

obj-y		+= fsl-ncsw-sp.o

fsl-ncsw-sp-objs	:= fm_sp.o fman_sp.o
