#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y           += -DVERSION=\"\"
#
#Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/fman1p8/ncsw_config.mk

NCSW_FM_INC = $(srctree)/drivers/net/ethernet/freescale/fman1p8/Peripherals/FM/inc

ccflags-y += -I$(NCSW_FM_INC)

obj-y		+= fsl-ncsw-Pcd.o

fsl-ncsw-Pcd-objs	:= fman_kg.o fman_prs.o fm_cc.o fm_kg.o fm_pcd.o fm_plcr.o fm_prs.o fm_manip.o

ifeq ($(CONFIG_FMAN_V3H_1P8),y)
fsl-ncsw-Pcd-objs	+= fm_replic.o
endif
ifeq ($(CONFIG_FMAN_V3L_1P8),y)
fsl-ncsw-Pcd-objs       += fm_replic.o
endif

