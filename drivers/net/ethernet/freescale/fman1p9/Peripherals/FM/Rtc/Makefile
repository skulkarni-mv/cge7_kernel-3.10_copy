#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y           += -DVERSION=\"\"
#
#Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/fman1p9/ncsw_config.mk

NCSW_FM_INC = $(srctree)/drivers/net/ethernet/freescale/fman1p9/Peripherals/FM/inc

ccflags-y += -I$(NCSW_FM_INC)

obj-y		+= fsl-ncsw-RTC.o

fsl-ncsw-RTC-objs	:=   fm_rtc.o fman_rtc.o
