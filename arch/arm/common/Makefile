#
# Makefile for the linux kernel.
#

obj-y				+= firmware.o

obj-$(CONFIG_ICST)		+= icst.o
obj-$(CONFIG_SA1111)		+= sa1111.o
obj-$(CONFIG_PCI_HOST_VIA82C505) += via82c505.o
obj-$(CONFIG_DMABOUNCE)		+= dmabounce.o
obj-$(CONFIG_SHARP_LOCOMO)	+= locomo.o
obj-$(CONFIG_SHARP_PARAM)	+= sharpsl_param.o
obj-$(CONFIG_SHARP_SCOOP)	+= scoop.o
obj-$(CONFIG_PCI_HOST_ITE8152)  += it8152.o
obj-$(CONFIG_MCPM)		+= mcpm_head.o mcpm_entry.o mcpm_platsmp.o vlock.o
AFLAGS_mcpm_head.o		:= -march=armv7-a
AFLAGS_vlock.o			:= -march=armv7-a
