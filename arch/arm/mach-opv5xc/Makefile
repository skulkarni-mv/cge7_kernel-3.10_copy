#
# Makefile for the linux kernel.
#

obj-y				:= board.o timer.o coherence.o
obj-$(CONFIG_ARCH_OPV5XC_CX4)	+= opv5xc.o dma.o
obj-$(CONFIG_ARCH_OPV5XC_ES1)	+= opv5xc.o clock.o dma.o
obj-$(CONFIG_ARCH_OPV5XC_ES2)	+= opv5xc.o clock.o dma.o
obj-$(CONFIG_SMP)		+= platsmp.o headsmp.o
