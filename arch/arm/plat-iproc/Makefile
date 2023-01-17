
obj-y := sysfs.o bcm5301x.o iproc-cache.o headsmp.o shm.o
obj-$(CONFIG_SMP) += platsmp.o

obj-$(CONFIG_HOTPLUG_CPU)  += hotplug.o

obj-$(CONFIG_HAVE_CLK) += clk-iproc-armpll.o clk-iproc-pll.o

ifneq ($(CONFIG_MACH_KT2), y)
obj-$(CONFIG_HAVE_CLK) += clk-iproc-genpll.o
endif

export DRIVERS_MMC_HOST_DIR := drivers/mmc/host/
#obj-y+=../../../../../bcmdrivers/
obj-y+=../../../drivers/staging/bcmdrivers/
