obj-y				:= i386.o init.o

obj-$(CONFIG_PCI_BIOS)		+= pcbios.o
obj-$(CONFIG_PCI_MMCONFIG)	+= direct.o mmconfig-shared.o
ifeq ($(BITS),32)
obj-$(CONFIG_PCI_MMCONFIG)	+= mmconfig_32.o
endif
obj-$(CONFIG_PCI_DIRECT)	+= direct.o
obj-$(CONFIG_PCI_OLPC)		+= olpc.o
obj-$(CONFIG_PCI_XEN)		+= xen.o

obj-y				+= fixup.o
obj-$(CONFIG_X86_INTEL_CE)      += ce4100.o
obj-$(CONFIG_ACPI)		+= acpi.o
obj-y				+= legacy.o irq.o

obj-$(CONFIG_STA2X11)           += sta2x11-fixup.o

obj-$(CONFIG_X86_VISWS)		+= visws.o

obj-$(CONFIG_X86_NUMAQ)		+= numaq_32.o
obj-$(CONFIG_X86_NUMACHIP)	+= numachip.o

obj-$(CONFIG_X86_INTEL_MID)	+= mrst.o

obj-y				+= common.o early.o
obj-y				+= bus_numa.o

obj-$(CONFIG_AMD_NB)		+= amd_bus.o
obj-$(CONFIG_PCI_CNB20LE_QUIRK)	+= broadcom_bus.o

ifeq ($(CONFIG_PCI_DEBUG),y)
EXTRA_CFLAGS += -DDEBUG
endif
