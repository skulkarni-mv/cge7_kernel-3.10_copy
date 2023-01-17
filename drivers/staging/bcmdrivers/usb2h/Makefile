
obj-$(CONFIG_IPROC_USB2H) := iproc_usb2h.o
iproc_usb2h-objs := bcm-iproc.o ehci-platform.o

ifeq ($(CONFIG_USB_OHCI_BCM), y)
iproc_usb2h-objs += ohci-platform.o
endif
