obj-$(CONFIG_IRQCHIP)			+= irqchip.o

obj-$(CONFIG_ARCH_BCM2835)		+= irq-bcm2835.o
obj-$(CONFIG_ARCH_EXYNOS)		+= exynos-combiner.o
ifeq ($(CONFIG_MACH_ARMADA_380),y)
obj-$(CONFIG_ARCH_MVEBU)		+= irq-armada-370-xp.o
endif
obj-$(CONFIG_MVEBU_PIC)			+= irq-mvebu-pic.o
obj-$(CONFIG_ARCH_MXS)			+= irq-mxs.o
obj-$(CONFIG_ARCH_S3C24XX)		+= irq-s3c24xx.o
obj-$(CONFIG_METAG)			+= irq-metag-ext.o
obj-$(CONFIG_METAG_PERFCOUNTER_IRQS)	+= irq-metag.o
obj-$(CONFIG_ARCH_SUNXI)		+= irq-sun4i.o
obj-$(CONFIG_ARCH_SPEAR3XX)		+= spear-shirq.o
obj-$(CONFIG_ARM_GIC)			+= irq-gic.o irq-gic-common.o
obj-$(CONFIG_ARM_GIC_V2M)		+= irq-gic-v2m.o
obj-$(CONFIG_ARM_GIC_V3)		+= irq-gic-v3.o irq-gic-common.o
obj-$(CONFIG_ARM_GIC_V3_ITS)		+= irq-gic-v3-its.o
obj-$(CONFIG_ARM_VIC)			+= irq-vic.o
obj-$(CONFIG_SIRF_IRQ)			+= irq-sirfsoc.o
obj-$(CONFIG_RENESAS_INTC_IRQPIN)	+= irq-renesas-intc-irqpin.o
obj-$(CONFIG_RENESAS_IRQC)		+= irq-renesas-irqc.o
obj-$(CONFIG_VERSATILE_FPGA_IRQ)	+= irq-versatile-fpga.o
obj-$(CONFIG_ARCH_VT8500)		+= irq-vt8500.o
obj-$(CONFIG_LS1_MSI)			+= irq-ls1-msi.o
obj-$(CONFIG_MVEBU_ODMI)		+= irq-mvebu-odmi.o
obj-$(CONFIG_MVEBU_SEI_IRQ)		+= irq-mvebu-sei.o
