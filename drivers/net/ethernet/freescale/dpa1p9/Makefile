#
# Makefile for the Freescale Ethernet controllers
#
ccflags-y += -DVERSION=\"\"
#
# Include netcomm SW specific definitions
include $(srctree)/drivers/net/ethernet/freescale/fman1p9/ncsw_config.mk

ccflags-y += -I$(NET_DPA)

obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_mac.o fsl_dpa.o
obj-$(CONFIG_PTP_1588_CLOCK_DPAA) += dpaa_ptp.o

fsl_dpa-objs += dpaa_ethtool.o dpaa_eth_sysfs.o dpaa_eth.o dpaa_eth_sg.o dpaa_eth_common.o
ifeq ($(CONFIG_FSL_DPAA_ETH_DEBUGFS),y)
fsl_dpa-objs += dpaa_debugfs.o
endif
ifeq ($(CONFIG_FSL_DPAA_1588),y)
fsl_dpa-objs += dpaa_1588.o
endif

fsl_mac-objs += mac.o mac-api.o

# Advanced drivers
ifeq ($(CONFIG_FSL_DPAA_ADVANCED_DRIVERS),y)
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_advanced.o
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_proxy.o
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_dpa_shared.o
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_dpa_macless.o
obj-$(CONFIG_FSL_DPAA_MACSEC) += fsl_dpa_macsec.o

fsl_advanced-objs += dpaa_eth_base.o
# suport for multiple drivers per kernel module comes in kernel 3.14
# so we are forced to generate several modules for the advanced drivers
fsl_proxy-objs += dpaa_eth_proxy.o
fsl_dpa_shared-objs += dpaa_eth_shared.o
fsl_dpa_macless-objs += dpaa_eth_macless.o
fsl_dpa_macsec-objs += dpaa_eth_macsec.o

ifeq ($(CONFIG_FSL_DPAA_MACSEC_DEBUGFS),y)
fsl_dpa_macsec-objs += dpaa_debugfs_macsec.o
endif

ifeq ($(CONFIG_FSL_DPAA_OFFLINE_PORTS),y)
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_oh.o

fsl_oh-objs += offline_port.o
endif
endif

# Generic driver
ifeq ($(CONFIG_FSL_DPAA_GENERIC_DRIVER),y)
obj-$(CONFIG_FSL_DPAA1P9_ETH) += fsl_generic.o

fsl_generic-objs += dpaa_eth_generic.o dpaa_eth_generic_sysfs.o dpaa_generic_ethtool.o
ifeq ($(CONFIG_FSL_DPAA_ETH_DEBUGFS),y)
fsl_generic-objs += dpaa_generic_debugfs.o
endif
endif

obj-$(CONFIG_FSL_CAPWAP) += capwap/

# Needed by the tracing framework
CFLAGS_dpaa_eth.o := -I$(src)
