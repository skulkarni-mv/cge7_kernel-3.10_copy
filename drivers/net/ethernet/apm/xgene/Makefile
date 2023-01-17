#
# Makefile for APM X-Gene Ethernet Driver.
#

xgene-enet-objs := \
		apm_enet_common.o	\
		apm_enet_mac.o		\
		apm_enet_access.o	\
		apm_enet_misc.o		\
		apm_enet_tools.o	\
		apm_xgenet_mac.o	

ifdef CONFIG_XGENE_NET_IPV4_FORWARD_OFFLOAD
xgene-enet-objs += apm_enet_ifo.o
endif

obj-$(CONFIG_XGENE_NET) += xgene-enet.o

enet-xgene-objs := xgene_enet_sm_ring.o xgene_enet_sc_ring.o xgene_enet_gmac.o \
	xgene_enet_sgmac.o xgene_enet_xgmac.o xgene_enet_main.o xgene_enet_tools.o

ifdef CONFIG_NET_XGENE_DEBUG_UTIL
enet-xgene-objs += xgene_enet_utils.o
endif

obj-$(CONFIG_NET_XGENE_PHY) += xgene_enet_phy.o
obj-$(CONFIG_NET_XGENE) += enet-xgene.o
