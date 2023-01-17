#
# Makefile config for the Freescale NetcommSW
#
NET_DPA     = $(srctree)/drivers/net
DRV_DPA     = $(srctree)/drivers/net/ethernet/freescale/dpa_v03
FMAN        = $(srctree)/drivers/net/ethernet/freescale/fman_v03

ifdef CONFIG_FMAN_V3H_V03
ccflags-y +=-include $(FMAN)/fmanv3h_dflags.h
endif
ifdef CONFIG_FMAN_V3L_V03
ccflags-y +=-include $(FMAN)/fmanv3l_dflags.h
endif
ifdef CONFIG_FMAN_LS1043
EXTRA_CFLAGS +=-include $(FMAN)/ls1043_dflags.h
endif

ccflags-y += -I$(DRV_DPA)/
ccflags-y += -I$(FMAN)/inc
ccflags-y += -I$(FMAN)/inc/cores
ccflags-y += -I$(FMAN)/inc/etc
ccflags-y += -I$(FMAN)/inc/Peripherals
ccflags-y += -I$(FMAN)/inc/flib

ifdef CONFIG_FMAN_V3H_V03
ccflags-y += -I$(FMAN)/inc/integrations/FMANV3H
endif
ifdef CONFIG_FMAN_V3L_V03
ccflags-y += -I$(FMAN)/inc/integrations/FMANV3L
endif
ifdef CONFIG_FMAN_LS1043
EXTRA_CFLAGS += -I$(FMAN)/inc/integrations/LS1043
endif

ccflags-y += -I$(FMAN)/src/inc
ccflags-y += -I$(FMAN)/src/inc/system
ccflags-y += -I$(FMAN)/src/inc/wrapper
ccflags-y += -I$(FMAN)/src/inc/xx
ccflags-y += -I$(srctree)/include/uapi/linux/fmd_v03
ccflags-y += -I$(srctree)/include/uapi/linux/fmd_v03/Peripherals
ccflags-y += -I$(srctree)/include/uapi/linux/fmd_v03/integrations
