ifeq ($(CONFIG_ARCH_OPV5XC_CX4),y)
   zreladdr-y	+= 0xE0008000
params_phys-y	:= 0xE0000100
initrd_phys-y	:= 0xE0800000
else
ifeq ($(CONFIG_ARCH_OPV5XC_ES1),y)
   zreladdr-y	+= 0x00008000
params_phys-y	:= 0x00000100
initrd_phys-y	:= 0x00800000
else
   zreladdr-y	+= 0x00008000
params_phys-y	:= 0x00000100
initrd_phys-y	:= 0x00800000
endif
endif
