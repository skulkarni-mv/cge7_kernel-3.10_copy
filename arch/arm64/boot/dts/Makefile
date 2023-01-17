dtb-$(CONFIG_ARCH_THUNDER) += thunder-88xx.dtb thunder-88xx-2n.dtb \
			      thunder-8104.dtb
dtb-$(CONFIG_ARCH_VEXPRESS) += rtsm_ve-aemv8a.dtb foundation-v8.dtb
dtb-$(CONFIG_ARCH_THUNDER_EMULATOR) += thunder-armv8.dtb
dtb-$(CONFIG_ARCH_XGENE) += apm-mustang.dtb
dtb-$(CONFIG_ARCH_FSL_LS1043A) += fsl-ls1043a-simu.dtb fsl-ls1043a-emu.dtb fsl-ls1043a-qds.dtb fsl-ls1043a-rdb.dtb
dtb-$(CONFIG_ARCH_LAYERSCAPE) += fsl-ls2085a-simu.dtb fsl-ls2085a-qds.dtb fsl-ls2085a-rdb.dtb \
				 fsl-ls2080a-simu.dtb fsl-ls2080a-qds.dtb fsl-ls2080a-rdb.dtb
dtb-$(CONFIG_ARCH_NORTHSTAR2) += ns2_svk.dtb broadcom-ns2-emgw.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-7040-db-router.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-router.dtb
dtb-$(CONFIG_ARCH_MVEBU) += armada-8040-db-A.dtb

dtb-$(CONFIG_ARCH_ZYNQMP) += zynqmp-zcu102-revB.dtb

targets += dtbs
targets += $(dtb-y)

dtbs: $(addprefix $(obj)/, $(dtb-y))

clean-files := *.dtb
