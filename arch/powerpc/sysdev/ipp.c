/*
 * APM SCU and iPP Messaging Driver
 * 
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * All rights reserved. Prodyut Hazarika <phazarika@apm.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/init.h>
#include <linux/interrupt.h>
#include <linux/device.h>
#include <linux/proc_fs.h>
#include <linux/module.h>
#include <linux/of_platform.h>
#include <linux/completion.h>
#include <linux/delay.h>
#include <linux/cpumask.h>
#include <linux/firmware.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/dma-mapping.h>
#include <asm/uaccess.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/apm_ipp_interface.h>
#include <asm/ipp.h>
#include <asm/apm86xxx_ocm.h>
#include <asm/apm86xxx_soc.h>
#include <asm/apm_ipp_imageinfo.h>
#include <asm/dcr.h>
#include <asm/mpic.h>
#include <asm/cacheflush.h>
#if !defined(CONFIG_APM862xx)
#include <asm/apm_ahbc_csr.h>
#endif

struct ipp_drv {
	void __iomem *regs;	/* Used to indicate driver initialized? */
	int trace_mode;
	int irq;
	int gpio_irq;
	int sys_msg;
	int ocm_offset;
	int ipp_active;
	int ipp_fw_loaded;
	int secure_mode;
	int dp_mode;
	int early_init;
	u32 laddr;
	u32 uaddr;
	u32 gpio_wakeup_mask;
	u32 gpio_lvl_mask;
	u32 scu_reg_base;
	u32 mpa_reg_base;
	u32 msg_reg_base;
	u32 pcode_offset;
	u32 acode_offset;
	u32 intstat_offset;
	u32 intmask_offset;
	u32 cpu_intstat_offset;
	u32 paramreg_offset;
	u32 scratch_offset;
	u32 cpu_offset;
	u32 in_msg[MAX_PPC_CORES];
	struct platform_device *pdev;
	ipp_pwr_state_t __iomem *ipp_buf;
};

/* LINUX_IPP_ADDR_BUF_MAX can be extended if needed */
#define LINUX_IPP_ADDR_BUF_MAX	32
volatile static unsigned int addr_msg_buf[LINUX_IPP_ADDR_BUF_MAX]
	____cacheline_aligned_in_smp;

#define TRACE_SOC	0
#define TRACE_CPM	1
#define TRACE_PLB	2
#define TRACE_PLB2X	3
#define TRACE_CORE0	4
#define TRACE_CORE1	5
#define TRACE_MAX	6

#define IPP_FW_NAME	"ipp_run.bin"
#define TRACE_CPM_VAL	(SOC_STRK_CLKMON_SEL3_MASK| \
			(0x1<<STRK_CLKMON_SEL3_SHIFT))
#define TRACE_PLB_VAL	(SOC_STRK_CLKMON_SEL3_MASK| \
			(0x2<<STRK_CLKMON_SEL3_SHIFT))
#define TRACE_PLB2X_VAL	(SOC_STRK_CLKMON_SEL3_MASK| \
			(0x3<<STRK_CLKMON_SEL3_SHIFT))
#define TRACE_CORE0_VAL	(SOC_STRK_CLKMON_SEL3_MASK| \
			(0x4<<STRK_CLKMON_SEL3_SHIFT))
#define TRACE_CORE1_VAL	(SOC_STRK_CLKMON_SEL3_MASK| \
			(0x5<<STRK_CLKMON_SEL3_SHIFT))

struct apm86xxx_trace_modes
{
        u32 val;
        const char *name;
};
static struct ipp_drv ipp_data = { .regs = NULL };
static DEFINE_MUTEX(ipp_mutex);
static BLOCKING_NOTIFIER_HEAD(ipp_chain_head);
static DECLARE_COMPLETION(ipp_cpu_complete);
static struct apm86xxx_trace_modes apm86xxx_trace_modes[TRACE_MAX] = {
        [TRACE_SOC]  = {0, "soc" },
        [TRACE_CPM]  = {TRACE_CPM_VAL, "cpm" },
        [TRACE_PLB]  = {TRACE_PLB_VAL, "plb" },
        [TRACE_PLB2X]  = {TRACE_PLB2X_VAL, "plb2x" },
        [TRACE_CORE0]  = {TRACE_CORE0_VAL, "core0" },
        [TRACE_CORE1]  = {TRACE_CORE1_VAL, "core1" },
};

static irqreturn_t hdlr_gpio(int irq, void *dev_instance)
{
	printk(KERN_INFO "%s\n", __func__);

	return IRQ_HANDLED;
}

static irqreturn_t hdlr_ipp(int irq, void *dev_instance)
{
	volatile u32 val;
	int cpu;
	u32 pack_mask, areq_mask;

	/* For SMP, always use DEFAULT_SMP_IPPMSG_CPU for messaging */
	cpu = (num_online_cpus() > 1) ? DEFAULT_SMP_IPPMSG_CPU
				: hard_smp_processor_id();

	BUG_ON(!ipp_data.scu_reg_base);

	/* Bit offsets are same for each CPU */
	pack_mask = P0_PCODE_ACKMASK_MASK;
	areq_mask = P0_ACODE_REQMASK_MASK;

	val = in_be32((volatile u32 *)(ipp_data.msg_reg_base +
			ipp_data.intstat_offset +
			cpu*ipp_data.cpu_intstat_offset));
	if (val & pack_mask) {
		out_be32((volatile u32 *)(ipp_data.msg_reg_base +
			ipp_data.intstat_offset +
			cpu*ipp_data.cpu_intstat_offset), pack_mask);
		complete(&ipp_cpu_complete);
	}
	if (val & areq_mask) {
		ipp_data.in_msg[cpu] = in_be32((volatile u32 *)
			(ipp_data.msg_reg_base + ipp_data.acode_offset +
				(cpu*ipp_data.cpu_offset)));
		out_be32((volatile u32 *)(ipp_data.msg_reg_base +
			ipp_data.intstat_offset +
			cpu*ipp_data.cpu_intstat_offset), areq_mask);
	}

	return IRQ_HANDLED;
}

int register_ipp_fwload_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_register(&ipp_chain_head, nb);
}
EXPORT_SYMBOL(register_ipp_fwload_notifier);

int unregister_ipp_fwload_notifier(struct notifier_block *nb)
{
	return blocking_notifier_chain_unregister(&ipp_chain_head, nb);
}
EXPORT_SYMBOL(unregister_ipp_fwload_notifier);

static void ipp_notifier_call_chain(unsigned long val)
{
	BUG_ON(!ipp_data.pdev);
	if (blocking_notifier_call_chain(&ipp_chain_head, val, NULL)
			== NOTIFY_BAD) {
		dev_info(&ipp_data.pdev->dev,
			"iPP Firmware Loaded notifier failure\n");
	}
}

static int __write_ipp_raw_msg(u32 msg_data, u32 msg_param, u32 *retcode)
{
	int cpu; 
	u32 pack_mask, areq_mask;
	int retval = 0;
	int busy_wait = irqs_disabled();

	if (ipp_data.early_init) {
		busy_wait = 1;
	}

	/* For SMP, always use DEFAULT_SMP_IPPMSG_CPU for messaging */
	cpu = (num_online_cpus() > 1) ? DEFAULT_SMP_IPPMSG_CPU
					: hard_smp_processor_id();
	/* Bit offsets are same for each CPU */
	pack_mask = P0_PCODE_ACKMASK_MASK;
	areq_mask = P0_ACODE_REQMASK_MASK;

#if defined(CONFIG_NOT_COHERENT_CACHE)
	flush_dcache_range((u32)addr_msg_buf, (u32)addr_msg_buf +
			sizeof(addr_msg_buf) + sizeof(u32));
#endif

	/* Write the message param followed by message */
	out_be32((volatile u32 *)(ipp_data.msg_reg_base +
			ipp_data.paramreg_offset +
			(cpu*ipp_data.cpu_offset)), msg_param);
	out_be32((volatile u32 *)(ipp_data.msg_reg_base +
			ipp_data.pcode_offset +
			(cpu*ipp_data.cpu_offset)), msg_data);

	if (retcode)
		*retcode = 0;

	if (busy_wait) {
		u32 val; 
		int count = 500;
		while (count-- > 0) {
			udelay(100);
			val = in_be32((volatile __iomem u32 *)
				(ipp_data.msg_reg_base +
				ipp_data.intstat_offset +
				cpu*ipp_data.cpu_intstat_offset));
			if (val & areq_mask) {
				ipp_data.in_msg[cpu] = in_be32
					((volatile __iomem u32 *)
					(ipp_data.msg_reg_base +
					ipp_data.acode_offset +
					(cpu*ipp_data.cpu_offset)));
				if (retcode)
					*retcode = ipp_data.in_msg[cpu];
				out_be32((volatile __iomem u32 *)(
					ipp_data.msg_reg_base +
					ipp_data.intstat_offset +
					cpu*ipp_data.cpu_intstat_offset),
					areq_mask);
			}
			if (val & pack_mask) {
				out_be32((volatile __iomem u32 *)
					(ipp_data.msg_reg_base +
					ipp_data.intstat_offset +
					cpu*ipp_data.cpu_intstat_offset),
					pack_mask);
				goto out;
			}
		}
		retval = -ETIMEDOUT;
	} else {
		if (wait_for_completion_timeout(&ipp_cpu_complete, 
							HZ * 2) == 0) {
			printk("iPP Messaging from Core%d Timed out\n",
				cpu);
			retval = -ETIMEDOUT;
		} else {
			if (retcode)
				*retcode = ipp_data.in_msg[cpu];
		}
	}

out:
	return retval;
}

int write_ipp_raw_msg(u32 msg_data, u32 msg_param)
{
	int ret;

	mutex_lock(&ipp_mutex);
	ret = __write_ipp_raw_msg(msg_data, msg_param, NULL);
	mutex_unlock(&ipp_mutex);
	return ret;
}

int write_ipp_raw_msg_withresp(u32 msg_data, u32 msg_param, u32 *resp)
{
	int ret;

	mutex_lock(&ipp_mutex);
	ret = __write_ipp_raw_msg(msg_data, msg_param, resp);
	mutex_unlock(&ipp_mutex);
	return ret;
}

static int __apm86xxx_disable_mem_shutdown(u32 __iomem *ram_shutdown_addr,
						u32 mem_rdy_mask)
{
	volatile u32 data;
	int mem_rdy_timeout_cnt;
	
	/* Disable Module Shutdown ONLY if in shutdown */
	/* common across register groups */
	if (ram_shutdown_addr) {
		BUG_ON(!mem_rdy_mask);
		if ((data = in_be32(ram_shutdown_addr))) {
			out_be32(ram_shutdown_addr, 0);
			data = in_be32(ram_shutdown_addr);
			ram_shutdown_addr++;
			mem_rdy_timeout_cnt = MEM_RDY_TIMEOUT_COUNT;
			while (mem_rdy_timeout_cnt-- > 0) {
				if ((data = in_be32(ram_shutdown_addr))
					== 0xFFFFFFFF)
					return 0;
			}
			if (mem_rdy_timeout_cnt <= 0) 
				return -EIO;
		}
	}
	return 0;
}

static int apm86xxx_sec_disable_mem_shutdown(u32 __iomem *ram_shutdown_addr,
						u32 mem_rdy_mask)
{
	int rc = 0;

	if (mem_rdy_mask & MPIC_F1_MASK) {
		rc = apm86xxx_dp_cfg(IPP_DP_CMD_CLR_MEMSHUTDOWN,  
			IPP_DP_RES_SDU, 0, 0xddd817000ULL, 
			0xddd817000ULL + 0xFFF);
		if (rc != 0) {
			printk(KERN_ERR "failed to release "
				"LCD memory error %d\n", rc); 
			return -EIO;
		}
	}
	return rc;
}

int apm86xxx_disable_mem_shutdown(u32 __iomem *ram_shutdown_addr,
					u32 mem_rdy_mask)
{
	int ret;
	
	if (apm86xxx_is_dp_mode() && (mem_rdy_mask & MPIC_F1_MASK)) {
		ret = apm86xxx_sec_disable_mem_shutdown(ram_shutdown_addr,
						mem_rdy_mask);
		return ret;
	}
	mutex_lock(&ipp_mutex);
	ret = __apm86xxx_disable_mem_shutdown(ram_shutdown_addr, mem_rdy_mask);
	mutex_unlock(&ipp_mutex);
	return ret;
}
EXPORT_SYMBOL(apm86xxx_disable_mem_shutdown);

/* Reset function for secure boot mode - send SlimPro message */
static int secure_reset_apm86xxx_block(struct apm86xxx_reset_ctrl *reset_ctrl)
{
	u32 data, len;
	int ret = -EIO, regcnt = 0;
	struct ipp_secboot_msg_hdr *hdrp =
		(struct ipp_secboot_msg_hdr *)addr_msg_buf;
	struct ipp_regoff *regp = (struct ipp_regoff *)
		((u32)addr_msg_buf + sizeof(struct ipp_secboot_msg_hdr));
	u32 regaddr[REG_GROUP_SRST_CLKEN_MAX][3] = 
		{{SCU_CLKEN_ADDR, SCU_SRST_ADDR, SCU_CSR_SRST_ADDR},
		 {SCU_CLKEN1_ADDR, SCU_SRST1_ADDR, SCU_CSR_SRST1_ADDR}};

	/* Take lock before modifying the shared addr_msg_buf */
	mutex_lock(&ipp_mutex);
	memset((void *)addr_msg_buf, 0, sizeof(addr_msg_buf));

	/* Assert CSR Reset */
	if (reset_ctrl->csr_reset_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][2];
		regp->mask = reset_ctrl->csr_reset_mask;
		regp->val = reset_ctrl->csr_reset_mask;
		regp++;
		regcnt++;
	}

	/* Assert Reset */
	if (reset_ctrl->reset_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][1];
		regp->mask = reset_ctrl->reset_mask;
		regp->val = reset_ctrl->reset_mask;
		regp++;
		regcnt++;
	}

	/* De-assert Clock */
	if (reset_ctrl->clken_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][0];
		regp->mask = reset_ctrl->clken_mask;
		regp->val = 0;
		regcnt++;
	}

	/* Update header now */
	hdrp->cmd = IPP_ENC_SECBOOTMSG_CMD(IPP_SECBOOT_MSG_WRITEREG_OFFSET,
					IPP_MSG_PARAM_UNUSED,
					IPP_REGBANK_SCU, regcnt);
	/* hdrp.status is filled by SlimPro */
	hdrp->status = 0;
	len = sizeof(struct ipp_secboot_msg_hdr) +
				regcnt*sizeof(struct ipp_regoff) - sizeof(u32);
	hdrp->len = len;
	wmb();

	/* Address control byte and parameter not necessary */
	data = IPP_ENCODE_ADDR_MSG(IPP_SECUREBOOT_ADDR_MSG_HDLR,
					IPP_MSG_CONTROL_URG_BIT,
					(u8)ipp_data.uaddr);
	if ((ret = __write_ipp_raw_msg(data, ipp_data.laddr, NULL)) < 0) {
		printk("Failed to write iPP Addr Msg %d\n", ret);
		goto out;
	}

	/* Don't clear reset if reset_type is ASSERT_RESET_FLAG */
	if (reset_ctrl->reset_type == ASSERT_RESET_FLAG) 
		goto out;

	memset((void *)addr_msg_buf, 0, sizeof(addr_msg_buf));
	regp = (struct ipp_regoff *) ((u32)addr_msg_buf +
			sizeof(struct ipp_secboot_msg_hdr));

	/* Read values back to make sure AXI writes are posted */
	if (reset_ctrl->clken_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][0];
		regp->mask = reset_ctrl->clken_mask;
		regp->val = reset_ctrl->clken_mask;
		regp++;
	}
	if (reset_ctrl->reset_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][1];
		regp->mask = reset_ctrl->reset_mask;
		regp->val = 0;
		regp++;
	}
	if (reset_ctrl->csr_reset_mask) {
		regp->offset = regaddr[reset_ctrl->reg_group][2];
		regp->mask = reset_ctrl->csr_reset_mask;
		regp->val = 0;
	}

	/* Update header now */
	hdrp->cmd = IPP_ENC_SECBOOTMSG_CMD(IPP_SECBOOT_MSG_WRITEREG_OFFSET,
					IPP_MSG_PARAM_UNUSED,
					IPP_REGBANK_SCU, regcnt);
	/* hdrp.status is filled by SlimPro */
	hdrp->status = 0;
	len = sizeof(struct ipp_secboot_msg_hdr) +
				regcnt*sizeof(struct ipp_regoff) - sizeof(u32);
	hdrp->len = len;
	wmb();

	/* Address control byte and parameter not necessary */
	data = IPP_ENCODE_ADDR_MSG(IPP_SECUREBOOT_ADDR_MSG_HDLR,
					IPP_MSG_CONTROL_URG_BIT,
					(u8)ipp_data.uaddr);
	if ((ret = __write_ipp_raw_msg(data, ipp_data.laddr, NULL)) < 0) {
		printk("Failed to write iPP Addr Msg %d\n", ret);
	}

out:
	mutex_unlock(&ipp_mutex);

	if (ret) 
		return ret;
	
	/* Disable Module Shutdown ONLY if in shutdown */
	/* common across register groups */
	return __apm86xxx_disable_mem_shutdown(reset_ctrl->ram_shutdown_addr, 
						reset_ctrl->mem_rdy_mask);
}

/* Module Reset Sequence */
/* 1) Enable Module clock (set appropriate bit in SCU_CLKEN or SCU_CLKEN1)   */
/* 2) Release the module's reset (clear the appropriate bit in               */
/*      SCU_SRST or SCU_SRST1 register)                                      */
/* 3) Clear Module CSR reset (clear appropriate bit in SCU_CSR_SRST          */
/*      or SCU_CSR_SRST1 register)                                           */
/* 4) Disable Module's RAM shutdown (write 0 to CFG_MEM_RAM_SHUTDOWN         */
/*      register in module's Global Diag section)                            */
/* 5) Read back CFG_MEM_RAM_SHUTDOWN register to ensure AXI write was posted */
/* 6) Wait till the module's MEM_RDY is set by polling for appropriate bit   */
/*      in SCU_MRDY register to be set                                       */

int __reset_apm86xxx_block(struct apm86xxx_reset_ctrl *reset_ctrl)
{
	volatile u32 data;
	u32 regaddr[REG_GROUP_SRST_CLKEN_MAX][3] = 
		{{SCU_CLKEN_ADDR, SCU_SRST_ADDR, SCU_CSR_SRST_ADDR},
		 {SCU_CLKEN1_ADDR, SCU_SRST1_ADDR, SCU_CSR_SRST1_ADDR}};

	if (reset_ctrl->reg_group >= REG_GROUP_SRST_CLKEN_MAX)
		return -EINVAL;

	if (ipp_data.secure_mode || ipp_data.dp_mode) 
		return secure_reset_apm86xxx_block(reset_ctrl);

	BUG_ON(!ipp_data.scu_reg_base);
	BUG_ON(!reset_ctrl);

	/* Assert reset first */
	if (reset_ctrl->csr_reset_mask) 
		setbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][2]),
			reset_ctrl->csr_reset_mask);
	if (reset_ctrl->reset_mask)
		setbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][1]),
			reset_ctrl->reset_mask);
	if (reset_ctrl->clken_mask) 
		clrbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][0]),
			reset_ctrl->clken_mask);

	/* Don't clear reset if reset_type is ASSERT_RESET_FLAG */
	if (reset_ctrl->reset_type == ASSERT_RESET_FLAG) 
		return 0;

	/* Read values back to make sure AXI writes are posted */
	if (reset_ctrl->clken_mask) {
		setbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][0]),
			reset_ctrl->clken_mask);
		data = in_be32((volatile u32 *)(ipp_data.scu_reg_base +
				regaddr[reset_ctrl->reg_group][0]));
	}
	if (reset_ctrl->reset_mask) {
		clrbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][1]),
			reset_ctrl->reset_mask);
		data = in_be32((volatile u32 *)(ipp_data.scu_reg_base +
				regaddr[reset_ctrl->reg_group][1]));
	}
	if (reset_ctrl->csr_reset_mask) {
		clrbits32((volatile u32 *)(ipp_data.scu_reg_base +
			regaddr[reset_ctrl->reg_group][2]),
			reset_ctrl->csr_reset_mask);
		data = in_be32((volatile u32 *)(ipp_data.scu_reg_base +
				regaddr[reset_ctrl->reg_group][2]));
	}
	
	/* Disable Module Shutdown ONLY if in shutdown */
	/* common across register groups */
	return __apm86xxx_disable_mem_shutdown(reset_ctrl->ram_shutdown_addr, 
						reset_ctrl->mem_rdy_mask);
}

int secure_write_reg(enum ipp_regbank_id bankid, u32 offset,
				u32 mask, u32 val)
{
	struct ipp_secboot_msg_hdr *hdrp =
		(struct ipp_secboot_msg_hdr *)addr_msg_buf;
	struct ipp_regoff *regp = (struct ipp_regoff *)
		((u32)addr_msg_buf + sizeof(struct ipp_secboot_msg_hdr));
	u32 data, len;
	int ret = -EIO;

	len = sizeof(struct ipp_secboot_msg_hdr) +
			sizeof(struct ipp_regoff) - sizeof(u32);

	/* Take lock before modifying the shared addr_msg_buf */
	mutex_lock(&ipp_mutex);

	memset((void *)addr_msg_buf, 0, sizeof(addr_msg_buf));
	/* We are just writing one set of registers */
	/* We are just writing 1 register */
	hdrp->cmd = IPP_ENC_SECBOOTMSG_CMD(IPP_SECBOOT_MSG_WRITEREG_OFFSET,
					IPP_MSG_PARAM_UNUSED,
					(u8)bankid, 1);
	/* hdrp.status is filled by SlimPro */
	hdrp->status = 0;
	hdrp->len = len;
	regp->offset = offset;
	regp->mask = mask;
	regp->val = val;
	wmb();

	/* Address control byte and parameter not necessary */
	data = IPP_ENCODE_ADDR_MSG(IPP_SECUREBOOT_ADDR_MSG_HDLR,
					IPP_MSG_CONTROL_URG_BIT,
					(u8)ipp_data.uaddr);
	if ((ret = __write_ipp_raw_msg(data, ipp_data.laddr, NULL)) < 0) {
		dev_info(&ipp_data.pdev->dev,
			"Failed to write iPP Addr Msg %d\n", ret);
	}
	mutex_unlock(&ipp_mutex);
	return ret;
}

int secure_read_reg(enum ipp_regbank_id bankid, u32 offset, u32 *val)
{
	struct ipp_secboot_msg_hdr *hdrp =
		(struct ipp_secboot_msg_hdr *)addr_msg_buf;
	struct ipp_regoff *regp = (struct ipp_regoff *)
		((u32)addr_msg_buf + sizeof(struct ipp_secboot_msg_hdr));
	u32 data, len;
	int ret = -EIO;

	/* We are just writing one set of registers */
	len = sizeof(struct ipp_secboot_msg_hdr) +
			sizeof(struct ipp_regoff) - sizeof(u32);

	/* Take lock before modifying the shared addr_msg_buf */
	mutex_lock(&ipp_mutex);

	memset((void *)addr_msg_buf, 0, sizeof(addr_msg_buf));
	/* We are just reading 1 register */
	hdrp->cmd = IPP_ENC_SECBOOTMSG_CMD(IPP_SECBOOT_MSG_READREG_OFFSET,
					IPP_MSG_PARAM_UNUSED,
					(u8)bankid, 1);
	/* hdrp.status is filled by SlimPro */
	hdrp->status = 0;
	hdrp->len = len;
	regp->offset = offset;
	regp->mask = regp->val = 0;
	wmb();

	/* Address control byte and parameter not necessary */
	data = IPP_ENCODE_ADDR_MSG(IPP_SECUREBOOT_ADDR_MSG_HDLR,
					IPP_MSG_CONTROL_URG_BIT,
					(u8)ipp_data.uaddr);
	if ((ret = __write_ipp_raw_msg(data, ipp_data.laddr, NULL)) < 0) {
		dev_info(&ipp_data.pdev->dev,
			"Failed to write iPP Addr Msg %d\n", ret);
	} else {
		*val = regp->val;
	}

	mutex_unlock(&ipp_mutex);
	return ret;
}

void apm86xxx_set_led(u32 led_mask)
{
	if (ipp_data.secure_mode || ipp_data.dp_mode) {
		secure_write_reg(IPP_REGBANK_MPA, MPA_LED_ADDR,
					led_mask, led_mask);
		return;
	}

	BUG_ON(!ipp_data.scu_reg_base);
	mutex_lock(&ipp_mutex);
	setbits32((volatile u32 *)(ipp_data.mpa_reg_base + MPA_LED_ADDR),
			led_mask);
	mutex_unlock(&ipp_mutex);
}

void apm86xxx_clear_led(u32 led_mask)
{
	if (ipp_data.secure_mode || ipp_data.dp_mode) {
		secure_write_reg(IPP_REGBANK_MPA, MPA_LED_ADDR,
					led_mask, 0);
		return;
	}

	BUG_ON(!ipp_data.scu_reg_base);
	mutex_lock(&ipp_mutex);
	clrbits32((volatile u32 *)(ipp_data.mpa_reg_base + MPA_LED_ADDR),
			led_mask);
	mutex_unlock(&ipp_mutex);
}

u32 *apm86xxx_get_scu_base(void)
{
	BUG_ON(!ipp_data.scu_reg_base);
	return (u32 *)(ipp_data.scu_reg_base);
}

int apm86xxx_write_scu_reg(u32 offset, u32 val)
{
	volatile u32 *scu_addr;

	if (ipp_data.secure_mode || ipp_data.dp_mode) {
		return secure_write_reg(IPP_REGBANK_SCU, offset,
						0xFFFFFFFF, val);
	}
	BUG_ON(!ipp_data.scu_reg_base);

	if (offset < 0x1FF) {
		mutex_lock(&ipp_mutex);
		scu_addr = (volatile u32 *) (ipp_data.scu_reg_base + offset);
		out_be32(scu_addr, val);
		val = in_be32(scu_addr);
		mutex_unlock(&ipp_mutex);
		return 0;
	} 
	return -EINVAL;
}
EXPORT_SYMBOL(apm86xxx_write_scu_reg);

int APM_OUT_BE32(volatile u32 *addr, u32 val)
{
    u32 scu_base = (u32) ipp_data.scu_reg_base;

	if ((u32)addr < (scu_base + 0x1FF) && (u32)addr > scu_base) {
		if (ipp_data.secure_mode || ipp_data.dp_mode) {
			return secure_write_reg(IPP_REGBANK_SCU, (u32)addr - scu_base, 0xFFFFFFFF, val);
		}
	}
	mutex_lock(&ipp_mutex);
	out_be32(addr, val);
	val = in_be32(addr);
	mutex_unlock(&ipp_mutex);

	return 0;
}

int apm86xxx_read_scu_reg(u32 offset, u32 *val)
{
	volatile u32 *scu_addr;

	if (ipp_data.secure_mode) {
		return secure_read_reg(IPP_REGBANK_SCU, offset, val);
	}
	BUG_ON(!ipp_data.scu_reg_base);

	if (offset < 0x1FF) {
		mutex_lock(&ipp_mutex);
		scu_addr = (volatile u32 *) (ipp_data.scu_reg_base + offset);
		*val = in_be32(scu_addr);
		mutex_unlock(&ipp_mutex);
		return 0;
	} 
	return -EINVAL;
}
EXPORT_SYMBOL(apm86xxx_read_scu_reg);

int APM_IN_BE32(volatile u32 *addr)
{
	u32 val;
    u32 scu_base = (u32) ipp_data.scu_reg_base;

	if ((u32)addr < (scu_base + 0x1FF) && (u32)addr > scu_base) {
		if (ipp_data.secure_mode) {
			secure_read_reg(IPP_REGBANK_SCU, (u32)addr - scu_base, &val);
			return val;
		}
	}
	mutex_lock(&ipp_mutex);
	val = in_be32(addr);
	mutex_unlock(&ipp_mutex);

	return val;
}

int apm86xxx_write_scu_reg_setmask(u32 offset, u32 mask)
{
        u32 data;
	int err;

        err = apm86xxx_read_scu_reg(offset, &data);
	if (err < 0)
		return err;

        data |= mask;
	return apm86xxx_write_scu_reg(offset, data);
}

int apm86xxx_write_scu_reg_clrmask(u32 offset, u32 mask)
{
        u32 data;
	int err;

        err = apm86xxx_read_scu_reg(offset, &data);
	if (err < 0)
		return err;

        data &= ~mask;
	return apm86xxx_write_scu_reg(offset, data);
}

#define TAP1CTL_MASK		0x00000200
#define CPU1ISOLATE_MASK	0x00000008
#define PS_CTL1_MASK		0x00000002
#define PWRGOODPPC1_MASK	0x00000004

int apm86xxx_powerdown_core(unsigned int cpu)
{
	u32 timeout;
	u32 data;

	if (cpu != 1)
		return -EINVAL;

        /* Disable PPC1 Clocks */
	apm86xxx_disable_ppc_clocks(cpu);

	/* Switch to Fake Tap for PPC1 */
	apm86xxx_write_scu_reg_setmask(SCU_SOC_PWR_CTL_ADDR,
					TAP1CTL_MASK);

	/* Set CPU1ISOLATE bit */
	apm86xxx_write_scu_reg_setmask(SCU_SOC_PWR_CTL_ADDR,
					CPU1ISOLATE_MASK);

	/* Disable PPC1 Domain Power */
	apm86xxx_write_scu_reg_clrmask(SCU_PS_CTL_ADDR,
					PS_CTL1_MASK);

	for (timeout = 0; timeout < 200; timeout++) {
		udelay(10);
		apm86xxx_read_scu_reg(SCU_PWRGOOD_ADDR, &data);
		if ((data & PWRGOODPPC1_MASK) == 0) {
			return 0;
		}
	}

	printk(KERN_ERR "%s: failed to powerdown CPU%d", __func__, cpu);
	return -EINVAL;
}

int apm86xxx_powerup_core(unsigned int cpu)
{
	u32 timeout;
        u32 data;
	int err;

	if (cpu != 1)
		return -EINVAL;

	/* just in case we call this early, exit without error message */
	if (!ipp_data.scu_reg_base)
		return 0;

	/* Check to see if we are on the Fake Tap for PPC1 */
        err = apm86xxx_read_scu_reg(SCU_SOC_PWR_CTL_ADDR, &data);
	if (err < 0)
		return err;

	if ((data & TAP1CTL_MASK) != TAP1CTL_MASK)
		return 0;

	/* Assert PPC1 reset */
	mpic_assertcore(cpu);

        /* Enable PPC1 Clocks */
	apm86xxx_enable_ppc_clocks(cpu);

        /* Enable PPC1 Domain Power */
        apm86xxx_write_scu_reg_setmask(SCU_PS_CTL_ADDR, PS_CTL1_MASK);

	apm86xxx_write_mpa_reg(MPA_ATMR0_ADDR,
				(0x1U << ATMR0_START0_SHIFT) |
				(10000 & ATMR0_PER0_MASK) |
				(0x2U << ATMR0_RES0_SHIFT));

        for (timeout = 0; timeout < 200; timeout++) {
                udelay(10);
                apm86xxx_read_scu_reg(SCU_PWRGOOD_ADDR, &data);
                if ((data & PWRGOODPPC1_MASK) == PWRGOODPPC1_MASK) {
			apm86xxx_read_mpa_reg(MPA_ARM_INTSTAT2_ADDR, &data);
			if ((data & ATMR0_EVENT2_MASK) == ATMR0_EVENT2_MASK) {
				printk(KERN_ERR "IPP_FAULT_PPC1_PWR_FAIL\n");
				apm86xxx_write_mpa_reg(MPA_ATMR0_ADDR, 0);
				return -EINVAL;
			}
			break;
		}
        }

	apm86xxx_write_mpa_reg(MPA_ATMR0_ADDR, 0);

	if (timeout >= 200) {
		printk(KERN_ERR "PWRGOODPPC1 timeout\n");
		return -EINVAL;
	}

	/* Clear PPC1 Isolate */
	apm86xxx_write_scu_reg_clrmask(SCU_SOC_PWR_CTL_ADDR,
					CPU1ISOLATE_MASK);

	/* Switch to Normal Tap for PPC1 */
	apm86xxx_write_scu_reg_clrmask(SCU_SOC_PWR_CTL_ADDR,
					TAP1CTL_MASK);

	return 0;
}

int apm86xxx_write_mpa_reg(u32 offset, u32 val)
{
	volatile u32 *mpa_addr;

	if (ipp_data.secure_mode || ipp_data.dp_mode)
		return secure_write_reg(IPP_REGBANK_MPA, offset, 0xFFFFFFFF, val);

	BUG_ON(!ipp_data.scu_reg_base);
	if (offset < 0x400) {
		mutex_lock(&ipp_mutex);
		mpa_addr = (volatile u32 *)(ipp_data.mpa_reg_base + offset);
		out_be32(mpa_addr, val);
		mutex_unlock(&ipp_mutex);
		return 0;
	} 
	return -EINVAL;
}

int apm86xxx_read_mpa_reg(u32 offset, u32 *val)
{
	volatile u32 *mpa_addr;

	if (ipp_data.secure_mode || ipp_data.dp_mode)
		return secure_read_reg(IPP_REGBANK_MPA, offset, val);

	BUG_ON(!ipp_data.scu_reg_base);
	if (offset < 0x400) {
		mutex_lock(&ipp_mutex);
		mpa_addr = (volatile u32 *)(ipp_data.mpa_reg_base + offset);
		*val = in_be32(mpa_addr);
		mutex_unlock(&ipp_mutex);
		return 0;
	} 
	return -EINVAL;
}

int apm86xxx_write_mpa_reg_setmask(u32 offset, u32 mask)
{
        u32 data;
	int err;

        err = apm86xxx_read_mpa_reg(offset, &data);
	if (err < 0)
		return err;

        data |= mask;

	return apm86xxx_write_mpa_reg(offset, data);
}

int apm86xxx_write_mpa_reg_clrmask(u32 offset, u32 mask)
{
        u32 data;
	int err;

        err = apm86xxx_read_mpa_reg(offset, &data);
	if (err < 0)
		return err;

        data &= ~mask;

	return apm86xxx_write_mpa_reg(offset, data);
}

static inline u32 __get_cpu_pll_output(volatile u32 *cpu_pll)
{
	volatile u32 data;
	u32 pll_nf, pll_nr, pll_od;

	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL0_ADDR));

	pll_nf = (data & CLKF0_MASK) + 1;
	pll_nr = ((data & CLKR0_MASK) >> CLKR0_SHIFT) + 1;
	pll_od = ((data & CLKOD0_MASK) >> CLKOD0_SHIFT) + 1;
	*cpu_pll = (APM86xxx_REFCLK_FREQ * pll_nf)/ (pll_nr * pll_od); 

	return *cpu_pll ? 0: -EINVAL;
}

static inline u32 __get_soc_pll_output(volatile u32 *soc_pll)
{
	volatile u32 data;
	u32 pll_nf, pll_nr, pll_od;

	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL1_ADDR));

	pll_nf = (data & CLKF1_MASK) + 1;
	pll_nr = ((data & CLKR1_MASK) >> CLKR1_SHIFT) + 1;
	pll_od = ((data & CLKOD1_MASK) >> CLKOD1_SHIFT) + 1;
	*soc_pll = (APM86xxx_REFCLK_FREQ * pll_nf)/ (pll_nr * pll_od); 

	return *soc_pll ? 0: -EINVAL;
}

int __apm86xxx_get_freq(int id, u32 *freq)
{
	volatile u32 data, div;
	u32 val;
	int ret = -EINVAL;
#if !defined(CONFIG_APM862xx)
        volatile u32 div1;
        void __iomem *ahbc_reg = NULL;
#endif

	switch (id) {
	case APM86xxx_CPU_PLL_FREQ:
		ret = __get_cpu_pll_output(freq);
		break;
	case APM86xxx_SOC_PLL_FREQ:
		ret = __get_soc_pll_output(freq);
		break;
	case APM86xxx_AXI_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV_ADDR));
			if ((val = IO_AXI_CLK_FREQ_SEL_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_AHB_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV_ADDR));
			if ((val = AHB_CLK_FREQ_SEL_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_IAHB_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV2_ADDR));
			if ((val = MPA_AHB_CLK_FREQ_SEL2_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_APB_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV_ADDR));
#if !defined(CONFIG_APM862xx)
                        ahbc_reg = ioremap_nocache(AHBC_TOP_REG_BASE_ADDR, 0x100);
                        if (ahbc_reg) {
                                div1 = in_be32((void *)(ahbc_reg + ENABLE_INTF_ADDR));
                                iounmap(ahbc_reg);
                        }
                        if ((val = AHB_CLK_FREQ_SEL_RD(div)*((div1 & 0xC0000000) >> 30)))
#else
			if ((val = APB_CLK_FREQ_SEL_RD(div)))
#endif
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_PCIE_REFCLK_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV1_ADDR));
			if ((val = PCIE_CLK_FREQ_SEL1_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_CRYPTO_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV2_ADDR));
			if ((val = SEC_CRYPTO_FREQ_SEL2_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_EBUS_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV5_ADDR));
			if ((val = EBUS_CLK_FREQ_SEL5_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_SDIO_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
					SCU_SOCDIV5_ADDR));
			if ((val = SDIO_CLK_FREQ_SEL5_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	case APM86xxx_HDLC_FREQ:
		ret = __get_soc_pll_output(&data);
		if (!ret) {
			div = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
						SCU_SOCDIV6_ADDR));
			if ((val = HDLC_CLK_FREQ_SEL6_RD(div)))
				*freq = data/val;
			else return -EINVAL;
		}
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int __apm86xxx_set_freq(int id, unsigned long rate)
{
	volatile u32 data, div;
	int ret = -EINVAL;

	switch (id) {
	case APM86xxx_SDIO_FREQ:
		/* Only 50MHz rate supported for SDIO */
		if (rate != 50000000) return -EINVAL;
		ret = __get_soc_pll_output(&data);

		if (!ret) {
			if (data == 1000000000) {
				/* Set SDIO rate only if SOC PLL 1000 MHz */
				div = APM_IN_BE32((volatile u32 *)
					(ipp_data.scu_reg_base + 
					SCU_SOCDIV5_ADDR));
				div &= ~SDIO_CLK_FREQ_SEL5_MASK;
				div |= SDIO_CLK_FREQ_SEL5_WR(20);
				APM_OUT_BE32((volatile u32 *)
					(ipp_data.scu_reg_base + 
					SCU_SOCDIV5_ADDR), div);
				return 0;
			} else if (data == 500000000) {
				/* Set SDIO rate only if SOC PLL 500 MHz */
				div = APM_IN_BE32((volatile u32 *)
					(ipp_data.scu_reg_base + 
					SCU_SOCDIV5_ADDR));
				div &= ~SDIO_CLK_FREQ_SEL5_MASK;
				div |= SDIO_CLK_FREQ_SEL5_WR(10); 
				APM_OUT_BE32((volatile u32 *)
					(ipp_data.scu_reg_base + 
					SCU_SOCDIV5_ADDR), div);
				return 0;
			}
		}
		break;
	default:
		return -EINVAL;
	}

	return ret;
}

int set_cpu_cpm_mode(int cpuid, int mode)
{
	u32 data;
	int ret;

	data = IPP_ENCODE_USER_MSG(IPP_CONFIG_SET_HDLR,
				IPP_MSG_CONTROL_URG_BIT,
				IPP_SLEEP_CTRL_MODE_VAR,
				cpuid);
	if ((ret = write_ipp_raw_msg(data, mode)) < 0) {
		dev_err(&ipp_data.pdev->dev,
				"CPU%d CPM global mode set fail: %d\n",
				cpuid, ret);
	}
	return ret;
}

static int read_cpm_reg_raw(u32 reg_num, volatile u32* reg_val)
{
	u32 cmd;
	u32 stat;
	u8  timeout;

	/* Send read command to CPM */
	cmd  = CPM_CMD_SEND | CPM_CMD_RD | CPM_CMD_ADDR(reg_num);
	out_be32((volatile u32 *)(ipp_data.mpa_reg_base +
			CPM_CMD_CTL_ADDR), cmd);

	/* Wait for CPM to complete read operation */
	for (timeout = 0; timeout < 100; timeout++) {
		stat = in_be32((volatile u32 *)(ipp_data.mpa_reg_base +
						CPM_CMD_STAT_ADDR));
		if ((stat & CPM_CMD_INPROGRESS) == 0) {
			/* Return success */
			*reg_val = in_be32((volatile u32 *)
					(ipp_data.mpa_reg_base +
					 CPM_RDDATA_ADDR));
			*reg_val &= CPM_CMD_RDDATA;
			return 0;
		}
	}

	return -EINVAL;
}

static int apm86xxx_secure_read_cpmreg(u8 offset, u32 *value) 
{
	int ret;
	u32 msg_data;
	u8 type, subtype, param0, param1;

	mutex_lock(&ipp_mutex);

	msg_data = IPP_ENCODE_DEBUG_MSG(IPP_DBG_SUBTYPE_CPMREAD,IPP_MSG_CONTROL_URG_BIT,
			offset,IPP_MSG_PARAM_UNUSED);
	ret = __write_ipp_raw_msg(msg_data, IPP_MSG_PARAM_UNUSED, &msg_data);
	if (ret < 0)
		goto done;

	type = IPP_DECODE_MSG_TYPE(msg_data);
	subtype = IPP_DECODE_DBGMSG_TYPE(msg_data);
	param0 = IPP_DECODE_DBGMSG_P0(msg_data);
	param1 = IPP_DECODE_DBGMSG_P1(msg_data);
	if ((type == IPP_DEBUG_MSG) && (subtype == IPP_DBG_SUBTYPE_CPMREAD_RESP) &&
			(param0 == offset)) {
		*value = param1;
	} else {
		ret = -EINVAL;
	}

done:
	mutex_unlock(&ipp_mutex);
	return ret;
}

int read_cpm_register(u32 reg_num, u32* reg_val)
{
	u32 val = 0;
	u8 cmp = 0;
	u8 retry;

	if (ipp_data.dp_mode || ipp_data.secure_mode)
		return apm86xxx_secure_read_cpmreg(reg_num, reg_val);

	for (retry = 0; retry < 10; retry++) {
		if (read_cpm_reg_raw(reg_num, reg_val) != 0)
			continue;

		/* Verify data was read correctly */
		if (cmp == 0) {
			cmp = 1;
			val = *reg_val;
		} else {
			cmp = 0;
			if (val == *reg_val)
				return 0;
		}
	}

	return -EINVAL;
}
EXPORT_SYMBOL(read_cpm_register);

static int write_cpm_reg_raw(u32  reg_num, volatile u32 reg_val)
{
	u32 cmd;
	u32 stat;
	u8 timeout;

        /* Send write command to CPM */
	cmd = CPM_CMD_SEND | CPM_CMD_WR |
	      CPM_CMD_ADDR(reg_num) | CPM_CMD_WRDATA(reg_val);
	out_be32((volatile u32 *)(ipp_data.mpa_reg_base +
			CPM_CMD_CTL_ADDR), cmd);

	/* Wait for CPM to complete write operation */
	for (timeout = 0; timeout < 100; timeout++) {
		stat = in_be32((volatile u32 *)(ipp_data.mpa_reg_base +
						CPM_CMD_STAT_ADDR));
		if ((stat & CPM_CMD_INPROGRESS) == 0)
			return 0;
	}

	return -EINVAL;
}


int apm86xxx_secure_write_cpmreg(u8 offset, u8 value) 
{
	u32 msg_data;
	int ret;

	msg_data = IPP_ENCODE_DEBUG_MSG(IPP_DBG_SUBTYPE_CPMWRITE,IPP_MSG_CONTROL_URG_BIT,
			offset,value);
	mutex_lock(&ipp_mutex);
	ret = __write_ipp_raw_msg(msg_data, IPP_MSG_PARAM_UNUSED, NULL);
	mutex_unlock(&ipp_mutex);
	return ret;
}

int write_cpm_register(u32 reg_num, u32 reg_val)
{
	u32 val;
	u8 retry;

	if (ipp_data.dp_mode || ipp_data.secure_mode)
		return apm86xxx_secure_write_cpmreg(reg_num, reg_val);

	for (retry = 0; retry < 10; retry++) {
		/* Verify data was written correctly */
		if ((write_cpm_reg_raw(reg_num, reg_val) == 0) &&
		    (read_cpm_register(reg_num, &val) == 0) &&
		    (val == reg_val))
		return 0;
	}

	return -EINVAL;
}
EXPORT_SYMBOL(write_cpm_register);

int write_cpm_register_setmask(u32 reg_num, u32 set_mask)
{
	u32 retval;
	u32 reg_val;
	u8 retry;

	for (retry = 0; retry < 10; retry++) {
		retval = read_cpm_register(reg_num, &reg_val);
		if (retval == 0) {
			return write_cpm_register(reg_num, reg_val|set_mask);
		}
	}

	return retval;
}

int write_cpm_register_clrmask(u8 reg_num, u8 clr_mask)
{
	u32 retval;
	u32 reg_val;
	u8 retry;

	for (retry = 0; retry < 10; retry++) {
		retval = read_cpm_register(reg_num, &reg_val);
		if (retval == 0) {
			return write_cpm_register(reg_num,
						 (reg_val & ~clr_mask));
		}
	}

	return retval;
}

int cpm_get_cpu_div(u32 core, u32 *div)
{
	u32 ret;

	ret = read_cpm_register(CPM_REG_CPU_DFSCTRL(core), div);
	if ((ret == 0) && (*div >= 2) && (*div <=32))
		return 0;

	return -EINVAL;
}

int cpm_get_plb2x_div(u32 *div)
{
	u32 ret;

	ret = read_cpm_register(CPM_REG_PLB_DFSCTRL, div);
	if ((ret == 0) && (*div >= 2) && (*div <=16))
		return 0;

	return -EINVAL;
}

int cpm_set_cpu_div(u32 core_mask, u32 div)
{
	u32 core;
	int err = 0;

	for (core = 0; core < 2; core++) {
		if ((core_mask & (0x1<<core)) != 0) {
			err = write_cpm_register(CPM_REG_CPU_DFSCTRL(core), div);
			BUG_ON(err);
		}
	}

	return err;
}

int cpm_set_plb2x_div(u32 div)
{
	int err;

	err = write_cpm_register(CPM_REG_PLB_DFSCTRL, div);
	BUG_ON(err);

	return err;
}

int apm86xxx_disable_ppc_clocks(unsigned int cpu)
{
	u32 timeout;	
	u32 regval;

	write_cpm_register_setmask(CPM_REG_CPU_PWRCTRL(cpu),
			CPM_CPU_PWRCTRL_SHUTDOWN_MASK |
			CPM_CPU_PWRCTRL_SLEEP_MASK);

	/* Read back CPM_CPU_PWRCTRL to make sure request completed */
	for (timeout = 0; timeout < 100; timeout++) {
		read_cpm_register(CPM_REG_CPU_PWRCTRL(cpu), &regval);
		regval &= CPM_CPU_PWRCTRL_SLEEP_MASK;
		if (regval == CPM_CPU_PWRCTRL_SLEEP_MASK) {
			write_cpm_register(CPM_REG_CPU_CLKCTRL(cpu), 0);
			return 0;
		}

		udelay(10);
	}

	printk(KERN_ERR "Failed to disable ppc clocks for CPU%d\n", cpu);
	return -EINVAL;
}

int apm86xxx_enable_ppc_clocks(unsigned int cpu)
{
	u32 timeout;	
	u32 regval;

	write_cpm_register(CPM_REG_CPU_CLKCTRL(cpu),
			CPM_CPU_CLKCTRL_CPUEN_MASK |
			CPM_CPU_CLKCTRL_PLBEN_MASK |
			CPM_CPU_CLKCTRL_FPUEN_MASK);

	write_cpm_register_clrmask(CPM_REG_CPU_PWRCTRL(cpu),
			CPM_CPU_PWRCTRL_SHUTDOWN_MASK |
			CPM_CPU_PWRCTRL_SLEEP_MASK);

	/* Read back CPM_CPU_PWRCTRL to make sure request completed */
	for (timeout = 0; timeout < 100; timeout++) {
		read_cpm_register(CPM_REG_CPU_PWRCTRL(cpu), &regval);
		regval &= CPM_CPU_PWRCTRL_SLEEP_MASK;
		if (regval == 0) {
			return 0;
		}

		udelay(10);
	}

	printk(KERN_ERR "Failed to enable ppc clocks for CPU%d\n", cpu);
	return -EINVAL;
}

static int ipp_fw_init(void)
{
	u32 data;
	int ret, cpu, id;

	BUG_ON(!ipp_data.scu_reg_base);
	BUG_ON(!ipp_data.pdev);

	/* Don't invoke ipp_send_user_msg in this function to avoid recursion */

	if (!ipp_data.ipp_active) {
		/* Notify Online Core Mask to iPP */
		id = 0;
		for_each_online_cpu(cpu) {
			id |= (num_online_cpus() == 1) ?
				1<<hard_smp_processor_id() : 1<<cpu;
		}
		data = IPP_ENCODE_USER_MSG(IPP_CONFIG_SET_HDLR, CTRL_BYTE_UNSED,
				IPP_ONLINE_PPC_CORES_MASK_VAR, id);
		if ((ret = write_ipp_raw_msg(data, IPP_MSG_PARAM_UNUSED)) < 0) {
			dev_err(&ipp_data.pdev->dev,
				"Failed to notify online cores to iPP: %d\n",
				ret);
			return ret;
		} else 
			dev_dbg(&ipp_data.pdev->dev,
				"Notified iPP of %d PPC cores\n",
				num_online_cpus());

#ifdef CONFIG_SUSPEND
		for_each_online_cpu(cpu) {
			id = (num_online_cpus() == 1) ?
				hard_smp_processor_id() : cpu;
			if ((ret = set_cpu_cpm_mode(id,
				IPP_GLOBAL_SLEEP_MODE)) < 0)
				return ret;
		}
#endif
		ipp_data.ipp_active = 1;
	} 
	return 0;
}

static void ipp_load_fw(u32 load_addr, u32 *data_addr, u32 size)
{
	int iter = size >> 2;

	BUG_ON(!ipp_data.scu_reg_base);
	while(iter-- > 0) {
		out_be32((volatile u32 *)(ipp_data.mpa_reg_base +
				MPA_IRAM_ADDR_ADDR), load_addr);
		wmb();
		writel(*data_addr, (volatile u32 *)
			(ipp_data.mpa_reg_base + MPA_IRAM_DATA_ADDR)); 
		load_addr += 4;
		data_addr++;
	}
}

/*
 * request_firmware() callback function
 *
 * This function is called by the kernel when a firmware is made available,
 * or if it times out waiting for the firmware.
 */

static int ipp_get_fw(const struct firmware *fw, void *context)
{
	struct device *dev = context;
	u32 data, scratch_val;
	int ret, timeout_cnt = 500;
	u32 rom_scratch_val = IPP_SCRATCH_ID_MAGIC |
				IPP_ROM_MODE_MASK;
	u32 run_scratch_val = IPP_SCRATCH_ID_MAGIC |
				IPP_RUNTIME_MODE_MASK;
	u32 ext_scratch_val = IPP_SCRATCH_ID_MAGIC |
				IPP_EXTBOOT_MODE_MASK;
	u32 scratch_mask = IPP_SCRATCH_ID_MAGIC |
				IPP_MODE_MASK;
	int cpu = (num_online_cpus() > 1) ? DEFAULT_SMP_IPPMSG_CPU :
						hard_smp_processor_id();

	if (!fw) {
		dev_err(dev, "firmware load timeout: is hotplug configured?\n");
		return -ENAVAIL;
	}

	if (ipp_data.ipp_fw_loaded) {
		dev_info(dev, "iPP Firmware already loaded ... skipping\n");
		return -EEXIST;
	}

	if ((num_online_cpus() == 1) && (hard_smp_processor_id() !=
			DEFAULT_SMP_IPPMSG_CPU)) {
		int fw_load_timeout_cnt = 250;

		/* Wait for firmware load to complete from Boot CPU */
		while (((data = in_be32((volatile u32 *) 
				(ipp_data.msg_reg_base + 
				 cpu*ipp_data.cpu_offset + 
				 ipp_data.scratch_offset))) &
				scratch_mask) == rom_scratch_val) {
			if (fw_load_timeout_cnt-- < 0) {
				dev_err(dev, 
					"iPP fwload to be done using CPU%d\n",
					hard_smp_processor_id());
				break;
			}
			msleep(20);
		}
	}

	/* load firmware only in iPP ROM Mode for Boot CPU */
	scratch_val = in_be32((volatile u32 *) (ipp_data.msg_reg_base +
			cpu*ipp_data.cpu_offset + ipp_data.scratch_offset));
	if ((scratch_val & scratch_mask) == rom_scratch_val) {
		ipp_imageinfo_t *ipp_fw_hdr = (ipp_imageinfo_t *)
			(((u32)(fw->data)) + IPP_IMAGEINFO_OFFSET);
		u32 *pfw_magic = (u32 *)((u32)ipp_fw_hdr +
			offsetof(ipp_imageinfo_t, image_signature));
		u16 *pfw_type = (u16 *)((u32)ipp_fw_hdr +
			offsetof(ipp_imageinfo_t, image_type));
		u32 *pfw_load_addr = (u32 *)((u32)ipp_fw_hdr +
			offsetof(ipp_imageinfo_t, image_loadaddr));
		u32 *pfw_sz = (u32 *)((u32)ipp_fw_hdr +
			offsetof(ipp_imageinfo_t, image_size));
		int backdoor_loaded = 0;
		u32 size;

		if (IPP_IMAGE_SIGNATURE != in_le32(pfw_magic)) {
			dev_err(dev, "invalid ipp firmware magic 0x%08x"
					" ... skipping firmware load\n",
				in_le32(pfw_magic));
			return -EINVAL;
		}

		if (IPP_RUNTIME_TYPE != in_le16(pfw_type)) {
			dev_err(dev, "invalid ipp firmware type (%d) "
				"... skipping firmware load\n",
				in_le16(pfw_type));
			return -EINVAL;
		}

		if (IPP_RUNTIME_LOADADDR != in_le32(pfw_load_addr)) {
			dev_err(dev, "invalid ipp fw load address"
				" 0x%08x... skipping firmware load\n",
				in_le32(pfw_load_addr));
			return -EINVAL;
		}
		
		/* Word align size */
		size = in_le32(pfw_sz) & ~0x3;
		out_be32((volatile u32 *)(ipp_data.mpa_reg_base +
			MPA_IRAM_ADDR_ADDR),
			(u32)in_le32(pfw_load_addr) +
			IPP_IMAGEINFO_OFFSET);
		backdoor_loaded = in_be32((volatile u32 *)
					(ipp_data.msg_reg_base +
					MPA_IRAM_RDATA_ADDR)) ==
					IPP_IMAGE_SIGNATURE;
		if (backdoor_loaded) {
			dev_info(dev, "iPP runtime loaded via backdoor"
				"... skipping overwrite\n");
		} else {
			ipp_load_fw((u32)in_le32(pfw_load_addr),
				(u32 *)(fw->data), size);
		}

		/* Send FWLoad command to IRAM */
		data = IPP_ENCODE_FWLOAD_MSG(IPP_FWLOAD_FROM_PPC);
		if ((ret = write_ipp_raw_msg(data,
				IPP_MSG_PARAM_UNUSED)) < 0) {
			dev_err(dev, "Failed to write iPP FWLOAD"
				" Msg : %d\n", ret);
			return -EIO;
		}

		/* Wait 5 secs for iPP Firmware to be Loaded */
		while (timeout_cnt-- > 0) {
			if (((data = in_be32((volatile u32 *)
				(ipp_data.msg_reg_base + 
				 cpu*ipp_data.cpu_offset +				 
				 ipp_data.scratch_offset))) &
				run_scratch_val) == run_scratch_val) {
				dev_info(dev, "iPP Firmware Version"
					" %d.%d loaded (%d bytes)\n",
					(data&IPP_MAJOR_VER_MASK)>>
					IPP_MAJOR_VER_SHIFT,
					data&IPP_MINOR_VER_MASK, size);
				break;

			} else {
				msleep(10);
			}
		}
		if (timeout_cnt <= 0) {
			dev_err(dev, "iPP FW Execution failure\n");
			return -EIO;
		}
	} else if ((scratch_val & scratch_mask) == run_scratch_val) {
		/* iPP Firmware is already loaded ... MUST skip load */
		dev_info(dev, "iPP Firmware already loaded ... "
				"Ver %d.%d\n", 
				(scratch_val&IPP_MAJOR_VER_MASK)>>
				IPP_MAJOR_VER_SHIFT,
				scratch_val&IPP_MINOR_VER_MASK);
	} else if ((scratch_val & scratch_mask) == ext_scratch_val) {
		/* MUST not load Firmware in External Boot mode */
		dev_info(dev, "iPP External Firmware Mode Ver %d.%d\n", 
				(scratch_val&IPP_MAJOR_VER_MASK)>>
				IPP_MAJOR_VER_SHIFT,
				scratch_val&IPP_MINOR_VER_MASK);
	}

	if (ipp_fw_init() != 0) {
		dev_err(dev, "iPP Messaging Init failure\n");
		return -EIO;
	} else {
		ipp_data.ipp_fw_loaded = 1;
		ipp_notifier_call_chain(IPP_FIRMWARE_LOADED);
		return 0;
	}
}

static int ipp_load_firmware(void)
{
	struct device *dev;
	const struct firmware *fw;
	int ret = -EINVAL;

	if (ipp_data.pdev) {
		dev = &ipp_data.pdev->dev;
		if ((ret = request_firmware(&fw, IPP_FW_NAME, dev)) == 0) {
			ipp_get_fw(fw, dev);
			release_firmware(fw);
		} else {
			dev_err(dev, "could not load firmware %s\n",
						IPP_FW_NAME);
		}
	} 
	return ret; 
}

#ifdef CONFIG_SYSFS
static ssize_t show_fwload(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%d\n", ipp_data.ipp_fw_loaded);
}
static ssize_t set_fwload(struct device_driver *drv,
				const char *buf, size_t count)
{
	int tmp;

	sscanf(buf, "%d", &tmp);
	if (tmp == 1)
		ipp_load_firmware();
	return count;
}

static ssize_t show_clktree(struct device_driver *drv, char *buf)
{
	return apm_show_clktree(buf);
}

static ssize_t show_cpu_msg(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "0x%08x\n", ipp_data.sys_msg);
}
static ssize_t set_cpu_msg(struct device_driver *drv,
				const char *buf, size_t count)
{
	sscanf(buf, "%x", &ipp_data.sys_msg);
	write_ipp_raw_msg(ipp_data.sys_msg, IPP_MSG_PARAM_UNUSED); 
	return count;
}

static ssize_t show_trace(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "%s\n",
		apm86xxx_trace_modes[ipp_data.trace_mode].name);
}
static ssize_t set_trace(struct device_driver *drv,
				const char *buf, size_t count)
{
	char *p;
	int i, len, found=0;
	volatile u32 val;

	p = memchr(buf, '\n', count);
	len = p ? p - buf : count;

	for (i = 0; i < TRACE_MAX; i++) {
		if (strncmp(buf, apm86xxx_trace_modes[i].name, len) == 0) {
			found = 1;
			break;
		}
	}

	if (!found) return -EINVAL;

	mutex_lock(&ipp_mutex);
	val = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
				SCU_SOCDIV3_ADDR));
	val &= ~(SOC_STRK_CLKMON_SEL3_MASK | STRK_CLKMON_SEL3_MASK);
	val |= apm86xxx_trace_modes[i].val;
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base +
				SCU_SOCDIV3_ADDR), val);
	ipp_data.trace_mode = i;
	mutex_unlock(&ipp_mutex);

	return count;
}

static ssize_t show_trace_modes(struct device_driver *drv, char *buf)
{
	char *s = buf;
	int i;

	for (i = 0; i < TRACE_MAX; i++) {
		s += sprintf(s, "%s ", apm86xxx_trace_modes[i].name);
	}

	*(s-1) = '\n'; /* convert the last space to a newline */

	return (s - buf);
}

static ssize_t show_gpio_wakeup(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "0x%04x\n", ipp_data.gpio_wakeup_mask &
						IPP_MAX_GPI0_WAKEUP_MASK);
}
static ssize_t set_gpio_wakeup(struct device_driver *drv,
				const char *buf, size_t count)
{
	sscanf(buf, "%x", &ipp_data.gpio_wakeup_mask);
	return count;
}
static ssize_t show_gpio_level(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "0x%04x\n", ipp_data.gpio_lvl_mask &
						IPP_MAX_GPI0_WAKEUP_MASK);
}
static ssize_t set_gpio_level(struct device_driver *drv,
				const char *buf, size_t count)
{
	sscanf(buf, "%x", &ipp_data.gpio_lvl_mask);
	return count;
}
static ssize_t show_features(struct device_driver *drv, char *buf)
{
	return sprintf(buf, "0x%08x\n", get_ipp_features());
}

static ssize_t show_ipp_pwrstats(struct device_driver *drv, char *buf)
{
	int ret;
        ssize_t size = 0;
	struct ipp_pwrmgmt_stats pwrstats;

	ret = get_ipp_pwrstats(&pwrstats);
	if (!ret) {
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Last Wakeup Event Mask: 0x%x \n",
					pwrstats.last_wakeup_mask);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"GPIO Wakeup Event Mask: 0x%x \n",
					pwrstats.gpio_wakeup_mask);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"DDR SelfRefresh Entry Count: %d\n",
					pwrstats.ddr_selfref_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"WoL Wakeup Count: %d\n",
					pwrstats.wakecnt.count.eth_wake);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"USB Wakeup Count: %d\n",
					pwrstats.wakecnt.count.usb_wake);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"GPIO Wakeup Count: %d\n",
					pwrstats.wakecnt.count.gpio_wake);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"RTC Wakeup Count: %d\n",
					pwrstats.wakecnt.count.rtc_wake);
        	return size;
	} else {
		return sprintf(buf, "Failed to get SlimPro Power Stats\n");
	}
}

static ssize_t show_ipp_netstats(struct device_driver *drv, char *buf)
{
	int ret;
        ssize_t size = 0;
	struct ipp_net_stats netstats;

	ret = get_ipp_netstats(&netstats);
	if (!ret) {
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Deep Sleep Network Stats:\n");
		size += snprintf(buf + size, PAGE_SIZE - size,
					"HW MTU: %d \n",
					netstats.hw_mtu);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Rx Packets: %d \n",
					netstats.rx_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Tx Packets: %d \n",
					netstats.tx_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Dropped Packets: %d \n",
					netstats.drop_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"WoL Packets: %d \n",
					netstats.wol_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Length Error Packets: %d \n",
					netstats.len_err_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"Mac Error Packets: %d \n",
					netstats.mac_err_pkt_cnt);
		size += snprintf(buf + size, PAGE_SIZE - size,
					"IP Error Packets: %d \n",
					netstats.ip_err_pkt_cnt);
        	return size;
	} else {
		return sprintf(buf, "Failed to get SlimPro Power Stats\n");
	}
}

static struct driver_attribute ipp_attrs[] = {
	__ATTR(fwload, S_IWUGO | S_IRUGO, show_fwload, set_fwload),
	__ATTR(clktree, S_IRUGO, show_clktree, NULL),
	__ATTR(value, S_IWUGO | S_IRUGO, show_cpu_msg, set_cpu_msg),
	__ATTR(trace, S_IWUGO | S_IRUGO, show_trace, set_trace),
	__ATTR(trace_modes, S_IRUGO, show_trace_modes, NULL),
	__ATTR(gpio_wakeup, S_IWUGO | S_IRUGO, show_gpio_wakeup,
						set_gpio_wakeup),
	__ATTR(gpio_level, S_IWUGO | S_IRUGO, show_gpio_level,
						set_gpio_level),
	__ATTR(features, S_IRUGO, show_features, NULL),
	__ATTR(pwrstats, S_IRUGO, show_ipp_pwrstats, NULL),
	__ATTR(netstats, S_IRUGO, show_ipp_netstats, NULL),
};

static int add_ipp_sysfs(struct device_driver *driver)
{
	int i;
	int err;

	for (i = 0; i < ARRAY_SIZE(ipp_attrs); i++) {
		if (is_apm86xxx_lite()) {
			if (strcmp(ipp_attrs[i].attr.name,"fwload") == 0 ||
			    strcmp(ipp_attrs[i].attr.name,"value") == 0)
				continue;
		}
		err = driver_create_file(driver, &ipp_attrs[i]);
		if (err) goto fail;
	}
	return 0;

 fail:
	while (--i >= 0) {
		if (is_apm86xxx_lite()) {
			if (strcmp(ipp_attrs[i].attr.name,"fwload") == 0 ||
			    strcmp(ipp_attrs[i].attr.name,"value") == 0)
				continue;
		}
		driver_remove_file(driver, &ipp_attrs[i]);
	}
	return err;
}

static void remove_ipp_sysfs(struct device_driver *driver)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(ipp_attrs); i++) {
		if (is_apm86xxx_lite()) {
			if (strcmp(ipp_attrs[i].attr.name,"fwload") == 0 ||
			    strcmp(ipp_attrs[i].attr.name,"value") == 0)
				continue;
		}
		driver_remove_file(driver, &ipp_attrs[i]);
	}
}

#else

#define add_ipp_sysfs(drv) do { } while (0)
#define remove_ipp_sysfs(drv) do { } while (0)

#endif /* CONFIG_SYSFS */

static int ipp_probe(struct platform_device *pdev)
{
	struct ipp_drv     *ipp = &ipp_data;
	int err = 0;
	int cpu = hard_smp_processor_id();

	cpu = (num_online_cpus() > 1) ? DEFAULT_SMP_IPPMSG_CPU :
				hard_smp_processor_id();
	ipp->pdev = pdev;
        dev_set_drvdata(&pdev->dev, ipp);

	err = add_ipp_sysfs(pdev->dev.driver);
	if (err)
		goto fail;
		
	if (!err) return err;

fail:
	dev_err(&pdev->dev, "SlimPRO probe failed\n");

	if (!is_apm86xxx_lite()) {
		if (ipp->irq != NO_IRQ) 
			free_irq(ipp->irq, NULL);
	} else {
		if (ipp->gpio_irq != NO_IRQ) 
			free_irq(ipp->gpio_irq, NULL);
	}

	remove_ipp_sysfs(pdev->dev.driver);
	return err;
}

int check_ipp_init(void)
{
	return !ipp_data.ipp_active ? -EINVAL: 0;
}

int ipp_online_cpu(u8 cpu)
{
	int ret; 

	/* just in case we call this early, exit without error message */
	if (check_ipp_init() < 0)
		return 0;

	ret = ipp_send_user_msg(IPP_PWRMGMT_HDLR,
		IPP_PWRMGMT_CMD_CPU_SET_NORMAL,
		cpu, IPP_MSG_CONTROL_URG_BIT,
		IPP_MSG_PARAM_UNUSED);

	if (ret < 0) {
		printk("Error: IPP failed to online CPU%d\n", cpu);
	}

	return ret;
}

int ipp_send_user_msg(enum ipp_user_message_handlers id, u8 arg1, u8 arg2,
			u8 control_byte, u32 arg3)
{
	u32 data;
	int ret;

	if ((ret = check_ipp_init()) < 0) {
		dev_err(&ipp_data.pdev->dev,
			"iPP Write msg fail ... firmware not loaded\n");
		return ret;
	}

	BUG_ON(!ipp_data.pdev);
	data = IPP_ENCODE_USER_MSG(id, control_byte, arg1, arg2);
	if ((ret = write_ipp_raw_msg(data, arg3)) < 0) {
		dev_err(&ipp_data.pdev->dev,
			"Failed to write iPP User Msg : %d\n", ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL(ipp_send_user_msg);

int ipp_send_data_msg(enum ipp_data_message_handlers hdlr, void *buf, int len,
			u32 *retcode)
{
	u32 data;
	u8 cbyte; 
	int ret=-EINVAL, index;
	u32 *ptr = (u32 *)buf;

	if ((len & 0x3) || (hdlr > IPP_MAX_DATA_MSG_HANDLERS))
		return ret;

	if ((ret = check_ipp_init()) < 0) {
		/* NOTE: Domain protection mode already has firmware 
			 loaded already */
		if (!apm86xxx_is_dp_mode())
			return ret;
	}

	len /= sizeof(u32);
	mutex_lock(&ipp_mutex);
	for (index=0,cbyte=IPP_DATA_MSG_CBYTE_START_BIT; index<len; index++) {
		data = IPP_ENCODE_DATA_MSG(hdlr, IPP_MSG_CONTROL_URG_BIT,
						cbyte, index);
		if ((ret = __write_ipp_raw_msg(data, *ptr++, retcode)) < 0) {
			dev_info(&ipp_data.pdev->dev,
				"Failed to write iPP Data Msg : %d word: %d\n",
				ret, index);
			goto out;
		}
		cbyte = (index == (len-2)) ? IPP_DATA_MSG_CBYTE_STOP_BIT:
					DATA_MSG_CTRL_BYTE_UNSED;
	}
out:
	mutex_unlock(&ipp_mutex);

	return ret;
}
EXPORT_SYMBOL(ipp_send_data_msg);

int ipp_send_addr_msg(enum ipp_addr_message_handlers hdlr, u32 *addr_buf,
				int len, u32 *resp)
{
	u32 data, lower_phys_addr;
	u8		upper_phys_addr;
	dma_addr_t	phys_addr;
	int		ret;

	BUG_ON(!ipp_data.pdev);
	if (!addr_buf || (hdlr > IPP_MAX_ADDR_MSG_HANDLERS))
		return -EINVAL;

	if ((ret = check_ipp_init()) < 0) {
		/* NOTE: Domain protection mode already has firmware 
			 loaded already */
		if (!apm86xxx_is_dp_mode())
			return ret;
	}

	if (len != addr_buf[0] && !apm86xxx_is_dp_mode()) {
		dev_err(&ipp_data.pdev->dev,
			"First word of address buffer not initialized "
			"to buffer length\n");
		return -EINVAL;
	}

	phys_addr = dma_map_single(&ipp_data.pdev->dev, addr_buf,
				len, DMA_TO_DEVICE);
	if (!phys_addr) {
		dev_info(&ipp_data.pdev->dev,
			"Failed to get physical address for "
			"iPP Address Buffer\n");
		return -EINVAL;
	}

	lower_phys_addr = phys_addr & 0xFFFFFFFF;
	upper_phys_addr = (phys_addr >> 32) & 0xF;
	data = IPP_ENCODE_ADDR_MSG(hdlr, IPP_MSG_CONTROL_URG_BIT,
					upper_phys_addr);
	ret = write_ipp_raw_msg_withresp(data, lower_phys_addr, resp);
	if (ret < 0) {
		dev_info(&ipp_data.pdev->dev,
			"Failed to write iPP Addr Msg %d\n", ret);
	}
	return ret;
}

int ipp_generic_rx_addrmsg(enum ipp_generic_databuf_index index,
				void *buf, int len)
{
	u32 data;
	int ret, i;

	BUG_ON(!ipp_data.pdev);
	if (!buf || (index > IPP_MAX_DATABUF_INDEX) ||
		(len > sizeof(addr_msg_buf)) || (!ipp_data.laddr)) {
		return -EINVAL;
	}

	if ((ret = check_ipp_init()) < 0) {
		return ret;
	}

	/* Take lock before modifying the shared addr_msg_buf */
	mutex_lock(&ipp_mutex);

	memset((void *)addr_msg_buf, 0, sizeof(addr_msg_buf));
	addr_msg_buf[0] = len;
#if defined(CONFIG_NOT_COHERENT_CACHE)
	flush_dcache_range((u32)addr_msg_buf, (u32)addr_msg_buf +
				len + sizeof(u32));
#endif 
	wmb();

	data = IPP_ENCODE_ADDRN_MSG(
			IPP_GENERIC_TX_RX_ADDR_MSG_HDLR,
			IPP_MSG_CONTROL_URG_BIT,
			(u8)ipp_data.uaddr,
			index,
			IPP_ADDR_MSG_CBYTE_PPC_ORIGIN |
			IPP_ADDR_MSG_CBYTE_RX_DIR);

	if ((ret = __write_ipp_raw_msg(data, ipp_data.laddr, NULL)) < 0) {
		dev_info(&ipp_data.pdev->dev,
			"Failed to write iPP Addr Msg %d\n", ret);
	} else {
#if defined(CONFIG_NOT_COHERENT_CACHE)
		invalidate_dcache_range((u32)addr_msg_buf,
				(u32)addr_msg_buf + len + sizeof(u32));
#endif
		/* Swap buffer on word boundary */
		for (i=1; i<(len+4)/4; i++)
			addr_msg_buf[i] = swab32(addr_msg_buf[i]);
		memcpy(buf, (const void *)&addr_msg_buf[1], len);
	}
	mutex_unlock(&ipp_mutex);
	return ret;
}

unsigned int get_ipp_features(void)
{
	u32 features = 0;

	/* If this fails, features will be 0 */
	ipp_generic_rx_addrmsg(IPP_DATABUF_FW_FEATURES,
		&features, sizeof(features));
	return features;
}
EXPORT_SYMBOL(get_ipp_features);

int get_ipp_pwrstats(struct ipp_pwrmgmt_stats *pstats)
{
	memset(pstats, 0, sizeof(struct ipp_pwrmgmt_stats));

	return ipp_generic_rx_addrmsg(IPP_DATABUF_PWRMGMT,
		pstats, sizeof(struct ipp_pwrmgmt_stats));
}

int get_ipp_netstats(struct ipp_net_stats *nstats)
{
	memset(nstats, 0, sizeof(struct ipp_net_stats));

	return ipp_generic_rx_addrmsg(IPP_DATABUF_NET,
		nstats, sizeof(struct ipp_net_stats));
}
EXPORT_SYMBOL(get_ipp_netstats);

static int init_ipp_shared_buf(void)
{
	int offset=0;
	ipp_pwr_state_t *ipp_buf = NULL;

	BUG_ON(!ipp_data.scu_reg_base);

	ipp_buf = ocm_get_buf(NULL, NULL, OCM_IPP, &offset);
	if (!ipp_buf)
		return -ENOBUFS;
	if ((num_online_cpus() == 1) && (hard_smp_processor_id() !=
			DEFAULT_SMP_IPPMSG_CPU)) {
		ipp_data.ipp_buf = ipp_buf + 1;
		ipp_data.ocm_offset = offset + sizeof(ipp_pwr_state_t);
	} else {
		ipp_data.ipp_buf = ipp_buf;
		ipp_data.ocm_offset = offset;
	}

	return 0;
}

int get_ipp_pwr_state_buf(ipp_pwr_state_t **addr)
{
	int ret = -ENOBUFS;

	BUG_ON(!ipp_data.pdev);
	if ((!ipp_data.ipp_buf) && (ret = init_ipp_shared_buf()) < 0) {
		dev_info(&ipp_data.pdev->dev,
			"iPP Shared Buffer init failure\n");
		return ret;
	}

	BUG_ON(!ipp_data.ipp_buf);
	*addr = ipp_data.ipp_buf;

	return 0;
}

int save_ipp_pwr_state_buf(ipp_pwr_state_t **addr)
{
	return ipp_send_user_msg(IPP_CONFIG_SET_HDLR,
				IPP_PWRSTATE_OCM_OFFSET_VAR,
				hard_smp_processor_id(),
				IPP_MSG_CONTROL_URG_BIT,
				ipp_data.ocm_offset);
}

int get_ipp_irq(void)
{
	BUG_ON(!ipp_data.scu_reg_base);
	return ipp_data.irq;
}

u32 get_gpio_wakeup_mask(void)
{
	return ipp_data.gpio_wakeup_mask;
}

u32 get_gpio_wakeup_level_mask(void)
{
	return ipp_data.gpio_lvl_mask;
}

int get_ipp_gpio_irq(void)
{
	BUG_ON(!ipp_data.scu_reg_base);
	BUG_ON(ipp_data.gpio_irq == NO_IRQ);

	return ipp_data.gpio_irq;
}

static struct of_device_id ipp_match[] = {
	{ .compatible = "apm,ipp", },
	{}
};

static struct platform_driver ipp_driver = {
	.driver = {
		.name	= "ipp",
		.of_match_table = ipp_match,
	},
	.probe = ipp_probe,
};

int ipp_init(int early_init)
{
	struct ipp_drv     *ipp = &ipp_data;
	struct resource	   res;
	const u32 *psrc;
	struct device_node *np = NULL;
	int err = 0;
	int cpu;
	u64 phy64;

	cpu = (num_online_cpus() > 1) ? DEFAULT_SMP_IPPMSG_CPU :
				hard_smp_processor_id();

        np = of_find_compatible_node(NULL, NULL, "apm,ipp");
        if (!np) {
                printk(KERN_ERR "no apm iPP entry in DTS\n");                	
		return -ENODEV;
        }
	/* Map iPP Reg space */
	if (of_address_to_resource(np, 0, &res)) {
		printk(KERN_ERR "%s: Can't get register base address\n",
			np->full_name);
		return -ENODEV;
	}

	if (ipp->regs == NULL) {
		ipp->regs = ioremap(res.start, res.end - res.start + 1);
		if (ipp->regs == NULL) {
			printk(KERN_ERR "%s: Can't map device registers!\n",
				np->full_name);
			return -ENOMEM;
		}
	}

	ipp->scu_reg_base = (u32)(ipp->regs);
	ipp->mpa_reg_base = (u32)(ipp->regs) + APM_MPA_REG_OFFSET;
	ipp->pcode_offset = MPA_P0_PCODE_ADDR;
	ipp->acode_offset = MPA_P0_ACODE_ADDR;
	ipp->intstat_offset = MPA_P0_INTSTAT_ADDR;
	ipp->intmask_offset = MPA_P0_INTSTATMASK_ADDR;
#ifdef CONFIG_APM862xx
	ipp->msg_reg_base = ipp->mpa_reg_base;
	ipp->cpu_offset = sizeof(u32);
	ipp->cpu_intstat_offset = 0x8;
	ipp->paramreg_offset = MPA_SCRATCH1_ADDR;
	ipp->scratch_offset = MPA_SCRATCH_ADDR;
#else
	ipp->msg_reg_base = ipp->scu_reg_base + APM_MPA_PPC0_REG_OFFSET;
	ipp->cpu_offset = 0x1000;
	ipp->cpu_intstat_offset = 0x1000;
	ipp->paramreg_offset = MPA_P0_SCRATCH0_ADDR;
	ipp->scratch_offset = MPA_P0_RO_SCRATCH_ADDR;
#endif

	ipp->secure_mode = in_be32((volatile u32 *) (ipp->msg_reg_base +
			ipp_data.scratch_offset + cpu*ipp->cpu_offset)) 
			& IPP_TPM_MODE_MASK;

#if defined(CONFIG_APM862xxvB) || defined(CONFIG_APM866xx)
	ipp->dp_mode = in_be32((u32 *) (ipp->scu_reg_base + 0x8000)) &
				0x80000000 ? 1 : 0;
#endif

	if (ipp->secure_mode)
		printk(KERN_INFO "APM SoC APM86xxx in Secure boot mode\n");
	if (ipp->dp_mode)
		printk(KERN_INFO "APM SoC APM86xxx Domain Protection mode\n");

	/* We cant' use DMA apis since we dont have device registered yet */
	/* Set physical address for ADDR mesg: UA is 0 since it is in DDR */
	phy64 = virt_to_phys(addr_msg_buf);
	ipp->laddr = (u32) phy64;
	ipp->uaddr = (u32) (phy64 >> 32);

	if (early_init) {
		ipp->early_init = 1;
		return 0;
	} else {
		ipp->early_init = 0;
	}

	psrc = of_get_property(np, "gpio_wakeup", NULL);
	if (psrc) {
		ipp->gpio_wakeup_mask = (0x1<< *psrc);
		ipp->gpio_wakeup_mask &= IPP_MAX_GPI0_WAKEUP_MASK;
	}

	/* Default GPIO wakeup level is low if not configured in DTS */
	psrc = of_get_property(np, "gpio_level", NULL);
	if (psrc)
		ipp->gpio_lvl_mask = *psrc ? ipp->gpio_wakeup_mask : 0;

	if (!is_apm86xxx_lite()) {
		ipp->irq = irq_of_parse_and_map(np, cpu);
		if (ipp->irq == NO_IRQ) {
			err = -ENODEV;
			goto error;
		}
		printk(KERN_INFO "APM SoC APM86xxx iPP CPU%d Hard CPU%d\n", 
			cpu, hard_smp_processor_id());
	} else {
		ipp->gpio_irq = irq_of_parse_and_map(np, 2);
		printk(KERN_INFO "APM SoC APM86xxx lite CPU%d Hard CPU%d\n", 
			cpu, hard_smp_processor_id());
	}

	if (!is_apm86xxx_lite()) {
		err = request_irq(ipp->irq, hdlr_ipp, 0, "iPP", NULL);
		if (!err)
			out_be32((volatile u32 *)(ipp->msg_reg_base +
				ipp->intmask_offset +
				cpu*ipp->cpu_intstat_offset), 0);
		else
			ipp->irq = NO_IRQ;
	} else {
		if (ipp->gpio_irq != NO_IRQ && ipp->gpio_wakeup_mask) {
			err = request_irq(ipp->gpio_irq, hdlr_gpio, 0,
					  "GPIO_WAKEUP", NULL);
			if (!err) {
				apm86xxx_write_mpa_reg_clrmask(
					MPA_GPIO_INT_LVL_ADDR,
					ipp->gpio_wakeup_mask);
				apm86xxx_write_mpa_reg_clrmask(
					MPA_GPIO_ADDR,
					GPIO_TYPE_WR(ipp->gpio_wakeup_mask));
				apm86xxx_write_mpa_reg_setmask(
					MPA_DIAG_ADDR,
					MPIC_EXT_IRQ_IN_SEL_WR
						(ipp->gpio_wakeup_mask));
			} else {
				ipp->gpio_irq = NO_IRQ;
			}
		} else {
			ipp->gpio_irq = NO_IRQ;
		}
	}

	/* Initialize the Clock interface */
	err = apm_clk_init();
	if (err) {
		printk(KERN_ERR "%s: APM86xxx clk init failed ...\n",
			np->full_name);
		goto error;
	}

	return platform_driver_register(&ipp_driver);
error:
	printk(KERN_ERR "SlimPRO initialize failed\n");

	if (!is_apm86xxx_lite()) {
		if (ipp->irq != NO_IRQ) 
			free_irq(ipp->irq, NULL);
	} else {
		if (ipp->gpio_irq != NO_IRQ) 
			free_irq(ipp->gpio_irq, NULL);
	}

	if (ipp->regs) {
		iounmap(ipp->regs);
		ipp->regs = NULL;
	}
	return err;
}

static int ipp_init_arch(void)
{
	return ipp_init(0);
}
arch_initcall(ipp_init_arch);

static int apm86xxx_lite = -1;
static int apm862xx = -1;
static int apm863xx = -1;
static int apm864xx = -1;
static int apm866xx = -1;
static int apm867xx = -1;
static char apm86xxxrev = ' '; /* Revision A, B, C, D, and etc */

static void apm86xxx_detect_variant(void)
{
	int err; 
	u32 data = 0;

	/* In case call this early, exit without error message */
	if (!ipp_data.scu_reg_base)
		return;

	err = apm86xxx_read_scu_reg(SCU_SOC_EFUSE_ADDR, &data);
	BUG_ON(err < 0);
	
	apm86xxx_lite = 0;
	apm862xx = 0;
	apm863xx = 0;
	apm864xx = 0;
	apm866xx = 0;
	apm867xx = 0;
	apm86xxxrev = 'A'; /* Default to A0 */

	if (mfspr(SPRN_PVR) == 0x00a144a0) {
		/* Detect APM866xx, APM862xxvB, and APM863xxvB */
		/* Extract the SW key of the EFUSE */
		switch (EFUSE0_RD(data) & 0xFE) {
		case 0x02:	/* BM die A0 */ 
			apm862xx = 1;
			apm86xxxrev = 'B';
			break;
		case 0x00:
		case 0x82: 	/* BM die A0 */
			apm866xx = 1;
			apm86xxxrev = 'A';
			break;
		case 0x42:	/* BM die A0 */
			apm863xx = 1;
			apm86xxxrev = 'B';
			break;
		case 0x06:	/* BM die A1 */
			apm862xx = 1;
			apm86xxxrev = 'C';
			break;
		case 0x86: 	/* BM die A1 */
			apm866xx = 1;
			apm86xxxrev = 'B';
			break;
		case 0x46:	/* BM die A1 */
			apm863xx = 1;
			apm86xxxrev = 'C';
			break;
		case 0x0E:	/* BM die A2 */
			apm862xx = 1;
			apm86xxxrev = 'D';
			break;
		case 0x8E:	/* BM die A2 */
			apm866xx = 1;
			apm86xxxrev = 'C';
			break;
		case 0x4E:	/* BM die A2 */
			apm863xx = 1;
			apm86xxxrev = 'D';
			break;		
		default:	/* BM die A2 */
			apm866xx = 1;
			apm86xxxrev = 'C';
			break;
		}
	} else if (mfspr(SPRN_PVR) == 0x00a16020) {
		/* Detect APM867xx and variants */
		/* Extract the SW key of the EFUSE */
		switch (EFUSE0_RD(data) & 0xFE) {
		case 0xE0: /* Rev A1 die */
                case 0xD0:
                case 0xF0:
                case 0xC8:
			apm864xx = 1;
			apm86xxxrev = 'A';
			break;
		case 0xC0: /* Rev A1 die */
                case 0xC1:
		case 0x00:
			apm867xx = 1;
			apm86xxxrev = 'A';
			break;
                case 0xE4: /* Rev A2 die */
                case 0xD4:
                case 0xF4:
                case 0xCC:
			apm864xx = 1;
			apm86xxxrev = 'B';
			break;
                case 0xC4: /* Rev A2 die */
                case 0xC5:
		case 0xDC:
		case 0xEC:
		default:
			apm867xx = 1;
			apm86xxxrev = 'B';
			break;
		}
	} else {
		/* Check for APM862xx and its variant */
		/* Extract the SW key of the EFUSE */
		switch ((EFUSE0_RD(data) >> 5) & 0xFE) {
		case 0x80:
			apm86xxx_lite = 1;
			apm862xx = 1;
			break;
		case 0x40:
			apm863xx = 1;
			break;
		default:
			apm862xx = 1;
			break;
		}
		apm86xxxrev = 'A';	
	}

	if (apm862xx) {
		if (apm86xxx_lite)
			printk(KERN_INFO 
				"APM862xx Rev%c Lite detected (0x%08X)\n",
				apm86xxxrev, data);
		else
			printk(KERN_INFO "APM862xx Rev%c detected (0x%08X)\n",
				apm86xxxrev, data);
	} else if (apm863xx) {
		printk(KERN_INFO "APM863xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else if (apm864xx) {
		printk(KERN_INFO "APM864xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else if (apm867xx) {
		printk(KERN_INFO "APM867xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else {
		printk(KERN_INFO "APM866xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	}	
}

static void apm86xxx_detect_rev(void)
{
	int err; 
	u32 data = 0;

	/* In case call this early, exit without error message */
	if (!ipp_data.scu_reg_base)
		return;
	err = apm86xxx_read_scu_reg(SCU_SOC_EFUSE_ADDR, &data);
	BUG_ON(err < 0);
	
	if (mfspr(SPRN_PVR) == 0x00a144a0) {
		/* Detect APM866xx, APM862xxvB, and APM863xxvB */
		/* Extract the SW key of the EFUSE */
		switch (EFUSE0_RD(data) & 0xFE) {
		case 0x02:	/* BM die A0 */ 
			apm86xxxrev = 'B';
			break;
		case 0x00:
		case 0x82: 	/* BM die A0 */
			if (apm863xx == 1)
				apm86xxxrev = 'B'; /* For DBvB emulation */				
			else
				apm86xxxrev = 'A';
			break;
		case 0x42:	/* BM die A0 */
			apm86xxxrev = 'B';
			break;
		case 0x06:	/* BM die A1 */
			apm86xxxrev = 'C';
			break;
		case 0x86: 	/* BM die A1 */
		case 0x8E: 
			if (apm863xx == 1)
				apm86xxxrev = 'C'; /* For DBvB emulation */
			else
				apm86xxxrev = 'B';
			break;
		case 0x46:	/* BM die A1 */
			apm86xxxrev = 'C';
			break;
		case 0x0E:	/* BM die A2 */
			apm86xxxrev = 'D';
			break;
		case 0x9E:	/* BM die A2 */
			if (apm863xx == 1)
				apm86xxxrev = 'D'; /* For DBvB emulation */
			else
				apm86xxxrev = 'C';
			break;
		case 0x4E:	/* BM die A2 */
			apm86xxxrev = 'D';
			break;		
		default:	/* BM die A2 */
			if (apm863xx == 1)
				apm86xxxrev = 'D'; /* For DBvB emulation */
			else
				apm86xxxrev = 'C';
			break;
		}
	} else if (mfspr(SPRN_PVR) == 0x00a16020) {
		/* Detect APM867xx and variants */
		/* Extract the SW key of the EFUSE */
		switch (EFUSE0_RD(data) & 0xFE) {
		case 0xE0: /* Rev A1 die */
                case 0xD0:
                case 0xF0:
                case 0xC8:
			apm86xxxrev = 'A';
			break;
		case 0xC0: /* Rev A1 die */
                case 0xC1:
		case 0x00:
			apm86xxxrev = 'A';
			break;
                case 0xE4: /* Rev A2 die */
                case 0xD4:
                case 0xF4:
                case 0xCC:
			apm86xxxrev = 'B';
			break;
                case 0xC4: /* Rev A2 die */
                case 0xC5:
		case 0xDC:
		case 0xEC:
		default:
			apm86xxxrev = 'B';
			break;
		}
	} else {
		/* Check for APM862xx and its variant */
		apm86xxxrev = 'A';	
	}

	if (apm862xx) {
		if (apm86xxx_lite)
			printk(KERN_INFO 
				"APM862xx Rev%c Lite detected (0x%08X)\n",
				apm86xxxrev, data);
		else
			printk(KERN_INFO "APM862xx Rev%c detected (0x%08X)\n",
				apm86xxxrev, data);
	} else if (apm863xx) {
		printk(KERN_INFO "APM863xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else if (apm864xx) {
		printk(KERN_INFO "APM864xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else if (apm867xx) {
		printk(KERN_INFO "APM867xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	} else {
		printk(KERN_INFO "APM866xx Rev%c detected (0x%08X)\n",
			apm86xxxrev, data);
	}	
}

static int __init apm86xxx_detect_param(char *p)
{
	if (strcmp("lite", p) == 0) {
		printk(KERN_INFO "APM86xxx Lite bootarg detected\n");
		apm86xxx_lite = 1;
		apm862xx = 1;
		apm863xx = 0;
		apm864xx = 0;
		apm866xx = 0;
		apm867xx = 0;
		apm86xxxrev = 'A';
	} else if (strcmp("apm863xx", p) == 0) {
		apm86xxx_lite = 0;
		apm862xx = 0;
		apm863xx = 1;
		apm864xx = 0;
		apm866xx = 0;
		apm867xx = 0;
		apm86xxx_detect_rev();	
	} else if (strcmp("apm864xx", p) == 0) {
		apm86xxx_lite = 0;
		apm862xx = 0;
		apm863xx = 0;
		apm864xx = 1;
		apm866xx = 0;
		apm867xx = 0;
		apm86xxx_detect_rev();	
	}
        return 0;
}
early_param("efuse", apm86xxx_detect_param);

int is_apm86xxx_lite(void)
{
	/* apm86xxx_lite cannot be true in secure boot mode */
	if (ipp_data.secure_mode || ipp_data.dp_mode) {
		apm86xxx_lite = 0;
		return apm86xxx_lite;
	} else if (apm86xxx_lite < 0) {
		apm86xxx_detect_variant();
	}

	return apm86xxx_lite;
}
EXPORT_SYMBOL(is_apm86xxx_lite);

int is_apm862xx(void)
{
	if (apm862xx < 0) {
		apm86xxx_detect_variant();
	}

	return apm862xx;
}
EXPORT_SYMBOL(is_apm862xx);

int is_apm863xx(void)
{
	if (apm863xx < 0) {
		apm86xxx_detect_variant();
	}

	return apm863xx;
}
EXPORT_SYMBOL(is_apm863xx);

int is_apm864xx(void)
{
	if (apm864xx < 0) {
		apm86xxx_detect_variant();
	}

	return apm864xx;
}

int is_apm867xx(void)
{
	if (apm867xx < 0) {
		apm86xxx_detect_variant();
	}

	return apm867xx;
}
EXPORT_SYMBOL(is_apm867xx);

int is_apm866xx(void)
{
	if (apm866xx < 0) {
		apm86xxx_detect_variant();
	}

	return apm866xx;
}

const char apm86xxx_rev(void)
{
	if (apm86xxxrev == ' ') {
		/* Check if we started detecting the CPU already. This can
                   occur if override from kernel paramater passing */
		if (apm862xx < 0)
			apm86xxx_detect_variant();
		else
			apm86xxx_detect_rev();	
	}

	return apm86xxxrev == ' ' ? 'A' : apm86xxxrev;
}

int apm86xxx_is_secure_mode(void)
{
	return ipp_data.secure_mode;
}

int apm86xxx_is_dp_mode(void)
{
	return ipp_data.dp_mode;
}

#if defined(CONFIG_APM862xx) || defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
static void wait_for_pllstart(void)
{
	volatile u32 data;

	BUG_ON(!ipp_data.scu_reg_base);
	/* Wait for SCU_PLLDLY.PLLSTARTDELAY time */
	/* FIXME: Calculate delay from SCU_PLLDLY.PLLSTARTDELAY */
	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
				SCU_PLLDLY_ADDR));
	data >>= PLLSTARTDELAY_SHIFT;

	/* Calculate delay in us - SYSCLK is 25MHz : Minimum is 5 us*/
	udelay(10);
}

static void wait_for_plllock(u32 lock_mask)
{
	volatile u32 data;

	BUG_ON(!ipp_data.scu_reg_base);

	/* Wait for SCU_PLLDLY.PLLSTARTDELAY time */
	/* FIXME: Calculate delay from SCU_PLLDLY.PLLLOCKDELAY */
	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
				SCU_PLLDLY_ADDR));
	data &= PLLLOCKDELAY_MASK;

	/* Calculate delay in us - SYSCLK is 25MHz : Minimum is 5 us*/
	udelay(10);
}

#if !defined(CONFIG_APM862xx)
static void wait_for_plllock1(u32 lock_mask)
{
        /* Calculate delay in us - SYSCLK is 25MHz : Minimum is 5 us*/
        udelay(10);
}
#endif

int enable_lcd_pll(struct apm86xxx_pll_ctrl *lcd_pll)
{
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
#define RESET3_MASK             0x00010000
#define MPA_GPIO_OE             0x00000aa0
#define PIN_14                  0x00004000
#define MPA_LED                 0x00000b24
#define LED_4                   0x00000010
#endif
	volatile u32 pll3_val, data;

	BUG_ON(!ipp_data.scu_reg_base);

#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
        /* Enable backlight */
        out_be32((volatile u32 *)(ipp_data.scu_reg_base + MPA_GPIO_OE), PIN_14);
        out_be32((volatile u32 *)(ipp_data.scu_reg_base + MPA_LED), LED_4);
#endif

	pll3_val = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
				SCU_SOCPLL3_ADDR));

	/* Return Success if PLL already configured */
	if (!(pll3_val & PWRDN3_MASK))
		return 0;
	
	/* Clear SOCPLL3 PWRDWN */
	pll3_val = (pll3_val | RESET3_MASK) & ~(PWRDN3_MASK | BYPASS3_MASK);
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR), pll3_val);

	/* Write SOCPLL3 CLKF/CLKOD/CLKR values */
	pll3_val = (pll3_val & ~(CLKR3_MASK | CLKOD3_MASK | CLKF3_MASK)) | 
			(CLKR3_WR(lcd_pll->clkr_val) |
			CLKOD3_WR(lcd_pll->clkod_val) | 
			CLKF3_WR(lcd_pll->clkf_val));
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR), pll3_val);
	pll3_val = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR));

	/* Write SOCPLLADJ3 BWADJ values - half of CLKF's divider val */
	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLLADJ3_ADDR));
	data &= ~BWADJ3_MASK;
	data |= lcd_pll->bwadj_val;
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			 SCU_SOCPLLADJ3_ADDR), data);

	/* Wait for SCU_PLLDLY.PLLSTARTDELAY time */
	wait_for_pllstart();

	/* Clear SOCPLL3 RESET */
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR),
			pll3_val & ~RESET3_MASK);

	/* Wait for SOCPLLSTAT.LOCK2 or PLLDLY.PLLLOCKDELAY */
	wait_for_plllock(LOCK3_MASK);

	return 0;
}

void disable_lcd_pll(void)
{
	BUG_ON(!ipp_data.scu_reg_base);

	/* Assert SOCPLL3 RESET */
	setbits32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR), RESET3_MASK);

	/* Assert SOCPLL3 PWRDWN */
	setbits32((volatile u32 *)(ipp_data.scu_reg_base +
			SCU_SOCPLL3_ADDR), PWRDN3_MASK);
}

int enable_eth_pll(struct apm86xxx_pll_ctrl *eth_pll)
{
	volatile u32 pll_val, data;
	int pll;
	int plladj;

	/* Bit definition is same for both PLL */
#if defined(CONFIG_APM862xx)
	pll = SCU_SOCPLL4_ADDR;
	plladj = SCU_SOCPLLADJ4_ADDR;
#else
	#define RESET4_MASK		MPA_RESET4_MASK
	pll = SCU_SOCPLL6_ADDR;	
	plladj = SCU_SOCPLLADJ6_ADDR;
#endif
	BUG_ON(!ipp_data.scu_reg_base);
	pll_val = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base + pll));

	/* Return Success if PLL already configured */
	if (!(pll_val & PWRDN4_MASK))
		return -EALREADY;
	
	/* Clear SOCPLL PWRDWN */
	pll_val = (pll_val | RESET4_MASK) & ~(PWRDN4_MASK | BYPASS4_MASK);
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base + pll), pll_val);

	/* Write SOCPLL CLKF/CLKOD/CLKR values */
#if defined(CONFIG_APM862xx)
	pll_val = (pll_val & ~(CLKR4_MASK | CLKOD4_MASK | CLKF4_MASK)) |
			(CLKR4_WR(eth_pll->clkr_val) |
			CLKOD4_WR(eth_pll->clkod_val) |
			CLKF4_WR(eth_pll->clkf_val));
#else
	pll_val = (pll_val & ~(CLKR4_MASK | CLKOD4_MASK | CLKF6_MASK)) |
			(CLKR4_WR(eth_pll->clkr_val) |
			CLKOD4_WR(eth_pll->clkod_val) |
			CLKF6_WR(eth_pll->clkf_val));
#endif
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base + pll), pll_val);
	pll_val = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base + pll));

	/* Write SOCPLLADJ BWADJ values - half of CLKF's divider val */
	data = APM_IN_BE32((volatile u32 *)(ipp_data.scu_reg_base + plladj));
	data &= ~BWADJ4_MASK;
	data |= eth_pll->bwadj_val;
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base + plladj), data);

	/* Wait for SCU_PLLDLY.PLLSTARTDELAY time */
	wait_for_pllstart();

	/* Clear SOCPLL RESET */
	APM_OUT_BE32((volatile u32 *)(ipp_data.scu_reg_base + pll), pll_val & ~RESET4_MASK);

#if defined(CONFIG_APM862xx)
	/* Wait for SOCPLLSTAT.LOCK4 or PLLDLY.PLLLOCKDELAY */
	wait_for_plllock(LOCK4_MASK);
#else
	/* Wait for SOCPLLSTAT1.LOCK6 or PLLDLY.PLLLOCKDELAY */
	wait_for_plllock1(LOCK61_MASK);
#endif
	return 0;
}
EXPORT_SYMBOL(enable_eth_pll);

void disable_eth_pll(void)
{
	int pll;
	BUG_ON(!ipp_data.scu_reg_base);
#if defined(CONFIG_APM862xx)
	pll = SCU_SOCPLL4_ADDR;
#else
	#define RESET4_MASK		MPA_RESET4_MASK
	pll = SCU_SOCPLL6_ADDR;
#endif
	/* Assert SOCPLL RESET */
	setbits32((volatile u32 *)(ipp_data.scu_reg_base + pll), RESET4_MASK);

	/* Assert SOCPLL PWRDWN */
	setbits32((volatile u32 *)(ipp_data.scu_reg_base + pll), PWRDN4_MASK);
}

#endif /* CONFIG_APM862xx || CONFIG_APM866xx  || CONFIG_APM862xxvB */

int apm86xxx_dp_cfg(u8 cmd, u8 res_type, u8 irq, u64 start_addr, u64 end_addr)
{
	struct ipp_dp_cmd dp;
	u32 resp;
	int rc;
	
	if (!apm86xxx_is_dp_mode())
		return 0;

	dp.cmd = cmd;
	dp.res_type = res_type;
	dp.rd = 1;
	dp.wr = 1;
	dp.rsvd1 = 0;
	dp.domain = 0;
	dp.irq = irq;
	dp.resv3 = 0;
	dp.phy_start_hi = (u8) (start_addr >> 32);
	dp.phy_start_lo = (u32) start_addr;
	dp.phy_end_hi = (u8) (end_addr >> 32);
	dp.phy_end_lo = (u32) end_addr;
        
	rc = ipp_send_data_msg(IPP_DP_HDLR, &dp, sizeof(dp), &resp);
	if (rc) {
		printk(KERN_ERR 
			"Domain protection command failed error %d\n", rc);
		return rc;
	}

	return IPP_DECODE_ERROR_MSG_CODE(resp);
}

int apm86xxx_dp_qm(u8 cmd, u8 res_type, int read, u32 param, u32 *data)
{
	struct ipp_dp_qm_cmd dp;
	u32 resp;
	int rc;
	int len;

	if (!apm86xxx_is_dp_mode())
		return 0;

	if (cmd == IPP_DP_CMD_QM_PB)
		len = 1;
	else if (cmd  == IPP_DP_CMD_QM_QSTATE)
		len = 5;
	else
		len = 2;

	dp.cmd = cmd;
	dp.res_type = res_type;
	dp.rd = read;
	dp.rsvd1 = 0;
	dp.domain = 0;
	dp.param = param;
	if (!read) 
		memcpy(dp.data, data, len * 4);

	rc = ipp_send_addr_msg(IPP_DP_ADDR_HDLR, (u32*) &dp, sizeof(dp), 
				&resp);
	if (rc) {
		printk(KERN_ERR 
			"Domain protection QM command failed error %d\n", rc);
		return rc;
	}

	if (read)
		memcpy(data, dp.data, len * 4);

	return IPP_DECODE_ERROR_MSG_CODE(resp);
}
