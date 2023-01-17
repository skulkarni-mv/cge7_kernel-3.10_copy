/*
 * APM86xxx SoC setup code
 *
 * Copyright (c) 2010 Applied Micro Circuits Corporation.
 * Loc Ho <lho@apm.com>.
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
#include <linux/stddef.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/interrupt.h>
#include <linux/irq.h>
#include <linux/of_platform.h>
#include <linux/export.h>
#include <linux/err.h>
#include <linux/syscore_ops.h>
#include <linux/delay.h>
#include <linux/clk.h>
//#include <linux/mtd/ufc.h>
#include <asm/io.h>
#include <asm/prom.h>
#include <asm/dcr.h>
#include <asm/dcr-regs.h>
#include <asm/dcr-native.h>
#include <asm/reg.h>
#include <asm/mpic.h>
#include <asm/apm86xxx_soc.h>
//#include <asm/apm86xxx_pm.h>
#include <asm/apm_pcie_csr.h>
#ifdef CONFIG_APM86xxx_SHMEM
#include <asm/apm_shm.h>
#endif
#include <asm/apm_ahbc_csr.h>
#include <asm/ipp.h>
#if defined(CONFIG_APM86xxx_PCI_EXPRESS)
#include "apm86xxx_pcie.h"
#endif
#include "apm_sdu_csr.h"

struct l2c {
	int status;
	int size;
	int dcraddr;
	int dcrdata;
	int ecc_enabled;
};

static struct l2c l2c_info[NR_CPUS];
static u8 *sdu_base = NULL;
static u8 *ahbc_base = NULL;
static void __iomem *ufc_base = NULL;
static u32 nfboot0;

static u32 ahbc_usb_clk_enable[3]   = { 0, 0, 0 };
static u32 ahbc_usb_enable[3]       = { 0, 0, 0 };
#if defined(CONFIG_APM867xx)
static int apm_enet_pcie2tosgmii0(int enable_sgmii_internal_clk);
static int apm_enet_sata0tosgmii1(int enable_sgmii_internal_clk);
#elif defined(CONFIG_APM862xx)
static u32 ahbc_usb_base[3] =         { 0x018, 0x024, 0x0ac };
static u32 ahbc_usb_hostcfg_base[3] = { 0x000, 0x064, 0x0b8 };
#else
static u32 ahbc_usb_base[3]         = { 0x200, 0x210, 0x220 };
static u32 ahbc_usb_hostcfg_base[3] = { 0x000, 0x230, 0x240 };
#endif

static inline unsigned l2c_get(int reg)
{
	mtdcr(DCRN_L2C_ADDR, reg);
	return mfdcr(DCRN_L2C_DATA);
}

static inline void l2c_set(int reg, unsigned val)
{
	mtdcr(DCRN_L2C_ADDR, reg);
	mtdcr(DCRN_L2C_DATA, val);
}

/*
 * cpu_to_l2cache (taken from ../kernel/smp.c)
 */
static struct device_node *cpu_to_l2cache(int cpu)
{
	struct device_node *np;
	struct device_node *cache;

	if (!cpu_present(cpu))
		return NULL;

	np = of_get_cpu_node(cpu, NULL);
	if (np == NULL)
		return NULL;

	cache = of_find_next_cache_node(np);

	of_node_put(np);

	return cache;
}

static void l2c_get_node(unsigned int cpu, struct l2c *l2c)
{
	struct device_node *np;
	const char *status;
	const unsigned int *dcrreg;
	const unsigned int *psize;
	const unsigned int *ecc_enable;
	int len;

#if defined(CONFIG_SMP)
	np = cpu_to_l2cache(cpu);
#else
	np = cpu_to_l2cache(0);
	cpu = (unsigned int)mfspr(SPRN_PIR);
#endif

	if (!np) {
		printk(KERN_INFO "CPU%d: could not find L2 cache node\n", cpu);
		return;
	}

	if (!of_device_is_compatible(np, "apm,l2-cache")) {
		printk(KERN_INFO "CPU%d: incompatible L2 cache node\n", cpu);
		goto out;
	}

	status = of_get_property(np, "status", &len);
	if (status && strcmp(status,"disabled") == 0) {
		printk(KERN_INFO "CPU%d: L2 cache is disabled\n", cpu);
		goto out;
	}

	psize = of_get_property(np, "cache-size", NULL);
	if (psize == NULL) {
		printk(KERN_INFO "CPU%d: Can't get L2 cache-size!\n", cpu);
		goto out;
	}

	dcrreg = of_get_property(np, "dcr-reg", &len);
	if (!dcrreg || (len != 2*sizeof(unsigned int))) {
		printk(KERN_INFO "CPU%d: L2 cache node has missing or invalid "
			   "dcr-reg property\n", cpu);
		goto out;
	}

	if (*dcrreg != DCRN_L2C_ADDR) {
		/* Do this to use mtdcr instead of mtdcrx because
		 * mtdcrx is not always available in binutils */
		printk(KERN_INFO "CPU%d: unknown L2 cache access for "
			   "dcr-reg property\n", cpu);
		goto out;
	}

	ecc_enable = of_get_property(np, "ecc-enable", &len);
	if (ecc_enable)
		l2c->ecc_enabled = *ecc_enable;
	else
		l2c->ecc_enabled = 1; /* default is enabled */

	l2c->dcraddr = *dcrreg;
	l2c->dcrdata = *dcrreg + 1;
	l2c->size    = *psize >> 10;
	l2c->status  = 1; /* enable */
out:
	if (np)
		of_node_put(np);

	return;
}

u32 apm86xxx_sdu_get_reg(u32 offset)
{
	if (sdu_base == NULL)
		return 0;
	return in_be32((void *) (sdu_base + offset));
}
EXPORT_SYMBOL(apm86xxx_sdu_get_reg);

void apm86xxx_sdu_set_reg(u32 offset, u32 val)
{
	if (sdu_base == NULL)
		return;

	if (!apm86xxx_is_dp_mode()) {
		out_be32((void *) (sdu_base + offset), val);
		return;
	}

	/* Write via SlimPRO interface */
	apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_SDU, 0, offset, val);	
}
EXPORT_SYMBOL(apm86xxx_sdu_set_reg);

u32 apm86xxx_ahbc_get_reg(u32 offset)
{
	if (ahbc_base == NULL)
		return 0;
	return in_be32((void *) (ahbc_base + 
				AHBC_TOP_REG_BASE_OFFSET + offset));
}
EXPORT_SYMBOL(apm86xxx_ahbc_get_reg);

void apm86xxx_ahbc_set_reg(u32 offset, u32 val)
{
	if (ahbc_base == NULL)
		return;

	if (!apm86xxx_is_dp_mode()) {
		out_be32((void *) (ahbc_base + 
				AHBC_TOP_REG_BASE_OFFSET + offset), val);
		return;
	}
	/* Write via SlimPRO interface */
	apm86xxx_dp_cfg(IPP_DP_CMD_REG_WR, IPP_DP_RES_AHBC, 0, offset, val);
}
EXPORT_SYMBOL(apm86xxx_ahbc_set_reg);

void set_plb_lowfreq_mode(int enable)
{
	u32 reg;

	reg = apm86xxx_sdu_get_reg(SDU_PBRG_CTRL_ADDR);
	if (enable)
		apm86xxx_sdu_set_reg(SDU_PBRG_CTRL_ADDR, 
					reg | PLB_LT_AXI_MASK);
	else
		apm86xxx_sdu_set_reg(SDU_PBRG_CTRL_ADDR, 
					reg & ~PLB_LT_AXI_MASK);
}

void cpu_l2c_enable(void)
{
	unsigned long flags;
	unsigned int l2cr0;
#if defined(CONFIG_SMP)
	unsigned int l2cr2;
	unsigned int cpu = smp_processor_id();
	struct l2c *l2c = &l2c_info[cpu];
#else
	unsigned int cpu = (unsigned int) mfspr(SPRN_PIR);
	struct l2c *l2c = &l2c_info[0];
#endif

	if (!l2c->status)
		return; /* L2 cache disabled */

	/*
	 * Coherency Configuration Settings for L2 cache.
	 *
	 * See section 3.7.4 in PPC465-S User's Manual
	 * See section 7.2 and 8.8.8 in Streak Software User's Guide
	 *
	 * TLB Attributes for Coherency Operation
	 *   WL1 = 1 -- Write-through in L1 DCache
	 *   W   = 0 -- Copy-Back, not Write-Through, in L2
	 *   I   = 0 -- Not cache inhibited
	 *   M   = 0 -- Coherent
	 *   G   = 0 -- Not Guarded
	 *
	 *   Configured in the following files
	 *     arch/powerpc/include/asm/mmu-44x.h
	 *     arch/powerpc/kernel/head_44x.S
	 */

	printk(KERN_DEBUG "CPU%d enabling L2 cache\n", cpu);

	local_irq_save(flags);
	asm volatile ("sync" ::: "memory");

	flush_dcache();

	/* Clear L2FER0 and L2FER1 to prevent errors from being forced */
	l2c_set(DCRN_L2FER0, 0);
	l2c_set(DCRN_L2FER1, 0);

	/* Set Extended Real Address Prefix */
	l2c_set(DCRN_L2ERAPR, 0);
	l2c_set(DCRN_L2SLVERAPR, 0);

	/* Set PLB settings for L2, use defaults for now */
	l2c_set(DCRN_L2CR3, 0);

	/* For L2 cache, use L2CR1 defaults */
	l2c_set(DCRN_L2CR1, 0);

	/* Set TAA and DAA to appropriate values.
	 * This values will be specified in a table
	 * based on voltage and frequency. */
	l2cr0  = l2c_get(DCRN_L2CR0);
	l2cr0 &= ~(L2CR0_TAA_MASK | L2CR0_DAA_MASK);
	l2cr0 |= (L2CR0_TAA_1 | L2CR0_DAA_1);
	l2c_set(DCRN_L2CR0, l2cr0);

	/* check if ECC should be enabled or disabled */
	if (l2c->ecc_enabled) {
		unsigned int l2mcrer;

		l2cr0 = l2c_get(DCRN_L2CR0);
		l2cr0 &= ~(L2CR0_DECC | L2CR0_DECA); 
		l2c_set(DCRN_L2CR0, l2cr0);

		l2mcrer = L2MCSR_ITSBE | L2MCSR_ITDBE |
			  L2MCSR_IDSBE | L2MCSR_IDDBE |
			  L2MCSR_DTSBE | L2MCSR_DTDBE |
			  L2MCSR_DDSBE | L2MCSR_DDDBE;
		l2c_set(DCRN_L2MCRER, l2mcrer);
	} else {
		l2cr0 = l2c_get(DCRN_L2CR0);
		l2cr0 |= (L2CR0_DECC | L2CR0_DECA); 
		l2c_set(DCRN_L2CR0, l2cr0);
	}
	
	/* enable L2 cache */
	l2cr0  = l2c_get(DCRN_L2CR0);
	l2cr0 &= ~L2CR0_AS_MASK;
	l2cr0 |= (L2CR0_AS_256K | L2CR0_TAI);
	l2c_set(DCRN_L2CR0, l2cr0);

	do {
		l2cr0 = l2c_get(DCRN_L2CR0);
	} while ( (l2cr0 & L2CR0_TAI) != 0);

	/* L2 cache Op Broadcast Enable */
	mtspr(SPRN_CCR1, (mfspr(SPRN_CCR1) | CCR1_L2COBE));

#if 0
	/* Data Intervention Enable */
	PLB_PCICR[DIE] = 1; 
#endif

#if defined(CONFIG_SMP)
	/* Disable Snoop Inihibit */
	mtdcr(DCRN_STRK_CR4, mfdcr(DCRN_STRK_CR4) & ~STRK_CR4_SNPI);
	/* Join Coherency domain */
	l2cr2 = L2CR2_SNPME | L2CR2_L1CE | L2CR2_SNPRQPD3;
	l2c_set(DCRN_L2CR2, l2cr2);
#endif

	asm volatile ("sync; isync" ::: "memory");
	local_irq_restore(flags);

	printk(KERN_DEBUG "CPU%d: L2CR0 = 0x%08x\n",
		cpu, l2c_get(DCRN_L2CR0));
	printk(KERN_DEBUG "CPU%d: L2CR1 = 0x%08x\n",
		cpu, l2c_get(DCRN_L2CR1));
	printk(KERN_DEBUG "CPU%d: L2CR2 = 0x%08x\n",
		cpu, l2c_get(DCRN_L2CR2));
	printk(KERN_DEBUG "CPU%d: L2CR3 = 0x%08x\n",
		cpu, l2c_get(DCRN_L2CR3));

	printk(KERN_INFO "CPU%d %dk L2 cache enabled\n", cpu, l2c->size);

	return;
}

void cpu_l2c_disable(void)
{
	unsigned int l2cr0;

	flush_dcache();

	l2cr0 = l2c_get(DCRN_L2CR0);
	if ((l2cr0 & L2CR0_AS_256K) == L2CR0_AS_256K) {
		l2c_disable();
	}
}

void cpu_l2c_init(void)
{
	unsigned int cpu;
	struct l2c *l2c;

	for (cpu = 0; cpu < NR_CPUS; cpu++) {
		l2c = &l2c_info[cpu];
		l2c->status = 0; /* disabled by default */
		l2c_get_node(cpu, l2c);
	}

	cpu_l2c_enable();
}

#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
static void apm86xxx_domain_violation(u64 paddr_dp_csr, int res_type)
{
	u32 intstat;
	u32 reg;
	u64 paddr;
	u32 tag;
	u32 domain;
	void *dp_csr;
	
	dp_csr = ioremap_nocache(paddr_dp_csr, 0x1000);
	if (dp_csr == NULL)
		return;

	intstat = in_be32(dp_csr + AMPP_INT_ADDR);
	if (intstat & RD_VIOL_MASK) {
		reg = in_be32(dp_csr + AMPP_RD_VIO_LOG_0_ADDR);
		domain = DOMAIN_ID0_RD(reg);
		paddr = ADDRESS_36_120_RD(reg);
		paddr <<= 12;
		reg = in_be32(dp_csr + AMPP_RD_VIO_LOG_1_ADDR);
		tag = TAG_9_51_RD(reg);
		paddr |= ADDRESS_11_01_RD(reg);
		printk("CSR 0x%02X.%08X Read violation domain %d tag 0x%02X "
			"PADDR 0x%02X.%08X\n", 
			(u32) (paddr_dp_csr >> 32), (u32) paddr_dp_csr,
			domain, tag, (u32) (paddr >> 32), (u32) paddr); 
	}
	if (intstat & WR_VIOL_MASK) {
		reg = in_be32(dp_csr + AMPP_WR_VIO_LOG_0_ADDR);
		domain = DOMAIN_ID0_RD(reg);
		paddr = ADDRESS_36_120_RD(reg);
		paddr <<= 12;
		reg = in_be32(dp_csr + AMPP_WR_VIO_LOG_1_ADDR);
		tag = TAG_9_51_RD(reg);
		paddr |= ADDRESS_11_01_RD(reg);
		printk("CSR 0x%02X.%08X Write violation domain %d tag 0x%02X "
			"PADDR 0x%02X.%08X\n",
			(u32) (paddr_dp_csr >> 32), (u32) paddr_dp_csr,
			domain, tag, (u32) (paddr >> 32), (u32) paddr); 
	}
	/* We need to clear the source indirectly via SlimPRO as 
           domain protection register is read-only */
	apm86xxx_dp_cfg(IPP_DP_CMD_CLR_VIOLATION, res_type, 0, 0x0ULL, 0x0ULL);

	iounmap(dp_csr);
}
#endif

/*
 * APM86xxx machine_check_4xx_custom routine
 *     This overrides the weak default custom_machine_check in kernel/trap.c
 *     to check for L2 and bridges errors.
 */
void machine_check_4xx_custom(void)
{
	u32 pesr; 
	u32 l2cr0;
	u32 l2mcsr = 0;
	u32 pearl = 0;
	u32 pearh = 0;
#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
	u32 vio_addr;
	u32 vio_flgs;
	u32 reg;
#endif

	/* Check L2 for error */
	l2cr0 = l2c_get(DCRN_L2CR0);
	if ((l2cr0 & L2CR0_AS_MASK) == 0)
		goto l2_done; /* L2C disabled */
	if ((l2cr0 & L2CR0_DECC) != 0 )
		goto l2_done; /* L2C ECC disabled */

	l2mcsr = l2c_get(DCRN_L2MCSR);
	if (l2mcsr == 0) 
		goto l2_done; /* no L2C machine check detected */

	if (l2mcsr & L2MCSR_ITSBE)
		printk("Instruction Side Tag Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_ITDBE)
		printk("Instruction Side Tag Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_IDSBE)
		printk("Instruction Side Data Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_IDDBE)
		printk("Instruction Side Data Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_DTSBE)
		printk("Data Side Tag Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_DTDBE)
		printk("Data Side Tag Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_DDSBE)
		printk("Data Side Data Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_DDDBE)
		printk("Data Side Data Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_SNPTSBE)
		printk("Snoop Side Tag Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_SNPTDBE)
		printk("Snoop Side Tag Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_SNPDSBE)
		printk("Snoop Side Data Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_SNPDDBE)
		printk("Snoop Side Data Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_FARM)
		printk("Fixed Address Region Mismatch\n");
	if (l2mcsr & L2MCSR_MSTRQE)
		printk("PLB Master Port Request Error\n");
	if (l2mcsr & L2MCSR_MSTRDE)
		printk("PLB Master Port Read Data Error\n");
	if (l2mcsr & L2MCSR_MSTRDPE)
		printk("PLB Master Port Read Data Parity Error\n");
	if (l2mcsr & L2MCSR_SNPAPE)
		printk("PLB Snoop Port Address Parity Error\n");
	if (l2mcsr & L2MCSR_SLVWDE)
		printk("PLB Slave Port Write Data Error\n");
	if (l2mcsr & L2MCSR_SLVWDPE)
		printk("PLB Slave Port Write Data Parity Error\n");
	if (l2mcsr & L2MCSR_SLVAPE)
		printk("PLB Slave Port Address Parity Error\n");
	if (l2mcsr & L2MCSR_SLVBEPE)
		printk("PLB Slave Port Byte Enable Parity Error\n");
	if (l2mcsr & L2MCSR_SLVDSBE)
		printk("PLB Slave Port Data Array Single Bit Error\n");
	if (l2mcsr & L2MCSR_SLVDDBE)
		printk("PLB Slave Port Data Array Double Bit Error\n");
	if (l2mcsr & L2MCSR_SLVIAE)
		printk("PLB Slave Port Invalid Address Error\n");
	if (l2mcsr & L2MCSR_SLVICE)
		printk("PLB Slave Port Invalid Command Error\n");
	if (l2mcsr & L2MCSR_DCRTO)
		printk("DCR Timeout\n");

	l2c_set(DCRN_L2MCSR, l2mcsr);
l2_done:

	#define DCRIPR_PESR		0x24000000
	#define DCRN_PESR		0x00000008
	#define DCRN_PEARL		0x00000009
	#define DCRN_PEARH		0x0000000A
	/* Check for bridge errors */
	mtspr(SPRN_DCRIPR, DCRIPR_PESR); /* set upper 22 bits of DCR address */
	isync();
	pesr = mfdcr(DCRN_PESR);
	if (pesr) {
		pearl = mfdcr(DCRN_PEARL);
		pearh = mfdcr(DCRN_PEARH);
		printk("PLB %s error 0x%08X at 0x%08X_%08X\n",
			 pesr & 0x10000000 ? "read" : "write", 
			 pesr, pearh, pearl);	
		/* Clear them */	
		mtdcr(DCRN_PESR, 0xFFFFFFFF);
	}	 
	mtspr(SPRN_DCRIPR, 0); /* clear upper 22 bits of DCR address */
	isync();

#if defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)
	#define DCRN_DP_VIO_ADDR		0x04
	#define DCRN_DP_VIO_FLGS		0x05
	#define DCRN_DP_VIO_FLG_VIOLATION	0x80000000
	#define DCRN_DP_VIO_FLG_READ		0x40000000
	#define DCRN_DP_VIO_FLG_DCR		0x20000000
	#define DCRN_DP_VIO_FLG_MULTI		0x10000000
	
	#define CONFIG_SYS_CSR_BASE	0xddd800000ULL
	#define QM_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0x08000)
	#define SDU_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0x18000)
	#define DMA_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0x28000)
	#define SEC_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0x38000)
	#define PBRG_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0x48000)
	#define OCM_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0x58000)
	#define SATA_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0x78000)
	#define PCIE0_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0x88000)
	#define PCIE1_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0x98000)
	#define ETH01_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0xa8000)
	#define ETH23_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0xc8000)
	#define QML_DP_CSR_BASE		(CONFIG_SYS_CSR_BASE + 0xd8000)
	#define CLE23_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0xe8000)
	#define PCIE2_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0xf8000)
	#define AHBC_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0x68000)
	#define SLIMPRO_DP_CSR_BASE	(CONFIG_SYS_CSR_BASE + 0xb8000)

	/* Check for domain protection violation */
	if (!(l2mcsr & (L2MCSR_MSTRQE | L2MCSR_MSTRDE | L2MCSR_SLVWDE)))
		goto done_dp_violation;

	vio_addr = mfdcr(DCRN_DP_VIO_ADDR);
	vio_flgs = mfdcr(DCRN_DP_VIO_FLGS);
	if (vio_flgs & DCRN_DP_VIO_FLG_VIOLATION) {
		if (vio_flgs & DCRN_DP_VIO_FLG_DCR) {
			printk("%s access voilation at DCR 0x%08X\n",
				vio_flgs & DCRN_DP_VIO_FLG_READ ? 
					"Read" : "Write",
				vio_addr);
		} else { 
			u64 paddr;
			paddr = vio_addr;
			paddr <<= 4;
			paddr |= pearl & 0xF;
			printk("%s access voilation at 0x%08X_%08X\n",
				vio_flgs & DCRN_DP_VIO_FLG_READ ? 
					"Read" : "Write", 
				(u32) (paddr >> 32), (u32) paddr);
		}	
		/* Clear it */
		mtdcr(DCRN_DP_VIO_FLGS, 0x0);
		mtdcr(DCRN_DP_VIO_ADDR, 0x0);

		panic("Unrecoverable Machine check");			
	}

	/* Check non-CPU IP entry */
	apm86xxx_read_mpa_reg(MPA_ARM_INTSTAT2_ADDR, &reg);
	if (reg & DOM_PROT_VIOL_EVENT2_MASK) {
		if (reg & (1 << 10))
			apm86xxx_domain_violation(QM_DP_CSR_BASE,
						IPP_DP_RES_QM);
		if (reg & (1 << 11))
			apm86xxx_domain_violation(AHBC_DP_CSR_BASE,
						IPP_DP_RES_AHBC);
		if (reg & (1 << 12))
			apm86xxx_domain_violation(DMA_DP_CSR_BASE,
						IPP_DP_RES_DMA);
		if (reg & (1 << 13))
			apm86xxx_domain_violation(SDU_DP_CSR_BASE,
						IPP_DP_RES_SDU);
		if (reg & (1 << 14))
			apm86xxx_domain_violation(PBRG_DP_CSR_BASE,
						IPP_DP_RES_PBRG);
		if (reg & (1 << 15))
			apm86xxx_domain_violation(SEC_DP_CSR_BASE,
						IPP_DP_RES_SEC);
		if (reg & (1 << 16))
			apm86xxx_domain_violation(OCM_DP_CSR_BASE,
						IPP_DP_RES_OCM);
		if (reg & (1 << 18))
			apm86xxx_domain_violation(ETH01_DP_CSR_BASE,
						IPP_DP_RES_ETH01);
		if (reg & (1 << 20))
			apm86xxx_domain_violation(QML_DP_CSR_BASE,
						IPP_DP_RES_QML);
		if (reg & (1 << 21))
			apm86xxx_domain_violation(PCIE2_DP_CSR_BASE,
						IPP_DP_RES_PCIE2);
		if (reg & (1 << 22))
			apm86xxx_domain_violation(PCIE1_DP_CSR_BASE,
						IPP_DP_RES_PCIE1);
		if (reg & (1 << 23))
			apm86xxx_domain_violation(PCIE0_DP_CSR_BASE,
						IPP_DP_RES_PCIE0);
		if (reg & (1 << 24))
			apm86xxx_domain_violation(SATA_DP_CSR_BASE,
						IPP_DP_RES_SATA);
		if (reg & (1 << 25))
			apm86xxx_domain_violation(ETH23_DP_CSR_BASE,
						IPP_DP_RES_ETH23);
		if (reg & (1 << 26))
			apm86xxx_domain_violation(CLE23_DP_CSR_BASE,
						IPP_DP_RES_CLE23);
		if (reg & (1 << 19))
			apm86xxx_domain_violation(SLIMPRO_DP_CSR_BASE,
						IPP_DP_RES_SLIMPRO);
		/* Clear them all via SlimPRO as not possible to write */
		apm86xxx_dp_cfg(IPP_DP_CMD_CLR_VIOLATION, IPP_DP_RES_NONE, 
				0, 0x0ULL, 0x0ULL);
		panic("Unrecoverable Machine check");			
	}	    
done_dp_violation:;
#endif

#if defined(CONFIG_APM86xxx_PCI_EXPRESS)
	/* Check for PCIE AXI error */
	apm_pcie_hdl_axi_error();
#endif
}

#if !defined(CONFIG_APM867xx)
void apm86xxx_ahbc_usb_enable(int port)
{
	u32 reg_val;
	static int once_done = 0;

	if (!ahbc_base)
		return;

#if (defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)) && \
    (defined(CONFIG_SMP) || defined(CONFIG_APM86xxx_IOCOHERENT))
        /* Enable coherency for USB IP's for SMP APM866xx & APM862xxvB */
        switch (port) {
	case 0: /* USB OTG */
		reg_val = apm86xxx_ahbc_get_reg(SDR_USB_OTG_AHB2AXI_CFG_ADDR);
		reg_val = PW_AXI_SIDEBAND_PRIO_F2_SET(reg_val, 0x1);
		reg_val = PR_AXI_SIDEBAND_PRIO_F2_SET(reg_val, 0x1);
		apm86xxx_ahbc_set_reg(SDR_USB_OTG_AHB2AXI_CFG_ADDR, reg_val);
		break;
	case 1: /* EHCI */
		reg_val = apm86xxx_ahbc_get_reg(SDR_EHCI_0_AHB2AXI_CFG_ADDR);
		reg_val = PW_AXI_SIDEBAND_PRIO_F3_SET(reg_val, 0x1);
		reg_val = PR_AXI_SIDEBAND_PRIO_F3_SET(reg_val, 0x1);
		apm86xxx_ahbc_set_reg(SDR_EHCI_0_AHB2AXI_CFG_ADDR, reg_val);
		/* OHCI */
		reg_val = apm86xxx_ahbc_get_reg(SDR_OHCI_0_AHB2AXI_CFG_ADDR);
		reg_val = PW_AXI_SIDEBAND_PRIO_F4_SET(reg_val, 0x1);
		reg_val = PR_AXI_SIDEBAND_PRIO_F4_SET(reg_val, 0x1);
		apm86xxx_ahbc_set_reg(SDR_OHCI_0_AHB2AXI_CFG_ADDR, reg_val);
		break;
	case 2: /* EHCI */
		reg_val = apm86xxx_ahbc_get_reg(SDR_EHCI_1_AHB2AXI_CFG_ADDR);
		reg_val = PW_AXI_SIDEBAND_PRIO_F5_SET(reg_val, 0x1);
		reg_val = PR_AXI_SIDEBAND_PRIO_F5_SET(reg_val, 0x1);
		apm86xxx_ahbc_set_reg(SDR_EHCI_1_AHB2AXI_CFG_ADDR, reg_val);
		/* OHCI */
		reg_val = apm86xxx_ahbc_get_reg(SDR_OHCI_1_AHB2AXI_CFG_ADDR);
		reg_val = PW_AXI_SIDEBAND_PRIO_F6_SET(reg_val, 0x1);
		reg_val = PR_AXI_SIDEBAND_PRIO_F6_SET(reg_val, 0x1);
		apm86xxx_ahbc_set_reg(SDR_OHCI_1_AHB2AXI_CFG_ADDR, reg_val);
		break;
	default:
		break;
        }
#endif

	/* Once AHBC USB[port] is reset & enabled, do not reset & re-enabled */
	if (ahbc_usb_enable[port])
		return;

#if defined(CONFIG_APM86xxx_SHMEM) && !defined(CONFIG_APM867xx)
	/* Check if AHBC USB OTG is out of reset, mark its flag */
	reg_val = apm86xxx_ahbc_get_reg(ahbc_usb_base[0] + 0x04);
	if ((reg_val & (USB0_OTGDISABLE_WR(1) | USB0_PORTRESET_WR(1) |
			USB0_POR_WR(1))) == 0)
		ahbc_usb_enable[0] = 1;
#endif
#if !defined(CONFIG_APM867xx)
	/* If AHBC USB_OTG is not reset & enabled, first reset & enable it 
           as the host port clock comes from USB OTG clock. */
	if (port && ahbc_usb_enable[0] == 0) {
		ahbc_usb_enable[0] = port;	/* Save original port */
		port = 0;			/* Setup for OTG port first */
	}
#endif

_ahbc_usb_enable_start:
	/* Put USB Port in reset */
	reg_val = USB0_PORTRESET_WR(1) | USB0_POR_WR(1);
#ifdef CONFIG_APM86xxx_SHMEM
	if (port == 0 && !apm86xxx_is_dp_mode())
		atomic_csr_clrsetbits(~reg_val, reg_val, 
			(void *)(ahbc_base + AHBC_TOP_REG_BASE_OFFSET + 
				 ahbc_usb_base[port] + 0x04));
	else
		apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x4, reg_val);
#else
	apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x4, reg_val);
#endif

	/* Set clock */
	/* Bring USB Port out of reset */
	reg_val = USB0_REFCLKDIV_WR(2);
	if (port)
		reg_val |= USB0_REFCLKSEL_WR(2);
#ifdef CONFIG_APM86xxx_SHMEM
	if (port == 0 && !apm86xxx_is_dp_mode()) {
		atomic_csr_clrsetbits(~reg_val, reg_val,
				(void *)(ahbc_base + AHBC_TOP_REG_BASE_OFFSET + 
				 ahbc_usb_base[port] + 0x08));
		atomic_csr_clrbits(0xffffffff, 
				(void *)(ahbc_base + AHBC_TOP_REG_BASE_OFFSET + 
				 ahbc_usb_base[port] + 0x04));
	} else {
		apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x08, reg_val);
		apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x04, 0x00);
	}
#else
	apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x08, reg_val);
	apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x04, 0x00);
#endif

	if (port) {
		reg_val = USBH_WORD_IF_WR(1);
		/* configure USBHOST_CFG register */
		apm86xxx_ahbc_set_reg(ahbc_usb_hostcfg_base[port], reg_val);
	}

	/* usb_tune 0x01b9c262 */
	reg_val = USB0_TXVREFTUNE_WR(0xD) |
			USB0_TXFSLSTUNE_WR(0xC) |
			USB0_TXPREEMPHASISTUNE_WR(3) |
			USB0_TXRISETUNE_WR(1) |
			USB0_TXHSXVTUNE_WR(0) |
			USB0_COMPDISTUNE_WR(2) |
			USB0_SQRXTUNE_WR(6) |
			USB0_OTGTUNE_WR(2);
	/* configure USB_TUNE register */
#ifdef CONFIG_APM86xxx_SHMEM
	if (port == 0 && !apm86xxx_is_dp_mode())
		atomic_csr_clrsetbits(~reg_val, reg_val, 
			(void *)(ahbc_base + AHBC_TOP_REG_BASE_OFFSET + 
				 ahbc_usb_base[port]));
	else
		apm86xxx_ahbc_set_reg(ahbc_usb_base[port], reg_val);
#else
	apm86xxx_ahbc_set_reg(ahbc_usb_base[port], reg_val);
#endif

	if (port == 0 && !once_done) {
		apm86xxx_read_mpa_reg(MPA_DIAG_ADDR, &reg_val);
		reg_val |= MPA_USB0_CTL_SEL_MASK;
		apm86xxx_write_mpa_reg(MPA_DIAG_ADDR, reg_val);

		/* Put USB Port in reset */
		reg_val = USB0_PORTRESET_WR(1) | USB0_POR_WR(1);
		apm86xxx_write_mpa_reg(MPA_USB0_RSTCTL_ADDR, reg_val);

		/* Set clock */
		/* Bring USB Port out of reset */
		reg_val = USB0_REFCLKDIV_WR(2);
		apm86xxx_write_mpa_reg(MPA_USB0_CLKCTL_ADDR, reg_val);
		udelay(100);
		apm86xxx_write_mpa_reg(MPA_USB0_RSTCTL_ADDR, 0);
		
		/* usb_tune 0x01b9c262 */
		reg_val = USB0_TXVREFTUNE_WR(0xD) |
			USB0_TXFSLSTUNE_WR(0xC) |
			USB0_TXPREEMPHASISTUNE_WR(3) |
			USB0_TXRISETUNE_WR(1) |
			USB0_TXHSXVTUNE_WR(0) |
			USB0_COMPDISTUNE_WR(2) |
			USB0_SQRXTUNE_WR(6) |
			USB0_OTGTUNE_WR(2);
		apm86xxx_write_mpa_reg(MPA_USB0_TUNE_ADDR, reg_val);
		once_done = 1;	
	}

	if (port == 0) {
		/* AHBC USB_OTG is reset & enabled,
		 * so now reset & enable actual port */
		if (ahbc_usb_enable[0]) {
			port = ahbc_usb_enable[0];
			goto _ahbc_usb_enable_start;
		}
	}

	/* Tune the SoF timing to match 125us for USB Host1 and host 2 */
	if (port == 1 || port == 2) {
		if (port == 1)
			reg_val = apm86xxx_ahbc_get_reg(USBHOST_CFG_ADDR);
		else		
			reg_val = apm86xxx_ahbc_get_reg(USBHOST1_CFG_ADDR);
		reg_val &= ~0x1F8;
		reg_val |= 37 << 3;
		if (port == 1)
			apm86xxx_ahbc_set_reg(USBHOST_CFG_ADDR, reg_val);
		else		
			apm86xxx_ahbc_set_reg(USBHOST1_CFG_ADDR, reg_val);
	}

	/* Mark AHBC USB[port] flag to avoid it from reset & re-enable */
	ahbc_usb_enable[port] = 1;
}

void apm86xxx_ahbc_usb_disable(int port)
{
	/* Put USB Port in reset */
	apm86xxx_ahbc_set_reg(ahbc_usb_base[port] + 0x04, 
				USB0_PORTRESET_WR(1) | USB0_POR_WR(1));
}

int apm86xxx_usb_clk_enable(int port)
{
	struct clk *clk;
	char devname[8];

	if (ahbc_usb_clk_enable[port])
		return 0;

	snprintf(devname, sizeof(devname), "usb%d", port);
	clk = clk_get(NULL, devname);

	if (IS_ERR(clk)) {
		printk("Error in enabling USB %d clock\n", port);
		return -1;
	}

	clk_enable(clk);
	apm86xxx_ahbc_usb_enable(port);
	udelay(1000);
	ahbc_usb_clk_enable[port] = 1;

	return 0;
}
#endif

static void __iomem *apm86xxx_ahbc_of_iomap(struct device_node *from)
{
	const u32 *node_val;
	u32 __iomem *ahbc_reg = NULL;
	u64 csr_base;
	u32 csr_size;
	int len;
	struct device_node *np_ahbc = NULL;

	/* Get AHBC address */
	np_ahbc = of_find_compatible_node(from, NULL, "apm,apm86xxx-ahbc");
	if (!np_ahbc) {
		printk(KERN_ERR "no AHBC bridge entry in DTS\n");
		goto _return;
	}

	node_val = of_get_property(np_ahbc, "reg", &len);
	csr_base = ((u64) node_val[0]) << 32 | node_val[1];
	csr_size = node_val[2];
	ahbc_reg = ioremap(csr_base, csr_size);

	if (ahbc_reg == NULL)
		printk(KERN_ERR "unable to map AHBC register\n");

	if (np_ahbc)
		of_node_put(np_ahbc);

_return:
	return ahbc_reg;
}

#ifdef CONFIG_PM
static u32 ahb_in_map[35];
static u32 pm_ahbc_ufc_csr[47]; /* Saved PM register for deep sleep */
static u32 pm_ahbc_ufc_save_reg[47] = {
#if !defined(CONFIG_APM862xx)
	UFC_SRAM_BANK0_START,
	UFC_SRAM_BANK0_END,
	UFC_SRAM_BANK1_START,
	UFC_SRAM_BANK1_END,
	UFC_SRAM_BANK2_START,
	UFC_SRAM_BANK2_END,
	UFC_SRAM_BANK3_START,
	UFC_SRAM_BANK3_END,
	UFC_SRAM_BANK4_START,
	UFC_SRAM_BANK4_END,
	UFC_SRAM_BANK5_START,
	UFC_SRAM_BANK5_END,
#endif
	UFC_SRAM_BANKCFG_0,
	UFC_SRAM_BANKCFG_1,
	UFC_SRAM_BANKCFG_2,
	UFC_SRAM_BANKCFG_3,
#if !defined(CONFIG_APM862xx)
	UFC_SRAM_BANKCFG_4,
	UFC_SRAM_BANKCFG_5,
#endif
	UFC_SRAM_CFG_0,
	UFC_SRAM_CFG_1,
	UFC_SRAM_CFG_2,
	UFC_SRAM_CFG_3,
#if !defined(CONFIG_APM862xx)
	UFC_SRAM_CFG_4,
	UFC_SRAM_CFG_5,
#endif
	UFC_SRAM_CTRL1_0,
	UFC_SRAM_CTRL1_1,
	UFC_SRAM_CTRL1_2,
	UFC_SRAM_CTRL1_3,
#if !defined(CONFIG_APM862xx)
	UFC_SRAM_CTRL1_4,
	UFC_SRAM_CTRL1_5,
#endif
	UFC_SRAM_CTRL2_0,
	UFC_SRAM_CTRL2_1,
	UFC_SRAM_CTRL2_2,
	UFC_SRAM_CTRL2_3,
#if !defined(CONFIG_APM862xx)
	UFC_SRAM_CTRL2_4,
	UFC_SRAM_CTRL2_5,
#endif
	UFC_NFLASH_CTRL3,
	UFC_BYTE_CTRL(0),
	UFC_BYTE_CTRL(1),
	UFC_BYTE_CTRL(2),
	UFC_BYTE_CTRL(3),
#if !defined(CONFIG_APM862xx)
	UFC_BYTE_CTRL(4),
	UFC_BYTE_CTRL(5),
#endif
	UFC_SRAM_CS,
	UFC_FLAG,
	UFC_SRAM_BOOT_CFG,
	0 /* terminator */
};

static int ahb_suspend(void)
{
	int i;

	if (ahbc_base == NULL || !suspending_to_deepsleep())
		return 0;

	/* Save all AHBC Address inbound translation registers */
	for (i = 0; i < sizeof(ahb_in_map)/sizeof(u32); i++)
		ahb_in_map[i] = apm86xxx_ahbc_get_reg(AIM_0_AHB_ADDR + i * 4);

#if !defined(CONFIG_APM867xx)
	/* Clear ahbc_usb_enable flag so that of_driver resume will enable
	 * AHBC USB[port] clocks
	 */
	for (i = 0; i < sizeof(ahbc_usb_enable)/sizeof(u32); i++)
		ahbc_usb_enable[i] = 0;
#endif

	/* Let use save the AHBC and NOR flash registers.  */
	apm86xxx_read_scu_reg(SCU_NFBOOT0_ADDR, &nfboot0);
	for (i = 0; pm_ahbc_ufc_save_reg[i] != 0; i++)
		pm_ahbc_ufc_csr[i] = in_le32((void *) ufc_base + pm_ahbc_ufc_save_reg[i]);

	return 0;
}

static void ahb_resume(void)
{
	int i;

	if (ahbc_base == NULL || !resumed_from_deepsleep())
		return;

	for (i = 0; i < sizeof(ahb_in_map)/sizeof(u32); i++)
		apm86xxx_ahbc_set_reg(AIM_0_AHB_ADDR + i * 4, ahb_in_map[i]);

	/* Let use restore the AHBC and NOR flash registers.  */
	apm86xxx_write_scu_reg(SCU_NFBOOT0_ADDR, nfboot0);
	for (i = 0; pm_ahbc_ufc_save_reg[i] != 0; i++) {
		out_le32((void *) ufc_base + pm_ahbc_ufc_save_reg[i],
				pm_ahbc_ufc_csr[i]);
	}
	__asm__ volatile ("sync");
	return;
}

static struct syscore_ops ahb_pm_syscore_ops = {
	.suspend = ahb_suspend,
	.resume = ahb_resume,
};

static int ahb_pm_init_sys(void)
{
	register_syscore_ops(&ahb_pm_syscore_ops);

	return 0;
}
device_initcall(ahb_pm_init_sys);
#endif

static int __init apm86xxx_ahb_probe(void)
{
	struct device_node *ahb_node;
	u32 soc_freq;
	u32 reg;
	u32 reg_old;

	/* Out of boot-mode to access NOR/NAND */
	apm86xxx_read_scu_reg(SCU_NFBOOT0_ADDR, &nfboot0);
	if ((nfboot0 & 0xC0000000) != 0x0) {
		nfboot0 &= ~0xc0000000;
		apm86xxx_write_scu_reg(SCU_NFBOOT0_ADDR, nfboot0);
	}

	ahb_node = of_find_node_by_type(NULL, "ahb");
	if (ahb_node == NULL) {
		printk(KERN_ERR "Unable to located the AHB node\n");
		return -ENODEV;
	}
	ahbc_base = (u8 *) apm86xxx_ahbc_of_iomap(ahb_node);
	if (ahbc_base == NULL) {
		printk(KERN_ERR "Cannot map AHB registers\n");
		return -ENODEV;
	}

	ufc_base = of_iomap(ahb_node, 0);

#if !defined(CONFIG_NOT_COHERENT_CACHE) || defined(CONFIG_APM86xxx_IOCOHERENT)
	/**
	 * Set AIM windows for 4GB regardless of DDR size
	 * Need 1 windows for this operation
	 */
	printk(KERN_INFO "Setup coherent AIM windows\n");		
	if (apm86xxx_ahbc_get_reg(AIM_8_SIZE_CTL_ADDR) != 0)
		apm86xxx_ahbc_set_reg(AIM_8_SIZE_CTL_ADDR, 0);
	if (apm86xxx_ahbc_get_reg(AIM_8_AXI_LO_ADDR) != 0x00900000)
		apm86xxx_ahbc_set_reg(AIM_8_AXI_LO_ADDR, 0x00900000);
	if (apm86xxx_ahbc_get_reg(AIM_8_AXI_HI_ADDR) != 0)
		apm86xxx_ahbc_set_reg(AIM_8_AXI_HI_ADDR, 0);
#endif

	/* Let's scale up the clock as required. We do this again in case
           boot loader does not do this step and we want to do this as 
           early as possible. */
	__apm86xxx_get_freq(APM86xxx_SOC_PLL_FREQ, &soc_freq);	
	if (soc_freq == 500000000) {	
		/* Scale up AXI to 250MHz and AHB to 100MHz */
                apm86xxx_read_scu_reg(SCU_SOCDIV_ADDR, &reg_old);
		reg = reg_old;
		reg = IO_AXI_CLK_FREQ_SEL_SET(reg, soc_freq / 250000000);	
                reg = AHB_CLK_FREQ_SEL_SET(reg, soc_freq / 100000000);
#if defined(CONFIG_APM862xx)
		reg = APB_CLK_FREQ_SEL_SET(reg, soc_freq / 100000000);
#endif
		if (reg != reg_old) {
			printk(KERN_INFO "Scaling AXI/AHB/APB frequency\n");
			apm86xxx_write_scu_reg(SCU_SOCDIV_ADDR, reg);
		}
		/* Scale up SlimPRO to 250MHz and SlimPRO trace to 250MHz */
		apm86xxx_read_scu_reg(SCU_SOCDIV2_ADDR, &reg_old);
		reg = reg_old;
		reg = SEC_CRYPTO_FREQ_SEL2_SET(reg, soc_freq / 250000000);
		reg = ARM_TRCLKIN_FREQ_SEL2_SET(reg, 3);
		reg = MPA_AHB_CLK_FREQ_SEL2_SET(reg, soc_freq / 250000000);
		if (reg != reg_old) {
			printk(KERN_INFO "Scaling SlimPRO/Crypto frequency\n");
			apm86xxx_write_scu_reg(SCU_SOCDIV2_ADDR, reg);
		}
		/* Scale up EBUS 62MHz */
		apm86xxx_read_scu_reg(SCU_SOCDIV5_ADDR, &reg_old);
		reg = reg_old;
		reg = EBUS_CLK_FREQ_SEL5_SET(reg, 8);
		if (reg != reg_old) {
			printk(KERN_INFO "Scaling EBUS frequency\n");
	                apm86xxx_write_scu_reg(SCU_SOCDIV5_ADDR, reg);
		}
#if !defined(CONFIG_APM862xx)
		/* Scale up APB to 100 */
		#define ENABLE_INTF 0x90	/* Offset to AHBC ENABLE_INTF */
		#define APB_CLK_FREQ_SEL_SET(dst,src) \
			(((dst) & ~0xC0000000) | (((u32)(src)<<30) & 0xC0000000))
		reg_old = apm86xxx_ahbc_get_reg(ENABLE_INTF);
		reg = reg_old;
		reg = APB_CLK_FREQ_SEL_SET(reg, 1);
		if (reg != reg_old) { 
			printk(KERN_INFO "Scaling APB frequency\n");
			apm86xxx_ahbc_set_reg(ENABLE_INTF, reg);
		}
#endif
	}

        return 0;
}
arch_initcall(apm86xxx_ahb_probe);

static irqreturn_t apm86xxx_sdu_error_hdlr(int irq, void *dev)
{
	int i;	
	u32 sdu_sts;
	u32 val;
	
	static char *sdu_err_msg[] = {
		"Memory queue parity error",
		"SATA port 0/1 partiy error",
		"PCIe port 0 parity error",
		"PCIe port 1 parity error",
		"PCIe port 2 parity error",
		"iPP parity error",
		"Ethernet parity error",
		"Classifier parity error",
		"OCM parity error",
		"Security parity error",
		"LCD controller parity error",
		"AHBC parity error",
		"QM ECC error",
		"USB DFS error",
		"USB EBM error",
		"Ethernet PCF error",
		NULL
	};
		
	static char *ahbc_err_msg[] = {
		"USB0 read slave error",
		"USB0 read decoder error",
		"USB0 write slave error",
		"USB0 write decoder error",
		"USB1 read slave error",
		"USB1 read decoder error",
		"USB1 write slave error",
		"USB1 write decoder error",
		"SDHC read slave error",
		"SDHC read decoder error",
		"SDHC write slave error",
		"SDHC write decoder error",
		"USB Host0 read slave error",
		"USB Host0 read decoder error",
		"USB Host0 write slave error",
		"USB Host0 write decoder error",
		"TDM read slave error",
		"TDM read decoder error",
		"TDM write slave error",
		"TDM write decoder error",
		"USB Host1 read slave error",
		"USB Host1 read decoder error",
		"USB Host1 write slave error",
		"USB Host1 write decoder error",
		"USB Host2 read slave error",
		"USB Host2 read decoder error",
		"USB Host2 write slave error",
		"USB Host2 write decoder error",
		NULL
	};
		
	/* Check for error */
	sdu_sts = apm86xxx_sdu_get_reg(SDU_ERR_STS_ADDR);
	if (sdu_sts & ECC_ERR_MASK) {
		/* ECC error */				
		printk(KERN_ERR "ECC error (0x%08X)\n", sdu_sts); 
		/* Check for module with ECC/parity error */
		val = apm86xxx_sdu_get_reg(SDU_PERR_ADDR);
		for (i = 0; sdu_err_msg[i] != NULL; i++)
			if (val & (1 << i))
				panic("%s PERR 0x%08X\n", sdu_err_msg[i], val);	
	}
	if (sdu_sts & AXI_DERR_MASK) {
		/* HBF decoder error */		
		printk(KERN_ERR "HBF decoder error (0x%08X)\n", sdu_sts);
		/* Check for decoder error */
		for (i = 0; i < 3; i++) {
			val = apm86xxx_sdu_get_reg(SDU_SLV0_STS_ADDR + i * 8);
			if (val & WRDECERR_MASK) {
				u32 err_addr;
				err_addr  = apm86xxx_sdu_get_reg( 
						SDU_SLV0_ADDR_STS_ADDR + 
						i * 8 + 4);
				/* Decoder error for write */
				printk(KERN_ERR 
					"HBF (AXI) slave %d decoder write "
					"error (0x%08X) at "
					"0x{%08X, b0000|b00000}\n", 
					i, val, err_addr);
			}
		}	
	}
	if (sdu_sts & BRG_ERR_MASK) {
		/* HBF decoder error */		
		printk(KERN_ERR "Bridges error (0x%08X)\n", sdu_sts);
		/* Check for bridges error */
		val = apm86xxx_sdu_get_reg(SDU_BRG_ERR_ADDR);
		if (val & AHBBRGERR_MASK) {
			/* AHBC error */
			val = apm86xxx_ahbc_get_reg(AHBC_INTERRUPT_ADDR);			
			for (i = 0; ahbc_err_msg[i] != NULL; i++)
				if (val & (1 << i))
					printk(KERN_ERR "%s (0x%08X)\n", 
						ahbc_err_msg[i], val);	
		}
		if (val & PLBBRGERR_MASK) {
			/* An unsupported request is sent from PLB to HBF 
			   (AXI) bridge */
			printk(KERN_ERR 
				"PLB to HBF (AXI) bridge error (0x%08X)\n",
				val);							
		}
		if (val & WRERRACK_MASK) {
			/* An unsupported request is sent from HBF to PLB
			   bridge */
			printk(KERN_ERR 
				"HBF (AXI) to PLB brdige error (0x%08X)\n", 
				val);
		}
	}
	if (sdu_sts & PLB5_WERR_MASK) {
		/* PLB5 write ECC error */		 
		u32 ecc_addr0;
		u32 ecc_addr1;
		ecc_addr0 = apm86xxx_sdu_get_reg(SDU_PLB_WERRL_ADDR);
		ecc_addr1 = apm86xxx_sdu_get_reg(SDU_PLB_WERRH_ADDR);
		/* PLB to AXI ECC error */
		printk(KERN_ERR "PLB5 to HBF (AXI) ECC write error CPU%d " 
			"len %d at 0x%02X_%08X (0x%08X)\n", 
			CPUID_RD(ecc_addr1), WR_LEN_RD(ecc_addr1),
			ADDR_HIGH_RD(ecc_addr1), ecc_addr0, sdu_sts);
	}
	
        return IRQ_HANDLED;
}

static int __init apm86xxx_sdu_probe(void)
{
        struct device_node *np_sdu  = NULL;
        const u32 *node_val;
        int irq = NO_IRQ;
        u64 csr_base;
	u32 csr_size;
        int len;
	u32 val;

	sdu_base = NULL;
	
        np_sdu = of_find_compatible_node(NULL, NULL, "apm,apm86xxx-sdu");
        if (!np_sdu) {
                printk(KERN_ERR "no apm-sdu entry in DTS\n");                	
                goto err;
        }

        /* Map DCRs */
        node_val = of_get_property(np_sdu, "reg", &len);
        csr_base = ((u64) node_val[0]) << 32 | node_val[1];
	if (len > 12)	/* 2 WORD size cell */
	        csr_size = node_val[3];
	else		/* 1 WORD size cell */
	        csr_size = node_val[2];
        sdu_base = ioremap(csr_base, csr_size);
        if (sdu_base == NULL) {
                printk(KERN_ERR "unable to map SDU register\n");
                goto err;
        }
        
        /* Get and map irq number from device tree */
        irq = irq_of_parse_and_map(np_sdu, 0);
        if (irq == NO_IRQ) {
                printk(KERN_ERR "no IRQ entry for apm-sdu\n");
                goto err;
        }

        /* Get AHBC address */
        if (!ahbc_base && !(ahbc_base = (u8 *)apm86xxx_ahbc_of_iomap(NULL))) {
                printk(KERN_ERR "unable to map AHBC register\n");
                goto err;
        }              
 
        /* Enable all AHBC error interrupt */
	apm86xxx_ahbc_set_reg(AHBC_INTERRUPTMASK_ADDR, 0x00000000);
        
	of_node_put(np_sdu);	

	/* Clear AHBC unexpected interrupts which cause bridge error when hard reset */
        val = apm86xxx_ahbc_get_reg(AHBC_INTERRUPT_ADDR);
        if (val)
                printk(KERN_INFO "Clear AHBC unexpected interrupts 0x%08X\n",
			val);

        /* Install error handler */
        if (request_irq(irq, apm86xxx_sdu_error_hdlr, IRQF_DISABLED, "sdu", 
        		0) < 0) {
                printk(KERN_ERR "Cannot install SDU error handler\n");
                goto err;
        }
	return 0;

err:
	if (irq != NO_IRQ)
		free_irq(irq, 0);
	if (sdu_base) {
		iounmap(sdu_base);
		sdu_base = NULL;	
	}
	if (np_sdu)
		of_node_put(np_sdu);	
        return -ENODEV;        
}
arch_initcall(apm86xxx_sdu_probe);

/*
 * At present, this routine just applies a system reset.
 */

#if defined(CONFIG_SMP)
extern void mpic_assertcore(unsigned int corenr);
#endif

static inline const char *reset_type_name(u32 reset_type)
{
	switch(reset_type) {
	case DBCR0_RST_CORE:   return "Core Reset";
	case DBCR0_RST_CHIP:   return "Chip Reset";
	case DBCR0_RST_SYSTEM: return "System Reset";
	default:
		BUG();
	}
}

static inline void reset_type_cmd_verify(char * cmd, u32 * reset_type)
{
	if (!cmd)
		return;
	else if (strcmp(cmd,"core") == 0)
		*reset_type = DBCR0_RST_CORE;
	else if (strcmp(cmd,"chip") == 0)
		*reset_type = DBCR0_RST_CHIP;
	else if (strcmp(cmd,"system") == 0)
		*reset_type = DBCR0_RST_SYSTEM;
}


#ifndef CONFIG_SMP
/* assume all CPU are enabled by default */
static unsigned int cpu_enabled_mask = 0xFF;

unsigned int cpu_enabled(unsigned int cpu)
{
	unsigned int cpu_mask = 1 << cpu;

	return (cpu_enabled_mask & cpu_mask);
}
EXPORT_SYMBOL(cpu_enabled);

static int __init cpu_late_config(void)
{
	unsigned int cpu;
	unsigned int cpu_mask;
	struct device_node *np;
	const u32 *reg;
	const char *status;
	int len;

	for_each_node_by_type(np, "cpu") {
		reg = of_get_property(np, "reg", NULL);
		if (reg == NULL)
			continue;

		cpu = *reg;

		status = of_get_property(np, "status", &len);
		if (status && strncmp(status,"disable",7) == 0) {
			cpu_mask = 1 << cpu;
			cpu_enabled_mask &= ~cpu_mask;
		}
	}

	return 0;
}

arch_initcall(cpu_late_config);

#endif

#ifdef CONFIG_APM867xx
/* r/w to mosys csr (indirect), takes data directly, not pointer */
static int mosys_wr_op(void * addr, u32 offset, u32 data)
{
        int rc = 0;
        u32 pcs_wr_done;

        out_be32((void *) (addr + X1_PCSCSR_REGADDR_ADDR), offset);
        out_be32((void *) (addr + X1_PCSCSR_REGWRDATA_ADDR), data);
        out_be32((void *) (addr + X1_PCSCSR_REGCMD_ADDR),
                        X1_MGMT_PCS_REG_WR_F2_MASK);
        pcs_wr_done  = 0;
        while (pcs_wr_done != 0x2) {
                pcs_wr_done = in_be32((void *) (addr +
                                        X1_PCSCSR_REGCMDDONE_ADDR));
                pcs_wr_done &= X1_MGMT_PCS_REG_WR_DONE_F2_MASK;
        }

        return rc;
}

static int mosys_rd(void * addr, u32 offset, u32 *pdata)
{
        int rc = 0;
        u32 pcs_rd_done;

        out_be32((void *) (addr + X1_PCSCSR_REGADDR_ADDR),
                        offset);
        out_be32((void *) (addr + X1_PCSCSR_REGCMD_ADDR),
                        X1_MGMT_PCS_REG_RD_F2_MASK);
        pcs_rd_done  = 0;

        while (pcs_rd_done != 0x1) {
                pcs_rd_done = in_be32((void *)
                                (addr + X1_PCSCSR_REGCMDDONE_ADDR));
                pcs_rd_done &= X1_MGMT_PCS_REG_RD_DONE_F2_MASK;
        }

        *pdata = in_be32((void *) (addr +
                                X1_PCSCSR_REGRDDATA_ADDR));
        return rc;
}

static void apm_enable_sgmii0_internal_clock(void)
{
	u32 reg, setval;

	printk("enter %s\n", __FUNCTION__);

	/* generate 1000MHz */
	apm86xxx_read_scu_reg(0xf0, &reg);
	setval = 0x00080013;
	printk(KERN_DEBUG "SCU_SOCPLL4 current val:0x%x 	new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0xf0, setval);

	apm86xxx_read_scu_reg(0xc4, &reg);
	/* PCIE_CLK_FREQ_SEL divided by 10: 0x000a0207 */
	setval = 0x000a0207; //1000MHz / 10 = 100MHz to SerDes
	printk(KERN_DEBUG "SCU_SOCDIV1 current val:0x%x new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0xc4, setval);

	apm86xxx_read_scu_reg(0xcc, &reg);
	/* SOC_TRC_MUX_SEL2 [14]:0 -- PCIE_PLL Drives PCIe 2 SERDES */
	setval = reg & 0xfffdffff;
	/* PCIE_PLL_REFCLK_SEL=1: selects XTAL_CORE_OSC as reference clk */
	setval |= 0x00001000;
	printk(KERN_DEBUG "SCU_SOCDIV3 current val:0x%x, new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0xcc, setval);
}

static void apm_enable_sgmii1_internal_clock(void)
{
	u32 reg, setval;

	printk("enter %s\n", __FUNCTION__);

	/* generate 1000MHz */
	apm86xxx_read_scu_reg(0x120, &reg);
	setval = 0x00080027;
	printk(KERN_DEBUG "SCU_SOCPLL5 current val:0x%x 	new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0x120, setval);

	apm86xxx_read_scu_reg(0xd4, &reg);
	/* SOC_SATA_CLK_FREQ_SEL div by 10:0x00005000 */
	setval = reg | 0x00005000;
	printk(KERN_DEBUG "SCU_SOCDIV5 current val:0x%x new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0xd4, setval);

	apm86xxx_read_scu_reg(0xcc, &reg);
	/* SOC_TRC_MUX_SEL3 [0]:0 -- SATA_PLL Drives STAT SerDes Ref clock */
	setval = reg & 0x7fffffff;
	/* SATA_PLL_REFCLK_SEL [18]:1 selects XTAL_CORE_OSC as reference clk */
	setval |= 0x00002000;
	printk(KERN_DEBUG "SCU_SOCDIV3 current val:0x%x, new:0x%x\n", reg, setval);
	apm86xxx_write_scu_reg(0xcc, setval);
}

/*
 * Below functions are used to convert the pcie and sata to 
 * two additional SGMII ethernet ports
 */
static int apm_enet_pcie2tosgmii0(int enable_sgmii_internal_clk)
{
	u32 reg, val, timeout=0;
	void *regaddr;

	printk(KERN_DEBUG "SGMII-Port0/1 Global Configuration Start\n");

	printk(KERN_DEBUG "\nRelease Reset for PCIe2/ENET2\n");
	// Release Reset for PCIE1/PCIE2/PCIE3
	apm86xxx_read_scu_reg(SCU_SRST_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x val:0x%08x\n",reg,val);
	/*
	 * Lets just release reset for PCIE2/and ENET2 for now
	 */
	reg = reg & 0xffddffff;  // PCIE2/ENET2
	apm86xxx_write_scu_reg(SCU_SRST_ADDR, reg);

	printk(KERN_DEBUG "\nClock Enable for PCIe2/ENET2\n");
	apm86xxx_read_scu_reg(SCU_CLKEN_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x val:0x%08x\n",reg,val);
	reg = reg | 0x00220000; // PCIE2/ENET2
	apm86xxx_write_scu_reg(SCU_CLKEN_ADDR, reg);

	printk(KERN_DEBUG "\nRelease Reset for PCIe-1/PCIe-2 CSR\n");
	apm86xxx_read_scu_reg(SCU_CSR_SRST_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x val:0x%08x\n",reg,val);
	reg = reg & 0xffddffff; // PCIE1/PCIE2/PCIE3/SATA0/SATA1/ENET2
	apm86xxx_write_scu_reg(SCU_CSR_SRST_ADDR, reg);

	/*
	 * Config SGMII-1 Config for ENET-Port-2
	 */
	printk(KERN_DEBUG "\nSGMII-Port0 SERDES Config\n");
	regaddr = ioremap_nocache(0xddd894000ULL, 0x1000);
	reg = in_be32(regaddr);
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x exp:0x00800000\n",(u32)regaddr,reg);
	reg = 0x7e9f102a;
	out_be32(regaddr, reg);

	// SERDES_CSR_CTL1
	reg = in_be32((void *)(regaddr + 4));
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x exp:0x00800000\n",(u32)regaddr, reg);
	reg = 0x00811499;
	out_be32((void *)(regaddr + 4), reg);

	// SERDES_CSR_CTL0
	reg = in_be32(regaddr);
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x\n",(u32)regaddr,reg);
	reg = 0x7e9f100a;
	out_be32(regaddr, reg);

	if(enable_sgmii_internal_clk) {
		udelay(20);
		apm_enable_sgmii0_internal_clock();
		reg = 0x7e9f104a;
		printk(KERN_DEBUG "%s %d reg:0x%08x val:0x%08x\n",__FUNCTION__, __LINE__, (u32)regaddr,reg);
		out_be32(regaddr, reg);
		udelay(20);
	}

	reg = in_be32((void *)(regaddr + 0x2c));
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x exp:0x00800000\n",(u32)regaddr,reg);
	reg = 0;
	out_be32((void *)(regaddr + 0x2c), reg);

	reg = in_be32((void *)(regaddr + 0x30));
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x exp:0x00800000\n",(u32)regaddr,reg);
	reg = 0;
	out_be32((void *)(regaddr + 0x30), reg);

	reg = in_be32((void *)(regaddr + 0x8));
	printk(KERN_DEBUG "reg:0x%08x val:0x%08x exp:0xc0f\n",(u32)regaddr,reg);

	timeout=1000;
	/* Poll PLL-Lock Ready */
	while (timeout > 0) {
		timeout --;
		reg = in_be32((void *)(regaddr + 0x8));
		if (reg & 0x00000C00) // sds_pcs_pll_lock/sds_pcs_clock_ready
		    break;
		udelay(100); /* FIXME - need to fine tune */
		if(timeout == 0) {
		    printk(KERN_DEBUG "FAIL PLL LOCK & PLL_CLK_READY SGMII-Port0\n");
		    return -1;
		}
	}
	printk(KERN_DEBUG "PLL LOCK & PLL_CLK_READY done SGMII-Port0 %x\n", reg);

	printk(KERN_DEBUG "\nConfigure Mosys SERDES for PreEmphasis/Power SGMII-Port0\n");
	/* Configure Mosys Serdes */
	mosys_wr_op(regaddr, 0x5800D, 0x206F /*0x205F*/);
	mosys_rd(regaddr, 0x5800d, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5800d, val);

	mosys_wr_op(regaddr, 0x58010, 0x6070);
	mosys_rd(regaddr, 0x58010, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x58010, val);

	mosys_wr_op(regaddr, 0x5C000, 0x585B);
	mosys_rd(regaddr, 0x5c000, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c000, val);

	mosys_wr_op(regaddr, 0x5C004, 0x1);
	mosys_rd(regaddr, 0x5c004, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c004, val);

	/* Configure Mosys Serdes */
	mosys_wr_op(regaddr, 0x5C065, 0);
	mosys_rd(regaddr, 0x5c065, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c065, val);

	mosys_wr_op(regaddr, 0x5C005, 6);
	udelay(100);
	mosys_rd(regaddr, 0x5c005, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c005, val);

	mosys_wr_op(regaddr, 0x5C005, 4);
	udelay(100);
	mosys_rd(regaddr, 0x5c005, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c005, val);

	printk(KERN_DEBUG "Mosys SERDES init Done SGMII-Port0\n");

	iounmap(regaddr);

	return 0;
}

static int apm_enet_sata0tosgmii1(int enable_sgmii_internal_clk)
{
	u32 reg, val, timeout;
	void *regaddr;

	printk(KERN_DEBUG "\nRelease Reset for SATA0\n");
	apm86xxx_read_scu_reg(SCU_SRST_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x\n", reg);
	/*
	 * Lets just release reset for SATA0/and ENET3 for now
	 */
	reg = reg & 0xf7ffffff;
	apm86xxx_write_scu_reg(SCU_SRST_ADDR, reg);

	printk(KERN_DEBUG "\nRelease Reset for ENET3\n");
	apm86xxx_read_scu_reg(SCU_SRST1_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x \n", reg);
	/*
	 * Lets just release reset for SATA0/and ENET3 for now
	 */
	reg = reg & 0xfffff7ff;
	apm86xxx_write_scu_reg(SCU_SRST1_ADDR, reg);

	printk(KERN_DEBUG "Clock Enable for SATA0\n");
	apm86xxx_read_scu_reg(SCU_CLKEN_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x \n",reg);
	reg = reg | 0x08000000;
	apm86xxx_write_scu_reg(SCU_CLKEN_ADDR, reg);


	printk(KERN_DEBUG "Clock Enable for ENET3\n");
	apm86xxx_read_scu_reg(SCU_CLKEN1_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x \n",reg);
	reg = reg | 0x00000800;
	apm86xxx_write_scu_reg(SCU_CLKEN1_ADDR, reg);

	printk(KERN_DEBUG "\nRelease Reset for SATA0 CSR\n");
	apm86xxx_read_scu_reg(SCU_CSR_SRST_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x\n",reg);
	reg = reg & 0xf7ffffff;
	apm86xxx_write_scu_reg(SCU_CSR_SRST_ADDR, reg);

	printk(KERN_DEBUG "\nRelease Reset for ENET3 CSR\n");
	apm86xxx_read_scu_reg(SCU_CSR_SRST1_ADDR, &reg);
	printk(KERN_DEBUG "befor reg:0x%08x\n",reg);
	reg = reg & 0xfffff7ff;
	apm86xxx_write_scu_reg(SCU_CSR_SRST1_ADDR, reg);

	printk(KERN_DEBUG "\nRelease Reset for ENET3\n");

	/*
	 * Config SGMII-2 Config for ENET-Port-2
	 */
	printk(KERN_DEBUG "\nSGMII-Port0 SERDES Config\n");
	regaddr = ioremap_nocache(0xddd874000ULL, 0x1000);

	/* SERDES_CSR_CTL0 */
	reg = in_be32(regaddr);
	printk(KERN_DEBUG "reg:0x%08x exp:0x00800000\n",reg);
	reg = 0x7e9f102a;
	out_be32(regaddr, reg);


	/* SERDES_CSR_CTL1 */
	reg = in_be32((void *)(regaddr + 0x4));
	printk(KERN_DEBUG "reg:0x%08x \n",reg);
	reg = 0x00811499;
	out_be32((void *)(regaddr + 0x4), reg);

	/* SERDES_CSR_CTL0 */
	reg = in_be32(regaddr);
	printk(KERN_DEBUG "reg:0x%08x exp:0x00800000\n",reg);
	reg = 0x7e9f100a;
	out_be32(regaddr, reg);

	if(enable_sgmii_internal_clk) {
		udelay(20);
		apm_enable_sgmii1_internal_clock();
		reg = 0x7e9f104a;
		out_be32(regaddr, reg);
		udelay(20);
	}
	reg = in_be32((void *)(regaddr + 0x2c));
	printk(KERN_DEBUG "reg:0x%08x exp:0x00800000\n",reg);
	reg = 0;
	out_be32((void *)(regaddr + 0x2c), reg);

	reg = in_be32((void *)(regaddr + 0x30));
	printk(KERN_DEBUG "reg:0x%08x exp:0x00800000\n",reg);
	reg = 0;
	out_be32((void *)(regaddr + 0x30), reg);

	reg = in_be32((void *)(regaddr + 0x8));
	printk(KERN_DEBUG "reg:0x%08x exp:0xc0f\n",reg);

	timeout=1000;
	/* Poll PLL-Lock Ready */
	while (timeout > 0) {
		timeout --;
		reg = in_be32((void *)(regaddr + 0x8));
		reg = reg & 0x00000C00; // sds_pcs_pll_lock/sds_pcs_clock_ready
		if (reg == 0x00000C00)
		    break;
		udelay(100); /* FIXME - need to fine tune */
		if(timeout == 0) {
		    printk(KERN_DEBUG "FAIL PLL LOCK & PLL_CLK_READY SGMII-Port0\n");
		    return -1;
		}
	}
	printk(KERN_DEBUG "PLL LOCK & PLL_CLK_READY done SGMII-Port1\n");

	printk(KERN_DEBUG "\nConfigure Mosys SERDES for PreEmphasis/Power for SGMII-Port1\n");
	/* Configure Mosys Serdes */
	reg = 0x84070000;
	mosys_wr_op(regaddr, 0x5800D, 0x206F /*0x205F*/);
	mosys_rd(regaddr, 0x5800d, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5800d, val);

	mosys_wr_op(regaddr, 0x58010, 0x6070);
	mosys_rd(regaddr, 0x58010, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x58010, val);

	mosys_wr_op(regaddr, 0x5C000, 0x585B);
	mosys_rd(regaddr, 0x5c000, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c000, val);

	mosys_wr_op(regaddr, 0x5C004, 0x1);
	mosys_rd(regaddr, 0x5c004, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c004, val);

	/* Configure Mosys Serdes */
	mosys_wr_op(regaddr, 0x5C065, 0);
	mosys_rd(regaddr, 0x5c065, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c065, val);

	mosys_wr_op(regaddr, 0x5C005, 6);
	udelay(100);
	mosys_rd(regaddr, 0x5c005, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c005, val);

	mosys_wr_op(regaddr, 0x5C005, 4);
	udelay(100);
	mosys_rd(regaddr, 0x5c005, &val);
	printk(KERN_DEBUG "MOSYS: RD[0x%08x]: off[0x%08x] val: 0x%08x \n",reg,0x5c005, val);

	printk(KERN_DEBUG "Mosys SERDES init Done for SGMII-Port1\n");

	iounmap(regaddr);

	return 0;
}

void apm_enet_serdes_init(u32 port, int enable_sgmii_internal_clk)
{
        if (port == 2)
                apm_enet_pcie2tosgmii0(enable_sgmii_internal_clk);
        if (port == 3)
                apm_enet_sata0tosgmii1(enable_sgmii_internal_clk);
}
#elif defined(CONFIG_APM866xx) || defined(CONFIG_APM862xxvB)

#if 0
#define SERDES_DEBUG(s, ...)	printk((s), ##__VA_ARGS__)
#else
#define SERDES_DEBUG(s, ...)
#endif

void sgmii_serdes_write(void __iomem *base, u32 off, u32 data) 
{
	void __iomem * reg;
	u32 temp=0;

	reg = base + 0x0010;			/* PCSCSR_REGADDR */
	out_be32(reg, off);    
	udelay(1000); 

	reg = base + 0x0014;			/* PCSCSR_REGWRDATA */
	out_be32(reg, data);    
	udelay(1000); 
    
	reg = base + 0x0018;			/* PCSCSR_REGCMD */
	out_be32(reg, 2); 
	udelay(1000); 

	reg = base + 0x001c;			/* PCSCSR_REGCMDDONE */
	while(1) {
		temp = in_be32(reg);
		if(temp == 2)
			break;
	}

	reg = base + 0x0018;			/* PCSCSR_REGCMD */
	out_be32(reg, 0); 
	udelay(1000);
	SERDES_DEBUG("Write Done off:0x%08x data:0x%08x\n",off,data);
}

void apm_enet_serdes_init(u32 port, int enable_sgmii_internal_clk)
{
	void __iomem *base;
	void __iomem *reg;
	u32 val, timeout=0;

	SERDES_DEBUG("\n");
	SERDES_DEBUG("SGMII-%d: serdes init\n", priv->port);
	base = ioremap_nocache(0xddd8f4000ULL, 0x1000);

	reg = base + 0x0000;			/* PCSCSR_COMMONCTL0 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	val &= 0xF0000000;
	val |= 0x08400270;
	val |= ((0x1 << port) << 28);
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x0004;			/* PCSCSR_COMMONCTL1 */
  	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n",(u32)reg,val);
	val = 0x00113231;
	out_be32(reg, val);
  	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n",(u32)reg,val);

	reg = base + 0x0048;			/* PCSCSR_CTL0 */
	val = in_be32(reg);
	SERDES_DEBUG("Reag: 0x%08x val:0x%08x\n", (u32)reg, val);
	/*val = 0x0F000056;*/ /* For SGMII-2/3 */
	/*val = 0x0F000056;*/ /* For SGMII-1/2/3 */
	val = 0x00000056; /* For SGMII-0/1/2/3 */
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x004c;			/* PCSCSR_CTL1 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	/*val = 0x0F638056;*/ /* For SGMII-2/3 */
	/*val = 0x00638052;*/ /* For SGMII-1/2/3 */
	val = 0x00638052; /* For SGMII-0/1/2/3 */
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x0050;			/* PCSCSR_CTL2 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	val = 0x00000052;
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x0054;			/* PCSCSR_CTL3 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	val = 0x00000052;
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x0000;			/* PCSCSR_COMMONCTL0 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	val &= 0xF0000000;
	val |= 0x08400270;
	val |= ((0x1 << port) << 28);
	out_be32(reg, val);
	val = in_be32(reg);
	SERDES_DEBUG("Write:0x%08x val:0x%08x\n", (u32)reg, val);

	reg = base + 0x000c;			/* PCSCSR_STATUS1 */
	val = in_be32(reg);
	SERDES_DEBUG("Read: 0x%08x val:0x%08x\n", (u32)reg, val);
	timeout=1000;
	while (timeout > 0) {			/* Poll PLL-Lock Ready */
		timeout--;
		val = in_be32(reg);
		val = val & 0x00000C00;		/* pll_lock or clock_ready */
		if (val == 0x00000C00)
			break;
		udelay(100);
		BUG_ON(timeout == 0);
	}
	SERDES_DEBUG("SGMII-%d: PLL LOCK & PLL_CLK_READY done\n", priv->port);

	/* Set the Pre-Emphasys Settings from defalut to 0x4070 */
	sgmii_serdes_write(base, 0x1F8010, 0x4070);
	udelay(1000);

	iounmap(base);

	return;
}

#else

void apm_enet_serdes_init(u32 port, int enable_sgmii_internal_clk)
{
	/* By default dont do anything. */
}
#endif
EXPORT_SYMBOL(apm_enet_serdes_init);
