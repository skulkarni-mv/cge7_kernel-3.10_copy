/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#ifndef _ASM_PCI_H
#define _ASM_PCI_H

#include <linux/mm.h>

#ifdef __KERNEL__

/*
 * This file essentially defines the interface between board
 * specific PCI code and MIPS common PCI code.  Should potentially put
 * into include/asm/pci.h file.
 */

#include <linux/ioport.h>
#include <linux/of.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/string.h>

#include <asm/scatterlist.h>
#include <asm/io.h>
#include <asm-generic/pci-bridge.h>

/* implement the pci_ DMA API in terms of the generic device dma_ one */
#include <asm-generic/pci-dma-compat.h>

#ifndef CONFIG_ARCH_THUNDER_EMULATOR

#define PCIBIOS_MIN_IO		0x1000
#define PCIBIOS_MIN_MEM		0

struct pci_host_bridge *find_pci_host_bridge(struct pci_bus *bus);

/* Arch hooks */
#define arch_msi_check_device arch_msi_check_device
#define arch_setup_msi_irqs arch_setup_msi_irqs
#define arch_teardown_msi_irqs arch_teardown_msi_irqs

/*
 * Set to 1 if the kernel should re-assign all PCI bus numbers
 */
#define pcibios_assign_all_busses() \
	(pci_has_flag(PCI_REASSIGN_ALL_BUS))

/*
 * PCI address space differs from physical memory address space
 */
#define PCI_DMA_BUS_IS_PHYS	(0)

extern int isa_dma_bridge_buggy;

/*
 * These legacy code  ported from arch/arm/kernel/bios32.c. This might break
 * pci on other boards. So compile only for below ARCHs
 */
#if defined(CONFIG_ARCH_FSL_LS1043A) || defined(CONFIG_ARCH_THUNDER) || defined(CONFIG_PCIE_IPROC) || defined(CONFIG_ARCH_MVEBU)

struct pci_sys_data;
struct pci_ops;
struct pci_bus;
struct device;

struct hw_pci {
#ifdef CONFIG_PCI_DOMAINS
	int		domain;
#endif
	struct pci_ops	*ops;
	int		nr_controllers;
	void		**private_data;

	int		(*setup)(int nr, struct pci_sys_data *);
	struct pci_bus *(*scan)(int nr, struct pci_sys_data *);
	void		(*preinit)(void);
	void		(*postinit)(void);
	u8		(*swizzle)(struct pci_dev *dev, u8 *pin);
	int		(*map_irq)(const struct pci_dev *dev, u8 slot, u8 pin);
	resource_size_t (*align_resource)(struct pci_dev *dev,
					  const struct resource *res,
					  resource_size_t start,
					  resource_size_t size,
					  resource_size_t align);
	void		(*add_bus)(struct pci_bus *bus);
	void		(*remove_bus)(struct pci_bus *bus);
};

/*
 * Per-controller structure
 */
struct pci_sys_data {
#ifdef CONFIG_PCI_DOMAINS
	int		domain;
#endif
	struct list_head node;
	int		busnr;	    /* primary bus number		*/
	u64		mem_offset; /* bus->cpu memory mapping offset	*/
	unsigned long	io_offset;  /* bus->cpu IO mapping offset	*/
	struct pci_bus	*bus;	    /* PCI bus				*/
	struct list_head resources; /* root bus resources (apertures)	*/
	struct resource io_res;

	char		io_res_name[12];
				/* Bridge swizzling		*/
	u8		(*swizzle)(struct pci_dev *, u8 *);
				/* IRQ mapping			*/
	int		(*map_irq)(const struct pci_dev *, u8, u8);
				/* Resource alignement requirements	*/
	resource_size_t (*align_resource)(struct pci_dev *dev,
					  const struct resource *res,
					  resource_size_t start,
					  resource_size_t size,
					  resource_size_t align);
	void		(*add_bus)(struct pci_bus *bus);
	void		(*remove_bus)(struct pci_bus *bus);
	void		*private_data;	/* platform controller private data */
};

/*
 * Call this with your hw_pci struct to initialise the PCI system.
 */
void pci_common_init_dev(struct device *, struct hw_pci *);

/*
 * Compatibility wrapper for older platforms that do not care about
 * passing the parent device.
 */
static inline void pci_common_init(struct hw_pci *hw)
{
	pci_common_init_dev(NULL, hw);
}
#endif

#ifdef CONFIG_PCI

#ifdef CONFIG_ACPI
/*
 * ARM64 PCI config space access primitives.
 */
static inline unsigned char mmio_config_readb(void __iomem *pos)
{
	return readb(pos);
}

static inline unsigned short mmio_config_readw(void __iomem *pos)
{
	return readw(pos);
}

static inline unsigned int mmio_config_readl(void __iomem *pos)
{
	return readl(pos);
}

static inline void mmio_config_writeb(void __iomem *pos, u8 val)
{
	writeb(val, pos);
}

static inline void mmio_config_writew(void __iomem *pos, u16 val)
{
	writew(val, pos);
}

static inline void mmio_config_writel(void __iomem *pos, u32 val)
{
	writel(val, pos);
}
#endif  /* CONFIG_ACPI */

static inline int pci_proc_domain(struct pci_bus *bus)
{
	return 1;
}
static inline void pcibios_penalize_isa_irq(int irq, int active)
{
	/* We don't do dynamic PCI IRQ allocation */
}

static inline int pci_get_legacy_ide_irq(struct pci_dev *dev, int channel)
{
	return 0;
}

void set_pcibios_add_device(int (*arg)(struct pci_dev *));
#endif

extern unsigned long pci_ioremap_io(const struct resource *res, phys_addr_t phys_addr);

#else
/*
 * Each pci channel is a top-level PCI bus seem by CPU.  A machine  with
 * multiple PCI channels may have multiple PCI host controllers or a
 * single controller supporting multiple channels.
 */
struct pci_controller {
	struct pci_controller *next;
	struct pci_bus *bus;
	struct device_node *of_node;

	struct pci_ops *pci_ops;
	struct resource *mem_resource;
	unsigned long mem_offset;
	struct resource *io_resource;
	unsigned long io_offset;
	unsigned long io_map_base;

	unsigned int index;
	/* For compatibility with current (as of July 2003) pciutils
	   and XFree86. Eventually will be removed. */
	unsigned int need_domain_info;

	int iommu;

	/* Optional access methods for reading/writing the bus number
	   of the PCI controller */
	int (*get_busno)(void);
	void (*set_busno)(int busno);

        /* Config space */
        uint64_t cfg_base;
};

/*
 * Used by boards to register their PCI busses before the actual scanning.
 */
extern struct pci_controller * alloc_pci_controller(void);
extern void register_pci_controller(struct pci_controller *hose);

/* Can be used to override the logic in pci_scan_bus for skipping
 * already-configured bus numbers - to be used for buggy BIOSes
 * or architectures with incomplete PCI setup by the loader */

extern unsigned int pcibios_assign_all_busses(void);

extern unsigned long PCIBIOS_MIN_IO;
extern unsigned long PCIBIOS_MIN_MEM;

#define HAVE_PCI_MMAP

extern int pci_mmap_page_range(struct pci_dev *dev, struct vm_area_struct *vma,
	enum pci_mmap_state mmap_state, int write_combine);

struct pci_dev;

/*
 * The PCI address space does equal the physical memory address space.  The
 * networking and block device layers use this boolean for bounce buffer
 * decisions.  This is set if any hose does not have an IOMMU.
 */
#define PCI_DMA_BUS_IS_PHYS     (1)

#ifdef CONFIG_PCI
static inline void pci_dma_burst_advice(struct pci_dev *pdev,
					enum pci_dma_burst_strategy *strat,
					unsigned long *strategy_parameter)
{
	*strat = PCI_DMA_BURST_INFINITY;
	*strategy_parameter = ~0UL;
}
#endif

#define pci_domain_nr(bus) ((struct pci_controller *)(bus)->sysdata)->index

#endif /* CONFIG_ARCH_THUNDER_EMULATOR */
#endif /* __KERNEL__ */

#ifdef CONFIG_ARCH_THUNDER_EMULATOR
/* Do platform specific device initialization at pci_enable_device() time */
extern int pcibios_plat_dev_init(struct pci_dev *dev);

/* Chances are this interrupt is wired PC-style ...  */
static inline int pci_get_legacy_ide_irq(struct pci_dev *dev, int channel)
{
	return channel ? 15 : 14;
}

/* MSI arch hook for THUNDER */
#define arch_setup_msi_irqs arch_setup_msi_irqs
#endif /* CONFIG_ARCH_THUNDER_EMULATOR */
#endif /* _ASM_PCI_H */
