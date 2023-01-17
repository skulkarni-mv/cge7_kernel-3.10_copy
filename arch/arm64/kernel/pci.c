/*
 * Code borrowed from powerpc/kernel/pci-common.c
 *
 * Copyright (C) 2003 Anton Blanchard <anton@au.ibm.com>, IBM
 * Copyright (C) 2014 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * version 2 as published by the Free Software Foundation.
 *
 */

#include <linux/version.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/of_pci.h>
#include <linux/of_platform.h>
#include <linux/slab.h>
#include <linux/acpi.h>
#include <linux/efi.h>
#include <linux/pci-acpi.h>
#include <asm/pci-bridge.h>

struct ioresource {
	struct list_head list;
	phys_addr_t start;
	resource_size_t size;
};

static LIST_HEAD(io_list);

int pci_register_io_range(phys_addr_t address, resource_size_t size)
{
	struct ioresource *res;
	resource_size_t allocated_size = 0;

	/* find if the range has not been already allocated */
	list_for_each_entry(res, &io_list, list) {
		if (address >= res->start &&
			address + size <= res->start + size)
			return 0;
		allocated_size += res->size;
	}

	/* range not already registered, check for space */
	if (allocated_size + size > IO_SPACE_LIMIT)
		return -E2BIG;

	/* add the range in the list */
	res = kzalloc(sizeof(*res), GFP_KERNEL);
	if (!res)
		return -ENOMEM;
	res->start = address;
	res->size = size;

	list_add_tail(&res->list, &io_list);

	return 0;
}
EXPORT_SYMBOL_GPL(pci_register_io_range);

unsigned long pci_address_to_pio(phys_addr_t address)
{
	struct ioresource *res;

	list_for_each_entry(res, &io_list, list) {
		if (address >= res->start &&
			address < res->start + res->size) {
			return res->start - address;
		}
	}

	return (unsigned long)-1;
}
EXPORT_SYMBOL_GPL(pci_address_to_pio);

/*
 * Called after each bus is probed, but before its children are examined
 */

#ifdef CONFIG_PCI_XGENE
extern int xgene_pcie_map_irq(const struct pci_dev *pci_dev, u8 slot, u8 pin);
#endif

void pcibios_fixup_bus(struct pci_bus *bus)
{
	struct pci_dev *dev;
	struct resource *res;
	int i;

	if (!pci_is_root_bus(bus)) {
		pci_read_bridge_bases(bus);

		pci_bus_for_each_resource(bus, res, i) {
			if (!res || !res->flags || res->parent)
				continue;

			/*
			 * If we are going to reassign everything, we can
			 * shrink the P2P resource to have zero size to
			 * save space
			 */
			if (pci_has_flag(PCI_REASSIGN_ALL_RSRC)) {
				res->flags |= IORESOURCE_UNSET;
				res->start = 0;
				res->end = -1;
				continue;
			}
		}
	}

	list_for_each_entry(dev, &bus->devices, bus_list) {
		/* Ignore fully discovered devices */
		if (dev->is_added)
			continue;

		set_dev_node(&dev->dev, pcibus_to_node(dev->bus));

		/* Read default IRQs and fixup if necessary */
#ifdef CONFIG_PCI_XGENE
#if LINUX_VERSION_CODE <= KERNEL_VERSION(3, 12, 0)
		dev->irq = xgene_pcie_map_irq(dev, 0, 0);
#else
		dev->irq = of_irq_parse_and_map_pci(dev, 0, 0);
#endif
#endif
	}
}
EXPORT_SYMBOL(pcibios_fixup_bus);

/*
 * We don't have to worry about legacy ISA devices, so nothing to do here
 */
resource_size_t pcibios_align_resource(void *data, const struct resource *res,
				resource_size_t size, resource_size_t align)
{
	return res->start;
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	return pci_enable_resources(dev, mask);
}

#define IO_SPACE_PAGES	((IO_SPACE_LIMIT + 1) / PAGE_SIZE)
static DECLARE_BITMAP(pci_iospace, IO_SPACE_PAGES);

unsigned long pci_ioremap_io(const struct resource *res, phys_addr_t phys_addr)
{
	unsigned long start, len, virt_start;
	int err;

	if (res->end > IO_SPACE_LIMIT)
		return -EINVAL;

	/*
	 * try finding free space for the whole size first,
	 * fall back to 64K if not available
	 */
	len = resource_size(res);
	start = bitmap_find_next_zero_area(pci_iospace, IO_SPACE_PAGES,
				res->start / PAGE_SIZE, len / PAGE_SIZE, 0);
	if (start == IO_SPACE_PAGES && len > SZ_64K) {
		len = SZ_64K;
		start = 0;
		start = bitmap_find_next_zero_area(pci_iospace, IO_SPACE_PAGES,
					start, len / PAGE_SIZE, 0);
	}

	/* no 64K area found */
	if (start == IO_SPACE_PAGES)
		return -ENOMEM;

	/* ioremap physical aperture to virtual aperture */
	virt_start = start * PAGE_SIZE + (unsigned long)PCI_IOBASE;
	err = ioremap_page_range(virt_start, virt_start + len,
				phys_addr, __pgprot(PROT_DEVICE_nGnRE));
	if (err)
		return err;

	bitmap_set(pci_iospace, start, len / PAGE_SIZE);

	/* return io_offset */
	return start * PAGE_SIZE - res->start;
}

static int (*pcibios_add_device_impl)(struct pci_dev *);

void set_pcibios_add_device(int (*arg)(struct pci_dev *))
{
	pcibios_add_device_impl = arg;
}

/*
 * Try to assign the IRQ number from DT when adding a new device
 */
int pcibios_add_device(struct pci_dev *dev)
{
	if (pcibios_add_device_impl)
		return pcibios_add_device_impl(dev);

	dev->irq = of_irq_parse_and_map_pci(dev, 0, 0);

	return 0;
}

/*
 * This is currently only used by the Freescale platforms and broadcom iproc
 * family, it breaks things on other platforms because it overrides
 * pcibios_add_bus in an incompatible way.
 */
#if defined(CONFIG_ARCH_FSL_LS1043A) || defined(CONFIG_PCIE_IPROC) || defined(CONFIG_ARCH_MVEBU)
static int debug_pci;

void pcibios_add_bus(struct pci_bus *bus)
{
	struct pci_sys_data *sys = bus->sysdata;

	if (sys->add_bus)
		sys->add_bus(bus);
}

void pcibios_remove_bus(struct pci_bus *bus)
{
	struct pci_sys_data *sys = bus->sysdata;

	if (sys->remove_bus)
		sys->remove_bus(bus);
}

/*
 * Swizzle the device pin each time we cross a bridge.  If a platform does
 * not provide a swizzle function, we perform the standard PCI swizzling.
 *
 * The default swizzling walks up the bus tree one level at a time, applying
 * the standard swizzle function at each step, stopping when it finds the PCI
 * root bus.  This will return the slot number of the bridge device on the
 * root bus and the interrupt pin on that device which should correspond
 * with the downstream device interrupt.
 *
 * Platforms may override this, in which case the slot and pin returned
 * depend entirely on the platform code.  However, please note that the
 * PCI standard swizzle is implemented on plug-in cards and Cardbus based
 * PCI extenders, so it can not be ignored.
 */
static u8 pcibios_swizzle(struct pci_dev *dev, u8 *pin)
{
	struct pci_sys_data *sys = dev->sysdata;
	int slot, oldpin = *pin;

	if (sys->swizzle)
		slot = sys->swizzle(dev, pin);
	else
		slot = pci_common_swizzle(dev, pin);

	if (debug_pci)
		pr_info("PCI: %s swizzling pin %d => pin %d slot %d\n",
			pci_name(dev), oldpin, *pin, slot);

	return slot;
}

/*
 * Map a slot/pin to an IRQ.
 */
static int pcibios_map_irq(const struct pci_dev *dev, u8 slot, u8 pin)
{
	struct pci_sys_data *sys = dev->sysdata;
	int irq = -1;

	if (sys->map_irq)
		irq = sys->map_irq(dev, slot, pin);

	if (debug_pci)
		pr_info("PCI: %s mapping slot %d pin %d => irq %d\n",
			pci_name(dev), slot, pin, irq);

	return irq;
}

static int pcibios_init_resources(int busnr, struct pci_sys_data *sys)
{
	int ret;
	struct pci_host_bridge_window *window;

	if (list_empty(&sys->resources)) {
		pci_add_resource_offset(&sys->resources,
			 &iomem_resource, sys->mem_offset);
	}

	list_for_each_entry(window, &sys->resources, list) {
		if (resource_type(window->res) == IORESOURCE_IO)
			return 0;
	}

	sys->io_res.start = (busnr * SZ_64K) ?  : PCIBIOS_MIN_IO;
	sys->io_res.end = (busnr + 1) * SZ_64K - 1;
	sys->io_res.flags = IORESOURCE_IO;
	sys->io_res.name = sys->io_res_name;
	sprintf(sys->io_res_name, "PCI%d I/O", busnr);

	ret = request_resource(&ioport_resource, &sys->io_res);
	if (ret) {
		pr_err("PCI: unable to allocate I/O port region (%d)\n", ret);
		return ret;
	}
	pci_add_resource_offset(&sys->resources, &sys->io_res,
				sys->io_offset);

	return 0;
}

static void pcibios_init_hw(struct device *parent, struct hw_pci *hw,
			    struct list_head *head)
{
	struct pci_sys_data *sys = NULL;
	int ret;
	int nr, busnr;

	for (nr = busnr = 0; nr < hw->nr_controllers; nr++) {
		sys = kzalloc(sizeof(struct pci_sys_data), GFP_KERNEL);
		if (!sys)
			panic("PCI: unable to allocate sys data!");

#ifdef CONFIG_PCI_DOMAINS
		sys->domain  = hw->domain;
#endif
		sys->busnr   = busnr;
		sys->swizzle = hw->swizzle;
		sys->map_irq = hw->map_irq;
		sys->align_resource = hw->align_resource;
		sys->add_bus = hw->add_bus;
		sys->remove_bus = hw->remove_bus;
		INIT_LIST_HEAD(&sys->resources);

		if (hw->private_data)
			sys->private_data = hw->private_data[nr];

		ret = hw->setup(nr, sys);

		if (ret > 0) {
			ret = pcibios_init_resources(nr, sys);
			if (ret)  {
				kfree(sys);
				break;
			}

			if (hw->scan)
				sys->bus = hw->scan(nr, sys);
			else
				sys->bus = pci_scan_root_bus(parent, sys->busnr,
						hw->ops, sys, &sys->resources);

			if (!sys->bus)
				panic("PCI: unable to scan bus!");

			busnr = sys->bus->busn_res.end + 1;

			list_add(&sys->node, head);
		} else {
			kfree(sys);
			if (ret < 0)
				break;
		}
	}
}

void pci_common_init_dev(struct device *parent, struct hw_pci *hw)
{
	struct pci_sys_data *sys;
	LIST_HEAD(head);

	pci_add_flags(PCI_REASSIGN_ALL_RSRC);
	if (hw->preinit)
		hw->preinit();
	pcibios_init_hw(parent, hw, &head);
	if (hw->postinit)
		hw->postinit();

	pci_fixup_irqs(pcibios_swizzle, pcibios_map_irq);

	list_for_each_entry(sys, &head, node) {
		struct pci_bus *bus = sys->bus;

		if (!pci_has_flag(PCI_PROBE_ONLY)) {
			/*
			 * Size the bridge windows.
			 */
			pci_bus_size_bridges(bus);

			/*
			 * Assign resources.
			 */
			pci_bus_assign_resources(bus);
		}

		/*
		 * Tell drivers about devices found.
		 */
		pci_bus_add_devices(bus);
	}

	list_for_each_entry(sys, &head, node) {
		struct pci_bus *bus = sys->bus;

		/* Configure PCI Express settings */
		if (bus && !pci_has_flag(PCI_PROBE_ONLY)) {
			struct pci_bus *child;

			list_for_each_entry(child, &bus->children, node)
				pcie_bus_configure_settings(child);
		}
	}
}

char * __init pcibios_setup(char *str)
{
	if (!strcmp(str, "debug")) {
		debug_pci = 1;
		return NULL;
	} else if (!strcmp(str, "firmware")) {
		pci_add_flags(PCI_PROBE_ONLY);
		return NULL;
	}
	return str;
}
#endif
