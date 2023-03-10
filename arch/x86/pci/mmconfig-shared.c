/*
 * mmconfig-shared.c - Low-level direct PCI config space access via
 *                     MMCONFIG - common code between i386 and x86-64.
 *
 * This code does:
 * - known chipset handling
 * - ACPI decoding and validation
 *
 * Per-architecture code takes care of the mappings and accesses
 * themselves.
 */

#include <linux/pci.h>
#include <linux/init.h>
#include <linux/sfi_acpi.h>
#include <linux/bitmap.h>
#include <linux/dmi.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/rculist.h>
#include <linux/mmconfig.h>
#include <asm/e820.h>
#include <asm/pci_x86.h>
#include <asm/acpi.h>

#define PREFIX "PCI: "

/* Indicate if the mmcfg resources have been placed into the resource table. */
static bool pci_mmcfg_running_state;
static bool pci_mmcfg_arch_init_failed;

#ifdef CONFIG_X86_64
static char __iomem *pci_dev_base(unsigned int seg, unsigned int bus,
				  unsigned int devfn)
{
	struct pci_mmcfg_region *cfg = pci_mmconfig_lookup(seg, bus);

	if (cfg && cfg->virt)
		return cfg->virt + (PCI_MMCFG_BUS_OFFSET(bus) | (devfn << 12));
	return NULL;
}

int pci_mmcfg_read(unsigned int seg, unsigned int bus,
		   unsigned int devfn, int reg, int len, u32 *value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095))) {
err:		*value = -1;
		return -EINVAL;
	}

	rcu_read_lock();
	addr = pci_dev_base(seg, bus, devfn);
	if (!addr) {
		rcu_read_unlock();
		goto err;
	}

	switch (len) {
	case 1:
		*value = mmio_config_readb(addr + reg);
		break;
	case 2:
		*value = mmio_config_readw(addr + reg);
		break;
	case 4:
		*value = mmio_config_readl(addr + reg);
		break;
	}
	rcu_read_unlock();

	return 0;
}

int pci_mmcfg_write(unsigned int seg, unsigned int bus,
		    unsigned int devfn, int reg, int len, u32 value)
{
	char __iomem *addr;

	/* Why do we have this when nobody checks it. How about a BUG()!? -AK */
	if (unlikely((bus > 255) || (devfn > 255) || (reg > 4095)))
		return -EINVAL;

	rcu_read_lock();
	addr = pci_dev_base(seg, bus, devfn);
	if (!addr) {
		rcu_read_unlock();
		return -EINVAL;
	}

	switch (len) {
	case 1:
		mmio_config_writeb(addr + reg, value);
		break;
	case 2:
		mmio_config_writew(addr + reg, value);
		break;
	case 4:
		mmio_config_writel(addr + reg, value);
		break;
	}
	rcu_read_unlock();

	return 0;
	return PCIBIOS_DEVICE_NOT_FOUND;
}
#endif

const struct pci_raw_ops pci_mmcfg = {
	.read =		pci_mmcfg_read,
	.write =	pci_mmcfg_write,
};

static const char *__init pci_mmcfg_e7520(void)
{
	u32 win;
	raw_pci_ops->read(0, 0, PCI_DEVFN(0, 0), 0xce, 2, &win);

	win = win & 0xf000;
	if (win == 0x0000 || win == 0xf000)
		return NULL;

	if (pci_mmconfig_add(0, 0, 255, win << 16) == NULL)
		return NULL;

	return "Intel Corporation E7520 Memory Controller Hub";
}

static const char *__init pci_mmcfg_intel_945(void)
{
	u32 pciexbar, mask = 0, len = 0;

	raw_pci_ops->read(0, 0, PCI_DEVFN(0, 0), 0x48, 4, &pciexbar);

	/* Enable bit */
	if (!(pciexbar & 1))
		return NULL;

	/* Size bits */
	switch ((pciexbar >> 1) & 3) {
	case 0:
		mask = 0xf0000000U;
		len  = 0x10000000U;
		break;
	case 1:
		mask = 0xf8000000U;
		len  = 0x08000000U;
		break;
	case 2:
		mask = 0xfc000000U;
		len  = 0x04000000U;
		break;
	default:
		return NULL;
	}

	/* Errata #2, things break when not aligned on a 256Mb boundary */
	/* Can only happen in 64M/128M mode */

	if ((pciexbar & mask) & 0x0fffffffU)
		return NULL;

	/* Don't hit the APIC registers and their friends */
	if ((pciexbar & mask) >= 0xf0000000U)
		return NULL;

	if (pci_mmconfig_add(0, 0, (len >> 20) - 1, pciexbar & mask) == NULL)
		return NULL;

	return "Intel Corporation 945G/GZ/P/PL Express Memory Controller Hub";
}

static const char *__init pci_mmcfg_amd_fam10h(void)
{
	u32 low, high, address;
	u64 base, msr;
	int i;
	unsigned segnbits = 0, busnbits, end_bus;

	if (!(pci_probe & PCI_CHECK_ENABLE_AMD_MMCONF))
		return NULL;

	address = MSR_FAM10H_MMIO_CONF_BASE;
	if (rdmsr_safe(address, &low, &high))
		return NULL;

	msr = high;
	msr <<= 32;
	msr |= low;

	/* mmconfig is not enable */
	if (!(msr & FAM10H_MMIO_CONF_ENABLE))
		return NULL;

	base = msr & (FAM10H_MMIO_CONF_BASE_MASK<<FAM10H_MMIO_CONF_BASE_SHIFT);

	busnbits = (msr >> FAM10H_MMIO_CONF_BUSRANGE_SHIFT) &
			 FAM10H_MMIO_CONF_BUSRANGE_MASK;

	/*
	 * only handle bus 0 ?
	 * need to skip it
	 */
	if (!busnbits)
		return NULL;

	if (busnbits > 8) {
		segnbits = busnbits - 8;
		busnbits = 8;
	}

	end_bus = (1 << busnbits) - 1;
	for (i = 0; i < (1 << segnbits); i++)
		if (pci_mmconfig_add(i, 0, end_bus,
				     base + (1<<28) * i) == NULL) {
			free_all_mmcfg();
			return NULL;
		}

	return "AMD Family 10h NB";
}

static bool __initdata mcp55_checked;
static const char *__init pci_mmcfg_nvidia_mcp55(void)
{
	int bus;
	int mcp55_mmconf_found = 0;

	static const u32 extcfg_regnum __initconst	= 0x90;
	static const u32 extcfg_regsize __initconst	= 4;
	static const u32 extcfg_enable_mask __initconst	= 1 << 31;
	static const u32 extcfg_start_mask __initconst	= 0xff << 16;
	static const int extcfg_start_shift __initconst	= 16;
	static const u32 extcfg_size_mask __initconst	= 0x3 << 28;
	static const int extcfg_size_shift __initconst	= 28;
	static const int extcfg_sizebus[] __initconst	= {
		0x100, 0x80, 0x40, 0x20
	};
	static const u32 extcfg_base_mask[] __initconst	= {
		0x7ff8, 0x7ffc, 0x7ffe, 0x7fff
	};
	static const int extcfg_base_lshift __initconst	= 25;

	/*
	 * do check if amd fam10h already took over
	 */
	if (!acpi_disabled || !list_empty(&pci_mmcfg_list) || mcp55_checked)
		return NULL;

	mcp55_checked = true;
	for (bus = 0; bus < 256; bus++) {
		u64 base;
		u32 l, extcfg;
		u16 vendor, device;
		int start, size_index, end;

		raw_pci_ops->read(0, bus, PCI_DEVFN(0, 0), 0, 4, &l);
		vendor = l & 0xffff;
		device = (l >> 16) & 0xffff;

		if (PCI_VENDOR_ID_NVIDIA != vendor || 0x0369 != device)
			continue;

		raw_pci_ops->read(0, bus, PCI_DEVFN(0, 0), extcfg_regnum,
				  extcfg_regsize, &extcfg);

		if (!(extcfg & extcfg_enable_mask))
			continue;

		size_index = (extcfg & extcfg_size_mask) >> extcfg_size_shift;
		base = extcfg & extcfg_base_mask[size_index];
		/* base could > 4G */
		base <<= extcfg_base_lshift;
		start = (extcfg & extcfg_start_mask) >> extcfg_start_shift;
		end = start + extcfg_sizebus[size_index] - 1;
		if (pci_mmconfig_add(0, start, end, base) == NULL)
			continue;
		mcp55_mmconf_found++;
	}

	if (!mcp55_mmconf_found)
		return NULL;

	return "nVidia MCP55";
}

struct pci_mmcfg_hostbridge_probe {
	u32 bus;
	u32 devfn;
	u32 vendor;
	u32 device;
	const char *(*probe)(void);
};

static const struct pci_mmcfg_hostbridge_probe pci_mmcfg_probes[] __initconst = {
	{ 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
	  PCI_DEVICE_ID_INTEL_E7520_MCH, pci_mmcfg_e7520 },
	{ 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_INTEL,
	  PCI_DEVICE_ID_INTEL_82945G_HB, pci_mmcfg_intel_945 },
	{ 0, PCI_DEVFN(0x18, 0), PCI_VENDOR_ID_AMD,
	  0x1200, pci_mmcfg_amd_fam10h },
	{ 0xff, PCI_DEVFN(0, 0), PCI_VENDOR_ID_AMD,
	  0x1200, pci_mmcfg_amd_fam10h },
	{ 0, PCI_DEVFN(0, 0), PCI_VENDOR_ID_NVIDIA,
	  0x0369, pci_mmcfg_nvidia_mcp55 },
};

static void __init pci_mmcfg_check_end_bus_number(void)
{
	struct pci_mmcfg_region *cfg, *cfgx;

	/* Fixup overlaps */
	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		if (cfg->end_bus < cfg->start_bus)
			cfg->end_bus = 255;

		/* Don't access the list head ! */
		if (cfg->list.next == &pci_mmcfg_list)
			break;

		cfgx = list_entry(cfg->list.next, typeof(*cfg), list);
		if (cfg->end_bus >= cfgx->start_bus)
			cfg->end_bus = cfgx->start_bus - 1;
	}
}

static int __init pci_mmcfg_check_hostbridge(void)
{
	u32 l;
	u32 bus, devfn;
	u16 vendor, device;
	int i;
	const char *name;

	if (!raw_pci_ops)
		return 0;

	free_all_mmcfg();

	for (i = 0; i < ARRAY_SIZE(pci_mmcfg_probes); i++) {
		bus =  pci_mmcfg_probes[i].bus;
		devfn = pci_mmcfg_probes[i].devfn;
		raw_pci_ops->read(0, bus, devfn, 0, 4, &l);
		vendor = l & 0xffff;
		device = (l >> 16) & 0xffff;

		name = NULL;
		if (pci_mmcfg_probes[i].vendor == vendor &&
		    pci_mmcfg_probes[i].device == device)
			name = pci_mmcfg_probes[i].probe();

		if (name)
			pr_info(PREFIX "%s with MMCONFIG support\n", name);
	}

	/* some end_bus_number is crazy, fix it */
	pci_mmcfg_check_end_bus_number();

	return !list_empty(&pci_mmcfg_list);
}

static acpi_status check_mcfg_resource(struct acpi_resource *res, void *data)
{
	struct resource *mcfg_res = data;
	struct acpi_resource_address64 address;
	acpi_status status;

	if (res->type == ACPI_RESOURCE_TYPE_FIXED_MEMORY32) {
		struct acpi_resource_fixed_memory32 *fixmem32 =
			&res->data.fixed_memory32;
		if (!fixmem32)
			return AE_OK;
		if ((mcfg_res->start >= fixmem32->address) &&
		    (mcfg_res->end < (fixmem32->address +
				      fixmem32->address_length))) {
			mcfg_res->flags = 1;
			return AE_CTRL_TERMINATE;
		}
	}
	if ((res->type != ACPI_RESOURCE_TYPE_ADDRESS32) &&
	    (res->type != ACPI_RESOURCE_TYPE_ADDRESS64))
		return AE_OK;

	status = acpi_resource_to_address64(res, &address);
	if (ACPI_FAILURE(status) ||
	   (address.address_length <= 0) ||
	   (address.resource_type != ACPI_MEMORY_RANGE))
		return AE_OK;

	if ((mcfg_res->start >= address.minimum) &&
	    (mcfg_res->end < (address.minimum + address.address_length))) {
		mcfg_res->flags = 1;
		return AE_CTRL_TERMINATE;
	}
	return AE_OK;
}

static acpi_status find_mboard_resource(acpi_handle handle, u32 lvl,
					void *context, void **rv)
{
	struct resource *mcfg_res = context;

	acpi_walk_resources(handle, METHOD_NAME__CRS,
			    check_mcfg_resource, context);

	if (mcfg_res->flags)
		return AE_CTRL_TERMINATE;

	return AE_OK;
}

static int is_acpi_reserved(u64 start, u64 end, unsigned not_used)
{
	struct resource mcfg_res;

	mcfg_res.start = start;
	mcfg_res.end = end - 1;
	mcfg_res.flags = 0;

	acpi_get_devices("PNP0C01", find_mboard_resource, &mcfg_res, NULL);

	if (!mcfg_res.flags)
		acpi_get_devices("PNP0C02", find_mboard_resource, &mcfg_res,
				 NULL);

	return mcfg_res.flags;
}

typedef int (*check_reserved_t)(u64 start, u64 end, unsigned type);

static int __ref is_mmconf_reserved(check_reserved_t is_reserved,
				    struct pci_mmcfg_region *cfg,
				    struct device *dev, int with_e820)
{
	u64 addr = cfg->res.start;
	u64 size = resource_size(&cfg->res);
	u64 old_size = size;
	int num_buses;
	char *method = with_e820 ? "E820" : "ACPI motherboard resources";

	while (!is_reserved(addr, addr + size, E820_RESERVED)) {
		size >>= 1;
		if (size < (16UL<<20))
			break;
	}

	if (size < (16UL<<20) && size != old_size)
		return 0;

	if (dev)
		dev_info(dev, "MMCONFIG at %pR reserved in %s\n",
			 &cfg->res, method);
	else
		pr_info(PREFIX "MMCONFIG at %pR reserved in %s\n",
		       &cfg->res, method);

	if (old_size != size) {
		/* update end_bus */
		cfg->end_bus = cfg->start_bus + ((size>>20) - 1);
		num_buses = cfg->end_bus - cfg->start_bus + 1;
		cfg->res.end = cfg->res.start +
		    PCI_MMCFG_BUS_OFFSET(num_buses) - 1;
		snprintf(cfg->name, PCI_MMCFG_RESOURCE_NAME_LEN,
			 "PCI MMCONFIG %04x [bus %02x-%02x]",
			 cfg->segment, cfg->start_bus, cfg->end_bus);

		if (dev)
			dev_info(dev,
				"MMCONFIG "
				"at %pR (base %#lx) (size reduced!)\n",
				&cfg->res, (unsigned long) cfg->address);
		else
			pr_info(PREFIX
				"MMCONFIG for %04x [bus%02x-%02x] "
				"at %pR (base %#lx) (size reduced!)\n",
				cfg->segment, cfg->start_bus, cfg->end_bus,
				&cfg->res, (unsigned long) cfg->address);
	}

	return 1;
}

static int __ref pci_mmcfg_check_reserved(struct device *dev,
		  struct pci_mmcfg_region *cfg, int early)
{
	if (!early && !acpi_disabled) {
		if (is_mmconf_reserved(is_acpi_reserved, cfg, dev, 0))
			return 1;

		if (dev)
			dev_info(dev, FW_INFO
				 "MMCONFIG at %pR not reserved in "
				 "ACPI motherboard resources\n",
				 &cfg->res);
		else
			pr_info(FW_INFO PREFIX
			       "MMCONFIG at %pR not reserved in "
			       "ACPI motherboard resources\n",
			       &cfg->res);
	}

	/*
	 * e820_all_mapped() is marked as __init.
	 * All entries from ACPI MCFG table have been checked at boot time.
	 * For MCFG information constructed from hotpluggable host bridge's
	 * _CBA method, just assume it's reserved.
	 */
	if (pci_mmcfg_running_state)
		return 1;

	/* Don't try to do this check unless configuration
	   type 1 is available. how about type 2 ?*/
	if (raw_pci_ops)
		return is_mmconf_reserved(e820_all_mapped, cfg, dev, 1);

	return 0;
}

static void __init pci_mmcfg_reject_broken(int early)
{
	struct pci_mmcfg_region *cfg;

	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		if (pci_mmcfg_check_reserved(NULL, cfg, early) == 0) {
			pr_info(PREFIX "not using MMCONFIG\n");
			free_all_mmcfg();
			return;
		}
	}
}

int __init acpi_mcfg_check_entry(struct acpi_table_mcfg *mcfg,
					struct acpi_mcfg_allocation *cfg)
{
	int year;

	if (cfg->address < 0xFFFFFFFF)
		return 0;

	if (!strncmp(mcfg->header.oem_id, "SGI", 3))
		return 0;

	if (mcfg->header.revision >= 1) {
		if (dmi_get_date(DMI_BIOS_DATE, &year, NULL, NULL) &&
		    year >= 2010)
			return 0;
	}

	pr_err(PREFIX "MCFG region for %04x [bus %02x-%02x] at %#llx "
	       "is above 4GB, ignored\n", cfg->pci_segment,
	       cfg->start_bus_number, cfg->end_bus_number, cfg->address);
	return -EINVAL;
}

#ifdef CONFIG_ACPI_APEI
extern int (*arch_apei_filter_addr)(int (*func)(__u64 start, __u64 size,
				     void *data), void *data);

static int pci_mmcfg_for_each_region(int (*func)(__u64 start, __u64 size,
				     void *data), void *data)
{
	struct pci_mmcfg_region *cfg;
	int rc;

	if (list_empty(&pci_mmcfg_list))
		return 0;

	list_for_each_entry(cfg, &pci_mmcfg_list, list) {
		rc = func(cfg->res.start, resource_size(&cfg->res), data);
		if (rc)
			return rc;
	}

	return 0;
}
#define set_apei_filter() (arch_apei_filter_addr = pci_mmcfg_for_each_region)
#else
#define set_apei_filter()
#endif

static void __init __pci_mmcfg_init(int early)
{
	pci_mmcfg_reject_broken(early);
	if (list_empty(&pci_mmcfg_list))
		return;

	if (pcibios_last_bus < 0) {
		const struct pci_mmcfg_region *cfg;

		list_for_each_entry(cfg, &pci_mmcfg_list, list) {
			if (cfg->segment)
				break;
			pcibios_last_bus = cfg->end_bus;
		}
	}

	if (pci_mmcfg_arch_init()) {
		raw_pci_ext_ops = &pci_mmcfg;
		pci_probe = (pci_probe & ~PCI_PROBE_MASK) | PCI_PROBE_MMCONF;
	} else {
		free_all_mmcfg();
		pci_mmcfg_arch_init_failed = true;
	}
}

static int __initdata known_bridge;

void __init pci_mmcfg_early_init(void)
{
	if (pci_probe & PCI_PROBE_MMCONF) {
		if (pci_mmcfg_check_hostbridge())
			known_bridge = 1;
		else
			acpi_sfi_table_parse(ACPI_SIG_MCFG, pci_parse_mcfg);
		__pci_mmcfg_init(1);

		set_apei_filter();
	}
}

void __init pci_mmcfg_late_init(void)
{
	/* MMCONFIG disabled */
	if ((pci_probe & PCI_PROBE_MMCONF) == 0)
		return;

	if (known_bridge)
		return;

	/* MMCONFIG hasn't been enabled yet, try again */
	if (pci_probe & PCI_PROBE_MASK & ~PCI_PROBE_MMCONF) {
		acpi_sfi_table_parse(ACPI_SIG_MCFG, pci_parse_mcfg);
		__pci_mmcfg_init(0);
	}
}

static int __init pci_mmcfg_late_insert_resources(void)
{
	struct pci_mmcfg_region *cfg;

	pci_mmcfg_running_state = true;

	/* If we are not using MMCONFIG, don't insert the resources. */
	if ((pci_probe & PCI_PROBE_MMCONF) == 0)
		return 1;

	/*
	 * Attempt to insert the mmcfg resources but not with the busy flag
	 * marked so it won't cause request errors when __request_region is
	 * called.
	 */
	list_for_each_entry(cfg, &pci_mmcfg_list, list)
		if (!cfg->res.parent)
			insert_resource(&iomem_resource, &cfg->res);

	return 0;
}

/*
 * Perform MMCONFIG resource insertion after PCI initialization to allow for
 * misprogrammed MCFG tables that state larger sizes but actually conflict
 * with other system resources.
 */
late_initcall(pci_mmcfg_late_insert_resources);

/* Add MMCFG information for host bridges */
int pci_mmconfig_insert(struct device *dev, u16 seg, u8 start, u8 end,
			phys_addr_t addr)
{
	int rc;
	struct resource *tmp = NULL;
	struct pci_mmcfg_region *cfg;

	if (!(pci_probe & PCI_PROBE_MMCONF) || pci_mmcfg_arch_init_failed)
		return -ENODEV;

	if (start > end || !addr)
		return -EINVAL;

	rc = -EBUSY;
	cfg = pci_mmconfig_alloc(seg, start, end, addr);
	if (cfg == NULL) {
		dev_warn(dev, "fail to add MMCONFIG (out of memory)\n");
		return -ENOMEM;
	} else if (!pci_mmcfg_check_reserved(dev, cfg, 0)) {
		dev_warn(dev, FW_BUG "MMCONFIG %pR isn't reserved\n",
			 &cfg->res);
		goto error;
	}

	/* Insert resource if it's not in boot stage */
	if (pci_mmcfg_running_state)
		tmp = insert_resource_conflict(&iomem_resource, &cfg->res);

	if (tmp) {
		dev_warn(dev,
			 "MMCONFIG %pR conflicts with %s %pR\n",
			 &cfg->res, tmp->name, tmp);
		goto error;
	}

	rc = pci_mmconfig_inject(cfg);
	if (rc)
		goto error;

	return 0;

error:
	if (cfg->res.parent)
		release_resource(&cfg->res);
	kfree(cfg);
	return rc;
}
