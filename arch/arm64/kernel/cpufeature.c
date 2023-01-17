/*
 * Contains CPU feature definitions
 *
 * Copyright (C) 2015 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define pr_fmt(fmt) "alternatives: " fmt

#include <linux/types.h>
#include <asm/cpu.h>
#include <asm/cpufeature.h>
#include <asm/cputype.h>

static bool
has_id_aa64pfr0_feature(const struct arm64_cpu_capabilities *entry)
{
	u64 val;

	val = read_cpuid(id_aa64pfr0_el1);
	return (val & entry->register_mask) == entry->register_value;
}

static bool has_no_hw_prefetch(const struct arm64_cpu_capabilities *entry)
{
	u32 midr = read_cpuid_id();
	u32 rv_min, rv_max;

	/* Cavium ThunderX pass 1.x and 2.x */
	rv_min = 0;
	rv_max = (1 << MIDR_VARIANT_SHIFT) | MIDR_REVISION_MASK;

	return MIDR_IS_CPU_MODEL_RANGE(midr, MIDR_THUNDERX, rv_min, rv_max);
}

static const struct arm64_cpu_capabilities arm64_features[] = {
	{
		.desc = "GIC system register CPU interface",
		.capability = ARM64_HAS_SYSREG_GIC_CPUIF,
		.matches = has_id_aa64pfr0_feature,
		.register_mask = (0xf << 24),
		.register_value = (1 << 24),
	},
	{
		.desc = "Software prefetching using PRFM",
		.capability = ARM64_HAS_NO_HW_PREFETCH,
		.matches = has_no_hw_prefetch,
	},
	{},
};

void check_cpu_capabilities(const struct arm64_cpu_capabilities *caps,
			    const char *info)
{
	int i;

	for (i = 0; caps[i].desc; i++) {
		if (!caps[i].matches(&caps[i]))
			continue;

		if (!cpus_have_cap(caps[i].capability))
			pr_info("%s %s\n", info, caps[i].desc);
		cpus_set_cap(caps[i].capability);
	}
}

void check_local_cpu_features(void)
{
	check_cpu_capabilities(arm64_features, "detected feature");
}
