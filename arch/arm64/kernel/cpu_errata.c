/*
 * Contains CPU specific errata definitions
 *
 * Copyright (C) 2014 ARM Ltd.
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

#include <linux/types.h>
#include <asm/cpu.h>
#include <asm/cputype.h>
#include <asm/cpufeature.h>

static bool __maybe_unused
is_affected_midr_range(const struct arm64_cpu_capabilities *entry)
{
	return MIDR_IS_CPU_MODEL_RANGE(read_cpuid_id(), entry->midr_model,
				       entry->midr_range_min,
				       entry->midr_range_max);
}

#define MIDR_RANGE(model, min, max) \
	.matches = is_affected_midr_range, \
	.midr_model = model, \
	.midr_range_min = min, \
	.midr_range_max = max

const struct arm64_cpu_capabilities arm64_errata[] = {
#if	defined(CONFIG_ARM64_ERRATUM_826319) || \
	defined(CONFIG_ARM64_ERRATUM_827319) || \
	defined(CONFIG_ARM64_ERRATUM_824069)
	{
	/* Cortex-A53 r0p[012] */
		.desc = "ARM errata 826319, 827319, 824069",
		.capability = ARM64_WORKAROUND_CLEAN_CACHE,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x02),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_819472
	{
	/* Cortex-A53 r0p[01] */
		.desc = "ARM errata 819472",
		.capability = ARM64_WORKAROUND_CLEAN_CACHE,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x01),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_832075
	{
	/* Cortex-A57 r0p0 - r1p2 */
		.desc = "ARM erratum 832075",
		.capability = ARM64_WORKAROUND_DEVICE_LOAD_ACQUIRE,
		MIDR_RANGE(MIDR_CORTEX_A57, 0x00, 0x12),
	},
#endif
#ifdef CONFIG_ARM64_ERRATUM_845719
	{
	/* Cortex-A53 r0p[01234] */
		.desc = "ARM erratum 845719",
		.capability = ARM64_WORKAROUND_845719,
		MIDR_RANGE(MIDR_CORTEX_A53, 0x00, 0x04),
	},
#endif
#ifdef CONFIG_CAVIUM_ERRATUM_23154
	{
	/* Cavium ThunderX, pass 1.x */
		.desc = "Cavium erratum 23154",
		.capability = ARM64_WORKAROUND_CAVIUM_23154,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x01),
	},
#endif
#ifdef CONFIG_CAVIUM_ERRATUM_27456
	{
	/* Cavium ThunderX, T88 pass 1.x - 2.1 */
		.desc = "Cavium erratum 27456",
		.capability = ARM64_WORKAROUND_CAVIUM_27456,
		MIDR_RANGE(MIDR_THUNDERX, 0x00,
			   (1 << MIDR_VARIANT_SHIFT) | 1),
	},
	{
	/* Cavium ThunderX, T81 pass 1.0 */
		.desc = "Cavium erratum 27456",
		.capability = ARM64_WORKAROUND_CAVIUM_27456,
		MIDR_RANGE(MIDR_THUNDERX_81XX, 0x00, 0x00),
	},
#endif
	{
	/* Cavium ThunderX, pass 1.0 */
		.desc = "Cavium erratum 23111",
		.capability = ARM64_WORKAROUND_CAVIUM_23111,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x00),
	},
	{
	/* Cavium ThunderX, pass 1.x */
		.desc = "Cavium erratum 22536",
		.capability = ARM64_WORKAROUND_CAVIUM_22536,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x01),
	},
	{
	
	/* Cavium ThunderX, pass 1.x */
		.desc = "Cavium erratum 21306",
		.capability = ARM64_WORKAROUND_CAVIUM_21306,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x01),
	},
	{
	/* Cavium ThunderX, pass 1.0 */
		.desc = "Cavium erratum 23238",
		.capability = ARM64_WORKAROUND_CAVIUM_23238,
		MIDR_RANGE(MIDR_THUNDERX, 0x00, 0x00),
	},
	{
	}
};

void check_local_cpu_errata(void)
{
	check_cpu_capabilities(arm64_errata, "enabling workaround for");
}
