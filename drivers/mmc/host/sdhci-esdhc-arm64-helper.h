/*
 * Freescale eSDHC controller driver helper functions for arm64
 *
 * Copyright (c) 2015 MontaVista Software, Inc.
 * Author: Arun chandran <achandran@mvista.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#ifndef _DRIVERS_MMC_SDHCI_ESDHC_ARM64_HELPER_H
#define _DRIVERS_MMC_SDHCI_ESDHC_ARM64_HELPER_H

#undef setbits32
#undef clrsetbits_be32

#if defined(CONFIG_ARCH_FSL_LS1043A) && !defined (CONFIG_ARCH_LAYERSCAPE)
#define BIG_ENDIAN_IP
#endif

static inline u32 in_be32(void __iomem *ioaddr)
{
#ifdef BIG_ENDIAN_IP
	return ioread32be(ioaddr);
#else
	return ioread32(ioaddr);
#endif
}

static inline u16 in_be16(void __iomem *ioaddr)
{
#ifdef BIG_ENDIAN_IP
	return ioread16be(ioaddr);
#else
	return ioread16(ioaddr);
#endif
}

static inline u8 in_8(void __iomem *ioaddr)
{
	return ioread8(ioaddr);
}

static inline void out_be32(void __iomem *ioaddr, u32 val)
{
#ifdef BIG_ENDIAN_IP
	iowrite32be(val, ioaddr);
#else
	iowrite32(val, ioaddr);
#endif
}


/* Below macros copied from arch/powerpc/include/asm/io.h */

#define setbits32(_addr, _v) out_be32((_addr), in_be32(_addr) |  (_v))

/* Clear and set bits in one shot.  These macros can be used to clear and
 * set multiple bits in a register using a single read-modify-write.  These
 * macros can also be used to set a multiple-bit bit pattern using a mask,
 * by specifying the mask in the 'clear' parameter and the new bit pattern
 * in the 'set' parameter.
 */

#define clrsetbits(type, addr, clear, set) \
	out_##type((addr), (in_##type(addr) & ~(clear)) | (set))

#define clrsetbits_be32(addr, clear, set) clrsetbits(be32, addr, clear, set)

#endif
