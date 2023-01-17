/*
 * Author: Open Silicon, Inc.
 * Contact: platform@open-silicon.com
 * This file is part of the Voledia SDK
 *
 * Copyright (c) 2012 Open-Silicon Inc.
 *
 * This file is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License, Version 2, as published by the Free Software Foundation.
 *
 * This file is distributed in the hope that it will be useful, but AS-IS and WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE, TITLE, or NONINFRINGEMENT. See the GNU
 * General Public License for more details.
 *
 * This file may also be available under a different license from Open-Silicon.
 * Contact Open-Silicon for more information
 */

#ifndef _PSE_OSDEP_H_
#define _PSE_OSDEP_H_

#define PSE_REG_BASE OPV5XC_CR_PSE_PPE_BASE

#if defined(CONFIG_OPV5XC_PSE_ACP_SUPPORT)
#define ACP_DESC
#define ACP_HEADER
#define ACP_PAYLOAD
 #undef ACP_PAYLOAD
#endif

/* Register */
#define wr32(value, reg) (writel(value, pse_base + reg))
#define rd32(reg) (readl(pse_base + reg))

#define fwr32(value, reg) (writel(value, pse_base_fast + reg))
#define frd32(reg) (readl(pse_base_fast + reg))



#if defined(ACP_DESC)
#define pse_desc_dma_alloc(d, s, h, f)	dma_alloc_coherent(d, s, h, f)
#define pse_desc_dma_free(d, s, h, f)	dma_free_coherent(d, s, h, f)
#else
#define pse_desc_dma_alloc(d, s, h, f)	dma_alloc_coherent(NULL, s, h, f)
#define pse_desc_dma_free(d, s, h, f)	dma_free_coherent(NULL, s, h, f)
#endif

#if defined(ACP_HEADER)
#define pse_dma_map_single(d, a, s, r) dma_map_single(d, a, s, r)
#define pse_dma_unmap_single(d, a, s, r) dma_unmap_single(d, a, s, r)
#define pse_dma_map_page(d, p, o, s, r) dma_map_page(d, p, o, s, r)
#define pse_dma_unmap_page(d, a, s, r) dma_unmap_page(d, a, s, r)
#define pse_skb_frag_dma_map(d, f, o, s, r)   skb_frag_dma_map(d, f, o, s, r)
#else
#define pse_dma_map_single(d, a, s, r) dma_map_single(NULL, a, s, r)
#define pse_dma_unmap_single(d, a, s, r) dma_unmap_single(NULL, a, s, r)
#define pse_dma_map_page(d, p, o, s, r) dma_map_page(NULL, p, o, s, r)
#define pse_dma_unmap_page(d, a, s, r) dma_unmap_page(NULL, a, s, r)
#define pse_skb_frag_dma_map(d, f, o, s, r)   skb_frag_dma_map(NULL, f, o, s, r)
#endif

#if defined(ACP_PAYLOAD)
#define pse_payload_dma_map_page(d, p, o, s, r) dma_map_page(d, p, o, s, r)
#define pse_payload_dma_unmap_page(d, a, s, r) dma_unmap_page(d, a, s, r)
#else
#define pse_payload_dma_map_page(d, p, o, s, r) dma_map_page(NULL, p, o, s, r)
#define pse_payload_dma_unmap_page(d, a, s, r) dma_unmap_page(NULL, a, s, r)
#endif

#endif /* _PSE_OSDEP_H_ */
