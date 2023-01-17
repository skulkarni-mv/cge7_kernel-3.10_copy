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

#ifndef _PSE_RING_H_
#define _PSE_RING_H_

struct pse_skb_frag {
	u32 dma;
	u32 length;
};

struct pse_buffer_info {
	struct sk_buff *skb;
	void *desc;
	struct pse_skb_frag frag_array[MAX_SKB_FRAGS + 1];
	u32 frag_count;
};

struct pse_ring {
	u16 ring_id;
	u8 cpu_id;
	u8 pmap;

	void *desc;	/* descriptor ring memory */
	dma_addr_t dma;	/* physical address of descriptor ring */

	u16 ringsz;	/* number of desc. in tx ring */
	u16 pktsz;
	u16 next_to_use;
	u16 next_to_clean;

	spinlock_t lock;
	struct pse_buffer_info *bi; /* array of buffer structure */
	struct napi_struct napi;
	struct net_device *dev;
	unsigned long count;

};

struct __pse_fp_ring {
	struct pse_ring *rx_ring;
	struct pse_ring *tx_ring;
};
#endif /* _PSE_RING_H_ */
