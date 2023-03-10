/*
 * Copyright (C) 2013, Broadcom Corporation. All Rights Reserved.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Broadcom Home Networking Division 10/100 Mbit/s Ethernet
 * Greyhound2 sudo EROM
 *
 */
#include <typedefs.h>

uint32 gh2_erom[] = {
	//#define CC_CORE_ID		0x800		/* chipcommon core */
	0x4bf80001, 0x2a004201, 0x18000005, 0x181200c5,
	//#define	GMAC_CORE_ID		0x82d		/* Gigabit MAC core */
	0x4bf82d01, 0x04004211, 0x00000103, 0x18042005, 0x181100c5,
	0x0000000f
};
