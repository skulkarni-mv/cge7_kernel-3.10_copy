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

#ifndef _PSE_DESC_H_
#define _PSE_DESC_H_

#define PSE_DESC_SIZE_ALIGN  (32) /* 32 bytes*/

/* TS descriptor */
struct pse_ts_desc {
	u32	sdp; /* segment data pointer */

	u16 sdl; /* segment data length */
	u16 tco:1;
	u16 uco:1;
	u16 ico:1; /* IP checksum offload */
	u16 tso:1; /* TCP checksum offload */
	u16 ufo:1; /* UDP checksum offload */
	u16 pri:4; /* forced priority; 15 is highest */
	u16 fp:1; /* force priority */
	u16 fr:1; /* force route */
	u16 intr:1;
	u16 lsd:1; /* last segment descriptor */
	u16 fsd:1; /* first segment descriptor */
	u16 eor:1; /* end of descriptor ring */
	u16 cown:1; /* CPU ownership */

	u16 ctv:1;
	u16 stv:1;
	u16 pmap:6; /* forced port map */
	u16 ssid:4;
	u16 mark:3;
	u16 dec:1; /* decrese preflow1 counter */

	u16 slot;

	u16 cvid:12;
	u16 ccfi:1;
	u16 cpri:3;

	u16 svid:12;
	u16 sdei:1;
	u16 spri:3;

	u32 payload_len:17;

	u32 mss_mtu:13;
	u32 mymac:1; /* my MAC */
	u32 fwan:1; /* from WAN */
	u32 temp;
} __aligned(32);

/* FS descriptor */
struct pse_fs_desc {
	u32 sdp; /* segment data pointer */

	u16 sdl; /* segment data length */
	u16 l4f:1; /* L4 checksum error */
	u16 ipf:1;	/* IP checksum error */
	u16 prot:5;
	u16:5;
	u16 lsd:1;
	u16 fsd:1;
	u16 eor:1;
	u16 cown:1;

	u16 ctv:1;
	u16 stv:1;
	u16 unv:1; /* unknown VLAN */
	u16 utag:1; /* un-tagged VLAN */
	u16 ssid:4;
	u16 sp:3;
	u16 tc:4; /* traffic class */
	u16:1;
	u16 slot;

	u16 cvid:12;
	u16 ccfi:1;
	u16 cpri:3;
	u16 svid:12;
	u16 sdei:1;
	u16 spri:3;

	u32:8;
	u32 pr:10; /* packet reason */
	u32:2;
	u32 l4_offset:7;
	u32 ip_offset:5;

	u32 soft_id;
} __aligned(32);

struct pse_dma_desc {
	u32 sdp; /* segment data pointer */

	u16 sdl; /* segment data length */
	u16 donot_care:12;
	u16 lsd:1;
	u16 fsd:1;
	u16 eor:1;
	u16 cown:1;

	u32 donot_care_dw[6];
};

/* PSE Protocol Encode */
#define PSE_IPV4_H5NF		(0x00) /* */
#define PSE_IPV4_H5NF_UDP	(0x01)
#define PSE_IPV4_H5NF_TCP	(0x02)
#define PSE_IPV4_H5NF_PPTP_GRE	(0x03)
#define PSE_IPV4_H5NF_ESP	(0x04)
#define PSE_IPV4_H5NF_AH	(0x05)
#define PSE_IPV_4H5F		(0x0A)

#define PSE_IPV6_NF		(0x10)
#define PSE_IPV6_NF_UDP		(0x11)
#define PSE_IPV6_NF_TCP		(0x12)
#define PSE_IPV6_NF_PPTP_GRE	(0x13)
#define PSE_IPV6_NF_ESP		(0x14)
#define PSE_IPV6_NF_AH		(0x15)
#define PSE_IPV6_F		(0x1A)

/* source port of extracted packet*/
#define PSE_SOURCE_PORT_MAC0	(0x0)
#define PSE_SOURCE_PORT_MAC1	(0x1)
#define PSE_SOURCE_PORT_CPU	(0x2)
#define PSE_SOURCE_PORT_MAC2	(0x4)

/* PSE forced Port Map*/
#define PSE_PORT_MAC0	(0x01)
#define PSE_PORT_MAC1	(0x02)
#define PSE_PORT_CPU	(0x04)
#define PSE_PORT_PPE	(0x08)
#define PSE_PORT_MAC2	(0x10)
#define PSE_PORT_ALL	(0x1F)




/* TSO/UFO reassembly status */

/* TSO: tso_ufo_sta[7:5] */
#define PSE_TSO_STA_AGING_OUT \
	(0x0 << 5)
#define PSE_TSO_STA_QUEUE_FULL \
	(0x1 << 5) /* queue full or reach max size */
#define PSE_TSO_STA_FLAG \
	(0x2 << 5) /* URG, PSH, RST or FIN */
#define PSE_TSO_STA_ERROR \
	(0x3 << 5) /* error pakcet or out of packet,
					the released reassembly doesn't include
					error packet or out of one */
#define PSE_TSO_STA_ERROR_ITSELF \
	(0x4 << 5) /* error packet itself */

/* TSO: tso_ufo_sta[4:0] */
#define PSE_TSO_STA_NO_ERROR \
	(0x00)
#define PSE_TSO_STA_CHECKSUM_ERROR \
	(0x01)	/* IP checksum or L4 checksum error */
#define PSE_TSO_STA_LENGTH_ERROR \
	(0x10)


/* UFO: tso_ufo_sta[7:5] */
#define PSE_UFO_STA_AGING_OUT \
	(0x0 << 5)
#define PSE_UFO_STA_QUEUE_FULL \
	(0x1 << 5)	/* queue full or reach max size */
#define PSE_UFO_STA_FLAG \
	(0x2 << 5)	/* MF (more fragment) == 0 */
#define PSE_UFO_STA_ERROR \
	(0x3 << 5)	/* error pakcet or out of packet,
					the released reassembly doesn't include
					error packet or out of one */
#define PSE_UFO_STA_ERROR_ITSELF \
	(0x4 << 5)	/* error packet itself*/
/* UFO: tso_ufo_sta[4:0] */
#define PSE_UFO_STA_NO_ERROR		(0x00)
#define PSE_UFO_STA_CHECKSUM_ERROR	(0x01)	/* IP checksum error */
#define PSE_UFO_STA_LENGTH_ERROR	(0x10)

#endif /* _PSE_DESC_H_ */
