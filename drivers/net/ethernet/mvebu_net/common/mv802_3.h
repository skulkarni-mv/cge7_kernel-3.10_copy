/*******************************************************************************
Copyright (C) Marvell International Ltd. and its affiliates

********************************************************************************
Marvell GPL License Option

If you received this File from Marvell, you may opt to use, redistribute and/or
modify this File in accordance with the terms and conditions of the General
Public License Version 2, June 1991 (the "GPL License"), a copy of which is
available along with the File in the license.txt file or by writing to the Free
Software Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 or
on the worldwide web at http://www.gnu.org/licenses/gpl.txt.

THE FILE IS DISTRIBUTED AS-IS, WITHOUT WARRANTY OF ANY KIND, AND THE IMPLIED
WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE ARE EXPRESSLY
DISCLAIMED.  The GPL License provides additional details about this warranty
disclaimer.

*******************************************************************************/

#ifndef __INCmv802_3h
#define __INCmv802_3h

/* includes */
#include "mvTypes.h"

/* Defines */
#define MV_MAX_ETH_DATA     1500
#define MV_ETH_MH_SIZE      2
#define MV_ETH_DSA_SIZE     4
#define MV_ETH_EDSA_SIZE    8
#define MV_ETH_VLAN_SIZE    4
#define MV_ETH_CRC_SIZE     4

/* Marvell tag types */
typedef enum {
	MV_TAG_TYPE_NONE = 0,
	MV_TAG_TYPE_MH   = 1,
	MV_TAG_TYPE_DSA  = 2,
	MV_TAG_TYPE_EDSA = 3,
	MV_TAG_TYPE_VLAN = 4,
	MV_TAG_TYPE_LAST = 5
} MV_TAG_TYPE;

typedef union mv_tag {
	MV_U32 edsa[2];
	MV_U32 dsa;
	MV_U32 vlan;
	MV_U16 mh;
} MV_TAG;

typedef struct mv_mux_tag {
	MV_TAG_TYPE tag_type;
	MV_TAG tx_tag;
	MV_TAG rx_tag_ptrn;
	MV_TAG rx_tag_mask;
	MV_BOOL leave_tag;
	MV_U16 proto_type;
} MV_MUX_TAG;

typedef enum {
	MV_PRESET_TRANSPARENT    = 0,
	MV_PRESET_SINGLE_VLAN    = 1,
	MV_PRESET_PER_PORT_VLAN  = 2,
} MV_SWITCH_PRESET_TYPE;

/* 802.3 types */
#define MV_IP_TYPE                  0x0800
#define MV_IP_ARP_TYPE              0x0806
#define MV_IP_LBDT_TYPE             0xfffa
#define MV_IP6_TYPE                 0x86dd
#define MV_APPLE_TALK_ARP_TYPE      0x80F3
#define MV_NOVELL_IPX_TYPE          0x8137
#define MV_EAPOL_TYPE               0x888e
#define MV_VLAN_TYPE                0x8100
#define MV_VLAN_1_TYPE              0x88A8
#define MV_PPPOE_TYPE               0x8864

/* PPPoE protocol type */
#define MV_IP_PPP  0x0021
#define MV_IP6_PPP 0x0057
/* Encapsulation header for RFC1042 and Ethernet_tunnel */

#define MV_RFC1042_SNAP_HEADER     { 0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00 }

#define MV_ETH_SNAP_LSB             0xF8

#define MV_MAC_ADDR_SIZE    (6)
#define MV_MAC_STR_SIZE     (20)
#define MV_LLC_HLEN         (6)
#define MV_VLAN_HLEN        (4)
#define MV_ETH_TYPE_LEN     (2)
#define MV_ETH_ALEN         (MV_MAC_ADDR_SIZE + MV_MAC_ADDR_SIZE + MV_ETH_TYPE_LEN)
#define MV_PPP_HDR_SIZE     (2)
#define MV_PPPOE_HDR_SIZE   (8) /* PPP header is 2, PPPoE header is 6 */

/* This macro checks for a multicast mac address    */
#define MV_IS_MULTICAST_MAC(mac)  (((mac)[0] & 0x1) == 1)

/* IPv4 */
#define MV_INET 2
/* IPv6 */
#define MV_INET6 10

#define MV_MAX_IPV4_ADDR_SIZE   (4)
#define MV_MAX_L3_ADDR_SIZE     (16)    /* IPv4: 4, IPv6: 16 */

/* This macro checks for an broadcast mac address     */
#define MV_IS_BROADCAST_MAC(mac)	    \
	(((mac)[0] == 0xFF) &&	     \
	 ((mac)[1] == 0xFF) &&	     \
	 ((mac)[2] == 0xFF) &&	     \
	 ((mac)[3] == 0xFF) &&	     \
	 ((mac)[4] == 0xFF) &&	     \
	 ((mac)[5] == 0xFF))

/* Typedefs */
typedef struct {
	MV_U8 pDA[MV_MAC_ADDR_SIZE];
	MV_U8 pSA[MV_MAC_ADDR_SIZE];
	MV_U16 typeOrLen;

} MV_802_3_HEADER;

/* 8 bytes - PPPoE header + PPP header */
typedef struct {
	MV_U8 version;
	MV_U8 code;
	MV_U16 session;
	MV_U16 len;
	MV_U16 proto;
} PPPoE_HEADER;

enum {
	MV_IP_PROTO_NULL = 0,           /* Dummy protocol for TCP               */
	MV_IP_PROTO_ICMP = 1,           /* Internet Control Message Protocol    */
	MV_IP_PROTO_IGMP = 2,           /* Internet Group Management Protocol   */
	MV_IP_PROTO_IPIP = 4,           /* IPIP tunnels (older KA9Q tunnels use 94) */
	MV_IP_PROTO_TCP = 6,            /* Transmission Control Protocol        */
	MV_IP_PROTO_EGP = 8,            /* Exterior Gateway Protocol            */
	MV_IP_PROTO_PUP = 12,           /* PUP protocol                         */
	MV_IP_PROTO_UDP = 17,           /* User Datagram Protocol               */
	MV_IP_PROTO_IDP = 22,           /* XNS IDP protocol                     */
	MV_IP_PROTO_DCCP = 33,          /* Datagram Congestion Control Protocol */
	MV_IP_PROTO_IPV6 = 41,          /* IPv6-in-IPv4 tunnelling              */
	MV_IP_PROTO_RH = 43,            /* Routing Header protocol              */
	MV_IP_PROTO_FH = 44,            /* Fragment Header protocol             */
	MV_IP_PROTO_RSVP = 46,          /* RSVP protocol                        */
	MV_IP_PROTO_GRE = 47,           /* Cisco GRE tunnels (rfc 1701,1702)    */
	MV_IP_PROTO_ESP = 50,           /* Encapsulation Security Payload protocol */
	MV_IP_PROTO_AH = 51,            /* Authentication Header protocol       */
	MV_IP_PROTO_ICMPV6 = 58, /* Internet Group Management Protocol V6 */
	MV_IP_PROTO_DH = 60,            /* Destination Options Header protocol  */
	MV_IP_PROTO_BEETPH = 94,        /* IP option pseudo header for BEET     */
	MV_IP_PROTO_PIM = 103,
	MV_IP_PROTO_COMP = 108,         /* Compression Header protocol          */
	MV_IP_PROTO_ZERO_HOP = 114,     /* Any 0 hop protocol (IANA)            */
	MV_IP_PROTO_SCTP = 132,         /* Stream Control Transport Protocol    */
	MV_IP_PROTO_MH = 135,           /* Mobility Header protocol             */
	MV_IP_PROTO_UDPLITE = 136,      /* UDP-Lite (RFC 3828)                  */

	MV_IP_PROTO_RAW = 255,          /* Raw IP packets                       */
	MV_IP_PROTO_MAX
};

#define MV_IP4_FRAG_OFFSET_MASK 0x1FFF
#define MV_IP4_DF_FLAG_MASK     0x4000
#define MV_IP4_MF_FLAG_MASK     0x2000

typedef struct {
	MV_U8 version;
	MV_U8 tos;
	MV_U16 totalLength;
	MV_U16 identifier;
	MV_U16 fragmentCtrl;
	MV_U8 ttl;
	MV_U8 protocol;
	MV_U16 checksum;
	MV_U32 srcIP;
	MV_U32 dstIP;

} MV_IP_HEADER;

typedef struct {
	MV_U32 verClassFlow;
	MV_U16 payloadLength;
	MV_U8 protocol;
	MV_U8 hoplimit;
	MV_U8 srcAddr[16];
	MV_U8 dstAddr[16];

} MV_IP6_HEADER;

typedef struct {
	int family;
	int ipOffset;
	int ipHdrLen;
	MV_U16 ipLen;
	MV_U8 ipProto;
	MV_U8 reserved;
	union {
		char          *l3;
		MV_IP_HEADER  *ip4;
		MV_IP6_HEADER *ip6;
	} ip_hdr;
} MV_IP_HEADER_INFO;

typedef struct {
	MV_U8 protocol;
	MV_U8 length;
	MV_U16 reserverd;
	MV_U32 spi;
	MV_U32 seqNum;
} MV_AH_HEADER;

typedef struct {
	MV_U32 spi;
	MV_U32 seqNum;
} MV_ESP_HEADER;

#define MV_ICMP_ECHOREPLY          0    /* Echo Reply                   */
#define MV_ICMP_DEST_UNREACH       3    /* Destination Unreachable      */
#define MV_ICMP_SOURCE_QUENCH      4    /* Source Quench                */
#define MV_ICMP_REDIRECT           5    /* Redirect (change route)      */
#define MV_ICMP_ECHO               8    /* Echo Request                 */
#define MV_ICMP_TIME_EXCEEDED      11   /* Time Exceeded                */
#define MV_ICMP_PARAMETERPROB      12   /* Parameter Problem            */
#define MV_ICMP_TIMESTAMP          13   /* Timestamp Request            */
#define MV_ICMP_TIMESTAMPREPLY     14   /* Timestamp Reply              */
#define MV_ICMP_INFO_REQUEST       15   /* Information Request          */
#define MV_ICMP_INFO_REPLY         16   /* Information Reply            */
#define MV_ICMP_ADDRESS            17   /* Address Mask Request         */
#define MV_ICMP_ADDRESSREPLY       18   /* Address Mask Reply           */

typedef struct {
	MV_U8 type;
	MV_U8 code;
	MV_U16 checksum;
	MV_U16 id;
	MV_U16 sequence;

} MV_ICMP_ECHO_HEADER;

#define MV_TCP_FLAG_FIN         (1 << 0)
#define MV_TCP_FLAG_RST         (1 << 2)

typedef struct {
	MV_U16 source;
	MV_U16 dest;
	MV_U32 seq;
	MV_U32 ack_seq;
	MV_U16 flags;
	MV_U16 window;
	MV_U16 chksum;
	MV_U16 urg_offset;

} MV_TCP_HEADER;

typedef struct {
	MV_U16 source;
	MV_U16 dest;
	MV_U16 len;
	MV_U16 check;

} MV_UDP_HEADER;

#endif /* __INCmv802_3h */