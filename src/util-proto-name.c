/* Copyright (C) 2007-2022 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * File to provide the protocol names based on protocol numbers defined by the
 * IANA
 */

#include "suricata-common.h"
#include "util-hash-string.h"
#include "util-proto-name.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#endif

/** Lookup array to hold the information related to known protocol
 *  values
 */

const char *known_proto[256] = {
    "HOPOPT",   /* 0x00: 0 - IPv6 Hop-by-Hop Option	RFC 8200 */
    "ICMP",     /* 0x01: 1 - Internet Control Message Protocol	RFC 792 */
    "IGMP",     /* 0x02: 2 - Internet Group Management Protocol	RFC 1112 */
    "GGP",      /* 0x03: 3 - Gateway-to-Gateway Protocol	RFC 823 */
    "IP-in-IP", /* 0x04: 4 - IP in IP (encapsulation)	RFC 2003 */
    "ST",       /* 0x05: 5 - Internet Stream Protocol	RFC 1190, RFC 1819 */
    "TCP",      /* 0x06: 6 - Transmission Control Protocol	RFC 793 */
    "CBT",      /* 0x07: 7 - Core-based trees	RFC 2189 */
    "EGP",      /* 0x08: 8 - Exterior Gateway Protocol	RFC 888 */
    "IGP", /* 0x09: 9 - Interior Gateway Protocol (any private interior gateway, for example Cisco's
              IGRP) */
    "BBN-RCC-MON", /* 0x0A: 10 - BBN RCC Monitoring */
    "NVP-II",      /* 0x0B: 11 - Network Voice Protocol	RFC 741 */
    "PUP",         /* 0x0C: 12 - Xerox PUP */
    "ARGUS",       /* 0x0D: 13 - ARGUS */
    "EMCON",       /* 0x0E: 14 - EMCON */
    "XNET",        /* 0x0F: 15 - Cross Net Debugger	IEN 158[2] */
    "CHAOS",       /* 0x10: 16 - Chaos */
    "UDP",         /* 0x11: 17 - User Datagram Protocol	RFC 768 */
    "MUX",         /* 0x12: 18 - Multiplexing	IEN 90[3] */
    "DCN-MEAS",    /* 0x13: 19 - DCN Measurement Subsystems */
    "HMP",         /* 0x14: 20 - Host Monitoring Protocol	RFC 869 */
    "PRM",         /* 0x15: 21 - Packet Radio Measurement */
    "XNS-IDP",     /* 0x16: 22 - XEROX NS IDP */
    "TRUNK-1",     /* 0x17: 23 - Trunk-1 */
    "TRUNK-2",     /* 0x18: 24 - Trunk-2 */
    "LEAF-1",      /* 0x19: 25 - Leaf-1 */
    "LEAF-2",      /* 0x1A: 26 - Leaf-2 */
    "RDP",         /* 0x1B: 27 - Reliable Data Protocol	RFC 908 */
    "IRTP",        /* 0x1C: 28 - Internet Reliable Transaction Protocol	RFC 938 */
    "ISO-TP4",     /* 0x1D: 29 - ISO Transport Protocol Class 4	RFC 905 */
    "NETBLT",      /* 0x1E: 30 - Bulk Data Transfer Protocol	RFC 998 */
    "MFE-NSP",     /* 0x1F: 31 - MFE Network Services Protocol */
    "MERIT-INP",   /* 0x20: 32 - MERIT Internodal Protocol */
    "DCCP",        /* 0x21: 33 - Datagram Congestion Control Protocol	RFC 4340 */
    "3PC",         /* 0x22: 34 - Third Party Connect Protocol */
    "IDPR",        /* 0x23: 35 - Inter-Domain Policy Routing Protocol	RFC 1479 */
    "XTP",         /* 0x24: 36 - Xpress Transport Protocol */
    "DDP",         /* 0x25: 37 - Datagram Delivery Protocol */
    "IDPR-CMTP",   /* 0x26: 38 - IDPR Control Message Transport Protocol */
    "TP++",        /* 0x27: 39 - TP++ Transport Protocol */
    "IL",          /* 0x28: 40 - IL Transport Protocol */
    "IPv6",        /* 0x29: 41 - IPv6 Encapsulation	RFC 2473 */
    "SDRP",        /* 0x2A: 42 - Source Demand Routing Protocol	RFC 1940 */
    "IPv6-Route",  /* 0x2B: 43 - Routing Header for IPv6	RFC 8200 */
    "IPv6-Frag",   /* 0x2C: 44 - Fragment Header for IPv6	RFC 8200 */
    "IDRP",        /* 0x2D: 45 - Inter-Domain Routing Protocol */
    "RSVP",        /* 0x2E: 46 - Resource Reservation Protocol	RFC 2205 */
    "GRE",         /* 0x2F: 47 - Generic Routing Encapsulation	RFC 2784, RFC 2890 */
    "DSR",         /* 0x30: 48 - Dynamic Source Routing Protocol	RFC 4728 */
    "BNA",         /* 0x31: 49 - Burroughs Network Architecture */
    "ESP",         /* 0x32: 50 - Encapsulating Security Payload	RFC 4303 */
    "AH",          /* 0x33: 51 - Authentication Header	RFC 4302 */
    "I-NLSP",      /* 0x34: 52 - Integrated Net Layer Security Protocol	TUBA */
    "SwIPe",       /* 0x35: 53 - SwIPe	RFC 5237 */
    "NARP",        /* 0x36: 54 - NBMA Address Resolution Protocol	RFC 1735 */
    "MOBILE",      /* 0x37: 55 - IP Mobility (Min Encap)	RFC 2004 */
    "TLSP",      /* 0x38: 56 - Transport Layer Security Protocol (using Kryptonet key management) */
    "SKIP",      /* 0x39: 57 - Simple Key-Management for Internet Protocol	RFC 2356 */
    "IPv6-ICMP", /* 0x3A: 58 - ICMP for IPv6	RFC 4443, RFC 4884 */
    "IPv6-NoNxt",  /* 0x3B: 59 - No Next Header for IPv6	RFC 8200 */
    "IPv6-Opts",   /* 0x3C: 60 - Destination Options for IPv6	RFC 8200 */
    "Any",         /* 0x3D: 61 - host internal protocol */
    "CFTP",        /* 0x3E: 62 - CFTP */
    "Any",         /* 0x3F: 63 - local network */
    "SAT-EXPAK",   /* 0x40: 64 - SATNET and Backroom EXPAK */
    "KRYPTOLAN",   /* 0x41: 65 - Kryptolan */
    "RVD",         /* 0x42: 66 - MIT Remote Virtual Disk Protocol */
    "IPPC",        /* 0x43: 67 - Internet Pluribus Packet Core */
    "Any",         /* 0x44: 68 - distributed file system */
    "SAT-MON",     /* 0x45: 69 - SATNET Monitoring */
    "VISA",        /* 0x46: 70 - VISA Protocol */
    "IPCU",        /* 0x47: 71 - Internet Packet Core Utility */
    "CPNX",        /* 0x48: 72 - Computer Protocol Network Executive */
    "CPHB",        /* 0x49: 73 - Computer Protocol Heart Beat */
    "WSN",         /* 0x4A: 74 - Wang Span Network */
    "PVP",         /* 0x4B: 75 - Packet Video Protocol */
    "BR-SAT-MON",  /* 0x4C: 76 - Backroom SATNET Monitoring */
    "SUN-ND",      /* 0x4D: 77 - SUN ND PROTOCOL-Temporary */
    "WB-MON",      /* 0x4E: 78 - WIDEBAND Monitoring */
    "WB-EXPAK",    /* 0x4F: 79 - WIDEBAND EXPAK */
    "ISO-IP",      /* 0x50: 80 - International Organization for Standardization Internet Protocol */
    "VMTP",        /* 0x51: 81 - Versatile Message Transaction Protocol	RFC 1045 */
    "SECURE-VMTP", /* 0x52: 82 - Secure Versatile Message Transaction Protocol	RFC 1045 */
    "VINES",       /* 0x53: 83 - VINES */
    "TTP",         /* 0x54: 84 - TTP */
    "NSFNET-IGP",  /* 0x55: 85 - NSFNET-IGP */
    "DGP",         /* 0x56: 86 - Dissimilar Gateway Protocol */
    "TCF",         /* 0x57: 87 - TCF */
    "EIGRP",       /* 0x58: 88 - EIGRP	Informational RFC 7868 */
    "OSPF",        /* 0x59: 89 - Open Shortest Path First	RFC 2328 */
    "Sprite-RPC",  /* 0x5A: 90 - Sprite RPC Protocol */
    "LARP",        /* 0x5B: 91 - Locus Address Resolution Protocol */
    "MTP",         /* 0x5C: 92 - Multicast Transport Protocol */
    "AX.25",       /* 0x5D: 93 - AX.25 */
    "OS",          /* 0x5E: 94 - KA9Q NOS compatible IP over IP tunneling */
    "MICP",        /* 0x5F: 95 - Mobile Internetworking Control Protocol */
    "SCC-SP",      /* 0x60: 96 - Semaphore Communications Sec. Pro */
    "ETHERIP",     /* 0x61: 97 - Ethernet-within-IP Encapsulation	RFC 3378 */
    "ENCAP",       /* 0x62: 98 - Encapsulation Header	RFC 1241 */
    "Any",         /* 0x63: 99 - private encryption scheme */
    "GMTP",        /* 0x64: 100 - GMTP */
    "IFMP",        /* 0x65: 101 - Ipsilon Flow Management Protocol */
    "PNNI",        /* 0x66: 102 - PNNI over IP */
    "PIM",         /* 0x67: 103 - Protocol Independent Multicast */
    "ARIS",        /* 0x68: 104 - IBM's ARIS (Aggregate Route IP Switching) Protocol */
    "SCPS",        /* 0x69: 105 - SCPS (Space Communications Protocol Standards)	SCPS-TP[4] */
    "QNX",         /* 0x6A: 106 - QNX */
    "A/N",         /* 0x6B: 107 - Active Networks */
    "IPComp",      /* 0x6C: 108 - IP Payload Compression Protocol	RFC 3173 */
    "SNP",         /* 0x6D: 109 - Sitara Networks Protocol */
    "Compaq-Peer", /* 0x6E: 110 - Compaq Peer Protocol */
    "IPX-in-IP",   /* 0x6F: 111 - IPX in IP */
    "VRRP",  /* 0x70: 112 - Virtual Router Redundancy Protocol, Common Address Redundancy Protocol
                (not IANA assigned)	VRRP:RFC 3768 */
    "PGM",   /* 0x71: 113 - PGM Reliable Transport Protocol	RFC 3208 */
    "Any",   /* 0x72: 114 - 0-hop protocol */
    "L2TP",  /* 0x73: 115 - Layer Two Tunneling Protocol Version 3	RFC 3931 */
    "DDX",   /* 0x74: 116 - D-II Data Exchange (DDX) */
    "IATP",  /* 0x75: 117 - Interactive Agent Transfer Protocol */
    "STP",   /* 0x76: 118 - Schedule Transfer Protocol */
    "SRP",   /* 0x77: 119 - SpectraLink Radio Protocol */
    "UTI",   /* 0x78: 120 - Universal Transport Interface Protocol */
    "SMP",   /* 0x79: 121 - Simple Message Protocol */
    "SM",    /* 0x7A: 122 - Simple Multicast Protocol	draft-perlman-simple-multicast-03 */
    "PTP",   /* 0x7B: 123 - Performance Transparency Protocol */
    "IS-IS", /* 0x7C: 124 - over IPv4	Intermediate System to Intermediate System (IS-IS) Protocol
                over IPv4	RFC 1142 and RFC 1195 */
    "FIRE",  /* 0x7D: 125 - Flexible Intra-AS Routing Environment */
    "CRTP",  /* 0x7E: 126 - Combat Radio Transport Protocol */
    "CRUDP", /* 0x7F: 127 - Combat Radio User Datagram */
    "SSCOPMCE", /* 0x80: 128 - Service-Specific Connection-Oriented Protocol in a Multilink and
                   Connectionless Environment	ITU-T Q.2111 (1999) */
    "IPLT",     /* 0x81: 129 -  */
    "SPS",      /* 0x82: 130 - Secure Packet Shield */
    "PIPE",     /* 0x83: 131 - Private IP Encapsulation within IP	Expired I-D
                   draft-petri-mobileip-pipe-00.txt */
    "SCTP",     /* 0x84: 132 - Stream Control Transmission Protocol	RFC 4960 */
    "FC",       /* 0x85: 133 - Fibre Channel */
    "RSVP-E2E-IGNORE", /* 0x86: 134 - Reservation Protocol (RSVP) End-to-End Ignore	RFC 3175 */
    "Mobility",        /* 0x87: 135 - Header	Mobility Extension Header for IPv6	RFC 6275 */
    "UDPLite",         /* 0x88: 136 - Lightweight User Datagram Protocol	RFC 3828 */
    "MPLS-in-IP",      /* 0x89: 137 - Multiprotocol Label Switching Encapsulated in IP	RFC 4023,
                          RFC      5332 */
    "manet",           /* 0x8A: 138 - MANET Protocols	RFC 5498 */
    "HIP",             /* 0x8B: 139 - Host Identity Protocol	RFC 5201 */
    "Shim6",           /* 0x8C: 140 - Site Multihoming by IPv6 Intermediation	RFC 5533 */
    "WESP",            /* 0x8D: 141 - Wrapped Encapsulating Security Payload	RFC 5840 */
    "ROHC",            /* 0x8E: 142 - Robust Header Compression	RFC 5856 */
    "Ethernet" /* 0x8F: 143 - IPv6 Segment Routing (TEMPORARY - registered 2020-01-31, expires
                  2021-01-31) */
};

/*
 * Protocol name aliases
 */
const char *proto_aliases[256] = {
    "ip",      /* 0x00: 0 - IPv6 Hop-by-Hop Option	RFC 8200 */
    "icmp",    /* 0x01: 1 - Internet Control Message Protocol	RFC 792 */
    "igmp",    /* 0x02: 2 - Internet Group Management Protocol	RFC 1112 */
    "ggp",     /* 0x03: 3 - Gateway-to-Gateway Protocol	RFC 823 */
    "ipencap", /* 0x04: 4 - IP in IP (encapsulation)	RFC 2003 */
    "st",      /* 0x05: 5 - Internet Stream Protocol	RFC 1190, RFC 1819 */
    "tcp",     /* 0x06: 6 - Transmission Control Protocol	RFC 793 */
    NULL,      /* 0x07: 7 - Core-based trees	RFC 2189 */
    "egp",     /* 0x08: 8 - Exterior Gateway Protocol	RFC 888 */
    "igp", /* 0x09: 9 - Interior Gateway Protocol (any private interior gateway, for example Cisco's
         IGRP) */
    NULL,  /* 0x0A: 10 - BBN RCC Monitoring */
    NULL,  /* 0x0B: 11 - Network Voice Protocol	RFC 741 */
    "pup", /* 0x0C: 12 - Xerox PUP */
    NULL,  /* 0x0D: 13 - ARGUS */
    NULL,  /* 0x0E: 14 - EMCON */
    NULL,  /* 0x0F: 15 - Cross Net Debugger	IEN 158[2] */
    NULL,  /* 0x10: 16 - Chaos */
    "udp", /* 0x11: 17 - User Datagram Protocol	RFC 768 */
    NULL,  /* 0x12: 18 - Multiplexing	IEN 90[3] */
    NULL,  /* 0x13: 19 - DCN Measurement Subsystems */
    "hmp", /* 0x14: 20 - Host Monitoring Protocol	RFC 869 */
    NULL,  /* 0x15: 21 - Packet Radio Measurement */
    "xns-idp",    /* 0x16: 22 - XEROX NS IDP */
    NULL,         /* 0x17: 23 - Trunk-1 */
    NULL,         /* 0x18: 24 - Trunk-2 */
    NULL,         /* 0x19: 25 - Leaf-1 */
    NULL,         /* 0x1A: 26 - Leaf-2 */
    "rdp",        /* 0x1B: 27 - Reliable Data Protocol	RFC 908 */
    NULL,         /* 0x1C: 28 - Internet Reliable Transaction Protocol	RFC 938 */
    "iso-tp4",    /* 0x1D: 29 - ISO Transport Protocol Class 4	RFC 905 */
    NULL,         /* 0x1E: 30 - Bulk Data Transfer Protocol	RFC 998 */
    NULL,         /* 0x1F: 31 - MFE Network Services Protocol */
    NULL,         /* 0x20: 32 - MERIT Internodal Protocol */
    "dccp",       /* 0x21: 33 - Datagram Congestion Control Protocol	RFC 4340 */
    NULL,         /* 0x22: 34 - Third Party Connect Protocol */
    NULL,         /* 0x23: 35 - Inter-Domain Policy Routing Protocol	RFC 1479 */
    "xtp",        /* 0x24: 36 - Xpress Transport Protocol */
    "ddp",        /* 0x25: 37 - Datagram Delivery Protocol */
    "idpr-cmtp",  /* 0x26: 38 - IDPR Control Message Transport Protocol */
    NULL,         /* 0x27: 39 - TP++ Transport Protocol */
    NULL,         /* 0x28: 40 - IL Transport Protocol */
    "ipV6",       /* 0x29: 41 - IPv6 Encapsulation	RFC 2473 */
    NULL,         /* 0x2A: 42 - Source Demand Routing Protocol	RFC 1940 */
    "ipv6-route", /* 0x2B: 43 - Routing Header for IPv6	RFC 8200 */
    "ipv6-frag",  /* 0x2C: 44 - Fragment Header for IPv6	RFC 8200 */
    "idrp",       /* 0x2D: 45 - Inter-Domain Routing Protocol */
    "rsvp",       /* 0x2E: 46 - Resource Reservation Protocol	RFC 2205 */
    "gre",        /* 0x2F: 47 - Generic Routing Encapsulation	RFC 2784, RFC 2890 */
    NULL,         /* 0x30: 48 - Dynamic Source Routing Protocol	RFC 4728 */
    NULL,         /* 0x31: 49 - Burroughs Network Architecture */
    "esp",        /* 0x32: 50 - Encapsulating Security Payload	RFC 4303 */
    "ah",         /* 0x33: 51 - Authentication Header	RFC 4302 */
    NULL,         /* 0x34: 52 - Integrated Net Layer Security Protocol	TUBA */
    NULL,         /* 0x35: 53 - SwIPe	RFC 5237 */
    NULL,         /* 0x36: 54 - NBMA Address Resolution Protocol	RFC 1735 */
    NULL,         /* 0x37: 55 - IP Mobility (Min Encap)	RFC 2004 */
    NULL,        /* 0x38: 56 - Transport Layer Security Protocol (using Kryptonet key management) */
    "skip",      /* 0x39: 57 - Simple Key-Management for Internet Protocol	RFC 2356 */
    "ipv6-icmp", /* 0x3A: 58 - ICMP for IPv6	RFC 4443, RFC 4884 */
    "ipv6-nonxt", /* 0x3B: 59 - No Next Header for IPv6	RFC 8200 */
    "ipv6-opts",  /* 0x3C: 60 - Destination Options for IPv6	RFC 8200 */
    NULL,         /* 0x3D: 61 - host internal protocol */
    NULL,         /* 0x3E: 62 - CFTP */
    NULL,         /* 0x3F: 63 - local network */
    NULL,         /* 0x40: 64 - SATNET and Backroom EXPAK */
    NULL,         /* 0x41: 65 - Kryptolan */
    NULL,         /* 0x42: 66 - MIT Remote Virtual Disk Protocol */
    NULL,         /* 0x43: 67 - Internet Pluribus Packet Core */
    NULL,         /* 0x44: 68 - distributed file system */
    NULL,         /* 0x45: 69 - SATNET Monitoring */
    NULL,         /* 0x46: 70 - VISA Protocol */
    NULL,         /* 0x47: 71 - Internet Packet Core Utility */
    NULL,         /* 0x48: 72 - Computer Protocol Network Executive */
    "cphb",       /* 0x49: 73 - Computer Protocol Heart Beat */
    NULL,         /* 0x4A: 74 - Wang Span Network */
    NULL,         /* 0x4B: 75 - Packet Video Protocol */
    NULL,         /* 0x4C: 76 - Backroom SATNET Monitoring */
    NULL,         /* 0x4D: 77 - SUN ND PROTOCOL-Temporary */
    NULL,         /* 0x4E: 78 - WIDEBAND Monitoring */
    NULL,         /* 0x4F: 79 - WIDEBAND EXPAK */
    NULL,         /* 0x50: 80 - International Organization for Standardization Internet Protocol */
    "vmtp",       /* 0x51: 81 - Versatile Message Transaction Protocol	RFC 1045 */
    NULL,         /* 0x52: 82 - Secure Versatile Message Transaction Protocol	RFC 1045 */
    NULL,         /* 0x53: 83 - VINES */
    NULL,         /* 0x54: 84 - TTP */
    NULL,         /* 0x55: 85 - NSFNET-IGP */
    NULL,         /* 0x56: 86 - Dissimilar Gateway Protocol */
    NULL,         /* 0x57: 87 - TCF */
    "eigrp",      /* 0x58: 88 - EIGRP	Informational RFC 7868 */
    "ospf",       /* 0x59: 89 - Open Shortest Path First	RFC 2328 */
    NULL,         /* 0x5A: 90 - Sprite RPC Protocol */
    NULL,         /* 0x5B: 91 - Locus Address Resolution Protocol */
    NULL,         /* 0x5C: 92 - Multicast Transport Protocol */
    "ax.25",      /* 0x5D: 93 - AX.25 */
    "ipip",       /* 0x5E: 94 - KA9Q NOS compatible IP over IP tunneling */
    NULL,         /* 0x5F: 95 - Mobile Internetworking Control Protocol */
    NULL,         /* 0x60: 96 - Semaphore Communications Sec. Pro */
    "etherip",    /* 0x61: 97 - Ethernet-within-IP Encapsulation	RFC 3378 */
    "encap",      /* 0x62: 98 - Encapsulation Header	RFC 1241 */
    NULL,         /* 0x63: 99 - private encryption scheme */
    "GMTP",       /* 0x64: 100 - GMTP */
    NULL,         /* 0x65: 101 - Ipsilon Flow Management Protocol */
    NULL,         /* 0x66: 102 - PNNI over IP */
    "pim",        /* 0x67: 103 - Protocol Independent Multicast */
    NULL,         /* 0x68: 104 - IBM's ARIS (Aggregate Route IP Switching) Protocol */
    NULL,         /* 0x69: 105 - SCPS (Space Communications Protocol Standards)	SCPS-TP[4] */
    NULL,         /* 0x6A: 106 - QNX */
    NULL,         /* 0x6B: 107 - Active Networks */
    "ipcomp",     /* 0x6C: 108 - IP Payload Compression Protocol	RFC 3173 */
    NULL,         /* 0x6D: 109 - Sitara Networks Protocol */
    NULL,         /* 0x6E: 110 - Compaq Peer Protocol */
    NULL,         /* 0x6F: 111 - IPX in IP */
    "vrrp", /* 0x70: 112 - Virtual Router Redundancy Protocol, Common Address Redundancy Protocol
            (not IANA assigned)	VRRP:RFC 3768 */
    NULL,   /* 0x71: 113 - PGM Reliable Transport Protocol	RFC 3208 */
    NULL,   /* 0x72: 114 - 0-hop protocol */
    "l2tp", /* 0x73: 115 - Layer Two Tunneling Protocol Version 3	RFC 3931 */
    NULL,   /* 0x74: 116 - D-II Data Exchange (DDX) */
    NULL,   /* 0x75: 117 - Interactive Agent Transfer Protocol */
    NULL,   /* 0x76: 118 - Schedule Transfer Protocol */
    NULL,   /* 0x77: 119 - SpectraLink Radio Protocol */
    NULL,   /* 0x78: 120 - Universal Transport Interface Protocol */
    NULL,   /* 0x79: 121 - Simple Message Protocol */
    NULL,   /* 0x7A: 122 - Simple Multicast Protocol	draft-perlman-simple-multicast-03 */
    NULL,   /* 0x7B: 123 - Performance Transparency Protocol */
    "isis", /* 0x7C: 124 - over IPv4	Intermediate System to Intermediate System (IS-IS) Protocol
            over IPv4	RFC 1142 and RFC 1195 */
    NULL,   /* 0x7D: 125 - Flexible Intra-AS Routing Environment */
    NULL,   /* 0x7E: 126 - Combat Radio Transport Protocol */
    NULL,   /* 0x7F: 127 - Combat Radio User Datagram */
    NULL,   /* 0x80: 128 - Service-Specific Connection-Oriented Protocol in a Multilink and
               Connectionless Environment	ITU-T Q.2111 (1999) */
    NULL,   /* 0x81: 129 -  */
    NULL,   /* 0x82: 130 - Secure Packet Shield */
    NULL,   /* 0x83: 131 - Private IP Encapsulation within IP	Expired I-D
               draft-petri-mobileip-pipe-00.txt */
    "sctp", /* 0x84: 132 - Stream Control Transmission Protocol	RFC 4960 */
    "fc",   /* 0x85: 133 - Fibre Channel */
    NULL,   /* 0x86: 134 - Reservation Protocol (RSVP) End-to-End Ignore	RFC 3175 */
    "mobility-header", /* 0x87: 135 - Header	Mobility Extension Header for IPv6	RFC 6275 */
    "udplite",         /* 0x88: 136 - Lightweight User Datagram Protocol	RFC 3828 */
    "mpls-in-ip",      /* 0x89: 137 - Multiprotocol Label Switching Encapsulated in IP	RFC 4023,
                                RFC      5332 */
    NULL,              /* 0x8A: 138 - MANET Protocols	RFC 5498 */
    "hip",             /* 0x8B: 139 - Host Identity Protocol	RFC 5201 */
    "shim6",           /* 0x8C: 140 - Site Multihoming by IPv6 Intermediation	RFC 5533 */
    "wesp",            /* 0x8D: 141 - Wrapped Encapsulating Security Payload	RFC 5840 */
    "rohc",            /* 0x8E: 142 - Robust Header Compression	RFC 5856 */
    /* no aliases for 142-255 */
};

typedef struct ProtoNameHashEntry_ {
    const char *name;
    uint8_t number;
} ProtoNameHashEntry;

static HashTable *proto_ht = NULL;

static uint32_t ProtoNameHashFunc(HashTable *ht, void *data, uint16_t datalen)
{
    /*
     * datalen covers the entire struct -- only the proto name is hashed
     * as the proto number is not used for lookups
     */
    ProtoNameHashEntry *p = (ProtoNameHashEntry *)data;
    return StringHashDjb2((uint8_t *)p->name, strlen(p->name)) % ht->array_size;
}

static char ProtoNameHashCompareFunc(void *data1, uint16_t datalen1, void *data2, uint16_t datalen2)
{
    ProtoNameHashEntry *p1 = (ProtoNameHashEntry *)data1;
    ProtoNameHashEntry *p2 = (ProtoNameHashEntry *)data2;

    if (p1 == NULL || p2 == NULL)
        return 0;

    if (p1->name == NULL || p2->name == NULL)
        return 0;

    int len1 = strlen(p1->name);
    int len2 = strlen(p2->name);

    return len1 == len2 && memcmp(p1->name, p2->name, len1) == 0;
}

static void ProtoNameAddEntry(const char *proto_name, const uint8_t proto_number)
{
    ProtoNameHashEntry *proto_ent = SCCalloc(1, sizeof(ProtoNameHashEntry));
    if (!proto_ent) {
        FatalError(SC_ERR_HASH_TABLE_INIT, "Unable to allocate protocol hash entry");
    }

    proto_ent->name = SCStrdup(proto_name);
    if (!proto_ent->name)
        FatalError(SC_ERR_MEM_ALLOC, "Unable to allocate memory for protocol name entries");

    proto_ent->number = proto_number;

    SCLogDebug("new protocol entry: name: \"%s\"; protocol number: %d", proto_ent->name,
            proto_ent->number);
    if (0 != HashTableAdd(proto_ht, proto_ent, 0)) {
        FatalError(SC_ERR_HASH_ADD,
                "Unable to add entry to proto hash table for "
                "name: \"%s\"; number: %d",
                proto_ent->name, proto_ent->number);
    }
    return;
}

static void ProtoNameHashFreeFunc(void *data)
{
    ProtoNameHashEntry *proto_ent = (ProtoNameHashEntry *)data;

    if (proto_ent) {
        if (proto_ent->name)
            SCFree((void *)proto_ent->name);
        SCFree(proto_ent);
    }
}

void SCProtoNameInit(void)
{
    proto_ht =
            HashTableInit(256, ProtoNameHashFunc, ProtoNameHashCompareFunc, ProtoNameHashFreeFunc);
    if (proto_ht == NULL) {
        FatalError(SC_ERR_HASH_TABLE_INIT, "Unable to initialize protocol name/number table");
    }

    for (uint16_t i = 0; i < ARRAY_SIZE(known_proto); i++) {
        if (known_proto[i]) {
            ProtoNameAddEntry(known_proto[i], (uint8_t)i);
        }
    }

    for (uint8_t i = 0;; i++) {
        if (proto_aliases[i]) {
            ProtoNameAddEntry(proto_aliases[i], (uint8_t)i);
        }
        if (i == UINT8_MAX) {
            break;
        }
    }
}

void SCProtoNameRelease(void)
{
    if (proto_ht != NULL) {
        HashTableFree(proto_ht);
        proto_ht = NULL;
    }
}

/**
 * \brief   Function to check if the received protocol number is valid and do
 *          we have corresponding name entry for this number or not.
 *
 * \param proto Protocol number to be validated
 * \retval ret On success returns true otherwise false
 */
bool SCProtoNameValid(uint16_t proto)
{
    return (proto <= 255 && known_proto[proto] != NULL);
}

/**
 * \brief   Function to return the protocol number for a named protocol. Note
 *          that protocol name aliases are honored.
 *
 * \param protoname Protocol name (or alias for a protocol name).
 * \param proto_number Where to return protocol number
 * \retval ret On success returns the protocol number; else -1
 */
bool SCGetProtoByName(const char *protoname, uint8_t *proto_number)
{
    if (!protoname || !proto_number) {
        return false;
    }

    ProtoNameHashEntry proto;
    proto.name = protoname;

    ProtoNameHashEntry *proto_ent = HashTableLookup(proto_ht, &proto, sizeof(proto));
    if (proto_ent) {
        *proto_number = proto_ent->number;
        return true;
    }
    return false;
}

#ifdef UNITTESTS
static int ProtoNameTest01(void)
{
    uint8_t proto;
    FAIL_IF(!SCGetProtoByName("tcp", &proto));
    FAIL_IF(SCGetProtoByName("TcP", &proto));
    FAIL_IF(!SCGetProtoByName("TCP", &proto));
    FAIL_IF(SCGetProtoByName("Invalid", &proto));
    FAIL_IF(!SCGetProtoByName("Ethernet", &proto));

    /* 'ip' is an alias for 'HOPOPT' */
    FAIL_IF(!SCGetProtoByName("ip", &proto));
    FAIL_IF(!SCGetProtoByName("HOPOPT", &proto));

    FAIL_IF(SCGetProtoByName("IP", &proto));

    PASS;
}

void SCProtoNameRegisterTests(void)
{
    UtRegisterTest("ProtoNameTest01", ProtoNameTest01);
}
#endif
