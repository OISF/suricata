/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author Ali Jad Khalil <jadkhal@amazon.com>
 *
 * Geneve tunneling scheme decoder.
 *
 * This implementation is based on the following specification doc:
 * https://tools.ietf.org/html/draft-ietf-nvo3-geneve-16#section-3
 */

#include "suricata-common.h"
#include "decode-geneve.h"

#include "detect-engine-port.h"

#include "util-validate.h"

#ifdef UNITTESTS
#include "host.h"
#include "util-profiling.h"
#include "pkt-var.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "flow.h"
#include "decode-events.h"
#include "decode.h"
#endif
#define VALID_GENEVE_VERSIONS                                                                      \
    {                                                                                              \
        0                                                                                          \
    }
#define GENEVE_VERSION(hdr_ptr)        (hdr_ptr->ver_plus_len >> 6)
#define GENEVE_RESERVED_FLAGS(hdr_ptr) (hdr_ptr->flags & 0x3F)

#define GENEVE_MIN_HEADER_LEN            sizeof(GeneveHeader)
#define GENEVE_TOTAL_OPT_LEN(hdr_ptr)    ((uint8_t)((hdr_ptr->ver_plus_len & 0x3F) << 2))
#define GENEVE_TOTAL_HEADER_LEN(hdr_ptr) (GENEVE_MIN_HEADER_LEN + GENEVE_TOTAL_OPT_LEN(hdr_ptr))

#define GENEVE_MIN_SINGLE_OPT_LEN         sizeof(GeneveOption)
#define GENEVE_SINGLE_OPT_LEN(option_ptr) ((uint8_t)((option_ptr->flags_plus_len & 0x1F) << 2))
#define GENEVE_SINGLE_OPT_TOTAL_LEN(option_ptr)                                                    \
    (GENEVE_MIN_SINGLE_OPT_LEN + GENEVE_SINGLE_OPT_LEN(option_ptr))

#define GENEVE_MAX_PORTS      4
#define GENEVE_UNSET_PORT     -1
#define GENEVE_DEFAULT_PORT   6081
#define GENEVE_DEFAULT_PORT_S "6081"

static bool g_geneve_enabled = true;
static int g_geneve_ports_idx = 0;
static int g_geneve_ports[GENEVE_MAX_PORTS] = { GENEVE_DEFAULT_PORT, GENEVE_UNSET_PORT,
    GENEVE_UNSET_PORT, GENEVE_UNSET_PORT };

/* Geneve structs based on diagrams from the following specification doc:
 *    https://tools.ietf.org/html/draft-ietf-nvo3-geneve-16#section-3 */
typedef struct GeneveOption_ {
    uint16_t option_class;
    uint8_t type;
    uint8_t flags_plus_len;
    uint8_t option_data[0];
} GeneveOption;

typedef struct GeneveHeader_ {
    uint8_t ver_plus_len;
    uint8_t flags;
    uint16_t eth_type;
    uint8_t vni[3];
    uint8_t res;
    GeneveOption options[0];
} GeneveHeader;

bool DecodeGeneveEnabledForPort(const uint16_t sp, const uint16_t dp)
{
    SCLogDebug("ports %u->%u ports %d %d %d %d", sp, dp, g_geneve_ports[0], g_geneve_ports[1],
            g_geneve_ports[2], g_geneve_ports[3]);

    if (g_geneve_enabled) {
        for (int i = 0; i < g_geneve_ports_idx; i++) {
            if (g_geneve_ports[i] == GENEVE_UNSET_PORT)
                return false;

            const int port = g_geneve_ports[i];
            if (port == (const int)sp || port == (const int)dp)
                return true;
        }
    }
    return false;
}

static void DecodeGeneveConfigPorts(const char *pstr)
{
    SCLogDebug("parsing \'%s\'", pstr);

    DetectPort *head = NULL;
    DetectPortParse(NULL, &head, pstr);

    g_geneve_ports_idx = 0;
    for (DetectPort *p = head; p != NULL; p = p->next) {
        if (g_geneve_ports_idx >= GENEVE_MAX_PORTS) {
            SCLogWarning(SC_ERR_INVALID_YAML_CONF_ENTRY, "more than %d Geneve ports defined",
                    GENEVE_MAX_PORTS);
            break;
        }
        g_geneve_ports[g_geneve_ports_idx++] = (int)p->port;
    }

    DetectPortCleanupList(NULL, head);
}

void DecodeGeneveConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.geneve.enabled", &enabled) == 1) {
        if (enabled) {
            g_geneve_enabled = true;
        } else {
            g_geneve_enabled = false;
        }
    }

    if (g_geneve_enabled) {
        ConfNode *node = ConfGetNode("decoder.geneve.ports");
        if (node && node->val) {
            DecodeGeneveConfigPorts(node->val);
        } else {
            DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S);
        }
    }
}

static inline bool IsValidGeneveVersion(const GeneveHeader *geneve_hdr)
{
    const int valid_verisons[] = VALID_GENEVE_VERSIONS;
    const int num_versions = sizeof(valid_verisons) / sizeof(int);
    const uint8_t cur_version = GENEVE_VERSION(geneve_hdr);

    for (int i = 0; i < num_versions; i++) {
        if (valid_verisons[i] == cur_version)
            return true;
    }

    return false;
}

/* Performs a check to ensure that option lens add up to total length specified in the fixed header
 */
static inline bool IsHeaderLengthConsistentWithOptions(const GeneveHeader *geneve_hdr)
{
    uint8_t *geneve_opt_ptr = (uint8_t *)geneve_hdr->options;
    int remaining_hdr_len = GENEVE_TOTAL_OPT_LEN(geneve_hdr);

    while (remaining_hdr_len > 0) {
        const GeneveOption *cur_opt = (const GeneveOption *)geneve_opt_ptr;
        const uint8_t cur_option_len = GENEVE_SINGLE_OPT_TOTAL_LEN(cur_opt);

        geneve_opt_ptr += cur_option_len;
        remaining_hdr_len -=
                cur_option_len; /* cur_option_len will always be between 4-128, inclusive */
    }

    return (remaining_hdr_len == 0);
}

/** \param pkt payload data directly above UDP header
 *  \param len length in bytes of pkt
 */
int DecodeGeneve(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    const GeneveHeader *geneve_hdr = (const GeneveHeader *)pkt;

    uint16_t eth_type, geneve_hdr_len;
    int decode_tunnel_proto = DECODE_TUNNEL_UNSET;

    /* General Geneve packet validation */
    if (unlikely(!g_geneve_enabled))
        return TM_ECODE_FAILED;

    if (unlikely(len < GENEVE_MIN_HEADER_LEN))
        return TM_ECODE_FAILED;
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    /* Specific Geneve header field validation */
    geneve_hdr_len = GENEVE_TOTAL_HEADER_LEN(geneve_hdr);
    if (len < geneve_hdr_len)
        return TM_ECODE_FAILED;

    if (!IsValidGeneveVersion(geneve_hdr))
        return TM_ECODE_FAILED;

    if (GENEVE_RESERVED_FLAGS(geneve_hdr) != 0 || geneve_hdr->res != 0)
        return TM_ECODE_FAILED;

    if (!IsHeaderLengthConsistentWithOptions(geneve_hdr))
        return TM_ECODE_FAILED;

#if DEBUG
    /* Print the VNI for debugging purposes */
    uint32_t vni = (geneve_hdr->vni[0] << 16) + (geneve_hdr->vni[1] << 8) + (geneve_hdr->vni[2]);
    SCLogDebug("Geneve vni %u", vni);
#endif

    /* Increment stats counter for Geneve packets */
    StatsIncr(tv, dtv->counter_geneve);

    /* Determine first protocol encapsulated after Geneve header */
    eth_type = SCNtohs(geneve_hdr->eth_type);
    SCLogDebug("Geneve ethertype 0x%04x", eth_type);

    switch (eth_type) {
        case ETHERNET_TYPE_IP:
            SCLogDebug("Geneve found IPv4");
            decode_tunnel_proto = DECODE_TUNNEL_IPV4;
            break;
        case ETHERNET_TYPE_IPV6:
            SCLogDebug("Geneve found IPv6");
            decode_tunnel_proto = DECODE_TUNNEL_IPV6;
            break;
        case ETHERNET_TYPE_BRIDGE:
            SCLogDebug("Geneve found Ethernet");
            decode_tunnel_proto = DECODE_TUNNEL_ETHERNET;
            break;
        case ETHERNET_TYPE_ARP:
            SCLogDebug("Geneve found ARP");
            break;
        default:
            SCLogDebug(
                    "Geneve found unsupported Ethertype - expected IPv4, IPv6, ARP, or Ethernet");
            ENGINE_SET_INVALID_EVENT(p, GENEVE_UNKNOWN_PAYLOAD_TYPE);
    }

    /* Set-up and process inner packet if it is a supported ethertype */
    if (decode_tunnel_proto != DECODE_TUNNEL_UNSET) {
        Packet *tp = PacketTunnelPktSetup(
                tv, dtv, p, pkt + geneve_hdr_len, len - geneve_hdr_len, decode_tunnel_proto);

        if (tp != NULL) {
            PKT_SET_SRC(tp, PKT_SRC_DECODER_GENEVE);
            PacketEnqueueNoLock(&tv->decode_pq, tp);
        }
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test DecodeGeneveTest01 tests a good Geneve header with 16-bytes of options.
 * Contains a Ethernet+IPv6 DHCP request packet.
 */
static int DecodeGeneveTest01(void)
{
    uint8_t raw_geneve[] = { 0x32, 0x10, 0x17, 0xc1, 0x00, 0xc1, 0x87, 0x51, /* UDP header */
        0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x25, 0x00, /* Geneve fixed header */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11, /* Geneve variable options */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11, /* Geneve variable options */
        0x33, 0x33, 0x00, 0x01, 0x00, 0x02,             /* inner destination MAC */
        0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95,             /* inner source MAC */
        0x86, 0xdd,                                     /* type is IPv6 0x86dd */
        0x60, 0x00, 0x00, 0x00, 0x00, 0x6b, 0x11, 0x01, /* IPv6 hdr */
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x27, 0xff, 0xfe, 0xfe, 0x8f,
        0x95, 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x02, 0x02, 0x22, 0x02, 0x23, 0x00, 0x6b, 0x9c, 0xfb, /* UDP src port 546 */
        0x03, 0x49, 0x17, 0x4e, 0x00, 0x01, 0x00, 0x0e,             /* DHCP request payload */
        0x00, 0x01, 0x00, 0x01, 0x1c, 0x39, 0xcf, 0x88, 0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95, 0x00,
        0x02, 0x00, 0x0e, 0x00, 0x01, 0x00, 0x01, 0x1c, 0x38, 0x25, 0xe8, 0x08, 0x00, 0x27, 0xd4,
        0x10, 0xbb, 0x00, 0x06, 0x00, 0x04, 0x00, 0x17, 0x00, 0x18, 0x00, 0x08, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x19, 0x00, 0x29, 0x27, 0xfe, 0x8f, 0x95, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x00,
        0x15, 0x18, 0x00, 0x1a, 0x00, 0x19, 0x00, 0x00, 0x1c, 0x20, 0x00, 0x00, 0x1d, 0x4c, 0x40,
        0x20, 0x01, 0x00, 0x00, 0x00, 0x00, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_geneve, sizeof(raw_geneve));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->udph == NULL);
    FAIL_IF_NOT(tp->sp == 546);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}

/**
 * \test DecodeGeneveTest02 tests a good Geneve header with 16-bytes of options.
 * Contains a IPv4 DNS request packet.
 */
static int DecodeGeneveTest02(void)
{
    uint8_t raw_geneve[] = {
        0x32, 0x10, 0x17, 0xc1, 0x00, 0x3c, 0x87, 0x51,             /* UDP header */
        0x04, 0x00, 0x08, 0x00, 0x00, 0x00, 0x25, 0x00,             /* Geneve fixed header */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* IPv4 hdr */
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06, 0x00, 0x35, 0x30, 0x39, 0x00,
        0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_geneve, sizeof(raw_geneve));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->udph == NULL);
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}

/**
 * \test DecodeGeneveTest03 tests a good Geneve header with 16-bytes of options.
 * Contains a IPv4 DNS request packet with a VLAN tag after the Ethernet frame.
 * In practice, this probably won't be used but it should be support either way.
 */
static int DecodeGeneveTest03(void)
{
    uint8_t raw_geneve[] = {
        0x32, 0x10, 0x17, 0xc1, 0x00, 0x4e, 0x87, 0x51,             /* UDP header */
        0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x25, 0x00,             /* Geneve fixed header */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x33, 0x33, 0x00, 0x01, 0x00, 0x02,                         /* inner destination MAC */
        0x08, 0x00, 0x27, 0xfe, 0x8f, 0x95,                         /* inner source MAC */
        0x81, 0x00, 0x00, 0xad,                                     /* 802.1Q VLAN tag */
        0x08, 0x00,                                                 /* type is IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* IPv4 hdr */
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06, 0x00, 0x35, 0x30, 0x39, 0x00,
        0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_geneve, sizeof(raw_geneve));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->udph == NULL);
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}

/**
 * \test DecodeGeneveTest04 tests default port disabled by the config.
 */
static int DecodeGeneveTest04(void)
{
    uint8_t raw_geneve[] = {
        0x32, 0x10, 0x17, 0xc1, 0x00, 0x4a, 0x87, 0x51,             /* UDP header */
        0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x25, 0x00,             /* Geneve fixed header */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00,                         /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5,                         /* inner source MAC */
        0x08, 0x00,                                                 /* type is IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* IPv4 hdr */
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06, 0x00, 0x35, 0x30, 0x39, 0x00,
        0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGeneveConfigPorts("1"); /* Set Suricata to use a non-default port for Geneve*/

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_geneve, sizeof(raw_geneve));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top != NULL); /* Geneve packet should not have been processed */

    DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S); /* Reset Geneve port list for future calls */
    FlowShutdown();
    PacketFree(p);
    PASS;
}

/**
 * \test DecodeGeneveTest05 tests if Geneve header has inconsistent option len values.
 */
static int DecodeGeneveTest05(void)
{
    uint8_t raw_geneve[] = {
        0x32, 0x10, 0x17, 0xc1, 0x00, 0x4a, 0x87, 0x51,             /* UDP header */
        0x04, 0x00, 0x65, 0x58, 0x00, 0x00, 0x25, 0x00,             /* Geneve fixed header */
        0x01, 0x08, 0x00, 0x04, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x01, 0x08, 0x00, 0x01, 0x11, 0x11, 0x11, 0x11,             /* Geneve variable options */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00,                         /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5,                         /* inner source MAC */
        0x08, 0x00,                                                 /* type is IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* IPv4 hdr */
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06, 0x00, 0x35, 0x30, 0x39, 0x00,
        0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeGeneveConfigPorts(GENEVE_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_geneve, sizeof(raw_geneve));

    FAIL_IF(p->udph == NULL);
    FAIL_IF(tv.decode_pq.top != NULL); /* Geneve packet should not have been processed */

    FlowShutdown();
    PacketFree(p);
    PASS;
}
#endif /* UNITTESTS */

void DecodeGeneveRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeGeneveTest01 -- Ethernet+IPv6 DHCP Request", DecodeGeneveTest01);
    UtRegisterTest("DecodeGeneveTest02 -- IPv4 DNS Request", DecodeGeneveTest02);
    UtRegisterTest("DecodeGeneveTest03 -- VLAN+IPv4 DNS Request", DecodeGeneveTest03);
    UtRegisterTest("DecodeGeneveTest04 -- Non-standard port configuration", DecodeGeneveTest04);
    UtRegisterTest("DecodeGeneveTest05 -- Inconsistent Geneve hdr option lens", DecodeGeneveTest05);
#endif /* UNITTESTS */
}
