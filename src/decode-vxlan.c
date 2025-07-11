/* Copyright (C) 2019-2021 Open Information Security Foundation
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
 * \author Henrik Kramshoej <hlk@kramse.org>
 *
 * VXLAN tunneling scheme decoder.
 *
 * This implementation is based on the following specification doc:
 * https://tools.ietf.org/html/rfc7348
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-vxlan.h"
#include "decode-events.h"

#include "detect.h"
#include "detect-engine-port.h"

#include "flow.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

#define VXLAN_HEADER_LEN sizeof(VXLANHeader)

#define VXLAN_MAX_PORTS         4
#define VXLAN_UNSET_PORT        -1
#define VXLAN_DEFAULT_PORT      4789
#define VXLAN_DEFAULT_PORT_S    "4789"

typedef enum {
    VXLAN_RES_CHECK_STRICT = 0,
    VXLAN_RES_CHECK_PERMISSIVE,
} VXLANReservedCheckMode;

static bool g_vxlan_enabled = true;
static int g_vxlan_ports_idx = 0;
static int g_vxlan_ports[VXLAN_MAX_PORTS] = { VXLAN_DEFAULT_PORT, VXLAN_UNSET_PORT,
    VXLAN_UNSET_PORT, VXLAN_UNSET_PORT };
static VXLANReservedCheckMode g_vxlan_reserved_check_mode = VXLAN_RES_CHECK_STRICT;

typedef struct VXLANHeader_ {
    uint8_t flags[2];
    uint16_t gdp;
    uint8_t vni[3];
    uint8_t res;
} VXLANHeader;

bool DecodeVXLANEnabledForPort(const uint16_t dp)
{
    SCLogDebug("checking dest port %u against ports %d %d %d %d", dp, g_vxlan_ports[0],
            g_vxlan_ports[1], g_vxlan_ports[2], g_vxlan_ports[3]);

    if (g_vxlan_enabled) {
        for (int i = 0; i < g_vxlan_ports_idx; i++) {
            if (g_vxlan_ports[i] == VXLAN_UNSET_PORT)
                return false;
            /* RFC 7348: VXLAN identification is based on destination port only */
            if (g_vxlan_ports[i] == (const int)dp)
                return true;
        }
    }
    return false;
}

static void DecodeVXLANConfigPorts(const char *pstr)
{
    SCLogDebug("parsing \'%s\'", pstr);

    DetectPort *head = NULL;
    DetectPortParse(NULL, &head, pstr);

    g_vxlan_ports_idx = 0;
    for (DetectPort *p = head; p != NULL; p = p->next) {
        if (g_vxlan_ports_idx >= VXLAN_MAX_PORTS) {
            SCLogWarning("more than %d VXLAN ports defined", VXLAN_MAX_PORTS);
            break;
        }
        g_vxlan_ports[g_vxlan_ports_idx++] = (int)p->port;
    }

    DetectPortCleanupList(NULL, head);
}

void DecodeVXLANConfig(void)
{
    int enabled = 0;
    if (SCConfGetBool("decoder.vxlan.enabled", &enabled) == 1) {
        if (enabled) {
            g_vxlan_enabled = true;
        } else {
            g_vxlan_enabled = false;
        }
    }

    if (g_vxlan_enabled) {
        SCConfNode *node = SCConfGetNode("decoder.vxlan.ports");
        if (node && node->val) {
            DecodeVXLANConfigPorts(node->val);
        } else {
            DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
        }

        node = SCConfGetNode("decoder.vxlan.reserved-bits-check");
        if (node && node->val) {
            if (strcasecmp(node->val, "strict") == 0) {
                g_vxlan_reserved_check_mode = VXLAN_RES_CHECK_STRICT;
            } else if (strcasecmp(node->val, "permissive") == 0) {
                g_vxlan_reserved_check_mode = VXLAN_RES_CHECK_PERMISSIVE;
            } else {
                SCLogWarning(
                        "Invalid VXLAN reserved-bits-check mode '%s', using 'strict'", node->val);
                g_vxlan_reserved_check_mode = VXLAN_RES_CHECK_STRICT;
            }
        }
    }
}

/** \param pkt payload data directly above UDP header
 *  \param len length in bytes of pkt
 *
 *  \note p->flow is not set yet at this point, so we cannot easily
 *  check if the flow is unidirectional here.
 */
int DecodeVXLAN(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    /* Initial packet validation */
    if (unlikely(!g_vxlan_enabled))
        return TM_ECODE_FAILED;

    if (len < (VXLAN_HEADER_LEN + sizeof(EthernetHdr)))
        return TM_ECODE_FAILED;
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    const VXLANHeader *vxlanh = (const VXLANHeader *)pkt;
    if ((vxlanh->flags[0] & 0x08) == 0)
        return TM_ECODE_FAILED;

    switch (g_vxlan_reserved_check_mode) {
        case VXLAN_RES_CHECK_STRICT:
            if ((vxlanh->flags[0] & 0xF7) != 0 || /* All reserved bits are zero except I bit */
                    vxlanh->flags[1] != 0 ||      /* Second byte should be all zeros */
                    vxlanh->gdp != 0 ||           /* GDP field is reserved in standard VXLAN */
                    vxlanh->res != 0) {           /* Last reserved byte should be zero */
                return TM_ECODE_FAILED;
            }
            break;
        case VXLAN_RES_CHECK_PERMISSIVE:
            break;
    }

#if DEBUG
    uint32_t vni = (vxlanh->vni[0] << 16) + (vxlanh->vni[1] << 8) + (vxlanh->vni[2]);
    SCLogDebug("VXLAN vni %u", vni);
#endif

    /* Increment stats counter for VXLAN packets */
    StatsIncr(tv, dtv->counter_vxlan);

    EthernetHdr *ethh = (EthernetHdr *)(pkt + VXLAN_HEADER_LEN);
    int decode_tunnel_proto = DECODE_TUNNEL_UNSET;

    /* Look at encapsulated Ethernet frame to get next protocol  */
    uint16_t eth_type = SCNtohs(ethh->eth_type);
    SCLogDebug("VXLAN ethertype 0x%04x", eth_type);

    switch (eth_type) {
        case ETHERNET_TYPE_ARP:
            SCLogDebug("VXLAN found ARP");
            break;
        case ETHERNET_TYPE_IP:
            SCLogDebug("VXLAN found IPv4");
            decode_tunnel_proto = DECODE_TUNNEL_IPV4;
            break;
        case ETHERNET_TYPE_IPV6:
            SCLogDebug("VXLAN found IPv6");
            decode_tunnel_proto = DECODE_TUNNEL_IPV6;
            break;
        case ETHERNET_TYPE_VLAN:
        case ETHERNET_TYPE_8021AD:
        case ETHERNET_TYPE_8021QINQ:
            SCLogDebug("VXLAN found VLAN");
            decode_tunnel_proto = DECODE_TUNNEL_VLAN;
            break;
        default:
            SCLogDebug("VXLAN found unsupported Ethertype - expected IPv4, IPv6, VLAN, or ARP");
            ENGINE_SET_INVALID_EVENT(p, VXLAN_UNKNOWN_PAYLOAD_TYPE);
    }

    /* Set-up and process inner packet if it is a supported ethertype */
    if (decode_tunnel_proto != DECODE_TUNNEL_UNSET) {
        Packet *tp = PacketTunnelPktSetup(tv, dtv, p, pkt + VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN,
                len - (VXLAN_HEADER_LEN + ETHERNET_HEADER_LEN), decode_tunnel_proto);
        if (tp != NULL) {
            PKT_SET_SRC(tp, PKT_SRC_DECODER_VXLAN);
            PacketEnqueueNoLock(&tv->decode_pq, tp);
        }
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "conf-yaml-loader.h"

/**
 * \test DecodeVXLANTest01 test a good vxlan header.
 * Contains a DNS request packet.
 */
static int DecodeVXLANtest01 (void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00, /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06,  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF_NOT(PacketIsUDP(tp));
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFreeOrRelease(tp);
    PASS;
}

/**
 * \test DecodeVXLANtest02 tests default port disabled by the config.
 */
static int DecodeVXLANtest02 (void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00, /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11,
        0x44, 0x45, 0x0a, 0x60, 0x00, 0x0a, 0xb9, 0x1b, 0x73, 0x06,  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfigPorts("1");
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    FAIL_IF(tv.decode_pq.top != NULL);

    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S); /* reset */
    FlowShutdown();
    PacketFree(p);
    PASS;
}

/**
 * \test DecodeVXLANtest03 tests the non-zero res field on receiver side.
 * Contains a HTTP response packet.
 */
static int DecodeVXLANtest03(void)
{
    uint8_t raw_vxlan[] = {
        0xc0, 0x00, 0x12, 0xb5, 0x00, 0x57, 0x00, 0x00, /* UDP header */
        0xff, 0x01, 0xd2, 0x0a, 0x00, 0x00, 0x0b, 0x01, /* VXLAN header (res = 0x01) */
        0xfa, 0x16, 0x3e, 0xfe, 0x55, 0x1c,             /* inner destination MAC */
        0xfa, 0x16, 0x3e, 0xfe, 0x57, 0xdc,             /* inner source MAC */
        0x08, 0x00,                                     /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x39, 0xc2, 0xae, 0x40, 0x00, 0x40, 0x06, 0x7e, 0x61, 0xc0, 0xa8, 0x01,
        0x86, 0xda, 0x5e, 0x5d, 0x22, /* IPv4 hdr */
        0x00, 0x50, 0xc8, 0x34, 0xaf, 0xbd, 0x02, 0x16, 0x56, 0xea, 0x3b, 0x41, 0x50, 0x18, 0x00,
        0xee, 0xf9, 0xda, 0x00, 0x00, /* TCP probe src port 80 */
        0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x30, 0x20, 0x32, 0x30, 0x30, 0x20, 0x4f, 0x4b,
        0xd, 0xa /* HTTP response (HTTP/1.0 200 OK\r\n) */
    };
    char config[] = "\
%YAML 1.1\n\
---\n\
decoder:\n\
\n\
  vxlan:\n\
    enabled: true\n\
    ports: \"4789\"\n\
    reserved-bits-check: permissive\n\
";

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfig();
    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF_NOT(PacketIsTCP(tp));
    FAIL_IF_NOT(tp->sp == 80);

    FlowShutdown();
    PacketFree(p);
    PacketFreeOrRelease(tp);
    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

/**
 * \test DecodeVXLANtest04 tests strict mode with standard VXLAN header.
 */
static int DecodeVXLANtest04(void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25, 0x00, /* VXLAN header (strict compliant) */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00,             /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5,             /* inner source MAC */
        0x08, 0x00,                                     /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x44, 0x45, 0x0a, 0x60, 0x00,
        0x0a, 0xb9, 0x1b, 0x73, 0x06,                  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    char config[] = "\
%YAML 1.1\n\
---\n\
decoder:\n\
\n\
  vxlan:\n\
    enabled: true\n\
    ports: \"4789\"\n\
    reserved-bits-check: strict\n\
";

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfig();
    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF_NOT(PacketIsUDP(tp));
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFreeOrRelease(tp);
    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

/**
 * \test DecodeVXLANtest05 tests strict mode with GBP header (should fail).
 */
static int DecodeVXLANtest05(void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x88, 0x00, 0x12, 0x34, 0x00, 0x00, 0x25,
        0x00,                               /* VXLAN-GBP header (G bit set, Group Policy ID) */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00,                         /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x44, 0x45, 0x0a, 0x60, 0x00,
        0x0a, 0xb9, 0x1b, 0x73, 0x06,                  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    char config[] = "\
%YAML 1.1\n\
---\n\
decoder:\n\
\n\
  vxlan:\n\
    enabled: true\n\
    ports: \"4789\"\n\
    reserved-bits-check: strict\n\
";

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfig();
    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    /* Should fail to decode VXLAN in strict mode */
    FAIL_IF(tv.decode_pq.top != NULL);

    FlowShutdown();
    PacketFree(p);
    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

/**
 * \test DecodeVXLANtest06 tests permissive mode with GBP header (should pass).
 */
static int DecodeVXLANtest06(void)
{
    uint8_t raw_vxlan[] = {
        0x12, 0xb5, 0x12, 0xb5, 0x00, 0x3a, 0x87, 0x51, /* UDP header */
        0x88, 0x00, 0x12, 0x34, 0x00, 0x00, 0x25,
        0x00,                               /* VXLAN-GBP header (G bit set, Group Policy ID) */
        0x10, 0x00, 0x00, 0x0c, 0x01, 0x00, /* inner destination MAC */
        0x00, 0x51, 0x52, 0xb3, 0x54, 0xe5, /* inner source MAC */
        0x08, 0x00,                         /* another IPv4 0x0800 */
        0x45, 0x00, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, 0x44, 0x45, 0x0a, 0x60, 0x00,
        0x0a, 0xb9, 0x1b, 0x73, 0x06,                  /* IPv4 hdr */
        0x00, 0x35, 0x30, 0x39, 0x00, 0x08, 0x98, 0xe4 /* UDP probe src port 53 */
    };
    char config[] = "\
%YAML 1.1\n\
---\n\
decoder:\n\
\n\
  vxlan:\n\
    enabled: true\n\
    ports: \"4789\"\n\
    reserved-bits-check: permissive\n\
";

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfig();
    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_vxlan, sizeof(raw_vxlan));
    FAIL_IF_NOT(PacketIsUDP(p));
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF_NOT(PacketIsUDP(tp));
    FAIL_IF_NOT(tp->sp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFreeOrRelease(tp);
    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

/**
 * \test DecodeVXLANtest07 tests that only destination port is checked for VXLAN identification.
 * Source port 4789, destination port 53 DNS query should NOT be VXLAN.
 */
static int DecodeVXLANtest07(void)
{
    uint8_t raw_dns[] = {
        0x12, 0xb5, 0x00, 0x35, 0x00, 0x24, 0xb9, 0xd7, /* UDP header (sp=4789, dp=53) */
        0x49, 0xa1, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x67, 0x6f,
        0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1d, 0x00,
        0x01 /* DNS query (google.com) */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    DecodeVXLANConfigPorts(VXLAN_DEFAULT_PORT_S);
    FlowInitConfig(FLOW_QUIET);

    DecodeUDP(&tv, &dtv, p, raw_dns, sizeof(raw_dns));
    FAIL_IF_NOT(PacketIsUDP(p));

    /* Should not be VXLAN packet, and not invalid packet */
    FAIL_IF(DecodeVXLANEnabledForPort(p->dp));
    FAIL_IF(tv.decode_pq.top != NULL);
    FAIL_IF(p->flags & PKT_IS_INVALID);

    FlowShutdown();
    PacketFree(p);
    PASS;
}
#endif /* UNITTESTS */

void DecodeVXLANRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeVXLANtest01",
                   DecodeVXLANtest01);
    UtRegisterTest("DecodeVXLANtest02",
                   DecodeVXLANtest02);
    UtRegisterTest("DecodeVXLANtest03", DecodeVXLANtest03);
    UtRegisterTest("DecodeVXLANtest04", DecodeVXLANtest04);
    UtRegisterTest("DecodeVXLANtest05", DecodeVXLANtest05);
    UtRegisterTest("DecodeVXLANtest06", DecodeVXLANtest06);
    UtRegisterTest("DecodeVXLANtest07", DecodeVXLANtest07);
#endif /* UNITTESTS */
}
