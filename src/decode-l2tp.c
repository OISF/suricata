/* Copyright (C) 2025 Open Information Security Foundation
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
 * \author Damian Poole <poodle@amazon.com>
 *
 * Layer Two Tunneling Protocol (L2TP) Version 3 over IP or UDP decoder.
 *
 * This implementation is based on the following specification docs:
 * https://datatracker.ietf.org/doc/html/rfc3931
 *
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-l2tp.h"
#include "decode-ethernet.h"
#include "decode-events.h"

#include "detect-engine-port.h"

#include "flow.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"

static bool g_l2tp_enabled = true;
static bool g_l2tp_strict = false;
static int g_l2tp_ports_idx = 0;
static int g_l2tp_ports[L2TP_MAX_PORTS] = { L2TP_DEFAULT_PORT, L2TP_UNSET_PORT, L2TP_UNSET_PORT,
    L2TP_UNSET_PORT };

bool DecodeL2TPEnabledForPort(const uint16_t sp, const uint16_t dp)
{
    if (g_l2tp_enabled) {
        for (int i = 0; i < g_l2tp_ports_idx; i++) {
            if (g_l2tp_ports[i] == L2TP_UNSET_PORT)
                return false;

            const int port = g_l2tp_ports[i];
            if (port == (const int)sp || port == (const int)dp)
                return true;
        }
    }
    return false;
}

static void DecodeL2TPConfigPorts(const char *pstr)
{
    SCLogDebug("parsing \'%s\'", pstr);

    DetectPort *head = NULL;
    DetectPortParse(NULL, &head, pstr);

    g_l2tp_ports_idx = 0;
    for (DetectPort *p = head; p != NULL; p = p->next) {
        if (g_l2tp_ports_idx >= L2TP_MAX_PORTS) {
            SCLogWarning("more than %d L2TP ports defined", L2TP_MAX_PORTS);
            break;
        }
        g_l2tp_ports[g_l2tp_ports_idx++] = (int)p->port;
    }

    DetectPortCleanupList(NULL, head);
}

void DecodeL2TPConfig(void)
{
    int enabled = 0;
    if (SCConfGetBool("decoder.l2tp.enabled", &enabled) == 1) {
        if (enabled) {
            g_l2tp_enabled = true;
        } else {
            g_l2tp_enabled = false;
        }
    }

    int strict = 0;
    if (SCConfGetBool("decoder.l2tp.strict", &strict) == 1) {
        if (strict) {
            g_l2tp_strict = true;
        } else {
            g_l2tp_strict = false;
        }
    }

    if (g_l2tp_enabled) {
        SCConfNode *node = SCConfGetNode("decoder.l2tp.ports");
        if (node && node->val) {
            DecodeL2TPConfigPorts(node->val);
        } else {
            DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);
        }
    }
}

/** \param pkt payload data directly above UDP or IP header
 *  \param len length in bytes of pkt
 */
int DecodeL2TP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    if (unlikely(pkt == NULL))
        return TM_ECODE_FAILED;

    /* General L2TP packet validation */
    if (unlikely(!g_l2tp_enabled))
        return TM_ECODE_FAILED;

    if (unlikely(len < L2TP_MIN_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, L2TP_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    if (p->proto == IPPROTO_UDP) {
        const L2TPoverUDPDataHdr *l2tp_hdr = (const L2TPoverUDPDataHdr *)pkt;
        /* L2F / L2TPv1 / L2TPv2 decoding is not implemented, just return OK */
        if (unlikely(l2tp_hdr->version == 1 || l2tp_hdr->version == 2)) {
            StatsIncr(tv, dtv->counter_l2tp);
            StatsIncr(tv, dtv->counter_l2tp_unsupported);
            return TM_ECODE_OK;
        } else if (unlikely(l2tp_hdr->version != 3)) {
            SCLogDebug("L2TP Invalid. Type: %u Version: %u Reserved: %u", l2tp_hdr->type,
                    l2tp_hdr->version, l2tp_hdr->reserved);
            if (g_l2tp_strict) {
                ENGINE_SET_INVALID_EVENT(p, L2TP_INVALID_VER);
                return TM_ECODE_FAILED;
            } else {
                ENGINE_SET_EVENT(p, L2TP_INVALID_VER);
                return TM_ECODE_OK;
            }
        } else if (unlikely(g_l2tp_strict && (l2tp_hdr->reserved != 0 || l2tp_hdr->type != 0))) {
            return TM_ECODE_FAILED;
        }
        len -= sizeof(L2TPoverUDPDataHdr);
        pkt += sizeof(L2TPoverUDPDataHdr);
    } else if (unlikely(p->proto != IPPROTO_L2TP)) {
        SCLogDebug("Invalid IP Protocol for L2TP (%u)", p->proto);
        ENGINE_SET_INVALID_EVENT(p, L2TP_INVALID_IP_PROTO);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("L2TPv3 found. Protocol is: %u", p->proto);
    StatsIncr(tv, dtv->counter_l2tp);

#ifdef DEBUG
    uint32_t session_id = (pkt[0] << 24) + (pkt[1] << 16) + (pkt[2] << 8) + pkt[3];
#endif
    len -= sizeof(uint32_t);
    pkt += sizeof(uint32_t);
    SCLogDebug("Session ID: 0x%08x", session_id);

    /**
     * Detect the possible Cookie/Sublayer combinations by looking for known EtherTypes
     * Note that the Cookie/Sublayer is optional (and the header doesn't tell us if they're present)
     */
    bool eth_found = false;
    for (int i = 0; i < 4 && !eth_found; i++) {
        /* check that we have at least an Ethernet header */
        if (unlikely(len < ETHERNET_HEADER_LEN)) {
            ENGINE_SET_INVALID_EVENT(p, L2TP_PKT_TOO_SMALL);
            return TM_ECODE_FAILED;
        }
        /* check the protocol type */
        EthernetHdr *ethh = (EthernetHdr *)(pkt);
        uint16_t proto = SCNtohs(ethh->eth_type);
        switch (proto) {
            case ETHERNET_TYPE_IP:
                L2TP_CHECK_INNER_TUNNEL(DECODE_TUNNEL_IPV4);
                break;
            case ETHERNET_TYPE_IPV6:
                L2TP_CHECK_INNER_TUNNEL(DECODE_TUNNEL_IPV6);
                break;
            case ETHERNET_TYPE_ARP:
                L2TP_CHECK_INNER_TUNNEL(DECODE_TUNNEL_ARP);
                break;
            case ETHERNET_TYPE_VLAN:
            case ETHERNET_TYPE_8021AD:
            case ETHERNET_TYPE_8021QINQ:
                L2TP_CHECK_INNER_TUNNEL(DECODE_TUNNEL_VLAN);
                break;
        }
        /* consume 4 bytes to detect all combinations of cookie/sublayer types */
        len -= sizeof(uint32_t);
        pkt += sizeof(uint32_t);
    }

    if (!eth_found) {
        SCLogDebug("L2TP found unsupported Ethertype - expected IPv4, IPv6, VLAN, or ARP");
        if (g_l2tp_strict) {
            ENGINE_SET_INVALID_EVENT(p, L2TP_UNKNOWN_PAYLOAD_TYPE);
            return TM_ECODE_FAILED;
        } else {
            ENGINE_SET_EVENT(p, L2TP_UNKNOWN_PAYLOAD_TYPE);
            return TM_ECODE_OK;
        }
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/**
 * \test DecodeL2TPTest01 tests a L2TPv3 over UDP packet with no sublayer or cookie present
 */
static int DecodeL2TPTest01(void)
{
    uint8_t raw_l2tp[] = { 0x06, 0xa5, 0x04, 0xd2, 0x00, 0x56, 0x00, 0x00, /* UDP Header */
        0x00, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, /* L2TPv3 Header + Session ID */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l4.hdrs.udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->l4.hdrs.udph == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
/**
 * \test DecodeL2TPTest02 tests a L2TPv3 over UDP packet with a 4 byte cookie (no sublayer)
 */
static int DecodeL2TPTest02(void)
{
    uint8_t raw_l2tp[] = { 0x04, 0xd2, 0x06, 0xa5, 0x00, 0x5a, 0x00, 0x00, /* UDP Header */
        0x00, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, /* L2TPv3 Header + Session ID */
        0xca, 0xfe, 0xba, 0xbe,                         /* L2TPv3 Cookie - 4 Bytes */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l4.hdrs.udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->l4.hdrs.udph == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
/**
 * \test DecodeL2TPTest03 tests a L2TPv3 over UDP packet with a 8 byte cookie (no sublayer)
 */
static int DecodeL2TPTest03(void)
{
    uint8_t raw_l2tp[] = { 0x04, 0xd2, 0x06, 0xa5, 0x00, 0x5e, 0x00, 0x00, /* UDP Header */
        0x00, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, /* L2TPv3 Header + Session ID */
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xbe, 0xef, /* L2TPv3 Cookie - 8 Bytes */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l4.hdrs.udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->l4.hdrs.udph == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
/**
 * \test DecodeL2TPTest04 tests a L2TPv3 over UDP packet with a 8 byte cookie and a L2 Sublayer
 */
static int DecodeL2TPTest04(void)
{
    uint8_t raw_l2tp[] = { 0x04, 0xd2, 0x06, 0xa5, 0x00, 0x62, 0x00, 0x00, /* UDP Header */
        0x00, 0x03, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, /* L2TPv3 Header + Session ID */
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xbe, 0xef, /* L2TPv3 Cookie - 8 Bytes */
        0x00, 0x00, 0x00, 0x00,                         /* L2TPv3 L2 Generic Sublayer - 4 Bytes */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l4.hdrs.udph == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->l4.hdrs.udph == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
/**
 * \test DecodeL2TPTest05 tests a L2TPv3 over IP packet with a 8 byte cookie and a L2 Sublayer
 */
static int DecodeL2TPTest05(void)
{
    uint8_t raw_l2tp[] = { 0x45, 0x00, 0x00, 0x6a, /* IPv4 Header */
        0x00, 0x01, 0x00, 0x00, 0x40, 0x73, 0xf8, 0xcc, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00,
        0x02, 0x11, 0x22, 0x33, 0x44,                   /* Session ID - 4 Bytes */
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xbe, 0xef, /* L2TPv3 Cookie - 8 Bytes */
        0x00, 0x00, 0x00, 0x00,                         /* L2TPv3 L2 Generic Sublayer - 4 Bytes */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV4(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l3.hdrs.ip4h == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(p->l3.hdrs.ip4h == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
#include "conf-yaml-loader.h"
/**
 * \test DecodeL2TPTest06 tests strict mode of the parser */
static int DecodeL2TPTest06(void)
{
    uint8_t raw_l2tp[] = { 0x06, 0xa5, 0x04, 0xd2, 0x00, 0x56, 0x00, 0x00, /* UDP Header */
        0x12, 0x03, 0xcd, 0xab, 0x12, 0x34, 0x56, 0x78, /* L2TPv3 Header + Session ID */
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08,
        0x00,                                                       /* Ethernet Header */
        0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40, 0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    char config[] = "\
%YAML 1.1\n\
---\n\
decoder:\n\
\n\
  l2tp:\n\
    enabled: true\n\
    ports: \"1701\"\n\
    strict: true\n\
";

    SCConfCreateContextBackup();
    SCConfInit();
    SCConfYamlLoadString(config, strlen(config));

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    DecodeL2TPConfig();
    DecodeL2TPConfigPorts(L2TP_DEFAULT_PORT_S);

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeUDP(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF_NOT(PacketIsUDP(p));

    FAIL_IF(tv.decode_pq.top != NULL);

    FlowShutdown();
    PacketFree(p);
    SCConfDeInit();
    SCConfRestoreContextBackup();
    PASS;
}

/**
 * \test DecodeL2TPTest07 tests a L2TPv3 over IP packet with a 8 byte cookie and a L2 sublayer w/an
 * OUI of 08-00-45 (edge case) See
 * https://github.com/OISF/suricata/pull/14023/files/db7449a7299226bf70199cd685c6a5af5ee58c74#r2435186058
 */
static int DecodeL2TPTest07(void)
{
    uint8_t raw_l2tp[] = { 0x45, 0x00, 0x00, 0x6a, /* IPv4 Header */
        0x00, 0x01, 0x00, 0x00, 0x40, 0x73, 0xf8, 0xcc, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00,
        0x02, 0x11, 0x22, 0x33, 0x44,                   /* Session ID - 4 Bytes */
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xbe, 0xef, /* L2TPv3 Cookie - 8 Bytes */
        0x00, 0x00, 0x00, 0x00,                         /* L2TPv3 L2 Generic Sublayer - 4 Bytes */
        0x08, 0x00, 0x45, 0x11, 0x22, 0x33, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, /* MAC Header */
        0x08, 0x00, 0x45, 0x00, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x40,
        0x11, /* Inner IPv4 Header */
        0xf9, 0x60, 0xc0, 0xa8, 0x00, 0x01, 0xc0, 0xa8, 0x00, 0x02, 0x04, 0xd2, 0x00, 0x35, 0x00,
        0x24, 0x4b, 0xa3,                               /* Inner UDP Header */
        0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, /* DNS Request */
        0x00, 0x00, 0x00, 0x00, 0x06, 0x61, 0x6d, 0x61, 0x7a, 0x6f, 0x6e, 0x03, 0x63, 0x6f, 0x6d,
        0x00, 0x00, 0x01, 0x00, 0x01 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeIPV4(&tv, &dtv, p, raw_l2tp, sizeof(raw_l2tp));

    FAIL_IF(p->l3.hdrs.ip4h == NULL);
    FAIL_IF(tv.decode_pq.top == NULL);

    Packet *tp = PacketDequeueNoLock(&tv.decode_pq);
    FAIL_IF(tp->l3.hdrs.ip4h == NULL);
    FAIL_IF_NOT(tp->dp == 53);

    FlowShutdown();
    PacketFree(p);
    PacketFree(tp);
    PASS;
}
#endif /* UNITTESTS */

void DecodeL2TPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeL2TPTest01 -- (UDP) No Sublayer/Cookie", DecodeL2TPTest01);
    UtRegisterTest("DecodeL2TPTest02 -- (UDP) No Sublayer/4 Byte Cookie", DecodeL2TPTest02);
    UtRegisterTest("DecodeL2TPTest03 -- (UDP) No Sublayer/8 Byte Cookie", DecodeL2TPTest03);
    UtRegisterTest("DecodeL2TPTest04 -- (UDP) Sublayer/8 Byte Cookie", DecodeL2TPTest04);
    UtRegisterTest("DecodeL2TPTest05 -- (IP)  Sublayer/8 Byte Cookie", DecodeL2TPTest05);
    UtRegisterTest("DecodeL2TPTest06 -- Strict Mode", DecodeL2TPTest06);
    UtRegisterTest("DecodeL2TPTest07", DecodeL2TPTest07);
#endif /* UNITTESTS */
}
