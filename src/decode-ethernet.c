/* Copyright (C) 2007-2026 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode Ethernet
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ethernet.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsCounterIncr(&tv->stats, dtv->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    EthernetHdr *ethh = PacketSetEthernet(p, pkt);

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, SCNtohs(ethh->eth_type));

    DecodeNetworkLayer(tv, dtv, SCNtohs(ethh->eth_type), p, pkt + ETHERNET_HEADER_LEN,
            len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
/** DecodeEthernettest01
 *  \brief Valid Ethernet packet
 *  \retval 0 Expected test value
 */
static int DecodeEthernetTest01 (void)
{
    /* ICMP packet wrapped in PPPOE */
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x88, 0x64, 0x11, 0x00,
        0x00, 0x01, 0x00, 0x68, 0x00, 0x21, 0x45, 0xc0,
        0x00, 0x64, 0x00, 0x1e, 0x00, 0x00, 0xff, 0x01,
        0xa7, 0x78, 0x0a, 0x00, 0x00, 0x02, 0x0a, 0x00,
        0x00, 0x01, 0x08, 0x00, 0x4a, 0x61, 0x00, 0x06,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f,
        0x3b, 0xd4, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    PacketFree(p);
    return 1;
}

/**
 * Test a DCE ethernet frame that is too small.
 */
static int DecodeEthernetTestDceTooSmall(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x89, 0x03,
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    PacketFree(p);
    PASS;
}

/**
 * Test that a DCE ethernet frame, followed by data that is too small
 * for an ethernet header.
 *
 * Redmine issue:
 * https://redmine.openinfosecfoundation.org/issues/2887
 */
static int DecodeEthernetTestDceNextTooSmall(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x89, 0x03, //0x88, 0x64,

        0x00, 0x00,

        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01,
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    PacketFree(p);
    PASS;
}

/**
 * \brief decode a frame with an unhandled ethertype and check the
 *        ethertype DecodeGetUnknownEthertype() reports for it
 */
static int DecodeEthernetUnknownEthertypeCheck(
        int datalink, const uint8_t *raw, uint32_t len, uint16_t expected)
{
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    FAIL_IF(PacketCopyData(p, raw, len) != 0);
    p->datalink = datalink;
    DecodeLinkLayer(&tv, &dtv, datalink, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ETHERNET_UNKNOWN_ETHERTYPE));
    uint16_t ethertype = 0;
    FAIL_IF_NOT(DecodeGetUnknownEthertype(p, &ethertype));
    FAIL_IF(ethertype != expected);

    PacketFree(p);
    PASS;
}

/** \test untagged frame: the unknown ethertype is the ethernet type */
static int DecodeEthernetTestUnknownEthertype(void)
{
    /* MACs, RARP ethertype, RARP payload */
    const uint8_t raw[] = { 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_ETHERNET, raw, sizeof(raw), 0x8035);
}

/** \test QinQ frame: the unknown ethertype follows the inner VLAN tag */
static int DecodeEthernetTestUnknownEthertypeQinQ(void)
{
    /* MACs, 802.1ad, outer tag (VID 100, next 802.1Q), inner tag (VID 200,
     * next RARP), RARP payload */
    const uint8_t raw[] = { 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x88, 0xa8, 0x00, 0x64, 0x81, 0x00, 0x00, 0xc8, 0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06,
        0x04, 0x00, 0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_ETHERNET, raw, sizeof(raw), 0x8035);
}

/** \test 802.1ah frame: the unknown ethertype follows the customer MACs */
static int DecodeEthernetTestUnknownEthertype8021ah(void)
{
    /* MACs, 802.1ah, flags, customer MACs, RARP ethertype, RARP payload */
    const uint8_t raw[] = { 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x88, 0xe7, 0x00, 0x00, 0x00, 0x01, 0x00, 0x10, 0x94, 0x57, 0x00, 0x01, 0x00, 0x10, 0x94,
        0x58, 0x00, 0x01, 0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_ETHERNET, raw, sizeof(raw), 0x8035);
}

/** \test SLL frame without an ethernet header: the unknown ethertype
 *        follows a VLAN tag after the SLL protocol field */
static int DecodeEthernetTestUnknownEthertypeSll(void)
{
    /* SLL packet type, ARPHRD type, address length, address, protocol 802.1Q,
     * tag (VID 100, next RARP), RARP payload */
    const uint8_t raw[] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x10, 0x94, 0x55, 0x00, 0x01,
        0x00, 0x00, 0x81, 0x00, 0x00, 0x64, 0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
        0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_LINUX_SLL, raw, sizeof(raw), 0x8035);
}

/** \test SLL2 frame: the SLL2 protocol is the first field of its header,
 *        so the VLAN tag starts after the whole header, not after that field */
static int DecodeEthernetTestUnknownEthertypeSll2(void)
{
    /* protocol 802.1Q, reserved, ifindex, ARPHRD type, packet type, address
     * length, address, tag (VID 100, next RARP), RARP payload */
    const uint8_t raw[] = { 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x06,
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x80, 0x35, 0x00, 0x01, 0x08,
        0x00, 0x06, 0x04, 0x00, 0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_LINUX_SLL2, raw, sizeof(raw), 0x8035);
}

/** \test Cisco HDLC frame: the unknown ethertype is the HDLC protocol */
static int DecodeEthernetTestUnknownEthertypeCHDLC(void)
{
    /* address, control, RARP protocol, RARP payload */
    const uint8_t raw[] = { 0x0f, 0x00, 0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00,
        0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_CISCO_HDLC, raw, sizeof(raw), 0x8035);
}

/** \test DCE frame: the unknown ethertype is in the inner ethernet header,
 *        not the outer DCE ethertype */
static int DecodeEthernetTestUnknownEthertypeDce(void)
{
    /* MACs, DCE, 2 DCE bytes, inner MACs, RARP ethertype, RARP payload */
    const uint8_t raw[] = { 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x89, 0x03, 0x00, 0x00, 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00,
        0x01, 0x80, 0x35, 0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x03 };
    return DecodeEthernetUnknownEthertypeCheck(LINKTYPE_ETHERNET, raw, sizeof(raw), 0x8035);
}

/** \test frame cut off inside a VLAN tag: no unknown ethertype event, and
 *        the lookup stops at the end of the packet instead of reading past it */
static int DecodeEthernetTestUnknownEthertypeTruncated(void)
{
    /* macs, 802.1Q, first half of the tag */
    const uint8_t raw[] = { 0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10, 0x94, 0x56, 0x00, 0x01,
        0x81, 0x00, 0x00, 0x64 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    FAIL_IF(PacketCopyData(p, raw, sizeof(raw)) != 0);
    p->datalink = LINKTYPE_ETHERNET;
    DecodeEthernet(&tv, &dtv, p, GET_PKT_DATA(p), GET_PKT_LEN(p));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, VLAN_HEADER_TOO_SMALL));
    FAIL_IF(ENGINE_ISSET_EVENT(p, ETHERNET_UNKNOWN_ETHERTYPE));
    uint16_t ethertype = 0;
    FAIL_IF(DecodeGetUnknownEthertype(p, &ethertype));

    PacketFree(p);
    PASS;
}

#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeEthernetRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeEthernetTest01", DecodeEthernetTest01);
    UtRegisterTest("DecodeEthernetTestDceNextTooSmall",
            DecodeEthernetTestDceNextTooSmall);
    UtRegisterTest("DecodeEthernetTestDceTooSmall",
            DecodeEthernetTestDceTooSmall);
    UtRegisterTest("DecodeEthernetTestUnknownEthertype", DecodeEthernetTestUnknownEthertype);
    UtRegisterTest(
            "DecodeEthernetTestUnknownEthertypeQinQ", DecodeEthernetTestUnknownEthertypeQinQ);
    UtRegisterTest(
            "DecodeEthernetTestUnknownEthertype8021ah", DecodeEthernetTestUnknownEthertype8021ah);
    UtRegisterTest("DecodeEthernetTestUnknownEthertypeSll", DecodeEthernetTestUnknownEthertypeSll);
    UtRegisterTest(
            "DecodeEthernetTestUnknownEthertypeSll2", DecodeEthernetTestUnknownEthertypeSll2);
    UtRegisterTest(
            "DecodeEthernetTestUnknownEthertypeCHDLC", DecodeEthernetTestUnknownEthertypeCHDLC);
    UtRegisterTest("DecodeEthernetTestUnknownEthertypeDce", DecodeEthernetTestUnknownEthertypeDce);
    UtRegisterTest("DecodeEthernetTestUnknownEthertypeTruncated",
            DecodeEthernetTestUnknownEthertypeTruncated);
#endif /* UNITTESTS */
}
/**
 * @}
 */
