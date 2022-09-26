/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * \author Jason Ish <jason.ish@emulex.com>
 *
 * MPLS decoder.
 */

#include "suricata-common.h"

#include "util-validate.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#include "decode.h"
#endif
#define MPLS_HEADER_LEN         4
#define MPLS_PW_LEN             4
#define MPLS_MAX_RESERVED_LABEL 15

#define MPLS_LABEL_IPV4         0
#define MPLS_LABEL_ROUTER_ALERT 1
#define MPLS_LABEL_IPV6         2
#define MPLS_LABEL_NULL         3

#define MPLS_LABEL(shim)        SCNtohl(shim) >> 12
#define MPLS_BOTTOM(shim)       ((SCNtohl(shim) >> 8) & 0x1)

/* Inner protocol guessing values. */
#define MPLS_PROTO_ETHERNET_PW  0
#define MPLS_PROTO_IPV4         4
#define MPLS_PROTO_IPV6         6

int DecodeMPLS(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    uint32_t shim;
    int label;
    uint8_t event = 0;

    StatsIncr(tv, dtv->counter_mpls);

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    do {
        if (len < MPLS_HEADER_LEN) {
            ENGINE_SET_INVALID_EVENT(p, MPLS_HEADER_TOO_SMALL);
            return TM_ECODE_FAILED;
        }
        memcpy(&shim, pkt, sizeof(shim));
        pkt += MPLS_HEADER_LEN;
        len -= MPLS_HEADER_LEN;
    } while (MPLS_BOTTOM(shim) == 0);

    label = MPLS_LABEL(shim);
    if (label == MPLS_LABEL_IPV4) {
        if (len > USHRT_MAX) {
            return TM_ECODE_FAILED;
        }
        return DecodeIPV4(tv, dtv, p, pkt, (uint16_t)len);
    }
    else if (label == MPLS_LABEL_ROUTER_ALERT) {
        /* Not valid at the bottom of the stack. */
        event = MPLS_BAD_LABEL_ROUTER_ALERT;
    }
    else if (label == MPLS_LABEL_IPV6) {
        if (len > USHRT_MAX) {
            return TM_ECODE_FAILED;
        }
        return DecodeIPV6(tv, dtv, p, pkt, (uint16_t)len);
    }
    else if (label == MPLS_LABEL_NULL) {
        /* Shouldn't appear on the wire. */
        event = MPLS_BAD_LABEL_IMPLICIT_NULL;
    }
    else if (label < MPLS_MAX_RESERVED_LABEL) {
        event = MPLS_BAD_LABEL_RESERVED;
    }

    if (event) {
        goto end;
    }

    // Make sure we still have enough data. While we only need 1 byte to test
    // for IPv4 and IPv4, we need for to check for ethernet.
    if (len < MPLS_PW_LEN) {
        ENGINE_SET_INVALID_EVENT(p, MPLS_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    /* Best guess at inner packet. */
    switch (pkt[0] >> 4) {
    case MPLS_PROTO_IPV4:
        if (len > USHRT_MAX) {
            return TM_ECODE_FAILED;
        }
        DecodeIPV4(tv, dtv, p, pkt, (uint16_t)len);
        break;
    case MPLS_PROTO_IPV6:
        if (len > USHRT_MAX) {
            return TM_ECODE_FAILED;
        }
        DecodeIPV6(tv, dtv, p, pkt, (uint16_t)len);
        break;
    case MPLS_PROTO_ETHERNET_PW:
        DecodeEthernet(tv, dtv, p, pkt + MPLS_PW_LEN, len - MPLS_PW_LEN);
        break;
    default:
        ENGINE_SET_INVALID_EVENT(p, MPLS_UNKNOWN_PAYLOAD_TYPE);
        return TM_ECODE_OK;
    }

end:
    if (event) {
        ENGINE_SET_EVENT(p, event);
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

static int DecodeMPLSTestHeaderTooSmall(void)
{
    int ret = 1;

    /* A packet that is too small to have a complete MPLS header. */
    uint8_t pkt[] = {
        0x00, 0x00, 0x11
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) {
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeMPLS(&tv, &dtv, p, pkt, sizeof(pkt));

    if (!ENGINE_ISSET_EVENT(p, MPLS_HEADER_TOO_SMALL)) {
        ret = 0;
    }

    SCFree(p);
    return ret;
}

static int DecodeMPLSTestPacketTooSmall(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    Packet *p0 = SCCalloc(1, SIZE_OF_PACKET);
    memset(p0, 0, SIZE_OF_PACKET);
    uint8_t pkt0[] = { 0x00, 0x01, 0x51, 0xff };
    DecodeMPLS(&tv, &dtv, p0, pkt0, sizeof(pkt0));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p0, MPLS_PKT_TOO_SMALL));
    SCFree(p0);

    Packet *p1 = SCCalloc(1, SIZE_OF_PACKET);
    FAIL_IF_NULL(p1);
    uint8_t pkt1[] = { 0x00, 0x01, 0x51, 0xff, 0x45 };
    DecodeMPLS(&tv, &dtv, p1, pkt1, sizeof(pkt1));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p1, MPLS_PKT_TOO_SMALL));
    SCFree(p1);

    Packet *p2 = SCCalloc(1, SIZE_OF_PACKET);
    FAIL_IF_NULL(p2);
    uint8_t pkt2[] = { 0x00, 0x01, 0x51, 0xff, 0x45, 0x01 };
    DecodeMPLS(&tv, &dtv, p2, pkt2, sizeof(pkt2));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p2, MPLS_PKT_TOO_SMALL));
    SCFree(p2);

    Packet *p3 = SCCalloc(1, SIZE_OF_PACKET);
    FAIL_IF_NULL(p3);
    uint8_t pkt3[] = { 0x00, 0x01, 0x51, 0xff, 0x45, 0x01, 0x02 };
    DecodeMPLS(&tv, &dtv, p3, pkt3, sizeof(pkt3));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p3, MPLS_PKT_TOO_SMALL));
    SCFree(p3);

    // This should not create a too small event is it has one more byte
    // than required.
    Packet *p4 = SCCalloc(1, SIZE_OF_PACKET);
    FAIL_IF_NULL(p4);
    uint8_t pkt4[] = { 0x00, 0x01, 0x51, 0xff, 0x45, 0x01, 0x02, 0x03 };
    DecodeMPLS(&tv, &dtv, p4, pkt4, sizeof(pkt4));
    FAIL_IF(ENGINE_ISSET_EVENT(p4, MPLS_PKT_TOO_SMALL));
    SCFree(p4);

    PASS;
}

static int DecodeMPLSTestBadLabelRouterAlert(void)
{
    int ret = 1;
    uint8_t pkt[] = {
        0x00, 0x00, 0x11, 0xff, 0x45, 0x00, 0x00, 0x64,
        0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a,
        0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x33, 0x50,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) {
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeMPLS(&tv, &dtv, p, pkt, sizeof(pkt));

    if (!ENGINE_ISSET_EVENT(p, MPLS_BAD_LABEL_ROUTER_ALERT)) {
        ret = 0;
    }

    SCFree(p);
    return ret;
}

static int DecodeMPLSTestBadLabelImplicitNull(void)
{
    int ret = 1;
    uint8_t pkt[] = {
        0x00, 0x00, 0x31, 0xff, 0x45, 0x00, 0x00, 0x64,
        0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a,
        0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x33, 0x50,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) {
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeMPLS(&tv, &dtv, p, pkt, sizeof(pkt));

    if (!ENGINE_ISSET_EVENT(p, MPLS_BAD_LABEL_IMPLICIT_NULL)) {
        ret = 0;
    }

    SCFree(p);
    return ret;
}

static int DecodeMPLSTestBadLabelReserved(void)
{
    int ret = 1;
    uint8_t pkt[] = {
        0x00, 0x00, 0x51, 0xff, 0x45, 0x00, 0x00, 0x64,
        0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a,
        0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x33, 0x50,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) {
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeMPLS(&tv, &dtv, p, pkt, sizeof(pkt));

    if (!ENGINE_ISSET_EVENT(p, MPLS_BAD_LABEL_RESERVED)) {
        ret = 0;
    }

    SCFree(p);
    return ret;
}

static int DecodeMPLSTestUnknownPayloadType(void)
{
    int ret = 1;

    /* Valid label: 21.
     * Unknown payload type: 1.
     */
    uint8_t pkt[] = {
        0x00, 0x01, 0x51, 0xff, 0x15, 0x00, 0x00, 0x64,
        0x00, 0x0a, 0x00, 0x00, 0xff, 0x01, 0xa5, 0x6a,
        0x0a, 0x01, 0x02, 0x01, 0x0a, 0x22, 0x00, 0x01,
        0x08, 0x00, 0x3a, 0x77, 0x0a, 0x39, 0x06, 0x2b,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x33, 0x50,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd,
        0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL)) {
        return 0;
    }
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeMPLS(&tv, &dtv, p, pkt, sizeof(pkt));

    if (!ENGINE_ISSET_EVENT(p, MPLS_UNKNOWN_PAYLOAD_TYPE)) {
        ret = 0;
    }

    SCFree(p);
    return ret;
}

#endif /* UNITTESTS */

void DecodeMPLSRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeMPLSTestHeaderTooSmall",
                   DecodeMPLSTestHeaderTooSmall);
    UtRegisterTest("DecodeMPLSTestPacketTooSmall",
                   DecodeMPLSTestPacketTooSmall);
    UtRegisterTest("DecodeMPLSTestBadLabelRouterAlert",
                   DecodeMPLSTestBadLabelRouterAlert);
    UtRegisterTest("DecodeMPLSTestBadLabelImplicitNull",
                   DecodeMPLSTestBadLabelImplicitNull);
    UtRegisterTest("DecodeMPLSTestBadLabelReserved",
                   DecodeMPLSTestBadLabelReserved);
    UtRegisterTest("DecodeMPLSTestUnknownPayloadType",
                   DecodeMPLSTestUnknownPayloadType);
#endif /* UNITTESTS */
}
