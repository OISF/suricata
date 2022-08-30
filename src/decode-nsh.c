/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Carl Smith <carl.smith@alliedtelesis.co.nz>
 *
 * Decodes Network Service Header (NSH)
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"
#include "decode-events.h"
#include "decode-nsh.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

/**
 * \brief Function to decode NSH packets
 */

int DecodeNSH(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_nsh);

    /* Check minimum header size */
    if (len < sizeof(NshHdr)) {
        ENGINE_SET_INVALID_EVENT(p, NSH_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    /* Sanity check the header version */
    const NshHdr *hdr = (const NshHdr *)pkt;
    uint16_t version = SCNtohs(hdr->ver_flags_len) >> 14;
    if (version != 0) {
        ENGINE_SET_EVENT(p, NSH_UNSUPPORTED_VERSION);
        return TM_ECODE_OK;
    }

    /* Should always be some data after the header */
    uint16_t length = (SCNtohs(hdr->ver_flags_len) & 0x003f) * 4;
    if (length >= len) {
        ENGINE_SET_INVALID_EVENT(p, NSH_BAD_HEADER_LENGTH);
        return TM_ECODE_FAILED;
    }

    /* Check for valid MD types */
    uint8_t md_type = hdr->md_type;
    if (md_type == 0 || md_type == 0xF) {
        /* We should silently ignore these packets */
        ENGINE_SET_EVENT(p, NSH_RESERVED_TYPE);
        return TM_ECODE_OK;
    } else if (md_type == 1) {
        /* Fixed header length format */
        if (length != 24) {
            ENGINE_SET_INVALID_EVENT(p, NSH_BAD_HEADER_LENGTH);
            return TM_ECODE_FAILED;
        }
    } else if (md_type != 2) {
        /* Not variable header length either */
        ENGINE_SET_EVENT(p, NSH_UNSUPPORTED_TYPE);
        return TM_ECODE_OK;
    }

    /* Now we can safely read the rest of the header */
    uint8_t next_protocol = hdr->next_protocol;
#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        uint32_t spi_si = SCNtohl(hdr->spi_si);
        uint32_t spi = ((spi_si & 0xFFFFFF00) >> 8);
        uint8_t si = (uint8_t)(spi_si & 0xFF);
        SCLogDebug("NSH: version %u length %u spi %u si %u next_protocol %u", version, length, spi,
                si, next_protocol);
    }
#endif /* DEBUG */

    /* Try to decode the payload */
    switch (next_protocol) {
        case NSH_NEXT_PROTO_IPV4:
            if (len - length > USHRT_MAX) {
                return TM_ECODE_FAILED;
            }
            return DecodeIPV4(tv, dtv, p, pkt + length, (uint16_t)(len - length));
        case NSH_NEXT_PROTO_IPV6:
            if (len - length > USHRT_MAX) {
                return TM_ECODE_FAILED;
            }
            return DecodeIPV6(tv, dtv, p, pkt + length, (uint16_t)(len - length));
        case NSH_NEXT_PROTO_ETHERNET:
            return DecodeEthernet(tv, dtv, p, pkt + length, len - length);
        case NSH_NEXT_PROTO_MPLS:
            return DecodeMPLS(tv, dtv, p, pkt + length, len - length);
        case NSH_NEXT_PROTO_NSH:
        default:
            SCLogDebug("NSH next protocol %u not supported", next_protocol);
            ENGINE_SET_EVENT(p, NSH_UNKNOWN_PAYLOAD);
            break;
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

static uint8_t valid_nsh_packet[] = { 0x00, 0x04, 0x02, 0x01, 0x00, 0x00, 0x02, 0x02, 0x45, 0x10,
    0x00, 0x3c, 0x78, 0x8f, 0x40, 0x00, 0x3f, 0x06, 0x79, 0x05, 0x0b, 0x06, 0x06, 0x06, 0x33, 0x06,
    0x06, 0x06, 0xbd, 0x2e, 0x00, 0x16, 0xc9, 0xee, 0x07, 0x62, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02,
    0x16, 0xd0, 0x2f, 0x36, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0xa9, 0x5f,
    0x7f, 0xed, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07 };

static int DecodeNSHTestHeaderTooSmall(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* A packet that is too small to have a complete NSH header */
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, 7);
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_HEADER_TOO_SMALL));

    SCFree(p);
    PASS;
}

static int DecodeNSHTestUnsupportedVersion(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* Non-zero version field */
    valid_nsh_packet[0] = 0xFF;
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, sizeof(valid_nsh_packet));
    valid_nsh_packet[0] = 0x00;
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_UNSUPPORTED_VERSION));

    SCFree(p);
    PASS;
}

static int DecodeNSHTestPacketTooSmall(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* A packet that has no payload */
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, 8);
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_BAD_HEADER_LENGTH));

    SCFree(p);
    PASS;
}

static int DecodeNSHTestReservedType(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* Reserved type */
    valid_nsh_packet[2] = 0x00;
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, sizeof(valid_nsh_packet));
    valid_nsh_packet[2] = 0x02;
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_RESERVED_TYPE));

    SCFree(p);
    PASS;
}

static int DecodeNSHTestInvalidType(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* Type length mismatch */
    valid_nsh_packet[2] = 0x01;
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, sizeof(valid_nsh_packet));
    valid_nsh_packet[2] = 0x02;
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_BAD_HEADER_LENGTH));
    SCFree(p);
    PASS;
}

static int DecodeNSHTestUnsupportedType(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* Unsupported type */
    valid_nsh_packet[2] = 0x03;
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, sizeof(valid_nsh_packet));
    valid_nsh_packet[2] = 0x02;
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_UNSUPPORTED_TYPE));

    SCFree(p);
    PASS;
}

static int DecodeNSHTestUnknownPayload(void)
{
    ThreadVars tv;
    DecodeThreadVars dtv;
    Packet *p;

    p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv, 0, sizeof(ThreadVars));

    /* Unknown type */
    valid_nsh_packet[3] = 0x99;
    DecodeNSH(&tv, &dtv, p, valid_nsh_packet, sizeof(valid_nsh_packet));
    valid_nsh_packet[3] = 0x01;
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, NSH_UNKNOWN_PAYLOAD));

    SCFree(p);
    PASS;
}

#endif /* UNITTESTS */

void DecodeNSHRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeNSHTestHeaderTooSmall", DecodeNSHTestHeaderTooSmall);
    UtRegisterTest("DecodeNSHTestUnsupportedVersion", DecodeNSHTestUnsupportedVersion);
    UtRegisterTest("DecodeNSHTestPacketTooSmall", DecodeNSHTestPacketTooSmall);
    UtRegisterTest("DecodeNSHTestReservedType", DecodeNSHTestReservedType);
    UtRegisterTest("DecodeNSHTestInvalidType", DecodeNSHTestInvalidType);
    UtRegisterTest("DecodeNSHTestUnsupportedType", DecodeNSHTestUnsupportedType);
    UtRegisterTest("DecodeNSHTestUnknownPayload", DecodeNSHTestUnknownPayload);
#endif /* UNITTESTS */
}
