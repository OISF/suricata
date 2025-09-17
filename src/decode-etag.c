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
 * \ingroup decode
 *
 * @{
 */

/**
 * \file
 *
 * \author Fupeng Zhao <fupeng.zhao@foxmail.com>
 *
 * Decode 802.1BR E-Tag headers
 *
 * This implementation is based on the following specification doc:
 * https://www.scribd.com/document/262742673/802-1BR-2012-pdf
 */

#include "suricata-common.h"
#include "decode-etag.h"
#include "decode.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

int DecodeETag(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_etag);

    if (len < ETAG_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, ETAG_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    const ETagHdr *etag_hdr = (const ETagHdr *)pkt;

    uint16_t proto = SCNtohs(etag_hdr->protocol);

    if (DecodeNetworkLayer(tv, dtv, proto, p, pkt + ETAG_HEADER_LEN, len - ETAG_HEADER_LEN) ==
            false) {
        ENGINE_SET_INVALID_EVENT(p, ETAG_UNKNOWN_TYPE);
        return TM_ECODE_FAILED;
    }

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "packet.h"

/**
 * \test DecodeETagTest01 test if etag header is too small.
 */
static int DecodeETagTest01(void)
{
    uint8_t raw_etag[] = { 0x00, 0x20, 0x08 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv = { 0 };
    DecodeThreadVars dtv = { 0 };

    FAIL_IF(TM_ECODE_OK == DecodeETag(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ETAG_HEADER_TOO_SMALL));

    PacketFree(p);
    PASS;
}

/**
 * \test DecodeETagTest02 test if etag header has unknown type.
 */
static int DecodeETagTest02(void)
{
    uint8_t raw_etag[] = { 0x10, 0x00, 0x00, 0xd8, 0x00, 0x00, 0xFF, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3B, 0x09, 0x40, 0x00, 0x7F, 0x06, 0x2E, 0x3A, 0xC0, 0xA8, 0x01, 0x2C, 0xC0, 0xA8, 0x10,
        0x04, 0x00, 0x19, 0x29, 0x2B, 0x3E, 0xE9, 0x31, 0x81, 0x20, 0x04, 0x4B, 0x9A, 0x80, 0x10,
        0x3E, 0xB8, 0x8E, 0x3C, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A, 0x5F, 0x3E, 0xE4, 0xAA, 0x63,
        0x0E, 0x6B, 0x03, 0x07, 0x69 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv = { 0 };
    DecodeThreadVars dtv = { 0 };

    FAIL_IF_NOT(TM_ECODE_OK != DecodeETag(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ETAG_UNKNOWN_TYPE));

    PacketFree(p);
    PASS;
}

/**
 * \test DecodeETagTest03 test a good etag header.
 */
static int DecodeETagTest03(void)
{
    uint8_t raw_etag[] = { 0x10, 0x00, 0x00, 0xd8, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x34,
        0x3B, 0x09, 0x40, 0x00, 0x7F, 0x06, 0x2E, 0x3A, 0xC0, 0xA8, 0x01, 0x2C, 0xC0, 0xA8, 0x10,
        0x04, 0x00, 0x19, 0x29, 0x2B, 0x3E, 0xE9, 0x31, 0x81, 0x20, 0x04, 0x4B, 0x9A, 0x80, 0x10,
        0x3E, 0xB8, 0x8E, 0x3C, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0A, 0x5F, 0x3E, 0xE4, 0xAA, 0x63,
        0x0E, 0x6B, 0x03, 0x07, 0x69 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv = { 0 };
    DecodeThreadVars dtv = { 0 };

    FlowInitConfig(FLOW_QUIET);

    FAIL_IF(TM_ECODE_OK != DecodeETag(&tv, &dtv, p, raw_etag, sizeof(raw_etag)));

    PacketRecycle(p);
    FlowShutdown();
    PacketFree(p);
    PASS;
}

#endif /* UNITTESTS */

void DecodeETagRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeETagTest01", DecodeETagTest01);
    UtRegisterTest("DecodeETagTest02", DecodeETagTest02);
    UtRegisterTest("DecodeETagTest03", DecodeETagTest03);
#endif
}

/**
 * @}
 */
