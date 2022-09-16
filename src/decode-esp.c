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
 * \ingroup decode
 *
 * @{
 */

/**
 * \file
 *
 * Decode Encapsulating Security Payload (ESP)
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#endif
#include "decode-esp.h"

#include "util-validate.h"

static int DecodeESPPacket(ThreadVars *tv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (unlikely(len < ESP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ESP_PKT_TOO_SMALL);
        return -1;
    }

    p->esph = (ESPHdr *)pkt;

    p->payload = (uint8_t *)pkt + sizeof(ESPHdr);
    p->payload_len = len - sizeof(ESPHdr);

    p->proto = IPPROTO_ESP;

    return 0;
}

/**
 * \brief Function to decode IPSEC-ESP packets
 * \param tv thread vars
 * \param dtv decoder thread vars
 * \param p packet
 * \param pkt raw packet data
 * \param len length in bytes of pkt array
 * \retval TM_ECODE_OK or TM_ECODE_FAILED on serious error
 */
int DecodeESP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_esp);

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    if (unlikely(DecodeESPPacket(tv, p, pkt, len) < 0)) {
        CLEAR_ESP_PACKET(p);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("ESP spi: %" PRIu32 " sequence: %" PRIu32, ESP_GET_SPI(p), ESP_GET_SEQUENCE(p));

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

#include "util-unittest.h"

/** \test Successful decoding */
static int DecodeESPTest01(void)
{
    uint8_t raw_esp[] = { 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x08 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    int ret = DecodeESP(&tv, &dtv, p, raw_esp, sizeof(raw_esp));
    FAIL_IF(ret != TM_ECODE_OK);

    FAIL_IF(p->proto != IPPROTO_ESP);
    FAIL_IF(p->payload_len != sizeof(raw_esp) - ESP_HEADER_LEN);
    FAIL_IF(ESP_GET_SPI(p) != 0x7b);
    FAIL_IF(ESP_GET_SEQUENCE(p) != 0x08);

    SCFree(p);

    PASS;
}

/** \test Successful decoding, with payload data */
static int DecodeESPTest02(void)
{
    uint8_t raw_esp[] = { 0x00, 0x00, 0x00, 0x7b, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xFF };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    int ret = DecodeESP(&tv, &dtv, p, raw_esp, sizeof(raw_esp));
    FAIL_IF(ret != TM_ECODE_OK);

    FAIL_IF(p->proto != IPPROTO_ESP);
    FAIL_IF(p->payload_len != sizeof(raw_esp) - ESP_HEADER_LEN);
    FAIL_IF(memcmp(p->payload, raw_esp + ESP_HEADER_LEN, p->payload_len) != 0);
    FAIL_IF(ESP_GET_SPI(p) != 0x7b);
    FAIL_IF(ESP_GET_SEQUENCE(p) != 0x08);

    SCFree(p);

    PASS;
}

/** \test Failure decoding, not enough data */
static int DecodeESPTest03(void)
{
    uint8_t raw_esp[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    int ret = DecodeESP(&tv, &dtv, p, raw_esp, sizeof(raw_esp));
    FAIL_IF(ret != TM_ECODE_FAILED);

    // expect ESP_PKT_TOO_SMALL
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ESP_PKT_TOO_SMALL));

    SCFree(p);

    PASS;
}

/** \test Failure decoding, no data */
static int DecodeESPTest04(void)
{
    uint8_t raw_esp[] = {};

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    int ret = DecodeESP(&tv, &dtv, p, raw_esp, sizeof(raw_esp));
    FAIL_IF(ret != TM_ECODE_FAILED);

    // expect ESP_PKT_TOO_SMALL
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, ESP_PKT_TOO_SMALL));

    SCFree(p);

    PASS;
}
#endif /* UNITTESTS */

void DecodeESPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeESPTest01", DecodeESPTest01);
    UtRegisterTest("DecodeESPTest02", DecodeESPTest02);
    UtRegisterTest("DecodeESPTest03", DecodeESPTest03);
    UtRegisterTest("DecodeESPTest04", DecodeESPTest04);
#endif /* UNITTESTS */
}

/**
 * @}
 */
