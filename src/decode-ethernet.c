/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#ifdef UNITTESTS
#include "util-debug.h"
#include "util-unittest.h"
#include "decode-events.h"
#include "decode.h"
#endif
#include "decode-ethernet.h"

#include "util-validate.h"

int DecodeEthernet(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_eth);

    if (unlikely(len < ETHERNET_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, ETHERNET_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }
    p->ethh = (EthernetHdr *)pkt;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, SCNtohs(p->ethh->eth_type));

    DecodeNetworkLayer(tv, dtv, SCNtohs(p->ethh->eth_type), p,
            pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

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

    SCFree(p);
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

    SCFree(p);
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

    SCFree(p);
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
#endif /* UNITTESTS */
}
/**
 * @}
 */
