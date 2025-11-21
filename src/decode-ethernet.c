/* Copyright (C) 2015 Open Information Security Foundation
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
 * version 2 along with this program; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301, USA.
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-ethernet.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"

static void DecodeEthernetRegisterTests(void);

void DecodeEthernetRegister(void)
{
    /* Placeholder register function to match Suricata module style.
     * If higher-level registration is required, add it here.
     */
#ifdef UNITTESTS
    /* Hook the test register function for external test runners if needed.
     * No global registration table exists for decode modules in this file,
     * so we simply ensure the symbol is present and can be called by test
     * harnesses when appropriate.
     */
    DecodeEthernetRegisterTests();
#endif
}

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

    EthernetHdr *ethh = PacketSetEthernet(p, pkt);

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, SCNtohs(ethh->eth_type));

    DecodeNetworkLayer(tv, dtv, SCNtohs(ethh->eth_type), p,
                       pkt + ETHERNET_HEADER_LEN, len - ETHERNET_HEADER_LEN);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

static int DecodeEthernetTest01(void);
static int DecodeEthernetTestDceTooSmall(void);
static int DecodeEthernetTestDceNextTooSmall(void);

static int DecodeEthernetTest01(void)
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
        0xab, 0xcd
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    int r = DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));
    FAIL_IF(r != TM_ECODE_OK);

    SCFree(p);
    PASS;
}

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
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

static int DecodeEthernetTestDceNextTooSmall(void)
{
    uint8_t raw_eth[] = {
        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01, 0x89, 0x03, /* 0x88, 0x64 removed on purpose */

        0x00, 0x00, /* too-small continuation */

        0x00, 0x10, 0x94, 0x55, 0x00, 0x01, 0x00, 0x10,
        0x94, 0x56, 0x00, 0x01,
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;
    memset(&tv, 0, sizeof(tv));
    memset(&dtv, 0, sizeof(dtv));

    DecodeEthernet(&tv, &dtv, p, raw_eth, sizeof(raw_eth));

    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, DCE_PKT_TOO_SMALL));

    SCFree(p);
    PASS;
}

static void DecodeEthernetRegisterTests(void)
{
    UtRegisterTest("DecodeEthernetTest01", DecodeEthernetTest01);
    UtRegisterTest("DecodeEthernetTestDceTooSmall", DecodeEthernetTestDceTooSmall);
    UtRegisterTest("DecodeEthernetTestDceNextTooSmall", DecodeEthernetTestDceNextTooSmall);
}

#endif /* UNITTESTS */
