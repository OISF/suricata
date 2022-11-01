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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Decode Cisco HDLC
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-chdlc.h"

#include "util-validate.h"

int DecodeCHDLC(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                   const uint8_t *pkt, uint32_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    StatsIncr(tv, dtv->counter_chdlc);

    if (unlikely(len < CHDLC_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, CHDLC_PKT_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (unlikely(len > CHDLC_HEADER_LEN + USHRT_MAX)) {
        return TM_ECODE_FAILED;
    }
    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    CHDLCHdr *hdr = (CHDLCHdr *)pkt;

    SCLogDebug("p %p pkt %p ether type %04x", p, pkt, SCNtohs(hdr->protocol));

    DecodeNetworkLayer(tv, dtv, SCNtohs(hdr->protocol), p,
            pkt + CHDLC_HEADER_LEN, len - CHDLC_HEADER_LEN);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS
static int DecodeCHDLCTest01 (void)
{
    uint8_t raw[] = { 0x0f,0x00,0x08,0x00,  // HDLC
        0x45,0x00,0x00,0x30,0x15,0x5a,0x40,0x00,0x80,0x06,
        0x6c,0xd0,0xc0,0xa8,0x02,0x07,0x41,0x37,0x74,0xb7,
        0x13,0x4a,0x00,0x50,0x9c,0x34,0x09,0x6c,0x00,0x00,
        0x00,0x00,0x70,0x02,0x40,0x00,0x11,0x47,0x00,0x00,
        0x02,0x04,0x05,0xb4,0x01,0x01,0x04,0x02 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&tv,  0, sizeof(ThreadVars));

    DecodeCHDLC(&tv, &dtv, p, raw, sizeof(raw));

    FAIL_IF_NOT(PKT_IS_IPV4(p));
    FAIL_IF_NOT(PKT_IS_TCP(p));
    FAIL_IF_NOT(p->dp == 80);

    SCFree(p);
    PASS;
}
#endif /* UNITTESTS */


/**
 * \brief Registers Ethernet unit tests
 * \todo More Ethernet tests
 */
void DecodeCHDLCRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeCHDLCTest01", DecodeCHDLCTest01);
#endif /* UNITTESTS */
}
/**
 * @}
 */
