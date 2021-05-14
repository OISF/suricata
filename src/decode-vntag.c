/* Copyright (C) 2021 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Decode VNTag 802.1Qbh
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-vntag.h"
#include "decode-events.h"

#include "flow.h"

#include "util-unittest.h"
#include "util-debug.h"

#include "pkt-var.h"
#include "util-profiling.h"
#include "host.h"

bool g_vntag_enabled = false;

void DecodeVNTagConfig(void)
{
    int enabled = 0;
    if (ConfGetBool("decoder.vntag.enabled", &enabled) == 1) {
        g_vntag_enabled = (enabled == 1);
    }
    SCLogDebug("VNTag decode support %s", g_vntag_enabled ? "enabled" : "disabled");
}

/**
 * \internal
 * \brief this function is used to decode 802.1Qbh packets
 *
 * \param tv pointer to the thread vars
 * \param dtv pointer to decode thread vars
 * \param p pointer to the packet struct
 * \param pkt pointer to the raw packet
 * \param len packet len
 *
 */
int DecodeVNTag(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p, const uint8_t *pkt, uint32_t len)
{
    if (!g_vntag_enabled)
        return TM_ECODE_FAILED;

    StatsIncr(tv, dtv->counter_vntag);

    if (len < VNTAG_HEADER_LEN) {
        ENGINE_SET_INVALID_EVENT(p, VNTAG_HEADER_TOO_SMALL);
        return TM_ECODE_FAILED;
    }

    if (!PacketIncreaseCheckLayers(p)) {
        return TM_ECODE_FAILED;
    }

    VNTagHdr *vntag_hdr = (VNTagHdr *)pkt;
    if (vntag_hdr == NULL)
        return TM_ECODE_FAILED;

    uint16_t proto = GET_VNTAG_PROTO(vntag_hdr);

    SCLogDebug("p %p pkt %p protocol %04x DIR %d PTR %d DEST %d LOOPED: %d VERSION: %d SRC: %d "
               "Len: %" PRIu32 "",
            p, pkt, proto, GET_VNTAG_DIR(vntag_hdr), GET_VNTAG_PTR(vntag_hdr),
            GET_VNTAG_DEST(vntag_hdr), GET_VNTAG_LOOPED(vntag_hdr), GET_VNTAG_VERSION(vntag_hdr),
            GET_VNTAG_SRC(vntag_hdr), len);

    if (DecodeNetworkLayer(tv, dtv, proto, p, pkt + VNTAG_HEADER_LEN, len - VNTAG_HEADER_LEN) ==
            false) {
        ENGINE_SET_INVALID_EVENT(p, VNTAG_UNKNOWN_TYPE);
        return TM_ECODE_FAILED;
    }
    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/**
 * \test DecodeVNTagTest01 test if vntag header is too small.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVNTagtest01(void)
{
    uint8_t raw_vntag[] = { 0x00, 0x20, 0x08 };
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    g_vntag_enabled = true;
    FAIL_IF(TM_ECODE_OK == DecodeVNTag(&tv, &dtv, p, raw_vntag, sizeof(raw_vntag)));
    g_vntag_enabled = false;

    PASS_IF(ENGINE_ISSET_EVENT(p, VNTAG_HEADER_TOO_SMALL));
}

/**
 * \test DecodeVNTagt02 test if vntag header has unknown type.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVNTagtest02(void)
{
    uint8_t raw_vntag[] = { 0x00, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x0b, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x64, 0xac, 0xe6, 0x00, 0x00, 0xff, 0xfd, 0x08, 0xb3, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x02, 0x01, 0xe5, 0xa3, 0x95, 0x5c, 0x5d, 0x82, 0x50, 0x24, 0x6f, 0x56, 0xac, 0xf4,
        0xf9, 0x9b, 0x28, 0x6a, 0x03, 0xb5, 0xab, 0x15, 0xfe, 0x6c, 0xab, 0x98, 0x0c, 0x4e, 0xcc,
        0xf4, 0xd1, 0x5b, 0x22, 0x0b, 0x81, 0x39, 0x08, 0xb3, 0xcf, 0xc2, 0x6b, 0x90, 0xe1, 0xcc,
        0xe6, 0x4f, 0x5f, 0xa0, 0xb6, 0xa8, 0x93, 0x38, 0x8a, 0x17, 0xac, 0x6e, 0x3b, 0xbc, 0xad,
        0x67, 0xad, 0xfc, 0x91, 0xf0, 0x16, 0x9d, 0xe2, 0xe1, 0xdf, 0x4f, 0x8c, 0xcb, 0xd3, 0xdc,
        0xd9, 0xed, 0x3c, 0x0c, 0x92, 0xad, 0x8b, 0xf0, 0x2c, 0x2d, 0x55, 0x41 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    g_vntag_enabled = true;
    int rc = DecodeVNTag(&tv, &dtv, p, raw_vntag, sizeof(raw_vntag));
    g_vntag_enabled = false;
    PASS_IF(TM_ECODE_OK != rc);
}

/**
 * \test DecodeVNTagTest03 test a good vntag header.
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVNTagtest03(void)
{
    uint8_t raw_vntag[] = { 0x00, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x0b, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x64, 0xac, 0xe6, 0x00, 0x00, 0xff, 0xfd, 0x08, 0xb3, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x02, 0x01, 0xe5, 0xa3, 0x95, 0x5c, 0x5d, 0x82, 0x50, 0x24, 0x6f, 0x56, 0xac, 0xf4,
        0xf9, 0x9b, 0x28, 0x6a, 0x03, 0xb5, 0xab, 0x15, 0xfe, 0x6c, 0xab, 0x98, 0x0c, 0x4e, 0xcc,
        0xf4, 0xd1, 0x5b, 0x22, 0x0b, 0x81, 0x39, 0x08, 0xb3, 0xcf, 0xc2, 0x6b, 0x90, 0xe1, 0xcc,
        0xe6, 0x4f, 0x5f, 0xa0, 0xb6, 0xa8, 0x93, 0x38, 0x8a, 0x17, 0xac, 0x6e, 0x3b, 0xbc, 0xad,
        0x67, 0xad, 0xfc, 0x91, 0xf0, 0x16, 0x9d, 0xe2, 0xe1, 0xdf, 0x4f, 0x8c, 0xcb, 0xd3, 0xdc,
        0xd9, 0xed, 0x3c, 0x0c, 0x92, 0xad, 0x8b, 0xf0, 0x2c, 0x2d, 0x55, 0x41 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);

    ThreadVars tv = { 0 };
    DecodeThreadVars dtv = { 0 };

    FlowInitConfig(FLOW_QUIET);

    g_vntag_enabled = true;
    FAIL_IF(TM_ECODE_OK != DecodeVNTag(&tv, &dtv, p, raw_vntag, sizeof(raw_vntag)));
    g_vntag_enabled = false;

    PACKET_RECYCLE(p);
    FlowShutdown();
    SCFree(p);

    PASS;
}

/**
 * \test DecodeVNTagtest04 Ensure decoder is disabled by default
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int DecodeVNTagtest04(void)
{
    FAIL_IF(g_vntag_enabled);
    PASS;
}
#endif /* UNITTESTS */

void DecodeVNTagRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DecodeVNTagtest01", DecodeVNTagtest01);
    UtRegisterTest("DecodeVNTagtest02", DecodeVNTagtest02);
    UtRegisterTest("DecodeVNTagtest03", DecodeVNTagtest03);
    UtRegisterTest("DecodeVNTagtest04", DecodeVNTagtest04);
#endif /* UNITTESTS */
}

/**
 * @}
 */
