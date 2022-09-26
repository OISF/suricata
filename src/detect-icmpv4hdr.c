/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-icmpv4hdr.h"

#ifdef UNITTESTS
#include "detect.h"
#endif
/* prototypes */
static int DetectIcmpv4HdrSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectIcmpv4HdrRegisterTests(void);
#endif

static int g_icmpv4hdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for icmpv4.hdr: keyword
 */
void DetectIcmpv4HdrRegister(void)
{
    sigmatch_table[DETECT_ICMPV4HDR].name = "icmpv4.hdr";
    sigmatch_table[DETECT_ICMPV4HDR].desc = "sticky buffer to match on the ICMP v4 header";
    sigmatch_table[DETECT_ICMPV4HDR].url = "/rules/header-keywords.html#icmpv4-hdr";
    sigmatch_table[DETECT_ICMPV4HDR].Setup = DetectIcmpv4HdrSetup;
    sigmatch_table[DETECT_ICMPV4HDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMPV4HDR].RegisterTests = DetectIcmpv4HdrRegisterTests;
#endif

    g_icmpv4hdr_buffer_id = DetectBufferTypeRegister("icmpv4.hdr");
    BUG_ON(g_icmpv4hdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("icmpv4.hdr");

    DetectPktMpmRegister("icmpv4.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("icmpv4.hdr", GetData, DetectEngineInspectPktBufferGeneric);

    return;
}

/**
 * \brief setup icmpv4.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIcmpv4HdrSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_ICMP)))
        return -1;

    s->proto.flags |= DETECT_PROTO_IPV4;
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, g_icmpv4hdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    if (p->icmpv4h == NULL) {
        SCReturnPtr(NULL, "InspectionBuffer");
    }

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint16_t hlen = ICMPV4_GET_HLEN_ICMPV4H(p);
        if (((uint8_t *)p->icmpv4h + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
            SCLogDebug("data out of range: %p > %p", ((uint8_t *)p->icmpv4h + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)p->icmpv4h;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-icmpv4hdr.c"
#endif
