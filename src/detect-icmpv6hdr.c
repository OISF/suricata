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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-icmpv6hdr.h"

#ifdef UNITTESTS
#include "util-validate.h"
#include "detect-fast-pattern.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect.h"
#endif
/* prototypes */
static int DetectICMPv6hdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectICMPv6hdrRegisterTests (void);
#endif

static int g_icmpv6hdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for icmpv6.hdr: keyword
 */
void DetectICMPv6hdrRegister(void)
{
    sigmatch_table[DETECT_ICMPV6HDR].name = "icmpv6.hdr";
    sigmatch_table[DETECT_ICMPV6HDR].desc = "sticky buffer to match on the ICMP V6 header";
    sigmatch_table[DETECT_ICMPV6HDR].url = "/rules/header-keywords.html#icmpv6hdr";
    sigmatch_table[DETECT_ICMPV6HDR].Setup = DetectICMPv6hdrSetup;
    sigmatch_table[DETECT_ICMPV6HDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ICMPV6HDR].RegisterTests = DetectICMPv6hdrRegisterTests;
#endif

    g_icmpv6hdr_buffer_id = DetectBufferTypeRegister("icmpv6.hdr");
    BUG_ON(g_icmpv6hdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("icmpv6.hdr");

    DetectPktMpmRegister("icmpv6.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("icmpv6.hdr", GetData,
            DetectEngineInspectPktBufferGeneric);

    return;
}

/**
 * \brief setup icmpv6.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectICMPv6hdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    // ICMPv6 comes only with IPv6
    s->proto.flags |= DETECT_PROTO_IPV6;
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_ICMPV6)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, g_icmpv6hdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t hlen = ICMPV6_HEADER_LEN;
        if (p->icmpv6h == NULL) {
            // DETECT_PROTO_IPV6 does not prefilter
            return NULL;
        }
        if (((uint8_t *)p->icmpv6h + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
        {
            SCLogDebug("data out of range: %p > %p",
                    ((uint8_t *)p->icmpv6h + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)p->icmpv6h;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-icmpv6hdr.c"
#endif
