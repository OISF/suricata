/* Copyright (C) 2007-2019 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "detect-fast-pattern.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect.h"
#endif

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-ipv6hdr.h"

/* prototypes */
static int DetectIpv6hdrSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectIpv6hdrRegisterTests (void);
#endif

static int g_ipv6hdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for ipv6.hdr: keyword
 */
void DetectIpv6hdrRegister(void)
{
    sigmatch_table[DETECT_IPV6HDR].name = "ipv6.hdr";
    sigmatch_table[DETECT_IPV6HDR].desc = "sticky buffer to match on the IPV6 header";
    sigmatch_table[DETECT_IPV6HDR].url = "/rules/header-keywords.html#ipv6hdr";
    sigmatch_table[DETECT_IPV6HDR].Setup = DetectIpv6hdrSetup;
    sigmatch_table[DETECT_IPV6HDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPV6HDR].RegisterTests = DetectIpv6hdrRegisterTests;
#endif

    g_ipv6hdr_buffer_id = DetectBufferTypeRegister("ipv6.hdr");
    BUG_ON(g_ipv6hdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("ipv6.hdr");

    DetectPktMpmRegister("ipv6.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("ipv6.hdr", GetData,
            DetectEngineInspectPktBufferGeneric);

    return;
}

/**
 * \brief setup ipv6.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIpv6hdrSetup (DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    s->proto.flags |= DETECT_PROTO_IPV6; // TODO

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (DetectBufferSetActiveList(s, g_ipv6hdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        if (p->ip6h == NULL) {
            // DETECT_PROTO_IPV6 does not prefilter
            return NULL;
        }
        uint32_t hlen = IPV6_HEADER_LEN + IPV6_GET_EXTHDRS_LEN(p);
        if (((uint8_t *)p->ip6h + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)))
        {
            SCLogDebug("data out of range: %p > %p (exthdrs_len %u)",
                    ((uint8_t *)p->ip6h + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)),
                    IPV6_GET_EXTHDRS_LEN(p));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)p->ip6h;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-ipv6hdr.c"
#endif
