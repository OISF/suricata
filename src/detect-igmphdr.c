/* Copyright (C) 2026 Open Information Security Foundation
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
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-igmphdr.h"
#include "detect-engine-prefilter.h"

/* prototypes */
static int DetectIGMPHdrSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectIGMPHdrRegisterTests(void);
#endif

static int g_igmphdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

/**
 * \brief Registration function for igmp.hdr: keyword
 */
void DetectIGMPHdrRegister(void)
{
    sigmatch_table[DETECT_IGMPHDR].name = "igmp.hdr";
    sigmatch_table[DETECT_IGMPHDR].desc = "sticky buffer to match on the IGMP header";
    sigmatch_table[DETECT_IGMPHDR].url = "/rules/header-keywords.html#igmp-hdr";
    sigmatch_table[DETECT_IGMPHDR].Setup = DetectIGMPHdrSetup;
    sigmatch_table[DETECT_IGMPHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IGMPHDR].RegisterTests = DetectIGMPHdrRegisterTests;
#endif

    g_igmphdr_buffer_id = DetectBufferTypeRegister("igmp.hdr");
    BUG_ON(g_igmphdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("igmp.hdr");

    DetectPktMpmRegister("igmp.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("igmp.hdr", GetData, DetectEngineInspectPktBufferGeneric);
}

/**
 * \brief setup igmp.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectIGMPHdrSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_IGMP)))
        return -1;

    s->proto.flags |= DETECT_PROTO_IPV4;
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_igmphdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    if (!PacketIsIGMP(p)) {
        SCReturnPtr(NULL, "InspectionBuffer");
    }

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const IGMPHdr *igmph = PacketGetIGMP(p);
        const uint16_t hlen = p->l4.vars.igmp.hlen;
        if (((uint8_t *)igmph + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
            SCLogDebug("data out of range: %p > %p", ((uint8_t *)igmph + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)igmph;

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-igmphdr.c"
#endif
