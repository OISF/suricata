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
 * Implements sctp.hdr sticky buffer
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-sctphdr.h"
#include "detect-engine-prefilter.h"

static int DetectSCTPHdrSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectSCTPHdrRegisterTests(void);
#endif

static int g_sctphdr_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

void DetectSCTPHdrRegister(void)
{
    sigmatch_table[DETECT_SCTPHDR].name = "sctp.hdr";
    sigmatch_table[DETECT_SCTPHDR].desc = "sticky buffer to match on the SCTP header";
    sigmatch_table[DETECT_SCTPHDR].url = "/rules/header-keywords.html#sctp-hdr";
    sigmatch_table[DETECT_SCTPHDR].Setup = DetectSCTPHdrSetup;
    sigmatch_table[DETECT_SCTPHDR].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTPHDR].RegisterTests = DetectSCTPHdrRegisterTests;
#endif

    g_sctphdr_buffer_id = DetectBufferTypeRegister("sctp.hdr");
    BUG_ON(g_sctphdr_buffer_id < 0);

    DetectBufferTypeSupportsPacket("sctp.hdr");

    DetectPktMpmRegister("sctp.hdr", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("sctp.hdr", GetData, DetectEngineInspectPktBufferGeneric);
}

/**
 * \brief setup sctp.hdr sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSCTPHdrSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_sctphdr_buffer_id) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    SCEnter();

    if (!PacketIsSCTP(p)) {
        SCReturnPtr(NULL, "InspectionBuffer");
    }

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SCTPHdr *sctph = PacketGetSCTP(p);
        const uint16_t hlen = p->l4.vars.sctp.hlen;
        if (((uint8_t *)sctph + (ptrdiff_t)hlen) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
            SCLogDebug("data out of range: %p > %p", ((uint8_t *)sctph + (ptrdiff_t)hlen),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        const uint32_t data_len = hlen;
        const uint8_t *data = (const uint8_t *)sctph;

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-sctphdr.c"
#endif
