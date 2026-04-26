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
 * Implements sctp.data sticky buffer
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-sctp-data.h"
#include "detect-engine-prefilter.h"

static int DetectSCTPDataSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
void DetectSCTPDataRegisterTests(void);
#endif

static int g_sctp_data_buffer_id = 0;

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

void DetectSCTPDataRegister(void)
{
    sigmatch_table[DETECT_SCTP_DATA].name = "sctp.data";
    sigmatch_table[DETECT_SCTP_DATA].desc = "sticky buffer to match on the SCTP DATA chunk payload";
    sigmatch_table[DETECT_SCTP_DATA].url = "/rules/header-keywords.html#sctp-data";
    sigmatch_table[DETECT_SCTP_DATA].Setup = DetectSCTPDataSetup;
    sigmatch_table[DETECT_SCTP_DATA].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
#ifdef UNITTESTS
    sigmatch_table[DETECT_SCTP_DATA].RegisterTests = DetectSCTPDataRegisterTests;
#endif

    g_sctp_data_buffer_id = DetectBufferTypeRegister("sctp.data");
    BUG_ON(g_sctp_data_buffer_id < 0);

    DetectBufferTypeSupportsPacket("sctp.data");

    DetectPktMpmRegister("sctp.data", 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister("sctp.data", GetData, DetectEngineInspectPktBufferGeneric);
}

/**
 * \brief setup sctp.data sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSCTPDataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_sctp_data_buffer_id) < 0)
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

    const uint16_t data_offset = p->l4.vars.sctp.data_offset;
    const uint16_t data_len = p->l4.vars.sctp.data_len;
    if (data_len == 0) {
        SCReturnPtr(NULL, "InspectionBuffer");
    }

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *data = (const uint8_t *)PacketGetSCTP(p) + data_offset;
        if ((data + (ptrdiff_t)data_len) >
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
            SCLogDebug("data out of range: %p > %p", (data + (ptrdiff_t)data_len),
                    ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
            SCReturnPtr(NULL, "InspectionBuffer");
        }

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }

    SCReturnPtr(buffer, "InspectionBuffer");
}

#ifdef UNITTESTS
#include "tests/detect-sctp-data.c"
#endif
