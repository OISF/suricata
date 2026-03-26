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
 * Implements sctp.chunk_data multi-buffer sticky buffer.
 *
 * Each SCTP DATA chunk payload in the packet is inspected as a
 * separate buffer instance (not reassembled).
 *
 * Author: Giuseppe Longo <glongo@oisf.net>
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-inspect-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-sctp-chunk-data.h"
#include "util-mpm.h"
#include "util-profiling.h"

static int DetectSCTPChunkDataSetup(DetectEngineCtx *, Signature *, const char *);

static int g_buffer_id = 0;

/**
 * \brief Get a multi-instance inspection buffer for a specific DATA chunk.
 *
 * \param det_ctx detection engine thread context
 * \param transforms transforms to apply
 * \param p packet
 * \param list_id buffer list id
 * \param local_id multi-instance buffer index
 * \param chunk_idx index into SCTPVars data_offsets/data_lens arrays
 *
 * \retval buffer or NULL
 */
static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id,
        const uint32_t local_id, const uint8_t chunk_idx)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, local_id);
    if (buffer == NULL)
        return NULL;
    if (buffer->initialized)
        return buffer;

    const uint16_t offset = p->l4.vars.sctp.data_offsets[chunk_idx];
    const uint16_t len = p->l4.vars.sctp.data_lens[chunk_idx];
    if (len == 0) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    const uint8_t *data = (const uint8_t *)PacketGetSCTP(p) + offset;
    if ((data + (ptrdiff_t)len) > ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p))) {
        SCLogDebug("data out of range: %p > %p", (data + (ptrdiff_t)len),
                ((uint8_t *)GET_PKT_DATA(p) + (ptrdiff_t)GET_PKT_LEN(p)));
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(det_ctx, buffer, transforms, data, len);
    return buffer;
}

/**
 * \brief Custom packet inspection callback for sctp.chunk_data.
 *
 * Loops over all tracked DATA chunks, inspecting each as a separate buffer.
 */
static int DetectEngineInspectSCTPChunkData(DetectEngineThreadCtx *det_ctx,
        const DetectEnginePktInspectionEngine *engine, const Signature *s, Packet *p,
        uint8_t *_alert_flags)
{
    if (!PacketIsSCTP(p))
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    const uint8_t cnt = p->l4.vars.sctp.data_chunk_cnt;
    if (cnt == 0)
        return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    const int list_id = engine->sm_list;
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v1.transforms;
    }

    for (uint8_t i = 0; i < cnt; i++) {
        InspectionBuffer *buffer = GetBuffer(det_ctx, transforms, p, list_id, (uint32_t)i, i);
        if (buffer == NULL || buffer->inspect == NULL)
            continue;

        if (DetectEngineContentInspectionBuffer(det_ctx->de_ctx, det_ctx, s, engine->smd, p,
                    p->flow, buffer, DETECT_ENGINE_CONTENT_INSPECTION_MODE_HEADER)) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

typedef struct PrefilterMpmSCTPChunkData {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpmSCTPChunkData;

/**
 * \brief Prefilter callback: run MPM on each DATA chunk buffer.
 */
static void PrefilterMpmSCTPChunkDataPkt(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (!PacketIsSCTP(p))
        return;

    const uint8_t cnt = p->l4.vars.sctp.data_chunk_cnt;
    if (cnt == 0)
        return;

    const PrefilterMpmSCTPChunkData *ctx = (const PrefilterMpmSCTPChunkData *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;

    for (uint8_t i = 0; i < cnt; i++) {
        InspectionBuffer *buffer = GetBuffer(det_ctx, ctx->transforms, p, list_id, (uint32_t)i, i);
        if (buffer == NULL || buffer->inspect == NULL)
            continue;

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }
    }
}

static void PrefilterMpmSCTPChunkDataFree(void *ptr)
{
    SCFree(ptr);
}

static int PrefilterSCTPChunkDataRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpmSCTPChunkData *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL)
        return -1;
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendEngine(de_ctx, sgh, PrefilterMpmSCTPChunkDataPkt, 0,
            SIGNATURE_HOOK_PKT_NOT_SET, pectx, PrefilterMpmSCTPChunkDataFree, mpm_reg->pname);
}

void DetectSCTPChunkDataRegister(void)
{
    sigmatch_table[DETECT_SCTP_CHUNK_DATA].name = "sctp.chunk_data";
    sigmatch_table[DETECT_SCTP_CHUNK_DATA].desc =
            "sticky buffer to match on each SCTP DATA chunk payload";
    sigmatch_table[DETECT_SCTP_CHUNK_DATA].url = "/rules/sctp-keywords.html#sctp-chunk-data";
    sigmatch_table[DETECT_SCTP_CHUNK_DATA].Setup = DetectSCTPChunkDataSetup;
    sigmatch_table[DETECT_SCTP_CHUNK_DATA].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    g_buffer_id = DetectBufferTypeRegister("sctp.chunk_data");
    BUG_ON(g_buffer_id < 0);

    DetectBufferTypeSupportsPacket("sctp.chunk_data");
    DetectBufferTypeSupportsMultiInstance("sctp.chunk_data");

    DetectPktMpmRegister("sctp.chunk_data", 2, PrefilterSCTPChunkDataRegister, NULL);

    DetectPktInspectEngineRegister("sctp.chunk_data", NULL, DetectEngineInspectSCTPChunkData);
}

/**
 * \brief setup sctp.chunk_data sticky buffer
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the current Signature
 * \param _unused unused
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectSCTPChunkDataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *_unused)
{
    if (!(DetectProtoContainsProto(s->proto, IPPROTO_SCTP)))
        return -1;

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;

    return 0;
}
