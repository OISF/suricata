/* Copyright (C) 2023 Open Information Security Foundation
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
 * Detect keyword for DNS answer rdata: dns.response.answer.rdata
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-dns-answer-name.h"
#include "rust.h"

static int DetectSetup(DetectEngineCtx *, Signature *, const char *);
static uint8_t DetectEngineInspectCb(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id);
static int dns_response_answer_name_id = 0;

void DetectDnsResponseAnswerNameRegister(void)
{
    static const char *keyword = "dns.response.answer.name";
    sigmatch_table[DETECT_AL_DNS_RESPONSE_ANSWER_NAME].name = keyword;
    sigmatch_table[DETECT_AL_DNS_RESPONSE_ANSWER_NAME].desc = "DNS answer name sticky buffer";
    sigmatch_table[DETECT_AL_DNS_RESPONSE_ANSWER_NAME].Setup = DetectSetup;
    sigmatch_table[DETECT_AL_DNS_RESPONSE_ANSWER_NAME].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_DNS_RESPONSE_ANSWER_NAME].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectCb, NULL);

    DetectBufferTypeSetDescriptionByName(keyword, "dns response answer name");
    DetectBufferTypeSupportsMultiInstance(keyword);

    dns_response_answer_name_id = DetectBufferTypeGetByName(keyword);
}

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    s->init_data->list = dns_response_answer_name_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, void *txv, uint32_t index, int list_id)
{
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, index);
    if (buffer == NULL) {
        return NULL;
    }
    if (buffer->initialized) {
        return buffer;
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (!SCDnsTxGetAnswerName(txv, index, &data, &data_len)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    } else {
        InspectionBufferSetupMulti(buffer, transforms, data, data_len);
        return buffer;
    }
}

static uint8_t DetectEngineInspectCb(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    const DetectEngineTransforms *transforms = NULL;
    if (!engine->mpm) {
        transforms = engine->v2.transforms;
    }

    for (uint32_t i = 0;; i++) {
        InspectionBuffer *buffer = GetBuffer(det_ctx, transforms, txv, i, engine->sm_list);
        if (buffer == NULL || buffer->inspect == NULL) {
            break;
        }

        det_ctx->buffer_offset = 0;
        det_ctx->discontinue_matching = 0;
        det_ctx->inspection_recursion_counter = 0;

        const int match = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)buffer->inspect, buffer->inspect_len, buffer->inspect_offset,
                DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
        if (match == 1) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
    }

    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}
