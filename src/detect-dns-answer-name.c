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

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectCb, NULL);

    dns_response_answer_name_id = DetectBufferTypeGetByName(keyword);
}

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    s->init_data->list = dns_response_answer_name_id;

    if (DetectSignatureSetAppProto(s, ALPROTO_DNS) != 0)
        return -1;

    return 0;
}

static uint8_t DetectEngineInspectCb(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *alstate, void *txv, uint64_t tx_id)
{
    uint8_t ret = 0;
    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    for (uint32_t i = 0;; i++) {
        if (!SCDnsTxGetAnswerName(txv, i, &data, &data_len)) {
            break;
        }
        ret = DetectEngineContentInspection(de_ctx, det_ctx, s, engine->smd, NULL, f,
                (uint8_t *)data, data_len, 0, DETECT_CI_FLAGS_SINGLE,
                DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
    }

    SCLogNotice("Returning %d.", ret);
    return ret;
}
