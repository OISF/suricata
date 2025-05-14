/* Copyright (C) 2025 Open Information Security Foundation
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
 * Detect keyword for DNS response: dns.response.rrname
 */

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-helper.h"
#include "detect-dns-response.h"
#include "util-profiling.h"
#include "rust.h"

static int detect_buffer_id = 0;
static int mdns_detect_buffer_id = 0;

typedef struct PrefilterMpm {
    int list_id;
    const MpmCtx *mpm_ctx;
    const DetectEngineTransforms *transforms;
} PrefilterMpm;

enum DnsResponseSection {
    DNS_RESPONSE_QUERY = 0,
    DNS_RESPONSE_ANSWER,
    DNS_RESPONSE_AUTHORITY,
    DNS_RESPONSE_ADDITIONAL,

    /* always last */
    DNS_RESPONSE_MAX,
};

struct DnsResponseGetDataArgs {
    enum DnsResponseSection response_section; /**< query, answer, authority, additional */
    uint32_t response_id;                     /**< index into response resource records */
    uint32_t local_id;                        /**< used as index into thread inspect array */
};

static int DetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, detect_buffer_id) < 0) {
        return -1;
    }
    if (SCDetectSignatureSetAppProto(s, ALPROTO_DNS) < 0) {
        return -1;
    }

    return 0;
}

static int MdnsDetectSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, mdns_detect_buffer_id) < 0) {
        return -1;
    }
    if (SCDetectSignatureSetAppProto(s, ALPROTO_MDNS) < 0) {
        return -1;
    }

    return 0;
}

static InspectionBuffer *GetBuffer(DetectEngineThreadCtx *det_ctx, uint8_t flags,
        const DetectEngineTransforms *transforms, void *txv, struct DnsResponseGetDataArgs *cbdata,
        int list_id, bool get_rdata)
{
    InspectionBuffer *buffer =
            InspectionBufferMultipleForListGet(det_ctx, list_id, cbdata->local_id);
    if (buffer == NULL) {
        return NULL;
    }
    if (buffer->initialized) {
        return buffer;
    }

    const uint8_t *data = NULL;
    uint32_t data_len = 0;

    if (get_rdata) {
        /* Get rdata values that are formatted as resource names.  */
        switch (cbdata->response_section) {
            case DNS_RESPONSE_ANSWER:
                if (!SCDnsTxGetAnswerRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_AUTHORITY:
                if (!SCDnsTxGetAuthorityRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ADDITIONAL:
                if (!SCDnsTxGetAdditionalRdata(txv, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            default:
                InspectionBufferSetupMultiEmpty(buffer);
                return NULL;
        }
    } else {
        /* Get name values. */
        switch (cbdata->response_section) {
            case DNS_RESPONSE_QUERY:
                if (!SCDnsTxGetQueryName(
                            det_ctx, txv, STREAM_TOCLIENT, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ANSWER:
                if (!SCDnsTxGetAnswerName(
                            det_ctx, txv, STREAM_TOCLIENT, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_AUTHORITY:
                if (!SCDnsTxGetAuthorityName(
                            det_ctx, txv, 0, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            case DNS_RESPONSE_ADDITIONAL:
                if (!SCDnsTxGetAdditionalName(
                            det_ctx, txv, 0, cbdata->response_id, &data, &data_len)) {
                    InspectionBufferSetupMultiEmpty(buffer);
                    return NULL;
                }
                break;
            default:
                InspectionBufferSetupMultiEmpty(buffer);
                return NULL;
        }
    }

    InspectionBufferSetupMulti(det_ctx, buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

static inline uint8_t CheckSectionRecords(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const struct DetectEngineAppInspectionEngine_ *engine, const Signature *s, Flow *f,
        uint8_t flags, void *txv, const DetectEngineTransforms *transforms, uint32_t *local_id,
        enum DnsResponseSection section)
{
    uint32_t response_id = 0;

    /* loop through each record in DNS response section inspecting "name" and "rdata" */
    while (1) {
        struct DnsResponseGetDataArgs cbdata = { section, response_id, *local_id };

        /* do inspection for resource record "name" */
        InspectionBuffer *buffer =
                GetBuffer(det_ctx, flags, transforms, txv, &cbdata, engine->sm_list, false);
        if (buffer == NULL || buffer->inspect == NULL) {
            (*local_id)++;
            break;
        }

        if (DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd, NULL, f, buffer,
                    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE)) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }

        (*local_id)++;
        if (section == DNS_RESPONSE_QUERY) {
            /* no rdata to inspect for query section, move on to next record */
            response_id++;
            continue;
        }

        /* do inspection for resource record "rdata" */
        cbdata.local_id = *local_id;
        buffer = GetBuffer(det_ctx, flags, transforms, txv, &cbdata, engine->sm_list, true);
        if (buffer == NULL || buffer->inspect == NULL) {
            (*local_id)++;
            response_id++;
            continue;
        }

        if (DetectEngineContentInspectionBuffer(de_ctx, det_ctx, s, engine->smd, NULL, f, buffer,
                    DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE)) {
            return DETECT_ENGINE_INSPECT_SIG_MATCH;
        }
        (*local_id)++;
        response_id++;
    }
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static inline void CheckSectionRecordsPrefilter(DetectEngineThreadCtx *det_ctx, const void *pectx,
        void *txv, const uint8_t flags, uint32_t *local_id, enum DnsResponseSection section)
{
    const PrefilterMpm *ctx = (const PrefilterMpm *)pectx;
    const MpmCtx *mpm_ctx = ctx->mpm_ctx;
    const int list_id = ctx->list_id;
    uint32_t response_id = 0;

    while (1) {
        struct DnsResponseGetDataArgs cbdata = { section, response_id, *local_id };

        /* extract resource record "name" */
        InspectionBuffer *buffer =
                GetBuffer(det_ctx, flags, ctx->transforms, txv, &cbdata, list_id, false);
        if (buffer == NULL) {
            (*local_id)++;
            break;
        }

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }

        (*local_id)++;
        if (section == DNS_RESPONSE_QUERY) {
            /* no rdata to inspect for query section, move on to next name entry */
            response_id++;
            continue;
        }

        /* extract resource record "rdata" */
        cbdata.local_id = *local_id;
        buffer = GetBuffer(det_ctx, flags, ctx->transforms, txv, &cbdata, list_id, true);
        if (buffer == NULL) {
            (*local_id)++;
            response_id++;
            continue;
        }

        if (buffer->inspect_len >= mpm_ctx->minlen) {
            (void)mpm_table[mpm_ctx->mpm_type].Search(
                    mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, buffer->inspect, buffer->inspect_len);
            PREFILTER_PROFILING_ADD_BYTES(det_ctx, buffer->inspect_len);
        }
        (*local_id)++;
        response_id++;
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

    uint32_t local_id = 0;
    uint8_t ret_match = DETECT_ENGINE_INSPECT_SIG_NO_MATCH;

    /* loop through each possible DNS response section */
    for (enum DnsResponseSection section = DNS_RESPONSE_QUERY;
            section < DNS_RESPONSE_MAX && ret_match == DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            section++) {

        /* check each record in section inspecting "name" and "rdata" */
        ret_match = CheckSectionRecords(
                de_ctx, det_ctx, engine, s, f, flags, txv, transforms, &local_id, section);
    }
    return ret_match;
}

static void DetectDnsResponsePrefilterTx(DetectEngineThreadCtx *det_ctx, const void *pectx,
        Packet *p, Flow *f, void *txv, const uint64_t idx, const AppLayerTxData *_txd,
        const uint8_t flags)
{
    SCEnter();

    uint32_t local_id = 0;
    /* loop through each possible DNS response section */
    for (enum DnsResponseSection section = DNS_RESPONSE_QUERY; section < DNS_RESPONSE_MAX;
            section++) {
        /* check each record in section inspecting "name" and "rdata" */
        CheckSectionRecordsPrefilter(det_ctx, pectx, txv, flags, &local_id, section);
    }
}

static void DetectDnsResponsePrefilterMpmFree(void *ptr)
{
    SCFree(ptr);
}

static int DetectDnsResponsePrefilterMpmRegister(DetectEngineCtx *de_ctx, SigGroupHead *sgh,
        MpmCtx *mpm_ctx, const DetectBufferMpmRegistry *mpm_reg, int list_id)
{
    PrefilterMpm *pectx = SCCalloc(1, sizeof(*pectx));
    if (pectx == NULL) {
        return -1;
    }
    pectx->list_id = list_id;
    pectx->mpm_ctx = mpm_ctx;
    pectx->transforms = &mpm_reg->transforms;

    return PrefilterAppendTxEngine(de_ctx, sgh, DetectDnsResponsePrefilterTx,
            mpm_reg->app_v2.alproto, mpm_reg->app_v2.tx_min_progress, pectx,
            DetectDnsResponsePrefilterMpmFree, mpm_reg->pname);
}

static void SCDetectMdnsResponseRrnameRegister(void)
{
    static const char *keyword = "mdns.response.rrname";
    int keyword_id = SCDetectHelperNewKeywordId();
    sigmatch_table[keyword_id].name = keyword;
    sigmatch_table[keyword_id].desc = "mDNS response rrname buffer";
    sigmatch_table[keyword_id].url = "/rules/mdns-keywords.html#mdns-response-rrname";
    sigmatch_table[keyword_id].Setup = MdnsDetectSetup;
    sigmatch_table[keyword_id].flags |= SIGMATCH_NOOPT;
    sigmatch_table[keyword_id].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register in the TO_SERVER direction, as all mDNS is toserver. */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_MDNS, SIG_FLAG_TOSERVER, 1, DetectEngineInspectCb, NULL);
    DetectAppLayerMpmRegister(keyword, SIG_FLAG_TOSERVER, 2, DetectDnsResponsePrefilterMpmRegister,
            NULL, ALPROTO_MDNS, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "mdns response rdata");
    DetectBufferTypeSupportsMultiInstance(keyword);

    mdns_detect_buffer_id = DetectBufferTypeGetByName(keyword);
}

void DetectDnsResponseRegister(void)
{
    static const char *keyword = "dns.response.rrname";
    sigmatch_table[DETECT_DNS_RESPONSE].name = keyword;
    sigmatch_table[DETECT_DNS_RESPONSE].desc = "DNS response sticky buffer";
    sigmatch_table[DETECT_DNS_RESPONSE].url = "/rules/dns-keywords.html#dns-response-rrname";
    sigmatch_table[DETECT_DNS_RESPONSE].Setup = DetectSetup;
    sigmatch_table[DETECT_DNS_RESPONSE].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_DNS_RESPONSE].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register in the TO_CLIENT direction. */
    DetectAppLayerInspectEngineRegister(
            keyword, ALPROTO_DNS, SIG_FLAG_TOCLIENT, 1, DetectEngineInspectCb, NULL);
    DetectAppLayerMpmRegister(keyword, SIG_FLAG_TOCLIENT, 2, DetectDnsResponsePrefilterMpmRegister,
            NULL, ALPROTO_DNS, 1);

    DetectBufferTypeSetDescriptionByName(keyword, "dns response rrname");
    DetectBufferTypeSupportsMultiInstance(keyword);

    detect_buffer_id = DetectBufferTypeGetByName(keyword);

    SCDetectMdnsResponseRrnameRegister();
}
