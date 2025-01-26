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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-helper.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"
#include "detect-engine-content-inspection.h"

int DetectHelperBufferRegister(const char *name, AppProto alproto, bool toclient, bool toserver)
{
    if (toserver) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    }
    if (toclient) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);
    }
    return DetectBufferTypeRegister(name);
}

InspectionBuffer *DetectHelperGetData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id,
        bool (*GetBuf)(void *txv, const uint8_t flow_flags, const uint8_t **buf, uint32_t *buf_len))
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (!GetBuf(txv, flow_flags, &b, &b_len))
            return NULL;

        InspectionBufferSetupAndApplyTransforms(det_ctx, list_id, buffer, b, b_len, transforms);
    }
    return buffer;
}

int DetectHelperBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        bool toclient, bool toserver, InspectionBufferGetDataPtr GetData)
{
    if (toserver) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectBufferGeneric, GetData);
        DetectAppLayerMpmRegister(
                name, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister, GetData, alproto, 0);
    }
    if (toclient) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectBufferGeneric, GetData);
        DetectAppLayerMpmRegister(
                name, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister, GetData, alproto, 0);
    }
    DetectBufferTypeSetDescriptionByName(name, desc);
    return DetectBufferTypeGetByName(name);
}

int DetectHelperMultiBufferProgressMpmRegister(const char *name, const char *desc, AppProto alproto,
        bool toclient, bool toserver, InspectionMultiBufferGetDataPtr GetData, int progress)
{
    if (toserver) {
        DetectAppLayerMultiRegister(
                name, alproto, SIG_FLAG_TOSERVER, progress, GetData, 2, progress);
    }
    if (toclient) {
        DetectAppLayerMultiRegister(
                name, alproto, SIG_FLAG_TOCLIENT, progress, GetData, 2, progress);
    }
    DetectBufferTypeSupportsMultiInstance(name);
    DetectBufferTypeSetDescriptionByName(name, desc);
    return DetectBufferTypeGetByName(name);
}

int DetectHelperMultiBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        bool toclient, bool toserver, InspectionMultiBufferGetDataPtr GetData)
{
    return DetectHelperMultiBufferProgressMpmRegister(
            name, desc, alproto, toclient, toserver, GetData, 0);
}

int SCDetectHelperNewKeywordId(void)
{
    if (DETECT_TBLSIZE_IDX >= DETECT_TBLSIZE) {
        void *tmp = SCRealloc(
                sigmatch_table, (DETECT_TBLSIZE + DETECT_TBLSIZE_STEP) * sizeof(SigTableElmt));
        if (unlikely(tmp == NULL)) {
            return -1;
        }
        sigmatch_table = tmp;
        memset(&sigmatch_table[DETECT_TBLSIZE], 0, DETECT_TBLSIZE_STEP * sizeof(SigTableElmt));
        DETECT_TBLSIZE += DETECT_TBLSIZE_STEP;
    }

    DETECT_TBLSIZE_IDX++;
    return DETECT_TBLSIZE_IDX - 1;
}

int DetectHelperKeywordRegister(const SCSigTableElmt *kw)
{
    int keyword_id = SCDetectHelperNewKeywordId();
    if (keyword_id < 0) {
        return -1;
    }

    sigmatch_table[keyword_id].name = kw->name;
    sigmatch_table[keyword_id].desc = kw->desc;
    sigmatch_table[keyword_id].url = kw->url;
    sigmatch_table[keyword_id].flags = kw->flags;
    sigmatch_table[keyword_id].AppLayerTxMatch =
            (int (*)(DetectEngineThreadCtx * det_ctx, Flow * f, uint8_t flags, void *alstate,
                    void *txv, const Signature *s, const SigMatchCtx *ctx)) kw->AppLayerTxMatch;
    sigmatch_table[keyword_id].Setup =
            (int (*)(DetectEngineCtx * de, Signature * s, const char *raw)) kw->Setup;
    sigmatch_table[keyword_id].Free = (void (*)(DetectEngineCtx * de, void *ptr)) kw->Free;

    return keyword_id;
}

void DetectHelperKeywordAliasRegister(int kwid, const char *alias)
{
    sigmatch_table[kwid].alias = alias;
}

int DetectHelperTransformRegister(const SCTransformTableElmt *kw)
{
    int transform_id = SCDetectHelperNewKeywordId();
    if (transform_id < 0) {
        return -1;
    }

    sigmatch_table[transform_id].name = kw->name;
    sigmatch_table[transform_id].desc = kw->desc;
    sigmatch_table[transform_id].url = kw->url;
    sigmatch_table[transform_id].flags = kw->flags;
    sigmatch_table[transform_id].Transform =
            (void (*)(DetectEngineThreadCtx * det_ctx, InspectionBuffer * buffer, void *options))
                    kw->Transform;
    sigmatch_table[transform_id].TransformValidate = (bool (*)(
            const uint8_t *content, uint16_t content_len, void *context))kw->TransformValidate;
    sigmatch_table[transform_id].Setup =
            (int (*)(DetectEngineCtx * de, Signature * s, const char *raw)) kw->Setup;
    sigmatch_table[transform_id].Free = (void (*)(DetectEngineCtx * de, void *ptr)) kw->Free;

    return transform_id;
}

InspectionBuffer *DetectHelperGetMultiData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id, uint32_t index, MultiGetTxBuffer GetBuf)
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

    if (!GetBuf(txv, flow_flags, index, &data, &data_len)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }
    InspectionBufferSetupMulti(det_ctx, buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}

const uint8_t *InspectionBufferPtr(InspectionBuffer *buf)
{
    return buf->inspect;
}

uint32_t InspectionBufferLength(InspectionBuffer *buf)
{
    return buf->inspect_len;
}
