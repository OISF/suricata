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
#include "rust.h"

int SCDetectHelperBufferRegister(const char *name, AppProto alproto, uint8_t direction)
{
    if (direction & STREAM_TOSERVER) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    }
    if (direction & STREAM_TOCLIENT) {
        DetectAppLayerInspectEngineRegister(
                name, alproto, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);
    }
    return DetectBufferTypeRegister(name);
}

int SCDetectHelperBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        uint8_t direction, InspectionSingleBufferGetDataPtr GetData)
{
    if (direction & STREAM_TOSERVER) {
        DetectAppLayerInspectEngineRegisterSingle(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectBufferSingle, GetData);
        DetectAppLayerMpmRegisterSingle(
                name, SIG_FLAG_TOSERVER, 2, PrefilterSingleMpmRegister, GetData, alproto, 0);
    }
    if (direction & STREAM_TOCLIENT) {
        DetectAppLayerInspectEngineRegisterSingle(
                name, alproto, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectBufferSingle, GetData);
        DetectAppLayerMpmRegisterSingle(
                name, SIG_FLAG_TOCLIENT, 2, PrefilterSingleMpmRegister, GetData, alproto, 0);
    }
    DetectBufferTypeSetDescriptionByName(name, desc);
    return DetectBufferTypeGetByName(name);
}

int SCDetectHelperMultiBufferProgressMpmRegister(const char *name, const char *desc,
        AppProto alproto, uint8_t direction, InspectionMultiBufferGetDataPtr GetData, int progress)
{
    if (direction & STREAM_TOSERVER) {
        DetectAppLayerMultiRegister(name, alproto, SIG_FLAG_TOSERVER, progress, GetData, 2);
    }
    if (direction & STREAM_TOCLIENT) {
        DetectAppLayerMultiRegister(name, alproto, SIG_FLAG_TOCLIENT, progress, GetData, 2);
    }
    DetectBufferTypeSupportsMultiInstance(name);
    DetectBufferTypeSetDescriptionByName(name, desc);
    return DetectBufferTypeGetByName(name);
}

int SCDetectHelperMultiBufferMpmRegister(const char *name, const char *desc, AppProto alproto,
        uint8_t direction, InspectionMultiBufferGetDataPtr GetData)
{
    return SCDetectHelperMultiBufferProgressMpmRegister(name, desc, alproto, direction, GetData, 0);
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

uint16_t SCDetectHelperKeywordRegister(const SCSigTableAppLiteElmt *kw)
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

    return (uint16_t)keyword_id;
}

void SCDetectHelperKeywordAliasRegister(uint16_t kwid, const char *alias)
{
    sigmatch_table[kwid].alias = alias;
}

int SCDetectHelperTransformRegister(const SCTransformTableElmt *kw)
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
    sigmatch_table[transform_id].TransformId =
            (void (*)(const uint8_t **id_data, uint32_t *length, void *context))kw->TransformId;

    return transform_id;
}
