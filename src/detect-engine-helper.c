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

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
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

int DetectHelperKeywordRegister(const SCSigTableElmt *kw)
{
    if (DETECT_TBLSIZE_IDX >= DETECT_TBLSIZE) {
        void *tmp = SCRealloc(
                              sigmatch_table, (DETECT_TBLSIZE + DETECT_TBLSIZE_STEP) * sizeof(SigTableElmt));
        if (unlikely(tmp == NULL)) {
            return -1;
        }
        sigmatch_table = tmp;
        DETECT_TBLSIZE += DETECT_TBLSIZE_STEP;
    }
    
    sigmatch_table[DETECT_TBLSIZE_IDX].name = kw->name;
    sigmatch_table[DETECT_TBLSIZE_IDX].desc = kw->desc;
    sigmatch_table[DETECT_TBLSIZE_IDX].url = kw->url;
    sigmatch_table[DETECT_TBLSIZE_IDX].flags = kw->flags;
    sigmatch_table[DETECT_TBLSIZE_IDX].AppLayerTxMatch =
    (int (*)(DetectEngineThreadCtx * det_ctx, Flow * f, uint8_t flags, void *alstate,
             void *txv, const Signature *s, const SigMatchCtx *ctx)) kw->AppLayerTxMatch;
    sigmatch_table[DETECT_TBLSIZE_IDX].Setup =
    (int (*)(DetectEngineCtx * de, Signature * s, const char *raw)) kw->Setup;
    sigmatch_table[DETECT_TBLSIZE_IDX].Free = (void (*)(DetectEngineCtx * de, void *ptr)) kw->Free;
    DETECT_TBLSIZE_IDX++;
    return DETECT_TBLSIZE_IDX - 1;
}

int DetectHelperTransformRegister(const SCPluginTransformTableElmt *kw)
{
    if (DETECT_TBLSIZE_IDX < DETECT_TBLSIZE) {
        sigmatch_table[DETECT_TBLSIZE_IDX].name = kw->name;
        sigmatch_table[DETECT_TBLSIZE_IDX].desc = kw->desc;
        sigmatch_table[DETECT_TBLSIZE_IDX].flags = kw->flags;
        sigmatch_table[DETECT_TBLSIZE_IDX].Transform = kw->Transform;
        sigmatch_table[DETECT_TBLSIZE_IDX].Setup = kw->Setup;
        sigmatch_table[DETECT_TBLSIZE_IDX].Free = kw->Free;
        DETECT_TBLSIZE_IDX++;
        return DETECT_TBLSIZE_IDX - 1;
    }
    return -1;
}

InspectionBuffer *DetectHelperGetMultiData(struct DetectEngineThreadCtx_ *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id, uint32_t index,
        bool (*GetBuf)(void *txv, const uint8_t flow_flags, uint32_t index, const uint8_t **buf, uint32_t *buf_len))
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
    InspectionBufferSetupMulti(buffer, transforms, data, data_len);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;
    return buffer;
}
