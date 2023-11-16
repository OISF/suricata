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

int DetectHelperBufferRegister(const char *name, AppProto alproto, bool toclient, bool toserver)
{
    if (toserver) {
        DetectAppLayerInspectEngineRegister2(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    }
    if (toclient) {
        DetectAppLayerInspectEngineRegister2(
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
        DetectAppLayerInspectEngineRegister2(
                name, alproto, SIG_FLAG_TOSERVER, 0, DetectEngineInspectBufferGeneric, GetData);
        DetectAppLayerMpmRegister2(
                name, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister, GetData, alproto, 0);
    }
    if (toclient) {
        DetectAppLayerInspectEngineRegister2(
                name, alproto, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectBufferGeneric, GetData);
        DetectAppLayerMpmRegister2(
                name, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister, GetData, alproto, 0);
    }
    DetectBufferTypeSetDescriptionByName(name, desc);
    return DetectBufferTypeGetByName(name);
}

int DetectHelperKeywordRegister(const SCPluginSigTableElmt *kw)
{
    if (DETECT_TBLSIZE_IDX < DETECT_TBLSIZE) {
        sigmatch_table[DETECT_TBLSIZE_IDX].name = kw->name;
        sigmatch_table[DETECT_TBLSIZE_IDX].desc = kw->desc;
        sigmatch_table[DETECT_TBLSIZE_IDX].flags = kw->flags;
        sigmatch_table[DETECT_TBLSIZE_IDX].AppLayerTxMatch = kw->AppLayerTxMatch;
        sigmatch_table[DETECT_TBLSIZE_IDX].Setup = kw->Setup;
        sigmatch_table[DETECT_TBLSIZE_IDX].Free = kw->Free;
        DETECT_TBLSIZE_IDX++;
        return DETECT_TBLSIZE_IDX - 1;
    }
    return -1;
}

int DetectHelperKeywordSetup(AppProto alproto, int kw_id, int buf_id, Signature *s, void *ctx)
{
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, alproto) != 0)
        return -1;

    /* okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        return -1;

    sm->type = (uint16_t)kw_id;
    sm->ctx = ctx;

    SigMatchAppendSMToList(s, sm, buf_id);
    return 0;
}
