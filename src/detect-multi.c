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

#include "suricata-common.h"
#include "rust.h"

#include "detect-multi.h"
#include "detect-engine-buffer.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"
// DetectAbsentData
#include "detect-isdataat.h"

#include "util-validate.h"

static void DetectDu32Free(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32Free(ptr);
}

int DetectMultiSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectU32Data *du32 = SCDetectMultiCountParse(arg);
    if (du32 != NULL) {
        if (SCSigMatchAppendSMToList(
                    de_ctx, s, DETECT_COUNT, (SigMatchCtx *)du32, s->init_data->list) != NULL) {
            return 0;
        }
        SCLogError("error during count setup");
        DetectDu32Free(de_ctx, du32);
        return -1;
    } // else not count
    DetectMultiIndex index_type;
    void *sm_ctx = SCDetectMultiIndexParse(arg, &index_type);
    DetectAbsentData *dad;
    switch (index_type) {
        case DetectMultiIndexAny:
            // default case, nothing to do
            return 0;
        case DetectMultiIndexAbsentOr:
            dad = SCMalloc(sizeof(DetectAbsentData));
            if (unlikely(dad == NULL))
                return -1;

            dad->or_else = true;
            if (SCSigMatchAppendSMToList(
                        de_ctx, s, DETECT_ABSENT, (SigMatchCtx *)dad, s->init_data->list) == NULL) {
                return 0;
            }
            // DetectAbsentFree
            SCFree(dad);
            return -1;
        case DetectMultiIndexAll:
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_MULTI_ALL, NULL, s->init_data->list) !=
                    NULL) {
                return 0;
            }
            return -1;
        case DetectMultiIndexAll1:
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_MULTI_ALL1, NULL, s->init_data->list) !=
                    NULL) {
                return 0;
            }
            return -1;
            // TODO precise index
        case DetectMultiIndexNb:
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_MULTI_NB, sm_ctx, s->init_data->list) !=
                    NULL) {
                return 0;
            }
            return -1;
        default:
            SCLogError("invalid argument for multi-buffer");
            return -1;
    }
}

bool DetectCountDoMatch(DetectEngineThreadCtx *det_ctx, Flow *f, const uint8_t flow_flags,
        void *txv, InspectionMultiBufferGetDataPtr GetBuf, const SigMatchCtx *ctx, bool eof)
{
    uint32_t count = 0;
    DetectU32Data *du32 = (DetectU32Data *)ctx;

    if (!eof && du32->mode != DETECT_UINT_GTE && du32->mode != DETECT_UINT_GT) {
        return false;
    }
    if (!GetBuf(det_ctx, txv, flow_flags, DETECT_COUNT_INDEX, NULL, &count)) {
        DEBUG_VALIDATE_BUG_ON(1);
        return false;
    }

    return DetectU32Match(count, du32);
}

void DetectCountRegister(void)
{
    // This is not used as a regular keyword
    // But an option that can be set on multi-buffers
    sigmatch_table[DETECT_COUNT].name = "count";
    sigmatch_table[DETECT_COUNT].desc = "count number of buffers in a multi-buffer";
    sigmatch_table[DETECT_COUNT].Free = DetectDu32Free;

    sigmatch_table[DETECT_MULTI_NB].Free = DetectDu32Free;
}
