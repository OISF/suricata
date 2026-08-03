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
    DetectMultiIndex index_type;
    DetectUintIndexPrecise *prec;
    DetectAbsentData *dad;
    void *sm_ctx = SCDetectMultiIndexParse(arg, &index_type);
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
                        de_ctx, s, DETECT_ABSENT, (SigMatchCtx *)dad, s->init_data->list) != NULL) {
                return 0;
            }
            sigmatch_table[DETECT_ABSENT].Free(de_ctx, dad);
            return -1;
        case DetectMultiIndexAll:
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_MULTI_ALL, NULL, s->init_data->list) !=
                    NULL) {
                return 0;
            }
            return -1;
        case DetectMultiIndexAllOrAbsent:
            if (SCSigMatchAppendSMToList(
                        de_ctx, s, DETECT_MULTI_ALL_OR_ABSENT, NULL, s->init_data->list) != NULL) {
                return 0;
            }
            return -1;
        case DetectMultiIndexNb:
            if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_MULTI_NB, sm_ctx, s->init_data->list) !=
                    NULL) {
                return 0;
            }
            return -1;
        case DetectMultiIndexPrecise:
            prec = (DetectUintIndexPrecise *)sm_ctx;
            if (prec->pos < 0) {
                SCLogError("negative index is not yet supported");
            }
            if (SCSigMatchAppendSMToList(
                        de_ctx, s, DETECT_MULTI_INDEX, sm_ctx, s->init_data->list) != NULL) {
                return 0;
            }
            return -1;
        default:
            SCLogError("invalid argument for multi-buffer");
            return -1;
    }
}

static void DetectMultiIndexFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectMultiIndexFree(ptr);
}

void DetectMultiRegister(void)
{
    // These are not used as a regular keyword
    // But as option that can be set on multi-buffers
    sigmatch_table[DETECT_MULTI_NB].name = "multi_nb";
    sigmatch_table[DETECT_MULTI_NB].desc = "count number of matches in a multi-buffer";
    sigmatch_table[DETECT_MULTI_NB].Free = DetectDu32Free;

    sigmatch_table[DETECT_MULTI_INDEX].name = "multi_index";
    sigmatch_table[DETECT_MULTI_INDEX].desc = "try to match a multi-buffer at a specific index";
    sigmatch_table[DETECT_MULTI_INDEX].Free = DetectMultiIndexFree;
}

bool DetectMultiValidateContentCallback(const Signature *s, const SignatureInitDataBuffer *b)
{
    const SigMatch *sm = b->head;
    if (sm != NULL && sm->next == NULL &&
            (sm->type == DETECT_MULTI_ALL || sm->type == DETECT_MULTI_ALL_OR_ABSENT ||
                    sm->type == DETECT_MULTI_NB || sm->type == DETECT_MULTI_INDEX)) {
        SCLogError("signature with multi-buffer keyword: expects other keywords to test on such as "
                   "content");
        return false;
    }

    return true;
}
