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

#include "detect-count.h"
#include "detect-engine-buffer.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

#include "util-validate.h"

static void DetectCountFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU32Free(ptr);
}

static int DetectCountSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    int sm_list = DETECT_SM_LIST_PMATCH;
    if (s->init_data->list == DETECT_SM_LIST_NOTSET) {
        SCLogError("count must be applied on a multi-buffer");
        return -1;
    }
    if (DetectBufferGetActiveList(de_ctx, s) == -1) {
        SCLogError("count must be applied on a multi-buffer");
        return -1;
    }

    sm_list = s->init_data->list;
    // TODO check it is a multi buffer and not a single buffer

    DetectU32Data *du32 = SCDetectU32Parse(arg);
    if (du32 == NULL) {
        SCLogError("invalid count argument");
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_COUNT, (SigMatchCtx *)du32, sm_list) != NULL) {
        return 0;
    }
    SCLogError("error during count setup");
    DetectCountFree(de_ctx, du32);
    return -1;
}

bool DetectCountDoMatch(DetectEngineThreadCtx *det_ctx, Flow *f, const uint8_t flow_flags,
        void *txv, InspectionMultiBufferGetDataPtr GetBuf, const SigMatchCtx *ctx)
{
    uint32_t count = 0;
    if (!GetBuf(det_ctx, txv, flow_flags, DETECT_COUNT_INDEX, NULL, &count)) {
        DEBUG_VALIDATE_BUG_ON(1);
        return false;
    }
    DetectU32Data *du32 = (DetectU32Data *)ctx;

    return DetectU32Match(count, du32);
}

void DetectCountRegister(void)
{
    sigmatch_table[DETECT_COUNT].name = "count";
    sigmatch_table[DETECT_COUNT].desc = "count number of buffers in a multi-buffer";
    // TODO doc
    sigmatch_table[DETECT_COUNT].url = "/rules/payload-keywords.html#count";
    sigmatch_table[DETECT_COUNT].Free = DetectCountFree;
    sigmatch_table[DETECT_COUNT].Setup = DetectCountSetup;
}
