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

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"

#include "detect-entropy.h"
#include "util-var-name.h"
#include "flow-var.h"

#include "rust.h"

static int DetectEntropySetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectEntropyData *ded = SCDetectEntropyParse(arg);
    if (ded == NULL) {
        goto error;
    }

    int sm_list = DETECT_SM_LIST_PMATCH;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        /* sticky buffer */
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        sm_list = s->init_data->list;
        const char *name;
        if (sm_list == DETECT_SM_LIST_BASE64_DATA) {
            name = "base64_data";
        } else {
            name = DetectEngineBufferTypeGetNameById(de_ctx, sm_list);
            if (name == NULL) {
                DEBUG_VALIDATE_BUG_ON(1);
                name = "unknown";
            }
        }
        ded->fv_idx = VarNameStoreRegister(name, VAR_TYPE_FLOW_FLOAT);
    } else {
        ded->fv_idx = VarNameStoreRegister("content", VAR_TYPE_FLOW_FLOAT);
    }
    if (ded->fv_idx == 0) {
        goto error;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_ENTROPY, (SigMatchCtx *)ded, sm_list) != NULL) {
        SCReturnInt(0);
    }

    /* fall through */

error:
    SCLogDebug("error during entropy setup");
    if (ded != NULL) {
        SCDetectEntropyFree(ded);
    }
    SCReturnInt(-1);
}

static void DetectEntropyFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr) {
        DetectEntropyData *ded = (DetectEntropyData *)ptr;
        VarNameStoreUnregister(ded->fv_idx, VAR_TYPE_FLOW_FLOAT);
        SCDetectEntropyFree(ptr);
    }
}

bool DetectEntropyDoMatch(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchCtx *ctx, Flow *flow, const uint8_t *buffer, const uint32_t buffer_len)
{
    double entropy = -1.0;
    bool rc = SCDetectEntropyMatch(buffer, buffer_len, (const DetectEntropyData *)ctx, &entropy);

    if (flow && entropy != -1.0) {
        DetectEntropyData *ded = (DetectEntropyData *)ctx;
        FlowVarAddFloat(flow, ded->fv_idx, entropy);
    }

    return rc;
}

void DetectEntropyRegister(void)
{
    sigmatch_table[DETECT_ENTROPY].name = "entropy";
    sigmatch_table[DETECT_ENTROPY].desc = "calculate entropy";
    sigmatch_table[DETECT_ENTROPY].url = "/rules/payload-keywords.html#entropy";
    sigmatch_table[DETECT_ENTROPY].Free = DetectEntropyFree;
    sigmatch_table[DETECT_ENTROPY].Setup = DetectEntropySetup;
}
