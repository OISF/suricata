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

/*
 * Base size required for the entropy var name:
 * - 17 (tags)
 *   10 (max sid)
 *   5 (separators)
 *   2 (entropy instance cnt)
 */
#define ENTROPY_VAR_NAME_BASE_LEN (17 + 10 + 5 + 2)
#define ENTROPY_VAR_NAME_FORMAT   "sid:%d;buffer:%s;instance:%d"

static int DetectEntropyRuleInstanceCount(Signature *s)
{
    int entropy_cnt = 1;
    for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
        for (SigMatch *sm = s->init_data->buffers[x].head; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_ENTROPY) {
                ++entropy_cnt;
            }
        }
    }

    return entropy_cnt;
}

static int DetectEntropySetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{

    int unique_name;
    SCConfGetBool("logging.entropy.make-unique", &unique_name);
    if (unique_name) {
        SCLogConfig("entropy values are marked with signature_id");
    }

    DetectEntropyData *ded = SCDetectEntropyParse(arg);
    if (ded == NULL) {
        goto error;
    }

    int sm_list = DETECT_SM_LIST_PMATCH;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        sm_list = s->init_data->list;
        const char *var_name_ptr = DetectEngineBufferTypeGetNameById(de_ctx, sm_list);
        if (unique_name) {
            int entropy_cnt = DetectEntropyRuleInstanceCount(s);
            SCLogDebug("There are a total of %d entropy usages in this rule", entropy_cnt);

            char name_buf[ENTROPY_VAR_NAME_BASE_LEN + strlen(var_name_ptr)];
            snprintf(name_buf, sizeof(name_buf), ENTROPY_VAR_NAME_FORMAT, s->id, var_name_ptr,
                    entropy_cnt);

            ded->fv_idx = VarNameStoreRegister(name_buf, VAR_TYPE_FLOW_FLOAT);
        } else {
            ded->fv_idx = VarNameStoreRegister(var_name_ptr, VAR_TYPE_FLOW_FLOAT);
        }
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
        const SigMatchCtx *ctx, const uint8_t *buffer, const uint32_t buffer_len)
{
    double entropy = -1.0;
    bool rc = SCDetectEntropyMatch(buffer, buffer_len, (const DetectEntropyData *)ctx, &entropy);

    if (entropy != -1.0) {
        DetectEntropyData *ded = (DetectEntropyData *)ctx;
        FlowVarAddFloat(det_ctx->p->flow, ded->fv_idx, entropy);
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
