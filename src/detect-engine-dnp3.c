/* Copyright (C) 2015 Open Information Security Foundation
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
#include "stream.h"
#include "detect.h"
#include "detect-engine-content-inspection.h"
#include "detect-dnp3.h"
#include "app-layer-dnp3.h"

static int DetectEngineInspectDNP3Obj(DetectDNP3 *detect,
    DNP3ObjectList *objects)
{
    DNP3Object *object;

    TAILQ_FOREACH(object, objects, next) {
        if (object->group == detect->obj_group &&
            object->variation == detect->obj_variation) {
            return 1;
        }
    }

    return 0;
}

int DetectEngineInspectDNP3(ThreadVars *tv, DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
    void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_DNP3_MATCH];
    DetectDNP3 *detect = (DetectDNP3 *) sm->ctx;
    int match = 0;

    if (detect->detect_type == DNP3_DETECT_TYPE_FC) {
        if (flags & STREAM_TOSERVER) {
            match = detect->function_code == tx->request_ah.function_code;
        }
        else if (flags & STREAM_TOCLIENT) {
            match = detect->function_code == tx->response_ah.function_code;
        }
    }
    else if ((flags & STREAM_TOCLIENT) &&
        (detect->detect_type == DNP3_DETECT_TYPE_IND)) {
        if ((tx->response_iin.iin1 & (detect->ind_flags >> 8)) ||
            (tx->response_iin.iin2 & (detect->ind_flags & 0xf))) {
            match = 1;
        }
    }
    else if (detect->detect_type == DNP3_DETECT_TYPE_OBJ) {
        if (flags & STREAM_TOSERVER) {
            match = DetectEngineInspectDNP3Obj(detect, &tx->request_objects);
        }
        else if (flags & STREAM_TOCLIENT) {
            match = DetectEngineInspectDNP3Obj(detect, &tx->response_objects);
        }
    }

    SCReturnInt(match);
}

int DetectEngineInspectDNP3Data(ThreadVars *tv, DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
    void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();
    DNP3Transaction *tx = (DNP3Transaction *)txv;

    int r = 0;

    /* Content match - should probably be put into its own file. */
    if (flags & STREAM_TOSERVER && tx->request_buffer != NULL) {
        r = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_DNP3_DATA_MATCH], f, tx->request_buffer,
            tx->request_buffer_len, 0, 0, NULL);
    }
    else if (flags & STREAM_TOCLIENT && tx->response_buffer != NULL) {
        r = DetectEngineContentInspection(de_ctx, det_ctx, s,
            s->sm_lists[DETECT_SM_LIST_DNP3_DATA_MATCH], f, tx->response_buffer,
            tx->response_buffer_len, 0, 0, NULL);
    }

    SCReturnInt(r);
}

int DetectEngineInspectDNP3Lua(ThreadVars *tv, DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
    void *alstate, void *txv, uint64_t tx_id)
{
    SCEnter();
    int match = 0;

    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_DNP3_LUA_MATCH];
    if (smd != NULL) {
        while (1) {
            match = sigmatch_table[smd->type]
                .AppLayerTxMatch(tv, det_ctx, f, flags, alstate, txv, s,
                    smd->ctx);
            if (match == 0) {
                return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
            }
            if (match == 2) {
                return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
            }

            if (smd->is_last) {
                break;
            }
            smd++;
        }
    }

    SCReturnInt(DETECT_ENGINE_INSPECT_SIG_MATCH);
}
