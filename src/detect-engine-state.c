/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \defgroup sigstate State support
 *
 * It is possible to do matching on reconstructed applicative flow.
 * This is done by this code. It uses the ::Flow structure to store
 * the list of signatures to match on the reconstructed stream.
 *
 * The Flow::de_state is a ::DetectEngineState structure. This is
 * basically a containter for storage item of type ::DeStateStore.
 * They contains an array of ::DeStateStoreItem which store the
 * state of match for an individual signature identified by
 * DeStateStoreItem::sid.
 *
 * The state is constructed by DeStateDetectStartDetection() which
 * also starts the matching. Work is continued by
 * DeStateDetectContinueDetection().
 *
 * Once a transaction has been analysed DeStateRestartDetection()
 * is used to reset the structures.
 *
 * @{
 */

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * \brief State based signature handling
 *
 */

#include "suricata-common.h"

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-state.h"

#include "detect-engine-uri.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-dcepayload.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc-common.h"
#include "app-layer-dcerpc.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

/** convert enum to string */
#define CASE_CODE(E)  case E: return #E

/** \brief get string for match enum */
const char *DeStateMatchResultToString(DeStateMatchResult res)
{
    switch (res) {
        CASE_CODE (DE_STATE_MATCH_NOSTATE);
        CASE_CODE (DE_STATE_MATCH_FULL);
        CASE_CODE (DE_STATE_MATCH_PARTIAL);
        CASE_CODE (DE_STATE_MATCH_NEW);
    }

    return NULL;
}

/**
 *  \brief Alloc a DeStateStore object
 *  \retval d alloc'd object
 */
DeStateStore *DeStateStoreAlloc(void) {
    SCEnter();

    DeStateStore *d = SCMalloc(sizeof(DeStateStore));
    if (d == NULL) {
        SCReturnPtr(NULL, "DeStateStore");
    }
    memset(d, 0x00, sizeof(DeStateStore));

    SCReturnPtr(d, "DeStateStore");
}

/**
 *  \brief free a DeStateStore object (recursively)
 *  \param store DeStateStore object to free
 */
void DeStateStoreFree(DeStateStore *store) {
    SCEnter();

    if (store == NULL) {
        SCReturn;
    }

    if (store->next != NULL) {
        DeStateStoreFree(store->next);
    }

    SCFree(store);
    SCReturn;
}

/**
 *  \brief Alloc a DetectEngineState object
 *  \param d alloc'd object
 */
DetectEngineState *DetectEngineStateAlloc(void) {
    SCEnter();

    DetectEngineState *d = SCMalloc(sizeof(DetectEngineState));
    if (d == NULL) {
        SCReturnPtr(NULL, "DetectEngineState");
    }
    memset(d, 0x00, sizeof(DetectEngineState));

    SCReturnPtr(d, "DetectEngineState");
}

/**
 *  \brief Free a DetectEngineState object
 *         You must lock the flow mutex for de_state
 *         (f->de_state_m)
 *  \param state DetectEngineState object to free
 */
void DetectEngineStateFree(DetectEngineState *state) {
    DeStateStore *iter = NULL;
    DeStateStore *aux = NULL;

    if (state == NULL)
        return;

    iter = state->head;
    while (iter != NULL) {
        aux = iter;
        iter = iter->next;
        SCFree(aux);
    }

    state->head = NULL;
    state->tail = NULL;

    state->cnt = 0;

    SCFree(state);
}

/**
 *  \brief reset a DetectEngineState state
 *  \param state LOCKED state
 */
void DetectEngineStateReset(DetectEngineState *state) {
    SCEnter();

    DeStateStore *iter = NULL;
    DeStateStore *aux = NULL;

    if (state == NULL)
        return;

    iter = state->head;
    while (iter != NULL) {
        aux = iter;
        iter = iter->next;
        SCFree(aux);
    }

    state->head = NULL;
    state->tail = NULL;

    state->cnt = 0;

    SCReturn;
}

/**
 *  \brief update the transaction id
 *
 *  \param f unlocked flow
 *  \param direction STREAM_TOCLIENT / STREAM_TOSERVER
 *
 *  \retval 2 current transaction done, new available
 *  \retval 1 current transaction done, no new (yet)
 *  \retval 0 current transaction is not done yet
 */
int DeStateUpdateInspectTransactionId(Flow *f, char direction) {
    SCEnter();

    int r = 0;

    SCMutexLock(&f->m);
    r = AppLayerTransactionUpdateInspectId(f, direction);
    SCMutexUnlock(&f->m);

    SCReturnInt(r);
}

/**
 * \brief Append a signature to the detect engine state
 *
 * \param state the detect engine state
 * \param s signature
 * \param sm sigmatch
 * \param uri did uri already match (if any)
 * \param dce did dce already match (if any)
 * \param hcbd did http client body already match (if any)
 *
 * \todo Need to use an array to transfer all these args.  Pushing so
 *       many args is slow.
 */
static void DeStateSignatureAppend(DetectEngineState *state, Signature *s,
                                   SigMatch *sm, uint16_t match_flags) {
    DeStateStore *store = state->tail;

    if (store == NULL) {
        store = DeStateStoreAlloc();
        if (store != NULL) {
            state->head = store;
            state->tail = store;
        }
    } else {
        if ((state->cnt % DE_STATE_CHUNK_SIZE) == 0) {
            store = DeStateStoreAlloc();
            if (store != NULL) {
                state->tail->next = store;
                state->tail = store;
            }
        }
    }

    if (store == NULL) {
        return;
    }

    SigIntId idx = state->cnt % DE_STATE_CHUNK_SIZE;
    store->store[idx].sid = s->num;
    store->store[idx].flags = 0;
    store->store[idx].flags |= match_flags;
    store->store[idx].nm = sm;
    state->cnt++;

    SCLogDebug("store %p idx %"PRIuMAX" cnt %"PRIuMAX" sig id %"PRIuMAX"",
            store, (uintmax_t)idx, (uintmax_t)state->cnt,
            (uintmax_t)store->store[idx].sid);

    return;
}



/*
    on first detection run:

    for each
        (1) app layer signature
        (2a) at least one app layer sm match OR
        (2b) content/uri match AND other app layer sigmatches present

        Cases:
            multiple app layer sm's
            content + uricontent
            content + app layer sm
            uricontent + app layer sm
*/

uint16_t DeStateGetStateVersion(DetectEngineState *de_state, uint8_t direction) {
    if (direction & STREAM_TOSERVER) {
        SCReturnUInt(de_state->toserver_version);
    } else {
        SCReturnUInt(de_state->toclient_version);
    }
}

void DeStateStoreStateVersion(DetectEngineState *de_state, uint8_t direction,
        uint16_t alversion)
{
    if (direction & STREAM_TOSERVER) {
        SCLogDebug("STREAM_TOSERVER updated to %"PRIu16, alversion);
        de_state->toserver_version = alversion;
    } else {
        SCLogDebug("STREAM_TOCLIENT updated to %"PRIu16, alversion);
        de_state->toclient_version = alversion;
    }
}

/**
 *  \brief Check if a flow already contains a flow detect state
 *
 *  \retval 2 has state, but it's not updated
 *  \retval 1 has state
 *  \retval 0 has no state
 */
int DeStateFlowHasState(Flow *f, uint8_t flags, uint16_t alversion) {
    SCEnter();

    int r = 0;
    SCMutexLock(&f->de_state_m);

    if (f->de_state == NULL || f->de_state->cnt == 0)
        r = 0;
    else if (DeStateGetStateVersion(f->de_state, flags) == alversion)
        r = 2;
    else
        r = 1;

    SCMutexUnlock(&f->de_state_m);
    SCReturnInt(r);
}

/** \brief Match app layer sig list against state. Set up state for non matches
 *         and partial matches.
 *  \retval 1 match
 *  \retval 0 no or partial match
 */
int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
        void *alstate, uint16_t alproto, uint16_t alversion)
{
    SCEnter();

    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_AMATCH];
    int match = 0;
    int r = 0;
    uint16_t inspect_flags = 0;
    uint16_t match_flags = 0;

    if (alstate == NULL) {
        SCReturnInt(0);
    }

    SCLogDebug("s->id %"PRIu32, s->id);

    /* Check the uricontent, http client body, http header keywords here */
    if (alproto == ALPROTO_HTTP) {
        if (flags & STREAM_TOSERVER) {
            if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_URI_INSPECT;

                SCLogDebug("inspecting uri");

                if (DetectEngineInspectPacketUris(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1)
                {
                    SCLogDebug("uri matched");
                    match_flags |= DE_STATE_FLAG_URI_MATCH;
                } else {
                    SCLogDebug("uri inspected but no match");
                }
            }
            if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HCBD_INSPECT;
                if (DetectEngineInspectHttpClientBody(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HCBD_MATCH;
                }
                SCLogDebug("inspecting http client body");
            }
            if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HHD_INSPECT;
                if (DetectEngineInspectHttpHeader(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HHD_MATCH;
                }
                SCLogDebug("inspecting http header");
            }
            if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HRHD_INSPECT;
                if (DetectEngineInspectHttpRawHeader(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HRHD_MATCH;
                }
                SCLogDebug("inspecting http raw header");
            }
            if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HMD_INSPECT;
                if (DetectEngineInspectHttpMethod(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HMD_MATCH;
                }
                SCLogDebug("inspecting http method");
            }
            if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HCD_INSPECT;
                if (DetectEngineInspectHttpCookie(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HCD_MATCH;
                }
                SCLogDebug("inspecting http cookie");
            }
            if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HRUD_INSPECT;
                if (DetectEngineInspectHttpRawUri(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HRUD_MATCH;
                }
                SCLogDebug("inspecting http raw uri");
            }
        } else if (flags & STREAM_TOCLIENT) {
            /* For to client set the flags in inspect so it can't match
             * if the sig requires something only the request has. The rest
             * will be inspected in the opposite direction. */
            if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_URI_INSPECT;
            }
            if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HCBD_INSPECT;
            }
            if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HHD_INSPECT;
                if (DetectEngineInspectHttpHeader(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HHD_MATCH;
                }
                SCLogDebug("inspecting http header");
            }
            if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HRHD_INSPECT;
                if (DetectEngineInspectHttpRawHeader(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HRHD_MATCH;
                }
                SCLogDebug("inspecting http raw header");
            }
            if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HMD_INSPECT;
            }
            if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HCD_INSPECT;
                if (DetectEngineInspectHttpCookie(de_ctx, det_ctx, s, f,
                            flags, alstate) == 1) {
                    match_flags |= DE_STATE_FLAG_HCD_MATCH;
                }
                SCLogDebug("inspecting http cookie");
            }
            if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL) {
                inspect_flags |= DE_STATE_FLAG_HRUD_INSPECT;
            }
        }
    } else if (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
        if (s->sm_lists[DETECT_SM_LIST_DMATCH] != NULL) {
            inspect_flags |= DE_STATE_FLAG_DCE_INSPECT;

            SCLogDebug("inspecting dce payload");

            if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                SMBState *smb_state = (SMBState *)alstate;

                if (smb_state->dcerpc_present &&
                    DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                                  flags, &smb_state->dcerpc) == 1) {
                    SCLogDebug("dce payload matched");
                    match_flags |= DE_STATE_FLAG_DCE_MATCH;
                } else {
                    SCLogDebug("dce payload inspected but no match");
                }
            } else {
                if (DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                                  flags, alstate) == 1) {
                    SCLogDebug("dce payload matched");
                    match_flags |= DE_STATE_FLAG_DCE_MATCH;
                } else {
                    SCLogDebug("dce payload inspected but no match");
                }
            }
        }
    }

    if (s->sm_lists[DETECT_SM_LIST_AMATCH] != NULL) {
        for ( ; sm != NULL; sm = sm->next) {
            SCLogDebug("sm %p, sm->next %p", sm, sm->next);

            if (sigmatch_table[sm->type].AppLayerMatch != NULL &&
                (alproto == sigmatch_table[sm->type].alproto ||
                 alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) )
            {
                if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                    SMBState *smb_state = (SMBState *)alstate;

                    if (smb_state->dcerpc_present) {
                        match = sigmatch_table[sm->type].
                            AppLayerMatch(tv, det_ctx, f, flags, &smb_state->dcerpc,
                                          s, sm);
                    }
                } else {
                    match = sigmatch_table[sm->type].
                        AppLayerMatch(tv, det_ctx, f, flags, alstate, s, sm);
                }

                if (match == 0) {
                    break;
                } else if (sm->next == NULL) {
                    sm = NULL; /* set to NULL as we have a match */

                    if (inspect_flags == 0 || (inspect_flags == match_flags)) {
                        r = 1;
                    }
                    break;
                }
            }
        }
    } else {
        if (inspect_flags != 0 && (inspect_flags == match_flags)) {
            r = 1;
        }
    }

    SCLogDebug("detection done, store results: sm %p, inspect_flags %04X, "
            "match_flags %04X", sm, inspect_flags, match_flags);

    SCMutexLock(&f->de_state_m);
    /* match or no match, we store the state anyway
     * "sm" here is either NULL (complete match) or
     * the last SigMatch that didn't match */
    if (f->de_state == NULL) {
        f->de_state = DetectEngineStateAlloc();
    }
    if (f->de_state != NULL) {
        /* \todo shift to an array to transfer these match values*/
        DeStateSignatureAppend(f->de_state, s, sm, match_flags);
        DeStateStoreStateVersion(f->de_state, flags, alversion);
    }
    SCMutexUnlock(&f->de_state_m);

    SCReturnInt(r);
}

/** \brief Continue DeState detection of the signatures stored in the state.
 *
 *  \retval 0 all is good
 */
int DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, uint16_t alproto, uint16_t alversion)
{
    SCEnter();
    SigIntId cnt = 0;
    SigIntId store_cnt = 0;
    DeStateStore *store = NULL;
    uint16_t inspect_flags = 0;
    uint16_t match_flags = 0;
    int match = 0;

    if (f == NULL || alstate == NULL || alproto == ALPROTO_UNKNOWN) {
        return 0;
    }

    SCMutexLock(&f->de_state_m);

    if (f->de_state == NULL || f->de_state->cnt == 0)
        goto end;

    if (DeStateGetStateVersion(f->de_state, flags) == alversion) {
        goto end;
    }

    /* loop through the stores */
    for (store = f->de_state->head; store != NULL; store = store->next)
    {
        /* loop through the sigs in the stores */
        for (store_cnt = 0;
                store_cnt < DE_STATE_CHUNK_SIZE && cnt < f->de_state->cnt;
                store_cnt++, cnt++)
        {
            DeStateStoreItem *item = &store->store[store_cnt];

            inspect_flags = 0;
            match_flags = 0;
            match = 0;

            SCLogDebug("internal id of signature to inspect: %"PRIuMAX,
                    (uintmax_t)item->sid);

            Signature *s = de_ctx->sig_array[item->sid];
            SCLogDebug("id of signature to inspect: %"PRIuMAX,
                    (uintmax_t)s->id);

            RULE_PROFILING_START;

            /* if we already fully matched previously, detect that here */
            if (item->flags & DE_STATE_FLAG_FULL_MATCH) {
                det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_FULL;
                goto next_sig;
            }

            /* let's continue detection */

            /* first, check uricontent */
            if (alproto == ALPROTO_HTTP && (flags & STREAM_TOSERVER)) {
                if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_URI_MATCH)) {
                        SCLogDebug("inspecting uri");
                        inspect_flags |= DE_STATE_FLAG_URI_INSPECT;

                        if (DetectEngineInspectPacketUris(de_ctx, det_ctx, s,
                                    f, flags, alstate) == 1)
                        {
                            SCLogDebug("uri matched");
                            match_flags |= DE_STATE_FLAG_URI_MATCH;
                        } else {
                            SCLogDebug("uri inspected but no match");
                        }
                    } else {
                        SCLogDebug("uri already inspected");
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HCBD_MATCH)) {
                        SCLogDebug("inspecting http client body data");
                        inspect_flags |= DE_STATE_FLAG_HCBD_INSPECT;

                        if (DetectEngineInspectHttpClientBody(de_ctx, det_ctx, s, f,
                                                              flags, alstate) == 1) {
                            SCLogDebug("http client body matched");
                            match_flags |= DE_STATE_FLAG_HCBD_MATCH;
                        }
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HHD_MATCH)) {
                        SCLogDebug("inspecting http header data");
                        inspect_flags |= DE_STATE_FLAG_HHD_INSPECT;

                        if (DetectEngineInspectHttpHeader(de_ctx, det_ctx, s, f,
                                                          flags, alstate) == 1) {
                            SCLogDebug("http header matched");
                            match_flags |= DE_STATE_FLAG_HHD_MATCH;
                        }
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HRHD_MATCH)) {
                        SCLogDebug("inspecting http raw header data");
                        inspect_flags |= DE_STATE_FLAG_HRHD_INSPECT;

                        if (DetectEngineInspectHttpRawHeader(de_ctx, det_ctx, s, f,
                                                             flags, alstate) == 1) {
                            SCLogDebug("http raw header matched");
                            match_flags |= DE_STATE_FLAG_HRHD_MATCH;
                        }
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HMD_MATCH)) {
                        SCLogDebug("inspecting http method data");
                        inspect_flags |= DE_STATE_FLAG_HMD_INSPECT;

                        if (DetectEngineInspectHttpMethod(de_ctx, det_ctx, s, f,
                                                          flags, alstate) == 1) {
                            SCLogDebug("http method matched");
                            match_flags |= DE_STATE_FLAG_HMD_MATCH;
                        }
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HCD_MATCH)) {
                        SCLogDebug("inspecting http cookie data");
                        inspect_flags |= DE_STATE_FLAG_HCD_INSPECT;

                        if (DetectEngineInspectHttpCookie(de_ctx, det_ctx, s, f,
                                                          flags, alstate) == 1) {
                            SCLogDebug("http cookie matched");
                            match_flags |= DE_STATE_FLAG_HCD_MATCH;
                        }
                    }
                }
                if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_HRUD_MATCH)) {
                        SCLogDebug("inspecting http raw uri data");
                        inspect_flags |= DE_STATE_FLAG_HRUD_INSPECT;

                        if (DetectEngineInspectHttpRawUri(de_ctx, det_ctx, s, f,
                                                          flags, alstate) == 1) {
                            SCLogDebug("http raw uri matched");
                            match_flags |= DE_STATE_FLAG_HRUD_MATCH;
                        }
                    }
                }

            } else if (alproto == ALPROTO_DCERPC || alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                if (s->sm_lists[DETECT_SM_LIST_DMATCH] != NULL) {
                    if (!(item->flags & DE_STATE_FLAG_DCE_MATCH)) {
                        SCLogDebug("inspecting dce payload");
                        inspect_flags |= DE_STATE_FLAG_DCE_INSPECT;

                        if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                            SMBState *smb_state = (SMBState *)alstate;
                            //DCERPCState dcerpc_state;
                            //dcerpc_state.dcerpc = smb_state->dcerpc;
                            if (smb_state->dcerpc_present &&
                                DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                                              flags, &smb_state->dcerpc) == 1) {
                                SCLogDebug("dce payload matched");
                                match_flags |= DE_STATE_FLAG_DCE_MATCH;
                            } else {
                                SCLogDebug("dce payload inspected but no match");
                            }
                        } else {
                            if (DetectEngineInspectDcePayload(de_ctx, det_ctx, s, f,
                                                              flags, alstate) == 1) {
                                SCLogDebug("dce payload matched");
                                match_flags |= DE_STATE_FLAG_DCE_MATCH;
                            } else {
                                SCLogDebug("dce payload inspected but no match");
                            }
                        }

                    } else {
                        SCLogDebug("dce payload already inspected");
                    }
                }

            }

            /* next, check the other sig matches */
            if (item->nm != NULL) {
                SigMatch *sm;
                for (sm = item->nm; sm != NULL; sm = sm->next) {
                    if (alproto == ALPROTO_SMB || alproto == ALPROTO_SMB2) {
                        SMBState *smb_state = (SMBState *)alstate;
                        //DCERPCState dcerpc_state;
                        //dcerpc_state.dcerpc = smb_state->dcerpc;
                        if (smb_state->dcerpc_present) {
                            match = sigmatch_table[sm->type].
                                AppLayerMatch(tv, det_ctx, f, flags, &smb_state->dcerpc,
                                              s, sm);
                        }
                    } else {
                        match = sigmatch_table[sm->type].
                            AppLayerMatch(tv, det_ctx, f, flags, alstate,
                                          s, sm);
                    }
                    /* no match, break out */
                    if (match == 0) {
                        item->nm = sm;
                        det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_PARTIAL;
                        SCLogDebug("state set to %s", DeStateMatchResultToString(DE_STATE_MATCH_PARTIAL));
                        break;

                    /* match, and no more sm's */
                    } else if (sm->next == NULL) {
                        /* mark the sig as matched */
                        item->nm = NULL;

                        if (inspect_flags == 0 || (inspect_flags == match_flags)) {
                            det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NEW;
                            SCLogDebug("state set to %s", DeStateMatchResultToString(DE_STATE_MATCH_NEW));
                            match_flags |= DE_STATE_FLAG_FULL_MATCH;
                        } else {
                            det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_PARTIAL;
                            SCLogDebug("state set to %s", DeStateMatchResultToString(DE_STATE_MATCH_PARTIAL));
                        }
                    }
                }
            } else {
                if (inspect_flags != 0 && (inspect_flags == match_flags)) {
                    det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_NEW;
                    SCLogDebug("state set to %s", DeStateMatchResultToString(DE_STATE_MATCH_NEW));
                    match_flags |= DE_STATE_FLAG_FULL_MATCH;
                } else {
                    det_ctx->de_state_sig_array[item->sid] = DE_STATE_MATCH_PARTIAL;
                    SCLogDebug("state set to %s", DeStateMatchResultToString(DE_STATE_MATCH_PARTIAL));
                }
            }

            item->flags |= match_flags;

            SCLogDebug("signature %"PRIu32" match state %s",
                    s->id, DeStateMatchResultToString(det_ctx->de_state_sig_array[item->sid]));

next_sig:
            RULE_PROFILING_END(s, match);

        }
    }

    DeStateStoreStateVersion(f->de_state, flags, alversion);
end:
    SCMutexUnlock(&f->de_state_m);
    SCReturnInt(0);
}

/**
 *  \brief Restart detection as we're going to inspect a new transaction
 */
int DeStateRestartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *alstate, uint16_t alproto)
{
    SCEnter();

    /* first clear the existing state as it belongs
     * to the previous transaction */
    SCMutexLock(&f->de_state_m);
    if (f->de_state != NULL) {
        DetectEngineStateReset(f->de_state);
    }
    SCMutexUnlock(&f->de_state_m);

    SCReturnInt(0);
}

#ifdef UNITTESTS
#include "flow-util.h"

static int DeStateTest01(void) {
    SCLogDebug("sizeof(DetectEngineState)\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DetectEngineState));
    SCLogDebug("sizeof(DeStateStore)\t\t\t%"PRIuMAX,
            (uintmax_t)sizeof(DeStateStore));
    SCLogDebug("sizeof(DeStateStoreItem)\t\t%"PRIuMAX"",
            (uintmax_t)sizeof(DeStateStoreItem));
    return 1;
}

static int DeStateTest02(void) {
    int result = 0;

    DetectEngineState *state = DetectEngineStateAlloc();
    if (state == NULL) {
        printf("d == NULL: ");
        goto end;
    }

    Signature s;
    memset(&s, 0x00, sizeof(s));

    s.num = 0;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 11;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 22;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 33;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 44;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 55;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 66;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 77;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 88;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 99;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 100;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 111;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 122;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 133;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 144;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 155;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 166;
    DeStateSignatureAppend(state, &s, NULL, 0);

    if (state->head == NULL) {
        goto end;
    }

    if (state->head->store[1].sid != 11) {
        goto end;
    }

    if (state->head->next == NULL) {
        goto end;
    }

    if (state->head->store[14].sid != 144) {
        goto end;
    }

    if (state->head->next->store[0].sid != 155) {
        goto end;
    }

    if (state->head->next->store[1].sid != 166) {
        goto end;
    }

    result = 1;
end:
    if (state != NULL) {
        DetectEngineStateFree(state);
    }
    return result;
}

static int DeStateTest03(void) {
    int result = 0;

    DetectEngineState *state = DetectEngineStateAlloc();
    if (state == NULL) {
        printf("d == NULL: ");
        goto end;
    }

    Signature s;
    memset(&s, 0x00, sizeof(s));

    s.num = 11;
    DeStateSignatureAppend(state, &s, NULL, 0);
    s.num = 22;
    DeStateSignatureAppend(state, &s, NULL, DE_STATE_FLAG_URI_MATCH);

    if (state->head == NULL) {
        goto end;
    }

    if (state->head->store[0].sid != 11) {
        goto end;
    }

    if (state->head->store[0].flags & DE_STATE_FLAG_URI_MATCH) {
        goto end;
    }

    if (state->head->store[1].sid != 22) {
        goto end;
    }

    if (!(state->head->store[1].flags & DE_STATE_FLAG_URI_MATCH)) {
        goto end;
    }

    result = 1;
end:
    if (state != NULL) {
        DetectEngineStateFree(state);
    }
    return result;
}

static int DeStateSigTest01(void) {
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\nContent-Length: 10\r\n\r\n";
    uint8_t httpbuf4[] = "Http Body!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    HtpState *http_state = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"dummy\"; http_cookie; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    result = 1;
end:
    if (http_state != NULL) {
        HTPStateFree(http_state);
    }
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}

/** \test multiple pipelined http transactions */
static int DeStateSigTest02(void) {
    int result = 0;
    Signature *s = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    ThreadVars th_v;
    Flow f;
    TcpSession ssn;
    Packet *p = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\n";
    uint8_t httpbuf2[] = "User-Agent: Mozilla/1.0\r\nContent-Length: 10\r\n";
    uint8_t httpbuf3[] = "Cookie: dummy\r\n\r\n";
    uint8_t httpbuf4[] = "Http Body!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "GET /?var=val HTTP/1.1\r\n";
    uint8_t httpbuf6[] = "User-Agent: Firefox/1.0\r\n";
    uint8_t httpbuf7[] = "Cookie: dummy2\r\nContent-Length: 10\r\n\r\nHttp Body!";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    uint32_t httplen7 = sizeof(httpbuf7) - 1; /* minus the \0 */

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"POST\"; http_method; content:\"Mozilla\"; http_header; content:\"dummy\"; http_cookie; sid:1; rev:1;)");
    if (s == NULL) {
        printf("sig parse failed: ");
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"GET\"; http_method; content:\"Firefox\"; http_header; content:\"dummy2\"; http_cookie; sid:2; rev:1;)");
    if (s == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (2): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't alert: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("signature matched, but shouldn't have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted (5): ");
        goto end;
    }
    p->alerts.cnt = 0;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf6, httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if ((PacketAlertCheck(p, 1)) || (PacketAlertCheck(p, 2))) {
        printf("sig 1 alerted (request 2, chunk 6): ");
        goto end;
    }
    p->alerts.cnt = 0;

    SCLogDebug("sending data chunk 7");

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf7, httplen7);
    if (r != 0) {
        printf("toserver chunk 7 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!(PacketAlertCheck(p, 2))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }
    p->alerts.cnt = 0;

    result = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePacket(p);
    return result;
}
#endif

void DeStateRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DeStateTest01", DeStateTest01, 1);
    UtRegisterTest("DeStateTest02", DeStateTest02, 1);
    UtRegisterTest("DeStateTest03", DeStateTest03, 1);
    UtRegisterTest("DeStateSigTest01", DeStateSigTest01, 1);
    UtRegisterTest("DeStateSigTest02", DeStateSigTest02, 1);
#endif
}

/**
 * @}
 */
