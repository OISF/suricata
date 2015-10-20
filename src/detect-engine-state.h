/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \ingroup sigstate
 *
 * @{
 */

/**
 * \file
 *
 * \brief Data structures and function prototypes for keeping
 *        state for the detection engine.
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

/* On DeState and locking.
 *
 * The DeState is part of a flow, but it can't be protected by the flow lock.
 * Reason is we need to lock the DeState data for an entire detection run,
 * as we're looping through on "continued" detection and rely on only a single
 * detection instance setting it up on first run. We can't keep the entire flow
 * locked during detection for performance reasons, it would slow us down too
 * much.
 *
 * So a new lock was introduced. The only part of the process where we need
 * the flow lock is obviously when we're getting/setting the de_state ptr from
 * to the flow.
 */

#ifndef __DETECT_ENGINE_STATE_H__
#define __DETECT_ENGINE_STATE_H__

#define DETECT_ENGINE_INSPECT_SIG_NO_MATCH 0
#define DETECT_ENGINE_INSPECT_SIG_MATCH 1
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH 2
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE 3

/** number of DeStateStoreItem's in one DeStateStore object */
#define DE_STATE_CHUNK_SIZE             15

/* per sig flags */
#define DE_STATE_FLAG_URI_INSPECT         (1)
#define DE_STATE_FLAG_HRUD_INSPECT        (1 << 1)
#define DE_STATE_FLAG_HCBD_INSPECT        (1 << 2)
#define DE_STATE_FLAG_HSBD_INSPECT        (1 << 3)
#define DE_STATE_FLAG_HHD_INSPECT         (1 << 4)
#define DE_STATE_FLAG_HRHD_INSPECT        (1 << 5)
#define DE_STATE_FLAG_HHHD_INSPECT        (1 << 6)
#define DE_STATE_FLAG_HRHHD_INSPECT       (1 << 7)
#define DE_STATE_FLAG_HUAD_INSPECT        (1 << 8)
#define DE_STATE_FLAG_HMD_INSPECT         (1 << 9)
#define DE_STATE_FLAG_HCD_INSPECT         (1 << 10)
#define DE_STATE_FLAG_HSMD_INSPECT        (1 << 11)
#define DE_STATE_FLAG_HSCD_INSPECT        (1 << 12)
#define DE_STATE_FLAG_FILE_TC_INSPECT     (1 << 13)
#define DE_STATE_FLAG_FILE_TS_INSPECT     (1 << 14)
#define DE_STATE_FLAG_FULL_INSPECT        (1 << 15)
#define DE_STATE_FLAG_SIG_CANT_MATCH      (1 << 16)
#define DE_STATE_FLAG_DNSQUERYNAME_INSPECT (1 << 17)
#define DE_STATE_FLAG_APP_EVENT_INSPECT   (1 << 18)
#define DE_STATE_FLAG_MODBUS_INSPECT	  (1 << 19)
#define DE_STATE_FLAG_HRL_INSPECT	      (1 << 20)
#define DE_STATE_FLAG_FD_SMTP_INSPECT     (1 << 21)
#define DE_STATE_FLAG_DNSREQUEST_INSPECT  (1 << 22)
#define DE_STATE_FLAG_DNSRESPONSE_INSPECT (1 << 23)
#define DE_STATE_FLAG_TEMPLATE_BUFFER_INSPECT (1 << 24)

/* state flags */
#define DETECT_ENGINE_STATE_FLAG_FILE_STORE_DISABLED 0x0001
#define DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW         0x0002
#define DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW         0x0004

/* We have 2 possible state values to be used by ContinueDetection() while
 * trying to figure if we have fresh state to install or not.
 *
 * For tx based alprotos, we don't need to indicate the below values on a
 * per sig basis, but for non-tx based alprotos we do, since we might have
 * new alstate coming in, and some sigs might have already matchced in
 * de_state and ContinueDetection needs to inform the detection filter that
 * it no longer needs to inspect this sig, since ContinueDetection would
 * handle it.
 *
 * Wrt tx based alprotos, if we have a new tx available apart from the one
 * currently being inspected(and also added to de_state), we continue with
 * the HAS_NEW_STATE flag, while if we don't have a new tx, we set
 * NO_NEW_STATE, to avoid getting the sig reinspected for the already
 * inspected tx. */
#define DE_STATE_MATCH_HAS_NEW_STATE 0x00
#define DE_STATE_MATCH_NO_NEW_STATE  0x80

/* TX BASED (inspect engines) */

typedef struct DeStateStoreItem_ {
    uint32_t flags;
    SigIntId sid;
} DeStateStoreItem;

typedef struct DeStateStore_ {
    DeStateStoreItem store[DE_STATE_CHUNK_SIZE];
    struct DeStateStore_ *next;
} DeStateStore;

typedef struct DetectEngineStateDirection_ {
    DeStateStore *head;
    DeStateStore *tail;
    SigIntId cnt;
    uint16_t filestore_cnt;
    uint8_t flags;
} DetectEngineStateDirection;

typedef struct DetectEngineState_ {
    DetectEngineStateDirection dir_state[2];
} DetectEngineState;

/* FLOW BASED (AMATCH) */

typedef struct DeStateStoreFlowRule_ {
    SigMatch *nm;
    uint32_t flags;
    SigIntId sid;
} DeStateStoreFlowRule;

typedef struct DeStateStoreFlowRules_ {
    DeStateStoreFlowRule store[DE_STATE_CHUNK_SIZE];
    struct DeStateStoreFlowRules_ *next;
} DeStateStoreFlowRules;

typedef struct DetectEngineStateDirectionFlow_ {
    DeStateStoreFlowRules *head;
    DeStateStoreFlowRules *tail;
    SigIntId cnt;
    uint8_t flags;
} DetectEngineStateDirectionFlow;

typedef struct DetectEngineStateFlow_ {
    DetectEngineStateDirectionFlow dir_state[2];
} DetectEngineStateFlow;

/**
 * \brief Alloc a DetectEngineState object.
 *
 * \retval Alloc'd instance of DetectEngineState.
 */
DetectEngineState *DetectEngineStateAlloc(void);

/**
 * \brief Frees a DetectEngineState object.
 *
 * \param state DetectEngineState instance to free.
 */
void DetectEngineStateFree(DetectEngineState *state);
void DetectEngineStateFlowFree(DetectEngineStateFlow *state);

/**
 * \brief Check if a flow already contains(newly updated as well) de state.
 *
 * \param f Pointer to the flow.
 * \param alversino The alversion to check against de_state's.
 * \param direction Direction to check.  0 - ts, 1 - tc.
 *
 * \retval 1 Has state.
 * \retval 0 Has no state.
 */
int DeStateFlowHasInspectableState(Flow *f, AppProto alproto, uint8_t alversion, uint8_t flags);

/**
 * \brief Match app layer sig list against app state and store relevant match
 *        information.
 *
 * \param tv Pointer to the threadvars.
 * \param de_ctx DetectEngineCtx instance.
 * \param det_ctx DetectEngineThreadCtx instance.
 * \param s Pointer to the signature.
 * \param f Pointer to the flow.
 * \param flags Flags.
 * \param alproto App protocol.
 * \param alversion Current app layer version.
 *
 * \retval >= 0 An integer value indicating the no of matches.
 */
int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                DetectEngineThreadCtx *det_ctx,
                                Signature *s, Packet *p, Flow *f, uint8_t flags,
                                AppProto alproto, uint8_t alversion);

/**
 * \brief Continue DeState detection of the signatures stored in the state.
 *
 * \param tv Pointer to the threadvars.
 * \param de_ctx DetectEngineCtx instance.
 * \param det_ctx DetectEngineThreadCtx instance.
 * \param f Pointer to the flow.
 * \param flags Flags.
 * \param alproto App protocol.
 * \param alversion Current app layer version.
 */
void DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                    DetectEngineThreadCtx *det_ctx,
                                    Packet *p, Flow *f, uint8_t flags,
                                    AppProto alproto, uint8_t alversion);

/**
 *  \brief Update the inspect id.
 *
 *  \param f unlocked flow
 *  \param flags direction and disruption flags
 */
void DeStateUpdateInspectTransactionId(Flow *f, const uint8_t flags);

/**
 * \brief Reset a DetectEngineState state.
 *
 * \param state     Pointer to the state(LOCKED).
 * \param direction Direction flags - STREAM_TOSERVER or STREAM_TOCLIENT.
 */
void DetectEngineStateReset(DetectEngineStateFlow *state, uint8_t direction);

void DetectEngineStateResetTxs(Flow *f);

void DeStateRegisterTests(void);

#endif /* __DETECT_ENGINE_STATE_H__ */

/**
 * @}
 */
