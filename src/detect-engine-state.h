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
 * \file
 *
 * \brief Data structures and function prototypes for keeping
 *        state for the detection engine.
 *
 * \author Victor Julien <victor@inliniac.net>
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

/** number of DeStateStoreItem's in one DeStateStore object */
#define DE_STATE_CHUNK_SIZE         16

#define DE_STATE_FLAG_PAYLOAD_MATCH 0x01 /**< payload part of the sig matched */
#define DE_STATE_FLAG_URI_MATCH     0x02 /**< uri part of the sig matched */
#define DE_STATE_FLAG_DCE_MATCH     0x04 /**< dce payload inspection part matched */

typedef enum {
    DE_STATE_MATCH_FULL = 0,    /**< sig already fully matched, no state */
    DE_STATE_MATCH_PARTIAL,     /**< partial state match */
    DE_STATE_MATCH_STORED,      /**< stored match in the state */
    DE_STATE_MATCH_NEW,         /**< new match */
} DeStateMatchResult;

/** \brief State storage for a single signature */
typedef struct DeStateStoreItem_ {
    SigIntId sid;   /**< Signature internal id to store the state for (16 or
                     *   32 bit depending on how SigIntId is defined). */
    uint16_t flags; /**< flags */
    SigMatch *nm;   /**< next sig match to try, or null if done */
} DeStateStoreItem;

/** \brief State store "chunk" for x number of signature */
typedef struct DeStateStore_ {
    DeStateStoreItem store[DE_STATE_CHUNK_SIZE];    /**< array of storage objects */
    struct DeStateStore_ *next;                     /**< ptr to the next array */
} DeStateStore;

/** \brief State store main object */
typedef struct DetectEngineState_ {
    DeStateStore *head; /**< signature state storage */
    DeStateStore *tail; /**< tail item of the storage list */
    SigIntId cnt;       /**< number of sigs in the storage */
    SCMutex m;          /**< lock for the de_state object */
} DetectEngineState;

void DeStateRegisterTests(void);

DeStateStore *DeStateStoreAlloc(void);
void DeStateStoreFree(DeStateStore *);
void DetectEngineStateReset(DetectEngineState *state);

DetectEngineState *DetectEngineStateAlloc(void);
void DetectEngineStateFree(DetectEngineState *);

//void DeStateSignatureAppend(DetectEngineState *, Signature *, SigMatch *, char);

int DeStateFlowHasState(Flow *);

int DeStateDetectStartDetection(ThreadVars *, DetectEngineCtx *,
        DetectEngineThreadCtx *, Signature *, Flow *, uint8_t, void *, uint16_t);

int DeStateDetectContinueDetection(ThreadVars *, DetectEngineCtx *,
        DetectEngineThreadCtx *, Flow *, uint8_t, void *, uint16_t);

const char *DeStateMatchResultToString(DeStateMatchResult);
int DeStateUpdateInspectTransactionId(Flow *, char);

#endif /* __DETECT_ENGINE_STATE_H__ */

