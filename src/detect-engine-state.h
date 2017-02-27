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


#ifndef __DETECT_ENGINE_STATE_H__
#define __DETECT_ENGINE_STATE_H__

#define DETECT_ENGINE_INSPECT_SIG_NO_MATCH 0
#define DETECT_ENGINE_INSPECT_SIG_MATCH 1
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH 2
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILESTORE 3
/** hack to work around a file inspection limitation. Since there can be
 *  multiple files in a TX and the detection engine really don't know
 *  about that, we have to give the file inspection engine a way to
 *  indicate that one of the files matched, but that there are still
 *  more files that have ongoing inspection. */
#define DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES 4

/** number of DeStateStoreItem's in one DeStateStore object */
#define DE_STATE_CHUNK_SIZE             15

/* per sig flags */
#define DE_STATE_FLAG_FULL_INSPECT              BIT_U32(0)
#define DE_STATE_FLAG_SIG_CANT_MATCH            BIT_U32(1)

#define DE_STATE_FLAG_FILE_TC_INSPECT           BIT_U32(2)
#define DE_STATE_FLAG_FILE_TS_INSPECT           BIT_U32(3)

/* first bit position after the built-ins */
#define DE_STATE_FLAG_BASE                      4UL

/* state flags
 *
 * Used by app-layer-parsers to notify us that new files
 * are available in the tx.
 */
#define DETECT_ENGINE_STATE_FLAG_FILE_TC_NEW    BIT_U8(0)
#define DETECT_ENGINE_STATE_FLAG_FILE_TS_NEW    BIT_U8(1)

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

/**
 * \brief Check if a flow already contains(newly updated as well) de state.
 *
 * \param f Pointer to the flow.
 * \param flags direction
 *
 * \retval 1 Has state.
 * \retval 0 Has no state.
 */
int DeStateFlowHasInspectableState(const Flow *f, const uint8_t flags);

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
 *
 * \retval >= 0 An integer value indicating the no of matches.
 */
int DeStateDetectStartDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                DetectEngineThreadCtx *det_ctx,
                                const Signature *s, Packet *p, Flow *f,
                                uint8_t flags, AppProto alproto);

/**
 * \brief Continue DeState detection of the signatures stored in the state.
 *
 * \param tv Pointer to the threadvars.
 * \param de_ctx DetectEngineCtx instance.
 * \param det_ctx DetectEngineThreadCtx instance.
 * \param f Pointer to the flow.
 * \param flags Flags.
 * \param alproto App protocol.
 */
void DeStateDetectContinueDetection(ThreadVars *tv, DetectEngineCtx *de_ctx,
                                    DetectEngineThreadCtx *det_ctx,
                                    Packet *p, Flow *f, uint8_t flags,
                                    AppProto alproto);

/**
 *  \brief Update the inspect id.
 *
 *  \param f unlocked flow
 *  \param flags direction and disruption flags
 */
void DeStateUpdateInspectTransactionId(Flow *f, const uint8_t flags);

void DetectEngineStateResetTxs(Flow *f);

void DeStateRegisterTests(void);

#endif /* __DETECT_ENGINE_STATE_H__ */

/**
 * @}
 */
