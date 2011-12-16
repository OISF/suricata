/* Copyright (C) 2007-2011 Open Information Security Foundation
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
#define DE_STATE_CHUNK_SIZE             15

/* per stored sig flags */
#define DE_STATE_FLAG_PAYLOAD_MATCH     0x0001 /**< payload part of the sig matched */
#define DE_STATE_FLAG_URI_MATCH         0x0002 /**< uri part of the sig matched */
#define DE_STATE_FLAG_DCE_MATCH         0x0004 /**< dce payload inspection part matched */
#define DE_STATE_FLAG_HCBD_MATCH        0x0008 /**< hcbd payload inspection part matched */
#define DE_STATE_FLAG_HSBD_MATCH        0x0010 /**< hcbd payload inspection part matched */
#define DE_STATE_FLAG_HHD_MATCH         0x0020 /**< hhd payload inspection part matched */
#define DE_STATE_FLAG_HRHD_MATCH        0x0040 /**< hrhd payload inspection part matched */
#define DE_STATE_FLAG_HMD_MATCH         0x0080 /**< hmd payload inspection part matched */
#define DE_STATE_FLAG_HCD_MATCH         0x0100 /**< hcd payload inspection part matched */
#define DE_STATE_FLAG_HRUD_MATCH        0x0200 /**< hrud payload inspection part matched */
#define DE_STATE_FLAG_FILE_TC_MATCH     0x0400
#define DE_STATE_FLAG_FILE_TS_MATCH     0x0800
#define DE_STATE_FLAG_FULL_MATCH        0x1000 /**< sig already fully matched */
#define DE_STATE_FLAG_SIG_CANT_MATCH    0x2000 /**< signature has no chance of matching */

#define DE_STATE_FLAG_URI_INSPECT       DE_STATE_FLAG_URI_MATCH     /**< uri part of the sig inspected */
#define DE_STATE_FLAG_DCE_INSPECT       DE_STATE_FLAG_DCE_MATCH     /**< dce payload inspection part inspected */
#define DE_STATE_FLAG_HCBD_INSPECT      DE_STATE_FLAG_HCBD_MATCH    /**< hcbd payload inspection part inspected */
#define DE_STATE_FLAG_HSBD_INSPECT      DE_STATE_FLAG_HSBD_MATCH    /**< hsbd payload inspection part inspected */
#define DE_STATE_FLAG_HHD_INSPECT       DE_STATE_FLAG_HHD_MATCH     /**< hhd payload inspection part inspected */
#define DE_STATE_FLAG_HRHD_INSPECT      DE_STATE_FLAG_HRHD_MATCH    /**< hrhd payload inspection part inspected */
#define DE_STATE_FLAG_HMD_INSPECT       DE_STATE_FLAG_HMD_MATCH     /**< hmd payload inspection part inspected */
#define DE_STATE_FLAG_HCD_INSPECT       DE_STATE_FLAG_HCD_MATCH     /**< hcd payload inspection part inspected */
#define DE_STATE_FLAG_HRUD_INSPECT      DE_STATE_FLAG_HRUD_MATCH    /**< hrud payload inspection part inspected */
#define DE_STATE_FLAG_FILE_TC_INSPECT   DE_STATE_FLAG_FILE_TC_MATCH
#define DE_STATE_FLAG_FILE_TS_INSPECT   DE_STATE_FLAG_FILE_TS_MATCH

/* state flags */
#define DE_STATE_FILE_STORE_DISABLED    0x0001
#define DE_STATE_FILE_TC_NEW            0x0002
#define DE_STATE_FILE_TS_NEW            0x0004

/** per signature detection engine state */
typedef enum {
    DE_STATE_MATCH_NOSTATE = 0, /**< no state for this sig*/
    DE_STATE_MATCH_FULL,        /**< sig already fully matched */
    DE_STATE_MATCH_PARTIAL,     /**< partial state match */
    DE_STATE_MATCH_NEW,         /**< new (full) match this run */
    DE_STATE_MATCH_NOMATCH,     /**< not a match */
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
    DeStateStore *head;             /**< signature state storage */
    DeStateStore *tail;             /**< tail item of the storage list */
    SigIntId cnt;                   /**< number of sigs in the storage */
    uint16_t toclient_version;      /**< app layer state "version" inspected
                                     *   last in to client direction */
    uint16_t toserver_version;      /**< app layer state "version" inspected
                                     *   last in to server direction */
    uint16_t toclient_filestore_cnt;/**< number of sigs with filestore that
                                     *   cannot match in to client direction. */
    uint16_t toserver_filestore_cnt;/**< number of sigs with filestore that
                                     *   cannot match in to server direction. */
    uint16_t flags;
} DetectEngineState;

void DeStateRegisterTests(void);

DeStateStore *DeStateStoreAlloc(void);
void DeStateStoreFree(DeStateStore *);
void DetectEngineStateReset(DetectEngineState *state);

DetectEngineState *DetectEngineStateAlloc(void);
void DetectEngineStateFree(DetectEngineState *);

int DeStateFlowHasState(Flow *, uint8_t, uint16_t);

int DeStateDetectStartDetection(ThreadVars *, DetectEngineCtx *,
        DetectEngineThreadCtx *, Signature *, Flow *, uint8_t, void *,
        uint16_t, uint16_t);

int DeStateDetectContinueDetection(ThreadVars *, DetectEngineCtx *,
        DetectEngineThreadCtx *, Flow *, uint8_t, void *, uint16_t,
        uint16_t);

const char *DeStateMatchResultToString(DeStateMatchResult);
int DeStateUpdateInspectTransactionId(Flow *, char);

#endif /* __DETECT_ENGINE_STATE_H__ */

/**
 * @}
 */
