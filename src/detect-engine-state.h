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
/** indicate that the file inspection portion of a sig didn't match.
 *  This is used to handle state keeping as the detect engine is still
 *  only marginally aware of files. */
#define DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES 3
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
/* flag set if file inspecting sig did not match, but might need to be
 * re-evaluated for a new file in a tx */
#define DE_STATE_ID_FILE_INSPECT                2UL
#define DE_STATE_FLAG_FILE_INSPECT              BIT_U32(DE_STATE_ID_FILE_INSPECT)

/* first bit position after the built-ins */
#define DE_STATE_FLAG_BASE                      3UL

/* state flags
 *
 * Used by app-layer-parsers to notify us that new files
 * are available in the tx.
 */
#define DETECT_ENGINE_STATE_FLAG_FILE_NEW       BIT_U8(0)

typedef struct DeStateStoreItem_ {
    uint32_t flags;
    SigIntId sid;
} DeStateStoreItem;

typedef struct DeStateStore_ {
    DeStateStoreItem store[DE_STATE_CHUNK_SIZE];
    struct DeStateStore_ *next;
} DeStateStore;

typedef struct DetectEngineStateDirection_ {
    DeStateStore *head; /**< head of the list */
    DeStateStore *cur;  /**< current active store */
    DeStateStore *tail; /**< tail of the list */
    SigIntId cnt;
    uint16_t filestore_cnt;
    uint8_t flags;
    /* coccinelle: DetectEngineStateDirection:flags:DETECT_ENGINE_STATE_FLAG_ */
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

#endif /* __DETECT_ENGINE_STATE_H__ */

/**
 * @}
 */
