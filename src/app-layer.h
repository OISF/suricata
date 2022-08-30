/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_H__
#define __APP_LAYER_H__

#include "threadvars.h"
#include "decode.h"
#include "flow.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"


#include "rust.h"

#define APP_LAYER_DATA_ALREADY_SENT_TO_APP_LAYER \
    (~STREAM_TOSERVER & ~STREAM_TOCLIENT)

/***** L7 layer dispatchers *****/

/**
 * \brief Handles reassembled tcp stream.
 */
int AppLayerHandleTCPData(ThreadVars *tv, TcpReassemblyThreadCtx *ra_ctx,
                          Packet *p, Flow *f,
                          TcpSession *ssn, TcpStream **stream,
                          uint8_t *data, uint32_t data_len,
                          uint8_t flags);

/**
 * \brief Handles an udp chunk.
 */
int AppLayerHandleUdp(ThreadVars *tv, AppLayerThreadCtx *app_tctx,
                      Packet *p, Flow *f);

/***** Utility *****/

/**
 * \brief Given a protocol string, returns the corresponding internal
 *        protocol id.
 *
 * \param The internal protocol id.
 */
AppProto AppLayerGetProtoByName(char *alproto_name);

/**
 * \brief Given the internal protocol id, returns a string representation
 *        of the protocol.
 *
 * \param alproto The internal protocol id.
 *
 * \retval String representation of the protocol.
 */
const char *AppLayerGetProtoName(AppProto alproto);

void AppLayerListSupportedProtocols(void);

/***** Setup/General Registration *****/

/**
 * \brief Setup the app layer.
 *
 *        Includes protocol detection setup and the protocol parser setup.
 *
 * \retval 0 On success.
 * \retval -1 On failure.
 */
int AppLayerSetup(void);

/**
 * \brief De initializes the app layer.
 *
 *        Includes de initializing protocol detection and the protocol parser.
 */
int AppLayerDeSetup(void);

/**
 * \brief Creates a new app layer thread context.
 *
 * \retval Pointer to the newly create thread context, on success;
 *         NULL, on failure.
 */
AppLayerThreadCtx *AppLayerGetCtxThread(ThreadVars *tv);

/**
 * \brief Destroys the context created by AppLayeGetCtxThread().
 *
 * \param tctx Pointer to the thread context to destroy.
 */
void AppLayerDestroyCtxThread(AppLayerThreadCtx *tctx);

/**
 * \brief Registers per flow counters for all protocols
 *
 */
void AppLayerRegisterThreadCounters(ThreadVars *tv);

/***** Profiling *****/

void AppLayerProfilingResetInternal(AppLayerThreadCtx *app_tctx);

static inline void AppLayerProfilingReset(AppLayerThreadCtx *app_tctx)
{
#ifdef PROFILING
    AppLayerProfilingResetInternal(app_tctx);
#endif
}

void AppLayerProfilingStoreInternal(AppLayerThreadCtx *app_tctx, Packet *p);

static inline void AppLayerProfilingStore(AppLayerThreadCtx *app_tctx, Packet *p)
{
#ifdef PROFILING
    AppLayerProfilingStoreInternal(app_tctx, p);
#endif
}

void AppLayerRegisterGlobalCounters(void);

/***** Unittests *****/

#ifdef UNITTESTS
void AppLayerUnittestsRegister(void);
#endif

void AppLayerIncTxCounter(ThreadVars *tv, Flow *f, uint64_t step);
void AppLayerIncGapErrorCounter(ThreadVars *tv, Flow *f);
void AppLayerIncAllocErrorCounter(ThreadVars *tv, Flow *f);
void AppLayerIncParserErrorCounter(ThreadVars *tv, Flow *f);
void AppLayerIncInternalErrorCounter(ThreadVars *tv, Flow *f);

static inline uint8_t StreamSliceGetFlags(const StreamSlice *stream_slice)
{
    return stream_slice->flags;
}

static inline const uint8_t *StreamSliceGetData(const StreamSlice *stream_slice)
{
    return stream_slice->input;
}

static inline uint32_t StreamSliceGetDataLen(const StreamSlice *stream_slice)
{
    return stream_slice->input_len;
}

static inline bool StreamSliceIsGap(const StreamSlice *stream_slice)
{
    return stream_slice->input == NULL && stream_slice->input_len > 0;
}

static inline uint32_t StreamSliceGetGapSize(const StreamSlice *stream_slice)
{
    return StreamSliceGetDataLen(stream_slice);
}
#endif
