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
 * \file
 *
 * Alpd - App Layer Protocol Detection.
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_DETECT_PROTO_H__
#define __APP_LAYER_DETECT_PROTO_H__

#include "stream.h"
#include "detect-content.h"
#include "app-layer-parser.h"
#include "app-layer-protos.h"
#include "flow-proto-private.h"

/**
 * \brief The global app layer protocol detection context used by suricata.
 */
extern AlpProtoDetectCtx alpd_ctx;

#define FLOW_IS_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_IS_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags & FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags & FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_SET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_SET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags |= FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags |= FLOW_TC_PP_ALPROTO_DETECT_DONE))

#define FLOW_RESET_PM_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PM_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PM_ALPROTO_DETECT_DONE))
#define FLOW_RESET_PP_DONE(f, dir) (((dir) & STREAM_TOSERVER) ? ((f)->flags &= ~FLOW_TS_PP_ALPROTO_DETECT_DONE) : ((f)->flags &= ~FLOW_TC_PP_ALPROTO_DETECT_DONE))

void AlpProtoFinalizeThread(AlpProtoDetectCtx *, AlpProtoDetectThreadCtx *);
void AlpProtoFinalize2Thread(AlpProtoDetectThreadCtx *);
void AlpProtoDeFinalize2Thread (AlpProtoDetectThreadCtx *);

/***** Anoop *****/

/**
 * \brief Inits and returns an app layer protocol detection context.
 *
 * \retval On success, pointer to the context; NULL on failure.
 */
void *AlpdGetCtx(void);
/**
 * \brief Destroys the app layer protocol detection context.
 *
 * \param ctx Pointer to the app layer protocol detection context.
 */
void AlpdDestoryCtx(void *ctx);

/**
 * \brief Inits and returns an app layer protocol detection thread context.

 * \param ctx Pointer to the app layer protocol detection context.
 *
 * \retval On success, pointer to the thread context; NULL on failure.
 */
void *AlpdGetCtxThread(void *ctx);
/**
 * \brief Destroys the app layer protocol detection thread context.
 *
 * \param ctx  Pointer to the app layer protocol detection context.
 * \param tctx Pointer to the app layer protocol detection thread context.
 */
void AlpdDestroyCtxThread(void *ctx, void *tctx);

/**
 * \brief Registers a protocol for protocol detection phase.
 *
 *        This is the first function to be called before adding patterns
 *        for protocol detection, setting the probing parser for protocol
 *        detection and registering the protocol parser callbacks.
 *        With this function you are also associating/registering a string
 *        that can be used by users to write rules, i.e.
 *        you register the http protocol for protocol detection using
 *        AlpdRegisterProtocol(ctx, ALPROTO_HTTP, "http");
 *        Following which you can write rules like this -
 *        alert http any any -> any any (sid:1;)
 *        Which basically matches on the protocol.
 *
 * \param ctx Pointer to the app layer protocol detection context.
 * \param alproto The protocol.
 * \param alproto_str The string to associate with the above "alproto".
 *
 * \retval  0 On success;
 *         -1 on failure.
 */
int AlpdRegisterProtocol(void *ctx,
                         AppProto alproto, const char *alproto_str);
/**
 * \brief Registers
int AlpdPMRegisterPatternCS(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);
int AlpdPMRegisterPatternCI(void *ctx,
                            uint16_t ipproto, uint16_t alproto,
                            const char *pattern,
                            uint16_t depth, uint16_t offset,
                            uint8_t direction);
void AlpdPrepareState(void *ctx);

uint16_t AlpdGetProto(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx,
                      Flow *f, uint8_t *buf, uint32_t buflen,
                      uint8_t flags, uint8_t ipproto);


void AlpDetectRegisterTests(void);

#endif /* __APP_LAYER_DETECT_PROTO_H__ */
