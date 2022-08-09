/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_DETECT_PROTO__H__
#define __APP_LAYER_DETECT_PROTO__H__

typedef struct AppLayerProtoDetectThreadCtx_ AppLayerProtoDetectThreadCtx;

typedef AppProto (*ProbingParserFPtr)(
        Flow *f, uint8_t flags, const uint8_t *input, uint32_t input_len, uint8_t *rdir);

/***** Protocol Retrieval *****/

/**
 * \brief Returns the app layer protocol given a buffer.
 *
 * \param tctx Pointer to the app layer protocol detection thread context.
 * \param f Pointer to the flow.
 * \param buf The buffer to be inspected.
 * \param buflen The length of the above buffer.
 * \param ipproto The ip protocol.
 * \param flags The direction bitfield - STREAM_TOSERVER/STREAM_TOCLIENT.
 * \param[out] reverse_flow true if flow is detected to be reversed
 *
 * \retval The app layer protocol.
 */
AppProto AppLayerProtoDetectGetProto(AppLayerProtoDetectThreadCtx *tctx, Flow *f,
        const uint8_t *buf, uint32_t buflen, uint8_t ipproto, uint8_t flags, bool *reverse_flow);

/***** State Preparation *****/

/**
 * \brief Prepares the internal state for protocol detection.
 *        This needs to be called once all the patterns and probing parser
 *        ports have been registered.
 */
int AppLayerProtoDetectPrepareState(void);

/***** PP registration *****/

void AppLayerProtoDetectPPRegister(uint8_t ipproto,
                                   const char *portstr,
                                   AppProto alproto,
                                   uint16_t min_depth, uint16_t max_depth,
                                   uint8_t direction,
                                   ProbingParserFPtr ProbingParser1,
                                   ProbingParserFPtr ProbingParser2);
/**
 *  \retval bool 0 if no config was found, 1 if config was found
 */
int AppLayerProtoDetectPPParseConfPorts(const char *ipproto_name,
                                         uint8_t ipproto,
                                         const char *alproto_name,
                                         AppProto alproto,
                                         uint16_t min_depth, uint16_t max_depth,
                                         ProbingParserFPtr ProbingParserTs,
                                         ProbingParserFPtr ProbingParserTc);

/***** PM registration *****/

/**
 * \brief Registers a case-sensitive pattern for protocol detection.
 */
int AppLayerProtoDetectPMRegisterPatternCS(uint8_t ipproto, AppProto alproto,
        const char *pattern, uint16_t depth, uint16_t offset,
        uint8_t direction);
int AppLayerProtoDetectPMRegisterPatternCSwPP(uint8_t ipproto, AppProto alproto,
        const char *pattern, uint16_t depth, uint16_t offset,
        uint8_t direction,
        ProbingParserFPtr PPFunc,
        uint16_t pp_min_depth, uint16_t pp_max_depth);

/**
 * \brief Registers a case-insensitive pattern for protocol detection.
 */
int AppLayerProtoDetectPMRegisterPatternCI(uint8_t ipproto, AppProto alproto,
                                           const char *pattern,
                                           uint16_t depth, uint16_t offset,
                                           uint8_t direction);

/***** Setup/General Registration *****/

/**
 * \brief The first function to be called.  This initializes a global
 *        protocol detection context.
 *
 * \retval 0 On success;
 * \retval -1 On failure.
 */
int AppLayerProtoDetectSetup(void);

/**
 * \brief Reset proto detect for flow
 */
void AppLayerProtoDetectReset(Flow *);

void AppLayerRequestProtocolChange(Flow *f, uint16_t dp, AppProto expect_proto);
void AppLayerRequestProtocolTLSUpgrade(Flow *f);

/**
 * \brief Cleans up the app layer protocol detection phase.
 */
int AppLayerProtoDetectDeSetup(void);

/**
 * \brief Registers a protocol for protocol detection phase.
 *
 *        This is the first function to be called after calling the
 *        setup function, AppLayerProtoDetectSetup(), before calling any other
 *        app layer functions, AppLayerParser or AppLayerProtoDetect, alike.
 *        With this function you are associating/registering a string
 *        that can be used by users to write rules, i.e.
 *        you register the http protocol for protocol detection using
 *        AppLayerProtoDetectRegisterProtocol(ctx, ALPROTO_HTTP1, "http"),
 *        following which you can write rules like -
 *        alert http any any -> any any (sid:1;)
 *        which basically matches on the HTTP protocol.
 *
 * \param alproto The protocol.
 * \param alproto_str The string to associate with the above "alproto".
 *                    Please send a static string that won't be destroyed
 *                    post making this call, since this function won't
 *                    create a copy of the received argument.
 *
 * \retval  0 On success;
 *         -1 On failure.
 */
void AppLayerProtoDetectRegisterProtocol(AppProto alproto, const char *alproto_name);

void AppLayerProtoDetectRegisterAlias(const char *proto_name, const char *proto_alias);

/**
 * \brief Given a protocol name, checks if proto detection is enabled in
 *        the conf file.
 *
 * \param alproto Name of the app layer protocol.
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AppLayerProtoDetectConfProtoDetectionEnabled(const char *ipproto,
                                                 const char *alproto);

/**
 * \brief Given a protocol name, checks if proto detection is enabled in
 *        the conf file.
 *
 * \param alproto Name of the app layer protocol.
 * \param default_enabled enable by default if not in the configuration file
 *
 * \retval 1 If enabled.
 * \retval 0 If disabled.
 */
int AppLayerProtoDetectConfProtoDetectionEnabledDefault(
        const char *ipproto, const char *alproto, bool default_enabled);

/**
 * \brief Inits and returns an app layer protocol detection thread context.

 * \param ctx Pointer to the app layer protocol detection context.
 *
 * \retval Pointer to the thread context, on success;
 *         NULL, on failure.
 */
AppLayerProtoDetectThreadCtx *AppLayerProtoDetectGetCtxThread(void);

/**
 * \brief Destroys the app layer protocol detection thread context.
 *
 * \param tctx Pointer to the app layer protocol detection thread context.
 */
void AppLayerProtoDetectDestroyCtxThread(AppLayerProtoDetectThreadCtx *tctx);

/***** Utility *****/

void AppLayerProtoDetectSupportedIpprotos(AppProto alproto, uint8_t *ipprotos);
AppProto AppLayerProtoDetectGetProtoByName(const char *alproto_name);
const char *AppLayerProtoDetectGetProtoName(AppProto alproto);
void AppLayerProtoDetectSupportedAppProtocols(AppProto *alprotos);

void AppLayerRegisterExpectationProto(uint8_t proto, AppProto alproto);

/***** Unittests *****/

#ifdef UNITTESTS

/**
 * \brief Backs up the internal context used by the app layer proto detection
 *        module.
 */
void AppLayerProtoDetectUnittestCtxBackup(void);

/**
 * \brief Restores back the internal context used by the app layer proto
 *        detection module, that was previously backed up by calling
 *        AppLayerProtoDetectUnittestCtxBackup().
 */
void AppLayerProtoDetectUnittestCtxRestore(void);

/**
 * \brief Register unittests for app layer proto detection module.
 */
void AppLayerProtoDetectUnittestsRegister(void);

#endif /* UNITTESTS */

#endif /* __APP_LAYER_DETECT_PROTO__H__ */
