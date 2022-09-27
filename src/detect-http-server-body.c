/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \ingroup httplayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements support for the http_server_body keyword
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-pcre.h"

#include "detect-http-server-body.h"

#ifdef UNITTESTS
#include "stream-tcp.h"
#include "app-layer-htp.h"
#include "app-layer-parser.h"
#include "app-layer.h"
#include "util-spm.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-util.h"
#include "flow-var.h"
#include "flow.h"
#include "detect-content.h"
#include "detect-engine-state.h"
#include "detect-engine-mpm.h"
#include "detect-parse.h"
#include "detect.h"
#include "decode.h"
#include "threads.h"
#endif
static int DetectHttpServerBodySetup(DetectEngineCtx *, Signature *, const char *);
static int DetectHttpServerBodySetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str);
#ifdef UNITTESTS
static void DetectHttpServerBodyRegisterTests(void);
#endif
static int g_file_data_buffer_id = 0;

/**
 * \brief Registers the keyword handlers for the "http_server_body" keyword.
 */
void DetectHttpServerBodyRegister(void)
{
    /* http_server_body content modifier */
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].name = "http_server_body";
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].desc = "content modifier to match on the HTTP response-body";
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].url = "/rules/http-keywords.html#http-server-body";
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].Setup = DetectHttpServerBodySetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].RegisterTests = DetectHttpServerBodyRegisterTests;
#endif
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].flags |= SIGMATCH_INFO_CONTENT_MODIFIER;
    sigmatch_table[DETECT_AL_HTTP_SERVER_BODY].alternative = DETECT_HTTP_RESPONSE_BODY;

    /* http.request_body sticky buffer */
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].name = "http.response_body";
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].desc = "sticky buffer to match the HTTP response body buffer";
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].url = "/rules/http-keywords.html#http-server-body";
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].Setup = DetectHttpServerBodySetupSticky;
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_HTTP_RESPONSE_BODY].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    g_file_data_buffer_id = DetectBufferTypeRegister("file_data");
}

/**
 * \brief The setup function for the http_server_body keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int DetectHttpServerBodySetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    return DetectEngineContentModifierBufferSetup(
            de_ctx, s, arg, DETECT_AL_HTTP_SERVER_BODY, g_file_data_buffer_id, ALPROTO_HTTP1);
}

/**
 * \brief this function setup the http.response_body keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectHttpServerBodySetupSticky(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_file_data_buffer_id) < 0)
        return -1;
    if (DetectSignatureSetAppProto(s, ALPROTO_HTTP1) < 0)
        return -1;
    return 0;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS
#include "tests/detect-http-server-body.c"
#endif /* UNITTESTS */

/**
 * @}
 */
