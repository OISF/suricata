/* Copyright (C) 2022 Open Information Security Foundation
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

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "detect-engine-prefilter.h"
#include "detect-tls-random.h"

static int DetectTlsRandomSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetDataTS(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetDataTC(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static int g_tls_random_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.random
 */
void DetectTlsRandomRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_RANDOM].name = "tls.random";
    sigmatch_table[DETECT_AL_TLS_RANDOM].desc =
            "sticky buffer to match specifically and only on the TLS random buffer";
    sigmatch_table[DETECT_AL_TLS_RANDOM].url = "/rules/tls-keywords.html#tls-random";
    sigmatch_table[DETECT_AL_TLS_RANDOM].Setup = DetectTlsRandomSetup;
    sigmatch_table[DETECT_AL_TLS_RANDOM].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_RANDOM].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    /* Register engine for Server random */
    DetectAppLayerInspectEngineRegister2("tls.random", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetDataTS);

    DetectAppLayerMpmRegister2("tls.random", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetDataTS, ALPROTO_TLS, 0);

    /* Register engine for Client random */
    DetectAppLayerInspectEngineRegister2("tls.random", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetDataTC);

    DetectAppLayerMpmRegister2("tls.random", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetDataTC, ALPROTO_TLS, 0);
    DetectBufferTypeSetDescriptionByName("tls.random", "TLS Random");

    g_tls_random_buffer_id = DetectBufferTypeGetByName("tls.random");
}

/**
 * \brief this function setup the tls.random sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsRandomSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_random_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetDataTC(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        /* First four bytes of random represent current UTC in the
         * Unix epoch format so for now, first byte should never be 0 */
        if (ssl_state->client_connp.random[0] == 0) {
            return NULL;
        }

        const uint32_t data_len = TLS_RANDOM_LEN;
        const uint8_t *data = ssl_state->client_connp.random;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetDataTS(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        /* First four bytes of random represent current UTC in the
         * Unix epoch format so for now, first byte should never be 0 */
        if (ssl_state->server_connp.random[0] == 0) {
            return NULL;
        }

        const uint32_t data_len = TLS_RANDOM_LEN;
        const uint8_t *data = ssl_state->server_connp.random;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}
