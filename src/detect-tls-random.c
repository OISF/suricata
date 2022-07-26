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
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"

#include "flow.h"
#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "detect-engine-prefilter.h"
#include "detect-tls-random.h"

#define DETECT_TLS_RANDOM_TIME_LEN  4
#define DETECT_TLS_RANDOM_BYTES_LEN 28

static int DetectTlsRandomTimeSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectTlsRandomBytesSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectTlsRandomSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetRandomTimeData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetRandomBytesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);
static InspectionBuffer *GetRandomData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id);

static int g_tls_random_time_buffer_id = 0;
static int g_tls_random_bytes_buffer_id = 0;
static int g_tls_random_buffer_id = 0;

void DetectTlsRandomTimeRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_RANDOM_TIME].name = "tls.random_time";
    sigmatch_table[DETECT_AL_TLS_RANDOM_TIME].desc = "sticky buffer to match specifically and only "
                                                     "on the first 4 bytes of a TLS random buffer";
    sigmatch_table[DETECT_AL_TLS_RANDOM_TIME].url = "/rules/tls-keywords.html#tls-random-time";
    sigmatch_table[DETECT_AL_TLS_RANDOM_TIME].Setup = DetectTlsRandomTimeSetup;
    sigmatch_table[DETECT_AL_TLS_RANDOM_TIME].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* Register engine for Server random */
    DetectAppLayerInspectEngineRegister2("tls.random_time", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetRandomTimeData);
    DetectAppLayerMpmRegister2("tls.random_time", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRandomTimeData, ALPROTO_TLS, 0);

    /* Register engine for Client random */
    DetectAppLayerInspectEngineRegister2("tls.random_time", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetRandomTimeData);
    DetectAppLayerMpmRegister2("tls.random_time", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetRandomTimeData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("tls.random_time", "TLS Random Time");

    g_tls_random_time_buffer_id = DetectBufferTypeGetByName("tls.random_time");
}

void DetectTlsRandomBytesRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_RANDOM_BYTES].name = "tls.random_bytes";
    sigmatch_table[DETECT_AL_TLS_RANDOM_BYTES].desc =
            "sticky buffer to match specifically and only on the last 28 bytes of a TLS random "
            "buffer";
    sigmatch_table[DETECT_AL_TLS_RANDOM_BYTES].url = "/rules/tls-keywords.html#tls-random-bytes";
    sigmatch_table[DETECT_AL_TLS_RANDOM_BYTES].Setup = DetectTlsRandomBytesSetup;
    sigmatch_table[DETECT_AL_TLS_RANDOM_BYTES].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* Register engine for Server random */
    DetectAppLayerInspectEngineRegister2("tls.random_bytes", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetRandomBytesData);
    DetectAppLayerMpmRegister2("tls.random_bytes", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetRandomBytesData, ALPROTO_TLS, 0);

    /* Register engine for Client random */
    DetectAppLayerInspectEngineRegister2("tls.random_bytes", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetRandomBytesData);
    DetectAppLayerMpmRegister2("tls.random_bytes", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetRandomBytesData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("tls.random_bytes", "TLS Random Bytes");

    g_tls_random_bytes_buffer_id = DetectBufferTypeGetByName("tls.random_bytes");
}

/**
 * \brief Registration function for keyword: tls.random
 */
void DetectTlsRandomRegister(void)
{
    DetectTlsRandomTimeRegister();
    DetectTlsRandomBytesRegister();

    sigmatch_table[DETECT_AL_TLS_RANDOM].name = "tls.random";
    sigmatch_table[DETECT_AL_TLS_RANDOM].desc =
            "sticky buffer to match specifically and only on a TLS random buffer";
    sigmatch_table[DETECT_AL_TLS_RANDOM].url = "/rules/tls-keywords.html#tls-random";
    sigmatch_table[DETECT_AL_TLS_RANDOM].Setup = DetectTlsRandomSetup;
    sigmatch_table[DETECT_AL_TLS_RANDOM].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* Register engine for Server random */
    DetectAppLayerInspectEngineRegister2("tls.random", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetRandomData);
    DetectAppLayerMpmRegister2("tls.random", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetRandomData, ALPROTO_TLS, 0);

    /* Register engine for Client random */
    DetectAppLayerInspectEngineRegister2("tls.random", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetRandomData);
    DetectAppLayerMpmRegister2("tls.random", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetRandomData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("tls.random", "TLS Random");

    g_tls_random_buffer_id = DetectBufferTypeGetByName("tls.random");
}

/**
 * \brief this function setup the tls.random_time sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsRandomTimeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_random_time_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

/**
 * \brief this function setup the tls.random_bytes sticky buffer keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsRandomBytesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_random_bytes_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
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

static InspectionBuffer *GetRandomTimeData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        if ((flow_flags & STREAM_TOSERVER) && !(ssl_state->flags & TLS_TS_RANDOM_SET)) {
            return NULL;
        } else if (!(ssl_state->flags & TLS_TC_RANDOM_SET)) {
            return NULL;
        }
        const uint32_t data_len = DETECT_TLS_RANDOM_TIME_LEN;
        const uint8_t *data;
        if (flow_flags & STREAM_TOSERVER) {
            data = ssl_state->server_connp.random;
        } else {
            data = ssl_state->client_connp.random;
        }
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

static InspectionBuffer *GetRandomBytesData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        if ((flow_flags & STREAM_TOSERVER) && !(ssl_state->flags & TLS_TS_RANDOM_SET)) {
            return NULL;
        } else if (!(ssl_state->flags & TLS_TC_RANDOM_SET)) {
            return NULL;
        }
        const uint32_t data_len = DETECT_TLS_RANDOM_BYTES_LEN;
        const uint8_t *data;
        if (flow_flags & STREAM_TOSERVER) {
            data = ssl_state->server_connp.random + DETECT_TLS_RANDOM_TIME_LEN;
        } else {
            data = ssl_state->client_connp.random + DETECT_TLS_RANDOM_TIME_LEN;
        }
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

static InspectionBuffer *GetRandomData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;
        if ((flow_flags & STREAM_TOSERVER) && !(ssl_state->flags & TLS_TS_RANDOM_SET)) {
            return NULL;
        } else if (!(ssl_state->flags & TLS_TC_RANDOM_SET)) {
            return NULL;
        }
        const uint32_t data_len = TLS_RANDOM_LEN;
        const uint8_t *data;
        if (flow_flags & STREAM_TOSERVER) {
            data = ssl_state->server_connp.random;
        } else {
            data = ssl_state->client_connp.random;
        }
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}
