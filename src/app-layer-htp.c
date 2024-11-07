/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Brian Rectanus <brectanu@gmail.com>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#include "suricata.h"
#include "suricata-common.h"
#include "conf.h"
#include "decode.h"

#include "util-print.h"
#include "util-byte.h"

#include "stream-tcp.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-frames.h"
#include "app-layer-htp.h"
#include "app-layer-htp-body.h"
#include "app-layer-htp-file.h"
#include "app-layer-htp-xff.h"
#include "app-layer-htp-range.h"
#include "app-layer-htp-mem.h"

#include "util-debug.h"
#include "util-misc.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "util-memcmp.h"
#include "util-random.h"
#include "util-validate.h"

//#define PRINT

/** Fast lookup tree (radix) for the various HTP configurations */
static SCRadixTree *cfgtree;
/** List of HTP configurations. */
static HTPCfgRec cfglist;

StreamingBufferConfig htp_sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

/** Limit to the number of libhtp messages that can be handled */
#define HTP_MAX_MESSAGES 512

SC_ATOMIC_DECLARE(uint32_t, htp_config_flags);

#ifdef DEBUG
static SCMutex htp_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

SCEnumCharMap http_decoder_event_table[] = {
    { "UNKNOWN_ERROR", HTP_LOG_CODE_UNKNOWN },
    { "GZIP_DECOMPRESSION_FAILED", HTP_LOG_CODE_GZIP_DECOMPRESSION_FAILED },
    { "REQUEST_FIELD_MISSING_COLON", HTP_LOG_CODE_REQUEST_FIELD_MISSING_COLON },
    { "RESPONSE_FIELD_MISSING_COLON", HTP_LOG_CODE_RESPONSE_FIELD_MISSING_COLON },
    { "INVALID_REQUEST_CHUNK_LEN", HTP_LOG_CODE_INVALID_REQUEST_CHUNK_LEN },
    { "INVALID_RESPONSE_CHUNK_LEN", HTP_LOG_CODE_INVALID_RESPONSE_CHUNK_LEN },
    { "INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST",
            HTP_LOG_CODE_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST },
    { "INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE",
            HTP_LOG_CODE_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE },
    { "INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST",
            HTP_LOG_CODE_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST },
    { "INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE",
            HTP_LOG_CODE_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE },
    { "DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST",
            HTP_LOG_CODE_DUPLICATE_CONTENT_LENGTH_FIELD_IN_REQUEST },
    { "DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE",
            HTP_LOG_CODE_DUPLICATE_CONTENT_LENGTH_FIELD_IN_RESPONSE },
    { "CONTINUE_ALREADY_SEEN", HTP_LOG_CODE_CONTINUE_ALREADY_SEEN },
    { "UNABLE_TO_MATCH_RESPONSE_TO_REQUEST", HTP_LOG_CODE_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST },
    { "INVALID_SERVER_PORT_IN_REQUEST", HTP_LOG_CODE_INVALID_SERVER_PORT_IN_REQUEST },
    { "INVALID_AUTHORITY_PORT", HTP_LOG_CODE_INVALID_AUTHORITY_PORT },
    { "REQUEST_HEADER_INVALID", HTP_LOG_CODE_REQUEST_HEADER_INVALID },
    { "RESPONSE_HEADER_INVALID", HTP_LOG_CODE_RESPONSE_HEADER_INVALID },
    { "MISSING_HOST_HEADER", HTP_LOG_CODE_MISSING_HOST_HEADER },
    { "HOST_HEADER_AMBIGUOUS", HTP_LOG_CODE_HOST_HEADER_AMBIGUOUS },
    { "INVALID_REQUEST_FIELD_FOLDING", HTP_LOG_CODE_INVALID_REQUEST_FIELD_FOLDING },
    { "INVALID_RESPONSE_FIELD_FOLDING", HTP_LOG_CODE_INVALID_RESPONSE_FIELD_FOLDING },
    { "REQUEST_FIELD_TOO_LONG", HTP_LOG_CODE_REQUEST_FIELD_TOO_LONG },
    { "RESPONSE_FIELD_TOO_LONG", HTP_LOG_CODE_RESPONSE_FIELD_TOO_LONG },
    { "REQUEST_LINE_INVALID", HTP_LOG_CODE_REQUEST_LINE_INVALID },
    { "REQUEST_BODY_UNEXPECTED", HTP_LOG_CODE_REQUEST_BODY_UNEXPECTED },
    { "RESPONSE_BODY_UNEXPECTED", HTP_LOG_CODE_RESPONSE_BODY_UNEXPECTED },
    { "REQUEST_SERVER_PORT_TCP_PORT_MISMATCH", HTP_LOG_CODE_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH },
    { "REQUEST_URI_HOST_INVALID", HTP_LOG_CODE_URI_HOST_INVALID },
    { "REQUEST_HEADER_HOST_INVALID", HTP_LOG_CODE_HEADER_HOST_INVALID },
    { "REQUEST_AUTH_UNRECOGNIZED", HTP_LOG_CODE_AUTH_UNRECOGNIZED },
    { "REQUEST_HEADER_REPETITION", HTP_LOG_CODE_REQUEST_HEADER_REPETITION },
    { "RESPONSE_HEADER_REPETITION", HTP_LOG_CODE_RESPONSE_HEADER_REPETITION },
    { "DOUBLE_ENCODED_URI", HTP_LOG_CODE_DOUBLE_ENCODED_URI },
    { "URI_DELIM_NON_COMPLIANT", HTP_LOG_CODE_URI_DELIM_NON_COMPLIANT },
    { "METHOD_DELIM_NON_COMPLIANT", HTP_LOG_CODE_METHOD_DELIM_NON_COMPLIANT },
    { "REQUEST_LINE_LEADING_WHITESPACE", HTP_LOG_CODE_REQUEST_LINE_LEADING_WHITESPACE },
    { "TOO_MANY_ENCODING_LAYERS", HTP_LOG_CODE_TOO_MANY_ENCODING_LAYERS },
    { "REQUEST_TOO_MANY_LZMA_LAYERS", HTP_LOG_CODE_REQUEST_TOO_MANY_LZMA_LAYERS },
    { "RESPONSE_TOO_MANY_LZMA_LAYERS", HTP_LOG_CODE_RESPONSE_TOO_MANY_LZMA_LAYERS },
    { "ABNORMAL_CE_HEADER", HTP_LOG_CODE_ABNORMAL_CE_HEADER },
    { "RESPONSE_MULTIPART_BYTERANGES", HTP_LOG_CODE_RESPONSE_MULTIPART_BYTERANGES },
    { "RESPONSE_ABNORMAL_TRANSFER_ENCODING", HTP_LOG_CODE_RESPONSE_ABNORMAL_TRANSFER_ENCODING },
    { "RESPONSE_CHUNKED_OLD_PROTO", HTP_LOG_CODE_RESPONSE_CHUNKED_OLD_PROTO },
    { "RESPONSE_INVALID_PROTOCOL", HTP_LOG_CODE_RESPONSE_INVALID_PROTOCOL },
    { "RESPONSE_INVALID_STATUS", HTP_LOG_CODE_RESPONSE_INVALID_STATUS },
    { "REQUEST_LINE_INCOMPLETE", HTP_LOG_CODE_REQUEST_LINE_INCOMPLETE },
    { "PROTOCOL_CONTAINS_EXTRA_DATA", HTP_LOG_CODE_PROTOCOL_CONTAINS_EXTRA_DATA },
    {
            "CONTENT_LENGTH_EXTRA_DATA_START",
            HTP_LOG_CODE_CONTENT_LENGTH_EXTRA_DATA_START,
    },
    {
            "CONTENT_LENGTH_EXTRA_DATA_END",
            HTP_LOG_CODE_CONTENT_LENGTH_EXTRA_DATA_END,
    },
    {
            "CONTENT_LENGTH_EXTRA_DATA_END",
            HTP_LOG_CODE_CONTENT_LENGTH_EXTRA_DATA_END,
    },
    { "SWITCHING_PROTO_WITH_CONTENT_LENGTH", HTP_LOG_CODE_SWITCHING_PROTO_WITH_CONTENT_LENGTH },
    { "DEFORMED_EOL", HTP_LOG_CODE_DEFORMED_EOL },
    { "PARSER_STATE_ERROR", HTP_LOG_CODE_PARSER_STATE_ERROR },
    { "MISSING_OUTBOUND_TRANSACTION_DATA", HTP_LOG_CODE_MISSING_OUTBOUND_TRANSACTION_DATA },
    { "MISSING_INBOUND_TRANSACTION_DATA", HTP_LOG_CODE_MISSING_INBOUND_TRANSACTION_DATA },
    { "MISSING_INBOUND_TRANSACTION_DATA", HTP_LOG_CODE_MISSING_INBOUND_TRANSACTION_DATA },
    { "ZERO_LENGTH_DATA_CHUNKS", HTP_LOG_CODE_ZERO_LENGTH_DATA_CHUNKS },
    { "REQUEST_LINE_UNKNOWN_METHOD", HTP_LOG_CODE_REQUEST_LINE_UNKNOWN_METHOD },
    { "REQUEST_LINE_UNKNOWN_METHOD", HTP_LOG_CODE_REQUEST_LINE_UNKNOWN_METHOD },
    { "REQUEST_LINE_UNKNOWN_METHOD_NO_PROTOCOL",
            HTP_LOG_CODE_REQUEST_LINE_UNKNOWN_METHOD_NO_PROTOCOL },
    { "REQUEST_LINE_UNKNOWN_METHOD_INVALID_PROTOCOL",
            HTP_LOG_CODE_REQUEST_LINE_UNKNOWN_METHOD_INVALID_PROTOCOL },
    { "REQUEST_LINE_MISSING_PROTOCOL", HTP_LOG_CODE_REQUEST_LINE_NO_PROTOCOL },
    { "RESPONSE_LINE_INVALID_PROTOCOL", HTP_LOG_CODE_RESPONSE_LINE_INVALID_PROTOCOL },
    { "RESPONSE_LINE_INVALID_RESPONSE_STATUS", HTP_LOG_CODE_RESPONSE_LINE_INVALID_RESPONSE_STATUS },
    { "RESPONSE_BODY_INTERNAL_ERROR", HTP_LOG_CODE_RESPONSE_BODY_INTERNAL_ERROR },
    { "REQUEST_BODY_DATA_CALLBACK_ERROR", HTP_LOG_CODE_REQUEST_BODY_DATA_CALLBACK_ERROR },
    { "RESPONSE_INVALID_EMPTY_NAME", HTP_LOG_CODE_RESPONSE_INVALID_EMPTY_NAME },
    { "REQUEST_INVALID_EMPTY_NAME", HTP_LOG_CODE_REQUEST_INVALID_EMPTY_NAME },
    { "RESPONSE_INVALID_LWS_AFTER_NAME", HTP_LOG_CODE_RESPONSE_INVALID_LWS_AFTER_NAME },
    { "RESPONSE_HEADER_NAME_NOT_TOKEN", HTP_LOG_CODE_RESPONSE_HEADER_NAME_NOT_TOKEN },
    { "REQUEST_INVALID_LWS_AFTER_NAME", HTP_LOG_CODE_REQUEST_INVALID_LWS_AFTER_NAME },
    { "LZMA_DECOMPRESSION_DISABLED", HTP_LOG_CODE_LZMA_DECOMPRESSION_DISABLED },
    { "CONNECTION_ALREADY_OPEN", HTP_LOG_CODE_CONNECTION_ALREADY_OPEN },
    { "COMPRESSION_BOMB_DOUBLE_LZMA", HTP_LOG_CODE_COMPRESSION_BOMB_DOUBLE_LZMA },
    { "INVALID_CONTENT_ENCODING", HTP_LOG_CODE_INVALID_CONTENT_ENCODING },
    { "INVALID_GAP", HTP_LOG_CODE_INVALID_GAP },
    { "REQUEST_CHUNK_EXTENSION", HTP_LOG_CODE_REQUEST_CHUNK_EXTENSION },
    { "RESPONSE_CHUNK_EXTENSION", HTP_LOG_CODE_RESPONSE_CHUNK_EXTENSION },

    { "LZMA_MEMLIMIT_REACHED", HTP_LOG_CODE_LZMA_MEMLIMIT_REACHED },
    { "COMPRESSION_BOMB", HTP_LOG_CODE_COMPRESSION_BOMB },

    { "REQUEST_TOO_MANY_HEADERS", HTP_LOG_CODE_REQUEST_TOO_MANY_HEADERS },
    { "RESPONSE_TOO_MANY_HEADERS", HTP_LOG_CODE_RESPONSE_TOO_MANY_HEADERS },

    /* suricata warnings/errors */
    { "MULTIPART_GENERIC_ERROR", HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR },
    { "MULTIPART_NO_FILEDATA", HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA },
    { "MULTIPART_INVALID_HEADER", HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER },
    { "TOO_MANY_WARNINGS", HTTP_DECODER_EVENT_TOO_MANY_WARNINGS },
    { "RANGE_INVALID", HTTP_DECODER_EVENT_RANGE_INVALID },
    { "FILE_NAME_TOO_LONG", HTTP_DECODER_EVENT_FILE_NAME_TOO_LONG },
    { "FAILED_PROTOCOL_CHANGE", HTTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE },

    { NULL, -1 },
};

/* app-layer-frame-documentation tag start: HttpFrameTypes */
enum HttpFrameTypes {
    HTTP_FRAME_REQUEST,
    HTTP_FRAME_RESPONSE,
};

SCEnumCharMap http_frame_table[] = {
    {
            "request",
            HTTP_FRAME_REQUEST,
    },
    {
            "response",
            HTTP_FRAME_RESPONSE,
    },
    { NULL, -1 },
};
/* app-layer-frame-documentation tag end: HttpFrameTypes */

static int HTTPGetFrameIdByName(const char *frame_name)
{
    int id = SCMapEnumNameToValue(frame_name, http_frame_table);
    if (id < 0) {
        return -1;
    }
    return id;
}

static const char *HTTPGetFrameNameById(const uint8_t frame_id)
{
    const char *name = SCMapEnumValueToName(frame_id, http_frame_table);
    return name;
}

static void *HTPStateGetTx(void *alstate, uint64_t tx_id);
static int HTPStateGetAlstateProgress(void *tx, uint8_t direction);
static uint64_t HTPStateGetTxCnt(void *alstate);
#ifdef UNITTESTS
static void HTPParserRegisterTests(void);
#endif

static inline uint64_t HtpGetActiveRequestTxID(HtpState *s)
{
    uint64_t id = HTPStateGetTxCnt(s);
    BUG_ON(id == 0);
    return id - 1;
}

static inline uint64_t HtpGetActiveResponseTxID(HtpState *s)
{
    return s->transaction_cnt;
}

#ifdef DEBUG
/**
 * \internal
 *
 * \brief Lookup the HTP personality string from the numeric personality.
 *
 * \todo This needs to be a libhtp function.
 */
static const char *HTPLookupPersonalityString(int p)
{
#define CASE_HTP_PERSONALITY_STRING(p)                                                             \
    case HTP_SERVER_PERSONALITY_##p:                                                               \
        return #p

    switch (p) {
        CASE_HTP_PERSONALITY_STRING(MINIMAL);
        CASE_HTP_PERSONALITY_STRING(GENERIC);
        CASE_HTP_PERSONALITY_STRING(IDS);
        CASE_HTP_PERSONALITY_STRING(IIS_4_0);
        CASE_HTP_PERSONALITY_STRING(IIS_5_0);
        CASE_HTP_PERSONALITY_STRING(IIS_5_1);
        CASE_HTP_PERSONALITY_STRING(IIS_6_0);
        CASE_HTP_PERSONALITY_STRING(IIS_7_0);
        CASE_HTP_PERSONALITY_STRING(IIS_7_5);
        CASE_HTP_PERSONALITY_STRING(APACHE_2);
    }

    return NULL;
}
#endif /* DEBUG */

/**
 * \internal
 *
 * \brief Lookup the numeric HTP personality from a string.
 *
 * \todo This needs to be a libhtp function.
 */
static int HTPLookupPersonality(const char *str)
{
#define IF_HTP_PERSONALITY_NUM(p)                                                                  \
    if (strcasecmp(#p, str) == 0)                                                                  \
    return HTP_SERVER_PERSONALITY_##p

    IF_HTP_PERSONALITY_NUM(MINIMAL);
    IF_HTP_PERSONALITY_NUM(GENERIC);
    IF_HTP_PERSONALITY_NUM(IDS);
    IF_HTP_PERSONALITY_NUM(IIS_4_0);
    IF_HTP_PERSONALITY_NUM(IIS_5_0);
    IF_HTP_PERSONALITY_NUM(IIS_5_1);
    IF_HTP_PERSONALITY_NUM(IIS_6_0);
    IF_HTP_PERSONALITY_NUM(IIS_7_0);
    IF_HTP_PERSONALITY_NUM(IIS_7_5);
    IF_HTP_PERSONALITY_NUM(APACHE_2);
    if (strcasecmp("TOMCAT_6_0", str) == 0) {
        SCLogError("Personality %s no "
                   "longer supported by libhtp.",
                str);
        return -1;
    } else if ((strcasecmp("APACHE", str) == 0) ||
               (strcasecmp("APACHE_2_2", str) == 0))
    {
        SCLogWarning("Personality %s no "
                     "longer supported by libhtp, failing back to "
                     "Apache2 personality.",
                str);
        return HTP_SERVER_PERSONALITY_APACHE_2;
    }

    return -1;
}

static void HTPSetEvent(HtpState *s, HtpTxUserData *htud,
        const uint8_t dir, const uint8_t e)
{
    SCLogDebug("setting event %u", e);

    if (htud) {
        AppLayerDecoderEventsSetEventRaw(&htud->tx_data.events, e);
        s->events++;
        return;
    }

    const uint64_t tx_id = (dir == STREAM_TOSERVER) ?
        HtpGetActiveRequestTxID(s) : HtpGetActiveResponseTxID(s);

    htp_tx_t *tx = HTPStateGetTx(s, tx_id);
    if (tx == NULL && tx_id > 0)
        tx = HTPStateGetTx(s, tx_id - 1);
    if (tx != NULL) {
        htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        if (htud != NULL) {
            AppLayerDecoderEventsSetEventRaw(&htud->tx_data.events, e);
            s->events++;
            return;
        }
    }
    SCLogDebug("couldn't set event %u", e);
}

/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCEnter();

    HtpState *s = HTPMalloc(sizeof(HtpState));
    if (unlikely(s == NULL)) {
        SCReturnPtr(NULL, "void");
    }

    memset(s, 0x00, sizeof(HtpState));

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt++;
    htp_state_memuse += sizeof(HtpState);
    SCLogDebug("htp memory %"PRIu64" (%"PRIu64")", htp_state_memuse, htp_state_memcnt);
    SCMutexUnlock(&htp_state_mem_lock);
#endif

    SCReturnPtr((void *)s, "void");
}

static void HtpTxUserDataFree(HtpState *state, HtpTxUserData *htud)
{
    if (likely(htud)) {
        HtpBodyFree(&htud->request_body);
        HtpBodyFree(&htud->response_body);
        if (htud->request_headers_raw)
            HTPFree(htud->request_headers_raw, htud->request_headers_raw_len);
        if (htud->response_headers_raw)
            HTPFree(htud->response_headers_raw, htud->response_headers_raw_len);
        AppLayerDecoderEventsFreeEvents(&htud->tx_data.events);
        if (htud->mime_state)
            SCMimeStateFree(htud->mime_state);
        if (htud->tx_data.de_state != NULL) {
            DetectEngineStateFree(htud->tx_data.de_state);
        }
        if (htud->file_range) {
            HTPFileCloseHandleRange(&htp_sbcfg, &htud->files_tc, 0, htud->file_range, NULL, 0);
            HttpRangeFreeBlock(htud->file_range);
        }
        FileContainerRecycle(&htud->files_ts, &htp_sbcfg);
        FileContainerRecycle(&htud->files_tc, &htp_sbcfg);
        HTPFree(htud, sizeof(HtpTxUserData));
    }
}

/** \brief Function to frees the HTTP state memory and also frees the HTTP
 *         connection parser memory which was used by the HTP library
 */
void HTPStateFree(void *state)
{
    SCEnter();

    HtpState *s = (HtpState *)state;
    if (s == NULL) {
        SCReturn;
    }

    /* free the connection parser memory used by HTP library */
    if (s->connp != NULL) {
        SCLogDebug("freeing HTP state");

        uint64_t tx_id;
        uint64_t total_txs = HTPStateGetTxCnt(state);
        /* free the list of body chunks */
        if (s->conn != NULL) {
            for (tx_id = 0; tx_id < total_txs; tx_id++) {
                htp_tx_t *tx = HTPStateGetTx(s, tx_id);
                if (tx != NULL) {
                    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
                    HtpTxUserDataFree(s, htud);
                    htp_tx_set_user_data(tx, NULL);
                }
            }
        }
        htp_connp_destroy_all(s->connp);
    }

    HTPFree(s, sizeof(HtpState));

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt--;
    htp_state_memuse -= sizeof(HtpState);
    SCLogDebug("htp memory %"PRIu64" (%"PRIu64")", htp_state_memuse, htp_state_memcnt);
    SCMutexUnlock(&htp_state_mem_lock);
#endif

    SCReturn;
}

/**
 *  \brief HTP transaction cleanup callback
 *
 */
static void HTPStateTransactionFree(void *state, uint64_t id)
{
    SCEnter();

    HtpState *s = (HtpState *)state;

    SCLogDebug("state %p, id %"PRIu64, s, id);

    htp_tx_t *tx = HTPStateGetTx(s, id);
    if (tx != NULL) {
        /* This will remove obsolete body chunks */
        HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        HtpTxUserDataFree(s, htud);
        htp_tx_set_user_data(tx, NULL);
        htp_tx_destroy(s->connp, tx);
    }
}

/**
 * \brief Sets a flag that informs the HTP app layer that some module in the
 *        engine needs the http request body data.
 * \initonly
 */
void AppLayerHtpEnableRequestBodyCallback(void)
{
    SCEnter();

    SC_ATOMIC_OR(htp_config_flags, HTP_REQUIRE_REQUEST_BODY);
    SCReturn;
}

/**
 * \brief Sets a flag that informs the HTP app layer that some module in the
 *        engine needs the http request body data.
 * \initonly
 */
void AppLayerHtpEnableResponseBodyCallback(void)
{
    SCEnter();

    SC_ATOMIC_OR(htp_config_flags, HTP_REQUIRE_RESPONSE_BODY);
    SCReturn;
}

/**
 * \brief Sets a flag that informs the HTP app layer that some module in the
 *        engine needs the http request file.
 *
 * \initonly
 */
void AppLayerHtpNeedFileInspection(void)
{
    SCEnter();
    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpEnableResponseBodyCallback();

    SC_ATOMIC_OR(htp_config_flags, HTP_REQUIRE_REQUEST_FILE);
    SCReturn;
}

static void AppLayerHtpSetStreamDepthFlag(void *tx, const uint8_t flags)
{
    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data((htp_tx_t *)tx);
    if (tx_ud) {
        SCLogDebug("setting HTP_STREAM_DEPTH_SET, flags %02x", flags);
        if (flags & STREAM_TOCLIENT) {
            tx_ud->tcflags |= HTP_STREAM_DEPTH_SET;
        } else {
            tx_ud->tsflags |= HTP_STREAM_DEPTH_SET;
        }
    }
}

static bool AppLayerHtpCheckDepth(const HTPCfgDir *cfg, HtpBody *body, uint8_t flags)
{
    SCLogDebug("cfg->body_limit %u stream_depth %u body->content_len_so_far %" PRIu64,
            cfg->body_limit, FileReassemblyDepth(), body->content_len_so_far);
    if (flags & HTP_STREAM_DEPTH_SET) {
        uint32_t stream_depth = FileReassemblyDepth();
        if (body->content_len_so_far < (uint64_t)stream_depth || stream_depth == 0) {
            SCLogDebug("true");
            return true;
        }
    } else {
        if (cfg->body_limit == 0 || body->content_len_so_far < cfg->body_limit) {
            return true;
        }
    }
    SCLogDebug("false");
    return false;
}

static uint32_t AppLayerHtpComputeChunkLength(uint64_t content_len_so_far, uint32_t body_limit,
                                              uint32_t stream_depth, uint8_t flags, uint32_t data_len)
{
    uint32_t chunk_len = 0;
    if (!(flags & HTP_STREAM_DEPTH_SET) && body_limit > 0 &&
        (content_len_so_far < (uint64_t)body_limit) &&
        (content_len_so_far + (uint64_t)data_len) > body_limit)
    {
        chunk_len = (uint32_t)(body_limit - content_len_so_far);
    } else if ((flags & HTP_STREAM_DEPTH_SET) && stream_depth > 0 &&
               (content_len_so_far < (uint64_t)stream_depth) &&
               (content_len_so_far + (uint64_t)data_len) > stream_depth)
    {
        chunk_len = (uint32_t)(stream_depth - content_len_so_far);
    }
    SCLogDebug("len %u", chunk_len);
    return (chunk_len == 0 ? data_len : chunk_len);
}

/**
 *  \internal
 *
 *  \brief Check state for errors, warnings and add any as events
 *
 *  \param s state
 *  \param dir direction: STREAM_TOSERVER or STREAM_TOCLIENT
 */
static void HTPHandleError(HtpState *s, const uint8_t dir)
{
    if (s == NULL || s->conn == NULL || s->htp_messages_count >= HTP_MAX_MESSAGES) {
        // ignore further messages
        return;
    }

    htp_log_t *log = htp_conn_next_log(s->conn);
    while (log != NULL) {
        char *msg = htp_log_message(log);
        if (msg == NULL) {
            htp_log_free(log);
            log = htp_conn_next_log(s->conn);
            continue;
        }

        SCLogDebug("message %s", msg);

        htp_log_code_t id = htp_log_code(log);
        if (id != HTP_LOG_CODE_UNKNOWN && id != HTP_LOG_CODE_ERROR) {
            HTPSetEvent(s, NULL, dir, (uint8_t)id);
        }
        htp_free_cstring(msg);
        htp_log_free(log);
        s->htp_messages_count++;
        if (s->htp_messages_count >= HTP_MAX_MESSAGES) {
            // only once per HtpState
            HTPSetEvent(s, NULL, dir, HTTP_DECODER_EVENT_TOO_MANY_WARNINGS);
            // too noisy in fuzzing
            // DEBUG_VALIDATE_BUG_ON("Too many libhtp messages");
            break;
        }
        log = htp_conn_next_log(s->conn);
    }
    SCLogDebug("s->htp_messages_count %u", s->htp_messages_count);
}

static inline void HTPErrorCheckTxRequestFlags(HtpState *s, const htp_tx_t *tx)
{
#ifdef DEBUG
    BUG_ON(s == NULL || tx == NULL);
#endif
    if (htp_tx_flags(tx) & (HTP_FLAGS_REQUEST_INVALID_T_E | HTP_FLAGS_REQUEST_INVALID_C_L |
                                   HTP_FLAGS_HOST_MISSING | HTP_FLAGS_HOST_AMBIGUOUS |
                                   HTP_FLAGS_HOSTU_INVALID | HTP_FLAGS_HOSTH_INVALID)) {
        HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        if (htud == NULL)
            return;

        if (htp_tx_flags(tx) & HTP_FLAGS_REQUEST_INVALID_T_E)
            HTPSetEvent(s, htud, STREAM_TOSERVER,
                    HTP_LOG_CODE_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST);
        if (htp_tx_flags(tx) & HTP_FLAGS_REQUEST_INVALID_C_L)
            HTPSetEvent(
                    s, htud, STREAM_TOSERVER, HTP_LOG_CODE_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST);
        if (htp_tx_flags(tx) & HTP_FLAGS_HOST_MISSING)
            HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_MISSING_HOST_HEADER);
        if (htp_tx_flags(tx) & HTP_FLAGS_HOST_AMBIGUOUS)
            HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_HOST_HEADER_AMBIGUOUS);
        if (htp_tx_flags(tx) & HTP_FLAGS_HOSTU_INVALID)
            HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_URI_HOST_INVALID);
        if (htp_tx_flags(tx) & HTP_FLAGS_HOSTH_INVALID)
            HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_HEADER_HOST_INVALID);
    }
    if (htp_tx_request_auth_type(tx) == HTP_AUTH_TYPE_UNRECOGNIZED) {
        HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        if (htud == NULL)
            return;
        HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_AUTH_UNRECOGNIZED);
    }
    if (htp_tx_is_protocol_0_9(tx) && htp_tx_request_method_number(tx) == HTP_METHOD_UNKNOWN &&
            (htp_tx_request_protocol_number(tx) == HTP_PROTOCOL_INVALID ||
                    htp_tx_request_protocol_number(tx) == HTP_PROTOCOL_UNKNOWN)) {
        HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
        if (htud == NULL)
            return;
        HTPSetEvent(s, htud, STREAM_TOSERVER, HTP_LOG_CODE_REQUEST_LINE_INVALID);
    }
}

static int Setup(Flow *f, HtpState *hstate)
{
    /* store flow ref in state so callbacks can access it */
    hstate->f = f;

    HTPCfgRec *htp_cfg_rec = &cfglist;
    htp_cfg_t *htp = cfglist.cfg; /* Default to the global HTP config */
    void *user_data = NULL;

    if (FLOW_IS_IPV4(f)) {
        SCLogDebug("Looking up HTP config for ipv4 %08x", *GET_IPV4_DST_ADDR_PTR(f));
        (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)GET_IPV4_DST_ADDR_PTR(f), cfgtree, &user_data);
    }
    else if (FLOW_IS_IPV6(f)) {
        SCLogDebug("Looking up HTP config for ipv6");
        (void)SCRadixFindKeyIPV6BestMatch((uint8_t *)GET_IPV6_DST_ADDR(f), cfgtree, &user_data);
    }
    else {
        SCLogError("unknown address family, bug!");
        goto error;
    }

    if (user_data != NULL) {
        htp_cfg_rec = user_data;
        htp = htp_cfg_rec->cfg;
        SCLogDebug("LIBHTP using config: %p", htp);
    } else {
        SCLogDebug("Using default HTP config: %p", htp);
    }

    if (NULL == htp) {
#ifdef DEBUG_VALIDATION
        BUG_ON(htp == NULL);
#endif
        /* should never happen if HTPConfigure is properly invoked */
        goto error;
    }

    hstate->connp = htp_connp_create(htp);
    if (hstate->connp == NULL) {
        goto error;
    }

    hstate->conn = (htp_conn_t *)htp_connp_connection(hstate->connp);

    htp_connp_set_user_data(hstate->connp, (void *)hstate);
    hstate->cfg = htp_cfg_rec;

    SCLogDebug("New hstate->connp %p", hstate->connp);

    struct timeval tv = { SCTIME_SECS(f->startts), SCTIME_USECS(f->startts) };
    htp_connp_open(hstate->connp, NULL, f->sp, NULL, f->dp, &tv);

    StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER,
            htp_cfg_rec->request.inspect_min_size);
    StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOCLIENT,
            htp_cfg_rec->response.inspect_min_size);
    return 0;
error:
    return -1;
}

/**
 *  \brief  Function to handle the reassembled data from client and feed it to
 *          the HTP library to process it.
 *
 *  \param  flow        Pointer to the flow the data belong to
 *  \param  htp_state   Pointer the state in which the parsed value to be stored
 *  \param  pstate      Application layer parser state for this session
 *
 *  \retval On success returns 1 or on failure returns -1.
 */
static AppLayerResult HTPHandleRequestData(Flow *f, void *htp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();
    int ret = 0;
    HtpState *hstate = (HtpState *)htp_state;

    /* On the first invocation, create the connection parser structure to
     * be used by HTP library.  This is looked up via IP in the radix
     * tree.  Failing that, the default HTP config is used.
     */
    if (NULL == hstate->conn) {
        if (Setup(f, hstate) != 0) {
            SCReturnStruct(APP_LAYER_ERROR);
        }
    }
    DEBUG_VALIDATE_BUG_ON(hstate->connp == NULL);
    hstate->slice = &stream_slice;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    struct timeval ts = { SCTIME_SECS(f->startts), SCTIME_USECS(f->startts) };
    /* pass the new data to the htp parser */
    if (input_len > 0) {
        const int r = htp_connp_request_data(hstate->connp, &ts, input, input_len);
        switch (r) {
            case HTP_STREAM_STATE_ERROR:
                ret = -1;
                break;
            default:
                break;
        }
        HTPHandleError(hstate, STREAM_TOSERVER);
    }

    /* if the TCP connection is closed, then close the HTTP connection */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) &&
        !(hstate->flags & HTP_FLAG_STATE_CLOSED_TS))
    {
        htp_connp_request_close(hstate->connp, &ts);
        hstate->flags |= HTP_FLAG_STATE_CLOSED_TS;
        SCLogDebug("stream eof encountered, closing htp handle for ts");
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    hstate->slice = NULL;

    if (ret < 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    SCReturnStruct(APP_LAYER_OK);
}

/**
 *  \brief  Function to handle the reassembled data from server and feed it to
 *          the HTP library to process it.
 *
 *  \param  flow        Pointer to the flow the data belong to
 *  \param  htp_state   Pointer the state in which the parsed value to be stored
 *  \param  pstate      Application layer parser state for this session
 *  \param  input       Pointer the received HTTP server data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the output (not used in this function)
 *
 *  \retval On success returns 1 or on failure returns -1
 */
static AppLayerResult HTPHandleResponseData(Flow *f, void *htp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();
    int ret = 0;
    HtpState *hstate = (HtpState *)htp_state;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    /* On the first invocation, create the connection parser structure to
     * be used by HTP library.  This is looked up via IP in the radix
     * tree.  Failing that, the default HTP config is used.
     */
    if (NULL == hstate->conn) {
        if (Setup(f, hstate) != 0) {
            SCReturnStruct(APP_LAYER_ERROR);
        }
    }
    DEBUG_VALIDATE_BUG_ON(hstate->connp == NULL);
    hstate->slice = &stream_slice;

    struct timeval ts = { SCTIME_SECS(f->startts), SCTIME_USECS(f->startts) };
    const htp_tx_t *tx = NULL;
    uint32_t consumed = 0;
    if (input_len > 0) {
        const int r = htp_connp_response_data(hstate->connp, &ts, input, input_len);
        switch (r) {
            case HTP_STREAM_STATE_ERROR:
                ret = -1;
                break;
            case HTP_STREAM_STATE_TUNNEL:
                tx = htp_connp_get_response_tx(hstate->connp);
                if (tx != NULL && htp_tx_response_status_number(tx) == 101) {
                    const htp_header_t *h = htp_tx_response_header(tx, "Upgrade");
                    if (h == NULL) {
                        break;
                    }
                    uint16_t dp = 0;
                    if (htp_tx_request_port_number(tx) != -1) {
                        dp = (uint16_t)htp_tx_request_port_number(tx);
                    }
                    consumed = (uint32_t)htp_connp_response_data_consumed(hstate->connp);
                    if (bstr_cmp_c(htp_header_value(h), "h2c") == 0) {
                        if (AppLayerProtoDetectGetProtoName(ALPROTO_HTTP2) == NULL) {
                            // if HTTP2 is disabled, keep the HTP_STREAM_TUNNEL mode
                            break;
                        }
                        hstate->slice = NULL;
                        if (!AppLayerRequestProtocolChange(hstate->f, dp, ALPROTO_HTTP2)) {
                            HTPSetEvent(hstate, NULL, STREAM_TOCLIENT,
                                    HTTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE);
                        }
                        // During HTTP2 upgrade, we may consume the HTTP1 part of the data
                        // and we need to parser the remaining part with HTTP2
                        if (consumed > 0 && consumed < input_len) {
                            SCReturnStruct(APP_LAYER_INCOMPLETE(consumed, input_len - consumed));
                        }
                        SCReturnStruct(APP_LAYER_OK);
                    } else if (bstr_cmp_c_nocase(htp_header_value(h), "WebSocket") == 0) {
                        if (AppLayerProtoDetectGetProtoName(ALPROTO_WEBSOCKET) == NULL) {
                            // if WS is disabled, keep the HTP_STREAM_TUNNEL mode
                            break;
                        }
                        hstate->slice = NULL;
                        if (!AppLayerRequestProtocolChange(hstate->f, dp, ALPROTO_WEBSOCKET)) {
                            HTPSetEvent(hstate, NULL, STREAM_TOCLIENT,
                                    HTTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE);
                        }
                        // During WS upgrade, we may consume the HTTP1 part of the data
                        // and we need to parser the remaining part with WS
                        if (consumed > 0 && consumed < input_len) {
                            SCReturnStruct(APP_LAYER_INCOMPLETE(consumed, input_len - consumed));
                        }
                        SCReturnStruct(APP_LAYER_OK);
                    }
                }
                break;
            default:
                break;
        }
        HTPHandleError(hstate, STREAM_TOCLIENT);
    }

    /* if we the TCP connection is closed, then close the HTTP connection */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) &&
        !(hstate->flags & HTP_FLAG_STATE_CLOSED_TC))
    {
        htp_connp_close(hstate->connp, &ts);
        hstate->flags |= HTP_FLAG_STATE_CLOSED_TC;
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    hstate->slice = NULL;

    if (ret < 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    SCReturnStruct(APP_LAYER_OK);
}

/**
 *  \param name /Lowercase/ version of the variable name
 */
static int HTTPParseContentDispositionHeader(const uint8_t *name, size_t name_len,
        const uint8_t *data, size_t len, uint8_t const **retptr, size_t *retlen)
{
#ifdef PRINT
    printf("DATA START: \n");
    PrintRawDataFp(stdout, data, len);
    printf("DATA END: \n");
#endif
    size_t x;
    int quote = 0;

    for (x = 0; x < len; x++) {
        if (!(isspace(data[x])))
            break;
    }

    if (x >= len)
        return 0;

    const uint8_t *line = data + x;
    size_t line_len = len-x;
    size_t offset = 0;
#ifdef PRINT
    printf("LINE START: \n");
    PrintRawDataFp(stdout, line, line_len);
    printf("LINE END: \n");
#endif
    for (x = 0 ; x < line_len; x++) {
        if (x > 0) {
            if (line[x - 1] != '\\' && line[x] == '\"') {
                quote++;
            }

            if (((line[x - 1] != '\\' && line[x] == ';') || ((x + 1) == line_len)) && (quote == 0 || quote % 2 == 0)) {
                const uint8_t *token = line + offset;
                size_t token_len = x - offset;

                if ((x + 1) == line_len) {
                    token_len++;
                }

                offset = x + 1;

                while (offset < line_len && isspace(line[offset])) {
                    x++;
                    offset++;
                }
#ifdef PRINT
                printf("TOKEN START: \n");
                PrintRawDataFp(stdout, token, token_len);
                printf("TOKEN END: \n");
#endif
                if (token_len > name_len) {
                    if (name == NULL || SCMemcmpLowercase(name, token, name_len) == 0) {
                        const uint8_t *value = token + name_len;
                        size_t value_len = token_len - name_len;

                        if (value[0] == '\"') {
                            value++;
                            value_len--;
                        }
                        if (value[value_len-1] == '\"') {
                            value_len--;
                        }
#ifdef PRINT
                        printf("VALUE START: \n");
                        PrintRawDataFp(stdout, value, value_len);
                        printf("VALUE END: \n");
#endif
                        *retptr = value;
                        *retlen = value_len;
                        return 1;
                    }
                }
            }
        }
    }

    return 0;
}

/**
 *  \brief setup multipart parsing: extract boundary and store it
 *
 *  \param d HTTP transaction
 *  \param htud transaction userdata
 *
 *  \retval 1 ok, multipart set up
 *  \retval 0 ok, not multipart though
 *  \retval -1 error: problem with the boundary
 *
 *  If the request contains a multipart message, this function will
 *  set the HTP_BOUNDARY_SET in the transaction.
 */
static int HtpRequestBodySetupMultipart(const htp_tx_t *tx, HtpTxUserData *htud)
{
    const htp_header_t *h = htp_tx_request_header(tx, "Content-Type");
    if (h != NULL && htp_header_value_len(h) > 0) {
        htud->mime_state =
                SCMimeStateInit(htp_header_value_ptr(h), (uint32_t)htp_header_value_len(h));
        if (htud->mime_state) {
            htud->tsflags |= HTP_BOUNDARY_SET;
            SCReturnInt(1);
        }
    }
    SCReturnInt(0);
}

/**
 *  \brief Create a single buffer from the HtpBodyChunks in our list
 *
 *  \param htud transaction user data
 *  \param chunks_buffers pointer to pass back the buffer to the caller
 *  \param chunks_buffer_len pointer to pass back the buffer length to the caller
 */
static void HtpRequestBodyReassemble(HtpTxUserData *htud,
        const uint8_t **chunks_buffer, uint32_t *chunks_buffer_len)
{
    StreamingBufferGetDataAtOffset(htud->request_body.sb,
            chunks_buffer, chunks_buffer_len,
            htud->request_body.body_parsed);
}

static void FlagDetectStateNewFile(HtpTxUserData *tx, int dir)
{
    SCEnter();
    if (tx && tx->tx_data.de_state) {
        if (dir == STREAM_TOSERVER) {
            SCLogDebug("DETECT_ENGINE_STATE_FLAG_FILE_NEW set");
            tx->tx_data.de_state->dir_state[0].flags |= DETECT_ENGINE_STATE_FLAG_FILE_NEW;
        } else if (dir == STREAM_TOCLIENT) {
            SCLogDebug("DETECT_ENGINE_STATE_FLAG_FILE_NEW set");
            tx->tx_data.de_state->dir_state[1].flags |= DETECT_ENGINE_STATE_FLAG_FILE_NEW;
        }
    }
}

static int HtpRequestBodyHandleMultipart(HtpState *hstate, HtpTxUserData *htud, const void *tx,
        const uint8_t *chunks_buffer, uint32_t chunks_buffer_len, bool eof)
{
#ifdef PRINT
    printf("CHUNK START: \n");
    PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    printf("CHUNK END: \n");
#endif

    // libhtp will not call us back too late
    // should libhtp send a callback eof for 0 chunked ?
    DEBUG_VALIDATE_BUG_ON(AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP1, (void *)tx,
                                  STREAM_TOSERVER) >= HTP_REQUEST_PROGRESS_COMPLETE);

    const uint8_t *cur_buf = chunks_buffer;
    uint32_t cur_buf_len = chunks_buffer_len;

    if (eof) {
        // abrupt end of connection
        if (htud->tsflags & HTP_FILENAME_SET && !(htud->tsflags & HTP_DONTSTORE)) {
            /* we currently only handle multipart for ts.  When we support it for tc,
             * we will need to supply right direction */
            HTPFileClose(htud, cur_buf, cur_buf_len, FILE_TRUNCATED, STREAM_TOSERVER);
        }
        htud->tsflags &= ~HTP_FILENAME_SET;
        goto end;
    }

    uint32_t consumed;
    uint32_t warnings;
    int result = 0;
    const uint8_t *filename = NULL;
    uint16_t filename_len = 0;

    // keep parsing mime and use callbacks when needed
    while (cur_buf_len > 0) {
        MimeParserResult r =
                SCMimeParse(htud->mime_state, cur_buf, cur_buf_len, &consumed, &warnings);
        DEBUG_VALIDATE_BUG_ON(consumed > cur_buf_len);
        htud->request_body.body_parsed += consumed;
        if (warnings) {
            if (warnings & MIME_EVENT_FLAG_INVALID_HEADER) {
                HTPSetEvent(
                        hstate, htud, STREAM_TOSERVER, HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER);
            }
            if (warnings & MIME_EVENT_FLAG_NO_FILEDATA) {
                HTPSetEvent(
                        hstate, htud, STREAM_TOSERVER, HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA);
            }
        }
        switch (r) {
            case MimeNeedsMore:
                // there is not enough data, wait for more next time
                goto end;
            case MimeFileOpen:
                // get filename owned by mime state
                SCMimeStateGetFilename(htud->mime_state, &filename, &filename_len);
                if (filename_len > 0) {
                    htud->tsflags |= HTP_FILENAME_SET;
                    htud->tsflags &= ~HTP_DONTSTORE;
                    result = HTPFileOpen(
                            hstate, htud, filename, filename_len, NULL, 0, STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->tsflags |= HTP_DONTSTORE;
                    }
                    FlagDetectStateNewFile(htud, STREAM_TOSERVER);
                }
                break;
            case MimeFileChunk:
                if (htud->tsflags & HTP_FILENAME_SET && !(htud->tsflags & HTP_DONTSTORE)) {
                    result = HTPFileStoreChunk(htud, cur_buf, consumed, STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        /* we know for sure we're not storing the file */
                        htud->tsflags |= HTP_DONTSTORE;
                    }
                }
                break;
            case MimeFileClose:
                if (htud->tsflags & HTP_FILENAME_SET && !(htud->tsflags & HTP_DONTSTORE)) {
                    uint32_t lastsize = consumed;
                    if (lastsize > 0 && cur_buf[lastsize - 1] == '\n') {
                        lastsize--;
                        if (lastsize > 0 && cur_buf[lastsize - 1] == '\r') {
                            lastsize--;
                        }
                    }
                    HTPFileClose(htud, cur_buf, lastsize, 0, STREAM_TOSERVER);
                }
                htud->tsflags &= ~HTP_FILENAME_SET;
                break;
        }
        cur_buf += consumed;
        cur_buf_len -= consumed;
    }

end:
    SCLogDebug("htud->request_body.body_parsed %"PRIu64, htud->request_body.body_parsed);
    return 0;
}

/** \internal
 *  \brief Handle POST or PUT, no multipart body data
 */
static int HtpRequestBodyHandlePOSTorPUT(HtpState *hstate, HtpTxUserData *htud, const htp_tx_t *tx,
        const uint8_t *data, uint32_t data_len)
{
    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tsflags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* get the name */
        if (htp_uri_path(htp_tx_parsed_uri(tx)) != NULL) {
            filename = (uint8_t *)bstr_ptr(htp_uri_path(htp_tx_parsed_uri(tx)));
            filename_len = bstr_len(htp_uri_path(htp_tx_parsed_uri(tx)));
        }

        if (filename != NULL) {
            if (filename_len > SC_FILENAME_MAX) {
                // explicitly truncate the file name if too long
                filename_len = SC_FILENAME_MAX;
                HTPSetEvent(hstate, htud, STREAM_TOSERVER, HTTP_DECODER_EVENT_FILE_NAME_TOO_LONG);
            }
            result = HTPFileOpen(hstate, htud, filename, (uint16_t)filename_len, data, data_len,
                    STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tsflags |= HTP_DONTSTORE;
            } else {
                FlagDetectStateNewFile(htud, STREAM_TOSERVER);
                htud->tsflags |= HTP_FILENAME_SET;
                htud->tsflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tsflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(htud, data, data_len, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->tsflags |= HTP_DONTSTORE;
            }
        }
    }

    return 0;
end:
    return -1;
}

static int HtpResponseBodyHandle(HtpState *hstate, HtpTxUserData *htud, const htp_tx_t *tx,
        const uint8_t *data, uint32_t data_len)
{
    SCEnter();

    int result = 0;

    /* see if we need to open the file
     * we check for htp_tx_response_line(tx) in case of junk
     * interpreted as body before response line
     */
    if (!(htud->tcflags & HTP_FILENAME_SET)) {
        SCLogDebug("setting up file name");

        const uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* try Content-Disposition header first */
        const htp_header_t *h = htp_tx_response_header(tx, "Content-Disposition");
        if (h != NULL && htp_header_value_len(h) > 0) {
            /* parse content-disposition */
            (void)HTTPParseContentDispositionHeader((uint8_t *)"filename=", 9,
                    htp_header_value_ptr(h), htp_header_value_len(h), &filename, &filename_len);
        }

        /* fall back to name from the uri */
        if (filename == NULL) {
            /* get the name */
            if (htp_uri_path(htp_tx_parsed_uri(tx)) != NULL) {
                filename = (uint8_t *)bstr_ptr(htp_uri_path(htp_tx_parsed_uri(tx)));
                filename_len = bstr_len(htp_uri_path(htp_tx_parsed_uri(tx)));
            }
        }

        if (filename != NULL) {
            // set range if present
            const htp_header_t *h_content_range = htp_tx_response_header(tx, "content-range");
            if (filename_len > SC_FILENAME_MAX) {
                // explicitly truncate the file name if too long
                filename_len = SC_FILENAME_MAX;
                HTPSetEvent(hstate, htud, STREAM_TOSERVER, HTTP_DECODER_EVENT_FILE_NAME_TOO_LONG);
            }
            if (h_content_range != NULL) {
                result = HTPFileOpenWithRange(hstate, htud, filename, (uint16_t)filename_len, data,
                        data_len, tx, htp_header_value(h_content_range), htud);
            } else {
                result = HTPFileOpen(hstate, htud, filename, (uint16_t)filename_len, data, data_len,
                        STREAM_TOCLIENT);
            }
            SCLogDebug("result %d", result);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tcflags |= HTP_DONTSTORE;
            } else {
                FlagDetectStateNewFile(htud, STREAM_TOCLIENT);
                htud->tcflags |= HTP_FILENAME_SET;
                htud->tcflags &= ~HTP_DONTSTORE;
            }
        }
    } else {
        /* otherwise, just store the data */

        if (!(htud->tcflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(htud, data, data_len, STREAM_TOCLIENT);
            SCLogDebug("result %d", result);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->tcflags |= HTP_DONTSTORE;
            }
        }
    }

    htud->response_body.body_parsed += data_len;
    return 0;
end:
    return -1;
}

/**
 * \brief Function callback to append chunks for Requests
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HTP_STATUS_OK if all goes well
 */
static int HTPCallbackRequestBodyData(const htp_connp_t *connp, htp_tx_data_t *d)
{
    SCEnter();

    const htp_tx_t *tx = htp_tx_data_tx(d);

    if (!(SC_ATOMIC_GET(htp_config_flags) & HTP_REQUIRE_REQUEST_BODY))
        SCReturnInt(HTP_STATUS_OK);

    if (htp_tx_data_is_empty(d))
        SCReturnInt(HTP_STATUS_OK);

#ifdef PRINT
    printf("HTPBODY START: \n");
    PrintRawDataFp(stdout, (uint8_t *)htp_tx_data_data(d), htp_tx_data_len(d));
    printf("HTPBODY END: \n");
#endif

    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    SCLogDebug("New request body data available at %p -> %p -> %p, bodylen "
               "%" PRIu32 "",
            hstate, d, htp_tx_data_data(d), (uint32_t)htp_tx_data_len(d));

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        SCReturnInt(HTP_STATUS_OK);
    }
    SCTxDataUpdateFileFlags(&tx_ud->tx_data, hstate->state_data.file_flags);

    if (!tx_ud->response_body_init) {
        tx_ud->response_body_init = 1;

        if (htp_tx_request_method_number(tx) == HTP_METHOD_POST) {
            SCLogDebug("POST");
            int r = HtpRequestBodySetupMultipart(tx, tx_ud);
            if (r == 1) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_MULTIPART;
            } else if (r == 0) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_POST;
                SCLogDebug("not multipart");
            }
        } else if (htp_tx_request_method_number(tx) == HTP_METHOD_PUT) {
            tx_ud->request_body_type = HTP_BODY_REQUEST_PUT;
        }
    }

    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(hstate, &tx_ud->request_body, STREAM_TOSERVER);

    SCLogDebug("tx_ud->request_body.content_len_so_far %"PRIu64, tx_ud->request_body.content_len_so_far);
    SCLogDebug("hstate->cfg->request.body_limit %u", hstate->cfg->request.body_limit);

    /* within limits, add the body chunk to the state. */
    if (AppLayerHtpCheckDepth(&hstate->cfg->request, &tx_ud->request_body, tx_ud->tsflags)) {
        uint32_t stream_depth = FileReassemblyDepth();
        uint32_t len = AppLayerHtpComputeChunkLength(tx_ud->request_body.content_len_so_far,
                hstate->cfg->request.body_limit, stream_depth, tx_ud->tsflags,
                (uint32_t)htp_tx_data_len(d));
        BUG_ON(len > (uint32_t)htp_tx_data_len(d));

        HtpBodyAppendChunk(&tx_ud->request_body, htp_tx_data_data(d), len);

        const uint8_t *chunks_buffer = NULL;
        uint32_t chunks_buffer_len = 0;

        if (tx_ud->request_body_type == HTP_BODY_REQUEST_MULTIPART) {
            /* multi-part body handling starts here */
            if (!(tx_ud->tsflags & HTP_BOUNDARY_SET)) {
                goto end;
            }

            HtpRequestBodyReassemble(tx_ud, &chunks_buffer, &chunks_buffer_len);
            if (chunks_buffer == NULL) {
                goto end;
            }
#ifdef PRINT
            printf("REASSCHUNK START: \n");
            PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
            printf("REASSCHUNK END: \n");
#endif

            HtpRequestBodyHandleMultipart(hstate, tx_ud, htp_tx_data_tx(d), chunks_buffer,
                    chunks_buffer_len, (htp_tx_data_data(d) == NULL && htp_tx_data_len(d) == 0));

        } else if (tx_ud->request_body_type == HTP_BODY_REQUEST_POST ||
                   tx_ud->request_body_type == HTP_BODY_REQUEST_PUT) {
            HtpRequestBodyHandlePOSTorPUT(
                    hstate, tx_ud, htp_tx_data_tx(d), htp_tx_data_data(d), len);
        }

    } else {
        if (tx_ud->tsflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(tx_ud, NULL, 0, FILE_TRUNCATED, STREAM_TOSERVER);
            tx_ud->tsflags &= ~HTP_FILENAME_SET;
        }
    }

end:
    if (hstate->conn != NULL) {
        SCLogDebug("checking body size %" PRIu64 " against inspect limit %u (cur %" PRIu64
                   ", last %" PRIu64 ")",
                tx_ud->request_body.content_len_so_far, hstate->cfg->request.inspect_min_size,
                (uint64_t)htp_conn_request_data_counter(hstate->conn),
                hstate->last_request_data_stamp);

        /* if we reach the inspect_min_size we'll trigger inspection,
         * so make sure that raw stream is also inspected. Set the
         * data to be used to the amount of raw bytes we've seen to
         * get here. */
        if (tx_ud->request_body.body_inspected == 0 &&
            tx_ud->request_body.content_len_so_far >= hstate->cfg->request.inspect_min_size) {
            if ((uint64_t)htp_conn_request_data_counter(hstate->conn) >
                            hstate->last_request_data_stamp &&
                    (uint64_t)htp_conn_request_data_counter(hstate->conn) -
                                    hstate->last_request_data_stamp <
                            (uint64_t)UINT_MAX) {
                uint32_t data_size =
                        (uint32_t)((uint64_t)htp_conn_request_data_counter(hstate->conn) -
                                   hstate->last_request_data_stamp);
                const uint32_t depth = MIN(data_size, hstate->cfg->request.inspect_min_size);

                /* body still in progress, but due to min inspect size we need to inspect now */
                StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOSERVER, depth);
                AppLayerParserTriggerRawStreamReassembly(hstate->f, STREAM_TOSERVER);
            }
        /* after the start of the body, disable the depth logic */
        } else if (tx_ud->request_body.body_inspected > 0) {
            StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOSERVER, 0);
        }
    }
    SCReturnInt(HTP_STATUS_OK);
}

/**
 * \brief Function callback to append chunks for Responses
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HTP_STATUS_OK if all goes well
 */
static int HTPCallbackResponseBodyData(const htp_connp_t *connp, htp_tx_data_t *d)
{
    SCEnter();

    const htp_tx_t *tx = htp_tx_data_tx(d);

    if (!(SC_ATOMIC_GET(htp_config_flags) & HTP_REQUIRE_RESPONSE_BODY))
        SCReturnInt(HTP_STATUS_OK);

    if (htp_tx_data_is_empty(d))
        SCReturnInt(HTP_STATUS_OK);

    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    SCLogDebug("New response body data available at %p -> %p -> %p, bodylen "
               "%" PRIu32 "",
            hstate, d, htp_tx_data_data(d), (uint32_t)htp_tx_data_len(d));

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        SCReturnInt(HTP_STATUS_OK);
    }
    SCTxDataUpdateFileFlags(&tx_ud->tx_data, hstate->state_data.file_flags);
    if (!tx_ud->request_body_init) {
        tx_ud->request_body_init = 1;
    }

    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(hstate, &tx_ud->response_body, STREAM_TOCLIENT);

    SCLogDebug("tx_ud->response_body.content_len_so_far %"PRIu64, tx_ud->response_body.content_len_so_far);
    SCLogDebug("hstate->cfg->response.body_limit %u", hstate->cfg->response.body_limit);

    /* within limits, add the body chunk to the state. */
    if (AppLayerHtpCheckDepth(&hstate->cfg->response, &tx_ud->response_body, tx_ud->tcflags)) {
        uint32_t stream_depth = FileReassemblyDepth();
        uint32_t len = AppLayerHtpComputeChunkLength(tx_ud->response_body.content_len_so_far,
                hstate->cfg->response.body_limit, stream_depth, tx_ud->tcflags,
                (uint32_t)htp_tx_data_len(d));
        BUG_ON(len > (uint32_t)htp_tx_data_len(d));

        HtpBodyAppendChunk(&tx_ud->response_body, htp_tx_data_data(d), len);

        HtpResponseBodyHandle(hstate, tx_ud, htp_tx_data_tx(d), htp_tx_data_data(d), len);
    } else {
        if (tx_ud->tcflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(tx_ud, NULL, 0, FILE_TRUNCATED, STREAM_TOCLIENT);
            tx_ud->tcflags &= ~HTP_FILENAME_SET;
        }
    }

    if (hstate->conn != NULL) {
        SCLogDebug("checking body size %" PRIu64 " against inspect limit %u (cur %" PRIu64
                   ", last %" PRIu64 ")",
                tx_ud->response_body.content_len_so_far, hstate->cfg->response.inspect_min_size,
                (uint64_t)htp_conn_request_data_counter(hstate->conn),
                hstate->last_response_data_stamp);
        /* if we reach the inspect_min_size we'll trigger inspection,
         * so make sure that raw stream is also inspected. Set the
         * data to be used to the amount of raw bytes we've seen to
         * get here. */
        if (tx_ud->response_body.body_inspected == 0 &&
            tx_ud->response_body.content_len_so_far >= hstate->cfg->response.inspect_min_size) {
            if ((uint64_t)htp_conn_response_data_counter(hstate->conn) >
                            hstate->last_response_data_stamp &&
                    (uint64_t)htp_conn_response_data_counter(hstate->conn) -
                                    hstate->last_response_data_stamp <
                            (uint64_t)UINT_MAX) {
                uint32_t data_size =
                        (uint32_t)((uint64_t)htp_conn_response_data_counter(hstate->conn) -
                                   hstate->last_response_data_stamp);
                const uint32_t depth = MIN(data_size, hstate->cfg->response.inspect_min_size);

                /* body still in progress, but due to min inspect size we need to inspect now */
                StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOCLIENT, depth);
                AppLayerParserTriggerRawStreamReassembly(hstate->f, STREAM_TOCLIENT);
            }
        /* after the start of the body, disable the depth logic */
        } else if (tx_ud->response_body.body_inspected > 0) {
            StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOCLIENT, 0);
        }
    }
    SCReturnInt(HTP_STATUS_OK);
}

/**
 * \brief Print the stats of the HTTP requests
 */
void HTPAtExitPrintStats(void)
{
#ifdef DEBUG
    SCEnter();
    SCMutexLock(&htp_state_mem_lock);
    SCLogDebug("http_state_memcnt %"PRIu64", http_state_memuse %"PRIu64"",
                htp_state_memcnt, htp_state_memuse);
    SCMutexUnlock(&htp_state_mem_lock);
    SCReturn;
#endif
}

/** \brief Clears the HTTP server configuration memory used by HTP library */
void HTPFreeConfig(void)
{
    SCEnter();

    if (!AppLayerProtoDetectConfProtoDetectionEnabled("tcp", "http") ||
        !AppLayerParserConfParserEnabled("tcp", "http"))
    {
        SCReturn;
    }

    HTPCfgRec *nextrec = cfglist.next;
    SCRadixReleaseRadixTree(cfgtree);
    cfgtree = NULL;
    htp_config_destroy(cfglist.cfg);
    while (nextrec != NULL) {
        HTPCfgRec *htprec = nextrec;
        nextrec = nextrec->next;

        htp_config_destroy(htprec->cfg);
        SCFree(htprec);
    }
    SCReturn;
}

static int HTPCallbackRequestHasTrailer(const htp_connp_t *connp, htp_tx_t *tx)
{
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        htud->request_has_trailers = 1;
    }
    return HTP_STATUS_OK;
}

static int HTPCallbackResponseHasTrailer(const htp_connp_t *connp, htp_tx_t *tx)
{
    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        htud->response_has_trailers = 1;
    }
    return HTP_STATUS_OK;
}

/**\internal
 * \brief called at start of request
 * Set min inspect size.
 */
static int HTPCallbackRequestStart(const htp_connp_t *connp, htp_tx_t *tx)
{
    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    uint64_t consumed = hstate->slice->offset + htp_connp_request_data_consumed(hstate->connp);
    SCLogDebug("HTTP request start: data offset %" PRIu64 ", in_data_counter %" PRIu64, consumed,
            (uint64_t)htp_conn_request_data_counter(hstate->conn));
    /* app-layer-frame-documentation tag start: frame registration http request */
    Frame *frame = AppLayerFrameNewByAbsoluteOffset(
            hstate->f, hstate->slice, consumed, -1, 0, HTTP_FRAME_REQUEST);
    if (frame) {
        SCLogDebug("frame %p/%" PRIi64, frame, frame->id);
        hstate->request_frame_id = frame->id;
        AppLayerFrameSetTxId(frame, HtpGetActiveRequestTxID(hstate));
    }
    /* app-layer-frame-documentation tag end: frame registration http request */

    if (hstate->cfg)
        StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOSERVER,
                hstate->cfg->request.inspect_min_size);

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        tx_ud = HTPCalloc(1, sizeof(HtpTxUserData));
        if (unlikely(tx_ud == NULL)) {
            SCReturnInt(HTP_STATUS_OK);
        }
        tx_ud->tx_data.file_tx = STREAM_TOSERVER | STREAM_TOCLIENT; // each http tx may xfer files
        htp_tx_set_user_data(tx, tx_ud);
    }
    SCReturnInt(HTP_STATUS_OK);
}

/**\internal
 * \brief called at start of response
 * Set min inspect size.
 */
static int HTPCallbackResponseStart(const htp_connp_t *connp, htp_tx_t *tx)
{
    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    uint64_t consumed = hstate->slice->offset + htp_connp_response_data_consumed(hstate->connp);
    SCLogDebug("HTTP response start: data offset %" PRIu64 ", out_data_counter %" PRIu64, consumed,
            (uint64_t)htp_conn_response_data_counter(hstate->conn));

    Frame *frame = AppLayerFrameNewByAbsoluteOffset(
            hstate->f, hstate->slice, consumed, -1, 1, HTTP_FRAME_RESPONSE);
    if (frame) {
        SCLogDebug("frame %p/%" PRIi64, frame, frame->id);
        hstate->response_frame_id = frame->id;
        AppLayerFrameSetTxId(frame, HtpGetActiveResponseTxID(hstate));
    }

    if (hstate->cfg)
        StreamTcpReassemblySetMinInspectDepth(hstate->f->protoctx, STREAM_TOCLIENT,
                hstate->cfg->response.inspect_min_size);

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        tx_ud = HTPCalloc(1, sizeof(HtpTxUserData));
        if (unlikely(tx_ud == NULL)) {
            SCReturnInt(HTP_STATUS_OK);
        }
        tx_ud->tx_data.file_tx =
                STREAM_TOCLIENT; // each http tx may xfer files. Toserver already missed.
        htp_tx_set_user_data(tx, tx_ud);
    }
    SCReturnInt(HTP_STATUS_OK);
}

/**
 *  \brief  callback for request to store the recent incoming request
            into the recent_request_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackRequestComplete(const htp_connp_t *connp, htp_tx_t *tx)
{
    SCEnter();

    if (tx == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    const uint64_t abs_right_edge =
            hstate->slice->offset + htp_connp_request_data_consumed(hstate->connp);

    /* app-layer-frame-documentation tag start: updating frame->len */
    if (hstate->request_frame_id > 0) {
        Frame *frame = AppLayerFrameGetById(hstate->f, 0, hstate->request_frame_id);
        if (frame) {
            const uint64_t request_size = abs_right_edge - hstate->last_request_data_stamp;

            SCLogDebug("HTTP request complete: data offset %" PRIu64 ", request_size %" PRIu64,
                    hstate->last_request_data_stamp, request_size);
            SCLogDebug("frame %p/%" PRIi64 " setting len to  %" PRIu64, frame, frame->id,
                    request_size);
            frame->len = (int64_t)request_size;
            /* app-layer-frame-documentation tag end: updating frame->len */
        }
        hstate->request_frame_id = 0;
    }

    SCLogDebug("transaction_cnt %"PRIu64", list_size %"PRIu64,
               hstate->transaction_cnt, HTPStateGetTxCnt(hstate));

    SCLogDebug("HTTP request completed");

    HTPErrorCheckTxRequestFlags(hstate, tx);

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        if (htud->tsflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(htud, NULL, 0, 0, STREAM_TOSERVER);
            htud->tsflags &= ~HTP_FILENAME_SET;
            if (abs_right_edge < (uint64_t)UINT32_MAX) {
                StreamTcpReassemblySetMinInspectDepth(
                        hstate->f->protoctx, STREAM_TOSERVER, (uint32_t)abs_right_edge);
            }
        }
    }

    hstate->last_request_data_stamp = abs_right_edge;
    /* request done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerParserTriggerRawStreamReassembly(hstate->f, STREAM_TOSERVER);
    SCReturnInt(HTP_STATUS_OK);
}

/**
 *  \brief  callback for response to remove the recent received requests
            from the recent_request_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackResponseComplete(const htp_connp_t *connp, htp_tx_t *tx)
{
    SCEnter();

    HtpState *hstate = htp_connp_user_data(connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_STATUS_ERROR);
    }

    /* we have one whole transaction now */
    hstate->transaction_cnt++;

    const uint64_t abs_right_edge =
            hstate->slice->offset + htp_connp_response_data_consumed(hstate->connp);

    if (hstate->response_frame_id > 0) {
        Frame *frame = AppLayerFrameGetById(hstate->f, 1, hstate->response_frame_id);
        if (frame) {
            const uint64_t response_size = abs_right_edge - hstate->last_response_data_stamp;

            SCLogDebug("HTTP response complete: data offset %" PRIu64 ", response_size %" PRIu64,
                    hstate->last_response_data_stamp, response_size);
            SCLogDebug("frame %p/%" PRIi64 " setting len to  %" PRIu64, frame, frame->id,
                    response_size);
            frame->len = (int64_t)response_size;
        }
        hstate->response_frame_id = 0;
    }

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        if (htud->tcflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(htud, NULL, 0, 0, STREAM_TOCLIENT);
            htud->tcflags &= ~HTP_FILENAME_SET;
        }
    }

    /* response done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerParserTriggerRawStreamReassembly(hstate->f, STREAM_TOCLIENT);

    /* handle HTTP CONNECT */
    if (htp_tx_request_method_number(tx) == HTP_METHOD_CONNECT) {
        /* any 2XX status response implies that the connection will become
           a tunnel immediately after this packet (RFC 7230, 3.3.3). */
        if ((htp_tx_response_status_number(tx) >= 200) &&
                (htp_tx_response_status_number(tx) < 300) && (hstate->transaction_cnt == 1)) {
            uint16_t dp = 0;
            if (htp_tx_request_port_number(tx) != -1) {
                dp = (uint16_t)htp_tx_request_port_number(tx);
            }
            // both ALPROTO_HTTP1 and ALPROTO_TLS are normal options
            if (!AppLayerRequestProtocolChange(hstate->f, dp, ALPROTO_UNKNOWN)) {
                HTPSetEvent(
                        hstate, htud, STREAM_TOCLIENT, HTTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE);
            }
        }
    }

    hstate->last_response_data_stamp = abs_right_edge;
    SCReturnInt(HTP_STATUS_OK);
}

static int HTPCallbackRequestLine(const htp_connp_t *connp, htp_tx_t *tx)
{
    HtpTxUserData *tx_ud;
    HtpState *hstate = htp_connp_user_data(connp);

    tx_ud = htp_tx_get_user_data(tx);
    if (unlikely(tx_ud == NULL)) {
        return HTP_STATUS_OK;
    }

    if (htp_tx_flags(tx)) {
        HTPErrorCheckTxRequestFlags(hstate, tx);
    }
    return HTP_STATUS_OK;
}

static int HTPCallbackRequestHeaderData(const htp_connp_t *connp, htp_tx_data_t *tx_data)
{
    void *ptmp;
    const htp_tx_t *tx = htp_tx_data_tx(tx_data);
    if (htp_tx_data_is_empty(tx_data) || tx == NULL)
        return HTP_STATUS_OK;

    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        return HTP_STATUS_OK;
    }
    ptmp = HTPRealloc(tx_ud->request_headers_raw, tx_ud->request_headers_raw_len,
            tx_ud->request_headers_raw_len + htp_tx_data_len(tx_data));
    if (ptmp == NULL) {
        return HTP_STATUS_OK;
    }
    tx_ud->request_headers_raw = ptmp;

    memcpy(tx_ud->request_headers_raw + tx_ud->request_headers_raw_len, htp_tx_data_data(tx_data),
            htp_tx_data_len(tx_data));
    tx_ud->request_headers_raw_len += htp_tx_data_len(tx_data);

    if (tx && htp_tx_flags(tx)) {
        HtpState *hstate = htp_connp_user_data(connp);
        HTPErrorCheckTxRequestFlags(hstate, tx);
    }
    return HTP_STATUS_OK;
}

static int HTPCallbackResponseHeaderData(const htp_connp_t *connp, htp_tx_data_t *tx_data)
{
    void *ptmp;
    const htp_tx_t *tx = htp_tx_data_tx(tx_data);
    if (htp_tx_data_is_empty(tx_data) || tx == NULL)
        return HTP_STATUS_OK;

    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        return HTP_STATUS_OK;
    }
    ptmp = HTPRealloc(tx_ud->response_headers_raw, tx_ud->response_headers_raw_len,
            tx_ud->response_headers_raw_len + htp_tx_data_len(tx_data));
    if (ptmp == NULL) {
        return HTP_STATUS_OK;
    }
    tx_ud->response_headers_raw = ptmp;

    memcpy(tx_ud->response_headers_raw + tx_ud->response_headers_raw_len, htp_tx_data_data(tx_data),
            htp_tx_data_len(tx_data));
    tx_ud->response_headers_raw_len += htp_tx_data_len(tx_data);

    return HTP_STATUS_OK;
}

/*
 * We have a similar set function called HTPConfigSetDefaultsPhase1.
 */
static void HTPConfigSetDefaultsPhase1(HTPCfgRec *cfg_prec)
{
    htp_config_set_normalized_uri_include_all(cfg_prec->cfg, false);
    cfg_prec->request.body_limit = HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT;
    cfg_prec->response.body_limit = HTP_CONFIG_DEFAULT_RESPONSE_BODY_LIMIT;
    cfg_prec->request.inspect_min_size = HTP_CONFIG_DEFAULT_REQUEST_INSPECT_MIN_SIZE;
    cfg_prec->request.inspect_window = HTP_CONFIG_DEFAULT_REQUEST_INSPECT_WINDOW;
    cfg_prec->response.inspect_min_size = HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_MIN_SIZE;
    cfg_prec->response.inspect_window = HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_WINDOW;

    if (!g_disable_randomness) {
        cfg_prec->randomize = HTP_CONFIG_DEFAULT_RANDOMIZE;
    } else {
        cfg_prec->randomize = 0;
    }
    cfg_prec->randomize_range = HTP_CONFIG_DEFAULT_RANDOMIZE_RANGE;

    htp_config_register_request_header_data(cfg_prec->cfg, HTPCallbackRequestHeaderData);
    htp_config_register_request_trailer_data(cfg_prec->cfg, HTPCallbackRequestHeaderData);
    htp_config_register_response_header_data(cfg_prec->cfg, HTPCallbackResponseHeaderData);
    htp_config_register_response_trailer_data(cfg_prec->cfg, HTPCallbackResponseHeaderData);

    htp_config_register_request_trailer(cfg_prec->cfg, HTPCallbackRequestHasTrailer);
    htp_config_register_response_trailer(cfg_prec->cfg, HTPCallbackResponseHasTrailer);

    htp_config_register_request_body_data(cfg_prec->cfg, HTPCallbackRequestBodyData);
    htp_config_register_response_body_data(cfg_prec->cfg, HTPCallbackResponseBodyData);

    htp_config_register_request_start(cfg_prec->cfg, HTPCallbackRequestStart);
    htp_config_register_request_complete(cfg_prec->cfg, HTPCallbackRequestComplete);

    htp_config_register_response_start(cfg_prec->cfg, HTPCallbackResponseStart);
    htp_config_register_response_complete(cfg_prec->cfg, HTPCallbackResponseComplete);

    htp_config_set_parse_request_cookies(cfg_prec->cfg, 0);
    htp_config_set_allow_space_uri(cfg_prec->cfg, 1);

    /* don't convert + to space by default */
    htp_config_set_plusspace_decode(cfg_prec->cfg, 0);
    // enables request decompression
    htp_config_set_request_decompression(cfg_prec->cfg, 1);
    htp_config_set_lzma_layers(cfg_prec->cfg, HTP_CONFIG_DEFAULT_LZMA_LAYERS);
    htp_config_set_lzma_memlimit(cfg_prec->cfg, HTP_CONFIG_DEFAULT_LZMA_MEMLIMIT);
    htp_config_set_compression_bomb_limit(cfg_prec->cfg, HTP_CONFIG_DEFAULT_COMPRESSION_BOMB_LIMIT);
    htp_config_set_compression_time_limit(cfg_prec->cfg, HTP_CONFIG_DEFAULT_COMPRESSION_TIME_LIMIT);
#define HTP_CONFIG_DEFAULT_MAX_TX_LIMIT 512
    htp_config_set_max_tx(cfg_prec->cfg, HTP_CONFIG_DEFAULT_MAX_TX_LIMIT);
#define HTP_CONFIG_DEFAULT_HEADERS_LIMIT 1024
    htp_config_set_number_headers_limit(cfg_prec->cfg, HTP_CONFIG_DEFAULT_HEADERS_LIMIT);
    htp_config_set_field_limit(cfg_prec->cfg, (size_t)HTP_CONFIG_DEFAULT_FIELD_LIMIT);
}

/* hack: htp random range code expects random values in range of 0-RAND_MAX,
 * but we can get both <0 and >RAND_MAX values from RandomGet
 */
static int RandomGetWrap(void)
{
    unsigned long r;

    do {
        r = RandomGet();
    } while(r >= ULONG_MAX - (ULONG_MAX % RAND_MAX));

    return r % RAND_MAX;
}

/*
 * We have this splitup so that in case double decoding has been enabled
 * for query and path, they would be called first on the callback queue,
 * before the callback set by Phase2() is called.  We need this, since
 * the callback in Phase2() generates the normalized uri which utilizes
 * the query and path. */
static void HTPConfigSetDefaultsPhase2(const char *name, HTPCfgRec *cfg_prec)
{
    /* randomize inspection size if needed */
    if (cfg_prec->randomize) {
        int rdrange = cfg_prec->randomize_range;

        long int r = RandomGetWrap();
        cfg_prec->request.inspect_min_size += (int)(cfg_prec->request.inspect_min_size *
                                                    ((double)r / RAND_MAX - 0.5) * rdrange / 100);

        r = RandomGetWrap();
        cfg_prec->request.inspect_window += (int)(cfg_prec->request.inspect_window *
                                                  ((double)r / RAND_MAX - 0.5) * rdrange / 100);
        SCLogConfig("'%s' server has 'request-body-minimal-inspect-size' set to"
                    " %u and 'request-body-inspect-window' set to %u after"
                    " randomization.",
                name, cfg_prec->request.inspect_min_size, cfg_prec->request.inspect_window);

        r = RandomGetWrap();
        cfg_prec->response.inspect_min_size += (int)(cfg_prec->response.inspect_min_size *
                                                     ((double)r / RAND_MAX - 0.5) * rdrange / 100);

        r = RandomGetWrap();
        cfg_prec->response.inspect_window += (int)(cfg_prec->response.inspect_window *
                                                   ((double)r / RAND_MAX - 0.5) * rdrange / 100);

        SCLogConfig("'%s' server has 'response-body-minimal-inspect-size' set to"
                    " %u and 'response-body-inspect-window' set to %u after"
                    " randomization.",
                name, cfg_prec->response.inspect_min_size, cfg_prec->response.inspect_window);
    }

    htp_config_register_request_line(cfg_prec->cfg, HTPCallbackRequestLine);
}

static void HTPConfigParseParameters(HTPCfgRec *cfg_prec, ConfNode *s,
                                     SCRadixTree *tree)
{
    if (cfg_prec == NULL || s == NULL || tree == NULL)
        return;

    ConfNode *p = NULL;

    /* Default Parameters */
    TAILQ_FOREACH(p, &s->head, next) {

        if (strcasecmp("address", p->name) == 0) {
            ConfNode *pval;
            /* Addresses */
            TAILQ_FOREACH(pval, &p->head, next) {
                SCLogDebug("LIBHTP server %s: %s=%s", s->name, p->name,
                           pval->val);

                /* IPV6 or IPV4? */
                if (strchr(pval->val, ':') != NULL) {
                    SCLogDebug("LIBHTP adding ipv6 server %s at %s: %p",
                               s->name, pval->val, cfg_prec->cfg);
                    if (!SCRadixAddKeyIPV6String(pval->val, tree, cfg_prec)) {
                        SCLogWarning("LIBHTP failed to "
                                     "add ipv6 server %s, ignoring",
                                pval->val);
                    }
                } else {
                    SCLogDebug("LIBHTP adding ipv4 server %s at %s: %p",
                               s->name, pval->val, cfg_prec->cfg);
                    if (!SCRadixAddKeyIPV4String(pval->val, tree, cfg_prec)) {
                        SCLogWarning("LIBHTP failed "
                                     "to add ipv4 server %s, ignoring",
                                pval->val);
                    }
                } /* else - if (strchr(pval->val, ':') != NULL) */
            } /* TAILQ_FOREACH(pval, &p->head, next) */

        } else if (strcasecmp("personality", p->name) == 0) {
            /* Personalities */
            int personality = HTPLookupPersonality(p->val);
            SCLogDebug("LIBHTP default: %s = %s", p->name, p->val);
            SCLogDebug("LIBHTP default: %s = %s", p->name, p->val);

            if (personality >= 0) {
                SCLogDebug("LIBHTP default: %s=%s (%d)", p->name, p->val,
                           personality);
                if (htp_config_set_server_personality(cfg_prec->cfg, personality) ==
                        HTP_STATUS_ERROR) {
                    SCLogWarning("LIBHTP Failed adding "
                                 "personality \"%s\", ignoring",
                            p->val);
                } else {
                    SCLogDebug("LIBHTP personality set to %s",
                               HTPLookupPersonalityString(personality));
                }

                /* The IDS personality by default converts the path (and due to
                 * our query string callback also the query string) to lowercase.
                 * Signatures do not expect this, so override it. */
                htp_config_set_convert_lowercase(cfg_prec->cfg, 0);
            } else {
                SCLogWarning("LIBHTP Unknown personality "
                             "\"%s\", ignoring",
                        p->val);
                continue;
            }

        } else if (strcasecmp("request-body-limit", p->name) == 0 ||
                   strcasecmp("request_body_limit", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request.body_limit) < 0) {
                SCLogError("Error parsing request-body-limit "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("response-body-limit", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response.body_limit) < 0) {
                SCLogError("Error parsing response-body-limit "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("request-body-minimal-inspect-size", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request.inspect_min_size) < 0) {
                SCLogError("Error parsing request-body-minimal-inspect-size "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("request-body-inspect-window", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request.inspect_window) < 0) {
                SCLogError("Error parsing request-body-inspect-window "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("double-decode-query", p->name) == 0) {
            htp_config_set_double_decode_normalized_query(cfg_prec->cfg, ConfValIsTrue(p->val));

        } else if (strcasecmp("double-decode-path", p->name) == 0) {
            htp_config_set_double_decode_normalized_path(cfg_prec->cfg, ConfValIsTrue(p->val));

        } else if (strcasecmp("response-body-minimal-inspect-size", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response.inspect_min_size) < 0) {
                SCLogError("Error parsing response-body-minimal-inspect-size "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("response-body-inspect-window", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response.inspect_window) < 0) {
                SCLogError("Error parsing response-body-inspect-window "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("response-body-decompress-layer-limit", p->name) == 0) {
            uint32_t value = 2;
            if (ParseSizeStringU32(p->val, &value) < 0) {
                SCLogError("Error parsing response-body-inspect-window "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }
            htp_config_set_decompression_layer_limit(cfg_prec->cfg, value);
        } else if (strcasecmp("path-convert-backslash-separators", p->name) == 0) {
            htp_config_set_backslash_convert_slashes(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-bestfit-replacement-char", p->name) == 0) {
            if (strlen(p->val) == 1) {
                htp_config_set_bestfit_replacement_byte(cfg_prec->cfg, p->val[0]);
            } else {
                SCLogError("Invalid entry "
                           "for libhtp param path-bestfit-replacement-char");
            }
        } else if (strcasecmp("path-convert-lowercase", p->name) == 0) {
            htp_config_set_convert_lowercase(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-nul-encoded-terminates", p->name) == 0) {
            htp_config_set_nul_encoded_terminates(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-nul-raw-terminates", p->name) == 0) {
            htp_config_set_nul_raw_terminates(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-separators-compress", p->name) == 0) {
            htp_config_set_path_separators_compress(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-separators-decode", p->name) == 0) {
            htp_config_set_path_separators_decode(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-u-encoding-decode", p->name) == 0) {
            htp_config_set_u_encoding_decode(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("path-url-encoding-invalid-handling", p->name) == 0) {
            enum htp_url_encoding_handling_t handling;
            if (strcasecmp(p->val, "preserve_percent") == 0) {
                handling = HTP_URL_ENCODING_HANDLING_PRESERVE_PERCENT;
            } else if (strcasecmp(p->val, "remove_percent") == 0) {
                handling = HTP_URL_ENCODING_HANDLING_REMOVE_PERCENT;
            } else if (strcasecmp(p->val, "decode_invalid") == 0) {
                handling = HTP_URL_ENCODING_HANDLING_PROCESS_INVALID;
            } else {
                SCLogError("Invalid entry "
                           "for libhtp param path-url-encoding-invalid-handling");
                return;
            }
            htp_config_set_url_encoding_invalid_handling(cfg_prec->cfg, handling);
        } else if (strcasecmp("path-utf8-convert-bestfit", p->name) == 0) {
            htp_config_set_utf8_convert_bestfit(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("uri-include-all", p->name) == 0) {
            htp_config_set_normalized_uri_include_all(cfg_prec->cfg, ConfValIsTrue(p->val));
            SCLogDebug("uri-include-all %s", ConfValIsTrue(p->val) ? "enabled" : "disabled");
        } else if (strcasecmp("query-plusspace-decode", p->name) == 0) {
            htp_config_set_plusspace_decode(cfg_prec->cfg, ConfValIsTrue(p->val));
        } else if (strcasecmp("meta-field-limit", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                SCLogError("Error meta-field-limit "
                           "from conf file - %s.  Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }
            if (limit == 0) {
                FatalError("Error meta-field-limit "
                           "from conf file cannot be 0.  Killing engine");
            }
            /* set default soft-limit with our new hard limit */
            htp_config_set_field_limit(cfg_prec->cfg, (size_t)limit);
        } else if (strcasecmp("lzma-memlimit", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                FatalError("failed to parse 'lzma-memlimit' "
                           "from conf file - %s.",
                        p->val);
            }
            if (limit == 0) {
                FatalError("'lzma-memlimit' "
                           "from conf file cannot be 0.");
            }
            /* set default soft-limit with our new hard limit */
            SCLogConfig("Setting HTTP LZMA memory limit to %"PRIu32" bytes", limit);
            htp_config_set_lzma_memlimit(cfg_prec->cfg, (size_t)limit);
        } else if (strcasecmp("lzma-enabled", p->name) == 0) {
            if (ConfValIsTrue(p->val)) {
                htp_config_set_lzma_layers(cfg_prec->cfg, 1);
            } else if (!ConfValIsFalse(p->val)) {
                int8_t limit;
                if (StringParseInt8(&limit, 10, 0, (const char *)p->val) < 0) {
                    FatalError("failed to parse 'lzma-enabled' "
                               "from conf file - %s.",
                            p->val);
                }
                SCLogConfig("Setting HTTP LZMA decompression layers to %" PRIu32 "", (int)limit);
                htp_config_set_lzma_layers(cfg_prec->cfg, limit);
            }
        } else if (strcasecmp("compression-bomb-limit", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                FatalError("failed to parse 'compression-bomb-limit' "
                           "from conf file - %s.",
                        p->val);
            }
            if (limit == 0) {
                FatalError("'compression-bomb-limit' "
                           "from conf file cannot be 0.");
            }
            /* set default soft-limit with our new hard limit */
            SCLogConfig("Setting HTTP compression bomb limit to %"PRIu32" bytes", limit);
            htp_config_set_compression_bomb_limit(cfg_prec->cfg, (size_t)limit);
        } else if (strcasecmp("decompression-time-limit", p->name) == 0) {
            uint32_t limit = 0;
            // between 1 usec and 1 second
            if (StringParseU32RangeCheck(&limit, 10, 0, p->val, 1, 1000000) < 0) {
                FatalError("failed to parse 'decompression-time-limit' "
                           "from conf file - %s.",
                        p->val);
            }
            SCLogConfig("Setting HTTP decompression time limit to %" PRIu32 " usec", limit);
            htp_config_set_compression_time_limit(cfg_prec->cfg, limit);
        } else if (strcasecmp("max-tx", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                FatalError("failed to parse 'max-tx' "
                           "from conf file - %s.",
                        p->val);
            }
            /* set default soft-limit with our new hard limit */
            SCLogConfig("Setting HTTP max-tx limit to %" PRIu32 " bytes", limit);
            htp_config_set_max_tx(cfg_prec->cfg, limit);
        } else if (strcasecmp("headers-limit", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                FatalError("failed to parse 'headers-limit' "
                           "from conf file - %s.",
                        p->val);
            }
            SCLogConfig("Setting HTTP headers limit to %" PRIu32, limit);
            htp_config_set_number_headers_limit(cfg_prec->cfg, limit);
        } else if (strcasecmp("randomize-inspection-sizes", p->name) == 0) {
            if (!g_disable_randomness) {
                cfg_prec->randomize = ConfValIsTrue(p->val);
            }
        } else if (strcasecmp("randomize-inspection-range", p->name) == 0) {
            uint32_t range;
            if (StringParseU32RangeCheck(&range, 10, 0,
                                         (const char *)p->val, 0, 100) < 0) {
                SCLogError("Invalid value for randomize"
                           "-inspection-range setting from conf file - \"%s\"."
                           " It should be a valid integer less than or equal to 100."
                           " Killing engine",
                        p->val);
                exit(EXIT_FAILURE);
            }
            cfg_prec->randomize_range = range;
        } else if (strcasecmp("http-body-inline", p->name) == 0) {
            if (ConfValIsTrue(p->val)) {
                cfg_prec->http_body_inline = 1;
            } else if (ConfValIsFalse(p->val)) {
                cfg_prec->http_body_inline = 0;
            } else {
                if (strcmp("auto", p->val) != 0) {
                    WarnInvalidConfEntry("http_body_inline", "%s", "auto");
                }
                if (EngineModeIsIPS()) {
                    cfg_prec->http_body_inline = 1;
                } else {
                    cfg_prec->http_body_inline = 0;
                }
            }
        } else if (strcasecmp("swf-decompression", p->name) == 0) {
            ConfNode *pval;

            TAILQ_FOREACH(pval, &p->head, next) {
                if (strcasecmp("enabled", pval->name) == 0) {
                    if (ConfValIsTrue(pval->val)) {
                        cfg_prec->swf_decompression_enabled = 1;
                    } else if (ConfValIsFalse(pval->val)) {
                        cfg_prec->swf_decompression_enabled = 0;
                    } else {
                        WarnInvalidConfEntry("swf-decompression.enabled", "%s", "no");
                    }
                } else if (strcasecmp("type", pval->name) == 0) {
                    if (strcasecmp("no", pval->val) == 0) {
                        cfg_prec->swf_compression_type = HTTP_SWF_COMPRESSION_NONE;
                    } else if (strcasecmp("deflate", pval->val) == 0) {
                        cfg_prec->swf_compression_type = HTTP_SWF_COMPRESSION_ZLIB;
                    } else if (strcasecmp("lzma", pval->val) == 0) {
                        cfg_prec->swf_compression_type = HTTP_SWF_COMPRESSION_LZMA;
                    } else if (strcasecmp("both", pval->val) == 0) {
                        cfg_prec->swf_compression_type = HTTP_SWF_COMPRESSION_BOTH;
                    } else {
                        SCLogError("Invalid entry for "
                                   "swf-decompression.type: %s - "
                                   "Killing engine",
                                pval->val);
                        exit(EXIT_FAILURE);
                    }
                } else if (strcasecmp("compress-depth", pval->name) == 0) {
                    if (ParseSizeStringU32(pval->val, &cfg_prec->swf_compress_depth) < 0) {
                        SCLogError("Error parsing swf-decompression.compression-depth "
                                   "from conf file - %s. Killing engine",
                                p->val);
                        exit(EXIT_FAILURE);
                    }
                } else if (strcasecmp("decompress-depth", pval->name) == 0) {
                    if (ParseSizeStringU32(pval->val, &cfg_prec->swf_decompress_depth) < 0) {
                        SCLogError("Error parsing swf-decompression.decompression-depth "
                                   "from conf file - %s. Killing engine",
                                p->val);
                        exit(EXIT_FAILURE);
                    }
                } else {
                    SCLogWarning("Ignoring unknown param %s", pval->name);
                }
            }
        } else {
            SCLogWarning("LIBHTP Ignoring unknown "
                         "default config: %s",
                    p->name);
        }
    } /* TAILQ_FOREACH(p, &default_config->head, next) */
}

void HTPConfigure(void)
{
    SCEnter();

    cfglist.next = NULL;

    htp_sbcfg.Calloc = HTPCalloc;
    htp_sbcfg.Realloc = HTPRealloc;
    htp_sbcfg.Free = HTPFree;

    cfgtree = SCRadixCreateRadixTree(NULL, NULL);
    if (NULL == cfgtree)
        exit(EXIT_FAILURE);

    /* Default Config */
    cfglist.cfg = htp_config_create();
    if (NULL == cfglist.cfg) {
        FatalError("Failed to create HTP default config");
    }
    SCLogDebug("LIBHTP default config: %p", cfglist.cfg);
    HTPConfigSetDefaultsPhase1(&cfglist);
    if (ConfGetNode("app-layer.protocols.http.libhtp") == NULL) {
        HTPConfigParseParameters(&cfglist, ConfGetNode("libhtp.default-config"),
                                 cfgtree);
    } else {
        HTPConfigParseParameters(&cfglist, ConfGetNode("app-layer.protocols.http.libhtp.default-config"), cfgtree);
    }
    HTPConfigSetDefaultsPhase2("default", &cfglist);

    HTPParseMemcap();

    /* Read server config and create a parser for each IP in radix tree */
    ConfNode *server_config = ConfGetNode("app-layer.protocols.http.libhtp.server-config");
    if (server_config == NULL) {
        server_config = ConfGetNode("libhtp.server-config");
        if (server_config == NULL) {
            SCLogDebug("LIBHTP Configuring %p", server_config);
            SCReturn;
        }
    }
    SCLogDebug("LIBHTP Configuring %p", server_config);

    ConfNode *si;
    /* Server Nodes */
    TAILQ_FOREACH(si, &server_config->head, next) {
        /* Need the named node, not the index */
        ConfNode *s = TAILQ_FIRST(&si->head);
        if (NULL == s) {
            SCLogDebug("LIBHTP s NULL");
            continue;
        }

        SCLogDebug("LIBHTP server %s", s->name);

        HTPCfgRec *nextrec = cfglist.next;
        HTPCfgRec *htprec = SCCalloc(1, sizeof(HTPCfgRec));
        if (NULL == htprec)
            exit(EXIT_FAILURE);

        cfglist.next = htprec;

        cfglist.next->next = nextrec;
        cfglist.next->cfg = htp_config_create();
        if (NULL == cfglist.next->cfg) {
            FatalError("Failed to create HTP server config");
        }

        HTPConfigSetDefaultsPhase1(htprec);
        HTPConfigParseParameters(htprec, s, cfgtree);
        HTPConfigSetDefaultsPhase2(s->name, htprec);
    }

    SCReturn;
}

void AppLayerHtpPrintStats(void)
{
#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    SCLogPerf("htp memory %"PRIu64" (%"PRIu64")", htp_state_memuse, htp_state_memcnt);
    SCMutexUnlock(&htp_state_mem_lock);
#endif
}

/** \internal
 *  \brief get files callback
 *  \param state state ptr
 *  \param direction flow direction
 *  \retval files files ptr
 */
static AppLayerGetFileState HTPGetTxFiles(void *txv, uint8_t direction)
{
    AppLayerGetFileState files = { .fc = NULL, .cfg = &htp_sbcfg };
    htp_tx_t *tx = (htp_tx_t *)txv;
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    if (tx_ud) {
        if (direction & STREAM_TOCLIENT) {
            files.fc = &tx_ud->files_tc;
        } else {
            files.fc = &tx_ud->files_ts;
        }
    }
    return files;
}

static int HTPStateGetAlstateProgress(void *tx, uint8_t direction)
{
    if (direction & STREAM_TOSERVER)
        return htp_tx_request_progress((htp_tx_t *)tx);
    else
        return htp_tx_response_progress((htp_tx_t *)tx);
}

static uint64_t HTPStateGetTxCnt(void *alstate)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->connp != NULL) {
        const int64_t size = htp_connp_tx_size(http_state->connp);
        if (size < 0)
            return 0ULL;
        SCLogDebug("size %"PRIu64, size);
        return (uint64_t)size;
    } else {
        return 0ULL;
    }
}

static void *HTPStateGetTx(void *alstate, uint64_t tx_id)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->connp != NULL)
        return (void *)htp_connp_tx(http_state->connp, tx_id);
    else
        return NULL;
}

void *HtpGetTxForH2(void *alstate)
{
    // gets last transaction
    HtpState *http_state = (HtpState *)alstate;
    if (http_state != NULL && http_state->connp != NULL) {
        size_t txid = htp_connp_tx_size(http_state->connp);
        if (txid > 0) {
            return (void *)htp_connp_tx(http_state->connp, txid - 1);
        }
    }
    return NULL;
}

static int HTPStateGetEventInfo(
        const char *event_name, uint8_t *event_id, AppLayerEventType *event_type)
{
    if (SCAppLayerGetEventIdByName(event_name, http_decoder_event_table, event_id) == 0) {
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        return 0;
    }
    return -1;
}

static int HTPStateGetEventInfoById(
        uint8_t event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, http_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "http's enum map table.",
                event_id);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppLayerTxData *HTPGetTxData(void *vtx)
{
    htp_tx_t *tx = (htp_tx_t *)vtx;
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    if (tx_ud) {
        return &tx_ud->tx_data;
    }
    return NULL;
}

static AppLayerStateData *HTPGetStateData(void *vstate)
{
    HtpState *s = vstate;
    return &s->state_data;
}

static int HTPRegisterPatternsForProtocolDetection(void)
{
    const char *methods[] = { "GET", "PUT", "POST", "HEAD", "TRACE", "OPTIONS",
        "CONNECT", "DELETE", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL",
        "COPY", "MOVE", "LOCK", "UNLOCK", "CHECKOUT", "UNCHECKOUT", "CHECKIN",
        "UPDATE", "LABEL", "REPORT", "MKWORKSPACE", "MKACTIVITY", "MERGE",
        "INVALID", "VERSION-CONTROL", "BASELINE-CONTROL", NULL};
    const char *spacings[] = { "|20|", "|09|", NULL };
    const char *versions[] = { "HTTP/0.9", "HTTP/1.0", "HTTP/1.1", NULL };

    int methods_pos;
    int spacings_pos;
    int versions_pos;
    int register_result;
    char method_buffer[32] = "";

    /* Loop through all the methods ands spacings and register the patterns */
    for (methods_pos = 0; methods[methods_pos]; methods_pos++) {
        for (spacings_pos = 0; spacings[spacings_pos]; spacings_pos++) {

            /* Combine the method name and the spacing */
            snprintf(method_buffer, sizeof(method_buffer), "%s%s", methods[methods_pos], spacings[spacings_pos]);

            /* Register the new method+spacing pattern
             * 3 is subtracted from the length since the spacing is hex typed as |xx|
             * but the pattern matching should only be one char
            */
            register_result = AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_HTTP1,
                    method_buffer, (uint16_t)strlen(method_buffer) - 3, 0, STREAM_TOSERVER);
            if (register_result < 0) {
                return -1;
            }
        }
    }

    /* Loop through all the http version patterns that are TO_CLIENT */
    for (versions_pos = 0; versions[versions_pos]; versions_pos++) {
        register_result = AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_HTTP1,
                versions[versions_pos], (uint16_t)strlen(versions[versions_pos]), 0,
                STREAM_TOCLIENT);
        if (register_result < 0) {
            return -1;
        }
    }

    return 0;
}

/**
 *  \brief  Register the HTTP protocol and state handling functions to APP layer
 *          of the engine.
 */
void RegisterHTPParsers(void)
{
    SCEnter();

    const char *proto_name = "http";

    /** HTTP */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_HTTP1, proto_name);
        if (HTPRegisterPatternsForProtocolDetection() < 0)
            return;
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_HTTP1, HTPStateAlloc, HTPStateFree);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_HTTP1, HTPStateTransactionFree);
        AppLayerParserRegisterGetTxFilesFunc(IPPROTO_TCP, ALPROTO_HTTP1, HTPGetTxFiles);
        AppLayerParserRegisterGetStateProgressFunc(
                IPPROTO_TCP, ALPROTO_HTTP1, HTPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP1, HTPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_HTTP1, HTPStateGetTx);

        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_HTTP1, HTP_REQUEST_PROGRESS_COMPLETE, HTP_RESPONSE_PROGRESS_COMPLETE);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_HTTP1, HTPStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(
                IPPROTO_TCP, ALPROTO_HTTP1, HTPStateGetEventInfoById);

        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_HTTP1, HTPGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_HTTP1, HTPGetStateData);

        AppLayerParserRegisterSetStreamDepthFlag(
                IPPROTO_TCP, ALPROTO_HTTP1, AppLayerHtpSetStreamDepthFlag);

        AppLayerParserRegisterParser(
                IPPROTO_TCP, ALPROTO_HTTP1, STREAM_TOSERVER, HTPHandleRequestData);
        AppLayerParserRegisterParser(
                IPPROTO_TCP, ALPROTO_HTTP1, STREAM_TOCLIENT, HTPHandleResponseData);
        SC_ATOMIC_INIT(htp_config_flags);
        /* This parser accepts gaps. */
        AppLayerParserRegisterOptionFlags(
                IPPROTO_TCP, ALPROTO_HTTP1, APP_LAYER_PARSER_OPT_ACCEPT_GAPS);
        AppLayerParserRegisterParserAcceptableDataDirection(
                IPPROTO_TCP, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_TOCLIENT);
        /* app-layer-frame-documentation tag start: registering relevant callbacks */
        AppLayerParserRegisterGetFrameFuncs(
                IPPROTO_TCP, ALPROTO_HTTP1, HTTPGetFrameIdByName, HTTPGetFrameNameById);
        /* app-layer-frame-documentation tag end: registering relevant callbacks */
        HTPConfigure();
    } else {
        SCLogInfo("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_HTTP1, HTPParserRegisterTests);
#endif

    SCReturn;
}

#ifdef UNITTESTS
#include "detect-engine-alert.h"

static HTPCfgRec cfglist_backup;

void HtpConfigCreateBackup(void)
{
    cfglist_backup = cfglist;
}

void HtpConfigRestoreBackup(void)
{
    cfglist = cfglist_backup;
}

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
static int HTPParserTest01(void)
{
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(bstr_cmp_c(htp_header_value(h), "Victor/1.0"));
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_POST);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test folding in 1 read case */
static int HTPParserTest01b(void)
{
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent:\r\n Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint8_t flags =STREAM_TOSERVER|STREAM_START|STREAM_EOF;
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(strcmp(bstr_util_strdup_to_c(htp_header_value(h)), "Victor/1.0"));
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_POST);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test folding in 1byte per read case */
static int HTPParserTest01c(void)
{
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent:\r\n Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */

    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(strcmp(bstr_util_strdup_to_c(htp_header_value(h)), "Victor/1.0"));
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_POST);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
static int HTPParserTest01a(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = " POST  /  HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(strcmp(bstr_util_strdup_to_c(htp_header_value(h)), "Victor/1.0"));
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_POST);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test See how it deals with an incomplete request. */
static int HTPParserTest02(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NOT_NULL(h);

    FAIL_IF_NULL(htp_tx_request_method(tx));
    char *method = bstr_util_strdup_to_c(htp_tx_request_method(tx));
    FAIL_IF_NULL(method);

    FAIL_IF(strcmp(method, "POST") != 0);
    SCFree(method);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test case where method is invalid and data is sent in smaller chunks
 *        and check the response of the parser from HTP library. */
static int HTPParserTest03(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "HELLO / HTTP/1.0\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }
    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NOT_NULL(h);
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_UNKNOWN);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test case where invalid data is sent and check the response of the
 *        parser from HTP library. */
static int HTPParserTest04(void)
{
    Flow *f = NULL;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "World!\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            STREAM_TOSERVER | STREAM_START | STREAM_EOF, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NOT_NULL(h);
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_UNKNOWN);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V0_9);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test both sides of a http stream mixed up to see if the HTP parser
 *        properly parsed them and also keeps them separated. */
static int HTPParserTest05(void)
{
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\nContent-Length: 17\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "Post D";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "ata is c0oL!";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "HTTP/1.0 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "post R";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint8_t httpbuf6[] = "esults are tha bomb!";
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */

    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf4, httplen4);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf5, httplen5);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF, httpbuf6, httplen6);
    FAIL_IF(r != 0);

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    FAIL_IF_NOT(htp_tx_request_method_number(tx) == HTP_METHOD_POST);
    FAIL_IF_NOT(htp_tx_request_protocol_number(tx) == HTP_PROTOCOL_V1_0);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF_NOT(htp_tx_response_status_number(tx) == 200);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test proper chunked encoded response body
 */
static int HTPParserTest06(void)
{
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\nDate: Sat, 03 Oct 2009 10:16:02 "
                         "GMT\r\n"
                         "Server: Apache/1.3.37 (Unix) mod_ssl/2.8.28 "
                         "OpenSSL/0.9.7a PHP/4.4.7 mod_perl/1.29 "
                         "FrontPage/5.0.2.2510\r\n"
                         "X-Powered-By: PHP/4.4.7\r\nTransfer-Encoding: "
                         "chunked\r\n"
                         "Content-Type: text/html\r\n\r\n"
                         "580\r\n"
                         "W2dyb3VwMV0NCnBob25lMT1wMDB3ODgyMTMxMzAyMTINCmxvZ2lu"
                         "MT0NCnBhc3N3b3JkMT0NCnBob25lMj1wMDB3ODgyMTMxMzAyMTIN"
                         "CmxvZ2luMj0NCnBhc3N3b3JkMj0NCnBob25lMz0NCmxvZ2luMz0N"
                         "CnBhc3N3b3JkMz0NCnBob25lND0NCmxvZ2luND0NCnBhc3N3b3Jk"
                         "ND0NCnBob25lNT0NCmxvZ2luNT0NCnBhc3N3b3JkNT0NCnBob25l"
                         "Nj0NCmxvZ2luNj0NCnBhc3N3b3JkNj0NCmNhbGxfdGltZTE9MzIN"
                         "CmNhbGxfdGltZTI9MjMyDQpkYXlfbGltaXQ9NQ0KbW9udGhfbGlt"
                         "aXQ9MTUNCltncm91cDJdDQpwaG9uZTE9DQpsb2dpbjE9DQpwYXNz"
                         "d29yZDE9DQpwaG9uZTI9DQpsb2dpbjI9DQpwYXNzd29yZDI9DQpw"
                         "aG9uZTM9DQpsb2dpbjM9DQpwYXNzd29yZDM9DQpwaG9uZTQ9DQps"
                         "b2dpbjQ9DQpwYXNzd29yZDQ9DQpwaG9uZTU9DQpsb2dpbjU9DQpw"
                         "YXNzd29yZDU9DQpwaG9uZTY9DQpsb2dpbjY9DQpwYXNzd29yZDY9"
                         "DQpjYWxsX3RpbWUxPQ0KY2FsbF90aW1lMj0NCmRheV9saW1pdD0N"
                         "Cm1vbnRoX2xpbWl0PQ0KW2dyb3VwM10NCnBob25lMT0NCmxvZ2lu"
                         "MT0NCnBhc3N3b3JkMT0NCnBob25lMj0NCmxvZ2luMj0NCnBhc3N3"
                         "b3JkMj0NCnBob25lMz0NCmxvZ2luMz0NCnBhc3N3b3JkMz0NCnBo"
                         "b25lND0NCmxvZ2luND0NCnBhc3N3b3JkND0NCnBob25lNT0NCmxv"
                         "Z2luNT0NCnBhc3N3b3JkNT0NCnBob25lNj0NCmxvZ2luNj0NCnBh"
                         "c3N3b3JkNj0NCmNhbGxfdGltZTE9DQpjYWxsX3RpbWUyPQ0KZGF5"
                         "X2xpbWl0PQ0KbW9udGhfbGltaXQ9DQpbZ3JvdXA0XQ0KcGhvbmUx"
                         "PQ0KbG9naW4xPQ0KcGFzc3dvcmQxPQ0KcGhvbmUyPQ0KbG9naW4y"
                         "PQ0KcGFzc3dvcmQyPQ0KcGhvbmUzPQ0KbG9naW4zPQ0KcGFzc3dv"
                         "cmQzPQ0KcGhvbmU0PQ0KbG9naW40PQ0KcGFzc3dvcmQ0PQ0KcGhv"
                         "bmU1PQ0KbG9naW41PQ0KcGFzc3dvcmQ1PQ0KcGhvbmU2PQ0KbG9n"
                         "aW42PQ0KcGFzc3dvcmQ2PQ0KY2FsbF90aW1lMT0NCmNhbGxfdGlt"
                         "ZTI9DQpkYXlfbGltaXQ9DQptb250aF9saW1pdD0NCltmaWxlc10N"
                         "Cmxpbms9aHR0cDovLzIwOS4yMDUuMTk2LjE2L2xkL2dldGJvdC5w"
                         "aHA=\r\n0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != 200);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test
 */
static int HTPParserTest07(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /awstats.pl?/migratemigrate%20=%20| HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref[] = "/awstats.pl?/migratemigrate = |";
    size_t reflen = sizeof(ref) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

#include "conf-yaml-loader.h"

/** \test Abort
 */
static int HTPParserTest08(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /secondhouse/image/js/\%ce\%de\%ce\%fd_RentCity.js?v=2011.05.02 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    HtpState *htp_state = NULL;
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint8_t flags = STREAM_TOSERVER | STREAM_START | STREAM_EOF;

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    PrintRawDataFp(stdout, bstr_ptr(request_uri_normalized), bstr_len(request_uri_normalized));

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    UTHFreeFlow(f);
    PASS;
}

/** \test Abort
 */
static int HTPParserTest09(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /secondhouse/image/js/\%ce\%de\%ce\%fd_RentCity.js?v=2011.05.02 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: Apache_2_2\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    HtpState *htp_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint8_t flags = STREAM_TOSERVER | STREAM_START | STREAM_EOF;

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    PrintRawDataFp(stdout, bstr_ptr(request_uri_normalized), bstr_len(request_uri_normalized));

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    UTHFreeFlow(f);
    PASS;
}

/** \test Host:www.google.com <- missing space between name:value (rfc violation)
 */
static int HTPParserTest10(void)
{

    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nHost:www.google.com\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    char *name = bstr_util_strdup_to_c(htp_header_name(h));
    FAIL_IF_NULL(name);
    FAIL_IF(strcmp(name, "Host") != 0);

    char *value = bstr_util_strdup_to_c(htp_header_value(h));
    FAIL_IF_NULL(value);
    FAIL_IF(strcmp(value, "www.google.com") != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    SCFree(name);
    SCFree(value);
    PASS;
}

/** \test double encoding in path
 */
static int HTPParserTest11(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /%2500 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);

    FAIL_IF(bstr_len(request_uri_normalized) != 4);
    FAIL_IF(bstr_ptr(request_uri_normalized)[0] != '/');
    FAIL_IF(bstr_ptr(request_uri_normalized)[1] != '%');
    FAIL_IF(bstr_ptr(request_uri_normalized)[2] != '0');
    FAIL_IF(bstr_ptr(request_uri_normalized)[3] != '0');

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test double encoding in query
 */
static int HTPParserTest12(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /?a=%2500 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);

    FAIL_IF(bstr_len(request_uri_normalized) != 7);
    FAIL_IF(bstr_ptr(request_uri_normalized)[0] != '/');
    FAIL_IF(bstr_ptr(request_uri_normalized)[1] != '?');
    FAIL_IF(bstr_ptr(request_uri_normalized)[2] != 'a');
    FAIL_IF(bstr_ptr(request_uri_normalized)[3] != '=');
    FAIL_IF(bstr_ptr(request_uri_normalized)[4] != '%');
    FAIL_IF(bstr_ptr(request_uri_normalized)[5] != '0');
    FAIL_IF(bstr_ptr(request_uri_normalized)[6] != '0');

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Host:www.google.com0dName: Value0d0a <- missing space between name:value (rfc violation)
 */
static int HTPParserTest13(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nHost:www.google.com\rName: Value\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);
    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    char *name = bstr_util_strdup_to_c(htp_header_name(h));
    FAIL_IF_NULL(name);
    FAIL_IF(strcmp(name, "Host") != 0);

    char *value = bstr_util_strdup_to_c(htp_header_value(h));
    FAIL_IF_NULL(value);
    FAIL_IF(strcmp(value, "www.google.com\rName: Value") != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    SCFree(name);
    SCFree(value);

    PASS;
}

/** \test Test basic config */
static int HTPParserConfigTest01(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
\n\
  server-config:\n\
\n\
    - apache-tomcat:\n\
        address: [192.168.1.0/24, 127.0.0.0/8, \"::1\"]\n\
        personality: Tomcat_6_0\n\
\n\
    - iis7:\n\
        address: \n\
          - 192.168.0.0/24\n\
          - 192.168.10.0/24\n\
        personality: IIS_7_0\n\
";

    ConfCreateContextBackup();
    ConfInit();

    ConfYamlLoadString(input, strlen(input));

    ConfNode *outputs;
    outputs = ConfGetNode("libhtp.default-config.personality");
    FAIL_IF_NULL(outputs);

    outputs = ConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);

    ConfNode *node = TAILQ_FIRST(&outputs->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "0") != 0);
    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "apache-tomcat") != 0);

    int i = 0;
    ConfNode *n;

    ConfNode *node2 = ConfNodeLookupChild(node, "personality");
    FAIL_IF_NULL(node2);
    FAIL_IF(strcmp(node2->val, "Tomcat_6_0") != 0);

    node = ConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    TAILQ_FOREACH (n, &node->head, next) {
        FAIL_IF_NULL(n);
        switch(i) {
            case 0:
                FAIL_IF(strcmp(n->name, "0") != 0);
                FAIL_IF(strcmp(n->val, "192.168.1.0/24") != 0);
                break;
            case 1:
                FAIL_IF(strcmp(n->name, "1") != 0);
                FAIL_IF(strcmp(n->val, "127.0.0.0/8") != 0);
                break;
            case 2:
                FAIL_IF(strcmp(n->name, "2") != 0);
                FAIL_IF(strcmp(n->val, "::1") != 0);
                break;
            default:
                FAIL;
        }
        i++;
    }

    outputs = ConfGetNode("libhtp.server-config");
    FAIL_IF_NULL(outputs);
    node = TAILQ_FIRST(&outputs->head);
    node = TAILQ_NEXT(node, next);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "1") != 0);
    node = TAILQ_FIRST(&node->head);
    FAIL_IF_NULL(node);
    FAIL_IF(strcmp(node->name, "iis7") != 0);

    node2 = ConfNodeLookupChild(node, "personality");
    FAIL_IF_NULL(node2);
    FAIL_IF(strcmp(node2->val, "IIS_7_0") != 0);

    node = ConfNodeLookupChild(node, "address");
    FAIL_IF_NULL(node);

    i = 0;
    TAILQ_FOREACH(n, &node->head, next) {
        FAIL_IF_NULL(n);

        switch(i) {
            case 0:
                FAIL_IF(strcmp(n->name, "0") != 0);
                FAIL_IF(strcmp(n->val, "192.168.0.0/24") != 0);
                break;
            case 1:
                FAIL_IF(strcmp(n->name, "1") != 0);
                FAIL_IF(strcmp(n->val, "192.168.10.0/24") != 0);
                break;
            default:
                FAIL;
        }
        i++;
    }

    ConfDeInit();
    ConfRestoreContextBackup();

    PASS;
}

/** \test Test config builds radix correctly */
static int HTPParserConfigTest02(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
\n\
  server-config:\n\
\n\
    - apache-tomcat:\n\
        address: [192.168.1.0/24, 127.0.0.0/8, \"::1\"]\n\
        personality: Tomcat_6_0\n\
\n\
    - iis7:\n\
        address: \n\
          - 192.168.0.0/24\n\
          - 192.168.10.0/24\n\
        personality: IIS_7_0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));

    HTPConfigure();

    FAIL_IF_NULL(cfglist.cfg);

    FAIL_IF_NULL(cfgtree);

    htp_cfg_t *htp = cfglist.cfg;
    uint8_t buf[128];
    const char *addr;
    void *user_data = NULL;

    addr = "192.168.10.42";
    FAIL_IF(inet_pton(AF_INET, addr, buf) != 1);
    (void)SCRadixFindKeyIPV4BestMatch(buf, cfgtree, &user_data);
    FAIL_IF_NULL(user_data);
    HTPCfgRec *htp_cfg_rec = user_data;
    htp = htp_cfg_rec->cfg;
    FAIL_IF_NULL(htp);
    SCLogDebug("LIBHTP using config: %p", htp);

    user_data = NULL;
    addr = "::1";
    FAIL_IF(inet_pton(AF_INET6, addr, buf) != 1);
    (void)SCRadixFindKeyIPV6BestMatch(buf, cfgtree, &user_data);
    FAIL_IF_NULL(user_data);
    htp_cfg_rec = user_data;
    htp = htp_cfg_rec->cfg;
    FAIL_IF_NULL(htp);
    SCLogDebug("LIBHTP using config: %p", htp);

    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    PASS;
}

/** \test Test traffic is handled by the correct htp config */
static int HTPParserConfigTest03(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
\n\
  server-config:\n\
\n\
    - apache-tomcat:\n\
        address: [192.168.1.0/24, 127.0.0.0/8, \"::1\"]\n\
        personality: Tomcat_6_0\n\
\n\
    - iis7:\n\
        address: \n\
          - 192.168.0.0/24\n\
          - 192.168.10.0/24\n\
        personality: IIS_7_0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));

    HTPConfigure();

    const char *addr = "192.168.10.42";

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    htp_cfg_t *htp = cfglist.cfg;

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)f->dst.addr_data32, cfgtree, &user_data);
    FAIL_IF_NULL(user_data);
    HTPCfgRec *htp_cfg_rec = user_data;
    htp = htp_cfg_rec->cfg;
    SCLogDebug("LIBHTP using config: %p", htp);

    FAIL_IF_NULL(htp);

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    FAIL_IF(HTPStateGetTxCnt(htp_state) != 2);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    tx = HTPStateGetTx(htp_state, 1);
    FAIL_IF_NULL(tx);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test %2f decoding in profile Apache_2_2
 *
 *        %2f in path is left untouched
 *        %2f in query string is normalized to %2F
 *        %252f in query string is decoded/normalized to %2F
 */
static int HTPParserDecodingTest01(void)
{
    uint8_t httpbuf1[] =
        "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: Apache_2\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    for (uint32_t u = 0; u < httplen1; u++) {
        uint8_t flags = 0;
        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/abc%2fdef";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));
    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    FAIL_IF_NULL(tx);

    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));
    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref2, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref3[] = "/abc/def?ghi%2fjkl";
    reflen = sizeof(ref3) - 1;
    tx = HTPStateGetTx(htp_state, 2);
    FAIL_IF_NULL(tx);

    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));
    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref3, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

static int HTPParserDecodingTest01a(void)
{
    uint8_t httpbuf1[] = "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
                         "GET /abc/def?ghi%2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
                         "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: Apache_2\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1,
            (STREAM_TOSERVER | STREAM_START | STREAM_EOF), httpbuf1, httplen1);
    FAIL_IF(r != 0);

    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/abc%2fdef";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);

    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));
    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    FAIL_IF_NULL(tx);
    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref2, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref3[] = "/abc/def?ghi%2fjkl";
    reflen = sizeof(ref3) - 1;
    tx = HTPStateGetTx(htp_state, 2);
    FAIL_IF_NULL(tx);
    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(tx_ud);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref3, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test %2f decoding in profile IDS
 *
 *        %2f in path decoded to /
 *        %2f in query string is decoded to /
 *        %252f in query string is decoded to %2F
 */
static int HTPParserDecodingTest02(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: no\n\
    double-decode-query: no\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/abc/def";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));
    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    FAIL_IF_NULL(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref2, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref3[] = "/abc/def?ghi%2fjkl";
    reflen = sizeof(ref3) - 1;
    tx = HTPStateGetTx(htp_state, 2);
    FAIL_IF_NULL(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref3, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test %2f decoding in profile IDS with double-decode-* options
 *
 *        %252f in path decoded to /
 *        %252f in query string is decoded to /
 */
static int HTPParserDecodingTest03(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc%252fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: yes\n\
    double-decode-query: yes\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/abc/def";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    FAIL_IF_NULL(tx);
    request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref2, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test http:// in query profile IDS
 */
static int HTPParserDecodingTest04(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc/def?a=http://www.abc.com/ HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: yes\n\
    double-decode-query: yes\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/abc/def?a=http://www.abc.com/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test \ char in query profile IDS. Bug 739
 */
static int HTPParserDecodingTest05(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /index?id=\\\"<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: yes\n\
    double-decode-query: yes\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/index?id=\\\"<script>alert(document.cookie)</script>";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test + char in query. Bug 1035
 */
static int HTPParserDecodingTest06(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /put.php?ip=1.2.3.4&port=+6000 HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: yes\n\
    double-decode-query: yes\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/put.php?ip=1.2.3.4&port=+6000";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test + char in query. Bug 1035
 */
static int HTPParserDecodingTest07(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /put.php?ip=1.2.3.4&port=+6000 HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: yes\n\
    double-decode-query: yes\n\
    query-plusspace-decode: yes\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/put.php?ip=1.2.3.4&port= 6000";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test 'proxy' URI normalization. Ticket 1008
 */
static int HTPParserDecodingTest08(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET http://suricata-ids.org/blah/ HTTP/1.1\r\nHost: suricata-ids.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "/blah/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test 'proxy' URI normalization. Ticket 1008
 */
static int HTPParserDecodingTest09(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET http://suricata-ids.org/blah/ HTTP/1.1\r\nHost: suricata-ids.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    uri-include-all: true\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    const char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, &httpbuf1[u], 1);
        FAIL_IF(r != 0);
    }

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    uint8_t ref1[] = "http://suricata-ids.org/blah/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    bstr *request_uri_normalized = (bstr *)htp_tx_normalized_uri(tx);
    FAIL_IF_NULL(request_uri_normalized);
    FAIL_IF(reflen != bstr_len(request_uri_normalized));

    FAIL_IF(memcmp(bstr_ptr(request_uri_normalized), ref1, bstr_len(request_uri_normalized)) != 0);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test BG box crash -- chunks are messed up. Observed for real. */
static int HTPBodyReassemblyTest01(void)
{
    HtpTxUserData htud;
    memset(&htud, 0x00, sizeof(htud));
    HtpState hstate;
    memset(&hstate, 0x00, sizeof(hstate));
    Flow flow;
    memset(&flow, 0x00, sizeof(flow));
    AppLayerParserState *parser = AppLayerParserStateAlloc();
    htp_cfg_t *cfg = htp_config_create();
    BUG_ON(cfg == NULL);
    htp_connp_t *connp = htp_connp_create(cfg);
    BUG_ON(connp == NULL);
    const htp_tx_t *tx = htp_connp_get_request_tx(connp);
    BUG_ON(tx == NULL);

    hstate.f = &flow;
    flow.alparser = parser;

    uint8_t chunk1[] = "--e5a320f21416a02493a0a6f561b1c494\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"D2GUef.jpg\"\r";
    uint8_t chunk2[] = "POST /uri HTTP/1.1\r\nHost: hostname.com\r\nKeep-Alive: 115\r\nAccept-Charset: utf-8\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:9.0.1) Gecko/20100101 Firefox/9.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: keep-alive\r\nContent-length: 68102\r\nReferer: http://otherhost.com\r\nAccept-Encoding: gzip\r\nContent-Type: multipart/form-data; boundary=e5a320f21416a02493a0a6f561b1c494\r\nCookie: blah\r\nAccept-Language: us\r\n\r\n--e5a320f21416a02493a0a6f561b1c494\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"D2GUef.jpg\"\r";

    int r = HtpBodyAppendChunk(&htud.request_body, chunk1, sizeof(chunk1) - 1);
    BUG_ON(r != 0);
    r = HtpBodyAppendChunk(&htud.request_body, chunk2, sizeof(chunk2) - 1);
    BUG_ON(r != 0);

    const uint8_t *chunks_buffer = NULL;
    uint32_t chunks_buffer_len = 0;

    HtpRequestBodyReassemble(&htud, &chunks_buffer, &chunks_buffer_len);
    FAIL_IF_NULL(chunks_buffer);
#ifdef PRINT
    printf("REASSCHUNK START: \n");
    PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    printf("REASSCHUNK END: \n");
#endif

    htud.mime_state = SCMimeStateInit((const uint8_t *)"multipart/form-data; boundary=toto",
            strlen("multipart/form-data; boundary=toto"));
    FAIL_IF_NULL(htud.mime_state);
    htud.tsflags |= HTP_BOUNDARY_SET;
    HtpRequestBodyHandleMultipart(&hstate, &htud, &tx, chunks_buffer, chunks_buffer_len, false);

    FAIL_IF(htud.request_body.content_len_so_far != 669);

    FAIL_IF_NOT_NULL(htud.files_ts.head);

    PASS;
}

/** \test BG crash */
static int HTPSegvTest01(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST /uri HTTP/1.1\r\nHost: hostname.com\r\nKeep-Alive: 115\r\nAccept-Charset: utf-8\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:9.0.1) Gecko/20100101 Firefox/9.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: keep-alive\r\nContent-length: 68102\r\nReferer: http://otherhost.com\r\nAccept-Encoding: gzip\r\nContent-Type: multipart/form-data; boundary=e5a320f21416a02493a0a6f561b1c494\r\nCookie: blah\r\nAccept-Language: us\r\n\r\n--e5a320f21416a02493a0a6f561b1c494\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"D2GUef.jpg\"\r";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: no\n\
    double-decode-query: no\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);
    SCLogDebug("\n>>>> processing chunk 1 again <<<<\n");
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    AppLayerDecoderEvents *decoder_events = AppLayerParserGetDecoderEvents(f->alparser);
    FAIL_IF_NOT_NULL(decoder_events);

    AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test really long request, this should result in HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG */
static int HTPParserTest14(void)
{
    size_t len = 18887;
    TcpSession ssn;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: no\n\
    double-decode-query: no\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
";
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    char *httpbuf = SCMalloc(len);
    FAIL_IF_NULL(httpbuf);
    memset(httpbuf, 0x00, len);

    /* create the request with a longer than 18k cookie */
    strlcpy(httpbuf, "GET /blah/ HTTP/1.1\r\n"
                     "Host: myhost.lan\r\n"
                     "Connection: keep-alive\r\n"
                     "Accept: */*\r\n"
                     "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.76 Safari/537.36\r\n"
                     "Referer: http://blah.lan/\r\n"
                     "Accept-Encoding: gzip,deflate,sdch\r\nAccept-Language: en-US,en;q=0.8\r\n"
                     "Cookie: ", len);
    size_t o = strlen(httpbuf);
    for ( ; o < len - 4; o++) {
        httpbuf[o] = 'A';
    }
    httpbuf[len - 4] = '\r';
    httpbuf[len - 3] = '\n';
    httpbuf[len - 2] = '\r';
    httpbuf[len - 1] = '\n';

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->alproto = ALPROTO_HTTP1;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < len; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (len - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        (void)AppLayerParserParse(
                NULL, alp_tctx, f, ALPROTO_HTTP1, flags, (uint8_t *)&httpbuf[u], 1);
    }
    HtpState *htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    void *txtmp = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    AppLayerDecoderEvents *decoder_events =
            AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP1, txtmp);
    FAIL_IF_NULL(decoder_events);

    FAIL_IF(decoder_events->events[0] != HTP_LOG_CODE_REQUEST_FIELD_TOO_LONG);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    SCFree(httpbuf);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    PASS;
}

/** \test Test really long request (same as HTPParserTest14), now with config
 *        update to allow it */
static int HTPParserTest15(void)
{
    Flow *f = NULL;
    char *httpbuf = NULL;
    size_t len = 18887;
    TcpSession ssn;
    HtpState *htp_state = NULL;
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    double-decode-path: no\n\
    double-decode-query: no\n\
    request-body-limit: 0\n\
    response-body-limit: 0\n\
    meta-field-limit: 20000\n\
";
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    httpbuf = SCMalloc(len);
    FAIL_IF_NULL(httpbuf);

    memset(httpbuf, 0x00, len);

    /* create the request with a longer than 18k cookie */
    strlcpy(httpbuf, "GET /blah/ HTTP/1.1\r\n"
                     "Host: myhost.lan\r\n"
                     "Connection: keep-alive\r\n"
                     "Accept: */*\r\n"
                     "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.76 Safari/537.36\r\n"
                     "Referer: http://blah.lan/\r\n"
                     "Accept-Encoding: gzip,deflate,sdch\r\nAccept-Language: en-US,en;q=0.8\r\n"
                     "Cookie: ", len);
    size_t o = strlen(httpbuf);
    for ( ; o < len - 4; o++) {
        httpbuf[o] = 'A';
    }
    httpbuf[len - 4] = '\r';
    httpbuf[len - 3] = '\n';
    httpbuf[len - 2] = '\r';
    httpbuf[len - 1] = '\n';

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint32_t u;
    for (u = 0; u < len; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (len - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        int r = AppLayerParserParse(
                NULL, alp_tctx, f, ALPROTO_HTTP1, flags, (uint8_t *)&httpbuf[u], 1);
        FAIL_IF(r != 0);
    }
    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    void *txtmp = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    AppLayerDecoderEvents *decoder_events =
            AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP1, txtmp);
    FAIL_IF_NOT_NULL(decoder_events);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    SCFree(httpbuf);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    PASS;
}

/** \test Test unusual delims in request line HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG */
static int HTPParserTest16(void)
{
    Flow *f = NULL;
    TcpSession ssn;
    HtpState *htp_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    uint8_t httpbuf[] = "GET\f/blah/\fHTTP/1.1\r\n"
                     "Host: myhost.lan\r\n"
                     "Connection: keep-alive\r\n"
                     "Accept: */*\r\n"
                     "User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/29.0.1547.76 Safari/537.36\r\n"
                     "Referer: http://blah.lan/\r\n"
                     "Accept-Encoding: gzip,deflate,sdch\r\nAccept-Language: en-US,en;q=0.8\r\n"
                     "Cookie: blah\r\n\r\n";
    size_t len = sizeof(httpbuf) - 1;

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    uint8_t flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, flags, (uint8_t *)httpbuf, len);
    FAIL_IF(r != 0);

    htp_state = f->alstate;
    FAIL_IF_NULL(htp_state);

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    FAIL_IF_NULL(tx);
    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
//these events are disabled during fuzzing as they are too noisy and consume much resource
    void *txtmp = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, f->alstate, 0);
    AppLayerDecoderEvents *decoder_events =
            AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP1, txtmp);

    FAIL_IF_NULL(decoder_events);
    FAIL_IF(decoder_events->events[0] != HTP_LOG_CODE_METHOD_DELIM_NON_COMPLIANT);
    FAIL_IF(decoder_events->events[1] != HTP_LOG_CODE_URI_DELIM_NON_COMPLIANT);
#endif

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test response not HTTP
 */
static int HTPParserTest20(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "NOTHTTP\r\nSOMEOTHERDATA";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "STILLNOTHTTP\r\nSOMEMOREOTHERDATA";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != 0);
    FAIL_IF(htp_tx_response_protocol_number(tx) != -1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test response not HTTP
 */
static int HTPParserTest21(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "999 NOTHTTP REALLY\r\nSOMEOTHERDATA\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "STILLNOTHTTP\r\nSOMEMOREOTHERDATA";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != 0);
    FAIL_IF(htp_tx_response_protocol_number(tx) != -1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test response not HTTP
 */
static int HTPParserTest22(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "\r\n0000=0000000/ASDF3_31.zip, 456723\r\n"
                          "AAAAAA_0000=0000000/AAAAAAAA.zip,46725\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != -0);
    FAIL_IF(htp_tx_response_protocol_number(tx) != -1);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test response not HTTP
 */
static int HTPParserTest23(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP0000=0000000/ASDF3_31.zip, 456723\r\n"
                          "AAAAAA_0000=0000000/AAAAAAAA.zip,46725\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != -1);
    FAIL_IF(htp_tx_response_protocol_number(tx) != -2);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test Test response not HTTP
 */
static int HTPParserTest24(void)
{
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.0 0000=0000000/ASDF3_31.zip, 456723\r\n"
                          "AAAAAA_0000=0000000/AAAAAAAA.zip,46725\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    http_state = f->alstate;
    FAIL_IF_NULL(http_state);
    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    FAIL_IF_NULL(tx);
    const htp_header_t *h = htp_tx_request_header_index(tx, 0);
    FAIL_IF_NULL(h);

    FAIL_IF(htp_tx_request_method_number(tx) != HTP_METHOD_GET);
    FAIL_IF(htp_tx_request_protocol_number(tx) != HTP_PROTOCOL_V1_1);

    FAIL_IF(htp_tx_response_status_number(tx) != -1);
    FAIL_IF(htp_tx_response_protocol_number(tx) != HTP_PROTOCOL_V1_0);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);
    PASS;
}

/** \test multi transactions and cleanup */
static int HTPParserTest25(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    StreamTcpInitConfig(true);
    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_HTTP1;

    const char *str = "GET / HTTP/1.1\r\nHost: www.google.com\r\nUser-Agent: Suricata/1.0\r\n\r\n";
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_START,
            (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);

    str = "HTTP 1.1 200 OK\r\nServer: Suricata/1.0\r\nContent-Length: 8\r\n\r\nSuricata";
    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_START,
            (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT, (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);

    AppLayerParserTransactionsCleanup(f, STREAM_TOCLIENT);

    uint64_t ret[4];
    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 8); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 8); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 8); // log_id
    FAIL_IF_NOT(ret[3] == 8); // min_id

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER | STREAM_EOF,
            (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f, STREAM_TOCLIENT);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 8); // inspect_id[0] not updated by ..Cleanup() until full tx is done
    FAIL_IF_NOT(ret[1] == 8); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 8); // log_id
    FAIL_IF_NOT(ret[3] == 8); // min_id

    r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOCLIENT | STREAM_EOF,
            (uint8_t *)str, strlen(str));
    FAIL_IF_NOT(r == 0);
    AppLayerParserTransactionsCleanup(f, STREAM_TOCLIENT);

    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 9); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 9); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 9); // log_id
    FAIL_IF_NOT(ret[3] == 9); // min_id

    HtpState *http_state = f->alstate;
    FAIL_IF_NULL(http_state);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);

    PASS;
}

static int HTPParserTest26(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    request-body-limit: 1\n\
    response-body-limit: 1\n\
";
    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    uint8_t httpbuf1[] = "GET /alice.txt HTTP/1.1\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\n"
                         "Content-Type: text/plain\r\n"
                         "Content-Length: 228\r\n\r\n"
                         "Alice was beginning to get very tired of sitting by her sister on the bank."
                         "Alice was beginning to get very tired of sitting by her sister on the bank.";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "Alice was beginning to get very tired of sitting by her sister on the bank.\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(filestore; sid:1; rev:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOSERVER, httpbuf1, httplen1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf2, httplen2);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    r = AppLayerParserParse(
            &th_v, alp_tctx, &f, ALPROTO_HTTP1, STREAM_TOCLIENT, httpbuf3, httplen3);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    void *tx_ptr = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP1, http_state, 0);
    FAIL_IF_NULL(tx_ptr);

    AppLayerGetFileState files = HTPGetTxFiles(tx_ptr, STREAM_TOCLIENT);
    FileContainer *ffc = files.fc;
    FAIL_IF_NULL(ffc);

    File *ptr = ffc->head;
    FAIL_IF(ptr->state != FILE_STATE_CLOSED);

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(true);

    HTPFreeConfig();
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    PASS;
}

static int HTPParserTest27(void)
{
    HTPCfgDir cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.body_limit = 1500;
    FileReassemblyDepthEnable(2000);

    uint32_t len = 1000;

    HtpTxUserData *tx_ud = SCMalloc(sizeof(HtpTxUserData));
    FAIL_IF_NULL(tx_ud);

    tx_ud->tsflags |= HTP_STREAM_DEPTH_SET;
    tx_ud->request_body.content_len_so_far = 2500;

    FAIL_IF(AppLayerHtpCheckDepth(&cfg, &tx_ud->request_body, tx_ud->tsflags));

    len = AppLayerHtpComputeChunkLength(tx_ud->request_body.content_len_so_far,
                                        0,
                                        FileReassemblyDepth(),
                                        tx_ud->tsflags,
                                        len);
    FAIL_IF(len != 1000);

    SCFree(tx_ud);

    PASS;
}

/**
 *  \brief  Register the Unit tests for the HTTP protocol
 */
static void HTPParserRegisterTests(void)
{
    UtRegisterTest("HTPParserTest01", HTPParserTest01);
    UtRegisterTest("HTPParserTest01a", HTPParserTest01a);
    UtRegisterTest("HTPParserTest01b", HTPParserTest01b);
    UtRegisterTest("HTPParserTest01c", HTPParserTest01c);
    UtRegisterTest("HTPParserTest02", HTPParserTest02);
    UtRegisterTest("HTPParserTest03", HTPParserTest03);
    UtRegisterTest("HTPParserTest04", HTPParserTest04);
    UtRegisterTest("HTPParserTest05", HTPParserTest05);
    UtRegisterTest("HTPParserTest06", HTPParserTest06);
    UtRegisterTest("HTPParserTest07", HTPParserTest07);
    UtRegisterTest("HTPParserTest08", HTPParserTest08);
    UtRegisterTest("HTPParserTest09", HTPParserTest09);
    UtRegisterTest("HTPParserTest10", HTPParserTest10);
    UtRegisterTest("HTPParserTest11", HTPParserTest11);
    UtRegisterTest("HTPParserTest12", HTPParserTest12);
    UtRegisterTest("HTPParserTest13", HTPParserTest13);
    UtRegisterTest("HTPParserConfigTest01", HTPParserConfigTest01);
    UtRegisterTest("HTPParserConfigTest02", HTPParserConfigTest02);
    UtRegisterTest("HTPParserConfigTest03", HTPParserConfigTest03);

    UtRegisterTest("HTPParserDecodingTest01", HTPParserDecodingTest01);
    UtRegisterTest("HTPParserDecodingTest01a", HTPParserDecodingTest01a);
    UtRegisterTest("HTPParserDecodingTest02", HTPParserDecodingTest02);
    UtRegisterTest("HTPParserDecodingTest03", HTPParserDecodingTest03);
    UtRegisterTest("HTPParserDecodingTest04", HTPParserDecodingTest04);
    UtRegisterTest("HTPParserDecodingTest05", HTPParserDecodingTest05);
    UtRegisterTest("HTPParserDecodingTest06", HTPParserDecodingTest06);
    UtRegisterTest("HTPParserDecodingTest07", HTPParserDecodingTest07);
    UtRegisterTest("HTPParserDecodingTest08", HTPParserDecodingTest08);
    UtRegisterTest("HTPParserDecodingTest09", HTPParserDecodingTest09);

    UtRegisterTest("HTPBodyReassemblyTest01", HTPBodyReassemblyTest01);

    UtRegisterTest("HTPSegvTest01", HTPSegvTest01);

    UtRegisterTest("HTPParserTest14", HTPParserTest14);
    UtRegisterTest("HTPParserTest15", HTPParserTest15);
    UtRegisterTest("HTPParserTest16", HTPParserTest16);
    UtRegisterTest("HTPParserTest20", HTPParserTest20);
    UtRegisterTest("HTPParserTest21", HTPParserTest21);
    UtRegisterTest("HTPParserTest22", HTPParserTest22);
    UtRegisterTest("HTPParserTest23", HTPParserTest23);
    UtRegisterTest("HTPParserTest24", HTPParserTest24);
    UtRegisterTest("HTPParserTest25", HTPParserTest25);
    UtRegisterTest("HTPParserTest26", HTPParserTest26);
    UtRegisterTest("HTPParserTest27", HTPParserTest27);

    HTPFileParserRegisterTests();
    HTPXFFParserRegisterTests();
}
#endif /* UNITTESTS */

/**
 * @}
 */
