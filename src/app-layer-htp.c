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
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "counters.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"
#include "util-file.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "app-layer.h"
#include "app-layer-htp.h"
#include "app-layer-htp-body.h"
#include "app-layer-htp-file.h"
#include "app-layer-htp-libhtp.h"
#include "app-layer-htp-xff.h"

#include "util-spm.h"
#include "util-debug.h"
#include "util-time.h"
#include "util-misc.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "decode-events.h"

#include "util-memcmp.h"

//#define PRINT

/** Fast lookup tree (radix) for the various HTP configurations */
static SCRadixTree *cfgtree;
/** List of HTP configurations. */
static HTPCfgRec cfglist;

#ifdef DEBUG
static SCMutex htp_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

SCEnumCharMap http_decoder_event_table[ ] = {
    { "UNKNOWN_ERROR",
        HTTP_DECODER_EVENT_UNKNOWN_ERROR},
    { "GZIP_DECOMPRESSION_FAILED",
        HTTP_DECODER_EVENT_GZIP_DECOMPRESSION_FAILED},
    { "REQUEST_FIELD_MISSING_COLON",
        HTTP_DECODER_EVENT_REQUEST_FIELD_MISSING_COLON},
    { "RESPONSE_FIELD_MISSING_COLON",
        HTTP_DECODER_EVENT_RESPONSE_FIELD_MISSING_COLON},
    { "INVALID_REQUEST_CHUNK_LEN",
        HTTP_DECODER_EVENT_INVALID_REQUEST_CHUNK_LEN},
    { "INVALID_RESPONSE_CHUNK_LEN",
        HTTP_DECODER_EVENT_INVALID_RESPONSE_CHUNK_LEN},
    { "INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST",
        HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST},
    { "INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE",
        HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE},
    { "INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST",
        HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST},
    { "INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE",
        HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE},
    { "100_CONTINUE_ALREADY_SEEN",
        HTTP_DECODER_EVENT_100_CONTINUE_ALREADY_SEEN},
    { "UNABLE_TO_MATCH_RESPONSE_TO_REQUEST",
        HTTP_DECODER_EVENT_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST},
    { "INVALID_SERVER_PORT_IN_REQUEST",
        HTTP_DECODER_EVENT_INVALID_SERVER_PORT_IN_REQUEST},
    { "INVALID_AUTHORITY_PORT",
        HTTP_DECODER_EVENT_INVALID_AUTHORITY_PORT},
    { "REQUEST_HEADER_INVALID",
        HTTP_DECODER_EVENT_REQUEST_HEADER_INVALID},
    { "RESPONSE_HEADER_INVALID",
        HTTP_DECODER_EVENT_RESPONSE_HEADER_INVALID},
    { "MISSING_HOST_HEADER",
        HTTP_DECODER_EVENT_MISSING_HOST_HEADER},
    { "HOST_HEADER_AMBIGUOUS",
        HTTP_DECODER_EVENT_HOST_HEADER_AMBIGUOUS},
    { "INVALID_REQUEST_FIELD_FOLDING",
        HTTP_DECODER_EVENT_INVALID_REQUEST_FIELD_FOLDING},
    { "INVALID_RESPONSE_FIELD_FOLDING",
        HTTP_DECODER_EVENT_INVALID_RESPONSE_FIELD_FOLDING},
    { "REQUEST_FIELD_TOO_LONG",
        HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG},
    { "RESPONSE_FIELD_TOO_LONG",
        HTTP_DECODER_EVENT_RESPONSE_FIELD_TOO_LONG},
    { "REQUEST_SERVER_PORT_TCP_PORT_MISMATCH",
        HTTP_DECODER_EVENT_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH},
    { "REQUEST_URI_HOST_INVALID",
        HTTP_DECODER_EVENT_URI_HOST_INVALID},
    { "REQUEST_HEADER_HOST_INVALID",
        HTTP_DECODER_EVENT_HEADER_HOST_INVALID},
    { "URI_DELIM_NON_COMPLIANT",
        HTTP_DECODER_EVENT_URI_DELIM_NON_COMPLIANT},
    { "METHOD_DELIM_NON_COMPLIANT",
        HTTP_DECODER_EVENT_METHOD_DELIM_NON_COMPLIANT},
    { "REQUEST_LINE_LEADING_WHITESPACE",
        HTTP_DECODER_EVENT_REQUEST_LINE_LEADING_WHITESPACE},

    /* suricata warnings/errors */
    { "MULTIPART_GENERIC_ERROR",
        HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR},
    { "MULTIPART_NO_FILEDATA",
        HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA},
    { "MULTIPART_INVALID_HEADER",
        HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER},

    { NULL,                      -1 },
};

static void *HTPStateGetTx(void *alstate, uint64_t tx_id);
static int HTPStateGetAlstateProgress(void *tx, uint8_t direction);
static uint64_t HTPStateGetTxCnt(void *alstate);
static int HTPStateGetAlstateProgressCompletionStatus(uint8_t direction);

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
#define CASE_HTP_PERSONALITY_STRING(p) \
    case HTP_SERVER_ ## p: return #p

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
#define IF_HTP_PERSONALITY_NUM(p) \
    if (strcasecmp(#p, str) == 0) return HTP_SERVER_ ## p

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
        SCLogError(SC_WARN_OPTION_OBSOLETE, "Personality %s no "
                   "longer supported by libhtp.", str);
        return -1;
    } else if ((strcasecmp("APACHE", str) == 0) ||
               (strcasecmp("APACHE_2_2", str) == 0))
    {
        SCLogWarning(SC_WARN_OPTION_OBSOLETE, "Personality %s no "
                   "longer supported by libhtp, failing back to "
                   "Apache2 personality.", str);
        return HTP_SERVER_APACHE_2;
    }

    return -1;
}

void HTPSetEvent(HtpState *s, HtpTxUserData *htud, uint8_t e)
{
    SCLogDebug("setting event %u", e);

    if (htud) {
        AppLayerDecoderEventsSetEventRaw(&htud->decoder_events, e);
        s->events++;
        return;
    }

    htp_tx_t *tx = HTPStateGetTx(s, s->transaction_cnt);
    if (tx != NULL) {
        htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud != NULL) {
            AppLayerDecoderEventsSetEventRaw(&htud->decoder_events, e);
            s->events++;
            return;
        }
    }
    SCLogDebug("couldn't set event %u", e);
}

static int HTPHasEvents(void *state)
{
    HtpState *htp_state = (HtpState *)state;
    return (htp_state->events > 0);
}

static AppLayerDecoderEvents *HTPGetEvents(void *state, uint64_t tx_id)
{
    SCLogDebug("get HTTP events for TX %"PRIu64, tx_id);

    HtpState *s = (HtpState *)state;
    htp_tx_t *tx = HTPStateGetTx(s, tx_id);
    if (tx != NULL) {
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud != NULL) {
            SCLogDebug("has htud, htud->decoder_events %p", htud->decoder_events);
            return htud->decoder_events;
        }
    }
    return NULL;
}

/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void)
{
    SCEnter();

    HtpState *s = HTPMalloc(sizeof(HtpState));
    if (unlikely(s == NULL))
        goto error;

    memset(s, 0x00, sizeof(HtpState));

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt++;
    htp_state_memuse += sizeof(HtpState);
    SCLogDebug("htp memory %"PRIu64" (%"PRIu64")", htp_state_memuse, htp_state_memcnt);
    SCMutexUnlock(&htp_state_mem_lock);
#endif

    SCReturnPtr((void *)s, "void");

error:
    if (s != NULL) {
        HTPFree(s, sizeof(HtpState));
    }

    SCReturnPtr(NULL, "void");
}

static void HtpTxUserDataFree(HtpState *state, HtpTxUserData *htud)
{
    if (likely(htud)) {
        HtpBodyFree(&htud->request_body);
        HtpBodyFree(&htud->response_body);
        bstr_free(htud->request_uri_normalized);
        if (htud->request_headers_raw)
            HTPFree(htud->request_headers_raw, htud->request_headers_raw_len);
        if (htud->response_headers_raw)
            HTPFree(htud->response_headers_raw, htud->response_headers_raw_len);
        AppLayerDecoderEventsFreeEvents(&htud->decoder_events);
        if (htud->boundary)
            HTPFree(htud->boundary, htud->boundary_len);
        if (htud->de_state != NULL) {
            if (likely(state != NULL)) { // should be impossible that it's null
                BUG_ON(state->tx_with_detect_state_cnt == 0);
                state->tx_with_detect_state_cnt--;
            }

            DetectEngineStateFree(htud->de_state);
        }
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

    /* Unset the body inspection */
    s->flags &=~ HTP_FLAG_NEW_BODY_SET;

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
                    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
                    HtpTxUserDataFree(s, htud);
                    htp_tx_set_user_data(tx, NULL);
                }
            }
        }
        htp_connp_destroy_all(s->connp);
    }
    BUG_ON(s->tx_with_detect_state_cnt > 0);

    FileContainerFree(s->files_ts);
    FileContainerFree(s->files_tc);
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
 *  \warning We cannot actually free the transactions here. It seems that
 *           HTP only accepts freeing of transactions in the response callback.
 */
static void HTPStateTransactionFree(void *state, uint64_t id)
{
    SCEnter();

    HtpState *s = (HtpState *)state;

    SCLogDebug("state %p, id %"PRIu64, s, id);

    htp_tx_t *tx = HTPStateGetTx(s, id);
    if (tx != NULL) {
        /* This will remove obsolete body chunks */
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        HtpTxUserDataFree(s, htud);
        htp_tx_set_user_data(tx, NULL);

        /* hack: even if libhtp considers the tx incomplete, we want to
         * free it here. htp_tx_destroy however, will refuse to do this.
         * As htp_tx_destroy_incomplete isn't available in the public API,
         * we hack around it here. */
        if (unlikely(!(
            tx->request_progress == HTP_REQUEST_COMPLETE &&
            tx->response_progress == HTP_RESPONSE_COMPLETE)))
        {
            tx->request_progress = HTP_REQUEST_COMPLETE;
            tx->response_progress = HTP_RESPONSE_COMPLETE;
        }
        htp_tx_destroy(tx);
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
 *        engine needs the http request multi part header.
 *
 * \initonly
 */
void AppLayerHtpNeedMultipartHeader(void)
{
    SCEnter();
    AppLayerHtpEnableRequestBodyCallback();

    SC_ATOMIC_OR(htp_config_flags, HTP_REQUIRE_REQUEST_MULTIPART);
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
    AppLayerHtpNeedMultipartHeader();
    AppLayerHtpEnableRequestBodyCallback();
    AppLayerHtpEnableResponseBodyCallback();

    SC_ATOMIC_OR(htp_config_flags, HTP_REQUIRE_REQUEST_FILE);
    SCReturn;
}

/* below error messages updated up to libhtp 0.5.7 (git 379632278b38b9a792183694a4febb9e0dbd1e7a) */
struct {
    char *msg;
    int  de;
} htp_errors[] = {
    { "GZip decompressor: inflateInit2 failed", HTTP_DECODER_EVENT_GZIP_DECOMPRESSION_FAILED},
    { "Request field invalid: colon missing", HTTP_DECODER_EVENT_REQUEST_FIELD_MISSING_COLON},
    { "Response field invalid: missing colon", HTTP_DECODER_EVENT_RESPONSE_FIELD_MISSING_COLON},
    { "Request chunk encoding: Invalid chunk length", HTTP_DECODER_EVENT_INVALID_REQUEST_CHUNK_LEN},
    { "Response chunk encoding: Invalid chunk length", HTTP_DECODER_EVENT_INVALID_RESPONSE_CHUNK_LEN},
/*  { "Invalid T-E value in request", HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST}, <- tx flag HTP_REQUEST_INVALID_T_E
    { "Invalid T-E value in response", HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE}, <- nothing to replace it */
/*  { "Invalid C-L field in request", HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST}, <- tx flag HTP_REQUEST_INVALID_C_L */
    { "Invalid C-L field in response", HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE},
    { "Already seen 100-Continue", HTTP_DECODER_EVENT_100_CONTINUE_ALREADY_SEEN},
    { "Unable to match response to request", HTTP_DECODER_EVENT_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST},
    { "Invalid server port information in request", HTTP_DECODER_EVENT_INVALID_SERVER_PORT_IN_REQUEST},
/*    { "Invalid authority port", HTTP_DECODER_EVENT_INVALID_AUTHORITY_PORT}, htp no longer returns this error */
    { "Request buffer over", HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG},
    { "Response buffer over", HTTP_DECODER_EVENT_RESPONSE_FIELD_TOO_LONG},
};

struct {
    char *msg;
    int  de;
} htp_warnings[] = {
    { "GZip decompressor:", HTTP_DECODER_EVENT_GZIP_DECOMPRESSION_FAILED},
    { "Request field invalid", HTTP_DECODER_EVENT_REQUEST_HEADER_INVALID},
    { "Response field invalid", HTTP_DECODER_EVENT_RESPONSE_HEADER_INVALID},
    { "Request header name is not a token", HTTP_DECODER_EVENT_REQUEST_HEADER_INVALID},
    { "Response header name is not a token", HTTP_DECODER_EVENT_RESPONSE_HEADER_INVALID},
/*  { "Host information in request headers required by HTTP/1.1", HTTP_DECODER_EVENT_MISSING_HOST_HEADER}, <- tx flag HTP_HOST_MISSING
    { "Host information ambiguous", HTTP_DECODER_EVENT_HOST_HEADER_AMBIGUOUS}, <- tx flag HTP_HOST_AMBIGUOUS */
    { "Invalid request field folding", HTTP_DECODER_EVENT_INVALID_REQUEST_FIELD_FOLDING},
    { "Invalid response field folding", HTTP_DECODER_EVENT_INVALID_RESPONSE_FIELD_FOLDING},
    /* line is now: htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request server port=%d number differs from the actual TCP port=%d", port, connp->conn->server_port);
     * luckily, "Request server port=" is unique */
/*    { "Request server port number differs from the actual TCP port", HTTP_DECODER_EVENT_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH}, */
    { "Request server port=", HTTP_DECODER_EVENT_REQUEST_SERVER_PORT_TCP_PORT_MISMATCH},
    { "Request line: URI contains non-compliant delimiter", HTTP_DECODER_EVENT_URI_DELIM_NON_COMPLIANT},
    { "Request line: non-compliant delimiter between Method and URI", HTTP_DECODER_EVENT_METHOD_DELIM_NON_COMPLIANT},
    { "Request line: leading whitespace", HTTP_DECODER_EVENT_REQUEST_LINE_LEADING_WHITESPACE},
};

#define HTP_ERROR_MAX (sizeof(htp_errors) / sizeof(htp_errors[0]))
#define HTP_WARNING_MAX (sizeof(htp_warnings) / sizeof(htp_warnings[0]))

/**
 *  \internal
 *
 *  \brief Get the warning id for the warning msg.
 *
 *  \param msg warning message
 *
 *  \retval id the id or 0 in case of not found
 */
static int HTPHandleWarningGetId(const char *msg)
{
    SCLogDebug("received warning \"%s\"", msg);
    size_t idx;
    for (idx = 0; idx < HTP_WARNING_MAX; idx++) {
        if (strncmp(htp_warnings[idx].msg, msg,
                    strlen(htp_warnings[idx].msg)) == 0)
        {
            return htp_warnings[idx].de;
        }
    }

    return 0;
}

/**
 *  \internal
 *
 *  \brief Get the error id for the error msg.
 *
 *  \param msg error message
 *
 *  \retval id the id or 0 in case of not found
 */
static int HTPHandleErrorGetId(const char *msg)
{
    SCLogDebug("received error \"%s\"", msg);

    size_t idx;
    for (idx = 0; idx < HTP_ERROR_MAX; idx++) {
        if (strncmp(htp_errors[idx].msg, msg,
                    strlen(htp_errors[idx].msg)) == 0)
        {
            return htp_errors[idx].de;
        }
    }

    return 0;
}

/**
 *  \internal
 *
 *  \brief Check state for errors, warnings and add any as events
 *
 *  \param s state
 */
static void HTPHandleError(HtpState *s)
{
    if (s == NULL || s->conn == NULL ||
        s->conn->messages == NULL) {
        return;
    }

    size_t size = htp_list_size(s->conn->messages);
    size_t msg;

    for (msg = s->htp_messages_offset; msg < size; msg++) {
        htp_log_t *log = htp_list_get(s->conn->messages, msg);
        if (log == NULL)
            continue;

        HtpTxUserData *htud = NULL;
        htp_tx_t *tx = log->tx; // will be NULL in <=0.5.9
        if (tx != NULL)
            htud = (HtpTxUserData *) htp_tx_get_user_data(tx);

        SCLogDebug("message %s", log->msg);

        int id = HTPHandleErrorGetId(log->msg);
        if (id == 0) {
            id = HTPHandleWarningGetId(log->msg);
            if (id == 0)
                id = HTTP_DECODER_EVENT_UNKNOWN_ERROR;
        }

        if (id > 0) {
            HTPSetEvent(s, htud, id);
        }
    }
    s->htp_messages_offset = (uint16_t)msg;
    SCLogDebug("s->htp_messages_offset %u", s->htp_messages_offset);
}

static inline void HTPErrorCheckTxRequestFlags(HtpState *s, htp_tx_t *tx)
{
#ifdef DEBUG
    BUG_ON(s == NULL || tx == NULL);
#endif
    if (tx->flags & (   HTP_REQUEST_INVALID_T_E|HTP_REQUEST_INVALID_C_L|
                        HTP_HOST_MISSING|HTP_HOST_AMBIGUOUS|HTP_HOSTU_INVALID|
                        HTP_HOSTH_INVALID))
    {
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud == NULL)
            return;

        if (tx->flags & HTP_REQUEST_INVALID_T_E)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST);
        if (tx->flags & HTP_REQUEST_INVALID_C_L)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST);
        if (tx->flags & HTP_HOST_MISSING)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_MISSING_HOST_HEADER);
        if (tx->flags & HTP_HOST_AMBIGUOUS)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_HOST_HEADER_AMBIGUOUS);
        if (tx->flags & HTP_HOSTU_INVALID)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_URI_HOST_INVALID);
        if (tx->flags & HTP_HOSTH_INVALID)
            HTPSetEvent(s, htud,
                    HTTP_DECODER_EVENT_HEADER_HOST_INVALID);
    }
}

/**
 *  \brief  Function to handle the reassembled data from client and feed it to
 *          the HTP library to process it.
 *
 *  \param  flow        Pointer to the flow the data belong to
 *  \param  htp_state   Pointer the state in which the parsed value to be stored
 *  \param  pstate      Application layer parser state for this session
 *  \param  input       Pointer the received HTTP client data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the output (not used in this function)
 *
 *  \retval On success returns 1 or on failure returns -1.
 */
static int HTPHandleRequestData(Flow *f, void *htp_state,
                                AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                void *local_data)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    //PrintRawDataFp(stdout, input, input_len);

    HtpState *hstate = (HtpState *)htp_state;
    hstate->f = f;

    /* On the first invocation, create the connection parser structure to
     * be used by HTP library.  This is looked up via IP in the radix
     * tree.  Failing that, the default HTP config is used.
     */
    if (NULL == hstate->conn) {
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
            SCLogError(SC_ERR_INVALID_ARGUMENT, "unknown address family, bug!");
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

        hstate->conn = htp_connp_get_connection(hstate->connp);

        htp_connp_set_user_data(hstate->connp, (void *)hstate);
        hstate->cfg = htp_cfg_rec;

        SCLogDebug("New hstate->connp %p", hstate->connp);
    }

    /* the code block above should make sure connp is never NULL here */
#ifdef DEBUG_VALIDATION
    BUG_ON(hstate->connp == NULL);
#endif

    /* Unset the body inspection (the callback should
     * reactivate it if necessary) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    /* Open the HTTP connection on receiving the first request */
    if (!(hstate->flags & HTP_FLAG_STATE_OPEN)) {
        SCLogDebug("opening htp handle at %p", hstate->connp);

        htp_connp_open(hstate->connp, NULL, f->sp, NULL, f->dp, &f->startts);
        hstate->flags |= HTP_FLAG_STATE_OPEN;
    } else {
        SCLogDebug("using existing htp handle at %p", hstate->connp);
    }

    htp_time_t ts = { f->lastts.tv_sec, f->lastts.tv_usec };
    /* pass the new data to the htp parser */
    if (input_len > 0) {
        r = htp_connp_req_data(hstate->connp, &ts, input, input_len);

        switch(r) {
            case HTP_STREAM_ERROR:

                hstate->flags |= HTP_FLAG_STATE_ERROR;
                hstate->flags &= ~HTP_FLAG_STATE_DATA;
                hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
                ret = -1;
                break;
            case HTP_STREAM_DATA:
            case HTP_STREAM_DATA_OTHER:

                hstate->flags |= HTP_FLAG_STATE_DATA;
                break;
            case HTP_STREAM_TUNNEL:
                break;
            default:
                hstate->flags &= ~HTP_FLAG_STATE_DATA;
                hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
        }
        HTPHandleError(hstate);
    }

    /* if the TCP connection is closed, then close the HTTP connection */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) &&
        !(hstate->flags & HTP_FLAG_STATE_CLOSED_TS))
    {
        htp_connp_close(hstate->connp, &ts);
        hstate->flags |= HTP_FLAG_STATE_CLOSED_TS;
        SCLogDebug("stream eof encountered, closing htp handle for ts");
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    SCReturnInt(ret);

error:
    SCReturnInt(-1);
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
static int HTPHandleResponseData(Flow *f, void *htp_state,
                                 AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 void *local_data)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    HtpState *hstate = (HtpState *)htp_state;
    hstate->f = f;
    if (hstate->connp == NULL) {
        SCLogDebug("HTP state has no connp");
        /* till we have the new libhtp changes that allow response first,
         * let's take response in first. */
        //BUG_ON(1);
        SCReturnInt(-1);
    }

    /* Unset the body inspection (the callback should
     * reactivate it if necessary) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    htp_time_t ts = { f->lastts.tv_sec, f->lastts.tv_usec };
    if (input_len > 0) {
        r = htp_connp_res_data(hstate->connp, &ts, input, input_len);
        switch(r) {
            case HTP_STREAM_ERROR:
                hstate->flags = HTP_FLAG_STATE_ERROR;
                hstate->flags &= ~HTP_FLAG_STATE_DATA;
                hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
                ret = -1;
                break;
            case HTP_STREAM_DATA:
            case HTP_STREAM_DATA_OTHER:
                hstate->flags |= HTP_FLAG_STATE_DATA;
                break;
            case HTP_STREAM_TUNNEL:
                break;
            default:
                hstate->flags &= ~HTP_FLAG_STATE_DATA;
                hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
        }
        HTPHandleError(hstate);
    }

    /* if we the TCP connection is closed, then close the HTTP connection */
    if (AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) &&
        !(hstate->flags & HTP_FLAG_STATE_CLOSED_TC))
    {
        htp_connp_close(hstate->connp, &ts);
        hstate->flags |= HTP_FLAG_STATE_CLOSED_TC;
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    SCReturnInt(ret);
}

/**
 *  \param name /Lowercase/ version of the variable name
 */
static int HTTPParseContentDispositionHeader(uint8_t *name, size_t name_len,
        uint8_t *data, size_t len, uint8_t **retptr, size_t *retlen)
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

    uint8_t *line = data+x;
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
                uint8_t *token = line + offset;
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
                        uint8_t *value = token + name_len;
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
 *  \param name /Lowercase/ version of the variable name
 */
static int HTTPParseContentTypeHeader(uint8_t *name, size_t name_len,
        uint8_t *data, size_t len, uint8_t **retptr, size_t *retlen)
{
    SCEnter();
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

    if (x >= len) {
        SCReturnInt(0);
    }

    uint8_t *line = data+x;
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
                uint8_t *token = line + offset;
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
                        uint8_t *value = token + name_len;
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
                        SCReturnInt(1);
                    }
                }
            }
        }
    }

    SCReturnInt(0);
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
static int HtpRequestBodySetupMultipart(htp_tx_data_t *d, HtpTxUserData *htud)
{
    htp_header_t *h = (htp_header_t *)htp_table_get_c(d->tx->request_headers,
            "Content-Type");
    if (h != NULL && bstr_len(h->value) > 0) {
        uint8_t *boundary = NULL;
        size_t boundary_len = 0;

        int r = HTTPParseContentTypeHeader((uint8_t *)"boundary=", 9,
                (uint8_t *) bstr_ptr(h->value), bstr_len(h->value),
                &boundary, &boundary_len);
        if (r == 1) {
#ifdef PRINT
            printf("BOUNDARY START: \n");
            PrintRawDataFp(stdout, boundary, boundary_len);
            printf("BOUNDARY END: \n");
#endif
            if (boundary_len < HTP_BOUNDARY_MAX) {
                htud->boundary = HTPMalloc(boundary_len);
                if (htud->boundary == NULL) {
                    return -1;
                }
                htud->boundary_len = (uint8_t)boundary_len;
                memcpy(htud->boundary, boundary, boundary_len);

                htud->tsflags |= HTP_BOUNDARY_SET;
            } else {
                SCLogDebug("invalid boundary");
                return -1;
            }
            SCReturnInt(1);
        }
        //SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Setup boundary buffers
 */
static int HtpRequestBodySetupBoundary(HtpTxUserData *htud,
        uint8_t **expected_boundary, uint8_t *expected_boundary_len,
        uint8_t **expected_boundary_end, uint8_t *expected_boundary_end_len)
{
    uint8_t *eb = NULL;
    uint8_t *ebe = NULL;

    uint8_t eb_len = htud->boundary_len + 2;
    eb = (uint8_t *)HTPMalloc(eb_len);
    if (eb == NULL) {
        goto error;
    }
    memset(eb, '-', eb_len);
    memcpy(eb + 2, htud->boundary, htud->boundary_len);

    uint8_t ebe_len = htud->boundary_len + 4;
    ebe = (uint8_t *)HTPMalloc(ebe_len);
    if (ebe == NULL) {
        goto error;
    }
    memset(ebe, '-', ebe_len);
    memcpy(ebe + 2, htud->boundary, htud->boundary_len);

    *expected_boundary = eb;
    *expected_boundary_len = eb_len;
    *expected_boundary_end = ebe;
    *expected_boundary_end_len = ebe_len;

    SCReturnInt(0);

error:
    if (eb != NULL) {
        HTPFree(eb, eb_len);
    }
    if (ebe != NULL) {
        HTPFree(ebe, ebe_len);
    }
    SCReturnInt(-1);
}

#define C_D_HDR "content-disposition:"
#define C_D_HDR_LEN 20
#define C_T_HDR "content-type:"
#define C_T_HDR_LEN 13

static void HtpRequestBodyMultipartParseHeader(HtpState *hstate,
        HtpTxUserData *htud,
        uint8_t *header, uint32_t header_len,
        uint8_t **filename, uint16_t *filename_len,
        uint8_t **filetype, uint16_t *filetype_len)
{
    uint8_t *fn = NULL;
    size_t fn_len = 0;
    uint8_t *ft = NULL;
    size_t ft_len = 0;

#ifdef PRINT
    printf("HEADER START: \n");
    PrintRawDataFp(stdout, header, header_len);
    printf("HEADER END: \n");
#endif

    while (header_len > 0) {
        uint8_t *next_line = Bs2bmSearch(header, header_len, (uint8_t *)"\r\n", 2);
        uint8_t *line = header;
        uint32_t line_len;

        if (next_line == NULL) {
            line_len = header_len;
        } else {
            line_len = next_line - header;
        }
        uint8_t *sc = (uint8_t *)memchr(line, ':', line_len);
        if (sc == NULL) {
            HTPSetEvent(hstate, htud,
                    HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER);
            /* if the : we found is the final char, it means we have
             * no value */
        } else if (line_len > 0 && sc == &line[line_len - 1]) {
            HTPSetEvent(hstate, htud,
                    HTTP_DECODER_EVENT_MULTIPART_INVALID_HEADER);
        } else {
#ifdef PRINT
            printf("LINE START: \n");
            PrintRawDataFp(stdout, line, line_len);
            printf("LINE END: \n");
#endif
            if (line_len >= C_D_HDR_LEN &&
                    SCMemcmpLowercase(C_D_HDR, line, C_D_HDR_LEN) == 0) {
                uint8_t *value = line + C_D_HDR_LEN;
                uint32_t value_len = line_len - C_D_HDR_LEN;

                /* parse content-disposition */
                (void)HTTPParseContentDispositionHeader((uint8_t *)"filename=", 9,
                        value, value_len, &fn, &fn_len);
            } else if (line_len >= C_T_HDR_LEN &&
                    SCMemcmpLowercase(C_T_HDR, line, C_T_HDR_LEN) == 0) {
                SCLogDebug("content-type line");
                uint8_t *value = line + C_T_HDR_LEN;
                uint32_t value_len = line_len - C_T_HDR_LEN;

                (void)HTTPParseContentTypeHeader(NULL, 0,
                        value, value_len, &ft, &ft_len);
            }
        }

        if (next_line == NULL) {
            SCLogDebug("no next_line");
            break;
        }
        header_len -= ((next_line + 2) - header);
        header = next_line + 2;
    } /* while (header_len > 0) */

    if (fn_len > USHRT_MAX)
        fn_len = USHRT_MAX;
    if (ft_len > USHRT_MAX)
        ft_len = USHRT_MAX;

    *filename = fn;
    *filename_len = fn_len;
    *filetype = ft;
    *filetype_len = ft_len;
}

/**
 *  \brief Create a single buffer from the HtpBodyChunks in our list
 *
 *  \param htud transaction user data
 *  \param chunks_buffers pointer to pass back the buffer to the caller
 *  \param chunks_buffer_len pointer to pass back the buffer length to the caller
 */
static void HtpRequestBodyReassemble(HtpTxUserData *htud,
        uint8_t **chunks_buffer, uint32_t *chunks_buffer_len)
{
    uint8_t *buf = NULL;
    uint8_t *pbuf = NULL;
    uint32_t buf_len = 0;
    HtpBodyChunk *cur = htud->request_body.first;

    for ( ; cur != NULL; cur = cur->next) {
        SCLogDebug("chunk %p", cur);

        /* skip body chunks entirely before what we parsed already */
        if ((uint64_t )cur->stream_offset + cur->len <= htud->request_body.body_parsed) {
            SCLogDebug("skipping chunk");
            continue;
        }

        SCLogDebug("cur->stream_offset %"PRIu64", cur->len %"PRIu32", body_parsed %"PRIu64,
            cur->stream_offset, cur->len, htud->request_body.body_parsed);

        if (cur->stream_offset < htud->request_body.body_parsed &&
                cur->stream_offset + cur->len >= htud->request_body.body_parsed) {
            SCLogDebug("use part");

            uint32_t toff = htud->request_body.body_parsed - cur->stream_offset;
            uint32_t tlen = (cur->stream_offset + cur->len) - htud->request_body.body_parsed;
            uint8_t *pbuf = NULL;

            buf_len += tlen;
            if ((pbuf = HTPRealloc(buf, buf_len - tlen, buf_len)) == NULL) {
                HTPFree(buf, buf_len - tlen);
                buf = NULL;
                buf_len = 0;
                break;
            }
            buf = pbuf;
            memcpy(buf + buf_len - tlen, cur->data + toff, tlen);

        } else {
            SCLogDebug("use entire chunk");

            buf_len += cur->len;
            if ((pbuf = HTPRealloc(buf, buf_len - cur->len, buf_len)) == NULL) {
                HTPFree(buf, buf_len - cur->len);
                buf = NULL;
                buf_len = 0;
                break;
            }
            buf = pbuf;
            memcpy(buf + buf_len - cur->len, cur->data, cur->len);
        }
    }

    *chunks_buffer = buf;
    *chunks_buffer_len = buf_len;
}

int HtpRequestBodyHandleMultipart(HtpState *hstate, HtpTxUserData *htud,
                                  void *tx, uint8_t *chunks_buffer, uint32_t chunks_buffer_len)
{
    int result = 0;
    uint8_t *expected_boundary = NULL;
    uint8_t *expected_boundary_end = NULL;
    uint8_t expected_boundary_len = 0;
    uint8_t expected_boundary_end_len = 0;
    int tx_progress = 0;

#ifdef PRINT
    printf("CHUNK START: \n");
    PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    printf("CHUNK END: \n");
#endif

    if (HtpRequestBodySetupBoundary(htud, &expected_boundary, &expected_boundary_len,
                &expected_boundary_end, &expected_boundary_end_len) < 0) {
        goto end;
    }

    /* search for the header start, header end and form end */
    uint8_t *header_start = Bs2bmSearch(chunks_buffer, chunks_buffer_len,
            expected_boundary, expected_boundary_len);
    uint8_t *header_end = NULL;
    if (header_start != NULL) {
        header_end = Bs2bmSearch(header_start, chunks_buffer_len - (header_start - chunks_buffer),
                (uint8_t *)"\r\n\r\n", 4);
    }
    uint8_t *form_end = Bs2bmSearch(chunks_buffer, chunks_buffer_len,
            expected_boundary_end, expected_boundary_end_len);

    SCLogDebug("header_start %p, header_end %p, form_end %p", header_start,
            header_end, form_end);

    /* we currently only handle multipart for ts.  When we support it for tc,
     * we will need to supply right direction */
    tx_progress = AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, STREAM_TOSERVER);
    /* if we're in the file storage process, deal with that now */
    if (htud->tsflags & HTP_FILENAME_SET) {
        if (header_start != NULL || form_end != NULL || (tx_progress > HTP_REQUEST_BODY)) {
            SCLogDebug("reached the end of the file");

            uint8_t *filedata = chunks_buffer;
            uint32_t filedata_len = 0;
            uint8_t flags = 0;

            if (header_start < form_end || (header_start != NULL && form_end == NULL)) {
                filedata_len = header_start - filedata - 2; /* 0d 0a */
            } else if (form_end != NULL && form_end < header_start) {
                filedata_len = form_end - filedata;
            } else if (form_end != NULL && form_end == header_start) {
                filedata_len = form_end - filedata - 2; /* 0d 0a */
            } else if (tx_progress > HTP_RESPONSE_BODY) {
                filedata_len = chunks_buffer_len;
                flags = FILE_TRUNCATED;
            }

            if (filedata_len > chunks_buffer_len) {
                HTPSetEvent(hstate, htud,
                        HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
                goto end;
            }
#ifdef PRINT
            printf("FILEDATA (final chunk) START: \n");
            PrintRawDataFp(stdout, filedata, filedata_len);
            printf("FILEDATA (final chunk) END: \n");
#endif
            if (!(htud->tsflags & HTP_DONTSTORE)) {
                if (HTPFileClose(hstate, filedata, filedata_len, flags,
                            STREAM_TOSERVER) == -1)
                {
                    goto end;
                }
            }

            htud->tsflags &=~ HTP_FILENAME_SET;

            /* fall through */
        } else {
            SCLogDebug("not yet at the end of the file");

            if (chunks_buffer_len > expected_boundary_end_len) {
                uint8_t *filedata = chunks_buffer;
                uint32_t filedata_len = chunks_buffer_len - expected_boundary_len;
#ifdef PRINT
                printf("FILEDATA (part) START: \n");
                PrintRawDataFp(stdout, filedata, filedata_len);
                printf("FILEDATA (part) END: \n");
#endif

                if (!(htud->tsflags & HTP_DONTSTORE)) {
                    result = HTPFileStoreChunk(hstate, filedata,
                            filedata_len, STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        /* we know for sure we're not storing the file */
                        htud->tsflags |= HTP_DONTSTORE;
                    }
                }

                htud->request_body.body_parsed += filedata_len;
            } else {
                SCLogDebug("chunk too small to already process in part");
            }

            goto end;
        }
    }

    while (header_start != NULL && header_end != NULL &&
            header_end != form_end &&
            header_start < (chunks_buffer + chunks_buffer_len) &&
            header_end < (chunks_buffer + chunks_buffer_len) &&
            header_start < header_end)
    {
        uint8_t *filename = NULL;
        uint16_t filename_len = 0;
        uint8_t *filetype = NULL;
        uint16_t filetype_len = 0;

        uint32_t header_len = header_end - header_start;
        SCLogDebug("header_len %u", header_len);
        uint8_t *header = header_start;

        /* skip empty records */
        if (expected_boundary_len == header_len) {
            goto next;
        } else if ((uint32_t)(expected_boundary_len + 2) <= header_len) {
            header_len -= (expected_boundary_len + 2);
            header = header_start + (expected_boundary_len + 2); // + for 0d 0a
        }

        HtpRequestBodyMultipartParseHeader(hstate, htud, header, header_len,
                &filename, &filename_len, &filetype, &filetype_len);

        if (filename != NULL) {
            uint8_t *filedata = NULL;
            uint32_t filedata_len = 0;

            SCLogDebug("we have a filename");

            htud->tsflags |= HTP_FILENAME_SET;
            htud->tsflags &= ~HTP_DONTSTORE;

            SCLogDebug("header_end %p", header_end);
            SCLogDebug("form_end %p", form_end);

            /* everything until the final boundary is the file */
            if (form_end != NULL) {
                filedata = header_end + 4;
                if (form_end == filedata) {
                    HTPSetEvent(hstate, htud,
                            HTTP_DECODER_EVENT_MULTIPART_NO_FILEDATA);
                    goto end;
                } else if (form_end < filedata) {
                    HTPSetEvent(hstate, htud,
                            HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
                    goto end;
                }

                filedata_len = form_end - (header_end + 4 + 2);
                SCLogDebug("filedata_len %"PRIuMAX, (uintmax_t)filedata_len);

                /* or is it? */
                uint8_t *header_next = Bs2bmSearch(filedata, filedata_len,
                        expected_boundary, expected_boundary_len);
                if (header_next != NULL) {
                    filedata_len -= (form_end - header_next);
                }

                if (filedata_len > chunks_buffer_len) {
                    HTPSetEvent(hstate, htud,
                            HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
                    goto end;
                }
                SCLogDebug("filedata_len %"PRIuMAX, (uintmax_t)filedata_len);
#ifdef PRINT
                printf("FILEDATA START: \n");
                PrintRawDataFp(stdout, filedata, filedata_len);
                printf("FILEDATA END: \n");
#endif

                result = HTPFileOpen(hstate, filename, filename_len,
                            filedata, filedata_len, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                if (result == -1) {
                    goto end;
                } else if (result == -2) {
                    htud->tsflags |= HTP_DONTSTORE;
                } else {
                    if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                        goto end;
                    }
                }

                htud->request_body.body_parsed += (header_end - chunks_buffer);
                htud->tsflags &= ~HTP_FILENAME_SET;
            } else {
                SCLogDebug("chunk doesn't contain form end");

                filedata = header_end + 4;
                filedata_len = chunks_buffer_len - (filedata - chunks_buffer);
                SCLogDebug("filedata_len %u (chunks_buffer_len %u)", filedata_len, chunks_buffer_len);

                if (filedata_len > chunks_buffer_len) {
                    HTPSetEvent(hstate, htud,
                            HTTP_DECODER_EVENT_MULTIPART_GENERIC_ERROR);
                    goto end;
                }

#ifdef PRINT
                printf("FILEDATA START: \n");
                PrintRawDataFp(stdout, filedata, filedata_len);
                printf("FILEDATA END: \n");
#endif
                /* form doesn't end in this chunk, but part might. Lets
                 * see if have another coming up */
                uint8_t *header_next = Bs2bmSearch(filedata, filedata_len,
                        expected_boundary, expected_boundary_len);
                SCLogDebug("header_next %p", header_next);
                if (header_next == NULL) {
                    /* no, but we'll handle the file data when we see the
                     * form_end */

                    SCLogDebug("more file data to come");

                    uint32_t offset = (header_end + 4) - chunks_buffer;
                    SCLogDebug("offset %u", offset);
                    htud->request_body.body_parsed += offset;

                    result = HTPFileOpen(hstate, filename, filename_len,
                            NULL, 0, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->tsflags |= HTP_DONTSTORE;
                    }
                } else if (header_next - filedata > 2) {
                    filedata_len = header_next - filedata - 2;
                    SCLogDebug("filedata_len %u", filedata_len);

                    result = HTPFileOpen(hstate, filename, filename_len,
                            filedata, filedata_len, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->tsflags |= HTP_DONTSTORE;
                    } else {
                        if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                            goto end;
                        }
                    }

                    htud->tsflags &= ~HTP_FILENAME_SET;
                    htud->request_body.body_parsed += (header_end - chunks_buffer);
                }
            }
        }
next:
        SCLogDebug("header_start %p, header_end %p, form_end %p",
                header_start, header_end, form_end);

        /* Search next boundary entry after the start of body */
        uint32_t cursizeread = header_end - chunks_buffer;
        header_start = Bs2bmSearch(header_end + 4,
                chunks_buffer_len - (cursizeread + 4),
                expected_boundary, expected_boundary_len);
        if (header_start != NULL) {
            header_end = Bs2bmSearch(header_end + 4,
                    chunks_buffer_len - (cursizeread + 4),
                    (uint8_t *) "\r\n\r\n", 4);
        }
    }
end:
    if (expected_boundary != NULL) {
        HTPFree(expected_boundary, expected_boundary_len);
    }
    if (expected_boundary_end != NULL) {
        HTPFree(expected_boundary_end, expected_boundary_end_len);
    }

    SCLogDebug("htud->request_body.body_parsed %"PRIu64, htud->request_body.body_parsed);
    return 0;
}

/** \brief setup things for put request
 *  \todo really needed? */
int HtpRequestBodySetupPUT(htp_tx_data_t *d, HtpTxUserData *htud)
{
//    if (d->tx->parsed_uri == NULL || d->tx->parsed_uri->path == NULL) {
//        return -1;
//    }

    /* filename is d->tx->parsed_uri->path */

    return 0;
}

/** \internal
 *  \brief Handle POST, no multipart body data
 */
static int HtpRequestBodyHandlePOST(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{
    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tsflags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        if (filename != NULL) {
            result = HTPFileOpen(hstate, filename, (uint32_t)filename_len, data, data_len,
                    hstate->transaction_cnt, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tsflags |= HTP_DONTSTORE;
            } else {
                htud->tsflags |= HTP_FILENAME_SET;
                htud->tsflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tsflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOSERVER);
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

/** \internal
 *  \brief Handle PUT body data
 */
static int HtpRequestBodyHandlePUT(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{
    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tsflags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        if (filename != NULL) {
            result = HTPFileOpen(hstate, filename, (uint32_t)filename_len, data, data_len,
                    hstate->transaction_cnt, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tsflags |= HTP_DONTSTORE;
            } else {
                htud->tsflags |= HTP_FILENAME_SET;
                htud->tsflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tsflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOSERVER);
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

int HtpResponseBodyHandle(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{
    SCEnter();

    int result = 0;

    /* see if we need to open the file */
    if (!(htud->tcflags & HTP_FILENAME_SET))
    {
        SCLogDebug("setting up file name");

        uint8_t *filename = NULL;
        size_t filename_len = 0;

        /* try Content-Disposition header first */
        htp_header_t *h = (htp_header_t *)htp_table_get_c(tx->response_headers,
                "Content-Disposition");
        if (h != NULL && bstr_len(h->value) > 0) {
            /* parse content-disposition */
            (void)HTTPParseContentDispositionHeader((uint8_t *)"filename=", 9,
                    (uint8_t *) bstr_ptr(h->value), bstr_len(h->value), &filename, &filename_len);
        }

        /* fall back to name from the uri */
        if (filename == NULL) {
            /* get the name */
            if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
                filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
                filename_len = bstr_len(tx->parsed_uri->path);
            }
        }

        if (filename != NULL) {
            result = HTPFileOpen(hstate, filename, (uint32_t)filename_len,
                    data, data_len, hstate->transaction_cnt, STREAM_TOCLIENT);
            SCLogDebug("result %d", result);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                htud->tcflags |= HTP_DONTSTORE;
            } else {
                htud->tcflags |= HTP_FILENAME_SET;
                htud->tcflags &= ~HTP_DONTSTORE;
            }
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->tcflags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOCLIENT);
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
 * \retval int HTP_OK if all goes well
 */
int HTPCallbackRequestBodyData(htp_tx_data_t *d)
{
    SCEnter();

    if (!(SC_ATOMIC_GET(htp_config_flags) & HTP_REQUIRE_REQUEST_BODY))
        SCReturnInt(HTP_OK);

    if (d->data == NULL || d->len == 0)
        SCReturnInt(HTP_OK);

#ifdef PRINT
    printf("HTPBODY START: \n");
    PrintRawDataFp(stdout, (uint8_t *)d->data, d->len);
    printf("HTPBODY END: \n");
#endif

    HtpState *hstate = htp_connp_get_user_data(d->tx->connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    SCLogDebug("New request body data available at %p -> %p -> %p, bodylen "
               "%"PRIu32"", hstate, d, d->data, (uint32_t)d->len);

    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (tx_ud == NULL) {
        tx_ud = HTPMalloc(sizeof(HtpTxUserData));
        if (unlikely(tx_ud == NULL)) {
            SCReturnInt(HTP_OK);
        }
        memset(tx_ud, 0, sizeof(HtpTxUserData));

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, tx_ud);
    }
    if (!tx_ud->response_body_init) {
        tx_ud->response_body_init = 1;
        tx_ud->operation = HTP_BODY_REQUEST;

        if (d->tx->request_method_number == HTP_M_POST) {
            SCLogDebug("POST");
            int r = HtpRequestBodySetupMultipart(d, tx_ud);
            if (r == 1) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_MULTIPART;
            } else if (r == 0) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_POST;
                SCLogDebug("not multipart");
            }
        } else if (d->tx->request_method_number == HTP_M_PUT) {
            if (HtpRequestBodySetupPUT(d, tx_ud) == 0) {
                tx_ud->request_body_type = HTP_BODY_REQUEST_PUT;
            }
        }
    }

    SCLogDebug("tx_ud->request_body.content_len_so_far %"PRIu64, tx_ud->request_body.content_len_so_far);
    SCLogDebug("hstate->cfg->request_body_limit %u", hstate->cfg->request_body_limit);

    /* within limits, add the body chunk to the state. */
    if (hstate->cfg->request_body_limit == 0 || tx_ud->request_body.content_len_so_far < hstate->cfg->request_body_limit)
    {
        uint32_t len = (uint32_t)d->len;

        if (hstate->cfg->request_body_limit > 0 &&
                (tx_ud->request_body.content_len_so_far + len) > hstate->cfg->request_body_limit)
        {
            len = hstate->cfg->request_body_limit - tx_ud->request_body.content_len_so_far;
            BUG_ON(len > (uint32_t)d->len);
        }
        SCLogDebug("len %u", len);

        HtpBodyAppendChunk(tx_ud, &tx_ud->request_body, (uint8_t *)d->data, len);

        uint8_t *chunks_buffer = NULL;
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

            HtpRequestBodyHandleMultipart(hstate, tx_ud, d->tx, chunks_buffer, chunks_buffer_len);

            if (chunks_buffer != NULL) {
                HTPFree(chunks_buffer, chunks_buffer_len);
            }
        } else if (tx_ud->request_body_type == HTP_BODY_REQUEST_POST) {
            HtpRequestBodyHandlePOST(hstate, tx_ud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
        } else if (tx_ud->request_body_type == HTP_BODY_REQUEST_PUT) {
            HtpRequestBodyHandlePUT(hstate, tx_ud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
        }

    }

end:
    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(hstate, &tx_ud->request_body, STREAM_TOSERVER);

    /* set the new chunk flag */
    hstate->flags |= HTP_FLAG_NEW_BODY_SET;

    SCReturnInt(HTP_OK);
}

/**
 * \brief Function callback to append chunks for Responses
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HTP_OK if all goes well
 */
int HTPCallbackResponseBodyData(htp_tx_data_t *d)
{
    SCEnter();

    if (!(SC_ATOMIC_GET(htp_config_flags) & HTP_REQUIRE_RESPONSE_BODY))
        SCReturnInt(HTP_OK);

    if (d->data == NULL || d->len == 0)
        SCReturnInt(HTP_OK);

    HtpState *hstate = htp_connp_get_user_data(d->tx->connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    SCLogDebug("New response body data available at %p -> %p -> %p, bodylen "
               "%"PRIu32"", hstate, d, d->data, (uint32_t)d->len);

    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (tx_ud == NULL) {
        tx_ud = HTPMalloc(sizeof(HtpTxUserData));
        if (unlikely(tx_ud == NULL)) {
            SCReturnInt(HTP_OK);
        }
        memset(tx_ud, 0, sizeof(HtpTxUserData));

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, tx_ud);
    }
    if (!tx_ud->request_body_init) {
        tx_ud->request_body_init = 1;
        tx_ud->operation = HTP_BODY_RESPONSE;
    }

    SCLogDebug("tx_ud->response_body.content_len_so_far %"PRIu64, tx_ud->response_body.content_len_so_far);
    SCLogDebug("hstate->cfg->response_body_limit %u", hstate->cfg->response_body_limit);

    /* within limits, add the body chunk to the state. */
    if (hstate->cfg->response_body_limit == 0 || tx_ud->response_body.content_len_so_far < hstate->cfg->response_body_limit)
    {
        uint32_t len = (uint32_t)d->len;

        if (hstate->cfg->response_body_limit > 0 &&
                (tx_ud->response_body.content_len_so_far + len) > hstate->cfg->response_body_limit)
        {
            len = hstate->cfg->response_body_limit - tx_ud->response_body.content_len_so_far;
            BUG_ON(len > (uint32_t)d->len);
        }
        SCLogDebug("len %u", len);

        HtpBodyAppendChunk(tx_ud, &tx_ud->response_body, (uint8_t *)d->data, len);

        HtpResponseBodyHandle(hstate, tx_ud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
    }

    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(hstate, &tx_ud->response_body, STREAM_TOCLIENT);

    /* set the new chunk flag */
    hstate->flags |= HTP_FLAG_NEW_BODY_SET;

    SCReturnInt(HTP_OK);
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

/**
 *  \brief  callback for request to store the recent incoming request
            in to the recent_in_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackRequest(htp_tx_t *tx)
{
    SCEnter();

    if (tx == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    HtpState *hstate = htp_connp_get_user_data(tx->connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    SCLogDebug("transaction_cnt %"PRIu64", list_size %"PRIu64,
               hstate->transaction_cnt, HTPStateGetTxCnt(hstate));

    SCLogDebug("HTTP request completed");

    HTPErrorCheckTxRequestFlags(hstate, tx);

    HtpTxUserData *htud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (htud != NULL) {
        if (htud->tsflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER);
            htud->tsflags &= ~HTP_FILENAME_SET;
        }
    }

    /* request done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerParserTriggerRawStreamReassembly(hstate->f);
    SCReturnInt(HTP_OK);
}

/**
 *  \brief  callback for response to remove the recent received requests
            from the recent_in_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackResponse(htp_tx_t *tx)
{
    SCEnter();

    HtpState *hstate = htp_connp_get_user_data(tx->connp);
    if (hstate == NULL) {
        SCReturnInt(HTP_ERROR);
    }

    /* we have one whole transaction now */
    hstate->transaction_cnt++;

    /* Unset the body inspection (if any) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (htud != NULL) {
        if (htud->tcflags & HTP_FILENAME_SET) {
            SCLogDebug("closing file that was being stored");
            (void)HTPFileClose(hstate, NULL, 0, 0, STREAM_TOCLIENT);
            htud->tcflags &= ~HTP_FILENAME_SET;
        }
    }

    /* response done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerParserTriggerRawStreamReassembly(hstate->f);
    SCReturnInt(HTP_OK);
}

static int HTPCallbackRequestLine(htp_tx_t *tx)
{
    HtpTxUserData *tx_ud;
    bstr *request_uri_normalized;
    HtpState *hstate = htp_connp_get_user_data(tx->connp);
    HTPCfgRec *cfg = hstate->cfg;

    request_uri_normalized = SCHTPGenerateNormalizedUri(tx, tx->parsed_uri, cfg->uri_include_all);
    if (request_uri_normalized == NULL)
        return HTP_OK;

    tx_ud = htp_tx_get_user_data(tx);
    if (likely(tx_ud == NULL)) {
        tx_ud = HTPMalloc(sizeof(*tx_ud));
        if (unlikely(tx_ud == NULL)) {
            bstr_free(request_uri_normalized);
            return HTP_OK;
        }
        memset(tx_ud, 0, sizeof(*tx_ud));
        htp_tx_set_user_data(tx, tx_ud);
    }
    if (unlikely(tx_ud->request_uri_normalized != NULL))
        bstr_free(tx_ud->request_uri_normalized);
    tx_ud->request_uri_normalized = request_uri_normalized;

    if (tx->flags) {
        HTPErrorCheckTxRequestFlags(hstate, tx);
    }
    return HTP_OK;
}

static int HTPCallbackDoubleDecodeQuery(htp_tx_t *tx)
{
    if (tx->parsed_uri == NULL || tx->parsed_uri->query == NULL)
        return HTP_OK;

    uint64_t flags = 0;
    htp_urldecode_inplace(tx->cfg, HTP_DECODER_URLENCODED, tx->parsed_uri->query, &flags);

    return HTP_OK;
}

static int HTPCallbackDoubleDecodePath(htp_tx_t *tx)
{
    if (tx->parsed_uri == NULL || tx->parsed_uri->path == NULL)
        return HTP_OK;

    uint64_t flags = 0;
    htp_urldecode_inplace(tx->cfg, HTP_DECODER_URL_PATH, tx->parsed_uri->path, &flags);

    return HTP_OK;
}

static int HTPCallbackRequestHeaderData(htp_tx_data_t *tx_data)
{
    void *ptmp;
    if (tx_data->len == 0)
        return HTP_OK;

    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx_data->tx);
    if (tx_ud == NULL) {
        tx_ud = HTPMalloc(sizeof(*tx_ud));
        if (unlikely(tx_ud == NULL))
            return HTP_OK;
        memset(tx_ud, 0, sizeof(*tx_ud));
        htp_tx_set_user_data(tx_data->tx, tx_ud);
    }
    ptmp = HTPRealloc(tx_ud->request_headers_raw,
                     tx_ud->request_headers_raw_len,
                     tx_ud->request_headers_raw_len + tx_data->len);
    if (ptmp == NULL) {
        /* error: we're freeing the entire user data */
        HtpState *hstate = htp_connp_get_user_data(tx_data->tx->connp);
        HtpTxUserDataFree(hstate, tx_ud);
        htp_tx_set_user_data(tx_data->tx, NULL);
        return HTP_OK;
    }
    tx_ud->request_headers_raw = ptmp;

    memcpy(tx_ud->request_headers_raw + tx_ud->request_headers_raw_len,
           tx_data->data, tx_data->len);
    tx_ud->request_headers_raw_len += tx_data->len;

    if (tx_data->tx && tx_data->tx->flags) {
        HtpState *hstate = htp_connp_get_user_data(tx_data->tx->connp);
        HTPErrorCheckTxRequestFlags(hstate, tx_data->tx);
    }
    return HTP_OK;
}

static int HTPCallbackResponseHeaderData(htp_tx_data_t *tx_data)
{
    void *ptmp;
    if (tx_data->len == 0)
        return HTP_OK;

    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx_data->tx);
    if (tx_ud == NULL) {
        tx_ud = HTPMalloc(sizeof(*tx_ud));
        if (unlikely(tx_ud == NULL))
            return HTP_OK;
        memset(tx_ud, 0, sizeof(*tx_ud));
        htp_tx_set_user_data(tx_data->tx, tx_ud);
    }
    ptmp = HTPRealloc(tx_ud->response_headers_raw,
                     tx_ud->response_headers_raw_len,
                     tx_ud->response_headers_raw_len + tx_data->len);
    if (ptmp == NULL) {
        /* error: we're freeing the entire user data */
        HtpState *hstate = htp_connp_get_user_data(tx_data->tx->connp);
        HtpTxUserDataFree(hstate, tx_ud);
        htp_tx_set_user_data(tx_data->tx, NULL);
        return HTP_OK;
    }
    tx_ud->response_headers_raw = ptmp;

    memcpy(tx_ud->response_headers_raw + tx_ud->response_headers_raw_len,
           tx_data->data, tx_data->len);
    tx_ud->response_headers_raw_len += tx_data->len;

    return HTP_OK;
}

/*
 * We have a similar set function called HTPConfigSetDefaultsPhase1.
 */
static void HTPConfigSetDefaultsPhase1(HTPCfgRec *cfg_prec)
{
    cfg_prec->uri_include_all = FALSE;
    cfg_prec->request_body_limit = HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT;
    cfg_prec->response_body_limit = HTP_CONFIG_DEFAULT_RESPONSE_BODY_LIMIT;
    cfg_prec->request_inspect_min_size = HTP_CONFIG_DEFAULT_REQUEST_INSPECT_MIN_SIZE;
    cfg_prec->request_inspect_window = HTP_CONFIG_DEFAULT_REQUEST_INSPECT_WINDOW;
    cfg_prec->response_inspect_min_size = HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_MIN_SIZE;
    cfg_prec->response_inspect_window = HTP_CONFIG_DEFAULT_RESPONSE_INSPECT_WINDOW;
    cfg_prec->randomize = HTP_CONFIG_DEFAULT_RANDOMIZE;
    cfg_prec->randomize_range = HTP_CONFIG_DEFAULT_RANDOMIZE_RANGE;

    htp_config_register_request_header_data(cfg_prec->cfg, HTPCallbackRequestHeaderData);
    htp_config_register_request_trailer_data(cfg_prec->cfg, HTPCallbackRequestHeaderData);
    htp_config_register_response_header_data(cfg_prec->cfg, HTPCallbackResponseHeaderData);
    htp_config_register_response_trailer_data(cfg_prec->cfg, HTPCallbackResponseHeaderData);

    htp_config_register_request_body_data(cfg_prec->cfg, HTPCallbackRequestBodyData);
    htp_config_register_response_body_data(cfg_prec->cfg, HTPCallbackResponseBodyData);

    htp_config_register_request_complete(cfg_prec->cfg, HTPCallbackRequest);
    htp_config_register_response_complete(cfg_prec->cfg, HTPCallbackResponse);

    htp_config_set_parse_request_cookies(cfg_prec->cfg, 0);
    htp_config_set_parse_request_auth(cfg_prec->cfg, 0);

    /* don't convert + to space by default */
    htp_config_set_plusspace_decode(cfg_prec->cfg, HTP_DECODER_URLENCODED, 0);

    /* libhtp <= 0.5.9 doesn't use soft limit, but it's impossible to set
     * only the hard limit. So we set both here to the (current) htp defaults.
     * The reason we do this is that if the user sets the hard limit in the
     * config, we have to set the soft limit as well. If libhtp starts using
     * the soft limit in the future, we at least make sure we control what
     * it's value is. */
    htp_config_set_field_limits(cfg_prec->cfg,
            (size_t)HTP_CONFIG_DEFAULT_FIELD_LIMIT_SOFT,
            (size_t)HTP_CONFIG_DEFAULT_FIELD_LIMIT_HARD);
    return;
}

/*
 * We have this splitup so that in case double decoding has been enabled
 * for query and path, they would be called first on the callback queue,
 * before the callback set by Phase2() is called.  We need this, since
 * the callback in Phase2() generates the normalized uri which utilizes
 * the query and path. */
static void HTPConfigSetDefaultsPhase2(char *name, HTPCfgRec *cfg_prec)
{
    /* randomize inspection size if needed */
    if (cfg_prec->randomize) {
        int rdrange = cfg_prec->randomize_range;

        cfg_prec->request_inspect_min_size +=
            (int) (cfg_prec->request_inspect_min_size *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
        cfg_prec->request_inspect_window +=
            (int) (cfg_prec->request_inspect_window *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
        SCLogInfo("'%s' server has 'request-body-minimal-inspect-size' set to"
                  " %d and 'request-body-inspect-window' set to %d after"
                  " randomization.",
                  name,
                  cfg_prec->request_inspect_min_size,
                  cfg_prec->request_inspect_window);


        cfg_prec->response_inspect_min_size +=
            (int) (cfg_prec->response_inspect_min_size *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);
        cfg_prec->response_inspect_window +=
            (int) (cfg_prec->response_inspect_window *
                   (random() * 1.0 / RAND_MAX - 0.5) * rdrange / 100);

        SCLogInfo("'%s' server has 'response-body-minimal-inspect-size' set to"
                  " %d and 'response-body-inspect-window' set to %d after"
                  " randomization.",
                  name,
                  cfg_prec->response_inspect_min_size,
                  cfg_prec->response_inspect_window);
    }

    htp_config_register_request_line(cfg_prec->cfg, HTPCallbackRequestLine);

    return;
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
                    if (SCRadixAddKeyIPV6String(pval->val, tree, cfg_prec) == NULL) {
                        SCLogWarning(SC_ERR_INVALID_VALUE, "LIBHTP failed to "
                                     "add ipv6 server %s, ignoring", pval->val);
                    }
                } else {
                    SCLogDebug("LIBHTP adding ipv4 server %s at %s: %p",
                               s->name, pval->val, cfg_prec->cfg);
                    if (SCRadixAddKeyIPV4String(pval->val, tree, cfg_prec) == NULL) {
                            SCLogWarning(SC_ERR_INVALID_VALUE, "LIBHTP failed "
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
                if (htp_config_set_server_personality(cfg_prec->cfg, personality) == HTP_ERROR){
                    SCLogWarning(SC_ERR_INVALID_VALUE, "LIBHTP Failed adding "
                                 "personality \"%s\", ignoring", p->val);
                } else {
                    SCLogDebug("LIBHTP personality set to %s",
                               HTPLookupPersonalityString(personality));
                }

                /* The IDS personality by default converts the path (and due to
                 * our query string callback also the query string) to lowercase.
                 * Signatures do not expect this, so override it. */
                htp_config_set_convert_lowercase(cfg_prec->cfg, HTP_DECODER_URL_PATH, 0);
            } else {
                SCLogWarning(SC_ERR_UNKNOWN_VALUE, "LIBHTP Unknown personality "
                             "\"%s\", ignoring", p->val);
                continue;
            }

        } else if (strcasecmp("request-body-limit", p->name) == 0 ||
                   strcasecmp("request_body_limit", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request_body_limit) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing request-body-limit "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("response-body-limit", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response_body_limit) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing response-body-limit "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("request-body-minimal-inspect-size", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request_inspect_min_size) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing request-body-minimal-inspect-size "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("request-body-inspect-window", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->request_inspect_window) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing request-body-inspect-window "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("double-decode-path", p->name) == 0) {
            if (ConfValIsTrue(p->val)) {
                htp_config_register_request_line(cfg_prec->cfg,
                                                 HTPCallbackDoubleDecodeQuery);
            }

        } else if (strcasecmp("double-decode-query", p->name) == 0) {
            if (ConfValIsTrue(p->val)) {
                htp_config_register_request_line(cfg_prec->cfg,
                                                 HTPCallbackDoubleDecodePath);
            }

        } else if (strcasecmp("response-body-minimal-inspect-size", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response_inspect_min_size) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing response-body-minimal-inspect-size "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("response-body-inspect-window", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &cfg_prec->response_inspect_window) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error parsing response-body-inspect-window "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }

        } else if (strcasecmp("path-convert-backslash-separators", p->name) == 0) {
            htp_config_set_backslash_convert_slashes(cfg_prec->cfg,
                                                     HTP_DECODER_URL_PATH,
                                                     ConfValIsTrue(p->val));
        } else if (strcasecmp("path-bestfit-replacement-char", p->name) == 0) {
            if (strlen(p->val) == 1) {
                htp_config_set_bestfit_replacement_byte(cfg_prec->cfg,
                                                        HTP_DECODER_URL_PATH,
                                                        p->val[0]);
            } else {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry "
                           "for libhtp param path-bestfit-replacement-char");
            }
        } else if (strcasecmp("path-convert-lowercase", p->name) == 0) {
            htp_config_set_convert_lowercase(cfg_prec->cfg,
                                             HTP_DECODER_URL_PATH,
                                             ConfValIsTrue(p->val));
        } else if (strcasecmp("path-nul-encoded-terminates", p->name) == 0) {
            htp_config_set_nul_encoded_terminates(cfg_prec->cfg,
                                                  HTP_DECODER_URL_PATH,
                                                  ConfValIsTrue(p->val));
        } else if (strcasecmp("path-nul-raw-terminates", p->name) == 0) {
            htp_config_set_nul_raw_terminates(cfg_prec->cfg,
                                              HTP_DECODER_URL_PATH,
                                              ConfValIsTrue(p->val));
        } else if (strcasecmp("path-separators-compress", p->name) == 0) {
            htp_config_set_path_separators_compress(cfg_prec->cfg,
                                                    HTP_DECODER_URL_PATH,
                                                    ConfValIsTrue(p->val));
        } else if (strcasecmp("path-separators-decode", p->name) == 0) {
            htp_config_set_path_separators_decode(cfg_prec->cfg,
                                                  HTP_DECODER_URL_PATH,
                                                  ConfValIsTrue(p->val));
        } else if (strcasecmp("path-u-encoding-decode", p->name) == 0) {
            htp_config_set_u_encoding_decode(cfg_prec->cfg,
                                             HTP_DECODER_URL_PATH,
                                             ConfValIsTrue(p->val));
        } else if (strcasecmp("path-url-encoding-invalid-handling", p->name) == 0) {
            enum htp_url_encoding_handling_t handling;
            if (strcasecmp(p->val, "preserve_percent") == 0) {
                handling = HTP_URL_DECODE_PRESERVE_PERCENT;
            } else if (strcasecmp(p->val, "remove_percent") == 0) {
                handling = HTP_URL_DECODE_REMOVE_PERCENT;
            } else if (strcasecmp(p->val, "decode_invalid") == 0) {
                handling = HTP_URL_DECODE_PROCESS_INVALID;
            } else {
                SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid entry "
                           "for libhtp param path-url-encoding-invalid-handling");
                return;
            }
            htp_config_set_url_encoding_invalid_handling(cfg_prec->cfg,
                                                         HTP_DECODER_URL_PATH,
                                                         handling);
        } else if (strcasecmp("path-utf8-convert-bestfit", p->name) == 0) {
            htp_config_set_utf8_convert_bestfit(cfg_prec->cfg,
                                                HTP_DECODER_URL_PATH,
                                                ConfValIsTrue(p->val));
        } else if (strcasecmp("uri-include-all", p->name) == 0) {
            cfg_prec->uri_include_all = ConfValIsTrue(p->val);
            SCLogDebug("uri-include-all %s",
                    cfg_prec->uri_include_all ? "enabled" : "disabled");
        } else if (strcasecmp("query-plusspace-decode", p->name) == 0) {
            htp_config_set_plusspace_decode(cfg_prec->cfg,
                                                HTP_DECODER_URLENCODED,
                                                ConfValIsTrue(p->val));
        } else if (strcasecmp("meta-field-limit", p->name) == 0) {
            uint32_t limit = 0;
            if (ParseSizeStringU32(p->val, &limit) < 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error meta-field-limit "
                           "from conf file - %s.  Killing engine", p->val);
                exit(EXIT_FAILURE);
            }
            if (limit == 0) {
                SCLogError(SC_ERR_SIZE_PARSE, "Error meta-field-limit "
                           "from conf file cannot be 0.  Killing engine");
                exit(EXIT_FAILURE);
            }
            /* set default soft-limit with our new hard limit */
            htp_config_set_field_limits(cfg_prec->cfg,
                    (size_t)HTP_CONFIG_DEFAULT_FIELD_LIMIT_SOFT,
                    (size_t)limit);
        } else if (strcasecmp("randomize-inspection-sizes", p->name) == 0) {
            cfg_prec->randomize = ConfValIsTrue(p->val);
        } else if (strcasecmp("randomize-inspection-range", p->name) == 0) {
            uint32_t range = atoi(p->val);
            if (range > 100) {
                SCLogError(SC_ERR_SIZE_PARSE, "Invalid value for randomize"
                           " inspection range setting from conf file - %s."
                           " It should be inferior to 100."
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
        } else {
            SCLogWarning(SC_ERR_UNKNOWN_VALUE, "LIBHTP Ignoring unknown "
                         "default config: %s", p->name);
        }
    } /* TAILQ_FOREACH(p, &default_config->head, next) */

    return;
}

void HTPConfigure(void)
{
    SCEnter();

    cfglist.next = NULL;

    cfgtree = SCRadixCreateRadixTree(NULL, NULL);
    if (NULL == cfgtree)
        exit(EXIT_FAILURE);

    /* Default Config */
    cfglist.cfg = htp_config_create();
    if (NULL == cfglist.cfg) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to create HTP default config");
        exit(EXIT_FAILURE);
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
        HTPCfgRec *htprec = SCMalloc(sizeof(HTPCfgRec));
        if (NULL == htprec)
            exit(EXIT_FAILURE);
        memset(htprec, 0x00, sizeof(*htprec));

        cfglist.next = htprec;

        cfglist.next->next = nextrec;
        cfglist.next->cfg = htp_config_create();
        if (NULL == cfglist.next->cfg) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to create HTP server config");
            exit(EXIT_FAILURE);
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
    SCLogInfo("htp memory %"PRIu64" (%"PRIu64")", htp_state_memuse, htp_state_memcnt);
    SCMutexUnlock(&htp_state_mem_lock);
#endif
}

/** \internal
 *  \brief get files callback
 *  \param state state ptr
 *  \param direction flow direction
 *  \retval files files ptr
 */
static FileContainer *HTPStateGetFiles(void *state, uint8_t direction)
{
    if (state == NULL)
        return NULL;

    HtpState *http_state = (HtpState *)state;

    if (direction & STREAM_TOCLIENT) {
        SCReturnPtr(http_state->files_tc, "FileContainer");
    } else {
        SCReturnPtr(http_state->files_ts, "FileContainer");
    }
}

static int HTPStateGetAlstateProgress(void *tx, uint8_t direction)
{
    if (direction & STREAM_TOSERVER)
        return ((htp_tx_t *)tx)->request_progress;
    else
        return ((htp_tx_t *)tx)->response_progress;
}

static uint64_t HTPStateGetTxCnt(void *alstate)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->conn != NULL)
        return (uint64_t)htp_list_size(http_state->conn->transactions);
    else
        return 0ULL;
}

static void *HTPStateGetTx(void *alstate, uint64_t tx_id)
{
    HtpState *http_state = (HtpState *)alstate;

    if (http_state != NULL && http_state->conn != NULL)
        return htp_list_get(http_state->conn->transactions, tx_id);
    else
        return NULL;
}

static int HTPStateGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return (direction & STREAM_TOSERVER) ? HTP_REQUEST_COMPLETE : HTP_RESPONSE_COMPLETE;
}

int HTPStateGetEventInfo(const char *event_name,
                         int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, http_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "http's enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static void HTPStateTruncate(void *state, uint8_t direction)
{
    FileContainer *fc = HTPStateGetFiles(state, direction);
    if (fc != NULL) {
        FileTruncateAllOpenFiles(fc);
    }
}

static int HTPStateHasTxDetectState(void *alstate)
{
    HtpState *htp_state = (HtpState *)alstate;
    return (htp_state->tx_with_detect_state_cnt > 0);
}

static DetectEngineState *HTPGetTxDetectState(void *vtx)
{
    htp_tx_t *tx = (htp_tx_t *)vtx;
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    return tx_ud ? tx_ud->de_state : NULL;
}

static int HTPSetTxDetectState(void *alstate, void *vtx, DetectEngineState *s)
{
    HtpState *htp_state = (HtpState *)alstate;
    htp_tx_t *tx = (htp_tx_t *)vtx;
    HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
    if (tx_ud == NULL) {
        tx_ud = HTPMalloc(sizeof(*tx_ud));
        if (unlikely(tx_ud == NULL))
            return -ENOMEM;
        memset(tx_ud, 0, sizeof(*tx_ud));
        htp_tx_set_user_data(tx, tx_ud);
    }
    htp_state->tx_with_detect_state_cnt++;
    tx_ud->de_state = s;
    return 0;
}

static int HTPRegisterPatternsForProtocolDetection(void)
{
    char *methods[] = { "GET", "PUT", "POST", "HEAD", "TRACE", "OPTIONS",
        "CONNECT", "DELETE", "PATCH", "PROPFIND", "PROPPATCH", "MKCOL",
        "COPY", "MOVE", "LOCK", "UNLOCK", "CHECKOUT", "UNCHECKOUT", "CHECKIN",
        "UPDATE", "LABEL", "REPORT", "MKWORKSPACE", "MKACTIVITY", "MERGE",
        "INVALID", "VERSION-CONTROL", "BASELINE-CONTROL", NULL};
    char *spacings[] = { "|20|", "|09|", NULL };
    char *versions[] = { "HTTP/0.9", "HTTP/1.0", "HTTP/1.1", NULL };

    uint methods_pos;
    uint spacings_pos;
    uint versions_pos;
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
            register_result = AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP,
                    ALPROTO_HTTP, method_buffer, strlen(method_buffer)-3, 0, STREAM_TOSERVER);
            if (register_result < 0) {
                return -1;
            }
        }
    }

    /* Loop through all the http verions patterns that are TO_CLIENT */
    for (versions_pos = 0; versions[versions_pos]; versions_pos++) {
        register_result = AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP,
                ALPROTO_HTTP, versions[versions_pos], strlen(versions[versions_pos]),
                0, STREAM_TOCLIENT);
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

    char *proto_name = "http";

    /** HTTP */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_HTTP, proto_name);
        if (HTPRegisterPatternsForProtocolDetection() < 0)
            return;
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_HTTP, HTPStateAlloc, HTPStateFree);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPStateTransactionFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPStateGetFiles);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, HTPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_HTTP, HTPStateGetTx);
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP, ALPROTO_HTTP,
                                                               HTPStateGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPHasEvents);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPGetEvents);
        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_HTTP, HTPStateGetEventInfo);

        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_HTTP, HTPStateTruncate);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_HTTP,
                                               HTPStateHasTxDetectState,
                                               HTPGetTxDetectState, HTPSetTxDetectState);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_HTTP, STREAM_TOSERVER,
                                     HTPHandleRequestData);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_HTTP, STREAM_TOCLIENT,
                                     HTPHandleResponseData);
        SC_ATOMIC_INIT(htp_config_flags);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_HTTP, STREAM_TOSERVER);
        HTPConfigure();
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_HTTP, HTPParserRegisterTests);
#endif

    SCReturn;
}

#ifdef UNITTESTS
static HTPCfgRec cfglist_backup;

void HtpConfigCreateBackup(void)
{
    cfglist_backup = cfglist;

    return;
}

void HtpConfigRestoreBackup(void)
{
    cfglist = cfglist_backup;

    return;
}

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
int HTPParserTest01(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (strcmp(bstr_util_strdup_to_c(h->value), "Victor/1.0")
        || tx->request_method_number != HTP_M_POST ||
        tx->request_protocol_number != HTP_PROTOCOL_1_0)
    {
        printf("expected header value: Victor/1.0 and got %s: and expected"
                " method: POST and got %s, expected protocol number HTTP/1.0"
                "  and got: %s \n", bstr_util_strdup_to_c(h->value),
                bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
static int HTPParserTest01a(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = " POST  /  HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (strcmp(bstr_util_strdup_to_c(h->value), "Victor/1.0")
        || tx->request_method_number != HTP_M_POST ||
        tx->request_protocol_number != HTP_PROTOCOL_1_0)
    {
        printf("expected header value: Victor/1.0 and got %s: and expected"
                " method: POST and got %s, expected protocol number HTTP/1.0"
                "  and got: %s \n", bstr_util_strdup_to_c(h->value),
                bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test See how it deals with an incomplete request. */
int HTPParserTest02(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                                STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if ((tx->request_method) != NULL || h != NULL)
    {
        printf("expected method NULL, got %s \n", bstr_util_strdup_to_c(tx->request_method));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test case where method is invalid and data is sent in smaller chunks
 *        and check the response of the parser from HTP library. */
int HTPParserTest03(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "HELLO / HTTP/1.0\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }
    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);

    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_UNKNOWN ||
        h != NULL || tx->request_protocol_number != HTP_PROTOCOL_1_0)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test case where invalid data is sent and check the response of the
 *        parser from HTP library. */
int HTPParserTest04(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "World!\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                            STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_UNKNOWN ||
        h != NULL || tx->request_protocol_number != HTP_PROTOCOL_0_9)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "NULL and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test both sides of a http stream mixed up to see if the HTP parser
 *        properly parsed them and also keeps them separated. */
int HTPParserTest05(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\n";
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                                httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf4,
                            httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3,
                            httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_EOF, httpbuf6,
                            httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_POST ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_0)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.0 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test proper chunked encoded response body
 */
int HTPParserTest06(void)
{
    int result = 0;
    Flow *f = NULL;
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
    HtpState *http_state = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                                httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                            httplen2);
    if (r != 0) {
        printf("toclient chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_GET ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200 ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected response 200 OK and got %"PRId32" %s: , expected proto"
                "col HTTP/1.1 and got %s \n", tx->response_status_number,
                bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test
 */
int HTPParserTest07(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /awstats.pl?/migratemigrate%20=%20| HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref[] = "/awstats.pl?/migratemigrate = |";
    size_t reflen = sizeof(ref) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

#include "conf-yaml-loader.h"

/** \test Abort
 */
int HTPParserTest08(void)
{
    int result = 0;
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

    HtpState *htp_state =  NULL;
    int r = 0;
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint8_t flags = 0;
    flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk returned %" PRId32 ", expected"
                " 0: ", r);
        result = 0;
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        //printf("uri %s\n", bstr_util_strdup_to_c(tx->request_uri_normalized));
        PrintRawDataFp(stdout, bstr_ptr(tx_ud->request_uri_normalized),
                       bstr_len(tx_ud->request_uri_normalized));
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);

    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    UTHFreeFlow(f);
    return result;
}

/** \test Abort
 */
int HTPParserTest09(void)
{
    int result = 0;
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

    HtpState *htp_state =  NULL;
    int r = 0;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint8_t flags = 0;
    flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk returned %" PRId32 ", expected"
                " 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        //printf("uri %s\n", bstr_util_strdup_to_c(tx->request_uri_normalized));
        PrintRawDataFp(stdout, bstr_ptr(tx_ud->request_uri_normalized),
                       bstr_len(tx_ud->request_uri_normalized));
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);

    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    UTHFreeFlow(f);
    return result;
}

/** \test Host:www.google.com <- missing space between name:value (rfc violation)
 */
int HTPParserTest10(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nHost:www.google.com\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (h == NULL) {
        goto end;
    }

    char *name = bstr_util_strdup_to_c(h->name);
    if (name == NULL) {
        goto end;
    }

    if (strcmp(name, "Host") != 0) {
        printf("header name not \"Host\", instead \"%s\": ", name);
        free(name);
        goto end;
    }
    free(name);

    char *value = bstr_util_strdup_to_c(h->value);
    if (value == NULL) {
        goto end;
    }

    if (strcmp(value, "www.google.com") != 0) {
        printf("header value not \"www.google.com\", instead \"%s\": ", value);
        free(value);
        goto end;
    }
    free(value);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test double encoding in path
 */
static int HTPParserTest11(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /%2500 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx != NULL && tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (4 != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be 2, is %"PRIuMAX,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (bstr_ptr(tx_ud->request_uri_normalized)[0] != '/' ||
            bstr_ptr(tx_ud->request_uri_normalized)[1] != '%' ||
            bstr_ptr(tx_ud->request_uri_normalized)[2] != '0' ||
            bstr_ptr(tx_ud->request_uri_normalized)[3] != '0')
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\": ");
            goto end;
        }
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test double encoding in query
 */
static int HTPParserTest12(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /?a=%2500 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (7 != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be 5, is %"PRIuMAX,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (bstr_ptr(tx_ud->request_uri_normalized)[0] != '/' ||
            bstr_ptr(tx_ud->request_uri_normalized)[1] != '?' ||
            bstr_ptr(tx_ud->request_uri_normalized)[2] != 'a' ||
            bstr_ptr(tx_ud->request_uri_normalized)[3] != '=' ||
            bstr_ptr(tx_ud->request_uri_normalized)[4] != '%' ||
            bstr_ptr(tx_ud->request_uri_normalized)[5] != '0' ||
            bstr_ptr(tx_ud->request_uri_normalized)[6] != '0')
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\": ");
            goto end;
        }
    }

    result = 1;
 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Host:www.google.com0dName: Value0d0a <- missing space between name:value (rfc violation)
 */
int HTPParserTest13(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET / HTTP/1.0\r\nHost:www.google.com\rName: Value\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0)
            flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1))
            flags = STREAM_TOSERVER|STREAM_EOF;
        else
            flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (h == NULL) {
        goto end;
    }

    char *name = bstr_util_strdup_to_c(h->name);
    if (name == NULL) {
        goto end;
    }

    if (strcmp(name, "Host") != 0) {
        printf("header name not \"Host\", instead \"%s\": ", name);
        free(name);
        goto end;
    }
    free(name);

    char *value = bstr_util_strdup_to_c(h->value);
    if (value == NULL) {
        goto end;
    }

    if (strcmp(value, "www.google.com\rName: Value") != 0) {
        printf("header value not \"www.google.com\", instead \"");
        PrintRawUriFp(stdout, (uint8_t *)value, strlen(value));
        printf("\": ");
        free(value);
        goto end;
    }
    free(value);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test basic config */
int HTPParserConfigTest01(void)
{
    int ret = 0;
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
    if (outputs == NULL) {
        goto end;
    }

    outputs = ConfGetNode("libhtp.server-config");
    if (outputs == NULL) {
        goto end;
    }

    ConfNode *node = TAILQ_FIRST(&outputs->head);
    if (node == NULL) {
        goto end;
    }
    if (strcmp(node->name, "0") != 0) {
        goto end;
    }
    node = TAILQ_FIRST(&node->head);
    if (node == NULL) {
        goto end;
    }
    if (strcmp(node->name, "apache-tomcat") != 0) {
        goto end;
    }

    int i = 0;
    ConfNode *n;

    ConfNode *node2 = ConfNodeLookupChild(node, "personality");
    if (node2 == NULL) {
        goto end;
    }
    if (strcmp(node2->val, "Tomcat_6_0") != 0) {
        goto end;
    }

    node = ConfNodeLookupChild(node, "address");
    if (node == NULL) {
        goto end;
    }
    TAILQ_FOREACH(n, &node->head, next) {
        if (n == NULL) {
            goto end;
        }

        switch(i) {
            case 0:
                if (strcmp(n->name, "0") != 0) {
                    goto end;
                }
                if (strcmp(n->val, "192.168.1.0/24") != 0) {
                    goto end;
                }
                break;
            case 1:
                if (strcmp(n->name, "1") != 0) {
                    goto end;
                }
                if (strcmp(n->val, "127.0.0.0/8") != 0) {
                    goto end;
                }
                break;
            case 2:
                if (strcmp(n->name, "2") != 0) {
                    goto end;
                }
                if (strcmp(n->val, "::1") != 0) {
                    goto end;
                }
                break;
            default:
                goto end;
        }
        i++;
    }

    outputs = ConfGetNode("libhtp.server-config");
    if (outputs == NULL) {
        goto end;
    }

    node = TAILQ_FIRST(&outputs->head);
    node = TAILQ_NEXT(node, next);
    if (node == NULL) {
        goto end;
    }
    if (strcmp(node->name, "1") != 0) {
        goto end;
    }
    node = TAILQ_FIRST(&node->head);
    if (node == NULL) {
        goto end;
    }
    if (strcmp(node->name, "iis7") != 0) {
        goto end;
    }

    node2 = ConfNodeLookupChild(node, "personality");
    if (node2 == NULL) {
        goto end;
    }
    if (strcmp(node2->val, "IIS_7_0") != 0) {
        goto end;
    }

    node = ConfNodeLookupChild(node, "address");
    if (node == NULL) {
        goto end;
    }

    i = 0;
    TAILQ_FOREACH(n, &node->head, next) {
        if (n == NULL) {
            goto end;
        }

        switch(i) {
            case 0:
                if (strcmp(n->name, "0") != 0) {
                    goto end;
                }
                if (strcmp(n->val, "192.168.0.0/24") != 0) {
                    goto end;
                }
                break;
            case 1:
                if (strcmp(n->name, "1") != 0) {
                    goto end;
                }
                if (strcmp(n->val, "192.168.10.0/24") != 0) {
                    goto end;
                }
                break;
            default:
                goto end;
        }
        i++;
    }

    ret = 1;

end:
    ConfDeInit();
    ConfRestoreContextBackup();

    return ret;
}

/** \test Test config builds radix correctly */
int HTPParserConfigTest02(void)
{
    int ret = 0;
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

    if (cfglist.cfg == NULL) {
        printf("No default config created.\n");
        goto end;
    }

    if (cfgtree == NULL) {
        printf("No config tree created.\n");
        goto end;
    }

    htp_cfg_t *htp = cfglist.cfg;
    uint8_t buf[128];
    const char *addr;
    void *user_data = NULL;

    addr = "192.168.10.42";
    if (inet_pton(AF_INET, addr, buf) == 1) {
        (void)SCRadixFindKeyIPV4BestMatch(buf, cfgtree, &user_data);
        if (user_data != NULL) {
            HTPCfgRec *htp_cfg_rec = user_data;
            htp = htp_cfg_rec->cfg;
            SCLogDebug("LIBHTP using config: %p", htp);
        }
        if (htp == NULL) {
            printf("Could not get config for: %s\n", addr);
            goto end;
        }
    }
    else {
        printf("Failed to parse address: %s\n", addr);
        goto end;
    }

    user_data = NULL;
    addr = "::1";
    if (inet_pton(AF_INET6, addr, buf) == 1) {
        (void)SCRadixFindKeyIPV6BestMatch(buf, cfgtree, &user_data);
        if (user_data != NULL) {
            HTPCfgRec *htp_cfg_rec = user_data;
            htp = htp_cfg_rec->cfg;
            SCLogDebug("LIBHTP using config: %p", htp);
        }
        if (htp == NULL) {
            printf("Could not get config for: %s\n", addr);
            goto end;
        }
    }
    else {
        printf("Failed to parse address: %s\n", addr);
        goto end;
    }

    ret = 1;

end:
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    return ret;
}

/** \test Test traffic is handled by the correct htp config */
int HTPParserConfigTest03(void)
{
    int result = 1;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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

    char *addr = "192.168.10.42";

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    htp_cfg_t *htp = cfglist.cfg;

    void *user_data = NULL;
    (void)SCRadixFindKeyIPV4BestMatch((uint8_t *)f->dst.addr_data32, cfgtree, &user_data);
    if (user_data != NULL) {
        HTPCfgRec *htp_cfg_rec = user_data;
        htp = htp_cfg_rec->cfg;
        SCLogDebug("LIBHTP using config: %p", htp);
    }
    if (htp == NULL) {
        printf("Could not get config for: %s\n", addr);
        goto end;
    }

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    if (HTPStateGetTxCnt(htp_state) != 2) {
        printf("HTPStateGetTxCnt(htp_state) failure\n");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    if (tx->cfg != htp) {
        printf("wrong HTP config (%p instead of %p - default=%p): ",
               tx->cfg, htp, cfglist.cfg);
        goto end;
    }
    tx = HTPStateGetTx(htp_state, 1);
    if (tx == NULL)
        goto end;
    if (tx->cfg != htp) {
        printf("wrong HTP config (%p instead of %p - default=%p): ",
               tx->cfg, htp, cfglist.cfg);
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/* disabled when we upgraded to libhtp 0.5.x */
#if 0
int HTPParserConfigTest04(void)
{
    int result = 0;

    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
    personality: IDS\n\
    path-control-char-handling: status_400\n\
    path-convert-utf8: yes\n\
    path-invalid-encoding-handling: remove_percent\n\
\n\
  server-config:\n\
\n\
    - apache-tomcat:\n\
        personality: Tomcat_6_0\n\
        path-invalid-utf8-handling: none\n\
        path-nul-encoded-handling: status_404\n\
        path-nul-raw-handling: status_400\n\
\n\
    - iis7:\n\
        personality: IIS_7_0\n\
        path-replacement-char: o\n\
        path-unicode-mapping: status_400\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));

    HTPConfigure();

    HTPCfgRec *cfg_rec = &cfglist;
    if (cfg_rec->cfg->path_control_char_handling != STATUS_400 ||
        cfg_rec->cfg->path_convert_utf8 != 1 ||
        cfg_rec->cfg->path_invalid_encoding_handling != URL_DECODER_REMOVE_PERCENT) {
        printf("failed 1\n");
        goto end;
    }

    cfg_rec = cfg_rec->next;
    if (cfg_rec->cfg->bestfit_replacement_char != 'o' ||
        cfg_rec->cfg->path_unicode_mapping != STATUS_400) {
        printf("failed 2\n");
        goto end;
    }

    cfg_rec = cfg_rec->next;
    if (cfg_rec->cfg->path_invalid_utf8_handling != NONE ||
        cfg_rec->cfg->path_nul_encoded_handling != STATUS_404 ||
        cfg_rec->cfg->path_nul_raw_handling != STATUS_400) {
        printf("failed 3\n");
        goto end;
    }

    result = 1;

end:
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    return result;
}
#endif

/** \test Test %2f decoding in profile Apache_2_2
 *
 *        %2f in path is left untouched
 *        %2f in query string is normalized to %2F
 *        %252f in query string is decoded/normalized to %2F
 */
static int HTPParserDecodingTest01(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/abc%2fdef";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    if (tx == NULL)
        goto end;
    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref2,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref2, reflen);
            printf("\": ");
            goto end;
        }
    }

    uint8_t ref3[] = "/abc/def?ghi%2fjkl";
    reflen = sizeof(ref3) - 1;
    tx = HTPStateGetTx(htp_state, 2);
    if (tx == NULL)
        goto end;
    tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref3,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref3, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test %2f decoding in profile IDS
 *
 *        %2f in path decoded to /
 *        %2f in query string is decoded to /
 *        %252f in query string is decoded to %2F
 */
static int HTPParserDecodingTest02(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc%2fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%2fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/abc/def";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    if (tx == NULL)
        goto end;
    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref2,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref2, reflen);
            printf("\": ");
            goto end;
        }
    }

    uint8_t ref3[] = "/abc/def?ghi%2fjkl";
    reflen = sizeof(ref3) - 1;
    tx = HTPStateGetTx(htp_state, 2);
    if (tx == NULL)
        goto end;
    tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX" (3): ",
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref3,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref3, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test %2f decoding in profile IDS with double-decode-* options
 *
 *        %252f in path decoded to /
 *        %252f in query string is decoded to /
 */
static int HTPParserDecodingTest03(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc%252fdef HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n"
        "GET /abc/def?ghi%252fjkl HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/abc/def";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    uint8_t ref2[] = "/abc/def?ghi/jkl";
    reflen = sizeof(ref2) - 1;

    tx = HTPStateGetTx(htp_state, 1);
    if (tx == NULL)
        goto end;
    tx_ud = (HtpTxUserData *)htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref2,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref2, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test http:// in query profile IDS
 */
static int HTPParserDecodingTest04(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /abc/def?a=http://www.abc.com/ HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/abc/def?a=http://www.abc.com/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test \ char in query profile IDS. Bug 739
 */
static int HTPParserDecodingTest05(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /index?id=\\\"<script>alert(document.cookie)</script> HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/index?id=\\\"<script>alert(document.cookie)</script>";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test + char in query. Bug 1035
 */
static int HTPParserDecodingTest06(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /put.php?ip=1.2.3.4&port=+6000 HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/put.php?ip=1.2.3.4&port=+6000";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test + char in query. Bug 1035
 */
static int HTPParserDecodingTest07(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET /put.php?ip=1.2.3.4&port=+6000 HTTP/1.1\r\nHost: www.domain.ltd\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/put.php?ip=1.2.3.4&port= 6000";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test 'proxy' URI normalization. Ticket 1008
 */
static int HTPParserDecodingTest08(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET http://suricata-ids.org/blah/ HTTP/1.1\r\nHost: suricata-ids.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "/blah/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test 'proxy' URI normalization. Ticket 1008
 */
static int HTPParserDecodingTest09(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] =
        "GET http://suricata-ids.org/blah/ HTTP/1.1\r\nHost: suricata-ids.org\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    HtpState *htp_state =  NULL;
    int r = 0;
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
    char *addr = "4.3.2.1";
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", addr, 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref1[] = "http://suricata-ids.org/blah/";
    size_t reflen = sizeof(ref1) - 1;

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL)
        goto end;
    HtpTxUserData *tx_ud = (HtpTxUserData *) htp_tx_get_user_data(tx);
    if (tx_ud != NULL && tx_ud->request_uri_normalized != NULL) {
        if (reflen != bstr_len(tx_ud->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                   (uintmax_t)reflen,
                   (uintmax_t)bstr_len(tx_ud->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx_ud->request_uri_normalized), ref1,
                   bstr_len(tx_ud->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, bstr_ptr(tx_ud->request_uri_normalized), bstr_len(tx_ud->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref1, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();

    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test BG box crash -- chunks are messed up. Observed for real. */
static int HTPBodyReassemblyTest01(void)
{
    int result = 0;
    HtpTxUserData htud;
    memset(&htud, 0x00, sizeof(htud));
    HtpState hstate;
    memset(&hstate, 0x00, sizeof(hstate));
    Flow flow;
    memset(&flow, 0x00, sizeof(flow));
    AppLayerParserState *parser = AppLayerParserStateAlloc();
    htp_tx_t tx;
    memset(&tx, 0, sizeof(tx));

    hstate.f = &flow;
    flow.alparser = parser;

    uint8_t chunk1[] = "--e5a320f21416a02493a0a6f561b1c494\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"D2GUef.jpg\"\r";
    uint8_t chunk2[] = "POST /uri HTTP/1.1\r\nHost: hostname.com\r\nKeep-Alive: 115\r\nAccept-Charset: utf-8\r\nUser-Agent: Mozilla/5.0 (X11; Linux i686; rv:9.0.1) Gecko/20100101 Firefox/9.0.1\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nConnection: keep-alive\r\nContent-length: 68102\r\nReferer: http://otherhost.com\r\nAccept-Encoding: gzip\r\nContent-Type: multipart/form-data; boundary=e5a320f21416a02493a0a6f561b1c494\r\nCookie: blah\r\nAccept-Language: us\r\n\r\n--e5a320f21416a02493a0a6f561b1c494\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"D2GUef.jpg\"\r";

    int r = HtpBodyAppendChunk(&htud, &htud.request_body, (uint8_t *)chunk1, sizeof(chunk1)-1);
    BUG_ON(r != 0);
    r = HtpBodyAppendChunk(&htud, &htud.request_body, (uint8_t *)chunk2, sizeof(chunk2)-1);
    BUG_ON(r != 0);

    uint8_t *chunks_buffer = NULL;
    uint32_t chunks_buffer_len = 0;

    HtpRequestBodyReassemble(&htud, &chunks_buffer, &chunks_buffer_len);
    if (chunks_buffer == NULL) {
        goto end;
    }
#ifdef PRINT
    printf("REASSCHUNK START: \n");
    PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    printf("REASSCHUNK END: \n");
#endif

    HtpRequestBodyHandleMultipart(&hstate, &htud, &tx, chunks_buffer, chunks_buffer_len);

    if (htud.request_body.content_len_so_far != 669) {
        printf("htud.request_body.content_len_so_far %"PRIu64": ", htud.request_body.content_len_so_far);
        goto end;
    }

    if (hstate.files_ts != NULL)
        goto end;

    result = 1;
end:
    return result;
}

/** \test BG crash */
static int HTPSegvTest01(void)
{
    int result = 0;
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
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCLogDebug("\n>>>> processing chunk 1 <<<<\n");
    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);
    SCLogDebug("\n>>>> processing chunk 1 again <<<<\n");
    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    SCMutexLock(&f->m);
    AppLayerDecoderEvents *decoder_events = AppLayerParserGetDecoderEvents(f->alparser);
    if (decoder_events != NULL) {
        printf("app events: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test really long request, this should result in HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG */
int HTPParserTest14(void)
{
    int result = 0;
    Flow *f = NULL;
    char *httpbuf = NULL;
    size_t len = 18887;
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
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

    memset(&ssn, 0, sizeof(ssn));

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    httpbuf = SCMalloc(len);
    if (unlikely(httpbuf == NULL))
        goto end;
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
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < len; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (len - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, (uint8_t *)&httpbuf[u], 1);
        if (u < 18294) { /* first 18294 bytes should result in 0 */
            if (r != 0) {
                printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                        " 0: ", u, r);
                SCMutexUnlock(&f->m);
                goto end;
            }
        } else if (u == 18294UL) { /* byte 18294 should result in error */
            if (r != -1) {
                printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                        " -1: ", u, r);
                SCMutexUnlock(&f->m);
                goto end;
            }

            /* break out, htp state is in error state now */
            SCMutexUnlock(&f->m);
            break;
        }
        SCMutexUnlock(&f->m);
    }
    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL || tx->request_method_number != HTP_M_GET || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    SCMutexLock(&f->m);
    AppLayerDecoderEvents *decoder_events = AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP,f->alstate, 0);
    if (decoder_events == NULL) {
        printf("no app events: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    if (decoder_events->events[0] != HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG) {
        printf("HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG not set: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    if (httpbuf != NULL)
        SCFree(httpbuf);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    return result;
}

/** \test Test really long request (same as HTPParserTest14), now with config
 *        update to allow it */
int HTPParserTest15(void)
{
    int result = 0;
    Flow *f = NULL;
    char *httpbuf = NULL;
    size_t len = 18887;
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
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
    if (unlikely(httpbuf == NULL))
        goto end;
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
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < len; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (len - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f->m);
        r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, (uint8_t *)&httpbuf[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            SCMutexUnlock(&f->m);
            goto end;
        }
        SCMutexUnlock(&f->m);
    }
    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL || tx->request_method_number != HTP_M_GET || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    SCMutexLock(&f->m);
    AppLayerDecoderEvents *decoder_events = AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP,f->alstate, 0);
    if (decoder_events != NULL) {
        printf("app events: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    if (httpbuf != NULL)
        SCFree(httpbuf);
    HTPFreeConfig();
    ConfDeInit();
    ConfRestoreContextBackup();
    HtpConfigRestoreBackup();
    return result;
}

/** \test Test unusual delims in request line HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG */
int HTPParserTest16(void)
{
    int result = 0;
    Flow *f = NULL;
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;
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
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint8_t flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    SCMutexLock(&f->m);
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, flags, (uint8_t *)httpbuf, len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(htp_state, 0);
    if (tx == NULL || tx->request_method_number != HTP_M_GET || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx ? bstr_util_strdup_to_c(tx->request_method) : "tx null",
                tx ? bstr_util_strdup_to_c(tx->request_protocol) : "tx null");
        goto end;
    }

    SCMutexLock(&f->m);
    AppLayerDecoderEvents *decoder_events = AppLayerParserGetEventsByTx(IPPROTO_TCP, ALPROTO_HTTP,f->alstate, 0);
    if (decoder_events == NULL) {
        printf("no app events: ");
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    if (decoder_events->events[0] != HTTP_DECODER_EVENT_METHOD_DELIM_NON_COMPLIANT) {
        printf("HTTP_DECODER_EVENT_METHOD_DELIM_NON_COMPLIANT not set: ");
        goto end;
    }

    if (decoder_events->events[1] != HTTP_DECODER_EVENT_URI_DELIM_NON_COMPLIANT) {
        printf("HTTP_DECODER_EVENT_URI_DELIM_NON_COMPLIANT not set: ");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test CONNECT with plain text HTTP being tunneled */
int HTPParserTest17(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    /* CONNECT setup */
    uint8_t httpbuf1[] = "CONNECT abc:443 HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    /* plain text HTTP */
    uint8_t httpbuf3[] = "GET / HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                                httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                            httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER,
                                httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf4,
                            httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    if (tx == NULL)
        goto end;
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_CONNECT ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }

    tx = HTPStateGetTx(http_state, 1);
    if (tx == NULL)
        goto end;
    h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_GET ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test CONNECT with plain text HTTP being tunneled */
int HTPParserTest18(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    /* CONNECT setup */
    uint8_t httpbuf1[] = "CONNECT abc:443 HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    /* plain text HTTP */
    uint8_t httpbuf3[] = "GE";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    uint8_t httpbuf4[] = "T / HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                                httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                            httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER,
                                httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER,
                                httpbuf4, httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }


    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf5,
                            httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    if (tx == NULL)
        goto end;
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_CONNECT ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }

    tx = HTPStateGetTx(http_state, 1);
    if (tx == NULL)
        goto end;
    h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_GET ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test CONNECT with TLS content (start of it at least) */
int HTPParserTest19(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    /* CONNECT setup */
    uint8_t httpbuf1[] = "CONNECT abc:443 HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    /* start of TLS/SSL */
    uint8_t httpbuf3[] = "\x16\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f->m);
    int r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                                httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                            httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    r = AppLayerParserParse(alp_tctx, f, ALPROTO_HTTP, STREAM_TOSERVER,
                                httpbuf3, httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }

    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    htp_tx_t *tx = HTPStateGetTx(http_state, 0);
    if (tx == NULL)
        goto end;
    htp_header_t *h =  htp_table_get_index(tx->request_headers, 0, NULL);
    if (tx->request_method_number != HTP_M_CONNECT ||
        h == NULL || tx->request_protocol_number != HTP_PROTOCOL_1_1)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_util_strdup_to_c(tx->request_method),
                bstr_util_strdup_to_c(tx->request_protocol));
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
               bstr_util_strdup_to_c(tx->response_message),
                bstr_util_strdup_to_c(tx->response_protocol));
        goto end;
    }

    /* no new tx should have been set up for the tunneled data */
    tx = HTPStateGetTx(http_state, 1);
    if (tx != NULL)
        goto end;

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

#endif /* UNITTESTS */

/**
 *  \brief  Register the Unit tests for the HTTP protocol
 */
void HTPParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HTPParserTest01", HTPParserTest01, 1);
    UtRegisterTest("HTPParserTest01a", HTPParserTest01a, 1);
    UtRegisterTest("HTPParserTest02", HTPParserTest02, 1);
    UtRegisterTest("HTPParserTest03", HTPParserTest03, 1);
    UtRegisterTest("HTPParserTest04", HTPParserTest04, 1);
    UtRegisterTest("HTPParserTest05", HTPParserTest05, 1);
    UtRegisterTest("HTPParserTest06", HTPParserTest06, 1);
    UtRegisterTest("HTPParserTest07", HTPParserTest07, 1);
    UtRegisterTest("HTPParserTest08", HTPParserTest08, 1);
    UtRegisterTest("HTPParserTest09", HTPParserTest09, 1);
    UtRegisterTest("HTPParserTest10", HTPParserTest10, 1);
    UtRegisterTest("HTPParserTest11", HTPParserTest11, 1);
    UtRegisterTest("HTPParserTest12", HTPParserTest12, 1);
    UtRegisterTest("HTPParserTest13", HTPParserTest13, 1);
    UtRegisterTest("HTPParserConfigTest01", HTPParserConfigTest01, 1);
    UtRegisterTest("HTPParserConfigTest02", HTPParserConfigTest02, 1);
    UtRegisterTest("HTPParserConfigTest03", HTPParserConfigTest03, 1);
#if 0 /* disabled when we upgraded to libhtp 0.5.x */
    UtRegisterTest("HTPParserConfigTest04", HTPParserConfigTest04, 1);
#endif

    UtRegisterTest("HTPParserDecodingTest01", HTPParserDecodingTest01, 1);
    UtRegisterTest("HTPParserDecodingTest02", HTPParserDecodingTest02, 1);
    UtRegisterTest("HTPParserDecodingTest03", HTPParserDecodingTest03, 1);
    UtRegisterTest("HTPParserDecodingTest04", HTPParserDecodingTest04, 1);
    UtRegisterTest("HTPParserDecodingTest05", HTPParserDecodingTest05, 1);
    UtRegisterTest("HTPParserDecodingTest06", HTPParserDecodingTest06, 1);
    UtRegisterTest("HTPParserDecodingTest07", HTPParserDecodingTest07, 1);
    UtRegisterTest("HTPParserDecodingTest08", HTPParserDecodingTest08, 1);
    UtRegisterTest("HTPParserDecodingTest09", HTPParserDecodingTest09, 1);

    UtRegisterTest("HTPBodyReassemblyTest01", HTPBodyReassemblyTest01, 1);

    UtRegisterTest("HTPSegvTest01", HTPSegvTest01, 1);

    UtRegisterTest("HTPParserTest14", HTPParserTest14, 1);
    UtRegisterTest("HTPParserTest15", HTPParserTest15, 1);
    UtRegisterTest("HTPParserTest16", HTPParserTest16, 1);
    UtRegisterTest("HTPParserTest17", HTPParserTest17, 1);
    UtRegisterTest("HTPParserTest18", HTPParserTest18, 1);
    UtRegisterTest("HTPParserTest19", HTPParserTest19, 1);

    HTPFileParserRegisterTests();
    HTPXFFParserRegisterTests();
#endif /* UNITTESTS */
}

/**
 * @}
 */
