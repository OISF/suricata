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
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

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

#include "app-layer-htp.h"
#include "app-layer-htp-body.h"
#include "app-layer-htp-file.h"

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

#include "conf.h"

#include "util-memcmp.h"

//#define PRINT

/** Need a linked list in order to keep track of these */
typedef struct HTPCfgRec_ {
    htp_cfg_t           *cfg;
    struct HTPCfgRec_   *next;

    /** max size of the client body we inspect */
    uint32_t            request_body_limit;
    uint32_t            response_body_limit;
} HTPCfgRec;

/** Fast lookup tree (radix) for the various HTP configurations */
static SCRadixTree *cfgtree;
/** List of HTP configurations. */
static HTPCfgRec cfglist;

#ifdef DEBUG
static SCMutex htp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

/** part of the engine needs the request body (e.g. http_client_body keyword) */
static uint8_t need_htp_request_body = 0;
/** part of the engine needs the request body multipart header (e.g. filename
 *  and / or fileext keywords) */
static uint8_t need_htp_request_multipart_hdr = 0;
/** part of the engine needs the request file (e.g. log-file module) */
static uint8_t need_htp_request_file = 0;
/** part of the engine needs the request body (e.g. file_data keyword) */
static uint8_t need_htp_response_body = 0;

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
    { NULL,                      -1 },
};

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
        CASE_HTP_PERSONALITY_STRING(TOMCAT_6_0);
        CASE_HTP_PERSONALITY_STRING(APACHE);
        CASE_HTP_PERSONALITY_STRING(APACHE_2_2);
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
    IF_HTP_PERSONALITY_NUM(TOMCAT_6_0);
    IF_HTP_PERSONALITY_NUM(APACHE);
    IF_HTP_PERSONALITY_NUM(APACHE_2_2);

    return -1;
}

/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void)
{
    SCEnter();

    HtpState *s = SCMalloc(sizeof(HtpState));
    if (s == NULL)
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
        SCFree(s);
    }

    SCReturnPtr(NULL, "void");
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

        size_t i;
        /* free the list of body chunks */
        if (s->connp->conn != NULL) {
            for (i = 0; i < list_size(s->connp->conn->transactions); i++) {
                htp_tx_t *tx = (htp_tx_t *)list_get(s->connp->conn->transactions, i);
                if (tx != NULL) {
                    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
                    if (htud != NULL) {
                        HtpBodyFree(&htud->request_body);
                        HtpBodyFree(&htud->response_body);
                        SCFree(htud);
                        htp_tx_set_user_data(tx, NULL);
                    }
                }
            }
        }
        htp_connp_destroy_all(s->connp);
    }

    FileContainerFree(s->files_ts);
    FileContainerFree(s->files_tc);
    SCFree(s);

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
 *  \brief Update the transaction id based on the http state
 */
void HTPStateUpdateTransactionId(void *state, uint16_t *id) {
    SCEnter();

    HtpState *s = (HtpState *)state;

    SCLogDebug("original id %"PRIu16", s->transaction_cnt %"PRIu16,
            *id, (s->transaction_cnt));

    if ((s->transaction_cnt) > (*id)) {
        SCLogDebug("original id %"PRIu16", updating with s->transaction_cnt %"PRIu16,
                *id, (s->transaction_cnt));

        (*id) = (s->transaction_cnt);

        SCLogDebug("updated id %"PRIu16, *id);
    }

    SCReturn;
}

/**
 *  \brief HTP transaction cleanup callback
 *
 *  \warning We cannot actually free the transactions here. It seems that
 *           HTP only accepts freeing of transactions in the response callback.
 */
void HTPStateTransactionFree(void *state, uint16_t id) {
    SCEnter();

    HtpState *s = (HtpState *)state;

    s->transaction_done = id;
    SCLogDebug("state %p, id %"PRIu16, s, id);

    /* we can't remove the actual transactions here */

    SCReturn;
}

/**
 * \brief Sets a flag that informs the HTP app layer that some module in the
 *        engine needs the http request body data.
 * \initonly
 */
void AppLayerHtpEnableRequestBodyCallback(void)
{
    SCEnter();
    need_htp_request_body = 1;
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
    need_htp_response_body = 1;
    SCReturn;
}

/**
 * \brief Sets a flag that informs the HTP app layer that some module in the
 *        engine needs the http request multi part header.
 *
 * \initonly
 */
void AppLayerHtpNeedMultipartHeader(void) {
    SCEnter();
    AppLayerHtpEnableRequestBodyCallback();

    need_htp_request_multipart_hdr = 1;
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

    need_htp_request_file = 1;
    SCReturn;
}

struct {
    char *msg;
    int  de;
} htp_errors[] = {
    { "GZip decompressor: inflateInit2 failed", HTTP_DECODER_EVENT_GZIP_DECOMPRESSION_FAILED},
    { "Request field invalid: colon missing", HTTP_DECODER_EVENT_REQUEST_FIELD_MISSING_COLON},
    { "Response field invalid: colon missing", HTTP_DECODER_EVENT_RESPONSE_FIELD_MISSING_COLON},
    { "Request chunk encoding: Invalid chunk length", HTTP_DECODER_EVENT_INVALID_REQUEST_CHUNK_LEN},
    { "Response chunk encoding: Invalid chunk length", HTTP_DECODER_EVENT_INVALID_RESPONSE_CHUNK_LEN},
    { "Invalid T-E value in request", HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_REQUEST},
    { "Invalid T-E value in response", HTTP_DECODER_EVENT_INVALID_TRANSFER_ENCODING_VALUE_IN_RESPONSE},
    { "Invalid C-L field in request", HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_REQUEST},
    { "Invalid C-L field in response", HTTP_DECODER_EVENT_INVALID_CONTENT_LENGTH_FIELD_IN_RESPONSE},
    { "Already seen 100-Continue", HTTP_DECODER_EVENT_100_CONTINUE_ALREADY_SEEN},
    { "Unable to match response to request", HTTP_DECODER_EVENT_UNABLE_TO_MATCH_RESPONSE_TO_REQUEST},
    { "Invalid server port information in request", HTTP_DECODER_EVENT_INVALID_SERVER_PORT_IN_REQUEST},
    { "Invalid authority port", HTTP_DECODER_EVENT_INVALID_AUTHORITY_PORT},
    { "Request field over", HTTP_DECODER_EVENT_REQUEST_FIELD_TOO_LONG},
    { "Response field over", HTTP_DECODER_EVENT_RESPONSE_FIELD_TOO_LONG},
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
    { "Host information in request headers required by HTTP/1.1", HTTP_DECODER_EVENT_MISSING_HOST_HEADER},
    { "Host information ambiguous", HTTP_DECODER_EVENT_HOST_HEADER_AMBIGUOUS},
    { "Invalid request field folding", HTTP_DECODER_EVENT_INVALID_REQUEST_FIELD_FOLDING},
    { "Invalid response field folding", HTTP_DECODER_EVENT_INVALID_RESPONSE_FIELD_FOLDING},
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
static int HTPHandleWarningGetId(const char *msg) {
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
static int HTPHandleErrorGetId(const char *msg) {
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
static void HTPHandleError(HtpState *s) {
    if (s == NULL || s->connp == NULL || s->connp->conn == NULL ||
        s->connp->conn->messages == NULL) {
        return;
    }

    size_t size = list_size(s->connp->conn->messages);
    size_t msg;

    for (msg = 0; msg < size; msg++) {
        htp_log_t *log = list_get(s->connp->conn->messages, msg);
        if (log == NULL)
            continue;

        int id = HTPHandleErrorGetId(log->msg);
        if (id > 0) {
            AppLayerDecoderEventsSetEvent(s->f, id);
        } else {
            id = HTPHandleWarningGetId(log->msg);
            if (id > 0) {
                AppLayerDecoderEventsSetEvent(s->f, id);
            } else {
                AppLayerDecoderEventsSetEvent(s->f,
                        HTTP_DECODER_EVENT_UNKNOWN_ERROR);
            }
        }
    }
}

/**
 *  \internal
 *
 *  \brief Check state for warnings and add any as events
 *
 *  \param s state
 */
static void HTPHandleWarning(HtpState *s) {
    if (s == NULL || s->connp == NULL || s->connp->conn == NULL ||
        s->connp->conn->messages == NULL) {
        return;
    }

    size_t size = list_size(s->connp->conn->messages);
    size_t msg;

    for (msg = 0; msg < size; msg++) {
        htp_log_t *log = list_get(s->connp->conn->messages, msg);
        if (log == NULL)
            continue;

        int id = HTPHandleWarningGetId(log->msg);
        if (id > 0) {
            AppLayerDecoderEventsSetEvent(s->f, id);
        } else {
            AppLayerDecoderEventsSetEvent(s->f, HTTP_DECODER_EVENT_UNKNOWN_ERROR);
        }
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
 *  \retval On success returns 1 or on failure returns -1
 */
static int HTPHandleRequestData(Flow *f, void *htp_state,
                                AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                void *local_data,
                                AppLayerParserResult *output)
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
    if (NULL == hstate->connp ) {
        htp_cfg_t *htp = cfglist.cfg; /* Default to the global HTP config */
        SCRadixNode *cfgnode = NULL;

        if (FLOW_IS_IPV4(f)) {
            SCLogDebug("Looking up HTP config for ipv4 %08x", *GET_IPV4_DST_ADDR_PTR(f));
            cfgnode = SCRadixFindKeyIPV4BestMatch((uint8_t *)GET_IPV4_DST_ADDR_PTR(f), cfgtree);
        }
        else if (FLOW_IS_IPV6(f)) {
            SCLogDebug("Looking up HTP config for ipv6");
            cfgnode = SCRadixFindKeyIPV6BestMatch((uint8_t *)GET_IPV6_DST_ADDR(f), cfgtree);
        }
        else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "unknown address family, bug!");
            goto error;
        }

        if (cfgnode != NULL) {
            HTPCfgRec *htp_cfg_rec = SC_RADIX_NODE_USERDATA(cfgnode, HTPCfgRec);
            if (htp_cfg_rec != NULL) {
                htp = htp_cfg_rec->cfg;
                SCLogDebug("LIBHTP using config: %p", htp);

                hstate->request_body_limit = htp_cfg_rec->request_body_limit;
                hstate->response_body_limit = htp_cfg_rec->response_body_limit;
            }
        } else {
            SCLogDebug("Using default HTP config: %p", htp);

            hstate->request_body_limit = cfglist.request_body_limit;
            hstate->response_body_limit = cfglist.response_body_limit;
        }

        if (NULL == htp) {
            BUG_ON(htp == NULL);
            /* should never happen if HTPConfigure is properly invoked */
            goto error;
        }

        hstate->connp = htp_connp_create(htp);
        if (hstate->connp == NULL) {
            goto error;
        }

        htp_connp_set_user_data(hstate->connp, (void *)hstate);

        SCLogDebug("New hstate->connp %p", hstate->connp);
    }

    /* the code block above should make sure connp is never NULL here */
    BUG_ON(hstate->connp == NULL);

    if (hstate->connp->in_status == STREAM_STATE_ERROR) {
        SCLogError(SC_ERR_ALPARSER, "Inbound parser is in error state, no"
                " need to feed data to libhtp");
        SCReturnInt(-1);
    }

    /* Unset the body inspection (the callback should
     * reactivate it if necessary) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    /* Open the HTTP connection on receiving the first request */
    if (!(hstate->flags & HTP_FLAG_STATE_OPEN)) {
        SCLogDebug("opening htp handle at %p", hstate->connp);

        htp_connp_open(hstate->connp, NULL, f->sp, NULL, f->dp, 0);
        hstate->flags |= HTP_FLAG_STATE_OPEN;
    } else {
        SCLogDebug("using existing htp handle at %p", hstate->connp);
    }

    /* pass the new data to the htp parser */
    r = htp_connp_req_data(hstate->connp, 0, input, input_len);

    switch(r) {
        case STREAM_STATE_ERROR:
            HTPHandleError(hstate);

            hstate->flags |= HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        case STREAM_STATE_DATA:
        case STREAM_STATE_DATA_OTHER:
            HTPHandleWarning(hstate);

            hstate->flags |= HTP_FLAG_STATE_DATA;
            break;
        default:
            HTPHandleWarning(hstate);
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
    }

    /* if the TCP connection is closed, then close the HTTP connection */
    if ((pstate->flags & APP_LAYER_PARSER_EOF) &&
            ! (hstate->flags & HTP_FLAG_STATE_CLOSED) &&
            ! (hstate->flags & HTP_FLAG_STATE_DATA))
    {
        htp_connp_close(hstate->connp, 0);
        hstate->flags |= HTP_FLAG_STATE_CLOSED;
        SCLogDebug("stream eof encountered, closing htp handle");
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
                                void *local_data,
                                AppLayerParserResult *output)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    HtpState *hstate = (HtpState *)htp_state;
    hstate->f = f;
    if (hstate->connp == NULL) {
        SCLogError(SC_ERR_ALPARSER, "HTP state has no connp");
        SCReturnInt(-1);
    }

    if (hstate->connp->out_status == STREAM_STATE_ERROR) {
        SCLogError(SC_ERR_ALPARSER, "Outbound parser is in error state, no"
                " need to feed data to libhtp");
        SCReturnInt(-1);
    }

    /* Unset the body inspection (the callback should
     * reactivate it if necessary) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    r = htp_connp_res_data(hstate->connp, 0, input, input_len);
    switch(r) {
        case STREAM_STATE_ERROR:
            HTPHandleError(hstate);

            hstate->flags = HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        case STREAM_STATE_DATA:
        case STREAM_STATE_DATA_OTHER:
            HTPHandleWarning(hstate);
            hstate->flags |= HTP_FLAG_STATE_DATA;
            break;
        default:
            HTPHandleWarning(hstate);
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
     }

    /* if we the TCP connection is closed, then close the HTTP connection */
    if ((pstate->flags & APP_LAYER_PARSER_EOF) &&
            ! (hstate->flags & HTP_FLAG_STATE_CLOSED) &&
            ! (hstate->flags & HTP_FLAG_STATE_DATA))
    {
        htp_connp_close(hstate->connp, 0);
        hstate->flags |= HTP_FLAG_STATE_CLOSED;
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    SCReturnInt(ret);
}

/**
 * \brief get the highest loggable transaction id
 */
int HtpTransactionGetLoggableId(Flow *f)
{
    SCEnter();

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    int id = 0;

    HtpState *http_state = f->alstate;
    if (http_state == NULL || http_state->connp == NULL ||
            http_state->connp->conn == NULL) {
        SCLogDebug("no (void) http state");
        goto error;
    }

    if (parser_state_store->id_flags & APP_LAYER_TRANSACTION_EOF) {
        SCLogDebug("eof, return current transaction as well");
        id = (int)(list_size(http_state->connp->conn->transactions));
    } else {
        id = (int)(parser_state_store->avail_id - 1);
    }

    SCReturnInt(id);

error:
    SCReturnInt(-1);
}

#ifdef HAVE_HTP_URI_NORMALIZE_HOOK
/**
 *  \brief Normalize the query part of the URI as if it's part of the URI.
 *
 *  \param c HTP connection pointer
 *
 *  \retval HOOK_OK we won't fail
 *
 *  This functionality requires the uri normalize hook introduced in libhtp
 *  version 0.2.5.
 */
static int HTPCallbackRequestUriNormalize(htp_connp_t *c)
{
    SCEnter();

    if (c == NULL || c->in_tx == NULL || c->in_tx->parsed_uri == NULL ||
        c->in_tx->parsed_uri->query == NULL)
    {
        SCReturnInt(HOOK_OK);
    }

    /* uri normalize the query string as well */
    htp_decode_path_inplace(c->cfg, c->in_tx,
            c->in_tx->parsed_uri->query);

    SCReturnInt(HOOK_OK);
}
#endif

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
 *  \retval 0 ok
 *  \retval -1 error: problem with the boundary
 *
 *  If the request contains a multipart message, this function will
 *  set the HTP_BOUNDARY_SET in the transaction.
 */
static int HtpRequestBodySetupMultipart(htp_tx_data_t *d, HtpTxUserData *htud) {
    htp_header_t *cl = table_getc(d->tx->request_headers, "content-length");
    if (cl != NULL)
        htud->request_body.content_len = htp_parse_content_length(cl->value);

    htp_header_t *h = (htp_header_t *)table_getc(d->tx->request_headers,
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
                htud->boundary = SCMalloc(boundary_len);
                if (htud->boundary == NULL) {
                    return -1;
                }
                htud->boundary_len = (uint8_t)boundary_len;
                memcpy(htud->boundary, boundary, boundary_len);

                htud->flags |= HTP_BOUNDARY_SET;
            } else {
                SCLogDebug("invalid boundary");
                return -1;
            }
        }
    }
    return 0;
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
    eb = (uint8_t *)SCMalloc(eb_len);
    if (eb == NULL) {
        goto error;
    }
    memset(eb, '-', eb_len);
    memcpy(eb + 2, htud->boundary, htud->boundary_len);

    uint8_t ebe_len = htud->boundary_len + 4;
    ebe = (uint8_t *)SCMalloc(ebe_len);
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
        SCFree(eb);
    }
    if (ebe != NULL) {
        SCFree(ebe);
    }
    SCReturnInt(-1);
}

#define C_D_HDR "content-disposition:"
#define C_D_HDR_LEN 20
#define C_T_HDR "content-type:"
#define C_T_HDR_LEN 13

static void HtpRequestBodyMultipartParseHeader(uint8_t *header, uint32_t header_len,
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
    uint32_t buf_len = 0;
    HtpBodyChunk *cur = htud->request_body.first;

    for ( ; cur != NULL; cur = cur->next) {
        SCLogDebug("chunk %p", cur);

        /* skip body chunks entirely before what we parsed already */
        if (cur->stream_offset + cur->len <= htud->request_body.body_parsed) {
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

            buf_len += tlen;
            if ((buf = SCRealloc(buf, buf_len)) == NULL) {
                buf_len = 0;
                break;
            }
            memcpy(buf + buf_len - tlen, cur->data + toff, tlen);

        } else {
            SCLogDebug("use entire chunk");

            buf_len += cur->len;
            if ((buf = SCRealloc(buf, buf_len)) == NULL) {
                buf_len = 0;
                break;
            }
            memcpy(buf + buf_len - cur->len, cur->data, cur->len);
        }
    }

    *chunks_buffer = buf;
    *chunks_buffer_len = buf_len;
}

int HtpRequestBodyHandleMultipart(HtpState *hstate, HtpTxUserData *htud,
        uint8_t *chunks_buffer, uint32_t chunks_buffer_len)
{
    int result = 0;
    uint8_t *expected_boundary = NULL;
    uint8_t *expected_boundary_end = NULL;
    uint8_t expected_boundary_len = 0;
    uint8_t expected_boundary_end_len = 0;

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

    /* if we're in the file storage process, deal with that now */
    if (htud->flags & HTP_FILENAME_SET) {
        if (header_start != NULL || form_end != NULL || htud->flags & HTP_BODY_COMPLETE) {
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
            } else if (htud->flags & HTP_BODY_COMPLETE) {
                filedata_len = chunks_buffer_len;
                flags = FILE_TRUNCATED;
            }

            BUG_ON(filedata_len > chunks_buffer_len);
#ifdef PRINT
            printf("FILEDATA (final chunk) START: \n");
            PrintRawDataFp(stdout, filedata, filedata_len);
            printf("FILEDATA (final chunk) END: \n");
#endif
            if (!(htud->flags & HTP_DONTSTORE)) {
                if (HTPFileClose(hstate, filedata, filedata_len, flags,
                            STREAM_TOSERVER) == -1)
                {
                    goto end;
                }
            }

            htud->flags &=~ HTP_FILENAME_SET;

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

                if (!(htud->flags & HTP_DONTSTORE)) {
                    result = HTPFileStoreChunk(hstate, filedata,
                            filedata_len, STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        /* we know for sure we're not storing the file */
                        htud->flags |= HTP_DONTSTORE;
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

        if ((uint32_t)(expected_boundary_len + 2) <= header_len) {
            header_len -= (expected_boundary_len + 2);
            header = header_start + (expected_boundary_len + 2); // + for 0d 0a
        }

        HtpRequestBodyMultipartParseHeader(header, header_len, &filename,
                &filename_len, &filetype, &filetype_len);

        if (filename != NULL) {
            uint8_t *filedata = NULL;
            uint32_t filedata_len = 0;

            SCLogDebug("we have a filename");

            htud->flags |= HTP_FILENAME_SET;
            htud->flags &= ~HTP_DONTSTORE;

            SCLogDebug("header_end %p", header_end);
            SCLogDebug("form_end %p", form_end);

            /* everything until the final boundary is the file */
            if (form_end != NULL) {
                filedata = header_end + 4;
                filedata_len = form_end - (header_end + 4 + 2);

                /* or is it? */
                uint8_t *header_next = Bs2bmSearch(filedata, filedata_len,
                        expected_boundary, expected_boundary_len);
                if (header_next != NULL) {
                    filedata_len -= (form_end - header_next);
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
                    htud->flags |= HTP_DONTSTORE;
                } else {
                    if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                        goto end;
                    }
                }

                htud->request_body.body_parsed += (header_end - chunks_buffer);
                htud->flags &= ~HTP_FILENAME_SET;
            } else {
                SCLogDebug("chunk doesn't contain form end");

                filedata = header_end + 4;
                filedata_len = chunks_buffer_len - (filedata - chunks_buffer);
                SCLogDebug("filedata_len %u (chunks_buffer_len %u)", filedata_len, chunks_buffer_len);

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
                        htud->flags |= HTP_DONTSTORE;
                    }
                } else {
                    filedata_len = header_next - filedata - 2;
                    SCLogDebug("filedata_len %u", filedata_len);

                    result = HTPFileOpen(hstate, filename, filename_len,
                            filedata, filedata_len, hstate->transaction_cnt,
                            STREAM_TOSERVER);
                    if (result == -1) {
                        goto end;
                    } else if (result == -2) {
                        htud->flags |= HTP_DONTSTORE;
                    } else {
                        if (HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER) == -1) {
                            goto end;
                        }
                    }

                    htud->flags &= ~HTP_FILENAME_SET;
                    htud->request_body.body_parsed += (header_end - chunks_buffer);
                }
            }

        } else {
            htud->request_body.body_parsed += (header_end - chunks_buffer);
        }

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
        SCFree(expected_boundary);
    }
    if (expected_boundary_end != NULL) {
        SCFree(expected_boundary_end);
    }

    SCLogDebug("htud->request_body.body_parsed %"PRIu64, htud->request_body.body_parsed);
    return 0;
}

/** \brief setup things for put request
 *  \todo really needed? */
int HtpRequestBodySetupPUT(htp_tx_data_t *d, HtpTxUserData *htud) {
//    if (d->tx->parsed_uri == NULL || d->tx->parsed_uri->path == NULL) {
//        return -1;
//    }

    /* filename is d->tx->parsed_uri->path */

    return 0;
}

int HtpRequestBodyHandlePUT(HtpState *hstate, HtpTxUserData *htud,
        htp_tx_t *tx, uint8_t *data, uint32_t data_len)
{
    int result = 0;

    /* see if we need to open the file */
    if (!(htud->flags & HTP_FILENAME_SET))
    {
        uint8_t *filename = NULL;
        uint32_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        result = HTPFileOpen(hstate, filename, filename_len, data, data_len,
                hstate->transaction_cnt, STREAM_TOSERVER);
        if (result == -1) {
            goto end;
        } else if (result == -2) {
            htud->flags |= HTP_DONTSTORE;
        } else {
            htud->flags |= HTP_FILENAME_SET;
            htud->flags &= ~HTP_DONTSTORE;
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->flags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOSERVER);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->flags |= HTP_DONTSTORE;
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
    if (!(htud->flags & HTP_FILENAME_SET))
    {
        SCLogDebug("setting up file name");

        uint8_t *filename = NULL;
        uint32_t filename_len = 0;

        /* get the name */
        if (tx->parsed_uri != NULL && tx->parsed_uri->path != NULL) {
            filename = (uint8_t *)bstr_ptr(tx->parsed_uri->path);
            filename_len = bstr_len(tx->parsed_uri->path);
        }

        result = HTPFileOpen(hstate, filename, filename_len,
                    data, data_len, hstate->transaction_cnt, STREAM_TOCLIENT);
        SCLogDebug("result %d", result);
        if (result == -1) {
            goto end;
        } else if (result == -2) {
            htud->flags |= HTP_DONTSTORE;
        } else {
            htud->flags |= HTP_FILENAME_SET;
            htud->flags &= ~HTP_DONTSTORE;
        }
    }
    else
    {
        /* otherwise, just store the data */

        if (!(htud->flags & HTP_DONTSTORE)) {
            result = HTPFileStoreChunk(hstate, data, data_len, STREAM_TOCLIENT);
            SCLogDebug("result %d", result);
            if (result == -1) {
                goto end;
            } else if (result == -2) {
                /* we know for sure we're not storing the file */
                htud->flags |= HTP_DONTSTORE;
            }
        }
    }

    return 0;
end:
    return -1;
}

/**
 * \brief Function callback to append chunks for Requests
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HOOK_OK if all goes well
 */
int HTPCallbackRequestBodyData(htp_tx_data_t *d)
{
    SCEnter();

#ifdef PRINT
    printf("HTPBODY START: \n");
    PrintRawDataFp(stdout, (uint8_t *)d->data, d->len);
    printf("HTPBODY END: \n");
#endif

    HtpState *hstate = (HtpState *)d->tx->connp->user_data;
    if (hstate == NULL) {
        SCReturnInt(HOOK_ERROR);
    }

    SCLogDebug("New request body data available at %p -> %p -> %p, bodylen "
               "%"PRIu32"", hstate, d, d->data, (uint32_t)d->len);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (htud == NULL) {
        htud = SCMalloc(sizeof(HtpTxUserData));
        if (htud == NULL) {
            SCReturnInt(HOOK_OK);
        }
        memset(htud, 0, sizeof(HtpTxUserData));
        htud->operation = HTP_BODY_REQUEST;

        if (d->tx->request_method_number == M_POST) {
            if (HtpRequestBodySetupMultipart(d, htud) == 0) {
                htud->request_body.type = HTP_BODY_REQUEST_MULTIPART;
            }
        } else if (d->tx->request_method_number == M_PUT) {
            if (HtpRequestBodySetupPUT(d, htud) == 0) {
                htud->request_body.type = HTP_BODY_REQUEST_PUT;
            }
        }

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, htud);
    }

    SCLogDebug("htud->request_body.content_len_so_far %"PRIu64, htud->request_body.content_len_so_far);
    SCLogDebug("hstate->request_body_limit %u", hstate->request_body_limit);

    /* within limits, add the body chunk to the state. */
    if (hstate->request_body_limit == 0 || htud->request_body.content_len_so_far < hstate->request_body_limit)
    {
        uint32_t len = (uint32_t)d->len;

        if (hstate->request_body_limit > 0 &&
                (htud->request_body.content_len_so_far + len) > hstate->request_body_limit)
        {
            len = hstate->request_body_limit - htud->request_body.content_len_so_far;
            BUG_ON(len > (uint32_t)d->len);
        }
        SCLogDebug("len %u", len);

        int r = HtpBodyAppendChunk(htud, &htud->request_body, (uint8_t *)d->data, len);
        if (r < 0) {
            htud->flags |= HTP_BODY_COMPLETE;
        } else if (hstate->request_body_limit > 0 &&
            htud->request_body.content_len_so_far >= hstate->request_body_limit)
        {
            htud->flags |= HTP_BODY_COMPLETE;
        } else if (htud->request_body.content_len_so_far == htud->request_body.content_len) {
            htud->flags |= HTP_BODY_COMPLETE;
        }

        uint8_t *chunks_buffer = NULL;
        uint32_t chunks_buffer_len = 0;

        if (htud->request_body.type == HTP_BODY_REQUEST_MULTIPART) {
            /* multi-part body handling starts here */
            if (!(htud->flags & HTP_BOUNDARY_SET)) {
                goto end;
            }

            HtpRequestBodyReassemble(htud, &chunks_buffer, &chunks_buffer_len);
            if (chunks_buffer == NULL) {
                goto end;
            }
#ifdef PRINT
    printf("REASSCHUNK START: \n");
    PrintRawDataFp(stdout, chunks_buffer, chunks_buffer_len);
    printf("REASSCHUNK END: \n");
#endif

            HtpRequestBodyHandleMultipart(hstate, htud, chunks_buffer, chunks_buffer_len);

            if (chunks_buffer != NULL) {
                SCFree(chunks_buffer);
            }
        } else if (htud->request_body.type == HTP_BODY_REQUEST_PUT) {
            HtpRequestBodyHandlePUT(hstate, htud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
        }

    }

end:
    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(&htud->request_body);

    /* set the new chunk flag */
    hstate->flags |= HTP_FLAG_NEW_BODY_SET;

    SCReturnInt(HOOK_OK);
}

/**
 * \brief Function callback to append chunks for Responses
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HOOK_OK if all goes well
 */
int HTPCallbackResponseBodyData(htp_tx_data_t *d)
{
    SCEnter();

    HtpState *hstate = (HtpState *)d->tx->connp->user_data;
    if (hstate == NULL) {
        SCReturnInt(HOOK_ERROR);
    }

    SCLogDebug("New response body data available at %p -> %p -> %p, bodylen "
               "%"PRIu32"", hstate, d, d->data, (uint32_t)d->len);

    HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (htud == NULL) {
        htud = SCMalloc(sizeof(HtpTxUserData));
        if (htud == NULL) {
            SCReturnInt(HOOK_OK);
        }
        memset(htud, 0, sizeof(HtpTxUserData));
        htud->operation = HTP_BODY_RESPONSE;

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, htud);
    }

    SCLogDebug("htud->response_body.content_len_so_far %"PRIu64, htud->response_body.content_len_so_far);
    SCLogDebug("hstate->response_body_limit %u", hstate->response_body_limit);

    /* within limits, add the body chunk to the state. */
    if (hstate->response_body_limit == 0 || htud->response_body.content_len_so_far < hstate->response_body_limit)
    {
        uint32_t len = (uint32_t)d->len;

        if (hstate->response_body_limit > 0 &&
                (htud->response_body.content_len_so_far + len) > hstate->response_body_limit)
        {
            len = hstate->response_body_limit - htud->response_body.content_len_so_far;
            BUG_ON(len > (uint32_t)d->len);
        }
        SCLogDebug("len %u", len);

        int r = HtpBodyAppendChunk(htud, &htud->response_body, (uint8_t *)d->data, len);
        if (r < 0) {
            htud->flags |= HTP_BODY_COMPLETE;
        } else if (hstate->response_body_limit > 0 &&
            htud->response_body.content_len_so_far >= hstate->response_body_limit)
        {
            htud->flags |= HTP_BODY_COMPLETE;
        } else if (htud->response_body.content_len_so_far == htud->response_body.content_len) {
            htud->flags |= HTP_BODY_COMPLETE;
        }

        HtpResponseBodyHandle(hstate, htud, d->tx, (uint8_t *)d->data, (uint32_t)d->len);
    }

    /* see if we can get rid of htp body chunks */
    HtpBodyPrune(&htud->response_body);

    /* set the new chunk flag */
    hstate->flags |= HTP_FLAG_NEW_BODY_SET;

    SCReturnInt(HOOK_OK);
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

    HTPCfgRec *nextrec = cfglist.next;
    SCRadixReleaseRadixTree(cfgtree);
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
static int HTPCallbackRequest(htp_connp_t *connp) {
    SCEnter();

    HtpState *hstate = (HtpState *)connp->user_data;
    if (hstate == NULL) {
        SCReturnInt(HOOK_ERROR);
    }

    SCLogDebug("transaction_cnt %"PRIu16", list_size %"PRIuMAX,
               hstate->transaction_cnt,
               (uintmax_t)list_size(hstate->connp->conn->transactions));

    SCLogDebug("HTTP request completed");

    if (connp->in_tx != NULL) {
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(connp->in_tx);
        if (htud != NULL) {
            if (htud->flags & HTP_FILENAME_SET) {
                SCLogDebug("closing file that was being stored");
                (void)HTPFileClose(hstate, NULL, 0, 0, STREAM_TOSERVER);
                htud->flags &= ~HTP_FILENAME_SET;
            }
        }
    }

    /* request done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerTriggerRawStreamReassembly(hstate->f);
    SCReturnInt(HOOK_OK);
}

/**
 *  \brief  callback for response to remove the recent received requests
            from the recent_in_tx for the given htp state
 *  \param  connp   pointer to the current connection parser which has the htp
 *                  state in it as user data
 */
static int HTPCallbackResponse(htp_connp_t *connp) {
    SCEnter();

    HtpState *hstate = (HtpState *)connp->user_data;
    if (hstate == NULL) {
        SCReturnInt(HOOK_ERROR);
    }

    /* we have one whole transaction now */
    hstate->transaction_cnt++;

    /* Unset the body inspection (if any) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    if (connp->out_tx != NULL) {
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(connp->out_tx);
        if (htud != NULL) {
            if (htud->flags & HTP_FILENAME_SET) {
                SCLogDebug("closing file that was being stored");
                (void)HTPFileClose(hstate, NULL, 0, 0, STREAM_TOCLIENT);
                htud->flags &= ~HTP_FILENAME_SET;
            }
        }
    }

    /* remove obsolete transactions */
    size_t idx;
    for (idx = 0; idx < hstate->transaction_done; idx++) {
        SCLogDebug("idx %"PRIuMAX, (uintmax_t)idx);

        htp_tx_t *tx = list_get(hstate->connp->conn->transactions, idx);
        if (tx == NULL)
            continue;

        /* This will remove obsolete body chunks */
        HtpTxUserData *htud = (HtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud != NULL) {
            HtpBodyFree(&htud->request_body);
            HtpBodyFree(&htud->response_body);
            SCFree(htud);
            htp_tx_set_user_data(tx, NULL);
        }

        htp_tx_destroy(tx);
    }

    /* response done, do raw reassembly now to inspect state and stream
     * at the same time. */
    AppLayerTriggerRawStreamReassembly(hstate->f);
    SCReturnInt(HOOK_OK);
}

static void HTPConfigure(void)
{
    SCEnter();
    ConfNode *default_config;
    ConfNode *server_config;

    cfglist.next = NULL;

    cfgtree = SCRadixCreateRadixTree(NULL, NULL);
    if (NULL == cfgtree) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error initializing HTP config tree");

        if (SCLogDebugEnabled()) {
            abort();
        }
        else {
            exit(EXIT_FAILURE);
        }
    }

    /* Default Config */
    cfglist.cfg = htp_config_create();
    if (NULL == cfglist.cfg) {
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to create HTP default config");

        if (SCLogDebugEnabled()) {
            abort();
        }
        else {
            exit(EXIT_FAILURE);
        }
    }

    SCLogDebug("LIBHTP default config: %p", cfglist.cfg);

    cfglist.request_body_limit = HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT;
    cfglist.response_body_limit = HTP_CONFIG_DEFAULT_RESPONSE_BODY_LIMIT;
    htp_config_register_request(cfglist.cfg, HTPCallbackRequest);
    htp_config_register_response(cfglist.cfg, HTPCallbackResponse);
#ifdef HAVE_HTP_URI_NORMALIZE_HOOK
    htp_config_register_request_uri_normalize(cfglist.cfg,
            HTPCallbackRequestUriNormalize);
#endif
    htp_config_set_generate_request_uri_normalized(cfglist.cfg, 1);

    default_config = ConfGetNode("libhtp.default-config");
    if (NULL != default_config) {
        ConfNode *p = NULL;

        /* Default Parameters */
        TAILQ_FOREACH(p, &default_config->head, next) {
            //ConfNode *pval;

            if (strcasecmp("personality", p->name) == 0) {
                /* Personalities */
                int personality = HTPLookupPersonality(p->val);

                SCLogDebug("LIBHTP default: %s=%s",
                        p->name, p->val);

                SCLogDebug("LIBHTP default: %s=%s",
                        p->name, p->val);

                if (personality >= 0) {
                    SCLogDebug("LIBHTP default: %s=%s (%d)",
                            p->name, p->val,
                            personality);
                    if (htp_config_set_server_personality(cfglist.cfg,
                                personality) == HTP_ERROR)
                    {
                        SCLogWarning(SC_ERR_INVALID_VALUE,
                                "LIBHTP Failed adding personality "
                                "\"%s\", ignoring", p->val);
                    } else {
                        SCLogDebug("LIBHTP personality set to %s",
                                HTPLookupPersonalityString(personality));
                    }

                    /* The IDS personality by default converts the path (and due to
                     * our query string callback also the query string) to lowercase.
                     * Signatures do not expect this, so override it. */
                    htp_config_set_path_case_insensitive(cfglist.cfg, 0);
                }
                else {
                    SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                            "LIBHTP Unknown personality "
                            "\"%s\", ignoring", p->val);
                    continue;
                }
            } else if (strcasecmp("request-body-limit", p->name) == 0 ||
                       strcasecmp("request_body_limit", p->name) == 0) {

                if (ParseSizeStringU32(p->val, &cfglist.request_body_limit) < 0) {
                    SCLogError(SC_ERR_SIZE_PARSE, "Error parsing request-body-limit "
                               "from conf file - %s.  Killing engine",
                               p->val);
                    exit(EXIT_FAILURE);
                }
            } else if (strcasecmp("response-body-limit", p->name) == 0) {
                if (ParseSizeStringU32(p->val, &cfglist.response_body_limit) < 0) {
                    SCLogError(SC_ERR_SIZE_PARSE, "Error parsing response-body-limit "
                               "from conf file - %s.  Killing engine",
                               p->val);
                    exit(EXIT_FAILURE);
                }
            } else {
                SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                        "LIBHTP Ignoring unknown default config: %s",
                        p->name);
            }
        }
    }

    /* Read server config and create a parser for each IP in radix tree */
    server_config = ConfGetNode("libhtp.server-config");
    SCLogDebug("LIBHTP Configuring %p", server_config);
    if (server_config != NULL) {
        ConfNode *si;
        ConfNode *s;
        HTPCfgRec *htprec;
        HTPCfgRec *nextrec;
        htp_cfg_t *htp;

        /* Server Nodes */
        TAILQ_FOREACH(si, &server_config->head, next) {
            ConfNode *p = NULL;

            /* Need the named node, not the index */
            s = TAILQ_FIRST(&si->head);
            if (NULL == s) {
                SCLogDebug("LIBHTP s NULL");
                continue;
            }

            SCLogDebug("LIBHTP server %s", s->name);

            nextrec = cfglist.next;
            htprec = cfglist.next = SCMalloc(sizeof(HTPCfgRec));
            if (NULL == htprec) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to create HTP server config rec");
                if (SCLogDebugEnabled()) {
                    abort();
                }
                else {
                    exit(EXIT_FAILURE);
                }
            }

            cfglist.next->next = nextrec;
            htp = cfglist.next->cfg = htp_config_create();
            if (NULL == htp) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to create HTP server config");
                if (SCLogDebugEnabled()) {
                    abort();
                }
                else {
                    exit(EXIT_FAILURE);
                }
            }

            htprec->request_body_limit = HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT;
            htprec->response_body_limit = HTP_CONFIG_DEFAULT_REQUEST_BODY_LIMIT;
            htp_config_register_request(htp, HTPCallbackRequest);
            htp_config_register_response(htp, HTPCallbackResponse);
            htp_config_set_generate_request_uri_normalized(htp, 1);

            /* Server Parameters */
            TAILQ_FOREACH(p, &s->head, next) {
                ConfNode *pval;

                if (strcasecmp("address", p->name) == 0) {

                    /* Addresses */
                    TAILQ_FOREACH(pval, &p->head, next) {
                        SCLogDebug("LIBHTP server %s: %s=%s",
                                   s->name, p->name, pval->val);

                        /* IPV6 or IPV4? */
                        if (strchr(pval->val, ':') != NULL) {
                            SCLogDebug("LIBHTP adding ipv6 server %s at %s: %p",
                                       s->name, pval->val, htp);
                            if (SCRadixAddKeyIPV6String(pval->val,
                                                        cfgtree, htprec) == NULL)
                            {
                                SCLogWarning(SC_ERR_INVALID_VALUE,
                                             "LIBHTP failed to add "
                                             "ipv6 server %s, ignoring",
                                             pval->val);
                            }
                        } else {
                            SCLogDebug("LIBHTP adding ipv4 server %s at %s: %p",
                                       s->name, pval->val, htp);
                            if (SCRadixAddKeyIPV4String(pval->val,
                                                        cfgtree, htprec) == NULL)
                            {
                                SCLogWarning(SC_ERR_INVALID_VALUE,
                                             "LIBHTP failed to add "
                                             "ipv4 server %s, ignoring",
                                             pval->val);
                            }
                        }
                    }
                } else if (strcasecmp("personality", p->name) == 0) {
                    /* Personalitie */
                    int personality = HTPLookupPersonality(p->val);

                    SCLogDebug("LIBHTP server %s: %s=%s",
                            s->name, p->name, p->val);

                    SCLogDebug("LIBHTP server %s: %s=%s",
                            s->name, p->name, p->val);

                    if (personality >= 0) {
                        SCLogDebug("LIBHTP %s: %s=%s (%d)",
                                s->name, p->name, p->val,
                                personality);
                        if (htp_config_set_server_personality(htp,
                                    personality) == HTP_ERROR)
                        {
                            SCLogWarning(SC_ERR_INVALID_VALUE,
                                    "LIBHTP Failed adding personality "
                                    "\"%s\", ignoring", p->val);
                        } else {
                            SCLogDebug("LIBHTP personality set to %s",
                                    HTPLookupPersonalityString(personality));
                        }

                        /* The IDS personality by default converts the path (and due to
                         * our query string callback also the query string) to lowercase.
                         * Signatures do not expect this, so override it. */
                        htp_config_set_path_case_insensitive(htp, 0);
                    }
                    else {
                        SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                                "LIBHTP Unknown personality "
                                "\"%s\", ignoring", p->val);
                        continue;
                    }

                /* VJ the non underscore version was a typo but keeping it for
                 * compatibility with existing installs */
                } else if (strcasecmp("request-body-limit", p->name) == 0 ||
                           strcasecmp("request_body_limit", p->name) == 0) {
                    /* limit */
                    SCLogDebug("LIBHTP default: %s=%s",
                            p->name, p->val);

                    if (ParseSizeStringU32(p->val, &htprec->request_body_limit) < 0) {
                        SCLogError(SC_ERR_SIZE_PARSE, "Error parsing request-body-limit "
                                   "from conf file - %s.  Killing engine",
                                   p->val);
                        exit(EXIT_FAILURE);
                    }
                } else if (strcasecmp("response-body-limit", p->name) == 0) {
                    if (ParseSizeStringU32(p->val, &htprec->response_body_limit) < 0) {
                        SCLogError(SC_ERR_SIZE_PARSE, "Error parsing response-body-limit "
                                   "from conf file - %s.  Killing engine",
                                   p->val);
                        exit(EXIT_FAILURE);
                    }
                } else {
                    SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                                 "LIBHTP Ignoring unknown server config: %s",
                                 p->name);
                }
            }
        }
    }

    SCReturn;
}

void AppLayerHtpPrintStats(void) {
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
static FileContainer *HTPStateGetFiles(void *state, uint8_t direction) {
    if (state == NULL)
        return NULL;

    HtpState *http_state = (HtpState *)state;

    if (direction & STREAM_TOCLIENT) {
        SCReturnPtr(http_state->files_tc, "FileContainer");
    } else {
        SCReturnPtr(http_state->files_ts, "FileContainer");
    }
}

/**
 *  \brief  Register the HTTP protocol and state handling functions to APP layer
 *          of the engine.
 */
void RegisterHTPParsers(void)
{
    SCEnter();

    /** HTTP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET|20|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET|09|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT|20|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT|09|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST|20|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST|09|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HEAD|20|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HEAD|09|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE|20|", 6, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE|09|", 6, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS|20|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS|09|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "CONNECT|20|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "CONNECT|09|", 8, 0, STREAM_TOSERVER);

    AppLayerRegisterStateFuncs(ALPROTO_HTTP, HTPStateAlloc, HTPStateFree);
    AppLayerRegisterTransactionIdFuncs(ALPROTO_HTTP, HTPStateUpdateTransactionId, HTPStateTransactionFree);
    AppLayerRegisterGetFilesFunc(ALPROTO_HTTP, HTPStateGetFiles);

    AppLayerDecoderEventsModuleRegister(ALPROTO_HTTP, http_decoder_event_table);

    AppLayerRegisterProto("http", ALPROTO_HTTP, STREAM_TOSERVER,
                          HTPHandleRequestData);
    AppLayerRegisterProto("http", ALPROTO_HTTP, STREAM_TOCLIENT,
                          HTPHandleResponseData);

    HTPConfigure();
    SCReturn;
}

/**
 * \brief This function is called at the end of SigLoadSignatures.  This function
 *        enables the htp layer to register a callback for the http request body.
 *        need_htp_request_body is a flag that informs the htp app layer that
 *        a module in the engine needs the http request body.
 */
void AppLayerHtpRegisterExtraCallbacks(void) {
    SCEnter();
    SCLogDebug("Registering extra htp callbacks");
    if (need_htp_request_body == 1) {
        SCLogDebug("Registering callback htp_config_register_request_body_data on htp");
        htp_config_register_request_body_data(cfglist.cfg,
                                              HTPCallbackRequestBodyData);
    }
    if (need_htp_response_body == 1) {
        SCLogDebug("Registering callback htp_config_register_response_body_data on htp");
        htp_config_register_response_body_data(cfglist.cfg,
                                              HTPCallbackResponseBodyData);
    }
    SCReturn;
}


#ifdef UNITTESTS
static HTPCfgRec cfglist_backup;

static void HtpConfigCreateBackup(void)
{
    cfglist_backup.cfg = cfglist.cfg;
    cfglist_backup.next = cfglist.next;
    cfglist_backup.request_body_limit = cfglist.request_body_limit;

    return;
}

static void HtpConfigRestoreBackup(void)
{
    cfglist.cfg = cfglist_backup.cfg;
    cfglist.next = cfglist_backup.next;
    cfglist.request_body_limit = cfglist_backup.request_body_limit;

    return;
}

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
int HTPParserTest01(void) {
    int result = 1;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

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

        r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || strcmp(bstr_tocstr(h->value), "Victor/1.0")
            || tx->request_method_number != M_POST ||
            tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected header value: Victor/1.0 and got %s: and expected"
                " method: POST and got %s, expected protocol number HTTP/1.0"
                "  and got: %s \n", bstr_tocstr(h->value),
                bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test See how it deals with an incomplete request. */
int HTPParserTest02(void) {
    int result = 1;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "POST";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if ((tx->request_method) != NULL || h != NULL)
    {
        printf("expected method NULL, got %s \n", bstr_tocstr(tx->request_method));
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test case where method is invalid and data is sent in smaller chunks
 *        and check the response of the parser from HTP library. */
int HTPParserTest03(void) {
    int result = 1;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "HELLO / HTTP/1.0\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

    HtpState *htp_state =  NULL;
    int r = 0;
    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }
    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || tx->request_method_number != M_UNKNOWN ||
             h != NULL || tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test case where invalid data is sent and check the response of the
 *        parser from HTP library. */
int HTPParserTest04(void) {
    int result = 1;
    Flow *f = NULL;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "World!\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        goto end;
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || tx->request_method_number != M_UNKNOWN ||
            h != NULL || tx->request_protocol_number != PROTOCOL_UNKNOWN)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "NULL and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test both sides of a http stream mixed up to see if the HTP parser
 *        properly parsed them and also keeps them separated. */
int HTPParserTest05(void) {
    int result = 1;
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

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                          httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf4,
                      httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3,
                      httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_EOF, httpbuf6,
                      httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if (http_state->connp == NULL || tx->request_method_number != M_POST ||
            h == NULL || tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if (tx->response_status_number != 200) {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.0 and got %s \n", tx->response_status_number,
                bstr_tocstr(tx->response_message),
                bstr_tocstr(tx->response_protocol));
        result = 0;
        goto end;
    }
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test Test proper chunked encoded response body
 */
int HTPParserTest06(void) {
    int result = 1;
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
                         "1408\r\n"
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
                         "aHA=0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                          httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                      httplen2);
    if (r != 0) {
        printf("toclient chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    table_iterator_next(tx->request_headers, (void **) & h);

    if (http_state->connp == NULL || tx->request_method_number != M_GET ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if (tx->response_status_number != 200 ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected response 200 OK and got %"PRId32" %s: , expected proto"
                "col HTTP/1.1 and got %s \n", tx->response_status_number,
                bstr_tocstr(tx->response_message),
                bstr_tocstr(tx->response_protocol));
        result = 0;
        goto end;
    }
end:
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    UTHFreeFlow(f);
    return result;
}

/** \test
 */
int HTPParserTest07(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /awstats.pl?/migratemigrate%20=%20| HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *htp_state =  NULL;
    int r = 0;

    memset(&ssn, 0, sizeof(ssn));

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

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

        r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            goto end;
        }
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    uint8_t ref[] = "/awstats.pl?/migratemigrate = |";
    size_t reflen = sizeof(ref) - 1;

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);
    if (tx != NULL && tx->request_uri_normalized != NULL) {
        if (reflen != bstr_size(tx->request_uri_normalized)) {
            printf("normalized uri len should be %"PRIuMAX", is %"PRIuMAX,
                (uintmax_t)reflen,
                (uintmax_t)bstr_size(tx->request_uri_normalized));
            goto end;
        }

        if (memcmp(bstr_ptr(tx->request_uri_normalized), ref,
                    bstr_size(tx->request_uri_normalized)) != 0)
        {
            printf("normalized uri \"");
            PrintRawUriFp(stdout, (uint8_t *)bstr_ptr(tx->request_uri_normalized), bstr_size(tx->request_uri_normalized));
            printf("\" != \"");
            PrintRawUriFp(stdout, ref, reflen);
            printf("\": ");
            goto end;
        }
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    UTHFreeFlow(f);
    return result;
}

#include "conf-yaml-loader.h"

/** \test Abort
 */
int HTPParserTest08(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /secondhouse/image/js/\%ce\%de\%ce\%fd_RentCity.js?v=2011.05.02 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

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

    StreamTcpInitConfig(TRUE);

    uint8_t flags = 0;
    flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk returned %" PRId32 ", expected"
                " 0: ", r);
        result = 0;
        goto end;
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);
    if (tx != NULL && tx->request_uri_normalized != NULL) {
        //printf("uri %s\n", bstr_tocstr(tx->request_uri_normalized));
        PrintRawDataFp(stdout, (uint8_t *)bstr_ptr(tx->request_uri_normalized),
                bstr_len(tx->request_uri_normalized));
    }

    result = 1;
end:
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
int HTPParserTest09(void) {
    int result = 0;
    Flow *f = NULL;
    uint8_t httpbuf1[] = "GET /secondhouse/image/js/\%ce\%de\%ce\%fd_RentCity.js?v=2011.05.02 HTTP/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

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

    StreamTcpInitConfig(TRUE);

    uint8_t flags = 0;
    flags = STREAM_TOSERVER|STREAM_START|STREAM_EOF;

    r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk returned %" PRId32 ", expected"
                " 0: ", r);
        result = 0;
        goto end;
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);
    if (tx != NULL && tx->request_uri_normalized != NULL) {
        //printf("uri %s\n", bstr_tocstr(tx->request_uri_normalized));
        PrintRawDataFp(stdout, (uint8_t *)bstr_ptr(tx->request_uri_normalized),
                bstr_len(tx->request_uri_normalized));
    }

    result = 1;
end:
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

    SCRadixNode *cfgnode = NULL;
    htp_cfg_t *htp = cfglist.cfg;
    uint8_t buf[128];
    const char *addr;

    addr = "192.168.10.42";
    if (inet_pton(AF_INET, addr, buf) == 1) {
        cfgnode = SCRadixFindKeyIPV4BestMatch(buf, cfgtree);
        if (cfgnode != NULL) {
            HTPCfgRec *htp_cfg_rec = SC_RADIX_NODE_USERDATA(cfgnode, HTPCfgRec);
            if (htp_cfg_rec != NULL) {
                htp = htp_cfg_rec->cfg;
                SCLogDebug("LIBHTP using config: %p", htp);
            }
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

    addr = "::1";
    if (inet_pton(AF_INET6, addr, buf) == 1) {
        cfgnode = SCRadixFindKeyIPV6BestMatch(buf, cfgtree);
        if (cfgnode != NULL) {
            HTPCfgRec *htp_cfg_rec = SC_RADIX_NODE_USERDATA(cfgnode, HTPCfgRec);
            if (htp_cfg_rec != NULL) {
                htp = htp_cfg_rec->cfg;
                SCLogDebug("LIBHTP using config: %p", htp);
            }
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

    SCRadixNode *cfgnode = NULL;
    htp_cfg_t *htp = cfglist.cfg;

    cfgnode = SCRadixFindKeyIPV4BestMatch((uint8_t *)f->dst.addr_data32, cfgtree);
    if (cfgnode != NULL) {
        HTPCfgRec *htp_cfg_rec = SC_RADIX_NODE_USERDATA(cfgnode, HTPCfgRec);
        if (htp_cfg_rec != NULL) {
            htp = htp_cfg_rec->cfg;
            SCLogDebug("LIBHTP using config: %p", htp);
        }
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

        r = AppLayerParse(NULL, f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    htp_state = f->alstate;
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    /* Check that the HTP state config matches the correct one */
    if (htp_state->connp->cfg != htp) {
        printf("wrong HTP config (%p instead of %p - default=%p): ",
               htp_state->connp->cfg, htp, cfglist.cfg);
        result = 0;
        goto end;
    }

end:
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

#endif /* UNITTESTS */

/**
 *  \brief  Register the Unit tests for the HTTP protocol
 */
void HTPParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HTPParserTest01", HTPParserTest01, 1);
    UtRegisterTest("HTPParserTest02", HTPParserTest02, 1);
    UtRegisterTest("HTPParserTest03", HTPParserTest03, 1);
    UtRegisterTest("HTPParserTest04", HTPParserTest04, 1);
    UtRegisterTest("HTPParserTest05", HTPParserTest05, 1);
    UtRegisterTest("HTPParserTest06", HTPParserTest06, 1);
    UtRegisterTest("HTPParserTest07", HTPParserTest07, 1);
    UtRegisterTest("HTPParserTest08", HTPParserTest08, 1);
    UtRegisterTest("HTPParserTest09", HTPParserTest09, 1);
    UtRegisterTest("HTPParserConfigTest01", HTPParserConfigTest01, 1);
    UtRegisterTest("HTPParserConfigTest02", HTPParserConfigTest02, 1);
    UtRegisterTest("HTPParserConfigTest03", HTPParserConfigTest03, 1);

    HTPFileParserRegisterTests();
#endif /* UNITTESTS */
}

/**
 * @}
 */
