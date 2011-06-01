/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * This file provides a HTTP protocol support for the engine using HTP library.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-radix-tree.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-spm.h"
#include "util-debug.h"
#include "app-layer-htp.h"
#include "util-time.h"
#include <htp/htp.h>

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

/** Need a linked list in order to keep track of these */
typedef struct HTPCfgRec_ HTPCfgRec;
struct HTPCfgRec_ {
    htp_cfg_t         *cfg;
    HTPCfgRec         *next;
};

/** Fast lookup tree (radix) for the various HTP configurations */
static SCRadixTree *cfgtree;
/** List of HTP configurations. */
static HTPCfgRec cfglist;

#ifdef DEBUG
static SCMutex htp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

static uint8_t need_htp_request_body = 0;


#if 0 /* Not used yet */
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
#endif /* Not used yet */

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
        size_t i;
        /* free the list of body chunks */
        if (s->connp->conn != NULL) {
            for (i = 0; i < list_size(s->connp->conn->transactions); i++) {
                htp_tx_t *tx = (htp_tx_t *)list_get(s->connp->conn->transactions, i);
                if (tx != NULL) {
                    SCHtpTxUserData *htud = (SCHtpTxUserData *) htp_tx_get_user_data(tx);
                    if (htud != NULL) {
                        HtpBodyFree(&htud->body);
                        SCFree(htud);
                    }
                    htp_tx_set_user_data(tx, NULL);
                }
            }
        }
        htp_connp_destroy_all(s->connp);
    }

    SCFree(s);

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt--;
    htp_state_memuse -= sizeof(HtpState);
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

    SCLogDebug("original id %"PRIu16", s->transaction_cnt+1 %"PRIu16,
            *id, (s->transaction_cnt+1));

    if ((s->transaction_cnt+1) > (*id)) {
        SCLogDebug("original id %"PRIu16", updating with s->transaction_cnt+1 %"PRIu16,
                *id, (s->transaction_cnt+1));

        (*id) = (s->transaction_cnt+1);

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
 *  \brief  Function to handle the reassembled data from client and feed it to
 *          the HTP library to process it.
 *
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
                                AppLayerParserResult *output)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    //PrintRawDataFp(stdout, input, input_len);

    HtpState *hstate = (HtpState *)htp_state;

    /* if the previous run set the new request flag, we unset it here. As
     * we're here after a new request completed, we know it's a new
     * transaction. So we set the new transaction flag. */
    if (hstate->flags & HTP_FLAG_NEW_REQUEST) {
        hstate->flags &=~ HTP_FLAG_NEW_REQUEST;

        /* new transaction */
        hstate->transaction_cnt++;
        SCLogDebug("transaction_cnt %"PRIu16", list_size %"PRIuMAX, hstate->transaction_cnt,
                (uintmax_t)list_size(hstate->connp->conn->transactions));
    }

    /* On the first invocation, create the connection parser structure to
     * be used by HTP library.  This is looked up via IP in the radix
     * tree.  Failing that, the default HTP config is used.
     */
    if (NULL == hstate->connp ) {
        htp_cfg_t *htp = cfglist.cfg; /* Default to the global HTP config */
        SCRadixNode *cfgnode = NULL;

        if (AF_INET == f->dst.family) {
            SCLogDebug("Looking up HTP config for ipv4 %08x", *GET_IPV4_DST_ADDR_PTR(f));
            cfgnode = SCRadixFindKeyIPV4BestMatch((uint8_t *)GET_IPV4_DST_ADDR_PTR(f), cfgtree);
        }
        else if (AF_INET6 == f->dst.family) {
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
            }
        } else {
            SCLogDebug("Using default HTP config: %p", htp);
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
            if (hstate->connp->last_error != NULL) {
                SCLogError(SC_ERR_ALPARSER, "Error in parsing HTTP client "
                                    "request: [%"PRId32"] [%s] [%"PRId32"] %s",
                                    hstate->connp->last_error->level,
                                    hstate->connp->last_error->file,
                                    hstate->connp->last_error->line,
                                    hstate->connp->last_error->msg);
            } else {
                SCLogError(SC_ERR_ALPARSER, "Error in parsing HTTP client "
                                            "request");
            }
            hstate->flags |= HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        case STREAM_STATE_DATA:
            hstate->flags |= HTP_FLAG_STATE_DATA;
            break;
        case STREAM_STATE_DATA_OTHER:
            SCLogDebug("CONNECT not supported yet");
            hstate->flags |= HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        default:
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
                                AppLayerParserResult *output)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    HtpState *hstate = (HtpState *)htp_state;
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
            if (hstate->connp->last_error != NULL) {
                SCLogError(SC_ERR_ALPARSER, "Error in parsing HTTP server "
                                    "response: [%"PRId32"] [%s] [%"PRId32"] %s",
                                    hstate->connp->last_error->level,
                                    hstate->connp->last_error->file,
                                    hstate->connp->last_error->line,
                                    hstate->connp->last_error->msg);
            } else {
                SCLogError(SC_ERR_ALPARSER, "Error in parsing HTTP server "
                                            "response");
            }
            hstate->flags = HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        case STREAM_STATE_DATA:
            hstate->flags |= HTP_FLAG_STATE_DATA;
            break;
        case STREAM_STATE_DATA_OTHER:
            SCLogDebug("CONNECT not supported yet");
            hstate->flags = HTP_FLAG_STATE_ERROR;
            hstate->flags &= ~HTP_FLAG_STATE_DATA;
            hstate->flags &= ~HTP_FLAG_NEW_BODY_SET;
            ret = -1;
            break;
        default:
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
 * \brief Append a chunk of body to the HtpBody struct
 * \param body pointer to the HtpBody holding the list
 * \param data pointer to the data of the chunk
 * \param len length of the chunk pointed by data
 * \retval none
 */
void HtpBodyAppendChunk(HtpBody *body, uint8_t *data, uint32_t len)
{
    SCEnter();

    HtpBodyChunk *bd = NULL;

    if (len == 0 || data == NULL)
        goto error;

    if (body->nchunks == 0) {
        /* New chunk */
        bd = (HtpBodyChunk *)SCMalloc(sizeof(HtpBodyChunk));
        if (bd == NULL)
            return;

        bd->len = len;
        bd->data = SCMalloc(len);
        if (bd->data == NULL) {
            SCFree(bd);

            SCLogError(SC_ERR_MEM_ALLOC, "malloc failed: %s", strerror(errno));
            goto error;
        }

        memcpy(bd->data, data, len);
        body->first = body->last = bd;
        body->nchunks++;
        bd->next = NULL;
        bd->id = body->nchunks;
    } else {
        /* New or old, we have to check it.. */
        if (body->last->data == data) {
            /* Weird, but sometimes htp lib calls the callback
             * more than once for the same chunk, with more
             * len, so updating the len */
            body->last->len = len;
            bd = body->last;

            bd->data = SCRealloc(bd->data, len);
            if (bd->data == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "realloc failed: %s", strerror(errno));
                goto error;
            }

            memcpy(bd->data, data, len);
        } else {
            bd = (HtpBodyChunk *)SCMalloc(sizeof(HtpBodyChunk));
            if (bd == NULL)
                return;

            bd->len = len;
            bd->data = SCMalloc(len);
            if (bd->data == NULL) {
                SCFree(bd);

                SCLogError(SC_ERR_MEM_ALLOC, "malloc failed: %s", strerror(errno));
                goto error;
            }

            memcpy(bd->data, data, len);
            body->last->next = bd;
            body->last = bd;
            body->nchunks++;
            bd->next = NULL;
            bd->id = body->nchunks;
        }
    }
    SCLogDebug("Body %p; Chunk id: %"PRIu32", data %p, len %"PRIu32"", body,
                bd->id, bd->data, (uint32_t)bd->len);

    SCReturn;

error:
    if (bd != NULL) {
        if (bd->data != NULL) {
            SCFree(bd->data);
        }
        SCFree(bd->data);
    }
    SCReturn;
}

/**
 * \brief Print the information and chunks of a Body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyPrint(HtpBody *body)
{
    if (SCLogDebugEnabled()) {
        SCEnter();

        if (body->nchunks == 0)
            return;

        HtpBodyChunk *cur = NULL;
        SCLogDebug("--- Start body chunks at %p ---", body);
        for (cur = body->first; cur != NULL; cur = cur->next) {
            SCLogDebug("Body %p; Chunk id: %"PRIu32", data %p, len %"PRIu32"\n",
                        body, cur->id, cur->data, (uint32_t)cur->len);
            PrintRawDataFp(stdout, (uint8_t*)cur->data, cur->len);
        }
        SCLogDebug("--- End body chunks at %p ---", body);
    }
}

/**
 * \brief Free the information held in the request body
 * \param body pointer to the HtpBody holding the list
 * \retval none
 */
void HtpBodyFree(HtpBody *body)
{
    SCEnter();

    if (body->nchunks == 0)
        return;

    SCLogDebug("Removing chunks of Body %p; Last Chunk id: %"PRIu32", data %p,"
               " len %"PRIu32"\n", body, body->last->id, body->last->data,
                (uint32_t)body->last->len);
    body->nchunks = 0;

    HtpBodyChunk *cur = NULL;
    HtpBodyChunk *prev = NULL;

    prev = body->first;
    while (prev != NULL) {
        cur = prev->next;
        if (prev->data != NULL)
            SCFree(prev->data);
        SCFree(prev);
        prev = cur;
    }
    body->first = body->last = NULL;
    body->pcre_flags = HTP_PCRE_NONE;
    body->operation = HTP_BODY_NONE;
}

/**
 * \brief Function callback to append chunks for Requests
 * \param d pointer to the htp_tx_data_t structure (a chunk from htp lib)
 * \retval int HOOK_OK if all goes well
 */
int HTPCallbackRequestBodyData(htp_tx_data_t *d)
{
    SCEnter();
    HtpState *hstate = (HtpState *)d->tx->connp->user_data;
    SCLogDebug("New response body data available at %p -> %p -> %p, bodylen "
               "%"PRIu32"", hstate, d, d->data, (uint32_t)d->len);

    //PrintRawDataFp(stdout, d->data, d->len);
    SCHtpTxUserData *htud = (SCHtpTxUserData *) htp_tx_get_user_data(d->tx);
    if (htud == NULL) {
        htud = SCMalloc(sizeof(SCHtpTxUserData));
        if (htud == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            SCReturnInt(HOOK_OK);
        }
        memset(htud, 0, sizeof(SCHtpTxUserData));
        htud->body.operation = HTP_BODY_NONE;
        htud->body.pcre_flags = HTP_PCRE_NONE;

        /* Set the user data for handling body chunks on this transaction */
        htp_tx_set_user_data(d->tx, htud);
    }

    htud->body.operation = HTP_BODY_REQUEST;

    HtpBodyAppendChunk(&htud->body, (uint8_t*)d->data, (uint32_t)d->len);
    htud->body.pcre_flags = HTP_PCRE_NONE;
    if (SCLogDebugEnabled()) {
        HtpBodyPrint(&htud->body);
    }

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

    hstate->flags |= HTP_FLAG_NEW_REQUEST;

    SCLogDebug("HTTP request completed");

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

    /* Unset the body inspection (if any) */
    hstate->flags &=~ HTP_FLAG_NEW_BODY_SET;

    /* remove obsolete transactions */
    size_t idx;
    for (idx = 0; idx < hstate->transaction_done; idx++) {
        htp_tx_t *tx = list_get(hstate->connp->conn->transactions, idx);
        if (tx == NULL)
            continue;

        /* This will remove obsolete body chunks */
        SCHtpTxUserData *htud = (SCHtpTxUserData *) htp_tx_get_user_data(tx);
        if (htud != NULL) {
            HtpBodyFree(&htud->body);
            htp_tx_set_user_data(tx, NULL);
            SCFree(htud);
        }

        htp_tx_destroy(tx);
    }

    SCReturnInt(HOOK_OK);
}

static void HTPConfigure(void)
{
    SCEnter();
    ConfNode *default_config;
    ConfNode *server_config;

    AppLayerRegisterStateFuncs(ALPROTO_HTTP, HTPStateAlloc, HTPStateFree);
    AppLayerRegisterTransactionIdFuncs(ALPROTO_HTTP, HTPStateUpdateTransactionId, HTPStateTransactionFree);

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

    htp_config_register_request(cfglist.cfg, HTPCallbackRequest);
    htp_config_register_response(cfglist.cfg, HTPCallbackResponse);
    htp_config_set_generate_request_uri_normalized(cfglist.cfg, 1);

    default_config = ConfGetNode("libhtp.default-config");
    if (NULL != default_config) {
        ConfNode *p = NULL;

        /* Default Parameters */
        TAILQ_FOREACH(p, &default_config->head, next) {
            ConfNode *pval;

            if (strcasecmp("personality", p->name) == 0) {
                /* Personalities */
                TAILQ_FOREACH(pval, &p->head, next) {
                    int personality = HTPLookupPersonality(pval->val);

                    SCLogDebug("LIBHTP default: %s=%s",
                               p->name, pval->val);


                    if (personality >= 0) {
                        SCLogDebug("LIBHTP default: %s=%s (%d)",
                                   p->name, pval->val,
                                   personality);
                        if (htp_config_set_server_personality(cfglist.cfg,
                                personality) == HTP_ERROR)
                        {
                            SCLogWarning(SC_ERR_INVALID_VALUE,
                                         "LIBHTP Failed adding personality "
                                         "\"%s\", ignoring", pval->val);
                        }
                    }
                    else {
                        SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                                     "LIBHTP Unknown personality "
                                     "\"%s\", ignoring", pval->val);
                        continue;
                    }

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
                    /* Personalities */
                    TAILQ_FOREACH(pval, &p->head, next) {
                        int personality = HTPLookupPersonality(pval->val);

                        SCLogDebug("LIBHTP server %s: %s=%s",
                                   s->name, p->name, pval->val);


                        if (personality >= 0) {
                            SCLogDebug("LIBHTP %s: %s=%s (%d)",
                                       s->name, p->name, pval->val,
                                       personality);
                            if (htp_config_set_server_personality(htp,
                                    personality) == HTP_ERROR)
                            {
                                SCLogWarning(SC_ERR_INVALID_VALUE,
                                             "LIBHTP Failed adding personality "
                                             "\"%s\", ignoring", pval->val);
                            }
                        }
                        else {
                            SCLogWarning(SC_ERR_UNKNOWN_VALUE,
                                         "LIBHTP Unknown personality "
                                         "\"%s\", ignoring", pval->val);
                            continue;
                        }

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

/**
 *  \brief  Register the HTTP protocol and state handling functions to APP layer
 *          of the engine.
 */
void RegisterHTPParsers(void)
{
    SCEnter();
    AppLayerRegisterStateFuncs(ALPROTO_HTTP, HTPStateAlloc, HTPStateFree);

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
    } else {
        SCLogDebug("No htp extra callback needed");
    }
    SCReturn;
}


#ifdef UNITTESTS

/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
int HTPParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

    HtpState *htp_state =  NULL;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(&f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    htp_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    return result;
}

/** \test See how it deals with an incomplete request. */
int HTPParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "POST";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    HtpState *http_state = NULL;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if ((tx->request_method) != NULL || h != NULL)
    {
        printf("expected method NULL, got %s \n", bstr_tocstr(tx->request_method));
        result = 0;
        goto end;
    }

end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    return result;
}

/** \test Test case where method is invalid and data is sent in smaller chunks
 *        and check the response of the parser from HTP library. */
int HTPParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "HELLO / HTTP/1.0\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

    HtpState *htp_state =  NULL;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(&f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }
    htp_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    return result;
}

/** \test Test case where invalid data is sent and check the response of the
 *        parser from HTP library. */
int HTPParserTest04(void) {
    int result = 1;
    Flow f;
    HtpState *htp_state = NULL;
    uint8_t httpbuf1[] = "World!\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1);

    htp_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    return result;
}

/** \test Test both sides of a http stream mixed up to see if the HTP parser
 *        properly parsed them and also keeps them separated. */
int HTPParserTest05(void) {
    int result = 1;
    Flow f;
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

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                          httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf4,
                      httplen4);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf5, httplen5);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3,
                      httplen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_EOF, httpbuf6,
                      httplen6);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    return result;
}

/** \test Test proper chunked encoded response body
 */
int HTPParserTest06(void) {
    int result = 1;
    Flow f;
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

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.src.family = AF_INET;
    f.dst.family = AF_INET;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                          httpbuf1, httplen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                      httplen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    http_state =  f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (http_state != NULL)
        HTPStateFree(http_state);
    return result;
}

#include "conf-yaml-loader.h"

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
    ConfDeInit();
    ConfRestoreContextBackup();

    return ret;
}

/** \test Test traffic is handled by the correct htp config */
int HTPParserConfigTest03(void)
{
    int result = 1;
    Flow f;
    FLOW_INITIALIZE(&f);
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

    ConfYamlLoadString(input, strlen(input));

    HTPConfigure();

    const char *addr = "192.168.10.42";

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.dst.family = AF_INET;
    inet_pton(f.dst.family, addr, f.dst.addr_data32);

    SCRadixNode *cfgnode = NULL;
    htp_cfg_t *htp = cfglist.cfg;
    cfgnode = SCRadixFindKeyIPV4BestMatch((uint8_t *)GET_IPV4_DST_ADDR_PTR(&f), cfgtree);
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
    FlowL7DataPtrInit(&f);

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(&f, ALPROTO_HTTP, flags, &httpbuf1[u], 1);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    htp_state = f.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
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
    ConfDeInit();
    ConfRestoreContextBackup();

    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    if (htp_state != NULL)
        HTPStateFree(htp_state);
    FLOW_DESTROY(&f);
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
    UtRegisterTest("HTPParserConfigTest01", HTPParserConfigTest01, 1);
    UtRegisterTest("HTPParserConfigTest02", HTPParserConfigTest02, 1);
    UtRegisterTest("HTPParserConfigTest03", HTPParserConfigTest03, 1);
#endif /* UNITTESTS */
}

