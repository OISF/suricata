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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Generic App-layer parsing functions.
 */

#include "suricata-common.h"
#include "debug.h"
#include "util-unittest.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"

#include "detect-engine-state.h"
#include "detect-engine-port.h"

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smb.h"
#include "app-layer-dcerpc.h"
#include "app-layer-dcerpc-udp.h"
#include "app-layer-htp.h"
#include "app-layer-ftp.h"
#include "app-layer-ssl.h"
#include "app-layer-ssh.h"
#include "app-layer-smtp.h"

#include "util-spm.h"

#include "util-debug.h"
#include "decode-events.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

AppLayerProto al_proto_table[ALPROTO_MAX];   /**< Application layer protocol
                                                table mapped to their
                                                corresponding parsers */

#define MAX_PARSERS 100
static AppLayerParserTableElement al_parser_table[MAX_PARSERS];
static uint16_t al_max_parsers = 0; /* incremented for every registered parser */

static Pool *al_result_pool = NULL;
static SCMutex al_result_pool_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef DEBUG
static uint32_t al_result_pool_elmts = 0;
#endif /* DEBUG */

/** \brief Get the file container flow
 *  \param f flow pointer to a LOCKED flow
 *  \retval files void pointer to the state
 *  \retval direction flow direction, either STREAM_TOCLIENT or STREAM_TOSERVER
 *  \retval NULL in case we have no state */
FileContainer *AppLayerGetFilesFromFlow(Flow *f, uint8_t direction) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t alproto = f->alproto;

    if (alproto == ALPROTO_UNKNOWN)
        SCReturnPtr(NULL, "FileContainer");

    if (al_proto_table[alproto].StateGetFiles != NULL) {
        FileContainer *ptr = al_proto_table[alproto].StateGetFiles(AppLayerGetProtoStateFromFlow(f), direction);
        SCReturnPtr(ptr, "FileContainer");
    } else {
        SCReturnPtr(NULL, "FileContainer");
    }
}

/** \brief Alloc a AppLayerParserResultElmt func for the pool */
static void *AlpResultElmtPoolAlloc()
{
    AppLayerParserResultElmt *e = NULL;

    e = (AppLayerParserResultElmt *)SCMalloc
        (sizeof(AppLayerParserResultElmt));
    if (e == NULL)
        return NULL;

#ifdef DEBUG
    al_result_pool_elmts++;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
    return e;
}

static void AlpResultElmtPoolCleanup(void *e)
{
    AppLayerParserResultElmt *re = (AppLayerParserResultElmt *)e;

    if (re->flags & ALP_RESULT_ELMT_ALLOC) {
        if (re->data_ptr != NULL)
            SCFree(re->data_ptr);
    }

#ifdef DEBUG
    al_result_pool_elmts--;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
}

static AppLayerParserResultElmt *AlpGetResultElmt(void)
{
    SCMutexLock(&al_result_pool_mutex);
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)PoolGet(al_result_pool);
    SCMutexUnlock(&al_result_pool_mutex);

    if (e == NULL) {
        return NULL;
    }
    e->next = NULL;
    return e;
}

static void AlpReturnResultElmt(AppLayerParserResultElmt *e)
{
    if (e->flags & ALP_RESULT_ELMT_ALLOC) {
        if (e->data_ptr != NULL)
            SCFree(e->data_ptr);
    }
    e->flags = 0;
    e->data_ptr = NULL;
    e->data_len = 0;
    e->next = NULL;

    SCMutexLock(&al_result_pool_mutex);
    PoolReturn(al_result_pool, (void *)e);
    SCMutexUnlock(&al_result_pool_mutex);
}

static void AlpAppendResultElmt(AppLayerParserResult *r, AppLayerParserResultElmt *e)
{
    if (r->head == NULL) {
        r->head = e;
        r->tail = e;
        r->cnt = 1;
    } else {
        r->tail->next = e;
        r->tail = e;
        r->cnt++;
    }
}

/**
 *  \param alloc Is ptr alloc'd (1) or a ptr to static mem (0).
 *  \retval -1 error
 *  \retval 0 ok
 */
static int AlpStoreField(AppLayerParserResult *output, uint16_t idx,
                         uint8_t *ptr, uint32_t len, uint8_t alloc)
{
    SCEnter();

    AppLayerParserResultElmt *e = AlpGetResultElmt();
    if (e == NULL) {
        SCLogError(SC_ERR_POOL_EMPTY, "App layer \"al_result_pool\" is empty");
        SCReturnInt(-1);
    }

    if (alloc == 1)
        e->flags |= ALP_RESULT_ELMT_ALLOC;

    e->name_idx = idx;
    e->data_ptr = ptr;
    e->data_len = len;
    AlpAppendResultElmt(output, e);

    SCReturnInt(0);
}

void AppLayerSetEOF(Flow *f)
{
    if (f == NULL)
        return;

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        parser_state_store->id_flags |= APP_LAYER_TRANSACTION_EOF;
        parser_state_store->to_client.flags |= APP_LAYER_PARSER_EOF;
        parser_state_store->to_server.flags |= APP_LAYER_PARSER_EOF;
    }
}

/** \brief Parse a field up to we reach the size limit
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldBySize(AppLayerParserResult *output, AppLayerParserState *pstate,
                        uint16_t field_idx, uint32_t size, uint8_t *input,
                        uint32_t input_len, uint32_t *offset)
{
    SCEnter();

    if ((pstate->store_len + input_len) < size) {
        if (pstate->store_len == 0) {
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        } else {
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }
    } else {
        if (pstate->store_len == 0) {
            int r = AlpStoreField(output, field_idx, input, size, /* static mem */0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += size;

            SCReturnInt(1);
        } else {
            uint32_t diff = size - pstate->store_len;

            pstate->store = SCRealloc(pstate->store, (diff + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, diff);
            pstate->store_len += diff;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, /* alloc mem */1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            (*offset) += diff;

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/** \brief Parse a field up to the EOF
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByEOF(AppLayerParserResult *output, AppLayerParserState *pstate,
                       uint16_t field_idx, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    if (pstate->store_len == 0) {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len 0 and EOF");

            int r = AlpStoreField(output, field_idx, input, input_len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len 0 but no EOF");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len %" PRIu32 " and EOF", pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            int r = AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }

            pstate->store = NULL;
            pstate->store_len = 0;

            SCReturnInt(1);
        } else {
            SCLogDebug("store_len %" PRIu32 " but no EOF", pstate->store_len);

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }

    }

    SCReturnInt(0);
}

/** \brief Parse a field up to a delimeter.
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByDelimiter(AppLayerParserResult *output, AppLayerParserState *pstate,
                            uint16_t field_idx, const uint8_t *delim, uint8_t delim_len,
                            uint8_t *input, uint32_t input_len, uint32_t *offset)
{
    SCEnter();
    SCLogDebug("pstate->store_len %" PRIu32 ", delim_len %" PRIu32 "",
                pstate->store_len, delim_len);

    if (pstate->store_len == 0) {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug(" len %" PRIu32 "", len);

            int r = AlpStoreField(output, field_idx, input, len, 0);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                SCLogDebug("delim not found and EOF");
                SCReturnInt(0);
            }

            SCLogDebug("delim not found, continue");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCMalloc(input_len);
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        uint8_t *ptr = SpmSearch(input, input_len, (uint8_t*)delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            SCLogDebug("len %" PRIu32 " + %" PRIu32 " = %" PRIu32 "", len,
                        pstate->store_len, len + pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, len);
            pstate->store_len += len;

            int r = AlpStoreField(output, field_idx, pstate->store,
                                  pstate->store_len, 1);
            if (r == -1) {
                SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                SCReturnInt(-1);
            }
            pstate->store = NULL;
            pstate->store_len = 0;

            (*offset) += (len + delim_len);
            SCReturnInt(1);
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                /* if the input len is smaller than the delim len we search the
                 * pstate->store since we may match there. */
                if (delim_len > input_len) {
                    /* delimiter field not found, so store the result for the
                     * next run */
                    pstate->store = SCRealloc(pstate->store, (input_len +
                                            pstate->store_len));
                    if (pstate->store == NULL)
                        SCReturnInt(-1);

                    memcpy(pstate->store+pstate->store_len, input, input_len);
                    pstate->store_len += input_len;
                    SCLogDebug("input_len < delim_len, checking pstate->store");

                    if (pstate->store_len >= delim_len) {
                        ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim,
                                        delim_len);
                        if (ptr != NULL) {
                            SCLogDebug("now we found the delim");

                            uint32_t len = ptr - pstate->store;
                            int r = AlpStoreField(output, field_idx,
                                                  pstate->store, len, 1);
                            if (r == -1) {
                                SCLogError(SC_ERR_ALPARSER, "Failed to store "
                                           "field value");
                                SCReturnInt(-1);
                            }

                            pstate->store = NULL;
                            pstate->store_len = 0;

                            (*offset) += (input_len);

                            SCLogDebug("offset %" PRIu32 "", (*offset));
                            SCReturnInt(1);
                        }
                        goto free_and_return;
                    }
                    goto free_and_return;
                }
            free_and_return:
                SCLogDebug("not found and EOF, so free what we have so far.");
                SCFree(pstate->store);
                pstate->store = NULL;
                pstate->store_len = 0;
                SCReturnInt(0);
            }

            /* delimiter field not found, so store the result for the next run */
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                SCReturnInt(-1);

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            /* if the input len is smaller than the delim len we search the
             * pstate->store since we may match there. */
            if (delim_len > input_len && delim_len <= pstate->store_len) {
                SCLogDebug("input_len < delim_len, checking pstate->store");

                ptr = SpmSearch(pstate->store, pstate->store_len, (uint8_t*)delim, delim_len);
                if (ptr != NULL) {
                    SCLogDebug("now we found the delim");

                    uint32_t len = ptr - pstate->store;
                    int r = AlpStoreField(output, field_idx, pstate->store, len, 1);
                    if (r == -1) {
                        SCLogError(SC_ERR_ALPARSER, "Failed to store field value");
                        SCReturnInt(-1);
                    }
                    pstate->store = NULL;
                    pstate->store_len = 0;

                    (*offset) += (input_len);

                    SCLogDebug("ffset %" PRIu32 "", (*offset));
                    SCReturnInt(1);
                }
            }
        }

    }

    SCReturnInt(0);
}

uint16_t AppLayerGetProtoByName(const char *name)
{
    uint8_t u = 1;
    SCLogDebug("looking for name %s", name);

    for ( ; u < ALPROTO_MAX; u++) {
        if (al_proto_table[u].name == NULL)
            continue;

        SCLogDebug("name %s proto %"PRIu16"",
            al_proto_table[u].name, u);

        if (strcasecmp(name,al_proto_table[u].name) == 0) {
            SCLogDebug("match, returning %"PRIu16"", u);
            return u;
        }
    }

    AppLayerProbingParser *pp = alp_proto_ctx.probing_parsers;
    while (pp != NULL) {
        AppLayerProbingParserPort *pp_port = pp->port;
        while (pp_port != NULL) {
            AppLayerProbingParserElement *pp_pe = pp_port->toserver;
            while (pp_pe != NULL) {
                if (strcasecmp(pp_pe->al_proto_name, name) == 0) {
                    return pp_pe->al_proto;
                }

                pp_pe = pp_pe->next;
            }

            pp_pe = pp_port->toclient;
            while (pp_pe != NULL) {
                if (strcasecmp(pp_pe->al_proto_name, name) == 0) {
                    return pp_pe->al_proto;
                }

                pp_pe = pp_pe->next;
            }

            pp_port = pp_port->next;
        }
        pp = pp->next;
    }

    return ALPROTO_UNKNOWN;
}

/** \brief Description: register a parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id,
                           int (*AppLayerParser)(Flow *f, void *protocol_state,
                                                 AppLayerParserState *parser_state,
                                                 uint8_t *input, uint32_t input_len,
                                                 void *local_data,
                                                 AppLayerParserResult *output),
                           char *dependency)
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].proto = proto;
    al_parser_table[al_max_parsers].parser_local_id = parser_id;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    SCLogDebug("registered %p at proto %" PRIu32 ", al_proto_table idx "
               "%" PRIu32 ", parser_local_id %" PRIu32 "",
                AppLayerParser, proto, al_max_parsers,
                parser_id);
    return 0;
}

/** \brief Description: register a protocol parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterProto(char *name, uint8_t proto, uint8_t flags,
                          int (*AppLayerParser)(Flow *f, void *protocol_state,
                                                AppLayerParserState *parser_state,
                                                uint8_t *input, uint32_t input_len,
                                                void *local_data, AppLayerParserResult *output))
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    /* create proto, direction -- parser mapping */
    if (flags & STREAM_TOSERVER) {
        al_proto_table[proto].to_server = al_max_parsers;
    } else if (flags & STREAM_TOCLIENT) {
        al_proto_table[proto].to_client = al_max_parsers;
    }

    SCLogDebug("registered %p at proto %" PRIu32 " flags %02X, al_proto_table "
                "idx %" PRIu32 ", %s", AppLayerParser, proto,
                flags, al_max_parsers, name);
    return 0;
}

void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void),
                                void (*StateFree)(void *))
{
    al_proto_table[proto].StateAlloc = StateAlloc;
    al_proto_table[proto].StateFree = StateFree;
}

void AppLayerRegisterTransactionIdFuncs(uint16_t proto,
        void (*StateUpdateTransactionId)(void *state, uint16_t *), void (*StateTransactionFree)(void *, uint16_t))
{
    al_proto_table[proto].StateUpdateTransactionId = StateUpdateTransactionId;
    al_proto_table[proto].StateTransactionFree = StateTransactionFree;
}

void AppLayerRegisterLocalStorageFunc(uint16_t proto,
                                      void *(*LocalStorageAlloc)(void),
                                      void (*LocalStorageFree)(void *))
{
    al_proto_table[proto].LocalStorageAlloc = LocalStorageAlloc;
    al_proto_table[proto].LocalStorageFree = LocalStorageFree;

    return;
}

void AppLayerRegisterTruncateFunc(uint16_t proto, void (*Truncate)(void *, uint8_t))
{
    al_proto_table[proto].Truncate = Truncate;

    return;
}

void AppLayerStreamTruncated(uint16_t proto, void *state, uint8_t flags) {
    if (al_proto_table[proto].Truncate != NULL) {
        al_proto_table[proto].Truncate(state, flags);
    }
}

void *AppLayerGetProtocolParserLocalStorage(uint16_t proto)
{
    if (al_proto_table[proto].LocalStorageAlloc != NULL) {
        return al_proto_table[proto].LocalStorageAlloc();
    }

    return NULL;
}

void AppLayerRegisterGetFilesFunc(uint16_t proto,
        FileContainer *(*StateGetFiles)(void *, uint8_t))
{
    al_proto_table[proto].StateGetFiles = StateGetFiles;
}

/** \brief Indicate to the app layer parser that a logger is active
 *         for this protocol.
 */
void AppLayerRegisterLogger(uint16_t proto) {
    al_proto_table[proto].logger = TRUE;
}


AppLayerParserStateStore *AppLayerParserStateStoreAlloc(void)
{
    AppLayerParserStateStore *s = (AppLayerParserStateStore *)SCMalloc
                                    (sizeof(AppLayerParserStateStore));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserStateStore));

    /* when we start, we're working with transaction id 1 */
    s->avail_id = 1;

    return s;
}

/** \brief free a AppLayerParserStateStore structure
 *  \param s AppLayerParserStateStore structure to free */
void AppLayerParserStateStoreFree(AppLayerParserStateStore *s)
{
    if (s->to_server.store != NULL)
        SCFree(s->to_server.store);
    if (s->to_client.store != NULL)
        SCFree(s->to_client.store);
    if (s->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(s->decoder_events);
    s->decoder_events = NULL;

    SCFree(s);
}

static void AppLayerParserResultCleanup(AppLayerParserResult *result)
{
    AppLayerParserResultElmt *e = result->head;
    while (e != NULL) {
        AppLayerParserResultElmt *next_e = e->next;

        result->head = next_e;
        if (next_e == NULL)
            result->tail = NULL;
        result->cnt--;

        AlpReturnResultElmt(e);
        e = next_e;
    }
}

static int AppLayerDoParse(void *local_data, Flow *f,
                           void *app_layer_state,
                           AppLayerParserState *parser_state,
                           uint8_t *input, uint32_t input_len,
                           uint16_t parser_idx,
                           uint16_t proto)
{
    SCEnter();
    DEBUG_ASSERT_FLOW_LOCKED(f);

    int retval = 0;
    AppLayerParserResult result = { NULL, NULL, 0 };

    SCLogDebug("parser_idx %" PRIu32 "", parser_idx);
    //printf("--- (%u)\n", input_len);
    //PrintRawDataFp(stdout, input,input_len);
    //printf("---\n");

    /* invoke the parser */
    int r = al_parser_table[parser_idx].
        AppLayerParser(f, app_layer_state,
                       parser_state, input, input_len,
                       local_data, &result);
    if (r < 0) {
        if (r == -1) {
            AppLayerParserResultCleanup(&result);
            SCReturnInt(-1);
#ifdef DEBUG
        } else {
            BUG_ON(r);  /* this is not supposed to happen!! */
#else
            SCReturnInt(-1);
#endif
        }
    }

    /* process the result elements */
    AppLayerParserResultElmt *e = result.head;
    for (; e != NULL; e = e->next) {
        SCLogDebug("e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len "
                   "%" PRIu32 ", map_size %" PRIu32 "", e, e->name_idx,
                   e->data_ptr, e->data_len, al_proto_table[proto].map_size);

        /* no parser defined for this field. */
        if (e->name_idx >= al_proto_table[proto].map_size ||
                al_proto_table[proto].map[e->name_idx] == NULL)
        {
            SCLogDebug("no parser for proto %" PRIu32 ", parser_local_id "
                        "%" PRIu32 "", proto, e->name_idx);
            continue;
        }

        uint16_t idx = al_proto_table[proto].map[e->name_idx]->parser_id;

        /* prepare */
        uint16_t tmp = parser_state->parse_field;
        parser_state->parse_field = 0;
        parser_state->flags |= APP_LAYER_PARSER_EOF;

        r = AppLayerDoParse(local_data, f, app_layer_state, parser_state, e->data_ptr,
                            e->data_len, idx, proto);

        /* restore */
        parser_state->flags &= ~APP_LAYER_PARSER_EOF;
        parser_state->parse_field = tmp;

        /* bail out on a serious error */
        if (r < 0) {
            if (r == -1) {
                retval = -1;
                break;
#ifdef DEBUG
            } else {
                BUG_ON(r);  /* this is not supposed to happen!! */
#else
                SCReturnInt(-1);
#endif
            }
        }
    }

    AppLayerParserResultCleanup(&result);
    SCReturnInt(retval);
}

/** \brief remove obsolete (inspected and logged) transactions */
static int AppLayerTransactionsCleanup(AppLayerProto *p, AppLayerParserStateStore *parser_state_store, void *app_layer_state) {
    SCEnter();

    uint16_t obsolete = 0;

    if (p->StateTransactionFree == NULL) {
        SCLogDebug("no StateTransactionFree function");
        goto end;
    }

    if (p->logger == TRUE) {
        uint16_t low = (parser_state_store->logged_id < parser_state_store->inspect_id) ?
            parser_state_store->logged_id : parser_state_store->inspect_id;

        obsolete = low - parser_state_store->base_id;

        SCLogDebug("low %"PRIu16" (logged %"PRIu16", inspect %"PRIu16"), base_id %"PRIu16", obsolete %"PRIu16", avail_id %"PRIu16,
                low, parser_state_store->logged_id, parser_state_store->inspect_id, parser_state_store->base_id, obsolete, parser_state_store->avail_id);
    } else {
        obsolete = parser_state_store->inspect_id - parser_state_store->base_id;
    }

    SCLogDebug("obsolete transactions: %"PRIu16, obsolete);

    /* call the callback on the obsolete transactions */
    while ((obsolete--)) {
        p->StateTransactionFree(app_layer_state, parser_state_store->base_id);
        parser_state_store->base_id++;
    }

    SCLogDebug("base_id %"PRIu16, parser_state_store->base_id);

end:
    SCReturnInt(0);
}

#ifdef DEBUG
uint32_t applayererrors = 0;
uint32_t applayerhttperrors = 0;
#endif

/**
 * \brief Layer 7 Parsing main entry point.
 *
 * \param f Properly initialized and locked flow.
 * \param proto L7 proto, e.g. ALPROTO_HTTP
 * \param flags Stream flags
 * \param input Input L7 data
 * \param input_len Length of the input data.
 *
 * \retval -1 error
 * \retval 0 ok
 */
int AppLayerParse(void *local_data, Flow *f, uint8_t proto,
                  uint8_t flags, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];
    TcpSession *ssn = NULL;

    /* Used only if it's TCP */
    ssn = f->protoctx;

    /* Do this check before calling AppLayerParse */
    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), this is not yet supported.");

        if (f->alstate != NULL)
            AppLayerStreamTruncated(proto, f->alstate, flags);
        goto error;
    }

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = f->alparser;
    if (parser_state_store == NULL) {
        parser_state_store = AppLayerParserStateStoreAlloc();
        if (parser_state_store == NULL)
            goto error;

        f->alparser = (void *)parser_state_store;
    }

    parser_state_store->version++;
    SCLogDebug("app layer state version incremented to %"PRIu16,
            parser_state_store->version);

    AppLayerParserState *parser_state = NULL;
    if (flags & STREAM_TOSERVER) {
        SCLogDebug("to_server msg (flow %p)", f);

        parser_state = &parser_state_store->to_server;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_server;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_server)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    } else {
        SCLogDebug("to_client msg (flow %p)", f);

        parser_state = &parser_state_store->to_client;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_client;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            SCLogDebug("using parser %" PRIu32 " we stored before (to_client)",
                        parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    }

    if (parser_idx == 0 || parser_state->flags & APP_LAYER_PARSER_DONE) {
        SCLogDebug("no parser for protocol %" PRIu32 "", proto);
        SCReturnInt(0);
    }

    if (flags & STREAM_EOF)
        parser_state->flags |= APP_LAYER_PARSER_EOF;

    /* See if we already have a 'app layer' state */
    void *app_layer_state = f->alstate;
    if (app_layer_state == NULL) {
        /* lock the allocation of state as we may
         * alloc more than one otherwise */
        app_layer_state = p->StateAlloc();
        if (app_layer_state == NULL) {
            goto error;
        }

        f->alstate = app_layer_state;
        SCLogDebug("alloced new app layer state %p (name %s)",
                app_layer_state, al_proto_table[f->alproto].name);
    } else {
        SCLogDebug("using existing app layer state %p (name %s))",
                app_layer_state, al_proto_table[f->alproto].name);
    }

    /* invoke the recursive parser, but only on data. We may get empty msgs on EOF */
    if (input_len > 0) {
        int r = AppLayerDoParse(local_data, f, app_layer_state, parser_state,
                                input, input_len, parser_idx, proto);
        if (r < 0)
            goto error;
    }

    /* set the packets to no inspection and reassembly if required */
    if (parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        AppLayerSetEOF(f);
        FlowSetNoPayloadInspectionFlag(f);
        FlowSetSessionNoApplayerInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (parser_state->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            if (ssn != NULL) {
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOCLIENT ? 1 : 0);
                StreamTcpSetSessionNoReassemblyFlag(ssn,
                        flags & STREAM_TOSERVER ? 1 : 0);
            }
        }
    }

    /* update the transaction id */
    if (p->StateUpdateTransactionId != NULL) {
        p->StateUpdateTransactionId(app_layer_state, &parser_state_store->avail_id);

        /* next, see if we can get rid of transactions now */
        AppLayerTransactionsCleanup(p, parser_state_store, app_layer_state);
    }
    if (parser_state->flags & APP_LAYER_PARSER_EOF) {
        SCLogDebug("eof, flag Transaction id's");
        parser_state_store->id_flags |= APP_LAYER_TRANSACTION_EOF;
    }

    /* stream truncated, inform app layer */
    if (flags & STREAM_DEPTH) {
        AppLayerStreamTruncated(proto, app_layer_state, flags);
    }

    SCReturnInt(0);

error:
    if (ssn != NULL) {
#ifdef DEBUG
        if (FLOW_IS_IPV4(f)) {
            char src[16];
            char dst[16];
            PrintInet(AF_INET, (const void*)&f->src.addr_data32[0], src,
                      sizeof (src));
            PrintInet(AF_INET, (const void*)&f->dst.addr_data32[0], dst,
                      sizeof (dst));

            SCLogDebug("Error occured in parsing \"%s\" app layer "
                       "protocol, using network protocol %"PRIu8", source IP "
                       "address %s, destination IP address %s, src port %"PRIu16" and "
                       "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                       f->proto, src, dst, f->sp, f->dp);
            fflush(stdout);
        } else if (FLOW_IS_IPV6(f)) {
            char dst6[46];
            char src6[46];

            PrintInet(AF_INET6, (const void*)&f->src.addr_data32, src6,
                      sizeof (src6));
            PrintInet(AF_INET6, (const void*)&f->dst.addr_data32, dst6,
                      sizeof (dst6));

            SCLogDebug("Error occured in parsing \"%s\" app layer "
                       "protocol, using network protocol %"PRIu8", source IPv6 "
                       "address %s, destination IPv6 address %s, src port %"PRIu16" and "
                       "dst port %"PRIu16"", al_proto_table[f->alproto].name,
                       f->proto, src6, dst6, f->sp, f->dp);
            fflush(stdout);
        }
        applayererrors++;
        if (f->alproto == ALPROTO_HTTP)
            applayerhttperrors++;
#endif
        /* Set the no app layer inspection flag for both
         * the stream in this Flow */
        FlowSetSessionNoApplayerInspectionFlag(f);
        AppLayerSetEOF(f);
    }

    SCReturnInt(-1);
}

/** \brief get the base transaction id */
int AppLayerTransactionGetBaseId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->base_id);

error:
    SCReturnInt(-1);
}

/** \brief get the base transaction id
 *
 *  \retval txid or -1 on error
 */
int AppLayerTransactionGetInspectId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->inspect_id);

error:
    SCReturnInt(-1);
}

uint16_t AppLayerTransactionGetAvailId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        SCReturnUInt(0);
    }

    SCReturnUInt(parser_state_store->avail_id);
}

/** \brief get the highest loggable transaction id */
int AppLayerTransactionGetLoggableId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    int id = 0;

    if (parser_state_store->id_flags & APP_LAYER_TRANSACTION_EOF) {
        SCLogDebug("eof, return current transaction as well");
        id = (int)(parser_state_store->avail_id);
    } else {
        id = (int)(parser_state_store->avail_id - 1);
    }

    SCReturnInt(id);

error:
    SCReturnInt(-1);
}

/** \brief get the highest loggable transaction id */
void AppLayerTransactionUpdateLoggedId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    parser_state_store->logged_id++;
    SCReturn;

error:
    SCReturn;
}
/** \brief get the highest loggable transaction id */
int AppLayerTransactionGetLoggedId(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    AppLayerParserStateStore *parser_state_store =
        (AppLayerParserStateStore *)f->alparser;

    if (parser_state_store == NULL) {
        SCLogDebug("no state store");
        goto error;
    }

    SCReturnInt((int)parser_state_store->logged_id);

error:
    SCReturnInt(-1);
}

/**
 *  \brief get the version of the state in a direction
 *
 *  \param f LOCKED flow
 *  \param direction STREAM_TOSERVER or STREAM_TOCLIENT
 */
uint16_t AppLayerGetStateVersion(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    uint16_t version = 0;
    AppLayerParserStateStore *parser_state_store = NULL;

    parser_state_store = (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        version = parser_state_store->version;
    }

    SCReturnUInt(version);
}

/**
 *  \param f LOCKED flow
 *  \param direction STREAM_TOSERVER or STREAM_TOCLIENT
 *
 *  \retval 2 current transaction done, new available
 *  \retval 1 current transaction done, no new (yet)
 *  \retval 0 current transaction is not done yet
 */
int AppLayerTransactionUpdateInspectId(Flow *f, char direction)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    int r = 0;
    AppLayerParserStateStore *parser_state_store = NULL;

    parser_state_store = (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        /* update inspect_id and see if it there are other transactions
         * as well */

        SCLogDebug("avail_id %"PRIu16", inspect_id %"PRIu16,
                parser_state_store->avail_id, parser_state_store->inspect_id);

        if (direction == STREAM_TOSERVER) {
            SCLogDebug("toserver");
            parser_state_store->id_flags |= APP_LAYER_TRANSACTION_TOSERVER;
        } else {
            SCLogDebug("toclient");
            parser_state_store->id_flags |= APP_LAYER_TRANSACTION_TOCLIENT;
        }

        if ((parser_state_store->inspect_id+1) < parser_state_store->avail_id &&
                (parser_state_store->id_flags & APP_LAYER_TRANSACTION_TOCLIENT) &&
                (parser_state_store->id_flags & APP_LAYER_TRANSACTION_TOSERVER))
        {
            parser_state_store->id_flags &=~ APP_LAYER_TRANSACTION_TOCLIENT;
            parser_state_store->id_flags &=~ APP_LAYER_TRANSACTION_TOSERVER;

            parser_state_store->inspect_id = parser_state_store->avail_id - 1;
            if (parser_state_store->inspect_id < parser_state_store->avail_id) {
                /* done and more transactions available */
                r = 2;

                SCLogDebug("inspect_id %"PRIu16", avail_id %"PRIu16,
                        parser_state_store->inspect_id,
                        parser_state_store->avail_id);
            } else {
                /* done but no more transactions available */
                r = 1;

                SCLogDebug("inspect_id %"PRIu16", avail_id %"PRIu16,
                        parser_state_store->inspect_id,
                        parser_state_store->avail_id);
            }
        }
    }

    SCReturnInt(r);
}

void AppLayerListSupportedProtocols(void)
{
    uint32_t i;
    uint32_t temp_alprotos_buf[ALPROTO_MAX];
    memset(temp_alprotos_buf, 0, sizeof(temp_alprotos_buf));

    printf("=========Supported App Layer Protocols=========\n");

    /* for each proto, alloc the map array */
    for (i = 0; i < ALPROTO_MAX; i++) {
        if (al_proto_table[i].name == NULL)
            continue;

        temp_alprotos_buf[i] = 1;
        printf("%s\n", al_proto_table[i].name);
    }

    AppLayerProbingParser *pp = alp_proto_ctx.probing_parsers;
    while (pp != NULL) {
        AppLayerProbingParserPort *pp_port = pp->port;
        while (pp_port != NULL) {
            AppLayerProbingParserElement *pp_pe = pp_port->toserver;
            while (pp_pe != NULL) {
                if (temp_alprotos_buf[pp_pe->al_proto] == 1) {
                    pp_pe = pp_pe->next;
                    continue;
                }

                printf("%s\n", pp_pe->al_proto_name);
                pp_pe = pp_pe->next;
            }

            pp_pe = pp_port->toclient;
            while (pp_pe != NULL) {
                if (temp_alprotos_buf[pp_pe->al_proto] == 1) {
                    pp_pe = pp_pe->next;;
                    continue;
                }

                printf("%s\n", pp_pe->al_proto_name);
                pp_pe = pp_pe->next;
            }

            pp_port = pp_port->next;
        }
        pp = pp->next;
    }

    return;
}

AppLayerDecoderEvents *AppLayerGetDecoderEventsForFlow(Flow *f)
{
    DEBUG_ASSERT_FLOW_LOCKED(f);

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = NULL;

    if (f == NULL || f->alparser == NULL) {
        return NULL;
    }

    parser_state_store = (AppLayerParserStateStore *)f->alparser;
    if (parser_state_store != NULL) {
        return parser_state_store->decoder_events;
    }

    return NULL;
}

/**
 *  \brief Trigger "raw" stream reassembly from the app layer.
 *
 *  This way HTTP for example, can trigger raw stream inspection right
 *  when the full request body is received. This is often smaller than
 *  our raw reassembly size limit.
 *
 *  \param f flow, for access the stream state
 */
void AppLayerTriggerRawStreamReassembly(Flow *f) {
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

#ifdef DEBUG
    BUG_ON(f == NULL);
#endif

    if (f != NULL && f->protoctx != NULL) {
        TcpSession *ssn = (TcpSession *)f->protoctx;
        StreamTcpReassembleTriggerRawReassembly(ssn);
    }

    SCReturn;
}

void RegisterAppLayerParsers(void)
{
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    /** setup result pool
     * \todo Per thread pool */
    al_result_pool = PoolInit(1000, 250,
            sizeof(AppLayerParserResultElmt),
            AlpResultElmtPoolAlloc, NULL, NULL,
            AlpResultElmtPoolCleanup, NULL);

    RegisterHTPParsers();
    RegisterSSLParsers();
    RegisterSMBParsers();
    RegisterDCERPCParsers();
    RegisterDCERPCUDPParsers();
    RegisterFTPParsers();
    RegisterSSHParsers();
    RegisterSMTPParsers();

    /** IMAP */
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "|2A 20|OK|20|", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, "imap", IPPROTO_TCP, ALPROTO_IMAP, "1|20|capability", 12, 0, STREAM_TOSERVER);

    /** MSN Messenger */
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, "msn", IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOSERVER);

    /** Jabber */
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOCLIENT);
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOSERVER);

    return;
}

void AppLayerParserCleanupState(Flow *f)
{
    if (f == NULL) {
        SCLogDebug("no flow");
        return;
    }
    if (f->alproto >= ALPROTO_MAX) {
        SCLogDebug("app layer proto unknown");
        return;
    }

    /* free the parser protocol state */
    AppLayerProto *p = &al_proto_table[f->alproto];
    if (p->StateFree != NULL && f->alstate != NULL) {
        SCLogDebug("calling StateFree");
        p->StateFree(f->alstate);
        f->alstate = NULL;
    }

    /* free the app layer parser api state */
    if (f->alparser != NULL) {
        SCLogDebug("calling AppLayerParserStateStoreFree");
        AppLayerParserStateStoreFree(f->alparser);
        f->alparser = NULL;
    }
}

/** \brief Create a mapping between the individual parsers local field id's
 *         and the global field parser id's.
 *
 */
void AppLayerParsersInitPostProcess(void)
{
    uint16_t u16 = 0;

    /* build local->global mapping */
    for (u16 = 1; u16 <= al_max_parsers; u16++) {
        /* no local parser */
        if (al_parser_table[u16].parser_local_id == 0)
            continue;

        if (al_parser_table[u16].parser_local_id >
                al_proto_table[al_parser_table[u16].proto].map_size)
        {
            al_proto_table[al_parser_table[u16].proto].map_size =
                                           al_parser_table[u16].parser_local_id;
        }
        SCLogDebug("map_size %" PRIu32 "", al_proto_table
                                        [al_parser_table[u16].proto].map_size);
    }

    /* for each proto, alloc the map array */
    for (u16 = 0; u16 < ALPROTO_MAX; u16++) {
        if (al_proto_table[u16].map_size == 0)
            continue;

        al_proto_table[u16].map_size++;
        al_proto_table[u16].map = (AppLayerLocalMap **)SCMalloc
                                    (al_proto_table[u16].map_size *
                                        sizeof(AppLayerLocalMap *));
        if (al_proto_table[u16].map == NULL) {
            SCLogError(SC_ERR_FATAL, "Fatal error encountered in AppLayerParsersInitPostProcess. Exiting...");
            exit(EXIT_FAILURE);
        }
        memset(al_proto_table[u16].map, 0, al_proto_table[u16].map_size *
                sizeof(AppLayerLocalMap *));

        uint16_t u = 0;
        for (u = 1; u <= al_max_parsers; u++) {
            /* no local parser */
            if (al_parser_table[u].parser_local_id == 0)
                continue;

            if (al_parser_table[u].proto != u16)
                continue;

            uint16_t parser_local_id = al_parser_table[u].parser_local_id;
            SCLogDebug("parser_local_id: %" PRIu32 "", parser_local_id);

            if (parser_local_id < al_proto_table[u16].map_size) {
                al_proto_table[u16].map[parser_local_id] = SCMalloc(sizeof(AppLayerLocalMap));
                if (al_proto_table[u16].map[parser_local_id] == NULL) {
                    exit(EXIT_FAILURE);
                }

                al_proto_table[u16].map[parser_local_id]->parser_id = u;
            }
        }
    }

    for (u16 = 0; u16 < ALPROTO_MAX; u16++) {
        if (al_proto_table[u16].map_size == 0)
            continue;

        if (al_proto_table[u16].map == NULL)
            continue;

        uint16_t x = 0;
        for (x = 0; x < al_proto_table[u16].map_size; x++) {
            if (al_proto_table[u16].map[x] == NULL)
                continue;

           SCLogDebug("al_proto_table[%" PRIu32 "].map[%" PRIu32 "]->parser_id:"
                      " %" PRIu32 "", u16, x, al_proto_table[u16].map[x]->parser_id);
        }
    }
}

/********************************Probing Parsers*******************************/


static uint32_t AppLayerProbingParserGetMask(uint16_t al_proto)
{
    if (al_proto > ALPROTO_UNKNOWN &&
        al_proto < ALPROTO_FAILED) {
        return (1 << al_proto);
    } else {
        SCLogError(SC_ERR_ALPARSER, "Unknown protocol detected - %"PRIu16,
                   al_proto);
        exit(EXIT_FAILURE);
    }
}

static inline AppLayerProbingParserElement *AllocAppLayerProbingParserElement(void)
{
    AppLayerProbingParserElement *p = SCMalloc(sizeof(AppLayerProbingParserElement));
    if (p == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProbingParserElement));

    return p;
}


static inline void DeAllocAppLayerProbingParserElement(AppLayerProbingParserElement *p)
{
    SCFree(p->al_proto_name);
    SCFree(p);
    return;
}

static inline AppLayerProbingParserPort *AllocAppLayerProbingParserPort(void)
{
    AppLayerProbingParserPort *p = SCMalloc(sizeof(AppLayerProbingParserPort));
    if (p == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProbingParserPort));

    return p;
}

static inline void DeAllocAppLayerProbingParserPort(AppLayerProbingParserPort *p)
{
    AppLayerProbingParserElement *e;

    e = p->toserver;
    while (e != NULL) {
        AppLayerProbingParserElement *e_next = e->next;
        DeAllocAppLayerProbingParserElement(e);
        e = e_next;
    }

    e = p->toclient;
    while (e != NULL) {
        AppLayerProbingParserElement *e_next = e->next;
        DeAllocAppLayerProbingParserElement(e);
        e = e_next;
    }

    SCFree(p);

    return;
}

static inline AppLayerProbingParser *AllocAppLayerProbingParser(void)
{
    AppLayerProbingParser *p = SCMalloc(sizeof(AppLayerProbingParser));
    if (p == NULL) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProbingParser));

    return p;
}

static inline void DeAllocAppLayerProbingParser(AppLayerProbingParser *p)
{
    AppLayerProbingParserPort *pt = p->port;
    while (pt != NULL) {
        AppLayerProbingParserPort *pt_next = pt->next;
        DeAllocAppLayerProbingParserPort(pt);
        pt = pt_next;
    }

    SCFree(p);

    return;
}

static AppLayerProbingParserElement *
AppLayerCreateAppLayerProbingParserElement(const char *al_proto_name,
                                           uint16_t al_proto,
                                           uint16_t port,
                                           uint16_t min_depth,
                                           uint16_t max_depth,
                                           uint16_t (*AppLayerProbingParser)
                                           (uint8_t *input, uint32_t input_len, uint32_t *offset))
{
    AppLayerProbingParserElement *pe = AllocAppLayerProbingParserElement();

    pe->al_proto_name = SCStrdup(al_proto_name);
    if (pe->al_proto_name == NULL)
        exit(EXIT_FAILURE);
    pe->al_proto = al_proto;
    pe->port = port;
    pe->al_proto_mask = AppLayerProbingParserGetMask(al_proto);
    pe->min_depth = min_depth;
    pe->max_depth = max_depth;
    pe->ProbingParser = AppLayerProbingParser;
    pe->next = NULL;

    if (max_depth != 0 && min_depth >= max_depth) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  min_depth >= max_depth");
        goto error;
    }
    if (al_proto <= ALPROTO_UNKNOWN || al_proto >= ALPROTO_MAX) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to register "
                   "the probing parser.  Invalid alproto - %d", al_proto);
        goto error;
    }
    if (AppLayerProbingParser == NULL) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  Probing parser func NULL");
        goto error;
    }

    return pe;
 error:
    DeAllocAppLayerProbingParserElement(pe);
    return NULL;
}

static AppLayerProbingParserElement *
DuplicateAppLayerProbingParserElement(AppLayerProbingParserElement *pe)
{
    AppLayerProbingParserElement *new_pe = AllocAppLayerProbingParserElement();
    if (unlikely(new_pe == NULL)) {
        return NULL;
    }

    new_pe->al_proto_name = SCStrdup(pe->al_proto_name);
    if (new_pe->al_proto_name == NULL)
        exit(EXIT_FAILURE);
    new_pe->al_proto = pe->al_proto;
    new_pe->port = pe->port;
    new_pe->al_proto_mask = pe->al_proto_mask;
    new_pe->min_depth = pe->min_depth;
    new_pe->max_depth = pe->max_depth;
    new_pe->ProbingParser = pe->ProbingParser;
    new_pe->next = NULL;

    return new_pe;
}

void AppLayerPrintProbingParsers(AppLayerProbingParser *pp)
{
    AppLayerProbingParserPort *pp_port = NULL;
    AppLayerProbingParserElement *pp_pe = NULL;

    printf("\n");

    for ( ; pp != NULL; pp = pp->next) {
        /* print ip protocol */
        if (pp->ip_proto == IPPROTO_TCP)
            printf("IPProto: TCP\n");
        else if (pp->ip_proto == IPPROTO_UDP)
            printf("IPProto: UDP\n");
        else
            printf("IPProto: %"PRIu16"\n", pp->ip_proto);

        pp_port = pp->port;
        for ( ; pp_port != NULL; pp_port = pp_port->next) {
            if (pp_port->toserver == NULL)
                goto AppLayerPrintProbingParsers_jump_toclient;
            printf("    Port: %"PRIu16 "\n", pp_port->port);

            printf("        To_Server: (max-depth: %"PRIu16 ", "
                   "mask - %"PRIu32")\n",
                   pp_port->toserver_max_depth,
                   pp_port->toserver_al_proto_mask);
            pp_pe = pp_port->toserver;
            for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {
                printf("            name: %s\n", pp_pe->al_proto_name);

                if (pp_pe->al_proto == ALPROTO_HTTP)
                    printf("            alproto: ALPROTO_HTTP\n");
                else if (pp_pe->al_proto == ALPROTO_FTP)
                    printf("            alproto: ALPROTO_FTP\n");
                else if (pp_pe->al_proto == ALPROTO_SMTP)
                    printf("            alproto: ALPROTO_SMTP\n");
                else if (pp_pe->al_proto == ALPROTO_TLS)
                    printf("            alproto: ALPROTO_TLS\n");
                else if (pp_pe->al_proto == ALPROTO_SSH)
                    printf("            alproto: ALPROTO_SSH\n");
                else if (pp_pe->al_proto == ALPROTO_IMAP)
                    printf("            alproto: ALPROTO_IMAP\n");
                else if (pp_pe->al_proto == ALPROTO_MSN)
                    printf("            alproto: ALPROTO_MSN\n");
                else if (pp_pe->al_proto == ALPROTO_JABBER)
                    printf("            alproto: ALPROTO_JABBER\n");
                else if (pp_pe->al_proto == ALPROTO_SMB)
                    printf("            alproto: ALPROTO_SMB\n");
                else if (pp_pe->al_proto == ALPROTO_SMB2)
                    printf("            alproto: ALPROTO_SMB2\n");
                else if (pp_pe->al_proto == ALPROTO_DCERPC)
                    printf("            alproto: ALPROTO_DCERPC\n");
                else if (pp_pe->al_proto == ALPROTO_DCERPC_UDP)
                    printf("            alproto: ALPROTO_DCERPC_UDP\n");
                else if (pp_pe->al_proto == ALPROTO_IRC)
                    printf("            alproto: ALPROTO_IRC\n");
                else
                    printf("impossible\n");

                printf("            port: %"PRIu16 "\n", pp_pe->port);
                printf("            mask: %"PRIu32 "\n", pp_pe->al_proto_mask);
                printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                printf("\n");
            }

        AppLayerPrintProbingParsers_jump_toclient:
            if (pp_port->toclient == NULL) {
                continue;
            }

            printf("        To_Client: (max-depth: %"PRIu16 ", "
                   "mask - %"PRIu32")\n",
                   pp_port->toclient_max_depth,
                   pp_port->toclient_al_proto_mask);
            pp_pe = pp_port->toclient;
            for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {
                printf("            name: %s\n", pp_pe->al_proto_name);

                if (pp_pe->al_proto == ALPROTO_HTTP)
                    printf("            alproto: ALPROTO_HTTP\n");
                else if (pp_pe->al_proto == ALPROTO_FTP)
                    printf("            alproto: ALPROTO_FTP\n");
                else if (pp_pe->al_proto == ALPROTO_SMTP)
                    printf("            alproto: ALPROTO_SMTP\n");
                else if (pp_pe->al_proto == ALPROTO_TLS)
                    printf("            alproto: ALPROTO_TLS\n");
                else if (pp_pe->al_proto == ALPROTO_SSH)
                    printf("            alproto: ALPROTO_SSH\n");
                else if (pp_pe->al_proto == ALPROTO_IMAP)
                    printf("            alproto: ALPROTO_IMAP\n");
                else if (pp_pe->al_proto == ALPROTO_MSN)
                    printf("            alproto: ALPROTO_MSN\n");
                else if (pp_pe->al_proto == ALPROTO_JABBER)
                    printf("            alproto: ALPROTO_JABBER\n");
                else if (pp_pe->al_proto == ALPROTO_SMB)
                    printf("            alproto: ALPROTO_SMB\n");
                else if (pp_pe->al_proto == ALPROTO_SMB2)
                    printf("            alproto: ALPROTO_SMB2\n");
                else if (pp_pe->al_proto == ALPROTO_DCERPC)
                    printf("            alproto: ALPROTO_DCERPC\n");
                else if (pp_pe->al_proto == ALPROTO_DCERPC_UDP)
                    printf("            alproto: ALPROTO_DCERPC_UDP\n");
                else if (pp_pe->al_proto == ALPROTO_IRC)
                    printf("            alproto: ALPROTO_IRC\n");
                else
                    printf("impossible\n");

                printf("            port: %"PRIu16 "\n", pp_pe->port);
                printf("            mask: %"PRIu32 "\n", pp_pe->al_proto_mask);
                printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                printf("\n");
            }
        }
    }

    return;
}

static inline void AppendAppLayerProbingParserElement(AppLayerProbingParserElement **head_pe,
                                                      AppLayerProbingParserElement *new_pe)
{
    if (*head_pe == NULL) {
        *head_pe = new_pe;
        return;
    }

    if ((*head_pe)->port == 0) {
        if (new_pe->port != 0) {
            new_pe->next = *head_pe;
            *head_pe = new_pe;
        } else {
            AppLayerProbingParserElement *temp_pe = *head_pe;
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        }
    } else {
        AppLayerProbingParserElement *temp_pe = *head_pe;
        if (new_pe->port == 0) {
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        } else {
            while (temp_pe->next != NULL && temp_pe->next->port != 0)
                temp_pe = temp_pe->next;
            new_pe->next = temp_pe->next;
            temp_pe->next = new_pe;
        }
    }

    return;
}

static inline void AppendAppLayerProbingParser(AppLayerProbingParser **head_pp,
                                               AppLayerProbingParser *new_pp)
{
    if (*head_pp == NULL) {
        *head_pp = new_pp;
        return;
    }

    AppLayerProbingParser *temp_pp = *head_pp;
    while (temp_pp->next != NULL)
        temp_pp = temp_pp->next;
    temp_pp->next = new_pp;

    return;
}

static inline void AppendAppLayerProbingParserPort(AppLayerProbingParserPort **head_port,
                                                   AppLayerProbingParserPort *new_port)
{
    if (*head_port == NULL) {
        *head_port = new_port;
        return;
    }

    if ((*head_port)->port == 0) {
        new_port->next = *head_port;
        *head_port = new_port;
    } else {
        AppLayerProbingParserPort *temp_port = *head_port;
        while (temp_port->next != NULL && temp_port->next->port != 0) {
            temp_port = temp_port->next;
        }
        new_port->next = temp_port->next;
        temp_port->next = new_port;
    }

    return;
}

static inline void AppLayerInsertNewProbingParser(AppLayerProbingParser **pp,
                                                  uint16_t ip_proto,
                                                  uint16_t port,
                                                  char *al_proto_name, uint16_t al_proto,
                                                  uint16_t min_depth, uint16_t max_depth,
                                                  uint8_t flags,
                                                  uint16_t (*ProbingParser)(uint8_t *input, uint32_t input_len, uint32_t *offset))
{
    /* get the top level ipproto pp */
    AppLayerProbingParser *curr_pp = *pp;
    while (curr_pp != NULL) {
        if (curr_pp->ip_proto == ip_proto)
            break;
        curr_pp = curr_pp->next;
    }
    if (curr_pp == NULL) {
        AppLayerProbingParser *new_pp = AllocAppLayerProbingParser();
        new_pp->ip_proto = ip_proto;
        AppendAppLayerProbingParser(pp, new_pp);
        curr_pp = new_pp;
    }

    /* get the top level port pp */
    AppLayerProbingParserPort *curr_port = curr_pp->port;
    while (curr_port != NULL) {
        if (curr_port->port == port)
            break;
        curr_port = curr_port->next;
    }
    if (curr_port == NULL) {
        AppLayerProbingParserPort *new_port = AllocAppLayerProbingParserPort();
        new_port->port = port;
        AppendAppLayerProbingParserPort(&curr_pp->port, new_port);
        curr_port = new_port;
        if (flags & STREAM_TOSERVER) {
            curr_port->toserver_max_depth = max_depth;
        } else {
            curr_port->toclient_max_depth = max_depth;
        } /* else - if (flags & STREAM_TOSERVER) */

        AppLayerProbingParserPort *zero_port;

        zero_port = curr_pp->port;
        while (zero_port != NULL && zero_port->port != 0) {
            zero_port = zero_port->next;
        }
        if (zero_port != NULL) {
            AppLayerProbingParserElement *zero_pe;

            zero_pe = zero_port->toserver;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->toserver == NULL)
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                if (curr_port->toserver_max_depth != 0 &&
                    curr_port->toserver_max_depth < zero_pe->max_depth) {
                    curr_port->toserver_max_depth = zero_pe->max_depth;
                }

                AppLayerProbingParserElement *dup_pe =
                    DuplicateAppLayerProbingParserElement(zero_pe);
                AppendAppLayerProbingParserElement(&curr_port->toserver, dup_pe);
                curr_port->toserver_al_proto_mask |= dup_pe->al_proto_mask;
            }

            zero_pe = zero_port->toclient;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->toclient == NULL)
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                if (curr_port->toclient_max_depth != 0 &&
                    curr_port->toclient_max_depth < zero_pe->max_depth) {
                    curr_port->toclient_max_depth = zero_pe->max_depth;
                }

                AppLayerProbingParserElement *dup_pe =
                    DuplicateAppLayerProbingParserElement(zero_pe);
                AppendAppLayerProbingParserElement(&curr_port->toclient, dup_pe);
                curr_port->toclient_al_proto_mask |= dup_pe->al_proto_mask;
            }
        } /* if (zero_port != NULL) */
    } /* if (curr_port == NULL) */

    /* insert the pe_pp */
    AppLayerProbingParserElement *curr_pe;
    if (flags & STREAM_TOSERVER)
        curr_pe = curr_port->toserver;
    else
        curr_pe = curr_port->toclient;
    while (curr_pe != NULL) {
        if (curr_pe->al_proto == al_proto) {
            SCLogError(SC_ERR_ALPARSER, "Duplicate pp registered");
            goto error;
        }
        curr_pe = curr_pe->next;
    }
    /* Get a new parser element */
    AppLayerProbingParserElement *new_pe =
        AppLayerCreateAppLayerProbingParserElement(al_proto_name,
                                                   al_proto,
                                                   curr_port->port,
                                                   min_depth, max_depth,
                                                   ProbingParser);
    if (new_pe == NULL)
        goto error;
    curr_pe = new_pe;
    AppLayerProbingParserElement **head_pe;
    if (flags & STREAM_TOSERVER) {
        if (curr_port->toserver == NULL)
            curr_port->toserver_max_depth = new_pe->max_depth;
        if (new_pe->max_depth == 0)
            curr_port->toserver_max_depth = new_pe->max_depth;
        if (curr_port->toserver_max_depth != 0 &&
            curr_port->toserver_max_depth < new_pe->max_depth) {
            curr_port->toserver_max_depth = new_pe->max_depth;
        }
        curr_port->toserver_al_proto_mask |= new_pe->al_proto_mask;
        head_pe = &curr_port->toserver;
    } else {
        if (curr_port->toclient == NULL)
            curr_port->toclient_max_depth = new_pe->max_depth;
        if (new_pe->max_depth == 0)
            curr_port->toclient_max_depth = new_pe->max_depth;
        if (curr_port->toclient_max_depth != 0 &&
            curr_port->toclient_max_depth < new_pe->max_depth) {
            curr_port->toclient_max_depth = new_pe->max_depth;
        }
        curr_port->toclient_al_proto_mask |= new_pe->al_proto_mask;
        head_pe = &curr_port->toclient;
    }
    AppendAppLayerProbingParserElement(head_pe, new_pe);

    if (curr_port->port == 0) {
        AppLayerProbingParserPort *temp_port = curr_pp->port;
        while (temp_port != NULL && temp_port->port != 0) {
            if (flags & STREAM_TOSERVER) {
                if (temp_port->toserver == NULL)
                    temp_port->toserver_max_depth = curr_pe->max_depth;
                if (curr_pe->max_depth == 0)
                    temp_port->toserver_max_depth = curr_pe->max_depth;
                if (temp_port->toserver_max_depth != 0 &&
                    temp_port->toserver_max_depth < curr_pe->max_depth) {
                    temp_port->toserver_max_depth = curr_pe->max_depth;
                }
                AppendAppLayerProbingParserElement(&temp_port->toserver,
                                                   DuplicateAppLayerProbingParserElement(curr_pe));
                temp_port->toserver_al_proto_mask |= curr_pe->al_proto_mask;
            } else {
                if (temp_port->toclient == NULL)
                    temp_port->toclient_max_depth = curr_pe->max_depth;
                if (curr_pe->max_depth == 0)
                    temp_port->toclient_max_depth = curr_pe->max_depth;
                if (temp_port->toclient_max_depth != 0 &&
                    temp_port->toclient_max_depth < curr_pe->max_depth) {
                    temp_port->toclient_max_depth = curr_pe->max_depth;
                }
                AppendAppLayerProbingParserElement(&temp_port->toclient,
                                                   DuplicateAppLayerProbingParserElement(curr_pe));
                temp_port->toclient_al_proto_mask |= curr_pe->al_proto_mask;
            }
            temp_port = temp_port->next;
        } /* while */
    } /* if */

 error:
    return;
}

void AppLayerRegisterProbingParser(AlpProtoDetectCtx *ctx,
                                   uint16_t ip_proto,
                                   char *portstr,
                                   char *al_proto_name, uint16_t al_proto,
                                   uint16_t min_depth, uint16_t max_depth,
                                   uint8_t flags,
                                   uint16_t (*ProbingParser)(uint8_t *input, uint32_t input_len, uint32_t *offset))
{
    DetectPort *head = NULL;
    DetectPortParse(&head, portstr);
    DetectPort *temp_dp = head;
    while (temp_dp != NULL) {
        uint32_t port = temp_dp->port;
        if (port == 0 && temp_dp->port2 != 0)
            port++;
        for ( ; port <= temp_dp->port2; port++) {
            AppLayerInsertNewProbingParser(&ctx->probing_parsers,
                                           ip_proto,
                                           port,
                                           al_proto_name, al_proto,
                                           min_depth, max_depth,
                                           flags,
                                           ProbingParser);
        }
        temp_dp = temp_dp->next;
    }
    DetectPortCleanupList(head);

    return;
}

void AppLayerFreeProbingParsers(AppLayerProbingParser *pp)
{
    if (pp == NULL)
        return;

    DeAllocAppLayerProbingParser(pp);

    return;
}

/**************************************Unittests*******************************/

#ifdef UNITTESTS

typedef struct TestState_ {
    uint8_t test;
}TestState;

/**
 *  \brief  Test parser function to test the memory deallocation of app layer
 *          parser of occurence of an error.
 */
static int TestProtocolParser(Flow *f, void *test_state, AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len,
                              void *local_data, AppLayerParserResult *output)
{
    return -1;
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void)
{
    void *s = SCMalloc(sizeof(TestState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(TestState));
    return s;
}

/** \brief Function to free the Test Protocol state memory
 */
static void TestProtocolStateFree(void *s)
{
    SCFree(s);
}

/** \test   Test the deallocation of app layer parser memory on occurance of
 *          error in the parsing process.
 */
static int AppLayerParserTest01 (void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;

    memset(&ssn, 0, sizeof(ssn));

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;

    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: ", r);
        goto end;
    }

    if (!(f->flags & FLOW_NO_APPLAYER_INSPECTION))
    {
        printf("flag should have been set, but is not: ");
        goto end;
    }

    result = 1;
end:
    StreamTcpFreeConfig(TRUE);

    UTHFreeFlow(f);
    return result;
}

/** \test   Test the deallocation of app layer parser memory on occurance of
 *          error in the parsing process for UDP.
 */
static int AppLayerParserTest02 (void)
{
    int result = 1;
    Flow *f = NULL;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "4.3.2.1", 20, 40);
    if (f == NULL)
        goto end;
    f->alproto = ALPROTO_TEST;
    f->proto = IPPROTO_UDP;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: \n", r);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    UTHFreeFlow(f);
    return result;
}

typedef struct AppLayerPPTestDataElement_ {
    char *al_proto_name;
    uint16_t al_proto;
    uint16_t port;
    uint32_t al_proto_mask;
    uint32_t min_depth;
    uint32_t max_depth;
} AppLayerPPTestDataElement;

typedef struct AppLayerPPTestDataPort_ {
    uint16_t port;
    uint32_t toserver_al_proto_mask;
    uint32_t toclient_al_proto_mask;
    uint16_t toserver_max_depth;
    uint16_t toclient_max_depth;

    AppLayerPPTestDataElement *toserver_element;
    AppLayerPPTestDataElement *toclient_element;
    int ts_no_of_element;
    int tc_no_of_element;
} AppLayerPPTestDataPort;


typedef struct AppLayerPPTestDataIPProto_ {
    uint16_t ip_proto;

    AppLayerPPTestDataPort *port;
    int no_of_port;
} AppLayerPPTestDataIPProto;

int AppLayerPPTestData(AppLayerProbingParser *pp,
                       AppLayerPPTestDataIPProto *ip_proto, int no_of_ip_proto)
{
    int result = 0;
    int i, j, k;
    int dir = 0;

    for (i = 0; i < no_of_ip_proto; i++, pp = pp->next) {
        if (pp->ip_proto != ip_proto[i].ip_proto)
            goto end;

        AppLayerProbingParserPort *pp_port = pp->port;
        for (k = 0; k < ip_proto[i].no_of_port; k++, pp_port = pp_port->next) {
            if (pp_port->port != ip_proto[i].port[k].port)
                goto end;
            if (pp_port->toserver_al_proto_mask != ip_proto[i].port[k].toserver_al_proto_mask)
                goto end;
            if (pp_port->toclient_al_proto_mask != ip_proto[i].port[k].toclient_al_proto_mask)
                goto end;
            if (pp_port->toserver_max_depth != ip_proto[i].port[k].toserver_max_depth)
                goto end;
            if (pp_port->toclient_max_depth != ip_proto[i].port[k].toclient_max_depth)
                goto end;

            AppLayerProbingParserElement *pp_element = pp_port->toserver;
            dir = 0;
            for (j = 0 ; j < ip_proto[i].port[k].ts_no_of_element;
                 j++, pp_element = pp_element->next) {

                if ((strlen(pp_element->al_proto_name) !=
                     strlen(ip_proto[i].port[k].toserver_element[j].al_proto_name)) ||
                    strcasecmp(pp_element->al_proto_name,
                               ip_proto[i].port[k].toserver_element[j].al_proto_name) != 0) {
                    goto end;
                }
                if (pp_element->al_proto != ip_proto[i].port[k].toserver_element[j].al_proto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toserver_element[j].port) {
                    goto end;
                }
                if (pp_element->al_proto_mask != ip_proto[i].port[k].toserver_element[j].al_proto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toserver_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toserver_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;

            pp_element = pp_port->toclient;
            dir = 1;
            for (j = 0 ; j < ip_proto[i].port[k].tc_no_of_element; j++, pp_element = pp_element->next) {
                if ((strlen(pp_element->al_proto_name) !=
                     strlen(ip_proto[i].port[k].toclient_element[j].al_proto_name)) ||
                    strcasecmp(pp_element->al_proto_name,
                               ip_proto[i].port[k].toclient_element[j].al_proto_name) != 0) {
                    goto end;
                }
                if (pp_element->al_proto != ip_proto[i].port[k].toclient_element[j].al_proto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toclient_element[j].port) {
                    goto end;
                }
                if (pp_element->al_proto_mask != ip_proto[i].port[k].toclient_element[j].al_proto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toclient_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toclient_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;
        }
        if (pp_port != NULL)
            goto end;
    }
    if (pp != NULL)
        goto end;

    result = 1;
 end:
#if DEBUG
    printf("i = %d, k = %d, j = %d(%s)\n", i, k, j, (dir == 0) ? "ts" : "tc");
#endif
    return result;
}

uint16_t ProbingParserDummyForTesting(uint8_t *input, uint32_t input_len, uint32_t *offset)
{
    return 0;
}

static int AppLayerProbingParserTest01(void)
{
    int result = 0;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "smtp",
                                  ALPROTO_SMTP,
                                  12, 0,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "tls",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);


    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "irc",
                                  ALPROTO_IRC,
                                  12, 25,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "jabber",
                                  ALPROTO_JABBER,
                                  12, 23,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_UDP,
                                  "85",
                                  "imap",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting);

    /* toclient */
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "jabber",
                                  ALPROTO_JABBER,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "irc",
                                  ALPROTO_IRC,
                                  12, 14,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);


    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "85",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "tls",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "81",
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "90",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_UDP,
                                  "85",
                                  "imap",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "0",
                                  "smtp",
                                  ALPROTO_SMTP,
                                  12, 17,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);
    AppLayerRegisterProbingParser(&ctx,
                                  IPPROTO_TCP,
                                  "80",
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting);

    //AppLayerPrintProbingParsers(ctx.probing_parsers);

    AppLayerPPTestDataElement element_ts_80[] =
        { { "http", ALPROTO_HTTP, 80, 1 << ALPROTO_HTTP, 5, 8 },
          { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
          { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_80[] =
        { { "http", ALPROTO_HTTP, 80, 1 << ALPROTO_HTTP, 5, 8 },
          { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
          { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_81[] =
        { { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_81[] =
        { { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_85[] =
        { { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 85, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_85[] =
        { { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_90[] =
        { { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_90[] =
        { { "ftp", ALPROTO_FTP, 90, 1 << ALPROTO_FTP, 7, 15 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerPPTestDataElement element_ts_0[] =
        { { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_0[] =
        { { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };


    AppLayerPPTestDataElement element_ts_85_udp[] =
        { { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };
    AppLayerPPTestDataElement element_tc_85_udp[] =
        { { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };

    AppLayerPPTestDataPort ports_tcp[] =
        { { 80,
            ((1 << ALPROTO_HTTP) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_HTTP) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_80, element_tc_80,
            sizeof(element_ts_80) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_80) / sizeof(AppLayerPPTestDataElement),
            },
          { 81,
            ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_FTP) | (1 << ALPROTO_DCERPC) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_81, element_tc_81,
            sizeof(element_ts_81) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_81) / sizeof(AppLayerPPTestDataElement),
          },
          { 85,
            ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) |
             (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_DCERPC) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_85, element_tc_85,
            sizeof(element_ts_85) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_85) / sizeof(AppLayerPPTestDataElement)
          },
          { 90,
            ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_FTP) |
             (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_90, element_tc_90,
            sizeof(element_ts_90) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_90) / sizeof(AppLayerPPTestDataElement)
          },
          { 0,
            ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
            ((1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
            0, 23,
            element_ts_0, element_tc_0,
            sizeof(element_ts_0) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_0) / sizeof(AppLayerPPTestDataElement)
          }
        };

    AppLayerPPTestDataPort ports_udp[] =
        { { 85,
            (1 << ALPROTO_IMAP),
            (1 << ALPROTO_IMAP),
            23, 23,
            element_ts_85_udp, element_tc_85_udp,
            sizeof(element_ts_85_udp) / sizeof(AppLayerPPTestDataElement),
            sizeof(element_tc_85_udp) / sizeof(AppLayerPPTestDataElement),
            },
        };

    AppLayerPPTestDataIPProto ip_proto[] =
        { { IPPROTO_TCP,
            ports_tcp,
            sizeof(ports_tcp) / sizeof(AppLayerPPTestDataPort),
            },
          { IPPROTO_UDP,
            ports_udp,
            sizeof(ports_udp) / sizeof(AppLayerPPTestDataPort),
          },
        };


    if (AppLayerPPTestData(ctx.probing_parsers, ip_proto,
                           sizeof(ip_proto) / sizeof(AppLayerPPTestDataIPProto)) == 0) {
        goto end;
    }

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

#endif /* UNITESTS */

void AppLayerParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01, 1);
    UtRegisterTest("AppLayerParserTest02", AppLayerParserTest02, 1);

    UtRegisterTest("AppLayerProbingParserTest01", AppLayerProbingParserTest01, 1);
#endif /* UNITTESTS */

    return;
}
