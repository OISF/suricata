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

    return ALPROTO_UNKNOWN;
}

const char *AppLayerGetProtoString(int proto)
{

    if ((proto >= ALPROTO_MAX) || (proto < 0)) {
        return "Undefined";
    }

    if (al_proto_table[proto].name == NULL)  {
        return "Unset";
    } else {
        return al_proto_table[proto].name;
    }
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

    if (parser_idx == 0 || (parser_state->flags & APP_LAYER_PARSER_DONE)) {
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

    AppLayerProbingParserInfo *pinfo = alp_proto_ctx.probing_parsers_info;
    while (pinfo != NULL) {
        if (temp_alprotos_buf[pinfo->al_proto] == 1) {
            pinfo = pinfo->next;
            continue;
        }

        printf("%s\n", pinfo->al_proto_name);
        temp_alprotos_buf[pinfo->al_proto] = 1;
        pinfo = pinfo->next;
    }

    printf("=====\n");


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

static AppLayerProbingParserElement *
AppLayerCreateAppLayerProbingParserElement(const char *al_proto_name,
                                           uint16_t ip_proto,
                                           uint16_t al_proto,
                                           uint16_t min_depth,
                                           uint16_t max_depth,
                                           uint16_t port,
                                           uint8_t priority,
                                           uint8_t top,
                                           uint16_t (*AppLayerProbingParser)
                                           (uint8_t *input, uint32_t input_len))
{
    AppLayerProbingParserElement *pe = SCMalloc(sizeof(AppLayerProbingParserElement));
    if (unlikely(pe == NULL)) {
        return NULL;
    }

    pe->al_proto_name = al_proto_name;
    pe->ip_proto = ip_proto;
    pe->al_proto = al_proto;
    pe->al_proto_mask = AppLayerProbingParserGetMask(al_proto);
    pe->min_depth = min_depth;
    pe->max_depth = max_depth;
    pe->port = port;
    pe->priority = priority;
    pe->top = top;
    pe->ProbingParser = AppLayerProbingParser;
    pe->next = NULL;

    if (max_depth != 0 && min_depth > max_depth) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  min_depth > max_depth");
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
    SCFree(pe);
    return NULL;
}

static AppLayerProbingParserElement *
AppLayerDuplicateAppLayerProbingParserElement(AppLayerProbingParserElement *pe)
{
    AppLayerProbingParserElement *new_pe = SCMalloc(sizeof(AppLayerProbingParserElement));
    if (unlikely(new_pe == NULL)) {
        return NULL;
    }

    new_pe->al_proto_name = pe->al_proto_name;
    new_pe->ip_proto = pe->ip_proto;
    new_pe->al_proto = pe->al_proto;
    new_pe->al_proto_mask = pe->al_proto_mask;
    new_pe->min_depth = pe->min_depth;
    new_pe->max_depth = pe->max_depth;
    new_pe->port = pe->port;
    new_pe->priority = pe->priority;
    new_pe->top = pe->top;
    new_pe->ProbingParser = pe->ProbingParser;
    new_pe->next = NULL;

    return new_pe;
}

static void
AppLayerFreeAppLayerProbingParserElement(AppLayerProbingParserElement *pe)
{
    SCFree(pe);

    return;
}

static void
AppLayerInsertNewProbingParserSingleElement(AppLayerProbingParser *pp,
                                            AppLayerProbingParser **probing_parsers,
                                            AppLayerProbingParserElement *new_pe,
                                            uint8_t flags)
{
    if (pp == NULL) {
        AppLayerProbingParser *new_pp = SCMalloc(sizeof(AppLayerProbingParser));
        if (unlikely(new_pp == NULL))
            return;
        memset(new_pp, 0, sizeof(AppLayerProbingParser));

        new_pp->port = new_pe->port;

        if (probing_parsers[0] == NULL) {
            probing_parsers[0] = new_pp;
        } else {
            AppLayerProbingParser *pp = probing_parsers[0];
            if (pp->port == 0) {
                new_pp->next = probing_parsers[0];
                probing_parsers[0] = new_pp;
            } else {
                /* port 0 based pp is always the last one.  Hence the
                 * premature exit condition if port is 0 */
                while (pp->next != NULL && pp->next->port != 0) {
                    pp = pp->next;
                }
                new_pp->next = pp->next;
                pp->next = new_pp;
            }
        }

        pp = new_pp;
    }

    AppLayerProbingParserElement *pe = NULL;
    if (flags & STREAM_TOSERVER) {
        pe = pp->toserver;
    } else {
        pe = pp->toclient;
    }

    if (pe == NULL) {
        if (flags & STREAM_TOSERVER) {
            pp->toserver = new_pe;
            pp->toserver_max_depth = new_pe->max_depth;
        } else {
            pp->toclient = new_pe;
            pp->toclient_max_depth = new_pe->max_depth;
        }
    } else {
        uint8_t break_priority;
        if (new_pe->top) {
            break_priority = new_pe->priority;
        } else {
            break_priority = new_pe->priority + 1;
        }

        AppLayerProbingParserElement *prev_pe = pe;
        while (pe != NULL) {
            if (pe->priority < break_priority) {
                prev_pe = pe;
                pe = pe->next;
                continue;
            }
            break;
        }
        if (prev_pe == pe) {
            if (flags & STREAM_TOSERVER) {
                new_pe->next = pp->toserver;
                pp->toserver = new_pe;
            } else {
                new_pe->next = pp->toclient;
                pp->toclient = new_pe;
            }
        } else {
            new_pe->next = prev_pe->next;
            prev_pe->next = new_pe;
        }

        if (flags & STREAM_TOSERVER) {
            if (new_pe->max_depth == 0) {
                pp->toserver_max_depth = 0;
            } else {
                if (pp->toserver_max_depth != 0 &&
                    pp->toserver_max_depth < new_pe->max_depth) {
                    pp->toserver_max_depth = new_pe->max_depth;
                }
            }
        } else {
            if (new_pe->max_depth == 0) {
                pp->toclient_max_depth = 0;
            } else {
                if (pp->toclient_max_depth != 0 &&
                    pp->toclient_max_depth < new_pe->max_depth) {
                    pp->toclient_max_depth = new_pe->max_depth;
                }
            }
        } /* else - if (flags & STREAM_TOSERVER) */

    } /* else - if (pe == NULL) */

    if (flags & STREAM_TOSERVER)
        pp->toserver_al_proto_mask |= new_pe->al_proto_mask;
    else
        pp->toclient_al_proto_mask |= new_pe->al_proto_mask;

    return;
}

static void AppLayerInsertNewProbingParserElement(AppLayerProbingParser **probing_parsers,
                                                  AppLayerProbingParserElement *new_pe,
                                                  uint8_t flags)
{
    AppLayerProbingParser *pp = probing_parsers[0];

    if (new_pe->port != 0) {
        AppLayerProbingParser *zero_pp = NULL;
        while (pp != NULL) {
            if (pp->port == new_pe->port) {
                break;
            }
            if (pp->port == 0)
                zero_pp = pp;
            pp = pp->next;
        }
        AppLayerInsertNewProbingParserSingleElement(pp, probing_parsers, new_pe,
                                                    flags);
        if (zero_pp != NULL) {
            pp = probing_parsers[0];
            while (pp != NULL) {
                if (pp->port == new_pe->port)
                    break;
                pp = pp->next;
            }
            BUG_ON(pp == NULL);
            AppLayerProbingParserElement *temp_pe;
            if (flags & STREAM_TOSERVER) {
                temp_pe = zero_pp->toserver;
            } else {
                temp_pe = zero_pp->toclient;
            }
            while (temp_pe != NULL) {
                AppLayerProbingParserElement *dup_pe =
                    AppLayerDuplicateAppLayerProbingParserElement(temp_pe);
                AppLayerInsertNewProbingParserSingleElement(pp, probing_parsers, dup_pe,
                                                            flags);
                temp_pe = temp_pe->next;
            }
        }

    } else {
        int zero_port_present = 0;
        while (pp != NULL) {
            AppLayerProbingParserElement *dup_pe =
                AppLayerDuplicateAppLayerProbingParserElement(new_pe);

            AppLayerInsertNewProbingParserSingleElement(pp, probing_parsers, dup_pe,
                                                        flags);
            if (pp->port == 0)
                zero_port_present = 1;
            pp = pp->next;
        }

        if (zero_port_present == 0) {
            AppLayerInsertNewProbingParserSingleElement(NULL, probing_parsers, new_pe,
                                                        flags);
        } else {
            SCFree(new_pe);
        }
    }

    return;
}

void AppLayerPrintProbingParsers(AppLayerProbingParser *pp)
{
    AppLayerProbingParserElement *pe = NULL;

    printf("\n");
    while (pp != NULL) {
        printf("Port: %"PRIu16 "\n", pp->port);
        printf("    to_server: max-depth: %"PRIu16 ", "
               "mask - %"PRIu32"\n", pp->toserver_max_depth,
               pp->toserver_al_proto_mask);
        pe = pp->toserver;
        while (pe != NULL) {
            printf("        name: %s\n", pe->al_proto_name);

            if (pe->al_proto == ALPROTO_HTTP)
                printf("        alproto: ALPROTO_HTTP\n");
            else if (pe->al_proto == ALPROTO_FTP)
                printf("        alproto: ALPROTO_FTP\n");
            else if (pe->al_proto == ALPROTO_SMTP)
                printf("        alproto: ALPROTO_SMTP\n");
            else if (pe->al_proto == ALPROTO_TLS)
                printf("        alproto: ALPROTO_TLS\n");
            else if (pe->al_proto == ALPROTO_SSH)
                printf("        alproto: ALPROTO_SSH\n");
            else if (pe->al_proto == ALPROTO_IMAP)
                printf("        alproto: ALPROTO_IMAP\n");
            else if (pe->al_proto == ALPROTO_MSN)
                printf("        alproto: ALPROTO_MSN\n");
            else if (pe->al_proto == ALPROTO_JABBER)
                printf("        alproto: ALPROTO_JABBER\n");
            else if (pe->al_proto == ALPROTO_SMB)
                printf("        alproto: ALPROTO_SMB\n");
            else if (pe->al_proto == ALPROTO_SMB2)
                printf("        alproto: ALPROTO_SMB2\n");
            else if (pe->al_proto == ALPROTO_DCERPC)
                printf("        alproto: ALPROTO_DCERPC\n");
            else if (pe->al_proto == ALPROTO_DCERPC_UDP)
                printf("        alproto: ALPROTO_DCERPC_UDP\n");
            else if (pe->al_proto == ALPROTO_IRC)
                printf("        alproto: ALPROTO_IRC\n");
            else
                printf("impossible\n");

            printf("        port: %"PRIu16 "\n", pe->port);

            if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
                printf("        priority: HIGH\n");
            else if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_MEDIUM)
                printf("        priority: MEDIUM\n");
            else if (pe->priority == APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
                printf("        priority: LOW\n");
            else
                printf("        priority: impossible\n");

            printf("        top: %"PRIu8 "\n", pe->top);

            printf("        min_depth: %"PRIu32 "\n", pe->min_depth);
            printf("        max_depth: %"PRIu32 "\n", pe->max_depth);
            printf("        mask: %"PRIu32 "\n", pe->al_proto_mask);

            printf("\n");
            pe = pe->next;
        }
        pp = pp->next;
    }

    return;
}

int AppLayerProbingParserInfoAdd(AlpProtoDetectCtx *ctx,
                                 const char *al_proto_name,
                                 uint16_t ip_proto,
                                 uint16_t al_proto,
                                 uint16_t (*ProbingParser)
                                 (uint8_t *input, uint32_t input_len))
{
    AppLayerProbingParserInfo *new_ppi = NULL;

    AppLayerProbingParserInfo *ppi = ctx->probing_parsers_info;
    while (ppi != NULL) {
        if (strcmp(ppi->al_proto_name, al_proto_name) == 0)
            break;
        ppi = ppi->next;
    }

    if (ppi == NULL) {
        new_ppi = SCMalloc(sizeof(AppLayerProbingParserInfo));
        if (unlikely(new_ppi == NULL)) {
            return -1;
        }
        memset(new_ppi, 0, sizeof(AppLayerProbingParserInfo));
        new_ppi->al_proto_name = al_proto_name;
        new_ppi->ip_proto = ip_proto;
        new_ppi->al_proto = al_proto;
        new_ppi->ProbingParser = ProbingParser;

        if (ctx->probing_parsers_info == NULL) {
            ctx->probing_parsers_info = new_ppi;
        } else {
            new_ppi->next = ctx->probing_parsers_info;
            ctx->probing_parsers_info = new_ppi;
        }
        return 0;
    }

    if (ppi->ip_proto != ip_proto) {
        SCLogError(SC_ERR_ALPARSER, "New probing parser \"%s\" being registered "
                   "already exists in the database of registered parsers, "
                   "except that the new one registers with a different ip_proto"
                   " %"PRIu16" compared to the existing entry of %"PRIu16,
                   ppi->al_proto_name, ppi->ip_proto, ip_proto);
        return -1;
    }
    if (ppi->al_proto != al_proto) {
        SCLogError(SC_ERR_ALPARSER, "New probing parser \"%s\" being registered "
                   "already exists in the database of registered parsers, "
                   "except that the new one registers with a different alproto "
                   "%"PRIu16" compared to the existing entry of %"PRIu16,
                   ppi->al_proto_name, ppi->al_proto, al_proto);
        return -1;
    }
    if (ppi->ProbingParser != ProbingParser) {
        SCLogError(SC_ERR_ALPARSER, "New probing parser \"%s\" being registered "
                   "already exists in the database of registered parsers, "
                   "except that the new one registers with a differnt "
                   "ProbingParser function compared to the existing entry "
                   "in the database", ppi->al_proto_name);
        return -1;
    }

    return 0;
}

void AppLayerRegisterProbingParser(AlpProtoDetectCtx *ctx,
                                   uint16_t port,
                                   uint16_t ip_proto,
                                   const char *al_proto_name,
                                   uint16_t al_proto,
                                   uint16_t min_depth,
                                   uint16_t max_depth,
                                   uint8_t flags,
                                   uint8_t priority,
                                   uint8_t top,
                                   uint16_t (*ProbingParser)
                                   (uint8_t *input, uint32_t input_len))
{
    AppLayerProbingParser **probing_parsers = &ctx->probing_parsers;
    AppLayerProbingParserElement *pe = NULL;
    AppLayerProbingParserElement *new_pe = NULL;
    AppLayerProbingParser *pp = NULL;

    /* Add info about this probing parser to our database.  Also detects any
     * duplicate existance of this parser but with conflicting parameters */
    if (AppLayerProbingParserInfoAdd(ctx, al_proto_name, ip_proto, al_proto,
                                     ProbingParser) < 0) {
        goto error;
    }

    /* \todo introduce parsing port range here */

    /* Get a new parser element */
    new_pe = AppLayerCreateAppLayerProbingParserElement(al_proto_name, ip_proto,
                                                   al_proto, min_depth,
                                                   max_depth, port,
                                                   priority, top,
                                                   ProbingParser);
    if (new_pe == NULL)
        goto error;

    pp = AppLayerGetProbingParsers(probing_parsers[0], ip_proto, port);
    if (pp != NULL) {
        if (flags & STREAM_TOSERVER) {
            pe = pp->toserver;
        } else {
            pe = pp->toclient;
        }
    }

    /* check if this parser has already been registered for this port + dir */
    if (pe != NULL) {
        AppLayerProbingParserElement *tmp_pe = pe;
        while (tmp_pe != NULL) {
            if (pe->al_proto == al_proto ||
                strcmp(pe->al_proto_name, al_proto_name) == 0) {
                /* looks like we have it registered for this port + dir */
                SCLogWarning(SC_ERR_ALPARSER, "App layer probing parser already "
                             "registered for this port, direction");
                goto error;
            }
            tmp_pe = tmp_pe->next;
        }
    }

    AppLayerInsertNewProbingParserElement(probing_parsers, new_pe, flags);

    return;
 error:
    if (new_pe != NULL)
        SCFree(new_pe);
    return;
}

void AppLayerFreeProbingParsersInfo(AppLayerProbingParserInfo *probing_parsers_info)
{
    AppLayerProbingParserInfo *ppi = probing_parsers_info;
    AppLayerProbingParserInfo *next_ppi = NULL;

    while (ppi != NULL) {
        next_ppi = ppi->next;
        SCFree(ppi);
        ppi = next_ppi;
    }

    return;
}

void AppLayerFreeProbingParsers(AppLayerProbingParser *probing_parsers)
{
    while (probing_parsers != NULL) {
        AppLayerProbingParserElement *pe;
        AppLayerProbingParserElement *next_pe;

        pe = probing_parsers->toserver;
        while (pe != NULL) {
            next_pe = pe->next;
            AppLayerFreeAppLayerProbingParserElement(pe);
            pe = next_pe;
        }

        pe = probing_parsers->toclient;
        while (pe != NULL) {
            next_pe = pe->next;
            AppLayerFreeAppLayerProbingParserElement(pe);
            pe = next_pe;
        }

        probing_parsers = probing_parsers->next;
    }

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

uint16_t ProbingParserDummyForTesting(uint8_t *input, uint32_t input_len)
{
    return 0;
}
static int AppLayerProbingParserTest01(void)
{
    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    if (ctx.probing_parsers == NULL)
        return 0;

    AlpProtoTestDestroy(&ctx);
    return 1;
}

static int AppLayerProbingParserTest02(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != 1 << ALPROTO_HTTP)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_SMB)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_SMB |
                                       1 << ALPROTO_DCERPC)) {
        goto end;
    }

    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_DCERPC) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest03(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_SMB)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_DCERPC |
                                       1 << ALPROTO_SMB)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_DCERPC) {
        goto end;
    }

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest04(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_SMB)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    if (pp->toserver_al_proto_mask != (1 << ALPROTO_HTTP |
                                       1 << ALPROTO_DCERPC |
                                       1 << ALPROTO_SMB)) {
        goto end;
    }
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_SMB) {
        goto end;
    }
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_HTTP) {
        goto end;
    }
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    if (pe->al_proto_mask != 1 << ALPROTO_DCERPC) {
        goto end;
    }

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest05(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest06(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest07(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest08(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest09(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest10(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 10)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* third one */
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest11(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest12(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest13(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_LOW, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 5,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 10)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    /* first pp */
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 5)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp */
    if (pp->next->next != NULL)
        goto end;
    if (pp->next->toclient != NULL)
        goto end;
    if (pp->next->port != 81)
        goto end;
    if (pp->next->toserver_max_depth != 15)
        goto end;
    if (pp->next->toclient_max_depth != 0)
        goto end;
    if (pp->next->toserver == NULL)
        goto end;
    if (pp->next->toserver->next == NULL)
        goto end;
    if (pp->next->toserver->next->next != NULL)
        goto end;
    /* second pp - first one */
    pe = pp->next->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second pp - second one */
    pe = pp->next->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_LOW)
        goto end;
    if (pe->min_depth != 9)
        goto end;
    if (pe->max_depth != 10)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerPrintProbingParsers(ctx.probing_parsers);

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest14(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 15)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  0,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  5, 25,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 0)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 50,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next == NULL)
        goto end;
    if (pp->next->next->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    /* second probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next != NULL)
        goto end;
    if (pp->port != 81)
        goto end;
    if (pp->toserver_max_depth != 50)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 50)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    /* third probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 0)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerPrintProbingParsers(ctx.probing_parsers);

    result = 1;

 end:
    AlpProtoTestDestroy(&ctx);
    return result;
}

static int AppLayerProbingParserTest15(void)
{
    int result = 0;
    AppLayerProbingParser *pp;
    AppLayerProbingParserElement *pe;

    AlpProtoDetectCtx ctx;
    AlpProtoInit(&ctx);

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "http",
                                  ALPROTO_HTTP,
                                  5, 8,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 8)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  80,
                                  IPPROTO_TCP,
                                  "smb",
                                  ALPROTO_SMB,
                                  5, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 15)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  0,
                                  IPPROTO_TCP,
                                  "dcerpc",
                                  ALPROTO_DCERPC,
                                  5, 25,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 0,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 0)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerRegisterProbingParser(&ctx,
                                  81,
                                  IPPROTO_TCP,
                                  "ftp",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  APP_LAYER_PROBING_PARSER_PRIORITY_HIGH, 1,
                                  ProbingParserDummyForTesting);
    pp = ctx.probing_parsers;
    if (ctx.probing_parsers == NULL) {
        goto end;
    }
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next == NULL)
        goto end;
    if (pp->next->next->next != NULL)
        goto end;
    if (pp->port != 80)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next == NULL)
        goto end;
    if (pp->toserver->next->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "http") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_HTTP)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 8)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "smb") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_SMB)
        goto end;
    if (pe->port != 80)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    pe = pp->toserver->next->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    /* second probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next == NULL)
        goto end;
    if (pp->next->next != NULL)
        goto end;
    if (pp->port != 81)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next == NULL)
        goto end;
    if (pp->toserver->next->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "ftp") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_FTP)
        goto end;
    if (pe->port != 81)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 7)
        goto end;
    if (pe->max_depth != 15)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;
    /* second one */
    pe = pp->toserver->next;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    /* third probing parser */
    pp = pp->next;
    if (pp->toclient != NULL)
        goto end;
    if (pp->next != NULL)
        goto end;
    if (pp->port != 0)
        goto end;
    if (pp->toserver_max_depth != 25)
        goto end;
    if (pp->toclient_max_depth != 0)
        goto end;
    if (pp->toserver == NULL)
        goto end;
    if (pp->toserver->next != NULL)
        goto end;
    /* first one */
    pe = pp->toserver;
    if (strcmp(pe->al_proto_name, "dcerpc") != 0)
        goto end;
    if (pe->al_proto != ALPROTO_DCERPC)
        goto end;
    if (pe->port != 0)
        goto end;
    if (pe->priority != APP_LAYER_PROBING_PARSER_PRIORITY_HIGH)
        goto end;
    if (pe->min_depth != 5)
        goto end;
    if (pe->max_depth != 25)
        goto end;
    if (pe->ProbingParser != ProbingParserDummyForTesting)
        goto end;

    AppLayerPrintProbingParsers(ctx.probing_parsers);

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
    UtRegisterTest("AppLayerProbingParserTest02", AppLayerProbingParserTest02, 1);
    UtRegisterTest("AppLayerProbingParserTest03", AppLayerProbingParserTest03, 1);
    UtRegisterTest("AppLayerProbingParserTest04", AppLayerProbingParserTest04, 1);
    UtRegisterTest("AppLayerProbingParserTest05", AppLayerProbingParserTest05, 1);
    UtRegisterTest("AppLayerProbingParserTest06", AppLayerProbingParserTest06, 1);
    UtRegisterTest("AppLayerProbingParserTest07", AppLayerProbingParserTest07, 1);
    UtRegisterTest("AppLayerProbingParserTest08", AppLayerProbingParserTest08, 1);
    UtRegisterTest("AppLayerProbingParserTest09", AppLayerProbingParserTest09, 1);
    UtRegisterTest("AppLayerProbingParserTest10", AppLayerProbingParserTest10, 1);
    UtRegisterTest("AppLayerProbingParserTest11", AppLayerProbingParserTest11, 1);
    UtRegisterTest("AppLayerProbingParserTest12", AppLayerProbingParserTest12, 1);
    UtRegisterTest("AppLayerProbingParserTest13", AppLayerProbingParserTest13, 1);
    UtRegisterTest("AppLayerProbingParserTest14", AppLayerProbingParserTest14, 1);
    UtRegisterTest("AppLayerProbingParserTest15", AppLayerProbingParserTest15, 1);
#endif /* UNITTESTS */

    return;
}
