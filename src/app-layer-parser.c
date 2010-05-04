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

#include "stream-tcp.h"
#include "stream-tcp-private.h"
#include "stream.h"
#include "stream-tcp-reassemble.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-spm.h"

#include "util-debug.h"

static uint16_t app_layer_sid = 0;
static AppLayerProto al_proto_table[ALPROTO_MAX];   /**< Application layer protocol
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


/** \brief Alloc a AppLayerParserResultElmt func for the pool */
static void *AlpResultElmtPoolAlloc(void *null)
{
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)SCMalloc
                                    (sizeof(AppLayerParserResultElmt));
    if (e == NULL) {
        return NULL;
    }

    memset(e, 0, sizeof(AppLayerParserResultElmt));

#ifdef DEBUG
    al_result_pool_elmts++;
    SCLogDebug("al_result_pool_elmts %"PRIu32"", al_result_pool_elmts);
#endif /* DEBUG */
    return e;
}

static void AlpResultElmtPoolFree(void *e)
{
    AppLayerParserResultElmt *re = (AppLayerParserResultElmt *)e;

    if (re->flags & ALP_RESULT_ELMT_ALLOC) {
        if (re->data_ptr != NULL)
            SCFree(re->data_ptr);
    }
    SCFree(re);

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed!");
                SCReturnInt(-1);
            }

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        } else {
            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed!");
                SCReturnInt(-1);
            }

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            SCLogDebug("store_len %" PRIu32 " and EOF", pstate->store_len);

            pstate->store = SCRealloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory allocation failed!");
                SCReturnInt(-1);
            }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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
                    if (pstate->store == NULL) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                        SCReturnInt(-1);
                    }

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
            if (pstate->store == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Memory reallocation failed!");
                SCReturnInt(-1);
            }

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

/** \brief Get the Parsers id for storing the parser state.
 *
 * \retval Parser subsys id
 */
uint16_t AppLayerParserGetStorageId(void)
{
    return app_layer_sid;
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

/** \brief Description: register a parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine
 *       knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 * \param max_outputs max number of unique outputs the parser can generate
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id,
                           int (*AppLayerParser)(Flow *f, void *protocol_state,
                            AppLayerParserState *parser_state, uint8_t *input,
                            uint32_t input_len, AppLayerParserResult *output),
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
               "%" PRIu32 ", storage_id %" PRIu32 ", parser_local_id %" PRIu32 "",
                AppLayerParser, proto, al_max_parsers,
                al_proto_table[proto].storage_id, parser_id);
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
                         AppLayerParserState *parser_state, uint8_t *input,
                         uint32_t input_len, AppLayerParserResult *output))
{

    al_max_parsers++;

    if(al_max_parsers >= MAX_PARSERS){
        SCLogInfo("Failed to register %s al_parser_table array full",name);
        exit(EXIT_FAILURE);
    }

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    al_proto_table[proto].name = name;

    /* create proto, direction -- parser mapping */
    if (flags & STREAM_TOSERVER) {
        al_proto_table[proto].to_server = al_max_parsers;
    } else if (flags & STREAM_TOCLIENT) {
        al_proto_table[proto].to_client = al_max_parsers;
    }

    if (al_proto_table[proto].storage_id == 0) {
        al_proto_table[proto].storage_id = StreamL7RegisterModule();
    }

    SCLogDebug("registered %p at proto %" PRIu32 " flags %02X, al_proto_table "
                "idx %" PRIu32 ", storage_id %" PRIu32 " %s", AppLayerParser, proto,
                flags, al_max_parsers, al_proto_table[proto].storage_id, name);
    return 0;
}

void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void),
                                void (*StateFree)(void *))
{
    al_proto_table[proto].StateAlloc = StateAlloc;
    al_proto_table[proto].StateFree = StateFree;
}

uint16_t AlpGetStateIdx(uint16_t proto)
{
    return al_proto_table[proto].storage_id;
}

AppLayerParserStateStore *AppLayerParserStateStoreAlloc(void)
{
    AppLayerParserStateStore *s = (AppLayerParserStateStore *)SCMalloc
                                    (sizeof(AppLayerParserStateStore));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserStateStore));
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

static int AppLayerDoParse(Flow *f, void *app_layer_state, AppLayerParserState *parser_state,
                           uint8_t *input, uint32_t input_len, uint16_t parser_idx,
                           uint16_t proto)
{
    SCEnter();
    int retval = 0;
    AppLayerParserResult result = { NULL, NULL, 0 };

    SCLogDebug("parser_idx %" PRIu32 "", parser_idx);
    //PrintRawDataFp(stdout, input,input_len);

    /* invoke the parser */
    int r = al_parser_table[parser_idx].AppLayerParser(f, app_layer_state,
                                       parser_state, input, input_len, &result);
    if (r < 0) {
        if (r == -1) {
            AppLayerParserResultCleanup(&result);
            SCReturnInt(-1);
        } else {
            BUG_ON(r);  /* this is not supposed to happen!! */
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

        r = AppLayerDoParse(f, app_layer_state, parser_state, e->data_ptr,
                            e->data_len, idx, proto);

        /* restore */
        parser_state->flags &= ~APP_LAYER_PARSER_EOF;
        parser_state->parse_field = tmp;

        /* bail out on a serious error */
        if (r < 0) {
            if (r == -1) {
                retval = -1;
                break;
            } else {
                BUG_ON(r);
            }
        }
    }

    AppLayerParserResultCleanup(&result);
    SCReturnInt(retval);
}

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
int AppLayerParse(Flow *f, uint8_t proto, uint8_t flags, uint8_t *input,
                  uint32_t input_len)
{
    SCEnter();

    uint16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];
    TcpSession *ssn = NULL;

    ssn = f->protoctx;
    if (ssn == NULL) {
        SCLogDebug("no TCP session");
        goto error;
    }

    if (flags & STREAM_GAP) {
        SCLogDebug("stream gap detected (missing packets), this is not yet supported.");
        goto error;
    }

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = NULL;

    if (ssn->aldata != NULL) {
        parser_state_store = (AppLayerParserStateStore *)
                                                    ssn->aldata[app_layer_sid];
        if (parser_state_store == NULL) {
            parser_state_store = AppLayerParserStateStoreAlloc();
            if (parser_state_store == NULL)
                goto error;

            ssn->aldata[app_layer_sid] = (void *)parser_state_store;
        }
    } else {
        SCLogDebug("No App Layer Data");
        /* Nothing is there to clean up, so just return from here after setting
         * up the no reassembly flags */
        StreamTcpSetSessionNoReassemblyFlag(ssn, flags & STREAM_TOCLIENT ? 1 : 0);
        StreamTcpSetSessionNoReassemblyFlag(ssn, flags & STREAM_TOSERVER ? 1 : 0);
        SCReturnInt(-1);
    }

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
    void *app_layer_state = NULL;
    app_layer_state = ssn->aldata[p->storage_id];

    if (app_layer_state == NULL) {
        /* lock the allocation of state as we may
         * alloc more than one otherwise */
        app_layer_state = p->StateAlloc();
        if (app_layer_state == NULL) {
            goto error;
        }

        ssn->aldata[p->storage_id] = app_layer_state;
        SCLogDebug("alloced new app layer state %p (p->storage_id %u, name %s)", app_layer_state, p->storage_id, al_proto_table[ssn->alproto].name);
    } else {
        SCLogDebug("using existing app layer state %p (p->storage_id %u, name %s))", app_layer_state, p->storage_id, al_proto_table[ssn->alproto].name);
    }

    /* invoke the recursive parser */
    int r = AppLayerDoParse(f, app_layer_state, parser_state, input, input_len,
                            parser_idx, proto);
    if (r < 0)
        goto error;

    /* set the packets to no inspection and reassembly for the TLS sessions */
    if (parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) {
        FlowSetNoPayloadInspectionFlag(f);

        /* Set the no reassembly flag for both the stream in this TcpSession */
        if (parser_state->flags & APP_LAYER_PARSER_NO_REASSEMBLY) {
            StreamTcpSetSessionNoReassemblyFlag(ssn,
                                               flags & STREAM_TOCLIENT ? 1 : 0);
            StreamTcpSetSessionNoReassemblyFlag(ssn,
                                               flags & STREAM_TOSERVER ? 1 : 0);
        }
    }

    SCReturnInt(0);
error:
    if (ssn != NULL) {
        /* Set the no reassembly flag for both the stream in this TcpSession */
        StreamTcpSetSessionNoReassemblyFlag(ssn, flags & STREAM_TOCLIENT ? 1 : 0);
        StreamTcpSetSessionNoReassemblyFlag(ssn, flags & STREAM_TOSERVER ? 1 : 0);

        if (f->src.family == AF_INET) {
            char src[16];
            char dst[16];
            inet_ntop(AF_INET, (const void*)&f->src.addr_data32[0], src,
                      sizeof (src));
            inet_ntop(AF_INET, (const void*)&f->dst.addr_data32[0], dst,
                      sizeof (dst));

            SCLogError(SC_ERR_ALPARSER, "Error occured in parsing \"%s\" app layer "
                "protocol, using network protocol %"PRIu8", source IP "
                "address %s, destination IP address %s, src port %"PRIu16" and "
                "dst port %"PRIu16"", al_proto_table[ssn->alproto].name,
                f->proto, src, dst, f->sp, f->dp);
        } else {
            char dst6[46];
            char src6[46];

            inet_ntop(AF_INET6, (const void*)&f->src.addr_data32, src6,
                      sizeof (src6));
            inet_ntop(AF_INET6, (const void*)&f->dst.addr_data32, dst6,
                      sizeof (dst6));

            SCLogError(SC_ERR_ALPARSER, "Error occured in parsing \"%s\" app layer "
                "protocol, using network protocol %"PRIu8", source IPv6 "
                "address %s, destination IPv6 address %s, src port %"PRIu16" and "
                "dst port %"PRIu16"", al_proto_table[ssn->alproto].name,
                f->proto, src6, dst6, f->sp, f->dp);
        }
    }

    SCReturnInt(-1);
}

void RegisterAppLayerParsers(void)
{
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    app_layer_sid = StreamL7RegisterModule();

    /** setup result pool
     * \todo Per thread pool */
    al_result_pool = PoolInit(1000,250,AlpResultElmtPoolAlloc,NULL,AlpResultElmtPoolFree);
}

void AppLayerParserCleanupState(TcpSession *ssn)
{
    if (ssn == NULL) {
        SCLogDebug("no ssn");
        return;
    }
    if (ssn->alproto >= ALPROTO_MAX) {
        SCLogDebug("app layer proto unknown");
        return;
    }

    /* free the parser protocol state */
    AppLayerProto *p = &al_proto_table[ssn->alproto];
    if (p->StateFree != NULL && ssn->aldata != NULL) {
        if (ssn->aldata[p->storage_id] != NULL) {
            SCLogDebug("calling StateFree");
            p->StateFree(ssn->aldata[p->storage_id]);
            ssn->aldata[p->storage_id] = NULL;
        }
    }

    /* free the app layer parser api state */
    if (ssn->aldata != NULL) {
        if (ssn->aldata[app_layer_sid] != NULL) {
            SCLogDebug("calling AppLayerParserStateStoreFree");
            AppLayerParserStateStoreFree(ssn->aldata[app_layer_sid]);
            ssn->aldata[app_layer_sid] = NULL;
        }

        StreamTcpDecrMemuse((uint32_t)(StreamL7GetStorageSize() * sizeof(void *)));
        SCFree(ssn->aldata);
        ssn->aldata = NULL;
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
            SCLogError(SC_ERR_MEM_ALLOC, "memory error");
            exit(1);
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
                    SCLogError(SC_ERR_MEM_ALLOC, "XXX memory error");
                    exit(1);
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

/* UNITTESTS*/
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
                                     AppLayerParserResult *output)
{
    return -1;
}

/** \brief Function to allocates the Test protocol state memory
 */
static void *TestProtocolStateAlloc(void)
{
    void *s = SCMalloc(sizeof(TestState));
    if (s == NULL)
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
    int result = 1;
    Flow f;
    uint8_t testbuf[] = { 0x11 };
    uint32_t testlen = sizeof(testbuf);
    TcpSession ssn;
    struct in_addr addr;
    struct in_addr addr1;
    Address src;
    Address dst;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&src, 0, sizeof(src));
    memset(&dst, 0, sizeof(dst));

    /* Register the Test protocol state and parser functions */
    AppLayerRegisterProto("test", ALPROTO_TEST, STREAM_TOSERVER,
                          TestProtocolParser);
    AppLayerRegisterStateFuncs(ALPROTO_TEST, TestProtocolStateAlloc,
                                TestProtocolStateFree);

    ssn.alproto = ALPROTO_TEST;
    f.protoctx = (void *)&ssn;

    inet_pton(AF_INET, "1.2.3.4", &addr.s_addr);
    src.family = AF_INET;
    src.addr_data32[0] = addr.s_addr;
    inet_pton(AF_INET, "4.3.2.1", &addr1.s_addr);
    dst.family = AF_INET;
    dst.addr_data32[0] = addr1.s_addr;
    f.src = src;
    f.dst = dst;
    f.sp = htons(20);
    f.dp = htons(40);
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TEST, STREAM_TOSERVER|STREAM_EOF, testbuf,
                          testlen);
    if (r != -1) {
        printf("returned %" PRId32 ", expected -1: \n", r);
        result = 0;
        goto end;
    }

    if (!(ssn.flags & STREAMTCP_FLAG_NOSERVER_REASSEMBLY) ||
            !(ssn.flags & STREAMTCP_FLAG_NOCLIENT_REASSEMBLY))
    {
        printf("flags should be set, but they are not !\n");
        result = 0;
        goto end;
    }

end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif /* UNITESTS */

void AppLayerParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("AppLayerParserTest01", AppLayerParserTest01, 1);
#endif /* UNITTESTS */
}
