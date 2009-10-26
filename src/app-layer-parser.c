/* Copyright (c) 2009 Victor Julien */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-binsearch.h"

#include "util-debug.h"

static Pool *al_result_pool = NULL;

/** \brief Alloc a AppLayerParserResultElmt func for the pool */
static void *AlpResultElmtPoolAlloc(void *null) {
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)malloc(sizeof(AppLayerParserResultElmt));
    if (e == NULL) {
        return NULL;
    }

    memset(e, 0, sizeof(AppLayerParserResultElmt));
    return e;
}

static void AlpResultElmtPoolFree(void *e) {
    AppLayerParserResultElmt *re = (AppLayerParserResultElmt *)e;

    if (re->flags & ALP_RESULT_ELMT_ALLOC) {
        if (re->data_ptr != NULL)
            free(re->data_ptr);
    }
    free(re);
}

static AppLayerParserResultElmt *AlpGetResultElmt(void) {
    AppLayerParserResultElmt *e = (AppLayerParserResultElmt *)PoolGet(al_result_pool);
    if (e == NULL) {
        return NULL;
    }
    e->next = NULL;
    return e;
}

static void AlpReturnResultElmt(AppLayerParserResultElmt *e) {
    if (e->flags & ALP_RESULT_ELMT_ALLOC) {
        if (e->data_ptr != NULL)
            free(e->data_ptr);
    }
    e->flags = 0;
    e->data_ptr = NULL;
    e->data_len = 0;
    e->next = NULL;

    PoolReturn(al_result_pool, (void *)e);
}

static void AlpAppendResultElmt(AppLayerParserResult *r, AppLayerParserResultElmt *e) {
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
 */
static void AlpStoreField(AppLayerParserResult *output, uint16_t idx, uint8_t *ptr, uint32_t len, uint8_t alloc) {
    AppLayerParserResultElmt *e = AlpGetResultElmt();
    if (e == NULL)
        return;

    if (alloc == 1)
        e->flags |= ALP_RESULT_ELMT_ALLOC;

    e->name_idx = idx;
    e->data_ptr = ptr;
    e->data_len = len;
    AlpAppendResultElmt(output, e);

    //printf("FIELD registered %" PRIu32 ":\n", idx);
    //PrintRawDataFp(stdout, e->data_ptr,e->data_len);
}

/** \brief Parse a field up to we reach the size limit
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldBySize(AppLayerParserResult *output, AppLayerParserState *pstate, uint16_t field_idx, uint32_t size, uint8_t *input, uint32_t input_len, uint32_t *offset) {
    if ((pstate->store_len + input_len) < size) {
        if (pstate->store_len == 0) {
            pstate->store = malloc(input_len);
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        } else {
            pstate->store = realloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }
    } else {
        if (pstate->store_len == 0) {
            AlpStoreField(output, field_idx, input, size, 0);
            (*offset) += size;
            return 1;
        } else {
            uint32_t diff = size - pstate->store_len;

            pstate->store = realloc(pstate->store, (diff + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, diff);
            pstate->store_len += diff;

            AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);

            (*offset) += diff;

            pstate->store = NULL;
            pstate->store_len = 0;
            return 1;
        }
    }

    return 0;
}

/** \brief Parse a field up to the EOF
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByEOF(AppLayerParserResult *output, AppLayerParserState *pstate, uint16_t field_idx, uint8_t *input, uint32_t input_len) {
    if (pstate->store_len == 0) {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            //printf("ParseFieldByEOF: store_len 0 and EOF\n");
            AlpStoreField(output, field_idx, input, input_len, 0);
            return 1;
        } else {
            //printf("ParseFieldByEOF: store_len 0 but no EOF\n");
            /* delimiter field not found, so store the result for the next run */
            pstate->store = malloc(input_len);
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        if (pstate->flags & APP_LAYER_PARSER_EOF) {
            //printf("ParseFieldByEOF: store_len %" PRIu32 " and EOF\n", pstate->store_len);
            pstate->store = realloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);
            pstate->store = NULL;
            pstate->store_len = 0;
            return 1;
        } else {
            //printf("ParseFieldByEOF: store_len %" PRIu32 " but no EOF\n", pstate->store_len);
            /* delimiter field not found, so store the result for the next run */
            pstate->store = realloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;
        }

    }

    return 0;
}

/** \brief Parse a field up to a delimeter.
 *
 * \retval  1 Field found and stored.
 * \retval  0 Field parsing in progress.
 * \retval -1 error
 */
int AlpParseFieldByDelimiter(AppLayerParserResult *output, AppLayerParserState *pstate, uint16_t field_idx, const uint8_t *delim, uint8_t delim_len, uint8_t *input, uint32_t input_len, uint32_t *offset) {
//    printf("ParseFieldByDelimiter: pstate->store_len %" PRIu32 ", delim_len %" PRIu32 "\n", pstate->store_len, delim_len);

    if (pstate->store_len == 0) {
        uint8_t *ptr = BinSearch(input, input_len, delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            //printf("ParseFieldByDelimiter: len %" PRIu32 "\n", len);

            AlpStoreField(output, field_idx, input, len, 0);
            (*offset) += (len + delim_len);
            return 1;
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                //printf("ParseFieldByDelimiter: delim not found and EOF\n");
                return 0;
            }

            //printf("ParseFieldByDelimiter: delim not found, continue\n");

            /* delimiter field not found, so store the result for the next run */
            pstate->store = malloc(input_len);
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store, input, input_len);
            pstate->store_len = input_len;
        }
    } else {
        uint8_t *ptr = BinSearch(input, input_len, delim, delim_len);
        if (ptr != NULL) {
            uint32_t len = ptr - input;
            //printf("ParseFieldByDelimiter: len %" PRIu32 " + %" PRIu32 " = %" PRIu32 "\n", len, pstate->store_len, len + pstate->store_len);

            pstate->store = realloc(pstate->store, (len + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, len);
            pstate->store_len += len;

            AlpStoreField(output, field_idx, pstate->store, pstate->store_len, 1);
            pstate->store = NULL;
            pstate->store_len = 0;

            (*offset) += (len + delim_len);
            return 1;
        } else {
            if (pstate->flags & APP_LAYER_PARSER_EOF) {
                /* if the input len is smaller than the delim len we search the
                 * pstate->store since we may match there. */
                if (delim_len > input_len) {
                    /* delimiter field not found, so store the result for the next run */
                    pstate->store = realloc(pstate->store, (input_len + pstate->store_len));
                    if (pstate->store == NULL)
                        return -1;

                    memcpy(pstate->store+pstate->store_len, input, input_len);
                    pstate->store_len += input_len;
                    //printf("ParseFieldByDelimiter: input_len < delim_len, checking pstate->store\n");

                    if (pstate->store_len >= delim_len) {
                        ptr = BinSearch(pstate->store, pstate->store_len, delim, delim_len);
                        if (ptr != NULL) {
                            //printf("ParseFieldByDelimiter: now we found the delim\n");

                            uint32_t len = ptr - pstate->store;
                            AlpStoreField(output, field_idx, pstate->store, len, 1);
                            pstate->store = NULL;
                            pstate->store_len = 0;

                            (*offset) += (input_len);

                            //printf("ParseFieldByDelimiter: offset %" PRIu32 "\n", (*offset));
                            return 1;
                        }
                        goto free_and_return;
                    }
                    goto free_and_return;
                }
            free_and_return:
                //printf("ParseFieldByDelimiter: not found and EOF, so free what we have so far.\n");
                free(pstate->store);
                pstate->store = NULL;
                pstate->store_len = 0;
                return 0;
            }

            /* delimiter field not found, so store the result for the next run */
            pstate->store = realloc(pstate->store, (input_len + pstate->store_len));
            if (pstate->store == NULL)
                return -1;

            memcpy(pstate->store+pstate->store_len, input, input_len);
            pstate->store_len += input_len;

            /* if the input len is smaller than the delim len we search the
             * pstate->store since we may match there. */
            if (delim_len > input_len && delim_len <= pstate->store_len) {
                //printf("ParseFieldByDelimiter: input_len < delim_len, checking pstate->store\n");

                ptr = BinSearch(pstate->store, pstate->store_len, delim, delim_len);
                if (ptr != NULL) {
                    //printf("ParseFieldByDelimiter: now we found the delim\n");

                    uint32_t len = ptr - pstate->store;
                    AlpStoreField(output, field_idx, pstate->store, len, 1);
                    pstate->store = NULL;
                    pstate->store_len = 0;

                    (*offset) += (input_len);

                    //printf("ParseFieldByDelimiter: offset %" PRIu32 "\n", (*offset));
                    return 1;
                }
            }
        }

    }

    return 0;
}

static uint16_t app_layer_sid = 0;
static AppLayerProto al_proto_table[ALPROTO_MAX];

#define MAX_PARSERS 100
static AppLayerParserTableElement al_parser_table[MAX_PARSERS];
static uint16_t al_max_parsers = 0; /* incremented for every registered parser */

/** \brief Get the Parsers id for storing the parser state.
 *
 * \retval Parser subsys id
 */
uint16_t AppLayerParserGetStorageId(void) {
    return app_layer_sid;
}

/** \brief Description: register a parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 * \param max_outputs max number of unique outputs the parser can generate
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id, int (*AppLayerParser)(void *protocol_state, AppLayerParserState *parser_state, uint8_t *input, uint32_t input_len, AppLayerParserResult *output), char *dependency) {

    al_max_parsers++;

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].proto = proto;
    al_parser_table[al_max_parsers].parser_local_id = parser_id;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    SCLogDebug("registered %p at proto %" PRIu32 ", al_proto_table idx %" PRIu32 ", storage_id %" PRIu32 ", parser_local_id %" PRIu32 "",
        AppLayerParser, proto, al_max_parsers, al_proto_table[proto].storage_id, parser_id);
    return 0;
}

/** \brief Description: register a protocol parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterProto(char *name, uint8_t proto, uint8_t flags, int (*AppLayerParser)(void *protocol_state, AppLayerParserState *parser_state, uint8_t *input, uint32_t input_len, AppLayerParserResult *output)) {

    al_max_parsers++;

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    /* create proto, direction -- parser mapping */
    if (flags & STREAM_TOSERVER) {
        al_proto_table[proto].to_server = al_max_parsers;
    } else if (flags & STREAM_TOCLIENT) {
        al_proto_table[proto].to_client = al_max_parsers;
    }

    if (al_proto_table[proto].storage_id == 0) {
        al_proto_table[proto].storage_id = StreamL7RegisterModule();
    }

    SCLogDebug("registered %p at proto %" PRIu32 " flags %02X, al_proto_table idx %" PRIu32 ", storage_id %" PRIu32 "",
        AppLayerParser, proto, flags, al_max_parsers, al_proto_table[proto].storage_id);
    return 0;
}

void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void), void (*StateFree)(void *)) {
    al_proto_table[proto].StateAlloc = StateAlloc;
    al_proto_table[proto].StateFree = StateFree;
}

uint16_t AlpGetStateIdx(uint16_t proto) {
    return al_proto_table[proto].storage_id;
}

AppLayerParserStateStore *AppLayerParserStateStoreAlloc(void) {
    AppLayerParserStateStore *s = (AppLayerParserStateStore *)malloc(sizeof(AppLayerParserStateStore));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserStateStore));
    return s;
}

/** \brief free a AppLayerParserStateStore structure
 *  \param s AppLayerParserStateStore structure to free */
void AppLayerParserStateStoreFree(AppLayerParserStateStore *s) {
    if (s->to_server.store != NULL)
        free(s->to_server.store);
    if (s->to_client.store != NULL)
        free(s->to_client.store);

    free(s);
}

static void AppLayerParserResultCleanup(AppLayerParserResult *result) {
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

static int AppLayerDoParse(void *app_layer_state, AppLayerParserState *parser_state, uint8_t *input, uint32_t input_len, uint16_t parser_idx, uint16_t proto) {
    int retval = 0;
    AppLayerParserResult result = { NULL, NULL, 0 };

    //printf("AppLayerDoParse: parser_idx %" PRIu32 "\n", parser_idx);
    //PrintRawDataFp(stdout, input,input_len);

    /* invoke the parser */
    int r = al_parser_table[parser_idx].AppLayerParser(app_layer_state, parser_state, input, input_len, &result);
    if (r < 0)
        return -1;

    /* process the result elements */
    AppLayerParserResultElmt *e = result.head;
    for (; e != NULL; e = e->next) {
        //printf("AppLayerParse: e %p e->name_idx %" PRIu32 ", e->data_ptr %p, e->data_len %" PRIu32 ", map_size %" PRIu32 "\n",
        //    e, e->name_idx, e->data_ptr, e->data_len, al_proto_table[proto].map_size);

        /* no parser defined for this field. */
        if (e->name_idx >= al_proto_table[proto].map_size || al_proto_table[proto].map[e->name_idx] == NULL) {
            //printf("AppLayerParse: no parser for proto %" PRIu32 ", parser_local_id %" PRIu32 "\n", proto, e->name_idx);
            continue;
        }

        uint16_t idx = al_proto_table[proto].map[e->name_idx]->parser_id;

        /* prepare */
        uint16_t tmp = parser_state->parse_field;
        parser_state->parse_field = 0;
        parser_state->flags |= APP_LAYER_PARSER_EOF;

        r = AppLayerDoParse(app_layer_state, parser_state, e->data_ptr, e->data_len, idx, proto);

        /* restore */
        parser_state->flags &= ~APP_LAYER_PARSER_EOF;
        parser_state->parse_field = tmp;

        /* bail out on a serious error */
        if (r < 0) {
            retval = -1;
            break;
        }
    }

    AppLayerParserResultCleanup(&result);
    return retval;
}

/**
 * \brief Layer 7 Parsing main entry point.
 *
 * \param f Properly initialized and locked flow.
 * \param proto L7 proto, e.g. ALPROTO_HTTP
 * \param flags Stream flags
 * \param input Input L7 data
 * \param input_len Length of the input data.
 * \param need_lock bool controlling locking for the flow
 *
 * \retval -1 error
 * \retval 0 ok
 */
int AppLayerParse(Flow *f, uint8_t proto, uint8_t flags, uint8_t *input, uint32_t input_len, char need_lock) {
    SCEnter();

    uint16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];

    TcpSession *ssn = f->protoctx;
    if (ssn == NULL) {
        printf("AppLayerParse: no session\n");
        goto error;
    }

    /* Get the parser state (if any) */
    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)ssn->aldata[app_layer_sid];
    if (parser_state_store == NULL) {
        parser_state_store = AppLayerParserStateStoreAlloc();
        if (parser_state_store == NULL)
            goto error;

        if (need_lock == TRUE) mutex_lock(&f->m);
        ssn->aldata[app_layer_sid] = (void *)parser_state_store;
        if (need_lock == TRUE) mutex_unlock(&f->m);
    }

    AppLayerParserState *parser_state = NULL;
    if (flags & STREAM_TOSERVER) {
        parser_state = &parser_state_store->to_server;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_server;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            //printf("AppLayerParse: using parser %" PRIu32 " we stored before (to_server)\n", parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    } else {
        parser_state = &parser_state_store->to_client;
        if (!(parser_state->flags & APP_LAYER_PARSER_USE)) {
            parser_idx = p->to_client;
            parser_state->cur_parser = parser_idx;
            parser_state->flags |= APP_LAYER_PARSER_USE;
        } else {
            //printf("AppLayerParse: using parser %" PRIu32 " we stored before (to_client)\n", parser_state->cur_parser);
            parser_idx = parser_state->cur_parser;
        }
    }

    if (parser_idx == 0 || parser_state->flags & APP_LAYER_PARSER_DONE) {
        //printf("AppLayerParse: no parser for protocol %" PRIu32 "\n", proto);
        SCReturnInt(0);
    }

    if (flags & STREAM_EOF)
        parser_state->flags |= APP_LAYER_PARSER_EOF;

    /* See if we already have a 'app layer' state */
    void *app_layer_state = NULL;
    if (need_lock == TRUE) mutex_lock(&f->m);
    app_layer_state = ssn->aldata[p->storage_id];
    if (need_lock == TRUE) mutex_unlock(&f->m);

    if (app_layer_state == NULL) {
        app_layer_state = p->StateAlloc();
        if (app_layer_state == NULL)
            goto error;

        if (need_lock == TRUE) mutex_lock(&f->m);
        ssn->aldata[p->storage_id] = app_layer_state;
        if (need_lock == TRUE) mutex_unlock(&f->m);
    }

    /* invoke the recursive parser */
    int r = AppLayerDoParse(app_layer_state, parser_state, input, input_len, parser_idx, proto);
    if (r < 0)
        goto error;

    SCReturnInt(0);
error:
    SCReturnInt(-1);
}

void RegisterAppLayerParsers(void) {
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    app_layer_sid = StreamL7RegisterModule();

    /** setup result pool
     * \todo Per thread pool */
    al_result_pool = PoolInit(250,10,AlpResultElmtPoolAlloc,NULL,AlpResultElmtPoolFree);
}

void AppLayerParserCleanupState(TcpSession *ssn) {
    if (ssn == NULL) {
        //printf("AppLayerParserCleanupState: no ssn\n");
        return;
    }

    AppLayerProto *p = &al_proto_table[ssn->alproto];
    if (p == NULL) {
        //printf("AppLayerParserCleanupState: no parser state for %"PRIu16"\n", ssn->alproto);
        return;
    }

    /* free the parser protocol state */
    if (p->StateFree != NULL) {
        if (ssn->aldata[p->storage_id] != NULL) {
            //printf("AppLayerParserCleanupState: calling StateFree\n");
            p->StateFree(ssn->aldata[p->storage_id]);
            ssn->aldata[p->storage_id] = NULL;
        }
    }

    if (ssn->aldata != NULL) {
        if (ssn->aldata[app_layer_sid] != NULL) {
            //printf("AppLayerParserCleanupState: calling AppLayerParserStateStoreFree\n");
            AppLayerParserStateStoreFree(ssn->aldata[app_layer_sid]);
            ssn->aldata[app_layer_sid] = NULL;
        }

        free(ssn->aldata);
        ssn->aldata = NULL;
    }
}

/** \brief Create a mapping between the individual parsers local field id's
 *         and the global field parser id's.
 *
 */
void AppLayerParsersInitPostProcess(void) {
    uint16_t u16 = 0;

    /* build local->global mapping */
    for (u16 = 1; u16 <= al_max_parsers; u16++) {
        /* no local parser */
        if (al_parser_table[u16].parser_local_id == 0)
            continue;

        if (al_parser_table[u16].parser_local_id > al_proto_table[al_parser_table[u16].proto].map_size)
            al_proto_table[al_parser_table[u16].proto].map_size = al_parser_table[u16].parser_local_id;

        //printf("AppLayerParsersInitPostProcess: map_size %" PRIu32 "\n", al_proto_table[al_parser_table[u16].proto].map_size);
    }

    /* for each proto, alloc the map array */
    for (u16 = 0; u16 < ALPROTO_MAX; u16++) {
        if (al_proto_table[u16].map_size == 0)
            continue;

        al_proto_table[u16].map_size++;
        al_proto_table[u16].map = (AppLayerLocalMap **)malloc(al_proto_table[u16].map_size * sizeof(AppLayerLocalMap *));
        if (al_proto_table[u16].map == NULL) {
            printf("XXX memory error\n");
            exit(1);
        }
        memset(al_proto_table[u16].map, 0, al_proto_table[u16].map_size * sizeof(AppLayerLocalMap *));

        uint16_t u = 0;
        for (u = 1; u <= al_max_parsers; u++) {
            /* no local parser */
            if (al_parser_table[u].parser_local_id == 0)
                continue;

            if (al_parser_table[u].proto != u16)
                continue;

            //printf("AppLayerParsersInitPostProcess: al_proto_table[%" PRIu32 "].map_size %" PRIu32 ", %p %p\n", u16, al_proto_table[u16].map_size, al_proto_table[u16].map[x], al_proto_table[u16].map);
            uint16_t parser_local_id = al_parser_table[u].parser_local_id;
            //printf("AppLayerParsersInitPostProcess: parser_local_id: %" PRIu32 "\n", parser_local_id);

            if (parser_local_id < al_proto_table[u16].map_size) {
                al_proto_table[u16].map[parser_local_id] = malloc(sizeof(AppLayerLocalMap));
                if (al_proto_table[u16].map[parser_local_id] == NULL) {
                    printf("XXX memory error\n");
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

            //printf("AppLayerParsersInitPostProcess: al_proto_table[%" PRIu32 "].map[%" PRIu32 "]->parser_id: %" PRIu32 "\n", u16, x, al_proto_table[u16].map[x]->parser_id);
        }
    }
}

