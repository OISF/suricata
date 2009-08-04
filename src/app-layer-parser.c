/* Copyright (c) 2009 Victor Julien */

#include "eidps.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

static Pool *al_result_pool = NULL;

void* AppLayerParserResultElementAlloc(void *null) {
    AppLayerParserResultElement *e = (AppLayerParserResultElement *)malloc(sizeof(AppLayerParserResultElement));
    if (e == NULL) {
        return NULL;
    }

    memset(e, 0, sizeof(AppLayerParserResultElement));
    return e;
}
#define AppLayerParserResultElementFree free

AppLayerParserResultElement *AppLayerGetResultElmt(void) {
    AppLayerParserResultElement *e = (AppLayerParserResultElement *)PoolGet(al_result_pool);
    return e;
}

static u_int16_t app_layer_sid = 0;
static AppLayerProto al_proto_table[ALPROTO_MAX];

#define MAX_PARSERS 16
static AppLayerParserTableElement al_parser_table[MAX_PARSERS];
static u_int16_t al_max_parsers = 0; /* incremented for every registered parser */

/** \brief Get the Parsers id for storing the parser state.
 *
 * \retval Parser subsys id
 */
u_int16_t AppLayerParserGetStorageId(void) {
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
int AppLayerRegisterParser(char *name, u_int16_t proto, u_int16_t parser_id, int (*AppLayerParser)(void *protocol_state, void *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResultElement **output, u_int16_t *output_num), char *dependency) {

    al_max_parsers++;

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].proto = proto;
    al_parser_table[al_max_parsers].parser_local_id = parser_id;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;

    printf("AppLayerRegisterParser: registered %p at proto %u, al_proto_table idx %u, storage_id %u, parser_local_id %u\n",
        AppLayerParser, proto, al_max_parsers, al_proto_table[proto].storage_id, parser_id);
    return 0;
}

/** \brief Description: register a protocol parser.
 *
 * \param name full parser name, e.g. "http.request_line"
 * \todo do we need recursive, so a "http" and a "request_line" where the engine knows it's actually "http.request_line"... same difference maybe.
 * \param AppLayerParser pointer to the parser function
 * \param max_outputs max number of unique outputs the parser can generate
 *
 * \retval 0 on success
 * \retval -1 on error
 */
int AppLayerRegisterProto(char *name, u_int8_t proto, u_int8_t flags, int (*AppLayerParser)(void *protocol_state, void *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResultElement **output, u_int16_t *output_num)) {

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

    printf("AppLayerRegisterProto: registered %p at proto %u flags %02X, al_proto_table idx %u, storage_id %u\n",
        AppLayerParser, proto, flags, al_max_parsers, al_proto_table[proto].storage_id);
    return 0;
}

AppLayerParserState* AppLayerParserStateAlloc(void) {
    AppLayerParserState *s = (AppLayerParserState *)malloc(sizeof(AppLayerParserState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(AppLayerParserState));
    return s;
}

/**
 * \brief Layer 7 Parsing main entry point.
 *
 */
int AppLayerParse(Flow *f, u_int8_t proto, u_int8_t flags, u_int8_t *input, u_int32_t input_len) {
    printf("AppLayerParse: proto %u, flags %02X\n", proto, flags);

    u_int16_t parser_idx = 0;
    AppLayerProto *p = &al_proto_table[proto];

    TcpSession *ssn = f->stream;
    if (ssn == NULL) {
        return -1;
    }

    /* Get the parser state (if any) */
    AppLayerParserState *parser_state = (AppLayerParserState *)ssn->l7data[app_layer_sid];
    /* See if we already have a 'app' state */
    void *app_layer_state = ssn->l7data[p->storage_id];

    if (parser_state == NULL) {
        if (flags & STREAM_TOSERVER) {
            parser_idx = p->to_server;
        } else if (flags & STREAM_TOCLIENT) {
            parser_idx = p->to_client;
        }
    } else {
        printf("AppLayerParse: using parser %u we stored before\n", parser_state->cur_parser);
        parser_idx = parser_state->cur_parser;
    }

    if (parser_idx == 0) {
        printf("AppLayerParse: no parser for protocol %u\n", proto);
        return 0;
    }

    if (parser_state == NULL) {
        parser_state = AppLayerParserStateAlloc();
        if (parser_state != NULL) {
            parser_state->cur_parser = parser_idx;

            ssn->l7data[app_layer_sid] = (void *)parser_state;
        }
    }

    AppLayerParserResultElement *result_tbl[256];
    memset(&result_tbl,0,sizeof(result_tbl));
    u_int16_t output_num = 0;
    int r = al_parser_table[parser_idx].AppLayerParser(app_layer_state, parser_state, input, input_len, result_tbl, &output_num);
    if (r < 0)
        return -1;

    printf("AppLayerParse: output_num %u\n", output_num);
    u_int16_t u = 0;
    for (u = 0; u < output_num; u++) {
        AppLayerParserResultElement *e = result_tbl[u];
        printf("AppLayerParse: e->name_idx %u, e->data_ptr %p, e->data_len %u, map_size %u\n", e->name_idx, e->data_ptr, e->data_len, al_proto_table[proto].map_size);

        /* no parser defined for this field. */
        if (e->name_idx >= al_proto_table[proto].map_size || al_proto_table[proto].map[e->name_idx] == NULL) {
            printf("AppLayerParse: no parser for proto %u, parser_local_id %u\n", proto, e->name_idx);
            continue;
        }

        parser_idx = al_proto_table[proto].map[e->name_idx]->parser_id;
        int r = al_parser_table[parser_idx].AppLayerParser(app_layer_state, parser_state, e->data_ptr, e->data_len, result_tbl, &output_num);
        if (r < 0)
            return -1;
    }

    return 0;
}

void RegisterAppLayerParsers(void) {
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    app_layer_sid = StreamL7RegisterModule();

    /** setup result pool
     * \todo Per thread pool */
    al_result_pool = PoolInit(100,10,AppLayerParserResultElementAlloc,NULL,AppLayerParserResultElementFree);
}

void AppLayerParsersInitPostProcess(void) {
    printf("AppLayerParsersInitPostProcess: start\n");
    u_int16_t u16 = 0;

    /* build local->global mapping */
    for (u16 = 1; u16 <= al_max_parsers; u16++) {
        /* no local parser */
        if (al_parser_table[u16].parser_local_id == 0)
            continue;

        if (al_parser_table[u16].parser_local_id > al_proto_table[al_parser_table[u16].proto].map_size)
            al_proto_table[al_parser_table[u16].proto].map_size = al_parser_table[u16].parser_local_id;

        printf("AppLayerParsersInitPostProcess: map_size %u\n", al_proto_table[al_parser_table[u16].proto].map_size);
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

        u_int16_t u = 0;
        u_int16_t x = 0;
        for (u = 1; u <= al_max_parsers; u++) {
            /* no local parser */
            if (al_parser_table[u].parser_local_id == 0)
                continue;

            if (al_parser_table[u].proto != u16)
                continue;

            printf("al_proto_table[%u].map_size %u, x %u, %p %p\n", u16, al_proto_table[u16].map_size, x, al_proto_table[u16].map[x], al_proto_table[u16].map);
            u_int16_t parser_local_id = al_parser_table[u].parser_local_id;
            printf("parser_local_id: %u\n", parser_local_id);

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

        u_int16_t x = 0;
        for (x = 0; x < al_proto_table[u16].map_size; x++) {
            if (al_proto_table[u16].map[x] == NULL)
                continue;

            printf("al_proto_table[%u].map[%u]->parser_id: %u\n", u16, x, al_proto_table[u16].map[x]->parser_id);
        }
    }
}

