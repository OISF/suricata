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
int AppLayerRegisterParser(char *name, int (*AppLayerParser)(void *protocol_state, void *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResultElement **output, u_int16_t *output_num), char *dependency) {

    al_max_parsers++;

    al_parser_table[al_max_parsers].name = name;
    al_parser_table[al_max_parsers].AppLayerParser = AppLayerParser;
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
        printf("L7Parse: using parser %u we stored before\n", parser_state->cur_parser);
        parser_idx = parser_state->cur_parser;
    }

    if (parser_idx == 0) {
        printf("L7Parse: no parser for protocol %u\n", proto);
        return 0;
    }

    if (parser_state == NULL) {
        parser_state = AppLayerParserStateAlloc();
        if (parser_state != NULL) {
            parser_state->cur_parser = parser_idx;

            ssn->l7data[app_layer_sid] = (void *)parser_state;
        }
    }

    int r = al_parser_table[parser_idx].AppLayerParser(app_layer_state, parser_state, input, input_len, NULL, NULL);
    if (r < 0)
        return -1;

    return 0;
}

void RegisterAppLayerParsers(void) {
    /** \todo move to general init function */
    memset(&al_proto_table, 0, sizeof(al_proto_table));
    memset(&al_parser_table, 0, sizeof(al_parser_table));

    app_layer_sid = StreamL7RegisterModule();
}

