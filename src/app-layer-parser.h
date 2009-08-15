#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

/** Mapping between local parser id's (e.g. HTTP_FIELD_REQUEST_URI) and
  * the dynamically assigned (at registration) global parser id. */
typedef struct AppLayerLocalMap_ {
    u_int16_t parser_id;
} AppLayerLocalMap;

/** \brief Mapping between ALPROTO_* and L7Parsers
 *
 * Map the proto to the parsers for the to_client and to_server directions.
 */
typedef struct AppLayerProto_ {
    u_int16_t to_server;
    u_int16_t to_client;
    u_int8_t storage_id;

    AppLayerLocalMap **map;
    u_int16_t map_size;

    void *(*StateAlloc)(void);
    void (*StateFree)(void *);
} AppLayerProto;

/** flags for the result elmts */
#define ALP_RESULT_ELMT_ALLOC 0x01

/** \brief Result elements for the parser */
typedef struct AppLayerParserResultElmt_ {
    u_int16_t flags; /* flags. E.g. local alloc */
    u_int16_t name_idx; /* idx for names like "http.request_line.uri" */

    u_int8_t  *data_ptr; /* point to the position in the "input" data
                          * or ptr to new mem if local alloc flag set */
    u_int32_t data_len; /* length of the data from the ptr */
    struct AppLayerParserResultElmt_ *next;
} AppLayerParserResultElmt;

/** \brief List head for parser result elmts */
typedef struct AppLayerParserResult_ {
    AppLayerParserResultElmt *head;
    AppLayerParserResultElmt *tail;
    u_int32_t cnt;
} AppLayerParserResult;

#define APP_LAYER_PARSER_USE   0x01
#define APP_LAYER_PARSER_EOF   0x02

typedef struct AppLayerParserState_ {
    u_int8_t flags;

    u_int16_t cur_parser; /* idx of currently active parser */
    u_int8_t *store;
    u_int32_t store_len;
    u_int16_t parse_field;
} AppLayerParserState;

typedef struct AppLayerParserStateStore_ {
    AppLayerParserState to_client;
    AppLayerParserState to_server;
} AppLayerParserStateStore;

typedef struct AppLayerParserTableElement_ {
    char *name;
    u_int16_t proto;
    u_int16_t parser_local_id; /** local id of the parser in the parser itself. */
    u_int8_t flags;
    int (*AppLayerParser)(void *protocol_state, AppLayerParserState *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResult *output);
    u_int16_t max_outputs; /* rationele is that if we know the max outputs of all parsers, we
                              can statically define our output array to be a certain size */
} AppLayerParserTableElement;

/* prototypes */
void AppLayerParsersInitPostProcess(void);
void RegisterAppLayerParsers(void);

int AppLayerRegisterProto(char *name, u_int8_t proto, u_int8_t flags, int (*AppLayerParser)(void *protocol_state, AppLayerParserState *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResult *output));
int AppLayerRegisterParser(char *name, u_int16_t proto, u_int16_t parser_id, int (*AppLayerParser)(void *protocol_state, AppLayerParserState *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResult *output), char *dependency);
void AppLayerRegisterStateFuncs(u_int16_t proto, void *(*StateAlloc)(void), void (*StateFree)(void *));

int AppLayerParse(Flow *f, u_int8_t proto, u_int8_t flags, u_int8_t *input, u_int32_t input_len);

int AlpParseFieldByEOF(AppLayerParserResult *, AppLayerParserState *, u_int16_t, u_int8_t *, u_int32_t);
int AlpParseFieldByDelimiter(AppLayerParserResult *, AppLayerParserState *, u_int16_t, const u_int8_t *, u_int8_t, u_int8_t *, u_int32_t, u_int32_t *);
u_int16_t AlpGetStateIdx(u_int16_t);

#endif /* __APP_LAYER_PARSER_H__ */

