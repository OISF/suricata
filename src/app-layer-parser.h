#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

/** Mapping between local parser id's (e.g. HTTP_FIELD_REQUEST_URI) and
  * the dynamically assigned (at registration) global parser id. */
typedef struct AppLayerLocalMap_ {
    uint16_t parser_id;
} AppLayerLocalMap;

/** \brief Mapping between ALPROTO_* and L7Parsers
 *
 * Map the proto to the parsers for the to_client and to_server directions.
 */
typedef struct AppLayerProto_ {
    char *name; /**< name of the registered proto */

    uint16_t to_server;
    uint16_t to_client;
    uint8_t storage_id;

    AppLayerLocalMap **map;
    uint16_t map_size;

    void *(*StateAlloc)(void);
    void (*StateFree)(void *);
} AppLayerProto;

/** flags for the result elmts */
#define ALP_RESULT_ELMT_ALLOC 0x01

/** \brief Result elements for the parser */
typedef struct AppLayerParserResultElmt_ {
    uint16_t flags; /* flags. E.g. local alloc */
    uint16_t name_idx; /* idx for names like "http.request_line.uri" */

    uint8_t  *data_ptr; /* point to the position in the "input" data
                          * or ptr to new mem if local alloc flag set */
    uint32_t data_len; /* length of the data from the ptr */
    struct AppLayerParserResultElmt_ *next;
} AppLayerParserResultElmt;

/** \brief List head for parser result elmts */
typedef struct AppLayerParserResult_ {
    AppLayerParserResultElmt *head;
    AppLayerParserResultElmt *tail;
    uint32_t cnt;
} AppLayerParserResult;

#define APP_LAYER_PARSER_USE            0x01
#define APP_LAYER_PARSER_EOF            0x02
#define APP_LAYER_PARSER_DONE           0x04  /**< parser is done, ignore more
                                                   msgs */
#define APP_LAYER_PARSER_NO_INSPECTION  0x08 /**< Flag to indicate no more
                                                  packets payload inspection */
#define APP_LAYER_PARSER_NO_REASSEMBLY  0x10 /**< Flag to indicate no more
                                                  packets reassembly for this
                                                  session */

typedef struct AppLayerParserState_ {
    uint8_t flags;

    uint16_t cur_parser; /* idx of currently active parser */
    uint8_t *store;
    uint32_t store_len;
    uint16_t parse_field;
} AppLayerParserState;

typedef struct AppLayerParserStateStore_ {
    AppLayerParserState to_client;
    AppLayerParserState to_server;
} AppLayerParserStateStore;

typedef struct AppLayerParserTableElement_ {
    char *name;
    uint16_t proto;
    uint16_t parser_local_id; /** local id of the parser in the parser itself. */
    uint8_t flags;
    int (*AppLayerParser)(Flow *f, void *protocol_state, AppLayerParserState
                          *parser_state, uint8_t *input, uint32_t input_len,
                          AppLayerParserResult *output);
    uint16_t max_outputs; /* rationele is that if we know the max outputs of all
                             parsers, we can statically define our output array
                             to be a certain size */
} AppLayerParserTableElement;

/* prototypes */
void AppLayerParsersInitPostProcess(void);
void RegisterAppLayerParsers(void);

int AppLayerRegisterProto(char *name, uint8_t proto, uint8_t flags,
                          int (*AppLayerParser)(Flow *f, void *protocol_state,
                          AppLayerParserState *parser_state, uint8_t *input,
                          uint32_t input_len, AppLayerParserResult *output));
int AppLayerRegisterParser(char *name, uint16_t proto, uint16_t parser_id,
                           int (*AppLayerParser)(Flow *f, void *protocol_state,
                           AppLayerParserState *parser_state, uint8_t *input,
                           uint32_t input_len, AppLayerParserResult *output),
                           char *dependency);
void AppLayerRegisterStateFuncs(uint16_t proto, void *(*StateAlloc)(void),
                                void (*StateFree)(void *));

int AppLayerParse(Flow *, uint8_t proto, uint8_t flags, uint8_t *input,
                  uint32_t input_len, char);

int AlpParseFieldBySize(AppLayerParserResult *, AppLayerParserState *, uint16_t,
                        uint32_t, uint8_t *, uint32_t, uint32_t *);
int AlpParseFieldByEOF(AppLayerParserResult *, AppLayerParserState *, uint16_t,
                       uint8_t *, uint32_t);
int AlpParseFieldByDelimiter(AppLayerParserResult *, AppLayerParserState *,
                             uint16_t, const uint8_t *, uint8_t, uint8_t *,
                             uint32_t, uint32_t *);
uint16_t AlpGetStateIdx(uint16_t);

uint16_t AppLayerGetProtoByName(const char *);

void AppLayerParserRegisterTests(void);

#include "stream-tcp-private.h"
void AppLayerParserCleanupState(TcpSession *);

#endif /* __APP_LAYER_PARSER_H__ */

