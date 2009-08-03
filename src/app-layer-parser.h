#ifndef __APP_LAYER_PARSER_H__
#define __APP_LAYER_PARSER_H__

/** \brief Mapping between ALPROTO_* and L7Parsers
 *
 * Map the proto to the parsers for the to_client and to_server directions.
 */
typedef struct AppLayerProto_ {
    u_int16_t to_server;
    u_int16_t to_client;
    u_int8_t storage_id;
} AppLayerProto;

typedef struct AppLayerParserResultElement_ {
    u_int16_t flags; /* flags. E.g. local alloc */
    u_int16_t name_idx; /* idx for names like "http.request_line.uri" */

    u_int8_t  *data_ptr; /* point to the position in the "input" data
                          * or ptr to new mem if local alloc flag set */
    u_int32_t data_len; /* length of the data from the ptr */
} AppLayerParserResultElement;

typedef struct AppLayerParserTableElement_ {
    char *name;
    u_int8_t flags;
    int (*AppLayerParser)(void *protocol_state, void *parser_state, u_int8_t *input, u_int32_t input_len, AppLayerParserResultElement **output, u_int16_t *output_num);
    u_int16_t max_outputs; /* rationele is that if we know the max outputs of all parsers, we
                              can statically define our output array to be a certain size */
} AppLayerParserTableElement;

#define APP_LAYER_PARSER_DONE  0x01 /** the last parser was done */
#define APP_LAYER_PARSER_MAYBE 0x02 /** we're not sure if the last parser is done */
#define APP_LAYER_PARSER_CONT  0x04 /** the last parser is still working */

typedef struct AppLayerParserState_ {
    u_int8_t flags;
    u_int16_t cur_parser; /* idx of currently active parser */

    /** \todo this needs to become dynamic */
    u_int8_t buf[1024];
    u_int8_t buflen;
} AppLayerParserState;

#endif /* __APP_LAYER_PARSER_H__ */

