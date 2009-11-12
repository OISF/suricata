/* Copyright (c) 2009 Victor Julien */
/** \todo support for the newly find TLS handshake GAP vulnerbility */
#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-tls.h"

#include "conf.h"

#include "util-binsearch.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-private.h"

#define TLS_CHANGE_CIPHER_SPEC  0x14   /*TLS change cipher spec content type*/
#define TLS_ALERT_PROTOCOL      0x15   /*TLS alert protocol content type */
#define TLS_HANDSHAKE_PROTOCOL  0x16   /*TLS hansdshake protocol content type*/
#define TLS_APPLICATION_PROTOCOL  0x17 /*TLS application protocol content type*/

/**
 * \brief Function to store the parsed TLS content type received from the client
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received content type value
 *  \param  input_len   Length in bytes of the received content type value
 *  \param  output      Pointer to the list of parsed elements
 */
static int TLSParseClientContentType(void *tls_state, AppLayerParserState
                                     *pstate, uint8_t *input, uint32_t input_len,
                                     AppLayerParserResult *output)
{
    TlsState *state = (TlsState *)tls_state;

    if (input == NULL)
        return 0;

    if (input_len != 1) {
        return 0;
    }

    /* check if we received the correct content type */
    switch (*input) {
        case TLS_CHANGE_CIPHER_SPEC:
        case TLS_ALERT_PROTOCOL:
        case TLS_HANDSHAKE_PROTOCOL:
        case TLS_APPLICATION_PROTOCOL:
            break;
        default:
            return 0;
    }

    state->client_content_type = *input;

    SCLogDebug("content_type %02"PRIx8"", state->client_content_type);

    /* The content type 23 signifies the encryption application protocol has
       been started and check if we have received the change_cipher_spec before
       accepting this packet and setting up the flag */
    if (state->client_content_type == TLS_APPLICATION_PROTOCOL &&
            (state->flags & TLS_FLAG_CLIENT_CHANGE_CIPHER_SPEC) &&
            (state->flags & TLS_FLAG_SERVER_CHANGE_CIPHER_SPEC))
    {
        pstate->flags |= APP_LAYER_PARSER_DONE;
        pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
        if (tls.no_reassemble == 1)
            pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
    }

    /* The content type 0x14 signifies the change_cipher_spec message */
    if (state->client_content_type == TLS_CHANGE_CIPHER_SPEC)
        state->flags |= TLS_FLAG_CLIENT_CHANGE_CIPHER_SPEC;

    return 1;
}

/**
 * \brief   Function to store the parsed TLS content version received from the
 *          client
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received TLS version value
 *  \param  input_len   Length in bytes of the received version value
 *  \param  output      Pointer to the list of parsed elements
 */
static int TLSParseClientVersion(void *tls_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output)
{
    TlsState *state = (TlsState *)tls_state;

    if (input_len != 2)
        return 0;

    /** \todo there must be an easier way to get from uint8_t * to a uint16_t */
    struct u16conv_ {
        uint16_t u;
    } *u16conv;
    u16conv = (struct u16conv_ *)input;

    state->client_version = ntohs(u16conv->u);

    SCLogDebug("version %04"PRIx16"", state->client_version);
    return 1;
}

/**
 * \brief Function to parse the TLS field in packet received from the client
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int TLSParseClientRecord(void *tls_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCLogDebug("tls_state %p, pstate %p, input %p,input_len %" PRIu32 "",
            tls_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    uint16_t max_fields = 3;
    int16_t u = 0;
    uint32_t offset = 0;
    uint32_t record_length = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u) {
            case 0: /* TLS CONTENT TYPE */
            {
                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_CLIENT_CONTENT_TYPE,
                                            /* single byte field */1, input,
                                            input_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 0;
                    return 0;
                }
                break;
            }
            case 1: /* TLS VERSION */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_CLIENT_VERSION,
                                            /* 2 byte field */2, data, data_len,
                                            &offset);
                if (r == 0) {
                    pstate->parse_field = 1;
                    return 0;
                }
                break;
            }
            case 2: /* TLS Record Message Length */
            {

                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;


                int r = AlpParseFieldBySize(output, pstate, TLS_FIELD_LENGTH,
                                            /* 2 byte field */2, data, data_len,
                                            &offset);
                if (r == 0) {
                    pstate->parse_field = 2;
                    return 0;
                }

                struct u16conv_ {
                    uint16_t u;
                } *u16conv;

                u16conv = (struct u16conv_ *) output->tail->data_ptr;
                record_length += offset + ntohs(u16conv->u);

                /* Check if parsed the whole segment or there are some more
                   TLS record options in the packet still left to be parsed */
                if (input_len > record_length) {
                    u = -1;
                    input += offset + ntohs(u16conv->u);
                    offset = 0;
                }
                break;
            }
        }

    }

    pstate->parse_field = 0;
    return 1;
}

/**
 * \brief Function to parse the TLS field in packet received from the server
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int TLSParseServerRecord(void *tls_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    uint16_t max_fields = 3;
    int16_t u = 0;
    uint32_t offset = 0;
    uint32_t record_length = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u) {
            case 0: /* TLS CONTENT TYPE */
            {
                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_SERVER_CONTENT_TYPE,
                                            /* single byte field */1, input,
                                            input_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 0;
                    return 0;
                }
                break;
            }
            case 1: /* TLS VERSION */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_SERVER_VERSION,/* 2 byte
                                           *field */2, data, data_len, &offset);
                if (r == 0) {
                    pstate->parse_field = 1;
                    return 0;
                }
                break;
            }
            case 2: /* TLS Record Message Length */
            {

                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;


                int r = AlpParseFieldBySize(output, pstate, TLS_FIELD_LENGTH,
                                            /* 2 byte field */2, data, data_len,
                                            &offset);

                if (r == 0) {
                    pstate->parse_field = 2;
                    return 0;
                }

                struct u16conv_ {
                    uint16_t u;
                } *u16conv;

                u16conv = (struct u16conv_ *) output->tail->data_ptr;
                record_length += offset + ntohs(u16conv->u);

                /* Check if parsed the whole segment or there are some more
                   TLS record options in the packet still left to be parsed */
                if (input_len > record_length) {
                    u = -1;
                    input += offset + ntohs(u16conv->u);
                    offset = 0;
                }
                break;
            }
        }

    }

    pstate->parse_field = 0;
    return 1;
}

/**
 * \brief   Function to store the parsed TLS content version received from the
 *          server
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received TLS version value
 *  \param  input_len   Length in bytes of the received version value
 *  \param  output      Pointer to the list of parsed elements
 */
static int TLSParseServerVersion(void *tls_state, AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 AppLayerParserResult *output)
{
    TlsState *state = (TlsState *)tls_state;

    if (input_len != 2)
        return 0;

    /** \todo there must be an easier way to get from uint8_t * to a uint16_t */
    struct u16conv_ {
        uint16_t u;
    } *u16conv;
    u16conv = (struct u16conv_ *)input;

    state->server_version = ntohs(u16conv->u);

    SCLogDebug("version %04"PRIx16"", state->server_version);
    return 1;
}

/**
 * \brief Function to store the parsed TLS content type received from the server
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received content type value
 *  \param  input_len   Length in bytes of the received content type value
 *  \param  output      Pointer to the list of parsed elements
 */
static int TLSParseServerContentType(void *tls_state, AppLayerParserState *pstate,
                                     uint8_t *input, uint32_t input_len,
                                     AppLayerParserResult *output)
{
    TlsState *state = (TlsState *)tls_state;

    if (input == NULL)
        return 0;

    if (input_len != 1) {
        return 0;
    }

    /* check if we received the correct content type */
    switch (*input) {
        case TLS_CHANGE_CIPHER_SPEC:
        case TLS_ALERT_PROTOCOL:
        case TLS_HANDSHAKE_PROTOCOL:
        case TLS_APPLICATION_PROTOCOL:
            break;
        default:
            return 0;
    }

    state->server_content_type = *input;

    SCLogDebug("content_type %02"PRIx8"", state->server_content_type);

    /* The content type 20 signifies the chage cipher spec message has been
       received and now onwards messages will be encrypted and authenticated */
    if (state->server_content_type == TLS_CHANGE_CIPHER_SPEC) {
        pstate->flags |= APP_LAYER_PARSER_DONE;
        state->flags |= TLS_FLAG_SERVER_CHANGE_CIPHER_SPEC;
    }

    /* The content type 23 signifies the encryption application protocol has
       been started and check if we have received the change_cipher_spec before
       accepting this packet and setting up the flag */
    if (state->client_content_type == TLS_APPLICATION_PROTOCOL &&
            (state->flags & TLS_FLAG_CLIENT_CHANGE_CIPHER_SPEC) &&
            (state->flags & TLS_FLAG_SERVER_CHANGE_CIPHER_SPEC))
    {
        pstate->flags |= APP_LAYER_PARSER_DONE;
        pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
        if (tls.no_reassemble == 1)
            pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
    }

    return 1;
}

/** \brief Function to allocates the TLS state memory
 */
static void *TLSStateAlloc(void)
{
    void *s = malloc(sizeof(TlsState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(TlsState));
    return s;
}

/** \brief Function to free the TLS state memory
 */
static void TLSStateFree(void *s)
{
    free(s);
}

/** \brief Function to register the TLS protocol parsers and other functions
 */
void RegisterTLSParsers(void)
{
    AppLayerRegisterProto("tls", ALPROTO_TLS, STREAM_TOSERVER,
                          TLSParseClientRecord);
    AppLayerRegisterParser("tls.client.content_type", ALPROTO_TLS,
                            TLS_FIELD_CLIENT_CONTENT_TYPE,
                            TLSParseClientContentType, "tls");
    AppLayerRegisterParser("tls.client.version", ALPROTO_TLS,
                            TLS_FIELD_CLIENT_VERSION, TLSParseClientVersion,
                            "tls");

    AppLayerRegisterProto("tls", ALPROTO_TLS, STREAM_TOCLIENT,
                            TLSParseServerRecord);
    AppLayerRegisterParser("tls.server.content_type", ALPROTO_TLS,
                            TLS_FIELD_SERVER_CONTENT_TYPE,
                            TLSParseServerContentType, "tls");
    AppLayerRegisterParser("tls.server.version", ALPROTO_TLS,
                            TLS_FIELD_SERVER_VERSION, TLSParseServerVersion,
                            "tls");

    AppLayerRegisterStateFuncs(ALPROTO_TLS, TLSStateAlloc, TLSStateFree);

    /* Get the value of no reassembly option from the config file */
    if(ConfGetBool("tls.no_reassemble", &tls.no_reassemble) != 1)
        tls.no_reassemble = 1;
}

/* UNITTESTS */
#ifdef UNITTESTS

extern uint16_t AppLayerParserGetStorageId (void);

/** \test Send a get request in one chunk. */
static int TLSParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER|STREAM_EOF, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    return result;
}

/** \test Send a get request in two chunks. */
static int TLSParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03, 0x01 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1,
                          FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2,FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    return result;
}

/** \test Send a get request in three chunks. */
static int TLSParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1,
                          FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2,FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3,FALSE);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    return result;
}

/** \test Send a get request in three chunks + more data. */
static int TLSParserTest04(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf1[] = { 0x16 };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    uint8_t tlsbuf2[] = { 0x03 };
    uint32_t tlslen2 = sizeof(tlsbuf2);
    uint8_t tlsbuf3[] = { 0x01 };
    uint32_t tlslen3 = sizeof(tlsbuf3);
    uint8_t tlsbuf4[] = { 0x01, 0x00, 0x00, 0xad, 0x03, 0x01 };
    uint32_t tlslen4 = sizeof(tlsbuf4);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1,
                          FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2,FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3,FALSE);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf4, tlslen4,FALSE);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    return result;
}

/** \test   Test the setting up of no reassembly and no payload inspection flag
 *          after detection of the TLS handshake completion */
static int TLSParserTest05(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01, 0x00, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x17) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x17,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }

    uint16_t app_layer_sid = AppLayerParserGetStorageId();
    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    ssn.aldata[app_layer_sid];
    AppLayerParserState *parser_state = &parser_state_store->to_server;

    if (!(parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) &&
            !(ssn.flags & STREAMTCP_FLAG_NOCLIENT_REASSEMBLY) &&
            !(ssn.flags & STREAMTCP_FLAG_NOSERVER_REASSEMBLY)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

end:
    return result;
}

/** \test   Test the setting up of no reassembly and no payload inspection flag
 *          after detection of the valid TLS handshake completion, the rouge
 *          0x17 packet will not be considered in the detection process */
static int TLSParserTest06(void) {
    int result = 1;
    Flow f;
    uint8_t tlsbuf[] = { 0x16, 0x03, 0x01, 0x00, 0x01 };
    uint32_t tlslen = sizeof(tlsbuf);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    TlsState *tls_state = ssn.aldata[AlpGetStateIdx(ALPROTO_TLS)];
    if (tls_state == NULL) {
        printf("no tls state: ");
        result = 0;
        goto end;
    }

    if (tls_state->client_content_type != 0x17) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x17,
                tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->client_version);
        result = 0;
        goto end;
    }

    uint16_t app_layer_sid = AppLayerParserGetStorageId();
    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    ssn.aldata[app_layer_sid];
    AppLayerParserState *parser_state = &parser_state_store->to_server;

    if ((parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) ||
            (ssn.flags & STREAMTCP_FLAG_NOCLIENT_REASSEMBLY) ||
            (ssn.flags & STREAMTCP_FLAG_NOSERVER_REASSEMBLY)) {
        printf("The flags should not be set\n");
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf,
                          tlslen, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    if (!(parser_state->flags & APP_LAYER_PARSER_NO_INSPECTION) &&
            !(ssn.flags & STREAMTCP_FLAG_NOCLIENT_REASSEMBLY) &&
            !(ssn.flags & STREAMTCP_FLAG_NOSERVER_REASSEMBLY)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION)) {
        printf("The flags should be set\n");
        result = 0;
        goto end;
    }

end:
    return result;
}

#endif /* UNITTESTS */

void TLSParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("TLSParserTest01", TLSParserTest01, 1);
    UtRegisterTest("TLSParserTest02", TLSParserTest02, 1);
    UtRegisterTest("TLSParserTest03", TLSParserTest03, 1);
    UtRegisterTest("TLSParserTest04", TLSParserTest04, 1);
    UtRegisterTest("TLSParserTest05", TLSParserTest05, 1);
    UtRegisterTest("TLSParserTest06", TLSParserTest06, 1);
#endif /* UNITTESTS */
}
