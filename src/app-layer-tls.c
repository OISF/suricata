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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * App-layer detection of TLS
 *
 * \todo support for the newly find TLS handshake GAP vulnerbility
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-tls.h"

#include "conf.h"

#include "app-layer-tls.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-private.h"

#include "util-byte.h"

#define TLS_CHANGE_CIPHER_SPEC      0x14   /**< TLS change cipher spec content type */
#define TLS_ALERT_PROTOCOL          0x15   /**< TLS alert protocol content type */
#define TLS_HANDSHAKE_PROTOCOL      0x16   /**< TLS hansdshake protocol content type */
#define TLS_APPLICATION_PROTOCOL    0x17   /**< TLS application protocol content type */

/**
 * \brief Function to store the parsed TLS content type received from the client
 *
 *  \param  tls_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received content type value
 *  \param  input_len   Length in bytes of the received content type value
 *  \param  output      Pointer to the list of parsed elements
 */
static int TLSParseClientContentType(Flow *f, void *tls_state, AppLayerParserState
                                     *pstate, uint8_t *input, uint32_t input_len,
                                     AppLayerParserResult *output)
{
    SCEnter();

    TlsState *state = (TlsState *)tls_state;

    if (input == NULL)
        SCReturnInt(-1);

    if (input_len != 1) {
        SCReturnInt(-1);
    }

    /* check if we received the correct content type */
    switch (*input) {
        case TLS_CHANGE_CIPHER_SPEC:
        case TLS_ALERT_PROTOCOL:
        case TLS_HANDSHAKE_PROTOCOL:
        case TLS_APPLICATION_PROTOCOL:
            break;
        default:
            SCReturnInt(0);
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

    SCReturnInt(0);
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
static int TLSParseClientVersion(Flow *f, void *tls_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output)
{
    SCEnter();

    TlsState *state = (TlsState *)tls_state;

    if (input_len != 2)
        SCReturnInt(-1);

    /** \todo there must be an easier way to get from uint8_t * to a uint16_t */
    struct u16conv_ {
        uint16_t u;
    } *u16conv;
    u16conv = (struct u16conv_ *)input;

    switch (ntohs(u16conv->u)) {
        case 0x0301:
            state->client_version = TLS_VERSION_10;
            break;
        case 0x0302:
            state->client_version = TLS_VERSION_11;
            break;
        case 0x0303:
            state->client_version = TLS_VERSION_12;
            break;
    }

    SCLogDebug("version %04"PRIx16"", state->client_version);
    SCReturnInt(0);
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
static int TLSParseClientRecord(Flow *f, void *tls_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();

    SCLogDebug("tls_state %p, pstate %p, input %p,input_len %" PRIu32 "",
            tls_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    uint16_t max_fields = 3;
    int16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        SCReturnInt(-1);

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u % 3) {
            case 0: /* TLS CONTENT TYPE */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_CLIENT_CONTENT_TYPE,
                                            /* single byte field */1, data,
                                            data_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 0;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
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
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
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
                SCLogDebug("AlpParseFieldBySize returned r %d, offset %"PRIu32""
                           , r, offset);
                if (r == 0) {
                    pstate->parse_field = 2;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                /* Parsing of the record is done. Since we may have more than
                 * one record, we check here if we still have data left *after*
                 * this record. In that case setup the parser to parse that
                 * record as well. */
                uint16_t record_len;
                int ret = ByteExtractUint16(&record_len, BYTE_BIG_ENDIAN,
                        output->tail->data_len, output->tail->data_ptr);
                if (ret != 2) {
                    SCReturnInt(-1);
                }

                /* calulate the point up to where the current record
                 * is in the data */
                uint32_t record_offset = (offset + record_len);

                SCLogDebug("record offset %"PRIu32" (offset %"PRIu32", record_len"
                           " %"PRIu16")", record_offset, offset, record_len);

                /* if our input buffer is bigger than the data up to and
                 * including the current record, we instruct the parser to
                 * expect another record of 3 fields */
                if (input_len <= record_offset)
                    break;

                max_fields += 3;
                offset += record_len;
                break;
            }
        }

    }

    pstate->parse_field = 0;
    SCReturnInt(1);
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
static int TLSParseServerRecord(Flow *f, void *tls_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();

    SCLogDebug("tls_state %p, pstate %p, input %p,input_len %" PRIu32 "",
            tls_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    uint16_t max_fields = 3;
    int16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        SCReturnInt(-1);

    for (u = pstate->parse_field; u < max_fields; u++) {
        SCLogDebug("u %" PRIu32 "", u);

        switch(u % 3) {
            case 0: /* TLS CONTENT TYPE */
            {
                uint8_t *data = input + offset;
                uint32_t data_len = input_len - offset;

                int r = AlpParseFieldBySize(output, pstate,
                                            TLS_FIELD_SERVER_CONTENT_TYPE,
                                            /* single byte field */1, data,
                                            data_len, &offset);
                SCLogDebug("r = %" PRId32 "", r);

                if (r == 0) {
                    pstate->parse_field = 0;
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
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
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
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
                    SCReturnInt(0);
                } else if (r == -1) {
                    SCLogError(SC_ERR_ALPARSER, "AlpParseFieldBySize failed, "
                               "r %d", r);
                    SCReturnInt(-1);
                }

                /* Parsing of the record is done. Since we may have more than
                 * one record, we check here if we still have data left *after*
                 * this record. In that case setup the parser to parse that
                 * record as well. */
                uint16_t record_len;
                int ret = ByteExtractUint16(&record_len, BYTE_BIG_ENDIAN,
                        output->tail->data_len, output->tail->data_ptr);
                if (ret != 2) {
                    SCReturnInt(-1);
                }

                /* calulate the point up to where the current record
                 * is in the data */
                uint32_t record_offset = (offset + record_len);

                SCLogDebug("record offset %"PRIu32" (offset %"PRIu32", record_len"
                           " %"PRIu16")", record_offset, offset, record_len);

                /* if our input buffer is bigger than the data up to and
                 * including the current record, we instruct the parser to
                 * expect another record of 3 fields */
                if (input_len <= record_offset)
                    break;

                max_fields += 3;
                offset += record_len;
                break;
            }
        }

    }

    pstate->parse_field = 0;
    SCReturnInt(1);
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
static int TLSParseServerVersion(Flow *f, void *tls_state, AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 AppLayerParserResult *output)
{
    SCEnter();
    TlsState *state = (TlsState *)tls_state;

    if (input_len != 2)
        SCReturnInt(-1);

    /** \todo there must be an easier way to get from uint8_t * to a uint16_t */
    struct u16conv_ {
        uint16_t u;
    } *u16conv;
    u16conv = (struct u16conv_ *)input;

    state->server_version = ntohs(u16conv->u);

    SCLogDebug("version %04"PRIx16"", state->server_version);
    SCReturnInt(0);
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
static int TLSParseServerContentType(Flow *f, void *tls_state, AppLayerParserState *pstate,
                                     uint8_t *input, uint32_t input_len,
                                     AppLayerParserResult *output)
{
    SCEnter();
    TlsState *state = (TlsState *)tls_state;

    if (input == NULL)
        SCReturnInt(-1);

    if (input_len != 1) {
        SCReturnInt(-1);
    }

    /* check if we received the correct content type */
    switch (*input) {
        case TLS_CHANGE_CIPHER_SPEC:
        case TLS_ALERT_PROTOCOL:
        case TLS_HANDSHAKE_PROTOCOL:
        case TLS_APPLICATION_PROTOCOL:
            break;
        default:
            SCReturnInt(0);
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

    SCReturnInt(0);
}

/** \brief Function to allocates the TLS state memory
 */
static void *TLSStateAlloc(void)
{
    void *s = SCMalloc(sizeof(TlsState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(TlsState));
    return s;
}

/** \brief Function to free the TLS state memory
 */
static void TLSStateFree(void *s)
{
    SCFree(s);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER|STREAM_EOF, tlsbuf, tlslen);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf4, tlslen4);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
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
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x14;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
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

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf, tlslen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    tlsbuf[0] = 0x17;

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf, tlslen);
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
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test multimsg test */
static int TLSParserMultimsgTest01(void) {
    int result = 1;
    Flow f;
    /* 3 msgs */
    uint8_t tlsbuf1[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x82, 0x00, 0x80, 0xd3, 0x6f, 0x1f, 0x63, 0x82,
        0x8d, 0x75, 0x77, 0x8c, 0x91, 0xbc, 0xa1, 0x3d,
        0xbb, 0xe1, 0xb5, 0xd3, 0x31, 0x92, 0x59, 0x2b,
        0x2c, 0x43, 0x96, 0xa3, 0xaa, 0x23, 0x92, 0xd0,
        0x91, 0x2a, 0x5e, 0x10, 0x5b, 0xc8, 0xc1, 0xe2,
        0xd3, 0x5c, 0x8b, 0x8c, 0x91, 0x9e, 0xc2, 0xf2,
        0x9c, 0x3c, 0x4f, 0x37, 0x1e, 0x20, 0x5e, 0x33,
        0xd5, 0xf0, 0xd6, 0xaf, 0x89, 0xf5, 0xcc, 0xb2,
        0xcf, 0xc1, 0x60, 0x3a, 0x46, 0xd5, 0x4e, 0x2a,
        0xb6, 0x6a, 0xb9, 0xfc, 0x32, 0x8b, 0xe0, 0x6e,
        0xa0, 0xed, 0x25, 0xa0, 0xa4, 0x82, 0x81, 0x73,
        0x90, 0xbf, 0xb5, 0xde, 0xeb, 0x51, 0x8d, 0xde,
        0x5b, 0x6f, 0x94, 0xee, 0xba, 0xe5, 0x69, 0xfa,
        0x1a, 0x80, 0x30, 0x54, 0xeb, 0x12, 0x01, 0xb9,
        0xfe, 0xbf, 0x82, 0x95, 0x01, 0x7b, 0xb0, 0x97,
        0x14, 0xc2, 0x06, 0x3c, 0x69, 0xfb, 0x1c, 0x66,
        0x47, 0x17, 0xd9, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x30, 0xf6, 0xbc,
        0x0d, 0x6f, 0xe8, 0xbb, 0xaa, 0xbf, 0x14, 0xeb,
        0x7b, 0xcc, 0x6c, 0x28, 0xb0, 0xfc, 0xa6, 0x01,
        0x2a, 0x97, 0x96, 0x17, 0x5e, 0xe8, 0xb4, 0x4e,
        0x78, 0xc9, 0x04, 0x65, 0x53, 0xb6, 0x93, 0x3d,
        0xeb, 0x44, 0xee, 0x86, 0xf9, 0x80, 0x49, 0x45,
        0x21, 0x34, 0xd1, 0xee, 0xc8, 0x9c
    };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1);
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

    if (tls_state->client_version != TLS_VERSION_10) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                TLS_VERSION_10, tls_state->client_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test multimsg test server */
static int TLSParserMultimsgTest02(void) {
    int result = 1;
    Flow f;
    /* 3 msgs */
    uint8_t tlsbuf1[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x82, 0x00, 0x80, 0xd3, 0x6f, 0x1f, 0x63, 0x82,
        0x8d, 0x75, 0x77, 0x8c, 0x91, 0xbc, 0xa1, 0x3d,
        0xbb, 0xe1, 0xb5, 0xd3, 0x31, 0x92, 0x59, 0x2b,
        0x2c, 0x43, 0x96, 0xa3, 0xaa, 0x23, 0x92, 0xd0,
        0x91, 0x2a, 0x5e, 0x10, 0x5b, 0xc8, 0xc1, 0xe2,
        0xd3, 0x5c, 0x8b, 0x8c, 0x91, 0x9e, 0xc2, 0xf2,
        0x9c, 0x3c, 0x4f, 0x37, 0x1e, 0x20, 0x5e, 0x33,
        0xd5, 0xf0, 0xd6, 0xaf, 0x89, 0xf5, 0xcc, 0xb2,
        0xcf, 0xc1, 0x60, 0x3a, 0x46, 0xd5, 0x4e, 0x2a,
        0xb6, 0x6a, 0xb9, 0xfc, 0x32, 0x8b, 0xe0, 0x6e,
        0xa0, 0xed, 0x25, 0xa0, 0xa4, 0x82, 0x81, 0x73,
        0x90, 0xbf, 0xb5, 0xde, 0xeb, 0x51, 0x8d, 0xde,
        0x5b, 0x6f, 0x94, 0xee, 0xba, 0xe5, 0x69, 0xfa,
        0x1a, 0x80, 0x30, 0x54, 0xeb, 0x12, 0x01, 0xb9,
        0xfe, 0xbf, 0x82, 0x95, 0x01, 0x7b, 0xb0, 0x97,
        0x14, 0xc2, 0x06, 0x3c, 0x69, 0xfb, 0x1c, 0x66,
        0x47, 0x17, 0xd9, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x30, 0xf6, 0xbc,
        0x0d, 0x6f, 0xe8, 0xbb, 0xaa, 0xbf, 0x14, 0xeb,
        0x7b, 0xcc, 0x6c, 0x28, 0xb0, 0xfc, 0xa6, 0x01,
        0x2a, 0x97, 0x96, 0x17, 0x5e, 0xe8, 0xb4, 0x4e,
        0x78, 0xc9, 0x04, 0x65, 0x53, 0xb6, 0x93, 0x3d,
        0xeb, 0x44, 0xee, 0x86, 0xf9, 0x80, 0x49, 0x45,
        0x21, 0x34, 0xd1, 0xee, 0xc8, 0x9c
    };
    uint32_t tlslen1 = sizeof(tlsbuf1);
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOCLIENT, tlsbuf1, tlslen1);
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

    if (tls_state->server_content_type != 0x16) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16,
                tls_state->server_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->server_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301,
                tls_state->server_version);
        result = 0;
        goto end;
    }
end:
    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
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

    UtRegisterTest("TLSParserMultimsgTest01", TLSParserMultimsgTest01, 1);
    UtRegisterTest("TLSParserMultimsgTest02", TLSParserMultimsgTest02, 1);
#endif /* UNITTESTS */
}
