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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 * App-layer detection of SSL2 protocol
 *
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

#include "detect-engine-state.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "app-layer-ssl.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "flow-private.h"
#include "flow-util.h"
#include "util-byte.h"

/**
 * \brief Function to parse the SSL field in packet received from the client
 *
 *  \param  ssl_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSLParseClientRecord(Flow *f, void *ssl_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();
    SslClient *client = NULL;
    SslState *ssl_st = NULL;

    /* SSL client message should be larger than 9 bytes as we need to know, to
       what is the SSL version and message type */
    if (input_len < 9) {
        SCLogDebug("Input message length (%"PRIu32") is not equal to minimum "
                "valid ssl record message length, thus returning", input_len);
        SCReturnInt(1);
    }

    client = (SslClient *)input;
    ssl_st = (SslState *)ssl_state;

    switch (client->msg_type) {
        case SSL_CLIENT_HELLO:
            if (client->major_ver != 0x02) {
                SCLogError(SC_ERR_ALPARSER, "SSL version is not equal to 2, "
                        "incorrect message!!");
                SCReturnInt(-1);
            }

            ssl_st->flags |= SSL_FLAG_CLIENT_HS;
            ssl_st->client_content_type = client->msg_type;
            ssl_st->client_version = client->minor_ver|client->major_ver;
            if (client->session_id_len == 0) {
                ssl_st->flags |= SSL_FLAG_NO_SESSION_ID;
            }
            SCLogDebug("SSLv2 CLIENT_HELLO message has been received");

            break;
        case SSL_CLIENT_MASTER_KEY:
            if ( ! (ssl_st->flags & SSL_FLAG_CLIENT_HS)) {
                SCLogDebug("client hello is not seen before master key "
                        "message!!");
                break;
            }
            ssl_st->flags |= SSL_FLAG_CLIENT_MASTER_KEY;
            ssl_st->client_content_type = client->msg_type;
            SCLogDebug("SSLv2 CLIENT_MASTER_KEY message has been received");

            break;
        case SSL_CLIENT_CERTIFICATE:
        case SSL_CLIENT_FINISHED:
        case SSL_REQUEST_CERTIFICATE:
            if ((ssl_st->flags & SSL_FLAG_CLIENT_HS) &&
                    (ssl_st->flags & SSL_FLAG_SERVER_HS))
            {
                if (ssl_st->flags & SSL_FLAG_NO_SESSION_ID) {
                    ssl_st->flags |= SSL_FLAG_CLIENT_SSN_ENCRYPTED;
                    SCLogDebug("SSLv2 Client side has started the encryption");
                } else if (ssl_st->flags & SSL_FLAG_CLIENT_MASTER_KEY) {
                    ssl_st->flags |= SSL_FLAG_CLIENT_SSN_ENCRYPTED;
                    SCLogDebug("SSLv2 Client side has started the encryption");
                }

                if ((ssl_st->flags & SSL_FLAG_CLIENT_SSN_ENCRYPTED) &&
                        (ssl_st->flags & SSL_FLAG_SERVER_SSN_ENCRYPTED))
                {
                    pstate->flags |= APP_LAYER_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
                    pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
                    SCLogDebug("SSLv2 No reassembly & inspection has been set");
                }
            }
            ssl_st->client_content_type = client->msg_type;

            break;
        case SSL_ERROR:
            SCLogError(SC_ERR_ALPARSER, "Error encountered in establishing the "
                    "sslv2 session");
            SCReturnInt(-1);
        default:
            SCLogError(SC_ERR_ALPARSER, "Incorrect message type (%"PRIu8") "
                    "while establishing the sslv2 session", client->msg_type);
            break;
    }
    SCReturnInt(1);
}

/**
 * \brief Function to parse the SSL field in packet received from the server
 *
 *  \param  ssl_state   Pointer the state in which the value to be stored
 *  \param  pstate      Application layer tarser state for this session
 *  \param  input       Pointer the received input data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the list of parsed output elements
 */
static int SSLParseServerRecord(Flow *f, void *ssl_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();
    SCEnter();
    SslServer *server = (SslServer *)input;
    SslState *ssl_st = (SslState *)ssl_state;

    if (input_len < 7) {
        SCLogDebug("Input message lentgh (%"PRIu32") is not equal to minimum "
                "valid ssl record message length, thus returning!!", input_len);
        SCReturnInt(1);
    }

    switch (server->msg_type) {
        case SSL_SERVER_HELLO:
            if (server->major_ver != 0x02) {
                SCLogError(SC_ERR_ALPARSER, "SSL version is not equal to 2, "
                        "incorrect message!!");
                SCReturnInt(-1);
            }
            SCLogDebug("SSLv2 SERVER_HELLO message has been received");

            ssl_st->flags |= SSL_FLAG_SERVER_HS;
            ssl_st->server_content_type = server->msg_type;
            ssl_st->server_version = server->minor_ver|server->major_ver;
            break;
        case SSL_SERVER_VERIFY:
        case SSL_SERVER_FINISHED:
        case SSL_REQUEST_CERTIFICATE:
            if ((ssl_st->flags & SSL_FLAG_SERVER_HS) &&
                    (ssl_st->flags & SSL_FLAG_CLIENT_HS))
            {
                ssl_st->flags |= SSL_FLAG_SERVER_SSN_ENCRYPTED;
                SCLogDebug("SSLv2 Server side has started the encryption");

                if ((ssl_st->flags & SSL_FLAG_CLIENT_SSN_ENCRYPTED) &&
                        (ssl_st->flags & SSL_FLAG_SERVER_SSN_ENCRYPTED))
                {
                    pstate->flags |= APP_LAYER_PARSER_DONE;
                    pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
                    pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
                    SCLogDebug("SSLv2 No reassembly & inspection has been set");
                }
            }
            ssl_st->server_content_type = server->msg_type;

            break;
        case SSL_ERROR:
            SCLogError(SC_ERR_ALPARSER, "Error encountered in establishing the "
                    "sslv2 session");
            SCReturnInt(-1);
        default:
            SCLogError(SC_ERR_ALPARSER, "Incorrect message type (%"PRIu8") "
                    "while establishing the sslv2 session", server->msg_type);
            break;
    }
    SCReturnInt(1);
}

/** \brief Function to allocates the TLS state memory
 */
static void *SSLStateAlloc(void)
{
    SCEnter();
    void *s = SCMalloc(sizeof(SslState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(SslState));
    SCReturnPtr(s, "SslState");
}

/** \brief Function to free the TLS state memory
 */
static void SSLStateFree(void *s)
{
    SCEnter();
    SCFree(s);
    SCReturn;
}

/** \brief Function to register the SSL protocol parsers and other functions
 */
void RegisterSSLParsers(void)
{
    AppLayerRegisterProto("ssl", ALPROTO_SSL, STREAM_TOSERVER,
                          SSLParseClientRecord);

    AppLayerRegisterProto("ssl", ALPROTO_SSL, STREAM_TOCLIENT,
                            SSLParseServerRecord);

    AppLayerRegisterStateFuncs(ALPROTO_SSL, SSLStateAlloc, SSLStateFree);

}

#ifdef UNITTESTS
#include "util-unittest-helper.h"
#include "stream-tcp-reassemble.h"
#include "decode-tcp.h"

extern uint16_t AppLayerParserGetStorageId (void);

static int SSLParserTest01(void) {
    int result = 0;
    Flow f;
    uint8_t *sslbuf = (uint8_t *) "\x80\x31\x01\x00\x02\x00\x00\x00\x01";

    /* PrintRawDataFp(stdout, sslbuf, 9); */

    uint32_t ssllen = 9;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_SSL, STREAM_TOSERVER|STREAM_EOF, sslbuf, ssllen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    SslState *ssl_state = f.aldata[AlpGetStateIdx(ALPROTO_SSL)];
    if (ssl_state == NULL) {
        printf("no ssl state: ");
        goto end;
    }

    if (ssl_state->client_content_type != 0x1) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x1,
                ssl_state->client_content_type);
        goto end;
    }

    if (ssl_state->client_version != SSL_CLIENT_VERSION) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_CLIENT_VERSION, ssl_state->client_version);
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SSLParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t sslbuf[] = {0x80, 0x31, 0x04, 0x00, 0x01, 0x00,
            0x02, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0,
            0x05, 0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00,
            0x80, 0x08, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04,
            0x00, 0x80, 0x02, 0x00, 0x80, 0x76, 0x64, 0x75,
            0x2d, 0xa7, 0x98, 0xfe, 0xc9, 0x12, 0x92, 0xc1,
            0x2f, 0x34, 0x84, 0x20, 0xc5};
    uint32_t ssllen = sizeof(sslbuf);
    TcpSession ssn;
    AppLayerDetectProtoThreadInit();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    int r = AppLayerParse(&f, ALPROTO_SSL, STREAM_TOCLIENT|STREAM_EOF, sslbuf, ssllen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SslState *ssl_state = f.aldata[AlpGetStateIdx(ALPROTO_SSL)];
    if (ssl_state == NULL) {
        printf("no ssl state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->server_content_type != SSL_SERVER_HELLO) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ",
                SSL_SERVER_HELLO, ssl_state->client_content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->server_version != SSL_SERVER_VERSION) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_SERVER_VERSION, ssl_state->client_version);
        result = 0;
        goto end;
    }
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

#if 0 /* VJ disabled 20100721 */
static int SSLParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t payload1[] = {  0x80, 0x31, 0x01, 0x00, 0x02, 0x00,
                0x18, 0x00, 0x00, 0x00, 0x10, 0x07, 0x00, 0xc0,
                0x05, 0x00, 0x80, 0x03, 0x00, 0x80, 0x01, 0x00,
                0x80, 0x08, 0x00, 0x80, 0x06, 0x00, 0x40, 0x04,
                0x00, 0x80, 0x02, 0x00, 0x80, 0x76, 0x64, 0x75,
                0x2d, 0xa7, 0x98, 0xfe, 0xc9, 0x12, 0x92, 0xc1,
                0x2f, 0x34, 0x84, 0x20, 0xc5 };
    uint32_t payload_len1 = sizeof(payload1);
    uint8_t payload2[] = {  0x83, 0xbb, 0x04, 0x00, 0x01, 0x00,
                0x02, 0x03, 0x8b, 0x00, 0x15, 0x00, 0x10, 0x30,
                0x82, 0x03, 0x87, 0x30, 0x82, 0x02, 0xf0, 0xa0,
                0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30,
                0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x30, 0x78,
                0x31, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04,
                0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30,
                0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x13, 0x0a,
                0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e,
                0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03,
                0x55, 0x04, 0x07, 0x13, 0x09, 0x53, 0x75, 0x6e,
                0x6e, 0x79, 0x76, 0x61, 0x6c, 0x65, 0x31, 0x19,
                0x30, 0x17, 0x06, 0x03, 0x55, 0x04, 0x0a, 0x13,
                0x10, 0x4d, 0x75, 0x53, 0x65, 0x63, 0x75, 0x72,
                0x69, 0x74, 0x79, 0x2c, 0x20, 0x49, 0x6e, 0x63,
                0x2e, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09, 0x2a,
                0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01,
                0x16, 0x16, 0x61, 0x74, 0x75, 0x72, 0x6e, 0x65,
                0x72, 0x40, 0x6d, 0x75, 0x73, 0x65, 0x63, 0x75,
                0x72, 0x69, 0x74, 0x79, 0x2e, 0x63, 0x6f, 0x6d,
                0x30, 0x1e, 0x17, 0x0d, 0x30, 0x35, 0x30, 0x36,
                0x30, 0x36, 0x32, 0x33, 0x32, 0x38, 0x35, 0x38,
                0x5a, 0x17, 0x0d, 0x31, 0x33, 0x31, 0x30, 0x32,
                0x37, 0x32, 0x33, 0x32, 0x38, 0x35, 0x38, 0x5a,
                0x30, 0x81, 0x96, 0x31, 0x0b, 0x30, 0x09, 0x06,
                0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53,
                0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04,
                0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69, 0x66,
                0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x12, 0x30,
                0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13, 0x09,
                0x53, 0x75, 0x6e, 0x6e, 0x79, 0x76, 0x61, 0x6c,
                0x65, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03, 0x55,
                0x04, 0x0a, 0x13, 0x10, 0x4d, 0x75, 0x53, 0x65,
                0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2c, 0x20,
                0x49, 0x6e, 0x63, 0x2e, 0x31, 0x1c, 0x30, 0x1a,
                0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x13, 0x73,
                0x74, 0x61, 0x6e, 0x2e, 0x6d, 0x75, 0x73, 0x65,
                0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x63,
                0x6f, 0x6d, 0x31, 0x25, 0x30, 0x23, 0x06, 0x09,
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
                0x01, 0x16, 0x16, 0x61, 0x74, 0x75, 0x72, 0x6e,
                0x65, 0x72, 0x40, 0x6d, 0x75, 0x73, 0x65, 0x63,
                0x75, 0x72, 0x69, 0x74, 0x79, 0x2e, 0x63, 0x6f,
                0x6d, 0x30, 0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09,
                0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                0x01, 0x05, 0x00, 0x03, 0x81, 0x8d, 0x00, 0x30,
                0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xe7,
                0x9b, 0x0a, 0xe8, 0xbb, 0xec, 0x4b, 0x1e, 0x5a,
                0x37, 0x95, 0xa5, 0x18, 0x7d, 0xad, 0xa5, 0xbd,
                0xa3, 0x6b, 0x5c, 0xd1, 0x51, 0xce, 0x38, 0xf3,
                0x81, 0xb3, 0x85, 0x0e, 0xfe, 0x17, 0xef, 0x87,
                0xcb, 0x7f, 0xc7, 0x92, 0xeb, 0xa0, 0x89, 0x76,
                0x8b, 0xa3, 0x25, 0xb8, 0x20, 0xeb, 0xd8, 0x4a,
                0xa9, 0xb0, 0x3b, 0x08, 0x81, 0xc1, 0x8e, 0x3c,
                0x8f, 0x63, 0x8a, 0x47, 0xb5, 0x7f, 0x27, 0x4c,
                0x21, 0x2f, 0x86, 0xd3, 0x66, 0x0a, 0x97, 0x2a,
                0xe5, 0x9c, 0xd7, 0xa2, 0x5d, 0xb4, 0xce, 0xbc,
                0x4e, 0x28, 0xdc, 0x25, 0x6b, 0x2e, 0x39, 0xf5,
                0xbc, 0x98, 0x1b, 0x4c, 0x7c, 0x77, 0xa1, 0x61,
                0x52, 0xfd, 0x95, 0x49, 0x70, 0xf8, 0x94, 0xfb,
                0xa4, 0x11, 0x8a, 0x81, 0xa8, 0xd3, 0x26, 0x51,
                0x40, 0x01, 0xb0, 0x70, 0x45, 0xd5, 0xe4, 0xc5,
                0x49, 0x33, 0xb3, 0xed, 0xd8, 0xe7, 0x02, 0x03,
                0x01, 0x00, 0x01, 0xa3, 0x82, 0x01, 0x00, 0x30,
                0x81, 0xfd, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d,
                0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x2c, 0x06,
                0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xf8, 0x42,
                0x01, 0x0d, 0x04, 0x1f, 0x16, 0x1d, 0x4f, 0x70,
                0x65, 0x6e, 0x53, 0x53, 0x4c, 0x20, 0x47, 0x65,
                0x6e, 0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x20,
                0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63,
                0x61, 0x74, 0x65, 0x30, 0x1d, 0x06, 0x03, 0x55,
                0x1d, 0x0e, 0x04, 0x16, 0x04, 0x14, 0xbe, 0x59,
                0x54, 0xcf, 0x22, 0xe1, 0x74, 0xec, 0xe1, 0x8e,
                0x5c, 0x06, 0x2b, 0xf7, 0x1a, 0x7a, 0x6a, 0x50,
                0x67, 0x68, 0x30, 0x81, 0xa2, 0x06, 0x03, 0x55,
                0x1d, 0x23, 0x04, 0x81, 0x9a, 0x30, 0x81, 0x97,
                0x80, 0x14, 0x7d, 0x02, 0x2d, 0x18, 0xe0, 0xe3,
                0x76, 0x45, 0x4b, 0x2e, 0x08, 0x0a, 0xd3, 0xe5,
                0xd4, 0x92, 0x22, 0x71, 0xa4, 0xde, 0xa1, 0x7c,
                0xa4, 0x7a, 0x30, 0x78, 0x31, 0x0b, 0x30, 0x09,
                0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
                0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55,
                0x04, 0x08, 0x13, 0x0a, 0x43, 0x61, 0x6c, 0x69,
                0x66, 0x6f, 0x72, 0x6e, 0x69, 0x61, 0x31, 0x12,
                0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x13,
                0x09, 0x53, 0x75, 0x6e, 0x6e, 0x79, 0x76, 0x61,
                0x6c, 0x65, 0x31, 0x19, 0x30, 0x17, 0x06, 0x03,
                0x55, 0x04, 0x0a, 0x13, 0x10, 0x4d, 0x75, 0x53,
                0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x2c,
                0x20, 0x49, 0x6e, 0x63, 0x2e, 0x31, 0x25, 0x30,
                0x23, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x09, 0x01, 0x16, 0x16, 0x61, 0x74,
                0x75, 0x72, 0x6e, 0x65, 0x72, 0x40, 0x6d, 0x75,
                0x73, 0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79,
                0x2e, 0x63, 0x6f, 0x6d, 0x82, 0x01, 0x00, 0x30,
                0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
                0x0d, 0x01, 0x01, 0x04, 0x05, 0x00, 0x03, 0x81,
                0x81, 0x00, 0x4a, 0x5a, 0xd9, 0xd4, 0xe1, 0xe9,
                0xdd, 0xd5, 0x5c, 0xd3, 0x27, 0x2b, 0x01, 0x95,
                0x1b, 0x8c, 0xa9, 0x9c, 0x93, 0x8e, 0x01, 0x72,
                0xbf, 0xbc, 0x74, 0xbb, 0x30, 0x61, 0xa0, 0x52,
                0xfb, 0xe0, 0xa8, 0x8e, 0x2b, 0x34, 0xe8, 0xf3,
                0x4a, 0xfc, 0xc0, 0xb4, 0x63, 0x83, 0xa8, 0xb4,
                0x5e, 0xb9, 0xe4, 0x21, 0x2f, 0x6b, 0x04, 0x84,
                0x14, 0x98, 0xf0, 0xde, 0x18, 0xd0, 0xa7, 0x9a,
                0x0d, 0x6a, 0xd5, 0xa9, 0x44, 0x57, 0xf9, 0xb4,
                0xdb, 0x59, 0x56, 0x3e, 0x26, 0x49, 0x98, 0xf3,
                0x39, 0x8b, 0x8a, 0x66, 0xd2, 0xcb, 0xa9, 0x48,
                0xda, 0x71, 0xc7, 0x53, 0x28, 0x15, 0xc4, 0xc3,
                0x4c, 0xbb, 0xab, 0xc1, 0x69, 0xfb, 0x37, 0xfa,
                0x99, 0x2b, 0x2b, 0xfa, 0x9d, 0x33, 0xaa, 0x17,
                0xb2, 0xb1, 0x78, 0x9e, 0xa5, 0x50, 0x0a, 0x7c,
                0x4f, 0x8f, 0x4a, 0x93, 0xc2, 0x36, 0x55, 0x2e,
                0x17, 0x98, 0x07, 0x00, 0xc0, 0x03, 0x00, 0x80,
                0x01, 0x00, 0x80, 0x08, 0x00, 0x80, 0x06, 0x00,
                0x40, 0x04, 0x00, 0x80, 0x02, 0x00, 0x80, 0x57,
                0xbe, 0x5d, 0x5d, 0x97, 0xad, 0x58, 0x25, 0xf1,
                0x78, 0xeb, 0x27, 0xba, 0x45, 0xe8, 0x44 };
    uint32_t payload_len2 = sizeof(payload2);
    uint8_t payload3[] = {  0x80, 0x92, 0x02, 0x07, 0x00, 0xc0,
                0x00, 0x00, 0x00, 0x80, 0x00, 0x08, 0x98, 0xb7,
                0xaf, 0x94, 0x0a, 0x00, 0x0c, 0x02, 0xb1, 0x4d,
                0x50, 0x50, 0x17, 0x78, 0x16, 0xba, 0x22, 0x7b,
                0x25, 0xab, 0x09, 0x9f, 0x30, 0xd6, 0xce, 0xa8,
                0xf6, 0x04, 0x41, 0xb3, 0xa4, 0x16, 0x33, 0x18,
                0x7b, 0x24, 0xa6, 0x30, 0x75, 0x67, 0x7a, 0xa7,
                0xac, 0xd2, 0xc2, 0xe3, 0x00, 0x13, 0xb0, 0x39,
                0xb0, 0x50, 0x2b, 0x55, 0x93, 0xd7, 0x65, 0x1f,
                0x00, 0x4f, 0xde, 0x15, 0xee, 0xa8, 0x9c, 0xbd,
                0x86, 0xaf, 0x99, 0x7a, 0x27, 0x53, 0xb3, 0x5a,
                0x4b, 0x90, 0xbd, 0xac, 0xc9, 0xd3, 0xc5, 0x31,
                0x06, 0x19, 0xd8, 0x2f, 0x6b, 0x3a, 0x31, 0xb4,
                0x34, 0xb8, 0x31, 0xec, 0x18, 0x6c, 0xad, 0x9e,
                0xa8, 0xf5, 0x3a, 0x9d, 0xd3, 0x74, 0x78, 0x33,
                0x06, 0x8b, 0x75, 0xc9, 0x39, 0xe8, 0x59, 0x98,
                0xc9, 0x96, 0xca, 0xc0, 0x2f, 0x1c, 0x53, 0xda,
                0x76, 0xab, 0xf1, 0x42, 0x6c, 0x71, 0xaf, 0xc9,
                0x52, 0xbe, 0xb0, 0x7a, 0x7d, 0xe1 };
    uint32_t payload_len3 = sizeof(payload3);
    uint8_t payload4[] = {  0x00, 0x28, 0x07, 0xb8, 0xbb, 0x2c,
                0xce, 0xbe, 0x72, 0xa9, 0x61, 0xef, 0xbf, 0xfa,
                0x50, 0x92, 0x6d, 0x62, 0x77, 0xa3, 0x7b, 0x75,
                0xd6, 0x6e, 0x82, 0x12, 0x27, 0x87, 0x23, 0xce,
                0x9d, 0x44, 0xfe, 0x1f, 0xd0, 0x0e, 0x62, 0xff,
                0xd0, 0x24, 0xea, 0xc0, 0x18 };
    uint32_t payload_len4 = sizeof(payload4);
    uint8_t payload5[] = {  0x00, 0x28, 0x07, 0x9a, 0x1d, 0xe2,
                0x5f, 0x79, 0xcc, 0x14, 0x5b, 0xb5, 0xad, 0x4f,
                0x15, 0x86, 0xe6, 0x03, 0x13, 0xe0, 0x96, 0x96,
                0x85, 0x46, 0x79, 0x0e, 0x3a, 0xe2, 0x84, 0x8d,
                0x8d, 0x88, 0xba, 0x7c, 0x6d, 0xa4, 0xb9, 0x9a,
                0xb1, 0x9f, 0x78, 0xe4, 0x83 };
    uint32_t payload_len5 = sizeof(payload5);
    TcpSession ssn;
    TCPHdr tcph;
    Packet *p1 = UTHBuildPacket(payload1, payload_len1, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacket(payload2, payload_len2, IPPROTO_TCP);
    Packet *p3 = UTHBuildPacket(payload3, payload_len3, IPPROTO_TCP);
    Packet *p4 = UTHBuildPacket(payload4, payload_len4, IPPROTO_TCP);
    Packet *p5 = UTHBuildPacket(payload5, payload_len5, IPPROTO_TCP);

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    memset(&tcph, 0, sizeof(tcph));

    StreamTcpInitConfig(TRUE);
    TcpReassemblyThreadCtx *ra_ctx = StreamTcpReassembleInitThreadCtx();
    AppLayerDetectProtoThreadInit();

    ssn.server.ra_base_seq = 390131220UL;
    ssn.server.isn = 390131220UL;
    ssn.server.last_ack = 427643676UL;
    ssn.client.ra_base_seq = 4276431676UL;
    ssn.client.isn = 4276431676UL;
    ssn.client.last_ack = 390133221UL;
    f.alproto = ALPROTO_UNKNOWN;

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    tcph.th_win = htons(5480);
    tcph.th_seq = htonl(4276431677UL);
    tcph.th_ack = htonl(390131221UL);
    tcph.th_flags = TH_ACK|TH_PUSH;
    p1->tcph = &tcph;
    p1->flowflags = FLOW_PKT_TOSERVER;
    ssn.state = TCP_ESTABLISHED;

    TcpStream *s = NULL;
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p1) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    p2->flowflags = FLOW_PKT_TOCLIENT;
    tcph.th_seq = htonl(390131221UL);
    tcph.th_ack = htonl(4276431728UL);
    p2->tcph = &tcph;
    p2->flow = &f;
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p2) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    if (StreamTcpReassembleProcessAppLayer(ra_ctx) < 0) {
        printf("failed in processing stream smsgs\n");
        goto end;
    }

    p3->flowflags = FLOW_PKT_TOSERVER;
    tcph.th_seq = htonl(4276431728UL);
    tcph.th_ack = htonl(390132178UL);
    p3->tcph = &tcph;
    p3->flow = &f;
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p3) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    if (StreamTcpReassembleProcessAppLayer(ra_ctx) < 0) {
        printf("failed in processing stream smsgs\n");
        goto end;
    }

    p4->flowflags = FLOW_PKT_TOCLIENT;
    tcph.th_seq = htonl(390132178UL);
    tcph.th_ack = htonl(4276431876UL);
    p4->tcph = &tcph;
    p4->flow = &f;
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p4) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    if (StreamTcpReassembleProcessAppLayer(ra_ctx) < 0) {
        printf("failed in processing stream smsgs\n");
        goto end;
    }

    p5->flowflags = FLOW_PKT_TOSERVER;
    tcph.th_seq = htonl(4276431876UL);
    tcph.th_ack = htonl(390132221UL);
    p5->tcph = &tcph;
    p5->flow = &f;
    s = &ssn.client;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p5) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    if (StreamTcpReassembleProcessAppLayer(ra_ctx) < 0) {
        printf("failed in processing stream smsgs\n");
        goto end;
    }

    tcph.th_seq = htonl(390132221UL);
    tcph.th_ack = htonl(4276431919UL);
    s = &ssn.server;

    if (StreamTcpReassembleHandleSegment(ra_ctx, &ssn, s, p4) == -1) {
        printf("failed in segments reassembly, while processing toserver packet\n");
        goto end;
    }

    if (StreamTcpReassembleProcessAppLayer(ra_ctx) < 0) {
        printf("failed in processing stream smsgs\n");
        goto end;
    }

    SslState *ssl_state = f.aldata[AlpGetStateIdx(ALPROTO_SSL)];
    if (ssl_state == NULL) {
        printf("no ssl state: ");
        result = 0;
        goto end;
    }

    if (ssl_state->client_content_type != 0x7) {
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x7,
                ssl_state->client_content_type);
        result = 0;
        goto end;
    }

    if (ssl_state->client_version != SSL_CLIENT_VERSION) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ",
                SSL_CLIENT_VERSION, ssl_state->client_version);
        result = 0;
        goto end;
    }

    uint16_t app_layer_sid = AppLayerParserGetStorageId();
    AppLayerParserStateStore *parser_state_store = (AppLayerParserStateStore *)
                                                    f.aldata[app_layer_sid];
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
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif
#endif /* UNITTESTS */

void SSLParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("SSLParserTest01", SSLParserTest01, 1);
    UtRegisterTest("SSLParserTest02", SSLParserTest02, 1);
/*    UtRegisterTest("SSLParserTest03", SSLParserTest03, 1); */
#endif /* UNITTESTS */
}
