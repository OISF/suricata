/* Copyright (c) 2009 Victor Julien */

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

#include "util-binsearch.h"
#include "util-unittest.h"

enum {
    TLS_FIELD_NONE = 0,

    TLS_FIELD_CLIENT_CONTENT_TYPE, /* len 1 */
    TLS_FIELD_CLIENT_VERSION,      /* len 2 */

    TLS_FIELD_SERVER_CONTENT_TYPE, /* len 1 */
    TLS_FIELD_SERVER_VERSION,      /* len 2 */

    /* must be last */
    TLS_FIELD_MAX,
};

typedef struct TlsState_ {
    uint8_t client_content_type;
    uint16_t client_version;

    uint8_t server_content_type;
    uint16_t server_version;
} TlsState;

static int TLSParseClientContentType(void *tls_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    TlsState *state = (TlsState *)tls_state;

    if (input_len != 1) {
        return 0;
    }
    state->client_content_type = *input;

    //printf("TLSParseClientContentType: content_type %02"PRIx8"\n", state->client_content_type);
    return 1;
}

static int TLSParseClientVersion(void *tls_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    TlsState *state = (TlsState *)tls_state;

    if (input_len != 2)
        return 0;

    /** \todo there must be an easier way to get from uint8_t * to a uint16_t */
    struct u16conv_ {
        uint16_t u;
    } *u16conv;
    u16conv = (struct u16conv_ *)input;

    state->client_version = ntohs(u16conv->u);

    //printf("TLSParseClientVersion: version %04"PRIx16"\n", state->client_version);
    return 1;
}

static int TLSParseClientRecord(void *tls_state, AppLayerParserState *pstate, uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    //printf("TLSParseRequestLine: tls_state %p, pstate %p, input %p, input_len %" PRIu32 "\n", tls_state, pstate, input, input_len);
    //PrintRawDataFp(stdout, input,input_len);

    uint16_t max_fields = 2;
    uint16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {
        //printf("TLSParseRequestLine: u %" PRIu32 "\n", u);

        switch(u) {
            case 0: /* TLS CONTENT TYPE */
            {
                int r = AlpParseFieldBySize(output, pstate, TLS_FIELD_CLIENT_CONTENT_TYPE, /* single byte field */1, input, input_len, &offset);
                //printf("TLSParseClientRecord: r = %" PRId32 "\n", r);

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

                int r = AlpParseFieldBySize(output, pstate, TLS_FIELD_CLIENT_VERSION, /* 2 byte field */2, data, data_len, &offset);
                if (r == 0) {
                    pstate->parse_field = 1;
                    return 0;
                }
                break;
            }
        }
    }

    pstate->parse_field = 0;
    pstate->flags |= APP_LAYER_PARSER_DONE;
    return 1;
}

static void *TLSStateAlloc(void) {
    void *s = malloc(sizeof(TlsState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(TlsState));
    return s;
}

static void TLSStateFree(void *s) {
    free(s);
}

void RegisterTLSParsers(void) {
    AppLayerRegisterProto("tls", ALPROTO_TLS, STREAM_TOSERVER, TLSParseClientRecord);
    AppLayerRegisterParser("tls.client.content_type", ALPROTO_TLS, TLS_FIELD_CLIENT_CONTENT_TYPE, TLSParseClientContentType, "tls");
    AppLayerRegisterParser("tls.client.version", ALPROTO_TLS, TLS_FIELD_CLIENT_VERSION, TLSParseClientVersion, "tls");
    AppLayerRegisterStateFuncs(ALPROTO_TLS, TLSStateAlloc, TLSStateFree);
}

/* UNITTESTS */
#ifdef UNITTESTS

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

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER|STREAM_EOF, tlsbuf, tlslen, FALSE);
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
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16, tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301, tls_state->client_version);
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

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2, FALSE);
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
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16, tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301, tls_state->client_version);
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

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2, FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3, FALSE);
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
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16, tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301, tls_state->client_version);
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

    int r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf1, tlslen1, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf2, tlslen2, FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf3, tlslen3, FALSE);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_TLS, STREAM_TOSERVER, tlsbuf4, tlslen4, FALSE);
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
        printf("expected content_type %" PRIu8 ", got %" PRIu8 ": ", 0x16, tls_state->client_content_type);
        result = 0;
        goto end;
    }

    if (tls_state->client_version != 0x0301) {
        printf("expected version %04" PRIu16 ", got %04" PRIu16 ": ", 0x0301, tls_state->client_version);
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
#endif /* UNITTESTS */
}
