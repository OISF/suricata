/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file   This file provides a HTTP protocol support for the engine using
 *         HTP library.
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include <htp/htp.h>

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-binsearch.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "app-layer-htp.h"

#ifdef DEBUG
static sc_mutex_t htp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void)
{
    void *s = malloc(sizeof(HtpState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(HtpState));

    /* create the connection parser structure to be used by HTP library */
    ((HtpState *)(s))->connp = htp_connp_create(cfg);

#ifdef DEBUG
    sc_mutex_lock(&htp_state_mem_lock);
    htp_state_memcnt++;
    htp_state_memuse+=sizeof(HtpState);
    sc_mutex_unlock(&htp_state_mem_lock);
#endif
    return s;
}

/** \brief Function to frees the HTTP state memory and also frees the HTTP
 *         connection parser memory which was used by the HTP library
 */
static void HTPStateFree(void *s)
{
    /* free the connection parser memory used by HTP library */
    if (s != NULL)
        if (((HtpState *)(s))->connp != NULL)
            htp_connp_destroy(((HtpState *)(s))->connp);

    free(s);
#ifdef DEBUG
    sc_mutex_lock(&htp_state_mem_lock);
    htp_state_memcnt--;
    htp_state_memuse-=sizeof(HtpState);
    sc_mutex_unlock(&htp_state_mem_lock);
#endif
}

/**
 *  \brief  Function to handle the reassembled data from client and feed it to
 *          the HTP library to process it.
 *
 *  \param  htp_state   Pointer the state in which the parsed value to be stored
 *  \param  pstate      Application layer parser state for this session
 *  \param  input       Pointer the received HTTP client data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the output (not used in this function)
 *
 *  \retval On success returns 1 or on failure returns -1
 */
static int HTPHandleRequestData(void *htp_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    HtpState *hstate = (HtpState *)htp_state;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    if (htp_connp_req_data(hstate->connp, tv.tv_usec, input, input_len) ==
                            HTP_ERROR)
    {
        return -1;
    }

    return 1;
}

/**
 *  \brief  Function to handle the reassembled data from server and feed it to
 *          the HTP library to process it.
 *
 *  \param  htp_state   Pointer the state in which the parsed value to be stored
 *  \param  pstate      Application layer parser state for this session
 *  \param  input       Pointer the received HTTP server data
 *  \param  input_len   Length in bytes of the received data
 *  \param  output      Pointer to the output (not used in this function)
 *
 *  \retval On success returns 1 or on failure returns -1
 */
static int HTPHandleResponseData(void *htp_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    HtpState *hstate = (HtpState *)htp_state;
    struct timeval tv;

    gettimeofday(&tv, NULL);

    if (htp_connp_res_data(hstate->connp, tv.tv_usec, input, input_len) ==
                            HTP_ERROR)
    {
        return -1;
    }

    return 1;
}

/**
 *  \brief  Register the HTTP protocol and state handling functions to APP layer
 *          of the engine.
 */
void RegisterHTPParsers(void)
{

    AppLayerRegisterStateFuncs(ALPROTO_HTTP, HTPStateAlloc, HTPStateFree);

    AppLayerRegisterProto("http", ALPROTO_HTTP, STREAM_TOSERVER,
                          HTPHandleRequestData);
    AppLayerRegisterProto("http", ALPROTO_HTTP, STREAM_TOCLIENT,
                          HTPHandleResponseData);

    cfg = htp_config_create();
}

//#ifdef UNITTESTS
/** \test Test case where chunks are sent in smaller chunks and check the
 *        response of the parser from HTP library. */
int HTPParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
                         " Data is c0oL!";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(&f, ALPROTO_HTTP, flags, &httpbuf1[u], 1, FALSE);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || strcmp(bstr_tocstr(h->value), "Victor/1.0")
            || tx->request_method_number != M_POST ||
            tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected header value: Victor/1.0 and got %s: and expected"
                " method: POST and got %s, expected protocol number HTTP/1.1"
                "  and got: %s \n", bstr_tocstr(h->value),
                bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    return result;
}

/** \test See how it deals with an incomplete request. */
int HTPParserTest02(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "POST";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());

    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if ((tx->request_method) != NULL || h != NULL)
    {
        printf("expected method NULL, got %s \n", bstr_tocstr(tx->request_method));
        result = 0;
        goto end;
    }

end:
    return result;
}

/** \test Test case where method is invalid and data is sent in smaller chunks
 *        and check the response of the parser from HTP library. */
int HTPParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "HELLO / HTTP/1.0\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    uint32_t u;
    for (u = 0; u < httplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (httplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(&f, ALPROTO_HTTP, flags, &httpbuf1[u], 1, FALSE);
        if (r != 0) {
            printf("toserver chunk %" PRIu32 " returned %" PRId32 ", expected"
                    " 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || tx->request_method_number != M_UNKNOWN ||
             h != NULL || tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    return result;
}

/** \test Test case where invalid data is sent and check the response of the
 *        parser from HTP library. */
int HTPParserTest04(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "World!\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START|
                          STREAM_EOF, httpbuf1, httplen1, FALSE);

    HtpState *htp_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (htp_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(htp_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if (htp_state->connp == NULL || tx->request_method_number != M_UNKNOWN ||
            h != NULL || tx->request_protocol_number != PROTOCOL_UNKNOWN)
    {
        printf("expected method M_UNKNOWN and got %s: , expected protocol "
                "NULL and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

end:
    return result;
}

/** \test Test both sides of a http stream mixed up to see if the HTP parser
 *        properly parsed them and also keeps them separated. */
int HTPParserTest05(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "POST / HTTP/1.1\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "Post D";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "ata is c0oL!";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "HTTP/1.1 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
    uint32_t httplen4 = sizeof(httpbuf4) - 1; /* minus the \0 */
    uint8_t httpbuf5[] = "post R";
    uint32_t httplen5 = sizeof(httpbuf5) - 1; /* minus the \0 */
    uint8_t httpbuf6[] = "esults are tha bomb!";
    uint32_t httplen6 = sizeof(httpbuf6) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());

    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_START,
                          httpbuf1, httplen1, FALSE);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf4,
                      httplen4, FALSE);
    if (r != 0) {
        printf("toserver chunk 4 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT, httpbuf5, httplen5, FALSE);
    if (r != 0) {
        printf("toserver chunk 5 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER, httpbuf2, httplen2, FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOSERVER|STREAM_EOF, httpbuf3,
                      httplen3, FALSE);
    if (r != 0) {
        printf("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_EOF, httpbuf6,
                      httplen6, FALSE);
    if (r != 0) {
        printf("toserver chunk 6 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    HtpState *http_state = ssn.aldata[AlpGetStateIdx(ALPROTO_HTTP)];
    if (http_state == NULL) {
        printf("no http state: ");
        result = 0;
        goto end;
    }

    htp_tx_t *tx = list_get(http_state->connp->conn->transactions, 0);

    bstr *key = NULL;
    htp_header_t *h = NULL;
    table_iterator_reset(tx->request_headers);
    key = table_iterator_next(tx->request_headers, (void **) & h);

    if (http_state->connp == NULL || tx->request_method_number != M_POST ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if (tx->response_status_number != 200 ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.1 and got %s \n", tx->response_status_number,
                bstr_tocstr(tx->response_message),
                bstr_tocstr(tx->response_protocol));
        result = 0;
        goto end;
    }
end:
    return result;
}

//#endif /* UNITTESTS */
/**
 *  \brief  Register the Unit tests for the HTTP protocol
 */
void HTPParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HTPParserTest01", HTPParserTest01, 1);
    UtRegisterTest("HTPParserTest02", HTPParserTest02, 1);
    UtRegisterTest("HTPParserTest03", HTPParserTest03, 1);
    UtRegisterTest("HTPParserTest04", HTPParserTest04, 1);
    UtRegisterTest("HTPParserTest05", HTPParserTest05, 1);
#endif /* UNITTESTS */
}

