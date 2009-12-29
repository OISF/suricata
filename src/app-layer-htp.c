/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file   This file provides a HTTP protocol support for the engine using
 *         HTP library.
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
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
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-binsearch.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "app-layer-htp.h"
#include "util-time.h"

#ifdef DEBUG
static SCMutex htp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t htp_state_memuse = 0;
static uint64_t htp_state_memcnt = 0;
#endif

/** \brief Function to allocates the HTTP state memory and also creates the HTTP
 *         connection parser to be used by the HTP library
 */
static void *HTPStateAlloc(void)
{
    SCEnter();

    HtpState *s = malloc(sizeof(HtpState));
    if (s == NULL) {
        goto error;
    }

    memset(s, 0x00, sizeof(HtpState));

    /* create the connection parser structure to be used by HTP library */
    s->connp = htp_connp_create(cfg);
    if (s->connp == NULL) {
        goto error;
    }

    SCLogDebug("s->connp %p", s->connp);

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt++;
    htp_state_memuse+=sizeof(HtpState);
    SCMutexUnlock(&htp_state_mem_lock);
#endif

    SCReturnPtr((void *)s, "void");

error:
    if (s != NULL)
        free(s);

    SCReturnPtr(NULL, "void");
}

/** \brief Function to frees the HTTP state memory and also frees the HTTP
 *         connection parser memory which was used by the HTP library
 */
static void HTPStateFree(void *state)
{
    SCEnter();

    HtpState *s = (HtpState *)state;

    /* free the connection parser memory used by HTP library */
    if (s != NULL) {
        if (s->connp != NULL) {
            htp_connp_destroy_all(s->connp);
        }
    }

    free(s);

#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    htp_state_memcnt--;
    htp_state_memuse-=sizeof(HtpState);
    SCMutexUnlock(&htp_state_mem_lock);
#endif

    SCReturn;
}

/**
 *  \brief  Function to convert the IP addresses in to the string
 *
 *  \param  f               pointer to the flow which contains the IP addresses
 *  \param  remote_addr     pointer the string which will contain the remote address
 *  \param  local_addr     pointer the string which will contain the local address
 */
void HTPGetIPAddr(Flow *f, int family, char *remote_addr, char *local_addr)
{
    inet_ntop(family, (const void *)&f->src.addr_data32[0], remote_addr,
            sizeof (remote_addr));
    inet_ntop(family, (const void *)&f->dst.addr_data32[0], local_addr,
            sizeof (local_addr));
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
static int HTPHandleRequestData(Flow *f, void *htp_state,
                                AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    HtpState *hstate = (HtpState *)htp_state;

    /* Open the HTTP connection on receiving the first request */
    if (!(hstate->flags & HTP_FLAG_STATE_OPEN)) {
        SCLogDebug("opening htp handle at %p", hstate->connp);

        htp_connp_open(hstate->connp, NULL, f->sp, NULL, f->dp, 0);
        hstate->flags |= HTP_FLAG_STATE_OPEN;
    } else {
        SCLogDebug("using existing htp handle at %p", hstate->connp);
    }

    r = htp_connp_req_data(hstate->connp, 0, input, input_len);
    if(r == STREAM_STATE_ERROR)
    {
        if (hstate->connp->last_error != NULL) {
            SCLogError(SC_ALPARSER_ERR, "Error in parsing HTTP client request: "
                "[%"PRId32"] [%s] [%"PRId32"] %s", hstate->connp->last_error->level,
                hstate->connp->last_error->file, hstate->connp->last_error->line,
                hstate->connp->last_error->msg);
        } else {
             SCLogError(SC_ALPARSER_ERR, "Error in parsing HTTP client request");
        }
        hstate->flags |= HTP_FLAG_STATE_ERROR;
        hstate->flags &= ~HTP_FLAG_STATE_DATA;
        ret = -1;

    } else if (r == STREAM_STATE_DATA) {
        hstate->flags |= HTP_FLAG_STATE_DATA;
    } else {
        hstate->flags &= ~HTP_FLAG_STATE_DATA;
    }

    /* if we the TCP connection is closed, then close the HTTP connection */
    if ((pstate->flags & APP_LAYER_PARSER_EOF) &&
            ! (hstate->flags & HTP_FLAG_STATE_CLOSED) &&
            ! (hstate->flags & HTP_FLAG_STATE_DATA))
    {
        htp_connp_close(hstate->connp, 0);
        hstate->flags |= HTP_FLAG_STATE_CLOSED;
        SCLogDebug("stream eof encountered, closing htp handle");
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    SCReturnInt(ret);
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
static int HTPHandleResponseData(Flow *f, void *htp_state,
                                AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len,
                                AppLayerParserResult *output)
{
    SCEnter();
    int r = -1;
    int ret = 1;

    HtpState *hstate = (HtpState *)htp_state;

    r = htp_connp_res_data(hstate->connp, 0, input, input_len);
    if (r == STREAM_STATE_ERROR)
    {
         if (hstate->connp->last_error != NULL) {
            SCLogError(SC_ALPARSER_ERR, "Error in parsing HTTP server request: "
                "[%"PRId32"] [%s] [%"PRId32"] %s", hstate->connp->last_error->level,
                hstate->connp->last_error->file, hstate->connp->last_error->line,
                hstate->connp->last_error->msg);
         } else {
             SCLogError(SC_ALPARSER_ERR, "Error in parsing HTTP server request");
         }
         hstate->flags = HTP_FLAG_STATE_ERROR;
         ret = -1;

    } else if (r == STREAM_STATE_DATA) {
        hstate->flags |= HTP_FLAG_STATE_DATA;
    } else {
        hstate->flags &= ~HTP_FLAG_STATE_DATA;
    }

    /* if we the TCP connection is closed, then close the HTTP connection */
    if ((pstate->flags & APP_LAYER_PARSER_EOF) &&
            ! (hstate->flags & HTP_FLAG_STATE_CLOSED) &&
            ! (hstate->flags & HTP_FLAG_STATE_DATA))
    {
        htp_connp_close(hstate->connp, 0);
        hstate->flags |= HTP_FLAG_STATE_CLOSED;
    }

    SCLogDebug("hstate->connp %p", hstate->connp);
    SCReturnInt(ret);
}

/**
 * \brief Print the stats of the HTTP requests
 */
void HTPAtExitPrintStats(void)
{
#ifdef DEBUG
    SCMutexLock(&htp_state_mem_lock);
    SCLogDebug("http_state_memcnt %"PRIu64", http_state_memuse %"PRIu64"",
                htp_state_memcnt, htp_state_memuse);
    SCMutexUnlock(&htp_state_mem_lock);
#endif
}

/** \brief Clears the HTTP server configuration memory used by HTP library */
void HTPFreeConfig(void)
{
    htp_config_destroy(cfg);
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
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\nPost"
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
            tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected header value: Victor/1.0 and got %s: and expected"
                " method: POST and got %s, expected protocol number HTTP/1.0"
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
    uint8_t httpbuf1[] = "POST / HTTP/1.0\r\nUser-Agent: Victor/1.0\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "Post D";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
    uint8_t httpbuf3[] = "ata is c0oL!";
    uint32_t httplen3 = sizeof(httpbuf3) - 1; /* minus the \0 */

    uint8_t httpbuf4[] = "HTTP/1.0 200 OK\r\nServer: VictorServer/1.0\r\n\r\n";
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
            h == NULL || tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected method M_POST and got %s: , expected protocol "
                "HTTP/1.0 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if (tx->response_status_number != 200 ||
            h == NULL || tx->request_protocol_number != HTTP_1_0)
    {
        printf("expected response 200 OK and got %"PRId32" %s: , expected protocol "
                "HTTP/1.0 and got %s \n", tx->response_status_number,
                bstr_tocstr(tx->response_message),
                bstr_tocstr(tx->response_protocol));
        result = 0;
        goto end;
    }
end:
    return result;
}

/** \test Test proper chunked encoded response body
 */
int HTPParserTest06(void) {
    int result = 1;
    Flow f;
    uint8_t httpbuf1[] = "GET /ld/index.php?id=412784631&cid=0064&version=4&"
                         "name=try HTTP/1.1\r\nAccept: */*\r\nUser-Agent: "
                         "LD-agent\r\nHost: 209.205.196.16\r\n\r\n";
    uint32_t httplen1 = sizeof(httpbuf1) - 1; /* minus the \0 */
    uint8_t httpbuf2[] = "HTTP/1.1 200 OK\r\nDate: Sat, 03 Oct 2009 10:16:02 "
                         "GMT\r\n"
                         "Server: Apache/1.3.37 (Unix) mod_ssl/2.8.28 "
                         "OpenSSL/0.9.7a PHP/4.4.7 mod_perl/1.29 "
                         "FrontPage/5.0.2.2510\r\n"
                         "X-Powered-By: PHP/4.4.7\r\nTransfer-Encoding: "
                         "chunked\r\n"
                         "Content-Type: text/html\r\n\r\n"
                         "1408\r\n"
                         "W2dyb3VwMV0NCnBob25lMT1wMDB3ODgyMTMxMzAyMTINCmxvZ2lu"
                         "MT0NCnBhc3N3b3JkMT0NCnBob25lMj1wMDB3ODgyMTMxMzAyMTIN"
                         "CmxvZ2luMj0NCnBhc3N3b3JkMj0NCnBob25lMz0NCmxvZ2luMz0N"
                         "CnBhc3N3b3JkMz0NCnBob25lND0NCmxvZ2luND0NCnBhc3N3b3Jk"
                         "ND0NCnBob25lNT0NCmxvZ2luNT0NCnBhc3N3b3JkNT0NCnBob25l"
                         "Nj0NCmxvZ2luNj0NCnBhc3N3b3JkNj0NCmNhbGxfdGltZTE9MzIN"
                         "CmNhbGxfdGltZTI9MjMyDQpkYXlfbGltaXQ9NQ0KbW9udGhfbGlt"
                         "aXQ9MTUNCltncm91cDJdDQpwaG9uZTE9DQpsb2dpbjE9DQpwYXNz"
                         "d29yZDE9DQpwaG9uZTI9DQpsb2dpbjI9DQpwYXNzd29yZDI9DQpw"
                         "aG9uZTM9DQpsb2dpbjM9DQpwYXNzd29yZDM9DQpwaG9uZTQ9DQps"
                         "b2dpbjQ9DQpwYXNzd29yZDQ9DQpwaG9uZTU9DQpsb2dpbjU9DQpw"
                         "YXNzd29yZDU9DQpwaG9uZTY9DQpsb2dpbjY9DQpwYXNzd29yZDY9"
                         "DQpjYWxsX3RpbWUxPQ0KY2FsbF90aW1lMj0NCmRheV9saW1pdD0N"
                         "Cm1vbnRoX2xpbWl0PQ0KW2dyb3VwM10NCnBob25lMT0NCmxvZ2lu"
                         "MT0NCnBhc3N3b3JkMT0NCnBob25lMj0NCmxvZ2luMj0NCnBhc3N3"
                         "b3JkMj0NCnBob25lMz0NCmxvZ2luMz0NCnBhc3N3b3JkMz0NCnBo"
                         "b25lND0NCmxvZ2luND0NCnBhc3N3b3JkND0NCnBob25lNT0NCmxv"
                         "Z2luNT0NCnBhc3N3b3JkNT0NCnBob25lNj0NCmxvZ2luNj0NCnBh"
                         "c3N3b3JkNj0NCmNhbGxfdGltZTE9DQpjYWxsX3RpbWUyPQ0KZGF5"
                         "X2xpbWl0PQ0KbW9udGhfbGltaXQ9DQpbZ3JvdXA0XQ0KcGhvbmUx"
                         "PQ0KbG9naW4xPQ0KcGFzc3dvcmQxPQ0KcGhvbmUyPQ0KbG9naW4y"
                         "PQ0KcGFzc3dvcmQyPQ0KcGhvbmUzPQ0KbG9naW4zPQ0KcGFzc3dv"
                         "cmQzPQ0KcGhvbmU0PQ0KbG9naW40PQ0KcGFzc3dvcmQ0PQ0KcGhv"
                         "bmU1PQ0KbG9naW41PQ0KcGFzc3dvcmQ1PQ0KcGhvbmU2PQ0KbG9n"
                         "aW42PQ0KcGFzc3dvcmQ2PQ0KY2FsbF90aW1lMT0NCmNhbGxfdGlt"
                         "ZTI9DQpkYXlfbGltaXQ9DQptb250aF9saW1pdD0NCltmaWxlc10N"
                         "Cmxpbms9aHR0cDovLzIwOS4yMDUuMTk2LjE2L2xkL2dldGJvdC5w"
                         "aHA=0\r\n\r\n";
    uint32_t httplen2 = sizeof(httpbuf2) - 1; /* minus the \0 */
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

    r = AppLayerParse(&f, ALPROTO_HTTP, STREAM_TOCLIENT|STREAM_START, httpbuf2,
                      httplen2, FALSE);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
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

    if (http_state->connp == NULL || tx->request_method_number != M_GET ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected method M_GET and got %s: , expected protocol "
                "HTTP/1.1 and got %s \n", bstr_tocstr(tx->request_method),
                bstr_tocstr(tx->request_protocol));
        result = 0;
        goto end;
    }

    if (tx->response_status_number != 200 ||
            h == NULL || tx->request_protocol_number != HTTP_1_1)
    {
        printf("expected response 200 OK and got %"PRId32" %s: , expected proto"
                "col HTTP/1.1 and got %s \n", tx->response_status_number,
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
    UtRegisterTest("HTPParserTest06", HTPParserTest06, 1);
#endif /* UNITTESTS */
}

