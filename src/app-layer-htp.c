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
static pthread_mutex_t htp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
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
    mutex_lock(&htp_state_mem_lock);
    htp_state_memcnt++;
    htp_state_memuse+=sizeof(HtpState);
    mutex_unlock(&htp_state_mem_lock);
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
    mutex_lock(&htp_state_mem_lock);
    htp_state_memcnt--;
    htp_state_memuse-=sizeof(HtpState);
    mutex_unlock(&htp_state_mem_lock);
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
 *  \retval On success returns 1 or on failure returns the HTTP error codes
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
        return -101;
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
 *  \retval On success returns 1 or on failure returns the HTTP error codes
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
        return -102;
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

    if (htp_state->connp == NULL || strcmp(bstr_tocstr(h->value), "Victor/1.0"))
    {
        printf("expected Victor/1.0 and got %s: \n", bstr_tocstr(h->value));
        result = 0;
        goto end;
    }

end:
    return result;
}

/**
 *  \brief  Register the Unit tests for the HTTP protocol
 */
void HTPParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("HTPParserTest01", HTPParserTest01, 1);
#endif /* UNITTESTS */
}

