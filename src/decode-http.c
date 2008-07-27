/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "decode.h"
#include "decode-http.h"
#include "decode-events.h"

#define HTTP_HEADER_LEN    10
#define HTTP_BANNER        "HTTP"
#define HTTP_GET           "GET"
#define HTTP_POST          "POST"

void DecodeHTTP(ThreadVars *t, Packet *p, u_int8_t *pkt, u_int16_t len)
{
    int i, u = 0;
    char uri[2048];
    char code[4];

    if (len < HTTP_HEADER_LEN)
        return;

    if (memcmp(pkt, HTTP_GET, 3) == 0) {
        for (u = 0, i = 4; i < len && pkt[i] != ' ' && u < sizeof(uri); i++) {
           uri[u] = pkt[i];
           u++;
        }
        uri[u] = '\0';
#ifdef DEBUG
        printf("HTTP GET %s\n", uri);
#endif

    } else if (memcmp(pkt, HTTP_POST, 4) == 0) {
        for (u = 0, i = 5; i < len && pkt[i] != ' ' && u < sizeof(uri); i++) {
           uri[u] = pkt[i];
           u++;
        }
        uri[u] = '\0';

#ifdef DEBUG
        printf("HTTP POST %s\n", uri);
#endif
    }
    if (memcmp(pkt, HTTP_BANNER, 4) == 0) {
        for (u = 0, i = 9; i < len && pkt[i] != ' ' && u < sizeof(code); i++) {
           code[u] = pkt[i];
           u++;
        }
        code[u] = '\0';

#ifdef DEBUG
        printf("HTTP reply code %s\n", code);
#endif
    }

    return;
}

