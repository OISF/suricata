/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#include "eidps-common.h"
#include "decode.h"
#include "decode-tcp.h"
#include "decode-events.h"

#include "flow.h"

static int DecodeTCPOptions(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    uint16_t plen = len;
    while (plen)
    {
        /* single byte options */
        if (*pkt == TCP_OPT_EOL) {
            break;
        } else if (*pkt == TCP_OPT_NOP) {
            pkt++;
            plen--;

        /* multibyte options */
        } else {
            if (plen < 2) {
                break;
            }

            p->TCP_OPTS[p->TCP_OPTS_CNT].type = *pkt;
            p->TCP_OPTS[p->TCP_OPTS_CNT].len  = *(pkt+1);
            if (plen > 2)
                p->TCP_OPTS[p->TCP_OPTS_CNT].data = (pkt+2);
            else
                p->TCP_OPTS[p->TCP_OPTS_CNT].data = NULL;

            /* we already know that the total options len is valid,
             * so here the len of the specific option must be bad.
             * Also check for invalid lengths 0 and 1. */
            if (p->TCP_OPTS[p->TCP_OPTS_CNT].len > plen ||
                p->TCP_OPTS[p->TCP_OPTS_CNT].len < 2) {
                DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                return -1;
            }

            /* we are parsing the most commonly used opts to prevent
             * us from having to walk the opts list for these all the
             * time. */
            switch (p->TCP_OPTS[p->TCP_OPTS_CNT].type) {
                case TCP_OPT_WS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_WS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ws != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.ws = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_MSS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_MSS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.mss != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.mss = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_SACKOK:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_SACKOK_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.sackok != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.sackok = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
                case TCP_OPT_TS:
                    if (p->TCP_OPTS[p->TCP_OPTS_CNT].len != TCP_OPT_TS_LEN) {
                        DECODER_SET_EVENT(p,TCP_OPT_INVALID_LEN);
                    } else {
                        if (p->tcpvars.ts != NULL) {
                            DECODER_SET_EVENT(p,TCP_OPT_DUPLICATE);
                        } else {
                            p->tcpvars.ts = &p->TCP_OPTS[p->TCP_OPTS_CNT];
                        }
                    }
                    break;
            }

            pkt += p->TCP_OPTS[p->TCP_OPTS_CNT].len;
            plen -= (p->TCP_OPTS[p->TCP_OPTS_CNT].len);
            p->TCP_OPTS_CNT++;
        }
    } 
    return 0;
}

static int DecodeTCPPacket(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    p->tcph = (TCPHdr *)pkt;

    if (len < TCP_HEADER_LEN) {
        DECODER_SET_EVENT(p, TCP_PKT_TOO_SMALL);
        return -1;
    }

    p->tcpvars.hlen = TCP_GET_HLEN(p);
    if (len < p->tcpvars.hlen) {
        DECODER_SET_EVENT(p, TCP_HLEN_TOO_SMALL);
        return -1;
    }

    SET_TCP_SRC_PORT(p,&p->sp);
    SET_TCP_DST_PORT(p,&p->dp);

    p->tcpvars.tcp_opt_len = p->tcpvars.hlen - TCP_HEADER_LEN;
    if (p->tcpvars.tcp_opt_len > TCP_OPTLENMAX) {
        DECODER_SET_EVENT(p, TCP_INVALID_OPTLEN);
        return -1;
    }

    if (p->tcpvars.tcp_opt_len > 0) {
        DecodeTCPOptions(t, p, pkt + TCP_HEADER_LEN, p->tcpvars.tcp_opt_len);
    }

    p->payload = pkt + p->tcpvars.hlen;
    p->payload_len = len - p->tcpvars.hlen;

    p->proto = IPPROTO_TCP;

    return 0;
}

void DecodeTCP(ThreadVars *t, Packet *p, uint8_t *pkt, uint16_t len)
{
    PerfCounterIncr(COUNTER_DECODER_TCP, t->pca);

    if (DecodeTCPPacket(t, p,pkt,len) < 0)
        return;

#ifdef DEBUG
    printf("TCP sp: %" PRIu32 " -> dp: %" PRIu32 " - HLEN: %" PRIu32 " LEN: %" PRIu32 " %s%s%s%s\n",
        GET_TCP_SRC_PORT(p), GET_TCP_DST_PORT(p), p->tcpvars.hlen, len,
        p->tcpvars.sackok ? "SACKOK " : "",
        p->tcpvars.ws ? "WS " : "",
        p->tcpvars.ts ? "TS " : "",
        p->tcpvars.mss ? "MSS " : "");
#endif

    /* Flow is an integral part of us */
    FlowHandlePacket(t, p);

    return;
}

