/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
/*  2009 Gurvinder Singh <gurvindersinghdahiya@gmail.com>*/

#include "decode.h"


#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "eidps.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "threads.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "util-pool.h"
#include "util-unittest.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"

#include "stream.h"

int StreamTcp (ThreadVars *, Packet *, void *, PacketQueue *);
int StreamTcpThreadInit(ThreadVars *, void *, void **);
int StreamTcpThreadDeinit(ThreadVars *, void *);
void StreamTcpExitPrintStats(ThreadVars *, void *);
static int ValidReset(TcpSession * , Packet *);
static int StreamTcpHandleFin(TcpSession *, Packet *);
void StreamTcpStreamReturntoPool (Packet *);
void StreamTcpRegisterTests (void);

void *StreamTcpSessionAlloc(void *null) {
    void *ptr = malloc(sizeof(TcpSession));
    if (ptr == NULL)
        return NULL;

    memset(ptr, 0, sizeof(TcpSession));
    return ptr;
}

#define StreamTcpSessionFree  free

static Pool *ssn_pool;
static pthread_mutex_t ssn_pool_mutex;

void TmModuleStreamTcpRegister (void) {
    StreamTcpReassembleInit();

    tmm_modules[TMM_STREAMTCP].name = "StreamTcp";
    tmm_modules[TMM_STREAMTCP].Init = StreamTcpThreadInit;
    tmm_modules[TMM_STREAMTCP].Func = StreamTcp;
    tmm_modules[TMM_STREAMTCP].ExitPrintStats = StreamTcpExitPrintStats;
    tmm_modules[TMM_STREAMTCP].Deinit = StreamTcpThreadDeinit;
    tmm_modules[TMM_STREAMTCP].RegisterTests = StreamTcpRegisterTests;

    ssn_pool = PoolInit(262144, 32768, StreamTcpSessionAlloc, NULL, StreamTcpSessionFree);
    if (ssn_pool == NULL) {
        exit(1);
    }

    pthread_mutex_init(&ssn_pool_mutex, NULL);
}

typedef struct StreamTcpThread_ {
    u_int64_t pkts;
} StreamTcpThread;

/**
 *  \brief  Function to handle the TCP_CLOSED or NONE state. The function handles
 *          packets while the session state is None which means a newly
 *          initialized structure, or a fully closed session.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateNone(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    switch (p->tcph->th_flags) {
        case TH_SYN:
            /* get a stream */
            mutex_lock(&ssn_pool_mutex);
            p->flow->stream = PoolGet(ssn_pool);
            mutex_unlock(&ssn_pool_mutex);

            TcpSession *ssn = (TcpSession *)p->flow->stream;
            if (ssn == NULL)
                return -1;

            /* set the state */
            ssn->state = TCP_SYN_SENT;
            printf("StreamTcpPacketStateNone (%p): =~ ssn state is now TCP_SYN_SENT\n", ssn);

            /* set the sequence numbers and window */
            ssn->client.isn = TCP_GET_SEQ(p);
            ssn->client.ra_base_seq = ssn->client.isn;
            ssn->client.next_seq = ssn->client.isn + 1;
            ssn->client.window = TCP_GET_WINDOW(p);

            //ssn->server.last_ack = ssn->client.isn + 1;
            //ssn->server.last_ack = TCP_GET_ACK(p);

            printf("StreamTcpPacketStateNone (%p): ssn->client.isn %u, ssn->client.next_seq %u, ssn->SERVER.last_ack %u\n",
                    ssn, ssn->client.isn, ssn->client.next_seq, ssn->server.last_ack);

            if (p->tcpvars.ws != NULL) {
                printf("StreamTcpPacketStateNone (%p): p->tcpvars.ws %p, %02x\n", ssn, p->tcpvars.ws, *p->tcpvars.ws->data);
                ssn->client.wscale = *p->tcpvars.ws->data;
            }
            break;
        default:
            printf("StreamTcpPacketStateNone: default case\n");
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_SYN_SENT state. The function handles
 *          SYN, SYN/ACK, RSTpackets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynSent(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            printf("StreamTcpPacketStateSynSent (%p): SYN packet on state SYN_SENT... resent\n", ssn);
            break;
        case TH_SYN|TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateSynSent (%p): SYN/ACK received in the wrong direction\n", ssn);
                return -1;
            }

            /* Check if the SYN/ACK packet ack's the earlier
             * received SYN packet. */
            if (!(SEQ_EQ(TCP_GET_ACK(p), ssn->client.isn + 1))) {
                printf("StreamTcpPacketStateSynSent (%p): ACK mismatch, packet ACK %u != %u from stream\n",
                        ssn, TCP_GET_ACK(p), ssn->client.isn + 1);
                return -1;
            }

            /* update state */
            ssn->state = TCP_SYN_RECV;
            printf("StreamTcpPacketStateSynSent (%p): =~ ssn state is now TCP_SYN_RECV\n", ssn);

            /* sequence number & window */
            ssn->server.isn = TCP_GET_SEQ(p);
            ssn->server.ra_base_seq = ssn->server.isn;
            ssn->server.next_seq = ssn->server.isn + 1;
            ssn->server.window = TCP_GET_WINDOW(p);
            printf("StreamTcpPacketStateSynSent: (%p): window %u\n", ssn, ssn->server.window);

            ssn->client.last_ack = TCP_GET_ACK(p);
            ssn->server.last_ack = ssn->server.isn + 1;

            if (ssn->client.wscale != 0 && p->tcpvars.ws != NULL) {
                printf("StreamTcpPacketStateSynSent (%p): p->tcpvars.ws %p, %02x\n", ssn, p->tcpvars.ws, *p->tcpvars.ws->data);
                ssn->server.wscale = *p->tcpvars.ws->data;
            } else {
                ssn->client.wscale = 0;
            }

            ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
            printf("StreamTcpPacketStateSynSent (%p): next_win %u\n", ssn, ssn->server.next_win);

            printf("StreamTcpPacketStateSynSent (%p): ssn->server.isn %u, ssn->server.next_seq %u, ssn->CLIENT.last_ack %u\n",
                    ssn, ssn->server.isn, ssn->server.next_seq, ssn->client.last_ack);
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            /* seq should be 0, win should be 0, ack should be isn +1.
             * check Snort's stream4/5 for more security*/
            if(ValidReset(ssn, p)){
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.isn) && SEQ_EQ(TCP_GET_WINDOW(p), 0) && SEQ_EQ(TCP_GET_ACK(p), (ssn->client.isn + 1))) {
                    ssn->state = TCP_CLOSED;
                    StreamTcpStreamReturntoPool(p);
                }
            } else
                return -1;
            break;
        default:
            printf("StreamTcpPacketStateSynSent (%p): default case\n", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_SYN_RECV state. The function handles
 *          SYN, SYN/ACK, ACK, FIN, RST packets and correspondingly changes
 *          the connection state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateSynRecv(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            printf("StreamTcpPacketStateSynRecv (%p): SYN packet on state SYN_RECV... resent\n", ssn);
            break;
        case TH_SYN|TH_ACK:
            printf("StreamTcpPacketStateSynRecv (%p): SYN/ACK packet on state SYN_RECV... resent\n", ssn);
            break;
        case TH_ACK:
            if (PKT_IS_TOCLIENT(p)) {
                printf("StreamTcpPacketStateSynRecv (%p): ACK received in the wrong direction\n", ssn);
                return -1;
            }

            if (!(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq))) {
                printf("StreamTcpPacketStateSynRecv (%p): ACK received in the wrong direction\n", ssn);
                return -1;
            }

            printf("StreamTcpPacketStateSynRecv (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                    ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

            ssn->state = TCP_ESTABLISHED;
            printf("StreamTcpPacketStateSynRecv (%p): =~ ssn state is now TCP_ESTABLISHED\n", ssn);

            ssn->client.next_seq += p->payload_len;
            ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

            ssn->server.last_ack = TCP_GET_ACK(p);
            ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
            printf("StreamTcpPacketStateSynRecv (%p): next_win %u\n", ssn, ssn->client.next_win);
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                ssn->state = TCP_CLOSED;
                StreamTcpStreamReturntoPool(p);
            } else
                return -1;
            break;
        case TH_FIN:
            /*FIN is handled in the same way as in TCP_ESTABLISHED case */;
            if((StreamTcpHandleFin(ssn, p)) == -1)
                return -1;
            break;
        default:
            printf("StreamTcpPacketStateSynRecv (%p): default case\n", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_ESTABLISHED state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state. The function handles the data inside packets and call
 *          StreamTcpReassembleHandleSegment() to handle the reassembling.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateEstablished(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch (p->tcph->th_flags) {
        case TH_SYN:
            printf("StreamTcpPacketStateEstablished (%p): SYN packet on state ESTABLISED... resent\n", ssn);
            break;
        case TH_SYN|TH_ACK:
            printf("StreamTcpPacketStateEstablished (%p): SYN/ACK packet on state ESTABLISHED... resent\n", ssn);
            break;
        case TH_ACK:
        case TH_ACK|TH_PUSH:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateEstablished (%p): =+ pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_EQ(ssn->client.next_seq, TCP_GET_SEQ(p))) {
                    ssn->client.next_seq += p->payload_len;
                    printf("StreamTcpPacketStateEstablished (%p): ssn->client.next_seq %u\n", ssn, ssn->client.next_seq);
                }

                if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.last_ack) &&
                    SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->client.next_win)) {
    
                    ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                        ssn->server.last_ack = TCP_GET_ACK(p);

                    if (SEQ_GT(ssn->client.last_ack + ssn->client.window, ssn->client.next_win)) {
                        ssn->client.next_win = ssn->client.last_ack + ssn->client.window;
                        printf("StreamTcpPacketStateEstablished (%p): ssn->client.next_win %u\n", ssn, ssn->client.next_win);
                    }

                    StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);
                } else {
                    printf("StreamTcpPacketStateEstablished (%p): server !!!!! => SEQ mismatch, packet SEQ %u, payload size %u (%u), last_ack %u, next_win %u\n",
                            ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->client.last_ack, ssn->client.next_win);
                }
                printf("StreamTcpPacketStateEstablished (%p): next SEQ %u, last ACK %u, next win %u, win %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack, ssn->client.next_win, ssn->client.window);
            } else { /* implied to client */
                printf("StreamTcpPacketStateEstablished (%p): =+ pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_EQ(ssn->server.next_seq, TCP_GET_SEQ(p))) {
                    ssn->server.next_seq += p->payload_len;
                    printf("StreamTcpPacketStateEstablished (%p): ssn->server.next_seq %u\n", ssn, ssn->server.next_seq);
                }

                if (SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.last_ack) &&
                    SEQ_LEQ(TCP_GET_SEQ(p) + p->payload_len, ssn->server.next_win)) {

                    ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                        ssn->client.last_ack = TCP_GET_ACK(p);

                    if (SEQ_GT(ssn->server.last_ack + ssn->server.window, ssn->server.next_win)) {
                        ssn->server.next_win = ssn->server.last_ack + ssn->server.window;
                        printf("StreamTcpPacketStateEstablished (%p): ssn->server.next_win %u\n", ssn, ssn->server.next_win);
                    }

                    StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);
                } else {
                    printf("StreamTcpPacketStateEstablished (%p): client !!!!! => SEQ mismatch, packet SEQ %u, payload size %u (%u), last_ack %u, next_win %u\n",
                            ssn, TCP_GET_SEQ(p), p->payload_len, TCP_GET_SEQ(p) + p->payload_len, ssn->server.last_ack, ssn->server.next_win);
                }

                printf("StreamTcpPacketStateEstablished (%p): next SEQ %u, last ACK %u, next win %u, win %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack, ssn->server.next_win, ssn->server.window);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_PUSH:
            if((StreamTcpHandleFin(ssn, p)) == -1)
                return -1;
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                if(PKT_IS_TOSERVER(p)) {
                    printf("StreamTcpPacketStateEstablished (%p): Reset received and state changed to TCP_CLOSED\n", ssn);
                    ssn->state = TCP_CLOSED;
                    /*Similar remote application is closed, so jump to CLOSE_WAIT*/
                    ssn->client.next_seq = TCP_GET_ACK(p);
                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    printf("StreamTcpPacketStateEstablished (%p): ssn->server.next_seq %u\n", ssn, ssn->server.next_seq);
                    ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                        ssn->server.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                    printf("StreamTcpPacketStateEstablished (%p): =+ next SEQ %u, last ACK %u\n",
                            ssn, ssn->client.next_seq, ssn->server.last_ack);
                    StreamTcpStreamReturntoPool(p);
                } else {
                   printf("StreamTcpPacketStateEstablished (%p): Reset received and state changed to TCP_CLOSED\n", ssn);
                    ssn->state = TCP_CLOSED;
                    /*Similar remote application is closed, so jump to CLOSE_WAIT*/
                    ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
                    ssn->client.next_seq = TCP_GET_ACK(p);
                    printf("StreamTcpPacketStateEstablished (%p): ssn->server.next_seq %u\n", ssn, ssn->server.next_seq);
                    ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                    if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                        ssn->client.last_ack = TCP_GET_ACK(p);

                    StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                    printf("StreamTcpPacketStateEstablished (%p): =+ next SEQ %u, last ACK %u\n",
                            ssn, ssn->server.next_seq, ssn->client.last_ack);
                    StreamTcpStreamReturntoPool(p);
                }
            } else
                return -1;
            break;
         default:
            printf("StreamTcpPacketStateEstablished (%p): default case\n", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the FIN packets for states TCP_SYN_RECV and
 *          TCP_ESTABLISHED and changes to another TCP state as required.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpHandleFin(TcpSession *ssn, Packet *p) {

    if (PKT_IS_TOSERVER(p)) {
        printf("StreamTcpPacket (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window))) {
              printf("StreamTcpPacket (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                      ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
              return -1;
        }

        printf("StreamTcpPacket (%p): state changed to TCP_CLOSE_WAIT\n", ssn);
        ssn->state = TCP_CLOSE_WAIT;
        ssn->client.next_seq = TCP_GET_ACK(p);
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        printf("StreamTcpPacket (%p): ssn->server.next_seq %u\n", ssn, ssn->server.next_seq);
        ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

        if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
            ssn->server.last_ack = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

        printf("StreamTcpPacket (%p): =+ next SEQ %u, last ACK %u\n",
                ssn, ssn->client.next_seq, ssn->server.last_ack);
    } else { /* implied to client */
        printf("StreamTcpPacket (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

        if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
            printf("StreamTcpPacket (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                    ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
            return -1;
        }

        printf("StreamTcpPacket (%p): state changed to TCP_FIN_WAIT1\n", ssn);
        ssn->state = TCP_FIN_WAIT1;
        ssn->server.next_seq = TCP_GET_SEQ(p) + p->payload_len + 1;
        ssn->client.next_seq = TCP_GET_ACK(p);
        printf("StreamTcpPacket (%p): ssn->server.next_seq %u\n", ssn, ssn->server.next_seq);
        ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

        if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
        ssn->client.last_ack = TCP_GET_ACK(p);

        StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

        printf("StreamTcpPacket (%p): =+ next SEQ %u, last ACK %u\n",
                ssn, ssn->server.next_seq, ssn->client.last_ack);
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT1 state. The function handles
 *          ACK, FIN, RST packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait1(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch (p->tcph->th_flags) {
        case TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateFinWait1 (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));


                printf("StreamTcpPacketStateFinWait1 (%p): state changed to TCP_FIN_WAIT2\n", ssn);
                ssn->state = TCP_FIN_WAIT2;

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateFinWait1 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                printf("StreamTcpPacketStateFinWait1 (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                printf("StreamTcpPacketStateFinWait1 (%p): state changed to TCP_FIN_WAIT2\n", ssn);
                ssn->state = TCP_FIN_WAIT2;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateFinWait1 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_FIN:
        case TH_FIN|TH_ACK:
        case TH_FIN|TH_ACK|TH_PUSH:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateFinWait1 (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))) {
                    printf("StreamTcpPacketStateFinWait1 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait1 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateFinWait1 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                printf("StreamTcpPacketStateFinWait1 (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    printf("StreamTcpPacketStateFinWait1 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait1 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateFinWait1 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                printf("StreamTcpPacketStateFinWait1 (%p): Reset received state changed to TCP_CLOSED\n", ssn);
                ssn->state = TCP_CLOSED;
                StreamTcpStreamReturntoPool(p);
            }
            else
                return -1;
            break;
        default:
            printf("StreamTcpPacketStateFinWait1 (%p): default case\n", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_FIN_WAIT2 state. The function handles
 *          ACK, RST, FIN packets and correspondingly changes the connection
 *          state.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateFinWait2(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch (p->tcph->th_flags) {
        case TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateFinWait2 (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    printf("StreamTcpPacketStateFinWait2 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait2 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateFinWait2 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                printf("StreamTcpPacketStateFinWait2 (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    printf("StreamTcpPacketStateFinWait2 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait2 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateFinWait2 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        case TH_RST:
        case TH_RST|TH_ACK:
            if(ValidReset(ssn, p)) {
                printf("StreamTcpPacketStateFinWait2 (%p): Reset received state changed to TCP_CLOSED\n", ssn);
                ssn->state = TCP_CLOSED;
                StreamTcpStreamReturntoPool(p);
            }
            else
                return -1;
            break;
        case TH_FIN:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateFinWait2 (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->client.next_seq || SEQ_GT(TCP_GET_SEQ(p), (ssn->client.last_ack + ssn->client.window)))) {
                    printf("StreamTcpPacketStateFinWait2 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait2 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;

                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateFinWait2 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                printf("StreamTcpPacketStateFinWait2 (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    printf("StreamTcpPacketStateFinWait2 (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateFinWait2 (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateFinWait2 (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            printf("StreamTcpPacketStateFinWait2 (%p): default case\n", ssn);
            break;
    }

    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSING state. Upon arrival of ACK
 *          the connection goes to TCP_TIME_WAIT state. The state has been
 *          reached as both end application has been closed.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateClosing(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch(p->tcph->th_flags) {
        case TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateClosing (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    printf("StreamTcpPacketStateClosing (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateClosing (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateClosing (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
            } else { /* implied to client */
                printf("StreamTcpPacketStateClosing (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    printf("StreamTcpPacketStateClosing (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateClosing (%p): state changed to TCP_TIME_WAIT\n", ssn);
                ssn->state = TCP_TIME_WAIT;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateClosing (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            printf("StreamTcpPacketStateClosing (%p): default case\n", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_CLOSE_WAIT state. Upon arrival of FIN
 *          packet from server the connection goes to TCP_LAST_ACK state.
 *          The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateCloseWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch(p->tcph->th_flags) {
        case TH_FIN:
            if (PKT_IS_TOCLIENT(p)) {
                printf("StreamTcpPacketStateCloseWait (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (SEQ_LT(TCP_GET_SEQ(p), ssn->server.next_seq) || SEQ_GT(TCP_GET_SEQ(p), (ssn->server.last_ack + ssn->server.window))) {
                    printf("StreamTcpPacketStateCloseWait (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateCloseWait (%p): state changed to TCP_LAST_ACK\n", ssn);
                ssn->state = TCP_LAST_ACK;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateCloseWait (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
            }
            break;
        default:
            printf("StreamTcpPacketStateCloseWait (%p): default case\n", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_LAST_ACK state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool. The state is possible only for server host.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPakcetStateLastAck(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch(p->tcph->th_flags) {
        case TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateLastAck (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    printf("StreamTcpPacketStateLastAck (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateLastAck (%p): state changed to TCP_CLOSED\n", ssn);
                ssn->state = TCP_CLOSED;
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateLastAck (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
                StreamTcpStreamReturntoPool(p);
            }
            break;
        default:
            printf("StreamTcpPacketStateLastAck (%p): default case\n", ssn);
            break;
    }
    return 0;
}

/**
 *  \brief  Function to handle the TCP_TIME_WAIT state. Upon arrival of ACK
 *          the connection goes to TCP_CLOSED state and stream memory is
 *          returned back to pool.
 *
 *  \param  tv      Thread Variable containig  input/output queue, cpu affinity etc.
 *  \param  p       Packet which has to be handled in this TCP state.
 *  \param  stt     Strean Thread module registered to handle the stream handling
 */

static int StreamTcpPacketStateTimeWait(ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    switch(p->tcph->th_flags) {
        case TH_ACK:
            if (PKT_IS_TOSERVER(p)) {
                printf("StreamTcpPacketStateTimeWait (%p): pkt (%u) is to server: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->client.next_seq) {
                    printf("StreamTcpPacketStateTimeWait (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->client.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateTimeWait (%p): state changed to TCP_CLOSED\n", ssn);
                ssn->state = TCP_CLOSED;
                ssn->client.window = TCP_GET_WINDOW(p) << ssn->client.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->server.last_ack))
                    ssn->server.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->client, p);

                printf("StreamTcpPacketStateTimeWait (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->client.next_seq, ssn->server.last_ack);
                StreamTcpStreamReturntoPool(p);
            } else {
                printf("StreamTcpPacketStateTimeWait (%p): pkt (%u) is to client: SEQ %u, ACK %u\n",
                        ssn, p->payload_len, TCP_GET_SEQ(p), TCP_GET_ACK(p));

                if (TCP_GET_SEQ(p) != ssn->server.next_seq) {
                    printf("StreamTcpPacketStateTimeWait (%p): -> SEQ mismatch, packet SEQ %u != %u from stream\n",
                            ssn, TCP_GET_SEQ(p), ssn->server.next_seq);
                    return -1;
                }

                printf("StreamTcpPacketStateTimeWait (%p): state changed to TCP_CLOSED\n", ssn);
                ssn->state = TCP_CLOSED;
                ssn->server.window = TCP_GET_WINDOW(p) << ssn->server.wscale;

                if (SEQ_GT(TCP_GET_ACK(p),ssn->client.last_ack))
                    ssn->client.last_ack = TCP_GET_ACK(p);

                StreamTcpReassembleHandleSegment(ssn, &ssn->server, p);

                printf("StreamTcpPacketStateTimeWait (%p): =+ next SEQ %u, last ACK %u\n",
                        ssn, ssn->server.next_seq, ssn->client.last_ack);
                StreamTcpStreamReturntoPool(p);
            }
            break;
        default:
            printf("StreamTcpPacketStateTimeWait (%p): default case\n", ssn);
            break;

    }
    return 0;
}

/* flow is and stays locked */
static int StreamTcpPacket (ThreadVars *tv, Packet *p, StreamTcpThread *stt) {
    TcpSession *ssn = (TcpSession *)p->flow->stream;

    if (ssn == NULL || ssn->state == 0 || ssn->state == TCP_CLOSED) {
        StreamTcpPacketStateNone(tv, p, stt);
    } else {
        switch (ssn->state) {
            case TCP_SYN_SENT:
                StreamTcpPacketStateSynSent(tv, p, stt);
                break;
            case TCP_SYN_RECV:
                StreamTcpPacketStateSynRecv(tv, p, stt);
                break;
            case TCP_ESTABLISHED:
                StreamTcpPacketStateEstablished(tv, p, stt);
                break;
            case TCP_FIN_WAIT1:
                StreamTcpPacketStateFinWait1(tv, p, stt);
                break;
            case TCP_FIN_WAIT2:
                StreamTcpPacketStateFinWait2(tv, p, stt);
                break;
            case TCP_CLOSING:
                StreamTcpPacketStateClosing(tv, p, stt);
                break;
            case TCP_CLOSE_WAIT:
                StreamTcpPacketStateCloseWait(tv, p, stt);
                break;
            case TCP_LAST_ACK:
                StreamTcpPakcetStateLastAck(tv, p, stt);
                break;
            case TCP_TIME_WAIT:
                StreamTcpPacketStateTimeWait(tv, p, stt);
                break;
        }
    }

    return 0;
}

int StreamTcp (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;

    if (!(PKT_IS_TCP(p)))
        return 0;

    if (p->flow == NULL)
        return 0;

#if 0
    printf("StreamTcp: seq %u, ack %u, %s%s%s%s%s%s%s%s: ", TCP_GET_SEQ(p), TCP_GET_ACK(p),
        TCP_ISSET_FLAG_FIN(p) ? "FIN " :"",
        TCP_ISSET_FLAG_SYN(p) ? "SYN " :"",
        TCP_ISSET_FLAG_RST(p) ? "RST " :"",
        TCP_ISSET_FLAG_PUSH(p)? "PUSH ":"",
        TCP_ISSET_FLAG_ACK(p) ? "ACK " :"",
        TCP_ISSET_FLAG_URG(p) ? "URG " :"",
        TCP_ISSET_FLAG_RES2(p)? "RES2 ":"",
        TCP_ISSET_FLAG_RES1(p)? "RES1 ":"");
#endif

    mutex_lock(&p->flow->m);
    StreamTcpPacket(tv, p, stt);
    mutex_unlock(&p->flow->m);

    stt->pkts++;
    return 0;
}

int StreamTcpThreadInit(ThreadVars *t, void *initdata, void **data)
{
    StreamTcpThread *stt = malloc(sizeof(StreamTcpThread));
    if (stt == NULL) {
        return -1;
    }
    memset(stt, 0, sizeof(StreamTcpThread));

    /* XXX */

    *data = (void *)stt;
    return 0;
}

int StreamTcpThreadDeinit(ThreadVars *t, void *data)
{
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return 0;
    }

    /* XXX */

    /* clear memory */
    memset(stt, 0, sizeof(StreamTcpThread));

    free(stt);
    return 0;
}

void StreamTcpExitPrintStats(ThreadVars *tv, void *data) {
    StreamTcpThread *stt = (StreamTcpThread *)data;
    if (stt == NULL) {
        return;
    }

    printf(" - (%s) Packets %llu.\n", tv->name, stt->pkts);
}

/**
 *  \brief   Function to check the validity of the RST packets based on the target
 *          OS of the given packet.
 *
 *  \param   ssn    TCP session to which the given packet belongs
 *  \param   p      Packet which has to be checked for its validity
 */

static int ValidReset(TcpSession *ssn, Packet *p) {

    u_int8_t os_policy;
    if (PKT_IS_TOSERVER(p))
        os_policy = ssn->server.os_policy;
    else
        os_policy = ssn->client.os_policy;
    switch(os_policy) {
        case OS_POLICY_BSD:
        case OS_POLICY_FIRST:
        case OS_POLICY_HPUX10:
        case OS_POLICY_IRIX:
        case OS_POLICY_MACOS:
        case OS_POLICY_LAST:
        case OS_POLICY_WINDOWS:
        case OS_POLICY_WINDOWS2K3:
        case OS_POLICY_VISTA:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and server SEQ: %d", TCP_GET_SEQ(p), ssn->client.next_seq );
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_EQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and client SEQ: %d", TCP_GET_SEQ(p), ssn->server.next_seq );
                    return 0;
                }
            }
            break;
        case OS_POLICY_HPUX11:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->client.next_seq)) {
                    printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and server SEQ: %d", TCP_GET_SEQ(p), ssn->client.next_seq );
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ(TCP_GET_SEQ(p), ssn->server.next_seq)) {
                    printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                    return 1;
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and client SEQ: %d", TCP_GET_SEQ(p), ssn->server.next_seq );
                    return 0;
                }
            }
            break;
        case OS_POLICY_OLD_LINUX:
        case OS_POLICY_LINUX:
        case OS_POLICY_SOLARIS:
            if(PKT_IS_TOSERVER(p)){
                if(SEQ_GEQ((TCP_GET_SEQ(p)+p->payload_len), ssn->client.last_ack)) { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->client.next_seq + ssn->client.window))) {
                        printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and server SEQ: %d", TCP_GET_SEQ(p), ssn->client.next_seq );
                    return 0;
                }
            } else { /* implied to client */
                if(SEQ_GEQ((TCP_GET_SEQ(p) + p->payload_len), ssn->server.last_ack)) { /*window base is needed !!*/
                    if(SEQ_LT(TCP_GET_SEQ(p), (ssn->server.next_seq + ssn->server.window))) {
                        printf("Reset is Valid! Pakcet SEQ: %d", TCP_GET_SEQ(p));
                        return 1;
                    }
                } else {
                    printf("Reset is not Valid! Packet SEQ: %d and client SEQ: %d", TCP_GET_SEQ(p), ssn->server.next_seq );
                    return 0;
                }
            }
            break;
        default:
            printf("Reset is not Valid! Packet SEQ: %d", TCP_GET_SEQ(p));
            break;
    }
    return 0;
}

/**
 *  \brief   Function to return the stream back to the pool.
 *
 *  \param   p  Packet used to identify the stream.
 */

void StreamTcpStreamReturntoPool (Packet *p) {
    /* get a stream */
    mutex_lock(&ssn_pool_mutex);
    PoolReturn(ssn_pool, p->flow->stream);
    mutex_unlock(&ssn_pool_mutex);
    p->flow->stream = NULL;
}

/*static int StreamTcpReassembleTest01 (void) {

    TcpSession ssn;
    TcpStream cstream, sstream;
    Packet p;
    ThreadVars tv;
    Flow f;
    StreamTcpThread stt;
    TCPHdr tcph;
    u_int8_t payload[] = { 0x41, 0x41, 0x41 };

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&cstream, 0, sizeof(TcpStream));
    memset(&sstream, 0, sizeof(TcpStream));
    memset(&p, 0, sizeof(Packet));
    memset(&f, 0, sizeof(Flow));
    memset(&stt, 0, sizeof(StreamTcpThread));
    memset(&tcph, 0, sizeof(TCPHdr));
    cstream.os_policy = OS_POLICY_BSD;
    sstream.os_policy = OS_POLICY_BSD;
    //ssn.state = 0;
    ssn.client = cstream;
    ssn.server = sstream;
    ssn.client.isn = 10;
    ssn.server.isn = 30;
    f.stream = &ssn;
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    //p.src = Address"10.0.0.1";
    //p.dst = "10.0.0.2";
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;
    tcph.th_seq = htonl(10);
    tcph.th_win = 5480;
    tcph.th_flags = TH_SYN;
    p.tcph = &tcph;
    p.flowflags = FLOW_PKT_TOSERVER;
    p.flow = &f;
    printf("I am executing hello world!!\n");
    //for (i=0; i<39; i++) {
        //p = (Packet)pkts[i];
       StreamTcpPacket(&tv, &p, &stt);
    //}
       tcph.th_seq = htonl(30);
       tcph.th_ack = htonl(11);
       tcph.th_win = 5480;
       tcph.th_flags = TH_SYN|TH_ACK;
       p.tcph = &tcph;
       p.flowflags = FLOW_PKT_TOCLIENT;

       StreamTcpPacket(&tv, &p, &stt);
       tcph.th_seq = htonl(11);
       tcph.th_ack = htonl(31);
       tcph.th_win = 5480;
       tcph.th_flags = TH_ACK;
       p.tcph = &tcph;
       p.flowflags = FLOW_PKT_TOSERVER;

       StreamTcpPacket(&tv, &p, &stt);
       tcph.th_seq = htonl(12);
       tcph.th_ack = htonl(31);
       tcph.th_win = 5480;
       tcph.th_flags = TH_PUSH|TH_ACK;
       p.tcph = &tcph;
       //payload =
       p.payload = payload;
       p.payload_len = 3;
       p.flowflags = FLOW_PKT_TOSERVER;

       StreamTcpPacket(&tv, &p, &stt);


    return 1;
}
*/

void StreamTcpRegisterTests (void) {
#ifdef UNITTESTS
    //UtRegisterTest("StreamTcpReassembleTest01", StreamTcpReassembleTest01, 1);

    /* set up the reassembly tests as well */
    StreamTcpReassembleRegisterTests();
#endif /* UNITTESTS */
}

