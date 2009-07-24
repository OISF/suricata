/* Copyright (c) 2009 Victor Julien */

#include "eidps.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream.h"

#define INSPECT_BYTES   64

#define PROTO_UNKNOWN   0
#define PROTO_HTTP      1
#define PROTO_FTP       2
#define PROTO_SMTP      3

static u_int8_t l7_proto_id = 0;

typedef struct _L7AppDetectDataProto {
    u_int8_t proto;
} L7AppDetectDataProto;

static Pool *l7appdetect_proto_pool = NULL;

void *L7AppDetectProtoAlloc(void *null) {
    L7AppDetectDataProto *d = malloc(sizeof(L7AppDetectDataProto));
    if (d == NULL) {
        return NULL;
    }

    d->proto = PROTO_UNKNOWN;
    return d;
}
#define L7AppDetectProtoFree free

void L7AppDetectThreadInit(void) {
    l7_proto_id = StreamL7RegisterModule(); 

    l7appdetect_proto_pool = PoolInit(262144, 32768, L7AppDetectProtoAlloc, NULL, L7AppDetectProtoFree);
    if (l7appdetect_proto_pool == NULL) {
        exit(1);
    }
}

u_int8_t L7AppDetectGetProto(u_int8_t *buf, u_int16_t buflen) {
    if (buflen < INSPECT_BYTES)
        return PROTO_UNKNOWN;

    /* XXX do actual detect */
    printf("L7AppDetectGetProto: protocol detection goes here.\n");
    return PROTO_HTTP;
}

void *L7AppDetectThread(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    char run = TRUE;

    /* get the stream msg queue for this thread */
    StreamMsgQueue *stream_q = StreamMsgQueueGetByPort(0);
    /* set the minimum size we expect */
    StreamMsgQueueSetMinInitChunkLen(stream_q, FLOW_PKT_TOSERVER, INSPECT_BYTES);
    StreamMsgQueueSetMinInitChunkLen(stream_q, FLOW_PKT_TOCLIENT, INSPECT_BYTES);

    /* main loop */
    while(run) {
        /* grab a msg, can return NULL on signals */
        StreamMsg *smsg = StreamMsgGetFromQueue(stream_q);
        if (smsg != NULL) {
            /* keep the flow locked during operation.
             * XXX we may be better off adding a mutex
             *     to the l7data object */
            mutex_lock(&smsg->flow->m);

            TcpSession *ssn = smsg->flow->stream;
            if (ssn != NULL) {
                if (ssn->l7data == NULL) {
                    /* XXX we can use a pool here,
                       or make it part of the stream setup */
                    StreamL7DataPtrInit(ssn,StreamL7GetStorageSize());
                }
                void *l7_data_ptr = ssn->l7data[l7_proto_id];

                if (smsg->flags & STREAM_START) {
                    //printf("L7AppDetectThread: stream initializer (len %u (%u))\n", smsg->init.data_len, MSG_INIT_DATA_SIZE);

                    //printf("=> Init Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
                    //printf("=> Init Stream Data -- end\n");

                    if (l7_data_ptr == NULL) {
                        L7AppDetectDataProto *l7proto = (L7AppDetectDataProto *)PoolGet(l7appdetect_proto_pool);
                        if (l7proto != NULL) {
                            l7proto->proto = L7AppDetectGetProto(smsg->data.data, smsg->data.data_len);

                            /* store */
                            ssn->l7data[l7_proto_id] = (void *)l7proto;
                        }
                    }
                } else {
                    //printf("L7AppDetectThread: stream data (len %u (%u))\n", smsg->data.data_len, MSG_DATA_SIZE);

                    //printf("=> Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
                    //printf("=> Stream Data -- end\n");

                    /* if we don't have a data object here we are not getting it
                     * a start msg should have gotten us one */
                    if (l7_data_ptr != NULL) {
                        L7AppDetectDataProto *l7proto = (L7AppDetectDataProto *)l7_data_ptr;
                        printf("L7AppDetectThread: already established that the proto is %u\n", l7proto->proto);
                    } else {
                        printf("L7AppDetectThread: smsg not start, but no l7 data? Weird\n");
                    }
                }

                mutex_unlock(&smsg->flow->m);
            }

            /* return the used message to the queue */
            StreamMsgReturnToPool(smsg);
        }

        if (tv->flags & THV_KILL)
            run = 0;
    }

    pthread_exit((void *) 0);
}

