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

#define TYPE_PROTO      0
#define TYPE_BUF        1

/* XXX type can be 1 bit, 7 bit for proto */
typedef struct _L7AppDetectDataProto {
    u_int8_t type;
    u_int8_t proto;
} L7AppDetectDataProto;

static Pool *l7appdetect_proto_pool = NULL;

void *L7AppDetectProtoAlloc(void *null) {
    L7AppDetectDataProto *d = malloc(sizeof(L7AppDetectDataProto));
    if (d == NULL) {
        return NULL;
    }

    d->type = TYPE_PROTO;
    d->proto = PROTO_UNKNOWN;
    return d;
}
#define L7AppDetectProtoFree free

void L7AppDetectThreadInit(void) {
    /* allocate 2 pools, 1 for proto objects, 1 for bufs. Normal stream will
     * jump straigth to protos so we alloc a lot less bufs */
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
    u_int8_t l7_data_id = 0;

    /* get the stream msg queue for this thread */
    StreamMsgQueue *stream_q = StreamMsgQueueGetByPort(0);
    StreamMsgQueueSetMinInitChunkLen(stream_q, INSPECT_BYTES);

    while(run) {
        /* grab a msg, can return NULL on signals */
        StreamMsg *smsg = StreamMsgGetFromQueue(stream_q);
        //printf("L7AppDetectThread: smsg %p\n", smsg);

        if (smsg != NULL) {
            /* keep the flow locked during operation.
             * XXX we may be better off adding a mutex
             *     to the l7data object */
            mutex_lock(&smsg->flow->m);

            TcpSession *ssn = smsg->flow->stream;
            if (ssn != NULL) {
                if (ssn->l7data == NULL) {
                    StreamL7DataPtrInit(ssn,1); /* XXX we can use a pool here,
                                                   or make it part of the stream setup */
                }
                void *l7_data_ptr = ssn->l7data[l7_data_id];

                if (smsg->flags & STREAM_START) {
                    //printf("L7AppDetectThread: stream initializer (len %u (%u))\n", smsg->init.data_len, MSG_INIT_DATA_SIZE);

                    //printf("=> Init Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
                    //printf("=> Init Stream Data -- end\n");

                    if (l7_data_ptr == NULL) {
                        L7AppDetectDataProto *l7proto = (L7AppDetectDataProto *)PoolGet(l7appdetect_proto_pool);
                        if (l7proto != NULL) {
                            l7proto->type = TYPE_PROTO;
                            l7proto->proto = L7AppDetectGetProto(smsg->data.data, smsg->data.data_len);

                            ssn->l7data[l7_data_id] = (void *)l7proto;
                        }
                    }
                } else {
                    //printf("L7AppDetectThread: stream data (len %u (%u))\n", smsg->data.data_len, MSG_DATA_SIZE);

                    /* if we don't have a data object here we are not getting it
                     * a start msg should have gotten us one */
                    if (l7_data_ptr != NULL) {
                        L7AppDetectDataProto *l7proto = (L7AppDetectDataProto *)l7_data_ptr;
                        printf("L7AppDetectThread: already established that the proto is %u\n", l7proto->proto);
                    } else {
                        printf("L7AppDetectThread: smsg not start, but no l7 data? Weird\n");
                    }
                    //printf("=> Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
                    //printf("=> Stream Data -- end\n");
                }

                mutex_unlock(&smsg->flow->m);
            }
            StreamMsgReturnToPool(smsg);
        }

        if (tv->flags & THV_KILL)
            run = 0;
    }

    pthread_exit((void *) 0);
}

