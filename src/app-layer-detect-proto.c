/* Copyright (c) 2009 Victor Julien */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "tm-modules.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#define INSPECT_BYTES   32

static uint8_t al_proto_id = 0;

typedef struct AppLayerDetectProtoData_ {
    uint8_t proto;
} AppLayerDetectProtoData;

static Pool *al_detect_proto_pool = NULL;

void *AppLayerDetectProtoAlloc(void *null) {
    AppLayerDetectProtoData *d = malloc(sizeof(AppLayerDetectProtoData));
    if (d == NULL) {
        return NULL;
    }

    d->proto = ALPROTO_UNKNOWN;
    return d;
}
#define AppLayerDetectProtoFree free

void AppLayerDetectProtoThreadInit(void) {
    al_proto_id = StreamL7RegisterModule();

    al_detect_proto_pool = PoolInit(262144, 32768, AppLayerDetectProtoAlloc, NULL, AppLayerDetectProtoFree);
    if (al_detect_proto_pool == NULL) {
        exit(1);
    }
}

uint8_t AppLayerDetectGetProto(uint8_t *buf, uint16_t buflen) {
    if (buflen < INSPECT_BYTES)
        return ALPROTO_UNKNOWN;

    /* XXX do actual detect */
    //printf("AppLayerDetectGetProto: protocol detection goes here.\n");
    return ALPROTO_HTTP;
}

void *AppLayerDetectProtoThread(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    char run = TRUE;
    AppLayerDetectProtoData *al_proto = NULL;
    char store = 0;
    void *al_data_ptr = NULL;

    /* get the stream msg queue for this thread */
    StreamMsgQueue *stream_q = StreamMsgQueueGetByPort(0);
    /* set the minimum size we expect */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, INSPECT_BYTES);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, INSPECT_BYTES);

    /* main loop */
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* grab a msg, can return NULL on signals */
        StreamMsg *smsg = StreamMsgGetFromQueue(stream_q);
        if (smsg != NULL) {
            mutex_lock(&smsg->flow->m);
            TcpSession *ssn = smsg->flow->stream;
            if (ssn != NULL) {
                if (ssn->l7data == NULL) {
                    /* XXX we can use a pool here,
                       or make it part of the stream setup */
                    StreamL7DataPtrInit(ssn,StreamL7GetStorageSize());
                }
                al_data_ptr = ssn->l7data[al_proto_id];
            }
            mutex_unlock(&smsg->flow->m);

            if (al_data_ptr != NULL) {
                if (smsg->flags & STREAM_START) {
                    //printf("L7AppDetectThread: stream initializer (len %" PRIu32 " (%" PRIu32 "))\n", smsg->data.data_len, MSG_DATA_SIZE);

                    //printf("=> Init Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
                    //printf("=> Init Stream Data -- end\n");

                    if (al_data_ptr == NULL) {
                        al_proto = (AppLayerDetectProtoData *)PoolGet(al_detect_proto_pool);
                        if (al_proto != NULL) {
                            al_proto->proto = AppLayerDetectGetProto(smsg->data.data, smsg->data.data_len);
                            store = 1;

                            AppLayerParse(smsg->flow, al_proto->proto, smsg->flags, smsg->data.data, smsg->data.data_len);
                        }
                    }
                } else {
                    //printf("AppLayerDetectThread: stream data (len %" PRIu32 " (%" PRIu32 "))\n", smsg->data.data_len, MSG_DATA_SIZE);

                    //printf("=> Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
                    //printf("=> Stream Data -- end\n");

                    /* if we don't have a data object here we are not getting it
                     * a start msg should have gotten us one */
                    if (al_data_ptr != NULL) {
                        al_proto = (AppLayerDetectProtoData *)al_data_ptr;
//                        printf("AppLayerDetectThread: already established that the proto is %" PRIu32 "\n", al_proto->proto);

                        AppLayerParse(smsg->flow, al_proto->proto, smsg->flags, smsg->data.data, smsg->data.data_len);
                    } else {
//                        printf("AppLayerDetectThread: smsg not start, but no l7 data? Weird\n");
                    }
                }
            }

            mutex_lock(&smsg->flow->m);
            if (store == 1) {
                /* store */
                ssn->l7data[al_proto_id] = (void *)al_proto;
                store = 0;
            }
            /* XXX we need to improve this logic */
            smsg->flow->use_cnt--;
            mutex_unlock(&smsg->flow->m);
            /* return the used message to the queue */
            StreamMsgReturnToPool(smsg);
        }

        if (tv->flags & THV_KILL)
            run = 0;
    }

    pthread_exit((void *) 0);
}

void AppLayerDetectProtoThreadSpawn()
{
    ThreadVars *tv_applayerdetect = NULL;

    tv_applayerdetect = TmThreadCreate("AppLayerDetectProtoThread", NULL, NULL, NULL, NULL,
                                    "custom", AppLayerDetectProtoThread, 0);
    if (tv_applayerdetect == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_applayerdetect, TVT_PPT, THV_USE) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    printf("AppLayerDetectProtoThread thread created\n");
    return;
}

