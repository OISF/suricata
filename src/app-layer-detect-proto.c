/* Copyright (c) 2009 Victor Julien */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  A simple application layer (L7) protocol detector. It works by allowing
 *  developers to set a series of patterns that if exactly matching indicate
 *  that the session is a certain protocol.
 *
 *  \todo More advanced detection methods, regex maybe.
 *  \todo Fall back to port based classification if other detection fails.
 */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "tm-modules.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-content.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#define INSPECT_BYTES  32
#define ALP_DETECT_MAX 256

typedef struct AlpProtoDetectDirectionThread_ {
    MpmThreadCtx mpm_ctx;
    PatternMatcherQueue pmq;
} AlpProtoDetectDirectionThread;

typedef struct AlpProtoDetectDirection_ {
    MpmCtx mpm_ctx;
    uint32_t id;
    /** a mapping between condition id's and protocol */
    uint16_t map[ALP_DETECT_MAX];
} AlpProtoDetectDirection;

typedef struct AlpProtoDetectThreadCtx_ {
    AlpProtoDetectDirectionThread toserver;
    AlpProtoDetectDirectionThread toclient;
} AlpProtoDetectThreadCtx;

typedef struct AlpProtoDetectCtx_ {
    AlpProtoDetectDirection toserver;
    AlpProtoDetectDirection toclient;
} AlpProtoDetectCtx;

static AlpProtoDetectCtx alp_proto_ctx;
static AlpProtoDetectThreadCtx alp_proto_tctx;


void AlpProtoInit(AlpProtoDetectCtx *ctx) {
    memset(ctx, 0x00, sizeof(AlpProtoDetectCtx));

    MpmInitCtx(&ctx->toserver.mpm_ctx, MPM_B2G);
    MpmInitCtx(&ctx->toclient.mpm_ctx, MPM_B2G);

    memset(&ctx->toserver.map, 0x00, sizeof(ctx->toserver.map));
    memset(&ctx->toclient.map, 0x00, sizeof(ctx->toclient.map));

    ctx->toserver.id = 0;
    ctx->toclient.id = 0;
}

void AlpProtoDestroy(AlpProtoDetectCtx *ctx) {
    ctx->toserver.mpm_ctx.DestroyCtx(&ctx->toserver.mpm_ctx);
    ctx->toclient.mpm_ctx.DestroyCtx(&ctx->toclient.mpm_ctx);
}

/** \brief Add a proto detection string to the detection ctx.
 *  \param ctx The detection ctx
 *  \param ip_proto The IP proto (TCP, UDP, etc)
 *  \param al_proto Application layer proto
 *  \param content A content string in the 'content:"some|20|string"' format.
 *  \param depth Depth setting for the content. E.g. 4 means that the content has to match in the first 4 bytes of the stream.
 *  \param offset Offset setting for the content. E.g. 4 mean that the content has to match after the first 4 bytes of the stream.
 *  \param flags Set STREAM_TOCLIENT or STREAM_TOSERVER for the direction in which to try to match the content.
 */
void AlpProtoAdd(AlpProtoDetectCtx *ctx, uint16_t ip_proto, uint16_t al_proto, char *content, uint16_t depth, uint16_t offset, uint8_t flags) {
    DetectContentData *cd = DetectContentParse(content);
    if (cd == NULL) {
        return;
    }
    cd->depth = depth;
    cd->offset = offset;

    //PrintRawDataFp(stdout,cd->content,cd->content_len);

    AlpProtoDetectDirection *dir;
    if (flags & STREAM_TOCLIENT) {
        dir = &ctx->toclient;
    } else {
        dir = &ctx->toserver;
    }

    dir->mpm_ctx.AddScanPattern(&dir->mpm_ctx, cd->content, cd->content_len,
                                cd->offset, cd->depth, dir->id, dir->id, 0);
    dir->map[dir->id] = al_proto;
    dir->id++;

    /* no longer need the cd */
    DetectContentFree(cd);
}

void AlpProtoFinalizeThread(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx) {
    uint32_t maxid;
    memset(tctx, 0x00, sizeof(AlpProtoDetectThreadCtx));

    if (ctx->toclient.id > 0) {
        maxid = ctx->toclient.id;
        ctx->toclient.mpm_ctx.InitThreadCtx(&ctx->toclient.mpm_ctx, &tctx->toclient.mpm_ctx, maxid);
        PmqSetup(&tctx->toclient.pmq, maxid);
    }
    if (ctx->toserver.id > 0) {
        maxid = ctx->toserver.id;
        ctx->toserver.mpm_ctx.InitThreadCtx(&ctx->toserver.mpm_ctx, &tctx->toserver.mpm_ctx, maxid);
        PmqSetup(&tctx->toserver.pmq, maxid);
    }
}

void AlpProtoFinalizeGlobal(AlpProtoDetectCtx *ctx) {
    if (ctx == NULL)
        return;

    ctx->toclient.mpm_ctx.Prepare(&ctx->toclient.mpm_ctx);
    ctx->toserver.mpm_ctx.Prepare(&ctx->toserver.mpm_ctx);
}

void AppLayerDetectProtoThreadInit(void) {
    AlpProtoInit(&alp_proto_ctx);

    /** \todo register these in the protocol parser api */

    /** HTTP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);

    /** SSH */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SSH, "SSH-", 4, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SSH, "SSH-", 4, 0, STREAM_TOSERVER);

    /** SSLv2 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SSL, "|01 03 00|", 5, 2, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SSL, "|16 03 00|", 5, 2, STREAM_TOSERVER);

    /** SSLv3 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|01 03 00|", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 00|", 3, 0, STREAM_TOSERVER); /* client hello */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 00|", 3, 0, STREAM_TOCLIENT); /* server hello */
    /** TLSv1 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|01 03 01|", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 01|", 3, 0, STREAM_TOSERVER); /* client hello */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 01|", 3, 0, STREAM_TOCLIENT); /* server hello */
    /** TLSv1.1 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|01 03 02|", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 02|", 3, 0, STREAM_TOSERVER); /* client hello */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 02|", 3, 0, STREAM_TOCLIENT); /* server hello */
    /** TLSv1.2 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|01 03 03|", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 03|", 3, 0, STREAM_TOSERVER); /* client hello */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_TLS, "|16 03 03|", 3, 0, STREAM_TOCLIENT); /* server hello */

    /** IMAP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "|2A 20|OK|20|", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_IMAP, "1|20|capability", 12, 0, STREAM_TOSERVER);

    /** SMTP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "EHLO ", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "HELO ", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "ESMTP ", 64, 4, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "SMTP ", 64, 4, STREAM_TOSERVER);

    /** FTP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "USER ", 5, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "AUTH SSL", 8, 0, STREAM_TOCLIENT);

    /** MSN Messenger */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOSERVER);

    /** Jabber */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOSERVER);

    AlpProtoFinalizeGlobal(&alp_proto_ctx);
    AlpProtoFinalizeThread(&alp_proto_ctx, &alp_proto_tctx);
}

uint16_t AppLayerDetectGetProto(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx, uint8_t *buf, uint16_t buflen, uint8_t flags) {
    //printf("AppLayerDetectGetProto: start\n");
    //PrintRawDataFp(stdout, buf, buflen);

    //if (buflen < INSPECT_BYTES)
    //    return ALPROTO_UNKNOWN;

    AlpProtoDetectDirection *dir;
    AlpProtoDetectDirectionThread *tdir;
    if (flags & STREAM_TOSERVER) {
        dir = &ctx->toserver;
        tdir = &tctx->toserver;
    } else {
        dir = &ctx->toclient;
        tdir = &tctx->toclient;
    }

    if (dir->id == 0)
        return ALPROTO_UNKNOWN;

    uint16_t proto;
    uint32_t cnt = dir->mpm_ctx.Scan(&dir->mpm_ctx, &tdir->mpm_ctx, &tdir->pmq, buf, buflen);
    //printf("AppLayerDetectGetProto: scan cnt %" PRIu32 "\n", cnt);
    if (cnt == 0) {
        proto = ALPROTO_UNKNOWN;
        goto end;
    }

    /** We just return the first match
     *  \todo what if we have more? */
    proto = dir->map[tdir->pmq.sig_id_array[0]];

end:
    PmqReset(&tdir->pmq);

    if (dir->mpm_ctx.Cleanup != NULL) {
        dir->mpm_ctx.Cleanup(&tdir->mpm_ctx);
    }
//#define DEBUG
#ifdef DEBUG
    printf("AppLayerDetectGetProto: returning %" PRIu16 " (%s): ", proto, flags & STREAM_TOCLIENT ? "TOCLIENT" : "TOSERVER");
    switch (proto) {
        case ALPROTO_HTTP:
            printf("HTTP: ");
            /* print the first 32 bytes */
            if (buflen > 0) {
                PrintRawUriFp(stdout,buf,(buflen>32)?32:buflen);
            }
            printf("\n");
            break;
        case ALPROTO_FTP:
            printf("FTP\n");
            break;
        case ALPROTO_SSL:
            printf("SSL\n");
            break;
        case ALPROTO_SSH:
            printf("SSH\n");
            break;
        case ALPROTO_TLS:
            printf("TLS\n");
            break;
        case ALPROTO_IMAP:
            printf("IMAP\n");
            break;
        case ALPROTO_SMTP:
            printf("SMTP\n");
            break;
        case ALPROTO_JABBER:
            printf("JABBER\n");
            break;
        case ALPROTO_MSN:
            printf("MSN\n");
            break;
        case ALPROTO_UNKNOWN:
        default:
            printf("UNKNOWN (%u): cnt was %u (", proto, cnt);
            /* print the first 32 bytes */
            if (buflen > 0) {
                PrintRawUriFp(stdout,buf,(buflen>32)?32:buflen);
            }
            printf(")\n");
            break;
    }
#endif
    return proto;
}

void *AppLayerDetectProtoThread(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    char run = TRUE;
    uint16_t alproto = ALPROTO_UNKNOWN;

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
            TcpSession *ssn = smsg->flow->protoctx;
            if (ssn != NULL) {
                alproto = ssn->alproto;
            }
            mutex_unlock(&smsg->flow->m);

            if (ssn != NULL) {
                if (smsg->flags & STREAM_START) {
                    //printf("L7AppDetectThread: stream initializer (len %" PRIu32 " (%" PRIu32 "))\n", smsg->data.data_len, MSG_DATA_SIZE);

                    //printf("=> Init Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
                    //printf("=> Init Stream Data -- end\n");

                    alproto = AppLayerDetectGetProto(&alp_proto_ctx, &alp_proto_tctx, smsg->data.data, smsg->data.data_len, smsg->flags);
                    if (alproto != ALPROTO_UNKNOWN) {
                        /* store the proto and setup the L7 data array */
                        mutex_lock(&smsg->flow->m);
                        StreamL7DataPtrInit(ssn,StreamL7GetStorageSize());
                        ssn->alproto = alproto;
                        mutex_unlock(&smsg->flow->m);

                        AppLayerParse(smsg->flow, alproto, smsg->flags, smsg->data.data, smsg->data.data_len);
                    }
                } else {
                    //printf("AppLayerDetectThread: stream data (len %" PRIu32 " (%" PRIu32 ")), alproto %"PRIu16"\n", smsg->data.data_len, MSG_DATA_SIZE, alproto);

                    //printf("=> Stream Data -- start\n");
                    //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
                    //printf("=> Stream Data -- end\n");

                    /* if we don't have a data object here we are not getting it
                     * a start msg should have gotten us one */
                    if (alproto != ALPROTO_UNKNOWN) {
                        AppLayerParse(smsg->flow, alproto, smsg->flags, smsg->data.data, smsg->data.data_len);
                    } else {
                        //printf("AppLayerDetectThread: smsg not start, but no l7 data? Weird\n");
                    }
                }
            }

            mutex_lock(&smsg->flow->m);
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

    tv_applayerdetect = TmThreadCreateMgmtThread("AppLayerDetectProtoThread",
                                                 AppLayerDetectProtoThread, 0);
    if (tv_applayerdetect == NULL) {
        printf("ERROR: TmThreadsCreate failed\n");
        exit(1);
    }
    if (TmThreadSpawn(tv_applayerdetect) != 0) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

    printf("AppLayerDetectProtoThread thread created\n");
    return;
}

#ifdef UNITTESTS

int AlpDetectTest01(void) {
    char *buf = strdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    buf = strdup("GET");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOSERVER);
    if (ctx.toserver.id != 1) {
        r = 0;
    }
    free(buf);

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest02(void) {
    char *buf = strdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = strdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest03(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = strdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = strdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint32_t cnt = ctx.toclient.mpm_ctx.Scan(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
    if (cnt != 1) {
        printf("cnt %u != 1: ", cnt);
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest04(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = strdup("200 ");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint32_t cnt = ctx.toclient.mpm_ctx.Scan(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
    if (cnt != 0) {
        printf("cnt %u != 0: ", cnt);
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest05(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n<HTML><BODY>Blahblah</BODY></HTML>";
    char *buf = strdup("HTTP");
    int r = 1;

    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = strdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest06(void) {
    uint8_t l7data[] = "220 Welcome to the OISF FTP server\r\n";
    char *buf = strdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = strdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_FTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_FTP);
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

int AlpDetectTest07(void) {
    uint8_t l7data[] = "220 Welcome to the OISF HTTP/FTP server\r\n";
    char *buf = strdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    free(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_UNKNOWN) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_UNKNOWN);
        r = 0;
    }

    AlpProtoDestroy(&ctx);
    return r;
}

void AlpDetectRegisterTests(void) {
    UtRegisterTest("AlpDetectTest01", AlpDetectTest01, 1);
    UtRegisterTest("AlpDetectTest02", AlpDetectTest02, 1);
    UtRegisterTest("AlpDetectTest03", AlpDetectTest03, 1);
    UtRegisterTest("AlpDetectTest04", AlpDetectTest04, 1);
    UtRegisterTest("AlpDetectTest05", AlpDetectTest05, 1);
    UtRegisterTest("AlpDetectTest06", AlpDetectTest06, 1);
    UtRegisterTest("AlpDetectTest07", AlpDetectTest07, 1);
}

#endif /* UNITTESTS */

