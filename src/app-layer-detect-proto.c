/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *
 *  A simple application layer (L7) protocol detector. It works by allowing
 *  developers to set a series of patterns that if exactly matching indicate
 *  that the session is a certain protocol.
 *
 *  \todo More advanced detection methods, regex maybe.
 *  \todo Fall back to port based classification if other detection fails.
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"
#include "tm-modules.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "util-cuda.h"
#include "util-cuda-handlers.h"
#include "util-mpm-b2g-cuda.h"
#include "util-debug.h"

#define INSPECT_BYTES  32
#define ALP_DETECT_MAX 256

/* undef __SC_CUDA_SUPPORT__.  We will get back to this later.  Need to
 * analyze the performance of cuda support for app layer */
#undef __SC_CUDA_SUPPORT__

typedef struct AlpProtoDetectDirection_ {
    MpmCtx mpm_ctx;
    uint32_t id;
    uint16_t map[ALP_DETECT_MAX];   /**< a mapping between condition id's and
                                         protocol */
    uint16_t max_len;              /**< max length of all patterns, so we can
                                         limit the search */
    uint16_t min_len;              /**< min length of all patterns, so we can
                                         tell the stream engine to feed data
                                         to app layer as soon as it has min
                                         size data */
} AlpProtoDetectDirection;

typedef struct AlpProtoDetectCtx_ {
    AlpProtoDetectDirection toserver;
    AlpProtoDetectDirection toclient;

    int alp_content_module_handle;
} AlpProtoDetectCtx;

/** global app layer detection context */
static AlpProtoDetectCtx alp_proto_ctx;

/** \brief Initialize the app layer proto detection */
void AlpProtoInit(AlpProtoDetectCtx *ctx) {
    memset(ctx, 0x00, sizeof(AlpProtoDetectCtx));

#ifndef __SC_CUDA_SUPPORT__
    MpmInitCtx(&ctx->toserver.mpm_ctx, MPM_B2G, -1);
    MpmInitCtx(&ctx->toclient.mpm_ctx, MPM_B2G, -1);
#else
    ctx->alp_content_module_handle = SCCudaHlRegisterModule("SC_ALP_CONTENT_B2G_CUDA");
    MpmInitCtx(&ctx->toserver.mpm_ctx, MPM_B2G_CUDA, ctx->alp_content_module_handle);
    MpmInitCtx(&ctx->toclient.mpm_ctx, MPM_B2G_CUDA, ctx->alp_content_module_handle);
#endif

    memset(&ctx->toserver.map, 0x00, sizeof(ctx->toserver.map));
    memset(&ctx->toclient.map, 0x00, sizeof(ctx->toclient.map));

    ctx->toserver.id = 0;
    ctx->toclient.id = 0;
    ctx->toclient.min_len = INSPECT_BYTES;
    ctx->toserver.min_len = INSPECT_BYTES;
}

void AlpProtoTestDestroy(AlpProtoDetectCtx *ctx) {
    mpm_table[ctx->toserver.mpm_ctx.mpm_type].DestroyCtx(&ctx->toserver.mpm_ctx);
    mpm_table[ctx->toclient.mpm_ctx.mpm_type].DestroyCtx(&ctx->toclient.mpm_ctx);
}

void AlpProtoDestroy() {
    SCEnter();
    mpm_table[alp_proto_ctx.toserver.mpm_ctx.mpm_type].DestroyCtx(&alp_proto_ctx.toserver.mpm_ctx);
    mpm_table[alp_proto_ctx.toclient.mpm_ctx.mpm_type].DestroyCtx(&alp_proto_ctx.toclient.mpm_ctx);
    SCReturn;
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

    mpm_table[dir->mpm_ctx.mpm_type].AddPattern(&dir->mpm_ctx, cd->content, cd->content_len,
                                cd->offset, cd->depth, dir->id, dir->id, 0);
    dir->map[dir->id] = al_proto;
    dir->id++;

    if (depth > dir->max_len)
        dir->max_len = depth;

    /* set the min_len for the stream engine to set the min smsg size for app
       layer*/
    if (depth < dir->min_len)
        dir->min_len = depth;

    /* no longer need the cd */
    DetectContentFree(cd);
}

void AlpProtoFinalizeThread(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx) {
    uint32_t maxid;
    memset(tctx, 0x00, sizeof(AlpProtoDetectThreadCtx));

    if (ctx->toclient.id > 0) {
        maxid = ctx->toclient.id;
        mpm_table[ctx->toclient.mpm_ctx.mpm_type].InitThreadCtx(&ctx->toclient.mpm_ctx, &tctx->toclient.mpm_ctx, maxid);
        PmqSetup(&tctx->toclient.pmq, maxid);
    }
    if (ctx->toserver.id > 0) {
        maxid = ctx->toserver.id;
        mpm_table[ctx->toserver.mpm_ctx.mpm_type].InitThreadCtx(&ctx->toserver.mpm_ctx, &tctx->toserver.mpm_ctx, maxid);
        PmqSetup(&tctx->toserver.pmq, maxid);
    }
}

void AlpProtoDeFinalize2Thread(AlpProtoDetectThreadCtx *tctx) {
    if (alp_proto_ctx.toclient.id > 0) {
        mpm_table[alp_proto_ctx.toclient.mpm_ctx.mpm_type].DestroyThreadCtx
                    (&alp_proto_ctx.toclient.mpm_ctx, &tctx->toclient.mpm_ctx);
        /* XXX GS any idea why it is invalid free ?*/
        //PmqFree(&tctx->toclient.pmq);
    }
    if (alp_proto_ctx.toserver.id > 0) {
        mpm_table[alp_proto_ctx.toserver.mpm_ctx.mpm_type].DestroyThreadCtx
                    (&alp_proto_ctx.toserver.mpm_ctx, &tctx->toserver.mpm_ctx);
        //PmqFree(&tctx->toserver.pmq);
    }

}
/** \brief to be called by ReassemblyThreadInit
 *  \todo this is a hack, we need a proper place to store the global ctx */
void AlpProtoFinalize2Thread(AlpProtoDetectThreadCtx *tctx) {
    return AlpProtoFinalizeThread(&alp_proto_ctx, tctx);
}

void AlpProtoFinalizeGlobal(AlpProtoDetectCtx *ctx) {
    if (ctx == NULL)
        return;

    mpm_table[ctx->toclient.mpm_ctx.mpm_type].Prepare(&ctx->toclient.mpm_ctx);
    mpm_table[ctx->toserver.mpm_ctx.mpm_type].Prepare(&ctx->toserver.mpm_ctx);

#ifdef __SC_CUDA_SUPPORT__
    CUcontext context;
    if (SCCudaCtxPopCurrent(&context) == -1)
        exit(EXIT_FAILURE);
    if (B2gCudaStartDispatcherThreadAPC("SC_ALP_CONTENT_B2G_CUDA") == -1)
        exit(EXIT_FAILURE);
#endif

    /* tell the stream reassembler, that initially we only want chunks of size
       min_len */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, ctx->toclient.min_len);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, ctx->toserver.min_len);
}

void AppLayerDetectProtoThreadInit(void) {
    AlpProtoInit(&alp_proto_ctx);

    /** \todo register these in the protocol parser api */

    /** HTTP */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET|20|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET|09|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT|20|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT|09|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST|20|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST|09|", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HEAD|20|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HEAD|09|", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE|20|", 6, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE|09|", 6, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS|20|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS|09|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "CONNECT|20|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "CONNECT|09|", 8, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_HTTP, "HTTP/", 5, 0, STREAM_TOCLIENT);

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
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "USER ", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "PASS ", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "PORT ", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_FTP, "AUTH SSL", 8, 0, STREAM_TOCLIENT);

    /** MSN Messenger */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_MSN, "MSNP", 10, 6, STREAM_TOSERVER);

    /** Jabber */
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOCLIENT);
    //AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_JABBER, "xmlns='jabber|3A|client'", 74, 53, STREAM_TOSERVER);

    /** SMB */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOSERVER);

    /** SMB2 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOSERVER);

    /** SMB2 */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB2, "|fe 53 4d 42|", 4, 4, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMB2, "|fe 53 4d 42|", 4, 4, STREAM_TOSERVER);

    /** DCERPC */
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_DCERPC, "|05 00|", 2, 0, STREAM_TOCLIENT);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_DCERPC, "|05 00|", 2, 0, STREAM_TOSERVER);

    AlpProtoFinalizeGlobal(&alp_proto_ctx);
}

/** \brief Get the app layer proto based on a buffer
 *
 *  \param ctx Global app layer detection context
 *  \param tctx Thread app layer detection context
 *  \param buf Pointer to the buffer to inspect
 *  \param buflen Lenght of the buffer
 *  \param flags Flags.
 *
 *  \retval proto App Layer proto, or ALPROTO_UNKNOWN if unknown
 */
uint16_t AppLayerDetectGetProto(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx, uint8_t *buf, uint16_t buflen, uint8_t flags) {
    SCEnter();

    AlpProtoDetectDirection *dir;
    AlpProtoDetectDirectionThread *tdir;
    if (flags & STREAM_TOSERVER) {
        dir = &ctx->toserver;
        tdir = &tctx->toserver;
    } else {
        dir = &ctx->toclient;
        tdir = &tctx->toclient;
    }

    if (dir->id == 0) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    /* see if we can limit the data we inspect */
    uint16_t searchlen = buflen;
    if (searchlen > dir->max_len)
        searchlen = dir->max_len;

    uint16_t proto = ALPROTO_UNKNOWN;
    uint32_t cnt = 0;
#ifndef __SC_CUDA_SUPPORT__
    cnt = mpm_table[dir->mpm_ctx.mpm_type].Search(&dir->mpm_ctx,
                                                &tdir->mpm_ctx,
                                                &tdir->pmq, buf,
                                                searchlen);
#else
    Packet *p = SCMalloc(sizeof(Packet));
    if (p == NULL)
        goto end;
    memset(p, 0, sizeof(Packet));

    p->cuda_done = 0;
    p->cuda_free_packet = 1;
    p->cuda_search = 0;
    p->cuda_mpm_ctx = &dir->mpm_ctx;
    p->cuda_mtc = &tdir->mpm_ctx;
    p->cuda_pmq = &tdir->pmq;
    p->payload = buf;
    p->payload_len = searchlen;
    B2gCudaPushPacketTo_tv_CMB2_APC(p);
    SCMutexLock(&p->cuda_mutex_q);
    SCondWait(&p->cuda_cond_q, &p->cuda_mutex_q);
    p->cuda_done = 1;
    SCMutexUnlock(&p->cuda_mutex_q);
    cnt = p->cuda_matches;
#endif
    SCLogDebug("search cnt %" PRIu32 "", cnt);
    if (cnt == 0) {
        proto = ALPROTO_UNKNOWN;
        goto end;
    }

    /** We just return the first match
     *  \todo what if we have more? */
    proto = dir->map[tdir->pmq.sig_id_array[0]];

end:
    PmqReset(&tdir->pmq);

    if (mpm_table[dir->mpm_ctx.mpm_type].Cleanup != NULL) {
        mpm_table[dir->mpm_ctx.mpm_type].Cleanup(&tdir->mpm_ctx);
    }
#if 0
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
        case ALPROTO_SMB:
            printf("SMB\n");
            break;
        case ALPROTO_SMB2:
            printf("SMB2\n");
            break;
        case ALPROTO_DCERPC:
            printf("DCERPC\n");
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
    SCReturnUInt(proto);
}

/** \brief Handle a app layer message
 *
 *  If the protocol is yet unknown, the proto detection code is run first.
 *
 *  \param dp_ctx Thread app layer detect context
 *  \param smsg Stream message
 *
 *  \retval 0 ok
 *  \retval -1 error
 */
int AppLayerHandleMsg(AlpProtoDetectThreadCtx *dp_ctx, StreamMsg *smsg)
{
    SCEnter();
    uint16_t alproto = ALPROTO_UNKNOWN;
    int r = 0;

    TcpSession *ssn = smsg->flow->protoctx;
    if (ssn != NULL) {
        alproto = ssn->alproto;

        /* if we don't know the proto yet and we have received a stream
         * initializer message, we run proto detection.
         * We receive 2 stream init msgs (one for each direction) but we
         * only run the proto detection once. */
        if (alproto == ALPROTO_UNKNOWN && smsg->flags & STREAM_START) {
            SCLogDebug("Stream initializer (len %" PRIu32 " (%" PRIu32 "))",
                        smsg->data.data_len, MSG_DATA_SIZE);

            //printf("=> Init Stream Data -- start\n");
            //PrintRawDataFp(stdout, smsg->init.data, smsg->init.data_len);
            //printf("=> Init Stream Data -- end\n");

            alproto = AppLayerDetectGetProto(&alp_proto_ctx, dp_ctx,
                            smsg->data.data, smsg->data.data_len, smsg->flags);
            if (alproto != ALPROTO_UNKNOWN) {
                /* store the proto and setup the L7 data array */
                StreamL7DataPtrInit(ssn);
                ssn->alproto = alproto;
                ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;

                r = AppLayerParse(smsg->flow, alproto, smsg->flags,
                               smsg->data.data, smsg->data.data_len);
            } else {
                if (smsg->flags & STREAM_TOSERVER) {
                    if (smsg->data.data_len >= alp_proto_ctx.toserver.max_len) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                        StreamTcpSetSessionNoReassemblyFlag(ssn, 0);
                    }
                } else if (smsg->flags & STREAM_TOCLIENT) {
                    if (smsg->data.data_len >= alp_proto_ctx.toclient.max_len) {
                        ssn->flags |= STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED;
                        SCLogDebug("ALPROTO_UNKNOWN flow %p", smsg->flow);
                        StreamTcpSetSessionNoReassemblyFlag(ssn, 1);
                    }
                }
            }
        } else {
            SCLogDebug("stream data (len %" PRIu32 " (%" PRIu32 ")), alproto "
                      "%"PRIu16" (flow %p)", smsg->data.data_len, MSG_DATA_SIZE,
                      alproto, smsg->flow);

            //printf("=> Stream Data -- start\n");
            //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);
            //printf("=> Stream Data -- end\n");

            /* if we don't have a data object here we are not getting it
             * a start msg should have gotten us one */
            if (alproto != ALPROTO_UNKNOWN) {
                r = AppLayerParse(smsg->flow, alproto, smsg->flags,
                            smsg->data.data, smsg->data.data_len);
            } else {
                SCLogDebug(" smsg not start, but no l7 data? Weird");
            }
        }
    }

    /* flow is free again */
    smsg->flow->use_cnt--;

    /* return the used message to the queue */
    StreamMsgReturnToPool(smsg);

    SCReturnInt(r);
}

/* VJ Originally I thought of having separate app layer
 * handling threads, leaving this here in case we'll revisit that */
#if 0
void *AppLayerDetectProtoThread(void *td)
{
    ThreadVars *tv = (ThreadVars *)td;
    char run = TRUE;

    /* get the stream msg queue for this thread */
    StreamMsgQueue *stream_q = StreamMsgQueueGetByPort(0);
    /* set the minimum size we expect */
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOSERVER, INSPECT_BYTES);
    StreamMsgQueueSetMinInitChunkLen(FLOW_PKT_TOCLIENT, INSPECT_BYTES);

    TmThreadsSetFlag(tv, THV_INIT_DONE);

    /* main loop */
    while(run) {
        TmThreadTestThreadUnPaused(tv);

        /* grab a msg, can return NULL on signals */
        StreamMsg *smsg = StreamMsgGetFromQueue(stream_q);
        if (smsg != NULL) {
            AppLayerHandleMsg(smsg, TRUE);
        }

        if (TmThreadsCheckFlag(tv, THV_KILL)) {
            SCPerfUpdateCounterArray(tv->sc_perf_pca, &tv->sc_perf_pctx, 0);
            run = 0;
        }
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
    if (TmThreadSpawn(tv_applayerdetect) != TM_ECODE_OK) {
        printf("ERROR: TmThreadSpawn failed\n");
        exit(1);
    }

#ifdef DEBUG
    printf("AppLayerDetectProtoThread thread created\n");
#endif
    return;
}
#endif
#ifdef UNITTESTS

int AlpDetectTest01(void) {
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    buf = SCStrdup("GET");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOSERVER);
    if (ctx.toserver.id != 1) {
        r = 0;
    }
    SCFree(buf);

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest02(void) {
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest03(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
    if (cnt != 1) {
        printf("cnt %u != 1: ", cnt);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest04(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = SCStrdup("200 ");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
    if (cnt != 0) {
        printf("cnt %u != 0: ", cnt);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest05(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n<HTML><BODY>Blahblah</BODY></HTML>";
    char *buf = SCStrdup("HTTP");
    int r = 1;

    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

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

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest06(void) {
    uint8_t l7data[] = "220 Welcome to the OISF FTP server\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

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

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest07(void) {
    uint8_t l7data[] = "220 Welcome to the OISF HTTP/FTP server\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

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

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest08(void) {
    uint8_t l7data[] = "\x00\x00\x00\x85"  // NBSS
        "\xff\x53\x4d\x42\x72\x00\x00\x00" // SMB
        "\x00\x18\x53\xc8\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\xff\xfe\x00\x00\x00\x00"
        "\x00" // WordCount
        "\x62\x00" // ByteCount
        "\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20"
        "\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73"
        "\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c"
        "\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
        "\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";
    char *buf = SCStrdup("|ff|SMB");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_SMB, buf, 8, 4, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_SMB) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_SMB) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_SMB);
        r = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

int AlpDetectTest09(void) {
    uint8_t l7data[] =
        "\x00\x00\x00\x66" // NBSS
        "\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00" // SMB2
        "\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x24\x00\x01\x00x00\x00\x00\x00\x00\x00\x0\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02";

    char *buf = SCStrdup("|fe|SMB");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_SMB2, buf, 8, 4, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_SMB2) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_SMB2) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_SMB2);
        r = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif
    return r;
}

int AlpDetectTest10(void) {
    uint8_t l7data[] = "\x05\x00\x0b\x03\x10\x00\x00\x00\x48\x00\x00\x00"
        "\x00\x00\x00\x00\xd0\x16\xd0\x16\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00"
        "\x01\x00\xb8\x4a\x9f\x4d\x1c\x7d\xcf\x11\x86\x1e\x00\x20\xaf\x6e\x7c\x57"
        "\x00\x00\x00\x00\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10"
        "\x48\x60\x02\x00\x00\x00";
    char *buf = SCStrdup("|05 00|");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_DCERPC, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_DCERPC) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data,sizeof(l7data), STREAM_TOCLIENT);
    if (proto != ALPROTO_DCERPC) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_DCERPC);
        r = 0;
    }

#ifdef __SC_CUDA_SUPPORT__
    B2gCudaKillDispatcherThreadAPC();
    if (SCCudaHlPushCudaContextFromModule("SC_ALP_CONTENT_B2G_CUDA") == -1) {
        printf("Call to SCCudaHlPushCudaContextForModule() failed\n");
        return 0;
    }
#endif

    AlpProtoTestDestroy(&ctx);

#ifdef __SC_CUDA_SUPPORT__
    if (SCCudaCtxPopCurrent(NULL) == -1) {
        printf("Call to SCCudaCtxPopCurrent() failed\n");
        return 0;
    }
#endif

    return r;
}

/** \test why we still get http for connect... obviously because we also match on the reply, duh */
int AlpDetectTest11(void) {
    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);

    if (ctx.toserver.id != 6) {
        printf("ctx.toserver.id %u != 6: ", ctx.toserver.id);
        r = 0;
    }

    if (ctx.toserver.map[ctx.toserver.id - 1] != ALPROTO_HTTP) {
        printf("ctx.toserver.id %u != %u: ", ctx.toserver.map[ctx.toserver.id - 1],ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint8_t proto = AppLayerDetectGetProto(&ctx, &tctx, l7data, sizeof(l7data), STREAM_TOCLIENT);
    if (proto == ALPROTO_HTTP) {
        printf("proto %" PRIu8 " == %" PRIu8 ": ", proto, ALPROTO_HTTP);
        r = 0;
    }

    proto = AppLayerDetectGetProto(&ctx, &tctx, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER);
    if (proto != ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", proto, ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);
    return r;
}

#endif /* UNITTESTS */

void AlpDetectRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("AlpDetectTest01", AlpDetectTest01, 1);
    UtRegisterTest("AlpDetectTest02", AlpDetectTest02, 1);
    UtRegisterTest("AlpDetectTest03", AlpDetectTest03, 1);
    UtRegisterTest("AlpDetectTest04", AlpDetectTest04, 1);
    UtRegisterTest("AlpDetectTest05", AlpDetectTest05, 1);
    UtRegisterTest("AlpDetectTest06", AlpDetectTest06, 1);
    UtRegisterTest("AlpDetectTest07", AlpDetectTest07, 1);
    UtRegisterTest("AlpDetectTest08", AlpDetectTest08, 1);
    UtRegisterTest("AlpDetectTest09", AlpDetectTest09, 1);
    UtRegisterTest("AlpDetectTest10", AlpDetectTest10, 1);
    UtRegisterTest("AlpDetectTest11", AlpDetectTest11, 1);
#endif /* UNITTESTS */
}
