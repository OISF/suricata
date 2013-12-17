/* Copyright (C) 2007-2013 Open Information Security Foundation
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
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-mpm.h"
#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "flow.h"
#include "flow-util.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "util-spm.h"
#include "util-cuda.h"
#include "util-debug.h"

#include "conf.h"

#define INSPECT_BYTES  32
#define ASYNC_MAX 75000

/** global app layer detection context */
AlpProtoDetectCtx alp_proto_ctx;

/** \brief Initialize the app layer proto detection */
void AlpProtoInit(AlpProtoDetectCtx *ctx) {
    memset(ctx, 0x00, sizeof(AlpProtoDetectCtx));

    MpmInitCtx(&ctx->toserver.mpm_ctx, MPM_B2G);
    MpmInitCtx(&ctx->toclient.mpm_ctx, MPM_B2G);

    memset(&ctx->toserver.map, 0x00, sizeof(ctx->toserver.map));
    memset(&ctx->toclient.map, 0x00, sizeof(ctx->toclient.map));

    ctx->toserver.id = 0;
    ctx->toclient.id = 0;
    ctx->toclient.min_len = INSPECT_BYTES;
    ctx->toserver.min_len = INSPECT_BYTES;

    intmax_t value = 0;
    if ((ConfGetInt("app-layer.proto-detect.toclient-async-max", &value)) == 1) {
        if (value >= 0 && value <= 1048576) {
            ctx->toclient.async_max = (uint32_t)value;
        } else {
            ctx->toclient.async_max = (uint32_t)ASYNC_MAX;
        }
    } else {
        ctx->toclient.async_max = (uint32_t)ASYNC_MAX;
    }
    if ((ConfGetInt("app-layer.proto-detect.toserver-async-max", &value)) == 1) {
        if (value >= 0 && value <= 1048576) {
            ctx->toserver.async_max = (uint32_t)value;
        } else {
            ctx->toserver.async_max = (uint32_t)ASYNC_MAX;
        }
    } else {
        ctx->toserver.async_max = (uint32_t)ASYNC_MAX;
    }
    SCLogDebug("toclient.async_max %u toserver.async_max %u",
            ctx->toclient.async_max, ctx->toserver.async_max);

    ctx->mpm_pattern_id_store = MpmPatternIdTableInitHash();
}

/**
 *  \brief Turn a proto detection into a AlpProtoSignature and store it
 *         in the ctx.
 *
 *  \param ctx the contex
 *  \param co the content match
 *  \param proto the proto id
 *  \initonly
 */
static void AlpProtoAddSignature(AlpProtoDetectCtx *ctx, DetectContentData *co, uint16_t ip_proto, uint16_t proto) {
    AlpProtoSignature *s = SCMalloc(sizeof(AlpProtoSignature));
    if (unlikely(s == NULL)) {
        SCLogError(SC_ERR_FATAL, "Error allocating memory. Signature not loaded. Not enough memory so.. exiting..");
        exit(EXIT_FAILURE);
    }
    memset(s, 0x00, sizeof(AlpProtoSignature));

    s->ip_proto = ip_proto;
    s->proto = proto;
    s->co = co;

    if (ctx->head == NULL) {
        ctx->head = s;
    } else {
        s->next = ctx->head;
        ctx->head = s;
    }

    ctx->sigs++;
}

/** \brief free a AlpProtoSignature, recursively free any next sig */
static void AlpProtoFreeSignature(AlpProtoSignature *s)
{
    if (s == NULL)
        return;

    DetectContentFree(s->co);
    s->co = NULL;
    s->proto = 0;

    AlpProtoSignature *next_s = s->next;

    SCFree(s);

    AlpProtoFreeSignature(next_s);
}

/**
 *  \brief Match a AlpProtoSignature against a buffer
 *
 *  \param s signature
 *  \param buf pointer to buffer
 *  \param buflen length of the buffer
 *  \param ip_proto packet's ip_proto
 *
 *  \retval proto the detected proto or ALPROTO_UNKNOWN if no match
 */
static uint16_t AlpProtoMatchSignature(AlpProtoSignature *s, uint8_t *buf,
        uint16_t buflen, uint16_t ip_proto)
{
    SCEnter();
    uint16_t proto = ALPROTO_UNKNOWN;
    uint8_t *found = NULL;

    if (s->ip_proto != ip_proto) {
        goto end;
    }

    if (s->co->offset > buflen) {
        SCLogDebug("s->co->offset (%"PRIu16") > buflen (%"PRIu16")",
                s->co->offset, buflen);
        goto end;
    }

    if (s->co->depth > buflen) {
        SCLogDebug("s->co->depth (%"PRIu16") > buflen (%"PRIu16")",
                s->co->depth, buflen);
        goto end;
    }

    uint8_t *sbuf = buf + s->co->offset;
    uint16_t sbuflen = s->co->depth - s->co->offset;
    SCLogDebug("s->co->offset (%"PRIu16") s->co->depth (%"PRIu16")",
                s->co->offset, s->co->depth);

    if (s->co->flags & DETECT_CONTENT_NOCASE)
        found = SpmNocaseSearch(sbuf, sbuflen, s->co->content, s->co->content_len);
    else
        found = SpmSearch(sbuf, sbuflen, s->co->content, s->co->content_len);
    if (found != NULL)
        proto = s->proto;

end:
    SCReturnInt(proto);
}

/**
 *  \brief Add a proto detection string to the detection ctx.
 *
 *  \param ctx The detection ctx
 *  \param ip_proto The IP proto (TCP, UDP, etc)
 *  \param al_proto Application layer proto
 *  \param content A content string in the 'content:"some|20|string"' format.
 *  \param depth Depth setting for the content. E.g. 4 means that the content has to match in the first 4 bytes of the stream.
 *  \param offset Offset setting for the content. E.g. 4 mean that the content has to match after the first 4 bytes of the stream.
 *  \param flags Set STREAM_TOCLIENT or STREAM_TOSERVER for the direction in which to try to match the content.
 *  \param ci Pattern is case-insensitive.
 */
void AlpProtoAddPattern(AlpProtoDetectCtx *ctx, char *name, uint16_t ip_proto,
                        uint16_t al_proto, char *content, uint16_t depth,
                        uint16_t offset, uint8_t flags, uint8_t ci)
{
    if (al_proto_table[al_proto].name != NULL) {
        BUG_ON(strcmp(al_proto_table[al_proto].name, name) != 0);
    } else {
        al_proto_table[al_proto].name = name;
    }

    DetectContentData *cd = DetectContentParseEncloseQuotes(content);
    if (cd == NULL) {
        return;
    }
    cd->depth = depth;
    cd->offset = offset;

    cd->id = DetectContentGetId(ctx->mpm_pattern_id_store, cd);

    //PrintRawDataFp(stdout,cd->content,cd->content_len);
    SCLogDebug("cd->depth %"PRIu16" and cd->offset %"PRIu16" cd->id  %"PRIu32"",
            cd->depth, cd->offset, cd->id);

    AlpProtoDetectDirection *dir;
    if (flags & STREAM_TOCLIENT) {
        dir = &ctx->toclient;
    } else {
        dir = &ctx->toserver;
    }

    if (ci == 1) {
        cd->flags |= DETECT_CONTENT_NOCASE;
        MpmAddPatternCI(&dir->mpm_ctx, cd->content, cd->content_len,
                        cd->offset, cd->depth,
                        cd->id, cd->id, 0);
    } else {
        MpmAddPatternCS(&dir->mpm_ctx, cd->content, cd->content_len,
                        cd->offset, cd->depth,
                        cd->id, cd->id, 0);
    }

    BUG_ON(dir->id == ALP_DETECT_MAX);
    dir->map[dir->id] = al_proto;
    dir->id++;

    if (depth > dir->max_len)
        dir->max_len = depth;

    /* set the min_len for the stream engine to set the min smsg size for app
       layer*/
    if (depth < dir->min_len)
        dir->min_len = depth;

    /* finally turn into a signature and add to the ctx */
    AlpProtoAddSignature(ctx, cd, ip_proto, al_proto);
}


void AlpProtoAddCI(AlpProtoDetectCtx *ctx, char *name, uint16_t ip_proto,
                   uint16_t al_proto, char *content, uint16_t depth,
                   uint16_t offset, uint8_t flags)
{
    AlpProtoAddPattern(ctx, name, ip_proto, al_proto, content, depth,
                       offset, flags, 1);

    return;
}

void AlpProtoAdd(AlpProtoDetectCtx *ctx, char *name, uint16_t ip_proto,
                 uint16_t al_proto, char *content, uint16_t depth,
                 uint16_t offset, uint8_t flags)
{
    AlpProtoAddPattern(ctx, name, ip_proto, al_proto, content, depth,
                       offset, flags, 0);

    return;
}

#ifdef UNITTESTS
void AlpProtoTestDestroy(AlpProtoDetectCtx *ctx) {
    mpm_table[ctx->toserver.mpm_ctx.mpm_type].DestroyCtx(&ctx->toserver.mpm_ctx);
    mpm_table[ctx->toclient.mpm_ctx.mpm_type].DestroyCtx(&ctx->toclient.mpm_ctx);
    AlpProtoFreeSignature(ctx->head);
    AppLayerFreeProbingParsers(ctx->probing_parsers);
    ctx->probing_parsers = NULL;

    return;
}
#endif

void AlpProtoDestroy() {
    SCEnter();
    mpm_table[alp_proto_ctx.toserver.mpm_ctx.mpm_type].DestroyCtx(&alp_proto_ctx.toserver.mpm_ctx);
    mpm_table[alp_proto_ctx.toclient.mpm_ctx.mpm_type].DestroyCtx(&alp_proto_ctx.toclient.mpm_ctx);
    MpmPatternIdTableFreeHash(alp_proto_ctx.mpm_pattern_id_store);
    AlpProtoFreeSignature(alp_proto_ctx.head);
    AppLayerFreeProbingParsers(alp_proto_ctx.probing_parsers);
    alp_proto_ctx.probing_parsers = NULL;

    SCReturn;
}

void AlpProtoFinalizeThread(AlpProtoDetectCtx *ctx, AlpProtoDetectThreadCtx *tctx) {
    uint32_t sig_maxid = 0;
    uint32_t pat_maxid = ctx->mpm_pattern_id_store ? ctx->mpm_pattern_id_store->max_id : 0;

    memset(tctx, 0x00, sizeof(AlpProtoDetectThreadCtx));

    if (ctx->toclient.id > 0) {
        //sig_maxid = ctx->toclient.id;
        mpm_table[ctx->toclient.mpm_ctx.mpm_type].InitThreadCtx(&ctx->toclient.mpm_ctx, &tctx->toclient.mpm_ctx, sig_maxid);
        PmqSetup(&tctx->toclient.pmq, sig_maxid, pat_maxid);
    }
    if (ctx->toserver.id > 0) {
        //sig_maxid = ctx->toserver.id;
        mpm_table[ctx->toserver.mpm_ctx.mpm_type].InitThreadCtx(&ctx->toserver.mpm_ctx, &tctx->toserver.mpm_ctx, sig_maxid);
        PmqSetup(&tctx->toserver.pmq, sig_maxid, pat_maxid);
    }

    int i;
    for (i = 0; i < ALPROTO_MAX; i++) {
        tctx->alproto_local_storage[i] = AppLayerGetProtocolParserLocalStorage(i);
    }

    return;
}

void AlpProtoDeFinalize2Thread(AlpProtoDetectThreadCtx *tctx) {
    if (alp_proto_ctx.toclient.id > 0) {
        mpm_table[alp_proto_ctx.toclient.mpm_ctx.mpm_type].DestroyThreadCtx
                    (&alp_proto_ctx.toclient.mpm_ctx, &tctx->toclient.mpm_ctx);
        PmqFree(&tctx->toclient.pmq);
    }
    if (alp_proto_ctx.toserver.id > 0) {
        mpm_table[alp_proto_ctx.toserver.mpm_ctx.mpm_type].DestroyThreadCtx
                    (&alp_proto_ctx.toserver.mpm_ctx, &tctx->toserver.mpm_ctx);
        PmqFree(&tctx->toserver.pmq);
    }

}
/** \brief to be called by ReassemblyThreadInit
 *  \todo this is a hack, we need a proper place to store the global ctx */
void AlpProtoFinalize2Thread(AlpProtoDetectThreadCtx *tctx) {
    AlpProtoFinalizeThread(&alp_proto_ctx, tctx);
    return;
}

void AlpProtoFinalizeGlobal(AlpProtoDetectCtx *ctx) {
    if (ctx == NULL)
        return;

    mpm_table[ctx->toclient.mpm_ctx.mpm_type].Prepare(&ctx->toclient.mpm_ctx);
    mpm_table[ctx->toserver.mpm_ctx.mpm_type].Prepare(&ctx->toserver.mpm_ctx);

    /* allocate and initialize the mapping between pattern id and signature */
    ctx->map = (AlpProtoSignature **)SCMalloc(ctx->sigs * sizeof(AlpProtoSignature *));
    if (ctx->map == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "%s", strerror(errno));
        return;
    }
    memset(ctx->map, 0x00, ctx->sigs * sizeof(AlpProtoSignature *));

    AlpProtoSignature *s = ctx->head;
    AlpProtoSignature *temp = NULL;
    for ( ; s != NULL; s = s->next) {
        BUG_ON(s->co == NULL);

        if (ctx->map[s->co->id] == NULL) {
            ctx->map[s->co->id] = s;
        } else {
            temp = ctx->map[s->co->id];
            while (temp->map_next != NULL)
                temp = temp->map_next;
            temp->map_next = s;
        }
    }
}

void AppLayerDetectProtoThreadInit(void) {
    AlpProtoInit(&alp_proto_ctx);
    RegisterAppLayerParsers();
    AlpProtoFinalizeGlobal(&alp_proto_ctx);

    return;
}

/**
 *  \brief Get the app layer proto based on a buffer using a Patter matcher
 *         parser.
 *
 *  \param ctx Global app layer detection context
 *  \param tctx Thread app layer detection context
 *  \param f Pointer to the flow.
 *  \param buf Pointer to the buffer to inspect
 *  \param buflen Lenght of the buffer
 *  \param flags Flags.
 *  \param Pointer to the results array, ALPROTO_MAX long.
 *
 *  \retval pm_matches Returns the no of alproto matches.
 */
uint16_t AppLayerDetectGetProtoPMParser(AlpProtoDetectCtx *ctx,
                                        AlpProtoDetectThreadCtx *tctx,
                                        Flow *f,
                                        uint8_t *buf, uint16_t buflen,
                                        uint8_t flags, uint8_t ipproto,
                                        uint16_t *pm_results) {
    SCEnter();

    uint16_t pm_matches = 0;
    pm_results[0] = ALPROTO_UNKNOWN;

    AlpProtoDetectDirection *dir;
    AlpProtoDetectDirectionThread *tdir;
    uint16_t max_len;

    if (flags & STREAM_TOSERVER) {
        dir = &ctx->toserver;
        tdir = &tctx->toserver;
        max_len = ctx->toserver.max_len;
    } else {
        dir = &ctx->toclient;
        tdir = &tctx->toclient;
        max_len = ctx->toclient.max_len;
    }

    if (dir->id == 0) {
        goto end;
    }

    /* see if we can limit the data we inspect */
    uint16_t searchlen = buflen;
    if (searchlen > dir->max_len)
        searchlen = dir->max_len;

    uint32_t search_cnt = 0;

    /* do the mpm search */
    search_cnt = mpm_table[dir->mpm_ctx.mpm_type].Search(&dir->mpm_ctx,
                                                         &tdir->mpm_ctx,
                                                         &tdir->pmq, buf,
                                                         searchlen);
    SCLogDebug("search cnt %" PRIu32 "", search_cnt);
    if (search_cnt == 0)
        goto end;

    /* alproto bit field */
    uint8_t pm_results_bf[ALPROTO_MAX / 8];
    memset(pm_results_bf, 0, sizeof(pm_results_bf));

    for (uint8_t s_cnt = 0; s_cnt < search_cnt; s_cnt++) {
        AlpProtoSignature *s = ctx->map[tdir->pmq.pattern_id_array[s_cnt]];
        SCLogDebug("array count is %"PRIu32" patid %"PRIu16"",
                   tdir->pmq.pattern_id_array_cnt,
                   tdir->pmq.pattern_id_array[s_cnt]);
        while (s != NULL) {
            uint16_t proto = AlpProtoMatchSignature(s, buf, buflen, ipproto);
            if (proto != ALPROTO_UNKNOWN && !(pm_results_bf[proto / 8] & (1 << (proto % 8))) ) {
                pm_results[pm_matches++] = proto;
                pm_results_bf[proto / 8] |= 1 << (proto % 8);
            }
            s = s->map_next;
        }
    }

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
    if (buflen >= max_len)
        FLOW_SET_PM_DONE(f, flags);
    SCReturnUInt(pm_matches);
}

/**
 * \brief Call the probing parser if it exists for this src or dst port.
 */
uint16_t AppLayerDetectGetProtoProbingParser(AlpProtoDetectCtx *ctx, Flow *f,
                                             uint8_t *buf, uint32_t buflen,
                                             uint8_t flags, uint8_t ipproto)
{
    AppLayerProbingParserPort *pp_port = NULL;
    AppLayerProbingParserElement *pe = NULL;
    uint32_t *al_proto_masks;

    if (flags & STREAM_TOSERVER) {
        pp_port = AppLayerGetProbingParsers(ctx->probing_parsers, ipproto, f->dp);
        al_proto_masks = &f->probing_parser_toserver_al_proto_masks;
        if (pp_port == NULL) {
            SCLogDebug("toserver-No probing parser registered for port %"PRIu16,
                       f->dp);
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
        pe = pp_port->toserver;
    } else {
        pp_port = AppLayerGetProbingParsers(ctx->probing_parsers, ipproto, f->sp);
        al_proto_masks = &f->probing_parser_toclient_al_proto_masks;
        if (pp_port == NULL) {
            SCLogDebug("toclient-No probing parser registered for port %"PRIu16,
                       f->sp);
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
        pe = pp_port->toclient;
    }


    while (pe != NULL) {
        if ((buflen < pe->min_depth)  ||
            (al_proto_masks[0] & pe->al_proto_mask)) {
            pe = pe->next;
            continue;
        }

        int alproto = pe->ProbingParser(buf, buflen, NULL);
        if (alproto != ALPROTO_UNKNOWN && alproto != ALPROTO_FAILED)
            return alproto;
        if (alproto == ALPROTO_FAILED ||
            (pe->max_depth != 0 && buflen > pe->max_depth)) {
            al_proto_masks[0] |= pe->al_proto_mask;
        }
        pe = pe->next;
    }

    if (flags & STREAM_TOSERVER) {
        if (al_proto_masks[0] == pp_port->toserver_al_proto_mask) {
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
    } else {
        if (al_proto_masks[0] == pp_port->toclient_al_proto_mask) {
            FLOW_SET_PP_DONE(f, flags);
            return ALPROTO_UNKNOWN;
        }
    }

    return ALPROTO_UNKNOWN;
}

/**
 *  \brief Get the app layer proto.
 *
 *  \param ctx    Global app layer detection context.
 *  \param tctx   Thread app layer detection context.
 *  \param f      Pointer to the flow.
 *  \param buf    Pointer to the buffer to inspect.
 *  \param buflen Lenght of the buffer.
 *  \param flags  Flags.
 *
 *  \retval proto App Layer proto, or ALPROTO_UNKNOWN if unknown
 */
uint16_t AppLayerDetectGetProto(AlpProtoDetectCtx *ctx,
                                AlpProtoDetectThreadCtx *tctx, Flow *f,
                                uint8_t *buf, uint32_t buflen,
                                uint8_t flags, uint8_t ipproto)
{
    if (!FLOW_IS_PM_DONE(f, flags)) {
        uint16_t pm_results[ALPROTO_MAX];
        uint16_t pm_matches = AppLayerDetectGetProtoPMParser(ctx, tctx, f, buf, buflen, flags, ipproto, pm_results);
        uint8_t dir = (flags & STREAM_TOSERVER) ? 0 : 1;
        for (uint16_t i = 0; i < pm_matches; i++) {
            if (al_proto_table[pm_results[i]].PPAlprotoMap[dir] != NULL) {
                if (pm_results[i] != al_proto_table[pm_results[i]].PPAlprotoMap[dir](buf, buflen, NULL)) {
                    /* \todo set event - Needs some deliberation */
                    continue;
                }
            }

            return pm_results[i];
        }
    }
    if (!FLOW_IS_PP_DONE(f, flags))
        return AppLayerDetectGetProtoProbingParser(ctx, f, buf, buflen, flags, ipproto);
    return ALPROTO_UNKNOWN;
}

/*****Unittests*****/

#ifdef UNITTESTS

int AlpDetectTest01(void) {
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    buf = SCStrdup("GET");
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOSERVER);
    if (ctx.toserver.id != 1) {
        r = 0;
    }
    SCFree(buf);

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest02(void) {
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest03(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, NULL, l7data, sizeof(l7data));
    if (cnt != 1) {
        printf("cnt %u != 1: ", cnt);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest04(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    char *buf = SCStrdup("200 ");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint32_t cnt = mpm_table[ctx.toclient.mpm_ctx.mpm_type].Search(&ctx.toclient.mpm_ctx, &tctx.toclient.mpm_ctx, &tctx.toclient.pmq, l7data, sizeof(l7data));
    if (cnt != 1) {
        printf("cnt %u != 1: ", cnt);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest05(void) {
    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n<HTML><BODY>Blahblah</BODY></HTML>";
    char *buf = SCStrdup("HTTP");
    int r = 1;

    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest06(void) {
    uint8_t l7data[] = "220 Welcome to the OISF FTP server\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    buf = SCStrdup("220 ");
    AlpProtoAdd(&ctx, "ftp", IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 2) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_FTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_FTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_FTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

    return r;
}

int AlpDetectTest07(void) {
    uint8_t l7data[] = "220 Welcome to the OISF HTTP/FTP server\r\n";
    char *buf = SCStrdup("HTTP");
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_HTTP) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_UNKNOWN) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_UNKNOWN);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

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

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "smb", IPPROTO_TCP, ALPROTO_SMB, buf, 8, 4, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_SMB) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_SMB) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_SMB);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

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

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "smb2", IPPROTO_TCP, ALPROTO_SMB2, buf, 8, 4, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_SMB2) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_SMB2) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_SMB2);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

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

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "dcerpc", IPPROTO_TCP, ALPROTO_DCERPC, buf, 4, 0, STREAM_TOCLIENT);
    SCFree(buf);

    if (ctx.toclient.id != 1) {
        r = 0;
    }

    if (ctx.toclient.map[ctx.toclient.id - 1] != ALPROTO_DCERPC) {
        r = 0;
    }

    AlpProtoFinalizeGlobal(&ctx);
    AlpProtoFinalizeThread(&ctx, &tctx);

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data,sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_DCERPC) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_DCERPC);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);

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

    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);

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

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] == ALPROTO_HTTP) {
        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_TCP, pm_results);
    if (pm_results[0] != ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);
    return r;
}

/** \test AlpProtoSignature test */
int AlpDetectTest12(void) {
    AlpProtoDetectCtx ctx;
    int r = 0;

    AlpProtoInit(&ctx);
    AlpProtoAdd(&ctx, "http", IPPROTO_TCP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
    AlpProtoFinalizeGlobal(&ctx);

    if (ctx.head == NULL) {
        printf("ctx.head == NULL: ");
        goto end;
    }

    if (ctx.head->proto != ALPROTO_HTTP) {
        printf("ctx.head->proto != ALPROTO_HTTP: ");
        goto end;
    }

    if (ctx.sigs != 1) {
        printf("ctx.sigs %"PRIu16", expected 1: ", ctx.sigs);
        goto end;
    }

    if (ctx.map == NULL) {
        printf("no mapping: ");
        goto end;
    }

    if (ctx.map[ctx.head->co->id] != ctx.head) {
        printf("wrong sig: ");
        goto end;
    }

    r = 1;
end:
    return r;
}

/**
 * \test What about if we add some sigs only for udp but call for tcp?
 *       It should not detect any proto
 */
int AlpDetectTest13(void) {
    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);

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

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_TCP, pm_results);
    if (pm_results[0] == ALPROTO_HTTP) {
        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_TCP, pm_results);
    if (pm_results[0] == ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);
    return r;
}

/**
 * \test What about if we add some sigs only for udp calling it for UDP?
 *       It should detect ALPROTO_HTTP (over udp). This is just a check
 *       to ensure that TCP/UDP differences work correctly.
 */
int AlpDetectTest14(void) {
    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    int r = 1;
    AlpProtoDetectCtx ctx;
    AlpProtoDetectThreadCtx tctx;

    AlpProtoInit(&ctx);

    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "GET", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "PUT", 3, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "POST", 4, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "TRACE", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AlpProtoAdd(&ctx, "http", IPPROTO_UDP, ALPROTO_HTTP, "HTTP", 4, 0, STREAM_TOCLIENT);

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

    uint16_t pm_results[ALPROTO_MAX];
    Flow f;
    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data, sizeof(l7data), STREAM_TOCLIENT, IPPROTO_UDP, pm_results);
    if (pm_results[0] == ALPROTO_HTTP) {
        printf("proto %" PRIu8 " == %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AppLayerDetectGetProtoPMParser(&ctx, &tctx, &f, l7data_resp, sizeof(l7data_resp), STREAM_TOSERVER, IPPROTO_UDP, pm_results);
    if (pm_results[0] != ALPROTO_HTTP) {
        printf("proto %" PRIu8 " != %" PRIu8 ": ", pm_results[0], ALPROTO_HTTP);
        r = 0;
    }

    AlpProtoTestDestroy(&ctx);
    return r;
}

/** \test test if the engine detect the proto and match with it */
static int AlpDetectTestSig1(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    if (p == NULL) {
        printf("packet setup failed: ");
        goto end;
    }

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL) {
        printf("flow setup failed: ");
        goto end;
    }
    f->protoctx = &ssn;
    p->flow = f;

    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    f->alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                                   "(msg:\"Test content option\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

   SCMutexLock(&f->m);
   int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }
    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto on a non standar port
 * and match with it */
static int AlpDetectTestSig2(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
                                   "(msg:\"http over non standar port\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    result = 1;

end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto and doesn't match
 * because the sig expects another proto (ex ftp)*/
static int AlpDetectTestSig3(void)
{
    int result = 0;
    Flow *f = NULL;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ftp any any -> any any "
                                   "(msg:\"Test content option\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    http_state = f->alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not (it's not ftp): ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto and doesn't match
 * because the packet has another proto (ex ftp) */
static int AlpDetectTestSig4(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t http_buf1[] = "MPUT one\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
                                   "(msg:\"http over non standar port\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_FTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not (it's ftp): ");
        goto end;
    }

    result = 1;

end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto and match with it
 *        and also against a content option */
static int AlpDetectTestSig5(void)
{
    int result = 0;
    Flow *f = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP;
    f->proto = IPPROTO_TCP;
    p->flags |= PKT_STREAM_ADD;
    p->flags |= PKT_STREAM_EOF;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    StreamTcpInitConfig(TRUE);

    StreamMsg *stream_msg = StreamMsgGetFromPool();
    if (stream_msg == NULL) {
        printf("no stream_msg: ");
        goto end;
    }

    memcpy(stream_msg->data, http_buf1, http_buf1_len);
    stream_msg->data_len = http_buf1_len;

    ssn.toserver_smsg_head = stream_msg;
    ssn.toserver_smsg_tail = stream_msg;

    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                                   "(msg:\"Test content option\"; "
                                   "content:\"one\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f->m);
    int r = AppLayerParse(NULL, f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f->m);
        goto end;
    }
    SCMutexUnlock(&f->m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    result = 1;

end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
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
    UtRegisterTest("AlpDetectTest12", AlpDetectTest12, 1);
    UtRegisterTest("AlpDetectTest13", AlpDetectTest13, 1);
    UtRegisterTest("AlpDetectTest14", AlpDetectTest14, 1);
    UtRegisterTest("AlpDetectTestSig1", AlpDetectTestSig1, 1);
    UtRegisterTest("AlpDetectTestSig2", AlpDetectTestSig2, 1);
    UtRegisterTest("AlpDetectTestSig3", AlpDetectTestSig3, 1);
    UtRegisterTest("AlpDetectTestSig4", AlpDetectTestSig4, 1);
    UtRegisterTest("AlpDetectTestSig5", AlpDetectTestSig5, 1);
#endif /* UNITTESTS */
}
