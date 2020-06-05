/* Copyright (C) 2007-2021 Open Information Security Foundation
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

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "decode.h"
#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "detect.h"
#include "detect-engine-port.h"
#include "detect-engine-build.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-validate.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-private.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "app-layer-expectation.h"

#include "conf.h"
#include "util-memcmp.h"
#include "util-spm.h"
#include "util-debug.h"
#include "util-validate.h"

#include "runmodes.h"

typedef struct AppLayerProtoDetectProbingParserElement_ {
    AppProto alproto;
    /* \todo don't really need it.  See if you can get rid of it */
    uint16_t port;
    /* \todo calculate at runtime and get rid of this var */
    uint32_t alproto_mask;
    /* the min length of data that has to be supplied to invoke the parser */
    uint16_t min_depth;
    /* the max length of data after which this parser won't be invoked */
    uint16_t max_depth;

    /* the to_server probing parser function */
    ProbingParserFPtr ProbingParserTs;

    /* the to_client probing parser function */
    ProbingParserFPtr ProbingParserTc;

    struct AppLayerProtoDetectProbingParserElement_ *next;
} AppLayerProtoDetectProbingParserElement;

typedef struct AppLayerProtoDetectProbingParserPort_ {
    /* the port no for which probing parser(s) are invoked */
    uint16_t port;

    uint32_t alproto_mask;

    /* the max depth for all the probing parsers registered for this port */
    uint16_t dp_max_depth;
    uint16_t sp_max_depth;

    AppLayerProtoDetectProbingParserElement *dp;
    AppLayerProtoDetectProbingParserElement *sp;

    struct AppLayerProtoDetectProbingParserPort_ *next;
} AppLayerProtoDetectProbingParserPort;

typedef struct AppLayerProtoDetectProbingParser_ {
    uint8_t ipproto;
    AppLayerProtoDetectProbingParserPort *port;

    struct AppLayerProtoDetectProbingParser_ *next;
} AppLayerProtoDetectProbingParser;

typedef struct AppLayerProtoDetectPMSignature_ {
    AppProto alproto;
    uint8_t direction;  /**< direction for midstream */
    SigIntId id;
    /* \todo Change this into a non-pointer */
    DetectContentData *cd;
    uint16_t pp_min_depth;
    uint16_t pp_max_depth;
    ProbingParserFPtr PPFunc;
    struct AppLayerProtoDetectPMSignature_ *next;
} AppLayerProtoDetectPMSignature;

typedef struct AppLayerProtoDetectPMCtx_ {
    uint16_t pp_max_len;
    uint16_t min_len;
    MpmCtx mpm_ctx;

    /** Mapping between pattern id and signature.  As each signature has a
     *  unique pattern with a unique id, we can lookup the signature by
     *  the pattern id. */
    AppLayerProtoDetectPMSignature **map;
    AppLayerProtoDetectPMSignature *head;

    /* \todo we don't need this except at setup time.  Get rid of it. */
    PatIntId max_pat_id;
    SigIntId max_sig_id;
} AppLayerProtoDetectPMCtx;

typedef struct AppLayerProtoDetectCtxIpproto_ {
    /* 0 - toserver, 1 - toclient */
    AppLayerProtoDetectPMCtx ctx_pm[2];
} AppLayerProtoDetectCtxIpproto;

/**
 * \brief The app layer protocol detection context.
 */
typedef struct AppLayerProtoDetectCtx_ {
    /* Context per ip_proto.
     * \todo Modify ctx_ipp to hold for only tcp and udp. The rest can be
     *       implemented if needed.  Waste of space otherwise. */
    AppLayerProtoDetectCtxIpproto ctx_ipp[FLOW_PROTO_DEFAULT];

    /* Global SPM thread context prototype. */
    SpmGlobalThreadCtx *spm_global_thread_ctx;

    AppLayerProtoDetectProbingParser *ctx_pp;

    /* Indicates the protocols that have registered themselves
     * for protocol detection.  This table is independent of the
     * ipproto. */
    const char *alproto_names[ALPROTO_MAX];
} AppLayerProtoDetectCtx;

typedef struct AppLayerProtoDetectAliases_ {
    const char *proto_name;
    const char *proto_alias;
    struct AppLayerProtoDetectAliases_ *next;
} AppLayerProtoDetectAliases;

/**
 * \brief The app layer protocol detection thread context.
 */
struct AppLayerProtoDetectThreadCtx_ {
    PrefilterRuleStore pmq;
    /* The value 2 is for direction(0 - toserver, 1 - toclient). */
    MpmThreadCtx mpm_tctx[FLOW_PROTO_DEFAULT][2];
    SpmThreadCtx *spm_thread_ctx;
};

/* The global app layer proto detection context. */
static AppLayerProtoDetectCtx alpd_ctx;
static AppLayerProtoDetectAliases *alpda_ctx = NULL;

static void AppLayerProtoDetectPEGetIpprotos(AppProto alproto,
                                             uint8_t *ipprotos);

/***** Static Internal Calls: Protocol Retrieval *****/

/** \internal
 *  \brief Handle SPM search for Signature
 *  \param buflen full size of the input buffer
 *  \param searchlen pattern matching portion of buffer */
static AppProto AppLayerProtoDetectPMMatchSignature(const AppLayerProtoDetectPMSignature *s,
        AppLayerProtoDetectThreadCtx *tctx, Flow *f, uint8_t flags, const uint8_t *buf,
        uint32_t buflen, uint16_t searchlen, bool *rflow)
{
    SCEnter();

    if (s->cd->offset > searchlen) {
        SCLogDebug("s->co->offset (%"PRIu16") > searchlen (%"PRIu16")",
                   s->cd->offset, searchlen);
        SCReturnUInt(ALPROTO_UNKNOWN);
    }
    if (s->cd->depth > searchlen) {
        SCLogDebug("s->co->depth (%"PRIu16") > searchlen (%"PRIu16")",
                   s->cd->depth, searchlen);
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    const uint8_t *sbuf = buf + s->cd->offset;
    uint16_t ssearchlen = s->cd->depth - s->cd->offset;
    SCLogDebug("s->co->offset (%"PRIu16") s->cd->depth (%"PRIu16")",
               s->cd->offset, s->cd->depth);

    uint8_t *found = SpmScan(s->cd->spm_ctx, tctx->spm_thread_ctx,
            sbuf, ssearchlen);
    if (found == NULL) {
        SCReturnUInt(ALPROTO_UNKNOWN);
    }

    uint8_t direction = (flags & (STREAM_TOSERVER | STREAM_TOCLIENT));
    SCLogDebug("matching, s->direction %s, our dir %s",
            (s->direction & STREAM_TOSERVER) ? "toserver" : "toclient",
            (flags & STREAM_TOSERVER) ? "toserver" : "toclient");
    if (s->PPFunc == NULL) {
        if (direction == s->direction) {
            SCLogDebug("direction is correct");
        } else {
            SCLogDebug("direction is wrong, rflow = true");
            *rflow = true;
        }
    /* validate using Probing Parser */
    } else {
        if (s->pp_min_depth > buflen) {
            SCLogDebug("PP can't be run yet as pp_min_depth %u > buflen %u",
                    s->pp_min_depth, buflen);
            SCReturnInt(ALPROTO_UNKNOWN);
        }

        uint8_t rdir = 0;
        AppProto r = s->PPFunc(f, flags, buf, buflen, &rdir);
        if (r == s->alproto) {
            SCLogDebug("found %s/%u, rdir %02x reverse_flow? %s",
                    AppProtoToString(r), r, rdir,
                    (rdir && direction != rdir) ? "true" : "false");
            *rflow = (rdir && direction != rdir);
            SCReturnUInt(s->alproto);
        } else if (r == ALPROTO_FAILED) {
            SCReturnUInt(ALPROTO_FAILED);
        } else {
            /* unknown: lets see if we will try again later */
            if (s->pp_max_depth < buflen) {
                SCLogDebug("depth reached and answer inconclusive: fail");
                SCReturnUInt(ALPROTO_FAILED);
            }
            SCReturnUInt(ALPROTO_UNKNOWN);
        }
    }
    SCReturnUInt(s->alproto);
}

/**
 *  \retval 0 no matches
 *  \retval -1 no matches, mpm depth reached
 */
static inline int PMGetProtoInspect(AppLayerProtoDetectThreadCtx *tctx,
        AppLayerProtoDetectPMCtx *pm_ctx, MpmThreadCtx *mpm_tctx, Flow *f, const uint8_t *buf,
        uint32_t buflen, uint8_t flags, AppProto *pm_results, bool *rflow)
{
    int pm_matches = 0;

    // maxdepth is u16, so minimum is u16
    uint16_t searchlen = (uint16_t)MIN(buflen, pm_ctx->mpm_ctx.maxdepth);
    SCLogDebug("searchlen %u buflen %u", searchlen, buflen);

    /* do the mpm search */
    uint32_t search_cnt = mpm_table[pm_ctx->mpm_ctx.mpm_type].Search(
            &pm_ctx->mpm_ctx, mpm_tctx, &tctx->pmq,
            buf, searchlen);
    if (search_cnt == 0) {
        if (buflen >= pm_ctx->mpm_ctx.maxdepth)
            return -1;
        return 0;
    }

    /* alproto bit field */
    uint8_t pm_results_bf[(ALPROTO_MAX / 8) + 1];
    memset(pm_results_bf, 0, sizeof(pm_results_bf));

    /* loop through unique pattern id's. Can't use search_cnt here,
     * as that contains all matches, tctx->pmq.pattern_id_array_cnt
     * contains only *unique* matches. */
    for (uint32_t cnt = 0; cnt < tctx->pmq.rule_id_array_cnt; cnt++) {
        const AppLayerProtoDetectPMSignature *s = pm_ctx->map[tctx->pmq.rule_id_array[cnt]];
        while (s != NULL) {
            AppProto proto = AppLayerProtoDetectPMMatchSignature(
                    s, tctx, f, flags, buf, buflen, searchlen, rflow);

            /* store each unique proto once */
            if (AppProtoIsValid(proto) &&
                !(pm_results_bf[proto / 8] & (1 << (proto % 8))) )
            {
                pm_results[pm_matches++] = proto;
                pm_results_bf[proto / 8] |= 1 << (proto % 8);
            }
            s = s->next;
        }
    }
    if (pm_matches == 0 && buflen >= pm_ctx->pp_max_len) {
        pm_matches = -2;
    }
    PmqReset(&tctx->pmq);
    return pm_matches;
}

/** \internal
 *  \brief Run Pattern Sigs against buffer
 *  \param direction direction for the patterns
 *  \param pm_results[out] AppProto array of size ALPROTO_MAX */
static AppProto AppLayerProtoDetectPMGetProto(AppLayerProtoDetectThreadCtx *tctx, Flow *f,
        const uint8_t *buf, uint32_t buflen, uint8_t flags, AppProto *pm_results, bool *rflow)
{
    SCEnter();

    pm_results[0] = ALPROTO_UNKNOWN;

    AppLayerProtoDetectPMCtx *pm_ctx;
    MpmThreadCtx *mpm_tctx;
    int m = -1;

    if (f->protomap >= FLOW_PROTO_DEFAULT) {
        pm_results[0] = ALPROTO_FAILED;
        SCReturnUInt(1);
    }

    if (flags & STREAM_TOSERVER) {
        pm_ctx = &alpd_ctx.ctx_ipp[f->protomap].ctx_pm[0];
        mpm_tctx = &tctx->mpm_tctx[f->protomap][0];
    } else {
        pm_ctx = &alpd_ctx.ctx_ipp[f->protomap].ctx_pm[1];
        mpm_tctx = &tctx->mpm_tctx[f->protomap][1];
    }
    if (likely(pm_ctx->mpm_ctx.pattern_cnt > 0)) {
        m = PMGetProtoInspect(tctx, pm_ctx, mpm_tctx, f, buf, buflen, flags, pm_results, rflow);
    }
    /* pattern found, yay */
    if (m > 0) {
        FLOW_SET_PM_DONE(f, flags);
        SCReturnUInt((uint16_t)m);

    /* handle non-found in non-midstream case */
    } else if (!stream_config.midstream) {
        /* we can give up if mpm gave no results and its search depth
         * was reached. */
        if (m < 0) {
            FLOW_SET_PM_DONE(f, flags);
            SCReturnUInt(0);
        } else if (m == 0) {
            SCReturnUInt(0);
        }
        SCReturnUInt((uint16_t)m);

    /* handle non-found in midstream case */
    } else if (m <= 0) {
        if (flags & STREAM_TOSERVER) {
            pm_ctx = &alpd_ctx.ctx_ipp[f->protomap].ctx_pm[1];
            mpm_tctx = &tctx->mpm_tctx[f->protomap][1];
        } else {
            pm_ctx = &alpd_ctx.ctx_ipp[f->protomap].ctx_pm[0];
            mpm_tctx = &tctx->mpm_tctx[f->protomap][0];
        }
        SCLogDebug("no matches and in midstream mode, lets try the "
                   "*patterns for the other side");

        int om = -1;
        if (likely(pm_ctx->mpm_ctx.pattern_cnt > 0)) {
            om = PMGetProtoInspect(
                    tctx, pm_ctx, mpm_tctx, f, buf, buflen, flags, pm_results, rflow);
        }
        /* found! */
        if (om > 0) {
            FLOW_SET_PM_DONE(f, flags);
            SCReturnUInt((uint16_t)om);

        /* both sides failed */
        } else if (om < 0 && m && m < 0) {
            FLOW_SET_PM_DONE(f, flags);
            SCReturnUInt(0);

        /* one side still uncertain */
        } else if (om == 0 || m == 0) {
            SCReturnUInt(0);
        }
    }
    SCReturnUInt(0);
}

static AppLayerProtoDetectProbingParserElement *AppLayerProtoDetectGetProbingParser(
        AppLayerProtoDetectProbingParser *pp, uint8_t ipproto, AppProto alproto)
{
    AppLayerProtoDetectProbingParserElement *pp_elem = NULL;
    AppLayerProtoDetectProbingParserPort *pp_port = NULL;

    while (pp != NULL) {
        if (pp->ipproto == ipproto)
            break;
        pp = pp->next;
    }
    if (pp == NULL)
        return NULL;

    pp_port = pp->port;
    while (pp_port != NULL) {
        if (pp_port->dp != NULL && pp_port->dp->alproto == alproto) {
            pp_elem = pp_port->dp;
            break;
        }
        if (pp_port->sp != NULL && pp_port->sp->alproto == alproto) {
            pp_elem = pp_port->sp;
            break;
        }
        pp_port = pp_port->next;
    }

    SCReturnPtr(pp_elem, "AppLayerProtoDetectProbingParserElement *");
}

static AppLayerProtoDetectProbingParserPort *AppLayerProtoDetectGetProbingParsers(AppLayerProtoDetectProbingParser *pp,
                                                                                  uint8_t ipproto,
                                                                                  uint16_t port)
{
    AppLayerProtoDetectProbingParserPort *pp_port = NULL;

    while (pp != NULL) {
        if (pp->ipproto == ipproto)
            break;

        pp = pp->next;
    }

    if (pp == NULL)
        goto end;

    pp_port = pp->port;
    while (pp_port != NULL) {
        if (pp_port->port == port || pp_port->port == 0) {
            break;
        }
        pp_port = pp_port->next;
    }

 end:
    SCReturnPtr(pp_port, "AppLayerProtoDetectProbingParserPort *");
}


/**
 * \brief Call the probing expectation to see if there is some for this flow.
 *
 */
static AppProto AppLayerProtoDetectPEGetProto(Flow *f, uint8_t ipproto, uint8_t flags)
{
    AppProto alproto = ALPROTO_UNKNOWN;

    SCLogDebug("expectation check for %p (dir %d)", f, flags);
    FLOW_SET_PE_DONE(f, flags);

    alproto = AppLayerExpectationHandle(f, flags);

    return alproto;
}

static inline AppProto PPGetProto(const AppLayerProtoDetectProbingParserElement *pe, Flow *f,
        uint8_t flags, const uint8_t *buf, uint32_t buflen, uint32_t *alproto_masks, uint8_t *rdir)
{
    while (pe != NULL) {
        if ((buflen < pe->min_depth)  ||
            (alproto_masks[0] & pe->alproto_mask)) {
            pe = pe->next;
            continue;
        }

        AppProto alproto = ALPROTO_UNKNOWN;
        if (flags & STREAM_TOSERVER && pe->ProbingParserTs != NULL) {
            alproto = pe->ProbingParserTs(f, flags, buf, buflen, rdir);
        } else if (flags & STREAM_TOCLIENT && pe->ProbingParserTc != NULL) {
            alproto = pe->ProbingParserTc(f, flags, buf, buflen, rdir);
        }
        if (AppProtoIsValid(alproto)) {
            SCReturnUInt(alproto);
        }
        if (alproto == ALPROTO_FAILED ||
            (pe->max_depth != 0 && buflen > pe->max_depth)) {
            alproto_masks[0] |= pe->alproto_mask;
        }
        pe = pe->next;
    }

    SCReturnUInt(ALPROTO_UNKNOWN);
}

/**
 * \brief Call the probing parser if it exists for this flow.
 *
 * First we check the flow's dp as it's most likely to match. If that didn't
 * lead to a PP, we try the sp.
 *
 */
static AppProto AppLayerProtoDetectPPGetProto(Flow *f, const uint8_t *buf, uint32_t buflen,
        uint8_t ipproto, const uint8_t flags, bool *reverse_flow)
{
    const AppLayerProtoDetectProbingParserPort *pp_port_dp = NULL;
    const AppLayerProtoDetectProbingParserPort *pp_port_sp = NULL;
    const AppLayerProtoDetectProbingParserElement *pe0 = NULL;
    const AppLayerProtoDetectProbingParserElement *pe1 = NULL;
    const AppLayerProtoDetectProbingParserElement *pe2 = NULL;
    AppProto alproto = ALPROTO_UNKNOWN;
    uint32_t *alproto_masks = NULL;
    uint32_t mask = 0;
    uint8_t idir = (flags & (STREAM_TOSERVER | STREAM_TOCLIENT));
    uint8_t dir = idir;
    uint16_t dp = f->protodetect_dp ? f->protodetect_dp : FLOW_GET_DP(f);
    uint16_t sp = FLOW_GET_SP(f);
    bool probe_is_found = false;

again_midstream:
    if (idir != dir) {
        SWAP_VARS(uint16_t, dp, sp); /* look up parsers in rev dir */
    }
    SCLogDebug("%u->%u %s", sp, dp,
            (dir == STREAM_TOSERVER) ? "toserver" : "toclient");

    if (dir == STREAM_TOSERVER) {
        /* first try the destination port */
        pp_port_dp = AppLayerProtoDetectGetProbingParsers(alpd_ctx.ctx_pp, ipproto, dp);
        alproto_masks = &f->probing_parser_toserver_alproto_masks;
        if (pp_port_dp != NULL) {
            SCLogDebug("toserver - Probing parser found for destination port %"PRIu16, dp);

            /* found based on destination port, so use dp registration */
            pe1 = pp_port_dp->dp;
        } else {
            SCLogDebug("toserver - No probing parser registered for dest port %"PRIu16, dp);
        }

        pp_port_sp = AppLayerProtoDetectGetProbingParsers(alpd_ctx.ctx_pp, ipproto, sp);
        if (pp_port_sp != NULL) {
            SCLogDebug("toserver - Probing parser found for source port %"PRIu16, sp);

            /* found based on source port, so use sp registration */
            pe2 = pp_port_sp->sp;
        } else {
            SCLogDebug("toserver - No probing parser registered for source port %"PRIu16, sp);
        }
    } else {
        /* first try the destination port */
        pp_port_dp = AppLayerProtoDetectGetProbingParsers(alpd_ctx.ctx_pp, ipproto, dp);
        if (dir == idir) {
            // do not update alproto_masks to let a chance to second packet
            // for instance when sending a junk packet to a DNS server
            alproto_masks = &f->probing_parser_toclient_alproto_masks;
        }
        if (pp_port_dp != NULL) {
            SCLogDebug("toclient - Probing parser found for destination port %"PRIu16, dp);

            /* found based on destination port, so use dp registration */
            pe1 = pp_port_dp->dp;
        } else {
            SCLogDebug("toclient - No probing parser registered for dest port %"PRIu16, dp);
        }

        pp_port_sp = AppLayerProtoDetectGetProbingParsers(alpd_ctx.ctx_pp, ipproto, sp);
        if (pp_port_sp != NULL) {
            SCLogDebug("toclient - Probing parser found for source port %"PRIu16, sp);

            pe2 = pp_port_sp->sp;
        } else {
            SCLogDebug("toclient - No probing parser registered for source port %"PRIu16, sp);
        }
    }

    if (dir == STREAM_TOSERVER && f->alproto_tc != ALPROTO_UNKNOWN) {
        pe0 = AppLayerProtoDetectGetProbingParser(alpd_ctx.ctx_pp, ipproto, f->alproto_tc);
    } else if (dir == STREAM_TOCLIENT && f->alproto_ts != ALPROTO_UNKNOWN) {
        pe0 = AppLayerProtoDetectGetProbingParser(alpd_ctx.ctx_pp, ipproto, f->alproto_ts);
    }

    if (pe1 == NULL && pe2 == NULL && pe0 == NULL) {
        SCLogDebug("%s - No probing parsers found for either port",
                (dir == STREAM_TOSERVER) ? "toserver":"toclient");
        goto noparsers;
    } else {
        probe_is_found = true;
    }

    /* run the parser(s): always call with original direction */
    uint8_t rdir = 0;
    alproto = PPGetProto(pe0, f, flags, buf, buflen, alproto_masks, &rdir);
    if (AppProtoIsValid(alproto))
        goto end;
    alproto = PPGetProto(pe1, f, flags, buf, buflen, alproto_masks, &rdir);
    if (AppProtoIsValid(alproto))
        goto end;
    alproto = PPGetProto(pe2, f, flags, buf, buflen, alproto_masks, &rdir);
    if (AppProtoIsValid(alproto))
        goto end;

    /* get the mask we need for this direction */
    if (dir == idir) {
        if (pp_port_dp && pp_port_sp)
            mask = pp_port_dp->alproto_mask|pp_port_sp->alproto_mask;
        else if (pp_port_dp)
            mask = pp_port_dp->alproto_mask;
        else if (pp_port_sp)
            mask = pp_port_sp->alproto_mask;

        if (alproto_masks[0] == mask) {
            FLOW_SET_PP_DONE(f, dir);
            SCLogDebug("%s, mask is now %08x, needed %08x, so done",
                    (dir == STREAM_TOSERVER) ? "toserver":"toclient",
                    alproto_masks[0], mask);
        } else {
            SCLogDebug("%s, mask is now %08x, need %08x",
                    (dir == STREAM_TOSERVER) ? "toserver":"toclient",
                    alproto_masks[0], mask);
        }
    }

noparsers:
    if (stream_config.midstream && idir == dir) {
        if (idir == STREAM_TOSERVER) {
            dir = STREAM_TOCLIENT;
        } else {
            dir = STREAM_TOSERVER;
        }
        SCLogDebug("no match + midstream, retry the other direction %s",
                (dir == STREAM_TOSERVER) ? "toserver" : "toclient");
        goto again_midstream;
    } else if (!probe_is_found) {
        FLOW_SET_PP_DONE(f, idir);
    }

 end:
    if (AppProtoIsValid(alproto) && rdir != 0 && rdir != idir) {
        SCLogDebug("PP found %u, is reverse flow", alproto);
        *reverse_flow = true;
    }

    SCLogDebug("%s, mask is now %08x",
            (idir == STREAM_TOSERVER) ? "toserver":"toclient", alproto_masks[0]);
    SCReturnUInt(alproto);
}

/***** Static Internal Calls: PP registration *****/

static void AppLayerProtoDetectPPGetIpprotos(AppProto alproto,
                                             uint8_t *ipprotos)
{
    SCEnter();

    const AppLayerProtoDetectProbingParser *pp;
    const AppLayerProtoDetectProbingParserPort *pp_port;
    const AppLayerProtoDetectProbingParserElement *pp_pe;

    for (pp = alpd_ctx.ctx_pp; pp != NULL; pp = pp->next) {
        for (pp_port = pp->port; pp_port != NULL; pp_port = pp_port->next) {
            for (pp_pe = pp_port->dp; pp_pe != NULL; pp_pe = pp_pe->next) {
                if (alproto == pp_pe->alproto)
                    ipprotos[pp->ipproto / 8] |= 1 << (pp->ipproto % 8);
            }
            for (pp_pe = pp_port->sp; pp_pe != NULL; pp_pe = pp_pe->next) {
                if (alproto == pp_pe->alproto)
                    ipprotos[pp->ipproto / 8] |= 1 << (pp->ipproto % 8);
            }
        }
    }

    SCReturn;
}

static uint32_t AppLayerProtoDetectProbingParserGetMask(AppProto alproto)
{
    SCEnter();

    if (!(alproto > ALPROTO_UNKNOWN && alproto < ALPROTO_FAILED)) {
        FatalError(SC_ERR_ALPARSER, "Unknown protocol detected - %u", alproto);
    }

    SCReturnUInt(1UL << (uint32_t)alproto);
}

static AppLayerProtoDetectProbingParserElement *AppLayerProtoDetectProbingParserElementAlloc(void)
{
    SCEnter();

    AppLayerProtoDetectProbingParserElement *p = SCMalloc(sizeof(AppLayerProtoDetectProbingParserElement));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProtoDetectProbingParserElement));

    SCReturnPtr(p, "AppLayerProtoDetectProbingParserElement");
}


static void AppLayerProtoDetectProbingParserElementFree(AppLayerProtoDetectProbingParserElement *p)
{
    SCEnter();
    SCFree(p);
    SCReturn;
}

static AppLayerProtoDetectProbingParserPort *AppLayerProtoDetectProbingParserPortAlloc(void)
{
    SCEnter();

    AppLayerProtoDetectProbingParserPort *p = SCMalloc(sizeof(AppLayerProtoDetectProbingParserPort));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProtoDetectProbingParserPort));

    SCReturnPtr(p, "AppLayerProtoDetectProbingParserPort");
}

static void AppLayerProtoDetectProbingParserPortFree(AppLayerProtoDetectProbingParserPort *p)
{
    SCEnter();

    AppLayerProtoDetectProbingParserElement *e;

    e = p->dp;
    while (e != NULL) {
        AppLayerProtoDetectProbingParserElement *e_next = e->next;
        AppLayerProtoDetectProbingParserElementFree(e);
        e = e_next;
    }

    e = p->sp;
    while (e != NULL) {
        AppLayerProtoDetectProbingParserElement *e_next = e->next;
        AppLayerProtoDetectProbingParserElementFree(e);
        e = e_next;
    }

    SCFree(p);

    SCReturn;
}

static AppLayerProtoDetectProbingParser *AppLayerProtoDetectProbingParserAlloc(void)
{
    SCEnter();

    AppLayerProtoDetectProbingParser *p = SCMalloc(sizeof(AppLayerProtoDetectProbingParser));
    if (unlikely(p == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(p, 0, sizeof(AppLayerProtoDetectProbingParser));

    SCReturnPtr(p, "AppLayerProtoDetectProbingParser");
}

static void AppLayerProtoDetectProbingParserFree(AppLayerProtoDetectProbingParser *p)
{
    SCEnter();

    AppLayerProtoDetectProbingParserPort *pt = p->port;
    while (pt != NULL) {
        AppLayerProtoDetectProbingParserPort *pt_next = pt->next;
        AppLayerProtoDetectProbingParserPortFree(pt);
        pt = pt_next;
    }

    SCFree(p);

    SCReturn;
}

static AppLayerProtoDetectProbingParserElement *
AppLayerProtoDetectProbingParserElementCreate(AppProto alproto,
                                              uint16_t port,
                                              uint16_t min_depth,
                                              uint16_t max_depth)
{
    AppLayerProtoDetectProbingParserElement *pe = AppLayerProtoDetectProbingParserElementAlloc();

    pe->alproto = alproto;
    pe->port = port;
    pe->alproto_mask = AppLayerProtoDetectProbingParserGetMask(alproto);
    pe->min_depth = min_depth;
    pe->max_depth = max_depth;
    pe->next = NULL;

    if (max_depth != 0 && min_depth >= max_depth) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to "
                   "register the probing parser.  min_depth >= max_depth");
        goto error;
    }
    if (alproto <= ALPROTO_UNKNOWN || alproto >= ALPROTO_MAX) {
        SCLogError(SC_ERR_ALPARSER, "Invalid arguments sent to register "
                   "the probing parser.  Invalid alproto - %d", alproto);
        goto error;
    }

    SCReturnPtr(pe, "AppLayerProtoDetectProbingParserElement");
 error:
    AppLayerProtoDetectProbingParserElementFree(pe);
    SCReturnPtr(NULL, "AppLayerProtoDetectProbingParserElement");
}

static AppLayerProtoDetectProbingParserElement *
AppLayerProtoDetectProbingParserElementDuplicate(AppLayerProtoDetectProbingParserElement *pe)
{
    SCEnter();

    AppLayerProtoDetectProbingParserElement *new_pe = AppLayerProtoDetectProbingParserElementAlloc();

    new_pe->alproto = pe->alproto;
    new_pe->port = pe->port;
    new_pe->alproto_mask = pe->alproto_mask;
    new_pe->min_depth = pe->min_depth;
    new_pe->max_depth = pe->max_depth;
    new_pe->ProbingParserTs = pe->ProbingParserTs;
    new_pe->ProbingParserTc = pe->ProbingParserTc;
    new_pe->next = NULL;

    SCReturnPtr(new_pe, "AppLayerProtoDetectProbingParserElement");
}

#ifdef DEBUG
static void AppLayerProtoDetectPrintProbingParsers(AppLayerProtoDetectProbingParser *pp)
{
    SCEnter();

    AppLayerProtoDetectProbingParserPort *pp_port = NULL;
    AppLayerProtoDetectProbingParserElement *pp_pe = NULL;

    printf("\nProtocol Detection Configuration\n");

    for ( ; pp != NULL; pp = pp->next) {
        /* print ip protocol */
        if (pp->ipproto == IPPROTO_TCP)
            printf("IPProto: TCP\n");
        else if (pp->ipproto == IPPROTO_UDP)
            printf("IPProto: UDP\n");
        else
            printf("IPProto: %"PRIu8"\n", pp->ipproto);

        pp_port = pp->port;
        for ( ; pp_port != NULL; pp_port = pp_port->next) {
            if (pp_port->dp != NULL) {
                printf("    Port: %"PRIu16 "\n", pp_port->port);

                printf("        Destination port: (max-depth: %"PRIu16 ", "
                        "mask - %"PRIu32")\n",
                        pp_port->dp_max_depth,
                        pp_port->alproto_mask);
                pp_pe = pp_port->dp;
                for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {

                    if (pp_pe->alproto == ALPROTO_HTTP1)
                        printf("            alproto: ALPROTO_HTTP1\n");
                    else if (pp_pe->alproto == ALPROTO_FTP)
                        printf("            alproto: ALPROTO_FTP\n");
                    else if (pp_pe->alproto == ALPROTO_FTPDATA)
                        printf("            alproto: ALPROTO_FTPDATA\n");
                    else if (pp_pe->alproto == ALPROTO_SMTP)
                        printf("            alproto: ALPROTO_SMTP\n");
                    else if (pp_pe->alproto == ALPROTO_TLS)
                        printf("            alproto: ALPROTO_TLS\n");
                    else if (pp_pe->alproto == ALPROTO_SSH)
                        printf("            alproto: ALPROTO_SSH\n");
                    else if (pp_pe->alproto == ALPROTO_IMAP)
                        printf("            alproto: ALPROTO_IMAP\n");
                    else if (pp_pe->alproto == ALPROTO_JABBER)
                        printf("            alproto: ALPROTO_JABBER\n");
                    else if (pp_pe->alproto == ALPROTO_SMB)
                        printf("            alproto: ALPROTO_SMB\n");
                    else if (pp_pe->alproto == ALPROTO_DCERPC)
                        printf("            alproto: ALPROTO_DCERPC\n");
                    else if (pp_pe->alproto == ALPROTO_IRC)
                        printf("            alproto: ALPROTO_IRC\n");
                    else if (pp_pe->alproto == ALPROTO_DNS)
                        printf("            alproto: ALPROTO_DNS\n");
                    else if (pp_pe->alproto == ALPROTO_MODBUS)
                        printf("            alproto: ALPROTO_MODBUS\n");
                    else if (pp_pe->alproto == ALPROTO_ENIP)
                        printf("            alproto: ALPROTO_ENIP\n");
                    else if (pp_pe->alproto == ALPROTO_NFS)
                        printf("            alproto: ALPROTO_NFS\n");
                    else if (pp_pe->alproto == ALPROTO_NTP)
                        printf("            alproto: ALPROTO_NTP\n");
                    else if (pp_pe->alproto == ALPROTO_TFTP)
                        printf("            alproto: ALPROTO_TFTP\n");
                    else if (pp_pe->alproto == ALPROTO_IKE)
                        printf("            alproto: ALPROTO_IKE\n");
                    else if (pp_pe->alproto == ALPROTO_KRB5)
                        printf("            alproto: ALPROTO_KRB5\n");
                    else if (pp_pe->alproto == ALPROTO_DHCP)
                        printf("            alproto: ALPROTO_DHCP\n");
                    else if (pp_pe->alproto == ALPROTO_QUIC)
                        printf("            alproto: ALPROTO_QUIC\n");
                    else if (pp_pe->alproto == ALPROTO_SNMP)
                        printf("            alproto: ALPROTO_SNMP\n");
                    else if (pp_pe->alproto == ALPROTO_SIP)
                        printf("            alproto: ALPROTO_SIP\n");
                    else if (pp_pe->alproto == ALPROTO_TEMPLATE_RUST)
                        printf("            alproto: ALPROTO_TEMPLATE_RUST\n");
                    else if (pp_pe->alproto == ALPROTO_RFB)
                        printf("            alproto: ALPROTO_RFB\n");
                    else if (pp_pe->alproto == ALPROTO_MQTT)
                        printf("            alproto: ALPROTO_MQTT\n");
                    else if (pp_pe->alproto == ALPROTO_PGSQL)
                        printf("            alproto: ALPROTO_PGSQL\n");
                    else if (pp_pe->alproto == ALPROTO_TELNET)
                        printf("            alproto: ALPROTO_TELNET\n");
                    else if (pp_pe->alproto == ALPROTO_TEMPLATE)
                        printf("            alproto: ALPROTO_TEMPLATE\n");
                    else if (pp_pe->alproto == ALPROTO_DNP3)
                        printf("            alproto: ALPROTO_DNP3\n");
                    else if (pp_pe->alproto == ALPROTO_BITTORRENT_DHT)
                        printf("            alproto: ALPROTO_BITTORRENT_DHT\n");
                    else
                        printf("impossible\n");

                    printf("            port: %"PRIu16 "\n", pp_pe->port);
                    printf("            mask: %"PRIu32 "\n", pp_pe->alproto_mask);
                    printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                    printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                    printf("\n");
                }
            }

            if (pp_port->sp == NULL) {
                continue;
            }

            printf("        Source port: (max-depth: %"PRIu16 ", "
                   "mask - %"PRIu32")\n",
                   pp_port->sp_max_depth,
                   pp_port->alproto_mask);
            pp_pe = pp_port->sp;
            for ( ; pp_pe != NULL; pp_pe = pp_pe->next) {

                if (pp_pe->alproto == ALPROTO_HTTP1)
                    printf("            alproto: ALPROTO_HTTP1\n");
                else if (pp_pe->alproto == ALPROTO_FTP)
                    printf("            alproto: ALPROTO_FTP\n");
                else if (pp_pe->alproto == ALPROTO_FTPDATA)
                    printf("            alproto: ALPROTO_FTPDATA\n");
                else if (pp_pe->alproto == ALPROTO_SMTP)
                    printf("            alproto: ALPROTO_SMTP\n");
                else if (pp_pe->alproto == ALPROTO_TLS)
                    printf("            alproto: ALPROTO_TLS\n");
                else if (pp_pe->alproto == ALPROTO_SSH)
                    printf("            alproto: ALPROTO_SSH\n");
                else if (pp_pe->alproto == ALPROTO_IMAP)
                    printf("            alproto: ALPROTO_IMAP\n");
                else if (pp_pe->alproto == ALPROTO_JABBER)
                    printf("            alproto: ALPROTO_JABBER\n");
                else if (pp_pe->alproto == ALPROTO_SMB)
                    printf("            alproto: ALPROTO_SMB\n");
                else if (pp_pe->alproto == ALPROTO_DCERPC)
                    printf("            alproto: ALPROTO_DCERPC\n");
                else if (pp_pe->alproto == ALPROTO_IRC)
                    printf("            alproto: ALPROTO_IRC\n");
                else if (pp_pe->alproto == ALPROTO_DNS)
                    printf("            alproto: ALPROTO_DNS\n");
                else if (pp_pe->alproto == ALPROTO_MODBUS)
                    printf("            alproto: ALPROTO_MODBUS\n");
                else if (pp_pe->alproto == ALPROTO_ENIP)
                    printf("            alproto: ALPROTO_ENIP\n");
                else if (pp_pe->alproto == ALPROTO_NFS)
                    printf("            alproto: ALPROTO_NFS\n");
                else if (pp_pe->alproto == ALPROTO_NTP)
                    printf("            alproto: ALPROTO_NTP\n");
                else if (pp_pe->alproto == ALPROTO_TFTP)
                    printf("            alproto: ALPROTO_TFTP\n");
                else if (pp_pe->alproto == ALPROTO_IKE)
                    printf("            alproto: ALPROTO_IKE\n");
                else if (pp_pe->alproto == ALPROTO_KRB5)
                    printf("            alproto: ALPROTO_KRB5\n");
                else if (pp_pe->alproto == ALPROTO_QUIC)
                    printf("            alproto: ALPROTO_QUIC\n");
                else if (pp_pe->alproto == ALPROTO_DHCP)
                    printf("            alproto: ALPROTO_DHCP\n");
                else if (pp_pe->alproto == ALPROTO_SNMP)
                    printf("            alproto: ALPROTO_SNMP\n");
                else if (pp_pe->alproto == ALPROTO_SIP)
                    printf("            alproto: ALPROTO_SIP\n");
                else if (pp_pe->alproto == ALPROTO_TEMPLATE_RUST)
                    printf("            alproto: ALPROTO_TEMPLATE_RUST\n");
                else if (pp_pe->alproto == ALPROTO_RFB)
                    printf("            alproto: ALPROTO_RFB\n");
                else if (pp_pe->alproto == ALPROTO_MQTT)
                    printf("            alproto: ALPROTO_MQTT\n");
                else if (pp_pe->alproto == ALPROTO_PGSQL)
                    printf("            alproto: ALPROTO_PGSQL\n");
                else if (pp_pe->alproto == ALPROTO_TELNET)
                    printf("            alproto: ALPROTO_TELNET\n");
                else if (pp_pe->alproto == ALPROTO_TEMPLATE)
                    printf("            alproto: ALPROTO_TEMPLATE\n");
                else if (pp_pe->alproto == ALPROTO_DNP3)
                    printf("            alproto: ALPROTO_DNP3\n");
                else if (pp_pe->alproto == ALPROTO_BITTORRENT_DHT)
                    printf("            alproto: ALPROTO_BITTORRENT_DHT\n");
                else
                    printf("impossible\n");

                printf("            port: %"PRIu16 "\n", pp_pe->port);
                printf("            mask: %"PRIu32 "\n", pp_pe->alproto_mask);
                printf("            min_depth: %"PRIu32 "\n", pp_pe->min_depth);
                printf("            max_depth: %"PRIu32 "\n", pp_pe->max_depth);

                printf("\n");
            }
        }
    }

    SCReturn;
}
#endif

static void AppLayerProtoDetectProbingParserElementAppend(AppLayerProtoDetectProbingParserElement **head_pe,
                                                          AppLayerProtoDetectProbingParserElement *new_pe)
{
    SCEnter();

    if (*head_pe == NULL) {
        *head_pe = new_pe;
        goto end;
    }

    if ((*head_pe)->port == 0) {
        if (new_pe->port != 0) {
            new_pe->next = *head_pe;
            *head_pe = new_pe;
        } else {
            AppLayerProtoDetectProbingParserElement *temp_pe = *head_pe;
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        }
    } else {
        AppLayerProtoDetectProbingParserElement *temp_pe = *head_pe;
        if (new_pe->port == 0) {
            while (temp_pe->next != NULL)
                temp_pe = temp_pe->next;
            temp_pe->next = new_pe;
        } else {
            while (temp_pe->next != NULL && temp_pe->next->port != 0)
                temp_pe = temp_pe->next;
            new_pe->next = temp_pe->next;
            temp_pe->next = new_pe;

        }
    }

 end:
    SCReturn;
}

static void AppLayerProtoDetectProbingParserAppend(AppLayerProtoDetectProbingParser **head_pp,
                                                   AppLayerProtoDetectProbingParser *new_pp)
{
    SCEnter();

    if (*head_pp == NULL) {
        *head_pp = new_pp;
        goto end;
    }

    AppLayerProtoDetectProbingParser *temp_pp = *head_pp;
    while (temp_pp->next != NULL)
        temp_pp = temp_pp->next;
    temp_pp->next = new_pp;

 end:
    SCReturn;
}

static void AppLayerProtoDetectProbingParserPortAppend(AppLayerProtoDetectProbingParserPort **head_port,
                                                       AppLayerProtoDetectProbingParserPort *new_port)
{
    SCEnter();

    if (*head_port == NULL) {
        *head_port = new_port;
        goto end;
    }

    if ((*head_port)->port == 0) {
        new_port->next = *head_port;
        *head_port = new_port;
    } else {
        AppLayerProtoDetectProbingParserPort *temp_port = *head_port;
        while (temp_port->next != NULL && temp_port->next->port != 0) {
            temp_port = temp_port->next;
        }
        new_port->next = temp_port->next;
        temp_port->next = new_port;
    }

 end:
    SCReturn;
}

static void AppLayerProtoDetectInsertNewProbingParser(AppLayerProtoDetectProbingParser **pp,
                                                             uint8_t ipproto,
                                                             uint16_t port,
                                                             AppProto alproto,
                                                             uint16_t min_depth, uint16_t max_depth,
                                                             uint8_t direction,
                                                             ProbingParserFPtr ProbingParser1,
                                                             ProbingParserFPtr ProbingParser2)
{
    SCEnter();

    /* get the top level ipproto pp */
    AppLayerProtoDetectProbingParser *curr_pp = *pp;
    while (curr_pp != NULL) {
        if (curr_pp->ipproto == ipproto)
            break;
        curr_pp = curr_pp->next;
    }
    if (curr_pp == NULL) {
        AppLayerProtoDetectProbingParser *new_pp = AppLayerProtoDetectProbingParserAlloc();
        new_pp->ipproto = ipproto;
        AppLayerProtoDetectProbingParserAppend(pp, new_pp);
        curr_pp = new_pp;
    }

    /* get the top level port pp */
    AppLayerProtoDetectProbingParserPort *curr_port = curr_pp->port;
    while (curr_port != NULL) {
        if (curr_port->port == port)
            break;
        curr_port = curr_port->next;
    }
    if (curr_port == NULL) {
        AppLayerProtoDetectProbingParserPort *new_port = AppLayerProtoDetectProbingParserPortAlloc();
        new_port->port = port;
        AppLayerProtoDetectProbingParserPortAppend(&curr_pp->port, new_port);
        curr_port = new_port;
        if (direction & STREAM_TOSERVER) {
            curr_port->dp_max_depth = max_depth;
        } else {
            curr_port->sp_max_depth = max_depth;
        }

        AppLayerProtoDetectProbingParserPort *zero_port;

        zero_port = curr_pp->port;
        while (zero_port != NULL && zero_port->port != 0) {
            zero_port = zero_port->next;
        }
        if (zero_port != NULL) {
            AppLayerProtoDetectProbingParserElement *zero_pe;

            zero_pe = zero_port->dp;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->dp == NULL)
                    curr_port->dp_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->dp_max_depth = zero_pe->max_depth;
                if (curr_port->dp_max_depth != 0 &&
                    curr_port->dp_max_depth < zero_pe->max_depth) {
                    curr_port->dp_max_depth = zero_pe->max_depth;
                }

                AppLayerProtoDetectProbingParserElement *dup_pe =
                    AppLayerProtoDetectProbingParserElementDuplicate(zero_pe);
                AppLayerProtoDetectProbingParserElementAppend(&curr_port->dp, dup_pe);
                curr_port->alproto_mask |= dup_pe->alproto_mask;
            }

            zero_pe = zero_port->sp;
            for ( ; zero_pe != NULL; zero_pe = zero_pe->next) {
                if (curr_port->sp == NULL)
                    curr_port->sp_max_depth = zero_pe->max_depth;
                if (zero_pe->max_depth == 0)
                    curr_port->sp_max_depth = zero_pe->max_depth;
                if (curr_port->sp_max_depth != 0 &&
                    curr_port->sp_max_depth < zero_pe->max_depth) {
                    curr_port->sp_max_depth = zero_pe->max_depth;
                }

                AppLayerProtoDetectProbingParserElement *dup_pe =
                    AppLayerProtoDetectProbingParserElementDuplicate(zero_pe);
                AppLayerProtoDetectProbingParserElementAppend(&curr_port->sp, dup_pe);
                curr_port->alproto_mask |= dup_pe->alproto_mask;
            }
        } /* if (zero_port != NULL) */
    } /* if (curr_port == NULL) */

    /* insert the pe_pp */
    AppLayerProtoDetectProbingParserElement *curr_pe;
    if (direction & STREAM_TOSERVER)
        curr_pe = curr_port->dp;
    else
        curr_pe = curr_port->sp;
    while (curr_pe != NULL) {
        if (curr_pe->alproto == alproto) {
            SCLogError(SC_ERR_ALPARSER, "Duplicate pp registered - "
                       "ipproto - %"PRIu8" Port - %"PRIu16" "
                       "App Protocol - NULL, App Protocol(ID) - "
                       "%"PRIu16" min_depth - %"PRIu16" "
                       "max_dept - %"PRIu16".",
                       ipproto, port, alproto,
                       min_depth, max_depth);
            goto error;
        }
        curr_pe = curr_pe->next;
    }
    /* Get a new parser element */
    AppLayerProtoDetectProbingParserElement *new_pe =
        AppLayerProtoDetectProbingParserElementCreate(alproto,
                                                      curr_port->port,
                                                      min_depth, max_depth);
    if (new_pe == NULL)
        goto error;
    curr_pe = new_pe;
    AppLayerProtoDetectProbingParserElement **head_pe;
    if (direction & STREAM_TOSERVER) {
        curr_pe->ProbingParserTs = ProbingParser1;
        curr_pe->ProbingParserTc = ProbingParser2;
        if (curr_port->dp == NULL)
            curr_port->dp_max_depth = new_pe->max_depth;
        if (new_pe->max_depth == 0)
            curr_port->dp_max_depth = new_pe->max_depth;
        if (curr_port->dp_max_depth != 0 &&
            curr_port->dp_max_depth < new_pe->max_depth) {
            curr_port->dp_max_depth = new_pe->max_depth;
        }
        curr_port->alproto_mask |= new_pe->alproto_mask;
        head_pe = &curr_port->dp;
    } else {
        curr_pe->ProbingParserTs = ProbingParser2;
        curr_pe->ProbingParserTc = ProbingParser1;
        if (curr_port->sp == NULL)
            curr_port->sp_max_depth = new_pe->max_depth;
        if (new_pe->max_depth == 0)
            curr_port->sp_max_depth = new_pe->max_depth;
        if (curr_port->sp_max_depth != 0 &&
            curr_port->sp_max_depth < new_pe->max_depth) {
            curr_port->sp_max_depth = new_pe->max_depth;
        }
        curr_port->alproto_mask |= new_pe->alproto_mask;
        head_pe = &curr_port->sp;
    }
    AppLayerProtoDetectProbingParserElementAppend(head_pe, new_pe);

    if (curr_port->port == 0) {
        AppLayerProtoDetectProbingParserPort *temp_port = curr_pp->port;
        while (temp_port != NULL && temp_port->port != 0) {
            if (direction & STREAM_TOSERVER) {
                if (temp_port->dp == NULL)
                    temp_port->dp_max_depth = curr_pe->max_depth;
                if (curr_pe->max_depth == 0)
                    temp_port->dp_max_depth = curr_pe->max_depth;
                if (temp_port->dp_max_depth != 0 &&
                    temp_port->dp_max_depth < curr_pe->max_depth) {
                    temp_port->dp_max_depth = curr_pe->max_depth;
                }
                AppLayerProtoDetectProbingParserElementAppend(&temp_port->dp,
                                                              AppLayerProtoDetectProbingParserElementDuplicate(curr_pe));
                temp_port->alproto_mask |= curr_pe->alproto_mask;
            } else {
                if (temp_port->sp == NULL)
                    temp_port->sp_max_depth = curr_pe->max_depth;
                if (curr_pe->max_depth == 0)
                    temp_port->sp_max_depth = curr_pe->max_depth;
                if (temp_port->sp_max_depth != 0 &&
                    temp_port->sp_max_depth < curr_pe->max_depth) {
                    temp_port->sp_max_depth = curr_pe->max_depth;
                }
                AppLayerProtoDetectProbingParserElementAppend(&temp_port->sp,
                                                              AppLayerProtoDetectProbingParserElementDuplicate(curr_pe));
                temp_port->alproto_mask |= curr_pe->alproto_mask;
            }
            temp_port = temp_port->next;
        } /* while */
    } /* if */

 error:
    SCReturn;
}

/***** Static Internal Calls: PM registration *****/

static void AppLayerProtoDetectPMGetIpprotos(AppProto alproto,
                                             uint8_t *ipprotos)
{
    SCEnter();

    for (uint8_t i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        uint8_t ipproto = FlowGetReverseProtoMapping(i);
        for (int j = 0; j < 2; j++) {
            AppLayerProtoDetectPMCtx *pm_ctx = &alpd_ctx.ctx_ipp[i].ctx_pm[j];

            for (SigIntId x = 0; x < pm_ctx->max_sig_id; x++) {
                const AppLayerProtoDetectPMSignature *s = pm_ctx->map[x];
                if (s->alproto == alproto)
                    ipprotos[ipproto / 8] |= 1 << (ipproto % 8);
            }
        }
    }

    SCReturn;
}

static int AppLayerProtoDetectPMSetContentIDs(AppLayerProtoDetectPMCtx *ctx)
{
    SCEnter();

    typedef struct TempContainer_ {
        PatIntId id;
        uint16_t content_len;
        uint8_t *content;
    } TempContainer;

    AppLayerProtoDetectPMSignature *s = NULL;
    uint32_t struct_total_size = 0;
    uint32_t content_total_size = 0;
    /* array hash buffer */
    uint8_t *ahb = NULL;
    uint8_t *content = NULL;
    uint16_t content_len = 0;
    PatIntId max_id = 0;
    TempContainer *struct_offset = NULL;
    uint8_t *content_offset = NULL;
    int ret = 0;

    if (ctx->head == NULL)
        goto end;

    for (s = ctx->head; s != NULL; s = s->next) {
        struct_total_size += sizeof(TempContainer);
        content_total_size += s->cd->content_len;
        ctx->max_sig_id++;
    }

    ahb = SCMalloc(sizeof(uint8_t) * (struct_total_size + content_total_size));
    if (unlikely(ahb == NULL))
        goto error;

    struct_offset = (TempContainer *)ahb;
    content_offset = ahb + struct_total_size;
    for (s = ctx->head; s != NULL; s = s->next) {
        TempContainer *tcdup = (TempContainer *)ahb;
        content = s->cd->content;
        content_len = s->cd->content_len;

        for (; tcdup != struct_offset; tcdup++) {
            if (tcdup->content_len != content_len ||
                SCMemcmp(tcdup->content, content, tcdup->content_len) != 0)
            {
                continue;
            }
            break;
        }

        if (tcdup != struct_offset) {
            s->cd->id = tcdup->id;
            continue;
        }

        struct_offset->content_len = content_len;
        struct_offset->content = content_offset;
        content_offset += content_len;
        memcpy(struct_offset->content, content, content_len);
        struct_offset->id = max_id++;
        s->cd->id = struct_offset->id;

        struct_offset++;
    }

    ctx->max_pat_id = max_id;

    goto end;
 error:
    ret = -1;
 end:
    if (ahb != NULL)
        SCFree(ahb);
    SCReturnInt(ret);
}

static int AppLayerProtoDetectPMMapSignatures(AppLayerProtoDetectPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    AppLayerProtoDetectPMSignature *s, *next_s;
    int mpm_ret;
    SigIntId id = 0;

    ctx->map = SCMalloc(ctx->max_sig_id * sizeof(AppLayerProtoDetectPMSignature *));
    if (ctx->map == NULL)
        goto error;
    memset(ctx->map, 0, ctx->max_sig_id * sizeof(AppLayerProtoDetectPMSignature *));

    /* add an array indexed by rule id to look up the sig */
    for (s = ctx->head; s != NULL; ) {
        next_s = s->next;
        s->id = id++;
        SCLogDebug("s->id %u offset %u depth %u",
                s->id, s->cd->offset, s->cd->depth);

        if (s->cd->flags & DETECT_CONTENT_NOCASE) {
            mpm_ret = MpmAddPatternCI(&ctx->mpm_ctx,
                    s->cd->content, s->cd->content_len,
                    s->cd->offset, s->cd->depth, s->cd->id, s->id, 0);
            if (mpm_ret < 0)
                goto error;
        } else {
            mpm_ret = MpmAddPatternCS(&ctx->mpm_ctx,
                    s->cd->content, s->cd->content_len,
                    s->cd->offset, s->cd->depth, s->cd->id, s->id, 0);
            if (mpm_ret < 0)
                goto error;
        }

        ctx->map[s->id] = s;
        s->next = NULL;
        s = next_s;
    }
    ctx->head = NULL;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static int AppLayerProtoDetectPMPrepareMpm(AppLayerProtoDetectPMCtx *ctx)
{
    SCEnter();

    int ret = 0;
    MpmCtx *mpm_ctx = &ctx->mpm_ctx;

    if (mpm_table[mpm_ctx->mpm_type].Prepare(mpm_ctx) < 0)
        goto error;

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

static void AppLayerProtoDetectPMFreeSignature(AppLayerProtoDetectPMSignature *sig)
{
    SCEnter();
    if (sig == NULL)
        SCReturn;
    if (sig->cd)
        DetectContentFree(NULL, sig->cd);
    SCFree(sig);
    SCReturn;
}

static int AppLayerProtoDetectPMAddSignature(AppLayerProtoDetectPMCtx *ctx, DetectContentData *cd,
                                             AppProto alproto, uint8_t direction,
                                             ProbingParserFPtr PPFunc,
                                             uint16_t pp_min_depth, uint16_t pp_max_depth)
{
    SCEnter();

    AppLayerProtoDetectPMSignature *s = SCCalloc(1, sizeof(*s));
    if (unlikely(s == NULL))
        SCReturnInt(-1);

    s->alproto = alproto;
    s->direction = direction;
    s->cd = cd;
    s->PPFunc = PPFunc;
    s->pp_min_depth = pp_min_depth;
    s->pp_max_depth = pp_max_depth;

    /* prepend to the list */
    s->next = ctx->head;
    ctx->head = s;

    SCReturnInt(0);
}

static int AppLayerProtoDetectPMRegisterPattern(uint8_t ipproto, AppProto alproto,
                                                const char *pattern,
                                                uint16_t depth, uint16_t offset,
                                                uint8_t direction,
                                                uint8_t is_cs,
                                                ProbingParserFPtr PPFunc,
                                                uint16_t pp_min_depth, uint16_t pp_max_depth)
{
    SCEnter();

    AppLayerProtoDetectCtxIpproto *ctx_ipp = &alpd_ctx.ctx_ipp[FlowGetProtoMapping(ipproto)];
    AppLayerProtoDetectPMCtx *ctx_pm = NULL;
    int ret = 0;

    DetectContentData *cd = DetectContentParseEncloseQuotes(
            alpd_ctx.spm_global_thread_ctx, pattern);
    if (cd == NULL)
        goto error;
    cd->depth = depth;
    cd->offset = offset;
    if (!is_cs) {
        /* Rebuild as nocase */
        SpmDestroyCtx(cd->spm_ctx);
        cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
                                 alpd_ctx.spm_global_thread_ctx);
        if (cd->spm_ctx == NULL) {
            goto error;
        }
        cd->flags |= DETECT_CONTENT_NOCASE;
    }
    if (depth < cd->content_len)
        goto error;

    if (direction & STREAM_TOSERVER)
        ctx_pm = (AppLayerProtoDetectPMCtx *)&ctx_ipp->ctx_pm[0];
    else
        ctx_pm = (AppLayerProtoDetectPMCtx *)&ctx_ipp->ctx_pm[1];

    if (pp_max_depth > ctx_pm->pp_max_len)
        ctx_pm->pp_max_len = pp_max_depth;
    if (depth < ctx_pm->min_len)
        ctx_pm->min_len = depth;

    /* Finally turn it into a signature and add to the ctx. */
    AppLayerProtoDetectPMAddSignature(ctx_pm, cd, alproto, direction,
            PPFunc, pp_min_depth, pp_max_depth);

    goto end;
 error:
    DetectContentFree(NULL, cd);
    ret = -1;
 end:
    SCReturnInt(ret);
}

/***** Protocol Retrieval *****/

AppProto AppLayerProtoDetectGetProto(AppLayerProtoDetectThreadCtx *tctx, Flow *f,
        const uint8_t *buf, uint32_t buflen, uint8_t ipproto, uint8_t flags, bool *reverse_flow)
{
    SCEnter();
    SCLogDebug("buflen %u for %s direction", buflen,
            (flags & STREAM_TOSERVER) ? "toserver" : "toclient");

    AppProto alproto = ALPROTO_UNKNOWN;
    AppProto pm_alproto = ALPROTO_UNKNOWN;

    if (!FLOW_IS_PM_DONE(f, flags)) {
        AppProto pm_results[ALPROTO_MAX];
        uint16_t pm_matches = AppLayerProtoDetectPMGetProto(
                tctx, f, buf, buflen, flags, pm_results, reverse_flow);
        if (pm_matches > 0) {
            DEBUG_VALIDATE_BUG_ON(pm_matches > 1);
            alproto = pm_results[0];

            // rerun probing parser for other direction if it is unknown
            uint8_t reverse_dir = (flags & STREAM_TOSERVER) ? STREAM_TOCLIENT : STREAM_TOSERVER;
            if (FLOW_IS_PP_DONE(f, reverse_dir)) {
                AppProto rev_alproto = (flags & STREAM_TOSERVER) ? f->alproto_tc : f->alproto_ts;
                if (rev_alproto == ALPROTO_UNKNOWN) {
                    FLOW_RESET_PP_DONE(f, reverse_dir);
                }
            }

            /* HACK: if detected protocol is dcerpc/udp, we run PP as well
             * to avoid misdetecting DNS as DCERPC. */
            if (!(ipproto == IPPROTO_UDP && alproto == ALPROTO_DCERPC))
                goto end;

            pm_alproto = alproto;

            /* fall through */
        }
    }

    if (!FLOW_IS_PP_DONE(f, flags)) {
        bool rflow = false;
        alproto = AppLayerProtoDetectPPGetProto(f, buf, buflen, ipproto, flags, &rflow);
        if (AppProtoIsValid(alproto)) {
            if (rflow) {
                *reverse_flow = true;
            }
            goto end;
        }
    }

    /* Look if flow can be found in expectation list */
    if (!FLOW_IS_PE_DONE(f, flags)) {
        alproto = AppLayerProtoDetectPEGetProto(f, ipproto, flags);
    }

 end:
    if (!AppProtoIsValid(alproto))
        alproto = pm_alproto;

    SCReturnUInt(alproto);
}

static void AppLayerProtoDetectFreeProbingParsers(AppLayerProtoDetectProbingParser *pp)
{
    SCEnter();

    AppLayerProtoDetectProbingParser *tmp_pp = NULL;

    if (pp == NULL)
        goto end;

    while (pp != NULL) {
        tmp_pp = pp->next;
        AppLayerProtoDetectProbingParserFree(pp);
        pp = tmp_pp;
    }

 end:
    SCReturn;
}

static void AppLayerProtoDetectFreeAliases(void)
{
    SCEnter();

    AppLayerProtoDetectAliases *cur_alias = alpda_ctx;
    if (cur_alias == NULL)
        goto end;

    AppLayerProtoDetectAliases *next_alias = NULL;
    while (cur_alias != NULL) {
        next_alias = cur_alias->next;
        SCFree(cur_alias);
        cur_alias = next_alias;
    }

    alpda_ctx = NULL;

end:
    SCReturn;
}

/***** State Preparation *****/

int AppLayerProtoDetectPrepareState(void)
{
    SCEnter();

    AppLayerProtoDetectPMCtx *ctx_pm;
    int i, j;
    int ret = 0;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            ctx_pm = &alpd_ctx.ctx_ipp[i].ctx_pm[j];

            if (AppLayerProtoDetectPMSetContentIDs(ctx_pm) < 0)
                goto error;

            if (ctx_pm->max_sig_id == 0)
                continue;

            if (AppLayerProtoDetectPMMapSignatures(ctx_pm) < 0)
                goto error;
            if (AppLayerProtoDetectPMPrepareMpm(ctx_pm) < 0)
                goto error;
        }
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        AppLayerProtoDetectPrintProbingParsers(alpd_ctx.ctx_pp);
    }
#endif

    goto end;
 error:
    ret = -1;
 end:
    SCReturnInt(ret);
}

/***** PP registration *****/

/** \brief register parser at a port
 *
 *  \param direction STREAM_TOSERVER or STREAM_TOCLIENT for dp or sp
 */
void AppLayerProtoDetectPPRegister(uint8_t ipproto,
                                   const char *portstr,
                                   AppProto alproto,
                                   uint16_t min_depth, uint16_t max_depth,
                                   uint8_t direction,
                                   ProbingParserFPtr ProbingParser1,
                                   ProbingParserFPtr ProbingParser2)
{
    SCEnter();

    DetectPort *head = NULL;
    DetectPortParse(NULL,&head, portstr);
    DetectPort *temp_dp = head;
    while (temp_dp != NULL) {
        uint16_t port = temp_dp->port;
        if (port == 0 && temp_dp->port2 != 0)
            port++;
        for (;;) {
            AppLayerProtoDetectInsertNewProbingParser(&alpd_ctx.ctx_pp,
                                                      ipproto,
                                                      port,
                                                      alproto,
                                                      min_depth, max_depth,
                                                      direction,
                                                      ProbingParser1,
                                                      ProbingParser2);
            if (port == temp_dp->port2) {
                break;
            } else {
                port++;
            }
        }
        temp_dp = temp_dp->next;
    }
    DetectPortCleanupList(NULL,head);

    SCReturn;
}

int AppLayerProtoDetectPPParseConfPorts(const char *ipproto_name,
                                         uint8_t ipproto,
                                         const char *alproto_name,
                                         AppProto alproto,
                                         uint16_t min_depth, uint16_t max_depth,
                                         ProbingParserFPtr ProbingParserTs,
                                         ProbingParserFPtr ProbingParserTc)
{
    SCEnter();

    char param[100];
    int r;
    ConfNode *node;
    ConfNode *port_node = NULL;
    int config = 0;

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto_name, ".detection-ports");
    if (r < 0) {
        FatalError(SC_ERR_FATAL, "snprintf failure.");
    } else if (r > (int)sizeof(param)) {
        FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
    }
    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogDebug("Entry for %s not found.", param);
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto_name, ".", ipproto_name, ".detection-ports");
        if (r < 0) {
            FatalError(SC_ERR_FATAL, "snprintf failure.");
        } else if (r > (int)sizeof(param)) {
            FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
        }
        node = ConfGetNode(param);
        if (node == NULL)
            goto end;
    }

    /* detect by destination port of the flow (e.g. port 53 for DNS) */
    port_node = ConfNodeLookupChild(node, "dp");
    if (port_node == NULL)
        port_node = ConfNodeLookupChild(node, "toserver");

    if (port_node != NULL && port_node->val != NULL) {
        AppLayerProtoDetectPPRegister(ipproto,
                                      port_node->val,
                                      alproto,
                                      min_depth, max_depth,
                                      STREAM_TOSERVER, /* to indicate dp */
                                      ProbingParserTs, ProbingParserTc);
    }

    /* detect by source port of flow */
    port_node = ConfNodeLookupChild(node, "sp");
    if (port_node == NULL)
        port_node = ConfNodeLookupChild(node, "toclient");

    if (port_node != NULL && port_node->val != NULL) {
        AppLayerProtoDetectPPRegister(ipproto,
                                      port_node->val,
                                      alproto,
                                      min_depth, max_depth,
                                      STREAM_TOCLIENT, /* to indicate sp */
                                      ProbingParserTc, ProbingParserTs);

    }

    config = 1;
 end:
    SCReturnInt(config);
}

/***** PM registration *****/

int AppLayerProtoDetectPMRegisterPatternCS(uint8_t ipproto, AppProto alproto,
                                           const char *pattern,
                                           uint16_t depth, uint16_t offset,
                                           uint8_t direction)
{
    SCEnter();
    int r = AppLayerProtoDetectPMRegisterPattern(ipproto, alproto,
            pattern, depth, offset,
            direction, 1 /* case-sensitive */,
            NULL, 0, 0);
    SCReturnInt(r);
}

int AppLayerProtoDetectPMRegisterPatternCSwPP(uint8_t ipproto, AppProto alproto,
        const char *pattern, uint16_t depth, uint16_t offset,
        uint8_t direction,
        ProbingParserFPtr PPFunc,
        uint16_t pp_min_depth, uint16_t pp_max_depth)
{
    SCEnter();
    int r = AppLayerProtoDetectPMRegisterPattern(ipproto, alproto,
            pattern, depth, offset,
            direction, 1 /* case-sensitive */,
            PPFunc, pp_min_depth, pp_max_depth);
    SCReturnInt(r);
}

int AppLayerProtoDetectPMRegisterPatternCI(uint8_t ipproto, AppProto alproto,
                                           const char *pattern,
                                           uint16_t depth, uint16_t offset,
                                           uint8_t direction)
{
    SCEnter();
    int r = AppLayerProtoDetectPMRegisterPattern(ipproto, alproto,
            pattern, depth, offset,
            direction, 0 /* !case-sensitive */,
            NULL, 0, 0);
    SCReturnInt(r);
}

/***** Setup/General Registration *****/

int AppLayerProtoDetectSetup(void)
{
    SCEnter();

    int i, j;

    memset(&alpd_ctx, 0, sizeof(alpd_ctx));

    uint16_t spm_matcher = SinglePatternMatchDefaultMatcher();
    uint8_t mpm_matcher = PatternMatchDefaultMatcher();

    alpd_ctx.spm_global_thread_ctx = SpmInitGlobalThreadCtx(spm_matcher);
    if (alpd_ctx.spm_global_thread_ctx == NULL) {
        FatalError(SC_ERR_FATAL, "Unable to alloc SpmGlobalThreadCtx.");
    }

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            MpmInitCtx(&alpd_ctx.ctx_ipp[i].ctx_pm[j].mpm_ctx, mpm_matcher);
        }
    }

    AppLayerExpectationSetup();

    SCReturnInt(0);
}

/**
 * \todo incomplete.  Need more work.
 */
int AppLayerProtoDetectDeSetup(void)
{
    SCEnter();

    int ipproto_map = 0;
    int dir = 0;
    PatIntId id = 0;
    AppLayerProtoDetectPMCtx *pm_ctx = NULL;
    AppLayerProtoDetectPMSignature *sig = NULL;

    for (ipproto_map = 0; ipproto_map < FLOW_PROTO_DEFAULT; ipproto_map++) {
        for (dir = 0; dir < 2; dir++) {
            pm_ctx = &alpd_ctx.ctx_ipp[ipproto_map].ctx_pm[dir];
            mpm_table[pm_ctx->mpm_ctx.mpm_type].DestroyCtx(&pm_ctx->mpm_ctx);
            for (id = 0; id < pm_ctx->max_sig_id; id++) {
                sig = pm_ctx->map[id];
                AppLayerProtoDetectPMFreeSignature(sig);
            }
            SCFree(pm_ctx->map);
            pm_ctx->map = NULL;
        }
    }

    SpmDestroyGlobalThreadCtx(alpd_ctx.spm_global_thread_ctx);

    AppLayerProtoDetectFreeAliases();

    AppLayerProtoDetectFreeProbingParsers(alpd_ctx.ctx_pp);

    SCReturnInt(0);
}

void AppLayerProtoDetectRegisterProtocol(AppProto alproto, const char *alproto_name)
{
    SCEnter();

    if (alpd_ctx.alproto_names[alproto] == NULL)
        alpd_ctx.alproto_names[alproto] = alproto_name;

    SCReturn;
}

void AppLayerProtoDetectRegisterAlias(const char *proto_name, const char *proto_alias)
{
    SCEnter();

    AppLayerProtoDetectAliases *new_alias = SCMalloc(sizeof(AppLayerProtoDetectAliases));
    if (unlikely(new_alias == NULL)) {
        exit(EXIT_FAILURE);
    }

    new_alias->proto_name = proto_name;
    new_alias->proto_alias = proto_alias;
    new_alias->next = NULL;

    if (alpda_ctx == NULL) {
        alpda_ctx = new_alias;
    } else {
        AppLayerProtoDetectAliases *cur_alias = alpda_ctx;
        while (cur_alias->next != NULL) {
            cur_alias = cur_alias->next;
        }
        cur_alias->next = new_alias;
    }

    SCReturn;
}

/** \brief request applayer to wrap up this protocol and rerun protocol
 *         detection.
 *
 *  When this is called, the old session is reset unconditionally. A
 *  'detect/log' flush packet is generated for both direction before
 *  the reset, so allow for final detection and logging.
 *
 *  \param f flow to act on
 *  \param dp destination port to use in protocol detection. Set to 443
 *            for start tls, set to the HTTP uri port for CONNECT and
 *            set to 0 to not use it.
 *  \param expect_proto expected protocol. AppLayer event will be set if
 *                      detected protocol differs from this.
 */
bool AppLayerRequestProtocolChange(Flow *f, uint16_t dp, AppProto expect_proto)
{
    if (FlowChangeProto(f)) {
        // If we are already changing protocols, from SMTP to TLS for instance,
        // and that we do not get TLS but HTTP1, which is requesting whange to HTTP2,
        // we do not proceed the new protocol change
        return false;
    }
    FlowSetChangeProtoFlag(f);
    f->protodetect_dp = dp;
    f->alproto_expect = expect_proto;
    DEBUG_VALIDATE_BUG_ON(f->alproto == ALPROTO_UNKNOWN);
    f->alproto_orig = f->alproto;
    // If one side is unknown yet, set it to the other known side
    if (f->alproto_ts == ALPROTO_UNKNOWN) {
        f->alproto_ts = f->alproto;
    }
    if (f->alproto_tc == ALPROTO_UNKNOWN) {
        f->alproto_tc = f->alproto;
    }
    return true;
}

/** \brief request applayer to wrap up this protocol and rerun protocol
 *         detection with expectation of TLS. Used by STARTTLS.
 *
 *  Sets detection port to 443 to make port based TLS detection work for
 *  SMTP, FTP etc as well.
 *
 *  \param f flow to act on
 */
bool AppLayerRequestProtocolTLSUpgrade(Flow *f)
{
    return AppLayerRequestProtocolChange(f, 443, ALPROTO_TLS);
}

void AppLayerProtoDetectReset(Flow *f)
{
    FLOW_RESET_PM_DONE(f, STREAM_TOSERVER);
    FLOW_RESET_PM_DONE(f, STREAM_TOCLIENT);
    FLOW_RESET_PP_DONE(f, STREAM_TOSERVER);
    FLOW_RESET_PP_DONE(f, STREAM_TOCLIENT);
    FLOW_RESET_PE_DONE(f, STREAM_TOSERVER);
    FLOW_RESET_PE_DONE(f, STREAM_TOCLIENT);
    f->probing_parser_toserver_alproto_masks = 0;
    f->probing_parser_toclient_alproto_masks = 0;

    // Does not free the structures for the parser
    // keeps f->alstate for new state creation
    f->alparser = NULL;
    f->alproto    = ALPROTO_UNKNOWN;
    f->alproto_ts = ALPROTO_UNKNOWN;
    f->alproto_tc = ALPROTO_UNKNOWN;
}

int AppLayerProtoDetectConfProtoDetectionEnabledDefault(
        const char *ipproto, const char *alproto, bool default_enabled)
{
    SCEnter();

    BUG_ON(ipproto == NULL || alproto == NULL);

    int enabled = 1;
    char param[100];
    ConfNode *node;
    int r;

    if (RunmodeIsUnittests())
        goto enabled;

    r = snprintf(param, sizeof(param), "%s%s%s", "app-layer.protocols.",
                 alproto, ".enabled");
    if (r < 0) {
        FatalError(SC_ERR_FATAL, "snprintf failure.");
    } else if (r > (int)sizeof(param)) {
        FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
    }

    node = ConfGetNode(param);
    if (node == NULL) {
        SCLogDebug("Entry for %s not found.", param);
        r = snprintf(param, sizeof(param), "%s%s%s%s%s", "app-layer.protocols.",
                     alproto, ".", ipproto, ".enabled");
        if (r < 0) {
            FatalError(SC_ERR_FATAL, "snprintf failure.");
        } else if (r > (int)sizeof(param)) {
            FatalError(SC_ERR_FATAL, "buffer not big enough to write param.");
        }

        node = ConfGetNode(param);
        if (node == NULL) {
            SCLogDebug("Entry for %s not found.", param);
            if (default_enabled) {
                goto enabled;
            } else {
                goto disabled;
            }
        }
    }

    if (node->val) {
        if (ConfValIsTrue(node->val)) {
            goto enabled;
        } else if (ConfValIsFalse(node->val)) {
            goto disabled;
        } else if (strcasecmp(node->val, "detection-only") == 0) {
            goto enabled;
        }
    }

    /* Invalid or null value. */
    SCLogError(SC_ERR_FATAL, "Invalid value found for %s.", param);
    exit(EXIT_FAILURE);

 disabled:
    enabled = 0;
 enabled:
    SCReturnInt(enabled);
}

int AppLayerProtoDetectConfProtoDetectionEnabled(const char *ipproto, const char *alproto)
{
    return AppLayerProtoDetectConfProtoDetectionEnabledDefault(ipproto, alproto, true);
}

AppLayerProtoDetectThreadCtx *AppLayerProtoDetectGetCtxThread(void)
{
    SCEnter();

    AppLayerProtoDetectThreadCtx *alpd_tctx = NULL;
    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int i, j;
    PatIntId max_pat_id = 0;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            if (max_pat_id == 0) {
                max_pat_id = alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id;

            } else if (alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id &&
                    max_pat_id < alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id)
            {
                max_pat_id = alpd_ctx.ctx_ipp[i].ctx_pm[j].max_pat_id;
            }
        }
    }

    alpd_tctx = SCMalloc(sizeof(*alpd_tctx));
    if (alpd_tctx == NULL)
        goto error;
    memset(alpd_tctx, 0, sizeof(*alpd_tctx));

    /* Get the max pat id for all the mpm ctxs. */
    if (PmqSetup(&alpd_tctx->pmq) < 0)
        goto error;

    for (i = 0; i < FLOW_PROTO_DEFAULT; i++) {
        for (j = 0; j < 2; j++) {
            mpm_ctx = &alpd_ctx.ctx_ipp[i].ctx_pm[j].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[i][j];
            mpm_table[mpm_ctx->mpm_type].InitThreadCtx(mpm_ctx, mpm_tctx);
        }
    }

    alpd_tctx->spm_thread_ctx = SpmMakeThreadCtx(alpd_ctx.spm_global_thread_ctx);
    if (alpd_tctx->spm_thread_ctx == NULL) {
        goto error;
    }

    goto end;
 error:
    if (alpd_tctx != NULL)
        AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    alpd_tctx = NULL;
 end:
    SCReturnPtr(alpd_tctx, "AppLayerProtoDetectThreadCtx");
}

void AppLayerProtoDetectDestroyCtxThread(AppLayerProtoDetectThreadCtx *alpd_tctx)
{
    SCEnter();

    MpmCtx *mpm_ctx;
    MpmThreadCtx *mpm_tctx;
    int ipproto_map, dir;

    for (ipproto_map = 0; ipproto_map < FLOW_PROTO_DEFAULT; ipproto_map++) {
        for (dir = 0; dir < 2; dir++) {
            mpm_ctx = &alpd_ctx.ctx_ipp[ipproto_map].ctx_pm[dir].mpm_ctx;
            mpm_tctx = &alpd_tctx->mpm_tctx[ipproto_map][dir];
            mpm_table[mpm_ctx->mpm_type].DestroyThreadCtx(mpm_ctx, mpm_tctx);
        }
    }
    PmqFree(&alpd_tctx->pmq);
    if (alpd_tctx->spm_thread_ctx != NULL) {
        SpmDestroyThreadCtx(alpd_tctx->spm_thread_ctx);
    }
    SCFree(alpd_tctx);

    SCReturn;
}

/***** Utility *****/

void AppLayerProtoDetectSupportedIpprotos(AppProto alproto, uint8_t *ipprotos)
{
    SCEnter();

    // Custom case for only signature-only protocol so far
    if (alproto == ALPROTO_HTTP) {
        AppLayerProtoDetectSupportedIpprotos(ALPROTO_HTTP1, ipprotos);
        AppLayerProtoDetectSupportedIpprotos(ALPROTO_HTTP2, ipprotos);
    } else {
        AppLayerProtoDetectPMGetIpprotos(alproto, ipprotos);
        AppLayerProtoDetectPPGetIpprotos(alproto, ipprotos);
        AppLayerProtoDetectPEGetIpprotos(alproto, ipprotos);
    }

    SCReturn;
}

AppProto AppLayerProtoDetectGetProtoByName(const char *alproto_name)
{
    SCEnter();

    AppLayerProtoDetectAliases *cur_alias = alpda_ctx;
    while (cur_alias != NULL) {
        if (strcasecmp(alproto_name, cur_alias->proto_alias) == 0) {
            alproto_name = cur_alias->proto_name;
        }

        cur_alias = cur_alias->next;
    }

    AppProto a;
    AppProto b = StringToAppProto(alproto_name);
    for (a = 0; a < ALPROTO_MAX; a++) {
        if (alpd_ctx.alproto_names[a] != NULL && AppProtoEquals(b, a)) {
            // That means return HTTP_ANY if HTTP1 or HTTP2 is enabled
            SCReturnCT(b, "AppProto");
        }
    }

    SCReturnCT(ALPROTO_UNKNOWN, "AppProto");
}

const char *AppLayerProtoDetectGetProtoName(AppProto alproto)
{
    // Special case for http (any version) :
    // returns "http" if both versions are enabled
    // and returns "http1" or "http2" if only one version is enabled
    if (alproto == ALPROTO_HTTP) {
        if (alpd_ctx.alproto_names[ALPROTO_HTTP1]) {
            if (alpd_ctx.alproto_names[ALPROTO_HTTP2]) {
                return "http";
            } // else
            return alpd_ctx.alproto_names[ALPROTO_HTTP1];
        } // else
        return alpd_ctx.alproto_names[ALPROTO_HTTP2];
    }
    return alpd_ctx.alproto_names[alproto];
}

void AppLayerProtoDetectSupportedAppProtocols(AppProto *alprotos)
{
    SCEnter();

    memset(alprotos, 0, ALPROTO_MAX * sizeof(AppProto));

    int alproto;

    for (alproto = 0; alproto != ALPROTO_MAX; alproto++) {
        if (alpd_ctx.alproto_names[alproto] != NULL)
            alprotos[alproto] = 1;
    }

    SCReturn;
}

uint8_t expectation_proto[ALPROTO_MAX];

static void AppLayerProtoDetectPEGetIpprotos(AppProto alproto,
                                             uint8_t *ipprotos)
{
    if (expectation_proto[alproto] == IPPROTO_TCP) {
        ipprotos[IPPROTO_TCP / 8] |= 1 << (IPPROTO_TCP % 8);
    }
    if (expectation_proto[alproto] == IPPROTO_UDP) {
        ipprotos[IPPROTO_UDP / 8] |= 1 << (IPPROTO_UDP % 8);
    }
}

void AppLayerRegisterExpectationProto(uint8_t proto, AppProto alproto)
{
    if (expectation_proto[alproto]) {
        if (proto != expectation_proto[alproto]) {
            SCLogError(SC_ERR_NOT_SUPPORTED,
                       "Expectation on 2 IP protocols are not supported");
        }
    }
    expectation_proto[alproto] = proto;
}

/***** Unittests *****/

#ifdef UNITTESTS

#include "app-layer-htp.h"
#include "detect-engine-alert.h"

static AppLayerProtoDetectCtx alpd_ctx_ut;

void AppLayerProtoDetectUnittestCtxBackup(void)
{
    SCEnter();
    alpd_ctx_ut = alpd_ctx;
    memset(&alpd_ctx, 0, sizeof(alpd_ctx));
    SCReturn;
}

void AppLayerProtoDetectUnittestCtxRestore(void)
{
    SCEnter();
    alpd_ctx = alpd_ctx_ut;
    memset(&alpd_ctx_ut, 0, sizeof(alpd_ctx_ut));
    SCReturn;
}

static int AppLayerProtoDetectTest01(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);
    buf = "GET";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOSERVER);

    AppLayerProtoDetectPrepareState();
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);

    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest02(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);
    buf = "ftp";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 2);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_FTP);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[1]->alproto != ALPROTO_HTTP1);

    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest03(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);


    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);
    buf = "220 ";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 2);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_FTP);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[1]->alproto != ALPROTO_HTTP1);

    bool rflow = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
                                                 &f, l7data, sizeof(l7data),
                                                 STREAM_TOCLIENT,
                                                 pm_results, &rflow);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest04(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n";
    Flow f;
    memset(&f, 0x00, sizeof(f));
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "200 ";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 13, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_HTTP1);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest05(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "HTTP/1.1 200 OK\r\nServer: Apache/1.0\r\n\r\n<HTML><BODY>Blahblah</BODY></HTML>";
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);
    buf = "220 ";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 2);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_FTP);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[1]->alproto != ALPROTO_HTTP1);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data),
            STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest06(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "220 Welcome to the OISF FTP server\r\n";
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);
    buf = "220 ";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_FTP, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 2);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_FTP);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[1]->alproto != ALPROTO_HTTP1);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_FTP);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest07(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "220 Welcome to the OISF HTTP/FTP server\r\n";
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));

    const char *buf = "HTTP";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_HTTP1, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_HTTP1);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 0);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest08(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = {
        0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
        0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
        0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
        0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
        0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
        0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
        0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57,
        0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
        0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
        0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
        0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
        0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54,
        0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
        0x00
    };
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "|ff|SMB";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, buf, 8, 4, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_SMB);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_SMB);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest09(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = {
        0x00, 0x00, 0x00, 0x66, 0xfe, 0x53, 0x4d, 0x42,
        0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x02, 0x02
    };
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "|fe|SMB";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, buf, 8, 4, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_SMB);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_SMB);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

static int AppLayerProtoDetectTest10(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0xb8, 0x4a, 0x9f, 0x4d, 0x1c, 0x7d, 0xcf, 0x11,
        0x86, 0x1e, 0x00, 0x20, 0xaf, 0x6e, 0x7c, 0x57,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00
    };
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    const char *buf = "|05 00|";
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_DCERPC, buf, 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 0);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_DCERPC);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_DCERPC);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

/**
 * \test Why we still get http for connect... obviously because
 *       we also match on the reply, duh
 */
static int AppLayerProtoDetectTest11(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    AppProto pm_results[ALPROTO_MAX];
    memset(pm_results, 0, sizeof(pm_results));
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "GET", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "PUT", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "POST", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "TRACE", 5, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "CONNECT", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 7);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].max_pat_id != 1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map == NULL);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map == NULL);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[0]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[1]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[2]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[3]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[4]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[5]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[6]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[1].map[0]->alproto != ALPROTO_HTTP1);

    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOSERVER,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    memset(pm_results, 0, sizeof(pm_results));
    cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data_resp, sizeof(l7data_resp), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

/**
 * \test AlpProtoSignature test
 */
static int AppLayerProtoDetectTest12(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    int r = 0;

    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_TCP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOSERVER);
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].head == NULL ||
        alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map != NULL)
    {
        printf("failure 1\n");
        goto end;
    }

    AppLayerProtoDetectPrepareState();
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].max_pat_id != 1) {
        printf("failure 2\n");
        goto end;
    }
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].head != NULL ||
        alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map == NULL)
    {
        printf("failure 3\n");
        goto end;
    }
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[0]->alproto != ALPROTO_HTTP1) {
        printf("failure 4\n");
        goto end;
    }
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[0]->cd->id != 0) {
        printf("failure 5\n");
        goto end;
    }
    if (alpd_ctx.ctx_ipp[FLOW_PROTO_TCP].ctx_pm[0].map[0]->next != NULL) {
        printf("failure 6\n");
        goto end;
    }

    r = 1;

 end:
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    return r;
}

/**
 * \test What about if we add some sigs only for udp but call for tcp?
 *       It should not detect any proto
 */
static int AppLayerProtoDetectTest13(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    AppProto pm_results[ALPROTO_MAX];

    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_TCP);

    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "GET", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "PUT", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "POST", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "TRACE", 5, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "CONNECT", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].max_pat_id != 7);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[1].max_pat_id != 1);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[0]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[1]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[2]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[3]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[4]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[5]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[6]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[1].map[0]->alproto != ALPROTO_HTTP1);

    memset(pm_results, 0, sizeof(pm_results));
    bool rdir = false;
    uint32_t cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOSERVER,
            pm_results, &rdir);
    FAIL_IF(cnt != 0);

    memset(pm_results, 0, sizeof(pm_results));
    cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data_resp, sizeof(l7data_resp), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 0);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

/**
 * \test What about if we add some sigs only for udp calling it for UDP?
 *       It should detect ALPROTO_HTTP1 (over udp). This is just a check
 *       to ensure that TCP/UDP differences work correctly.
 */
static int AppLayerProtoDetectTest14(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t l7data[] = "CONNECT www.ssllabs.com:443 HTTP/1.0\r\n";
    uint8_t l7data_resp[] = "HTTP/1.1 405 Method Not Allowed\r\n";
    AppProto pm_results[ALPROTO_MAX];
    uint32_t cnt;
    Flow f;
    memset(&f, 0x00, sizeof(f));
    f.protomap = FlowGetProtoMapping(IPPROTO_UDP);

    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "GET", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "PUT", 3, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "POST", 4, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "TRACE", 5, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "OPTIONS", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "CONNECT", 7, 0, STREAM_TOSERVER);
    AppLayerProtoDetectPMRegisterPatternCS(
            IPPROTO_UDP, ALPROTO_HTTP1, "HTTP", 4, 0, STREAM_TOCLIENT);

    AppLayerProtoDetectPrepareState();
    /* AppLayerProtoDetectGetCtxThread() should be called post AppLayerProtoDetectPrepareState(), since
     * it sets internal structures which depends on the above function. */
    AppLayerProtoDetectThreadCtx *alpd_tctx = AppLayerProtoDetectGetCtxThread();
    FAIL_IF_NULL(alpd_tctx);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].max_pat_id != 7);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[1].max_pat_id != 1);

    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[0]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[1]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[2]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[3]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[4]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[5]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[0].map[6]->alproto != ALPROTO_HTTP1);
    FAIL_IF(alpd_ctx.ctx_ipp[FLOW_PROTO_UDP].ctx_pm[1].map[0]->alproto != ALPROTO_HTTP1);

    memset(pm_results, 0, sizeof(pm_results));
    bool rdir = false;
    cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data, sizeof(l7data), STREAM_TOSERVER,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    memset(pm_results, 0, sizeof(pm_results));
    cnt = AppLayerProtoDetectPMGetProto(alpd_tctx,
            &f, l7data_resp, sizeof(l7data_resp), STREAM_TOCLIENT,
            pm_results, &rdir);
    FAIL_IF(cnt != 1);
    FAIL_IF(pm_results[0] != ALPROTO_HTTP1);

    AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    PASS;
}

typedef struct AppLayerProtoDetectPPTestDataElement_ {
    const char *alproto_name;
    AppProto alproto;
    uint16_t port;
    uint32_t alproto_mask;
    uint32_t min_depth;
    uint32_t max_depth;
} AppLayerProtoDetectPPTestDataElement;

typedef struct AppLayerProtoDetectPPTestDataPort_ {
    uint16_t port;
    uint32_t alproto_mask;
    uint16_t dp_max_depth;
    uint16_t sp_max_depth;

    AppLayerProtoDetectPPTestDataElement *toserver_element;
    AppLayerProtoDetectPPTestDataElement *toclient_element;
    int ts_no_of_element;
    int tc_no_of_element;
} AppLayerProtoDetectPPTestDataPort;


typedef struct AppLayerProtoDetectPPTestDataIPProto_ {
    uint8_t ipproto;

    AppLayerProtoDetectPPTestDataPort *port;
    int no_of_port;
} AppLayerProtoDetectPPTestDataIPProto;

static int AppLayerProtoDetectPPTestData(AppLayerProtoDetectProbingParser *pp,
                                         AppLayerProtoDetectPPTestDataIPProto *ip_proto,
                                         int no_of_ip_proto)
{
    int result = 0;
    int i = -1, j = -1 , k = -1;
#ifdef DEBUG
    int dir = 0;
#endif
    for (i = 0; i < no_of_ip_proto; i++, pp = pp->next) {
        if (pp->ipproto != ip_proto[i].ipproto)
            goto end;

        AppLayerProtoDetectProbingParserPort *pp_port = pp->port;
        for (k = 0; k < ip_proto[i].no_of_port; k++, pp_port = pp_port->next) {
            if (pp_port->port != ip_proto[i].port[k].port)
                goto end;
            if (pp_port->alproto_mask != ip_proto[i].port[k].alproto_mask)
                goto end;
            if (pp_port->alproto_mask != ip_proto[i].port[k].alproto_mask)
                goto end;
            if (pp_port->dp_max_depth != ip_proto[i].port[k].dp_max_depth)
                goto end;
            if (pp_port->sp_max_depth != ip_proto[i].port[k].sp_max_depth)
                goto end;

            AppLayerProtoDetectProbingParserElement *pp_element = pp_port->dp;
#ifdef DEBUG
            dir = 0;
#endif
            for (j = 0 ; j < ip_proto[i].port[k].ts_no_of_element;
                 j++, pp_element = pp_element->next) {

                if (pp_element->alproto != ip_proto[i].port[k].toserver_element[j].alproto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toserver_element[j].port) {
                    goto end;
                }
                if (pp_element->alproto_mask != ip_proto[i].port[k].toserver_element[j].alproto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toserver_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toserver_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;

            pp_element = pp_port->sp;
#ifdef DEBUG
            dir = 1;
#endif
            for (j = 0 ; j < ip_proto[i].port[k].tc_no_of_element; j++, pp_element = pp_element->next) {
                if (pp_element->alproto != ip_proto[i].port[k].toclient_element[j].alproto) {
                    goto end;
                }
                if (pp_element->port != ip_proto[i].port[k].toclient_element[j].port) {
                    goto end;
                }
                if (pp_element->alproto_mask != ip_proto[i].port[k].toclient_element[j].alproto_mask) {
                    goto end;
                }
                if (pp_element->min_depth != ip_proto[i].port[k].toclient_element[j].min_depth) {
                    goto end;
                }
                if (pp_element->max_depth != ip_proto[i].port[k].toclient_element[j].max_depth) {
                    goto end;
                }
            } /* for */
            if (pp_element != NULL)
                goto end;
        }
        if (pp_port != NULL)
            goto end;
    }
    if (pp != NULL)
        goto end;

    result = 1;
 end:
#ifdef DEBUG
    printf("i = %d, k = %d, j = %d(%s)\n", i, k, j, (dir == 0) ? "ts" : "tc");
#endif
    return result;
}

static uint16_t ProbingParserDummyForTesting(Flow *f, uint8_t direction,
                                             const uint8_t *input,
                                             uint32_t input_len, uint8_t *rdir)
{
    return 0;
}

static int AppLayerProtoDetectTest15(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    int result = 0;

    AppLayerProtoDetectPPRegister(IPPROTO_TCP, "80", ALPROTO_HTTP1, 5, 8, STREAM_TOSERVER,
            ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "80",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "80",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);

    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "81",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "81",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_SMTP,
                                  12, 0,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);

    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "85",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "85",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);
    result = 1;

    AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                  "85",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOSERVER,
                                  ProbingParserDummyForTesting, NULL);

    /* toclient */
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_JABBER,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_IRC,
                                  12, 14,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);

    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "85",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "81",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_TLS,
                                  12, 18,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP, "80", ALPROTO_HTTP1, 5, 8, STREAM_TOCLIENT,
            ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "81",
                                  ALPROTO_DCERPC,
                                  9, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "90",
                                  ALPROTO_FTP,
                                  7, 15,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "80",
                                  ALPROTO_SMB,
                                  5, 6,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_UDP,
                                  "85",
                                  ALPROTO_IMAP,
                                  12, 23,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "0",
                                  ALPROTO_SMTP,
                                  12, 17,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);
    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "80",
                                  ALPROTO_FTP,
                                  7, 10,
                                  STREAM_TOCLIENT,
                                  ProbingParserDummyForTesting, NULL);

    AppLayerProtoDetectPPTestDataElement element_ts_80[] = {
        { "http", ALPROTO_HTTP1, 80, 1 << ALPROTO_HTTP1, 5, 8 },
        { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
        { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
        { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
        { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
        { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
        { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
    };
    AppLayerProtoDetectPPTestDataElement element_tc_80[] = { { "http", ALPROTO_HTTP1, 80,
                                                                     1 << ALPROTO_HTTP1, 5, 8 },
        { "smb", ALPROTO_SMB, 80, 1 << ALPROTO_SMB, 5, 6 },
        { "ftp", ALPROTO_FTP, 80, 1 << ALPROTO_FTP, 7, 10 },
        { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
        { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
        { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 } };

    AppLayerProtoDetectPPTestDataElement element_ts_81[] = {
        { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerProtoDetectPPTestDataElement element_tc_81[] = {
        { "ftp", ALPROTO_FTP, 81, 1 << ALPROTO_FTP, 7, 15 },
          { "dcerpc", ALPROTO_DCERPC, 81, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerProtoDetectPPTestDataElement element_ts_85[] = {
        { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "ftp", ALPROTO_FTP, 85, 1 << ALPROTO_FTP, 7, 15 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerProtoDetectPPTestDataElement element_tc_85[] = {
        { "dcerpc", ALPROTO_DCERPC, 85, 1 << ALPROTO_DCERPC, 9, 10 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerProtoDetectPPTestDataElement element_ts_90[] = {
        { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerProtoDetectPPTestDataElement element_tc_90[] = {
        { "ftp", ALPROTO_FTP, 90, 1 << ALPROTO_FTP, 7, 15 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };

    AppLayerProtoDetectPPTestDataElement element_ts_0[] = {
        { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 0 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 25 },
          { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
        };
    AppLayerProtoDetectPPTestDataElement element_tc_0[] = {
        { "jabber", ALPROTO_JABBER, 0, 1 << ALPROTO_JABBER, 12, 23 },
          { "irc", ALPROTO_IRC, 0, 1 << ALPROTO_IRC, 12, 14 },
          { "tls", ALPROTO_TLS, 0, 1 << ALPROTO_TLS, 12, 18 },
          { "smtp", ALPROTO_SMTP, 0, 1 << ALPROTO_SMTP, 12, 17 }
        };


    AppLayerProtoDetectPPTestDataElement element_ts_85_udp[] = {
        { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };
    AppLayerProtoDetectPPTestDataElement element_tc_85_udp[] = {
        { "imap", ALPROTO_IMAP, 85, 1 << ALPROTO_IMAP, 12, 23 },
        };

    AppLayerProtoDetectPPTestDataPort ports_tcp[] = {
        {
                80,
                ((1 << ALPROTO_HTTP1) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
                        (1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) |
                        (1 << ALPROTO_JABBER)),
                ((1 << ALPROTO_HTTP1) | (1 << ALPROTO_SMB) | (1 << ALPROTO_FTP) |
                        (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) |
                        (1 << ALPROTO_SMTP)),
                23,
                element_ts_80,
                element_tc_80,
                sizeof(element_ts_80) / sizeof(AppLayerProtoDetectPPTestDataElement),
                sizeof(element_tc_80) / sizeof(AppLayerProtoDetectPPTestDataElement),
        },
        {
                81,
                ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) | (1 << ALPROTO_SMTP) |
                        (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
                ((1 << ALPROTO_FTP) | (1 << ALPROTO_DCERPC) | (1 << ALPROTO_JABBER) |
                        (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
                23,
                element_ts_81,
                element_tc_81,
                sizeof(element_ts_81) / sizeof(AppLayerProtoDetectPPTestDataElement),
                sizeof(element_tc_81) / sizeof(AppLayerProtoDetectPPTestDataElement),
        },
        { 85,
                ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_FTP) | (1 << ALPROTO_SMTP) |
                        (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) | (1 << ALPROTO_JABBER)),
                ((1 << ALPROTO_DCERPC) | (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) |
                        (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
                23, element_ts_85, element_tc_85,
                sizeof(element_ts_85) / sizeof(AppLayerProtoDetectPPTestDataElement),
                sizeof(element_tc_85) / sizeof(AppLayerProtoDetectPPTestDataElement) },
        { 90,
                ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) |
                        (1 << ALPROTO_JABBER)),
                ((1 << ALPROTO_FTP) | (1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) |
                        (1 << ALPROTO_TLS) | (1 << ALPROTO_SMTP)),
                23, element_ts_90, element_tc_90,
                sizeof(element_ts_90) / sizeof(AppLayerProtoDetectPPTestDataElement),
                sizeof(element_tc_90) / sizeof(AppLayerProtoDetectPPTestDataElement) },
        { 0,
                ((1 << ALPROTO_SMTP) | (1 << ALPROTO_TLS) | (1 << ALPROTO_IRC) |
                        (1 << ALPROTO_JABBER)),
                ((1 << ALPROTO_JABBER) | (1 << ALPROTO_IRC) | (1 << ALPROTO_TLS) |
                        (1 << ALPROTO_SMTP)),
                23, element_ts_0, element_tc_0,
                sizeof(element_ts_0) / sizeof(AppLayerProtoDetectPPTestDataElement),
                sizeof(element_tc_0) / sizeof(AppLayerProtoDetectPPTestDataElement) }
    };

    AppLayerProtoDetectPPTestDataPort ports_udp[] = {
        { 85,
            (1 << ALPROTO_IMAP),
            (1 << ALPROTO_IMAP),
            23,
            element_ts_85_udp, element_tc_85_udp,
            sizeof(element_ts_85_udp) / sizeof(AppLayerProtoDetectPPTestDataElement),
            sizeof(element_tc_85_udp) / sizeof(AppLayerProtoDetectPPTestDataElement),
            },
        };

    AppLayerProtoDetectPPTestDataIPProto ip_proto[] = {
        { IPPROTO_TCP,
          ports_tcp,
          sizeof(ports_tcp) / sizeof(AppLayerProtoDetectPPTestDataPort),
        },
        { IPPROTO_UDP,
          ports_udp,
          sizeof(ports_udp) / sizeof(AppLayerProtoDetectPPTestDataPort),
        },
    };


    if (AppLayerProtoDetectPPTestData(alpd_ctx.ctx_pp, ip_proto,
                                      sizeof(ip_proto) / sizeof(AppLayerProtoDetectPPTestDataIPProto)) == 0) {
        goto end;
    }
    result = 1;

 end:
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    return result;
}


/** \test test if the engine detect the proto and match with it */
static int AppLayerProtoDetectTest16(void)
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

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
    f->proto = IPPROTO_TCP;
    p->flow = f;

    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any any -> any any "
                                   "(msg:\"Test content option\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto on a non standar port
 * and match with it */
static int AppLayerProtoDetectTest17(void)
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
                                   "(msg:\"http over non standar port\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto and doesn't match
 * because the sig expects another proto (ex ftp)*/
static int AppLayerProtoDetectTest18(void)
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(http_buf1, http_buf1_len, IPPROTO_TCP);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_HTTP1;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ftp any any -> any any "
                                   "(msg:\"Test content option\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_HTTP1, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);

    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

/** \test test if the engine detect the proto and doesn't match
 * because the packet has another proto (ex ftp) */
static int AppLayerProtoDetectTest19(void)
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacketSrcDstPorts(http_buf1, http_buf1_len, IPPROTO_TCP, 12345, 88);

    f = UTHBuildFlow(AF_INET, "1.1.1.1", "2.2.2.2", 1024, 80);
    if (f == NULL)
        goto end;
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    p->flow = f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f->alproto = ALPROTO_FTP;

    StreamTcpInitConfig(true);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert http any !80 -> any any "
                                   "(msg:\"http over non standar port\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_FTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 alerted, but it should not (it's ftp): ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(true);
    UTHFreePackets(&p, 1);
    UTHFreeFlow(f);
    return result;
}

void AppLayerProtoDetectUnittestsRegister(void)
{
    SCEnter();

    UtRegisterTest("AppLayerProtoDetectTest01", AppLayerProtoDetectTest01);
    UtRegisterTest("AppLayerProtoDetectTest02", AppLayerProtoDetectTest02);
    UtRegisterTest("AppLayerProtoDetectTest03", AppLayerProtoDetectTest03);
    UtRegisterTest("AppLayerProtoDetectTest04", AppLayerProtoDetectTest04);
    UtRegisterTest("AppLayerProtoDetectTest05", AppLayerProtoDetectTest05);
    UtRegisterTest("AppLayerProtoDetectTest06", AppLayerProtoDetectTest06);
    UtRegisterTest("AppLayerProtoDetectTest07", AppLayerProtoDetectTest07);
    UtRegisterTest("AppLayerProtoDetectTest08", AppLayerProtoDetectTest08);
    UtRegisterTest("AppLayerProtoDetectTest09", AppLayerProtoDetectTest09);
    UtRegisterTest("AppLayerProtoDetectTest10", AppLayerProtoDetectTest10);
    UtRegisterTest("AppLayerProtoDetectTest11", AppLayerProtoDetectTest11);
    UtRegisterTest("AppLayerProtoDetectTest12", AppLayerProtoDetectTest12);
    UtRegisterTest("AppLayerProtoDetectTest13", AppLayerProtoDetectTest13);
    UtRegisterTest("AppLayerProtoDetectTest14", AppLayerProtoDetectTest14);
    UtRegisterTest("AppLayerProtoDetectTest15", AppLayerProtoDetectTest15);
    UtRegisterTest("AppLayerProtoDetectTest16", AppLayerProtoDetectTest16);
    UtRegisterTest("AppLayerProtoDetectTest17", AppLayerProtoDetectTest17);
    UtRegisterTest("AppLayerProtoDetectTest18", AppLayerProtoDetectTest18);
    UtRegisterTest("AppLayerProtoDetectTest19", AppLayerProtoDetectTest19);

    SCReturn;
}

#endif /* UNITTESTS */
