/* Copyright (C) 2007-2025 Open Information Security Foundation
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
 *
 * Basic detection engine
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"
#include "packet.h"
#include "flow.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-frames.h"

#include "detect.h"
#include "detect-dsize.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-frame.h"
#include "detect-engine-profile.h"

#include "detect-engine-alert.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-engine-threshold.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-state.h"
#include "detect-engine-analyzer.h"

#include "detect-engine-payload.h"
#include "detect-engine-event.h"

#include "detect-filestore.h"
#include "detect-flowvar.h"
#include "detect-replace.h"

#include "util-validate.h"
#include "util-detect.h"
#include "util-profiling.h"

#include "action-globals.h"

typedef struct DetectRunScratchpad {
    const AppProto alproto;
    const uint8_t flow_flags; /* flow/state flags: STREAM_* */
    const bool app_decoder_events;
    /**
     *  Either ACTION_DROP (drop:packet) or ACTION_ACCEPT (accept:hook)
     *
     *  ACTION_DROP means the default policy of drop:packet is applied
     *  ACTION_ACCEPT means the default policy of accept:hook is applied
     */
    const uint8_t default_action;
    const SigGroupHead *sgh;
} DetectRunScratchpad;

/* prototypes */
static DetectRunScratchpad DetectRunSetup(const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *const p, Flow *const pflow,
        const uint8_t default_action);
static void DetectRunInspectIPOnly(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Flow * const pflow, Packet * const p);
static inline void DetectRunGetRuleGroup(const DetectEngineCtx *de_ctx,
        Packet * const p, Flow * const pflow, DetectRunScratchpad *scratch);
static inline void DetectRunPrefilterPkt(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p, DetectRunScratchpad *scratch);
static inline uint8_t DetectRulePacketRules(ThreadVars *const tv,
        const DetectEngineCtx *const de_ctx, DetectEngineThreadCtx *const det_ctx, Packet *const p,
        Flow *const pflow, const DetectRunScratchpad *scratch);
static void DetectRunTx(ThreadVars *tv, DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p,
        Flow *f, DetectRunScratchpad *scratch);
static void DetectRunFrames(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow *f, DetectRunScratchpad *scratch);
static inline void DetectRunPostRules(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *const p, Flow *const pflow,
        DetectRunScratchpad *scratch);
static void DetectRunCleanup(DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow * const pflow);
static inline void DetectRunAppendDefaultAccept(DetectEngineThreadCtx *det_ctx, Packet *p);

/** \internal
 */
static void DetectRun(ThreadVars *th_v,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Packet *p)
{
    SCEnter();
    SCLogDebug("p->pcap_cnt %" PRIu64 " direction %s pkt_src %s", p->pcap_cnt,
            p->flow ? (FlowGetPacketDirection(p->flow, p) == TOSERVER ? "toserver" : "toclient")
                    : "noflow",
            PktSrcToString(p->pkt_src));

    /* Load the Packet's flow early, even though it might not be needed.
     * Mark as a constant pointer, although the flow itself can change. */
    Flow * const pflow = p->flow;

    DetectRunScratchpad scratch = DetectRunSetup(de_ctx, det_ctx, p, pflow, ACTION_DROP);

    /* run the IPonly engine */
    DetectRunInspectIPOnly(th_v, de_ctx, det_ctx, pflow, p);

    /* get our rule group */
    DetectRunGetRuleGroup(de_ctx, p, pflow, &scratch);
    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (scratch.sgh == NULL) {
        SCLogDebug("no sgh for this packet, nothing to match against");
        goto end;
    }

    /* run the prefilters for packets */
    DetectRunPrefilterPkt(th_v, de_ctx, det_ctx, p, &scratch);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_RULES);
    /* inspect the rules against the packet */
    const uint8_t pkt_policy = DetectRulePacketRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_RULES);

    /* Only FW rules will already have set the action, IDS rules go through PacketAlertFinalize
     *
     * If rules told us to drop or accept:packet/accept:flow, we skip app_filter and app_td.
     *
     * accept:hook won't have set the pkt_policy, so we simply continue.
     *
     * TODO what about app state progression, cleanup and such? */
    if (pkt_policy & (ACTION_DROP | ACTION_ACCEPT)) {
        goto end;
    }

    /* run tx/state inspection. Don't call for ICMP error msgs. */
    if (pflow && pflow->alstate && likely(pflow->proto == p->proto)) {
        if (p->proto == IPPROTO_TCP) {
            if ((p->flags & PKT_STREAM_EST) == 0) {
                SCLogDebug("packet %" PRIu64 ": skip tcp non-established", p->pcap_cnt);
                DetectRunAppendDefaultAccept(det_ctx, p);
                goto end;
            }
            const TcpSession *ssn = p->flow->protoctx;
            bool setting_nopayload = p->flow->alparser &&
                                     SCAppLayerParserStateIssetFlag(
                                             p->flow->alparser, APP_LAYER_PARSER_NO_INSPECTION) &&
                                     !(p->flags & PKT_NOPAYLOAD_INSPECTION);
            // we may be right after disabling app-layer (ssh)
            if (ssn &&
                    ((ssn->flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) == 0 || setting_nopayload)) {
                // PACKET_PROFILING_DETECT_START(p, PROF_DETECT_TX);
                DetectRunFrames(th_v, de_ctx, det_ctx, p, pflow, &scratch);
                // PACKET_PROFILING_DETECT_END(p, PROF_DETECT_TX);
            }
            // no update to transactions
            if (!PKT_IS_PSEUDOPKT(p) && p->app_update_direction == 0 &&
                    ((PKT_IS_TOSERVER(p) && (p->flow->flags & FLOW_TS_APP_UPDATED) == 0) ||
                            (PKT_IS_TOCLIENT(p) && (p->flow->flags & FLOW_TC_APP_UPDATED) == 0))) {
                SCLogDebug("packet %" PRIu64 ": no app-layer update", p->pcap_cnt);
                DetectRunAppendDefaultAccept(det_ctx, p);
                goto end;
            }
        } else if (p->proto == IPPROTO_UDP) {
            DetectRunFrames(th_v, de_ctx, det_ctx, p, pflow, &scratch);
        }

        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_TX);
        DetectRunTx(th_v, de_ctx, det_ctx, p, pflow, &scratch);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_TX);
        /* see if we need to increment the inspect_id and reset the de_state */
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_TX_UPDATE);
        AppLayerParserSetTransactionInspectId(
                pflow, pflow->alparser, pflow->alstate, scratch.flow_flags, (scratch.sgh == NULL));
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_TX_UPDATE);
    } else {
        SCLogDebug("packet %" PRIu64 ": no flow / app-layer", p->pcap_cnt);
        DetectRunAppendDefaultAccept(det_ctx, p);
    }

end:
    DetectRunPostRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);

    DetectRunCleanup(det_ctx, p, pflow);
    SCReturn;
}

/** \internal
 */
static void DetectRunPacketHook(ThreadVars *th_v, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, const SigGroupHead *sgh, Packet *p)
{
    SCEnter();
    SCLogDebug("p->pcap_cnt %" PRIu64 " direction %s pkt_src %s", p->pcap_cnt,
            p->flow ? (FlowGetPacketDirection(p->flow, p) == TOSERVER ? "toserver" : "toclient")
                    : "noflow",
            PktSrcToString(p->pkt_src));

    /* Load the Packet's flow early, even though it might not be needed.
     * Mark as a constant pointer, although the flow itself can change. */
    Flow *const pflow = p->flow;

    DetectRunScratchpad scratch = DetectRunSetup(de_ctx, det_ctx, p, pflow, ACTION_ACCEPT);
    scratch.sgh = sgh;

    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (scratch.sgh == NULL) {
        SCLogDebug("no sgh for this packet, nothing to match against");
        goto end;
    }

    /* run the prefilters for packets */
    DetectRunPrefilterPkt(th_v, de_ctx, det_ctx, p, &scratch);

    //    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_RULES); // TODO
    /* inspect the rules against the packet */
    const uint8_t pkt_policy = DetectRulePacketRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);
    //    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_RULES);
    if (pkt_policy & (ACTION_DROP | ACTION_ACCEPT)) {
        goto end;
    }

end:
    DetectRunPostRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);

    DetectRunCleanup(det_ctx, p, pflow);
    SCReturn;
}

static void DetectRunPostMatch(ThreadVars *tv,
                               DetectEngineThreadCtx *det_ctx, Packet *p,
                               const Signature *s)
{
    /* run the packet match functions */
    const SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];
    if (smd != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);

        SCLogDebug("running match functions, sm %p", smd);

        while (1) {
            KEYWORD_PROFILING_START;
            (void)sigmatch_table[smd->type].Match(det_ctx, p, s, smd->ctx);
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
            if (smd->is_last)
                break;
            smd++;
        }
    }
}

/**
 *  \brief Get the SigGroupHead for a packet.
 *
 *  \param de_ctx detection engine context
 *  \param p packet
 *
 *  \retval sgh the SigGroupHead or NULL if non applies to the packet
 */
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx,
        const Packet *p)
{
    SCEnter();
    SigGroupHead *sgh = NULL;

    /* if the packet proto is 0 (not set), we're inspecting it against
     * the decoder events sgh we have. */
    if (p->proto == 0 && p->events.cnt > 0) {
        SCReturnPtr(de_ctx->decoder_event_sgh, "SigGroupHead");
    } else if (p->proto == 0) {
        if (!(PacketIsIPv4(p) || PacketIsIPv6(p))) {
            /* not IP, so nothing to do */
            SCReturnPtr(NULL, "SigGroupHead");
        }
    }

    /* select the flow_gh */
    const int dir = (p->flowflags & FLOW_PKT_TOCLIENT) == 0;

    int proto = PacketGetIPProto(p);
    if (proto == IPPROTO_TCP) {
        DetectPort *list = de_ctx->flow_gh[dir].tcp;
        SCLogDebug("tcp toserver %p, tcp toclient %p: going to use %p", de_ctx->flow_gh[1].tcp,
                de_ctx->flow_gh[0].tcp, de_ctx->flow_gh[dir].tcp);
        const uint16_t port = dir ? p->dp : p->sp;
        SCLogDebug("tcp port %u -> %u:%u", port, p->sp, p->dp);
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("TCP list %p, port %u, direction %s, sghport %p, sgh %p", list, port,
                dir ? "toserver" : "toclient", sghport, sgh);
    } else if (proto == IPPROTO_UDP) {
        DetectPort *list = de_ctx->flow_gh[dir].udp;
        uint16_t port = dir ? p->dp : p->sp;
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("UDP list %p, port %u, direction %s, sghport %p, sgh %p", list, port,
                dir ? "toserver" : "toclient", sghport, sgh);
    } else {
        sgh = de_ctx->flow_gh[dir].sgh[proto];
    }

    SCReturnPtr(sgh, "SigGroupHead");
}

static inline void DetectPrefilterCopyDeDup(
        const DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx)
{
    SigIntId *pf_ptr = det_ctx->pmq.rule_id_array;
    uint32_t final_cnt = det_ctx->pmq.rule_id_array_cnt;
    Signature **sig_array = de_ctx->sig_array;
    Signature **match_array = det_ctx->match_array;
    SigIntId previous_id = (SigIntId)-1;
    while (final_cnt-- > 0) {
        SigIntId id = *pf_ptr++;
        Signature *s = sig_array[id];

        /* As the prefilter list can contain duplicates, check for that here. */
        if (likely(id != previous_id)) {
            *match_array++ = s;
            previous_id = id;
        }
    }

    det_ctx->match_array_cnt = (uint32_t)(match_array - det_ctx->match_array);
    DEBUG_VALIDATE_BUG_ON(det_ctx->pmq.rule_id_array_cnt < det_ctx->match_array_cnt);
    PMQ_RESET(&det_ctx->pmq);
}

/** \internal
 *  \brief update flow's file tracking flags based on the detection engine
 *         A set of flags is prepared that is sent to the File API. The
           File API may reject one or more based on the global force settings.
 */
static inline void
DetectPostInspectFileFlagsUpdate(Flow *f, const SigGroupHead *sgh, uint8_t direction)
{
    uint16_t flow_file_flags = FLOWFILE_INIT;

    if (sgh == NULL) {
        SCLogDebug("requesting disabling all file features for flow");
        flow_file_flags = FLOWFILE_NONE;
    } else {
        if (sgh->filestore_cnt == 0) {
            SCLogDebug("requesting disabling filestore for flow");
            flow_file_flags |= (FLOWFILE_NO_STORE_TS|FLOWFILE_NO_STORE_TC);
        }
#ifdef HAVE_MAGIC
        if (!(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMAGIC)) {
            SCLogDebug("requesting disabling magic for flow");
            flow_file_flags |= (FLOWFILE_NO_MAGIC_TS|FLOWFILE_NO_MAGIC_TC);
        }
#endif
        if (!(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMD5)) {
            SCLogDebug("requesting disabling md5 for flow");
            flow_file_flags |= (FLOWFILE_NO_MD5_TS|FLOWFILE_NO_MD5_TC);
        }
        if (!(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA1)) {
            SCLogDebug("requesting disabling sha1 for flow");
            flow_file_flags |= (FLOWFILE_NO_SHA1_TS|FLOWFILE_NO_SHA1_TC);
        }
        if (!(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA256)) {
            SCLogDebug("requesting disabling sha256 for flow");
            flow_file_flags |= (FLOWFILE_NO_SHA256_TS|FLOWFILE_NO_SHA256_TC);
        }
    }
    if (flow_file_flags != 0) {
        FileUpdateFlowFileFlags(f, flow_file_flags, direction);
    }
}

static inline void
DetectRunPostGetFirstRuleGroup(const Packet *p, Flow *pflow, const SigGroupHead *sgh)
{
    if ((p->flowflags & FLOW_PKT_TOSERVER) && !(pflow->flags & FLOW_SGH_TOSERVER)) {
        /* first time we see this toserver sgh, store it */
        pflow->sgh_toserver = sgh;
        pflow->flags |= FLOW_SGH_TOSERVER;

        if (p->proto == IPPROTO_TCP && (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVERAWSTREAM))) {
            if (pflow->protoctx != NULL) {
                TcpSession *ssn = pflow->protoctx;
                SCLogDebug("STREAMTCP_STREAM_FLAG_DISABLE_RAW ssn.client");
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
            }
        }

        DetectPostInspectFileFlagsUpdate(pflow,
                pflow->sgh_toserver, STREAM_TOSERVER);

    } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && !(pflow->flags & FLOW_SGH_TOCLIENT)) {
        pflow->sgh_toclient = sgh;
        pflow->flags |= FLOW_SGH_TOCLIENT;

        if (p->proto == IPPROTO_TCP && (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVERAWSTREAM))) {
            if (pflow->protoctx != NULL) {
                TcpSession *ssn = pflow->protoctx;
                SCLogDebug("STREAMTCP_STREAM_FLAG_DISABLE_RAW ssn.server");
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
            }
        }

        DetectPostInspectFileFlagsUpdate(pflow,
                pflow->sgh_toclient, STREAM_TOCLIENT);
    }
}

static inline void DetectRunGetRuleGroup(
    const DetectEngineCtx *de_ctx,
    Packet * const p, Flow * const pflow,
    DetectRunScratchpad *scratch)
{
    const SigGroupHead *sgh = NULL;

    if (pflow) {
        bool use_flow_sgh = false;
        /* Get the stored sgh from the flow (if any). Make sure we're not using
         * the sgh for icmp error packets part of the same stream. */
        if (PacketGetIPProto(p) == pflow->proto) { /* filter out icmp */
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            if ((p->flowflags & FLOW_PKT_TOSERVER) && (pflow->flags & FLOW_SGH_TOSERVER)) {
                sgh = pflow->sgh_toserver;
                SCLogDebug("sgh = pflow->sgh_toserver; => %p", sgh);
                use_flow_sgh = true;
            } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && (pflow->flags & FLOW_SGH_TOCLIENT)) {
                sgh = pflow->sgh_toclient;
                SCLogDebug("sgh = pflow->sgh_toclient; => %p", sgh);
                use_flow_sgh = true;
            }
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
        }

        if (!(use_flow_sgh)) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            sgh = SigMatchSignaturesGetSgh(de_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);

            /* HACK: prevent the wrong sgh (or NULL) from being stored in the
             * flow's sgh pointers */
            if (PacketIsICMPv4(p) && ICMPV4_DEST_UNREACH_IS_VALID(p)) {
                ; /* no-op */
            } else {
                /* store the found sgh (or NULL) in the flow to save us
                 * from looking it up again for the next packet.
                 * Also run other tasks */
                DetectRunPostGetFirstRuleGroup(p, pflow, sgh);
            }
        }
    } else { /* p->flags & PKT_HAS_FLOW */
        /* no flow */

        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
        sgh = SigMatchSignaturesGetSgh(de_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
    }

    scratch->sgh = sgh;
}

static void DetectRunInspectIPOnly(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx,
        Flow * const pflow, Packet * const p)
{
    if (pflow) {
        if (p->flowflags & (FLOW_PKT_TOSERVER_FIRST | FLOW_PKT_TOCLIENT_FIRST)) {
            SCLogDebug("testing against \"ip-only\" signatures");

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
            IPOnlyMatchPacket(tv, de_ctx, det_ctx, &de_ctx->io_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);
        }
    } else { /* p->flags & PKT_HAS_FLOW */
        /* no flow */

        /* Even without flow we should match the packet src/dst */
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
        IPOnlyMatchPacket(tv, de_ctx, det_ctx, &de_ctx->io_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);
    }
}

/** \internal
 *  \brief inspect the rule header: protocol, ports, etc
 *  \retval bool false if no match, true if match */
static inline bool DetectRunInspectRuleHeader(const Packet *p, const Flow *f, const Signature *s,
        const uint32_t sflags, const uint8_t s_proto_flags)
{
    /* check if this signature has a requirement for flowvars of some type
     * and if so, if we actually have any in the flow. If not, the sig
     * can't match and we skip it. */
    if ((p->flags & PKT_HAS_FLOW) && (sflags & SIG_FLAG_REQUIRE_FLOWVAR)) {
        DEBUG_VALIDATE_BUG_ON(f == NULL);

        /* no flowvars? skip this sig */
        const bool fv = f->flowvar != NULL;
        if (!fv) {
            SCLogDebug("skipping sig as the flow has no flowvars and sig "
                    "has SIG_FLAG_REQUIRE_FLOWVAR flag set.");
            return false;
        }
    }

    if ((s_proto_flags & DETECT_PROTO_IPV4) && !PacketIsIPv4(p)) {
        SCLogDebug("ip version didn't match");
        return false;
    }
    if ((s_proto_flags & DETECT_PROTO_IPV6) && !PacketIsIPv6(p)) {
        SCLogDebug("ip version didn't match");
        return false;
    }

    if (DetectProtoContainsProto(&s->proto, PacketGetIPProto(p)) == 0) {
        SCLogDebug("proto didn't match");
        return false;
    }

    /* check the source & dst port in the sig */
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
        if (!(sflags & SIG_FLAG_DP_ANY)) {
            if (p->flags & PKT_IS_FRAGMENT)
                return false;
            const DetectPort *dport = DetectPortLookupGroup(s->dp, p->dp);
            if (dport == NULL) {
                SCLogDebug("dport didn't match.");
                return false;
            }
        }
        if (!(sflags & SIG_FLAG_SP_ANY)) {
            if (p->flags & PKT_IS_FRAGMENT)
                return false;
            const DetectPort *sport = DetectPortLookupGroup(s->sp, p->sp);
            if (sport == NULL) {
                SCLogDebug("sport didn't match.");
                return false;
            }
        }
    } else if ((sflags & (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) != (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) {
        SCLogDebug("port-less protocol and sig needs ports");
        return false;
    }

    /* check the destination address */
    if (!(sflags & SIG_FLAG_DST_ANY)) {
        if (PacketIsIPv4(p)) {
            if (DetectAddressMatchIPv4(s->addr_dst_match4, s->addr_dst_match4_cnt, &p->dst) == 0)
                return false;
        } else if (PacketIsIPv6(p)) {
            if (DetectAddressMatchIPv6(s->addr_dst_match6, s->addr_dst_match6_cnt, &p->dst) == 0)
                return false;
        }
    }
    /* check the source address */
    if (!(sflags & SIG_FLAG_SRC_ANY)) {
        if (PacketIsIPv4(p)) {
            if (DetectAddressMatchIPv4(s->addr_src_match4, s->addr_src_match4_cnt, &p->src) == 0)
                return false;
        } else if (PacketIsIPv6(p)) {
            if (DetectAddressMatchIPv6(s->addr_src_match6, s->addr_src_match6_cnt, &p->src) == 0)
                return false;
        }
    }

    return true;
}

/** \internal
 *  \brief run packet/stream prefilter engines
 */
static inline void DetectRunPrefilterPkt(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p, DetectRunScratchpad *scratch)
{
    /* create our prefilter mask */
    PacketCreateMask(p, &p->sig_mask, scratch->alproto, scratch->app_decoder_events);
    /* run the prefilter engines */
    Prefilter(det_ctx, scratch->sgh, p, scratch->flow_flags, p->sig_mask);
    /* create match list if we have non-pf and/or pf */
    if (det_ctx->pmq.rule_id_array_cnt) {
#ifdef PROFILING
        if (tv) {
            StatsAddUI64(tv, det_ctx->counter_mpm_list, (uint64_t)det_ctx->pmq.rule_id_array_cnt);
        }
#endif
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT2);
        DetectPrefilterCopyDeDup(de_ctx, det_ctx);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT2);
    }
}

/** \internal
 *  \brief check if the tx whose id is given is the only one
 *  live transaction for the flow in the given direction
 *
 *  \param f flow
 *  \param txid transaction id
 *  \param dir direction
 *
 *  \retval bool true if we are sure this tx is the only one live in said direction
 */
static bool IsOnlyTxInDirection(Flow *f, uint64_t txid, uint8_t dir)
{
    uint64_t tx_cnt = AppLayerParserGetTxCnt(f, f->alstate);
    if (tx_cnt == txid + 1) {
        // only live tx
        return true;
    }
    if (tx_cnt == txid + 2) {
        // 2 live txs, one after us
        void *tx = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, txid + 1);
        if (tx) {
            AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, tx);
            // test if the other tx is unidirectional in the other way
            if ((dir == STREAM_TOSERVER && (txd->flags & APP_LAYER_TX_SKIP_INSPECT_TS)) ||
                    (dir == STREAM_TOCLIENT && (txd->flags & APP_LAYER_TX_SKIP_INSPECT_TC))) {
                return true;
            }
        }
    }
    return false;
}

static int SortHelper(const void *a, const void *b)
{
    const Signature *sa = *(const Signature **)a;
    const Signature *sb = *(const Signature **)b;
    if (sa->iid == sb->iid)
        return 0;
    return sa->iid > sb->iid ? 1 : -1;
}

static inline uint8_t DetectRulePacketRules(ThreadVars *const tv,
        const DetectEngineCtx *const de_ctx, DetectEngineThreadCtx *const det_ctx, Packet *const p,
        Flow *const pflow, const DetectRunScratchpad *scratch)
{
    uint8_t action = 0;
    bool fw_verdict = false;
    const bool have_fw_rules = EngineModeIsFirewall();
    const Signature *next_s = NULL;

    /* inspect the sigs against the packet */
    /* Prefetch the next signature. */
    SigIntId match_cnt = det_ctx->match_array_cnt;
#ifdef PROFILING
    if (tv) {
        StatsAddUI64(tv, det_ctx->counter_match_list,
                             (uint64_t)match_cnt);
    }
#endif
    Signature **match_array = det_ctx->match_array;

    SGH_PROFILING_RECORD(det_ctx, scratch->sgh);
#ifdef PROFILING
    if (match_cnt >= de_ctx->profile_match_logging_threshold)
        RulesDumpMatchArray(det_ctx, scratch->sgh, p);
#endif

    bool skip_fw = false;
    uint32_t sflags, next_sflags = 0;
    if (match_cnt) {
        next_s = *match_array++;
        next_sflags = next_s->flags;
    }
    while (match_cnt--) {
        RULE_PROFILING_START(p);
        bool break_out_of_packet_filter = false;
        uint8_t alert_flags = 0;
#ifdef PROFILE_RULES
        bool smatch = false; /* signature match */
#endif
        const Signature *s = next_s;
        sflags = next_sflags;
        if (match_cnt) {
            next_s = *match_array++;
            next_sflags = next_s->flags;
        }
        const uint8_t s_proto_flags = s->proto.flags;

        SCLogDebug("packet %" PRIu64 ": inspecting signature id %" PRIu32 "", p->pcap_cnt, s->id);

        /* if we accept:hook'd the `packet_filter` hook, we skip the rest of the firewall rules. */
        if (s->flags & SIG_FLAG_FIREWALL) {
            if (skip_fw) {
                SCLogDebug("skipping firewall rule %u", s->id);
                goto next;
            }
        } else if (have_fw_rules) {
            /* fw mode, we skip anything after the fw rules if:
             * - flow pass is set
             * - packet pass (e.g. exception policy) */
            if (p->flags & PKT_NOPACKET_INSPECTION ||
                    (pflow != NULL && pflow->flags & (FLOW_ACTION_PASS))) {
                SCLogDebug("skipping firewall rule %u", s->id);
                break_out_of_packet_filter = true;
                goto next;
            }
        }

        if (s->app_inspect != NULL) {
            goto next; // handle sig in DetectRunTx
        }
        if (s->frame_inspect != NULL) {
            goto next; // handle sig in DetectRunFrame
        }

        /* skip pkt sigs for flow end packets */
        if ((p->flags & PKT_PSEUDO_STREAM_END) != 0 && s->type == SIG_TYPE_PKT)
            goto next;

        /* don't run mask check for stateful rules.
         * There we depend on prefilter */
        if ((s->mask & p->sig_mask) != s->mask) {
            SCLogDebug("mask mismatch %x & %x != %x", s->mask, p->sig_mask, s->mask);
            goto next;
        }

        if (SigDsizePrefilter(p, s, sflags))
            goto next;

        /* if the sig has alproto and the session as well they should match */
        if (likely(sflags & SIG_FLAG_APPLAYER)) {
            if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, scratch->alproto)) {
                SCLogDebug("alproto mismatch");
                goto next;
            }
        }

        if (!DetectRunInspectRuleHeader(p, pflow, s, sflags, s_proto_flags)) {
            goto next;
        }

        if (!DetectEnginePktInspectionRun(tv, det_ctx, s, pflow, p, &alert_flags)) {
            goto next;
        }

#ifdef PROFILE_RULES
        smatch = true;
#endif
        DetectRunPostMatch(tv, det_ctx, p, s);

        uint64_t txid = PACKET_ALERT_NOTX;
        if (pflow && pflow->alstate) {
            uint8_t dir = (p->flowflags & FLOW_PKT_TOCLIENT) ? STREAM_TOCLIENT : STREAM_TOSERVER;
            txid = AppLayerParserGetTransactionInspectId(pflow->alparser, dir);
            if ((s->alproto != ALPROTO_UNKNOWN && pflow->proto == IPPROTO_UDP) ||
                    (de_ctx->guess_applayer && IsOnlyTxInDirection(pflow, txid, dir))) {
                // if there is a UDP specific app-layer signature,
                // or only one live transaction
                // try to use the good tx for the packet direction
                void *tx_ptr =
                        AppLayerParserGetTx(pflow->proto, pflow->alproto, pflow->alstate, txid);
                AppLayerTxData *txd =
                        tx_ptr ? AppLayerParserGetTxData(pflow->proto, pflow->alproto, tx_ptr)
                               : NULL;
                if (txd && txd->guessed_applayer_logged < de_ctx->guess_applayer_log_limit) {
                    alert_flags |= PACKET_ALERT_FLAG_TX;
                    if (pflow->proto != IPPROTO_UDP) {
                        alert_flags |= PACKET_ALERT_FLAG_TX_GUESSED;
                    }
                    txd->guessed_applayer_logged++;
                }
            }
        }
        AlertQueueAppend(det_ctx, s, p, txid, alert_flags);

        if (det_ctx->post_rule_work_queue.len > 0) {
            /* run post match prefilter engines on work queue */
            PrefilterPostRuleMatch(det_ctx, scratch->sgh, p, pflow);

            if (det_ctx->pmq.rule_id_array_cnt > 0) {
                /* undo "prefetch" */
                if (next_s)
                    match_array--;
                /* create temporary rule pointer array starting
                 * at where we are in the current match array */
                const Signature *replace[de_ctx->sig_array_len]; // TODO heap?
                SCLogDebug("sig_array_len %u det_ctx->pmq.rule_id_array_cnt %u",
                        de_ctx->sig_array_len, det_ctx->pmq.rule_id_array_cnt);
                const Signature **r = replace;
                for (uint32_t x = 0; x < match_cnt; x++) {
                    *r++ = match_array[x];
                    SCLogDebug("appended %u", match_array[x]->id);
                }
                /* append the prefilter results, then sort it */
                for (uint32_t x = 0; x < det_ctx->pmq.rule_id_array_cnt; x++) {
                    SCLogDebug("adding iid %u", det_ctx->pmq.rule_id_array[x]);
                    Signature *ts = de_ctx->sig_array[det_ctx->pmq.rule_id_array[x]];
                    SCLogDebug("adding id %u", ts->id);
                    if (ts->app_inspect == NULL) {
                        *r++ = ts;
                        match_cnt++;
                    }
                }
                if (match_cnt > 1) {
                    qsort(replace, match_cnt, sizeof(Signature *), SortHelper);
                }
                /* rewrite match_array to include the new additions, and deduplicate
                 * while at it. */
                Signature **m = match_array;
                Signature *last_sig = NULL;
                uint32_t skipped = 0;
                for (uint32_t x = 0; x < match_cnt; x++) {
                    /* de-duplicate */
                    if (last_sig == *m) {
                        skipped++;
                        continue;
                    }
                    last_sig = *m;
                    *m++ = (Signature *)replace[x];
                }
                match_cnt -= skipped;
                /* prefetch next */
                next_s = *match_array++;
                next_sflags = next_s->flags;
                SCLogDebug("%u rules added", det_ctx->pmq.rule_id_array_cnt);
                det_ctx->post_rule_work_queue.len = 0;
                PMQ_RESET(&det_ctx->pmq);
            }
        }

        /* firewall logic in the packet:filter table:
         * 1. firewall rules preceed the packet:td rules in the list
         * 2. if no rule issues an accept, we drop
         * 3. drop is immediate
         * 4. accept:
         *    - hook: skip rest of fw rules, inspect packet:td rules
         *    - packet: immediate accept, no packet:td or app:* inspect
         *    - flow: as packet, but applied to all future packets in the
         *            flow as well
         */
        if (s->flags & SIG_FLAG_FIREWALL) {
            if (s->action & (ACTION_ACCEPT)) {
                fw_verdict = true;

                enum ActionScope as = s->action_scope;
                if (as == ACTION_SCOPE_HOOK) {
                    /* accept:hook: jump to first TD. Implemented as:
                     * skip until the first TD rule.
                     * Don't update action as we're just continuing to the next hook. */
                    skip_fw = true;

                } else if (as == ACTION_SCOPE_PACKET) {
                    /* accept:packet: break loop, return accept */
                    action |= s->action;
                    break_out_of_packet_filter = true;

                } else if (as == ACTION_SCOPE_FLOW) {
                    /* accept:flow: break loop, return accept */
                    action |= s->action;
                    break_out_of_packet_filter = true;

                    /* set immediately, as we're in hook "packet_filter" */
                    if (pflow) {
                        pflow->flags |= FLOW_ACTION_ACCEPT;
                    }
                }
            } else if (s->action & ACTION_DROP) {
                /* apply a drop immediately here */
                fw_verdict = true;
                action |= s->action;
                break_out_of_packet_filter = true;
            }
        }
next:
        DetectVarProcessList(det_ctx, pflow, p);
        DetectReplaceFree(det_ctx);
        RULE_PROFILING_END(det_ctx, s, smatch, p);

        /* fw accept:packet or accept:flow means we're done here */
        if (break_out_of_packet_filter)
            break;

        continue;
    }

    /* if no rule told us to accept, and no rule explicitly dropped, we invoke the default drop
     * policy
     */
    if (have_fw_rules && scratch->default_action == ACTION_DROP) {
        if (!fw_verdict) {
            DEBUG_VALIDATE_BUG_ON(action & ACTION_DROP);
            PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_DEFAULT_PACKET_POLICY);
            action |= ACTION_DROP;
        } else {
            /* apply fw action */
            p->action |= action;
        }
    }
    return action;
}

/** \internal
 *  \param default_action either ACTION_DROP (drop:packet) or ACTION_ACCEPT (accept:hook)
 *
 *  ACTION_DROP means the default policy of drop:packet is applied
 *  ACTION_ACCEPT means the default policy of accept:hook is applied
 */
static DetectRunScratchpad DetectRunSetup(const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *const p, Flow *const pflow,
        const uint8_t default_action)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    uint8_t flow_flags = 0; /* flow/state flags */
    bool app_decoder_events = false;

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_SETUP);

#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        p->alerts.cnt = 0;
        p->alerts.discarded = 0;
        p->alerts.suppressed = 0;
    }
#endif
    det_ctx->filestore_cnt = 0;
    det_ctx->base64_decoded_len = 0;
    det_ctx->raw_stream_progress = 0;
    det_ctx->match_array_cnt = 0;
    det_ctx->json_content_len = 0;

    det_ctx->alert_queue_size = 0;
    p->alerts.drop.action = 0;

#ifdef DEBUG
    if (p->flags & PKT_STREAM_ADD) {
        det_ctx->pkt_stream_add_cnt++;
    }
#endif

    /* grab the protocol state we will detect on */
    if (p->flags & PKT_HAS_FLOW) {
        DEBUG_VALIDATE_BUG_ON(pflow == NULL);

        if (p->flowflags & FLOW_PKT_TOSERVER) {
            flow_flags = STREAM_TOSERVER;
            SCLogDebug("flag STREAM_TOSERVER set");
        } else if (p->flowflags & FLOW_PKT_TOCLIENT) {
            flow_flags = STREAM_TOCLIENT;
            SCLogDebug("flag STREAM_TOCLIENT set");
        }
        SCLogDebug("p->flowflags 0x%02x", p->flowflags);

        if (p->flags & PKT_PSEUDO_STREAM_END) {
            flow_flags |= STREAM_EOF;
            SCLogDebug("STREAM_EOF set");
        }

        /* store tenant_id in the flow so that we can use it
         * for creating pseudo packets */
        if (p->tenant_id > 0 && pflow->tenant_id == 0) {
            pflow->tenant_id = p->tenant_id;
        }

        /* live ruleswap check for flow updates */
        if (pflow->de_ctx_version == 0) {
            /* first time this flow is inspected, set id */
            pflow->de_ctx_version = de_ctx->version;
        } else if (pflow->de_ctx_version != de_ctx->version) {
            /* first time we inspect flow with this de_ctx, reset */
            pflow->flags &= ~FLOW_SGH_TOSERVER;
            pflow->flags &= ~FLOW_SGH_TOCLIENT;
            pflow->sgh_toserver = NULL;
            pflow->sgh_toclient = NULL;

            pflow->de_ctx_version = de_ctx->version;
            SCGenericVarFree(pflow->flowvar);
            pflow->flowvar = NULL;

            DetectEngineStateResetTxs(pflow);
        }

        /* Retrieve the app layer state and protocol and the tcp reassembled
         * stream chunks. */
        if ((p->proto == IPPROTO_TCP && (p->flags & PKT_STREAM_EST)) ||
                (p->proto == IPPROTO_UDP) ||
                (p->proto == IPPROTO_SCTP && (p->flowflags & FLOW_PKT_ESTABLISHED)))
        {
            /* update flow flags with knowledge on disruptions */
            flow_flags = FlowGetDisruptionFlags(pflow, flow_flags);
            alproto = FlowGetAppProtocol(pflow);
            if (p->proto == IPPROTO_TCP && pflow->protoctx &&
                    StreamReassembleRawHasDataReady(pflow->protoctx, p)) {
                p->flags |= PKT_DETECT_HAS_STREAMDATA;
            }
            SCLogDebug("alproto %u", alproto);
        } else {
            SCLogDebug("packet doesn't have established flag set (proto %d)", p->proto);
        }

        app_decoder_events = AppLayerParserHasDecoderEvents(pflow->alparser);
    }

    DetectRunScratchpad pad = { alproto, flow_flags, app_decoder_events, default_action, NULL };
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_SETUP);
    return pad;
}

static inline void DetectRunPostRules(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *const p, Flow *const pflow,
        DetectRunScratchpad *scratch)
{
    /* so now let's iterate the alerts and remove the ones after a pass rule
     * matched (if any). This is done inside PacketAlertFinalize() */
    /* PR: installed "tag" keywords are handled after the threshold inspection */

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_ALERT);
    PacketAlertFinalize(de_ctx, det_ctx, p);
    if (p->alerts.cnt > 0) {
        StatsAddUI64(tv, det_ctx->counter_alerts, (uint64_t)p->alerts.cnt);
    }
    if (p->alerts.discarded > 0) {
        StatsAddUI64(tv, det_ctx->counter_alerts_overflow, (uint64_t)p->alerts.discarded);
    }
    if (p->alerts.suppressed > 0) {
        StatsAddUI64(tv, det_ctx->counter_alerts_suppressed, (uint64_t)p->alerts.suppressed);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_ALERT);

    /* firewall: "fail" closed if we don't have an ACCEPT. This can happen
     * if there was no rule group. */
    // TODO review packet src types here
    if (EngineModeIsFirewall() && !(p->action & ACTION_ACCEPT) && p->pkt_src == PKT_SRC_WIRE &&
            scratch->default_action == ACTION_DROP) {
        SCLogDebug("packet %" PRIu64 ": droppit as no ACCEPT set %02x (pkt %s)", p->pcap_cnt,
                p->action, PktSrcToString(p->pkt_src));
        PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_DEFAULT_PACKET_POLICY);
    }
}

static void DetectRunCleanup(DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow * const pflow)
{
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_CLEANUP);
    InspectionBufferClean(det_ctx);

    if (pflow != NULL) {
        /* update inspected tracker for raw reassembly */
        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL &&
                (p->flags & PKT_DETECT_HAS_STREAMDATA)) {
            StreamReassembleRawUpdateProgress(pflow->protoctx, p,
                    det_ctx->raw_stream_progress);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_CLEANUP);
    SCReturn;
}

void RuleMatchCandidateTxArrayInit(DetectEngineThreadCtx *det_ctx, uint32_t size)
{
    DEBUG_VALIDATE_BUG_ON(det_ctx->tx_candidates);
    det_ctx->tx_candidates = SCCalloc(size, sizeof(RuleMatchCandidateTx));
    if (det_ctx->tx_candidates == NULL) {
        FatalError("failed to allocate %" PRIu64 " bytes",
                (uint64_t)(size * sizeof(RuleMatchCandidateTx)));
    }
    det_ctx->tx_candidates_size = size;
    SCLogDebug("array initialized to %u elements (%"PRIu64" bytes)",
            size, (uint64_t)(size * sizeof(RuleMatchCandidateTx)));
}

void RuleMatchCandidateTxArrayFree(DetectEngineThreadCtx *det_ctx)
{
    SCFree(det_ctx->tx_candidates);
    det_ctx->tx_candidates_size = 0;
}

/* if size >= cur_space */
static inline bool RuleMatchCandidateTxArrayHasSpace(const DetectEngineThreadCtx *det_ctx,
        const uint32_t need)
{
    if (det_ctx->tx_candidates_size >= need)
        return 1;
    return 0;
}

/* realloc */
static int RuleMatchCandidateTxArrayExpand(DetectEngineThreadCtx *det_ctx, const uint32_t needed)
{
    const uint32_t old_size = det_ctx->tx_candidates_size;
    uint32_t new_size = needed;
    void *ptmp = SCRealloc(det_ctx->tx_candidates, (new_size * sizeof(RuleMatchCandidateTx)));
    if (ptmp == NULL) {
        FatalError("failed to expand to %" PRIu64 " bytes",
                (uint64_t)(new_size * sizeof(RuleMatchCandidateTx)));
        // TODO can this be handled more gracefully?
    }
    det_ctx->tx_candidates = ptmp;
    det_ctx->tx_candidates_size = new_size;
    SCLogDebug("array expanded from %u to %u elements (%"PRIu64" bytes -> %"PRIu64" bytes)",
            old_size, new_size, (uint64_t)(old_size * sizeof(RuleMatchCandidateTx)),
            (uint64_t)(new_size * sizeof(RuleMatchCandidateTx))); (void)old_size;
    return 1;
}

/** \internal
 *  \brief sort helper for sorting match candidates by id: ascending
 *
 *  The id field is set from Signature::num, so we sort the candidates to match the signature
 *  sort order (ascending), where candidates that have flags go first.
 */
static int
DetectRunTxSortHelper(const void *a, const void *b)
{
    const RuleMatchCandidateTx *s0 = a;
    const RuleMatchCandidateTx *s1 = b;
    if (s1->id == s0->id) {
        if (s1->flags && !s0->flags)
            return 1;
        else if (!s1->flags && s0->flags)
            return -1;
        return 0;
    } else
        return s0->id > s1->id ? 1 : -1;
}

#if 0
#define TRACE_SID_TXS(sid,txs,...)          \
    do {                                    \
        char _trace_buf[2048];              \
        snprintf(_trace_buf, sizeof(_trace_buf), __VA_ARGS__);  \
        SCLogNotice("%p/%"PRIu64"/%u: %s", txs->tx_ptr, txs->tx_id, sid, _trace_buf);   \
    } while(0)
#else
#define TRACE_SID_TXS(sid,txs,...)
#endif

// Get inner transaction for engine
void *DetectGetInnerTx(void *tx_ptr, AppProto alproto, AppProto engine_alproto, uint8_t flow_flags)
{
    if (unlikely(alproto == ALPROTO_DOH2)) {
        if (engine_alproto == ALPROTO_DNS) {
            // need to get the dns tx pointer
            tx_ptr = SCDoH2GetDnsTx(tx_ptr, flow_flags);
        } else if (engine_alproto != ALPROTO_HTTP2 && engine_alproto != ALPROTO_UNKNOWN) {
            // incompatible engine->alproto with flow alproto
            tx_ptr = NULL;
        }
    } else if (engine_alproto != alproto && engine_alproto != ALPROTO_UNKNOWN) {
        // incompatible engine->alproto with flow alproto
        tx_ptr = NULL;
    }
    return tx_ptr;
}

/** \internal
 *  \brief inspect a rule against a transaction
 *
 *  Inspect a rule. New detection or continued stateful
 *  detection.
 *
 *  \param stored_flags pointer to stored flags or NULL.
 *         If stored_flags is set it means we're continuing
 *         inspection from an earlier run.
 *
 *  \retval bool true sig matched, false didn't match
 */
static bool DetectRunTxInspectRule(ThreadVars *tv,
        DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx,
        Packet *p,
        Flow *f,
        const uint8_t in_flow_flags,   // direction, EOF, etc
        void *alstate,
        DetectTransaction *tx,
        const Signature *s,
        uint32_t *stored_flags,
        RuleMatchCandidateTx *can,
        DetectRunScratchpad *scratch)
{
    const uint8_t flow_flags = in_flow_flags;
    const int direction = (flow_flags & STREAM_TOSERVER) ? 0 : 1;
    uint32_t inspect_flags = stored_flags ? *stored_flags : 0;
    int total_matches = 0;
    uint16_t file_no_match = 0;
    bool retval = false;
    bool mpm_before_progress = false;   // is mpm engine before progress?
    bool mpm_in_progress = false;       // is mpm engine in a buffer we will revisit?

    TRACE_SID_TXS(s->id, tx, "starting %s", direction ? "toclient" : "toserver");

    /* for a new inspection we inspect pkt header and packet matches */
    if (likely(stored_flags == NULL)) {
        TRACE_SID_TXS(s->id, tx, "first inspect, run packet matches");
        if (!DetectRunInspectRuleHeader(p, f, s, s->flags, s->proto.flags)) {
            TRACE_SID_TXS(s->id, tx, "DetectRunInspectRuleHeader() no match");
            return false;
        }
        if (!DetectEnginePktInspectionRun(tv, det_ctx, s, f, p, NULL)) {
            TRACE_SID_TXS(s->id, tx, "DetectEnginePktInspectionRun no match");
            return false;
        }
        /* stream mpm and negated mpm sigs can end up here with wrong proto */
        if (!(AppProtoEquals(s->alproto, f->alproto) || s->alproto == ALPROTO_UNKNOWN)) {
            TRACE_SID_TXS(s->id, tx, "alproto mismatch");
            return false;
        }
    }

    const DetectEngineAppInspectionEngine *engine = s->app_inspect;
    do {
        TRACE_SID_TXS(s->id, tx, "engine %p inspect_flags %x", engine, inspect_flags);
        // also if it is not the same direction, but
        // this is a transactional signature, and we are toclient
        if (!(inspect_flags & BIT_U32(engine->id)) &&
                (direction == engine->dir || ((s->flags & SIG_FLAG_TXBOTHDIR) && direction == 1))) {

            void *tx_ptr = DetectGetInnerTx(tx->tx_ptr, f->alproto, engine->alproto, flow_flags);
            if (tx_ptr == NULL) {
                if (engine->alproto != ALPROTO_UNKNOWN) {
                    /* special case: file_data on 'alert tcp' will have engines
                     * in the list that are not for us. */
                    engine = engine->next;
                    continue;
                } else {
                    tx_ptr = tx->tx_ptr;
                }
            }

            /* engines are sorted per progress, except that the one with
             * mpm/prefilter enabled is first */
            if (tx->tx_progress < engine->progress) {
                SCLogDebug("tx progress %d < engine progress %d",
                        tx->tx_progress, engine->progress);
                break;
            }
            if (engine->mpm) {
                if (tx->tx_progress > engine->progress) {
                    TRACE_SID_TXS(s->id, tx,
                            "engine->mpm: t->tx_progress %u > engine->progress %u, so set "
                            "mpm_before_progress",
                            tx->tx_progress, engine->progress);
                    mpm_before_progress = true;
                } else if (tx->tx_progress == engine->progress) {
                    TRACE_SID_TXS(s->id, tx,
                            "engine->mpm: t->tx_progress %u == engine->progress %u, so set "
                            "mpm_in_progress",
                            tx->tx_progress, engine->progress);
                    mpm_in_progress = true;
                }
            }

            uint8_t engine_flags = flow_flags;
            if (direction != engine->dir) {
                engine_flags = flow_flags ^ (STREAM_TOCLIENT | STREAM_TOSERVER);
            }
            /* run callback: but bypass stream callback if we can */
            uint8_t match;
            if (unlikely(engine->stream && can->stream_stored)) {
                match = can->stream_result;
                TRACE_SID_TXS(s->id, tx, "stream skipped, stored result %d used instead", match);
            } else if (engine->v2.Callback == NULL) {
                /* TODO is this the cleanest way to support a non-app sig on a app hook? */

                if (tx->tx_progress > engine->progress) {
                    mpm_before_progress = true; // TODO needs a new name now
                }

                /* we don't have to store a "hook" match, also don't want to keep any state to make
                 * sure the hook gets invoked again until tx progress progresses. */
                if (tx->tx_progress <= engine->progress)
                    return DETECT_ENGINE_INSPECT_SIG_MATCH;

                /* if progress > engine progress, track state to avoid additional matches */
                match = DETECT_ENGINE_INSPECT_SIG_MATCH;
            } else {
                KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
                DEBUG_VALIDATE_BUG_ON(engine->v2.Callback == NULL);
                match = engine->v2.Callback(
                        de_ctx, det_ctx, engine, s, f, engine_flags, alstate, tx_ptr, tx->tx_id);
                TRACE_SID_TXS(s->id, tx, "engine %p match %d", engine, match);
                if (engine->stream) {
                    can->stream_stored = true;
                    can->stream_result = match;
                    TRACE_SID_TXS(s->id, tx, "stream ran, store result %d for next tx (if any)", match);
                }
            }
            if (match == DETECT_ENGINE_INSPECT_SIG_MATCH) {
                inspect_flags |= BIT_U32(engine->id);
                engine = engine->next;
                total_matches++;
                continue;
            } else if (match == DETECT_ENGINE_INSPECT_SIG_MATCH_MORE_FILES) {
                /* if the file engine matched, but indicated more
                 * files are still in progress, we don't set inspect
                 * flags as these would end inspection for this tx */
                engine = engine->next;
                total_matches++;
                continue;
            } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                inspect_flags |= BIT_U32(engine->id);
            } else if (match == DETECT_ENGINE_INSPECT_SIG_CANT_MATCH_FILES) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                inspect_flags |= BIT_U32(engine->id);
                file_no_match = 1;
            }
            /* implied DETECT_ENGINE_INSPECT_SIG_NO_MATCH */
            if (engine->mpm && mpm_before_progress) {
                inspect_flags |= DE_STATE_FLAG_SIG_CANT_MATCH;
                inspect_flags |= BIT_U32(engine->id);
            }
            break;
        } else if (!(inspect_flags & BIT_U32(engine->id)) && s->flags & SIG_FLAG_TXBOTHDIR &&
                   direction != engine->dir) {
            // for transactional rules, the engines on the opposite direction
            // are ordered by progress on the different side
            // so we have a two mixed-up lists, and we skip the elements
            if (direction == 0 && engine->next == NULL) {
                // do not match yet on request only
                break;
            }
            engine = engine->next;
            continue;
        }

        engine = engine->next;
    } while (engine != NULL);
    TRACE_SID_TXS(s->id, tx, "inspect_flags %x, total_matches %u, engine %p",
            inspect_flags, total_matches, engine);

    if (engine == NULL && total_matches) {
        inspect_flags |= DE_STATE_FLAG_FULL_INSPECT;
        TRACE_SID_TXS(s->id, tx, "MATCH");
        retval = true;
    }

    if (stored_flags) {
        *stored_flags = inspect_flags;
        TRACE_SID_TXS(s->id, tx, "continue inspect flags %08x", inspect_flags);
    } else {
        // store... or? If tx is done we might not want to come back to this tx

        // also... if mpmid tracking is enabled, we won't do a sig again for this tx...
        TRACE_SID_TXS(s->id, tx, "start inspect flags %08x", inspect_flags);
        if (inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
            if (file_no_match) {
                /* if we have a mismatch on a file sig, we need to keep state.
                 * We may get another file on the same tx (for http and smtp
                 * at least), so for a new file we need to re-eval the sig.
                 * Thoughts / TODO:
                 *  - not for some protos that have 1 file per tx (e.g. nfs)
                 *  - maybe we only need this for file sigs that mix with
                 *    other matches? E.g. 'POST + filename', is different than
                 *    just 'filename'.
                 */
                DetectRunStoreStateTx(scratch->sgh, f, tx->tx_ptr, tx->tx_id, s,
                        inspect_flags, flow_flags, file_no_match);
            }
        } else if ((inspect_flags & DE_STATE_FLAG_FULL_INSPECT) && mpm_before_progress) {
            TRACE_SID_TXS(s->id, tx, "no need to store match sig, "
                    "mpm won't trigger for it anymore");

            if (inspect_flags & DE_STATE_FLAG_FILE_INSPECT) {
                TRACE_SID_TXS(s->id, tx, "except that for new files, "
                        "we may have to revisit anyway");
                DetectRunStoreStateTx(scratch->sgh, f, tx->tx_ptr, tx->tx_id, s,
                        inspect_flags, flow_flags, file_no_match);
            }
        } else if ((inspect_flags & DE_STATE_FLAG_FULL_INSPECT) == 0 && mpm_in_progress) {
            TRACE_SID_TXS(s->id, tx, "no need to store no-match sig, "
                    "mpm will revisit it");
        } else if (inspect_flags != 0 || file_no_match != 0) {
            TRACE_SID_TXS(s->id, tx, "storing state: flags %08x", inspect_flags);
            DetectRunStoreStateTx(scratch->sgh, f, tx->tx_ptr, tx->tx_id, s,
                    inspect_flags, flow_flags, file_no_match);
        }
    }

    return retval;
}

#define NO_TX                                                                                      \
    {                                                                                              \
        NULL, 0, NULL, NULL, 0, 0, 0, 0,                                                           \
    }

/** \internal
 *  \brief get a DetectTransaction object
 *  \retval struct filled with relevant info or all nulls/0s
 */
static DetectTransaction GetDetectTx(const uint8_t ipproto, const AppProto alproto,
        const uint64_t tx_id, void *tx_ptr, const int tx_end_state, const uint8_t flow_flags)
{
    AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx_ptr);
    const int tx_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx_ptr, flow_flags);
    bool updated = (flow_flags & STREAM_TOSERVER) ? txd->updated_ts : txd->updated_tc;
    if (!updated && tx_progress < tx_end_state && ((flow_flags & STREAM_EOF) == 0)) {
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }
    const uint8_t inspected_flag =
            (flow_flags & STREAM_TOSERVER) ? APP_LAYER_TX_INSPECTED_TS : APP_LAYER_TX_INSPECTED_TC;
    if (unlikely(txd->flags & inspected_flag)) {
        SCLogDebug("%" PRIu64 " tx already fully inspected for %s. Flags %02x", tx_id,
                flow_flags & STREAM_TOSERVER ? "toserver" : "toclient", txd->flags);
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }
    const uint8_t skip_flag = (flow_flags & STREAM_TOSERVER) ? APP_LAYER_TX_SKIP_INSPECT_TS
                                                             : APP_LAYER_TX_SKIP_INSPECT_TC;
    if (unlikely(txd->flags & skip_flag)) {
        SCLogDebug("%" PRIu64 " tx should not be inspected in direction %s. Flags %02x", tx_id,
                flow_flags & STREAM_TOSERVER ? "toserver" : "toclient", txd->flags);
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }

    const uint8_t detect_progress =
            (flow_flags & STREAM_TOSERVER) ? txd->detect_progress_ts : txd->detect_progress_tc;

    const int dir_int = (flow_flags & STREAM_TOSERVER) ? 0 : 1;
    DetectEngineState *tx_de_state = txd->de_state;
    DetectEngineStateDirection *tx_dir_state =
            tx_de_state ? &tx_de_state->dir_state[dir_int] : NULL;
    DetectTransaction tx = {
        .tx_ptr = tx_ptr,
        .tx_id = tx_id,
        .tx_data_ptr = (struct AppLayerTxData *)txd,
        .de_state = tx_dir_state,
        .detect_progress = detect_progress,
        .detect_progress_orig = detect_progress,
        .tx_progress = tx_progress,
        .tx_end_state = tx_end_state,
    };
    return tx;
}

static inline void StoreDetectProgress(
        DetectTransaction *tx, const uint8_t flow_flags, const uint8_t progress)
{
    AppLayerTxData *txd = (AppLayerTxData *)tx->tx_data_ptr;
    if (flow_flags & STREAM_TOSERVER) {
        txd->detect_progress_ts = progress;
    } else {
        txd->detect_progress_tc = progress;
    }
}

// Merge 'state' rules from the regular prefilter
// updates array_idx on the way
static inline void RuleMatchCandidateMergeStateRules(
        DetectEngineThreadCtx *det_ctx, uint32_t *array_idx)
{
    // Now, we will merge 2 sorted lists :
    // the one in det_ctx->tx_candidates
    // and the one in det_ctx->match_array
    // For match_array, we take only the relevant elements where s->app_inspect != NULL

    // Basically, we iterate at the same time over the 2 lists
    // comparing and taking an element from either.

    // Trick is to do so in place in det_ctx->tx_candidates,
    // so as to minimize the number of moves in det_ctx->tx_candidates.
    // For this, the algorithm traverses the lists in reverse order.
    // Otherwise, if the first element of match_array was to be put before
    // all tx_candidates, we would need to shift all tx_candidates

    // Retain the number of elements sorted in tx_candidates before merge
    uint32_t j = *array_idx;
    // First loop only counting the number of elements to add
    for (uint32_t i = 0; i < det_ctx->match_array_cnt; i++) {
        const Signature *s = det_ctx->match_array[i];
        if (s->app_inspect != NULL) {
            (*array_idx)++;
        }
    }
    // Future number of elements in tx_candidates after merge
    uint32_t k = *array_idx;

    if (k == j) {
        // no new element from match_array to merge in tx_candidates
        return;
    }

    // variable i is for all elements of match_array (even not relevant ones)
    // variable j is for elements of tx_candidates before merge
    // variable k is for elements of tx_candidates after merge
    for (uint32_t i = det_ctx->match_array_cnt; i > 0;) {
        const Signature *s = det_ctx->match_array[i - 1];
        if (s->app_inspect == NULL) {
            // no relevant element, get the next one from match_array
            i--;
            continue;
        }
        // we have one element from match_array to merge in tx_candidates
        k--;
        if (j > 0) {
            // j > 0 means there is still at least one element in tx_candidates to merge
            const RuleMatchCandidateTx *s0 = &det_ctx->tx_candidates[j - 1];
            if (s->iid <= s0->id) {
                // get next element from previous tx_candidates
                j--;
                // take the element from tx_candidates before merge
                det_ctx->tx_candidates[k].s = det_ctx->tx_candidates[j].s;
                det_ctx->tx_candidates[k].id = det_ctx->tx_candidates[j].id;
                det_ctx->tx_candidates[k].flags = det_ctx->tx_candidates[j].flags;
                det_ctx->tx_candidates[k].stream_reset = det_ctx->tx_candidates[j].stream_reset;
                continue;
            }
        } // otherwise
        // get next element from match_array
        i--;
        // take the element from match_array
        det_ctx->tx_candidates[k].s = s;
        det_ctx->tx_candidates[k].id = s->iid;
        det_ctx->tx_candidates[k].flags = NULL;
        det_ctx->tx_candidates[k].stream_reset = 0;
    }
    // Even if k > 0 or j > 0, the loop is over. (Note that j == k now)
    // The remaining elements in tx_candidates up to k were already sorted
    // and come before any other element later in the list
}

/**
 * \internal
 * \brief Check and update firewall rules state.
 *
 * \param skip_fw_hook bool to indicate firewall rules skips
 * For state `skip_before_progress` should be skipped.
 *
 * \param skip_before_progress progress value to skip rules before.
 * Only used if `skip_fw_hook` is set.
 *
 * \param last_for_progress[out] set to true if this is the last rule for a progress value
 *
 * \param fw_next_progress_missing[out] set to true if the next fw rule does not target the next
 * progress value, or there is no fw rule for that value.
 *
 * \retval 0 no action needed
 * \retval 1 rest of rules shouldn't inspected
 * \retval -1 skip this rule
 */
static int DetectRunTxCheckFirewallPolicy(DetectEngineThreadCtx *det_ctx, Packet *p, Flow *f,
        DetectTransaction *tx, const Signature *s, const uint32_t can_idx, const uint32_t can_size,
        bool *skip_fw_hook, const uint8_t skip_before_progress, bool *last_for_progress,
        bool *fw_next_progress_missing)
{
    if (s->flags & SIG_FLAG_FIREWALL) {
        /* check if the next sig is on the same progress hook. If not, we need to apply our
         * default policy in case the current sig doesn't apply one. If the next sig has a
         * progress beyond our progress + 1, it means the next progress has no rules and needs
         * the default policy applied. But only after we evaluate the current rule first, as
         * that may override it.
         * TODO should we do this after dedup below? */

        if (can_idx + 1 < can_size) {
            const Signature *next_s = det_ctx->tx_candidates[can_idx + 1].s;
            SCLogDebug(
                    "peek: peeking at sid %u / progress %u", next_s->id, next_s->app_progress_hook);
            if (next_s->flags & SIG_FLAG_FIREWALL) {
                if (s->app_progress_hook != next_s->app_progress_hook) {
                    SCLogDebug("peek: next sid progress %u != current progress %u, so current "
                               "is last for progress",
                            next_s->app_progress_hook, s->app_progress_hook);
                    *last_for_progress = true;

                    if (next_s->app_progress_hook - s->app_progress_hook > 1) {
                        SCLogDebug("peek: missing progress, so we'll drop that unless we get a "
                                   "sweeping accept first");
                        *fw_next_progress_missing = true;
                    }
                }
            } else {
                SCLogDebug("peek: next sid not a fw rule, so current is last for progress");
                *last_for_progress = true;
            }
        } else {
            SCLogDebug("peek: no peek beyond last rule");
            if (s->app_progress_hook < tx->tx_progress) {
                SCLogDebug("peek: there are no rules to allow the state after this rule");
                *fw_next_progress_missing = true;
            }
        }

        if ((*skip_fw_hook) == true) {
            if (s->app_progress_hook <= skip_before_progress) {
                return -1;
            }
            *skip_fw_hook = false;
        }
    } else {
        /* fw mode, we skip anything after the fw rules if:
         * - flow pass is set
         * - packet pass (e.g. exception policy) */
        if (p->flags & PKT_NOPACKET_INSPECTION || (f->flags & (FLOW_ACTION_PASS))) {
            SCLogDebug("skipping firewall rule %u", s->id);
            return 1;
        }
    }
    return 0;
}

// TODO move into det_ctx?
thread_local Signature default_accept;
static inline void DetectRunAppendDefaultAccept(DetectEngineThreadCtx *det_ctx, Packet *p)
{
    if (EngineModeIsFirewall()) {
        memset(&default_accept, 0, sizeof(default_accept));
        default_accept.action = ACTION_ACCEPT;
        default_accept.action_scope = ACTION_SCOPE_PACKET;
        default_accept.iid = UINT32_MAX;
        default_accept.type = SIG_TYPE_PKT;
        default_accept.flags = SIG_FLAG_FIREWALL;
        AlertQueueAppend(det_ctx, &default_accept, p, 0, PACKET_ALERT_FLAG_APPLY_ACTION_TO_PACKET);
    }
}

/** \internal
 * \brief see if the accept rule needs to apply to the packet
 */
static inline bool ApplyAcceptToPacket(
        const uint64_t total_txs, const DetectTransaction *tx, const Signature *s)
{
    if ((s->flags & SIG_FLAG_FIREWALL) == 0) {
        return false;
    }
    if ((s->action & ACTION_ACCEPT) == 0) {
        return false;
    }

    /* for accept:tx we need:
     * - packet will only be accepted if this is set on the last tx
     */
    if (s->action_scope == ACTION_SCOPE_TX) {
        if (total_txs == tx->tx_id + 1) {
            return true;
        }
    }
    /* for accept:hook we need a bit more checking:
     * - packet will only be accepted if this is set on the last tx
     * - the hook accepted should be the last progress available. */
    if (s->action_scope == ACTION_SCOPE_HOOK) {
        if ((total_txs == tx->tx_id + 1) && /* last tx */
                (s->app_progress_hook == tx->tx_progress)) {
            return true;
        }
    }
    return false;
}

/** \internal
 * \retval bool true: break_out_of_app_filter, false: don't break out */
static bool ApplyAccept(Packet *p, const uint8_t flow_flags, const Signature *s,
        DetectTransaction *tx, const int tx_end_state, const bool fw_next_progress_missing,
        bool *tx_fw_verdict, bool *skip_fw_hook, uint8_t *skip_before_progress)
{
    *tx_fw_verdict = true;

    const enum ActionScope as = s->action_scope;
    /* accept:hook: jump to first rule of next state.
     * Implemented as skip until the first rule of next state. */
    if (as == ACTION_SCOPE_HOOK) {
        *skip_fw_hook = true;
        *skip_before_progress = s->app_progress_hook;

        /* if there is no fw rule for the next progress value,
         * we invoke the default drop policy. */
        if (fw_next_progress_missing) {
            SCLogDebug("%" PRIu64 ": %s default drop for progress", p->pcap_cnt,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient");
            PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_DEFAULT_APP_POLICY);
            p->flow->flags |= FLOW_ACTION_DROP;
            return true;
        }
        return false;
    } else if (as == ACTION_SCOPE_TX) {
        tx->tx_data_ptr->flags |= APP_LAYER_TX_ACCEPT;
        *skip_fw_hook = true;
        *skip_before_progress = (uint8_t)tx_end_state + 1; // skip all hooks
        SCLogDebug(
                "accept:tx applied, skip_fw_hook, skip_before_progress %u", *skip_before_progress);
        return false;
    } else if (as == ACTION_SCOPE_PACKET) {
        return true;
    } else if (as == ACTION_SCOPE_FLOW) {
        return true;
    }
    return false;
}

static void DetectRunTx(ThreadVars *tv,
                    DetectEngineCtx *de_ctx,
                    DetectEngineThreadCtx *det_ctx,
                    Packet *p,
                    Flow *f,
                    DetectRunScratchpad *scratch)
{
    const uint8_t flow_flags = scratch->flow_flags;
    const SigGroupHead * const sgh = scratch->sgh;
    void * const alstate = f->alstate;
    const uint8_t ipproto = f->proto;
    const AppProto alproto = f->alproto;

    const uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
    uint64_t tx_id_min = AppLayerParserGetTransactionInspectId(f->alparser, flow_flags);
    const int tx_end_state = AppLayerParserGetStateProgressCompletionStatus(alproto, flow_flags);

    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(ipproto, alproto);
    AppLayerGetTxIterState state = { 0 };

    uint32_t fw_verdicted = 0;
    uint32_t tx_inspected = 0;
    const bool have_fw_rules = EngineModeIsFirewall();

    SCLogDebug("packet %" PRIu64, p->pcap_cnt);

    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, tx_id_min, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        DetectTransaction tx =
                GetDetectTx(ipproto, alproto, ires.tx_id, ires.tx_ptr, tx_end_state, flow_flags);
        if (tx.tx_ptr == NULL) {
            SCLogDebug("%p/%"PRIu64" no transaction to inspect",
                    tx.tx_ptr, tx_id_min);

            tx_id_min++; // next (if any) run look for +1
            goto next;
        }
        tx_id_min = tx.tx_id + 1; // next look for cur + 1
        tx_inspected++;

        SCLogDebug("%p/%" PRIu64 " txd flags %02x", tx.tx_ptr, tx_id_min, tx.tx_data_ptr->flags);

        det_ctx->tx_id = tx.tx_id;
        det_ctx->tx_id_set = true;
        det_ctx->p = p;

        bool do_sort = false; // do we need to sort the tx candidate list?
        uint32_t array_idx = 0;
        uint32_t total_rules = det_ctx->match_array_cnt;
        total_rules += (tx.de_state ? tx.de_state->cnt : 0);

        /* run prefilter engines and merge results into a candidates array */
        if (sgh->tx_engines) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_TX);
            DetectRunPrefilterTx(det_ctx, sgh, p, ipproto, flow_flags, alproto,
                    alstate, &tx);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_TX);
            SCLogDebug("%p/%"PRIu64" rules added from prefilter: %u candidates",
                    tx.tx_ptr, tx.tx_id, det_ctx->pmq.rule_id_array_cnt);

            total_rules += det_ctx->pmq.rule_id_array_cnt;
            if (!(RuleMatchCandidateTxArrayHasSpace(det_ctx, total_rules))) {
                RuleMatchCandidateTxArrayExpand(det_ctx, total_rules);
            }

            for (uint32_t i = 0; i < det_ctx->pmq.rule_id_array_cnt; i++) {
                const Signature *s = de_ctx->sig_array[det_ctx->pmq.rule_id_array[i]];
                const SigIntId id = s->iid;
                det_ctx->tx_candidates[array_idx].s = s;
                det_ctx->tx_candidates[array_idx].id = id;
                det_ctx->tx_candidates[array_idx].flags = NULL;
                det_ctx->tx_candidates[array_idx].stream_reset = 0;
                array_idx++;
            }
            PMQ_RESET(&det_ctx->pmq);
        } else {
            if (!(RuleMatchCandidateTxArrayHasSpace(det_ctx, total_rules))) {
                RuleMatchCandidateTxArrayExpand(det_ctx, total_rules);
            }
        }

        /* merge 'state' rules from the regular prefilter */
#ifdef PROFILING
        uint32_t x = array_idx;
#endif
        RuleMatchCandidateMergeStateRules(det_ctx, &array_idx);

        /* merge stored state into results */
        if (tx.de_state != NULL) {
            const uint32_t old = array_idx;

            /* if tx.de_state->flags has 'new file' set and sig below has
             * 'file inspected' flag, reset the file part of the state */
            const bool have_new_file = (tx.de_state->flags & DETECT_ENGINE_STATE_FLAG_FILE_NEW);
            if (have_new_file) {
                SCLogDebug("%p/%"PRIu64" destate: need to consider new file",
                        tx.tx_ptr, tx.tx_id);
                tx.de_state->flags &= ~DETECT_ENGINE_STATE_FLAG_FILE_NEW;
            }

            SigIntId state_cnt = 0;
            DeStateStore *tx_store = tx.de_state->head;
            for (; tx_store != NULL; tx_store = tx_store->next) {
                SCLogDebug("tx_store %p", tx_store);

                SigIntId store_cnt = 0;
                for (store_cnt = 0;
                        store_cnt < DE_STATE_CHUNK_SIZE && state_cnt < tx.de_state->cnt;
                        store_cnt++, state_cnt++)
                {
                    DeStateStoreItem *item = &tx_store->store[store_cnt];
                    SCLogDebug("rule id %u, inspect_flags %u", item->sid, item->flags);
                    if (have_new_file && (item->flags & DE_STATE_FLAG_FILE_INSPECT)) {
                        /* remove part of the state. File inspect engine will now
                         * be able to run again */
                        item->flags &= ~(DE_STATE_FLAG_SIG_CANT_MATCH|DE_STATE_FLAG_FULL_INSPECT|DE_STATE_FLAG_FILE_INSPECT);
                        SCLogDebug("rule id %u, post file reset inspect_flags %u", item->sid, item->flags);
                    }
                    det_ctx->tx_candidates[array_idx].s = de_ctx->sig_array[item->sid];
                    det_ctx->tx_candidates[array_idx].id = item->sid;
                    det_ctx->tx_candidates[array_idx].flags = &item->flags;
                    det_ctx->tx_candidates[array_idx].stream_reset = 0;
                    array_idx++;
                }
            }
            do_sort |= (old && old != array_idx); // sort if continue list adds sids
            SCLogDebug("%p/%" PRIu64 " rules added from 'continue' list: %u", tx.tx_ptr, tx.tx_id,
                    array_idx - old);
        }
        if (do_sort) {
            qsort(det_ctx->tx_candidates, array_idx, sizeof(RuleMatchCandidateTx),
                    DetectRunTxSortHelper);
        }

#ifdef PROFILING
        if (array_idx >= de_ctx->profile_match_logging_threshold)
            RulesDumpTxMatchArray(det_ctx, scratch->sgh, p, tx.tx_id, array_idx, x);
#endif

#ifdef DEBUG
        for (uint32_t i = 0; i < array_idx; i++) {
            RuleMatchCandidateTx *can = &det_ctx->tx_candidates[i];
            const Signature *s = det_ctx->tx_candidates[i].s;
            SCLogDebug("%u: sid %u flags %p", i, s->id, can->flags);
        }
#endif
        bool skip_fw_hook = false;
        uint8_t skip_before_progress = 0;
        bool fw_next_progress_missing = false;

        /* if there are no rules / rule candidates, make sure we don't
         * invoke the default drop */
        if (have_fw_rules && array_idx == 0 && (tx.tx_data_ptr->flags & APP_LAYER_TX_ACCEPT)) {
            fw_verdicted++;

            /* current tx is the last we have, append a blank accept:packet */
            if (total_txs == tx.tx_id + 1) {
                DetectRunAppendDefaultAccept(det_ctx, p);
                return;
            }
            goto next;
        }

        bool tx_fw_verdict = false;
        /* run rules: inspect the match candidates */
        for (uint32_t i = 0; i < array_idx; i++) {
            RuleMatchCandidateTx *can = &det_ctx->tx_candidates[i];
            const Signature *s = det_ctx->tx_candidates[i].s;
            uint32_t *inspect_flags = det_ctx->tx_candidates[i].flags;
            bool break_out_of_app_filter = false;

            SCLogDebug("%" PRIu64 ": sid:%u: %s tx %u/%u/%u sig %u", p->pcap_cnt, s->id,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient", tx.tx_progress,
                    tx.detect_progress, tx.detect_progress_orig, s->app_progress_hook);

            /* deduplicate: rules_array is sorted, but not deduplicated:
             * both mpm and stored state could give us the same sid.
             * As they are back to back in that case we can check for it
             * here. We select the stored state one as that comes first
             * in the array. */
            while ((i + 1) < array_idx &&
                    det_ctx->tx_candidates[i].s == det_ctx->tx_candidates[i + 1].s) {
                SCLogDebug("%p/%" PRIu64 " inspecting SKIP NEXT: sid %u (%u), flags %08x",
                        tx.tx_ptr, tx.tx_id, s->id, s->iid, inspect_flags ? *inspect_flags : 0);
                i++;
            }

            /* skip fw rules if we're in accept:tx mode */
            if (have_fw_rules && (tx.tx_data_ptr->flags & APP_LAYER_TX_ACCEPT)) {
                /* append a blank accept:packet action for the APP_LAYER_TX_ACCEPT,
                 * if this is the last tx */
                if (!tx_fw_verdict) {
                    const bool accept_tx_applies_to_packet = total_txs == tx.tx_id + 1;
                    if (accept_tx_applies_to_packet) {
                        SCLogDebug("accept:(tx|hook): should be applied to the packet");
                        DetectRunAppendDefaultAccept(det_ctx, p);
                    }
                }
                tx_fw_verdict = true;

                if (s->flags & SIG_FLAG_FIREWALL) {
                    SCLogDebug("APP_LAYER_TX_ACCEPT, so skip rule");
                    continue;
                }

                /* threat detect rules will be inspected */
            }

            SCLogDebug("%p/%" PRIu64 " inspecting: sid %u (%u), flags %08x", tx.tx_ptr, tx.tx_id,
                    s->id, s->iid, inspect_flags ? *inspect_flags : 0);

            if (inspect_flags) {
                if (*inspect_flags & DE_STATE_FLAG_FULL_INSPECT) {
                    SCLogDebug("%p/%" PRIu64
                               " inspecting: sid %u (%u), flags %08x DE_STATE_FLAG_FULL_INSPECT",
                            tx.tx_ptr, tx.tx_id, s->id, s->iid, *inspect_flags);

                    /* if we're still in the same progress state as an earlier full
                     * match, we need to apply the same accept */
                    if (have_fw_rules && (s->flags & SIG_FLAG_FIREWALL) &&
                            (s->action & ACTION_ACCEPT) && s->app_progress_hook == tx.tx_progress) {
                        const bool fw_accept_to_packet = ApplyAcceptToPacket(total_txs, &tx, s);
                        break_out_of_app_filter = ApplyAccept(p, flow_flags, s, &tx, tx_end_state,
                                fw_next_progress_missing, &tx_fw_verdict, &skip_fw_hook,
                                &skip_before_progress);
                        if (fw_accept_to_packet)
                            DetectRunAppendDefaultAccept(det_ctx, p);
                        if (break_out_of_app_filter)
                            break;
                    }
                    continue;
                }
                if (*inspect_flags & DE_STATE_FLAG_SIG_CANT_MATCH) {
                    SCLogDebug("%p/%" PRIu64
                               " inspecting: sid %u (%u), flags %08x DE_STATE_FLAG_SIG_CANT_MATCH",
                            tx.tx_ptr, tx.tx_id, s->id, s->iid, *inspect_flags);
                    continue;
                }
            }

            if (inspect_flags) {
                /* continue previous inspection */
                SCLogDebug("%p/%" PRIu64 " Continuing sid %u", tx.tx_ptr, tx.tx_id, s->id);
            } else {
                /* start new inspection */
                SCLogDebug("%p/%"PRIu64" Start sid %u", tx.tx_ptr, tx.tx_id, s->id);
            }

            bool last_for_progress = false;
            if (have_fw_rules) {
                int fw_r = DetectRunTxCheckFirewallPolicy(det_ctx, p, f, &tx, s, i, array_idx,
                        &skip_fw_hook, skip_before_progress, &last_for_progress,
                        &fw_next_progress_missing);
                if (fw_r == -1)
                    continue;
                if (fw_r == 1)
                    break;
            }

            /* call individual rule inspection */
            RULE_PROFILING_START(p);
            const int r = DetectRunTxInspectRule(tv, de_ctx, det_ctx, p, f, flow_flags,
                    alstate, &tx, s, inspect_flags, can, scratch);
            if (r == 1) {
                /* match */
                DetectRunPostMatch(tv, det_ctx, p, s);

                /* see if we need to apply tx/hook accept to the packet. This can be needed when
                 * we've completed the inspection so far for an incomplete tx, and an accept:tx or
                 * accept:hook is the last match.*/
                const bool fw_accept_to_packet = ApplyAcceptToPacket(total_txs, &tx, s);

                uint8_t alert_flags = (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_TX);
                if (fw_accept_to_packet) {
                    SCLogDebug("accept:(tx|hook): should be applied to the packet");
                    alert_flags |= PACKET_ALERT_FLAG_APPLY_ACTION_TO_PACKET;
                }

                SCLogDebug(
                        "%p/%" PRIu64 " sig %u (%u) matched", tx.tx_ptr, tx.tx_id, s->id, s->iid);
                AlertQueueAppend(det_ctx, s, p, tx.tx_id, alert_flags);

                if ((s->flags & SIG_FLAG_FIREWALL) && (s->action & ACTION_ACCEPT)) {
                    break_out_of_app_filter = ApplyAccept(p, flow_flags, s, &tx, tx_end_state,
                            fw_next_progress_missing, &tx_fw_verdict, &skip_fw_hook,
                            &skip_before_progress);
                }
            } else if (last_for_progress) {
                SCLogDebug("sid %u: not a match: %s rule, last_for_progress %s", s->id,
                        (s->flags & SIG_FLAG_FIREWALL) ? "firewall" : "regular",
                        BOOL2STR(last_for_progress));
                if (s->flags & SIG_FLAG_FIREWALL) {
                    SCLogDebug("%" PRIu64 ": %s default drop for progress", p->pcap_cnt,
                            flow_flags & STREAM_TOSERVER ? "toserver" : "toclient");
                    /* if this rule was the last for our progress state, and it didn't match,
                     * we have to invoke the default drop policy. */
                    PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_DEFAULT_APP_POLICY);
                    p->flow->flags |= FLOW_ACTION_DROP;
                    break_out_of_app_filter = true;
                    tx_fw_verdict = true;
                }
            }
            DetectVarProcessList(det_ctx, p->flow, p);
            RULE_PROFILING_END(det_ctx, s, r, p);

            if (det_ctx->post_rule_work_queue.len > 0) {
                SCLogDebug("%p/%" PRIu64 " post_rule_work_queue len %u", tx.tx_ptr, tx.tx_id,
                        det_ctx->post_rule_work_queue.len);
                /* run post match prefilter engines on work queue */
                PrefilterPostRuleMatch(det_ctx, scratch->sgh, p, f);

                uint32_t prev_array_idx = array_idx;
                for (uint32_t j = 0; j < det_ctx->pmq.rule_id_array_cnt; j++) {
                    const Signature *ts = de_ctx->sig_array[det_ctx->pmq.rule_id_array[j]];
                    if (ts->app_inspect != NULL) {
                        const SigIntId id = ts->iid;
                        det_ctx->tx_candidates[array_idx].s = ts;
                        det_ctx->tx_candidates[array_idx].id = id;
                        det_ctx->tx_candidates[array_idx].flags = NULL;
                        det_ctx->tx_candidates[array_idx].stream_reset = 0;
                        array_idx++;

                        SCLogDebug("%p/%" PRIu64 " rule %u (%u) added from 'post match' prefilter",
                                tx.tx_ptr, tx.tx_id, ts->id, id);
                    }
                }
                SCLogDebug("%p/%" PRIu64 " rules added from 'post match' prefilter: %u", tx.tx_ptr,
                        tx.tx_id, array_idx - prev_array_idx);
                if (prev_array_idx != array_idx) {
                    /* sort, but only part of array we're still going to process */
                    qsort(det_ctx->tx_candidates + i, array_idx - i, sizeof(RuleMatchCandidateTx),
                            DetectRunTxSortHelper);
                }
                det_ctx->post_rule_work_queue.len = 0;
                PMQ_RESET(&det_ctx->pmq);
            }

            if (break_out_of_app_filter)
                break;
        }
        if (tx_fw_verdict)
            fw_verdicted++;

        det_ctx->tx_id = 0;
        det_ctx->tx_id_set = false;
        det_ctx->p = NULL;

        /* see if we have any updated state to store in the tx */

        /* this side of the tx is done */
        if (tx.tx_progress >= tx.tx_end_state) {
            SCLogDebug("%" PRIu64 ": %s tx done", p->pcap_cnt,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient");
            const uint8_t inspected_flag = (flow_flags & STREAM_TOSERVER)
                                                   ? APP_LAYER_TX_INSPECTED_TS
                                                   : APP_LAYER_TX_INSPECTED_TC;
            tx.tx_data_ptr->flags |= inspected_flag;
            SCLogDebug("%p/%" PRIu64 " tx is done for direction %s. Progress %02x", tx.tx_ptr,
                    tx.tx_id, flow_flags & STREAM_TOSERVER ? "toserver" : "toclient",
                    tx.detect_progress);
        }

        if (tx.detect_progress != tx.detect_progress_orig) {
            SCLogDebug("%" PRIu64 ": %s tx state change %u -> %u", p->pcap_cnt,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient", tx.detect_progress_orig,
                    tx.detect_progress);
            SCLogDebug("%p/%" PRIu64 " Storing new progress %02x (was %02x)", tx.tx_ptr, tx.tx_id,
                    tx.detect_progress, tx.detect_progress_orig);

            StoreDetectProgress(&tx, flow_flags, tx.detect_progress);
        }

        InspectionBufferClean(det_ctx);

    next:
        if (!ires.has_next)
            break;
    }

    /* apply default policy if there were txs to inspect, we have fw rules and non of the rules
     * applied a policy. */
    SCLogDebug("packet %" PRIu64 ": tx_inspected %u fw_verdicted %u", p->pcap_cnt, tx_inspected,
            fw_verdicted);
    if (tx_inspected && have_fw_rules && tx_inspected != fw_verdicted) {
        SCLogDebug("%" PRIu64 ": %s default drop", p->pcap_cnt,
                flow_flags & STREAM_TOSERVER ? "toserver" : "toclient");
        PacketDrop(p, ACTION_DROP, PKT_DROP_REASON_DEFAULT_APP_POLICY);
        p->flow->flags |= FLOW_ACTION_DROP;
        return;
    }
    /* if all tables have been bypassed, we accept:packet */
    if (tx_inspected == 0 && fw_verdicted == 0 && have_fw_rules) {
        DetectRunAppendDefaultAccept(det_ctx, p);
    }
}

static void DetectRunFrames(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow *f, DetectRunScratchpad *scratch)
{
    const SigGroupHead *const sgh = scratch->sgh;
    const AppProto alproto = f->alproto;

    /* for TCP, limit inspection to pseudo packets or real packet that did
     * an app-layer update. */
    if (p->proto == IPPROTO_TCP && !PKT_IS_PSEUDOPKT(p) &&
            ((PKT_IS_TOSERVER(p) && (f->flags & FLOW_TS_APP_UPDATED) == 0) ||
                    (PKT_IS_TOCLIENT(p) && (f->flags & FLOW_TC_APP_UPDATED) == 0))) {
        SCLogDebug("pcap_cnt %" PRIu64 ": %s: skip frame inspection for TCP w/o APP UPDATE",
                p->pcap_cnt, PKT_IS_TOSERVER(p) ? "toserver" : "toclient");
        return;
    }
    FramesContainer *frames_container = AppLayerFramesGetContainer(f);
    if (frames_container == NULL) {
        return;
    }
    Frames *frames;
    if (PKT_IS_TOSERVER(p)) {
        frames = &frames_container->toserver;
    } else {
        frames = &frames_container->toclient;
    }

    for (uint32_t idx = 0; idx < frames->cnt; idx++) {
        SCLogDebug("frame %u", idx);
        Frame *frame = FrameGetByIndex(frames, idx);
        if (frame == NULL) {
            continue;
        }

        det_ctx->frame_inspect_progress = 0;
        uint32_t array_idx = 0;
        uint32_t total_rules = det_ctx->match_array_cnt;

        /* run prefilter engines and merge results into a candidates array */
        if (sgh->frame_engines) {
            //            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_TX);
            DetectRunPrefilterFrame(det_ctx, sgh, p, frames, frame, alproto);
            //            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_TX);
            SCLogDebug("%p/%" PRIi64 " rules added from prefilter: %u candidates", frame, frame->id,
                    det_ctx->pmq.rule_id_array_cnt);

            total_rules += det_ctx->pmq.rule_id_array_cnt;

            if (!(RuleMatchCandidateTxArrayHasSpace(
                        det_ctx, total_rules))) { // TODO is it safe to overload?
                RuleMatchCandidateTxArrayExpand(det_ctx, total_rules);
            }

            for (uint32_t i = 0; i < det_ctx->pmq.rule_id_array_cnt; i++) {
                const Signature *s = de_ctx->sig_array[det_ctx->pmq.rule_id_array[i]];
                const SigIntId id = s->iid;
                det_ctx->tx_candidates[array_idx].s = s;
                det_ctx->tx_candidates[array_idx].id = id;
                det_ctx->tx_candidates[array_idx].flags = NULL;
                det_ctx->tx_candidates[array_idx].stream_reset = 0;
                array_idx++;
            }
            PMQ_RESET(&det_ctx->pmq);
        }
        /* merge 'state' rules from the regular prefilter */
        uint32_t x = array_idx;
        for (uint32_t i = 0; i < det_ctx->match_array_cnt; i++) {
            const Signature *s = det_ctx->match_array[i];
            if (s->frame_inspect != NULL) {
                const SigIntId id = s->iid;
                det_ctx->tx_candidates[array_idx].s = s;
                det_ctx->tx_candidates[array_idx].id = id;
                det_ctx->tx_candidates[array_idx].flags = NULL;
                det_ctx->tx_candidates[array_idx].stream_reset = 0;
                array_idx++;

                SCLogDebug("%p/%" PRIi64 " rule %u (%u) added from 'match' list", frame, frame->id,
                        s->id, id);
            }
        }
        SCLogDebug("%p/%" PRIi64 " rules added from 'match' list: %u", frame, frame->id,
                array_idx - x);
        (void)x;

        /* run rules: inspect the match candidates */
        for (uint32_t i = 0; i < array_idx; i++) {
            const Signature *s = det_ctx->tx_candidates[i].s;

            /* deduplicate: rules_array is sorted, but not deduplicated.
             * As they are back to back in that case we can check for it
             * here. We select the stored state one as that comes first
             * in the array. */
            while ((i + 1) < array_idx &&
                    det_ctx->tx_candidates[i].s == det_ctx->tx_candidates[i + 1].s) {
                i++;
            }
            SCLogDebug("%p/%" PRIi64 " inspecting: sid %u (%u)", frame, frame->id, s->id, s->iid);

            /* start new inspection */
            SCLogDebug("%p/%" PRIi64 " Start sid %u", frame, frame->id, s->id);

            /* call individual rule inspection */
            RULE_PROFILING_START(p);
            bool r = DetectRunInspectRuleHeader(p, f, s, s->flags, s->proto.flags);
            if (r) {
                r = DetectRunFrameInspectRule(tv, det_ctx, s, f, p, frames, frame);
                if (r) {
                    /* match */
                    DetectRunPostMatch(tv, det_ctx, p, s);

                    uint8_t alert_flags = (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_FRAME);
                    det_ctx->frame_id = frame->id;
                    SCLogDebug(
                            "%p/%" PRIi64 " sig %u (%u) matched", frame, frame->id, s->id, s->iid);
                    if (frame->flags & FRAME_FLAG_TX_ID_SET) {
                        alert_flags |= PACKET_ALERT_FLAG_TX;
                    }
                    AlertQueueAppend(det_ctx, s, p, frame->tx_id, alert_flags);
                }
            }
            DetectVarProcessList(det_ctx, p->flow, p);
            RULE_PROFILING_END(det_ctx, s, r, p);
        }

        /* update Frame::inspect_progress here instead of in the code above. The reason is that a
         * frame might be used more than once in buffers with transforms. */
        if (frame->inspect_progress < det_ctx->frame_inspect_progress) {
            frame->inspect_progress = det_ctx->frame_inspect_progress;
            SCLogDebug("frame->inspect_progress: %" PRIu64 " -> updated", frame->inspect_progress);
        } else {
            SCLogDebug(
                    "frame->inspect_progress: %" PRIu64 " -> not updated", frame->inspect_progress);
        }

        SCLogDebug("%p/%" PRIi64 " rules inspected, running cleanup", frame, frame->id);
        InspectionBufferClean(det_ctx);
    }
}

static DetectEngineThreadCtx *GetTenantById(HashTable *h, uint32_t id)
{
    /* technically we need to pass a DetectEngineThreadCtx struct with the
     * tenant_id member. But as that member is the first in the struct, we
     * can use the id directly. */
    return HashTableLookup(h, &id, 0);
}

static void DetectFlow(ThreadVars *tv,
                       DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                       Packet *p)
{
    Flow *const f = p->flow;

    /* we check the flow drop here, and not the packet drop. This is
     * to allow stream engine "invalid" drop packets to still be
     * evaluated by the stream event rules. */
    if (f->flags & FLOW_ACTION_DROP) {
        DEBUG_VALIDATE_BUG_ON(!(PKT_IS_PSEUDOPKT(p)) && !PacketCheckAction(p, ACTION_DROP));
        SCReturn;
    }

    /* in firewall mode, we still need to run the fw rulesets even for exception policy pass */
    bool skip = false;
    if (EngineModeIsFirewall()) {
        skip = (f->flags & (FLOW_ACTION_ACCEPT));

    } else {
        skip = (p->flags & PKT_NOPACKET_INSPECTION || f->flags & (FLOW_ACTION_PASS));
    }
    if (skip) {
        /* enfore prior accept:flow */
        if (f->flags & FLOW_ACTION_ACCEPT) {
            p->action |= ACTION_ACCEPT;
        }
        /* hack: if we are in pass the entire flow mode, we need to still
         * update the inspect_id forward. So test for the condition here,
         * and call the update code if necessary. */
        const int pass = (f->flags & (FLOW_ACTION_PASS | FLOW_ACTION_ACCEPT));
        if (pass) {
            uint8_t flags = STREAM_FLAGS_FOR_PACKET(p);
            flags = FlowGetDisruptionFlags(f, flags);
            if (f->alstate) {
                AppLayerParserSetTransactionInspectId(f, f->alparser, f->alstate, flags, true);
            }
        }
        SCLogDebug("p->pcap %"PRIu64": no detection on packet, "
                "PKT_NOPACKET_INSPECTION is set", p->pcap_cnt);
        return;
    }

    /* see if the packet matches one or more of the sigs */
    DetectRun(tv, de_ctx, det_ctx, p);
}


static void DetectNoFlow(ThreadVars *tv,
                         DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                         Packet *p)
{
    /* No need to perform any detection on this packet, if the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) || (PacketCheckAction(p, ACTION_DROP))) {
        return;
    }

    /* see if the packet matches one or more of the sigs */
    DetectRun(tv, de_ctx, det_ctx, p);
}

uint8_t DetectPreFlow(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    const DetectEngineCtx *de_ctx = det_ctx->de_ctx;
    const SigGroupHead *sgh = de_ctx->pre_flow_sgh;

    SCLogDebug("thread id: %u, packet %" PRIu64 ", sgh %p", tv->id, p->pcap_cnt, sgh);
    DetectRunPacketHook(tv, de_ctx, det_ctx, sgh, p);
    return p->action;
}

uint8_t DetectPreStream(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    const DetectEngineCtx *de_ctx = det_ctx->de_ctx;
    const int direction = (PKT_IS_TOCLIENT(p) != 0);
    const SigGroupHead *sgh = de_ctx->pre_stream_sgh[direction];

    SCLogDebug("thread id: %u, packet %" PRIu64 ", sgh %p", tv->id, p->pcap_cnt, sgh);
    DetectRunPacketHook(tv, de_ctx, det_ctx, sgh, p);
    return p->action;
}

/** \brief Detection engine thread wrapper.
 *  \param tv thread vars
 *  \param p packet to inspect
 *  \param data thread specific data
 *  \param pq packet queue
 *  \retval TM_ECODE_FAILED error
 *  \retval TM_ECODE_OK ok
 */
TmEcode Detect(ThreadVars *tv, Packet *p, void *data)
{
    DEBUG_VALIDATE_PACKET(p);

    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    if (det_ctx == NULL) {
        printf("ERROR: Detect has no thread ctx\n");
        goto error;
    }

    if (unlikely(SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0)) {
        (void)SC_ATOMIC_SET(det_ctx->so_far_used_by_detect, 1);
        SCLogDebug("Detect Engine using new det_ctx - %p",
                  det_ctx);
    }

    /* if in MT mode _and_ we have tenants registered, use
     * MT logic. */
    if (det_ctx->mt_det_ctxs_cnt > 0 && det_ctx->TenantGetId != NULL)
    {
        uint32_t tenant_id = p->tenant_id;
        if (tenant_id == 0)
            tenant_id = det_ctx->TenantGetId(det_ctx, p);
        if (tenant_id > 0 && tenant_id < det_ctx->mt_det_ctxs_cnt) {
            p->tenant_id = tenant_id;
            det_ctx = GetTenantById(det_ctx->mt_det_ctxs_hash, tenant_id);
            if (det_ctx == NULL)
                return TM_ECODE_OK;
            de_ctx = det_ctx->de_ctx;
            if (de_ctx == NULL)
                return TM_ECODE_OK;

            if (unlikely(SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0)) {
                (void)SC_ATOMIC_SET(det_ctx->so_far_used_by_detect, 1);
                SCLogDebug("MT de_ctx %p det_ctx %p (tenant %u)", de_ctx, det_ctx, tenant_id);
            }
        } else {
            /* use default if no tenants are registered for this packet */
            de_ctx = det_ctx->de_ctx;
        }
    } else {
        de_ctx = det_ctx->de_ctx;
    }

    if (p->flow) {
        DetectFlow(tv, de_ctx, det_ctx, p);
    } else {
        DetectNoFlow(tv, de_ctx, det_ctx, p);
    }

#ifdef PROFILE_RULES
    /* aggregate statistics */
    struct timeval ts;
    gettimeofday(&ts, NULL);
    if (ts.tv_sec != det_ctx->rule_perf_last_sync) {
        SCProfilingRuleThreatAggregate(det_ctx);
        det_ctx->rule_perf_last_sync = ts.tv_sec;
    }
#endif

    return TM_ECODE_OK;
error:
    return TM_ECODE_FAILED;
}

/** \brief disable file features we don't need
 *  Called if we have no detection engine.
 */
void DisableDetectFlowFileFlags(Flow *f)
{
    DetectPostInspectFileFlagsUpdate(f, NULL /* no sgh */, STREAM_TOSERVER);
    DetectPostInspectFileFlagsUpdate(f, NULL /* no sgh */, STREAM_TOCLIENT);
}

#ifdef UNITTESTS
/**
 *  \brief wrapper for old tests
 */
void SigMatchSignatures(
        ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    if (p->flow) {
        DetectFlow(tv, de_ctx, det_ctx, p);
    } else {
        DetectNoFlow(tv, de_ctx, det_ctx, p);
    }
}
#endif

/*
 * TESTS
 */

#ifdef UNITTESTS
#include "tests/detect.c"
#endif
