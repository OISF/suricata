/* Copyright (C) 2007-2022 Open Information Security Foundation
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
    const SigGroupHead *sgh;
    SignatureMask pkt_mask;
} DetectRunScratchpad;

/* prototypes */
static DetectRunScratchpad DetectRunSetup(const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet * const p, Flow * const pflow);
static void DetectRunInspectIPOnly(ThreadVars *tv, const DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Flow * const pflow, Packet * const p);
static inline void DetectRunGetRuleGroup(const DetectEngineCtx *de_ctx,
        Packet * const p, Flow * const pflow, DetectRunScratchpad *scratch);
static inline void DetectRunPrefilterPkt(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p,
        DetectRunScratchpad *scratch);
static inline void DetectRulePacketRules(ThreadVars * const tv,
        DetectEngineCtx * const de_ctx, DetectEngineThreadCtx * const det_ctx,
        Packet * const p, Flow * const pflow, const DetectRunScratchpad *scratch);
static void DetectRunTx(ThreadVars *tv, DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet *p,
        Flow *f, DetectRunScratchpad *scratch);
static void DetectRunFrames(ThreadVars *tv, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow *f, DetectRunScratchpad *scratch);
static inline void DetectRunPostRules(ThreadVars *tv, DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Packet * const p, Flow * const pflow,
        DetectRunScratchpad *scratch);
static void DetectRunCleanup(DetectEngineThreadCtx *det_ctx,
        Packet *p, Flow * const pflow);

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

    /* bail early if packet should not be inspected */
    if (p->flags & PKT_NOPACKET_INSPECTION) {
        /* nothing to do */
        SCReturn;
    }

    /* Load the Packet's flow early, even though it might not be needed.
     * Mark as a constant pointer, although the flow itself can change. */
    Flow * const pflow = p->flow;

    DetectRunScratchpad scratch = DetectRunSetup(de_ctx, det_ctx, p, pflow);

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
    DetectRulePacketRules(th_v, de_ctx, det_ctx, p, pflow, &scratch);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_RULES);

    /* run tx/state inspection. Don't call for ICMP error msgs. */
    if (pflow && pflow->alstate && likely(pflow->proto == p->proto)) {
        if (p->proto == IPPROTO_TCP) {
            if ((p->flags & PKT_STREAM_EST) == 0) {
                goto end;
            }
            const TcpSession *ssn = p->flow->protoctx;
            bool setting_nopayload = p->flow->alparser &&
                                     AppLayerParserStateIssetFlag(
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

static inline void DetectPrefilterMergeSort(DetectEngineCtx *de_ctx,
                                            DetectEngineThreadCtx *det_ctx)
{
    SigIntId mpm, nonmpm;
    SigIntId *mpm_ptr = det_ctx->pmq.rule_id_array;
    SigIntId *nonmpm_ptr = det_ctx->non_pf_id_array;
    uint32_t m_cnt = det_ctx->pmq.rule_id_array_cnt;
    uint32_t n_cnt = det_ctx->non_pf_id_cnt;
    SigIntId *final_ptr;
    uint32_t final_cnt;
    SigIntId id;
    SigIntId previous_id = (SigIntId)-1;
    Signature **sig_array = de_ctx->sig_array;
    Signature **match_array = det_ctx->match_array;
    Signature *s;

    SCLogDebug("PMQ rule id array count %d", det_ctx->pmq.rule_id_array_cnt);

    /* Load first values. */
    if (likely(m_cnt)) {
        mpm = *mpm_ptr;
    } else {
        /* mpm list is empty */
        final_ptr = nonmpm_ptr;
        final_cnt = n_cnt;
        goto final;
    }
    if (likely(n_cnt)) {
        nonmpm = *nonmpm_ptr;
    } else {
        /* non-mpm list is empty. */
        final_ptr = mpm_ptr;
        final_cnt = m_cnt;
        goto final;
    }
    while (1) {
        if (mpm < nonmpm) {
            /* Take from mpm list */
            id = mpm;

            s = sig_array[id];
            /* As the mpm list can contain duplicates, check for that here. */
            if (likely(id != previous_id)) {
                *match_array++ = s;
                previous_id = id;
            }
            if (unlikely(--m_cnt == 0)) {
                /* mpm list is now empty */
                final_ptr = nonmpm_ptr;
                final_cnt = n_cnt;
                goto final;
             }
             mpm_ptr++;
             mpm = *mpm_ptr;
         } else if (mpm > nonmpm) {
             id = nonmpm;

             s = sig_array[id];
             /* As the mpm list can contain duplicates, check for that here. */
             if (likely(id != previous_id)) {
                 *match_array++ = s;
                 previous_id = id;
             }
             if (unlikely(--n_cnt == 0)) {
                 final_ptr = mpm_ptr;
                 final_cnt = m_cnt;
                 goto final;
             }
             nonmpm_ptr++;
             nonmpm = *nonmpm_ptr;

        } else { /* implied mpm == nonmpm */
            /* special case: if on both lists, it's a negated mpm pattern */

            /* mpm list may have dups, so skip past them here */
            while (--m_cnt != 0) {
                mpm_ptr++;
                mpm = *mpm_ptr;
                if (mpm != nonmpm)
                    break;
            }
            /* if mpm is done, update nonmpm_ptrs and jump to final */
            if (unlikely(m_cnt == 0)) {
                n_cnt--;

                /* mpm list is now empty */
                final_ptr = ++nonmpm_ptr;
                final_cnt = n_cnt;
                goto final;
            }
            /* otherwise, if nonmpm is done jump to final for mpm
             * mpm ptrs already updated */
            if (unlikely(--n_cnt == 0)) {
                final_ptr = mpm_ptr;
                final_cnt = m_cnt;
                goto final;
            }

            /* not at end of the lists, update nonmpm. Mpm already
             * updated in while loop above. */
            nonmpm_ptr++;
            nonmpm = *nonmpm_ptr;
        }
    }

 final: /* Only one list remaining. Just walk that list. */

    while (final_cnt-- > 0) {
        id = *final_ptr++;
        s = sig_array[id];

        /* As the mpm list can contain duplicates, check for that here. */
        if (likely(id != previous_id)) {
            *match_array++ = s;
            previous_id = id;
        }
    }

    det_ctx->match_array_cnt = match_array - det_ctx->match_array;
    DEBUG_VALIDATE_BUG_ON((det_ctx->pmq.rule_id_array_cnt + det_ctx->non_pf_id_cnt) < det_ctx->match_array_cnt);
    PMQ_RESET(&det_ctx->pmq);
}

/** \internal
 *  \brief build non-prefilter list based on the rule group list we've set.
 */
static inline void DetectPrefilterBuildNonPrefilterList(
        DetectEngineThreadCtx *det_ctx, const SignatureMask mask, const AppProto alproto)
{
    for (uint32_t x = 0; x < det_ctx->non_pf_store_cnt; x++) {
        /* only if the mask matches this rule can possibly match,
         * so build the non_mpm array only for match candidates */
        const SignatureMask rule_mask = det_ctx->non_pf_store_ptr[x].mask;
        const AppProto rule_alproto = det_ctx->non_pf_store_ptr[x].alproto;
        if ((rule_mask & mask) == rule_mask &&
                (rule_alproto == 0 || AppProtoEquals(rule_alproto, alproto))) {
            det_ctx->non_pf_id_array[det_ctx->non_pf_id_cnt++] = det_ctx->non_pf_store_ptr[x].id;
        }
    }
}

/** \internal
 *  \brief select non-mpm list
 *  Based on the packet properties, select the non-mpm list to use
 *  \todo move non_pf_store* into scratchpad */
static inline void
DetectPrefilterSetNonPrefilterList(const Packet *p, DetectEngineThreadCtx *det_ctx, DetectRunScratchpad *scratch)
{
    if ((p->proto == IPPROTO_TCP) && PacketIsTCP(p) && (PacketGetTCP(p)->th_flags & TH_SYN)) {
        det_ctx->non_pf_store_ptr = scratch->sgh->non_pf_syn_store_array;
        det_ctx->non_pf_store_cnt = scratch->sgh->non_pf_syn_store_cnt;
    } else {
        det_ctx->non_pf_store_ptr = scratch->sgh->non_pf_other_store_array;
        det_ctx->non_pf_store_cnt = scratch->sgh->non_pf_other_store_cnt;
    }
    SCLogDebug("sgh non_pf ptr %p cnt %u (syn %p/%u, other %p/%u)",
            det_ctx->non_pf_store_ptr, det_ctx->non_pf_store_cnt,
            scratch->sgh->non_pf_syn_store_array, scratch->sgh->non_pf_syn_store_cnt,
            scratch->sgh->non_pf_other_store_array, scratch->sgh->non_pf_other_store_cnt);
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
        if (!(sgh->flags & SIG_GROUP_HEAD_HAVEFILESIZE)) {
            SCLogDebug("requesting disabling filesize for flow");
            flow_file_flags |= (FLOWFILE_NO_SIZE_TS|FLOWFILE_NO_SIZE_TC);
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
        /* set the iponly stuff */
        if (pflow->flags & FLOW_TOCLIENT_IPONLY_SET)
            p->flowflags |= FLOW_PKT_TOCLIENT_IPONLY_SET;
        if (pflow->flags & FLOW_TOSERVER_IPONLY_SET)
            p->flowflags |= FLOW_PKT_TOSERVER_IPONLY_SET;

        if (((p->flowflags & FLOW_PKT_TOSERVER) && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
            ((p->flowflags & FLOW_PKT_TOCLIENT) && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET)))
        {
            SCLogDebug("testing against \"ip-only\" signatures");

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
            IPOnlyMatchPacket(tv, de_ctx, det_ctx, &de_ctx->io_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

            /* save in the flow that we scanned this direction... */
            FlowSetIPOnlyFlag(pflow, p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0);
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
        if (fv == false) {
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
static inline void DetectRunPrefilterPkt(
    ThreadVars *tv,
    DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx,
    Packet *p,
    DetectRunScratchpad *scratch
)
{
    DetectPrefilterSetNonPrefilterList(p, det_ctx, scratch);

    /* create our prefilter mask */
    PacketCreateMask(p, &scratch->pkt_mask, scratch->alproto, scratch->app_decoder_events);

    /* build and prefilter non_pf list against the mask of the packet */
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_NONMPMLIST);
    det_ctx->non_pf_id_cnt = 0;
    if (likely(det_ctx->non_pf_store_cnt > 0)) {
        DetectPrefilterBuildNonPrefilterList(det_ctx, scratch->pkt_mask, scratch->alproto);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_NONMPMLIST);

    /* run the prefilter engines */
    Prefilter(det_ctx, scratch->sgh, p, scratch->flow_flags, scratch->pkt_mask);
    /* create match list if we have non-pf and/or pf */
    if (det_ctx->non_pf_store_cnt || det_ctx->pmq.rule_id_array_cnt) {
#ifdef PROFILING
        if (tv) {
            StatsAddUI64(tv, det_ctx->counter_mpm_list, (uint64_t)det_ctx->pmq.rule_id_array_cnt);
        }
#endif
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT2);
        DetectPrefilterMergeSort(de_ctx, det_ctx);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT2);
    }

#ifdef PROFILING
    if (tv) {
        StatsAddUI64(tv, det_ctx->counter_nonmpm_list,
                             (uint64_t)det_ctx->non_pf_store_cnt);
        /* non mpm sigs after mask prefilter */
        StatsAddUI64(tv, det_ctx->counter_fnonmpm_list,
                             (uint64_t)det_ctx->non_pf_id_cnt);
    }
#endif
}

static inline void DetectRulePacketRules(
    ThreadVars * const tv,
    DetectEngineCtx * const de_ctx,
    DetectEngineThreadCtx * const det_ctx,
    Packet * const p,
    Flow * const pflow,
    const DetectRunScratchpad *scratch
)
{
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

    uint32_t sflags, next_sflags = 0;
    if (match_cnt) {
        next_s = *match_array++;
        next_sflags = next_s->flags;
    }
    while (match_cnt--) {
        RULE_PROFILING_START(p);
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

        SCLogDebug("inspecting signature id %"PRIu32"", s->id);

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
        if ((s->mask & scratch->pkt_mask) != s->mask) {
            SCLogDebug("mask mismatch %x & %x != %x", s->mask, scratch->pkt_mask, s->mask);
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

        if (DetectRunInspectRuleHeader(p, pflow, s, sflags, s_proto_flags) == false) {
            goto next;
        }

        if (DetectEnginePktInspectionRun(tv, det_ctx, s, pflow, p, &alert_flags) == false) {
            goto next;
        }

#ifdef PROFILE_RULES
        smatch = true;
#endif
        DetectRunPostMatch(tv, det_ctx, p, s);

        uint64_t txid = PACKET_ALERT_NOTX;
        if ((alert_flags & PACKET_ALERT_FLAG_STREAM_MATCH) ||
                (s->alproto != ALPROTO_UNKNOWN && pflow->proto == IPPROTO_UDP)) {
            // if there is a stream match (TCP), or
            // a UDP specific app-layer signature,
            // try to use the good tx for the packet direction
            if (pflow->alstate) {
                uint8_t dir =
                        (p->flowflags & FLOW_PKT_TOCLIENT) ? STREAM_TOCLIENT : STREAM_TOSERVER;
                txid = AppLayerParserGetTransactionInspectId(pflow->alparser, dir);
                void *tx_ptr =
                        AppLayerParserGetTx(pflow->proto, pflow->alproto, pflow->alstate, txid);
                AppLayerTxData *txd =
                        tx_ptr ? AppLayerParserGetTxData(pflow->proto, pflow->alproto, tx_ptr)
                               : NULL;
                if (txd && txd->stream_logged < de_ctx->stream_tx_log_limit) {
                    alert_flags |= PACKET_ALERT_FLAG_TX;
                    txd->stream_logged++;
                }
            }
        }
        AlertQueueAppend(det_ctx, s, p, txid, alert_flags);
next:
        DetectVarProcessList(det_ctx, pflow, p);
        DetectReplaceFree(det_ctx);
        RULE_PROFILING_END(det_ctx, s, smatch, p);
        continue;
    }
}

static DetectRunScratchpad DetectRunSetup(
    const DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx,
    Packet * const p, Flow * const pflow)
{
    AppProto alproto = ALPROTO_UNKNOWN;
    uint8_t flow_flags = 0; /* flow/state flags */
    bool app_decoder_events = false;

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_SETUP);

#ifdef UNITTESTS
    p->alerts.cnt = 0;
    p->alerts.discarded = 0;
    p->alerts.suppressed = 0;
#endif
    det_ctx->filestore_cnt = 0;
    det_ctx->base64_decoded_len = 0;
    det_ctx->raw_stream_progress = 0;
    det_ctx->match_array_cnt = 0;

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

        if (p->flags & PKT_STREAM_EOF) {
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
            GenericVarFree(pflow->flowvar);
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

    DetectRunScratchpad pad = { alproto, flow_flags, app_decoder_events, NULL, 0 };
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_SETUP);
    return pad;
}

static inline void DetectRunPostRules(
    ThreadVars *tv,
    DetectEngineCtx *de_ctx,
    DetectEngineThreadCtx *det_ctx,
    Packet * const p,
    Flow * const pflow,
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
        } else if (engine_alproto != ALPROTO_HTTP2) {
            // incompatible engine->alproto with flow alproto
            tx_ptr = NULL;
        }
    } else if (engine_alproto != alproto) {
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
        if (DetectRunInspectRuleHeader(p, f, s, s->flags, s->proto.flags) == false) {
            TRACE_SID_TXS(s->id, tx, "DetectRunInspectRuleHeader() no match");
            return false;
        }
        if (DetectEnginePktInspectionRun(tv, det_ctx, s, f, p, NULL) == false) {
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
        if (!(inspect_flags & BIT_U32(engine->id)) &&
                direction == engine->dir)
        {
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

            /* run callback: but bypass stream callback if we can */
            uint8_t match;
            if (unlikely(engine->stream && can->stream_stored)) {
                match = can->stream_result;
                TRACE_SID_TXS(s->id, tx, "stream skipped, stored result %d used instead", match);
            } else {
                KEYWORD_PROFILING_SET_LIST(det_ctx, engine->sm_list);
                DEBUG_VALIDATE_BUG_ON(engine->v2.Callback == NULL);
                match = engine->v2.Callback(
                        de_ctx, det_ctx, engine, s, f, flow_flags, alstate, tx_ptr, tx->tx_id);
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
        NULL, 0, NULL, NULL, 0, 0, 0, 0, 0,                                                        \
    }

/** \internal
 *  \brief get a DetectTransaction object
 *  \retval struct filled with relevant info or all nulls/0s
 */
static DetectTransaction GetDetectTx(const uint8_t ipproto, const AppProto alproto,
        void *alstate, const uint64_t tx_id, void *tx_ptr, const int tx_end_state,
        const uint8_t flow_flags)
{
    AppLayerTxData *txd = AppLayerParserGetTxData(ipproto, alproto, tx_ptr);
    if (unlikely(txd == NULL)) {
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }
    uint64_t detect_flags =
            (flow_flags & STREAM_TOSERVER) ? txd->detect_flags_ts : txd->detect_flags_tc;
    if (detect_flags & APP_LAYER_TX_INSPECTED_FLAG) {
        SCLogDebug("%"PRIu64" tx already fully inspected for %s. Flags %016"PRIx64,
                tx_id, flow_flags & STREAM_TOSERVER ? "toserver" : "toclient",
                detect_flags);
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }
    if (detect_flags & APP_LAYER_TX_SKIP_INSPECT_FLAG) {
        SCLogDebug("%" PRIu64 " tx should not be inspected in direction %s. Flags %016" PRIx64,
                tx_id, flow_flags & STREAM_TOSERVER ? "toserver" : "toclient", detect_flags);
        DetectTransaction no_tx = NO_TX;
        return no_tx;
    }

    const int tx_progress = AppLayerParserGetStateProgress(ipproto, alproto, tx_ptr, flow_flags);
    const int dir_int = (flow_flags & STREAM_TOSERVER) ? 0 : 1;
    DetectEngineState *tx_de_state = txd->de_state;
    DetectEngineStateDirection *tx_dir_state = tx_de_state ? &tx_de_state->dir_state[dir_int] : NULL;
    uint64_t prefilter_flags = detect_flags & APP_LAYER_TX_PREFILTER_MASK;
    DEBUG_VALIDATE_BUG_ON(prefilter_flags & APP_LAYER_TX_RESERVED_FLAGS);

    DetectTransaction tx = {
                            .tx_ptr = tx_ptr,
                            .tx_id = tx_id,
                            .tx_data_ptr = (struct AppLayerTxData *)txd,
                            .de_state = tx_dir_state,
                            .detect_flags = detect_flags,
                            .prefilter_flags = prefilter_flags,
                            .prefilter_flags_orig = prefilter_flags,
                            .tx_progress = tx_progress,
                            .tx_end_state = tx_end_state,
                           };
    return tx;
}

static inline void StoreDetectFlags(DetectTransaction *tx, const uint8_t flow_flags,
        const uint8_t ipproto, const AppProto alproto, const uint64_t detect_flags)
{
    AppLayerTxData *txd = (AppLayerTxData *)tx->tx_data_ptr;
    if (likely(txd != NULL)) {
        if (flow_flags & STREAM_TOSERVER) {
            txd->detect_flags_ts = detect_flags;
        } else {
            txd->detect_flags_tc = detect_flags;
        }
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
            if (s->num <= s0->id) {
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
        det_ctx->tx_candidates[k].id = s->num;
        det_ctx->tx_candidates[k].flags = NULL;
        det_ctx->tx_candidates[k].stream_reset = 0;
    }
    // Even if k > 0 or j > 0, the loop is over. (Note that j == k now)
    // The remaining elements in tx_candidates up to k were already sorted
    // and come before any other element later in the list
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

    while (1) {
        AppLayerGetTxIterTuple ires = IterFunc(ipproto, alproto, alstate, tx_id_min, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        DetectTransaction tx = GetDetectTx(ipproto, alproto,
                alstate, ires.tx_id, ires.tx_ptr, tx_end_state, flow_flags);
        if (tx.tx_ptr == NULL) {
            SCLogDebug("%p/%"PRIu64" no transaction to inspect",
                    tx.tx_ptr, tx_id_min);

            tx_id_min++; // next (if any) run look for +1
            goto next;
        }
        tx_id_min = tx.tx_id + 1; // next look for cur + 1

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
                const SigIntId id = s->num;
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
        det_ctx->tx_id = tx.tx_id;
        det_ctx->tx_id_set = true;
        det_ctx->p = p;

#ifdef DEBUG
        for (uint32_t i = 0; i < array_idx; i++) {
            RuleMatchCandidateTx *can = &det_ctx->tx_candidates[i];
            const Signature *s = det_ctx->tx_candidates[i].s;
            SCLogDebug("%u: sid %u flags %p", i, s->id, can->flags);
        }
#endif
        /* run rules: inspect the match candidates */
        for (uint32_t i = 0; i < array_idx; i++) {
            RuleMatchCandidateTx *can = &det_ctx->tx_candidates[i];
            const Signature *s = det_ctx->tx_candidates[i].s;
            uint32_t *inspect_flags = det_ctx->tx_candidates[i].flags;

            /* deduplicate: rules_array is sorted, but not deduplicated:
             * both mpm and stored state could give us the same sid.
             * As they are back to back in that case we can check for it
             * here. We select the stored state one as that comes first
             * in the array. */
            while ((i + 1) < array_idx &&
                    det_ctx->tx_candidates[i].s == det_ctx->tx_candidates[i + 1].s) {
                SCLogDebug("%p/%" PRIu64 " inspecting SKIP NEXT: sid %u (%u), flags %08x",
                        tx.tx_ptr, tx.tx_id, s->id, s->num, inspect_flags ? *inspect_flags : 0);
                i++;
            }

            SCLogDebug("%p/%"PRIu64" inspecting: sid %u (%u), flags %08x",
                    tx.tx_ptr, tx.tx_id, s->id, s->num, inspect_flags ? *inspect_flags : 0);

            if (inspect_flags) {
                if (*inspect_flags & (DE_STATE_FLAG_FULL_INSPECT|DE_STATE_FLAG_SIG_CANT_MATCH)) {
                    SCLogDebug("%p/%"PRIu64" inspecting: sid %u (%u), flags %08x ALREADY COMPLETE",
                            tx.tx_ptr, tx.tx_id, s->id, s->num, *inspect_flags);
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

            /* call individual rule inspection */
            RULE_PROFILING_START(p);
            const int r = DetectRunTxInspectRule(tv, de_ctx, det_ctx, p, f, flow_flags,
                    alstate, &tx, s, inspect_flags, can, scratch);
            if (r == 1) {
                /* match */
                DetectRunPostMatch(tv, det_ctx, p, s);

                const uint8_t alert_flags = (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_TX);
                SCLogDebug("%p/%"PRIu64" sig %u (%u) matched", tx.tx_ptr, tx.tx_id, s->id, s->num);
                AlertQueueAppend(det_ctx, s, p, tx.tx_id, alert_flags);
            }
            DetectVarProcessList(det_ctx, p->flow, p);
            RULE_PROFILING_END(det_ctx, s, r, p);
        }

        det_ctx->tx_id = 0;
        det_ctx->tx_id_set = false;
        det_ctx->p = NULL;

        /* see if we have any updated state to store in the tx */

        uint64_t new_detect_flags = 0;
        /* this side of the tx is done */
        if (tx.tx_progress >= tx.tx_end_state) {
            new_detect_flags |= APP_LAYER_TX_INSPECTED_FLAG;
            SCLogDebug("%p/%"PRIu64" tx is done for direction %s. Flag %016"PRIx64,
                    tx.tx_ptr, tx.tx_id,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient",
                    new_detect_flags);
        }
        if (tx.prefilter_flags != tx.prefilter_flags_orig) {
            new_detect_flags |= tx.prefilter_flags;
            DEBUG_VALIDATE_BUG_ON(new_detect_flags & APP_LAYER_TX_RESERVED_FLAGS);
            SCLogDebug("%p/%"PRIu64" updated prefilter flags %016"PRIx64" "
                    "(was: %016"PRIx64") for direction %s. Flag %016"PRIx64,
                    tx.tx_ptr, tx.tx_id, tx.prefilter_flags, tx.prefilter_flags_orig,
                    flow_flags & STREAM_TOSERVER ? "toserver" : "toclient",
                    new_detect_flags);
        }
        if (new_detect_flags != 0 &&
                (new_detect_flags | tx.detect_flags) != tx.detect_flags)
        {
            new_detect_flags |= tx.detect_flags;
            DEBUG_VALIDATE_BUG_ON(new_detect_flags & APP_LAYER_TX_RESERVED_FLAGS);
            SCLogDebug("%p/%"PRIu64" Storing new flags %016"PRIx64" (was %016"PRIx64")",
                    tx.tx_ptr, tx.tx_id, new_detect_flags, tx.detect_flags);

            StoreDetectFlags(&tx, flow_flags, ipproto, alproto, new_detect_flags);
        }
        InspectionBufferClean(det_ctx);

    next:
        if (!ires.has_next)
            break;
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
                const SigIntId id = s->num;
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
                const SigIntId id = s->num;
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
            SCLogDebug("%p/%" PRIi64 " inspecting: sid %u (%u)", frame, frame->id, s->id, s->num);

            /* start new inspection */
            SCLogDebug("%p/%" PRIi64 " Start sid %u", frame, frame->id, s->id);

            /* call individual rule inspection */
            RULE_PROFILING_START(p);
            bool r = DetectRunInspectRuleHeader(p, f, s, s->flags, s->proto.flags);
            if (r == true) {
                r = DetectRunFrameInspectRule(tv, det_ctx, s, f, p, frames, frame);
                if (r == true) {
                    /* match */
                    DetectRunPostMatch(tv, det_ctx, p, s);

                    uint8_t alert_flags = (PACKET_ALERT_FLAG_STATE_MATCH | PACKET_ALERT_FLAG_FRAME);
                    det_ctx->frame_id = frame->id;
                    SCLogDebug(
                            "%p/%" PRIi64 " sig %u (%u) matched", frame, frame->id, s->id, s->num);
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

    if (p->flags & PKT_NOPACKET_INSPECTION) {
        /* hack: if we are in pass the entire flow mode, we need to still
         * update the inspect_id forward. So test for the condition here,
         * and call the update code if necessary. */
        const int pass = ((f->flags & FLOW_NOPACKET_INSPECTION));
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

    /* we check the flow drop here, and not the packet drop. This is
     * to allow stream engine "invalid" drop packets to still be
     * evaluated by the stream event rules. */
    if (f->flags & FLOW_ACTION_DROP) {
        DEBUG_VALIDATE_BUG_ON(!(PKT_IS_PSEUDOPKT(p)) && !PacketCheckAction(p, ACTION_DROP));
        SCReturn;
    }

    /* see if the packet matches one or more of the sigs */
    (void)DetectRun(tv, de_ctx, det_ctx, p);
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
