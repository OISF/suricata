/* Copyright (C) 2007-2017 Open Information Security Foundation
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
#include "conf.h"

#include "decode.h"
#include "flow.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "app-layer-parser.h"

#include "detect.h"
#include "detect-engine.h"
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
#include "detect-engine-filedata.h"


#include "detect-engine-payload.h"
#include "detect-engine-event.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hsbd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-hsmd.h"
#include "detect-engine-hscd.h"
#include "detect-engine-hua.h"
#include "detect-engine-hhhd.h"
#include "detect-engine-hrhhd.h"

#include "detect-filestore.h"
#include "detect-flowvar.h"
#include "detect-replace.h"

#include "util-validate.h"
#include "util-detect.h"

static void SigMatchSignaturesCleanup(DetectEngineThreadCtx *det_ctx,
    Packet *p, Flow *pflow, const bool use_flow_sgh);

int SigMatchSignaturesRunPostMatch(ThreadVars *tv,
                                   DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p,
                                   const Signature *s)
{
    /* run the packet match functions */
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];
    if (smd != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);

        SCLogDebug("running match functions, sm %p", smd);

        while (1) {
            KEYWORD_PROFILING_START;
            (void)sigmatch_table[smd->type].Match(tv, det_ctx, p, s, smd->ctx);
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
            if (smd->is_last)
                break;
            smd++;
        }
    }

    DetectReplaceExecute(p, det_ctx);

    if (s->flags & SIG_FLAG_FILESTORE)
        DetectFilestorePostMatch(tv, det_ctx, p, s);

    return 1;
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

    int f;
    SigGroupHead *sgh = NULL;

    /* if the packet proto is 0 (not set), we're inspecting it against
     * the decoder events sgh we have. */
    if (p->proto == 0 && p->events.cnt > 0) {
        SCReturnPtr(de_ctx->decoder_event_sgh, "SigGroupHead");
    } else if (p->proto == 0) {
        if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
            /* not IP, so nothing to do */
            SCReturnPtr(NULL, "SigGroupHead");
        }
    }

    /* select the flow_gh */
    if (p->flowflags & FLOW_PKT_TOCLIENT)
        f = 0;
    else
        f = 1;

    int proto = IP_GET_IPPROTO(p);
    if (proto == IPPROTO_TCP) {
        DetectPort *list = de_ctx->flow_gh[f].tcp;
        SCLogDebug("tcp toserver %p, tcp toclient %p: going to use %p",
                de_ctx->flow_gh[1].tcp, de_ctx->flow_gh[0].tcp, de_ctx->flow_gh[f].tcp);
        uint16_t port = f ? p->dp : p->sp;
        SCLogDebug("tcp port %u -> %u:%u", port, p->sp, p->dp);
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("TCP list %p, port %u, direction %s, sghport %p, sgh %p",
                list, port, f ? "toserver" : "toclient", sghport, sgh);
    } else if (proto == IPPROTO_UDP) {
        DetectPort *list = de_ctx->flow_gh[f].udp;
        uint16_t port = f ? p->dp : p->sp;
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("UDP list %p, port %u, direction %s, sghport %p, sgh %p",
                list, port, f ? "toserver" : "toclient", sghport, sgh);
    } else {
        sgh = de_ctx->flow_gh[f].sgh[proto];
    }

    SCReturnPtr(sgh, "SigGroupHead");
}

static inline void DetectPrefilterMergeSort(DetectEngineCtx *de_ctx,
                                            DetectEngineThreadCtx *det_ctx)
{
    SigIntId mpm, nonmpm;
    det_ctx->match_array_cnt = 0;
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
             * mpm ptrs alrady updated */
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

    BUG_ON((det_ctx->pmq.rule_id_array_cnt + det_ctx->non_pf_id_cnt) < det_ctx->match_array_cnt);
}

static inline void
DetectPrefilterBuildNonPrefilterList(DetectEngineThreadCtx *det_ctx, SignatureMask mask)
{
    uint32_t x = 0;
    for (x = 0; x < det_ctx->non_pf_store_cnt; x++) {
        /* only if the mask matches this rule can possibly match,
         * so build the non_mpm array only for match candidates */
        SignatureMask rule_mask = det_ctx->non_pf_store_ptr[x].mask;
        if ((rule_mask & mask) == rule_mask) {
            det_ctx->non_pf_id_array[det_ctx->non_pf_id_cnt++] = det_ctx->non_pf_store_ptr[x].id;
        }
    }
}

/** \internal
 *  \brief select non-mpm list
 *  Based on the packet properties, select the non-mpm list to use */
static inline void
DetectPrefilterSetNonPrefilterList(const Packet *p, DetectEngineThreadCtx *det_ctx)
{
    if ((p->proto == IPPROTO_TCP) && (p->tcph != NULL) && (p->tcph->th_flags & TH_SYN)) {
        det_ctx->non_pf_store_ptr = det_ctx->sgh->non_pf_syn_store_array;
        det_ctx->non_pf_store_cnt = det_ctx->sgh->non_pf_syn_store_cnt;
    } else {
        det_ctx->non_pf_store_ptr = det_ctx->sgh->non_pf_other_store_array;
        det_ctx->non_pf_store_cnt = det_ctx->sgh->non_pf_other_store_cnt;
    }
    SCLogDebug("sgh non_pf ptr %p cnt %u (syn %p/%u, other %p/%u)",
            det_ctx->non_pf_store_ptr, det_ctx->non_pf_store_cnt,
            det_ctx->sgh->non_pf_syn_store_array, det_ctx->sgh->non_pf_syn_store_cnt,
            det_ctx->sgh->non_pf_other_store_array, det_ctx->sgh->non_pf_other_store_cnt);
}

/** \internal
 *  \brief update flow's file tracking flags based on the detection engine
 */
static inline void
DetectPostInspectFileFlagsUpdate(Flow *pflow, const SigGroupHead *sgh, uint8_t direction)
{
    /* see if this sgh requires us to consider file storing */
    if (!FileForceFilestore() && (sgh == NULL ||
                sgh->filestore_cnt == 0))
    {
        FileDisableStoring(pflow, direction);
    }
#ifdef HAVE_MAGIC
    /* see if this sgh requires us to consider file magic */
    if (!FileForceMagic() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMAGIC)))
    {
        SCLogDebug("disabling magic for flow");
        FileDisableMagic(pflow, direction);
    }
#endif
    /* see if this sgh requires us to consider file md5 */
    if (!FileForceMd5() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMD5)))
    {
        SCLogDebug("disabling md5 for flow");
        FileDisableMd5(pflow, direction);
    }

    /* see if this sgh requires us to consider file sha1 */
    if (!FileForceSha1() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA1)))
    {
        SCLogDebug("disabling sha1 for flow");
        FileDisableSha1(pflow, direction);
    }

    /* see if this sgh requires us to consider file sha256 */
    if (!FileForceSha256() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA256)))
    {
        SCLogDebug("disabling sha256 for flow");
        FileDisableSha256(pflow, direction);
    }

    /* see if this sgh requires us to consider filesize */
    if (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESIZE))
    {
        SCLogDebug("disabling filesize for flow");
        FileDisableFilesize(pflow, direction);
    }
}

static inline void
DetectPostInspectFirstSGH(const Packet *p, Flow *pflow, const SigGroupHead *sgh)
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

/* returns 0 if no match, 1 if match */
static inline int DetectRunInspectRuleHeader(
    const Packet *p,
    const Flow *f,
    const Signature *s,
    const uint32_t sflags,
    const uint8_t s_proto_flags)
{
    /* check if this signature has a requirement for flowvars of some type
     * and if so, if we actually have any in the flow. If not, the sig
     * can't match and we skip it. */
    if ((p->flags & PKT_HAS_FLOW) && (sflags & SIG_FLAG_REQUIRE_FLOWVAR)) {
        int m  = f->flowvar ? 1 : 0;

        /* no flowvars? skip this sig */
        if (m == 0) {
            SCLogDebug("skipping sig as the flow has no flowvars and sig "
                    "has SIG_FLAG_REQUIRE_FLOWVAR flag set.");
            return 0;
        }
    }

    if ((s_proto_flags & DETECT_PROTO_IPV4) && !PKT_IS_IPV4(p)) {
        SCLogDebug("ip version didn't match");
        return 0;
    }
    if ((s_proto_flags & DETECT_PROTO_IPV6) && !PKT_IS_IPV6(p)) {
        SCLogDebug("ip version didn't match");
        return 0;
    }

    if (DetectProtoContainsProto(&s->proto, IP_GET_IPPROTO(p)) == 0) {
        SCLogDebug("proto didn't match");
        return 0;
    }

    /* check the source & dst port in the sig */
    if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
        if (!(sflags & SIG_FLAG_DP_ANY)) {
            if (p->flags & PKT_IS_FRAGMENT)
                return 0;
            DetectPort *dport = DetectPortLookupGroup(s->dp,p->dp);
            if (dport == NULL) {
                SCLogDebug("dport didn't match.");
                return 0;
            }
        }
        if (!(sflags & SIG_FLAG_SP_ANY)) {
            if (p->flags & PKT_IS_FRAGMENT)
                return 0;
            DetectPort *sport = DetectPortLookupGroup(s->sp,p->sp);
            if (sport == NULL) {
                SCLogDebug("sport didn't match.");
                return 0;
            }
        }
    } else if ((sflags & (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) != (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) {
        SCLogDebug("port-less protocol and sig needs ports");
        return 0;
    }

    /* check the destination address */
    if (!(sflags & SIG_FLAG_DST_ANY)) {
        if (PKT_IS_IPV4(p)) {
            if (DetectAddressMatchIPv4(s->addr_dst_match4, s->addr_dst_match4_cnt, &p->dst) == 0)
                return 0;
        } else if (PKT_IS_IPV6(p)) {
            if (DetectAddressMatchIPv6(s->addr_dst_match6, s->addr_dst_match6_cnt, &p->dst) == 0)
                return 0;
        }
    }
    /* check the source address */
    if (!(sflags & SIG_FLAG_SRC_ANY)) {
        if (PKT_IS_IPV4(p)) {
            if (DetectAddressMatchIPv4(s->addr_src_match4, s->addr_src_match4_cnt, &p->src) == 0)
                return 0;
        } else if (PKT_IS_IPV6(p)) {
            if (DetectAddressMatchIPv6(s->addr_src_match6, s->addr_src_match6_cnt, &p->src) == 0)
                return 0;
        }
    }

    return 1;
}

/**
 *  \brief Signature match function
 */
void SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    bool use_flow_sgh = false;
    uint8_t alert_flags = 0;
    AppProto alproto = ALPROTO_UNKNOWN;
    uint8_t flow_flags = 0; /* flow/state flags */
    const Signature *s = NULL;
    const Signature *next_s = NULL;
    bool app_decoder_events = false;
    bool has_state = false;     /* do we have an alstate to work with? */

    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
#ifdef UNITTESTS
    p->alerts.cnt = 0;
#endif
    det_ctx->ticker++;
    det_ctx->filestore_cnt = 0;
    det_ctx->base64_decoded_len = 0;
    det_ctx->raw_stream_progress = 0;

#ifdef DEBUG
    if (p->flags & PKT_STREAM_ADD) {
        det_ctx->pkt_stream_add_cnt++;
    }
#endif

    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if (p->flags & PKT_NOPACKET_INSPECTION) {
        SCReturn;
    }

    /* Load the Packet's flow early, even though it might not be needed.
     * Mark as a constant pointer, although the flow can change.
     */
    Flow * const pflow = p->flow;

    /* grab the protocol state we will detect on */
    if (p->flags & PKT_HAS_FLOW) {
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

        /* set the iponly stuff */
        if (pflow->flags & FLOW_TOCLIENT_IPONLY_SET)
            p->flowflags |= FLOW_PKT_TOCLIENT_IPONLY_SET;
        if (pflow->flags & FLOW_TOSERVER_IPONLY_SET)
            p->flowflags |= FLOW_PKT_TOSERVER_IPONLY_SET;

        /* Get the stored sgh from the flow (if any). Make sure we're not using
         * the sgh for icmp error packets part of the same stream. */
        if (IP_GET_IPPROTO(p) == pflow->proto) { /* filter out icmp */
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            if ((p->flowflags & FLOW_PKT_TOSERVER) && (pflow->flags & FLOW_SGH_TOSERVER)) {
                det_ctx->sgh = pflow->sgh_toserver;
                SCLogDebug("det_ctx->sgh = pflow->sgh_toserver; => %p", det_ctx->sgh);
                use_flow_sgh = true;
            } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && (pflow->flags & FLOW_SGH_TOCLIENT)) {
                det_ctx->sgh = pflow->sgh_toclient;
                SCLogDebug("det_ctx->sgh = pflow->sgh_toclient; => %p", det_ctx->sgh);
                use_flow_sgh = true;
            }
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
        }

        /* Retrieve the app layer state and protocol and the tcp reassembled
         * stream chunks. */
        if ((p->proto == IPPROTO_TCP && (p->flags & PKT_STREAM_EST)) ||
                (p->proto == IPPROTO_UDP) ||
                (p->proto == IPPROTO_SCTP && (p->flowflags & FLOW_PKT_ESTABLISHED)))
        {
            /* update flow flags with knowledge on disruptions */
            flow_flags = FlowGetDisruptionFlags(pflow, flow_flags);
            has_state = (FlowGetAppState(pflow) != NULL);
            alproto = FlowGetAppProtocol(pflow);
            if (p->proto == IPPROTO_TCP && pflow->protoctx &&
                    StreamReassembleRawHasDataReady(pflow->protoctx, p)) {
                p->flags |= PKT_DETECT_HAS_STREAMDATA;
            }
            SCLogDebug("alstate %s, alproto %u", has_state ? "true" : "false", alproto);
        } else {
            SCLogDebug("packet doesn't have established flag set (proto %d)", p->proto);
        }

        app_decoder_events = AppLayerParserHasDecoderEvents(pflow,
                pflow->alstate,
                pflow->alparser,
                flow_flags);

        if (((p->flowflags & FLOW_PKT_TOSERVER) && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
            ((p->flowflags & FLOW_PKT_TOCLIENT) && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET)))
        {
            SCLogDebug("testing against \"ip-only\" signatures");

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
            IPOnlyMatchPacket(th_v, de_ctx, det_ctx, &de_ctx->io_ctx, &det_ctx->io_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

            /* save in the flow that we scanned this direction... */
            FlowSetIPOnlyFlag(pflow, p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0);

        } else if (((p->flowflags & FLOW_PKT_TOSERVER) &&
                   (pflow->flags & FLOW_TOSERVER_IPONLY_SET)) ||
                   ((p->flowflags & FLOW_PKT_TOCLIENT) &&
                   (pflow->flags & FLOW_TOCLIENT_IPONLY_SET)))
        {
            /* If we have a drop from IP only module,
             * we will drop the rest of the flow packets
             * This will apply only to inline/IPS */
            if (pflow->flags & FLOW_ACTION_DROP)
            {
                alert_flags = PACKET_ALERT_FLAG_DROP_FLOW;
                PACKET_DROP(p);
            }
        }

        if (!(use_flow_sgh)) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
        }

    } else { /* p->flags & PKT_HAS_FLOW */
        /* no flow */

        /* Even without flow we should match the packet src/dst */
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
        IPOnlyMatchPacket(th_v, de_ctx, det_ctx, &de_ctx->io_ctx,
                          &det_ctx->io_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
        det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
    }

    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (det_ctx->sgh == NULL) {
        SCLogDebug("no sgh for this packet, nothing to match against");
        goto end;
    }

    DetectPrefilterSetNonPrefilterList(p, det_ctx);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_CONT);
    /* stateful app layer detection */
    if ((p->flags & PKT_HAS_FLOW) && has_state) {
        memset(det_ctx->de_state_sig_array, 0x00, det_ctx->de_state_sig_array_len);
        int has_inspectable_state = DeStateFlowHasInspectableState(pflow, flow_flags);
        if (has_inspectable_state == 1) {
            /* initialize to 0(DE_STATE_MATCH_HAS_NEW_STATE) */
            DeStateDetectContinueDetection(th_v, de_ctx, det_ctx, p, pflow,
                                           flow_flags, alproto);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_CONT);

    /* create our prefilter mask */
    SignatureMask mask = 0;
    PacketCreateMask(p, &mask, alproto, has_state, app_decoder_events);

    /* build and prefilter non_pf list against the mask of the packet */
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_NONMPMLIST);
    det_ctx->non_pf_id_cnt = 0;
    if (likely(det_ctx->non_pf_store_cnt > 0)) {
        DetectPrefilterBuildNonPrefilterList(det_ctx, mask);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_NONMPMLIST);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PREFILTER);
    /* run the prefilter engines */
    Prefilter(det_ctx, det_ctx->sgh, p, flow_flags, has_state);
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT2);
    DetectPrefilterMergeSort(de_ctx, det_ctx);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT2);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PREFILTER);

#ifdef PROFILING
    if (th_v) {
        StatsAddUI64(th_v, det_ctx->counter_mpm_list,
                             (uint64_t)det_ctx->pmq.rule_id_array_cnt);
        StatsAddUI64(th_v, det_ctx->counter_nonmpm_list,
                             (uint64_t)det_ctx->non_pf_store_cnt);
        /* non mpm sigs after mask prefilter */
        StatsAddUI64(th_v, det_ctx->counter_fnonmpm_list,
                             (uint64_t)det_ctx->non_pf_id_cnt);
    }
#endif

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_RULES);
    /* inspect the sigs against the packet */
    /* Prefetch the next signature. */
    SigIntId match_cnt = det_ctx->match_array_cnt;
#ifdef PROFILING
    if (th_v) {
        StatsAddUI64(th_v, det_ctx->counter_match_list,
                             (uint64_t)match_cnt);
    }
#endif
    Signature **match_array = det_ctx->match_array;

    SGH_PROFILING_RECORD(det_ctx, det_ctx->sgh);
#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
    if (match_cnt >= de_ctx->profile_match_logging_threshold)
        RulesDumpMatchArray(det_ctx, p);
#endif
#endif

    uint32_t sflags, next_sflags = 0;
    if (match_cnt) {
        next_s = *match_array++;
        next_sflags = next_s->flags;
    }
    while (match_cnt--) {
        RULE_PROFILING_START(p);
        bool state_alert = false;
#ifdef PROFILING
        bool smatch = false; /* signature match */
#endif
        s = next_s;
        sflags = next_sflags;
        if (match_cnt) {
            next_s = *match_array++;
            next_sflags = next_s->flags;
        }
        const uint8_t s_proto_flags = s->proto.flags;

        SCLogDebug("inspecting signature id %"PRIu32"", s->id);

        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (det_ctx->de_state_sig_array[s->num] & DE_STATE_MATCH_NO_NEW_STATE)
                goto next;
        } else {
            /* don't run mask check for stateful rules.
             * There we depend on prefilter */
            if ((s->mask & mask) != s->mask) {
                SCLogDebug("mask mismatch %x & %x != %x", s->mask, mask, s->mask);
                goto next;
            }

            if (unlikely(sflags & SIG_FLAG_DSIZE)) {
                if (likely(p->payload_len < s->dsize_low || p->payload_len > s->dsize_high)) {
                    SCLogDebug("kicked out as p->payload_len %u, dsize low %u, hi %u",
                            p->payload_len, s->dsize_low, s->dsize_high);
                    goto next;
                }
            }
        }

        /* if the sig has alproto and the session as well they should match */
        if (likely(sflags & SIG_FLAG_APPLAYER)) {
            if (s->alproto != ALPROTO_UNKNOWN && s->alproto != alproto) {
                if (s->alproto == ALPROTO_DCERPC) {
                    if (alproto != ALPROTO_SMB && alproto != ALPROTO_SMB2) {
                        SCLogDebug("DCERPC sig, alproto not SMB or SMB2");
                        goto next;
                    }
                } else {
                    SCLogDebug("alproto mismatch");
                    goto next;
                }
            }
        }

        if (DetectRunInspectRuleHeader(p, pflow, s, sflags, s_proto_flags) == 0) {
            goto next;
        }

        /* Check the payload keywords. If we are a MPM sig and we've made
         * to here, we've had at least one of the patterns match */
        if (!(sflags & SIG_FLAG_STATE_MATCH) && s->sm_arrays[DETECT_SM_LIST_PMATCH] != NULL) {
            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_PMATCH);
            /* if we have stream msgs, inspect against those first,
             * but not for a "dsize" signature */
            if (sflags & SIG_FLAG_REQUIRE_STREAM) {
                int pmatch = 0;
                if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
                    pmatch = DetectEngineInspectStreamPayload(de_ctx, det_ctx, s, pflow, p);
                    if (pmatch) {
                        det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH;
                        /* Tell the engine that this reassembled stream can drop the
                         * rest of the pkts with no further inspection */
                        if (s->action & ACTION_DROP)
                            alert_flags |= PACKET_ALERT_FLAG_DROP_FLOW;

                        alert_flags |= PACKET_ALERT_FLAG_STREAM_MATCH;
                    }
                }
                /* no match? then inspect packet payload */
                if (pmatch == 0) {
                    SCLogDebug("no match in stream, fall back to packet payload");

                    /* skip if we don't have to inspect the packet and segment was
                     * added to stream */
                    if (!(sflags & SIG_FLAG_REQUIRE_PACKET) && (p->flags & PKT_STREAM_ADD)) {
                        goto next;
                    }

                    if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                        goto next;
                    }
                }
            } else {
                if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                    goto next;
                }
            }
        }

        /* run the packet match functions */
        if (s->sm_arrays[DETECT_SM_LIST_MATCH] != NULL) {
            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_MATCH);
            SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_MATCH];

            SCLogDebug("running match functions, sm %p", smd);
            if (smd != NULL) {
                while (1) {
                    KEYWORD_PROFILING_START;
                    if (sigmatch_table[smd->type].Match(th_v, det_ctx, p, s, smd->ctx) <= 0) {
                        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
                        SCLogDebug("no match");
                        goto next;
                    }
                    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                    if (smd->is_last) {
                        SCLogDebug("match and is_last");
                        break;
                    }
                    smd++;
                }
            }
        }

        /* consider stateful sig matches */
        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (has_state == false) {
                SCLogDebug("state matches but no state, we can't match");
                goto next;
            }

            SCLogDebug("stateful app layer match inspection starting");

            /* if DeStateDetectStartDetection matches, it's a full
             * signature match. It will then call PacketAlertAppend
             * itself, so we can skip it below. This is done so it
             * can store the tx_id with the alert */
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_START);
            state_alert = DeStateDetectStartDetection(th_v, de_ctx, det_ctx, s,
                                                      p, pflow, flow_flags, alproto);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_START);
            if (state_alert == false)
                goto next;

            /* match */
            if (s->action & ACTION_DROP)
                alert_flags |= PACKET_ALERT_FLAG_DROP_FLOW;

            alert_flags |= PACKET_ALERT_FLAG_STATE_MATCH;
        }

#ifdef PROFILING
        smatch = true;
#endif

        SigMatchSignaturesRunPostMatch(th_v, de_ctx, det_ctx, p, s);

        if (!(sflags & SIG_FLAG_NOALERT)) {
            /* stateful sigs call PacketAlertAppend from DeStateDetectStartDetection */
            if (!state_alert)
                PacketAlertAppend(det_ctx, s, p, 0, alert_flags);
        } else {
            /* apply actions even if not alerting */
            DetectSignatureApplyActions(p, s, alert_flags);
        }
next:
        DetectVarProcessList(det_ctx, pflow, p);
        DetectReplaceFree(det_ctx);
        RULE_PROFILING_END(det_ctx, s, smatch, p);

        det_ctx->flags = 0;
        continue;
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_RULES);

end:
    /* see if we need to increment the inspect_id and reset the de_state */
    if (has_state && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_UPDATE);
        DeStateUpdateInspectTransactionId(pflow, flow_flags);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_UPDATE);
    }

    /* so now let's iterate the alerts and remove the ones after a pass rule
     * matched (if any). This is done inside PacketAlertFinalize() */
    /* PR: installed "tag" keywords are handled after the threshold inspection */

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_ALERT);
    PacketAlertFinalize(de_ctx, det_ctx, p);
    if (p->alerts.cnt > 0) {
        StatsAddUI64(th_v, det_ctx->counter_alerts, (uint64_t)p->alerts.cnt);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_ALERT);

    SigMatchSignaturesCleanup(det_ctx, p, pflow, use_flow_sgh);
    SCReturn;
}

/* TODO move use_flow_sgh into det_ctx */
static void SigMatchSignaturesCleanup(DetectEngineThreadCtx *det_ctx,
    Packet *p, Flow * const pflow, const bool use_flow_sgh)
{
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_CLEANUP);
    /* cleanup pkt specific part of the patternmatcher */
    PacketPatternCleanup(det_ctx);

    /* store the found sgh (or NULL) in the flow to save us from looking it
     * up again for the next packet. Also return any stream chunk we processed
     * to the pool. */
    if (pflow != NULL) {
        /* HACK: prevent the wrong sgh (or NULL) from being stored in the
         * flow's sgh pointers */
        if (PKT_IS_ICMPV4(p) && ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            ; /* no-op */

        } else if (!(use_flow_sgh)) {
            DetectPostInspectFirstSGH(p, pflow, det_ctx->sgh);
        }

        /* update inspected tracker for raw reassembly */
        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL) {
            StreamReassembleRawUpdateProgress(pflow->protoctx, p,
                    det_ctx->raw_stream_progress);

            DetectEngineCleanHCBDBuffers(det_ctx);
            DetectEngineCleanHSBDBuffers(det_ctx);
            DetectEngineCleanFiledataBuffers(det_ctx);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_CLEANUP);
    SCReturn;
}

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable */
void DetectSignatureApplyActions(Packet *p,
        const Signature *s, const uint8_t alert_flags)
{
    PACKET_UPDATE_ACTION(p, s->action);

    if (s->action & ACTION_DROP) {
        if (p->alerts.drop.action == 0) {
            p->alerts.drop.num = s->num;
            p->alerts.drop.action = s->action;
            p->alerts.drop.s = (Signature *)s;
        }
    } else if (s->action & ACTION_PASS) {
        /* if an stream/app-layer match we enforce the pass for the flow */
        if ((p->flow != NULL) &&
                (alert_flags & (PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_STREAM_MATCH)))
        {
            FlowSetNoPacketInspectionFlag(p->flow);
        }

    }
}

static DetectEngineThreadCtx *GetTenantById(HashTable *h, uint32_t id)
{
    /* technically we need to pass a DetectEngineThreadCtx struct with the
     * tentant_id member. But as that member is the first in the struct, we
     * can use the id directly. */
    return HashTableLookup(h, &id, 0);
}

static void DetectFlow(ThreadVars *tv,
                       DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                       Packet *p)
{
    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) ||
        (PACKET_TEST_ACTION(p, ACTION_DROP)))
    {
        /* hack: if we are in pass the entire flow mode, we need to still
         * update the inspect_id forward. So test for the condition here,
         * and call the update code if necessary. */
        const int pass = ((p->flow->flags & FLOW_NOPACKET_INSPECTION));
        const AppProto alproto = FlowGetAppProtocol(p->flow);
        if (pass && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
            uint8_t flags;
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                flags = STREAM_TOSERVER;
            } else {
                flags = STREAM_TOCLIENT;
            }
            flags = FlowGetDisruptionFlags(p->flow, flags);
            DeStateUpdateInspectTransactionId(p->flow, flags);
        }
        return;
    }

    /* see if the packet matches one or more of the sigs */
    (void)SigMatchSignatures(tv,de_ctx,det_ctx,p);
}


static void DetectNoFlow(ThreadVars *tv,
                         DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                         Packet *p)
{
    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) ||
        (PACKET_TEST_ACTION(p, ACTION_DROP)))
    {
        return;
    }

    /* see if the packet matches one or more of the sigs */
    (void)SigMatchSignatures(tv,de_ctx,det_ctx,p);
    return;
}

/** \brief Detection engine thread wrapper.
 *  \param tv thread vars
 *  \param p packet to inspect
 *  \param data thread specific data
 *  \param pq packet queue
 *  \retval TM_ECODE_FAILED error
 *  \retval TM_ECODE_OK ok
 */
TmEcode Detect(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
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

/*
 * TESTS
 */

#ifdef UNITTESTS
#include "tests/detect.c"
#endif

