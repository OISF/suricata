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

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine-build.h"
#include "detect-engine-address.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-iponly.h"
#include "detect-engine-mpm.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-port.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-proto.h"
#include "detect-engine-threshold.h"

#include "detect-dsize.h"
#include "detect-tcp-flags.h"
#include "detect-flow.h"
#include "detect-config.h"
#include "detect-flowbits.h"

#include "util-profiling.h"
#include "util-validate.h"
#include "util-var-name.h"

void SigCleanSignatures(DetectEngineCtx *de_ctx)
{
    if (de_ctx == NULL)
        return;

    for (Signature *s = de_ctx->sig_list; s != NULL;) {
        Signature *ns = s->next;
        SigFree(de_ctx, s);
        s = ns;
    }
    de_ctx->sig_list = NULL;

    DetectEngineResetMaxSigId(de_ctx);
    de_ctx->sig_list = NULL;
}

/** \brief Find a specific signature by sid and gid
 *  \param de_ctx detection engine ctx
 *  \param sid the signature id
 *  \param gid the signature group id
 *
 *  \retval s sig found
 *  \retval NULL sig not found
 */
Signature *SigFindSignatureBySidGid(DetectEngineCtx *de_ctx, uint32_t sid, uint32_t gid)
{
    if (de_ctx == NULL)
        return NULL;

    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->id == sid && s->gid == gid)
            return s;
    }

    return NULL;
}

/**
 *  \brief Check if a signature contains the filestore keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilestoring(const Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->flags & SIG_FLAG_FILESTORE)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filemagic keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilemagicInspecting(const Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->file_flags & FILE_SIG_NEED_MAGIC)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filemd5 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileMd5Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_MD5))
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesha1 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileSha1Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_SHA1))
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesha256 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileSha256Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_SHA256))
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesize keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilesizeInspecting(const Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->file_flags & FILE_SIG_NEED_SIZE)
        return 1;

    return 0;
}

/** \brief Test is a initialized signature is IP only
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is ip only
 *  \retval 2 sig is like ip only
 *  \retval 0 sig is not ip only
 */
int SignatureIsIPOnly(DetectEngineCtx *de_ctx, const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN)
        return 0;

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 0;

    // may happen for 'config' keyword, postmatch
    if (s->flags & SIG_FLAG_APPLAYER)
        return 0;

    /* if flow dir is set we can't process it in ip-only */
    if (!(((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == 0) ||
            (s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) ==
            (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)))
        return 0;

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = s->init_data->smlists_array_size;
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectEngineBufferTypeGetNameById(de_ctx, i)))
            continue;

        SCReturnInt(0);
    }

    /* TMATCH list can be ignored, it contains TAGs and
     * tags are compatible to IP-only. */

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; sm != NULL; sm = sm->next) {
        if (!(sigmatch_table[sm->type].flags & SIGMATCH_IPONLY_COMPAT))
            return 0;
        /* we have enabled flowbits to be compatible with ip only sigs, as long
         * as the sig only has a "set" flowbits */
        if (sm->type == DETECT_FLOWBITS &&
                (((DetectFlowbitsData *)sm->ctx)->cmd != DETECT_FLOWBITS_CMD_SET)) {
            return 0;
        }
    }
    sm = s->init_data->smlists[DETECT_SM_LIST_POSTMATCH];
    for ( ; sm != NULL; sm = sm->next) {
        if ( !(sigmatch_table[sm->type].flags & SIGMATCH_IPONLY_COMPAT))
            return 0;
        /* we have enabled flowbits to be compatible with ip only sigs, as long
         * as the sig only has a "set" flowbits */
        if (sm->type == DETECT_FLOWBITS &&
            (((DetectFlowbitsData *)sm->ctx)->cmd != DETECT_FLOWBITS_CMD_SET) ) {
            return 0;
        }
    }

    if (s->init_data->src_contains_negation || s->init_data->dst_contains_negation) {
        /* Rule is IP only, but contains negated addresses. */
        return 2;
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("IP-ONLY (%" PRIu32 "): source %s, dest %s", s->id,
                   s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET",
                   s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    }
    return 1;
}

/** \internal
 *  \brief Test is a initialized signature is inspecting protocol detection only
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is dp only
 *  \retval 0 sig is not dp only
 */
static int SignatureIsPDOnly(const DetectEngineCtx *de_ctx, const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN)
        return 0;

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 0;

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = s->init_data->smlists_array_size;
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectEngineBufferTypeGetNameById(de_ctx, i)))
            continue;

        SCReturnInt(0);
    }

    /* TMATCH list can be ignored, it contains TAGs and
     * tags are compatible to DP-only. */

    /* match list matches may be compatible to DP only. We follow the same
     * logic as IP-only so we can use that flag */

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    if (sm == NULL)
        return 0;

    int pd = 0;
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_AL_APP_LAYER_PROTOCOL) {
            pd = 1;
        } else {
            /* flowbits are supported for dp only sigs, as long
             * as the sig only has a "set" flowbits */
            if (sm->type == DETECT_FLOWBITS) {
                if ((((DetectFlowbitsData *)sm->ctx)->cmd != DETECT_FLOWBITS_CMD_SET) ) {
                    SCLogDebug("%u: not PD-only: flowbit settings other than 'set'", s->id);
                    return 0;
                }
            } else if (sm->type == DETECT_FLOW) {
                if (((DetectFlowData *)sm->ctx)->flags & ~(DETECT_FLOW_FLAG_TOSERVER|DETECT_FLOW_FLAG_TOCLIENT)) {
                    SCLogDebug("%u: not PD-only: flow settings other than toserver/toclient", s->id);
                    return 0;
                }
            } else if ( !(sigmatch_table[sm->type].flags & SIGMATCH_IPONLY_COMPAT)) {
                SCLogDebug("%u: not PD-only: %s not PD/IP-only compat", s->id, sigmatch_table[sm->type].name);
                return 0;
            }
        }
    }

    if (pd) {
        SCLogDebug("PD-ONLY (%" PRIu32 ")", s->id);
    }
    return pd;
}

/**
 *  \internal
 *  \brief Check if the initialized signature is inspecting the packet payload
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is inspecting the payload
 *  \retval 0 sig is not inspecting the payload
 */
static int SignatureIsInspectingPayload(DetectEngineCtx *de_ctx, const Signature *s)
{

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL) {
        return 1;
    }
    return 0;
}

/**
 *  \internal
 *  \brief check if a signature is decoder event matching only
 *  \param de_ctx detection engine
 *  \param s the signature to test
 *  \retval 0 not a DEOnly sig
 *  \retval 1 DEOnly sig
 */
static int SignatureIsDEOnly(DetectEngineCtx *de_ctx, const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN) {
        SCReturnInt(0);
    }

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
    {
        SCReturnInt(0);
    }

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = s->init_data->smlists_array_size;
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectEngineBufferTypeGetNameById(de_ctx, i)))
            continue;

        SCReturnInt(0);
    }

    /* check for conflicting keywords */
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for ( ;sm != NULL; sm = sm->next) {
        if ( !(sigmatch_table[sm->type].flags & SIGMATCH_DEONLY_COMPAT))
            SCReturnInt(0);
    }

    /* need at least one decode event keyword to be considered decode event. */
    sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for ( ;sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_DECODE_EVENT)
            goto deonly;
        if (sm->type == DETECT_ENGINE_EVENT)
            goto deonly;
        if (sm->type == DETECT_STREAM_EVENT)
            goto deonly;
    }

    SCReturnInt(0);

deonly:
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("DE-ONLY (%" PRIu32 "): source %s, dest %s", s->id,
                   s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET",
                   s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    }

    SCReturnInt(1);
}

#define MASK_TCP_INITDEINIT_FLAGS   (TH_SYN|TH_RST|TH_FIN)
#define MASK_TCP_UNUSUAL_FLAGS      (TH_URG|TH_ECN|TH_CWR)

/* Create mask for this packet + it's flow if it has one
 */
void
PacketCreateMask(Packet *p, SignatureMask *mask, AppProto alproto,
        bool app_decoder_events)
{
    if (!(p->flags & PKT_NOPAYLOAD_INSPECTION) && p->payload_len > 0) {
        SCLogDebug("packet has payload");
        (*mask) |= SIG_MASK_REQUIRE_PAYLOAD;
    } else if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
        SCLogDebug("stream data available");
        (*mask) |= SIG_MASK_REQUIRE_PAYLOAD;
    } else {
        SCLogDebug("packet has no payload");
        (*mask) |= SIG_MASK_REQUIRE_NO_PAYLOAD;
    }

    if (p->events.cnt > 0 || app_decoder_events != 0 || p->app_layer_events != NULL) {
        SCLogDebug("packet/flow has events set");
        (*mask) |= SIG_MASK_REQUIRE_ENGINE_EVENT;
    }

    if (!(PKT_IS_PSEUDOPKT(p)) && PKT_IS_TCP(p)) {
        if ((p->tcph->th_flags & MASK_TCP_INITDEINIT_FLAGS) != 0) {
            (*mask) |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
        }
        if ((p->tcph->th_flags & MASK_TCP_UNUSUAL_FLAGS) != 0) {
            (*mask) |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
        }
    }

    if (p->flags & PKT_HAS_FLOW) {
        SCLogDebug("packet has flow");
        (*mask) |= SIG_MASK_REQUIRE_FLOW;
    }

    if (alproto == ALPROTO_SMB || alproto == ALPROTO_DCERPC) {
        SCLogDebug("packet will be inspected for DCERPC");
        (*mask) |= SIG_MASK_REQUIRE_DCERPC;
    }
}

static int g_dce_generic_list_id = -1;
static int g_dce_stub_data_buffer_id = -1;

static bool SignatureNeedsDCERPCMask(const Signature *s)
{
    if (g_dce_generic_list_id == -1) {
        g_dce_generic_list_id = DetectBufferTypeGetByName("dce_generic");
        SCLogDebug("g_dce_generic_list_id %d", g_dce_generic_list_id);
    }
    if (g_dce_stub_data_buffer_id == -1) {
        g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");
        SCLogDebug("g_dce_stub_data_buffer_id %d", g_dce_stub_data_buffer_id);
    }

    if (g_dce_generic_list_id >= 0 &&
            s->init_data->smlists[g_dce_generic_list_id] != NULL)
    {
        return true;
    }
    if (g_dce_stub_data_buffer_id >= 0 &&
            s->init_data->smlists[g_dce_stub_data_buffer_id] != NULL)
    {
        return true;
    }
    return false;
}

static int SignatureCreateMask(Signature *s)
{
    SCEnter();

    if (SignatureNeedsDCERPCMask(s)) {
        s->mask |= SIG_MASK_REQUIRE_DCERPC;
        SCLogDebug("sig requires DCERPC");
    }

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
        SCLogDebug("sig requires payload");
    }

    SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch(sm->type) {
            case DETECT_FLOWBITS:
            {
                /* figure out what flowbit action */
                DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
                if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                    /* not a mask flag, but still set it here */
                    s->flags |= SIG_FLAG_REQUIRE_FLOWVAR;

                    SCLogDebug("SIG_FLAG_REQUIRE_FLOWVAR set as sig has "
                            "flowbit isset option.");
                }

                /* flow is required for any flowbit manipulation */
                s->mask |= SIG_MASK_REQUIRE_FLOW;
                SCLogDebug("sig requires flow to be able to manipulate "
                        "flowbit(s)");
                break;
            }
            case DETECT_FLOWINT:
                /* flow is required for any flowint manipulation */
                s->mask |= SIG_MASK_REQUIRE_FLOW;
                SCLogDebug("sig requires flow to be able to manipulate "
                        "flowint(s)");
                break;
            case DETECT_FLAGS:
            {
                DetectFlagsData *fl = (DetectFlagsData *)sm->ctx;

                if (fl->flags & TH_SYN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_RST) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_FIN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_URG) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                if (fl->flags & TH_ECN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                if (fl->flags & TH_CWR) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                break;
            }
            case DETECT_DSIZE:
            {
                DetectU16Data *ds = (DetectU16Data *)sm->ctx;
                /* LT will include 0, so no payload.
                 * if GT is used in the same rule the
                 * flag will be set anyway. */
                if (ds->mode == DETECT_UINT_RA || ds->mode == DETECT_UINT_GT ||
                        ds->mode == DETECT_UINT_NE || ds->mode == DETECT_UINT_GTE) {

                    s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
                    SCLogDebug("sig requires payload");

                } else if (ds->mode == DETECT_UINT_EQ) {
                    if (ds->arg1 > 0) {
                        s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
                        SCLogDebug("sig requires payload");
                    } else {
                        s->mask |= SIG_MASK_REQUIRE_NO_PAYLOAD;
                        SCLogDebug("sig requires no payload");
                    }
                }
                break;
            }
            case DETECT_AL_APP_LAYER_EVENT:
                s->mask |= SIG_MASK_REQUIRE_ENGINE_EVENT;
                break;
            case DETECT_ENGINE_EVENT:
                s->mask |= SIG_MASK_REQUIRE_ENGINE_EVENT;
                break;
        }
    }

    for (sm = s->init_data->smlists[DETECT_SM_LIST_POSTMATCH]; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_CONFIG: {
                DetectConfigData *fd = (DetectConfigData *)sm->ctx;
                if (fd->scope == CONFIG_SCOPE_FLOW) {
                    s->mask |= SIG_MASK_REQUIRE_FLOW;
                }
                break;
            }
        }
    }

    if (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    if (s->flags & SIG_FLAG_APPLAYER) {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    SCLogDebug("mask %02X", s->mask);
    SCReturnInt(0);
}

static void SigInitStandardMpmFactoryContexts(DetectEngineCtx *de_ctx)
{
    DetectMpmInitializeBuiltinMpms(de_ctx);
}

/** \brief Pure-PCRE or bytetest rule */
static int RuleInspectsPayloadHasNoMpm(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL && s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 1;
    return 0;
}

static int RuleGetMpmPatternSize(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL)
        return -1;
    int mpm_list = s->init_data->mpm_sm_list;
    if (mpm_list < 0)
        return -1;
    const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
    if (cd == NULL)
        return -1;
    return (int)cd->content_len;
}

static int RuleMpmIsNegated(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL)
        return 0;
    int mpm_list = s->init_data->mpm_sm_list;
    if (mpm_list < 0)
        return 0;
    const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
    if (cd == NULL)
        return 0;
    return (cd->flags & DETECT_CONTENT_NEGATED);
}

static json_t *RulesGroupPrintSghStats(const DetectEngineCtx *de_ctx, const SigGroupHead *sgh,
        const int add_rules, const int add_mpm_stats)
{
    uint32_t prefilter_cnt = 0;
    uint32_t mpm_cnt = 0;
    uint32_t nonmpm_cnt = 0;
    uint32_t mpm_depth_cnt = 0;
    uint32_t mpm_endswith_cnt = 0;
    uint32_t negmpm_cnt = 0;
    uint32_t any5_cnt = 0;
    uint32_t payload_no_mpm_cnt = 0;
    uint32_t syn_cnt = 0;

    uint32_t mpms_min = 0;
    uint32_t mpms_max = 0;

    int max_buffer_type_id = DetectBufferTypeMaxId() + 1;

    struct {
        uint32_t total;
        uint32_t cnt;
        uint32_t min;
        uint32_t max;
    } mpm_stats[max_buffer_type_id];
    memset(mpm_stats, 0x00, sizeof(mpm_stats));

    uint32_t alstats[ALPROTO_MAX] = {0};
    uint32_t mpm_sizes[max_buffer_type_id][256];
    memset(mpm_sizes, 0, sizeof(mpm_sizes));
    uint32_t alproto_mpm_bufs[ALPROTO_MAX][max_buffer_type_id];
    memset(alproto_mpm_bufs, 0, sizeof(alproto_mpm_bufs));

    DEBUG_VALIDATE_BUG_ON(sgh->init == NULL);
    if (sgh->init == NULL)
        return NULL;

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    json_object_set_new(js, "id", json_integer(sgh->id));

    json_t *js_array = json_array();

    const Signature *s;
    uint32_t x;
    for (x = 0; x < sgh->init->sig_cnt; x++) {
        s = sgh->init->match_array[x];
        if (s == NULL)
            continue;

        int any = 0;
        if (s->proto.flags & DETECT_PROTO_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_DST_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_SRC_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_DP_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_SP_ANY) {
            any++;
        }
        if (any == 5) {
            any5_cnt++;
        }

        prefilter_cnt += (s->init_data->prefilter_sm != 0);
        if (s->init_data->mpm_sm == NULL) {
            nonmpm_cnt++;

            if (s->sm_arrays[DETECT_SM_LIST_MATCH] != NULL) {
                SCLogDebug("SGH %p Non-MPM inspecting only packets. Rule %u", sgh, s->id);
            }

            DetectPort *sp = s->sp;
            DetectPort *dp = s->dp;

            if (s->flags & SIG_FLAG_TOSERVER && (dp->port == 0 && dp->port2 == 65535)) {
                SCLogDebug("SGH %p Non-MPM toserver and to 'any'. Rule %u", sgh, s->id);
            }
            if (s->flags & SIG_FLAG_TOCLIENT && (sp->port == 0 && sp->port2 == 65535)) {
                SCLogDebug("SGH %p Non-MPM toclient and to 'any'. Rule %u", sgh, s->id);
            }

            if (DetectFlagsSignatureNeedsSynPackets(s)) {
                syn_cnt++;
            }

        } else {
            int mpm_list = s->init_data->mpm_sm_list;
            BUG_ON(mpm_list < 0);
            const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
            uint32_t size = cd->content_len < 256 ? cd->content_len : 255;

            mpm_sizes[mpm_list][size]++;
            alproto_mpm_bufs[s->alproto][mpm_list]++;

            if (mpm_list == DETECT_SM_LIST_PMATCH) {
                if (size == 1) {
                    DetectPort *sp = s->sp;
                    DetectPort *dp = s->dp;
                    if (s->flags & SIG_FLAG_TOSERVER) {
                        if (dp->port == 0 && dp->port2 == 65535) {
                            SCLogDebug("SGH %p toserver 1byte fast_pattern to ANY. Rule %u", sgh, s->id);
                        } else {
                            SCLogDebug("SGH %p toserver 1byte fast_pattern to port(s) %u-%u. Rule %u", sgh, dp->port, dp->port2, s->id);
                        }
                    }
                    if (s->flags & SIG_FLAG_TOCLIENT) {
                        if (sp->port == 0 && sp->port2 == 65535) {
                            SCLogDebug("SGH %p toclient 1byte fast_pattern to ANY. Rule %u", sgh, s->id);
                        } else {
                            SCLogDebug("SGH %p toclient 1byte fast_pattern to port(s) %u-%u. Rule %u", sgh, sp->port, sp->port2, s->id);
                        }
                    }
                }
            }

            uint32_t w = PatternStrength(cd->content, cd->content_len);
            if (mpms_min == 0)
                mpms_min = w;
            if (w < mpms_min)
                mpms_min = w;
            if (w > mpms_max)
                mpms_max = w;

            mpm_stats[mpm_list].total += w;
            mpm_stats[mpm_list].cnt++;
            if (mpm_stats[mpm_list].min == 0 || w < mpm_stats[mpm_list].min)
                mpm_stats[mpm_list].min = w;
            if (w > mpm_stats[mpm_list].max)
                mpm_stats[mpm_list].max = w;

            mpm_cnt++;

            if (w < 10) {
                SCLogDebug("SGH %p Weak MPM Pattern on %s. Rule %u", sgh, DetectListToString(mpm_list), s->id);
            }
            if (w < 10 && any == 5) {
                SCLogDebug("SGH %p Weak MPM Pattern on %s, rule is 5xAny. Rule %u", sgh, DetectListToString(mpm_list), s->id);
            }

            if (cd->flags & DETECT_CONTENT_NEGATED) {
                SCLogDebug("SGH %p MPM Pattern on %s, is negated. Rule %u", sgh, DetectListToString(mpm_list), s->id);
                negmpm_cnt++;
            }
            if (cd->flags & DETECT_CONTENT_ENDS_WITH) {
                mpm_endswith_cnt++;
            }
            if (cd->flags & DETECT_CONTENT_DEPTH) {
                mpm_depth_cnt++;
            }
        }

        if (RuleInspectsPayloadHasNoMpm(s)) {
            SCLogDebug("SGH %p No MPM. Payload inspecting. Rule %u", sgh, s->id);
            payload_no_mpm_cnt++;
        }

        alstats[s->alproto]++;

        if (add_rules) {
            json_t *js_sig = json_object();
            if (unlikely(js == NULL))
                continue;
            json_object_set_new(js_sig, "sig_id", json_integer(s->id));
            json_array_append_new(js_array, js_sig);
        }
    }

    json_object_set_new(js, "rules", js_array);

    json_t *stats = json_object();
    json_object_set_new(stats, "total", json_integer(sgh->init->sig_cnt));

    json_t *types = json_object();
    json_object_set_new(types, "mpm", json_integer(mpm_cnt));
    json_object_set_new(types, "non_mpm", json_integer(nonmpm_cnt));
    json_object_set_new(types, "mpm_depth", json_integer(mpm_depth_cnt));
    json_object_set_new(types, "mpm_endswith", json_integer(mpm_endswith_cnt));
    json_object_set_new(types, "negated_mpm", json_integer(negmpm_cnt));
    json_object_set_new(types, "payload_but_no_mpm", json_integer(payload_no_mpm_cnt));
    json_object_set_new(types, "prefilter", json_integer(prefilter_cnt));
    json_object_set_new(types, "syn", json_integer(syn_cnt));
    json_object_set_new(types, "any5", json_integer(any5_cnt));
    json_object_set_new(stats, "types", types);

    for (AppProto i = 0; i < ALPROTO_MAX; i++) {
        if (alstats[i] > 0) {
            json_t *app = json_object();
            json_object_set_new(app, "total", json_integer(alstats[i]));

            for (int y = 0; y < max_buffer_type_id; y++) {
                if (alproto_mpm_bufs[i][y] == 0)
                    continue;

                const char *name;
                if (y < DETECT_SM_LIST_DYNAMIC_START)
                    name = DetectListToHumanString(y);
                else
                    name = DetectEngineBufferTypeGetNameById(de_ctx, y);

                json_object_set_new(app, name, json_integer(alproto_mpm_bufs[i][y]));
            }

            const char *proto_name = (i == ALPROTO_UNKNOWN) ? "payload" : AppProtoToString(i);
            json_object_set_new(stats, proto_name, app);
        }
    }

    if (add_mpm_stats) {
        json_t *mpm_js = json_object();

        for (int i = 0; i < max_buffer_type_id; i++) {
            if (mpm_stats[i].cnt > 0) {

                json_t *mpm_sizes_array = json_array();
                for (int y = 0; y < 256; y++) {
                    if (mpm_sizes[i][y] == 0)
                        continue;

                    json_t *e = json_object();
                    json_object_set_new(e, "size", json_integer(y));
                    json_object_set_new(e, "count", json_integer(mpm_sizes[i][y]));
                    json_array_append_new(mpm_sizes_array, e);
                }

                json_t *buf = json_object();
                json_object_set_new(buf, "total", json_integer(mpm_stats[i].cnt));
                json_object_set_new(buf, "avg_strength", json_integer(mpm_stats[i].total / mpm_stats[i].cnt));
                json_object_set_new(buf, "min_strength", json_integer(mpm_stats[i].min));
                json_object_set_new(buf, "max_strength", json_integer(mpm_stats[i].max));

                json_object_set_new(buf, "sizes", mpm_sizes_array);

                const char *name;
                if (i < DETECT_SM_LIST_DYNAMIC_START)
                    name = DetectListToHumanString(i);
                else
                    name = DetectEngineBufferTypeGetNameById(de_ctx, i);

                json_object_set_new(mpm_js, name, buf);
            }
        }

        json_object_set_new(stats, "mpm", mpm_js);
    }
    json_object_set_new(js, "stats", stats);

    json_object_set_new(js, "whitelist", json_integer(sgh->init->whitelist));

    return js;
}

static void RulesDumpGrouping(const DetectEngineCtx *de_ctx,
                       const int add_rules, const int add_mpm_stats)
{
    json_t *js = json_object();
    if (unlikely(js == NULL))
        return;

    int p;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP) {
            const char *name = (p == IPPROTO_TCP) ? "tcp" : "udp";

            json_t *tcp = json_object();

            json_t *ts_array = json_array();
            DetectPort *list = (p == IPPROTO_TCP) ? de_ctx->flow_gh[1].tcp :
                                                    de_ctx->flow_gh[1].udp;
            while (list != NULL) {
                json_t *port = json_object();
                json_object_set_new(port, "port", json_integer(list->port));
                json_object_set_new(port, "port2", json_integer(list->port2));

                json_t *tcp_ts =
                        RulesGroupPrintSghStats(de_ctx, list->sh, add_rules, add_mpm_stats);
                json_object_set_new(port, "rulegroup", tcp_ts);
                json_array_append_new(ts_array, port);

                list = list->next;
            }
            json_object_set_new(tcp, "toserver", ts_array);

            json_t *tc_array = json_array();
            list = (p == IPPROTO_TCP) ? de_ctx->flow_gh[0].tcp :
                                        de_ctx->flow_gh[0].udp;
            while (list != NULL) {
                json_t *port = json_object();
                json_object_set_new(port, "port", json_integer(list->port));
                json_object_set_new(port, "port2", json_integer(list->port2));

                json_t *tcp_tc =
                        RulesGroupPrintSghStats(de_ctx, list->sh, add_rules, add_mpm_stats);
                json_object_set_new(port, "rulegroup", tcp_tc);
                json_array_append_new(tc_array, port);

                list = list->next;
            }
            json_object_set_new(tcp, "toclient", tc_array);

            json_object_set_new(js, name, tcp);
        } else if (p == IPPROTO_ICMP || p == IPPROTO_ICMPV6) {
            const char *name = (p == IPPROTO_ICMP) ? "icmpv4" : "icmpv6";
            json_t *o = json_object();
            if (de_ctx->flow_gh[1].sgh[p]) {
                json_t *ts = json_object();
                json_t *group_ts = RulesGroupPrintSghStats(
                        de_ctx, de_ctx->flow_gh[1].sgh[p], add_rules, add_mpm_stats);
                json_object_set_new(ts, "rulegroup", group_ts);
                json_object_set_new(o, "toserver", ts);
            }
            if (de_ctx->flow_gh[0].sgh[p]) {
                json_t *tc = json_object();
                json_t *group_tc = RulesGroupPrintSghStats(
                        de_ctx, de_ctx->flow_gh[0].sgh[p], add_rules, add_mpm_stats);
                json_object_set_new(tc, "rulegroup", group_tc);
                json_object_set_new(o, "toclient", tc);
            }
            json_object_set_new(js, name, o);
        }
    }

    const char *filename = "rule_group.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";

    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    FILE *fp = fopen(log_path, "w");
    if (fp == NULL) {
        return;
    }

    char *js_s = json_dumps(js,
                            JSON_PRESERVE_ORDER|JSON_ESCAPE_SLASH);
    if (unlikely(js_s == NULL)) {
        fclose(fp);
        return;
    }

    json_object_clear(js);
    json_decref(js);

    fprintf(fp, "%s\n", js_s);
    free(js_s);
    fclose(fp);
    return;
}

static int RulesGroupByProto(DetectEngineCtx *de_ctx)
{
    Signature *s = de_ctx->sig_list;

    uint32_t max_idx = 0;
    SigGroupHead *sgh_ts[256] = {NULL};
    SigGroupHead *sgh_tc[256] = {NULL};

    for ( ; s != NULL; s = s->next) {
        if (s->flags & SIG_FLAG_IPONLY)
            continue;

        int p;
        for (p = 0; p < 256; p++) {
            if (p == IPPROTO_TCP || p == IPPROTO_UDP) {
                continue;
            }
            if (!(s->proto.proto[p / 8] & (1<<(p % 8)) || (s->proto.flags & DETECT_PROTO_ANY))) {
                continue;
            }

            if (s->flags & SIG_FLAG_TOCLIENT) {
                SigGroupHeadAppendSig(de_ctx, &sgh_tc[p], s);
                max_idx = s->num;
            }
            if (s->flags & SIG_FLAG_TOSERVER) {
                SigGroupHeadAppendSig(de_ctx, &sgh_ts[p], s);
                max_idx = s->num;
            }
        }
    }
    SCLogDebug("max_idx %u", max_idx);

    /* lets look at deduplicating this list */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadHashInit(de_ctx);

    uint32_t cnt = 0;
    uint32_t own = 0;
    uint32_t ref = 0;
    int p;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;
        if (sgh_ts[p] == NULL)
            continue;

        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, sgh_ts[p]);
        if (lookup_sgh == NULL) {
            SCLogDebug("proto group %d sgh %p is the original", p, sgh_ts[p]);

            SigGroupHeadSetSigCnt(sgh_ts[p], max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, sgh_ts[p], max_idx);

            SigGroupHeadHashAdd(de_ctx, sgh_ts[p]);
            SigGroupHeadStore(de_ctx, sgh_ts[p]);

            de_ctx->gh_unique++;
            own++;
        } else {
            SCLogDebug("proto group %d sgh %p is a copy", p, sgh_ts[p]);

            SigGroupHeadFree(de_ctx, sgh_ts[p]);
            sgh_ts[p] = lookup_sgh;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
    SCLogPerf("OTHER %s: %u proto groups, %u unique SGH's, %u copies",
            "toserver", cnt, own, ref);

    cnt = 0;
    own = 0;
    ref = 0;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;
        if (sgh_tc[p] == NULL)
            continue;

        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, sgh_tc[p]);
        if (lookup_sgh == NULL) {
            SCLogDebug("proto group %d sgh %p is the original", p, sgh_tc[p]);

            SigGroupHeadSetSigCnt(sgh_tc[p], max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, sgh_tc[p], max_idx);

            SigGroupHeadHashAdd(de_ctx, sgh_tc[p]);
            SigGroupHeadStore(de_ctx, sgh_tc[p]);

            de_ctx->gh_unique++;
            own++;

        } else {
            SCLogDebug("proto group %d sgh %p is a copy", p, sgh_tc[p]);

            SigGroupHeadFree(de_ctx, sgh_tc[p]);
            sgh_tc[p] = lookup_sgh;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
    SCLogPerf("OTHER %s: %u proto groups, %u unique SGH's, %u copies",
            "toclient", cnt, own, ref);

    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;

        de_ctx->flow_gh[0].sgh[p] = sgh_tc[p];
        de_ctx->flow_gh[1].sgh[p] = sgh_ts[p];
    }

    return 0;
}

static int PortIsWhitelisted(const DetectEngineCtx *de_ctx,
                             const DetectPort *a, int ipproto)
{
    DetectPort *w = de_ctx->tcp_whitelist;
    if (ipproto == IPPROTO_UDP)
        w = de_ctx->udp_whitelist;

    while (w) {
        if (a->port >= w->port && a->port2 <= w->port) {
            SCLogDebug("port group %u:%u whitelisted -> %d", a->port, a->port2, w->port);
            return 1;
        }
        w = w->next;
    }

    return 0;
}

static int RuleSetWhitelist(Signature *s)
{
    DetectPort *p = NULL;
    if (s->flags & SIG_FLAG_TOSERVER)
        p = s->dp;
    else if (s->flags & SIG_FLAG_TOCLIENT)
        p = s->sp;
    else
        return 0;

    /* for sigs that don't use 'any' as port, see if we want to
     * whitelist poor sigs */
    int wl = 0;
    if (!(p->port == 0 && p->port2 == 65535)) {
        /* pure pcre, bytetest, etc rules */
        if (RuleInspectsPayloadHasNoMpm(s)) {
            SCLogDebug("Rule %u MPM has 1 byte fast_pattern. Whitelisting SGH's.", s->id);
            wl = 99;

        } else if (RuleMpmIsNegated(s)) {
            SCLogDebug("Rule %u MPM is negated. Whitelisting SGH's.", s->id);
            wl = 77;

            /* one byte pattern in packet/stream payloads */
        } else if (s->init_data->mpm_sm != NULL &&
                   s->init_data->mpm_sm_list == DETECT_SM_LIST_PMATCH &&
                   RuleGetMpmPatternSize(s) == 1) {
            SCLogDebug("Rule %u No MPM. Payload inspecting. Whitelisting SGH's.", s->id);
            wl = 55;

        } else if (DetectFlagsSignatureNeedsSynPackets(s) &&
                   DetectFlagsSignatureNeedsSynOnlyPackets(s)) {
            SCLogDebug("Rule %u Needs SYN, so inspected often. Whitelisting SGH's.", s->id);
            wl = 33;
        }
    }

    s->init_data->whitelist = wl;
    return wl;
}

int CreateGroupedPortList(DetectEngineCtx *de_ctx, DetectPort *port_list, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx);
int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b);

static DetectPort *RulesGroupByPorts(DetectEngineCtx *de_ctx, uint8_t ipproto, uint32_t direction)
{
    /* step 1: create a hash of 'DetectPort' objects based on all the
     *         rules. Each object will have a SGH with the sigs added
     *         that belong to the SGH. */
    DetectPortHashInit(de_ctx);

    uint32_t max_idx = 0;
    const Signature *s = de_ctx->sig_list;
    DetectPort *list = NULL;
    while (s) {
        /* IP Only rules are handled separately */
        if (s->flags & SIG_FLAG_IPONLY)
            goto next;
        if (!(s->proto.proto[ipproto / 8] & (1<<(ipproto % 8)) || (s->proto.flags & DETECT_PROTO_ANY)))
            goto next;
        if (direction == SIG_FLAG_TOSERVER) {
            if (!(s->flags & SIG_FLAG_TOSERVER))
                goto next;
        } else if (direction == SIG_FLAG_TOCLIENT) {
            if (!(s->flags & SIG_FLAG_TOCLIENT))
                goto next;
        }

        DetectPort *p = NULL;
        if (direction == SIG_FLAG_TOSERVER)
            p = s->dp;
        else if (direction == SIG_FLAG_TOCLIENT)
            p = s->sp;
        else
            BUG_ON(1);

        /* see if we want to exclude directionless sigs that really care only for
         * to_server syn scans/floods */
        if ((direction == SIG_FLAG_TOCLIENT) &&
             DetectFlagsSignatureNeedsSynPackets(s) &&
             DetectFlagsSignatureNeedsSynOnlyPackets(s) &&
            ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) &&
            (!(s->dp->port == 0 && s->dp->port2 == 65535)))
        {
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: SYN-only to port(s) %u:%u "
                    "w/o direction specified, disabling for toclient direction",
                    s->id, s->dp->port, s->dp->port2);
            goto next;
        }

        int wl = s->init_data->whitelist;
        while (p) {
            int pwl = PortIsWhitelisted(de_ctx, p, ipproto) ? 111 : 0;
            pwl = MAX(wl,pwl);

            DetectPort *lookup = DetectPortHashLookup(de_ctx, p);
            if (lookup) {
                SigGroupHeadAppendSig(de_ctx, &lookup->sh, s);
                lookup->sh->init->whitelist = MAX(lookup->sh->init->whitelist, pwl);
            } else {
                DetectPort *tmp2 = DetectPortCopySingle(de_ctx, p);
                BUG_ON(tmp2 == NULL);
                SigGroupHeadAppendSig(de_ctx, &tmp2->sh, s);
                tmp2->sh->init->whitelist = pwl;
                DetectPortHashAdd(de_ctx, tmp2);
            }

            p = p->next;
        }
        max_idx = s->num;
    next:
        s = s->next;
    }

    /* step 2: create a list of DetectPort objects */
    HashListTableBucket *htb = NULL;
    for (htb = HashListTableGetListHead(de_ctx->dport_hash_table);
            htb != NULL;
            htb = HashListTableGetListNext(htb))
    {
        DetectPort *p = HashListTableGetListData(htb);
        DetectPort *tmp = DetectPortCopySingle(de_ctx, p);
        BUG_ON(tmp == NULL);
        int r = DetectPortInsert(de_ctx, &list , tmp);
        BUG_ON(r == -1);
    }
    DetectPortHashFree(de_ctx);
    de_ctx->dport_hash_table = NULL;

    SCLogDebug("rules analyzed");

    /* step 3: group the list and shrink it if necessary */
    DetectPort *newlist = NULL;
    uint16_t groupmax = (direction == SIG_FLAG_TOCLIENT) ? de_ctx->max_uniq_toclient_groups :
                                                           de_ctx->max_uniq_toserver_groups;
    CreateGroupedPortList(de_ctx, list, &newlist, groupmax, CreateGroupedPortListCmpCnt, max_idx);
    list = newlist;

    /* step 4: deduplicate the SGH's */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadHashInit(de_ctx);

    uint32_t cnt = 0;
    uint32_t own = 0;
    uint32_t ref = 0;
    DetectPort *iter;
    for (iter = list ; iter != NULL; iter = iter->next) {
        BUG_ON (iter->sh == NULL);
        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, iter->sh);
        if (lookup_sgh == NULL) {
            SCLogDebug("port group %p sgh %p is the original", iter, iter->sh);

            SigGroupHeadSetSigCnt(iter->sh, max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, iter->sh, max_idx);
            SigGroupHeadSetProtoAndDirection(iter->sh, ipproto, direction);
            SigGroupHeadHashAdd(de_ctx, iter->sh);
            SigGroupHeadStore(de_ctx, iter->sh);
            iter->flags |= PORT_SIGGROUPHEAD_COPY;
            de_ctx->gh_unique++;
            own++;
        } else {
            SCLogDebug("port group %p sgh %p is a copy", iter, iter->sh);

            SigGroupHeadFree(de_ctx, iter->sh);
            iter->sh = lookup_sgh;
            iter->flags |= PORT_SIGGROUPHEAD_COPY;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
#if 0
    for (iter = list ; iter != NULL; iter = iter->next) {
        SCLogInfo("PORT %u-%u %p (sgh=%s, whitelisted=%s/%d)",
                iter->port, iter->port2, iter->sh,
                iter->flags & PORT_SIGGROUPHEAD_COPY ? "ref" : "own",
                iter->sh->init->whitelist ? "true" : "false",
                iter->sh->init->whitelist);
    }
#endif
    SCLogPerf("%s %s: %u port groups, %u unique SGH's, %u copies",
            ipproto == 6 ? "TCP" : "UDP",
            direction == SIG_FLAG_TOSERVER ? "toserver" : "toclient",
            cnt, own, ref);
    return list;
}

void SignatureSetType(DetectEngineCtx *de_ctx, Signature *s)
{
    int iponly = 0;

    /* see if the sig is dp only */
    if (SignatureIsPDOnly(de_ctx, s) == 1) {
        s->flags |= SIG_FLAG_PDONLY;

    /* see if the sig is ip only */
    } else if ((iponly = SignatureIsIPOnly(de_ctx, s)) > 0) {
        if (iponly == 1) {
            s->flags |= SIG_FLAG_IPONLY;
        } else if (iponly == 2) {
            s->flags |= SIG_FLAG_LIKE_IPONLY;
        }
    } else if (SignatureIsDEOnly(de_ctx, s) == 1) {
        s->init_data->init_flags |= SIG_FLAG_INIT_DEONLY;
    }
}

/**
 * \brief Preprocess signature, classify ip-only, etc, build sig array
 *
 * \param de_ctx Pointer to the Detection Engine Context
 *
 * \retval  0 on success
 * \retval -1 on failure
 */
int SigAddressPrepareStage1(DetectEngineCtx *de_ctx)
{
    uint32_t cnt_iponly = 0;
    uint32_t cnt_payload = 0;
    uint32_t cnt_applayer = 0;
    uint32_t cnt_deonly = 0;

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("building signature grouping structure, stage 1: "
                   "preprocessing rules...");
    }

    de_ctx->sig_array_len = DetectEngineGetMaxSigId(de_ctx);
    de_ctx->sig_array_size = (de_ctx->sig_array_len * sizeof(Signature *));
    de_ctx->sig_array = (Signature **)SCMalloc(de_ctx->sig_array_size);
    if (de_ctx->sig_array == NULL)
        goto error;
    memset(de_ctx->sig_array,0,de_ctx->sig_array_size);

    SCLogDebug("signature lookup array: %" PRIu32 " sigs, %" PRIu32 " bytes",
               de_ctx->sig_array_len, de_ctx->sig_array_size);

    /* now for every rule add the source group */
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        de_ctx->sig_array[s->num] = s;

        SCLogDebug("Signature %" PRIu32 ", internal id %" PRIu32 ", ptrs %p %p ", s->id, s->num, s, de_ctx->sig_array[s->num]);

        if (s->flags & SIG_FLAG_PDONLY) {
            SCLogDebug("Signature %"PRIu32" is considered \"PD only\"", s->id);
        } else if (s->flags & SIG_FLAG_IPONLY) {
            SCLogDebug("Signature %"PRIu32" is considered \"IP only\"", s->id);
            cnt_iponly++;
        } else if (SignatureIsInspectingPayload(de_ctx, s) == 1) {
            SCLogDebug("Signature %"PRIu32" is considered \"Payload inspecting\"", s->id);
            cnt_payload++;
        } else if (s->init_data->init_flags & SIG_FLAG_INIT_DEONLY) {
            SCLogDebug("Signature %"PRIu32" is considered \"Decoder Event only\"", s->id);
            cnt_deonly++;
        } else if (s->flags & SIG_FLAG_APPLAYER) {
            SCLogDebug("Signature %"PRIu32" is considered \"Applayer inspecting\"", s->id);
            cnt_applayer++;
        }

#ifdef DEBUG
        if (SCLogDebugEnabled()) {
            uint16_t colen = 0;
            char copresent = 0;
            SigMatch *sm;
            DetectContentData *co;
            for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
                if (sm->type != DETECT_CONTENT)
                    continue;

                copresent = 1;
                co = (DetectContentData *)sm->ctx;
                if (co->content_len > colen)
                    colen = co->content_len;
            }

            if (copresent && colen == 1) {
                SCLogDebug("signature %8u content maxlen 1", s->id);
                for (int proto = 0; proto < 256; proto++) {
                    if (s->proto.proto[(proto/8)] & (1<<(proto%8)))
                        SCLogDebug("=> proto %" PRId32 "", proto);
                }
            }
        }
#endif /* DEBUG */

        if (RuleMpmIsNegated(s)) {
            s->flags |= SIG_FLAG_MPM_NEG;
        }

        SignatureCreateMask(s);
        DetectContentPropagateLimits(s);
        SigParseApplyDsizeToContent(s);

        RuleSetWhitelist(s);

        /* if keyword engines are enabled in the config, handle them here */
        if (de_ctx->prefilter_setting == DETECT_PREFILTER_AUTO &&
                !(s->flags & SIG_FLAG_PREFILTER))
        {
            int prefilter_list = DETECT_TBLSIZE;

            /* get the keyword supporting prefilter with the lowest type */
            for (int i = 0; i < (int)s->init_data->smlists_array_size; i++) {
                SigMatch *sm = s->init_data->smlists[i];
                while (sm != NULL) {
                    if (sigmatch_table[sm->type].SupportsPrefilter != NULL) {
                        if (sigmatch_table[sm->type].SupportsPrefilter(s)) {
                            prefilter_list = MIN(prefilter_list, sm->type);
                        }
                    }
                    sm = sm->next;
                }
            }

            /* apply that keyword as prefilter */
            if (prefilter_list != DETECT_TBLSIZE) {
                for (int i = 0; i < (int)s->init_data->smlists_array_size; i++) {
                    SigMatch *sm = s->init_data->smlists[i];
                    while (sm != NULL) {
                        if (sm->type == prefilter_list) {
                            s->init_data->prefilter_sm = sm;
                            s->flags |= SIG_FLAG_PREFILTER;
                            SCLogConfig("sid %u: prefilter is on \"%s\"", s->id, sigmatch_table[sm->type].name);
                            break;
                        }
                        sm = sm->next;
                    }
                }
            }
        }

        /* run buffer type callbacks if any */
        for (int x = 0; x < (int)s->init_data->smlists_array_size; x++) {
            if (s->init_data->smlists[x])
                DetectEngineBufferRunSetupCallback(de_ctx, x, s);
        }

        de_ctx->sig_cnt++;
    }

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("%" PRIu32 " signatures processed. %" PRIu32 " are IP-only "
                "rules, %" PRIu32 " are inspecting packet payload, %"PRIu32
                " inspect application layer, %"PRIu32" are decoder event only",
                de_ctx->sig_cnt, cnt_iponly, cnt_payload, cnt_applayer,
                cnt_deonly);

        SCLogConfig("building signature grouping structure, stage 1: "
               "preprocessing rules... complete");
    }

    if (DetectFlowbitsAnalyze(de_ctx) != 0)
        goto error;

    return 0;

error:
    return -1;
}

static int PortGroupWhitelist(const DetectPort *a)
{
    return a->sh->init->whitelist;
}

int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b)
{
    if (PortGroupWhitelist(a) && !PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)", a->port, a->port2,
                a->sh->init->sig_cnt, PortGroupWhitelist(a), b->port, b->port2,
                b->sh->init->sig_cnt, PortGroupWhitelist(b));
        return 1;
    } else if (!PortGroupWhitelist(a) && PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) loses against %u:%u (cnt %u, wl %d)", a->port, a->port2,
                a->sh->init->sig_cnt, PortGroupWhitelist(a), b->port, b->port2,
                b->sh->init->sig_cnt, PortGroupWhitelist(b));
        return 0;
    } else if (PortGroupWhitelist(a) > PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)", a->port, a->port2,
                a->sh->init->sig_cnt, PortGroupWhitelist(a), b->port, b->port2,
                b->sh->init->sig_cnt, PortGroupWhitelist(b));
        return 1;
    } else if (PortGroupWhitelist(a) == PortGroupWhitelist(b)) {
        if (a->sh->init->sig_cnt > b->sh->init->sig_cnt) {
            SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)", a->port,
                    a->port2, a->sh->init->sig_cnt, PortGroupWhitelist(a), b->port, b->port2,
                    b->sh->init->sig_cnt, PortGroupWhitelist(b));
            return 1;
        }
    }

    SCLogDebug("%u:%u (cnt %u, wl %d) loses against %u:%u (cnt %u, wl %d)", a->port, a->port2,
            a->sh->init->sig_cnt, PortGroupWhitelist(a), b->port, b->port2, b->sh->init->sig_cnt,
            PortGroupWhitelist(b));
    return 0;
}

/** \internal
 *  \brief Create a list of DetectPort objects sorted based on CompareFunc's
 *         logic.
 *
 *  List can limit the number of groups. In this case an extra "join" group
 *  is created that contains the sigs belonging to that. It's *appended* to
 *  the list, meaning that if the list is walked linearly it's found last.
 *  The joingr is meant to be a catch all.
 *
 */
int CreateGroupedPortList(DetectEngineCtx *de_ctx, DetectPort *port_list, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx)
{
    DetectPort *tmplist = NULL, *joingr = NULL;
    char insert = 0;
    uint32_t groups = 0;
    DetectPort *list;

   /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt' and on wehther a group
     * is whitelisted. */

    DetectPort *oldhead = port_list;
    while (oldhead) {
        /* take the top of the list */
        list = oldhead;
        oldhead = oldhead->next;
        list->next = NULL;

        groups++;

        SigGroupHeadSetSigCnt(list->sh, max_idx);

        /* insert it */
        DetectPort *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = list;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL && !insert; tmpgr = tmpgr->next) {
                if (CompareFunc(list, tmpgr) == 1) {
                    if (tmpgr == tmplist) {
                        list->next = tmplist;
                        tmplist = list;
                        SCLogDebug("new list top: %u:%u", tmplist->port, tmplist->port2);
                    } else {
                        list->next = prevtmpgr->next;
                        prevtmpgr->next = list;
                    }
                    insert = 1;
                    break;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                list->next = NULL;
                prevtmpgr->next = list;
            }
            insert = 0;
        }
    }

    uint32_t left = unique_groups;
    if (left == 0)
        left = groups;

    /* create another list: take the port groups from above
     * and add them to the 2nd list until we have met our
     * count. The rest is added to the 'join' group. */
    DetectPort *tmplist2 = NULL, *tmplist2_tail = NULL;
    DetectPort *gr, *next_gr;
    for (gr = tmplist; gr != NULL; ) {
        next_gr = gr->next;

        SCLogDebug("temp list gr %p %u:%u", gr, gr->port, gr->port2);
        DetectPortPrint(gr);

        /* if we've set up all the unique groups, add the rest to the
         * catch-all joingr */
        if (left == 0) {
            if (joingr == NULL) {
                DetectPortParse(de_ctx, &joingr, "0:65535");
                if (joingr == NULL) {
                    goto error;
                }
                SCLogDebug("joingr => %u-%u", joingr->port, joingr->port2);
                joingr->next = NULL;
            }
            SigGroupHeadCopySigs(de_ctx,gr->sh,&joingr->sh);

            /* when a group's sigs are added to the joingr, we can free it */
            gr->next = NULL;
            DetectPortFree(de_ctx, gr);
            gr = NULL;

        /* append */
        } else {
            gr->next = NULL;

            if (tmplist2 == NULL) {
                tmplist2 = gr;
                tmplist2_tail = gr;
            } else {
                tmplist2_tail->next = gr;
                tmplist2_tail = gr;
            }
        }

        if (left > 0)
            left--;

        gr = next_gr;
    }

    /* if present, append the joingr that covers the rest */
    if (joingr != NULL) {
        SCLogDebug("appending joingr %p %u:%u", joingr, joingr->port, joingr->port2);

        if (tmplist2 == NULL) {
            tmplist2 = joingr;
            //tmplist2_tail = joingr;
        } else {
            tmplist2_tail->next = joingr;
            //tmplist2_tail = joingr;
        }
    } else {
        SCLogDebug("no joingr");
    }

    /* pass back our new list to the caller */
    *newhead = tmplist2;
    DetectPortPrintList(*newhead);

    return 0;
error:
    return -1;
}

/**
 *  \internal
 *  \brief add a decoder event signature to the detection engine ctx
 */
static void DetectEngineAddDecoderEventSig(DetectEngineCtx *de_ctx, Signature *s)
{
    SCLogDebug("adding signature %"PRIu32" to the decoder event sgh", s->id);
    SigGroupHeadAppendSig(de_ctx, &de_ctx->decoder_event_sgh, s);
}

/**
 * \brief Fill the global src group head, with the sigs included
 *
 * \param de_ctx Pointer to the Detection Engine Context whose Signatures have
 *               to be processed
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int SigAddressPrepareStage2(DetectEngineCtx *de_ctx)
{
    SCLogDebug("building signature grouping structure, stage 2: "
            "building source address lists...");

    IPOnlyInit(de_ctx, &de_ctx->io_ctx);

    de_ctx->flow_gh[1].tcp = RulesGroupByPorts(de_ctx, IPPROTO_TCP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].tcp = RulesGroupByPorts(de_ctx, IPPROTO_TCP, SIG_FLAG_TOCLIENT);
    de_ctx->flow_gh[1].udp = RulesGroupByPorts(de_ctx, IPPROTO_UDP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].udp = RulesGroupByPorts(de_ctx, IPPROTO_UDP, SIG_FLAG_TOCLIENT);

    /* Setup the other IP Protocols (so not TCP/UDP) */
    RulesGroupByProto(de_ctx);

    /* now for every rule add the source group to our temp lists */
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        SCLogDebug("s->id %"PRIu32, s->id);
        if (s->flags & SIG_FLAG_IPONLY) {
            IPOnlyAddSignature(de_ctx, &de_ctx->io_ctx, s);
        }

        if (s->init_data->init_flags & SIG_FLAG_INIT_DEONLY) {
            DetectEngineAddDecoderEventSig(de_ctx, s);
        }
    }

    IPOnlyPrepare(de_ctx);
    IPOnlyPrint(de_ctx, &de_ctx->io_ctx);
    return 0;
}

static void DetectEngineBuildDecoderEventSgh(DetectEngineCtx *de_ctx)
{
    if (de_ctx->decoder_event_sgh == NULL)
        return;

    uint32_t max_idx = DetectEngineGetMaxSigId(de_ctx);
    SigGroupHeadSetSigCnt(de_ctx->decoder_event_sgh, max_idx);
    SigGroupHeadBuildMatchArray(de_ctx, de_ctx->decoder_event_sgh, max_idx);
}

int SigAddressPrepareStage3(DetectEngineCtx *de_ctx)
{
    /* prepare the decoder event sgh */
    DetectEngineBuildDecoderEventSgh(de_ctx);
    return 0;
}

int SigAddressCleanupStage1(DetectEngineCtx *de_ctx)
{
    BUG_ON(de_ctx == NULL);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("cleaning up signature grouping structure...");
    }
    if (de_ctx->decoder_event_sgh)
        SigGroupHeadFree(de_ctx, de_ctx->decoder_event_sgh);
    de_ctx->decoder_event_sgh = NULL;

    for (int f = 0; f < FLOW_STATES; f++) {
        for (int p = 0; p < 256; p++) {
            de_ctx->flow_gh[f].sgh[p] = NULL;
        }

        /* free lookup lists */
        DetectPortCleanupList(de_ctx, de_ctx->flow_gh[f].tcp);
        de_ctx->flow_gh[f].tcp = NULL;
        DetectPortCleanupList(de_ctx, de_ctx->flow_gh[f].udp);
        de_ctx->flow_gh[f].udp = NULL;
    }

    for (uint32_t idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;

        SCLogDebug("sgh %p", sgh);
        SigGroupHeadFree(de_ctx, sgh);
    }
    SCFree(de_ctx->sgh_array);
    de_ctx->sgh_array = NULL;
    de_ctx->sgh_array_cnt = 0;
    de_ctx->sgh_array_size = 0;

    IPOnlyDeinit(de_ctx, &de_ctx->io_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("cleaning up signature grouping structure... complete");
    }
    return 0;
}

#if 0
static void DbgPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        printf("%" PRIu32 " ", sgh->match_array[sig]->id);
    }
    printf("\n");
}

static void DbgPrintSigs2(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL || sgh->init == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < DetectEngineGetMaxSigId(de_ctx); sig++) {
        if (sgh->init->sig_array[(sig/8)] & (1<<(sig%8))) {
            printf("%" PRIu32 " ", de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}
#endif

/** \brief finalize preparing sgh's */
int SigAddressPrepareStage4(DetectEngineCtx *de_ctx)
{
    SCEnter();

    //SCLogInfo("sgh's %"PRIu32, de_ctx->sgh_array_cnt);

    uint32_t cnt = 0;
    for (uint32_t idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;

        SCLogDebug("sgh %p", sgh);

        SigGroupHeadSetFilemagicFlag(de_ctx, sgh);
        SigGroupHeadSetFileHashFlag(de_ctx, sgh);
        SigGroupHeadSetFilesizeFlag(de_ctx, sgh);
        SigGroupHeadSetFilestoreCount(de_ctx, sgh);
        SCLogDebug("filestore count %u", sgh->filestore_cnt);

        PrefilterSetupRuleGroup(de_ctx, sgh);

        SigGroupHeadBuildNonPrefilterArray(de_ctx, sgh);

        sgh->id = idx;
        cnt++;
    }
    SCLogPerf("Unique rule groups: %u", cnt);

    MpmStoreReportStats(de_ctx);

    if (de_ctx->decoder_event_sgh != NULL) {
        /* no need to set filestore count here as that would make a
         * signature not decode event only. */
    }

    int dump_grouping = 0;
    (void)ConfGetBool("detect.profiling.grouping.dump-to-disk", &dump_grouping);

    if (dump_grouping) {
        int add_rules = 0;
        (void)ConfGetBool("detect.profiling.grouping.include-rules", &add_rules);
        int add_mpm_stats = 0;
        (void)ConfGetBool("detect.profiling.grouping.include-mpm-stats", &add_mpm_stats);

        RulesDumpGrouping(de_ctx, add_rules, add_mpm_stats);
    }

    for (uint32_t idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;
        SigGroupHeadInitDataFree(sgh->init);
        sgh->init = NULL;
    }
    /* cleanup the hashes now since we won't need them
     * after the initialization phase. */
    SigGroupHeadHashFree(de_ctx);

#ifdef PROFILING
    SCProfilingSghInitCounters(de_ctx);
#endif
    SCReturnInt(0);
}

extern int rule_engine_analysis_set;
/** \internal
 *  \brief perform final per signature setup tasks
 *
 *  - Create SigMatchData arrays from the init only SigMatch lists
 *  - Setup per signature inspect engines
 *  - remove signature init data.
 */
static int SigMatchPrepare(DetectEngineCtx *de_ctx)
{
    SCEnter();

    Signature *s = de_ctx->sig_list;
    for (; s != NULL; s = s->next) {
        /* set up inspect engines */
        DetectEngineAppInspectionEngine2Signature(de_ctx, s);

        /* built-ins */
        int type;
        for (type = 0; type < DETECT_SM_LIST_MAX; type++) {
            /* skip PMATCH if it is used in a stream 'app engine' instead */
            if (type == DETECT_SM_LIST_PMATCH && (s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH))
                continue;
            SigMatch *sm = s->init_data->smlists[type];
            s->sm_arrays[type] = SigMatchList2DataArray(sm);
        }
        /* set up the pkt inspection engines */
        DetectEnginePktInspectionSetup(s);

        if (rule_engine_analysis_set) {
            EngineAnalysisAddAllRulePatterns(de_ctx, s);
            EngineAnalysisRules2(de_ctx, s);
        }
        /* free lists. Ctx' are xferred to sm_arrays so won't get freed */
        uint32_t i;
        for (i = 0; i < s->init_data->smlists_array_size; i++) {
            SigMatch *sm = s->init_data->smlists[i];
            while (sm != NULL) {
                SigMatch *nsm = sm->next;
                SigMatchFree(de_ctx, sm);
                sm = nsm;
            }
        }
        SCFree(s->init_data->smlists);
        SCFree(s->init_data->smlists_tail);
        for (i = 0; i < (uint32_t)s->init_data->transforms.cnt; i++) {
            if (s->init_data->transforms.transforms[i].options) {
                int transform = s->init_data->transforms.transforms[i].transform;
                sigmatch_table[transform].Free(
                        de_ctx, s->init_data->transforms.transforms[i].options);
                s->init_data->transforms.transforms[i].options = NULL;
            }
        }
        SCFree(s->init_data);
        s->init_data = NULL;
    }

    DumpPatterns(de_ctx);
    SCReturnInt(0);
}

/**
 * \brief Convert the signature list into the runtime match structure.
 *
 * \param de_ctx Pointer to the Detection Engine Context whose Signatures have
 *               to be processed
 *
 * \retval  0 On Success.
 * \retval -1 On failure.
 */
int SigGroupBuild(DetectEngineCtx *de_ctx)
{
    Signature *s = de_ctx->sig_list;

    /* Assign the unique order id of signatures after sorting,
     * so the IP Only engine process them in order too.  Also
     * reset the old signums and assign new signums.  We would
     * have experienced Sig reordering by now, hence the new
     * signums. */
    de_ctx->signum = 0;
    while (s != NULL) {
        s->num = de_ctx->signum++;

        s = s->next;
    }

    if (DetectSetFastPatternAndItsId(de_ctx) < 0)
        return -1;

    SigInitStandardMpmFactoryContexts(de_ctx);

    if (SigAddressPrepareStage1(de_ctx) != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }

    if (SigAddressPrepareStage2(de_ctx) != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }

    if (SigAddressPrepareStage3(de_ctx) != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }
    if (SigAddressPrepareStage4(de_ctx) != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }

    int r = DetectMpmPrepareBuiltinMpms(de_ctx);
    r |= DetectMpmPrepareAppMpms(de_ctx);
    r |= DetectMpmPreparePktMpms(de_ctx);
    r |= DetectMpmPrepareFrameMpms(de_ctx);
    if (r != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }

    if (SigMatchPrepare(de_ctx) != 0) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }

#ifdef PROFILING
    SCProfilingKeywordInitCounters(de_ctx);
    SCProfilingPrefilterInitCounters(de_ctx);
    de_ctx->profile_match_logging_threshold = UINT_MAX; // disabled

    intmax_t v = 0;
    if (ConfGetInt("detect.profiling.inspect-logging-threshold", &v) == 1)
        de_ctx->profile_match_logging_threshold = (uint32_t)v;

    SCProfilingRuleInitCounters(de_ctx);
#endif

    ThresholdHashAllocate(de_ctx);

    if (!DetectEngineMultiTenantEnabled()) {
        VarNameStoreActivateStaging();
    }
    return 0;
}

int SigGroupCleanup (DetectEngineCtx *de_ctx)
{
    SigAddressCleanupStage1(de_ctx);

    return 0;
}
