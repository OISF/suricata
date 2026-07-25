/* Copyright (C) 2007-2026 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-build.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-prefilter-common.h"
#include "detect-parse.h"
#include "detect-app-layer-protocol.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#ifdef UNITTESTS
static void DetectAppLayerProtocolRegisterTests(void);
#endif

enum {
    DETECT_ALPROTO_DIRECTION = 0,
    DETECT_ALPROTO_FINAL = 1,
    DETECT_ALPROTO_EITHER = 2,
    DETECT_ALPROTO_TOSERVER = 3,
    DETECT_ALPROTO_TOCLIENT = 4,
    DETECT_ALPROTO_ORIG = 5,
};

static void DetectAppLayerProtocolFree(DetectEngineCtx *de_ctx, void *ptr);

/** \internal
 *  \brief size in bytes of an alproto bitmask (g_alproto_max bits). */
static inline uint32_t AlprotoBitmaskSize(void)
{
    return (uint32_t)((g_alproto_max + 7) / 8);
}

static inline void AlprotoBitmaskSet(uint8_t *bm, AppProto a)
{
    bm[a >> 3] |= (uint8_t)(1u << (a & 7));
}

static inline bool AlprotoBitmaskTest(const uint8_t *bm, AppProto a)
{
    return (bm[a >> 3] & (uint8_t)(1u << (a & 7))) != 0;
}

/** \internal
 *  \brief Compare a configured value against a flow protocol under the rule's
 *         matching policy.
 *
 *  By default the historical AppProtoEquals() equivalences apply (dns/doh2,
 *  http/http1/http2, dcerpc/smb, ...). With the `exact` option the match is a
 *  strict identity, with no equivalences and no http umbrella. Used to expand
 *  the match set at rule load and by the single-value prefilter comparator. */
static inline bool DetectAppLayerProtocolCompare(AppProto sigproto, AppProto alproto, bool exact)
{
    return exact ? (sigproto == alproto) : AppProtoEquals(sigproto, alproto);
}

/** \internal
 *  \brief Expand one configured value into the match bitmask: set a bit for
 *         every flow protocol that should match it. Done once at rule load so
 *         the per-packet match is a single bitmask test. */
static void DetectAppLayerProtocolExpand(uint8_t *bm, AppProto sigproto, bool exact)
{
    for (AppProto a = 0; a < g_alproto_max; a++) {
        if (DetectAppLayerProtocolCompare(sigproto, a, exact))
            AlprotoBitmaskSet(bm, a);
    }
}

static int DetectAppLayerProtocolPacketMatch(
        DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    const DetectAppLayerProtocolData *data = (const DetectAppLayerProtocolData *)ctx;

    /* if the sig is PD-only we only match when PD packet flags are set */
    if (s->type == SIG_TYPE_PDONLY &&
            (p->flags & (PKT_PROTO_DETECT_TS_DONE | PKT_PROTO_DETECT_TC_DONE)) == 0) {
        SCLogDebug("packet %" PRIu64 ": flags not set", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    const Flow *f = p->flow;
    if (f == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow", PcapPacketCntGet(p));
        SCReturnInt(0);
    }

    /* Resolve the flow's alproto for the configured mode. */
    AppProto resolved_alproto = ALPROTO_UNKNOWN;
    switch (data->mode) {
        case DETECT_ALPROTO_DIRECTION:
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                resolved_alproto = f->alproto_ts;
            } else {
                resolved_alproto = f->alproto_tc;
            }
            break;
        case DETECT_ALPROTO_ORIG:
            resolved_alproto = f->alproto_orig;
            break;
        case DETECT_ALPROTO_FINAL:
            resolved_alproto = f->alproto;
            break;
        case DETECT_ALPROTO_TOSERVER:
            resolved_alproto = f->alproto_ts;
            break;
        case DETECT_ALPROTO_TOCLIENT:
            resolved_alproto = f->alproto_tc;
            break;
        case DETECT_ALPROTO_EITHER:
            /* Handled separately below against both directions. */
            break;
    }

    /* Negated rules never match when alproto is still unknown. */
    if (data->negated) {
        if (data->mode == DETECT_ALPROTO_EITHER) {
            if (f->alproto_ts == ALPROTO_UNKNOWN && f->alproto_tc == ALPROTO_UNKNOWN) {
                SCReturnInt(0);
            }
        } else {
            if (resolved_alproto == ALPROTO_UNKNOWN) {
                SCReturnInt(0);
            }
        }
    }

    bool r = false;
    if (data->mode == DETECT_ALPROTO_EITHER) {
        r = AlprotoBitmaskTest(data->alprotos, f->alproto_ts) ||
            AlprotoBitmaskTest(data->alprotos, f->alproto_tc);
    } else {
        r = AlprotoBitmaskTest(data->alprotos, resolved_alproto);
    }

    /* XOR with negated for NOR semantics. */
    r = r ^ data->negated;

    if (r) {
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

#define MAX_ALPROTO_NAME 50

/** \internal
 *  \brief Map a textual mode-qualifier token to its DETECT_ALPROTO_* value.
 */
static int DetectAppLayerProtocolMapModeName(const char *name)
{
    if (strcmp(name, "final") == 0)
        return DETECT_ALPROTO_FINAL;
    if (strcmp(name, "original") == 0)
        return DETECT_ALPROTO_ORIG;
    if (strcmp(name, "either") == 0)
        return DETECT_ALPROTO_EITHER;
    if (strcmp(name, "to_server") == 0)
        return DETECT_ALPROTO_TOSERVER;
    if (strcmp(name, "to_client") == 0)
        return DETECT_ALPROTO_TOCLIENT;
    if (strcmp(name, "direction") == 0)
        return DETECT_ALPROTO_DIRECTION;
    return -1;
}

/** \brief Map a DETECT_ALPROTO_* mode value to its textual qualifier. */
const char *DetectAppLayerProtocolModeName(uint8_t mode)
{
    switch (mode) {
        case DETECT_ALPROTO_FINAL:
            return "final";
        case DETECT_ALPROTO_ORIG:
            return "original";
        case DETECT_ALPROTO_EITHER:
            return "either";
        case DETECT_ALPROTO_TOSERVER:
            return "to_server";
        case DETECT_ALPROTO_TOCLIENT:
            return "to_client";
        case DETECT_ALPROTO_DIRECTION:
        default:
            return "direction";
    }
}

/** \brief Fill out[] with the keyword's set protocol values.
 *  \retval number of values written (capped at max). */
uint16_t DetectAppLayerProtocolGetValues(
        const DetectAppLayerProtocolData *data, AppProto *out, uint16_t max)
{
    uint16_t n = 0;
    for (AppProto a = 0; a < g_alproto_max && n < max; a++) {
        if (AlprotoBitmaskTest(data->alprotos, a))
            out[n++] = a;
    }
    return n;
}

/** \internal
 *  \brief Build a comma-separated list of supported app-layer protocol names.
 */
static void DetectAppLayerProtocolBuildSupportedList(char *buf, size_t buflen)
{
    if (buflen == 0)
        return;
    buf[0] = '\0';

    AppProto alprotos[g_alproto_max];
    AppLayerProtoDetectSupportedAppProtocols(alprotos);

    size_t offset = 0;
    for (AppProto a = 0; a < g_alproto_max; a++) {
        if (alprotos[a] != 1)
            continue;
        const char *name = AppProtoToString(a);
        if (name == NULL)
            continue;
        int w = snprintf(buf + offset, buflen - offset, "%s%s", (offset == 0) ? "" : ", ", name);
        if (w < 0 || (size_t)w >= buflen - offset)
            break; /* truncated; stop appending */
        offset += (size_t)w;
    }
}

/** \internal
 *  \brief Resolve a single protocol token to its AppProto value.
 *  \retval 0 on success, -1 on error (logs the reason). */
static int DetectAppLayerProtocolResolveToken(
        const char *token, const char *arg, bool negate, AppProto *out)
{
    size_t tlen = strlen(token);
    if (tlen == 0) {
        SCLogError("app-layer-protocol keyword value \"%s\" contains an empty token", arg);
        return -1;
    }
    if (tlen >= MAX_ALPROTO_NAME) {
        SCLogError("app-layer-protocol keyword token \"%s\" in \"%s\" exceeds the "
                   "maximum token length of %d characters",
                token, arg, MAX_ALPROTO_NAME - 1);
        return -1;
    }
    if (strcmp(token, "failed") == 0) {
        *out = ALPROTO_FAILED;
        return 0;
    }
    if (strcmp(token, "unknown") == 0) {
        if (negate) {
            SCLogError("app-layer-protocol keyword can't use negation with protocol 'unknown'");
            return -1;
        }
        *out = ALPROTO_UNKNOWN;
        return 0;
    }
    AppProto ap = AppLayerGetProtoByName(token);
    if (ap == ALPROTO_UNKNOWN) {
        char supported[1024];
        DetectAppLayerProtocolBuildSupportedList(supported, sizeof(supported));
        SCLogError("app-layer-protocol keyword supplied with unknown protocol "
                   "\"%s\" in \"%s\"; supported protocols: %s",
                token, arg, supported);
        return -1;
    }
    *out = ap;
    return 0;
}

static DetectAppLayerProtocolData *DetectAppLayerProtocolParse(const char *arg, bool negate)
{
    if (arg == NULL) {
        SCLogError("app-layer-protocol keyword requires a value");
        return NULL;
    }

    /* Total-length validation. The limit bounds the on-stack copy below
     * (buf[1025]) and is far larger than any realistic protocol value list. */
    size_t arglen = strlen(arg);
    if (arglen > 1024) {
        SCLogError("app-layer-protocol keyword argument too long (\"%s\"): maximum "
                   "supported length is 1024 characters",
                arg);
        return NULL;
    }
    if (arglen == 0) {
        SCLogError("app-layer-protocol keyword value is empty (an empty value list "
                   "is not permitted)");
        return NULL;
    }

    char buf[1025];
    strlcpy(buf, arg, sizeof(buf));

    /* Split the protocol list from the trailing comma-separated qualifiers.
     * The list itself is pipe-separated; each qualifier is a direction mode
     * (at most one) or the `exact` option, in any order. */
    uint8_t mode = DETECT_ALPROTO_DIRECTION;
    bool exact = false;
    char *qualifiers = strchr(buf, ',');
    if (qualifiers != NULL) {
        *qualifiers = '\0';
        qualifiers++;
        bool mode_set = false;
        char *q = qualifiers;
        while (q != NULL && *q != '\0') {
            char *next = strchr(q, ',');
            if (next != NULL)
                *next++ = '\0';
            if (strcmp(q, "exact") == 0) {
                exact = true;
            } else {
                int m = DetectAppLayerProtocolMapModeName(q);
                if (m < 0) {
                    SCLogError("app-layer-protocol keyword supplied with unknown "
                               "qualifier \"%s\" in \"%s\"",
                            q, arg);
                    return NULL;
                }
                if (mode_set) {
                    SCLogError("app-layer-protocol keyword supplied with multiple "
                               "mode qualifiers in \"%s\"",
                            arg);
                    return NULL;
                }
                mode = (uint8_t)m;
                mode_set = true;
            }
            q = next;
        }
    }

    DetectAppLayerProtocolData *data = SCCalloc(1, sizeof(*data));
    if (unlikely(data == NULL))
        return NULL;
    data->alprotos = SCCalloc(1, AlprotoBitmaskSize());
    if (unlikely(data->alprotos == NULL)) {
        SCFree(data);
        return NULL;
    }
    data->negated = negate;
    data->mode = mode;
    data->exact = exact;
    data->alproto = ALPROTO_UNKNOWN;

    /* Tokenize the protocol list on '|' and expand each value into the
     * effective match set under the chosen policy, so the per-packet match is
     * a single bitmask test. */
    int value_count = 0;
    char *cur = buf;
    while (1) {
        char *pipe = strchr(cur, '|');
        if (pipe != NULL)
            *pipe = '\0';

        AppProto value;
        if (DetectAppLayerProtocolResolveToken(cur, arg, negate, &value) < 0)
            goto error;

        /* The generic ALPROTO_HTTP is never a flow's classified protocol, so
         * an exact http match can never fire; steer users to http1/http2. */
        if (exact && value == ALPROTO_HTTP) {
            SCLogError("app-layer-protocol keyword: 'http' with 'exact' never "
                       "matches (flows are classified as http1/http2); use "
                       "http1 or http2");
            goto error;
        }

        if (value_count == 0)
            data->alproto = value;
        DetectAppLayerProtocolExpand(data->alprotos, value, exact);
        value_count++;

        if (pipe == NULL)
            break;
        cur = pipe + 1;
    }

    data->is_list = (value_count > 1);
    if (data->is_list)
        data->alproto = ALPROTO_UNKNOWN; /* lists are not prefilterable: no single-value key */

    return data;

error:
    DetectAppLayerProtocolFree(NULL, data);
    return NULL;
}

/**
 * \brief Check whether two app-layer-protocol SigMatches conflict.
 */
static bool DetectAppLayerProtocolsConflict(
        const DetectAppLayerProtocolData *us, const DetectAppLayerProtocolData *them)
{
    /* Different modes never conflict. */
    if (us->mode != them->mode)
        return false;

    /* Both negated under the same mode: only a conflict when the value sets
     * intersect. Identical or overlapping negated lists are redundant, while
     * disjoint negated lists (e.g. !http; !dns;) are a valid NOR combination. */
    if (us->negated && them->negated) {
        for (AppProto a = 0; a < g_alproto_max; a++) {
            if (AlprotoBitmaskTest(us->alprotos, a) && AlprotoBitmaskTest(them->alprotos, a)) {
                SCLogError("conflicting app-layer-protocol rules: "
                           "duplicate or overlapping negated entries under the same mode");
                return true;
            }
        }
        return false;
    }

    /* Two non-negated under the same mode: always conflict. */
    if (!us->negated && !them->negated) {
        SCLogError("conflicting app-layer-protocol rules: "
                   "multiple non-negated entries under the same mode");
        return true;
    }

    /* Mixed negation under the same mode: conflict. Collect the intersecting
     * values for the error message. */
    char conflict_buf[512];
    size_t buf_offset = 0;
    bool has_intersection = false;

    for (AppProto a = 0; a < g_alproto_max; a++) {
        if (!AlprotoBitmaskTest(us->alprotos, a) || !AlprotoBitmaskTest(them->alprotos, a))
            continue;
        has_intersection = true;
        const char *name = AppProtoToString(a);
        if (name == NULL)
            name = "unknown";
        if (buf_offset > 0 && buf_offset < sizeof(conflict_buf) - 2) {
            conflict_buf[buf_offset++] = ',';
            conflict_buf[buf_offset++] = ' ';
        }
        size_t name_len = strlen(name);
        if (buf_offset + name_len < sizeof(conflict_buf) - 1) {
            memcpy(conflict_buf + buf_offset, name, name_len);
            buf_offset += name_len;
        }
    }
    conflict_buf[buf_offset] = '\0';

    if (has_intersection) {
        SCLogError("conflicting app-layer-protocol rules: "
                   "can't mix positive match with negated match under the same "
                   "mode; intersecting protocol value(s): %s",
                conflict_buf);
    } else {
        SCLogError("conflicting app-layer-protocol rules: "
                   "can't mix positive app-layer-protocol match with negated "
                   "match or match for 'failed'");
    }
    return true;
}

static int DetectAppLayerProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectAppLayerProtocolData *data = NULL;

    /* Early rejection: rule already bound to a protocol. */
    if (s->alproto != ALPROTO_UNKNOWN) {
        SCLogError("Either we already "
                   "have the rule match on an app layer protocol set through "
                   "other keywords that match on this protocol, or have "
                   "already seen a non-negated app-layer-protocol.");
        goto error;
    }

    data = DetectAppLayerProtocolParse(arg, s->init_data->negated);
    if (data == NULL)
        goto error;

    SigMatch *tsm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for (; tsm != NULL; tsm = tsm->next) {
        if (tsm->type == DETECT_APP_LAYER_PROTOCOL) {
            const DetectAppLayerProtocolData *them = (const DetectAppLayerProtocolData *)tsm->ctx;

            if (DetectAppLayerProtocolsConflict(data, them)) {
                SCLogError("conflicting app-layer-protocol options detected "
                           "(see preceding error for details).");
                goto error;
            }
        }
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_APP_LAYER_PROTOCOL, (SigMatchCtx *)data,
                DETECT_SM_LIST_MATCH) == NULL) {
        goto error;
    }
    return 0;

error:
    DetectAppLayerProtocolFree(de_ctx, data);
    return -1;
}

static void DetectAppLayerProtocolFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectAppLayerProtocolData *data = (DetectAppLayerProtocolData *)ptr;
    if (data == NULL)
        return;
    if (data->alprotos != NULL)
        SCFree(data->alprotos);
    SCFree(data);
}

/** \internal
 *  \brief prefilter function for protocol detect matching
 */
static void PrefilterPacketAppProtoMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    if (!PrefilterPacketHeaderExtraMatch(ctx, p)) {
        SCLogDebug("packet %" PRIu64 ": extra match failed", PcapPacketCntGet(p));
        SCReturn;
    }

    if (p->flow == NULL) {
        SCLogDebug("packet %" PRIu64 ": no flow, no alproto", PcapPacketCntGet(p));
        SCReturn;
    }

    if ((p->flags & (PKT_PROTO_DETECT_TS_DONE|PKT_PROTO_DETECT_TC_DONE)) == 0) {
        SCLogDebug("packet %" PRIu64 ": flags not set", PcapPacketCntGet(p));
        SCReturn;
    }

    Flow *f = p->flow;
    AppProto alproto = ALPROTO_UNKNOWN;
    bool negated = (bool)ctx->v1.u8[2];
    bool exact = (bool)ctx->v1.u8[4];
    switch (ctx->v1.u8[3]) {
        case DETECT_ALPROTO_DIRECTION:
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                alproto = f->alproto_ts;
            } else {
                alproto = f->alproto_tc;
            }
            break;
        case DETECT_ALPROTO_ORIG:
            alproto = f->alproto_orig;
            break;
        case DETECT_ALPROTO_FINAL:
            alproto = f->alproto;
            break;
        case DETECT_ALPROTO_TOSERVER:
            alproto = f->alproto_ts;
            break;
        case DETECT_ALPROTO_TOCLIENT:
            alproto = f->alproto_tc;
            break;
        case DETECT_ALPROTO_EITHER:
            // check if either protocol toclient or toserver matches
            // the one in the signature ctx
            if (negated) {
                if (f->alproto_tc != ALPROTO_UNKNOWN &&
                        !DetectAppLayerProtocolCompare(ctx->v1.u16[0], f->alproto_tc, exact)) {
                    PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
                } else if (f->alproto_ts != ALPROTO_UNKNOWN &&
                           !DetectAppLayerProtocolCompare(ctx->v1.u16[0], f->alproto_ts, exact)) {
                    PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
                }
            } else {
                if (DetectAppLayerProtocolCompare(ctx->v1.u16[0], f->alproto_tc, exact) ||
                        DetectAppLayerProtocolCompare(ctx->v1.u16[0], f->alproto_ts, exact)) {
                    PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
                }
            }
            // We return right away to avoid calling PrefilterAddSids again
            return;
    }

    if (negated) {
        if (alproto != ALPROTO_UNKNOWN) {
            if (!DetectAppLayerProtocolCompare(ctx->v1.u16[0], alproto, exact)) {
                PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
            }
        }
    } else {
        if (DetectAppLayerProtocolCompare(ctx->v1.u16[0], alproto, exact)) {
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
        }
    }
}

static void
PrefilterPacketAppProtoSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectAppLayerProtocolData *a = smctx;
    /* Only single-value rules are prefilterable; alproto is that value. */
    v->u16[0] = a->alproto;
    v->u8[2] = (uint8_t)a->negated;
    v->u8[3] = a->mode;
    v->u8[4] = (uint8_t)a->exact;
}

static bool
PrefilterPacketAppProtoCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectAppLayerProtocolData *a = smctx;
    return v.u16[0] == a->alproto && v.u8[2] == (uint8_t)a->negated && v.u8[3] == a->mode &&
           v.u8[4] == (uint8_t)a->exact;
}

static int PrefilterSetupAppProto(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_APP_LAYER_PROTOCOL, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketAppProtoSet, PrefilterPacketAppProtoCompare,
            PrefilterPacketAppProtoMatch);
}

static bool PrefilterAppProtoIsPrefilterable(const Signature *s)
{
    if (s->type != SIG_TYPE_PDONLY) {
        return false;
    }

    /* Multi-value rules cannot be prefiltered (single-valued bucket key). */
    const SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_APP_LAYER_PROTOCOL) {
            const DetectAppLayerProtocolData *data = (const DetectAppLayerProtocolData *)sm->ctx;
            if (data->is_list) {
                return false;
            }
            break;
        }
    }
    return true;
}

void DetectAppLayerProtocolRegister(void)
{
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].name = "app-layer-protocol";
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].desc = "match on the detected app-layer protocol";
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].url = "/rules/app-layer.html#app-layer-protocol";
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].Match = DetectAppLayerProtocolPacketMatch;
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].Setup = DetectAppLayerProtocolSetup;
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].Free = DetectAppLayerProtocolFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].RegisterTests = DetectAppLayerProtocolRegisterTests;
#endif
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].flags =
            (SIGMATCH_QUOTES_OPTIONAL | SIGMATCH_HANDLE_NEGATION | SIGMATCH_SUPPORT_FIREWALL);

    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].SetupPrefilter = PrefilterSetupAppProto;
    sigmatch_table[DETECT_APP_LAYER_PROTOCOL].SupportsPrefilter = PrefilterAppProtoIsPrefilterable;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS

static int DetectAppLayerProtocolTest01(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("http", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated != 0);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

static int DetectAppLayerProtocolTest02(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("http", true);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated == 0);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

static int DetectAppLayerProtocolTest03(void)
{
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:http; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF(s->alproto != ALPROTO_UNKNOWN);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectAppLayerProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest04(void)
{
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:!http; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF(s->alproto != ALPROTO_UNKNOWN);
    FAIL_IF(s->flags & SIG_FLAG_APPLAYER);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectAppLayerProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest05(void)
{
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:!http; app-layer-protocol:!smtp; sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF(s->alproto != ALPROTO_UNKNOWN);
    FAIL_IF(s->flags & SIG_FLAG_APPLAYER);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectAppLayerProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated == 0);

    data = (DetectAppLayerProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->next->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_SMTP));
    FAIL_IF(data->negated == 0);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest06(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
            "(app-layer-protocol:smtp; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest07(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert http any any -> any any "
            "(app-layer-protocol:!smtp; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest08(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:!smtp; app-layer-protocol:http; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest09(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:http; app-layer-protocol:!smtp; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest10(void)
{
    Signature *s = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:smtp; app-layer-protocol:!http; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest11(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("failed", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_FAILED));
    FAIL_IF(data->negated != 0);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

static int DetectAppLayerProtocolTest12(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("failed", true);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_FAILED));
    FAIL_IF(data->negated == 0);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

static int DetectAppLayerProtocolTest13(void)
{
    Signature *s = NULL;
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:failed; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF(s->alproto != ALPROTO_UNKNOWN);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);

    data = (DetectAppLayerProtocolData *)s->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_FAILED));
    FAIL_IF(data->negated);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest14(void)
{
    DetectAppLayerProtocolData *data = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s1 = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:http; flowbits:set,blah; sid:1;)");
    FAIL_IF_NULL(s1);
    FAIL_IF(s1->alproto != ALPROTO_UNKNOWN);
    FAIL_IF_NULL(s1->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s1->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);
    data = (DetectAppLayerProtocolData *)s1->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated);

    Signature *s2 = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:http; flow:to_client; sid:2;)");
    FAIL_IF_NULL(s2);
    FAIL_IF(s2->alproto != ALPROTO_UNKNOWN);
    FAIL_IF_NULL(s2->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s2->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);
    data = (DetectAppLayerProtocolData *)s2->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated);

    /* flow:established and other options not supported for PD-only */
    Signature *s3 = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
            "(app-layer-protocol:http; flow:to_client,established; sid:3;)");
    FAIL_IF_NULL(s3);
    FAIL_IF(s3->alproto != ALPROTO_UNKNOWN);
    FAIL_IF_NULL(s3->init_data->smlists[DETECT_SM_LIST_MATCH]);
    FAIL_IF_NULL(s3->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx);
    data = (DetectAppLayerProtocolData *)s3->init_data->smlists[DETECT_SM_LIST_MATCH]->ctx;
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated);

    SigGroupBuild(de_ctx);
    FAIL_IF_NOT(s1->type == SIG_TYPE_PDONLY);
    FAIL_IF_NOT(s2->type == SIG_TYPE_PDONLY);
    FAIL_IF(s3->type == SIG_TYPE_PDONLY); // failure now

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectAppLayerProtocolTest15(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("http,final", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->negated != 0);
    FAIL_IF(data->mode != DETECT_ALPROTO_FINAL);
    FAIL_IF(data->is_list);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test Multi-value without mode qualifier. */
static int DetectAppLayerProtocolTest16(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|http", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->is_list);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->mode != DETECT_ALPROTO_DIRECTION); /* default */
    FAIL_IF(data->negated != 0);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test Multi-value with mode qualifier. */
static int DetectAppLayerProtocolTest17(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|http,either", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->is_list);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->mode != DETECT_ALPROTO_EITHER);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test A bare mode name with no protocol is treated as a protocol lookup (fails). */
static int DetectAppLayerProtocolTest18(void)
{
    /* "final" alone is treated as a protocol name (which won't resolve). */
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("final", false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Multi-value list with an explicit 'direction' mode qualifier. */
static int DetectAppLayerProtocolTest19(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|http,direction", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->is_list);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    FAIL_IF(data->mode != DETECT_ALPROTO_DIRECTION);
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test Empty value list rejected. */
static int DetectAppLayerProtocolTest20(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("", false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Negation of 'unknown' rejected. */
static int DetectAppLayerProtocolTest21(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("unknown", true);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Oversized argument length rejected. */
static int DetectAppLayerProtocolTest22(void)
{
    /* Build a string >1024 characters. */
    char big[1030];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse(big, false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Empty token in pipe-separated list rejected. */
static int DetectAppLayerProtocolTest23(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls||http", false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Negated multi-value parses correctly (!tls|http). */
static int DetectAppLayerProtocolTest24(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|http", true);
    FAIL_IF_NULL(data);
    FAIL_IF(data->negated != 1);
    FAIL_IF_NOT(data->is_list);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_HTTP));
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test Unknown protocol name in list rejected. */
static int DetectAppLayerProtocolTest25(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|bogus_proto_xyz", false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test Negated single-value against unclassified flow returns 0. */
static int DetectAppLayerProtocolTest26(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(app-layer-protocol:!tls; sid:1;)");
    FAIL_IF_NULL(s);

    /* Check data BEFORE SigGroupBuild (init_data is freed by build). */
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    FAIL_IF_NULL(sm);
    DetectAppLayerProtocolData *data = (DetectAppLayerProtocolData *)sm->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF(data->negated != 1);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));

    SigGroupBuild(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Multi-value rule is NOT prefiltered. */
static int DetectAppLayerProtocolTest27(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(app-layer-protocol:tls|dns; sid:1;)");
    FAIL_IF_NULL(s);

    /* Verify the parsed data is list-valued BEFORE SigGroupBuild. */
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    FAIL_IF_NULL(sm);
    DetectAppLayerProtocolData *data = (DetectAppLayerProtocolData *)sm->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->is_list);

    /* A single-valued packet-detect-only rule is prefilter-eligible; the
     * multi-value guard must exclude this one. init_data is read by the
     * predicate, so check before SigGroupBuild frees it. */
    s->type = SIG_TYPE_PDONLY;
    FAIL_IF(PrefilterAppProtoIsPrefilterable(s));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Multi-value rule combined with buffer-keyword that pre-binds s->alproto is rejected. */
static int DetectAppLayerProtocolTest28(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    /* tls.sni binds s->alproto = TLS, so app-layer-protocol:tls|dns is rejected. */
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any "
            "(tls.sni; content:\"example.com\"; app-layer-protocol:tls|dns; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Default matching keeps AppProtoEquals equivalences (dns covers doh2). */
static int DetectAppLayerProtocolTest29(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("dns", false);
    FAIL_IF_NULL(data);
    FAIL_IF(data->exact);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_DNS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_DOH2));
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test The exact option drops equivalences (dns no longer covers doh2). */
static int DetectAppLayerProtocolTest30(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("dns,exact", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->exact);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_DNS));
    FAIL_IF(AlprotoBitmaskTest(data->alprotos, ALPROTO_DOH2));
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test 'http' with 'exact' is rejected (can never match a real flow). */
static int DetectAppLayerProtocolTest31(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("http,exact", false);
    FAIL_IF_NOT_NULL(data);
    PASS;
}

/** \test exact combines with a direction mode, order-independent. */
static int DetectAppLayerProtocolTest32(void)
{
    DetectAppLayerProtocolData *data = DetectAppLayerProtocolParse("tls|dns,either,exact", false);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->exact);
    FAIL_IF_NOT(data->is_list);
    FAIL_IF(data->mode != DETECT_ALPROTO_EITHER);
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_TLS));
    FAIL_IF_NOT(AlprotoBitmaskTest(data->alprotos, ALPROTO_DNS));
    FAIL_IF(AlprotoBitmaskTest(data->alprotos, ALPROTO_DOH2));
    DetectAppLayerProtocolFree(NULL, data);
    PASS;
}

/** \test Single-value rule IS prefilter-eligible (mirror of Test27). */
static int DetectAppLayerProtocolTest33(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(app-layer-protocol:tls; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    FAIL_IF_NULL(sm);
    DetectAppLayerProtocolData *data = (DetectAppLayerProtocolData *)sm->ctx;
    FAIL_IF_NULL(data);
    FAIL_IF(data->is_list);

    /* A single-valued packet-detect-only rule is prefilter-eligible. init_data
     * is read by the predicate, so check before SigGroupBuild frees it. */
    s->type = SIG_TYPE_PDONLY;
    FAIL_IF_NOT(PrefilterAppProtoIsPrefilterable(s));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static void DetectAppLayerProtocolRegisterTests(void)
{
    UtRegisterTest("DetectAppLayerProtocolTest01", DetectAppLayerProtocolTest01);
    UtRegisterTest("DetectAppLayerProtocolTest02", DetectAppLayerProtocolTest02);
    UtRegisterTest("DetectAppLayerProtocolTest03", DetectAppLayerProtocolTest03);
    UtRegisterTest("DetectAppLayerProtocolTest04", DetectAppLayerProtocolTest04);
    UtRegisterTest("DetectAppLayerProtocolTest05", DetectAppLayerProtocolTest05);
    UtRegisterTest("DetectAppLayerProtocolTest06", DetectAppLayerProtocolTest06);
    UtRegisterTest("DetectAppLayerProtocolTest07", DetectAppLayerProtocolTest07);
    UtRegisterTest("DetectAppLayerProtocolTest08", DetectAppLayerProtocolTest08);
    UtRegisterTest("DetectAppLayerProtocolTest09", DetectAppLayerProtocolTest09);
    UtRegisterTest("DetectAppLayerProtocolTest10", DetectAppLayerProtocolTest10);
    UtRegisterTest("DetectAppLayerProtocolTest11", DetectAppLayerProtocolTest11);
    UtRegisterTest("DetectAppLayerProtocolTest12", DetectAppLayerProtocolTest12);
    UtRegisterTest("DetectAppLayerProtocolTest13", DetectAppLayerProtocolTest13);
    UtRegisterTest("DetectAppLayerProtocolTest14", DetectAppLayerProtocolTest14);
    UtRegisterTest("DetectAppLayerProtocolTest15", DetectAppLayerProtocolTest15);
    UtRegisterTest("DetectAppLayerProtocolTest16", DetectAppLayerProtocolTest16);
    UtRegisterTest("DetectAppLayerProtocolTest17", DetectAppLayerProtocolTest17);
    UtRegisterTest("DetectAppLayerProtocolTest18", DetectAppLayerProtocolTest18);
    UtRegisterTest("DetectAppLayerProtocolTest19", DetectAppLayerProtocolTest19);
    UtRegisterTest("DetectAppLayerProtocolTest20", DetectAppLayerProtocolTest20);
    UtRegisterTest("DetectAppLayerProtocolTest21", DetectAppLayerProtocolTest21);
    UtRegisterTest("DetectAppLayerProtocolTest22", DetectAppLayerProtocolTest22);
    UtRegisterTest("DetectAppLayerProtocolTest23", DetectAppLayerProtocolTest23);
    UtRegisterTest("DetectAppLayerProtocolTest24", DetectAppLayerProtocolTest24);
    UtRegisterTest("DetectAppLayerProtocolTest25", DetectAppLayerProtocolTest25);
    UtRegisterTest("DetectAppLayerProtocolTest26", DetectAppLayerProtocolTest26);
    UtRegisterTest("DetectAppLayerProtocolTest27", DetectAppLayerProtocolTest27);
    UtRegisterTest("DetectAppLayerProtocolTest28", DetectAppLayerProtocolTest28);
    UtRegisterTest("DetectAppLayerProtocolTest29", DetectAppLayerProtocolTest29);
    UtRegisterTest("DetectAppLayerProtocolTest30", DetectAppLayerProtocolTest30);
    UtRegisterTest("DetectAppLayerProtocolTest31", DetectAppLayerProtocolTest31);
    UtRegisterTest("DetectAppLayerProtocolTest32", DetectAppLayerProtocolTest32);
    UtRegisterTest("DetectAppLayerProtocolTest33", DetectAppLayerProtocolTest33);
}
#endif /* UNITTESTS */
