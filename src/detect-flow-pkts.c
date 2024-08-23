/* Copyright (C) 2023-2024 Open Information Security Foundation
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
#include "rust.h"
#include "detect-flow-pkts.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

enum FlowDirection {
    DETECT_FLOW_TOSERVER = 1,
    DETECT_FLOW_TOCLIENT,
    DETECT_FLOW_TOEITHER,
};

typedef struct DetectFlow_ {
    DetectU32Data *pkt_data;
    DetectU64Data *byte_data;
    enum FlowDirection dir;
} DetectFlow;

static int DetectFlowPktsMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }

    const DetectFlow *df = (const DetectFlow *)ctx;
    if (df->dir == DETECT_FLOW_TOSERVER) {
        return DetectU32Match(p->flow->todstpktcnt, df->pkt_data);
    } else if (df->dir == DETECT_FLOW_TOCLIENT) {
        return DetectU32Match(p->flow->tosrcpktcnt, df->pkt_data);
    } else if (df->dir == DETECT_FLOW_TOEITHER) {
        if (DetectU32Match(p->flow->tosrcpktcnt, df->pkt_data)) {
            return 1;
        }
        return DetectU32Match(p->flow->todstpktcnt, df->pkt_data);
    }
    return 0;
}

static void DetectFlowPktsFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlow *df = (DetectFlow *)ptr;
    if (df != NULL) {
        rs_detect_u32_free(df->pkt_data);
        SCFree(df);
    }
}

static int DetectFlowPktsToServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    DetectFlow *df = SCCalloc(1, sizeof(DetectFlow));
    if (df == NULL)
        return -1;

    df->pkt_data = du32;
    df->dir = DETECT_FLOW_TOSERVER;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOW_PKTS, (SigMatchCtx *)df, DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowPktsFree(de_ctx, df);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static int DetectFlowPktsToClientSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU32Data *du32 = DetectU32Parse(rawstr);
    if (du32 == NULL)
        return -1;

    DetectFlow *df = SCCalloc(1, sizeof(DetectFlow));
    if (df == NULL)
        return -1;

    df->pkt_data = du32;
    df->dir = DETECT_FLOW_TOCLIENT;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOW_PKTS, (SigMatchCtx *)df, DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowPktsFree(de_ctx, df);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static int DetectFlowPktsSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlow *df = NULL;
    char copy[strlen(rawstr) + 1];
    strlcpy(copy, rawstr, sizeof(copy));
    char *context = NULL;
    char *token = strtok_r(copy, ",", &context);
    uint8_t num_tokens = 1;
    uint8_t dir = 0;
    char *pkt_data = NULL;

    while (token != NULL) {
        if (num_tokens > 2)
            goto error;

        while (*token != '\0' && isblank(*token)) {
            token++;
        }
        if (strlen(token) == 0) {
            goto next;
        }

        num_tokens++;

        if (strcmp(token, "toserver") == 0) {
            dir = DETECT_FLOW_TOSERVER;
        } else if (strcmp(token, "toclient") == 0) {
            dir = DETECT_FLOW_TOCLIENT;
        } else if (strcmp(token, "either") == 0) {
            dir = DETECT_FLOW_TOEITHER;
        }

        if (dir) {
            pkt_data = token;
        }
    next:
        token = strtok_r(NULL, ",", &context);
    }

    if (dir) {
        DetectU32Data *du32 = DetectU32Parse(pkt_data);
        if (du32 == NULL)
            goto error;
        df = SCCalloc(1, sizeof(DetectFlow));
        if (df == NULL)
            return -1;
        df->dir = dir;
        df->pkt_data = du32;
        if (SigMatchAppendSMToList(
                    de_ctx, s, DETECT_FLOW_PKTS, (SigMatchCtx *)df, DETECT_SM_LIST_MATCH) == NULL) {
            goto error;
        }
    }

    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
error:
    if (df != NULL)
        DetectFlowPktsFree(de_ctx, df);
    return -1;
}

static void PrefilterPacketFlowPktsMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;
    if (!PrefilterPacketHeaderExtraMatch(ctx, p))
        return;

    DetectU32Data du32;
    du32.mode = ctx->v1.u8[0];
    du32.arg1 = ctx->v1.u32[1];
    du32.arg2 = ctx->v1.u32[2];
    if (DetectFlowPktsMatch(det_ctx, p, NULL, (const SigMatchCtx *)&du32)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupFlowPkts(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_FLOW_PKTS, SIG_MASK_REQUIRE_FLOW,
            PrefilterPacketU32Set, PrefilterPacketU32Compare, PrefilterPacketFlowPktsMatch);
}

static bool PrefilterFlowPktsIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_FLOW_PKTS);
}

void DetectFlowPktsRegister(void)
{
    sigmatch_table[DETECT_FLOW_PKTS].name = "flow.pkts";
    sigmatch_table[DETECT_FLOW_PKTS].desc = "match number of packets in a flow";
    sigmatch_table[DETECT_FLOW_PKTS].url = "/rules/flow-keywords.html#flow-pkts";
    sigmatch_table[DETECT_FLOW_PKTS].Match = DetectFlowPktsMatch;
    sigmatch_table[DETECT_FLOW_PKTS].Setup = DetectFlowPktsSetup;
    sigmatch_table[DETECT_FLOW_PKTS].Free = DetectFlowPktsFree;
    sigmatch_table[DETECT_FLOW_PKTS].SupportsPrefilter = PrefilterFlowPktsIsPrefilterable;
    sigmatch_table[DETECT_FLOW_PKTS].SetupPrefilter = PrefilterSetupFlowPkts;
}

void DetectFlowPktsToServerRegister(void)
{
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].name = "flow.pkts_toserver";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].desc =
            "match number of packets in a flow in to server direction";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].url = "/rules/flow-keywords.html#flow-pkts";
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Match = DetectFlowPktsMatch;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Setup = DetectFlowPktsToServerSetup;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].Free = DetectFlowPktsFree;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].SupportsPrefilter = PrefilterFlowPktsIsPrefilterable;
    sigmatch_table[DETECT_FLOW_PKTS_TO_SERVER].SetupPrefilter = PrefilterSetupFlowPkts;
}

void DetectFlowPktsToClientRegister(void)
{
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].name = "flow.pkts_toclient";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].desc =
            "match number of packets in a flow in to client direction";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].url = "/rules/flow-keywords.html#flow-pkts";
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Match = DetectFlowPktsMatch;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Setup = DetectFlowPktsToClientSetup;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].Free = DetectFlowPktsFree;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].SupportsPrefilter = PrefilterFlowPktsIsPrefilterable;
    sigmatch_table[DETECT_FLOW_PKTS_TO_CLIENT].SetupPrefilter = PrefilterSetupFlowPkts;
}

static int DetectFlowBytesMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->flow == NULL) {
        return 0;
    }

    const DetectFlow *df = (const DetectFlow *)ctx;
    if (df->dir == DETECT_FLOW_TOSERVER) {
        return DetectU64Match(p->flow->todstbytecnt, df->byte_data);
    } else if (df->dir == DETECT_FLOW_TOCLIENT) {
        return DetectU64Match(p->flow->tosrcbytecnt, df->byte_data);
    } else if (df->dir == DETECT_FLOW_TOEITHER) {
        if (DetectU64Match(p->flow->tosrcbytecnt, df->byte_data)) {
            return 1;
        }
        return DetectU64Match(p->flow->todstbytecnt, df->byte_data);
    }
    return 0;
}

static void DetectFlowBytesFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectFlow *df = (DetectFlow *)ptr;
    if (df != NULL) {
        rs_detect_u64_free(df->byte_data);
        SCFree(df);
    }
}

static int DetectFlowBytesToServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    DetectFlow *df = SCCalloc(1, sizeof(DetectFlow));
    if (df == NULL)
        return -1;

    df->byte_data = du64;
    df->dir = DETECT_FLOW_TOSERVER;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOW_BYTES, (SigMatchCtx *)df, DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowBytesFree(de_ctx, df);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static int DetectFlowBytesToClientSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU64Data *du64 = DetectU64Parse(rawstr);
    if (du64 == NULL)
        return -1;

    DetectFlow *df = SCCalloc(1, sizeof(DetectFlow));
    if (df == NULL)
        return -1;

    df->byte_data = du64;
    df->dir = DETECT_FLOW_TOCLIENT;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FLOW_BYTES, (SigMatchCtx *)df, DETECT_SM_LIST_MATCH) == NULL) {
        DetectFlowBytesFree(de_ctx, df);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static int DetectFlowBytesSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlow *df = NULL;
    char copy[strlen(rawstr) + 1];
    strlcpy(copy, rawstr, sizeof(copy));
    char *context = NULL;
    char *token = strtok_r(copy, ",", &context);
    uint8_t num_tokens = 1;
    uint8_t dir = 0;
    char *byte_data = NULL;

    while (token != NULL) {
        if (num_tokens > 2)
            goto error;

        while (*token != '\0' && isblank(*token)) {
            token++;
        }
        if (strlen(token) == 0) {
            goto next;
        }

        num_tokens++;

        if (strcmp(token, "toserver") == 0) {
            dir = DETECT_FLOW_TOSERVER;
        } else if (strcmp(token, "toclient") == 0) {
            dir = DETECT_FLOW_TOCLIENT;
        } else if (strcmp(token, "either") == 0) {
            dir = DETECT_FLOW_TOEITHER;
        }

        if (dir) {
            byte_data = token;
        }
    next:
        token = strtok_r(NULL, ",", &context);
    }

    if (dir) {
        DetectU64Data *du64 = DetectU64Parse(byte_data);
        if (du64 == NULL)
            goto error;
        df = SCCalloc(1, sizeof(DetectFlow));
        if (df == NULL)
            return -1;
        df->dir = dir;
        df->byte_data = du64;
        if (SigMatchAppendSMToList(de_ctx, s, DETECT_FLOW_BYTES, (SigMatchCtx *)df,
                    DETECT_SM_LIST_MATCH) == NULL) {
            goto error;
        }
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
error:
    if (df)
        DetectFlowBytesFree(de_ctx, df);
    return -1;
}

void DetectFlowBytesRegister(void)
{
    sigmatch_table[DETECT_FLOW_BYTES].name = "flow.bytes";
    sigmatch_table[DETECT_FLOW_BYTES].desc = "match number of bytes in a flow";
    sigmatch_table[DETECT_FLOW_BYTES].url = "/rules/flow-keywords.html#flow-bytes";
    sigmatch_table[DETECT_FLOW_BYTES].Match = DetectFlowBytesMatch;
    sigmatch_table[DETECT_FLOW_BYTES].Setup = DetectFlowBytesSetup;
    sigmatch_table[DETECT_FLOW_BYTES].Free = DetectFlowBytesFree;
}

void DetectFlowBytesToServerRegister(void)
{
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].name = "flow.bytes_toserver";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].desc =
            "match number of bytes in a flow in to server dir";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].url = "/rules/flow-keywords.html#flow-bytes";
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Match = DetectFlowBytesMatch;
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Setup = DetectFlowBytesToServerSetup;
    sigmatch_table[DETECT_FLOW_BYTES_TO_SERVER].Free = DetectFlowBytesFree;
}

void DetectFlowBytesToClientRegister(void)
{
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].name = "flow.bytes_toclient";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].desc =
            "match number of bytes in a flow in to client dir";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].url = "/rules/flow-keywords.html#flow-bytes";
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Match = DetectFlowBytesMatch;
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Setup = DetectFlowBytesToClientSetup;
    sigmatch_table[DETECT_FLOW_BYTES_TO_CLIENT].Free = DetectFlowBytesFree;
}
