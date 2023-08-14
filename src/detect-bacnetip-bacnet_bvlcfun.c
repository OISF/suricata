/* Copyright (C) 2023 Open Information Security Foundation
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

/*
 * TODO: Update the \author in this file and detect-bacnetip.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "bacnetip_rust" keyword to allow content
 * inspections on the decoded bacnetip application layer buffers.
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-bacnetip-bacnet_bvlcfun.h"
#include "app-layer-parser.h"
#include "detect-engine-build.h"
#include "rust.h"

static int DetectBacNetIpbacnet_bvlcfunSetup(DetectEngineCtx *, Signature *, const char *);
static int DetectBacnetBvlcFunMatch(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
        const SigMatchCtx *ctx);
static void DetectBacNetIpbacnet_bvlcfunFree(DetectEngineCtx *de_ctx, void *ptr);

static int g_bacnetip_rust_id = 0;

void DetectBacNetIpbacnet_bvlcfunRegister(void)
{
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].name = "bacnetip.bvlcfun";
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].desc =
            "BacNetIp content modifier to match on the bacnetip buffers";
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].Setup = DetectBacNetIpbacnet_bvlcfunSetup;
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].Free  = DetectBacNetIpbacnet_bvlcfunFree;
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].Match = NULL;
    sigmatch_table[DETECT_AL_BACNETIP_BACNET_BVLCFUN].AppLayerTxMatch = DetectBacnetBvlcFunMatch;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2(
            "bacnetip.bvlcfun", ALPROTO_BACNETIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, 1);

    DetectAppLayerInspectEngineRegister2(
            "bacnetip.bvlcfun", ALPROTO_BACNETIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, 1);

    g_bacnetip_rust_id = DetectBufferTypeGetByName("bacnetip.bvlcfun");

    SCLogNotice("BacNetIp application layer detect registered.");
}

static int DetectBacNetIpbacnet_bvlcfunSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (DetectSignatureSetAppProto(s, ALPROTO_BACNETIP) != 0) {
        return -1;
    }

    void *detect = rs_detect_bacnetip_bvlcfunc_parse(str);
    if (detect == NULL) {
        SCLogError("failed to parse dns.opcode: %s", str);
        return -1;
    }

    SigMatch *sm = SigMatchAlloc();
    if (unlikely(sm == NULL)) {
        goto error;
    }

    sm->type = DETECT_AL_BACNETIP_BACNET_BVLCFUN;
    sm->ctx = (void *)detect;
    SigMatchAppendSMToList(s, sm, g_bacnetip_rust_id);
    
    SCReturnInt(0);

error:
    DetectBacNetIpbacnet_bvlcfunFree(de_ctx, detect);
    SCReturnInt(-1);
}

static void DetectBacNetIpbacnet_bvlcfunFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        rs_bacnetip_detect_bvlcfunc_free(ptr);
    }
    SCReturn;
}

static int DetectBacnetBvlcFunMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    return rs_bacnet_bvlcfunc_match(txv, (void *)ctx, flags);
}
