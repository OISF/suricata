/* Copyright (C) 2024 Open Information Security Foundation
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

#include "detect-vlan.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"
#include "rust.h"

static int DetectVlanIdMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectVlanIdData *vdata = (const DetectVlanIdData *)ctx;

    if (p->vlan_idx == 0) {
        return 0;
    }

    switch (vdata->layer) {
        case DETECT_VLAN_ID_ANY:
            for (int i = 0; i < p->vlan_idx; i++) {
                if (DetectU16Match(p->vlan_id[i], &vdata->du16)) {
                    return 1;
                }
            }
            return 0;
        case DETECT_VLAN_ID_ALL:
            for (int i = 0; i < p->vlan_idx; i++) {
                if (!DetectU16Match(p->vlan_id[i], &vdata->du16)) {
                    return 0;
                }
            }
            return 1;
        default:
            if (vdata->layer < 0) { // Negative layer values for backward indexing.
                if (((int16_t)p->vlan_idx) + vdata->layer < 0) {
                    return 0;
                }
                return DetectU16Match(p->vlan_id[p->vlan_idx + vdata->layer], &vdata->du16);
            } else {
                if (p->vlan_idx < vdata->layer) {
                    return 0;
                }
                return DetectU16Match(p->vlan_id[vdata->layer], &vdata->du16);
            }
    }
}

static void DetectVlanIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectVlanIdFree(ptr);
}

static int DetectVlanIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectVlanIdData *vdata = SCDetectVlanIdParse(rawstr);
    if (vdata == NULL) {
        SCLogError("vlan id invalid %s", rawstr);
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_VLAN_ID, (SigMatchCtx *)vdata, DETECT_SM_LIST_MATCH) == NULL) {
        DetectVlanIdFree(de_ctx, vdata);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketVlanIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    DetectVlanIdData vdata;
    vdata.du16.mode = ctx->v1.u8[0];
    vdata.layer = ctx->v1.u8[1];
    vdata.du16.arg1 = ctx->v1.u16[2];
    vdata.du16.arg2 = ctx->v1.u16[3];

    if (p->vlan_idx == 0)
        return;

    if (DetectVlanIdMatch(det_ctx, p, NULL, (const SigMatchCtx *)&vdata)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketVlanIdSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    v->u8[0] = a->du16.mode;
    v->u8[1] = a->layer;
    v->u16[2] = a->du16.arg1;
    v->u16[3] = a->du16.arg2;
}

static bool PrefilterPacketVlanIdCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    if (v.u8[0] == a->du16.mode && v.u8[1] == a->layer && v.u16[2] == a->du16.arg1 &&
            v.u16[3] == a->du16.arg2)
        return true;
    return false;
}

static int PrefilterSetupVlanId(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_VLAN_ID, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketVlanIdSet, PrefilterPacketVlanIdCompare, PrefilterPacketVlanIdMatch);
}

static bool PrefilterVlanIdIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_VLAN_ID);
}

void DetectVlanIdRegister(void)
{
    sigmatch_table[DETECT_VLAN_ID].name = "vlan.id";
    sigmatch_table[DETECT_VLAN_ID].desc = "match vlan id";
    sigmatch_table[DETECT_VLAN_ID].url = "/rules/vlan-keywords.html#vlan-id";
    sigmatch_table[DETECT_VLAN_ID].Match = DetectVlanIdMatch;
    sigmatch_table[DETECT_VLAN_ID].Setup = DetectVlanIdSetup;
    sigmatch_table[DETECT_VLAN_ID].Free = DetectVlanIdFree;
    sigmatch_table[DETECT_VLAN_ID].SupportsPrefilter = PrefilterVlanIdIsPrefilterable;
    sigmatch_table[DETECT_VLAN_ID].SetupPrefilter = PrefilterSetupVlanId;
}

static int DetectVlanLayersMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t nb = p->vlan_idx;

    const DetectU8Data *du8 = (const DetectU8Data *)ctx;
    return DetectU8Match(nb, du8);
}

static void DetectVlanLayersFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8Free(ptr);
}

static int DetectVlanLayersSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectU8Data *du8 = DetectU8Parse(rawstr);

    if (du8 == NULL) {
        SCLogError("vlan layers invalid %s", rawstr);
        return -1;
    }

    if (du8->arg1 > VLAN_MAX_LAYERS || du8->arg2 > VLAN_MAX_LAYERS) {
        SCLogError("number of layers out of range %s", rawstr);
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_VLAN_LAYERS, (SigMatchCtx *)du8, DETECT_SM_LIST_MATCH) == NULL) {
        DetectVlanLayersFree(de_ctx, du8);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketVlanLayersMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    const PrefilterPacketHeaderCtx *ctx = pectx;

    DetectU8Data du8;
    du8.mode = ctx->v1.u8[0];
    du8.arg1 = ctx->v1.u8[1];
    du8.arg2 = ctx->v1.u8[2];

    if (DetectVlanLayersMatch(det_ctx, p, NULL, (const SigMatchCtx *)&du8)) {
        PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static int PrefilterSetupVlanLayers(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_VLAN_LAYERS, SIG_MASK_REQUIRE_REAL_PKT,
            PrefilterPacketU8Set, PrefilterPacketU8Compare, PrefilterPacketVlanLayersMatch);
}

static bool PrefilterVlanLayersIsPrefilterable(const Signature *s)
{
    return PrefilterIsPrefilterableById(s, DETECT_VLAN_LAYERS);
}

void DetectVlanLayersRegister(void)
{
    sigmatch_table[DETECT_VLAN_LAYERS].name = "vlan.layers";
    sigmatch_table[DETECT_VLAN_LAYERS].desc = "match number of vlan layers";
    sigmatch_table[DETECT_VLAN_LAYERS].url = "/rules/vlan-keywords.html#vlan-layers";
    sigmatch_table[DETECT_VLAN_LAYERS].Match = DetectVlanLayersMatch;
    sigmatch_table[DETECT_VLAN_LAYERS].Setup = DetectVlanLayersSetup;
    sigmatch_table[DETECT_VLAN_LAYERS].Free = DetectVlanLayersFree;
    sigmatch_table[DETECT_VLAN_LAYERS].SupportsPrefilter = PrefilterVlanLayersIsPrefilterable;
    sigmatch_table[DETECT_VLAN_LAYERS].SetupPrefilter = PrefilterSetupVlanLayers;
}
