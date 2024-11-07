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

#include "detect-vlan-id.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"

extern const int8_t ANY_VLAN_LAYER;
extern const int8_t ALL_VLAN_LAYERS;

static int DetectVlanIdMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->vlan_idx == 0) {
        return 0;
    }

    const DetectVlanIdData *vdata = (const DetectVlanIdData *)ctx;
    if (vdata->layer == ANY_VLAN_LAYER) {
        for (int i = 0; i < p->vlan_idx; i++) {
            if (DetectU16Match(p->vlan_id[i], &vdata->du16)) {
                return 1;
            }
        }
    }
    if (vdata->layer == ALL_VLAN_LAYERS) {
        for (int i = 0; i < p->vlan_idx; i++) {
            if (!DetectU16Match(p->vlan_id[i], &vdata->du16)) {
                return 0;
            }
        }
        return 1;
    } else {
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
    return 0;
}

static void DetectVlanIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    rs_detect_vlan_id_free(ptr);
}

static int DetectVlanIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectVlanIdData *vdata = rs_detect_vlan_id_parse(rawstr);
    if (vdata == NULL) {
        SCLogError("vlan id invalid %s", rawstr);
        return -1;
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_VLAN_ID, (SigMatchCtx *)vdata, DETECT_SM_LIST_MATCH) == NULL) {
        DetectVlanIdFree(de_ctx, vdata);
        return -1;
    }
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;
}

static void PrefilterPacketVlanIdMatch(DetectEngineThreadCtx *det_ctx, Packet *p, const void *pectx)
{
    if (p->vlan_idx == 0)
        return;

    const PrefilterPacketHeaderCtx *ctx = pectx;

    DetectVlanIdData vdata;
    vdata.du16.mode = ctx->v1.u8[0];
    vdata.layer = ctx->v1.u8[1];
    vdata.du16.arg1 = ctx->v1.u16[2];
    vdata.du16.arg2 = ctx->v1.u16[3];
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
    return PrefilterSetupPacketHeader(de_ctx, sgh, DETECT_VLAN_ID, SIG_MASK_REQUIRE_FLOW,
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
