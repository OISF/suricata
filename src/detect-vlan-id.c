/* Copyright (C) 2022 Open Information Security Foundation
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
#include "detect-vlan-id.h"
#include "detect-engine.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-uint.h"
#include "detect-parse.h"
#include "util-byte.h"

#ifdef UNITTESTS
static void DetectVlanIdRegisterTests(void);
#endif

#define PARSE_REGEX "^([0-9]+)(?:,\\s*([0-9]|any))?$"

static DetectParseRegex parse_regex;

static int DetectVlanIdMatch(
        DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    if (p->vlan_idx == 0) {
        return 0;
    }

    const DetectVlanIdData *vdata = (const DetectVlanIdData *)ctx;
    for (int i = 0; i < p->vlan_idx; i++) {
        if (p->vlan_id[i] == vdata->id && (vdata->layer == ANY || vdata->layer - 1 == i))
            return 1;
    }

    return 0;
}

static void DetectVlanIdFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectVlanIdData *data = ptr;
    SCFree(data);
}

static DetectVlanIdData *DetectVlanIdParse(DetectEngineCtx *de_ctx, const char *rawstr)
{
    DetectVlanIdData *vdata = NULL;
    int res = 0;
    size_t pcre2_len;
    pcre2_match_data *match = NULL;

    int count = DetectParsePcreExec(&parse_regex, &match, rawstr, 0, 0);
    if (count != 2 && count != 3) {
        SCLogError("\"%s\" is not a valid setting for vlan-id.", rawstr);
        goto error;
    }

    const char *str_ptr;
    res = SC_Pcre2SubstringGet(match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError("pcre2_substring_get_bynumber failed");
        goto error;
    }

    vdata = SCMalloc(sizeof(DetectVlanIdData));
    if (unlikely(vdata == NULL))
        goto error;

    if (StringParseUint16(&vdata->id, 10, 0, str_ptr) < 0) {
        SCLogError("specified vlan id %s is not valid", str_ptr);
        goto error;
    }
    vdata->layer = ANY;

    if (count == 3) {
        res = SC_Pcre2SubstringGet(match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }

        if (strcasecmp(str_ptr, "any") != 0) {
            if (StringParseUint8(&vdata->layer, 10, 0, str_ptr) < 0) {
                SCLogError("specified vlan layer %s is not valid", str_ptr);
                goto error;
            }
        }
    }

    if (vdata->layer > VLAN_MAX_LAYERS) {
        SCLogError("specified vlan layer %s is not valid", str_ptr);
        goto error;
    }

    if (vdata->id == 0 || vdata->id >= 4095) {
        SCLogError("specified vlan id %s is not valid. Valid range 1-4094", str_ptr);
        goto error;
    }

    pcre2_match_data_free(match);
    return vdata;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    if (vdata != NULL) {
        DetectVlanIdFree(de_ctx, vdata);
    }
    return NULL;
}

static int DetectVlanIdSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(de_ctx, rawstr);
    if (vdata == NULL)
        return -1;

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
    const PrefilterPacketHeaderCtx *ctx = pectx;

    for (int i = 0; i < p->vlan_idx; i++) {
        if (p->vlan_id[i] == ctx->v1.u16[0] && (ctx->v1.u8[0] == ANY || ctx->v1.u8[0] - 1 == i))
            PrefilterAddSids(&det_ctx->pmq, ctx->sigs_array, ctx->sigs_cnt);
    }
}

static void PrefilterPacketVlanIdSet(PrefilterPacketHeaderValue *v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    v->u16[0] = a->id;
    v->u8[0] = a->layer;
}

static bool PrefilterPacketVlanIdCompare(PrefilterPacketHeaderValue v, void *smctx)
{
    const DetectVlanIdData *a = smctx;
    if (v.u16[0] == a->id && v.u8[0] == a->layer)
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
    sigmatch_table[DETECT_VLAN_ID].url = "/rules/vlan-id-keyword.html";
    sigmatch_table[DETECT_VLAN_ID].Match = DetectVlanIdMatch;
    sigmatch_table[DETECT_VLAN_ID].Setup = DetectVlanIdSetup;
    sigmatch_table[DETECT_VLAN_ID].Free = DetectVlanIdFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_VLAN_ID].RegisterTests = DetectVlanIdRegisterTests;
#endif
    sigmatch_table[DETECT_VLAN_ID].SupportsPrefilter = PrefilterVlanIdIsPrefilterable;
    sigmatch_table[DETECT_VLAN_ID].SetupPrefilter = PrefilterSetupVlanId;
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-engine-mpm.h"

/**
 * \test DetectVlanIdParseTest01 is a test for setting a valid vlan id value
 */
static int DetectVlanIdParseTest01(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "300");
    FAIL_IF_NULL(vdata);
    FAIL_IF_NOT(vdata->id == 300);
    DetectVlanIdFree(NULL, vdata);
    PASS;
}

/**
 * \test DetectVlanIdParseTest02 is a test for setting a valid vlan id value and a specific vlan
 * layer
 */
static int DetectVlanIdParseTest02(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "200,1");
    FAIL_IF_NULL(vdata);
    FAIL_IF_NOT(vdata->id == 200);
    FAIL_IF_NOT(vdata->layer == 1);
    DetectVlanIdFree(NULL, vdata);
    PASS;
}

/**
 * \test DetectVlanIdParseTest03 is a test for setting a valid vlan id value and explicit "any" vlan
 * layer
 */
static int DetectVlanIdParseTest03(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "200,any");
    FAIL_IF_NULL(vdata);
    FAIL_IF_NOT(vdata->id == 200);
    FAIL_IF_NOT(vdata->layer == 0);
    DetectVlanIdFree(NULL, vdata);
    PASS;
}

/**
 * \test DetectVlanIdParseTest04 is a test for setting a invalid vlan id value
 */
static int DetectVlanIdParseTest04(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "200abc");
    FAIL_IF_NOT_NULL(vdata);
    PASS;
}

/**
 * \test DetectVlanIdParseTest05 is a test for setting a invalid vlan id value that is out of range
 */
static int DetectVlanIdParseTest05(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "4096");
    FAIL_IF_NOT_NULL(vdata);
    PASS;
}

/**
 * \test DetectVlanIdParseTest06 is a test for setting a invalid vlan layer
 */
static int DetectVlanIdParseTest06(void)
{
    DetectVlanIdData *vdata = DetectVlanIdParse(NULL, "600,abc");
    FAIL_IF_NOT_NULL(vdata);
    PASS;
}

static void DetectVlanIdRegisterTests(void)
{
    UtRegisterTest("DetectVlanIdParseTest01", DetectVlanIdParseTest01);
    UtRegisterTest("DetectVlanIdParseTest02", DetectVlanIdParseTest02);
    UtRegisterTest("DetectVlanIdParseTest03", DetectVlanIdParseTest03);
    UtRegisterTest("DetectVlanIdParseTest04", DetectVlanIdParseTest04);
    UtRegisterTest("DetectVlanIdParseTest05", DetectVlanIdParseTest05);
    UtRegisterTest("DetectVlanIdParseTest06", DetectVlanIdParseTest06);
}
#endif /* UNITTESTS */