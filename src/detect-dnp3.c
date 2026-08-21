/* Copyright (C) 2015-2022 Open Information Security Foundation
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
 * DNP3 rule keywords, all scoped to ALPROTO_DNP3 and matched per
 * transaction:
 *   dnp3_func  application function code (u8)
 *   dnp3_ind   response internal indicator flags (u16 bitfield)
 *   dnp3_obj   presence of a (group, variation) object pair
 *   dnp3.data  sticky buffer over the reassembled app-layer buffer
 *
 * func/ind/obj live on their own inspection lists. dnp3.data
 * registers inspect + MPM engines for both directions and exposes
 * the transaction buffer via GetDNP3Data. Request-vs-response
 * filtering happens at match time from tx->is_request.
 */

#include "suricata-common.h"
#include "stream.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-dnp3.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-engine-uint.h"

#include "app-layer-dnp3.h"
#include "util-byte.h"

static int g_dnp3_match_buffer_id = 0;
static int g_dnp3_data_buffer_id = 0;
static int g_dnp3_ind_buffer_id = 0;
/** dnp3_obj context: the (group, variation) pair to look for. */
typedef struct DetectDNP3_ {
    uint8_t obj_group;
    uint8_t obj_variation;
} DetectDNP3;

#ifdef UNITTESTS
static void DetectDNP3FuncRegisterTests(void);
static void DetectDNP3ObjRegisterTests(void);
#endif

/** \brief Inspection buffer accessor for dnp3.data. Returns NULL
 *         when the direction doesn't match the transaction side,
 *         so the wrong side's payload can't leak into a match. */
static InspectionBuffer *GetDNP3Data(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    SCLogDebug("list_id %d", list_id);
    InspectionBuffer *buffer = SCInspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        DNP3Transaction *tx = (DNP3Transaction *)txv;
        SCLogDebug("tx %p", tx);

        if ((flow_flags & STREAM_TOSERVER && !tx->is_request) ||
                (flow_flags & STREAM_TOCLIENT && tx->is_request)) {
            return NULL;
        }

        if (tx->buffer == NULL || tx->buffer_len == 0) {
            return NULL;
        }

        SCLogDebug("tx %p data %p data_len %u", tx, tx->buffer, tx->buffer_len);
        SCInspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, tx->buffer, tx->buffer_len, transforms);
    }
    return buffer;
}

static void DetectDNP3FuncFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU8Free(ptr);
}

static int DetectDNP3FuncSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (SCDetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

    DetectU8Data *detect = SCDnp3DetectFuncParse(str);
    if (detect == NULL) {
        SCLogError("Invalid argument \"%s\" supplied to dnp3_func keyword.", str);
        return -1;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_DNP3FUNC, (SigMatchCtx *)detect,
                g_dnp3_match_buffer_id) == NULL) {
        goto error;
    }

    SCReturnInt(0);
error:
    if (detect != NULL) {
        DetectDNP3FuncFree(NULL, detect);
    }
    SCReturnInt(-1);
}

static void DetectDNP3IndFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCDetectU16Free(ptr);
}

static int DetectDNP3IndSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    if (SCDetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

        DetectU16Data *detect = SCDnp3DetectIndParse(str);
    if (detect == NULL) {
        SCLogError("Invalid argument \"%s\" supplied to dnp3.ind keyword.", str);
        return -1;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_DNP3IND, (SigMatchCtx *)detect, g_dnp3_ind_buffer_id) == NULL) {
        goto error;
    }

    SCReturnInt(0);
error:
    if (detect != NULL) {
        DetectDNP3IndFree(NULL, detect);
    }
    SCReturnInt(-1);
}

/**
 * \brief Parse the value of string of the dnp3_obj keyword.
 *
 * \param str the input string
 * \param gout pointer to variable to store the parsed group integer
 * \param vout pointer to variable to store the parsed variation integer
 *
 * \retval 1 if parsing successful otherwise 0.
 */
static int DetectDNP3ObjParse(const char *str, uint8_t *group, uint8_t *var)
{
    size_t size = strlen(str) + 1;
    char groupstr[size], *varstr, *sep;
    strlcpy(groupstr, str, size);

    sep = strchr(groupstr, ',');
    if (sep == NULL) {
        return 0;
    }
    *sep = '\0';
    varstr = sep + 1;

    if (StringParseUint8(group, 0, (uint16_t)strlen(groupstr), groupstr) <= 0) {
        return 0;
    }

    if (StringParseUint8(var, 0, (uint16_t)strlen(varstr), varstr) <= 0) {
        return 0;
    }

    return 1;
}

static int DetectDNP3ObjSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    uint8_t group;
    uint8_t variation;
    DetectDNP3 *detect = NULL;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

        if (!DetectDNP3ObjParse(str, &group, &variation)) {
        goto fail;
    }

    detect = SCCalloc(1, sizeof(*detect));
    if (unlikely(detect == NULL)) {
        goto fail;
    }
    detect->obj_group = group;
    detect->obj_variation = variation;

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_DNP3OBJ, (SigMatchCtx *)detect, g_dnp3_match_buffer_id) == NULL) {
        goto fail;
    }

    SCReturnInt(1);
fail:
    if (detect != NULL) {
        SCFree(detect);
    }
    SCReturnInt(0);
}

static void DetectDNP3Free(DetectEngineCtx *de_ctx, void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        SCFree(ptr);
    }
    SCReturn;
}

/** \brief Match function code, gated on direction. Requests go
 *         toserver, responses toclient; wrong direction is a
 *         non-match. */
static int DetectDNP3FuncMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectU8Data *detect = (DetectU8Data *)ctx;

    if (flags & STREAM_TOSERVER && tx->is_request) {
        return DetectU8Match(tx->ah.function_code, detect);
    } else if (flags & STREAM_TOCLIENT && !tx->is_request) {
        return DetectU8Match(tx->ah.function_code, detect);
    }

    return 0;
}

/** \brief Match if any object in the transaction has the
 *         configured (group, variation). Linear scan; DNP3 object
 *         lists are usually short. */
static int DetectDNP3ObjMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectDNP3 *detect = (DetectDNP3 *)ctx;
    DNP3ObjectList *objects = NULL;

    if (flags & STREAM_TOSERVER && tx->is_request) {
        objects = &tx->objects;
    } else if (flags & STREAM_TOCLIENT && !tx->is_request) {
        objects = &tx->objects;
    }

    if (objects != NULL) {
        DNP3Object *object;
        TAILQ_FOREACH(object, objects, next) {
            if (object->group == detect->obj_group &&
                object->variation == detect->obj_variation) {
                return 1;
            }
        }
    }

    return 0;
}

/** \brief Match on the packed IIN1|IIN2 word (IIN1 high, IIN2 low)
 *         from the response header. */
static int DetectDNP3IndMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectU16Data *detect = (DetectU16Data *)ctx;

    return DetectU16Match((uint16_t)((tx->iin.iin1 << 8) | tx->iin.iin2), detect);
}

static void DetectDNP3FuncRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_DNP3FUNC].name = "dnp3_func";
    sigmatch_table[DETECT_DNP3FUNC].alias = "dnp3.func";
    sigmatch_table[DETECT_DNP3FUNC].desc =
            "match on the application function code found in DNP3 request and responses";
    sigmatch_table[DETECT_DNP3FUNC].url = "/rules/dnp3-keywords.html#dnp3-func";
    sigmatch_table[DETECT_DNP3FUNC].Match = NULL;
    sigmatch_table[DETECT_DNP3FUNC].AppLayerTxMatch = DetectDNP3FuncMatch;
    sigmatch_table[DETECT_DNP3FUNC].Setup = DetectDNP3FuncSetup;
    sigmatch_table[DETECT_DNP3FUNC].Free = DetectDNP3FuncFree;
    sigmatch_table[DETECT_DNP3FUNC].flags = SIGMATCH_INFO_UINT8 | SIGMATCH_INFO_ENUM_UINT;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DNP3FUNC].RegisterTests = DetectDNP3FuncRegisterTests;
#endif
    SCReturn;
}

static void DetectDNP3IndRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_DNP3IND].name = "dnp3_ind";
    sigmatch_table[DETECT_DNP3IND].alias = "dnp3.ind";
    sigmatch_table[DETECT_DNP3IND].desc =
            "match on the DNP3 internal indicator flags in the response application header";
    sigmatch_table[DETECT_DNP3IND].url = "/rules/dnp3-keywords.html#dnp3-ind";
    sigmatch_table[DETECT_DNP3IND].Match = NULL;
    sigmatch_table[DETECT_DNP3IND].AppLayerTxMatch = DetectDNP3IndMatch;
    sigmatch_table[DETECT_DNP3IND].Setup = DetectDNP3IndSetup;
    sigmatch_table[DETECT_DNP3IND].Free = DetectDNP3IndFree;
    sigmatch_table[DETECT_DNP3IND].flags = SIGMATCH_INFO_UINT16 | SIGMATCH_INFO_BITFLAGS_UINT;

    SCReturn;
}

static void DetectDNP3ObjRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_DNP3OBJ].name = "dnp3_obj";
    sigmatch_table[DETECT_DNP3OBJ].alias = "dnp3.obj";
    sigmatch_table[DETECT_DNP3OBJ].desc = "match on the DNP3 application data objects";
    sigmatch_table[DETECT_DNP3OBJ].url = "/rules/dnp3-keywords.html#dnp3-obj";
    sigmatch_table[DETECT_DNP3OBJ].Match = NULL;
    sigmatch_table[DETECT_DNP3OBJ].AppLayerTxMatch = DetectDNP3ObjMatch;
    sigmatch_table[DETECT_DNP3OBJ].Setup = DetectDNP3ObjSetup;
    sigmatch_table[DETECT_DNP3OBJ].Free = DetectDNP3Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_DNP3OBJ].RegisterTests = DetectDNP3ObjRegisterTests;
#endif
    SCReturn;
}

static int DetectDNP3DataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    if (SCDetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

    if (SCDetectBufferSetActiveList(de_ctx, s, g_dnp3_data_buffer_id) != 0)
        return -1;

    SCReturnInt(0);
}
/** \brief Register the dnp3.data sticky buffer. Inspect + MPM
 *         engines are registered for both directions; direction
 *         filtering happens inside GetDNP3Data. */
static void DetectDNP3DataRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_DNP3DATA].name = "dnp3.data";
    sigmatch_table[DETECT_DNP3DATA].alias = "dnp3_data";
    sigmatch_table[DETECT_DNP3DATA].desc =
            "make the following content options to match on the re-assembled application buffer";
    sigmatch_table[DETECT_DNP3DATA].url = "/rules/dnp3-keywords.html#dnp3-data";
    sigmatch_table[DETECT_DNP3DATA].Setup = DetectDNP3DataSetup;
    sigmatch_table[DETECT_DNP3DATA].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister("dnp3_data", ALPROTO_DNP3, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetDNP3Data);
    DetectAppLayerMpmRegister("dnp3_data", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetDNP3Data, ALPROTO_DNP3, 0);

            DetectAppLayerInspectEngineRegister("dnp3_data", ALPROTO_DNP3, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetDNP3Data);
    DetectAppLayerMpmRegister("dnp3_data", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetDNP3Data, ALPROTO_DNP3, 0);

            g_dnp3_data_buffer_id = DetectBufferTypeGetByName("dnp3_data");
    SCReturn;
}
/** \brief Register all four DNP3 keywords and their engines. */
void DetectDNP3Register(void)
{
    DetectDNP3DataRegister();

    DetectDNP3FuncRegister();
    DetectDNP3IndRegister();
    DetectDNP3ObjRegister();
    /* shared "dnp3" list carries func + obj matches, both directions */
    DetectAppLayerInspectEngineRegister(
            "dnp3", ALPROTO_DNP3, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister(
            "dnp3", ALPROTO_DNP3, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);
            g_dnp3_match_buffer_id = DetectBufferTypeRegister("dnp3");
    /* dnp3_ind is response-only */
    DetectAppLayerInspectEngineRegister(
            "dnp3_ind", ALPROTO_DNP3, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);
    g_dnp3_ind_buffer_id = DetectBufferTypeRegister("dnp3_ind");
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "flow-util.h"
#include "stream-tcp.h"

/** \test dnp3_func:2 parses and lands on the dnp3 match list. */
static int DetectDNP3FuncTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert dnp3 any any -> any any "
                                                 "(msg:\"SURICATA DNP3 Write request\"; "
                                                 "dnp3_func:2; sid:5000009; rev:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_dnp3_match_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->ctx);

    DetectU8Data *dnp3func = (DetectU8Data *)sm->ctx;
    FAIL_IF(dnp3func->arg1 != 2);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test dnp3_obj:99,99 stores group and variation on the ctx. */
static int DetectDNP3ObjSetupTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert dnp3 any any -> any any "
                                                 "(msg:\"SURICATA DNP3 Object Test\"; "
                                                 "dnp3_obj:99,99; sid:1; rev:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_dnp3_match_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NULL(sm->ctx);

    DetectDNP3 *detect = (DetectDNP3 *)sm->ctx;
    FAIL_IF(detect->obj_group != 99);
    FAIL_IF(detect->obj_variation != 99);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test dnp3_obj parser: valid u8, rejects overflow and non-numeric. */
static int DetectDNP3ObjParseTest(void)
{
    uint8_t group, var;

    FAIL_IF(!DetectDNP3ObjParse("0,0", &group, &var));
    FAIL_IF(group != 0 || var != 0);

    FAIL_IF(!DetectDNP3ObjParse("255,255", &group, &var));
    FAIL_IF(group != 255 || var != 255);

    FAIL_IF(DetectDNP3ObjParse("-1,-1", &group, &var));
    FAIL_IF(DetectDNP3ObjParse("256,256", &group, &var));
    FAIL_IF(DetectDNP3ObjParse("a,1", &group, &var));
    FAIL_IF(DetectDNP3ObjParse("1,a", &group, &var));

    PASS;
}

static void DetectDNP3FuncRegisterTests(void)
{
    UtRegisterTest("DetectDNP3FuncTest01", DetectDNP3FuncTest01);
}

static void DetectDNP3ObjRegisterTests(void)
{
    UtRegisterTest("DetectDNP3ObjParseTest", DetectDNP3ObjParseTest);
    UtRegisterTest("DetectDNP3ObjSetupTest", DetectDNP3ObjSetupTest);
}
#endif
