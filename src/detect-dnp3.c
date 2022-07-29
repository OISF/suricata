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

#include "suricata-common.h"

#include "detect-parse.h"
#include "detect-dnp3.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "app-layer-dnp3.h"
#include "util-byte.h"

static int g_dnp3_match_buffer_id = 0;
static int g_dnp3_data_buffer_id = 0;

/**
 * The detection struct.
 */
typedef struct DetectDNP3_ {
    union {
        struct {
            /* Function code for function code detection. */
            uint8_t  function_code;
        };
        struct {
            /* Internal indicator flags for IIN detection. */
            uint16_t ind_flags;
        };
        struct {
            /* Object info for object detection. */
            uint8_t  obj_group;
            uint8_t  obj_variation;
        };
    };
} DetectDNP3;

/**
 * Indicator names to value mappings (Snort compatible).
 */
DNP3Mapping DNP3IndicatorsMap[] = {
    {"device_restart",        0x8000},
    {"device_trouble",        0x4000},
    {"local_control",         0x2000},
    {"need_time",             0x1000},
    {"class_3_events",        0x0800},
    {"class_2_events",        0x0400},
    {"class_1_events",        0x0200},
    {"all_stations",          0x0100},

    {"reserved_1",            0x0080},
    {"reserved_2",            0x0040},
    {"config_corrupt",        0x0020},
    {"already_executing",     0x0010},
    {"event_buffer_overflow", 0x0008},
    {"parameter_error",       0x0004},
    {"object_unknown",        0x0002},
    {"no_func_code_support",  0x0001},

    {NULL, 0},
};

/**
 * Application function code name to code mappings (Snort compatible).
 */
DNP3Mapping DNP3FunctionNameMap[] = {
    {"confirm",              0},
    {"read",                 1},
    {"write",                2},
    {"select",               3},
    {"operate",              4},
    {"direct_operate",       5},
    {"direct_operate_nr",    6},
    {"immed_freeze",         7},
    {"immed_freeze_nr",      8},
    {"freeze_clear",         9},
    {"freeze_clear_nr",      10},
    {"freeze_at_time",       11},
    {"freeze_at_time_nr",    12},
    {"cold_restart",         13},
    {"warm_restart",         14},
    {"initialize_data",      15},
    {"initialize_appl",      16},
    {"start_appl",           17},
    {"stop_appl",            18},
    {"save_config",          19},
    {"enable_unsolicited",   20},
    {"disable_unsolicited",  21},
    {"assign_class",         22},
    {"delay_measure",        23},
    {"record_current_time",  24},
    {"open_file",            25},
    {"close_file",           26},
    {"delete_file",          27},
    {"get_file_info",        28},
    {"authenticate_file",    29},
    {"abort_file",           30},
    {"activate_config",      31},
    {"authenticate_req",     32},
    {"authenticate_err",     33},
    {"response",             129},
    {"unsolicited_response", 130},
    {"authenticate_resp",    131}
};

#ifdef UNITTESTS
static void DetectDNP3FuncRegisterTests(void);
static void DetectDNP3IndRegisterTests(void);
static void DetectDNP3ObjRegisterTests(void);
#endif

/**
 * \brief Utility function to trim leading and trailing whitespace
 *     from a string.
 */
static char *TrimString(char *str)
{
    char *end = str + strlen(str) - 1;
    while (isspace(*str)) {
        str++;
    }
    while (end > str && isspace(*end)) {
        end--;
    }
    *(end + 1) = '\0';
    return str;
}

static InspectionBuffer *GetDNP3Data(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    SCLogDebug("list_id %d", list_id);
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        DNP3Transaction *tx = (DNP3Transaction *)txv;
        SCLogDebug("tx %p", tx);

        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        }
        if (data == NULL || data_len == 0)
            return NULL;

        SCLogDebug("tx %p data %p data_len %u", tx, data, data_len);
        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

/**
 * \brief Parse the provided function name or code to its integer
 *     value.
 *
 * If the value passed is a number, it will be checked that it falls
 * within the range of valid function codes.  If function name is
 * passed it will be resolved to its function code.
 *
 * \retval The function code as an integer if successul, -1 on
 *     failure.
 */
static int DetectDNP3FuncParseFunctionCode(const char *str, uint8_t *fc)
{
    if (StringParseUint8(fc, 10, (uint16_t)strlen(str), str) >= 0) {
        return 1;
    }

    /* Lookup by name. */
    for (size_t i = 0;
            i < sizeof(DNP3FunctionNameMap) / sizeof(DNP3Mapping); i++) {
        if (strcasecmp(str, DNP3FunctionNameMap[i].name) == 0) {
            *fc = (uint8_t)(DNP3FunctionNameMap[i].value);
            return 1;
        }
    }

    return 0;
}

static int DetectDNP3FuncSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectDNP3 *dnp3 = NULL;
    SigMatch *sm = NULL;
    uint8_t function_code;

    if (DetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

    if (!DetectDNP3FuncParseFunctionCode(str, &function_code)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "Invalid argument \"%s\" supplied to dnp3_func keyword.", str);
        return -1;
    }

    dnp3 = SCCalloc(1, sizeof(DetectDNP3));
    if (unlikely(dnp3 == NULL)) {
        goto error;
    }
    dnp3->function_code = function_code;

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }
    sm->type = DETECT_AL_DNP3FUNC;
    sm->ctx = (void *)dnp3;

    SigMatchAppendSMToList(s, sm, g_dnp3_match_buffer_id);

    SCReturnInt(0);
error:
    if (dnp3 != NULL) {
        SCFree(dnp3);
    }
    if (sm != NULL) {
        SCFree(sm);
    }
    SCReturnInt(-1);
}

static int DetectDNP3IndParseByName(const char *str, uint16_t *flags)
{
    char tmp[strlen(str) + 1];
    char *p, *last = NULL;

    strlcpy(tmp, str, sizeof(tmp));

    for ((p = strtok_r(tmp, ",", &last)); p; (p = strtok_r(NULL, ",", &last))) {
        p = TrimString(p);
        int found = 0;
        int i = 0;
        while (DNP3IndicatorsMap[i].name != NULL) {
            if (strcasecmp(p, DNP3IndicatorsMap[i].name) == 0) {
                *flags |= DNP3IndicatorsMap[i].value;
                found = 1;
                break;
            }
            i++;
        }

        if (!found) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                "Bad argument \"%s\" supplied to dnp3.ind keyword.", p);
            return 0;
        }
    }

    return 1;
}

static int DetectDNP3IndParse(const char *str, uint16_t *flags)
{
    *flags = 0;

    if (StringParseUint16(flags, 0, (uint16_t)strlen(str), str) > 0) {
        return 1;
    }

    /* Parse by name - will log a more specific error message on error. */
    if (DetectDNP3IndParseByName(str, flags)) {
        return 1;
    }

    return 0;
}

static int DetectDNP3IndSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    DetectDNP3 *detect = NULL;
    SigMatch *sm = NULL;
    uint16_t flags;

    if (DetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

    if (!DetectDNP3IndParse(str, &flags)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "Invalid argument \"%s\" supplied to dnp3.ind keyword.", str);
        return -1;
    }

    detect = SCCalloc(1, sizeof(DetectDNP3));
    if (unlikely(detect == NULL)) {
        goto error;
    }
    detect->ind_flags = flags;

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }
    sm->type = DETECT_AL_DNP3IND;
    sm->ctx = (void *)detect;
    SigMatchAppendSMToList(s, sm, g_dnp3_match_buffer_id);

    SCReturnInt(0);
error:
    if (detect != NULL) {
        SCFree(detect);
    }
    if (sm != NULL) {
        SCFree(sm);
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

    if (StringParseUint8(group, 0, (uint16_t)strlen(groupstr), groupstr) < 0) {
        return 0;
    }

    if (StringParseUint8(var, 0, (uint16_t)strlen(varstr), varstr) < 0) {
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
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
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

    sm = SigMatchAlloc();
    if (unlikely(sm == NULL)) {
        goto fail;
    }
    sm->type = DETECT_AL_DNP3OBJ;
    sm->ctx = (void *)detect;
    SigMatchAppendSMToList(s, sm, g_dnp3_match_buffer_id);

    SCReturnInt(1);
fail:
    if (detect != NULL) {
        SCFree(detect);
    }
    if (sm != NULL) {
        SCFree(sm);
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

static int DetectDNP3FuncMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectDNP3 *detect = (DetectDNP3 *)ctx;
    int match = 0;

    if (flags & STREAM_TOSERVER) {
        match = detect->function_code == tx->request_ah.function_code;
    }
    else if (flags & STREAM_TOCLIENT) {
        match = detect->function_code == tx->response_ah.function_code;
    }

    return match;
}

static int DetectDNP3ObjMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectDNP3 *detect = (DetectDNP3 *)ctx;
    DNP3ObjectList *objects = NULL;

    if (flags & STREAM_TOSERVER) {
        objects = &tx->request_objects;
    }
    else if (flags & STREAM_TOCLIENT) {
        objects = &tx->response_objects;
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

static int DetectDNP3IndMatch(DetectEngineThreadCtx *det_ctx,
    Flow *f, uint8_t flags, void *state, void *txv, const Signature *s,
    const SigMatchCtx *ctx)
{
    DNP3Transaction *tx = (DNP3Transaction *)txv;
    DetectDNP3 *detect = (DetectDNP3 *)ctx;

    if (flags & STREAM_TOCLIENT) {
        if ((tx->response_iin.iin1 & (detect->ind_flags >> 8)) ||
            (tx->response_iin.iin2 & (detect->ind_flags & 0xf))) {
            return 1;
        }
    }

    return 0;
}

static void DetectDNP3FuncRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3FUNC].name          = "dnp3_func";
    sigmatch_table[DETECT_AL_DNP3FUNC].alias         = "dnp3.func";
    sigmatch_table[DETECT_AL_DNP3FUNC].desc          = "match on the application function code found in DNP3 request and responses";
    sigmatch_table[DETECT_AL_DNP3FUNC].url           = "/rules/dnp3-keywords.html#dnp3-func";
    sigmatch_table[DETECT_AL_DNP3FUNC].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3FUNC].AppLayerTxMatch = DetectDNP3FuncMatch;
    sigmatch_table[DETECT_AL_DNP3FUNC].Setup         = DetectDNP3FuncSetup;
    sigmatch_table[DETECT_AL_DNP3FUNC].Free          = DetectDNP3Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DNP3FUNC].RegisterTests =
        DetectDNP3FuncRegisterTests;
#endif
    SCReturn;
}

static void DetectDNP3IndRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3IND].name          = "dnp3_ind";
    sigmatch_table[DETECT_AL_DNP3IND].alias         = "dnp3.ind";
    sigmatch_table[DETECT_AL_DNP3IND].desc          = "match on the DNP3 internal indicator flags in the response application header";
    sigmatch_table[DETECT_AL_DNP3IND].url           = "/rules/dnp3-keywords.html#dnp3-ind";
    sigmatch_table[DETECT_AL_DNP3IND].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3IND].AppLayerTxMatch = DetectDNP3IndMatch;
    sigmatch_table[DETECT_AL_DNP3IND].Setup         = DetectDNP3IndSetup;
    sigmatch_table[DETECT_AL_DNP3IND].Free          = DetectDNP3Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DNP3IND].RegisterTests =
        DetectDNP3IndRegisterTests;
#endif
    SCReturn;
}

static void DetectDNP3ObjRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3OBJ].name          = "dnp3_obj";
    sigmatch_table[DETECT_AL_DNP3OBJ].alias         = "dnp3.obj";
    sigmatch_table[DETECT_AL_DNP3OBJ].desc          = "match on the DNP3 application data objects";
    sigmatch_table[DETECT_AL_DNP3OBJ].url           = "/rules/dnp3-keywords.html#dnp3-obj";
    sigmatch_table[DETECT_AL_DNP3OBJ].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3OBJ].AppLayerTxMatch = DetectDNP3ObjMatch;
    sigmatch_table[DETECT_AL_DNP3OBJ].Setup         = DetectDNP3ObjSetup;
    sigmatch_table[DETECT_AL_DNP3OBJ].Free          = DetectDNP3Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_DNP3OBJ].RegisterTests =
        DetectDNP3ObjRegisterTests;
#endif
    SCReturn;
}

static int DetectDNP3DataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();
    if (DetectSignatureSetAppProto(s, ALPROTO_DNP3) != 0)
        return -1;

    if (DetectBufferSetActiveList(s, g_dnp3_data_buffer_id) != 0)
        return -1;

    SCReturnInt(0);
}

static void DetectDNP3DataRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3DATA].name          = "dnp3.data";
    sigmatch_table[DETECT_AL_DNP3DATA].alias         = "dnp3_data";
    sigmatch_table[DETECT_AL_DNP3DATA].desc          = "make the following content options to match on the re-assembled application buffer";
    sigmatch_table[DETECT_AL_DNP3DATA].url           = "/rules/dnp3-keywords.html#dnp3-data";
    sigmatch_table[DETECT_AL_DNP3DATA].Setup         = DetectDNP3DataSetup;
    sigmatch_table[DETECT_AL_DNP3DATA].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("dnp3_data",
            ALPROTO_DNP3, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric,
            GetDNP3Data);
    DetectAppLayerMpmRegister2("dnp3_data", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetDNP3Data,
            ALPROTO_DNP3, 0);

    DetectAppLayerInspectEngineRegister2("dnp3_data",
            ALPROTO_DNP3, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric,
            GetDNP3Data);
    DetectAppLayerMpmRegister2("dnp3_data", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetDNP3Data,
            ALPROTO_DNP3, 0);

    g_dnp3_data_buffer_id = DetectBufferTypeGetByName("dnp3_data");
    SCReturn;
}

void DetectDNP3Register(void)
{
    DetectDNP3DataRegister();

    DetectDNP3FuncRegister();
    DetectDNP3IndRegister();
    DetectDNP3ObjRegister();

    /* Register the list of func, ind and obj. */
    DetectAppLayerInspectEngineRegister2(
            "dnp3", ALPROTO_DNP3, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);
    DetectAppLayerInspectEngineRegister2(
            "dnp3", ALPROTO_DNP3, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    g_dnp3_match_buffer_id = DetectBufferTypeRegister("dnp3");

}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "detect-engine.h"

static int DetectDNP3FuncParseFunctionCodeTest(void)
{
    uint8_t fc;

    /* Valid. */
    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("0", &fc));
    FAIL_IF(fc != 0);

    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("1", &fc));
    FAIL_IF(fc != 1);

    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("254", &fc));
    FAIL_IF(fc != 254);

    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("255", &fc));
    FAIL_IF(fc != 255);

    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("confirm", &fc));
    FAIL_IF(fc != 0);

    FAIL_IF_NOT(DetectDNP3FuncParseFunctionCode("CONFIRM", &fc));
    FAIL_IF(fc != 0);

    /* Invalid. */
    FAIL_IF(DetectDNP3FuncParseFunctionCode("", &fc));
    FAIL_IF(DetectDNP3FuncParseFunctionCode("-1", &fc));
    FAIL_IF(DetectDNP3FuncParseFunctionCode("-2", &fc));
    FAIL_IF(DetectDNP3FuncParseFunctionCode("256", &fc));
    FAIL_IF(DetectDNP3FuncParseFunctionCode("unknown_function_code", &fc));

    PASS;
}

static int DetectDNP3FuncTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectDNP3 *dnp3func = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->sig_list = SigInit(de_ctx,
        "alert dnp3 any any -> any any "
        "(msg:\"SURICATA DNP3 Write request\"; "
        "dnp3_func:2; sid:5000009; rev:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id]);
    FAIL_IF_NULL(de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id]->ctx);

    dnp3func = (DetectDNP3 *)de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id]->ctx;
    FAIL_IF(dnp3func->function_code != 2);

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    PASS;
}

static int DetectDNP3IndTestParseAsInteger(void)
{
    uint16_t flags = 0;

    FAIL_IF(!DetectDNP3IndParse("0", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("1", &flags));
    FAIL_IF(flags != 0x0001);

    FAIL_IF(!DetectDNP3IndParse("0x0", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("0x0000", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("0x0001", &flags));
    FAIL_IF(flags != 0x0001);

    FAIL_IF(!DetectDNP3IndParse("0x8421", &flags));
    FAIL_IF(flags != 0x8421);

    FAIL_IF(DetectDNP3IndParse("a", &flags));

    PASS;
}

static int DetectDNP3IndTestParseByName(void)
{
    uint16_t flags = 0;

    FAIL_IF(!DetectDNP3IndParse("all_stations", &flags));
    FAIL_IF(!(flags & 0x0100));
    FAIL_IF(!DetectDNP3IndParse("class_1_events , class_2_events", &flags));
    FAIL_IF(!(flags & 0x0200));
    FAIL_IF(!(flags & 0x0400));
    FAIL_IF((flags & 0xf9ff));

    FAIL_IF(DetectDNP3IndParse("something", &flags));

    PASS;
}

static int DetectDNP3ObjSetupTest(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectDNP3 *detect = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx,
        "alert dnp3 any any -> any any "
        "(msg:\"SURICATA DNP3 Object Test\"; "
        "dnp3_obj:99,99; sid:1; rev:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    FAIL_IF(de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id] == NULL);
    FAIL_IF(de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id]->ctx == NULL);

    detect = (DetectDNP3 *)de_ctx->sig_list->sm_lists_tail[g_dnp3_match_buffer_id]->ctx;
    FAIL_IF(detect->obj_group != 99);
    FAIL_IF(detect->obj_variation != 99);

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    PASS;
}

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
    UtRegisterTest("DetectDNP3FuncParseFunctionCodeTest",
                   DetectDNP3FuncParseFunctionCodeTest);
    UtRegisterTest("DetectDNP3FuncTest01", DetectDNP3FuncTest01);
}

static void DetectDNP3IndRegisterTests(void)
{
    UtRegisterTest("DetectDNP3IndTestParseAsInteger",
                   DetectDNP3IndTestParseAsInteger);
    UtRegisterTest("DetectDNP3IndTestParseByName",
                   DetectDNP3IndTestParseByName);
}

static void DetectDNP3ObjRegisterTests(void)
{
    UtRegisterTest("DetectDNP3ObjParseTest", DetectDNP3ObjParseTest);
    UtRegisterTest("DetectDNP3ObjSetupTest", DetectDNP3ObjSetupTest);
}
#endif
