/* Copyright (C) 2015 Open Information Security Foundation
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
#include "detect-parse.h"
#include "detect-dnp3.h"

void DetectDNP3FuncRegisterTests(void);

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
 *
 * TODO Function name support.
 */
static int DetectDNP3FuncParseFunctionCode(char *str)
{
    long val;
    char *ep;

    errno = 0;

    /* First convert to a number and verify. */
    val = strtol(str, &ep, 10);
    if (str[0] == '\0' || *ep != '\0') {
        goto fail;
    }
    if (errno == ERANGE && (val == LONG_MAX || val == LONG_MIN)) {
        goto fail;
    }

    /* Now check that its within the bounds of a DNP3 function code. */
    if ((val < 0) || (val > 0xff)) {
        goto fail;
    }

    return (int)val;

fail:
    return -1;
}

static int DetectDNP3FuncSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    DetectDNP3 *dnp3 = NULL;
    SigMatch *sm = NULL;
    int function_code;

    function_code = DetectDNP3FuncParseFunctionCode(str);
    if (function_code == -1) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "Invalid argument \"%s\" supplied to dnp3_func keyword.", str);
        return -1;
    }

    dnp3 = SCCalloc(1, sizeof(DetectDNP3));
    if (unlikely(dnp3 == NULL)) {
        goto error;
    }
    dnp3->type = DNP3_DETECT_FUNCTION_CODE;
    dnp3->function_code = function_code;

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }

    sm->type = DETECT_AL_DNP3FUNC;
    sm->ctx = (void *)dnp3;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_DNP3_MATCH);
    s->alproto = ALPROTO_DNP3;
    s->flags |= SIG_FLAG_STATE_MATCH;

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

static void DetectDNP3FuncFree(void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        SCFree(ptr);
    }
    SCReturn;
}

void DetectDNP3FuncRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3FUNC].name          = "dnp3.func";
    sigmatch_table[DETECT_AL_DNP3FUNC].alias         = "dnp3_func";
    sigmatch_table[DETECT_AL_DNP3FUNC].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3FUNC].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_DNP3FUNC].alproto       = ALPROTO_DNP3;
    sigmatch_table[DETECT_AL_DNP3FUNC].Setup         = DetectDNP3FuncSetup;
    sigmatch_table[DETECT_AL_DNP3FUNC].Free          = DetectDNP3FuncFree;
    sigmatch_table[DETECT_AL_DNP3FUNC].RegisterTests =
        DetectDNP3FuncRegisterTests;

    SCReturn;
}

#ifdef UNITTESTS

#include "detect-engine.h"
#include "util-unittest.h"

#define FAIL_IF(expr) do {                                      \
        if (expr) {                                             \
            printf("Failed at %s:%d\n", __FILE__, __LINE__);    \
            goto fail;                                          \
        }                                                       \
    } while (0);

static int DetectDNP3FuncParseFunctionCodeTest(void)
{
    /* Valid. */
    FAIL_IF(DetectDNP3FuncParseFunctionCode("0") != 0);
    FAIL_IF(DetectDNP3FuncParseFunctionCode("1") != 1);
    FAIL_IF(DetectDNP3FuncParseFunctionCode("254") != 254);
    FAIL_IF(DetectDNP3FuncParseFunctionCode("255") != 255);

    /* Invalid. */
    FAIL_IF((DetectDNP3FuncParseFunctionCode("") != -1));
    FAIL_IF((DetectDNP3FuncParseFunctionCode("-1") != -1));
    FAIL_IF((DetectDNP3FuncParseFunctionCode("-2") != -1));
    FAIL_IF((DetectDNP3FuncParseFunctionCode("256") != -1));
    FAIL_IF((DetectDNP3FuncParseFunctionCode("unknown_function_code") != -1));

    return 1;
fail:
    return 0;
}

static int DetectDNP3FuncTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectDNP3 *detect = NULL;
    int rc = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx, "alert dnp3 any any -> any any (msg:\"SURICATA DNP3 Write request\"; dnp3_func:2; sid:5000009; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    if (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_DNP3_MATCH] == NULL)
        goto end;
    if (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_DNP3_MATCH]->ctx == NULL)
        goto end;

    detect = (DetectDNP3 *)de_ctx->
        sig_list->sm_lists_tail[DETECT_SM_LIST_DNP3_MATCH]->ctx;
    if (detect->function_code != 2)
        goto end;

    rc = 1;
end:
    return rc;
}

#endif

void DetectDNP3FuncRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDNP3FuncParseFunctionCodeTest",
        DetectDNP3FuncParseFunctionCodeTest, 1);
    UtRegisterTest("DetectDNP3FuncTest01", DetectDNP3FuncTest01, 1);
#endif
}
