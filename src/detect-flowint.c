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

/**
 * \file
 *
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 *
 * Flowvar management for integer types, part of the detection engine
 * Keyword: flowint
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-var.h"
#include "detect-flowint.h"
#include "util-spm.h"
#include "util-var-name.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-sigorder.h"
#include "detect-engine-build.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"

/*                         name             modifiers          value      */
#define PARSE_REGEX "^\\s*([a-zA-Z][\\w\\d_./]+)\\s*,\\s*([+=-]{1}|==|!=|<|<=|>|>=|isset|notset)\\s*,?\\s*([a-zA-Z][\\w\\d]+|[\\d]{1,10})?\\s*$"
/* Varnames must begin with a letter */

static DetectParseRegex parse_regex;

int DetectFlowintMatch(DetectEngineThreadCtx *, Packet *,
                       const Signature *, const SigMatchCtx *);
static int DetectFlowintSetup(DetectEngineCtx *, Signature *, const char *);
void DetectFlowintFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectFlowintRegisterTests(void);
#endif

void DetectFlowintRegister(void)
{
    sigmatch_table[DETECT_FLOWINT].name = "flowint";
    sigmatch_table[DETECT_FLOWINT].desc = "operate on a per-flow integer";
    sigmatch_table[DETECT_FLOWINT].url = "/rules/flow-keywords.html#flowint";
    sigmatch_table[DETECT_FLOWINT].Match = DetectFlowintMatch;
    sigmatch_table[DETECT_FLOWINT].Setup = DetectFlowintSetup;
    sigmatch_table[DETECT_FLOWINT].Free = DetectFlowintFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FLOWINT].RegisterTests = DetectFlowintRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to create a flowint, add/substract values,
 *        compare it with other flowints, etc
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s  pointer to the current Signature
 * \param m pointer to the sigmatch that we will cast into DetectFlowintData
 *
 * \retval 0 no match, when a var doesn't exist
 * \retval 1 match, when a var is initialized well, add/substracted, or a true
 * condition
 */
int DetectFlowintMatch(DetectEngineThreadCtx *det_ctx,
                        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectFlowintData *sfd = (const DetectFlowintData *)ctx;
    FlowVar *fv;
    FlowVar *fvt;
    uint32_t targetval;
    int ret = 0;

    if (p->flow == NULL)
        return 0;

    /** ATM If we are going to compare the current var with another
     * that doesn't exist, the default value will be zero;
     * if you don't want this behaviour, you can use the keyword
     * "isset" to make it match or not before using the default
     * value of zero;
     * But it is mandatory that the current var exist, otherwise, it will
     * return zero(not match).
     */
    if (sfd->targettype == FLOWINT_TARGET_VAR) {
        uint32_t tvar_idx = VarNameStoreLookupByName(sfd->target.tvar.name, VAR_TYPE_FLOW_INT);

        fvt = FlowVarGet(p->flow, tvar_idx);
            /* We don't have that variable initialized yet */
        if (fvt == NULL)
            targetval = 0;
        else
            targetval = fvt->data.fv_int.value;
    } else {
        targetval = sfd->target.value;
    }

    SCLogDebug("Our var %s is at idx: %"PRIu32"", sfd->name, sfd->idx);

    if (sfd->modifier == FLOWINT_MODIFIER_SET) {
        FlowVarAddIntNoLock(p->flow, sfd->idx, targetval);
        SCLogDebug("Setting %s = %u", sfd->name, targetval);
        ret = 1;
        goto end;
    }

    fv = FlowVarGet(p->flow, sfd->idx);

    if (sfd->modifier == FLOWINT_MODIFIER_ISSET) {
        SCLogDebug(" Isset %s? = %u", sfd->name,(fv) ? 1 : 0);
        if (fv != NULL)
            ret = 1;
        goto end;
    }

    if (sfd->modifier == FLOWINT_MODIFIER_NOTSET) {
        SCLogDebug(" Not set %s? = %u", sfd->name,(fv) ? 0 : 1);
        if (fv == NULL)
            ret = 1;
        goto end;
    }

    if (fv != NULL && fv->datatype == FLOWVAR_TYPE_INT) {
        if (sfd->modifier == FLOWINT_MODIFIER_ADD) {
            SCLogDebug("Adding %u to %s", targetval, sfd->name);
            FlowVarAddIntNoLock(p->flow, sfd->idx, fv->data.fv_int.value +
                           targetval);
            ret = 1;
            goto end;
        }

        if (sfd->modifier == FLOWINT_MODIFIER_SUB) {
            SCLogDebug("Substracting %u to %s", targetval, sfd->name);
            FlowVarAddIntNoLock(p->flow, sfd->idx, fv->data.fv_int.value -
                           targetval);
            ret = 1;
            goto end;
        }

        switch(sfd->modifier) {
            case FLOWINT_MODIFIER_EQ:
                SCLogDebug("( %u EQ %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value == targetval);
                break;
            case FLOWINT_MODIFIER_NE:
                SCLogDebug("( %u NE %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value != targetval);
                break;
            case FLOWINT_MODIFIER_LT:
                SCLogDebug("( %u LT %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value < targetval);
                break;
            case FLOWINT_MODIFIER_LE:
                SCLogDebug("( %u LE %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value <= targetval);
                break;
            case FLOWINT_MODIFIER_GT:
                SCLogDebug("( %u GT %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value > targetval);
                break;
            case FLOWINT_MODIFIER_GE:
                SCLogDebug("( %u GE %u )", fv->data.fv_int.value, targetval);
                ret = (fv->data.fv_int.value >= targetval);
                break;
            default:
                SCLogDebug("Unknown Modifier!");
#ifdef DEBUG
                BUG_ON(1);
#endif
        }
    } else {
        /* allow a add on a non-existing var, it will init to the "add" value,
         * so implying a 0 set. */
        if (sfd->modifier == FLOWINT_MODIFIER_ADD) {
            SCLogDebug("Adding %u to %s (new var)", targetval, sfd->name);
            FlowVarAddIntNoLock(p->flow, sfd->idx, targetval);
            ret = 1;
        } else {
            SCLogDebug("Var not found!");
            /* It doesn't exist because it wasn't set
             * or it is a string var, that we don't compare here
             */
            ret = 0;
        }
    }

end:
    return ret;
}

/**
 * \brief This function is used to parse a flowint option
 *
 * \param de_ctx pointer to the engine context
 * \param rawstr pointer to the string holding the options
 *
 * \retval NULL if invalid option
 * \retval DetectFlowintData pointer with the flowint parsed
 */
static DetectFlowintData *DetectFlowintParse(DetectEngineCtx *de_ctx, const char *rawstr)
{
    DetectFlowintData *sfd = NULL;
    char *varname = NULL;
    char *varval = NULL;
    char *modstr = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    uint8_t modifier = FLOWINT_MODIFIER_UNKNOWN;
    unsigned long long value_long = 0;
    const char *str_ptr;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 3 || ret > 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for flowint(ret = %d).", rawstr, ret);
        return NULL;
    }

    /* Get our flowint varname */
    res = pcre2_substring_get_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }
    varname = (char *)str_ptr;

    res = pcre2_substring_get_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        goto error;
    }
    modstr = (char *)str_ptr;

    /* Get the modifier */
    if (strcmp("=", modstr) == 0)
        modifier = FLOWINT_MODIFIER_SET;
    if (strcmp("+", modstr) == 0)
        modifier = FLOWINT_MODIFIER_ADD;
    if (strcmp("-", modstr) == 0)
        modifier = FLOWINT_MODIFIER_SUB;

    if (strcmp("<", modstr) == 0)
        modifier = FLOWINT_MODIFIER_LT;
    if (strcmp("<=", modstr) == 0)
        modifier = FLOWINT_MODIFIER_LE;
    if (strcmp("!=", modstr) == 0)
        modifier = FLOWINT_MODIFIER_NE;
    if (strcmp("==", modstr) == 0)
        modifier = FLOWINT_MODIFIER_EQ;
    if (strcmp(">=", modstr) == 0)
        modifier = FLOWINT_MODIFIER_GE;
    if (strcmp(">", modstr) == 0)
        modifier = FLOWINT_MODIFIER_GT;
    if (strcmp("isset", modstr) == 0)
        modifier = FLOWINT_MODIFIER_ISSET;
    if (strcmp("notset", modstr) == 0)
        modifier = FLOWINT_MODIFIER_NOTSET;

    if (modifier == FLOWINT_MODIFIER_UNKNOWN) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "Unknown modifier");
        goto error;
    }

    sfd = SCMalloc(sizeof(DetectFlowintData));
    if (unlikely(sfd == NULL))
        goto error;

    /* If we need another arg, check it out(isset doesn't need another arg) */
    if (modifier != FLOWINT_MODIFIER_ISSET && modifier != FLOWINT_MODIFIER_NOTSET) {
        if (ret < 4)
            goto error;

        res = pcre2_substring_get_bynumber(
                parse_regex.match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        varval = (char *)str_ptr;
        if (res < 0 || varval == NULL || strcmp(varval, "") == 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }

        if (varval[0] >= '0' && varval[0] <= '9') { /* is digit, look at the regexp */
            sfd->targettype = FLOWINT_TARGET_VAL;
            value_long = atoll(varval);
            if (value_long > UINT32_MAX) {
                SCLogDebug("DetectFlowintParse: Cannot load this value."
                            " Values should be between 0 and %"PRIu32, UINT32_MAX);
                goto error;
            }
            sfd->target.value = (uint32_t) value_long;
        } else {
            sfd->targettype = FLOWINT_TARGET_VAR;
            sfd->target.tvar.name = SCStrdup(varval);
            if (unlikely(sfd->target.tvar.name == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "malloc from strdup failed");
                goto error;
            }
        }
    } else {
        sfd->targettype = FLOWINT_TARGET_SELF;
    }

    /* Set the name of the origin var to modify/compared with the target */
    sfd->name = SCStrdup(varname);
    if (unlikely(sfd->name == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc from strdup failed");
        goto error;
    }
    sfd->idx = VarNameStoreSetupAdd(varname, VAR_TYPE_FLOW_INT);
    SCLogDebug("sfd->name %s id %u", sfd->name, sfd->idx);
    sfd->modifier = modifier;

    pcre2_substring_free((PCRE2_UCHAR *)varname);
    pcre2_substring_free((PCRE2_UCHAR *)modstr);
    if (varval)
        pcre2_substring_free((PCRE2_UCHAR *)varval);
    return sfd;
error:
    if (varname)
        pcre2_substring_free((PCRE2_UCHAR *)varname);
    if (varval)
        pcre2_substring_free((PCRE2_UCHAR *)varval);
    if (modstr)
        pcre2_substring_free((PCRE2_UCHAR *)modstr);
    if (sfd != NULL)
        SCFree(sfd);
    return NULL;
}

/**
 * \brief This function is used to set up the SigMatch holding the flowint opt
 *
 * \param de_ctx pointer to the engine context
 * \param s  pointer to the current Signature
 * \param rawstr pointer to the string holding the options
 *
 * \retval 0 if all is ok
 * \retval -1 if we find any problem
 */
static int DetectFlowintSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectFlowintData *sfd = NULL;
    SigMatch *sm = NULL;

    sfd = DetectFlowintParse(de_ctx, rawstr);
    if (sfd == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOWINT;
    sm->ctx = (SigMatchCtx *)sfd;

    switch (sfd->modifier) {
        case FLOWINT_MODIFIER_SET:
        case FLOWINT_MODIFIER_ADD:
        case FLOWINT_MODIFIER_SUB:
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
            break;

        case FLOWINT_MODIFIER_LT:
        case FLOWINT_MODIFIER_LE:
        case FLOWINT_MODIFIER_NE:
        case FLOWINT_MODIFIER_EQ:
        case FLOWINT_MODIFIER_GE:
        case FLOWINT_MODIFIER_GT:
        case FLOWINT_MODIFIER_ISSET:
        case FLOWINT_MODIFIER_NOTSET:
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
            break;
        default:
            goto error;
    }

    return 0;

error:
    if (sfd)
        DetectFlowintFree(de_ctx, sfd);
    if (sm)
        SCFree(sm);
    return -1;
}

/**
 * \brief This function is used to free the data of DetectFlowintData
 */
void DetectFlowintFree(DetectEngineCtx *de_ctx, void *tmp)
{
    DetectFlowintData *sfd =(DetectFlowintData*) tmp;
    if (sfd != NULL) {
        if (sfd->name != NULL)
            SCFree(sfd->name);
        if (sfd->targettype == FLOWINT_TARGET_VAR)
            if (sfd->target.tvar.name != NULL)
                SCFree(sfd->target.tvar.name);
        SCFree(sfd);
    }
}

#ifdef UNITTESTS
/**
 * \brief This is a helper funtion used for debugging purposes
 */
static void DetectFlowintPrintData(DetectFlowintData *sfd)
{
    if (sfd == NULL) {
        SCLogDebug("DetectFlowintPrintData: Error, DetectFlowintData == NULL!");
        return;
    }

    SCLogDebug("Varname: %s, modifier: %"PRIu8", idx: %"PRIu32" Target: ",
                sfd->name, sfd->modifier, sfd->idx);
    switch(sfd->targettype) {
        case FLOWINT_TARGET_VAR:
            SCLogDebug("target_var: %s",
                        sfd->target.tvar.name);
            break;
        case FLOWINT_TARGET_VAL:
            SCLogDebug("Value: %"PRIu32"; ", sfd->target.value);
            break;
        default :
            SCLogDebug("DetectFlowintPrintData: Error, Targettype not known!");
    }
}

/**
 * \test DetectFlowintTestParseVal01 is a test to make sure that we set the
 *  DetectFlowint correctly for setting a valid target value
 */
static int DetectFlowintTestParseVal01(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,=,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_SET) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar01 is a test to make sure that we set the
 *  DetectFlowint correctly for setting a valid target variable
 */
static int DetectFlowintTestParseVar01(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,=,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_SET) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal02 is a test to make sure that we set the
 *  DetectFlowint correctly for adding a valid target value
 */
static int DetectFlowintTestParseVal02(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,+,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_ADD) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar02 is a test to make sure that we set the
 *  DetectFlowint correctly for adding a valid target variable
 */
static int DetectFlowintTestParseVar02(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,+,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_ADD) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal03 is a test to make sure that we set the
 *  DetectFlowint correctly for substract a valid target value
 */
static int DetectFlowintTestParseVal03(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,-,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_SUB) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar03 is a test to make sure that we set the
 *  DetectFlowint correctly for substract a valid target variable
 */
static int DetectFlowintTestParseVar03(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,-,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_SUB) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}


/**
 * \test DetectFlowintTestParseVal04 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if equal to a valid target value
 */
static int DetectFlowintTestParseVal04(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,==,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_EQ) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar04 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if equal to a valid target variable
 */
static int DetectFlowintTestParseVar04(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,==,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_EQ) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal05 is a test to make sure that we set the
 *  DetectFlowint correctly for cheking if not equal to a valid target value
 */
static int DetectFlowintTestParseVal05(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,!=,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_NE) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar05 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if not equal to a valid target variable
 */
static int DetectFlowintTestParseVar05(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,!=,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_NE) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal06 is a test to make sure that we set the
 *  DetectFlowint correctly for cheking if greater than a valid target value
 */
static int DetectFlowintTestParseVal06(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, >,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_GT) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar06 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if greater than a valid target variable
 */
static int DetectFlowintTestParseVar06(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, >,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_GT) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal07 is a test to make sure that we set the
 *  DetectFlowint correctly for cheking if greater or equal than a valid target value
 */
static int DetectFlowintTestParseVal07(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, >= ,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_GE) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar07 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if greater or equal than a valid target variable
 */
static int DetectFlowintTestParseVar07(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, >= ,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_GE) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal08 is a test to make sure that we set the
 *  DetectFlowint correctly for cheking if lower or equal than a valid target value
 */
static int DetectFlowintTestParseVal08(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, <= ,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_LE) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar08 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if lower or equal than a valid target variable
 */
static int DetectFlowintTestParseVar08(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, <= ,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_LE) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVal09 is a test to make sure that we set the
 *  DetectFlowint correctly for cheking if lower than a valid target value
 */
static int DetectFlowintTestParseVal09(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, < ,35");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && sfd->target.value == 35 && !strcmp(sfd->name, "myvar")
            && sfd->modifier == FLOWINT_MODIFIER_LT) {
        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar09 is a test to make sure that we set the
 *  DetectFlowint correctly for checking if lower than a valid target variable
 */
static int DetectFlowintTestParseVar09(void)
{
    int result = 0;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, < ,targetvar");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_VAR
            && sfd->target.tvar.name != NULL
            && !strcmp(sfd->target.tvar.name, "targetvar")
            && sfd->modifier == FLOWINT_MODIFIER_LT) {

        result = 1;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseVar09 is a test to make sure that handle the
 * isset keyword correctly
 */
static int DetectFlowintTestParseIsset10(void)
{
    int result = 1;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return 0;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar, isset");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_SELF
            && sfd->modifier == FLOWINT_MODIFIER_ISSET) {

        result &= 1;
    } else {
        result = 0;
    }

    if (sfd) DetectFlowintFree(NULL, sfd);
    sfd = DetectFlowintParse(de_ctx, "myvar, notset");
    DetectFlowintPrintData(sfd);
    if (sfd != NULL && !strcmp(sfd->name, "myvar")
            && sfd->targettype == FLOWINT_TARGET_SELF
            && sfd->modifier == FLOWINT_MODIFIER_NOTSET) {

        result &= 1;
    } else {
        result = 0;
    }

    if (sfd) DetectFlowintFree(NULL, sfd);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test DetectFlowintTestParseInvalidSyntaxis01 is a test to make sure that we dont set the
 *  DetectFlowint for a invalid input option
 */
static int DetectFlowintTestParseInvalidSyntaxis01(void)
{
    int result = 1;
    DetectFlowintData *sfd = NULL;
    DetectEngineCtx *de_ctx;
    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto error;
    de_ctx->flags |= DE_QUIET;

    sfd = DetectFlowintParse(de_ctx, "myvar,=,9999999999");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,=,9532458716234857");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar,=,45targetvar");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,=,45targetvar ");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "657myvar,=,targetvar");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at 657myvar,=,targetvar ");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar,=<,targetvar");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,=<,targetvar ");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar,===,targetvar");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,===,targetvar ");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar,==");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,==");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar,");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar,");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    sfd = DetectFlowintParse(de_ctx, "myvar");
    if (sfd != NULL) {
        SCLogDebug("DetectFlowintTestParseInvalidSyntaxis01: ERROR: invalid option at myvar");
        result = 0;
    }
    if (sfd) DetectFlowintFree(NULL, sfd);

    DetectEngineCtxFree(de_ctx);

    return result;
error:
    if (de_ctx)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test DetectFlowintTestPacket01Real
 * \brief Set a counter when we see a content:"GET"
 *        and increment it by 2 if we match a "Unauthorized"
 *        When it reach 3(with the last +2), another counter starts
 *        and when that counter reach 6 packets.
 *
 *        All the Signatures generate an alert(its for testing)
 *        but the ignature that increment the second counter +1, that has
 *        a "noalert", so we can do all increments
 *        silently until we reach 6 next packets counted
 */
static int DetectFlowintTestPacket01Real(void)
{
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    const char *sigs[5];
    sigs[0] = "alert tcp any any -> any any (msg:\"Setting a flowint counter\"; content:\"GET\"; flowint:myvar,=,1; flowint:maxvar,=,6; sid:101;)";
    sigs[1] = "alert tcp any any -> any any (msg:\"Adding to flowint counter\"; content:\"Unauthorized\"; flowint: myvar,+,2; sid:102;)";
    sigs[2] = "alert tcp any any -> any any (msg:\"if the flowint counter is 3 create a new counter\"; content:\"Unauthorized\"; flowint: myvar,==,3; flowint: cntpackets, =, 0; sid:103;)";
    sigs[3] = "alert tcp any any -> any any (msg:\"and count the rest of the packets received without generating alerts!!!\"; flowint: myvar,==,3; flowint: cntpackets, +, 1; noalert;sid:104;)";
    sigs[4] = "alert tcp any any -> any any (msg:\" and fire this when it reach 6\"; flowint: cntpackets, ==, maxvar; sid:105;)";
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 5) == 0);

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v,(void *) de_ctx,(void *) &det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1",
            41424, 80);
    FAIL_IF(f == NULL);
    f->proto = IPPROTO_TCP;

    p = UTHBuildPacket((uint8_t *)"GET", 3, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 101));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"Unauthorized", 12, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 102));
    FAIL_IF(!PacketAlertCheck(p, 103));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"1", 1, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"X", 1, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 105));
    UTHFreePacket(p);

    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v,(void *) det_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectFlowintTestPacket02Real
 * \brief like DetectFlowintTestPacket01Real but using isset/notset keywords
 */
static int DetectFlowintTestPacket02Real(void)
{
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    const char *sigs[5];
    sigs[0] = "alert tcp any any -> any any (msg:\"Setting a flowint counter\"; content:\"GET\"; flowint: myvar, notset; flowint:maxvar,notset; flowint: myvar,=,1; flowint: maxvar,=,6; sid:101;)";
    sigs[1] = "alert tcp any any -> any any (msg:\"Adding to flowint counter\"; content:\"Unauthorized\"; flowint:myvar,isset; flowint: myvar,+,2; sid:102;)";
    sigs[2] = "alert tcp any any -> any any (msg:\"if the flowint counter is 3 create a new counter\"; content:\"Unauthorized\"; flowint: myvar, isset; flowint: myvar,==,3; flowint:cntpackets,notset; flowint: cntpackets, =, 0; sid:103;)";
    sigs[3] = "alert tcp any any -> any any (msg:\"and count the rest of the packets received without generating alerts!!!\"; flowint: cntpackets,isset; flowint: cntpackets, +, 1; noalert;sid:104;)";
    sigs[4] = "alert tcp any any -> any any (msg:\" and fire this when it reach 6\"; flowint: cntpackets, isset; flowint: maxvar,isset; flowint: cntpackets, ==, maxvar; sid:105;)";
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 5) == 0);

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v,(void *) de_ctx,(void *) &det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1",
            41424, 80);
    FAIL_IF(f == NULL);
    f->proto = IPPROTO_TCP;

    p = UTHBuildPacket((uint8_t *)"GET", 3, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 101));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"Unauthorized", 12, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 102));
    FAIL_IF(!PacketAlertCheck(p, 103));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"1", 1, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"X", 1, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 105));
    UTHFreePacket(p);

    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v,(void *) det_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectFlowintTestPacket03Real
 * \brief Check the behaviour of isset/notset
 */
static int DetectFlowintTestPacket03Real(void)
{
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    const char *sigs[3];
    sigs[0] = "alert tcp any any -> any any (msg:\"check notset\"; content:\"GET\"; flowint: myvar, notset; flowint: myvar,=,0; flowint: other,=,10; sid:101;)";
    sigs[1] = "alert tcp any any -> any any (msg:\"check isset\"; content:\"Unauthorized\"; flowint:myvar,isset; flowint: other,isset; sid:102;)";
    sigs[2] = "alert tcp any any -> any any (msg:\"check notset\"; content:\"Unauthorized\"; flowint:lala,isset; sid:103;)";
    FAIL_IF(UTHAppendSigs(de_ctx, sigs, 3) == 0);

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v,(void *) de_ctx,(void *) &det_ctx);

    Flow *f = UTHBuildFlow(AF_INET, "192.168.1.5", "192.168.1.1",
            41424, 80);
    FAIL_IF(f == NULL);
    f->proto = IPPROTO_TCP;

    p = UTHBuildPacket((uint8_t *)"GET", 3, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 101));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"Unauthorized", 12, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(!PacketAlertCheck(p, 102));
    FAIL_IF(PacketAlertCheck(p, 103));
    UTHFreePacket(p);

    p = UTHBuildPacket((uint8_t *)"1", 1, IPPROTO_TCP);
    FAIL_IF(p == NULL);
    UTHAssignFlow(p, f);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 102));
    FAIL_IF(PacketAlertCheck(p, 103));
    UTHFreePacket(p);

    UTHFreeFlow(f);
    DetectEngineThreadCtxDeinit(&th_v,(void *) det_ctx);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectFlowint
 */
void DetectFlowintRegisterTests(void)
{
    UtRegisterTest("DetectFlowintTestParseVal01", DetectFlowintTestParseVal01);
    UtRegisterTest("DetectFlowintTestParseVar01", DetectFlowintTestParseVar01);
    UtRegisterTest("DetectFlowintTestParseVal02", DetectFlowintTestParseVal02);
    UtRegisterTest("DetectFlowintTestParseVar02", DetectFlowintTestParseVar02);
    UtRegisterTest("DetectFlowintTestParseVal03", DetectFlowintTestParseVal03);
    UtRegisterTest("DetectFlowintTestParseVar03", DetectFlowintTestParseVar03);
    UtRegisterTest("DetectFlowintTestParseVal04", DetectFlowintTestParseVal04);
    UtRegisterTest("DetectFlowintTestParseVar04", DetectFlowintTestParseVar04);
    UtRegisterTest("DetectFlowintTestParseVal05", DetectFlowintTestParseVal05);
    UtRegisterTest("DetectFlowintTestParseVar05", DetectFlowintTestParseVar05);
    UtRegisterTest("DetectFlowintTestParseVal06", DetectFlowintTestParseVal06);
    UtRegisterTest("DetectFlowintTestParseVar06", DetectFlowintTestParseVar06);
    UtRegisterTest("DetectFlowintTestParseVal07", DetectFlowintTestParseVal07);
    UtRegisterTest("DetectFlowintTestParseVar07", DetectFlowintTestParseVar07);
    UtRegisterTest("DetectFlowintTestParseVal08", DetectFlowintTestParseVal08);
    UtRegisterTest("DetectFlowintTestParseVar08", DetectFlowintTestParseVar08);
    UtRegisterTest("DetectFlowintTestParseVal09", DetectFlowintTestParseVal09);
    UtRegisterTest("DetectFlowintTestParseVar09", DetectFlowintTestParseVar09);
    UtRegisterTest("DetectFlowintTestParseIsset10",
                   DetectFlowintTestParseIsset10);
    UtRegisterTest("DetectFlowintTestParseInvalidSyntaxis01",
                   DetectFlowintTestParseInvalidSyntaxis01);
    UtRegisterTest("DetectFlowintTestPacket01Real",
                   DetectFlowintTestPacket01Real);
    UtRegisterTest("DetectFlowintTestPacket02Real",
                   DetectFlowintTestPacket02Real);
    UtRegisterTest("DetectFlowintTestPacket03Real",
                   DetectFlowintTestPacket03Real);
}
#endif /* UNITTESTS */
