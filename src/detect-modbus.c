/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author David DIALLO <diallo@et.esiea.fr>
 *
 * Implements the Modbus function and access keywords
 * You can specify a:
 * - concrete function like Modbus:
 *     function 8, subfunction 4 (diagnostic: Force Listen Only Mode)
 * - data (in primary table) register access (r/w) like Modbus:
 *     access read coils, address 1000 (.i.e Read coils: at address 1000)
 * - write data value at specific address Modbus:
 *     access write, address 1500<>2000, value >2000 (Write multiple coils/register:
 *     at address between 1500 and 2000 value greater than 2000)
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-modbus.h"

#include "util-debug.h"

#include "app-layer-modbus.h"

#include "stream-tcp.h"

/**
 * \brief Regex for parsing the Modbus function string
 */
#define PARSE_REGEX_FUNCTION "^\\s*\"?\\s*function\\s*(!?[A-z0-9]+)(,\\s*subfunction\\s+(\\d+))?\\s*\"?\\s*$"
static pcre         *function_parse_regex;
static pcre_extra   *function_parse_regex_study;

/**
 * \brief Regex for parsing the Modbus access string
 */
#define PARSE_REGEX_ACCESS "^\\s*\"?\\s*access\\s*(read|write)\\s*(discretes|coils|input|holding)?(,\\s*address\\s+([<>]?\\d+)(<>\\d+)?(,\\s*value\\s+([<>]?\\d+)(<>\\d+)?)?)?\\s*\"?\\s*$"
static pcre         *access_parse_regex;
static pcre_extra   *access_parse_regex_study;

#define MAX_SUBSTRINGS 30

void DetectModbusRegisterTests(void);

/** \internal
 *
 * \brief this function will free memory associated with DetectModbus
 *
 * \param ptr pointer to DetectModbus
 */
static void DetectModbusFree(void *ptr) {
    SCEnter();
    DetectModbus *modbus = (DetectModbus *) ptr;

    if(modbus) {
        if (modbus->subfunction)
            SCFree(modbus->subfunction);

        if (modbus->address)
            SCFree(modbus->address);

        if (modbus->data)
            SCFree(modbus->data);

        SCFree(modbus);
    }
}

/** \internal
 *
 * \brief This function is used to parse Modbus parameters in access mode
 *
 * \param str Pointer to the user provided id option
 *
 * \retval Pointer to DetectModbusData on success or NULL on failure
 */
static DetectModbus *DetectModbusAccessParse(char *str)
{
    SCEnter();
    DetectModbus *modbus = NULL;

    char    arg[MAX_SUBSTRINGS];
    int     ov[MAX_SUBSTRINGS], ret, res;

    ret = pcre_exec(access_parse_regex, access_parse_regex_study, str, strlen(str), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Modbus option */
    modbus = (DetectModbus *) SCCalloc(1, sizeof(DetectModbus));
    if (unlikely(modbus == NULL))
        goto error;

    if (strcmp(arg, "read") == 0)
        modbus->type = MODBUS_TYP_READ;
    else if (strcmp(arg, "write") == 0)
        modbus->type = MODBUS_TYP_WRITE;
    else
        goto error;

    if (ret > 2) {
        res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 2, arg, MAX_SUBSTRINGS);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        if (*arg != '\0') {
            if (strcmp(arg, "discretes") == 0) {
                if (modbus->type == MODBUS_TYP_WRITE)
                    /* Discrete access is only read access. */
                    goto error;

                modbus->type |= MODBUS_TYP_DISCRETES;
            }
            else if (strcmp(arg, "coils") == 0) {
                modbus->type |= MODBUS_TYP_COILS;
            }
            else if (strcmp(arg, "input") == 0) {
                if (modbus->type == MODBUS_TYP_WRITE) {
                    /* Input access is only read access. */
                    goto error;
                }

                modbus->type |= MODBUS_TYP_INPUT;
            }
            else if (strcmp(arg, "holding") == 0) {
                modbus->type |= MODBUS_TYP_HOLDING;
            }
            else
                goto error;
        }

        if (ret > 4) {
            res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 4, arg, MAX_SUBSTRINGS);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            /* We have a correct address option */
            modbus->address = (DetectModbusValue *) SCCalloc(1, sizeof(DetectModbusValue));
            if (unlikely(modbus->address == NULL))
                goto error;

            if (arg[0] == '>') {
                modbus->address->min    = atoi((const char*) (arg+1));
                modbus->address->mode   = DETECT_MODBUS_GT;
            } else if (arg[0] == '<') {
                modbus->address->min    = atoi((const char*) (arg+1));
                modbus->address->mode   = DETECT_MODBUS_LT;
            } else {
                modbus->address->min    = atoi((const char*) arg);
            }
            SCLogDebug("and min/equal address %d", modbus->address->min);

            if (ret > 5) {
                res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 5, arg, MAX_SUBSTRINGS);
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                if (*arg != '\0') {
                    modbus->address->max    = atoi((const char*) (arg+2));
                    modbus->address->mode   = DETECT_MODBUS_RA;
                    SCLogDebug("and max address %d", modbus->address->max);
                }

                if (ret > 7) {
                    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 7, arg, MAX_SUBSTRINGS);
                    if (res < 0) {
                        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                        goto error;
                    }

                    if (modbus->address->mode != DETECT_MODBUS_EQ) {
                        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords (address range and value).");
                        goto error;
                    }

                    /* We have a correct address option */
                    modbus->data = (DetectModbusValue *) SCCalloc(1, sizeof(DetectModbusValue));
                    if (unlikely(modbus->data == NULL))
                        goto error;

                    if (arg[0] == '>') {
                        modbus->data->min   = atoi((const char*) (arg+1));
                        modbus->data->mode  = DETECT_MODBUS_GT;
                    } else if (arg[0] == '<') {
                        modbus->data->min   = atoi((const char*) (arg+1));
                        modbus->data->mode  = DETECT_MODBUS_LT;
                    } else {
                        modbus->data->min   = atoi((const char*) arg);
                    }
                    SCLogDebug("and min/equal value %d", modbus->data->min);

                    if (ret > 8) {
                        res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 8, arg, MAX_SUBSTRINGS);
                        if (res < 0) {
                            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                            goto error;
                        }

                        if (*arg != '\0') {
                            modbus->data->max   = atoi((const char*) (arg+2));
                            modbus->data->mode  = DETECT_MODBUS_RA;
                            SCLogDebug("and max value %d", modbus->data->max);
                        }
                    }
                }
            }
        }
    }

    SCReturnPtr(modbus, "DetectModbusAccess");

error:
    if (modbus != NULL)
        DetectModbusFree(modbus);

    SCReturnPtr(NULL, "DetectModbus");
}

/** \internal
 *
 * \brief This function is used to parse Modbus parameters in function mode
 *
 * \param str Pointer to the user provided id option
 *
 * \retval id_d pointer to DetectModbusData on success
 * \retval NULL on failure
 */
static DetectModbus *DetectModbusFunctionParse(char *str)
{
    SCEnter();
    DetectModbus *modbus = NULL;

    char    arg[MAX_SUBSTRINGS], *ptr = arg;
    int     ov[MAX_SUBSTRINGS], res, ret;

    ret = pcre_exec(function_parse_regex, function_parse_regex_study, str, strlen(str), 0, 0, ov, MAX_SUBSTRINGS);

    if (ret < 1)
        goto error;

    res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 1, arg, MAX_SUBSTRINGS);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* We have a correct Modbus function option */
    modbus = (DetectModbus *) SCCalloc(1, sizeof(DetectModbus));
    if (unlikely(modbus == NULL))
        goto error;

    if (isdigit((unsigned char)ptr[0])) {
        modbus->function = atoi((const char*) ptr);
        SCLogDebug("will look for modbus function %d", modbus->function);

        if (ret > 2) {
            res = pcre_copy_substring(str, ov, MAX_SUBSTRINGS, 3, arg, MAX_SUBSTRINGS);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            /* We have a correct address option */
            modbus->subfunction =(uint16_t *) SCCalloc(1, sizeof(uint16_t));
            if (modbus->subfunction == NULL)
                goto error;

            *(modbus->subfunction) = atoi((const char*) arg);
            SCLogDebug("and subfunction %d", *(modbus->subfunction));
        }
    } else {
        uint8_t neg = 0;

        if (ptr[0] == '!') {
            neg = 1;
            ptr++;
        }

        if (strcmp("assigned", ptr) == 0)
            modbus->category = MODBUS_CAT_PUBLIC_ASSIGNED;
        else if (strcmp("unassigned", ptr) == 0)
            modbus->category = MODBUS_CAT_PUBLIC_UNASSIGNED;
        else if (strcmp("public", ptr) == 0)
            modbus->category = MODBUS_CAT_PUBLIC_ASSIGNED | MODBUS_CAT_PUBLIC_UNASSIGNED;
        else if (strcmp("user", ptr) == 0)
            modbus->category = MODBUS_CAT_USER_DEFINED;
        else if (strcmp("reserved", ptr) == 0)
            modbus->category = MODBUS_CAT_RESERVED;
        else if (strcmp("all", ptr) == 0)
            modbus->category = MODBUS_CAT_ALL;

        if (neg)
            modbus->category = ~modbus->category;
        SCLogDebug("will look for modbus category function %d", modbus->category);
    }

    SCReturnPtr(modbus, "DetectModbusFunction");

error:
    if (modbus != NULL)
        DetectModbusFree(modbus);

    SCReturnPtr(NULL, "DetectModbus");
}

/** \internal
 *
 * \brief this function is used to add the parsed "id" option into the current signature
 *
 * \param de_ctx    Pointer to the Detection Engine Context
 * \param s         Pointer to the Current Signature
 * \param str       Pointer to the user provided "id" option
 *
 * \retval 0 on Success or -1 on Failure
 */
static int DetectModbusSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    DetectModbus    *modbus = NULL;
    SigMatch        *sm = NULL;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_MODBUS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if ((modbus = DetectModbusFunctionParse(str)) == NULL) {
        if ((modbus = DetectModbusAccessParse(str)) == NULL) {
            SCLogError(SC_ERR_PCRE_MATCH, "invalid modbus option");
            goto error;
        }
    }

    /* Okay so far so good, lets get this into a SigMatch and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type    = DETECT_AL_MODBUS;
    sm->ctx     = (void *) modbus;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MODBUS_MATCH);
    s->alproto = ALPROTO_MODBUS;

    SCReturnInt(0);

error:
    if (modbus != NULL)
        DetectModbusFree(modbus);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief Registration function for Modbus keyword
 */
void DetectModbusRegister(void)
{
    SCEnter();
    sigmatch_table[DETECT_AL_MODBUS].name          = "modbus";
    sigmatch_table[DETECT_AL_MODBUS].Match         = NULL;
    sigmatch_table[DETECT_AL_MODBUS].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_MODBUS].alproto       = ALPROTO_MODBUS;
    sigmatch_table[DETECT_AL_MODBUS].Setup         = DetectModbusSetup;
    sigmatch_table[DETECT_AL_MODBUS].Free          = DetectModbusFree;
    sigmatch_table[DETECT_AL_MODBUS].RegisterTests = DetectModbusRegisterTests;

    const char *eb;
    int eo, opts = 0;

    SCLogDebug("registering modbus rule option");

    /* Function PARSE_REGEX */
    function_parse_regex = pcre_compile(PARSE_REGEX_FUNCTION, opts, &eb, &eo, NULL);
    if (function_parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                    PARSE_REGEX_FUNCTION, eo, eb);
        goto error;
    }

    function_parse_regex_study = pcre_study(function_parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    /* Access PARSE_REGEX */
    access_parse_regex = pcre_compile(PARSE_REGEX_ACCESS, opts, &eb, &eo, NULL);
    if (access_parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                   PARSE_REGEX_ACCESS, eo, eb);
        goto error;
    }

    access_parse_regex_study = pcre_study(access_parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

error:
    SCReturn;
}

#ifdef UNITTESTS /* UNITTESTS */
#include "detect-engine.h"

#include "util-unittest.h"

/** \test Signature containing a function. */
static int DetectModbusTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function\"; "
                                       "modbus: function 1;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if (modbus->function != 1) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", 1, modbus->function);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a function and a subfunction. */
static int DetectModbusTest02(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function and subfunction\"; "
                                       "modbus: function 8, subfunction 4;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if ((modbus->function != 8) || (*modbus->subfunction != 4)) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", 1, modbus->function);
        printf("expected subfunction %" PRIu8 ", got %" PRIu16 ": ", 4, *modbus->subfunction);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a function category. */
static int DetectModbusTest03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.function\"; "
                                       "modbus: function reserved;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if (modbus->category != MODBUS_CAT_RESERVED) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", MODBUS_CAT_RESERVED, modbus->category);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a negative function category. */
static int DetectModbusTest04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    uint8_t category = ~MODBUS_CAT_PUBLIC_ASSIGNED;

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus function\"; "
                                       "modbus: function !assigned;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if (modbus->category != category) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", ~MODBUS_CAT_PUBLIC_ASSIGNED, modbus->category);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a access type. */
static int DetectModbusTest05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if (modbus->type != MODBUS_TYP_READ) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", MODBUS_TYP_READ, modbus->type);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a access function. */
static int DetectModbusTest06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    DetectModbus    *modbus = NULL;

    uint8_t type = (MODBUS_TYP_READ | MODBUS_TYP_DISCRETES);

    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read discretes;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if (modbus->type != type) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", type, modbus->type);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a read access at an address. */
static int DetectModbusTest07(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_EQ;

    uint8_t type = MODBUS_TYP_READ;
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access read, address 1000;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if ((modbus->type != type) ||
        ((*modbus->address).mode != mode) ||
        ((*modbus->address).min != 1000)) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", type, modbus->type);
        printf("expected mode %" PRIu8 ", got %" PRIu16 ": ", mode, (*modbus->address).mode);
        printf("expected address %" PRIu8 ", got %" PRIu16 ": ", 1000, (*modbus->address).min);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a write access at a range of address. */
static int DetectModbusTest08(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    mode = DETECT_MODBUS_GT;

    uint8_t type = (MODBUS_TYP_WRITE | MODBUS_TYP_COILS);
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access write coils, address >500;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if ((modbus->type != type) ||
        ((*modbus->address).mode != mode) ||
        ((*modbus->address).min != 500)) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", type, modbus->type);
        printf("expected mode %" PRIu8 ", got %" PRIu16 ": ", mode, (*modbus->address).mode);
        printf("expected address %" PRIu8 ", got %" PRIu16 ": ", 500, (*modbus->address).min);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/** \test Signature containing a write access at a address a range of value. */
static int DetectModbusTest09(void)
{
    DetectEngineCtx     *de_ctx = NULL;
    DetectModbus        *modbus = NULL;
    DetectModbusMode    addressMode = DETECT_MODBUS_EQ;
    DetectModbusMode    valueMode = DETECT_MODBUS_RA;

    uint8_t type = (MODBUS_TYP_WRITE | MODBUS_TYP_HOLDING);
    int result = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert modbus any any -> any any "
                                       "(msg:\"Testing modbus.access\"; "
                                       "modbus: access write holding, address 100, value 500<>1000;  sid:1;)");

    if (de_ctx->sig_list == NULL)
        goto end;

    if ((de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH] == NULL) ||
        (de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx == NULL)) {
        printf("de_ctx->pmatch_tail == NULL && de_ctx->pmatch_tail->ctx == NULL: ");
        goto end;
    }

    modbus = (DetectModbus *) de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_MODBUS_MATCH]->ctx;

    if ((modbus->type != type) ||
        ((*modbus->address).mode != addressMode) ||
        ((*modbus->address).min != 100)  ||
        ((*modbus->data).mode != valueMode) ||
        ((*modbus->data).min != 500)   ||
        ((*modbus->data).max != 1000)) {
        printf("expected function %" PRIu8 ", got %" PRIu8 ": ", type, modbus->type);
        printf("expected address mode %" PRIu8 ", got %" PRIu16 ": ", addressMode, (*modbus->address).mode);
        printf("expected address %" PRIu8 ", got %" PRIu16 ": ", 500, (*modbus->address).min);
        printf("expected value mode %" PRIu8 ", got %" PRIu16 ": ", valueMode, (*modbus->data).mode);
        printf("expected min value %" PRIu8 ", got %" PRIu16 ": ", 500, (*modbus->data).min);
        printf("expected max value %" PRIu8 ", got %" PRIu16 ": ", 1000, (*modbus->data).max);
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectModbus
 */
void DetectModbusRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectModbusTest01 - Testing function", DetectModbusTest01, 1);
    UtRegisterTest("DetectModbusTest02 - Testing function and subfunction", DetectModbusTest02, 1);
    UtRegisterTest("DetectModbusTest03 - Testing category function", DetectModbusTest03, 1);
    UtRegisterTest("DetectModbusTest04 - Testing category function in negative", DetectModbusTest04, 1);
    UtRegisterTest("DetectModbusTest05 - Testing access type", DetectModbusTest05, 1);
    UtRegisterTest("DetectModbusTest06 - Testing access function", DetectModbusTest06, 1);
    UtRegisterTest("DetectModbusTest07 - Testing access at address", DetectModbusTest07, 1);
    UtRegisterTest("DetectModbusTest08 - Testing a range of address", DetectModbusTest08, 1);
    UtRegisterTest("DetectModbusTest09 - Testing write a range of value", DetectModbusTest09, 1);
#endif /* UNITTESTS */
}
