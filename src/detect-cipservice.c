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

/**
 * \file
 *
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * Set up ENIP Commnad and CIP Service rule parsing and entry point for matching
 */

#include "suricata-common.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"

#include "app-layer-enip-common.h"
#include "detect-cipservice.h"
#include "detect-engine-enip.h"

/*
 * CIP SERVICE CODE
 */

#ifdef UNITTESTS
#include "util-unittest.h"
#endif
/**
 * \brief CIP Service Detect Prototypes
 */
static int DetectCipServiceSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectCipServiceFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectCipServiceRegisterTests(void);
#endif
static int g_cip_buffer_id = 0;

/**
 * \brief Registration function for cip_service: keyword
 */
void DetectCipServiceRegister(void)
{
    SCEnter();
    sigmatch_table[DETECT_CIPSERVICE].name = "cip_service"; //rule keyword
    sigmatch_table[DETECT_CIPSERVICE].desc = "match on CIP Service";
    sigmatch_table[DETECT_CIPSERVICE].url = "/rules/enip-keyword.html#enip-cip-keywords";
    sigmatch_table[DETECT_CIPSERVICE].Match = NULL;
    sigmatch_table[DETECT_CIPSERVICE].Setup = DetectCipServiceSetup;
    sigmatch_table[DETECT_CIPSERVICE].Free = DetectCipServiceFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_CIPSERVICE].RegisterTests
            = DetectCipServiceRegisterTests;
#endif
    DetectAppLayerInspectEngineRegister2(
            "cip", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectCIP, NULL);
    DetectAppLayerInspectEngineRegister2(
            "cip", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectCIP, NULL);

    g_cip_buffer_id = DetectBufferTypeGetByName("cip");

    SCReturn;
}

/**
 * \brief This function is used to parse cip_service options passed via cip_service: keyword
 *
 * \param rulestr Pointer to the user provided rulestr options
 * Takes comma seperated string with numeric tokens.  Only first 3 are used
 *
 * \retval cipserviced pointer to DetectCipServiceData on success
 * \retval NULL on failure
 */
static DetectCipServiceData *DetectCipServiceParse(const char *rulestrc)
{
    const char delims[] = ",";
    DetectCipServiceData *cipserviced = NULL;

    //SCLogDebug("DetectCipServiceParse - rule string  %s", rulestr);

    /* strtok_r modifies the string so work with a copy */
    char *rulestr = SCStrdup(rulestrc);
    if (unlikely(rulestr == NULL))
        goto error;

    cipserviced = SCMalloc(sizeof(DetectCipServiceData));
    if (unlikely(cipserviced == NULL))
        goto error;

    cipserviced->cipservice = 0;
    cipserviced->cipclass = 0;
    cipserviced->matchattribute = 1;
    cipserviced->cipattribute = 0;

    char* token;
    char *save;
    uint8_t var;
    uint8_t input[3] = { 0, 0, 0 };
    uint8_t i = 0;

    token = strtok_r(rulestr, delims, &save);
    while (token != NULL)
    {
        if (i > 2) //for now only need 3 parameters
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "too many parameters");
            goto error;
        }

        if (i < 2) //if on service or class
        {
            if (!isdigit((int) *token))
            {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "parameter error %s", token);
                goto error;
            }
        } else //if on attribute
        {

            if (token[0] == '!')
            {
                cipserviced->matchattribute = 0;
                token++;
            }

            if (!isdigit((int) *token))
            {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "attribute error  %s", token);
                goto error;
            }

        }

        unsigned long num = atol(token);
        if ((num > MAX_CIP_SERVICE) && (i == 0))//if service greater than 7 bit
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid CIP service %lu", num);
            goto error;
        } else if ((num > MAX_CIP_CLASS) && (i == 1))//if service greater than 16 bit
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid CIP class %lu", num);
            goto error;
        } else if ((num > MAX_CIP_ATTRIBUTE) && (i == 2))//if service greater than 16 bit
        {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid CIP attribute %lu", num);
            goto error;
        }

        sscanf(token, "%2" SCNu8, &var);
        input[i++] = var;

        token = strtok_r(NULL, delims, &save);
    }

    if (i == 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "no tokens found");
        goto error;
    }

    cipserviced->cipservice = input[0];
    cipserviced->cipclass = input[1];
    cipserviced->cipattribute = input[2];
    cipserviced->tokens = i;

    SCLogDebug("DetectCipServiceParse - tokens %d", cipserviced->tokens);
    SCLogDebug("DetectCipServiceParse - service %d", cipserviced->cipservice);
    SCLogDebug("DetectCipServiceParse - class %d", cipserviced->cipclass);
    SCLogDebug("DetectCipServiceParse - match attribute %d",
            cipserviced->matchattribute);
    SCLogDebug("DetectCipServiceParse - attribute %d",
            cipserviced->cipattribute);

    SCFree(rulestr);
    SCReturnPtr(cipserviced, "DetectENIPFunction");

error:
    if (cipserviced)
        SCFree(cipserviced);
    if (rulestr)
        SCFree(rulestr);
    SCReturnPtr(NULL, "DetectENIP");
}

/**
 * \brief this function is used to a cipserviced the parsed cip_service data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided cip_service options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectCipServiceSetup(DetectEngineCtx *de_ctx, Signature *s,
        const char *rulestr)
{
    SCEnter();

    DetectCipServiceData *cipserviced = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    cipserviced = DetectCipServiceParse(rulestr);
    if (cipserviced == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CIPSERVICE;
    sm->ctx = (void *) cipserviced;

    SigMatchAppendSMToList(s, sm, g_cip_buffer_id);
    SCReturnInt(0);

error:
    if (cipserviced != NULL)
        DetectCipServiceFree(de_ctx, cipserviced);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectCipServiceData
 *
 * \param ptr pointer to DetectCipServiceData
 */
static void DetectCipServiceFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectCipServiceData *cipserviced = (DetectCipServiceData *) ptr;
    SCFree(cipserviced);
}

#ifdef UNITTESTS

/**
 * \test Test CIP Command parameter parsing
 */
static int DetectCipServiceParseTest01 (void)
{
    DetectCipServiceData *cipserviced = NULL;
    cipserviced = DetectCipServiceParse("7");
    FAIL_IF_NULL(cipserviced);
    FAIL_IF(cipserviced->cipservice != 7);
    DetectCipServiceFree(NULL, cipserviced);
    PASS;
}

/**
 * \test Test CIP Service signature
 */
static int DetectCipServiceSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (cip_service:1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectCipService
 */
static void DetectCipServiceRegisterTests(void)
{
    UtRegisterTest("DetectCipServiceParseTest01",
            DetectCipServiceParseTest01);
    UtRegisterTest("DetectCipServiceSignatureTest01",
            DetectCipServiceSignatureTest01);
}
#endif /* UNITTESTS */

/*
 * ENIP COMMAND CODE
 */

/**
 * \brief ENIP Commond Detect Prototypes
 */
static int DetectEnipCommandSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectEnipCommandFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectEnipCommandRegisterTests(void);
#endif
static int g_enip_buffer_id = 0;

/**
 * \brief Registration function for enip_command: keyword
 */
void DetectEnipCommandRegister(void)
{
    sigmatch_table[DETECT_ENIPCOMMAND].name = "enip_command"; //rule keyword
    sigmatch_table[DETECT_ENIPCOMMAND].desc
            = "rules for detecting EtherNet/IP command";
    sigmatch_table[DETECT_ENIPCOMMAND].url = "/rules/enip-keyword.html#enip-cip-keywords";
    sigmatch_table[DETECT_ENIPCOMMAND].Match = NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].Setup = DetectEnipCommandSetup;
    sigmatch_table[DETECT_ENIPCOMMAND].Free = DetectEnipCommandFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ENIPCOMMAND].RegisterTests
            = DetectEnipCommandRegisterTests;
#endif
    DetectAppLayerInspectEngineRegister2(
            "enip", ALPROTO_ENIP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectENIP, NULL);
    DetectAppLayerInspectEngineRegister2(
            "enip", ALPROTO_ENIP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectENIP, NULL);

    g_enip_buffer_id = DetectBufferTypeGetByName("enip");
}

/**
 * \brief This function is used to parse cip_service options passed via enip_command: keyword
 *
 * \param rulestr Pointer to the user provided rulestr options
 * Takes single single numeric value
 *
 * \retval enipcmdd pointer to DetectCipServiceData on success
 * \retval NULL on failure
 */
static DetectEnipCommandData *DetectEnipCommandParse(const char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;

    enipcmdd = SCMalloc(sizeof(DetectEnipCommandData));
    if (unlikely(enipcmdd == NULL))
        goto error;

    if (!(isdigit((int) *rulestr))) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid ENIP command %s", rulestr);
        goto error;
    }

    uint16_t cmd;
    if (StringParseUint16(&cmd, 10, 0, rulestr) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid ENIP command"
                   ": \"%s\"", rulestr);
        goto error;
    }

    enipcmdd->enipcommand = cmd;

    return enipcmdd;

error:
    if (enipcmdd)
        SCFree(enipcmdd);
    return NULL;
}

/**
 * \brief this function is used by enipcmdd to parse enip_command data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rulestr pointer to the user provided enip command options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectEnipCommandSetup(DetectEngineCtx *de_ctx, Signature *s,
        const char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_ENIP) != 0)
        return -1;

    enipcmdd = DetectEnipCommandParse(rulestr);
    if (enipcmdd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ENIPCOMMAND;
    sm->ctx = (void *) enipcmdd;

    SigMatchAppendSMToList(s, sm, g_enip_buffer_id);
    SCReturnInt(0);

error:
    if (enipcmdd != NULL)
        DetectEnipCommandFree(de_ctx, enipcmdd);
    if (sm != NULL)
        SCFree(sm);
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectEnipCommandData
 *
 * \param ptr pointer to DetectEnipCommandData
 */
static void DetectEnipCommandFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectEnipCommandData *enipcmdd = (DetectEnipCommandData *) ptr;
    SCFree(enipcmdd);
}

#ifdef UNITTESTS

/**
 * \test ENIP parameter test
 */

static int DetectEnipCommandParseTest01 (void)
{
    DetectEnipCommandData *enipcmdd = NULL;

    enipcmdd = DetectEnipCommandParse("1");
    FAIL_IF_NULL(enipcmdd);
    FAIL_IF_NOT(enipcmdd->enipcommand == 1);

    DetectEnipCommandFree(NULL, enipcmdd);
    PASS;
}

/**
 * \test ENIP Command signature test
 */
static int DetectEnipCommandSignatureTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (enip_command:1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectEnipCommand
 */
static void DetectEnipCommandRegisterTests(void)
{
    UtRegisterTest("DetectEnipCommandParseTest01",
            DetectEnipCommandParseTest01);
    UtRegisterTest("DetectEnipCommandSignatureTest01",
            DetectEnipCommandSignatureTest01);
}
#endif /* UNITTESTS */
