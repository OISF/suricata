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
#include "util-unittest.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"

#include "detect-cipservice.h"


/*
 * CIP SERVICE CODE
 */

/**
 * \brief CIP Service Detect Prototypes
 */
static int DetectCipServiceSetup(DetectEngineCtx *, Signature *, char *);
static void DetectCipServiceFree(void *);
static void DetectCipServiceRegisterTests(void);

/**
 * \brief Registration function for cip_service: keyword
 */
void DetectCipServiceRegister(void)
{
    SCEnter();
    sigmatch_table[DETECT_CIPSERVICE].name = "cip_service"; //rule keyword
    sigmatch_table[DETECT_CIPSERVICE].desc = "Rules for detecting CIP Service ";
    sigmatch_table[DETECT_CIPSERVICE].Match = NULL;
    sigmatch_table[DETECT_CIPSERVICE].AppLayerMatch = NULL;
    sigmatch_table[DETECT_CIPSERVICE].Setup = DetectCipServiceSetup;
    sigmatch_table[DETECT_CIPSERVICE].Free = DetectCipServiceFree;
    sigmatch_table[DETECT_CIPSERVICE].RegisterTests
            = DetectCipServiceRegisterTests;

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
DetectCipServiceData *DetectCipServiceParse(char *rulestr)
{
    const char delims[] = ",";
    DetectCipServiceData *cipserviced = NULL;

    //SCLogDebug("DetectCipServiceParse - rule string  %s\n", rulestr);

    cipserviced = SCMalloc(sizeof(DetectCipServiceData));
    if (unlikely(cipserviced == NULL))
        goto error;

    cipserviced->cipservice = 0;
    cipserviced->cipclass = 0;
    cipserviced->matchattribute = 1;
    cipserviced->cipattribute = 0;

    char* token;
    char *save;
    int var;
    int input[3];
    int i = 0;

    token = strtok_r(rulestr, delims, &save);
    while (token != NULL)
    {
        if (i > 2) //for now only need 3 parameters
        {
            printf("DetectEnipCommandParse: Too many parameters\n");
            goto error;
        }

        if (i < 2) //if on service or class
        {
            if (!isdigit((int) *token))
            {
                printf("DetectCipServiceParse - Parameter Error %s\n", token);
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
                printf("DetectCipServiceParse - Attribute Error  %s\n", token);
                goto error;
            }

        }

        unsigned long num = atol(token);
        if ((num > MAX_CIP_SERVICE) && (i == 0))//if service greater than 7 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP service %lu\n", num);
            goto error;
        } else if ((num > MAX_CIP_CLASS) && (i == 1))//if service greater than 16 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP class %lu\n", num);
            goto error;
        } else if ((num > MAX_CIP_ATTRIBUTE) && (i == 2))//if service greater than 16 bit
        {
            printf("DetectEnipCommandParse: Invalid CIP attribute %lu\n", num);
            goto error;
        }

        sscanf(token, "%d", &var);
        input[i++] = var;

        token = strtok_r(NULL, delims, &save);
    }

    cipserviced->cipservice = input[0];
    cipserviced->cipclass = input[1];
    cipserviced->cipattribute = input[2];
    cipserviced->tokens = i;

    SCLogDebug("DetectCipServiceParse - tokens %d\n", cipserviced->tokens);
    SCLogDebug("DetectCipServiceParse - service %d\n", cipserviced->cipservice);
    SCLogDebug("DetectCipServiceParse - class %d\n", cipserviced->cipclass);
    SCLogDebug("DetectCipServiceParse - match attribute %d\n",
            cipserviced->matchattribute);
    SCLogDebug("DetectCipServiceParse - attribute %d\n",
            cipserviced->cipattribute);

    SCReturnPtr(cipserviced, "DetectENIPFunction");

error:
    if (cipserviced)
        SCFree(cipserviced);
    printf("DetectCipServiceParse - Error Parsing Parameters\n");
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
        char *rulestr)
{
    SCEnter();

    DetectCipServiceData *cipserviced = NULL;
    SigMatch *sm = NULL;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_ENIP)
    {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                "rule contains conflicting keywords.");
        goto error;
    }

    cipserviced = DetectCipServiceParse(rulestr);
    if (cipserviced == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_CIPSERVICE;
    sm->ctx = (void *) cipserviced;

    s->alproto = ALPROTO_ENIP;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_CIP_MATCH);

    SCReturnInt(0);

error:
    if (cipserviced != NULL)
        DetectCipServiceFree(cipserviced);
    if (sm != NULL)
        SCFree(sm);
    printf("DetectCipServiceSetup - Error\n");

    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectCipServiceData
 *
 * \param ptr pointer to DetectCipServiceData
 */
void DetectCipServiceFree(void *ptr)
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
    uint8_t res = 1;

    /*DetectCipServiceData *cipserviced = NULL;
     cipserviced = DetectCipServiceParse("1");
     if (cipserviced != NULL)
     {
     if (cipserviced->cipservice == 1)
     {
     res = 1;
     }

     DetectCipServiceFree(cipserviced);
     }
     */
    return res;
}

/**
 * \test Test CIP Service signature
 */
static int DetectCipServiceSignatureTest01 (void)
{
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (cip_service:1; sid:1; rev:1;)");
    if (sig == NULL)
    {
        printf("parsing signature failed: ");
        goto end;
    }

    /* if we get here, all conditions pass */
    res = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return res;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectCipService
 */
void DetectCipServiceRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectCipServiceParseTest01",
            DetectCipServiceParseTest01);
    UtRegisterTest("DetectCipServiceSignatureTest01",
            DetectCipServiceSignatureTest01);
#endif /* UNITTESTS */
}

/*
 * ENIP COMMAND CODE
 */

/**
 * \brief ENIP Commond Detect Prototypes
 */
static int DetectEnipCommandSetup(DetectEngineCtx *, Signature *, char *);
static void DetectEnipCommandFree(void *);
static void DetectEnipCommandRegisterTests(void);

/**
 * \brief Registration function for enip_command: keyword
 */
void DetectEnipCommandRegister(void)
{
    sigmatch_table[DETECT_ENIPCOMMAND].name = "enip_command"; //rule keyword
    sigmatch_table[DETECT_ENIPCOMMAND].desc
            = "Rules for detecting EtherNet/IP command";
    sigmatch_table[DETECT_ENIPCOMMAND].Match = NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].AppLayerMatch = NULL;
    sigmatch_table[DETECT_ENIPCOMMAND].Setup = DetectEnipCommandSetup;
    sigmatch_table[DETECT_ENIPCOMMAND].Free = DetectEnipCommandFree;
    sigmatch_table[DETECT_ENIPCOMMAND].RegisterTests
            = DetectEnipCommandRegisterTests;

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
DetectEnipCommandData *DetectEnipCommandParse(char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;

    enipcmdd = SCMalloc(sizeof(DetectEnipCommandData));
    if (unlikely(enipcmdd == NULL))
        goto error;

    if (isdigit((int) *rulestr))
    {
        unsigned long cmd = atol(rulestr);
        if (cmd > MAX_ENIP_CMD) //if command greater than 16 bit
        {
            //printf("DetectEnipCommandParse: Invalid ENIP command %lu\n", cmd);
            goto error;
        }

        enipcmdd->enipcommand = (uint16_t) atoi(rulestr);

    } else
    {
        goto error;
    }

    return enipcmdd;

error:
    if (enipcmdd)
        SCFree(enipcmdd);
    //printf("DetectEnipCommandParse - Error Parsing Parameters\n");
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
        char *rulestr)
{
    DetectEnipCommandData *enipcmdd = NULL;
    SigMatch *sm = NULL;

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_ENIP)
    {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                "rule contains conflicting keywords.");
        goto error;
    }

    enipcmdd = DetectEnipCommandParse(rulestr);
    if (enipcmdd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ENIPCOMMAND;
    sm->ctx = (void *) enipcmdd;

    s->alproto = ALPROTO_ENIP;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_ENIP_MATCH);

    SCReturnInt(0);

error:
    if (enipcmdd != NULL)
        DetectEnipCommandFree(enipcmdd);
    if (sm != NULL)
        SCFree(sm);
    printf("DetectEnipCommandSetup - Error\n");
    SCReturnInt(-1);
}

/**
 * \brief this function will free memory associated with DetectEnipCommandData
 *
 * \param ptr pointer to DetectEnipCommandData
 */
void DetectEnipCommandFree(void *ptr)
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

    DetectEnipCommandFree(enipcmdd);
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

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectEnipCommand
 */
void DetectEnipCommandRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectEnipCommandParseTest01",
            DetectEnipCommandParseTest01);
    UtRegisterTest("DetectEnipCommandSignatureTest01",
            DetectEnipCommandSignatureTest01);
#endif /* UNITTESTS */
}

