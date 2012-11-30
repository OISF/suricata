/* Copyright (C) 2012 Open Information Security Foundation
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
 * \author Yourname <youremail@yourdomain>
 *
 * Short description of the purpose of this keyword
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-helloworld.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*([0-9]+)?\\s*,s*([0-9]+)?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

/* prototypes */
static int DetectHelloWorldMatch (ThreadVars *, DetectEngineThreadCtx *,
        Packet *, Signature *, const SigMatchCtx *);
static int DetectHelloWorldSetup (DetectEngineCtx *, Signature *, char *);
static void DetectHelloWorldFree (void *);
static void DetectHelloWorldRegisterTests (void);

/**
 * \brief Registration function for helloworld: keyword
 */
void DetectHelloWorldRegister(void) {
    sigmatch_table[DETECT_HELLOWORLD].name = "helloworld";
    sigmatch_table[DETECT_HELLOWORLD].desc = "<todo>";
    sigmatch_table[DETECT_HELLOWORLD].url = "<todo>";
    sigmatch_table[DETECT_HELLOWORLD].Match = DetectHelloWorldMatch;
    sigmatch_table[DETECT_HELLOWORLD].Setup = DetectHelloWorldSetup;
    sigmatch_table[DETECT_HELLOWORLD].Free = DetectHelloWorldFree;
    sigmatch_table[DETECT_HELLOWORLD].RegisterTests = DetectHelloWorldRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    if (parse_regex != NULL)
        SCFree(parse_regex);
    if (parse_regex_study != NULL)
        SCFree(parse_regex_study);
    return;
}

/**
 * \brief This function is used to match HELLOWORLD rule option on a packet
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch with context that we will cast into DetectHelloWorldData
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectHelloWorldMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                           Signature *s, const SigMatchCtx *ctx)
{
    int ret = 0;
    const DetectHelloWorldData *helloworldd = (const DetectHelloWorldData *) ctx;
#if 0
    if (PKT_IS_PSEUDOPKT(p)) {
        /* fake pkt */
    }

    if (PKT_IS_IPV4(p)) {
        /* ipv4 pkt */
    } else if (PKT_IS_IPV6(p)) {
        /* ipv6 pkt */
    } else {
        SCLogDebug("pcket is of not IPv4 or IPv6");
        return ret;
    }
#endif
    /* packet payload access */
    if (p->payload != NULL && p->payload_len > 0) {
        if (helloworldd->helloworld1 == p->payload[0] &&
            helloworldd->helloworld2 == p->payload[p->payload_len - 1])
        {
            ret = 1;
        }
    }

    return ret;
}

/**
 * \brief This function is used to parse helloworld options passed via helloworld: keyword
 *
 * \param helloworldstr Pointer to the user provided helloworld options
 *
 * \retval helloworldd pointer to DetectHelloWorldData on success
 * \retval NULL on failure
 */

DetectHelloWorldData *DetectHelloWorldParse (char *helloworldstr)
{
    DetectHelloWorldData *helloworldd = NULL;
    char *arg1 = NULL;
    char *arg2 = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, helloworldstr, strlen(helloworldstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }
    const char *str_ptr;

    res = pcre_get_substring((char *) helloworldstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    arg1 = (char *) str_ptr;
    SCLogDebug("Arg1 \"%s\"", arg1);

    if (ret >= 3) {
        res = pcre_get_substring((char *) helloworldstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }
        arg2 = (char *) str_ptr;
        SCLogDebug("Arg2 \"%s\"", arg2);

    }

    helloworldd = SCMalloc(sizeof (DetectHelloWorldData));
    if (unlikely(helloworldd == NULL))
        goto error;
    helloworldd->helloworld1 = (uint8_t)atoi(arg1);
    helloworldd->helloworld2 = (uint8_t)atoi(arg2);

    SCFree(arg1);
    SCFree(arg2);
    return helloworldd;

error:
    if (helloworldd)
        SCFree(helloworldd);
    if (arg1)
        SCFree(arg1);
    if (arg2)
        SCFree(arg2);
    return NULL;
}

/**
 * \brief this function is used to ahelloworldd the parsed helloworld data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param helloworldstr pointer to the user provided helloworld options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectHelloWorldSetup (DetectEngineCtx *de_ctx, Signature *s, char *helloworldstr)
{
    DetectHelloWorldData *helloworldd = NULL;
    SigMatch *sm = NULL;

    helloworldd = DetectHelloWorldParse(helloworldstr);
    if (helloworldd == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_HELLOWORLD;
    sm->ctx = (void *)helloworldd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

error:
    if (helloworldd != NULL)
        DetectHelloWorldFree(helloworldd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectHelloWorldData
 *
 * \param ptr pointer to DetectHelloWorldData
 */
void DetectHelloWorldFree(void *ptr) {
    DetectHelloWorldData *helloworldd = (DetectHelloWorldData *)ptr;
    SCFree(helloworldd);
}

#ifdef UNITTESTS

/**
 * \test description of the test
 */

static int DetectHelloWorldParseTest01 (void) {
    DetectHelloWorldData *helloworldd = NULL;
    uint8_t res = 0;

    helloworldd = DetectHelloWorldParse("1,10");
    if (helloworldd != NULL) {
        if (helloworldd->helloworld1 == 1 && helloworldd->helloworld2 == 10)
            res = 1;

        DetectHelloWorldFree(helloworldd);
    }

    return res;
}

static int DetectHelloWorldSignatureTest01 (void) {
    uint8_t res = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (helloworld:1,10; sid:1; rev:1;)");
    if (sig == NULL) {
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
 * \brief this function registers unit tests for DetectHelloWorld
 */
void DetectHelloWorldRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectHelloWorldParseTest01",
            DetectHelloWorldParseTest01, 1);
    UtRegisterTest("DetectHelloWorldSignatureTest01",
            DetectHelloWorldSignatureTest01, 1);
#endif /* UNITTESTS */
}
