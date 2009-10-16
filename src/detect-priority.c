/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-unittest.h"

#define DETECT_PRIORITY_REGEX "^\\s*(\\d+|\"\\d+\")\\s*$"

static pcre *regex = NULL;
static pcre_extra *regex_study = NULL;

int DetectPrioritySetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *sidstr);
void SCPriorityRegisterTests(void);

/**
 * \brief Registers the handler functions for the "priority" keyword
 */
void DetectPriorityRegister (void)
{
    const char *eb = NULL;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_PRIORITY].name = "priority";
    sigmatch_table[DETECT_PRIORITY].Match = NULL;
    sigmatch_table[DETECT_PRIORITY].Setup = DetectPrioritySetup;
    sigmatch_table[DETECT_PRIORITY].Free = NULL;
    sigmatch_table[DETECT_PRIORITY].RegisterTests = SCPriorityRegisterTests;

    regex = pcre_compile(DETECT_PRIORITY_REGEX, opts, &eb, &eo, NULL);
    if (regex == NULL) {
        SCLogDebug("Compile of \"%s\" failed at offset %" PRId32 ": %s",
                   DETECT_PRIORITY_REGEX, eo, eb);
        goto end;
    }

    regex_study = pcre_study(regex, 0, &eb);
    if (eb != NULL) {
        SCLogDebug("pcre study failed: %s", eb);
        goto end;
    }

 end:
    return;
}

int DetectPrioritySetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    const char *prio_str = NULL;

#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(regex, regex_study, rawstr, strlen(rawstr), 0, 0, ov, 30);
    if (ret < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid Priority in Signature "
                     "- %s", rawstr);
        return -1;
    }

    ret = pcre_get_substring((char *)rawstr, ov, 30, 1, &prio_str);
    if (ret < 0) {
        SCLogInfo("pcre_get_substring() failed");
        return -1;
    }

    /* if we have reached here, we have had a valid priority.  Assign it */
    s->prio = atoi(prio_str);

    return 0;
}

/*------------------------------Unittests-------------------------------------*/

#ifdef UNITTESTS

int DetectPriorityTest01()
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Priority test\"; priority:2; sid:1;)");
    if (de_ctx->sig_list != NULL)
        result = 1;

    DetectEngineCtxFree(de_ctx);

end:
    return result;
}

int DetectPriorityTest02()
{
    int result = 0;
    Signature *last = NULL;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:1; sid:1;)");
    de_ctx->sig_list = last = sig;
    result = (sig != NULL);
    result &= (sig->prio == 1);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo; sid:1;)");
    last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:10boo; sid:1;)");
    last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:b10oo; sid:1;)");
    last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:boo10; sid:1;)");
    last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; priority:-1; sid:1;)");
    last->next = sig;
    result &= (sig == NULL);

    sig = SigInit(de_ctx, "alert tcp any any -> any any "
                  "(msg:\"Priority test\"; sid:1;)");
    last->next = sig;
    last = sig;
    result &= (sig != NULL);
    result &= (sig->prio == 3);

    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    return result;
}


#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for Classification Config API.
 */
void SCPriorityRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("DetectPriorityTest01", DetectPriorityTest01, 1);
    UtRegisterTest("DetectPriorityTest02", DetectPriorityTest02, 1);

#endif /* UNITTESTS */

}
