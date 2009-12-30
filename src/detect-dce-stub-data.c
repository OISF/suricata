/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-dce-stub-data.h"

#include "util-debug.h"
#include "util-unittest.h"

int DetectDceStubDataMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t,
                           void *, Signature *, SigMatch *);
int DetectDceStubDataSetup(DetectEngineCtx *, Signature *s, SigMatch *m, char *arg);

/**
 * \brief Registers the keyword handlers for the "dce_stub_data" keyword.
 */
void DetectDceStubDataRegister(void)
{
    sigmatch_table[DETECT_DCE_STUB_DATA].name = "dce_stub_data";
    sigmatch_table[DETECT_DCE_STUB_DATA].Match = NULL;
    sigmatch_table[DETECT_DCE_STUB_DATA].AppLayerMatch = DetectDceStubDataMatch;
    sigmatch_table[DETECT_DCE_STUB_DATA].Setup = DetectDceStubDataSetup;
    sigmatch_table[DETECT_DCE_STUB_DATA].Free  = NULL;
    sigmatch_table[DETECT_DCE_STUB_DATA].RegisterTests = DetectDceStubDataRegisterTests;

    return;
}

int DetectDceStubDataMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
                           uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    return 1;
}

/**
 * \brief Creates a SigMatch for the "dce_stub_data" keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed
 * \param arg    Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */

int DetectDceStubDataSetup(DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                           char *arg)
{
    SigMatch *sm = NULL;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DCE_STUB_DATA;
    sm->ctx = NULL;

    SigMatchAppend(s, m, sm);

    return 0;

 error:
    if (sm != NULL)
        free(sm);
    return -1;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

static int DetectDceStubDataTestParse01(void)
{
    Signature s;
    int result = 0;

    memset(&s, 0, sizeof(Signature));

    result = (DetectDceStubDataSetup(NULL, &s, NULL, NULL) == 0);

    if (s.match != NULL) {
        result = 1;
    }

    return result;
}

#endif

void DetectDceStubDataRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("DetectDceStubDataTestParse01", DetectDceStubDataTestParse01, 1);

#endif

}
