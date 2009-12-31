/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-dce-opnum.h"

#include "util-debug.h"
#include "util-unittest.h"

#define DETECT_DCE_OPNUM_PCRE_PARSE_ARGS "^\\s*([0-9]{1,5}(\\s*-\\s*[0-9]{1,5}\\s*)?)(,\\s*[0-9]{1,5}(\\s*-\\s*[0-9]{1,5})?\\s*)*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

int DetectDceOpnumMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t,
                        void *, Signature *, SigMatch *);
int DetectDceOpnumSetup(DetectEngineCtx *, Signature *s, SigMatch *m, char *arg);
void DetectDceOpnumFree(void *);

/**
 * \brief Registers the keyword handlers for the "dce_opnum" keyword.
 */
void DetectDceOpnumRegister(void)
{
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_DCE_OPNUM].name = "dce_iface";
    sigmatch_table[DETECT_DCE_OPNUM].Match = NULL;
    sigmatch_table[DETECT_DCE_OPNUM].AppLayerMatch = DetectDceOpnumMatch;
    sigmatch_table[DETECT_DCE_OPNUM].Setup = DetectDceOpnumSetup;
    sigmatch_table[DETECT_DCE_OPNUM].Free  = DetectDceOpnumFree;
    sigmatch_table[DETECT_DCE_OPNUM].RegisterTests = DetectDceOpnumRegisterTests;

    parse_regex = pcre_compile(DETECT_DCE_OPNUM_PCRE_PARSE_ARGS, opts, &eb,
                               &eo, NULL);
    if (parse_regex == NULL) {
        SCLogDebug("pcre compile of \"%s\" failed at offset %" PRId32 ": %s",
                   DETECT_DCE_OPNUM_PCRE_PARSE_ARGS, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogDebug("pcre study failed: %s", eb);
        goto error;
    }

    return;

 error:
    /* we need to handle error?! */
    return;
}

/**
 * \internal
 * \brief Creates and returns a new instance of DetectDceOpnumRange.
 *
 * \retval dor Pointer to the new instance DetectDceOpnumRange.
 */
static inline DetectDceOpnumRange *DetectDceOpnumAllocDetectDceOpnumRange(void)
{
    DetectDceOpnumRange *dor = NULL;

    if ( (dor = malloc(sizeof(DetectDceOpnumRange))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(dor, 0, sizeof(DetectDceOpnumRange));
    dor->range1 = dor->range2 = -1;

    return dor;
}

/**
 * \internal
 * \brief Parses the argument sent along with the "dce_opnum" keyword.
 *
 * \param arg Pointer to the string containing the argument to be parsed.
 *
 * \retval did Pointer to a DetectDceIfaceData instance that holds the data
 *             from the parsed arg.
 */
static inline DetectDceOpnumData *DetectDceOpnumArgParse(const char *arg)
{
    DetectDceOpnumData *dod = NULL;

    DetectDceOpnumRange *dor = NULL;
    DetectDceOpnumRange *prev_dor = NULL;

#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *pcre_sub_str = NULL;

    char *dup_str = NULL;
    char *dup_str_temp = NULL;
    char *dup_str_head = NULL;
    char *comma_token = NULL;
    char *hyphen_token = NULL;

    ret = pcre_exec(parse_regex, parse_regex_study, arg, strlen(arg), 0, 0, ov,
                    MAX_SUBSTRINGS);
    if (ret < 2) {
        SCLogDebug("pcre_exec parse error, ret %" PRId32 ", string %s", ret, arg);
        goto error;
    }

    res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 0, &pcre_sub_str);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED, "pcre_get_substring failed");
        goto error;
    }

    if ( (dod = malloc(sizeof(DetectDceOpnumData))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        goto error;
    }
    memset(dod, 0, sizeof(DetectDceOpnumData));

    if ( (dup_str = strdup(pcre_sub_str)) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    /* keep a copy of the strdup string in dup_str_head so that we can free it
     * once we are done using it */
    dup_str_head = dup_str;
    dup_str_temp = dup_str;
    while ( (comma_token = index(dup_str, ',')) != NULL) {
        comma_token[0] = '\0';
        dup_str = comma_token + 1;

        dor = DetectDceOpnumAllocDetectDceOpnumRange();

        if ( (hyphen_token = index(dup_str_temp, '-')) != NULL) {
            hyphen_token[0] = '\0';
            hyphen_token++;
            dor->range1 = atoi(dup_str_temp);
            if (dor->range1 > 65535)
                goto error;
            dor->range2 = atoi(hyphen_token);
            if (dor->range2 > 65535)
                goto error;
            if (dor->range1 > dor->range2)
                goto error;
        }
        dor->range1 = atoi(dup_str_temp);
        if (dor->range1 > 65535)
            goto error;

        if (prev_dor == NULL) {
            prev_dor = dor;
            dod->range = dor;
        } else {
            prev_dor->next = dor;
            prev_dor = dor;
        }

        dup_str_temp = dup_str;
    }

    dor = DetectDceOpnumAllocDetectDceOpnumRange();

    if ( (hyphen_token = index(dup_str, '-')) != NULL) {
        hyphen_token[0] = '\0';
        hyphen_token++;
        dor->range1 = atoi(dup_str);
        if (dor->range1 > 65535)
            goto error;
        dor->range2 = atoi(hyphen_token);
        if (dor->range2 > 65535)
            goto error;
        if (dor->range1 > dor->range2)
            goto error;
    }
    dor->range1 = atoi(dup_str);
    if (dor->range1 > 65535)
        goto error;

    if (prev_dor == NULL) {
        prev_dor = dor;
        dod->range = dor;
    } else {
        prev_dor->next = dor;
        prev_dor = dor;
    }

    if (dup_str_head != NULL)
        free(dup_str_head);

    return dod;

 error:
    if (dup_str_head != NULL)
        free(dup_str_head);
    DetectDceOpnumFree(dod);
    return NULL;
}

int DetectDceOpnumMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
                        uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    return 1;
}

/**
 * \brief Creates a SigMatch for the "dce_opnum" keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure
 */

int DetectDceOpnumSetup(DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                        char *arg)
{
    DetectDceOpnumData *dod = NULL;
    SigMatch *sm = NULL;

    dod = DetectDceOpnumArgParse(arg);
    if (dod == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dce_opnum option in "
                   "signature");
        goto error;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DCE_OPNUM;
    sm->ctx = (void *)dod;

    SigMatchAppend(s, m, sm);

    return 0;

 error:
    DetectDceOpnumFree(dod);
    if (sm != NULL)
        free(sm);
    return -1;
}

void DetectDceOpnumFree(void *ptr)
{
    DetectDceOpnumData *dod = ptr;
    DetectDceOpnumRange *dor = NULL;
    DetectDceOpnumRange *dor_temp = NULL;

    if (dod != NULL) {
        dor = dod->range;
        dor_temp = dod->range;
        while (dor != NULL) {
            dor_temp = dor;
            dor = dor->next;
            free(dor_temp);
        }
        free(dod);
    }

    return;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

static int DetectDceOpnumTestParse01(void)
{
    Signature *s = SigAlloc();
    int result = 0;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "12") == 0);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12,24") == 0);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12,12-24") == 0);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12-14,12,121,62-78") == 0);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12,26,62,61,6513-6666") == 0);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12,26,62,61,6513--") == -1);
    result &= (DetectDceOpnumSetup(NULL, s, NULL, "12-14,12,121,62-8") == -1);

    if (s->match != NULL) {
        SigFree(s);
        result &= 1;
    }

    return result;
}

static int DetectDceOpnumTestParse02(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "12") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 12 && dor->range2 == -1);
        result &= (dor->next == NULL);
    }

 end:
    SigFree(s);
    return result;
}

static int DetectDceOpnumTestParse03(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "12-24") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 12 && dor->range2 == 24);
        result &= (dor->next == NULL);
    }

 end:
    SigFree(s);
    return result;
}

static int DetectDceOpnumTestParse04(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "12-24,24,62-72,623-635,62,25,213-235") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 12 && dor->range2 == 24);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 24 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 62 && dor->range2 == 72);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 623 && dor->range2 == 635);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 62 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 25 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 213 && dor->range2 == 235);
        if (result == 0)
            goto end;
    }

 end:
    SigFree(s);
    return result;
}

static int DetectDceOpnumTestParse05(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "1,2,3,4,5,6,7") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 1 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 2 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 3 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 4 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 5 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 6 && dor->range2 == -1);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 7 && dor->range2 == -1);
        if (result == 0)
            goto end;
    }

 end:
    SigFree(s);
    return result;
}

static int DetectDceOpnumTestParse06(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "1-2,3-4,5-6,7-8") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 1 && dor->range2 == 2);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 3 && dor->range2 == 4);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 5 && dor->range2 == 6);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 7 && dor->range2 == 8);
        if (result == 0)
            goto end;

    }

 end:
    SigFree(s);
    return result;
}

static int DetectDceOpnumTestParse07(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceOpnumData *dod = NULL;
    DetectDceOpnumRange *dor = NULL;
    SigMatch *temp = NULL;

    memset(s, 0, sizeof(Signature));

    result = (DetectDceOpnumSetup(NULL, s, NULL, "1-2,3-4,5-6,7-8,9") == 0);

    if (s->match != NULL) {
        temp = s->match;
        dod = temp->ctx;
        if (dod == NULL)
            goto end;
        dor = dod->range;
        result &= (dor->range1 == 1 && dor->range2 == 2);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 3 && dor->range2 == 4);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 5 && dor->range2 == 6);
        result &= (dor->next != NULL);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 7 && dor->range2 == 8);
        if (result == 0)
            goto end;

        dor = dor->next;
        result &= (dor->range1 == 9 && dor->range2 == -1);
        if (result == 0)
            goto end;
    }

 end:
    SigFree(s);
    return result;
}

#endif

void DetectDceOpnumRegisterTests(void)
{

#ifdef UNITTESTS

    UtRegisterTest("DetectDceOpnumTestParse01", DetectDceOpnumTestParse01, 1);
    UtRegisterTest("DetectDceOpnumTestParse02", DetectDceOpnumTestParse02, 1);
    UtRegisterTest("DetectDceOpnumTestParse03", DetectDceOpnumTestParse03, 1);
    UtRegisterTest("DetectDceOpnumTestParse04", DetectDceOpnumTestParse04, 1);
    UtRegisterTest("DetectDceOpnumTestParse05", DetectDceOpnumTestParse05, 1);
    UtRegisterTest("DetectDceOpnumTestParse06", DetectDceOpnumTestParse06, 1);
    UtRegisterTest("DetectDceOpnumTestParse07", DetectDceOpnumTestParse07, 1);

#endif

}
