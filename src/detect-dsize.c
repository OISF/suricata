/* DSIZE part of the detection engine. */
/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Victor Julien <victor@inliniac.net>
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "detect-dsize.h"

#include "util-unittest.h"
#include "util-debug.h"
#include "util-byte.h"

/**
 *  dsize:[<>]<0-65535>[<><0-65535>];
 */
#define PARSE_REGEX "^\\s*(<|>)?\\s*([0-9]{1,5})\\s*(?:(<>)\\s*([0-9]{1,5}))?\\s*$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectDsizeMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectDsizeSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);
void DsizeRegisterTests(void);
static void DetectDsizeFree(void *);

/**
 * \brief Registration function for dsize: keyword
 */
void DetectDsizeRegister (void) {
    sigmatch_table[DETECT_DSIZE].name = "dsize";
    sigmatch_table[DETECT_DSIZE].Match = DetectDsizeMatch;
    sigmatch_table[DETECT_DSIZE].Setup = DetectDsizeSetup;
    sigmatch_table[DETECT_DSIZE].Free  = DetectDsizeFree;
    sigmatch_table[DETECT_DSIZE].RegisterTests = DsizeRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_PCRE_COMPILE_FAILED,"pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_PCRE_STUDY_FAILED,"pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/**
 * \internal
 * \brief This function is used to match flags on a packet with those passed via dsize:
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param s pointer to the Signature
 * \param m pointer to the sigmatch
 *
 * \retval 0 no match
 * \retval 1 match
 */
int DetectDsizeMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    int ret = 0;

    DetectDsizeData *dd = (DetectDsizeData *)m->ctx;

    if (dd->mode == DETECTDSIZE_EQ && dd->dsize == p->payload_len)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_LT && p->payload_len < dd->dsize)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_GT && p->payload_len > dd->dsize)
        ret = 1;
    else if (dd->mode == DETECTDSIZE_RA && p->payload_len > dd->dsize && p->payload_len < dd->dsize2)
        ret = 1;

    return ret;
}

/**
 * \internal
 * \brief This function is used to parse dsize options passed via dsize: keyword
 *
 * \param rawstr Pointer to the user provided dsize options
 *
 * \retval dd pointer to DetectDsizeData on success
 * \retval NULL on failure
 */
DetectDsizeData *DetectDsizeParse (char *rawstr)
{
    DetectDsizeData *dd = NULL;
    char *value1 = NULL, *value2 = NULL,
         *mode = NULL, *range = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 3 || ret > 5) {
        SCLogError(SC_PCRE_MATCH_FAILED,"Parse error %s", rawstr);
        goto error;
    }

    const char *str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED,"pcre_get_substring failed");
        goto error;
    }
    mode = (char *)str_ptr;
    SCLogDebug("mode \"%s\"", mode);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED,"pcre_get_substring failed");
        goto error;
    }
    value1 = (char *)str_ptr;
    SCLogDebug("value1 \"%s\"", value1);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED,"pcre_get_substring failed");
        goto error;
    }
    range = (char *)str_ptr;
    SCLogDebug("range \"%s\"", range);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, &str_ptr);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED,"pcre_get_substring failed");
        goto error;
    }
    value2 = (char *)str_ptr;
    SCLogDebug("value2 \"%s\"", value2);

    dd = malloc(sizeof(DetectDsizeData));
    if (dd == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        goto error;
    }
    dd->dsize = 0;
    dd->dsize2 = 0;

    if (mode[0] == '<') dd->mode = DETECTDSIZE_LT;
    else if (mode[0] == '>') dd->mode = DETECTDSIZE_GT;
    else dd->mode = DETECTDSIZE_EQ;

    if (strcmp("<>", range) == 0) {
        if (strlen(mode) != 0) {
            SCLogError(SC_INVALID_ARGUMENT,"Range specified but mode also set");
            goto error;
        }
        dd->mode = DETECTDSIZE_RA;
    }

    /** set the first dsize value */
    if(ByteExtractStringUint16(&dd->dsize,10,strlen(value1),value1) <= 0){
        SCLogError(SC_INVALID_ARGUMENT,"Invalid size value1:\"%s\"",value1);
        goto error;
    }

    /** set the second dsize value if specified */
    if (strlen(value2) > 0) {
        if (dd->mode != DETECTDSIZE_RA) {
            SCLogError(SC_INVALID_ARGUMENT,"Multiple dsize values specified but mode is not range");
            goto error;
        }

        if(ByteExtractStringUint16(&dd->dsize2,10,strlen(value2),value2) <= 0){
            SCLogError(SC_INVALID_ARGUMENT,"Invalid size value2:\"%s\"",value2);
            goto error;
        }

        if (dd->dsize2 <= dd->dsize){
            SCLogError(SC_INVALID_ARGUMENT,"dsize2:%"PRIu16" <= dsize:%"PRIu16"",dd->dsize2,dd->dsize);
            goto error;
        }
    }

    SCLogDebug("dsize parsed succesfully dsize: %"PRIu16" dsize2: %"PRIu16"",dd->dsize,dd->dsize2);

    free(value1);
    free(value2);
    free(mode);
    free(range);
    return dd;

error:
    if (dd) free(dd);
    if (value1) free(value1);
    if (value2) free(value2);
    if (mode) free(mode);
    if (range) free(range);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed dsize into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param m pointer to the Current SigMatch
 * \param rawstr pointer to the user provided flags options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectDsizeSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    DetectDsizeData *dd = NULL;
    SigMatch *sm = NULL;

    SCLogDebug("\'%s\'", rawstr);

    dd = DetectDsizeParse(rawstr);
    if (dd == NULL) {
        SCLogError(SC_INVALID_ARGUMENT,"Parsing \'%s\' failed", rawstr);
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL){
        SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory for SigMatch");
        goto error;
    }

    sm->type = DETECT_DSIZE;
    sm->ctx = (void *)dd;

    SigMatchAppend(s,m,sm);

    /* tell the sig it has a dsize to speed up engine init */
    s->flags |= SIG_FLAG_DSIZE;
    return 0;

error:
    if (dd) free(dd);
    if (sm) free(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectDsizeData
 *
 * \param de pointer to DetectDsizeData
 */
void DetectDsizeFree(void *de_ptr) {
    DetectDsizeData *dd = (DetectDsizeData *)de_ptr;
    if(dd) free(dd);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse01 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value >10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse02 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value <100
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse03 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value 1<>2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse04 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse05 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        if (dd->dsize == 1)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value >10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse06 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        if (dd->dsize == 10 && dd->mode == DETECTDSIZE_GT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value <100
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse07 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        if (dd->dsize == 100 && dd->mode == DETECTDSIZE_LT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a valid dsize value 1<>2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse08 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        if (dd->dsize == 1 && dd->dsize2 == 2 && dd->mode == DETECTDSIZE_RA)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a invalid dsize value A
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse09 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("A");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value >10<>10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse10 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value <>10
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse11 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value 1<>
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse12 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a valid dsize value 1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse13 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1");
    if (dd) {
        if (dd->dsize2 == 0)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is a test for a invalid dsize value ""
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse14 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value " "
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse15 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(" ");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a invalid dsize value 2<>1
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse16 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("2<>1");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

/**
 * \test this is a test for a valid dsize value 1 <> 2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse17 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(" 1 <> 2 ");
    if (dd) {
        if (dd->dsize == 1 && dd->dsize2 == 2 && dd->mode == DETECTDSIZE_RA)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test this is test for a valid dsize value > 2
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse18 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("> 2 ");
    if (dd) {
        if (dd->dsize == 2 && dd->mode == DETECTDSIZE_GT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test test for a valid dsize value <   12
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse19 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<   12 ");
    if (dd) {
        if (dd->dsize == 12 && dd->mode == DETECTDSIZE_LT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

/**
 * \test test for a valid dsize value    12
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int DsizeTestParse20 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("   12 ");
    if (dd) {
        if (dd->dsize == 12 && dd->mode == DETECTDSIZE_EQ)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for dsize
 */
void DsizeRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DsizeTestParse01", DsizeTestParse01, 1);
    UtRegisterTest("DsizeTestParse02", DsizeTestParse02, 1);
    UtRegisterTest("DsizeTestParse03", DsizeTestParse03, 1);
    UtRegisterTest("DsizeTestParse04", DsizeTestParse04, 1);
    UtRegisterTest("DsizeTestParse05", DsizeTestParse05, 1);
    UtRegisterTest("DsizeTestParse06", DsizeTestParse06, 1);
    UtRegisterTest("DsizeTestParse07", DsizeTestParse07, 1);
    UtRegisterTest("DsizeTestParse08", DsizeTestParse08, 1);
    UtRegisterTest("DsizeTestParse09", DsizeTestParse09, 1);
    UtRegisterTest("DsizeTestParse10", DsizeTestParse10, 1);
    UtRegisterTest("DsizeTestParse11", DsizeTestParse11, 1);
    UtRegisterTest("DsizeTestParse12", DsizeTestParse12, 1);
    UtRegisterTest("DsizeTestParse13", DsizeTestParse13, 1);
    UtRegisterTest("DsizeTestParse14", DsizeTestParse14, 1);
    UtRegisterTest("DsizeTestParse15", DsizeTestParse15, 1);
    UtRegisterTest("DsizeTestParse16", DsizeTestParse16, 1);
    UtRegisterTest("DsizeTestParse17", DsizeTestParse17, 1);
    UtRegisterTest("DsizeTestParse18", DsizeTestParse18, 1);
    UtRegisterTest("DsizeTestParse19", DsizeTestParse19, 1);
    UtRegisterTest("DsizeTestParse20", DsizeTestParse20, 1);
#endif /* UNITTESTS */
}

