/* DSIZE part of the detection engine. */

#include "decode.h"
#include "detect.h"
#include "flow-var.h"

#include "util-unittest.h"

#include <pcre.h>

#define PARSE_REGEX "^(?:\\\")?(<|>)?([0-9]+)(?:(<>)([0-9]+))?(?:\\\")?$"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

#define LT 0
#define EQ 1
#define GT 2
#define RA 3

typedef struct _DetectDsizeData {
    u_int16_t dsize;
    u_int16_t dsize2;
    u_int8_t mode;
} DetectDsizeData;

int DetectDsizeMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectDsizeSetup (DetectEngineCtx *, Signature *s, SigMatch *m, char *str);
void DsizeRegisterTests(void);

void DetectDsizeRegister (void) {
    sigmatch_table[DETECT_DSIZE].name = "dsize";
    sigmatch_table[DETECT_DSIZE].Match = DetectDsizeMatch;
    sigmatch_table[DETECT_DSIZE].Setup = DetectDsizeSetup;
    sigmatch_table[DETECT_DSIZE].Free  = NULL;
    sigmatch_table[DETECT_DSIZE].RegisterTests = DsizeRegisterTests;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectDsizeMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
    int ret = 0;

    DetectDsizeData *dd = (DetectDsizeData *)m->ctx;

    if (dd->mode == EQ && dd->dsize == p->tcp_payload_len)
        ret = 1;
    else if (dd->mode == LT && p->tcp_payload_len < dd->dsize)
        ret = 1;
    else if (dd->mode == GT && p->tcp_payload_len > dd->dsize)
        ret = 1;
    else if (dd->mode == RA && p->tcp_payload_len > dd->dsize && p->tcp_payload_len < dd->dsize2)
        ret = 1;

    return ret;
}

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
        //printf("DetectDsizeSetup: parse error, ret %d\n", ret);
        goto error;
    }

    const char *str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        printf("DetectDsizeSetup: pcre_get_substring failed\n");
        goto error;
    }
    mode = (char *)str_ptr;
    //printf("mode \"%s\"\n", mode);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        printf("DetectDsizeSetup: pcre_get_substring failed\n");
        goto error;
    }
    value1 = (char *)str_ptr;
    //printf("value1 \"%s\"\n", value1);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
    if (res < 0) {
        printf("DetectDsizeSetup: pcre_get_substring failed\n");
        goto error;
    }
    range = (char *)str_ptr;
    //printf("range \"%s\"\n", range);

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, &str_ptr);
    if (res < 0) {
        printf("DetectDsizeSetup: pcre_get_substring failed\n");
        goto error;
    }
    value2 = (char *)str_ptr;
    //printf("value2 \"%s\"\n", value2);

    dd = malloc(sizeof(DetectDsizeData));
    if (dd == NULL) {
        printf("DetectDsizeSetup malloc failed\n");
        goto error;
    }
    dd->dsize = 0;
    dd->dsize2 = 0;

    if (mode[0] == '<') dd->mode = LT;
    else if (mode[0] == '>') dd->mode = GT;
    else dd->mode = EQ;

    if (strcmp("<>", range) == 0) {
        if (strlen(mode) != 0)
            goto error;

        dd->mode = RA;
    }

    /* set the value */
    dd->dsize = (u_int16_t)atoi(value1);
    if (strlen(value2) > 0) {
        if (dd->mode != RA)
            goto error;

        dd->dsize2 = (u_int16_t)atoi(value2);

        if (dd->dsize2 <= dd->dsize)
            goto error;
    }

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

int DetectDsizeSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *rawstr)
{
    DetectDsizeData *dd = NULL;
    SigMatch *sm = NULL;

    //printf("DetectDsizeSetup: \'%s\'\n", rawstr);

    dd = DetectDsizeParse(rawstr);
    if (dd == NULL) goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DSIZE;
    sm->ctx = (void *)dd;

    SigMatchAppend(s,m,sm);
    return 0;

error:
    if (dd) free(dd);
    if (sm) free(sm);
    return -1;
}

void DetectDsizeFree(DetectDsizeData *dd) {
    free(dd);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
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

int DsizeTestParse02 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

int DsizeTestParse03 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

int DsizeTestParse04 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        DetectDsizeFree(dd);
        return 1;
    }

    return 0;
}

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

int DsizeTestParse06 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10");
    if (dd) {
        if (dd->dsize == 10 && dd->mode == GT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

int DsizeTestParse07 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<100");
    if (dd) {
        if (dd->dsize == 100 && dd->mode == LT)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

int DsizeTestParse08 (void) {
    int result = 0;
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>2");
    if (dd) {
        if (dd->dsize == 1 && dd->dsize2 == 2 && dd->mode == RA)
            result = 1;

        DetectDsizeFree(dd);
    }

    return result;
}

int DsizeTestParse09 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("A");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

int DsizeTestParse10 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(">10<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

int DsizeTestParse11 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("<>10");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

int DsizeTestParse12 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("1<>");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

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

int DsizeTestParse14 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

int DsizeTestParse15 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse(" ");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

int DsizeTestParse16 (void) {
    DetectDsizeData *dd = NULL;
    dd = DetectDsizeParse("2<>1");
    if (dd) {
        DetectDsizeFree(dd);
        return 0;
    }

    return 1;
}

void DsizeRegisterTests(void) {
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
}

