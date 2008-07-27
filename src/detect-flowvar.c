/* Simple flowvar content match part of the detection engine.
 *
 * Copyright (C) 2008 by Victor Julien <victor@inliniac.net> */

#include <ctype.h>
#include <pcre.h>
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-var.h"
#include "detect-flowvar.h"
#include "util-binsearch.h"

#define PARSE_REGEX         "(.*),(.*)"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFlowvarMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectFlowvarSetup (Signature *, SigMatch *, char *);

void DetectFlowvarRegister (void) {
    sigmatch_table[DETECT_FLOWVAR].name = "flowvar";
    sigmatch_table[DETECT_FLOWVAR].Match = DetectFlowvarMatch;
    sigmatch_table[DETECT_FLOWVAR].Setup = DetectFlowvarSetup;
    sigmatch_table[DETECT_FLOWVAR].Free  = NULL;
    sigmatch_table[DETECT_FLOWVAR].RegisterTests  = NULL;

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
    return;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectFlowvarMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
    int ret = 0;
    DetectFlowvarData *fd = (DetectFlowvarData *)m->ctx;

    /* we need a lock */
    mutex_lock(&p->flow->m);

    FlowVar *fv = FlowVarGet(p->flow, fd->name);
    if (fv != NULL) {
        u_int8_t *ptr = BinSearch(fv->value, fv->value_len, fd->content, fd->content_len);
        if (ptr != NULL)
            ret = 1;
    }
    mutex_unlock(&p->flow->m);

    return ret;
}

int DetectFlowvarSetup (Signature *s, SigMatch *m, char *rawstr)
{
    DetectFlowvarData *cd = NULL;
    SigMatch *sm = NULL;
    char *str = rawstr;
    char dubbed = 0;
    u_int16_t len;
    char *varname = NULL, *varcontent = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            printf("DetectPcreSetup: pcre_get_substring failed\n");
            return -1;
        }
        varname = (char *)str_ptr;

        if (ret > 2) {
            res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
            if (res < 0) {
                printf("DetectPcreSetup: pcre_get_substring failed\n");
                return -1;
            }
            varcontent = (char *)str_ptr;
        }
    }

    printf("DetectFlowvarSetup: varname %s, varcontent %s\n", varname, varcontent);

    if (varcontent[0] == '\"' && varcontent[strlen(varcontent)-1] == '\"') {
        str = strdup(varcontent+1);
        str[strlen(varcontent)-2] = '\0';
        dubbed = 1;
    }

    len = strlen(str);
    if (len == 0)
        return -1;

    cd = malloc(sizeof(DetectFlowvarData));
    if (cd == NULL) {
        printf("DetectFlowvarSetup malloc failed\n");
        goto error;
    }

    char converted = 0;

    {
        u_int16_t i, x;
        u_int8_t bin = 0, binstr[3] = "", binpos = 0;
        for (i = 0, x = 0; i < len; i++) {
            // printf("str[%02u]: %c\n", i, str[i]);
            if (str[i] == '|') {
                if (bin) {
                    bin = 0;
                } else {
                    bin = 1;
                }
            } else {
                if (bin) {
                    if (isdigit(str[i]) ||
                        str[i] == 'A' || str[i] == 'a' ||
                        str[i] == 'B' || str[i] == 'b' ||
                        str[i] == 'C' || str[i] == 'c' ||
                        str[i] == 'D' || str[i] == 'd' ||
                        str[i] == 'E' || str[i] == 'e' ||
                        str[i] == 'F' || str[i] == 'f') {
                        // printf("part of binary: %c\n", str[i]);

                        binstr[binpos] = (char)str[i];
                        binpos++;

                        if (binpos == 2) {
                            u_int8_t c = strtol((char *)binstr, (char **) NULL, 16) & 0xFF;
#ifdef DEBUG
                            printf("Binstr %X\n", c);
#endif
                            binpos = 0;
                            str[x] = c;
                            x++;
                            converted = 1;
                        }
                    } else if (str[i] == ' ') {
                        // printf("space as part of binary string\n");
                    }
                } else {
                    str[x] = str[i];
                    x++;
                }
            }
        }
//#ifdef DEBUG
        for (i = 0; i < x; i++) {
            if (isprint(str[i])) printf("%c", str[i]);
            else                 printf("\\x%02u", str[i]);
        }
        printf("\n");
//#endif

        if (converted)
            len = x;
    }

    cd->content = malloc(len);
    if (cd->content == NULL)
        return -1;

    cd->name = strdup(varname);
    memcpy(cd->content, str, len);
    cd->content_len = len;
    cd->flags = 0;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FLOWVAR;
    sm->ctx = (void *)cd;

    SigMatchAppend(s,m,sm);

    if (dubbed) free(str);
    return 0;

error:
    if (dubbed) free(str);
    if (cd) free(cd);
    if (sm) free(sm);
    return -1;
}


