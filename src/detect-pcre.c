/* PCRE part of the detection engine. */

#include <pcre.h>

#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "pkt-var.h"
#include "flow-var.h"

#include "detect-pcre.h"

#include "detect-engine-mpm.h"

#define PARSE_CAPTURE_REGEX "\\(\\?P\\<([A-z]+)\\_([A-z0-9_]+)\\>"
#define PARSE_REGEX         "(?<!\\\\)/(.*)(?<!\\\\)/([A-z]*)"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_capture_regex;
static pcre_extra *parse_capture_regex_study;

int DetectPcreMatch (ThreadVars *, PatternMatcherThread *, Packet *, Signature *, SigMatch *);
int DetectPcreSetup (Signature *, SigMatch *, char *);
int DetectPcreFree(SigMatch *);

void DetectPcreRegister (void) {
    sigmatch_table[DETECT_PCRE].name = "pcre";
    sigmatch_table[DETECT_PCRE].Match = DetectPcreMatch;
    sigmatch_table[DETECT_PCRE].Setup = DetectPcreSetup;
    sigmatch_table[DETECT_PCRE].Free  = DetectPcreFree;
    sigmatch_table[DETECT_PCRE].RegisterTests  = NULL;

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

    opts |= PCRE_UNGREEDY; /* pkt_http_ua should be pkt, http_ua, for this reason the UNGREEDY */
    parse_capture_regex = pcre_compile(PARSE_CAPTURE_REGEX, opts, &eb, &eo, NULL);
    if(parse_capture_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", PARSE_CAPTURE_REGEX, eo, eb);
        goto error;
    }

    parse_capture_regex_study = pcre_study(parse_capture_regex, 0, &eb);
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

int DetectPcreMatch (ThreadVars *t, PatternMatcherThread *pmt, Packet *p, Signature *s, SigMatch *m)
{
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    u_int8_t *ptr = NULL;
    u_int16_t len = 0;

    if (p->tcp_payload_len == 0)
        return 0;

    //printf("DetectPcre: pre match: t->pkt_ptr %p t->pkt_off %u\n", t->pkt_ptr, t->pkt_off);

    DetectPcreData *pe = (DetectPcreData *)m->ctx;
    if (s->flags & SIG_FLAG_RECURSIVE) {
        ptr = pmt->pkt_ptr ? pmt->pkt_ptr : p->tcp_payload;
        len = p->tcp_payload_len - pmt->pkt_off;
    } else if (pe->flags & DETECT_PCRE_RELATIVE) {
        ptr = pmt->pkt_ptr;
        len = p->tcp_payload_len - pmt->pkt_off;
        if (ptr == NULL || len == 0)
            return 0;
    } else {
        ptr = p->tcp_payload;
        len = p->tcp_payload_len;
    }

    //printf("DetectPcre: ptr %p, len %u\n", ptr, len);

    ret = pcre_exec(pe->re, pe->sd, (char *)ptr, len, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret >= 0) {
        if (ret > 1 && pe->capname != NULL) {
            const char *str_ptr;
            ret = pcre_get_substring((char *)ptr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
            if (ret) {
                if (strcmp(pe->capname,"http_uri") == 0) {
                    if (pmt->de_scanned_httpuri == 1)
                        PacketPatternCleanup(t, pmt);

                    pmt->de_have_httpuri = 1;
                    pmt->de_scanned_httpuri = 0;

                    p->http_uri.raw[pmt->pkt_cnt] = (u_int8_t *)str_ptr;
                    p->http_uri.raw_size[pmt->pkt_cnt] = ret;
                    p->http_uri.cnt = pmt->pkt_cnt + 1;
                } else {
                    if (pe->flags & DETECT_PCRE_CAPTURE_PKT) {
                        PktVarAdd(p, pe->capname, (u_int8_t *)str_ptr, ret);
                    } else if (pe->flags & DETECT_PCRE_CAPTURE_FLOW) {
                        FlowVarAdd(p->flow, pe->capname, (u_int8_t *)str_ptr, ret);
                    }
                }
            }
        }

        /* update ptrs for pcre RELATIVE */
        pmt->pkt_ptr =  ptr+ov[1];
        pmt->pkt_off = (ptr+ov[1]) - p->tcp_payload;
        //printf("DetectPcre: post match: t->pkt_ptr %p t->pkt_off %u\n", t->pkt_ptr, t->pkt_off);

        ret = 1;
    } else {
        ret = 0;
    }

    //printf("DetectPcreMatch: ret %d\n", ret);
    return ret;
}

int DetectPcreSetup (Signature *s, SigMatch *m, char *regexstr)
{
    const char *eb;
    int eo;
    int opts = 0;
    DetectPcreData *pd = NULL;
    SigMatch *sm = NULL;
    char *re = NULL, *op_ptr = NULL, *op = NULL;
    char dubbed = 0;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *capture_str_ptr = NULL, *type_str_ptr = NULL;

    //printf("DetectPcreSetup: \'%s\'\n", regexstr);

    ret = pcre_exec(parse_capture_regex, parse_capture_regex_study, regexstr, strlen(regexstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret > 1) {
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 1, &type_str_ptr);
        if (res < 0) {
            printf("DetectPcreSetup: pcre_get_substring failed\n");
            return -1;
        }
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 2, &capture_str_ptr);
        if (res < 0) {
            printf("DetectPcreSetup: pcre_get_substring failed\n");
            return -1;
        }
    }
    //printf("DetectPcreSetup: type \'%s\'\n", type_str_ptr ? type_str_ptr : "NULL");
    //printf("DetectPcreSetup: capture \'%s\'\n", capture_str_ptr ? capture_str_ptr : "NULL");

    ret = pcre_exec(parse_regex, parse_regex_study, regexstr, strlen(regexstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 0) {
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            printf("DetectPcreSetup: pcre_get_substring failed\n");
            return -1;
        }
        re = (char *)str_ptr;

        if (ret > 2) {
            res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
            if (res < 0) {
                printf("DetectPcreSetup: pcre_get_substring failed\n");
                return -1;
            }
            op_ptr = op = (char *)str_ptr;
        }
    }
    //printf("ret %d re \'%s\', op \'%s\'\n", ret, re, op);

    pd = malloc(sizeof(DetectPcreData));
    if (pd == NULL) {
        printf("DetectPcreSetup malloc failed\n");
        goto error;
    }
    memset(pd, 0, sizeof(DetectPcreData));

    pd->depth = 0;
    pd->flags = 0;

    if (capture_str_ptr != NULL) {
        pd->capname = strdup((char *)capture_str_ptr);
    }
    if (type_str_ptr != NULL) {
        if (strcmp(type_str_ptr,"pkt") == 0) {
            pd->flags |= DETECT_PCRE_CAPTURE_PKT;
        } else if (strcmp(type_str_ptr,"flow") == 0) {
            pd->flags |= DETECT_PCRE_CAPTURE_FLOW;
        }
    }
    //printf("DetectPcreSetup: pd->capname %s\n", pd->capname ? pd->capname : "NULL");

    if (op != NULL) {
        while (*op) {
            DEBUGPRINT("DetectPcreSetup: regex option %c", *op);

            switch (*op) {
                case 'A':
                    opts |= PCRE_ANCHORED;
                    break;
                case 'E':
                    opts |= PCRE_DOLLAR_ENDONLY;
                    break;
                case 'G':
                    opts |= PCRE_UNGREEDY;
                    break;

                case 'i':
                    opts |= PCRE_CASELESS;
                    break;
                case 'm':
                    opts |= PCRE_MULTILINE;
                    break;
                case 's':
                    opts |= PCRE_DOTALL;
                    break;
                case 'x':
                    opts |= PCRE_EXTENDED;
                    break;

                case 'B': /* snort's option */
                    pd->flags |= DETECT_PCRE_RAWBYTES;
                    break;
                case 'R': /* snort's option */
                    pd->flags |= DETECT_PCRE_RELATIVE;
                    break;
                case 'U': /* snort's option */
                    pd->flags |= DETECT_PCRE_URI;
                    break;
                default:
                    printf("DetectPcreSetup: unknown regex modifier '%c'\n", *op);
                    break;
            }
            op++;
        }
    }

    //printf("DetectPcreSetup: \"%s\"\n", re);

    pd->re = pcre_compile(re, opts, &eb, &eo, NULL);
    if(pd->re == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %d: %s\n", regexstr, eo, eb);
        goto error;
    }

    pd->sd = pcre_study(pd->re, 0, &eb);
    if(eb != NULL)
    {
        printf("pcre study failed : %s\n", eb);
        goto error;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_PCRE;
    sm->ctx = (void *)pd;

    SigMatchAppend(s,m,sm);

    if (type_str_ptr != NULL) pcre_free((char *)type_str_ptr);
    if (capture_str_ptr != NULL) pcre_free((char *)capture_str_ptr);
    if (re != NULL) free(re);
    if (op_ptr != NULL) free(op_ptr);
    return 0;

error:
    if (re != NULL) free(re);
    if (op_ptr != NULL) free(op_ptr);
    if (pd != NULL && pd->capname != NULL) free(pd->capname);
    if (pd != NULL && pd->re != NULL) pcre_free(pd->re);
    if (pd != NULL && pd->sd != NULL) pcre_free(pd->sd);
    if (dubbed) free(re);
    if (pd) free(pd);
    if (sm) free(sm);
    return -1;
}

int DetectPcreFree(SigMatch *sm) {
    DetectPcreData *pd = (DetectPcreData *)sm->ctx;

    if (pd->capname != NULL) free(pd->capname);
    if (pd->re != NULL) pcre_free(pd->re);
    if (pd->sd != NULL) pcre_free(pd->sd);

    free(sm->ctx);
    return 0;
}

