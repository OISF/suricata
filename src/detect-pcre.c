/* PCRE part of the detection engine. */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "pkt-var.h"
#include "flow-var.h"

#include "detect-pcre.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "util-var-name.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "conf.h"

#define PARSE_CAPTURE_REGEX "\\(\\?P\\<([A-z]+)\\_([A-z0-9_]+)\\>"
#define PARSE_REGEX         "(?<!\\\\)/(.*)(?<!\\\\)/([^\"]*)"

#define DEFAULT_MATCH_LIMIT 10000000
#define DEFAULT_MATCH_LIMIT_RECURSION 10000000

#define MATCH_LIMIT_DEFAULT 1500

static int pcre_match_limit = 0;
static int pcre_match_limit_recursion = 0;

static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_capture_regex;
static pcre_extra *parse_capture_regex_study;

int DetectPcreMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectPcreSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectPcreFree(void *);
void DetectPcreRegisterTests(void);

void DetectPcreRegister (void) {
    sigmatch_table[DETECT_PCRE].name = "pcre";
    sigmatch_table[DETECT_PCRE].Match = DetectPcreMatch;
    sigmatch_table[DETECT_PCRE].Setup = DetectPcreSetup;
    sigmatch_table[DETECT_PCRE].Free  = DetectPcreFree;
    sigmatch_table[DETECT_PCRE].RegisterTests  = DetectPcreRegisterTests;

    sigmatch_table[DETECT_PCRE].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;
    intmax_t val = 0;

    if (!ConfGetInt("pcre.match-limit", &val)) {
        pcre_match_limit = DEFAULT_MATCH_LIMIT;
    }
    else    {
        pcre_match_limit = val;
    }

    val = 0;

    if (!ConfGetInt("pcre.match-limit-recursion", &val)) {
        pcre_match_limit_recursion = DEFAULT_MATCH_LIMIT_RECURSION;
    }
    else    {
        pcre_match_limit_recursion = val;
    }

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
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
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_CAPTURE_REGEX, eo, eb);
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

int DetectPcreMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    SCEnter();

#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    uint8_t *ptr = NULL;
    uint16_t len = 0;

    if (p->payload_len == 0)
        SCReturnInt(0);

    DetectPcreData *pe = (DetectPcreData *)m->ctx;
    if (s->flags & SIG_FLAG_RECURSIVE) {
        ptr = det_ctx->pkt_ptr ? det_ctx->pkt_ptr : p->payload;
        len = p->payload_len - det_ctx->pkt_off;
    } else if (pe->flags & DETECT_PCRE_RELATIVE) {
        ptr = det_ctx->pkt_ptr;
        len = p->payload_len - det_ctx->pkt_off;
        if (ptr == NULL || len == 0)
            SCReturnInt(0);
    } else {
        ptr = p->payload;
        len = p->payload_len;
    }

    //printf("DetectPcre: ptr %p, len %" PRIu32 "\n", ptr, len);

    ret = pcre_exec(pe->re, pe->sd, (char *)ptr, len, 0, 0, ov, MAX_SUBSTRINGS);
    SCLogDebug("ret %d (negating %s)", ret, pe->negate ? "set" : "not set");

    if (ret == PCRE_ERROR_NOMATCH) {
        if (pe->negate == 1) {
            /* regex didn't match with negate option means we consider it a match */
            ret = 1;
        } else {
            ret = 0;
        }
    } else if (ret >= 0) {
        if (pe->negate == 1) {
            /* regex matched but we're negated, so not considering it a match */
            ret = 0;
        } else {
            /* regex matched and we're not negated, considering it a match */
            if (ret > 1 && pe->capidx != 0) {
                const char *str_ptr;
                ret = pcre_get_substring((char *)ptr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
                if (ret) {
                    if (strcmp(pe->capname,"http_uri") == 0) {
                        p->http_uri.raw[det_ctx->pkt_cnt] = (uint8_t *)str_ptr;
                        p->http_uri.raw_size[det_ctx->pkt_cnt] = ret;
                        p->http_uri.cnt = det_ctx->pkt_cnt + 1;

                        /* count how many uri's we handle for stats */
                        det_ctx->uris++;

                        //printf("DetectPcre: URI det_ctx->sgh %p, det_ctx->mcu %p\n", det_ctx->sgh, det_ctx->mcu);
                        //PrintRawUriFp(stdout,p->http_uri.raw[det_ctx->pkt_cnt],p->http_uri.raw_size[det_ctx->pkt_cnt]);
                        //printf(" (pkt_cnt %" PRIu32 ", mcu %p)\n", det_ctx->pkt_cnt, det_ctx->mcu);

                        /* don't bother scanning if we don't have a pattern matcher ctx
                         * which means we don't have uricontent sigs */
                        if (det_ctx->sgh->mpm_uri_ctx != NULL) {
                            if (det_ctx->sgh->mpm_uricontent_maxlen <= p->http_uri.raw_size[det_ctx->pkt_cnt]) {
                                if (det_ctx->sgh->mpm_uricontent_maxlen == 1)      det_ctx->pkts_uri_scanned1++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 2) det_ctx->pkts_uri_scanned2++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 3) det_ctx->pkts_uri_scanned3++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 4) det_ctx->pkts_uri_scanned4++;
                                else                                           det_ctx->pkts_uri_scanned++;

                                det_ctx->pmq.mode = PMQ_MODE_SCAN;
                                ret = mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Scan(det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq, p->http_uri.raw[det_ctx->pkt_cnt], p->http_uri.raw_size[det_ctx->pkt_cnt]);
                                if (ret > 0) {
                                    if (det_ctx->sgh->mpm_uricontent_maxlen == 1)      det_ctx->pkts_uri_searched1++;
                                    else if (det_ctx->sgh->mpm_uricontent_maxlen == 2) det_ctx->pkts_uri_searched2++;
                                    else if (det_ctx->sgh->mpm_uricontent_maxlen == 3) det_ctx->pkts_uri_searched3++;
                                    else if (det_ctx->sgh->mpm_uricontent_maxlen == 4) det_ctx->pkts_uri_searched4++;
                                    else                                           det_ctx->pkts_uri_searched++;

                                    det_ctx->pmq.mode = PMQ_MODE_SEARCH;
                                    ret += mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Search(det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq, p->http_uri.raw[det_ctx->pkt_cnt], p->http_uri.raw_size[det_ctx->pkt_cnt]);

                                    /* indicate to uricontent that we have a uri,
                                     * we scanned it _AND_ we found pattern matches. */
                                    det_ctx->de_have_httpuri = 1;
                                }
                            }
                        }
                    } else {
                        if (pe->flags & DETECT_PCRE_CAPTURE_PKT) {
                            PktVarAdd(p, pe->capname, (uint8_t *)str_ptr, ret);
                        } else if (pe->flags & DETECT_PCRE_CAPTURE_FLOW) {
                            FlowVarAddStr(p->flow, pe->capidx, (uint8_t *)str_ptr, ret);
                        }
                    }
                }
            }
            /* update ptrs for pcre RELATIVE */
            det_ctx->pkt_ptr =  ptr+ov[1];
            det_ctx->pkt_off = (ptr+ov[1]) - p->payload;
            //printf("DetectPcre: post match: t->pkt_ptr %p t->pkt_off %" PRIu32 "\n", t->pkt_ptr, t->pkt_off);

            ret = 1;
        }

    } else {
        SCLogDebug("pcre had matching error");
        ret = 0;
    }

    SCReturnInt(ret);
}

DetectPcreData *DetectPcreParse (char *regexstr)
{
    const char *eb;
    int eo;
    int opts = 0;
    DetectPcreData *pd = NULL;
    char *re = NULL, *op_ptr = NULL, *op = NULL;
    char dubbed = 0;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    uint16_t slen = strlen(regexstr);
    uint16_t pos = 0;
    uint8_t negate = 0;

    while (pos < slen && isspace(regexstr[pos])) {
        pos++;
    }

    if (regexstr[pos] == '!') {
        negate = 1;
        pos++;
    }

    ret = pcre_exec(parse_regex, parse_regex_study, regexstr+pos, slen-pos, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 0) {
        goto error;
    }

    if (ret > 1) {
        const char *str_ptr;
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
        if (res < 0) {
            printf("DetectPcreParse: pcre_get_substring failed\n");
            return NULL;
        }
        re = (char *)str_ptr;

        if (ret > 2) {
            res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
            if (res < 0) {
                printf("DetectPcreParse: pcre_get_substring failed\n");
                return NULL;
            }
            op_ptr = op = (char *)str_ptr;
        }
    }
    //printf("ret %" PRId32 " re \'%s\', op \'%s\'\n", ret, re, op);

    pd = malloc(sizeof(DetectPcreData));
    if (pd == NULL) {
        printf("DetectPcreParse: malloc failed\n");
        goto error;
    }
    memset(pd, 0, sizeof(DetectPcreData));

    if (negate)
        pd->negate = 1;

    if (op != NULL) {
        while (*op) {
            SCLogDebug("regex option %c", *op);

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
                case 'O':
                    pd->flags |= DETECT_PCRE_MATCH_LIMIT;
                    break;
                default:
                    printf("DetectPcreParse: unknown regex modifier '%c'\n", *op);
                    goto error;
            }
            op++;
        }
    }

    //printf("DetectPcreParse: \"%s\"\n", re);

    pd->re = pcre_compile(re, opts, &eb, &eo, NULL);
    if(pd->re == NULL)  {
        printf("DetectPcreParse: pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", regexstr, eo, eb);
        goto error;
    }

    pd->sd = pcre_study(pd->re, 0, &eb);
    if(eb != NULL)  {
        printf("DetectPcreParse: pcre study failed : %s\n", eb);
        goto error;
    }

    if(pd->sd == NULL)
        pd->sd = (pcre_extra *) calloc(1,sizeof(pcre_extra));

    if(pd->sd)  {

        if(pd->flags & DETECT_PCRE_MATCH_LIMIT) {

            if(pcre_match_limit >= -1)    {
                pd->sd->match_limit = pcre_match_limit;
                pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT;
            }

            if(pcre_match_limit_recursion >= -1)    {
                pd->sd->match_limit_recursion = pcre_match_limit_recursion;
                pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;
            }

        }
        else    {

            pd->sd->match_limit = MATCH_LIMIT_DEFAULT;
            pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT;

            pd->sd->match_limit_recursion = MATCH_LIMIT_DEFAULT;
            pd->sd->flags |= PCRE_EXTRA_MATCH_LIMIT_RECURSION;

        }

    }

    if (re != NULL) free(re);
    if (op_ptr != NULL) free(op_ptr);
    return pd;

error:
    if (re != NULL) free(re);
    if (op_ptr != NULL) free(op_ptr);
    if (pd != NULL && pd->re != NULL) pcre_free(pd->re);
    if (pd != NULL && pd->sd != NULL) pcre_free(pd->sd);
    if (dubbed) free(re);
    if (pd) free(pd);
    return NULL;
}

DetectPcreData *DetectPcreParseCapture(char *regexstr, DetectEngineCtx *de_ctx, DetectPcreData *pd)
{
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    const char *capture_str_ptr = NULL, *type_str_ptr = NULL;

    if(pd == NULL)
        goto error;

    if(de_ctx == NULL)
        goto error;
    //printf("DetectPcreParseCapture: \'%s\'\n", regexstr);

    ret = pcre_exec(parse_capture_regex, parse_capture_regex_study, regexstr, strlen(regexstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret > 1) {
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 1, &type_str_ptr);
        if (res < 0) {
            printf("DetectPcreParseCapture: pcre_get_substring failed\n");
            goto error;
        }
        res = pcre_get_substring((char *)regexstr, ov, MAX_SUBSTRINGS, 2, &capture_str_ptr);
        if (res < 0) {
            printf("DetectPcreParseCapture: pcre_get_substring failed\n");
            goto error;
        }
    }
    //printf("DetectPcreParseCapture: type \'%s\'\n", type_str_ptr ? type_str_ptr : "NULL");
    //printf("DetectPcreParseCapture: capture \'%s\'\n", capture_str_ptr ? capture_str_ptr : "NULL");

    if (capture_str_ptr != NULL) {
        pd->capname = strdup((char *)capture_str_ptr);
    }
    if (type_str_ptr != NULL) {
        if (strcmp(type_str_ptr,"pkt") == 0) {
            pd->flags |= DETECT_PCRE_CAPTURE_PKT;
        } else if (strcmp(type_str_ptr,"flow") == 0) {
            pd->flags |= DETECT_PCRE_CAPTURE_FLOW;
        }
        if (capture_str_ptr != NULL) {
            if (pd->flags & DETECT_PCRE_CAPTURE_PKT)
                pd->capidx = VariableNameGetIdx(de_ctx,(char *)capture_str_ptr,DETECT_PKTVAR);
            else if (pd->flags & DETECT_PCRE_CAPTURE_FLOW)
                pd->capidx = VariableNameGetIdx(de_ctx,(char *)capture_str_ptr,DETECT_FLOWVAR);
        }
    }
    //printf("DetectPcreParseCapture: pd->capname %s\n", pd->capname ? pd->capname : "NULL");

    if (type_str_ptr != NULL) pcre_free((char *)type_str_ptr);
    if (capture_str_ptr != NULL) pcre_free((char *)capture_str_ptr);
    return pd;

error:
    if (pd != NULL && pd->capname != NULL) free(pd->capname);
    if (pd) free(pd);
    return NULL;

}

int DetectPcreSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *regexstr)
{
    DetectPcreData *pd = NULL;
    SigMatch *sm = NULL;

    pd = DetectPcreParse(regexstr);
    if (pd == NULL) goto error;

    pd = DetectPcreParseCapture(regexstr, de_ctx, pd);
    if (pd == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_PCRE;
    sm->ctx = (void *)pd;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (pd != NULL) DetectPcreFree(pd);
    if (sm != NULL) free(sm);
    return -1;
}

void DetectPcreFree(void *ptr) {
    DetectPcreData *pd = (DetectPcreData *)ptr;

    if (pd->capname != NULL) free(pd->capname);
    if (pd->re != NULL) pcre_free(pd->re);
    if (pd->sd != NULL) pcre_free(pd->sd);

    free(pd);
    return;
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectPcreParseTest01 make sure we don't allow invalid opts 7.
 */
static int DetectPcreParseTest01 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/7";

    pd = DetectPcreParse(teststring);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }
    return result;
}

/**
 * \test DetectPcreParseTest02 make sure we don't allow invalid opts Ui$.
 */
static int DetectPcreParseTest02 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/Ui$";

    pd = DetectPcreParse(teststring);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }
    return result;
}

/**
 * \test DetectPcreParseTest03 make sure we don't allow invalid opts UZi.
 */
static int DetectPcreParseTest03 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/UZi";

    pd = DetectPcreParse(teststring);
    if (pd != NULL) {
        printf("expected NULL: got %p", pd);
        result = 0;
        DetectPcreFree(pd);
    }
    return result;
}

/**
 * \test DetectPcreParseTest04 make sure we allow escaped "
 */
static int DetectPcreParseTest04 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b\\\"lah/i";

    pd = DetectPcreParse(teststring);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    return result;
}

/**
 * \test DetectPcreParseTest05 make sure we parse pcre with no opts
 */
static int DetectPcreParseTest05 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/";

    pd = DetectPcreParse(teststring);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    return result;
}

/**
 * \test DetectPcreParseTest06 make sure we parse pcre with smi opts
 */
static int DetectPcreParseTest06 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/smi";

    pd = DetectPcreParse(teststring);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    return result;
}

/**
 * \test DetectPcreParseTest07 make sure we parse pcre with /Ui opts
 */
static int DetectPcreParseTest07 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/blah/Ui";

    pd = DetectPcreParse(teststring);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    return result;
}

/**
 * \test DetectPcreParseTest08 make sure we parse pcre with O opts
 */
static int DetectPcreParseTest08 (void) {
    int result = 1;
    DetectPcreData *pd = NULL;
    char *teststring = "/b(l|a)h/O";

    pd = DetectPcreParse(teststring);
    if (pd == NULL) {
        printf("expected %p: got NULL", pd);
        result = 0;
    }

    DetectPcreFree(pd);
    return result;
}

static int DetectPcreTestSig01Real(int mpm_type) {
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; pcre:\"^/gEt/i\"; pcre:\"/\\/two\\//U; pcre:\"/GET \\/two\\//\"; pcre:\"/\\s+HTTP/R\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int DetectPcreTestSig02Real(int mpm_type) {
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    pcre_match_limit = 100;
    pcre_match_limit_recursion = 100;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; pcre:\"/two/O\"; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 2))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int DetectPcreTestSig01B2g (void) {
    return DetectPcreTestSig01Real(MPM_B2G);
}
static int DetectPcreTestSig01B3g (void) {
    return DetectPcreTestSig01Real(MPM_B3G);
}
static int DetectPcreTestSig01Wm (void) {
    return DetectPcreTestSig01Real(MPM_WUMANBER);
}

static int DetectPcreTestSig02B2g (void) {
    return DetectPcreTestSig02Real(MPM_B2G);
}
static int DetectPcreTestSig02B3g (void) {
    return DetectPcreTestSig02Real(MPM_B3G);
}
static int DetectPcreTestSig02Wm (void) {
    return DetectPcreTestSig02Real(MPM_WUMANBER);
}

/**
 * \test DetectPcreTestSig03Real negation test ! outside of "" this sig should not match
 */
static int DetectPcreTestSig03Real(int mpm_type) {
    uint8_t *buf = (uint8_t *)
        "GET /one/ HTTP/1.1\r\n"
        "Host: one.example.org\r\n"
        "\r\n\r\n"
        "GET /two/ HTTP/1.1\r\n"
        "Host: two.example.org\r\n"
        "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet p;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 1;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = buf;
    p.payload_len = buflen;
    p.proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"GET\"; pcre:!\"/two/\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);
    if (PacketAlertCheck(&p, 1)){
        printf("sid 1 matched even though it shouldn't have:");
        result = 0;
    }
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    return result;
}

static int DetectPcreTestSig03B2g (void) {
    return DetectPcreTestSig03Real(MPM_B2G);
}
static int DetectPcreTestSig03B3g (void) {
    return DetectPcreTestSig03Real(MPM_B3G);
}
static int DetectPcreTestSig03Wm (void) {
    return DetectPcreTestSig03Real(MPM_WUMANBER);
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectPcre
 */
void DetectPcreRegisterTests(void) {
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectPcreParseTest01", DetectPcreParseTest01, 1);
    UtRegisterTest("DetectPcreParseTest02", DetectPcreParseTest02, 1);
    UtRegisterTest("DetectPcreParseTest03", DetectPcreParseTest03, 1);
    UtRegisterTest("DetectPcreParseTest04", DetectPcreParseTest04, 1);
    UtRegisterTest("DetectPcreParseTest05", DetectPcreParseTest05, 1);
    UtRegisterTest("DetectPcreParseTest06", DetectPcreParseTest06, 1);
    UtRegisterTest("DetectPcreParseTest07", DetectPcreParseTest07, 1);
    UtRegisterTest("DetectPcreParseTest08", DetectPcreParseTest08, 1);
    UtRegisterTest("DetectPcreTestSig01B2g -- pcre test", DetectPcreTestSig01B2g, 1);
    UtRegisterTest("DetectPcreTestSig01B3g -- pcre test", DetectPcreTestSig01B3g, 1);
    UtRegisterTest("DetectPcreTestSig01Wm -- pcre test", DetectPcreTestSig01Wm, 1);
    UtRegisterTest("DetectPcreTestSig02B2g -- pcre test", DetectPcreTestSig02B2g, 1);
    UtRegisterTest("DetectPcreTestSig02B3g -- pcre test", DetectPcreTestSig02B3g, 1);
    UtRegisterTest("DetectPcreTestSig02Wm -- pcre test", DetectPcreTestSig02Wm, 1);
    UtRegisterTest("DetectPcreTestSig03B2g -- negated pcre test", DetectPcreTestSig03B2g, 1);
    UtRegisterTest("DetectPcreTestSig03B3g -- negated pcre test", DetectPcreTestSig03B3g, 1);
    UtRegisterTest("DetectPcreTestSig03Wm -- negated pcre test", DetectPcreTestSig03Wm, 1);
#endif /* UNITTESTS */
}

