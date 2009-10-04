/* PCRE part of the detection engine. */

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "pkt-var.h"
#include "flow-var.h"

#include "detect-pcre.h"

#include "detect-engine-mpm.h"

#include "util-var-name.h"
#include "util-debug.h"

#define PARSE_CAPTURE_REGEX "\\(\\?P\\<([A-z]+)\\_([A-z0-9_]+)\\>"
#define PARSE_REGEX         "(?<!\\\\)/(.*)(?<!\\\\)/([A-z]*)"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_capture_regex;
static pcre_extra *parse_capture_regex_study;

int DetectPcreMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
int DetectPcreSetup (DetectEngineCtx *, Signature *, SigMatch *, char *);
void DetectPcreFree(void *);

void DetectPcreRegister (void) {
    sigmatch_table[DETECT_PCRE].name = "pcre";
    sigmatch_table[DETECT_PCRE].Match = DetectPcreMatch;
    sigmatch_table[DETECT_PCRE].Setup = DetectPcreSetup;
    sigmatch_table[DETECT_PCRE].Free  = DetectPcreFree;
    sigmatch_table[DETECT_PCRE].RegisterTests  = NULL;

    sigmatch_table[DETECT_PCRE].flags |= SIGMATCH_PAYLOAD;

    const char *eb;
    int eo;
    int opts = 0;

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
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    uint8_t *ptr = NULL;
    uint16_t len = 0;

    if (p->payload_len == 0)
        return 0;

    DetectPcreData *pe = (DetectPcreData *)m->ctx;
    if (s->flags & SIG_FLAG_RECURSIVE) {
        ptr = det_ctx->pkt_ptr ? det_ctx->pkt_ptr : p->payload;
        len = p->payload_len - det_ctx->pkt_off;
    } else if (pe->flags & DETECT_PCRE_RELATIVE) {
        ptr = det_ctx->pkt_ptr;
        len = p->payload_len - det_ctx->pkt_off;
        if (ptr == NULL || len == 0)
            return 0;
    } else {
        ptr = p->payload;
        len = p->payload_len;
    }

    //printf("DetectPcre: ptr %p, len %" PRIu32 "\n", ptr, len);

    ret = pcre_exec(pe->re, pe->sd, (char *)ptr, len, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret >= 0) {
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
                            ret = det_ctx->sgh->mpm_uri_ctx->Scan(det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq, p->http_uri.raw[det_ctx->pkt_cnt], p->http_uri.raw_size[det_ctx->pkt_cnt]);
                            if (ret > 0) {
                                if (det_ctx->sgh->mpm_uricontent_maxlen == 1)      det_ctx->pkts_uri_searched1++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 2) det_ctx->pkts_uri_searched2++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 3) det_ctx->pkts_uri_searched3++;
                                else if (det_ctx->sgh->mpm_uricontent_maxlen == 4) det_ctx->pkts_uri_searched4++;
                                else                                           det_ctx->pkts_uri_searched++;

                                det_ctx->pmq.mode = PMQ_MODE_SEARCH;
                                ret += det_ctx->sgh->mpm_uri_ctx->Search(det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq, p->http_uri.raw[det_ctx->pkt_cnt], p->http_uri.raw_size[det_ctx->pkt_cnt]);

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
                        FlowVarAdd(p->flow, pe->capidx, (uint8_t *)str_ptr, ret);
                    }
                }
            }
        }

        /* update ptrs for pcre RELATIVE */
        det_ctx->pkt_ptr =  ptr+ov[1];
        det_ctx->pkt_off = (ptr+ov[1]) - p->payload;
        //printf("DetectPcre: post match: t->pkt_ptr %p t->pkt_off %" PRIu32 "\n", t->pkt_ptr, t->pkt_off);

        ret = 1;
    } else {
        ret = 0;
    }

    //printf("DetectPcreMatch: ret %" PRId32 "\n", ret);
    return ret;
}

int DetectPcreSetup (DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *regexstr)
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
    //printf("ret %" PRId32 " re \'%s\', op \'%s\'\n", ret, re, op);

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
        if (capture_str_ptr != NULL) {
            if (pd->flags & DETECT_PCRE_CAPTURE_PKT)
                pd->capidx = VariableNameGetIdx(de_ctx,(char *)capture_str_ptr,DETECT_PKTVAR);
            else if (pd->flags & DETECT_PCRE_CAPTURE_FLOW)
                pd->capidx = VariableNameGetIdx(de_ctx,(char *)capture_str_ptr,DETECT_FLOWVAR);
        }
    }
    //printf("DetectPcreSetup: pd->capname %s\n", pd->capname ? pd->capname : "NULL");

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
        printf("pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", regexstr, eo, eb);
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

void DetectPcreFree(void *ptr) {
    DetectPcreData *pd = (DetectPcreData *)ptr;

    if (pd->capname != NULL) free(pd->capname);
    if (pd->re != NULL) pcre_free(pd->re);
    if (pd->sd != NULL) pcre_free(pd->sd);

    free(pd);
    return;
}

