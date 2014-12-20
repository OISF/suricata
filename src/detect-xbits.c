/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 *  \author Victor Julien <victor@inliniac.net>
 *
 * Implements the xbits keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-util.h"
#include "detect-xbits.h"
#include "detect-hostbits.h"
#include "util-spm.h"

#include "detect-engine-sigorder.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow-bit.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"

/*
    xbits:set,bitname,track ip_pair,expire 60
 */

#define PARSE_REGEX     "([a-z]+)" "(?:,\\s*([^,]+))?" "(?:,\\s*(?:track\\s+([^,]+)))" "(?:,\\s*(?:expire\\s+([^,]+)))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectXbitMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectXbitSetup (DetectEngineCtx *, Signature *, char *);
void DetectXbitFree (void *);
void XBitsRegisterTests(void);

void DetectXbitsRegister (void)
{
    sigmatch_table[DETECT_XBITS].name = "xbits";
    sigmatch_table[DETECT_XBITS].desc = "operate on bits";
//    sigmatch_table[DETECT_XBITS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords#Flowbits";
    sigmatch_table[DETECT_XBITS].Match = DetectXbitMatch;
    sigmatch_table[DETECT_XBITS].Setup = DetectXbitSetup;
    sigmatch_table[DETECT_XBITS].Free  = DetectXbitFree;
    sigmatch_table[DETECT_XBITS].RegisterTests = XBitsRegisterTests;
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_XBITS].flags |= SIGMATCH_IPONLY_COMPAT;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    return;
}

static int DetectIPPairbitMatchToggle (Packet *p, const DetectXbitsData *fd)
{
    IPPair *pair = IPPairGetIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 0;

    IPPairBitToggle(pair,fd->idx);
    IPPairRelease(pair);
    return 1;
}

/* return true even if bit not found */
static int DetectIPPairbitMatchUnset (Packet *p, const DetectXbitsData *fd)
{
    IPPair *pair = IPPairLookupIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 1;

    IPPairBitUnset(pair,fd->idx);
    IPPairRelease(pair);
    return 1;
}

static int DetectIPPairbitMatchSet (Packet *p, const DetectXbitsData *fd)
{
    IPPair *pair = IPPairGetIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 0;

    IPPairBitSet(pair,fd->idx);
    IPPairRelease(pair);
    return 1;
}

static int DetectIPPairbitMatchIsset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    IPPair *pair = IPPairLookupIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 0;

    r = IPPairBitIsset(pair,fd->idx);
    IPPairRelease(pair);
    return r;
}

static int DetectIPPairbitMatchIsnotset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    IPPair *pair = IPPairLookupIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 1;

    r = IPPairBitIsnotset(pair,fd->idx);
    IPPairRelease(pair);
    return r;
}

static int DetectXbitMatchIPPair(Packet *p, const DetectXbitsData *xd)
{
    switch (xd->cmd) {
        case DETECT_XBITS_CMD_ISSET:
            return DetectIPPairbitMatchIsset(p,xd);
        case DETECT_XBITS_CMD_ISNOTSET:
            return DetectIPPairbitMatchIsnotset(p,xd);
        case DETECT_XBITS_CMD_SET:
            return DetectIPPairbitMatchSet(p,xd);
        case DETECT_XBITS_CMD_UNSET:
            return DetectIPPairbitMatchUnset(p,xd);
        case DETECT_XBITS_CMD_TOGGLE:
            return DetectIPPairbitMatchToggle(p,xd);
        default:
            SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown cmd %" PRIu32 "", xd->cmd);
            return 0;
    }
    return 0;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

int DetectXbitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    DetectXbitsData *fd = (DetectXbitsData *)m->ctx;
    if (fd == NULL)
        return 0;

    switch (fd->type) {
        case VAR_TYPE_HOST_BIT:
            return DetectXbitMatchHost(p, (const DetectXbitsData *)fd);
            break;
        case VAR_TYPE_IPPAIR_BIT:
            return DetectXbitMatchIPPair(p, (const DetectXbitsData *)fd);
            break;
        default:
            break;
    }
    return 0;
}

int DetectXbitSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectXbitsData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t fb_cmd = 0;
    uint8_t hb_dir = 0;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    char fb_cmd_str[16] = "", fb_name[256] = "";
    char hb_dir_str[16] = "";
    enum VarTypes var_type = VAR_TYPE_NOT_SET;
    int expire = 30;

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 2 && ret != 3 && ret != 4 && ret != 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for xbits.", rawstr);
        return -1;
    }
    SCLogInfo("ret %d, %s", ret, rawstr);
    res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, fb_cmd_str, sizeof(fb_cmd_str));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return -1;
    }

    if (ret >= 3) {
        res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, fb_name, sizeof(fb_name));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        if (ret >= 4) {
            res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, hb_dir_str, sizeof(hb_dir_str));
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
                goto error;
            }
            SCLogInfo("hb_dir_str %s", hb_dir_str);
            if (strlen(hb_dir_str) > 0) {
                if (strcmp(hb_dir_str, "ip_src") == 0) {
                    hb_dir = DETECT_XBITS_TRACK_IPSRC;
                    var_type = VAR_TYPE_HOST_BIT;
                } else if (strcmp(hb_dir_str, "ip_dst") == 0) {
                    hb_dir = DETECT_XBITS_TRACK_IPDST;
                    var_type = VAR_TYPE_HOST_BIT;
                } else if (strcmp(hb_dir_str, "ip_pair") == 0) {
                    hb_dir = DETECT_XBITS_TRACK_IPPAIR;
                    var_type = VAR_TYPE_IPPAIR_BIT;
                } else {
                    // TODO
                    goto error;
                }
            }

            if (ret >= 5) {
                char expire_str[16] = "";
                res = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, expire_str, sizeof(expire_str));
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }
                SCLogInfo("expire_str %s", expire_str);
                expire = atoi(expire_str);
                SCLogInfo("expire %d", expire);
            }
        }
    }

    if (strcmp(fb_cmd_str,"noalert") == 0) {
        fb_cmd = DETECT_XBITS_CMD_NOALERT;
    } else if (strcmp(fb_cmd_str,"isset") == 0) {
        fb_cmd = DETECT_XBITS_CMD_ISSET;
    } else if (strcmp(fb_cmd_str,"isnotset") == 0) {
        fb_cmd = DETECT_XBITS_CMD_ISNOTSET;
    } else if (strcmp(fb_cmd_str,"set") == 0) {
        fb_cmd = DETECT_XBITS_CMD_SET;
    } else if (strcmp(fb_cmd_str,"unset") == 0) {
        fb_cmd = DETECT_XBITS_CMD_UNSET;
    } else if (strcmp(fb_cmd_str,"toggle") == 0) {
        fb_cmd = DETECT_XBITS_CMD_TOGGLE;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: flowbits action \"%s\" is not supported.", fb_cmd_str);
        goto error;
    }

    switch (fb_cmd) {
        case DETECT_XBITS_CMD_NOALERT:
            if (strlen(fb_name) != 0)
                goto error;
            s->flags |= SIG_FLAG_NOALERT;
            return 0;
        case DETECT_XBITS_CMD_ISNOTSET:
        case DETECT_XBITS_CMD_ISSET:
        case DETECT_XBITS_CMD_SET:
        case DETECT_XBITS_CMD_UNSET:
        case DETECT_XBITS_CMD_TOGGLE:
        default:
            if (strlen(fb_name) == 0)
                goto error;
            break;
    }

    cd = SCMalloc(sizeof(DetectXbitsData));
    if (unlikely(cd == NULL))
        goto error;

    cd->idx = VariableNameGetIdx(de_ctx, fb_name, var_type);
    cd->cmd = fb_cmd;
    cd->tracker = hb_dir;
    cd->type = var_type;
    cd->expire = expire;

    SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
        cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_XBITS;
    sm->ctx = (void *)cd;

    switch (fb_cmd) {
        case DETECT_XBITS_CMD_NOALERT:
            /* nothing to do */
            break;

        case DETECT_XBITS_CMD_ISNOTSET:
        case DETECT_XBITS_CMD_ISSET:
            /* checks, so packet list */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
            break;

        case DETECT_XBITS_CMD_SET:
        case DETECT_XBITS_CMD_UNSET:
        case DETECT_XBITS_CMD_TOGGLE:
            /* modifiers, only run when entire sig has matched */
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
            break;
    }

    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectXbitFree (void *ptr)
{
    DetectXbitsData *fd = (DetectXbitsData *)ptr;

    if (fd == NULL)
        return;

    SCFree(fd);
}

#ifdef UNITTESTS

static void XBitsTestSetup(void)
{
    StorageInit();
    HostBitInitCtx();
    IPPairBitInitCtx();
    StorageFinalize();
    HostInitConfig(TRUE);
    IPPairInitConfig(TRUE);
}

static void XBitsTestShutdown(void)
{
    HostCleanup();
    IPPairCleanup();
    StorageCleanup();
}

/**
 * \test HostBitsTestSig01 is a test for a valid noalert flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int XBitsTestSig01(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    XBitsTestSetup();

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        printf("bad de_ctx: ");
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:set,abc,track ip_pair; content:\"GET \"; sid:1;)");
    if (s == NULL) {
        printf("bad sig: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    result = 1;

end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    XBitsTestShutdown();

    SCFree(p);
    return result;
}

/**
 * \test various options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int XBitsTestSig02(void)
{
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    int error_count = 0;

    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:isset,abc,track ip_src; content:\"GET \"; sid:1;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:isnotset,abc,track ip_dst; content:\"GET \"; sid:2;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:set,abc,track ip_pair; content:\"GET \"; sid:3;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:unset,abc,track ip_src; content:\"GET \"; sid:4;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:toggle,abc,track ip_dst; content:\"GET \"; sid:5;)");
    if (s == NULL) {
        error_count++;
    }

    if (error_count != 0)
        goto end;

    result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    return result;
}

#if 0
/**
 * \test HostBitsTestSig03 is a test for a invalid flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig03(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Unknown cmd\"; flowbits:wrongcmd; content:\"GET \"; sid:1;)");

    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }


    SCFree(p);
    return result;
}

/**
 * \test HostBitsTestSig04 is a test check idx value
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig04(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    int idx = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    HostBitsTestSetup();

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset option\"; hostbits:isset,fbt; content:\"GET \"; sid:1;)");

    idx = VariableNameGetIdx(de_ctx, "fbt", VAR_TYPE_HOST_BIT);

    if (s == NULL || idx != 1) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostBitsTestShutdown();

    SCFree(p);
    return result;

end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    HostBitsTestShutdown();

    SCFree(p);
    return result;
}

/**
 * \test HostBitsTestSig05 is a test check noalert flag
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig05(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    HostBitsTestSetup();

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
        "alert ip any any -> any any (hostbits:noalert; content:\"GET \"; sid:1;)");

    if (s == NULL || ((s->flags & SIG_FLAG_NOALERT) != SIG_FLAG_NOALERT)) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        result = 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostBitsTestShutdown();

    SCFree(p);
    return result;
end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    HostBitsTestShutdown();

    SCFree(p);
    return result;
}

/**
 * \test HostBitsTestSig06 is a test set flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig06(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    int idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow; sid:10;)");

    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_FLOW_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
                result = 1;
        }
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    return result;
end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);
    SCFree(p);
    return result;
}

/**
 * \test HostBitsTestSig07 is a test unset flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig07(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    GenericVar flowvar, *gv = NULL;
    int result = 0;
    int idx = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));
    memset(&flowvar, 0, sizeof(GenericVar));

    FLOW_INITIALIZE(&f);
    p->flow = &f;
    p->flow->flowvar = &flowvar;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit set\"; flowbits:set,myflow2; sid:10;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Flowbit unset\"; flowbits:unset,myflow2; sid:11;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_FLOW_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_XBITS && gv->idx == idx) {
                result = 1;
        }
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    return result;
end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    if(gv) GenericVarFree(gv);
    FLOW_DESTROY(&f);

    SCFree(p);
    return result;
}

/**
 * \test set / isset
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int HostBitsTestSig07(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    int result = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));

    HostBitsTestSetup();

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
            "alert ip any any -> any any (hostbits:set,myflow2; sid:10;)");

    if (s == NULL) {
        goto end;
    }

    s = s->next  = SigInit(de_ctx,
            "alert ip any any -> any any (hostbits:isset,myflow2; sid:11;)");

    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    SCLogInfo("p->host_src %p", p->host_src);

    if (HostHasHostBits(p->host_src) == 1) {
        if (PacketAlertCheck(p, 11)) {
            result = 1;
        }
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);

    HostBitsTestShutdown();
    SCFree(p);
    return result;
end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);

    HostBitsTestShutdown();
    SCFree(p);
    return result;
}

/**
 * \test set / toggle / toggle / isset
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int HostBitsTestSig08(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    Flow f;
    int result = 0;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(Flow));

    HostBitsTestSetup();

    FLOW_INITIALIZE(&f);
    p->flow = &f;

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:set,myflow2; sid:10;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:toggle,myflow2; sid:11;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:toggle,myflow2; sid:12;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:isset,myflow2; sid:13;)");
    if (s == NULL) {
        goto end;
    }

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    SCLogInfo("p->host_src %p", p->host_src);

    if (HostHasHostBits(p->host_src) == 1) {
        if (PacketAlertCheck(p, 10)) {
            SCLogInfo("sid 10 matched");
        }
        if (PacketAlertCheck(p, 11)) {
            SCLogInfo("sid 11 matched");
        }
        if (PacketAlertCheck(p, 12)) {
            SCLogInfo("sid 12 matched");
        }
        if (PacketAlertCheck(p, 13)) {
            SCLogInfo("sid 13 matched");
            result = 1;
        }
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);

    HostBitsTestShutdown();

    SCFree(p);
    return result;
end:

    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }

    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }

    FLOW_DESTROY(&f);

    HostBitsTestShutdown();

    SCFree(p);
    return result;
}
#endif
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for HostBits
 */
void XBitsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("XBitsTestSig01", XBitsTestSig01, 1);
    UtRegisterTest("XBitsTestSig02", XBitsTestSig02, 1);
#if 0
    UtRegisterTest("XBitsTestSig03", XBitsTestSig03, 0);
    UtRegisterTest("XBitsTestSig04", XBitsTestSig04, 1);
    UtRegisterTest("XBitsTestSig05", XBitsTestSig05, 1);
    UtRegisterTest("XBitsTestSig06", XBitsTestSig06, 1);
    UtRegisterTest("XBitsTestSig07", XBitsTestSig07, 1);
    UtRegisterTest("XBitsTestSig08", XBitsTestSig08, 1);
#endif
#endif /* UNITTESTS */
}
