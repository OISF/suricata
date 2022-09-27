/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "detect-xbits.h"
#include "detect-hostbits.h"
#include "util-byte.h"

#include "detect-parse.h"

#include "ippair-bit.h"
#include "util-var-name.h"

#ifdef UNITTESTS
#include "util-unittest.h"
#include "host-bit.h"
#include "detect-engine-build.h"
#include "detect-engine.h"
#endif
/*
    xbits:set,bitname,track ip_pair,expire 60
 */

#define PARSE_REGEX     "^([a-z]+)" "(?:,\\s*([^,]+))?" "(?:,\\s*(?:track\\s+([^,]+)))" "(?:,\\s*(?:expire\\s+([^,]+)))?"
static DetectParseRegex parse_regex;

static int DetectXbitMatch (DetectEngineThreadCtx *, Packet *, const Signature *, const SigMatchCtx *);
static int DetectXbitSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void XBitsRegisterTests(void);
#endif
static void DetectXbitFree (DetectEngineCtx *, void *);

void DetectXbitsRegister (void)
{
    sigmatch_table[DETECT_XBITS].name = "xbits";
    sigmatch_table[DETECT_XBITS].desc = "operate on bits";
    sigmatch_table[DETECT_XBITS].url = "/rules/xbits.html";
    sigmatch_table[DETECT_XBITS].Match = DetectXbitMatch;
    sigmatch_table[DETECT_XBITS].Setup = DetectXbitSetup;
    sigmatch_table[DETECT_XBITS].Free  = DetectXbitFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_XBITS].RegisterTests = XBitsRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_XBITS].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int DetectIPPairbitMatchToggle (Packet *p, const DetectXbitsData *fd)
{
    IPPair *pair = IPPairGetIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 0;

    IPPairBitToggle(pair,fd->idx,p->ts.tv_sec + fd->expire);
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

    IPPairBitSet(pair, fd->idx, p->ts.tv_sec + fd->expire);
    IPPairRelease(pair);
    return 1;
}

static int DetectIPPairbitMatchIsset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    IPPair *pair = IPPairLookupIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 0;

    r = IPPairBitIsset(pair,fd->idx,p->ts.tv_sec);
    IPPairRelease(pair);
    return r;
}

static int DetectIPPairbitMatchIsnotset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    IPPair *pair = IPPairLookupIPPairFromHash(&p->src, &p->dst);
    if (pair == NULL)
        return 1;

    r = IPPairBitIsnotset(pair,fd->idx,p->ts.tv_sec);
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
    }
    return 0;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */

static int DetectXbitMatch (DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    const DetectXbitsData *fd = (const DetectXbitsData *)ctx;
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

/** \internal
 *  \brief parse xbits rule options
 *  \retval 0 ok
 *  \retval -1 bad
 *  \param[out] cdout return DetectXbitsData structure or NULL if noalert
 */
static int DetectXbitParse(DetectEngineCtx *de_ctx,
        const char *rawstr, DetectXbitsData **cdout)
{
    DetectXbitsData *cd = NULL;
    uint8_t fb_cmd = 0;
    uint8_t hb_dir = 0;
    int ret = 0, res = 0;
    size_t pcre2len;
    char fb_cmd_str[16] = "", fb_name[256] = "";
    char hb_dir_str[16] = "";
    enum VarTypes var_type = VAR_TYPE_NOT_SET;
    uint32_t expire = DETECT_XBITS_EXPIRE_DEFAULT;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret != 2 && ret != 3 && ret != 4 && ret != 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for xbits.", rawstr);
        return -1;
    }
    SCLogDebug("ret %d, %s", ret, rawstr);
    pcre2len = sizeof(fb_cmd_str);
    res = pcre2_substring_copy_bynumber(
            parse_regex.match, 1, (PCRE2_UCHAR8 *)fb_cmd_str, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return -1;
    }

    if (ret >= 3) {
        pcre2len = sizeof(fb_name);
        res = pcre2_substring_copy_bynumber(
                parse_regex.match, 2, (PCRE2_UCHAR8 *)fb_name, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return -1;
        }
        if (ret >= 4) {
            pcre2len = sizeof(hb_dir_str);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, 3, (PCRE2_UCHAR8 *)hb_dir_str, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                return -1;
            }
            SCLogDebug("hb_dir_str %s", hb_dir_str);
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
                    return -1;
                }
            }

            if (ret >= 5) {
                char expire_str[16] = "";
                pcre2len = sizeof(expire_str);
                res = pcre2_substring_copy_bynumber(
                        parse_regex.match, 4, (PCRE2_UCHAR8 *)expire_str, &pcre2len);
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                    return -1;
                }
                SCLogDebug("expire_str %s", expire_str);
                if (StringParseUint32(&expire, 10, 0, (const char *)expire_str) < 0) {
                    SCLogError(SC_ERR_INVALID_VALUE, "Invalid value for "
                               "expire: \"%s\"", expire_str);
                    return -1;
                }
                if (expire == 0) {
                    SCLogError(SC_ERR_INVALID_VALUE, "expire must be bigger than 0");
                    return -1;
                }
                SCLogDebug("expire %d", expire);
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
        SCLogError(SC_ERR_UNKNOWN_VALUE, "xbits action \"%s\" is not supported.", fb_cmd_str);
        return -1;
    }

    switch (fb_cmd) {
        case DETECT_XBITS_CMD_NOALERT: {
            if (strlen(fb_name) != 0)
                return -1;
            /* return ok, cd is NULL. Flag sig. */
            *cdout = NULL;
            return 0;
        }
        case DETECT_XBITS_CMD_ISNOTSET:
        case DETECT_XBITS_CMD_ISSET:
        case DETECT_XBITS_CMD_SET:
        case DETECT_XBITS_CMD_UNSET:
        case DETECT_XBITS_CMD_TOGGLE:
            if (strlen(fb_name) == 0)
                return -1;
            break;
    }

    cd = SCMalloc(sizeof(DetectXbitsData));
    if (unlikely(cd == NULL))
        return -1;

    cd->idx = VarNameStoreSetupAdd(fb_name, var_type);
    cd->cmd = fb_cmd;
    cd->tracker = hb_dir;
    cd->type = var_type;
    cd->expire = expire;

    SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
        cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");

    *cdout = cd;
    return 0;
}

int DetectXbitSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SigMatch *sm = NULL;
    DetectXbitsData *cd = NULL;

    int result = DetectXbitParse(de_ctx, rawstr, &cd);
    if (result < 0) {
        return -1;
    /* noalert doesn't use a cd/sm struct. It flags the sig. We're done. */
    } else if (result == 0 && cd == NULL) {
        s->flags |= SIG_FLAG_NOALERT;
        return 0;
    }

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_XBITS;
    sm->ctx = (void *)cd;

    switch (cd->cmd) {
        /* case DETECT_XBITS_CMD_NOALERT can't happen here */

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
    return -1;
}

static void DetectXbitFree (DetectEngineCtx *de_ctx, void *ptr)
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
    HostInitConfig(true);
    IPPairInitConfig(true);
}

static void XBitsTestShutdown(void)
{
    HostCleanup();
    IPPairCleanup();
    StorageCleanup();
}


static int XBitsTestParse01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    DetectXbitsData *cd = NULL;

#define BAD_INPUT(str) \
    FAIL_IF_NOT(DetectXbitParse(de_ctx, (str), &cd) == -1);

    BAD_INPUT("alert");
    BAD_INPUT("n0alert");
    BAD_INPUT("nOalert");
    BAD_INPUT("set,abc,track nonsense, expire 3600");
    BAD_INPUT("set,abc,track ip_source, expire 3600");
    BAD_INPUT("set,abc,track ip_src, expire -1");
    BAD_INPUT("set,abc,track ip_src, expire 0");

#undef BAD_INPUT

#define GOOD_INPUT(str, command, trk, typ, exp)             \
    FAIL_IF_NOT(DetectXbitParse(de_ctx, (str), &cd) == 0);  \
    FAIL_IF_NULL(cd);                                       \
    FAIL_IF_NOT(cd->cmd == (command));                      \
    FAIL_IF_NOT(cd->tracker == (trk));                      \
    FAIL_IF_NOT(cd->type == (typ));                         \
    FAIL_IF_NOT(cd->expire == (exp));                       \
    DetectXbitFree(NULL, cd);                               \
    cd = NULL;

    GOOD_INPUT("set,abc,track ip_pair",
            DETECT_XBITS_CMD_SET,
            DETECT_XBITS_TRACK_IPPAIR, VAR_TYPE_IPPAIR_BIT,
            DETECT_XBITS_EXPIRE_DEFAULT);
    GOOD_INPUT("set,abc,track ip_pair, expire 3600",
            DETECT_XBITS_CMD_SET,
            DETECT_XBITS_TRACK_IPPAIR, VAR_TYPE_IPPAIR_BIT,
            3600);
    GOOD_INPUT("set,abc,track ip_src, expire 1234",
            DETECT_XBITS_CMD_SET,
            DETECT_XBITS_TRACK_IPSRC, VAR_TYPE_HOST_BIT,
            1234);

#undef GOOD_INPUT

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test
 */

static int XBitsTestSig01(void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    XBitsTestSetup();

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:set,abc,track ip_pair; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    XBitsTestShutdown();
    SCFree(p);
    StatsThreadCleanup(&th_v);
    StatsReleaseResources();
    PASS;
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
    DetectEngineCtx *de_ctx = NULL;
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:isset,abc,track ip_src; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:isnotset,abc,track ip_dst; content:\"GET \"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:set,abc,track ip_pair; content:\"GET \"; sid:3;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:unset,abc,track ip_src; content:\"GET \"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:toggle,abc,track ip_dst; content:\"GET \"; sid:5;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (xbits:!set,abc,track ip_dst; content:\"GET \"; sid:6;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for XBits
 */
static void XBitsRegisterTests(void)
{
    UtRegisterTest("XBitsTestParse01", XBitsTestParse01);
    UtRegisterTest("XBitsTestSig01", XBitsTestSig01);
    UtRegisterTest("XBitsTestSig02", XBitsTestSig02);
}
#endif /* UNITTESTS */
