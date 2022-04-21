/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "util-byte.h"

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
    bool cmd_set = false;
    bool name_set = false;
    bool track_set = false;
    bool expire_set = false;
    uint8_t cmd = 0;
    uint8_t track = 0;
    enum VarTypes var_type = VAR_TYPE_NOT_SET;
    uint32_t expire = DETECT_XBITS_EXPIRE_DEFAULT;
    DetectXbitsData *cd = NULL;
    char name[256] = "";
    char copy[strlen(rawstr) + 1];
    strlcpy(copy, rawstr, sizeof(copy));
    char *context = NULL;
    char *token = strtok_r(copy, ",", &context);
    while (token != NULL) {
        while (*token != '\0' && isblank(*token)) {
            token++;
        }
        char *val = strchr(token, ' ');
        if (val != NULL) {
            *val++ = '\0';
            while (*val != '\0' && isblank(*val)) {
                val++;
            }
        } else {
            SCLogDebug("val %s", token);
        }
        if (strlen(token) == 0) {
            goto next;
        }
        if (strcmp(token, "noalert") == 0 && !cmd_set) {
            if (strtok_r(NULL, ",", &context) != NULL) {
                return -1;
            }
            if (val && strlen(val) != 0) {
                return -1;
            }
            *cdout = NULL;
            return 0;
        }
        if (!cmd_set) {
            if (val && strlen(val) != 0) {
                return -1;
            }
            if (strcmp(token, "set") == 0) {
                cmd = DETECT_XBITS_CMD_SET;
            } else if (strcmp(token, "isset") == 0) {
                cmd = DETECT_XBITS_CMD_ISSET;
            } else if (strcmp(token, "unset") == 0) {
                cmd = DETECT_XBITS_CMD_UNSET;
            } else if (strcmp(token, "isnotset") == 0) {
                cmd = DETECT_XBITS_CMD_ISNOTSET;
            } else if (strcmp(token, "toggle") == 0) {
                cmd = DETECT_XBITS_CMD_TOGGLE;
            } else {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid xbits cmd: %s", token);
                return -1;
            }
            cmd_set = true;
        } else if (!name_set) {
            if (val && strlen(val) != 0) {
                return -1;
            }
            strlcpy(name, token, sizeof(name));
            name_set = true;
        } else if (!track_set || !expire_set) {
            if (val == NULL) {
                return -1;
            }
            if (strcmp(token, "track") == 0) {
                if (track_set) {
                    return -1;
                }
                if (strcmp(val, "ip_src") == 0) {
                    track = DETECT_XBITS_TRACK_IPSRC;
                    var_type = VAR_TYPE_HOST_BIT;
                } else if (strcmp(val, "ip_dst") == 0) {
                    track = DETECT_XBITS_TRACK_IPDST;
                    var_type = VAR_TYPE_HOST_BIT;
                } else if (strcmp(val, "ip_pair") == 0) {
                    track = DETECT_XBITS_TRACK_IPPAIR;
                    var_type = VAR_TYPE_IPPAIR_BIT;
                } else {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid hostbit direction: %s", val);
                    return -1;
                }
                track_set = true;
            } else if (strcmp(token, "expire") == 0) {
                if (expire_set) {
                    return -1;
                }
                if ((StringParseUint32(&expire, 10, 0, val) < 0) || (expire == 0)) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid expire value: %s", val);
                    return -1;
                }
                expire_set = true;
            }
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid xbits keyword: %s", token);
            return -1;
        }
    next:
        token = strtok_r(NULL, ",", &context);
    }

    cd = SCMalloc(sizeof(DetectXbitsData));
    if (unlikely(cd == NULL))
        return -1;

    cd->idx = VarNameStoreSetupAdd(name, var_type);
    cd->cmd = cmd;
    cd->tracker = track;
    cd->type = var_type;
    cd->expire = expire;

    SCLogDebug("idx %" PRIu32 ", cmd %d, name %s", cd->idx, cmd, strlen(name) ? name : "(none)");

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
    HostInitConfig(TRUE);
    IPPairInitConfig(TRUE);
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

/* Test to demonstrate redmine bug 4820 */
static int XBitsTestSig03(void)
{
    DetectEngineCtx *de_ctx = NULL;
    XBitsTestSetup();
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert http any any -> any any (msg:\"TEST - No Error\")\";\
            flow:established,to_server; http.method; content:\"GET\"; \
            xbits:set,ET.2020_8260.1,track ip_src,expire 10; sid:1;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    XBitsTestShutdown();
    PASS;
}

/* Test to demonstrate redmine bug 4820 */
static int XBitsTestSig04(void)
{
    DetectEngineCtx *de_ctx = NULL;
    XBitsTestSetup();
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s =
            DetectEngineAppendSig(de_ctx, "alert http any any -> any any (msg:\"TEST - Error\")\"; \
            flow:established,to_server; http.method; content:\"GET\"; \
            xbits:set,ET.2020_8260.1,noalert,track ip_src,expire 10; sid:2;)");
    FAIL_IF_NOT_NULL(s);

    DetectEngineCtxFree(de_ctx);
    XBitsTestShutdown();
    PASS;
}

static int XBitsTestSig05(void)
{
    DetectEngineCtx *de_ctx = NULL;
    XBitsTestSetup();
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"ET EXPLOIT Possible Pulse Secure VPN RCE "
            "Chain Stage 1 Inbound - Request Config Backup (CVE-2020-8260)\"; "
            "flow:established,to_server; http.method; content:\"GET\"; http.uri; "
            "content:\"/dana-admin/cached/config/config.cgi?type=system\"; fast_pattern; "
            "xbits:set,ET.2020_8260.1,track ip_src,expire 10; xbits:noalert; "
            "classtype:attempted-admin; sid:2033750; rev:1;");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    XBitsTestShutdown();
    PASS;
}

static int XBitsTestSig06(void)
{
    DetectEngineCtx *de_ctx = NULL;
    XBitsTestSetup();
    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert http any any -> any any (msg:\"ET EXPLOIT Possible Pulse Secure VPN RCE "
            "Chain Stage 2 Inbound - Upload Malicious Config (CVE-2020-8260)\"; "
            "flow:established,to_server; http.method; content:\"POST\"; http.uri; "
            "content:\"/dana-admin/cached/config/import.cgi\"; "
            "xbits:isset,ET.2020_8260.1,track ip_src,expire 10;"
            "xbits:set,ET.2020_8260.2,track ip_src,expire 10; "
            "classtype:attempted-admin; sid:2033751; rev:1;");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    XBitsTestShutdown();
    PASS;
}

static int DetectXBitsTestBadRules(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    const char *sigs[] = {
        "alert http any any -> any any (content:\"abc\"; xbits:set,bit1,noalert,track "
        "ip_src;sid:1;)",
        "alert http any any -> any any (content:\"abc\"; xbits:noalert,set,bit1,noalert,track "
        "ip_src;sid:10;)",
        "alert http any any -> any any (content:\"abc\"; xbits:isset,bit2,track "
        "ip_dst,asdf;sid:2;)",
        "alert http any any -> any any (content:\"abc\"; xbits:isnotset,track ip_pair;sid:3;)",
        "alert http any any -> any any (content:\"abc\"; xbits:toggle,track ip_pair,bit4;sid:4;)",
        "alert http any any -> any any (content:\"abc\"; xbits:unset,bit5,track ipsrc;sid:5;)",
        "alert http any any -> any any (content:\"abc\"; xbits:bit6,set,track ip_src,expire "
        "10;sid:6;)",
        "alert http any any -> any any (content:\"abc\"; xbits:set,bit7,track "
        "ip_pair,expire;sid:7;)",
        "alert http any any -> any any (content:\"abc\"; xbits:set,bit7,trackk ip_pair,expire "
        "3600, noalert;sid:8;)",
        NULL,
    };

    const char **sig = sigs;
    while (*sig) {
        SCLogDebug("sig %s", *sig);
        Signature *s = DetectEngineAppendSig(de_ctx, *sig);
        FAIL_IF_NOT_NULL(s);
        sig++;
    }

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectXBitsTestGoodRules(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    const char *sigs[] = {
        "alert http any any -> any any (content:\"abc\"; xbits:set,bit1,track ip_src;sid:1;)",
        "alert http any any -> any any (content:\"abc\"; xbits:isset,bit2,track ip_dst;sid:2;)",
        "alert http any any -> any any (content:\"abc\"; xbits:isnotset, bit3,  track "
        "ip_pair;sid:3;)",
        "alert http any any -> any any (content:\"abc\"; xbits:toggle,bit4, track   "
        "ip_pair;sid:4;)",
        "alert http any any -> any any (content:\"abc\"; xbits:  unset ,bit5,track ip_src;sid:5;)",
        "alert http any any -> any any (content:\"abc\"; xbits:set,bit6 ,track ip_src, expire "
        "10 ;sid:6;)",
        "alert http any any -> any any (content:\"abc\"; xbits:set, bit7, track ip_pair, expire "
        "3600;sid:7;)",
        "alert http any any -> any any (content:\"abc\"; xbits:set, bit7, track ip_pair, expire "
        "3600; xbits:noalert; sid:8;)",
        "alert http any any -> any any (content:\"abc\"; xbits:noalert; xbits:set, bit7, track "
        "ip_pair, expire "
        "3600;sid:9;)",
        NULL,
    };

    const char **sig = sigs;
    while (*sig) {
        SCLogDebug("sig %s", *sig);
        Signature *s = DetectEngineAppendSig(de_ctx, *sig);
        FAIL_IF_NULL(s);
        sig++;
    }

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
    UtRegisterTest("XBitsTestSig03", XBitsTestSig03);
    UtRegisterTest("XBitsTestSig04", XBitsTestSig04);
    UtRegisterTest("XBitsTestSig05", XBitsTestSig05);
    UtRegisterTest("XBitsTestSig06", XBitsTestSig06);
    UtRegisterTest("DetectXBitsTestBadRules", DetectXBitsTestBadRules);
    UtRegisterTest("DetectXBitsTestGoodRules", DetectXBitsTestGoodRules);
}
#endif /* UNITTESTS */
