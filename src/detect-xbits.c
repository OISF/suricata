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
#include "detect-engine-build.h"

#include "flow-bit.h"
#include "host-bit.h"
#include "ippair-bit.h"
#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "rust.h"

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

    switch (fd->vartype) {
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
    cd = rs_xbits_parse(rawstr);

    if (cd == NULL) {
        return -1;
    }
    switch (cd->cmd) {
        case DETECT_XBITS_CMD_NOALERT: {
            if (cd->name != NULL) {
                rs_xbits_free(cd, cd->name);
                return -1;
            }
            /* return ok, cd is NULL. Flag sig. */
            *cdout = NULL;
            return 0;
        }
        case DETECT_XBITS_CMD_ISNOTSET:
        case DETECT_XBITS_CMD_ISSET:
        case DETECT_XBITS_CMD_SET:
        case DETECT_XBITS_CMD_UNSET:
        case DETECT_XBITS_CMD_TOGGLE:
        default:
            if (strlen(cd->name) == 0) {
                rs_xbits_free(cd, cd->name);
                return -1;
            }
            break;
    }

    cd->idx = VarNameStoreSetupAdd(cd->name, cd->vartype);
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

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (xbits:toggle,abc,track ip_dst, "
                                      "noalert; content:\"GET \"; sid:5;)");
    FAIL_IF_NOT_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (xbits:toggle,abc,track ip_dst; "
                                      "xbits:noalert; content:\"GET \"; sid:34;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (xbits:toggle,abc,track ip_dst; "
                                      "content:\"GET \"; sid:53;)");
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
    UtRegisterTest("XBitsTestSig01", XBitsTestSig01);
    UtRegisterTest("XBitsTestSig02", XBitsTestSig02);
}
#endif /* UNITTESTS */
