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
 * Implements the hostbits keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-util.h"
#include "detect-hostbits.h"
#include "util-spm.h"

#include "detect-engine-sigorder.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"

#include "flow-bit.h"
#include "host-bit.h"
#include "util-var-name.h"
#include "util-unittest.h"
#include "util-debug.h"

/*
    hostbits:isset,bitname;
    hostbits:set,bitname;

    hostbits:set,bitname,src;
    hostbits:set,bitname,dst;
TODO:
    hostbits:set,bitname,both;

    hostbits:set,bitname,src,3600;
    hostbits:set,bitname,dst,60;
    hostbits:set,bitname,both,120;
 */

#define PARSE_REGEX "^([a-z]+)"          /* Action */                    \
    "(?:\\s*,\\s*([^\\s,]+))?(?:\\s*)?" /* Name. */                     \
    "(?:\\s*,\\s*([^,\\s]+))?(?:\\s*)?" /* Direction. */                \
    "(.+)?"                             /* Any remainding data. */
static DetectParseRegex parse_regex;

static int DetectHostbitMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectHostbitSetup (DetectEngineCtx *, Signature *, const char *);
void DetectHostbitFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
void HostBitsRegisterTests(void);
#endif

void DetectHostbitsRegister (void)
{
    sigmatch_table[DETECT_HOSTBITS].name = "hostbits";
    sigmatch_table[DETECT_HOSTBITS].desc = "operate on host flag";
//    sigmatch_table[DETECT_HOSTBITS].url = "/rules/flow-keywords.html#flowbits";
    sigmatch_table[DETECT_HOSTBITS].Match = DetectHostbitMatch;
    sigmatch_table[DETECT_HOSTBITS].Setup = DetectHostbitSetup;
    sigmatch_table[DETECT_HOSTBITS].Free  = DetectHostbitFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_HOSTBITS].RegisterTests = HostBitsRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_HOSTBITS].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

static int DetectHostbitMatchToggle (Packet *p, const DetectXbitsData *fd)
{
    switch (fd->tracker) {
        case DETECT_XBITS_TRACK_IPSRC:
            if (p->host_src == NULL) {
                p->host_src = HostGetHostFromHash(&p->src);
                if (p->host_src == NULL)
                    return 0;
            }
            else
                HostLock(p->host_src);

            HostBitToggle(p->host_src,fd->idx,p->ts.tv_sec + fd->expire);
            HostUnlock(p->host_src);
            break;
        case DETECT_XBITS_TRACK_IPDST:
            if (p->host_dst == NULL) {
                p->host_dst = HostGetHostFromHash(&p->dst);
                if (p->host_dst == NULL)
                    return 0;
            }
            else
                HostLock(p->host_dst);

            HostBitToggle(p->host_dst,fd->idx,p->ts.tv_sec + fd->expire);
            HostUnlock(p->host_dst);
            break;
    }
    return 1;
}

/* return true even if bit not found */
static int DetectHostbitMatchUnset (Packet *p, const DetectXbitsData *fd)
{
    switch (fd->tracker) {
        case DETECT_XBITS_TRACK_IPSRC:
            if (p->host_src == NULL) {
                p->host_src = HostLookupHostFromHash(&p->src);
                if (p->host_src == NULL)
                    return 1;
            } else
                HostLock(p->host_src);

            HostBitUnset(p->host_src,fd->idx);
            HostUnlock(p->host_src);
            break;
        case DETECT_XBITS_TRACK_IPDST:
            if (p->host_dst == NULL) {
                p->host_dst = HostLookupHostFromHash(&p->dst);
                if (p->host_dst == NULL)
                    return 1;
            } else
                HostLock(p->host_dst);

            HostBitUnset(p->host_dst,fd->idx);
            HostUnlock(p->host_dst);
            break;
    }
    return 1;
}

static int DetectHostbitMatchSet (Packet *p, const DetectXbitsData *fd)
{
    switch (fd->tracker) {
        case DETECT_XBITS_TRACK_IPSRC:
            if (p->host_src == NULL) {
                p->host_src = HostGetHostFromHash(&p->src);
                if (p->host_src == NULL)
                    return 0;
            } else
                HostLock(p->host_src);

            HostBitSet(p->host_src,fd->idx,p->ts.tv_sec + fd->expire);
            HostUnlock(p->host_src);
            break;
        case DETECT_XBITS_TRACK_IPDST:
            if (p->host_dst == NULL) {
                p->host_dst = HostGetHostFromHash(&p->dst);
                if (p->host_dst == NULL)
                    return 0;
            } else
                HostLock(p->host_dst);

            HostBitSet(p->host_dst,fd->idx, p->ts.tv_sec + fd->expire);
            HostUnlock(p->host_dst);
            break;
    }
    return 1;
}

static int DetectHostbitMatchIsset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    switch (fd->tracker) {
        case DETECT_XBITS_TRACK_IPSRC:
            if (p->host_src == NULL) {
                p->host_src = HostLookupHostFromHash(&p->src);
                if (p->host_src == NULL)
                    return 0;
            } else
                HostLock(p->host_src);

            r = HostBitIsset(p->host_src,fd->idx, p->ts.tv_sec);
            HostUnlock(p->host_src);
            return r;
        case DETECT_XBITS_TRACK_IPDST:
            if (p->host_dst == NULL) {
                p->host_dst = HostLookupHostFromHash(&p->dst);
                if (p->host_dst == NULL)
                    return 0;
            } else
                HostLock(p->host_dst);

            r = HostBitIsset(p->host_dst,fd->idx, p->ts.tv_sec);
            HostUnlock(p->host_dst);
            return r;
    }
    return 0;
}

static int DetectHostbitMatchIsnotset (Packet *p, const DetectXbitsData *fd)
{
    int r = 0;
    switch (fd->tracker) {
        case DETECT_XBITS_TRACK_IPSRC:
            if (p->host_src == NULL) {
                p->host_src = HostLookupHostFromHash(&p->src);
                if (p->host_src == NULL)
                    return 1;
            } else
                HostLock(p->host_src);

            r = HostBitIsnotset(p->host_src,fd->idx, p->ts.tv_sec);
            HostUnlock(p->host_src);
            return r;
        case DETECT_XBITS_TRACK_IPDST:
            if (p->host_dst == NULL) {
                p->host_dst = HostLookupHostFromHash(&p->dst);
                if (p->host_dst == NULL)
                    return 1;
            } else
                HostLock(p->host_dst);

            r = HostBitIsnotset(p->host_dst,fd->idx, p->ts.tv_sec);
            HostUnlock(p->host_dst);
            return r;
    }
    return 0;
}

int DetectXbitMatchHost(Packet *p, const DetectXbitsData *xd)
{
    switch (xd->cmd) {
        case DETECT_XBITS_CMD_ISSET:
            return DetectHostbitMatchIsset(p,xd);
        case DETECT_XBITS_CMD_ISNOTSET:
            return DetectHostbitMatchIsnotset(p,xd);
        case DETECT_XBITS_CMD_SET:
            return DetectHostbitMatchSet(p,xd);
        case DETECT_XBITS_CMD_UNSET:
            return DetectHostbitMatchUnset(p,xd);
        case DETECT_XBITS_CMD_TOGGLE:
            return DetectHostbitMatchToggle(p,xd);
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

static int DetectHostbitMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectXbitsData *xd = (const DetectXbitsData *)ctx;
    if (xd == NULL)
        return 0;

    return DetectXbitMatchHost(p, xd);
}

static int DetectHostbitParse(const char *str, char *cmd, int cmd_len,
    char *name, int name_len, char *dir, int dir_len)
{
    int count, rc;
    size_t pcre2len;

    count = DetectParsePcreExec(&parse_regex, str, 0, 0);
    if (count != 2 && count != 3 && count != 4) {
        SCLogError(SC_ERR_PCRE_MATCH,
            "\"%s\" is not a valid setting for hostbits.", str);
        return 0;
    }

    pcre2len = cmd_len;
    rc = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)cmd, &pcre2len);
    if (rc < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        return 0;
    }

    if (count >= 3) {
        pcre2len = name_len;
        rc = pcre2_substring_copy_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 *)name, &pcre2len);
        if (rc < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
            return 0;
        }
        if (count >= 4) {
            pcre2len = dir_len;
            rc = pcre2_substring_copy_bynumber(
                    parse_regex.match, 3, (PCRE2_UCHAR8 *)dir, &pcre2len);
            if (rc < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
                return 0;
            }
        }
    }

    return 1;
}

int DetectHostbitSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectXbitsData *cd = NULL;
    SigMatch *sm = NULL;
    uint8_t fb_cmd = 0;
    uint8_t hb_dir = 0;
    char fb_cmd_str[16] = "", fb_name[256] = "";
    char hb_dir_str[16] = "";

    if (!DetectHostbitParse(rawstr, fb_cmd_str, sizeof(fb_cmd_str),
            fb_name, sizeof(fb_name), hb_dir_str, sizeof(hb_dir_str))) {
        return -1;
    }

    if (strlen(hb_dir_str) > 0) {
        if (strcmp(hb_dir_str, "src") == 0)
            hb_dir = DETECT_XBITS_TRACK_IPSRC;
        else if (strcmp(hb_dir_str, "dst") == 0)
            hb_dir = DETECT_XBITS_TRACK_IPDST;
        else if (strcmp(hb_dir_str, "both") == 0) {
            //hb_dir = DETECT_XBITS_TRACK_IPBOTH;
            SCLogError(SC_ERR_UNIMPLEMENTED, "'both' not implemented");
            goto error;
        } else {
            // TODO
            goto error;
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

    cd->idx = VarNameStoreSetupAdd(fb_name, VAR_TYPE_HOST_BIT);
    cd->cmd = fb_cmd;
    cd->tracker = hb_dir;
    cd->vartype = VAR_TYPE_HOST_BIT;
    cd->expire = 300;

    SCLogDebug("idx %" PRIu32 ", cmd %s, name %s",
        cd->idx, fb_cmd_str, strlen(fb_name) ? fb_name : "(none)");

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_HOSTBITS;
    sm->ctx = (void *)cd;

    switch (fb_cmd) {
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

        // suppress coverity warning as scan-build-7 warns w/o this.
        // coverity[deadcode : FALSE]
        default:
            goto error;
    }

    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectHostbitFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectXbitsData *fd = (DetectXbitsData *)ptr;

    if (fd == NULL)
        return;

    SCFree(fd);
}

#ifdef UNITTESTS

static void HostBitsTestSetup(void)
{
    StorageInit();
    HostBitInitCtx();
    StorageFinalize();
    HostInitConfig(true);
}

static void HostBitsTestShutdown(void)
{
    HostCleanup();
    StorageCleanup();
}

static int HostBitsTestParse01(void)
{
    char cmd[16] = "", name[256] = "", dir[16] = "";

    /* No direction. */
    FAIL_IF(!DetectHostbitParse("isset,name", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);
    FAIL_IF(strlen(dir));

    /* No direction, leading space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset, name", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);

    /* No direction, trailing space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset,name ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);

    /* No direction, leading and trailing space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset, name ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);

    /* With direction. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset,name,src", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);
    FAIL_IF(strcmp(dir, "src") != 0);

    /* With direction - leading and trailing spaces on name. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset, name ,src", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);
    FAIL_IF(strcmp(dir, "src") != 0);

    /* With direction - space around direction. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(!DetectHostbitParse("isset, name , src ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));
    FAIL_IF(strcmp(cmd, "isset") != 0);
    FAIL_IF(strcmp(name, "name") != 0);
    FAIL_IF(strcmp(dir, "src") != 0);

    /* Name with space, no direction - should fail. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    FAIL_IF(DetectHostbitParse("isset, name withspace ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir)));

    PASS;
}

/**
 * \test HostBitsTestSig01 is a test for a valid noalert flowbits option
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig01(void)
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

    HostBitsTestSetup();

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (hostbits:set,abc; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PacketFree(p);
    HostBitsTestShutdown();
    PASS;
}

/**
 * \test various options
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */

static int HostBitsTestSig02(void)
{
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:isset,abc,src; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:isnotset,abc,dst; content:\"GET \"; sid:2;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:!isset,abc,dst; content:\"GET \"; sid:3;)");
    FAIL_IF_NOT_NULL(s);

/* TODO reenable after both is supported
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:set,abc,both; content:\"GET \"; sid:3;)");
    FAIL_IF_NULL(s);
*/
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:unset,abc,src; content:\"GET \"; sid:4;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:toggle,abc,dst; content:\"GET \"; sid:5;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test HostBitsTestSig03 is a test check idx value
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
    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int idx = 0;

    memset(&th_v, 0, sizeof(th_v));
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    HostBitsTestSetup();

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"isset option\"; hostbits:isset,fbt; content:\"GET \"; sid:1;)");
    FAIL_IF_NULL(s);

    idx = VarNameStoreSetupAdd("fbt", VAR_TYPE_HOST_BIT);
    FAIL_IF(idx != 1);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostBitsTestShutdown();

    SCFree(p);
    PASS;
}

/**
 * \brief this function registers unit tests for HostBits
 */
void HostBitsRegisterTests(void)
{
    UtRegisterTest("HostBitsTestParse01", HostBitsTestParse01);
    UtRegisterTest("HostBitsTestSig01", HostBitsTestSig01);
    UtRegisterTest("HostBitsTestSig02", HostBitsTestSig02);
    UtRegisterTest("HostBitsTestSig03", HostBitsTestSig03);
}
#endif /* UNITTESTS */
