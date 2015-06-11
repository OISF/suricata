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

#define PARSE_REGEX "([a-z]+)(?:\\s*,\\s*([^\\s,]+))?(?:\\s*,\\s*([^,\\s]+))?"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectHostbitMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectHostbitSetup (DetectEngineCtx *, Signature *, char *);
void DetectHostbitFree (void *);
void HostBitsRegisterTests(void);

void DetectHostbitsRegister (void)
{
    sigmatch_table[DETECT_HOSTBITS].name = "hostbits";
    sigmatch_table[DETECT_HOSTBITS].desc = "operate on host flag";
//    sigmatch_table[DETECT_HOSTBITS].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Flow-keywords#Flowbits";
    sigmatch_table[DETECT_HOSTBITS].Match = DetectHostbitMatch;
    sigmatch_table[DETECT_HOSTBITS].Setup = DetectHostbitSetup;
    sigmatch_table[DETECT_HOSTBITS].Free  = DetectHostbitFree;
    sigmatch_table[DETECT_HOSTBITS].RegisterTests = HostBitsRegisterTests;
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_HOSTBITS].flags |= SIGMATCH_IPONLY_COMPAT;

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

int DetectHostbitMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectXbitsData *xd = (const DetectXbitsData *)ctx;
    if (xd == NULL)
        return 0;

    return DetectXbitMatchHost(p, xd);
}

static int DetectHostbitParse(const char *str, char *cmd, int cmd_len,
    char *name, int name_len, char *dir, int dir_len)
{
    const int max_substrings = 30;
    int count, rc;
    int ov[max_substrings];

    count = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0,
        ov, max_substrings);
    if (count != 2 && count != 3 && count != 4) {
        SCLogError(SC_ERR_PCRE_MATCH,
            "\"%s\" is not a valid setting for hostbits.", str);
        return 0;
    }

    rc = pcre_copy_substring((char *)str, ov, max_substrings, 1, cmd, cmd_len);
    if (rc < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        return 0;
    }

    if (count >= 3) {
        rc = pcre_copy_substring((char *)str, ov, max_substrings, 2, name,
            name_len);
        if (rc < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            return 0;
        }
        if (count >= 4) {
            rc = pcre_copy_substring((char *)str, ov, max_substrings, 3, dir,
                dir_len);
            if (rc < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                    "pcre_copy_substring failed");
                return 0;
            }
        }
    }

    return 1;
}

int DetectHostbitSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
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

    cd->idx = VariableNameGetIdx(de_ctx, fb_name, VAR_TYPE_HOST_BIT);
    cd->cmd = fb_cmd;
    cd->tracker = hb_dir;
    cd->type = VAR_TYPE_HOST_BIT;
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
    }

    return 0;

error:
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectHostbitFree (void *ptr)
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
    HostInitConfig(TRUE);
}

static void HostBitsTestShutdown(void)
{
    HostCleanup();
    StorageCleanup();
}

static int HostBitsTestParse01(void)
{
    int ret = 0;
    char cmd[16] = "", name[256] = "", dir[16] = "";

    /* No direction. */
    if (!DetectHostbitParse("isset,name", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }
    if (strlen(dir)) {
        goto end;
    }

    /* No direction, leading space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset, name", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }

    /* No direction, trailing space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset,name ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }

    /* No direction, leading and trailing space. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset, name ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }

    /* With direction. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset,name,src", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }
    if (strcmp(dir, "src") != 0) {
        goto end;
    }

    /* With direction - leading and trailing spaces on name. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset, name ,src", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }
    if (strcmp(dir, "src") != 0) {
        goto end;
    }

    /* With direction - space around direction. */
    *cmd = '\0';
    *name = '\0';
    *dir = '\0';
    if (!DetectHostbitParse("isset, name , src ", cmd, sizeof(cmd), name,
            sizeof(name), dir, sizeof(dir))) {
        goto end;
    }
    if (strcmp(cmd, "isset") != 0) {
        goto end;
    }
    if (strcmp(name, "name") != 0) {
        goto end;
    }
    if (strcmp(dir, "src") != 0) {
        goto end;
    }

    ret = 1;
end:
    return ret;
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
        printf("bad de_ctx: ");
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (hostbits:set,abc; content:\"GET \"; sid:1;)");

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

    HostBitsTestShutdown();

    SCFree(p);
    return result;
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
    int result = 0;
    int error_count = 0;

    memset(&th_v, 0, sizeof(th_v));

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:isset,abc,src; content:\"GET \"; sid:1;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:isnotset,abc,dst; content:\"GET \"; sid:2;)");
    if (s == NULL) {
        error_count++;
    }
/* TODO reenable after both is supported
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:set,abc,both; content:\"GET \"; sid:3;)");
    if (s == NULL) {
        error_count++;
    }
*/
    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:unset,abc,src; content:\"GET \"; sid:4;)");
    if (s == NULL) {
        error_count++;
    }

    s = DetectEngineAppendSig(de_ctx,
            "alert ip any any -> any any (hostbits:toggle,abc,dst; content:\"GET \"; sid:5;)");
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
#endif

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

#if 0
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

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_HOST_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_HOSTBITS && gv->idx == idx) {
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

    idx = VariableNameGetIdx(de_ctx, "myflow", VAR_TYPE_HOST_BIT);

    gv = p->flow->flowvar;

    for ( ; gv != NULL; gv = gv->next) {
        if (gv->type == DETECT_HOSTBITS && gv->idx == idx) {
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
#endif

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
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for HostBits
 */
void HostBitsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("HostBitsTestParse01", HostBitsTestParse01, 1);
    UtRegisterTest("HostBitsTestSig01", HostBitsTestSig01, 1);
    UtRegisterTest("HostBitsTestSig02", HostBitsTestSig02, 1);
#if 0
    UtRegisterTest("HostBitsTestSig03", HostBitsTestSig03, 0);
#endif
    UtRegisterTest("HostBitsTestSig04", HostBitsTestSig04, 1);
    UtRegisterTest("HostBitsTestSig05", HostBitsTestSig05, 1);
#if 0
    UtRegisterTest("HostBitsTestSig06", HostBitsTestSig06, 1);
#endif
    UtRegisterTest("HostBitsTestSig07", HostBitsTestSig07, 1);
    UtRegisterTest("HostBitsTestSig08", HostBitsTestSig08, 1);
#endif /* UNITTESTS */
}
