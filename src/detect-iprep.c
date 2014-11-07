/* Copyright (C) 2012 Open Information Security Foundation
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
 * Implements the iprep keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-iprep.h"
#include "util-spm.h"

#include "app-layer-parser.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-fmemopen.h"

#include "reputation.h"
#include "host.h"

#define PARSE_REGEX         "\\s*(any|src|dst|both)\\s*,\\s*([A-Za-z0-9\\-\\_]+)\\s*,\\s*(\\<|\\>|\\=)\\s*,\\s*([0-9]+)\\s*"
static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectIPRepMatch (ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, const SigMatchCtx *);
static int DetectIPRepSetup (DetectEngineCtx *, Signature *, char *);
void DetectIPRepFree (void *);
void IPRepRegisterTests(void);

void DetectIPRepRegister (void)
{
    sigmatch_table[DETECT_IPREP].name = "iprep";
    sigmatch_table[DETECT_IPREP].Match = DetectIPRepMatch;
    sigmatch_table[DETECT_IPREP].Setup = DetectIPRepSetup;
    sigmatch_table[DETECT_IPREP].Free  = DetectIPRepFree;
    sigmatch_table[DETECT_IPREP].RegisterTests = IPRepRegisterTests;
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_IPREP].flags |= SIGMATCH_IPONLY_COMPAT;

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

static uint8_t GetHostRepSrc(Packet *p, uint8_t cat, uint32_t version)
{
    uint8_t val = 0;
    Host *h = NULL;

    if (p->flags & PKT_HOST_SRC_LOOKED_UP && p->host_src == NULL) {
        return 0;
    } else if (p->host_src != NULL) {
        h = (Host *)p->host_src;
        HostLock(h);
    } else {
        h = HostLookupHostFromHash(&(p->src));

        p->flags |= PKT_HOST_SRC_LOOKED_UP;

        if (h == NULL)
            return 0;

        HostReference(&p->host_src, h);
    }

    if (h->iprep == NULL) {
        HostRelease(h);
        return 0;
    }

    SReputation *r = (SReputation *)h->iprep;

    /* allow higher versions as this happens during
     * rule reload */
    if (r->version >= version)
        val = r->rep[cat];
    else
        SCLogDebug("version mismatch %u != %u", r->version, version);

    HostRelease(h);
    return val;
}

static uint8_t GetHostRepDst(Packet *p, uint8_t cat, uint32_t version)
{
    uint8_t val = 0;
    Host *h = NULL;

    if (p->flags & PKT_HOST_DST_LOOKED_UP && p->host_dst == NULL) {
        return 0;
    } else if (p->host_dst != NULL) {
        h = (Host *)p->host_dst;
        HostLock(h);
    } else {
        h = HostLookupHostFromHash(&(p->dst));

        p->flags |= PKT_HOST_DST_LOOKED_UP;

        if (h == NULL) {
            return 0;
        }

        HostReference(&p->host_dst, h);
    }

    if (h->iprep == NULL) {
        HostRelease(h);
        return 0;
    }

    SReputation *r = (SReputation *)h->iprep;

    /* allow higher versions as this happens during
     * rule reload */
    if (r->version >= version)
        val = r->rep[cat];
    else
        SCLogDebug("version mismatch %u != %u", r->version, version);

    HostRelease(h);
    return val;
}

static inline int RepMatch(uint8_t op, uint8_t val1, uint8_t val2)
{
    if (op == DETECT_IPREP_OP_GT && val1 > val2) {
        return 1;
    } else if (op == DETECT_IPREP_OP_LT && val1 < val2) {
        return 1;
    } else if (op == DETECT_IPREP_OP_EQ && val1 == val2) {
        return 1;
    }
    return 0;
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */
int DetectIPRepMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, const SigMatchCtx *ctx)
{
    const DetectIPRepData *rd = (const DetectIPRepData *)ctx;
    if (rd == NULL)
        return 0;

    uint32_t version = det_ctx->de_ctx->srep_version;
    uint8_t val = 0;

    SCLogDebug("rd->cmd %u", rd->cmd);
    switch(rd->cmd) {
        case DETECT_IPREP_CMD_ANY:
            val = GetHostRepSrc(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                if (RepMatch(rd->op, val, rd->val) == 1)
                    return 1;
            }
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return RepMatch(rd->op, val, rd->val);
            }
            break;

        case DETECT_IPREP_CMD_SRC:
            val = GetHostRepSrc(p, rd->cat, version);
            SCLogDebug("checking src -- val %u (looking for cat %u, val %u)", val, rd->cat, rd->val);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return RepMatch(rd->op, val, rd->val);
            }
            break;

        case DETECT_IPREP_CMD_DST:
            SCLogDebug("checking dst");
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return RepMatch(rd->op, val, rd->val);
            }
            break;

        case DETECT_IPREP_CMD_BOTH:
            val = GetHostRepSrc(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val == 0 || RepMatch(rd->op, val, rd->val) == 0)
                return 0;
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return RepMatch(rd->op, val, rd->val);
            }
            break;
    }

    return 0;
}

int DetectIPRepSetup (DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    DetectIPRepData *cd = NULL;
    SigMatch *sm = NULL;
    char *cmd_str = NULL, *name = NULL, *op_str = NULL, *value = NULL;
    uint8_t cmd = 0;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 5) {
        SCLogError(SC_ERR_PCRE_MATCH, "\"%s\" is not a valid setting for iprep", rawstr);
        return -1;
    }

    const char *str_ptr;
    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        return -1;
    }
    cmd_str = (char *)str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    name = (char *)str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    op_str = (char *)str_ptr;

    res = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, &str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }
    value = (char *)str_ptr;

    if (strcmp(cmd_str,"any") == 0) {
        cmd = DETECT_IPREP_CMD_ANY;
    } else if (strcmp(cmd_str,"both") == 0) {
        cmd = DETECT_IPREP_CMD_BOTH;
    } else if (strcmp(cmd_str,"src") == 0) {
        cmd = DETECT_IPREP_CMD_SRC;
    } else if (strcmp(cmd_str,"dst") == 0) {
        cmd = DETECT_IPREP_CMD_DST;
    } else {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "ERROR: iprep \"%s\" is not supported.", cmd_str);
        goto error;
    }

    //SCLogInfo("category %s", name);
    uint8_t cat = SRepCatGetByShortname(name);
    if (cat == 0) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "unknown iprep category \"%s\"", name);
        goto error;
    }

    uint8_t op = 0;
    uint8_t val = 0;

    if (op_str == NULL || strlen(op_str) != 1) {
        goto error;
    }

    switch(op_str[0]) {
        case '<':
            op = DETECT_IPREP_OP_LT;
            break;
        case '>':
            op = DETECT_IPREP_OP_GT;
            break;
        case '=':
            op = DETECT_IPREP_OP_EQ;
            break;
        default:
            goto error;
            break;
    }

    if (value != NULL && strlen(value) > 0) {
        int ival = atoi(value);
        if (ival < 0 || ival > 127)
            goto error;
        val = (uint8_t)ival;
    }

    cd = SCMalloc(sizeof(DetectIPRepData));
    if (unlikely(cd == NULL))
        goto error;

    cd->cmd = cmd;
    cd->cat = cat;
    cd->op = op;
    cd->val = val;
    SCLogDebug("cmd %u, cat %u, op %u, val %u", cd->cmd, cd->cat, cd->op, cd->val);

    pcre_free_substring(name);
    name = NULL;
    pcre_free_substring(cmd_str);
    cmd_str = NULL;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_IPREP;
    sm->ctx = (SigMatchCtx *)cd;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (name != NULL)
        pcre_free_substring(name);
    if (cmd_str != NULL)
        pcre_free_substring(cmd_str);
    if (cd != NULL)
        SCFree(cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectIPRepFree (void *ptr)
{
    DetectIPRepData *fd = (DetectIPRepData *)ptr;

    if (fd == NULL)
        return;

    SCFree(fd);
}

#ifdef UNITTESTS
FILE *DetectIPRepGenerateCategoriesDummy()
{
    FILE *fd = NULL;
    const char *buffer = "1,BadHosts,Know bad hosts";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

FILE *DetectIPRepGenerateCategoriesDummy2()
{
    FILE *fd = NULL;
    const char *buffer =
        "1,BadHosts,Know bad hosts\n"
        "2,GoodHosts,Know good hosts\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

FILE *DetectIPRepGenerateNetworksDummy()
{
    FILE *fd = NULL;
    const char *buffer = "10.0.0.0/24,1,20";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

FILE *DetectIPRepGenerateNetworksDummy2()
{
    FILE *fd = NULL;
    const char *buffer =
        "0.0.0.0/0,1,10\n"
        "192.168.0.0/16,2,127";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

static int DetectIPRepTest01(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:any,BadHosts,>,1; sid:1;rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest02(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:src,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest03(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->dst.addr_data32[0] = UTHSetIPv4Address("10.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:dst,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest04(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("10.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:both,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest05(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest06(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest07(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->dst.addr_data32[0] = UTHSetIPv4Address("1.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest08(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

static int DetectIPRepTest09(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int result = 0, r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    if (de_ctx == NULL || p == NULL)
        goto end;

    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("192.168.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy2();
    r = SRepLoadCatFileFromFD(fd);
    if (r < 0) {
        goto end;
    }

    fd = DetectIPRepGenerateNetworksDummy2();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    if (r < 0) {
        goto end;
    }

    sig = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"test\"; iprep:src,BadHosts,>,9; sid:1; rev:1;)");
    if (sig == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for IPRep
 */
void IPRepRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectIPRepTest01", DetectIPRepTest01, 1);
    UtRegisterTest("DetectIPRepTest02", DetectIPRepTest02, 1);
    UtRegisterTest("DetectIPRepTest03", DetectIPRepTest03, 1);
    UtRegisterTest("DetectIPRepTest04", DetectIPRepTest04, 1);
    UtRegisterTest("DetectIPRepTest05", DetectIPRepTest05, 0);
    UtRegisterTest("DetectIPRepTest06", DetectIPRepTest06, 0);
    UtRegisterTest("DetectIPRepTest07", DetectIPRepTest07, 0);
    UtRegisterTest("DetectIPRepTest08", DetectIPRepTest08, 0);
    UtRegisterTest("DetectIPRepTest09", DetectIPRepTest09, 1);
#endif /* UNITTESTS */
}
