/* Copyright (C) 2012-2021 Open Information Security Foundation
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
#ifdef UNITTESTS
#include "util-fmemopen.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "detect-engine-build.h"
#include "detect-engine.h"
#endif
#include "detect-iprep.h"

#include "detect-parse.h"
#include "detect-engine-uint.h"

#include "util-validate.h"

static int DetectIPRepMatch (DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectIPRepSetup (DetectEngineCtx *, Signature *, const char *);
void DetectIPRepFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void IPRepRegisterTests(void);
#endif

void DetectIPRepRegister (void)
{
    sigmatch_table[DETECT_IPREP].name = "iprep";
    sigmatch_table[DETECT_IPREP].desc = "match on the IP reputation information for a host";
    sigmatch_table[DETECT_IPREP].url = "/rules/ip-reputation-rules.html#iprep";
    sigmatch_table[DETECT_IPREP].Match = DetectIPRepMatch;
    sigmatch_table[DETECT_IPREP].Setup = DetectIPRepSetup;
    sigmatch_table[DETECT_IPREP].Free  = DetectIPRepFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPREP].RegisterTests = IPRepRegisterTests;
#endif
    /* this is compatible to ip-only signatures */
    sigmatch_table[DETECT_IPREP].flags |= SIGMATCH_IPONLY_COMPAT;
}

static inline uint8_t GetRep(const SReputation *r, const uint8_t cat, const uint32_t version)
{
    /* allow higher versions as this happens during
     * rule reload */
    if (r != NULL && r->version >= version) {
        return r->rep[cat];
    }
    return 0;
}

static uint8_t GetHostRepSrc(Packet *p, uint8_t cat, uint32_t version)
{
    if (p->flags & PKT_HOST_SRC_LOOKED_UP && p->host_src == NULL) {
        return 0;
    } else if (p->host_src != NULL) {
        Host *h = (Host *)p->host_src;
        HostLock(h);
        /* use_cnt: 1 for having iprep, 1 for packet ref */
        DEBUG_VALIDATE_BUG_ON(h->iprep != NULL && SC_ATOMIC_GET(h->use_cnt) < 2);
        uint8_t val = GetRep(h->iprep, cat, version);
        HostUnlock(h);
        return val;
    } else {
        Host *h = HostLookupHostFromHash(&(p->src));
        p->flags |= PKT_HOST_SRC_LOOKED_UP;
        if (h == NULL)
            return 0;
        HostReference(&p->host_src, h);
        /* use_cnt: 1 for having iprep, 1 for HostLookupHostFromHash,
         * 1 for HostReference to packet */
        DEBUG_VALIDATE_BUG_ON(h->iprep != NULL && SC_ATOMIC_GET(h->use_cnt) < 3);
        uint8_t val = GetRep(h->iprep, cat, version);
        HostRelease(h); /* use_cnt >= 2: 1 for iprep, 1 for packet ref */
        return val;
    }
}

static uint8_t GetHostRepDst(Packet *p, uint8_t cat, uint32_t version)
{
    if (p->flags & PKT_HOST_DST_LOOKED_UP && p->host_dst == NULL) {
        return 0;
    } else if (p->host_dst != NULL) {
        Host *h = (Host *)p->host_dst;
        HostLock(h);
        /* use_cnt: 1 for having iprep, 1 for packet ref */
        DEBUG_VALIDATE_BUG_ON(h->iprep != NULL && SC_ATOMIC_GET(h->use_cnt) < 2);
        uint8_t val = GetRep(h->iprep, cat, version);
        HostUnlock(h);
        return val;
    } else {
        Host *h = HostLookupHostFromHash(&(p->dst));
        p->flags |= PKT_HOST_DST_LOOKED_UP;
        if (h == NULL)
            return 0;
        HostReference(&p->host_dst, h);
        /* use_cnt: 1 for having iprep, 1 for HostLookupHostFromHash,
         * 1 for HostReference to packet */
        DEBUG_VALIDATE_BUG_ON(h->iprep != NULL && SC_ATOMIC_GET(h->use_cnt) < 3);
        uint8_t val = GetRep(h->iprep, cat, version);
        HostRelease(h); /* use_cnt >= 2: 1 for iprep, 1 for packet ref */
        return val;
    }
}

/*
 * returns 0: no match
 *         1: match
 *        -1: error
 */
static int DetectIPRepMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectIPRepData *rd = (const DetectIPRepData *)ctx;
    if (rd == NULL)
        return 0;

    uint32_t version = det_ctx->de_ctx->srep_version;
    uint8_t val = 0;

    SCLogDebug("rd->cmd %u", rd->cmd);
    switch(rd->cmd) {
        case IPRepCmdAny:
            val = GetHostRepSrc(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                if (DetectU8Match(val, &rd->du8))
                    return 1;
            }
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return DetectU8Match(val, &rd->du8);
            }
            break;

        case IPRepCmdSrc:
            val = GetHostRepSrc(p, rd->cat, version);
            SCLogDebug("checking src -- val %u (looking for cat %u, val %u)", val, rd->cat,
                    rd->du8.arg1);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return DetectU8Match(val, &rd->du8);
            }
            break;

        case IPRepCmdDst:
            SCLogDebug("checking dst");
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return DetectU8Match(val, &rd->du8);
            }
            break;

        case IPRepCmdBoth:
            val = GetHostRepSrc(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepSrc(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val == 0 || DetectU8Match(val, &rd->du8) == 0)
                return 0;
            val = GetHostRepDst(p, rd->cat, version);
            if (val == 0)
                val = SRepCIDRGetIPRepDst(det_ctx->de_ctx->srepCIDR_ctx, p, rd->cat, version);
            if (val > 0) {
                return DetectU8Match(val, &rd->du8);
            }
            break;
    }

    return 0;
}

int DetectIPRepSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    SigMatch *sm = NULL;

    DetectIPRepData *cd = rs_detect_iprep_parse(rawstr);
    if (cd == NULL) {
        SCLogError(SC_ERR_UNKNOWN_VALUE, "\"%s\" is not a valid setting for iprep", rawstr);
        goto error;
    }

    SCLogDebug("cmd %u, cat %u, op %u, val %u", cd->cmd, cd->cat, cd->du8.mode, cd->du8.arg1);

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
    if (cd != NULL)
        DetectIPRepFree(de_ctx, cd);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectIPRepFree (DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIPRepData *fd = (DetectIPRepData *)ptr;

    if (fd == NULL)
        return;

    rs_detect_iprep_free(fd);
}

#ifdef UNITTESTS
static FILE *DetectIPRepGenerateCategoriesDummy(void)
{
    FILE *fd = NULL;
    const char *buffer = "1,BadHosts,Know bad hosts";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

static FILE *DetectIPRepGenerateCategoriesDummy2(void)
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

static FILE *DetectIPRepGenerateNetworksDummy(void)
{
    FILE *fd = NULL;
    const char *buffer = "10.0.0.0/24,1,20";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen()");

    return fd;
}

static FILE *DetectIPRepGenerateNetworksDummy2(void)
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
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:any,BadHosts,>,1; sid:1;rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest02(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:src,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest03(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->dst.addr_data32[0] = UTHSetIPv4Address("10.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:dst,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest04(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("10.0.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("10.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:both,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest05(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 0);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest06(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy2();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest07(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->dst.addr_data32[0] = UTHSetIPv4Address("1.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy2();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest08(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("1.0.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.0.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"IPREP High value "
                                        "badhost\"; iprep:any,BadHosts,>,1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 0);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

static int DetectIPRepTest09(void)
{
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Signature *sig = NULL;
    FILE *fd = NULL;
    int r = 0;
    Packet *p = UTHBuildPacket((uint8_t *)"lalala", 6, IPPROTO_TCP);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    HostInitConfig(HOST_QUIET);
    memset(&th_v, 0, sizeof(th_v));

    FAIL_IF_NULL(de_ctx);
    FAIL_IF_NULL(p);

    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("192.168.0.2");
    de_ctx->flags |= DE_QUIET;

    SRepInit(de_ctx);
    SRepResetVersion();

    fd = DetectIPRepGenerateCategoriesDummy2();
    r = SRepLoadCatFileFromFD(fd);
    FAIL_IF(r < 0);

    fd = DetectIPRepGenerateNetworksDummy2();
    r = SRepLoadFileFromFD(de_ctx->srepCIDR_ctx, fd);
    FAIL_IF(r < 0);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"test\"; iprep:src,BadHosts,>,9; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1);
    FAIL_IF(PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

/**
 * \brief this function registers unit tests for IPRep
 */
void IPRepRegisterTests(void)
{
    UtRegisterTest("DetectIPRepTest01", DetectIPRepTest01);
    UtRegisterTest("DetectIPRepTest02", DetectIPRepTest02);
    UtRegisterTest("DetectIPRepTest03", DetectIPRepTest03);
    UtRegisterTest("DetectIPRepTest04", DetectIPRepTest04);
    UtRegisterTest("DetectIPRepTest05", DetectIPRepTest05);
    UtRegisterTest("DetectIPRepTest06", DetectIPRepTest06);
    UtRegisterTest("DetectIPRepTest07", DetectIPRepTest07);
    UtRegisterTest("DetectIPRepTest08", DetectIPRepTest08);
    UtRegisterTest("DetectIPRepTest09", DetectIPRepTest09);
}
#endif /* UNITTESTS */
