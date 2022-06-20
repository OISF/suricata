/* Copyright (C) 2012-2013 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 *
 * Implements the l3_proto keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-ipproto.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-build.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"

#include "detect-l3proto.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "util-debug.h"

static int DetectL3ProtoSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectL3protoRegisterTests(void);
#endif

void DetectL3ProtoRegister(void)
{
    sigmatch_table[DETECT_L3PROTO].name = "l3_proto";
    sigmatch_table[DETECT_L3PROTO].Match = NULL;
    sigmatch_table[DETECT_L3PROTO].Setup = DetectL3ProtoSetup;
    sigmatch_table[DETECT_L3PROTO].Free  = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_L3PROTO].RegisterTests = DetectL3protoRegisterTests;
#endif
}
/**
 * \internal
 * \brief Setup l3_proto keyword.
 *
 * \param de_ctx Detection engine context
 * \param s Signature
 * \param optstr Options string
 *
 * \return Non-zero on error
 */
static int DetectL3ProtoSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    const char *str = optstr;

    /* reset possible any value */
    if (s->proto.flags & DETECT_PROTO_ANY) {
        s->proto.flags &= ~DETECT_PROTO_ANY;
    }

    /* authorized value, ip, any, ip4, ipv4, ip6, ipv6 */
    if (strcasecmp(str,"ipv4") == 0 ||
            strcasecmp(str,"ip4") == 0 ) {
        if (s->proto.flags & DETECT_PROTO_IPV6) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Conflicting l3 proto specified");
            goto error;
        }
        s->proto.flags |= DETECT_PROTO_IPV4;
        SCLogDebug("IPv4 protocol detected");
    } else if (strcasecmp(str,"ipv6") == 0 ||
            strcasecmp(str,"ip6") == 0 ) {
        if (s->proto.flags & DETECT_PROTO_IPV6) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Conflicting l3 proto specified");
            goto error;
        }
        s->proto.flags |= DETECT_PROTO_IPV6;
        SCLogDebug("IPv6 protocol detected");
    } else {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid l3 proto: \"%s\"", str);
        goto error;
    }

    return 0;
error:
    return -1;
}

#ifdef UNITTESTS

/**
 * \test DetectL3protoTestSig01 is a test for checking the working of ttl keyword
 *       by setting up the signature and later testing its working by matching
 *       the received packet against the sig.
 */

static int DetectL3protoTestSig1(void)
{

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    IPV4Hdr ip4h;

    memset(&th_v, 0, sizeof(th_v));

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;
    p->ip4h = &ip4h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv4\"; l3_proto:ipv4; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv6\"; l3_proto:ipv6; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ip4\"; l3_proto:ip4; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ip6\"; l3_proto:ip6; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 0) {
        printf("sid 1 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2)) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3) == 0) {
        printf("sid 3 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 4)) {
        printf("sid 4 alerted, but should not have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p);
    return result;
}

/**
 * \test DetectL3protoTestSig02 is a test for checking the working of l3proto keyword
 *       by setting up the signature and later testing its working by matching
 *       the received IPv6 packet against the sig.
 */

static int DetectL3protoTestSig2(void)
{

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    IPV6Hdr ip6h;

    memset(&th_v, 0, sizeof(th_v));

    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->proto = IPPROTO_TCP;
    p->ip6h = &ip6h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv4\"; l3_proto:ipv4; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv6\"; l3_proto:ipv6; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ip4\"; l3_proto:ip4; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ip6\"; l3_proto:ip6; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2) == 0) {
        printf("sid 2 did not alert, but should have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3)) {
        printf("sid 3 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 4) == 0) {
        printf("sid 4 did not alert, but should have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p);
    return result;
}

/**
 * \test DetectL3protoTestSig03 is a test for checking the working of l3proto keyword
 *       in conjonction with ip_proto keyword.
 */

static int DetectL3protoTestSig3(void)
{

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    Signature *s = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;
    int result = 0;
    IPV6Hdr ip6h;

    memset(&th_v, 0, sizeof(th_v));

    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;
    p->proto = IPPROTO_TCP;
    p->ip6h = &ip6h;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv4 and ip_proto udp\"; l3_proto:ipv4; ip_proto:17; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv6 and ip_proto udp\"; l3_proto:ipv6; ip_proto:17; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ip4 and ip_proto tcp\"; l3_proto:ipv4; ip_proto:6; sid:3;)");
    if (s == NULL) {
        goto end;
    }

    s = s->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"l3proto ipv6 and ip_proto tcp\"; l3_proto:ipv6; ip_proto:6; sid:4;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 2)) {
        printf("sid 2 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 3)) {
        printf("sid 3 alerted, but should not have: ");
        goto cleanup;
    } else if (PacketAlertCheck(p, 4) == 0) {
        printf("sid 4 did not alert, but should have: ");
        goto cleanup;
    }

    result = 1;

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p);
    return result;
}

/**
 * \brief this function registers unit tests for DetectL3proto
 */
static void DetectL3protoRegisterTests(void)
{
    UtRegisterTest("DetectL3protoTestSig1", DetectL3protoTestSig1);
    UtRegisterTest("DetectL3protoTestSig2", DetectL3protoTestSig2);
    UtRegisterTest("DetectL3protoTestSig3", DetectL3protoTestSig3);
}
#endif /* UNITTESTS */
