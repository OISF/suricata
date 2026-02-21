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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Proto part of the detection engine.
 *
 * \todo move this out of the detection plugin structure
 */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"

#include "app-layer-parser.h"

#include "flow-util.h"
#include "flow-var.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-state.h"

#include "util-cidr.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"

struct {
    const char *name;
    uint8_t proto;
    uint8_t proto2;
    uint8_t flags;
} proto_table[] = {
    { "tcp", IPPROTO_TCP, 0, 0 },
    { "tcp-pkt", IPPROTO_TCP, 0, DETECT_PROTO_ONLY_PKT },
    { "tcp-stream", IPPROTO_TCP, 0, DETECT_PROTO_ONLY_STREAM },
    { "udp", IPPROTO_UDP, 0, 0 },
    { "icmpv4", IPPROTO_ICMP, 0, 0 },
    { "icmpv6", IPPROTO_ICMPV6, 0, 0 },
    { "icmp", IPPROTO_ICMP, IPPROTO_ICMPV6, 0 },
    { "sctp", IPPROTO_SCTP, 0, 0 },
    { "ipv4", 0, 0, DETECT_PROTO_IPV4 | DETECT_PROTO_ANY },
    { "ip4", 0, 0, DETECT_PROTO_IPV4 | DETECT_PROTO_ANY },
    { "ipv6", 0, 0, DETECT_PROTO_IPV6 | DETECT_PROTO_ANY },
    { "ip6", 0, 0, DETECT_PROTO_IPV6 | DETECT_PROTO_ANY },
    { "ip", 0, 0, DETECT_PROTO_ANY },
    { "pkthdr", 0, 0, DETECT_PROTO_ANY },
};

void DetectEngineProtoList(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(proto_table); i++) {
        printf("%s\n", proto_table[i].name);
    }
}

/**
 * \brief Parses a protocol sent as a string.
 *
 * \param dp  Pointer to the DetectProto instance which will be updated with the
 *            incoming protocol information.
 * \param str Pointer to the string containing the protocol name.
 *
 * \retval >=0 If proto is detected, -1 otherwise.
 */
int DetectProtoParse(DetectProto *dp, const char *str)
{
    int found = -1;
    for (size_t i = 0; i < ARRAY_SIZE(proto_table); i++) {
        if (strcasecmp(str, proto_table[i].name) == 0) {
            if (proto_table[i].proto != 0)
                dp->proto[proto_table[i].proto / 8] |= 1 << (proto_table[i].proto % 8);
            if (proto_table[i].proto2 != 0)
                dp->proto[proto_table[i].proto2 / 8] |= 1 << (proto_table[i].proto2 % 8);
            dp->flags |= proto_table[i].flags;
            if (proto_table[i].flags & DETECT_PROTO_ANY)
                memset(dp->proto, 0xff, sizeof(dp->proto));
            found = 0;
            break;
        }
    }
    return found;
}

/** \brief see if a DetectProto contains a certain proto
 *  \param dp detect proto to inspect
 *  \param proto protocol (such as IPPROTO_TCP) to look for
 *  \retval 0 protocol not in the set
 *  \retval 1 protocol is in the set */
int DetectProtoContainsProto(const DetectProto *dp, int proto)
{
    if (dp == NULL || dp->flags & DETECT_PROTO_ANY)
        return 1;

    if (dp->proto[proto / 8] & (1<<(proto % 8)))
        return 1;

    return 0;
}

/** \brief see if a DetectProto explicitly a certain proto
 *  Explicit means the protocol was explicitly set, so "any"
 *  doesn't qualify.
 *  \param dp detect proto to inspect
 *  \param proto protocol (such as IPPROTO_TCP) to look for
 *  \retval false protocol not in the set
 *  \retval true protocol is in the set */
bool DetectProtoHasExplicitProto(const DetectProto *dp, const uint8_t proto)
{
    if (dp == NULL || dp->flags & DETECT_PROTO_ANY)
        return false;

    return ((dp->proto[proto / 8] & (1 << (proto % 8))));
}

/* return true if protocols enabled are only TCP and/or UDP */
static int DetectProtoIsOnlyTCPUDP(const DetectProto *dp)
{
    uint8_t protos[256 / 8];
    memset(protos, 0x00, sizeof(protos));
    protos[IPPROTO_TCP / 8] |= (1 << (IPPROTO_TCP % 8));
    protos[IPPROTO_UDP / 8] |= (1 << (IPPROTO_UDP % 8));

    int cnt = 0;
    for (size_t i = 0; i < sizeof(protos); i++) {
        if ((dp->proto[i] & protos[i]) != 0)
            cnt++;
    }
    return cnt != 0;
}

int DetectProtoFinalizeSignature(Signature *s)
{
    BUG_ON(s->proto);
    /* IP-only sigs are not per SGH, so need full proto */
    if (s->type == SIG_TYPE_IPONLY && !(s->init_data->proto.flags & DETECT_PROTO_ANY))
        goto full;
    /* Frames like the dns.pdu are registered for UDP and TCP, and share a MPM. So
     * a UDP rule can become a match candidate for a TCP sgh, meaning we need to
     * evaluate the rule's proto. */
    if ((s->init_data->init_flags & SIG_FLAG_INIT_FRAME) != 0 &&
            !(s->init_data->proto.flags & DETECT_PROTO_ANY))
        goto full;

    /* for now, we use the full protocol logic for DETECT_PROTO_IPV4/DETECT_PROTO_IPV6,
     * but we should address that as well. */
    if (s->init_data->proto.flags & (DETECT_PROTO_IPV4 | DETECT_PROTO_IPV6)) {
        SCLogDebug("sid %u has IPV4 or IPV6 flag set, so need full protocol", s->id);
        goto full;
    }

    /* no need to set up Signature::proto if sig needs any protocol,
     * or only TCP and/or UDP, as for those the SGH is per TCP/UDP */
    if ((s->init_data->proto.flags & DETECT_PROTO_ANY) ||
            DetectProtoIsOnlyTCPUDP(&s->init_data->proto)) {
        s->proto = NULL;
        return 0;
    }

full:
    s->proto = SCCalloc(1, sizeof(*s->proto));
    if (s->proto == NULL)
        return -1;

    memcpy(s->proto, &s->init_data->proto, sizeof(*s->proto));
    return 0;
}

/* TESTS */

#ifdef UNITTESTS
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-mpm.h"

/**
 * \brief this function is used to initialize the detection engine context and
 *        setup the signature with passed values.
 */
static int DetectProtoInitTest(DetectEngineCtx **de_ctx, Signature **sig,
                               DetectProto *dp, const char *str)
{
    char fullstr[1024];
    int result = 0;
    static uint32_t test_sid = 1;

    *sig = NULL;

    if (snprintf(fullstr, 1024,
                "alert %s any any -> any any (msg:\"DetectProto"
                " test\"; sid:%u;)",
                str, test_sid++) >= 1024) {
        goto end;
    }

    if (*de_ctx == NULL) {
        *de_ctx = DetectEngineCtxInit();
        if (*de_ctx == NULL) {
            goto end;
        }

        (*de_ctx)->flags |= DE_QUIET;
    }

    Signature *s = DetectEngineAppendSig(*de_ctx, fullstr);
    if (s == NULL) {
        goto end;
    }
    *sig = s;

    result = 1;

end:
    return result;
}

/**
 * \test ProtoTestParse01 is a test to make sure that we parse the
 *  protocol correctly, when given valid proto option.
 */
static int ProtoTestParse01 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "6");

    FAIL_IF_NOT(r < 0);

    PASS;
}
/**
 * \test ProtoTestParse02 is a test to make sure that we parse the
 *  protocol correctly, when given "tcp" as proto option.
 */
static int ProtoTestParse02 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "tcp");

    FAIL_IF_NOT(r >= 0);
    FAIL_IF_NOT(dp.proto[(IPPROTO_TCP / 8)] & (1 << (IPPROTO_TCP % 8)));

    PASS;
}
/**
 * \test ProtoTestParse03 is a test to make sure that we parse the
 *  protocol correctly, when given "ip" as proto option.
 */
static int ProtoTestParse03 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    int r = DetectProtoParse(&dp, "ip");

    FAIL_IF_NOT(r >= 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ANY);

    PASS;
}

/**
 * \test ProtoTestParse04 is a test to make sure that we do not parse the
 *  protocol, when given an invalid proto option.
 */
static int ProtoTestParse04 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad number */
    int r = DetectProtoParse(&dp, "4242");

    FAIL_IF_NOT(r < 0);

    PASS;
}

/**
 * \test ProtoTestParse05 is a test to make sure that we do not parse the
 *  protocol, when given an invalid proto option.
 */
static int ProtoTestParse05 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp/udp");

    FAIL_IF_NOT(r < 0);

    PASS;
}

/**
 * \test make sure that we properly parse tcp-pkt
 */
static int ProtoTestParse06 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp-pkt");

    FAIL_IF(r < 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ONLY_PKT);

    PASS;
}

/**
 * \test make sure that we properly parse tcp-stream
 */
static int ProtoTestParse07 (void)
{
    DetectProto dp;
    memset(&dp,0,sizeof(DetectProto));

    /* Check for a bad string */
    int r = DetectProtoParse(&dp, "tcp-stream");

    FAIL_IF(r < 0);
    FAIL_IF_NOT(dp.flags & DETECT_PROTO_ONLY_STREAM);

    PASS;
}

/**
 * \test DetectIPProtoTestSetup01 is a test for a protocol setting up in
 *       signature.
 */
static int DetectProtoTestSetup01(void)
{
    DetectProto dp;
    Signature *sig = NULL;
    DetectEngineCtx *de_ctx = NULL;
    int i;

    memset(&dp, 0, sizeof(dp));

    FAIL_IF_NOT(DetectProtoInitTest(&de_ctx, &sig, &dp, "tcp"));

    /* The signature proto should be TCP */
    FAIL_IF_NOT(sig->init_data->proto.proto[(IPPROTO_TCP / 8)] & (1 << (IPPROTO_TCP % 8)));

    for (i = 2; i < 256 / 8; i++) {
        FAIL_IF(sig->init_data->proto.proto[i] != 0);
    }

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test DetectProtoTestSetup02 is a test for a icmpv4 and icmpv6
 *       protocol setting up in signature.
 */
static int DetectProtoTestSetup02(void)
{
    DetectProto dp;
    Signature *sig_icmpv4 = NULL;
    Signature *sig_icmpv6 = NULL;
    Signature *sig_icmp = NULL;
    DetectEngineCtx *de_ctx = NULL;

    memset(&dp, 0, sizeof(dp));

    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmpv4, &dp, "icmpv4") == 0);
    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmpv6, &dp, "icmpv6") == 0);
    FAIL_IF(DetectProtoInitTest(&de_ctx, &sig_icmp, &dp, "icmp") == 0);

    FAIL_IF_NOT(sig_icmpv4->init_data->proto.proto[IPPROTO_ICMP / 8] & (1 << (IPPROTO_ICMP % 8)));
    FAIL_IF_NOT(
            sig_icmpv6->init_data->proto.proto[IPPROTO_ICMPV6 / 8] & (1 << (IPPROTO_ICMPV6 % 8)));

    FAIL_IF_NOT(sig_icmp->init_data->proto.proto[IPPROTO_ICMP / 8] & (1 << (IPPROTO_ICMP % 8)));
    FAIL_IF_NOT(sig_icmp->init_data->proto.proto[IPPROTO_ICMPV6 / 8] & (1 << (IPPROTO_ICMPV6 % 8)));

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \test signature parsing with tcp-pkt and tcp-stream
 */

static int DetectProtoTestSig01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert tcp-pkt any any -> any any (msg:\"tcp-pkt\"; content:\"blah\"; sid:1;)");
    FAIL_IF_NULL(s);

    s = DetectEngineAppendSig(de_ctx,
            "alert tcp-stream any any -> any any (msg:\"tcp-stream\"; content:\"blah\"; sid:2;)");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);

    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectProto
 */
void DetectProtoTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("ProtoTestParse01", ProtoTestParse01);
    UtRegisterTest("ProtoTestParse02", ProtoTestParse02);
    UtRegisterTest("ProtoTestParse03", ProtoTestParse03);
    UtRegisterTest("ProtoTestParse04", ProtoTestParse04);
    UtRegisterTest("ProtoTestParse05", ProtoTestParse05);
    UtRegisterTest("ProtoTestParse06", ProtoTestParse06);
    UtRegisterTest("ProtoTestParse07", ProtoTestParse07);

    UtRegisterTest("DetectProtoTestSetup01", DetectProtoTestSetup01);
    UtRegisterTest("DetectProtoTestSetup02", DetectProtoTestSetup02);

    UtRegisterTest("DetectProtoTestSig01", DetectProtoTestSig01);
#endif /* UNITTESTS */
}

