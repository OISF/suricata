/* Copyright (C) 2022 Open Information Security Foundation
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
 *
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 */

#include "conf-yaml-loader.h"
#include "detect-engine.h"
#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "util-unittest-helper.h"

#define TEST_INIT                                                       \
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();                    \
    FAIL_IF(de_ctx == NULL);                                            \
    SRepInit(de_ctx);                                                   \
                                                                        \
    Address a;                                                          \
    uint8_t cat = 0, value = 0;

#define TEST_INIT_WITH_PACKET(ip)                                       \
    uint8_t *buf = (uint8_t *)"Hi all!";                                \
    uint16_t buflen = strlen((char *)buf);                              \
    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);    \
    FAIL_IF(p == NULL);                                                 \
    p->src.addr_data32[0] = UTHSetIPv4Address(ip);                      \
    TEST_INIT

#define TEST_CLEANUP                                                    \
    DetectEngineCtxFree(de_ctx);

#define TEST_CLEANUP_WITH_PACKET                                        \
    UTHFreePacket(p);                                                   \
    TEST_CLEANUP

static int SRepTest01(void)
{
    TEST_INIT;

    char ipstr[16];
    char str[] = "1.2.3.4,1,2";
    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 0);
    PrintInet(AF_INET, (const void *)&a.address, ipstr, sizeof(ipstr));
    FAIL_IF(strcmp(ipstr, "1.2.3.4") != 0);
    FAIL_IF(cat != 1);
    FAIL_IF(value != 2);

    TEST_CLEANUP;
    PASS;
}

static int SRepTest02(void)
{
    TEST_INIT;

    char str[] = "1.1.1.1,";
    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) == 0);

    TEST_CLEANUP;
    PASS;
}

static int SRepTest03(void)
{
    char str[] = "1,Shortname,Long Name";
    uint8_t cat = 0;
    char shortname[SREP_SHORTNAME_LEN];

    FAIL_IF(SRepCatSplitLine(str, &cat, shortname, sizeof(shortname)) != 0);
    FAIL_IF(strcmp(shortname, "Shortname") != 0);
    FAIL_IF(cat != 1);

    PASS;
}

static int SRepTest04(void)
{
    TEST_INIT;

    char str[] = "10.0.0.0/16,1,2";
    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1);

    TEST_CLEANUP;
    PASS;
}

static int SRepTest05(void)
{
    TEST_INIT_WITH_PACKET("10.0.0.1");

    char str[] = "10.0.0.0/16,1,20";
    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1);

    cat = 1;
    FAIL_IF(SRepCIDRGetIPRepSrc(de_ctx->srepCIDR_ctx, p, cat, 0) != 20);

    TEST_CLEANUP_WITH_PACKET;
    PASS;
}

static int SRepTest06(void)
{
    TEST_INIT_WITH_PACKET("192.168.0.1");

    char str[] =
        "0.0.0.0/0,1,10\n"
        "192.168.0.0/16,2,127";

    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) != 1);

    cat = 1;
    FAIL_IF(SRepCIDRGetIPRepSrc(de_ctx->srepCIDR_ctx, p, cat, 0) != 10);

    TEST_CLEANUP_WITH_PACKET;
    PASS;
}

static int SRepTest07(void) {
    TEST_INIT;

    char str[] = "2000:0000:0000:0000:0000:0000:0000:0001,";
    FAIL_IF(SRepSplitLine(de_ctx->srepCIDR_ctx, str, &a, &cat, &value) == 0);

    TEST_CLEANUP;
    PASS;
}

/** Register the following unittests for the Reputation module */
void SCReputationRegisterTests(void)
{
    UtRegisterTest("SRepTest01", SRepTest01);
    UtRegisterTest("SRepTest02", SRepTest02);
    UtRegisterTest("SRepTest03", SRepTest03);
    UtRegisterTest("SRepTest04", SRepTest04);
    UtRegisterTest("SRepTest05", SRepTest05);
    UtRegisterTest("SRepTest06", SRepTest06);
    UtRegisterTest("SRepTest07", SRepTest07);
}
