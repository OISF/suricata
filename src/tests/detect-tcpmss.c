/* Copyright (C) 2007-2019 Open Information Security Foundation
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

#include "../suricata-common.h"

#include "../detect.h"
#include "../detect-parse.h"
#include "../detect-engine-prefilter-common.h"

#include "../detect-tcpmss.h"

#include "../util-unittest.h"

/**
 * \test setting up a valid tcpmss value.
 */

static int DetectTcpmssParseTest01 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse("10");

    FAIL_IF_NULL(tcpmssd);
    FAIL_IF_NOT(tcpmssd->arg1 == 10);
    FAIL_IF_NOT(tcpmssd->mode == DETECT_TCPMSS_EQ);

    DetectTcpmssFree(tcpmssd);

    PASS;
}

/**
 * \test setting up a valid tcpmss value with "<" operator.
 */

static int DetectTcpmssParseTest02 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse("<10");

    FAIL_IF_NULL(tcpmssd);
    FAIL_IF_NOT(tcpmssd->arg1 == 10);
    FAIL_IF_NOT(tcpmssd->mode == DETECT_TCPMSS_LT);

    DetectTcpmssFree(tcpmssd);

    PASS;
}

/**
 * \test setting up an valid tcpmss values with "-" operator.
 */

static int DetectTcpmssParseTest03 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse("1-2");

    FAIL_IF_NULL(tcpmssd);
    FAIL_IF_NOT(tcpmssd->arg1 == 1);
    FAIL_IF_NOT(tcpmssd->mode == DETECT_TCPMSS_RA);

    DetectTcpmssFree(tcpmssd);

    PASS;
}

/**
 * \test setting up an valid tcpmss value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectTcpmssParseTest04 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse(" > 10 ");

    FAIL_IF_NULL(tcpmssd);
    FAIL_IF_NOT(tcpmssd->arg1 == 10);
    FAIL_IF_NOT(tcpmssd->mode == DETECT_TCPMSS_GT);

    DetectTcpmssFree(tcpmssd);

    PASS;
}

/**
 * \test setting up an valid tcpmss values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectTcpmssParseTest05 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse(" 1 - 2 ");

    FAIL_IF_NULL(tcpmssd);
    FAIL_IF_NOT(tcpmssd->arg1 == 1);
    FAIL_IF_NOT(tcpmssd->arg2 == 2);
    FAIL_IF_NOT(tcpmssd->mode == DETECT_TCPMSS_RA);

    DetectTcpmssFree(tcpmssd);

    PASS;
}

/**
 * \test setting up an valid tcpmss values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectTcpmssParseTest06 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(tcpmssd);
    PASS;
}

/**
 * \test setting up valid tcpmss values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectTcpmssParseTest07 (void)
{
    DetectTcpmssData *tcpmssd = DetectTcpmssParse(" 1<>2 ");
    FAIL_IF_NOT_NULL(tcpmssd);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTcpmss
 */
void DetectTcpmssRegisterTests(void)
{
    UtRegisterTest("DetectTcpmssParseTest01", DetectTcpmssParseTest01);
    UtRegisterTest("DetectTcpmssParseTest02", DetectTcpmssParseTest02);
    UtRegisterTest("DetectTcpmssParseTest03", DetectTcpmssParseTest03);
    UtRegisterTest("DetectTcpmssParseTest04", DetectTcpmssParseTest04);
    UtRegisterTest("DetectTcpmssParseTest05", DetectTcpmssParseTest05);
    UtRegisterTest("DetectTcpmssParseTest06", DetectTcpmssParseTest06);
    UtRegisterTest("DetectTcpmssParseTest07", DetectTcpmssParseTest07);
}
