/* Copyright (C) 2007-2018 Open Information Security Foundation
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

#include "../detect-template2.h"

#include "../util-unittest.h"

/**
 * \test DetectTemplate2ParseTest01 is a test for setting up an valid template2 value.
 */

static int DetectTemplate2ParseTest01 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse("10");

    FAIL_IF_NULL(template2d);
    FAIL_IF_NOT(template2d->arg1 == 10);
    FAIL_IF_NOT(template2d->mode == DETECT_TEMPLATE2_EQ);

    DetectTemplate2Free(template2d);

    PASS;
}

/**
 * \test DetectTemplate2ParseTest02 is a test for setting up an valid template2 value with
 *       "<" operator.
 */

static int DetectTemplate2ParseTest02 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse("<10");

    FAIL_IF_NULL(template2d);
    FAIL_IF_NOT(template2d->arg1 == 10);
    FAIL_IF_NOT(template2d->mode == DETECT_TEMPLATE2_LT);

    DetectTemplate2Free(template2d);

    PASS;
}

/**
 * \test DetectTemplate2ParseTest03 is a test for setting up an valid template2 values with
 *       "-" operator.
 */

static int DetectTemplate2ParseTest03 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse("1-2");

    FAIL_IF_NULL(template2d);
    FAIL_IF_NOT(template2d->arg1 == 1);
    FAIL_IF_NOT(template2d->mode == DETECT_TEMPLATE2_RA);

    DetectTemplate2Free(template2d);

    PASS;
}

/**
 * \test DetectTemplate2ParseTest04 is a test for setting up an valid template2 value with
 *       ">" operator and include spaces arround the given values.
 */

static int DetectTemplate2ParseTest04 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse(" > 10 ");

    FAIL_IF_NULL(template2d);
    FAIL_IF_NOT(template2d->arg1 == 10);
    FAIL_IF_NOT(template2d->mode == DETECT_TEMPLATE2_GT);

    DetectTemplate2Free(template2d);

    PASS;
}

/**
 * \test DetectTemplate2ParseTest05 is a test for setting up an valid template2 values with
 *       "-" operator and include spaces arround the given values.
 */

static int DetectTemplate2ParseTest05 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse(" 1 - 2 ");

    FAIL_IF_NULL(template2d);
    FAIL_IF_NOT(template2d->arg1 == 1);
    FAIL_IF_NOT(template2d->arg2 == 2);
    FAIL_IF_NOT(template2d->mode == DETECT_TEMPLATE2_RA);

    DetectTemplate2Free(template2d);

    PASS;
}

/**
 * \test DetectTemplate2ParseTest06 is a test for setting up an valid template2 values with
 *       invalid "=" operator and include spaces arround the given values.
 */

static int DetectTemplate2ParseTest06 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse(" 1 = 2 ");
    FAIL_IF_NOT_NULL(template2d);
    PASS;
}

/**
 * \test DetectTemplate2ParseTest07 is a test for setting up an valid template2 values with
 *       invalid "<>" operator and include spaces arround the given values.
 */

static int DetectTemplate2ParseTest07 (void)
{
    DetectTemplate2Data *template2d = DetectTemplate2Parse(" 1<>2 ");
    FAIL_IF_NOT_NULL(template2d);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectTemplate2
 */
void DetectTemplate2RegisterTests(void)
{
    UtRegisterTest("DetectTemplate2ParseTest01", DetectTemplate2ParseTest01);
    UtRegisterTest("DetectTemplate2ParseTest02", DetectTemplate2ParseTest02);
    UtRegisterTest("DetectTemplate2ParseTest03", DetectTemplate2ParseTest03);
    UtRegisterTest("DetectTemplate2ParseTest04", DetectTemplate2ParseTest04);
    UtRegisterTest("DetectTemplate2ParseTest05", DetectTemplate2ParseTest05);
    UtRegisterTest("DetectTemplate2ParseTest06", DetectTemplate2ParseTest06);
    UtRegisterTest("DetectTemplate2ParseTest07", DetectTemplate2ParseTest07);
}

