/* Copyright (C) 2019 Open Information Security Foundation
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

#include "../app-layer-htp-file.h"
#include "../util-unittest.h"

/**
 * \test AppLayerHtpFileParseContentRangeTest01 is a test
 * for setting up a valid range value.
 */

static int AppLayerHtpFileParseContentRangeTest01 (void)
{
    FileContentRange range;
    bstr * rawvalue = bstr_dup_c("bytes 12-25/100");
    FAIL_IF_NOT(HTPParseContentRange(rawvalue, &range) == 0);
    FAIL_IF_NOT(range.start == 12);
    FAIL_IF_NOT(range.end == 25);
    FAIL_IF_NOT(range.size == 100);
    bstr_free(rawvalue);
    PASS;
}

/**
 * \test AppLayerHtpFileParseContentRangeTest02 is a regression test
 * for setting up an invalid range value.
 */

static int AppLayerHtpFileParseContentRangeTest02 (void)
{
    FileContentRange range;
    bstr * rawvalue = bstr_dup_c("bytes 15335424-27514354/");
    FAIL_IF(HTPParseContentRange(rawvalue, &range) == 0);
    bstr_free(rawvalue);
    PASS;
}

/**
 * \test AppLayerHtpFileParseContentRangeTest03 is a regression test
 * for setting up an invalid range value.
 */

static int AppLayerHtpFileParseContentRangeTest03 (void)
{
    FileContentRange range;
    bstr * rawvalue = bstr_dup_c("bytes 15335424-");
    FAIL_IF(HTPParseContentRange(rawvalue, &range) == 0);
    bstr_free(rawvalue);
    PASS;
}


/**
 * \test AppLayerHtpFileParseContentRangeTest04 is a test
 * for setting up a valid range value without the size.
 */

static int AppLayerHtpFileParseContentRangeTest04 (void)
{
    FileContentRange range;
    bstr * rawvalue = bstr_dup_c("bytes 24-42/*");
    FAIL_IF_NOT(HTPParseContentRange(rawvalue, &range) == 0);
    FAIL_IF_NOT(range.start == 24);
    FAIL_IF_NOT(range.end == 42);
    bstr_free(rawvalue);
    PASS;
}

/**
 * \brief this function registers unit tests for AppLayerHtpFile
 */
void AppLayerHtpFileRegisterTests(void)
{
    UtRegisterTest("AppLayerHtpFileParseContentRangeTest01", AppLayerHtpFileParseContentRangeTest01);
    UtRegisterTest("AppLayerHtpFileParseContentRangeTest02", AppLayerHtpFileParseContentRangeTest02);
    UtRegisterTest("AppLayerHtpFileParseContentRangeTest03", AppLayerHtpFileParseContentRangeTest03);
    UtRegisterTest("AppLayerHtpFileParseContentRangeTest04", AppLayerHtpFileParseContentRangeTest04);
}
