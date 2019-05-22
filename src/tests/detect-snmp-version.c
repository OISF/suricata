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

#include "util-unittest.h"
#include "util-unittest-helper.h"

/**
 * \test This is a test for a valid value 2.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int SNMPValidityTestParse01 (void)
{
    DetectSNMPVersionData *dd = NULL;
    dd = DetectSNMPVersionParse("2");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->version == 2 && dd->mode == PROCEDURE_EQ);
    DetectSNMPVersionFree(dd);
    PASS;
}

/**
 * \test This is a test for a valid value >2.
 *
 * \retval 1 on success.
 * \retval 0 on failure.
 */
static int SNMPValidityTestParse02 (void)
{
    DetectSNMPVersionData *dd = NULL;
    dd = DetectSNMPVersionParse(">2");
    FAIL_IF_NULL(dd);
    FAIL_IF_NOT(dd->version == 2 && dd->mode == PROCEDURE_GT);
    DetectSNMPVersionFree(dd);
    PASS;
}

static void DetectSNMPVersionRegisterTests(void)
{
    UtRegisterTest("SNMPValidityTestParse01", SNMPValidityTestParse01);
    UtRegisterTest("SNMPValidityTestParse02", SNMPValidityTestParse02);
}
