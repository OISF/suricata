/* Copyright (C) 2020-2022 Open Information Security Foundation
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

#include "../detect-icmpv4hdr.h"

#include "../util-unittest.h"

static int DetectIcmpv4HdrParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NULL(DetectEngineAppendSig(
            de_ctx, "alert icmp any any -> any any (icmpv4.hdr; content:\"A\"; sid:1; rev:1;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectIcmpv4Hdr
 */
void DetectIcmpv4HdrRegisterTests(void)
{
    UtRegisterTest("DetectIcmpv4HdrParseTest01", DetectIcmpv4HdrParseTest01);
}
