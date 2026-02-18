/* Copyright (C) 2026 Open Information Security Foundation
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

#include "../detect-igmphdr.h"

#include "../util-unittest.h"

static int DetectIGMPHdrParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FAIL_IF_NULL(DetectEngineAppendSig(
            de_ctx, "alert igmp any any -> any any (igmp.hdr; content:\"A\"; sid:1; rev:1;)"));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief register tests
 */
void DetectIGMPHdrRegisterTests(void)
{
    UtRegisterTest("DetectIGMPHdrParseTest01", DetectIGMPHdrParseTest01);
}
