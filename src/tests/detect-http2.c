/* Copyright (C) 2020 Open Information Security Foundation
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

#include "../detect-engine.h"

#include "../detect-http2.h"

#include "../util-unittest.h"

/**
 * \test signature with a valid http2.frametype value.
 */

static int DetectHTTP2frameTypeParseTest01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert http2 any any -> any any (http2.frametype:GOAWAY; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;

}

/**
 * \brief this function registers unit tests for DetectICMPv6mtu
 */
void DetectHTTP2RegisterTests(void)
{
    UtRegisterTest("DetectHTTP2frameTypeParseTest01", DetectHTTP2frameTypeParseTest01);
}
