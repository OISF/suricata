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
 * \author Giuseppe Longo <giuseppelng@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#ifdef UNITTESTS

#include "../stream-tcp.h"
#include "../detect.h"
#include "../detect-isdataat.h"

static int DetectEngineSMTPFiledataTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NOT(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert smtp any any -> any any "
                                                 "(msg:\"file_data smtp test\"; "
                                                 "file_data; content:\"message\"; sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT(s->flags & SIG_FLAG_TOSERVER);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test the file_data fails with flow:to_server.
 */
static int DetectFiledataParseTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert smtp any any -> any any "
            "(msg:\"test\"; flow:to_client,established; file_data; content:\"abc\"; sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectFiledataRegisterTests(void)
{
    UtRegisterTest("DetectEngineSMTPFiledataTest02", DetectEngineSMTPFiledataTest02);
    UtRegisterTest("DetectFiledataParseTest04", DetectFiledataParseTest04);
}
#endif
