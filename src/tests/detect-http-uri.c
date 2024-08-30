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

/** \file
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 */

#include "../suricata-common.h"
#include "../util-unittest.h"

#include "../detect-isdataat.h"
#include "../detect-engine-register.h"
#include "../detect-engine.h"
#include "../detect-parse.h"

static int DetectHttpUriIsdataatParseTest(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                                 "content:\"one\"; http_uri; "
                                                 "isdataat:!4,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = DetectBufferGetLastSigMatch(s, g_http_uri_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_ISDATAAT);

    DetectIsdataatData *data = (DetectIsdataatData *)sm->ctx;
    FAIL_IF_NOT(data->flags & ISDATAAT_RELATIVE);
    FAIL_IF_NOT(data->flags & ISDATAAT_NEGATED);
    FAIL_IF(data->flags & ISDATAAT_RAWBYTES);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief   Register the UNITTESTS for the http_uri keyword
 */
static void DetectHttpUriRegisterTests (void)
{
    UtRegisterTest("DetectHttpUriIsdataatParseTest", DetectHttpUriIsdataatParseTest);
}
