/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the sid keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "util-debug.h"
#include "util-error.h"
#include "util-unittest.h"

static int DetectSidSetup (DetectEngineCtx *, Signature *, char *);
static void DetectSidRegisterTests(void);

void DetectSidRegister (void)
{
    sigmatch_table[DETECT_SID].name = "sid";
    sigmatch_table[DETECT_SID].desc = "set rule id";
    sigmatch_table[DETECT_SID].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Meta-settings#Sid-signature-id";
    sigmatch_table[DETECT_SID].Match = NULL;
    sigmatch_table[DETECT_SID].Setup = DetectSidSetup;
    sigmatch_table[DETECT_SID].Free = NULL;
    sigmatch_table[DETECT_SID].RegisterTests = DetectSidRegisterTests;
}

static int DetectSidSetup (DetectEngineCtx *de_ctx, Signature *s, char *sidstr)
{
    char *str = sidstr;
    char duped = 0;

    /* Strip leading and trailing "s. */
    if (sidstr[0] == '\"') {
        str = SCStrdup(sidstr + 1);
        if (unlikely(str == NULL)) {
            return -1;
        }
        if (strlen(str) && str[strlen(str) - 1] == '\"') {
            str[strlen(str) - 1] = '\0';
        }
        duped = 1;
    }

    unsigned long id = 0;
    char *endptr = NULL;
    id = strtoul(sidstr, &endptr, 10);
    if (endptr == NULL || *endptr != '\0') {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid character as arg "
                   "to sid keyword");
        goto error;
    }
    if (id >= UINT_MAX) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "sid value to high, max %u", UINT_MAX);
        goto error;
    }

    s->id = (uint32_t)id;

    if (duped)
        SCFree(str);
    return 0;

 error:
    if (duped)
        SCFree(str);
    return -1;
}

#ifdef UNITTESTS

static int SidTestParse01(void)
{
    int result = 0;
    Signature *s = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    s = DetectEngineAppendSig(de_ctx,
        "alert tcp 1.2.3.4 any -> any any (sid:1; gid:1;)");
    if (s == NULL || s->id != 1)
        goto end;

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SidTestParse02(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx,
            "alert tcp 1.2.3.4 any -> any any (sid:a; gid:1;)") != NULL)
        goto end;

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SidTestParse03(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (content:\"ABC\"; sid:\";)") != NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

#endif

/**
 * \brief Register DetectSid unit tests.
 */
static void DetectSidRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SidTestParse01", SidTestParse01, 1);
    UtRegisterTest("SidTestParse02", SidTestParse02, 1);
    UtRegisterTest("SidTestParse03", SidTestParse03, 1);
#endif /* UNITTESTS */
}
