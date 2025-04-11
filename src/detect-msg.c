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
 * Implements the msg keyword
 */

#include "suricata-common.h"
#include "detect.h"
#include "util-classification-config.h"
#include "util-debug.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-msg.h"

static int DetectMsgSetup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectMsgRegisterTests(void);
#endif

void DetectMsgRegister (void)
{
    sigmatch_table[DETECT_MSG].name = "msg";
    sigmatch_table[DETECT_MSG].desc = "information about the rule and the possible alert";
    sigmatch_table[DETECT_MSG].url = "/rules/meta.html#msg-message";
    sigmatch_table[DETECT_MSG].Match = NULL;
    sigmatch_table[DETECT_MSG].Setup = DetectMsgSetup;
    sigmatch_table[DETECT_MSG].Free = NULL;
#ifdef UNITTESTS
    sigmatch_table[DETECT_MSG].RegisterTests = DetectMsgRegisterTests;
#endif
    sigmatch_table[DETECT_MSG].flags = (SIGMATCH_QUOTES_MANDATORY | SIGMATCH_SUPPORT_FIREWALL);
}

static int DetectMsgSetup (DetectEngineCtx *de_ctx, Signature *s, const char *msgstr)
{
    size_t slen = strlen(msgstr);
    if (slen == 0)
        return -1;

    char input[slen + 1];
    strlcpy(input, msgstr, slen + 1);
    char *str = input;
    char converted = 0;

    {
        size_t i, x;
        uint8_t escape = 0;

        /* it doesn't matter if we need to escape or not we remove the extra "\" to mimic snort */
        for (i = 0, x = 0; i < slen; i++) {
            //printf("str[%02u]: %c\n", i, str[i]);
            if(!escape && str[i] == '\\') {
                escape = 1;
            } else if (escape) {
                if (str[i] != ':' &&
                        str[i] != ';' &&
                        str[i] != '\\' &&
                        str[i] != '\"')
                {
                    SCLogDebug("character \"%c\" does not need to be escaped but is" ,str[i]);
                }
                escape = 0;
                converted = 1;

                str[x] = str[i];
                x++;
            }else{
                str[x] = str[i];
                x++;
            }

        }
#if 0 //def DEBUG
        if (SCLogDebugEnabled()) {
            for (i = 0; i < x; i++) {
                printf("%c", str[i]);
            }
            printf("\n");
        }
#endif

        if (converted) {
            slen = x;
            str[slen] = '\0';
        }
    }

    if (s->msg != NULL) {
        SCLogError("duplicated 'msg' keyword detected");
        goto error;
    }
    s->msg = SCStrdup(str);
    if (s->msg == NULL)
        goto error;
    return 0;

error:
    return -1;
}

/* -------------------------------------Unittests-----------------------------*/

#ifdef UNITTESTS
static int DetectMsgParseTest01(void)
{
    const char *teststringparsed = "flow stateless to_server";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassificationConfigFile(de_ctx, fd);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"flow stateless to_server\"; "
            "flow:stateless,to_server; content:\"flowstatelesscheck\"; "
            "classtype:bad-unknown; sid: 40000002; rev: 1;)");
    FAIL_IF_NULL(sig);

    FAIL_IF(strcmp(sig->msg, teststringparsed) != 0);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static int DetectMsgParseTest02(void)
{
    const char *teststringparsed = "msg escape tests wxy'\"\\;:";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"msg escape tests \\w\\x\\y\\'\\\"\\\\;\\:\"; "
            "flow:to_server,established; content:\"blah\"; uricontent:\"/blah/\"; sid: 100;)");
    FAIL_IF_NULL(sig);

    FAIL_IF(strcmp(sig->msg, teststringparsed) != 0);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static int DetectMsgParseTest03(void)
{
    const char *teststringparsed = "flow stateless to_server";
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassificationConfigFile(de_ctx, fd);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg: \"flow stateless to_server\"; "
            "flow:stateless,to_server; content:\"flowstatelesscheck\"; "
            "classtype:bad-unknown; sid: 40000002; rev: 1;)");
    FAIL_IF_NULL(sig);

    FAIL_IF(strcmp(sig->msg, teststringparsed) != 0);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectMsg
 */
void DetectMsgRegisterTests(void)
{
    UtRegisterTest("DetectMsgParseTest01", DetectMsgParseTest01);
    UtRegisterTest("DetectMsgParseTest02", DetectMsgParseTest02);
    UtRegisterTest("DetectMsgParseTest03", DetectMsgParseTest03);
}
#endif /* UNITTESTS */
