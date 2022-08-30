/* Copyright (C) 2017-2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Match on ftp command used to trigger a ftp data transfer
 */

#include "suricata-common.h"
#include "util-unittest.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"

#include "app-layer-ftp.h"

#include "detect-ftpdata.h"

/**
 * \brief Regex for parsing our keyword options
 */
#define PARSE_REGEX  "^\\s*(stor|retr)\\s*$"
static DetectParseRegex parse_regex;

/* Prototypes of functions registered in DetectFtpdataRegister below */
static int DetectFtpdataMatch(DetectEngineThreadCtx *,
        Flow *, uint8_t, void *, void *,
        const Signature *, const SigMatchCtx *);
static int DetectFtpdataSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFtpdataFree (DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectFtpdataRegisterTests (void);
#endif
static int g_ftpdata_buffer_id = 0;

/**
 * \brief Registration function for ftpcommand: keyword
 *
 * This function is called once in the 'lifetime' of the engine.
 */
void DetectFtpdataRegister(void) {
    /* keyword name: this is how the keyword is used in a rule */
    sigmatch_table[DETECT_FTPDATA].name = "ftpdata_command";
    /* description: listed in "suricata --list-keywords=all" */
    sigmatch_table[DETECT_FTPDATA].desc = "match FTP command triggering a FTP data channel";
    sigmatch_table[DETECT_FTPDATA].url = "/rules/ftp-keywords.html#ftpdata-command";
    sigmatch_table[DETECT_FTPDATA].AppLayerTxMatch = DetectFtpdataMatch;
    /* setup function is called during signature parsing, when the ftpcommand
     * keyword is encountered in the rule */
    sigmatch_table[DETECT_FTPDATA].Setup = DetectFtpdataSetup;
    /* free function is called when the detect engine is freed. Normally at
     * shutdown, but also during rule reloads. */
    sigmatch_table[DETECT_FTPDATA].Free = DetectFtpdataFree;
    /* registers unittests into the system */
#ifdef UNITTESTS
    sigmatch_table[DETECT_FTPDATA].RegisterTests = DetectFtpdataRegisterTests;
#endif
    DetectAppLayerInspectEngineRegister2("ftpdata_command", ALPROTO_FTPDATA, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister2("ftpdata_command", ALPROTO_FTPDATA, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectGenericList, NULL);
    g_ftpdata_buffer_id = DetectBufferTypeGetByName("ftpdata_command");

    /* set up the PCRE for keyword parsing */
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to check matches from the FTP App Layer Parser
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFtpdataMatch(DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags,
        void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    const DetectFtpdataData *ftpcommandd = (const DetectFtpdataData *) m;
    const FtpDataState *ftp_state = (const FtpDataState *)state;

    if (ftp_state == NULL)
        return 0;

    if (ftpcommandd->command == ftp_state->command) {
        /* Only match if the flow is in the good direction */
        if ((flags & STREAM_TOSERVER) && (ftpcommandd->command == FTP_COMMAND_RETR)) {
            return 0;
        } else if ((flags & STREAM_TOCLIENT) && (ftpcommandd->command == FTP_COMMAND_STOR)) {
            return 0;
        }
        return 1;
    }

    return 0;
}

/**
 * \brief This function is used to parse ftpcommand options passed via ftpcommand: keyword
 *
 * \param ftpcommandstr Pointer to the user provided ftpcommand options
 *
 * \retval ftpcommandd pointer to DetectFtpdataData on success
 * \retval NULL on failure
 */
static DetectFtpdataData *DetectFtpdataParse(const char *ftpcommandstr)
{
    DetectFtpdataData *ftpcommandd = NULL;
    char arg1[5] = "";
    size_t pcre2len;

    int ret = DetectParsePcreExec(&parse_regex, ftpcommandstr, 0, 0);
    if (ret != 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 "", ret);
        goto error;
    }

    pcre2len = sizeof(arg1);
    int res = pcre2_substring_copy_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 *)arg1, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed");
        goto error;
    }
    SCLogDebug("Arg1 \"%s\"", arg1);

    ftpcommandd = SCMalloc(sizeof (DetectFtpdataData));
    if (unlikely(ftpcommandd == NULL))
        goto error;
    if (!strcmp(arg1, "stor")) {
        ftpcommandd->command = FTP_COMMAND_STOR;
    } else if (!strcmp(arg1, "retr")) {
        ftpcommandd->command = FTP_COMMAND_RETR;
    } else {
        SCLogError(SC_ERR_NOT_SUPPORTED, "Invalid command value");
        goto error;
    }

    return ftpcommandd;

error:
    if (ftpcommandd)
        SCFree(ftpcommandd);
    return NULL;
}

/**
 * \brief parse the options from the 'ftpcommand' keyword in the rule into
 *        the Signature data structure.
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided ftpcommand options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFtpdataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectSignatureSetAppProto(s, ALPROTO_FTPDATA) != 0)
        return -1;

    DetectFtpdataData *ftpcommandd = DetectFtpdataParse(str);
    if (ftpcommandd == NULL)
        return -1;

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectFtpdataFree(de_ctx, ftpcommandd);
        return -1;
    }
    sm->type = DETECT_FTPDATA;
    sm->ctx = (void *)ftpcommandd;

    SigMatchAppendSMToList(s, sm, g_ftpdata_buffer_id);
    return 0;
}

/**
 * \brief this function will free memory associated with DetectFtpdataData
 *
 * \param ptr pointer to DetectFtpdataData
 */
static void DetectFtpdataFree(DetectEngineCtx *de_ctx, void *ptr) {
    DetectFtpdataData *ftpcommandd = (DetectFtpdataData *)ptr;

    /* do more specific cleanup here, if needed */

    SCFree(ftpcommandd);
}

#ifdef UNITTESTS

static int DetectFtpdataParseTest01(void)
{
    DetectFtpdataData *ftpcommandd = DetectFtpdataParse("stor");
    FAIL_IF_NULL(ftpcommandd);
    FAIL_IF(!(ftpcommandd->command == FTP_COMMAND_STOR));
    DetectFtpdataFree(NULL, ftpcommandd);
    PASS;
}

static int DetectFtpdataSignatureTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (ftpdata_command:stor; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);
    sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (ftpdata_command:retr; sid:2; rev:1;)");
    FAIL_IF_NULL(sig);
    sig = DetectEngineAppendSig(de_ctx, "alert ip any any -> any any (ftpdata_command:xxx; sid:3; rev:1;)");
    FAIL_IF_NOT_NULL(sig);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \brief this function registers unit tests for DetectFtpdata
 */
static void DetectFtpdataRegisterTests(void)
{
    UtRegisterTest("DetectFtpdataParseTest01", DetectFtpdataParseTest01);
    UtRegisterTest("DetectFtpdataSignatureTest01",
                   DetectFtpdataSignatureTest01);
}
#endif /* UNITTESTS */
