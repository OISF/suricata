/* Copyright (C) 2025 Open Information Security Foundation
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
 *
 * \author Jeff Lucovsky <jlucovsky@oisf.net>
 *
 * Implements the ftp.mode sticky buffer
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"

#include "rust.h"
#include "flow.h"

#include "util-debug.h"

#include "app-layer.h"
#include "app-layer-ftp.h"

#include "detect-ftp-mode.h"

#define KEYWORD_NAME "ftp.mode"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-mode"
#define BUFFER_NAME  "ftp.mode"
#define BUFFER_DESC  "ftp mode"

static int g_ftp_mode_buffer_id = 0;

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
static int DetectFtpModeMatch(DetectEngineThreadCtx *det_ctx, Flow *f, uint8_t flags, void *state,
        void *txv, const Signature *s, const SigMatchCtx *m)
{
    FTPTransaction *tx = (FTPTransaction *)txv;
    if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN) {
        return 0;
    }
    if (!tx->dyn_port) {
        return 0;
    }

    const DetectFtpModeData *ftpmoded = (const DetectFtpModeData *)m;
    return ftpmoded->active == tx->active;
}

/**
 * \brief this function will free memory associated with DetectFtpModeData
 *
 * \param ptr pointer to DetectFtpModeData
 */
static void DetectFtpModeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCFTPFreeModeData(ptr);
}

/**
 * \brief This function is used to parse ftp.mode options passed via ftp.mode keyword
 *
 * \param str Pointer to the user provided ftp.mode options
 *
 * \retval  pointer to DetectFtpModeData on success
 * \retval NULL on failure
 */
static DetectFtpModeData *DetectFtpModeParse(const char *optstr)
{
    DetectFtpModeData *ftpmoded = SCFTPParseMode(optstr);
    if (unlikely(ftpmoded == NULL)) {
        SCLogError("Invalid command value");
        return NULL;
    }

    return ftpmoded;
}

static int DetectFtpModeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) != 0)
        return -1;

    DetectFtpModeData *ftpmoded = DetectFtpModeParse(str);
    if (ftpmoded == NULL)
        return -1;

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_FTP_MODE, (SigMatchCtx *)ftpmoded,
                g_ftp_mode_buffer_id) == NULL) {
        DetectFtpModeFree(de_ctx, ftpmoded);
        return -1;
    }

    return 0;
}

void DetectFtpModeRegister(void)
{
    /* ftp.mode sticky buffer */
    sigmatch_table[DETECT_FTP_MODE].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_MODE].desc = "sticky buffer to match on the FTP mode buffer";
    sigmatch_table[DETECT_FTP_MODE].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_MODE].Setup = DetectFtpModeSetup;
    sigmatch_table[DETECT_FTP_MODE].AppLayerTxMatch = DetectFtpModeMatch;
    sigmatch_table[DETECT_FTP_MODE].Free = DetectFtpModeFree;

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0, DetectEngineInspectGenericList, NULL);

    DetectAppLayerInspectEngineRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOSERVER, 0, DetectEngineInspectGenericList, NULL);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_mode_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
