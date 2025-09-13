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
 * Implements the ftp.completion-code sticky buffer
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-helper.h"
#include "detect-ftp-completion-code.h"

#include "app-layer.h"
#include "app-layer-ftp.h"

#include "flow.h"

#include "util-debug.h"

#define KEYWORD_NAME "ftp.completion_code"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-completion_code"
#define BUFFER_NAME  "ftp.completion_code"
#define BUFFER_DESC  "ftp completion code"

static int g_ftp_ccode_buffer_id = 0;

static int DetectFtpCompletionCodeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_ftp_ccode_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) < 0)
        return -1;

    return 0;
}

static bool DetectFTPCompletionCodeGetData(DetectEngineThreadCtx *_det_ctx, const void *txv,
        uint8_t _flow_flags, uint32_t index, const uint8_t **buffer, uint32_t *buffer_len)
{
    FTPTransaction *tx = (FTPTransaction *)txv;

    if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN)
        return false;

    if (!TAILQ_EMPTY(&tx->response_list)) {
        uint32_t count = 0;
        FTPResponseWrapper *wrapper;
        TAILQ_FOREACH (wrapper, &tx->response_list, next) {
            DEBUG_VALIDATE_BUG_ON(wrapper->response == NULL);
            if (index == count) {
                *buffer = (const uint8_t *)wrapper->response->code;
                *buffer_len = (uint32_t)wrapper->response->code_length;
                return true;
            }
            count++;
        }
    }

    *buffer = NULL;
    *buffer_len = 0;
    return false;
}

void DetectFtpCompletionCodeRegister(void)
{
    /* ftp.completion_code sticky buffer */
    sigmatch_table[DETECT_FTP_COMPLETION_CODE].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_COMPLETION_CODE].desc =
            "sticky buffer to match on the FTP completion code buffer";
    sigmatch_table[DETECT_FTP_COMPLETION_CODE].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_COMPLETION_CODE].Setup = DetectFtpCompletionCodeSetup;
    sigmatch_table[DETECT_FTP_COMPLETION_CODE].flags =
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;

    DetectAppLayerMultiRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0, DetectFTPCompletionCodeGetData, 2);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_ccode_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
