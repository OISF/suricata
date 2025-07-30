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
 * Implements the ftp.reply sticky buffer
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-helper.h"
#include "detect-engine-content-inspection.h"
#include "detect-ftp-reply.h"

#include "app-layer.h"
#include "app-layer-ftp.h"

#include "flow.h"

#include "util-debug.h"

#include "rust.h"

#define KEYWORD_NAME "ftp.reply"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-reply"
#define BUFFER_NAME  "ftp.reply"
#define BUFFER_DESC  "ftp reply"

static int g_ftp_reply_buffer_id = 0;

static int DetectFtpReplySetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_ftp_reply_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) < 0)
        return -1;

    return 0;
}

static bool DetectFTPReplyGetData(DetectEngineThreadCtx *_det_ctx, const void *txv,
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
                *buffer = (const uint8_t *)wrapper->response->response;
                *buffer_len = (uint32_t)wrapper->response->length;
                return true;
            }
            count++;
        }
    }

    *buffer = NULL;
    *buffer_len = 0;
    return false;
}

void DetectFtpReplyRegister(void)
{
    /* ftp.reply sticky buffer */
    sigmatch_table[DETECT_FTP_REPLY].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_REPLY].desc = "sticky buffer to match on the FTP reply buffer";
    sigmatch_table[DETECT_FTP_REPLY].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_REPLY].Setup = DetectFtpReplySetup;
    sigmatch_table[DETECT_FTP_REPLY].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;

    DetectAppLayerMultiRegister(
            BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOCLIENT, 1, DetectFTPReplyGetData, 2);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_reply_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
