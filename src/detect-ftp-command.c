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
 * Implements the ftp.command sticky buffer
 *
 */

#include "suricata-common.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-helper.h"

#include "flow.h"

#include "app-layer.h"
#include "app-layer-ftp.h"

#include "detect-ftp-command.h"

#define KEYWORD_NAME "ftp.command"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-command"
#define BUFFER_NAME  "ftp.command"
#define BUFFER_DESC  "ftp command"

static int g_ftp_cmd_buffer_id = 0;

static int DetectFtpCommandSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_ftp_cmd_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_FTP) < 0)
        return -1;

    return 0;
}

static bool DetectFTPCommandGetData(
        const void *txv, const uint8_t _flow_flags, const uint8_t **buffer, uint32_t *buffer_len)
{
    FTPTransaction *tx = (FTPTransaction *)txv;

    if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN)
        return false;

    uint8_t b_len = 0;
    if (SCGetFtpCommandInfo(
                tx->command_descriptor.command_index, (const char **)buffer, NULL, &b_len)) {
        *buffer_len = b_len;
        return true;
    } else {
        return false;
    }
}

void DetectFtpCommandRegister(void)
{
    /* ftp.command sticky buffer */
    sigmatch_table[DETECT_FTP_COMMAND].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_COMMAND].desc = "sticky buffer to match on the FTP command buffer";
    sigmatch_table[DETECT_FTP_COMMAND].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_COMMAND].Setup = DetectFtpCommandSetup;
    sigmatch_table[DETECT_FTP_COMMAND].flags |= SIGMATCH_NOOPT;

    g_ftp_cmd_buffer_id = SCDetectHelperBufferMpmRegister(
            BUFFER_NAME, BUFFER_DESC, ALPROTO_FTP, STREAM_TOSERVER, DetectFTPCommandGetData);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
