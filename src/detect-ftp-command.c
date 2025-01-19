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
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-content.h"

#include "flow.h"

#include "util-debug.h"

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
    if (DetectBufferSetActiveList(de_ctx, s, g_ftp_cmd_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_FTP) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        FTPTransaction *tx = (FTPTransaction *)txv;

        if (tx->command_descriptor->command_name == NULL ||
                tx->command_descriptor->command_length == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer,
                (const uint8_t *)tx->command_descriptor->command_name,
                tx->command_descriptor->command_length);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectFtpCommandRegister(void)
{
    /* ftp.command sticky buffer */
    sigmatch_table[DETECT_FTP_COMMAND].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_COMMAND].desc = "sticky buffer to match on the FTP command buffer";
    sigmatch_table[DETECT_FTP_COMMAND].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_COMMAND].Setup = DetectFtpCommandSetup;
    sigmatch_table[DETECT_FTP_COMMAND].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_FTP, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_cmd_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
