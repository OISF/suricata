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
 * Implements the ftp.dynamic_port sticky buffer
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

#include "detect-ftp-dynamic_port.h"

#define KEYWORD_NAME "ftp.dynamic_port"
#define KEYWORD_DOC  "ftp-keywords.html#ftp-dynamic_port"
#define BUFFER_NAME  "ftp.dynamic_port"
#define BUFFER_DESC  "ftp dynamic_port"

static int g_ftp_dynport_buffer_id = 0;

static int DetectFtpDynamicPortSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_ftp_dynport_buffer_id) < 0)
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

        if (tx->command_descriptor.command_code == FTP_COMMAND_UNKNOWN)
            return NULL;

        if (tx->dyn_port_str == NULL)
            return NULL;

        SCLogDebug("ftp dyn port %s [%d bytes]", tx->dyn_port_str, tx->dyn_port_len);
        InspectionBufferSetupAndApplyTransforms(det_ctx, list_id, buffer,
                (const uint8_t *)tx->dyn_port_str, tx->dyn_port_len, transforms);
    }

    return buffer;
}

void DetectFtpDynamicPortRegister(void)
{
    /* ftp.dynamic_port sticky buffer */
    sigmatch_table[DETECT_FTP_DYNPORT].name = KEYWORD_NAME;
    sigmatch_table[DETECT_FTP_DYNPORT].desc =
            "sticky buffer to match on the FTP dynamic_port buffer";
    sigmatch_table[DETECT_FTP_DYNPORT].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_FTP_DYNPORT].Setup = DetectFtpDynamicPortSetup;
    sigmatch_table[DETECT_FTP_DYNPORT].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_FTP, 1);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_FTP, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_FTP, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ftp_dynport_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    SCLogDebug("registering " BUFFER_NAME " rule option");
}
