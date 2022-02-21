/* Copyright (C) 2022 Open Information Security Foundation
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

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-share.h"
#include "rust.h"

static int g_smb_filename_buffer_id = 0;

void DetectSmbFilenameRegister(void);

static int DetectSmbFilenameSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_smb_filename_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetFilenameData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_smb_tx_get_filename(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbFilenameRegister(void)
{
    sigmatch_table[DETECT_SMB_FILENAME].name = "smb.filename";
    sigmatch_table[DETECT_SMB_FILENAME].alias = "smb_filename";
    sigmatch_table[DETECT_SMB_FILENAME].Setup = DetectSmbFilenameSetup;
    sigmatch_table[DETECT_SMB_FILENAME].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[DETECT_SMB_FILENAME].desc =
            "sticky buffer to match on SMB filenamenames in create request";

    DetectAppLayerMpmRegister2("smb_filename", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetFilenameData, ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2("smb_filename", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetFilenameData);

    g_smb_filename_buffer_id = DetectBufferTypeGetByName("smb_filename");
}
