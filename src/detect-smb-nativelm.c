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
#include "rust.h"
#include "detect-smb-nativelm.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-parse.h"

static int g_buffer_id = 0;

static int DetectSMBNativelmSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) != 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, const uint8_t flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t data_len = 0;
        const uint8_t *data = NULL;

        rs_smb_tx_get_nativelm(txv, &data, &data_len, flow_flags);
        if (data == NULL || data_len == 0) {
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectSMBNativelmRegister(void)
{
    sigmatch_table[DETECT_AL_SMB_NATIVELM].name = "smb.nativelm";
    sigmatch_table[DETECT_AL_SMB_NATIVELM].desc =
            "SMB content modifier to match on the SMB native_lm";
    sigmatch_table[DETECT_AL_SMB_NATIVELM].Setup = DetectSMBNativelmSetup;

    sigmatch_table[DETECT_AL_SMB_NATIVELM].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    /* register inspect engines */
    DetectAppLayerInspectEngineRegister2("smb.nativelm", ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("smb.nativelm", SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_SMB, 0);
    DetectAppLayerInspectEngineRegister2("smb.nativelm", ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerMpmRegister2("smb.nativelm", SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetData, ALPROTO_SMB, 0);

    DetectBufferTypeSetDescriptionByName("smb.nativelm", "SMB native_lm");

    g_buffer_id = DetectBufferTypeGetByName("smb.nativelm");
}
