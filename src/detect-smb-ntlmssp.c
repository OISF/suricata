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

/**
 * \file
 *
 * \author Eric Leblond <el@stamus-networks.com>
 *
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "detect-smb-ntlmssp.h"
#include "rust.h"

#define BUFFER_NAME         "smb_ntlmssp_user"
#define KEYWORD_NAME        "smb.ntlmssp_user"
#define KEYWORD_NAME_LEGACY BUFFER_NAME
#define KEYWORD_ID          DETECT_SMB_NTLMSSP_USER

static int g_smb_nltmssp_user_buffer_id = 0;

static int DetectSmbNtlmsspUserSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_smb_nltmssp_user_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetNtlmsspUserData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_smb_tx_get_ntlmssp_user(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbNtlmsspUserRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNtlmsspUserSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB ntlmssp user in session setup";

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetNtlmsspUserData, ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetNtlmsspUserData);

    g_smb_nltmssp_user_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
