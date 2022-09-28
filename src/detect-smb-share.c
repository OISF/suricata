/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"

#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "detect-smb-share.h"
#include "rust.h"

#define BUFFER_NAME "smb_named_pipe"
#define KEYWORD_NAME "smb.named_pipe"
#define KEYWORD_NAME_LEGACY BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_NAMED_PIPE

static int g_smb_named_pipe_buffer_id = 0;

static int DetectSmbNamedPipeSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_smb_named_pipe_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetNamedPipeData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_smb_tx_get_named_pipe(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbNamedPipeRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbNamedPipeSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB named pipe in tree connect";

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetNamedPipeData,
            ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetNamedPipeData);

    g_smb_named_pipe_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

#undef BUFFER_NAME
#undef KEYWORD_NAME
#undef KEYWORD_NAME_LEGACY
#undef KEYWORD_ID

#define BUFFER_NAME "smb_share"
#define KEYWORD_NAME "smb.share"
#define KEYWORD_NAME_LEGACY BUFFER_NAME
#define KEYWORD_ID DETECT_SMB_SHARE

static int g_smb_share_buffer_id = 0;

static int DetectSmbShareSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_smb_share_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SMB) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetShareData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        uint32_t b_len = 0;
        const uint8_t *b = NULL;

        if (rs_smb_tx_get_share(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }
    return buffer;
}

void DetectSmbShareRegister(void)
{
    sigmatch_table[KEYWORD_ID].name = KEYWORD_NAME;
    sigmatch_table[KEYWORD_ID].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[KEYWORD_ID].Setup = DetectSmbShareSetup;
    sigmatch_table[KEYWORD_ID].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;
    sigmatch_table[KEYWORD_ID].desc = "sticky buffer to match on SMB share name in tree connect";

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetShareData,
            ALPROTO_SMB, 1);

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetShareData);

    g_smb_share_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}
