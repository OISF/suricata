/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements dce_stub_data keyword
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "queue.h"
#include "stream-tcp-reassemble.h"

#include "detect-dce-stub-data.h"

#include "util-debug.h"

#include "stream-tcp.h"

#include "rust.h"

#define BUFFER_NAME "dce_stub_data"

static int DetectDceStubDataSetup(DetectEngineCtx *, Signature *, const char *);
static int g_dce_stub_data_buffer_id = 0;

static InspectionBuffer *GetSMBData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (!buffer->initialized) {
        uint32_t data_len = 0;
        const uint8_t *data = NULL;
        uint8_t dir = flow_flags & (STREAM_TOSERVER|STREAM_TOCLIENT);
        if (SCSmbTxGetStubData(txv, dir, &data, &data_len) != 1)
            return NULL;
        SCLogDebug("have data!");

        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }
    return buffer;
}

static InspectionBuffer *GetDCEData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (!buffer->initialized) {
        uint32_t data_len = 0;
        const uint8_t *data = NULL;
        uint8_t endianness;

        SCDcerpcGetStubData(txv, &data, &data_len, &endianness, flow_flags);
        if (data == NULL || data_len == 0)
            return NULL;

        if (endianness > 0) {
            buffer->flags = DETECT_CI_FLAGS_DCE_LE;
        } else {
            buffer->flags |= DETECT_CI_FLAGS_DCE_BE;
        }
        InspectionBufferSetupAndApplyTransforms(
                det_ctx, list_id, buffer, data, data_len, transforms);
    }
    return buffer;
}

/**
 * \brief Registers the keyword handlers for the "dce_stub_data" keyword.
 */
void DetectDceStubDataRegister(void)
{
    sigmatch_table[DETECT_DCE_STUB_DATA].name = "dcerpc.stub_data";
    sigmatch_table[DETECT_DCE_STUB_DATA].alias = "dce_stub_data";
    sigmatch_table[DETECT_DCE_STUB_DATA].Setup = DetectDceStubDataSetup;
    sigmatch_table[DETECT_DCE_STUB_DATA].desc = "match on the stub data in a DCERPC packet";
    sigmatch_table[DETECT_DCE_STUB_DATA].url = "/rules/dcerpc-keywords.html#dcerpc-stub-data";
    sigmatch_table[DETECT_DCE_STUB_DATA].flags |= SIGMATCH_NOOPT|SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetSMBData);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetSMBData, ALPROTO_SMB, 0);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetSMBData);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetSMBData, ALPROTO_SMB, 0);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_DCERPC, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetDCEData);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetDCEData, ALPROTO_DCERPC, 0);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_DCERPC, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetDCEData);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, PrefilterGenericMpmRegister,
            GetDCEData, ALPROTO_DCERPC, 0);

    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

/**
 * \brief setups the dce_stub_data list
 *
 * \param de_ctx Pointer to the detection engine context
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules
 * \param arg    Pointer to the string holding the keyword value
 *
 * \retval 0 on success, -1 on failure
 */

static int DetectDceStubDataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
        return -1;
    if (SCDetectBufferSetActiveList(de_ctx, s, g_dce_stub_data_buffer_id) < 0)
        return -1;
    return 0;
}
