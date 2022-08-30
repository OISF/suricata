/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * \author Frank Honza <frank.honza@dcso.de>
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-urilen.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

#include "app-layer.h"
#include "app-layer-parser.h"

#include "detect-ike-spi.h"
#include "stream-tcp.h"

#include "rust.h"
#include "app-layer-ike.h"
#include "rust-bindings.h"

#define KEYWORD_NAME_INITIATOR "ike.init_spi"
#define KEYWORD_DOC_INITIATOR  "ike-keywords.html#ike-init_spi";
#define BUFFER_NAME_INITIATOR  "ike.init_spi"
#define BUFFER_DESC_INITIATOR  "ike init spi"

#define KEYWORD_NAME_RESPONDER "ike.resp_spi"
#define KEYWORD_DOC_RESPONDER  "ike-keywords.html#ike-resp_spi";
#define BUFFER_NAME_RESPONDER  "ike.resp_spi"
#define BUFFER_DESC_RESPONDER  "ike resp spi"

static int g_buffer_initiator_id = 0;
static int g_buffer_responder_id = 0;

static int DetectSpiInitiatorSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_initiator_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;

    return 0;
}

static int DetectSpiResponderSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_buffer_responder_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_IKE) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetInitiatorData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_ike_state_get_spi_initiator(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static InspectionBuffer *GetResponderData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f, const uint8_t _flow_flags, void *txv,
        const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const uint8_t *b = NULL;
        uint32_t b_len = 0;

        if (rs_ike_state_get_spi_responder(txv, &b, &b_len) != 1)
            return NULL;
        if (b == NULL || b_len == 0)
            return NULL;

        InspectionBufferSetup(det_ctx, list_id, buffer, b, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

void DetectIkeSpiRegister(void)
{
    // register initiator
    sigmatch_table[DETECT_AL_IKE_SPI_INITIATOR].name = KEYWORD_NAME_INITIATOR;
    sigmatch_table[DETECT_AL_IKE_SPI_INITIATOR].url =
            "/rules/" KEYWORD_DOC_INITIATOR sigmatch_table[DETECT_AL_IKE_SPI_INITIATOR].desc =
                    "sticky buffer to match on the IKE spi initiator";
    sigmatch_table[DETECT_AL_IKE_SPI_INITIATOR].Setup = DetectSpiInitiatorSetup;
    sigmatch_table[DETECT_AL_IKE_SPI_INITIATOR].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_INITIATOR, ALPROTO_IKE, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectBufferGeneric, GetInitiatorData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_INITIATOR, SIG_FLAG_TOSERVER, 1,
            PrefilterGenericMpmRegister, GetInitiatorData, ALPROTO_IKE, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_INITIATOR, BUFFER_DESC_INITIATOR);

    g_buffer_initiator_id = DetectBufferTypeGetByName(BUFFER_NAME_INITIATOR);
    SCLogDebug("registering " BUFFER_NAME_INITIATOR " rule option");

    // register responder
    sigmatch_table[DETECT_AL_IKE_SPI_RESPONDER].name = KEYWORD_NAME_RESPONDER;
    sigmatch_table[DETECT_AL_IKE_SPI_RESPONDER].url =
            "/rules/" KEYWORD_DOC_RESPONDER sigmatch_table[DETECT_AL_IKE_SPI_RESPONDER].desc =
                    "sticky buffer to match on the IKE spi responder";
    sigmatch_table[DETECT_AL_IKE_SPI_RESPONDER].Setup = DetectSpiResponderSetup;
    sigmatch_table[DETECT_AL_IKE_SPI_RESPONDER].flags |=
            SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME_RESPONDER, ALPROTO_IKE, SIG_FLAG_TOCLIENT, 1,
            DetectEngineInspectBufferGeneric, GetResponderData);

    DetectAppLayerMpmRegister2(BUFFER_NAME_RESPONDER, SIG_FLAG_TOCLIENT, 1,
            PrefilterGenericMpmRegister, GetResponderData, ALPROTO_IKE, 1);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME_RESPONDER, BUFFER_DESC_RESPONDER);

    g_buffer_responder_id = DetectBufferTypeGetByName(BUFFER_NAME_RESPONDER);
    SCLogDebug("registering " BUFFER_NAME_RESPONDER " rule option");
}
