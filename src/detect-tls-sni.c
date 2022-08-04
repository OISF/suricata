/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements support for tls.sni keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "detect-engine-prefilter.h"
#include "detect-tls-sni.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsSniSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsSniRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
       const DetectEngineTransforms *transforms,
       Flow *f, const uint8_t flow_flags,
       void *txv, const int list_id);
static int g_tls_sni_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.sni
 */
void DetectTlsSniRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_SNI].name = "tls.sni";
    sigmatch_table[DETECT_AL_TLS_SNI].alias = "tls_sni";
    sigmatch_table[DETECT_AL_TLS_SNI].desc = "sticky buffer to match specifically and only on the TLS SNI buffer";
    sigmatch_table[DETECT_AL_TLS_SNI].url = "/rules/tls-keywords.html#tls-sni";
    sigmatch_table[DETECT_AL_TLS_SNI].Setup = DetectTlsSniSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_SNI].RegisterTests = DetectTlsSniRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_SNI].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_SNI].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerInspectEngineRegister2("tls.sni", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("tls.sni", SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS, 0);

    DetectBufferTypeSetDescriptionByName("tls.sni",
            "TLS Server Name Indication (SNI) extension");

    g_tls_sni_buffer_id = DetectBufferTypeGetByName("tls.sni");
}


/**
 * \brief this function setup the tls.sni modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 */
static int DetectTlsSniSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_sni_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const SSLState *ssl_state = (SSLState *)f->alstate;

        if (ssl_state->client_connp.sni == NULL) {
            return NULL;
        }

        const uint32_t data_len = strlen(ssl_state->client_connp.sni);
        const uint8_t *data = (uint8_t *)ssl_state->client_connp.sni;

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-tls-sni.c"
#endif
