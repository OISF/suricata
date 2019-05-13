/* Copyright (C) 2019 Open Information Security Foundation
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
 * Implements support for tls.cert keyword.
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
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-tls-cert.h"

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

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsCertSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTlsCertRegisterTests(void);
#endif
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t _flow_flags,
        void *txv, const int list_id);
static int g_tls_cert_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.cert
 */
void DetectTlsCertRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERT].name = "tls.cert";
    sigmatch_table[DETECT_AL_TLS_CERT].desc = "content modifier to match the TLS certificate buffer";
    sigmatch_table[DETECT_AL_TLS_CERT].url = DOC_URL DOC_VERSION "/rules/tls-keywords.html#tls.cert";
    sigmatch_table[DETECT_AL_TLS_CERT].Setup = DetectTlsCertSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TLS_CERT].RegisterTests = DetectTlsCertRegisterTests;
#endif
    sigmatch_table[DETECT_AL_TLS_CERT].flags |= SIGMATCH_NOOPT;

    DetectAppLayerInspectEngineRegister2("tls.cert", ALPROTO_TLS,
            SIG_FLAG_TOCLIENT, TLS_STATE_CERT_READY,
            DetectEngineInspectBufferGeneric, GetData);

    DetectAppLayerMpmRegister2("tls.cert", SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetData, ALPROTO_TLS,
            TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.cert", "TLS certificate");

    g_tls_cert_buffer_id = DetectBufferTypeGetByName("tls.cert");
}

/**
 * \brief This function setup the tls.cert modifier keyword
 *
 * \param de_ctx Pointer to the Detect Engine Context
 * \param s      Pointer to the Signature to which the keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsCertSetup(DetectEngineCtx *de_ctx, Signature *s,
                              const char *str)
{
    if (DetectBufferSetActiveList(s, g_tls_cert_buffer_id) < 0)
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

        if (TAILQ_EMPTY(&ssl_state->server_connp.certs)) {
            return NULL;
        }

        const SSLCertsChain *cert = TAILQ_FIRST(&ssl_state->server_connp.certs);
        if (cert == NULL) {
            return NULL;
        }

        InspectionBufferSetup(buffer, cert->cert_data, cert->cert_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-tls-cert.c"
#endif
