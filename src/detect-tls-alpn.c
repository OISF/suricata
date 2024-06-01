/* Copyright (C) 2024 Open Information Security Foundation
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
 * \author Victor Julien <vjulien@oisf.net>
 *
 * Implements support for tls.alpn keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"
#include "detect-content.h"
#include "detect-tls-alpn.h"
#include "detect-engine-uint.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"
#include "util-profiling.h"

static int DetectTlsAlpnSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *TlsAlpnGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flags, void *txv, int list_id,
        uint32_t index);

static int g_tls_alpn_buffer_id = 0;

/**
 * \brief Registration function for keyword: tls.alpn
 */
void DetectTlsAlpnRegister(void)
{
    sigmatch_table[DETECT_TLS_ALPN].name = "tls.alpn";
    sigmatch_table[DETECT_TLS_ALPN].desc = "sticky buffer to match the TLS ALPN buffer";
    sigmatch_table[DETECT_TLS_ALPN].url = "/rules/tls-keywords.html#tls-alpn";
    sigmatch_table[DETECT_TLS_ALPN].Setup = DetectTlsAlpnSetup;
    sigmatch_table[DETECT_TLS_ALPN].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_TLS_ALPN].flags |= SIGMATCH_INFO_STICKY_BUFFER;

    DetectAppLayerMultiRegister("tls.alpn", ALPROTO_TLS, SIG_FLAG_TOSERVER, 0, TlsAlpnGetData, 2,
            TLS_STATE_IN_PROGRESS);
    DetectAppLayerMultiRegister(
            "tls.alpn", ALPROTO_TLS, SIG_FLAG_TOCLIENT, 0, TlsAlpnGetData, 2, TLS_STATE_CERT_READY);

    DetectBufferTypeSetDescriptionByName("tls.alpn", "TLS APLN");

    DetectBufferTypeSupportsMultiInstance("tls.alpn");

    g_tls_alpn_buffer_id = DetectBufferTypeGetByName("tls.alpn");
}

/**
 * \brief This function setup the tls.alpn sticky buffer keyword
 *
 * \param de_ctx Pointer to the Detect Engine Context
 * \param s      Pointer to the Signature to which the keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
static int DetectTlsAlpnSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_tls_alpn_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}

static InspectionBuffer *TlsAlpnGetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *f, uint8_t flags, void *txv, int list_id,
        uint32_t idx)
{
    SCEnter();
    InspectionBuffer *buffer = InspectionBufferMultipleForListGet(det_ctx, list_id, idx);
    if (buffer == NULL || buffer->initialized)
        return buffer;

    const SSLState *ssl_state = (SSLState *)f->alstate;
    const SSLStateConnp *connp;

    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (TAILQ_EMPTY(&connp->alpns)) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    SSLAlpns *a;
    if (idx == 0) {
        a = TAILQ_FIRST(&connp->alpns);
    } else {
        // TODO optimize ?
        a = TAILQ_FIRST(&connp->alpns);
        for (uint32_t i = 0; i < idx; i++) {
            a = TAILQ_NEXT(a, next);
        }
    }
    if (a == NULL) {
        InspectionBufferSetupMultiEmpty(buffer);
        return NULL;
    }

    InspectionBufferSetupMulti(buffer, transforms, a->alpn, a->size);
    buffer->flags = DETECT_CI_FLAGS_SINGLE;

    SCReturnPtr(buffer, "InspectionBuffer");
}
