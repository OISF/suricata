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
#include "detect-engine-buffer.h"
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
static int g_tls_alpn_buffer_id = 0;

static bool TlsAlpnGetData(DetectEngineThreadCtx *det_ctx, const void *txv, const uint8_t flags,
        uint32_t idx, const uint8_t **buf, uint32_t *buf_len)
{
    SCEnter();

    const SSLState *ssl_state = (SSLState *)txv;
    const SSLStateConnp *connp;
    CStringData d;

    if (flags & STREAM_TOSERVER) {
        connp = &ssl_state->client_connp;
    } else {
        connp = &ssl_state->server_connp;
    }

    if (SCTLSHandshakeGetALPN(connp->hs, idx, &d)) {
        *buf = d.data;
        *buf_len = (uint32_t)d.len;
        return true;
    } else {
        return false;
    }
}

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
    sigmatch_table[DETECT_TLS_ALPN].flags |=
            SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_INFO_MULTI_BUFFER;

    DetectAppLayerMultiRegister("tls.alpn", ALPROTO_TLS, SIG_FLAG_TOSERVER,
            TLS_STATE_CLIENT_HELLO_DONE, TlsAlpnGetData, 2);
    DetectAppLayerMultiRegister(
            "tls.alpn", ALPROTO_TLS, SIG_FLAG_TOCLIENT, TLS_STATE_SERVER_HELLO, TlsAlpnGetData, 2);

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
    if (SCDetectBufferSetActiveList(de_ctx, s, g_tls_alpn_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_TLS) < 0)
        return -1;

    return 0;
}
