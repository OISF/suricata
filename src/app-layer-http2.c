/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 * Parser for HTTP2, RFC 7540
 */

#include "suricata-common.h"
#include "stream.h"
#include "conf.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "app-layer-http2.h"
#include "rust.h"

static int HTTP2RegisterPatternsForProtocolDetection(void)
{
    /* Using the 24 bytes pattern makes AppLayerTest09 fail/leak
     * The complete pattern is "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
     */
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_HTTP2,
                                               "PRI * HTTP/2.0\r\n",
                                               16, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    return 0;
}

static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;
static SuricataFileContext sfc = { &sbcfg };

void RegisterHTTP2Parsers(void)
{
    const char *proto_name = "http2";

    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, true)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_HTTP2, proto_name);
        if (HTTP2RegisterPatternsForProtocolDetection() < 0)
            return;

        rs_http2_init(&sfc);
        rs_http2_register_parser();
    }

#ifdef UNITTESTS
    //TODOask HTTP2ParserRegisterTests();
#endif
}

void HTTP2MimicHttp1Request(void *alstate_orig, void *h2s)
{
    htp_tx_t *h1tx = HtpGetTxForH2(alstate_orig);
    if (h2s == NULL || h1tx == NULL) {
        return;
    }
    if (htp_tx_request_method(h1tx) == NULL) {
        // may happen if we only got the reply, not the HTTP1 request
        return;
    }
    // else
    rs_http2_tx_set_method(h2s, bstr_ptr(htp_tx_request_method(h1tx)), bstr_len(htp_tx_request_method(h1tx)));
    if (htp_tx_request_uri(h1tx) != NULL) {
        // A request line without spaces gets interpreted as a request_method
        // and has request_uri=NULL
        rs_http2_tx_set_uri(h2s, bstr_ptr(htp_tx_request_uri(h1tx)), bstr_len(htp_tx_request_uri(h1tx)));
    }
    size_t nbheaders = htp_tx_request_headers_size(h1tx);
    for (size_t i = 0; i < nbheaders; i++) {
        const htp_header_t *h = htp_tx_request_header_index(h1tx, i);
        if (h != NULL) {
            rs_http2_tx_add_header(h2s, htp_header_name_ptr(h), htp_header_name_len(h), htp_header_value_ptr(h), htp_header_value_len(h));
        }
    }
}
