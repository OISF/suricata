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

#include "app-layer-http2.h"
#include "rust.h"

static int HTTP2RegisterPatternsForProtocolDetection(void)
{
    //TODO is this too restrictive and can be evaded ?
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_HTTP2,
                                               "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n",
                                               24, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    return 0;
}

void RegisterHTTP2Parsers(void)
{
    const char *proto_name = "http2";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_HTTP2, proto_name);
        if (HTTP2RegisterPatternsForProtocolDetection() < 0)
            return;
    }

    rs_http2_register_parser();

#ifdef UNITTESTS
    //TODO tests
#endif
}
