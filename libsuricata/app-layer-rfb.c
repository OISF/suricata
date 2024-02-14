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
 * \author Sascha Steinbiss <sascha.steinbiss@dcso.de>
 *
 * RFB (VNC) application layer detector and parser.
 *
 */

#include "suricata-common.h"

#include "util-unittest.h"

#include "app-layer-detect-proto.h"
#include "app-layer-parser.h"
#include "app-layer-rfb.h"

#include "rust.h"

static int RFBRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_RFB,
                                               "RFB ", 4, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_RFB,
                                               "RFB ", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    return 0;
}

void RFBParserRegisterTests(void);

void RegisterRFBParsers(void)
{
    rs_rfb_register_parser();
    if (RFBRegisterPatternsForProtocolDetection() < 0 )
            return;
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_RFB,
        RFBParserRegisterTests);
#endif
}


#ifdef UNITTESTS

#include "stream-tcp.h"
#include "util-unittest-helper.h"

static int RFBParserTest(void)
{
    uint64_t ret[4];
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    StreamTcpInitConfig(true);
    TcpSession ssn;
    memset(&ssn, 0, sizeof(ssn));

    Flow *f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 59001, 5900);
    FAIL_IF_NULL(f);
    f->protoctx = &ssn;
    f->proto = IPPROTO_TCP;
    f->alproto = ALPROTO_RFB;

    static const unsigned char rfb_version_str[12] = {
            0x52, 0x46, 0x42, 0x20, 0x30, 0x30, 0x33, 0x2e, 0x30, 0x30, 0x37, 0x0a
    };

    // the RFB server sending the first handshake message
    int r = AppLayerParserParse(NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOCLIENT | STREAM_START,
            (uint8_t *)rfb_version_str, sizeof(rfb_version_str));
    FAIL_IF_NOT(r == 0);

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOSERVER, (uint8_t *)rfb_version_str, sizeof(rfb_version_str));
    FAIL_IF_NOT(r == 0);

    static const unsigned char security_types[3] = {
            0x02, 0x01, 0x02
    };
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOCLIENT, (uint8_t *)security_types, sizeof(security_types));
    FAIL_IF_NOT(r == 0);

    static const unsigned char type_selection[1] = {
            0x01
    };
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOSERVER, (uint8_t *)type_selection, sizeof(type_selection));
    FAIL_IF_NOT(r == 0);

    static const unsigned char client_init[1] = {
            0x01
    };
    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOSERVER, (uint8_t *)client_init, sizeof(client_init));
    FAIL_IF_NOT(r == 0);

    static const unsigned char server_init[] = {
          0x05, 0x00, 0x03, 0x20, 0x20, 0x18, 0x00, 0x01,
          0x00, 0xff, 0x00, 0xff, 0x00, 0xff, 0x10, 0x08,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1e,
          0x61, 0x6e, 0x65, 0x61, 0x67, 0x6c, 0x65, 0x73,
          0x40, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f,
          0x73, 0x74, 0x2e, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
          0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e
    };

    r = AppLayerParserParse(
            NULL, alp_tctx, f, ALPROTO_RFB, STREAM_TOCLIENT, (uint8_t *)server_init, sizeof(server_init));
    FAIL_IF_NOT(r == 0);

    AppLayerParserTransactionsCleanup(f, STREAM_TOCLIENT);
    UTHAppLayerParserStateGetIds(f->alparser, &ret[0], &ret[1], &ret[2], &ret[3]);
    FAIL_IF_NOT(ret[0] == 1); // inspect_id[0]
    FAIL_IF_NOT(ret[1] == 1); // inspect_id[1]
    FAIL_IF_NOT(ret[2] == 1); // log_id
    FAIL_IF_NOT(ret[3] == 1); // min_id

    AppLayerParserTransactionsCleanup(f, STREAM_TOCLIENT);
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    UTHFreeFlow(f);

    PASS;
}

void RFBParserRegisterTests(void)
{
    UtRegisterTest("RFBParserTest", RFBParserTest);
}

#endif
