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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Tests for the hsbd with swf files
 */

#include "../suricata-common.h"
#include "../decode.h"
#include "../flow.h"
#include "../detect.h"

static int DetectEngineHttpServerBodyFileDataTest19(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";
    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();
    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest20(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: no\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest21(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: deflate\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest22(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: lzma\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest23(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x01, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"CWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest24(void)
{
#ifdef HAVE_LIBLZMA
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe,
        0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37,
        0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0,
        0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59, 0x56, 0x06, 0x08, 0xe9,
        0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);


    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
#else
    PASS;
#endif /* HAVE_LIBLZMA */
}

static int DetectEngineHttpServerBodyFileDataTest25(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: no\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20, 0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19,
        0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05,
        0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2,
        0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0, 0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59,
        0x56, 0x06, 0x08, 0xe9, 0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest26(void)
{
#ifdef HAVE_LIBLZMA
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: lzma\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '1', '0', '3', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61, 0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe,
        0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b, 0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37,
        0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1, 0xfc, 0x9e, 0x64, 0xda, 0x6c, 0x11, 0x21, 0x33, 0xed, 0xa0,
        0x0e, 0x76, 0x70, 0xa0, 0xcd, 0x98, 0x2e, 0x76, 0x80, 0xf0, 0xe0, 0x59, 0x56, 0x06, 0x08, 0xe9,
        0xca, 0xeb, 0xa2, 0xc6, 0xdb, 0x5a, 0x86
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
#else
    PASS;
#endif /* HAVE_LIBLZMA */
}

static int DetectEngineHttpServerBodyFileDataTest27(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: deflate\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x17, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61,
        0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b,
        0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest28(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 0\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();

    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','o','c','t','e','t','-','s','t','r','e','a','m', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x5a, 0x57, 0x53, 0x01, 0x5c, 0x24, 0x00, 0x00, 0xb7, 0x21, 0x00, 0x00, 0x5d, 0x00, 0x00, 0x20,
        0x00, 0x00, 0x3b, 0xff, 0xfc, 0x8e, 0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85,
        0x19, 0xfa, 0xdf, 0xe7, 0x66, 0x08, 0xa0, 0x3d, 0x3e, 0x85, 0xf5, 0x75, 0x6f, 0xd0, 0x7e, 0x61,
        0x35, 0x1b, 0x1a, 0x8b, 0x16, 0x4d, 0xdf, 0x05, 0x32, 0xfe, 0xa4, 0x4c, 0x46, 0x49, 0xb7, 0x7b,
        0x6b, 0x75, 0xf9, 0x2b, 0x5c, 0x37, 0x29, 0x0b, 0x91, 0x37, 0x01, 0x37, 0x0e, 0xe9, 0xf2, 0xe1,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"ZWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static int DetectEngineHttpServerBodyFileDataTest29(void)
{
    char input[] = "\
%YAML 1.1\n\
---\n\
libhtp:\n\
\n\
  default-config:\n\
\n\
    swf-decompression:\n\
      enabled: yes\n\
      type: both\n\
      compress-depth: 1000\n\
      decompress-depth: 0\n\
";

    ConfCreateContextBackup();
    ConfInit();
    HtpConfigCreateBackup();
    ConfYamlLoadString(input, strlen(input));
    HTPConfigure();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    ThreadVars th_v;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    HtpState *http_state = NULL;
    Flow f;
    uint8_t http_buf1[] =
        "GET /file.swf HTTP/1.0\r\n"
        "Host: www.openinfosecfoundation.org\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7\r\n"
        "\r\n";
    uint32_t http_len1 = sizeof(http_buf1) - 1;
    uint8_t http_buf2[] = {
        'H', 'T', 'T', 'P', '/', '1', '.', '1', ' ', '2', '0', '0', 'o', 'k', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'L', 'e', 'n', 'g', 't', 'h', ':', ' ', '8', '0', 0x0d, 0x0a,
        'C', 'o', 'n', 't', 'e', 'n', 't', '-', 'T', 'y', 'p', 'e', ':', ' ',
        'a','p','p','l','i','c','a','t','i','o','n','/','x','-','s','h','o','c','k','w','a','v','e','-','f','l','a','s','h', 0x0d, 0x0a,
        0x0d, 0x0a,
        0x43, 0x57, 0x53, 0x0a, 0xcb, 0x6c, 0x00, 0x00, 0x78, 0xda, 0xad, 0xbd, 0x07, 0x98, 0x55, 0x55,
        0x9e, 0xee, 0xbd, 0x4f, 0xd8, 0xb5, 0x4e, 0x15, 0xc1, 0xc2, 0x80, 0x28, 0x86, 0xd2, 0x2e, 0x5a,
        0xdb, 0x46, 0xd9, 0x39, 0x38, 0xdd, 0x4e, 0x1b, 0xa8, 0x56, 0x5b, 0xc5, 0x6b, 0xe8, 0x76, 0xfa,
        0x0e, 0xc2, 0x8e, 0x50, 0x76, 0x51, 0xc5, 0x54, 0x15, 0x88, 0x73, 0xc3, 0xd0, 0x88, 0x39, 0x81,
        0x98, 0x63, 0x91, 0x93, 0x8a, 0x82, 0x89, 0x60, 0x00, 0xcc, 0xb1, 0x00, 0x01, 0x73, 0xce, 0x39,
    };
    uint32_t http_len2 = sizeof(http_buf2);
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    FAIL_IF_NULL(alp_tctx);

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOCLIENT;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any "
                               "(flow:established,from_server; "
                               "file_data; content:\"FWS\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    int r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_len1);
    FAIL_IF(r != 0);

    http_state = f.alstate;
    FAIL_IF_NULL(http_state);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);

    FAIL_IF((PacketAlertCheck(p1, 1)));

    r = AppLayerParserParse(&th_v, alp_tctx, &f, ALPROTO_HTTP, STREAM_TOCLIENT, http_buf2, http_len2);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF(!(PacketAlertCheck(p2, 1)));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HTPFreeConfig();
    HtpConfigRestoreBackup();
    ConfRestoreContextBackup();

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    PASS;
}

static void DetectEngineHttpServerBodyFileRegisterTests(void)
{
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest19",
                  DetectEngineHttpServerBodyFileDataTest19);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest20",
                  DetectEngineHttpServerBodyFileDataTest20);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest21",
                  DetectEngineHttpServerBodyFileDataTest21);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest22",
                  DetectEngineHttpServerBodyFileDataTest22);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest23",
                  DetectEngineHttpServerBodyFileDataTest23);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest24",
                  DetectEngineHttpServerBodyFileDataTest24);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest25",
                  DetectEngineHttpServerBodyFileDataTest25);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest26",
                  DetectEngineHttpServerBodyFileDataTest26);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest27",
                  DetectEngineHttpServerBodyFileDataTest27);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest28",
                  DetectEngineHttpServerBodyFileDataTest28);
    UtRegisterTest("DetectEngineHttpServerBodyFileDataTest29",
                  DetectEngineHttpServerBodyFileDataTest29);
}
