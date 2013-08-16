/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smtp.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-app-layer-event.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "decode-events.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"


int DetectAppLayerEventPktMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                Packet *p, Signature *s, SigMatch *m);
int DetectAppLayerEventAppMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *,
                                uint8_t, void *, Signature *, SigMatch *);
int DetectAppLayerEventSetup(DetectEngineCtx *, Signature *, char *);
void DetectAppLayerEventRegisterTests(void);
void DetectAppLayerEventFree(void *);

/**
 * \brief Registers the keyword handlers for the "app-layer-event" keyword.
 */
void DetectAppLayerEventRegister(void)
{
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].name = "app-layer-event";
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Match =
        DetectAppLayerEventPktMatch;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].AppLayerMatch =
        DetectAppLayerEventAppMatch;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Setup = DetectAppLayerEventSetup;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].Free = DetectAppLayerEventFree;
    sigmatch_table[DETECT_AL_APP_LAYER_EVENT].RegisterTests =
        DetectAppLayerEventRegisterTests;

    return;
}


int DetectAppLayerEventPktMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                Packet *p, Signature *s, SigMatch *m)
{
    DetectAppLayerEventData *aled = (DetectAppLayerEventData *)m->ctx;

    return AppLayerDecoderEventsIsEventSet(p->app_layer_events,
                                           aled->event_id);
}

int DetectAppLayerEventAppMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                                Flow *f, uint8_t flags, void *state, Signature *s,
                                SigMatch *m)
{
    SCEnter();
    AppLayerDecoderEvents *decoder_events = NULL;
    int r = 0;
    uint64_t tx_id = 0, max_id;
    DetectAppLayerEventData *aled = (DetectAppLayerEventData *)m->ctx;

    FLOWLOCK_RDLOCK(f);

    /* inspect TX events first if we need to */
    if (AppLayerProtoIsTxEventAware(f->alproto)) {
        SCLogDebug("proto is AppLayerProtoIsTxEventAware true");

        tx_id = AppLayerTransactionGetInspectId(f, flags);
        max_id = AppLayerGetTxCnt(f->alproto, f->alstate);

        for (; tx_id < max_id; tx_id++) {
            decoder_events = AppLayerGetEventsFromFlowByTx(f, tx_id);
            if (decoder_events != NULL &&
                    AppLayerDecoderEventsIsEventSet(decoder_events, aled->event_id)) {
                r = 1;
                break;
            }
        }
    }

    if (r == 0) {
        decoder_events = AppLayerGetDecoderEventsForFlow(f);
        if (decoder_events != NULL &&
                AppLayerDecoderEventsIsEventSet(decoder_events, aled->event_id)) {
            r = 1;
        }
    }

    FLOWLOCK_UNLOCK(f);
    SCReturnInt(r);
}

static DetectAppLayerEventData *DetectAppLayerEventParsePkt(const char *arg,
                                                            AppLayerEventType *event_type)
{
    DetectAppLayerEventData *aled;

    int event_id = 0;
    int r = 0;

    r = AppLayerGetPktEventInfo(arg, &event_id);
    if (r < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword "
                   "supplied with packet based event - \"%s\" that isn't "
                   "supported yet.", arg);
        return NULL;
    }

    aled = SCMalloc(sizeof(DetectAppLayerEventData));
    if (unlikely(aled == NULL))
        return NULL;
    aled->event_id = event_id;
    *event_type = APP_LAYER_EVENT_TYPE_PACKET;

    return aled;
}

static DetectAppLayerEventData *DetectAppLayerEventParseApp(const char *arg,
                                                            AppLayerEventType *event_type)
{
    /* period index */
    DetectAppLayerEventData *aled;

    uint16_t alproto;
    int event_id = 0;

    const char *p_idx;
    char alproto_name[50];
    int r = 0;

    p_idx = strchr(arg, '.');
    /* + 1 for trailing \0 */
    strlcpy(alproto_name, arg, p_idx - arg + 1);

    /* XXX HACK to support "dns" we use this trick */
    if (strcasecmp(alproto_name, "dns") == 0)
        strlcpy(alproto_name, "dnsudp", sizeof(alproto_name));

    alproto = AppLayerGetProtoByName(alproto_name);
    if (alproto == ALPROTO_UNKNOWN) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword "
                   "supplied with unknown protocol \"%s\"",
                   alproto_name);
        return NULL;
    }
    r = AppLayerGetEventInfo(alproto, p_idx + 1, &event_id, event_type);
    if (r < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword's "
                   "protocol \"%s\" doesn't have event \"%s\" registered",
                   alproto_name, p_idx + 1);
        return NULL;
    }

    aled = SCMalloc(sizeof(DetectAppLayerEventData));
    if (unlikely(aled == NULL))
        return NULL;
    aled->alproto = alproto;
    aled->event_id = event_id;

    return aled;
}

static DetectAppLayerEventData *DetectAppLayerEventParse(const char *arg,
                                                         AppLayerEventType *event_type)
{
    if (arg == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "app-layer-event keyword supplied "
                   "with no arguments.  This keyword needs an argument.");
        return NULL;
    }

    while (*arg != '\0' && isspace((unsigned char)*arg))
        arg++;

    if (strchr(arg, '.') == NULL) {
        return DetectAppLayerEventParsePkt(arg, event_type);
    } else {
        return DetectAppLayerEventParseApp(arg, event_type);
    }
}

int DetectAppLayerEventSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    DetectAppLayerEventData *data = NULL;
    SigMatch *sm = NULL;
    AppLayerEventType event_type;

    data = DetectAppLayerEventParse(arg, &event_type);
    if (data == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_APP_LAYER_EVENT;
    sm->ctx = (void *)data;

    if (s->alproto != ALPROTO_UNKNOWN) {
        if (s->alproto == ALPROTO_DNS &&
                (data->alproto == ALPROTO_DNS_UDP || data->alproto == ALPROTO_DNS_TCP))
        {
            SCLogDebug("DNS app layer event");
        } else if (s->alproto != data->alproto) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains "
                       "conflicting keywords needing different alprotos");
            goto error;
        }
    } else {
        s->alproto = data->alproto;
    }

    if (event_type == APP_LAYER_EVENT_TYPE_PACKET) {
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    } else {
        SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_AMATCH);
        s->flags |= SIG_FLAG_APPLAYER;
    }

    return 0;

error:
    if (data)
        SCFree(data);
    if (sm) {
        sm->ctx = NULL;
        SigMatchFree(sm);
    }
    return -1;
}

void DetectAppLayerEventFree(void *ptr)
{
    SCFree(ptr);

    return;
}

/**********************************Unittests***********************************/

#ifdef UNITTESTS /* UNITTESTS */

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "app-layer.h"

#define APP_LAYER_EVENT_TEST_MAP_EVENT1 0
#define APP_LAYER_EVENT_TEST_MAP_EVENT2 1
#define APP_LAYER_EVENT_TEST_MAP_EVENT3 2
#define APP_LAYER_EVENT_TEST_MAP_EVENT4 3
#define APP_LAYER_EVENT_TEST_MAP_EVENT5 4
#define APP_LAYER_EVENT_TEST_MAP_EVENT6 5

SCEnumCharMap app_layer_event_test_map[ ] = {
    { "event1", APP_LAYER_EVENT_TEST_MAP_EVENT1 },
    { "event2", APP_LAYER_EVENT_TEST_MAP_EVENT2 },
    { "event3", APP_LAYER_EVENT_TEST_MAP_EVENT3 },
    { "event4", APP_LAYER_EVENT_TEST_MAP_EVENT4 },
    { "event5", APP_LAYER_EVENT_TEST_MAP_EVENT5 },
    { "event6", APP_LAYER_EVENT_TEST_MAP_EVENT6 },
};

static int DetectAppLayerEventTestGetEventInfo(const char *event_name,
                                               int *event_id,
                                               AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, app_layer_event_test_map);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "app-layer-event's test enum map table.",  event_name);
        /* this should be treated as fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_GENERAL;

    return 0;
}


int DetectAppLayerEventTest01(void)
{
    AppLayerParserBackupAlprotoTable();
    AppLayerRegisterGetEventInfo(ALPROTO_SMTP,
                                 DetectAppLayerEventTestGetEventInfo);

    AppLayerEventType event_type;
    int result = 0;

    DetectAppLayerEventData *aled = DetectAppLayerEventParse("smtp.event1",
                                                             &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT1) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    AppLayerParserRestoreAlprotoTable();
    if (aled != NULL)
        DetectAppLayerEventFree(aled);
    return result;
}

int DetectAppLayerEventTest02(void)
{
    AppLayerParserBackupAlprotoTable();

    AppLayerRegisterGetEventInfo(ALPROTO_SMTP,
                                 DetectAppLayerEventTestGetEventInfo);
    AppLayerRegisterGetEventInfo(ALPROTO_HTTP,
                                 DetectAppLayerEventTestGetEventInfo);
    AppLayerRegisterGetEventInfo(ALPROTO_SMB,
                                 DetectAppLayerEventTestGetEventInfo);
    AppLayerRegisterGetEventInfo(ALPROTO_FTP,
                                 DetectAppLayerEventTestGetEventInfo);

    AppLayerEventType event_type;
    int result = 0;

    DetectAppLayerEventData *aled = DetectAppLayerEventParse("smtp.event1",
                                                             &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT1) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("smtp.event4",
                                    &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT4) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("http.event2",
                                    &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_HTTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT2) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("smb.event3",
                                    &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_SMB ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT3) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    aled = DetectAppLayerEventParse("ftp.event5",
                                    &event_type);
    if (aled == NULL)
        goto end;
    if (aled->alproto != ALPROTO_FTP ||
        aled->event_id != APP_LAYER_EVENT_TEST_MAP_EVENT5) {
        printf("test failure.  Holding wrong state\n");
        goto end;
    }

    result = 1;

 end:
    AppLayerParserRestoreAlprotoTable();
    if (aled != NULL)
        DetectAppLayerEventFree(aled);
    return result;
}

int DetectAppLayerEventTest03(void)
{
    int result = 0;
    ThreadVars tv;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    Packet *p = NULL;
    Flow *f = NULL;
    TcpSession ssn;
    TcpStream stream_ts, stream_tc;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t buf_ts[] = "GET /index.html HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100402 Firefox/3.6.3\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-us,en;q=0.5\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Keep-Alive: 115\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    uint8_t buf_tc[] = "HTTP/1.1 200 OK\r\n"
        "Date: Fri, 22 Oct 2010 12:31:08 GMT\r\n"
        "Server: Apache/2.2.15 (Unix) DAV/2\r\n"
        "Last-Modified: Sat, 20 Nov 2004 20:16:24 GMT\r\n"
        "ETag: \"ab8486-2c-3e9564c23b600\"\r\n"
        "Accept-Ranges: bytes\r\n"
        "Content-Length: 44\r\n"
        "Keep-Alive: timeout=5, max=100\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body><h1>It works!</h1></body></html>";

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&stream_ts, 0, sizeof(TcpStream));
    memset(&stream_tc, 0, sizeof(TcpStream));

    ssn.data_first_seen_dir = STREAM_TOSERVER;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(app-layer-event: applayer_mismatch_protocol_both_directions; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    FLOW_INITIALIZE(f);
    f->protoctx = &ssn;
    f->flags |= FLOW_IPV4;

    p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        goto end;
    p->flow = f;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;

    ra_ctx = StreamTcpReassembleInitThreadCtx();
    if (ra_ctx == NULL)
        goto end;
    StreamTcpInitConfig(TRUE);

    p->flowflags = FLOW_PKT_TOSERVER;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_ts, buf_ts,
                              sizeof(buf_ts), p, STREAM_TOSERVER | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_tc, buf_tc,
                              sizeof(buf_tc), p, STREAM_TOCLIENT | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    result = 1;
 end:
    return result;
}

int DetectAppLayerEventTest04(void)
{
    int result = 0;
    ThreadVars tv;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    Packet *p = NULL;
    Flow *f = NULL;
    TcpSession ssn;
    TcpStream stream_ts, stream_tc;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t buf_ts[] = "GET /index.html HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100402 Firefox/3.6.3\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-us,en;q=0.5\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Keep-Alive: 115\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    uint8_t buf_tc[] = "XTTP/1.1 200 OK\r\n"
        "Date: Fri, 22 Oct 2010 12:31:08 GMT\r\n"
        "Server: Apache/2.2.15 (Unix) DAV/2\r\n"
        "Last-Modified: Sat, 20 Nov 2004 20:16:24 GMT\r\n"
        "ETag: \"ab8486-2c-3e9564c23b600\"\r\n"
        "Accept-Ranges: bytes\r\n"
        "Content-Length: 44\r\n"
        "Keep-Alive: timeout=5, max=100\r\n"
        "Connection: Keep-Alive\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html><body><h1>It works!</h1></body></html>";

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&stream_ts, 0, sizeof(TcpStream));
    memset(&stream_tc, 0, sizeof(TcpStream));

    ssn.data_first_seen_dir = STREAM_TOSERVER;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(app-layer-event: applayer_detect_protocol_only_one_direction; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    FLOW_INITIALIZE(f);
    f->protoctx = &ssn;
    f->flags |= FLOW_IPV4;

    p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        goto end;
    p->flow = f;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;

    ra_ctx = StreamTcpReassembleInitThreadCtx();
    if (ra_ctx == NULL)
        goto end;
    StreamTcpInitConfig(TRUE);

    p->flowflags = FLOW_PKT_TOSERVER;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_ts, buf_ts,
                              sizeof(buf_ts), p, STREAM_TOSERVER | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_tc, buf_tc,
                              sizeof(buf_tc), p, STREAM_TOCLIENT | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;
 end:
    return result;
}

int DetectAppLayerEventTest05(void)
{
    int result = 0;
    ThreadVars tv;
    TcpReassemblyThreadCtx *ra_ctx = NULL;
    Packet *p = NULL;
    Flow *f = NULL;
    TcpSession ssn;
    TcpStream stream_ts, stream_tc;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;

    uint8_t buf_ts[] = "GET /index.html HTTP/1.1\r\n"
        "Host: 127.0.0.1\r\n"
        "User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.3) Gecko/20100402 Firefox/3.6.3\r\n"
        "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
        "Accept-Language: en-us,en;q=0.5\r\n"
        "Accept-Encoding: gzip,deflate\r\n"
        "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n"
        "Keep-Alive: 115\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    /* tls */
    uint8_t buf_tc[] = {
        0x16, 0x03, 0x01, 0x00, 0x86, 0x10, 0x00, 0x00,
        0x82, 0x00, 0x80, 0xd3, 0x6f, 0x1f, 0x63, 0x82,
        0x8d, 0x75, 0x77, 0x8c, 0x91, 0xbc, 0xa1, 0x3d,
        0xbb, 0xe1, 0xb5, 0xd3, 0x31, 0x92, 0x59, 0x2b,
        0x2c, 0x43, 0x96, 0xa3, 0xaa, 0x23, 0x92, 0xd0,
        0x91, 0x2a, 0x5e, 0x10, 0x5b, 0xc8, 0xc1, 0xe2,
        0xd3, 0x5c, 0x8b, 0x8c, 0x91, 0x9e, 0xc2, 0xf2,
        0x9c, 0x3c, 0x4f, 0x37, 0x1e, 0x20, 0x5e, 0x33,
        0xd5, 0xf0, 0xd6, 0xaf, 0x89, 0xf5, 0xcc, 0xb2,
        0xcf, 0xc1, 0x60, 0x3a, 0x46, 0xd5, 0x4e, 0x2a,
        0xb6, 0x6a, 0xb9, 0xfc, 0x32, 0x8b, 0xe0, 0x6e,
        0xa0, 0xed, 0x25, 0xa0, 0xa4, 0x82, 0x81, 0x73,
        0x90, 0xbf, 0xb5, 0xde, 0xeb, 0x51, 0x8d, 0xde,
        0x5b, 0x6f, 0x94, 0xee, 0xba, 0xe5, 0x69, 0xfa,
        0x1a, 0x80, 0x30, 0x54, 0xeb, 0x12, 0x01, 0xb9,
        0xfe, 0xbf, 0x82, 0x95, 0x01, 0x7b, 0xb0, 0x97,
        0x14, 0xc2, 0x06, 0x3c, 0x69, 0xfb, 0x1c, 0x66,
        0x47, 0x17, 0xd9, 0x14, 0x03, 0x01, 0x00, 0x01,
        0x01, 0x16, 0x03, 0x01, 0x00, 0x30, 0xf6, 0xbc,
        0x0d, 0x6f, 0xe8, 0xbb, 0xaa, 0xbf, 0x14, 0xeb,
        0x7b, 0xcc, 0x6c, 0x28, 0xb0, 0xfc, 0xa6, 0x01,
        0x2a, 0x97, 0x96, 0x17, 0x5e, 0xe8, 0xb4, 0x4e,
        0x78, 0xc9, 0x04, 0x65, 0x53, 0xb6, 0x93, 0x3d,
        0xeb, 0x44, 0xee, 0x86, 0xf9, 0x80, 0x49, 0x45,
        0x21, 0x34, 0xd1, 0xee, 0xc8, 0x9c,
    };

    memset(&tv, 0, sizeof (ThreadVars));
    memset(&ssn, 0, sizeof(TcpSession));
    memset(&stream_ts, 0, sizeof(TcpStream));
    memset(&stream_tc, 0, sizeof(TcpStream));

    ssn.data_first_seen_dir = STREAM_TOSERVER;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(app-layer-event: applayer_mismatch_protocol_both_directions; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    f = UTHBuildFlow(AF_INET, "1.2.3.4", "1.2.3.5", 200, 220);
    if (f == NULL)
        goto end;
    FLOW_INITIALIZE(f);
    f->protoctx = &ssn;
    f->flags |= FLOW_IPV4;

    p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        goto end;
    p->flow = f;
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->proto = IPPROTO_TCP;

    ra_ctx = StreamTcpReassembleInitThreadCtx();
    if (ra_ctx == NULL)
        goto end;
    StreamTcpInitConfig(TRUE);

    p->flowflags = FLOW_PKT_TOSERVER;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_ts, buf_ts,
                              sizeof(buf_ts), p, STREAM_TOSERVER | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    p->flowflags = FLOW_PKT_TOCLIENT;
    if (AppLayerHandleTCPData(&tv, ra_ctx, f, &ssn, &stream_tc, buf_tc,
                              sizeof(buf_tc), p, STREAM_TOCLIENT | STREAM_START) < 0) {
        printf("AppLayerHandleTCPData failure\n");
        goto end;
    }
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match but should have\n");
        goto end;
    }

    result = 1;
 end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for "app-layer-event" keyword.
 */
void DetectAppLayerEventRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectAppLayerEventTest01", DetectAppLayerEventTest01, 1);
    UtRegisterTest("DetectAppLayerEventTest02", DetectAppLayerEventTest02, 1);
    UtRegisterTest("DetectAppLayerEventTest03", DetectAppLayerEventTest03, 1);
    UtRegisterTest("DetectAppLayerEventTest04", DetectAppLayerEventTest04, 1);
    UtRegisterTest("DetectAppLayerEventTest05", DetectAppLayerEventTest05, 1);
#endif /* UNITTESTS */

    return;
}
