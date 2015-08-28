/*
 * Copyright (C) 2014 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Kevin Wong <kwong@solananetworks.com>
 *
 * App-layer parser for ENIP protocol
 *
 */

#include "suricata-common.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-enum.h"
#include "util-mem.h"
#include "util-misc.h"

#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-enip.h"
#include "app-layer-enip-common.h"

#include "app-layer-detect-proto.h"

#include "conf.h"
#include "decode.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "pkt-var.h"
#include "util-profiling.h"

/** \brief get value for 'complete' status in ENIP
 *
 *  For ENIP we use a simple bool.
 */
int ENIPGetAlstateProgress(void *tx, uint8_t direction)
{

    printf("ENIPGetAlstateProgress direction %d", direction);

    return 1;
}

/** \brief get value for 'complete' status in ENIP
 *
 *  For ENIP we use a simple bool.
 */
int ENIPGetAlstateProgressCompletionStatus(uint8_t direction)
{
    printf("ENIPGetAlstateProgressCompletionStatus direction %d", direction);

    return 1;
}

/** \brief Allocate enip state
 *
 *  return state
 */
void *ENIPStateAlloc(void)
{
    void *s = SCMalloc(sizeof(ENIPState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(ENIPState));

    ENIPState *enip_state = (ENIPState *) s;

    TAILQ_INIT(&enip_state->tx_list);
    return s;
}

/** \internal
 *  \brief Free a ENIP TX
 *  \param tx ENIP TX to free */
static void ENIPTransactionFree(ENIPTransaction *tx, ENIPState *state)
{
    SCEnter();

    CIPServiceEntry *svc = NULL;
    while ((svc = TAILQ_FIRST(&tx->service_list)))
    {
        TAILQ_REMOVE(&tx->service_list, svc, next);

        SegmentEntry *seg = NULL;
        while ((seg = TAILQ_FIRST(&svc->segment_list)))
        {
            TAILQ_REMOVE(&svc->segment_list, seg, next);
            SCFree(seg);
        }

        AttributeEntry *attr = NULL;
        while ((attr = TAILQ_FIRST(&svc->attrib_list)))
        {
            TAILQ_REMOVE(&svc->attrib_list, attr, next);
            SCFree(attr);
        }

        SCFree(svc);
    }

    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    if (tx->de_state != NULL)
    {
        DetectEngineStateFree(tx->de_state);

        state->tx_with_detect_state_cnt--;
    }

    if (state->iter == tx)
        state->iter = NULL;

    SCFree(tx);
    SCReturn;
}

/** \brief Free enip state
 *
 */
void ENIPStateFree(void *s)
{
    SCEnter();
    if (s)
    {
        ENIPState *enip_state = (ENIPState *) s;

        ENIPTransaction *tx = NULL;
        while ((tx = TAILQ_FIRST(&enip_state->tx_list)))
        {
            TAILQ_REMOVE(&enip_state->tx_list, tx, next);
            ENIPTransactionFree(tx, enip_state);
        }

        if (enip_state->buffer != NULL)
        {
            SCFree(enip_state->buffer);
        }

        SCFree(s);
    }
    SCReturn;
}

/** \internal
 *  \brief Allocate a ENIP TX
 *  \retval tx or NULL */
static ENIPTransaction *ENIPTransactionAlloc(ENIPState *state,
        const uint16_t tx_id)
{

    ENIPTransaction *tx = (ENIPTransaction *) SCCalloc(1,
            sizeof(ENIPTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    memset(tx, 0x00, sizeof(ENIPTransaction));
    TAILQ_INIT(&tx->service_list);

    tx->tx_id = tx_id;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;

}

/**
 *  \brief enip transaction cleanup callback
 */
void ENIPStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();

    ENIPState *enip_state = state;
    ENIPTransaction *tx = NULL;

    TAILQ_FOREACH(tx, &enip_state->tx_list, next)
    {

        if ((tx_id+1) < tx->tx_num)
        break;
        else if ((tx_id+1) > tx->tx_num)
        continue;

        if (tx == enip_state->curr)
        enip_state->curr = NULL;

        if (tx->decoder_events != NULL)
        {
            if (tx->decoder_events->cnt <= enip_state->events)
            enip_state->events -= tx->decoder_events->cnt;
            else
            enip_state->events = 0;
        }

        TAILQ_REMOVE(&enip_state->tx_list, tx, next);
        ENIPTransactionFree(tx, state);
        break;
    }
    SCReturn;
}

/** \internal
 *
 * \brief This function is called to retrieve a ENIP
 *
 * \param state     ENIP state structure for the parser
 * \param input     Input line of the command
 * \param input_len Length of the request
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int ENIPParse(Flow *f, void *state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, void *local_data)
{
    SCEnter();
    ENIPState *enip = (ENIPState *) state;
    ENIPTransaction *tx;
    int ret = 0;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate,
            APP_LAYER_PARSER_EOF))
    {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0)
    {
        SCReturnInt(-1);
    }

    while (input_len > 0)
    {
        SCLogDebug("ENIPParse input_len %d\n", input_len);

        tx = ENIPTransactionAlloc(enip, enip->transaction_max);

        if (tx == NULL)
            SCReturnInt(0);
        enip->transaction_max++;

        ret = DecodeENIPPDU(input, input_len, tx);
        uint32_t pkt_len = tx->header.length + sizeof(ENIPEncapHdr);
        //printf("ENIPParse packet len %d\n", pkt_len);
        if (pkt_len > input_len)
        {
            SCLogDebug("Invalid packet length \n");
            break;
        }

        input += pkt_len;
        input_len -= pkt_len;
        //SCLogDebug("remaining %d\n", input_len);

        if (input_len < sizeof(ENIPEncapHdr))
        {
            //SCLogDebug("Not enough data\n"); //not enough data for ENIP
            break;
        }

    }

    return 1;
}

static uint16_t ENIPProbingParser(uint8_t *input, uint32_t input_len,
        uint32_t *offset)
{
    if (input_len < sizeof(ENIPEncapHdr))
    {
        SCLogDebug("Length too small to be a ENIP header.\n");
        return ALPROTO_UNKNOWN;
    }

    return ALPROTO_ENIP;
}

/**
 * \brief Function to register the ENIP protocol parsers and other functions
 */
void RegisterENIPUDPParsers(void)
{
    SCEnter();
    char *proto_name = "enip";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("udp", proto_name))
    {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_ENIP, proto_name);

        if (RunmodeIsUnittests())
        {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser);

            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT, ENIPProbingParser);

        } else
        {

            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr),
                    ENIPProbingParser))
            {
                SCLogDebug(
                        "no ENIP UDP config found enabling ENIP detection on port 44818.");

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOSERVER,
                        ENIPProbingParser);

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT,
                        ENIPProbingParser);

            }
        }

    } else
    {
        printf("Protocol detection and parser disabled for %s protocol.",
                proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("udp", proto_name))
    {

        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_ENIP,
                STREAM_TOSERVER, ENIPParse);
        AppLayerParserRegisterParser(IPPROTO_UDP, ALPROTO_ENIP,
                STREAM_TOCLIENT, ENIPParse);

        AppLayerParserRegisterStateFuncs(IPPROTO_UDP, ALPROTO_ENIP,
                ENIPStateAlloc, ENIPStateFree);

        //      AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetAlstateProgress);
        //      AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetAlstateProgressCompletionStatus);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP,
                ALPROTO_ENIP, STREAM_TOSERVER | STREAM_TOCLIENT);

    } else
    {
        SCLogInfo(
                "Parsed disabled for %s protocol. Protocol detection" "still on.",
                proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_UDP, ALPROTO_ENIP, ENIPParserRegisterTests);
#endif

    SCReturn;
}

/**
 * \brief Function to register the ENIP protocol parsers and other functions
 */
void RegisterENIPTCPParsers(void)
{
    SCEnter();
    char *proto_name = "enip";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name))
    {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_ENIP, proto_name);

        if (RunmodeIsUnittests())
        {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT, ENIPProbingParser);

        } else
        {

            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr),
                    ENIPProbingParser))
            {
                SCLogDebug(
                        "no ENIP UDP config found enabling ENIP detection on port 44818.");

                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOSERVER,
                        ENIPProbingParser);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT,
                        ENIPProbingParser);

            }
        }

    } else
    {
        SCLogDebug("Protocol detection and parser disabled for %s protocol.",
                proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name))
    {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_ENIP,
                STREAM_TOSERVER, ENIPParse);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_ENIP,
                STREAM_TOCLIENT, ENIPParse);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_ENIP,
                ENIPStateAlloc, ENIPStateFree);

        //    AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetAlstateProgress);
        //    AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetAlstateProgressCompletionStatus);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP,
                ALPROTO_ENIP, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else
    {
        SCLogInfo(
                "Parsed disabled for %s protocol. Protocol detection" "still on.",
                proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_ENIP, ENIPParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS

/**
 * \brief Test if ENIP Packet matches signature
 */
int ALENIPTestMatch(uint8_t *raw_eth_pkt, uint16_t pktsize, char *sig,
        uint32_t sid)
{
    int result = 0;
    FlowInitConfig(FLOW_QUIET);
    Packet *p = UTHBuildPacketFromEth(raw_eth_pkt, pktsize);
    result = UTHPacketMatchSig(p, sig);
    PACKET_RECYCLE(p);
    FlowShutdown();
    return result;
}

/**
 * \brief Test List Identity
 */
static int ALDecodeENIPTest01 (void)
{
    /* List Identity */
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x0f, 0x73, 0x02, 0xfd, 0xa8, 0x00, 0xe0,
        0xed, 0x0d, 0x1e, 0xe4, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x34, 0x00, 0x00, 0x00, 0x00, 0xff, 0x11,
        0x37, 0x68, 0xc0, 0xa8, 0x01, 0x01, 0xc0, 0xa8,
        0x01, 0xff, 0xaf, 0x12, 0xaf, 0x12, 0x00, 0x20,
        0xba, 0x37, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00
    };

    char *sig = "alert enip any any -> any any (msg:\"Nothing..\"; enip_command:99; sid:1;)";

    return ALENIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}

/**
 * \brief Test Get Attribute All
 */
static int ALDecodeCIPTest01 (void)
{
    /* Single Get Attribute All */
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x5c, 0x81, 0xb9, 0x40, 0x00, 0x80, 0x06,
        0xe2, 0xb0, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x04, 0x4e, 0xaf, 0x12, 0x46, 0xb6,
        0xaf, 0x0e, 0x91, 0xb1, 0x1f, 0x2a, 0x50, 0x18,
        0xfd, 0xae, 0x96, 0x80, 0x00, 0x00, 0x70, 0x00,
        0x1c, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x29, 0x83, 0x00, 0xb1, 0x00,
        0x08, 0x00, 0x26, 0x00, 0x01, 0x02, 0x20, 0x02,
        0x24, 0x01
    };

    char *sig = "alert enip any any -> any any (msg:\"Nothing..\"; cip_service:1; sid:1;)";

    return ALENIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt),
            sig, 1);
}

/**
 * \brief Test Multi Service Packet with Get Attribute List
 */
static int ALDecodeCIPTest02 (void)
{
    /* Multi Service Packet with Get Attribute Lists*/
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x9c, 0x81, 0x95, 0x40, 0x00, 0x80, 0x06,
        0xe2, 0x94, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x04, 0x4e, 0xaf, 0x12, 0x46, 0xb6,
        0xa6, 0xc3, 0x91, 0xb1, 0x15, 0xfb, 0x50, 0x18,
        0xfb, 0x56, 0x96, 0xc0, 0x00, 0x00, 0x70, 0x00,
        0x5c, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x29, 0x83, 0x00, 0xb1, 0x00,
        0x48, 0x00, 0x05, 0x00, 0x0a, 0x02, 0x20, 0x02,
        0x24, 0x01, 0x05, 0x00, 0x0c, 0x00, 0x16, 0x00,
        0x22, 0x00, 0x2c, 0x00, 0x36, 0x00, 0x03, 0x02,
        0x20, 0x8e, 0x24, 0x01, 0x01, 0x00, 0x08, 0x00,
        0x03, 0x02, 0x20, 0x64, 0x24, 0x01, 0x02, 0x00,
        0x01, 0x00, 0x02, 0x00, 0x03, 0x02, 0x20, 0x01,
        0x24, 0x01, 0x01, 0x00, 0x05, 0x00, 0x03, 0x02,
        0x20, 0x69, 0x24, 0x00, 0x01, 0x00, 0x0b, 0x00,
        0x03, 0x02, 0x20, 0x69, 0x24, 0x01, 0x01, 0x00,
        0x0a, 0x00
    };

    char *sig = "alert enip any any -> any any (msg:\"Nothing..\"; cip_service:3; sid:1;)";

    return ALENIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}

/**
 * \brief Test Change Time
 */
static int ALDecodeCIPTest03 (void)
{
    /* Set Attribute List Change Time*/
    uint8_t raw_eth_pkt[] =
    {
        0x00, 0x00, 0xbc, 0x3e, 0xeb, 0xe4, 0x00, 0x1d,
        0x09, 0x99, 0xb2, 0x2c, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x68, 0x5e, 0x7d, 0x40, 0x00, 0x80, 0x06,
        0x05, 0xe1, 0xc0, 0xa8, 0x0a, 0x69, 0xc0, 0xa8,
        0x0a, 0x78, 0x0b, 0xd9, 0xaf, 0x12, 0xcf, 0xce,
        0x17, 0xe7, 0x8d, 0xf5, 0x35, 0x00, 0x50, 0x18,
        0xfa, 0xd2, 0x96, 0x8c, 0x00, 0x00, 0x70, 0x00,
        0x28, 0x00, 0x00, 0x01, 0x02, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x02, 0x00, 0xa1, 0x00,
        0x04, 0x00, 0x01, 0x0b, 0x7c, 0x00, 0xb1, 0x00,
        0x14, 0x00, 0xb2, 0x04, 0x04, 0x02, 0x20, 0x8b,
        0x24, 0x01, 0x01, 0x00, 0x06, 0x00, 0xc0, 0x32,
        0x5c, 0xff, 0xf3, 0x59, 0x04, 0x00
    };

    char *sig = "alert enip any any -> any any (msg:\"Nothing..\"; cip_service:4,139,6; sid:1;)";

    return ALENIPTestMatch(raw_eth_pkt, (uint16_t)sizeof(raw_eth_pkt), sig, 1);
}

#endif /* UNITTESTS */

void ENIPParserRegisterTests(void)
{
#ifdef UNITTESTS
    //  UtRegisterTest("ALDecodeENIPTest01", ALDecodeENIPTest01, 1);
    //  UtRegisterTest("ALDecodeCIPTest01", ALDecodeCIPTest01, 1);
    //  UtRegisterTest("ALDecodeCIPTest02", ALDecodeCIPTest02, 1);
    //  UtRegisterTest("ALDecodeCIPTest03", ALDecodeCIPTest03, 1);

#endif /* UNITTESTS */
}
