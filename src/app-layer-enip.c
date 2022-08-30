/* Copyright (C) 2022 Open Information Security Foundation
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

#include "app-layer.h"
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


SCEnumCharMap enip_decoder_event_table[ ] = {
    { NULL,                         -1 },
};

/** \brief get value for 'complete' status in ENIP
 *
 *  For ENIP we use a simple bool.
 */
static int ENIPGetAlstateProgress(void *tx, uint8_t direction)
{
    return 1;
}

static AppLayerTxData *ENIPGetTxData(void *vtx)
{
    ENIPTransaction *tx = (ENIPTransaction *)vtx;
    return &tx->tx_data;
}

static void *ENIPGetTx(void *alstate, uint64_t tx_id)
{
    ENIPState         *enip = (ENIPState *) alstate;
    ENIPTransaction   *tx = NULL;

    if (enip->curr && enip->curr->tx_num == tx_id + 1)
        return enip->curr;

    TAILQ_FOREACH(tx, &enip->tx_list, next) {
        if (tx->tx_num != (tx_id+1))
            continue;

        SCLogDebug("returning tx %p", tx);
        return tx;
    }

    return NULL;
}

static uint64_t ENIPGetTxCnt(void *alstate)
{
    return ((ENIPState *)alstate)->transaction_max;
}

static int ENIPStateGetEventInfo(const char *event_name, int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, enip_decoder_event_table);

    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "enip's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int ENIPStateGetEventInfoById(int event_id, const char **event_name,
                                     AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, enip_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%d\" not present in "
                   "enip's enum map table.",  event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

/** \brief Allocate enip state
 *
 *  return state
 */
static void *ENIPStateAlloc(void *orig_state, AppProto proto_orig)
{
    SCLogDebug("ENIPStateAlloc");
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
    SCLogDebug("ENIPTransactionFree");
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

    AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    if (tx->tx_data.de_state != NULL) {
        DetectEngineStateFree(tx->tx_data.de_state);

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
static void ENIPStateFree(void *s)
{
    SCEnter();
    SCLogDebug("ENIPStateFree");
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
static ENIPTransaction *ENIPTransactionAlloc(ENIPState *state)
{
    SCLogDebug("ENIPStateTransactionAlloc");
    ENIPTransaction *tx = (ENIPTransaction *) SCCalloc(1,
            sizeof(ENIPTransaction));
    if (unlikely(tx == NULL))
        return NULL;

    state->curr = tx;
    state->transaction_max++;

    memset(tx, 0x00, sizeof(ENIPTransaction));
    TAILQ_INIT(&tx->service_list);

    tx->enip  = state;
    tx->tx_num  = state->transaction_max;
    tx->service_count = 0;

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);

    return tx;
}

/**
 *  \brief enip transaction cleanup callback
 */
static void ENIPStateTransactionFree(void *state, uint64_t tx_id)
{
    SCEnter();
    SCLogDebug("ENIPStateTransactionFree");
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

        if (tx->tx_data.events != NULL) {
            if (tx->tx_data.events->cnt <= enip_state->events)
                enip_state->events -= tx->tx_data.events->cnt;
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
static AppLayerResult ENIPParse(Flow *f, void *state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();
    ENIPState *enip = (ENIPState *) state;
    ENIPTransaction *tx;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate,
            APP_LAYER_PARSER_EOF_TS|APP_LAYER_PARSER_EOF_TC))
    {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL && input_len != 0) {
        // GAP
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0)
    {
        SCReturnStruct(APP_LAYER_ERROR);
    }

    while (input_len > 0)
    {
        tx = ENIPTransactionAlloc(enip);
        if (tx == NULL)
            SCReturnStruct(APP_LAYER_OK);

        SCLogDebug("ENIPParse input len %d", input_len);
        DecodeENIPPDU(input, input_len, tx);
        uint32_t pkt_len = tx->header.length + sizeof(ENIPEncapHdr);
        SCLogDebug("ENIPParse packet len %d", pkt_len);
        if (pkt_len > input_len)
        {
            SCLogDebug("Invalid packet length");
            break;
        }

        input += pkt_len;
        input_len -= pkt_len;
        //SCLogDebug("remaining %d", input_len);

        if (input_len < sizeof(ENIPEncapHdr))
        {
            //SCLogDebug("Not enough data"); //not enough data for ENIP
            break;
        }
    }

    SCReturnStruct(APP_LAYER_OK);
}

#define ENIP_LEN_REGISTER_SESSION 4 // protocol u16, options u16

static uint16_t ENIPProbingParser(Flow *f, uint8_t direction,
        const uint8_t *input, uint32_t input_len, uint8_t *rdir)
{
    // SCLogDebug("ENIPProbingParser %d", input_len);
    if (input_len < sizeof(ENIPEncapHdr))
    {
        SCLogDebug("length too small to be a ENIP header");
        return ALPROTO_UNKNOWN;
    }
    uint16_t cmd;
    uint16_t enip_len;
    uint32_t status;
    uint32_t option;
    uint16_t nbitems;

    int ret = ByteExtractUint32(
            &status, BYTE_LITTLE_ENDIAN, sizeof(uint32_t), (const uint8_t *)(input + 8));
    if (ret < 0) {
        return ALPROTO_FAILED;
    }
    switch (status) {
        case SUCCESS:
        case INVALID_CMD:
        case NO_RESOURCES:
        case INCORRECT_DATA:
        case INVALID_SESSION:
        case INVALID_LENGTH:
        case UNSUPPORTED_PROT_REV:
        case ENCAP_HEADER_ERROR:
            break;
        default:
            return ALPROTO_FAILED;
    }
    ret = ByteExtractUint16(&cmd, BYTE_LITTLE_ENDIAN, sizeof(uint16_t), (const uint8_t *)(input));
    if(ret < 0) {
        return ALPROTO_FAILED;
    }
    ret = ByteExtractUint32(
            &option, BYTE_LITTLE_ENDIAN, sizeof(uint32_t), (const uint8_t *)(input + 20));
    if (ret < 0) {
        return ALPROTO_FAILED;
    }
    ret = ByteExtractUint16(
            &enip_len, BYTE_LITTLE_ENDIAN, sizeof(uint16_t), (const uint8_t *)(input + 2));
    if (ret < 0) {
        return ALPROTO_FAILED;
    }

    //ok for all the known commands
    switch(cmd) {
        case NOP:
            if (option != 0) {
                return ALPROTO_FAILED;
            }
            break;
        case REGISTER_SESSION:
            if (enip_len != ENIP_LEN_REGISTER_SESSION) {
                return ALPROTO_FAILED;
            }
            break;
        case UNREGISTER_SESSION:
            if (enip_len != ENIP_LEN_REGISTER_SESSION && enip_len != 0) {
                // 0 for request and 4 for response
                return ALPROTO_FAILED;
            }
            break;
        case LIST_SERVICES:
        case LIST_IDENTITY:
        case SEND_RR_DATA:
        case SEND_UNIT_DATA:
        case INDICATE_STATUS:
        case CANCEL:
            break;
        case LIST_INTERFACES:
            if (input_len < sizeof(ENIPEncapHdr) + 2) {
                SCLogDebug("length too small to be a ENIP LIST_INTERFACES");
                return ALPROTO_UNKNOWN;
            }
            ret = ByteExtractUint16(
                    &nbitems, BYTE_LITTLE_ENDIAN, sizeof(uint16_t), (const uint8_t *)(input));
            if(ret < 0) {
                return ALPROTO_FAILED;
            }
            if (enip_len < sizeof(ENIPEncapHdr) + 2 * (size_t)nbitems) {
                return ALPROTO_FAILED;
            }
            break;
        default:
            return ALPROTO_FAILED;
    }
    return ALPROTO_ENIP;
}

/**
 * \brief Function to register the ENIP protocol parsers and other functions
 */
void RegisterENIPUDPParsers(void)
{
    SCEnter();
    const char *proto_name = "enip";

    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("udp", proto_name, false)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_ENIP, proto_name);

        if (RunmodeIsUnittests())
        {
            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT, ENIPProbingParser, NULL);

        } else
        {
            if (!AppLayerProtoDetectPPParseConfPorts("udp", IPPROTO_UDP,
                    proto_name, ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr),
                    ENIPProbingParser, ENIPProbingParser))
            {
                SCLogDebug(
                        "no ENIP UDP config found enabling ENIP detection on port 44818.");

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOSERVER,
                        ENIPProbingParser, NULL);

                AppLayerProtoDetectPPRegister(IPPROTO_UDP, "44818",
                        ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT,
                        ENIPProbingParser, NULL);
            }
        }

    } else {
        SCLogConfig("Protocol detection and parser disabled for %s protocol.",
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

        AppLayerParserRegisterGetTx(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetTxData);
        AppLayerParserRegisterGetTxCnt(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetTxCnt);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPStateTransactionFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_UDP, ALPROTO_ENIP, ENIPGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_ENIP, 1, 1);

        AppLayerParserRegisterGetEventInfo(IPPROTO_UDP, ALPROTO_ENIP, ENIPStateGetEventInfo);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_UDP, ALPROTO_ENIP, ENIPStateGetEventInfoById);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_UDP,
                ALPROTO_ENIP, STREAM_TOSERVER | STREAM_TOCLIENT);
        AppLayerParserRegisterOptionFlags(
                IPPROTO_UDP, ALPROTO_ENIP, APP_LAYER_PARSER_OPT_UNIDIR_TXS);
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
    const char *proto_name = "enip";

    if (AppLayerProtoDetectConfProtoDetectionEnabledDefault("tcp", proto_name, false)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_ENIP, proto_name);

        if (RunmodeIsUnittests())
        {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOSERVER, ENIPProbingParser, NULL);

            AppLayerProtoDetectPPRegister(IPPROTO_TCP, "44818", ALPROTO_ENIP,
                    0, sizeof(ENIPEncapHdr), STREAM_TOCLIENT, ENIPProbingParser, NULL);

        } else
        {
            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_ENIP, 0, sizeof(ENIPEncapHdr),
                    ENIPProbingParser, ENIPProbingParser))
            {
                return;
            }
        }

    } else {
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

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetTxData);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetTxCnt);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_ENIP, ENIPStateTransactionFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_ENIP, ENIPGetAlstateProgress);
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_ENIP, 1, 1);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_ENIP, ENIPStateGetEventInfo);

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP,
                ALPROTO_ENIP, STREAM_TOSERVER | STREAM_TOCLIENT);

        /* This parser accepts gaps. */
        AppLayerParserRegisterOptionFlags(IPPROTO_TCP, ALPROTO_ENIP,
                APP_LAYER_PARSER_OPT_ACCEPT_GAPS);

        AppLayerParserRegisterOptionFlags(
                IPPROTO_TCP, ALPROTO_ENIP, APP_LAYER_PARSER_OPT_UNIDIR_TXS);
    } else
    {
        SCLogConfig("Parser disabled for %s protocol. Protocol detection still on.",
                proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_ENIP, ENIPParserRegisterTests);
#endif

    SCReturn;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "app-layer-parser.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "flow-util.h"
#include "stream-tcp.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

static uint8_t listIdentity[] = {/* List ID */    0x63, 0x00,
                                 /* Length */     0x00, 0x00,
                                 /* Session */    0x00, 0x00, 0x00, 0x00,
                                 /* Status */     0x00, 0x00, 0x00, 0x00,
                                 /*  Delay*/      0x00,
                                 /* Context */    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                 /* Quantity of coils */ 0x00, 0x00, 0x00, 0x00, 0x00};

/**
 * \brief Test if ENIP Packet matches signature
 */
static int ALDecodeENIPTest(void)
{
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow f;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx  = (void *)&ssn;
    f.proto     = IPPROTO_TCP;
    f.alproto   = ALPROTO_ENIP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_ENIP, STREAM_TOSERVER,
            listIdentity, sizeof(listIdentity));
    FAIL_IF(r != 0);

    ENIPState    *enip_state = f.alstate;
    FAIL_IF_NULL(enip_state);

    ENIPTransaction *tx = ENIPGetTx(enip_state, 0);
    FAIL_IF_NULL(tx);

    FAIL_IF(tx->header.command != 99);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);

    PASS;
}

#endif /* UNITTESTS */

void ENIPParserRegisterTests(void)
{
#ifdef UNITTESTS
      UtRegisterTest("ALDecodeENIPTest", ALDecodeENIPTest);
#endif /* UNITTESTS */
}
