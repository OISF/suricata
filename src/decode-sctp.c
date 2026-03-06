/* Copyright (C) 2011-2021 Open Information Security Foundation
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
 * \ingroup decode
 *
 * @{
 */


/**
 * \file
 *
 * \author Eric Leblond <eric@regit.org>
 *
 * Decode SCTP
 */

#include "suricata-common.h"
#include "decode.h"
#include "decode-sctp.h"
#include "decode-events.h"

#include "util-validate.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-optimize.h"
#include "flow.h"

/**
 * \brief Parse SCTP chunks after the common header.
 *
 * Iterates over chunks, validates each chunk header, and populates
 * SCTPVars with chunk metadata.
 *
 * \param p Packet to decode
 * \param pkt Pointer to the start of chunk data (after 12-byte common header)
 * \param len Length of chunk data remaining
 *
 * \retval 0 on success (even if some events were set)
 * \retval -1 on fatal error (packet should be rejected)
 */
static int DecodeSCTPChunks(Packet *p, const uint8_t *pkt, uint32_t len)
{
    const SCTPHdr *sctph = PacketGetSCTP(p);
    const uint32_t vtag = SCTP_GET_RAW_VTAG(sctph);
    uint32_t offset = 0;
    uint8_t chunk_cnt = 0;
    bool has_init = false;
    bool has_init_ack = false;
    bool has_data = false;
    bool has_abort = false;
    int ret = 0;

    while (offset < len) {
        /* need at least a chunk header */
        if (len - offset < SCTP_CHUNK_HDR_LEN) {
            ENGINE_SET_INVALID_EVENT(p, SCTP_CHUNK_TOO_SMALL);
            ret = -1;
            break;
        }

        const SCTPChunkHdr *chunk = (const SCTPChunkHdr *)(pkt + offset);
        const uint16_t chunk_len = SCNtohs(chunk->length);

        /* RFC 4960 sec 3.2: chunk length includes the header and must be >= 4 */
        if (chunk_len < SCTP_CHUNK_HDR_LEN) {
            ENGINE_SET_INVALID_EVENT(p, SCTP_CHUNK_LEN_INVALID);
            ret = -1;
            break;
        }

        /* chunk must not extend beyond available data */
        if (chunk_len > (len - offset)) {
            ENGINE_SET_INVALID_EVENT(p, SCTP_CHUNK_LEN_INVALID);
            ret = -1;
            break;
        }

        if (chunk_cnt < SCTP_MAX_TRACKED_CHUNKS) {
            p->l4.vars.sctp.chunk_types[chunk_cnt] = chunk->type;
        }
        chunk_cnt++;

        switch (chunk->type) {
            case SCTP_CHUNK_TYPE_INIT:
                has_init = true;
                /* RFC 4960 sec 8.5.1: INIT must have vtag == 0 */
                if (vtag != 0) {
                    ENGINE_SET_EVENT(p, SCTP_INIT_WITH_NON_ZERO_VTAG);
                }
                break;
            case SCTP_CHUNK_TYPE_INIT_ACK:
                has_init_ack = true;
                break;
            case SCTP_CHUNK_TYPE_DATA:
                has_data = true;
                /* DATA chunks must not have vtag == 0 */
                if (vtag == 0) {
                    ENGINE_SET_EVENT(p, SCTP_DATA_WITH_ZERO_VTAG);
                }
                break;
            case SCTP_CHUNK_TYPE_ABORT:
                has_abort = true;
                break;
            default:
                break;
        }

        /* advance to next chunk: padded to 4-byte boundary (RFC 4960 sec 3.2) */
        uint32_t padded_len = (chunk_len + 3) & ~3U;
        /* guard against infinite loop with zero-padding overshoot */
        if (padded_len < SCTP_CHUNK_HDR_LEN) {
            padded_len = SCTP_CHUNK_HDR_LEN;
        }
        offset += padded_len;
    }

    /* RFC 4960 sec 6.10: INIT/INIT_ACK must be the only chunk in the packet */
    if ((has_init || has_init_ack) && chunk_cnt > 1) {
        ENGINE_SET_EVENT(p, SCTP_INIT_CHUNK_NOT_ALONE);
    }

    p->l4.vars.sctp.hlen = (uint16_t)(SCTP_HEADER_LEN + MIN(offset, len));
    p->l4.vars.sctp.chunk_cnt = chunk_cnt;
    p->l4.vars.sctp.has_init = has_init;
    p->l4.vars.sctp.has_init_ack = has_init_ack;
    p->l4.vars.sctp.has_data = has_data;
    p->l4.vars.sctp.has_abort = has_abort;

    return ret;
}

static int DecodeSCTPPacket(ThreadVars *tv, Packet *p, const uint8_t *pkt, uint16_t len)
{
    DEBUG_VALIDATE_BUG_ON(pkt == NULL);

    if (unlikely(len < SCTP_HEADER_LEN)) {
        ENGINE_SET_INVALID_EVENT(p, SCTP_PKT_TOO_SMALL);
        return -1;
    }

    const SCTPHdr *sctph = PacketSetSCTP(p, pkt);

    p->sp = SCTP_GET_RAW_SRC_PORT(sctph);
    p->dp = SCTP_GET_RAW_DST_PORT(sctph);
    p->payload = (uint8_t *)pkt + SCTP_HEADER_LEN;
    p->payload_len = len - SCTP_HEADER_LEN;
    p->proto = IPPROTO_SCTP;

    if (p->payload_len > 0) {
        if (DecodeSCTPChunks(p, p->payload, p->payload_len) < 0) {
            p->payload_len = 0;
            return -1;
        }
    } else {
        p->l4.vars.sctp.hlen = SCTP_HEADER_LEN;
    }

    return 0;
}

int DecodeSCTP(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
        const uint8_t *pkt, uint16_t len)
{
    StatsCounterIncr(&tv->stats, dtv->counter_sctp);

    if (unlikely(DecodeSCTPPacket(tv, p, pkt, len) < 0)) {
        PacketClearL4(p);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("SCTP sp: %u -> dp: %u", p->sp, p->dp);

    if (p->l4.vars.sctp.has_init) {
        StatsCounterIncr(&tv->stats, dtv->counter_sctp_init);
    }
    if (p->l4.vars.sctp.has_init_ack) {
        StatsCounterIncr(&tv->stats, dtv->counter_sctp_init_ack);
    }
    if (p->l4.vars.sctp.has_data) {
        StatsCounterIncr(&tv->stats, dtv->counter_sctp_data);
    }
    if (p->l4.vars.sctp.has_abort) {
        StatsCounterIncr(&tv->stats, dtv->counter_sctp_abort);
    }
    const uint8_t tracked = MIN(p->l4.vars.sctp.chunk_cnt, SCTP_MAX_TRACKED_CHUNKS);
    for (uint8_t i = 0; i < tracked; i++) {
        if (p->l4.vars.sctp.chunk_types[i] == SCTP_CHUNK_TYPE_SHUTDOWN) {
            StatsCounterIncr(&tv->stats, dtv->counter_sctp_shutdown);
            break;
        }
    }

    FlowSetupPacket(p);

    return TM_ECODE_OK;
}

#ifdef UNITTESTS

/** \test Valid SCTP packet with INIT chunk */
static int SCTPDecodeValidInitTest01(void)
{
    /* SCTP common header: sport=1234 dport=80 vtag=0 checksum=0
     * followed by INIT chunk: type=0x01 flags=0x00 length=20
     * with 16 bytes of INIT-specific data (initiate_tag, a_rwnd, etc.) */
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x00, /* vtag=0 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        0x01, 0x00, 0x00, 0x14, /* chunk: INIT, flags=0, len=20 */
        0x00, 0x00, 0x00, 0x01, /* initiate_tag=1 */
        0x00, 0x01, 0x00, 0x00, /* a_rwnd=65536 */
        0x00, 0x01, 0x00, 0x01, /* num_outbound=1, num_inbound=1 */
        0x00, 0x00, 0x00, 0x01, /* initial_tsn=1 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF_NOT(PacketIsSCTP(p));

    FAIL_IF(p->sp != 1234);
    FAIL_IF(p->dp != 80);
    FAIL_IF(p->l4.vars.sctp.chunk_types[0] != SCTP_CHUNK_TYPE_INIT);
    FAIL_IF(p->l4.vars.sctp.chunk_cnt != 1);
    FAIL_IF(!p->l4.vars.sctp.has_init);
    FAIL_IF(p->l4.vars.sctp.has_data);
    FAIL_IF(p->l4.vars.sctp.has_abort);

    /* no protocol violation events expected */
    FAIL_IF(ENGINE_ISSET_EVENT(p, SCTP_INIT_WITH_NON_ZERO_VTAG));
    FAIL_IF(ENGINE_ISSET_EVENT(p, SCTP_INIT_CHUNK_NOT_ALONE));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Packet too small (< 12 bytes) */
static int SCTPDecodePktTooSmallTest02(void)
{
    uint8_t raw_sctp[] = { 0x04, 0xd2, 0x00, 0x50, 0x00, 0x00 };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    int ret = DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF(ret != TM_ECODE_FAILED);
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, SCTP_PKT_TOO_SMALL));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Chunk too small - header + 2 bytes garbage (not enough for chunk header) */
static int SCTPDecodeChunkTooSmallTest03(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x01, /* vtag=1 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        0x01, 0x00,             /* only 2 bytes of chunk data */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    int ret = DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF(ret != TM_ECODE_FAILED);
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, SCTP_CHUNK_TOO_SMALL));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Invalid chunk length (chunk_len < 4) */
static int SCTPDecodeChunkLenInvalidTest04(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x01, /* vtag=1 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        0x00, 0x00, 0x00, 0x02, /* chunk: DATA, flags=0, len=2 (invalid < 4) */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    int ret = DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF(ret != TM_ECODE_FAILED);
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, SCTP_CHUNK_LEN_INVALID));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test INIT with non-zero verification tag */
static int SCTPDecodeInitNonZeroVtagTest05(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x42, /* vtag=0x42 (non-zero, invalid for INIT) */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        0x01, 0x00, 0x00, 0x14, /* chunk: INIT, flags=0, len=20 */
        0x00, 0x00, 0x00, 0x01, /* initiate_tag=1 */
        0x00, 0x01, 0x00, 0x00, /* a_rwnd=65536 */
        0x00, 0x01, 0x00, 0x01, /* num_outbound=1, num_inbound=1 */
        0x00, 0x00, 0x00, 0x01, /* initial_tsn=1 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF_NOT(PacketIsSCTP(p));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, SCTP_INIT_WITH_NON_ZERO_VTAG));

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test Multiple chunks: DATA + SACK */
static int SCTPDecodeMultiChunkTest06(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x01, /* vtag=1 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        /* DATA chunk: type=0x00, flags=0x03, len=20 */
        0x00, 0x03, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, /* TSN=0 */
        0x00, 0x01, 0x00, 0x00,                         /* stream_id=1, stream_seq=0 */
        0x00, 0x00, 0x00, 0x00,                         /* PPID=0 */
        0x41, 0x42, 0x43, 0x44,                         /* data="ABCD" */
        /* SACK chunk: type=0x03, flags=0x00, len=16 */
        0x03, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01, /* cumulative_tsn_ack=1 */
        0x00, 0x01, 0x00, 0x00,                         /* a_rwnd=65536 */
        0x00, 0x00, 0x00, 0x00,                         /* num_gap_blocks=0, num_dup_tsns=0 */
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF_NOT(PacketIsSCTP(p));

    FAIL_IF(p->l4.vars.sctp.chunk_cnt != 2);
    FAIL_IF(p->l4.vars.sctp.chunk_types[0] != SCTP_CHUNK_TYPE_DATA);
    FAIL_IF(p->l4.vars.sctp.chunk_types[1] != SCTP_CHUNK_TYPE_SACK);
    FAIL_IF(!p->l4.vars.sctp.has_data);
    FAIL_IF(p->l4.vars.sctp.has_init);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

/** \test INIT bundled with another chunk (violates RFC 4960 sec 6.10) */
static int SCTPDecodeInitNotAloneTest07(void)
{
    uint8_t raw_sctp[] = {
        0x04, 0xd2, 0x00, 0x50, /* sport=1234, dport=80 */
        0x00, 0x00, 0x00, 0x00, /* vtag=0 */
        0x00, 0x00, 0x00, 0x00, /* checksum=0 */
        /* INIT chunk: type=0x01, flags=0, len=20 */
        0x01, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x01, /* initiate_tag=1 */
        0x00, 0x01, 0x00, 0x00, /* a_rwnd=65536 */
        0x00, 0x01, 0x00, 0x01, /* num_outbound=1, num_inbound=1 */
        0x00, 0x00, 0x00, 0x01, /* initial_tsn=1 */
        /* DATA chunk: type=0x00, flags=0, len=16 (bundled illegally) */
        0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    Packet *p = PacketGetFromAlloc();
    FAIL_IF_NULL(p);
    ThreadVars tv;
    DecodeThreadVars dtv;

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&dtv, 0, sizeof(DecodeThreadVars));

    FlowInitConfig(FLOW_QUIET);
    DecodeSCTP(&tv, &dtv, p, raw_sctp, sizeof(raw_sctp));
    FAIL_IF_NOT(PacketIsSCTP(p));
    FAIL_IF_NOT(ENGINE_ISSET_EVENT(p, SCTP_INIT_CHUNK_NOT_ALONE));
    FAIL_IF(p->l4.vars.sctp.chunk_cnt != 2);

    PacketFree(p);
    FlowShutdown();
    PASS;
}

#endif /* UNITTESTS */

void DecodeSCTPRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCTPDecodeValidInitTest01", SCTPDecodeValidInitTest01);
    UtRegisterTest("SCTPDecodePktTooSmallTest02", SCTPDecodePktTooSmallTest02);
    UtRegisterTest("SCTPDecodeChunkTooSmallTest03", SCTPDecodeChunkTooSmallTest03);
    UtRegisterTest("SCTPDecodeChunkLenInvalidTest04", SCTPDecodeChunkLenInvalidTest04);
    UtRegisterTest("SCTPDecodeInitNonZeroVtagTest05", SCTPDecodeInitNonZeroVtagTest05);
    UtRegisterTest("SCTPDecodeMultiChunkTest06", SCTPDecodeMultiChunkTest06);
    UtRegisterTest("SCTPDecodeInitNotAloneTest07", SCTPDecodeInitNotAloneTest07);
#endif
}
/**
 * @}
 */
