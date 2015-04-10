/* Copyright (C) 2015 Open Information Security Foundation
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

#include "suricata-common.h"
#include "stream.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-hashlist.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-detect-proto.h"

#include "app-layer-dnp3.h"

/** Default number of unreplied requests to be considered a flood. */
#define DNP3_DEFAULT_REQ_FLOOD_COUNT 500

#define DNP3_DEFAULT_PORT "20000"
#define DNP3_START_BYTE0  0x05
#define DNP3_START_BYTE1  0x64
#define DNP3_MIN_LEN      5
#define DNP3_CRC_LEN      2
#define DNP3_BLOCK_SIZE   16

#define DNP3_MAX_TRAN_SEQNO 64
#define DNP3_MAX_APP_SEQNO  16

/* The number of bytes in the header that are counted as part of the
 * header length field. */
#define DNP3_LINK_HDR_LEN 5

#define DNP3_LINK_FC(control)  (control & 0x0f)
#define DNP3_LINK_DIR(control) (control & 0x80)

/* Link control function codes. */
#define DNP3_LINK_FC_CONFIRMED_USER_DATA   3
#define DNP3_LINK_FC_UNCONFIRMED_USER_DATA 4

/* Reserved addresses. */
#define DNP3_RESERVED_ADDR_MIN 0xfff0
#define DNP3_RESERVED_ADDR_MAX 0xfffb

/* Source addresses must be < 0xfff0. */
#define DNP3_SRC_ADDR_MAX 0xfff0

/* Transport layer. */
#define DNP3_TRANSPORT_FIN(x) (x & 0x80)
#define DNP3_TRANSPORT_FIR(x) (x & 0x40)
#define DNP3_TRANSPORT_SEQ(x) (x & 0x3f)

/* Extract fields from the application control octet. */
#define DNP3_APP_FIR(x) (x & 0x80)
#define DNP3_APP_FIN(x) (x & 0x40)
#define DNP3_APP_CON(x) (x & 0x20)
#define DNP3_APP_UNS(x) (x & 0x10)
#define DNP3_APP_SEQ(x) (x & 0x0f)

/* DNP3 application request function codes. */
#define DNP3_APP_FC_CONFIRM                0x00
#define DNP3_APP_FC_READ                   0x01
#define DNP3_APP_FC_WRITE                  0x02
#define DNP3_APP_FC_SELECT                 0x03
#define DNP3_APP_FC_OPERATE                0x04
#define DNP3_APP_FC_DIR_OPERATE            0x05
#define DNP3_APP_FC_DIR_OPERATE_NR         0x06
#define DNP3_APP_FC_FREEZE                 0x07
#define DNP3_APP_FC_FREEZE_NR              0x08
#define DNP3_APP_FC_FREEZE_CLEAR           0x09
#define DNP3_APP_FC_FREEZE_CLEAR_NR        0x0a
#define DNP3_APP_FC_FREEZE_AT_TIME         0x0b
#define DNP3_APP_FC_FREEZE_AT_TIME_NR      0x0c
#define DNP3_APP_FC_COLD_RESTART           0x0d
#define DNP3_APP_FC_WARM_RESTART           0x0e
#define DNP3_APP_FC_INITIALIZE_DATA        0x0f
#define DNP3_APP_FC_INITIALIZE_APPLICATION 0x10
#define DNP3_APP_FC_START_APPLICATION      0x11
#define DNP3_APP_FC_STOP_APPLICATION       0x12
#define DNP3_APP_FC_SAVE_CONFIGURATION     0x13
#define DNP3_APP_FC_ENABLE_UNSOLICITED     0x14
#define DNP3_APP_FC_DISABLE_UNSOLICTED     0x15
#define DNP3_APP_FC_ASSIGN_CLASS           0x16
#define DNP3_APP_FC_DELAY_MEASUREMENT      0x17
#define DNP3_APP_FC_RECORD_CURRENT_TIME    0x18
#define DNP3_APP_FC_OPEN_TIME              0x19
#define DNP3_APP_FC_CLOSE_FILE             0x1a
#define DNP3_APP_FC_DELETE_FILE            0x1b
#define DNP3_APP_FC_GET_FILE_INFO          0x1c
#define DNP3_APP_FC_AUTHENTICATE_FILE      0x1d
#define DNP3_APP_FC_ABORT_FILE             0x1e
#define DNP3_APP_FC_ACTIVATE_CONFIG        0x1f
#define DNP3_APP_FC_AUTH_REQ               0x20
#define DNP3_APP_FC_AUTH_REQ_NR            0x21

/* DNP3 application response function codes. */
#define DNP3_APP_FC_RESPONSE               0x81
#define DNP3_APP_FC_UNSOLICITED_RESP       0x82
#define DNP3_APP_FC_AUTH_RESP              0x83

SCEnumCharMap dnp3_decoder_event_table[] = {
    {"FLOODED", DNP3_DECODER_EVENT_FLOODED},
    {"LEN_TOO_SMALL", DNP3_DECODER_EVENT_LEN_TOO_SMALL},
    {"BAD_LINK_CRC", DNP3_DECODER_EVENT_BAD_LINK_CRC},
    {"BAD_TRANSPORT_CRC", DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC},
    {"BAD_TRANSPORT_SEQNO", DNP3_DECODER_EVENT_BAD_TRANSPORT_SEQNO},
    {"BAD_APPLICATION_SEQNO", DNP3_DECODER_EVENT_BAD_APPLICATION_SEQNO},
    {NULL, -1},
};

static const char banner[] = "DNP3";

typedef struct DNP3LinkHeader_ {
    uint8_t  start_byte0;
    uint8_t  start_byte1;
    uint8_t  len;
    uint8_t  control;
    uint16_t dst;
    uint16_t src;
    uint16_t crc;
} __attribute__((__packed__)) DNP3LinkHeader;

typedef uint8_t DNP3TransportHeader;

typedef struct DNP3ApplicationHeader_ {
    uint8_t control;
    uint8_t function_code;
} __attribute__((__packed__)) DNP3ApplicationHeader;

typedef struct DNP3InternalInd_ {
    uint8_t iin1;
    uint8_t iin2;
} __attribute__((__packed__)) DNP3InternalInd;

/* DNP3 values are stored in little endian on the wire, so swapping will be
 * needed on big endian architectures. */
#if __BYTE_ORDER == __BIG_ENDIAN
#define dnp3_tohs(x) SCByteSwap16(x)
#define dnp3_tons(x) SCByteSwap16(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define dnp3_tohs(x) x
#define dnp3_tons(x) x
#endif

#define NEXT_TRAN_SEQNO(current) ((current + 1) % DNP3_MAX_TRAN_SEQNO)
#define NEXT_APP_SEQNO(current)  ((current + 1) % DNP3_MAX_APP_SEQNO)

/* CRC table generated by pycrc - http://github.com/tpircher/pycrc.
 * - Polynomial: 0x3d65.
 */
static const uint16_t crc_table[256] = {
    0x0000, 0x365e, 0x6cbc, 0x5ae2, 0xd978, 0xef26, 0xb5c4, 0x839a,
    0xff89, 0xc9d7, 0x9335, 0xa56b, 0x26f1, 0x10af, 0x4a4d, 0x7c13,
    0xb26b, 0x8435, 0xded7, 0xe889, 0x6b13, 0x5d4d, 0x07af, 0x31f1,
    0x4de2, 0x7bbc, 0x215e, 0x1700, 0x949a, 0xa2c4, 0xf826, 0xce78,
    0x29af, 0x1ff1, 0x4513, 0x734d, 0xf0d7, 0xc689, 0x9c6b, 0xaa35,
    0xd626, 0xe078, 0xba9a, 0x8cc4, 0x0f5e, 0x3900, 0x63e2, 0x55bc,
    0x9bc4, 0xad9a, 0xf778, 0xc126, 0x42bc, 0x74e2, 0x2e00, 0x185e,
    0x644d, 0x5213, 0x08f1, 0x3eaf, 0xbd35, 0x8b6b, 0xd189, 0xe7d7,
    0x535e, 0x6500, 0x3fe2, 0x09bc, 0x8a26, 0xbc78, 0xe69a, 0xd0c4,
    0xacd7, 0x9a89, 0xc06b, 0xf635, 0x75af, 0x43f1, 0x1913, 0x2f4d,
    0xe135, 0xd76b, 0x8d89, 0xbbd7, 0x384d, 0x0e13, 0x54f1, 0x62af,
    0x1ebc, 0x28e2, 0x7200, 0x445e, 0xc7c4, 0xf19a, 0xab78, 0x9d26,
    0x7af1, 0x4caf, 0x164d, 0x2013, 0xa389, 0x95d7, 0xcf35, 0xf96b,
    0x8578, 0xb326, 0xe9c4, 0xdf9a, 0x5c00, 0x6a5e, 0x30bc, 0x06e2,
    0xc89a, 0xfec4, 0xa426, 0x9278, 0x11e2, 0x27bc, 0x7d5e, 0x4b00,
    0x3713, 0x014d, 0x5baf, 0x6df1, 0xee6b, 0xd835, 0x82d7, 0xb489,
    0xa6bc, 0x90e2, 0xca00, 0xfc5e, 0x7fc4, 0x499a, 0x1378, 0x2526,
    0x5935, 0x6f6b, 0x3589, 0x03d7, 0x804d, 0xb613, 0xecf1, 0xdaaf,
    0x14d7, 0x2289, 0x786b, 0x4e35, 0xcdaf, 0xfbf1, 0xa113, 0x974d,
    0xeb5e, 0xdd00, 0x87e2, 0xb1bc, 0x3226, 0x0478, 0x5e9a, 0x68c4,
    0x8f13, 0xb94d, 0xe3af, 0xd5f1, 0x566b, 0x6035, 0x3ad7, 0x0c89,
    0x709a, 0x46c4, 0x1c26, 0x2a78, 0xa9e2, 0x9fbc, 0xc55e, 0xf300,
    0x3d78, 0x0b26, 0x51c4, 0x679a, 0xe400, 0xd25e, 0x88bc, 0xbee2,
    0xc2f1, 0xf4af, 0xae4d, 0x9813, 0x1b89, 0x2dd7, 0x7735, 0x416b,
    0xf5e2, 0xc3bc, 0x995e, 0xaf00, 0x2c9a, 0x1ac4, 0x4026, 0x7678,
    0x0a6b, 0x3c35, 0x66d7, 0x5089, 0xd313, 0xe54d, 0xbfaf, 0x89f1,
    0x4789, 0x71d7, 0x2b35, 0x1d6b, 0x9ef1, 0xa8af, 0xf24d, 0xc413,
    0xb800, 0x8e5e, 0xd4bc, 0xe2e2, 0x6178, 0x5726, 0x0dc4, 0x3b9a,
    0xdc4d, 0xea13, 0xb0f1, 0x86af, 0x0535, 0x336b, 0x6989, 0x5fd7,
    0x23c4, 0x159a, 0x4f78, 0x7926, 0xfabc, 0xcce2, 0x9600, 0xa05e,
    0x6e26, 0x5878, 0x029a, 0x34c4, 0xb75e, 0x8100, 0xdbe2, 0xedbc,
    0x91af, 0xa7f1, 0xfd13, 0xcb4d, 0x48d7, 0x7e89, 0x246b, 0x1235
};

static uint16_t DNP3ComputeCRC(uint8_t *buf, uint32_t len)
{
    uint16_t crc = 0;
    uint8_t *byte = buf;
    int idx;

    while (len--) {
        idx = (crc ^ *byte) & 0xff;
        crc = (crc_table[idx] ^ (crc >> 8)) & 0xffff;
        byte++;
    }

    return ~crc & 0xffff;
}

/**
 * \brief Check the CRC of a block.
 *
 * \param block The block of data with CRC to be checked.
 * \param len The size of the data block.
 *
 * \retval 1 if CRC is OK, otherwise 0.
 */
static int DNP3CheckCRC(uint8_t *block, uint32_t len)
{
    uint32_t crc_offset = len - DNP3_CRC_LEN;
    uint16_t crc = DNP3ComputeCRC(block, len - DNP3_CRC_LEN);
    if (((crc & 0xff) == block[crc_offset]) &&
        ((crc >> 8) == block[crc_offset + 1])) {
        return 1;
    }

    return 0;
}

static int DNP3CheckLinkHeaderCRC(DNP3LinkHeader *header)
{
    return DNP3CheckCRC((uint8_t *)header, sizeof(DNP3LinkHeader));
}

/**
 * \brief Check user data CRCs.
 *
 * \param data Pointer to user data.
 * \param len Length of user data.
 *
 * \retval 1 if CRCs are OK, otherwise 0.
 */
static int DNP3CheckUserDataCRCs(uint8_t *data, uint32_t len)
{
    uint32_t offset = 0;
    uint32_t block_size;

    while (offset < len) {
        if (len - offset >= DNP3_BLOCK_SIZE + DNP3_CRC_LEN) {
            block_size = DNP3_BLOCK_SIZE + DNP3_CRC_LEN;
        }
        else {
            block_size = len - offset;
        }

        if (!DNP3CheckCRC(data + offset, block_size)) {
            /* Once failed, may as well return immediately. */
            return 0;
        }

        offset += block_size;
    }

    return 1;
}

/**
 * \brief Allocate a DNP3 session.
 */
static DNP3Session *DNP3SessionAlloc(DNP3LinkHeader *header)
{
    SCEnter();
    DNP3Session *session = SCCalloc(1, sizeof(DNP3Session));
    if (unlikely(session == NULL)) {
        SCReturnPtr(NULL, "DNP3Session");
    }
    if (DNP3_LINK_DIR(header->control)) {
        session->master = header->src;
        session->slave = header->dst;
    }
    else {
        session->master = header->dst;
        session->slave = header->src;
    }
    SCReturnPtr(session, "DNP3Session");
}

/**
 * \brief Free a DNPSession.
 *
 * Note: Argument is void so this function can be provided to the hash
 *   table implemention.
 */
static void DNP3SessionFree(void *data)
{
    if (data != NULL) {
        SCFree(data);
    }
}

/**
 * \brief Get a DNP3 session, allocating if necessary.
 */
static DNP3Session *DNP3SessionGet(DNP3State *dnp3, DNP3LinkHeader *header)
{
    DNP3Session *session = NULL;

    session = HashListTableLookup(dnp3->sessions, header,
        sizeof(DNP3LinkHeader));
    if (session == NULL) {
        session = DNP3SessionAlloc(header);
        if (session != NULL) {
            HashListTableAdd(dnp3->sessions, session, sizeof(DNP3Session));
        }
    }

    return session;
}

/**
 * \brief Check the DNP3 frame start bytes.
 *
 * \retval 1 if valid, 0 if not.
 */
static inline int DNP3CheckStartBytes(DNP3LinkHeader *header)
{
    return header->start_byte0 == DNP3_START_BYTE0 &&
        header->start_byte1 == DNP3_START_BYTE1;
}

/**
 * \brief Check if a frame contains a banner.
 *
 * Some servers (outstations) appear to send back a banner that fails
 * the normal frame checks.  So first check for a banner.
 *
 * \retval 1 if a banner is found, 0 if not.
 */
static int DNP3ContainsBanner(uint8_t *input, uint32_t len)
{
    return memmem(input, len, banner, strlen(banner)) != NULL;
}

static uint16_t DNP3ProbingParser(uint8_t *input, uint32_t len,
    uint32_t *offset)
{
    DNP3LinkHeader *hdr = (DNP3LinkHeader *)input;

    /* Check that we have the minimum amount of bytes. */
    if (len < sizeof(DNP3LinkHeader)) {
        return ALPROTO_UNKNOWN;
    }

    /* May be a banner. */
    if (DNP3ContainsBanner(input, len)) {
        goto end;
    }

    /* Verify start value (from AN2013-004b). */
    if (!DNP3CheckStartBytes(hdr)) {
        return ALPROTO_FAILED;
    }

    /* Verify minimum length. */
    if (hdr->len < DNP3_MIN_LEN) {
        return ALPROTO_FAILED;
    }

end:
    return ALPROTO_DNP3;
}

static uint32_t DNP3SessionHash(HashListTable *ht, void *buf, uint16_t buflen)
{
    uint16_t a = 0, b = 0;
    uint32_t hash;

    if (buflen == sizeof(DNP3Session)) {
        DNP3Session *session = buf;
        a = session->master;
        b = session->slave;
    }
    else if (buflen == sizeof(DNP3LinkHeader)) {
        DNP3LinkHeader *header = buf;
        a = header->src;
        b = header->dst;
    }

    hash = (a * b) % ht->array_size;
    return hash;
}

static char DNP3SessionHashCompare(void *a, uint16_t alen, void *b,
    uint16_t blen)
{
    uint16_t a1 = 0, a2 = 0;
    uint16_t b1 = 0, b2 = 0;

    if (alen == sizeof(DNP3Session)) {
        DNP3Session *session = a;
        a1 = session->master;
        a2 = session->slave;
    }
    else if (alen == sizeof(DNP3LinkHeader)) {
        DNP3LinkHeader *header = a;
        a1 = header->src;
        a2 = header->dst;
    }

    if (blen == sizeof(DNP3Session)) {
        DNP3Session *session = b;
        b1 = session->master;
        b2 = session->slave;
    }
    else if (blen == sizeof(DNP3LinkHeader)) {
        DNP3LinkHeader *header = b;
        b1 = header->src;
        b2 = header->dst;
    }

    if (a1 == b1 && a2 == b2) {
        return 1;
    }
    if (a1 == b2 && a2 == b1) {
        return 1;
    }

    return 0;
}

/**
 * \brief Strip the CRCs from user data.
 *
 * The buffer returned starts at the transport header.
 *
 * \param input Input data.
 * \param input_len Length of input data.
 * \param output_len Pointer where reassembled data length will be stored.
 *
 * \retval Pointer to allocated reassembled data.
 */
static uint8_t *DNP3StripCRCs(uint8_t *input, uint32_t input_len,
    uint32_t *output_len)
{
    int len = 0, offset = 0;
    uint8_t *output = SCCalloc(1, input_len);
    if (unlikely(output == NULL)) {
        return NULL;
    }

    int block_size;
    while ((uint32_t)offset < input_len) {
        if (input_len - offset > DNP3_BLOCK_SIZE + DNP3_CRC_LEN) {
            block_size = DNP3_BLOCK_SIZE + DNP3_CRC_LEN;
        }
        else {
            block_size = input_len - offset;
        }
        BUG_ON(len + block_size - DNP3_CRC_LEN >= (long)input_len);
        memcpy(output + len, input + offset, block_size - DNP3_CRC_LEN);
        len += block_size - DNP3_CRC_LEN;
        offset += block_size;
        BUG_ON((uint32_t)offset > input_len);
    }

    *output_len = len;
    return output;
}

static void *DNP3StateAlloc(void)
{
    SCEnter();
    DNP3State *dnp3;

    dnp3 = (DNP3State *)SCCalloc(1, sizeof(DNP3State));
    if (unlikely(dnp3 == NULL)) {
        return NULL;
    }
    TAILQ_INIT(&dnp3->tx_list);

    dnp3->sessions = HashListTableInit(256, DNP3SessionHash,
        DNP3SessionHashCompare, DNP3SessionFree);
    if (unlikely(dnp3->sessions == NULL)) {
        goto fail;
    }

    SCReturnPtr(dnp3, "void");
fail:
    if (dnp3 != NULL)
        SCFree(dnp3);
    SCReturnPtr(NULL, "void");
}

static void DNP3SetEvent(DNP3State *dnp3, uint8_t event)
{
    if (dnp3 && dnp3->curr) {
        AppLayerDecoderEventsSetEventRaw(&dnp3->curr->decoder_events, event);
        dnp3->events++;
    }
    else {
        SCLogWarning(SC_ERR_ALPARSER,
            "Fail set set event, state or txn was NULL.");
    }
}

static DNP3Transaction *DNP3TxAlloc(DNP3State *dnp3)
{
    DNP3Transaction *tx = SCCalloc(1, sizeof(DNP3Transaction));
    if (unlikely(tx == NULL)) {
        return NULL;
    }
    dnp3->unreplied++;
    dnp3->curr = tx;
    tx->dnp3 = dnp3;
    tx->tx_num = ++dnp3->transaction_max;
    TAILQ_INSERT_TAIL(&dnp3->tx_list, tx, next);

    /* Check for flood state. */
    if (dnp3->unreplied > DNP3_DEFAULT_REQ_FLOOD_COUNT) {
        DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_FLOODED);
        dnp3->flooded = 1;
    }

    return tx;
}

static DNP3Transaction *DNP3FindTransaction(DNP3State *dnp3,
    DNP3Session *session, uint8_t seqno)
{
    if (dnp3->curr == NULL) {
        return NULL;
    }

    if (dnp3->curr->session == session && dnp3->curr->app_seqno == seqno) {
        return dnp3->curr;
    }

    DNP3Transaction *tx;
    TAILQ_FOREACH(tx, &dnp3->tx_list, next) {
        if (tx->session == session && tx->app_seqno == seqno) {
            return tx;
        }
    }

    return NULL;
}

/**
 * \brief Calculate the length of a frame with CRCs added.
 */
static uint32_t DNP3CalculateUnassembledLength(uint8_t length)
{
    /* Subtract the 5 bytes of the header that are included in the
     * length. */
    length -= DNP3_LINK_HDR_LEN;

    /* The unassembled length is 18 bytes for each 16 byte block plus
     * the size of the last block plus 2 bytes, plus the size of the
     * link header. */
    return ((length / DNP3_BLOCK_SIZE) * (DNP3_BLOCK_SIZE + DNP3_CRC_LEN)) +
        ((length % DNP3_BLOCK_SIZE) + DNP3_CRC_LEN) + sizeof(DNP3LinkHeader);
}

/**
 * \brief Check if the link function code specifies user data.
 */
static int DNP3IsUserData(DNP3LinkHeader *header)
{
    switch (DNP3_LINK_FC(header->control)) {
    case DNP3_LINK_FC_CONFIRMED_USER_DATA:
    case DNP3_LINK_FC_UNCONFIRMED_USER_DATA:
        return 1;
    default:
        return 0;
    }
}

/**
 * \brief Check if the length of the header is long enough for the
 *     frame to contain user data.
 */
static int DNP3HasUserData(DNP3LinkHeader *header)
{
    if (DNP3_LINK_DIR(header->control)) {
        return header->len >= DNP3_LINK_HDR_LEN + sizeof(DNP3TransportHeader) +
            sizeof(DNP3ApplicationHeader);
    }
    else {
        return header->len >= DNP3_LINK_HDR_LEN + sizeof(DNP3TransportHeader) +
            sizeof(DNP3ApplicationHeader) + sizeof(DNP3InternalInd);
    }
}

static void DNP3BufferReset(DNP3Buffer *buffer)
{
    buffer->offset = 0;
    buffer->len = 0;
}

static void DNP3BufferAdd(DNP3Buffer *buffer, uint8_t *buf, uint32_t len)
{
    BUG_ON(buffer->len + len > sizeof(buffer->buffer));
    memcpy(buffer->buffer + buffer->len, buf, len);
    buffer->len += len;
}

static void DNP3BufferTrim(DNP3Buffer *buffer)
{
    if (buffer->offset == buffer->len) {
        DNP3BufferReset(buffer);
    }
    else if (buffer->offset > 0) {
        memmove(buffer->buffer, buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        buffer->len = buffer->len - buffer->offset;
        buffer->offset = 0;
    }
}

/**
 * \retval number of bytes processed.
 */
static int DNP3ParseRequestPDUs(DNP3State *dnp3, uint8_t *input,
    uint32_t input_len)
{
    SCEnter();
    uint32_t processed = 0;

    while (input_len) {
        uint32_t offset = 0;

        /* Need at least enough bytes for a DNP3 header. */
        if (input_len < sizeof(DNP3LinkHeader)) {
            break;
        }

        DNP3LinkHeader *header = (DNP3LinkHeader *)input;
        offset += sizeof(DNP3LinkHeader);

        if (!DNP3CheckStartBytes(header)) {
            goto error;
        }

        if (!DNP3CheckLinkHeaderCRC(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_LINK_CRC);
            goto error;
        }

        uint32_t required_input = DNP3CalculateUnassembledLength(header->len);
        if (input_len < required_input) {
            break;
        }

        /* Ignore non-user data for now. */
        if (!DNP3IsUserData(header)) {
            goto ignore;
        }

        /* Make sure the header length is large enough for transport and
         * application headers. */
        if (!DNP3HasUserData(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_LEN_TOO_SMALL);
            goto error;
        }

        if (!DNP3CheckUserDataCRCs(input + offset, required_input - offset)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC);
            goto error;
        }

        DNP3Session *session = DNP3SessionGet(dnp3, header);
        if (unlikely(session == NULL)) {
            goto error;
        }
        session->master_count++;

        DNP3TransportHeader th = input[offset];
        uint32_t th_offset = offset++;

        /* Validate transport sequence number. */
        uint8_t tseqno = DNP3_TRANSPORT_SEQ(th);
        if (session->master_count != 1) {
            if (tseqno != NEXT_TRAN_SEQNO(session->master_tran_seqno)) {
                DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_SEQNO);
            }
        }
        session->master_tran_seqno = tseqno;

        DNP3ApplicationHeader *ah = (DNP3ApplicationHeader *)(input + offset);
        offset += sizeof(DNP3ApplicationHeader);

        DNP3Transaction *tx = NULL;
        if (ah->function_code == DNP3_APP_FC_CONFIRM) {
            tx = DNP3FindTransaction(dnp3, session, DNP3_APP_SEQ(ah->control));
            if (unlikely(tx == NULL)) {
                goto error;
            }
            tx->replied = 1;
        }
        else {
            tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            tx->session = session;
            tx->app_seqno = DNP3_APP_SEQ(ah->control);
            tx->app_function_code = ah->function_code;

            /* Validate application sequence number. */
            if (session->master_count != 1) {
                uint8_t expected_seqno =
                    NEXT_APP_SEQNO(session->master_app_seqno);
                if (tx->app_seqno != expected_seqno) {
                    SCLogDebug("Bad application sequence number: expected: %d; "
                        "got %d.", expected_seqno, tx->app_seqno);
                    DNP3SetEvent(dnp3,
                        DNP3_DECODER_EVENT_BAD_APPLICATION_SEQNO);
                }
            }
            session->master_app_seqno = tx->app_seqno;
        }

        /* Reassemble the request buffer. */
        tx->request_buffer = DNP3StripCRCs(input + th_offset,
            input_len - th_offset, &tx->request_buffer_len);

    ignore:
        input += required_input;
        input_len -= required_input;
        processed += required_input;
    }

    SCReturnInt(processed);
error:
    SCReturnInt(-1);
}

/**
 * \brief Handle incoming request data.
 *
 * The actual request PDU parsing is done in
 * DNP3ParseRequestPDUs. This function takes care of buffering TCP
 * date if a segment does not contain a complete frame (or contains
 * multiple frames, but not the complete final frame).
 */
static int DNP3ParseRequest(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    SCEnter();
    DNP3State *dnp3 = (DNP3State *)state;
    DNP3Buffer *buffer = &dnp3->request_buffer;
    int processed = 0;

    if (buffer->len) {
        DNP3BufferAdd(buffer, input, input_len);
        input_len = 0;
        processed = DNP3ParseRequestPDUs(dnp3,
            buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        if (processed < 0) {
            goto error;
        }
        buffer->offset += processed;
    }
    else {
        processed = DNP3ParseRequestPDUs(dnp3, input, input_len);
        if (processed < 0) {
            goto error;
        }
        input += processed;
        input_len -= processed;
    }

    /* Buffer management. */
    DNP3BufferTrim(buffer);

    /* Not all data was processed, buffer it. */
    if (input_len) {
        DNP3BufferAdd(buffer, input, input_len);
    }

    SCReturnInt(1);

error:
    /* Reset the buffer. */
    DNP3BufferReset(buffer);
    SCReturnInt(-1);
}

static int DNP3ParseResponsePDUs(DNP3State *dnp3, uint8_t *input,
    uint32_t input_len)
{
    SCEnter();
    uint32_t processed = 0;

    while (input_len) {
        uint32_t offset = 0;

        /* May be a banner, discard. */
        if (DNP3ContainsBanner(input, input_len)) {
            SCReturnInt(0);
        }

        /* Need at least enough bytes for a DNP3 header. */
        if (input_len < sizeof(DNP3LinkHeader)) {
            SCLogDebug("Not enough data for valid header.");
            break;
        }

        DNP3LinkHeader *header = (DNP3LinkHeader *)input;
        offset += sizeof(DNP3LinkHeader);

        if (!DNP3CheckStartBytes(header)) {
            SCLogDebug("Invalid start bytes.");
            goto error;
        }

        if (!DNP3CheckLinkHeaderCRC(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_LINK_CRC);
            goto error;
        }

        uint32_t required_input = DNP3CalculateUnassembledLength(header->len);
        if (input_len < required_input) {
            SCLogDebug("Not enough data for complete PDU.");
            break;
        }

        /* If no user data, ignore. */
        if (!DNP3IsUserData(header)) {
            goto ignore;
        }

        /* Make sure the header length is large enough for transport and
         * application headers. */
        if (!DNP3HasUserData(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_LEN_TOO_SMALL);
            SCLogDebug("Link layer lenght not long enough for user data.");
            goto error;
        }

        if (!DNP3CheckUserDataCRCs(input + offset, required_input - offset)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC);
            SCLogDebug("Bad transport layer CRC.");
            goto error;
        }

        DNP3Session *session = DNP3SessionGet(dnp3, header);
        if (unlikely(session == NULL)) {
            goto error;
        }
        session->outstation_count++;

        DNP3TransportHeader th = input[offset];
        uint32_t th_offset = offset++;

        /* Validate transport sequence number. */
        uint8_t tseqno = DNP3_TRANSPORT_SEQ(th);
        if (session->outstation_count != 1) {
            if (tseqno != NEXT_TRAN_SEQNO(session->outstation_tran_seqno)) {
                DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_SEQNO);
            }
        }
        session->outstation_tran_seqno = tseqno;

        DNP3ApplicationHeader *ah = (DNP3ApplicationHeader *)(input + offset);
        offset += sizeof(DNP3ApplicationHeader);

        DNP3InternalInd *ind = (DNP3InternalInd *)(input + offset);
        offset += sizeof(DNP3InternalInd);

        DNP3Transaction *tx = NULL;
        if (ah->function_code == DNP3_APP_FC_UNSOLICITED_RESP) {
            tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            tx->session = session;
            tx->app_seqno = DNP3_APP_SEQ(ah->control);
            tx->app_function_code = ah->function_code;
            session->outstation_unsol_resp_count++;

            /* Validate application sequence number. */
            if (session->outstation_unsol_resp_count != 1) {
                if (tx->app_seqno !=
                    NEXT_APP_SEQNO(session->outstation_app_seqno)) {
                    DNP3SetEvent(dnp3,
                        DNP3_DECODER_EVENT_BAD_APPLICATION_SEQNO);
                }
            }
            session->outstation_app_seqno = tx->app_seqno;
        }
        else {
            tx = DNP3FindTransaction(dnp3, session, DNP3_APP_SEQ(ah->control));
            if (tx == NULL) {
                goto error;
            }
            tx->replied = 1;
        }
        tx->response_buffer = DNP3StripCRCs(input + th_offset,
            input_len - th_offset, &tx->response_buffer_len);
        tx->iin1 = ind->iin1;
        tx->iin2 = ind->iin2;

    ignore:
        input += required_input;
        input_len -= required_input;
        processed += required_input;
    }

    SCReturnInt(processed);
error:
    SCReturnInt(-1);
}

static int DNP3ParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    SCEnter();
    DNP3State *dnp3 = (DNP3State *)state;
    DNP3Buffer *buffer = &dnp3->response_buffer;
    int processed;

    if (buffer->len) {
        DNP3BufferAdd(buffer, input, input_len);
        input_len = 0;
        processed = DNP3ParseResponsePDUs(dnp3,
            buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        if (processed < 0) {
            goto error;
        }
        buffer->offset += processed;
    }
    else {
        processed = DNP3ParseResponsePDUs(dnp3, input, input_len);
        if (processed < 0) {
            goto error;
        }
        input += processed;
        input_len -= processed;
    }

    DNP3BufferTrim(buffer);

    if (input_len) {
        DNP3BufferAdd(buffer, input, input_len);
    }

    SCReturnInt(1);

error:
    SCLogDebug("Returning with error.");
    DNP3BufferReset(buffer);
    SCReturnInt(-1);
}

AppLayerDecoderEvents *DNP3GetEvents(void *state, uint64_t id) {
    DNP3State *dnp3 = state;
    DNP3Transaction *tx;

    if (dnp3->curr && dnp3->curr->tx_num == (id + 1)) {
        return dnp3->curr->decoder_events;
    }

    TAILQ_FOREACH(tx, &dnp3->tx_list, next) {
        if (tx->tx_num == (id + 1)) {
            return tx->decoder_events;
        }
    }

    return NULL;
}

int DNP3HasEvents(void *state) {
    SCEnter();
    uint16_t events = (((DNP3State *)state)->events);
    SCReturnInt(events);
}

void *DNP3GetTx(void *alstate, uint64_t tx_id) {
    SCEnter();
    DNP3State *dnp3 = (DNP3State *)alstate;
    DNP3Transaction *tx = NULL;

    if (dnp3->curr && dnp3->curr->tx_num == (tx_id + 1)) {
        SCReturnPtr(dnp3->curr, "void");
    }

    TAILQ_FOREACH(tx, &dnp3->tx_list, next) {
        if (tx_id + 1 != tx->tx_num) {
            continue;
        }
        SCReturnPtr(tx, "void");
    }

    SCReturnPtr(NULL, "void");
}

uint64_t DNP3GetTxCnt(void *state) {
    SCEnter();
    uint64_t count = ((uint64_t)((DNP3State *)state)->transaction_max);
    SCReturnUInt(count);
}

static void DNP3TxFree(DNP3Transaction *tx)
{
    SCEnter();
    if (tx->request_buffer != NULL) {
        SCFree(tx->request_buffer);
    }
    if (tx->response_buffer != NULL) {
        SCFree(tx->response_buffer);
    }
    AppLayerDecoderEventsFreeEvents(&tx->decoder_events);
    if (tx->de_state != NULL) {
        DetectEngineStateFree(tx->de_state);
    }

    SCFree(tx);
    SCReturn;
}

static void DNP3StateTxFree(void *state, uint64_t tx_id)
{
    SCEnter();
    DNP3State *dnp3 = state;
    DNP3Transaction *tx = NULL, *ttx;

    TAILQ_FOREACH_SAFE(tx, &dnp3->tx_list, next, ttx) {

        if (tx->tx_num != tx_id + 1) {
            continue;
        }

        if (tx == dnp3->curr) {
            dnp3->curr = NULL;
        }

        if (tx->decoder_events != NULL) {
            if (tx->decoder_events->cnt <= dnp3->events) {
                dnp3->events -= tx->decoder_events->cnt;
            }
            else {
                dnp3->events = 0;
            }
        }
        dnp3->unreplied--;

        /* Check flood state. */
        if (dnp3->flooded && dnp3->unreplied < DNP3_DEFAULT_REQ_FLOOD_COUNT) {
            dnp3->flooded = 0;
        }

        TAILQ_REMOVE(&dnp3->tx_list, tx, next);
        DNP3TxFree(tx);
        break;
    }

    SCReturn;
}

static void DNP3StateFree(void *state)
{
    SCEnter();
    DNP3State *dnp3 = state;
    DNP3Transaction *tx = NULL, *ttx;
    if (state != NULL) {
        TAILQ_FOREACH_SAFE(tx, &dnp3->tx_list, next, ttx) {
            AppLayerDecoderEventsFreeEvents(&tx->decoder_events);
            DNP3TxFree(tx);
        }
        HashListTableFree(dnp3->sessions);
        SCFree(dnp3);
    }
    SCReturn;
}

static int DNP3GetAlstateProgress(void *tx, uint8_t direction) {
    SCEnter();
    DNP3Transaction *dnp3tx = (DNP3Transaction *)tx;
    DNP3State *dnp3 = dnp3tx->dnp3;

    SCLogDebug("direction: 0x%02x", direction);

    if (dnp3tx->replied) {
        SCReturnInt(1);
    }

    /* If flooded, "ack" old transactions. */
    if (dnp3->flooded && (dnp3->transaction_max -
            dnp3tx->tx_num >= DNP3_DEFAULT_REQ_FLOOD_COUNT)) {
        SCLogDebug("flooded: returning tx as done.");
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

static int DNP3GetAlstateProgressCompletionStatus(uint8_t direction) {
    SCEnter();
    SCReturnInt(1);
}

static int DNP3StateGetEventInfo(const char *event_name, int *event_id,
    AppLayerEventType *event_type) {

    *event_id = SCMapEnumNameToValue(event_name, dnp3_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "Event \"%s\" not present in "
            "the DNP3 enum event map table.", event_name);
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static DetectEngineState *DNP3GetTxDetectState(void *vtx)
{
    DNP3Transaction *tx = vtx;
    return tx->de_state;
}

static int DNP3SetTxDetectState(void *vtx, DetectEngineState *s)
{
    DNP3Transaction *tx = vtx;
    tx->de_state = s;
    return 0;
}

/**
 * \brief Register the DNP3 application protocol parser.
 */
void RegisterDNP3Parsers(void)
{
    SCEnter();

    char *proto_name = "dnp3";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {

        AppLayerProtoDetectRegisterProtocol(ALPROTO_DNP3, proto_name);

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP, DNP3_DEFAULT_PORT,
                ALPROTO_DNP3, 0, sizeof(DNP3LinkHeader), STREAM_TOSERVER,
                DNP3ProbingParser);
        }
        else {
            if (!AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                    proto_name, ALPROTO_DNP3, 0, sizeof(DNP3LinkHeader),
                    DNP3ProbingParser)) {
                SCLogWarning(SC_ERR_DNP3_CONFIG,
                    "No DNP3 configuration found, enabling DNP3 detection on "
                    "port " DNP3_DEFAULT_PORT);
                AppLayerProtoDetectPPRegister(IPPROTO_TCP, DNP3_DEFAULT_PORT,
                    ALPROTO_DNP3, 0, sizeof(DNP3LinkHeader), STREAM_TOSERVER,
                    DNP3ProbingParser);
            }
        }

    }
    else {
        SCLogInfo("Protocol detection and parser disabled for DNP3.");
        SCReturn;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        SCLogInfo("Registering DNP3/tcp parsers.");

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DNP3, STREAM_TOSERVER,
            DNP3ParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_DNP3, STREAM_TOCLIENT,
            DNP3ParseResponse);

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3StateAlloc, DNP3StateFree);

        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3GetEvents);
        AppLayerParserRegisterHasEventsFunc(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3HasEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3GetTxDetectState, DNP3SetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_DNP3, DNP3GetTx);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_DNP3, DNP3GetTxCnt);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3StateTxFree);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3GetAlstateProgress);
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP,
            ALPROTO_DNP3, DNP3GetAlstateProgressCompletionStatus);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_DNP3,
            DNP3StateGetEventInfo);

        /* Limit probing to packets to the server. */
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP,
            ALPROTO_DNP3, STREAM_TOSERVER);

    }
    else {
        SCLogInfo("Parser disabled for protocol %s. "
            "Protocol detection still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_DNP3,
        DNP3ParserRegisterTests);
#endif

    SCReturn;
}

#ifdef UNITTESTS

#include "flow-util.h"
#include "stream-tcp.h"

#define FAIL_IF(expr) do {                                      \
        if (expr) {                                             \
            printf("Failed at %s:%d\n", __FILE__, __LINE__);    \
            goto end;                                           \
        }                                                       \
    } while (0);

/**
 * Test CRC checking on partial and full blocks.
 */
static int DNP3ParserTestCheckCRC(void)
{
    int result = 0;

    uint8_t request[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer - segment 1. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef,

        /* Application layer - segment 2. */
        0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    /* Check link header CRC. */
    FAIL_IF(!DNP3CheckCRC(request, sizeof(DNP3LinkHeader)));

    /* Check first application layer segment. */
    FAIL_IF(!DNP3CheckCRC(request + sizeof(DNP3LinkHeader),
            DNP3_BLOCK_SIZE + DNP3_CRC_LEN));

    /* Change a byte in link header, should fail now. */
    request[2]++;
    FAIL_IF(DNP3CheckCRC(request, sizeof(DNP3LinkHeader)));

    /* Change a byte in the first application segment, should fail
     * now. */
    request[sizeof(DNP3LinkHeader) + 3]++;
    FAIL_IF(DNP3CheckCRC(request + sizeof(DNP3LinkHeader),
            DNP3_BLOCK_SIZE + DNP3_CRC_LEN));

    result = 1;
end:
    return result;
}

/**
 * Test validation of all CRCs in user data.
 */
static int DNP3CheckUserDataCRCsTest(void)
{
    int result = 0;

    uint8_t data_valid[] = {

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0x00, 0x00, 0x00, 0x00,
        0x00,
        0xff, 0xff, /* CRC. */
    };

    FAIL_IF(!DNP3CheckUserDataCRCs(data_valid, sizeof(data_valid)));

    uint8_t data_invalid[] = {

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0x00, 0x00, 0x00, 0x00,
        0x01, /* Invalid byte. */
        0xff, 0xff, /* CRC. */
    };

    FAIL_IF(DNP3CheckUserDataCRCs(data_invalid, sizeof(data_invalid)));

    result = 1;
end:
    return result;
}

static int DNP3ParserCheckLinkHeaderCRC(void)
{
    int result = 0;

    uint8_t request[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    DNP3LinkHeader *header = (DNP3LinkHeader *)request;
    FAIL_IF(!DNP3CheckLinkHeaderCRC(header));

    result = 1;
end:
    return result;
}

/**
 * Test removal of CRCs from user data.
 */
static int DNP3RemoveCRCsTest(void)
{
    int result = 0;

    uint8_t payload[] = {

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        0x72, 0xef, /* CRC. */

        0x00, 0x00, 0x00, 0x00,
        0x00,
        0xff, 0xff, /* CRC. */
    };

    uint8_t expected[] = {
        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        /* CRC removed. */
        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        /* CRC removed. */
        0xff, 0xc9, 0x05, 0x0c,
        0x01, 0x28, 0x01, 0x00,
        0x00, 0x00, 0x01, 0x01,
        0x01, 0x00, 0x00, 0x00,
        /* CRC removed. */
        0x00, 0x00, 0x00, 0x00,
        0x00
        /* CRC removed. */
    };

    uint32_t reassembled_len;
    uint8_t *reassembled = DNP3StripCRCs(payload, sizeof(payload),
        &reassembled_len);
    FAIL_IF(reassembled == NULL);
    FAIL_IF(reassembled_len != sizeof(expected));
    FAIL_IF(memcmp(expected, reassembled, reassembled_len));

    SCFree(reassembled);
    result = 1;
end:
    return result;
}

/**
 * Test the probing parser.
 */
static int DNP3ProbingParserTest(void)
{
    /* From pcapr.net - dnp3_request_link_status.pcap.
     * - Datalink offset: 54 */
    uint8_t pkt[] = {
        0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x01, 0x02,
        0x03, 0x04, 0x05, 0x06, 0x08, 0x00, 0x45, 0x00,
        0x00, 0x32, 0x03, 0x00, 0x00, 0x00, 0x40, 0x06,
        0x79, 0xc4, 0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00,
        0x00, 0x01, 0xdf, 0xab, 0x4e, 0x20, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x02, 0x50, 0x18,
        0x80, 0x00, 0x34, 0x51, 0x00, 0x00, 0x05, 0x64,
        0x05, 0xc9, 0x03, 0x00, 0x04, 0x00, 0xbd, 0x71
    };
    uint32_t offset = 54;

    return DNP3ProbingParser(pkt + offset, sizeof(pkt) - offset, NULL) ==
        ALPROTO_DNP3;
}

/**
 * Test the DNP3 session hash functions.
 */
int DNP3SessionHashTest(void)
{
    int result = 0;

    HashListTable *ht = HashListTableInit(256, DNP3SessionHash,
        DNP3SessionHashCompare, DNP3SessionFree);
    if (ht == NULL) {
        goto end;
    }

    DNP3LinkHeader header_ab, header_ba;
    header_ab.src = header_ba.dst = 1;
    header_ab.dst = header_ba.src = 2;
    header_ab.control = 0x80;

    if (HashListTableLookup(ht, &header_ab, sizeof(DNP3LinkHeader)) != NULL)
        goto end;
    if (HashListTableLookup(ht, &header_ba, sizeof(DNP3LinkHeader)) != NULL)
        goto end;

    DNP3Session *session0 = DNP3SessionAlloc(&header_ab);
    FAIL_IF(session0 == NULL);

    uint32_t hash_a = DNP3SessionHash(ht, &header_ab, sizeof(DNP3LinkHeader));
    uint32_t hash_b = DNP3SessionHash(ht, &header_ba, sizeof(DNP3LinkHeader));
    FAIL_IF(hash_a != hash_b);
    FAIL_IF(DNP3SessionHash(ht, session0, sizeof(DNP3Session)) != hash_a);
    FAIL_IF(HashListTableAdd(ht, session0, sizeof(DNP3Session)) != 0);

    /* Should find a session. */
    FAIL_IF(HashListTableLookup(ht, &header_ab,
            sizeof(DNP3LinkHeader)) == NULL);
    FAIL_IF(HashListTableLookup(ht, &header_ba,
            sizeof(DNP3LinkHeader)) == NULL);
    FAIL_IF(HashListTableLookup(ht, session0, sizeof(DNP3Session)) == NULL);

    /* Change master address, should not find session. */
    header_ab.src = header_ab.dst = ++session0->master;
    FAIL_IF(HashListTableLookup(ht, &header_ab,
            sizeof(DNP3LinkHeader)) != NULL);
    FAIL_IF(HashListTableLookup(ht, &header_ba,
            sizeof(DNP3LinkHeader)) != NULL);
    FAIL_IF(HashListTableLookup(ht, session0, sizeof(DNP3Session)) != NULL);

    result = 1;
end:
    if (ht != NULL) {
        HashListTableFree(ht);
    }
    return result;
}

/**
 * Test a basic request/response.
 */
int DNP3ParserTestRequestResponse(void)
{
    DNP3State *state = NULL;
    int result = 0;

    uint8_t request[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    uint8_t response[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1c, 0x44, 0x01, 0x00, 0x02, 0x00,
        0xe2, 0x59,

        /* Transport header. */
        0xc3,

        /* Application layer. */
        0xc9, 0x81, 0x00, 0x00, 0x0c, 0x01, 0x28, 0x01,
        0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x7a,
        0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff
    };

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow flow;
    TcpSession ssn;

    memset(&flow, 0, sizeof(flow));
    memset(&ssn, 0, sizeof(ssn));

    flow.protoctx = (void *)&ssn;
    flow.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
            request, sizeof(request))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);

    state = flow.alstate;
    FAIL_IF(state == NULL);
    FAIL_IF(DNP3HasEvents(state));

    DNP3Transaction *tx = DNP3GetTx(state, 0);
    FAIL_IF(tx == NULL);
    FAIL_IF(tx->tx_num != 1);
    FAIL_IF(tx != state->curr);
    FAIL_IF(tx->request_buffer == NULL);
    FAIL_IF(tx->request_buffer_len != 21);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
            response, sizeof(response))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);
    FAIL_IF(DNP3GetTx(state, 0) != tx);
    FAIL_IF(!tx->replied);
    FAIL_IF(tx->response_buffer == NULL);

    result = 1;
end:
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&flow);
    DNP3StateFree(state);
    return result;
}

/**
 * Test an unsolicited response from an outstation. This is kind of
 * like a request initiated from the "server".
 */
static int DNP3ParserTestUnsolicitedResponseConfirm(void)
{
    DNP3State *state = NULL;
    int result = 0;

    /* Unsolicited response with confirm bit set. */
    uint8_t response[] = {
        0x05, 0x64, 0x16, 0x44, 0x01, 0x00, 0x02, 0x00,
        0x89, 0xe5, 0xc4, 0xfa, 0x82, 0x00, 0x00, 0x02,
        0x02, 0x17, 0x01, 0x01, 0x81, 0xa7, 0x75, 0xd8,
        0x32, 0x4c, 0x81, 0x3e, 0x01, 0xa1, 0xc9
    };

    /* Confirm. */
    uint8_t confirm[] = {
        0x05, 0x64, 0x08, 0xc4, 0x02, 0x00,
        0x01, 0x00, 0xd3, 0xb7, 0xc0, 0xda, 0x00, 0x6a,
        0x3d
    };

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow flow;
    TcpSession ssn;

    memset(&flow, 0, sizeof(flow));
    memset(&ssn, 0, sizeof(ssn));

    flow.protoctx = (void *)&ssn;
    flow.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
            response, sizeof(response))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);

    state = flow.alstate;
    FAIL_IF(state == NULL);
    FAIL_IF(DNP3HasEvents(state));

    DNP3Transaction *tx = DNP3GetTx(state, 0);
    FAIL_IF(tx == NULL);
    FAIL_IF(tx->tx_num != 1);
    FAIL_IF(tx != state->curr);
    FAIL_IF(tx->request_buffer != NULL);
    FAIL_IF(tx->response_buffer == NULL);
    FAIL_IF(tx->replied);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_UNSOLICITED_RESP);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
            confirm, sizeof(confirm))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);
    FAIL_IF(DNP3GetTx(state, 0) != tx);
    FAIL_IF(!tx->replied);
    FAIL_IF(tx->response_buffer == NULL);
    FAIL_IF(tx->iin1 != 0 || tx->iin2 != 0);

    result = 1;
end:
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&flow);
    DNP3StateFree(state);
    return result;
}

/**
 * Test flood state.
 */
int DNP3ParserTestFlooded(void)
{
    DNP3State *state = NULL;
    int result = 0;

    uint8_t request[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow flow;
    TcpSession ssn;

    memset(&flow, 0, sizeof(flow));
    memset(&ssn, 0, sizeof(ssn));

    flow.protoctx = (void *)&ssn;
    flow.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
            request, sizeof(request))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);

    state = flow.alstate;
    FAIL_IF(state == NULL);
    FAIL_IF(DNP3HasEvents(state));

    DNP3Transaction *tx = DNP3GetTx(state, 0);
    FAIL_IF(tx == NULL);
    FAIL_IF(tx->tx_num != 1);
    FAIL_IF(tx != state->curr);
    FAIL_IF(tx->request_buffer == NULL);
    FAIL_IF(tx->request_buffer_len != 21);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);
    FAIL_IF(tx->replied);

    for (int i = 0; i < DNP3_DEFAULT_REQ_FLOOD_COUNT - 1; i++) {
        SCMutexLock(&flow.m);
        if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
                request, sizeof(request))) {
            SCMutexUnlock(&flow.m);
            goto end;
        }
        SCMutexUnlock(&flow.m);
    }
    FAIL_IF(state->flooded);
    FAIL_IF(DNP3GetAlstateProgress(tx, 0));

    /* One more request should trip us into flooded state. */
    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
            request, sizeof(request))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);
    FAIL_IF(!state->flooded);

    /* Progress for the oldest tx should return 1. */
    FAIL_IF(!DNP3GetAlstateProgress(tx, 0));

    /* But progress for the current state should still return 0. */
    FAIL_IF(DNP3GetAlstateProgress(state->curr, 0));

    result = 1;
end:
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&flow);
    DNP3StateFree(state);
    return result;
}

static int DNP3ParserTestPartialFrame(void)
{
    DNP3State *state = NULL;
    int result = 0;

    uint8_t request_partial1[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1a, 0xc4, 0x02, 0x00, 0x01, 0x00,
        0xa5, 0xe9,

        /* Transport header. */
        0xff,

        /* Application layer. */
        0xc9, 0x05, 0x0c, 0x01, 0x28, 0x01, 0x00, 0x00,
    };

    uint8_t request_partial2[] = {
        0x00, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x72,
        0xef, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff
    };

    uint8_t response_partial1[] = {
        /* DNP3 start. */
        0x05, 0x64, 0x1c, 0x44, 0x01, 0x00, 0x02, 0x00,
        0xe2, 0x59,

        /* Transport header. */
        0xc3,

        /* Application layer. */
        0xc9, 0x81, 0x00, 0x00, 0x0c, 0x01, 0x28, 0x01,
    };

    uint8_t response_partial2[] = {
        0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x00, 0x7a,
        0x65, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xff, 0xff
    };

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow flow;
    TcpSession ssn;
    memset(&flow, 0, sizeof(flow));
    memset(&ssn, 0, sizeof(ssn));
    flow.protoctx = (void *)&ssn;
    flow.proto = IPPROTO_TCP;
    StreamTcpInitConfig(TRUE);

    int r;

    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
        request_partial1, sizeof(request_partial1));
    SCMutexUnlock(&flow.m);
    FAIL_IF(r != 0);

    state = flow.alstate;
    FAIL_IF(state == NULL);
    FAIL_IF(state->request_buffer.len != sizeof(request_partial1));
    FAIL_IF(state->request_buffer.offset != 0);
    FAIL_IF(!memcpy(state->request_buffer.buffer, request_partial1,
            sizeof(request_partial1)));

    /* There should not be a transaction yet. */
    DNP3Transaction *tx = DNP3GetTx(state, 0);
    FAIL_IF(tx != NULL);

    /* Send the second partial. */
    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
        request_partial2, sizeof(request_partial2));
    SCMutexUnlock(&flow.m);
    FAIL_IF(r != 0);

    /* Should now have a complete transaction. */
    tx = DNP3GetTx(state, 0);
    FAIL_IF(tx == NULL);
    FAIL_IF(tx->tx_num != 1);
    FAIL_IF(tx != state->curr);
    FAIL_IF(tx->request_buffer == NULL);
    FAIL_IF(tx->request_buffer_len != 21);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);

    /* Buffer should be empty. */
    FAIL_IF(state->request_buffer.len != 0);

    /* Send partial response. */
    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
        response_partial1, sizeof(response_partial1));
    SCMutexUnlock(&flow.m);
    FAIL_IF(tx->replied);
    FAIL_IF(r != 0);
    FAIL_IF(state->response_buffer.len != sizeof(response_partial1));
    FAIL_IF(state->response_buffer.offset != 0);

    /* Send rest of response. */
    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
        response_partial2, sizeof(response_partial2));
    SCMutexUnlock(&flow.m);
    FAIL_IF(r != 0);

    /* Buffer should now be empty. */
    FAIL_IF(state->response_buffer.len != 0);
    FAIL_IF(state->response_buffer.offset != 0);

    /* Transaction should be replied to now. */
    FAIL_IF(!tx->replied);
    FAIL_IF(tx->response_buffer == NULL);
    FAIL_IF(tx->response_buffer_len == 0);

    result = 1;
end:
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&flow);
    DNP3StateFree(state);
    return result;
}

/**
 * Test the scenario where a input data may contain more than one DNP3 frame.
 */
static int DNP3ParserTestMultiFrame(void)
{
    DNP3State *state = NULL;
    int result = 0;

    /* Onsolicited response 1. */
    uint8_t unsol_response1[] = {
        0x05, 0x64, 0x16, 0x44, 0x01, 0x00, 0x02, 0x00,
        0x89, 0xe5, 0xc4, 0xfa, 0x82, 0x00, 0x00, 0x02,
        0x02, 0x17, 0x01, 0x01, 0x81, 0xa7, 0x75, 0xd8,
        0x32, 0x4c, 0x81, 0x3e, 0x01, 0xa1, 0xc9,
    };

    /* Frame (97 bytes) */
    uint8_t unsol_response2[] = {
        0x05, 0x64, 0x16, 0x44, 0x01, 0x00, 0x02, 0x00,
        0x89, 0xe5, 0xc5, 0xfb, 0x82, 0x00, 0x00, 0x02,
        0x02, 0x17, 0x01, 0x0c, 0x01, 0xd8, 0x75, 0xd8,
        0x32, 0x4c, 0xc9, 0x3c, 0x01, 0xa1, 0xc9,
    };

    uint8_t combined[sizeof(unsol_response1) + sizeof(unsol_response2)];
    memcpy(combined, unsol_response1, sizeof(unsol_response1));
    memcpy(combined + sizeof(unsol_response1), unsol_response2,
        sizeof(unsol_response2));

    /* Setup. */
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    Flow flow;
    TcpSession ssn;
    int r;
    memset(&flow, 0, sizeof(flow));
    memset(&ssn, 0, sizeof(ssn));
    flow.protoctx = (void *)&ssn;
    flow.proto = IPPROTO_TCP;
    StreamTcpInitConfig(TRUE);

    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
        combined, sizeof(combined));
    SCMutexUnlock(&flow.m);
    FAIL_IF(r != 0);

    state = flow.alstate;
    FAIL_IF(state == NULL);
    FAIL_IF(state->transaction_max != 2);

    result = 1;
end:
    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&flow);
    DNP3StateFree(state);
    return result;
}

#endif

void DNP3ParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DNP3ParserTestCheckCRC", DNP3ParserTestCheckCRC, 1);
    UtRegisterTest("DNP3ParserCheckLinkHeaderCRC", DNP3ParserCheckLinkHeaderCRC,
        1);
    UtRegisterTest("DNP3CheckUserDataCRCsTest", DNP3CheckUserDataCRCsTest, 1);
    UtRegisterTest("DNP3RemoveCRCsTest", DNP3RemoveCRCsTest, 1);
    UtRegisterTest("DNP3ProbingParserTest", DNP3ProbingParserTest, 1);
    UtRegisterTest("DNP3SessionHashTest", DNP3SessionHashTest, 1);
    UtRegisterTest("DNP3ParserTestRequestResponse",
        DNP3ParserTestRequestResponse, 1);
    UtRegisterTest("DNP3ParserTestUnsolicitedResponseConfirm",
        DNP3ParserTestUnsolicitedResponseConfirm, 1);
    UtRegisterTest("DNP3ParserTestFlooded", DNP3ParserTestFlooded, 1);
    UtRegisterTest("DNP3ParserTestPartialFrame", DNP3ParserTestPartialFrame, 1);
    UtRegisterTest("DNP3ParserTestMultiFrame", DNP3ParserTestMultiFrame, 1);
#endif
}
