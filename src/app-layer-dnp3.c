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

#include "util-print.h"

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

/* Link control function codes. */
#define DNP3_LINK_FC_CONFIRMED_USER_DATA   3
#define DNP3_LINK_FC_UNCONFIRMED_USER_DATA 4

/* Reserved addresses. */
#define DNP3_RESERVED_ADDR_MIN 0xfff0
#define DNP3_RESERVED_ADDR_MAX 0xfffb

/* Source addresses must be < 0xfff0. */
#define DNP3_SRC_ADDR_MAX 0xfff0

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

#define DNP3_OBJ_GROUP_MAX 256
#define DNP3_OBJ_VAR_MAX 256

#define DNP3_OBJ_TIME_SIZE   6  /* AKA UINT48. */
#define DNP3_OBJ_G12_V1_SIZE 11
#define DNP3_OBJ_G12_V2_SIZE 11
#define DNP3_OBJ_G12_V3_SIZE 1

/* Extract the prefix code from the object qualifier. */
#define DNP3_OBJ_PREFIX(x) ((x >> 4) & 0x3)

/* Extract the range code from the object qualifier. */
#define DNP3_OBJ_RANGE(x)  (x & 0xf)

typedef struct DNP3LinkHeader_ {
    uint8_t  start_byte0;
    uint8_t  start_byte1;
    uint8_t  len;
    uint8_t  control;
    uint16_t dst;
    uint16_t src;
    uint16_t crc;
} __attribute__((__packed__)) DNP3LinkHeader;

typedef struct DNP3ApplicationHeader_ {
    uint8_t control;
    uint8_t function_code;
} __attribute__((__packed__)) DNP3ApplicationHeader;

typedef struct DNP3InternalInd_ {
    uint8_t iin1;
    uint8_t iin2;
} __attribute__((__packed__)) DNP3InternalInd;

/**
 * DNP3 application object header.
 */
typedef struct DNP3ObjHeader_ {
    uint8_t group;
    uint8_t variation;
    uint8_t qualifier;
} __attribute__((packed)) DNP3ObjHeader;

/**
 * A table to hold object sizes for all object groups and their
 * variations.
 *
 * Sizes are in bits.
 */
static int GROUP_VAR_SIZE_MAP[DNP3_OBJ_GROUP_MAX][DNP3_OBJ_VAR_MAX];

#define BSTRn    1
#define BSTR1    1
#define BSTR6    6
#define BSTR8    8
#define FLT32    32
#define FLT64    64
#define INT16    16
#define INT32    32
#define UINT2    2
#define UINT4    4
#define UINT7    7
#define UINT8    8
#define UINT16   16
#define UINT32   32
#define DNP3TIME (DNP3_OBJ_TIME_SIZE * 8)

/**
 * \brief Initialize the group/variation object size table for objects
 *     that have a static size.
 */
static void DNP3InitGroupVarSizeMap(void)
{
    /* Initialize all values to -1 to denote unset/unknown. */
    for (int i = 0; i < DNP3_OBJ_GROUP_MAX; i++) {
        for (int j = 0; j < DNP3_OBJ_VAR_MAX; j++) {
            GROUP_VAR_SIZE_MAP[i][j] = -1;
        }
    }

    GROUP_VAR_SIZE_MAP[1][1] = BSTRn;
    GROUP_VAR_SIZE_MAP[1][2] = BSTR8;

    GROUP_VAR_SIZE_MAP[2][1] = BSTR8;
    GROUP_VAR_SIZE_MAP[2][2] = BSTR8 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[2][3] = BSTR8 + UINT16;

    GROUP_VAR_SIZE_MAP[3][1] = UINT2;
    GROUP_VAR_SIZE_MAP[3][2] = BSTR6 + UINT2;

    GROUP_VAR_SIZE_MAP[4][1] = BSTR6 + UINT2;
    GROUP_VAR_SIZE_MAP[4][2] = BSTR6 + UINT2 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[4][3] = BSTR6 + UINT2 + UINT16;

    GROUP_VAR_SIZE_MAP[10][1] = BSTRn;
    GROUP_VAR_SIZE_MAP[10][2] = BSTR8;

    GROUP_VAR_SIZE_MAP[11][1] = BSTR8;
    GROUP_VAR_SIZE_MAP[11][2] = BSTR8 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[12][1] = UINT4 + BSTR1 + BSTR1 + UINT2 + UINT8 +
        UINT32 + UINT32 + UINT7 + BSTR1;
    GROUP_VAR_SIZE_MAP[12][2] = GROUP_VAR_SIZE_MAP[12][1];
    GROUP_VAR_SIZE_MAP[12][3] = BSTRn;

    GROUP_VAR_SIZE_MAP[13][1] = UINT7 + BSTR1;
    GROUP_VAR_SIZE_MAP[13][2] = UINT7 + BSTR1 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[20][1] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[20][2] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[20][3] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[20][4] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[20][5] = UINT32;
    GROUP_VAR_SIZE_MAP[20][6] = UINT16;
    GROUP_VAR_SIZE_MAP[20][7] = UINT32;
    GROUP_VAR_SIZE_MAP[20][8] = UINT16;

    GROUP_VAR_SIZE_MAP[21][1] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[21][2] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[21][3] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[21][4] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[21][5] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[21][6] = BSTR8 + UINT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[21][7] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[21][8] = BSTR8 + UINT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[21][9] = UINT32;
    GROUP_VAR_SIZE_MAP[21][10] = UINT16;
    GROUP_VAR_SIZE_MAP[21][11] = UINT32;
    GROUP_VAR_SIZE_MAP[21][12] = UINT16;

    GROUP_VAR_SIZE_MAP[22][1] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[22][2] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[22][3] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[22][4] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[22][5] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[22][6] = BSTR8 + UINT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[22][7] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[22][8] = BSTR8 + UINT16 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[23][1] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[23][2] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[23][3] = BSTR8 + UINT32;
    GROUP_VAR_SIZE_MAP[23][4] = BSTR8 + UINT16;
    GROUP_VAR_SIZE_MAP[23][5] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[23][6] = BSTR8 + UINT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[23][7] = BSTR8 + UINT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[23][8] = BSTR8 + UINT16 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[30][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[30][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[30][3] = INT32;
    GROUP_VAR_SIZE_MAP[30][4] = INT16;
    GROUP_VAR_SIZE_MAP[30][5] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[30][6] = BSTR8 + FLT64;

    GROUP_VAR_SIZE_MAP[31][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[31][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[31][3] = BSTR8 + INT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[31][4] = BSTR8 + INT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[31][5] = INT32;
    GROUP_VAR_SIZE_MAP[31][6] = INT16;
    GROUP_VAR_SIZE_MAP[31][7] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[31][8] = BSTR8 + FLT64;

    GROUP_VAR_SIZE_MAP[32][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[32][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[32][3] = BSTR8 + INT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[32][4] = BSTR8 + INT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[32][5] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[32][6] = BSTR8 + FLT64;
    GROUP_VAR_SIZE_MAP[32][7] = BSTR8 + FLT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[32][8] = BSTR8 + FLT32 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[33][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[33][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[33][3] = BSTR8 + INT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[33][4] = BSTR8 + INT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[33][5] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[33][6] = BSTR8 + FLT64;
    GROUP_VAR_SIZE_MAP[33][7] = BSTR8 + FLT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[33][8] = BSTR8 + FLT32 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[34][1] = UINT16;
    GROUP_VAR_SIZE_MAP[34][2] = UINT32;
    GROUP_VAR_SIZE_MAP[34][3] = FLT32;

    GROUP_VAR_SIZE_MAP[40][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[40][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[40][3] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[40][4] = BSTR8 + FLT64;

    GROUP_VAR_SIZE_MAP[41][1] = INT32 + UINT8;
    GROUP_VAR_SIZE_MAP[41][2] = INT16 + UINT8;
    GROUP_VAR_SIZE_MAP[41][3] = FLT32 + UINT8;
    GROUP_VAR_SIZE_MAP[41][4] = FLT64 + UINT8;

    GROUP_VAR_SIZE_MAP[42][1] = BSTR8 + INT32;
    GROUP_VAR_SIZE_MAP[42][2] = BSTR8 + INT16;
    GROUP_VAR_SIZE_MAP[42][3] = BSTR8 + INT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[42][4] = BSTR8 + INT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[42][5] = BSTR8 + FLT32;
    GROUP_VAR_SIZE_MAP[42][6] = BSTR8 + FLT64;
    GROUP_VAR_SIZE_MAP[42][7] = BSTR8 + FLT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[42][8] = BSTR8 + FLT64 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[43][1] = UINT7 + BSTR1 + INT32;
    GROUP_VAR_SIZE_MAP[43][2] = UINT7 + BSTR1 + INT16;
    GROUP_VAR_SIZE_MAP[43][3] = UINT7 + BSTR1 + INT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[43][4] = UINT7 + BSTR1 + INT16 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[43][5] = UINT7 + BSTR1 + FLT32;
    GROUP_VAR_SIZE_MAP[43][6] = UINT7 + BSTR1 + FLT64;
    GROUP_VAR_SIZE_MAP[43][7] = UINT7 + BSTR1 + FLT32 + DNP3TIME;
    GROUP_VAR_SIZE_MAP[43][8] = UINT7 + BSTR1 + FLT64 + DNP3TIME;

    GROUP_VAR_SIZE_MAP[50][1] = DNP3TIME;
    GROUP_VAR_SIZE_MAP[50][2] = DNP3TIME + UINT32;
    GROUP_VAR_SIZE_MAP[50][3] = DNP3TIME;
    GROUP_VAR_SIZE_MAP[50][4] = DNP3TIME + UINT32 + UINT8;

    GROUP_VAR_SIZE_MAP[51][1] = DNP3TIME;
    GROUP_VAR_SIZE_MAP[51][2] = DNP3TIME;

    GROUP_VAR_SIZE_MAP[52][1] = UINT16;
    GROUP_VAR_SIZE_MAP[52][1] = UINT16;

    GROUP_VAR_SIZE_MAP[60][1] = 0;
    GROUP_VAR_SIZE_MAP[60][2] = 0;
    GROUP_VAR_SIZE_MAP[60][3] = 0;
    GROUP_VAR_SIZE_MAP[60][4] = 0;

    GROUP_VAR_SIZE_MAP[80][1] = BSTRn;

    GROUP_VAR_SIZE_MAP[81][1] = UINT7 + BSTR1 + UINT8 + UINT8;

    GROUP_VAR_SIZE_MAP[102][1] = UINT8;

    GROUP_VAR_SIZE_MAP[121][1] = BSTR8 + UINT16 + UINT32;

    GROUP_VAR_SIZE_MAP[122][1] = BSTR8 + UINT16 + UINT32;
    GROUP_VAR_SIZE_MAP[122][2] = BSTR8 + UINT16 + UINT32 + DNP3TIME;
}

/* Map DNP3 object prefix codes to their size.
 * Table 4-4, IEEE 1815-2012. */
static int DNP3_OBJ_PREFIX_CODE_MAP[] = {
    0,                          /* 0. No prefix. */
    1,                          /* 1. 1 octet. */
    2,                          /* 2. 2 octet. */
    4,                          /* 3. 4 octet. */
    1,                          /* 4. 1 octet. */
    2,                          /* 5. 2 octet. */
    4,                          /* 6. 4 octet. */
    -1,                         /* 7. Reserved. */
};

/* Decoder event map. */
SCEnumCharMap dnp3_decoder_event_table[] = {
    {"FLOODED",           DNP3_DECODER_EVENT_FLOODED},
    {"LEN_TOO_SMALL",     DNP3_DECODER_EVENT_LEN_TOO_SMALL},
    {"BAD_LINK_CRC",      DNP3_DECODER_EVENT_BAD_LINK_CRC},
    {"BAD_TRANSPORT_CRC", DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC},
    {NULL, -1},
};

/* Some DNP3 servers start with a banner. */
static const char banner[] = "DNP3";

/* DNP3 values are stored in little endian on the wire, so swapping will be
 * needed on big endian architectures. */
#if __BYTE_ORDER == __BIG_ENDIAN
#define dnp3_swap16(x) SCByteSwap16(x)
#define dnp3_swap32(x) SCByteSwap32(x)
#elif __BYTE_ORDER == __LITTLE_ENDIAN
#define dnp3_swap16(x) x
#define dnp3_swap32(x) x
#endif

/* Calculate the next transport sequence number. */
#define NEXT_TRAN_SEQNO(current) ((current + 1) % DNP3_MAX_TRAN_SEQNO)

/* Calculate the next application sequence number. */
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
        SCLogDebug("Length too small to be a DNP3 header.");
        return ALPROTO_UNKNOWN;
    }

    /* May be a banner. */
    if (DNP3ContainsBanner(input, len)) {
        SCLogDebug("Packet contains a DNP3 banner.");
        goto end;
    }

    /* Verify start value (from AN2013-004b). */
    if (!DNP3CheckStartBytes(hdr)) {
        SCLogDebug("Invalid start bytes.");
        return ALPROTO_FAILED;
    }

    /* Verify minimum length. */
    if (hdr->len < DNP3_MIN_LEN) {
        SCLogDebug("Packet too small to be a valid DNP3 fragment.");
        return ALPROTO_FAILED;
    }

end:
    SCLogDebug("Detected DNP3.");
    return ALPROTO_DNP3;
}

/**
 * \brief Calculate a DNP3 session hash for the session hash table.
 */
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

/**
 * \brief Compare DNP3 session hash - for the session hash table.
 */
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
 * \brief Reassemble the application layer by stripping the CRCs.
 *
 * \param input Input buffer starting at the transport header (which
 *    will be removed from the output).
 * \param input_len Length of the input buffer.
 * \param output Pointer to output buffer (may be realloc'd).
 * \param output_len Pointer to output length.
 *
 * \retval Pointer to output buffer if successful, otherwise NULL.
 */
static uint8_t *DNP3ReassembleApplicationLayer(uint8_t *input,
    uint32_t input_len, uint8_t **output, uint32_t *output_len)
{
    int len = (input_len / (DNP3_BLOCK_SIZE + DNP3_CRC_LEN)) * DNP3_BLOCK_SIZE;
    int rem = input_len % (DNP3_BLOCK_SIZE + DNP3_CRC_LEN);

    if (rem) {
        /* The remainder must be at least one byte plus a CRC. */
        if (rem < 3) {
            return NULL;
        }
        len += rem + DNP3_CRC_LEN;
    }

    /* Remove one byte for the transport header which won't be
     * included in the output. */
    len--;

    if (*output == NULL) {
        *output = SCCalloc(1, len);
        if (unlikely(*output == NULL)) {
            return NULL;
        }
    }
    else {
        uint8_t *ptr = SCRealloc(*output, (size_t)(*output_len + len));
        if (unlikely(ptr == NULL)) {
            SCFree(*output);
            return NULL;
        }
        *output = ptr;
    }

    int offset = 0, block_size;
    while ((uint32_t)offset < input_len) {
        if (input_len - offset > DNP3_BLOCK_SIZE + DNP3_CRC_LEN) {
            block_size = DNP3_BLOCK_SIZE + DNP3_CRC_LEN;
        }
        else {
            block_size = input_len - offset;
        }

        /* For the first block we trim the leading transport header. */
        if (offset == 0) {
            memcpy(*output + *output_len, input + offset + 1,
                block_size - DNP3_CRC_LEN - 1);
            *output_len += block_size - DNP3_CRC_LEN - 1;
        }
        else {
            memcpy(*output + *output_len, input + offset,
                block_size - DNP3_CRC_LEN);
            *output_len += block_size - DNP3_CRC_LEN;
        }
        offset += block_size;
    }

    return *output;
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
    TAILQ_INIT(&tx->request_objects);
    TAILQ_INIT(&tx->response_objects);
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
    uint32_t frame_len = 0;
    int rem;

    /* Subtract the 5 bytes of the header that are included in the
     * length. */
    length -= DNP3_LINK_HDR_LEN;

    rem = length % DNP3_BLOCK_SIZE;
    frame_len = (length / DNP3_BLOCK_SIZE) * (DNP3_BLOCK_SIZE + DNP3_CRC_LEN);
    if (rem) {
        frame_len += rem + DNP3_CRC_LEN;
    }

    return frame_len + sizeof(DNP3LinkHeader);
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

/**
 * DNP3 buffer helper function - reset the buffer.
 */
static void DNP3BufferReset(DNP3Buffer *buffer)
{
    buffer->offset = 0;
    buffer->len = 0;
}

/**
 * DNP3 buffer helper function - add data to the buffer, making the buffer
 * larger if needed.
 */
static int DNP3BufferAdd(DNP3Buffer *buffer, uint8_t *buf, uint32_t len)
{
    if (buffer->size == 0) {
        buffer->buffer = SCCalloc(1, len);
        if (unlikely(buffer->buffer == NULL)) {
            return 0;
        }
        buffer->size = len;
    }
    else if (buffer->len + len > buffer->size) {
        uint8_t *tmp = SCRealloc(buffer->buffer, buffer->len + len);
        if (unlikely(tmp == NULL)) {
            return 0;
        }
        buffer->buffer = tmp;
        buffer->size = buffer->len + len;
    }
    memcpy(buffer->buffer + buffer->len, buf, len);
    buffer->len += len;

    return 1;
}

/**
 * DNP3 buffer helper function - pulls up the data to the beginning of the
 * buffer to make room at the end for more data.
 */
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
 * \brief Decode DNP3 application objects.
 *
 * This function decoded known DNP3 application objects. As the
 * protocol isn't self describing, we can only decode the buffer while
 * the application objects are known.  As soon as an unknown
 * group/variation is hit, we must stop processing.
 *
 * \param buf the input buffer
 * \param len length of the input buffer
 * \param objects pointer to list where decoded objects will be stored.
 *
 * \retval 1 if all objects decoded, 0 if all objects could not be decoded (
 *    unknown group/variations)
 */
static int DNP3DecodeApplicationObjects(uint8_t *buf, uint32_t len,
    DNP3ObjectList *objects)
{
    int retval = 0;

    if (buf == NULL || len == 0) {
        return 1;
    }

    while (len) {
        uint32_t offset = 0;

        if (len < sizeof(DNP3ObjHeader)) {
            SCLogInfo(
                "Insufficient data: not enough data for object header (%d).",
                len);
            SCLogInfo("%02x", buf[2]);
            goto done;
        }
        DNP3ObjHeader *header = (DNP3ObjHeader *)buf;
        offset += sizeof(DNP3ObjHeader);

        DNP3Object *object = SCCalloc(1, sizeof(*object));
        if (object != NULL) {
            object->group = header->group;
            object->variation = header->variation;
            TAILQ_INSERT_TAIL(objects, object, next);
        }

        SCLogDebug("Group: 0x%02x (%d); Variation: 0x%02x (%d); "
            "Qualifier: 0x%02x (%d)",
            header->group, header->group,
            header->variation, header->variation,
            header->qualifier, header->qualifier);
        uint8_t prefix_code = DNP3_OBJ_PREFIX(header->qualifier);
        uint8_t range_code = DNP3_OBJ_RANGE(header->qualifier);
        object->prefix = DNP3_OBJ_PREFIX(header->qualifier);
        object->range = DNP3_OBJ_RANGE(header->qualifier);

        int prefix_len = DNP3_OBJ_PREFIX_CODE_MAP[prefix_code];
        if (prefix_len < 0) {
            goto unknown;
        }

        uint32_t count = 0;

        /* IEEE 1815-2012, Table 4-5. */
        switch (range_code) {
            case 0x00: {
                uint8_t start = buf[offset++];
                uint8_t stop = buf[offset++];
                count = stop - start + 1;
                break;
            }
            case 0x01: {
                uint16_t start = dnp3_swap16((uint16_t)(*buf));
                buf = buf + sizeof(uint16_t);
                uint16_t stop = dnp3_swap16((uint16_t)(*buf));
                count = stop - start + 1;
                break;
            }
            case 0x02: {
                uint32_t start = dnp3_swap32((uint32_t)(*buf));
                buf = buf + sizeof(uint32_t);
                uint32_t stop = dnp3_swap32((uint32_t)(*buf));
                count = stop - start + 1;
                break;
            }
            case 0x06:
                /* No range field. */
                count = 0;
                break;
            case 0x07:
                /* 1 octet count of objects. */
                count = buf[offset++];
                break;
            case 0x08: {
                /* 2 octet count of objects. */
                count = *(uint16_t *)(buf + offset);
                offset += sizeof(uint16_t);
                break;
            }
            case 0x03:
            case 0x04:
            case 0x05:
            case 0x09:
            case 0x0b:
                SCLogInfo("Range code 0x%02x not yet implemented.", range_code);
                goto done;
            default:
                SCLogInfo("Range code 0x%02x is reserved.", range_code);
                goto done;
        }

        if (count == 0) {
            goto next;
        }

        /* Get the size of the object - in bits. */
        int object_size = GROUP_VAR_SIZE_MAP[header->group][header->variation];
        if (object_size < 0) {
            goto unknown;
        }

        /* Calculate the full length of the object:
         * (prefix + object * size) * (number of items)
         * then round up to the nearest byte.
         */
        int object_len_bits = ((prefix_len * 8) + object_size) * count;
        int object_len = object_len_bits / 8;
        if (object_len_bits % 8 != 0) {
            object_len++;
        }
        if (offset + object_len > len) {
            SCLogInfo("Insufficient data to decode object %d:%d", header->group,
                header->variation);
            goto not_enough_data;
        }

        offset += object_len;
    next:

        object->data = SCCalloc(1, offset);
        if (object->data != NULL) {
            memcpy(object->data, buf, offset);
            object->len = offset;
        }

        buf += offset;
        len -= offset;

        continue;

        /* Can't continue on an unknown group or variation as we don't
         * know how far to advance the buffer. */

    unknown:
        SCLogInfo("Unknown variation 0x%02x (%d) for group 0x%02x (%d)",
            header->variation, header->variation, header->group, header->group);
        goto done;
    }

    /* All objects were decoded. */
    retval = 1;

not_enough_data:
done:
    return retval;
}

static int DNP3HandleRequestTransportLayer(DNP3State *dnp3, uint8_t *input,
    uint32_t input_len)
{
    SCEnter();
    DNP3LinkHeader *header;
    DNP3Session *session;
    DNP3TransportHeader th;
    DNP3Transaction *tx;
    DNP3ApplicationHeader *ah;
    uint32_t offset = 0;
    uint32_t th_offset = 0;

    header = (DNP3LinkHeader *)input;
    offset += sizeof(DNP3LinkHeader);

    th = input[offset];
    th_offset = offset++;

    session = DNP3SessionGet(dnp3, header);
    if (unlikely(session == NULL)) {
        goto error;
    }

    if (!DNP3_TRANSPORT_FIR(th)) {
        /* Need to look further into multi-segment fragments from the master. */
        SCLogInfo("Unexpected multi-frame fragment from master.");
        goto done;
    }

    ah = (DNP3ApplicationHeader *)(input + offset);
    offset += sizeof(DNP3ApplicationHeader);

    tx = DNP3TxAlloc(dnp3);
    if (unlikely(tx == NULL)) {
        goto error;
    }
    tx->session = session;
    session->last_tx = tx;
    tx->app_seqno = DNP3_APP_SEQ(ah->control);
    tx->app_function_code = ah->function_code;
    tx->request_ll_control = header->control;
    tx->request_th = th;
    tx->request_al_control = ah->control;
    tx->request_al_fc = ah->function_code;

    /* Some function codes do not expect a reply. */
    switch (ah->function_code) {
        case DNP3_APP_FC_CONFIRM:
        case DNP3_APP_FC_DIR_OPERATE_NR:
        case DNP3_APP_FC_FREEZE_NR:
        case DNP3_APP_FC_FREEZE_CLEAR_NR:
        case DNP3_APP_FC_FREEZE_AT_TIME_NR:
        case DNP3_APP_FC_AUTH_REQ_NR:
            tx->response_done = 1;
        default:
            break;
    }

    /* Reassemble the request buffer. */
    tx->request_buffer = DNP3ReassembleApplicationLayer(
        input + th_offset, // + sizeof(DNP3TransportHeader),
            input_len - th_offset, // - sizeof(DNP3TransportHeader),
            &tx->request_buffer, &tx->request_buffer_len);
    tx->request_done = 1;

    if (DNP3DecodeApplicationObjects(
        tx->request_buffer + sizeof(DNP3ApplicationHeader),
            tx->request_buffer_len - sizeof(DNP3ApplicationHeader),
            &tx->request_objects)) {
        tx->request_decode_complete = 1;
    }

done:
    SCReturnInt(1);
error:
    SCReturnInt(0);
}

/**
 * \brief Decode the DNP3 request link layer.
 *
 * \retval number of bytes processed.
 */
static int DNP3HandleRequestLinkLayer(DNP3State *dnp3, uint8_t *input,
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
            SCLogInfo("Bad start bytes.");
            goto error;
        }

        if (!DNP3CheckLinkHeaderCRC(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            SCLogDebug("Bad request link header CRC.");
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_LINK_CRC);
            goto error;
        }

        uint32_t frame_len = DNP3CalculateUnassembledLength(header->len);
        if (input_len < frame_len) {
            /* Insufficient, just break - will wait for more data. */
            break;
        }

        /* Ignore non-user data for now. */
        if (!DNP3IsUserData(header)) {
            SCLogDebug("Fragment is not user data, ignoring.");
            goto next;
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

        if (!DNP3CheckUserDataCRCs(input + offset, frame_len - offset)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            SCLogInfo("Bad transport CRC");
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC);
            goto error;
        }

        /* Frame looks OK, move on to transport layer handling. */
        DNP3HandleRequestTransportLayer(dnp3, input, frame_len);

    next:
        input += frame_len;
        input_len -= frame_len;
        processed += frame_len;
    }

    SCReturnInt(processed);
error:
    SCReturnInt(-1);
}

/**
 * \brief Handle incoming request data.
 *
 * The actual request PDU parsing is done in
 * DNP3HandleRequestLinkLayer. This function takes care of buffering TCP
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
        if (!DNP3BufferAdd(buffer, input, input_len)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory to buffer "
                "DNP3 request data");
            goto error;
        }
        input_len = 0;
        processed = DNP3HandleRequestLinkLayer(dnp3,
            buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        if (processed < 0) {
            goto error;
        }
        buffer->offset += processed;
        DNP3BufferTrim(buffer);
    }
    else {
        processed = DNP3HandleRequestLinkLayer(dnp3, input, input_len);
        if (processed < 0) {
            goto error;
        }
        input += processed;
        input_len -= processed;

        /* Not all data was processed, buffer it. */
        if (input_len) {
            if (!DNP3BufferAdd(buffer, input, input_len)) {
                SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory to buffer DNP3 request data");
                goto error;
            }
        }
    }

    SCReturnInt(1);

error:
    /* Reset the buffer. */
    DNP3BufferReset(buffer);
    SCReturnInt(-1);
}

static int DNP3HandleResponseTransportLayer(DNP3State *dnp3, uint8_t *input,
    uint32_t input_len)
{
    SCEnter();
    DNP3LinkHeader *header;
    DNP3Transaction *tx;
    uint32_t offset = 0;

    header = (DNP3LinkHeader *)input;
    offset += sizeof(DNP3LinkHeader);

    DNP3Session *session = DNP3SessionGet(dnp3, header);
    if (unlikely(session == NULL)) {
        goto error;
    }

    DNP3TransportHeader th = input[offset];
    uint32_t th_offset = offset++;

    if (!DNP3_TRANSPORT_FIR(th)) {
        /* This frame is a continuation of an existing response, there
         * will be no application header. Add to the last transaction
         * response. */
        tx = session->last_tx;

        if (tx == NULL) {
            /* Subsequent segment without a transaction. */
            goto done;
        }

        /* Check the sequence number.  If its not what is expected,
         * wrap up the existing transaction. */
        if (NEXT_TRAN_SEQNO(session->outstation_tran_seqno) !=
            DNP3_TRANSPORT_SEQ(th)) {
            tx->response_done = 1;
            goto done;
        }

        tx->response_buffer = DNP3ReassembleApplicationLayer(
            input + th_offset, input_len - th_offset,
                &tx->response_buffer, &tx->response_buffer_len);
    }
    else {
        DNP3ApplicationHeader *ah =
            (DNP3ApplicationHeader *)(input + offset);
        offset += sizeof(DNP3ApplicationHeader);

        DNP3InternalInd *iin = (DNP3InternalInd *)(input + offset);
        offset += sizeof(DNP3InternalInd);

        if (ah->function_code == DNP3_APP_FC_UNSOLICITED_RESP) {
            tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            tx->session = session;
            session->last_tx = tx;
            tx->app_seqno = DNP3_APP_SEQ(ah->control);
            tx->app_function_code = ah->function_code;
        }
        else {
            tx = DNP3FindTransaction(dnp3, session,
                DNP3_APP_SEQ(ah->control));
            if (tx == NULL) {
                SCLogInfo("Failed to find transaction, ignoring.");
                goto done;
            }
        }

        tx->response_ll_control = header->control;
        tx->response_th = th;
        tx->response_al_control = ah->control;
        tx->response_al_fc = ah->function_code;
        tx->iin1 = iin->iin1;
        tx->iin2 = iin->iin2;
        tx->response_buffer = DNP3ReassembleApplicationLayer(
            input + th_offset, input_len - th_offset,
                &tx->response_buffer, &tx->response_buffer_len);
    }

    /* If no more frames are expected, mark as done. */
    if (DNP3_TRANSPORT_FIN(th)) {
        tx->response_done = 1;
    }

    if (tx->response_done) {
        offset = sizeof(DNP3ApplicationHeader) + sizeof(DNP3InternalInd);
        if (DNP3DecodeApplicationObjects(tx->response_buffer + offset,
            tx->response_buffer_len - offset,
                &tx->response_objects)) {
            tx->response_decode_complete = 1;
        }
    }

done:
    session->outstation_tran_seqno = DNP3_TRANSPORT_SEQ(th);
    SCReturnInt(1);
error:
    SCReturnInt(0);
}

/**
 * \brief Handle the DNP3 link layer.
 *
 * Decodes and validates DNP3 frames.
 */
static int DNP3HandleResponseLinkLayer(DNP3State *dnp3, uint8_t *input,
    uint32_t input_len)
{
    SCEnter();
    uint32_t processed = 0;

    while (input_len) {

        /* Need at least enough bytes for a DNP3 header. */
        if (input_len < sizeof(DNP3LinkHeader)) {
            SCLogDebug("Not enough data for valid header.");
            break;
        }

        DNP3LinkHeader *header = (DNP3LinkHeader *)input;

        if (!DNP3CheckStartBytes(header)) {
            SCLogInfo("Invalid start bytes.");
            goto error;
        }

        if (!DNP3CheckLinkHeaderCRC(header)) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            SCLogInfo("Bad link CRC");
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_LINK_CRC);
            goto error;
        }

        /* Calculate the number of bytes needed to for this frame. */
        uint32_t frame_len = DNP3CalculateUnassembledLength(header->len);
        if (input_len < frame_len) {
            SCLogInfo("Not enough data for complete frame: header->len = %d; "
                "have %d, need %d", header->len, input_len, frame_len);
            break;
        }

        /* Only handle user data frames for now. */
        if (!DNP3IsUserData(header)) {
            goto next;
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
            SCLogDebug("Link layer length not long enough for user data.");
            goto error;
        }

        if (!DNP3CheckUserDataCRCs(input + sizeof(DNP3LinkHeader),
                frame_len - sizeof(DNP3LinkHeader))) {
            /* Allocate a transaction just for creating an alert. */
            DNP3Transaction *tx = DNP3TxAlloc(dnp3);
            if (unlikely(tx == NULL)) {
                goto error;
            }
            SCLogDebug("Bad response transport CRC.");
            DNP3SetEvent(dnp3, DNP3_DECODER_EVENT_BAD_TRANSPORT_CRC);
            goto error;
        }

        /* Frame looks OK, move on to transport layer handling. */
        DNP3HandleResponseTransportLayer(dnp3, input, frame_len);

    next:
        /* Advance the input buffer. */
        input += frame_len;
        input_len -= frame_len;
        processed += frame_len;
    }

    SCReturnInt(processed);
error:
    SCReturnInt(-1);
}

/**
 * \brief Parse incoming data.
 *
 * This is the entry function for DNP3 application layer data. Its
 * main responsibility is buffering incoming data that cannot be
 * processed.
 *
 * See DNP3ParseResponsePDUs for DNP3 frame handling.
 */
static int DNP3ParseResponse(Flow *f, void *state, AppLayerParserState *pstate,
    uint8_t *input, uint32_t input_len, void *local_data)
{
    SCEnter();
    DNP3State *dnp3 = (DNP3State *)state;
    DNP3Buffer *buffer = &dnp3->response_buffer;
    int processed;

    if (buffer->len) {
        if (!DNP3BufferAdd(buffer, input, input_len)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Failed to allocate memory to buffer "
                "DNP3 response data");
            goto error;
        }
        input_len = 0;
        processed = DNP3HandleResponseLinkLayer(dnp3,
            buffer->buffer + buffer->offset,
            buffer->len - buffer->offset);
        if (processed < 0) {
            goto error;
        }
        buffer->offset += processed;
        DNP3BufferTrim(buffer);
    }
    else {

        /* Check if this is a banner, ignore if it is. */
        if (DNP3ContainsBanner(input, input_len)) {
            goto done;
        }

        processed = DNP3HandleResponseLinkLayer(dnp3, input, input_len);
        if (processed < 0) {
            goto error;
        }
        input += processed;
        input_len -= processed;
        if (input_len) {
            if (!DNP3BufferAdd(buffer, input, input_len)) {
                SCLogError(SC_ERR_MEM_ALLOC,
                    "Failed to allocate memory to buffer DNP3 response data");
                goto error;
            }
        }
    }

done:
    SCReturnInt(1);

error:
    /* An error occurred while processing DNP3 frames.  Dump the
     * buffer as we can't be assured that they are valid anymore. */
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

/**
 * \brief Free all the objects in a DNP3ObjectList.
 */
static void DNP3TxFreeObjects(DNP3ObjectList *objects)
{
    DNP3Object *object;

    while ((object = TAILQ_FIRST(objects)) != NULL) {
        TAILQ_REMOVE(objects, object, next);
        SCFree(object);
    }
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

    DNP3TxFreeObjects(&tx->request_objects);
    DNP3TxFreeObjects(&tx->response_objects);

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
        if (dnp3->request_buffer.buffer != NULL) {
            SCFree(dnp3->request_buffer.buffer);
        }
        if (dnp3->response_buffer.buffer != NULL) {
            SCFree(dnp3->response_buffer.buffer);
        }
        SCFree(dnp3);
    }
    SCReturn;
}

static int DNP3GetAlstateProgress(void *tx, uint8_t direction) {
    SCEnter();
    DNP3Transaction *dnp3tx = (DNP3Transaction *)tx;
    DNP3State *dnp3 = dnp3tx->dnp3;

    /* If flooded, "ack" old transactions. */
    if (dnp3->flooded && (dnp3->transaction_max -
            dnp3tx->tx_num >= DNP3_DEFAULT_REQ_FLOOD_COUNT)) {
        SCLogDebug("flooded: returning tx as done.");
        SCReturnInt(1);
    }

    if (direction & STREAM_TOSERVER && dnp3tx->request_done) {
        SCReturnInt(1);
    }
    else if (dnp3tx->response_done) {
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

static int DNP3SetTxDetectState(void *state, void *vtx, DetectEngineState *s)
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
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_DNP3, NULL,
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

#if 0
        /* Limit probing to packets to the server. */
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP,
            ALPROTO_DNP3, STREAM_TOSERVER);
#endif

    }
    else {
        SCLogInfo("Parser disabled for protocol %s. "
            "Protocol detection still on.", proto_name);
    }

    DNP3InitGroupVarSizeMap();

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
static int DNP3ReassembleApplicationLayerTest01(void)
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
              0xc9, 0x05, 0x0c,
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

    uint8_t *output = NULL;
    FAIL_IF(output != NULL);

    uint32_t reassembled_len = 0;
    uint8_t *reassembled = DNP3ReassembleApplicationLayer(payload,
        sizeof(payload), &output, &reassembled_len);
    FAIL_IF(output == NULL);
    FAIL_IF(output != reassembled);
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
    FAIL_IF(tx->request_buffer_len != 20);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
            response, sizeof(response))) {
        SCMutexUnlock(&flow.m);
        goto end;
    }
    SCMutexUnlock(&flow.m);
    FAIL_IF(DNP3GetTx(state, 0) != tx);
    FAIL_IF(!tx->response_done);
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
        FAIL_IF(1);
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
    FAIL_IF(!tx->response_done)
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_UNSOLICITED_RESP);

    SCMutexLock(&flow.m);
    if (AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOSERVER,
            confirm, sizeof(confirm))) {
        SCMutexUnlock(&flow.m);
        FAIL_IF(1);
    }
    SCMutexUnlock(&flow.m);
    FAIL_IF(DNP3GetTx(state, 0) != tx);
    FAIL_IF(!tx->response_done);
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
    FAIL_IF(tx->request_buffer_len != 20);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);
    FAIL_IF(tx->response_done);

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
    FAIL_IF(tx->request_buffer_len != 20);
    FAIL_IF(tx->app_function_code != DNP3_APP_FC_DIR_OPERATE);

    /* Buffer should be empty. */
    FAIL_IF(state->request_buffer.len != 0);

    /* Send partial response. */
    SCMutexLock(&flow.m);
    r = AppLayerParserParse(alp_tctx, &flow, ALPROTO_DNP3, STREAM_TOCLIENT,
        response_partial1, sizeof(response_partial1));
    SCMutexUnlock(&flow.m);
    FAIL_IF(tx->response_done);
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
    FAIL_IF(!tx->response_done);
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

    /* Unsolicited response 1. */
    uint8_t unsol_response1[] = {
        0x05, 0x64, 0x16, 0x44, 0x01, 0x00, 0x02, 0x00,
        0x89, 0xe5, 0xc4, 0xfa, 0x82, 0x00, 0x00, 0x02,
        0x02, 0x17, 0x01, 0x01, 0x81, 0xa7, 0x75, 0xd8,
        0x32, 0x4c, 0x81, 0x3e, 0x01, 0xa1, 0xc9,
    };

    /* Unsolicited response 2. */
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
    UtRegisterTest("DNP3ReassembleApplicationLayerTest01",
        DNP3ReassembleApplicationLayerTest01, 1);
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
