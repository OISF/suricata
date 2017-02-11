/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Kirby Kuehl <kkuehl@gmail.com>
 *
 * \brief SMBv1 parser/decoder
 */

#include "suricata-common.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"
#include "util-debug.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-memcmp.h"

#include "app-layer-smb.h"

enum {
    SMB_FIELD_NONE = 0,
    SMB_PARSE_NBSS_HEADER,
    SMB_PARSE_SMB_HEADER,
    SMB_PARSE_GET_WORDCOUNT,
    SMB_PARSE_WORDCOUNT,
    SMB_PARSE_GET_BYTECOUNT,
    SMB_PARSE_BYTECOUNT,
    /* must be last */
    SMB_FIELD_MAX,
};

/**
 *  \brief SMB Write AndX Request Parsing
 */
/* For WriteAndX we need to get writeandxdataoffset */
static uint32_t SMBParseWriteAndX(Flow *f, void *smb_state,
                                  AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    switch (sstate->andx.andxbytesprocessed) {
        case 0:
            sstate->andx.paddingparsed = 0;
            if (input_len >= 28) {
                sstate->andx.andxcommand = *p;
                sstate->andx.andxoffset = *(p + 2);
                sstate->andx.andxoffset |= *(p + 3) << 8;
                sstate->andx.datalengthhigh = *(p + 18);
                sstate->andx.datalengthhigh |= *(p + 19) << 8;
                sstate->andx.datalength = *(p + 20);
                sstate->andx.datalength |= *(p + 21) << 8;
                sstate->andx.dataoffset = *(p + 22);
                sstate->andx.dataoffset |= *(p + 23) << 8;
                sstate->andx.dataoffset |= (uint64_t) *(p + 24) << 56;
                sstate->andx.dataoffset |= (uint64_t) *(p + 25) << 48;
                sstate->andx.dataoffset |= (uint64_t) *(p + 26) << 40;
                sstate->andx.dataoffset |= (uint64_t) *(p + 27) << 32;
                sstate->bytesprocessed += 28;
                SCReturnUInt(28U);
            } else {
                sstate->andx.andxcommand = *(p++);
                if (!(--input_len))
                    break;
            }
            /* fall through */
        case 1:
            p++; // Reserved
            if (!(--input_len))
                break;
            /* fall through */
        case 2:
            sstate->andx.andxoffset = *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 3:
            sstate->andx.andxoffset |= *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 4:
            // SMB_COM_WRITE_ANDX Fid 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 5:
            // SMB_COM_WRITE_ANDX Fid 2
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 6:
            // SMB_COM_WRITE_ANDX Offset 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 7:
            // SMB_COM_WRITE_ANDX Offset 2
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 8:
            // SMB_COM_WRITE_ANDX Offset 3
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 9:
            // SMB_COM_WRITE_ANDX Offset 4
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 10:
            // SMB_COM_WRITE_ANDX Reserved 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 11:
            // SMB_COM_WRITE_ANDX Reserved 2
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 12:
            // SMB_COM_WRITE_ANDX Reserved 3
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 13:
            // SMB_COM_WRITE_ANDX Reserved 4
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 14:
            // SMB_COM_WRITE_ANDX WriteMode 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 15:
            // SMB_COM_WRITE_ANDX WriteMode 2
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 16:
            // SMB_COM_WRITE_ANDX BytesRemaining 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 17:
            // SMB_COM_WRITE_ANDX BytesRemaining 2
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 18:
            // DataLengthHigh 1
            sstate->andx.datalengthhigh = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 19:
            // DataLengthHigh 2
            sstate->andx.datalengthhigh |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 20:
            // DataLength 1
            sstate->andx.datalength = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 21:
            // DataLength 2
            sstate->andx.datalength |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 22:
            sstate->andx.dataoffset = *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 23:
            sstate->andx.dataoffset |= *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 24:
            sstate->andx.dataoffset |= (uint64_t) *(p++) << 56;
            if (!(--input_len))
                break;
            /* fall through */
        case 25:
            sstate->andx.dataoffset |= (uint64_t) *(p++) << 48;
            if (!(--input_len))
                break;
            /* fall through */
        case 26:
            sstate->andx.dataoffset |= (uint64_t) *(p++) << 40;
            if (!(--input_len))
                break;
            /* fall through */
        case 27:
            sstate->andx.dataoffset |= (uint64_t) *(p++) << 32;
            --input_len;
            break;
            /* fall through */
        default:
		sstate->bytesprocessed++;
		SCReturnUInt(1);
		break;
    }
    sstate->bytesprocessed += (p - input);
    SCReturnUInt((uint32_t)(p - input));
}

/**
 * \brief SMB Read AndX Response Parsing
 */
static uint32_t SMBParseReadAndX(Flow *f, void *smb_state,
                                 AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    switch (sstate->andx.andxbytesprocessed) {
        case 0:
            sstate->andx.paddingparsed = 0;
            if (input_len >= 24) {
                sstate->andx.andxcommand = *p;
                sstate->andx.andxoffset = *(p + 2);
                sstate->andx.andxoffset |= *(p + 3) << 8;
                sstate->andx.datalength = *(p + 10);
                sstate->andx.datalength |= *(p + 11) << 8;
                sstate->andx.dataoffset = *(p + 12);
                sstate->andx.dataoffset |= *(p + 13) << 8;
                sstate->andx.datalength |= (uint64_t) *(p + 14) << 32;
                sstate->andx.datalength |= (uint64_t) *(p + 15) << 40;
                sstate->andx.datalength |= (uint64_t) *(p + 16) << 48;
                sstate->andx.datalength |= (uint64_t) *(p + 17) << 56;
                sstate->bytesprocessed += 24;
                SCReturnUInt(24U);
            } else {
                sstate->andx.andxcommand = *(p++);
                if (!(--input_len))
                    break;
            }
            /* fall through */
        case 1:
            p++; // Reserved
            if (!(--input_len))
                break;
            /* fall through */
        case 2:
            sstate->andx.andxoffset |= *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 3:
            sstate->andx.andxoffset |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 4:
            // SMB_COM_READ_ANDX Remaining Reserved must be 0xff
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 5:
            // SMB_COM_READ_ANDX Remaining Reserved must be 0xff
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 6:
            // SMB_COM_READ_ANDX DataCompactionMode 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 7:
            // SMB_COM_READ_ANDX DataCompactionMode 1
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 8:
            // SMB_COM_READ_ANDX Reserved
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 9:
            // SMB_COM_READ_ANDX Reserved
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 10:
            sstate->andx.datalength = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 11:
            sstate->andx.datalength |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 12:
            sstate->andx.dataoffset = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 13:
            sstate->andx.dataoffset |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 14:
            sstate->andx.datalength |= *(p++) << 16;
            if (!(--input_len))
                break;
            /* fall through */
        case 15:
            sstate->andx.datalength |= *(p++) << 24;
            if (!(--input_len))
                break;
            /* fall through */
        case 16:
            // SMB_COM_READ_ANDX Reserved
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 17:
            // SMB_COM_READ_ANDX Reserved
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 18:
            // SMB_COM_READ_ANDX Reserved
            p++;
            --input_len;
            break;
        default:
            sstate->bytesprocessed++;
            SCReturnUInt(1);
            break;

    }
    sstate->bytesprocessed += (p - input);
    SCReturnUInt((uint32_t)(p - input));
}

static uint32_t SMBParseTransact(Flow *f, void *smb_state,
                                 AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    switch (sstate->andx.andxbytesprocessed) {
        case 0:
            sstate->andx.paddingparsed = 0;
            if (input_len >= 26) {
                sstate->andx.datalength = *(p + 22);
                sstate->andx.datalength |= *(p + 23) << 8;
                sstate->andx.dataoffset = *(p + 24);
                sstate->andx.dataoffset |= *(p + 25) << 8;
                sstate->andx.datalength |= (uint64_t) *(p + 14) << 56;
                sstate->andx.datalength |= (uint64_t) *(p + 15) << 48;
                sstate->andx.datalength |= (uint64_t) *(p + 16) << 40;
                sstate->andx.datalength |= (uint64_t) *(p + 17) << 32;
                sstate->bytesprocessed += 26;
                sstate->andx.andxbytesprocessed += 26;
                SCReturnUInt(sstate->wordcount.wordcount);
            } else {
                /* total parameter count 1 */
                p++;
                if (!(--input_len))
                    break;
            }
            /* fall through */
        case 1:
            /* total parameter count 2 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 2:
            /* total data count 1 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 3:
            /* total data count 2 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 4:
            /* max parameter count 1 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 5:
            /* max parameter count 2 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 6:
            /* max data count 1 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 7:
            /* max data count 2 */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 8:
            /* max setup count */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 9:
            /* Reserved */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 10:
            /* Flags */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 11:
            /* Flags */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 12:
            /* Timeout */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 13:
            /* Timeout */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 14:
            /* Timeout */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 15:
            /* Timeout */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 16:
            /* Reserved */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 17:
            /* Reserved */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 18:
            /* Parameter Count */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 19:
            /* Parameter Count */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 20:
            /* Parameter Offset */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 21:
            /* Parameter Offset */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 22:
            /* Data Count */
            sstate->andx.datalength = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 23:
            /* Data Count */
            sstate->andx.datalength |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 24:
            /* Data Offset */
            sstate->andx.dataoffset = *(p++);
            if (!(--input_len))
                break;
            /* fall through */
        case 25:
            /* Data Offset */
            sstate->andx.dataoffset |= *(p++) << 8;
            if (!(--input_len))
                break;
            /* fall through */
        case 26:
            /* Setup Count */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 27:
            /* Reserved */
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 28:
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 29:
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 30:
            p++;
            if (!(--input_len))
                break;
            /* fall through */
        case 31:
            p++;
            --input_len;
            break;
        default:
            SCLogDebug("SMB_COM_TRANSACTION AndX bytes processed is greater than 31 %u", sstate->andx.andxbytesprocessed);
            sstate->bytesprocessed++;
            sstate->andx.andxbytesprocessed++;
            SCReturnUInt(1);
            break;
    }
    sstate->bytesprocessed += (p - input);
    sstate->andx.andxbytesprocessed += (p - input);
    SCReturnUInt((uint32_t)(p - input));
}

/**
 * Handle variable length padding for WriteAndX and ReadAndX
 */
static uint32_t PaddingParser(void *smb_state, AppLayerParserState *pstate,
                              uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    /* Check for validity of dataoffset */
    if ((uint64_t)(sstate->bytesprocessed - NBSS_HDR_LEN) > sstate->andx.dataoffset) {
        sstate->andx.paddingparsed = 1;
        SCReturnUInt((uint32_t)(p - input));
    }
    while (((uint64_t)(sstate->bytesprocessed - NBSS_HDR_LEN) + (p - input))
            < sstate->andx.dataoffset && sstate->bytecount.bytecountleft--
            && input_len--) {
        SCLogDebug("0x%02x ", *p);
        p++;
    }
    if (((uint64_t)(sstate->bytesprocessed - NBSS_HDR_LEN) + (p - input))
            == sstate->andx.dataoffset) {
        sstate->andx.paddingparsed = 1;
    }
    sstate->bytesprocessed += (p - input);
    SCReturnUInt((uint32_t)(p - input));
}

/**
 * \brief Parse WriteAndX and ReadAndX Data
 * \retval -1 f DCERPCParser does not validate
 * \retval Number of bytes processed
 */
static int32_t DataParser(void *smb_state, AppLayerParserState *pstate,
                          uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    int32_t parsed = 0;

    if (sstate->andx.paddingparsed) {
        parsed = DCERPCParser(&sstate->ds.dcerpc, input, input_len);
        if (parsed == -1 || parsed > sstate->bytecount.bytecountleft || parsed > (int32_t)input_len) {
            SCReturnInt(-1);
        } else {
            sstate->dcerpc_present = 1;
            sstate->bytesprocessed += parsed;
            sstate->bytecount.bytecountleft -= parsed;
            input_len -= parsed;
            (void)input_len; /* for scan-build */
        }
    }
    SCReturnInt(parsed);
}

/**
 * \brief Obtain SMB WordCount which is 2 times the value.
 * Reset bytecount.bytecountbytes to 0.
 * Determine if this is an SMB AndX Command
 */
static uint32_t SMBGetWordCount(Flow *f, void *smb_state,
                                AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    if (input_len > 0) {
        SMBState *sstate = (SMBState *) smb_state;
        sstate->wordcount.wordcount = *(input) * 2;
        sstate->wordcount.wordcountleft = sstate->wordcount.wordcount;
        sstate->bytesprocessed++;
        sstate->bytecount.bytecountbytes = 0;
        sstate->andx.isandx = isAndX(sstate);
        SCLogDebug("Wordcount (%u):", sstate->wordcount.wordcount);
        SCReturnUInt(1U);
    }

    SCReturnUInt(0);
}

/*
 * Obtain SMB Bytecount. Handle the corner obfuscation case where a packet boundary
 * is after the first bytecount byte.
 */

static uint32_t SMBGetByteCount(Flow *f, void *smb_state,
                                AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    if (input_len && sstate->bytesprocessed == NBSS_HDR_LEN + SMB_HDR_LEN + 1
            + sstate->wordcount.wordcount) {
        sstate->bytecount.bytecount = *(p++);
        sstate->bytesprocessed++;
        --input_len;
    }

    if (input_len && sstate->bytesprocessed == NBSS_HDR_LEN + SMB_HDR_LEN + 2
            + sstate->wordcount.wordcount) {
        sstate->bytecount.bytecount |= *(p++) << 8;
        sstate->bytecount.bytecountleft = sstate->bytecount.bytecount;
        sstate->bytesprocessed++;
        SCLogDebug("Bytecount %u", sstate->bytecount.bytecount);
        --input_len;
    }

    SCReturnUInt((uint32_t)(p - input));
}

/**
 *  \brief SMBParseWordCount parses the SMB Wordcount portion of the SMB Transaction.
 *         until sstate->wordcount.wordcount bytes are parsed.
 */
static uint32_t SMBParseWordCount(Flow *f, void *smb_state,
                                  AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    uint32_t retval = 0;

    if ((sstate->smb.flags & SMB_FLAGS_SERVER_TO_REDIR) && sstate->smb.command
            == SMB_COM_READ_ANDX) {
        retval = SMBParseReadAndX(f, sstate, pstate, input, input_len);
        if (retval <= sstate->wordcount.wordcountleft) {
            sstate->wordcount.wordcountleft -= retval;
            SCLogDebug("SMB_COM_READ_ANDX returned %d - %u bytes at offset %"PRIu64"", retval, sstate->andx.datalength, sstate->andx.dataoffset);
            SCReturnUInt(retval);
        } else {
            SCReturnUInt(0U);
        }

    } else if (((sstate->smb.flags & SMB_FLAGS_SERVER_TO_REDIR) == 0)
            && sstate->smb.command == SMB_COM_WRITE_ANDX) {
        retval = SMBParseWriteAndX(f, sstate, pstate, input, input_len);
        if (retval <= sstate->wordcount.wordcountleft) {
            sstate->wordcount.wordcountleft -= retval;
            SCLogDebug("SMB_COM_WRITE_ANDX returned %d -  %u bytes at offset %"PRIu64"", retval, sstate->andx.datalength, sstate->andx.dataoffset);
            SCReturnUInt(retval);
        } else {
            SCReturnUInt(0U);
        }

    } else if (sstate->smb.command == SMB_COM_TRANSACTION) {
        retval = SMBParseTransact(f, sstate, pstate, input, input_len);
        if (retval <= sstate->wordcount.wordcountleft) {
            sstate->wordcount.wordcountleft -= retval;
            SCLogDebug("SMB_COM_TRANSACTION returned %d -  %u bytes at offset %"PRIu64"", retval, sstate->andx.datalength, sstate->andx.dataoffset);
            SCReturnUInt(retval);
        } else {
            SCReturnUInt(0U);
        }

    } else { /* Generic WordCount Handler */
        while (sstate->wordcount.wordcountleft-- && input_len--) {
            SCLogDebug("0x%02x wordcount %u/%u input_len %u", *p,
                            sstate->wordcount.wordcountleft,
                            sstate->wordcount.wordcount, input_len);
            p++;
        }
        sstate->bytesprocessed += (p - input);
        SCReturnUInt((uint32_t)(p - input));
    }
}

/**
 *  \brief SMBParseByteCount parses the SMB ByteCount portion of the SMB Transaction.
 *         until sstate->bytecount.bytecount bytes are parsed.
 */
static uint32_t SMBParseByteCount(Flow *f, void *smb_state,
                                  AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    uint32_t ures = 0; /* unsigned */
    int32_t sres = 0; /* signed */
    uint32_t parsed = 0;

    if (((sstate->smb.flags & SMB_FLAGS_SERVER_TO_REDIR) &&
                sstate->smb.command == SMB_COM_READ_ANDX) ||
            (((sstate->smb.flags & SMB_FLAGS_SERVER_TO_REDIR) == 0)
             && sstate->smb.command == SMB_COM_WRITE_ANDX) ||
            (sstate->smb.command == SMB_COM_TRANSACTION))
    {
        if (sstate->andx.paddingparsed == 0) {
            ures = PaddingParser(sstate, pstate, input + parsed, input_len);
            if (ures <= input_len) {
                parsed += ures;
                input_len -= ures;
            } else {
                SCReturnUInt(0U);
            }
        }

        if (sstate->andx.datalength && input_len) {
		/* Uncomment the next line to help debug DCERPC over SMB */
		//hexdump(f, input + parsed, input_len);
            sres = DataParser(sstate, pstate, input + parsed, input_len);
            if (sres != -1 && sres <= (int32_t)input_len) {
                parsed += (uint32_t)sres;
                (void)parsed; /* for scan-build */
                input_len -= (uint32_t)sres;
                (void)input_len; /* for scan-build */
            } else { /* Did not Validate as DCERPC over SMB */
                while (sstate->bytecount.bytecountleft-- && input_len--) {
                    SCLogDebug("0x%02x bytecount %"PRIu16"/%"PRIu16" input_len %"PRIu32, *p,
                            sstate->bytecount.bytecountleft,
                            sstate->bytecount.bytecount, input_len);
                    p++;
                }
                sstate->bytesprocessed += (p - input);
                SCReturnUInt((p - input));
            }
        }
        SCReturnUInt(ures);
    }

    while (sstate->bytecount.bytecountleft-- && input_len--) {
        SCLogDebug("0x%02x bytecount %u/%u input_len %u", *p,
                sstate->bytecount.bytecountleft,
                sstate->bytecount.bytecount, input_len);
        p++;
    }
    sstate->bytesprocessed += (p - input);

    SCReturnUInt((p - input));
}

/**
 *  \brief Parse a NBSS header.
 *
 *  \retval 4 parsing of the header is done
 *  \retval 3 parsing partially done
 *  \retval 2 parsing partially done
 *  \retval 1 parsing partially done
 *  \retval 0 no input or already done
 */
static uint32_t NBSSParseHeader(Flow *f, void *smb_state,
                                AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    if (input_len > 0 && sstate->bytesprocessed < (NBSS_HDR_LEN - 1)) {
        switch (sstate->bytesprocessed) {
            case 0:
                /* Initialize */
                sstate->andx.andxcommand = SMB_NO_SECONDARY_ANDX_COMMAND;
                sstate->andx.maxchainedandx = 5;

                /* fast track for having all bytes (common case) */
                if (input_len >= NBSS_HDR_LEN) {
                    sstate->nbss.type = *p;
                    sstate->nbss.length = (*(p + 1) & 0x01) << 16;
                    sstate->nbss.length |= *(p + 2) << 8;
                    sstate->nbss.length |= *(p + 3);
                    sstate->bytesprocessed += NBSS_HDR_LEN;
                    SCReturnUInt(4U);
                } else {
                    sstate->nbss.type = *(p++);
                    if (!(--input_len))
                        break;
                }
                /* fall through */
            case 1:
                sstate->nbss.length = (*(p++) & 0x01) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 2:
                sstate->nbss.length |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 3:
                sstate->nbss.length |= *(p++);
                --input_len;
                break;
        }
        sstate->bytesprocessed += (p - input);
    }

    SCReturnUInt((uint32_t)(p - input));
}

/**
 *  \brief parse and validate the 32 byte SMB Header
 *
 *  \retval 32 parsing done
 *  \retval >0<32 parsing in progress
 *  \retval 0 no input or already fully parsed
 *  \retval -1 error
 */
static int SMBParseHeader(Flow *f, void *smb_state,
                          AppLayerParserState *pstate, uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;

    if (input_len > 0) {
        switch (sstate->bytesprocessed) {
            case 4:
                // fallthrough
                /* above statement to prevent coverity FPs from the switch
                 * fall through */
                if (input_len >= SMB_HDR_LEN) {
                    if (SCMemcmp(p, "\xff\x53\x4d\x42", 4) != 0) {
                        SCLogDebug("SMB Header did not validate");
                        SCReturnInt(-1);
                    }
                    sstate->smb.command = *(p + 4);
                    sstate->smb.status = (uint32_t) *(p + 5) << 24;
                    sstate->smb.status |= (uint32_t) *(p + 6) << 16;
                    sstate->smb.status |= (uint32_t) *(p + 7) << 8;
                    sstate->smb.status |= (uint32_t) *(p + 8);
                    sstate->smb.flags = *(p + 9);
                    sstate->smb.flags2 = *(p + 10) << 8;
                    sstate->smb.flags2 |= *(p + 11);
                    sstate->smb.pidhigh = *(p + 12) << 8;
                    sstate->smb.pidhigh |= *(p + 13);
                    sstate->smb.securitysignature = (uint64_t) *(p + 14) << 56;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 15) << 48;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 16) << 40;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 17) << 32;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 18) << 24;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 19) << 16;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 20) << 8;
                    sstate->smb.securitysignature |= (uint64_t) *(p + 21);
                    sstate->smb.tid = *(p + 24) << 8;
                    sstate->smb.tid |= *(p + 25);
                    sstate->smb.pid = *(p + 26) << 8;
                    sstate->smb.pid |= *(p + 27);
                    sstate->smb.uid = *(p + 28) << 8;
                    sstate->smb.uid |= *(p + 29);
                    sstate->smb.mid = *(p + 30) << 8;
                    sstate->smb.mid |= *(p + 31);
                    sstate->bytesprocessed += SMB_HDR_LEN;
                    SCReturnInt(32);
                    break;
                } else {
                    if (*(p++) != 0xff) {
                        SCLogDebug("SMB Header did not validate");
                        SCReturnInt(-1);
                    }
                    if (!(--input_len))
                        break;
                    /* We fall through to the next case if we still have input.
                     * Same applies for other cases as well */
                }
                /* fall through */
            case 5:
                if (*(p++) != 'S') {
                        SCLogDebug("SMB Header did not validate");
                    SCReturnInt(-1);
                }
                if (!(--input_len))
                    break;
                /* fall through */
            case 6:
                if (*(p++) != 'M') {
                        SCLogDebug("SMB Header did not validate");
                    SCReturnInt(-1);
                }
                if (!(--input_len))
                    break;
                /* fall through */
            case 7:
                if (*(p++) != 'B') {
                        SCLogDebug("SMB Header did not validate");
                    SCReturnInt(-1);
                }
                if (!(--input_len))
                    break;
                /* fall through */
            case 8:
                sstate->smb.command = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 9:
                sstate->smb.status = *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 10:
                sstate->smb.status |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 11:
                sstate->smb.status |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 12:
                sstate->smb.status |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 13:
                sstate->smb.flags = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 14:
                sstate->smb.flags2 = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 15:
                sstate->smb.flags2 |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 16:
                sstate->smb.pidhigh = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 17:
                sstate->smb.pidhigh |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 18:
                sstate->smb.securitysignature = (uint64_t) *(p++) << 56;
                if (!(--input_len))
                    break;
                /* fall through */
            case 19:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 48;
                if (!(--input_len))
                    break;
                /* fall through */
            case 20:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 40;
                if (!(--input_len))
                    break;
                /* fall through */
            case 21:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 32;
                if (!(--input_len))
                    break;
                /* fall through */
            case 22:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 23:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 24:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 25:
                sstate->smb.securitysignature |= (uint64_t) *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 26:
                p++; // UNUSED
                if (!(--input_len))
                    break;
                /* fall through */
            case 27:
                p++; // UNUSED
                if (!(--input_len))
                    break;
                /* fall through */
            case 28:
                sstate->smb.tid = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 29:
                sstate->smb.tid |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 30:
                sstate->smb.pid = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 31:
                sstate->smb.pid |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 32:
                sstate->smb.uid = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 33:
                sstate->smb.uid |= *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 34:
                sstate->smb.mid = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 35:
                sstate->smb.mid |= *(p++);
                --input_len;
                break;
                /* fall through */
        }
    }
    sstate->bytesprocessed += (p - input);

    SCReturnInt((p - input));
}

static int SMBParse(Flow *f, void *smb_state, AppLayerParserState *pstate,
                    uint8_t *input, uint32_t input_len,
                    void *local_data, uint8_t dir)
{
    SCEnter();

    SMBState *sstate = (SMBState *) smb_state;
    uint64_t retval = 0;
    uint64_t parsed = 0;
    int hdrretval = 0;
    int counter = 0;

    if (pstate == NULL) {
        SCLogDebug("pstate == NULL");
        SCReturnInt(0);
    }

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    }

    if (sstate->bytesprocessed != 0 && sstate->data_needed_for_dir != dir) {
        SCReturnInt(-1);
    }

    while (input_len) {
        /* till we clear corner cases */
        if (counter++ == 30) {
            SCLogDebug("Somehow seem to be stuck inside the smb "
                       "parser for quite sometime.  Let's get out of here.");
            sstate->bytesprocessed = 0;
            SCReturnInt(0);
        }

        while (input_len && sstate->bytesprocessed < NBSS_HDR_LEN) {
            retval = NBSSParseHeader(f, smb_state, pstate, input + parsed,
                                     input_len);
            if (retval && retval <= input_len) {
                parsed += retval;
                input_len -= retval;
                SCLogDebug("[1] NBSS Header (%u/%u) Type 0x%02x Length 0x%04x "
                           "parsed %"PRIu64" input_len %u",
                           sstate->bytesprocessed, NBSS_HDR_LEN, sstate->nbss.type,
                           sstate->nbss.length, parsed, input_len);
            } else if (input_len) {
                SCLogDebug("Error parsing NBSS Header");
                sstate->bytesprocessed = 0;
                SCReturnInt(0);
            }
        }

        switch (sstate->nbss.type) {
            case NBSS_SESSION_MESSAGE:
                while (input_len &&
                       (sstate->bytesprocessed >= NBSS_HDR_LEN &&
                        sstate->bytesprocessed < NBSS_HDR_LEN + SMB_HDR_LEN)) {
                    /* inside while */
                    hdrretval = SMBParseHeader(f, smb_state, pstate, input + parsed,
                                               input_len);
                    if (hdrretval == -1 || hdrretval > (int32_t)input_len) {
                        SCLogDebug("Error parsing SMB Header");
                        sstate->bytesprocessed = 0;
                        SCReturnInt(0);
                    } else {
                        parsed += hdrretval;
                        input_len -= hdrretval;
                        SCLogDebug("[2] SMB Header (%u/%u) Command 0x%02x "
                                   "parsed %"PRIu64" input_len %u",
                                   sstate->bytesprocessed, NBSS_HDR_LEN + SMB_HDR_LEN,
                                   sstate->smb.command, parsed, input_len);
                    }
                } /* while */

                do {
                    if (input_len &&
                        (sstate->bytesprocessed == NBSS_HDR_LEN + SMB_HDR_LEN)) {
                        /* inside if */
                        retval = SMBGetWordCount(f, smb_state, pstate, input + parsed,
                                                 input_len);
                        if (retval && retval <= input_len) {
                            parsed += retval;
                            input_len -= retval;
                        } else if (input_len) {
                            SCLogDebug("Error parsing SMB Word Count");
                            sstate->bytesprocessed = 0;
                            SCReturnInt(0);
                        }
                        SCLogDebug("[3] WordCount (%u/%u) WordCount %u parsed "
                                   "%"PRIu64" input_len %u",
                                   sstate->bytesprocessed,
                                   NBSS_HDR_LEN + SMB_HDR_LEN + 1,
                                   sstate->wordcount.wordcount,
                                   parsed, input_len);
                    } /* if (input_len && ..) */

                    while (input_len &&
                           (sstate->bytesprocessed >= NBSS_HDR_LEN + SMB_HDR_LEN + 1 &&
                            sstate->bytesprocessed < (NBSS_HDR_LEN + SMB_HDR_LEN + 1 +
                                                      sstate->wordcount.wordcount))) {
                        /* inside while */
                        retval = SMBParseWordCount(f, smb_state, pstate,
                                                   input + parsed, input_len);
                        if (retval && retval <= input_len) {
                            parsed += retval;
                            input_len -= retval;
                        } else if (input_len) {
                            SCLogDebug("Error parsing SMB Word Count Data retval "
                                       "%"PRIu64" input_len %u", retval, input_len);
                            sstate->bytesprocessed = 0;
                            SCReturnInt(0);
                        }
                        SCLogDebug("[4] Parsing WordCount (%u/%u) WordCount %u "
                                   "parsed %"PRIu64" input_len %u",
                                   sstate->bytesprocessed,
                                   NBSS_HDR_LEN + SMB_HDR_LEN + 1 +
                                   sstate->wordcount.wordcount,
                                   sstate->wordcount.wordcount,
                                   parsed, input_len);
                    } /* while (input_len && ..) */

                    while (input_len &&
                           (sstate->bytesprocessed >= (NBSS_HDR_LEN + SMB_HDR_LEN +
                                                       1 + sstate->wordcount.wordcount) &&
                            sstate->bytesprocessed < (NBSS_HDR_LEN + SMB_HDR_LEN + 3
                                                      + sstate->wordcount.wordcount))) {
                        /* inside while */
                        retval = SMBGetByteCount(f, smb_state, pstate, input + parsed,
                                                 input_len);
                        if (retval && retval <= input_len) {
                            parsed += retval;
                            input_len -= retval;
                        } else if (input_len) {
                            SCLogDebug("Error parsing SMB Byte Count");
                            sstate->bytesprocessed = 0;
                            SCReturnInt(0);
                        }
                        SCLogDebug("[5] ByteCount (%u/%u) ByteCount %u parsed "
                                   "%"PRIu64" input_len %u",
                                   sstate->bytesprocessed,
                                   NBSS_HDR_LEN + SMB_HDR_LEN + 3,
                                   sstate->bytecount.bytecount,
                                   parsed, input_len);

                        if (sstate->bytecount.bytecount == 0) {
                            sstate->bytesprocessed = 0;
                            input_len = 0;
                        }
                    } /* while (input_len && ..) */

                    while (input_len &&
                           (sstate->bytesprocessed >= (NBSS_HDR_LEN + SMB_HDR_LEN +
                                                       3 + sstate->wordcount.wordcount)) &&
                           (sstate->bytesprocessed < (NBSS_HDR_LEN + SMB_HDR_LEN + 3
                                                      + sstate->wordcount.wordcount
                                                      + sstate->bytecount.bytecount))) {
                        /* inside while */
                        retval = SMBParseByteCount(f, smb_state, pstate,
                                                   input + parsed, input_len);
                        if (retval && retval <= input_len) {
                            parsed += retval;
                            input_len -= retval;
                        } else if (input_len) {
                            SCLogDebug("Error parsing SMB Byte Count Data");
                            sstate->bytesprocessed = 0;
                            SCReturnInt(0);
                        }
                        SCLogDebug("[6] Parsing ByteCount (%u/%u) ByteCount %u "
                                   "parsed %"PRIu64" input_len %u",
                                   sstate->bytesprocessed,
                                   NBSS_HDR_LEN + SMB_HDR_LEN + 1 +
                                   sstate->wordcount.wordcount + 2 +
                                   sstate->bytecount.bytecount,
                                   sstate->bytecount.bytecount, parsed, input_len);
                    } /* while (input_len && ..) */

                } while (sstate->andx.andxcommand != SMB_NO_SECONDARY_ANDX_COMMAND &&
                         input_len && sstate->andx.maxchainedandx--);

                if (sstate->bytesprocessed >= sstate->nbss.length + NBSS_HDR_LEN ||
                    sstate->andx.maxchainedandx == 0) {
                    /* inside if */
                    sstate->bytesprocessed = 0;
                    sstate->transaction_id++;
                    input_len = 0;
                }
                break;

            case NBSS_SESSION_REQUEST:
            case NBSS_POSITIVE_SESSION_RESPONSE:
            case NBSS_NEGATIVE_SESSION_RESPONSE:
            case NBSS_RETARGET_SESSION_RESPONSE:
            case NBSS_SESSION_KEEP_ALIVE:
                if (sstate->bytesprocessed < (sstate->nbss.length + NBSS_HDR_LEN)) {
                    if (input_len >= (sstate->nbss.length + NBSS_HDR_LEN -
                                      sstate->bytesprocessed)) {
                        /* inside if */
                        input_len -= (sstate->nbss.length + NBSS_HDR_LEN -
                                      sstate->bytesprocessed);
                        parsed += (sstate->nbss.length + NBSS_HDR_LEN -
                                   sstate->bytesprocessed);
                        sstate->bytesprocessed = 0;
                    } else {
                        sstate->bytesprocessed += input_len;
                        input_len = 0;
                    }
                } else {
                    sstate->bytesprocessed = 0;
                }
                break;

            default:
                sstate->bytesprocessed = 0;
                break;
        } /* switch */

    } /* while (input_len) */

    sstate->data_needed_for_dir = dir;
    SCReturnInt(1);
}

static int SMBParseRequest(Flow *f, void *smb_state, AppLayerParserState *pstate,
                           uint8_t *input, uint32_t input_len,
                           void *local_data)
{
    return SMBParse(f, smb_state, pstate, input, input_len, local_data, 0);
}

static int SMBParseResponse(Flow *f, void *smb_state, AppLayerParserState *pstate,
                            uint8_t *input, uint32_t input_len,
                            void *local_data)
{
    return SMBParse(f, smb_state, pstate, input, input_len, local_data, 1);
}


/**
 * \brief determines if the SMB command is an ANDX command
 * \retval 1 if smb command is an AndX command
 * \retval 0 if smb command is not an AndX command
 */

int isAndX(SMBState *smb_state)
{
    SCEnter();

    switch (smb_state->smb.command) {
        case SMB_NO_SECONDARY_ANDX_COMMAND:
        case SMB_COM_LOCKING_ANDX:
        case SMB_COM_OPEN_ANDX:
        case SMB_COM_READ_ANDX:
        case SMB_COM_WRITE_ANDX:
        case SMB_COM_SESSION_SETUP_ANDX:
        case SMB_COM_LOGOFF_ANDX:
        case SMB_COM_TREE_CONNECT_ANDX:
        case SMB_COM_NT_CREATE_ANDX:
            smb_state->andx.andxbytesprocessed = 0;
            SCReturnInt(1);
        default:
            SCReturnInt(0);
    }
}

/** \internal
 *  \brief Allocate a SMBState
 *  \retval s State, or NULL in case of error
 */
static void *SMBStateAlloc(void)
{
    SCEnter();

    SMBState *s = (SMBState *)SCCalloc(1, sizeof(SMBState));
    if (unlikely(s == NULL)) {
        SCReturnPtr(NULL, "void");
    }

    DCERPCInit(&s->ds.dcerpc);

    SCReturnPtr(s, "void");
}

/** \internal
 *  \brief Free a SMBState
 */
static void SMBStateFree(void *s)
{
    SCEnter();
    SMBState *sstate = (SMBState *) s;

    DCERPCCleanup(&sstate->ds.dcerpc);

    if (sstate->ds.de_state) {
        DetectEngineStateFree(sstate->ds.de_state);
    }

    SCFree(s);
    SCReturn;
}

static int SMBStateHasTxDetectState(void *state)
{
    SMBState *smb_state = (SMBState *)state;
    if (smb_state->ds.de_state)
        return 1;
    return 0;
}

static int SMBSetTxDetectState(void *state, void *vtx, DetectEngineState *de_state)
{
    SMBState *smb_state = (SMBState *)state;
    smb_state->ds.de_state = de_state;
    return 0;
}

static DetectEngineState *SMBGetTxDetectState(void *vtx)
{
    SMBState *smb_state = (SMBState *)vtx;
    return smb_state->ds.de_state;
}

static void SMBStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static void *SMBGetTx(void *state, uint64_t tx_id)
{
    SMBState *smb_state = (SMBState *)state;
    return smb_state;
}

static uint64_t SMBGetTxCnt(void *state)
{
    /* single tx */
    return 1;
}

static int SMBGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return 1;
}

static int SMBGetAlstateProgress(void *tx, uint8_t direction)
{
    return 0;
}

#define SMB_PROBING_PARSER_MIN_DEPTH 8

static uint16_t SMBProbingParser(uint8_t *input, uint32_t ilen, uint32_t *offset)
{
    int32_t len;
    int32_t input_len = ilen;

    while (input_len >= SMB_PROBING_PARSER_MIN_DEPTH) {
        switch (input[0]) {
            case NBSS_SESSION_MESSAGE:
                if (input[4] == 0xFF && input[5] == 'S' && input[6] == 'M' &&
                    input[7] == 'B') {
                    return ALPROTO_SMB;
                }

                /* fall through */
            case NBSS_SESSION_REQUEST:
            case NBSS_POSITIVE_SESSION_RESPONSE:
            case NBSS_NEGATIVE_SESSION_RESPONSE:
            case NBSS_RETARGET_SESSION_RESPONSE:
            case NBSS_SESSION_KEEP_ALIVE:
                len = (input[1] & 0x01) << 16;
                len |= input[2] << 8;
                len |= input[3];
                break;
            default:
                /* -1 indicates a stream where the probing parser would be
                 * unable to find nbss, even if it exists.  This should
                 * prevent the probing parser from beig invoked henceforth */
                return ALPROTO_FAILED;
        }

        input_len -= 4;
        if (len >= input_len) {
            return ALPROTO_UNKNOWN;
        }

        input_len -= len;
        input += 4 + len;
    }

    return ALPROTO_UNKNOWN;
}

static int SMBRegisterPatternsForProtocolDetection(void)
{
    int r = 0;
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|ff|SMB", 8, 4, STREAM_TOSERVER);
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB,
            "|ff|SMB", 8, 4, STREAM_TOCLIENT);

    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2,
            "|fe|SMB", 8, 4, STREAM_TOSERVER);
    r |= AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2,
            "|fe|SMB", 8, 4, STREAM_TOCLIENT);
    return r == 0 ? 0 : -1;
}

void RegisterSMBParsers(void)
{
    const char *proto_name = "smb";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_SMB, proto_name);
        if (SMBRegisterPatternsForProtocolDetection() < 0)
            return;

        if (RunmodeIsUnittests()) {
            AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                          "139",
                                          ALPROTO_SMB,
                                          SMB_PROBING_PARSER_MIN_DEPTH, 0,
                                          STREAM_TOSERVER,
                                          SMBProbingParser, SMBProbingParser);
        } else {
            AppLayerProtoDetectPPParseConfPorts("tcp", IPPROTO_TCP,
                                                proto_name, ALPROTO_SMB,
                                                SMB_PROBING_PARSER_MIN_DEPTH, 0,
                                                SMBProbingParser, SMBProbingParser);
        }

        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_SMB, STREAM_TOSERVER);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMB, STREAM_TOSERVER, SMBParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMB, STREAM_TOCLIENT, SMBParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SMB, SMBStateAlloc, SMBStateFree);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_SMB, SMBStateTransactionFree);

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_SMB, SMBStateHasTxDetectState,
                                               SMBGetTxDetectState, SMBSetTxDetectState);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_SMB, SMBGetTx);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_SMB, SMBGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_SMB, SMBGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_SMB,
                                                               SMBGetAlstateProgressCompletionStatus);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection "
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SMB, SMBParserRegisterTests);
#endif
    return;
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "flow-util.h"

/**
 * \test SMBParserTest01 tests the NBSS and SMB header decoding
 */
static int SMBParserTest01(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf[] = "\x00\x00\x00\x85" // NBSS
        "\xff\x53\x4d\x42\x72\x00\x00\x00" // SMB
        "\x00\x18\x53\xc8\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\xff\xfe\x00\x00\x00\x00"
        "\x00" // WordCount
        "\x62\x00" // ByteCount
        "\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20"
        "\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73"
        "\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c"
        "\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
        "\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

    uint32_t smblen = sizeof(smbbuf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                                STREAM_TOSERVER | STREAM_EOF, smbbuf, smblen);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("expected nbss type 0x%02x , got 0x%02x : ", NBSS_SESSION_MESSAGE, smb_state->nbss.type);
        goto end;
    }

    if (smb_state->nbss.length != 133) {
        printf("expected nbss length 0x%02x , got 0x%02x : ", 133, smb_state->nbss.length);
        goto end;
    }

    if (smb_state->smb.command != SMB_COM_NEGOTIATE) {
        printf("expected SMB command 0x%02x , got 0x%02x : ", SMB_COM_NEGOTIATE, smb_state->smb.command);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test SMBParserTest02 tests the NBSS, SMB, and DCERPC over SMB header decoding
 */
static int SMBParserTest02(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf[] = {
    0x00, 0x00, 0x00, 0x92, 0xff, 0x53, 0x4d, 0x42,
    0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x64, 0x05,
    0x00, 0x08, 0x00, 0x00, 0x10, 0x00, 0x00, 0x48,
    0x00, 0x00, 0x04, 0xe0, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x4a, 0x00, 0x48, 0x00, 0x4a, 0x00, 0x02,
    0x00, 0x26, 0x00, 0x00, 0x40, 0x4f, 0x00, 0x5c,
    0x50, 0x49, 0x50, 0x45, 0x5c, 0x00, 0x05, 0x00,
    0x0b, 0x03, 0x10, 0x00, 0x00, 0x00, 0x48, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xd0, 0x16,
    0xd0, 0x16, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x40, 0xfd,
    0x2c, 0x34, 0x6c, 0x3c, 0xce, 0x11, 0xa8, 0x93,
    0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d, 0x00, 0x00,
    0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c,
    0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10,
    0x48, 0x60, 0x02, 0x00, 0x00, 0x00 };

    uint32_t smblen = sizeof(smbbuf);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                                STREAM_TOSERVER | STREAM_EOF, smbbuf, smblen);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("expected nbss type 0x%02x , got 0x%02x : ", NBSS_SESSION_MESSAGE, smb_state->nbss.type);
        goto end;
    }

    if (smb_state->nbss.length != 146) {
        printf("expected nbss length 0x%02x , got 0x%02x : ", 146, smb_state->nbss.length);
        goto end;
    }

    if (smb_state->smb.command != SMB_COM_TRANSACTION) {
        printf("expected SMB command 0x%02x , got 0x%02x : ", SMB_COM_TRANSACTION, smb_state->smb.command);
        goto end;
    }

    printUUID("BIND", smb_state->ds.dcerpc.dcerpcbindbindack.uuid_entry);
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest03(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
    0x00, 0x00, 0x07, 0x57, 0xff, 0x53, 0x4d, 0x42,
    0x2f, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x20,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7f, 0x13,
    0x01, 0x08, 0xc9, 0x29, 0x0e, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x55, 0x01, 0x00, 0x00, 0xff,
    0xff, 0xff, 0xff, 0x08, 0x00, 0x0e, 0x00, 0x00,
    0x00, 0x0e, 0x00, 0x49, 0x07, 0x00, 0x00, 0x00,
    0x00, 0x18, 0x07, 0xcc, 0x1b, 0x19, 0xb8, 0x75,
    0x2c, 0x85, 0x52, 0x39, 0x72, 0xfa, 0x9c, 0x5f,
    0x5a, 0xb7, 0x59, 0xa1, 0x83, 0xba, 0x87, 0xd3,
    0xc3, 0xbf, 0xf4, 0x5d, 0x08, 0x32, 0x22, 0x33,
    0x2e, 0x62, 0x46, 0x4d, 0x03, 0x48, 0x1f, 0xea,
    0x7c, 0x65, 0x3e, 0x71, 0xf8, 0xea, 0x20, 0x85,
    0x29, 0x6f, 0x3c, 0xf2, 0x19, 0xb5, 0x65, 0xb0,
    0xce, 0x06, 0xcc, 0x90, 0x86, 0x20, 0x77, 0xf5,
    0xa0, 0xbc, 0x45, 0x9d, 0x4e, 0x92, 0xb4, 0x24,
    0xc8, 0x58, 0x4a, 0xc3, 0x4e, 0xb8, 0x95, 0x8d,
    0x93, 0x0c, 0xce, 0xe0, 0xf9, 0x7d, 0x7e, 0xd3,
    0x46, 0x53, 0x32, 0x95, 0x7d, 0x22, 0x76, 0x0e,
    0x95, 0x23, 0x2e, 0xa6, 0x58, 0x1a, 0xb6, 0x74,
    0x54, 0x4f, 0x37, 0x5c, 0x60, 0x00, 0xb4, 0x55,
    0x5b, 0xda, 0xea, 0x2c, 0xf3, 0x9b, 0x91, 0x6f,
    0xa8, 0x20, 0xd3, 0x40, 0x0c, 0x7c, 0xc7, 0x85,
    0x8c, 0x44, 0x76, 0xbc, 0x22, 0x9d, 0xfd, 0x8e,
    0x21, 0x46, 0x05, 0x41, 0x73, 0x0c, 0x88, 0x62,
    0xdc, 0x62, 0xc1, 0xc8, 0x14, 0xbb, 0x96, 0x60,
    0x77, 0x6c, 0x5c, 0x31, 0x2a, 0xaa, 0x87, 0x69,
    0x99, 0xaa, 0x83, 0x5e, 0x71, 0x11, 0x2a, 0x85,
    0xca, 0x5d, 0xe1, 0x67, 0x4f, 0xa2, 0x3e, 0x4e,
    0x94, 0xe7, 0xa3, 0xe6, 0xa0, 0xdb, 0xc2, 0x05,
    0x01, 0x4f, 0xf5, 0xe9, 0xfc, 0xa2, 0x2a, 0x1c,
    0x63, 0x21, 0xd5, 0x27, 0x98, 0x86, 0x9c, 0x66,
    0x5e, 0xf1, 0x97, 0xb0, 0x86, 0x58, 0x5b, 0x94,
    0x51, 0xfd, 0xb9, 0x83, 0x4c, 0xc4, 0x0f, 0x5f,
    0xdd, 0xc8, 0xce, 0x43, 0xed, 0xe8, 0xae, 0xbc,
    0x52, 0x73, 0xf6, 0x0f, 0x0d, 0xb4, 0xd6, 0xa7,
    0xcf, 0xef, 0x0e, 0x72, 0x34, 0xff, 0x2b, 0x50,
    0x71, 0x2a, 0x98, 0xf0, 0x60, 0x58, 0xde, 0x1d,
    0x96, 0x50, 0xd8, 0xec, 0xeb, 0x40, 0xcb, 0x4c,
    0x3b, 0x2c, 0xee, 0x76, 0xd6, 0x97, 0x1c, 0x69,
    0x61, 0x89, 0xc1, 0x9b, 0x03, 0xda, 0x08, 0x0b,
    0x15, 0xba, 0xd3, 0x3d, 0x8c, 0xea, 0xf7, 0x17,
    0xc3, 0x77, 0xf8, 0x04, 0xca, 0x72, 0xed, 0xfe,
    0xd0, 0x02, 0x73, 0x1b, 0x71, 0x72, 0x17, 0x9f,
    0x14, 0x96, 0xe2, 0x5f, 0xae, 0x5b, 0x7d, 0x7f,
    0xc9, 0x72, 0x9f, 0xd5, 0x32, 0xf4, 0xf3, 0x39,
    0x89, 0x36, 0x00, 0x44, 0xa9, 0x18, 0x21, 0x4b,
    0x26, 0xf2, 0x5a, 0x2a, 0x80, 0xea, 0x6b, 0x3e,
    0x68, 0x27, 0xd0, 0xa0, 0x84, 0x81, 0xb5, 0xa6,
    0x3b, 0xd5, 0xdc, 0xdd, 0xd1, 0xd4, 0x5b, 0xad,
    0x80, 0x91, 0xf2, 0x30, 0x5e, 0x90, 0x17, 0x35,
    0x59, 0xad, 0x34, 0x65, 0x54, 0x04, 0x5a, 0x3c,
    0xe4, 0x68, 0xa7, 0x30, 0x06, 0x7a, 0x85, 0xe7,
    0xf4, 0x20, 0xe3, 0xd7, 0xa5, 0x8b, 0x60, 0xfe,
    0x51, 0xad, 0xda, 0xe2, 0xd1, 0x4f, 0xfb, 0x94,
    0xc9, 0xba, 0xa4, 0x09, 0x5c, 0xde, 0x78, 0xdc,
    0x78, 0x36, 0x96, 0x8b, 0xd6, 0x72, 0xc4, 0xa7,
    0x1c, 0xde, 0x45, 0x85, 0xdf, 0x84, 0xb1, 0x3f,
    0x2b, 0x3f, 0xfe, 0x56, 0x80, 0x8d, 0x26, 0x4a,
    0x39, 0x22, 0x1f, 0x10, 0x89, 0x2e, 0x4e, 0x87,
    0xf5, 0x9c, 0x0e, 0xd9, 0xdd, 0xb2, 0xc9, 0x9c,
    0x3f, 0xc5, 0xe3, 0xab, 0xdc, 0x85, 0x1c, 0xf9,
    0xda, 0xbb, 0x36, 0x9b, 0xe7, 0x21, 0x58, 0x44,
    0xee, 0xb3, 0xe7, 0x37, 0xd3, 0xc3, 0x76, 0x09,
    0x79, 0xe2, 0xf4, 0xf1, 0x27, 0x6b, 0x74, 0xc4,
    0x5f, 0x06, 0x76, 0x78, 0x56, 0xb9, 0x80, 0x7f,
    0x63, 0x53, 0xa2, 0xd1, 0xfc, 0xfb, 0x69, 0x38,
    0x0c, 0x13, 0x6e, 0x9e, 0xea, 0x79, 0xc9, 0x6d,
    0x45, 0x6b, 0xa3, 0xa8, 0x20, 0x21, 0x24, 0xff,
    0x0d, 0x8d, 0xd9, 0x0a, 0x9e, 0xf4, 0x3f, 0xf5,
    0x18, 0x39, 0xdd, 0x9f, 0xed, 0xd6, 0x2b, 0xb1,
    0x4b, 0x3f, 0x24, 0x7e, 0x11, 0x79, 0x37, 0x01,
    0x10, 0xe7, 0x34, 0x1d, 0x36, 0x5f, 0x26, 0x99,
    0x5a, 0x4d, 0xe9, 0x1a, 0x89, 0x24, 0xf8, 0xea,
    0xca, 0x16, 0x19, 0x6c, 0x3b, 0x8e, 0x44, 0x70,
    0x20, 0x5f, 0x46, 0x3c, 0x60, 0xbe, 0x03, 0xfc,
    0x99, 0x29, 0xd7, 0x30, 0x5e, 0xbe, 0x5b, 0x17,
    0x4f, 0xfe, 0x3f, 0xe0, 0x50, 0xa0, 0x1b, 0x1a,
    0x6b, 0x17, 0xf3, 0xf9, 0x01, 0xe8, 0xc6, 0xc8,
    0x0f, 0x81, 0xbd, 0x2d, 0xc5, 0x8c, 0xa1, 0xab,
    0x9d, 0x13, 0xce, 0x73, 0x14, 0x56, 0x56, 0xb4,
    0x68, 0xac, 0x35, 0xf8, 0x6a, 0x55, 0x3e, 0x50,
    0x34, 0x5a, 0x66, 0x17, 0x98, 0x4d, 0xd1, 0xa7,
    0xdf, 0x57, 0xd6, 0xd4, 0x44, 0x64, 0xa7, 0x74,
    0x18, 0x0a, 0x4f, 0xa9, 0xe4, 0xb4, 0x0f, 0x89,
    0xa2, 0xc5, 0xb8, 0xa7, 0x20, 0xa2, 0xb1, 0xf8,
    0x70, 0xaf, 0xee, 0x6e, 0x62, 0xa5, 0x89, 0x5d,
    0xc9, 0x8a, 0xb9, 0x87, 0xac, 0x4d, 0x4d, 0x81,
    0x1c, 0x62, 0xd3, 0xbf, 0x83, 0x79, 0x98, 0x81,
    0xbd, 0xcc, 0x1f, 0x76, 0xc8, 0x7e, 0x2c, 0xec,
    0xdb, 0xa7, 0xa5, 0xea, 0x05, 0x94, 0x3f, 0xef,
    0x66, 0x1c, 0x5d, 0xc4, 0xbd, 0x73, 0x53, 0x1f,
    0xf3, 0xac, 0x1f, 0xa4, 0xb9, 0x78, 0x1b, 0x93,
    0xcb, 0x17, 0xb6, 0xda, 0xbb, 0x45, 0x21, 0xfa,
    0x52, 0xc7, 0x71, 0x05, 0xb3, 0xeb, 0x82, 0x09,
    0x99, 0x90, 0x5d, 0xa9, 0x76, 0xd1, 0x63, 0x6a,
    0x14, 0x99, 0xe9, 0xa5, 0x98, 0x5d, 0xe0, 0xb5,
    0x2a, 0xd1, 0xf1, 0x2e, 0xe7, 0x85, 0xdb, 0x42,
    0xfc, 0x61, 0x09, 0x14, 0xe5, 0x8e, 0x92, 0x70,
    0x91, 0x15, 0x74, 0x2c, 0x16, 0x30, 0xc4, 0xb0,
    0xf1, 0x61, 0xd5, 0x55, 0xa8, 0xa3, 0xca, 0x88,
    0xe6, 0xb1, 0x58, 0x76, 0xa5, 0x4c, 0x48, 0xe3,
    0xdd, 0x7a, 0x5e, 0x0a, 0x86, 0xfd, 0xd6, 0xe8,
    0xc0, 0x47, 0x27, 0x1a, 0x58, 0x92, 0xad, 0xa6,
    0x51, 0x32, 0x4d, 0x0d, 0x29, 0xd3, 0xcf, 0xf1,
    0xcc, 0x29, 0x1a, 0xfe, 0xf6, 0xa0, 0xf3, 0xdd,
    0x98, 0x73, 0xcb, 0xbb, 0x8a, 0xe9, 0x55, 0xba,
    0x89, 0x2d, 0x31, 0x9b, 0x3d, 0x04, 0x1f, 0xb5,
    0x1c, 0x84, 0x63, 0xca, 0xde, 0x75, 0xac, 0x91,
    0x78, 0x1f, 0x8b, 0x37, 0x8d, 0x46, 0xaa, 0x79,
    0x51, 0xbf, 0x30, 0xfa, 0x3d, 0x9b, 0xd9, 0x20,
    0x25, 0x18, 0x46, 0xb6, 0xe7, 0x8e, 0xf7, 0x5e,
    0x7d, 0xf8, 0xd3, 0x01, 0x39, 0xe5, 0x9d, 0x46,
    0x6b, 0x8c, 0xcf, 0x9d, 0xc6, 0xb9, 0xe8, 0xd8,
    0x25, 0x2d, 0x96, 0x07, 0xc7, 0x4e, 0xa3, 0x3a,
    0x9a, 0xbc, 0x9d, 0x80, 0xa6, 0x5d, 0xb1, 0xc0,
    0x3e, 0x81, 0xe0, 0x52, 0x8f, 0x9a, 0x1a, 0xc2,
    0xdb, 0x9f, 0x91, 0x85, 0x56, 0xdb, 0xb8, 0x69,
    0x10, 0x35, 0xe4, 0xc4, 0xaf, 0xb6, 0x13, 0xf8,
    0x86, 0xe1, 0x2d, 0x3c, 0xf8, 0x94, 0x60, 0xb7,
    0xa1, 0xde, 0x25, 0x51, 0x7d, 0xff, 0xff, 0xa6,
    0x23, 0x68, 0x28, 0x1f, 0x79, 0x33, 0x60, 0x86,
    0xe9, 0x2c, 0x3a, 0xb9, 0x3c, 0x70, 0xb3, 0xe0,
    0x4c, 0x8c, 0x7e, 0x06, 0xdf, 0x4d, 0xf6, 0x88,
    0xda, 0x9e, 0x4f, 0x5b, 0xd2, 0x2e, 0x28, 0xb8,
    0xe0, 0x27, 0x7a, 0x43, 0xfb, 0x23, 0x4b, 0x8a,
    0xd9, 0x4f, 0x29, 0x53, 0x5d, 0x75, 0xc6, 0xfc };
    uint8_t smbbuf2[] = {
    0x0a, 0x30, 0xe0, 0x74, 0x3c, 0x23, 0xc3, 0x11,
    0x95, 0x25, 0x04, 0xe4, 0x2d, 0x7b, 0x29, 0xa1,
    0x75, 0x69, 0x3f, 0x49, 0x9c, 0xfa, 0x66, 0x78,
    0x3c, 0xf1, 0xab, 0xee, 0xab, 0x9a, 0x75, 0x63,
    0x54, 0x80, 0x2b, 0x5c, 0x07, 0xf7, 0xec, 0x72,
    0xfb, 0xd0, 0x52, 0x5e, 0x7e, 0x99, 0xf5, 0x3b,
    0xc4, 0x77, 0x96, 0x12, 0xb8, 0x36, 0xb2, 0xcf,
    0xab, 0xf5, 0xd3, 0xf3, 0x19, 0x77, 0xbb, 0x03,
    0xdb, 0xf7, 0x4d, 0x81, 0xe3, 0xe8, 0x6c, 0x23,
    0x02, 0xe0, 0xcf, 0x24, 0xc1, 0xd5, 0x3d, 0x42,
    0xa4, 0xbc, 0x97, 0xf4, 0x83, 0xee, 0xff, 0x85,
    0x2c, 0xfd, 0xdd, 0xdc, 0x23, 0x1c, 0x87, 0x0c,
    0xe4, 0xd5, 0xfc, 0xc3, 0x8b, 0x10, 0xa5, 0x42,
    0x0f, 0x14, 0xd1, 0x89, 0xa6, 0xaf, 0xaa, 0x77,
    0xfc, 0x3b, 0xce, 0x6c, 0xbe, 0x62, 0xc9, 0xdd,
    0x16, 0xc6, 0x14, 0xc2, 0xa6, 0x13, 0x12, 0xfa,
    0x5a, 0x8b, 0x05, 0x88, 0x06, 0xf9, 0xef, 0x9c,
    0xce, 0xf7, 0x27, 0x46, 0x1d, 0x50, 0xe2, 0xeb,
    0x49, 0xb2, 0xb1, 0x7c, 0x6b, 0xaf, 0xe9, 0xc7,
    0xdd, 0x59, 0x8c, 0xda, 0x32, 0x55, 0xb5, 0xfe,
    0xdc, 0xe0, 0x47, 0xf4, 0xa0, 0xe7, 0xaa, 0x47,
    0x49, 0xdf, 0xcf, 0x9c, 0xd6, 0xfa, 0xd2, 0xca,
    0x55, 0xa7, 0x3f, 0x62, 0x14, 0x6c, 0xc8, 0x7f,
    0xad, 0x7c, 0xb1, 0x70, 0x88, 0xb3, 0x51, 0x13,
    0x2c, 0x3b, 0x78, 0x1d, 0xa2, 0x5e, 0xf7, 0x83,
    0x62, 0x6a, 0x51, 0xbd, 0xe9, 0x77, 0x62, 0xc6,
    0x06, 0x06, 0x51, 0x9d, 0x03, 0x95, 0x51, 0x7c,
    0xd3, 0x73, 0x50, 0x9b, 0x36, 0x5a, 0x28, 0x52,
    0xc0, 0x05, 0xee, 0xd5, 0x2d, 0xd5, 0x77, 0x52,
    0xab, 0x7c, 0x4a, 0x4c, 0x7e, 0xf6, 0xba, 0x52,
    0xc5, 0x4d, 0xb5, 0x74, 0x83, 0x77, 0x5f, 0xaa,
    0xba, 0x86, 0x94, 0xd2, 0x19, 0xca, 0xef, 0xc9,
    0x6e, 0x5b, 0x50, 0xee, 0x2c, 0xdd, 0x67, 0xc8,
    0xfd, 0xc3, 0xa4, 0x80, 0x63, 0x1d, 0xa2, 0x07,
    0x1e, 0x1a, 0x9d, 0x70, 0xe4, 0xab, 0x34, 0x7a,
    0xfb, 0x08, 0x82, 0x85, 0xec, 0x2d, 0x25, 0x3e,
    0x70, 0x22, 0x6e, 0x9d, 0x0f, 0xed, 0x60, 0x8f,
    0xc5, 0x06, 0x66, 0x42, 0x95, 0xcc, 0x77, 0xbe,
    0x4d, 0x19, 0x7c, 0xd1, 0x31, 0x26, 0xfb, 0x52,
    0xad, 0xbd, 0x19, 0x1d, 0x68, 0x56, 0x2c, 0xb9,
    0x5b, 0xaa, 0x92, 0x48, 0xcf, 0xdf, 0x65, 0x2d,
    0xdb, 0x87, 0x06, 0xbe, 0x51, 0x61, 0x6b, 0xf6,
    0x87, 0xdc, 0xbb, 0xa5, 0x48, 0x81, 0xaf, 0xd7,
    0xfc, 0x15, 0xf7, 0x41, 0xde, 0xe3, 0xe9, 0xd4,
    0xad, 0x5d, 0x64, 0x8f, 0x13, 0x68, 0xe5, 0x2b,
    0x4d, 0x87, 0x59, 0x7e, 0xcb, 0x2b, 0xbf, 0xbc,
    0xaa, 0xd2, 0xc7, 0x60, 0xef, 0xe1, 0x25, 0xe2,
    0x89, 0xb4, 0x78, 0x24, 0x52, 0xb4, 0x54, 0xe3,
    0xf0, 0xe5, 0x81, 0xba, 0xe3, 0x00, 0x62, 0x09,
    0x8a, 0x19, 0x7b, 0x9b, 0x0f, 0x50, 0x91, 0xa7,
    0x80, 0xdb, 0x0e, 0x68, 0xe1, 0x22, 0x54, 0x89,
    0x07, 0xc7, 0x39, 0x38, 0xca, 0xae, 0xbf, 0x5b,
    0xbb, 0xe4, 0x70, 0x28, 0xc5, 0x18, 0x98, 0xea };
    uint8_t smbbuf3[] = {
    0x39, 0x99, 0x97, 0x1f, 0xf1, 0x6a, 0x72, 0x0d,
    0x35, 0xd5, 0x33, 0x42, 0x5a, 0x9f, 0xea, 0x0f,
    0x6f, 0x3b, 0xc7, 0xb9, 0xd3, 0x04, 0xdf, 0x44,
    0x45, 0xc7, 0xc6, 0x06, 0x0b, 0x77, 0x8e, 0x8e,
    0x9a, 0x3c, 0xa4, 0x15, 0x85, 0x80, 0xce, 0xd0,
    0x8c, 0x54, 0x60, 0xf9, 0x1f, 0xb3, 0x3e, 0xed,
    0x21, 0x3e, 0xfa, 0x30, 0xf4, 0x50, 0x2b, 0x00,
    0x00, 0xea, 0xd1, 0xb3, 0xd2, 0x7e, 0x6c, 0x14,
    0xe5, 0xf0, 0xf4, 0x9c, 0xb4, 0x2e, 0x32, 0x41,
    0x20, 0x2a, 0x18, 0x78, 0x1a, 0xed, 0x04, 0x94,
    0x83, 0xd1, 0x87, 0x39, 0xf6, 0xcb, 0xf4, 0xc1,
    0xc7, 0xe0, 0x50, 0x87, 0x65, 0x4f, 0x36, 0x73,
    0x70, 0xf5, 0x0a, 0xaa, 0x2b, 0x28, 0xad, 0x05,
    0x28, 0x8d, 0x3b, 0x42, 0xfb, 0xe2, 0xd3, 0xb8,
    0x82, 0x71, 0x25, 0xcd, 0xa2, 0xf2, 0x4b, 0x62,
    0xeb, 0x14, 0x3b, 0x81, 0xaf, 0xd4, 0x68, 0x5a,
    0xae, 0x8e, 0x10, 0x9a, 0x17, 0x4c, 0xf1, 0x3d,
    0x43, 0xb9, 0xd2, 0xd5, 0x86, 0xee, 0x3a, 0xf3,
    0xe5, 0x41, 0xe5, 0x52, 0xda, 0x61, 0xf3, 0x20,
    0x30, 0x5b, 0xe5, 0x1f, 0xe2, 0x4e, 0x9d, 0xd6,
    0xd6, 0x2e, 0x2a, 0x63, 0xbc, 0xf6, 0xb9, 0xc2,
    0xec, 0xd0, 0xe9, 0xfd, 0x07, 0xfb, 0x2d, 0x8e,
    0xbc, 0x43, 0xcb, 0x7e, 0x55, 0x63, 0x9f, 0xb6,
    0xf8, 0x8b, 0x4c, 0xcd, 0x4b, 0x28, 0x47, 0x56,
    0xc9, 0xd2, 0xfe, 0x0e, 0x63, 0x11, 0x09, 0xd9,
    0xd9, 0x97, 0x0a, 0x5a, 0x21, 0xad, 0xdb, 0x53,
    0x24, 0xee, 0x62, 0x4a, 0xaa, 0x49, 0x14, 0xdf,
    0xc0, 0x61, 0x85, 0x11, 0x57, 0x6e, 0x3b, 0x8c,
    0x37, 0x24, 0x13, 0xde, 0xc7, 0xf3, 0x44, 0x54,
    0x8a, 0x69, 0x78, 0x0c, 0xf3, 0xd1, 0xcd, 0xc5,
    0xad, 0x45, 0xc6, 0x06, 0x56, 0x0b, 0x53, 0x40,
    0x79, 0x12, 0x90, 0x6b, 0xdf, 0xc5, 0x80, 0xde,
    0x9c, 0x8e, 0xe1, 0x73, 0xdc, 0x92, 0xc2, 0xf1,
    0xeb, 0xd9, 0x66, 0x0a, 0x12, 0xd2, 0x3f, 0x04,
    0x03, 0xaa, 0x6f, 0xd0, 0x90, 0xfa, 0xb0, 0x6b,
    0x7d, 0xfc, 0x76, 0xf9, 0xe3, 0xa2, 0x17, 0x28,
    0x4e, 0x9d, 0x2d, 0xa6, 0x7e, 0xfa, 0x19, 0x91,
    0xeb, 0xe5, 0xe4, 0xca, 0x09, 0x77, 0xfe, 0xc0,
    0x1c, 0xaa, 0xc4, 0x7c, 0xc2, 0x6a, 0x0e, 0xf3,
    0x4e, 0x79, 0x9b, 0x82, 0x2a, 0x4b, 0xd3, 0x35,
    0x1d, 0x92, 0x6c, 0x3f, 0x85, 0x57, 0x5a, 0x16,
    0xa1, 0x0d, 0xc7, 0x64, 0xb8, 0x46, 0x73, 0xbf,
    0x91, 0x5f, 0x10, 0x2a, 0x2b, 0x51, 0x49, 0xe1,
    0xea, 0xda, 0x2f, 0x41, 0x7b, 0x96, 0xa3, 0xd2,
    0x7b, 0x72, 0xc0, 0x88, 0x84, 0xcb, 0xe0, 0xb7,
    0xae, 0x74, 0xc9, 0x78, 0x82, 0x47, 0xf3, 0x19,
    0x21, 0x53, 0xe6, 0xe1, 0x67, 0xbb, 0x39, 0x05,
    0x6e, 0x1c, 0x38, 0x33, 0x10, 0x60, 0x24, 0x48,
    0xb2, 0x7a, 0xb9, 0x4e, 0x8d, 0x36, 0xcf, 0xce,
    0xf6, 0x31, 0x3b, 0xa3, 0x18, 0x78, 0x49, 0x91,
    0xef, 0xed, 0x86, 0x2c, 0x98, 0x00, 0x18, 0x49,
    0x73, 0xb8, 0xe5, 0x2f, 0xc1, 0x58, 0xe0, 0x47,
    0x2b, 0x16, 0x41, 0xc3, 0x41, 0x05, 0x00, 0x0b,
    0x03, 0x10, 0x00, 0x00, 0x00, 0xb0, 0x02, 0x00,
    0x00, 0x00, 0x00 };

    uint32_t smblen1 = sizeof(smbbuf1);
    uint32_t smblen2 = sizeof(smbbuf2);
    uint32_t smblen3 = sizeof(smbbuf3);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOSERVER | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->smb.command != SMB_COM_WRITE_ANDX) {
        printf("expected SMB command 0x%02x , got 0x%02x : ", SMB_COM_WRITE_ANDX, smb_state->smb.command);
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf2, smblen2);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf3, smblen3);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    printUUID("BIND", smb_state->ds.dcerpc.dcerpcbindbindack.uuid_entry);
    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest04(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
    0x00, 0x00, 0x00, 0x88, 0xff, 0x53, 0x4d, 0x42,
    0x2f, 0x00, 0x00, 0x00, 0x00, 0x18, 0x07, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7c, 0x05,
    0x00, 0x08, 0x00, 0x00, 0x0e, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0xff,
    0x00, 0x00, 0x00, 0x08, 0x00, 0x48, 0x00, 0x00,
    0x00, 0x48, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x49, 0x00, 0xab, 0x05, 0x00, 0x0b, 0x03,
    0x10, 0x00, 0x00, 0x00, 0x48, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00, 0xd0, 0x16, 0xd0, 0x16,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00, 0x78, 0x56, 0x34, 0x12,
    0x34, 0x12, 0xcd, 0xab, 0xef, 0x00, 0x01, 0x23,
    0x45, 0x67, 0x89, 0xab, 0x01, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00 };
    uint8_t smbbuf2[] = {
    0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42,
    0x2f, 0x00, 0x00, 0x00, 0x00, 0x98, 0x07, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7c, 0x05,
    0x00, 0x08, 0x00, 0x00, 0x06, 0xff, 0x00, 0x2f,
    0x00, 0x48, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00 };
    uint8_t smbbuf3[] = {
    0x00, 0x00, 0x00, 0x3b, 0xff, 0x53, 0x4d, 0x42,
    0x2e, 0x00, 0x00, 0x00, 0x00, 0x18, 0x03, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7c, 0x05,
    0x00, 0x08, 0x00, 0x00, 0x0c, 0xff, 0x00, 0xde,
    0xde, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x00, 0x04, 0xff, 0xff, 0xff, 0xff, 0x00,
    0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    uint8_t smbbuf4[] = {
    0x00, 0x00, 0x00, 0x80, 0xff, 0x53, 0x4d, 0x42,
    0x2e, 0x00, 0x00, 0x00, 0x00, 0x98, 0x03, 0xc8,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x7c, 0x05,
    0x00, 0x08, 0x00, 0x00, 0x0c, 0xff, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44,
    0x00, 0x3c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x45, 0x00, 0x00,
    0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
    0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0xb8, 0x10, 0xb8, 0x10, 0x5d, 0xe0, 0x00, 0x00,
    0x0e, 0x00, 0x5c, 0x70, 0x69, 0x70, 0x65, 0x5c,
    0x73, 0x70, 0x6f, 0x6f, 0x6c, 0x73, 0x73, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
    0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
    0x02, 0x00, 0x00, 0x00 };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint32_t smblen2 = sizeof(smbbuf2);
    uint32_t smblen3 = sizeof(smbbuf3);
    uint32_t smblen4 = sizeof(smbbuf4);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOSERVER | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->smb.command != SMB_COM_WRITE_ANDX) {
        printf("expected SMB command 0x%02x , got 0x%02x : ", SMB_COM_WRITE_ANDX, smb_state->smb.command);
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf2, smblen2);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf3, smblen3);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);
    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf4, smblen4);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest05(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t smbbuf1[] = {
        /* session request */
        0x81, 0x00, 0x00, 0x44, 0x20, 0x43, 0x4b, 0x46,
        0x44, 0x45, 0x4e, 0x45, 0x43, 0x46, 0x44, 0x45,
        0x46, 0x46, 0x43, 0x46, 0x47, 0x45, 0x46, 0x46,
        0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint8_t smbbuf2[] = {
        /* session request */
        0x81, 0x00, 0x00, 0x44, 0x20, 0x43, 0x4b, 0x46,
        0x44, 0x45, 0x4e, 0x45, 0x43, 0x46, 0x44, 0x45,
        0x46, 0x46, 0x43, 0x46, 0x47, 0x45, 0x46, 0x46,
        0x43, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x43, 0x41, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00,
        /* session message */
        0x00, 0x00, 0x00, 0x60, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x20,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x2d,
        0x00, 0x00, 0xdd, 0xca, 0x00, 0x3d, 0x00, 0x02,
        0x4d, 0x45, 0x54, 0x41, 0x53, 0x50, 0x4c, 0x4f,
        0x49, 0x54, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d,
        0x41, 0x4e, 0x31, 0x2e, 0x30, 0x00, 0x02, 0x4c,
        0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30, 0x32,
        0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, 0x41, 0x4e,
        0x4d, 0x41, 0x4e, 0x20, 0x31, 0x2e, 0x30, 0x00,
        0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30,
        0x2e, 0x31, 0x32, 0x00
    };
    uint32_t smblen2 = sizeof(smbbuf2);

    int result = 0;
    AppProto alproto;
    Flow f;
    AppLayerProtoDetectThreadCtx *alpd_tctx;
    memset(&f, 0, sizeof(f));
    f.dp = 139;

    /** SMB */
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOCLIENT);
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOSERVER);

    /** SMB2 */
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOCLIENT);
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOSERVER);

    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                                  "139",
                                  ALPROTO_SMB,
                                  SMB_PROBING_PARSER_MIN_DEPTH, 0,
                                  STREAM_TOSERVER,
                                  SMBProbingParser, NULL);

    AppLayerProtoDetectPrepareState();
    alpd_tctx = AppLayerProtoDetectGetCtxThread();

    alproto = AppLayerProtoDetectGetProto(alpd_tctx,
                                          &f,
                                          smbbuf1, smblen1,
                                          IPPROTO_TCP, STREAM_TOSERVER);
    if (alproto != ALPROTO_UNKNOWN) {
        printf("alproto is %"PRIu16 ".  Should be ALPROTO_UNKNOWN\n",
               alproto);
        goto end;
    }

    alproto = AppLayerProtoDetectGetProto(alpd_tctx,
                                          &f,
                                          smbbuf2, smblen2,
                                          IPPROTO_TCP, STREAM_TOSERVER);
    if (alproto != ALPROTO_SMB) {
        printf("alproto is %"PRIu16 ".  Should be ALPROTO_SMB\n",
               alproto);
        goto end;
    }

    result = 1;
 end:
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    if (alpd_tctx != NULL)
        AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest06(void)
{
    AppLayerProtoDetectUnittestCtxBackup();
    AppLayerProtoDetectSetup();

    uint8_t smbbuf1[] = {
        /* session request */
        0x83, 0x00, 0x00, 0x01, 0x82
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint8_t smbbuf2[] = {
        /* session request */
        0x83, 0x00, 0x00, 0x01, 0x82,
        /* session message */
        0x00, 0x00, 0x00, 0x55, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x53, 0xc8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03,
        0x0a, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfd, 0xe3, 0x00, 0x80, 0xb8, 0xcb, 0x22, 0x5f,
        0xfd, 0xeb, 0xc3, 0x01, 0x68, 0x01, 0x00, 0x10,
        0x00, 0x50, 0xb5, 0xc3, 0x62, 0x59, 0x02, 0xd1,
        0x4d, 0x99, 0x6d, 0x85, 0x7d, 0xfa, 0x93, 0x2d,
        0xbb
    };
    uint32_t smblen2 = sizeof(smbbuf2);

    int result = 0;
    AppProto alproto;
    Flow f;
    AppLayerProtoDetectThreadCtx *alpd_tctx;
    memset(&f, 0, sizeof(f));
    f.dp = 139;

    /** SMB */
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOCLIENT);
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB, "|ff|SMB", 8, 4, STREAM_TOSERVER);

    /** SMB2 */
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOCLIENT);
    AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMB2, "|fe|SMB", 8, 4, STREAM_TOSERVER);

    AppLayerProtoDetectPPRegister(IPPROTO_TCP,
                   "139",
                   ALPROTO_SMB,
                   SMB_PROBING_PARSER_MIN_DEPTH, 0,
                   STREAM_TOSERVER,
                   SMBProbingParser, NULL);

    AppLayerProtoDetectPrepareState();
    alpd_tctx = AppLayerProtoDetectGetCtxThread();

    alproto = AppLayerProtoDetectGetProto(alpd_tctx,
                                          &f,
                                          smbbuf1, smblen1,
                                          IPPROTO_TCP, STREAM_TOSERVER);
    if (alproto != ALPROTO_UNKNOWN) {
        printf("alproto is %"PRIu16 ".  Should be ALPROTO_UNKNOWN\n",
               alproto);
        goto end;
    }

    alproto = AppLayerProtoDetectGetProto(alpd_tctx,
                                          &f,
                                          smbbuf2, smblen2,
                                          IPPROTO_TCP, STREAM_TOSERVER);
    if (alproto != ALPROTO_SMB) {
        printf("alproto is %"PRIu16 ".  Should be ALPROTO_SMB\n",
               alproto);
        goto end;
    }

    result = 1;
 end:
    AppLayerProtoDetectDeSetup();
    AppLayerProtoDetectUnittestCtxRestore();
    if (alpd_tctx != NULL)
        AppLayerProtoDetectDestroyCtxThread(alpd_tctx);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest07(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
        /* negative session response */
        0x83, 0x00, 0x00, 0x01, 0x82
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOCLIENT | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->smb.command != 0) {
        printf("we shouldn't have any smb state as yet\n");
        goto end;
    }

    if (smb_state->nbss.length != 1 ||
        smb_state->nbss.type != NBSS_NEGATIVE_SESSION_RESPONSE) {
        printf("something wrong with nbss parsing\n");
        goto end;
    }

    if (smb_state->bytesprocessed != 0) {
        printf("smb parser bytesprocessed should be 0, but it is not\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest08(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
        /* positive session response */
        0x82, 0x00, 0x00, 0x00
    };
    uint8_t smbbuf2[] = {
        /* negotiate protocol */
        0x00, 0x00, 0x00, 0x55, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x53, 0xc8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03,
        0x0a, 0x00, 0x01, 0x00, 0x04, 0x11, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfd, 0xe3, 0x00, 0x80, 0x40, 0x8a, 0x57, 0x5c,
        0xfd, 0xeb, 0xc3, 0x01, 0x68, 0x01, 0x00, 0x10,
        0x00, 0x50, 0xb5, 0xc3, 0x62, 0x59, 0x02, 0xd1,
        0x4d, 0x99, 0x6d, 0x85, 0x7d, 0xfa, 0x93, 0x2d,
        0xbb
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint32_t smblen2 = sizeof(smbbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOCLIENT | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->smb.command != 0) {
        printf("we shouldn't have any smb state as yet\n");
        goto end;
    }

    if (smb_state->nbss.length != 0 ||
        smb_state->nbss.type != NBSS_POSITIVE_SESSION_RESPONSE) {
        printf("something wrong with nbss parsing\n");
        goto end;
    }

    if (smb_state->bytesprocessed != 0) {
        printf("smb parser bytesprocessed should be 0, but it is not\n");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOCLIENT,
                            smbbuf2, smblen2);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    if (smb_state->smb.command != SMB_COM_NEGOTIATE) {
        printf("we should expect SMB command 0x%02x , got 0x%02x : ",
               SMB_COM_NEGOTIATE, smb_state->smb.command);
        goto end;
    }

    if (smb_state->nbss.length != 85 ||
        smb_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("something wrong with nbss parsing\n");
        goto end;
    }

    if (smb_state->bytesprocessed != 0) {
        printf("smb parser bytesprocessed should be 0, but it is not\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

static int SMBParserTest09(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
        /* session request */
        0x81, 0x00, 0x00, 0x44, 0x20, 0x45, 0x44, 0x45,
        0x4a, 0x46, 0x44, 0x45, 0x44, 0x45, 0x50, 0x43,
        0x4e, 0x46, 0x48, 0x44, 0x43, 0x45, 0x4c, 0x43,
        0x4e, 0x46, 0x43, 0x46, 0x45, 0x45, 0x4e, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x00, 0x20, 0x45,
        0x44, 0x45, 0x4a, 0x46, 0x44, 0x45, 0x44, 0x45,
        0x50, 0x43, 0x4e, 0x46, 0x49, 0x46, 0x41, 0x43,
        0x4e, 0x46, 0x43, 0x46, 0x45, 0x45, 0x4e, 0x43,
        0x41, 0x43, 0x41, 0x43, 0x41, 0x41, 0x41, 0x00
    };
    uint8_t smbbuf2[] = {
        /* session service - negotiate protocol */
        0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
        0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
        0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
        0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
        0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
        0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
        0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57,
        0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
        0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
        0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
        0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
        0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54,
        0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
        0x00
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint32_t smblen2 = sizeof(smbbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOSERVER | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->smb.command != 0) {
        printf("we shouldn't have any smb state as yet\n");
        goto end;
    }

    if (smb_state->nbss.length != 68 ||
        smb_state->nbss.type != NBSS_SESSION_REQUEST) {
        printf("something wrong with nbss parsing\n");
        goto end;
    }

    if (smb_state->bytesprocessed != 0) {
        printf("smb parser bytesprocessed should be 0, but it is not\n");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOSERVER,
                            smbbuf2, smblen2);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    if (smb_state->smb.command != SMB_COM_NEGOTIATE) {
        printf("we should expect SMB command 0x%02x , got 0x%02x : ",
               SMB_COM_NEGOTIATE, smb_state->smb.command);
        goto end;
    }

    if (smb_state->nbss.length != 133 ||
        smb_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("something wrong with nbss parsing\n");
        goto end;
    }

    if (smb_state->bytesprocessed != 0) {
        printf("smb parser bytesprocessed should be 0, but it is not\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Test to temporarily to show the direction demaraction issue in the
 *       smb parser.
 */
static int SMBParserTest10(void)
{
    int result = 0;
    Flow f;
    uint8_t smbbuf1[] = {
        /* partial request */
       0x00, 0x00, 0x00, 0x85, 0xff, 0x53, 0x4d, 0x42,
       0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xc8,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
       0x00, 0x00, 0x00, 0x00, 0x00, 0x62, 0x00, 0x02,
       0x50, 0x43, 0x20, 0x4e, 0x45, 0x54, 0x57, 0x4f,
       0x52, 0x4b, 0x20, 0x50, 0x52, 0x4f, 0x47, 0x52,
       0x41, 0x4d, 0x20, 0x31, 0x2e, 0x30, 0x00, 0x02,
       0x4c, 0x41, 0x4e, 0x4d, 0x41, 0x4e, 0x31, 0x2e,
       0x30, 0x00, 0x02, 0x57, 0x69, 0x6e, 0x64, 0x6f,
       0x77, 0x73, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x57,
       0x6f, 0x72, 0x6b, 0x67, 0x72, 0x6f, 0x75, 0x70,
       0x73, 0x20, 0x33, 0x2e, 0x31, 0x61, 0x00, 0x02,
       0x4c, 0x4d, 0x31, 0x2e, 0x32, 0x58, 0x30, 0x30,
       0x32, 0x00, 0x02, 0x4c, 0x41, 0x4e, 0x4d, 0x41,
    };
    //0x4e, 0x32, 0x2e, 0x31, 0x00, 0x02, 0x4e, 0x54,
    //0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32,
    //0x00

    uint8_t smbbuf2[] = {
        /* response */
        0x00, 0x00, 0x00, 0x55, 0xff, 0x53, 0x4d, 0x42,
        0x72, 0x00, 0x00, 0x00, 0x00, 0x98, 0x53, 0xc8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xfe,
        0x00, 0x00, 0x00, 0x00, 0x11, 0x05, 0x00, 0x03,
        0x32, 0x00, 0x01, 0x00, 0x04, 0x41, 0x00, 0x00,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xfd, 0xf3, 0x00, 0x80, 0x20, 0x03, 0x1a, 0x2d,
        0x77, 0x98, 0xc5, 0x01, 0xa4, 0x01, 0x00, 0x10,
        0x00, 0xb7, 0xeb, 0x0b, 0x05, 0x21, 0x22, 0x50,
        0x42, 0x8c, 0x38, 0x2a, 0x7f, 0xc5, 0x6a, 0x7c,
        0x0c
    };
    uint32_t smblen1 = sizeof(smbbuf1);
    uint32_t smblen2 = sizeof(smbbuf2);
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_SMB;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB,
                            STREAM_TOSERVER | STREAM_START, smbbuf1, smblen1);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMBState *smb_state = f.alstate;
    if (smb_state == NULL) {
        printf("no smb state: ");
        goto end;
    }

    if (smb_state->bytesprocessed == 0) {
        printf("request - smb parser bytesprocessed should not be 0.\n");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB, STREAM_TOCLIENT,
                            smbbuf2, smblen2);
    if (r == 0) {
        printf("smb parser didn't return fail\n");
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

#endif

void SMBParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SMBParserTest01", SMBParserTest01);
    UtRegisterTest("SMBParserTest02", SMBParserTest02);
    UtRegisterTest("SMBParserTest03", SMBParserTest03);
    UtRegisterTest("SMBParserTest04", SMBParserTest04);
    UtRegisterTest("SMBParserTest05", SMBParserTest05);
    UtRegisterTest("SMBParserTest06", SMBParserTest06);
    UtRegisterTest("SMBParserTest07", SMBParserTest07);
    UtRegisterTest("SMBParserTest08", SMBParserTest08);
    UtRegisterTest("SMBParserTest09", SMBParserTest09);
    UtRegisterTest("SMBParserTest10", SMBParserTest10);
#endif
}

