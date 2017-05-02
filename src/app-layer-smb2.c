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
 * SMBv2 parser/decoder
 */

#include "suricata-common.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-memcmp.h"

#include "app-layer-smb2.h"

enum {
    SMB2_FIELD_NONE = 0,
    SMB2_PARSE_NBSS_HEADER,
    SMB2_PARSE_SMB_HEADER,

    /* must be last */
    SMB_FIELD_MAX,
};

static uint32_t NBSSParseHeader(void *smb2_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len)
{
    SCEnter();
    SMB2State *sstate = (SMB2State *) smb2_state;
    uint8_t *p = input;

    if (input_len && sstate->bytesprocessed < NBSS_HDR_LEN - 1) {
        switch (sstate->bytesprocessed) {
            case 0:
                /* Initialize */
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

static uint32_t SMB2ParseHeader(void *smb2_state, AppLayerParserState *pstate,
                                uint8_t *input, uint32_t input_len)
{
    SCEnter();

    SMB2State *sstate = (SMB2State *) smb2_state;
    uint8_t *p = input;

    if (input_len) {
        switch (sstate->bytesprocessed) {
            case 4:
                // fallthrough
                /* above statement to prevent coverity FPs from the switch
                 * fall through */
                if (input_len >= SMB2_HDR_LEN) {
                    if (SCMemcmp(p, "\xfe\x53\x4d\x42", 4) != 0) {
                        //printf("SMB2 Header did not validate\n");
                        return 0;
                    }
                    sstate->smb2.StructureSize = *(p + 4);
                    sstate->smb2.StructureSize |= *(p + 5) << 8;
                    sstate->smb2.CreditCharge = *(p + 6);
                    sstate->smb2.CreditCharge |= *(p + 7) << 8;
                    sstate->smb2.Status = *(p + 8);
                    sstate->smb2.Status |= *(p + 9) << 8;
                    sstate->smb2.Status |= *(p + 10) << 16;
                    sstate->smb2.Status |= *(p + 11) << 24;
                    sstate->smb2.Command = *(p + 12);
                    sstate->smb2.Command |= *(p + 13) << 8;
                    sstate->smb2.CreditRequestResponse = *(p + 14);
                    sstate->smb2.CreditRequestResponse |= *(p + 15) << 8;
                    sstate->smb2.Flags = *(p + 16);
                    sstate->smb2.Flags |= *(p + 17) << 8;
                    sstate->smb2.Flags |= *(p + 18) << 16;
                    sstate->smb2.Flags |= *(p + 19) << 24;
                    sstate->smb2.NextCommand = *(p + 20);
                    sstate->smb2.NextCommand |= *(p + 21) << 8;
                    sstate->smb2.NextCommand |= *(p + 22) << 16;
                    sstate->smb2.NextCommand |= *(p + 23) << 24;
                    sstate->smb2.MessageId = *(p + 24);
                    sstate->smb2.MessageId |= *(p + 25) << 8;
                    sstate->smb2.MessageId |= *(p + 26) << 16;
                    sstate->smb2.MessageId |= (uint64_t) *(p + 27) << 24;
                    sstate->smb2.MessageId |= (uint64_t) *(p + 28) << 32;
                    sstate->smb2.MessageId |= (uint64_t) *(p + 29) << 40;
                    sstate->smb2.MessageId |= (uint64_t) *(p + 30) << 48;
                    sstate->smb2.MessageId |= (uint64_t) *(p + 31) << 56;
                    sstate->smb2.ProcessId = *(p + 32);
                    sstate->smb2.ProcessId |= *(p + 33) << 8;
                    sstate->smb2.ProcessId |= *(p + 34) << 16;
                    sstate->smb2.ProcessId |= *(p + 35) << 24;
                    sstate->smb2.TreeId = *(p + 36);
                    sstate->smb2.TreeId |= *(p + 37) << 8;
                    sstate->smb2.TreeId |= *(p + 38) << 16;
                    sstate->smb2.TreeId |= *(p + 39) << 24;
                    sstate->smb2.SessionId = *(p + 40);
                    sstate->smb2.SessionId |= *(p + 41) << 8;
                    sstate->smb2.SessionId |= *(p + 42) << 16;
                    sstate->smb2.SessionId |= (uint64_t) *(p + 43) << 24;
                    sstate->smb2.SessionId |= (uint64_t) *(p + 44) << 32;
                    sstate->smb2.SessionId |= (uint64_t) *(p + 45) << 40;
                    sstate->smb2.SessionId |= (uint64_t) *(p + 46) << 48;
                    sstate->smb2.SessionId |= (uint64_t) *(p + 47) << 56;
                    sstate->smb2.Signature[0] = *(p + 48);
                    sstate->smb2.Signature[1] = *(p + 49);
                    sstate->smb2.Signature[2] = *(p + 50);
                    sstate->smb2.Signature[3] = *(p + 51);
                    sstate->smb2.Signature[4] = *(p + 52);
                    sstate->smb2.Signature[5] = *(p + 53);
                    sstate->smb2.Signature[6] = *(p + 54);
                    sstate->smb2.Signature[7] = *(p + 55);
                    sstate->smb2.Signature[8] = *(p + 56);
                    sstate->smb2.Signature[9] = *(p + 57);
                    sstate->smb2.Signature[10] = *(p + 58);
                    sstate->smb2.Signature[11] = *(p + 59);
                    sstate->smb2.Signature[12] = *(p + 60);
                    sstate->smb2.Signature[13] = *(p + 61);
                    sstate->smb2.Signature[14] = *(p + 62);
                    sstate->smb2.Signature[15] = *(p + 63);
                    sstate->bytesprocessed += SMB2_HDR_LEN;
                    SCReturnUInt(64U);
                    break;
                } else {
                    //sstate->smb2.protocol[0] = *(p++);
                    if (*(p++) != 0xfe)
                        return 0;
                    if (!(--input_len))
                        break;
                    /* We fall through to the next case if we still have input.
                     * Same applies for other cases as well */
                }
                /* fall through */
            case 5:
                //sstate->smb2.protocol[1] = *(p++);
                if (*(p++) != 'S')
                    return 0;
                if (!(--input_len))
                    break;
                /* fall through */
            case 6:
                //sstate->smb2.protocol[2] = *(p++);
                if (*(p++) != 'M')
                    return 0;
                if (!(--input_len))
                    break;
                /* fall through */
            case 7:
                //sstate->smb2.protocol[3] = *(p++);
                if (*(p++) != 'B')
                    return 0;
                if (!(--input_len))
                    break;
                /* fall through */
            case 8:
                sstate->smb2.StructureSize = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 9:
                sstate->smb2.StructureSize |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 10:
                sstate->smb2.CreditCharge = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 11:
                sstate->smb2.CreditCharge |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 12:
                sstate->smb2.Status = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 13:
                sstate->smb2.Status |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 14:
                sstate->smb2.Status |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 15:
                sstate->smb2.Status |= *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 16:
                sstate->smb2.Command = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 17:
                sstate->smb2.Command |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 18:
                sstate->smb2.CreditRequestResponse = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 19:
                sstate->smb2.CreditRequestResponse |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 20:
                sstate->smb2.Flags = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 21:
                sstate->smb2.Flags |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 22:
                sstate->smb2.Flags |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 23:
                sstate->smb2.Flags |= *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 24:
                sstate->smb2.NextCommand = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 25:
                sstate->smb2.NextCommand |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 26:
                sstate->smb2.NextCommand |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 27:
                sstate->smb2.NextCommand |= *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 28:
                sstate->smb2.MessageId = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 29:
                sstate->smb2.MessageId = *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 30:
                sstate->smb2.MessageId = *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 31:
                sstate->smb2.MessageId = (uint64_t) *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 32:
                sstate->smb2.MessageId = (uint64_t) *(p++) << 32;
                if (!(--input_len))
                    break;
                /* fall through */
            case 33:
                sstate->smb2.MessageId = (uint64_t) *(p++) << 40;
                if (!(--input_len))
                    break;
                /* fall through */
            case 34:
                sstate->smb2.MessageId = (uint64_t) *(p++) << 48;
                if (!(--input_len))
                    break;
                /* fall through */
            case 35:
                sstate->smb2.MessageId = (uint64_t) *(p++) << 56;
                if (!(--input_len))
                    break;
                /* fall through */
            case 36:
                sstate->smb2.ProcessId = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 37:
                sstate->smb2.ProcessId |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 38:
                sstate->smb2.ProcessId |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 39:
                sstate->smb2.ProcessId |= *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 40:
                sstate->smb2.TreeId = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 41:
                sstate->smb2.TreeId |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 42:
                sstate->smb2.TreeId |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 43:
                sstate->smb2.TreeId |= *(p++) <<  24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 44:
                sstate->smb2.SessionId = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 45:
                sstate->smb2.SessionId |= *(p++) << 8;
                if (!(--input_len))
                    break;
                /* fall through */
            case 46:
                sstate->smb2.SessionId |= *(p++) << 16;
                if (!(--input_len))
                    break;
                /* fall through */
            case 47:
                sstate->smb2.SessionId |= (uint64_t) *(p++) << 24;
                if (!(--input_len))
                    break;
                /* fall through */
            case 48:
                sstate->smb2.SessionId |= (uint64_t) *(p++) << 32;
                if (!(--input_len))
                    break;
                /* fall through */
            case 49:
                sstate->smb2.SessionId |= (uint64_t) *(p++) << 40;
                if (!(--input_len))
                    break;
                /* fall through */
            case 50:
                sstate->smb2.SessionId |= (uint64_t) *(p++) << 48;
                if (!(--input_len))
                    break;
                /* fall through */
            case 51:
                sstate->smb2.SessionId |= (uint64_t) *(p++) << 56;
                if (!(--input_len))
                    break;
                /* fall through */
            case 52:
                sstate->smb2.Signature[0] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 53:
                sstate->smb2.Signature[1] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 54:
                sstate->smb2.Signature[2] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 55:
                sstate->smb2.Signature[3] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 56:
                sstate->smb2.Signature[4] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 57:
                sstate->smb2.Signature[5] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 58:
                sstate->smb2.Signature[6] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 59:
                sstate->smb2.Signature[7] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 60:
                sstate->smb2.Signature[8] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 61:
                sstate->smb2.Signature[9] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 62:
                sstate->smb2.Signature[10] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 63:
                sstate->smb2.Signature[11] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 64:
                sstate->smb2.Signature[12] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 65:
                sstate->smb2.Signature[13] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 66:
                sstate->smb2.Signature[14] = *(p++);
                if (!(--input_len))
                    break;
                /* fall through */
            case 67:
                sstate->smb2.Signature[15] = *(p++);
                --input_len;
                break;
                /* fall through */
        }
    }
    sstate->bytesprocessed += (p - input);
    SCReturnUInt((uint32_t)(p - input));
}

static int SMB2Parse(Flow *f, void *smb2_state, AppLayerParserState *pstate,
                     uint8_t *input, uint32_t input_len,
                     void *local_data)
{
    SCEnter();
    SMB2State *sstate = (SMB2State *) smb2_state;
    uint32_t retval = 0;
    uint32_t parsed = 0;

    if (pstate == NULL)
        return -1;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    while (sstate->bytesprocessed <  NBSS_HDR_LEN && input_len) {
        retval = NBSSParseHeader(smb2_state, pstate, input, input_len);
        if (retval <= input_len) {
            parsed += retval;
            input_len -= retval;
        } else {
            return -1;
        }

        SCLogDebug("NBSS Header (%u/%u) Type 0x%02x Length 0x%04x parsed %u input_len %u",
                sstate->bytesprocessed, NBSS_HDR_LEN, sstate->nbss.type,
                sstate->nbss.length, parsed, input_len);
    }

    switch(sstate->nbss.type) {
        case NBSS_SESSION_MESSAGE:
            while (input_len && (sstate->bytesprocessed >= NBSS_HDR_LEN &&
                        sstate->bytesprocessed < NBSS_HDR_LEN + SMB2_HDR_LEN)) {
                retval = SMB2ParseHeader(smb2_state, pstate, input + parsed, input_len);
                if (retval <= input_len) {
                    parsed += retval;
                    input_len -= retval;
                } else {
                    return -1;
                }

                SCLogDebug("SMB2 Header (%u/%u) Command 0x%04x parsed %u input_len %u",
                        sstate->bytesprocessed, NBSS_HDR_LEN + SMB2_HDR_LEN,
                        sstate->smb2.Command, parsed, input_len);
            }
            break;
        default:
            break;
    }
    SCReturnInt(1);
}


static void *SMB2StateAlloc(void)
{
    void *s = SCMalloc(sizeof(SMB2State));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(SMB2State));
    return s;
}

static void SMB2StateFree(void *s)
{
    if (s) {
        SCFree(s);
        s = NULL;
    }
}

void RegisterSMB2Parsers(void)
{
    /** SMB2 */
    const char *proto_name = "smb2";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMB2, STREAM_TOSERVER, SMB2Parse);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMB2, STREAM_TOCLIENT, SMB2Parse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SMB2, SMB2StateAlloc, SMB2StateFree);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SMB2, SMB2ParserRegisterTests);
#endif
    return;
}

/* UNITTESTS */
#ifdef UNITTESTS

static int SMB2ParserTest01(void)
{
    int result = 1;
    Flow f;
    uint8_t smb2buf[] =
        "\x00\x00\x00\x66" // NBSS
        "\xfe\x53\x4d\x42\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00" // SMB2
        "\x3f\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x24\x00\x01\x00x00\x00\x00\x00\x00\x00\x0\x00\x00\x00\x00\x00\x00\x00\x00"
        "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x02";

    uint32_t smb2len = sizeof(smb2buf) - 1;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMB2,
                                STREAM_TOSERVER | STREAM_EOF, smb2buf,
                                smb2len);
    if (r != 0) {
        printf("smb2 header check returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    SMB2State *smb2_state = f.alstate;
    if (smb2_state == NULL) {
        printf("no smb2 state: ");
        result = 0;
        goto end;
    }

    if (smb2_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("expected nbss type 0x%02x , got 0x%02x : ", NBSS_SESSION_MESSAGE, smb2_state->nbss.type);
        result = 0;
        goto end;
    }

    if (smb2_state->nbss.length != 102) {
        printf("expected nbss length 0x%02x , got 0x%02x : ", 102, smb2_state->nbss.length);
        result = 0;
        goto end;
    }

    if (smb2_state->smb2.Command != SMB2_NEGOTIATE) {
        printf("expected SMB2 command 0x%04x , got 0x%04x : ", SMB2_NEGOTIATE, smb2_state->smb2.Command);
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

void SMB2ParserRegisterTests(void)
{
    UtRegisterTest("SMB2ParserTest01", SMB2ParserTest01);
}
#endif

