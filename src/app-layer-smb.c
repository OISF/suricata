/*
 * Copyright (c) 2009 Open Information Security Foundation
 * app-layer-smb.c
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */
#include "eidps-common.h"

#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"

#include "util-binsearch.h"
#include "util-unittest.h"

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

void hexdump(const void *buf, size_t len) {
    /* dumps len bytes of *buf to stdout. Looks like:
     * [0000] 75 6E 6B 6E 6F 77 6E 20
     *                  30 FF 00 00 00 00 39 00 unknown 0.....9.
     * (in a single line of course)
     */

    const unsigned char *p = buf;
    unsigned char c;
    size_t n;
    char bytestr[4] = { 0 };
    char addrstr[10] = { 0 };
    char hexstr[16 * 3 + 5] = { 0 };
    char charstr[16 * 1 + 5] = { 0 };
    for (n = 1; n <= len; n++) {
        if (n % 16 == 1) {
            /* store address for this line */
#if __WORDSIZE == 64
            snprintf(addrstr, sizeof(addrstr), "%.4lx",
                    ((uint64_t)p-(uint64_t)buf) );
#else
            snprintf(addrstr, sizeof(addrstr), "%.4x", ((uint32_t) p
                        - (uint32_t) buf));
#endif
        }

        c = *p;
        if (isalnum(c) == 0) {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr) - strlen(hexstr) - 1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr) - strlen(charstr) - 1);

        if (n % 16 == 0) {
            /* line completed */
            printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        } else if (n % 8 == 0) {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr) - strlen(hexstr) - 1);
            strncat(charstr, " ", sizeof(charstr) - strlen(charstr) - 1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0) {
        /* print rest of buffer if not empty */
        printf("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

static int SMBParseAndX(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    switch (sstate->andx.andxbytesprocessed) {
        case 0:
            sstate->andx.andxcommand = *(p++);
            if (!(--input_len)) break;
        case 2:
            p++; // Reserved
            if (!(--input_len)) break;
        case 3:
            sstate->andx.andxoffset |= *(p++) << 8;
            if (!(--input_len)) break;
        case 4:
            sstate->andx.andxoffset |= *(p++);
            if (!(--input_len)) break;
        default:
            break;
    }
    return 0;
}

/*
 * Obtain SMB WordCount which is 2 times the value.
 * Reset bytecount.bytecountbytes to 0.
 * Determine if this is an SMB AndX Command
 */
static int SMBGetWordCount(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    if (input_len) {
        SMBState *sstate = (SMBState *) smb_state;
        sstate->wordcount.wordcount = *(input) * 2;
        sstate->bytesprocessed++;
        sstate->bytecount.bytecountbytes = 0;
        sstate->andx.isandx = isAndX(sstate);
        printf("Wordcount (%u):\n", sstate->wordcount.wordcount);
        return 1;
    }
    return 0;
}

/*
 * Obtain SMB Bytecount. Handle the corner obfuscation case where a packet boundary
 * is after the first bytecount byte.
 */
static int SMBGetByteCount(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    if (input_len) {
        SMBState *sstate = (SMBState *) smb_state;
        uint8_t *p = input;
        switch(sstate->bytecount.bytecountbytes) {
            case 0:
                sstate->bytecount.bytecount = *(p++) << 8;
                sstate->bytecount.bytecountbytes++;
                if (!(--input_len)) break;
            case 1:
                sstate->bytecount.bytecount |= *(p++);
                sstate->bytecount.bytecountbytes++;
                printf("Bytecount %u\n", sstate->bytecount.bytecount);
                break;
            default:
                return 0;
        }
        sstate->bytesprocessed += (p - input);
        return 1;
    }
    return 0;
}

static int SMBParseWordCount(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    while (sstate->wordcount.wordcount-- && input_len--) {
        if (sstate->andx.isandx) {
            SMBParseAndX(smb_state, pstate, input, input_len, output);
        }
        printf("0x%02x\n", *(p++));
    }
    sstate->bytesprocessed += (p - input);
    return 0;
}

static int SMBParseByteCount(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    while (sstate->bytecount.bytecount-- && input_len--) {
        printf("0x%02x\n", *(p++));
    }
    sstate->bytesprocessed += (p - input);
    return 0;
}

#define DEBUG 1
static int NBSSParseHeader(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    if (input_len && sstate->bytesprocessed < NBSS_HDR_LEN - 1) {
        switch (sstate->bytesprocessed) {
            case 0:
                if (input_len >= NBSS_HDR_LEN) {
                    sstate->nbss.type = *p;
                    sstate->nbss.length = (*(p + 1) & 0x01) << 16;
                    sstate->nbss.length |= *(p + 2) << 8;
                    sstate->nbss.length |= *(p + 3);
                    input_len -= NBSS_HDR_LEN;
                    sstate->bytesprocessed += NBSS_HDR_LEN;
                    return 0;
                } else {
                    sstate->nbss.type = *(p++);
                    if (!(--input_len)) break;
                }
            case 1:
                sstate->nbss.length = (*(p++) & 0x01) << 16;
                if (!(--input_len)) break;
            case 2:
                sstate->nbss.length |= *(p++) << 8;
                if (!(--input_len)) break;
            case 3:
                sstate->nbss.length |= *(p++);
                --input_len;
                break;
            default:
                return -1;
                break;
        }
        sstate->bytesprocessed += (p - input);
    }
    return 0;
}

static int SMBParseHeader(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint8_t *p = input;
    hexdump(p, input_len);
    if (input_len) {
        switch (sstate->bytesprocessed) {
            case 4:
                if (input_len >= SMB_HDR_LEN) {
                    //if (sstate->nbss.type != NBSS_SESSION_MESSAGE) return 1;
                    //if (sstate->nbss.length < MINIMUM_SMB_LEN) return 2;
                    if (memcmp(p, "\xff\x53\x4d\x42", 4) != 0) {
                        printf("SMB Header did not validate\n");
                        return 3;
                    }
                    sstate->smb.command = *(p + 4);
                    sstate->smb.status = *(p + 5) << 24;
                    sstate->smb.status |= *(p + 6) << 16;
                    sstate->smb.status |= *(p + 7) << 8;
                    sstate->smb.status |= *(p + 8);
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
                    input_len -= (SMB_HDR_LEN + 1);
                    sstate->bytesprocessed += (SMB_HDR_LEN + 1);
                    return 1;
                    break;
                } else {
                    //sstate->smb.protocol[0] = *(p++);
                    if (*(p++) != 0xff)
                        return 4;
                    if (!(--input_len)) break;
                }
            case 5:
                //sstate->smb.protocol[1] = *(p++);
                if (*(p++) != 'S')
                    return 5;
                if (!(--input_len)) break;
            case 6:
                //sstate->smb.protocol[2] = *(p++);
                if (*(p++) != 'M')
                    return 6;
                if (!(--input_len)) break;
            case 7:
                //sstate->smb.protocol[3] = *(p++);
                if (*(p++) != 'B')
                    return 7;
                if (!(--input_len)) break;
            case 8:
                sstate->smb.command = *(p++);
                if (!(--input_len)) break;
            case 9:
                sstate->smb.status = *(p++) << 24;
                if (!(--input_len)) break;
            case 10:
                sstate->smb.status |= *(p++) << 16;
                if (!(--input_len)) break;
            case 11:
                sstate->smb.status |= *(p++) << 8;
                if (!(--input_len)) break;
            case 12:
                sstate->smb.status |= *(p++);
                if (!(--input_len)) break;
            case 13:
                sstate->smb.flags = *(p++);
                if (!(--input_len)) break;
            case 14:
                sstate->smb.flags2 = *(p++) << 8;
                if (!(--input_len)) break;
            case 15:
                sstate->smb.flags2 |= *(p++);
                if (!(--input_len)) break;
            case 16:
                sstate->smb.pidhigh = *(p++) << 8;
                if (!(--input_len)) break;
            case 17:
                sstate->smb.pidhigh |= *(p++);
                if (!(--input_len)) break;
            case 18:
                sstate->smb.securitysignature = (uint64_t) *(p++) << 56;
                if (!(--input_len)) break;
            case 19:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 48;
                if (!(--input_len)) break;
            case 20:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 40;
                if (!(--input_len)) break;
            case 21:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 32;
                if (!(--input_len)) break;
            case 22:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 24;
                if (!(--input_len)) break;
            case 23:
                sstate->smb.securitysignature |=(uint64_t) *(p++) << 16;
                if (!(--input_len)) break;
            case 24:
                sstate->smb.securitysignature |= (uint64_t) *(p++) << 8;
                if (!(--input_len)) break;
            case 25:
                sstate->smb.securitysignature |= (uint64_t) *(p++);
                if (!(--input_len)) break;
            case 26:
                p++; // UNUSED
                if (!(--input_len)) break;
            case 27:
                p++; // UNUSED
                if (!(--input_len)) break;
            case 28:
                sstate->smb.tid = *(p++) << 8;
                if (!(--input_len)) break;
            case 29:
                sstate->smb.tid |= *(p++);
                if (!(--input_len)) break;
            case 30:
                sstate->smb.pid = *(p++) << 8;
                if (!(--input_len)) break;
            case 31:
                sstate->smb.pid |= *(p++);
                if (!(--input_len)) break;
            case 32:
                sstate->smb.uid = *(p++) << 8;
                if (!(--input_len)) break;
            case 33:
                sstate->smb.uid |= *(p++);
                if (!(--input_len)) break;
            case 34:
                sstate->smb.mid = *(p++) << 8;
                if (!(--input_len)) break;
            case 35:
                sstate->smb.mid |= *(p++);
                --input_len;
                break;
            default: // SHOULD NEVER OCCUR
                return 8;
        }
    }
    sstate->bytesprocessed += (p - input);
    return 0;
}

static int SMBParse(void *smb_state, AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len, AppLayerParserResult *output) {
    SMBState *sstate = (SMBState *) smb_state;
    uint16_t max_fields = 3;
    uint16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {
        printf("SMBParse: u %" PRIu32 "\n", u);
        switch (u) {
            case 0:
                {
                    int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_NBSS_HEADER,
                            NBSS_HDR_LEN, input, input_len, &offset);

                    if (r == 0) {
                        pstate->parse_field = 0;
                        return 0;
                    }
                    break;
                }
            case 1:
                {
                    uint8_t *data = input + offset;
                    uint32_t data_len = input_len - offset;
                    if (sstate->nbss.type == NBSS_SESSION_MESSAGE) {
                        int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_SMB_HEADER,
                                SMB_HDR_LEN, data, data_len, &offset);
                        if (r == 0) {
                            pstate->parse_field = 1;
                            return 0;
                        }
                    }
                    break;
                }
            case 2:
                {
                    uint8_t *data = input + offset;
                    uint32_t data_len = input_len - offset;
                    int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_GET_WORDCOUNT,
                            1, data, data_len, &offset);
                    if (r == 0) {
                        pstate->parse_field = 2;
                        return 0;
                    }
                    break;
                }
            case 3:
                {
                    uint8_t *data = input + offset;
                    uint32_t data_len = input_len - offset;
                    printf("wordcount %d\n", sstate->wordcount.wordcount);

                    int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_WORDCOUNT,
                            sstate->wordcount.wordcount, data, data_len, &offset);
                    if (r == 0) {
                        pstate->parse_field = 3;
                        return 0;
                    }
                    break;
                }
            case 4:
                {
                    uint8_t *data = input + offset;
                    uint32_t data_len = input_len - offset;

                    int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_GET_BYTECOUNT,
                            2, data, data_len, &offset);
                    if (r == 0) {
                        pstate->parse_field = 4;
                        return 0;
                    }
                    break;
                }
            case 5:
                {
                    uint8_t *data = input + offset;
                    uint32_t data_len = input_len - offset;

                    int r = AlpParseFieldBySize(output, pstate, SMB_PARSE_BYTECOUNT,
                            sstate->bytecount.bytecount, data, data_len, &offset);
                    if (r == 0) {
                        pstate->parse_field = 5;
                        return 0;
                    }
                    break;
                }
        }
    }

    pstate->parse_field = 0;
    pstate->flags |= APP_LAYER_PARSER_DONE;
    return 1;
}

int isAndX(SMBState *smb_state) {
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
            return 1;
        default:
            return 0;
    }
}

static void *SMBStateAlloc(void) {
    void *s = malloc(sizeof(SMBState));
    if (s == NULL)
        return NULL;

    memset(s, 0, sizeof(SMBState));
    return s;
}

static void SMBStateFree(void *s) {
    if (s) {
        free(s);
        s = NULL;
    }
}

void RegisterSMBParsers(void) {
    AppLayerRegisterProto("smb", ALPROTO_SMB, STREAM_TOSERVER, SMBParse);
    AppLayerRegisterProto("smb", ALPROTO_SMB, STREAM_TOCLIENT, SMBParse);
    AppLayerRegisterParser("nbss.hdr", ALPROTO_SMB, SMB_PARSE_NBSS_HEADER,
            NBSSParseHeader, "smb");
    AppLayerRegisterParser("smb.hdr", ALPROTO_SMB, SMB_PARSE_SMB_HEADER,
            SMBParseHeader, "smb");
    AppLayerRegisterParser("smb.getwordcount", ALPROTO_SMB, SMB_PARSE_GET_WORDCOUNT,
            SMBGetWordCount, "smb");
    AppLayerRegisterParser("smb.wordcount", ALPROTO_SMB, SMB_PARSE_WORDCOUNT,
            SMBParseWordCount, "smb");
    AppLayerRegisterParser("smb.getbytecount", ALPROTO_SMB, SMB_PARSE_GET_BYTECOUNT,
            SMBGetByteCount, "smb");
    AppLayerRegisterParser("smb.bytecount", ALPROTO_SMB, SMB_PARSE_BYTECOUNT,
            SMBParseByteCount, "smb");
    AppLayerRegisterStateFuncs(ALPROTO_SMB, SMBStateAlloc, SMBStateFree);
}

/* UNITTESTS */
#ifdef UNITTESTS

int SMBParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t smbbuf[] = "\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00"
        "\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00"
        "\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20"
        "\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73"
        "\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c"
        "\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54"
        "\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00";

    uint32_t smblen = sizeof(smbbuf) - 1;
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    StreamL7DataPtrInit(&ssn,StreamL7GetStorageSize());
    f.protoctx = (void *)&ssn;

    int r = AppLayerParse(&f, ALPROTO_SMB, STREAM_TOSERVER|STREAM_EOF, smbbuf, smblen, FALSE);
    if (r != 0) {
        printf("smb header check returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    SMBState *smb_state = ssn.aldata[AlpGetStateIdx(ALPROTO_SMB)];
    if (smb_state == NULL) {
        printf("no smb state: ");
        result = 0;
        goto end;
    }

    if (smb_state->nbss.type != NBSS_SESSION_MESSAGE) {
        printf("expected nbss type 0x%02x , got 0x%02x : ", NBSS_SESSION_MESSAGE, smb_state->nbss.type);
        result = 0;
        goto end;
    }

    if (smb_state->nbss.length != 133) {
        printf("expected nbss length 0x%02x , got 0x%02x : ", 133, smb_state->nbss.length);
        result = 0;
        goto end;
    }

    if (smb_state->smb.command != SMB_COM_NEGOTIATE) {
        printf("expected SMB command 0x%02x , got 0x%02x : ", SMB_COM_NEGOTIATE, smb_state->smb.command);
        result = 0;
        goto end;
    }

end:
    return result;
}

void SMBParserRegisterTests(void) {
    printf("SMBParserRegisterTests\n");
    UtRegisterTest("SMBParserTest01", SMBParserTest01, 1);
}
#endif

