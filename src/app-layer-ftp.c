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
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * App Layer Parser for FTP
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"

#include "detect-engine-state.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ftp.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-memcmp.h"

/**
 * \brief This function is called to determine and set which command is being
 * transfered to the ftp server
 * \param ftp_state the ftp state structure for the parser
 * \param input input line of the command
 * \param len of the command
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseRequestCommand(void *ftp_state, uint8_t *input,
                                  uint32_t input_len) {
    SCEnter();
    FtpState *fstate = (FtpState *)ftp_state;

    if (input_len >= 4) {
        if (SCMemcmpLowercase("port", input, 4) == 0) {
            fstate->command = FTP_COMMAND_PORT;
        }

        /* else {
         *     Add the ftp commands you need here
         * }
         */
    }
    return 1;
}

/**
 * \brief This function is called to retrieve the request line and parse it
 * \param ftp_state the ftp state structure for the parser
 * \param input input line of the command
 * \param input_len length of the request
 * \param output the resulting output
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseRequestCommandLine(Flow *f, void *ftp_state, AppLayerParserState
                                      *pstate, uint8_t *input,uint32_t input_len,
                                      void *local_data, AppLayerParserResult *output) {
    SCEnter();
    //PrintRawDataFp(stdout, input,input_len);

    FtpState *fstate = (FtpState *)ftp_state;
    uint16_t max_fields = 2;
    uint16_t u = 0;
    uint32_t offset = 0;

    if (pstate == NULL)
        return -1;

    for (u = pstate->parse_field; u < max_fields; u++) {

        switch(u) {
            case 0: /* REQUEST COMMAND */
            {
                const uint8_t delim[] = { 0x20, };
                int r = AlpParseFieldByDelimiter(output, pstate,
                                FTP_FIELD_REQUEST_COMMAND, delim, sizeof(delim),
                                input, input_len, &offset);

                if (r == 0) {
                    pstate->parse_field = 0;
                    return 0;
                }
                fstate->arg_offset = offset;
                FTPParseRequestCommand(ftp_state, input, input_len);
                break;
            }
            case 1: /* REQUEST COMMAND ARG */
            {
                switch (fstate->command) {
                    case FTP_COMMAND_PORT:
                        /* We don't need to parse args, we are going to check
                        * the ftpbounce condition directly from detect-ftpbounce
                        */
                        if (fstate->port_line != NULL)
                            SCFree(fstate->port_line);
                        fstate->port_line = SCMalloc(input_len);
                        if (fstate->port_line == NULL)
                            return 0;
                        fstate->port_line = memcpy(fstate->port_line, input,
                                                   input_len);
                        fstate->port_line_len = input_len;
                    break;
                    default:
                    break;
                } /* end switch command specified args */

                break;
            }
        }
    }

    pstate->parse_field = 0;
    return 1;
}

/**
 * \brief This function is called to retrieve a ftp request
 * \param ftp_state the ftp state structure for the parser
 * \param input input line of the command
 * \param input_len length of the request
 * \param output the resulting output
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseRequest(Flow *f, void *ftp_state,
                           AppLayerParserState *pstate,
                           uint8_t *input, uint32_t input_len,
                           void *local_data, AppLayerParserResult *output)
{
    SCEnter();
    /* PrintRawDataFp(stdout, input,input_len); */

    uint32_t offset = 0;

    if (pstate == NULL)
        return -1;


    //PrintRawDataFp(stdout, pstate->store, pstate->store_len);

    const uint8_t delim[] = { 0x0D, 0x0A };
    int r = AlpParseFieldByDelimiter(output, pstate, FTP_FIELD_REQUEST_LINE,
                                     delim, sizeof(delim), input, input_len,
                                     &offset);
    if (r == 0) {
        pstate->parse_field = 0;
        return 0;
    }
    if (pstate->store_len)
        PrintRawDataFp(stdout, pstate->store, pstate->store_len);

    pstate->parse_field = 0;
    return 1;
}

/**
 * \brief This function is called to retrieve a ftp response
 * \param ftp_state the ftp state structure for the parser
 * \param input input line of the command
 * \param input_len length of the request
 * \param output the resulting output
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseResponse(Flow *f, void *ftp_state, AppLayerParserState *pstate,
                            uint8_t *input, uint32_t input_len,
                            void *local_data, AppLayerParserResult *output)
{
    SCEnter();
    //PrintRawDataFp(stdout, input,input_len);

    uint32_t offset = 0;
    FtpState *fstate = (FtpState *)ftp_state;

    if (pstate == NULL)
        return -1;


    const uint8_t delim[] = { 0x0D, 0x0A };
    int r = AlpParseFieldByDelimiter(output, pstate, FTP_FIELD_RESPONSE_LINE,
                                     delim, sizeof(delim), input, input_len,
                                     &offset);
    if (r == 0) {
        pstate->parse_field = 0;
        return 0;
    }
    char rcode[5];
    memcpy(rcode, input, 4);
    rcode[4] = '\0';
    fstate->response_code = atoi(rcode);
    SCLogDebug("Response: %u\n", fstate->response_code);

    pstate->parse_field = 0;
    return 1;
}

#ifdef DEBUG
static SCMutex ftp_state_mem_lock = PTHREAD_MUTEX_INITIALIZER;
static uint64_t ftp_state_memuse = 0;
static uint64_t ftp_state_memcnt = 0;
#endif

static void *FTPStateAlloc(void) {
    void *s = SCMalloc(sizeof(FtpState));
    if (unlikely(s == NULL))
        return NULL;

    memset(s, 0, sizeof(FtpState));

#ifdef DEBUG
    SCMutexLock(&ftp_state_mem_lock);
    ftp_state_memcnt++;
    ftp_state_memuse+=sizeof(FtpState);
    SCMutexUnlock(&ftp_state_mem_lock);
#endif
    return s;
}

static void FTPStateFree(void *s) {
    FtpState *fstate = (FtpState *) s;
    if (fstate->port_line != NULL)
        SCFree(fstate->port_line);
    SCFree(s);
#ifdef DEBUG
    SCMutexLock(&ftp_state_mem_lock);
    ftp_state_memcnt--;
    ftp_state_memuse-=sizeof(FtpState);
    SCMutexUnlock(&ftp_state_mem_lock);
#endif
}


void RegisterFTPParsers(void) {
    char *proto_name = "ftp";

    /** FTP */
    AlpProtoAdd(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_FTP, "USER ", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_FTP, "PASS ", 5, 0, STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, proto_name, IPPROTO_TCP, ALPROTO_FTP, "PORT ", 5, 0, STREAM_TOSERVER);

    AppLayerRegisterProto(proto_name, ALPROTO_FTP, STREAM_TOSERVER,
                          FTPParseRequest);
    AppLayerRegisterProto(proto_name, ALPROTO_FTP, STREAM_TOCLIENT,
                          FTPParseResponse);
    AppLayerRegisterParser("ftp.request_command_line", ALPROTO_FTP,
                           FTP_FIELD_REQUEST_LINE, FTPParseRequestCommandLine,
                           "ftp");
    AppLayerRegisterStateFuncs(ALPROTO_FTP, FTPStateAlloc, FTPStateFree);
}

void FTPAtExitPrintStats(void) {
#ifdef DEBUG
    SCMutexLock(&ftp_state_mem_lock);
    SCLogDebug("ftp_state_memcnt %"PRIu64", ftp_state_memuse %"PRIu64"",
               ftp_state_memcnt, ftp_state_memuse);
    SCMutexUnlock(&ftp_state_mem_lock);
#endif
}

/* UNITTESTS */
#ifdef UNITTESTS

/** \test Send a get request in one chunk. */
int FTPParserTest01(void) {
    int result = 1;
    Flow f;
    uint8_t ftpbuf[] = "PORT 192,168,1,1,0,80\r\n";
    uint32_t ftplen = sizeof(ftpbuf) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf, ftplen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_PORT) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", FTP_COMMAND_PORT, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a splitted get request. */
int FTPParserTest03(void) {
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "POR";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    uint8_t ftpbuf2[] = "T 192,168,1";
    uint32_t ftplen2 = sizeof(ftpbuf2) - 1; /* minus the \0 */
    uint8_t ftpbuf3[] = "1,1,10,20\r\n";
    uint32_t ftplen3 = sizeof(ftpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER, ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf3, ftplen3);
    if (r != 0) {
        SCLogDebug("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_PORT) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", FTP_COMMAND_PORT, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test See how it deals with an incomplete request. */
int FTPParserTest06(void) {
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_UNKNOWN) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", FTP_COMMAND_UNKNOWN, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test See how it deals with an incomplete request in multiple chunks. */
int FTPParserTest07(void) {
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PO";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    uint8_t ftpbuf2[] = "RT\r\n";
    uint32_t ftplen2 = sizeof(ftpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    int r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        goto end;
    }

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_UNKNOWN) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", FTP_COMMAND_UNKNOWN, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Test case where chunks are smaller than the delim length and the
  *       last chunk is supposed to match the delim. */
int FTPParserTest10(void) {
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT 1,2,3,4,5,6\r\n";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < ftplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (ftplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        r = AppLayerParse(NULL, &f, ALPROTO_FTP, flags, &ftpbuf1[u], 1);
        if (r != 0) {
            SCLogDebug("toserver chunk %" PRIu32 " returned %" PRId32 ", expected 0: ", u, r);
            result = 0;
            goto end;
        }
    }

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_PORT) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ", FTP_COMMAND_PORT, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif /* UNITTESTS */

void FTPParserRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("FTPParserTest01", FTPParserTest01, 1);
    UtRegisterTest("FTPParserTest03", FTPParserTest03, 1);
    UtRegisterTest("FTPParserTest06", FTPParserTest06, 1);
    UtRegisterTest("FTPParserTest07", FTPParserTest07, 1);
    UtRegisterTest("FTPParserTest10", FTPParserTest10, 1);
#endif /* UNITTESTS */
}

