/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ftp.h"

#include "util-spm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-memcmp.h"

static int FTPGetLineForDirection(FtpState *state, FtpLineState *line_state)
{
    void *ptmp;
    if (line_state->current_line_lf_seen == 1) {
        /* we have seen the lf for the previous line.  Clear the parser
         * details to parse new line */
        line_state->current_line_lf_seen = 0;
        if (line_state->current_line_db == 1) {
            line_state->current_line_db = 0;
            SCFree(line_state->db);
            line_state->db = NULL;
            line_state->db_len = 0;
            state->current_line = NULL;
            state->current_line_len = 0;
        }
    }

    uint8_t *lf_idx = memchr(state->input, 0x0a, state->input_len);

    if (lf_idx == NULL) {
        /* fragmented lines.  Decoder event for special cases.  Not all
         * fragmented lines should be treated as a possible evasion
         * attempt.  With multi payload ftp chunks we can have valid
         * cases of fragmentation.  But within the same segment chunk
         * if we see fragmentation then it's definitely something you
         * should alert about */
        if (line_state->current_line_db == 0) {
            line_state->db = SCMalloc(state->input_len);
            if (line_state->db == NULL) {
                return -1;
            }
            line_state->current_line_db = 1;
            memcpy(line_state->db, state->input, state->input_len);
            line_state->db_len = state->input_len;
        } else {
            ptmp = SCRealloc(line_state->db,
                             (line_state->db_len + state->input_len));
            if (ptmp == NULL) {
                SCFree(line_state->db);
                line_state->db = NULL;
                line_state->db_len = 0;
                return -1;
            }
            line_state->db = ptmp;

            memcpy(line_state->db + line_state->db_len,
                   state->input, state->input_len);
            line_state->db_len += state->input_len;
        }
        state->input += state->input_len;
        state->input_len = 0;

        return -1;

    } else {
        line_state->current_line_lf_seen = 1;

        if (line_state->current_line_db == 1) {
            ptmp = SCRealloc(line_state->db,
                             (line_state->db_len + (lf_idx + 1 - state->input)));
            if (ptmp == NULL) {
                SCFree(line_state->db);
                line_state->db = NULL;
                line_state->db_len = 0;
                return -1;
            }
            line_state->db = ptmp;

            memcpy(line_state->db + line_state->db_len,
                   state->input, (lf_idx + 1 - state->input));
            line_state->db_len += (lf_idx + 1 - state->input);

            if (line_state->db_len > 1 &&
                line_state->db[line_state->db_len - 2] == 0x0D) {
                line_state->db_len -= 2;
                state->current_line_delimiter_len = 2;
            } else {
                line_state->db_len -= 1;
                state->current_line_delimiter_len = 1;
            }

            state->current_line = line_state->db;
            state->current_line_len = line_state->db_len;

        } else {
            state->current_line = state->input;
            state->current_line_len = lf_idx - state->input;

            if (state->input != lf_idx &&
                *(lf_idx - 1) == 0x0D) {
                state->current_line_len--;
                state->current_line_delimiter_len = 2;
            } else {
                state->current_line_delimiter_len = 1;
            }
        }

        state->input_len -= (lf_idx - state->input) + 1;
        state->input = (lf_idx + 1);

        return 0;
    }

}

static int FTPGetLine(FtpState *state)
{
    SCEnter();

    /* we have run out of input */
    if (state->input_len <= 0)
        return -1;

    /* toserver */
    if (state->direction == 0)
        return FTPGetLineForDirection(state, &state->line_state[0]);
    else
        return FTPGetLineForDirection(state, &state->line_state[1]);
}

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
                                  uint32_t input_len)
{
    SCEnter();
    FtpState *fstate = (FtpState *)ftp_state;
    fstate->command = FTP_COMMAND_UNKNOWN;

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
                           void *local_data)
{
    SCEnter();
    /* PrintRawDataFp(stdout, input,input_len); */

    FtpState *state = (FtpState *)ftp_state;
    void *ptmp;

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    state->input = input;
    state->input_len = input_len;
    /* toserver stream */
    state->direction = 0;

    while (FTPGetLine(state) >= 0) {
        FTPParseRequestCommand(state,
                               state->current_line, state->current_line_len);
        if (state->command == FTP_COMMAND_PORT) {
            if (state->current_line_len > state->port_line_size) {
                ptmp = SCRealloc(state->port_line, state->current_line_len);
                if (ptmp == NULL) {
                    SCFree(state->port_line);
                    state->port_line = NULL;
                    state->port_line_size = 0;
                    return 0;
                }
                state->port_line = ptmp;

                state->port_line_size = state->current_line_len;
            }
            memcpy(state->port_line, state->current_line,
                   state->current_line_len);
            state->port_line_len = state->current_line_len;
        }
    }

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
                            void *local_data)
{
    return 1;
}

#ifdef DEBUG
static SCMutex ftp_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftp_state_memuse = 0;
static uint64_t ftp_state_memcnt = 0;
#endif

static void *FTPStateAlloc(void)
{
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

static void FTPStateFree(void *s)
{
    FtpState *fstate = (FtpState *) s;
    if (fstate->port_line != NULL)
        SCFree(fstate->port_line);
    if (fstate->line_state[0].db)
        SCFree(fstate->line_state[0].db);
    if (fstate->line_state[1].db)
        SCFree(fstate->line_state[1].db);
    SCFree(s);
#ifdef DEBUG
    SCMutexLock(&ftp_state_mem_lock);
    ftp_state_memcnt--;
    ftp_state_memuse-=sizeof(FtpState);
    SCMutexUnlock(&ftp_state_mem_lock);
#endif
}

static int FTPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_FTP,
                                               "USER ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_FTP,
                                               "PASS ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_FTP,
                                               "PORT ", 5, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    return 0;
}

void RegisterFTPParsers(void)
{
    char *proto_name = "ftp";

    /** FTP */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_FTP, proto_name);
        if (FTPRegisterPatternsForProtocolDetection() < 0 )
            return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOSERVER,
                                     FTPParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOCLIENT,
                                     FTPParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_FTP, FTPStateAlloc, FTPStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOSERVER | STREAM_TOCLIENT);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }
#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_FTP, FTPParserRegisterTests);
#endif
}

void FTPAtExitPrintStats(void)
{
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
int FTPParserTest01(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf[] = "PORT 192,168,1,1,0,80\r\n";
    uint32_t ftplen = sizeof(ftpbuf) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf, ftplen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Send a splitted get request. */
int FTPParserTest03(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "POR";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    uint8_t ftpbuf2[] = "T 192,168,1";
    uint32_t ftplen2 = sizeof(ftpbuf2) - 1; /* minus the \0 */
    uint8_t ftpbuf3[] = "1,1,10,20\r\n";
    uint32_t ftplen3 = sizeof(ftpbuf3) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER, ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf3, ftplen3);
    if (r != 0) {
        SCLogDebug("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/** \test See how it deals with an incomplete request. */
int FTPParserTest06(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START|STREAM_EOF, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test See how it deals with an incomplete request in multiple chunks. */
int FTPParserTest07(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PO";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    uint8_t ftpbuf2[] = "RT\r\n";
    uint32_t ftplen2 = sizeof(ftpbuf2) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_START, ftpbuf1, ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER|STREAM_EOF, ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_PORT) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ",
                   FTP_COMMAND_PORT, ftp_state->command);
        result = 0;
        goto end;
    }

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/** \test Test case where chunks are smaller than the delim length and the
  *       last chunk is supposed to match the delim. */
int FTPParserTest10(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT 1,2,3,4,5,6\r\n";
    uint32_t ftplen1 = sizeof(ftpbuf1) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int r = 0;
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < ftplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (ftplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        SCMutexLock(&f.m);
        r = AppLayerParserParse(alp_tctx, &f, ALPROTO_FTP, flags, &ftpbuf1[u], 1);
        if (r != 0) {
            SCLogDebug("toserver chunk %" PRIu32 " returned %" PRId32 ", expected 0: ", u, r);
            result = 0;
            SCMutexUnlock(&f.m);
            goto end;
        }
        SCMutexUnlock(&f.m);
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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
#endif /* UNITTESTS */

void FTPParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FTPParserTest01", FTPParserTest01, 1);
    UtRegisterTest("FTPParserTest03", FTPParserTest03, 1);
    UtRegisterTest("FTPParserTest06", FTPParserTest06, 1);
    UtRegisterTest("FTPParserTest07", FTPParserTest07, 1);
    UtRegisterTest("FTPParserTest10", FTPParserTest10, 1);
#endif /* UNITTESTS */
}

