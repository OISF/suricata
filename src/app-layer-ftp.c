/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * App Layer Parser for FTP
 */

#include "suricata-common.h"
#include "app-layer-ftp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-expectation.h"
#include "app-layer-detect-proto.h"

#include "rust.h"

#include "util-misc.h"
#include "util-mpm.h"
#include "util-validate.h"

typedef struct FTPThreadCtx_ {
    MpmThreadCtx *ftp_mpm_thread_ctx;
    PrefilterRuleStore *pmq;
} FTPThreadCtx;

#define FTP_MPM mpm_default_matcher

static MpmCtx *ftp_mpm_ctx = NULL;

// clang-format off
const FtpCommand FtpCommands[FTP_COMMAND_MAX + 1] = {
    /* Parsed and handled */
    { "PORT",   FTP_COMMAND_PORT,   4 },
    { "EPRT",   FTP_COMMAND_EPRT,   4 },
    { "AUTH TLS",   FTP_COMMAND_AUTH_TLS,   8 },
    { "PASV",   FTP_COMMAND_PASV,   4 },
    { "RETR",   FTP_COMMAND_RETR,   4 },
    { "EPSV",   FTP_COMMAND_EPSV,   4 },
    { "STOR",   FTP_COMMAND_STOR,   4 },

    /* Parsed, but not handled */
    { "ABOR",   FTP_COMMAND_ABOR,   4 },
    { "ACCT",   FTP_COMMAND_ACCT,   4 },
    { "ALLO",   FTP_COMMAND_ALLO,   4 },
    { "APPE",   FTP_COMMAND_APPE,   4 },
    { "CDUP",   FTP_COMMAND_CDUP,   4 },
    { "CHMOD",  FTP_COMMAND_CHMOD,  5 },
    { "CWD",    FTP_COMMAND_CWD,    3 },
    { "DELE",   FTP_COMMAND_DELE,   4 },
    { "HELP",   FTP_COMMAND_HELP,   4 },
    { "IDLE",   FTP_COMMAND_IDLE,   4 },
    { "LIST",   FTP_COMMAND_LIST,   4 },
    { "MAIL",   FTP_COMMAND_MAIL,   4 },
    { "MDTM",   FTP_COMMAND_MDTM,   4 },
    { "MKD",    FTP_COMMAND_MKD,    3 },
    { "MLFL",   FTP_COMMAND_MLFL,   4 },
    { "MODE",   FTP_COMMAND_MODE,   4 },
    { "MRCP",   FTP_COMMAND_MRCP,   4 },
    { "MRSQ",   FTP_COMMAND_MRSQ,   4 },
    { "MSAM",   FTP_COMMAND_MSAM,   4 },
    { "MSND",   FTP_COMMAND_MSND,   4 },
    { "MSOM",   FTP_COMMAND_MSOM,   4 },
    { "NLST",   FTP_COMMAND_NLST,   4 },
    { "NOOP",   FTP_COMMAND_NOOP,   4 },
    { "PASS",   FTP_COMMAND_PASS,   4 },
    { "PWD",    FTP_COMMAND_PWD,    3 },
    { "QUIT",   FTP_COMMAND_QUIT,   4 },
    { "REIN",   FTP_COMMAND_REIN,   4 },
    { "REST",   FTP_COMMAND_REST,   4 },
    { "RMD",    FTP_COMMAND_RMD,    3 },
    { "RNFR",   FTP_COMMAND_RNFR,   4 },
    { "RNTO",   FTP_COMMAND_RNTO,   4 },
    { "SITE",   FTP_COMMAND_SITE,   4 },
    { "SIZE",   FTP_COMMAND_SIZE,   4 },
    { "SMNT",   FTP_COMMAND_SMNT,   4 },
    { "STAT",   FTP_COMMAND_STAT,   4 },
    { "STOU",   FTP_COMMAND_STOU,   4 },
    { "STRU",   FTP_COMMAND_STRU,   4 },
    { "SYST",   FTP_COMMAND_SYST,   4 },
    { "TYPE",   FTP_COMMAND_TYPE,   4 },
    { "UMASK",  FTP_COMMAND_UMASK,  5 },
    { "USER",   FTP_COMMAND_USER,   4 },
    { NULL,     FTP_COMMAND_UNKNOWN,    0 }
};
// clang-format on

uint64_t ftp_config_memcap = 0;
uint32_t ftp_config_maxtx = 1024;
uint32_t ftp_max_line_len = 4096;

SC_ATOMIC_DECLARE(uint64_t, ftp_memuse);
SC_ATOMIC_DECLARE(uint64_t, ftp_memcap);

static FTPTransaction *FTPGetOldestTx(const FtpState *, FTPTransaction *);

static void FTPParseMemcap(void)
{
    const char *conf_val;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("app-layer.protocols.ftp.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &ftp_config_memcap) < 0) {
            SCLogError("Error parsing ftp.memcap "
                       "from conf file - %s.  Killing engine",
                    conf_val);
            exit(EXIT_FAILURE);
        }
        SCLogInfo("FTP memcap: %"PRIu64, ftp_config_memcap);
    } else {
        /* default to unlimited */
        ftp_config_memcap = 0;
    }

    SC_ATOMIC_INIT(ftp_memuse);
    SC_ATOMIC_INIT(ftp_memcap);

    if ((ConfGet("app-layer.protocols.ftp.max-tx", &conf_val)) == 1) {
        if (ParseSizeStringU32(conf_val, &ftp_config_maxtx) < 0) {
            SCLogError("Error parsing ftp.max-tx "
                       "from conf file - %s.",
                    conf_val);
        }
        SCLogInfo("FTP max tx: %" PRIu32, ftp_config_maxtx);
    }

    if ((ConfGet("app-layer.protocols.ftp.max-line-length", &conf_val)) == 1) {
        if (ParseSizeStringU32(conf_val, &ftp_max_line_len) < 0) {
            SCLogError("Error parsing ftp.max-line-length from conf file - %s.", conf_val);
        }
        SCLogConfig("FTP max line length: %" PRIu32, ftp_max_line_len);
    }
}

static void FTPIncrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_ADD(ftp_memuse, size);
    return;
}

static void FTPDecrMemuse(uint64_t size)
{
    (void) SC_ATOMIC_SUB(ftp_memuse, size);
    return;
}

uint64_t FTPMemuseGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(ftp_memuse);
    return tmpval;
}

uint64_t FTPMemcapGlobalCounter(void)
{
    uint64_t tmpval = SC_ATOMIC_GET(ftp_memcap);
    return tmpval;
}

/**
 *  \brief Check if alloc'ing "size" would mean we're over memcap
 *
 *  \retval 1 if in bounds
 *  \retval 0 if not in bounds
 */
static int FTPCheckMemcap(uint64_t size)
{
    if (ftp_config_memcap == 0 || size + SC_ATOMIC_GET(ftp_memuse) <= ftp_config_memcap)
        return 1;
    (void) SC_ATOMIC_ADD(ftp_memcap, 1);
    return 0;
}

static void *FTPCalloc(size_t n, size_t size)
{
    if (FTPCheckMemcap((uint32_t)(n * size)) == 0) {
        sc_errno = SC_ELIMIT;
        return NULL;
    }

    void *ptr = SCCalloc(n, size);

    if (unlikely(ptr == NULL)) {
        sc_errno = SC_ENOMEM;
        return NULL;
    }

    FTPIncrMemuse((uint64_t)(n * size));
    return ptr;
}

static void *FTPRealloc(void *ptr, size_t orig_size, size_t size)
{
    void *rptr = NULL;

    if (FTPCheckMemcap((uint32_t)(size - orig_size)) == 0) {
        sc_errno = SC_ELIMIT;
        return NULL;
    }

    rptr = SCRealloc(ptr, size);
    if (rptr == NULL) {
        sc_errno = SC_ENOMEM;
        return NULL;
    }

    if (size > orig_size) {
        FTPIncrMemuse(size - orig_size);
    } else {
        FTPDecrMemuse(orig_size - size);
    }

    return rptr;
}

static void FTPFree(void *ptr, size_t size)
{
    SCFree(ptr);

    FTPDecrMemuse((uint64_t)size);
}

static FTPString *FTPStringAlloc(void)
{
    return FTPCalloc(1, sizeof(FTPString));
}

static void FTPStringFree(FTPString *str)
{
    if (str->str) {
        FTPFree(str->str, str->len);
    }

    FTPFree(str, sizeof(FTPString));
}

static void *FTPLocalStorageAlloc(void)
{
    /* needed by the mpm */
    FTPThreadCtx *td = SCCalloc(1, sizeof(*td));
    if (td == NULL) {
        exit(EXIT_FAILURE);
    }

    td->pmq = SCCalloc(1, sizeof(*td->pmq));
    if (td->pmq == NULL) {
        exit(EXIT_FAILURE);
    }
    PmqSetup(td->pmq);

    td->ftp_mpm_thread_ctx = SCCalloc(1, sizeof(MpmThreadCtx));
    if (unlikely(td->ftp_mpm_thread_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    MpmInitThreadCtx(td->ftp_mpm_thread_ctx, FTP_MPM);
    return td;
}

static void FTPLocalStorageFree(void *ptr)
{
    FTPThreadCtx *td = ptr;
    if (td != NULL) {
        if (td->pmq != NULL) {
            PmqFree(td->pmq);
            SCFree(td->pmq);
        }

        if (td->ftp_mpm_thread_ctx != NULL) {
            mpm_table[FTP_MPM].DestroyThreadCtx(ftp_mpm_ctx, td->ftp_mpm_thread_ctx);
            SCFree(td->ftp_mpm_thread_ctx);
        }

        SCFree(td);
    }

    return;
}
static FTPTransaction *FTPTransactionCreate(FtpState *state)
{
    SCEnter();
    FTPTransaction *firsttx = TAILQ_FIRST(&state->tx_list);
    if (firsttx && state->tx_cnt - firsttx->tx_id > ftp_config_maxtx) {
        // FTP does not set events yet...
        return NULL;
    }
    FTPTransaction *tx = FTPCalloc(1, sizeof(*tx));
    if (tx == NULL) {
        return NULL;
    }

    TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
    tx->tx_id = state->tx_cnt++;

    TAILQ_INIT(&tx->response_list);

    SCLogDebug("new transaction %p (state tx cnt %"PRIu64")", tx, state->tx_cnt);
    return tx;
}

static void FTPTransactionFree(FTPTransaction *tx)
{
    SCEnter();

    if (tx->tx_data.de_state != NULL) {
        DetectEngineStateFree(tx->tx_data.de_state);
    }

    if (tx->request) {
        FTPFree(tx->request, tx->request_length);
    }

    FTPString *str = NULL;
    while ((str = TAILQ_FIRST(&tx->response_list))) {
        TAILQ_REMOVE(&tx->response_list, str, next);
        FTPStringFree(str);
    }

    if (tx->tx_data.events) {
        AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);
    }

    FTPFree(tx, sizeof(*tx));
}

typedef struct FtpInput_ {
    const uint8_t *buf;
    int32_t consumed;
    int32_t len;
    int32_t orig_len;
} FtpInput;

static AppLayerResult FTPGetLineForDirection(
        FtpState *state, FtpLineState *line, FtpInput *input, bool *current_line_truncated)
{
    SCEnter();

    /* we have run out of input */
    if (input->len <= 0)
        return APP_LAYER_ERROR;

    uint8_t *lf_idx = memchr(input->buf + input->consumed, 0x0a, input->len);

    if (lf_idx == NULL) {
        if (!(*current_line_truncated) && (uint32_t)input->len >= ftp_max_line_len) {
            *current_line_truncated = true;
            line->buf = input->buf;
            line->len = ftp_max_line_len;
            line->delim_len = 0;
            input->len = 0;
            SCReturnStruct(APP_LAYER_OK);
        }
        SCReturnStruct(APP_LAYER_INCOMPLETE(input->consumed, input->len + 1));
    } else if (*current_line_truncated) {
        // Whatever came in with first LF should also get discarded
        *current_line_truncated = false;
        line->len = 0;
        line->delim_len = 0;
        input->len = 0;
        SCReturnStruct(APP_LAYER_ERROR);
    } else {
        // There could be one chunk of command data that has LF but post the line limit
        // e.g. input_len = 5077
        //      lf_idx = 5010
        //      max_line_len = 4096
        uint32_t o_consumed = input->consumed;
        input->consumed = lf_idx - input->buf + 1;
        line->len = input->consumed - o_consumed;
        input->len -= line->len;
        line->lf_found = true;
        DEBUG_VALIDATE_BUG_ON((input->consumed + input->len) != input->orig_len);
        line->buf = input->buf + o_consumed;
        if (line->len >= ftp_max_line_len) {
            *current_line_truncated = true;
            line->len = ftp_max_line_len;
            SCReturnStruct(APP_LAYER_OK);
        }
        if (input->consumed >= 2 && input->buf[input->consumed - 2] == 0x0D) {
            line->delim_len = 2;
            line->len -= 2;
        } else {
            line->delim_len = 1;
            line->len -= 1;
        }
        SCReturnStruct(APP_LAYER_OK);
    }
}

/**
 * \brief This function is called to determine and set which command is being
 * transferred to the ftp server
 * \param thread context
 * \param input input line of the command
 * \param len of the command
 * \param cmd_descriptor when the command has been parsed
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseRequestCommand(
        FTPThreadCtx *td, FtpLineState *line, const FtpCommand **cmd_descriptor)
{
    SCEnter();

    /* I don't like this pmq reset here.  We'll devise a method later, that
     * should make the use of the mpm very efficient */
    PmqReset(td->pmq);
    int mpm_cnt = mpm_table[FTP_MPM].Search(
            ftp_mpm_ctx, td->ftp_mpm_thread_ctx, td->pmq, line->buf, line->len);
    if (mpm_cnt) {
        *cmd_descriptor = &FtpCommands[td->pmq->rule_id_array[0]];
        SCReturnInt(1);
    }

    *cmd_descriptor = NULL;
    SCReturnInt(0);
}

struct FtpTransferCmd {
    /** Need to look like a ExpectationData so DFree must
     *  be first field . */
    void (*DFree)(void *);
    uint64_t flow_id;
    uint8_t *file_name;
    uint16_t file_len;
    uint8_t direction; /**< direction in which the data will flow */
    FtpRequestCommand cmd;
};

static void FtpTransferCmdFree(void *data)
{
    struct FtpTransferCmd *cmd = (struct FtpTransferCmd *) data;
    if (cmd == NULL)
        return;
    if (cmd->file_name) {
        FTPFree(cmd->file_name, cmd->file_len + 1);
    }
    FTPFree(cmd, sizeof(struct FtpTransferCmd));
}

static uint32_t CopyCommandLine(uint8_t **dest, FtpLineState *line)
{
    if (likely(line->len)) {
        uint8_t *where = FTPCalloc(line->len + 1, sizeof(char));
        if (unlikely(where == NULL)) {
            return 0;
        }
        memcpy(where, line->buf, line->len);

        /* Remove trailing newlines/carriage returns */
        while (line->len && isspace((unsigned char)where[line->len - 1])) {
            line->len--;
        }

        where[line->len] = '\0';
        *dest = where;
    }
    /* either 0 or actual */
    return line->len ? line->len + 1 : 0;
}

#include "util-print.h"

/**
 * \brief This function is called to retrieve a ftp request
 * \param ftp_state the ftp state structure for the parser
 *
 * \retval APP_LAYER_OK when input was process successfully
 * \retval APP_LAYER_ERROR when a unrecoverable error was encountered
 */
static AppLayerResult FTPParseRequest(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    FTPThreadCtx *thread_data = local_data;

    SCEnter();
    /* PrintRawDataFp(stdout, input,input_len); */

    FtpState *state = (FtpState *)ftp_state;
    void *ptmp;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }

    FtpInput ftpi = { .buf = input, .len = input_len, .orig_len = input_len, .consumed = 0 };
    FtpLineState line = { .buf = NULL, .len = 0, .delim_len = 0, .lf_found = false };

    uint8_t direction = STREAM_TOSERVER;
    AppLayerResult res;
    while (1) {
        res = FTPGetLineForDirection(state, &line, &ftpi, &state->current_line_truncated_ts);
        if (res.status == 1) {
            return res;
        } else if (res.status == -1) {
            break;
        }
        const FtpCommand *cmd_descriptor;

        if (!FTPParseRequestCommand(thread_data, &line, &cmd_descriptor)) {
            state->command = FTP_COMMAND_UNKNOWN;
            continue;
        }

        state->command = cmd_descriptor->command;
        FTPTransaction *tx = FTPTransactionCreate(state);
        if (unlikely(tx == NULL))
            SCReturnStruct(APP_LAYER_ERROR);
        tx->tx_data.updated_ts = true;
        state->curr_tx = tx;

        tx->command_descriptor = cmd_descriptor;
        tx->request_length = CopyCommandLine(&tx->request, &line);
        tx->request_truncated = state->current_line_truncated_ts;

        if (line.lf_found) {
            state->current_line_truncated_ts = false;
        }
        if (tx->request_truncated) {
            AppLayerDecoderEventsSetEventRaw(&tx->tx_data.events, FtpEventRequestCommandTooLong);
        }

        /* change direction (default to server) so expectation will handle
         * the correct message when expectation will match.
         * For ftp active mode, data connection direction is opposite to
         * control direction.
         */
        if ((state->active && state->command == FTP_COMMAND_STOR) ||
                (!state->active && state->command == FTP_COMMAND_RETR)) {
            direction = STREAM_TOCLIENT;
        }

        switch (state->command) {
            case FTP_COMMAND_EPRT:
                // fallthrough
            case FTP_COMMAND_PORT:
                if (line.len + 1 > state->port_line_size) {
                    /* Allocate an extra byte for a NULL terminator */
                    ptmp = FTPRealloc(state->port_line, state->port_line_size, line.len);
                    if (ptmp == NULL) {
                        if (state->port_line) {
                            FTPFree(state->port_line, state->port_line_size);
                            state->port_line = NULL;
                            state->port_line_size = 0;
                            state->port_line_len = 0;
                        }
                        SCReturnStruct(APP_LAYER_OK);
                    }
                    state->port_line = ptmp;
                    state->port_line_size = line.len;
                }
                memcpy(state->port_line, line.buf, line.len);
                state->port_line_len = line.len;
                break;
            case FTP_COMMAND_RETR:
                // fallthrough
            case FTP_COMMAND_STOR: {
                /* Ensure that there is a negotiated dyn port and a file
                 * name -- need more than 5 chars: cmd [4], space, <filename>
                 */
                if (state->dyn_port == 0 || line.len < 6) {
                    SCReturnStruct(APP_LAYER_ERROR);
                }
                struct FtpTransferCmd *data = FTPCalloc(1, sizeof(struct FtpTransferCmd));
                if (data == NULL)
                    SCReturnStruct(APP_LAYER_ERROR);
                data->DFree = FtpTransferCmdFree;
                /*
                 * Min size has been checked in FTPParseRequestCommand
                 * SC_FILENAME_MAX includes the null
                 */
                uint32_t file_name_len = MIN(SC_FILENAME_MAX - 1, line.len - 5);
#if SC_FILENAME_MAX > UINT16_MAX
#error SC_FILENAME_MAX is greater than UINT16_MAX
#endif
                    data->file_name = FTPCalloc(file_name_len + 1, sizeof(char));
                    if (data->file_name == NULL) {
                        FtpTransferCmdFree(data);
                        SCReturnStruct(APP_LAYER_ERROR);
                    }
                    data->file_name[file_name_len] = 0;
                    data->file_len = (uint16_t)file_name_len;
                    memcpy(data->file_name, line.buf + 5, file_name_len);
                    data->cmd = state->command;
                    data->flow_id = FlowGetId(f);
                    data->direction = direction;
                    int ret = AppLayerExpectationCreate(f, direction,
                                            0, state->dyn_port, ALPROTO_FTPDATA, data);
                    if (ret == -1) {
                        FtpTransferCmdFree(data);
                        SCLogDebug("No expectation created.");
                        SCReturnStruct(APP_LAYER_ERROR);
                    } else {
                        SCLogDebug("Expectation created [direction: %s, dynamic port %"PRIu16"].",
                            state->active ? "to server" : "to client",
                            state->dyn_port);
                    }

                    /* reset the dyn port to avoid duplicate */
                    state->dyn_port = 0;
                    /* reset active/passive indicator */
                    state->active = false;
            } break;
            default:
                break;
        }
        if (line.len >= ftp_max_line_len) {
            ftpi.consumed = ftpi.len + 1;
            break;
        }
    }

    SCReturnStruct(APP_LAYER_OK);
}

static int FTPParsePassiveResponse(Flow *f, FtpState *state, const uint8_t *input, uint32_t input_len)
{
    uint16_t dyn_port = rs_ftp_pasv_response(input, input_len);
    if (dyn_port == 0) {
        return -1;
    }
    SCLogDebug("FTP passive mode (v4): dynamic port %"PRIu16"", dyn_port);
    state->active = false;
    state->dyn_port = dyn_port;
    state->curr_tx->dyn_port = dyn_port;
    state->curr_tx->active = false;

    return 0;
}

static int FTPParsePassiveResponseV6(Flow *f, FtpState *state, const uint8_t *input, uint32_t input_len)
{
    uint16_t dyn_port = rs_ftp_epsv_response(input, input_len);
    if (dyn_port == 0) {
        return -1;
    }
    SCLogDebug("FTP passive mode (v6): dynamic port %"PRIu16"", dyn_port);
    state->active = false;
    state->dyn_port = dyn_port;
    state->curr_tx->dyn_port = dyn_port;
    state->curr_tx->active = false;
    return 0;
}

/**
 * \brief  Handle preliminary replies -- keep tx open
 * \retval bool True for a positive preliminary reply; false otherwise
 *
 * 1yz   Positive Preliminary reply
 *
 *                The requested action is being initiated; expect another
 *                               reply before proceeding with a new command
 */
static inline bool FTPIsPPR(const uint8_t *input, uint32_t input_len)
{
    return input_len >= 4 && isdigit(input[0]) && input[0] == '1' &&
           isdigit(input[1]) && isdigit(input[2]) && isspace(input[3]);
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
static AppLayerResult FTPParseResponse(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    FtpState *state = (FtpState *)ftp_state;

    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (unlikely(input_len == 0)) {
        SCReturnStruct(APP_LAYER_OK);
    }
    FtpInput ftpi = { .buf = input, .len = input_len, .orig_len = input_len, .consumed = 0 };
    FtpLineState line = { .buf = NULL, .len = 0, .delim_len = 0, .lf_found = false };

    FTPTransaction *lasttx = TAILQ_FIRST(&state->tx_list);
    AppLayerResult res;
    while (1) {
        res = FTPGetLineForDirection(state, &line, &ftpi, &state->current_line_truncated_tc);
        if (res.status == 1) {
            return res;
        } else if (res.status == -1) {
            break;
        }
        FTPTransaction *tx = FTPGetOldestTx(state, lasttx);
        if (tx == NULL) {
            tx = FTPTransactionCreate(state);
        }
        if (unlikely(tx == NULL)) {
            SCReturnStruct(APP_LAYER_ERROR);
        }
        lasttx = tx;
        tx->tx_data.updated_tc = true;
        if (state->command == FTP_COMMAND_UNKNOWN || tx->command_descriptor == NULL) {
            /* unknown */
            tx->command_descriptor = &FtpCommands[FTP_COMMAND_MAX - 1];
        }

        state->curr_tx = tx;
        uint16_t dyn_port;
        switch (state->command) {
            case FTP_COMMAND_AUTH_TLS:
                if (line.len >= 4 && SCMemcmp("234 ", line.buf, 4) == 0) {
                    AppLayerRequestProtocolTLSUpgrade(f);
                }
                break;

            case FTP_COMMAND_EPRT:
                dyn_port = rs_ftp_active_eprt(state->port_line, state->port_line_len);
                if (dyn_port == 0) {
                    goto tx_complete;
                }
                state->dyn_port = dyn_port;
                state->active = true;
                tx->dyn_port = dyn_port;
                tx->active = true;
                SCLogDebug("FTP active mode (v6): dynamic port %" PRIu16 "", dyn_port);
                break;

            case FTP_COMMAND_PORT:
                dyn_port = rs_ftp_active_port(state->port_line, state->port_line_len);
                if (dyn_port == 0) {
                    goto tx_complete;
                }
                state->dyn_port = dyn_port;
                state->active = true;
                tx->dyn_port = state->dyn_port;
                tx->active = true;
                SCLogDebug("FTP active mode (v4): dynamic port %" PRIu16 "", dyn_port);
                break;

            case FTP_COMMAND_PASV:
                if (line.len >= 4 && SCMemcmp("227 ", line.buf, 4) == 0) {
                    FTPParsePassiveResponse(f, ftp_state, line.buf, line.len);
                }
                break;

            case FTP_COMMAND_EPSV:
                if (line.len >= 4 && SCMemcmp("229 ", line.buf, 4) == 0) {
                    FTPParsePassiveResponseV6(f, ftp_state, line.buf, line.len);
                }
                break;
            default:
                break;
        }

        if (likely(line.len)) {
            FTPString *response = FTPStringAlloc();
            if (likely(response)) {
                response->len = CopyCommandLine(&response->str, &line);
                response->truncated = state->current_line_truncated_tc;
                if (response->truncated) {
                    AppLayerDecoderEventsSetEventRaw(
                            &tx->tx_data.events, FtpEventResponseCommandTooLong);
                }
                if (line.lf_found) {
                    state->current_line_truncated_tc = false;
                }
                TAILQ_INSERT_TAIL(&tx->response_list, response, next);
            }
        }

        /* Handle preliminary replies -- keep tx open */
        if (FTPIsPPR(line.buf, line.len)) {
            continue;
        }
    tx_complete:
        tx->done = true;

        if (line.len >= ftp_max_line_len) {
            ftpi.consumed = ftpi.len + 1;
            break;
        }
    }

    SCReturnStruct(APP_LAYER_OK);
}


#ifdef DEBUG
static SCMutex ftp_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftp_state_memuse = 0;
static uint64_t ftp_state_memcnt = 0;
#endif

static void *FTPStateAlloc(void *orig_state, AppProto proto_orig)
{
    void *s = FTPCalloc(1, sizeof(FtpState));
    if (unlikely(s == NULL))
        return NULL;

    FtpState *ftp_state = (FtpState *) s;
    TAILQ_INIT(&ftp_state->tx_list);

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
        FTPFree(fstate->port_line, fstate->port_line_size);

    FTPTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&fstate->tx_list))) {
        TAILQ_REMOVE(&fstate->tx_list, tx, next);
        SCLogDebug("[%s] state %p id %" PRIu64 ", Freeing %d bytes at %p",
                tx->command_descriptor->command_name, s, tx->tx_id, tx->request_length,
                tx->request);
        FTPTransactionFree(tx);
    }

    FTPFree(s, sizeof(FtpState));
#ifdef DEBUG
    SCMutexLock(&ftp_state_mem_lock);
    ftp_state_memcnt--;
    ftp_state_memuse-=sizeof(FtpState);
    SCMutexUnlock(&ftp_state_mem_lock);
#endif
}

/**
 * \brief This function returns the oldest open transaction; if none
 * are open, then the oldest transaction is returned
 * \param ftp_state the ftp state structure for the parser
 * \param starttx the ftp transaction where to start looking
 *
 * \retval transaction pointer when a transaction was found; NULL otherwise.
 */
static FTPTransaction *FTPGetOldestTx(const FtpState *ftp_state, FTPTransaction *starttx)
{
    if (unlikely(!ftp_state)) {
        SCLogDebug("NULL state object; no transactions available");
        return NULL;
    }
    FTPTransaction *tx = starttx;
    FTPTransaction *lasttx = NULL;
    while(tx != NULL) {
        /* Return oldest open tx */
        if (!tx->done) {
            SCLogDebug("Returning tx %p id %"PRIu64, tx, tx->tx_id);
            return tx;
        }
        /* save for the end */
        lasttx = tx;
        tx = TAILQ_NEXT(tx, next);
    }
    /* All tx are closed; return last element */
    if (lasttx)
        SCLogDebug("Returning OLDEST tx %p id %"PRIu64, lasttx, lasttx->tx_id);
    return lasttx;
}

static void *FTPGetTx(void *state, uint64_t tx_id)
{
    FtpState *ftp_state = (FtpState *)state;
    if (ftp_state) {
        FTPTransaction *tx = NULL;

        if (ftp_state->curr_tx == NULL)
            return NULL;
        if (ftp_state->curr_tx->tx_id == tx_id)
            return ftp_state->curr_tx;

        TAILQ_FOREACH(tx, &ftp_state->tx_list, next) {
            if (tx->tx_id == tx_id)
                return tx;
        }
    }
    return NULL;
}

static AppLayerTxData *FTPGetTxData(void *vtx)
{
    FTPTransaction *tx = (FTPTransaction *)vtx;
    return &tx->tx_data;
}

static AppLayerStateData *FTPGetStateData(void *vstate)
{
    FtpState *s = (FtpState *)vstate;
    return &s->state_data;
}

static void FTPStateTransactionFree(void *state, uint64_t tx_id)
{
    FtpState *ftp_state = state;
    FTPTransaction *tx = NULL;
    TAILQ_FOREACH(tx, &ftp_state->tx_list, next) {
        if (tx_id < tx->tx_id)
            break;
        else if (tx_id > tx->tx_id)
            continue;

        if (tx == ftp_state->curr_tx)
            ftp_state->curr_tx = NULL;
        TAILQ_REMOVE(&ftp_state->tx_list, tx, next);
        FTPTransactionFree(tx);
        break;
    }
}

static uint64_t FTPGetTxCnt(void *state)
{
    uint64_t cnt = 0;
    FtpState *ftp_state = state;
    if (ftp_state) {
        cnt = ftp_state->tx_cnt;
    }
    SCLogDebug("returning state %p %"PRIu64, state, cnt);
    return cnt;
}

static int FTPGetAlstateProgress(void *vtx, uint8_t direction)
{
    SCLogDebug("tx %p", vtx);
    FTPTransaction *tx = vtx;

    if (!tx->done) {
        if (direction == STREAM_TOSERVER && tx->command_descriptor->command == FTP_COMMAND_PORT) {
            return FTP_STATE_PORT_DONE;
        }
        return FTP_STATE_IN_PROGRESS;
    }

    return FTP_STATE_FINISHED;
}


static int FTPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_FTP, "220 (", 5, 0, STREAM_TOCLIENT) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_FTP, "FEAT", 4, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_FTP, "USER ", 5, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_FTP, "PASS ", 5, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(
                IPPROTO_TCP, ALPROTO_FTP, "PORT ", 5, 0, STREAM_TOSERVER) < 0) {
        return -1;
    }

    return 0;
}


static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

/**
 * \brief This function is called to retrieve a ftp request
 * \param ftp_state the ftp state structure for the parser
 * \param output the resulting output
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static AppLayerResult FTPDataParse(Flow *f, FtpDataState *ftpdata_state,
        AppLayerParserState *pstate, StreamSlice stream_slice, void *local_data, uint8_t direction)
{
    const uint8_t *input = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);
    const bool eof = (direction & STREAM_TOSERVER)
                             ? AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) != 0
                             : AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) != 0;

    SCTxDataUpdateFileFlags(&ftpdata_state->tx_data, ftpdata_state->state_data.file_flags);
    if (ftpdata_state->tx_data.file_tx == 0)
        ftpdata_state->tx_data.file_tx = direction & (STREAM_TOSERVER | STREAM_TOCLIENT);
    if (direction & STREAM_TOSERVER) {
        ftpdata_state->tx_data.updated_ts = true;
    } else {
        ftpdata_state->tx_data.updated_tc = true;
    }
    /* we depend on detection engine for file pruning */
    const uint16_t flags = FileFlowFlagsToFlags(ftpdata_state->tx_data.file_flags, direction);
    int ret = 0;

    SCLogDebug("FTP-DATA input_len %u flags %04x dir %d/%s EOF %s", input_len, flags, direction,
            (direction & STREAM_TOSERVER) ? "toserver" : "toclient", eof ? "true" : "false");

    SCLogDebug("FTP-DATA flags %04x dir %d", flags, direction);
    if (input_len && ftpdata_state->files == NULL) {
        struct FtpTransferCmd *data =
                (struct FtpTransferCmd *)FlowGetStorageById(f, AppLayerExpectationGetFlowId());
        if (data == NULL) {
            SCReturnStruct(APP_LAYER_ERROR);
        }

        /* we shouldn't get data in the wrong dir. Don't set things up for this dir */
        if ((direction & data->direction) == 0) {
            // TODO set event for data in wrong direction
            SCLogDebug("input %u not for our direction (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    data->cmd == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (data->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnStruct(APP_LAYER_OK);
        }

        ftpdata_state->files = FileContainerAlloc();
        if (ftpdata_state->files == NULL) {
            FlowFreeStorageById(f, AppLayerExpectationGetFlowId());
            SCReturnStruct(APP_LAYER_ERROR);
        }

        ftpdata_state->file_name = data->file_name;
        ftpdata_state->file_len = data->file_len;
        data->file_name = NULL;
        data->file_len = 0;
        f->parent_id = data->flow_id;
        ftpdata_state->command = data->cmd;
        switch (data->cmd) {
            case FTP_COMMAND_STOR:
                ftpdata_state->direction = data->direction;
                SCLogDebug("STOR data to %s",
                        (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
                break;
            case FTP_COMMAND_RETR:
                ftpdata_state->direction = data->direction;
                SCLogDebug("RETR data to %s",
                        (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
                break;
            default:
                break;
        }

        /* open with fixed track_id 0 as we can have just one
         * file per ftp-data flow. */
        if (FileOpenFileWithId(ftpdata_state->files, &sbcfg,
                         0ULL, (uint8_t *) ftpdata_state->file_name,
                         ftpdata_state->file_len,
                         input, input_len, flags) != 0) {
            SCLogDebug("Can't open file");
            ret = -1;
        }
        FlowFreeStorageById(f, AppLayerExpectationGetFlowId());
        ftpdata_state->tx_data.files_opened = 1;
    } else {
        if (ftpdata_state->state == FTPDATA_STATE_FINISHED) {
            SCLogDebug("state is already finished");
            DEBUG_VALIDATE_BUG_ON(input_len); // data after state finished is a bug.
            SCReturnStruct(APP_LAYER_OK);
        }
        if ((direction & ftpdata_state->direction) == 0) {
            if (input_len) {
                // TODO set event for data in wrong direction
            }
            SCLogDebug("input %u not for us (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    ftpdata_state->command == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnStruct(APP_LAYER_OK);
        }
        if (input_len != 0) {
            ret = FileAppendData(ftpdata_state->files, &sbcfg, input, input_len);
            if (ret == -2) {
                ret = 0;
                SCLogDebug("FileAppendData() - file no longer being extracted");
                goto out;
            } else if (ret < 0) {
                SCLogDebug("FileAppendData() failed: %d", ret);
                ret = -2;
                goto out;
            }
        }
    }

    BUG_ON((direction & ftpdata_state->direction) == 0); // should be unreachable
    if (eof) {
        ret = FileCloseFile(ftpdata_state->files, &sbcfg, NULL, 0, flags);
        ftpdata_state->state = FTPDATA_STATE_FINISHED;
        SCLogDebug("closed because of eof: state now FTPDATA_STATE_FINISHED");
    }
out:
    if (ret < 0) {
        SCReturnStruct(APP_LAYER_ERROR);
    }
    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult FTPDataParseRequest(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return FTPDataParse(f, ftp_state, pstate, stream_slice, local_data, STREAM_TOSERVER);
}

static AppLayerResult FTPDataParseResponse(Flow *f, void *ftp_state, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    return FTPDataParse(f, ftp_state, pstate, stream_slice, local_data, STREAM_TOCLIENT);
}

#ifdef DEBUG
static SCMutex ftpdata_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftpdata_state_memuse = 0;
static uint64_t ftpdata_state_memcnt = 0;
#endif

static void *FTPDataStateAlloc(void *orig_state, AppProto proto_orig)
{
    void *s = FTPCalloc(1, sizeof(FtpDataState));
    if (unlikely(s == NULL))
        return NULL;

    FtpDataState *state = (FtpDataState *) s;
    state->state = FTPDATA_STATE_IN_PROGRESS;

#ifdef DEBUG
    SCMutexLock(&ftpdata_state_mem_lock);
    ftpdata_state_memcnt++;
    ftpdata_state_memuse+=sizeof(FtpDataState);
    SCMutexUnlock(&ftpdata_state_mem_lock);
#endif
    return s;
}

static void FTPDataStateFree(void *s)
{
    FtpDataState *fstate = (FtpDataState *) s;

    if (fstate->tx_data.de_state != NULL) {
        DetectEngineStateFree(fstate->tx_data.de_state);
    }
    if (fstate->file_name != NULL) {
        FTPFree(fstate->file_name, fstate->file_len + 1);
    }

    FileContainerFree(fstate->files, &sbcfg);

    FTPFree(s, sizeof(FtpDataState));
#ifdef DEBUG
    SCMutexLock(&ftpdata_state_mem_lock);
    ftpdata_state_memcnt--;
    ftpdata_state_memuse-=sizeof(FtpDataState);
    SCMutexUnlock(&ftpdata_state_mem_lock);
#endif
}

static AppLayerTxData *FTPDataGetTxData(void *vtx)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    return &ftp_state->tx_data;
}

static AppLayerStateData *FTPDataGetStateData(void *vstate)
{
    FtpDataState *ftp_state = (FtpDataState *)vstate;
    return &ftp_state->state_data;
}

static void FTPDataStateTransactionFree(void *state, uint64_t tx_id)
{
    /* do nothing */
}

static void *FTPDataGetTx(void *state, uint64_t tx_id)
{
    FtpDataState *ftp_state = (FtpDataState *)state;
    return ftp_state;
}

static uint64_t FTPDataGetTxCnt(void *state)
{
    /* ftp-data is single tx */
    return 1;
}

static int FTPDataGetAlstateProgress(void *tx, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)tx;
    if (direction == ftpdata_state->direction)
        return ftpdata_state->state;
    else
        return FTPDATA_STATE_FINISHED;
}

static AppLayerGetFileState FTPDataStateGetTxFiles(void *_state, void *tx, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)tx;
    AppLayerGetFileState files = { .fc = NULL, .cfg = &sbcfg };

    if (direction == ftpdata_state->direction)
        files.fc = ftpdata_state->files;

    return files;
}

static void FTPSetMpmState(void)
{
    ftp_mpm_ctx = SCMalloc(sizeof(MpmCtx));
    if (unlikely(ftp_mpm_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(ftp_mpm_ctx, 0, sizeof(MpmCtx));
    MpmInitCtx(ftp_mpm_ctx, FTP_MPM);

    uint32_t i = 0;
    for (i = 0; i < sizeof(FtpCommands)/sizeof(FtpCommand) - 1; i++) {
        const FtpCommand *cmd = &FtpCommands[i];
        if (cmd->command_length == 0)
            continue;

        MpmAddPatternCI(ftp_mpm_ctx,
                       (uint8_t *)cmd->command_name,
                       cmd->command_length,
                       0 /* defunct */, 0 /* defunct */,
                       i /*  id */, i /* rule id */ , 0 /* no flags */);
    }

    mpm_table[FTP_MPM].Prepare(ftp_mpm_ctx);

}

static void FTPFreeMpmState(void)
{
    if (ftp_mpm_ctx != NULL) {
        mpm_table[FTP_MPM].DestroyCtx(ftp_mpm_ctx);
        SCFree(ftp_mpm_ctx);
        ftp_mpm_ctx = NULL;
    }
}

/** \brief FTP tx iterator, specialized for its linked list
 *
 *  \retval txptr or NULL if no more txs in list
 */
static AppLayerGetTxIterTuple FTPGetTxIterator(const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
    FtpState *ftp_state = (FtpState *)alstate;
    AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
    if (ftp_state) {
        FTPTransaction *tx_ptr;
        if (state->un.ptr == NULL) {
            tx_ptr = TAILQ_FIRST(&ftp_state->tx_list);
        } else {
            tx_ptr = (FTPTransaction *)state->un.ptr;
        }
        if (tx_ptr) {
            while (tx_ptr->tx_id < min_tx_id) {
                tx_ptr = TAILQ_NEXT(tx_ptr, next);
                if (!tx_ptr) {
                    return no_tuple;
                }
            }
            if (tx_ptr->tx_id >= max_tx_id) {
                return no_tuple;
            }
            state->un.ptr = TAILQ_NEXT(tx_ptr, next);
            AppLayerGetTxIterTuple tuple = {
                .tx_ptr = tx_ptr,
                .tx_id = tx_ptr->tx_id,
                .has_next = (state->un.ptr != NULL),
            };
            return tuple;
        }
    }
    return no_tuple;
}

void RegisterFTPParsers(void)
{
    const char *proto_name = "ftp";
    const char *proto_data_name = "ftp-data";

    /** FTP */
    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_FTP, proto_name);
        if (FTPRegisterPatternsForProtocolDetection() < 0 )
            return;
        AppLayerProtoDetectRegisterProtocol(ALPROTO_FTPDATA, proto_data_name);
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOSERVER,
                                     FTPParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOCLIENT,
                                     FTPParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_FTP, FTPStateAlloc, FTPStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_FTP, STREAM_TOSERVER | STREAM_TOCLIENT);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_FTP, FTPStateTransactionFree);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_FTP, FTPGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_FTP, FTPGetTxData);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_FTP, FTPGetTxIterator);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_FTP, FTPGetStateData);

        AppLayerParserRegisterLocalStorageFunc(IPPROTO_TCP, ALPROTO_FTP, FTPLocalStorageAlloc,
                                               FTPLocalStorageFree);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_FTP, FTPGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_FTP, FTPGetAlstateProgress);

        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_FTP, FTP_STATE_FINISHED, FTP_STATE_FINISHED);

        AppLayerRegisterExpectationProto(IPPROTO_TCP, ALPROTO_FTPDATA);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER,
                                     FTPDataParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOCLIENT,
                                     FTPDataParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateAlloc, FTPDataStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER | STREAM_TOCLIENT);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateTransactionFree);

        AppLayerParserRegisterGetTxFilesFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateGetTxFiles);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTx);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetStateData);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetAlstateProgress);

        AppLayerParserRegisterStateProgressCompletionStatus(
                ALPROTO_FTPDATA, FTPDATA_STATE_FINISHED, FTPDATA_STATE_FINISHED);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_FTP, ftp_get_event_info);
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_FTP, ftp_get_event_info_by_id);

        sbcfg.buf_size = 4096;
        sbcfg.Calloc = FTPCalloc;
        sbcfg.Realloc = FTPRealloc;
        sbcfg.Free = FTPFree;

        FTPParseMemcap();
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    FTPSetMpmState();

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


/*
 * \brief Returns the ending offset of the next line from a multi-line buffer.
 *
 * "Buffer" refers to a FTP response in a single buffer containing multiple lines.
 * Here, "next line" is defined as terminating on
 * - Newline character
 * - Null character
 *
 * \param buffer Contains zero or more characters.
 * \param len Size, in bytes, of buffer.
 *
 * \retval Offset from the start of buffer indicating the where the
 * next "line ends". The characters between the input buffer and this
 * value comprise the line.
 *
 * NULL is found first or a newline isn't found, then UINT16_MAX is returned.
 */
uint16_t JsonGetNextLineFromBuffer(const char *buffer, const uint16_t len)
{
    if (!buffer || *buffer == '\0') {
        return UINT16_MAX;
    }

    char *c = strchr(buffer, '\n');
    return c == NULL ? len : (uint16_t)(c - buffer + 1);
}

void EveFTPDataAddMetadata(const Flow *f, JsonBuilder *jb)
{
    const FtpDataState *ftp_state = NULL;
    if (f->alstate == NULL)
        return;

    ftp_state = (FtpDataState *)f->alstate;

    if (ftp_state->file_name) {
        jb_set_string_from_bytes(jb, "filename", ftp_state->file_name, ftp_state->file_len);
    }
    switch (ftp_state->command) {
        case FTP_COMMAND_STOR:
            JB_SET_STRING(jb, "command", "STOR");
            break;
        case FTP_COMMAND_RETR:
            JB_SET_STRING(jb, "command", "RETR");
            break;
        default:
            break;
    }
}

/**
 * \brief Free memory allocated for global FTP parser state.
 */
void FTPParserCleanup(void)
{
    FTPFreeMpmState();
}

/* UNITTESTS */
#ifdef UNITTESTS
#include "stream-tcp.h"

/** \test Send a get request in one chunk. */
static int FTPParserTest01(void)
{
    Flow f;
    uint8_t ftpbuf[] = "PORT 192,168,1,1,0,80\r\n";
    uint32_t ftplen = sizeof(ftpbuf) - 1; /* minus the \0 */
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_EOF, ftpbuf, ftplen);
    FAIL_IF(r != 0);

    FtpState *ftp_state = f.alstate;
    FAIL_IF_NULL(ftp_state);
    FAIL_IF(ftp_state->command != FTP_COMMAND_PORT);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    PASS;
}

/** \test Supply RETR without a filename */
static int FTPParserTest11(void)
{
    Flow f;
    uint8_t ftpbuf1[] = "PORT 192,168,1,1,0,80\r\n";
    uint8_t ftpbuf2[] = "RETR\r\n";
    uint8_t ftpbuf3[] = "227 OK\r\n";
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                sizeof(ftpbuf1) - 1);
    FAIL_IF(r != 0);

    /* Response */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOCLIENT,
                                ftpbuf3,
                                sizeof(ftpbuf3) - 1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER, ftpbuf2,
                                sizeof(ftpbuf2) - 1);
    FAIL_IF(r == 0);

    FtpState *ftp_state = f.alstate;
    FAIL_IF_NULL(ftp_state);

    FAIL_IF(ftp_state->command != FTP_COMMAND_RETR);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    PASS;
}

/** \test Supply STOR without a filename */
static int FTPParserTest12(void)
{
    Flow f;
    uint8_t ftpbuf1[] = "PORT 192,168,1,1,0,80\r\n";
    uint8_t ftpbuf2[] = "STOR\r\n";
    uint8_t ftpbuf3[] = "227 OK\r\n";
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(true);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                sizeof(ftpbuf1) - 1);
    FAIL_IF(r != 0);

    /* Response */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOCLIENT,
                                ftpbuf3,
                                sizeof(ftpbuf3) - 1);
    FAIL_IF(r != 0);

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER, ftpbuf2,
                                sizeof(ftpbuf2) - 1);
    FAIL_IF(r == 0);

    FtpState *ftp_state = f.alstate;
    FAIL_IF_NULL(ftp_state);

    FAIL_IF(ftp_state->command != FTP_COMMAND_STOR);

    AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    PASS;
}
#endif /* UNITTESTS */

void FTPParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("FTPParserTest01", FTPParserTest01);
    UtRegisterTest("FTPParserTest11", FTPParserTest11);
    UtRegisterTest("FTPParserTest12", FTPParserTest12);
#endif /* UNITTESTS */
}

