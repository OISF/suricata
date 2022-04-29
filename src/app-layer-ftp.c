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
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "util-print.h"
#include "util-pool.h"

#include "flow-util.h"
#include "flow-storage.h"

#include "detect-engine-state.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-ftp.h"
#include "app-layer-expectation.h"

#include "util-spm.h"
#include "util-mpm.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-memcmp.h"
#include "util-memrchr.h"
#include "util-byte.h"
#include "util-mem.h"
#include "util-misc.h"
#include "util-validate.h"

#include "rust-ftp-mod-gen.h"

#include "output-json.h"

typedef struct FTPThreadCtx_ {
    MpmThreadCtx *ftp_mpm_thread_ctx;
    PrefilterRuleStore *pmq;
} FTPThreadCtx;

#define FTP_MPM mpm_default_matcher

static MpmCtx *ftp_mpm_ctx = NULL;

const FtpCommand FtpCommands[FTP_COMMAND_MAX + 1] = {
    /* Parsed and handled */
    { FTP_COMMAND_PORT, "PORT", 4},
    { FTP_COMMAND_EPRT, "EPRT", 4},
    { FTP_COMMAND_AUTH_TLS, "AUTH TLS", 8},
    { FTP_COMMAND_PASV, "PASV", 4},
    { FTP_COMMAND_RETR, "RETR", 4},
    { FTP_COMMAND_EPSV, "EPSV", 4},
    { FTP_COMMAND_STOR, "STOR", 4},

    /* Parsed, but not handled */
    { FTP_COMMAND_ABOR, "ABOR", 4},
    { FTP_COMMAND_ACCT, "ACCT", 4},
    { FTP_COMMAND_ALLO, "ALLO", 4},
    { FTP_COMMAND_APPE, "APPE", 4},
    { FTP_COMMAND_CDUP, "CDUP", 4},
    { FTP_COMMAND_CHMOD, "CHMOD", 5},
    { FTP_COMMAND_CWD, "CWD", 3},
    { FTP_COMMAND_DELE, "DELE", 4},
    { FTP_COMMAND_HELP, "HELP", 4},
    { FTP_COMMAND_IDLE, "IDLE", 4},
    { FTP_COMMAND_LIST, "LIST", 4},
    { FTP_COMMAND_MAIL, "MAIL", 4},
    { FTP_COMMAND_MDTM, "MDTM", 4},
    { FTP_COMMAND_MKD, "MKD", 3},
    { FTP_COMMAND_MLFL, "MLFL", 4},
    { FTP_COMMAND_MODE, "MODE", 4},
    { FTP_COMMAND_MRCP, "MRCP", 4},
    { FTP_COMMAND_MRSQ, "MRSQ", 4},
    { FTP_COMMAND_MSAM, "MSAM", 4},
    { FTP_COMMAND_MSND, "MSND", 4},
    { FTP_COMMAND_MSOM, "MSOM", 4},
    { FTP_COMMAND_NLST, "NLST", 4},
    { FTP_COMMAND_NOOP, "NOOP", 4},
    { FTP_COMMAND_PASS, "PASS", 4},
    { FTP_COMMAND_PWD, "PWD", 3},
    { FTP_COMMAND_QUIT, "QUIT", 4},
    { FTP_COMMAND_REIN, "REIN", 4},
    { FTP_COMMAND_REST, "REST", 4},
    { FTP_COMMAND_RMD, "RMD", 3},
    { FTP_COMMAND_RNFR, "RNFR", 4},
    { FTP_COMMAND_RNTO, "RNTO", 4},
    { FTP_COMMAND_SITE, "SITE", 4},
    { FTP_COMMAND_SIZE, "SIZE", 4},
    { FTP_COMMAND_SMNT, "SMNT", 4},
    { FTP_COMMAND_STAT, "STAT", 4},
    { FTP_COMMAND_STOU, "STOU", 4},
    { FTP_COMMAND_STRU, "STRU", 4},
    { FTP_COMMAND_SYST, "SYST", 4},
    { FTP_COMMAND_TYPE, "TYPE", 4},
    { FTP_COMMAND_UMASK, "UMASK", 5},
    { FTP_COMMAND_USER, "USER", 4},
    { FTP_COMMAND_UNKNOWN, NULL, 0}
};
uint64_t ftp_config_memcap = 0;
uint32_t ftp_max_line_len = 4096;

SC_ATOMIC_DECLARE(uint64_t, ftp_memuse);
SC_ATOMIC_DECLARE(uint64_t, ftp_memcap);

static FTPTransaction *FTPGetOldestTx(FtpState *, FTPTransaction *);

static void FTPParseMemcap(void)
{
    const char *conf_val;

    /** set config values for memcap, prealloc and hash_size */
    if ((ConfGet("app-layer.protocols.ftp.memcap", &conf_val)) == 1)
    {
        if (ParseSizeStringU64(conf_val, &ftp_config_memcap) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing ftp.memcap "
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

    if ((ConfGet("app-layer.protocols.ftp.max-line-length", &conf_val)) == 1) {
        if (ParseSizeStringU32(conf_val, &ftp_max_line_len) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing ftp.max-line-length from conf file - %s.",
                    conf_val);
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

static void *FTPMalloc(size_t size)
{
    void *ptr = NULL;

    if (FTPCheckMemcap((uint32_t)size) == 0)
        return NULL;

    ptr = SCMalloc(size);

    if (unlikely(ptr == NULL))
        return NULL;

    FTPIncrMemuse((uint64_t)size);

    return ptr;
}

static void *FTPCalloc(size_t n, size_t size)
{
    void *ptr = NULL;

    if (FTPCheckMemcap((uint32_t)(n * size)) == 0)
        return NULL;

    ptr = SCCalloc(n, size);

    if (unlikely(ptr == NULL))
        return NULL;

    FTPIncrMemuse((uint64_t)(n * size));

    return ptr;
}

static void *FTPRealloc(void *ptr, size_t orig_size, size_t size)
{
    void *rptr = NULL;

    if (FTPCheckMemcap((uint32_t)(size - orig_size)) == 0)
        return NULL;

    rptr = SCRealloc(ptr, size);
    if (rptr == NULL)
        return NULL;

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

    if (tx->de_state != NULL) {
        DetectEngineStateFree(tx->de_state);
    }

    if (tx->request) {
        FTPFree(tx->request, tx->request_length);
    }

    FTPString *str = NULL;
    while ((str = TAILQ_FIRST(&tx->response_list))) {
        TAILQ_REMOVE(&tx->response_list, str, next);
        FTPStringFree(str);
    }

    FTPFree(tx, sizeof(*tx));
}

static int FTPGetLineForDirection(FtpState *state, FtpLineState *line_state)
{
    void *ptmp;
    if (line_state->current_line_lf_seen == 1) {
        /* we have seen the lf for the previous line.  Clear the parser
         * details to parse new line */
        line_state->current_line_lf_seen = 0;
        state->current_line_truncated = false;
        if (line_state->current_line_db == 1) {
            line_state->current_line_db = 0;
            FTPFree(line_state->db, line_state->db_len);
            line_state->db = NULL;
            line_state->db_len = 0;
            state->current_line = NULL;
            state->current_line_len = 0;
        }
    }

    /* Should be guaranteed by the caller. */
    DEBUG_VALIDATE_BUG_ON(state->input_len <= 0);

    uint8_t *lf_idx = memchr(state->input, 0x0a, state->input_len);

    if (lf_idx == NULL) {
        /* fragmented lines.  Decoder event for special cases.  Not all
         * fragmented lines should be treated as a possible evasion
         * attempt.  With multi payload ftp chunks we can have valid
         * cases of fragmentation.  But within the same segment chunk
         * if we see fragmentation then it's definitely something you
         * should alert about */
        if (line_state->current_line_db == 0) {
            int32_t input_len = state->input_len;
            if ((uint32_t)input_len > ftp_max_line_len) {
                input_len = ftp_max_line_len;
                state->current_line_truncated = true;
            }
            line_state->db = FTPMalloc(input_len);
            if (line_state->db == NULL) {
                return -1;
            }
            line_state->current_line_db = 1;
            memcpy(line_state->db, state->input, input_len);
            line_state->db_len = input_len;
        } else if (!state->current_line_truncated) {
            int32_t input_len = state->input_len;
            if (line_state->db_len + input_len > ftp_max_line_len) {
                input_len = ftp_max_line_len - line_state->db_len;
                DEBUG_VALIDATE_BUG_ON(input_len < 0);
                state->current_line_truncated = true;
            }
            if (input_len > 0) {
                ptmp = FTPRealloc(
                        line_state->db, line_state->db_len, (line_state->db_len + input_len));
                if (ptmp == NULL) {
                    FTPFree(line_state->db, line_state->db_len);
                    line_state->db = NULL;
                    line_state->db_len = 0;
                    return -1;
                }
                line_state->db = ptmp;

                memcpy(line_state->db + line_state->db_len, state->input, input_len);
                line_state->db_len += input_len;
            }
        }
        state->input += state->input_len;
        state->input_len = 0;

        return -1;

    } else {
        line_state->current_line_lf_seen = 1;

        if (line_state->current_line_db == 1) {
            if (!state->current_line_truncated) {
                int32_t input_len = lf_idx + 1 - state->input;
                if (line_state->db_len + input_len > ftp_max_line_len) {
                    input_len = ftp_max_line_len - line_state->db_len;
                    DEBUG_VALIDATE_BUG_ON(input_len < 0);
                    state->current_line_truncated = true;
                }
                if (input_len > 0) {
                    ptmp = FTPRealloc(
                            line_state->db, line_state->db_len, (line_state->db_len + input_len));
                    if (ptmp == NULL) {
                        FTPFree(line_state->db, line_state->db_len);
                        line_state->db = NULL;
                        line_state->db_len = 0;
                        return -1;
                    }
                    line_state->db = ptmp;

                    memcpy(line_state->db + line_state->db_len, state->input, input_len);
                    line_state->db_len += input_len;

                    if (line_state->db_len > 1 && line_state->db[line_state->db_len - 2] == 0x0D) {
                        line_state->db_len -= 2;
                        state->current_line_delimiter_len = 2;
                    } else {
                        line_state->db_len -= 1;
                        state->current_line_delimiter_len = 1;
                    }
                }
            }

            state->current_line = line_state->db;
            state->current_line_len = line_state->db_len;

        } else {
            state->current_line = state->input;
            if (lf_idx - state->input > ftp_max_line_len) {
                state->current_line_len = ftp_max_line_len;
                state->current_line_truncated = true;
            } else {
                state->current_line_len = lf_idx - state->input;
            }

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
 * transferred to the ftp server
 * \param thread context
 * \param input input line of the command
 * \param len of the command
 * \param cmd_descriptor when the command has been parsed
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPParseRequestCommand(FTPThreadCtx *td,
                                  const uint8_t *input, uint32_t input_len,
                                  const FtpCommand **cmd_descriptor)
{
    SCEnter();

    /* I don't like this pmq reset here.  We'll devise a method later, that
     * should make the use of the mpm very efficient */
    PmqReset(td->pmq);
    int mpm_cnt = mpm_table[FTP_MPM].Search(ftp_mpm_ctx, td->ftp_mpm_thread_ctx,
                                            td->pmq, input, input_len);
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

static uint32_t CopyCommandLine(uint8_t **dest, const uint8_t *src, uint32_t length)
{
    if (likely(length)) {
        uint8_t *where = FTPCalloc(length + 1, sizeof(char));
        if (unlikely(where == NULL)) {
            return 0;
        }
        memcpy(where, src, length);

        /* Remove trailing newlines/carriage returns */
        while (length && isspace((unsigned char) where[length - 1])) {
            length--;
        }

        where[length] = '\0';
        *dest = where;
    }
    /* either 0 or actual */
    return length ? length + 1 : 0;
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
                           const uint8_t *input, uint32_t input_len,
                           void *local_data, const uint8_t flags)
{
    FTPThreadCtx *thread_data = local_data;

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

    int direction = STREAM_TOSERVER;
    while (FTPGetLine(state) >= 0) {
        const FtpCommand *cmd_descriptor;

        if (!FTPParseRequestCommand(thread_data, state->current_line, state->current_line_len, &cmd_descriptor)) {
            state->command = FTP_COMMAND_UNKNOWN;
            continue;
        }

        state->command = cmd_descriptor->command;

        FTPTransaction *tx = FTPTransactionCreate(state);
        if (unlikely(tx == NULL))
            return -1;
        state->curr_tx = tx;

        tx->command_descriptor = cmd_descriptor;
        tx->request_length = CopyCommandLine(&tx->request, state->current_line, state->current_line_len);
        tx->request_truncated = state->current_line_truncated;

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
                if (state->current_line_len + 1 > state->port_line_size) {
                    /* Allocate an extra byte for a NULL terminator */
                    ptmp = FTPRealloc(state->port_line, state->port_line_size,
                                      state->current_line_len);
                    if (ptmp == NULL) {
                        if (state->port_line) {
                            FTPFree(state->port_line, state->port_line_size);
                            state->port_line = NULL;
                            state->port_line_size = 0;
                        }
                        return 0;
                    }
                    state->port_line = ptmp;
                    state->port_line_size = state->current_line_len;
                }
                memcpy(state->port_line, state->current_line,
                        state->current_line_len);
                state->port_line_len = state->current_line_len;
                break;
            case FTP_COMMAND_RETR:
                // fallthrough
            case FTP_COMMAND_STOR:
                {
                    /* Ensure that there is a negotiated dyn port and a file
                     * name -- need more than 5 chars: cmd [4], space, <filename>
                     */
                    if (state->dyn_port == 0 || state->current_line_len < 6) {
                        SCReturnInt(-1);
                    }
                    struct FtpTransferCmd *data = FTPCalloc(1, sizeof(struct FtpTransferCmd));
                    if (data == NULL)
                        SCReturnInt(-1);
                    data->DFree = FtpTransferCmdFree;
                    /* Min size has been checked in FTPParseRequestCommand */
                    data->file_name = FTPCalloc(state->current_line_len - 4, sizeof(char));
                    if (data->file_name == NULL) {
                        FtpTransferCmdFree(data);
                        SCReturnInt(-1);
                    }
                    data->file_name[state->current_line_len - 5] = 0;
                    data->file_len = state->current_line_len - 5;
                    memcpy(data->file_name, state->current_line + 5, state->current_line_len - 5);
                    data->cmd = state->command;
                    data->flow_id = FlowGetId(f);
                    data->direction = direction;
                    int ret = AppLayerExpectationCreate(f, direction,
                                            0, state->dyn_port, ALPROTO_FTPDATA, data);
                    if (ret == -1) {
                        FtpTransferCmdFree(data);
                        SCLogDebug("No expectation created.");
                        SCReturnInt(-1);
                    } else {
                        SCLogDebug("Expectation created [direction: %s, dynamic port %"PRIu16"].",
                            (direction & STREAM_TOSERVER) ? "to server" : "to client",
                            state->dyn_port);
                    }

                    /* reset the dyn port to avoid duplicate */
                    state->dyn_port = 0;
                    /* reset active/passive indicator */
                    state->active = false;
                }
                break;
            default:
                break;
        }
    }

    return 1;
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
 * \retval: True for a positive preliminary reply; false otherwise
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
static int FTPParseResponse(Flow *f, void *ftp_state, AppLayerParserState *pstate,
                            const uint8_t *input, uint32_t input_len,
                            void *local_data, const uint8_t flags)
{
    FtpState *state = (FtpState *)ftp_state;
    int retcode = 1;

    if (unlikely(input_len == 0)) {
        return 1;
    }
    state->input = input;
    state->input_len = input_len;
    /* toclient stream */
    state->direction = 1;

    FTPTransaction *lasttx = TAILQ_FIRST(&state->tx_list);
    while (FTPGetLine(state) >= 0) {
        FTPTransaction *tx = FTPGetOldestTx(state, lasttx);
        if (tx == NULL) {
            tx = FTPTransactionCreate(state);
        }
        if (unlikely(tx == NULL)) {
            return -1;
        }
        lasttx = tx;
        if (state->command == FTP_COMMAND_UNKNOWN || tx->command_descriptor == NULL) {
            /* unknown */
            tx->command_descriptor = &FtpCommands[FTP_COMMAND_MAX -1];
        }

        state->curr_tx = tx;
        if (state->command == FTP_COMMAND_AUTH_TLS) {
            if (state->current_line_len >= 4 && SCMemcmp("234 ", state->current_line, 4) == 0) {
                AppLayerRequestProtocolTLSUpgrade(f);
            }
        }

        if (state->command == FTP_COMMAND_EPRT) {
            uint16_t dyn_port = rs_ftp_active_eprt(state->port_line, state->port_line_len);
            if (dyn_port == 0) {
                goto tx_complete;
            }
            state->dyn_port = dyn_port;
            state->active = true;
            tx->dyn_port = dyn_port;
            tx->active = true;
            SCLogDebug("FTP active mode (v6): dynamic port %"PRIu16"", dyn_port);
        }

        if (state->command == FTP_COMMAND_PORT) {
            if ((flags & STREAM_TOCLIENT)) {
                uint16_t dyn_port = rs_ftp_active_port(state->port_line, state->port_line_len);
                if (dyn_port == 0) {
                    goto tx_complete;
                }
                state->dyn_port = dyn_port;
                state->active = true;
                tx->dyn_port = state->dyn_port;
                tx->active = true;
                SCLogDebug("FTP active mode (v4): dynamic port %"PRIu16"", dyn_port);
            }
        }

        if (state->command == FTP_COMMAND_PASV) {
            if (state->current_line_len >= 4 && SCMemcmp("227 ", state->current_line, 4) == 0) {
                FTPParsePassiveResponse(f, ftp_state, state->current_line, state->current_line_len);
            }
        }

        if (state->command == FTP_COMMAND_EPSV) {
            if (state->current_line_len >= 4 && SCMemcmp("229 ", state->current_line, 4) == 0) {
                FTPParsePassiveResponseV6(f, ftp_state, state->current_line, state->current_line_len);
            }
        }

        if (likely(state->current_line_len)) {
            FTPString *response = FTPStringAlloc();
            if (likely(response)) {
                response->len = CopyCommandLine(&response->str, state->current_line, state->current_line_len);
                response->truncated = state->current_line_truncated;
                TAILQ_INSERT_TAIL(&tx->response_list, response, next);
            }
        }

        /* Handle preliminary replies -- keep tx open */
        if (FTPIsPPR(state->current_line, state->current_line_len)) {
            continue;
        }
    tx_complete:
        tx->done = true;
    }

    return retcode;
}


#ifdef DEBUG
static SCMutex ftp_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftp_state_memuse = 0;
static uint64_t ftp_state_memcnt = 0;
#endif

static void *FTPStateAlloc(void)
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
    if (fstate->line_state[0].db)
        FTPFree(fstate->line_state[0].db, fstate->line_state[0].db_len);
    if (fstate->line_state[1].db)
        FTPFree(fstate->line_state[1].db, fstate->line_state[1].db_len);

    //AppLayerDecoderEventsFreeEvents(&s->decoder_events);

    FTPTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&fstate->tx_list))) {
        TAILQ_REMOVE(&fstate->tx_list, tx, next);
        SCLogDebug("[%s] state %p id %"PRIu64", Freeing %d bytes at %p",
            tx->command_descriptor->command_name,
            s, tx->tx_id,
            tx->request_length, tx->request);
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

static int FTPSetTxDetectState(void *vtx, DetectEngineState *de_state)
{
    FTPTransaction *tx = (FTPTransaction *)vtx;
    tx->de_state = de_state;
    return 0;
}

/**
 * \brief This function returns the oldest open transaction; if none
 * are open, then the oldest transaction is returned
 * \param ftp_state the ftp state structure for the parser
 * \param starttx the ftp transaction where to start looking
 *
 * \retval transaction pointer when a transaction was found; NULL otherwise.
 */
static FTPTransaction *FTPGetOldestTx(FtpState *ftp_state, FTPTransaction *starttx)
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

static DetectEngineState *FTPGetTxDetectState(void *vtx)
{
    FTPTransaction *tx = (FTPTransaction *)vtx;
    return tx->de_state;
}


static uint64_t FTPGetTxDetectFlags(void *vtx, uint8_t dir)
{
    FTPTransaction *tx = (FTPTransaction *)vtx;
    if (dir & STREAM_TOSERVER) {
        return tx->detect_flags_ts;
    } else {
        return tx->detect_flags_tc;
    }
}

static void FTPSetTxDetectFlags(void *vtx, uint8_t dir, uint64_t flags)
{
    FTPTransaction *tx = (FTPTransaction *)vtx;
    if (dir & STREAM_TOSERVER) {
        tx->detect_flags_ts = flags;
    } else {
        tx->detect_flags_tc = flags;
    }
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

static int FTPGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return FTP_STATE_FINISHED;
}

static int FTPGetAlstateProgress(void *vtx, uint8_t direction)
{
    SCLogDebug("tx %p", vtx);
    FTPTransaction *tx = vtx;

    if (!tx->done) {
        if (direction == STREAM_TOSERVER &&
            tx->command_descriptor->command == FTP_COMMAND_PORT) {
            return FTP_STATE_PORT_DONE;
        }
        return FTP_STATE_IN_PROGRESS;
    }

    return FTP_STATE_FINISHED;
}


static int FTPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_FTP,
                                              "220 (", 5, 0, STREAM_TOCLIENT) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_FTP,
                                               "FEAT", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
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


static StreamingBufferConfig sbcfg = STREAMING_BUFFER_CONFIG_INITIALIZER;

/**
 * \brief This function is called to retrieve a ftp request
 * \param ftp_state the ftp state structure for the parser
 * \param input input line of the command
 * \param input_len length of the request
 * \param output the resulting output
 *
 * \retval 1 when the command is parsed, 0 otherwise
 */
static int FTPDataParse(Flow *f, FtpDataState *ftpdata_state,
        AppLayerParserState *pstate,
        const uint8_t *input, uint32_t input_len,
        void *local_data, int direction)
{
    uint16_t flags = FileFlowToFlags(f, direction);
    int ret = 0;
    /* we depend on detection engine for file pruning */
    flags |= FILE_USE_DETECT;
    const bool eof = (direction & ftpdata_state->direction) != 0 &&
        AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF) != 0;

    SCLogDebug("FTP-DATA input_len %u flags %04x dir %d/%s EOF %s", input_len, flags, direction,
            (direction & STREAM_TOSERVER) ? "toserver" : "toclient", eof ? "true" : "false");
    if (input_len && ftpdata_state->files == NULL) {
        struct FtpTransferCmd *data = (struct FtpTransferCmd *)FlowGetStorageById(f, AppLayerExpectationGetDataId());
        if (data == NULL) {
            SCReturnInt(-1);
        }

        /* we shouldn't get data in the wrong dir. Don't set things up for this dir */
        if ((direction & data->direction) == 0) {
            // TODO set event for data in wrong direction
            SCLogDebug("input %u not for our direction (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    data->cmd == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (data->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnInt(-1);
        }

        ftpdata_state->files = FileContainerAlloc();
        if (ftpdata_state->files == NULL) {
            FlowFreeStorageById(f, AppLayerExpectationGetDataId());
            SCReturnInt(-1);
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
        FlowFreeStorageById(f, AppLayerExpectationGetDataId());
    } else {
        if (ftpdata_state->state == FTPDATA_STATE_FINISHED) {
            SCLogDebug("state is already finished");
            DEBUG_VALIDATE_BUG_ON(input_len); // data after state finished is a bug.
            SCReturnInt(0);
        }
        if ((direction & ftpdata_state->direction) == 0) {
            if (input_len) {
                // TODO set event for data in wrong direction
            }
            SCLogDebug("input %u not for us (%s): %s/%s", input_len,
                    (direction & STREAM_TOSERVER) ? "toserver" : "toclient",
                    ftpdata_state->command == FTP_COMMAND_STOR ? "STOR" : "RETR",
                    (ftpdata_state->direction & STREAM_TOSERVER) ? "toserver" : "toclient");
            SCReturnInt(0);
        }
        if (input_len != 0) {
            ret = FileAppendData(ftpdata_state->files, input, input_len);
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
    DEBUG_VALIDATE_BUG_ON((direction & ftpdata_state->direction) == 0); // should be unreachble
    if (eof) {
        ret = FileCloseFile(ftpdata_state->files, NULL, 0, flags);
        ftpdata_state->state = FTPDATA_STATE_FINISHED;
        SCLogDebug("closed because of eof");
    }
out:
    return ret;
}

static void FTPStateSetTxLogged(void *state, void *vtx, LoggerId logged)
{
    FTPTransaction *tx = vtx;
    tx->logged = logged;
}

static LoggerId FTPStateGetTxLogged(void *state, void *vtx)
{
    FTPTransaction *tx = vtx;
    return tx->logged;
}
static int FTPDataParseRequest(Flow *f, void *ftp_state,
        AppLayerParserState *pstate,
        const uint8_t *input, uint32_t input_len,
        void *local_data, const uint8_t flags)
{
    return FTPDataParse(f, ftp_state, pstate, input, input_len,
                               local_data, STREAM_TOSERVER);
}

static int FTPDataParseResponse(Flow *f, void *ftp_state,
        AppLayerParserState *pstate,
        const uint8_t *input, uint32_t input_len,
        void *local_data, const uint8_t flags)
{
    return FTPDataParse(f, ftp_state, pstate, input, input_len,
                               local_data, STREAM_TOCLIENT);
}

#ifdef DEBUG
static SCMutex ftpdata_state_mem_lock = SCMUTEX_INITIALIZER;
static uint64_t ftpdata_state_memuse = 0;
static uint64_t ftpdata_state_memcnt = 0;
#endif

static void *FTPDataStateAlloc(void)
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

    if (fstate->de_state != NULL) {
        DetectEngineStateFree(fstate->de_state);
    }
    if (fstate->file_name != NULL) {
        FTPFree(fstate->file_name, fstate->file_len + 1);
    }

    FileContainerFree(fstate->files);

    FTPFree(s, sizeof(FtpDataState));
#ifdef DEBUG
    SCMutexLock(&ftpdata_state_mem_lock);
    ftpdata_state_memcnt--;
    ftpdata_state_memuse-=sizeof(FtpDataState);
    SCMutexUnlock(&ftpdata_state_mem_lock);
#endif
}

static int FTPDataSetTxDetectState(void *vtx, DetectEngineState *de_state)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    ftp_state->de_state = de_state;
    return 0;
}

static DetectEngineState *FTPDataGetTxDetectState(void *vtx)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    return ftp_state->de_state;
}

static void FTPDataSetTxDetectFlags(void *vtx, uint8_t dir, uint64_t flags)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    if (dir & STREAM_TOSERVER) {
        ftp_state->detect_flags_ts = flags;
    } else {
        ftp_state->detect_flags_tc = flags;
    }
}

static uint64_t FTPDataGetTxDetectFlags(void *vtx, uint8_t dir)
{
    FtpDataState *ftp_state = (FtpDataState *)vtx;
    if (dir & STREAM_TOSERVER) {
        return ftp_state->detect_flags_ts;
    } else {
        return ftp_state->detect_flags_tc;
    }
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

static int FTPDataGetAlstateProgressCompletionStatus(uint8_t direction)
{
    return FTPDATA_STATE_FINISHED;
}

static int FTPDataGetAlstateProgress(void *tx, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)tx;
    return ftpdata_state->state;
}

static FileContainer *FTPDataStateGetFiles(void *state, uint8_t direction)
{
    FtpDataState *ftpdata_state = (FtpDataState *)state;

    if (direction != ftpdata_state->direction)
        SCReturnPtr(NULL, "FileContainer");

    SCReturnPtr(ftpdata_state->files, "FileContainer");
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

        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_FTP,
                FTPGetTxDetectState, FTPSetTxDetectState);

        AppLayerParserRegisterDetectFlagsFuncs(IPPROTO_TCP, ALPROTO_FTP,
                                               FTPGetTxDetectFlags, FTPSetTxDetectFlags);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_FTP, FTPGetTx);
        AppLayerParserRegisterLoggerFuncs(IPPROTO_TCP, ALPROTO_FTP, FTPStateGetTxLogged,
                                          FTPStateSetTxLogged);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_FTP, FTPGetTxIterator);

        AppLayerParserRegisterLocalStorageFunc(IPPROTO_TCP, ALPROTO_FTP, FTPLocalStorageAlloc,
                                               FTPLocalStorageFree);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_FTP, FTPGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_FTP, FTPGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_FTP,
                                                               FTPGetAlstateProgressCompletionStatus);


        AppLayerRegisterExpectationProto(IPPROTO_TCP, ALPROTO_FTPDATA);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER,
                                     FTPDataParseRequest);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOCLIENT,
                                     FTPDataParseResponse);
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateAlloc, FTPDataStateFree);
        AppLayerParserRegisterParserAcceptableDataDirection(IPPROTO_TCP, ALPROTO_FTPDATA, STREAM_TOSERVER | STREAM_TOCLIENT);
        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateTransactionFree);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_FTPDATA,
                FTPDataGetTxDetectState, FTPDataSetTxDetectState);
        AppLayerParserRegisterDetectFlagsFuncs(IPPROTO_TCP, ALPROTO_FTPDATA,
                FTPDataGetTxDetectFlags, FTPDataSetTxDetectFlags);

        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataStateGetFiles);

        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTx);

        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetTxCnt);

        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_FTPDATA, FTPDataGetAlstateProgress);

        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_FTPDATA,
                FTPDataGetAlstateProgressCompletionStatus);

        sbcfg.buf_size = 4096;
        sbcfg.Malloc = FTPMalloc;
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
    return c == NULL ? len : c - buffer + 1;
}

json_t *JsonFTPDataAddMetadata(const Flow *f)
{
    const FtpDataState *ftp_state = NULL;
    if (f->alstate == NULL)
        return NULL;
    ftp_state = (FtpDataState *)f->alstate;
    json_t *ftpd = json_object();
    if (ftpd == NULL)
        return NULL;
    if (ftp_state->file_name) {
        size_t size = ftp_state->file_len * 2 + 1;
        char string[size];
        BytesToStringBuffer(ftp_state->file_name, ftp_state->file_len, string, size);
        json_object_set_new(ftpd, "filename", SCJsonString(string));
    }
    switch (ftp_state->command) {
        case FTP_COMMAND_STOR:
            json_object_set_new(ftpd, "command", json_string("STOR"));
            break;
        case FTP_COMMAND_RETR:
            json_object_set_new(ftpd, "command", json_string("RETR"));
            break;
        default:
            break;
    }
    return ftpd;
}

/**
 * \brief Free memory allocated for global SMTP parser state.
 */
void FTPParserCleanup(void)
{
    FTPFreeMpmState();
}

/* UNITTESTS */
#ifdef UNITTESTS

/** \test Send a get request in one chunk. */
static int FTPParserTest01(void)
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
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_EOF, ftpbuf, ftplen);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

/** \test Send a split get request. */
static int FTPParserTest03(void)
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

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP, STREAM_TOSERVER,
                            ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                            STREAM_TOSERVER | STREAM_EOF, ftpbuf3, ftplen3);
    if (r != 0) {
        SCLogDebug("toserver chunk 3 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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
static int FTPParserTest06(void)
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
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START | STREAM_EOF,
                                ftpbuf1,
                                ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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
static int FTPParserTest07(void)
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
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                ftplen1);
    if (r != 0) {
        SCLogDebug("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                            STREAM_TOSERVER | STREAM_EOF, ftpbuf2, ftplen2);
    if (r != 0) {
        SCLogDebug("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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
static int FTPParserTest10(void)
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
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    uint32_t u;
    for (u = 0; u < ftplen1; u++) {
        uint8_t flags = 0;

        if (u == 0) flags = STREAM_TOSERVER|STREAM_START;
        else if (u == (ftplen1 - 1)) flags = STREAM_TOSERVER|STREAM_EOF;
        else flags = STREAM_TOSERVER;

        FLOWLOCK_WRLOCK(&f);
        r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP, flags,
                                &ftpbuf1[u], 1);
        if (r != 0) {
            SCLogDebug("toserver chunk %" PRIu32 " returned %" PRId32 ", expected 0: ", u, r);
            result = 0;
            FLOWLOCK_UNLOCK(&f);
            goto end;
        }
        FLOWLOCK_UNLOCK(&f);
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

/** \test Supply RETR without a filename */
static int FTPParserTest11(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT 192,168,1,1,0,80\r\n";
    uint8_t ftpbuf2[] = "RETR\r\n";
    uint8_t ftpbuf3[] = "227 OK\r\n";
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                sizeof(ftpbuf1) - 1);
    if (r != 0) {
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* Response */
    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOCLIENT,
                                ftpbuf3,
                                sizeof(ftpbuf3) - 1);
    if (r != 0) {
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER, ftpbuf2,
                                sizeof(ftpbuf2) - 1);
    if (r == 0) {
        SCLogDebug("parse should've failed");
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_RETR) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ",
                   FTP_COMMAND_RETR, ftp_state->command);
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

/** \test Supply STOR without a filename */
static int FTPParserTest12(void)
{
    int result = 1;
    Flow f;
    uint8_t ftpbuf1[] = "PORT 192,168,1,1,0,80\r\n";
    uint8_t ftpbuf2[] = "STOR\r\n";
    uint8_t ftpbuf3[] = "227 OK\r\n";
    TcpSession ssn;

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.alproto = ALPROTO_FTP;

    StreamTcpInitConfig(TRUE);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER | STREAM_START, ftpbuf1,
                                sizeof(ftpbuf1) - 1);
    if (r != 0) {
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* Response */
    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOCLIENT,
                                ftpbuf3,
                                sizeof(ftpbuf3) - 1);
    if (r != 0) {
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_FTP,
                                STREAM_TOSERVER, ftpbuf2,
                                sizeof(ftpbuf2) - 1);
    if (r == 0) {
        SCLogDebug("parse should've failed");
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    FtpState *ftp_state = f.alstate;
    if (ftp_state == NULL) {
        SCLogDebug("no ftp state: ");
        result = 0;
        goto end;
    }

    if (ftp_state->command != FTP_COMMAND_STOR) {
        SCLogDebug("expected command %" PRIu32 ", got %" PRIu32 ": ",
                   FTP_COMMAND_STOR, ftp_state->command);
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
    UtRegisterTest("FTPParserTest01", FTPParserTest01);
    UtRegisterTest("FTPParserTest03", FTPParserTest03);
    UtRegisterTest("FTPParserTest06", FTPParserTest06);
    UtRegisterTest("FTPParserTest07", FTPParserTest07);
    UtRegisterTest("FTPParserTest10", FTPParserTest10);
    UtRegisterTest("FTPParserTest11", FTPParserTest11);
    UtRegisterTest("FTPParserTest12", FTPParserTest12);
#endif /* UNITTESTS */
}

