/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

#ifndef __APP_LAYER_FTP_H__
#define __APP_LAYER_FTP_H__

#include "rust.h"

enum {
    FTP_STATE_IN_PROGRESS,
    FTP_STATE_PORT_DONE,
    FTP_STATE_FINISHED,
};

typedef enum {
    FTP_COMMAND_UNKNOWN = 0,
    FTP_COMMAND_ABOR,
    FTP_COMMAND_ACCT,
    FTP_COMMAND_ALLO,
    FTP_COMMAND_APPE,
    FTP_COMMAND_AUTH_TLS,
    FTP_COMMAND_CDUP,
    FTP_COMMAND_CHMOD,
    FTP_COMMAND_CWD,
    FTP_COMMAND_DELE,
    FTP_COMMAND_EPSV,
    FTP_COMMAND_HELP,
    FTP_COMMAND_IDLE,
    FTP_COMMAND_LIST,
    FTP_COMMAND_MAIL,
    FTP_COMMAND_MDTM,
    FTP_COMMAND_MKD,
    FTP_COMMAND_MLFL,
    FTP_COMMAND_MODE,
    FTP_COMMAND_MRCP,
    FTP_COMMAND_MRSQ,
    FTP_COMMAND_MSAM,
    FTP_COMMAND_MSND,
    FTP_COMMAND_MSOM,
    FTP_COMMAND_NLST,
    FTP_COMMAND_NOOP,
    FTP_COMMAND_PASS,
    FTP_COMMAND_PASV,
    FTP_COMMAND_PORT,
    FTP_COMMAND_PWD,
    FTP_COMMAND_QUIT,
    FTP_COMMAND_REIN,
    FTP_COMMAND_REST,
    FTP_COMMAND_RETR,
    FTP_COMMAND_RMD,
    FTP_COMMAND_RNFR,
    FTP_COMMAND_RNTO,
    FTP_COMMAND_SITE,
    FTP_COMMAND_SIZE,
    FTP_COMMAND_SMNT,
    FTP_COMMAND_STAT,
    FTP_COMMAND_STOR,
    FTP_COMMAND_STOU,
    FTP_COMMAND_STRU,
    FTP_COMMAND_SYST,
    FTP_COMMAND_TYPE,
    FTP_COMMAND_UMASK,
    FTP_COMMAND_USER,
    FTP_COMMAND_EPRT,

    /* must be last */
    FTP_COMMAND_MAX
    /** \todo more if missing.. */
} FtpRequestCommand;

typedef struct FtpCommand_ {
    FtpRequestCommand command;
    const char *command_name;
    const uint8_t command_length;
} FtpCommand;
extern const FtpCommand FtpCommands[FTP_COMMAND_MAX + 1];

typedef uint32_t FtpRequestCommandArgOfs;

typedef uint16_t FtpResponseCode;

enum {
    FTP_FIELD_NONE = 0,

    FTP_FIELD_REQUEST_LINE,
    FTP_FIELD_REQUEST_COMMAND,
    FTP_FIELD_REQUEST_ARGS,

    FTP_FIELD_RESPONSE_LINE,
    FTP_FIELD_REPONSE_CODE,

    /* must be last */
    FTP_FIELD_MAX,
};

/** used to hold the line state when we have fragmentation. */
typedef struct FtpLineState_ {
    /** used to indicate if the current_line buffer is a malloced buffer.  We
     * use a malloced buffer, if a line is fragmented */
    uint8_t *db;
    uint32_t db_len;
    uint8_t current_line_db;
    /** we have seen LF for the currently parsed line */
    uint8_t current_line_lf_seen;
} FtpLineState;

typedef struct FTPString_ {
    uint8_t *str;
    uint32_t len;
    bool truncated;
    TAILQ_ENTRY(FTPString_) next;
} FTPString;

typedef struct FTPTransaction_  {
    /** id of this tx, starting at 0 */
    uint64_t tx_id;

    AppLayerTxData tx_data;

    /* for the request */
    uint32_t request_length;
    uint8_t *request;
    bool request_truncated;

    /* for the command description */
    const FtpCommand *command_descriptor;

    uint16_t dyn_port; /* dynamic port, if applicable */
    bool done; /* transaction complete? */
    bool active; /* active or passive mode */

    uint8_t direction;

    /* Handle multiple responses */
    TAILQ_HEAD(, FTPString_) response_list;

    TAILQ_ENTRY(FTPTransaction_) next;
} FTPTransaction;

/** FTP State for app layer parser */
typedef struct FtpState_ {
    bool active;

    FTPTransaction *curr_tx;
    TAILQ_HEAD(, FTPTransaction_) tx_list;  /**< transaction list */
    uint64_t tx_cnt;

    /* --parser details-- */
    /** current line extracted by the parser from the call to FTPGetline() */
    const uint8_t *current_line;
    /** length of the line in current_line.  Doesn't include the delimiter */
    uint32_t current_line_len;
    uint8_t current_line_delimiter_len;
    bool current_line_truncated;

    /* 0 for toserver, 1 for toclient */
    FtpLineState line_state[2];

    FtpRequestCommand command;
    FtpRequestCommandArgOfs arg_offset;
    uint32_t port_line_len;
    uint32_t port_line_size;
    uint8_t *port_line;

    uint16_t dyn_port;
    /* specifies which loggers are done logging */
    uint32_t logged;

    AppLayerStateData state_data;
} FtpState;

enum {
    FTPDATA_STATE_IN_PROGRESS,
    FTPDATA_STATE_FINISHED,
};

/** FTP Data State for app layer parser */
typedef struct FtpDataState_ {
    uint8_t *input;
    uint8_t *file_name;
    FileContainer *files;
    int32_t input_len;
    int16_t file_len;
    FtpRequestCommand command;
    uint8_t state;
    uint8_t direction;
    AppLayerTxData tx_data;
    AppLayerStateData state_data;
} FtpDataState;

void RegisterFTPParsers(void);
void FTPParserRegisterTests(void);
void FTPAtExitPrintStats(void);
void FTPParserCleanup(void);
uint64_t FTPMemuseGlobalCounter(void);
uint64_t FTPMemcapGlobalCounter(void);

uint16_t JsonGetNextLineFromBuffer(const char *buffer, const uint16_t len);
void EveFTPDataAddMetadata(const Flow *f, JsonBuilder *jb);

#endif /* __APP_LAYER_FTP_H__ */

