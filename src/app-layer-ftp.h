/* Copyright (C) 2007-2025 Open Information Security Foundation
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

#ifndef SURICATA_APP_LAYER_FTP_H
#define SURICATA_APP_LAYER_FTP_H

#include "rust.h"

struct FtpCommand;

typedef uint32_t FtpRequestCommandArgOfs;

/** used to hold the line state when we have fragmentation. */
typedef struct FtpLineState_ {
    /** used to indicate if the current_line buffer is a malloced buffer.  We
     * use a malloced buffer, if a line is fragmented */
    const uint8_t *buf;
    uint32_t len;
    uint8_t delim_len;
    bool lf_found;
} FtpLineState;

typedef struct FTPResponseWrapper_ {
    FTPResponseLine *response;
    TAILQ_ENTRY(FTPResponseWrapper_) next;
} FTPResponseWrapper;

/*
 * These are the values for the table index value and the FTP command
 * enum value. These *should* be the same if the enum and command insertion
 * order remain the same. However, we store each value to protect against
 * drift between enum and insertion order.
 */
typedef struct FtpCommandInfo_ {
    uint8_t command_index;
    FtpRequestCommand command_code;
} FtpCommandInfo;

typedef struct FTPTransaction_  {
    /** id of this tx, starting at 0 */
    uint64_t tx_id;

    AppLayerTxData tx_data;

    /* for the request */
    uint32_t request_length;
    uint8_t *request;
    bool request_truncated;

    /* for the command description */
    FtpCommandInfo command_descriptor;

    uint16_t dyn_port; /* dynamic port, if applicable */
    bool done; /* transaction complete? */
    bool active; /* active or passive mode */

    uint8_t direction;

    /* Handle multiple responses */
    TAILQ_HEAD(, FTPResponseWrapper_) response_list;

    TAILQ_ENTRY(FTPTransaction_) next;
} FTPTransaction;

/** FTP State for app layer parser */
typedef struct FtpState_ {
    bool active;

    FTPTransaction *curr_tx;
    TAILQ_HEAD(, FTPTransaction_) tx_list;  /**< transaction list */
    uint64_t tx_cnt;

    bool current_line_truncated_ts;
    bool current_line_truncated_tc;

    FtpRequestCommand command;
    FtpRequestCommandArgOfs arg_offset;
    uint32_t port_line_len;
    uint32_t port_line_size;
    uint8_t *port_line;

    uint16_t dyn_port;

    AppLayerStateData state_data;
} FtpState;

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
void FTPParserCleanup(void);
int FTPSetMemcap(uint64_t size);
uint64_t FTPMemuseGlobalCounter(void);
uint64_t FTPMemcapGlobalCounter(void);

uint16_t JsonGetNextLineFromBuffer(const char *buffer, const uint16_t len);
bool EveFTPDataAddMetadata(void *vtx, SCJsonBuilder *jb);

#endif /* SURICATA_APP_LAYER_FTP_H */
