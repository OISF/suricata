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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef SURICATA_APP_LAYER_SMTP_H
#define SURICATA_APP_LAYER_SMTP_H

#include "rust.h"
#include "app-layer-frames.h"
#include "util-streaming-buffer.h"

/* Limit till the data would be buffered in current line */
#define SMTP_LINE_BUFFER_LIMIT 4096

enum {
    SMTP_DECODER_EVENT_INVALID_REPLY,
    SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST,
    SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE,
    SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE,
    SMTP_DECODER_EVENT_TLS_REJECTED,
    SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED,
    SMTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE,

    /* MIME Events */
    SMTP_DECODER_EVENT_MIME_PARSE_FAILED,
    SMTP_DECODER_EVENT_MIME_MALFORMED_MSG,
    SMTP_DECODER_EVENT_MIME_INVALID_BASE64,
    SMTP_DECODER_EVENT_MIME_INVALID_QP,
    SMTP_DECODER_EVENT_MIME_LONG_LINE,
    SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE,
    SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME,
    SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE,
    SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG,
    SMTP_DECODER_EVENT_MIME_LONG_FILENAME,

    /* Invalid behavior or content */
    SMTP_DECODER_EVENT_DUPLICATE_FIELDS,
    SMTP_DECODER_EVENT_UNPARSABLE_CONTENT,
    /* For line >= 4KB */
    SMTP_DECODER_EVENT_TRUNCATED_LINE,
};

typedef struct SMTPString_ {
    uint8_t *str;
    uint16_t len;

    TAILQ_ENTRY(SMTPString_) next;
} SMTPString;

typedef struct SMTPTransaction_ {
    /** id of this tx, starting at 0 */
    uint64_t tx_id;

    AppLayerTxData tx_data;

    /** the tx is complete and can be logged and cleaned */
    bool done;
    /** the tx has seen a DATA command */
    // another DATA command within the same context
    // will trigger an app-layer event.
    bool is_data;
    /** the mime decoding parser state */
    MimeStateSMTP *mime_state;

    /* MAIL FROM parameters */
    uint8_t *mail_from;
    uint16_t mail_from_len;

    TAILQ_HEAD(, SMTPString_) rcpt_to_list;  /**< rcpt to string list */

    FileContainer files_ts;

    TAILQ_ENTRY(SMTPTransaction_) next;
} SMTPTransaction;

/**
 * \brief Structure for containing configuration options
 *
 */

typedef struct SMTPConfig {

    bool decode_mime;
    uint32_t content_limit;
    uint32_t content_inspect_min_size;
    uint32_t content_inspect_window;
    uint64_t max_tx;

    bool raw_extraction;

    StreamingBufferConfig sbcfg;
} SMTPConfig;

typedef struct SMTPState_ {
    AppLayerStateData state_data;
    SMTPTransaction *curr_tx;
    TAILQ_HEAD(, SMTPTransaction_) tx_list;  /**< transaction list */
    uint64_t tx_cnt;
    uint64_t toserver_data_count;
    uint64_t toserver_last_data_stamp;

    /* If rest of the bytes should be discarded in case of long line w/o LF */
    bool discard_till_lf_ts;
    bool discard_till_lf_tc;

    /** var to indicate parser state */
    uint8_t parser_state;
    /** current command in progress */
    uint8_t current_command;
    /** bdat chunk len */
    uint32_t bdat_chunk_len;
    /** bdat chunk idx */
    uint32_t bdat_chunk_idx;

    /* the request commands are store here and the reply handler uses these
     * stored command in the buffer to match the reply(ies) with the command */
    /** the command buffer */
    uint8_t *cmds;
    /** the buffer length */
    uint16_t cmds_buffer_len;
    /** no of commands stored in the above buffer */
    uint16_t cmds_cnt;
    /** index of the command in the buffer, currently in inspection by reply
     *  handler */
    uint16_t cmds_idx;

    /* HELO of HELO message content */
    uint16_t helo_len;
    uint8_t *helo;

    /* SMTP Mime decoding and file extraction */
    /** the list of files sent to the server */
    uint32_t file_track_id;
} SMTPState;

/* Create SMTP config structure */
extern SMTPConfig smtp_config;

void *SMTPStateAlloc(void *orig_state, AppProto proto_orig);
void RegisterSMTPParsers(void);
void SMTPParserCleanup(void);
void SMTPParserRegisterTests(void);

#endif /* SURICATA_APP_LAYER_SMTP_H */
