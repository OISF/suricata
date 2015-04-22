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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __APP_LAYER_SMTP_H__
#define __APP_LAYER_SMTP_H__

#include "decode-events.h"
#include "util-decode-mime.h"
#include "queue.h"

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
};

typedef struct SMTPString_ {
    uint8_t *str;
    uint16_t len;

    TAILQ_ENTRY(SMTPString_) next;
} SMTPString;

typedef struct SMTPTransaction_ {
    /** id of this tx, starting at 0 */
    uint64_t tx_id;
    int done;
    /** the first message contained in the session */
    MimeDecEntity *msg_head;
    /** the last message contained in the session */
    MimeDecEntity *msg_tail;
    /** the mime decoding parser state */
    MimeDecParseState *mime_state;

    AppLayerDecoderEvents *decoder_events;          /**< per tx events */
    DetectEngineState *de_state;

    /* MAIL FROM parameters */
    uint8_t *mail_from;
    uint16_t mail_from_len;

    TAILQ_HEAD(, SMTPString_) rcpt_to_list;  /**< rcpt to string list */

    TAILQ_ENTRY(SMTPTransaction_) next;
} SMTPTransaction;

typedef struct SMTPConfig {

    int decode_mime;
    MimeDecConfig mime_config;
    uint32_t content_limit;
    uint32_t content_inspect_min_size;
    uint32_t content_inspect_window;
} SMTPConfig;

typedef struct SMTPState_ {
    SMTPTransaction *curr_tx;
    TAILQ_HEAD(, SMTPTransaction_) tx_list;  /**< transaction list */
    uint64_t tx_cnt;

    /* current input that is being parsed */
    uint8_t *input;
    int32_t input_len;
    uint8_t direction;

    /* --parser details-- */
    /** current line extracted by the parser from the call to SMTPGetline() */
    uint8_t *current_line;
    /** length of the line in current_line.  Doesn't include the delimiter */
    int32_t current_line_len;
    uint8_t current_line_delimiter_len;
    PatternMatcherQueue *thread_local_data;

    /** used to indicate if the current_line buffer is a malloced buffer.  We
     * use a malloced buffer, if a line is fragmented */
    uint8_t *tc_db;
    int32_t tc_db_len;
    uint8_t tc_current_line_db;
    /** we have see LF for the currently parsed line */
    uint8_t tc_current_line_lf_seen;

    /** used to indicate if the current_line buffer is a malloced buffer.  We
     * use a malloced buffer, if a line is fragmented */
    uint8_t *ts_db;
    int32_t ts_db_len;
    uint8_t ts_current_line_db;
    /** we have see LF for the currently parsed line */
    uint8_t ts_current_line_lf_seen;

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

    /* SMTP Mime decoding and file extraction */
    /** the list of files sent to the server */
    FileContainer *files_ts;

    /* HELO of HELO message content */
    uint8_t *helo;
    uint16_t helo_len;
} SMTPState;

/* Create SMTP config structure */
extern SMTPConfig smtp_config;

int SMTPProcessDataChunk(const uint8_t *chunk, uint32_t len, MimeDecParseState *state);
void *SMTPStateAlloc(void);
void RegisterSMTPParsers(void);
void SMTPParserRegisterTests(void);

#endif /* __APP_LAYER_SMTP_H__ */
