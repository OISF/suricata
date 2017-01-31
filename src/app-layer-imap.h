/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 */

#ifndef __APP_LAYER_IMAP_H__
#define __APP_LAYER_IMAP_H__

#include "decode-events.h"
#include "util-decode-mime.h"

enum {
    IMAP_DECODER_EVENT_INVALID_REPLY,
    IMAP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST,
    IMAP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED,
    IMAP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED,
    IMAP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE,
    IMAP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED,
    IMAP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE,
    IMAP_DECODER_EVENT_TLS_REJECTED,
    IMAP_DECODER_EVENT_DATA_COMMAND_REJECTED,

    /* MIME Events */
    IMAP_DECODER_EVENT_MIME_PARSE_FAILED,
    IMAP_DECODER_EVENT_MIME_MALFORMED_MSG,
    IMAP_DECODER_EVENT_MIME_INVALID_BASE64,
    IMAP_DECODER_EVENT_MIME_INVALID_QP,
    IMAP_DECODER_EVENT_MIME_LONG_LINE,
    IMAP_DECODER_EVENT_MIME_LONG_ENC_LINE,
    IMAP_DECODER_EVENT_MIME_LONG_HEADER_NAME,
    IMAP_DECODER_EVENT_MIME_LONG_HEADER_VALUE,
};

typedef struct IMAPTransaction_ {
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

    TAILQ_ENTRY(IMAPTransaction_) next;
} IMAPTransaction;

typedef struct IMAPState_ {
    IMAPTransaction *curr_tx;
    TAILQ_HEAD(, IMAPTransaction_) tx_list;  /**< transaction list */
    uint64_t tx_cnt;

    /* current input that is being parsed */
    uint8_t *input;
    int32_t input_len;
    uint8_t direction;

    /* --parser details-- */
    /** current line extracted by the parser from the call to POP3Getline() */
    uint8_t *current_line;
    /** length of the line in current_line.  Doesn't include the delimiter */
    int32_t current_line_len;
    uint8_t current_line_delimiter_len;
    int32_t remaining_fetch_len;

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

    uint8_t *parser_position;
    /** command number in progress */
    uint8_t *command_token;
    uint32_t command_token_len;
    /** command in progress */
    uint8_t *command;
    uint32_t command_len;
    /** command args in progress */
    uint8_t *command_args;
    uint32_t command_args_len;

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

    /* IMAP Mime decoding and file extraction */
    /** the list of files sent to the server */
    FileContainer *files_ts;
} IMAPState;

void RegisterIMAPParsers(void);
void IMAPParserRegisterTests(void);

#endif /* __APP_LAYER_IMAP_H__ */
