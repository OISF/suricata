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

#ifndef __APP_LAYER_POP3_H__
#define __APP_LAYER_POP3_H__

#include "decode-events.h"
#include "util-decode-mime.h"

enum {
    POP3_DECODER_EVENT_INVALID_REPLY,
    POP3_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST,
    POP3_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED,
    POP3_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED,
    POP3_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE,
    POP3_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED,
    POP3_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE,
    POP3_DECODER_EVENT_TLS_REJECTED,
    POP3_DECODER_EVENT_DATA_COMMAND_REJECTED,

    /* MIME Events */
    POP3_DECODER_EVENT_MIME_PARSE_FAILED,
    POP3_DECODER_EVENT_MIME_MALFORMED_MSG,
    POP3_DECODER_EVENT_MIME_INVALID_BASE64,
    POP3_DECODER_EVENT_MIME_INVALID_QP,
    POP3_DECODER_EVENT_MIME_LONG_LINE,
    POP3_DECODER_EVENT_MIME_LONG_ENC_LINE,
    POP3_DECODER_EVENT_MIME_LONG_HEADER_NAME,
    POP3_DECODER_EVENT_MIME_LONG_HEADER_VALUE,
};

typedef struct POP3Transaction_ {
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

    TAILQ_ENTRY(POP3Transaction_) next;
} POP3Transaction;

typedef struct POP3State_ {
    POP3Transaction *curr_tx;
    TAILQ_HEAD(, POP3Transaction_) tx_list;  /**< transaction list */
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

    /* POP3 Mime decoding and file extraction */
    /** the list of files sent to the server */
    FileContainer *files_ts;
} POP3State;

void RegisterPOP3Parsers(void);
void POP3ParserRegisterTests(void);

#endif /* __APP_LAYER_POP3_H__ */
