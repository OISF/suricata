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

enum {
    SMTP_DECODER_EVENT_INVALID_REPLY,
    SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST,
    SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE,
    SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED,
    SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE,
    SMTP_DECODER_EVENT_TLS_REJECTED,
    SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED
};

typedef struct SMTPState_ {
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

    /** buffer for bytes that make up the header */
    uint8_t *header_bytes;
    /** size of the bytes used */
    size_t header_size;
    /** number of bytes allocated for the header */
    size_t header_allocated;

    /** keeps track of how much of header_bytes is really the header */
    size_t header_portion;

    /** htp config needed to init multi-part config */
    htp_cfg_t *mpartp_config;
    /** multi-part parser config */
    htp_mpartp_t* mpartp_parser;

    /** status from finding the boundary */
    htp_status_t find_boundary_status;

    /** status from the last add to the multi-part */
    htp_status_t last_mpart_parse_status;

    /** status from the call to finalize if any */
    htp_status_t finalize_status;

    htp_table_t *mail_header;

    /** holds the content of the from field */
    uint8_t *from;

    /** holds an array of the to fields */
    uint8_t **to;

    /** holds the length of the to fields */
    size_t to_len;

    /** holds the length of the to fields allocated */
    size_t to_len_allocated;

} SMTPState;

void RegisterSMTPParsers(void);
void SMTPParserRegisterTests(void);

#endif /* __APP_LAYER_SMTP_H__ */

