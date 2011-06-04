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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __APP_LAYER_SMTP_H__
#define __APP_LAYER_SMTP_H__

typedef struct SMTPState_ {
    /* current input that is being parsed */
    uint8_t *input;
    uint32_t input_len;

    /* --parser details-- */
    /* current line extracted by the parser from the call to SMTPGetline() */
    uint8_t *current_line;
    /* length of the line in current_line.  Doesn't include the delimiter */
    uint32_t current_line_len;
    /* used to indicate if the current_line buffer is a malloced buffer.  We
     * use a malloced buffer, if a line is fragmented */
    uint8_t current_line_buffer_dynamic;
    /* we have see LF for the currently parsed line */
    uint8_t current_line_lf_seen;
    /* var to indicate parser state */
    uint8_t parser_state;
    /* current command in progress */
    uint8_t current_command;

    /* the request commands are store here and the reply handler uses these
     * stored command in the buffer to match the reply(ies) with the command */
    /* the command buffer */
    uint8_t *cmds;
    /* the buffer length */
    uint8_t cmds_buffer_len;
    /* no of commands stored in the above buffer */
    uint8_t cmds_cnt;
    /* index of the command in the buffer, currently in inspection by reply
     * handler */
    uint8_t cmds_idx;
    /* padding - you can replace this if you want to. */
    uint8_t pad;
} SMTPState;

void RegisterSMTPParsers(void);
void SMTPParserRegisterTests(void);

#endif /* __APP_LAYER_SMTP_H__ */
