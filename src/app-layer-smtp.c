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

#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smtp.h"

#include "util-debug.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "conf.h"

#define SMTP_MAX_REQUEST_AND_REPLY_LINE_LENGTH 510

#define SMTP_COMMAND_BUFFER_STEPS 5

/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
#define SMTP_PARSER_STATE_COMMAND_MODE            0x00
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
#define SMTP_PARSER_STATE_COMMAND_DATA_MODE       0x01
/* Used when we are still in the process of parsing a server command.  Used
 * with multi-line replies and the stream is fragmented before all the lines
 * for a response is seen */
#define SMTP_PARSER_STATE_PARSING_SERVER_RESPONSE 0x02
/* Used to indicate that the parser has seen the first reply */
#define SMTP_PARSER_STATE_FIRST_REPLY_SEEN        0x04
/* Used to indicate that the parser is parsing a multiline reply */
#define SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY 0x08

/* Various SMTP commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed */
#define SMTP_COMMAND_STARTTLS  1
#define SMTP_COMMAND_DATA      2
#define SMTP_COMMAND_BDAT      3
/* not an actual command per se, but the mode where we accept the mail after
 * DATA has it's own reply code for completion, from the server.  We give this
 * stage a pseudo command of it's own, so that we can add this to the command
 * buffer to match with the reply */
#define SMTP_COMMAND_DATA_MODE 4
/* All other commands are represented by this var */
#define SMTP_COMMAND_OTHER_CMD 5

/* Different EHLO extensions.  Not used now. */
#define SMTP_EHLO_EXTENSION_PIPELINING
#define SMTP_EHLO_EXTENSION_SIZE
#define SMTP_EHLO_EXTENSION_DSN
#define SMTP_EHLO_EXTENSION_STARTTLS
#define SMTP_EHLO_EXTENSION_8BITMIME

//static void SMTPParserReset(void)
//{
//    return;
//}

/**
 * \internal
 * \brief Get the next line from input.  It doesn't do any length validation.
 *
 * \param state The smtp state.
 *
 * \retval  0 On suceess.
 * \retval -1 Either when we don't have any new lines to supply anymore or
 *            on failure.
 */
static int SMTPGetLine(SMTPState *state)
{
    /* we have run out of input */
    if (state->input_len <= 0)
        return -1;

    /* toserver */
    if (state->direction == 0) {
        if (state->ts_current_line_lf_seen == 1) {
            /* we have seen the lf for the previous line.  Clear the parser
             * details to parse new line */
            state->ts_current_line_lf_seen = 0;
            if (state->ts_current_line_db == 1) {
                state->ts_current_line_db = 0;
                SCFree(state->ts_db);
                state->ts_db = NULL;
                state->ts_db_len = 0;
                state->current_line = NULL;
                state->current_line_len = 0;
            }
        }

        uint8_t *lf_idx = memchr(state->input, 0x0a, state->input_len);

        if (lf_idx == NULL) {
            /* Fragmented line - set decoder event */
            if (state->ts_current_line_db == 0) {
                state->ts_db = SCMalloc(state->input_len);
                if (state->ts_db == NULL) {
                    return -1;
                }
                state->ts_current_line_db = 1;
                memcpy(state->ts_db, state->input, state->input_len);
                state->ts_db_len = state->input_len;
            } else {
                state->ts_db = SCRealloc(state->ts_db, (state->ts_db_len +
                                                        state->input_len));
                if (state->ts_db == NULL) {
                    return -1;
                }
                memcpy(state->ts_db + state->ts_db_len,
                       state->input, state->input_len);
                state->ts_db_len += state->input_len;
            } /* else */
            state->input += state->input_len;
            state->input_len = 0;

            return -1;

        } else {
            state->ts_current_line_lf_seen = 1;

            if (state->ts_current_line_db == 1) {
                state->ts_db = SCRealloc(state->ts_db,
                                         (state->ts_db_len +
                                          (lf_idx + 1 - state->input)));
                if (state->ts_db == NULL) {
                    return -1;
                }
                memcpy(state->ts_db + state->ts_db_len,
                       state->input, (lf_idx + 1 - state->input));
                state->ts_db_len += (lf_idx + 1 - state->input);

                if (state->ts_db_len > 1 &&
                    state->ts_db[state->ts_db_len - 2] == 0x0D) {
                    state->ts_db_len -= 2;
                    state->current_line_delimiter_len = 2;
                } else {
                    state->ts_db_len -= 1;
                    state->current_line_delimiter_len = 1;
                }

                state->current_line = state->ts_db;
                state->current_line_len = state->ts_db_len;

            } else {
                state->current_line = state->input;
                state->current_line_len = lf_idx - state->input;

                if (state->input != lf_idx &&
                    *(lf_idx - 1) == 0x0D) {
                    state->current_line_len--;
                    state->current_line_delimiter_len = 2;
                } else {
                    /* set decoder event for just LF delimiter */
                    state->current_line_delimiter_len = 1;
                }
            }

            state->input_len -= (lf_idx - state->input) + 1;
            state->input = (lf_idx + 1);

            return 0;
        }

        /* toclient */
    } else {
        if (state->tc_current_line_lf_seen == 1) {
            /* we have seen the lf for the previous line.  Clear the parser
             * details to parse new line */
            state->tc_current_line_lf_seen = 0;
            if (state->tc_current_line_db == 1) {
                state->tc_current_line_db = 0;
                SCFree(state->tc_db);
                state->tc_db = NULL;
                state->tc_db_len = 0;
                state->current_line = NULL;
                state->current_line_len = 0;
            }
        }

        uint8_t *lf_idx = memchr(state->input, 0x0a, state->input_len);

        if (lf_idx == NULL) {
            /* Fragmented line - set decoder event */
            if (state->tc_current_line_db == 0) {
                state->tc_db = SCMalloc(state->input_len);
                if (state->tc_db == NULL) {
                    return -1;
                }
                state->tc_current_line_db = 1;
                memcpy(state->tc_db, state->input, state->input_len);
                state->tc_db_len = state->input_len;
            } else {
                state->tc_db = SCRealloc(state->tc_db, (state->tc_db_len +
                                                        state->input_len));
                if (state->tc_db == NULL) {
                    return -1;
                }
                memcpy(state->tc_db + state->tc_db_len,
                       state->input, state->input_len);
                state->tc_db_len += state->input_len;
            } /* else */
            state->input += state->input_len;
            state->input_len = 0;

            return -1;

        } else {
            state->tc_current_line_lf_seen = 1;

            if (state->tc_current_line_db == 1) {
                state->tc_db = SCRealloc(state->tc_db,
                                         (state->tc_db_len +
                                          (lf_idx + 1 - state->input)));
                if (state->tc_db == NULL) {
                    return -1;
                }
                memcpy(state->tc_db + state->tc_db_len,
                       state->input, (lf_idx + 1 - state->input));
                state->tc_db_len += (lf_idx + 1 - state->input);

                if (state->tc_db_len > 1 &&
                    state->tc_db[state->tc_db_len - 2] == 0x0D) {
                    state->tc_db_len -= 2;
                    state->current_line_delimiter_len = 2;
                } else {
                    state->tc_db_len -= 1;
                    state->current_line_delimiter_len = 1;
                }

                state->current_line = state->tc_db;
                state->current_line_len = state->tc_db_len;

            } else {
                state->current_line = state->input;
                state->current_line_len = lf_idx - state->input;

                if (state->input != lf_idx &&
                    *(lf_idx - 1) == 0x0D) {
                    state->current_line_len--;
                    state->current_line_delimiter_len = 2;
                } else {
                    /* set decoder event for just LF delimiter */
                    state->current_line_delimiter_len = 1;
                }
            }

            state->input_len -= (lf_idx - state->input) + 1;
            state->input = (lf_idx + 1);

            return 0;
        } /* else - if (lf_idx == NULL) */
    }

}

static int SMTPInsertCommandIntoCommandBuffer(uint8_t command, SMTPState *state)
{
    if (state->cmds_cnt >= state->cmds_buffer_len) {
        int increment = SMTP_COMMAND_BUFFER_STEPS;
        if ((int)(state->cmds_buffer_len + SMTP_COMMAND_BUFFER_STEPS) > (int)USHRT_MAX) {
            increment = USHRT_MAX - state->cmds_buffer_len;
        }

        state->cmds = SCRealloc(state->cmds,
                                sizeof(uint8_t) *
                                (state->cmds_buffer_len +
                                 increment));
        if (state->cmds == NULL) {
            return -1;
        }
        state->cmds_buffer_len += increment;
    }
    if (state->cmds_cnt >= 1 &&
        ((state->cmds[state->cmds_cnt - 1] == SMTP_COMMAND_STARTTLS) ||
         (state->cmds[state->cmds_cnt - 1] == SMTP_COMMAND_DATA))) {
        /* decoder event */
        /* we have to have EHLO, DATA, VRFY, EXPN, TURN, QUIT, NOOP,
         * STARTTLS as the last command in pipelined mode */
    }

    /** \todo decoder event */
    if ((int)(state->cmds_cnt + 1) > (int)USHRT_MAX)
        return -1;

    state->cmds[state->cmds_cnt] = command;
    state->cmds_cnt++;

    return 0;
}

static int SMTPProcessCommandBDAT(SMTPState *state, Flow *f,
                                  AppLayerParserState *pstate)
{
    state->bdat_chunk_idx += (state->current_line_len +
                              state->current_line_delimiter_len);
    if (state->bdat_chunk_idx > state->bdat_chunk_len) {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        /* decoder event */
        return -1;
    } else if (state->bdat_chunk_idx == state->bdat_chunk_len) {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
    }

    return 0;
}

static int SMTPProcessCommandDATA(SMTPState *state, Flow *f,
                                   AppLayerParserState *pstate)
{
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        /* looks like are still waiting for a confirmination from the server */
        return 0;
    }

    if (state->current_line_len == 1 && state->current_line[0] == '.') {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        /* kinda like a hack.  The mail sent in DATA mode, would be
         * acknowledged with a reply.  We insert a dummy command to
         * the command buffer to be used by the reply handler to match
         * the reply received */
        SMTPInsertCommandIntoCommandBuffer(SMTP_COMMAND_DATA_MODE, state);
    }

    return 0;
}

static int SMTPProcessCommandSTARTTLS(SMTPState *state, Flow *f,
                                      AppLayerParserState *pstate)
{
    return 0;
}

static int SMTPProcessReply(SMTPState *state, Flow *f,
                            AppLayerParserState *pstate)
{
    uint64_t reply_code = 0;

    if (state->cmds_idx == state->cmds_cnt) {
        /* decoder event - unable to match reply with request */
        return -1;
    }

    /* the reply code has to contain at least 3 bytes, to hold the 3 digit
     * reply code */
    if (state->current_line_len < 3) {
        /* decoder event */
        return -1;
    }

    if (state->current_line_len >= 4) {
        if (state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY) {
            if (state->current_line[3] != '-') {
                state->parser_state &= ~SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY;
            }
        } else {
            if (state->current_line[3] == '-') {
                state->parser_state |= SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY;
            }
        }
    } else {
        if (state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY) {
            state->parser_state &= ~SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY;
        }
    }

    if (ByteExtractString(&reply_code, 10, 3,
                          (const char *)state->current_line) < 3) {
        /* decoder event */
        return -1;
    }

    /* kinda hack needed for us.  Our parser logs commands, to be
     * matched against server replies.  SMTP is normally accompanied by a
     * toclient welcome message, which would have had no command to
     * accompany it with.  And also alproto detection sees to it that the
     * toserver stream is the first one to be processed by the app layer.
     * Hence check the first reply and if it is a welcome message(220),
     * leave without matching it against any buffered command */
    if (!(state->parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        state->parser_state |= SMTP_PARSER_STATE_FIRST_REPLY_SEEN;
        if (reply_code == 220) {
            return 0;
        }
    }

    if (state->cmds[state->cmds_idx] == SMTP_COMMAND_STARTTLS) {
        if (reply_code == 220) {
            /* we are entering STARRTTLS data mode */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            pstate->flags |= APP_LAYER_PARSER_DONE;
            pstate->flags |= APP_LAYER_PARSER_NO_INSPECTION;
            pstate->flags |= APP_LAYER_PARSER_NO_REASSEMBLY;
        } else {
            /* decoder event */
        }
    } else if (state->cmds[state->cmds_idx] == SMTP_COMMAND_DATA) {
        if (reply_code == 354) {
            /* Next comes the mail for the DATA command in toserver direction */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else {
            /* decoder event */
        }
    } else {
        /* we don't care for any other command */
    }

    /* if it is a multiline reply, we need to move the index only once for all
     * the line of the reply.  We unset the multiline flag on the last
     * line of the multiline reply, following which we increment the index */
    if (!(state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY)) {
        state->cmds_idx++;
    }

    /* if we have matched all the buffered commands, reset the cnt and index */
    if (state->cmds_idx == state->cmds_cnt) {
        state->cmds_cnt = 0;
        state->cmds_idx = 0;
    }

    return 0;
}

static int SMTPParseCommandBDAT(SMTPState *state)
{
    int i = 4;
    while (i < state->current_line_len) {
        if (state->current_line[i] != ' ') {
            break;
        }
        i++;
    }
    if (i == 4) {
        /* decoder event */
        return -1;
    }
    if (i == state->current_line_len) {
        /* decoder event */
        return -1;
    }
    uint8_t *endptr = NULL;
    state->bdat_chunk_len = strtoul((const char *)state->current_line + i,
                                    (char **)&endptr, 10);
    if (endptr == state->current_line + i) {
        /* decoder event */
        return -1;
    }

    return 0;
}

static int SMTPProcessRequest(SMTPState *state, Flow *f,
                              AppLayerParserState *pstate)
{
    /* there are 2 commands that can push it into this COMMAND_DATA mode -
     * STARTTLS and DATA */
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        int r = 0;

        if (state->current_line_len >= 8 &&
            SCMemcmpLowercase("starttls", state->current_line, 8) == 0) {
            state->current_command = SMTP_COMMAND_STARTTLS;
        } else if (state->current_line_len >= 4 &&
                   SCMemcmpLowercase("data", state->current_line, 4) == 0) {
            state->current_command = SMTP_COMMAND_DATA;
        } else if (state->current_line_len >= 4 &&
                   SCMemcmpLowercase("bdat", state->current_line, 4) == 0) {
            r = SMTPParseCommandBDAT(state);
            if (r == -1)
                return -1;
            state->current_command = SMTP_COMMAND_BDAT;
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else {
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        }

        /* Every command is inserted into a command buffer, to be matched
         * against reply(ies) sent by the server */
        if (SMTPInsertCommandIntoCommandBuffer(state->current_command,
                                               state) == -1) {
            return -1;
        }

        return r;
    }

    switch (state->current_command) {
        case SMTP_COMMAND_STARTTLS:
            return SMTPProcessCommandSTARTTLS(state, f, pstate);

        case SMTP_COMMAND_DATA:
            return SMTPProcessCommandDATA(state, f, pstate);

        case SMTP_COMMAND_BDAT:
            return SMTPProcessCommandBDAT(state, f, pstate);

        default:
            /* we have nothing to do with any other command at this instant.
             * Just let it go through */
            return 0;
    }
}

static int SMTPParse(int direction, Flow *f, SMTPState *state,
                     AppLayerParserState *pstate, uint8_t *input,
                     uint32_t input_len, AppLayerParserResult *output)
{
    state->input = input;
    state->input_len = input_len;
    state->direction = direction;

    while (SMTPGetLine(state) >= 0) {
        /* toserver */
        if (direction == 0) {
            if (SMTPProcessRequest(state, f, pstate) == -1)
                return -1;

            /* toclient */
        } else {
            if (SMTPProcessReply(state, f, pstate) == -1)
                return -1;
        }
    }

    return 0;
}

static int SMTPParseClientRecord(Flow *f, void *alstate,
                                 AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 AppLayerParserResult *output)
{
    /* first arg 0 is toserver */
    return SMTPParse(0, f, alstate, pstate, input, input_len, output);
}

static int SMTPParseServerRecord(Flow *f, void *alstate,
                                 AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 AppLayerParserResult *output)
{
    /* first arg 1 is toclient */
    return SMTPParse(1, f, alstate, pstate, input, input_len, output);

    return 0;
}

/**
 * \internal
 * \brief Function to allocate SMTP state memory.
 */
static void *SMTPStateAlloc(void)
{
    SMTPState *smtp_state = SCMalloc(sizeof(SMTPState));
    if (smtp_state == NULL)
        return NULL;
    memset(smtp_state, 0, sizeof(SMTPState));

    smtp_state->cmds = SCMalloc(sizeof(uint8_t) *
                                SMTP_COMMAND_BUFFER_STEPS);
    if (smtp_state->cmds == NULL) {
        SCFree(smtp_state);
        return NULL;
    }
    smtp_state->cmds_buffer_len = SMTP_COMMAND_BUFFER_STEPS;

    return smtp_state;
}

/**
 * \internal
 * \brief Function to free SMTP state memory.
 */
static void SMTPStateFree(void *p)
{
    SMTPState *smtp_state = (SMTPState *)p;

    if (smtp_state->cmds != NULL) {
        SCFree(smtp_state->cmds);
    }
    if (smtp_state->ts_current_line_db) {
        SCFree(smtp_state->ts_db);
    }
    if (smtp_state->tc_current_line_db) {
        SCFree(smtp_state->tc_db);
    }

    SCFree(smtp_state);

    return;
}

/**
 * \brief Register the SMPT Protocol parser.
 */
void RegisterSMTPParsers(void)
{
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "EHLO", 4, 0,
                STREAM_TOSERVER);
    AlpProtoAdd(&alp_proto_ctx, IPPROTO_TCP, ALPROTO_SMTP, "HELO", 4, 0,
                STREAM_TOSERVER);

    AppLayerRegisterStateFuncs(ALPROTO_SMTP, SMTPStateAlloc, SMTPStateFree);

    AppLayerRegisterProto("smtp", ALPROTO_SMTP, STREAM_TOSERVER,
                          SMTPParseClientRecord);
    AppLayerRegisterProto("smtp", ALPROTO_SMTP, STREAM_TOCLIENT,
                          SMTPParseServerRecord);

    return;
}

/***************************************Unittests******************************/

/*
 * \test Test STARTTLS.
 */
int SMTPParserTest01(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 mx.google.com ESMTP d15sm986283wfl.6<CR><LF> */
    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x6d, 0x78, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x45, 0x53, 0x4d, 0x54, 0x50, 0x20,
        0x64, 0x31, 0x35, 0x73, 0x6d, 0x39, 0x38, 0x36,
        0x32, 0x38, 0x33, 0x77, 0x66, 0x6c, 0x2e, 0x36,
        0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO [192.168.0.158]<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x5b, 0x31, 0x39,
        0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e,
        0x31, 0x35, 0x38, 0x5d, 0x0d, 0x0a
    };
    uint32_t request1_len = sizeof(request1);
    /* 250-mx.google.com at your service, [117.198.115.50]<CR><LF>
     * 250-SIZE 35882577<CR><LF>
     * 250-8BITMIME<CR><LF>
     * 250-STARTTLS<CR><LF>
     * 250 ENHANCEDSTATUSCODES<CR><LF>
     */
    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x2d, 0x6d, 0x78, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x61, 0x74, 0x20, 0x79, 0x6f, 0x75,
        0x72, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
        0x65, 0x2c, 0x20, 0x5b, 0x31, 0x31, 0x37, 0x2e,
        0x31, 0x39, 0x38, 0x2e, 0x31, 0x31, 0x35, 0x2e,
        0x35, 0x30, 0x5d, 0x0d, 0x0a, 0x32, 0x35, 0x30,
        0x2d, 0x53, 0x49, 0x5a, 0x45, 0x20, 0x33, 0x35,
        0x38, 0x38, 0x32, 0x35, 0x37, 0x37, 0x0d, 0x0a,
        0x32, 0x35, 0x30, 0x2d, 0x38, 0x42, 0x49, 0x54,
        0x4d, 0x49, 0x4d, 0x45, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x53, 0x54, 0x41, 0x52, 0x54, 0x54,
        0x4c, 0x53, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x20,
        0x45, 0x4e, 0x48, 0x41, 0x4e, 0x43, 0x45, 0x44,
        0x53, 0x54, 0x41, 0x54, 0x55, 0x53, 0x43, 0x4f,
        0x44, 0x45, 0x53, 0x0d, 0x0a
    };
    uint32_t reply1_len = sizeof(reply1);

    /* STARTTLS<CR><LF> */
    uint8_t request2[] = {
        0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53,
        0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);
    /* 220 2.0.0 Ready to start TLS<CR><LF> */
    uint8_t reply2[] = {
        0x32, 0x32, 0x30, 0x20, 0x32, 0x2e, 0x30, 0x2e,
        0x30, 0x20, 0x52, 0x65, 0x61, 0x64, 0x79, 0x20,
        0x74, 0x6f, 0x20, 0x73, 0x74, 0x61, 0x72, 0x74,
        0x20, 0x54, 0x4c, 0x53, 0x0d, 0x0a
    };
    uint32_t reply2_len = sizeof(reply2);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION) ||
        !(f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        !(((TcpSession *)f.protoctx)->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        !(((TcpSession *)f.protoctx)->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Test multiple DATA commands(full mail transactions).
 */
int SMTPParserTest02(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 mx.google.com ESMTP d15sm986283wfl.6<CR><LF> */
    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x6d, 0x78, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x45, 0x53, 0x4d, 0x54, 0x50, 0x20,
        0x64, 0x31, 0x35, 0x73, 0x6d, 0x39, 0x38, 0x36,
        0x32, 0x38, 0x33, 0x77, 0x66, 0x6c, 0x2e, 0x36,
        0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request1_len = sizeof(request1);
    /* 250-mx.google.com at your service, [117.198.115.50]<CR><LF>
     * 250-SIZE 35882577<CR><LF>
     * 250-8BITMIME<CR><LF>
     * 250-STARTTLS<CR><LF>
     * 250 ENHANCEDSTATUSCODES<CR><LF>
     */
    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x2d, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x50, 0x49, 0x50,
        0x45, 0x4c, 0x49, 0x4e, 0x49, 0x4e, 0x47, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x49, 0x5a,
        0x45, 0x20, 0x31, 0x30, 0x32, 0x34, 0x30, 0x30,
        0x30, 0x30, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d,
        0x56, 0x52, 0x46, 0x59, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x45, 0x54, 0x52, 0x4e, 0x0d, 0x0a,
        0x32, 0x35, 0x30, 0x2d, 0x45, 0x4e, 0x48, 0x41,
        0x4e, 0x43, 0x45, 0x44, 0x53, 0x54, 0x41, 0x54,
        0x55, 0x53, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x38, 0x42, 0x49,
        0x54, 0x4d, 0x49, 0x4d, 0x45, 0x0d, 0x0a, 0x32,
        0x35, 0x30, 0x20, 0x44, 0x53, 0x4e, 0x0d, 0x0a
    };
    uint32_t reply1_len = sizeof(reply1);

    /* MAIL FROM:asdff@asdf.com<CR><LF> */
    uint8_t request2[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x61, 0x73, 0x64, 0x66, 0x66, 0x40,
        0x61, 0x73, 0x64, 0x66, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);
    /* 250 2.1.0 Ok<CR><LF> */
    uint8_t reply2[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply2_len = sizeof(reply2);

    /* RCPT TO:bimbs@gmail.com<CR><LF> */
    uint8_t request3[] = {
        0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a,
        0x62, 0x69, 0x6d, 0x62, 0x73, 0x40, 0x67, 0x6d,
        0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
        0x0a
    };
    uint32_t request3_len = sizeof(request3);
    /* 250 2.1.5 Ok<CR><LF> */
    uint8_t reply3[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x35, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply3_len = sizeof(reply3);

    /* DATA<CR><LF> */
    uint8_t request4[] = {
        0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a
    };
    uint32_t request4_len = sizeof(request4);
    /* 354 End data with <CR><LF>.<CR><LF>|<CR><LF>| */
    uint8_t reply4[] = {
        0x33, 0x35, 0x34, 0x20, 0x45, 0x6e, 0x64, 0x20,
        0x64, 0x61, 0x74, 0x61, 0x20, 0x77, 0x69, 0x74,
        0x68, 0x20, 0x3c, 0x43, 0x52, 0x3e, 0x3c, 0x4c,
        0x46, 0x3e, 0x2e, 0x3c, 0x43, 0x52, 0x3e, 0x3c,
        0x4c, 0x46, 0x3e, 0x0d, 0x0a
    };
    uint32_t reply4_len = sizeof(reply4);

    /* FROM:asdff@asdf.com<CR><LF> */
    uint8_t request5_1[] = {
        0x46, 0x52, 0x4f, 0x4d, 0x3a, 0x61, 0x73, 0x64,
        0x66, 0x66, 0x40, 0x61, 0x73, 0x64, 0x66, 0x2e,
        0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request5_1_len = sizeof(request5_1);
    /* TO:bimbs@gmail.com<CR><LF> */
    uint8_t request5_2[] = {
        0x54, 0x4f, 0x3a, 0x62, 0x69, 0x6d, 0x62, 0x73,
        0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63,
        0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request5_2_len = sizeof(request5_2);
    /* <CR><LF> */
    uint8_t request5_3[] = {
        0x0d, 0x0a
    };
    uint32_t request5_3_len = sizeof(request5_3);
    /* this is test mail1<CR><LF> */
    uint8_t request5_4[] = {
        0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x61, 0x69,
        0x6c, 0x31, 0x0d, 0x0a
    };
    uint32_t request5_4_len = sizeof(request5_4);
    /* .<CR><LF> */
    uint8_t request5_5[] = {
        0x2e, 0x0d, 0x0a
    };
    uint32_t request5_5_len = sizeof(request5_5);
    /* 250 2.0.0 Ok: queued as 6A1AF20BF2<CR><LF> */
    uint8_t reply5[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x30, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x3a, 0x20, 0x71, 0x75,
        0x65, 0x75, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20,
        0x36, 0x41, 0x31, 0x41, 0x46, 0x32, 0x30, 0x42,
        0x46, 0x32, 0x0d, 0x0a
    };
    uint32_t reply5_len = sizeof(reply5);

    /* MAIL FROM:asdfg@asdf.com<CR><LF> */
    uint8_t request6[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x61, 0x73, 0x64, 0x66, 0x67, 0x40,
        0x61, 0x73, 0x64, 0x66, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a
    };
    uint32_t request6_len = sizeof(request6);
    /* 250 2.1.0 Ok<CR><LF> */
    uint8_t reply6[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply6_len = sizeof(reply6);

    /* RCPT TO:bimbs@gmail.com<CR><LF> */
    uint8_t request7[] = {
        0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a,
        0x62, 0x69, 0x6d, 0x62, 0x73, 0x40, 0x67, 0x6d,
        0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
        0x0a
    };
    uint32_t request7_len = sizeof(request7);
    /* 250 2.1.5 Ok<CR><LF> */
    uint8_t reply7[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x35, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply7_len = sizeof(reply7);

    /* DATA<CR><LF> */
    uint8_t request8[] = {
        0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a
    };
    uint32_t request8_len = sizeof(request8);
    /* 354 End data with <CR><LF>.<CR><LF>|<CR><LF>| */
    uint8_t reply8[] = {
        0x33, 0x35, 0x34, 0x20, 0x45, 0x6e, 0x64, 0x20,
        0x64, 0x61, 0x74, 0x61, 0x20, 0x77, 0x69, 0x74,
        0x68, 0x20, 0x3c, 0x43, 0x52, 0x3e, 0x3c, 0x4c,
        0x46, 0x3e, 0x2e, 0x3c, 0x43, 0x52, 0x3e, 0x3c,
        0x4c, 0x46, 0x3e, 0x0d, 0x0a
    };
    uint32_t reply8_len = sizeof(reply8);

    /* FROM:asdfg@gmail.com<CR><LF> */
    uint8_t request9_1[] = {
        0x46, 0x52, 0x4f, 0x4d, 0x3a, 0x61, 0x73, 0x64,
        0x66, 0x67, 0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request9_1_len = sizeof(request9_1);
    /* TO:bimbs@gmail.com<CR><LF> */
    uint8_t request9_2[] = {
        0x54, 0x4f, 0x3a, 0x62, 0x69, 0x6d, 0x62, 0x73,
        0x40, 0x67, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63,
        0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request9_2_len = sizeof(request9_2);
    /* <CR><LF> */
    uint8_t request9_3[] = {
        0x0d, 0x0a
    };
    uint32_t request9_3_len = sizeof(request9_3);
    /* this is test mail2<CR><LF> */
    uint8_t request9_4[] = {
        0x74, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x74, 0x65, 0x73, 0x74, 0x20, 0x6d, 0x61, 0x69,
        0x6c, 0x32, 0x0d, 0x0a
    };
    uint32_t request9_4_len = sizeof(request9_4);
    /* .<CR><LF> */
    uint8_t request9_5[] = {
        0x2e, 0x0d, 0x0a
    };
    uint32_t request9_5_len = sizeof(request9_5);
    /* 250 2.0.0 Ok: queued as 28CFF20BF2<CR><LF> */
    uint8_t reply9[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x30, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x3a, 0x20, 0x71, 0x75,
        0x65, 0x75, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20,
        0x32, 0x38, 0x43, 0x46, 0x46, 0x32, 0x30, 0x42,
        0x46, 0x32, 0x0d, 0x0a
    };
    uint32_t reply9_len = sizeof(reply9);

    /* QUIT<CR><LF> */
    uint8_t request10[] = {
        0x51, 0x55, 0x49, 0x54, 0x0d, 0x0a
    };
    uint32_t request10_len = sizeof(request10);
    /* 221 2.0.0 Bye<CR><LF> */
    uint8_t reply10[] = {
        0x32, 0x32, 0x31, 0x20, 0x32, 0x2e, 0x30, 0x2e,
        0x30, 0x20, 0x42, 0x79, 0x65, 0x0d, 0x0a
    };
    uint32_t reply10_len = sizeof(reply10);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply4, reply4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5_1, request5_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5_2, request5_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5_3, request5_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5_4, request5_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5_5, request5_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply5, reply5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply6, reply6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request7, request7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply7, reply7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request8, request8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply8, reply8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request9_1, request9_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request9_2, request9_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request9_3, request9_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request9_4, request9_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request9_5, request9_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply9, reply9_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request10, request10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply10, reply10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Testing parsing pipelined commands.
 */
int SMTPParserTest03(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 poona_slack_vm1.localdomain ESMTP Postfix<CR><LF> */
    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20,
        0x45, 0x53, 0x4d, 0x54, 0x50, 0x20, 0x50, 0x6f,
        0x73, 0x74, 0x66, 0x69, 0x78, 0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0a
    };
    uint32_t request1_len = sizeof(request1);
    /* 250-poona_slack_vm1.localdomain<CR><LF>
     * 250-PIPELINING<CR><LF>
     * 250-SIZE 10240000<CR><LF>
     * 250-VRFY<CR><LF>
     * 250-ETRN<CR><LF>
     * 250-ENHANCEDSTATUSCODES<CR><LF>
     * 250-8BITMIME<CR><LF>
     * 250 DSN<CR><LF>
     */
    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x2d, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x50, 0x49, 0x50,
        0x45, 0x4c, 0x49, 0x4e, 0x49, 0x4e, 0x47, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x49, 0x5a,
        0x45, 0x20, 0x31, 0x30, 0x32, 0x34, 0x30, 0x30,
        0x30, 0x30, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d,
        0x56, 0x52, 0x46, 0x59, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x45, 0x54, 0x52, 0x4e, 0x0d, 0x0a,
        0x32, 0x35, 0x30, 0x2d, 0x45, 0x4e, 0x48, 0x41,
        0x4e, 0x43, 0x45, 0x44, 0x53, 0x54, 0x41, 0x54,
        0x55, 0x53, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x38, 0x42, 0x49,
        0x54, 0x4d, 0x49, 0x4d, 0x45, 0x0d, 0x0a, 0x32,
        0x35, 0x30, 0x20, 0x44, 0x53, 0x4e, 0x0d, 0x0a
    };
    uint32_t reply1_len = sizeof(reply1);

    /* MAIL FROM:pbsf@asdfs.com<CR><LF>
     * RCPT TO:pbsf@asdfs.com<CR><LF>
     * DATA<CR><LF>
     */
    uint8_t request2[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x52, 0x43, 0x50, 0x54, 0x20, 0x54,
        0x4f, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);
    /* 250 2.1.0 Ok<CR><LF>
     * 250 2.1.5 Ok<CR><LF>
     * 354 End data with <CR><LF>.<CR><LF>|<CR><LF>|
     */
    uint8_t reply2[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e, 0x35, 0x20,
        0x4f, 0x6b, 0x0d, 0x0a, 0x33, 0x35, 0x34, 0x20,
        0x45, 0x6e, 0x64, 0x20, 0x64, 0x61, 0x74, 0x61,
        0x20, 0x77, 0x69, 0x74, 0x68, 0x20, 0x3c, 0x43,
        0x52, 0x3e, 0x3c, 0x4c, 0x46, 0x3e, 0x2e, 0x3c,
        0x43, 0x52, 0x3e, 0x3c, 0x4c, 0x46, 0x3e, 0x0d,
        0x0a
    };
    uint32_t reply2_len = sizeof(reply2);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 3 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->cmds[1] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->cmds[2] != SMTP_COMMAND_DATA ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test smtp with just <LF> delimter instead of <CR><LF>.
 */
int SMTPParserTest04(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 poona_slack_vm1.localdomain ESMTP Postfix<CR><LF> */
    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20,
        0x45, 0x53, 0x4d, 0x54, 0x50, 0x20, 0x50, 0x6f,
        0x73, 0x74, 0x66, 0x69, 0x78, 0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x32, 0x32, 0x30, 0x20, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20,
        0x45, 0x53, 0x4d, 0x54, 0x50, 0x20, 0x50, 0x6f,
        0x73, 0x74, 0x66, 0x69, 0x78, 0x0d, 0x0a
    };
    uint32_t request1_len = sizeof(request1);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test STARTTLS fail.
 */
int SMTPParserTest05(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 poona_slack_vm1.localdomain ESMTP Postfix<CR><LF> */
    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x20,
        0x45, 0x53, 0x4d, 0x54, 0x50, 0x20, 0x50, 0x6f,
        0x73, 0x74, 0x66, 0x69, 0x78, 0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    uint32_t request1_len = sizeof(request1);
    /* 250-poona_slack_vm1.localdomain<CR><LF>
     * 250-PIPELINING<CR><LF>
     * 250-SIZE 10240000<CR><LF>
     * 250-VRFY<CR><LF>
     * 250-ETRN<CR><LF>
     * 250-ENHANCEDSTATUSCODES<CR><LF>
     * 250-8BITMIME<CR><LF>
     * 250 DSN<CR><LF>
     */
    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x2d, 0x70, 0x6f, 0x6f, 0x6e,
        0x61, 0x5f, 0x73, 0x6c, 0x61, 0x63, 0x6b, 0x5f,
        0x76, 0x6d, 0x31, 0x2e, 0x6c, 0x6f, 0x63, 0x61,
        0x6c, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x50, 0x49, 0x50,
        0x45, 0x4c, 0x49, 0x4e, 0x49, 0x4e, 0x47, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53, 0x49, 0x5a,
        0x45, 0x20, 0x31, 0x30, 0x32, 0x34, 0x30, 0x30,
        0x30, 0x30, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d,
        0x56, 0x52, 0x46, 0x59, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x45, 0x54, 0x52, 0x4e, 0x0d, 0x0a,
        0x32, 0x35, 0x30, 0x2d, 0x45, 0x4e, 0x48, 0x41,
        0x4e, 0x43, 0x45, 0x44, 0x53, 0x54, 0x41, 0x54,
        0x55, 0x53, 0x43, 0x4f, 0x44, 0x45, 0x53, 0x0d,
        0x0a, 0x32, 0x35, 0x30, 0x2d, 0x38, 0x42, 0x49,
        0x54, 0x4d, 0x49, 0x4d, 0x45, 0x0d, 0x0a, 0x32,
        0x35, 0x30, 0x20, 0x44, 0x53, 0x4e, 0x0d, 0x0a
    };
    uint32_t reply1_len = sizeof(reply1);

    /* STARTTLS<CR><LF> */
    uint8_t request2[] = {
        0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53,
        0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);
    /* 502 5.5.2 Error: command not recognized<CR><LF> */
    uint8_t reply2[] = {
        0x35, 0x30, 0x32, 0x20, 0x35, 0x2e, 0x35, 0x2e,
        0x32, 0x20, 0x45, 0x72, 0x72, 0x6f, 0x72, 0x3a,
        0x20, 0x63, 0x6f, 0x6d, 0x6d, 0x61, 0x6e, 0x64,
        0x20, 0x6e, 0x6f, 0x74, 0x20, 0x72, 0x65, 0x63,
        0x6f, 0x67, 0x6e, 0x69, 0x7a, 0x65, 0x64, 0x0d,
        0x0a
    };
    uint32_t reply2_len = sizeof(reply2);

    /* QUIT<CR><LF> */
    uint8_t request3[] = {
        0x51, 0x55, 0x49, 0x54, 0x0d, 0x0a

    };
    uint32_t request3_len = sizeof(request3);
    /* 221 2.0.0 Bye<CR><LF> */
    uint8_t reply3[] = {
        0x32, 0x32, 0x31, 0x20, 0x32, 0x2e, 0x30, 0x2e,
        0x30, 0x20, 0x42, 0x79, 0x65, 0x0d, 0x0a
    };
    uint32_t reply3_len = sizeof(reply3);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if ((f.flags & FLOW_NOPAYLOAD_INSPECTION) ||
        (f.flags & FLOW_NO_APPLAYER_INSPECTION) ||
        (((TcpSession *)f.protoctx)->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (((TcpSession *)f.protoctx)->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Test multiple DATA commands(full mail transactions).
 */
int SMTPParserTest06(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    uint8_t welcome_reply[] = {
        0x32, 0x32, 0x30, 0x20, 0x62, 0x61, 0x79, 0x30,
        0x2d, 0x6d, 0x63, 0x36, 0x2d, 0x66, 0x31, 0x30,
        0x2e, 0x62, 0x61, 0x79, 0x30, 0x2e, 0x68, 0x6f,
        0x74, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x53, 0x65, 0x6e, 0x64, 0x69, 0x6e,
        0x67, 0x20, 0x75, 0x6e, 0x73, 0x6f, 0x6c, 0x69,
        0x63, 0x69, 0x74, 0x65, 0x64, 0x20, 0x63, 0x6f,
        0x6d, 0x6d, 0x65, 0x72, 0x63, 0x69, 0x61, 0x6c,
        0x20, 0x6f, 0x72, 0x20, 0x62, 0x75, 0x6c, 0x6b,
        0x20, 0x65, 0x2d, 0x6d, 0x61, 0x69, 0x6c, 0x20,
        0x74, 0x6f, 0x20, 0x4d, 0x69, 0x63, 0x72, 0x6f,
        0x73, 0x6f, 0x66, 0x74, 0x27, 0x73, 0x20, 0x63,
        0x6f, 0x6d, 0x70, 0x75, 0x74, 0x65, 0x72, 0x20,
        0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x20,
        0x69, 0x73, 0x20, 0x70, 0x72, 0x6f, 0x68, 0x69,
        0x62, 0x69, 0x74, 0x65, 0x64, 0x2e, 0x20, 0x4f,
        0x74, 0x68, 0x65, 0x72, 0x20, 0x72, 0x65, 0x73,
        0x74, 0x72, 0x69, 0x63, 0x74, 0x69, 0x6f, 0x6e,
        0x73, 0x20, 0x61, 0x72, 0x65, 0x20, 0x66, 0x6f,
        0x75, 0x6e, 0x64, 0x20, 0x61, 0x74, 0x20, 0x68,
        0x74, 0x74, 0x70, 0x3a, 0x2f, 0x2f, 0x70, 0x72,
        0x69, 0x76, 0x61, 0x63, 0x79, 0x2e, 0x6d, 0x73,
        0x6e, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x41, 0x6e,
        0x74, 0x69, 0x2d, 0x73, 0x70, 0x61, 0x6d, 0x2f,
        0x2e, 0x20, 0x56, 0x69, 0x6f, 0x6c, 0x61, 0x74,
        0x69, 0x6f, 0x6e, 0x73, 0x20, 0x77, 0x69, 0x6c,
        0x6c, 0x20, 0x72, 0x65, 0x73, 0x75, 0x6c, 0x74,
        0x20, 0x69, 0x6e, 0x20, 0x75, 0x73, 0x65, 0x20,
        0x6f, 0x66, 0x20, 0x65, 0x71, 0x75, 0x69, 0x70,
        0x6d, 0x65, 0x6e, 0x74, 0x20, 0x6c, 0x6f, 0x63,
        0x61, 0x74, 0x65, 0x64, 0x20, 0x69, 0x6e, 0x20,
        0x43, 0x61, 0x6c, 0x69, 0x66, 0x6f, 0x72, 0x6e,
        0x69, 0x61, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x6f,
        0x74, 0x68, 0x65, 0x72, 0x20, 0x73, 0x74, 0x61,
        0x74, 0x65, 0x73, 0x2e, 0x20, 0x46, 0x72, 0x69,
        0x2c, 0x20, 0x31, 0x36, 0x20, 0x46, 0x65, 0x62,
        0x20, 0x32, 0x30, 0x30, 0x37, 0x20, 0x30, 0x35,
        0x3a, 0x30, 0x33, 0x3a, 0x32, 0x33, 0x20, 0x2d,
        0x30, 0x38, 0x30, 0x30, 0x20, 0x0d, 0x0a
    };
    uint32_t welcome_reply_len = sizeof(welcome_reply);

    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x45, 0x58, 0x43,
        0x48, 0x41, 0x4e, 0x47, 0x45, 0x32, 0x2e, 0x63,
        0x67, 0x63, 0x65, 0x6e, 0x74, 0x2e, 0x6d, 0x69,
        0x61, 0x6d, 0x69, 0x2e, 0x65, 0x64, 0x75, 0x0d,
        0x0a
    };
    uint32_t request1_len = sizeof(request1);

    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x2d, 0x62, 0x61, 0x79, 0x30,
        0x2d, 0x6d, 0x63, 0x36, 0x2d, 0x66, 0x31, 0x30,
        0x2e, 0x62, 0x61, 0x79, 0x30, 0x2e, 0x68, 0x6f,
        0x74, 0x6d, 0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f,
        0x6d, 0x20, 0x28, 0x33, 0x2e, 0x33, 0x2e, 0x31,
        0x2e, 0x34, 0x29, 0x20, 0x48, 0x65, 0x6c, 0x6c,
        0x6f, 0x20, 0x5b, 0x31, 0x32, 0x39, 0x2e, 0x31,
        0x37, 0x31, 0x2e, 0x33, 0x32, 0x2e, 0x35, 0x39,
        0x5d, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x53,
        0x49, 0x5a, 0x45, 0x20, 0x32, 0x39, 0x36, 0x39,
        0x36, 0x30, 0x30, 0x30, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x50, 0x49, 0x50, 0x45, 0x4c, 0x49,
        0x4e, 0x49, 0x4e, 0x47, 0x0d, 0x0a, 0x32, 0x35,
        0x30, 0x2d, 0x38, 0x62, 0x69, 0x74, 0x6d, 0x69,
        0x6d, 0x65, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d,
        0x42, 0x49, 0x4e, 0x41, 0x52, 0x59, 0x4d, 0x49,
        0x4d, 0x45, 0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d,
        0x43, 0x48, 0x55, 0x4e, 0x4b, 0x49, 0x4e, 0x47,
        0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x41, 0x55,
        0x54, 0x48, 0x20, 0x4c, 0x4f, 0x47, 0x49, 0x4e,
        0x0d, 0x0a, 0x32, 0x35, 0x30, 0x2d, 0x41, 0x55,
        0x54, 0x48, 0x3d, 0x4c, 0x4f, 0x47, 0x49, 0x4e,
        0x0d, 0x0a, 0x32, 0x35, 0x30, 0x20, 0x4f, 0x4b,
        0x0d, 0x0a
    };
    uint32_t reply1_len = sizeof(reply1);

    /* MAIL FROM:asdff@asdf.com<CR><LF> */
    uint8_t request2[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x61, 0x73, 0x64, 0x66, 0x66, 0x40,
        0x61, 0x73, 0x64, 0x66, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);
    /* 250 2.1.0 Ok<CR><LF> */
    uint8_t reply2[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x30, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply2_len = sizeof(reply2);

    /* RCPT TO:bimbs@gmail.com<CR><LF> */
    uint8_t request3[] = {
        0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a,
        0x62, 0x69, 0x6d, 0x62, 0x73, 0x40, 0x67, 0x6d,
        0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
        0x0a
    };
    uint32_t request3_len = sizeof(request3);
    /* 250 2.1.5 Ok<CR><LF> */
    uint8_t reply3[] = {
        0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
        0x35, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    uint32_t reply3_len = sizeof(reply3);

    /* BDAT 51<CR><LF> */
    uint8_t request4[] = {
        0x42, 0x44, 0x41, 0x54, 0x20, 0x35, 0x31, 0x0d,
        0x0a,
    };
    uint32_t request4_len = sizeof(request4);

    uint8_t request5[] = {
        0x46, 0x52, 0x4f, 0x4d, 0x3a, 0x61, 0x73, 0x64,
        0x66, 0x66, 0x40, 0x61, 0x73, 0x64, 0x66, 0x2e,
        0x66, 0x66, 0x40, 0x61, 0x73, 0x64, 0x66, 0x2e,
        0x66, 0x66, 0x40, 0x61, 0x73, 0x64, 0x0d, 0x0a,
    };
    uint32_t request5_len = sizeof(request5);

    uint8_t request6[] = {
        0x46, 0x52, 0x4f, 0x4d, 0x3a, 0x61, 0x73, 0x64,
        0x66, 0x66, 0x40, 0x61, 0x73, 0x64, 0x66, 0x2e,
        0x66, 0x0d, 0x0a,
    };
    uint32_t request6_len = sizeof(request6);

    TcpSession ssn;

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;

    StreamTcpInitConfig(TRUE);
    FlowL7DataPtrInit(&f);

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.aldata[AlpGetStateIdx(ALPROTO_SMTP)];
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOCLIENT,
                      reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_BDAT ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE) ||
        smtp_state->bdat_chunk_len != 51 ||
        smtp_state->bdat_chunk_idx != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request5, request5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE) ||
        smtp_state->bdat_chunk_len != 51 ||
        smtp_state->bdat_chunk_idx != 32) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParse(&f, ALPROTO_SMTP, STREAM_TOSERVER,
                      request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN ||
        smtp_state->bdat_chunk_len != 51 ||
        smtp_state->bdat_chunk_idx != 51) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    FlowL7DataPtrFree(&f);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

void SMTPParserRegisterTests(void)
{
    UtRegisterTest("SMTPParserTest01", SMTPParserTest01, 1);
    UtRegisterTest("SMTPParserTest02", SMTPParserTest02, 1);
    UtRegisterTest("SMTPParserTest03", SMTPParserTest03, 1);
    UtRegisterTest("SMTPParserTest04", SMTPParserTest04, 1);
    UtRegisterTest("SMTPParserTest05", SMTPParserTest05, 1);
    UtRegisterTest("SMTPParserTest06", SMTPParserTest06, 1);
    return;
}
