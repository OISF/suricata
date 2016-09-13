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
#include "app-layer-pop3.h"

#include "util-mpm.h"
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

#include "decode-events.h"
#include "conf.h"

#define POP3_MAX_REQUEST_AND_REPLY_LINE_LENGTH 510

#define POP3_COMMAND_BUFFER_STEPS 5

/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
#define POP3_PARSER_STATE_COMMAND_MODE            0x00
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
#define POP3_PARSER_STATE_COMMAND_DATA_MODE       0x01
/* Used when we are still in the process of parsing a server command.  Used
 * with multi-line replies and the stream is fragmented before all the lines
 * for a response is seen */
#define POP3_PARSER_STATE_PARSING_SERVER_RESPONSE 0x02
/* Used to indicate that the parser has seen the first reply */
#define POP3_PARSER_STATE_FIRST_REPLY_SEEN        0x04
/* Used to indicate that the parser is parsing a multiline reply */
#define POP3_PARSER_STATE_PARSING_MULTILINE_REPLY 0x08

/* Various POP3 commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed */
#define POP3_COMMAND_USER      1
#define POP3_COMMAND_RETR      2
/* not an actual command per se, but the mode where we accept the mail after
 * DATA has it's own reply code for completion, from the server.  We give this
 * stage a pseudo command of it's own, so that we can add this to the command
 * buffer to match with the reply */
#define POP3_COMMAND_DATA_MODE 4
/* All other commands are represented by this var */
#define POP3_COMMAND_OTHER_CMD 5

SCEnumCharMap pop3_decoder_event_table[ ] = {
    { "INVALID_REPLY",           POP3_DECODER_EVENT_INVALID_REPLY },
    { "UNABLE_TO_MATCH_REPLY_WITH_REQUEST",
      POP3_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST },
    { "MAX_COMMAND_LINE_LEN_EXCEEDED",
      POP3_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED },
    { "MAX_REPLY_LINE_LEN_EXCEEDED",
      POP3_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED },
    { "INVALID_PIPELINED_SEQUENCE",
      POP3_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE },
    { "BDAT_CHUNK_LEN_EXCEEDED",
      POP3_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED },
    { "NO_SERVER_WELCOME_MESSAGE",
      POP3_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE },
    { "TLS_REJECTED",
      POP3_DECODER_EVENT_TLS_REJECTED },
    { "DATA_COMMAND_REJECTED",
      POP3_DECODER_EVENT_DATA_COMMAND_REJECTED },

    /* MIME Events */
    { "MIME_PARSE_FAILED",
      POP3_DECODER_EVENT_MIME_PARSE_FAILED },
    { "MIME_MALFORMED_MSG",
      POP3_DECODER_EVENT_MIME_MALFORMED_MSG },
    { "MIME_INVALID_BASE64",
      POP3_DECODER_EVENT_MIME_INVALID_BASE64 },
    { "MIME_INVALID_QP",
      POP3_DECODER_EVENT_MIME_INVALID_QP },
    { "MIME_LONG_LINE",
      POP3_DECODER_EVENT_MIME_LONG_LINE },
    { "MIME_LONG_ENC_LINE",
      POP3_DECODER_EVENT_MIME_LONG_ENC_LINE },
    { "MIME_LONG_HEADER_NAME",
      POP3_DECODER_EVENT_MIME_LONG_HEADER_NAME },
    { "MIME_LONG_HEADER_VALUE",
      POP3_DECODER_EVENT_MIME_LONG_HEADER_VALUE },

    { NULL,                      -1 },
};

typedef struct POP3Config {

    int decode_mime;
    MimeDecConfig mime_config;
    uint32_t content_limit;
    uint32_t content_inspect_min_size;
    uint32_t content_inspect_window;

    StreamingBufferConfig sbcfg;
} POP3Config;

/* Create POP3 config structure */
static POP3Config pop3_config = { 0, { 0, 0, 0, 0, 0 }, 0, 0, 0, STREAMING_BUFFER_CONFIG_INITIALIZER };

/**
 * \brief Configure POP3 Mime Decoder by parsing out 'pop3-mime' section of YAML
 * config file
 *
 * \return none
 */
static void POP3Configure(void) {

    SCEnter();
    int ret = 0, val;
    intmax_t imval;

    ConfNode *config = ConfGetNode("app-layer.protocols.pop3.mime");
    if (config != NULL) {

        ret = ConfGetChildValueBool(config, "decode-mime", &val);
        if (ret) {
            pop3_config.decode_mime = val;
        }

        ret = ConfGetChildValueBool(config, "decode-base64", &val);
        if (ret) {
            pop3_config.mime_config.decode_base64 = val;
        }

        ret = ConfGetChildValueBool(config, "decode-quoted-printable", &val);
        if (ret) {
            pop3_config.mime_config.decode_quoted_printable = val;
        }

        ret = ConfGetChildValueInt(config, "header-value-depth", &imval);
        if (ret) {
            pop3_config.mime_config.header_value_depth = (uint32_t) imval;
        }

        ret = ConfGetChildValueBool(config, "extract-urls", &val);
        if (ret) {
            pop3_config.mime_config.extract_urls = val;
        }
    }

    /* Pass mime config data to MimeDec API */
    MimeDecSetConfig(&pop3_config.mime_config);

    SCReturn;
}

static POP3Transaction *POP3TransactionCreate(void)
{
    POP3Transaction *tx = SCCalloc(1, sizeof(*tx));
    if (tx == NULL) {
        return NULL;
    }

    tx->mime_state = NULL;
    return tx;
}

static int POP3ProcessDataChunk(const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state) {

    int ret = MIME_DEC_OK;
    Flow *flow = (Flow *) state->data;
    POP3State *pop3_state = (POP3State *) flow->alstate;
    MimeDecEntity *entity = (MimeDecEntity *) state->stack->top->data;
    FileContainer *files = NULL;
    uint16_t flags = 0;

    /* Set flags */
    if (flow->flags & FLOW_FILE_NO_STORE_TS) {
        flags |= FILE_NOSTORE;
    }

    if (flow->flags & FLOW_FILE_NO_MAGIC_TS) {
        flags |= FILE_NOMAGIC;
    }

    if (flow->flags & FLOW_FILE_NO_MD5_TS) {
        flags |= FILE_NOMD5;
    }

    /* Find file */
    if (entity->ctnt_flags & CTNT_IS_ATTACHMENT) {

        /* Make sure file container allocated */
        if (pop3_state->files_ts == NULL) {
            pop3_state->files_ts = FileContainerAlloc();
            if (pop3_state->files_ts == NULL) {
                ret = MIME_DEC_ERR_MEM;
                SCLogError(SC_ERR_MEM_ALLOC, "Could not create file container");
                goto end;
            }
        }
        files = pop3_state->files_ts;

        /* Open file if necessary */
        if (state->body_begin) {

            if (SCLogDebugEnabled()) {
                SCLogDebug("Opening file...%u bytes", len);
                printf("File - ");
                for (uint32_t i = 0; i < entity->filename_len; i++) {
                    printf("%c", entity->filename[i]);
                }
                printf("\n");
            }

            /* Set storage flag if applicable since only the first file in the
             * flow seems to be processed by the 'filestore' detector */
            if (files->head != NULL && (files->head->flags & FILE_STORE)) {
                flags |= FILE_STORE;
            }

            if (FileOpenFile(files, &pop3_config.sbcfg, (uint8_t *) entity->filename, entity->filename_len,
                    (uint8_t *) chunk, len, flags) == NULL) {
                ret = MIME_DEC_ERR_DATA;
                SCLogDebug("FileOpenFile() failed");
            }

            /* If close in the same chunk, then pass in empty bytes */
            if (state->body_end) {

                SCLogDebug("Closing file...%u bytes", len);

                if (files && files->tail && files->tail->state == FILE_STATE_OPENED) {
                    ret = FileCloseFile(files, (uint8_t *) NULL, 0, flags);
                    if (ret != 0) {
                        SCLogDebug("FileCloseFile() failed: %d", ret);
                    }
                } else {
                    SCLogDebug("File already closed");
                }
            }
        } else if (state->body_end) {
            /* Close file */
            SCLogDebug("Closing file...%u bytes", len);

            if (files && files->tail && files->tail->state == FILE_STATE_OPENED) {
                ret = FileCloseFile(files, (uint8_t *) chunk, len, flags);
                if (ret != 0) {
                    SCLogDebug("FileCloseFile() failed: %d", ret);
                }
            } else {
                SCLogDebug("File already closed");
            }
        } else {
            /* Append data chunk to file */
            SCLogDebug("Appending file...%u bytes", len);

            /* 0 is ok, -2 is not stored, -1 is error */
            ret = FileAppendData(files, (uint8_t *) chunk, len);
            if (ret == -2) {
                ret = 0;
                SCLogDebug("FileAppendData() - file no longer being extracted");
            } else if (ret < 0) {
                SCLogDebug("FileAppendData() failed: %d", ret);
            }
        }

        if (ret == MIME_DEC_OK) {
            SCLogDebug("Successfully processed file data!");
        }
    } else {
        SCLogDebug("Body not a Ctnt_attachment");
    }

    if (files != NULL) {
        FilePrune(files);
    }
end:
    SCReturnInt(ret);
}

/**
 * \internal
 * \brief Get the next line from input.  It doesn't do any length validation.
 *
 * \param state The pop3 state.
 *
 * \retval  0 On suceess.
 * \retval -1 Either when we don't have any new lines to supply anymore or
 *            on failure.
 */
static int POP3GetLine(POP3State *state)
{
    SCEnter();
    void *ptmp;

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
            /* fragmented lines.  Decoder event for special cases.  Not all
             * fragmented lines should be treated as a possible evasion
             * attempt.  With multi payload pop3 chunks we can have valid
             * cases of fragmentation.  But within the same segment chunk
             * if we see fragmentation then it's definitely something you
             * should alert about */
            if (state->ts_current_line_db == 0) {
                state->ts_db = SCMalloc(state->input_len);
                if (state->ts_db == NULL) {
                    return -1;
                }
                state->ts_current_line_db = 1;
                memcpy(state->ts_db, state->input, state->input_len);
                state->ts_db_len = state->input_len;
            } else {
                ptmp = SCRealloc(state->ts_db,
                                 (state->ts_db_len + state->input_len));
                if (ptmp == NULL) {
                    SCFree(state->ts_db);
                    state->ts_db = NULL;
                    state->ts_db_len = 0;
                    return -1;
                }
                state->ts_db = ptmp;

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
                ptmp = SCRealloc(state->ts_db,
                                 (state->ts_db_len + (lf_idx + 1 - state->input)));
                if (ptmp == NULL) {
                    SCFree(state->ts_db);
                    state->ts_db = NULL;
                    state->ts_db_len = 0;
                    return -1;
                }
                state->ts_db = ptmp;

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
            /* fragmented lines.  Decoder event for special cases.  Not all
             * fragmented lines should be treated as a possible evasion
             * attempt.  With multi payload pop3 chunks we can have valid
             * cases of fragmentation.  But within the same segment chunk
             * if we see fragmentation then it's definitely something you
             * should alert about */
            if (state->tc_current_line_db == 0) {
                state->tc_db = SCMalloc(state->input_len);
                if (state->tc_db == NULL) {
                    return -1;
                }
                state->tc_current_line_db = 1;
                memcpy(state->tc_db, state->input, state->input_len);
                state->tc_db_len = state->input_len;
            } else {
                ptmp = SCRealloc(state->tc_db,
                                 (state->tc_db_len + state->input_len));
                if (ptmp == NULL) {
                    SCFree(state->tc_db);
                    state->tc_db = NULL;
                    state->tc_db_len = 0;
                    return -1;
                }
                state->tc_db = ptmp;

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
                ptmp = SCRealloc(state->tc_db,
                                 (state->tc_db_len + (lf_idx + 1 - state->input)));
                if (ptmp == NULL) {
                    SCFree(state->tc_db);
                    state->tc_db = NULL;
                    state->tc_db_len = 0;
                    return -1;
                }
                state->tc_db = ptmp;

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
                    state->current_line_delimiter_len = 1;
                }
            }

            state->input_len -= (lf_idx - state->input) + 1;
            state->input = (lf_idx + 1);

            return 0;
        } /* else - if (lf_idx == NULL) */
    }

}

static int POP3InsertCommandIntoCommandBuffer(uint8_t command, POP3State *state, Flow *f)
{
    SCEnter();
    void *ptmp;

    if (state->cmds_cnt >= state->cmds_buffer_len) {
        int increment = POP3_COMMAND_BUFFER_STEPS;
        if ((int)(state->cmds_buffer_len + POP3_COMMAND_BUFFER_STEPS) > (int)USHRT_MAX) {
            increment = USHRT_MAX - state->cmds_buffer_len;
        }

        ptmp = SCRealloc(state->cmds,
                         sizeof(uint8_t) * (state->cmds_buffer_len + increment));
        if (ptmp == NULL) {
            SCFree(state->cmds);
            state->cmds = NULL;
            SCLogDebug("SCRealloc failure");
            return -1;
        }
        state->cmds = ptmp;

        state->cmds_buffer_len += increment;
    }
    if (state->cmds_cnt >= 1) {
        /* decoder event */
        AppLayerDecoderEventsSetEvent(f,
                POP3_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE);
        /* we have to have EHLO, DATA, VRFY, EXPN, TURN, QUIT, NOOP,
         * STARTTLS as the last command in pipelined mode */
    }

    /** \todo decoder event */
    if ((int)(state->cmds_cnt + 1) > (int)USHRT_MAX) {
        SCLogDebug("command buffer overflow");
        return -1;
    }

    state->cmds[state->cmds_cnt] = command;
    state->cmds_cnt++;

    return 0;
}

static int POP3ProcessCommandRETR(POP3State *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();
    SCReturnInt(0);
}

/* toclient */
static int POP3ProcessReply(POP3State *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();

//printf("current_command: %d\n", state->current_command);
    switch (state->current_command) {
        case POP3_COMMAND_RETR:

            if (state->parser_state & POP3_PARSER_STATE_COMMAND_DATA_MODE) {
            if (state->current_line_len == 1 && state->current_line[0] == '.') {
                state->parser_state &= ~POP3_PARSER_STATE_COMMAND_DATA_MODE;

                if (pop3_config.decode_mime &&
                    (state->curr_tx != NULL) &&
                    (state->curr_tx->mime_state != NULL)) {
                    /* Complete parsing task */
//printf("Mime parse complete\n");
                    int ret = MimeDecParseComplete(state->curr_tx->mime_state);
                    if (ret != MIME_DEC_OK) {

                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_PARSE_FAILED);
                        SCLogDebug("MimeDecParseComplete() function failed");
                    }

                    /* Generate decoder events */
                    MimeDecEntity *msg = state->curr_tx->mime_state->msg;
                    if (msg->anomaly_flags & ANOM_INVALID_BASE64) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_INVALID_BASE64);
                    }
                    if (msg->anomaly_flags & ANOM_INVALID_QP) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_INVALID_QP);
                    }
                    if (msg->anomaly_flags & ANOM_LONG_LINE) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_LONG_LINE);
                    }
                    if (msg->anomaly_flags & ANOM_LONG_ENC_LINE) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_LONG_ENC_LINE);
                    }
                    if (msg->anomaly_flags & ANOM_LONG_HEADER_NAME) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_LONG_HEADER_NAME);
                    }
                    if (msg->anomaly_flags & ANOM_LONG_HEADER_VALUE) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_LONG_HEADER_VALUE);
                    }
                    if (msg->anomaly_flags & ANOM_MALFORMED_MSG) {
                        AppLayerDecoderEventsSetEvent(f, POP3_DECODER_EVENT_MIME_MALFORMED_MSG);
                    }
                }
                if (state->curr_tx != NULL) {
                    state->curr_tx->done = 1;
                    SCLogDebug("marked tx as done");
                }
            }
            /* If DATA, then parse out a MIME message */
            if (state->parser_state & POP3_PARSER_STATE_COMMAND_DATA_MODE) {

                if (pop3_config.decode_mime &&
                    (state->curr_tx != NULL) &&
                    (state->curr_tx->mime_state != NULL)) {
                    int ret = MimeDecParseLine((const uint8_t *) state->current_line,
                            state->current_line_len,
                            state->current_line_delimiter_len,
                            state->curr_tx->mime_state);
                    if (ret != MIME_DEC_OK) {
                        SCLogDebug("MimeDecParseLine() function returned an error code: %d", ret);
                    }
                }
            }
            } else if (state->current_line_len >= 3 &&
                SCMemcmpLowercase("+ok", state->current_line, 3) == 0) {
                state->parser_state |= POP3_PARSER_STATE_COMMAND_DATA_MODE;
            }

            break;
        default:
            break;
    }
    /* if it is a multi-line reply, we need to move the index only once for all
     * the line of the reply.  We unset the multiline flag on the last
     * line of the multiline reply, following which we increment the index */
    if (!(state->parser_state & POP3_PARSER_STATE_PARSING_MULTILINE_REPLY)) {
        state->cmds_idx++;
    }

    /* if we have matched all the buffered commands, reset the cnt and index */
    if (state->cmds_idx == state->cmds_cnt) {
        state->cmds_cnt = 0;
        state->cmds_idx = 0;
    }

    return 0;
}

/* toserver */
static int POP3ProcessRequest(POP3State *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();
    POP3Transaction *tx = state->curr_tx;

    if (tx == NULL || (tx->done/* && !NoNewTx(state)*/)) {
        tx = POP3TransactionCreate();
        if (tx == NULL)
            return -1;
        state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
        tx->tx_id = state->tx_cnt++;
    }


    /* there are 2 commands that can push it into this COMMAND_DATA mode -
     * STARTTLS and DATA */
    if (!(state->parser_state & POP3_PARSER_STATE_COMMAND_DATA_MODE)) {
        int r = 0;

        if (state->current_line_len >= 4 &&
                SCMemcmpLowercase("user", state->current_line, 4) == 0) {
            state->current_command = POP3_COMMAND_USER;
        } else if (state->current_line_len >= 4 &&
                SCMemcmpLowercase("retr", state->current_line, 4) == 0) {
            state->current_command = POP3_COMMAND_RETR;

            if (pop3_config.decode_mime) {
                tx->mime_state = MimeDecInitParser(f, POP3ProcessDataChunk);
                if (tx->mime_state == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "MimeDecInitParser() failed to "
                            "allocate data");
                    return MIME_DEC_ERR_MEM;
                }

                /* Add new MIME message to end of list */
                if (tx->msg_head == NULL) {
                    tx->msg_head = tx->mime_state->msg;
                    tx->msg_tail = tx->mime_state->msg;
                }
                else {
                    tx->msg_tail->next = tx->mime_state->msg;
                    tx->msg_tail = tx->mime_state->msg;
                }
            }
        } else {
            state->current_command = POP3_COMMAND_OTHER_CMD;
        }
        /* Every command is inserted into a command buffer, to be matched
         * against reply(ies) sent by the server */
        if (POP3InsertCommandIntoCommandBuffer(state->current_command,
                state, f) == -1) {
            SCReturnInt(-1);
        }

        SCReturnInt(r);
    }

    switch (state->current_command) {
    case POP3_COMMAND_RETR:
        return POP3ProcessCommandRETR(state, f, pstate);
    default:
        /* we have nothing to do with any other command at this instant.
         * Just let it go through */
        SCReturnInt(0);
    }
}

static int POP3Parse(int direction, Flow *f, POP3State *state,
        AppLayerParserState *pstate, uint8_t *input,
        uint32_t input_len,
        PatternMatcherQueue *local_data)
{
    SCEnter();

    state->input = input;
    state->input_len = input_len;
    state->direction = direction;
    state->thread_local_data = local_data;

    /* toserver */
    if (direction == 0) {
        while (POP3GetLine(state) >= 0) {
            if (POP3ProcessRequest(state, f, pstate) == -1)
                SCReturnInt(-1);
        }

        /* toclient */
    } else {
        while (POP3GetLine(state) >= 0) {
            if (POP3ProcessReply(state, f, pstate) == -1)
                SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
}

static int POP3ParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{
    SCEnter();

    /* first arg 0 is toserver */
    return POP3Parse(0, f, alstate, pstate, input, input_len, local_data);
}

static int POP3ParseServerRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{
    SCEnter();

    /* first arg 1 is toclient */
    return POP3Parse(1, f, alstate, pstate, input, input_len, local_data);
}

/**
 * \internal
 * \brief Function to allocate POP3 state memory.
 */
static void *POP3StateAlloc(void)
{
    POP3State *pop3_state = SCMalloc(sizeof(POP3State));
    if (unlikely(pop3_state == NULL))
        return NULL;
    memset(pop3_state, 0, sizeof(POP3State));

    pop3_state->cmds = SCMalloc(sizeof(uint8_t) *
            POP3_COMMAND_BUFFER_STEPS);
    if (pop3_state->cmds == NULL) {
        SCFree(pop3_state);
        return NULL;
    }
    pop3_state->cmds_buffer_len = POP3_COMMAND_BUFFER_STEPS;

    TAILQ_INIT(&pop3_state->tx_list);

    return pop3_state;
}

static void POP3TransactionFree(POP3Transaction *tx, POP3State *state)
{
    if (tx->mime_state != NULL) {
        MimeDecDeInitParser(tx->mime_state);
    }
    /* Free list of MIME message recursively */
    MimeDecFreeEntity(tx->msg_head);

    if (tx->decoder_events != NULL)
        AppLayerDecoderEventsFreeEvents(&tx->decoder_events);

    if (tx->de_state != NULL)
        DetectEngineStateFree(tx->de_state);

    SCFree(tx);
}

/**
 * \internal
 * \brief Function to free POP3 state memory.
 */
static void POP3StateFree(void *p)
{
    POP3State *pop3_state = (POP3State *)p;

    if (pop3_state->cmds != NULL) {
        SCFree(pop3_state->cmds);
    }
    if (pop3_state->ts_current_line_db) {
        SCFree(pop3_state->ts_db);
    }
    if (pop3_state->tc_current_line_db) {
        SCFree(pop3_state->tc_db);
    }

    FileContainerFree(pop3_state->files_ts);

    POP3Transaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&pop3_state->tx_list))) {
        TAILQ_REMOVE(&pop3_state->tx_list, tx, next);
        POP3TransactionFree(tx, pop3_state);
    }

    SCFree(pop3_state);

    return;
}

int POP3StateGetEventInfo(const char *event_name,
                          int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, pop3_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "pop3's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_GENERAL;

    return 0;
}

static void POP3StateTransactionFree (void *state, uint64_t tx_id)
{
    POP3State *pop3_state = state;
    POP3Transaction *tx = NULL;
    TAILQ_FOREACH(tx, &pop3_state->tx_list, next) {
        if (tx_id < tx->tx_id)
            break;
        else if (tx_id > tx->tx_id)
            continue;

        if (tx == pop3_state->curr_tx)
            pop3_state->curr_tx = NULL;
        TAILQ_REMOVE(&pop3_state->tx_list, tx, next);
        POP3TransactionFree(tx, state);
        break;
    }


}

/** \todo slow */
static uint64_t POP3StateGetTxCnt(void *state)
{
    POP3State *pop3_state = state;
    return pop3_state->tx_cnt;
}

static void *POP3StateGetTx(void *state, uint64_t id)
{
    POP3State *pop3_state = state;
    if (pop3_state) {
        POP3Transaction *tx = NULL;

        if (pop3_state->curr_tx == NULL)
            return NULL;
        if (pop3_state->curr_tx->tx_id == id)
            return pop3_state->curr_tx;

        TAILQ_FOREACH(tx, &pop3_state->tx_list, next) {
            if (tx->tx_id == id)
                return tx;
        }
    }
    return NULL;

}

static int POP3StateGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

static int POP3StateGetAlstateProgress(void *vtx, uint8_t direction)
{
    POP3Transaction *tx = vtx;
    return tx->done;
}

/** \internal
 *  \brief get files callback
 *  \param state state ptr
 *  \param direction flow direction
 *  \retval files files ptr
 */
static FileContainer *POP3StateGetFiles(void *state, uint8_t direction) {
    if (state == NULL)
        return NULL;

    POP3State *pop3_state = (POP3State *)state;

    if (direction & STREAM_TOCLIENT) {
        SCReturnPtr(NULL, "FileContainer");
    } else {
        SCReturnPtr(pop3_state->files_ts, "FileContainer");
    }
}

static void POP3StateTruncate(void *state, uint8_t direction)
{
    FileContainer *fc = POP3StateGetFiles(state, direction);
    if (fc != NULL) {
        SCLogDebug("truncating stream, closing files in %s direction (container %p)",
                direction & STREAM_TOCLIENT ? "STREAM_TOCLIENT" : "STREAM_TOSERVER", fc);
        FileTruncateAllOpenFiles(fc);
    }
}

static AppLayerDecoderEvents *POP3GetEvents(void *state, uint64_t tx_id)
{
    SCLogDebug("get POP3 events for TX %"PRIu64, tx_id);

    POP3Transaction *tx = POP3StateGetTx(state, tx_id);
    if (tx != NULL) {
        return tx->decoder_events;
    }
    return NULL;
}

static DetectEngineState *POP3GetTxDetectState(void *vtx)
{
    POP3Transaction *tx = (POP3Transaction *)vtx;
    return tx->de_state;
}

static int POP3SetTxDetectState(void *state, void *vtx, DetectEngineState *s)
{
    POP3Transaction *tx = (POP3Transaction *)vtx;
    tx->de_state = s;
    return 0;
}


/**
 * \brief Register the SMPT Protocol parser.
 */
void RegisterPOP3Parsers(void)
{
    char *proto_name = "pop3";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_POP3, proto_name);
        AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_POP3,
                                               "+OK ", 4, 0,
                                               STREAM_TOCLIENT);
        AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_POP3,
                                               "+OK|00|", 4, 0,
                                               STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {

        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_POP3,
                                         POP3StateAlloc, POP3StateFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_POP3,
                                           POP3StateGetFiles);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_POP3, STREAM_TOSERVER,
                                     POP3ParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_POP3, STREAM_TOCLIENT,
                                     POP3ParseServerRecord);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_POP3,
                                           POP3StateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_POP3, POP3GetEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_POP3, NULL,
                                               POP3GetTxDetectState, POP3SetTxDetectState);


        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_POP3, POP3StateTransactionFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_POP3, POP3StateGetFiles);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_POP3, POP3StateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_POP3, POP3StateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_POP3, POP3StateGetTx);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_POP3,
                                                               POP3StateGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_POP3, POP3StateTruncate);

    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    POP3Configure();

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_POP3, POP3ParserRegisterTests);
#endif
    return;

}

/***************************************Unittests******************************/

#ifdef UNITTESTS
#endif /* UNITTESTS */

void POP3ParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif /* UNITTESTS */
    return;
}
