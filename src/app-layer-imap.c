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
#include "app-layer-imap.h"

#include "util-mpm.h"
#include "util-debug.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-byte.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "util-print.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-parse.h"

#include "decode-events.h"
#include "conf.h"

//#define PRINT

#define IMAP_MAX_REQUEST_AND_REPLY_LINE_LENGTH 510

#define IMAP_COMMAND_BUFFER_STEPS 5

/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
#define IMAP_PARSER_STATE_COMMAND_MODE            0x00
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
#define IMAP_PARSER_STATE_COMMAND_DATA_MODE       0x01
/* we are in mode of retrieving email content from the server */
#define IMAP_PARSER_STATE_COMMAND_SERVER_DATA_MODE       0x02
/* Used when we are still in the process of parsing a server command.  Used
 * with multi-line replies and the stream is fragmented before all the lines
 * for a response is seen */
#define IMAP_PARSER_STATE_PARSING_SERVER_RESPONSE 0x04
/* Used to indicate that the parser has seen the first reply */
#define IMAP_PARSER_STATE_FIRST_REPLY_SEEN        0x08
/* Used to indicate that the parser is parsing a multiline reply */
#define IMAP_PARSER_STATE_PARSING_MULTILINE_REPLY 0x10

/* Various IMAP commands
 * We currently have var-ified just STARTTLS and DATA, since we need to them
 * for state transitions.  The rest are just indicate as OTHER_CMD.  Other
 * commands would be introduced as and when needed */
#define IMAP_COMMAND_LOGIN     1
#define IMAP_COMMAND_APPEND    2
#define IMAP_COMMAND_USER      3
#define IMAP_COMMAND_RETR      4

/* not an actual command per se, but the mode where we accept the mail after
 * DATA has it's own reply code for completion, from the server.  We give this
 * stage a pseudo command of it's own, so that we can add this to the command
 * buffer to match with the reply */
#define IMAP_COMMAND_DATA_MODE 4
/* All other commands are represented by this var */
#define IMAP_COMMAND_OTHER_CMD 5

SCEnumCharMap imap_decoder_event_table[ ] = {
    { "INVALID_REPLY",           IMAP_DECODER_EVENT_INVALID_REPLY },
    { "UNABLE_TO_MATCH_REPLY_WITH_REQUEST",
      IMAP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST },
    { "MAX_COMMAND_LINE_LEN_EXCEEDED",
      IMAP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED },
    { "MAX_REPLY_LINE_LEN_EXCEEDED",
      IMAP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED },
    { "INVALID_PIPELINED_SEQUENCE",
      IMAP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE },
    { "BDAT_CHUNK_LEN_EXCEEDED",
      IMAP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED },
    { "NO_SERVER_WELCOME_MESSAGE",
      IMAP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE },
    { "TLS_REJECTED",
      IMAP_DECODER_EVENT_TLS_REJECTED },
    { "DATA_COMMAND_REJECTED",
      IMAP_DECODER_EVENT_DATA_COMMAND_REJECTED },

    /* MIME Events */
    { "MIME_PARSE_FAILED",
      IMAP_DECODER_EVENT_MIME_PARSE_FAILED },
    { "MIME_MALFORMED_MSG",
      IMAP_DECODER_EVENT_MIME_MALFORMED_MSG },
    { "MIME_INVALID_BASE64",
      IMAP_DECODER_EVENT_MIME_INVALID_BASE64 },
    { "MIME_INVALID_QP",
      IMAP_DECODER_EVENT_MIME_INVALID_QP },
    { "MIME_LONG_LINE",
      IMAP_DECODER_EVENT_MIME_LONG_LINE },
    { "MIME_LONG_ENC_LINE",
      IMAP_DECODER_EVENT_MIME_LONG_ENC_LINE },
    { "MIME_LONG_HEADER_NAME",
      IMAP_DECODER_EVENT_MIME_LONG_HEADER_NAME },
    { "MIME_LONG_HEADER_VALUE",
      IMAP_DECODER_EVENT_MIME_LONG_HEADER_VALUE },

    { NULL,                      -1 },
};

#define IMAP_MPM DEFAULT_MPM

static MpmCtx *imap_mpm_ctx = NULL;
MpmThreadCtx *imap_mpm_thread_ctx;

static pcre *fetch_body_regex;
static pcre_extra *fetch_body_regex_study;

#define IMAP_FETCH_BODY "FETCH.*BODY*\\[\\]"

/* imap reply codes.  If an entry is made here, please make a simultaneous
 * entry in imap_server_map */
enum {
    IMAP_SERVER_REPLY,
};

SCEnumCharMap imap_server_map[ ] = {
    { "* ", IMAP_SERVER_REPLY },
    {  NULL,  -1 },
};

typedef struct IMAPConfig {

    int decode_mime;
    MimeDecConfig mime_config;
    uint32_t content_limit;
    uint32_t content_inspect_min_size;
    uint32_t content_inspect_window;

    StreamingBufferConfig sbcfg;
} IMAPConfig;

/* Create IMAP config structure */
static IMAPConfig imap_config = { 0, { 0, 0, 0, 0, 0 }, 0, 0, 0, STREAMING_BUFFER_CONFIG_INITIALIZER };

/**
 * \brief Configure IMAP Mime Decoder by parsing out 'imap-mime' section of YAML
 * config file
 *
 * \return none
 */
static void IMAPConfigure(void) {

    SCEnter();
    int ret = 0, val;
    intmax_t imval;

    ConfNode *config = ConfGetNode("app-layer.protocols.imap.mime");
    if (config != NULL) {

        ret = ConfGetChildValueBool(config, "decode-mime", &val);
        if (ret) {
            imap_config.decode_mime = val;
        }

        ret = ConfGetChildValueBool(config, "decode-base64", &val);
        if (ret) {
            imap_config.mime_config.decode_base64 = val;
        }

        ret = ConfGetChildValueBool(config, "decode-quoted-printable", &val);
        if (ret) {
            imap_config.mime_config.decode_quoted_printable = val;
        }

        ret = ConfGetChildValueInt(config, "header-value-depth", &imval);
        if (ret) {
            imap_config.mime_config.header_value_depth = (uint32_t) imval;
        }

        ret = ConfGetChildValueBool(config, "extract-urls", &val);
        if (ret) {
            imap_config.mime_config.extract_urls = val;
        }
    }

    /* Pass mime config data to MimeDec API */
    MimeDecSetConfig(&imap_config.mime_config);

    SCReturn;
}

static IMAPTransaction *IMAPTransactionCreate(void)
{
    IMAPTransaction *tx = SCCalloc(1, sizeof(*tx));
    if (tx == NULL) {
        return NULL;
    }

    tx->mime_state = NULL;
    return tx;
}

static int ProcessDataChunk(const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state) {

    int ret = MIME_DEC_OK;
    Flow *flow = (Flow *) state->data;
    IMAPState *imap_state = (IMAPState *) flow->alstate;
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
        if (imap_state->files_ts == NULL) {
            imap_state->files_ts = FileContainerAlloc();
            if (imap_state->files_ts == NULL) {
                ret = MIME_DEC_ERR_MEM;
                SCLogError(SC_ERR_MEM_ALLOC, "Could not create file container");
                goto end;
            }
        }
        files = imap_state->files_ts;

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

            if (FileOpenFile(files, &imap_config.sbcfg, (uint8_t *) entity->filename, entity->filename_len,
                    (uint8_t *) chunk, len, flags) == NULL) {
                ret = MIME_DEC_ERR_DATA;
                SCLogDebug("FileOpenFile() failed");
            }

            /* If close in the same chunk, then pass in empty bytes */
            if (state->body_end) {

                SCLogDebug("Closing file...%u bytes", len);

                if (files->tail->state == FILE_STATE_OPENED) {
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

            if (files->tail->state == FILE_STATE_OPENED) {
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
 * \param state The imap state.
 *
 * \retval  0 On suceess.
 * \retval -1 Either when we don't have any new lines to supply anymore or
 *            on failure.
 */
static int IMAPGetLine(IMAPState *state)
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
             * attempt.  With multi payload imap chunks we can have valid
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
             * attempt.  With multi payload imap chunks we can have valid
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

static int IMAPInsertCommandIntoCommandBuffer(uint8_t command, IMAPState *state, Flow *f)
{ SCEnter();
    void *ptmp;

    if (state->cmds_cnt >= state->cmds_buffer_len) {
        int increment = IMAP_COMMAND_BUFFER_STEPS;
        if ((int)(state->cmds_buffer_len + IMAP_COMMAND_BUFFER_STEPS) > (int)USHRT_MAX) {
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
                IMAP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE);
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

static int IMAPProcessCommandRETR(IMAPState *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();
    SCReturnInt(0);
}

static void *memxchr(const void *s, int c, size_t n)
{
   const uint8_t *p = s;
   size_t i;

   for (i = 0; i < n; i++)
       if ((int)p[i] != c)
            return (void *)&p[i];
   return NULL;
}

static int IMAPParseCommand(IMAPState *state)
{
    SCEnter();
    uint32_t remaining = state->current_line_len;
    uint32_t whitespace_len;
    uint8_t *p;

    state->command_token_len = state->command_len = state->command_args_len = 0;
    state->parser_position = state->current_line;

    state->command_token = state->parser_position;
    state->parser_position = memchr(state->parser_position, ' ', remaining);
    if (state->parser_position == NULL) {
        state->command_token_len = remaining;
        goto done;
    }
    state->command_token_len = (state->parser_position - state->command_token);
    remaining -= state->command_token_len;
    p = memxchr(state->parser_position, ' ', remaining);
    if (p == NULL) {
        goto done;
    }
    whitespace_len = (p - state->parser_position);
    remaining -= whitespace_len;

    state->command = &state->parser_position[whitespace_len];
    state->parser_position = memchr(state->command, ' ', remaining);
    if (state->parser_position == NULL) {
        state->command_len = remaining;
        goto done;
    }
    state->command_len = (state->parser_position - state->command);
    remaining -= state->command_len;
    p = memxchr(state->parser_position, ' ', remaining);
    if (p == NULL) {
        goto done;
    }
    whitespace_len = (p - state->parser_position);
    remaining -= whitespace_len;

    state->command_args = &state->parser_position[whitespace_len];
    state->command_args_len = remaining;

done:
#ifdef PRINT
    printf("Token:\n");
    PrintRawDataFp(stdout, state->command_token, state->command_token_len);
    printf("Comand:\n");
    PrintRawDataFp(stdout, state->command, state->command_len);
    printf("args:\n");
    PrintRawDataFp(stdout, state->command_args, state->command_args_len);
#endif
    SCReturnInt(0);
}

static int IMAPParseReply(IMAPState *state)
{
    SCEnter();
    uint32_t remaining = state->current_line_len;
    uint32_t whitespace_len;
    uint8_t *p;

    state->command_token_len = state->command_len = state->command_args_len = 0;
    state->parser_position = state->current_line;

    state->command_token = state->parser_position;
    state->parser_position = memchr(state->parser_position, ' ', remaining);
    if (state->parser_position == NULL) {
        state->command_token_len = remaining;
        goto done;
    }
    state->command_token_len = (state->parser_position - state->command_token);
    remaining -= state->command_token_len;
    p = memxchr(state->parser_position, ' ', remaining);
    if (p == NULL) {
        goto done;
    }
    whitespace_len = (p - state->parser_position);
    remaining -= whitespace_len;

    state->command = &state->parser_position[whitespace_len];
    state->parser_position = memchr(state->command, ' ', remaining);
    if (state->parser_position == NULL) {
        state->command_len = remaining;
        goto done;
    }
    state->command_len = (state->parser_position - state->command);
    remaining -= state->command_len;
    p = memxchr(state->parser_position, ' ', remaining);
    if (p == NULL) {
        goto done;
    }
    whitespace_len = (p - state->parser_position);
    remaining -= whitespace_len;

    state->command_args = &state->parser_position[whitespace_len];
    state->command_args_len = remaining;

done:
#ifdef PRINT
    printf("Token:\n");
    PrintRawDataFp(stdout, state->command_token, state->command_token_len);
    printf("Comand:\n");
    PrintRawDataFp(stdout, state->command, state->command_len);
    printf("args:\n");
    PrintRawDataFp(stdout, state->command_args, state->command_args_len);
#endif
    SCReturnInt(0);
}

/* toclient */
static int IMAPProcessReply(IMAPState *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();
    IMAPTransaction *tx = state->curr_tx;
    uint64_t reply_code = 0;
    PatternMatcherQueue *pmq = state->thread_local_data;

    if (tx == NULL || (tx->done/*&& !NoNewTx(state)*/)) {
        tx = IMAPTransactionCreate();
        if (tx == NULL)
            return -1;
        state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
        tx->tx_id = state->tx_cnt++;
    }

    /* If SERVER DATA, then parse out a MIME message */
    if (state->parser_state & IMAP_PARSER_STATE_COMMAND_SERVER_DATA_MODE) {
        if (imap_config.decode_mime) {
            if (tx->mime_state != NULL) {
                int ret = MimeDecParseLine((const uint8_t *) state->current_line,
                                           state->current_line_len, state->current_line_delimiter_len,
                                           tx->mime_state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("MimeDecParseLine() function returned an error code: %d", ret);
                }
            }
        }
        state->remaining_fetch_len -= (state->current_line_len + 2);
        if (state->remaining_fetch_len <= 0) {
            if (imap_config.decode_mime) {
                if (tx->mime_state != NULL) {
                    /* Complete parsing task */
                    int ret = MimeDecParseComplete(tx->mime_state);
                    if (ret != MIME_DEC_OK) {

                        AppLayerDecoderEventsSetEvent(f, IMAP_DECODER_EVENT_MIME_PARSE_FAILED);
                        SCLogDebug("MimeDecParseComplete() function failed");
                    }
                }
            }

            state->parser_state &= ~IMAP_PARSER_STATE_COMMAND_SERVER_DATA_MODE;
            state->curr_tx->done = 1;
            SCLogDebug("marked tx as done");
        }
    /* If CLIENT DATA, then wait for OK */
    } else if (state->parser_state & IMAP_PARSER_STATE_COMMAND_DATA_MODE) {
        IMAPParseReply(state);
        if (state->command_len >= 2 &&
                SCMemcmpLowercase("ok", state->command, 2) == 0) {
            if (imap_config.decode_mime) {
                if (tx->mime_state != NULL) {
                    /* Complete parsing task */
                    int ret = MimeDecParseComplete(tx->mime_state);
                    if (ret != MIME_DEC_OK) {

                        AppLayerDecoderEventsSetEvent(f, IMAP_DECODER_EVENT_MIME_PARSE_FAILED);
                        SCLogDebug("MimeDecParseComplete() function failed");
                    }
                }
            }

            state->parser_state &= ~IMAP_PARSER_STATE_COMMAND_SERVER_DATA_MODE;
            tx->done = 1;
            SCLogDebug("marked tx as done");
        }
    } else {

        /* I don't like this pmq reset here.  We'll devise a method later, that
         * should make the use of the mpm very efficient */
        PmqReset(pmq);
        int mpm_cnt = mpm_table[IMAP_MPM].Search(imap_mpm_ctx, imap_mpm_thread_ctx,
                pmq, state->current_line,
                state->current_line_len/*3*/);
        if (mpm_cnt == 0) {
            /* set decoder event - reply code invalid */
            AppLayerDecoderEventsSetEvent(f,
                    IMAP_DECODER_EVENT_INVALID_REPLY);
            SCLogDebug("invalid reply code %02x %02x %02x",
                    state->current_line[0], state->current_line[1], state->current_line[2]);
            SCReturnInt(0);
        }
        reply_code = imap_server_map[pmq->rule_id_array[0]].enum_value;
        if (reply_code == IMAP_SERVER_REPLY) {

#define MAX_SUBSTRINGS 30
            int ov[MAX_SUBSTRINGS];
            int ret;

            ret = pcre_exec(fetch_body_regex, fetch_body_regex_study,
                            (const char *)state->current_line, state->current_line_len,
                            0, 0, ov, MAX_SUBSTRINGS);
            if (ret == PCRE_ERROR_NOMATCH) {
                SCReturnInt(0);
            } else if (ret >= 0) {
                state->remaining_fetch_len = state->input_len;
                if (imap_config.decode_mime) {
                    /* Re-init the MIME parser */
                    if (tx->mime_state != NULL) {
                        MimeDecDeInitParser(tx->mime_state);
                    }
                    tx->mime_state = MimeDecInitParser(f, ProcessDataChunk);
                    if (state->curr_tx->mime_state == NULL) {
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
                state->parser_state |= IMAP_PARSER_STATE_COMMAND_SERVER_DATA_MODE;
            } else {
                SCLogError(SC_ERR_PCRE_MATCH, "pcre parse error: %s", IMAP_FETCH_BODY);
                SCReturnInt(0);
            }
        }
    }

    /* if it is a multi-line reply, we need to move the index only once for all
     * the line of the reply.  We unset the multiline flag on the last
     * line of the multiline reply, following which we increment the index */
    if (!(state->parser_state & IMAP_PARSER_STATE_PARSING_MULTILINE_REPLY)) {
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
static int IMAPProcessRequest(IMAPState *state, Flow *f,
        AppLayerParserState *pstate)
{
    SCEnter();
    IMAPTransaction *tx = state->curr_tx;
    if (tx == NULL || (tx->done/*&& !NoNewTx(state)*/)) {
        tx = IMAPTransactionCreate();
        if (tx == NULL)
            return -1;
        state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
        tx->tx_id = state->tx_cnt++;
    }

    if (!(state->parser_state & IMAP_PARSER_STATE_COMMAND_DATA_MODE)) {
        int r = 0;

        IMAPParseCommand(state);
        if (state->command_len >= 5 &&
                SCMemcmpLowercase("login", state->command, 5) == 0) {
            state->current_command = IMAP_COMMAND_LOGIN;
        } else if (state->command_len >= 6 &&
                SCMemcmpLowercase("append", state->command, 6) == 0) {
            state->current_command = IMAP_COMMAND_APPEND;
            if (imap_config.decode_mime) {
                /* Re-init the MIME parser */
                if (tx->mime_state != NULL) {
                    MimeDecDeInitParser(tx->mime_state);
                }
                tx->mime_state = MimeDecInitParser(f, ProcessDataChunk);
                /* Add new MIME message to end of list */
                if (tx->msg_head == NULL) {
                    tx->msg_head = state->curr_tx->mime_state->msg;
                    tx->msg_tail = state->curr_tx->mime_state->msg;
                }
                else {
                    tx->msg_tail->next = state->curr_tx->mime_state->msg;
                    tx->msg_tail = state->curr_tx->mime_state->msg;
                }
                if (state->curr_tx->mime_state != NULL) {
                    state->parser_state |= IMAP_PARSER_STATE_COMMAND_DATA_MODE;
                } else {
                    SCLogError(SC_ERR_MEM_ALLOC, "MimeDecInitParser() failed to "
                                "allocate data");
                }
            }
        } else if (state->command_len >= 4 &&
                SCMemcmpLowercase("user", state->command, 4) == 0) {
            state->current_command = IMAP_COMMAND_USER;
        } else if (state->command_len >= 4 &&
                SCMemcmpLowercase("retr", state->command, 4) == 0) {
            state->current_command = IMAP_COMMAND_RETR;

            if (imap_config.decode_mime) {
                /* Re-init the MIME parser */
                if (state->curr_tx->mime_state != NULL) {
                    MimeDecDeInitParser(state->curr_tx->mime_state);
                }
                state->curr_tx->mime_state = MimeDecInitParser(f, ProcessDataChunk);
                if (state->curr_tx->mime_state == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "MimeDecInitParser() failed to "
                            "allocate data");
                    return MIME_DEC_ERR_MEM;
                }

                /* Add new MIME message to end of list */
                if (tx->msg_head == NULL) {
                    tx->msg_head = state->curr_tx->mime_state->msg;
                    tx->msg_tail = state->curr_tx->mime_state->msg;
                }
                else {
                    tx->msg_tail->next = state->curr_tx->mime_state->msg;
                    tx->msg_tail = state->curr_tx->mime_state->msg;
                }
            }
        } else {
            state->current_command = IMAP_COMMAND_OTHER_CMD;
        }
        /* Every command is inserted into a command buffer, to be matched
         * against reply(ies) sent by the server */
        if (IMAPInsertCommandIntoCommandBuffer(state->current_command,
                state, f) == -1) {
            SCReturnInt(-1);
        }

        SCReturnInt(r);
    } else {
        if (imap_config.decode_mime) {
            if (tx->mime_state != NULL) {
                int ret = MimeDecParseLine((const uint8_t *) state->current_line,
                                           state->current_line_len, state->current_line_delimiter_len,
                                           tx->mime_state);
                if (ret != MIME_DEC_OK) {
                    SCLogDebug("MimeDecParseLine() function returned an error code: %d", ret);
                }
            }
        }
    }

    switch (state->current_command) {
    case IMAP_COMMAND_RETR:
        return IMAPProcessCommandRETR(state, f, pstate);
    default:
        /* we have nothing to do with any other command at this instant.
         * Just let it go through */
        SCReturnInt(0);
    }
}

static int IMAPParse(int direction, Flow *f, IMAPState *state,
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

        while (IMAPGetLine(state) >= 0) {
            if (IMAPProcessRequest(state, f, pstate) == -1)
                SCReturnInt(-1);
        }

        /* toclient */
    } else {
        while (IMAPGetLine(state) >= 0) {
            if (IMAPProcessReply(state, f, pstate) == -1)
                SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
}

static int IMAPParseClientRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{
    SCEnter();

    /* first arg 0 is toserver */
    return IMAPParse(0, f, alstate, pstate, input, input_len, local_data);
}

static int IMAPParseServerRecord(Flow *f, void *alstate,
        AppLayerParserState *pstate,
        uint8_t *input, uint32_t input_len,
        void *local_data)
{
    SCEnter();

    /* first arg 1 is toclient */
    return IMAPParse(1, f, alstate, pstate, input, input_len, local_data);

    return 0;
}

/**
 * \internal
 * \brief Function to allocate IMAP state memory.
 */
static void *IMAPStateAlloc(void)
{
    IMAPState *imap_state = SCMalloc(sizeof(IMAPState));
    if (unlikely(imap_state == NULL))
        return NULL;
    memset(imap_state, 0, sizeof(IMAPState));

    imap_state->cmds = SCMalloc(sizeof(uint8_t) *
            IMAP_COMMAND_BUFFER_STEPS);
    if (imap_state->cmds == NULL) {
        SCFree(imap_state);
        return NULL;
    }
    imap_state->cmds_buffer_len = IMAP_COMMAND_BUFFER_STEPS;

    TAILQ_INIT(&imap_state->tx_list);

    return imap_state;
}

static void *IMAPLocalStorageAlloc(void)
{
    /* needed by the mpm */
    PatternMatcherQueue *pmq = SCMalloc(sizeof(PatternMatcherQueue));
    if (unlikely(pmq == NULL)) {
        exit(EXIT_FAILURE);
    }
    PmqSetup(pmq);

    return pmq;
}

static void IMAPLocalStorageFree(void *pmq)
{
    if (pmq != NULL) {
        PmqFree(pmq);
        SCFree(pmq);
    }

    return;
}

static void IMAPTransactionFree(IMAPTransaction *tx, IMAPState *state)
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
 * \brief Function to free IMAP state memory.
 */
static void IMAPStateFree(void *p)
{
    IMAPState *imap_state = (IMAPState *)p;

    if (imap_state->cmds != NULL) {
        SCFree(imap_state->cmds);
    }
    if (imap_state->ts_current_line_db) {
        SCFree(imap_state->ts_db);
    }
    if (imap_state->tc_current_line_db) {
        SCFree(imap_state->tc_db);
    }

    FileContainerFree(imap_state->files_ts);

    IMAPTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&imap_state->tx_list))) {
        TAILQ_REMOVE(&imap_state->tx_list, tx, next);
        IMAPTransactionFree(tx, imap_state);
    }

    SCFree(imap_state);

    return;
}

static void IMAPSetMpmState(void)
{
    imap_mpm_ctx = SCMalloc(sizeof(MpmCtx));
    if (unlikely(imap_mpm_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(imap_mpm_ctx, 0, sizeof(MpmCtx));
    MpmInitCtx(imap_mpm_ctx, IMAP_MPM);

    imap_mpm_thread_ctx = SCMalloc(sizeof(MpmThreadCtx));
    if (unlikely(imap_mpm_thread_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(imap_mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitThreadCtx(imap_mpm_thread_ctx, IMAP_MPM);

    uint32_t i = 0;
    for (i = 0; i < sizeof(imap_server_map)/sizeof(SCEnumCharMap) - 1; i++) {
        SCEnumCharMap *map = &imap_server_map[i];
        MpmAddPatternCI(imap_mpm_ctx, (uint8_t *)map->enum_name, 
                        strlen(map->enum_name),
                        0 /* defunct */, 0 /* defunct */,
                        i /* pattern id */, 0, 0 /* no flags */);
    }

    mpm_table[IMAP_MPM].Prepare(imap_mpm_ctx);

    /* compile required pcre */
    const char *eb;
    int eo;
    int opts = 0/*PCRE_UNGREEDY*/;

    fetch_body_regex = pcre_compile(IMAP_FETCH_BODY, opts, &eb, &eo, NULL);
    if (fetch_body_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", IMAP_FETCH_BODY, eo, eb);
        goto error;
    }
   
    fetch_body_regex_study = pcre_study(fetch_body_regex, 0, &eb);
    if (eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    } 
error:
    return;
}

int IMAPStateGetEventInfo(const char *event_name,
                          int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, imap_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "imap's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_GENERAL;

    return 0;
}

static void IMAPStateTransactionFree (void *state, uint64_t tx_id)
{
    IMAPState *imap_state = state;
    IMAPTransaction *tx = NULL;
    TAILQ_FOREACH(tx, &imap_state->tx_list, next) {
        if (tx_id < tx->tx_id)
            break;
        else if (tx_id > tx->tx_id)
            continue;

        if (tx == imap_state->curr_tx)
            imap_state->curr_tx = NULL;
        TAILQ_REMOVE(&imap_state->tx_list, tx, next);
        IMAPTransactionFree(tx, state);
        break;
    }


}

/** \todo slow */
static uint64_t IMAPStateGetTxCnt(void *state)
{
    uint64_t cnt = 0;
    IMAPState *imap_state = state;
    if (imap_state) {
        IMAPTransaction *tx = NULL;

        if (imap_state->curr_tx == NULL)
            return 0ULL;

        TAILQ_FOREACH(tx, &imap_state->tx_list, next) {
            cnt++;
        }
    }
    SCLogDebug("returning %"PRIu64, cnt);
    return cnt;
}

static void *IMAPStateGetTx(void *state, uint64_t id)
{
    IMAPState *imap_state = state;
    if (imap_state) {
        IMAPTransaction *tx = NULL;

        if (imap_state->curr_tx == NULL)
            return NULL;
        if (imap_state->curr_tx->tx_id == id)
            return imap_state->curr_tx;

        TAILQ_FOREACH(tx, &imap_state->tx_list, next) {
            if (tx->tx_id == id)
                return tx;
        }
    }
    return NULL;
}

static int IMAPStateGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

static int IMAPStateGetAlstateProgress(void *vtx, uint8_t direction)
{
    IMAPTransaction *tx = vtx;
    return tx->done;
}

/** \internal
 *  \brief get files callback
 *  \param state state ptr
 *  \param direction flow direction
 *  \retval files files ptr
 */
static FileContainer *IMAPStateGetFiles(void *state, uint8_t direction) {
    if (state == NULL)
        return NULL;

    IMAPState *imap_state = (IMAPState *)state;

    if (direction & STREAM_TOCLIENT) {
        SCReturnPtr(NULL, "FileContainer");
    } else {
        SCReturnPtr(imap_state->files_ts, "FileContainer");
    }
}

static void IMAPStateTruncate(void *state, uint8_t direction)
{
    FileContainer *fc = IMAPStateGetFiles(state, direction);
    if (fc != NULL) {
        SCLogDebug("truncating stream, closing files in %s direction (container %p)",
                direction & STREAM_TOCLIENT ? "STREAM_TOCLIENT" : "STREAM_TOSERVER", fc);
        FileTruncateAllOpenFiles(fc);
    }
}

static AppLayerDecoderEvents *IMAPGetEvents(void *state, uint64_t tx_id)
{
    SCLogDebug("get IMAP events for TX %"PRIu64, tx_id);

    IMAPTransaction *tx = IMAPStateGetTx(state, tx_id);
    if (tx != NULL) {
        return tx->decoder_events;
    }
    return NULL;
}

static DetectEngineState *IMAPGetTxDetectState(void *vtx)
{
    IMAPTransaction *tx = (IMAPTransaction *)vtx;
    return tx->de_state;
}

static int IMAPSetTxDetectState(void *state, void *vtx, DetectEngineState *s)
{
    IMAPTransaction *tx = (IMAPTransaction *)vtx;
    tx->de_state = s;
    return 0;
}


/**
 * \brief Register the IMAP Protocol parser.
 */
void RegisterIMAPParsers(void)
{
    char *proto_name = "imap";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_IMAP, proto_name);
        AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_IMAP,
                                               "* OK", 4, 0, STREAM_TOCLIENT);
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_IMAP,
                                         IMAPStateAlloc, IMAPStateFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateGetFiles);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IMAP, STREAM_TOSERVER,
                              IMAPParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_IMAP, STREAM_TOCLIENT,
                              IMAPParseServerRecord);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_IMAP,
                                           IMAPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPGetEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_IMAP, NULL,
                                               IMAPGetTxDetectState, IMAPSetTxDetectState);

        AppLayerParserRegisterLocalStorageFunc(IPPROTO_TCP, ALPROTO_IMAP,
                                               IMAPLocalStorageAlloc,
                                               IMAPLocalStorageFree);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateTransactionFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateGetFiles);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateGetTx);
        AppLayerParserRegisterGetStateProgressCompletionStatus(ALPROTO_IMAP,
                                                               IMAPStateGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_IMAP, IMAPStateTruncate);

    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    IMAPSetMpmState();

    IMAPConfigure();

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_IMAP, IMAPParserRegisterTests);
#endif
    return;

}

/***************************************Unittests******************************/

#ifdef UNITTESTS
#endif /* UNITTESTS */

void IMAPParserRegisterTests(void)
{
#ifdef UNITTESTS
#endif /* UNITTESTS */

    return;
}
