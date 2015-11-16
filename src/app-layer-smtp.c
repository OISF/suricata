/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#include "suricata.h"
#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "threads.h"

#include "stream-tcp-private.h"
#include "stream-tcp-reassemble.h"
#include "stream-tcp.h"
#include "stream.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-smtp.h"

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

#include "util-mem.h"
#include "util-misc.h"

/* content-limit default value */
#define FILEDATA_CONTENT_LIMIT 1000
/* content-inspect-min-size default value */
#define FILEDATA_CONTENT_INSPECT_MIN_SIZE 1000
/* content-inspect-window default value */
#define FILEDATA_CONTENT_INSPECT_WINDOW 1000

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

SCEnumCharMap smtp_decoder_event_table[ ] = {
    { "INVALID_REPLY",           SMTP_DECODER_EVENT_INVALID_REPLY },
    { "UNABLE_TO_MATCH_REPLY_WITH_REQUEST",
      SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST },
    { "MAX_COMMAND_LINE_LEN_EXCEEDED",
      SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED },
    { "MAX_REPLY_LINE_LEN_EXCEEDED",
      SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED },
    { "INVALID_PIPELINED_SEQUENCE",
      SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE },
    { "BDAT_CHUNK_LEN_EXCEEDED",
      SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED },
    { "NO_SERVER_WELCOME_MESSAGE",
      SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE },
    { "TLS_REJECTED",
      SMTP_DECODER_EVENT_TLS_REJECTED },
    { "DATA_COMMAND_REJECTED",
      SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED },

    /* MIME Events */
    { "MIME_PARSE_FAILED",
      SMTP_DECODER_EVENT_MIME_PARSE_FAILED },
    { "MIME_MALFORMED_MSG",
      SMTP_DECODER_EVENT_MIME_MALFORMED_MSG },
    { "MIME_INVALID_BASE64",
      SMTP_DECODER_EVENT_MIME_INVALID_BASE64 },
    { "MIME_INVALID_QP",
      SMTP_DECODER_EVENT_MIME_INVALID_QP },
    { "MIME_LONG_LINE",
      SMTP_DECODER_EVENT_MIME_LONG_LINE },
    { "MIME_LONG_ENC_LINE",
      SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE },
    { "MIME_LONG_HEADER_NAME",
      SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME },
    { "MIME_LONG_HEADER_VALUE",
      SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE },
    { "MIME_LONG_BOUNDARY",
      SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG },

    { NULL,                      -1 },
};

#define SMTP_MPM DEFAULT_MPM

static MpmCtx *smtp_mpm_ctx = NULL;
MpmThreadCtx *smtp_mpm_thread_ctx;

/* smtp reply codes.  If an entry is made here, please make a simultaneous
 * entry in smtp_reply_map */
enum {
    SMTP_REPLY_211,
    SMTP_REPLY_214,
    SMTP_REPLY_220,
    SMTP_REPLY_221,
    SMTP_REPLY_235,
    SMTP_REPLY_250,
    SMTP_REPLY_251,
    SMTP_REPLY_252,

    SMTP_REPLY_334,
    SMTP_REPLY_354,

    SMTP_REPLY_421,
    SMTP_REPLY_450,
    SMTP_REPLY_451,
    SMTP_REPLY_452,
    SMTP_REPLY_455,

    SMTP_REPLY_500,
    SMTP_REPLY_501,
    SMTP_REPLY_502,
    SMTP_REPLY_503,
    SMTP_REPLY_504,
    SMTP_REPLY_550,
    SMTP_REPLY_551,
    SMTP_REPLY_552,
    SMTP_REPLY_553,
    SMTP_REPLY_554,
    SMTP_REPLY_555,
};

SCEnumCharMap smtp_reply_map[ ] = {
    { "211", SMTP_REPLY_211 },
    { "214", SMTP_REPLY_214 },
    { "220", SMTP_REPLY_220 },
    { "221", SMTP_REPLY_221 },
    { "235", SMTP_REPLY_235 },
    { "250", SMTP_REPLY_250 },
    { "251", SMTP_REPLY_251 },
    { "252", SMTP_REPLY_252 },

    { "334", SMTP_REPLY_334 },
    { "354", SMTP_REPLY_354 },

    { "421", SMTP_REPLY_421 },
    { "450", SMTP_REPLY_450 },
    { "451", SMTP_REPLY_451 },
    { "452", SMTP_REPLY_452 },
    { "455", SMTP_REPLY_455 },

    { "500", SMTP_REPLY_500 },
    { "501", SMTP_REPLY_501 },
    { "502", SMTP_REPLY_502 },
    { "503", SMTP_REPLY_503 },
    { "504", SMTP_REPLY_504 },
    { "550", SMTP_REPLY_550 },
    { "551", SMTP_REPLY_551 },
    { "552", SMTP_REPLY_552 },
    { "553", SMTP_REPLY_553 },
    { "554", SMTP_REPLY_554 },
    { "555", SMTP_REPLY_555 },
    {  NULL,  -1 },
};

/* Create SMTP config structure */
SMTPConfig smtp_config = { 0, { 0, 0, 0, 0, 0 }, 0, 0, 0};

static SMTPString *SMTPStringAlloc(void);

/**
 * \brief Configure SMTP Mime Decoder by parsing out mime section of YAML
 * config file
 *
 * \return none
 */
static void SMTPConfigure(void) {

    SCEnter();
    int ret = 0, val;
    intmax_t imval;
    uint32_t content_limit = 0;
    uint32_t content_inspect_min_size = 0;
    uint32_t content_inspect_window = 0;

    ConfNode *config = ConfGetNode("app-layer.protocols.smtp.mime");
    if (config != NULL) {

        ret = ConfGetChildValueBool(config, "decode-mime", &val);
        if (ret) {
            smtp_config.decode_mime = val;
        }

        ret = ConfGetChildValueBool(config, "decode-base64", &val);
        if (ret) {
            smtp_config.mime_config.decode_base64 = val;
        }

        ret = ConfGetChildValueBool(config, "decode-quoted-printable", &val);
        if (ret) {
            smtp_config.mime_config.decode_quoted_printable = val;
        }

        ret = ConfGetChildValueInt(config, "header-value-depth", &imval);
        if (ret) {
            smtp_config.mime_config.header_value_depth = (uint32_t) imval;
        }

        ret = ConfGetChildValueBool(config, "extract-urls", &val);
        if (ret) {
            smtp_config.mime_config.extract_urls = val;
        }

        ret = ConfGetChildValueBool(config, "body-md5", &val);
        if (ret) {
            smtp_config.mime_config.body_md5 = val;
        }
    }

    /* Pass mime config data to MimeDec API */
    MimeDecSetConfig(&smtp_config.mime_config);

    ConfNode *t = ConfGetNode("app-layer.protocols.smtp.inspected-tracker");
    ConfNode *p = NULL;

    if (t == NULL)
        return;

    TAILQ_FOREACH(p, &t->head, next) {
        if (strcasecmp("content-limit", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &content_limit) < 0) {
                SCLogWarning(SC_ERR_SIZE_PARSE, "Error parsing content-limit "
                             "from conf file - %s. Killing engine", p->val);
                content_limit = FILEDATA_CONTENT_LIMIT;
            }
        }

        if (strcasecmp("content-inspect-min-size", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &content_inspect_min_size) < 0) {
                SCLogWarning(SC_ERR_SIZE_PARSE, "Error parsing content-inspect-min-size-limit "
                             "from conf file - %s. Killing engine", p->val);
                content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;
            }
        }

        if (strcasecmp("content-inspect-window", p->name) == 0) {
            if (ParseSizeStringU32(p->val, &content_inspect_window) < 0) {
                SCLogWarning(SC_ERR_SIZE_PARSE, "Error parsing content-inspect-window "
                             "from conf file - %s. Killing engine", p->val);
                content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
            }
        }
    }

    SCReturn;
}

void SMTPSetEvent(SMTPState *s, uint8_t e)
{
    SCLogDebug("setting event %u", e);

    if (s->curr_tx != NULL) {
        AppLayerDecoderEventsSetEventRaw(&s->curr_tx->decoder_events, e);
//        s->events++;
        return;
    }
    SCLogDebug("couldn't set event %u", e);
}

static SMTPTransaction *SMTPTransactionCreate(void)
{
    SMTPTransaction *tx = SCCalloc(1, sizeof(*tx));
    if (tx == NULL) {
        return NULL;
    }

    TAILQ_INIT(&tx->rcpt_to_list);
    tx->mime_state = NULL;
    return tx;
}

int SMTPProcessDataChunk(const uint8_t *chunk, uint32_t len,
        MimeDecParseState *state) {

    int ret = MIME_DEC_OK;
    Flow *flow = (Flow *) state->data;
    SMTPState *smtp_state = (SMTPState *) flow->alstate;
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

    /* Determine whether to process files */
    if ((flags & (FILE_NOSTORE | FILE_NOMAGIC | FILE_NOMD5)) ==
            (FILE_NOSTORE | FILE_NOMAGIC | FILE_NOMD5)) {
        SCLogDebug("File content ignored");
        return 0;
    }

    /* Find file */
    if (entity->ctnt_flags & CTNT_IS_ATTACHMENT) {

        /* Make sure file container allocated */
        if (smtp_state->files_ts == NULL) {
            smtp_state->files_ts = FileContainerAlloc();
            if (smtp_state->files_ts == NULL) {
                ret = MIME_DEC_ERR_MEM;
                SCLogError(SC_ERR_MEM_ALLOC, "Could not create file container");
                SCReturnInt(ret);
            }
        }
        files = smtp_state->files_ts;

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

            if (FileOpenFile(files, (uint8_t *) entity->filename, entity->filename_len,
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
                        ret = MIME_DEC_ERR_DATA;
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
                    ret = MIME_DEC_ERR_DATA;
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
                ret = MIME_DEC_ERR_DATA;
            }
        }

        if (ret == 0) {
            SCLogDebug("Successfully processed file data!");
        }
    } else {
        SCLogDebug("Body not a Ctnt_attachment");
    }

    if (files != NULL) {
        FilePrune(files);
    }

    SCReturnInt(ret);
}

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
             * attempt.  With multi payload smtp chunks we can have valid
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
             * attempt.  With multi payload smtp chunks we can have valid
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

static int SMTPInsertCommandIntoCommandBuffer(uint8_t command, SMTPState *state, Flow *f)
{
    SCEnter();
    void *ptmp;

    if (state->cmds_cnt >= state->cmds_buffer_len) {
        int increment = SMTP_COMMAND_BUFFER_STEPS;
        if ((int)(state->cmds_buffer_len + SMTP_COMMAND_BUFFER_STEPS) > (int)USHRT_MAX) {
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
    if (state->cmds_cnt >= 1 &&
        ((state->cmds[state->cmds_cnt - 1] == SMTP_COMMAND_STARTTLS) ||
         (state->cmds[state->cmds_cnt - 1] == SMTP_COMMAND_DATA))) {
        /* decoder event */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE);
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

static int SMTPProcessCommandBDAT(SMTPState *state, Flow *f,
                                  AppLayerParserState *pstate)
{
    SCEnter();

    state->bdat_chunk_idx += (state->current_line_len +
                              state->current_line_delimiter_len);
    if (state->bdat_chunk_idx > state->bdat_chunk_len) {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        /* decoder event */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED);
        SCReturnInt(-1);
    } else if (state->bdat_chunk_idx == state->bdat_chunk_len) {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
    }

    SCReturnInt(0);
}

static int SMTPProcessCommandDATA(SMTPState *state, Flow *f,
                                  AppLayerParserState *pstate)
{
    SCEnter();

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
        SMTPInsertCommandIntoCommandBuffer(SMTP_COMMAND_DATA_MODE, state, f);

        if (smtp_config.decode_mime) {
            /* Complete parsing task */
            int ret = MimeDecParseComplete(state->curr_tx->mime_state);
            if (ret != MIME_DEC_OK) {

                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_PARSE_FAILED);
                SCLogDebug("MimeDecParseComplete() function failed");
            }

            /* Generate decoder events */
            MimeDecEntity *msg = state->curr_tx->mime_state->msg;
            if (msg->anomaly_flags & ANOM_INVALID_BASE64) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_INVALID_BASE64);
            }
            if (msg->anomaly_flags & ANOM_INVALID_QP) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_INVALID_QP);
            }
            if (msg->anomaly_flags & ANOM_LONG_LINE) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_LINE);
            }
            if (msg->anomaly_flags & ANOM_LONG_ENC_LINE) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE);
            }
            if (msg->anomaly_flags & ANOM_LONG_HEADER_NAME) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME);
            }
            if (msg->anomaly_flags & ANOM_LONG_HEADER_VALUE) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE);
            }
            if (msg->anomaly_flags & ANOM_MALFORMED_MSG) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_MALFORMED_MSG);
            }
            if (msg->anomaly_flags & ANOM_LONG_BOUNDARY) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG);
            }
        }
        state->curr_tx->done = 1;
        SCLogDebug("marked tx as done");
    }

    /* If DATA, then parse out a MIME message */
    if (state->current_command == SMTP_COMMAND_DATA &&
            (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        if (smtp_config.decode_mime && state->curr_tx->mime_state) {
            int ret = MimeDecParseLine((const uint8_t *) state->current_line,
                    state->current_line_len, state->current_line_delimiter_len,
                    state->curr_tx->mime_state);
            if (ret != MIME_DEC_OK) {
                SCLogDebug("MimeDecParseLine() function returned an error code: %d", ret);
            }
        }
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
    SCEnter();

    uint64_t reply_code = 0;
    PatternMatcherQueue *pmq = state->thread_local_data;

    /* the reply code has to contain at least 3 bytes, to hold the 3 digit
     * reply code */
    if (state->current_line_len < 3) {
        /* decoder event */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
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

    /* I don't like this pmq reset here.  We'll devise a method later, that
     * should make the use of the mpm very efficient */
    PmqReset(pmq);
    int mpm_cnt = mpm_table[SMTP_MPM].Search(smtp_mpm_ctx, smtp_mpm_thread_ctx,
                                             pmq, state->current_line,
                                             3);
    if (mpm_cnt == 0) {
        /* set decoder event - reply code invalid */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
        SCLogDebug("invalid reply code %02x %02x %02x",
                state->current_line[0], state->current_line[1], state->current_line[2]);
        SCReturnInt(-1);
    }
    reply_code = smtp_reply_map[pmq->pattern_id_array[0]].enum_value;

    if (state->cmds_idx == state->cmds_cnt) {
        if (!(state->parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
            /* the first server reply can be a multiline message. Let's
             * flag the fact that we have seen the first reply only at the end
             * of a multiline reply
             */
            if (!(state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY))
                state->parser_state |= SMTP_PARSER_STATE_FIRST_REPLY_SEEN;
            if (reply_code == SMTP_REPLY_220)
                SCReturnInt(0);
            else
                SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
        } else {
            /* decoder event - unable to match reply with request */
            SCLogDebug("unable to match reply with request");
            SCReturnInt(-1);
        }
    }

    if (state->cmds_cnt == 0) {
        /* reply but not a command we have stored, fall through */
    } else if (state->cmds[state->cmds_idx] == SMTP_COMMAND_STARTTLS) {
        if (reply_code == SMTP_REPLY_220) {
            /* we are entering STARRTTLS data mode */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            AppLayerParserStateSetFlag(pstate,
                                             APP_LAYER_PARSER_NO_INSPECTION |
                                             APP_LAYER_PARSER_NO_REASSEMBLY);
        } else {
            /* decoder event */
            SMTPSetEvent(state, SMTP_DECODER_EVENT_TLS_REJECTED);
        }
    } else if (state->cmds[state->cmds_idx] == SMTP_COMMAND_DATA) {
        if (reply_code == SMTP_REPLY_354) {
            /* Next comes the mail for the DATA command in toserver direction */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else {
            /* decoder event */
            SMTPSetEvent(state, SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED);
        }
    } else {
        /* we don't care for any other command for now */
        /* check if reply falls in the valid list of replies for SMTP.  If not
         * decoder event */
    }

    /* if it is a multi-line reply, we need to move the index only once for all
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
    SCEnter();

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
    char *endptr = NULL;
    state->bdat_chunk_len = strtoul((const char *)state->current_line + i,
                                    (char **)&endptr, 10);
    if ((uint8_t *)endptr == state->current_line + i) {
        /* decoder event */
        return -1;
    }

    return 0;
}

static int SMTPParseCommandWithParam(SMTPState *state, uint8_t prefix_len, uint8_t **target, uint16_t *target_len)
{
    int i = prefix_len + 1;
    int spc_i = 0;

    while (i < state->current_line_len) {
        if (state->current_line[i] != ' ') {
            break;
        }
        i++;
    }

    /* rfc1870: with the size extension the mail from can be followed by an option.
       We use the space separator to detect it. */
    spc_i = i;
    while (spc_i < state->current_line_len) {
        if (state->current_line[spc_i] == ' ') {
            break;
        }
        spc_i++;
    }

    *target = SCMalloc(spc_i - i + 1);
    if (*target == NULL)
        return -1;
    memcpy(*target, state->current_line + i, spc_i - i);
    (*target)[spc_i - i] = '\0';
    *target_len = spc_i - i;

    return 0;
}

static int SMTPParseCommandHELO(SMTPState *state)
{
    return SMTPParseCommandWithParam(state, 4, &state->helo, &state->helo_len);
}

static int SMTPParseCommandMAILFROM(SMTPState *state)
{
    return SMTPParseCommandWithParam(state, 9,
                                     &state->curr_tx->mail_from,
                                     &state->curr_tx->mail_from_len);
}

static int SMTPParseCommandRCPTTO(SMTPState *state)
{
    uint8_t *rcptto;
    uint16_t rcptto_len;

    if (SMTPParseCommandWithParam(state, 7, &rcptto, &rcptto_len) == 0) {
        SMTPString *rcptto_str = SMTPStringAlloc();
        if (rcptto_str) {
            rcptto_str->str = rcptto;
            rcptto_str->len = rcptto_len;
            TAILQ_INSERT_TAIL(&state->curr_tx->rcpt_to_list, rcptto_str, next);
        } else {
            SCFree(rcptto);
            return -1;
        }
    } else {
        return -1;
    }
    return 0;
}

/* consider 'rset' and 'quit' to be part of the existing state */
static int NoNewTx(SMTPState *state)
{
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        if (state->current_line_len >= 4 &&
            SCMemcmpLowercase("rset", state->current_line, 4) == 0) {
            return 1;
        } else if (state->current_line_len >= 4 &&
            SCMemcmpLowercase("quit", state->current_line, 4) == 0) {
            return 1;
        }
    }
    return 0;
}

static int SMTPProcessRequest(SMTPState *state, Flow *f,
                              AppLayerParserState *pstate)
{
    SCEnter();
    SMTPTransaction *tx = state->curr_tx;

    if (state->curr_tx == NULL || (state->curr_tx->done && !NoNewTx(state))) {
        tx = SMTPTransactionCreate();
        if (tx == NULL)
            return -1;
        state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
        tx->tx_id = state->tx_cnt++;
    }

    if (!(state->parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE);
    }

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
            if (smtp_config.decode_mime) {
                tx->mime_state = MimeDecInitParser(f, SMTPProcessDataChunk);
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

        } else if (state->current_line_len >= 4 &&
                   SCMemcmpLowercase("bdat", state->current_line, 4) == 0) {
            r = SMTPParseCommandBDAT(state);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_BDAT;
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else if (state->current_line_len >= 4 &&
                   ((SCMemcmpLowercase("helo", state->current_line, 4) == 0) ||
                    SCMemcmpLowercase("ehlo", state->current_line, 4) == 0))  {
            r = SMTPParseCommandHELO(state);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else if (state->current_line_len >= 9 &&
                   SCMemcmpLowercase("mail from", state->current_line, 9) == 0) {
            r = SMTPParseCommandMAILFROM(state);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else if (state->current_line_len >= 7 &&
                   SCMemcmpLowercase("rcpt to", state->current_line, 7) == 0) {
            r = SMTPParseCommandRCPTTO(state);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else {
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        }

        /* Every command is inserted into a command buffer, to be matched
         * against reply(ies) sent by the server */
        if (SMTPInsertCommandIntoCommandBuffer(state->current_command,
                                               state, f) == -1) {
            SCReturnInt(-1);
        }

        SCReturnInt(r);
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
            SCReturnInt(0);
    }
}

static int SMTPParse(int direction, Flow *f, SMTPState *state,
                     AppLayerParserState *pstate, uint8_t *input,
                     uint32_t input_len,
                     PatternMatcherQueue *local_data)
{
    SCEnter();

    if (input == NULL && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF)) {
        SCReturnInt(1);
    } else if (input == NULL || input_len == 0) {
        SCReturnInt(-1);
    }

    state->input = input;
    state->input_len = input_len;
    state->direction = direction;
    state->thread_local_data = local_data;

    /* toserver */
    if (direction == 0) {
        while (SMTPGetLine(state) >= 0) {
            if (SMTPProcessRequest(state, f, pstate) == -1)
                SCReturnInt(-1);
        }

        /* toclient */
    } else {
        while (SMTPGetLine(state) >= 0) {
            if (SMTPProcessReply(state, f, pstate) == -1)
                SCReturnInt(-1);
        }
    }

    SCReturnInt(0);
}

static int SMTPParseClientRecord(Flow *f, void *alstate,
                                 AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 void *local_data)
{
    SCEnter();

    /* first arg 0 is toserver */
    return SMTPParse(0, f, alstate, pstate, input, input_len, local_data);
}

static int SMTPParseServerRecord(Flow *f, void *alstate,
                                 AppLayerParserState *pstate,
                                 uint8_t *input, uint32_t input_len,
                                 void *local_data)
{
    SCEnter();

    /* first arg 1 is toclient */
    return SMTPParse(1, f, alstate, pstate, input, input_len, local_data);

    return 0;
}

/**
 * \internal
 * \brief Function to allocate SMTP state memory.
 */
void *SMTPStateAlloc(void)
{
    SMTPState *smtp_state = SCMalloc(sizeof(SMTPState));
    if (unlikely(smtp_state == NULL))
        return NULL;
    memset(smtp_state, 0, sizeof(SMTPState));

    smtp_state->cmds = SCMalloc(sizeof(uint8_t) *
                                SMTP_COMMAND_BUFFER_STEPS);
    if (smtp_state->cmds == NULL) {
        SCFree(smtp_state);
        return NULL;
    }
    smtp_state->cmds_buffer_len = SMTP_COMMAND_BUFFER_STEPS;

    TAILQ_INIT(&smtp_state->tx_list);

    return smtp_state;
}

static SMTPString *SMTPStringAlloc(void)
{
    SMTPString *smtp_string = SCMalloc(sizeof(SMTPString));
    if (unlikely(smtp_string == NULL))
        return NULL;
    memset(smtp_string, 0, sizeof(SMTPString));

    return smtp_string;
}


static void SMTPStringFree(SMTPString *str)
{
    if (str->str) {
        SCFree(str->str);
    }
    SCFree(str);
}

static void *SMTPLocalStorageAlloc(void)
{
    /* needed by the mpm */
    PatternMatcherQueue *pmq = SCMalloc(sizeof(PatternMatcherQueue));
    if (unlikely(pmq == NULL)) {
        exit(EXIT_FAILURE);
    }
    PmqSetup(pmq,
             sizeof(smtp_reply_map)/sizeof(SCEnumCharMap) - 2);

    return pmq;
}

static void SMTPLocalStorageFree(void *pmq)
{
    if (pmq != NULL) {
        PmqFree(pmq);
        SCFree(pmq);
    }

    return;
}

static void SMTPTransactionFree(SMTPTransaction *tx, SMTPState *state)
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

    if (tx->mail_from)
        SCFree(tx->mail_from);

    SMTPString *str = NULL;
    while ((str = TAILQ_FIRST(&tx->rcpt_to_list))) {
        TAILQ_REMOVE(&tx->rcpt_to_list, str, next);
        SMTPStringFree(str);
    }
#if 0
        if (tx->decoder_events->cnt <= smtp_state->events)
            smtp_state->events -= tx->decoder_events->cnt;
        else
            smtp_state->events = 0;
#endif
    SCFree(tx);
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

    if (smtp_state->helo) {
        SCFree(smtp_state->helo);
    }

    FileContainerFree(smtp_state->files_ts);

    SMTPTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&smtp_state->tx_list))) {
        TAILQ_REMOVE(&smtp_state->tx_list, tx, next);
        SMTPTransactionFree(tx, smtp_state);
    }

    SCFree(smtp_state);

    return;
}

static void SMTPSetMpmState(void)
{
    smtp_mpm_ctx = SCMalloc(sizeof(MpmCtx));
    if (unlikely(smtp_mpm_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(smtp_mpm_ctx, 0, sizeof(MpmCtx));
    MpmInitCtx(smtp_mpm_ctx, SMTP_MPM);

    smtp_mpm_thread_ctx = SCMalloc(sizeof(MpmThreadCtx));
    if (unlikely(smtp_mpm_thread_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(smtp_mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitThreadCtx(smtp_mpm_thread_ctx, SMTP_MPM, 0);

    uint32_t i = 0;
    for (i = 0; i < sizeof(smtp_reply_map)/sizeof(SCEnumCharMap) - 1; i++) {
        SCEnumCharMap *map = &smtp_reply_map[i];
        /* The third argument is 3, because reply code is always 3 bytes. */
        MpmAddPatternCI(smtp_mpm_ctx, (uint8_t *)map->enum_name, 3,
                        0 /* defunct */, 0 /* defunct */,
                        i /* pattern id */, 0, 0 /* no flags */);
    }

    mpm_table[SMTP_MPM].Prepare(smtp_mpm_ctx);
}

int SMTPStateGetEventInfo(const char *event_name,
                          int *event_id, AppLayerEventType *event_type)
{
    *event_id = SCMapEnumNameToValue(event_name, smtp_decoder_event_table);
    if (*event_id == -1) {
        SCLogError(SC_ERR_INVALID_ENUM_MAP, "event \"%s\" not present in "
                   "smtp's enum map table.",  event_name);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static int SMTPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMTP,
                                               "EHLO", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMTP,
                                               "HELO", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCS(IPPROTO_TCP, ALPROTO_SMTP,
                                               "QUIT", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }

    return 0;
}

static void SMTPStateTransactionFree (void *state, uint64_t tx_id)
{
    SMTPState *smtp_state = state;
    SMTPTransaction *tx = NULL;
    TAILQ_FOREACH(tx, &smtp_state->tx_list, next) {
        if (tx_id < tx->tx_id)
            break;
        else if (tx_id > tx->tx_id)
            continue;

        if (tx == smtp_state->curr_tx)
            smtp_state->curr_tx = NULL;
        TAILQ_REMOVE(&smtp_state->tx_list, tx, next);
        SMTPTransactionFree(tx, state);
        break;
    }


}

/** \retval cnt highest tx id */
static uint64_t SMTPStateGetTxCnt(void *state)
{
    uint64_t cnt = 0;
    SMTPState *smtp_state = state;
    if (smtp_state) {
        cnt = smtp_state->tx_cnt;
    }
    SCLogDebug("returning %"PRIu64, cnt);
    return cnt;
}

static void *SMTPStateGetTx(void *state, uint64_t id)
{
    SMTPState *smtp_state = state;
    if (smtp_state) {
        SMTPTransaction *tx = NULL;

        if (smtp_state->curr_tx == NULL)
            return NULL;
        if (smtp_state->curr_tx->tx_id == id)
            return smtp_state->curr_tx;

        TAILQ_FOREACH(tx, &smtp_state->tx_list, next) {
            if (tx->tx_id == id)
                return tx;
        }
    }
    return NULL;

}

static int SMTPStateGetAlstateProgressCompletionStatus(uint8_t direction) {
    return 1;
}

static int SMTPStateGetAlstateProgress(void *vtx, uint8_t direction)
{
    SMTPTransaction *tx = vtx;
    return tx->done;
}

static FileContainer *SMTPStateGetFiles(void *state, uint8_t direction)
{
    if (state == NULL)
        return NULL;

    SMTPState *smtp_state = (SMTPState *)state;

    if (direction & STREAM_TOCLIENT) {
        SCReturnPtr(NULL, "FileContainer");
    } else {
        SCLogDebug("smtp_state->files_ts %p", smtp_state->files_ts);
        SCReturnPtr(smtp_state->files_ts, "FileContainer");
    }
}

static void SMTPStateTruncate(void *state, uint8_t direction)
{
    FileContainer *fc = SMTPStateGetFiles(state, direction);
    if (fc != NULL) {
        SCLogDebug("truncating stream, closing files in %s direction (container %p)",
                direction & STREAM_TOCLIENT ? "STREAM_TOCLIENT" : "STREAM_TOSERVER", fc);
        FileTruncateAllOpenFiles(fc);
    }
}

static AppLayerDecoderEvents *SMTPGetEvents(void *state, uint64_t tx_id)
{
    SCLogDebug("get SMTP events for TX %"PRIu64, tx_id);

    SMTPTransaction *tx = SMTPStateGetTx(state, tx_id);
    if (tx != NULL) {
        return tx->decoder_events;
    }
    return NULL;
}

static DetectEngineState *SMTPGetTxDetectState(void *vtx)
{
    SMTPTransaction *tx = (SMTPTransaction *)vtx;
    return tx->de_state;
}

static int SMTPSetTxDetectState(void *state, void *vtx, DetectEngineState *s)
{
    SMTPTransaction *tx = (SMTPTransaction *)vtx;
    tx->de_state = s;
    return 0;
}

/**
 * \brief Register the SMTP Protocol parser.
 */
void RegisterSMTPParsers(void)
{
    char *proto_name = "smtp";

    if (AppLayerProtoDetectConfProtoDetectionEnabled("tcp", proto_name)) {
        AppLayerProtoDetectRegisterProtocol(ALPROTO_SMTP, proto_name);
        if (SMTPRegisterPatternsForProtocolDetection() < 0 )
            return;
    } else {
        SCLogInfo("Protocol detection and parser disabled for %s protocol.",
                  proto_name);
        return;
    }

    if (AppLayerParserConfParserEnabled("tcp", proto_name)) {
        AppLayerParserRegisterStateFuncs(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateAlloc, SMTPStateFree);

        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMTP, STREAM_TOSERVER,
                                     SMTPParseClientRecord);
        AppLayerParserRegisterParser(IPPROTO_TCP, ALPROTO_SMTP, STREAM_TOCLIENT,
                                     SMTPParseServerRecord);

        AppLayerParserRegisterGetEventInfo(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetEventInfo);
        AppLayerParserRegisterGetEventsFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPGetEvents);
        AppLayerParserRegisterDetectStateFuncs(IPPROTO_TCP, ALPROTO_SMTP, NULL,
                                               SMTPGetTxDetectState, SMTPSetTxDetectState);

        AppLayerParserRegisterLocalStorageFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPLocalStorageAlloc,
                                               SMTPLocalStorageFree);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateTransactionFree);
        AppLayerParserRegisterGetFilesFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetFiles);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetTx);
        AppLayerParserRegisterGetStateProgressCompletionStatus(IPPROTO_TCP, ALPROTO_SMTP,
                                                               SMTPStateGetAlstateProgressCompletionStatus);
        AppLayerParserRegisterTruncateFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateTruncate);
    } else {
        SCLogInfo("Parsed disabled for %s protocol. Protocol detection"
                  "still on.", proto_name);
    }

    SMTPSetMpmState();

    SMTPConfigure();

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SMTP, SMTPParserRegisterTests);
#endif
    return;
}

/***************************************Unittests******************************/

#ifdef UNITTESTS

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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if (!(f.flags & FLOW_NOPAYLOAD_INSPECTION) ||
        !(ssn.flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
        !(((TcpSession *)f.protoctx)->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        !(((TcpSession *)f.protoctx)->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply4, reply4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5_1, request5_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5_2, request5_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5_3, request5_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5_4, request5_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5_5, request5_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply5, reply5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply6, reply6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request7, request7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply7, reply7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request8, request8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply8, reply8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request9_1, request9_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request9_2, request9_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request9_3, request9_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request9_4, request9_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                                     SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request9_5, request9_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply9, reply9_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request10, request10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply10, reply10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if ((f.flags & FLOW_NOPAYLOAD_INSPECTION) ||
        (ssn.flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
        (((TcpSession *)f.protoctx)->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (((TcpSession *)f.protoctx)->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
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
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 1 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
        smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
        smtp_state->cmds_cnt != 0 ||
        smtp_state->cmds_idx != 0 ||
        smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request5, request5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
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
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test retrieving lines when frag'ed.
 */
int SMTPParserTest07(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    const char *request1_str = "EHLO boo.com";
    /* EHLO boo.com<CR> */
    uint8_t request1_1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d,
    };
    int32_t request1_1_len = sizeof(request1_1);

    /* <LF> */
    uint8_t request1_2[] = {
        0x0a
    };
    int32_t request1_2_len = sizeof(request1_2);

    /* EHLO boo.com<CR><LF> */
    uint8_t request2[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request2_len = sizeof(request2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_1, request1_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->current_line != NULL ||
        smtp_state->current_line_len != 0 ||
        smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != request1_1_len ||
        memcmp(smtp_state->ts_db, request1_1, request1_1_len) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_2, request1_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->ts_db, request1_str, strlen(request1_str)) != 0 ||
        smtp_state->current_line != smtp_state->ts_db ||
        smtp_state->current_line_len != smtp_state->ts_db_len) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 0 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        smtp_state->current_line == NULL ||
        smtp_state->current_line_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->current_line, request1_str, strlen(request1_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test retrieving lines when frag'ed.
 */
int SMTPParserTest08(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    const char *request1_str = "EHLO boo.com";
    /* EHLO boo.com */
    uint8_t request1_1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d,
    };
    int32_t request1_1_len = sizeof(request1_1);

    /* <CR><LF> */
    uint8_t request1_2[] = {
        0x0d, 0x0a
    };
    int32_t request1_2_len = sizeof(request1_2);

    /* EHLO boo.com<CR><LF> */
    uint8_t request2[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request2_len = sizeof(request2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_1, request1_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->current_line != NULL ||
        smtp_state->current_line_len != 0 ||
        smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != request1_1_len ||
        memcmp(smtp_state->ts_db, request1_1, request1_1_len) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_2, request1_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->ts_db, request1_str, strlen(request1_str)) != 0 ||
        smtp_state->current_line != smtp_state->ts_db ||
        smtp_state->current_line_len != smtp_state->ts_db_len) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 0 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        smtp_state->current_line == NULL ||
        smtp_state->current_line_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->current_line, request1_str, strlen(request1_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test retrieving lines when frag'ed.
 */
int SMTPParserTest09(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    const char *request1_str = "EHLO boo.com";
    /* EHLO boo. */
    uint8_t request1_1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e,
    };
    int32_t request1_1_len = sizeof(request1_1);

    /* com<CR><LF> */
    uint8_t request1_2[] = {
        0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    int32_t request1_2_len = sizeof(request1_2);

    /* EHLO boo.com<CR><LF> */
    uint8_t request2[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request2_len = sizeof(request2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_1, request1_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->current_line != NULL ||
        smtp_state->current_line_len != 0 ||
        smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != request1_1_len ||
        memcmp(smtp_state->ts_db, request1_1, request1_1_len) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_2, request1_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->ts_db, request1_str, strlen(request1_str)) != 0 ||
        smtp_state->current_line != smtp_state->ts_db ||
        smtp_state->current_line_len != smtp_state->ts_db_len) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 0 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        smtp_state->current_line == NULL ||
        smtp_state->current_line_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->current_line, request1_str, strlen(request1_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test retrieving lines when frag'ed.
 */
int SMTPParserTest10(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    const char *request1_str = "";
    /* EHLO boo. */
    uint8_t request1_1[] = {
        0x0d,
    };
    int32_t request1_1_len = sizeof(request1_1);

    /* com<CR><LF> */
    uint8_t request1_2[] = {
        0x0a,
    };
    int32_t request1_2_len = sizeof(request1_2);

    const char *request2_str = "EHLO boo.com";
    /* EHLO boo.com<CR><LF> */
    uint8_t request2[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request2_len = sizeof(request2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_1, request1_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->current_line != NULL ||
        smtp_state->current_line_len != 0 ||
        smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != request1_1_len ||
        memcmp(smtp_state->ts_db, request1_1, request1_1_len) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1_2, request1_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 1 ||
        smtp_state->ts_db == NULL ||
        smtp_state->ts_db_len != (int32_t)strlen(request1_str) ||
        memcmp(smtp_state->ts_db, request1_str, strlen(request1_str)) != 0 ||
        smtp_state->current_line != smtp_state->ts_db ||
        smtp_state->current_line_len != smtp_state->ts_db_len) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 0 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        smtp_state->current_line == NULL ||
        smtp_state->current_line_len != (int32_t)strlen(request2_str) ||
        memcmp(smtp_state->current_line, request2_str, strlen(request2_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test retrieving lines when frag'ed.
 */
int SMTPParserTest11(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    const char *request1_str = "";
    /* EHLO boo. */
    uint8_t request1[] = {
        0x0a,
    };
    int32_t request1_len = sizeof(request1);

    const char *request2_str = "EHLO boo.com";
    /* EHLO boo.com<CR><LF> */
    uint8_t request2[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request2_len = sizeof(request2);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->current_line == NULL ||
        smtp_state->current_line_len != 0 ||
        smtp_state->ts_current_line_db == 1 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        memcmp(smtp_state->current_line, request1_str, strlen(request1_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->ts_current_line_db != 0 ||
        smtp_state->ts_db != NULL ||
        smtp_state->ts_db_len != 0 ||
        smtp_state->current_line == NULL ||
        smtp_state->current_line_len != (int32_t)strlen(request2_str) ||
        memcmp(smtp_state->current_line, request2_str, strlen(request2_str)) != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

int SMTPParserTest12(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    SMTPState *smtp_state = NULL;
    int r = 0;

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request1_len = sizeof(request1);

    /* 388<CR><LF>
     */
    uint8_t reply1[] = {
        0x31, 0x38, 0x38, 0x0d, 0x0a,
    };
    uint32_t reply1_len = sizeof(reply1);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any "
                                   "(msg:\"SMTP event handling\"; "
                                   "app-layer-event: smtp.invalid_reply; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER | STREAM_START,
                            request1, request1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched.  It shouldn't match: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT | STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r == 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match.  Should have matched: ");
        goto end;
    }

    result = 1;

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

int SMTPParserTest13(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    SMTPState *smtp_state = NULL;
    int r = 0;

    /* EHLO boo.com<CR><LF> */
    uint8_t request1[] = {
        0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
        0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a,
    };
    int32_t request1_len = sizeof(request1);

    /* 250<CR><LF>
     */
    uint8_t reply1[] = {
        0x32, 0x35, 0x30, 0x0d, 0x0a,
    };
    uint32_t reply1_len = sizeof(reply1);

    /* MAIL FROM:pbsf@asdfs.com<CR><LF>
     * RCPT TO:pbsf@asdfs.com<CR><LF>
     * DATA<CR><LF>
     * STARTTLS<CR><LF>
     */
    uint8_t request2[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x52, 0x43, 0x50, 0x54, 0x20, 0x54,
        0x4f, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a,
        0x53, 0x54, 0x41, 0x52, 0x54, 0x54, 0x4c, 0x53,
        0x0d, 0x0a
    };
    uint32_t request2_len = sizeof(request2);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                              "(msg:\"SMTP event handling\"; "
                              "app-layer-event: "
                              "smtp.invalid_pipelined_sequence; "
                              "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER | STREAM_START,
                            request1, request1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched.  It shouldn't match: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
                            reply1, reply1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched.  It shouldn't match: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request2, request2_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't match.  Should have matched: ");
        goto end;
    }

    result = 1;

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test DATA command w/MIME message.
 */
int SMTPParserTest14(void)
{
    int result = 0;
    Flow f;
    int r = 0;

    /* 220 mx.google.com ESMTP d15sm986283wfl.6<CR><LF> */
    static uint8_t welcome_reply[] = {
            0x32, 0x32, 0x30, 0x20, 0x6d, 0x78, 0x2e, 0x67,
            0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
            0x6d, 0x20, 0x45, 0x53, 0x4d, 0x54, 0x50, 0x20,
            0x64, 0x31, 0x35, 0x73, 0x6d, 0x39, 0x38, 0x36,
            0x32, 0x38, 0x33, 0x77, 0x66, 0x6c, 0x2e, 0x36,
            0x0d, 0x0a
    };
    static uint32_t welcome_reply_len = sizeof(welcome_reply);

    /* EHLO boo.com<CR><LF> */
    static uint8_t request1[] = {
            0x45, 0x48, 0x4c, 0x4f, 0x20, 0x62, 0x6f, 0x6f,
            0x2e, 0x63, 0x6f, 0x6d, 0x0d, 0x0a
    };
    static uint32_t request1_len = sizeof(request1);
    /* 250-mx.google.com at your service, [117.198.115.50]<CR><LF>
     * 250-SIZE 35882577<CR><LF>
     * 250-8BITMIME<CR><LF>
     * 250-STARTTLS<CR><LF>
     * 250 ENHANCEDSTATUSCODES<CR><LF>
     */
    static uint8_t reply1[] = {
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
    static uint32_t reply1_len = sizeof(reply1);

    /* MAIL FROM:asdff@asdf.com<CR><LF> */
    static uint8_t request2[] = {
            0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
            0x4d, 0x3a, 0x61, 0x73, 0x64, 0x66, 0x66, 0x40,
            0x61, 0x73, 0x64, 0x66, 0x2e, 0x63, 0x6f, 0x6d,
            0x0d, 0x0a
    };
    static uint32_t request2_len = sizeof(request2);
    /* 250 2.1.0 Ok<CR><LF> */
    static uint8_t reply2[] = {
            0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
            0x30, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    static uint32_t reply2_len = sizeof(reply2);

    /* RCPT TO:bimbs@gmail.com<CR><LF> */
    static uint8_t request3[] = {
            0x52, 0x43, 0x50, 0x54, 0x20, 0x54, 0x4f, 0x3a,
            0x62, 0x69, 0x6d, 0x62, 0x73, 0x40, 0x67, 0x6d,
            0x61, 0x69, 0x6c, 0x2e, 0x63, 0x6f, 0x6d, 0x0d,
            0x0a
    };
    static uint32_t request3_len = sizeof(request3);
    /* 250 2.1.5 Ok<CR><LF> */
    static uint8_t reply3[] = {
            0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x31, 0x2e,
            0x35, 0x20, 0x4f, 0x6b, 0x0d, 0x0a
    };
    static uint32_t reply3_len = sizeof(reply3);

    /* DATA<CR><LF> */
    static uint8_t request4[] = {
            0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a
    };
    static uint32_t request4_len = sizeof(request4);
    /* 354 End data with <CR><LF>.<CR><LF>|<CR><LF>| */
    static uint8_t reply4[] = {
            0x33, 0x35, 0x34, 0x20, 0x45, 0x6e, 0x64, 0x20,
            0x64, 0x61, 0x74, 0x61, 0x20, 0x77, 0x69, 0x74,
            0x68, 0x20, 0x3c, 0x43, 0x52, 0x3e, 0x3c, 0x4c,
            0x46, 0x3e, 0x2e, 0x3c, 0x43, 0x52, 0x3e, 0x3c,
            0x4c, 0x46, 0x3e, 0x0d, 0x0a
    };
    static uint32_t reply4_len = sizeof(reply4);

    /* MIME_MSG */
    static uint64_t filesize = 133;
    static uint8_t request4_msg[] = {
            0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,
            0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
            0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
            0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A,
            0x20, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61,
            0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6F, 0x63, 0x74,
            0x65, 0x74, 0x2D, 0x73, 0x74, 0x72, 0x65, 0x61,
            0x6D, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
            0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61, 0x6E, 0x73,
            0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E, 0x63, 0x6F,
            0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x62, 0x61,
            0x73, 0x65, 0x36, 0x34, 0x0D, 0x0A, 0x43, 0x6F,
            0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x44, 0x69,
            0x73, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x69, 0x6F,
            0x6E, 0x3A, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63,
            0x68, 0x6D, 0x65, 0x6E, 0x74, 0x3B, 0x20, 0x66,
            0x69, 0x6C, 0x65, 0x6E, 0x61, 0x6D, 0x65, 0x3D,
            0x22, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x65, 0x78,
            0x65, 0x22, 0x3B, 0x0D, 0x0A, 0x0D, 0x0A, 0x54,
            0x56, 0x6F, 0x41, 0x41, 0x46, 0x42, 0x46, 0x41,
            0x41, 0x42, 0x4D, 0x41, 0x51, 0x45, 0x41, 0x61,
            0x69, 0x70, 0x59, 0x77, 0x77, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x42,
            0x41, 0x41, 0x44, 0x41, 0x51, 0x73, 0x42, 0x43,
            0x41, 0x41, 0x42, 0x41, 0x41, 0x43, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x48, 0x6B, 0x41, 0x41,
            0x41, 0x41, 0x4D, 0x41, 0x41, 0x41, 0x41, 0x65,
            0x51, 0x41, 0x41, 0x41, 0x41, 0x77, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x45, 0x41, 0x41, 0x42,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x51, 0x41, 0x41,
            0x41, 0x42, 0x30, 0x41, 0x41, 0x41, 0x41, 0x49,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x51, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x42,
            0x41, 0x45, 0x41, 0x41, 0x49, 0x67, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x67, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x42, 0x63, 0x58, 0x44, 0x59, 0x32, 0x4C,
            0x6A, 0x6B, 0x7A, 0x4C, 0x6A, 0x59, 0x34, 0x4C,
            0x6A, 0x5A, 0x63, 0x65, 0x67, 0x41, 0x41, 0x4F,
            0x41, 0x3D, 0x3D, 0x0D,0x0A    };
    static uint32_t request4_msg_len = sizeof(request4_msg);

    /* DATA COMPLETED */
    static uint8_t request4_end[] = {
            0x0d, 0x0a, 0x2e, 0x0d, 0x0a
    };
    static uint32_t request4_end_len = sizeof(request4_end);
    /* 250 2.0.0 Ok: queued as 6A1AF20BF2<CR><LF> */
    static uint8_t reply4_end[] = {
            0x32, 0x35, 0x30, 0x20, 0x32, 0x2e, 0x30, 0x2e,
            0x30, 0x20, 0x4f, 0x6b, 0x3a, 0x20, 0x71, 0x75,
            0x65, 0x75, 0x65, 0x64, 0x20, 0x61, 0x73, 0x20,
            0x36, 0x41, 0x31, 0x41, 0x46, 0x32, 0x30, 0x42,
            0x46, 0x32, 0x0d, 0x0a
    };
    static uint32_t reply4_end_len = sizeof(reply4_end);

    /* QUIT<CR><LF> */
    static uint8_t request5[] = {
            0x51, 0x55, 0x49, 0x54, 0x0d, 0x0a
    };
    static uint32_t request5_len = sizeof(request5);
    /* 221 2.0.0 Bye<CR><LF> */
    static uint8_t reply5[] = {
            0x32, 0x32, 0x31, 0x20, 0x32, 0x2e, 0x30, 0x2e,
            0x30, 0x20, 0x42, 0x79, 0x65, 0x0d, 0x0a
    };
    static uint32_t reply5_len = sizeof(reply5);

    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;

    StreamTcpInitConfig(TRUE);

    SCMutexLock(&f.m);
    /* Welcome reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
                            request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* EHLO Reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    if ((smtp_state->helo_len != 7) || strncmp("boo.com", (char *)smtp_state->helo, 7)) {
        printf("incorrect parsing of HELO field '%s' (%d)\n", smtp_state->helo, smtp_state->helo_len);
        SCMutexUnlock(&f.m);
        goto end;
    }

    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* MAIL FROM Request */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* MAIL FROM Reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }

    if ((smtp_state->curr_tx->mail_from_len != 14) ||
        strncmp("asdff@asdf.com", (char *)smtp_state->curr_tx->mail_from, 14)) {
        printf("incorrect parsing of MAIL FROM field '%s' (%d)\n",
               smtp_state->curr_tx->mail_from,
               smtp_state->curr_tx->mail_from_len);
        SCMutexUnlock(&f.m);
        goto end;
    }

    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* RCPT TO Request */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* RCPT TO Reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* Enable mime decoding */
    smtp_config.decode_mime = 1;
    smtp_config.mime_config.decode_base64 = 1;
    smtp_config.mime_config.decode_quoted_printable = 1;
    MimeDecSetConfig(&smtp_config.mime_config);

    SCMutexLock(&f.m);
    /* DATA request */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* Data reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply4, reply4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                    SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* DATA message */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request4_msg, request4_msg_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->curr_tx->mime_state == NULL || smtp_state->curr_tx->msg_head == NULL || /* MIME data structures */
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN |
                    SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* DATA . request */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request4_end, request4_end_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
            smtp_state->curr_tx->mime_state == NULL || smtp_state->curr_tx->msg_head == NULL || /* MIME data structures */
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SMTPState *state = (SMTPState *) f.alstate;
    FileContainer *files = state->files_ts;
    if (files != NULL && files->head != NULL) {
        File *file = files->head;

        if(strncmp((const char *)file->name, "test.exe", 8) != 0){
            printf("smtp-mime file name is incorrect");
            goto end;
        }
        if(file->size != filesize){
            printf("smtp-mime file size %"PRIu64" is incorrect", file->size);
            goto end;
        }
        static uint8_t org_binary[] = {
                0x4D, 0x5A, 0x00, 0x00, 0x50, 0x45, 0x00, 0x00,
                0x4C, 0x01, 0x01, 0x00, 0x6A, 0x2A, 0x58, 0xC3,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x04, 0x00, 0x03, 0x01, 0x0B, 0x01, 0x08, 0x00,
                0x01, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00,
                0x79, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
                0x79, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x40, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x04, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00, 0x00,
                0x20, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x04, 0x01, 0x00, 0x00,
                0x88, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x5C, 0x5C, 0x36, 0x36,
                0x2E, 0x39, 0x33, 0x2E, 0x36, 0x38, 0x2E, 0x36,
                0x5C, 0x7A, 0x00, 0x00, 0x38,};
        uint64_t z;
        for (z=0; z < filesize; z++){
            if(org_binary[z] != file->chunks_head->data[z]){
                printf("smtp-mime file data incorrect\n");
                goto end;
            }
        }
    }

    SCMutexLock(&f.m);
    /* DATA . reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply4_end, reply4_end_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* QUIT Request */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOSERVER,
            request5, request5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 1 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SCMutexLock(&f.m);
    /* QUIT Reply */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_SMTP, STREAM_TOCLIENT,
            reply5, reply5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);
    if (smtp_state->input_len != 0 ||
            smtp_state->cmds_cnt != 0 ||
            smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}

int SMTPProcessDataChunkTest01(void){
    Flow f;
    FLOW_INITIALIZE(&f);
    f.flags = FLOW_FILE_NO_STORE_TS;
    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    int ret;
    ret = SMTPProcessDataChunk(NULL, 0, state);

    return ret;
}


int SMTPProcessDataChunkTest02(void){
    char mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,
            0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
            0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
            0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A,
            0x20, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61,
            0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6F, 0x63, 0x74,
            0x65, 0x74, 0x2D, 0x73, 0x74, 0x72, 0x65, 0x61,
            0x6D, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
            0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61, 0x6E, 0x73,
            0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E, 0x63, 0x6F,
            0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x62, 0x61,
            0x73, 0x65, 0x36, 0x34, 0x0D, 0x0A, 0x43, 0x6F,
            0x6E, 0x74, 0x65, 0x6E, 0x74, 0x2D, 0x44, 0x69,
            0x73, 0x70, 0x6F, 0x73, 0x69, 0x74, 0x69, 0x6F,
            0x6E, 0x3A, 0x20, 0x61, 0x74, 0x74, 0x61, 0x63,
            0x68, 0x6D, 0x65, 0x6E, 0x74, 0x3B, 0x20, 0x66,
            0x69, 0x6C, 0x65, 0x6E, 0x61, 0x6D, 0x65, 0x3D,
            0x22, 0x74, 0x65, 0x73, 0x74, 0x2E, 0x65, 0x78,
            0x65, 0x22, 0x3B, 0x0D, 0x0A, 0x0D, 0x0A, 0x54,
            0x56, 0x6F, 0x41, 0x41, 0x46, 0x42, 0x46, 0x41,
            0x41, 0x42, 0x4D, 0x41, 0x51, 0x45, 0x41, 0x61,
            0x69, 0x70, 0x59, 0x77, 0x77, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x42,
            0x41, 0x41, 0x44, 0x41, 0x51, 0x73, 0x42, 0x43,
            0x41, 0x41, 0x42, 0x41, 0x41, 0x43, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x48, 0x6B, 0x41, 0x41,
            0x41, 0x41, 0x4D, 0x41, 0x41, 0x41, 0x41, 0x65,
            0x51, 0x41, 0x41, 0x41, 0x41, 0x77, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x45, 0x41, 0x41, 0x42,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x51, 0x41, 0x41,
            0x41, 0x42, 0x30, 0x41, 0x41, 0x41, 0x41, 0x49,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x51, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x42,
            0x41, 0x45, 0x41, 0x41, 0x49, 0x67, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x67, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x42, 0x63, 0x58, 0x44, 0x59, 0x32, 0x4C,
            0x6A, 0x6B, 0x7A, 0x4C, 0x6A, 0x59, 0x34, 0x4C,
            0x6A, 0x5A, 0x63, 0x65, 0x67, 0x41, 0x41, 0x4F,
            0x41, 0x3D, 0x3D, 0x0D, 0x0A,};

    Flow f;
    FLOW_INITIALIZE(&f);
    f.alstate = SMTPStateAlloc();
    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;
    int ret;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state);


    return ret;
}



int SMTPProcessDataChunkTest03(void){
    char mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72, };
    char mimemsg2[] = {0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E, };
    char mimemsg3[] = {0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, };
    char mimemsg4[] = {0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A, };
    char mimemsg5[] = {0x20, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, };
    char mimemsg6[] = {0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6F, 0x63, 0x74, };
    char mimemsg7[] = {0x65, 0x74, 0x2D, 0x73, 0x74, 0x72, 0x65, 0x61, };
    char mimemsg8[] = {0x6D, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, };
    char mimemsg9[] = {0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61, 0x6E, 0x73, };
    char mimemsg10[] = {0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E, 0x63, 0x6F, };
    char mimemsg11[] = {0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x62, 0x61, };
    char mimemsg12[] = {0x73, 0x65, 0x36, 0x34, 0x0D, 0x0A, 0x43, 0x6F, };

    Flow f;
    FLOW_INITIALIZE(&f);
    f.alstate = SMTPStateAlloc();
    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    int ret;

    state->body_begin = 1;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state);
    if(ret) goto end;
    state->body_begin = 0;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg2, sizeof(mimemsg2), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg3, sizeof(mimemsg3), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg4, sizeof(mimemsg4), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg5, sizeof(mimemsg5), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg6, sizeof(mimemsg6), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg7, sizeof(mimemsg7), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg8, sizeof(mimemsg8), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg9, sizeof(mimemsg9), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg10, sizeof(mimemsg10), state);
    if(ret) goto end;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg11, sizeof(mimemsg11), state);
    if(ret) goto end;
    state->body_end = 1;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg12, sizeof(mimemsg12), state);
    if(ret) goto end;

    end:
    return ret;
}


int SMTPProcessDataChunkTest04(void){
    char mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72, };
    char mimemsg2[] = {0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E, };
    char mimemsg3[] = {0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, };
    char mimemsg4[] = {0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A, };
    char mimemsg5[] = {0x20, 0x61, 0x70, 0x70, 0x6C, 0x69, 0x63, 0x61, };
    char mimemsg6[] = {0x74, 0x69, 0x6F, 0x6E, 0x2F, 0x6F, 0x63, 0x74, };
    char mimemsg7[] = {0x65, 0x74, 0x2D, 0x73, 0x74, 0x72, 0x65, 0x61, };
    char mimemsg8[] = {0x6D, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65, };
    char mimemsg9[] = {0x6E, 0x74, 0x2D, 0x54, 0x72, 0x61, 0x6E, 0x73, };
    char mimemsg10[] = {0x66, 0x65, 0x72, 0x2D, 0x45, 0x6E, 0x63, 0x6F, };
    char mimemsg11[] = {0x64, 0x69, 0x6E, 0x67, 0x3A, 0x20, 0x62, 0x61, };

    Flow f;
    FLOW_INITIALIZE(&f);
    f.alstate = SMTPStateAlloc();
    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    int ret = MIME_DEC_OK;

    state->body_begin = 1;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg2, sizeof(mimemsg2), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg3, sizeof(mimemsg3), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg4, sizeof(mimemsg4), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg5, sizeof(mimemsg5), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg6, sizeof(mimemsg6), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg7, sizeof(mimemsg7), state) != 0) goto end;
    state->body_begin = 0;
    state->body_end = 1;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg8, sizeof(mimemsg8), state) != 0) goto end;
    state->body_end = 0;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg9, sizeof(mimemsg9), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg10, sizeof(mimemsg10), state) != 0) goto end;
    if(SMTPProcessDataChunk((uint8_t *)mimemsg11, sizeof(mimemsg11), state) != 0) goto end;

    end:
    return ret;
}

int SMTPProcessDataChunkTest05(void){
    char mimemsg[] = {0x4D, 0x49, 0x4D, 0x45, 0x2D, 0x56, 0x65, 0x72,
            0x73, 0x69, 0x6F, 0x6E, 0x3A, 0x20, 0x31, 0x2E,
            0x30, 0x0D, 0x0A, 0x43, 0x6F, 0x6E, 0x74, 0x65,
            0x6E, 0x74, 0x2D, 0x54, 0x79, 0x70, 0x65, 0x3A,
            0x6A, 0x6B, 0x7A, 0x4C, 0x6A, 0x59, 0x34, 0x4C,
            0x6A, 0x5A, 0x63, 0x65, 0x67, 0x41, 0x41, 0x4F,
            0x41, 0x3D, 0x3D, 0x0D, 0x0A,};

    Flow f;
    FLOW_INITIALIZE(&f);
    f.alstate = SMTPStateAlloc();
    MimeDecParseState *state = MimeDecInitParser(&f, NULL);
    ((MimeDecEntity *)state->stack->top->data)->ctnt_flags = CTNT_IS_ATTACHMENT;
    state->body_begin = 1;
    int ret;
    uint64_t file_size = 0;
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state);
    state->body_begin = 0;
    if(ret){goto end;}
    SMTPState *smtp_state = (SMTPState *)((Flow *)state->data)->alstate;
    FileContainer *files = smtp_state->files_ts;
    File *file = files->head;
    file_size = file->size;

    FileDisableStoring(&f, STREAM_TOSERVER);
    FileDisableMagic(&f, STREAM_TOSERVER);
    FileDisableMd5(&f, STREAM_TOSERVER);
    ret = SMTPProcessDataChunk((uint8_t *)mimemsg, sizeof(mimemsg), state);
    if(ret){goto end;}
    printf("%u\t%u\n", (uint32_t) file->size, (uint32_t) file_size);
    if(file->size == file_size){
        return 0;
    }else{
        return 1;
    }

    end:
    return ret;
}

#endif /* UNITTESTS */

void SMTPParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SMTPParserTest01", SMTPParserTest01, 1);
    UtRegisterTest("SMTPParserTest02", SMTPParserTest02, 1);
    UtRegisterTest("SMTPParserTest03", SMTPParserTest03, 1);
    UtRegisterTest("SMTPParserTest04", SMTPParserTest04, 1);
    UtRegisterTest("SMTPParserTest05", SMTPParserTest05, 1);
    UtRegisterTest("SMTPParserTest06", SMTPParserTest06, 1);
    UtRegisterTest("SMTPParserTest07", SMTPParserTest07, 1);
    UtRegisterTest("SMTPParserTest08", SMTPParserTest08, 1);
    UtRegisterTest("SMTPParserTest09", SMTPParserTest09, 1);
    UtRegisterTest("SMTPParserTest10", SMTPParserTest10, 1);
    UtRegisterTest("SMTPParserTest11", SMTPParserTest11, 1);
    UtRegisterTest("SMTPParserTest12", SMTPParserTest12, 1);
    UtRegisterTest("SMTPParserTest13", SMTPParserTest13, 1);
    UtRegisterTest("SMTPParserTest14", SMTPParserTest14, 1);
    UtRegisterTest("SMTPProcessDataChunkTest01", SMTPProcessDataChunkTest01, 0);
    UtRegisterTest("SMTPProcessDataChunkTest02", SMTPProcessDataChunkTest02, 0);
    UtRegisterTest("SMTPProcessDataChunkTest03", SMTPProcessDataChunkTest03, 0);
    UtRegisterTest("SMTPProcessDataChunkTest04", SMTPProcessDataChunkTest04, 0);
    UtRegisterTest("SMTPProcessDataChunkTest05", SMTPProcessDataChunkTest05, 0);
#endif /* UNITTESTS */

    return;
}
