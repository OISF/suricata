/* Copyright (C) 2007-2024 Open Information Security Foundation
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
#include "decode.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-detect-proto.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-frames.h"
#include "app-layer-smtp.h"

#include "util-enum.h"
#include "util-mpm.h"
#include "util-debug.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "flow-util.h"

#include "detect-engine.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"
#include "detect-parse.h"

#include "conf.h"

#include "util-mem.h"
#include "util-misc.h"
#include "util-validate.h"

/* content-limit default value */
#define FILEDATA_CONTENT_LIMIT 100000
/* content-inspect-min-size default value */
#define FILEDATA_CONTENT_INSPECT_MIN_SIZE 32768
/* content-inspect-window default value */
#define FILEDATA_CONTENT_INSPECT_WINDOW 4096

/* raw extraction default value */
#define SMTP_RAW_EXTRACTION_DEFAULT_VALUE false

#define SMTP_COMMAND_BUFFER_STEPS 5

/* we are in process of parsing a fresh command.  Just a placeholder.  If we
 * are not in STATE_COMMAND_DATA_MODE, we have to be in this mode */
// unused #define SMTP_PARSER_STATE_COMMAND_MODE            0x00
/* we are in mode of parsing a command's data.  Used when we are parsing tls
 * or accepting the rfc 2822 mail after DATA command */
#define SMTP_PARSER_STATE_COMMAND_DATA_MODE 0x01
/* Used to indicate that the parser has seen the first reply */
#define SMTP_PARSER_STATE_FIRST_REPLY_SEEN        0x04
/* Used to indicate that the parser is parsing a multiline reply */
#define SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY 0x08
/* Used to indicate that the server supports pipelining */
#define SMTP_PARSER_STATE_PIPELINING_SERVER        0x10

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
#define SMTP_COMMAND_RSET      6

#define SMTP_DEFAULT_MAX_TX 256

typedef struct SMTPInput_ {
    /* current input that is being parsed */
    const uint8_t *buf;
    int32_t len;

    /* original length of an input */
    int32_t orig_len;

    /* Consumed bytes till current line */
    int32_t consumed;
} SMTPInput;

typedef struct SMTPLine_ {
    /** current line extracted by the parser from the call to SMTPGetline() */
    const uint8_t *buf;
    /** length of the line in current_line.  Doesn't include the delimiter */
    int32_t len;
    uint8_t delim_len;
    bool lf_found;
} SMTPLine;

SCEnumCharMap smtp_decoder_event_table[] = {
    { "INVALID_REPLY", SMTP_DECODER_EVENT_INVALID_REPLY },
    { "UNABLE_TO_MATCH_REPLY_WITH_REQUEST", SMTP_DECODER_EVENT_UNABLE_TO_MATCH_REPLY_WITH_REQUEST },
    { "MAX_COMMAND_LINE_LEN_EXCEEDED", SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED },
    { "MAX_REPLY_LINE_LEN_EXCEEDED", SMTP_DECODER_EVENT_MAX_REPLY_LINE_LEN_EXCEEDED },
    { "INVALID_PIPELINED_SEQUENCE", SMTP_DECODER_EVENT_INVALID_PIPELINED_SEQUENCE },
    { "BDAT_CHUNK_LEN_EXCEEDED", SMTP_DECODER_EVENT_BDAT_CHUNK_LEN_EXCEEDED },
    { "NO_SERVER_WELCOME_MESSAGE", SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE },
    { "TLS_REJECTED", SMTP_DECODER_EVENT_TLS_REJECTED },
    { "DATA_COMMAND_REJECTED", SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED },
    { "FAILED_PROTOCOL_CHANGE", SMTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE },

    /* MIME Events */
    { "MIME_PARSE_FAILED", SMTP_DECODER_EVENT_MIME_PARSE_FAILED },
    { "MIME_INVALID_BASE64", SMTP_DECODER_EVENT_MIME_INVALID_BASE64 },
    { "MIME_INVALID_QP", SMTP_DECODER_EVENT_MIME_INVALID_QP },
    { "MIME_LONG_LINE", SMTP_DECODER_EVENT_MIME_LONG_LINE },
    { "MIME_LONG_ENC_LINE", SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE },
    { "MIME_LONG_HEADER_NAME", SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME },
    { "MIME_LONG_HEADER_VALUE", SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE },
    { "MIME_LONG_BOUNDARY", SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG },
    { "MIME_LONG_FILENAME", SMTP_DECODER_EVENT_MIME_LONG_FILENAME },

    /* Invalid behavior or content */
    { "DUPLICATE_FIELDS", SMTP_DECODER_EVENT_DUPLICATE_FIELDS },
    { "UNPARSABLE_CONTENT", SMTP_DECODER_EVENT_UNPARSABLE_CONTENT },
    { "TRUNCATED_LINE", SMTP_DECODER_EVENT_TRUNCATED_LINE },
    { NULL, -1 },
};

enum SMTPFrameTypes {
    SMTP_FRAME_COMMAND_LINE,
    SMTP_FRAME_DATA,
    SMTP_FRAME_RESPONSE_LINE,
};

SCEnumCharMap smtp_frame_table[] = {
    {
            "command_line",
            SMTP_FRAME_COMMAND_LINE,
    },
    {
            "data",
            SMTP_FRAME_DATA,
    },
    {
            "response_line",
            SMTP_FRAME_RESPONSE_LINE,
    },
    { NULL, -1 },
};

static int SMTPGetFrameIdByName(const char *frame_name)
{
    int id = SCMapEnumNameToValue(frame_name, smtp_frame_table);
    if (id < 0) {
        return -1;
    }
    return id;
}

static const char *SMTPGetFrameNameById(const uint8_t frame_id)
{
    const char *name = SCMapEnumValueToName(frame_id, smtp_frame_table);
    return name;
}

typedef struct SMTPThreadCtx_ {
    MpmThreadCtx *smtp_mpm_thread_ctx;
    PrefilterRuleStore *pmq;
} SMTPThreadCtx;

#define SMTP_MPM mpm_default_matcher

static MpmCtx *smtp_mpm_ctx = NULL;

/* smtp reply codes.  If an entry is made here, please make a simultaneous
 * entry in smtp_reply_map */
enum SMTPCode {
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

    SMTP_REPLY_401, // Unauthorized
    SMTP_REPLY_402, // Command not implemented
    SMTP_REPLY_421,
    SMTP_REPLY_435, // Your account has not yet been verified
    SMTP_REPLY_450,
    SMTP_REPLY_451,
    SMTP_REPLY_452,
    SMTP_REPLY_454, // Temporary authentication failure
    SMTP_REPLY_455,

    SMTP_REPLY_500,
    SMTP_REPLY_501,
    SMTP_REPLY_502,
    SMTP_REPLY_503,
    SMTP_REPLY_504,
    SMTP_REPLY_511, // Bad email address
    SMTP_REPLY_521, // Server does not accept mail
    SMTP_REPLY_522, // Recipient has exceeded mailbox limit
    SMTP_REPLY_525, // User Account Disabled
    SMTP_REPLY_530, // Authentication required
    SMTP_REPLY_534, // Authentication mechanism is too weak
    SMTP_REPLY_535, // Authentication credentials invalid
    SMTP_REPLY_541, // No response from host
    SMTP_REPLY_543, // Routing server failure. No available route
    SMTP_REPLY_550,
    SMTP_REPLY_551,
    SMTP_REPLY_552,
    SMTP_REPLY_553,
    SMTP_REPLY_554,
    SMTP_REPLY_555,
};

SCEnumCharMap smtp_reply_map[] = {
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

    { "401", SMTP_REPLY_401 },
    { "402", SMTP_REPLY_402 },
    { "421", SMTP_REPLY_421 },
    { "435", SMTP_REPLY_435 },
    { "450", SMTP_REPLY_450 },
    { "451", SMTP_REPLY_451 },
    { "452", SMTP_REPLY_452 },
    { "454", SMTP_REPLY_454 },
    // { "4.7.0", SMTP_REPLY_454 }, // rfc4954
    { "455", SMTP_REPLY_455 },

    { "500", SMTP_REPLY_500 },
    { "501", SMTP_REPLY_501 },
    { "502", SMTP_REPLY_502 },
    { "503", SMTP_REPLY_503 },
    { "504", SMTP_REPLY_504 },
    { "511", SMTP_REPLY_511 },
    { "521", SMTP_REPLY_521 },
    { "522", SMTP_REPLY_522 },
    { "525", SMTP_REPLY_525 },
    { "530", SMTP_REPLY_530 },
    { "534", SMTP_REPLY_534 },
    { "535", SMTP_REPLY_535 },
    { "541", SMTP_REPLY_541 },
    { "543", SMTP_REPLY_543 },
    { "550", SMTP_REPLY_550 },
    { "551", SMTP_REPLY_551 },
    { "552", SMTP_REPLY_552 },
    { "553", SMTP_REPLY_553 },
    { "554", SMTP_REPLY_554 },
    { "555", SMTP_REPLY_555 },
    { NULL, -1 },
};

/* Create SMTP config structure */
SMTPConfig smtp_config = {
    .decode_mime = true,
    .content_limit = FILEDATA_CONTENT_LIMIT,
    .content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE,
    .content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW,
    .raw_extraction = SMTP_RAW_EXTRACTION_DEFAULT_VALUE,
    STREAMING_BUFFER_CONFIG_INITIALIZER,
};

static SMTPString *SMTPStringAlloc(void);

#define SCHEME_SUFFIX_LEN 3

/**
 * \brief Configure SMTP Mime Decoder by parsing out mime section of YAML
 * config file
 *
 * \return none
 */
static void SMTPConfigure(void) {

    SCEnter();
    intmax_t imval;
    uint32_t content_limit = 0;
    uint32_t content_inspect_min_size = 0;
    uint32_t content_inspect_window = 0;

    ConfNode *config = ConfGetNode("app-layer.protocols.smtp.mime");
    if (config != NULL) {
        ConfNode *extract_urls_schemes = NULL;

        int val;
        int ret = ConfGetChildValueBool(config, "decode-mime", &val);
        if (ret) {
            smtp_config.decode_mime = val;
        }

        ret = ConfGetChildValueBool(config, "decode-base64", &val);
        if (ret) {
            SCMimeSmtpConfigDecodeBase64(val);
        }

        ret = ConfGetChildValueBool(config, "decode-quoted-printable", &val);
        if (ret) {
            SCMimeSmtpConfigDecodeQuoted(val);
        }

        ret = ConfGetChildValueInt(config, "header-value-depth", &imval);
        if (ret) {
            if (imval < 0 || imval > UINT32_MAX) {
                FatalError("Invalid value for header-value-depth");
            }
            SCMimeSmtpConfigHeaderValueDepth((uint32_t)imval);
        }

        ret = ConfGetChildValueBool(config, "extract-urls", &val);
        if (ret) {
            SCMimeSmtpConfigExtractUrls(val);
        }

        /* Parse extract-urls-schemes from mime config, add '://' suffix to found schemes,
         * and provide a default value of 'http' for the schemes to be extracted
         * if no schemes are found in the config */
        extract_urls_schemes = ConfNodeLookupChild(config, "extract-urls-schemes");
        if (extract_urls_schemes) {
            ConfNode *scheme = NULL;

            SCMimeSmtpConfigExtractUrlsSchemeReset();
            TAILQ_FOREACH (scheme, &extract_urls_schemes->head, next) {
                size_t scheme_len = strlen(scheme->val);
                if (scheme_len > UINT16_MAX - SCHEME_SUFFIX_LEN) {
                    FatalError("Too long value for extract-urls-schemes");
                }
                if (scheme->val[scheme_len - 1] != '/') {
                    scheme_len += SCHEME_SUFFIX_LEN;
                    char *new_val = SCMalloc(scheme_len + 1);
                    if (unlikely(new_val == NULL)) {
                        FatalError("SCMalloc failure.");
                    }
                    int r = snprintf(new_val, scheme_len + 1, "%s://", scheme->val);
                    if (r != (int)scheme_len) {
                        FatalError("snprintf failure for SMTP url extraction scheme.");
                    }
                    SCFree(scheme->val);
                    scheme->val = new_val;
                }
                int r = SCMimeSmtpConfigExtractUrlsSchemeAdd(scheme->val);
                if (r < 0) {
                    FatalError("Failed to add smtp extract url scheme");
                }
            }
        } else {
            /* Add default extract url scheme 'http' since
             * extract-urls-schemes wasn't found in the config */
            SCMimeSmtpConfigExtractUrlsSchemeReset();
            SCMimeSmtpConfigExtractUrlsSchemeAdd("http://");
        }

        ret = ConfGetChildValueBool(config, "log-url-scheme", &val);
        if (ret) {
            SCMimeSmtpConfigLogUrlScheme(val);
        }

        ret = ConfGetChildValueBool(config, "body-md5", &val);
        if (ret) {
            SCMimeSmtpConfigBodyMd5(val);
        }
    }

    ConfNode *t = ConfGetNode("app-layer.protocols.smtp.inspected-tracker");
    ConfNode *p = NULL;

    if (t != NULL) {
        TAILQ_FOREACH(p, &t->head, next) {
            if (strcasecmp("content-limit", p->name) == 0) {
                if (ParseSizeStringU32(p->val, &content_limit) < 0) {
                    SCLogWarning("parsing content-limit %s failed", p->val);
                    content_limit = FILEDATA_CONTENT_LIMIT;
                }
                smtp_config.content_limit = content_limit;
            }

            if (strcasecmp("content-inspect-min-size", p->name) == 0) {
                if (ParseSizeStringU32(p->val, &content_inspect_min_size) < 0) {
                    SCLogWarning("parsing content-inspect-min-size %s failed", p->val);
                    content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;
                }
                smtp_config.content_inspect_min_size = content_inspect_min_size;
            }

            if (strcasecmp("content-inspect-window", p->name) == 0) {
                if (ParseSizeStringU32(p->val, &content_inspect_window) < 0) {
                    SCLogWarning("parsing content-inspect-window %s failed", p->val);
                    content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
                }
                smtp_config.content_inspect_window = content_inspect_window;
            }
        }
    }

    smtp_config.sbcfg.buf_size = content_limit ? content_limit : 256;

    if (ConfGetBool("app-layer.protocols.smtp.raw-extraction",
                (int *)&smtp_config.raw_extraction) != 1) {
        smtp_config.raw_extraction = SMTP_RAW_EXTRACTION_DEFAULT_VALUE;
    }
    if (smtp_config.raw_extraction && smtp_config.decode_mime) {
        SCLogError("\"decode-mime\" and \"raw-extraction\" "
                   "options can't be enabled at the same time, "
                   "disabling raw extraction");
        smtp_config.raw_extraction = 0;
    }

    uint64_t value = SMTP_DEFAULT_MAX_TX;
    smtp_config.max_tx = SMTP_DEFAULT_MAX_TX;
    const char *str = NULL;
    if (ConfGet("app-layer.protocols.smtp.max-tx", &str) == 1) {
        if (ParseSizeStringU64(str, &value) < 0) {
            SCLogWarning("max-tx value cannot be deduced: %s,"
                         " keeping default",
                    str);
        }
        smtp_config.max_tx = value;
    }

    SCReturn;
}

static void SMTPSetEvent(SMTPState *s, uint8_t e)
{
    SCLogDebug("setting event %u", e);

    if (s->curr_tx != NULL) {
        AppLayerDecoderEventsSetEventRaw(&s->curr_tx->tx_data.events, e);
        //        s->events++;
        return;
    }
    SCLogDebug("couldn't set event %u", e);
}

static SMTPTransaction *SMTPTransactionCreate(SMTPState *state)
{
    if (state->tx_cnt > smtp_config.max_tx) {
        return NULL;
    }
    SMTPTransaction *tx = SCCalloc(1, sizeof(*tx));
    if (tx == NULL) {
        return NULL;
    }

    TAILQ_INIT(&tx->rcpt_to_list);
    tx->tx_data.file_tx = STREAM_TOSERVER; // can xfer files
    return tx;
}

static void FlagDetectStateNewFile(SMTPTransaction *tx)
{
    if (tx && tx->tx_data.de_state) {
        SCLogDebug("DETECT_ENGINE_STATE_FLAG_FILE_NEW set");
        tx->tx_data.de_state->dir_state[0].flags |= DETECT_ENGINE_STATE_FLAG_FILE_NEW;
    } else if (tx == NULL) {
        SCLogDebug("DETECT_ENGINE_STATE_FLAG_FILE_NEW NOT set, no TX");
    } else if (tx->tx_data.de_state == NULL) {
        SCLogDebug("DETECT_ENGINE_STATE_FLAG_FILE_NEW NOT set, no TX DESTATE");
    }
}

static void SMTPNewFile(SMTPTransaction *tx, File *file)
{
    DEBUG_VALIDATE_BUG_ON(tx == NULL);
    DEBUG_VALIDATE_BUG_ON(file == NULL);
#ifdef UNITTESTS
    if (RunmodeIsUnittests()) {
        if (tx == NULL || file == NULL) {
            return;
        }
    }
#endif
    FlagDetectStateNewFile(tx);
    tx->tx_data.files_opened++;

    /* set inspect sizes used in file pruning logic.
     * TODO consider moving this to the file.data code that
     * would actually have use for this. */
    FileSetInspectSizes(file, smtp_config.content_inspect_window,
            smtp_config.content_inspect_min_size);
}

/**
 * \internal
 * \brief Get the next line from input.  It doesn't do any length validation.
 *
 * \param state The smtp state.
 *
 * \retval  0 On success.
 * \retval -1 Either when we don't have any new lines to supply anymore or
 *            on failure.
 */
static AppLayerResult SMTPGetLine(Flow *f, StreamSlice *slice, SMTPState *state, SMTPInput *input,
        SMTPLine *line, uint16_t direction)
{
    SCEnter();

    /* we have run out of input */
    if (input->len <= 0)
        return APP_LAYER_ERROR;

    const uint8_t type = direction == 0 ? SMTP_FRAME_COMMAND_LINE : SMTP_FRAME_RESPONSE_LINE;
    Frame *frame = AppLayerFrameGetLastOpenByType(f, direction, type);
    if (frame == NULL) {
        if (direction == 0 &&
                !(state->current_command == SMTP_COMMAND_DATA &&
                        (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE))) {
            frame = AppLayerFrameNewByPointer(
                    f, slice, input->buf + input->consumed, -1, 0, SMTP_FRAME_COMMAND_LINE);
            /* can't set tx id before (possibly) creating it */

        } else if (direction == 1) {
            frame = AppLayerFrameNewByPointer(
                    f, slice, input->buf + input->consumed, -1, 1, SMTP_FRAME_RESPONSE_LINE);
            if (frame != NULL && state->curr_tx) {
                AppLayerFrameSetTxId(frame, state->curr_tx->tx_id);
            }
        }
    }
    SCLogDebug("frame %p", frame);

    uint8_t *lf_idx = memchr(input->buf + input->consumed, 0x0a, input->len);
    bool discard_till_lf = (direction == 0) ? state->discard_till_lf_ts : state->discard_till_lf_tc;

    if (lf_idx == NULL) {
        if (!discard_till_lf && input->len >= SMTP_LINE_BUFFER_LIMIT) {
            line->buf = input->buf;
            line->len = SMTP_LINE_BUFFER_LIMIT;
            line->delim_len = 0;
            SCReturnStruct(APP_LAYER_OK);
        }
        SCReturnStruct(APP_LAYER_INCOMPLETE(input->consumed, input->len + 1));
    } else {
        /* There could be one chunk of command data that has LF but post the line limit
         * e.g. input_len = 5077
         *      lf_idx = 5010
         *      max_line_len = 4096 */
        uint32_t o_consumed = input->consumed;
        input->consumed = (uint32_t)(lf_idx - input->buf + 1);
        line->len = input->consumed - o_consumed;
        line->lf_found = true;
        DEBUG_VALIDATE_BUG_ON(line->len < 0);
        if (line->len < 0)
            SCReturnStruct(APP_LAYER_ERROR);
        input->len -= line->len;
        DEBUG_VALIDATE_BUG_ON((input->consumed + input->len) != input->orig_len);
        line->buf = input->buf + o_consumed;

        if (frame != NULL) {
            frame->len = (int64_t)line->len;
        }

        if (line->len >= SMTP_LINE_BUFFER_LIMIT) {
            line->len = SMTP_LINE_BUFFER_LIMIT;
            line->delim_len = 0;
            SCReturnStruct(APP_LAYER_OK);
        }
        if (discard_till_lf) {
            // Whatever came in with first LF should also get discarded
            if (direction == 0) {
                state->discard_till_lf_ts = false;
            } else {
                state->discard_till_lf_tc = false;
            }
            line->len = 0;
            line->delim_len = 0;
            SCReturnStruct(APP_LAYER_OK);
        }
        if (input->consumed >= 2 && input->buf[input->consumed - 2] == 0x0D) {
            line->delim_len = 2;
            line->len -= 2;
        } else {
            line->delim_len = 1;
            line->len -= 1;
        }
        SCReturnStruct(APP_LAYER_OK);
    }
}

static int SMTPInsertCommandIntoCommandBuffer(uint8_t command, SMTPState *state)
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

static int SMTPProcessCommandBDAT(SMTPState *state, const SMTPLine *line)
{
    SCEnter();

    state->bdat_chunk_idx += (line->len + line->delim_len);
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

static void SetMimeEvents(SMTPState *state, uint32_t events)
{
    if (events == 0) {
        return;
    }

    if (events & MIME_ANOM_INVALID_BASE64) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_INVALID_BASE64);
    }
    if (events & MIME_ANOM_INVALID_QP) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_INVALID_QP);
    }
    if (events & MIME_ANOM_LONG_LINE) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_LINE);
    }
    if (events & MIME_ANOM_LONG_ENC_LINE) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_ENC_LINE);
    }
    if (events & MIME_ANOM_LONG_HEADER_NAME) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_HEADER_NAME);
    }
    if (events & MIME_ANOM_LONG_HEADER_VALUE) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_HEADER_VALUE);
    }
    if (events & MIME_ANOM_LONG_BOUNDARY) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_BOUNDARY_TOO_LONG);
    }
    if (events & MIME_ANOM_LONG_FILENAME) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_FILENAME);
    }
}

static inline void SMTPTransactionComplete(SMTPState *state)
{
    DEBUG_VALIDATE_BUG_ON(state->curr_tx == NULL);
    if (state->curr_tx)
        state->curr_tx->done = true;
}

/**
 *  \retval 0 ok
 *  \retval -1 error
 */
static int SMTPProcessCommandDATA(
        SMTPState *state, SMTPTransaction *tx, Flow *f, const SMTPLine *line)
{
    SCEnter();
    DEBUG_VALIDATE_BUG_ON(tx == NULL);

    SCTxDataUpdateFileFlags(&tx->tx_data, state->state_data.file_flags);
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        /* looks like are still waiting for a confirmation from the server */
        return 0;
    }

    if (line->len == 1 && line->buf[0] == '.') {
        state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        /* kinda like a hack.  The mail sent in DATA mode, would be
         * acknowledged with a reply.  We insert a dummy command to
         * the command buffer to be used by the reply handler to match
         * the reply received */
        SMTPInsertCommandIntoCommandBuffer(SMTP_COMMAND_DATA_MODE, state);
        if (smtp_config.raw_extraction) {
            /* we use this as the signal that message data is complete. */
            FileCloseFile(&tx->files_ts, &smtp_config.sbcfg, NULL, 0, 0);
        } else if (smtp_config.decode_mime && tx->mime_state != NULL) {
            /* Complete parsing task */
            SCSmtpMimeComplete(tx->mime_state);
            if (tx->files_ts.tail && tx->files_ts.tail->state == FILE_STATE_OPENED) {
                FileCloseFile(&tx->files_ts, &smtp_config.sbcfg, NULL, 0,
                        FileFlowToFlags(f, STREAM_TOSERVER));
            }
        }
        SMTPTransactionComplete(state);
        SCLogDebug("marked tx as done");
    } else if (smtp_config.raw_extraction) {
        // message not over, store the line. This is a substitution of
        // ProcessDataChunk
        FileAppendData(&tx->files_ts, &smtp_config.sbcfg, line->buf, line->len + line->delim_len);
    }

    /* If DATA, then parse out a MIME message */
    if (state->current_command == SMTP_COMMAND_DATA &&
            (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        if (smtp_config.decode_mime && tx->mime_state != NULL) {
            uint32_t events;
            uint16_t flags = FileFlowToFlags(f, STREAM_TOSERVER);
            const uint8_t *filename = NULL;
            uint16_t filename_len = 0;
            uint32_t depth;

            /* we depend on detection engine for file pruning */
            flags |= FILE_USE_DETECT;
            MimeSmtpParserResult ret = SCSmtpMimeParseLine(
                    line->buf, line->len, line->delim_len, &events, tx->mime_state);
            SetMimeEvents(state, events);
            switch (ret) {
                case MimeSmtpFileOpen:
                    // get filename owned by mime state
                    SCMimeSmtpGetFilename(state->curr_tx->mime_state, &filename, &filename_len);

                    if (filename_len == 0) {
                        // not an attachment
                        break;
                    }
                    depth = (uint32_t)(smtp_config.content_inspect_min_size +
                                       (state->toserver_data_count -
                                               state->toserver_last_data_stamp));
                    SCLogDebug("StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER %" PRIu32,
                            depth);
                    StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER, depth);

                    if (filename_len > SC_FILENAME_MAX) {
                        filename_len = SC_FILENAME_MAX;
                        SMTPSetEvent(state, SMTP_DECODER_EVENT_MIME_LONG_FILENAME);
                    }
                    if (FileOpenFileWithId(&tx->files_ts, &smtp_config.sbcfg,
                                state->file_track_id++, filename, filename_len, NULL, 0,
                                flags) != 0) {
                        SCLogDebug("FileOpenFile() failed");
                    }
                    SMTPNewFile(state->curr_tx, tx->files_ts.tail);
                    break;
                case MimeSmtpFileChunk:
                    // rust already run FileAppendData
                    if (tx->files_ts.tail && tx->files_ts.tail->content_inspected == 0 &&
                            tx->files_ts.tail->size >= smtp_config.content_inspect_min_size) {
                        depth = (uint32_t)(smtp_config.content_inspect_min_size +
                                           (state->toserver_data_count -
                                                   state->toserver_last_data_stamp));
                        AppLayerParserTriggerRawStreamReassembly(f, STREAM_TOSERVER);
                        SCLogDebug(
                                "StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER %u", depth);
                        StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER, depth);
                        /* after the start of the body inspection, disable the depth logic */
                    } else if (tx->files_ts.tail && tx->files_ts.tail->content_inspected > 0) {
                        StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER, 0);
                        /* expand the limit as long as we get file data, as the file data is bigger
                         * on the wire due to base64 */
                    } else {
                        depth = (uint32_t)(smtp_config.content_inspect_min_size +
                                           (state->toserver_data_count -
                                                   state->toserver_last_data_stamp));
                        SCLogDebug("StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER %" PRIu32,
                                depth);
                        StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER, depth);
                    }
                    break;
                case MimeSmtpFileClose:
                    if (tx->files_ts.tail && tx->files_ts.tail->state == FILE_STATE_OPENED) {
                        if (FileCloseFile(&tx->files_ts, &smtp_config.sbcfg, NULL, 0, flags) != 0) {
                            SCLogDebug("FileCloseFile() failed: %d", ret);
                        }
                    } else {
                        SCLogDebug("File already closed");
                    }
                    depth = (uint32_t)(state->toserver_data_count -
                                       state->toserver_last_data_stamp);
                    AppLayerParserTriggerRawStreamReassembly(f, STREAM_TOSERVER);
                    SCLogDebug("StreamTcpReassemblySetMinInspectDepth STREAM_TOSERVER %u", depth);
                    StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER, depth);
            }
        }
    }

    return 0;
}

static inline bool IsReplyToCommand(const SMTPState *state, const uint8_t cmd)
{
    return (state->cmds_idx < state->cmds_buffer_len &&
            state->cmds[state->cmds_idx] == cmd);
}

static int SMTPProcessReply(
        SMTPState *state, Flow *f, SMTPThreadCtx *td, SMTPInput *input, const SMTPLine *line)
{
    SCEnter();

    /* Line with just LF */
    if (line->len == 0 && input->consumed == 1 && line->delim_len == 1) {
        return 0; // to continue processing further
    }

    /* the reply code has to contain at least 3 bytes, to hold the 3 digit
     * reply code */
    if (line->len < 3) {
        /* decoder event */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
        return -1;
    }

    if (line->len >= 4) {
        if (state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY) {
            if (line->buf[3] != '-') {
                state->parser_state &= ~SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY;
            }
        } else {
            if (line->buf[3] == '-') {
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
    PmqReset(td->pmq);
    int mpm_cnt = mpm_table[SMTP_MPM].Search(
            smtp_mpm_ctx, td->smtp_mpm_thread_ctx, td->pmq, line->buf, 3);
    if (mpm_cnt == 0) {
        /* set decoder event - reply code invalid */
        SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
        SCLogDebug("invalid reply code %02x %02x %02x", line->buf[0], line->buf[1], line->buf[2]);
        SCReturnInt(-1);
    }
    enum SMTPCode reply_code = smtp_reply_map[td->pmq->rule_id_array[0]].enum_value;
    SCLogDebug("REPLY: reply_code %u / %s", reply_code,
            smtp_reply_map[reply_code].enum_name);

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
            else {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_INVALID_REPLY);
                SCReturnInt(0);
            }
        } else {
            /* decoder event - unable to match reply with request */
            SCLogDebug("unable to match reply with request");
            SCReturnInt(0);
        }
    }

    if (state->cmds_cnt == 0) {
        /* reply but not a command we have stored, fall through */
    } else if (IsReplyToCommand(state, SMTP_COMMAND_STARTTLS)) {
        if (reply_code == SMTP_REPLY_220) {
            /* we are entering STARTTLS data mode */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            if (!AppLayerRequestProtocolTLSUpgrade(f)) {
                SMTPSetEvent(state, SMTP_DECODER_EVENT_FAILED_PROTOCOL_CHANGE);
            }
            if (state->curr_tx) {
                SMTPTransactionComplete(state);
            }
        } else {
            /* decoder event */
            SMTPSetEvent(state, SMTP_DECODER_EVENT_TLS_REJECTED);
        }
    } else if (IsReplyToCommand(state, SMTP_COMMAND_DATA)) {
        if (reply_code == SMTP_REPLY_354) {
            /* Next comes the mail for the DATA command in toserver direction */
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else {
            /* decoder event */
            if (state->parser_state & SMTP_PARSER_STATE_PIPELINING_SERVER) {
                // reset data mode if we had entered it prematurely
                state->parser_state &= ~SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            }
            SMTPSetEvent(state, SMTP_DECODER_EVENT_DATA_COMMAND_REJECTED);
        }
    } else if (IsReplyToCommand(state, SMTP_COMMAND_RSET)) {
        if (reply_code == SMTP_REPLY_250 && state->curr_tx &&
                !(state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY)) {
            SMTPTransactionComplete(state);
        }
    } else {
        /* we don't care for any other command for now */
    }

    /* if it is a multi-line reply, we need to move the index only once for all
     * the line of the reply.  We unset the multiline flag on the last
     * line of the multiline reply, following which we increment the index */
    if (!(state->parser_state & SMTP_PARSER_STATE_PARSING_MULTILINE_REPLY)) {
        state->cmds_idx++;
    } else if (state->parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        /* we check if the server is indicating pipelining support */
        if (reply_code == SMTP_REPLY_250 && line->len == 14 &&
                SCMemcmpLowercase("pipelining", line->buf + 4, 10) == 0) {
            state->parser_state |= SMTP_PARSER_STATE_PIPELINING_SERVER;
        }
    }

    /* if we have matched all the buffered commands, reset the cnt and index */
    if (state->cmds_idx == state->cmds_cnt) {
        state->cmds_cnt = 0;
        state->cmds_idx = 0;
    }

    return 0;
}

static int SMTPParseCommandBDAT(SMTPState *state, const SMTPLine *line)
{
    SCEnter();

    int i = 4;
    while (i < line->len) {
        if (line->buf[i] != ' ') {
            break;
        }
        i++;
    }
    if (i == 4) {
        /* decoder event */
        return -1;
    }
    if (i == line->len) {
        /* decoder event */
        return -1;
    }
    // copy in temporary null-terminated buffer for conversion
    char strbuf[24];
    int len = 23;
    if (line->len - i < len) {
        len = line->len - i;
    }
    memcpy(strbuf, line->buf + i, len);
    strbuf[len] = '\0';
    if (ByteExtractStringUint32(&state->bdat_chunk_len, 10, 0, strbuf) < 0) {
        /* decoder event */
        return -1;
    }

    return 0;
}

static int SMTPParseCommandWithParam(SMTPState *state, const SMTPLine *line, uint8_t prefix_len,
        uint8_t **target, uint16_t *target_len)
{
    int i = prefix_len + 1;

    while (i < line->len) {
        if (line->buf[i] != ' ') {
            break;
        }
        i++;
    }

    /* rfc1870: with the size extension the mail from can be followed by an option.
       We use the space separator to detect it. */
    int spc_i = i;
    while (spc_i < line->len) {
        if (line->buf[spc_i] == ' ') {
            break;
        }
        spc_i++;
    }

    *target = SCMalloc(spc_i - i + 1);
    if (*target == NULL)
        return -1;
    memcpy(*target, line->buf + i, spc_i - i);
    (*target)[spc_i - i] = '\0';
    if (spc_i - i > UINT16_MAX) {
        *target_len = UINT16_MAX;
        SMTPSetEvent(state, SMTP_DECODER_EVENT_MAX_COMMAND_LINE_LEN_EXCEEDED);
    } else {
        *target_len = (uint16_t)(spc_i - i);
    }

    return 0;
}

static int SMTPParseCommandHELO(SMTPState *state, const SMTPLine *line)
{
    if (state->helo) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_DUPLICATE_FIELDS);
        return 0;
    }
    return SMTPParseCommandWithParam(state, line, 4, &state->helo, &state->helo_len);
}

static int SMTPParseCommandMAILFROM(SMTPState *state, const SMTPLine *line)
{
    if (state->curr_tx->mail_from) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_DUPLICATE_FIELDS);
        return 0;
    }
    return SMTPParseCommandWithParam(
            state, line, 9, &state->curr_tx->mail_from, &state->curr_tx->mail_from_len);
}

static int SMTPParseCommandRCPTTO(SMTPState *state, const SMTPLine *line)
{
    uint8_t *rcptto;
    uint16_t rcptto_len;

    if (SMTPParseCommandWithParam(state, line, 7, &rcptto, &rcptto_len) == 0) {
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
static int NoNewTx(SMTPState *state, const SMTPLine *line)
{
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        if (line->len >= 4 && SCMemcmpLowercase("rset", line->buf, 4) == 0) {
            return 1;
        } else if (line->len >= 4 && SCMemcmpLowercase("quit", line->buf, 4) == 0) {
            return 1;
        }
    }
    return 0;
}

/* XXX have a better name */
#define rawmsgname "rawmsg"

/*
 * @brief Process an SMTP Request
 *
 * Parse and decide the current command and set appropriate variables on the state
 * accordingly. Create transactions if needed or update the current transaction
 * with the appropriate data/params. Pass the control to the respective command
 * parser in the end.
 *
 * @param state  Pointer to current SMTPState
 * @param f      Pointer to the current Flow
 * @param pstate Pointer to the current AppLayerParserState
 * @param input  Pointer to the current input data to SMTP parser
 * @param line   Pointer to the current line being parsed by the SMTP parser
 * @return  0 for success
 *         -1 for errors and inconsistent states
 *         -2 if MIME state could not be allocated
 * */
static int SMTPProcessRequest(
        SMTPState *state, Flow *f, SMTPInput *input, const SMTPLine *line, const StreamSlice *slice)
{
    SCEnter();
    SMTPTransaction *tx = state->curr_tx;

    Frame *frame = AppLayerFrameGetLastOpenByType(f, 0, SMTP_FRAME_COMMAND_LINE);
    if (frame) {
        frame->len = (int64_t)line->len;
    } else {
        if (!(state->current_command == SMTP_COMMAND_DATA &&
                    (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE))) {
            frame = AppLayerFrameNewByPointer(
                    f, slice, line->buf, line->len, 0, SMTP_FRAME_COMMAND_LINE);
        }
    }

    /* If current input is to be discarded because it completes a long line,
     * line's length and delimiter len are reset to 0. Skip processing this line.
     * This line is only to get us out of the state where we should discard any
     * data till LF. */
    if (line->len == 0 && line->delim_len == 0) {
        return 0;
    }
    if (state->curr_tx == NULL || (state->curr_tx->done && !NoNewTx(state, line))) {
        tx = SMTPTransactionCreate(state);
        if (tx == NULL)
            return -1;
        state->curr_tx = tx;
        TAILQ_INSERT_TAIL(&state->tx_list, tx, next);
        tx->tx_id = state->tx_cnt++;

        /* keep track of the start of the tx */
        state->toserver_last_data_stamp = state->toserver_data_count;
        StreamTcpReassemblySetMinInspectDepth(f->protoctx, STREAM_TOSERVER,
                smtp_config.content_inspect_min_size);
    }
    if (frame != NULL && state->curr_tx) {
        AppLayerFrameSetTxId(frame, state->curr_tx->tx_id);
    }

    state->toserver_data_count += (line->len + line->delim_len);

    if (!(state->parser_state & SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        SMTPSetEvent(state, SMTP_DECODER_EVENT_NO_SERVER_WELCOME_MESSAGE);
    }

    /* there are 2 commands that can push it into this COMMAND_DATA mode -
     * STARTTLS and DATA */
    if (!(state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        int r = 0;

        if (line->len >= 8 && SCMemcmpLowercase("starttls", line->buf, 8) == 0) {
            state->current_command = SMTP_COMMAND_STARTTLS;
        } else if (line->len >= 4 && SCMemcmpLowercase("data", line->buf, 4) == 0) {
            state->current_command = SMTP_COMMAND_DATA;
            if (state->curr_tx->is_data) {
                // We did not receive a confirmation from server
                // And now client sends a next DATA
                SMTPSetEvent(state, SMTP_DECODER_EVENT_UNPARSABLE_CONTENT);
                SCReturnInt(0);
            } else if (smtp_config.raw_extraction) {
                if (FileOpenFileWithId(&tx->files_ts, &smtp_config.sbcfg, state->file_track_id++,
                            (uint8_t *)rawmsgname, strlen(rawmsgname), NULL, 0,
                            FILE_NOMD5 | FILE_NOMAGIC) == 0) {
                    SMTPNewFile(tx, tx->files_ts.tail);
                }
            } else if (smtp_config.decode_mime) {
                DEBUG_VALIDATE_BUG_ON(tx->mime_state);
                tx->mime_state = SCMimeSmtpStateInit(&tx->files_ts, &smtp_config.sbcfg);
                if (tx->mime_state == NULL) {
                    SCLogDebug("MimeDecInitParser() failed to "
                               "allocate data");
                    return -1;
                }
            }
            state->curr_tx->is_data = true;

            Frame *data_frame = AppLayerFrameNewByPointer(
                    f, slice, input->buf + input->consumed, -1, 0, SMTP_FRAME_DATA);
            if (data_frame == NULL) {
                SCLogDebug("data_frame %p - no data frame set up", data_frame);
            } else {
                AppLayerFrameSetTxId(data_frame, state->curr_tx->tx_id);
            }

            /* Enter immediately data mode without waiting for server reply */
            if (state->parser_state & SMTP_PARSER_STATE_PIPELINING_SERVER) {
                state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
            }
        } else if (line->len >= 4 && SCMemcmpLowercase("bdat", line->buf, 4) == 0) {
            r = SMTPParseCommandBDAT(state, line);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_BDAT;
            state->parser_state |= SMTP_PARSER_STATE_COMMAND_DATA_MODE;
        } else if (line->len >= 4 && ((SCMemcmpLowercase("helo", line->buf, 4) == 0) ||
                                             SCMemcmpLowercase("ehlo", line->buf, 4) == 0)) {
            r = SMTPParseCommandHELO(state, line);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else if (line->len >= 9 && SCMemcmpLowercase("mail from", line->buf, 9) == 0) {
            r = SMTPParseCommandMAILFROM(state, line);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else if (line->len >= 7 && SCMemcmpLowercase("rcpt to", line->buf, 7) == 0) {
            r = SMTPParseCommandRCPTTO(state, line);
            if (r == -1) {
                SCReturnInt(-1);
            }
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        } else if (line->len >= 4 && SCMemcmpLowercase("rset", line->buf, 4) == 0) {
            // Resets chunk index in case of connection reuse
            state->bdat_chunk_idx = 0;
            state->current_command = SMTP_COMMAND_RSET;
        } else {
            state->current_command = SMTP_COMMAND_OTHER_CMD;
        }

        /* Every command is inserted into a command buffer, to be matched
         * against reply(ies) sent by the server */
        if (SMTPInsertCommandIntoCommandBuffer(state->current_command, state) == -1) {
            SCReturnInt(-1);
        }

        SCReturnInt(r);
    }

    switch (state->current_command) {
        case SMTP_COMMAND_DATA:
            return SMTPProcessCommandDATA(state, tx, f, line);

        case SMTP_COMMAND_BDAT:
            return SMTPProcessCommandBDAT(state, line);

        default:
            /* we have nothing to do with any other command at this instant.
             * Just let it go through */
            SCReturnInt(0);
    }
}

static inline void ResetLine(SMTPLine *line)
{
    if (line != NULL) {
        line->len = 0;
        line->delim_len = 0;
        line->buf = NULL;
    }
}

/*
 * @brief Pre Process the data that comes in DATA mode.
 *
 * If currently, the command that is being processed is DATA, whatever data
 * comes as a part of it must be handled by this function. This is because
 * there should be no char limit imposition on the line arriving in the DATA
 * mode. Such limits are in place for any lines passed to the GetLine function
 * and the lines are capped there at SMTP_LINE_BUFFER_LIMIT.
 * One such limit in DATA mode may lead to file data or parts of e-mail being
 * truncated if the line were too long.
 *
 * @param state  Pointer to the current SMTPState
 * @param f      Pointer to the current Flow
 * @param pstate Pointer to the current AppLayerParserState
 * @param input  Pointer to the current input data to SMTP parser
 * @param line   Pointer to the current line being parsed by the SMTP parser
 * @return  0 for success
 *          1 for handing control over to GetLine
 *         -1 for errors and inconsistent states
 * */
static int SMTPPreProcessCommands(
        SMTPState *state, Flow *f, StreamSlice *slice, SMTPInput *input, SMTPLine *line)
{
    DEBUG_VALIDATE_BUG_ON((state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) == 0);
    DEBUG_VALIDATE_BUG_ON(line->len != 0);
    DEBUG_VALIDATE_BUG_ON(line->delim_len != 0);

    /* fall back to strict line parsing for mime header parsing */
    if (state->curr_tx && state->curr_tx->mime_state &&
            SCMimeSmtpGetState(state->curr_tx->mime_state) < MimeSmtpBody)
        return 1;

    bool line_complete = false;
    const int32_t input_len = input->len;
    const int32_t offset = input->consumed;
    for (int32_t i = 0; i < input_len; i++) {
        if (input->buf[offset + i] == 0x0d) {
            if (i < input_len - 1 && input->buf[offset + i + 1] == 0x0a) {
                i++;
                line->delim_len++;
            }
            /* Line is just ending in CR */
            line->delim_len++;
            line_complete = true;
        } else if (input->buf[offset + i] == 0x0a) {
            /* Line is just ending in LF */
            line->delim_len++;
            line_complete = true;
        }
        /* Either line is complete or fragmented */
        if (line_complete || (i == input_len - 1)) {
            DEBUG_VALIDATE_BUG_ON(input->consumed + input->len != input->orig_len);
            DEBUG_VALIDATE_BUG_ON(input->len == 0 && input_len != 0);
            /* state->input_len reflects data from start of the line in progress. */
            if ((input->len == 1 && input->buf[input->consumed] == '-') ||
                    (input->len > 1 && input->buf[input->consumed] == '-' &&
                            input->buf[input->consumed + 1] == '-')) {
                SCLogDebug("Possible boundary, yield to GetLine");
                return 1;
            }
            /* total_consumed should be input consumed so far + i + 1 */
            int32_t total_consumed = offset + i + 1;
            int32_t current_line_consumed = total_consumed - input->consumed;
            DEBUG_VALIDATE_BUG_ON(current_line_consumed < line->delim_len);
            line->buf = input->buf + input->consumed;
            line->len = current_line_consumed - line->delim_len;
            DEBUG_VALIDATE_BUG_ON(line->len < 0);
            if (line->len < 0) {
                return -1;
            }

            input->consumed = total_consumed;
            input->len -= current_line_consumed;
            DEBUG_VALIDATE_BUG_ON(input->consumed + input->len != input->orig_len);
            if (SMTPProcessRequest(state, f, input, line, slice) == -1) {
                return -1;
            }
            line_complete = false;
            line->buf = NULL;
            line->len = 0;
            line->delim_len = 0;

            /* bail if `SMTPProcessRequest` ended the data mode */
            if ((state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE) == 0) {
                Frame *data_frame = AppLayerFrameGetLastOpenByType(f, 0, SMTP_FRAME_DATA);
                if (data_frame) {
                    data_frame->len = (slice->offset + input->consumed) - data_frame->offset;
                }
                break;
            }
        }
    }
    return 0;
}

static AppLayerResult SMTPParse(uint8_t direction, Flow *f, SMTPState *state,
        AppLayerParserState *pstate, StreamSlice stream_slice, SMTPThreadCtx *thread_data)
{
    SCEnter();

    const uint8_t *input_buf = StreamSliceGetData(&stream_slice);
    uint32_t input_len = StreamSliceGetDataLen(&stream_slice);

    if (input_buf == NULL &&
            ((direction == 0 && AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS)) ||
                    (direction == 1 &&
                            AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC)))) {
        SCReturnStruct(APP_LAYER_OK);
    } else if (input_buf == NULL || input_len == 0) {
        SCReturnStruct(APP_LAYER_OK);
    }

    SMTPInput input = { .buf = input_buf, .len = input_len, .orig_len = input_len, .consumed = 0 };
    SMTPLine line = { NULL, 0, 0, false };

    /* toserver */
    if (direction == 0) {
        if (((state->current_command == SMTP_COMMAND_DATA) ||
                    (state->current_command == SMTP_COMMAND_BDAT)) &&
                (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
            int ret = SMTPPreProcessCommands(state, f, &stream_slice, &input, &line);
            DEBUG_VALIDATE_BUG_ON(ret != 0 && ret != -1 && ret != 1);
            if (ret == 0 && input.consumed == input.orig_len) {
                SCReturnStruct(APP_LAYER_OK);
            } else if (ret < 0) {
                SCReturnStruct(APP_LAYER_ERROR);
            }
        }
        AppLayerResult res = SMTPGetLine(f, &stream_slice, state, &input, &line, direction);
        while (res.status == 0) {
            int retval = SMTPProcessRequest(state, f, &input, &line, &stream_slice);
            if (retval != 0)
                SCReturnStruct(APP_LAYER_ERROR);
            if (line.delim_len == 0 && line.len == SMTP_LINE_BUFFER_LIMIT) {
                if (!line.lf_found) {
                    state->discard_till_lf_ts = true;
                }
                input.consumed = input.len + 1; // For the newly found LF
                SMTPSetEvent(state, SMTP_DECODER_EVENT_TRUNCATED_LINE);
                break;
            }
            /* If request was successfully parsed, reset line as it has already been used
             * wherever it had to be */
            ResetLine(&line);

            /* If DATA mode was entered in the middle of input parsing, exempt it from GetLine as we
             * don't want input limits to be exercised on DATA data. Here, SMTPPreProcessCommands
             * should either consume all the data or return in case it encounters another boundary.
             * In case of another boundary, the control should be passed to SMTPGetLine */
            if ((input.len > 0) && (state->current_command == SMTP_COMMAND_DATA) &&
                    (state->parser_state & SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
                int ret = SMTPPreProcessCommands(state, f, &stream_slice, &input, &line);
                DEBUG_VALIDATE_BUG_ON(ret != 0 && ret != -1 && ret != 1);
                if (ret == 0 && input.consumed == input.orig_len) {
                    SCReturnStruct(APP_LAYER_OK);
                } else if (ret < 0) {
                    SCReturnStruct(APP_LAYER_ERROR);
                }
            }
            res = SMTPGetLine(f, &stream_slice, state, &input, &line, direction);
        }
        if (res.status == 1)
            return res;
        /* toclient */
    } else {
        AppLayerResult res = SMTPGetLine(f, &stream_slice, state, &input, &line, direction);
        while (res.status == 0) {
            if (SMTPProcessReply(state, f, thread_data, &input, &line) != 0)
                SCReturnStruct(APP_LAYER_ERROR);
            if (line.delim_len == 0 && line.len == SMTP_LINE_BUFFER_LIMIT) {
                if (!line.lf_found) {
                    state->discard_till_lf_tc = true;
                }
                input.consumed = input.len + 1; // For the newly found LF
                SMTPSetEvent(state, SMTP_DECODER_EVENT_TRUNCATED_LINE);
                break;
            }
            res = SMTPGetLine(f, &stream_slice, state, &input, &line, direction);
        }
        if (res.status == 1)
            return res;
    }

    SCReturnStruct(APP_LAYER_OK);
}

static AppLayerResult SMTPParseClientRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();

    /* first arg 0 is toserver */
    return SMTPParse(0, f, alstate, pstate, stream_slice, local_data);
}

static AppLayerResult SMTPParseServerRecord(Flow *f, void *alstate, AppLayerParserState *pstate,
        StreamSlice stream_slice, void *local_data)
{
    SCEnter();

    /* first arg 1 is toclient */
    return SMTPParse(1, f, alstate, pstate, stream_slice, local_data);
}

/**
 * \internal
 * \brief Function to allocate SMTP state memory.
 */
void *SMTPStateAlloc(void *orig_state, AppProto proto_orig)
{
    SMTPState *smtp_state = SCCalloc(1, sizeof(SMTPState));
    if (unlikely(smtp_state == NULL))
        return NULL;

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
    SMTPString *smtp_string = SCCalloc(1, sizeof(SMTPString));
    if (unlikely(smtp_string == NULL))
        return NULL;

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
    SMTPThreadCtx *td = SCCalloc(1, sizeof(*td));
    if (td == NULL) {
        exit(EXIT_FAILURE);
    }

    td->pmq = SCCalloc(1, sizeof(*td->pmq));
    if (td->pmq == NULL) {
        exit(EXIT_FAILURE);
    }
    PmqSetup(td->pmq);

    td->smtp_mpm_thread_ctx = SCCalloc(1, sizeof(MpmThreadCtx));
    if (unlikely(td->smtp_mpm_thread_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    MpmInitThreadCtx(td->smtp_mpm_thread_ctx, SMTP_MPM);
    return td;
}

static void SMTPLocalStorageFree(void *ptr)
{
    SMTPThreadCtx *td = ptr;
    if (td != NULL) {
        if (td->pmq != NULL) {
            PmqFree(td->pmq);
            SCFree(td->pmq);
        }

        if (td->smtp_mpm_thread_ctx != NULL) {
            MpmDestroyThreadCtx(td->smtp_mpm_thread_ctx, SMTP_MPM);
            SCFree(td->smtp_mpm_thread_ctx);
        }

        SCFree(td);
    }
}

static void SMTPTransactionFree(SMTPTransaction *tx, SMTPState *state)
{
    if (tx->mime_state != NULL) {
        SCMimeSmtpStateFree(tx->mime_state);
    }

    if (tx->tx_data.events != NULL)
        AppLayerDecoderEventsFreeEvents(&tx->tx_data.events);

    if (tx->tx_data.de_state != NULL)
        DetectEngineStateFree(tx->tx_data.de_state);

    if (tx->mail_from)
        SCFree(tx->mail_from);

    SMTPString *str = NULL;
    while ((str = TAILQ_FIRST(&tx->rcpt_to_list))) {
        TAILQ_REMOVE(&tx->rcpt_to_list, str, next);
        SMTPStringFree(str);
    }
    FileContainerRecycle(&tx->files_ts, &smtp_config.sbcfg);

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

    if (smtp_state->helo) {
        SCFree(smtp_state->helo);
    }

    SMTPTransaction *tx = NULL;
    while ((tx = TAILQ_FIRST(&smtp_state->tx_list))) {
        TAILQ_REMOVE(&smtp_state->tx_list, tx, next);
        SMTPTransactionFree(tx, smtp_state);
    }

    SCFree(smtp_state);
}

static void SMTPSetMpmState(void)
{
    smtp_mpm_ctx = SCCalloc(1, sizeof(MpmCtx));
    if (unlikely(smtp_mpm_ctx == NULL)) {
        exit(EXIT_FAILURE);
    }
    MpmInitCtx(smtp_mpm_ctx, SMTP_MPM);

    uint32_t i = 0;
    for (i = 0; i < sizeof(smtp_reply_map)/sizeof(SCEnumCharMap) - 1; i++) {
        SCEnumCharMap *map = &smtp_reply_map[i];
        /* The third argument is 3, because reply code is always 3 bytes. */
        MpmAddPatternCI(smtp_mpm_ctx, (uint8_t *)map->enum_name, 3,
                        0 /* defunct */, 0 /* defunct */,
                        i /* pattern id */, i /* rule id */ , 0 /* no flags */);
    }

    mpm_table[SMTP_MPM].Prepare(smtp_mpm_ctx);
}

static void SMTPFreeMpmState(void)
{
    if (smtp_mpm_ctx != NULL) {
        mpm_table[SMTP_MPM].DestroyCtx(smtp_mpm_ctx);
        SCFree(smtp_mpm_ctx);
        smtp_mpm_ctx = NULL;
    }
}

static int SMTPStateGetEventInfo(
        const char *event_name, uint8_t *event_id, AppLayerEventType *event_type)
{
    if (SCAppLayerGetEventIdByName(event_name, smtp_decoder_event_table, event_id) == 0) {
        *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;
        return 0;
    }
    return -1;
}

static int SMTPStateGetEventInfoById(
        uint8_t event_id, const char **event_name, AppLayerEventType *event_type)
{
    *event_name = SCMapEnumValueToName(event_id, smtp_decoder_event_table);
    if (*event_name == NULL) {
        SCLogError("event \"%d\" not present in "
                   "smtp's enum map table.",
                event_id);
        /* yes this is fatal */
        return -1;
    }

    *event_type = APP_LAYER_EVENT_TYPE_TRANSACTION;

    return 0;
}

static AppProto SMTPServerProbingParser(
        Flow *f, uint8_t direction, const uint8_t *input, uint32_t len, uint8_t *rdir)
{
    // another check for minimum length
    if (len < 5) {
        return ALPROTO_UNKNOWN;
    }
    // begins by 220
    if (input[0] != '2' || input[1] != '2' || input[2] != '0') {
        return ALPROTO_FAILED;
    }
    // followed by space or hypen
    if (input[3] != ' ' && input[3] != '-') {
        return ALPROTO_FAILED;
    }
    // If client side is SMTP, do not validate domain
    // so that server banner can be parsed first.
    if (f->alproto_ts == ALPROTO_SMTP) {
        if (memchr(input + 4, '\n', len - 4) != NULL) {
            return ALPROTO_SMTP;
        }
        return ALPROTO_UNKNOWN;
    }
    AppProto r = ALPROTO_UNKNOWN;
    if (f->todstbytecnt > 4 && f->alproto_ts == ALPROTO_UNKNOWN) {
        // Only validates SMTP if client side is unknown
        // despite having received bytes.
        r = ALPROTO_SMTP;
    }
    uint32_t offset = SCValidateDomain(input + 4, len - 4);
    if (offset == 0) {
        return ALPROTO_FAILED;
    }
    if (r != ALPROTO_UNKNOWN && memchr(input + 4, '\n', len - 4) != NULL) {
        return r;
    }
    // This should not go forever because of engine limiting probing parsers.
    return ALPROTO_UNKNOWN;
}

static int SMTPRegisterPatternsForProtocolDetection(void)
{
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SMTP,
                                               "EHLO", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SMTP,
                                               "HELO", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (AppLayerProtoDetectPMRegisterPatternCI(IPPROTO_TCP, ALPROTO_SMTP,
                                               "QUIT", 4, 0, STREAM_TOSERVER) < 0)
    {
        return -1;
    }
    if (!AppLayerProtoDetectPPParseConfPorts(
                "tcp", IPPROTO_TCP, "smtp", ALPROTO_SMTP, 0, 5, NULL, SMTPServerProbingParser)) {
        // STREAM_TOSERVER means here use 25 as flow destination port
        AppLayerProtoDetectPPRegister(IPPROTO_TCP, "25,465", ALPROTO_SMTP, 0, 5, STREAM_TOSERVER,
                NULL, SMTPServerProbingParser);
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

static int SMTPStateGetAlstateProgress(void *vtx, uint8_t direction)
{
    SMTPTransaction *tx = vtx;
    return tx->done;
}

static AppLayerGetFileState SMTPGetTxFiles(void *txv, uint8_t direction)
{
    AppLayerGetFileState files = { .fc = NULL, .cfg = &smtp_config.sbcfg };
    SMTPTransaction *tx = (SMTPTransaction *)txv;

    if (direction & STREAM_TOSERVER) {
        files.fc = &tx->files_ts;
    }
    return files;
}

static AppLayerTxData *SMTPGetTxData(void *vtx)
{
    SMTPTransaction *tx = (SMTPTransaction *)vtx;
    return &tx->tx_data;
}

static AppLayerStateData *SMTPGetStateData(void *vstate)
{
    SMTPState *state = (SMTPState *)vstate;
    return &state->state_data;
}

/** \brief SMTP tx iterator, specialized for its linked list
 *
 *  \retval txptr or NULL if no more txs in list
 */
static AppLayerGetTxIterTuple SMTPGetTxIterator(const uint8_t ipproto, const AppProto alproto,
        void *alstate, uint64_t min_tx_id, uint64_t max_tx_id, AppLayerGetTxIterState *state)
{
    SMTPState *smtp_state = (SMTPState *)alstate;
    AppLayerGetTxIterTuple no_tuple = { NULL, 0, false };
    if (smtp_state) {
        SMTPTransaction *tx_ptr;
        if (state->un.ptr == NULL) {
            tx_ptr = TAILQ_FIRST(&smtp_state->tx_list);
        } else {
            tx_ptr = (SMTPTransaction *)state->un.ptr;
        }
        if (tx_ptr) {
            while (tx_ptr->tx_id < min_tx_id) {
                tx_ptr = TAILQ_NEXT(tx_ptr, next);
                if (!tx_ptr) {
                    return no_tuple;
                }
            }
            if (tx_ptr->tx_id >= max_tx_id) {
                return no_tuple;
            }
            state->un.ptr = TAILQ_NEXT(tx_ptr, next);
            AppLayerGetTxIterTuple tuple = {
                .tx_ptr = tx_ptr,
                .tx_id = tx_ptr->tx_id,
                .has_next = (state->un.ptr != NULL),
            };
            return tuple;
        }
    }
    return no_tuple;
}

/**
 * \brief Register the SMTP Protocol parser.
 */
void RegisterSMTPParsers(void)
{
    const char *proto_name = "smtp";

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
        AppLayerParserRegisterGetEventInfoById(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetEventInfoById);

        AppLayerParserRegisterLocalStorageFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPLocalStorageAlloc,
                                               SMTPLocalStorageFree);

        AppLayerParserRegisterTxFreeFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateTransactionFree);
        AppLayerParserRegisterGetTxFilesFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPGetTxFiles);
        AppLayerParserRegisterGetStateProgressFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetAlstateProgress);
        AppLayerParserRegisterGetTxCnt(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetTxCnt);
        AppLayerParserRegisterGetTx(IPPROTO_TCP, ALPROTO_SMTP, SMTPStateGetTx);
        AppLayerParserRegisterGetTxIterator(IPPROTO_TCP, ALPROTO_SMTP, SMTPGetTxIterator);
        AppLayerParserRegisterTxDataFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPGetTxData);
        AppLayerParserRegisterStateDataFunc(IPPROTO_TCP, ALPROTO_SMTP, SMTPGetStateData);
        AppLayerParserRegisterStateProgressCompletionStatus(ALPROTO_SMTP, 1, 1);
        AppLayerParserRegisterGetFrameFuncs(
                IPPROTO_TCP, ALPROTO_SMTP, SMTPGetFrameIdByName, SMTPGetFrameNameById);
    } else {
        SCLogInfo("Parser disabled for %s protocol. Protocol detection still on.", proto_name);
    }

    SMTPSetMpmState();

    SMTPConfigure();

#ifdef UNITTESTS
    AppLayerParserRegisterProtocolUnittests(IPPROTO_TCP, ALPROTO_SMTP, SMTPParserRegisterTests);
#endif
}

/**
 * \brief Free memory allocated for global SMTP parser state.
 */
void SMTPParserCleanup(void)
{
    SMTPFreeMpmState();
}

/***************************************Unittests******************************/

#ifdef UNITTESTS
#include "detect-engine-alert.h"

static void SMTPTestInitConfig(void)
{
    smtp_config.content_limit = FILEDATA_CONTENT_LIMIT;
    smtp_config.content_inspect_window = FILEDATA_CONTENT_INSPECT_WINDOW;
    smtp_config.content_inspect_min_size = FILEDATA_CONTENT_INSPECT_MIN_SIZE;

    smtp_config.max_tx = SMTP_DEFAULT_MAX_TX;

    smtp_config.sbcfg.buf_size = FILEDATA_CONTENT_INSPECT_WINDOW;
}

/*
 * \test Test STARTTLS.
 */
static int SMTPParserTest01(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if (!FlowChangeProto(&f)) {
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Test multiple DATA commands(full mail transactions).
 */
static int SMTPParserTest02(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply4, reply4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5_1, request5_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5_2, request5_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5_3, request5_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5_4, request5_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5_5, request5_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply5, reply5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply6, reply6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request7, request7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply7, reply7_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request8, request8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply8, reply8_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request9_1, request9_1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request9_2, request9_2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request9_3, request9_3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request9_4, request9_4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {

        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request9_5, request9_5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply9, reply9_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request10, request10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply10, reply10_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Testing parsing pipelined commands.
 */
static int SMTPParserTest03(void)
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
     * Immediate data
     */
    uint8_t request2[] = {
        0x4d, 0x41, 0x49, 0x4c, 0x20, 0x46, 0x52, 0x4f,
        0x4d, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x52, 0x43, 0x50, 0x54, 0x20, 0x54,
        0x4f, 0x3a, 0x70, 0x62, 0x73, 0x66, 0x40, 0x61,
        0x73, 0x64, 0x66, 0x73, 0x2e, 0x63, 0x6f, 0x6d,
        0x0d, 0x0a, 0x44, 0x41, 0x54, 0x41, 0x0d, 0x0a,
        0x49, 0x6d, 0x6d, 0x65, 0x64, 0x69, 0x61, 0x74,
        0x65, 0x20, 0x64, 0x61, 0x74, 0x61, 0x0d, 0x0a,
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 3 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->cmds[1] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->cmds[2] != SMTP_COMMAND_DATA ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE |
                            SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE |
                            SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test smtp with just <LF> delimiter instead of <CR><LF>.
 */
static int SMTPParserTest04(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/*
 * \test Test STARTTLS fail.
 */
static int SMTPParserTest05(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_STARTTLS ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    if ((f.flags & FLOW_NOPAYLOAD_INSPECTION) ||
        (ssn.flags & STREAMTCP_FLAG_APP_LAYER_DISABLED) ||
        (((TcpSession *)f.protoctx)->server.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY) ||
        (((TcpSession *)f.protoctx)->client.flags & STREAMTCP_STREAM_FLAG_NOREASSEMBLY)) {
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_PIPELINING_SERVER)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

/**
 * \test Test multiple DATA commands(full mail transactions).
 */
static int SMTPParserTest06(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_BDAT ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE) ||
            smtp_state->bdat_chunk_len != 51 || smtp_state->bdat_chunk_idx != 0) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5, request5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE) ||
            smtp_state->bdat_chunk_len != 51 || smtp_state->bdat_chunk_idx != 32) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request6, request6_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN ||
            smtp_state->bdat_chunk_len != 51 || smtp_state->bdat_chunk_idx != 51) {
        printf("smtp parser in inconsistent state\n");
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}

static int SMTPParserTest12(void)
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
    f.alproto = ALPROTO_SMTP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER | STREAM_START, request1,
                            request1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT | STREAM_TOCLIENT, reply1,
                            reply1_len);
    if (r == 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        goto end;
    }

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
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

static int SMTPParserTest13(void)
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
    f.alproto = ALPROTO_SMTP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER | STREAM_START, request1,
                            request1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched.  It shouldn't match: ");
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("AppLayerParse for smtp failed.  Returned %" PRId32, r);
        goto end;
    }

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
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test DATA command w/MIME message.
 */
static int SMTPParserTest14(void)
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
    f.alproto = ALPROTO_SMTP;

    StreamTcpInitConfig(true);
    SMTPTestInitConfig();

    /* Welcome reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, welcome_reply, welcome_reply_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    SMTPState *smtp_state = f.alstate;
    if (smtp_state == NULL) {
        printf("no smtp state: ");
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request1, request1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* EHLO Reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply1, reply1_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    if ((smtp_state->helo_len != 7) || strncmp("boo.com", (char *)smtp_state->helo, 7)) {
        printf("incorrect parsing of HELO field '%s' (%d)\n", smtp_state->helo, smtp_state->helo_len);
        goto end;
    }

    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* MAIL FROM Request */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request2, request2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* MAIL FROM Reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply2, reply2_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    if ((smtp_state->curr_tx->mail_from_len != 14) ||
        strncmp("asdff@asdf.com", (char *)smtp_state->curr_tx->mail_from, 14)) {
        printf("incorrect parsing of MAIL FROM field '%s' (%d)\n",
               smtp_state->curr_tx->mail_from,
               smtp_state->curr_tx->mail_from_len);
        goto end;
    }

    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* RCPT TO Request */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request3, request3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* RCPT TO Reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply3, reply3_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* Enable mime decoding */
    smtp_config.decode_mime = true;
    SCMimeSmtpConfigDecodeBase64(1);
    SCMimeSmtpConfigDecodeQuoted(1);

    /* DATA request */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request4, request4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* Data reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply4, reply4_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* DATA message */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request4_msg, request4_msg_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->curr_tx->mime_state == NULL ||
            smtp_state->parser_state !=
                    (SMTP_PARSER_STATE_FIRST_REPLY_SEEN | SMTP_PARSER_STATE_COMMAND_DATA_MODE)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* DATA . request */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request4_end, request4_end_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }

    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_DATA_MODE ||
            smtp_state->curr_tx->mime_state == NULL ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    SMTPState *state = (SMTPState *) f.alstate;
    FAIL_IF_NULL(state);
    FAIL_IF_NULL(state->curr_tx);

    FileContainer *files = &state->curr_tx->files_ts;
    if (files != NULL && files->head != NULL) {
        File *file = files->head;

        if(strncmp((const char *)file->name, "test.exe", 8) != 0){
            printf("smtp-mime file name is incorrect");
            goto end;
        }
        if (FileTrackedSize(file) != filesize){
            printf("smtp-mime file size %"PRIu64" is incorrect", FileDataSize(file));
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

        if (StreamingBufferCompareRawData(file->sb,
                    org_binary, sizeof(org_binary)) != 1)
        {
            printf("smtp-mime file data incorrect\n");
            goto end;
        }
    }

    /* DATA . reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply4_end, reply4_end_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* QUIT Request */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOSERVER, request5, request5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 1 || smtp_state->cmds_idx != 0 ||
            smtp_state->cmds[0] != SMTP_COMMAND_OTHER_CMD ||
            smtp_state->parser_state != SMTP_PARSER_STATE_FIRST_REPLY_SEEN) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    /* QUIT Reply */
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_SMTP,
                            STREAM_TOCLIENT, reply5, reply5_len);
    if (r != 0) {
        printf("smtp check returned %" PRId32 ", expected 0: ", r);
        goto end;
    }
    if (smtp_state->cmds_cnt != 0 || smtp_state->cmds_idx != 0 ||
            smtp_state->parser_state != (SMTP_PARSER_STATE_FIRST_REPLY_SEEN)) {
        printf("smtp parser in inconsistent state l.%d\n", __LINE__);
        goto end;
    }

    result = 1;
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    StreamTcpFreeConfig(true);
    FLOW_DESTROY(&f);
    return result;
}
#endif /* UNITTESTS */

void SMTPParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SMTPParserTest01", SMTPParserTest01);
    UtRegisterTest("SMTPParserTest02", SMTPParserTest02);
    UtRegisterTest("SMTPParserTest03", SMTPParserTest03);
    UtRegisterTest("SMTPParserTest04", SMTPParserTest04);
    UtRegisterTest("SMTPParserTest05", SMTPParserTest05);
    UtRegisterTest("SMTPParserTest06", SMTPParserTest06);
    UtRegisterTest("SMTPParserTest12", SMTPParserTest12);
    UtRegisterTest("SMTPParserTest13", SMTPParserTest13);
    UtRegisterTest("SMTPParserTest14", SMTPParserTest14);
#endif /* UNITTESTS */
}
