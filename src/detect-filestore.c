/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-filestore.h"

/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

int DetectFilestoreMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t, void *, Signature *, SigMatch *);
static int DetectFilestoreSetup (DetectEngineCtx *, Signature *, char *);

/**
 * \brief Registration function for keyword: filestore
 */
void DetectFilestoreRegister(void) {
    sigmatch_table[DETECT_FILESTORE].name = "filestore";
    sigmatch_table[DETECT_FILESTORE].Match = NULL;
    sigmatch_table[DETECT_FILESTORE].AppLayerMatch = DetectFilestoreMatch;
    sigmatch_table[DETECT_FILESTORE].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESTORE].Setup = DetectFilestoreSetup;
    sigmatch_table[DETECT_FILESTORE].Free  = NULL;
    sigmatch_table[DETECT_FILESTORE].RegisterTests = NULL;

    const char *eb;
    int eo;
    int opts = 0;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }
	SCLogDebug("registering filestore rule option");
    return;
error:
    /* XXX */
    return;
}

/**
 * \brief match the specified filestore
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectFilestoreData
 *
 * \retval 0 no match
 * \retval 1 match
 *
 * \todo when we start supporting more protocols, the logic in this function
 *       needs to be put behind a api.
 */
int DetectFilestoreMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    SCEnter();
    DetectFilestoreData *filestore = m->ctx;
    if (filestore != NULL) {
        int this_file = 0;
        int this_tx = 0;
        int this_flow = 0;
        int rule_dir = 0;
        int toserver_dir = 0;
        int toclient_dir = 0;

        switch (filestore->direction) {
            case FILESTORE_DIR_DEFAULT:
                rule_dir = 1;
                break;
            case FILESTORE_DIR_BOTH:
                toserver_dir = 1;
                toclient_dir = 1;
                break;
            case FILESTORE_DIR_TOSERVER:
                toserver_dir = 1;
                break;
            case FILESTORE_DIR_TOCLIENT:
                toclient_dir = 1;
                break;
        }

        switch (filestore->scope) {
            case FILESTORE_SCOPE_DEFAULT:
                if (rule_dir) {
                    this_file = 1;
                } else if (flags & STREAM_TOCLIENT && toclient_dir) {
                    this_file = 1;
                } else if (flags & STREAM_TOSERVER && toserver_dir) {
                    this_file = 1;
                }
                break;
            case FILESTORE_SCOPE_TX:
                this_tx = 1;
                break;
            case FILESTORE_SCOPE_SSN:
                this_flow = 1;
                break;
        }

        if (this_file) {
            File *file = (File *)state;
            FileStore(file);
        } else if (this_tx) {
            /* flag tx all files will be stored */
            if (f->alproto == ALPROTO_HTTP && f->alstate != NULL) {
                HtpState *htp_state = f->alstate;
                if (toserver_dir) {
                    htp_state->flags |= HTP_FLAG_STORE_FILES_TX_TS;
                    FileStoreAllFilesForTx(htp_state->files_ts, det_ctx->tx_id);
                }
                if (toclient_dir) {
                    htp_state->flags |= HTP_FLAG_STORE_FILES_TX_TC;
                    FileStoreAllFilesForTx(htp_state->files_tc, det_ctx->tx_id);
                }
                htp_state->store_tx_id = det_ctx->tx_id;
            }

        } else if (this_flow) {
            /* flag flow all files will be stored */
            if (f->alproto == ALPROTO_HTTP && f->alstate != NULL) {
                HtpState *htp_state = f->alstate;
                if (toserver_dir) {
                    htp_state->flags |= HTP_FLAG_STORE_FILES_TS;
                    FileStoreAllFiles(htp_state->files_ts);
                }
                if (toclient_dir) {
                    htp_state->flags |= HTP_FLAG_STORE_FILES_TC;
                    FileStoreAllFiles(htp_state->files_tc);
                }
            }
        } else {
            File *file = (File *)state;
            FileStore(file);
        }
    } else {
        File *file = (File *)state;
        FileStore(file);
    }
    SCReturnInt(1);
}

/**
 * \brief this function is used to parse filestore options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filestore" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilestoreSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();

    DetectFilestoreData *fd = NULL;
    SigMatch *sm = NULL;
    char *args[3] = {NULL,NULL,NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILESTORE;

    if (str != NULL && strlen(str) > 0) {
        SCLogDebug("str %s", str);

        ret = pcre_exec(parse_regex, parse_regex_study, str, strlen(str), 0, 0, ov, MAX_SUBSTRINGS);
        if (ret < 1 || ret > 4) {
            SCLogError(SC_ERR_PCRE_MATCH, "parse error, ret %" PRId32 ", string %s", ret, str);
            goto error;
        }

        if (ret > 1) {
            const char *str_ptr;
            res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 1, &str_ptr);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }
            args[0] = (char *)str_ptr;

            if (ret > 2) {
                res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 2, &str_ptr);
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }
                args[1] = (char *)str_ptr;
            }
            if (ret > 3) {
                res = pcre_get_substring((char *)str, ov, MAX_SUBSTRINGS, 3, &str_ptr);
                if (res < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }
                args[2] = (char *)str_ptr;
            }
        }

        fd = SCMalloc(sizeof(DetectFilestoreData));
        if (fd == NULL)
            goto error;
        memset(fd, 0x00, sizeof(DetectFilestoreData));

        if (args[0] != NULL) {
            SCLogDebug("first arg %s", args[0]);

            if (strcasecmp(args[0], "request") == 0 ||
                    strcasecmp(args[0], "to_server") == 0)
            {
                fd->direction = FILESTORE_DIR_TOSERVER;
                fd->scope = FILESTORE_SCOPE_TX;
            }
            else if (strcasecmp(args[0], "response") == 0 ||
                    strcasecmp(args[0], "to_client") == 0)
            {
                fd->direction = FILESTORE_DIR_TOCLIENT;
                fd->scope = FILESTORE_SCOPE_TX;
            }
            else if (strcasecmp(args[0], "both") == 0)
            {
                fd->direction = FILESTORE_DIR_BOTH;
                fd->scope = FILESTORE_SCOPE_TX;
            }
        } else {
            fd->direction = FILESTORE_DIR_DEFAULT;
        }

        if (args[1] != NULL) {
            SCLogDebug("second arg %s", args[1]);

            if (strcasecmp(args[1], "file") == 0)
            {
                fd->scope = FILESTORE_SCOPE_DEFAULT;
            } else if (strcasecmp(args[1], "tx") == 0)
            {
                fd->scope = FILESTORE_SCOPE_TX;
            } else if (strcasecmp(args[1], "ssn") == 0 ||
                       strcasecmp(args[1], "flow") == 0)
            {
                fd->scope = FILESTORE_SCOPE_SSN;
            }
        } else {
            if (fd->scope == 0)
                fd->scope = FILESTORE_SCOPE_DEFAULT;
        }

        sm->ctx = fd;
    } else {
        sm->ctx = NULL;
    }

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_HTTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    AppLayerHtpNeedFileInspection();

    s->alproto = ALPROTO_HTTP;

    s->init_flags |= SIG_FLAG_FILESTORE;
    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}
