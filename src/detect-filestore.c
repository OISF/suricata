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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the filestore keyword
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
#include "app-layer-parser.h"

#include "stream-tcp.h"

#include "detect-filestore.h"

/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectFilestoreMatch (ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, const Signature *, const SigMatchCtx *);
static int DetectFilestoreSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFilestoreFree(void *);
static void DetectFilestoreRegisterTests(void);
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for keyword: filestore
 */
void DetectFilestoreRegister(void)
{
    sigmatch_table[DETECT_FILESTORE].name = "filestore";
    sigmatch_table[DETECT_FILESTORE].desc = "stores files to disk if the rule matched";
    sigmatch_table[DETECT_FILESTORE].url = DOC_URL DOC_VERSION "/rules/file-keywords.html#filestore";
    sigmatch_table[DETECT_FILESTORE].FileMatch = DetectFilestoreMatch;
    sigmatch_table[DETECT_FILESTORE].Setup = DetectFilestoreSetup;
    sigmatch_table[DETECT_FILESTORE].Free  = DetectFilestoreFree;
    sigmatch_table[DETECT_FILESTORE].RegisterTests = DetectFilestoreRegisterTests;
    sigmatch_table[DETECT_FILESTORE].flags = SIGMATCH_OPTIONAL_OPT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    g_file_match_list_id = DetectBufferTypeRegister("files");
}

/**
 *  \brief apply the post match filestore with options
 */
static int FilestorePostMatchWithOptions(Packet *p, Flow *f, const DetectFilestoreData *filestore, FileContainer *fc,
        uint16_t file_id, uint16_t tx_id)
{
    if (filestore == NULL) {
        SCReturnInt(0);
    }

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
            } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && toclient_dir) {
                this_file = 1;
            } else if ((p->flowflags & FLOW_PKT_TOSERVER) && toserver_dir) {
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

    if (this_file)  {
        FileStoreFileById(fc, file_id);
    } else if (this_tx) {
        /* flag tx all files will be stored */
        if (f->alproto == ALPROTO_HTTP && f->alstate != NULL) {
            HtpState *htp_state = f->alstate;
            if (toserver_dir) {
                htp_state->flags |= HTP_FLAG_STORE_FILES_TX_TS;
                FileStoreAllFilesForTx(htp_state->files_ts, tx_id);
            }
            if (toclient_dir) {
                htp_state->flags |= HTP_FLAG_STORE_FILES_TX_TC;
                FileStoreAllFilesForTx(htp_state->files_tc, tx_id);
            }
            htp_state->store_tx_id = tx_id;
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
        FileStoreFileById(fc, file_id);
    }

    SCReturnInt(0);
}

/**
 *  \brief post-match function for filestore
 *
 *  \param t thread local vars
 *  \param det_ctx pattern matcher thread local data
 *  \param p packet
 *
 *  The match function for filestore records store candidates in the det_ctx.
 *  When we are sure all parts of the signature matched, we run this function
 *  to finalize the filestore.
 */
int DetectFilestorePostMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, const Signature *s)
{
    uint8_t flags = 0;

    SCEnter();

    if (det_ctx->filestore_cnt == 0) {
        SCReturnInt(0);
    }

    if ((s->filestore_ctx == NULL && !(s->flags & SIG_FLAG_FILESTORE)) || p->flow == NULL) {
#ifndef DEBUG
        SCReturnInt(0);
#else
        BUG_ON(1);
#endif
    }

    /* set filestore depth for stream reassembling */
    TcpSession *ssn = (TcpSession *)p->flow->protoctx;
    TcpSessionSetReassemblyDepth(ssn, FileReassemblyDepth());

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= STREAM_TOCLIENT;
    else
        flags |= STREAM_TOSERVER;

    FileContainer *ffc = AppLayerParserGetFiles(p->flow->proto, p->flow->alproto,
                                                p->flow->alstate, flags);

    /* filestore for single files only */
    if (s->filestore_ctx == NULL) {
        uint16_t u;
        for (u = 0; u < det_ctx->filestore_cnt; u++) {
            FileStoreFileById(ffc, det_ctx->filestore[u].file_id);
        }
    } else {
        uint16_t u;

        for (u = 0; u < det_ctx->filestore_cnt; u++) {
            FilestorePostMatchWithOptions(p, p->flow, s->filestore_ctx, ffc,
                    det_ctx->filestore[u].file_id, det_ctx->filestore[u].tx_id);
        }
    }

    SCReturnInt(0);
}

/**
 * \brief match the specified filestore
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFilestoreData
 *
 * \retval 0 no match
 * \retval 1 match
 *
 * \todo when we start supporting more protocols, the logic in this function
 *       needs to be put behind a api.
 */
static int DetectFilestoreMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    uint16_t file_id = 0;

    SCEnter();

    if (det_ctx->filestore_cnt >= DETECT_FILESTORE_MAX) {
        SCReturnInt(1);
    }

    /* file can be NULL when a rule with filestore scope > file
     * matches. */
    if (file != NULL) {
        file_id = file->file_store_id;
    }

    det_ctx->filestore[det_ctx->filestore_cnt].file_id = file_id;
    det_ctx->filestore[det_ctx->filestore_cnt].tx_id = det_ctx->tx_id;

    SCLogDebug("%u, file %u, tx %"PRIu64, det_ctx->filestore_cnt,
        det_ctx->filestore[det_ctx->filestore_cnt].file_id,
        det_ctx->filestore[det_ctx->filestore_cnt].tx_id);

    det_ctx->filestore_cnt++;
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
static int DetectFilestoreSetup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    DetectFilestoreData *fd = NULL;
    SigMatch *sm = NULL;
    char *args[3] = {NULL,NULL,NULL};
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    /* filestore and bypass keywords can't work together */
    if (s->flags & SIG_FLAG_BYPASS) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                   "filestore can't work with bypass keyword");
        return -1;
    }

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
        if (unlikely(fd == NULL))
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

        sm->ctx = (SigMatchCtx*)fd;
    } else {
        sm->ctx = (SigMatchCtx*)NULL;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    SigMatchAppendSMToList(s, sm, g_file_match_list_id);
    s->filestore_ctx = (const DetectFilestoreData *)sm->ctx;

    s->flags |= SIG_FLAG_FILESTORE;
    return 0;

error:
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

static void DetectFilestoreFree(void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

#ifdef UNITTESTS
/*
 * The purpose of this test is to confirm that
 * filestore and bypass keywords can't
 * can't work together
 */
static int DetectFilestoreTest01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert http any any -> any any "
                               "(bypass; filestore; "
                               "content:\"message\"; http_host; "
                               "sid:1;)");
    FAIL_IF_NOT_NULL(de_ctx->sig_list);

    DetectEngineCtxFree(de_ctx);

    return result;
}
#endif /* UNITTESTS */

void DetectFilestoreRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectFilestoreTest01", DetectFilestoreTest01);
#endif /* UNITTESTS */
}
