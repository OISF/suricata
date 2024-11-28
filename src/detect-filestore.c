/* Copyright (C) 2007-2021 Open Information Security Foundation
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
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "feature.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "stream-tcp.h"

#include "detect-filestore.h"

#include "util-validate.h"

/**
 * \brief Regex for parsing our flow options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+))?\\s*(?:,\\s*([A-z_]+))?\\s*$"

static DetectParseRegex parse_regex;

static int DetectFilestoreMatch (DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, const Signature *, const SigMatchCtx *);
static int DetectFilestorePostMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx);
static int DetectFilestoreSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectFilestoreFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectFilestoreRegisterTests(void);
#endif
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for keyword: filestore
 */
void DetectFilestoreRegister(void)
{
    sigmatch_table[DETECT_FILESTORE].name = "filestore";
    sigmatch_table[DETECT_FILESTORE].desc = "stores files to disk if the rule matched";
    sigmatch_table[DETECT_FILESTORE].url = "/rules/file-keywords.html#filestore";
    sigmatch_table[DETECT_FILESTORE].FileMatch = DetectFilestoreMatch;
    sigmatch_table[DETECT_FILESTORE].Setup = DetectFilestoreSetup;
    sigmatch_table[DETECT_FILESTORE].Free  = DetectFilestoreFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILESTORE].RegisterTests = DetectFilestoreRegisterTests;
#endif
    sigmatch_table[DETECT_FILESTORE].flags = SIGMATCH_OPTIONAL_OPT;

    sigmatch_table[DETECT_FILESTORE_POSTMATCH].name = "__filestore__postmatch__";
    sigmatch_table[DETECT_FILESTORE_POSTMATCH].Match = DetectFilestorePostMatch;
    sigmatch_table[DETECT_FILESTORE_POSTMATCH].Free  = DetectFilestoreFree;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    g_file_match_list_id = DetectBufferTypeRegister("files");
}

static void FilestoreTriggerFlowStorage(Flow *f, int toserver_dir, int toclient_dir)
{
    /* set in flow and AppLayerStateData */
    AppLayerStateData *sd = AppLayerParserGetStateData(f->proto, f->alproto, f->alstate);
    if (toclient_dir) {
        f->file_flags |= FLOWFILE_STORE_TC;
        if (sd != NULL) {
            sd->file_flags |= FLOWFILE_STORE_TC;
        }
    }
    if (toserver_dir) {
        f->file_flags |= FLOWFILE_STORE_TS;
        if (sd != NULL) {
            sd->file_flags |= FLOWFILE_STORE_TS;
        }
    }
    /* Start storage for all existing files attached to the flow in correct direction */
    void *alstate = FlowGetAppState(f);
    if (alstate != NULL) {
        uint64_t total_txs = AppLayerParserGetTxCnt(f, alstate);
        for (uint64_t tx_id = 0; tx_id < total_txs; tx_id++) {
            void *txv = AppLayerParserGetTx(f->proto, f->alproto, alstate, tx_id);
            DEBUG_VALIDATE_BUG_ON(txv == NULL);
            if (txv != NULL) {
                AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, txv);
                DEBUG_VALIDATE_BUG_ON(txd == NULL);
                if (txd != NULL) {
                    if (toclient_dir) {
                        txd->file_flags |= FLOWFILE_STORE_TC;
                    }
                    if (toserver_dir) {
                        txd->file_flags |= FLOWFILE_STORE_TS;
                    }
                }
            }
        }
    }
}

/**
 *  \brief apply the post match filestore with options
 */
static int FilestorePostMatchWithOptions(Packet *p, Flow *f, const DetectFilestoreData *filestore,
        FileContainer *fc, uint32_t file_id, uint64_t tx_id)
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
            // will use both sides if scope is not default
            // fallthrough
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
        /* set in AppLayerTxData. Parsers and logger will propagate it to the
         * individual files, both new and current. */
        void *txv = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
        DEBUG_VALIDATE_BUG_ON(txv == NULL);
        if (txv != NULL) {
            AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, txv);
            DEBUG_VALIDATE_BUG_ON(txd == NULL);
            if (txd != NULL) {
                if (toclient_dir) {
                    txd->file_flags |= FLOWFILE_STORE_TC;
                }
                if (toserver_dir) {
                    txd->file_flags |= FLOWFILE_STORE_TS;
                }
            }
        }
    } else if (this_flow) {
        FilestoreTriggerFlowStorage(f, toserver_dir, toclient_dir);
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
static int DetectFilestorePostMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();

    if (p->flow == NULL) {
#ifndef DEBUG
        SCReturnInt(0);
#else
        BUG_ON(1);
#endif
    }

    if (det_ctx->filestore_cnt == 0) {
        if (s->filestore_ctx && (s->filestore_ctx->scope == FILESTORE_SCOPE_SSN)) {
            int toserver_dir = 0;
            int toclient_dir = 0;
            switch (s->filestore_ctx->direction) {
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
            FilestoreTriggerFlowStorage(p->flow, toserver_dir, toclient_dir);
        }
        SCReturnInt(0);
    }

    if (s->filestore_ctx == NULL && !(s->flags & SIG_FLAG_FILESTORE)) {
#ifndef DEBUG
        SCReturnInt(0);
#else
        BUG_ON(1);
#endif
    }

    if (p->flow->proto == IPPROTO_TCP && p->flow->protoctx != NULL) {
        /* set filestore depth for stream reassembling */
        TcpSession *ssn = (TcpSession *)p->flow->protoctx;
        TcpSessionSetReassemblyDepth(ssn, FileReassemblyDepth());
    }

    SCLogDebug("s->filestore_ctx %p", s->filestore_ctx);

    const uint8_t flags = STREAM_FLAGS_FOR_PACKET(p);
    for (uint16_t u = 0; u < det_ctx->filestore_cnt; u++) {
        void *alstate = FlowGetAppState(p->flow);
        AppLayerParserSetStreamDepthFlag(
                p->flow->proto, p->flow->alproto, alstate, det_ctx->filestore[u].tx_id, flags);

        void *txv = AppLayerParserGetTx(
                p->flow->proto, p->flow->alproto, alstate, det_ctx->filestore[u].tx_id);
        DEBUG_VALIDATE_BUG_ON(txv == NULL);
        if (txv) {
            AppLayerGetFileState files = AppLayerParserGetTxFiles(p->flow, txv, flags);
            FileContainer *ffc_tx = files.fc;
            DEBUG_VALIDATE_BUG_ON(ffc_tx == NULL);
            if (ffc_tx) {
                SCLogDebug("u %u txv %p ffc_tx %p file_id %u", u, txv, ffc_tx,
                        det_ctx->filestore[u].file_id);

                /* filestore for single files only */
                if (s->filestore_ctx == NULL) {
                    FileStoreFileById(ffc_tx, det_ctx->filestore[u].file_id);
                } else {
                    FilestorePostMatchWithOptions(p, p->flow, s->filestore_ctx, ffc_tx,
                            det_ctx->filestore[u].file_id, det_ctx->filestore[u].tx_id);
                }
            }
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
static int DetectFilestoreMatch (DetectEngineThreadCtx *det_ctx, Flow *f,
        uint8_t flags, File *file, const Signature *s, const SigMatchCtx *m)
{
    uint32_t file_id = 0;

    SCEnter();

    if (!RunmodeIsUnittests()) {
        extern bool g_filedata_logger_enabled;
        if (!g_filedata_logger_enabled) {
            SCLogDebug("not storing file match: no filedata logger enabled");
            SCReturnInt(1);
        }
    }
    if (det_ctx->filestore_cnt >= DETECT_FILESTORE_MAX) {
        SCReturnInt(1);
    }

    /* file can be NULL when a rule with filestore scope > file
     * matches. */
    if (file != NULL) {
        file_id = file->file_track_id;
        if (file->sid != NULL && s->id > 0) {
            if (file->sid_cnt >= file->sid_max) {
                void *p = SCRealloc(file->sid, sizeof(uint32_t) * (file->sid_max + 8));
                if (p == NULL) {
                    SCFree(file->sid);
                    file->sid = NULL;
                    file->sid_cnt = 0;
                    file->sid_max = 0;
                    goto continue_after_realloc_fail;
                } else {
                    file->sid = p;
                    file->sid_max += 8;
                }
            }
            file->sid[file->sid_cnt] = s->id;
            file->sid_cnt++;
        }
    }

continue_after_realloc_fail:

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

    static bool warn_not_configured = false;
    static uint32_t de_version = 0;

    if (de_ctx->filestore_cnt == UINT16_MAX) {
        SCLogError("Cannot have more than 65535 filestore signatures");
        return -1;
    }

    /* Check on first-time loads (includes following a reload) */
    if (!warn_not_configured || (de_ctx->version != de_version)) {
        if (de_version != de_ctx->version) {
            SCLogDebug("reload-detected; re-checking feature presence; DE version now %"PRIu32,
                       de_ctx->version);
        }
        if (!RequiresFeature(FEATURE_OUTPUT_FILESTORE)) {
            SCLogWarning("One or more rule(s) depends on the "
                         "file-store output log which is not enabled. "
                         "Enable the output \"file-store\".");
        }
        warn_not_configured = true;
        de_version = de_ctx->version;
    }

    DetectFilestoreData *fd = NULL;
    char *args[3] = {NULL,NULL,NULL};
    int res = 0;
    size_t pcre2len;
    pcre2_match_data *match = NULL;

    /* filestore and bypass keywords can't work together */
    if (s->flags & SIG_FLAG_BYPASS) {
        SCLogError("filestore can't work with bypass keyword");
        return -1;
    }

    if (str != NULL && strlen(str) > 0) {
        char str_0[32];
        char str_1[32];
        char str_2[32];
        SCLogDebug("str %s", str);

        int ret = DetectParsePcreExec(&parse_regex, &match, str, 0, 0);
        if (ret < 1 || ret > 4) {
            SCLogError("parse error, ret %" PRId32 ", string %s", ret, str);
            goto error;
        }

        if (ret > 1) {
            pcre2len = sizeof(str_0);
            res = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)str_0, &pcre2len);
            if (res < 0) {
                SCLogError("pcre2_substring_copy_bynumber failed");
                goto error;
            }
            args[0] = (char *)str_0;

            if (ret > 2) {
                pcre2len = sizeof(str_1);
                res = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)str_1, &pcre2len);
                if (res < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    goto error;
                }
                args[1] = (char *)str_1;
            }
            if (ret > 3) {
                pcre2len = sizeof(str_2);
                res = pcre2_substring_copy_bynumber(match, 3, (PCRE2_UCHAR8 *)str_2, &pcre2len);
                if (res < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    goto error;
                }
                args[2] = (char *)str_2;
            }
        }

        fd = SCCalloc(1, sizeof(DetectFilestoreData));
        if (unlikely(fd == NULL))
            goto error;

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
    }

    if (s->alproto == ALPROTO_HTTP1 || s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FILESTORE, (SigMatchCtx *)fd, g_file_match_list_id) == NULL) {
        DetectFilestoreFree(de_ctx, fd);
        goto error;
    }
    s->filestore_ctx = fd;

    if (SigMatchAppendSMToList(
                de_ctx, s, DETECT_FILESTORE_POSTMATCH, NULL, DETECT_SM_LIST_POSTMATCH) == NULL) {
        goto error;
    }

    s->flags |= SIG_FLAG_FILESTORE;
    de_ctx->filestore_cnt++;

    if (match)
        pcre2_match_data_free(match);

    return 0;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    return -1;
}

static void DetectFilestoreFree(DetectEngineCtx *de_ctx, void *ptr)
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

void DetectFilestoreRegisterTests(void)
{
    UtRegisterTest("DetectFilestoreTest01", DetectFilestoreTest01);
}
#endif /* UNITTESTS */
