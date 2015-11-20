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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Basic detection engine
 */

#include "suricata-common.h"
#include "suricata.h"
#include "debug.h"
#include "detect.h"
#include "flow.h"
#include "flow-private.h"
#include "flow-bit.h"

#include "detect-parse.h"
#include "detect-engine.h"

#include "detect-engine-alert.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-engine-threshold.h"

#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-dns-query.h"
#include "detect-engine-state.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-filedata-smtp.h"

#include "detect-http-cookie.h"
#include "detect-http-method.h"
#include "detect-http-ua.h"
#include "detect-http-hh.h"
#include "detect-http-hrh.h"

#include "detect-engine-event.h"
#include "decode.h"

#include "detect-base64-decode.h"
#include "detect-base64-data.h"
#include "detect-ipopts.h"
#include "detect-flags.h"
#include "detect-fragbits.h"
#include "detect-fragoffset.h"
#include "detect-gid.h"
#include "detect-ack.h"
#include "detect-seq.h"
#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-depth.h"
#include "detect-nocase.h"
#include "detect-rawbytes.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-sameip.h"
#include "detect-l3proto.h"
#include "detect-ipproto.h"
#include "detect-within.h"
#include "detect-distance.h"
#include "detect-offset.h"
#include "detect-sid.h"
#include "detect-priority.h"
#include "detect-classtype.h"
#include "detect-reference.h"
#include "detect-tag.h"
#include "detect-threshold.h"
#include "detect-metadata.h"
#include "detect-msg.h"
#include "detect-rev.h"
#include "detect-flow.h"
#include "detect-window.h"
#include "detect-ftpbounce.h"
#include "detect-isdataat.h"
#include "detect-id.h"
#include "detect-rpc.h"
#include "detect-asn1.h"
#include "detect-filename.h"
#include "detect-fileext.h"
#include "detect-filestore.h"
#include "detect-filemagic.h"
#include "detect-filemd5.h"
#include "detect-filesize.h"
#include "detect-dsize.h"
#include "detect-flowvar.h"
#include "detect-flowint.h"
#include "detect-pktvar.h"
#include "detect-noalert.h"
#include "detect-flowbits.h"
#include "detect-hostbits.h"
#include "detect-xbits.h"
#include "detect-csum.h"
#include "detect-stream_size.h"
#include "detect-engine-sigorder.h"
#include "detect-ttl.h"
#include "detect-fast-pattern.h"
#include "detect-itype.h"
#include "detect-icode.h"
#include "detect-icmp-id.h"
#include "detect-icmp-seq.h"
#include "detect-dce-iface.h"
#include "detect-dce-opnum.h"
#include "detect-dce-stub-data.h"
#include "detect-urilen.h"
#include "detect-detection-filter.h"
#include "detect-http-client-body.h"
#include "detect-http-server-body.h"
#include "detect-http-header.h"
#include "detect-http-raw-header.h"
#include "detect-http-uri.h"
#include "detect-http-raw-uri.h"
#include "detect-http-stat-msg.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hsbd.h"
#include "detect-engine-hhd.h"
#include "detect-engine-hrhd.h"
#include "detect-engine-hmd.h"
#include "detect-engine-hcd.h"
#include "detect-engine-hrud.h"
#include "detect-engine-hsmd.h"
#include "detect-engine-hscd.h"
#include "detect-engine-hua.h"
#include "detect-engine-hhhd.h"
#include "detect-engine-hrhhd.h"
#include "detect-byte-extract.h"
#include "detect-file-data.h"
#include "detect-pkt-data.h"
#include "detect-replace.h"
#include "detect-tos.h"
#include "detect-app-layer-event.h"
#include "detect-lua.h"
#include "detect-iprep.h"
#include "detect-geoip.h"
#include "detect-dns-query.h"
#include "detect-app-layer-protocol.h"
#include "detect-template.h"
#include "detect-template-buffer.h"

#include "util-rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "app-layer-template.h"
#include "detect-tls.h"
#include "detect-tls-version.h"
#include "detect-ssh-proto-version.h"
#include "detect-ssh-software-version.h"
#include "detect-http-stat-code.h"
#include "detect-ssl-version.h"
#include "detect-ssl-state.h"
#include "detect-modbus.h"

#include "action-globals.h"
#include "tm-threads.h"

#include "pkt-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"
#include "stream-tcp-inline.h"

#include "util-var-name.h"
#include "util-classification-config.h"
#include "util-print.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "util-hashlist.h"
#include "util-cuda.h"
#include "util-privs.h"
#include "util-profiling.h"
#include "util-validate.h"
#include "util-optimize.h"
#include "util-path.h"
#include "util-mpm-ac.h"

#include "runmodes.h"

#include <glob.h>

extern int rule_reload;

extern int engine_analysis;
static int fp_engine_analysis_set = 0;
static int rule_engine_analysis_set = 0;

SigMatch *SigMatchAlloc(void);
void DetectExitPrintStats(ThreadVars *tv, void *data);

void DbgPrintSigs(DetectEngineCtx *, SigGroupHead *);
void DbgPrintSigs2(DetectEngineCtx *, SigGroupHead *);
static void PacketCreateMask(Packet *, SignatureMask *, uint16_t, int, StreamMsg *, int);

/* tm module api functions */
TmEcode Detect(ThreadVars *, Packet *, void *, PacketQueue *, PacketQueue *);
TmEcode DetectThreadInit(ThreadVars *, void *, void **);
TmEcode DetectThreadDeinit(ThreadVars *, void *);

void TmModuleDetectRegister (void)
{
    tmm_modules[TMM_DETECT].name = "Detect";
    tmm_modules[TMM_DETECT].ThreadInit = DetectThreadInit;
    tmm_modules[TMM_DETECT].Func = Detect;
    tmm_modules[TMM_DETECT].ThreadExitPrintStats = DetectExitPrintStats;
    tmm_modules[TMM_DETECT].ThreadDeinit = DetectThreadDeinit;
    tmm_modules[TMM_DETECT].RegisterTests = SigRegisterTests;
    tmm_modules[TMM_DETECT].cap_flags = 0;
    tmm_modules[TMM_DETECT].flags = TM_FLAG_DETECT_TM;

    PacketAlertTagInit();
}

void DetectExitPrintStats(ThreadVars *tv, void *data)
{
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    if (det_ctx == NULL)
        return;
}

/**
 *  \brief Create the path if default-rule-path was specified
 *  \param sig_file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */
char *DetectLoadCompleteSigPath(const DetectEngineCtx *de_ctx, char *sig_file)
{
    char *defaultpath = NULL;
    char *path = NULL;
    char varname[128] = "default-rule-path";

    if (strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.default-rule-path",
                de_ctx->config_prefix);
    }

    /* Path not specified */
    if (PathIsRelative(sig_file)) {
        if (ConfGet(varname, &defaultpath) == 1) {
            SCLogDebug("Default path: %s", defaultpath);
            size_t path_len = sizeof(char) * (strlen(defaultpath) +
                          strlen(sig_file) + 2);
            path = SCMalloc(path_len);
            if (unlikely(path == NULL))
                return NULL;
            strlcpy(path, defaultpath, path_len);
#if defined OS_WIN32 || defined __CYGWIN__
            if (path[strlen(path) - 1] != '\\')
                strlcat(path, "\\\\", path_len);
#else
            if (path[strlen(path) - 1] != '/')
                strlcat(path, "/", path_len);
#endif
            strlcat(path, sig_file, path_len);
       } else {
            path = SCStrdup(sig_file);
            if (unlikely(path == NULL))
                return NULL;
        }
    } else {
        path = SCStrdup(sig_file);
        if (unlikely(path == NULL))
            return NULL;
    }
    return path;
}

/**
 *  \brief Load a file with signatures
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename to load signatures from
 *  \param goodsigs_tot Will store number of valid signatures in the file
 *  \param badsigs_tot Will store number of invalid signatures in the file
 *  \retval 0 on success, -1 on error
 */
static int DetectLoadSigFile(DetectEngineCtx *de_ctx, char *sig_file,
        int *goodsigs, int *badsigs)
{
    Signature *sig = NULL;
    int good = 0, bad = 0;
    char line[DETECT_MAX_RULE_SIZE] = "";
    size_t offset = 0;
    int lineno = 0, multiline = 0;

    (*goodsigs) = 0;
    (*badsigs) = 0;

    FILE *fp = fopen(sig_file, "r");
    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening rule file %s:"
                   " %s.", sig_file, strerror(errno));
        return -1;
    }

    while(fgets(line + offset, (int)sizeof(line) - offset, fp) != NULL) {
        lineno++;
        size_t len = strlen(line);

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line [0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        /* Check for multiline rules. */
        while (len > 0 && isspace((unsigned char)line[--len]));
        if (line[len] == '\\') {
            multiline++;
            offset = len;
            if (offset < sizeof(line) - 1) {
                /* We have room for more. */
                continue;
            }
            /* No more room in line buffer, continue, rule will fail
             * to parse. */
        }

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
        }

        /* Reset offset. */
        offset = 0;

        de_ctx->rule_file = sig_file;
        de_ctx->rule_line = lineno - multiline;

        sig = DetectEngineAppendSig(de_ctx, line);
        if (sig != NULL) {
            if (rule_engine_analysis_set || fp_engine_analysis_set) {
                sig->mpm_sm = RetrieveFPForSigV2(sig);
                if (fp_engine_analysis_set) {
                    EngineAnalysisFP(sig, line);
                }
                if (rule_engine_analysis_set) {
                    EngineAnalysisRules(sig, line);
                }
            }
            SCLogDebug("signature %"PRIu32" loaded", sig->id);
            good++;
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "error parsing signature \"%s\" from "
                 "file %s at line %"PRId32"", line, sig_file, lineno - multiline);

            if (rule_engine_analysis_set) {
                EngineAnalysisRulesFailure(line, sig_file, lineno - multiline);
            }
            bad++;
        }
        multiline = 0;
    }
    fclose(fp);

    *goodsigs = good;
    *badsigs = bad;
    return 0;
}

/**
 *  \brief Expands wildcards and reads signatures from each matching file
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename (or pattern) holding signatures
 *  \retval -1 on error
 */
static int ProcessSigFiles(DetectEngineCtx *de_ctx, char *pattern,
        SigFileLoaderStat *st, int *good_sigs, int *bad_sigs)
{
    if (pattern == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "opening rule file null");
        return -1;
    }

    glob_t files;
    int r = glob(pattern, 0, NULL, &files);

    if (r == GLOB_NOMATCH) {
        SCLogWarning(SC_ERR_NO_RULES, "No rule files match the pattern %s", pattern);
        ++(st->bad_files);
        ++(st->total_files);
        return -1;
    } else if (r != 0) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "error expanding template %s: %s",
                 pattern, strerror(errno));
        return -1;
    }

    for (size_t i = 0; i < (size_t)files.gl_pathc; i++) {
        char *fname = files.gl_pathv[i];
        SCLogInfo("Loading rule file: %s", fname);
        r = DetectLoadSigFile(de_ctx, fname, good_sigs, bad_sigs);
        if (r < 0) {
            ++(st->bad_files);
        }

        ++(st->total_files);

        if (*good_sigs == 0) {
            SCLogWarning(SC_ERR_NO_RULES,
                "No rules loaded from %s", fname);
        }

        st->good_sigs_total += *good_sigs;
        st->bad_sigs_total += *bad_sigs;
    }

    globfree(&files);
    return r;
}

/**
 *  \brief Load signatures
 *  \param de_ctx Pointer to the detection engine context
 *  \param sig_file Filename (or pattern) holding signatures
 *  \param sig_file_exclusive File passed in 'sig_file' should be loaded exclusively.
 *  \retval -1 on error
 */
int SigLoadSignatures(DetectEngineCtx *de_ctx, char *sig_file, int sig_file_exclusive)
{
    SCEnter();

    ConfNode *rule_files;
    ConfNode *file = NULL;
    SigFileLoaderStat sig_stat;
    int ret = 0;
    char *sfile = NULL;
    char varname[128] = "rule-files";
    int good_sigs = 0;
    int bad_sigs = 0;

    memset(&sig_stat, 0, sizeof(SigFileLoaderStat));

    if (strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.rule-files",
                de_ctx->config_prefix);
    }

    if (RunmodeGetCurrent() == RUNMODE_ENGINE_ANALYSIS) {
        fp_engine_analysis_set = SetupFPAnalyzer();
        rule_engine_analysis_set = SetupRuleAnalyzer();
    }

    /* ok, let's load signature files from the general config */
    if (!(sig_file != NULL && sig_file_exclusive == TRUE)) {
        rule_files = ConfGetNode(varname);
        if (rule_files != NULL) {
            if (!ConfNodeIsSequence(rule_files)) {
                SCLogWarning(SC_ERR_INVALID_ARGUMENT,
                    "Invalid rule-files configuration section: "
                    "expected a list of filenames.");
            }
            else {
                TAILQ_FOREACH(file, &rule_files->head, next) {
                    sfile = DetectLoadCompleteSigPath(de_ctx, file->val);
                    good_sigs = bad_sigs = 0;
                    ret = ProcessSigFiles(de_ctx, sfile, &sig_stat, &good_sigs, &bad_sigs);
                    SCFree(sfile);

                    if (ret != 0 || good_sigs == 0) {
                        if (de_ctx->failure_fatal == 1) {
                            exit(EXIT_FAILURE);
                        }
                    }
                }
            }
        }
    }

    /* If a Signature file is specified from commandline, parse it too */
    if (sig_file != NULL) {
        ret = ProcessSigFiles(de_ctx, sig_file, &sig_stat, &good_sigs, &bad_sigs);

        if (ret != 0) {
            if (de_ctx->failure_fatal == 1) {
                exit(EXIT_FAILURE);
            }
        }

        if (good_sigs == 0) {
            SCLogError(SC_ERR_NO_RULES, "No rules loaded from %s", sig_file);

            if (de_ctx->failure_fatal == 1) {
                exit(EXIT_FAILURE);
            }
        }
    }

    /* now we should have signatures to work with */
    if (sig_stat.good_sigs_total <= 0) {
        if (sig_stat.total_files > 0) {
           SCLogWarning(SC_ERR_NO_RULES_LOADED, "%d rule files specified, but no rule was loaded at all!", sig_stat.total_files);
        } else {
            SCLogInfo("No signatures supplied.");
            goto end;
        }
    } else {
        /* we report the total of files and rules successfully loaded and failed */
        SCLogInfo("%" PRId32 " rule files processed. %" PRId32 " rules successfully loaded, %" PRId32 " rules failed",
            sig_stat.total_files, sig_stat.good_sigs_total, sig_stat.bad_sigs_total);
    }

    if ((sig_stat.bad_sigs_total || sig_stat.bad_files) && de_ctx->failure_fatal) {
        ret = -1;
        goto end;
    }

    SCSigRegisterSignatureOrderingFuncs(de_ctx);
    SCSigOrderSignatures(de_ctx);
    SCSigSignatureOrderingModuleCleanup(de_ctx);

    /* Setup the signature group lookup structure and pattern matchers */
    if (SigGroupBuild(de_ctx) < 0)
        goto end;

    ret = 0;

 end:
    if (RunmodeGetCurrent() == RUNMODE_ENGINE_ANALYSIS) {
        if (rule_engine_analysis_set) {
            CleanupRuleAnalyzer();
        }
        if (fp_engine_analysis_set) {
            CleanupFPAnalyzer();
        }
    }

    DetectParseDupSigHashFree(de_ctx);
    SCReturnInt(ret);
}

int SigMatchSignaturesRunPostMatch(ThreadVars *tv,
                                   DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p,
                                   Signature *s)
{
    /* run the packet match functions */
    if (s->sm_arrays[DETECT_SM_LIST_POSTMATCH] != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);

        SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];
        SCLogDebug("running match functions, sm %p", smd);

        if (smd != NULL) {
            while (1) {
                KEYWORD_PROFILING_START;
                (void)sigmatch_table[smd->type].Match(tv, det_ctx, p, s, smd->ctx);
                KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                if (smd->is_last)
                    break;
                smd++;
            }
        }
    }

    DetectReplaceExecute(p, det_ctx);

    if (s->flags & SIG_FLAG_FILESTORE)
        DetectFilestorePostMatch(tv, det_ctx, p, s);

    return 1;
}

/**
 *  \brief Get the SigGroupHead for a packet.
 *
 *  \param de_ctx detection engine context
 *  \param det_ctx thread detection engine content
 *  \param p packet
 *
 *  \retval sgh the SigGroupHead or NULL if non applies to the packet
 */
SigGroupHead *SigMatchSignaturesGetSgh(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    SCEnter();

    int f;
    SigGroupHead *sgh = NULL;

    /* if the packet proto is 0 (not set), we're inspecting it against
     * the decoder events sgh we have. */
    if (p->proto == 0 && p->events.cnt > 0) {
        SCReturnPtr(de_ctx->decoder_event_sgh, "SigGroupHead");
    }

    /* select the flow_gh */
    if (p->flowflags & FLOW_PKT_TOCLIENT)
        f = 0;
    else
        f = 1;

    SCLogDebug("f %d", f);
    SCLogDebug("IP_GET_IPPROTO(p) %u", IP_GET_IPPROTO(p));

    /* find the right mpm instance */
    DetectAddress *ag = DetectAddressLookupInHead(de_ctx->flow_gh[f].src_gh[IP_GET_IPPROTO(p)], &p->src);
    if (ag != NULL) {
        /* source group found, lets try a dst group */
        ag = DetectAddressLookupInHead(ag->dst_gh, &p->dst);
        if (ag != NULL) {
            if (ag->port == NULL) {
                SCLogDebug("we don't have ports");
                sgh = ag->sh;
            } else {
                SCLogDebug("we have ports");

                DetectPort *sport = DetectPortLookupGroup(ag->port,p->sp);
                if (sport != NULL) {
                    DetectPort *dport = DetectPortLookupGroup(sport->dst_ph,p->dp);
                    if (dport != NULL) {
                        sgh = dport->sh;
                    } else {
                        SCLogDebug("no dst port group found for the packet with dp %"PRIu16"", p->dp);
                    }
                } else {
                    SCLogDebug("no src port group found for the packet with sp %"PRIu16"", p->sp);
                }
            }
        } else {
            SCLogDebug("no dst address group found for the packet");
        }
    } else {
        SCLogDebug("no src address group found for the packet");
    }

    SCReturnPtr(sgh, "SigGroupHead");
}

/** \brief Get the smsgs relevant to this packet
 *
 *  \param f LOCKED flow
 *  \param p packet
 *  \param flags stream flags
 */
static StreamMsg *SigMatchSignaturesGetSmsg(Flow *f, Packet *p, uint8_t flags)
{
    SCEnter();

    DEBUG_ASSERT_FLOW_LOCKED(f);

    StreamMsg *smsg = NULL;

    if (p->proto == IPPROTO_TCP && f->protoctx != NULL && (p->flags & PKT_STREAM_EST)) {
        TcpSession *ssn = (TcpSession *)f->protoctx;

        /* at stream eof, or in inline mode, inspect all smsg's */
        if ((flags & STREAM_EOF) || StreamTcpInlineMode()) {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                smsg = ssn->toserver_smsg_head;
                /* deref from the ssn */
                ssn->toserver_smsg_head = NULL;
                ssn->toserver_smsg_tail = NULL;

                SCLogDebug("to_server smsg %p at stream eof", smsg);
            } else {
                smsg = ssn->toclient_smsg_head;
                /* deref from the ssn */
                ssn->toclient_smsg_head = NULL;
                ssn->toclient_smsg_tail = NULL;

                SCLogDebug("to_client smsg %p at stream eof", smsg);
            }
        } else {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                StreamMsg *head = ssn->toserver_smsg_head;
                if (unlikely(head == NULL)) {
                    SCLogDebug("no smsgs in to_server direction");
                    goto end;
                }

                /* if the smsg is bigger than the current packet, we will
                 * process the smsg in a later run */
                if (SEQ_GT((head->seq + head->data_len), (TCP_GET_SEQ(p) + p->payload_len))) {
                    SCLogDebug("smsg ends beyond current packet, skipping for now %"PRIu32">%"PRIu32,
                            (head->seq + head->data_len), (TCP_GET_SEQ(p) + p->payload_len));
                    goto end;
                }

                smsg = head;
                /* deref from the ssn */
                ssn->toserver_smsg_head = NULL;
                ssn->toserver_smsg_tail = NULL;

                SCLogDebug("to_server smsg %p", smsg);
            } else {
                StreamMsg *head = ssn->toclient_smsg_head;
                if (unlikely(head == NULL))
                    goto end;

                /* if the smsg is bigger than the current packet, we will
                 * process the smsg in a later run */
                if (SEQ_GT((head->seq + head->data_len), (TCP_GET_SEQ(p) + p->payload_len))) {
                    SCLogDebug("smsg ends beyond current packet, skipping for now %"PRIu32">%"PRIu32,
                            (head->seq + head->data_len), (TCP_GET_SEQ(p) + p->payload_len));
                    goto end;
                }

                smsg = head;
                /* deref from the ssn */
                ssn->toclient_smsg_head = NULL;
                ssn->toclient_smsg_tail = NULL;

                SCLogDebug("to_client smsg %p", smsg);
            }
        }
    }

end:
    SCReturnPtr(smsg, "StreamMsg");
}

static inline void DetectPrefilterMergeSort(DetectEngineCtx *de_ctx,
                                            DetectEngineThreadCtx *det_ctx)
//                                            SigGroupHead *sgh)
{
    SigIntId mpm, nonmpm;
    det_ctx->match_array_cnt = 0;
    SigIntId *mpm_ptr = det_ctx->pmq.rule_id_array;
    SigIntId *nonmpm_ptr = det_ctx->non_mpm_id_array;
    //SigIntId *nonmpm_ptr = sgh->non_mpm_id_array;
    uint32_t m_cnt = det_ctx->pmq.rule_id_array_cnt;
    //uint32_t n_cnt = sgh->non_mpm_id_cnt;
    uint32_t n_cnt = det_ctx->non_mpm_id_cnt;
    SCLogDebug("PMQ rule id array count %d", det_ctx->pmq.rule_id_array_cnt);
//    SCLogDebug("SGH non-MPM id count %d", sgh->non_mpm_id_cnt);
    SigIntId *final_ptr;
    uint32_t final_cnt;
    SigIntId id;
    SigIntId previous_id = (SigIntId)-1;
    Signature **sig_array = de_ctx->sig_array;
    Signature **match_array = det_ctx->match_array;
    Signature *s;

    /* Load first values. */
    if (likely(m_cnt)) {
        mpm = *mpm_ptr;
    } else {
        /* mpm list is empty */
        final_ptr = nonmpm_ptr;
        final_cnt = n_cnt;
        goto final;
    }
    if (likely(n_cnt)) {
        nonmpm = *nonmpm_ptr;
    } else {
        /* non-mpm list is empty. */
        final_ptr = mpm_ptr;
        final_cnt = m_cnt;
        goto final;
    }
    while (1) {
        if (mpm <= nonmpm) {
            /* Take from mpm list */
            id = mpm;

            s = sig_array[id];
            /* As the mpm list can contain duplicates, check for that here. */
            if (likely(id != previous_id)) {
                *match_array++ = s;
                previous_id = id;
            }
            if (unlikely(--m_cnt == 0)) {
                /* mpm list is now empty */
                final_ptr = nonmpm_ptr;
                 final_cnt = n_cnt;
                 goto final;
             }
             mpm_ptr++;
             mpm = *mpm_ptr;
         } else {
             id = nonmpm;

             s = sig_array[id];
             /* As the mpm list can contain duplicates, check for that here. */
             if (likely(id != previous_id)) {
                 *match_array++ = s;
                 previous_id = id;
             }
             if (unlikely(--n_cnt == 0)) {
                 final_ptr = mpm_ptr;
                 final_cnt = m_cnt;
                 goto final;
             }
             nonmpm_ptr++;
             nonmpm = *nonmpm_ptr;
        }
    }

 final: /* Only one list remaining. Just walk that list. */

    while (final_cnt-- > 0) {
        id = *final_ptr++;
        s = sig_array[id];

        /* As the mpm list can contain duplicates, check for that here. */
        if (likely(id != previous_id)) {
            *match_array++ = s;
            previous_id = id;
        }
    }

    det_ctx->match_array_cnt = match_array - det_ctx->match_array;

    BUG_ON((det_ctx->pmq.rule_id_array_cnt + det_ctx->non_mpm_id_cnt) < det_ctx->match_array_cnt);
}

/* Return true is the list is sorted smallest to largest */
static void QuickSortSigIntId(SigIntId *sids, uint32_t n)
{
    if (n < 2)
        return;
    SigIntId p = sids[n / 2];
    SigIntId *l = sids;
    SigIntId *r = sids + n - 1;
    while (l <= r) {
        if (*l < p)
            l++;
        else if (*r > p)
            r--;
        else {
            SigIntId t = *l;
            *l = *r;
            *r = t;
            l++;
            r--;
        }
    }
    QuickSortSigIntId(sids, r - sids + 1);
    QuickSortSigIntId(l, sids + n - l);
}

#define SMS_USE_FLOW_SGH        0x01
#define SMS_USED_PM             0x02
#define SMS_USED_STREAM_PM      0x04

/**
 * \internal
 * \brief Run mpm on packet, stream and other buffers based on
 *        alproto, sgh state.
 *
 * \param de_ctx       Pointer to the detection engine context.
 * \param det_ctx      Pointer to the detection engine thread context.
 * \param smsg         The stream segment to inspect for stream mpm.
 * \param p            Packet.
 * \param flags        Flags.
 * \param alproto      Flow alproto.
 * \param has_state    Bool indicating we have (al)state
 * \param sms_runflags Used to store state by detection engine.
 */
static inline void DetectMpmPrefilter(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, StreamMsg *smsg, Packet *p,
        const uint8_t flags, const AppProto alproto,
        const int has_state, uint8_t *sms_runflags)
{
    /* have a look at the reassembled stream (if any) */
    if (p->flowflags & FLOW_PKT_ESTABLISHED) {
        SCLogDebug("p->flowflags & FLOW_PKT_ESTABLISHED");

        /* all http based mpms */
        if (has_state && alproto == ALPROTO_HTTP) {
            FLOWLOCK_WRLOCK(p->flow);
            void *alstate = FlowGetAppState(p->flow);
            if (alstate == NULL) {
                SCLogDebug("no alstate");
                FLOWLOCK_UNLOCK(p->flow);
                return;
            }

            HtpState *htp_state = (HtpState *)alstate;
            if (htp_state->connp == NULL) {
                SCLogDebug("no HTTP connp");
                FLOWLOCK_UNLOCK(p->flow);
                return;
            }

            int tx_progress = 0;
            uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser, flags);
            uint64_t total_txs = AppLayerParserGetTxCnt(IPPROTO_TCP, ALPROTO_HTTP, alstate);
            for (; idx < total_txs; idx++) {
                htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, idx);
                if (tx == NULL)
                    continue;

                if (p->flowflags & FLOW_PKT_TOSERVER) {
                    tx_progress = AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags);

                    if (tx_progress > HTP_REQUEST_LINE) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_URI) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_URI);
                            DetectUricontentInspectMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_URI);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HRUD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HRUD);
                            DetectEngineRunHttpRawUriMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HRUD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HMD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HMD);
                            DetectEngineRunHttpMethodMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HMD);
                        }
                    }

                    if (tx_progress >= HTP_REQUEST_HEADERS) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HHHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HHHD);
                            DetectEngineRunHttpHHMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HHHD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HRHHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HRHHD);
                            DetectEngineRunHttpHRHMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HRHHD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HCD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HCD);
                            DetectEngineRunHttpCookieMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HCD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HUAD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HUAD);
                            DetectEngineRunHttpUAMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HUAD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HHD);
                            DetectEngineRunHttpHeaderMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HHD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HRHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HRHD);
                            DetectEngineRunHttpRawHeaderMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HRHD);
                        }
                    }

                    if (tx_progress >= HTP_REQUEST_BODY) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HCBD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HCBD);
                            DetectEngineRunHttpClientBodyMpm(de_ctx, det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HCBD);
                        }
                    }
                } else { /* implied FLOW_PKT_TOCLIENT */
                    tx_progress = AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_HTTP, tx, flags);

                    if (tx_progress > HTP_RESPONSE_LINE) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HSMD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HSMD);
                            DetectEngineRunHttpStatMsgMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HSMD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HSCD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HSCD);
                            DetectEngineRunHttpStatCodeMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HSCD);
                        }
                    }

                    if (tx_progress >= HTP_RESPONSE_HEADERS) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HHD);
                            DetectEngineRunHttpHeaderMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HHD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HRHD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HRHD);
                            DetectEngineRunHttpRawHeaderMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HRHD);
                        }
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HCD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HCD);
                            DetectEngineRunHttpCookieMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HCD);
                        }
                    }

                    if (tx_progress >= HTP_RESPONSE_BODY) {
                        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_HSBD) {
                            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_HSBD);
                            DetectEngineRunHttpServerBodyMpm(de_ctx, det_ctx, p->flow, alstate, flags, tx, idx);
                            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_HSBD);
                        }
                    }
                }
            } /* for */

            FLOWLOCK_UNLOCK(p->flow);
        }
        /* all dns based mpms */
        else if (alproto == ALPROTO_DNS && has_state) {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_DNSQUERY) {
                    FLOWLOCK_RDLOCK(p->flow);
                    void *alstate = FlowGetAppState(p->flow);
                    if (alstate == NULL) {
                        SCLogDebug("no alstate");
                        FLOWLOCK_UNLOCK(p->flow);
                        return;
                    }

                    uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser, flags);
                    uint64_t total_txs = AppLayerParserGetTxCnt(p->flow->proto, alproto, alstate);
                    for (; idx < total_txs; idx++) {
                        void *tx = AppLayerParserGetTx(p->flow->proto, alproto, alstate, idx);
                        if (tx == NULL)
                            continue;

                        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_DNSQUERY);
                        DetectDnsQueryInspectMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_DNSQUERY);
                    }
                    FLOWLOCK_UNLOCK(p->flow);
                }
            }
        } else if (alproto == ALPROTO_SMTP && has_state) {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_FD_SMTP) {
                    FLOWLOCK_RDLOCK(p->flow);
                    void *alstate = FlowGetAppState(p->flow);
                    if (alstate == NULL) {
                        SCLogDebug("no alstate");
                        FLOWLOCK_UNLOCK(p->flow);
                        return;
                    }

                    SMTPState *smtp_state = (SMTPState *)alstate;
                    uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser, flags);
                    uint64_t total_txs = AppLayerParserGetTxCnt(p->flow->proto, alproto, alstate);
                    for (; idx < total_txs; idx++) {
                        void *tx = AppLayerParserGetTx(p->flow->proto, alproto, alstate, idx);
                        if (tx == NULL)
                            continue;

                        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_FD_SMTP);
                        DetectEngineRunSMTPMpm(de_ctx, det_ctx, p->flow, smtp_state, flags, tx, idx);
                        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_FD_SMTP);
                    }
                    FLOWLOCK_UNLOCK(p->flow);
                }
            }
        }

        if (smsg != NULL && (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_STREAM)) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_STREAM);
            StreamPatternSearch(det_ctx, p, smsg, flags);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_STREAM);

            *sms_runflags |= SMS_USED_STREAM_PM;
        } else {
            SCLogDebug("smsg NULL or no stream mpm for this sgh");
        }
    } else {
        SCLogDebug("NOT p->flowflags & FLOW_PKT_ESTABLISHED");
    }

    if (p->payload_len > 0 && (!(p->flags & PKT_NOPAYLOAD_INSPECTION))) {
        if (!(p->flags & PKT_STREAM_ADD) && (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_STREAM)) {
            *sms_runflags |= SMS_USED_PM;
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_PKT_STREAM);
            PacketPatternSearchWithStreamCtx(det_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_PKT_STREAM);
        }
        if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_PACKET) {
            /* run the multi packet matcher against the payload of the packet */
            SCLogDebug("search: (%p, minlen %" PRIu32 ", sgh->sig_cnt %" PRIu32 ")",
                    det_ctx->sgh, det_ctx->sgh->mpm_content_minlen, det_ctx->sgh->sig_cnt);

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_PACKET);
            PacketPatternSearch(det_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_PACKET);

            *sms_runflags |= SMS_USED_PM;
        }
    }

    /* UDP DNS inspection is independent of est or not */
    if (alproto == ALPROTO_DNS && has_state) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            SCLogDebug("mpm inspection");
            if (det_ctx->sgh->flags & SIG_GROUP_HEAD_MPM_DNSQUERY) {
                FLOWLOCK_RDLOCK(p->flow);
                void *alstate = FlowGetAppState(p->flow);
                if (alstate == NULL) {
                    SCLogDebug("no alstate");
                    FLOWLOCK_UNLOCK(p->flow);
                    return;
                }

                uint64_t idx = AppLayerParserGetTransactionInspectId(p->flow->alparser, flags);
                uint64_t total_txs = AppLayerParserGetTxCnt(p->flow->proto, alproto, alstate);
                for (; idx < total_txs; idx++) {
                    void *tx = AppLayerParserGetTx(p->flow->proto, alproto, alstate, idx);
                    if (tx == NULL)
                        continue;
                    SCLogDebug("tx %p",tx);
                    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM_DNSQUERY);
                    DetectDnsQueryInspectMpm(det_ctx, p->flow, alstate, flags, tx, idx);
                    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM_DNSQUERY);
                }
                FLOWLOCK_UNLOCK(p->flow);
            }
        }
    }

    /* Sort the rule list to lets look at pmq.
     * NOTE due to merging of 'stream' pmqs we *MAY* have duplicate entries */
    if (det_ctx->pmq.rule_id_array_cnt > 1) {
        QuickSortSigIntId(det_ctx->pmq.rule_id_array, det_ctx->pmq.rule_id_array_cnt);
    }
}

#ifdef DEBUG
static void DebugInspectIds(Packet *p, Flow *f, StreamMsg *smsg)
{
    SCLogDebug("pcap_cnt %02"PRIu64", %s, %12s, smsg %s",
               p->pcap_cnt, p->flowflags & FLOW_PKT_TOSERVER ? "toserver" : "toclient",
               p->flags & PKT_STREAM_EST ? "established" : "stateless",
               smsg ? "yes" : "no");
    AppLayerParserStatePrintDetails(f->alparser);
}
#endif

static void AlertDebugLogModeSyncFlowbitsNamesToPacketStruct(Packet *p, DetectEngineCtx *de_ctx)
{
#define MALLOC_JUMP 5

    int i = 0;

    GenericVar *gv = p->flow->flowvar;

    while (gv != NULL) {
        i++;
        gv = gv->next;
    }
    if (i == 0)
        return;

    p->debuglog_flowbits_names_len = i;

    p->debuglog_flowbits_names = SCMalloc(sizeof(char *) *
                                          p->debuglog_flowbits_names_len);
    if (p->debuglog_flowbits_names == NULL) {
        return;
    }
    memset(p->debuglog_flowbits_names, 0,
           sizeof(char *) * p->debuglog_flowbits_names_len);

    i = 0;
    gv = p->flow->flowvar;
    while (gv != NULL) {
        if (gv->type != DETECT_FLOWBITS) {
            gv = gv->next;
            continue;
        }

        FlowBit *fb = (FlowBit *) gv;
        char *name = VariableIdxGetName(de_ctx, fb->idx, VAR_TYPE_FLOW_BIT);
        if (name != NULL) {
            p->debuglog_flowbits_names[i] = SCStrdup(name);
            if (p->debuglog_flowbits_names[i] == NULL) {
                return;
            }
            i++;
        }

        if (i == p->debuglog_flowbits_names_len) {
            p->debuglog_flowbits_names_len += MALLOC_JUMP;
            const char **names = SCRealloc(p->debuglog_flowbits_names,
                                                   sizeof(char *) *
                                                   p->debuglog_flowbits_names_len);
            if (names == NULL) {
                SCFree(p->debuglog_flowbits_names);
                p->debuglog_flowbits_names = NULL;
                p->debuglog_flowbits_names_len = 0;
                return;
            }
            p->debuglog_flowbits_names = names;
            memset(p->debuglog_flowbits_names +
                   p->debuglog_flowbits_names_len - MALLOC_JUMP,
                   0, sizeof(char *) * MALLOC_JUMP);
        }

        gv = gv->next;
    }

    return;
}

static inline void DetectPrefilterBuildNonMpmList(DetectEngineThreadCtx *det_ctx, SignatureMask mask)
{
    uint32_t x = 0;
    for (x = 0; x < det_ctx->sgh->non_mpm_store_cnt; x++) {
        /* only if the mask matches this rule can possibly match,
         * so build the non_mpm array only for match candidates */
        SignatureMask rule_mask = det_ctx->sgh->non_mpm_store_array[x].mask;
        if ((rule_mask & mask) == rule_mask) {
            det_ctx->non_mpm_id_array[det_ctx->non_mpm_id_cnt++] = det_ctx->sgh->non_mpm_store_array[x].id;
        }
    }
}

/**
 *  \brief Signature match function
 *
 *  \retval 1 one or more signatures matched
 *  \retval 0 no matches were found
 */
int SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    uint8_t sms_runflags = 0;   /* function flags */
    uint8_t alert_flags = 0;
    AppProto alproto = ALPROTO_UNKNOWN;
#ifdef PROFILING
    int smatch = 0; /* signature match: 1, no match: 0 */
#endif
    uint8_t flow_flags = 0; /* flow/state flags */
    StreamMsg *smsg = NULL;
    Signature *s = NULL;
    Signature *next_s = NULL;
    uint8_t alversion = 0;
    int state_alert = 0;
    int alerts = 0;
    int app_decoder_events = 0;
    int has_state = 0;          /* do we have an alstate to work with? */

    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);

    p->alerts.cnt = 0;
    det_ctx->filestore_cnt = 0;

    det_ctx->base64_decoded_len = 0;

    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if (p->flags & PKT_NOPACKET_INSPECTION) {
        SCReturnInt(0);
    }

    /* Load the Packet's flow early, even though it might not be needed.
     * Mark as a constant pointer, although the flow can change.
     */
    Flow * const pflow = p->flow;

    /* grab the protocol state we will detect on */
    if (p->flags & PKT_HAS_FLOW) {
        if (p->flowflags & FLOW_PKT_TOSERVER) {
            flow_flags = STREAM_TOSERVER;
            SCLogDebug("flag STREAM_TOSERVER set");
        } else if (p->flowflags & FLOW_PKT_TOCLIENT) {
            flow_flags = STREAM_TOCLIENT;
            SCLogDebug("flag STREAM_TOCLIENT set");
        }
        SCLogDebug("p->flowflags 0x%02x", p->flowflags);

        if (p->flags & PKT_STREAM_EOF) {
            flow_flags |= STREAM_EOF;
            SCLogDebug("STREAM_EOF set");
        }

        FLOWLOCK_WRLOCK(pflow);
        {
            /* store tenant_id in the flow so that we can use it
             * for creating pseudo packets */
            if (p->tenant_id > 0 && pflow->tenant_id == 0) {
                pflow->tenant_id = p->tenant_id;
            }

            /* live ruleswap check for flow updates */
            if (pflow->de_ctx_id == 0) {
                /* first time this flow is inspected, set id */
                pflow->de_ctx_id = de_ctx->id;
            } else if (pflow->de_ctx_id != de_ctx->id) {
                /* first time we inspect flow with this de_ctx, reset */
                pflow->flags &= ~FLOW_SGH_TOSERVER;
                pflow->flags &= ~FLOW_SGH_TOCLIENT;
                pflow->sgh_toserver = NULL;
                pflow->sgh_toclient = NULL;

                pflow->de_ctx_id = de_ctx->id;
                GenericVarFree(pflow->flowvar);
                pflow->flowvar = NULL;

                DetectEngineStateReset(pflow->de_state,
                        (STREAM_TOSERVER|STREAM_TOCLIENT));
                DetectEngineStateResetTxs(pflow);
            }

            /* set the iponly stuff */
            if (pflow->flags & FLOW_TOCLIENT_IPONLY_SET)
                p->flowflags |= FLOW_PKT_TOCLIENT_IPONLY_SET;
            if (pflow->flags & FLOW_TOSERVER_IPONLY_SET)
                p->flowflags |= FLOW_PKT_TOSERVER_IPONLY_SET;

            /* Get the stored sgh from the flow (if any). Make sure we're not using
             * the sgh for icmp error packets part of the same stream. */
            if (IP_GET_IPPROTO(p) == pflow->proto) { /* filter out icmp */
                PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
                if ((p->flowflags & FLOW_PKT_TOSERVER) && (pflow->flags & FLOW_SGH_TOSERVER)) {
                    det_ctx->sgh = pflow->sgh_toserver;
                    sms_runflags |= SMS_USE_FLOW_SGH;
                } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && (pflow->flags & FLOW_SGH_TOCLIENT)) {
                    det_ctx->sgh = pflow->sgh_toclient;
                    sms_runflags |= SMS_USE_FLOW_SGH;
                }
                PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);

                smsg = SigMatchSignaturesGetSmsg(pflow, p, flow_flags);
#if 0
                StreamMsg *tmpsmsg = smsg;
                while (tmpsmsg) {
                    printf("detect ---start---:\n");
                    PrintRawDataFp(stdout,tmpsmsg->data.data,tmpsmsg->data.data_len);
                    printf("detect ---end---:\n");
                    tmpsmsg = tmpsmsg->next;
                }
#endif
            }

            /* Retrieve the app layer state and protocol and the tcp reassembled
             * stream chunks. */
            if ((p->proto == IPPROTO_TCP && (p->flags & PKT_STREAM_EST)) ||
                (p->proto == IPPROTO_UDP) ||
                (p->proto == IPPROTO_SCTP && (p->flowflags & FLOW_PKT_ESTABLISHED)))
            {
                /* update flow flags with knowledge on disruptions */
                flow_flags = FlowGetDisruptionFlags(pflow, flow_flags);
                has_state = (FlowGetAppState(pflow) != NULL);
                alproto = FlowGetAppProtocol(pflow);
                alversion = AppLayerParserGetStateVersion(pflow->alparser);
                SCLogDebug("alstate %s, alproto %u", has_state ? "true" : "false", alproto);
            } else {
                SCLogDebug("packet doesn't have established flag set (proto %d)", p->proto);
            }

            app_decoder_events = AppLayerParserHasDecoderEvents(pflow->proto,
                                                                pflow->alproto,
                                                                pflow->alstate,
                                                                pflow->alparser,
                                                                flow_flags);
        }
        FLOWLOCK_UNLOCK(pflow);

        if (((p->flowflags & FLOW_PKT_TOSERVER) && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
            ((p->flowflags & FLOW_PKT_TOCLIENT) && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET)))
        {
            SCLogDebug("testing against \"ip-only\" signatures");

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
            IPOnlyMatchPacket(th_v, de_ctx, det_ctx, &de_ctx->io_ctx, &det_ctx->io_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

            /* save in the flow that we scanned this direction... locking is
             * done in the FlowSetIPOnlyFlag function. */
            FlowSetIPOnlyFlag(pflow, p->flowflags & FLOW_PKT_TOSERVER ? 1 : 0);

        } else if (((p->flowflags & FLOW_PKT_TOSERVER) &&
                   (pflow->flags & FLOW_TOSERVER_IPONLY_SET)) ||
                   ((p->flowflags & FLOW_PKT_TOCLIENT) &&
                   (pflow->flags & FLOW_TOCLIENT_IPONLY_SET)))
        {
            /* If we have a drop from IP only module,
             * we will drop the rest of the flow packets
             * This will apply only to inline/IPS */
            if (pflow->flags & FLOW_ACTION_DROP)
            {
                alert_flags = PACKET_ALERT_FLAG_DROP_FLOW;
                PACKET_DROP(p);
            }
        }

        if (!(sms_runflags & SMS_USE_FLOW_SGH)) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
        }

#ifdef DEBUG
        if (pflow) {
            SCMutexLock(&pflow->m);
            DebugInspectIds(p, pflow, smsg);
            SCMutexUnlock(&pflow->m);
        }
#endif
    } else { /* p->flags & PKT_HAS_FLOW */
        /* no flow */

        /* Even without flow we should match the packet src/dst */
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
        IPOnlyMatchPacket(th_v, de_ctx, det_ctx, &de_ctx->io_ctx,
                          &det_ctx->io_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
        det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
    }

    /* if we didn't get a sig group head, we
     * have nothing to do.... */
    if (det_ctx->sgh == NULL) {
        SCLogDebug("no sgh for this packet, nothing to match against");
        goto end;
    }

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL);
    /* stateful app layer detection */
    if ((p->flags & PKT_HAS_FLOW) && has_state) {
        memset(det_ctx->de_state_sig_array, 0x00, det_ctx->de_state_sig_array_len);
        int has_inspectable_state = DeStateFlowHasInspectableState(pflow, alproto, alversion, flow_flags);
        if (has_inspectable_state == 1) {
            /* initialize to 0(DE_STATE_MATCH_HAS_NEW_STATE) */
            DeStateDetectContinueDetection(th_v, de_ctx, det_ctx, p, pflow,
                                           flow_flags, alproto, alversion);
        } else if (has_inspectable_state == 2) {
            /* no inspectable state, so pretend we don't have a state at all */
            has_state = 0;
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL);

    /* create our prefilter mask */
    SignatureMask mask = 0;
    PacketCreateMask(p, &mask, alproto, has_state, smsg, app_decoder_events);

    /* build and prefilter non_mpm list against the mask of the packet */
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_NONMPMLIST);
    det_ctx->non_mpm_id_cnt = 0;
    if (likely(det_ctx->sgh->non_mpm_store_cnt > 0)) {
        DetectPrefilterBuildNonMpmList(det_ctx, mask);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_NONMPMLIST);

    /* run the mpm for each type */
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_MPM);
    DetectMpmPrefilter(de_ctx, det_ctx, smsg, p, flow_flags, alproto, has_state, &sms_runflags);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_MPM);
#ifdef PROFILING
    if (th_v) {
        StatsAddUI64(th_v, det_ctx->counter_mpm_list,
                             (uint64_t)det_ctx->pmq.rule_id_array_cnt);
        StatsAddUI64(th_v, det_ctx->counter_nonmpm_list,
                             (uint64_t)det_ctx->sgh->non_mpm_store_cnt);
        /* non mpm sigs after mask prefilter */
        StatsAddUI64(th_v, det_ctx->counter_fnonmpm_list,
                             (uint64_t)det_ctx->non_mpm_id_cnt);
    }
#endif

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PREFILTER);
    DetectPrefilterMergeSort(de_ctx, det_ctx);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PREFILTER);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_RULES);
    /* inspect the sigs against the packet */
    /* Prefetch the next signature. */
    SigIntId match_cnt = det_ctx->match_array_cnt;
#ifdef PROFILING
    if (th_v) {
        StatsAddUI64(th_v, det_ctx->counter_match_list,
                             (uint64_t)match_cnt);
    }
#endif
    Signature **match_array = det_ctx->match_array;

    uint32_t sflags, next_sflags = 0;
    if (match_cnt) {
        next_s = *match_array++;
        next_sflags = next_s->flags;
    }

    while (match_cnt--) {
        RULE_PROFILING_START(p);
        state_alert = 0;
#ifdef PROFILING
        smatch = 0;
#endif

        s = next_s;
        sflags = next_sflags;
        if (match_cnt) {
            next_s = *match_array++;
            next_sflags = next_s->flags;
        }
        uint8_t s_proto_flags = s->proto.flags;

        SCLogDebug("inspecting signature id %"PRIu32"", s->id);

        /* if the sig has alproto and the session as well they should match */
        if (likely(sflags & SIG_FLAG_APPLAYER)) {
            if (s->alproto != ALPROTO_UNKNOWN && s->alproto != alproto) {
                if (s->alproto == ALPROTO_DCERPC) {
                    if (alproto != ALPROTO_SMB && alproto != ALPROTO_SMB2) {
                        SCLogDebug("DCERPC sig, alproto not SMB or SMB2");
                        goto next;
                    }
                } else {
                    SCLogDebug("alproto mismatch");
                    goto next;
                }
            }
        }

        if (unlikely(sflags & SIG_FLAG_DSIZE)) {
            if (likely(p->payload_len < s->dsize_low || p->payload_len > s->dsize_high)) {
                SCLogDebug("kicked out as p->payload_len %u, dsize low %u, hi %u",
                           p->payload_len, s->dsize_low, s->dsize_high);
                goto next;
            }
        }

        /* check for a pattern match of the one pattern in this sig. */
        if (likely(sflags & (SIG_FLAG_MPM_PACKET|SIG_FLAG_MPM_STREAM|SIG_FLAG_MPM_APPLAYER))) {
            /* filter out sigs that want pattern matches, but
             * have no matches */
            if (!(det_ctx->pmq.pattern_id_bitarray[(s->mpm_pattern_id_div_8)] & s->mpm_pattern_id_mod_8)) {
                if (sflags & SIG_FLAG_MPM_PACKET) {
                    if (!(sflags & SIG_FLAG_MPM_PACKET_NEG)) {
                        goto next;
                    }
                } else if (sflags & SIG_FLAG_MPM_STREAM) {
                    /* filter out sigs that want pattern matches, but
                     * have no matches */
                    if (!(sflags & SIG_FLAG_MPM_STREAM_NEG)) {
                        goto next;
                    }
                } else if (sflags & SIG_FLAG_MPM_APPLAYER) {
                    if (!(sflags & SIG_FLAG_MPM_APPLAYER_NEG)) {
                        goto next;
                    }
                }
            }
        }
        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (det_ctx->de_state_sig_array[s->num] & DE_STATE_MATCH_NO_NEW_STATE)
                goto next;
        }

        /* check if this signature has a requirement for flowvars of some type
         * and if so, if we actually have any in the flow. If not, the sig
         * can't match and we skip it. */
        if ((p->flags & PKT_HAS_FLOW) && (sflags & SIG_FLAG_REQUIRE_FLOWVAR)) {
            FLOWLOCK_RDLOCK(pflow);
            int m  = pflow->flowvar ? 1 : 0;
            FLOWLOCK_UNLOCK(pflow);

            /* no flowvars? skip this sig */
            if (m == 0) {
                SCLogDebug("skipping sig as the flow has no flowvars and sig "
                           "has SIG_FLAG_REQUIRE_FLOWVAR flag set.");
                goto next;
            }
        }

        if ((s_proto_flags & DETECT_PROTO_IPV4) && !PKT_IS_IPV4(p)) {
            SCLogDebug("ip version didn't match");
            goto next;
        }
        if ((s_proto_flags & DETECT_PROTO_IPV6) && !PKT_IS_IPV6(p)) {
            SCLogDebug("ip version didn't match");
            goto next;
        }

        if (DetectProtoContainsProto(&s->proto, IP_GET_IPPROTO(p)) == 0) {
            SCLogDebug("proto didn't match");
            goto next;
        }

        /* check the source & dst port in the sig */
        if (p->proto == IPPROTO_TCP || p->proto == IPPROTO_UDP || p->proto == IPPROTO_SCTP) {
            if (!(sflags & SIG_FLAG_DP_ANY)) {
                if (p->flags & PKT_IS_FRAGMENT)
                    goto next;
                DetectPort *dport = DetectPortLookupGroup(s->dp,p->dp);
                if (dport == NULL) {
                    SCLogDebug("dport didn't match.");
                    goto next;
                }
            }
            if (!(sflags & SIG_FLAG_SP_ANY)) {
                if (p->flags & PKT_IS_FRAGMENT)
                    goto next;
                DetectPort *sport = DetectPortLookupGroup(s->sp,p->sp);
                if (sport == NULL) {
                    SCLogDebug("sport didn't match.");
                    goto next;
                }
            }
        } else if ((sflags & (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) != (SIG_FLAG_DP_ANY|SIG_FLAG_SP_ANY)) {
            SCLogDebug("port-less protocol and sig needs ports");
            goto next;
        }

        /* check the destination address */
        if (!(sflags & SIG_FLAG_DST_ANY)) {
            if (PKT_IS_IPV4(p)) {
                if (DetectAddressMatchIPv4(s->addr_dst_match4, s->addr_dst_match4_cnt, &p->dst) == 0)
                    goto next;
            } else if (PKT_IS_IPV6(p)) {
                if (DetectAddressMatchIPv6(s->addr_dst_match6, s->addr_dst_match6_cnt, &p->dst) == 0)
                    goto next;
            }
        }
        /* check the source address */
        if (!(sflags & SIG_FLAG_SRC_ANY)) {
            if (PKT_IS_IPV4(p)) {
                if (DetectAddressMatchIPv4(s->addr_src_match4, s->addr_src_match4_cnt, &p->src) == 0)
                    goto next;
            } else if (PKT_IS_IPV6(p)) {
                if (DetectAddressMatchIPv6(s->addr_src_match6, s->addr_src_match6_cnt, &p->src) == 0)
                    goto next;
            }
        }

        /* Check the payload keywords. If we are a MPM sig and we've made
         * to here, we've had at least one of the patterns match */
        if (s->sm_arrays[DETECT_SM_LIST_PMATCH] != NULL) {
            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_PMATCH);
            /* if we have stream msgs, inspect against those first,
             * but not for a "dsize" signature */
            if (sflags & SIG_FLAG_REQUIRE_STREAM) {
                char pmatch = 0;
                if (smsg != NULL) {
                    uint8_t pmq_idx = 0;
                    StreamMsg *smsg_inspect = smsg;
                    for ( ; smsg_inspect != NULL; smsg_inspect = smsg_inspect->next, pmq_idx++) {
                        /* filter out sigs that want pattern matches, but
                         * have no matches */
                        if ((sflags & SIG_FLAG_MPM_STREAM) && !(sflags & SIG_FLAG_MPM_STREAM_NEG) &&
                            !(det_ctx->smsg_pmq[pmq_idx].pattern_id_bitarray[(s->mpm_pattern_id_div_8)] & s->mpm_pattern_id_mod_8)) {
                            SCLogDebug("no match in this smsg");
                            continue;
                        }

                        if (DetectEngineInspectStreamPayload(de_ctx, det_ctx, s, pflow, smsg_inspect->data, smsg_inspect->data_len) == 1) {
                            SCLogDebug("match in smsg %p", smsg);
                            pmatch = 1;
                            det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH;
                            /* Tell the engine that this reassembled stream can drop the
                             * rest of the pkts with no further inspection */
                            if (s->action & ACTION_DROP)
                              alert_flags |= PACKET_ALERT_FLAG_DROP_FLOW;

                            alert_flags |= PACKET_ALERT_FLAG_STREAM_MATCH;
                            break;
                        }
                    }

                } /* if (smsg != NULL) */

                /* no match? then inspect packet payload */
                if (pmatch == 0) {
                    SCLogDebug("no match in smsg, fall back to packet payload");

                    if (!(sflags & SIG_FLAG_REQUIRE_PACKET)) {
                        if (p->flags & PKT_STREAM_ADD)
                            goto next;
                    }

                    if (sms_runflags & SMS_USED_PM) {
                        if ((sflags & SIG_FLAG_MPM_PACKET) && !(sflags & SIG_FLAG_MPM_PACKET_NEG) &&
                            !(det_ctx->pmq.pattern_id_bitarray[(s->mpm_pattern_id_div_8)] &
                              s->mpm_pattern_id_mod_8)) {
                            goto next;
                        }
                        if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                            goto next;
                        }
                    } else {
                        if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                            goto next;
                        }
                    }
                }
            } else {
                if (sms_runflags & SMS_USED_PM) {
                    if ((sflags & SIG_FLAG_MPM_PACKET) && !(sflags & SIG_FLAG_MPM_PACKET_NEG) &&
                        !(det_ctx->pmq.pattern_id_bitarray[(s->mpm_pattern_id_div_8)] &
                          s->mpm_pattern_id_mod_8)) {
                        goto next;
                    }
                    if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                        goto next;
                    }
                } else {
                    if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1)
                        goto next;
                }
            }
        }

        /* run the packet match functions */
        if (s->sm_arrays[DETECT_SM_LIST_MATCH] != NULL) {
            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_MATCH);
            SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_MATCH];

            SCLogDebug("running match functions, sm %p", smd);
            if (smd != NULL) {
                while (1) {
                    KEYWORD_PROFILING_START;
                    if (sigmatch_table[smd->type].Match(th_v, det_ctx, p, s, smd->ctx) <= 0) {
                        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
                        goto next;
                    }
                    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                    if (smd->is_last)
                        break;
                    smd++;
                }
            }
        }

        SCLogDebug("s->sm_lists[DETECT_SM_LIST_AMATCH] %p, "
                   "s->sm_lists[DETECT_SM_LIST_UMATCH] %p, "
                   "s->sm_lists[DETECT_SM_LIST_DMATCH] %p, "
                   "s->sm_lists[DETECT_SM_LIST_HCDMATCH] %p",
                   s->sm_lists[DETECT_SM_LIST_AMATCH],
                   s->sm_lists[DETECT_SM_LIST_UMATCH],
                   s->sm_lists[DETECT_SM_LIST_DMATCH],
                   s->sm_lists[DETECT_SM_LIST_HCDMATCH]);

        /* consider stateful sig matches */
        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (has_state == 0) {
                SCLogDebug("state matches but no state, we can't match");
                goto next;
            }

            SCLogDebug("stateful app layer match inspection starting");

            /* if DeStateDetectStartDetection matches, it's a full
             * signature match. It will then call PacketAlertAppend
             * itself, so we can skip it below. This is done so it
             * can store the tx_id with the alert */
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL);
            state_alert = DeStateDetectStartDetection(th_v, de_ctx, det_ctx, s,
                                                      p, pflow, flow_flags, alproto, alversion);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL);
            if (state_alert == 0)
                goto next;

            /* match */
            if (s->action & ACTION_DROP)
                alert_flags |= PACKET_ALERT_FLAG_DROP_FLOW;

            alert_flags |= PACKET_ALERT_FLAG_STATE_MATCH;
        }

#ifdef PROFILING
        smatch = 1;
#endif

        SigMatchSignaturesRunPostMatch(th_v, de_ctx, det_ctx, p, s);

        if (!(sflags & SIG_FLAG_NOALERT)) {
            /* stateful sigs call PacketAlertAppend from DeStateDetectStartDetection */
            if (!state_alert)
                PacketAlertAppend(det_ctx, s, p, 0, alert_flags);
        } else {
            /* apply actions even if not alerting */
            DetectSignatureApplyActions(p, s);
        }
        alerts++;
next:
        DetectFlowvarProcessList(det_ctx, pflow);
        DetectReplaceFree(det_ctx);
        RULE_PROFILING_END(det_ctx, s, smatch, p);

        det_ctx->flags = 0;
        continue;
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_RULES);

end:
#ifdef __SC_CUDA_SUPPORT__
    CudaReleasePacket(p);
#endif

    /* see if we need to increment the inspect_id and reset the de_state */
    if (has_state && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL);
        DeStateUpdateInspectTransactionId(pflow, flow_flags);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL);
    }

    /* so now let's iterate the alerts and remove the ones after a pass rule
     * matched (if any). This is done inside PacketAlertFinalize() */
    /* PR: installed "tag" keywords are handled after the threshold inspection */

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_ALERT);
    PacketAlertFinalize(de_ctx, det_ctx, p);
    if (p->alerts.cnt > 0) {
        StatsAddUI64(th_v, det_ctx->counter_alerts, (uint64_t)p->alerts.cnt);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_ALERT);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_CLEANUP);
    /* cleanup pkt specific part of the patternmatcher */
    PacketPatternCleanup(th_v, det_ctx);

    DetectEngineCleanHCBDBuffers(det_ctx);
    DetectEngineCleanHSBDBuffers(det_ctx);
    DetectEngineCleanHHDBuffers(det_ctx);

    /* store the found sgh (or NULL) in the flow to save us from looking it
     * up again for the next packet. Also return any stream chunk we processed
     * to the pool. */
    if (p->flags & PKT_HAS_FLOW) {
        if (sms_runflags & SMS_USED_STREAM_PM) {
            StreamPatternCleanup(th_v, det_ctx, smsg);
        }

        FLOWLOCK_WRLOCK(pflow);
        if (debuglog_enabled) {
            if (p->alerts.cnt > 0) {
                AlertDebugLogModeSyncFlowbitsNamesToPacketStruct(p, de_ctx);
            }
        }

        if (!(sms_runflags & SMS_USE_FLOW_SGH)) {
            if ((p->flowflags & FLOW_PKT_TOSERVER) && !(pflow->flags & FLOW_SGH_TOSERVER)) {
                /* first time we see this toserver sgh, store it */
                pflow->sgh_toserver = det_ctx->sgh;
                pflow->flags |= FLOW_SGH_TOSERVER;

                /* see if this sgh requires us to consider file storing */
                if (pflow->sgh_toserver == NULL || pflow->sgh_toserver->filestore_cnt == 0) {
                    FileDisableStoring(pflow, STREAM_TOSERVER);
                }

                /* see if this sgh requires us to consider file magic */
                if (!FileForceMagic() && (pflow->sgh_toserver == NULL ||
                            !(pflow->sgh_toserver->flags & SIG_GROUP_HEAD_HAVEFILEMAGIC)))
                {
                    SCLogDebug("disabling magic for flow");
                    FileDisableMagic(pflow, STREAM_TOSERVER);
                }

                /* see if this sgh requires us to consider file md5 */
                if (!FileForceMd5() && (pflow->sgh_toserver == NULL ||
                            !(pflow->sgh_toserver->flags & SIG_GROUP_HEAD_HAVEFILEMD5)))
                {
                    SCLogDebug("disabling md5 for flow");
                    FileDisableMd5(pflow, STREAM_TOSERVER);
                }

                /* see if this sgh requires us to consider filesize */
                if (pflow->sgh_toserver == NULL ||
                            !(pflow->sgh_toserver->flags & SIG_GROUP_HEAD_HAVEFILESIZE))
                {
                    SCLogDebug("disabling filesize for flow");
                    FileDisableFilesize(pflow, STREAM_TOSERVER);
                }
            } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && !(pflow->flags & FLOW_SGH_TOCLIENT)) {
                pflow->sgh_toclient = det_ctx->sgh;
                pflow->flags |= FLOW_SGH_TOCLIENT;

                if (pflow->sgh_toclient == NULL || pflow->sgh_toclient->filestore_cnt == 0) {
                    FileDisableStoring(pflow, STREAM_TOCLIENT);
                }

                /* check if this flow needs magic, if not disable it */
                if (!FileForceMagic() && (pflow->sgh_toclient == NULL ||
                            !(pflow->sgh_toclient->flags & SIG_GROUP_HEAD_HAVEFILEMAGIC)))
                {
                    SCLogDebug("disabling magic for flow");
                    FileDisableMagic(pflow, STREAM_TOCLIENT);
                }

                /* check if this flow needs md5, if not disable it */
                if (!FileForceMd5() && (pflow->sgh_toclient == NULL ||
                            !(pflow->sgh_toclient->flags & SIG_GROUP_HEAD_HAVEFILEMD5)))
                {
                    SCLogDebug("disabling md5 for flow");
                    FileDisableMd5(pflow, STREAM_TOCLIENT);
                }

                /* see if this sgh requires us to consider filesize */
                if (pflow->sgh_toclient == NULL ||
                            !(pflow->sgh_toclient->flags & SIG_GROUP_HEAD_HAVEFILESIZE))
                {
                    SCLogDebug("disabling filesize for flow");
                    FileDisableFilesize(pflow, STREAM_TOCLIENT);
                }
            }
        }

        /* if we had no alerts that involved the smsgs,
         * we can get rid of them now. */
        StreamMsgReturnListToPool(smsg);

        FLOWLOCK_UNLOCK(pflow);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_CLEANUP);

    SCReturnInt((int)(alerts > 0));
}

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable */
void DetectSignatureApplyActions(Packet *p, const Signature *s)
{
    PACKET_UPDATE_ACTION(p, s->action);

    if (s->action & ACTION_DROP) {
        if (p->alerts.drop.action == 0) {
            p->alerts.drop.num = s->num;
            p->alerts.drop.action = s->action;
            p->alerts.drop.s = (Signature *)s;
        }
    }
}

/* tm module api functions */

static DetectEngineThreadCtx *GetTenantById(HashTable *h, uint32_t id)
{
    /* technically we need to pass a DetectEngineThreadCtx struct with the
     * tentant_id member. But as that member is the first in the struct, we
     * can use the id directly. */
    return HashTableLookup(h, &id, 0);
}

/** \brief Detection engine thread wrapper.
 *  \param tv thread vars
 *  \param p packet to inspect
 *  \param data thread specific data
 *  \param pq packet queue
 *  \retval TM_ECODE_FAILED error
 *  \retval TM_ECODE_OK ok
 */
TmEcode Detect(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    DEBUG_VALIDATE_PACKET(p);

    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) ||
        (PACKET_TEST_ACTION(p, ACTION_DROP)))
    {
        /* hack: if we are in pass the entire flow mode, we need to still
         * update the inspect_id forward. So test for the condition here,
         * and call the update code if necessary. */
        if (p->flow) {
            uint8_t flags = 0;
            FLOWLOCK_RDLOCK(p->flow);
            int pass = ((p->flow->flags & FLOW_NOPACKET_INSPECTION));
            flags = FlowGetDisruptionFlags(p->flow, flags);
            AppProto alproto = FlowGetAppProtocol(p->flow);
            FLOWLOCK_UNLOCK(p->flow);
            if (pass && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
                if (p->flowflags & FLOW_PKT_TOSERVER) {
                    flags |= STREAM_TOSERVER;
                } else {
                    flags |= STREAM_TOCLIENT;
                }
                DeStateUpdateInspectTransactionId(p->flow, flags);
            }
        }
        return 0;
    }

    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    if (det_ctx == NULL) {
        printf("ERROR: Detect has no thread ctx\n");
        goto error;
    }

    if (SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0) {
        (void)SC_ATOMIC_SET(det_ctx->so_far_used_by_detect, 1);
        SCLogDebug("Detect Engine using new det_ctx - %p",
                  det_ctx);
    }

    /* if in MT mode _and_ we have tenants registered, use
     * MT logic. */
    if (det_ctx->mt_det_ctxs_cnt > 0 && det_ctx->TenantGetId != NULL)
    {
        uint32_t tenant_id = p->tenant_id;
        if (tenant_id == 0)
            tenant_id = det_ctx->TenantGetId(det_ctx, p);
        if (tenant_id > 0 && tenant_id < det_ctx->mt_det_ctxs_cnt) {
            p->tenant_id = tenant_id;
            det_ctx = GetTenantById(det_ctx->mt_det_ctxs_hash, tenant_id);
            if (det_ctx == NULL)
                return TM_ECODE_OK;
            de_ctx = det_ctx->de_ctx;
            if (de_ctx == NULL)
                return TM_ECODE_OK;

            if (SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0) {
                (void)SC_ATOMIC_SET(det_ctx->so_far_used_by_detect, 1);
                SCLogDebug("MT de_ctx %p det_ctx %p (tenant %u)", de_ctx, det_ctx, tenant_id);
            }
        } else {
            /* use default if no tenants are registered for this packet */
            de_ctx = det_ctx->de_ctx;
        }
    } else {
        de_ctx = det_ctx->de_ctx;
    }

    /* see if the packet matches one or more of the sigs */
    int r = SigMatchSignatures(tv,de_ctx,det_ctx,p);
    if (r >= 0) {
        return TM_ECODE_OK;
    }

error:
    return TM_ECODE_FAILED;
}

TmEcode DetectThreadInit(ThreadVars *t, void *initdata, void **data)
{
    return DetectEngineThreadCtxInit(t,initdata,data);
}

TmEcode DetectThreadDeinit(ThreadVars *t, void *data)
{
    return DetectEngineThreadCtxDeinit(t,data);
}

void SigCleanSignatures(DetectEngineCtx *de_ctx)
{
    Signature *s = NULL, *ns;

    if (de_ctx == NULL)
        return;

    for (s = de_ctx->sig_list; s != NULL;) {
        ns = s->next;
        SigFree(s);
        s = ns;
    }

    de_ctx->sig_list = NULL;

    DetectEngineResetMaxSigId(de_ctx);
    de_ctx->sig_list = NULL;
}

/** \brief Find a specific signature by sid and gid
 *  \param de_ctx detection engine ctx
 *  \param sid the signature id
 *  \param gid the signature group id
 *
 *  \retval s sig found
 *  \retval NULL sig not found
 */
Signature *SigFindSignatureBySidGid(DetectEngineCtx *de_ctx, uint32_t sid, uint32_t gid)
{
    Signature *s = NULL;

    if (de_ctx == NULL)
        return NULL;

    for (s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (s->id == sid && s->gid == gid)
            return s;
    }

    return NULL;
}


int SignatureIsAppLayer(DetectEngineCtx *de_ctx, Signature *s)
{
    if (s->alproto != 0)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filestore keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilestoring(Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->flags & SIG_FLAG_FILESTORE)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filemagic keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilemagicInspecting(Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->file_flags & FILE_SIG_NEED_MAGIC)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filemd5 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileMd5Inspecting(Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->file_flags & FILE_SIG_NEED_MD5)
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesize keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilesizeInspecting(Signature *s)
{
    if (s == NULL)
        return 0;

    if (s->file_flags & FILE_SIG_NEED_SIZE)
        return 1;

    return 0;
}

/** \brief Test is a initialized signature is IP only
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is ip only
 *  \retval 0 sig is not ip only
 */
int SignatureIsIPOnly(DetectEngineCtx *de_ctx, Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_FILEDATA] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HSMDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HSCDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HUADMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HHHDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_HRHHDMATCH] != NULL)
        return 0;

    if (s->sm_lists[DETECT_SM_LIST_AMATCH] != NULL)
        return 0;

    /* TMATCH list can be ignored, it contains TAGs and
     * tags are compatible to IP-only. */

    IPOnlyCIDRItem *cidr_item;
    cidr_item = s->CidrSrc;
    while (cidr_item != NULL) {
        if (cidr_item->negated)
            return 0;

        cidr_item = cidr_item->next;
    }
    cidr_item = s->CidrDst;
    while (cidr_item != NULL) {
        if (cidr_item->negated)
            return 0;

        cidr_item = cidr_item->next;
    }

    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_MATCH];
    if (sm == NULL)
        goto iponly;

    for ( ; sm != NULL; sm = sm->next) {
        if ( !(sigmatch_table[sm->type].flags & SIGMATCH_IPONLY_COMPAT))
            return 0;
        /* we have enabled flowbits to be compatible with ip only sigs, as long
         * as the sig only has a "set" flowbits */
        if (sm->type == DETECT_FLOWBITS &&
            (((DetectFlowbitsData *)sm->ctx)->cmd != DETECT_FLOWBITS_CMD_SET) ) {
            return 0;
        }
    }

iponly:
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("IP-ONLY (%" PRIu32 "): source %s, dest %s", s->id,
                   s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET",
                   s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    }
    return 1;
}

/**
 *  \internal
 *  \brief Check if the initialized signature is inspecting the packet payload
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is inspecting the payload
 *  \retval 0 sig is not inspecting the payload
 */
static int SignatureIsInspectingPayload(DetectEngineCtx *de_ctx, Signature *s)
{

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        return 1;
    }
#if 0
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm == NULL)
        return 0;

    for (; sm != NULL; sm = sm->next) {
        if (sigmatch_table[sm->type].flags & SIGMATCH_PAYLOAD) {
            if (!(de_ctx->flags & DE_QUIET))
                SCLogDebug("Signature (%" PRIu32 "): is inspecting payload.", s->id);
            return 1;
        }
    }
#endif
    return 0;
}

/**
 *  \internal
 *  \brief check if a signature is decoder event matching only
 *  \param de_ctx detection engine
 *  \param s the signature to test
 *  \retval 0 not a DEOnly sig
 *  \retval 1 DEOnly sig
 */
static int SignatureIsDEOnly(DetectEngineCtx *de_ctx, Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN) {
        SCReturnInt(0);
    }

    if (s->sm_lists[DETECT_SM_LIST_PMATCH]    != NULL ||
        s->sm_lists[DETECT_SM_LIST_UMATCH]    != NULL ||
        s->sm_lists[DETECT_SM_LIST_AMATCH]    != NULL ||
        s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_FILEDATA] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HHDMATCH]  != NULL ||
        s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HMDMATCH]  != NULL ||
        s->sm_lists[DETECT_SM_LIST_HCDMATCH]  != NULL ||
        s->sm_lists[DETECT_SM_LIST_HSMDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HSCDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HUADMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HHHDMATCH] != NULL ||
        s->sm_lists[DETECT_SM_LIST_HRHHDMATCH] != NULL)
    {
        SCReturnInt(0);
    }

    /* check for conflicting keywords */
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_MATCH];
    for ( ;sm != NULL; sm = sm->next) {
        if ( !(sigmatch_table[sm->type].flags & SIGMATCH_DEONLY_COMPAT))
            SCReturnInt(0);
    }

    /* need at least one decode event keyword to be considered decode event. */
    sm = s->sm_lists[DETECT_SM_LIST_MATCH];
    for ( ;sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_DECODE_EVENT)
            goto deonly;
        if (sm->type == DETECT_ENGINE_EVENT)
            goto deonly;
        if (sm->type == DETECT_STREAM_EVENT)
            goto deonly;
    }

    SCReturnInt(0);

deonly:
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("DE-ONLY (%" PRIu32 "): source %s, dest %s", s->id,
                   s->flags & SIG_FLAG_SRC_ANY ? "ANY" : "SET",
                   s->flags & SIG_FLAG_DST_ANY ? "ANY" : "SET");
    }

    SCReturnInt(1);
}

#define MASK_TCP_INITDEINIT_FLAGS   (TH_SYN|TH_RST|TH_FIN)
#define MASK_TCP_UNUSUAL_FLAGS      (TH_URG|TH_ECN|TH_CWR)

/* Create mask for this packet + it's flow if it has one
 *
 * Sets SIG_MASK_REQUIRE_PAYLOAD, SIG_MASK_REQUIRE_FLOW,
 * SIG_MASK_REQUIRE_HTTP_STATE, SIG_MASK_REQUIRE_DCE_STATE
 */
static void
PacketCreateMask(Packet *p, SignatureMask *mask, AppProto alproto, int has_state, StreamMsg *smsg,
        int app_decoder_events)
{
    /* no payload inspect flag doesn't apply to smsg */
    if (smsg != NULL || (!(p->flags & PKT_NOPAYLOAD_INSPECTION) && p->payload_len > 0)) {
        SCLogDebug("packet has payload");
        (*mask) |= SIG_MASK_REQUIRE_PAYLOAD;
    } else {
        SCLogDebug("packet has no payload");
        (*mask) |= SIG_MASK_REQUIRE_NO_PAYLOAD;
    }

    if (p->events.cnt > 0 || app_decoder_events != 0 || p->app_layer_events != NULL) {
        SCLogDebug("packet/flow has events set");
        (*mask) |= SIG_MASK_REQUIRE_ENGINE_EVENT;
    }

    if (PKT_IS_TCP(p)) {
        if ((p->tcph->th_flags & MASK_TCP_INITDEINIT_FLAGS) != 0) {
            (*mask) |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
        }
        if ((p->tcph->th_flags & MASK_TCP_UNUSUAL_FLAGS) != 0) {
            (*mask) |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
        }
    }

    if (p->flags & PKT_HAS_FLOW) {
        SCLogDebug("packet has flow");
        (*mask) |= SIG_MASK_REQUIRE_FLOW;

        if (has_state) {
            switch(alproto) {
                case ALPROTO_HTTP:
                    SCLogDebug("packet/flow has http state");
                    (*mask) |= SIG_MASK_REQUIRE_HTTP_STATE;
                    break;
                case ALPROTO_SMB:
                case ALPROTO_SMB2:
                case ALPROTO_DCERPC:
                    SCLogDebug("packet/flow has dce state");
                    (*mask) |= SIG_MASK_REQUIRE_DCE_STATE;
                    break;
                case ALPROTO_SSH:
                    SCLogDebug("packet/flow has ssh state");
                    (*mask) |= SIG_MASK_REQUIRE_SSH_STATE;
                    break;
                case ALPROTO_TLS:
                    SCLogDebug("packet/flow has tls state");
                    (*mask) |= SIG_MASK_REQUIRE_TLS_STATE;
                    break;
                case ALPROTO_DNS:
                    SCLogDebug("packet/flow has dns state");
                    (*mask) |= SIG_MASK_REQUIRE_DNS_STATE;
                    break;
                case ALPROTO_FTP:
                    SCLogDebug("packet/flow has ftp state");
                    (*mask) |= SIG_MASK_REQUIRE_FTP_STATE;
                    break;
                case ALPROTO_SMTP:
                    SCLogDebug("packet/flow has smtp state");
                    (*mask) |= SIG_MASK_REQUIRE_SMTP_STATE;
                    break;
                case ALPROTO_TEMPLATE:
                    SCLogDebug("packet/flow has template state");
                    (*mask) |= SIG_MASK_REQUIRE_TEMPLATE_STATE;
                    break;
                default:
                    SCLogDebug("packet/flow has other state");
                    break;
            }
        } else {
            SCLogDebug("no alstate");
        }
    }
}

static int SignatureCreateMask(Signature *s)
{
    SCEnter();

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
        SCLogDebug("sig requires payload");
    }

    if (s->sm_lists[DETECT_SM_LIST_DMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_DCE_STATE;
        SCLogDebug("sig requires dce state");
    }

    if (s->sm_lists[DETECT_SM_LIST_UMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HCBDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_FILEDATA] != NULL) {
        /* set the state depending from the protocol */
        if (s->alproto == ALPROTO_HTTP)
            s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        else if (s->alproto == ALPROTO_SMTP)
            s->mask |= SIG_MASK_REQUIRE_SMTP_STATE;

        SCLogDebug("sig requires http or smtp app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HHDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HRHDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HMDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HCDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HRUDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HSMDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HSCDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HUADMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HHHDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    if (s->sm_lists[DETECT_SM_LIST_HRHHDMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
        SCLogDebug("sig requires http app state");
    }

    SigMatch *sm;
    for (sm = s->sm_lists[DETECT_SM_LIST_AMATCH] ; sm != NULL; sm = sm->next) {
        switch(sm->type) {
            case DETECT_AL_URILEN:
            case DETECT_AL_HTTP_URI:
                s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
                SCLogDebug("sig requires dce http state");
                break;
            case DETECT_AL_APP_LAYER_EVENT:
                s->mask |= SIG_MASK_REQUIRE_ENGINE_EVENT;
                break;
        }
    }

    for (sm = s->sm_lists[DETECT_SM_LIST_APP_EVENT] ; sm != NULL; sm = sm->next) {
        switch (sm->type) {
            case DETECT_AL_APP_LAYER_EVENT:
            {
                DetectAppLayerEventData *aed = (DetectAppLayerEventData *)sm->ctx;
                switch (aed->alproto) {
                    case ALPROTO_HTTP:
                        s->mask |= SIG_MASK_REQUIRE_HTTP_STATE;
                        SCLogDebug("sig %u requires http app state (http event)", s->id);
                        break;
                    case ALPROTO_SMTP:
                        s->mask |= SIG_MASK_REQUIRE_SMTP_STATE;
                        SCLogDebug("sig %u requires smtp app state (smtp event)", s->id);
                        break;
                    case ALPROTO_DNS:
                        s->mask |= SIG_MASK_REQUIRE_DNS_STATE;
                        SCLogDebug("sig %u requires dns app state (dns event)", s->id);
                        break;
                }
                break;
            }
        }
    }

    for (sm = s->sm_lists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
        switch(sm->type) {
            case DETECT_FLOWBITS:
            {
                /* figure out what flowbit action */
                DetectFlowbitsData *fb = (DetectFlowbitsData *)sm->ctx;
                if (fb->cmd == DETECT_FLOWBITS_CMD_ISSET) {
                    /* not a mask flag, but still set it here */
                    s->flags |= SIG_FLAG_REQUIRE_FLOWVAR;

                    SCLogDebug("SIG_FLAG_REQUIRE_FLOWVAR set as sig has "
                            "flowbit isset option.");
                }

                /* flow is required for any flowbit manipulation */
                s->mask |= SIG_MASK_REQUIRE_FLOW;
                SCLogDebug("sig requires flow to be able to manipulate "
                        "flowbit(s)");
                break;
            }
            case DETECT_FLAGS:
            {
                DetectFlagsData *fl = (DetectFlagsData *)sm->ctx;

                if (fl->flags & TH_SYN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_RST) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_FIN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_INITDEINIT;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_INITDEINIT");
                }
                if (fl->flags & TH_URG) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                if (fl->flags & TH_ECN) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                if (fl->flags & TH_CWR) {
                    s->mask |= SIG_MASK_REQUIRE_FLAGS_UNUSUAL;
                    SCLogDebug("sig requires SIG_MASK_REQUIRE_FLAGS_UNUSUAL");
                }
                break;
            }
            case DETECT_DSIZE:
            {
                DetectDsizeData *ds = (DetectDsizeData *)sm->ctx;
                switch (ds->mode) {
                    case DETECTDSIZE_LT:
                        /* LT will include 0, so no payload.
                         * if GT is used in the same rule the
                         * flag will be set anyway. */
                        break;
                    case DETECTDSIZE_RA:
                    case DETECTDSIZE_GT:
                        s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
                        SCLogDebug("sig requires payload");
                        break;
                    case DETECTDSIZE_EQ:
                        if (ds->dsize > 0) {
                            s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
                            SCLogDebug("sig requires payload");
                        } else if (ds->dsize == 0) {
                            s->mask |= SIG_MASK_REQUIRE_NO_PAYLOAD;
                            SCLogDebug("sig requires no payload");
                        }
                        break;
                }
                break;
            }
            case DETECT_AL_APP_LAYER_EVENT:
                s->mask |= SIG_MASK_REQUIRE_ENGINE_EVENT;
                break;
            case DETECT_ENGINE_EVENT:
                s->mask |= SIG_MASK_REQUIRE_ENGINE_EVENT;
                break;
        }
    }

    if (s->alproto == ALPROTO_SSH) {
        s->mask |= SIG_MASK_REQUIRE_SSH_STATE;
        SCLogDebug("sig requires ssh state");
    }
    if (s->alproto == ALPROTO_TLS) {
        s->mask |= SIG_MASK_REQUIRE_TLS_STATE;
        SCLogDebug("sig requires tls state");
    }
    if (s->alproto == ALPROTO_DNS) {
        s->mask |= SIG_MASK_REQUIRE_DNS_STATE;
        SCLogDebug("sig requires dns state");
    }
    if (s->alproto == ALPROTO_FTP) {
        s->mask |= SIG_MASK_REQUIRE_FTP_STATE;
        SCLogDebug("sig requires ftp state");
    }
    if (s->alproto == ALPROTO_SMTP) {
        s->mask |= SIG_MASK_REQUIRE_SMTP_STATE;
        SCLogDebug("sig requires smtp state");
    }
    if (s->alproto == ALPROTO_TEMPLATE) {
        s->mask |= SIG_MASK_REQUIRE_TEMPLATE_STATE;
        SCLogDebug("sig requires template state");
    }

    if ((s->mask & SIG_MASK_REQUIRE_DCE_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_HTTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_SSH_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_DNS_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_FTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_SMTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_TEMPLATE_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_TLS_STATE))
    {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    if (s->init_flags & SIG_FLAG_INIT_FLOW) {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    if (s->sm_lists[DETECT_SM_LIST_AMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    if (s->flags & SIG_FLAG_APPLAYER) {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    SCLogDebug("mask %02X", s->mask);
    SCReturnInt(0);
}

static void SigInitStandardMpmFactoryContexts(DetectEngineCtx *de_ctx)
{
    de_ctx->sgh_mpm_context_proto_tcp_packet =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "packet_proto_tcp",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_proto_udp_packet =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "packet_proto_udp",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_proto_other_packet =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "packet_proto_other",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_uri =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "uri",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_stream =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "stream",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hcbd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hcbd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hsbd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hsbd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_smtp =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "smtp",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hhd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hhd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hrhd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hrhd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hmd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hmd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hcd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hcd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hrud =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hrud",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hsmd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hsmd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hscd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hscd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_huad =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "huad",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hhhd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hhhd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_hrhhd =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "hrhhd",
                                        MPM_CTX_FACTORY_FLAGS_PREPARE_WITH_SIG_GROUP_BUILD);
    de_ctx->sgh_mpm_context_app_proto_detect =
        MpmFactoryRegisterMpmCtxProfile(de_ctx, "app_proto_detect", 0);

    return;
}

/** \brief get max dsize "depth"
 *  \param s signature to get dsize value from
 *  \retval depth or negative value
 */
static int SigParseGetMaxDsize(Signature *s)
{
    if (s->flags & SIG_FLAG_DSIZE && s->dsize_sm != NULL) {
        DetectDsizeData *dd = (DetectDsizeData *)s->dsize_sm->ctx;

        switch (dd->mode) {
            case DETECTDSIZE_LT:
            case DETECTDSIZE_EQ:
                return dd->dsize;
            case DETECTDSIZE_RA:
                return dd->dsize2;
            case DETECTDSIZE_GT:
            default:
                SCReturnInt(-2);
        }
    }
    SCReturnInt(-1);
}

/** \brief set prefilter dsize pair
 *  \param s signature to get dsize value from
 */
static void SigParseSetDsizePair(Signature *s)
{
    if (s->flags & SIG_FLAG_DSIZE && s->dsize_sm != NULL) {
        DetectDsizeData *dd = (DetectDsizeData *)s->dsize_sm->ctx;

        uint16_t low = 0;
        uint16_t high = 65535;

        switch (dd->mode) {
            case DETECTDSIZE_LT:
                low = 0;
                high = dd->dsize;
                break;
            case DETECTDSIZE_EQ:
                low = dd->dsize;
                high = dd->dsize;
                break;
            case DETECTDSIZE_RA:
                low = dd->dsize;
                high = dd->dsize2;
                break;
            case DETECTDSIZE_GT:
                low = dd->dsize;
                high = 65535;
                break;
        }
        s->dsize_low = low;
        s->dsize_high = high;

        SCLogDebug("low %u, high %u", low, high);
    }
}

/**
 *  \brief Apply dsize as depth to content matches in the rule
 *  \param s signature to get dsize value from
 */
static void SigParseApplyDsizeToContent(Signature *s)
{
    SCEnter();

    if (s->flags & SIG_FLAG_DSIZE) {
        SigParseSetDsizePair(s);

        int dsize = SigParseGetMaxDsize(s);
        if (dsize < 0) {
            /* nothing to do */
            return;
        }

        SigMatch *sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
        for ( ; sm != NULL;  sm = sm->next) {
            if (sm->type != DETECT_CONTENT) {
                continue;
            }

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            if (cd == NULL) {
                continue;
            }

            if (cd->depth == 0 || cd->depth >= dsize) {
                cd->depth = (uint16_t)dsize;
                SCLogDebug("updated %u, content %u to have depth %u "
                        "because of dsize.", s->id, cd->id, cd->depth);
            }
        }
    }
}

/**
 * \brief Preprocess signature, classify ip-only, etc, build sig array
 *
 * \param de_ctx Pointer to the Detection Engine Context
 *
 * \retval  0 on success
 * \retval -1 on failure
 */
int SigAddressPrepareStage1(DetectEngineCtx *de_ctx)
{
    Signature *tmp_s = NULL;
    uint32_t cnt_iponly = 0;
    uint32_t cnt_payload = 0;
    uint32_t cnt_applayer = 0;
    uint32_t cnt_deonly = 0;

    //DetectAddressPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("building signature grouping structure, stage 1: "
                   "preprocessing rules...");
    }

#ifdef HAVE_LUAJIT
    /* run this before the mpm states are initialized */
    if (DetectLuajitSetupStatesPool(de_ctx->detect_luajit_instances, TRUE) != 0) {
        if (de_ctx->failure_fatal)
            return -1;
    }
#endif

    de_ctx->sig_array_len = DetectEngineGetMaxSigId(de_ctx);
    de_ctx->sig_array_size = (de_ctx->sig_array_len * sizeof(Signature *));
    de_ctx->sig_array = (Signature **)SCMalloc(de_ctx->sig_array_size);
    if (de_ctx->sig_array == NULL)
        goto error;
    memset(de_ctx->sig_array,0,de_ctx->sig_array_size);

    SCLogDebug("signature lookup array: %" PRIu32 " sigs, %" PRIu32 " bytes",
               de_ctx->sig_array_len, de_ctx->sig_array_size);

    /* now for every rule add the source group */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        de_ctx->sig_array[tmp_s->num] = tmp_s;

        SCLogDebug("Signature %" PRIu32 ", internal id %" PRIu32 ", ptrs %p %p ", tmp_s->id, tmp_s->num, tmp_s, de_ctx->sig_array[tmp_s->num]);

        /* see if the sig is ip only */
        if (SignatureIsIPOnly(de_ctx, tmp_s) == 1) {
            tmp_s->flags |= SIG_FLAG_IPONLY;
            cnt_iponly++;

            SCLogDebug("Signature %"PRIu32" is considered \"IP only\"", tmp_s->id);

        /* see if any sig is inspecting the packet payload */
        } else if (SignatureIsInspectingPayload(de_ctx, tmp_s) == 1) {
            tmp_s->init_flags |= SIG_FLAG_INIT_PAYLOAD;
            cnt_payload++;

            SCLogDebug("Signature %"PRIu32" is considered \"Payload inspecting\"", tmp_s->id);
        } else if (SignatureIsDEOnly(de_ctx, tmp_s) == 1) {
            tmp_s->init_flags |= SIG_FLAG_INIT_DEONLY;
            SCLogDebug("Signature %"PRIu32" is considered \"Decoder Event only\"", tmp_s->id);
            cnt_deonly++;
        }

        if (tmp_s->flags & SIG_FLAG_APPLAYER) {
            SCLogDebug("Signature %"PRIu32" is considered \"Applayer inspecting\"", tmp_s->id);
            cnt_applayer++;
        }

#ifdef DEBUG
        if (SCLogDebugEnabled()) {
            uint16_t colen = 0;
            char copresent = 0;
            SigMatch *sm;
            DetectContentData *co;
            for (sm = tmp_s->sm_lists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
                if (sm->type != DETECT_CONTENT)
                    continue;

                copresent = 1;
                co = (DetectContentData *)sm->ctx;
                if (co->content_len > colen)
                    colen = co->content_len;
            }

            if (copresent && colen == 1) {
                SCLogDebug("signature %8u content maxlen 1", tmp_s->id);
                int proto;
                for (proto = 0; proto < 256; proto++) {
                    if (tmp_s->proto.proto[(proto/8)] & (1<<(proto%8)))
                        SCLogDebug("=> proto %" PRId32 "", proto);
                }
            }
        }
#endif /* DEBUG */

        SignatureCreateMask(tmp_s);
        SigParseApplyDsizeToContent(tmp_s);

        de_ctx->sig_cnt++;
    }

    //DetectAddressPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("%" PRIu32 " signatures processed. %" PRIu32 " are IP-only "
                "rules, %" PRIu32 " are inspecting packet payload, %"PRIu32
                " inspect application layer, %"PRIu32" are decoder event only",
                de_ctx->sig_cnt, cnt_iponly, cnt_payload, cnt_applayer,
                cnt_deonly);

        SCLogInfo("building signature grouping structure, stage 1: "
               "preprocessing rules... complete");
    }
    return 0;

error:
    return -1;
}

static int DetectEngineLookupBuildSourceAddressList(DetectEngineCtx *de_ctx, DetectEngineLookupFlow *flow_gh, Signature *s, int family)
{
    DetectAddress *gr = NULL, *lookup_gr = NULL, *head = NULL;
    int proto;

    if (family == AF_INET) {
        head = s->src.ipv4_head;
    } else if (family == AF_INET6) {
        head = s->src.ipv6_head;
    } else {
        head = s->src.any_head;
    }

    /* for each source address group in the signature... */
    for (gr = head; gr != NULL; gr = gr->next) {
        BUG_ON(gr->ip.family == 0 && !(gr->flags & ADDRESS_FLAG_ANY));

        /* ...and each protocol the signature matches on... */
        for (proto = 0; proto < 256; proto++) {
            if ((s->proto.proto[(proto/8)] & (1<<(proto%8))) || (s->proto.flags & DETECT_PROTO_ANY)) {
                /* ...see if the group is in the tmp list, and if not add it. */
                if (family == AF_INET) {
                    lookup_gr = DetectAddressLookupInList(flow_gh->tmp_gh[proto]->ipv4_head,gr);
                } else if (family == AF_INET6) {
                    lookup_gr = DetectAddressLookupInList(flow_gh->tmp_gh[proto]->ipv6_head,gr);
                } else {
                    lookup_gr = DetectAddressLookupInList(flow_gh->tmp_gh[proto]->any_head,gr);
                }

                if (lookup_gr == NULL) {
                    DetectAddress *grtmp = DetectAddressCopy(gr);
                    if (grtmp == NULL) {
                        goto error;
                    }
                    SigGroupHeadAppendSig(de_ctx, &grtmp->sh, s);

                    /* add to the lookup list */
                    if (family == AF_INET) {
                        DetectAddressAdd(&flow_gh->tmp_gh[proto]->ipv4_head, grtmp);
                    } else if (family == AF_INET6) {
                        DetectAddressAdd(&flow_gh->tmp_gh[proto]->ipv6_head, grtmp);
                    } else {
                        DetectAddressAdd(&flow_gh->tmp_gh[proto]->any_head, grtmp);
                    }
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx, &lookup_gr->sh, s);
                    lookup_gr->cnt++;
                }
            }
        }
    }

    return 0;
error:
    return -1;
}

/**
 *  \brief add signature to the right flow group(s)
 */
static int DetectEngineLookupFlowAddSig(DetectEngineCtx *de_ctx, Signature *s, int family)
{
    SCLogDebug("s->id %u", s->id);

    if (s->flags & SIG_FLAG_TOCLIENT) {
        SCLogDebug("s->id %u (toclient)", s->id);
        DetectEngineLookupBuildSourceAddressList(de_ctx,
                &de_ctx->flow_gh[0], s, family);
    }

    if (s->flags & SIG_FLAG_TOSERVER) {
        SCLogDebug("s->id %u (toserver)", s->id);
        DetectEngineLookupBuildSourceAddressList(de_ctx,
                &de_ctx->flow_gh[1], s, family);
    }

    return 0;
}

static DetectAddress *GetHeadPtr(DetectAddressHead *head, int family)
{
    DetectAddress *grhead;

    if (head == NULL)
        return NULL;

    if (family == AF_INET) {
        grhead = head->ipv4_head;
    } else if (family == AF_INET6) {
        grhead = head->ipv6_head;
    } else {
        grhead = head->any_head;
    }

    return grhead;
}

//#define SMALL_MPM(c) 0
#define SMALL_MPM(c) ((c) == 1)
// || (c) == 2)
// || (c) == 3)

int CreateGroupedAddrListCmpCnt(DetectAddress *a, DetectAddress *b)
{
    if (a->cnt > b->cnt)
        return 1;
    return 0;
}

int CreateGroupedAddrListCmpMpmMinlen(DetectAddress *a, DetectAddress *b)
{
    if (a->sh == NULL || b->sh == NULL)
        return 0;

    if (SMALL_MPM(a->sh->mpm_content_minlen))
        return 1;

    if (a->sh->mpm_content_minlen < b->sh->mpm_content_minlen)
        return 1;
    return 0;
}

/* set unique_groups to 0 for no grouping.
 *
 * srchead is a ordered "inserted" list w/o internal overlap
 *
 */
int CreateGroupedAddrList(DetectEngineCtx *de_ctx, DetectAddress *srchead,
                          int family, DetectAddressHead *newhead,
                          uint32_t unique_groups,
                          int (*CompareFunc)(DetectAddress *, DetectAddress *),
                          uint32_t max_idx)
{
    DetectAddress *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectAddress *gr, *next_gr;
    uint32_t groups = 0;

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for (gr = srchead; gr != NULL; gr = gr->next) {
        BUG_ON(gr->ip.family == 0 && !(gr->flags & ADDRESS_FLAG_ANY));

        if (SMALL_MPM(gr->sh->mpm_content_minlen) && unique_groups > 0)
            unique_groups++;

        groups++;

        /* alloc a copy */
        DetectAddress *newtmp = DetectAddressCopy(gr);
        if (newtmp == NULL) {
            goto error;
        }
        SigGroupHeadCopySigs(de_ctx, gr->sh,&newtmp->sh);

        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx,&newtmp->port, port);
            newtmp->flags |= ADDRESS_HAVEPORT;
        }

        /* insert it */
        DetectAddress *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = newtmp;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL&&!insert; tmpgr = tmpgr->next) {
                if (CompareFunc(gr, tmpgr)) {
                    if (tmpgr == tmplist) {
                        newtmp->next = tmplist;
                        tmplist = newtmp;
                    } else {
                        newtmp->next = prevtmpgr->next;
                        prevtmpgr->next = newtmp;
                    }
                    insert = 1;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                newtmp->next = NULL;
                prevtmpgr->next = newtmp;
            }
            insert = 0;
        }
    }

    uint32_t i = unique_groups;
    if (i == 0) i = groups;

    for (gr = tmplist; gr != NULL; ) {
        BUG_ON(gr->ip.family == 0 && !(gr->flags & ADDRESS_FLAG_ANY));

        if (i == 0) {
            if (joingr == NULL) {
                joingr = DetectAddressCopy(gr);
                if (joingr == NULL) {
                    goto error;
                }

                SigGroupHeadCopySigs(de_ctx,gr->sh,&joingr->sh);

                DetectPort *port = gr->port;
                for ( ; port != NULL; port = port->next) {
                    DetectPortInsertCopy(de_ctx,&joingr->port, port);
                    joingr->flags |= ADDRESS_HAVEPORT;
                }
            } else {
                DetectAddressJoin(de_ctx, joingr, gr);
            }
        } else {
            DetectAddress *newtmp = DetectAddressCopy(gr);
            if (newtmp == NULL) {
                goto error;
            }

            SigGroupHeadCopySigs(de_ctx,gr->sh,&newtmp->sh);

            DetectPort *port = gr->port;
            for ( ; port != NULL; port = port->next) {
                DetectPortInsertCopy(de_ctx,&newtmp->port, port);
                newtmp->flags |= ADDRESS_HAVEPORT;
            }

            if (tmplist2 == NULL) {
                tmplist2 = newtmp;
            } else {
                newtmp->next = tmplist2;
                tmplist2 = newtmp;
            }
        }
        if (i)i--;

        next_gr = gr->next;
        DetectAddressFree(gr);
        gr = next_gr;
    }

    /* we now have a tmplist2 containing the 'unique' groups and
     * possibly a joingr that covers the rest. Now build the newhead
     * that we will pass back to the caller.
     *
     * Start with inserting the unique groups */
    for (gr = tmplist2; gr != NULL; ) {
        BUG_ON(gr->ip.family == 0 && !(gr->flags & ADDRESS_FLAG_ANY));

        DetectAddress *newtmp = DetectAddressCopy(gr);
        if (newtmp == NULL) {
            goto error;
        }
        SigGroupHeadCopySigs(de_ctx, gr->sh,&newtmp->sh);

        DetectPort *port = gr->port;
        for ( ; port != NULL; port = port->next) {
            DetectPortInsertCopy(de_ctx, &newtmp->port, port);
            newtmp->flags |= ADDRESS_HAVEPORT;
        }

        DetectAddressInsert(de_ctx, newhead, newtmp);

        next_gr = gr->next;
        DetectAddressFree(gr);
        gr = next_gr;
    }

    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
        DetectAddressInsert(de_ctx, newhead, joingr);
    }

    return 0;
error:
    return -1;
}

int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b)
{
    if (a->cnt > b->cnt)
        return 1;
    return 0;
}

int CreateGroupedPortListCmpMpmMinlen(DetectPort *a, DetectPort *b)
{
    if (a->sh == NULL || b->sh == NULL)
        return 0;

    if (SMALL_MPM(a->sh->mpm_content_minlen))
        return 1;

    if (a->sh->mpm_content_minlen < b->sh->mpm_content_minlen)
        return 1;

    return 0;
}

static uint32_t g_groupportlist_maxgroups = 0;
static uint32_t g_groupportlist_groupscnt = 0;
static uint32_t g_groupportlist_totgroups = 0;

int CreateGroupedPortList(DetectEngineCtx *de_ctx,HashListTable *port_hash, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx)
{
    DetectPort *tmplist = NULL, *tmplist2 = NULL, *joingr = NULL;
    char insert = 0;
    DetectPort *gr, *next_gr;
    uint32_t groups = 0;

    HashListTableBucket *htb = HashListTableGetListHead(port_hash);

    /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt'. */
    for ( ; htb != NULL; htb = HashListTableGetListNext(htb)) {
        gr = (DetectPort *)HashListTableGetListData(htb);

        SCLogDebug("hash list gr %p", gr);
        DetectPortPrint(gr);

        if (SMALL_MPM(gr->sh->mpm_content_minlen) && unique_groups > 0)
            unique_groups++;

        groups++;

        /* alloc a copy */
        DetectPort *newtmp = DetectPortCopySingle(de_ctx, gr);
        if (newtmp == NULL) {
            goto error;
        }

        /* insert it */
        DetectPort *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = newtmp;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL&&!insert; tmpgr = tmpgr->next) {
                if (CompareFunc(gr, tmpgr)) {
                    if (tmpgr == tmplist) {
                        newtmp->next = tmplist;
                        tmplist = newtmp;
                    } else {
                        newtmp->next = prevtmpgr->next;
                        prevtmpgr->next = newtmp;
                    }
                    insert = 1;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                newtmp->next = NULL;
                prevtmpgr->next = newtmp;
            }
            insert = 0;
        }
    }

    uint32_t i = unique_groups;
    if (i == 0) i = groups;

    if (unique_groups > g_groupportlist_maxgroups)
        g_groupportlist_maxgroups = unique_groups;
    g_groupportlist_groupscnt++;
    g_groupportlist_totgroups += unique_groups;

    for (gr = tmplist; gr != NULL; ) {
        SCLogDebug("temp list gr %p", gr);
        DetectPortPrint(gr);

        if (i == 0) {
            if (joingr == NULL) {
                joingr = DetectPortCopySingle(de_ctx,gr);
                if (joingr == NULL) {
                    goto error;
                }
            } else {
                DetectPortJoin(de_ctx,joingr, gr);
            }
        } else {
            DetectPort *newtmp = DetectPortCopySingle(de_ctx,gr);
            if (newtmp == NULL) {
                goto error;
            }

            if (tmplist2 == NULL) {
                tmplist2 = newtmp;
            } else {
                newtmp->next = tmplist2;
                tmplist2 = newtmp;
            }
        }
        if (i)i--;

        next_gr = gr->next;
        gr->next = NULL;
        DetectPortFree(gr);
        gr = next_gr;
    }

    /* we now have a tmplist2 containing the 'unique' groups and
     * possibly a joingr that covers the rest. Now build the newhead
     * that we will pass back to the caller.
     *
     * Start with inserting the unique groups */
    for (gr = tmplist2; gr != NULL; ) {
        SCLogDebug("temp list2 gr %p", gr);
        DetectPortPrint(gr);

        DetectPort *newtmp = DetectPortCopySingle(de_ctx,gr);
        if (newtmp == NULL) {
            goto error;
        }

        int r = DetectPortInsert(de_ctx,newhead,newtmp);
        BUG_ON(r == -1);

        next_gr = gr->next;
        gr->next = NULL;
        DetectPortFree(gr);
        gr = next_gr;
    }

    DetectPortPrintList(*newhead);

    /* if present, insert the joingr that covers the rest */
    if (joingr != NULL) {
        SCLogDebug("inserting joingr %p", joingr);
        DetectPortInsert(de_ctx,newhead,joingr);
    } else {
        SCLogDebug("no joingr");
    }

    return 0;
error:
    return -1;
}

/**
 *  \internal
 *  \brief add a decoder event signature to the detection engine ctx
 */
static void DetectEngineAddDecoderEventSig(DetectEngineCtx *de_ctx, Signature *s)
{
    SCLogDebug("adding signature %"PRIu32" to the decoder event sgh", s->id);
    SigGroupHeadAppendSig(de_ctx, &de_ctx->decoder_event_sgh, s);
}

/**
 * \brief Fill the global src group head, with the sigs included
 *
 * \param de_ctx Pointer to the Detection Engine Context whose Signatures have
 *               to be processed
 *
 * \retval  0 On success
 * \retval -1 On failure
 */
int SigAddressPrepareStage2(DetectEngineCtx *de_ctx)
{
    Signature *tmp_s = NULL;
    uint32_t sigs = 0;

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("building signature grouping structure, stage 2: "
                  "building source address lists...");
    }

    IPOnlyInit(de_ctx, &de_ctx->io_ctx);

    int f, proto;
    for (f = 0; f < FLOW_STATES; f++) {
        for (proto = 0; proto < 256; proto++) {
            de_ctx->flow_gh[f].src_gh[proto] = DetectAddressHeadInit();
            if (de_ctx->flow_gh[f].src_gh[proto] == NULL) {
                goto error;
            }
            de_ctx->flow_gh[f].tmp_gh[proto] = DetectAddressHeadInit();
            if (de_ctx->flow_gh[f].tmp_gh[proto] == NULL) {
                goto error;
            }
        }
    }

    /* now for every rule add the source group to our temp lists */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        SCLogDebug("tmp_s->id %"PRIu32, tmp_s->id);
        if (tmp_s->flags & SIG_FLAG_IPONLY) {
            IPOnlyAddSignature(de_ctx, &de_ctx->io_ctx, tmp_s);
        } else {
            DetectEngineLookupFlowAddSig(de_ctx, tmp_s, AF_INET);
            DetectEngineLookupFlowAddSig(de_ctx, tmp_s, AF_INET6);
            DetectEngineLookupFlowAddSig(de_ctx, tmp_s, AF_UNSPEC);
        }

        if (tmp_s->init_flags & SIG_FLAG_INIT_DEONLY) {
            DetectEngineAddDecoderEventSig(de_ctx, tmp_s);
        }

        sigs++;
    }

    /* create the final src addr list based on the tmplist. */
    for (f = 0; f < FLOW_STATES; f++) {
        for (proto = 0; proto < 256; proto++) {
            int groups = (f ? de_ctx->max_uniq_toserver_src_groups : de_ctx->max_uniq_toclient_src_groups);

            CreateGroupedAddrList(de_ctx,
                    de_ctx->flow_gh[f].tmp_gh[proto]->ipv4_head, AF_INET,
                    de_ctx->flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMinlen, DetectEngineGetMaxSigId(de_ctx));

            CreateGroupedAddrList(de_ctx,
                    de_ctx->flow_gh[f].tmp_gh[proto]->ipv6_head, AF_INET6,
                    de_ctx->flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMinlen, DetectEngineGetMaxSigId(de_ctx));
            CreateGroupedAddrList(de_ctx,
                    de_ctx->flow_gh[f].tmp_gh[proto]->any_head, AF_UNSPEC,
                    de_ctx->flow_gh[f].src_gh[proto], groups,
                    CreateGroupedAddrListCmpMpmMinlen, DetectEngineGetMaxSigId(de_ctx));

            DetectAddressHeadFree(de_ctx->flow_gh[f].tmp_gh[proto]);
            de_ctx->flow_gh[f].tmp_gh[proto] = NULL;
        }
    }
    //DetectAddressPrintMemory();
    //DetectSigGroupPrintMemory();

    //printf("g_src_gh strt\n");
    //DetectAddressPrintList(g_src_gh->ipv4_head);
    //printf("g_src_gh end\n");

    IPOnlyPrepare(de_ctx);
    IPOnlyPrint(de_ctx, &de_ctx->io_ctx);
#ifdef DEBUG
    DetectAddress *gr = NULL;
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("%" PRIu32 " total signatures:", sigs);
    }

    /* TCP */
    uint32_t cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_TCP]->any_head; gr != NULL; gr = gr->next) {
            cnt_any++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_TCP]->ipv4_head; gr != NULL; gr = gr->next) {
            cnt_ipv4++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_TCP]->ipv6_head; gr != NULL; gr = gr->next) {
            cnt_ipv6++;
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("TCP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    /* UDP */
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_UDP]->any_head; gr != NULL; gr = gr->next) {
            cnt_any++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_UDP]->ipv4_head; gr != NULL; gr = gr->next) {
            cnt_ipv4++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_UDP]->ipv6_head; gr != NULL; gr = gr->next) {
            cnt_ipv6++;
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("UDP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    /* SCTP */
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP]->any_head; gr != NULL; gr = gr->next) {
            cnt_any++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP]->ipv4_head; gr != NULL; gr = gr->next) {
            cnt_ipv4++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP]->ipv6_head; gr != NULL; gr = gr->next) {
            cnt_ipv6++;
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("SCTP Source address blocks:     any: %4u, ipv4: %4u, ipv6: %4u.", cnt_any, cnt_ipv4, cnt_ipv6);
    }

    /* ICMP */
    cnt_any = 0, cnt_ipv4 = 0, cnt_ipv6 = 0;
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[1]->any_head; gr != NULL; gr = gr->next) {
            cnt_any++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[1]->ipv4_head; gr != NULL; gr = gr->next) {
            cnt_ipv4++;
        }
    }
    for (f = 0; f < FLOW_STATES; f++) {
        for (gr = de_ctx->flow_gh[f].src_gh[1]->ipv6_head; gr != NULL; gr = gr->next) {
            cnt_ipv6++;
        }
    }
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("ICMP Source address blocks:    any: %4u, ipv4: %4u, ipv6: %4u.", cnt_any, cnt_ipv4, cnt_ipv6);
    }
#endif /* DEBUG */
    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("building signature grouping structure, stage 2: building source address list... complete");
    }

    return 0;
error:
    printf("SigAddressPrepareStage2 error\n");
    return -1;
}

/**
 *  \brief Build the destination address portion of the match tree
 */
int BuildDestinationAddressHeads(DetectEngineCtx *de_ctx, DetectAddressHead *head, int family, int flow)
{
    Signature *tmp_s = NULL;
    DetectAddress *gr = NULL, *sgr = NULL, *lookup_gr = NULL;
    uint32_t max_idx = 0;

    DetectAddress *grhead = NULL, *grdsthead = NULL, *grsighead = NULL;

    /* based on the family, select the list we are using in the head */
    grhead = GetHeadPtr(head, family);

    /* loop through the global source address list */
    for (gr = grhead; gr != NULL; gr = gr->next) {
        //printf(" * Source group (BuildDestinationAddressHeads): "); DetectAddressPrint(gr); printf(" (%p)\n", gr);

        /* initialize the destination group head */
        gr->dst_gh = DetectAddressHeadInit();
        if (gr->dst_gh == NULL) {
            goto error;
        }

        /* use a tmp list for speeding up insertions */
        DetectAddress *tmp_gr_list = NULL;

        /* loop through all signatures in this source address group
         * and build the temporary destination address list for it */
        uint32_t sig;
        for (sig = 0; sig < de_ctx->sig_array_len; sig++) {
            if (!(gr->sh->init->sig_array[(sig/8)] & (1<<(sig%8))))
                continue;

            tmp_s = de_ctx->sig_array[sig];
            if (tmp_s == NULL)
                continue;

            //printf("  * (tmp) Signature %u (num %u)\n", tmp_s->id, tmp_s->num);

            max_idx = sig;

            /* build the temp list */
            grsighead = GetHeadPtr(&tmp_s->dst, family);
            for (sgr = grsighead; sgr != NULL; sgr = sgr->next) {
                //printf("  * (tmp) dst group: "); DetectAddressPrint(sgr); printf(" (%p)\n", sgr);

                if ((lookup_gr = DetectAddressLookupInList(tmp_gr_list, sgr)) == NULL) {
                    DetectAddress *grtmp = DetectAddressCopy(sgr);
                    if (grtmp == NULL) {
                        goto error;
                    }
                    SigGroupHeadAppendSig(de_ctx,&grtmp->sh,tmp_s);

                    DetectAddressAdd(&tmp_gr_list,grtmp);
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx, &lookup_gr->sh, tmp_s);
                    lookup_gr->cnt++;
                }
            }

        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        int groups = (flow ? de_ctx->max_uniq_toserver_dst_groups : de_ctx->max_uniq_toclient_dst_groups);

        CreateGroupedAddrList(de_ctx, tmp_gr_list, family, gr->dst_gh, groups,
                CreateGroupedAddrListCmpMpmMinlen, max_idx);

        /* see if the sig group head of each address group is the
         * same as an earlier one. If it is, free our head and use
         * a pointer to the earlier one. This saves _a lot_ of memory.
         */
        grdsthead = GetHeadPtr(gr->dst_gh, family);
        for (sgr = grdsthead; sgr != NULL; sgr = sgr->next) {
            //printf("  * Destination group: "); DetectAddressPrint(sgr); printf("\n");

            /* Because a pattern matcher context uses quite some
             * memory, we first check if we can reuse it from
             * another group head. */
            SigGroupHead *sgh = SigGroupHeadHashLookup(de_ctx, sgr->sh);
            if (sgh == NULL) {
                /* put the contents in our sig group head */
                SigGroupHeadSetSigCnt(sgr->sh, max_idx);
                SigGroupHeadBuildMatchArray(de_ctx, sgr->sh, max_idx);

                /* init the pattern matcher, this will respect the copy
                 * setting */
                if (PatternMatchPrepareGroup(de_ctx, sgr->sh) < 0) {
                    printf("PatternMatchPrepareGroup failed\n");
                    goto error;
                }
                SigGroupHeadHashAdd(de_ctx, sgr->sh);
                SigGroupHeadStore(de_ctx, sgr->sh);
                de_ctx->gh_unique++;
            } else {
                SCLogDebug("calling SigGroupHeadFree sgr %p, sgr->sh %p", sgr, sgr->sh);
                SigGroupHeadFree(sgr->sh);
                sgr->sh = sgh;

                de_ctx->gh_reuse++;
                sgr->flags |= ADDRESS_SIGGROUPHEAD_COPY;
                sgr->sh->flags |= SIG_GROUP_HEAD_REFERENCED;
            }
        }

        /* free the temp list */
        DetectAddressCleanupList(tmp_gr_list);
        /* clear now unneeded sig group head */
        SCLogDebug("calling SigGroupHeadFree gr %p, gr->sh %p", gr, gr->sh);
        SigGroupHeadFree(gr->sh);
        gr->sh = NULL;
    }

    return 0;
error:
    return -1;
}

//static
int BuildDestinationAddressHeadsWithBothPorts(DetectEngineCtx *de_ctx, DetectAddressHead *head, int family, int flow)
{
    Signature *tmp_s = NULL;
    DetectAddress *src_gr = NULL, *dst_gr = NULL, *sig_gr = NULL, *lookup_gr = NULL;
    DetectAddress *src_gr_head = NULL, *dst_gr_head = NULL, *sig_gr_head = NULL;
    uint32_t max_idx = 0;

    /* loop through the global source address list */
    src_gr_head = GetHeadPtr(head,family);
    for (src_gr = src_gr_head; src_gr != NULL; src_gr = src_gr->next) {
        //printf(" * Source group: "); DetectAddressPrint(src_gr); printf("\n");

        /* initialize the destination group head */
        src_gr->dst_gh = DetectAddressHeadInit();
        if (src_gr->dst_gh == NULL) {
            goto error;
        }

        /* use a tmp list for speeding up insertions */
        DetectAddress *tmp_gr_list = NULL;

        /* loop through all signatures in this source address group
         * and build the temporary destination address list for it */
        uint32_t sig;
        for (sig = 0; sig < de_ctx->sig_array_len; sig++) {
            if (!(src_gr->sh->init->sig_array[(sig/8)] & (1<<(sig%8))))
                continue;

            tmp_s = de_ctx->sig_array[sig];
            if (tmp_s == NULL)
                continue;

            //printf(" * Source group: "); DetectAddressPrint(src_gr); printf("\n");

            max_idx = sig;

            /* build the temp list */
            sig_gr_head = GetHeadPtr(&tmp_s->dst,family);
            for (sig_gr = sig_gr_head; sig_gr != NULL; sig_gr = sig_gr->next) {
                //printf("  * Sig dst addr: "); DetectAddressPrint(sig_gr); printf("\n");

                if ((lookup_gr = DetectAddressLookupInList(tmp_gr_list, sig_gr)) == NULL) {
                    DetectAddress *grtmp = DetectAddressCopy(sig_gr);
                    if (grtmp == NULL) {
                        goto error;
                    }
                    SigGroupHeadAppendSig(de_ctx, &grtmp->sh, tmp_s);

                    DetectAddressAdd(&tmp_gr_list,grtmp);
                } else {
                    /* our group will only have one sig, this one. So add that. */
                    SigGroupHeadAppendSig(de_ctx, &lookup_gr->sh, tmp_s);
                    lookup_gr->cnt++;
                }

                SCLogDebug("calling SigGroupHeadFree sig_gr %p, sig_gr->sh %p", sig_gr, sig_gr->sh);
                SigGroupHeadFree(sig_gr->sh);
                sig_gr->sh = NULL;
            }
        }

        /* Create the destination address list, keeping in
         * mind the limits we use. */
        int groups = (flow ? de_ctx->max_uniq_toserver_dst_groups : de_ctx->max_uniq_toclient_dst_groups);

        CreateGroupedAddrList(de_ctx, tmp_gr_list, family, src_gr->dst_gh, groups,
                CreateGroupedAddrListCmpMpmMinlen, max_idx);

        /* add the ports to the dst address groups and the sigs
         * to the ports */
        dst_gr_head = GetHeadPtr(src_gr->dst_gh,family);
        for (dst_gr = dst_gr_head; dst_gr != NULL; dst_gr = dst_gr->next) {
            //printf("  * Destination group: "); DetectAddressPrint(dst_gr); printf("\n");

            dst_gr->flags |= ADDRESS_HAVEPORT;

            if (dst_gr->sh == NULL)
                continue;

            /* we will reuse address sig group heads at this points,
             * because if the sigs are the same, the ports will be
             * the same. Saves memory and a lot of init time. */
            SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, dst_gr->sh);
            if (lookup_sgh == NULL) {
                DetectPortSpHashReset(de_ctx);

                uint32_t sig2;
                for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                    if (!(dst_gr->sh->init->sig_array[(sig2/8)] & (1<<(sig2%8))))
                        continue;

                    Signature *s = de_ctx->sig_array[sig2];
                    if (s == NULL)
                        continue;

                    //printf("  + Destination group (grouped): "); DetectAddressPrint(dst_gr); printf("\n");

                    DetectPort *sdp = s->sp;
                    for ( ; sdp != NULL; sdp = sdp->next) {
                        DetectPort *lookup_port = DetectPortSpHashLookup(de_ctx, sdp);
                        if (lookup_port == NULL) {
                            DetectPort *port = DetectPortCopySingle(de_ctx,sdp);
                            if (port == NULL)
                                goto error;

                            SigGroupHeadAppendSig(de_ctx, &port->sh, s);
                            DetectPortSpHashAdd(de_ctx, port);
                            port->cnt = 1;
                        } else {
                            SigGroupHeadAppendSig(de_ctx, &lookup_port->sh, s);
                            lookup_port->cnt++;
                        }
                    }
                }

                int spgroups = (flow ? de_ctx->max_uniq_toserver_sp_groups : de_ctx->max_uniq_toclient_sp_groups);

                CreateGroupedPortList(de_ctx, de_ctx->sport_hash_table, &dst_gr->port, spgroups,
                        CreateGroupedPortListCmpMpmMinlen, max_idx);

                SCLogDebug("adding sgh %p to the hash", dst_gr->sh);
                SigGroupHeadHashAdd(de_ctx, dst_gr->sh);

                dst_gr->sh->init->port = dst_gr->port;
                /* mark this head for deletion once we no longer need
                 * the hash. We're only using the port ptr, so no problem
                 * when we remove this after initialization is done */
                dst_gr->sh->flags |= SIG_GROUP_HEAD_FREE;

                /* for each destination port we setup the siggrouphead here */
                DetectPort *sp = dst_gr->port;
                for ( ; sp != NULL; sp = sp->next) {
                    //printf("   * Src Port(range): "); DetectPortPrint(sp); printf("\n");

                    if (sp->sh == NULL)
                        continue;

                    /* we will reuse address sig group heads at this points,
                     * because if the sigs are the same, the ports will be
                     * the same. Saves memory and a lot of init time. */
                    SigGroupHead *lookup_sp_sgh = SigGroupHeadSPortHashLookup(de_ctx, sp->sh);
                    if (lookup_sp_sgh == NULL) {
                        DetectPortDpHashReset(de_ctx);
                        uint32_t sig2;
                        for (sig2 = 0; sig2 < max_idx+1; sig2++) {
                            if (!(sp->sh->init->sig_array[(sig2/8)] & (1<<(sig2%8))))
                                continue;

                            Signature *s = de_ctx->sig_array[sig2];
                            if (s == NULL)
                                continue;

                            DetectPort *sdp = s->dp;
                            for ( ; sdp != NULL; sdp = sdp->next) {
                                DetectPort *lookup_port = DetectPortDpHashLookup(de_ctx,sdp);
                                if (lookup_port == NULL) {
                                    DetectPort *port = DetectPortCopySingle(de_ctx,sdp);
                                    if (port == NULL)
                                        goto error;

                                    SigGroupHeadAppendSig(de_ctx, &port->sh, s);
                                    DetectPortDpHashAdd(de_ctx,port);
                                    port->cnt = 1;
                                } else {
                                    SigGroupHeadAppendSig(de_ctx, &lookup_port->sh, s);
                                    lookup_port->cnt++;
                                }
                            }
                        }

                        int dpgroups = (flow ? de_ctx->max_uniq_toserver_dp_groups : de_ctx->max_uniq_toclient_dp_groups);

                        CreateGroupedPortList(de_ctx, de_ctx->dport_hash_table,
                            &sp->dst_ph, dpgroups,
                            CreateGroupedPortListCmpMpmMinlen, max_idx);

                        SigGroupHeadSPortHashAdd(de_ctx, sp->sh);

                        sp->sh->init->port = sp->dst_ph;
                        /* mark this head for deletion once we no longer need
                         * the hash. We're only using the port ptr, so no problem
                         * when we remove this after initialization is done */
                        sp->sh->flags |= SIG_GROUP_HEAD_FREE;

                        /* for each destination port we setup the siggrouphead here */
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            if (dp->sh == NULL)
                                continue;

                            /* Because a pattern matcher context uses quite some
                             * memory, we first check if we can reuse it from
                             * another group head. */
                            SigGroupHead *lookup_dp_sgh = SigGroupHeadDPortHashLookup(de_ctx, dp->sh);
                            if (lookup_dp_sgh == NULL) {
                                SCLogDebug("dp %p dp->sh %p is the original (sp %p, dst_gr %p, src_gr %p)", dp, dp->sh, sp, dst_gr, src_gr);

                                SigGroupHeadSetSigCnt(dp->sh, max_idx);
                                SigGroupHeadBuildMatchArray(de_ctx,dp->sh, max_idx);

                                /* init the pattern matcher, this will respect the copy
                                 * setting */
                                if (PatternMatchPrepareGroup(de_ctx, dp->sh) < 0) {
                                    printf("PatternMatchPrepareGroup failed\n");
                                    goto error;
                                }
                                SigGroupHeadDPortHashAdd(de_ctx, dp->sh);
                                SigGroupHeadStore(de_ctx, dp->sh);
                                de_ctx->gh_unique++;
                            } else {
                                SCLogDebug("dp %p dp->sh %p is a copy", dp, dp->sh);

                                SigGroupHeadFree(dp->sh);
                                dp->sh = lookup_dp_sgh;
                                dp->flags |= PORT_SIGGROUPHEAD_COPY;
                                dp->sh->flags |= SIG_GROUP_HEAD_REFERENCED;

                                de_ctx->gh_reuse++;
                            }
                        }
                    /* sig group head found in hash, free it and use the hashed one */
                    } else {
                        SigGroupHeadFree(sp->sh);
                        sp->sh = lookup_sp_sgh;
                        sp->flags |= PORT_SIGGROUPHEAD_COPY;
                        sp->sh->flags |= SIG_GROUP_HEAD_REFERENCED;

                        SCLogDebug("replacing sp->dst_ph %p with lookup_sp_sgh->init->port %p", sp->dst_ph, lookup_sp_sgh->init->port);
                        DetectPortCleanupList(sp->dst_ph);
                        sp->dst_ph = lookup_sp_sgh->init->port;
                        sp->flags |= PORT_GROUP_PORTS_COPY;

                        de_ctx->gh_reuse++;
                    }
                }
            } else {
                SigGroupHeadFree(dst_gr->sh);
                dst_gr->sh = lookup_sgh;
                dst_gr->flags |= ADDRESS_SIGGROUPHEAD_COPY;
                dst_gr->sh->flags |= SIG_GROUP_HEAD_REFERENCED;

                SCLogDebug("replacing dst_gr->port %p with lookup_sgh->init->port %p", dst_gr->port, lookup_sgh->init->port);
                DetectPortCleanupList(dst_gr->port);
                dst_gr->port = lookup_sgh->init->port;
                dst_gr->flags |= ADDRESS_PORTS_COPY;

                de_ctx->gh_reuse++;
            }
        }
        /* free the temp list */
        DetectAddressCleanupList(tmp_gr_list);
        /* clear now unneeded sig group head */
        SigGroupHeadFree(src_gr->sh);
        src_gr->sh = NULL;

        /* free dst addr sgh's */
        dst_gr_head = GetHeadPtr(src_gr->dst_gh,family);
        for (dst_gr = dst_gr_head; dst_gr != NULL; dst_gr = dst_gr->next) {
            if (!(dst_gr->flags & ADDRESS_SIGGROUPHEAD_COPY)) {
                if (!(dst_gr->sh->flags & SIG_GROUP_HEAD_REFERENCED)) {
                    SCLogDebug("removing sgh %p from hash", dst_gr->sh);

                    int r = SigGroupHeadHashRemove(de_ctx,dst_gr->sh);
                    BUG_ON(r == -1);
                    if (r == 0) {
                        SCLogDebug("removed sgh %p from hash", dst_gr->sh);
                        SigGroupHeadFree(dst_gr->sh);
                        dst_gr->sh = NULL;
                    }
                }
            }
        }
    }

    return 0;
error:
    return -1;
}

static void DetectEngineBuildDecoderEventSgh(DetectEngineCtx *de_ctx)
{
    if (de_ctx->decoder_event_sgh == NULL)
        return;

    uint32_t max_idx = DetectEngineGetMaxSigId(de_ctx);
    SigGroupHeadSetSigCnt(de_ctx->decoder_event_sgh, max_idx);
    SigGroupHeadBuildMatchArray(de_ctx, de_ctx->decoder_event_sgh, max_idx);
}

int SigAddressPrepareStage3(DetectEngineCtx *de_ctx)
{
    int r;

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("building signature grouping structure, stage 3: "
               "building destination address lists...");
    }
    //DetectAddressPrintMemory();
    //DetectSigGroupPrintMemory();
    //DetectPortPrintMemory();

    int f = 0;
    int proto;
    for (f = 0; f < FLOW_STATES; f++) {
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_TCP],AF_INET,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_UDP],AF_INET,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP],AF_INET,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[IPPROTO_SCTP],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_TCP],AF_INET6,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_UDP],AF_INET6,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP],AF_INET6,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[IPPROTO_SCTP],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_TCP],AF_UNSPEC,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[6],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_UDP],AF_UNSPEC,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[17],AF_INET) failed\n");
            goto error;
        }
        r = BuildDestinationAddressHeadsWithBothPorts(de_ctx, de_ctx->flow_gh[f].src_gh[IPPROTO_SCTP],AF_UNSPEC,f);
        if (r < 0) {
            printf ("BuildDestinationAddressHeads(src_gh[IPPROTO_SCTP],AF_INET) failed\n");
            goto error;
        }
        for (proto = 0; proto < 256; proto++) {
            if (proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_SCTP)
                continue;

            r = BuildDestinationAddressHeads(de_ctx, de_ctx->flow_gh[f].src_gh[proto],AF_INET,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_INET) failed\n", proto);
                goto error;
            }
            r = BuildDestinationAddressHeads(de_ctx, de_ctx->flow_gh[f].src_gh[proto],AF_INET6,f);
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_INET6) failed\n", proto);
                goto error;
            }
            r = BuildDestinationAddressHeads(de_ctx, de_ctx->flow_gh[f].src_gh[proto],AF_UNSPEC,f); /* for any */
            if (r < 0) {
                printf ("BuildDestinationAddressHeads(src_gh[%" PRId32 "],AF_UNSPEC) failed\n", proto);
                goto error;
            }
        }
    }

    /* prepare the decoder event sgh */
    DetectEngineBuildDecoderEventSgh(de_ctx);

    /* cleanup group head (uri)content_array's */
    SigGroupHeadFreeMpmArrays(de_ctx);
    /* cleanup group head sig arrays */
    SigGroupHeadFreeSigArrays(de_ctx);

    /* cleanup the hashes now since we won't need them
     * after the initialization phase. */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadDPortHashFree(de_ctx);
    SigGroupHeadSPortHashFree(de_ctx);
    SigGroupHeadMpmHashFree(de_ctx);
    SigGroupHeadMpmUriHashFree(de_ctx);
    DetectPortDpHashFree(de_ctx);
    DetectPortSpHashFree(de_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("max sig id %" PRIu32 ", array size %" PRIu32 "", DetectEngineGetMaxSigId(de_ctx), DetectEngineGetMaxSigId(de_ctx) / 8 + 1);
        SCLogDebug("signature group heads: unique %" PRIu32 ", copies %" PRIu32 ".", de_ctx->gh_unique, de_ctx->gh_reuse);
        SCLogDebug("port maxgroups: %" PRIu32 ", avg %" PRIu32 ", tot %" PRIu32 "", g_groupportlist_maxgroups, g_groupportlist_groupscnt ? g_groupportlist_totgroups/g_groupportlist_groupscnt : 0, g_groupportlist_totgroups);

        SCLogInfo("building signature grouping structure, stage 3: building destination address lists... complete");
    }
    return 0;
error:
    printf("SigAddressPrepareStage3 error\n");
    return -1;
}

int SigAddressCleanupStage1(DetectEngineCtx *de_ctx)
{
    BUG_ON(de_ctx == NULL);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("cleaning up signature grouping structure...");
    }

    int f, proto;
    for (f = 0; f < FLOW_STATES; f++) {
        for (proto = 0; proto < 256; proto++) {
            /* XXX fix this */
            DetectAddressHeadFree(de_ctx->flow_gh[f].src_gh[proto]);
            de_ctx->flow_gh[f].src_gh[proto] = NULL;
        }
    }

    if (de_ctx->decoder_event_sgh)
        SigGroupHeadFree(de_ctx->decoder_event_sgh);
    de_ctx->decoder_event_sgh = NULL;

    IPOnlyDeinit(de_ctx, &de_ctx->io_ctx);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("cleaning up signature grouping structure... complete");
    }
    return 0;
}

void DbgPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        printf("%" PRIu32 " ", sgh->match_array[sig]->id);
    }
    printf("\n");
}

void DbgPrintSigs2(DetectEngineCtx *de_ctx, SigGroupHead *sgh)
{
    if (sgh == NULL || sgh->init == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < DetectEngineGetMaxSigId(de_ctx); sig++) {
        if (sgh->init->sig_array[(sig/8)] & (1<<(sig%8))) {
            printf("%" PRIu32 " ", de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}

void DbgSghContainsSig(DetectEngineCtx *de_ctx, SigGroupHead *sgh, uint32_t sid)
{
    if (sgh == NULL || sgh->init == NULL) {
        printf("\n");
        return;
    }

    uint32_t sig;
    for (sig = 0; sig < DetectEngineGetMaxSigId(de_ctx); sig++) {
        if (!(sgh->init->sig_array[(sig/8)] & (1<<(sig%8))))
            continue;

        Signature *s = de_ctx->sig_array[sig];
        if (s == NULL)
            continue;

        if (sid == s->id) {
            printf("%" PRIu32 " ", de_ctx->sig_array[sig]->id);
        }
    }
    printf("\n");
}

/** \brief finalize preparing sgh's */
int SigAddressPrepareStage4(DetectEngineCtx *de_ctx)
{
    SCEnter();

    //SCLogInfo("sgh's %"PRIu32, de_ctx->sgh_array_cnt);

    uint32_t idx = 0;

    for (idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;
        SigGroupHeadSetFilemagicFlag(de_ctx, sgh);
        SigGroupHeadSetFileMd5Flag(de_ctx, sgh);
        SigGroupHeadSetFilesizeFlag(de_ctx, sgh);
        SigGroupHeadSetFilestoreCount(de_ctx, sgh);
        SCLogDebug("filestore count %u", sgh->filestore_cnt);

        SigGroupHeadBuildNonMpmArray(de_ctx, sgh);

        sgh->mpm_uricontent_minlen = SigGroupHeadGetMinMpmSize(de_ctx, sgh, DETECT_SM_LIST_UMATCH);
        SCLogDebug("http_uri content min mpm len: %u", sgh->mpm_uricontent_minlen);
    }

    if (de_ctx->decoder_event_sgh != NULL) {
        /* no need to set filestore count here as that would make a
         * signature not decode event only. */
    }

    SCFree(de_ctx->sgh_array);
    de_ctx->sgh_array_cnt = 0;
    de_ctx->sgh_array_size = 0;

    SCReturnInt(0);
}

/* shortcut for debugging. If enabled Stage5 will
 * print sigid's for all groups */
#define PRINTSIGS

/* just printing */
int SigAddressPrepareStage5(DetectEngineCtx *de_ctx)
{
    DetectAddressHead *global_dst_gh = NULL;
    DetectAddress *global_src_gr = NULL, *global_dst_gr = NULL;
    uint32_t u;

    printf("* Building signature grouping structure, stage 5: print...\n");

    int f, proto;
    printf("\n");
    for (f = 0; f < FLOW_STATES; f++) {
        printf("\n");
        for (proto = 0; proto < 256; proto++) {
            if (proto != IPPROTO_TCP)
                continue;

            for (global_src_gr = de_ctx->flow_gh[f].src_gh[proto]->ipv4_head; global_src_gr != NULL;
                    global_src_gr = global_src_gr->next)
            {
                printf("1 Src Addr: "); DetectAddressPrint(global_src_gr);
                printf(" (sh %p)\n", global_src_gr->sh);
                //printf("\n");

#ifdef PRINTSIGS
                SigGroupHeadPrintSigs(de_ctx, global_src_gr->sh);
                if (global_src_gr->sh != NULL) {
                    printf(" - ");
                    for (u = 0; u < global_src_gr->sh->sig_cnt; u++) {
                        Signature *s = global_src_gr->sh->match_array[u];
                        printf("%" PRIu32 " ", s->id);
                    }
                    printf("\n");
                }
#endif

                global_dst_gh = global_src_gr->dst_gh;
                if (global_dst_gh == NULL)
                    continue;

                for (global_dst_gr = global_dst_gh->ipv4_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" 2 Dst Addr: "); DetectAddressPrint(global_dst_gr);

                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf(" (COPY): ");
                        } else {
                            printf(" (ORIGINAL): ");
                        }
                    } else {
                        printf(" ");
                    }

#ifdef PRINTSIGS
                    if (global_dst_gr->sh != NULL) {
                        printf(" - ");
                        for (u = 0; u < global_dst_gr->sh->sig_cnt; u++) {
                            Signature *s = global_dst_gr->sh->match_array[u];
                            printf("%" PRIu32 " ", s->id);
                        }
                        printf("\n");
                    }
#endif


                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  3 Src port(range): "); DetectPortPrint(sp);
                        //printf(" (sh %p)", sp->sh);
                        printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   4 Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ", sgh %p, minlen %" PRIu32 ")", dp->sh->sig_cnt, dp->sh, dp->sh->mpm_content_minlen);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = dp->sh->match_array[u];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
                for (global_dst_gr = global_dst_gh->any_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = dp->sh->match_array[u];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
            }
#if 0
            for (global_src_gr = de_ctx->flow_gh[f].src_gh[proto]->ipv6_head; global_src_gr != NULL;
                    global_src_gr = global_src_gr->next)
            {
                printf("- "); DetectAddressPrint(global_src_gr);
                //printf(" (sh %p)\n", global_src_gr->sh);

                global_dst_gh = global_src_gr->dst_gh;
                if (global_dst_gh == NULL)
                    continue;

                for (global_dst_gr = global_dst_gh->ipv6_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = de_ctx->sig_array[dp->sh->match_array[u]];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
                for (global_dst_gr = global_dst_gh->any_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = de_ctx->sig_array[dp->sh->match_array[u]];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
            }

            for (global_src_gr = de_ctx->flow_gh[f].src_gh[proto]->any_head; global_src_gr != NULL;
                    global_src_gr = global_src_gr->next)
            {
                printf("- "); DetectAddressPrint(global_src_gr);
                //printf(" (sh %p)\n", global_src_gr->sh);

                global_dst_gh = global_src_gr->dst_gh;
                if (global_dst_gh == NULL)
                    continue;

                for (global_dst_gr = global_dst_gh->any_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = de_ctx->sig_array[dp->sh->match_array[u]];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
                for (global_dst_gr = global_dst_gh->ipv4_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = de_ctx->sig_array[dp->sh->match_array[u]];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
                for (global_dst_gr = global_dst_gh->ipv6_head;
                        global_dst_gr != NULL;
                        global_dst_gr = global_dst_gr->next)
                {
                    printf(" - "); DetectAddressPrint(global_dst_gr);
                    //printf(" (sh %p) ", global_dst_gr->sh);
                    if (global_dst_gr->sh) {
                        if (global_dst_gr->sh->flags & ADDRESS_SIGGROUPHEAD_COPY) {
                            printf("(COPY)\n");
                        } else {
                            printf("\n");
                        }
                    }
                    DetectPort *sp = global_dst_gr->port;
                    for ( ; sp != NULL; sp = sp->next) {
                        printf("  * Src port(range): "); DetectPortPrint(sp); printf("\n");
                        DetectPort *dp = sp->dst_ph;
                        for ( ; dp != NULL; dp = dp->next) {
                            printf("   * Dst port(range): "); DetectPortPrint(dp);
                            printf(" (sigs %" PRIu32 ")", dp->sh->sig_cnt);
#ifdef PRINTSIGS
                            printf(" - ");
                            for (u = 0; u < dp->sh->sig_cnt; u++) {
                                Signature *s = de_ctx->sig_array[dp->sh->match_array[u]];
                                printf("%" PRIu32 " ", s->id);
                            }
#endif
                            printf("\n");
                        }
                    }
                }
            }
#endif
        }
    }

    printf("* Building signature grouping structure, stage 5: print... done\n");
    return 0;
}

static int SigMatchListLen(SigMatch *sm)
{
    int len = 0;
    for (; sm != NULL; sm = sm->next)
        len++;

    return len;
}

static int SigMatchPrepare(DetectEngineCtx *de_ctx)
{
    SCEnter();

    Signature *s = de_ctx->sig_list;
    for (; s != NULL; s = s->next) {
        int type;
        for (type = 0; type < DETECT_SM_LIST_MAX; type++) {
            SigMatch *sm = s->sm_lists[type];
            int len = SigMatchListLen(sm);
            if (len == 0)
                s->sm_arrays[type] = NULL;
            else {
                SigMatchData *smd = (SigMatchData*)SCMalloc(len * sizeof(SigMatchData));
                if (smd == NULL) {
                    SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
                    exit(EXIT_FAILURE);
                }
                /* Copy sm type and Context into array */
                s->sm_arrays[type] = smd;
                for (; sm != NULL; sm = sm->next, smd++) {
                    smd->type = sm->type;
                    smd->ctx = sm->ctx;
                    smd->is_last = (sm->next == NULL);
                }
            }
        }
    }

    SCReturnInt(0);
}

/**
 * \brief Convert the signature list into the runtime match structure.
 *
 * \param de_ctx Pointer to the Detection Engine Context whose Signatures have
 *               to be processed
 *
 * \retval  0 On Success.
 * \retval -1 On failure.
 */
int SigGroupBuild(DetectEngineCtx *de_ctx)
{
    Signature *s = de_ctx->sig_list;

    /* Assign the unique order id of signatures after sorting,
     * so the IP Only engine process them in order too.  Also
     * reset the old signums and assign new signums.  We would
     * have experienced Sig reordering by now, hence the new
     * signums. */
    de_ctx->signum = 0;
    while (s != NULL) {
        s->num = de_ctx->signum++;

        s = s->next;
    }

    if (DetectSetFastPatternAndItsId(de_ctx) < 0)
        return -1;

    /* if we are using single sgh_mpm_context then let us init the standard mpm
     * contexts using the mpm_ctx factory */
    if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
        SigInitStandardMpmFactoryContexts(de_ctx);
    }

    if (SigAddressPrepareStage1(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }
//exit(0);
    if (SigAddressPrepareStage2(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

    if (SigAddressPrepareStage3(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }
    if (SigAddressPrepareStage4(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

    if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
        MpmCtx *mpm_ctx = NULL;

#ifdef __SC_CUDA_SUPPORT__
        if (PatternMatchDefaultMatcher() == MPM_AC_CUDA) {
            /* setting it to default.  You've gotta remove it once you fix the state table thing */
            SCACConstructBoth16and32StateTables();

            MpmCudaConf *conf = CudaHandlerGetCudaProfile("mpm");
            CUcontext cuda_context = CudaHandlerModuleGetContext(MPM_AC_CUDA_MODULE_NAME, conf->device_id);
            if (cuda_context == 0) {
                SCLogError(SC_ERR_FATAL, "cuda context is NULL.");
                exit(EXIT_FAILURE);
            }
            int r = SCCudaCtxPushCurrent(cuda_context);
            if (r < 0) {
                SCLogError(SC_ERR_FATAL, "context push failed.");
                exit(EXIT_FAILURE);
            }
        }
#endif

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_tcp_packet, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("packet- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_udp_packet, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("packet- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_proto_other_packet, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("packet- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_uri, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_uri, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("uri- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcbd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcbd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hcbd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsbd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsbd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hsbd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_smtp, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_smtp, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("smtp- %d\n"; mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hhd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hrhd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hmd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hmd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hmd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hcd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hcd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrud, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrud, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hrud- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_stream, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("stream- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsmd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hsmd- %d\n", mpm_ctx->pattern_cnt);
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hsmd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hsmd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hscd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hscd- %d\n", mpm_ctx->pattern_cnt);
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hscd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hscd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_huad, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("huad- %d\n", mpm_ctx->pattern_cnt);
        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_huad, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("huad- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhhd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hhhd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hhhd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hhhd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhhd, 0);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hrhhd- %d\n", mpm_ctx->pattern_cnt);

        mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx, de_ctx->sgh_mpm_context_hrhhd, 1);
        if (mpm_table[de_ctx->mpm_matcher].Prepare != NULL) {
            mpm_table[de_ctx->mpm_matcher].Prepare(mpm_ctx);
        }
        //printf("hrhhd- %d\n", mpm_ctx->pattern_cnt);

#ifdef __SC_CUDA_SUPPORT__
        if (PatternMatchDefaultMatcher() == MPM_AC_CUDA) {
            int r = SCCudaCtxPopCurrent(NULL);
            if (r < 0) {
                SCLogError(SC_ERR_FATAL, "cuda context pop failure.");
                exit(EXIT_FAILURE);
            }
        }

        /* too late to call this either ways.  Should be called post ac goto.
         * \todo Support this. */
        DetermineCudaStateTableSize(de_ctx);
#endif

    }

//    SigAddressPrepareStage5(de_ctx);
//    DetectAddressPrintMemory();
//    DetectSigGroupPrintMemory();
//    DetectPortPrintMemory();

    if (SigMatchPrepare(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

#ifdef PROFILING
    SCProfilingRuleInitCounters(de_ctx);
#endif
    return 0;
}

int SigGroupCleanup (DetectEngineCtx *de_ctx)
{
    SigAddressCleanupStage1(de_ctx);

    return 0;
}

static inline void PrintFeatureList(int flags, char sep)
{
    int prev = 0;
    if (flags & SIGMATCH_NOOPT) {
        printf("No option");
        prev = 1;
    }
    if (flags & SIGMATCH_IPONLY_COMPAT) {
        if (prev == 1)
            printf("%c", sep);
        printf("compatible with IP only rule");
        prev = 1;
    }
    if (flags & SIGMATCH_DEONLY_COMPAT) {
        if (prev == 1)
            printf("%c", sep);
        printf("compatible with decoder event only rule");
        prev = 1;
    }
    if (flags & SIGMATCH_PAYLOAD) {
        if (prev == 1)
            printf("%c", sep);
        printf("payload inspecting keyword");
        prev = 1;
    }
    if (prev == 0) {
        printf("none");
    }
}

static inline void SigMultilinePrint(int i, char *prefix)
{
    if (sigmatch_table[i].desc) {
        printf("%sDescription: %s\n", prefix, sigmatch_table[i].desc);
    }
    printf("%sProtocol: %s\n", prefix,
           AppLayerGetProtoName(sigmatch_table[i].alproto));
    printf("%sFeatures: ", prefix);
    PrintFeatureList(sigmatch_table[i].flags, ',');
    if (sigmatch_table[i].url) {
        printf("\n%sDocumentation: %s", prefix, sigmatch_table[i].url);
    }
    printf("\n");
}

void SigTableList(const char *keyword)
{
    size_t size = sizeof(sigmatch_table) / sizeof(SigTableElmt);
    size_t i;
    char *proto_name;

    if (keyword == NULL) {
        printf("=====Supported keywords=====\n");
        for (i = 0; i < size; i++) {
            if (sigmatch_table[i].name != NULL) {
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    printf("- %s (not built-in)\n", sigmatch_table[i].name);
                } else {
                    printf("- %s\n", sigmatch_table[i].name);
                }
            }
        }
    } else if (!strcmp("csv", keyword)) {
        printf("name;description;app layer;features;documentation\n");
        for (i = 0; i < size; i++) {
            if (sigmatch_table[i].name != NULL) {
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    continue;
                }
                printf("%s;", sigmatch_table[i].name);
                if (sigmatch_table[i].desc) {
                    printf("%s", sigmatch_table[i].desc);
                }
                /* Build feature */
                proto_name = AppLayerGetProtoName(sigmatch_table[i].alproto);
                printf(";%s;", proto_name ? proto_name : "Unset");
                PrintFeatureList(sigmatch_table[i].flags, ':');
                printf(";");
                if (sigmatch_table[i].url) {
                    printf("%s", sigmatch_table[i].url);
                }
                printf(";");
                printf("\n");
            }
        }
    } else if (!strcmp("all", keyword)) {
        for (i = 0; i < size; i++) {
            printf("%s:\n", sigmatch_table[i].name);
            SigMultilinePrint(i, "\t");
        }
    } else {
        for (i = 0; i < size; i++) {
            if ((sigmatch_table[i].name != NULL) &&
                !strcmp(sigmatch_table[i].name, keyword)) {
                printf("= %s =\n", sigmatch_table[i].name);
                if (sigmatch_table[i].flags & SIGMATCH_NOT_BUILT) {
                    printf("Not built-in\n");
                    return;
                }
                SigMultilinePrint(i, "");
                return;
            }
        }
    }
    return;
}

void SigTableSetup(void)
{
    memset(sigmatch_table, 0, sizeof(sigmatch_table));

    DetectSidRegister();
    DetectPriorityRegister();
    DetectRevRegister();
    DetectClasstypeRegister();
    DetectReferenceRegister();
    DetectTagRegister();
    DetectThresholdRegister();
    DetectMetadataRegister();
    DetectMsgRegister();
    DetectAckRegister();
    DetectSeqRegister();
    DetectContentRegister();
    DetectUricontentRegister();
    DetectPcreRegister();
    DetectDepthRegister();
    DetectNocaseRegister();
    DetectRawbytesRegister();
    DetectBytetestRegister();
    DetectBytejumpRegister();
    DetectSameipRegister();
    DetectGeoipRegister();
    DetectL3ProtoRegister();
    DetectIPProtoRegister();
    DetectWithinRegister();
    DetectDistanceRegister();
    DetectOffsetRegister();
    DetectReplaceRegister();
    DetectFlowRegister();
    DetectWindowRegister();
    DetectRpcRegister();
    DetectFtpbounceRegister();
    DetectIsdataatRegister();
    DetectIdRegister();
    DetectDsizeRegister();
    DetectFlowvarRegister();
    DetectFlowintRegister();
    DetectPktvarRegister();
    DetectNoalertRegister();
    DetectFlowbitsRegister();
    DetectHostbitsRegister();
    DetectXbitsRegister();
    DetectEngineEventRegister();
    DetectIpOptsRegister();
    DetectFlagsRegister();
    DetectFragBitsRegister();
    DetectFragOffsetRegister();
    DetectGidRegister();
    DetectMarkRegister();
    DetectCsumRegister();
    DetectStreamSizeRegister();
    DetectTtlRegister();
    DetectTosRegister();
    DetectFastPatternRegister();
    DetectITypeRegister();
    DetectICodeRegister();
    DetectIcmpIdRegister();
    DetectIcmpSeqRegister();
    DetectDceIfaceRegister();
    DetectDceOpnumRegister();
    DetectDceStubDataRegister();
    DetectHttpCookieRegister();
    DetectHttpMethodRegister();
    DetectHttpStatMsgRegister();
    DetectTlsRegister();
    DetectTlsVersionRegister();
    DetectUrilenRegister();
    DetectDetectionFilterRegister();
    DetectHttpHeaderRegister();
    DetectHttpRawHeaderRegister();
    DetectHttpClientBodyRegister();
    DetectHttpServerBodyRegister();
    DetectHttpUriRegister();
    DetectHttpRawUriRegister();
    DetectAsn1Register();
    DetectSshVersionRegister();
    DetectSshSoftwareVersionRegister();
    DetectSslStateRegister();
    DetectHttpStatCodeRegister();
    DetectSslVersionRegister();
    DetectByteExtractRegister();
    DetectFiledataRegister();
    DetectPktDataRegister();
    DetectFilenameRegister();
    DetectFileextRegister();
    DetectFilestoreRegister();
    DetectFilemagicRegister();
    DetectFileMd5Register();
    DetectFilesizeRegister();
    DetectAppLayerEventRegister();
    DetectHttpUARegister();
    DetectHttpHHRegister();
    DetectHttpHRHRegister();
    DetectLuaRegister();
    DetectIPRepRegister();
    DetectDnsQueryRegister();
    DetectModbusRegister();
    DetectAppLayerProtocolRegister();
    DetectBase64DecodeRegister();
    DetectBase64DataRegister();
    DetectTemplateRegister();
    DetectTemplateBufferRegister();
}

void SigTableRegisterTests(void)
{
    /* register the tests */
    int i = 0;
    for (i = 0; i < DETECT_TBLSIZE; i++) {
        g_ut_modules++;
        if (sigmatch_table[i].RegisterTests != NULL) {
            sigmatch_table[i].RegisterTests();
            g_ut_covered++;
        } else {
            SCLogDebug("detection plugin %s has no unittest "
                   "registration function.", sigmatch_table[i].name);

            if (coverage_unittests)
                SCLogWarning(SC_WARN_NO_UNITTESTS, "detection plugin %s has no unittest "
                        "registration function.", sigmatch_table[i].name);
        }
    }
}

/*
 * TESTS
 */

#ifdef UNITTESTS
#include "flow-util.h"
#include "stream-tcp-reassemble.h"
#include "util-var-name.h"

static const char *dummy_conf_string =
    "%YAML 1.1\n"
    "---\n"
    "\n"
    "default-log-dir: /var/log/suricata\n"
    "\n"
    "logging:\n"
    "\n"
    "  default-log-level: debug\n"
    "\n"
    "  default-format: \"<%t> - <%l>\"\n"
    "\n"
    "  default-startup-message: Your IDS has started.\n"
    "\n"
    "  default-output-filter:\n"
    "\n"
    "  output:\n"
    "\n"
    "  - interface: console\n"
    "    log-level: info\n"
    "\n"
    "  - interface: file\n"
    "    filename: /var/log/suricata.log\n"
    "\n"
    "  - interface: syslog\n"
    "    facility: local5\n"
    "    format: \"%l\"\n"
    "\n"
    "pfring:\n"
    "\n"
    "  interface: eth0\n"
    "\n"
    "  clusterid: 99\n"
    "\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[192.168.0.0/16,10.8.0.0/16,127.0.0.1,2001:888:"
    "13c5:5AFE::/64,2001:888:13c5:CAFE::/64]\"\n"
    "\n"
    "    EXTERNAL_NET: \"[!192.168.0.0/16,2000::/3]\"\n"
    "\n"
    "    HTTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SMTP_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    SQL_SERVERS: \"!192.168.0.0/16\"\n"
    "\n"
    "    DNS_SERVERS: any\n"
    "\n"
    "    TELNET_SERVERS: any\n"
    "\n"
    "    AIM_SERVERS: any\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n"
    "    SHELLCODE_PORTS: 80\n"
    "\n"
    "    ORACLE_PORTS: 1521\n"
    "\n"
    "    SSH_PORTS: 22\n"
    "\n";

static int SigTest01Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, mpm_type) == 0) {
        result = 0;
        goto end;
    }
#if 0
    //printf("URI0 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[0], p.http_uri.raw_size[0]);
    //printf("URI1 \"%s\", len %" PRIu32 "\n", p.http_uri.raw[1], p.http_uri.raw_size[1]);

    if (p->http_uri.raw_size[0] == 5 &&
        memcmp(p->http_uri.raw[0], "/one/", 5) == 0 &&
        p->http_uri.raw_size[1] == 5 &&
        memcmp(p->http_uri.raw[1], "/two/", 5) == 0)
    {
        result = 1;
    }

#endif
    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int SigTest01B2g (void)
{
    return SigTest01Real(MPM_B2G);
}
static int SigTest01B3g (void)
{
    return SigTest01Real(MPM_B3G);
}
static int SigTest01Wm (void)
{
    return SigTest01Real(MPM_WUMANBER);
}

static int SigTest02Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    char sig[] = "alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:41; sid:1;)";
    int ret = UTHPacketMatchSigMpm(p, sig, mpm_type);
    UTHFreePacket(p);
    return ret;
}

static int SigTest02B2g (void)
{
    return SigTest02Real(MPM_B2G);
}
static int SigTest02B3g (void)
{
    return SigTest02Real(MPM_B3G);
}
static int SigTest02Wm (void)
{
    return SigTest02Real(MPM_WUMANBER);
}


static int SigTest03Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:39; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest03B2g (void)
{
    return SigTest03Real(MPM_B2G);
}
static int SigTest03B3g (void)
{
    return SigTest03Real(MPM_B3G);
}
static int SigTest03Wm (void)
{
    return SigTest03Real(MPM_WUMANBER);
}


static int SigTest04Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n" /* 20*/
                    "Host: one.example.org\r\n" /* 23, post "Host:" 18 */
                    "\r\n\r\n" /* 4 */
                    "GET /two/ HTTP/1.1\r\n" /* 20 */
                    "Host: two.example.org\r\n" /* 23 */
                    "\r\n\r\n"; /* 4 */
    uint16_t buflen = strlen((char *)buf);

    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:42; within:47; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest04B2g (void)
{
    return SigTest04Real(MPM_B2G);
}
static int SigTest04B3g (void)
{
    return SigTest04Real(MPM_B3G);
}
static int SigTest04Wm (void)
{
    return SigTest04Real(MPM_WUMANBER);
}


static int SigTest05Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host:\"; offset:20; depth:25; content:\"Host:\"; distance:48; within:52; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)) {
        result = 1;
    } else {
        printf("sig matched but shouldn't have: ");
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest05B2g (void)
{
    return SigTest05Real(MPM_B2G);
}
static int SigTest05B3g (void)
{
    return SigTest05Real(MPM_B3G);
}
static int SigTest05Wm (void)
{
    return SigTest05Real(MPM_WUMANBER);
}


static int SigTest06Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;
    else
        printf("sid:1 %s, sid:2 %s: ",
            PacketAlertCheck(p, 1) ? "OK" : "FAIL",
            PacketAlertCheck(p, 2) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest06B2g (void)
{
    return SigTest06Real(MPM_B2G);
}
static int SigTest06B3g (void)
{
    return SigTest06Real(MPM_B3G);
}
static int SigTest06Wm (void)
{
    return SigTest06Real(MPM_WUMANBER);
}


static int SigTest07Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"three\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FlowCleanupAppLayer(&f);
    FLOW_DESTROY(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}
static int SigTest07B2g (void)
{
    return SigTest07Real(MPM_B2G);
}
static int SigTest07B3g (void)
{
    return SigTest07Real(MPM_B3G);
}
static int SigTest07Wm (void)
{
    return SigTest07Real(MPM_WUMANBER);
}


static int SigTest08Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&f, 0, sizeof(Flow));
    memset(&th_v, 0, sizeof(th_v));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"one\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;
    else
        printf("sid:1 %s, sid:2 %s: ",
            PacketAlertCheck(p, 1) ? "OK" : "FAIL",
            PacketAlertCheck(p, 2) ? "OK" : "FAIL");

end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest08B2g (void)
{
    return SigTest08Real(MPM_B2G);
}
static int SigTest08B3g (void)
{
    return SigTest08Real(MPM_B3G);
}
static int SigTest08Wm (void)
{
    return SigTest08Real(MPM_WUMANBER);
}


static int SigTest09Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.0\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.0\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/1\\.0\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI test\"; uricontent:\"two\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;
    else
        result = 0;

end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest09B2g (void)
{
    return SigTest09Real(MPM_B2G);
}
static int SigTest09B3g (void)
{
    return SigTest09Real(MPM_B3G);
}
static int SigTest09Wm (void)
{
    return SigTest09Real(MPM_WUMANBER);
}


static int SigTest10Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "ABC";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (1)\"; content:\"ABCD\"; depth:4; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Long content test (2)\"; content:\"VWXYZ\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);


    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

 end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest10B2g (void)
{
    return SigTest10Real(MPM_B2G);
}
static int SigTest10B3g (void)
{
    return SigTest10Real(MPM_B3G);
}
static int SigTest10Wm (void)
{
    return SigTest10Real(MPM_WUMANBER);
}


static int SigTest11Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    Flow f;
    TcpSession ssn;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (content:\"VWXYZabcde\"; content:\"5678\"; content:\"89\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) && PacketAlertCheck(p, 2))
        result = 1;

 end:
    FlowCleanupAppLayer(&f);
    SigGroupCleanup(de_ctx);
    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p, 1);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest11B2g (void)
{
    return SigTest11Real(MPM_B2G);
}
static int SigTest11B3g (void)
{
    return SigTest11Real(MPM_B3G);
}
static int SigTest11Wm (void)
{
    return SigTest11Real(MPM_WUMANBER);
}


static int SigTest12Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"klmnop\"; content:\"1234\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        result = 0;

    if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
end:
    UTHFreePackets(&p, 1);
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest12B2g (void)
{
    return SigTest12Real(MPM_B2G);
}
static int SigTest12B3g (void)
{
    return SigTest12Real(MPM_B3G);
}
static int SigTest12Wm (void)
{
    return SigTest12Real(MPM_WUMANBER);
}


static int SigTest13Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Flow f;
    memset(&f, 0, sizeof(Flow));

    FLOW_INITIALIZE(&f);

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        result = 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest13B2g (void)
{
    return SigTest13Real(MPM_B2G);
}
static int SigTest13B3g (void)
{
    return SigTest13Real(MPM_B3G);
}
static int SigTest13Wm (void)
{
    return SigTest13Real(MPM_WUMANBER);
}


static int SigTest14Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Content order test\"; content:\"ABCDEFGHIJ\"; content:\"1234\"; content:\"klmnop\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest14B2g (void)
{
    return SigTest14Real(MPM_B2G);
}
static int SigTest14B3g (void)
{
    return SigTest14Real(MPM_B3G);
}
static int SigTest14Wm (void)
{
    return SigTest14Real(MPM_WUMANBER);
}


static int SigTest15Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 80;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 2008284))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}
static int SigTest15B2g (void)
{
    return SigTest15Real(MPM_B2G);
}
static int SigTest15B3g (void)
{
    return SigTest15Real(MPM_B3G);
}
static int SigTest15Wm (void)
{
    return SigTest15Real(MPM_WUMANBER);
}


static int SigTest16Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "CONNECT 213.92.8.7:31204 HTTP/1.1";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));

    p = UTHBuildPacketSrcDstPorts((uint8_t *)buf, buflen, IPPROTO_TCP, 12345, 1234);

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any !$HTTP_PORTS (msg:\"ET POLICY Inbound HTTP CONNECT Attempt on Off-Port\"; content:\"CONNECT \"; nocase; depth:8; content:\" HTTP/1.\"; nocase; within:1000; sid:2008284; rev:2;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 2008284))
        result = 1;
    else
        printf("sid:2008284 %s: ", PacketAlertCheck(p, 2008284) ? "OK" : "FAIL");

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest16B2g (void)
{
    return SigTest16Real(MPM_B2G);
}
static int SigTest16B3g (void)
{
    return SigTest16Real(MPM_B3G);
}
static int SigTest16Wm (void)
{
    return SigTest16Real(MPM_WUMANBER);
}


static int SigTest17Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"    /* 20 */
                    "Host: one.example.org\r\n" /* 23, 43 */
                    "\r\n\r\n"                  /* 4,  47 */
                    "GET /two/ HTTP/1.1\r\n"    /* 20, 67 */
                    "Host: two.example.org\r\n" /* 23, 90 */
                    "\r\n\r\n";                 /* 4,  94 */
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketSrcDstPorts((uint8_t *)buf, buflen, IPPROTO_TCP, 12345, 80);

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; content:\"Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    PktVar *pv_hn = PktVarGet(p, "http_host");
    if (pv_hn != NULL) {
        if (memcmp(pv_hn->value, "one.example.org", pv_hn->value_len < 15 ? pv_hn->value_len : 15) == 0)
            result = 1;
        else {
            printf("\"");
            PrintRawUriFp(stdout, pv_hn->value, pv_hn->value_len);
            printf("\" != \"one.example.org\": ");
        }
        PktVarFree(pv_hn);
    } else {
        printf("Pkt var http_host not captured: ");
    }

end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    ConfDeInit();
    ConfRestoreContextBackup();
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTest17B2g (void)
{
    return SigTest17Real(MPM_B2G);
}
static int SigTest17B3g (void)
{
    return SigTest17Real(MPM_B3G);
}
static int SigTest17Wm (void)
{
    return SigTest17Real(MPM_WUMANBER);
}

static int SigTest18Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any !21:902 -> any any (msg:\"ET MALWARE Suspicious 220 Banner on Local Port\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:2003055; rev:4;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 2003055))
        result = 1;
    else
        printf("signature shouldn't match, but did: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p);
    return result;
}
static int SigTest18B2g (void)
{
    return SigTest18Real(MPM_B2G);
}
static int SigTest18B3g (void)
{
    return SigTest18Real(MPM_B3G);
}
static int SigTest18Wm (void)
{
    return SigTest18Real(MPM_WUMANBER);
}

int SigTest19Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> 1.2.3.4 any (msg:\"IP-ONLY test (1)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}
static int SigTest19B2g (void)
{
    return SigTest19Real(MPM_B2G);
}
static int SigTest19B3g (void)
{
    return SigTest19Real(MPM_B3G);
}
static int SigTest19Wm (void)
{
    return SigTest19Real(MPM_WUMANBER);
}

static int SigTest20Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> [99.99.99.99,1.2.3.0/24,1.1.1.1,3.0.0.0/8] any (msg:\"IP-ONLY test (2)\"; sid:999; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    //DetectEngineIPOnlyThreadInit(de_ctx,&det_ctx->io_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 999))
        result = 1;
    else
        printf("signature didn't match, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}
static int SigTest20B2g (void)
{
    return SigTest20Real(MPM_B2G);
}
static int SigTest20B3g (void)
{
    return SigTest20Real(MPM_B3G);
}
static int SigTest20Wm (void)
{
    return SigTest20Real(MPM_WUMANBER);
}


static int SigTest21Real (int mpm_type)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;
    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sid 2 didn't alert, but should have: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        if (det_ctx != NULL) {
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        }
    }
    DetectEngineCtxFree(de_ctx);
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest21B2g (void)
{
    return SigTest21Real(MPM_B2G);
}
static int SigTest21B3g (void)
{
    return SigTest21Real(MPM_B3G);
}
static int SigTest21Wm (void)
{
    return SigTest21Real(MPM_WUMANBER);
}


static int SigTest22Real (int mpm_type)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:set,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.abc; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2)))
        result = 1;
    else
        printf("sid 2 alerted, but shouldn't: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest22B2g (void)
{
    return SigTest22Real(MPM_B2G);
}
static int SigTest22B3g (void)
{
    return SigTest22Real(MPM_B3G);
}
static int SigTest22Wm (void)
{
    return SigTest22Real(MPM_WUMANBER);
}

static int SigTest23Real (int mpm_type)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    Flow f;
    memset(&f, 0, sizeof(f));
    FLOW_INITIALIZE(&f);

    /* packet 1 */
    uint8_t *buf1 = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf1len = strlen((char *)buf1);
    Packet *p1 = NULL;

    p1 = UTHBuildPacket((uint8_t *)buf1, buf1len, IPPROTO_TCP);
    p1->flow = &f;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    /* packet 2 */
    uint8_t *buf2 = (uint8_t *)"GET /two/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buf2len = strlen((char *)buf2);
    Packet *p2 = NULL;

    p2 = UTHBuildPacket((uint8_t *)buf2, buf2len, IPPROTO_TCP);
    p2->flow = &f;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT SET\"; content:\"/one/\"; flowbits:toggle,TEST.one; flowbits:noalert; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"FLOWBIT TEST\"; content:\"/two/\"; flowbits:isset,TEST.one; sid:2;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        printf("sid 1 alerted, but shouldn't: ");
        goto end;
    }
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result = 1;
    else
        printf("sid 2 didn't alert, but should have: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}
static int SigTest23B2g (void)
{
    return SigTest23Real(MPM_B2G);
}
static int SigTest23B3g (void)
{
    return SigTest23Real(MPM_B3G);
}
static int SigTest23Wm (void)
{
    return SigTest23Real(MPM_WUMANBER);
}

int SigTest24IPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x06};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);
    PACKET_RESET_CHECKSUMS(p1);
    PACKET_RESET_CHECKSUMS(p2);

    p1->ip4h = (IPV4Hdr *)valid_raw_ipv4;

    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    p2->ip4h = (IPV4Hdr *)invalid_raw_ipv4;

    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
            "alert ip any any -> any any "
            "(content:\"/one/\"; ipv4-csum:valid; "
            "msg:\"ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig 1 parse: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
            "alert ip any any -> any any "
            "(content:\"/one/\"; ipv4-csum:invalid; "
            "msg:\"ipv4-csum keyword check(1)\"; "
            "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        printf("sig 2 parse: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("signature 1 didn't match, but should have: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!((PacketAlertCheck(p2, 2)))) {
        printf("signature 2 didn't match, but should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest25NegativeIPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0xb7, 0x52, 0xc0, 0xa8, 0x01, 0x03,
        0xc0, 0xa8, 0x01, 0x06};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);
    PACKET_RESET_CHECKSUMS(p1);
    PACKET_RESET_CHECKSUMS(p2);

    p1->ip4h = (IPV4Hdr *)valid_raw_ipv4;

    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    p2->ip4h = (IPV4Hdr *)invalid_raw_ipv4;

    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"/one/\"; ipv4-csum:invalid; "
                               "msg:\"ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"/one/\"; ipv4-csum:valid; "
                                     "msg:\"ipv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest26TCPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0x4A, 0x04, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                               "msg:\"tcpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; "
                                     "msg:\"tcpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sig 1 didn't match: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sig 2 didn't match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

/* Test SigTest26TCPV4Keyword but also check for invalid IPV4 checksum */
static int SigTest26TCPV4AndNegativeIPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0x4A, 0x04, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                               "ipv4-csum:invalid; "
                               "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; "
                                     "ipv4-csum:invalid; "
                                     "msg:\"tcpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sig 1 didn't match: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sig 2 didn't match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

/* Similar to SigTest26, but with different packet */
static int SigTest26TCPV4AndIPV4Keyword(void)
{
    /* IPV4: src:192.168.176.67 dst: 192.168.176.116
     * TTL: 64 Flags: Don't Fragment
     */
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x40, 0x9b, 0xa4, 0x40, 0x00,
        0x40, 0x06, 0xbd, 0x0a, 0xc0, 0xa8, 0xb0, 0x43,
        0xc0, 0xa8, 0xb0, 0x74};

    /* TCP: sport: 49517 dport: 445 Flags: SYN
     * Window size: 65535, checksum: 0x2009,
     * MTU: 1460, Window scale: 4, TSACK permitted,
     * 24 bytes of options, no payload.
     */
    uint8_t valid_raw_tcp[] = {
        0xc1, 0x6d, 0x01, 0xbd, 0x03, 0x10, 0xd3, 0xc9,
        0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff,
        0x20, 0x09, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x04, 0x01, 0x01, 0x08, 0x0a,
        0x19, 0x69, 0x81, 0x7e, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00};

    uint8_t invalid_raw_tcp[] = {
        0xc1, 0x6d, 0x01, 0xbd, 0x03, 0x10, 0xd3, 0xc9,
        0x00, 0x00, 0x00, 0x00, 0xb0, 0x02, 0xff, 0xff,
        0x20, 0x09, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x01, 0x03, 0x03, 0x04, 0x01, 0x01, 0x08, 0x0a,
        0x19, 0x69, 0x81, 0x7e, 0xFF, 0xAA, 0x00, 0x00,
        0x04, 0x02, 0x00, 0x00};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;

    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20 + 24;
    p1->payload_len = 0;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20 + 24;
    p2->payload_len = 0;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(tcpv4-csum:valid; "
                               "ipv4-csum:valid; "
                               "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(tcpv4-csum:invalid; "
                                     "ipv4-csum:valid; "
                                     "msg:\"tcpv4-csum and ipv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sig 1 didn't match: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sig 2 didn't match: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

static int SigTest27NegativeTCPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x40, 0x8e, 0x7e, 0xb2,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x02};

    uint8_t invalid_raw_tcp[] = {
        0x00, 0x50, 0x8e, 0x16, 0x0d, 0x59, 0xcd, 0x3c,
        0xcf, 0x0d, 0x21, 0x80, 0x50, 0x12, 0x16, 0xa0,
        0xfa, 0x03, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4,
        0x04, 0x02, 0x08, 0x0a, 0x6e, 0x18, 0x78, 0x73,
        0x01, 0x71, 0x74, 0xde, 0x01, 0x03, 0x03, 0x03};


    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PacketCopyData(p1, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p1, GET_PKT_LEN(p1), valid_raw_tcp, sizeof(valid_raw_tcp));

    PacketCopyData(p2, raw_ipv4, sizeof(raw_ipv4));
    PacketCopyDataOffset(p2, GET_PKT_LEN(p2), invalid_raw_tcp, sizeof(invalid_raw_tcp));

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)GET_PKT_DATA(p1);
    p1->tcph = (TCPHdr *)(GET_PKT_DATA(p1) + sizeof(raw_ipv4));
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = (uint8_t *)GET_PKT_DATA(p1) + sizeof(raw_ipv4) + 20;
    p1->payload_len = 20;
    p1->proto = IPPROTO_TCP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)GET_PKT_DATA(p2);
    p2->tcph = (TCPHdr *)(GET_PKT_DATA(p2) + sizeof(raw_ipv4));
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = (uint8_t *)GET_PKT_DATA(p2) + sizeof(raw_ipv4) + 20;
    p2->payload_len = 20;
    p2->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; dsize:20; "
            "msg:\"tcpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                                     "msg:\"tcpv4-csum keyword check(2)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!PacketAlertCheck(p1, 1)) {
        printf("sig 1 didn't match on p1: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2)) {
        printf("sig 2 matched on p2: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest28TCPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xf2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x27};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xc2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x28};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->tcph = (TCPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = valid_raw_ipv6 + 54 + 20;
    p1->payload_len = 12;
    p1->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p1) != 20) {
        BUG_ON(1);
    }

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->tcph = (TCPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = invalid_raw_ipv6 + 54 + 20;;
    p2->payload_len = 12;
    p2->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p2) != 20) {
        BUG_ON(1);
    }

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"|00 01 69|\"; tcpv6-csum:valid; dsize:12; "
                               "msg:\"tcpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|00 01 69|\"; tcpv6-csum:invalid; dsize:12; "
                                     "msg:\"tcpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 1))) {
        printf("sid 1 didn't match on p1: ");
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 2))) {
        printf("sid 2 didn't match on p2: ");
        goto end;
    }

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest29NegativeTCPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xf2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x27};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd,

        0x60, 0x00, 0x00, 0x00, 0x00, 0x20, 0x06, 0x40,
        0x3f, 0xfe, 0x05, 0x07, 0x00, 0x00, 0x00, 0x01,
        0x02, 0x00, 0x86, 0xff, 0xfe, 0x05, 0x80, 0xda,
        0x3f, 0xfe, 0x05, 0x01, 0x04, 0x10, 0x00, 0x00,
        0x02, 0xc0, 0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e,

        0x03, 0xfe, 0x00, 0x16, 0xd6, 0x76, 0xf5, 0x2d,
        0x0c, 0x7a, 0x08, 0x77, 0x50, 0x10, 0x21, 0x5c,
        0xc2, 0xf1, 0x00, 0x00,

        0x01, 0x01, 0x08, 0x0a, 0x00, 0x08, 0xca, 0x5a,
        0x00, 0x01, 0x69, 0x28};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->tcph = (TCPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = valid_raw_ipv6 + 54 + 20;
    p1->payload_len = 12;
    p1->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p1) != 20) {
        BUG_ON(1);
    }

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->tcph = (TCPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = invalid_raw_ipv6 + 54 + 20;;
    p2->payload_len = 12;
    p2->proto = IPPROTO_TCP;

    if (TCP_GET_HLEN(p2) != 20) {
        BUG_ON(1);
    }

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"|00 01 69|\"; tcpv6-csum:invalid; dsize:12; "
                               "msg:\"tcpv6-csum keyword check(1)\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert tcp any any -> any any "
                                     "(content:\"|00 01 69|\"; tcpv6-csum:valid; dsize:12; "
                                     "msg:\"tcpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        goto end;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        goto end;

    result = 1;
end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest30UDPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x11, 0x00, 0x00, 0xd0, 0x43, 0xdc, 0xdc,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    uint8_t invalid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0yyyyyyyyyyyyyyyy\r\n"
                    "\r\n\r\nyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->udph = (UDPHdr *)valid_raw_udp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = sizeof(valid_raw_udp) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)raw_ipv4;
    p2->udph = (UDPHdr *)invalid_raw_udp;
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = sizeof(invalid_raw_udp) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv4-csum:valid; "
                               "msg:\"udpv4-csum keyword check(1)\"; "
                               "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv4-csum:invalid; "
                                     "msg:\"udpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 1;
    else
        result &= 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 1;
    else
        result &= 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest31NegativeUDPV4Keyword(void)
{
    uint8_t raw_ipv4[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xd0, 0x43, 0xdc, 0xdc,
        0xc0, 0xa8, 0x01, 0x03};

    uint8_t valid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x26};

    uint8_t invalid_raw_udp[] = {
        0x00, 0x35, 0xcf, 0x34, 0x00, 0x55, 0x6c, 0xe0,
        0x83, 0xfc, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x70, 0x61, 0x67,
        0x65, 0x61, 0x64, 0x32, 0x11, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0x73, 0x79, 0x6e, 0x64, 0x69,
        0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x03, 0x63,
        0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x01, 0x4b,
        0x50, 0x00, 0x12, 0x06, 0x70, 0x61, 0x67, 0x65,
        0x61, 0x64, 0x01, 0x6c, 0x06, 0x67, 0x6f, 0x6f,
        0x67, 0x6c, 0x65, 0xc0, 0x27};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0yyyyyyyyyyyyyyyy\r\n"
                    "\r\n\r\nyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy";

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->udph = (UDPHdr *)valid_raw_udp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = sizeof(valid_raw_udp) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)raw_ipv4;
    p2->udph = (UDPHdr *)invalid_raw_udp;
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = sizeof(invalid_raw_udp) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv4-csum:invalid; "
                               "msg:\"udpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv4-csum:valid; "
                                     "msg:\"udpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2)) {
        result &= 0;
    }
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}


int SigTest32UDPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP\r\n"
                    "\r\n\r\n";

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->udph = (UDPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = IPV6_GET_PLEN((p1)) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->udph = (UDPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = IPV6_GET_PLEN((p2)) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv6-csum:valid; "
                               "msg:\"udpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv6-csum:invalid; "
                                     "msg:\"udpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 1;
    else
        result &= 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 1;
    else
        result &= 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest33NegativeUDPV6Keyword(void)
{
    static uint8_t valid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x00};

    static uint8_t invalid_raw_ipv6[] = {
        0x00, 0x60, 0x97, 0x07, 0x69, 0xea, 0x00, 0x00,
        0x86, 0x05, 0x80, 0xda, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x02, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0xa0, 0x00, 0x14, 0x1a, 0xc3, 0x06, 0x02,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0x57, 0xb0,
        0x09, 0x01};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP\r\n"
                    "\r\n\r\n";

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->udph = (UDPHdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = IPV6_GET_PLEN((p1)) - UDP_HEADER_LEN;
    p1->proto = IPPROTO_UDP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->udph = (UDPHdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = IPV6_GET_PLEN((p2)) - UDP_HEADER_LEN;
    p2->proto = IPPROTO_UDP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv6-csum:invalid; "
                               "msg:\"udpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv6-csum:valid; "
                                     "msg:\"udpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest34ICMPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x38};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)(valid_raw_ipv4);
    p1->ip4h->ip_verhl = 69;
    p1->icmpv4h = (ICMPV4Hdr *) (valid_raw_ipv4 + IPV4_GET_RAW_HLEN(p1->ip4h) * 4);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)(invalid_raw_ipv4);
    p2->ip4h->ip_verhl = 69;
    p2->icmpv4h = (ICMPV4Hdr *) (invalid_raw_ipv4 + IPV4_GET_RAW_HLEN(p2->ip4h) * 4);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmp any any -> any any "
                               "(content:\"/one/\"; icmpv4-csum:valid; "
                               "msg:\"icmpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmp any any -> any any "
                                     "(content:\"/one/\"; icmpv4-csum:invalid; "
                                     "msg:\"icmpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 1;
    else
        result &= 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 1;
    else
        result &= 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest35NegativeICMPV4Keyword(void)
{
    uint8_t valid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37};

    uint8_t invalid_raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x54, 0x00, 0x00, 0x40, 0x00,
        0x40, 0x01, 0x3c, 0xa7, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0xc3, 0x01,
        0x2b, 0x36, 0x00, 0x01, 0x3f, 0x16, 0x9a, 0x4a,
        0x41, 0x63, 0x04, 0x00, 0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23,
        0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b,
        0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x38};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip4h = (IPV4Hdr *)(valid_raw_ipv4);
    p1->ip4h->ip_verhl = 69;
    p1->icmpv4h = (ICMPV4Hdr *) (valid_raw_ipv4 + IPV4_GET_RAW_HLEN(p1->ip4h) * 4);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMP;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip4h = (IPV4Hdr *)(invalid_raw_ipv4);
    p2->ip4h->ip_verhl = 69;
    p2->icmpv4h = (ICMPV4Hdr *) (invalid_raw_ipv4 + IPV4_GET_RAW_HLEN(p2->ip4h) * 4);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmp any any -> any any "
                               "(content:\"/one/\"; icmpv4-csum:invalid; "
                               "msg:\"icmpv4-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmp any any -> any any "
                                     "(content:\"/one/\"; icmpv4-csum:valid; "
                                     "msg:\"icmpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else {
        result &= 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest36ICMPV6Keyword(void)
{
    uint8_t valid_raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x00};

    uint8_t invalid_raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x01};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->icmpv6h = (ICMPV6Hdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMPV6;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->icmpv6h = (ICMPV6Hdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMPV6;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmpv6 any any -> any any "
                               "(content:\"/one/\"; icmpv6-csum:valid; "
                               "msg:\"icmpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmpv6 any any -> any any "
                                     "(content:\"/one/\"; icmpv6-csum:invalid; "
                                     "msg:\"icmpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 1;
    else
        result &= 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 1;
    else
        result &= 0;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest37NegativeICMPV6Keyword(void)
{
    uint8_t valid_raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x00};

    uint8_t invalid_raw_ipv6[] = {
        0x00, 0x00, 0x86, 0x05, 0x80, 0xda, 0x00, 0x60,
        0x97, 0x07, 0x69, 0xea, 0x86, 0xdd, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x44, 0x3a, 0x40, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x60,
        0x97, 0xff, 0xfe, 0x07, 0x69, 0xea, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x03, 0x00,
        0xf7, 0x52, 0x00, 0x00, 0x00, 0x00, 0x60, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x11, 0x01, 0x3f, 0xfe,
        0x05, 0x07, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00,
        0x86, 0xff, 0xfe, 0x05, 0x80, 0xda, 0x3f, 0xfe,
        0x05, 0x01, 0x04, 0x10, 0x00, 0x00, 0x02, 0xc0,
        0xdf, 0xff, 0xfe, 0x47, 0x03, 0x3e, 0xa0, 0x75,
        0x82, 0x9b, 0x00, 0x14, 0x82, 0x8b, 0x01, 0x01,
        0x00, 0x00, 0xf9, 0xc8, 0xe7, 0x36, 0xf5, 0xed,
        0x08, 0x01};

    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL)) {
        SCFree(p1);
        return 0;
    }
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    uint8_t *buf = (uint8_t *)"GET /one/ HTTP/1.0\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);
    memset(p2, 0, SIZE_OF_PACKET);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ip6h = (IPV6Hdr *)(valid_raw_ipv6 + 14);
    p1->icmpv6h = (ICMPV6Hdr *) (valid_raw_ipv6 + 54);
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = buf;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_ICMPV6;

    PACKET_RESET_CHECKSUMS(p2);
    p2->ip6h = (IPV6Hdr *)(invalid_raw_ipv6 + 14);
    p2->icmpv6h = (ICMPV6Hdr *) (invalid_raw_ipv6 + 54);
    p2->src.family = AF_INET;
    p2->dst.family = AF_INET;
    p2->payload = buf;
    p2->payload_len = buflen;
    p2->proto = IPPROTO_ICMPV6;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert icmpv6 any any -> any any "
                               "(content:\"/one/\"; icmpv6-csum:invalid; "
                               "msg:\"icmpv6-csum keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert icmpv6 any any -> any any "
                                     "(content:\"/one/\"; icmpv6-csum:valid; "
                                     "msg:\"icmpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1))
        result &= 0;
    else
        result &= 1;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (PacketAlertCheck(p2, 2))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p1);
    SCFree(p2);
    return result;
}

int SigTest38Real(int mpm_type)
{
    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;
    uint8_t raw_eth[] = {
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00
    };
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x7d, 0xd8, 0xf3, 0x40, 0x00,
        0x40, 0x06, 0x63, 0x85, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    uint8_t raw_tcp[] = {
        0xad, 0x22, 0x04, 0x00, 0x16, 0x39, 0x72,
        0xe2, 0x16, 0x1f, 0x79, 0x84, 0x80, 0x18,
        0x01, 0x01, 0xfe, 0x71, 0x00, 0x00, 0x01,
        0x01, 0x08, 0x0a, 0x00, 0x22, 0xaa, 0x10,
        0x00, 0x22, 0xaa, 0x10
    };
    uint8_t buf[] = {
        0x00, 0x00, 0x00, 0x08, 0x62, 0x6f, 0x6f, 0x65,
        0x65, 0x6b, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x31,
        0x20, 0x38, 0x0d, 0x0a, 0x66, 0x6f, 0x30, 0x30, /* LEN1|20| ends at 17 */
        0x30, 0x38, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x32, /* "0008" at offset 5 */
        0x20, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x0d, 0x0a, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d,
        0x0a
    };
    uint16_t ethlen = sizeof(raw_eth);
    uint16_t ipv4len = sizeof(raw_ipv4);
    uint16_t tcplen = sizeof(raw_tcp);
    uint16_t buflen = sizeof(buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);

    /* Copy raw data into packet */
    if (PacketCopyData(p1, raw_eth, ethlen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen, raw_ipv4, ipv4len) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len, raw_tcp, tcplen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len + tcplen, buf, buflen) == -1) {
        SCFree(p1);
        return 1;
    }
    SET_PKT_LEN(p1, ethlen + ipv4len + tcplen + buflen);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ethh = (EthernetHdr *)raw_eth;
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->tcph = (TCPHdr *)raw_tcp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = GET_PKT_DATA(p1) + ethlen + ipv4len + tcplen;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,0; "
                               "msg:\"byte_test keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,5,relative,string,dec; "
                               "msg:\"byte_test keyword check(2)\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 1 didn't alert, but should have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p1, 2)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 2 didn't alert, but should have: ");
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p1);
    return result;
}
static int SigTest38B2g (void)
{
    return SigTest38Real(MPM_B2G);
}
static int SigTest38B3g (void)
{
    return SigTest38Real(MPM_B3G);
}
static int SigTest38Wm (void)
{
    return SigTest38Real(MPM_WUMANBER);
}

int SigTest39Real(int mpm_type)
{
    Packet *p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;
    uint8_t raw_eth[] = {
        0x00, 0x00, 0x03, 0x04, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00
    };
    uint8_t raw_ipv4[] = {
        0x45, 0x00, 0x00, 0x7d, 0xd8, 0xf3, 0x40, 0x00,
        0x40, 0x06, 0x63, 0x85, 0x7f, 0x00, 0x00, 0x01,
        0x7f, 0x00, 0x00, 0x01
    };
    uint8_t raw_tcp[] = {
        0xad, 0x22, 0x04, 0x00, 0x16, 0x39, 0x72,
        0xe2, 0x16, 0x1f, 0x79, 0x84, 0x80, 0x18,
        0x01, 0x01, 0xfe, 0x71, 0x00, 0x00, 0x01,
        0x01, 0x08, 0x0a, 0x00, 0x22, 0xaa, 0x10,
        0x00, 0x22, 0xaa, 0x10
    };
    uint8_t buf[] = {
        0x00, 0x00, 0x00, 0x08, 0x62, 0x6f, 0x6f, 0x65,
        0x65, 0x6b, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x31,
        0x20, 0x38, 0x0d, 0x0a, 0x66, 0x30, 0x30, 0x30,
        0x38, 0x72, 0x0d, 0x0a, 0x4c, 0x45, 0x4e, 0x32,
        0x20, 0x39, 0x39, 0x4c, 0x45, 0x4e, 0x32, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39, 0x39,
        0x39, 0x39, 0x39, 0x0d, 0x0a, 0x41, 0x41, 0x41,
        0x41, 0x41, 0x41, 0x0d, 0x0a, 0x0d, 0x0a, 0x0d,
        0x0a
    };
    uint16_t ethlen = sizeof(raw_eth);
    uint16_t ipv4len = sizeof(raw_ipv4);
    uint16_t tcplen = sizeof(raw_tcp);
    uint16_t buflen = sizeof(buf);

    memset(&th_v, 0, sizeof(ThreadVars));
    memset(p1, 0, SIZE_OF_PACKET);

    /* Copy raw data into packet */
    if (PacketCopyData(p1, raw_eth, ethlen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen, raw_ipv4, ipv4len) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len, raw_tcp, tcplen) == -1) {
        SCFree(p1);
        return 1;
    }
    if (PacketCopyDataOffset(p1, ethlen + ipv4len + tcplen, buf, buflen) == -1) {
        SCFree(p1);
        return 1;
    }
    SET_PKT_LEN(p1, ethlen + ipv4len + tcplen + buflen);

    PACKET_RESET_CHECKSUMS(p1);
    p1->ethh = (EthernetHdr *)raw_eth;
    p1->ip4h = (IPV4Hdr *)raw_ipv4;
    p1->tcph = (TCPHdr *)raw_tcp;
    p1->src.family = AF_INET;
    p1->dst.family = AF_INET;
    p1->payload = GET_PKT_DATA(p1) + ethlen + ipv4len + tcplen;
    p1->payload_len = buflen;
    p1->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,0; "
                               "byte_jump:4,0; "
                               "byte_test:6,=,0x4c454e312038,0,relative; "
                               "msg:\"byte_jump keyword check(1)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result &= 0;
        goto end;
    }
    // XXX TODO
    de_ctx->sig_list->next = SigInit(de_ctx,
                               "alert tcp any any -> any any "
                               "(content:\"LEN1|20|\"; "
                               "byte_test:4,=,8,4,relative,string,dec; "
                               "byte_jump:4,4,relative,string,dec,post_offset 2; "
                               "byte_test:4,=,0x4c454e32,0,relative; "
                               "msg:\"byte_jump keyword check(2)\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result &= 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (PacketAlertCheck(p1, 1)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 1 didn't alert, but should have: ");
        goto cleanup;
    }
    if (PacketAlertCheck(p1, 2)) {
        result = 1;
    } else {
        result = 0;
        printf("sid 2 didn't alert, but should have: ");
        goto cleanup;
    }

cleanup:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

end:
    SCFree(p1);
    return result;
}
static int SigTest39B2g (void)
{
    return SigTest39Real(MPM_B2G);
}
static int SigTest39B3g (void)
{
    return SigTest39Real(MPM_B3G);
}
static int SigTest39Wm (void)
{
    return SigTest39Real(MPM_WUMANBER);
}



/**
 * \test SigTest36ContentAndIsdataatKeywords01 is a test to check window with constructed packets,
 * \brief expecting to match a size
 */

int SigTest36ContentAndIsdataatKeywords01Real (int mpm_type)
{
    int result = 0;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
   0x00,0x25,0x00,0x9e,0xfa,0xfe,0x00,0x02,0xcf,0x74,0xfe,0xe1,0x08,0x00,0x45,0x00
	,0x01,0xcc,0xcb,0x91,0x00,0x00,0x34,0x06,0xdf,0xa8,0xd1,0x55,0xe3,0x67,0xc0,0xa8
	,0x64,0x8c,0x00,0x50,0xc0,0xb7,0xd1,0x11,0xed,0x63,0x81,0xa9,0x9a,0x05,0x80,0x18
	,0x00,0x75,0x0a,0xdd,0x00,0x00,0x01,0x01,0x08,0x0a,0x09,0x8a,0x06,0xd0,0x12,0x21
	,0x2a,0x3b,0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46
	,0x6f,0x75,0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20
	,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c
	,0x65,0x2e,0x65,0x73,0x2f,0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e
	,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43
	,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78
	,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d
	,0x55,0x54,0x46,0x2d,0x38,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a,0x20,0x4d,0x6f,0x6e
	,0x2c,0x20,0x31,0x34,0x20,0x53,0x65,0x70,0x20,0x32,0x30,0x30,0x39,0x20,0x30,0x38
	,0x3a,0x34,0x38,0x3a,0x33,0x31,0x20,0x47,0x4d,0x54,0x0d,0x0a,0x53,0x65,0x72,0x76
	,0x65,0x72,0x3a,0x20,0x67,0x77,0x73,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74
	,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x32,0x31,0x38,0x0d,0x0a,0x0d,0x0a
	,0x3c,0x48,0x54,0x4d,0x4c,0x3e,0x3c,0x48,0x45,0x41,0x44,0x3e,0x3c,0x6d,0x65,0x74
	,0x61,0x20,0x68,0x74,0x74,0x70,0x2d,0x65,0x71,0x75,0x69,0x76,0x3d,0x22,0x63,0x6f
	,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x74,0x79,0x70,0x65,0x22,0x20,0x63,0x6f,0x6e,0x74
	,0x65,0x6e,0x74,0x3d,0x22,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x63
	,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x22,0x3e,0x0a,0x3c
	,0x54,0x49,0x54,0x4c,0x45,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76,0x65,0x64,0x3c
	,0x2f,0x54,0x49,0x54,0x4c,0x45,0x3e,0x3c,0x2f,0x48,0x45,0x41,0x44,0x3e,0x3c,0x42
	,0x4f,0x44,0x59,0x3e,0x0a,0x3c,0x48,0x31,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76
	,0x65,0x64,0x3c,0x2f,0x48,0x31,0x3e,0x0a,0x54,0x68,0x65,0x20,0x64,0x6f,0x63,0x75
	,0x6d,0x65,0x6e,0x74,0x20,0x68,0x61,0x73,0x20,0x6d,0x6f,0x76,0x65,0x64,0x0a,0x3c
	,0x41,0x20,0x48,0x52,0x45,0x46,0x3d,0x22,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77
	,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x65,0x73,0x2f,0x22,0x3e,0x68
	,0x65,0x72,0x65,0x3c,0x2f,0x41,0x3e,0x2e,0x0d,0x0a,0x3c,0x2f,0x42,0x4f,0x44,0x59
	,0x3e,0x3c,0x2f,0x48,0x54,0x4d,0x4c,0x3e,0x0d,0x0a };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);


    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest36ContentAndIsdataatKeywords01 \"; content:\"HTTP\"; isdataat:404, relative; sid:101;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    //PatternMatchPrepare(mpm_ctx, mpm_type);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 101) == 0) {
        result = 0;
        goto end;
    } else {
        result=1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if(de_ctx)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if(det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    //PatternMatchDestroy(mpm_ctx);

    if(de_ctx)
             DetectEngineCtxFree(de_ctx);

    if (p != NULL)
        PACKET_RECYCLE(p);

    FlowShutdown();

    SCFree(p);
    return result;
}


/**
 * \test SigTest37ContentAndIsdataatKeywords02 is a test to check window with constructed packets,
 *  \brief not expecting to match a size
 */

int SigTest37ContentAndIsdataatKeywords02Real (int mpm_type)
{
    int result = 0;

    // Buid and decode the packet

    uint8_t raw_eth [] = {
   0x00,0x25,0x00,0x9e,0xfa,0xfe,0x00,0x02,0xcf,0x74,0xfe,0xe1,0x08,0x00,0x45,0x00
	,0x01,0xcc,0xcb,0x91,0x00,0x00,0x34,0x06,0xdf,0xa8,0xd1,0x55,0xe3,0x67,0xc0,0xa8
	,0x64,0x8c,0x00,0x50,0xc0,0xb7,0xd1,0x11,0xed,0x63,0x81,0xa9,0x9a,0x05,0x80,0x18
	,0x00,0x75,0x0a,0xdd,0x00,0x00,0x01,0x01,0x08,0x0a,0x09,0x8a,0x06,0xd0,0x12,0x21
	,0x2a,0x3b,0x48,0x54,0x54,0x50,0x2f,0x31,0x2e,0x31,0x20,0x33,0x30,0x32,0x20,0x46
	,0x6f,0x75,0x6e,0x64,0x0d,0x0a,0x4c,0x6f,0x63,0x61,0x74,0x69,0x6f,0x6e,0x3a,0x20
	,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c
	,0x65,0x2e,0x65,0x73,0x2f,0x0d,0x0a,0x43,0x61,0x63,0x68,0x65,0x2d,0x43,0x6f,0x6e
	,0x74,0x72,0x6f,0x6c,0x3a,0x20,0x70,0x72,0x69,0x76,0x61,0x74,0x65,0x0d,0x0a,0x43
	,0x6f,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x54,0x79,0x70,0x65,0x3a,0x20,0x74,0x65,0x78
	,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x20,0x63,0x68,0x61,0x72,0x73,0x65,0x74,0x3d
	,0x55,0x54,0x46,0x2d,0x38,0x0d,0x0a,0x44,0x61,0x74,0x65,0x3a,0x20,0x4d,0x6f,0x6e
	,0x2c,0x20,0x31,0x34,0x20,0x53,0x65,0x70,0x20,0x32,0x30,0x30,0x39,0x20,0x30,0x38
	,0x3a,0x34,0x38,0x3a,0x33,0x31,0x20,0x47,0x4d,0x54,0x0d,0x0a,0x53,0x65,0x72,0x76
	,0x65,0x72,0x3a,0x20,0x67,0x77,0x73,0x0d,0x0a,0x43,0x6f,0x6e,0x74,0x65,0x6e,0x74
	,0x2d,0x4c,0x65,0x6e,0x67,0x74,0x68,0x3a,0x20,0x32,0x31,0x38,0x0d,0x0a,0x0d,0x0a
	,0x3c,0x48,0x54,0x4d,0x4c,0x3e,0x3c,0x48,0x45,0x41,0x44,0x3e,0x3c,0x6d,0x65,0x74
	,0x61,0x20,0x68,0x74,0x74,0x70,0x2d,0x65,0x71,0x75,0x69,0x76,0x3d,0x22,0x63,0x6f
	,0x6e,0x74,0x65,0x6e,0x74,0x2d,0x74,0x79,0x70,0x65,0x22,0x20,0x63,0x6f,0x6e,0x74
	,0x65,0x6e,0x74,0x3d,0x22,0x74,0x65,0x78,0x74,0x2f,0x68,0x74,0x6d,0x6c,0x3b,0x63
	,0x68,0x61,0x72,0x73,0x65,0x74,0x3d,0x75,0x74,0x66,0x2d,0x38,0x22,0x3e,0x0a,0x3c
	,0x54,0x49,0x54,0x4c,0x45,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76,0x65,0x64,0x3c
	,0x2f,0x54,0x49,0x54,0x4c,0x45,0x3e,0x3c,0x2f,0x48,0x45,0x41,0x44,0x3e,0x3c,0x42
	,0x4f,0x44,0x59,0x3e,0x0a,0x3c,0x48,0x31,0x3e,0x33,0x30,0x32,0x20,0x4d,0x6f,0x76
	,0x65,0x64,0x3c,0x2f,0x48,0x31,0x3e,0x0a,0x54,0x68,0x65,0x20,0x64,0x6f,0x63,0x75
	,0x6d,0x65,0x6e,0x74,0x20,0x68,0x61,0x73,0x20,0x6d,0x6f,0x76,0x65,0x64,0x0a,0x3c
	,0x41,0x20,0x48,0x52,0x45,0x46,0x3d,0x22,0x68,0x74,0x74,0x70,0x3a,0x2f,0x2f,0x77
	,0x77,0x77,0x2e,0x67,0x6f,0x6f,0x67,0x6c,0x65,0x2e,0x65,0x73,0x2f,0x22,0x3e,0x68
	,0x65,0x72,0x65,0x3c,0x2f,0x41,0x3e,0x2e,0x0d,0x0a,0x3c,0x2f,0x42,0x4f,0x44,0x59
	,0x3e,0x3c,0x2f,0x48,0x54,0x4d,0x4c,0x3e,0x0d,0x0a };

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(p, 0, SIZE_OF_PACKET);
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);


    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    Signature *s = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest37ContentAndIsdataatKeywords01 \"; content:\"HTTP\"; isdataat:500, relative; sid:101;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        result = 0;
        goto end;
    }

    if (s->sm_lists[DETECT_SM_LIST_PMATCH]->type != DETECT_CONTENT) {
        printf("type not content: ");
        goto end;
    }
/*
    if (s->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL) {
        printf("s->sm_lists[DETECT_SM_LIST_PMATCH]->next == NULL: ");
        goto end;
    }
    if (s->sm_lists[DETECT_SM_LIST_PMATCH]->next->type != DETECT_ISDATAAT) {
        printf("type not isdataat: ");
        goto end;
    }
*/
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 101) == 0) {
        result = 1;
        goto end;
    } else {
        printf("sig matched, but should not have: ");
        result=0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    PACKET_RECYCLE(p);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if(de_ctx)
    {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if(det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if(de_ctx)
        DetectEngineCtxFree(de_ctx);

    if (p != NULL)
        PACKET_RECYCLE(p);

    FlowShutdown();

    SCFree(p);
    return result;
}


// Wrapper functions to pass the mpm_type
static int SigTest36ContentAndIsdataatKeywords01B2g (void)
{
    return SigTest36ContentAndIsdataatKeywords01Real(MPM_B2G);
}
static int SigTest36ContentAndIsdataatKeywords01B3g (void)
{
    return SigTest36ContentAndIsdataatKeywords01Real(MPM_B3G);
}
static int SigTest36ContentAndIsdataatKeywords01Wm (void)
{
    return SigTest36ContentAndIsdataatKeywords01Real(MPM_WUMANBER);
}

static int SigTest37ContentAndIsdataatKeywords02B2g (void)
{
    return SigTest37ContentAndIsdataatKeywords02Real(MPM_B2G);
}
static int SigTest37ContentAndIsdataatKeywords02B3g (void)
{
    return SigTest37ContentAndIsdataatKeywords02Real(MPM_B3G);
}
static int SigTest37ContentAndIsdataatKeywords02Wm (void)
{
    return SigTest37ContentAndIsdataatKeywords02Real(MPM_WUMANBER);
}


/**
 * \test SigTest41NoPacketInspection is a test to check that when PKT_NOPACKET_INSPECTION
 *  flag is set, we don't need to inspect the packet protocol header or its contents.
 */

int SigTest40NoPacketInspection01(void)
{

    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    TCPHdr tcphdr;
    if (unlikely(p == NULL))
    return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    PacketQueue pq;
    Flow f;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    memset(&pq, 0, sizeof(pq));
    memset(&f, 0, sizeof(f));
    memset(&tcphdr, 0, sizeof(tcphdr));

    p->src.family = AF_INET;
    p->src.addr_data32[0] = UTHSetIPv4Address("192.168.0.1");
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->dp = 34260;
    p->sp = 21;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flags |= PKT_NOPACKET_INSPECTION;
    p->tcph = &tcphdr;
    p->flow = &f;

    FLOW_INITIALIZE(&f);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> 1.2.3.4 any (msg:\"No Packet Inspection Test\"; flow:to_server; sid:2; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    det_ctx->de_ctx = de_ctx;

    Detect(&th_v, p, det_ctx, &pq, NULL);
    if (PacketAlertCheck(p, 2))
        result = 0;
    else
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    //PatternMatchDestroy(mpm_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p);
    return result;
}

/**
 * \test SigTest42NoPayloadInspection is a test to check that when PKT_NOPAYLOAD_INSPECTION
 *  flasg is set, we don't need to inspect the packet contents.
 */

int SigTest40NoPayloadInspection02(void)
{

    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
    return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 1;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_NOPAYLOAD_INSPECTION;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"No Payload TEST\"; content:\"220 (vsFTPd 2.0.5)\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    if (!(de_ctx->sig_list->init_flags & SIG_FLAG_INIT_PAYLOAD))
        result = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        result &= 0;
    else
        result &= 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    SCFree(p);
    return result;
}

static int SigTestMemory01 (void)
{
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n\r\n"
                    "GET /two/ HTTP/1.1\r\n"
                    "Host: two.example.org\r\n"
                    "\r\n\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

printf("@pre cleanup\n\n");
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
    DetectPortPrintMemory();

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

printf("@exit\n\n");
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
    DetectPortPrintMemory();

    result = 1;
end:
    SCFree(p);
    return result;
}

static int SigTestMemory02 (void)
{
    ThreadVars th_v;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 456 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any 1:1000 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);

printf("@cleanup\n\n");
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

printf("@exit\n\n");
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
    DetectPortPrintMemory();
printf("@exit\n\n");
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
    DetectPortPrintMemory();

    result = 1;
end:
    return result;
}

static int SigTestMemory03 (void)
{
    ThreadVars th_v;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> 1.2.3.4 456 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> 1.2.3.3-1.2.3.6 1:1000 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert tcp any any -> !1.2.3.5 1:990 (msg:\"HTTP URI cap\"; content:\"GET \"; depth:4; pcre:\"/GET (?P<pkt_http_uri>.*) HTTP\\/\\d\\.\\d\\r\\n/G\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);

printf("@cleanup\n\n");
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

printf("@exit\n\n");
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
    DetectPortPrintMemory();

    result = 1;
end:
    return result;
}

static int SigTestSgh01 (void)
{
    ThreadVars th_v;
    int result = 0;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&th_v, 0, sizeof(th_v));

    Packet *p = NULL;
    p = UTHBuildPacketSrcDstPorts((uint8_t *)"a", 1, IPPROTO_TCP, 12345, 80);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"1\"; content:\"one\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->num != 0) {
        printf("internal id != 0: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any 81 (msg:\"2\"; content:\"two\"; content:\"abcd\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->num != 1) {
        printf("internal id != 1: ");
        goto end;
    }

    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"3\"; content:\"three\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->next->num != 2) {
        printf("internal id != 2: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }
#if 0
    printf("-\n");
    printf("sgh->mpm_content_maxlen %u\n", sgh->mpm_content_maxlen);
    printf("sgh->mpm_uricontent_maxlen %u\n", sgh->mpm_uricontent_maxlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
#endif
    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->match_array == NULL) {
        printf("sgh->match_array == NULL: ");
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have (sgh->match_array[0] %p, expected %p): ", sgh->match_array[0], de_ctx->sig_list);
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }

    p->dp = 81;

    SigGroupHead *sgh2 = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh2 == NULL) {
        printf("no sgh2: ");
        goto end;
    }
#if 0
    if (!(SigGroupHeadContainsSigId(de_ctx, sgh2, 1))) {
        printf("sgh2 doesn't have sid 1: ");
        goto end;
    }
#endif
    if (sgh2->sig_cnt != 1) {
        printf("expected one sig, got %u in sgh2: ", sgh2->sig_cnt);
        goto end;
    }

    if (sgh2->match_array[0] != de_ctx->sig_list->next) {
        printf("sgh doesn't contain sid 2, should have (sgh2->match_array[0] %p, expected %p): ",
                sgh2->match_array[0], de_ctx->sig_list->next);
        goto end;
    }

#if 0
    printf("-\n");
    printf("sgh2->mpm_content_minlen %u\n", sgh2->mpm_content_minlen);
    printf("sgh2->mpm_uricontent_minlen %u\n", sgh2->mpm_uricontent_minlen);
    printf("sgh2->sig_cnt %u\n", sgh2->sig_cnt);
    printf("sgh2->sig_size %u\n", sgh2->sig_size);
#endif
    if (sgh2->mpm_content_minlen != 4) {
        printf("sgh2->mpm_content_minlen %u, expected 4: ", sgh2->mpm_content_minlen);
        goto end;
    }

    if (sgh2->match_array[0] != de_ctx->sig_list->next) {
        printf("sgh2 doesn't contain sid 2, should have: ");
        goto end;
    }

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    return result;
}

static int SigTestSgh02 (void)
{
    ThreadVars th_v;
    int result = 0;
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;
    p = UTHBuildPacketSrcDstPorts((uint8_t *)"a", 1, IPPROTO_TCP, 12345, 80);

    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any 80:82 (msg:\"1\"; content:\"one\"; content:\"1\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->num != 0) {
        printf("internal id != 0: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any 81 (msg:\"2\"; content:\"two2\"; content:\"abcdef\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->num != 1) {
        printf("internal id != 1: ");
        goto end;
    }
    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert tcp any any -> any 80:81 (msg:\"3\"; content:\"three\"; content:\"abcdefgh\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->next->num != 2) {
        printf("internal id != 2: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->match_array == NULL) {
        printf("sgh->match_array == NULL: ");
        goto end;
    }

    if (sgh->sig_cnt != 2) {
        printf("sgh sig cnt %u, expected 2: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have (sgh->match_array[0] %p, expected %p): ", sgh->match_array[0], de_ctx->sig_list);
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->dp = 81;

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 3) {
        printf("sgh sig cnt %u, expected 3: ", sgh->sig_cnt);
        goto end;
    }
    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next) {
        printf("sgh doesn't contain sid 2, should have: ");
        goto end;
    }
    if (sgh->match_array[2] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->dp = 82;

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 1) {
        printf("sgh sig cnt %u, expected 1: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->src.family = AF_INET6;
    p->dst.family = AF_INET6;

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 1) {
        printf("sgh sig cnt %u, expected 1: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    return result;
}

static int SigTestSgh03 (void)
{
    ThreadVars th_v;
    int result = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload_len = 1;
    p->proto = IPPROTO_TCP;
    p->dp = 80;
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> 1.2.3.4-1.2.3.6 any (msg:\"1\"; content:\"one\"; content:\"1\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->num != 0) {
        printf("internal id != 0: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert ip any any -> 1.2.3.5 any (msg:\"2\"; content:\"two2\"; content:\"abcdef\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->num != 1) {
        printf("internal id != 1: ");
        goto end;
    }
    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert ip any any -> 1.2.3.4-1.2.3.5 any (msg:\"3\"; content:\"three\"; content:\"abcdefgh\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->next->num != 2) {
        printf("internal id != 2: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }
#if 0
    printf("-\n");
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->match_array == NULL) {
        printf("sgh->match_array == NULL: ");
        goto end;
    }

    if (sgh->sig_cnt != 2) {
        printf("sgh sig cnt %u, expected 2: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have (sgh->match_array[0] %p, expected %p): ", sgh->match_array[0], de_ctx->sig_list);
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }

    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.5");

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }
#if 0
    printf("-\n");
    printf("sgh %p\n", sgh);
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    if (sgh->sig_cnt != 3) {
        printf("sgh sig cnt %u, expected 3: ", sgh->sig_cnt);
        goto end;
    }
    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
    if (sgh->match_array[2] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3 (%x): ", sgh->mpm_content_minlen, p->dst.addr_data32[0]);
        goto end;
    }


    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.6");

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }
#if 0
    printf("-\n");
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 1) {
        printf("sgh sig cnt %u, expected 1: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    SCFree(p);
    return result;
}

static int SigTestSgh04 (void)
{
    ThreadVars th_v;
    int result = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload_len = 1;
    p->proto = IPPROTO_TCP;
    p->dp = 80;
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> 1.2.3.4-1.2.3.6 any (msg:\"1\"; content:\"one\"; content:\"1\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->num != 0) {
        printf("internal id != 0: ");
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert ip any any -> 1.2.3.5 any (msg:\"2\"; content:\"two2\"; content:\"abcdef\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->num != 1) {
        printf("internal id != 1: ");
        goto end;
    }
    de_ctx->sig_list->next->next = SigInit(de_ctx,"alert ip any any -> 1.2.3.4-1.2.3.5 any (msg:\"3\"; content:\"three\"; content:\"abcdefgh\"; sid:3;)");
    if (de_ctx->sig_list->next->next == NULL) {
        result = 0;
        goto end;
    }
    if (de_ctx->sig_list->next->next->num != 2) {
        printf("internal id != 2: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->match_array == NULL) {
        printf("sgh->match_array == NULL: ");
        goto end;
    }

    if (sgh->sig_cnt != 2) {
        printf("sgh sig cnt %u, expected 2: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have (sgh->match_array[0] %p, expected %p): ", sgh->match_array[0], de_ctx->sig_list);
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.5");

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 3) {
        printf("sgh sig cnt %u, expected 3: ", sgh->sig_cnt);
        goto end;
    }
    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
    if (sgh->match_array[1] != de_ctx->sig_list->next) {
        printf("sgh doesn't contain sid 2, should have: ");
        goto end;
    }
    if (sgh->match_array[2] != de_ctx->sig_list->next->next) {
        printf("sgh doesn't contain sid 3, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.6");

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->sig_cnt != 1) {
        printf("sgh sig cnt %u, expected 1: ", sgh->sig_cnt);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }
#if 0
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    p->proto = IPPROTO_GRE;

    sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }
#if 0
    printf("-\n");
    printf("sgh->mpm_content_minlen %u\n", sgh->mpm_content_minlen);
    printf("sgh->mpm_uricontent_minlen %u\n", sgh->mpm_uricontent_minlen);
    printf("sgh->sig_cnt %u\n", sgh->sig_cnt);
    printf("sgh->sig_size %u\n", sgh->sig_size);
    printf("sgh->refcnt %u\n", sgh->refcnt);
#endif
    if (sgh->mpm_content_minlen != 3) {
        printf("sgh->mpm_content_minlen %u, expected 3: ", sgh->mpm_content_minlen);
        goto end;
    }

    if (sgh->match_array[0] != de_ctx->sig_list) {
        printf("sgh doesn't contain sid 1, should have: ");
        goto end;
    }

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    SCFree(p);
    return result;
}

/** \test setting of mpm type */
static int SigTestSgh05 (void)
{
    ThreadVars th_v;
    int result = 0;
    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));
    memset(p, 0, SIZE_OF_PACKET);
    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload_len = 1;
    p->proto = IPPROTO_TCP;
    p->dp = 80;
    p->dst.addr_data32[0] = UTHSetIPv4Address("1.2.3.4");

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;
    de_ctx->mpm_matcher = MPM_WUMANBER;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> 1.2.3.4-1.2.3.6 any (msg:\"1\"; content:\"one\"; content:\"1\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigGroupHead *sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
    if (sgh == NULL) {
        printf("no sgh: ");
        goto end;
    }

    if (sgh->mpm_proto_tcp_ctx_ts != NULL || sgh->mpm_proto_tcp_ctx_tc != NULL ||
        sgh->mpm_proto_udp_ctx_ts != NULL || sgh->mpm_proto_udp_ctx_tc != NULL ||
        sgh->mpm_proto_other_ctx != NULL) {
        printf("sgh->mpm_proto_tcp_ctx_ts != NULL || sgh->mpm_proto_tcp_ctx_tc != NULL"
               "sgh->mpm_proto_udp_ctx_ts != NULL || sgh->mpm_proto_udp_ctx_tc != NULL"
               "sgh->mpm_proto_other_ctx != NULL: ");
        goto end;
    }

    if (sgh->mpm_stream_ctx_ts == NULL || sgh->mpm_stream_ctx_tc == NULL) {
        printf("sgh->mpm_stream_ctx == NULL || sgh->mpm_stream_ctx_tc == NULL: ");
        goto end;
    }

    if (sgh->mpm_stream_ctx_ts->mpm_type != MPM_WUMANBER) {
        printf("sgh->mpm_type != MPM_WUMANBER, expected %d, got %d: ", MPM_WUMANBER, sgh->mpm_stream_ctx_ts->mpm_type);
        goto end;
    }

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    SCFree(p);
    return result;
}

static int SigTestContent01Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestContent01B2g (void)
{
    return SigTestContent01Real(MPM_B2G);
}
static int SigTestContent01B3g (void)
{
    return SigTestContent01Real(MPM_B3G);
}
static int SigTestContent01Wm (void)
{
    return SigTestContent01Real(MPM_WUMANBER);
}

static int SigTestContent02Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 31\"; content:\"0123456789012345678901234567890\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)) {
        if (PacketAlertCheck(p, 2)) {
            result = 1;
        } else
            printf("sig 2 didn't match: ");
    }
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestContent02B2g (void)
{
    return SigTestContent02Real(MPM_B2G);
}
static int SigTestContent02B3g (void)
{
    return SigTestContent02Real(MPM_B3G);
}
static int SigTestContent02Wm (void)
{
    return SigTestContent02Real(MPM_WUMANBER);
}

static int SigTestContent03Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestContent03B2g (void)
{
    return SigTestContent03Real(MPM_B2G);
}
static int SigTestContent03B3g (void)
{
    return SigTestContent03Real(MPM_B3G);
}
static int SigTestContent03Wm (void)
{
    return SigTestContent03Real(MPM_WUMANBER);
}

static int SigTestContent04Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;
    else
        printf("sig 1 didn't match: ");

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestContent04B2g (void)
{
    return SigTestContent04Real(MPM_B2G);
}
static int SigTestContent04B3g (void)
{
    return SigTestContent04Real(MPM_B3G);
}
static int SigTestContent04Wm (void)
{
    return SigTestContent04Real(MPM_WUMANBER);
}

/** \test sigs with patterns at the limit of the pm's size limit */
static int SigTestContent05Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901PADabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        printf("de_ctx == NULL: ");
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig1 parse failed: ");
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Test 32\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:1; within:32; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        printf("sig2 parse failed: ");
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't: ");
        goto end;
    }

    if (PacketAlertCheck(p, 2)) {
        printf("sig 2 matched but shouldn't: ");
        goto end;
    }

    result = 1;
end:
    UTHFreePackets(&p, 1);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    }
    if (de_ctx != NULL) {
        DetectEngineCtxFree(de_ctx);
    }
    return result;
}
static int SigTestContent05B2g (void)
{
    return SigTestContent05Real(MPM_B2G);
}
static int SigTestContent05B3g (void)
{
    return SigTestContent05Real(MPM_B3G);
}
static int SigTestContent05Wm (void)
{
    return SigTestContent05Real(MPM_WUMANBER);
}

static int SigTestContent06Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    Packet *p = NULL;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Test 32 sig1\"; content:\"01234567890123456789012345678901\"; content:\"abcdefghijklmnopqrstuvwxyzABCDEF\"; distance:0; within:32; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    de_ctx->sig_list->next = SigInit(de_ctx,"alert ip any any -> any any (msg:\"Test 32 sig2\"; content:\"01234567890123456789012345678901\"; content:\"abcdefg\"; sid:2;)");
    if (de_ctx->sig_list->next == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1)){
        //printf("sig 1 matched :");
    }else{
        printf("sig 1 didn't match: ");
        goto end;
    }

    if (PacketAlertCheck(p, 2)){
        result = 1;
    }else{
        printf("sig 2 didn't match: ");
        goto end;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestContent06B2g (void)
{
    return SigTestContent06Real(MPM_B2G);
}
static int SigTestContent06B3g (void)
{
    return SigTestContent06Real(MPM_B3G);
}
static int SigTestContent06Wm (void)
{
    return SigTestContent06Real(MPM_WUMANBER);
}

static int SigTestWithinReal01 (int mpm_type)
{
    DecodeThreadVars dtv;
    ThreadVars th_v;
    int result = 0;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Packet *p3 = NULL;
    Packet *p4 = NULL;

    uint8_t rawpkt1[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x95,0x50,0x00,0x00,0x40,0x06,
        0x2d,0x45,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcc,0x03,0x09,0x18,0x72,
        0xd0,0xe3,0x1a,0xab,0x7c,0x98,0x50,0x00,
        0x02,0x00,0x46,0xa0,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt1 */

    uint8_t rawpkt2[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x30,0x87,0x00,0x00,0x40,0x06,
        0x92,0x0e,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcd,0x03,0x09,0x73,0xec,
        0xd5,0x35,0x14,0x7d,0x7c,0x12,0x50,0x00,
        0x02,0x00,0xed,0x86,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt2 */

    uint8_t rawpkt3[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0x57,0xd8,0x00,0x00,0x40,0x06,
        0x6a,0xbd,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xce,0x03,0x09,0x06,0x3d,
        0x02,0x22,0x2f,0x9b,0x6f,0x8f,0x50,0x00,
        0x02,0x00,0x1f,0xae,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt3 */

    uint8_t rawpkt4[] = {
        0x00,0x04,0x76,0xd3,0xd8,0x6a,0x00,0x24,
        0xe8,0x29,0xfa,0x4f,0x08,0x00,0x45,0x00,
        0x00,0x8c,0xa7,0x2e,0x00,0x00,0x40,0x06,
        0x1b,0x67,0xc0,0xa8,0x02,0x03,0xd0,0x45,
        0x24,0xe6,0x06,0xcf,0x03,0x09,0x00,0x0e,
        0xdf,0x72,0x3d,0xc2,0x21,0xce,0x50,0x00,
        0x02,0x00,0x88,0x25,0x00,0x00,0x48,0x69,
        0x2c,0x20,0x74,0x68,0x69,0x73,0x20,0x69,
        0x73,0x20,0x61,0x20,0x62,0x69,0x67,0x20,
        0x74,0x65,0x73,0x74,0x20,0x74,0x6f,0x20,
        0x63,0x68,0x65,0x63,0x6b,0x20,0x63,0x6f,
        0x6e,0x74,0x65,0x6e,0x74,0x20,0x6d,0x61,
        0x74,0x63,0x68,0x65,0x73,0x0a,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
        0x00,0x00 }; /* end rawpkt4 */

    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;

    FlowInitConfig(FLOW_QUIET);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"within test\"; content:\"Hi, this is a big test to check \"; content:\"content matches\"; distance:0; within:15; sid:556;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* packet 1 */
    p1 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p1 == NULL))
        return 0;
    memset(p1, 0, SIZE_OF_PACKET);
    DecodeEthernet(&th_v, &dtv, p1, rawpkt1, sizeof(rawpkt1), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if (!(PacketAlertCheck(p1, 556))) {
        printf("failed to match on packet 1: ");
        goto end;
    }

    /* packet 2 */
    p2 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p2 == NULL))
        return 0;
    memset(p2, 0, SIZE_OF_PACKET);
    DecodeEthernet(&th_v, &dtv, p2, rawpkt2, sizeof(rawpkt2), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    if (!(PacketAlertCheck(p2, 556))) {
        printf("failed to match on packet 2: ");
        goto end;
    }

    /* packet 3 */
    p3 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p3 == NULL))
        return 0;
    memset(p3, 0, SIZE_OF_PACKET);
    DecodeEthernet(&th_v, &dtv, p3, rawpkt3, sizeof(rawpkt3), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    if (!(PacketAlertCheck(p3, 556))) {
        printf("failed to match on packet 3: ");
        goto end;
    }

    /* packet 4 */
    p4 = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p4 == NULL))
        return 0;
    memset(p4, 0, SIZE_OF_PACKET);
    DecodeEthernet(&th_v, &dtv, p4, rawpkt4, sizeof(rawpkt4), NULL);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p4);
    if (!(PacketAlertCheck(p4, 556))) {
        printf("failed to match on packet 4: ");
        goto end;
    }

    /* packet 5 */
    uint8_t *p5buf = (uint8_t *)"Hi, this is a big test to check content matches";
    uint16_t p5buflen = strlen((char *)p5buf);
    Packet *p5 = UTHBuildPacket(p5buf, p5buflen, IPPROTO_TCP);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p5);
    if (!(PacketAlertCheck(p5, 556))) {
        printf("failed to match on packet 5: ");
        goto end;
    }
    UTHFreePackets(&p5, 1);

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    if (p1 != NULL) {
        PACKET_RECYCLE(p1);
        SCFree(p1);
    }
    if (p2 != NULL) {
        PACKET_RECYCLE(p2);
        SCFree(p2);
    }
    if (p3 != NULL) {
        PACKET_RECYCLE(p3);
        SCFree(p3);
    }
    if (p4 != NULL) {
        PACKET_RECYCLE(p4);
        SCFree(p4);
    }
    FlowShutdown();
    return result;
}

static int SigTestWithinReal01B2g (void)
{
    return SigTestWithinReal01(MPM_B2G);
}
static int SigTestWithinReal01B3g (void)
{
    return SigTestWithinReal01(MPM_B3G);
}
static int SigTestWithinReal01Wm (void)
{
    return SigTestWithinReal01(MPM_WUMANBER);
}

static int SigTestDepthOffset01Real (int mpm_type)
{
    uint8_t *buf = (uint8_t *)"01234567890123456789012345678901abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_type;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"depth offset\"; content:\"456\"; offset:4; depth:3; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1))
        result = 1;

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p, 1);
    return result;
}
static int SigTestDepthOffset01B2g (void)
{
    return SigTestDepthOffset01Real(MPM_B2G);
}
static int SigTestDepthOffset01B3g (void)
{
    return SigTestDepthOffset01Real(MPM_B3G);
}
static int SigTestDepthOffset01Wm (void)
{
    return SigTestDepthOffset01Real(MPM_WUMANBER);
}

static int SigTestDetectAlertCounter(void)
{
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&tv, 0, sizeof(tv));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"Test counter\"; "
                               "content:\"boo\"; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    tv.name = "detect_test";
    DetectEngineThreadCtxInit(&tv, de_ctx, (void *)&det_ctx);

    /* init counters */
    StatsSetupPrivate(&tv);

    p = UTHBuildPacket((uint8_t *)"boo", strlen("boo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    result = (StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 1);

    Detect(&tv, p, det_ctx, NULL, NULL);
    result &= (StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"roo", strlen("roo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    result &= (StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"laboosa", strlen("laboosa"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    result &= (StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 3);
    UTHFreePackets(&p, 1);

end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode */
static int SigTestDropFlow01(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop http any any -> any any "
                                   "(msg:\"Test proto match\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    if ( !(p->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Ok, now we know that the flag is set for proto http */

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode */
static int SigTestDropFlow02(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;
    TcpSession ssn;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't alert, but it should: ");
        goto end;
    }

    if ( !(p->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Ok, now we know that the flag is set for app layer sigs
     * (ex: inspecting uricontent) */

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p, 1);
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IPS mode, and it doesn't inspect
 *        any other packet of the stream */
static int SigTestDropFlow03(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;

    uint8_t http_buf2[] = "POST /two HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf1) - 1;

    /* Set the engine mode to IPS */
    EngineModeSetIPS();

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    /* the no inspection flag should be set after the first sig gets triggered,
     * so the second packet should not match the next sig (because of no inspection) */
    s = de_ctx->sig_list->next = SigInit(de_ctx, "alert tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"two\";"
                                   "sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!PacketAlertCheck(p1, 1)) {
        printf("sig 1 didn't alert on p1, but it should: ");
        goto end;
    }

    if ( !(p1->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    /* Second part.. Let's feed with another packet */
    if (StreamTcpCheckFlowDrops(p2) == 1) {
        SCLogDebug("This flow/stream triggered a drop rule");
        FlowSetNoPacketInspectionFlag(p2->flow);
        DecodeSetNoPacketInspectionFlag(p2);
        StreamTcpDisableAppLayer(p2->flow);
        p2->action |= ACTION_DROP;
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p2);
    }


    if ( !(p2->flags & PKT_NOPACKET_INSPECTION)) {
        printf("The packet was not flagged with no-inspection: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sig 1 alerted, but it should not since the no pkt inspection should be set: ");
        goto end;
    }

    if (PacketAlertCheck(p2, 2)) {
        printf("sig 2 alerted, but it should not since the no pkt inspection should be set: ");
        goto end;
    }

    if ( !(PACKET_TEST_ACTION(p2, ACTION_DROP))) {
        printf("A \"drop\" action should be set from the flow to the packet: ");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);

    /* Restore mode to IDS */
    EngineModeSetIDS();
    return result;
}

/** \test test if the engine set flag to drop pkts of a flow that
 *        triggered a drop action on IDS mode, but continue the inspection
 *        as usual (instead of on IPS mode) */
static int SigTestDropFlow04(void)
{
    int result = 0;
    Flow f;
    HtpState *http_state = NULL;
    uint8_t http_buf1[] = "POST /one HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf1_len = sizeof(http_buf1) - 1;

    uint8_t http_buf2[] = "POST /two HTTP/1.0\r\n"
        "User-Agent: Mozilla/1.0\r\n"
        "Cookie: hellocatch\r\n\r\n";
    uint32_t http_buf2_len = sizeof(http_buf1) - 1;

    TcpSession ssn;
    Packet *p1 = NULL;
    Packet *p2 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));
    memset(&ssn, 0, sizeof(TcpSession));

    p1 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);
    p2 = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    f.flags |= FLOW_IPV4;

    p1->flow = &f;
    p1->flowflags |= FLOW_PKT_TOSERVER;
    p1->flowflags |= FLOW_PKT_ESTABLISHED;
    p1->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;

    p2->flow = &f;
    p2->flowflags |= FLOW_PKT_TOSERVER;
    p2->flowflags |= FLOW_PKT_ESTABLISHED;
    p2->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_HTTP;

    StreamTcpInitConfig(TRUE);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    /* the no inspection flag should be set after the first sig gets triggered,
     * so the second packet should not match the next sig (because of no inspection) */
    s = de_ctx->sig_list->next = SigInit(de_ctx, "alert tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"two\";"
                                   "sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    SCMutexLock(&f.m);
    int r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    http_state = f.alstate;
    if (http_state == NULL) {
        printf("no http state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (!PacketAlertCheck(p1, 1)) {
        printf("sig 1 didn't alert on p1, but it should: ");
        goto end;
    }

    if (PacketAlertCheck(p1, 2)) {
        printf("sig 2 alerted on p1, but it should not: ");
        goto end;
    }

    if ( !(p1->flow->flags & FLOW_ACTION_DROP)) {
        printf("sig 1 alerted but flow was not flagged correctly: ");
        goto end;
    }

    if (!(PACKET_TEST_ACTION(p1, ACTION_DROP))) {
        printf("A \"drop\" action was set from the flow to the packet "
               "which is right, but setting the flag shouldn't disable "
               "inspection on the packet in IDS mode");
        goto end;
    }

    /* Second part.. Let's feed with another packet */
    if (StreamTcpCheckFlowDrops(p2) == 1) {
        FlowSetNoPacketInspectionFlag(p2->flow);
        DecodeSetNoPacketInspectionFlag(p2);
        StreamTcpDisableAppLayer(p2->flow);
        p2->action |= ACTION_DROP;
        /* return the segments to the pool */
        StreamTcpSessionPktFree(p2);
    }

    if ( (p2->flags & PKT_NOPACKET_INSPECTION)) {
        printf("The packet was flagged with no-inspection but we are not on IPS mode: ");
        goto end;
    }

    SCMutexLock(&f.m);
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_HTTP, STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        SCMutexUnlock(&f.m);
        goto end;
    }
    SCMutexUnlock(&f.m);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p2);

    if (PacketAlertCheck(p2, 1)) {
        printf("sig 1 alerted, but it should not: ");
        goto end;
    }

    if (!PacketAlertCheck(p2, 2)) {
        printf("sig 2 didn't alert, but it should, since we are not on IPS mode: ");
        goto end;
    }

    if (!(PACKET_TEST_ACTION(p2, ACTION_DROP))) {
        printf("A \"drop\" action was set from the flow to the packet "
               "which is right, but setting the flag shouldn't disable "
               "inspection on the packet in IDS mode");
        goto end;
    }

    result = 1;

end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);

    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);

    return result;
}

/** \test ICMP packet shouldn't be matching port based sig
 *        Bug #611 */
static int SigTestPorts01(void)
{
    int result = 0;
    Packet *p1 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    uint8_t payload[] = "AAAAAAAAAAAAAAAAAA";

    memset(&tv, 0, sizeof(ThreadVars));

    p1 = UTHBuildPacket(payload, sizeof(payload), IPPROTO_ICMP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->mpm_matcher = MPM_B2G;
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "alert ip any any -> any 80 "
                                   "(content:\"AAA\"; sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sig 1 alerted on p1, but it should not: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    return result;
}

/** \test almost identical patterns */
static int SigTestBug01(void)
{
    int result = 0;
    Packet *p1 = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    uint8_t payload[] = "!mymy";

    memset(&tv, 0, sizeof(ThreadVars));

    p1 = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                   "(content:\"Omymy\"; nocase; sid:1;)");
    if (s == NULL) {
        goto end;
    }
    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                   "(content:\"!mymy\"; nocase; sid:2;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p1);

    if (PacketAlertCheck(p1, 1)) {
        printf("sig 1 alerted on p1, but it should not: ");
        goto end;
    }
    if (!(PacketAlertCheck(p1, 2))) {
        printf("sig 2 did not p1, but it should have: ");
        goto end;
    }

    result = 1;
end:
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    if (de_ctx != NULL)
        SigGroupCleanup(de_ctx);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    UTHFreePackets(&p1, 1);
    return result;
}

static const char *dummy_conf_string2 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24, !10.10.10.247]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing01 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string2, strlen(dummy_conf_string2));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string3 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24, !10.10.10.247/32]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing02 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string3, strlen(dummy_conf_string3));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string4 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.10.10.0/24,       !10.10.10.247/32]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

static int DetectAddressYamlParsing03 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string4, strlen(dummy_conf_string4));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}

static const char *dummy_conf_string5 =
    "%YAML 1.1\n"
    "---\n"
    "vars:\n"
    "\n"
    "  address-groups:\n"
    "\n"
    "    HOME_NET: \"[10.196.0.0/24, !10.196.0.15]\"\n"
    "\n"
    "    EXTERNAL_NET: \"any\"\n"
    "\n"
    "  port-groups:\n"
    "\n"
    "    HTTP_PORTS: \"80:81,88\"\n"
    "\n";

/** \test bug #815 */
static int DetectAddressYamlParsing04 (void)
{
    int result = 0;

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string5, strlen(dummy_conf_string5));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->flags |= DE_QUIET;

    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> any any (sid:1;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp any any -> $HOME_NET any (sid:2;)")) == NULL)
        goto end;
    if ((DetectEngineAppendSig(de_ctx, "alert tcp $HOME_NET any -> $HOME_NET any (sid:3;)")) == NULL)
        goto end;

    result = 1;

    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    return result;
}
#endif /* UNITTESTS */

void SigRegisterTests(void)
{
#ifdef UNITTESTS
    SigParseRegisterTests();
    IPOnlyRegisterTests();

    UtRegisterTest("SigTest01B2g -- HTTP URI cap", SigTest01B2g, 1);
    UtRegisterTest("SigTest01B3g -- HTTP URI cap", SigTest01B3g, 1);
    UtRegisterTest("SigTest01Wm -- HTTP URI cap", SigTest01Wm, 1);

    UtRegisterTest("SigTest02B2g -- Offset/Depth match", SigTest02B2g, 1);
    UtRegisterTest("SigTest02B3g -- Offset/Depth match", SigTest02B3g, 1);
    UtRegisterTest("SigTest02Wm -- Offset/Depth match", SigTest02Wm, 1);

    UtRegisterTest("SigTest03B2g -- offset/depth mismatch", SigTest03B2g, 1);
    UtRegisterTest("SigTest03B3g -- offset/depth mismatch", SigTest03B3g, 1);
    UtRegisterTest("SigTest03Wm -- offset/depth mismatch", SigTest03Wm, 1);

    UtRegisterTest("SigTest04B2g -- distance/within match", SigTest04B2g, 1);
    UtRegisterTest("SigTest04B3g -- distance/within match", SigTest04B3g, 1);
    UtRegisterTest("SigTest04Wm -- distance/within match", SigTest04Wm, 1);

    UtRegisterTest("SigTest05B2g -- distance/within mismatch", SigTest05B2g, 1);
    UtRegisterTest("SigTest05B3g -- distance/within mismatch", SigTest05B3g, 1);
    UtRegisterTest("SigTest05Wm -- distance/within mismatch", SigTest05Wm, 1);

    UtRegisterTest("SigTest06B2g -- uricontent HTTP/1.1 match test", SigTest06B2g, 1);
    UtRegisterTest("SigTest06B3g -- uricontent HTTP/1.1 match test", SigTest06B3g, 1);
    UtRegisterTest("SigTest06wm -- uricontent HTTP/1.1 match test", SigTest06Wm, 1);

    UtRegisterTest("SigTest07B2g -- uricontent HTTP/1.1 mismatch test", SigTest07B2g, 1);
    UtRegisterTest("SigTest07B3g -- uricontent HTTP/1.1 mismatch test", SigTest07B3g, 1);
    UtRegisterTest("SigTest07Wm -- uricontent HTTP/1.1 mismatch test", SigTest07Wm, 1);

    UtRegisterTest("SigTest08B2g -- uricontent HTTP/1.0 match test", SigTest08B2g, 1);
    UtRegisterTest("SigTest08B3g -- uricontent HTTP/1.0 match test", SigTest08B3g, 1);
    UtRegisterTest("SigTest08Wm -- uricontent HTTP/1.0 match test", SigTest08Wm, 1);

    UtRegisterTest("SigTest09B2g -- uricontent HTTP/1.0 mismatch test", SigTest09B2g, 1);
    UtRegisterTest("SigTest09B3g -- uricontent HTTP/1.0 mismatch test", SigTest09B3g, 1);
    UtRegisterTest("SigTest09Wm -- uricontent HTTP/1.0 mismatch test", SigTest09Wm, 1);

    UtRegisterTest("SigTest10B2g -- long content match, longer than pkt", SigTest10B2g, 1);
    UtRegisterTest("SigTest10B3g -- long content match, longer than pkt", SigTest10B3g, 1);
    UtRegisterTest("SigTest10Wm -- long content match, longer than pkt", SigTest10Wm, 1);

    UtRegisterTest("SigTest11B2g -- mpm searching", SigTest11B2g, 1);
    UtRegisterTest("SigTest11B3g -- mpm searching", SigTest11B3g, 1);
    UtRegisterTest("SigTest11Wm -- mpm searching", SigTest11Wm, 1);

    UtRegisterTest("SigTest12B2g -- content order matching, normal", SigTest12B2g, 1);
    UtRegisterTest("SigTest12B3g -- content order matching, normal", SigTest12B3g, 1);
    UtRegisterTest("SigTest12Wm -- content order matching, normal", SigTest12Wm, 1);

    UtRegisterTest("SigTest13B2g -- content order matching, diff order", SigTest13B2g, 1);
    UtRegisterTest("SigTest13B3g -- content order matching, diff order", SigTest13B3g, 1);
    UtRegisterTest("SigTest13Wm -- content order matching, diff order", SigTest13Wm, 1);

    UtRegisterTest("SigTest14B2g -- content order matching, distance 0", SigTest14B2g, 1);
    UtRegisterTest("SigTest14B3g -- content order matching, distance 0", SigTest14B3g, 1);
    UtRegisterTest("SigTest14Wm -- content order matching, distance 0", SigTest14Wm, 1);

    UtRegisterTest("SigTest15B2g -- port negation sig (no match)", SigTest15B2g, 1);
    UtRegisterTest("SigTest15B3g -- port negation sig (no match)", SigTest15B3g, 1);
    UtRegisterTest("SigTest15Wm -- port negation sig (no match)", SigTest15Wm, 1);

    UtRegisterTest("SigTest16B2g -- port negation sig (match)", SigTest16B2g, 1);
    UtRegisterTest("SigTest16B3g -- port negation sig (match)", SigTest16B3g, 1);
    UtRegisterTest("SigTest16Wm -- port negation sig (match)", SigTest16Wm, 1);

    UtRegisterTest("SigTest17B2g -- HTTP Host Pkt var capture", SigTest17B2g, 1);
    UtRegisterTest("SigTest17B3g -- HTTP Host Pkt var capture", SigTest17B3g, 1);
    UtRegisterTest("SigTest17Wm -- HTTP Host Pkt var capture", SigTest17Wm, 1);

    UtRegisterTest("SigTest18B2g -- Ftp negation sig test", SigTest18B2g, 1);
    UtRegisterTest("SigTest18B3g -- Ftp negation sig test", SigTest18B3g, 1);
    UtRegisterTest("SigTest18Wm -- Ftp negation sig test", SigTest18Wm, 1);

    UtRegisterTest("SigTest19B2g -- IP-ONLY test (1)", SigTest19B2g, 1);
    UtRegisterTest("SigTest19B3g -- IP-ONLY test (1)", SigTest19B3g, 1);
    UtRegisterTest("SigTest19Wm -- IP-ONLY test (1)", SigTest19Wm, 1);

    UtRegisterTest("SigTest20B2g -- IP-ONLY test (2)", SigTest20B2g, 1);
    UtRegisterTest("SigTest20B3g -- IP-ONLY test (2)", SigTest20B3g, 1);
    UtRegisterTest("SigTest20Wm -- IP-ONLY test (2)", SigTest20Wm, 1);

    UtRegisterTest("SigTest21B2g -- FLOWBIT test (1)", SigTest21B2g, 1);
    UtRegisterTest("SigTest21B3g -- FLOWBIT test (1)", SigTest21B3g, 1);
    UtRegisterTest("SigTest21Wm -- FLOWBIT test (1)", SigTest21Wm, 1);

    UtRegisterTest("SigTest22B2g -- FLOWBIT test (2)", SigTest22B2g, 1);
    UtRegisterTest("SigTest22B3g -- FLOWBIT test (2)", SigTest22B3g, 1);
    UtRegisterTest("SigTest22Wm -- FLOWBIT test (2)", SigTest22Wm, 1);

    UtRegisterTest("SigTest23B2g -- FLOWBIT test (3)", SigTest23B2g, 1);
    UtRegisterTest("SigTest23B3g -- FLOWBIT test (3)", SigTest23B3g, 1);
    UtRegisterTest("SigTest23Wm -- FLOWBIT test (3)", SigTest23Wm, 1);

    UtRegisterTest("SigTest24IPV4Keyword", SigTest24IPV4Keyword, 1);
    UtRegisterTest("SigTest25NegativeIPV4Keyword",
                   SigTest25NegativeIPV4Keyword, 1);

    UtRegisterTest("SigTest26TCPV4Keyword", SigTest26TCPV4Keyword, 1);
    UtRegisterTest("SigTest26TCPV4AndNegativeIPV4Keyword", SigTest26TCPV4AndNegativeIPV4Keyword, 1);
    UtRegisterTest("SigTest26TCPV4AndIPV4Keyword", SigTest26TCPV4AndIPV4Keyword, 1);
    UtRegisterTest("SigTest27NegativeTCPV4Keyword",
                   SigTest27NegativeTCPV4Keyword, 1);

    UtRegisterTest("SigTest28TCPV6Keyword", SigTest28TCPV6Keyword, 1);
    UtRegisterTest("SigTest29NegativeTCPV6Keyword",
                   SigTest29NegativeTCPV6Keyword, 1);

    UtRegisterTest("SigTest30UDPV4Keyword", SigTest30UDPV4Keyword, 1);
    UtRegisterTest("SigTest31NegativeUDPV4Keyword",
                   SigTest31NegativeUDPV4Keyword, 1);

    UtRegisterTest("SigTest32UDPV6Keyword", SigTest32UDPV6Keyword, 1);
    UtRegisterTest("SigTest33NegativeUDPV6Keyword",
                   SigTest33NegativeUDPV6Keyword, 1);

    UtRegisterTest("SigTest34ICMPV4Keyword", SigTest34ICMPV4Keyword, 1);
    UtRegisterTest("SigTest35NegativeICMPV4Keyword",
                   SigTest35NegativeICMPV4Keyword, 1);

    /* The following tests check content options with isdataat options
       relative to that content match
    */

    UtRegisterTest("SigTest36ContentAndIsdataatKeywords01B2g",
                    SigTest36ContentAndIsdataatKeywords01B2g, 1);
    UtRegisterTest("SigTest36ContentAndIsdataatKeywords01B3g",
                    SigTest36ContentAndIsdataatKeywords01B3g, 1);
    UtRegisterTest("SigTest36ContentAndIsdataatKeywords01Wm" ,
                    SigTest36ContentAndIsdataatKeywords01Wm,  1);

    UtRegisterTest("SigTest37ContentAndIsdataatKeywords02B2g",
                    SigTest37ContentAndIsdataatKeywords02B2g, 1);
    UtRegisterTest("SigTest37ContentAndIsdataatKeywords02B3g",
                    SigTest37ContentAndIsdataatKeywords02B3g, 1);
    UtRegisterTest("SigTest37ContentAndIsdataatKeywords02Wm" ,
                    SigTest37ContentAndIsdataatKeywords02Wm,  1);

    /* We need to enable these tests, as soon as we add the ICMPv6 protocol
       support in our rules engine */
    //UtRegisterTest("SigTest36ICMPV6Keyword", SigTest36ICMPV6Keyword, 1);
    //UtRegisterTest("SigTest37NegativeICMPV6Keyword",
    //               SigTest37NegativeICMPV6Keyword, 1);

    UtRegisterTest("SigTest38B2g -- byte_test test (1)", SigTest38B2g, 1);
    UtRegisterTest("SigTest38B3g -- byte_test test (1)", SigTest38B3g, 1);
    UtRegisterTest("SigTest38Wm -- byte_test test (1)", SigTest38Wm, 1);

    UtRegisterTest("SigTest39B2g -- byte_jump test (2)", SigTest39B2g, 1);
    UtRegisterTest("SigTest39B3g -- byte_jump test (2)", SigTest39B3g, 1);
    UtRegisterTest("SigTest39Wm -- byte_jump test (2)", SigTest39Wm, 1);

    UtRegisterTest("SigTest40NoPacketInspection01", SigTest40NoPacketInspection01, 1);
    UtRegisterTest("SigTest40NoPayloadInspection02", SigTest40NoPayloadInspection02, 1);

    UtRegisterTest("SigTestMemory01", SigTestMemory01, 1);
    UtRegisterTest("SigTestMemory02", SigTestMemory02, 1);
    UtRegisterTest("SigTestMemory03", SigTestMemory03, 1);

    UtRegisterTest("SigTestSgh01", SigTestSgh01, 1);
    UtRegisterTest("SigTestSgh02", SigTestSgh02, 1);
    UtRegisterTest("SigTestSgh03", SigTestSgh03, 1);
    UtRegisterTest("SigTestSgh04", SigTestSgh04, 1);
    UtRegisterTest("SigTestSgh05", SigTestSgh05, 1);

    UtRegisterTest("SigTestContent01B2g -- 32 byte pattern", SigTestContent01B2g, 1);
    UtRegisterTest("SigTestContent01B3g -- 32 byte pattern", SigTestContent01B3g, 1);
    UtRegisterTest("SigTestContent01Wm -- 32 byte pattern", SigTestContent01Wm, 1);

    UtRegisterTest("SigTestContent02B2g -- 32+31 byte pattern", SigTestContent02B2g, 1);
    UtRegisterTest("SigTestContent02B3g -- 32+31 byte pattern", SigTestContent02B3g, 1);
    UtRegisterTest("SigTestContent02Wm -- 32+31 byte pattern", SigTestContent02Wm, 1);

    UtRegisterTest("SigTestContent03B2g -- 32 byte pattern, x2 + distance", SigTestContent03B2g, 1);
    UtRegisterTest("SigTestContent03B3g -- 32 byte pattern, x2 + distance", SigTestContent03B3g, 1);
    UtRegisterTest("SigTestContent03Wm -- 32 byte pattern, x2 + distance", SigTestContent03Wm, 1);

    UtRegisterTest("SigTestContent04B2g -- 32 byte pattern, x2 + distance/within", SigTestContent04B2g, 1);
    UtRegisterTest("SigTestContent04B3g -- 32 byte pattern, x2 + distance/within", SigTestContent04B3g, 1);
    UtRegisterTest("SigTestContent04Wm -- 32 byte pattern, x2 + distance/within", SigTestContent04Wm, 1);

    UtRegisterTest("SigTestContent05B2g -- distance/within", SigTestContent05B2g, 1);
    UtRegisterTest("SigTestContent05B3g -- distance/within", SigTestContent05B3g, 1);
    UtRegisterTest("SigTestContent05Wm -- distance/within", SigTestContent05Wm, 1);

    UtRegisterTest("SigTestContent06B2g -- distance/within ip only", SigTestContent06B2g, 1);
    UtRegisterTest("SigTestContent06B3g -- distance/within ip only", SigTestContent06B3g, 1);
    UtRegisterTest("SigTestContent06Wm -- distance/within ip only", SigTestContent06Wm, 1);

    UtRegisterTest("SigTestWithinReal01B2g", SigTestWithinReal01B2g, 1);
    UtRegisterTest("SigTestWithinReal01B3g", SigTestWithinReal01B3g, 1);
    UtRegisterTest("SigTestWithinReal01Wm", SigTestWithinReal01Wm, 1);

    UtRegisterTest("SigTestDepthOffset01B2g", SigTestDepthOffset01B2g, 1);
    UtRegisterTest("SigTestDepthOffset01B3g", SigTestDepthOffset01B3g, 1);
    UtRegisterTest("SigTestDepthOffset01Wm", SigTestDepthOffset01Wm, 1);

    UtRegisterTest("SigTestDetectAlertCounter", SigTestDetectAlertCounter, 1);

    UtRegisterTest("SigTestDropFlow01", SigTestDropFlow01, 1);
    UtRegisterTest("SigTestDropFlow02", SigTestDropFlow02, 1);
    UtRegisterTest("SigTestDropFlow03", SigTestDropFlow03, 1);
    UtRegisterTest("SigTestDropFlow04", SigTestDropFlow04, 1);

    UtRegisterTest("DetectAddressYamlParsing01", DetectAddressYamlParsing01, 1);
    UtRegisterTest("DetectAddressYamlParsing02", DetectAddressYamlParsing02, 1);
    UtRegisterTest("DetectAddressYamlParsing03", DetectAddressYamlParsing03, 1);
    UtRegisterTest("DetectAddressYamlParsing04", DetectAddressYamlParsing04, 1);

    UtRegisterTest("SigTestPorts01", SigTestPorts01, 1);
    UtRegisterTest("SigTestBug01", SigTestBug01, 1);

#if 0
    DetectSimdRegisterTests();
#endif
#endif /* UNITTESTS */
}

