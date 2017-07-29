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
#include "detect-engine-profile.h"

#include "detect-engine-alert.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"
#include "detect-engine-proto.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "detect-engine-threshold.h"
#include "detect-engine-prefilter.h"

#include "detect-engine-payload.h"
#include "detect-engine-dcepayload.h"
#include "detect-engine-uri.h"
#include "detect-dns-query.h"
#include "detect-tls-sni.h"
#include "detect-tls-cert-issuer.h"
#include "detect-tls-cert-subject.h"
#include "detect-tls-cert-serial.h"
#include "detect-engine-state.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-filedata-smtp.h"

#include "detect-http-cookie.h"
#include "detect-http-method.h"
#include "detect-http-ua.h"
#include "detect-http-hh.h"
#include "detect-http-hrh.h"

#include "detect-nfs-procedure.h"
#include "detect-nfs-version.h"

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
#include "detect-prefilter.h"
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
#include "detect-filesha1.h"
#include "detect-filesha256.h"
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
#include "detect-http-header-names.h"
#include "detect-http-headers.h"
#include "detect-http-raw-header.h"
#include "detect-http-uri.h"
#include "detect-http-protocol.h"
#include "detect-http-start.h"
#include "detect-http-raw-uri.h"
#include "detect-http-stat-msg.h"
#include "detect-http-request-line.h"
#include "detect-http-response-line.h"
#include "detect-engine-hcbd.h"
#include "detect-engine-hsbd.h"
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
#include "detect-app-layer-protocol.h"
#include "detect-template.h"
#include "detect-target.h"
#include "detect-template-buffer.h"
#include "detect-bypass.h"
#include "detect-engine-content-inspection.h"

#include "util-rule-vars.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "app-layer-template.h"
#include "detect-tls.h"
#include "detect-tls-cert-validity.h"
#include "detect-tls-version.h"
#include "detect-ssh-proto.h"
#include "detect-ssh-proto-version.h"
#include "detect-ssh-software.h"
#include "detect-ssh-software-version.h"
#include "detect-http-stat-code.h"
#include "detect-ssl-version.h"
#include "detect-ssl-state.h"
#include "detect-modbus.h"
#include "detect-cipservice.h"
#include "detect-dnp3.h"

#include "action-globals.h"
#include "tm-threads.h"

#include "pkt-var.h"

#include "conf.h"
#include "conf-yaml-loader.h"

#include "stream-tcp.h"
#include "stream-tcp-inline.h"

#include "util-lua.h"
#include "util-var-name.h"
#include "util-classification-config.h"
#include "util-threshold-config.h"
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
static void PacketCreateMask(Packet *, SignatureMask *, AppProto, bool, int);

/**
 *  \brief Create the path if default-rule-path was specified
 *  \param sig_file The name of the file
 *  \retval str Pointer to the string path + sig_file
 */
char *DetectLoadCompleteSigPath(const DetectEngineCtx *de_ctx, const char *sig_file)
{
    const char *defaultpath = NULL;
    char *path = NULL;
    char varname[128];

    if (strlen(de_ctx->config_prefix) > 0) {
        snprintf(varname, sizeof(varname), "%s.default-rule-path",
                de_ctx->config_prefix);
    } else {
        snprintf(varname, sizeof(varname), "default-rule-path");
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
                RetrieveFPForSig(sig);
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
        if (strcmp("/dev/null", fname) == 0)
            continue;

        SCLogConfig("Loading rule file: %s", fname);
        r = DetectLoadSigFile(de_ctx, fname, good_sigs, bad_sigs);
        if (r < 0) {
            ++(st->bad_files);
        }

        ++(st->total_files);

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

                    if (de_ctx->failure_fatal && ret != 0) {
                        /* Some rules failed to load, just exit as
                         * errors would have already been logged. */
                        exit(EXIT_FAILURE);
                    }

                    if (good_sigs == 0) {
                        SCLogConfig("No rules loaded from %s.", file->val);
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
            SCLogConfig("No rules loaded from %s", sig_file);
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

    SCThresholdConfInitContext(de_ctx);

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
                                   const Signature *s)
{
    /* run the packet match functions */
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_POSTMATCH];
    if (smd != NULL) {
        KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_POSTMATCH);

        SCLogDebug("running match functions, sm %p", smd);

        while (1) {
            KEYWORD_PROFILING_START;
            (void)sigmatch_table[smd->type].Match(tv, det_ctx, p, s, smd->ctx);
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
            if (smd->is_last)
                break;
            smd++;
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
    } else if (p->proto == 0) {
        if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
            /* not IP, so nothing to do */
            SCReturnPtr(NULL, "SigGroupHead");
        }
    }

    /* select the flow_gh */
    if (p->flowflags & FLOW_PKT_TOCLIENT)
        f = 0;
    else
        f = 1;

    int proto = IP_GET_IPPROTO(p);
    if (proto == IPPROTO_TCP) {
        DetectPort *list = de_ctx->flow_gh[f].tcp;
        SCLogDebug("tcp toserver %p, tcp toclient %p: going to use %p",
                de_ctx->flow_gh[1].tcp, de_ctx->flow_gh[0].tcp, de_ctx->flow_gh[f].tcp);
        uint16_t port = f ? p->dp : p->sp;
        SCLogDebug("tcp port %u -> %u:%u", port, p->sp, p->dp);
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("TCP list %p, port %u, direction %s, sghport %p, sgh %p",
                list, port, f ? "toserver" : "toclient", sghport, sgh);
    } else if (proto == IPPROTO_UDP) {
        DetectPort *list = de_ctx->flow_gh[f].udp;
        uint16_t port = f ? p->dp : p->sp;
        DetectPort *sghport = DetectPortLookupGroup(list, port);
        if (sghport != NULL)
            sgh = sghport->sh;
        SCLogDebug("UDP list %p, port %u, direction %s, sghport %p, sgh %p",
                list, port, f ? "toserver" : "toclient", sghport, sgh);
    } else {
        sgh = de_ctx->flow_gh[f].sgh[proto];
    }

    SCReturnPtr(sgh, "SigGroupHead");
}

static inline void DetectPrefilterMergeSort(DetectEngineCtx *de_ctx,
                                            DetectEngineThreadCtx *det_ctx)
{
    SigIntId mpm, nonmpm;
    det_ctx->match_array_cnt = 0;
    SigIntId *mpm_ptr = det_ctx->pmq.rule_id_array;
    SigIntId *nonmpm_ptr = det_ctx->non_pf_id_array;
    uint32_t m_cnt = det_ctx->pmq.rule_id_array_cnt;
    uint32_t n_cnt = det_ctx->non_pf_id_cnt;
    SigIntId *final_ptr;
    uint32_t final_cnt;
    SigIntId id;
    SigIntId previous_id = (SigIntId)-1;
    Signature **sig_array = de_ctx->sig_array;
    Signature **match_array = det_ctx->match_array;
    Signature *s;

    SCLogDebug("PMQ rule id array count %d", det_ctx->pmq.rule_id_array_cnt);

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
        if (mpm < nonmpm) {
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
         } else if (mpm > nonmpm) {
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

        } else { /* implied mpm == nonmpm */
            /* special case: if on both lists, it's a negated mpm pattern */

            /* mpm list may have dups, so skip past them here */
            while (--m_cnt != 0) {
                mpm_ptr++;
                mpm = *mpm_ptr;
                if (mpm != nonmpm)
                    break;
            }
            /* if mpm is done, update nonmpm_ptrs and jump to final */
            if (unlikely(m_cnt == 0)) {
                n_cnt--;

                /* mpm list is now empty */
                final_ptr = ++nonmpm_ptr;
                final_cnt = n_cnt;
                goto final;
            }
            /* otherwise, if nonmpm is done jump to final for mpm
             * mpm ptrs alrady updated */
            if (unlikely(--n_cnt == 0)) {
                final_ptr = mpm_ptr;
                final_cnt = m_cnt;
                goto final;
            }

            /* not at end of the lists, update nonmpm. Mpm already
             * updated in while loop above. */
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

    BUG_ON((det_ctx->pmq.rule_id_array_cnt + det_ctx->non_pf_id_cnt) < det_ctx->match_array_cnt);
}

static inline void
DetectPrefilterBuildNonPrefilterList(DetectEngineThreadCtx *det_ctx, SignatureMask mask)
{
    uint32_t x = 0;
    for (x = 0; x < det_ctx->non_pf_store_cnt; x++) {
        /* only if the mask matches this rule can possibly match,
         * so build the non_mpm array only for match candidates */
        SignatureMask rule_mask = det_ctx->non_pf_store_ptr[x].mask;
        if ((rule_mask & mask) == rule_mask) {
            det_ctx->non_pf_id_array[det_ctx->non_pf_id_cnt++] = det_ctx->non_pf_store_ptr[x].id;
        }
    }
}

/** \internal
 *  \brief select non-mpm list
 *  Based on the packet properties, select the non-mpm list to use */
static inline void
DetectPrefilterSetNonPrefilterList(const Packet *p, DetectEngineThreadCtx *det_ctx)
{
    if ((p->proto == IPPROTO_TCP) && (p->tcph != NULL) && (p->tcph->th_flags & TH_SYN)) {
        det_ctx->non_pf_store_ptr = det_ctx->sgh->non_pf_syn_store_array;
        det_ctx->non_pf_store_cnt = det_ctx->sgh->non_pf_syn_store_cnt;
    } else {
        det_ctx->non_pf_store_ptr = det_ctx->sgh->non_pf_other_store_array;
        det_ctx->non_pf_store_cnt = det_ctx->sgh->non_pf_other_store_cnt;
    }
    SCLogDebug("sgh non_pf ptr %p cnt %u (syn %p/%u, other %p/%u)",
            det_ctx->non_pf_store_ptr, det_ctx->non_pf_store_cnt,
            det_ctx->sgh->non_pf_syn_store_array, det_ctx->sgh->non_pf_syn_store_cnt,
            det_ctx->sgh->non_pf_other_store_array, det_ctx->sgh->non_pf_other_store_cnt);
}

/** \internal
 *  \brief update flow's file tracking flags based on the detection engine
 */
static inline void
DetectPostInspectFileFlagsUpdate(Flow *pflow, const SigGroupHead *sgh, uint8_t direction)
{
    /* see if this sgh requires us to consider file storing */
    if (!FileForceFilestore() && (sgh == NULL ||
                sgh->filestore_cnt == 0))
    {
        FileDisableStoring(pflow, direction);
    }
#ifdef HAVE_MAGIC
    /* see if this sgh requires us to consider file magic */
    if (!FileForceMagic() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMAGIC)))
    {
        SCLogDebug("disabling magic for flow");
        FileDisableMagic(pflow, direction);
    }
#endif
    /* see if this sgh requires us to consider file md5 */
    if (!FileForceMd5() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILEMD5)))
    {
        SCLogDebug("disabling md5 for flow");
        FileDisableMd5(pflow, direction);
    }

    /* see if this sgh requires us to consider file sha1 */
    if (!FileForceSha1() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA1)))
    {
        SCLogDebug("disabling sha1 for flow");
        FileDisableSha1(pflow, direction);
    }

    /* see if this sgh requires us to consider file sha256 */
    if (!FileForceSha256() && (sgh == NULL ||
                !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESHA256)))
    {
        SCLogDebug("disabling sha256 for flow");
        FileDisableSha256(pflow, direction);
    }

    /* see if this sgh requires us to consider filesize */
    if (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVEFILESIZE))
    {
        SCLogDebug("disabling filesize for flow");
        FileDisableFilesize(pflow, direction);
    }
}

static inline void
DetectPostInspectFirstSGH(const Packet *p, Flow *pflow, const SigGroupHead *sgh)
{
    if ((p->flowflags & FLOW_PKT_TOSERVER) && !(pflow->flags & FLOW_SGH_TOSERVER)) {
        /* first time we see this toserver sgh, store it */
        pflow->sgh_toserver = sgh;
        pflow->flags |= FLOW_SGH_TOSERVER;

        if (p->proto == IPPROTO_TCP && (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVERAWSTREAM))) {
            if (pflow->protoctx != NULL) {
                TcpSession *ssn = pflow->protoctx;
                SCLogDebug("STREAMTCP_STREAM_FLAG_DISABLE_RAW ssn.client");
                ssn->client.flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
            }
        }

        DetectPostInspectFileFlagsUpdate(pflow,
                pflow->sgh_toserver, STREAM_TOSERVER);

    } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && !(pflow->flags & FLOW_SGH_TOCLIENT)) {
        pflow->sgh_toclient = sgh;
        pflow->flags |= FLOW_SGH_TOCLIENT;

        if (p->proto == IPPROTO_TCP && (sgh == NULL || !(sgh->flags & SIG_GROUP_HEAD_HAVERAWSTREAM))) {
            if (pflow->protoctx != NULL) {
                TcpSession *ssn = pflow->protoctx;
                SCLogDebug("STREAMTCP_STREAM_FLAG_DISABLE_RAW ssn.server");
                ssn->server.flags |= STREAMTCP_STREAM_FLAG_DISABLE_RAW;
            }
        }

        DetectPostInspectFileFlagsUpdate(pflow,
                pflow->sgh_toclient, STREAM_TOCLIENT);
    }
}

/**
 *  \brief Signature match function
 */
void SigMatchSignatures(ThreadVars *th_v, DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx, Packet *p)
{
    bool use_flow_sgh = false;
    uint8_t alert_flags = 0;
    AppProto alproto = ALPROTO_UNKNOWN;
#ifdef PROFILING
    int smatch = 0; /* signature match: 1, no match: 0 */
#endif
    uint8_t flow_flags = 0; /* flow/state flags */
    const Signature *s = NULL;
    const Signature *next_s = NULL;
    int state_alert = 0;
    int app_decoder_events = 0;
    bool has_state = false;     /* do we have an alstate to work with? */

    SCEnter();

    SCLogDebug("pcap_cnt %"PRIu64, p->pcap_cnt);
#ifdef UNITTESTS
    p->alerts.cnt = 0;
#endif
    det_ctx->ticker++;
    det_ctx->filestore_cnt = 0;
    det_ctx->base64_decoded_len = 0;
    det_ctx->raw_stream_progress = 0;

#ifdef DEBUG
    if (p->flags & PKT_STREAM_ADD) {
        det_ctx->pkt_stream_add_cnt++;
    }
#endif

    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if (p->flags & PKT_NOPACKET_INSPECTION) {
        SCReturn;
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

        {
            /* store tenant_id in the flow so that we can use it
             * for creating pseudo packets */
            if (p->tenant_id > 0 && pflow->tenant_id == 0) {
                pflow->tenant_id = p->tenant_id;
            }

            /* live ruleswap check for flow updates */
            if (pflow->de_ctx_version == 0) {
                /* first time this flow is inspected, set id */
                pflow->de_ctx_version = de_ctx->version;
            } else if (pflow->de_ctx_version != de_ctx->version) {
                /* first time we inspect flow with this de_ctx, reset */
                pflow->flags &= ~FLOW_SGH_TOSERVER;
                pflow->flags &= ~FLOW_SGH_TOCLIENT;
                pflow->sgh_toserver = NULL;
                pflow->sgh_toclient = NULL;

                pflow->de_ctx_version = de_ctx->version;
                GenericVarFree(pflow->flowvar);
                pflow->flowvar = NULL;

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
                    SCLogDebug("det_ctx->sgh = pflow->sgh_toserver; => %p", det_ctx->sgh);
                    use_flow_sgh = true;
                } else if ((p->flowflags & FLOW_PKT_TOCLIENT) && (pflow->flags & FLOW_SGH_TOCLIENT)) {
                    det_ctx->sgh = pflow->sgh_toclient;
                    SCLogDebug("det_ctx->sgh = pflow->sgh_toclient; => %p", det_ctx->sgh);
                    use_flow_sgh = true;
                }
                PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
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
                if (p->proto == IPPROTO_TCP && pflow->protoctx &&
                    StreamReassembleRawHasDataReady(pflow->protoctx, p)) {
                    p->flags |= PKT_DETECT_HAS_STREAMDATA;
                }
                SCLogDebug("alstate %s, alproto %u", has_state ? "true" : "false", alproto);
            } else {
                SCLogDebug("packet doesn't have established flag set (proto %d)", p->proto);
            }

            app_decoder_events = AppLayerParserHasDecoderEvents(pflow,
                                                                pflow->alstate,
                                                                pflow->alparser,
                                                                flow_flags);
        }

        if (((p->flowflags & FLOW_PKT_TOSERVER) && !(p->flowflags & FLOW_PKT_TOSERVER_IPONLY_SET)) ||
            ((p->flowflags & FLOW_PKT_TOCLIENT) && !(p->flowflags & FLOW_PKT_TOCLIENT_IPONLY_SET)))
        {
            SCLogDebug("testing against \"ip-only\" signatures");

            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_IPONLY);
            IPOnlyMatchPacket(th_v, de_ctx, det_ctx, &de_ctx->io_ctx, &det_ctx->io_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_IPONLY);

            /* save in the flow that we scanned this direction... */
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

        if (!(use_flow_sgh)) {
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_GETSGH);
            det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, det_ctx, p);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_GETSGH);
        }

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

    DetectPrefilterSetNonPrefilterList(p, det_ctx);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_CONT);
    /* stateful app layer detection */
    if ((p->flags & PKT_HAS_FLOW) && has_state) {
        memset(det_ctx->de_state_sig_array, 0x00, det_ctx->de_state_sig_array_len);
        int has_inspectable_state = DeStateFlowHasInspectableState(pflow, flow_flags);
        if (has_inspectable_state == 1) {
            /* initialize to 0(DE_STATE_MATCH_HAS_NEW_STATE) */
            DeStateDetectContinueDetection(th_v, de_ctx, det_ctx, p, pflow,
                                           flow_flags, alproto);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_CONT);

    /* create our prefilter mask */
    SignatureMask mask = 0;
    PacketCreateMask(p, &mask, alproto, has_state, app_decoder_events);

    /* build and prefilter non_pf list against the mask of the packet */
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_NONMPMLIST);
    det_ctx->non_pf_id_cnt = 0;
    if (likely(det_ctx->non_pf_store_cnt > 0)) {
        DetectPrefilterBuildNonPrefilterList(det_ctx, mask);
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_NONMPMLIST);

    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PREFILTER);
    /* run the prefilter engines */
    Prefilter(det_ctx, det_ctx->sgh, p, flow_flags, has_state);
    PACKET_PROFILING_DETECT_START(p, PROF_DETECT_PF_SORT2);
    DetectPrefilterMergeSort(de_ctx, det_ctx);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PF_SORT2);
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_PREFILTER);

#ifdef PROFILING
    if (th_v) {
        StatsAddUI64(th_v, det_ctx->counter_mpm_list,
                             (uint64_t)det_ctx->pmq.rule_id_array_cnt);
        StatsAddUI64(th_v, det_ctx->counter_nonmpm_list,
                             (uint64_t)det_ctx->non_pf_store_cnt);
        /* non mpm sigs after mask prefilter */
        StatsAddUI64(th_v, det_ctx->counter_fnonmpm_list,
                             (uint64_t)det_ctx->non_pf_id_cnt);
    }
#endif

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

    SGH_PROFILING_RECORD(det_ctx, det_ctx->sgh);
#ifdef PROFILING
#ifdef HAVE_LIBJANSSON
    if (match_cnt >= de_ctx->profile_match_logging_threshold)
        RulesDumpMatchArray(det_ctx, p);
#endif
#endif

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
        const uint8_t s_proto_flags = s->proto.flags;

        SCLogDebug("inspecting signature id %"PRIu32"", s->id);

        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (det_ctx->de_state_sig_array[s->num] & DE_STATE_MATCH_NO_NEW_STATE)
                goto next;
        } else {
            /* don't run mask check for stateful rules.
             * There we depend on prefilter */
            if ((s->mask & mask) != s->mask) {
                SCLogDebug("mask mismatch %x & %x != %x", s->mask, mask, s->mask);
                goto next;
            }

            if (unlikely(sflags & SIG_FLAG_DSIZE)) {
                if (likely(p->payload_len < s->dsize_low || p->payload_len > s->dsize_high)) {
                    SCLogDebug("kicked out as p->payload_len %u, dsize low %u, hi %u",
                            p->payload_len, s->dsize_low, s->dsize_high);
                    goto next;
                }
            }
        }

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

        /* check if this signature has a requirement for flowvars of some type
         * and if so, if we actually have any in the flow. If not, the sig
         * can't match and we skip it. */
        if ((p->flags & PKT_HAS_FLOW) && (sflags & SIG_FLAG_REQUIRE_FLOWVAR)) {
            int m  = pflow->flowvar ? 1 : 0;

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
        if (!(sflags & SIG_FLAG_STATE_MATCH) && s->sm_arrays[DETECT_SM_LIST_PMATCH] != NULL) {
            KEYWORD_PROFILING_SET_LIST(det_ctx, DETECT_SM_LIST_PMATCH);
            /* if we have stream msgs, inspect against those first,
             * but not for a "dsize" signature */
            if (sflags & SIG_FLAG_REQUIRE_STREAM) {
                int pmatch = 0;
                if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
                    pmatch = DetectEngineInspectStreamPayload(de_ctx, det_ctx, s, pflow, p);
                    if (pmatch) {
                        det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_STREAM_CONTENT_MATCH;
                        /* Tell the engine that this reassembled stream can drop the
                         * rest of the pkts with no further inspection */
                        if (s->action & ACTION_DROP)
                            alert_flags |= PACKET_ALERT_FLAG_DROP_FLOW;

                        alert_flags |= PACKET_ALERT_FLAG_STREAM_MATCH;
                    }
                }
                /* no match? then inspect packet payload */
                if (pmatch == 0) {
                    SCLogDebug("no match in stream, fall back to packet payload");

                    /* skip if we don't have to inspect the packet and segment was
                     * added to stream */
                    if (!(sflags & SIG_FLAG_REQUIRE_PACKET) && (p->flags & PKT_STREAM_ADD)) {
                        goto next;
                    }

                    if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
                        goto next;
                    }
                }
            } else {
                if (DetectEngineInspectPacketPayload(de_ctx, det_ctx, s, pflow, p) != 1) {
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
                        SCLogDebug("no match");
                        goto next;
                    }
                    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                    if (smd->is_last) {
                        SCLogDebug("match and is_last");
                        break;
                    }
                    smd++;
                }
            }
        }

        /* consider stateful sig matches */
        if (sflags & SIG_FLAG_STATE_MATCH) {
            if (has_state == false) {
                SCLogDebug("state matches but no state, we can't match");
                goto next;
            }

            SCLogDebug("stateful app layer match inspection starting");

            /* if DeStateDetectStartDetection matches, it's a full
             * signature match. It will then call PacketAlertAppend
             * itself, so we can skip it below. This is done so it
             * can store the tx_id with the alert */
            PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_START);
            state_alert = DeStateDetectStartDetection(th_v, de_ctx, det_ctx, s,
                                                      p, pflow, flow_flags, alproto);
            PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_START);
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
            DetectSignatureApplyActions(p, s, alert_flags);
        }
next:
        DetectVarProcessList(det_ctx, pflow, p);
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
        PACKET_PROFILING_DETECT_START(p, PROF_DETECT_STATEFUL_UPDATE);
        DeStateUpdateInspectTransactionId(pflow, flow_flags);
        PACKET_PROFILING_DETECT_END(p, PROF_DETECT_STATEFUL_UPDATE);
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

    /* store the found sgh (or NULL) in the flow to save us from looking it
     * up again for the next packet. Also return any stream chunk we processed
     * to the pool. */
    if (p->flags & PKT_HAS_FLOW) {
        /* HACK: prevent the wrong sgh (or NULL) from being stored in the
         * flow's sgh pointers */
        if (PKT_IS_ICMPV4(p) && ICMPV4_DEST_UNREACH_IS_VALID(p)) {
            ; /* no-op */

        } else if (!(use_flow_sgh)) {
            DetectPostInspectFirstSGH(p, pflow, det_ctx->sgh);
        }

        /* update inspected tracker for raw reassembly */
        if (p->proto == IPPROTO_TCP && pflow->protoctx != NULL) {
            StreamReassembleRawUpdateProgress(pflow->protoctx, p,
                    det_ctx->raw_stream_progress);

            DetectEngineCleanHCBDBuffers(det_ctx);
            DetectEngineCleanHSBDBuffers(det_ctx);
            DetectEngineCleanSMTPBuffers(det_ctx);
        }
    }
    PACKET_PROFILING_DETECT_END(p, PROF_DETECT_CLEANUP);
    SCReturn;
}

/** \brief Apply action(s) and Set 'drop' sig info,
 *         if applicable */
void DetectSignatureApplyActions(Packet *p,
        const Signature *s, const uint8_t alert_flags)
{
    PACKET_UPDATE_ACTION(p, s->action);

    if (s->action & ACTION_DROP) {
        if (p->alerts.drop.action == 0) {
            p->alerts.drop.num = s->num;
            p->alerts.drop.action = s->action;
            p->alerts.drop.s = (Signature *)s;
        }
    } else if (s->action & ACTION_PASS) {
        /* if an stream/app-layer match we enforce the pass for the flow */
        if ((p->flow != NULL) &&
                (alert_flags & (PACKET_ALERT_FLAG_STATE_MATCH|PACKET_ALERT_FLAG_STREAM_MATCH)))
        {
            FlowSetNoPacketInspectionFlag(p->flow);
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

static void DetectFlow(ThreadVars *tv,
                       DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                       Packet *p)
{
    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) ||
        (PACKET_TEST_ACTION(p, ACTION_DROP)))
    {
        /* hack: if we are in pass the entire flow mode, we need to still
         * update the inspect_id forward. So test for the condition here,
         * and call the update code if necessary. */
        int pass = ((p->flow->flags & FLOW_NOPACKET_INSPECTION));
        uint8_t flags = FlowGetDisruptionFlags(p->flow, 0);
        AppProto alproto = FlowGetAppProtocol(p->flow);
        if (pass && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                flags |= STREAM_TOSERVER;
            } else {
                flags |= STREAM_TOCLIENT;
            }
            DeStateUpdateInspectTransactionId(p->flow, flags);
        }
        return;
    }

    /* see if the packet matches one or more of the sigs */
    (void)SigMatchSignatures(tv,de_ctx,det_ctx,p);
}


static void DetectNoFlow(ThreadVars *tv,
                         DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
                         Packet *p)
{
    /* No need to perform any detection on this packet, if the the given flag is set.*/
    if ((p->flags & PKT_NOPACKET_INSPECTION) ||
        (PACKET_TEST_ACTION(p, ACTION_DROP)))
    {
        return;
    }

    /* see if the packet matches one or more of the sigs */
    (void)SigMatchSignatures(tv,de_ctx,det_ctx,p);
    return;
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

    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = (DetectEngineThreadCtx *)data;
    if (det_ctx == NULL) {
        printf("ERROR: Detect has no thread ctx\n");
        goto error;
    }

    if (unlikely(SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0)) {
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

            if (unlikely(SC_ATOMIC_GET(det_ctx->so_far_used_by_detect) == 0)) {
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

    if (p->flow) {
        DetectFlow(tv, de_ctx, det_ctx, p);
    } else {
        DetectNoFlow(tv, de_ctx, det_ctx, p);
    }
    return TM_ECODE_OK;
error:
    return TM_ECODE_FAILED;
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

/**
 *  \brief Check if a signature contains the filestore keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFilestoring(const Signature *s)
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
int SignatureIsFilemagicInspecting(const Signature *s)
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
int SignatureIsFileMd5Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_MD5))
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesha1 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileSha1Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_SHA1))
        return 1;

    return 0;
}

/**
 *  \brief Check if a signature contains the filesha256 keyword.
 *
 *  \param s signature
 *
 *  \retval 0 no
 *  \retval 1 yes
 */
int SignatureIsFileSha256Inspecting(const Signature *s)
{
    if ((s != NULL) && (s->file_flags & FILE_SIG_NEED_SHA256))
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
int SignatureIsFilesizeInspecting(const Signature *s)
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
int SignatureIsIPOnly(DetectEngineCtx *de_ctx, const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN)
        return 0;

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 0;

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = DetectBufferTypeMaxId();
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectBufferTypeGetNameById(i)))
            continue;

        SCReturnInt(0);
    }

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

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
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

/** \internal
 *  \brief Test is a initialized signature is inspecting protocol detection only
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is dp only
 *  \retval 0 sig is not dp only
 */
static int SignatureIsPDOnly(const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN)
        return 0;

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 0;

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = DetectBufferTypeMaxId();
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectBufferTypeGetNameById(i)))
            continue;

        SCReturnInt(0);
    }

    /* TMATCH list can be ignored, it contains TAGs and
     * tags are compatible to DP-only. */

    /* match list matches may be compatible to DP only. We follow the same
     * logic as IP-only so we can use that flag */

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    if (sm == NULL)
        return 0;

    int pd = 0;
    for ( ; sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_AL_APP_LAYER_PROTOCOL) {
            pd = 1;
        } else {
            /* flowbits are supported for dp only sigs, as long
             * as the sig only has a "set" flowbits */
            if (sm->type == DETECT_FLOWBITS) {
                if ((((DetectFlowbitsData *)sm->ctx)->cmd != DETECT_FLOWBITS_CMD_SET) ) {
                    SCLogDebug("%u: not PD-only: flowbit settings other than 'set'", s->id);
                    return 0;
                }
            } else if (sm->type == DETECT_FLOW) {
                if (((DetectFlowData *)sm->ctx)->flags & ~(DETECT_FLOW_FLAG_TOSERVER|DETECT_FLOW_FLAG_TOCLIENT)) {
                    SCLogDebug("%u: not PD-only: flow settings other than toserver/toclient", s->id);
                    return 0;
                }
            } else if ( !(sigmatch_table[sm->type].flags & SIGMATCH_IPONLY_COMPAT)) {
                SCLogDebug("%u: not PD-only: %s not PD/IP-only compat", s->id, sigmatch_table[sm->type].name);
                return 0;
            }
        }
    }

    if (pd) {
        SCLogDebug("PD-ONLY (%" PRIu32 ")", s->id);
    }
    return pd;
}

/**
 *  \internal
 *  \brief Check if the initialized signature is inspecting the packet payload
 *  \param de_ctx detection engine ctx
 *  \param s the signature
 *  \retval 1 sig is inspecting the payload
 *  \retval 0 sig is not inspecting the payload
 */
static int SignatureIsInspectingPayload(DetectEngineCtx *de_ctx, const Signature *s)
{

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL) {
        return 1;
    }
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
static int SignatureIsDEOnly(DetectEngineCtx *de_ctx, const Signature *s)
{
    if (s->alproto != ALPROTO_UNKNOWN) {
        SCReturnInt(0);
    }

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
    {
        SCReturnInt(0);
    }

    /* for now assume that all registered buffer types are incompatible */
    const int nlists = DetectBufferTypeMaxId();
    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        if (!(DetectBufferTypeGetNameById(i)))
            continue;

        SCReturnInt(0);
    }

    /* check for conflicting keywords */
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    for ( ;sm != NULL; sm = sm->next) {
        if ( !(sigmatch_table[sm->type].flags & SIGMATCH_DEONLY_COMPAT))
            SCReturnInt(0);
    }

    /* need at least one decode event keyword to be considered decode event. */
    sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
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
PacketCreateMask(Packet *p, SignatureMask *mask, AppProto alproto,
        bool has_state, int app_decoder_events)
{
    if (!(p->flags & PKT_NOPAYLOAD_INSPECTION) && p->payload_len > 0) {
        SCLogDebug("packet has payload");
        (*mask) |= SIG_MASK_REQUIRE_PAYLOAD;
    } else if (p->flags & PKT_DETECT_HAS_STREAMDATA) {
        SCLogDebug("stream data available");
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
                case ALPROTO_ENIP:
                    SCLogDebug("packet/flow has enip state");
                    (*mask) |= SIG_MASK_REQUIRE_ENIP_STATE;
                    break;
                case ALPROTO_DNP3:
                    SCLogDebug("packet/flow has dnp3 state");
                    (*mask) |= SIG_MASK_REQUIRE_DNP3_STATE;
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

    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL) {
        s->mask |= SIG_MASK_REQUIRE_PAYLOAD;
        SCLogDebug("sig requires payload");
    }

    SigMatch *sm;
    for (sm = s->init_data->smlists[DETECT_SM_LIST_MATCH] ; sm != NULL; sm = sm->next) {
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
    if (s->alproto == ALPROTO_DNP3) {
        s->mask |= SIG_MASK_REQUIRE_DNP3_STATE;
        SCLogDebug("sig requires dnp3 state");
    }
    if (s->alproto == ALPROTO_FTP) {
        s->mask |= SIG_MASK_REQUIRE_FTP_STATE;
        SCLogDebug("sig requires ftp state");
    }
    if (s->alproto == ALPROTO_SMTP) {
        s->mask |= SIG_MASK_REQUIRE_SMTP_STATE;
        SCLogDebug("sig requires smtp state");
    }
    if (s->alproto == ALPROTO_ENIP) {
        s->mask |= SIG_MASK_REQUIRE_ENIP_STATE;
        SCLogDebug("sig requires enip state");
    }
    if (s->alproto == ALPROTO_TEMPLATE) {
        s->mask |= SIG_MASK_REQUIRE_TEMPLATE_STATE;
        SCLogDebug("sig requires template state");
    }

    if ((s->mask & SIG_MASK_REQUIRE_DCE_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_HTTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_SSH_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_DNS_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_DNP3_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_FTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_SMTP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_ENIP_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_TEMPLATE_STATE) ||
        (s->mask & SIG_MASK_REQUIRE_TLS_STATE))
    {
        s->mask |= SIG_MASK_REQUIRE_FLOW;
        SCLogDebug("sig requires flow");
    }

    if (s->init_data->init_flags & SIG_FLAG_INIT_FLOW) {
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

/** \brief disable file features we don't need
 *  Called if we have no detection engine.
 */
void DisableDetectFlowFileFlags(Flow *f)
{
    DetectPostInspectFileFlagsUpdate(f, NULL /* no sgh */, STREAM_TOSERVER);
    DetectPostInspectFileFlagsUpdate(f, NULL /* no sgh */, STREAM_TOCLIENT);
}

static void SigInitStandardMpmFactoryContexts(DetectEngineCtx *de_ctx)
{
    DetectMpmInitializeBuiltinMpms(de_ctx);
    DetectMpmInitializeAppMpms(de_ctx);

    return;
}

/** \brief Pure-PCRE or bytetest rule */
static int RuleInspectsPayloadHasNoMpm(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL && s->init_data->smlists[DETECT_SM_LIST_PMATCH] != NULL)
        return 1;
    return 0;
}

static int RuleGetMpmPatternSize(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL)
        return -1;
    int mpm_list = SigMatchListSMBelongsTo(s, s->init_data->mpm_sm);
    if (mpm_list < 0)
        return -1;
    const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
    if (cd == NULL)
        return -1;
    return (int)cd->content_len;
}

static int RuleMpmIsNegated(const Signature *s)
{
    if (s->init_data->mpm_sm == NULL)
        return 0;
    int mpm_list = SigMatchListSMBelongsTo(s, s->init_data->mpm_sm);
    if (mpm_list < 0)
        return 0;
    const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
    if (cd == NULL)
        return 0;
    return (cd->flags & DETECT_CONTENT_NEGATED);
}

#ifdef HAVE_LIBJANSSON
static json_t *RulesGroupPrintSghStats(const SigGroupHead *sgh,
                                const int add_rules, const int add_mpm_stats)
{
    uint32_t mpm_cnt = 0;
    uint32_t nonmpm_cnt = 0;
    uint32_t negmpm_cnt = 0;
    uint32_t any5_cnt = 0;
    uint32_t payload_no_mpm_cnt = 0;
    uint32_t syn_cnt = 0;

    uint32_t mpms_total = 0;
    uint32_t mpms_min = 0;
    uint32_t mpms_max = 0;

    struct {
        uint32_t total;
        uint32_t cnt;
        uint32_t min;
        uint32_t max;
    } mpm_stats[DETECT_SM_LIST_MAX];
    memset(mpm_stats, 0x00, sizeof(mpm_stats));

    uint32_t alstats[ALPROTO_MAX] = {0};
    uint32_t mpm_sizes[DETECT_SM_LIST_MAX][256];
    memset(mpm_sizes, 0, sizeof(mpm_sizes));
    uint32_t alproto_mpm_bufs[ALPROTO_MAX][DETECT_SM_LIST_MAX];
    memset(alproto_mpm_bufs, 0, sizeof(alproto_mpm_bufs));

    json_t *js = json_object();
    if (unlikely(js == NULL))
        return NULL;

    json_object_set_new(js, "id", json_integer(sgh->id));

    json_t *js_array = json_array();

    const Signature *s;
    uint32_t x;
    for (x = 0; x < sgh->sig_cnt; x++) {
        s = sgh->match_array[x];
        if (s == NULL)
            continue;

        int any = 0;
        if (s->proto.flags & DETECT_PROTO_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_DST_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_SRC_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_DP_ANY) {
            any++;
        }
        if (s->flags & SIG_FLAG_SP_ANY) {
            any++;
        }
        if (any == 5) {
            any5_cnt++;
        }

        if (s->init_data->mpm_sm == NULL) {
            nonmpm_cnt++;

            if (s->sm_arrays[DETECT_SM_LIST_MATCH] != NULL) {
                SCLogDebug("SGH %p Non-MPM inspecting only packets. Rule %u", sgh, s->id);
            }

            DetectPort *sp = s->sp;
            DetectPort *dp = s->dp;

            if (s->flags & SIG_FLAG_TOSERVER && (dp->port == 0 && dp->port2 == 65535)) {
                SCLogDebug("SGH %p Non-MPM toserver and to 'any'. Rule %u", sgh, s->id);
            }
            if (s->flags & SIG_FLAG_TOCLIENT && (sp->port == 0 && sp->port2 == 65535)) {
                SCLogDebug("SGH %p Non-MPM toclient and to 'any'. Rule %u", sgh, s->id);
            }

            if (DetectFlagsSignatureNeedsSynPackets(s)) {
                syn_cnt++;
            }

        } else {
            int mpm_list = SigMatchListSMBelongsTo(s, s->init_data->mpm_sm);
            BUG_ON(mpm_list < 0);
            const DetectContentData *cd = (const DetectContentData *)s->init_data->mpm_sm->ctx;
            uint32_t size = cd->content_len < 256 ? cd->content_len : 255;

            mpm_sizes[mpm_list][size]++;
            if (s->alproto != ALPROTO_UNKNOWN) {
                alproto_mpm_bufs[s->alproto][mpm_list]++;
            }

            if (mpm_list == DETECT_SM_LIST_PMATCH) {
                if (size == 1) {
                    DetectPort *sp = s->sp;
                    DetectPort *dp = s->dp;
                    if (s->flags & SIG_FLAG_TOSERVER) {
                        if (dp->port == 0 && dp->port2 == 65535) {
                            SCLogDebug("SGH %p toserver 1byte fast_pattern to ANY. Rule %u", sgh, s->id);
                        } else {
                            SCLogDebug("SGH %p toserver 1byte fast_pattern to port(s) %u-%u. Rule %u", sgh, dp->port, dp->port2, s->id);
                        }
                    }
                    if (s->flags & SIG_FLAG_TOCLIENT) {
                        if (sp->port == 0 && sp->port2 == 65535) {
                            SCLogDebug("SGH %p toclient 1byte fast_pattern to ANY. Rule %u", sgh, s->id);
                        } else {
                            SCLogDebug("SGH %p toclient 1byte fast_pattern to port(s) %u-%u. Rule %u", sgh, sp->port, sp->port2, s->id);
                        }
                    }
                }
            }

            uint32_t w = PatternStrength(cd->content, cd->content_len);
            mpms_total += w;
            if (mpms_min == 0)
                mpms_min = w;
            if (w < mpms_min)
                mpms_min = w;
            if (w > mpms_max)
                mpms_max = w;

            mpm_stats[mpm_list].total += w;
            mpm_stats[mpm_list].cnt++;
            if (mpm_stats[mpm_list].min == 0 || w < mpm_stats[mpm_list].min)
                mpm_stats[mpm_list].min = w;
            if (w > mpm_stats[mpm_list].max)
                mpm_stats[mpm_list].max = w;

            mpm_cnt++;

            if (w < 10) {
                SCLogDebug("SGH %p Weak MPM Pattern on %s. Rule %u", sgh, DetectListToString(mpm_list), s->id);
            }
            if (w < 10 && any == 5) {
                SCLogDebug("SGH %p Weak MPM Pattern on %s, rule is 5xAny. Rule %u", sgh, DetectListToString(mpm_list), s->id);
            }

            if (cd->flags & DETECT_CONTENT_NEGATED) {
                SCLogDebug("SGH %p MPM Pattern on %s, is negated. Rule %u", sgh, DetectListToString(mpm_list), s->id);
                negmpm_cnt++;
            }
        }

        if (RuleInspectsPayloadHasNoMpm(s)) {
            SCLogDebug("SGH %p No MPM. Payload inspecting. Rule %u", sgh, s->id);
            payload_no_mpm_cnt++;
        }

        if (s->alproto != ALPROTO_UNKNOWN) {
            alstats[s->alproto]++;
        }

        if (add_rules) {
            json_t *js_sig = json_object();
            if (unlikely(js == NULL))
                continue;
            json_object_set_new(js_sig, "sig_id", json_integer(s->id));
            json_array_append_new(js_array, js_sig);
        }
    }

    json_object_set_new(js, "rules", js_array);

    json_t *stats = json_object();
    json_object_set_new(stats, "total", json_integer(sgh->sig_cnt));

    json_t *types = json_object();
    json_object_set_new(types, "mpm", json_integer(mpm_cnt));
    json_object_set_new(types, "non_mpm", json_integer(nonmpm_cnt));
    json_object_set_new(types, "negated_mpm", json_integer(negmpm_cnt));
    json_object_set_new(types, "payload_but_no_mpm", json_integer(payload_no_mpm_cnt));
    json_object_set_new(types, "syn", json_integer(syn_cnt));
    json_object_set_new(types, "any5", json_integer(any5_cnt));
    json_object_set_new(stats, "types", types);

    int i;
    for (i = 0; i < ALPROTO_MAX; i++) {
        if (alstats[i] > 0) {
            json_t *app = json_object();
            json_object_set_new(app, "total", json_integer(alstats[i]));

            for (x = 0; x < DETECT_SM_LIST_MAX; x++) {
                if (alproto_mpm_bufs[i][x] == 0)
                    continue;
                json_object_set_new(app, DetectListToHumanString(x), json_integer(alproto_mpm_bufs[i][x]));
            }

            json_object_set_new(stats, AppProtoToString(i), app);
        }
    }

    if (add_mpm_stats) {
        json_t *mpm_js = json_object();

        for (i = 0; i < DETECT_SM_LIST_MAX; i++) {
            if (mpm_stats[i].cnt > 0) {

                json_t *mpm_sizes_array = json_array();
                for (x = 0; x < 256; x++) {
                    if (mpm_sizes[i][x] == 0)
                        continue;

                    json_t *e = json_object();
                    json_object_set_new(e, "size", json_integer(x));
                    json_object_set_new(e, "count", json_integer(mpm_sizes[i][x]));
                    json_array_append_new(mpm_sizes_array, e);
                }

                json_t *buf = json_object();
                json_object_set_new(buf, "total", json_integer(mpm_stats[i].cnt));
                json_object_set_new(buf, "avg_strength", json_integer(mpm_stats[i].total / mpm_stats[i].cnt));
                json_object_set_new(buf, "min_strength", json_integer(mpm_stats[i].min));
                json_object_set_new(buf, "max_strength", json_integer(mpm_stats[i].max));

                json_object_set_new(buf, "sizes", mpm_sizes_array);

                json_object_set_new(mpm_js, DetectListToHumanString(i), buf);
            }
        }

        json_object_set_new(stats, "mpm", mpm_js);
    }
    json_object_set_new(js, "stats", stats);

    json_object_set_new(js, "whitelist", json_integer(sgh->init->whitelist));

    return js;
}
#endif /* HAVE_LIBJANSSON */

static void RulesDumpGrouping(const DetectEngineCtx *de_ctx,
                       const int add_rules, const int add_mpm_stats)
{
#ifdef HAVE_LIBJANSSON
    json_t *js = json_object();
    if (unlikely(js == NULL))
        return;

    int p;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP) {
            const char *name = (p == IPPROTO_TCP) ? "tcp" : "udp";

            json_t *tcp = json_object();

            json_t *ts_array = json_array();
            DetectPort *list = (p == IPPROTO_TCP) ? de_ctx->flow_gh[1].tcp :
                                                    de_ctx->flow_gh[1].udp;
            while (list != NULL) {
                json_t *port = json_object();
                json_object_set_new(port, "port", json_integer(list->port));
                json_object_set_new(port, "port2", json_integer(list->port2));

                json_t *tcp_ts = RulesGroupPrintSghStats(list->sh,
                        add_rules, add_mpm_stats);
                json_object_set_new(port, "rulegroup", tcp_ts);
                json_array_append_new(ts_array, port);

                list = list->next;
            }
            json_object_set_new(tcp, "toserver", ts_array);

            json_t *tc_array = json_array();
            list = (p == IPPROTO_TCP) ? de_ctx->flow_gh[0].tcp :
                                        de_ctx->flow_gh[0].udp;
            while (list != NULL) {
                json_t *port = json_object();
                json_object_set_new(port, "port", json_integer(list->port));
                json_object_set_new(port, "port2", json_integer(list->port2));

                json_t *tcp_tc = RulesGroupPrintSghStats(list->sh,
                        add_rules, add_mpm_stats);
                json_object_set_new(port, "rulegroup", tcp_tc);
                json_array_append_new(tc_array, port);

                list = list->next;
            }
            json_object_set_new(tcp, "toclient", tc_array);

            json_object_set_new(js, name, tcp);
        }

    }

    const char *filename = "rule_group.json";
    const char *log_dir = ConfigGetLogDirectory();
    char log_path[PATH_MAX] = "";

    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, filename);

    FILE *fp = fopen(log_path, "w");
    if (fp == NULL) {
        return;
    }

    char *js_s = json_dumps(js,
                            JSON_PRESERVE_ORDER|JSON_ESCAPE_SLASH);
    if (unlikely(js_s == NULL)) {
        fclose(fp);
        return;
    }

    json_object_clear(js);
    json_decref(js);

    fprintf(fp, "%s\n", js_s);
    free(js_s);
    fclose(fp);
#endif
    return;
}

static int RulesGroupByProto(DetectEngineCtx *de_ctx)
{
    Signature *s = de_ctx->sig_list;

    uint32_t max_idx = 0;
    SigGroupHead *sgh_ts[256] = {NULL};
    SigGroupHead *sgh_tc[256] = {NULL};

    for ( ; s != NULL; s = s->next) {
        if (s->flags & SIG_FLAG_IPONLY)
            continue;

        int p;
        for (p = 0; p < 256; p++) {
            if (p == IPPROTO_TCP || p == IPPROTO_UDP) {
                continue;
            }
            if (!(s->proto.proto[p / 8] & (1<<(p % 8)) || (s->proto.flags & DETECT_PROTO_ANY))) {
                continue;
            }

            if (s->flags & SIG_FLAG_TOCLIENT) {
                SigGroupHeadAppendSig(de_ctx, &sgh_tc[p], s);
                max_idx = s->num;
            }
            if (s->flags & SIG_FLAG_TOSERVER) {
                SigGroupHeadAppendSig(de_ctx, &sgh_ts[p], s);
                max_idx = s->num;
            }
        }
    }
    SCLogDebug("max_idx %u", max_idx);

    /* lets look at deduplicating this list */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadHashInit(de_ctx);

    uint32_t cnt = 0;
    uint32_t own = 0;
    uint32_t ref = 0;
    int p;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;
        if (sgh_ts[p] == NULL)
            continue;

        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, sgh_ts[p]);
        if (lookup_sgh == NULL) {
            SCLogDebug("proto group %d sgh %p is the original", p, sgh_ts[p]);

            SigGroupHeadSetSigCnt(sgh_ts[p], max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, sgh_ts[p], max_idx);

            SigGroupHeadHashAdd(de_ctx, sgh_ts[p]);
            SigGroupHeadStore(de_ctx, sgh_ts[p]);

            de_ctx->gh_unique++;
            own++;
        } else {
            SCLogDebug("proto group %d sgh %p is a copy", p, sgh_ts[p]);

            SigGroupHeadFree(sgh_ts[p]);
            sgh_ts[p] = lookup_sgh;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
    SCLogPerf("OTHER %s: %u proto groups, %u unique SGH's, %u copies",
            "toserver", cnt, own, ref);

    cnt = 0;
    own = 0;
    ref = 0;
    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;
        if (sgh_tc[p] == NULL)
            continue;

        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, sgh_tc[p]);
        if (lookup_sgh == NULL) {
            SCLogDebug("proto group %d sgh %p is the original", p, sgh_tc[p]);

            SigGroupHeadSetSigCnt(sgh_tc[p], max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, sgh_tc[p], max_idx);

            SigGroupHeadHashAdd(de_ctx, sgh_tc[p]);
            SigGroupHeadStore(de_ctx, sgh_tc[p]);

            de_ctx->gh_unique++;
            own++;

        } else {
            SCLogDebug("proto group %d sgh %p is a copy", p, sgh_tc[p]);

            SigGroupHeadFree(sgh_tc[p]);
            sgh_tc[p] = lookup_sgh;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
    SCLogPerf("OTHER %s: %u proto groups, %u unique SGH's, %u copies",
            "toclient", cnt, own, ref);

    for (p = 0; p < 256; p++) {
        if (p == IPPROTO_TCP || p == IPPROTO_UDP)
            continue;

        de_ctx->flow_gh[0].sgh[p] = sgh_tc[p];
        de_ctx->flow_gh[1].sgh[p] = sgh_ts[p];
    }

    return 0;
}

static int PortIsWhitelisted(const DetectEngineCtx *de_ctx,
                             const DetectPort *a, int ipproto)
{
    DetectPort *w = de_ctx->tcp_whitelist;
    if (ipproto == IPPROTO_UDP)
        w = de_ctx->udp_whitelist;

    while (w) {
        if (a->port >= w->port && a->port2 <= w->port) {
            SCLogDebug("port group %u:%u whitelisted -> %d", a->port, a->port2, w->port);
            return 1;
        }
        w = w->next;
    }

    return 0;
}

static int RuleSetWhitelist(Signature *s)
{
    DetectPort *p = NULL;
    if (s->flags & SIG_FLAG_TOSERVER)
        p = s->dp;
    else if (s->flags & SIG_FLAG_TOCLIENT)
        p = s->sp;
    else
        return 0;

    /* for sigs that don't use 'any' as port, see if we want to
     * whitelist poor sigs */
    int wl = 0;
    if (!(p->port == 0 && p->port2 == 65535)) {
        /* pure pcre, bytetest, etc rules */
        if (RuleInspectsPayloadHasNoMpm(s)) {
            SCLogDebug("Rule %u MPM has 1 byte fast_pattern. Whitelisting SGH's.", s->id);
            wl = 99;

        } else if (RuleMpmIsNegated(s)) {
            SCLogDebug("Rule %u MPM is negated. Whitelisting SGH's.", s->id);
            wl = 77;

            /* one byte pattern in packet/stream payloads */
        } else if (s->init_data->mpm_sm != NULL &&
                   SigMatchListSMBelongsTo(s, s->init_data->mpm_sm) == DETECT_SM_LIST_PMATCH &&
                   RuleGetMpmPatternSize(s) == 1)
        {
            SCLogDebug("Rule %u No MPM. Payload inspecting. Whitelisting SGH's.", s->id);
            wl = 55;

        } else if (DetectFlagsSignatureNeedsSynPackets(s) &&
                   DetectFlagsSignatureNeedsSynOnlyPackets(s))
        {
            SCLogDebug("Rule %u Needs SYN, so inspected often. Whitelisting SGH's.", s->id);
            wl = 33;
        }
    }

    s->init_data->whitelist = wl;
    return wl;
}

int CreateGroupedPortList(DetectEngineCtx *de_ctx, DetectPort *port_list, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx);
int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b);

static DetectPort *RulesGroupByPorts(DetectEngineCtx *de_ctx, int ipproto, uint32_t direction) {
    /* step 1: create a hash of 'DetectPort' objects based on all the
     *         rules. Each object will have a SGH with the sigs added
     *         that belong to the SGH. */
    DetectPortHashInit(de_ctx);

    uint32_t max_idx = 0;
    const Signature *s = de_ctx->sig_list;
    DetectPort *list = NULL;
    while (s) {
        /* IP Only rules are handled separately */
        if (s->flags & SIG_FLAG_IPONLY)
            goto next;
        if (!(s->proto.proto[ipproto / 8] & (1<<(ipproto % 8)) || (s->proto.flags & DETECT_PROTO_ANY)))
            goto next;
        if (direction == SIG_FLAG_TOSERVER) {
            if (!(s->flags & SIG_FLAG_TOSERVER))
                goto next;
        } else if (direction == SIG_FLAG_TOCLIENT) {
            if (!(s->flags & SIG_FLAG_TOCLIENT))
                goto next;
        }

        DetectPort *p = NULL;
        if (direction == SIG_FLAG_TOSERVER)
            p = s->dp;
        else if (direction == SIG_FLAG_TOCLIENT)
            p = s->sp;
        else
            BUG_ON(1);

        /* see if we want to exclude directionless sigs that really care only for
         * to_server syn scans/floods */
        if ((direction == SIG_FLAG_TOCLIENT) &&
             DetectFlagsSignatureNeedsSynPackets(s) &&
             DetectFlagsSignatureNeedsSynOnlyPackets(s) &&
            ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) &&
            (!(s->dp->port == 0 && s->dp->port2 == 65535)))
        {
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: SYN-only to port(s) %u:%u "
                    "w/o direction specified, disabling for toclient direction",
                    s->id, s->dp->port, s->dp->port2);
            goto next;
        }

        int wl = s->init_data->whitelist;
        while (p) {
            int pwl = PortIsWhitelisted(de_ctx, p, ipproto) ? 111 : 0;
            pwl = MAX(wl,pwl);

            DetectPort *lookup = DetectPortHashLookup(de_ctx, p);
            if (lookup) {
                SigGroupHeadAppendSig(de_ctx, &lookup->sh, s);
                lookup->sh->init->whitelist = MAX(lookup->sh->init->whitelist, pwl);
            } else {
                DetectPort *tmp2 = DetectPortCopySingle(de_ctx, p);
                BUG_ON(tmp2 == NULL);
                SigGroupHeadAppendSig(de_ctx, &tmp2->sh, s);
                tmp2->sh->init->whitelist = pwl;
                DetectPortHashAdd(de_ctx, tmp2);
            }

            p = p->next;
        }
        max_idx = s->num;
    next:
        s = s->next;
    }

    /* step 2: create a list of DetectPort objects */
    HashListTableBucket *htb = NULL;
    for (htb = HashListTableGetListHead(de_ctx->dport_hash_table);
            htb != NULL;
            htb = HashListTableGetListNext(htb))
    {
        DetectPort *p = HashListTableGetListData(htb);
        DetectPort *tmp = DetectPortCopySingle(de_ctx, p);
        BUG_ON(tmp == NULL);
        int r = DetectPortInsert(de_ctx, &list , tmp);
        BUG_ON(r == -1);
    }
    DetectPortHashFree(de_ctx);
    de_ctx->dport_hash_table = NULL;

    SCLogDebug("rules analyzed");

    /* step 3: group the list and shrink it if necessary */
    DetectPort *newlist = NULL;
    uint16_t groupmax = (direction == SIG_FLAG_TOCLIENT) ? de_ctx->max_uniq_toclient_groups :
                                                           de_ctx->max_uniq_toserver_groups;
    CreateGroupedPortList(de_ctx, list, &newlist, groupmax, CreateGroupedPortListCmpCnt, max_idx);
    list = newlist;

    /* step 4: deduplicate the SGH's */
    SigGroupHeadHashFree(de_ctx);
    SigGroupHeadHashInit(de_ctx);

    uint32_t cnt = 0;
    uint32_t own = 0;
    uint32_t ref = 0;
    DetectPort *iter;
    for (iter = list ; iter != NULL; iter = iter->next) {
        BUG_ON (iter->sh == NULL);
        cnt++;

        SigGroupHead *lookup_sgh = SigGroupHeadHashLookup(de_ctx, iter->sh);
        if (lookup_sgh == NULL) {
            SCLogDebug("port group %p sgh %p is the original", iter, iter->sh);

            SigGroupHeadSetSigCnt(iter->sh, max_idx);
            SigGroupHeadBuildMatchArray(de_ctx, iter->sh, max_idx);
            SigGroupHeadSetProtoAndDirection(iter->sh, ipproto, direction);
            SigGroupHeadHashAdd(de_ctx, iter->sh);
            SigGroupHeadStore(de_ctx, iter->sh);
            iter->flags |= PORT_SIGGROUPHEAD_COPY;
            de_ctx->gh_unique++;
            own++;
        } else {
            SCLogDebug("port group %p sgh %p is a copy", iter, iter->sh);

            SigGroupHeadFree(iter->sh);
            iter->sh = lookup_sgh;
            iter->flags |= PORT_SIGGROUPHEAD_COPY;

            de_ctx->gh_reuse++;
            ref++;
        }
    }
#if 0
    for (iter = list ; iter != NULL; iter = iter->next) {
        SCLogInfo("PORT %u-%u %p (sgh=%s, whitelisted=%s/%d)",
                iter->port, iter->port2, iter->sh,
                iter->flags & PORT_SIGGROUPHEAD_COPY ? "ref" : "own",
                iter->sh->init->whitelist ? "true" : "false",
                iter->sh->init->whitelist);
    }
#endif
    SCLogPerf("%s %s: %u port groups, %u unique SGH's, %u copies",
            ipproto == 6 ? "TCP" : "UDP",
            direction == SIG_FLAG_TOSERVER ? "toserver" : "toclient",
            cnt, own, ref);
    return list;
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
    const int nlists = DetectBufferTypeMaxId();

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("building signature grouping structure, stage 1: "
                   "preprocessing rules...");
    }

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

        /* see if the sig is dp only */
        if (SignatureIsPDOnly(tmp_s) == 1) {
            tmp_s->flags |= SIG_FLAG_PDONLY;
            SCLogDebug("Signature %"PRIu32" is considered \"PD only\"", tmp_s->id);

        /* see if the sig is ip only */
        } else if (SignatureIsIPOnly(de_ctx, tmp_s) == 1) {
            tmp_s->flags |= SIG_FLAG_IPONLY;
            cnt_iponly++;

            SCLogDebug("Signature %"PRIu32" is considered \"IP only\"", tmp_s->id);

        /* see if any sig is inspecting the packet payload */
        } else if (SignatureIsInspectingPayload(de_ctx, tmp_s) == 1) {
            cnt_payload++;

            SCLogDebug("Signature %"PRIu32" is considered \"Payload inspecting\"", tmp_s->id);
        } else if (SignatureIsDEOnly(de_ctx, tmp_s) == 1) {
            tmp_s->init_data->init_flags |= SIG_FLAG_INIT_DEONLY;
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
            for (sm = tmp_s->init_data->smlists[DETECT_SM_LIST_MATCH]; sm != NULL; sm = sm->next) {
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

        if (RuleMpmIsNegated(tmp_s)) {
            tmp_s->flags |= SIG_FLAG_MPM_NEG;
        }

        SignatureCreateMask(tmp_s);
        SigParseApplyDsizeToContent(tmp_s);

        RuleSetWhitelist(tmp_s);

        /* if keyword engines are enabled in the config, handle them here */
        if (de_ctx->prefilter_setting == DETECT_PREFILTER_AUTO &&
            !(tmp_s->flags & SIG_FLAG_PREFILTER))
        {
            int i;
            int prefilter_list = DETECT_TBLSIZE;

            /* get the keyword supporting prefilter with the lowest type */
            for (i = 0; i < nlists; i++) {
                SigMatch *sm = tmp_s->init_data->smlists[i];
                while (sm != NULL) {
                    if (sigmatch_table[sm->type].SupportsPrefilter != NULL) {
                        if (sigmatch_table[sm->type].SupportsPrefilter(tmp_s) == TRUE) {
                            prefilter_list = MIN(prefilter_list, sm->type);
                        }
                    }
                    sm = sm->next;
                }
            }

            /* apply that keyword as prefilter */
            if (prefilter_list != DETECT_TBLSIZE) {
                for (i = 0; i < nlists; i++) {
                    SigMatch *sm = tmp_s->init_data->smlists[i];
                    while (sm != NULL) {
                        if (sm->type == prefilter_list) {
                            tmp_s->init_data->prefilter_sm = sm;
                            tmp_s->flags |= SIG_FLAG_PREFILTER;
                            SCLogConfig("sid %u: prefilter is on \"%s\"", tmp_s->id, sigmatch_table[sm->type].name);
                            break;
                        }
                        sm = sm->next;
                    }
                }
            }
        }

        /* run buffer type callbacks if any */
        int x;
        for (x = 0; x < nlists; x++) {
            if (tmp_s->init_data->smlists[x])
                DetectBufferRunSetupCallback(x, tmp_s);
        }

        de_ctx->sig_cnt++;
    }

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogInfo("%" PRIu32 " signatures processed. %" PRIu32 " are IP-only "
                "rules, %" PRIu32 " are inspecting packet payload, %"PRIu32
                " inspect application layer, %"PRIu32" are decoder event only",
                de_ctx->sig_cnt, cnt_iponly, cnt_payload, cnt_applayer,
                cnt_deonly);

        SCLogConfig("building signature grouping structure, stage 1: "
               "preprocessing rules... complete");
    }
    return 0;

error:
    return -1;
}

static int PortGroupWhitelist(const DetectPort *a)
{
    return a->sh->init->whitelist;
}

int CreateGroupedPortListCmpCnt(DetectPort *a, DetectPort *b)
{
    if (PortGroupWhitelist(a) && !PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)",
                a->port, a->port2, a->sh->sig_cnt, PortGroupWhitelist(a),
                b->port, b->port2, b->sh->sig_cnt, PortGroupWhitelist(b));
        return 1;
    } else if (!PortGroupWhitelist(a) && PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) loses against %u:%u (cnt %u, wl %d)",
                a->port, a->port2, a->sh->sig_cnt, PortGroupWhitelist(a),
                b->port, b->port2, b->sh->sig_cnt, PortGroupWhitelist(b));
        return 0;
    } else if (PortGroupWhitelist(a) > PortGroupWhitelist(b)) {
        SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)",
                a->port, a->port2, a->sh->sig_cnt, PortGroupWhitelist(a),
                b->port, b->port2, b->sh->sig_cnt, PortGroupWhitelist(b));
        return 1;
    } else if (PortGroupWhitelist(a) == PortGroupWhitelist(b)) {
        if (a->sh->sig_cnt > b->sh->sig_cnt) {
            SCLogDebug("%u:%u (cnt %u, wl %d) wins against %u:%u (cnt %u, wl %d)",
                    a->port, a->port2, a->sh->sig_cnt, PortGroupWhitelist(a),
                    b->port, b->port2, b->sh->sig_cnt, PortGroupWhitelist(b));
            return 1;
        }
    }

    SCLogDebug("%u:%u (cnt %u, wl %d) loses against %u:%u (cnt %u, wl %d)",
            a->port, a->port2, a->sh->sig_cnt, PortGroupWhitelist(a),
            b->port, b->port2, b->sh->sig_cnt, PortGroupWhitelist(b));
    return 0;
}

/** \internal
 *  \brief Create a list of DetectPort objects sorted based on CompareFunc's
 *         logic.
 *
 *  List can limit the number of groups. In this case an extra "join" group
 *  is created that contains the sigs belonging to that. It's *appended* to
 *  the list, meaning that if the list is walked linearly it's found last.
 *  The joingr is meant to be a catch all.
 *
 */
int CreateGroupedPortList(DetectEngineCtx *de_ctx, DetectPort *port_list, DetectPort **newhead, uint32_t unique_groups, int (*CompareFunc)(DetectPort *, DetectPort *), uint32_t max_idx)
{
    DetectPort *tmplist = NULL, *joingr = NULL;
    char insert = 0;
    uint32_t groups = 0;
    DetectPort *list;

   /* insert the addresses into the tmplist, where it will
     * be sorted descending on 'cnt' and on wehther a group
     * is whitelisted. */

    DetectPort *oldhead = port_list;
    while (oldhead) {
        /* take the top of the list */
        list = oldhead;
        oldhead = oldhead->next;
        list->next = NULL;

        groups++;

        SigGroupHeadSetSigCnt(list->sh, max_idx);

        /* insert it */
        DetectPort *tmpgr = tmplist, *prevtmpgr = NULL;
        if (tmplist == NULL) {
            /* empty list, set head */
            tmplist = list;
        } else {
            /* look for the place to insert */
            for ( ; tmpgr != NULL && !insert; tmpgr = tmpgr->next) {
                if (CompareFunc(list, tmpgr) == 1) {
                    if (tmpgr == tmplist) {
                        list->next = tmplist;
                        tmplist = list;
                        SCLogDebug("new list top: %u:%u", tmplist->port, tmplist->port2);
                    } else {
                        list->next = prevtmpgr->next;
                        prevtmpgr->next = list;
                    }
                    insert = 1;
                    break;
                }
                prevtmpgr = tmpgr;
            }
            if (insert == 0) {
                list->next = NULL;
                prevtmpgr->next = list;
            }
            insert = 0;
        }
    }

    uint32_t left = unique_groups;
    if (left == 0)
        left = groups;

    /* create another list: take the port groups from above
     * and add them to the 2nd list until we have met our
     * count. The rest is added to the 'join' group. */
    DetectPort *tmplist2 = NULL, *tmplist2_tail = NULL;
    DetectPort *gr, *next_gr;
    for (gr = tmplist; gr != NULL; ) {
        next_gr = gr->next;

        SCLogDebug("temp list gr %p %u:%u", gr, gr->port, gr->port2);
        DetectPortPrint(gr);

        /* if we've set up all the unique groups, add the rest to the
         * catch-all joingr */
        if (left == 0) {
            if (joingr == NULL) {
                DetectPortParse(de_ctx, &joingr, "0:65535");
                if (joingr == NULL) {
                    goto error;
                }
                SCLogDebug("joingr => %u-%u", joingr->port, joingr->port2);
                joingr->next = NULL;
            }
            SigGroupHeadCopySigs(de_ctx,gr->sh,&joingr->sh);

            /* when a group's sigs are added to the joingr, we can free it */
            gr->next = NULL;
            DetectPortFree(gr);
            gr = NULL;

        /* append */
        } else {
            gr->next = NULL;

            if (tmplist2 == NULL) {
                tmplist2 = gr;
                tmplist2_tail = gr;
            } else {
                tmplist2_tail->next = gr;
                tmplist2_tail = gr;
            }
        }

        if (left > 0)
            left--;

        gr = next_gr;
    }

    /* if present, append the joingr that covers the rest */
    if (joingr != NULL) {
        SCLogDebug("appending joingr %p %u:%u", joingr, joingr->port, joingr->port2);

        if (tmplist2 == NULL) {
            tmplist2 = joingr;
            //tmplist2_tail = joingr;
        } else {
            tmplist2_tail->next = joingr;
            //tmplist2_tail = joingr;
        }
    } else {
        SCLogDebug("no joingr");
    }

    /* pass back our new list to the caller */
    *newhead = tmplist2;
    DetectPortPrintList(*newhead);

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

    de_ctx->flow_gh[1].tcp = RulesGroupByPorts(de_ctx, IPPROTO_TCP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].tcp = RulesGroupByPorts(de_ctx, IPPROTO_TCP, SIG_FLAG_TOCLIENT);
    de_ctx->flow_gh[1].udp = RulesGroupByPorts(de_ctx, IPPROTO_UDP, SIG_FLAG_TOSERVER);
    de_ctx->flow_gh[0].udp = RulesGroupByPorts(de_ctx, IPPROTO_UDP, SIG_FLAG_TOCLIENT);

    /* Setup the other IP Protocols (so not TCP/UDP) */
    RulesGroupByProto(de_ctx);

    /* now for every rule add the source group to our temp lists */
    for (tmp_s = de_ctx->sig_list; tmp_s != NULL; tmp_s = tmp_s->next) {
        SCLogDebug("tmp_s->id %"PRIu32, tmp_s->id);
        if (tmp_s->flags & SIG_FLAG_IPONLY) {
            IPOnlyAddSignature(de_ctx, &de_ctx->io_ctx, tmp_s);
        }

        if (tmp_s->init_data->init_flags & SIG_FLAG_INIT_DEONLY) {
            DetectEngineAddDecoderEventSig(de_ctx, tmp_s);
        }

        sigs++;
    }

    IPOnlyPrepare(de_ctx);
    IPOnlyPrint(de_ctx, &de_ctx->io_ctx);

    return 0;
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
    /* prepare the decoder event sgh */
    DetectEngineBuildDecoderEventSgh(de_ctx);
    return 0;
}

int SigAddressCleanupStage1(DetectEngineCtx *de_ctx)
{
    BUG_ON(de_ctx == NULL);

    if (!(de_ctx->flags & DE_QUIET)) {
        SCLogDebug("cleaning up signature grouping structure...");
    }
    if (de_ctx->decoder_event_sgh)
        SigGroupHeadFree(de_ctx->decoder_event_sgh);
    de_ctx->decoder_event_sgh = NULL;

    int f;
    for (f = 0; f < FLOW_STATES; f++) {
        int p;
        for (p = 0; p < 256; p++) {
            de_ctx->flow_gh[f].sgh[p] = NULL;
        }

        /* free lookup lists */
        DetectPortCleanupList(de_ctx->flow_gh[f].tcp);
        de_ctx->flow_gh[f].tcp = NULL;
        DetectPortCleanupList(de_ctx->flow_gh[f].udp);
        de_ctx->flow_gh[f].udp = NULL;
    }

    uint32_t idx;
    for (idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;

        SCLogDebug("sgh %p", sgh);
        SigGroupHeadFree(sgh);
    }
    SCFree(de_ctx->sgh_array);
    de_ctx->sgh_array = NULL;
    de_ctx->sgh_array_cnt = 0;
    de_ctx->sgh_array_size = 0;

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

/** \brief finalize preparing sgh's */
int SigAddressPrepareStage4(DetectEngineCtx *de_ctx)
{
    SCEnter();

    //SCLogInfo("sgh's %"PRIu32, de_ctx->sgh_array_cnt);

    uint32_t cnt = 0;
    uint32_t idx = 0;
    for (idx = 0; idx < de_ctx->sgh_array_cnt; idx++) {
        SigGroupHead *sgh = de_ctx->sgh_array[idx];
        if (sgh == NULL)
            continue;

        SCLogDebug("sgh %p", sgh);

        SigGroupHeadSetFilemagicFlag(de_ctx, sgh);
        SigGroupHeadSetFileHashFlag(de_ctx, sgh);
        SigGroupHeadSetFilesizeFlag(de_ctx, sgh);
        SigGroupHeadSetFilestoreCount(de_ctx, sgh);
        SCLogDebug("filestore count %u", sgh->filestore_cnt);

        PrefilterSetupRuleGroup(de_ctx, sgh);

        SigGroupHeadBuildNonPrefilterArray(de_ctx, sgh);

        sgh->id = idx;
        cnt++;
    }
    SCLogPerf("Unique rule groups: %u", cnt);

    MpmStoreReportStats(de_ctx);

    if (de_ctx->decoder_event_sgh != NULL) {
        /* no need to set filestore count here as that would make a
         * signature not decode event only. */
    }

    /* cleanup the hashes now since we won't need them
     * after the initialization phase. */
    SigGroupHeadHashFree(de_ctx);

    int dump_grouping = 0;
    (void)ConfGetBool("detect.profiling.grouping.dump-to-disk", &dump_grouping);

    if (dump_grouping) {
        int add_rules = 0;
        (void)ConfGetBool("detect.profiling.grouping.include-rules", &add_rules);
        int add_mpm_stats = 0;
        (void)ConfGetBool("detect.profiling.grouping.include-mpm-stats", &add_rules);

        RulesDumpGrouping(de_ctx, add_rules, add_mpm_stats);
    }

#ifdef PROFILING
    SCProfilingSghInitCounters(de_ctx);
#endif
    SCReturnInt(0);
}

/** \internal
 *  \brief perform final per signature setup tasks
 *
 *  - Create SigMatchData arrays from the init only SigMatch lists
 *  - Setup per signature inspect engines
 *  - remove signature init data.
 */
static int SigMatchPrepare(DetectEngineCtx *de_ctx)
{
    SCEnter();

    const int nlists = DetectBufferTypeMaxId();
    Signature *s = de_ctx->sig_list;
    for (; s != NULL; s = s->next) {
        /* set up inspect engines */
        DetectEngineAppInspectionEngine2Signature(s);

        /* built-ins */
        int type;
        for (type = 0; type < DETECT_SM_LIST_MAX; type++) {
            SigMatch *sm = s->init_data->smlists[type];
            s->sm_arrays[type] = SigMatchList2DataArray(sm);
        }

        /* free lists. Ctx' are xferred to sm_arrays so won't get freed */
        int i;
        for (i = 0; i < nlists; i++) {
            SigMatch *sm = s->init_data->smlists[i];
            while (sm != NULL) {
                SigMatch *nsm = sm->next;
                SigMatchFree(sm);
                sm = nsm;
            }
        }
        SCFree(s->init_data->smlists);
        SCFree(s->init_data->smlists_tail);
        SCFree(s->init_data);
        s->init_data = NULL;
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

    SigInitStandardMpmFactoryContexts(de_ctx);

    if (SigAddressPrepareStage1(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

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

#ifdef __SC_CUDA_SUPPORT__
    if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
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
    }
#endif

    int r = DetectMpmPrepareBuiltinMpms(de_ctx);
    r |= DetectMpmPrepareAppMpms(de_ctx);
    if (r != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

    if (SigMatchPrepare(de_ctx) != 0) {
        SCLogError(SC_ERR_DETECT_PREPARE, "initializing the detection engine failed");
        exit(EXIT_FAILURE);
    }

#ifdef PROFILING
    SCProfilingRuleInitCounters(de_ctx);
#endif
    SCFree(de_ctx->app_mpms);
    de_ctx->app_mpms = NULL;

    if (!DetectEngineMultiTenantEnabled()) {
        VarNameStoreActivateStaging();
    }
    return 0;
}

int SigGroupCleanup (DetectEngineCtx *de_ctx)
{
    SigAddressCleanupStage1(de_ctx);

    return 0;
}

static void PrintFeatureList(const SigTableElmt *e, char sep)
{
    const uint8_t flags = e->flags;

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
    if (e->SupportsPrefilter) {
        if (prev == 1)
            printf("%c", sep);
        printf("prefilter");
        prev = 1;
    }
    if (prev == 0) {
        printf("none");
    }
}

static void SigMultilinePrint(int i, const char *prefix)
{
    if (sigmatch_table[i].desc) {
        printf("%sDescription: %s\n", prefix, sigmatch_table[i].desc);
    }
    printf("%sFeatures: ", prefix);
    PrintFeatureList(&sigmatch_table[i], ',');
    if (sigmatch_table[i].url) {
        printf("\n%sDocumentation: %s", prefix, sigmatch_table[i].url);
    }
    printf("\n");
}

void SigTableList(const char *keyword)
{
    size_t size = sizeof(sigmatch_table) / sizeof(SigTableElmt);
    size_t i;

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
    } else if (strcmp("csv", keyword) == 0) {
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
                printf(";Unset;"); // this used to be alproto
                PrintFeatureList(&sigmatch_table[i], ':');
                printf(";");
                if (sigmatch_table[i].url) {
                    printf("%s", sigmatch_table[i].url);
                }
                printf(";");
                printf("\n");
            }
        }
    } else if (strcmp("all", keyword) == 0) {
        for (i = 0; i < size; i++) {
            if (sigmatch_table[i].name != NULL) {
                printf("%s:\n", sigmatch_table[i].name);
                SigMultilinePrint(i, "\t");
            }
        }
    } else {
        for (i = 0; i < size; i++) {
            if ((sigmatch_table[i].name != NULL) &&
                strcmp(sigmatch_table[i].name, keyword) == 0) {
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
    DetectPrefilterRegister();
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

    /* NOTE: the order of these currently affects inspect
     * engine registration order and ultimately the order
     * of inspect engines in the rule. Which in turn affects
     * state keeping */
    DetectHttpUriRegister();
    DetectHttpRequestLineRegister();
    DetectHttpClientBodyRegister();
    DetectHttpResponseLineRegister();
    DetectHttpServerBodyRegister();
    DetectHttpHeaderRegister();
    DetectHttpHeaderNamesRegister();
    DetectHttpHeadersRegister();
    DetectHttpProtocolRegister();
    DetectHttpStartRegister();
    DetectHttpRawHeaderRegister();
    DetectHttpMethodRegister();
    DetectHttpCookieRegister();
    DetectHttpRawUriRegister();

    DetectFilenameRegister();
    DetectFileextRegister();
    DetectFilestoreRegister();
    DetectFilemagicRegister();
    DetectFileMd5Register();
    DetectFileSha1Register();
    DetectFileSha256Register();
    DetectFilesizeRegister();

    DetectHttpUARegister();
    DetectHttpHHRegister();
    DetectHttpHRHRegister();

    DetectHttpStatMsgRegister();
    DetectHttpStatCodeRegister();

    DetectDnsQueryRegister();
    DetectModbusRegister();
    DetectCipServiceRegister();
    DetectEnipCommandRegister();
    DetectDNP3Register();

    DetectTlsSniRegister();
    DetectTlsIssuerRegister();
    DetectTlsSubjectRegister();
    DetectTlsSerialRegister();

    DetectAppLayerEventRegister();
    /* end of order dependent regs */

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
    DetectTlsRegister();
    DetectTlsValidityRegister();
    DetectTlsVersionRegister();
    DetectNfsProcedureRegister();
    DetectNfsVersionRegister();
    DetectUrilenRegister();
    DetectDetectionFilterRegister();
    DetectAsn1Register();
    DetectSshProtocolRegister();
    DetectSshVersionRegister();
    DetectSshSoftwareRegister();
    DetectSshSoftwareVersionRegister();
    DetectSslStateRegister();
    DetectSslVersionRegister();
    DetectByteExtractRegister();
    DetectFiledataRegister();
    DetectPktDataRegister();
    DetectLuaRegister();
    DetectIPRepRegister();
    DetectAppLayerProtocolRegister();
    DetectBase64DecodeRegister();
    DetectBase64DataRegister();
    DetectTemplateRegister();
    DetectTargetRegister();
    DetectTemplateBufferRegister();
    DetectBypassRegister();
    DetectHttpRequestLineRegister();
    DetectHttpResponseLineRegister();

    /* close keyword registration */
    DetectBufferTypeFinalizeRegistration();
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

static int SigTest01 (void)
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
    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
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

static int SigTest02 (void)
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
    int ret = UTHPacketMatchSigMpm(p, sig, MPM_AC);
    UTHFreePacket(p);
    return ret;
}

static int SigTest03 (void)
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

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"HTTP TEST\"; content:\"Host: one.example.org\"; offset:20; depth:39; sid:1;)");
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

static int SigTest04 (void)
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

static int SigTest05 (void)
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

static int SigTest06 (void)
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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

static int SigTest07 (void)
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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int SigTest08 (void)
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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

static int SigTest09 (void)
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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

static int SigTest10 (void)
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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, buf, buflen);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        result = 0;
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

static int SigTest11 (void)
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

static int SigTest12 (void)
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

static int SigTest13 (void)
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

static int SigTest14 (void)
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

static int SigTest15 (void)
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

static int SigTest16 (void)
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

static int SigTest17 (void)
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
    memset(&th_v, 0, sizeof(th_v));

    p = UTHBuildPacketSrcDstPorts((uint8_t *)buf, buflen, IPPROTO_TCP, 12345, 80);
    FAIL_IF_NULL(p);

    ConfCreateContextBackup();
    ConfInit();
    ConfYamlLoadString(dummy_conf_string, strlen(dummy_conf_string));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any $HTTP_PORTS (msg:\"HTTP host cap\"; content:\"Host:\"; pcre:\"/^Host: (?P<pkt_http_host>.*)\\r\\n/m\"; noalert; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    uint32_t capid = VarNameStoreLookupByName("http_host", VAR_TYPE_PKT_VAR);

    PktVar *pv_hn = PktVarGet(p, capid);
    FAIL_IF_NULL(pv_hn);

    FAIL_IF(pv_hn->value_len != 15);
    FAIL_IF_NOT(memcmp(pv_hn->value, "one.example.org", pv_hn->value_len) == 0);

    PktVarFree(pv_hn);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ConfDeInit();
    ConfRestoreContextBackup();
    UTHFreePackets(&p, 1);

    PASS;
}

static int SigTest18 (void)
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

static int SigTest19 (void)
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

static int SigTest20 (void)
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

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert ip $HOME_NET any -> [99.99.99.99,1.2.3.0/24,1.1.1.1,3.0.0.0/8] any (msg:\"IP-ONLY test (2)\"; sid:999; rev:1;)");
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
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
end:
    ConfDeInit();
    ConfRestoreContextBackup();
    SCFree(p);
    return result;
}

static int SigTest21 (void)
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

static int SigTest22 (void)
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
    DetectEngineCtxFree(de_ctx);
end:
    UTHFreePackets(&p1, 1);
    UTHFreePackets(&p2, 1);
    FLOW_DESTROY(&f);
    return result;
}

static int SigTest23 (void)
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

static int SigTest24IPV4Keyword(void)
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

static int SigTest25NegativeIPV4Keyword(void)
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

static int SigTest26TCPV4Keyword(void)
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
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any "
                               "(content:\"|DE 01 03|\"; tcpv4-csum:valid; dsize:20; "
                               "msg:\"tcpv4-csum keyword check(1)\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert ip any any -> any any "
                                     "(content:\"|DE 01 03|\"; tcpv4-csum:invalid; "
                                     "msg:\"tcpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(!(PacketAlertCheck(p1, 1)));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(!(PacketAlertCheck(p2, 2)));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    PASS;
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

static int SigTest28TCPV6Keyword(void)
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

static int SigTest29NegativeTCPV6Keyword(void)
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

static int SigTest30UDPV4Keyword(void)
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
    FAIL_IF_NULL(p1);
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p2);

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

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
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv4-csum:valid; "
                               "msg:\"udpv4-csum keyword check(1)\"; "
                               "sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv4-csum:invalid; "
                                     "msg:\"udpv4-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 2));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p1);
    SCFree(p2);
    PASS;
}

static int SigTest31NegativeUDPV4Keyword(void)
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


static int SigTest32UDPV6Keyword(void)
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
    FAIL_IF_NULL(p1);
    Packet *p2 = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p2);

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

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
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert udp any any -> any any "
                               "(content:\"/one/\"; udpv6-csum:valid; "
                               "msg:\"udpv6-csum keyword check(1)\"; sid:1;)");
    FAIL_IF_NULL(de_ctx->sig_list);

    de_ctx->sig_list->next = SigInit(de_ctx,
                                     "alert udp any any -> any any "
                                     "(content:\"/one/\"; udpv6-csum:invalid; "
                                     "msg:\"udpv6-csum keyword check(1)\"; "
                                     "sid:2;)");
    FAIL_IF_NULL(de_ctx->sig_list->next);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx,(void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1));

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketAlertCheck(p2, 2));

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    if (det_ctx != NULL)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    SCFree(p1);
    SCFree(p2);
    PASS;
}

static int SigTest33NegativeUDPV6Keyword(void)
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

static int SigTest34ICMPV4Keyword(void)
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

static int SigTest35NegativeICMPV4Keyword(void)
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

static int SigTest38(void)
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

static int SigTest39(void)
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

/**
 * \test SigTest36ContentAndIsdataatKeywords01 is a test to check window with constructed packets,
 * \brief expecting to match a size
 */

static int SigTest36ContentAndIsdataatKeywords01 (void)
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

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"SigTest36ContentAndIsdataatKeywords01 \"; content:\"HTTP\"; isdataat:404, relative; sid:101;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
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

static int SigTest37ContentAndIsdataatKeywords02 (void)
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

/**
 * \test SigTest41NoPacketInspection is a test to check that when PKT_NOPACKET_INSPECTION
 *  flag is set, we don't need to inspect the packet protocol header or its contents.
 */

static int SigTest40NoPacketInspection01(void)
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

static int SigTest40NoPayloadInspection02(void)
{

    uint8_t *buf = (uint8_t *)
                    "220 (vsFTPd 2.0.5)\r\n";
    uint16_t buflen = strlen((char *)buf);
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    FAIL_IF_NULL(p);
    memset(p, 0, SIZE_OF_PACKET);

    p->src.family = AF_INET;
    p->dst.family = AF_INET;
    p->payload = buf;
    p->payload_len = buflen;
    p->proto = IPPROTO_TCP;
    p->flags |= PKT_NOPAYLOAD_INSPECTION;

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"No Payload TEST\"; content:\"220 (vsFTPd 2.0.5)\"; sid:1;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1));

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    SCFree(p);
    PASS;
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

    SigGroupCleanup(de_ctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

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

    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

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

    SigGroupCleanup(de_ctx);
    DetectEngineCtxFree(de_ctx);

    result = 1;
end:
    return result;
}

static int SigTestContent01 (void)
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

static int SigTestContent02 (void)
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

static int SigTestContent03 (void)
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

static int SigTestContent04 (void)
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

/** \test sigs with patterns at the limit of the pm's size limit */
static int SigTestContent05 (void)
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

static int SigTestContent06 (void)
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

static int SigTestWithin01 (void)
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

static int SigTestDepthOffset01 (void)
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

static int SigTestDetectAlertCounter(void)
{
    Packet *p = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    memset(&tv, 0, sizeof(tv));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"Test counter\"; "
                               "content:\"boo\"; sid:1;)");
    FAIL_IF(de_ctx->sig_list == NULL);

    SigGroupBuild(de_ctx);
    strlcpy(tv.name, "detect_test", sizeof(tv.name));
    DetectEngineThreadCtxInit(&tv, de_ctx, (void *)&det_ctx);
    /* init counters */
    StatsSetupPrivate(&tv);

    p = UTHBuildPacket((uint8_t *)"boo", strlen("boo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 1);

    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"roo", strlen("roo"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 2);
    UTHFreePackets(&p, 1);

    p = UTHBuildPacket((uint8_t *)"laboosa", strlen("laboosa"), IPPROTO_TCP);
    Detect(&tv, p, det_ctx, NULL, NULL);
    FAIL_IF_NOT(StatsGetLocalCounterValue(&tv, det_ctx->counter_alerts) == 3);
    UTHFreePackets(&p, 1);

    DetectEngineThreadCtxDeinit(&tv, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
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
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop http any any -> any any "
                                   "(msg:\"Test proto match\"; "
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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
    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx, "drop tcp any any -> any 80 "
                                   "(msg:\"Test proto match\"; uricontent:\"one\";"
                                   "sid:1;)");
    if (s == NULL) {
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

    FLOWLOCK_WRLOCK(&f);
    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                                STREAM_TOSERVER, http_buf1, http_buf1_len);
    if (r != 0) {
        printf("toserver chunk 1 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_HTTP,
                            STREAM_TOSERVER, http_buf2, http_buf2_len);
    if (r != 0) {
        printf("toserver chunk 2 returned %" PRId32 ", expected 0: ", r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

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

    UtRegisterTest("SigTest01", SigTest01);
    UtRegisterTest("SigTest02 -- Offset/Depth match", SigTest02);
    UtRegisterTest("SigTest03 -- offset/depth mismatch", SigTest03);
    UtRegisterTest("SigTest04 -- distance/within match", SigTest04);
    UtRegisterTest("SigTest05 -- distance/within mismatch", SigTest05);
    UtRegisterTest("SigTest06 -- uricontent HTTP/1.1 match test", SigTest06);
    UtRegisterTest("SigTest07 -- uricontent HTTP/1.1 mismatch test",
                   SigTest07);
    UtRegisterTest("SigTest08 -- uricontent HTTP/1.0 match test", SigTest08);
    UtRegisterTest("SigTest09 -- uricontent HTTP/1.0 mismatch test",
                   SigTest09);
    UtRegisterTest("SigTest10 -- long content match, longer than pkt",
                   SigTest10);
    UtRegisterTest("SigTest11 -- mpm searching", SigTest11);
    UtRegisterTest("SigTest12 -- content order matching, normal", SigTest12);
    UtRegisterTest("SigTest13 -- content order matching, diff order",
                   SigTest13);
    UtRegisterTest("SigTest14 -- content order matching, distance 0",
                   SigTest14);
    UtRegisterTest("SigTest15 -- port negation sig (no match)", SigTest15);
    UtRegisterTest("SigTest16 -- port negation sig (match)", SigTest16);
    UtRegisterTest("SigTest17 -- HTTP Host Pkt var capture", SigTest17);
    UtRegisterTest("SigTest18 -- Ftp negation sig test", SigTest18);
    UtRegisterTest("SigTest19 -- IP-ONLY test (1)", SigTest19);
    UtRegisterTest("SigTest20 -- IP-ONLY test (2)", SigTest20);
    UtRegisterTest("SigTest21 -- FLOWBIT test (1)", SigTest21);
    UtRegisterTest("SigTest22 -- FLOWBIT test (2)", SigTest22);
    UtRegisterTest("SigTest23 -- FLOWBIT test (3)", SigTest23);

    UtRegisterTest("SigTest24IPV4Keyword", SigTest24IPV4Keyword);
    UtRegisterTest("SigTest25NegativeIPV4Keyword",
                   SigTest25NegativeIPV4Keyword);

    UtRegisterTest("SigTest26TCPV4Keyword", SigTest26TCPV4Keyword);
    UtRegisterTest("SigTest26TCPV4AndNegativeIPV4Keyword",
                   SigTest26TCPV4AndNegativeIPV4Keyword);
    UtRegisterTest("SigTest26TCPV4AndIPV4Keyword",
                   SigTest26TCPV4AndIPV4Keyword);
    UtRegisterTest("SigTest27NegativeTCPV4Keyword",
                   SigTest27NegativeTCPV4Keyword);

    UtRegisterTest("SigTest28TCPV6Keyword", SigTest28TCPV6Keyword);
    UtRegisterTest("SigTest29NegativeTCPV6Keyword",
                   SigTest29NegativeTCPV6Keyword);

    UtRegisterTest("SigTest30UDPV4Keyword", SigTest30UDPV4Keyword);
    UtRegisterTest("SigTest31NegativeUDPV4Keyword",
                   SigTest31NegativeUDPV4Keyword);

    UtRegisterTest("SigTest32UDPV6Keyword", SigTest32UDPV6Keyword);
    UtRegisterTest("SigTest33NegativeUDPV6Keyword",
                   SigTest33NegativeUDPV6Keyword);

    UtRegisterTest("SigTest34ICMPV4Keyword", SigTest34ICMPV4Keyword);
    UtRegisterTest("SigTest35NegativeICMPV4Keyword",
                   SigTest35NegativeICMPV4Keyword);
    UtRegisterTest("SigTest36ContentAndIsdataatKeywords01",
                   SigTest36ContentAndIsdataatKeywords01);
    UtRegisterTest("SigTest37ContentAndIsdataatKeywords02",
                   SigTest37ContentAndIsdataatKeywords02);

    UtRegisterTest("SigTest38 -- byte_test test (1)", SigTest38);

    UtRegisterTest("SigTest39 -- byte_jump test (2)", SigTest39);

    UtRegisterTest("SigTest40NoPacketInspection01",
                   SigTest40NoPacketInspection01);
    UtRegisterTest("SigTest40NoPayloadInspection02",
                   SigTest40NoPayloadInspection02);

    UtRegisterTest("SigTestMemory01", SigTestMemory01);
    UtRegisterTest("SigTestMemory02", SigTestMemory02);
    UtRegisterTest("SigTestMemory03", SigTestMemory03);

    UtRegisterTest("SigTestContent01 -- 32 byte pattern", SigTestContent01);
    UtRegisterTest("SigTestContent02 -- 32+31 byte pattern", SigTestContent02);
    UtRegisterTest("SigTestContent03 -- 32 byte pattern, x2 + distance",
                   SigTestContent03);
    UtRegisterTest("SigTestContent04 -- 32 byte pattern, x2 + distance/within",
                   SigTestContent04);
    UtRegisterTest("SigTestContent05 -- distance/within", SigTestContent05);
    UtRegisterTest("SigTestContent06 -- distance/within ip only",
                   SigTestContent06);

    UtRegisterTest("SigTestWithinReal01", SigTestWithin01);
    UtRegisterTest("SigTestDepthOffset01", SigTestDepthOffset01);

    UtRegisterTest("SigTestDetectAlertCounter", SigTestDetectAlertCounter);

    UtRegisterTest("SigTestDropFlow01", SigTestDropFlow01);
    UtRegisterTest("SigTestDropFlow02", SigTestDropFlow02);
    UtRegisterTest("SigTestDropFlow03", SigTestDropFlow03);
    UtRegisterTest("SigTestDropFlow04", SigTestDropFlow04);

    UtRegisterTest("DetectAddressYamlParsing01", DetectAddressYamlParsing01);
    UtRegisterTest("DetectAddressYamlParsing02", DetectAddressYamlParsing02);
    UtRegisterTest("DetectAddressYamlParsing03", DetectAddressYamlParsing03);
    UtRegisterTest("DetectAddressYamlParsing04", DetectAddressYamlParsing04);

    UtRegisterTest("SigTestPorts01", SigTestPorts01);
    UtRegisterTest("SigTestBug01", SigTestBug01);

    DetectEngineContentInspectionRegisterTests();
#if 0
    DetectSimdRegisterTests();
#endif
#endif /* UNITTESTS */
}

