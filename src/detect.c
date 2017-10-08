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
#include "detect-tls-cert-fingerprint.h"
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
#include "util-detect.h"
#include "runmodes.h"

#ifdef HAVE_GLOB_H
#include <glob.h>
#endif

extern int rule_reload;

extern int engine_analysis;
static int fp_engine_analysis_set = 0;
static int rule_engine_analysis_set = 0;

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
            if (!SigStringAppend(&de_ctx->sig_stat, sig_file, line, de_ctx->sigerror, (lineno - multiline))) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error adding sig \"%s\" from "
                     "file %s at line %"PRId32"", line, sig_file, lineno - multiline);
            }
            if (de_ctx->sigerror) {
                de_ctx->sigerror = NULL;
            }
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
    int r = 0;

    if (pattern == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "opening rule file null");
        return -1;
    }

#ifdef HAVE_GLOB_H
    glob_t files;
    r = glob(pattern, 0, NULL, &files);

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
#else
        char *fname = pattern;
        if (strcmp("/dev/null", fname) == 0)
            return 0;
#endif

        SCLogConfig("Loading rule file: %s", fname);
        r = DetectLoadSigFile(de_ctx, fname, good_sigs, bad_sigs);
        if (r < 0) {
            ++(st->bad_files);
        }

        ++(st->total_files);

        st->good_sigs_total += *good_sigs;
        st->bad_sigs_total += *bad_sigs;
#ifdef HAVE_GLOB_H
    }
    globfree(&files);
#endif
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
    SigFileLoaderStat *sig_stat = &de_ctx->sig_stat;
    int ret = 0;
    char *sfile = NULL;
    char varname[128] = "rule-files";
    int good_sigs = 0;
    int bad_sigs = 0;

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
                    ret = ProcessSigFiles(de_ctx, sfile, sig_stat, &good_sigs, &bad_sigs);
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
        ret = ProcessSigFiles(de_ctx, sig_file, sig_stat, &good_sigs, &bad_sigs);

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
    if (sig_stat->good_sigs_total <= 0) {
        if (sig_stat->total_files > 0) {
           SCLogWarning(SC_ERR_NO_RULES_LOADED, "%d rule files specified, but no rule was loaded at all!", sig_stat->total_files);
        } else {
            SCLogInfo("No signatures supplied.");
            goto end;
        }
    } else {
        /* we report the total of files and rules successfully loaded and failed */
        SCLogInfo("%" PRId32 " rule files processed. %" PRId32 " rules successfully loaded, %" PRId32 " rules failed",
            sig_stat->total_files, sig_stat->good_sigs_total, sig_stat->bad_sigs_total);
    }

    if ((sig_stat->bad_sigs_total || sig_stat->bad_files) && de_ctx->failure_fatal) {
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
    gettimeofday(&de_ctx->last_reload, NULL);
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
 *  \param p packet
 *
 *  \retval sgh the SigGroupHead or NULL if non applies to the packet
 */
const SigGroupHead *SigMatchSignaturesGetSgh(const DetectEngineCtx *de_ctx,
        const Packet *p)
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
            det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, p);
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
        det_ctx->sgh = SigMatchSignaturesGetSgh(de_ctx, p);
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
        bool smatch = false; /* signature match */
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
        smatch = true;
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
    PacketPatternCleanup(det_ctx);

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
        const int pass = ((p->flow->flags & FLOW_NOPACKET_INSPECTION));
        const AppProto alproto = FlowGetAppProtocol(p->flow);
        if (pass && AppLayerParserProtocolSupportsTxs(p->proto, alproto)) {
            uint8_t flags;
            if (p->flowflags & FLOW_PKT_TOSERVER) {
                flags = STREAM_TOSERVER;
            } else {
                flags = STREAM_TOCLIENT;
            }
            flags = FlowGetDisruptionFlags(p->flow, flags);
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
            case DETECT_FLOWINT:
                /* flow is required for any flowint manipulation */
                s->mask |= SIG_MASK_REQUIRE_FLOW;
                SCLogDebug("sig requires flow to be able to manipulate "
                        "flowint(s)");
                break;
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
        DetectContentPropagateLimits(tmp_s);
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
    DetectTlsFingerprintRegister();

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
#include "tests/detect.c"
#endif

