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
 * \author Eileen Donlon <emdonlo@gmail.com>
 *
 * Rule analyzer for the detection engine
 */

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-mpm.h"
#include "conf.h"
#include "detect-content.h"
#include "detect-flow.h"
#include "detect-flags.h"
#include "util-print.h"

static int rule_warnings_only = 0;
static FILE *rule_engine_analysis_FD = NULL;
static FILE *fp_engine_analysis_FD = NULL;
static pcre *percent_re = NULL;
static pcre_extra *percent_re_study = NULL;
static char log_path[PATH_MAX];

typedef struct FpPatternStats_ {
    uint16_t min;
    uint16_t max;
    uint32_t cnt;
    uint64_t tot;
} FpPatternStats;

static FpPatternStats fp_pattern_stats[DETECT_SM_LIST_MAX];

static void FpPatternStatsAdd(int list, uint16_t patlen)
{
    if (list < 0 || list >= DETECT_SM_LIST_MAX)
        return;

    FpPatternStats *f = &fp_pattern_stats[list];

    if (f->min == 0)
        f->min = patlen;
    else if (patlen < f->min)
        f->min = patlen;

    if (patlen > f->max)
        f->max = patlen;

    f->cnt++;
    f->tot += patlen;
}

void EngineAnalysisFP(Signature *s, char *line)
{
    int fast_pattern_set = 0;
    int fast_pattern_only_set = 0;
    int fast_pattern_chop_set = 0;
    DetectContentData *fp_cd = NULL;
    SigMatch *mpm_sm = s->init_data->mpm_sm;

    if (mpm_sm != NULL) {
        fp_cd = (DetectContentData *)mpm_sm->ctx;
        if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN) {
            fast_pattern_set = 1;
            if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                fast_pattern_only_set = 1;
            } else if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                fast_pattern_chop_set = 1;
            }
        }
    }

    fprintf(fp_engine_analysis_FD, "== Sid: %u ==\n", s->id);
    fprintf(fp_engine_analysis_FD, "%s\n", line);

    fprintf(fp_engine_analysis_FD, "    Fast Pattern analysis:\n");
    if (s->init_data->prefilter_sm != NULL) {
        fprintf(fp_engine_analysis_FD, "        Prefilter on: %s\n",
                sigmatch_table[s->init_data->prefilter_sm->type].name);
        fprintf(fp_engine_analysis_FD, "\n");
        return;
    }

    if (fp_cd == NULL) {
        fprintf(fp_engine_analysis_FD, "        No content present\n");
        fprintf(fp_engine_analysis_FD, "\n");
        return;
    }

    fprintf(fp_engine_analysis_FD, "        Fast pattern matcher: ");
    int list_type = SigMatchListSMBelongsTo(s, mpm_sm);
    if (list_type == DETECT_SM_LIST_PMATCH)
        fprintf(fp_engine_analysis_FD, "content\n");
    else {
        const char *desc = DetectBufferTypeGetDescriptionById(list_type);
        const char *name = DetectBufferTypeGetNameById(list_type);
        if (desc && name) {
            fprintf(fp_engine_analysis_FD, "%s (%s)\n", desc, name);
        }
    }

    int flags_set = 0;
    fprintf(fp_engine_analysis_FD, "        Flags:");
    if (fp_cd->flags & DETECT_CONTENT_OFFSET) {
        fprintf(fp_engine_analysis_FD, " Offset");
        flags_set = 1;
    } if (fp_cd->flags & DETECT_CONTENT_DEPTH) {
        fprintf(fp_engine_analysis_FD, " Depth");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_WITHIN) {
        fprintf(fp_engine_analysis_FD, " Within");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_DISTANCE) {
        fprintf(fp_engine_analysis_FD, " Distance");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NOCASE) {
        fprintf(fp_engine_analysis_FD, " Nocase");
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NEGATED) {
        fprintf(fp_engine_analysis_FD, " Negated");
        flags_set = 1;
    }
    if (flags_set == 0)
        fprintf(fp_engine_analysis_FD, " None");
    fprintf(fp_engine_analysis_FD, "\n");

    fprintf(fp_engine_analysis_FD, "        Fast pattern set: %s\n", fast_pattern_set ? "yes" : "no");
    fprintf(fp_engine_analysis_FD, "        Fast pattern only set: %s\n",
            fast_pattern_only_set ? "yes" : "no");
    fprintf(fp_engine_analysis_FD, "        Fast pattern chop set: %s\n",
            fast_pattern_chop_set ? "yes" : "no");
    if (fast_pattern_chop_set) {
        fprintf(fp_engine_analysis_FD, "        Fast pattern offset, length: %u, %u\n",
                fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
    }

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memcpy(pat, fp_cd->content, fp_cd->content_len);
    pat[fp_cd->content_len] = '\0';
    fprintf(fp_engine_analysis_FD, "        Original content: ");
    PrintRawUriFp(fp_engine_analysis_FD, pat, patlen);
    fprintf(fp_engine_analysis_FD, "\n");

    if (fast_pattern_chop_set) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';
        fprintf(fp_engine_analysis_FD, "        Final content: ");
        PrintRawUriFp(fp_engine_analysis_FD, pat, patlen);
        fprintf(fp_engine_analysis_FD, "\n");

        FpPatternStatsAdd(list_type, patlen);
    } else {
        fprintf(fp_engine_analysis_FD, "        Final content: ");
        PrintRawUriFp(fp_engine_analysis_FD, pat, patlen);
        fprintf(fp_engine_analysis_FD, "\n");

        FpPatternStatsAdd(list_type, patlen);
    }
    SCFree(pat);

    fprintf(fp_engine_analysis_FD, "\n");
    return;
}

/**
 * \brief Sets up the fast pattern analyzer according to the config.
 *
 * \retval 1 If rule analyzer successfully enabled.
 * \retval 0 If not enabled.
 */
int SetupFPAnalyzer(void)
{
    int fp_engine_analysis_set = 0;

    if ((ConfGetBool("engine-analysis.rules-fast-pattern",
                     &fp_engine_analysis_set)) == 0) {
        return 0;
    }

    if (fp_engine_analysis_set == 0)
        return 0;

    const char *log_dir;
    log_dir = ConfigGetLogDirectory();
    snprintf(log_path, sizeof(log_path), "%s/%s", log_dir,
             "rules_fast_pattern.txt");

    fp_engine_analysis_FD = fopen(log_path, "w");
    if (fp_engine_analysis_FD == NULL) {
        SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", log_path,
                   strerror(errno));
        return 0;
    }

    SCLogInfo("Engine-Analysis for fast_pattern printed to file - %s",
              log_path);

    struct timeval tval;
    struct tm *tms;
    gettimeofday(&tval, NULL);
    struct tm local_tm;
    tms = SCLocalTime(tval.tv_sec, &local_tm);
    fprintf(fp_engine_analysis_FD, "----------------------------------------------"
            "---------------------\n");
    fprintf(fp_engine_analysis_FD, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
            "%02d:%02d:%02d\n",
            tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour,
            tms->tm_min, tms->tm_sec);
    fprintf(fp_engine_analysis_FD, "----------------------------------------------"
            "---------------------\n");

    memset(&fp_pattern_stats, 0, sizeof(fp_pattern_stats));
    return 1;
}

/**
 * \brief Sets up the rule analyzer according to the config
 * \retval 1 if rule analyzer successfully enabled
 * \retval 0 if not enabled
 */
int SetupRuleAnalyzer(void)
{
    ConfNode *conf = ConfGetNode("engine-analysis");
    int enabled = 0;
    if (conf != NULL) {
        const char *value = ConfNodeLookupChildValue(conf, "rules");
        if (value && ConfValIsTrue(value)) {
            enabled = 1;
        } else if (value && strcasecmp(value, "warnings-only") == 0) {
            enabled = 1;
            rule_warnings_only = 1;
        }
        if (enabled) {
            const char *log_dir;
            log_dir = ConfigGetLogDirectory();
            snprintf(log_path, sizeof(log_path), "%s/%s", log_dir, "rules_analysis.txt");
            rule_engine_analysis_FD = fopen(log_path, "w");
            if (rule_engine_analysis_FD == NULL) {
                SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", log_path, strerror(errno));
                return 0;
            }

            SCLogInfo("Engine-Analysis for rules printed to file - %s",
                      log_path);

            struct timeval tval;
            struct tm *tms;
            gettimeofday(&tval, NULL);
            struct tm local_tm;
            tms = SCLocalTime(tval.tv_sec, &local_tm);
            fprintf(rule_engine_analysis_FD, "----------------------------------------------"
                    "---------------------\n");
            fprintf(rule_engine_analysis_FD, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
                    "%02d:%02d:%02d\n",
                    tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour,
                    tms->tm_min, tms->tm_sec);
            fprintf(rule_engine_analysis_FD, "----------------------------------------------"
                    "---------------------\n");

            /*compile regex's for rule analysis*/
            if (PerCentEncodingSetup()== 0) {
                fprintf(rule_engine_analysis_FD, "Error compiling regex; can't check for percent encoding in normalized http content.\n");
            }
        }
    }
    else {
        SCLogInfo("Conf parameter \"engine-analysis.rules\" not found. "
                                      "Defaulting to not printing the rules analysis report.");
    }
    if (!enabled) {
        SCLogInfo("Engine-Analysis for rules disabled in conf file.");
        return 0;
    }
    return 1;
}

void CleanupFPAnalyzer(void)
{
    fprintf(fp_engine_analysis_FD, "============\n"
        "Summary:\n============\n");
    int i;
    for (i = 0; i < DETECT_SM_LIST_MAX; i++) {
        FpPatternStats *f = &fp_pattern_stats[i];
        if (f->cnt == 0)
            continue;

        fprintf(fp_engine_analysis_FD,
            "%s, smallest pattern %u byte(s), longest pattern %u byte(s), number of patterns %u, avg pattern len %.2f byte(s)\n",
            DetectSigmatchListEnumToString(i), f->min, f->max, f->cnt, (float)((double)f->tot/(float)f->cnt));
    }

    if (fp_engine_analysis_FD != NULL) {
        fclose(fp_engine_analysis_FD);
        fp_engine_analysis_FD = NULL;
    }

    return;
}


void CleanupRuleAnalyzer(void)
{
    if (rule_engine_analysis_FD != NULL) {
         SCLogInfo("Engine-Analyis for rules printed to file - %s", log_path);
        fclose(rule_engine_analysis_FD);
        rule_engine_analysis_FD = NULL;
    }
}

/**
 * \brief Compiles regex for rule analysis
 * \retval 1 if successful
 * \retval 0 if on error
 */
int PerCentEncodingSetup ()
{
#define DETECT_PERCENT_ENCODING_REGEX "%[0-9|a-f|A-F]{2}"
    const char *eb = NULL;
    int eo = 0;
    int opts = 0;    //PCRE_NEWLINE_ANY??

    percent_re = pcre_compile(DETECT_PERCENT_ENCODING_REGEX, opts, &eb, &eo, NULL);
    if (percent_re == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",
                   DETECT_PERCENT_ENCODING_REGEX, eo, eb);
        return 0;
    }

    percent_re_study = pcre_study(percent_re, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        return 0;
    }
    return 1;
}

/**
 * \brief Checks for % encoding in content.
 * \param Pointer to content
 * \retval number of matches if content has % encoding
 * \retval 0 if it doesn't have % encoding
 * \retval -1 on error
 */
int PerCentEncodingMatch (uint8_t *content, uint8_t content_len)
{
#define MAX_ENCODED_CHARS 240
    int ret = 0;
    int ov[MAX_ENCODED_CHARS];

    ret = pcre_exec(percent_re, percent_re_study, (char *)content, content_len, 0, 0, ov, MAX_ENCODED_CHARS);
    if (ret == -1) {
        return 0;
    }
    else if (ret < -1) {
        SCLogError(SC_ERR_PCRE_MATCH, "Error parsing content - %s; error code is %d", content, ret);
        return -1;
    }
    return ret;
}

static void EngineAnalysisRulesPrintFP(const Signature *s)
{
    DetectContentData *fp_cd = NULL;
    SigMatch *mpm_sm = s->init_data->mpm_sm;

    if (mpm_sm != NULL) {
        fp_cd = (DetectContentData *)mpm_sm->ctx;
    }

    if (fp_cd == NULL) {
        return;
    }

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memcpy(pat, fp_cd->content, fp_cd->content_len);
    pat[fp_cd->content_len] = '\0';

    if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';
        fprintf(rule_engine_analysis_FD, "    Fast Pattern \"");
        PrintRawUriFp(rule_engine_analysis_FD, pat, patlen);
    } else {
        fprintf(rule_engine_analysis_FD, "    Fast Pattern \"");
        PrintRawUriFp(rule_engine_analysis_FD, pat, patlen);
    }
    SCFree(pat);

    fprintf(rule_engine_analysis_FD, "\" on \"");

    int list_type = SigMatchListSMBelongsTo(s, mpm_sm);
    if (list_type == DETECT_SM_LIST_PMATCH) {
        int payload = 0;
        int stream = 0;
        if (SignatureHasPacketContent(s))
            payload = 1;
        if (SignatureHasStreamContent(s))
            stream = 1;
        fprintf(rule_engine_analysis_FD, "%s",
                payload ? (stream ? "payload and reassembled stream" : "payload") : "reassembled stream");
    }
    else {
        const char *desc = DetectBufferTypeGetDescriptionById(list_type);
        const char *name = DetectBufferTypeGetNameById(list_type);
        if (desc && name) {
            fprintf(rule_engine_analysis_FD, "%s (%s)", desc, name);
        }
    }

    fprintf(rule_engine_analysis_FD, "\" buffer.\n");

    return;
}


void EngineAnalysisRulesFailure(char *line, char *file, int lineno)
{
        fprintf(rule_engine_analysis_FD, "== Sid: UNKNOWN ==\n");
        fprintf(rule_engine_analysis_FD, "%s\n", line);
        fprintf(rule_engine_analysis_FD, "    FAILURE: invalid rule.\n");
        fprintf(rule_engine_analysis_FD, "    File: %s.\n", file);
        fprintf(rule_engine_analysis_FD, "    Line: %d.\n", lineno);
        fprintf(rule_engine_analysis_FD, "\n");
}

/**
 * \brief Prints analysis of loaded rules.
 *
 *        Warns if potential rule issues are detected. For example,
 *        warns if a rule uses a construct that may perform poorly,
 *        e.g. pcre without content or with http_method content only;
 *        warns if a rule uses a construct that may not be consistent with intent,
 *        e.g. client side ports only, http and content without any http_* modifiers, etc.
 *
 * \param s Pointer to the signature.
 */
void EngineAnalysisRules(const Signature *s, const char *line)
{
    uint32_t rule_bidirectional = 0;
    uint32_t rule_pcre = 0;
    uint32_t rule_pcre_http = 0;
    uint32_t rule_content = 0;
    uint32_t rule_flow = 0;
    uint32_t rule_flags = 0;
    uint32_t rule_flow_toserver = 0;
    uint32_t rule_flow_toclient = 0;
    uint32_t rule_flow_nostream = 0;
    uint32_t rule_ipv4_only = 0;
    uint32_t rule_ipv6_only = 0;
    uint32_t rule_flowbits = 0;
    uint32_t rule_flowint = 0;
    //uint32_t rule_flowvar = 0;
    uint32_t rule_content_http = 0;
    uint32_t rule_content_offset_depth = 0;
    int32_t list_id = 0;
    uint32_t rule_warning = 0;
    uint32_t raw_http_buf = 0;
    uint32_t norm_http_buf = 0;
    uint32_t stream_buf = 0;
    uint32_t packet_buf = 0;
    uint32_t http_header_buf = 0;
    uint32_t http_uri_buf = 0;
    uint32_t http_method_buf = 0;
    uint32_t http_cookie_buf = 0;
    uint32_t http_client_body_buf = 0;
    uint32_t http_server_body_buf = 0;
    uint32_t http_stat_code_buf = 0;
    uint32_t http_stat_msg_buf = 0;
    uint32_t http_raw_header_buf = 0;
    uint32_t http_raw_uri_buf = 0;
    uint32_t http_ua_buf = 0;
    uint32_t warn_pcre_no_content = 0;
    uint32_t warn_pcre_http_content = 0;
    uint32_t warn_pcre_http = 0;
    uint32_t warn_content_http_content = 0;
    uint32_t warn_content_http = 0;
    uint32_t warn_tcp_no_flow = 0;
    uint32_t warn_client_ports = 0;
    uint32_t warn_direction = 0;
    uint32_t warn_method_toclient = 0;
    uint32_t warn_method_serverbody = 0;
    uint32_t warn_pcre_method = 0;
    uint32_t warn_encoding_norm_http_buf = 0;
    uint32_t warn_offset_depth_pkt_stream = 0;
    uint32_t warn_offset_depth_alproto = 0;
    uint32_t warn_non_alproto_fp_for_alproto_sig = 0;
    uint32_t warn_no_direction = 0;
    uint32_t warn_both_direction = 0;

    const int nlists = DetectBufferTypeMaxId();
    const int filedata_id = DetectBufferTypeGetByName("file_data");
    const int httpmethod_id = DetectBufferTypeGetByName("http_method");
    const int httpuri_id = DetectBufferTypeGetByName("http_uri");
    const int httpuseragent_id = DetectBufferTypeGetByName("http_user_agent");
    const int httpcookie_id = DetectBufferTypeGetByName("http_cookie");
    const int httpstatcode_id = DetectBufferTypeGetByName("http_stat_code");
    const int httpstatmsg_id = DetectBufferTypeGetByName("http_stat_msg");
    const int httpheader_id = DetectBufferTypeGetByName("http_header");
    const int httprawheader_id = DetectBufferTypeGetByName("http_raw_header");
    const int httpclientbody_id = DetectBufferTypeGetByName("http_client_body");
    const int httprawuri_id = DetectBufferTypeGetByName("http_raw_uri");

    if (s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        rule_bidirectional = 1;
    }

    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        packet_buf += 1;
    }
    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        stream_buf += 1;
    }

    if (s->proto.flags & DETECT_PROTO_IPV4) {
        rule_ipv4_only += 1;
    }
    if (s->proto.flags & DETECT_PROTO_IPV6) {
        rule_ipv6_only += 1;
    }

    for (list_id = 0; list_id < nlists; list_id++) {
        SigMatch *sm = NULL;
        for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_PCRE) {
                if (list_id == httpclientbody_id) {
                    rule_pcre_http += 1;
                    http_client_body_buf += 1;
                    raw_http_buf += 1;
                }
                else if (list_id == httpuri_id) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_uri_buf += 1;
                }
                else if (list_id == httpheader_id) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_header_buf += 1;
                }
                else if (list_id == httpcookie_id) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_cookie_buf += 1;
                }
                else if (list_id == filedata_id) {
                    rule_pcre_http += 1;
                    http_server_body_buf += 1;
                    raw_http_buf += 1;
                }
                else if (list_id == httprawheader_id) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_raw_header_buf += 1;
                }
                else if (list_id == httpmethod_id) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_method_buf += 1;
                }
                else if (list_id == httprawuri_id) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_raw_uri_buf += 1;
                }
                else if (list_id == httpstatmsg_id) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_stat_msg_buf += 1;
                }
                else if (list_id == httpstatcode_id) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_stat_code_buf += 1;
                }
                else if (list_id == httpuseragent_id) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_ua_buf += 1;
                }
                else {
                    rule_pcre += 1;
                }
            }
            else if (sm->type == DETECT_CONTENT) {

                if (list_id == httpuri_id
                          || list_id == httpheader_id
                          || list_id == httpcookie_id) {
                    rule_content_http += 1;
                    norm_http_buf += 1;
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd != NULL && PerCentEncodingMatch(cd->content, cd->content_len) > 0) {
                        warn_encoding_norm_http_buf += 1;
                        rule_warning += 1;
                    }
                    if (list_id == httpuri_id) {
                        http_uri_buf += 1;
                    }
                    else if (list_id == httpheader_id) {
                        http_header_buf += 1;
                    }
                    else if (list_id == httpcookie_id) {
                        http_cookie_buf += 1;
                    }
                }
                else if (list_id == httpclientbody_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_client_body_buf += 1;
                }
                else if (list_id == filedata_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_server_body_buf += 1;
                }
                else if (list_id == httprawheader_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_raw_header_buf += 1;
                }
                else if (list_id == httprawuri_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_raw_uri_buf += 1;
                }
                else if (list_id == httpstatmsg_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_stat_msg_buf += 1;
                }
                else if (list_id == httpstatcode_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_stat_code_buf += 1;
                }
                else if (list_id == httpmethod_id) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_method_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_PMATCH) {
                    rule_content += 1;
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd->flags &
                        (DETECT_CONTENT_OFFSET | DETECT_CONTENT_DEPTH)) {
                        rule_content_offset_depth++;
                    }
                }
            }
            else if (sm->type == DETECT_FLOW) {
                rule_flow += 1;
                if ((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_TOCLIENT)) {
                    rule_flow_toserver = 1;
                }
                else if ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_TOSERVER)) {
                    rule_flow_toclient = 1;
                }
                DetectFlowData *fd = (DetectFlowData *)sm->ctx;
                if (fd != NULL) {
                    if (fd->flags & DETECT_FLOW_FLAG_NOSTREAM)
                        rule_flow_nostream = 1;
                }
            }
            else if (sm->type == DETECT_FLOWBITS) {
                if (list_id == DETECT_SM_LIST_MATCH) {
                    rule_flowbits += 1;
                }
            }
            else if (sm->type == DETECT_FLOWINT) {
                if (list_id == DETECT_SM_LIST_MATCH) {
                    rule_flowint += 1;
                }
            }
            else if (sm->type == DETECT_FLAGS) {
                DetectFlagsData *fd = (DetectFlagsData *)sm->ctx;
                if (fd != NULL) {
                    rule_flags = 1;
                }
            }
        } /* for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) */

    } /* for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) */


    if (rule_pcre > 0 && rule_content == 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_pcre_no_content = 1;
    }

    if (rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http_content = 1;
    }
    else if (s->alproto == ALPROTO_HTTP && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http = 1;
    }

    if (rule_content > 0 && rule_content_http > 0) {
        rule_warning += 1;
        warn_content_http_content = 1;
    }
    if (s->alproto == ALPROTO_HTTP && rule_content > 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_content_http = 1;
    }
    if (rule_content == 1) {
         //todo: warning if content is weak, separate warning for pcre + weak content
    }
    if (rule_flow == 0 && rule_flags == 0
        && !(s->proto.flags & DETECT_PROTO_ANY) && DetectProtoContainsProto(&s->proto, IPPROTO_TCP)
        && (rule_content || rule_content_http || rule_pcre || rule_pcre_http || rule_flowbits)) {
        rule_warning += 1;
        warn_tcp_no_flow = 1;
    }
    if (rule_flow && !rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)
                  && !((s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))) {
        if (((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))
          || ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_DP_ANY) && (s->flags & SIG_FLAG_SP_ANY))) {
            rule_warning += 1;
            warn_client_ports = 1;
        }
    }
    if (rule_flow && rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)) {
        rule_warning += 1;
        warn_direction = 1;
    }
    if (http_method_buf) {
        if (rule_flow && rule_flow_toclient) {
            rule_warning += 1;
            warn_method_toclient = 1;
        }
        if (http_server_body_buf) {
            rule_warning += 1;
            warn_method_serverbody = 1;
        }
        if (rule_content == 0 && rule_content_http == 0 && (rule_pcre > 0 || rule_pcre_http > 0)) {
            rule_warning += 1;
            warn_pcre_method = 1;
        }
    }
    if (rule_content_offset_depth > 0 && stream_buf && packet_buf) {
        rule_warning += 1;
        warn_offset_depth_pkt_stream = 1;
    }
    if (rule_content_offset_depth > 0 && !stream_buf && packet_buf && s->alproto != ALPROTO_UNKNOWN) {
        rule_warning += 1;
        warn_offset_depth_alproto = 1;
    }
    if (s->init_data->mpm_sm != NULL && s->alproto == ALPROTO_HTTP &&
        SigMatchListSMBelongsTo(s, s->init_data->mpm_sm) == DETECT_SM_LIST_PMATCH) {
        rule_warning += 1;
        warn_non_alproto_fp_for_alproto_sig = 1;
    }

    if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == 0) {
        warn_no_direction += 1;
        rule_warning += 1;
    }
    if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) {
        warn_both_direction += 1;
        rule_warning += 1;
    }

    if (!rule_warnings_only || (rule_warnings_only && rule_warning > 0)) {
        fprintf(rule_engine_analysis_FD, "== Sid: %u ==\n", s->id);
        fprintf(rule_engine_analysis_FD, "%s\n", line);

        if (s->flags & SIG_FLAG_IPONLY) fprintf(rule_engine_analysis_FD, "    Rule is ip only.\n");
        if (s->flags & SIG_FLAG_PDONLY) fprintf(rule_engine_analysis_FD, "    Rule is PD only.\n");
        if (rule_ipv6_only) fprintf(rule_engine_analysis_FD, "    Rule is IPv6 only.\n");
        if (rule_ipv4_only) fprintf(rule_engine_analysis_FD, "    Rule is IPv4 only.\n");
        if (packet_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on packets.\n");
        if (!rule_flow_nostream && stream_buf && (rule_flow || rule_flowbits || rule_content || rule_pcre)) {
            fprintf(rule_engine_analysis_FD, "    Rule matches on reassembled stream.\n");
        }
        if (http_uri_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http uri buffer.\n");
        if (http_header_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http header buffer.\n");
        if (http_cookie_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http cookie buffer.\n");
        if (http_raw_uri_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http raw uri buffer.\n");
        if (http_raw_header_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http raw header buffer.\n");
        if (http_method_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http method buffer.\n");
        if (http_server_body_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http server body buffer.\n");
        if (http_client_body_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http client body buffer.\n");
        if (http_stat_msg_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http stat msg buffer.\n");
        if (http_stat_code_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http stat code buffer.\n");
        if (http_ua_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on http user agent buffer.\n");
        if (s->alproto != ALPROTO_UNKNOWN) {
            fprintf(rule_engine_analysis_FD, "    App layer protocol is %s.\n", AppProtoToString(s->alproto));
        }
        if (rule_content || rule_content_http || rule_pcre || rule_pcre_http) {
            fprintf(rule_engine_analysis_FD, "    Rule contains %d content options, %d http content options, %d pcre options, and %d pcre options with http modifiers.\n", rule_content, rule_content_http, rule_pcre, rule_pcre_http);
        }

        /* print fast pattern info */
        if (s->init_data->prefilter_sm) {
            fprintf(rule_engine_analysis_FD, "    Prefilter on: %s.\n",
                    sigmatch_table[s->init_data->prefilter_sm->type].name);
        } else {
            EngineAnalysisRulesPrintFP(s);
        }

        /* this is where the warnings start */
        if (warn_pcre_no_content /*rule_pcre > 0 && rule_content == 0 && rule_content_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule uses pcre without a content option present.\n"
                                             "             -Consider adding a content to improve performance of this rule.\n");
        }
        if (warn_pcre_http_content /*rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content options with http_* and pcre options without http modifiers.\n"
                                             "             -Consider adding http pcre modifier.\n");
        }
        else if (warn_pcre_http /*s->alproto == ALPROTO_HTTP && rule_pcre > 0 && rule_pcre_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but pcre options do not have http modifiers.\n"
                                             "             -Consider adding http pcre modifiers.\n");
        }
        if (warn_content_http_content /*rule_content > 0 && rule_content_http > 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule contains content with http_* and content without http_*.\n"
                                         "             -Consider adding http content modifiers.\n");
        }
        if (warn_content_http /*s->alproto == ALPROTO_HTTP && rule_content > 0 && rule_content_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but content options do not have http_* modifiers.\n"
                                             "             -Consider adding http content modifiers.\n");
        }
        if (rule_content == 1) {
             //todo: warning if content is weak, separate warning for pcre + weak content
        }
        if (warn_encoding_norm_http_buf) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule may contain percent encoded content for a normalized http buffer match.\n");
        }
        if (warn_tcp_no_flow /*rule_flow == 0 && rule_flow == 0
                && !(s->proto.flags & DETECT_PROTO_ANY) && DetectProtoContainsProto(&s->proto, IPPROTO_TCP)*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: TCP rule without a flow or flags option.\n"
                                             "             -Consider adding flow or flags to improve performance of this rule.\n");
        }
        if (warn_client_ports /*rule_flow && !rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)
                      && !((s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY)))
            if (((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))
                || ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_DP_ANY) && (s->flags & SIG_FLAG_SP_ANY))*/) {
                fprintf(rule_engine_analysis_FD, "    Warning: Rule contains ports or port variables only on the client side.\n"
                                                 "             -Flow direction possibly inconsistent with rule.\n");
        }
        if (warn_direction /*rule_flow && rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule is bidirectional and has a flow option with a specific direction.\n");
        }
        if (warn_method_toclient /*http_method_buf && rule_flow && rule_flow_toclient*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content or pcre for http_method with flow:to_client or from_server\n");
        }
        if (warn_method_serverbody /*http_method_buf && http_server_body_buf*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content or pcre for http_method with content or pcre for http_server_body.\n");
        }
        if (warn_pcre_method /*http_method_buf && rule_content == 0 && rule_content_http == 0
                               && (rule_pcre > 0 || rule_pcre_http > 0)*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule uses pcre with only a http_method content; possible performance issue.\n");
        }
        if (warn_offset_depth_pkt_stream) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule has depth"
                    "/offset with raw content keywords.  Please note the "
                    "offset/depth will be checked against both packet "
                    "payloads and stream.  If you meant to have the offset/"
                    "depth checked against just the payload, you can update "
                    "the signature as \"alert tcp-pkt...\"\n");
        }
        if (warn_offset_depth_alproto) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule has "
                    "offset/depth set along with a match on a specific "
                    "app layer protocol - %d.  This can lead to FNs if we "
                    "have a offset/depth content match on a packet payload "
                    "before we can detect the app layer protocol for the "
                    "flow.\n", s->alproto);
        }
        if (warn_non_alproto_fp_for_alproto_sig) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer "
                    "protocol is http, but the fast_pattern is set on the raw "
                    "stream.  Consider adding fast_pattern over a http "
                    "buffer for increased performance.");
        }
        if (warn_no_direction) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule has no direction indicator.\n");
        }
        if (warn_both_direction) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule is inspecting both directions.\n");
        }
        if (rule_warning == 0) {
            fprintf(rule_engine_analysis_FD, "    No warnings for this rule.\n");
        }
        fprintf(rule_engine_analysis_FD, "\n");
    }
    return;
}
