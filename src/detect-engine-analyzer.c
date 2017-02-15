/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com> - JSON output
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

typedef enum {
    OUTPUT_FORMAT_TXT = 0,
    OUTPUT_FORMAT_JSON = 1
} EngineAnalysisOutputFormat;

static EngineAnalysisOutputFormat output_format;

static const char *format_txt_extension = ".txt";

#define IS_OUTPUT_FORMAT(x) (output_format == OUTPUT_FORMAT_##x)
#define TXT(...) if (IS_OUTPUT_FORMAT(TXT)) { __VA_ARGS__ ; }

#ifdef HAVE_LIBJANSSON
/* with json support */
#define JSON(...) if (IS_OUTPUT_FORMAT(JSON)) { __VA_ARGS__ ; }
#define JSON_DECL(...)  __VA_ARGS__

static json_t *rule_engine_analysis_js = NULL;
static json_t *rule_engine_analysis_sigs_array_js = NULL;
static json_t *rule_engine_analysis_sigs_array_failure_js = NULL;
static json_t *fp_engine_analysis_js = NULL;
static json_t *fp_engine_analysis_sigs_array_js = NULL;
static const char *format_json_extension = ".json";

#else
/* without json support */
#undef IS_OUTPUT_FORMAT
#define IS_OUTPUT_FORMAT(x) (output_format == OUTPUT_FORMAT_##x && \
                             output_format != OUTPUT_FORMAT_JSON)

#define JSON(...)
#define JSON_DECL(...)
#endif

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

void EngineAnalysisFP(Signature *s, char *line, const char *file)
{
    int fast_pattern_set = 0;
    int fast_pattern_only_set = 0;
    int fast_pattern_chop_set = 0;
    DetectContentData *fp_cd = NULL;
    SigMatch *mpm_sm = s->mpm_sm;

    JSON_DECL(
        json_t *sig_js = json_object();
        if (unlikely(sig_js == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        json_t * info = json_array();
        if (unlikely(info == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        json_t * flags = json_array();
        if (unlikely(flags == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    )

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

    /* Write sig id, line and file */
    TXT(fprintf(fp_engine_analysis_FD, "== Sid: %u ==\n", s->id));
    TXT(fprintf(fp_engine_analysis_FD, "%s\n", line));
    JSON(json_object_set(sig_js, "sid", json_integer(s->id)));
    JSON(json_object_set(sig_js, "line", json_string(line)));
    JSON(json_object_set(sig_js, "file", json_string(file)));

    TXT(fprintf(fp_engine_analysis_FD, "    Fast Pattern analysis:\n"));

    if (s->prefilter_sm != NULL) {

        TXT(fprintf(fp_engine_analysis_FD, "        Prefilter on: %s\n",
                    sigmatch_table[s->prefilter_sm->type].name));
        TXT(fprintf(fp_engine_analysis_FD, "\n"));

        JSON(
            const char str_format[] =  "Prefiler on: %s.";
            size_t len = sizeof(str_format) + strlen(sigmatch_table[s->prefilter_sm->type].name) + 1;
            char *str_data = SCMalloc(len);
            if (unlikely(str_data == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            if (str_data) {
                memset(str_data, '\0', len);
                snprintf(str_data, len, str_format, sigmatch_table[s->prefilter_sm->type].name);
                JSON(json_array_append(info, json_string(str_data)));
                SCFree(str_data);
            }
        );
        return;
    }

    if (fp_cd == NULL) {
        TXT(fprintf(fp_engine_analysis_FD, "        No content present\n"));
        TXT(fprintf(fp_engine_analysis_FD, "\n"));
        JSON(json_array_append(info, json_string("No content present")));
        return;
    }

    TXT(fprintf(fp_engine_analysis_FD, "        Fast pattern matcher: "));

    JSON_DECL(json_t * matcher = NULL);

    int list_type = SigMatchListSMBelongsTo(s, mpm_sm);
    if (list_type == DETECT_SM_LIST_PMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "content\n"));
        JSON(matcher = json_string("content"));
    } else if (list_type == DETECT_SM_LIST_UMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http uri content\n"));
        JSON(matcher = json_string("http uri content"));
    } else if (list_type == DETECT_SM_LIST_HRUDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http raw uri content\n"));
        JSON(matcher = json_string("http raw uri content"));
    } else if (list_type == DETECT_SM_LIST_HHDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http header content\n"));
        JSON(matcher = json_string("http header content"));
    } else if (list_type == DETECT_SM_LIST_HRHDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http raw header content\n"));
        JSON(matcher = json_string("http raw header contents"));
    } else if (list_type == DETECT_SM_LIST_HMDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http method content\n"));
        JSON(matcher = json_string("http method content"));
    } else if (list_type == DETECT_SM_LIST_HCDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http cookie content\n"));
        JSON(matcher = json_string("http cookie content"));
    } else if (list_type == DETECT_SM_LIST_HCBDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http client body content\n"));
        JSON(matcher = json_string("http client body content"));
    } else if (list_type == DETECT_SM_LIST_FILEDATA) {
        TXT(fprintf(fp_engine_analysis_FD, "http server body content\n"));
        JSON(matcher = json_string("http server body content"));
    } else if (list_type == DETECT_SM_LIST_HSCDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http stat code content\n"));
        JSON(matcher = json_string("htto stat code content"));
    } else if (list_type == DETECT_SM_LIST_HSMDMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http stat msg content\n"));
        JSON(matcher = json_string("http stat msg content"));
    } else if (list_type == DETECT_SM_LIST_HUADMATCH) {
        TXT(fprintf(fp_engine_analysis_FD, "http user agent content\n"));
        JSON(matcher = json_string("http user agent content"));
    }

    JSON(json_object_set(sig_js, "matcher", matcher));

    int flags_set = 0;
    TXT(fprintf(fp_engine_analysis_FD, "        Flags:"));
    if (fp_cd->flags & DETECT_CONTENT_OFFSET) {
        TXT(fprintf(fp_engine_analysis_FD, " Offset"));
        JSON(json_array_append(flags, json_string("Offset")));
        flags_set = 1;
    } if (fp_cd->flags & DETECT_CONTENT_DEPTH) {
        TXT(fprintf(fp_engine_analysis_FD, " Depth"));
        JSON(json_array_append(flags, json_string("Depth")));
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_WITHIN) {
        TXT(fprintf(fp_engine_analysis_FD, " Within"));
        JSON(json_array_append(flags, json_string("Within")));
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_DISTANCE) {
        TXT(fprintf(fp_engine_analysis_FD, " Distance"));
        JSON(json_array_append(flags, json_string("Distance")));
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NOCASE) {
        TXT(fprintf(fp_engine_analysis_FD, " Nocase"));
        JSON(json_array_append(flags, json_string("Nocase")));
        flags_set = 1;
    }
    if (fp_cd->flags & DETECT_CONTENT_NEGATED) {
        TXT(fprintf(fp_engine_analysis_FD, " Negated"));
        JSON(json_array_append(flags, json_string("Negated")));
        flags_set = 1;
    }
    if (flags_set == 0) {
        TXT(fprintf(fp_engine_analysis_FD, " None"));
        JSON(json_array_append(flags, json_string("None")));
    }

    JSON(json_object_set(sig_js, "flags", flags));

    TXT(fprintf(fp_engine_analysis_FD, "\n"));
    TXT(fprintf(fp_engine_analysis_FD, "        Fast pattern set: %s\n",
            fast_pattern_set ? "yes" : "no"));
    TXT(fprintf(fp_engine_analysis_FD, "        Fast pattern only set: %s\n",
            fast_pattern_only_set ? "yes" : "no"));
    TXT(fprintf(fp_engine_analysis_FD, "        Fast pattern chop set: %s\n",
            fast_pattern_chop_set ? "yes" : "no"));
    if (fast_pattern_chop_set) {
        TXT(fprintf(fp_engine_analysis_FD, "        Fast pattern offset, length: %u, %u\n",
                fp_cd->fp_chop_offset, fp_cd->fp_chop_len));
    }
    JSON (
        JSON(json_object_set(sig_js, "set",
             fast_pattern_set ? json_string("yes") : json_string("no")));
        JSON(json_object_set(sig_js, "only-set",
             fast_pattern_only_set ? json_string("yes") : json_string("no")));
        JSON(json_object_set(sig_js, "chop-set",
                    fast_pattern_chop_set ? json_string("yes") : json_string("no")));
        const char str_format[] =  "lenght %u,  %u";
        size_t len = sizeof(str_format) + ( sizeof("4294967295") * 2);
        char *str_data = SCMalloc(len);
        if (unlikely(str_data == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        if (str_data) {
            memset(str_data, '\0', len);
            snprintf(str_data, len, str_format, fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
            JSON(json_object_set(sig_js, "pattern-offset", json_string(str_data)));
            SCFree(str_data);
        }
    )

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memcpy(pat, fp_cd->content, fp_cd->content_len);
    pat[fp_cd->content_len] = '\0';

    TXT(fprintf(fp_engine_analysis_FD, "        Original content: "));
    TXT(PrintRawUriFp(fp_engine_analysis_FD, pat, patlen));
    TXT(fprintf(fp_engine_analysis_FD, "\n"));
    JSON (
        char *retbuf = SCMalloc(patlen * 2);
        if (unlikely(retbuf == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        uint32_t offset = 0;
        memset(retbuf, '\0', patlen * 2);
        PrintRawUriBuf(retbuf, &offset, (patlen*2) - 1, pat, patlen);
        JSON(json_object_set(sig_js, "original-content", json_string(retbuf)));
        SCFree(retbuf);
    )
    if (fast_pattern_chop_set) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';

        TXT(fprintf(fp_engine_analysis_FD, "        Final content: "));
        TXT(PrintRawUriFp(fp_engine_analysis_FD, pat, patlen));
        TXT(fprintf(fp_engine_analysis_FD, "\n"));

        JSON (
            char *retbuf = SCMalloc(patlen * 2);
            if (unlikely(retbuf == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            uint32_t offset = 0;
            memset(retbuf, '\0', patlen * 2);
            PrintRawUriBuf(retbuf, &offset, (patlen*2) - 1, pat, patlen);
            JSON(json_object_set(sig_js, "final-content", json_string(retbuf)));
            SCFree(retbuf);
        )
        FpPatternStatsAdd(list_type, patlen);
    } else {
        TXT(fprintf(fp_engine_analysis_FD, "        Final content: "));
        TXT(PrintRawUriFp(fp_engine_analysis_FD, pat, patlen));
        TXT(fprintf(fp_engine_analysis_FD, "\n"));

        JSON (
            char *retbuf = SCMalloc(patlen * 2);
            if (unlikely(retbuf == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            uint32_t offset = 0;
            memset(retbuf, '\0', patlen * 2);
            PrintRawUriBuf(retbuf, &offset, (patlen*2) - 1, pat, patlen);
            JSON(json_object_set(sig_js, "final-content", json_string(retbuf)));
            SCFree(retbuf);
        )
        FpPatternStatsAdd(list_type, patlen);
    }
    SCFree(pat);

    TXT(fprintf(fp_engine_analysis_FD, "\n"));
    JSON(json_array_append(fp_engine_analysis_sigs_array_js, sig_js));
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
    ConfNode *conf = ConfGetNode("engine-analysis");
    if (!conf) {
        return 0;
    }

    const char *format = ConfNodeLookupChildValue(conf, "output-format");
    output_format = OUTPUT_FORMAT_TXT;
    if (format) {
        if (strcasecmp(format, "txt") == 0) {
            format = format_txt_extension;
#ifdef HAVE_LIBJANSSON
        } else if (strcasecmp(format, "json") == 0) {
            fp_engine_analysis_js = json_object();
            if (!fp_engine_analysis_js) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to create json object for FP engine analysis.");
                return 0;
            }
            fp_engine_analysis_sigs_array_js = json_array();
            if (!fp_engine_analysis_sigs_array_js) {
                SCLogError(SC_ERR_MEM_ALLOC, "Failed to create json array object for signatures for FP engine analysis.");
                return 0;
            }

            format = format_json_extension;
            output_format = OUTPUT_FORMAT_JSON;
#else
        } else if (strcasecmp(format, "json") == 0) {
                SCLogError(SC_ERR_NO_JSON_SUPPORT, "no json support compiled in.");
                return 0;
#endif
        } else {
            SCLogInfo("Unknown output-format. Reverting to txt format.");
            format = format_txt_extension;
        }
    } else {
        /* default format is txt */
        format = format_txt_extension;
    }

    if (fp_engine_analysis_set == 0)
        return 0;

    char *log_dir;
    log_dir = ConfigGetLogDirectory();
    snprintf(log_path, sizeof(log_path), "%s/%s%s", log_dir,
             "rules_fast_pattern", format );

    fp_engine_analysis_FD = fopen(log_path, "w");
    if (fp_engine_analysis_FD == NULL) {
        SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", log_path,
                   strerror(errno));
        return 0;
    }

    SCLogInfo("Engine-Analysis for fast_pattern printed to file - %s",
            log_path);

    struct timeval tval;
    gettimeofday(&tval, NULL);

    TXT (
        struct tm *tms;
        struct tm local_tm;
        SCLogInfo("Fast-Pattern Engine-Analysis output format - %s", "txt");
        tms = SCLocalTime(tval.tv_sec, &local_tm);
        fprintf(fp_engine_analysis_FD, "----------------------------------------------"
                "---------------------\n");
        fprintf(fp_engine_analysis_FD, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
                "%02d:%02d:%02d\n",
                tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour,
                tms->tm_min, tms->tm_sec);
        fprintf(fp_engine_analysis_FD, "----------------------------------------------"
                "---------------------\n");

    );
    JSON (
        char timebuf[64] = { 0 };
        SCLogInfo("Fast-Pattern Engine-Analysis output format - %s", "json");

        CreateUtcIsoTimeString(&tval, timebuf, sizeof(timebuf));

        JSON(json_object_set(fp_engine_analysis_js, "time", json_string(timebuf)));
        JSON(json_object_set(fp_engine_analysis_js, "tz", json_string("UTC")));
    );

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
        const char *format = ConfNodeLookupChildValue(conf, "output-format");
        output_format = OUTPUT_FORMAT_TXT;
        if (value && ConfValIsTrue(value)) {
            enabled = 1;
        } else if (value && strcasecmp(value, "warnings-only") == 0) {
            enabled = 1;
            rule_warnings_only = 1;
        }
        if (format) {
            if (strcasecmp(format, "txt") == 0) {
                format = format_txt_extension;
#ifdef HAVE_LIBJANSSON
            } else if (strcasecmp(format, "json") == 0) {
                rule_engine_analysis_js = json_object();
                if (!rule_engine_analysis_js) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to create json object for rule engine analysis.");
                    return 0;
                }
                rule_engine_analysis_sigs_array_js = json_array();
                if (!rule_engine_analysis_sigs_array_js) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Failed to create json array object for signatures in engine analysis.");
                    return 0;
                }

                format = format_json_extension;
                output_format = OUTPUT_FORMAT_JSON;
#else
            } else if (strcasecmp(format, "json") == 0) {
                SCLogError(SC_ERR_NO_JSON_SUPPORT, "no json support compiled in.");
                return 0;
#endif
            } else {
                SCLogInfo("Unknown output-format. Reverting to txt format.");
                format = format_txt_extension;
            }
        } else {
            /* default format is txt */
            format = format_txt_extension;
        }

        if (enabled) {
            char *log_dir;
            log_dir = ConfigGetLogDirectory();
            snprintf(log_path, sizeof(log_path), "%s/%s%s", log_dir, "rules_analysis", format);
            rule_engine_analysis_FD = fopen(log_path, "w");
            if (rule_engine_analysis_FD == NULL) {
                SCLogError(SC_ERR_FOPEN, "failed to open %s: %s", log_path, strerror(errno));
                return 0;
            }
            SCLogInfo("Engine-Analysis for rules printed to file - %s",
                      log_path);

            struct timeval tval;
            gettimeofday(&tval, NULL);

            TXT (
                struct tm local_tm;
                struct tm *tms;

                SCLogInfo("Engine-Analysis output format - %s", "txt");
                tms = SCLocalTime(tval.tv_sec, &local_tm);

                fprintf(rule_engine_analysis_FD, "----------------------------------------------"
                        "---------------------\n");
                fprintf(rule_engine_analysis_FD, "Date: %" PRId32 "/%" PRId32 "/%04d -- "
                        "%02d:%02d:%02d\n",
                        tms->tm_mday, tms->tm_mon + 1, tms->tm_year + 1900, tms->tm_hour,
                        tms->tm_min, tms->tm_sec);
                fprintf(rule_engine_analysis_FD, "----------------------------------------------"
                        "---------------------\n");
            );
            JSON (
                char timebuf[64] = { 0 };
                SCLogInfo("Engine-Analysis output format - %s", "json");

                CreateUtcIsoTimeString(&tval, timebuf, sizeof(timebuf));

                JSON(json_object_set(rule_engine_analysis_js, "time", json_string(timebuf)));
                JSON(json_object_set(rule_engine_analysis_js, "tz", json_string("UTC")));
            );
            /*compile regex's for rule analysis*/
            if (PerCentEncodingSetup()== 0) {
                TXT(fprintf(rule_engine_analysis_FD, "Error compiling regex; can't check for percent encoding in normalized http content.\n"));
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
    if (fp_engine_analysis_FD != NULL) {
        TXT (
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
        );
        JSON (
            json_t *stats = json_array();;
            if (unlikely(stats == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            int i;
            for (i = 0; i < DETECT_SM_LIST_MAX; i++) {
                FpPatternStats *f = &fp_pattern_stats[i];
                if (f->cnt == 0)
                    continue;

                const char str_format[] =  "%s, smallest pattern %u byte(s), longest pattern %u byte(s), number of patterns %u, avg pattern len %.2f byte(s)";
                size_t len = sizeof(str_format) +
                             1 + strlen(DetectSigmatchListEnumToString(i)) +
                             ( sizeof("4294967295") * 8);
                char *str_data = SCMalloc(len);
                if (unlikely(str_data == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                if (str_data) {
                    memset(str_data, '\0', len);
                    snprintf(str_data, len, str_format,
                             DetectSigmatchListEnumToString(i), f->min, f->max, f->cnt,
                             (float)((double)f->tot/(float)f->cnt));
                    json_array_append(stats, json_string(str_data));
                    SCFree(str_data);
                }
            }

            if (fp_engine_analysis_sigs_array_js)
                json_object_set(fp_engine_analysis_js, "sigs", fp_engine_analysis_sigs_array_js);

            json_object_set(fp_engine_analysis_js, "stats", stats);

            char * txt = json_dumps(fp_engine_analysis_js, JSON_INDENT(1));
            if (txt) {
                fprintf(fp_engine_analysis_FD, "%s", txt);
                fprintf(fp_engine_analysis_FD, "\n");
                SCFree(txt);
            }

            fclose(fp_engine_analysis_FD);
            fp_engine_analysis_FD = NULL;
            json_decref(fp_engine_analysis_sigs_array_js);
            json_decref(fp_engine_analysis_js);
            fp_engine_analysis_js = NULL;
            fp_engine_analysis_sigs_array_js = NULL;
        );
    }

    return;
}


void CleanupRuleAnalyzer(void)
{
    if (rule_engine_analysis_FD != NULL) {
        TXT (
            SCLogInfo("Engine-Analyis for rules printed to file - %s", log_path);
            fclose(rule_engine_analysis_FD);
            rule_engine_analysis_FD = NULL;
        );
        JSON (
            if (rule_engine_analysis_sigs_array_js)
                json_object_set(rule_engine_analysis_js, "sigs", rule_engine_analysis_sigs_array_js);

            if (rule_engine_analysis_sigs_array_failure_js)
                json_object_set(rule_engine_analysis_js, "errors", rule_engine_analysis_sigs_array_failure_js);

            char * txt = json_dumps(rule_engine_analysis_js, JSON_INDENT(1));
            if (txt) {
                fprintf(rule_engine_analysis_FD, "%s", txt);
                fprintf(rule_engine_analysis_FD, "\n");
                SCFree(txt);
            }

            fclose(rule_engine_analysis_FD);
            rule_engine_analysis_FD = NULL;
            json_decref(rule_engine_analysis_sigs_array_js);
            json_decref(rule_engine_analysis_sigs_array_failure_js);
            json_decref(rule_engine_analysis_js);
            rule_engine_analysis_js = NULL;
            rule_engine_analysis_sigs_array_js = NULL;
            rule_engine_analysis_sigs_array_failure_js = NULL;
        )
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

#ifdef HAVE_LIBJANSSON
static void EngineAnalysisRulesPrintFP(const Signature *s, json_t *sig_js)
#else
static void EngineAnalysisRulesPrintFP(const Signature *s)
#endif
{
    DetectContentData *fp_cd = NULL;
    SigMatch *mpm_sm = s->mpm_sm;

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

#ifdef HAVE_LIBJANSSON
    json_t *fast_pattern = json_object();
    if (unlikely(fast_pattern == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
#endif

    if (fp_cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
        SCFree(pat);
        patlen = fp_cd->fp_chop_len;
        pat = SCMalloc(fp_cd->fp_chop_len + 1);
        if (unlikely(pat == NULL)) {
            exit(EXIT_FAILURE);
        }
        memcpy(pat, fp_cd->content + fp_cd->fp_chop_offset, fp_cd->fp_chop_len);
        pat[fp_cd->fp_chop_len] = '\0';

        TXT(fprintf(rule_engine_analysis_FD, "    Fast Pattern \""));
        TXT(PrintRawUriFp(rule_engine_analysis_FD, pat, patlen));

        JSON (
            char *retbuf = SCMalloc(patlen * 2);
            if (unlikely(retbuf == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            uint32_t offset = 0;
            memset(retbuf, '\0', patlen * 2);
            PrintRawUriBuf(retbuf, &offset, (patlen*2) - 1, pat, patlen);
            JSON(json_object_set(fast_pattern, "pattern", json_string(retbuf)));
            SCFree(retbuf);
        );
    } else {
        TXT(fprintf(rule_engine_analysis_FD, "    Fast Pattern \""));
        JSON (
            char *retbuf = SCMalloc(patlen * 2);
            if (unlikely(retbuf == NULL)) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                exit(EXIT_FAILURE);
            }
            uint32_t offset = 0;
            memset(retbuf, '\0', patlen * 2);
            PrintRawUriBuf(retbuf, &offset, (patlen*2) - 1, pat, patlen);
            JSON(json_object_set(fast_pattern, "pattern", json_string(retbuf)));
            SCFree(retbuf);
        );
    }
    SCFree(pat);

    TXT(fprintf(rule_engine_analysis_FD, "\" on \""));

    int list_type = SigMatchListSMBelongsTo(s, mpm_sm);
    if (list_type == DETECT_SM_LIST_PMATCH) {
        int payload = 0;
        int stream = 0;
        if (SignatureHasPacketContent(s))
            payload = 1;
        if (SignatureHasStreamContent(s))
            stream = 1;
        TXT(fprintf(rule_engine_analysis_FD, "%s",
                    payload ? (stream ? "payload and reassembled stream" : "payload") : "reassembled stream"));
        JSON(json_object_set(fast_pattern, "payload-reassemble",
                    json_string(payload ? (stream ? "payload and reassembled stream" : "payload") : "reassembled stream")));
    }
    else if (list_type == DETECT_SM_LIST_UMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http uri content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http uri content")));
    } else if (list_type == DETECT_SM_LIST_HRUDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http raw uri content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http raw uri content")));
    } else if (list_type == DETECT_SM_LIST_HHDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http header content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http header content")));
    } else if (list_type == DETECT_SM_LIST_HRHDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http raw header content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http raw header content")));
    } else if (list_type == DETECT_SM_LIST_HMDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http method content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http method content")));
    } else if (list_type == DETECT_SM_LIST_HCDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http cookie content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http cookie content")));
    } else if (list_type == DETECT_SM_LIST_HCBDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http client body content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http client body content")));
    } else if (list_type == DETECT_SM_LIST_FILEDATA) {
        TXT(fprintf(rule_engine_analysis_FD, "http server body content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http server body content")));
    } else if (list_type == DETECT_SM_LIST_HSCDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http stat code content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http stat code content")));
    } else if (list_type == DETECT_SM_LIST_HSMDMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http stat msg content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http stat msg content")));
    } else if (list_type == DETECT_SM_LIST_HUADMATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "http user agent content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("http user agent content")));
    } else if (list_type == DETECT_SM_LIST_DNSQUERYNAME_MATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "dns query name content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("dns query name content")));
    } else if (list_type == DETECT_SM_LIST_TLSSNI_MATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "tls sni extension content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("tls sni extension content")));
    } else if (list_type == DETECT_SM_LIST_TLSISSUER_MATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "tls issuer content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("tls issuer content")));
    } else if (list_type == DETECT_SM_LIST_TLSSUBJECT_MATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "tls subject content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("tls subject content")));
    } else if (list_type == DETECT_SM_LIST_DNP3_DATA_MATCH) {
        TXT(fprintf(rule_engine_analysis_FD, "dnp3 data content"));
        JSON(json_object_set(fast_pattern, "buffer", json_string("dnp3 data content")));
    }
    TXT(fprintf(rule_engine_analysis_FD, "\" buffer.\n"));
    JSON(json_object_set(sig_js, "fast-pattern", fast_pattern));

    return;
}

void EngineAnalysisRulesFailure(char *line, char *file, int lineno)
{
    TXT(fprintf(rule_engine_analysis_FD, "== Sid: UNKNOWN ==\n"));
    TXT(fprintf(rule_engine_analysis_FD, "%s\n", line));
    TXT(fprintf(rule_engine_analysis_FD, "    FAILURE: invalid rule.\n"));
    TXT(fprintf(rule_engine_analysis_FD, "    File: %s.\n", file));
    TXT(fprintf(rule_engine_analysis_FD, "    Line: %d.\n", lineno));
    TXT(fprintf(rule_engine_analysis_FD, "\n"));
    JSON (
        if (rule_engine_analysis_sigs_array_failure_js == NULL) {
            rule_engine_analysis_sigs_array_failure_js = json_array();
        }
        if (rule_engine_analysis_sigs_array_failure_js) {
            json_t *error  = json_object();
            //TODO: check alloc
            if (error) {
                json_object_set(error, "line", json_string(line));
                json_object_set(error, "file", json_string(file));
                json_object_set(error, "msg", json_string("FAILURE: invalid rule."));
                json_array_append(rule_engine_analysis_sigs_array_failure_js, error);
            }
        }
    );
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
void EngineAnalysisRules(const Signature *s, const char *line, const char *file)
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
    uint32_t list_id = 0;
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

    if (s->init_flags & SIG_FLAG_INIT_BIDIREC) {
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

    for (list_id = 0; list_id < DETECT_SM_LIST_MAX; list_id++) {

        SigMatch *sm = NULL;
        for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_PCRE) {
                if (list_id == DETECT_SM_LIST_HCBDMATCH) {
                    rule_pcre_http += 1;
                    http_client_body_buf += 1;
                    raw_http_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_UMATCH) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_uri_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HHDMATCH) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_header_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HCDMATCH) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_cookie_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_FILEDATA) {
                    rule_pcre_http += 1;
                    http_server_body_buf += 1;
                    raw_http_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HRHDMATCH) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_raw_header_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HMDMATCH) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_method_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HRUDMATCH) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_raw_uri_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HSMDMATCH) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_stat_msg_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HSCDMATCH) {
                    rule_pcre_http += 1;
                    raw_http_buf += 1;
                    http_stat_code_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HUADMATCH) {
                    rule_pcre_http += 1;
                    norm_http_buf += 1;
                    http_ua_buf += 1;
                }
                else {
                    rule_pcre += 1;
                }
            }
            else if (sm->type == DETECT_CONTENT) {

                if (list_id == DETECT_SM_LIST_UMATCH
                          || list_id == DETECT_SM_LIST_HHDMATCH
                          || list_id == DETECT_SM_LIST_HCDMATCH) {
                    rule_content_http += 1;
                    norm_http_buf += 1;
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd != NULL && PerCentEncodingMatch(cd->content, cd->content_len) > 0) {
                        warn_encoding_norm_http_buf += 1;
                        rule_warning += 1;
                    }
                    if (list_id == DETECT_SM_LIST_UMATCH) {
                        http_uri_buf += 1;
                    }
                    else if (list_id == DETECT_SM_LIST_HHDMATCH) {
                        http_header_buf += 1;
                    }
                    else if (list_id == DETECT_SM_LIST_HCDMATCH) {
                        http_cookie_buf += 1;
                    }
                }
                else if (list_id == DETECT_SM_LIST_HCBDMATCH) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_client_body_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_FILEDATA) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_server_body_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HRHDMATCH) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_raw_header_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HRUDMATCH) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_raw_uri_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HSMDMATCH) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_stat_msg_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HSCDMATCH) {
                    rule_content_http += 1;
                    raw_http_buf += 1;
                    http_stat_code_buf += 1;
                }
                else if (list_id == DETECT_SM_LIST_HMDMATCH) {
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
    if (s->mpm_sm != NULL && s->alproto == ALPROTO_HTTP &&
        SigMatchListSMBelongsTo(s, s->mpm_sm) == DETECT_SM_LIST_PMATCH) {
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

    JSON_DECL (
        json_t * sig_js = json_object();
        json_t * info = json_array();
        json_t * warnings = json_array();
    );

    JSON (
        if (unlikely(sig_js == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }

        if (unlikely(info == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        if (unlikely(warnings == NULL)) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
    );

    if (!rule_warnings_only || (rule_warnings_only && rule_warning > 0)) {

        TXT(fprintf(rule_engine_analysis_FD, "== Sid: %u ==\n", s->id));
        TXT(fprintf(rule_engine_analysis_FD, "File: [%s]\n", file));
        TXT(fprintf(rule_engine_analysis_FD, "%s\n", line));

        JSON(json_object_set(sig_js, "sid", json_integer(s->id)));
        JSON(json_object_set(sig_js, "line", json_string(line)));
        JSON(json_object_set(sig_js, "file", json_string(file)));

        if (s->flags & SIG_FLAG_IPONLY) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule is ip only.\n"));
            JSON(json_array_append(info, json_string("Rule is ip only.")));
        }
        if (s->flags & SIG_FLAG_PDONLY) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule is PD only.\n"));
            JSON(json_array_append(info, json_string("Rule is PD only.")));
        }
        if (rule_ipv6_only) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule is IPv6 only.\n"));
            JSON(json_array_append(info, json_string("Rule is IPV6 only.")));
        }
        if (rule_ipv4_only) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule is IPv4 only.\n"));
            JSON(json_array_append(info, json_string("Rule is IPV4 only.")));
        }
        if (packet_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on packets.\n"));
            JSON(json_array_append(info, json_string("Rule matches on packets.")));
        }
        if (!rule_flow_nostream && stream_buf && (rule_flow || rule_flowbits || rule_content || rule_pcre)) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on reassembled stream.\n"));
            JSON(json_array_append(info, json_string("Rule matches on reassembled stream.")));
        }
        if (http_uri_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http uri buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http uri buffer.")));
        }
        if (http_header_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http header buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http header buffer.")));
        }
        if (http_cookie_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http cookie buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http cookie buffer.")));
        }
        if (http_raw_uri_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http raw uri buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http raw uri buffer.")));
        }
        if (http_raw_header_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http raw header buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http raw header buffer.")));
        }
        if (http_method_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http method buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http method buffer.")));
        }
        if (http_server_body_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http server body buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http server body buffer.")));
        }
        if (http_client_body_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http client body buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http client body buffer.")));
        }
        if (http_stat_msg_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http stat msg buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http stat msg buffer.")));
        }
        if (http_stat_code_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http stat code buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http stat code buffer.")));
        }
        if (http_ua_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule matches on http user agent buffer.\n"));
            JSON(json_array_append(info, json_string("Rule matches on http user agent buffer.")));
        }
        if (s->alproto != ALPROTO_UNKNOWN) {
            TXT(fprintf(rule_engine_analysis_FD, "    App layer protocol is %s.\n",
                        AppProtoToString(s->alproto)));
            JSON (
                const char str_format[] =  "App layer protocol is %s.";
                size_t len = sizeof(str_format) + strlen(AppProtoToString(s->alproto)) + 1;
                char *str_data = SCMalloc(len);
                if (unlikely(str_data == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                if (str_data) {
                    memset(str_data, '\0', len);
                    snprintf(str_data, len, str_format, AppProtoToString(s->alproto));
                    json_array_append(info, json_string(str_data));
                    SCFree(str_data);
                }
            )
        }
        if (rule_content || rule_content_http || rule_pcre || rule_pcre_http) {
            TXT(fprintf(rule_engine_analysis_FD, "    Rule contains %d content options, %d http content options, %d pcre options, and %d pcre options with http modifiers.\n", rule_content, rule_content_http, rule_pcre, rule_pcre_http));
            JSON (
                const char str_format[] =  "Rule contains %d content options, %d http content options, %d pcre options, and %d pcre options with http modifiers.";
                size_t len = sizeof(str_format) + ( sizeof("4294967295") * 4);
                char *str_data = SCMalloc(len);
                if (unlikely(str_data == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                if (str_data) {
                    memset(str_data, '\0', len);
                    snprintf(str_data, len, str_format, rule_content, rule_content_http, rule_pcre, rule_pcre_http);
                    json_array_append(info, json_string(str_data));
                    SCFree(str_data);
                }
            )
        }
        /* print fast pattern info */
        if (s->prefilter_sm) {
            TXT(fprintf(rule_engine_analysis_FD, "    Prefilter on: %s.\n",
                        sigmatch_table[s->prefilter_sm->type].name));
            JSON (
                const char str_format[] =  "Prefiler on: %s.";
                size_t len = sizeof(str_format) + strlen(sigmatch_table[s->prefilter_sm->type].name) + 1;
                char *str_data = SCMalloc(len);
                if (unlikely(str_data == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    exit(EXIT_FAILURE);
                }
                if (str_data) {
                    memset(str_data, '\0', len);
                    snprintf(str_data, len, str_format, sigmatch_table[s->prefilter_sm->type].name);
                    json_array_append(info, json_string(str_data));
                    SCFree(str_data);
                }
            )

        } else {
#ifdef HAVE_LIBJANSSON
            EngineAnalysisRulesPrintFP(s, sig_js);
#else
            EngineAnalysisRulesPrintFP(s);
#endif
        }

        /* this is where the warnings start */
        if (warn_pcre_no_content /*rule_pcre > 0 && rule_content == 0 && rule_content_http == 0*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule uses pcre without a content option present.\n"
                        "             -Consider adding a content to improve performance of this rule.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule uses pcre without a content option present."));
                json_object_set(warn, "fix", json_string("Consider adding a content to improve performance of this rule."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_pcre_http_content /*rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content options with http_* and pcre options without http modifiers.\n"
                        "             -Consider adding http pcre modifier.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule uses content options with http_* and pcre options without http modifiers."));
                json_object_set(warn, "fix", json_string("Consider adding http pcre modifier."));
                json_array_append(warnings, warn);
            );
        }
        else if (warn_pcre_http /*s->alproto == ALPROTO_HTTP && rule_pcre > 0 && rule_pcre_http == 0*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but pcre options do not have http modifiers.\n"
                        "             -Consider adding http pcre modifiers.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule app layer protocol is http, but pcre options do not have http modifiers."));
                json_object_set(warn, "fix", json_string("Consider adding http pcre modifiers."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_content_http_content /*rule_content > 0 && rule_content_http > 0*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule contains content with http_* and content without http_*.\n"
                        "             -Consider adding http content modifiers.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule contains content with http_* and content without http_*."));
                json_object_set(warn, "fix", json_string("Consider adding http content modifiers."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_content_http /*s->alproto == ALPROTO_HTTP && rule_content > 0 && rule_content_http == 0*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but content options do not have http_* modifiers.\n"
                        "             -Consider adding http content modifiers.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule app layer protocol is http, but content options do not have http_* modifiers."));
                json_object_set(warn, "fix", json_string("Consider adding http content modifiers."));
                json_array_append(warnings, warn);
            );
        }
        if (rule_content == 1) {
             //todo: warning if content is weak, separate warning for pcre + weak content
        }
        if (warn_encoding_norm_http_buf) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule may contain percent encoded content for a normalized http buffer match.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Warning: Rule may contain percent encoded content for a normalized http buffer match."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_tcp_no_flow /*rule_flow == 0 && rule_flow == 0
                && !(s->proto.flags & DETECT_PROTO_ANY) && DetectProtoContainsProto(&s->proto, IPPROTO_TCP)*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: TCP rule without a flow or flags option.\n"
                        "             -Consider adding flow or flags to improve performance of this rule.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("TCP rule without a flow or flags option."));
                json_object_set(warn, "fix", json_string("Consider adding flow or flags to improve performance of this rule."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_client_ports /*rule_flow && !rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)
                      && !((s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY)))
            if (((s->flags & SIG_FLAG_TOSERVER) && !(s->flags & SIG_FLAG_SP_ANY) && (s->flags & SIG_FLAG_DP_ANY))
                || ((s->flags & SIG_FLAG_TOCLIENT) && !(s->flags & SIG_FLAG_DP_ANY) && (s->flags & SIG_FLAG_SP_ANY))*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule contains ports or port variables only on the client side.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule contains ports or port variables only on the client side."));
                json_object_set(warn, "fix", json_string("Flow direction possibly inconsistent with rule."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_direction /*rule_flow && rule_bidirectional && (rule_flow_toserver || rule_flow_toclient)*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule is bidirectional and has a flow option with a specific direction.\n"));
           JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule is bidirectional and has a flow option with a specific direction."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_method_toclient /*http_method_buf && rule_flow && rule_flow_toclient*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content or pcre for http_method with flow:to_client or from_server.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule uses content or pcre for http_method with flow:to_client or from_server."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_method_serverbody /*http_method_buf && http_server_body_buf*/) {
                TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule uses content or pcre for http_method with content or pcre for http_server_body.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule uses content or pcre for http_method with content or pcre for http_server_body."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_pcre_method /*http_method_buf && rule_content == 0 && rule_content_http == 0
                               && (rule_pcre > 0 || rule_pcre_http > 0)*/) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule uses pcre with only a http_method content; possible performance issue.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule uses pcre with only a http_method content; possible performance issue."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_offset_depth_pkt_stream) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule has depth"
                        "/offset with raw content keywords.  Please note the "
                        "offset/depth will be checked against both packet "
                        "payloads and stream.  If you meant to have the offset/"
                        "depth checked against just the payload, you can update "
                        "the signature as \"alert tcp-pkt...\"\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule has depth"
                        "/offset with raw content keywords.  Please note the "
                        "offset/depth will be checked against both packet "
                        "payloads and stream.  If you meant to have the offset/"
                        "depth checked against just the payload, you can update "
                        "the signature as \"alert tcp-pkt...\""));
                json_array_append(warnings, warn);
            );
        }
        if (warn_offset_depth_alproto) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule has "
                        "offset/depth set along with a match on a specific "
                        "app layer protocol - %d.  This can lead to FNs if we "
                        "have a offset/depth content match on a packet payload "
                        "before we can detect the app layer protocol for the "
                        "flow.\n", s->alproto));
            JSON (
                const char str_format[] =  "Rule has "
                        "offset/depth set along with a match on a specific "
                        "app layer protocol - %d.  This can lead to FNs if we "
                        "have a offset/depth content match on a packet payload "
                        "before we can detect the app layer protocol for the "
                        "flow.";
                char str_data[sizeof(str_format) + 8] = {0};
                snprintf(str_data, sizeof(str_data), str_format, s->alproto);

                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string(str_data));
                json_array_append(warnings, warn);
            );
        }
        if (warn_non_alproto_fp_for_alproto_sig) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer "
                        "protocol is http, but the fast_pattern is set on the raw "
                        "stream.  Consider adding fast_pattern over a http "
                        "buffer for increased performance."));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule app layer "
                        "protocol is http, but the fast_pattern is set on the raw "
                        "stream.  Consider adding fast_pattern over a http "
                        "buffer for increased performance."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_no_direction) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule has no direction indicator.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule has no direction indicator."));
                json_array_append(warnings, warn);
            );
        }
        if (warn_both_direction) {
            TXT(fprintf(rule_engine_analysis_FD, "    Warning: Rule is inspecting both directions.\n"));
            JSON (
                json_t *warn = json_object();
                json_object_set(warn, "msg", json_string("Rule is inspecting both directions."));
                json_array_append(warnings, warn);
            );
        }
        if (IS_OUTPUT_FORMAT(TXT)) {
            if (rule_warning == 0) {
                fprintf(rule_engine_analysis_FD, "    No warnings for this rule.\n");
            }
            fprintf(rule_engine_analysis_FD, "\n");
        }
        JSON (
            if (json_array_size(info))
                json_object_set(sig_js, "info", info);
            if (json_array_size(warnings))
                json_object_set(sig_js, "warn", warnings);
            json_array_append(rule_engine_analysis_sigs_array_js, sig_js);
        );
    }
    return;
}
