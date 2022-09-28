/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Rule analyzers for the detection engine
 */

#include "suricata-common.h"
#include "rust.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-analyzer.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-flow.h"
#include "detect-tcp-flags.h"
#include "feature.h"
#include "util-print.h"
#include "util-time.h"
#include "util-validate.h"

static int rule_warnings_only = 0;
static FILE *rule_engine_analysis_FD = NULL;
static FILE *fp_engine_analysis_FD = NULL;
static pcre2_code *percent_re = NULL;
static pcre2_match_data *percent_re_match = NULL;
static char log_path[PATH_MAX];

typedef struct FpPatternStats_ {
    uint16_t min;
    uint16_t max;
    uint32_t cnt;
    uint64_t tot;
} FpPatternStats;

/* Details for each buffer being tracked */
typedef struct DetectEngineAnalyzerItems {
    int16_t     item_id;
    bool        item_seen;
    bool        export_item_seen;
    bool        check_encoding_match;
    const char  *item_name;
    const char  *display_name;
} DetectEngineAnalyzerItems;

/* Track which items require the item_seen value to be exposed */
struct ExposedItemSeen {
    const char  *bufname;
    bool        *item_seen_ptr;
};

DetectEngineAnalyzerItems analyzer_items[] = {
    /* request keywords */
    { 0, false, false, true,  "http_uri",           "http uri" },
    { 0, false, false, false, "http_raw_uri",       "http raw uri" },
    { 0, false, true,  false, "http_method",        "http method" },
    { 0, false, false, false, "http_request_line",  "http request line" },
    { 0, false, false, false, "http_client_body",   "http client body" },
    { 0, false, false, true,  "http_header",        "http header" },
    { 0, false, false, false, "http_raw_header",    "http raw header" },
    { 0, false, false, true,  "http_cookie",        "http cookie" },
    { 0, false, false, false, "http_user_agent",    "http user agent" },
    { 0, false, false, false, "http_host",          "http host" },
    { 0, false, false, false, "http_raw_host",      "http raw host" },
    { 0, false, false, false, "http_accept_enc",    "http accept enc" },
    { 0, false, false, false, "http_referer",       "http referer" },
    { 0, false, false, false, "http_content_type",  "http content type" },
    { 0, false, false, false, "http_header_names",  "http header names" },

    /* response keywords not listed above */
    { 0, false, false, false, "http_stat_msg",      "http stat msg" },
    { 0, false, false, false, "http_stat_code",     "http stat code" },
    { 0, false, true,  false, "file_data",          "http server body"},

    /* missing request keywords */
    { 0, false, false, false, "http_request_line",  "http request line" },
    { 0, false, false, false, "http_accept",        "http accept" },
    { 0, false, false, false, "http_accept_lang",   "http accept lang" },
    { 0, false, false, false, "http_connection",    "http connection" },
    { 0, false, false, false, "http_content_len",   "http content len" },
    { 0, false, false, false, "http_protocol",      "http protocol" },
    { 0, false, false, false, "http_start",         "http start" },

    /* missing response keywords; some of the missing are listed above*/
    { 0, false, false, false, "http_response_line", "http response line" },
    { 0, false, false, false, "http.server",        "http server" },
    { 0, false, false, false, "http.location",      "http location" },
};

/*
 * This array contains the map between the `analyzer_items` array listed above and
 * the item ids returned by DetectBufferTypeGetByName. Iterating signature's sigmatch
 * array provides list_ids. The map converts those ids into elements of the
 * analyzer items array.
 *
 * Ultimately, the g_buffer_type_hash is searched for each buffer name. The size of that
 * hashlist is 256, so that's the value we use here.
 */
int16_t analyzer_item_map[256];

/*
 * Certain values must be directly accessible. This array contains items that are directly
 * accessed when checking if they've been seen or not.
 */
struct ExposedItemSeen exposed_item_seen_list[] = {
    { .bufname = "http_method"},
    { .bufname = "file_data"}
};

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

void EngineAnalysisFP(const DetectEngineCtx *de_ctx, const Signature *s, char *line)
{
    int fast_pattern_set = 0;
    int fast_pattern_only_set = 0;
    int fast_pattern_chop_set = 0;
    const DetectContentData *fp_cd = NULL;
    const SigMatch *mpm_sm = s->init_data->mpm_sm;
    const int mpm_sm_list = s->init_data->mpm_sm_list;

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
    int list_type = mpm_sm_list;
    if (list_type == DETECT_SM_LIST_PMATCH)
        fprintf(fp_engine_analysis_FD, "content\n");
    else {
        const char *desc = DetectEngineBufferTypeGetDescriptionById(de_ctx, list_type);
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, list_type);
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
        FatalError(SC_ERR_FATAL, "Error allocating memory");
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
         SCLogInfo("Engine-Analysis for rules printed to file - %s", log_path);
        fclose(rule_engine_analysis_FD);
        rule_engine_analysis_FD = NULL;
    }
    if (percent_re != NULL) {
        pcre2_code_free(percent_re);
    }
    pcre2_match_data_free(percent_re_match);
}

/**
 * \brief Compiles regex for rule analysis
 * \retval 1 if successful
 * \retval 0 if on error
 */
int PerCentEncodingSetup ()
{
#define DETECT_PERCENT_ENCODING_REGEX "%[0-9|a-f|A-F]{2}"
    int en;
    PCRE2_SIZE eo = 0;
    int opts = 0; // PCRE2_NEWLINE_ANY??

    percent_re = pcre2_compile((PCRE2_SPTR8)DETECT_PERCENT_ENCODING_REGEX, PCRE2_ZERO_TERMINATED,
            opts, &en, &eo, NULL);
    if (percent_re == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %d: %s",
                DETECT_PERCENT_ENCODING_REGEX, (int)eo, errbuffer);
        return 0;
    }

    percent_re_match = pcre2_match_data_create_from_pattern(percent_re, NULL);
    return 1;
}

/**
 * \brief Checks for % encoding in content.
 * \param Pointer to content
 * \retval number of matches if content has % encoding
 * \retval 0 if it doesn't have % encoding
 * \retval -1 on error
 */
static int PerCentEncodingMatch(uint8_t *content, uint16_t content_len)
{
    int ret = 0;

    ret = pcre2_match(percent_re, (PCRE2_SPTR8)content, content_len, 0, 0, percent_re_match, NULL);
    if (ret == -1) {
        return 0;
    }
    else if (ret < -1) {
        SCLogError(SC_ERR_PCRE_MATCH, "Error parsing content - %s; error code is %d", content, ret);
        return -1;
    }
    return ret;
}

static void EngineAnalysisRulesPrintFP(const DetectEngineCtx *de_ctx, const Signature *s)
{
    const DetectContentData *fp_cd = NULL;
    const SigMatch *mpm_sm = s->init_data->mpm_sm;
    const int mpm_sm_list = s->init_data->mpm_sm_list;

    if (mpm_sm != NULL) {
        fp_cd = (DetectContentData *)mpm_sm->ctx;
    }

    if (fp_cd == NULL) {
        return;
    }

    uint16_t patlen = fp_cd->content_len;
    uint8_t *pat = SCMalloc(fp_cd->content_len + 1);
    if (unlikely(pat == NULL)) {
        FatalError(SC_ERR_FATAL, "Error allocating memory");
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

    const int list_type = mpm_sm_list;
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
        const char *desc = DetectEngineBufferTypeGetDescriptionById(de_ctx, list_type);
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, list_type);
        if (desc && name) {
            fprintf(rule_engine_analysis_FD, "%s (%s)", desc, name);
        } else if (desc || name) {
            fprintf(rule_engine_analysis_FD, "%s", desc ? desc : name);
        }

    }

    fprintf(rule_engine_analysis_FD, "\" ");
    const DetectBufferType *bt = DetectEngineBufferTypeGetById(de_ctx, list_type);
    if (bt && bt->transforms.cnt) {
        fprintf(rule_engine_analysis_FD, "(with %d transform(s)) ", bt->transforms.cnt);
    }
    fprintf(rule_engine_analysis_FD, "buffer.\n");

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

typedef struct RuleAnalyzer {
    JsonBuilder *js; /* document root */

    JsonBuilder *js_warnings;
    JsonBuilder *js_notes;
} RuleAnalyzer;

static void ATTR_FMT_PRINTF(2, 3) AnalyzerNote(RuleAnalyzer *ctx, char *fmt, ...)
{
    va_list ap;
    char str[1024];

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    if (!ctx->js_notes)
        ctx->js_notes = jb_new_array();
    if (ctx->js_notes)
        jb_append_string(ctx->js_notes, str);
}

static void ATTR_FMT_PRINTF(2, 3) AnalyzerWarning(RuleAnalyzer *ctx, char *fmt, ...)
{
    va_list ap;
    char str[1024];

    va_start(ap, fmt);
    vsnprintf(str, sizeof(str), fmt, ap);
    va_end(ap);

    if (!ctx->js_warnings)
        ctx->js_warnings = jb_new_array();
    if (ctx->js_warnings)
        jb_append_string(ctx->js_warnings, str);
}

#define CHECK(pat) if (strlen((pat)) <= len && memcmp((pat), buf, MIN(len, strlen((pat)))) == 0) return true;

static bool LooksLikeHTTPMethod(const uint8_t *buf, uint16_t len)
{
    CHECK("GET /");
    CHECK("POST /");
    CHECK("HEAD /");
    CHECK("PUT /");
    return false;
}

static bool LooksLikeHTTPUA(const uint8_t *buf, uint16_t len)
{
    CHECK("User-Agent: ");
    CHECK("\nUser-Agent: ");
    return false;
}

static void DumpContent(JsonBuilder *js, const DetectContentData *cd)
{
    char pattern_str[1024] = "";
    DetectContentPatternPrettyPrint(cd, pattern_str, sizeof(pattern_str));

    jb_set_string(js, "pattern", pattern_str);
    jb_set_uint(js, "length", cd->content_len);
    jb_set_bool(js, "nocase", cd->flags & DETECT_CONTENT_NOCASE);
    jb_set_bool(js, "negated", cd->flags & DETECT_CONTENT_NEGATED);
    jb_set_bool(js, "starts_with", cd->flags & DETECT_CONTENT_STARTS_WITH);
    jb_set_bool(js, "ends_with", cd->flags & DETECT_CONTENT_ENDS_WITH);
    jb_set_bool(js, "is_mpm", cd->flags & DETECT_CONTENT_MPM);
    jb_set_bool(js, "no_double_inspect", cd->flags & DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED);
    if (cd->flags & DETECT_CONTENT_OFFSET) {
        jb_set_uint(js, "offset", cd->offset);
    }
    if (cd->flags & DETECT_CONTENT_DEPTH) {
        jb_set_uint(js, "depth", cd->depth);
    }
    if (cd->flags & DETECT_CONTENT_DISTANCE) {
        jb_set_uint(js, "distance", cd->distance);
    }
    if (cd->flags & DETECT_CONTENT_WITHIN) {
        jb_set_uint(js, "within", cd->within);
    }
    jb_set_bool(js, "fast_pattern", cd->flags & DETECT_CONTENT_FAST_PATTERN);
}

static void DumpMatches(RuleAnalyzer *ctx, JsonBuilder *js, const SigMatchData *smd)
{
    if (smd == NULL)
        return;

    jb_open_array(js, "matches");
    do {
        jb_start_object(js);
        const char *mname = sigmatch_table[smd->type].name;
        jb_set_string(js, "name", mname);

        switch (smd->type) {
            case DETECT_CONTENT: {
                const DetectContentData *cd = (const DetectContentData *)smd->ctx;

                jb_open_object(js, "content");
                DumpContent(js, cd);
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                    AnalyzerNote(ctx, (char *)"'fast_pattern:only' option is silently ignored and "
                                              "is interpreted as regular 'fast_pattern'");
                }
                if (LooksLikeHTTPMethod(cd->content, cd->content_len)) {
                    AnalyzerWarning(ctx,
                            (char *)"pattern looks like it inspects HTTP, use http.request_line or "
                                    "http.method and http.uri instead for improved performance");
                }
                if (LooksLikeHTTPUA(cd->content, cd->content_len)) {
                    AnalyzerWarning(ctx,
                            (char *)"pattern looks like it inspects HTTP, use http.user_agent "
                                    "or http.header for improved performance");
                }
                jb_close(js);
                break;
            }
        }
        jb_close(js);

        if (smd->is_last)
            break;
        smd++;
    } while (1);
    jb_close(js);
}

SCMutex g_rules_analyzer_write_m = SCMUTEX_INITIALIZER;
void EngineAnalysisRules2(const DetectEngineCtx *de_ctx, const Signature *s)
{
    SCEnter();

    RuleAnalyzer ctx = { NULL, NULL, NULL };

    ctx.js = jb_new_object();
    if (ctx.js == NULL)
        SCReturn;

    jb_set_string(ctx.js, "raw", s->sig_str);
    jb_set_uint(ctx.js, "id", s->id);
    jb_set_uint(ctx.js, "gid", s->gid);
    jb_set_uint(ctx.js, "rev", s->rev);
    jb_set_string(ctx.js, "msg", s->msg);

    const char *alproto = AppProtoToString(s->alproto);
    jb_set_string(ctx.js, "app_proto", alproto);

    jb_open_array(ctx.js, "requirements");
    if (s->mask & SIG_MASK_REQUIRE_PAYLOAD) {
        jb_append_string(ctx.js, "payload");
    }
    if (s->mask & SIG_MASK_REQUIRE_NO_PAYLOAD) {
        jb_append_string(ctx.js, "no_payload");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLOW) {
        jb_append_string(ctx.js, "flow");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLAGS_INITDEINIT) {
        jb_append_string(ctx.js, "tcp_flags_init_deinit");
    }
    if (s->mask & SIG_MASK_REQUIRE_FLAGS_UNUSUAL) {
        jb_append_string(ctx.js, "tcp_flags_unusual");
    }
    if (s->mask & SIG_MASK_REQUIRE_DCERPC) {
        jb_append_string(ctx.js, "dcerpc");
    }
    if (s->mask & SIG_MASK_REQUIRE_ENGINE_EVENT) {
        jb_append_string(ctx.js, "engine_event");
    }
    jb_close(ctx.js);

    jb_open_array(ctx.js, "flags");
    if (s->flags & SIG_FLAG_SRC_ANY) {
        jb_append_string(ctx.js, "src_any");
    }
    if (s->flags & SIG_FLAG_DST_ANY) {
        jb_append_string(ctx.js, "dst_any");
    }
    if (s->flags & SIG_FLAG_SP_ANY) {
        jb_append_string(ctx.js, "sp_any");
    }
    if (s->flags & SIG_FLAG_DP_ANY) {
        jb_append_string(ctx.js, "dp_any");
    }
    if (s->flags & SIG_FLAG_NOALERT) {
        jb_append_string(ctx.js, "noalert");
    }
    if (s->flags & SIG_FLAG_DSIZE) {
        jb_append_string(ctx.js, "dsize");
    }
    if (s->flags & SIG_FLAG_APPLAYER) {
        jb_append_string(ctx.js, "applayer");
    }
    if (s->flags & SIG_FLAG_IPONLY) {
        jb_append_string(ctx.js, "ip_only");
    }
    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        jb_append_string(ctx.js, "need_packet");
    }
    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        jb_append_string(ctx.js, "need_stream");
    }
    if (s->flags & SIG_FLAG_MPM_NEG) {
        jb_append_string(ctx.js, "negated_mpm");
    }
    if (s->flags & SIG_FLAG_FLUSH) {
        jb_append_string(ctx.js, "flush");
    }
    if (s->flags & SIG_FLAG_REQUIRE_FLOWVAR) {
        jb_append_string(ctx.js, "need_flowvar");
    }
    if (s->flags & SIG_FLAG_FILESTORE) {
        jb_append_string(ctx.js, "filestore");
    }
    if (s->flags & SIG_FLAG_TOSERVER) {
        jb_append_string(ctx.js, "toserver");
    }
    if (s->flags & SIG_FLAG_TOCLIENT) {
        jb_append_string(ctx.js, "toclient");
    }
    if (s->flags & SIG_FLAG_TLSSTORE) {
        jb_append_string(ctx.js, "tlsstore");
    }
    if (s->flags & SIG_FLAG_BYPASS) {
        jb_append_string(ctx.js, "bypass");
    }
    if (s->flags & SIG_FLAG_PREFILTER) {
        jb_append_string(ctx.js, "prefilter");
    }
    if (s->flags & SIG_FLAG_PDONLY) {
        jb_append_string(ctx.js, "proto_detect_only");
    }
    if (s->flags & SIG_FLAG_SRC_IS_TARGET) {
        jb_append_string(ctx.js, "src_is_target");
    }
    if (s->flags & SIG_FLAG_DEST_IS_TARGET) {
        jb_append_string(ctx.js, "dst_is_target");
    }
    jb_close(ctx.js);

    const DetectEnginePktInspectionEngine *pkt_mpm = NULL;
    const DetectEngineAppInspectionEngine *app_mpm = NULL;

    jb_open_array(ctx.js, "pkt_engines");
    const DetectEnginePktInspectionEngine *pkt = s->pkt_inspect;
    for ( ; pkt != NULL; pkt = pkt->next) {
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, pkt->sm_list);
        if (name == NULL) {
            switch (pkt->sm_list) {
                case DETECT_SM_LIST_PMATCH:
                    name = "payload";
                    break;
                case DETECT_SM_LIST_MATCH:
                    name = "packet";
                    break;
                default:
                    name = "unknown";
                    break;
            }
        }
        jb_start_object(ctx.js);
        jb_set_string(ctx.js, "name", name);
        jb_set_bool(ctx.js, "is_mpm", pkt->mpm);
        DumpMatches(&ctx, ctx.js, pkt->smd);
        jb_close(ctx.js);
        if (pkt->mpm) {
            pkt_mpm = pkt;
        }
    }
    jb_close(ctx.js);
    jb_open_array(ctx.js, "frame_engines");
    const DetectEngineFrameInspectionEngine *frame = s->frame_inspect;
    for (; frame != NULL; frame = frame->next) {
        const char *name = DetectEngineBufferTypeGetNameById(de_ctx, frame->sm_list);
        jb_start_object(ctx.js);
        jb_set_string(ctx.js, "name", name);
        jb_set_bool(ctx.js, "is_mpm", frame->mpm);
        DumpMatches(&ctx, ctx.js, frame->smd);
        jb_close(ctx.js);
    }
    jb_close(ctx.js);

    if (s->init_data->init_flags & SIG_FLAG_INIT_STATE_MATCH) {
        bool has_stream = false;
        bool has_client_body_mpm = false;
        bool has_file_data_mpm = false;

        jb_open_array(ctx.js, "engines");
        const DetectEngineAppInspectionEngine *app = s->app_inspect;
        for ( ; app != NULL; app = app->next) {
            const char *name = DetectEngineBufferTypeGetNameById(de_ctx, app->sm_list);
            if (name == NULL) {
                switch (app->sm_list) {
                    case DETECT_SM_LIST_PMATCH:
                        name = "stream";
                        break;
                    default:
                        name = "unknown";
                        break;
                }
            }

            if (app->sm_list == DETECT_SM_LIST_PMATCH && !app->mpm) {
                has_stream = true;
            } else if (app->mpm && strcmp(name, "http_client_body") == 0) {
                has_client_body_mpm = true;
            } else if (app->mpm && strcmp(name, "file_data") == 0) {
                has_file_data_mpm = true;
            }

            jb_start_object(ctx.js);
            jb_set_string(ctx.js, "name", name);
            const char *direction = app->dir == 0 ? "toserver" : "toclient";
            jb_set_string(ctx.js, "direction", direction);
            jb_set_bool(ctx.js, "is_mpm", app->mpm);
            jb_set_string(ctx.js, "app_proto", AppProtoToString(app->alproto));
            jb_set_uint(ctx.js, "progress", app->progress);
            DumpMatches(&ctx, ctx.js, app->smd);
            jb_close(ctx.js);
            if (app->mpm) {
                app_mpm = app;
            }
        }
        jb_close(ctx.js);

        if (has_stream && has_client_body_mpm)
            AnalyzerNote(&ctx, (char *)"mpm in http_client_body combined with stream match leads to stream buffering");
        if (has_stream && has_file_data_mpm)
            AnalyzerNote(&ctx, (char *)"mpm in file_data combined with stream match leads to stream buffering");
    }

    jb_open_object(ctx.js, "lists");
    for (int i = 0; i < DETECT_SM_LIST_MAX; i++) {
        if (s->sm_arrays[i] != NULL) {
            jb_open_object(ctx.js, DetectSigmatchListEnumToString(i));
            DumpMatches(&ctx, ctx.js, s->sm_arrays[i]);
            jb_close(ctx.js);
        }
    }
    jb_close(ctx.js);

    if (pkt_mpm || app_mpm) {
        jb_open_object(ctx.js, "mpm");

        int mpm_list = pkt_mpm ? DETECT_SM_LIST_PMATCH : app_mpm->sm_list;
        const char *name;
        if (mpm_list < DETECT_SM_LIST_DYNAMIC_START)
            name = DetectListToHumanString(mpm_list);
        else
            name = DetectEngineBufferTypeGetNameById(de_ctx, mpm_list);
        jb_set_string(ctx.js, "buffer", name);

        SigMatchData *smd = pkt_mpm ? pkt_mpm->smd : app_mpm->smd;
        if (smd == NULL && mpm_list == DETECT_SM_LIST_PMATCH) {
            smd = s->sm_arrays[mpm_list];
        }
        do {
            switch (smd->type) {
                case DETECT_CONTENT: {
                    const DetectContentData *cd = (const DetectContentData *)smd->ctx;
                    if (cd->flags & DETECT_CONTENT_MPM) {
                        DumpContent(ctx.js, cd);
                    }
                    break;
                }
            }

            if (smd->is_last)
                break;
            smd++;
        } while (1);
        jb_close(ctx.js);
    } else if (s->init_data->prefilter_sm) {
        jb_open_object(ctx.js, "prefilter");
        int prefilter_list = SigMatchListSMBelongsTo(s, s->init_data->prefilter_sm);
        const char *name;
        if (prefilter_list < DETECT_SM_LIST_DYNAMIC_START)
            name = DetectListToHumanString(prefilter_list);
        else
            name = DetectEngineBufferTypeGetNameById(de_ctx, prefilter_list);
        jb_set_string(ctx.js, "buffer", name);
        const char *mname = sigmatch_table[s->init_data->prefilter_sm->type].name;
        jb_set_string(ctx.js, "name", mname);
        jb_close(ctx.js);
    }

    if (ctx.js_warnings) {
        jb_close(ctx.js_warnings);
        jb_set_object(ctx.js, "warnings", ctx.js_warnings);
        jb_free(ctx.js_warnings);
        ctx.js_warnings = NULL;
    }
    if (ctx.js_notes) {
        jb_close(ctx.js_notes);
        jb_set_object(ctx.js, "notes", ctx.js_notes);
        jb_free(ctx.js_notes);
        ctx.js_notes = NULL;
    }
    jb_close(ctx.js);

    const char *filename = "rules.json";
    const char *log_dir = ConfigGetLogDirectory();
    char json_path[PATH_MAX] = "";
    snprintf(json_path, sizeof(json_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rules_analyzer_write_m);
    FILE *fp = fopen(json_path, "a");
    if (fp != NULL) {
        fwrite(jb_ptr(ctx.js), jb_len(ctx.js), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_rules_analyzer_write_m);
    jb_free(ctx.js);
    SCReturn;
}

void DumpPatterns(DetectEngineCtx *de_ctx)
{
    if (de_ctx->pattern_hash_table == NULL)
        return;

    JsonBuilder *root_jb = jb_new_object();
    JsonBuilder *arrays[de_ctx->buffer_type_id];
    memset(&arrays, 0, sizeof(JsonBuilder *) * de_ctx->buffer_type_id);

    jb_open_array(root_jb, "buffers");

    for (HashListTableBucket *htb = HashListTableGetListHead(de_ctx->pattern_hash_table);
            htb != NULL; htb = HashListTableGetListNext(htb)) {
        char str[1024] = "";
        DetectPatternTracker *p = HashListTableGetListData(htb);
        DetectContentPatternPrettyPrint(p->cd, str, sizeof(str));

        JsonBuilder *jb = arrays[p->sm_list];
        if (arrays[p->sm_list] == NULL) {
            jb = arrays[p->sm_list] = jb_new_object();
            const char *name;
            if (p->sm_list < DETECT_SM_LIST_DYNAMIC_START)
                name = DetectListToHumanString(p->sm_list);
            else
                name = DetectEngineBufferTypeGetNameById(de_ctx, p->sm_list);
            jb_set_string(jb, "name", name);
            jb_set_uint(jb, "list_id", p->sm_list);

            jb_open_array(jb, "patterns");
        }

        jb_start_object(jb);
        jb_set_string(jb, "pattern", str);
        jb_set_uint(jb, "patlen", p->cd->content_len);
        jb_set_uint(jb, "cnt", p->cnt);
        jb_set_uint(jb, "mpm", p->mpm);
        jb_open_object(jb, "flags");
        jb_set_bool(jb, "nocase", p->cd->flags & DETECT_CONTENT_NOCASE);
        jb_set_bool(jb, "negated", p->cd->flags & DETECT_CONTENT_NEGATED);
        jb_set_bool(jb, "depth", p->cd->flags & DETECT_CONTENT_DEPTH);
        jb_set_bool(jb, "offset", p->cd->flags & DETECT_CONTENT_OFFSET);
        jb_set_bool(jb, "endswith", p->cd->flags & DETECT_CONTENT_ENDS_WITH);
        jb_close(jb);
        jb_close(jb);
    }

    for (uint32_t i = 0; i < de_ctx->buffer_type_id; i++) {
        JsonBuilder *jb = arrays[i];
        if (jb == NULL)
            continue;

        jb_close(jb); // array
        jb_close(jb); // object

        jb_append_object(root_jb, jb);
        jb_free(jb);
    }
    jb_close(root_jb);
    jb_close(root_jb);

    const char *filename = "patterns.json";
    const char *log_dir = ConfigGetLogDirectory();
    char json_path[PATH_MAX] = "";
    snprintf(json_path, sizeof(json_path), "%s/%s", log_dir, filename);

    SCMutexLock(&g_rules_analyzer_write_m);
    FILE *fp = fopen(json_path, "a");
    if (fp != NULL) {
        fwrite(jb_ptr(root_jb), jb_len(root_jb), 1, fp);
        fprintf(fp, "\n");
        fclose(fp);
    }
    SCMutexUnlock(&g_rules_analyzer_write_m);
    jb_free(root_jb);

    HashListTableFree(de_ctx->pattern_hash_table);
    de_ctx->pattern_hash_table = NULL;
}

static void EngineAnalysisItemsReset(void)
{
    for (size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
        analyzer_items[i].item_seen = false;
    }
}

static void EngineAnalysisItemsInit(void)
{
    static bool analyzer_init = false;

    if (analyzer_init) {
        EngineAnalysisItemsReset();
        return;
    }

    memset(analyzer_item_map, -1, sizeof(analyzer_item_map));

    for (size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
        DetectEngineAnalyzerItems *analyzer_item = &analyzer_items[i];

        int item_id = DetectBufferTypeGetByName(analyzer_item->item_name);
        DEBUG_VALIDATE_BUG_ON(item_id < 0 || item_id > UINT16_MAX);
        analyzer_item->item_id = (uint16_t)item_id;
        if (analyzer_item->item_id == -1) {
            /* Mismatch between the analyzer_items array and what's supported */
            FatalError(SC_ERR_INITIALIZATION,
                       "unable to initialize engine-analysis table: detect buffer \"%s\" not recognized.",
                       analyzer_item->item_name);
        }
        analyzer_item->item_seen = false;

        if (analyzer_item->export_item_seen) {
            for (size_t k = 0; k < ARRAY_SIZE(exposed_item_seen_list); k++) {
                if (0 == strcmp(exposed_item_seen_list[k].bufname, analyzer_item->item_name))
                    exposed_item_seen_list[k].item_seen_ptr = &analyzer_item->item_seen;
            }

        }
        analyzer_item_map[analyzer_item->item_id] = (int16_t) i;
    }

    analyzer_init = true;
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
void EngineAnalysisRules(const DetectEngineCtx *de_ctx,
        const Signature *s, const char *line)
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
    uint32_t rule_content_http = 0;
    uint32_t rule_content_offset_depth = 0;
    int32_t list_id = 0;
    uint32_t rule_warning = 0;
    uint32_t stream_buf = 0;
    uint32_t packet_buf = 0;
    uint32_t file_store = 0;
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
    uint32_t warn_file_store_not_present = 0;
    uint32_t warn_offset_depth_pkt_stream = 0;
    uint32_t warn_offset_depth_alproto = 0;
    uint32_t warn_non_alproto_fp_for_alproto_sig = 0;
    uint32_t warn_no_direction = 0;
    uint32_t warn_both_direction = 0;

    EngineAnalysisItemsInit();

    bool *http_method_item_seen_ptr = exposed_item_seen_list[0].item_seen_ptr;
    bool *http_server_body_item_seen_ptr = exposed_item_seen_list[1].item_seen_ptr;

    if (s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        rule_bidirectional = 1;
    }

    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        packet_buf += 1;
    }
    if (s->flags & SIG_FLAG_FILESTORE) {
        file_store += 1;
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

    for (list_id = 0; list_id < (int)s->init_data->smlists_array_size; list_id++) {
        SigMatch *sm = NULL;
        for (sm = s->init_data->smlists[list_id]; sm != NULL; sm = sm->next) {
            int16_t item_slot = analyzer_item_map[list_id];
            if (sm->type == DETECT_PCRE) {
                if (item_slot == -1) {
                    rule_pcre++;
                    continue;
                }

                rule_pcre_http++;
                analyzer_items[item_slot].item_seen = true;
            } else if (sm->type == DETECT_CONTENT) {
                if (item_slot == -1) {
                    rule_content++;
                    if (list_id == DETECT_SM_LIST_PMATCH) {
                        DetectContentData *cd = (DetectContentData *)sm->ctx;
                        if (cd->flags & (DETECT_CONTENT_OFFSET | DETECT_CONTENT_DEPTH)) {
                            rule_content_offset_depth++;
                        }
                    }
                    continue;
                }

                rule_content_http++;
                analyzer_items[item_slot].item_seen = true;

                if (analyzer_items[item_slot].check_encoding_match) {
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd != NULL && PerCentEncodingMatch(cd->content, cd->content_len) > 0) {
                        warn_encoding_norm_http_buf += 1;
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


    if (file_store && !RequiresFeature("output::file-store")) {
        rule_warning += 1;
        warn_file_store_not_present = 1;
    }

    if (rule_pcre > 0 && rule_content == 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_pcre_no_content = 1;
    }

    if (rule_content_http > 0 && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http_content = 1;
    } else if (s->alproto == ALPROTO_HTTP1 && rule_pcre > 0 && rule_pcre_http == 0) {
        rule_warning += 1;
        warn_pcre_http = 1;
    }

    if (rule_content > 0 && rule_content_http > 0) {
        rule_warning += 1;
        warn_content_http_content = 1;
    }
    if (s->alproto == ALPROTO_HTTP1 && rule_content > 0 && rule_content_http == 0) {
        rule_warning += 1;
        warn_content_http = 1;
    }
    if (rule_content == 1) {
         //todo: warning if content is weak, separate warning for pcre + weak content
    }
    if (rule_flow == 0 && rule_flags == 0 && !(s->proto.flags & DETECT_PROTO_ANY) &&
            DetectProtoContainsProto(&s->proto, IPPROTO_TCP) &&
            (rule_content || rule_content_http || rule_pcre || rule_pcre_http || rule_flowbits ||
                    rule_flowint)) {
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

    if (*http_method_item_seen_ptr) {
        if (rule_flow && rule_flow_toclient) {
            rule_warning += 1;
            warn_method_toclient = 1;
        }
        if (*http_server_body_item_seen_ptr) {
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
    if (s->init_data->mpm_sm != NULL && s->alproto == ALPROTO_HTTP1 &&
            s->init_data->mpm_sm_list == DETECT_SM_LIST_PMATCH) {
        rule_warning += 1;
        warn_non_alproto_fp_for_alproto_sig = 1;
    }

    if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == 0) {
        warn_no_direction += 1;
        rule_warning += 1;
    }

    /* No warning about direction for ICMP protos */
    if (!(DetectProtoContainsProto(&s->proto, IPPROTO_ICMPV6) && DetectProtoContainsProto(&s->proto, IPPROTO_ICMP))) {
        if ((s->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) {
            warn_both_direction += 1;
            rule_warning += 1;
        }
    }

    if (!rule_warnings_only || (rule_warnings_only && rule_warning > 0)) {
        fprintf(rule_engine_analysis_FD, "== Sid: %u ==\n", s->id);
        fprintf(rule_engine_analysis_FD, "%s\n", line);

        if (s->flags & SIG_FLAG_IPONLY) fprintf(rule_engine_analysis_FD, "    Rule is ip only.\n");
        if (s->flags & SIG_FLAG_PDONLY) fprintf(rule_engine_analysis_FD, "    Rule is PD only.\n");
        if (rule_ipv6_only) fprintf(rule_engine_analysis_FD, "    Rule is IPv6 only.\n");
        if (rule_ipv4_only) fprintf(rule_engine_analysis_FD, "    Rule is IPv4 only.\n");
        if (packet_buf) fprintf(rule_engine_analysis_FD, "    Rule matches on packets.\n");
        if (!rule_flow_nostream && stream_buf &&
                (rule_flow || rule_flowbits || rule_flowint || rule_content || rule_pcre)) {
            fprintf(rule_engine_analysis_FD, "    Rule matches on reassembled stream.\n");
        }
        for(size_t i = 0; i < ARRAY_SIZE(analyzer_items); i++) {
            DetectEngineAnalyzerItems *ai = &analyzer_items[i];
            if (ai->item_seen) {
                 fprintf(rule_engine_analysis_FD, "    Rule matches on %s buffer.\n", ai->display_name);
            }
        }
        if (s->alproto != ALPROTO_UNKNOWN) {
            fprintf(rule_engine_analysis_FD, "    App layer protocol is %s.\n", AppProtoToString(s->alproto));
        }
        if (rule_content || rule_content_http || rule_pcre || rule_pcre_http) {
            fprintf(rule_engine_analysis_FD,
                    "    Rule contains %u content options, %u http content options, %u pcre "
                    "options, and %u pcre options with http modifiers.\n",
                    rule_content, rule_content_http, rule_pcre, rule_pcre_http);
        }

        /* print fast pattern info */
        if (s->init_data->prefilter_sm) {
            fprintf(rule_engine_analysis_FD, "    Prefilter on: %s.\n",
                    sigmatch_table[s->init_data->prefilter_sm->type].name);
        } else {
            EngineAnalysisRulesPrintFP(de_ctx, s);
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
        else if (warn_pcre_http /*s->alproto == ALPROTO_HTTP1 && rule_pcre > 0 && rule_pcre_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but pcre options do not have http modifiers.\n"
                                             "             -Consider adding http pcre modifiers.\n");
        }
        if (warn_content_http_content /*rule_content > 0 && rule_content_http > 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule contains content with http_* and content without http_*.\n"
                                         "             -Consider adding http content modifiers.\n");
        }
        if (warn_content_http /*s->alproto == ALPROTO_HTTP1 && rule_content > 0 && rule_content_http == 0*/) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule app layer protocol is http, but content options do not have http_* modifiers.\n"
                                             "             -Consider adding http content modifiers.\n");
        }
        if (rule_content == 1) {
             //todo: warning if content is weak, separate warning for pcre + weak content
        }
        if (warn_encoding_norm_http_buf) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule may contain percent encoded content for a normalized http buffer match.\n");
        }
        if (warn_tcp_no_flow /*rule_flow == 0 && rule_flags == 0
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
            fprintf(rule_engine_analysis_FD, "    Warning: Rule is inspecting both the request and the response.\n");
        }
        if (warn_file_store_not_present) {
            fprintf(rule_engine_analysis_FD, "    Warning: Rule requires file-store but the output file-store is not enabled.\n");
        }
        if (rule_warning == 0) {
            fprintf(rule_engine_analysis_FD, "    No warnings for this rule.\n");
        }
        fprintf(rule_engine_analysis_FD, "\n");
    }
    return;
}
