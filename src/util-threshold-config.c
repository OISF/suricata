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
 * \ingroup threshold
 * @{
 */

/**
 * \file
 *
 * \author Breno Silva Pinto <breno.silva@gmail.com>
 *
 * \todo Need to support suppress
 *
 * Implements Threshold support
 */

#include "suricata-common.h"

#include "host.h"
#include "ippair.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-threshold.h"
#include "detect-threshold.h"
#include "detect-parse.h"

#include "conf.h"
#include "util-threshold-config.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-time.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-fmemopen.h"

typedef enum ThresholdRuleType {
    THRESHOLD_TYPE_EVENT_FILTER,
    THRESHOLD_TYPE_THRESHOLD,
    THRESHOLD_TYPE_RATE,
    THRESHOLD_TYPE_SUPPRESS,
} ThresholdRuleType;

#ifdef UNITTESTS
/* File descriptor for unittests */
static FILE *g_ut_threshold_fp = NULL;
#endif

/* common base for all options */
#define DETECT_BASE_REGEX "^\\s*(event_filter|threshold|rate_filter|suppress)\\s*gen_id\\s*(\\d+)\\s*,\\s*sig_id\\s*(\\d+)\\s*(.*)\\s*$"

#define DETECT_THRESHOLD_REGEX                                                                     \
    "^,\\s*type\\s*(limit|both|threshold)\\s*,\\s*track\\s*(by_dst|by_src|by_both|by_rule)\\s*,"   \
    "\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*$"

/* TODO: "apply_to" */
#define DETECT_RATE_REGEX "^,\\s*track\\s*(by_dst|by_src|by_both|by_rule)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*,\\s*new_action\\s*(alert|drop|pass|log|sdrop|reject)\\s*,\\s*timeout\\s*(\\d+)\\s*$"

/*
 * suppress has two form:
 *  suppress gen_id 0, sig_id 0, track by_dst, ip 10.88.0.14
 *  suppress gen_id 1, sig_id 2000328
 *  suppress gen_id 1, sig_id 2000328, track by_src, ip fe80::/10
*/
#define DETECT_SUPPRESS_REGEX "^,\\s*track\\s*(by_dst|by_src|by_either)\\s*,\\s*ip\\s*([\\[\\],\\$\\s\\da-zA-Z.:/_]+)*\\s*$"

/* Default path for the threshold.config file */
#if defined OS_WIN32 || defined __CYGWIN__
#define THRESHOLD_CONF_DEF_CONF_FILEPATH CONFIG_DIR "\\\\threshold.config"
#else
#define THRESHOLD_CONF_DEF_CONF_FILEPATH CONFIG_DIR "/threshold.config"
#endif

static pcre *regex_base = NULL;
static pcre_extra *regex_base_study = NULL;

static pcre *regex_threshold = NULL;
static pcre_extra *regex_threshold_study = NULL;

static pcre *regex_rate = NULL;
static pcre_extra *regex_rate_study = NULL;

static pcre *regex_suppress = NULL;
static pcre_extra *regex_suppress_study = NULL;

static void SCThresholdConfDeInitContext(DetectEngineCtx *de_ctx, FILE *fd);

void SCThresholdConfGlobalInit(void)
{
    const char *eb = NULL;
    int eo;
    int opts = 0;

    regex_base = pcre_compile(DETECT_BASE_REGEX, opts, &eb, &eo, NULL);
    if (regex_base == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_BASE_REGEX, eo, eb);
    }

    regex_base_study = pcre_study(regex_base, 0, &eb);
    if (eb != NULL) {
        FatalError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
    }

    regex_threshold = pcre_compile(DETECT_THRESHOLD_REGEX, opts, &eb, &eo, NULL);
    if (regex_threshold == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_THRESHOLD_REGEX, eo, eb);
    }

    regex_threshold_study = pcre_study(regex_threshold, 0, &eb);
    if (eb != NULL) {
        FatalError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
    }

    regex_rate = pcre_compile(DETECT_RATE_REGEX, opts, &eb, &eo, NULL);
    if (regex_rate == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_RATE_REGEX, eo, eb);
    }

    regex_rate_study = pcre_study(regex_rate, 0, &eb);
    if (eb != NULL) {
        FatalError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
    }

    regex_suppress = pcre_compile(DETECT_SUPPRESS_REGEX, opts, &eb, &eo, NULL);
    if (regex_suppress == NULL) {
        FatalError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_SUPPRESS_REGEX, eo, eb);
    }

    regex_suppress_study = pcre_study(regex_suppress, 0, &eb);
    if (eb != NULL) {
        FatalError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
    }

}

void SCThresholdConfGlobalFree(void)
{
    if (regex_base != NULL) {
        pcre_free(regex_base);
        regex_base = NULL;
    }
    if (regex_base_study != NULL) {
        pcre_free(regex_base_study);
        regex_base_study = NULL;
    }

    if (regex_threshold != NULL) {
        pcre_free(regex_threshold);
        regex_threshold = NULL;
    }
    if (regex_threshold_study != NULL) {
        pcre_free(regex_threshold_study);
        regex_threshold_study = NULL;
    }

    if (regex_rate != NULL) {
        pcre_free(regex_rate);
        regex_rate = NULL;
    }
    if (regex_rate_study != NULL) {
        pcre_free(regex_rate_study);
        regex_rate_study = NULL;
    }

    if (regex_suppress != NULL) {
        pcre_free(regex_suppress);
        regex_suppress = NULL;
    }
    if (regex_suppress_study != NULL) {
        pcre_free(regex_suppress_study);
        regex_suppress_study = NULL;
    }
}

/**
 * \brief Returns the path for the Threshold Config file.  We check if we
 *        can retrieve the path from the yaml conf file.  If it is not present,
 *        return the default path for the threshold file which is
 *        "./threshold.config".
 *
 * \retval log_filename Pointer to a string containing the path for the
 *                      Threshold Config file.
 */
static const char *SCThresholdConfGetConfFilename(const DetectEngineCtx *de_ctx)
{
    const char *log_filename = NULL;

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0) {
        char config_value[256];
        snprintf(config_value, sizeof(config_value),
                 "%s.threshold-file", de_ctx->config_prefix);

        /* try loading prefix setting, fall back to global if that
         * fails. */
        if (ConfGet(config_value, &log_filename) != 1) {
            if (ConfGet("threshold-file", &log_filename) != 1) {
                log_filename = (char *)THRESHOLD_CONF_DEF_CONF_FILEPATH;
            }
        }
    } else {
        if (ConfGet("threshold-file", &log_filename) != 1) {
            log_filename = (char *)THRESHOLD_CONF_DEF_CONF_FILEPATH;
        }
    }
    return log_filename;
}

/**
 * \brief Inits the context to be used by the Threshold Config parsing API.
 *
 *        This function initializes the hash table to be used by the Detection
 *        Engine Context to hold the data from the threshold.config file,
 *        obtains the file desc to parse the threshold.config file, and
 *        inits the regex used to parse the lines from threshold.config
 *        file.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCThresholdConfInitContext(DetectEngineCtx *de_ctx)
{
    const char *filename = NULL;
#ifndef UNITTESTS
    FILE *fd = NULL;
#else
    FILE *fd = g_ut_threshold_fp;
    if (fd == NULL) {
#endif
        filename = SCThresholdConfGetConfFilename(de_ctx);
        if ( (fd = fopen(filename, "r")) == NULL) {
            SCLogWarning(SC_ERR_FOPEN, "Error opening file: \"%s\": %s", filename, strerror(errno));
            goto error;
        }
#ifdef UNITTESTS
    }
#endif

    SCThresholdConfParseFile(de_ctx, fd);
    SCThresholdConfDeInitContext(de_ctx, fd);

#ifdef UNITTESTS
    g_ut_threshold_fp = NULL;
#endif
    SCLogDebug("Global thresholding options defined");
    return 0;

error:
    SCThresholdConfDeInitContext(de_ctx, fd);
    return -1;
}

/**
 * \brief Releases resources used by the Threshold Config API.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param fd Pointer to file descriptor.
 */
static void SCThresholdConfDeInitContext(DetectEngineCtx *de_ctx, FILE *fd)
{
    if (fd != NULL)
        fclose(fd);
    return;
}

/** \internal
 *  \brief setup suppress rules
 *  \retval 0 ok
 *  \retval -1 error
 */
static int SetupSuppressRule(DetectEngineCtx *de_ctx, uint32_t id, uint32_t gid,
        uint8_t parsed_type, uint8_t parsed_track, uint32_t parsed_count,
        uint32_t parsed_seconds, uint32_t parsed_timeout, uint8_t parsed_new_action,
        const char *th_ip)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectThresholdData *de = NULL;

    BUG_ON(parsed_type != TYPE_SUPPRESS);

    DetectThresholdData *orig_de = NULL;
    if (parsed_track != TRACK_RULE) {
        orig_de = SCCalloc(1, sizeof(DetectThresholdData));
        if (unlikely(orig_de == NULL))
            goto error;

        orig_de->type = TYPE_SUPPRESS;
        orig_de->track = parsed_track;
        orig_de->count = parsed_count;
        orig_de->seconds = parsed_seconds;
        orig_de->new_action = parsed_new_action;
        orig_de->timeout = parsed_timeout;
        if (DetectAddressParse((const DetectEngineCtx *)de_ctx, &orig_de->addrs, (char *)th_ip) <
                0) {
            SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "failed to parse %s", th_ip);
            goto error;
        }
    }

    /* Install it */
    if (id == 0 && gid == 0) {
        if (parsed_track == TRACK_RULE) {
            SCLogWarning(SC_ERR_EVENT_ENGINE, "suppressing all rules");
        }

        /* update each sig with our suppress info */
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            /* tag the rule as noalert */
            if (parsed_track == TRACK_RULE) {
                s->flags |= SIG_FLAG_NOALERT;
                continue;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_SUPPRESS);
        }
    } else if (id == 0 && gid > 0)    {
        if (parsed_track == TRACK_RULE) {
            SCLogWarning(SC_ERR_EVENT_ENGINE, "suppressing all rules with gid %"PRIu32, gid);
        }
        /* set up suppression for each signature with a matching gid */
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            if (s->gid != gid)
                continue;

            /* tag the rule as noalert */
            if (parsed_track == TRACK_RULE) {
                s->flags |= SIG_FLAG_NOALERT;
                continue;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_SUPPRESS);
        }
    } else if (id > 0 && gid == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Can't use a event config that has "
                                         "sid > 0 and gid == 0. Please fix this "
                                         "in your threshold.config file");
        goto error;
    } else {
        s = SigFindSignatureBySidGid(de_ctx, id, gid);
        if (s == NULL) {
            SCLogWarning(SC_ERR_EVENT_ENGINE, "can't suppress sid "
                    "%"PRIu32", gid %"PRIu32": unknown rule", id, gid);
        } else {
            if (parsed_track == TRACK_RULE) {
                s->flags |= SIG_FLAG_NOALERT;
                goto end;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_SUPPRESS);
        }
    }

end:
    if (orig_de != NULL) {
        DetectAddressHeadCleanup(&orig_de->addrs);
        SCFree(orig_de);
    }
    return 0;
error:
    if (orig_de != NULL) {
        DetectAddressHeadCleanup(&orig_de->addrs);
        SCFree(orig_de);
    }
    if (de != NULL) {
        DetectAddressHeadCleanup(&de->addrs);
        SCFree(de);
    }
    return -1;
}

/** \internal
 *  \brief setup suppress rules
 *  \retval 0 ok
 *  \retval -1 error
 */
static int SetupThresholdRule(DetectEngineCtx *de_ctx, uint32_t id, uint32_t gid,
        uint8_t parsed_type, uint8_t parsed_track, uint32_t parsed_count,
        uint32_t parsed_seconds, uint32_t parsed_timeout, uint8_t parsed_new_action,
        const char *th_ip)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectThresholdData *de = NULL;

    BUG_ON(parsed_type == TYPE_SUPPRESS);

    /* Install it */
    if (id == 0 && gid == 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            sm = DetectGetLastSMByListId(s,
                    DETECT_SM_LIST_THRESHOLD, DETECT_THRESHOLD, -1);
            if (sm != NULL) {
                SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                        "an event var set.  The signature event var is "
                        "given precedence over the threshold.conf one.  "
                        "We'll change this in the future though.", s->id);
                continue;
            }

            sm = DetectGetLastSMByListId(s,
                    DETECT_SM_LIST_THRESHOLD, DETECT_DETECTION_FILTER, -1);
            if (sm != NULL) {
                SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                        "an event var set.  The signature event var is "
                        "given precedence over the threshold.conf one.  "
                        "We'll change this in the future though.", s->id);
                continue;
            }

            de = SCMalloc(sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;
            memset(de,0,sizeof(DetectThresholdData));

            de->type = parsed_type;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            if (parsed_type == TYPE_RATE)
                sm->type = DETECT_DETECTION_FILTER;
            else
                sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);
        }

    } else if (id == 0 && gid > 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            if (s->gid == gid) {
                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_THRESHOLD, DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "an event var set.  The signature event var is "
                            "given precedence over the threshold.conf one.  "
                            "We'll change this in the future though.", id);
                    continue;
                }

                de = SCMalloc(sizeof(DetectThresholdData));
                if (unlikely(de == NULL))
                    goto error;
                memset(de,0,sizeof(DetectThresholdData));

                de->type = parsed_type;
                de->track = parsed_track;
                de->count = parsed_count;
                de->seconds = parsed_seconds;
                de->new_action = parsed_new_action;
                de->timeout = parsed_timeout;

                sm = SigMatchAlloc();
                if (sm == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                    goto error;
                }

                if (parsed_type == TYPE_RATE)
                    sm->type = DETECT_DETECTION_FILTER;
                else
                    sm->type = DETECT_THRESHOLD;
                sm->ctx = (void *)de;

                SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);
            }
        }
    } else if (id > 0 && gid == 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Can't use a event config that has "
                   "sid > 0 and gid == 0. Please fix this "
                   "in your threshold.conf file");
    } else {
        s = SigFindSignatureBySidGid(de_ctx, id, gid);
        if (s == NULL) {
            SCLogWarning(SC_ERR_EVENT_ENGINE, "can't suppress sid "
                    "%"PRIu32", gid %"PRIu32": unknown rule", id, gid);
        } else {
            if (parsed_type != TYPE_SUPPRESS && parsed_type != TYPE_THRESHOLD &&
                parsed_type != TYPE_BOTH && parsed_type != TYPE_LIMIT)
            {
                sm = DetectGetLastSMByListId(s,
                        DETECT_SM_LIST_THRESHOLD, DETECT_THRESHOLD, -1);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "a threshold set. The signature event var is "
                            "given precedence over the threshold.conf one. "
                            "Bug #425.", s->id);
                    goto end;
                }

                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "a detection_filter set. The signature event var is "
                            "given precedence over the threshold.conf one. "
                            "Bug #425.", s->id);
                    goto end;
                }

            /* replace threshold on sig if we have a global override for it */
            } else if (parsed_type == TYPE_THRESHOLD || parsed_type == TYPE_BOTH || parsed_type == TYPE_LIMIT) {
                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_THRESHOLD, DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SigMatchRemoveSMFromList(s, sm, DETECT_SM_LIST_THRESHOLD);
                    SigMatchFree(de_ctx, sm);
                    sm = NULL;
                }
            }

            de = SCMalloc(sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;
            memset(de,0,sizeof(DetectThresholdData));

            de->type = parsed_type;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            if (parsed_type == TYPE_RATE)
                sm->type = DETECT_DETECTION_FILTER;
            else
                sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);
        }
    }
end:
    return 0;
error:
    if (de != NULL) {
        DetectAddressHeadCleanup(&de->addrs);
        SCFree(de);
    }
    return -1;
}

static int ParseThresholdRule(DetectEngineCtx *de_ctx, char *rawstr,
    uint32_t *ret_id, uint32_t *ret_gid,
    uint8_t *ret_parsed_type, uint8_t *ret_parsed_track,
    uint32_t *ret_parsed_count, uint32_t *ret_parsed_seconds, uint32_t *ret_parsed_timeout,
    uint8_t *ret_parsed_new_action,
    char **ret_th_ip)
{
    char th_rule_type[32];
    char th_gid[16];
    char th_sid[16];
    const char *rule_extend = NULL;
    char th_type[16] = "";
    char th_track[16] = "";
    char th_count[16] = "";
    char th_seconds[16] = "";
    char th_new_action[16] = "";
    char th_timeout[16] = "";
    const char *th_ip = NULL;

    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint8_t parsed_new_action = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;
    uint32_t parsed_timeout = 0;

    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    uint32_t id = 0, gid = 0;
    ThresholdRuleType rule_type;

    if (de_ctx == NULL)
        return -1;

    ret = pcre_exec(regex_base, regex_base_study, rawstr, strlen(rawstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 4) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

    /* retrieve the classtype name */
    ret = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 1, th_rule_type, sizeof(th_rule_type));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    /* retrieve the classtype name */
    ret = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 2, th_gid, sizeof(th_gid));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    ret = pcre_copy_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 3, th_sid, sizeof(th_sid));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    /* Use "get" for heap allocation */
    ret = pcre_get_substring((char *)rawstr, ov, MAX_SUBSTRINGS, 4, &rule_extend);
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* get type of rule */
    if (strcasecmp(th_rule_type,"event_filter") == 0) {
        rule_type = THRESHOLD_TYPE_EVENT_FILTER;
    } else if (strcasecmp(th_rule_type,"threshold") == 0) {
        rule_type = THRESHOLD_TYPE_THRESHOLD;
    } else if (strcasecmp(th_rule_type,"rate_filter") == 0) {
        rule_type = THRESHOLD_TYPE_RATE;
    } else if (strcasecmp(th_rule_type,"suppress") == 0) {
        rule_type = THRESHOLD_TYPE_SUPPRESS;
    } else {
        SCLogError(SC_ERR_INVALID_VALUE, "rule type %s is unknown", th_rule_type);
        goto error;
    }

    /* get end of rule */
    switch(rule_type) {
        case THRESHOLD_TYPE_EVENT_FILTER:
        case THRESHOLD_TYPE_THRESHOLD:
            if (strlen(rule_extend) > 0) {
                ret = pcre_exec(regex_threshold, regex_threshold_study,
                        rule_extend, strlen(rule_extend),
                        0, 0, ov, MAX_SUBSTRINGS);
                if (ret < 4) {
                    SCLogError(SC_ERR_PCRE_MATCH,
                            "pcre_exec parse error, ret %" PRId32 ", string %s",
                            ret, rule_extend);
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 1, th_type, sizeof(th_type));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 2, th_track, sizeof(th_track));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 3, th_count, sizeof(th_count));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 4, th_seconds, sizeof(th_seconds));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                if (strcasecmp(th_type,"limit") == 0)
                    parsed_type = TYPE_LIMIT;
                else if (strcasecmp(th_type,"both") == 0)
                    parsed_type = TYPE_BOTH;
                else if (strcasecmp(th_type,"threshold") == 0)
                    parsed_type = TYPE_THRESHOLD;
                else {
                    SCLogError(SC_ERR_INVALID_ARGUMENTS, "limit type not supported: %s", th_type);
                    goto error;
                }
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENTS, "rule invalid: %s", rawstr);
                goto error;
            }
            break;
        case THRESHOLD_TYPE_SUPPRESS:
            if (strlen(rule_extend) > 0) {
                ret = pcre_exec(regex_suppress, regex_suppress_study,
                        rule_extend, strlen(rule_extend),
                        0, 0, ov, MAX_SUBSTRINGS);
                if (ret < 2) {
                    SCLogError(SC_ERR_PCRE_MATCH,
                            "pcre_exec parse error, ret %" PRId32 ", string %s",
                            ret, rule_extend);
                    goto error;
                }
                /* retrieve the track mode */
                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 1, th_track, sizeof(th_track));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }
                /* retrieve the IP; use "get" for heap allocation */
                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 2, &th_ip);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }
            } else {
                parsed_track = TRACK_RULE;
            }
            parsed_type = TYPE_SUPPRESS;
            break;
        case THRESHOLD_TYPE_RATE:
            if (strlen(rule_extend) > 0) {
                ret = pcre_exec(regex_rate, regex_rate_study,
                        rule_extend, strlen(rule_extend),
                        0, 0, ov, MAX_SUBSTRINGS);
                if (ret < 5) {
                    SCLogError(SC_ERR_PCRE_MATCH,
                            "pcre_exec parse error, ret %" PRId32 ", string %s",
                            ret, rule_extend);
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 1, th_track, sizeof(th_track));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 2, th_count, sizeof(th_count));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 3, th_seconds, sizeof(th_seconds));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 4, th_new_action, sizeof(th_new_action));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                ret = pcre_copy_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 5, th_timeout, sizeof(th_timeout));
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_COPY_SUBSTRING, "pcre_copy_substring failed");
                    goto error;
                }

                /* TODO: implement option "apply_to" */

                if (StringParseUint32(&parsed_timeout, 10, strlen(th_timeout), th_timeout) <= 0) {
                    goto error;
                }

                /* Get the new action to take */
                if (strcasecmp(th_new_action, "alert") == 0)
                    parsed_new_action = TH_ACTION_ALERT;
                if (strcasecmp(th_new_action, "drop") == 0)
                    parsed_new_action = TH_ACTION_DROP;
                if (strcasecmp(th_new_action, "pass") == 0)
                    parsed_new_action = TH_ACTION_PASS;
                if (strcasecmp(th_new_action, "reject") == 0)
                    parsed_new_action = TH_ACTION_REJECT;
                if (strcasecmp(th_new_action, "log") == 0) {
                    SCLogInfo("log action for rate_filter not supported yet");
                    parsed_new_action = TH_ACTION_LOG;
                }
                if (strcasecmp(th_new_action, "sdrop") == 0) {
                    SCLogInfo("sdrop action for rate_filter not supported yet");
                    parsed_new_action = TH_ACTION_SDROP;
                }
                parsed_type = TYPE_RATE;
            } else {
                SCLogError(SC_ERR_INVALID_ARGUMENTS, "rule invalid: %s", rawstr);
                goto error;
            }
            break;
    }

    switch (rule_type) {
        /* This part is common to threshold/event_filter/rate_filter */
        case THRESHOLD_TYPE_EVENT_FILTER:
        case THRESHOLD_TYPE_THRESHOLD:
        case THRESHOLD_TYPE_RATE:
            if (strcasecmp(th_track,"by_dst") == 0)
                parsed_track = TRACK_DST;
            else if (strcasecmp(th_track,"by_src") == 0)
                parsed_track = TRACK_SRC;
            else if (strcasecmp(th_track, "by_both") == 0) {
                parsed_track = TRACK_BOTH;
            }
            else if (strcasecmp(th_track,"by_rule") == 0)
                parsed_track = TRACK_RULE;
            else {
                SCLogError(SC_ERR_INVALID_VALUE, "Invalid track parameter %s in %s", th_track, rawstr);
                goto error;
            }

            if (StringParseUint32(&parsed_count, 10, strlen(th_count), th_count) <= 0) {
                goto error;
            }
            if (parsed_count == 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "rate filter count should be > 0");
                goto error;
            }

            if (StringParseUint32(&parsed_seconds, 10, strlen(th_seconds), th_seconds) <= 0) {
                goto error;
            }

           break;
        case THRESHOLD_TYPE_SUPPRESS:
            /* need to get IP if extension is provided */
            if (strcmp("", th_track) != 0) {
                if (strcasecmp(th_track,"by_dst") == 0)
                    parsed_track = TRACK_DST;
                else if (strcasecmp(th_track,"by_src") == 0)
                    parsed_track = TRACK_SRC;
                else if (strcasecmp(th_track,"by_either") == 0) {
                    parsed_track = TRACK_EITHER;
                }
                else {
                    SCLogError(SC_ERR_INVALID_VALUE, "Invalid track parameter %s in %s", th_track, rule_extend);
                    goto error;
                }
            }
            break;
    }

    if (StringParseUint32(&id, 10, strlen(th_sid), th_sid) <= 0) {
        goto error;
    }

    if (StringParseUint32(&gid, 10, strlen(th_gid), th_gid) <= 0) {
        goto error;
    }

    *ret_id = id;
    *ret_gid = gid;
    *ret_parsed_type = parsed_type;
    *ret_parsed_track = parsed_track;
    *ret_parsed_new_action = parsed_new_action;
    *ret_parsed_count = parsed_count;
    *ret_parsed_seconds = parsed_seconds;
    *ret_parsed_timeout = parsed_timeout;
    *ret_th_ip = NULL;
    if (th_ip != NULL) {
        *ret_th_ip = (char *)th_ip;
    } else {
        SCFree((char *)th_ip);
    }
    SCFree((char *)rule_extend);
    return 0;

error:
    if (rule_extend != NULL) {
        SCFree((char *)rule_extend);
    }
    if (th_ip != NULL) {
        SCFree((char *)th_ip);
    }
    return -1;
}

/**
 * \brief Parses a line from the threshold file and applies it to the
 *        detection engine
 *
 * \param rawstr Pointer to the string to be parsed.
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCThresholdConfAddThresholdtype(char *rawstr, DetectEngineCtx *de_ctx)
{
    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint8_t parsed_new_action = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;
    uint32_t parsed_timeout = 0;
    char *th_ip = NULL;
    uint32_t id = 0, gid = 0;

    int r = 0;
    r = ParseThresholdRule(de_ctx, rawstr, &id, &gid, &parsed_type, &parsed_track,
                    &parsed_count, &parsed_seconds, &parsed_timeout, &parsed_new_action,
                    &th_ip);
    if (r < 0)
        goto error;

    if (parsed_type == TYPE_SUPPRESS) {
        r = SetupSuppressRule(de_ctx, id, gid, parsed_type, parsed_track,
                    parsed_count, parsed_seconds, parsed_timeout, parsed_new_action,
                    th_ip);
    } else {
        r = SetupThresholdRule(de_ctx, id, gid, parsed_type, parsed_track,
                    parsed_count, parsed_seconds, parsed_timeout, parsed_new_action,
                    th_ip);
    }
    if (r < 0) {
        goto error;
    }

    SCFree(th_ip);
    return 0;
error:
    if (th_ip != NULL)
        SCFree(th_ip);
    return -1;
}

/**
 * \brief Checks if a string is a comment or a blank line.
 *
 *        Comments lines are lines of the following format -
 *        "# This is a comment string" or
 *        "   # This is a comment string".
 *
 * \param line String that has to be checked
 *
 * \retval 1 On the argument string being a comment or blank line
 * \retval 0 Otherwise
 */
static int SCThresholdConfIsLineBlankOrComment(char *line)
{
    while (*line != '\0') {
        /* we have a comment */
        if (*line == '#')
            return 1;

        /* this line is neither a comment line, nor a blank line */
        if (!isspace((unsigned char)*line))
            return 0;

        line++;
    }

    /* we have a blank line */
    return 1;
}

/**
 * \brief Checks if the rule is multiline, by searching an ending slash
 *
 * \param line String that has to be checked
 *
 * \retval the position of the slash making it multiline
 * \retval 0 Otherwise
 */
static int SCThresholdConfLineIsMultiline(char *line)
{
    int flag = 0;
    char *rline = line;
    int len = strlen(line);

    while (line < rline + len && *line != '\n') {
        /* we have a comment */
        if (*line == '\\')
            flag = line - rline;
        else
            if (!isspace((unsigned char)*line))
                flag = 0;

        line++;
    }

    /* we have a blank line */
    return flag;
}

/**
 * \brief Parses the Threshold Config file
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param fd Pointer to file descriptor.
 */
void SCThresholdConfParseFile(DetectEngineCtx *de_ctx, FILE *fp)
{
    char line[8192] = "";
    int rule_num = 0;

    /* position of "\", on multiline rules */
    int esc_pos = 0;

    if (fp == NULL)
        return;

    while (fgets(line + esc_pos, (int)sizeof(line) - esc_pos, fp) != NULL) {
        if (SCThresholdConfIsLineBlankOrComment(line)) {
            continue;
        }

        esc_pos = SCThresholdConfLineIsMultiline(line);
        if (esc_pos == 0) {
            rule_num++;
            SCLogDebug("Adding threshold.config rule num %"PRIu32"( %s )", rule_num, line);
            SCThresholdConfAddThresholdtype(line, de_ctx);
        }
    }

    SCLogInfo("Threshold config parsed: %d rule(s) found", rule_num);

    return;
}

#ifdef UNITTESTS

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD01(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "event_filter gen_id 1, sig_id 10, type limit, track by_src, count 1, seconds 60\n"
        "threshold gen_id 1, sig_id 100, type both, track by_dst, count 10, seconds 60\n"
        "event_filter gen_id 1, sig_id 1000, type threshold, track by_src, count 100, seconds 60\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with some valid options and a couple of invalid options.
 *        For testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateInValidDummyFD02(void)
{
    FILE *fd;
    const char *buffer =
        "event_filter gen_id 1, sig_id 1000, type invalid, track by_src, count 100, seconds 60\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD03(void)
{
    FILE *fd;
    const char *buffer =
        "event_filter gen_id 0, sig_id 0, type threshold, track by_src, count 100, seconds 60\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD04(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "event_filter gen_id 1 \\\n, sig_id 10, type limit, track by_src, \\\ncount 1, seconds 60\n"
        "threshold gen_id 1, \\\nsig_id 100, type both\\\n, track by_dst, count 10, \\\n seconds 60\n"
        "event_filter gen_id 1, sig_id 1000, \\\ntype threshold, track \\\nby_src, count 100, seconds 60\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD05(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_src, count 1, seconds 60, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, sig_id 100, track by_dst, count 10, seconds 60, new_action pass, timeout 5\n"
        "rate_filter gen_id 1, sig_id 1000, track by_rule, count 100, seconds 60, new_action alert, timeout 30\n"
        "rate_filter gen_id 1, sig_id 10000, track by_both, count 1000, seconds 60, new_action reject, timeout 21\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD06(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter \\\ngen_id 1, sig_id 10, track by_src, count 1, seconds 60\\\n, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, \\\nsig_id 100, track by_dst, \\\ncount 10, seconds 60, new_action pass, timeout 5\n"
        "rate_filter gen_id 1, sig_id 1000, \\\ntrack by_rule, count 100, seconds 60, new_action alert, timeout 30\n"
        "rate_filter gen_id 1, sig_id 10000, track by_both, count 1000, \\\nseconds 60, new_action reject, timeout 21\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD07(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_src, count 3, seconds 3, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, sig_id 11, track by_src, count 3, seconds 1, new_action drop, timeout 5\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, for testing rate_filter, track by_rule
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD08(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_rule, count 3, seconds 3, new_action drop, timeout 10\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD09(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "event_filter gen_id 1 \\\n, sig_id 10, type limit, track by_src, \\\ncount 2, seconds 60\n"
        "threshold gen_id 1, \\\nsig_id 11, type threshold\\\n, track by_dst, count 3, \\\n seconds 60\n"
        "event_filter gen_id 1, sig_id 12, \\\ntype both, track \\\nby_src, count 2, seconds 60\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD10(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "event_filter gen_id 1 \\\n, sig_id 10, type limit, track by_src, \\\ncount 5, seconds 2\n"
        "threshold gen_id 1, \\\nsig_id 11, type threshold\\\n, track by_dst, count 5, \\\n seconds 2\n"
        "event_filter gen_id 1, sig_id 12, \\\ntype both, track \\\nby_src, count 5, seconds 2\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD11(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "suppress gen_id 1, sig_id 10000\n"
        "suppress gen_id 1, sig_id 1000, track by_src, ip 192.168.1.1\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD01();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);

    FAIL_IF_NOT(de->type == TYPE_LIMIT && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:100;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD01();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);

    FAIL_IF_NOT(de->type == TYPE_BOTH && de->track == TRACK_DST && de->count == 10 && de->seconds == 60);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD01();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);

    FAIL_IF_NOT(de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateInValidDummyFD02();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NOT_NULL(m);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1;)");
    FAIL_IF_NULL(sig);
    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any 80 (msg:\"Threshold limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any 80 (msg:\"Threshold limit\"; gid:1; sid:100;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD03();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    Signature *s = de_ctx->sig_list;
    SigMatch *m = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);
    FAIL_IF_NULL(m->ctx);
    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NOT(de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60);

    s = de_ctx->sig_list->next;
    m = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);
    FAIL_IF_NULL(m->ctx);
    de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NOT(de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60);

    s = de_ctx->sig_list->next->next;
    m = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);
    FAIL_IF_NULL(m->ctx);
    de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NOT(de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60);

    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD04();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_LIMIT && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the rate_filter rules are loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest07(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD05();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_DETECTION_FILTER, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_RATE && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the rate_filter rules are loaded and well parsed
 *       with multilines
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest08(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD06();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_DETECTION_FILTER, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_RATE && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest09(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    HostInitConfig(HOST_QUIET);

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    DetectEngineThreadCtx *det_ctx = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"ratefilter test\"; gid:1; sid:10;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD07();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP));
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP));
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP));

    TimeSetIncrementTime(2);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || !(PACKET_TEST_ACTION(p, ACTION_DROP)));

    TimeSetIncrementTime(3);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || !(PACKET_TEST_ACTION(p, ACTION_DROP)));

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP));

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the rate_filter rules work with track by_rule
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest10(void)
{
    HostInitConfig(HOST_QUIET);

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    /* Create two different packets falling to the same rule, and
    *  because count:3, we should drop on match #4.
    */
    Packet *p1 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP,
            "172.26.0.2", "172.26.0.11");
    FAIL_IF_NULL(p1);
    Packet *p2 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP,
            "172.26.0.1", "172.26.0.10");
    FAIL_IF_NULL(p2);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    DetectEngineThreadCtx *det_ctx = NULL;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"ratefilter test\"; gid:1; sid:10;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD08();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    TimeGet(&p1->ts);
    p2->ts = p1->ts;

    /* All should be alerted, none dropped */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);
    p2->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;

    /* Match #4 should be dropped*/
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);
    p2->action = 0;

    TimeSetIncrementTime(2);
    TimeGet(&p1->ts);

    /* Still dropped because timeout not expired */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;

    TimeSetIncrementTime(10);
    TimeGet(&p1->ts);

    /* Not dropped because timeout expired */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    /* Ensure that a Threshold entry was installed at the sig */
    FAIL_IF_NULL(de_ctx->ths_ctx.th_entry[s->num]);

    UTHFreePacket(p1);
    UTHFreePacket(p2);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest11(void)
{
    HostInitConfig(HOST_QUIET);

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    DetectEngineThreadCtx *det_ctx = NULL;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test threshold\"; gid:1; sid:11;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test both\"; gid:1; sid:12;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD09();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);

    int alerts10 = 0;
    int alerts11 = 0;
    int alerts12 = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);

    TimeSetIncrementTime(100);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);

    FAIL_IF_NOT(alerts10 == 4);
    /* One on the first interval, another on the second */
    FAIL_IF_NOT(alerts11 == 2);
    FAIL_IF_NOT(alerts12 == 2);

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest12(void)
{
    HostInitConfig(HOST_QUIET);

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    DetectEngineThreadCtx *det_ctx = NULL;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test limit\"; gid:1; sid:10;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test threshold\"; gid:1; sid:11;)");
    FAIL_IF_NULL(s);
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"event_filter test both\"; gid:1; sid:12;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD10();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);

    int alerts10 = 0;
    int alerts11 = 0;
    int alerts12 = 0;

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);

    TimeSetIncrementTime(100);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);
    alerts12 += PacketAlertCheck(p, 12);

    FAIL_IF_NOT(alerts10 == 10);
    /* One on the first interval, another on the second */
    FAIL_IF_NOT(alerts11 == 1);
    FAIL_IF_NOT(alerts12 == 1);

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest13(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigMatch *m = DetectGetLastSMByListId(sig,
            DETECT_SM_LIST_SUPPRESS, DETECT_THRESHOLD, -1);
    FAIL_IF_NULL(m);

    DetectThresholdData *de = (DetectThresholdData *)m->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest14(void)
{
    HostInitConfig(HOST_QUIET);

    Packet *p1 = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p1);
    Packet *p2 = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.1.1",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p2);

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any (msg:\"suppress test\"; gid:1; sid:10000;)");
    FAIL_IF_NULL(sig);
    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"suppress test 2\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);
    sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"suppress test 3\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    FAIL_IF_NOT(PacketAlertCheck(p1, 10000) == 0);
    FAIL_IF_NOT(PacketAlertCheck(p1, 10) == 1);
    FAIL_IF_NOT(PacketAlertCheck(p1, 1000) == 1);
    FAIL_IF_NOT(PacketAlertCheck(p2, 1000) == 0);

    UTHFreePacket(p1);
    UTHFreePacket(p2);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    PASS;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest15(void)
{
    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any any (msg:\"suppress test\"; content:\"lalala\"; gid:1; sid:10000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    FAIL_IF(PacketAlertCheck(p, 10000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PACKET_TEST_ACTION(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest16(void)
{
    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.1.1",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any any (msg:\"suppress test\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PACKET_TEST_ACTION(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the suppress rules work - ip only rule
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest17(void)
{
    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    struct timeval ts;
    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:10000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    FAIL_IF(PacketAlertCheck(p, 10000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PACKET_TEST_ACTION(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateInvalidDummyFD12(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "suppress gen_id 1, sig_id 2200029, track by_dst, ip fe80::/16\n"
        "suppress gen_id 1, sig_id 2200029, track by_stc, ip fe80::/16\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \test Check if the suppress rule parsing handles errors correctly
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest18(void)
{
    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateInvalidDummyFD12();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);
    SigGroupBuild(de_ctx);

    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_DST);

    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateInvalidDummyFD13(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "suppress gen_id 1, sig_id 2200029, track by_stc, ip fe80::/16\n"
        "suppress gen_id 1, sig_id 2200029, track by_dst, ip fe80::/16\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \test Check if the suppress rule parsing handles errors correctly
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest19(void)
{
    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateInvalidDummyFD13();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);
    SigGroupBuild(de_ctx);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_DST);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateValidDummyFD20(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "suppress gen_id 1, sig_id 1000, track by_src, ip 2.2.3.4\n"
        "suppress gen_id 1, sig_id 1000, track by_src, ip 1.2.3.4\n"
        "suppress gen_id 1, sig_id 1000, track by_src, ip 192.168.1.1\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest20(void)
{
    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; sid:1000;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD20();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);
    SigGroupBuild(de_ctx);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);

    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF(smd->is_last);

    smd++;
    de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF(smd->is_last);

    smd++;
    de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF_NOT(smd->is_last);

    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed, and applied
 *       correctly to a rule with thresholding
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest21(void)
{
    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    FAIL_IF_NULL(s);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD20();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);
    SigGroupBuild(de_ctx);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);

    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF(smd->is_last);

    smd++;
    de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF(smd->is_last);

    smd++;
    de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_SRC);
    FAIL_IF_NOT(smd->is_last);

    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    PASS;
}

/**
* \brief Creates a dummy rate_filter file, for testing rate filtering by_both source and destination
*
* \retval fd Pointer to file descriptor.
*/
static FILE *SCThresholdConfGenerateValidDummyFD22(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_both, count 2, seconds 5, new_action drop, timeout 6\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
* \test Check if the rate_filter rules work with track by_both
*
*  \retval 1 on succces
*  \retval 0 on failure
*/
static int SCThresholdConfTest22(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    IPPairInitConfig(IPPAIR_QUIET);

    struct timeval ts;
    memset(&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    /* This packet will cause rate_filter */
    Packet *p1 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.1", "172.26.0.10");
    FAIL_IF_NULL(p1);

    /* Should not be filtered for different destination */
    Packet *p2 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.1", "172.26.0.2");
    FAIL_IF_NULL(p2);

    /* Should not be filtered when both src and dst the same */
    Packet *p3 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.1", "172.26.0.1");
    FAIL_IF_NULL(p3);

    DetectEngineThreadCtx *det_ctx = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"ratefilter by_both test\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD22();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p1->ts);
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, none dropped */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PACKET_TEST_ACTION(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    p1->action = p2->action = p3->action = 0;

    TimeSetIncrementTime(2);
    TimeGet(&p1->ts);
    p2->ts = p3->ts = p1->ts;

    /* p1 still shouldn't be dropped after 2nd alert */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    p1->action = 0;

    TimeSetIncrementTime(2);
    TimeGet(&p1->ts);
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, only p1 must be dropped  due to rate_filter*/
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PACKET_TEST_ACTION(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    p1->action = p2->action = p3->action = 0;

    TimeSetIncrementTime(7);
    TimeGet(&p1->ts);
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, none dropped (because timeout expired) */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PACKET_TEST_ACTION(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    UTHFreePacket(p3);
    UTHFreePacket(p2);
    UTHFreePacket(p1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    IPPairShutdown();
    PASS;
}

/**
* \brief Creates a dummy rate_filter file, for testing rate filtering by_both source and destination
*
* \retval fd Pointer to file descriptor.
*/
static FILE *SCThresholdConfGenerateValidDummyFD23(void)
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_both, count 1, seconds 5, new_action drop, timeout 6\n";

    fd = SCFmemopen((void *)buffer, strlen(buffer), "r");
    if (fd == NULL)
        SCLogDebug("Error with SCFmemopen() called by Threshold Config test code");

    return fd;
}

/**
* \test Check if the rate_filter by_both work when similar packets
*       going in opposite direction
*
*  \retval 1 on succces
*  \retval 0 on failure
*/
static int SCThresholdConfTest23(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    IPPairInitConfig(IPPAIR_QUIET);

    struct timeval ts;
    memset(&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    /* Create two packets between same addresses in opposite direction */
    Packet *p1 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.1", "172.26.0.10");
    FAIL_IF_NULL(p1);

    Packet *p2 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.10", "172.26.0.1");
    FAIL_IF_NULL(p2);

    DetectEngineThreadCtx *det_ctx = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
        "alert tcp any any -> any any (msg:\"ratefilter by_both test\"; gid:1; sid:10;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD23();
    FAIL_IF_NULL(g_ut_threshold_fp);
    SCThresholdConfInitContext(de_ctx);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p1->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    /* First packet should be alerted, not dropped */
    FAIL_IF(PACKET_TEST_ACTION(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    TimeSetIncrementTime(2);
    TimeGet(&p2->ts);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    /* Second packet should be dropped because it considered as "the same pair"
       and rate_filter count reached*/
    FAIL_IF_NOT(PACKET_TEST_ACTION(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    UTHFreePacket(p2);
    UTHFreePacket(p1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    IPPairShutdown();
    PASS;
}
#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for Classification Config API.
 */
void SCThresholdConfRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCThresholdConfTest01", SCThresholdConfTest01);
    UtRegisterTest("SCThresholdConfTest02", SCThresholdConfTest02);
    UtRegisterTest("SCThresholdConfTest03", SCThresholdConfTest03);
    UtRegisterTest("SCThresholdConfTest04", SCThresholdConfTest04);
    UtRegisterTest("SCThresholdConfTest05", SCThresholdConfTest05);
    UtRegisterTest("SCThresholdConfTest06", SCThresholdConfTest06);
    UtRegisterTest("SCThresholdConfTest07", SCThresholdConfTest07);
    UtRegisterTest("SCThresholdConfTest08", SCThresholdConfTest08);
    UtRegisterTest("SCThresholdConfTest09 - rate_filter",
                   SCThresholdConfTest09);
    UtRegisterTest("SCThresholdConfTest10 - rate_filter",
                   SCThresholdConfTest10);
    UtRegisterTest("SCThresholdConfTest11 - event_filter",
                   SCThresholdConfTest11);
    UtRegisterTest("SCThresholdConfTest12 - event_filter",
                   SCThresholdConfTest12);
    UtRegisterTest("SCThresholdConfTest13", SCThresholdConfTest13);
    UtRegisterTest("SCThresholdConfTest14 - suppress", SCThresholdConfTest14);
    UtRegisterTest("SCThresholdConfTest15 - suppress drop",
                   SCThresholdConfTest15);
    UtRegisterTest("SCThresholdConfTest16 - suppress drop",
                   SCThresholdConfTest16);
    UtRegisterTest("SCThresholdConfTest17 - suppress drop",
                   SCThresholdConfTest17);

    UtRegisterTest("SCThresholdConfTest18 - suppress parsing",
                   SCThresholdConfTest18);
    UtRegisterTest("SCThresholdConfTest19 - suppress parsing",
                   SCThresholdConfTest19);
    UtRegisterTest("SCThresholdConfTest20 - suppress parsing",
                   SCThresholdConfTest20);
    UtRegisterTest("SCThresholdConfTest21 - suppress parsing",
                   SCThresholdConfTest21);
    UtRegisterTest("SCThresholdConfTest22 - rate_filter by_both",
                   SCThresholdConfTest22);
    UtRegisterTest("SCThresholdConfTest23 - rate_filter by_both opposite",
        SCThresholdConfTest23);

#endif /* UNITTESTS */
}

/**
 * @}
 */
