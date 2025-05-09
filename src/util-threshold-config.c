/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * Implements Threshold support
 */

#include "suricata-common.h"

#include "action-globals.h"
#include "host.h"
#include "ippair.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-threshold.h"
#include "detect-threshold.h"
#include "detect-parse.h"
#include "detect-engine-build.h"

#include "conf.h"
#include "util-threshold-config.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-time.h"
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
    "^,\\s*type\\s*(limit|both|threshold)\\s*,\\s*track\\s*(by_dst|by_src|by_both|by_rule|by_"     \
    "flow)\\s*,"                                                                                   \
    "\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*$"

/* TODO: "apply_to" */
#define DETECT_RATE_REGEX                                                                          \
    "^,\\s*track\\s*(by_dst|by_src|by_both|by_rule|by_flow)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*"      \
    "seconds\\s*(\\d+)\\s*,\\s*new_action\\s*(alert|drop|pass|log|sdrop|reject)\\s*,\\s*"          \
    "timeout\\s*(\\d+)\\s*$"

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

static DetectParseRegex *regex_base = NULL;
static DetectParseRegex *regex_threshold = NULL;
static DetectParseRegex *regex_rate = NULL;
static DetectParseRegex *regex_suppress = NULL;

static void SCThresholdConfDeInitContext(DetectEngineCtx *de_ctx, FILE *fd);

void SCThresholdConfGlobalInit(void)
{
    regex_base = DetectSetupPCRE2(DETECT_BASE_REGEX, 0);
    if (regex_base == NULL) {
        FatalError("classification base regex setup failed");
    }
    regex_threshold = DetectSetupPCRE2(DETECT_THRESHOLD_REGEX, 0);
    if (regex_threshold == NULL) {
        FatalError("classification threshold regex setup failed");
    }
    regex_rate = DetectSetupPCRE2(DETECT_RATE_REGEX, 0);
    if (regex_rate == NULL) {
        FatalError("classification rate_filter regex setup failed");
    }
    regex_suppress = DetectSetupPCRE2(DETECT_SUPPRESS_REGEX, 0);
    if (regex_suppress == NULL) {
        FatalError("classification suppress regex setup failed");
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
        if (SCConfGet(config_value, &log_filename) != 1) {
            if (SCConfGet("threshold-file", &log_filename) != 1) {
                log_filename = (char *)THRESHOLD_CONF_DEF_CONF_FILEPATH;
            }
        }
    } else {
        if (SCConfGet("threshold-file", &log_filename) != 1) {
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
    int ret = 0;
#ifndef UNITTESTS
    FILE *fd = NULL;
#else
    FILE *fd = g_ut_threshold_fp;
    if (fd == NULL) {
#endif
        filename = SCThresholdConfGetConfFilename(de_ctx);
        if ( (fd = fopen(filename, "r")) == NULL) {
            SCLogWarning("Error opening file: \"%s\": %s", filename, strerror(errno));
            SCThresholdConfDeInitContext(de_ctx, fd);
            return 0;
        }
#ifdef UNITTESTS
    }
#endif

    if (SCThresholdConfParseFile(de_ctx, fd) < 0) {
        SCLogWarning("Error loading threshold configuration from %s", filename);
        SCThresholdConfDeInitContext(de_ctx, fd);
        /* maintain legacy behavior so no errors unless config testing */
        if (SCRunmodeGet() == RUNMODE_CONF_TEST) {
            ret = -1;
        }
        return ret;
    }
    SCThresholdConfDeInitContext(de_ctx, fd);

#ifdef UNITTESTS
    g_ut_threshold_fp = NULL;
#endif
    SCLogDebug("Global thresholding options defined");
    return 0;
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
            SCLogError("failed to parse %s", th_ip);
            goto error;
        }
    }

    /* Install it */
    if (id == 0 && gid == 0) {
        if (parsed_track == TRACK_RULE) {
            SCLogWarning("suppressing all rules");
        }

        /* update each sig with our suppress info */
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            /* tag the rule as noalert */
            if (parsed_track == TRACK_RULE) {
                s->action &= ~ACTION_ALERT;
                continue;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            if (SigMatchAppendSMToList(de_ctx, s, DETECT_THRESHOLD, (SigMatchCtx *)de,
                        DETECT_SM_LIST_SUPPRESS) == NULL) {
                goto error;
            }
        }
    } else if (id == 0 && gid > 0)    {
        if (parsed_track == TRACK_RULE) {
            SCLogWarning("suppressing all rules with gid %" PRIu32, gid);
        }
        /* set up suppression for each signature with a matching gid */
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            if (s->gid != gid)
                continue;

            /* tag the rule as noalert */
            if (parsed_track == TRACK_RULE) {
                s->action &= ~ACTION_ALERT;
                continue;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            if (SigMatchAppendSMToList(de_ctx, s, DETECT_THRESHOLD, (SigMatchCtx *)de,
                        DETECT_SM_LIST_SUPPRESS) == NULL) {
                goto error;
            }
        }
    } else if (id > 0 && gid == 0) {
        SCLogError("Can't use a event config that has "
                   "sid > 0 and gid == 0. Please fix this "
                   "in your threshold.config file");
        goto error;
    } else {
        s = SigFindSignatureBySidGid(de_ctx, id, gid);
        if (s == NULL) {
            SCLogWarning("can't suppress sid "
                         "%" PRIu32 ", gid %" PRIu32 ": unknown rule",
                    id, gid);
        } else {
            if (parsed_track == TRACK_RULE) {
                s->action &= ~ACTION_ALERT;
                goto end;
            }

            de = DetectThresholdDataCopy(orig_de);
            if (unlikely(de == NULL))
                goto error;

            if (SigMatchAppendSMToList(de_ctx, s, DETECT_THRESHOLD, (SigMatchCtx *)de,
                        DETECT_SM_LIST_SUPPRESS) == NULL) {
                goto error;
            }
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
        uint8_t parsed_type, uint8_t parsed_track, uint32_t parsed_count, uint32_t parsed_seconds,
        uint32_t parsed_timeout, uint8_t parsed_new_action)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectThresholdData *de = NULL;

    BUG_ON(parsed_type == TYPE_SUPPRESS);

    /* Install it */
    if (id == 0 && gid == 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD, DETECT_THRESHOLD, -1);
            if (sm != NULL) {
                SCLogWarning("signature sid:%" PRIu32 " has "
                             "an event var set.  The signature event var is "
                             "given precedence over the threshold.conf one.  "
                             "We'll change this in the future though.",
                        s->id);
                continue;
            }

            sm = DetectGetLastSMByListId(s,
                    DETECT_SM_LIST_THRESHOLD, DETECT_DETECTION_FILTER, -1);
            if (sm != NULL) {
                SCLogWarning("signature sid:%" PRIu32 " has "
                             "an event var set.  The signature event var is "
                             "given precedence over the threshold.conf one.  "
                             "We'll change this in the future though.",
                        s->id);
                continue;
            }

            de = SCCalloc(1, sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;

            de->type = parsed_type;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            uint16_t smtype = DETECT_THRESHOLD;
            if (parsed_type == TYPE_RATE)
                smtype = DETECT_DETECTION_FILTER;

            if (SigMatchAppendSMToList(
                        de_ctx, s, smtype, (SigMatchCtx *)de, DETECT_SM_LIST_THRESHOLD) == NULL) {
                goto error;
            }
        }

    } else if (id == 0 && gid > 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            if (s->gid == gid) {
                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_THRESHOLD, DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SCLogWarning("signature sid:%" PRIu32 " has "
                                 "an event var set.  The signature event var is "
                                 "given precedence over the threshold.conf one.  "
                                 "We'll change this in the future though.",
                            id);
                    continue;
                }

                de = SCCalloc(1, sizeof(DetectThresholdData));
                if (unlikely(de == NULL))
                    goto error;

                de->type = parsed_type;
                de->track = parsed_track;
                de->count = parsed_count;
                de->seconds = parsed_seconds;
                de->new_action = parsed_new_action;
                de->timeout = parsed_timeout;

                uint16_t smtype = DETECT_THRESHOLD;
                if (parsed_type == TYPE_RATE)
                    smtype = DETECT_DETECTION_FILTER;

                if (SigMatchAppendSMToList(de_ctx, s, smtype, (SigMatchCtx *)de,
                            DETECT_SM_LIST_THRESHOLD) == NULL) {
                    goto error;
                }
            }
        }
    } else if (id > 0 && gid == 0) {
        SCLogError("Can't use a event config that has "
                   "sid > 0 and gid == 0. Please fix this "
                   "in your threshold.conf file");
    } else {
        s = SigFindSignatureBySidGid(de_ctx, id, gid);
        if (s == NULL) {
            SCLogWarning("can't suppress sid "
                         "%" PRIu32 ", gid %" PRIu32 ": unknown rule",
                    id, gid);
        } else {
            if (parsed_type != TYPE_SUPPRESS && parsed_type != TYPE_THRESHOLD &&
                parsed_type != TYPE_BOTH && parsed_type != TYPE_LIMIT)
            {
                sm = DetectGetLastSMByListId(s,
                        DETECT_SM_LIST_THRESHOLD, DETECT_THRESHOLD, -1);
                if (sm != NULL) {
                    SCLogWarning("signature sid:%" PRIu32 " has "
                                 "a threshold set. The signature event var is "
                                 "given precedence over the threshold.conf one. "
                                 "Bug #425.",
                            s->id);
                    goto end;
                }

                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SCLogWarning("signature sid:%" PRIu32 " has "
                                 "a detection_filter set. The signature event var is "
                                 "given precedence over the threshold.conf one. "
                                 "Bug #425.",
                            s->id);
                    goto end;
                }

            /* replace threshold on sig if we have a global override for it */
            } else if (parsed_type == TYPE_THRESHOLD || parsed_type == TYPE_BOTH || parsed_type == TYPE_LIMIT) {
                sm = DetectGetLastSMByListId(s, DETECT_SM_LIST_THRESHOLD,
                        DETECT_THRESHOLD, DETECT_DETECTION_FILTER, -1);
                if (sm != NULL) {
                    SigMatchRemoveSMFromList(s, sm, DETECT_SM_LIST_THRESHOLD);
                    SigMatchFree(de_ctx, sm);
                }
            }

            de = SCCalloc(1, sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;

            de->type = parsed_type;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            uint16_t smtype = DETECT_THRESHOLD;
            if (parsed_type == TYPE_RATE)
                smtype = DETECT_DETECTION_FILTER;

            if (SigMatchAppendSMToList(
                        de_ctx, s, smtype, (SigMatchCtx *)de, DETECT_SM_LIST_THRESHOLD) == NULL) {
                goto error;
            }
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

static int ParseThresholdRule(const DetectEngineCtx *de_ctx, char *rawstr, uint32_t *ret_id,
        uint32_t *ret_gid, uint8_t *ret_parsed_type, uint8_t *ret_parsed_track,
        uint32_t *ret_parsed_count, uint32_t *ret_parsed_seconds, uint32_t *ret_parsed_timeout,
        uint8_t *ret_parsed_new_action, char **ret_th_ip)
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
    uint32_t id = 0, gid = 0;
    ThresholdRuleType rule_type;

    if (de_ctx == NULL)
        return -1;

    pcre2_match_data *regex_base_match = NULL;
    ret = DetectParsePcreExec(regex_base, &regex_base_match, rawstr, 0, 0);
    if (ret < 4) {
        SCLogError("pcre2_match parse error, ret %" PRId32 ", string %s", ret, rawstr);
        pcre2_match_data_free(regex_base_match);
        goto error;
    }

    /* retrieve the classtype name */
    size_t copylen = sizeof(th_rule_type);
    ret = pcre2_substring_copy_bynumber(
            regex_base_match, 1, (PCRE2_UCHAR8 *)th_rule_type, &copylen);
    if (ret < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        pcre2_match_data_free(regex_base_match);
        goto error;
    }

    /* retrieve the classtype name */
    copylen = sizeof(th_gid);
    ret = pcre2_substring_copy_bynumber(regex_base_match, 2, (PCRE2_UCHAR8 *)th_gid, &copylen);
    if (ret < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        pcre2_match_data_free(regex_base_match);
        goto error;
    }

    copylen = sizeof(th_sid);
    ret = pcre2_substring_copy_bynumber(regex_base_match, 3, (PCRE2_UCHAR8 *)th_sid, &copylen);
    if (ret < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed");
        pcre2_match_data_free(regex_base_match);
        goto error;
    }

    /* Use "get" for heap allocation */
    ret = pcre2_substring_get_bynumber(
            regex_base_match, 4, (PCRE2_UCHAR8 **)&rule_extend, &copylen);
    if (ret < 0) {
        SCLogError("pcre2_substring_get_bynumber failed");
        pcre2_match_data_free(regex_base_match);
        goto error;
    }
    pcre2_match_data_free(regex_base_match);
    regex_base_match = NULL;

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
        SCLogError("rule type %s is unknown", th_rule_type);
        goto error;
    }

    /* get end of rule */
    switch(rule_type) {
        case THRESHOLD_TYPE_EVENT_FILTER:
        case THRESHOLD_TYPE_THRESHOLD:
            if (strlen(rule_extend) > 0) {
                pcre2_match_data *match = NULL;

                ret = DetectParsePcreExec(regex_threshold, &match, rule_extend, 0, 0);
                if (ret < 4) {
                    SCLogError("pcre2_match parse error, ret %" PRId32 ", string %s", ret,
                            rule_extend);
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_type);
                ret = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)th_type, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_track);
                ret = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)th_track, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_count);
                ret = pcre2_substring_copy_bynumber(match, 3, (PCRE2_UCHAR8 *)th_count, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_seconds);
                ret = pcre2_substring_copy_bynumber(match, 4, (PCRE2_UCHAR8 *)th_seconds, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }
                pcre2_match_data_free(match);

                if (strcasecmp(th_type,"limit") == 0)
                    parsed_type = TYPE_LIMIT;
                else if (strcasecmp(th_type,"both") == 0)
                    parsed_type = TYPE_BOTH;
                else if (strcasecmp(th_type,"threshold") == 0)
                    parsed_type = TYPE_THRESHOLD;
                else {
                    SCLogError("limit type not supported: %s", th_type);
                    goto error;
                }
            } else {
                SCLogError("rule invalid: %s", rawstr);
                goto error;
            }
            break;
        case THRESHOLD_TYPE_SUPPRESS:
            if (strlen(rule_extend) > 0) {
                pcre2_match_data *match = NULL;
                ret = DetectParsePcreExec(regex_suppress, &match, rule_extend, 0, 0);
                if (ret < 2) {
                    SCLogError("pcre2_match parse error, ret %" PRId32 ", string %s", ret,
                            rule_extend);
                    pcre2_match_data_free(match);
                    goto error;
                }
                /* retrieve the track mode */
                copylen = sizeof(th_seconds);
                ret = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)th_track, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }
                /* retrieve the IP; use "get" for heap allocation */
                ret = pcre2_substring_get_bynumber(match, 2, (PCRE2_UCHAR8 **)&th_ip, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_get_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }
                pcre2_match_data_free(match);
            } else {
                parsed_track = TRACK_RULE;
            }
            parsed_type = TYPE_SUPPRESS;
            break;
        case THRESHOLD_TYPE_RATE:
            if (strlen(rule_extend) > 0) {
                pcre2_match_data *match = NULL;
                ret = DetectParsePcreExec(regex_rate, &match, rule_extend, 0, 0);
                if (ret < 5) {
                    SCLogError("pcre2_match parse error, ret %" PRId32 ", string %s", ret,
                            rule_extend);
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_track);
                ret = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)th_track, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_count);
                ret = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)th_count, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_seconds);
                ret = pcre2_substring_copy_bynumber(match, 3, (PCRE2_UCHAR8 *)th_seconds, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_new_action);
                ret = pcre2_substring_copy_bynumber(
                        match, 4, (PCRE2_UCHAR8 *)th_new_action, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }

                copylen = sizeof(th_timeout);
                ret = pcre2_substring_copy_bynumber(match, 5, (PCRE2_UCHAR8 *)th_timeout, &copylen);
                if (ret < 0) {
                    SCLogError("pcre2_substring_copy_bynumber failed");
                    pcre2_match_data_free(match);
                    goto error;
                }
                pcre2_match_data_free(match);

                /* TODO: implement option "apply_to" */

                if (StringParseUint32(&parsed_timeout, 10, sizeof(th_timeout), th_timeout) <= 0) {
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
                SCLogError("rule invalid: %s", rawstr);
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
            else if (strcasecmp(th_track, "by_flow") == 0)
                parsed_track = TRACK_FLOW;
            else {
                SCLogError("Invalid track parameter %s in %s", th_track, rawstr);
                goto error;
            }

            if (StringParseUint32(&parsed_count, 10, sizeof(th_count), th_count) <= 0) {
                goto error;
            }
            if (parsed_count == 0) {
                SCLogError("rate filter count should be > 0");
                goto error;
            }

            if (StringParseUint32(&parsed_seconds, 10, sizeof(th_seconds), th_seconds) <= 0) {
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
                    SCLogError("Invalid track parameter %s in %s", th_track, rule_extend);
                    goto error;
                }
            }
            break;
    }

    if (StringParseUint32(&id, 10, sizeof(th_sid), th_sid) <= 0) {
        goto error;
    }

    if (StringParseUint32(&gid, 10, sizeof(th_gid), th_gid) <= 0) {
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
    }
    pcre2_substring_free((PCRE2_UCHAR8 *)rule_extend);
    return 0;

error:
    if (rule_extend != NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)rule_extend);
    }
    if (th_ip != NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)th_ip);
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

    int r = ParseThresholdRule(de_ctx, rawstr, &id, &gid, &parsed_type, &parsed_track,
            &parsed_count, &parsed_seconds, &parsed_timeout, &parsed_new_action, &th_ip);
    if (r < 0)
        goto error;

    if (parsed_type == TYPE_SUPPRESS) {
        r = SetupSuppressRule(de_ctx, id, gid, parsed_type, parsed_track,
                    parsed_count, parsed_seconds, parsed_timeout, parsed_new_action,
                    th_ip);
    } else {
        r = SetupThresholdRule(de_ctx, id, gid, parsed_type, parsed_track, parsed_count,
                parsed_seconds, parsed_timeout, parsed_new_action);
    }
    if (r < 0) {
        goto error;
    }

    pcre2_substring_free((PCRE2_UCHAR8 *)th_ip);
    return 0;
error:
    if (th_ip != NULL)
        pcre2_substring_free((PCRE2_UCHAR8 *)th_ip);
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
    size_t len = strlen(line);

    while (line < rline + len && *line != '\n') {
        /* we have a comment */
        if (*line == '\\')
            flag = (int)(line - rline);
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
int SCThresholdConfParseFile(DetectEngineCtx *de_ctx, FILE *fp)
{
    char line[8192] = "";
    int rule_num = 0;

    /* position of "\", on multiline rules */
    int esc_pos = 0;

    if (fp == NULL)
        return -1;

    while (fgets(line + esc_pos, (int)sizeof(line) - esc_pos, fp) != NULL) {
        if (SCThresholdConfIsLineBlankOrComment(line)) {
            continue;
        }

        esc_pos = SCThresholdConfLineIsMultiline(line);
        if (esc_pos == 0) {
            if (SCThresholdConfAddThresholdtype(line, de_ctx) < 0) {
                if (SCRunmodeGet() == RUNMODE_CONF_TEST)
                    return -1;
            } else {
                SCLogDebug("Adding threshold.config rule num %" PRIu32 "( %s )", rule_num, line);
                rule_num++;
            }
        }
    }

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0)
        SCLogInfo("tenant id %d: Threshold config parsed: %d rule(s) found", de_ctx->tenant_id,
                rule_num);
    else
        SCLogInfo("Threshold config parsed: %d rule(s) found", rule_num);
    return 0;
}

#ifdef UNITTESTS
#include "detect-engine-alert.h"
#include "packet.h"
#include "action-globals.h"

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
static FILE *SCThresholdConfGenerateInvalidDummyFD02(void)
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
 *        with split rules (multiline), for testing purposes.
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
 *        with split rules (multiline), for testing purposes.
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
 *        with split rules (multiline), for testing purposes.
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
 *        with split rules (multiline), for testing purposes.
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
 *        with split rules (multiline), for testing purposes.
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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    g_ut_threshold_fp = SCThresholdConfGenerateInvalidDummyFD02();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigMatch *m = DetectGetLastSMByListId(sig, DETECT_SM_LIST_THRESHOLD,
            DETECT_THRESHOLD, -1);
    FAIL_IF_NOT_NULL(m);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest09(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PacketTestAction(p, ACTION_DROP));
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PacketTestAction(p, ACTION_DROP));
    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PacketTestAction(p, ACTION_DROP));

    TimeSetIncrementTime(2);
    p->ts = TimeGet();

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || !(PacketTestAction(p, ACTION_DROP)));

    TimeSetIncrementTime(3);
    p->ts = TimeGet();

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || !(PacketTestAction(p, ACTION_DROP)));

    TimeSetIncrementTime(10);
    p->ts = TimeGet();

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PacketTestAction(p, ACTION_DROP));

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(p->alerts.cnt != 1 || PacketTestAction(p, ACTION_DROP));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the rate_filter rules work with track by_rule
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest10(void)
{
    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);
    p1->ts = TimeGet();
    p2->ts = p1->ts;

    /* All should be alerted, none dropped */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);
    p2->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;

    /* Match #4 should be dropped*/
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF_NOT(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);
    p2->action = 0;

    TimeSetIncrementTime(2);
    p1->ts = TimeGet();

    /* Still dropped because timeout not expired */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
    p1->action = 0;

    TimeSetIncrementTime(10);
    p1->ts = TimeGet();

    /* Not dropped because timeout expired */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);
#if 0
    /* Ensure that a Threshold entry was installed at the sig */
    FAIL_IF_NULL(de_ctx->ths_ctx.th_entry[s->iid]);
#endif
    UTHFreePacket(p1);
    UTHFreePacket(p2);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest11(void)
{
    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();

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
    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);

    TimeSetIncrementTime(10);
    p->ts = TimeGet();

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
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest12(void)
{
    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p->ts = TimeGet();

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
    p->ts = TimeGet();

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts10 += PacketAlertCheck(p, 10);
    alerts11 += PacketAlertCheck(p, 11);

    TimeSetIncrementTime(10);
    p->ts = TimeGet();

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
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on success
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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest14(void)
{
    ThresholdInit();

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

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

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

    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest15(void)
{
    ThresholdInit();

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any any (msg:\"suppress test\"; content:\"lalala\"; gid:1; sid:10000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    FAIL_IF(PacketAlertCheck(p, 10000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PacketTestAction(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest16(void)
{
    ThresholdInit();

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.1.1",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any any (msg:\"suppress test\"; gid:1; sid:1000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(PacketAlertCheck(p, 1000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PacketTestAction(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the suppress rules work - ip only rule
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest17(void)
{
    ThresholdInit();

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    FAIL_IF_NULL(p);

    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *sig = DetectEngineAppendSig(de_ctx,
            "drop tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:10000;)");
    FAIL_IF_NULL(sig);

    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD11();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    FAIL_IF(PacketAlertCheck(p, 10000) != 0);
    /* however, it should have set the drop flag */
    FAIL_IF(!(PacketTestAction(p, ACTION_DROP)));

    UTHFreePacket(p);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest18(void)
{
    ThresholdInit();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateInvalidDummyFD12();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));
    SigGroupBuild(de_ctx);

    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_DST);

    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest19(void)
{
    ThresholdInit();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateInvalidDummyFD13();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));
    SigGroupBuild(de_ctx);
    FAIL_IF_NULL(s->sm_arrays[DETECT_SM_LIST_SUPPRESS]);
    SigMatchData *smd = s->sm_arrays[DETECT_SM_LIST_SUPPRESS];
    DetectThresholdData *de = (DetectThresholdData *)smd->ctx;
    FAIL_IF_NULL(de);
    FAIL_IF_NOT(de->type == TYPE_SUPPRESS && de->track == TRACK_DST);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest20(void)
{
    ThresholdInit();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; sid:1000;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT_NULL(g_ut_threshold_fp);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD20();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));
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
    ThresholdDestroy();
    PASS;
}

/**
 * \test Check if the threshold file is loaded and well parsed, and applied
 *       correctly to a rule with thresholding
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest21(void)
{
    ThresholdInit();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    FAIL_IF_NULL(s);
    g_ut_threshold_fp = SCThresholdConfGenerateValidDummyFD20();
    FAIL_IF_NULL(g_ut_threshold_fp);
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));
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
    ThresholdDestroy();
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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest22(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p1->ts = TimeGet();
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, none dropped */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PacketTestAction(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    p1->action = p2->action = p3->action = 0;

    TimeSetIncrementTime(2);
    p1->ts = TimeGet();
    p2->ts = p3->ts = p1->ts;

    /* p1 still shouldn't be dropped after 2nd alert */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    p1->action = 0;

    TimeSetIncrementTime(2);
    p1->ts = TimeGet();
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, only p1 must be dropped  due to rate_filter*/
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF_NOT(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PacketTestAction(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    p1->action = p2->action = p3->action = 0;

    TimeSetIncrementTime(7);
    p1->ts = TimeGet();
    p2->ts = p3->ts = p1->ts;

    /* All should be alerted, none dropped (because timeout expired) */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    FAIL_IF(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p3);
    FAIL_IF(PacketTestAction(p3, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p3, 10) != 1);

    UTHFreePacket(p3);
    UTHFreePacket(p2);
    UTHFreePacket(p1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
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
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int SCThresholdConfTest23(void)
{
    ThreadVars th_v;
    memset(&th_v, 0, sizeof(th_v));

    ThresholdInit();

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
    FAIL_IF(-1 == SCThresholdConfInitContext(de_ctx));

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    p1->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    /* First packet should be alerted, not dropped */
    FAIL_IF(PacketTestAction(p1, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p1, 10) != 1);

    TimeSetIncrementTime(2);
    p2->ts = TimeGet();
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);

    /* Second packet should be dropped because it considered as "the same pair"
       and rate_filter count reached*/
    FAIL_IF_NOT(PacketTestAction(p2, ACTION_DROP));
    FAIL_IF(PacketAlertCheck(p2, 10) != 1);

    UTHFreePacket(p2);
    UTHFreePacket(p1);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    ThresholdDestroy();
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
