/* Copyright (C) 2007-2010 Open Information Security Foundation
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

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
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

/* File descriptor for unittests */

/* common base for all options */
#define DETECT_BASE_REGEX "^\\s*(event_filter|threshold|rate_filter|suppress)\\s*gen_id\\s*(\\d+)\\s*,\\s*sig_id\\s*(\\d+)\\s*(.*)\\s*$"

#define DETECT_THRESHOLD_REGEX "^,\\s*type\\s*(limit|both|threshold)\\s*,\\s*track\\s*(by_dst|by_src)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*$"

/* TODO: "apply_to" */
#define DETECT_RATE_REGEX "^,\\s*track\\s*(by_dst|by_src|by_rule)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*,\\s*new_action\\s*(alert|drop|pass|log|sdrop|reject)\\s*,\\s*timeout\\s*(\\d+)\\s*$"

/*
 * suppress has two form:
 *  suppress gen_id 0, sig_id 0, track by_dst, ip 10.88.0.14
 *  suppress gen_id 1, sig_id 2000328
 *  suppress gen_id 1, sig_id 2000328, track by_src, ip fe80::/10
*/
#define DETECT_SUPPRESS_REGEX "^,\\s*track\\s*(by_dst|by_src|by_either)\\s*,\\s*ip\\s*([\\[\\],\\$\\da-zA-Z.:/_]+)*\\s*$"

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

/**
 * \brief Returns the path for the Threshold Config file.  We check if we
 *        can retrieve the path from the yaml conf file.  If it is not present,
 *        return the default path for the threshold file which is
 *        "./threshold.config".
 *
 * \retval log_filename Pointer to a string containing the path for the
 *                      Threshold Config file.
 */
static char *SCThresholdConfGetConfFilename(const DetectEngineCtx *de_ctx)
{
    char *log_filename = NULL;
    char config_value[256] = "";

    if (de_ctx != NULL && strlen(de_ctx->config_prefix) > 0) {
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
 * \param utfd Pointer for unit test file descriptor.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCThresholdConfInitContext(DetectEngineCtx *de_ctx, FILE *utfd)
{
    char *filename = NULL;
    const char *eb = NULL;
    FILE *fd = utfd;
    int eo;
    int opts = 0;

    if (fd == NULL) {
        filename = SCThresholdConfGetConfFilename(de_ctx);
        if ( (fd = fopen(filename, "r")) == NULL) {
            SCLogWarning(SC_ERR_FOPEN, "Error opening file: \"%s\": %s", filename, strerror(errno));
            goto error;
        }
    }

    regex_base = pcre_compile(DETECT_BASE_REGEX, opts, &eb, &eo, NULL);
    if (regex_base == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_BASE_REGEX, eo, eb);
        goto error;
    }

    regex_base_study = pcre_study(regex_base, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    regex_threshold = pcre_compile(DETECT_THRESHOLD_REGEX, opts, &eb, &eo, NULL);
    if (regex_threshold == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_THRESHOLD_REGEX, eo, eb);
        goto error;
    }

    regex_threshold_study = pcre_study(regex_threshold, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    regex_rate = pcre_compile(DETECT_RATE_REGEX, opts, &eb, &eo, NULL);
    if (regex_rate == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_RATE_REGEX, eo, eb);
        goto error;
    }

    regex_rate_study = pcre_study(regex_rate, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    regex_suppress = pcre_compile(DETECT_SUPPRESS_REGEX, opts, &eb, &eo, NULL);
    if (regex_suppress == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_SUPPRESS_REGEX, eo, eb);
        goto error;
    }

    regex_suppress_study = pcre_study(regex_suppress, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    SCThresholdConfParseFile(de_ctx, fd);
    SCThresholdConfDeInitContext(de_ctx, fd);

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
void SCThresholdConfDeInitContext(DetectEngineCtx *de_ctx, FILE *fd)
{
    if (fd != NULL)
        fclose(fd);

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

            de = SCMalloc(sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;
            memset(de,0,sizeof(DetectThresholdData));

            de->type = TYPE_SUPPRESS;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            if (parsed_track != TRACK_RULE) {
                if (DetectAddressParse((const DetectEngineCtx *)de_ctx, &de->addrs, (char *)th_ip) != 0) {
                    SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "failed to parse %s", th_ip);
                    goto error;
                }
            }

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

            de = SCMalloc(sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;

            memset(de,0,sizeof(DetectThresholdData));

            de->type = TYPE_SUPPRESS;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            if (parsed_track != TRACK_RULE) {
                if (DetectAddressParse((const DetectEngineCtx *)de_ctx, &de->addrs, (char *)th_ip) != 0) {
                    SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "failed to parse %s", th_ip);
                    goto error;
                }
            }

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
                   "in your threshold.conf file");
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

            de = SCMalloc(sizeof(DetectThresholdData));
            if (unlikely(de == NULL))
                goto error;
            memset(de,0,sizeof(DetectThresholdData));

            de->type = TYPE_SUPPRESS;
            de->track = parsed_track;
            de->count = parsed_count;
            de->seconds = parsed_seconds;
            de->new_action = parsed_new_action;
            de->timeout = parsed_timeout;

            if (DetectAddressParse((const DetectEngineCtx *)de_ctx, &de->addrs, (char *)th_ip) != 0) {
                SCLogError(SC_ERR_INVALID_IP_NETBLOCK, "failed to parse %s", th_ip);
                goto error;
            }

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
    return 0;
error:
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
    void *ptmp;

    BUG_ON(parsed_type == TYPE_SUPPRESS);

    /* Install it */
    if (id == 0 && gid == 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            sm = SigMatchGetLastSMFromLists(s, 2,
                    DETECT_THRESHOLD, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
            if (sm != NULL) {
                SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                        "an event var set.  The signature event var is "
                        "given precedence over the threshold.conf one.  "
                        "We'll change this in the future though.", s->id);
                continue;
            }

            sm = SigMatchGetLastSMFromLists(s, 2,
                    DETECT_DETECTION_FILTER, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
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

            if (parsed_track == TRACK_RULE) {
                ptmp = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                if (ptmp == NULL) {
                    SCFree(de_ctx->ths_ctx.th_entry);
                    de_ctx->ths_ctx.th_entry = NULL;
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                    " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                } else {
                    de_ctx->ths_ctx.th_entry = ptmp;
                    de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                    de_ctx->ths_ctx.th_size++;
                }
            }
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_THRESHOLD);
        }

    } else if (id == 0 && gid > 0) {
        for (s = de_ctx->sig_list; s != NULL; s = s->next) {
            if (s->gid == gid) {
                sm = SigMatchGetLastSMFromLists(s, 2,
                        DETECT_THRESHOLD, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "an event var set.  The signature event var is "
                            "given precedence over the threshold.conf one.  "
                            "We'll change this in the future though.", id);
                    continue;
                }

                sm = SigMatchGetLastSMFromLists(s, 2,
                        DETECT_DETECTION_FILTER, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
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

                if (parsed_track == TRACK_RULE) {
                    ptmp = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                    if (ptmp == NULL) {
                        SCFree(de_ctx->ths_ctx.th_entry);
                        de_ctx->ths_ctx.th_entry = NULL;
                        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                        " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                    } else {
                        de_ctx->ths_ctx.th_entry = ptmp;
                        de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                        de_ctx->ths_ctx.th_size++;
                    }
                }
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
                sm = SigMatchGetLastSMFromLists(s, 2,
                        DETECT_THRESHOLD, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "a threshold set. The signature event var is "
                            "given precedence over the threshold.conf one. "
                            "Bug #425.", s->id);
                    goto end;
                }

                sm = SigMatchGetLastSMFromLists(s, 2,
                        DETECT_DETECTION_FILTER, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
                if (sm != NULL) {
                    SCLogWarning(SC_ERR_EVENT_ENGINE, "signature sid:%"PRIu32 " has "
                            "a detection_filter set. The signature event var is "
                            "given precedence over the threshold.conf one. "
                            "Bug #425.", s->id);
                    goto end;
                }

            /* replace threshold on sig if we have a global override for it */
#if 1
            } else if (parsed_type == TYPE_THRESHOLD || parsed_type == TYPE_BOTH || parsed_type == TYPE_LIMIT) {
                sm = SigMatchGetLastSMFromLists(s, 2,
                        DETECT_THRESHOLD, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
                if (sm == NULL) {
                    sm = SigMatchGetLastSMFromLists(s, 2,
                            DETECT_DETECTION_FILTER, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);
                }
                if (sm != NULL) {
                    SigMatchRemoveSMFromList(s, sm, DETECT_SM_LIST_THRESHOLD);
                    SigMatchFree(sm);
                    sm = NULL;
                }
#endif
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

            if (parsed_track == TRACK_RULE) {
                 ptmp = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                if (ptmp == NULL) {
                    SCFree(de_ctx->ths_ctx.th_entry);
                    de_ctx->ths_ctx.th_entry = NULL;
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                    " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                } else {
                    de_ctx->ths_ctx.th_entry = ptmp;
                    de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                    de_ctx->ths_ctx.th_size++;
                }
            }

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
    const char **ret_th_ip)
{
    char th_rule_type[32];
    char th_gid[16];
    char th_sid[16];
    char rule_extend[1024];
    const char *th_type = NULL;
    const char *th_track = NULL;
    const char *th_count = NULL;
    const char *th_seconds = NULL;
    const char *th_new_action= NULL;
    const char *th_timeout = NULL;
    const char *th_ip = NULL;

    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint8_t parsed_new_action = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;
    uint32_t parsed_timeout = 0;

#define MAX_SUBSTRINGS 30
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
    ret = pcre_copy_substring((char *)rawstr, ov, 30, 1, th_rule_type, sizeof(th_rule_type));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    /* retrieve the classtype name */
    ret = pcre_copy_substring((char *)rawstr, ov, 30, 2, th_gid, sizeof(th_gid));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    ret = pcre_copy_substring((char *)rawstr, ov, 30, 3, th_sid, sizeof(th_sid));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    ret = pcre_copy_substring((char *)rawstr, ov, 30, 4, rule_extend, sizeof(rule_extend));
    if (ret < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
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

                ret = pcre_get_substring((char *)rule_extend, ov, 30, 1, &th_type);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, 30, 2, &th_track);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, 30, 3, &th_count);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, 30, 4, &th_seconds);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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
                ret = pcre_get_substring((char *)rule_extend, ov, 30, 1, &th_track);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }
                /* retrieve the IP */
                ret = pcre_get_substring((char *)rule_extend, ov, 30, 2, &th_ip);
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

                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 1, &th_track);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 2, &th_count);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 3, &th_seconds);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 4, &th_new_action);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                ret = pcre_get_substring((char *)rule_extend, ov, MAX_SUBSTRINGS, 5, &th_timeout);
                if (ret < 0) {
                    SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                    goto error;
                }

                /* TODO: implement option "apply_to" */

                if (ByteExtractStringUint32(&parsed_timeout, 10, strlen(th_timeout), th_timeout) <= 0) {
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
        default:
            SCLogError(SC_ERR_PCRE_MATCH, "unable to find rule type for string %s", rawstr);
            goto error;
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
            else if (strcasecmp(th_track,"by_rule") == 0)
                parsed_track = TRACK_RULE;
            else {
                SCLogError(SC_ERR_INVALID_VALUE, "Invalid track parameter %s in %s", th_track, rawstr);
                goto error;
            }

            if (ByteExtractStringUint32(&parsed_count, 10, strlen(th_count), th_count) <= 0) {
                goto error;
            }
            if (parsed_count == 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "rate filter count should be > 0");
                goto error;
            }

            if (ByteExtractStringUint32(&parsed_seconds, 10, strlen(th_seconds), th_seconds) <= 0) {
                goto error;
            }

           break;
        case THRESHOLD_TYPE_SUPPRESS:
            /* need to get IP if extension is provided */
            if (th_track != NULL) {
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

    if (ByteExtractStringUint32(&id, 10, strlen(th_sid), th_sid) <= 0) {
        goto error;
    }

    if (ByteExtractStringUint32(&gid, 10, strlen(th_gid), th_gid) <= 0) {
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
    *ret_th_ip = th_ip;
    return 0;
error:
    if (th_track != NULL)
        SCFree((char *)th_track);
    if (th_count != NULL)
        SCFree((char *)th_count);
    if (th_seconds != NULL)
        SCFree((char *)th_seconds);
    if (th_type != NULL)
        SCFree((char *)th_type);
    if (th_ip != NULL)
        SCFree((char *)th_ip);
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
int SCThresholdConfAddThresholdtype(char *rawstr, DetectEngineCtx *de_ctx)
{
    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint8_t parsed_new_action = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;
    uint32_t parsed_timeout = 0;
    const char *th_ip = NULL;
    uint32_t id, gid;

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

    return 0;
error:
    if (th_ip != NULL)
        SCFree((char *)th_ip);
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
int SCThresholdConfIsLineBlankOrComment(char *line)
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
int SCThresholdConfLineIsMultiline(char *line)
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
 * \brief Get the config line length to allocate the buffer needed
 *
 * \param fd Pointer to file descriptor.
 * \retval int of the line length
 */
int SCThresholdConfLineLength(FILE *fd)
{
    long pos = ftell(fd);
    int len = 0;
    int c;

    while ( (c = fgetc(fd)) && (char)c != '\n' && c != EOF && !feof(fd))
        len++;

    if (pos < 0)
        pos = 0;

    if (fseek(fd, pos, SEEK_SET) < 0) {
        SCLogError(SC_ERR_THRESHOLD_SETUP, "threshold fseek failure: %s",
                strerror(errno));
        return -1;
    }
    return len;
}

/**
 * \brief Parses the Threshold Config file
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param fd Pointer to file descriptor.
 */
void SCThresholdConfParseFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    char *line = NULL;
    int len = 0;
    int rule_num = 0;

    /* position of "\", on multiline rules */
    int esc_pos = 0;

    if (fd == NULL)
        return;

    while (!feof(fd)) {
        len = SCThresholdConfLineLength(fd);

        if (len > 0) {
            if (line == NULL) {
                line = SCMalloc(len + 1);
                if (unlikely(line == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    return;
                }
            } else {
                char *newline = SCRealloc(line, strlen(line) + len + 1);
                if (unlikely(newline == NULL)) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                    SCFree(line);
                    return;
                }
                line = newline;
            }

            if (fgets(line + esc_pos, len + 1, fd) == NULL)
                break;

            /* Skip EOL to inspect the next line (or read EOF) */
            (void)fgetc(fd);

            if (SCThresholdConfIsLineBlankOrComment(line)) {
                continue;
            }

            esc_pos = SCThresholdConfLineIsMultiline(line);
            if (esc_pos == 0) {
                rule_num++;
                SCLogDebug("Adding threshold.config rule num %"PRIu32"( %s )", rule_num, line);
                SCThresholdConfAddThresholdtype(line, de_ctx);
            }
        } else {
            /* Skip EOL to inspect the next line (or read EOF) */
            (void)fgetc(fd);
            if (feof(fd))
                break;
        }
    }

    SCLogInfo("Threshold config parsed: %d rule(s) found", rule_num);

    /* Free the last line */
    SCFree(line);

    return;
}

#ifdef UNITTESTS

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
FILE *SCThresholdConfGenerateValidDummyFD01()
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
FILE *SCThresholdConfGenerateInValidDummyFD02()
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
FILE *SCThresholdConfGenerateValidDummyFD03()
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
FILE *SCThresholdConfGenerateValidDummyFD04()
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
FILE *SCThresholdConfGenerateValidDummyFD05()
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_src, count 1, seconds 60, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, sig_id 100, track by_dst, count 10, seconds 60, new_action pass, timeout 5\n"
        "rate_filter gen_id 1, sig_id 1000, track by_rule, count 100, seconds 60, new_action alert, timeout 30\n";

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
FILE *SCThresholdConfGenerateValidDummyFD06()
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter \\\ngen_id 1, sig_id 10, track by_src, count 1, seconds 60\\\n, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, \\\nsig_id 100, track by_dst, \\\ncount 10, seconds 60, new_action pass, timeout 5\n"
        "rate_filter gen_id 1, sig_id 1000, \\\ntrack by_rule, count 100, seconds 60, new_action alert, timeout 30\n";

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
FILE *SCThresholdConfGenerateValidDummyFD07()
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
 * \brief Creates a dummy threshold file, with all valid options, but
 *        with splitted rules (multiline), for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
FILE *SCThresholdConfGenerateValidDummyFD08()
{
    FILE *fd = NULL;
    const char *buffer =
        "rate_filter gen_id 1, sig_id 10, track by_rule, count 3, seconds 3, new_action drop, timeout 10\n"
        "rate_filter gen_id 1, sig_id 11, track by_src, count 3, seconds 1, new_action drop, timeout 5\n";

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
FILE *SCThresholdConfGenerateValidDummyFD09()
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
FILE *SCThresholdConfGenerateValidDummyFD10()
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
FILE *SCThresholdConfGenerateValidDummyFD11()
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
int SCThresholdConfTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD01();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_LIMIT && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60))
            result = 1;
    }

end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:100;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD01();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_BOTH && de->track == TRACK_DST && de->count == 10 && de->seconds == 60))
            result = 1;
    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest03(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD01();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60))
            result = 1;
    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest04(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateInValidDummyFD02();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de == NULL)
            return result;
        else
            result = 1;
    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest05(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    Signature *s = NULL, *ns = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1;)");
    if (sig == NULL) {
        goto end;
    }

    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any 80 (msg:\"Threshold limit\"; gid:1; sid:100;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD03();
    SCThresholdConfInitContext(de_ctx,fd);

    for (s = de_ctx->sig_list; s != NULL;) {

        ns = s->next;

        if(s->id == 1 || s->id == 10 || s->id == 100) {

            m = SigMatchGetLastSMFromLists(s, 2,
                                           DETECT_THRESHOLD, s->sm_lists[DETECT_SM_LIST_THRESHOLD]);

            if(m == NULL)   {
                goto end;
            } else {
                de = (DetectThresholdData *)m->ctx;
                if(de != NULL && (de->type == TYPE_THRESHOLD && de->track == TRACK_SRC && de->count == 100 && de->seconds == 60))
                    result++;
            }
        }

        s = ns;
    }

    if(result == 3)
        result = 1;

end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest06(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD04();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_LIMIT && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60))
            result = 1;
    }

end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the rate_filter rules are loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest07(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD05();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_DETECTION_FILTER, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_RATE && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60))
            result = 1;
    }

end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the rate_filter rules are loaded and well parsed
 *       with multilines
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest08(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD06();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_DETECTION_FILTER, sig->sm_lists[DETECT_SM_LIST_THRESHOLD]);

    if(m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_RATE && de->track == TRACK_SRC && de->count == 1 && de->seconds == 60))
            result = 1;
    }

end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest09(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"ratefilter test\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD07();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        result = 0;
        goto end;
    }

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        result = 0;
        goto end;
    }

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(2);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || !(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(3);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || !(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        result = 0;
        goto end;
    }

    p->alerts.cnt = 0;
    p->action = 0;
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (p->alerts.cnt != 1 || PACKET_TEST_ACTION(p, ACTION_DROP)) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the rate_filter rules work with track by_rule
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest10(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    Packet *p2 = UTHBuildPacketSrcDst((uint8_t*)"lalala", 6, IPPROTO_TCP, "172.26.0.1", "172.26.0.10");

    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int alerts = 0;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL || p2 == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"ratefilter test\"; gid:1; sid:10;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD08();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts += PacketAlertCheck(p2, 10);
    if (alerts > 0) {
        result = 0;
        goto end;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    if (alerts != 1) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(2);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p2);
    alerts += PacketAlertCheck(p2, 10);
    if (alerts != 2) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);

    if (alerts == 2)
        result = 1;

    /* Ensure that a Threshold entry was installed at the sig */
    if (de_ctx->ths_ctx.th_entry[sig->num] == NULL) {
        result = 0;
        goto end;
    }

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest11(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int alerts10 = 0;
    int alerts11 = 0;
    int alerts12 = 0;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test limit\"; gid:1; sid:10;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test threshold\"; gid:1; sid:11;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test both\"; gid:1; sid:12;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD09();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

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

    if (alerts10 == 4)
        result = 1;

    /* One on the first interval, another on the second */
    if (alerts11 == 2)
        result = 1;

    if (alerts12 == 2)
        result = 1;

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the rate_filter rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest12(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int alerts10 = 0;
    int alerts11 = 0;
    int alerts12 = 0;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test limit\"; gid:1; sid:10;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test threshold\"; gid:1; sid:11;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"event_filter test both\"; gid:1; sid:12;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD10();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

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

    /* Yes, none of the alerts will be out of the count of the given interval for type limit */
    if (alerts10 == 10)
        result = 1;

    /* One on the first interval, another on the second */
    if (alerts11 == 1)
        result = 1;

    if (alerts12 == 1)
        result = 1;

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the threshold file is loaded and well parsed
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest13(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; gid:1; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD11();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_SUPPRESS]);

    if (m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if(de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC))
            result = 1;

    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    return result;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
int SCThresholdConfTest14(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    Packet *p1 = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.1.1",
                                    "192.168.0.100", 1234, 24);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"suppress test\"; gid:1; sid:10000;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"suppress test 2\"; gid:1; sid:10;)");
    sig = sig->next = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"suppress test 3\"; gid:1; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD11();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p1);
    if ((PacketAlertCheck(p, 10000) == 0) && (PacketAlertCheck(p, 10) == 1) &&
        (PacketAlertCheck(p, 1000) == 1) && (PacketAlertCheck(p1, 1000) == 0))
        result = 1;

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest15(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any any (msg:\"suppress test\"; content:\"lalala\"; gid:1; sid:10000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD11();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    if (PacketAlertCheck(p, 10000) != 0) {
        printf("sid 10000 should not have alerted: ");
        goto end;
    }
    /* however, it should have set the drop flag */
    if (!(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        printf("sid 10000 should have set DROP flag even if suppressed: ");
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the suppress rules work
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest16(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.1.1",
                                    "192.168.0.100", 1234, 24);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"drop tcp any any -> any any (msg:\"suppress test\"; gid:1; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD11();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    if (PacketAlertCheck(p, 1000) != 0) {
        printf("sid 1000 should not have alerted: ");
        goto end;
    }
    /* however, it should have set the drop flag */
    if (!(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        printf("sid 1000 should have set DROP flag even if suppressed: ");
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \test Check if the suppress rules work - ip only rule
 *
 *  \retval 1 on succces
 *  \retval 0 on failure
 */
static int SCThresholdConfTest17(void)
{
    Signature *sig = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    Packet *p = UTHBuildPacketReal((uint8_t*)"lalala", 6, IPPROTO_TCP, "192.168.0.10",
                                    "192.168.0.100", 1234, 24);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    memset(&th_v, 0, sizeof(th_v));

    struct timeval ts;

    memset (&ts, 0, sizeof(struct timeval));
    TimeGet(&ts);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL || p == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"drop tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:10000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD11();
    SCThresholdConfInitContext(de_ctx,fd);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* 10000 shouldn't match */
    if (PacketAlertCheck(p, 10000) != 0) {
        printf("sid 10000 should not have alerted: ");
        goto end;
    }
    /* however, it should have set the drop flag */
    if (!(PACKET_TEST_ACTION(p, ACTION_DROP))) {
        printf("sid 10000 should have set DROP flag even if suppressed: ");
        goto end;
    }

    result = 1;
end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    HostShutdown();
    return result;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateInvalidDummyFD12()
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
    Signature *s = NULL;
    int result = 0;
    FILE *fd = NULL;
    SigMatch *sm = NULL;
    DetectThresholdData *de = NULL;

    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return result;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    if (s == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateInvalidDummyFD12();
    SCThresholdConfInitContext(de_ctx,fd);
    SigGroupBuild(de_ctx);

    if (s->sm_lists[DETECT_SM_LIST_SUPPRESS] == NULL) {
        printf("no thresholds: ");
        goto end;
    }
    sm = s->sm_lists[DETECT_SM_LIST_SUPPRESS];
    if (sm == NULL) {
        printf("no sm: ");
        goto end;
    }

    de = (DetectThresholdData *)sm->ctx;
    if (de == NULL) {
        printf("no de: ");
        goto end;
    }
    if (!(de->type == TYPE_SUPPRESS && de->track == TRACK_DST)) {
        printf("de state wrong: ");
        goto end;
    }

    result = 1;
end:
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    return result;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
static FILE *SCThresholdConfGenerateInvalidDummyFD13()
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
    Signature *s = NULL;
    int result = 0;
    FILE *fd = NULL;
    SigMatch *sm = NULL;
    DetectThresholdData *de = NULL;

    HostInitConfig(HOST_QUIET);
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        return result;
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.0.10 any -> 192.168.0.100 any (msg:\"suppress test\"; gid:1; sid:2200029;)");
    if (s == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateInvalidDummyFD13();
    SCThresholdConfInitContext(de_ctx,fd);
    SigGroupBuild(de_ctx);

    if (s->sm_lists[DETECT_SM_LIST_SUPPRESS] == NULL) {
        printf("no thresholds: ");
        goto end;
    }
    sm = s->sm_lists[DETECT_SM_LIST_SUPPRESS];
    if (sm == NULL) {
        printf("no sm: ");
        goto end;
    }

    de = (DetectThresholdData *)sm->ctx;
    if (de == NULL) {
        printf("no de: ");
        goto end;
    }
    if (!(de->type == TYPE_SUPPRESS && de->track == TRACK_DST)) {
        printf("de state wrong: ");
        goto end;
    }

    result = 1;
end:
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    return result;
}

/**
 * \brief Creates a dummy threshold file, with all valid options, for testing purposes.
 *
 * \retval fd Pointer to file descriptor.
 */
FILE *SCThresholdConfGenerateValidDummyFD20()
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD20();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_SUPPRESS]);
    if (m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
            m = m->next;
            if (m != NULL)   {
                de = (DetectThresholdData *)m->ctx;
                if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
                    m = m->next;
                    if (m != NULL)   {
                        de = (DetectThresholdData *)m->ctx;
                        if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
                            result = 1;
                        }
                    }
                }
            }
        }
    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    return result;
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectThresholdData *de = NULL;
    Signature *sig = NULL;
    SigMatch *m = NULL;
    int result = 0;
    FILE *fd = NULL;

    HostInitConfig(HOST_QUIET);

    if (de_ctx == NULL)
        return result;

    de_ctx->flags |= DE_QUIET;

    sig = de_ctx->sig_list = SigInit(de_ctx,"alert tcp any any -> any any (msg:\"Threshold limit\"; content:\"abc\"; threshold: type limit, track by_dst, count 5, seconds 60; sid:1000;)");
    if (sig == NULL) {
        goto end;
    }

    fd = SCThresholdConfGenerateValidDummyFD20();
    SCThresholdConfInitContext(de_ctx,fd);

    m = SigMatchGetLastSMFromLists(sig, 2,
                                   DETECT_THRESHOLD, sig->sm_lists[DETECT_SM_LIST_SUPPRESS]);
    if (m != NULL)   {
        de = (DetectThresholdData *)m->ctx;
        if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
            m = m->next;
            if (m != NULL)   {
                de = (DetectThresholdData *)m->ctx;
                if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
                    m = m->next;
                    if (m != NULL)   {
                        de = (DetectThresholdData *)m->ctx;
                        if (de != NULL && (de->type == TYPE_SUPPRESS && de->track == TRACK_SRC)) {
                            result = 1;
                        }
                    }
                }
            }
        }
    }
end:
    SigGroupBuild(de_ctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    HostShutdown();
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief This function registers unit tests for Classification Config API.
 */
void SCThresholdConfRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SCThresholdConfTest01", SCThresholdConfTest01, 1);
    UtRegisterTest("SCThresholdConfTest02", SCThresholdConfTest02, 1);
    UtRegisterTest("SCThresholdConfTest03", SCThresholdConfTest03, 1);
    UtRegisterTest("SCThresholdConfTest04", SCThresholdConfTest04, 0);
    UtRegisterTest("SCThresholdConfTest05", SCThresholdConfTest05, 1);
    UtRegisterTest("SCThresholdConfTest06", SCThresholdConfTest06, 1);
    UtRegisterTest("SCThresholdConfTest07", SCThresholdConfTest07, 1);
    UtRegisterTest("SCThresholdConfTest08", SCThresholdConfTest08, 1);
    UtRegisterTest("SCThresholdConfTest09 - rate_filter", SCThresholdConfTest09, 1);
    UtRegisterTest("SCThresholdConfTest10 - rate_filter", SCThresholdConfTest10, 1);
    UtRegisterTest("SCThresholdConfTest11 - event_filter", SCThresholdConfTest11, 1);
    UtRegisterTest("SCThresholdConfTest12 - event_filter", SCThresholdConfTest12, 1);
    UtRegisterTest("SCThresholdConfTest13", SCThresholdConfTest13, 1);
    UtRegisterTest("SCThresholdConfTest14 - suppress", SCThresholdConfTest14, 1);
    UtRegisterTest("SCThresholdConfTest15 - suppress drop", SCThresholdConfTest15, 1);
    UtRegisterTest("SCThresholdConfTest16 - suppress drop", SCThresholdConfTest16, 1);
    UtRegisterTest("SCThresholdConfTest17 - suppress drop", SCThresholdConfTest17, 1);

    UtRegisterTest("SCThresholdConfTest18 - suppress parsing", SCThresholdConfTest18, 1);
    UtRegisterTest("SCThresholdConfTest19 - suppress parsing", SCThresholdConfTest19, 1);
    UtRegisterTest("SCThresholdConfTest20 - suppress parsing", SCThresholdConfTest20, 1);
    UtRegisterTest("SCThresholdConfTest21 - suppress parsing", SCThresholdConfTest21, 1);
#endif /* UNITTESTS */
}

/**
 * @}
 */
