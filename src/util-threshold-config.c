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
 * \file
 *
 * \author Breno Silva Pinto <breno.silva@gmail.com>
 *
 * \todo Need to support suppress
 *
 * Implements Threshold support
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-engine.h"
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

/* File descriptor for unittests */

#define DETECT_THRESHOLD_REGEX "^\\s*(event_filter|threshold)\\s*gen_id\\s*(\\d+)\\s*,\\s*sig_id\\s*(\\d+)\\s*,\\s*type\\s*(limit|both|threshold)\\s*,\\s*track\\s*(by_dst|by_src)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*$"

/* TODO: "apply_to" */
#define DETECT_RATE_REGEX "^\\s*(rate_filter)\\s*gen_id\\s*(\\d+)\\s*,\\s*sig_id\\s*(\\d+)\\s*,\\s*track\\s*(by_dst|by_src|by_rule)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*,\\s*new_action\\s*(alert|drop|pass|log|sdrop|reject)\\s*,\\s*timeout\\s*(\\d+)\\s*$"

/* Default path for the threshold.config file */
#define THRESHOLD_CONF_DEF_CONF_FILEPATH "threshold.config"

static pcre *regex = NULL;
static pcre_extra *regex_study = NULL;

static pcre *rate_regex = NULL;
static pcre_extra *rate_regex_study = NULL;

/**
 * \brief Returns the path for the Threshold Config file.  We check if we
 *        can retrieve the path from the yaml conf file.  If it is not present,
 *        return the default path for the threshold file which is
 *        "./threshold.config".
 *
 * \retval log_filename Pointer to a string containing the path for the
 *                      Threshold Config file.
 */
char *SCThresholdConfGetConfFilename(void)
{
    char *log_filename = NULL;

    if (ConfGet("threshold-file", &log_filename) != 1) {
        log_filename = (char *)THRESHOLD_CONF_DEF_CONF_FILEPATH;
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
        filename = SCThresholdConfGetConfFilename();
        if ( (fd = fopen(filename, "r")) == NULL) {
            SCLogError(SC_ERR_FOPEN, "Error opening file: \"%s\": %s", filename, strerror(errno));
            goto error;
        }
    }

    regex = pcre_compile(DETECT_THRESHOLD_REGEX, opts, &eb, &eo, NULL);
    if (regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_THRESHOLD_REGEX, eo, eb);
        goto error;
    }

    regex_study = pcre_study(regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    rate_regex = pcre_compile(DETECT_RATE_REGEX, opts, &eb, &eo, NULL);
    if (regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Compile of \"%s\" failed at offset %" PRId32 ": %s",DETECT_RATE_REGEX, eo, eb);
        goto error;
    }

    rate_regex_study = pcre_study(rate_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    SCThresholdConfParseFile(de_ctx, fd);
    SCThresholdConfDeInitContext(de_ctx, fd);

    SCLogInfo("Global thresholding options defined");
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

    if(fd != NULL)
        fclose(fd);
    return;
}

/**
 * \brief Parses a line from the threshold file and adds it to Thresholdtype
 *
 * \param rawstr Pointer to the string to be parsed.
 * \param de_ctx Pointer to the Detection Engine Context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int SCThresholdConfAddThresholdtype(char *rawstr, DetectEngineCtx *de_ctx)
{
    const char *th_gid = NULL;
    const char *th_sid = NULL;
    const char *th_type = NULL;
    const char *th_track = NULL;
    const char *th_count = NULL;
    const char *th_seconds = NULL;
    const char *th_new_action= NULL;
    const char *th_timeout = NULL;

    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint8_t parsed_new_action = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;
    uint32_t parsed_timeout = 0;

    Signature *sig = NULL;
    Signature *s = NULL, *ns = NULL;
    DetectThresholdData *de = NULL;
    SigMatch *sm = NULL;
    SigMatch *m = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];
    uint32_t id = 0, gid = 0;

    if (de_ctx == NULL)
        return -1;

    ret = pcre_exec(regex, regex_study, rawstr, strlen(rawstr), 0, 0, ov, 30);

    if (ret < 8) {
        /* Its not threshold/event_filter, so try rate_filter regexp */
        ret = pcre_exec(rate_regex, rate_regex_study, rawstr, strlen(rawstr), 0, 0, ov, 30);
        if (ret < 9) {
            SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
            goto error;
        } else {
        /* Start rate_filter parsing */
            /* retrieve the classtype name */
            ret = pcre_get_substring((char *)rawstr, ov, 30, 2, &th_gid);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 3, &th_sid);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 4, &th_track);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 5, &th_count);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 6, &th_seconds);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 7, &th_new_action);
            if (ret < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
                goto error;
            }

            ret = pcre_get_substring((char *)rawstr, ov, 30, 8, &th_timeout);
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

        } /* End rate_filter parsing */
    } else {
        /* Its a threshold/event_filter rule, Parse it */

        /* retrieve the classtype name */
        ret = pcre_get_substring((char *)rawstr, ov, 30, 2, &th_gid);
        if (ret < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        ret = pcre_get_substring((char *)rawstr, ov, 30, 3, &th_sid);
        if (ret < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        ret = pcre_get_substring((char *)rawstr, ov, 30, 4, &th_type);
        if (ret < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        ret = pcre_get_substring((char *)rawstr, ov, 30, 5, &th_track);
        if (ret < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        ret = pcre_get_substring((char *)rawstr, ov, 30, 6, &th_count);
        if (ret < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        ret = pcre_get_substring((char *)rawstr, ov, 30, 7, &th_seconds);
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
    } /* End of threshold/event_filter parsing */

    /* This part is common to threshold/event_filter/rate_filter */
    if (strcasecmp(th_track,"by_dst") == 0)
        parsed_track = TRACK_DST;
    else if (strcasecmp(th_track,"by_src") == 0)
        parsed_track = TRACK_SRC;
    else if (strcasecmp(th_track,"by_rule") == 0)
        parsed_track = TRACK_RULE;

    if (ByteExtractStringUint32(&parsed_count, 10, strlen(th_count), th_count) <= 0) {
        goto error;
    }

    if (ByteExtractStringUint32(&parsed_seconds, 10, strlen(th_seconds), th_seconds) <= 0) {
        goto error;
    }

    if (ByteExtractStringUint32(&id, 10, strlen(th_sid), th_sid) <= 0) {
        goto error;
    }

    if (ByteExtractStringUint32(&gid, 10, strlen(th_gid), th_gid) <= 0) {
        goto error;
    }


    /* Install it */
    if (id == 0 && gid == 0) {

        for (s = de_ctx->sig_list; s != NULL;) {

            ns = s->next;

            m = SigMatchGetLastSM(s->match, DETECT_THRESHOLD);

            if(m != NULL)
                goto end;

            m = SigMatchGetLastSM(s->match, DETECT_DETECTION_FILTER);

            if(m != NULL)
                goto end;

            de = SCMalloc(sizeof(DetectThresholdData));
            if (de == NULL)
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
                de_ctx->ths_ctx.th_entry = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                if (de_ctx->ths_ctx.th_entry == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                    " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                } else {
                    de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                    de_ctx->ths_ctx.th_size++;
                }
            }
            SigMatchAppendPacket(s, sm);
            s = ns;
        }

    } else if (id == 0 && gid > 0)    {

        for (s = de_ctx->sig_list; s != NULL;) {

            ns = s->next;

            if(s->gid == gid)   {

                m = SigMatchGetLastSM(s->match, DETECT_THRESHOLD);

                if(m != NULL)
                    goto end;

                m = SigMatchGetLastSM(s->match, DETECT_DETECTION_FILTER);

                if(m != NULL)
                    goto end;

                de = SCMalloc(sizeof(DetectThresholdData));
                if (de == NULL)
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
                    de_ctx->ths_ctx.th_entry = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                    if (de_ctx->ths_ctx.th_entry == NULL) {
                        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                        " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                    } else {
                        de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                        de_ctx->ths_ctx.th_size++;
                    }
                }
                SigMatchAppendPacket(s, sm);
            }
            s = ns;
        }
    } else {
        sig = SigFindSignatureBySidGid(de_ctx,id,gid);

        if(sig != NULL) {

            m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

            if(m != NULL)
                goto end;

            m = SigMatchGetLastSM(sig->match, DETECT_DETECTION_FILTER);

            if(m != NULL)
                goto end;

            de = SCMalloc(sizeof(DetectThresholdData));
            if (de == NULL)
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
                de_ctx->ths_ctx.th_entry = SCRealloc(de_ctx->ths_ctx.th_entry, (de_ctx->ths_ctx.th_size + 1) * sizeof(DetectThresholdEntry *));
                if (de_ctx->ths_ctx.th_entry == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory for threshold config"
                    " (tried to allocate %"PRIu32"th_entrys for rule tracking with rate_filter)", de_ctx->ths_ctx.th_size + 1);
                } else {
                    de_ctx->ths_ctx.th_entry[de_ctx->ths_ctx.th_size] = NULL;
                    de_ctx->ths_ctx.th_size++;
                }
            }

            SigMatchAppendPacket(sig, sm);
        }

    }

end:
    if(th_sid != NULL) SCFree((char *)th_sid);
    if(th_gid != NULL) SCFree((char *)th_gid);
    if(th_track != NULL) SCFree((char *)th_track);
    if(th_count != NULL) SCFree((char *)th_count);
    if(th_seconds != NULL) SCFree((char *)th_seconds);
    if(th_type != NULL) SCFree((char *)th_type);

    return 0;

error:
    if(de != NULL) SCFree(de);
    if(th_sid != NULL) SCFree((char *)th_sid);
    if(th_gid != NULL) SCFree((char *)th_gid);
    if(th_track != NULL) SCFree((char *)th_track);
    if(th_count != NULL) SCFree((char *)th_count);
    if(th_seconds != NULL) SCFree((char *)th_seconds);
    if(th_type != NULL) SCFree((char *)th_type);
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
        if (!isspace(*line))
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
            if (!isspace(*line))
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
int SCThresholdConfLineLength(FILE *fd) {
    long pos = ftell(fd);
    int len = 0;
    int c;

    while ( (c = fgetc(fd)) && c != '\n' && !feof(fd))
        len++;

    if (pos < 0)
        pos = 0;

    fseek(fd, pos, SEEK_SET);
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
    int c;
    int rule_num = 0;

    /* position of "\", on multiline rules */
    int esc_pos = 0;

    if (fd == NULL)
        return;

    while (!feof(fd)) {
        len = SCThresholdConfLineLength(fd);

        if (len > 0) {
            if (line == NULL)
                line = SCRealloc(line, len + 1);
            else
                line = SCRealloc(line, strlen(line) + len + 1);

            if (line == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
                break;
            }

            if (fgets(line + esc_pos, len + 1, fd) == NULL)
                break;

            /* Skip EOL to inspect the next line (or read EOF) */
            c = fgetc(fd);

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
            c = fgetc(fd);
            if (feof(fd))
                break;
        }
    }

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

    m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

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

    m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

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

    m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

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

    m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

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

            m = SigMatchGetLastSM(s->match, DETECT_THRESHOLD);

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

    m = SigMatchGetLastSM(sig->match, DETECT_THRESHOLD);

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

    m = SigMatchGetLastSM(sig->match, DETECT_DETECTION_FILTER);

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

    m = SigMatchGetLastSM(sig->match, DETECT_DETECTION_FILTER);

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

    Packet *p = UTHBuildPacket((uint8_t*)"lalala", 6, IPPROTO_TCP);
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int alerts = 0;

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

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts = PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    if (alerts > 0) {
        goto end;
        result = 0;
    }

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    if (alerts != 1) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(2);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    if (alerts != 2) {
        result = 0;
        goto end;
    }

    TimeSetIncrementTime(10);
    TimeGet(&p->ts);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    alerts += PacketAlertCheck(p, 10);

    if (alerts == 2)
        result = 1;

end:
    UTHFreePacket(p);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

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
        goto end;
        result = 0;
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
#endif /* UNITTESTS */
}

