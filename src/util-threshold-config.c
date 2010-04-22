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
#include "util-byte.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-fmemopen.h"

/* File descriptor for unittests */

#define DETECT_THRESHOLD_REGEX "^\\s*(event_filter|threshold)\\s*gen_id\\s*(\\d+)\\s*,\\s*sig_id\\s*(\\d+)\\s*,\\s*type\\s*(limit|both|threshold)\\s*,\\s*track\\s*(by_dst|by_src)\\s*,\\s*count\\s*(\\d+)\\s*,\\s*seconds\\s*(\\d+)\\s*$"

/* Default path for the threshold.config file */
#define THRESHOLD_CONF_DEF_CONF_FILEPATH "threshold.config"

static pcre *regex = NULL;
static pcre_extra *regex_study = NULL;

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
    char *log_filename = (char *)THRESHOLD_CONF_DEF_CONF_FILEPATH;

    ConfGet("threshold-file", &log_filename);

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

    uint8_t parsed_type = 0;
    uint8_t parsed_track = 0;
    uint32_t parsed_count = 0;
    uint32_t parsed_seconds = 0;

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
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        goto error;
    }

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

    if (strcasecmp(th_track,"by_dst") == 0)
        parsed_track = TRACK_DST;
    else if (strcasecmp(th_track,"by_src") == 0)
        parsed_track = TRACK_SRC;

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

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

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

                sm = SigMatchAlloc();
                if (sm == NULL) {
                    SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                    goto error;
                }

                sm->type = DETECT_THRESHOLD;
                sm->ctx = (void *)de;

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

            sm = SigMatchAlloc();
            if (sm == NULL) {
                SCLogError(SC_ERR_MEM_ALLOC, "Error allocating SigMatch");
                goto error;
            }

            sm->type = DETECT_THRESHOLD;
            sm->ctx = (void *)de;

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
 * \brief Parses the Threshold Config file
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param fd Pointer to file descriptor.
 */
void SCThresholdConfParseFile(DetectEngineCtx *de_ctx, FILE *fd)
{
    char line[1024];

    if(fd == NULL)
        return;

    while (fgets(line, sizeof(line), fd) != NULL) {
        if (SCThresholdConfIsLineBlankOrComment(line))
            continue;

        SCThresholdConfAddThresholdtype(line, de_ctx);
    }

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
#endif /* UNITTESTS */
}

