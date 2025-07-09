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
 * \file detect-tag.c
 *
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the tag keyword
 *
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-tag.h"
#include "detect-engine-tag.h"
#include "detect-engine.h"
#include "detect-engine-state.h"
#include "app-layer-parser.h"

#include "decode.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"
#include "stream-tcp-private.h"

#include "util-time.h"
#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "threads.h"

SC_ATOMIC_EXTERN(unsigned int, num_tags);

/* format: tag: <type>, <count>, <metric>, [direction]; */
#define PARSE_REGEX  "^\\s*(host|session)\\s*(,\\s*(\\d+)\\s*,\\s*(packets|bytes|seconds)\\s*(,\\s*(src|dst))?\\s*)?$"

static DetectParseRegex parse_regex;

static int DetectTagMatch(DetectEngineThreadCtx *, Packet *,
        const Signature *, const SigMatchCtx *);
static int DetectTagSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectTagRegisterTests(void);
#endif
void DetectTagDataFree(DetectEngineCtx *, void *);

/**
 * \brief Registration function for keyword tag
 */
void DetectTagRegister(void)
{
    sigmatch_table[DETECT_TAG].name = "tag";
    sigmatch_table[DETECT_TAG].Match = DetectTagMatch;
    sigmatch_table[DETECT_TAG].Setup = DetectTagSetup;
    sigmatch_table[DETECT_TAG].Free  = DetectTagDataFree;
    sigmatch_table[DETECT_TAG].desc = "tag of current and future packets for a flow or host";
    sigmatch_table[DETECT_TAG].url = "/rules/tag.html#tag";
#ifdef UNITTESTS
    sigmatch_table[DETECT_TAG].RegisterTests = DetectTagRegisterTests;
#endif
    sigmatch_table[DETECT_TAG].flags |= SIGMATCH_IPONLY_COMPAT;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief This function is used to setup a tag for session/host
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectTagData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectTagMatch(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
    const DetectTagData *td = (const DetectTagData *)ctx;
    DetectTagDataEntry tde;
    memset(&tde, 0, sizeof(DetectTagDataEntry));

    switch (td->type) {
        case DETECT_TAG_TYPE_HOST:
#ifdef DEBUG
            BUG_ON(!(td->direction == DETECT_TAG_DIR_SRC || td->direction == DETECT_TAG_DIR_DST));
#endif

            tde.sid = s->id;
            tde.gid = s->gid;
            tde.last_ts = tde.first_ts = p->ts;
            tde.metric = td->metric;
            tde.count = td->count;
            if (td->direction == DETECT_TAG_DIR_SRC)
                tde.flags |= TAG_ENTRY_FLAG_DIR_SRC;
            else if (td->direction == DETECT_TAG_DIR_DST)
                tde.flags |= TAG_ENTRY_FLAG_DIR_DST;

            SCLogDebug("Tagging Host with sid %"PRIu32":%"PRIu32"", s->id, s->gid);
            TagHashAddTag(&tde, p);
            break;
        case DETECT_TAG_TYPE_SESSION:
            if (p->flow != NULL) {
                SCLogDebug("Setting up tag for flow");
                /* If it already exists it will be updated */
                tde.sid = s->id;
                tde.gid = s->gid;
                tde.last_ts = tde.first_ts = p->ts;
                tde.metric = td->metric;
                tde.count = td->count;

                SCLogDebug("Adding to or updating flow; first_ts %" PRIu64 " count %u",
                        (uint64_t)SCTIME_SECS(tde.first_ts), tde.count);
                TagFlowAdd(p, &tde);
            } else {
                SCLogDebug("No flow to append the session tag");
            }
            break;
#ifdef DEBUG
        default:
            SCLogDebug("unknown type of a tag keyword (not session nor host)");
            BUG_ON(1);
            break;
#endif
    }

    return 1;
}

/**
 * \brief This function is used to parse tag options passed to tag keyword
 *
 * \param tagstr Pointer to the user provided tag options
 *
 * \retval td pointer to DetectTagData on success
 * \retval NULL on failure
 */
static DetectTagData *DetectTagParse(const char *tagstr)
{
    DetectTagData td;
    size_t pcre2_len;
    const char *str_ptr = NULL;

    pcre2_match_data *match = NULL;
    int ret = DetectParsePcreExec(&parse_regex, &match, tagstr, 0, 0);
    if (ret < 1) {
        SCLogError("parse error, ret %" PRId32 ", string %s", ret, tagstr);
        goto error;
    }

    int res = pcre2_substring_get_bynumber(match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0 || str_ptr == NULL) {
        SCLogError("pcre2_substring_get_bynumber failed");
        goto error;
    }

    /* Type */
    if (strcasecmp("session", str_ptr) == 0) {
        td.type = DETECT_TAG_TYPE_SESSION;
    } else if (strcasecmp("host", str_ptr) == 0) {
        td.type = DETECT_TAG_TYPE_HOST;
    } else {
        SCLogError("Invalid argument type. Must be session or host (%s)", tagstr);
        goto error;
    }
    pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    str_ptr = NULL;

    /* default tag is 256 packets from session or dst host */
    td.count = DETECT_TAG_MAX_PKTS;
    td.metric = DETECT_TAG_METRIC_PACKET;
    td.direction = DETECT_TAG_DIR_DST;

    if (ret > 4) {
        res = pcre2_substring_get_bynumber(match, 3, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0 || str_ptr == NULL) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }

        /* count */
        if (StringParseUint32(&td.count, 10, strlen(str_ptr),
                    str_ptr) <= 0) {
            SCLogError("Invalid argument for count. Must be a value in the range of 0 to %" PRIu32
                       " (%s)",
                    UINT32_MAX, tagstr);
            goto error;
        }

        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
        str_ptr = NULL;

        res = pcre2_substring_get_bynumber(match, 4, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0 || str_ptr == NULL) {
            SCLogError("pcre2_substring_get_bynumber failed");
            goto error;
        }

        /* metric */
        if (strcasecmp("packets", str_ptr) == 0) {
            td.metric = DETECT_TAG_METRIC_PACKET;
            if (DETECT_TAG_MAX_PKTS > 0 && td.count > DETECT_TAG_MAX_PKTS)
                td.count = DETECT_TAG_MAX_PKTS;
            /* TODO: load DETECT_TAG_MAX_PKTS from config */
        } else if (strcasecmp("seconds", str_ptr) == 0) {
            td.metric = DETECT_TAG_METRIC_SECONDS;
        } else if (strcasecmp("bytes", str_ptr) == 0) {
            td.metric = DETECT_TAG_METRIC_BYTES;
        } else {
            SCLogError(
                    "Invalid argument metric. Must be one of \"seconds\", \"packets\" or \"bytes\" "
                    "(%s)",
                    tagstr);
            goto error;
        }

        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
        str_ptr = NULL;

        /* if specified, overwrite it */
        if (ret == 7) {
            res = pcre2_substring_get_bynumber(match, 6, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
            if (res < 0 || str_ptr == NULL) {
                SCLogError("pcre2_substring_get_bynumber failed");
                goto error;
            }

            /* metric */
            if (strcasecmp("src", str_ptr) == 0) {
                td.direction = DETECT_TAG_DIR_SRC;
            } else if (strcasecmp("dst", str_ptr) == 0) {
                td.direction = DETECT_TAG_DIR_DST;
            } else {
                SCLogError(
                        "Invalid argument direction. Must be one of \"src\" or \"dst\" (only valid "
                        "for tag host type, not sessions) (%s)",
                        tagstr);
                goto error;
            }

            if (td.type != DETECT_TAG_TYPE_HOST) {
                SCLogWarning(
                        "Argument direction doesn't make sense for type \"session\" (%s [%" PRIu8
                        "])",
                        tagstr, td.type);
            }

            pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
            str_ptr = NULL;
        }
    }

    DetectTagData *real_td = SCMalloc(sizeof(DetectTagData));
    if (unlikely(real_td == NULL)) {
        SCLogError("Error allocating memory");
        goto error;
    }

    memcpy(real_td, &td, sizeof(DetectTagData));
    pcre2_match_data_free(match);
    return real_td;

error:
    if (match) {
        pcre2_match_data_free(match);
    }
    if (str_ptr != NULL)
        pcre2_substring_free((PCRE2_UCHAR *)str_ptr);
    return NULL;
}

/**
 * \brief this function is used to add the parsed tag data into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param tagstr pointer to the user provided tag options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
int DetectTagSetup(DetectEngineCtx *de_ctx, Signature *s, const char *tagstr)
{
    DetectTagData *td = DetectTagParse(tagstr);
    if (td == NULL)
        return -1;

    /* Append it to the list of tags */
    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_TAG, (SigMatchCtx *)td, DETECT_SM_LIST_TMATCH) ==
            NULL) {
        DetectTagDataFree(de_ctx, td);
        return -1;
    }
    return 0;
}

/** \internal
 *  \brief this function will free memory associated with
 *        DetectTagDataEntry
 *
 *  \param td pointer to DetectTagDataEntry
 */
static void DetectTagDataEntryFree(void *ptr)
{
    if (ptr != NULL) {
        DetectTagDataEntry *dte = (DetectTagDataEntry *)ptr;
        SCFree(dte);
    }
}


/**
 * \brief this function will free all the entries of a list
 *        DetectTagDataEntry
 *
 * \param td pointer to DetectTagDataEntryList
 */
void DetectTagDataListFree(void *ptr)
{
    if (ptr != NULL) {
        DetectTagDataEntry *entry = ptr;

        while (entry != NULL) {
            DetectTagDataEntry *next_entry = entry->next;
            DetectTagDataEntryFree(entry);
            (void) SC_ATOMIC_SUB(num_tags, 1);
            entry = next_entry;
        }
    }
}

/**
 * \brief this function will free memory associated with DetectTagData
 *
 * \param td pointer to DetectTagData
 */
void DetectTagDataFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectTagData *td = (DetectTagData *)ptr;
    SCFree(td);
}

#ifdef UNITTESTS

/**
 * \test DetectTagTestParse01 is a test to make sure that we return "something"
 *  when given valid tag opt
 */
static int DetectTagTestParse01(void)
{
    int result = 0;
    DetectTagData *td = NULL;
    td = DetectTagParse("session, 123, packets");
    if (td != NULL && td->type == DETECT_TAG_TYPE_SESSION
        && td->count == 123
        && td->metric == DETECT_TAG_METRIC_PACKET) {
        DetectTagDataFree(NULL, td);
        result = 1;
    }

    return result;
}

/**
 * \test DetectTagTestParse02 is a test to check that we parse tag correctly
 */
static int DetectTagTestParse02(void)
{
    int result = 0;
    DetectTagData *td = NULL;
    td = DetectTagParse("host, 200, bytes, src");
    if (td != NULL && td->type == DETECT_TAG_TYPE_HOST
        && td->count == 200
        && td->metric == DETECT_TAG_METRIC_BYTES
        && td->direction == DETECT_TAG_DIR_SRC) {
            result = 1;
        DetectTagDataFree(NULL, td);
    }

    return result;
}

/**
 * \test DetectTagTestParse03 is a test for setting the stateless tag opt
 */
static int DetectTagTestParse03(void)
{
    int result = 0;
    DetectTagData *td = NULL;
    td = DetectTagParse("host, 200, bytes, dst");
    if (td != NULL && td->type == DETECT_TAG_TYPE_HOST
        && td->count == 200
        && td->metric == DETECT_TAG_METRIC_BYTES
        && td->direction == DETECT_TAG_DIR_DST) {
            result = 1;
        DetectTagDataFree(NULL, td);
    }

    return result;
}

/**
 * \test DetectTagTestParse04 is a test for default opts
 */
static int DetectTagTestParse04(void)
{
    int result = 0;
    DetectTagData *td = NULL;
    td = DetectTagParse("session");
    if (td != NULL && td->type == DETECT_TAG_TYPE_SESSION
        && td->count == DETECT_TAG_MAX_PKTS
        && td->metric == DETECT_TAG_METRIC_PACKET) {
            result = 1;
        DetectTagDataFree(NULL, td);
    }

    return result;
}

/**
 * \test DetectTagTestParse05 is a test for default opts
 */
static int DetectTagTestParse05(void)
{
    int result = 0;
    DetectTagData *td = NULL;
    td = DetectTagParse("host");
    if (td != NULL && td->type == DETECT_TAG_TYPE_HOST
        && td->count == DETECT_TAG_MAX_PKTS
        && td->metric == DETECT_TAG_METRIC_PACKET
        && td->direction == DETECT_TAG_DIR_DST) {
            result = 1;
        DetectTagDataFree(NULL, td);
    }

    return result;
}

/**
 * \brief this function registers unit tests for DetectTag
 */
void DetectTagRegisterTests(void)
{
    UtRegisterTest("DetectTagTestParse01", DetectTagTestParse01);
    UtRegisterTest("DetectTagTestParse02", DetectTagTestParse02);
    UtRegisterTest("DetectTagTestParse03", DetectTagTestParse03);
    UtRegisterTest("DetectTagTestParse04", DetectTagTestParse04);
    UtRegisterTest("DetectTagTestParse05", DetectTagTestParse05);

    DetectEngineTagRegisterTests();
}
#endif /* UNITTESTS */
