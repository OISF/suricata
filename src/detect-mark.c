/* Copyright (C) 2011-2021 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Implements the mark keyword. Based  on detect-gid
 * by Breno Silva <breno.silva@gmail.com>
 */

#include "suricata-common.h"

#include "detect-mark.h"
#include "detect-parse.h"

#define PARSE_REGEX "([0x]*[0-9a-f]+)/([0x]*[0-9a-f]+)"

static DetectParseRegex parse_regex;

static int DetectMarkSetup (DetectEngineCtx *, Signature *, const char *);
static int DetectMarkPacket(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx);
void DetectMarkDataFree(DetectEngineCtx *, void *ptr);
#if defined UNITTESTS && defined NFQ
static void MarkRegisterTests(void);
#endif

/**
 * \brief Registration function for nfq_set_mark: keyword
 */

void DetectMarkRegister (void)
{
    sigmatch_table[DETECT_MARK].name = "nfq_set_mark";
    sigmatch_table[DETECT_MARK].Match = DetectMarkPacket;
    sigmatch_table[DETECT_MARK].Setup = DetectMarkSetup;
    sigmatch_table[DETECT_MARK].Free  = DetectMarkDataFree;
#if defined UNITTESTS && defined NFQ
    sigmatch_table[DETECT_MARK].RegisterTests = MarkRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

#ifdef NFQ
/**
 * \internal
 * \brief This function is used to parse mark options passed via mark: keyword
 *
 * \param rawstr Pointer to the user provided mark options
 *
 * \retval 0 on success
 * \retval < 0 on failure
 */
static void * DetectMarkParse (const char *rawstr)
{
    int ret = 0, res = 0;
    size_t pcre2_len;
    const char *str_ptr = NULL;
    char *ptr = NULL;
    char *endptr = NULL;
    uint32_t mark;
    uint32_t mask;
    DetectMarkData *data;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, rawstr);
        return NULL;
    }

    res = pcre2_substring_get_bynumber(parse_regex.match, 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        return NULL;
    }

    ptr = (char *)str_ptr;

    if (ptr == NULL)
        return NULL;

    errno = 0;
    mark = strtoul(ptr, &endptr, 0);
    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    }     /* If there is no numeric value in the given string then strtoull(), makes
             endptr equals to ptr and return 0 as result */
    else if (endptr == ptr && mark == 0) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "No numeric value");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    } else if (endptr == ptr) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    }

    res = pcre2_substring_get_bynumber(parse_regex.match, 2, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
        return NULL;
    }

    pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
    ptr = (char *)str_ptr;

    if (ptr == NULL) {
        data = SCMalloc(sizeof(DetectMarkData));
        if (unlikely(data == NULL)) {
            return NULL;
        }
        data->mark = mark;
        data->mask = 0xffff;
        return data;
    }

    errno = 0;
    mask = strtoul(ptr, &endptr, 0);
    if (errno == ERANGE) {
        SCLogError(SC_ERR_NUMERIC_VALUE_ERANGE, "Numeric value out of range");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    }     /* If there is no numeric value in the given string then strtoull(), makes
             endptr equals to ptr and return 0 as result */
    else if (endptr == ptr && mask == 0) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "No numeric value");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    }
    else if (endptr == ptr) {
        SCLogError(SC_ERR_INVALID_NUMERIC_VALUE, "Invalid numeric value");
        pcre2_substring_free((PCRE2_UCHAR8 *)ptr);
        return NULL;
    }

    SCLogDebug("Rule will set mark 0x%x with mask 0x%x", mark, mask);
    pcre2_substring_free((PCRE2_UCHAR8 *)ptr);

    data = SCMalloc(sizeof(DetectMarkData));
    if (unlikely(data == NULL)) {
        return NULL;
    }
    data->mark = mark;
    data->mask = mask;
    return data;
}

#endif /* NFQ */

/**
 * \internal
 * \brief this function is used to add the parsed mark into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided mark options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectMarkSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
#ifndef NFQ
    return 0;
#else
    DetectMarkData *data = DetectMarkParse(rawstr);
    if (data == NULL) {
        return -1;
    }
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectMarkDataFree(de_ctx, data);
        return -1;
    }

    sm->type = DETECT_MARK;
    sm->ctx = (SigMatchCtx *)data;

    /* Append it to the list of post match, so the mark is set if the
     * full signature matches. */
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_POSTMATCH);
    return 0;
#endif
}

void DetectMarkDataFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectMarkData *data = (DetectMarkData *)ptr;
    SCFree(data);
}


static int DetectMarkPacket(DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx)
{
#ifdef NFQ
    const DetectMarkData *nf_data = (const DetectMarkData *)ctx;
    if (nf_data->mask) {
        if (!(IS_TUNNEL_PKT(p))) {
            /* coverity[missing_lock] */
            p->nfq_v.mark = (nf_data->mark & nf_data->mask)
                | (p->nfq_v.mark & ~(nf_data->mask));
            p->flags |= PKT_MARK_MODIFIED;
        } else {
            /* real tunnels may have multiple flows inside them, so marking
             * might 'mark' too much. Rebuilt packets from IP fragments
             * are fine. */
            if (p->flags & PKT_REBUILT_FRAGMENT) {
                Packet *tp = p->root ? p->root : p;
                SCMutexLock(&tp->tunnel_mutex);
                tp->nfq_v.mark = (nf_data->mark & nf_data->mask)
                    | (tp->nfq_v.mark & ~(nf_data->mask));
                tp->flags |= PKT_MARK_MODIFIED;
                SCMutexUnlock(&tp->tunnel_mutex);
            }
        }
    }
#endif
    return 1;
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#if defined UNITTESTS && defined NFQ
#include "util-unittest.h"

/**
 * \test MarkTestParse01 is a test for a valid mark value
 *
 */
static int MarkTestParse01 (void)
{
    DetectMarkData *data;

    data = DetectMarkParse("1/1");

    FAIL_IF_NULL(data);

    DetectMarkDataFree(NULL, data);
    PASS;
}

/**
 * \test MarkTestParse02 is a test for an invalid mark value
 *
 */
static int MarkTestParse02 (void)
{
    DetectMarkData *data;

    data = DetectMarkParse("4");

    FAIL_IF_NOT_NULL(data);

    DetectMarkDataFree(NULL, data);
    PASS;
}

/**
 * \test MarkTestParse03 is a test for a valid mark value
 *
 */
static int MarkTestParse03 (void)
{
    DetectMarkData *data;

    data = DetectMarkParse("0x10/0xff");

    FAIL_IF_NULL(data);

    DetectMarkDataFree(NULL, data);
    PASS;
}

/**
 * \test MarkTestParse04 is a test for a invalid mark value
 *
 */
static int MarkTestParse04 (void)
{
    DetectMarkData *data;

    data = DetectMarkParse("0x1g/0xff");

    FAIL_IF_NOT_NULL(data);

    DetectMarkDataFree(NULL, data);
    PASS;
}

/**
 * \brief this function registers unit tests for Mark
 */
static void MarkRegisterTests(void)
{
    UtRegisterTest("MarkTestParse01", MarkTestParse01);
    UtRegisterTest("MarkTestParse02", MarkTestParse02);
    UtRegisterTest("MarkTestParse03", MarkTestParse03);
    UtRegisterTest("MarkTestParse04", MarkTestParse04);
}
#endif /* UNITTESTS */
