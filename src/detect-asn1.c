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
 * \file detect-asn1.c
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *
 * Implements "asn1" keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow.h"
#include "detect-asn1.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-debug.h"
#include "util-decode-asn1.h"

/* delimiters for functions/arguments */
const char *ASN_DELIM = " \t,\n";

static int DetectAsn1Match(ThreadVars *, DetectEngineThreadCtx *, Packet *,
                     const Signature *, const SigMatchCtx *);
static int DetectAsn1Setup (DetectEngineCtx *, Signature *, const char *);
static void DetectAsn1RegisterTests(void);
static void DetectAsn1Free(void *);

/**
 * \brief Registration function for asn1
 */
void DetectAsn1Register(void)
{
    sigmatch_table[DETECT_ASN1].name = "asn1";
    sigmatch_table[DETECT_ASN1].Match = DetectAsn1Match;
    sigmatch_table[DETECT_ASN1].Setup = DetectAsn1Setup;
    sigmatch_table[DETECT_ASN1].Free  = DetectAsn1Free;
    sigmatch_table[DETECT_ASN1].RegisterTests = DetectAsn1RegisterTests;

    return;
}

/**
 * \brief The main checks are done here
 *        This function implements the detection of the following options:
 *          - oversize_length
 *          - bitstring_overflow
 *          - double_overflow
 *        We can add more checks here easily since we have all the data of the
 *        node avaliable. If we need all the tree, we can just pass the
 *        ASN1 ctx as argument and perform the checks here
 * \param node pointer to the Asn1Node to inspect
 * \param ad pointer to the parsed options of the asn1 keyword (which hold the
 *           checks that we want to perform, and the lenght of oversize check
 * \retval 1 if any of the options match, 0 if not
 */
static uint8_t DetectAsn1Checks(Asn1Node *node, const DetectAsn1Data *ad)
{

    /* oversize_length will check if a node has a length greater than
     * the user supplied length */
    if (ad->flags & ASN1_OVERSIZE_LEN) {
        if (node->len.len > ad->oversize_length
            || node->data.len > ad->oversize_length)
            return 1;
    }

    /* 8.6 */
    /* bitstring_overflow check a malformed option where the number of bits
     * to ignore is greater than the length decoded (in bits) */
    if (ad->flags & ASN1_BITSTRING_OVF) {
        if (node->id.class_tag == ASN1_BER_CLASS_UNIV &&
            node->id.tag_num == ASN1_UNITAG_BIT_STRING &&
            node->id.tag_type == ASN1_TAG_TYPE_PRIMITIVE)
        {
            if (node->len.len > 0 && node->data.ptr != NULL
                && (node->len.len) * 8 < (uint8_t) *node->data.ptr)
            {
                return 1;
            }
        }
    }

    /* double_overflow checks a known issue that affect the MSASN1 library
     * when decoding double/real types. If the endoding is ASCII,
     * and the buffer is greater than 256, the array is overflown
     */
    if (ad->flags & ASN1_DOUBLE_OVF) {
        if (node->id.class_tag == ASN1_BER_CLASS_UNIV &&
            node->id.tag_num == ASN1_UNITAG_REAL &&
            node->id.tag_type == ASN1_TAG_TYPE_PRIMITIVE)
        {
            if (node->len.len > 0 && node->data.ptr != NULL
                && !((uint8_t) *node->data.ptr & 0xC0)
                && (node->len.len > 256 || node->data.len > 256))
            {
                return 1;
            }
        }
    }

    /* Good to know :) */
    return 0;
}

/**
 * \brief This function will decode the asn1 data and inspect the resulting
 *        nodes to detect if any of the specified checks match this data
 *
 * \param t pointer to thread vars
 * \param det_ctx pointer to the pattern matcher thread
 * \param p pointer to the current packet
 * \param m pointer to the sigmatch that we will cast into DetectAsn1Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectAsn1Match(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p,
                    const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t ret = 0;

    if (p->payload_len == 0) {
        /* No error, parser done, no data in bounds to decode */
        return 0;
    }

    const DetectAsn1Data *ad = (const DetectAsn1Data *)ctx;

    Asn1Ctx *ac = SCAsn1CtxNew();
    if (ac == NULL)
        return 0;

    if (ad->flags & ASN1_ABSOLUTE_OFFSET) {
        SCAsn1CtxInit(ac, p->payload + ad->absolute_offset,
                      p->payload_len - ad->absolute_offset);
    } else if (ad->flags & ASN1_RELATIVE_OFFSET) {
        SCAsn1CtxInit(ac, p->payload + ad->relative_offset,
                      p->payload_len - ad->relative_offset);
    } else {
        SCAsn1CtxInit(ac, p->payload, p->payload_len);
    }

    SCAsn1Decode(ac, ac->cur_frame);

    /* Ok, now we have all the data. Let's check the nodes */

    if (ac->cur_frame > 0 || (ac->asn1_stack[0] != NULL && ac->asn1_stack[0]->id.ptr != NULL)) {
        /* We spect at least one node */
        uint16_t n_iter = 0;
        ret = 0;

        for (; n_iter <= ac->cur_frame; n_iter++) {
            Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

            if (node == NULL || node->id.ptr == NULL)
                continue; /* Should not happen */

            ret = DetectAsn1Checks(node, ad);
            /* Got a match? */
            if (ret == 1)
                break;
        }
    }

    SCAsn1CtxDestroy(ac);
    return ret;
}

/**
 * \brief This function is used to parse asn1 options passed via asn1: keyword
 *
 * \param asn1str Pointer to the user provided asn1 options
 *
 * \retval fd pointer to DetectAsn1Data on success
 * \retval NULL on failure
 */
static DetectAsn1Data *DetectAsn1Parse(const char *instr)
{
    DetectAsn1Data *fd = NULL;
    char *tok = NULL;
    uint32_t ov_len = 0;
    uint32_t abs_off = 0;
    int32_t rel_off = 0;
    uint8_t flags = 0;
    char *saveptr = NULL;

    char *asn1str = SCStrdup(instr);
    if (asn1str == NULL)
        return NULL;

    tok = strtok_r(asn1str, ASN_DELIM, &saveptr);
    if (tok == NULL) {
        SCLogError(SC_ERR_INVALID_VALUE, "Malformed asn1 argument: %s",
                   asn1str);
        SCFree(asn1str);
        return NULL;
    }

    while (tok != NULL) {
        if (strcasecmp("bitstring_overflow", tok) == 0) {
            /* No arg here, just set the flag */
            flags |= ASN1_BITSTRING_OVF;
        } else if (strcasecmp("double_overflow", tok) == 0) {
            /* No arg here, just set the flag */
            flags |= ASN1_DOUBLE_OVF;
        } else if (strcasecmp("oversize_length", tok) == 0) {
            flags |= ASN1_OVERSIZE_LEN;
            /* get the param */
            tok = strtok_r(NULL, ASN_DELIM, &saveptr);
            if ( tok == NULL ||
                ByteExtractStringUint32(&ov_len, 10, 0, tok) <= 0)
            {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed value for "
                           "oversize_length: %s", tok);
                goto error;
            }
        } else if (strcasecmp("absolute_offset", tok) == 0) {
            flags |= ASN1_ABSOLUTE_OFFSET;
            /* get the param */
            tok = strtok_r(NULL, ASN_DELIM, &saveptr);
            if (tok == NULL ||
                ByteExtractStringUint32(&abs_off, 10, 0, tok) <= 0)
            {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed value for "
                           "absolute_offset: %s", tok);
                goto error;
            }
        } else if (strcasecmp("relative_offset",tok) == 0) {
            flags |= ASN1_RELATIVE_OFFSET;
            /* get the param */
            tok = strtok_r(NULL, ASN_DELIM, &saveptr);
            if (tok == NULL ||
                ByteExtractStringInt32(&rel_off, 10, 0, tok) <= 0)
            {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed value for "
                           "relative_offset: %s", tok);
                goto error;
            }
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed asn1 argument: %s",
                       asn1str);
            return NULL;
        }
        tok = strtok_r(NULL, ASN_DELIM, &saveptr);
    }

    fd = SCMalloc(sizeof(DetectAsn1Data));
    if (unlikely(fd == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(fd, 0x00, sizeof(DetectAsn1Data));

    fd->flags = flags;
    fd->oversize_length = ov_len;    /* Length argument if needed */
    fd->absolute_offset = abs_off;   /* Length argument if needed */
    fd->relative_offset = rel_off;   /* Length argument if needed */
    SCFree(asn1str);
    return fd;

error:
    SCFree(asn1str);
    return NULL;
}

/**
 * \brief this function is used to add the parsed asn1 data into
 *        the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param asn1str pointer to the user provided asn1 options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectAsn1Setup(DetectEngineCtx *de_ctx, Signature *s, const char *asn1str)
{
    DetectAsn1Data *ad = NULL;
    SigMatch *sm = NULL;

    ad = DetectAsn1Parse(asn1str);
    if (ad == NULL) goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_ASN1;
    sm->ctx = (SigMatchCtx *)ad;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;

error:
    if (ad != NULL)
        DetectAsn1Free(ad);
    if (sm != NULL)
        SCFree(sm);
    return -1;

}

/**
 * \brief this function will free memory associated with DetectAsn1Data
 *
 * \param ad pointer to DetectAsn1Data
 */
static void DetectAsn1Free(void *ptr)
{
    DetectAsn1Data *ad = (DetectAsn1Data *)ptr;
    SCFree(ad);
}

#ifdef UNITTESTS

/**
 * \test DetectAsn1TestParse01 check that we parse oversize_length correctly
 */
static int DetectAsn1TestParse01(void)
{
    int result = 0;
    char str[] = "oversize_length 1024";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL) {
        if (ad->oversize_length == 1024 && (ad->flags & ASN1_OVERSIZE_LEN)) {
            result = 1;
        }
        DetectAsn1Free(ad);
    }

    return result;
}

/**
 * \test DetectAsn1TestParse02 check that we parse absolute_offset correctly
 */
static int DetectAsn1TestParse02(void)
{
    int result = 0;
    DetectAsn1Data *ad = NULL;
    char str[] = "absolute_offset 1024";

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->absolute_offset == 1024
        && (ad->flags & ASN1_ABSOLUTE_OFFSET)) {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse03 check that we parse relative_offset correctly
 */
static int DetectAsn1TestParse03(void)
{
    int result = 0;
    char str[] = "relative_offset     1024";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->relative_offset == 1024
        && (ad->flags & ASN1_RELATIVE_OFFSET)) {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse04 check that we parse bitstring_overflow correctly
 */
static int DetectAsn1TestParse04(void)
{
    int result = 0;
    char str[] = "bitstring_overflow";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_BITSTRING_OVF)) {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse05 check that we parse double_overflow correctly
 */
static int DetectAsn1TestParse05(void)
{
    int result = 0;
    char str[] = "double_overflow";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_DOUBLE_OVF)) {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse06 check that we fail if a needed arg is not given
 */
static int DetectAsn1TestParse06(void)
{
    int result = 1;
    char str[] = "absolute_offset";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL) {
        DetectAsn1Free(ad);
        result = 0;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse07 check that we fail if a needed arg is not given
 */
static int DetectAsn1TestParse07(void)
{
    int result = 1;
    char str[] = "relative_offset";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL) {
        DetectAsn1Free(ad);
        result = 0;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse08 check that we fail if a needed arg is not given
 */
static int DetectAsn1TestParse08(void)
{
    int result = 1;
    char str[] = "oversize_length";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL) {
        DetectAsn1Free(ad);
        result = 0;
    }

    return result;
}



/**
 * \test DetectAsn1TestParse09 test that we break on invalid options
 */
static int DetectAsn1TestParse09(void)
{
    int result = 1;
    DetectAsn1Data *fd = NULL;
    char str[] = "oversize_length 1024, lalala 360";

    fd = DetectAsn1Parse(str);
    if (fd != NULL) {
        result = 0;
        DetectAsn1Free(fd);
    }

    return result;
}

/**
 * \test DetectAsn1TestParse10 test that we break with a empty string
 */
static int DetectAsn1TestParse10(void)
{
    int result = 1;
    DetectAsn1Data *fd = NULL;
    char str[] = "";

    fd = DetectAsn1Parse(str);
    if (fd != NULL) {
        result = 0;
        DetectAsn1Free(fd);
    }

    return result;
}

/**
 * \test DetectAsn1TestParse11 check for combinations of keywords
 */
static int DetectAsn1TestParse11(void)
{
    int result = 0;
    char str[] = "oversize_length 1024, relative_offset 10";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 1024
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && ad->relative_offset == 10
        && (ad->flags & ASN1_RELATIVE_OFFSET))
    {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse12 check for combinations of keywords
 */
static int DetectAsn1TestParse12(void)
{
    int result = 0;
    char str[] = "oversize_length 1024 absolute_offset 10";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 1024
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && ad->absolute_offset == 10
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse13 check for combinations of keywords
 */
static int DetectAsn1TestParse13(void)
{
    int result = 0;
    char str[] = "oversize_length 1024 absolute_offset 10, bitstring_overflow";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 1024
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && (ad->flags & ASN1_BITSTRING_OVF)
        && ad->absolute_offset == 10
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse14 check for combinations of keywords
 */
static int DetectAsn1TestParse14(void)
{
    int result = 0;
    char str[] = "double_overflow, oversize_length 1024 absolute_offset 10,"
                 " bitstring_overflow";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 1024
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && (ad->flags & ASN1_BITSTRING_OVF)
        && (ad->flags & ASN1_DOUBLE_OVF)
        && ad->absolute_offset == 10
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestParse15 check for combinations of keywords
 */
static int DetectAsn1TestParse15(void)
{
    int result = 0;
    char str[] = "double_overflow, oversize_length 1024 relative_offset 10,"
                 " bitstring_overflow";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 1024
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && (ad->flags & ASN1_BITSTRING_OVF)
        && (ad->flags & ASN1_DOUBLE_OVF)
        && ad->relative_offset == 10
        && (ad->flags & ASN1_RELATIVE_OFFSET))
    {
        DetectAsn1Free(ad);
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1Test01 Ensure that the checks work when they should
 */
static int DetectAsn1Test01(void)
{
    /* Match if any of the nodes after offset 0 has greater length than 10 */
    char str[] = "oversize_length 132 absolute_offset 0";

    DetectAsn1Data *ad = DetectAsn1Parse(str);
    FAIL_IF_NULL(ad);
    FAIL_IF_NOT(ad->oversize_length == 132);
    FAIL_IF_NOT(ad->flags & ASN1_OVERSIZE_LEN);
    FAIL_IF_NOT(ad->absolute_offset == 0);
    FAIL_IF_NOT(ad->flags & ASN1_ABSOLUTE_OFFSET);

    // Example from the specification X.690-0207 Appendix A.3
    char buf[] = "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
        "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
        "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
        "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
        "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
        "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
        "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
        "Jones""\xA0\x0A\x43\x08""19590717";

    Asn1Ctx *ac = SCAsn1CtxNew();
    FAIL_IF_NULL(ac);

    uint16_t len = strlen((char *)buf)-1;

    SCAsn1CtxInit(ac, (uint8_t *)buf, len);
    SCAsn1Decode(ac, ac->cur_frame);

    /* The first node has length 133, so it should match the oversize */
    FAIL_IF_NOT(ac->cur_frame > 0);

    /* We spect at least one node */
    uint16_t n_iter = 0;
    int result = 0;
    for (; n_iter <= ac->cur_frame; n_iter++) {
        Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

        if (node == NULL || node->id.ptr == NULL)
            continue; /* Should not happen */

        result = DetectAsn1Checks(node, ad);
        /* Got a match? */
        if (result == 1)
            break;
    }
    FAIL_IF(result != 1);

    SCAsn1CtxDestroy(ac);
    DetectAsn1Free(ad);

    PASS;
}

/**
 * \test DetectAsn1Test02 Ensure that the checks work when they should
 */
static int DetectAsn1Test02(void)
{
    int result = 0;
    /* Match if any of the nodes has the bitstring overflow condition */
    char str[] = "oversize_length 133, absolute_offset 0";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && ad->oversize_length == 133
        && (ad->flags & ASN1_OVERSIZE_LEN)
        && ad->absolute_offset == 0
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
       // Example from the specification X.690-0207 Appendix A.3
        uint8_t *buf = (uint8_t*) "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717";

        Asn1Ctx *ac = SCAsn1CtxNew();
        if (ac == NULL)
            return 0;

        uint16_t len = strlen((char *)buf)-1;

        SCAsn1CtxInit(ac, buf, len);

        SCAsn1Decode(ac, ac->cur_frame);

        /* The first node has length 133, so it should match the oversize */
        if (ac->cur_frame > 0) {
            /* We spect at least one node */
            uint16_t n_iter = 0;

            for (; n_iter <= ac->cur_frame; n_iter++) {
                Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

                if (node == NULL || node->id.ptr == NULL)
                    continue; /* Should not happen */

                result |= DetectAsn1Checks(node, ad);
            }
        }

        /* Got a match? We don't have nodes greater than 133, it should not */
        if (result == 1) {
            printf("Error, oversize_length should not match"
                   " any of the nodes: ");
            result = 0;
        } else {
            result = 1;
        }

        SCAsn1CtxDestroy(ac);
        DetectAsn1Free(ad);

    }

    return result;
}

/**
 * \test DetectAsn1Test03 Ensure that the checks work when they should
 */
static int DetectAsn1Test03(void)
{
    int result = 0;
    /* Match if any of the nodes after offset 0 has a bitstring overflow */
    char str[] = "bitstring_overflow, absolute_offset 0";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_BITSTRING_OVF)
        && ad->absolute_offset == 0
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        /* Let's say tagnum bitstring, primitive, and as universal tag,
         * and then length = 1 octet, but the next octet specify to ignore
         * the last  256 bits... (let's match!) */
        uint8_t *buf = (uint8_t*) "\x03\x01\xFF";

        Asn1Ctx *ac = SCAsn1CtxNew();
        if (ac == NULL)
            return 0;

        uint16_t len = 3;

        SCAsn1CtxInit(ac, buf, len);

        SCAsn1Decode(ac, ac->cur_frame);

        if (ac->cur_frame > 0 || ac->asn1_stack[0]->id.ptr != NULL) {
            /* We spect at least one node */
            uint16_t n_iter = 0;

            for (; n_iter <= ac->cur_frame; n_iter++) {
                Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

                if (node == NULL || node->id.ptr == NULL)
                    continue; /* Should not happen */

                result = DetectAsn1Checks(node, ad);
                /* Got a match? */
                if (result == 1)
                    break;
            }
        }

        SCAsn1CtxDestroy(ac);
        DetectAsn1Free(ad);

    }

    if (result == 0) {
        printf("Error, bitstring_overflow should match the first node: ");
    }

    return result;
}

/**
 * \test DetectAsn1Test04 Ensure that the checks work when they should
 */
static int DetectAsn1Test04(void)
{
    int result = 0;
    /* Match if any of the nodes after offset 0 has a bitstring overflow */
    char str[] = "bitstring_overflow, absolute_offset 0";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_BITSTRING_OVF)
        && ad->absolute_offset == 0
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        /* Let's say tagnum bitstring, primitive, and as universal tag,
         * and then length = 1 octet, but the next octet specify to ignore
         * the last  7 bits... (should not match) */
        uint8_t *buf = (uint8_t*) "\x03\x01\x07";

        Asn1Ctx *ac = SCAsn1CtxNew();
        if (ac == NULL)
            return 0;

        uint16_t len = 3;

        SCAsn1CtxInit(ac, buf, len);

        SCAsn1Decode(ac, ac->cur_frame);

        if (ac->cur_frame > 0 || ac->asn1_stack[0]->id.ptr != NULL) {
            /* We spect at least one node */
            uint16_t n_iter = 0;

            for (; n_iter <= ac->cur_frame; n_iter++) {
                Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

                if (node == NULL || node->id.ptr == NULL)
                    continue; /* Should not happen */

                result = DetectAsn1Checks(node, ad);
                /* Got a match? */
                if (result == 1)
                    break;
            }
        }

        SCAsn1CtxDestroy(ac);
        DetectAsn1Free(ad);

    }

    if (result == 1) {
        printf("Error, bitstring_overflog should not match any node: ");
        result = 0;
    } else {
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1Test05 Ensure that the checks work when they should
 */
static int DetectAsn1Test05(void)
{
    int result = 0;
    /* Match if any of the nodes after offset 0 has a double overflow */
    char str[] = "double_overflow, absolute_offset 0";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_DOUBLE_OVF)
        && ad->absolute_offset == 0
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        /* Let's say tag num 9 (type Real), and encoded as ASCII, with length
         * 257, then we must match */
        uint8_t buf[261];
        /* universal class, primitive type, tag_num = 9 (Data type Real) */
        buf[0] = '\x09';
        /* length, definite form, 2 octets */
        buf[1] = '\x82';
        /* length is the sum of the following octets (257): */
        buf[2] = '\xFE';
        buf[3] = '\x03';

        /* Fill the content of the number */
        uint16_t i = 4;
        for (; i < 257;i++)
            buf[i] = '\x05';

        Asn1Ctx *ac = SCAsn1CtxNew();
        if (ac == NULL)
            return 0;

        uint16_t len = 261;

        SCAsn1CtxInit(ac, buf, len);

        SCAsn1Decode(ac, ac->cur_frame);

        if (ac->cur_frame > 0 || ac->asn1_stack[0]->id.ptr != NULL) {
            /* We spect at least one node */
            uint16_t n_iter = 0;

            for (; n_iter <= ac->cur_frame; n_iter++) {
                Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

                if (node == NULL || node->id.ptr == NULL)
                    continue; /* Should not happen */

                result = DetectAsn1Checks(node, ad);
                /* Got a match? */
                if (result == 1)
                    break;
            }
        }

        SCAsn1CtxDestroy(ac);
        DetectAsn1Free(ad);

    }

    if (result == 0) {
        printf("Error, double_overflow should match the first node: ");
    }

    return result;
}

/**
 * \test DetectAsn1Test06 Ensure that the checks work when they should
 */
static int DetectAsn1Test06(void)
{
    int result = 0;
    /* Match if any of the nodes after offset 0 has a double overflow */
    char str[] = "double_overflow, absolute_offset 0";
    DetectAsn1Data *ad = NULL;

    ad = DetectAsn1Parse(str);
    if (ad != NULL && (ad->flags & ASN1_DOUBLE_OVF)
        && ad->absolute_offset == 0
        && (ad->flags & ASN1_ABSOLUTE_OFFSET))
    {
        /* Let's say tag num 9 (type Real), and encoded as ASCII, with length
         * 256, which fit in the buffer, so it should not match */
        uint8_t buf[260];
        /* universal class, primitive type, tag_num = 9 (Data type Real) */
        buf[0] = '\x09';
        /* length, definite form, 2 octets */
        buf[1] = '\x82';
        /* length is the sum of the following octets (256): */
        buf[2] = '\xFE';
        buf[3] = '\x02';

        /* Fill the content of the number */
        uint16_t i = 4;
        for (; i < 256;i++)
            buf[i] = '\x05';

        Asn1Ctx *ac = SCAsn1CtxNew();
        if (ac == NULL)
            return 0;

        uint16_t len = 260;

        SCAsn1CtxInit(ac, buf, len);

        SCAsn1Decode(ac, ac->cur_frame);

        if (ac->cur_frame > 0 || ac->asn1_stack[0]->id.ptr != NULL) {
            /* We spect at least one node */
            uint16_t n_iter = 0;

            for (; n_iter <= ac->cur_frame; n_iter++) {
                Asn1Node *node = ASN1CTX_GET_NODE(ac, n_iter);

                if (node == NULL || node->id.ptr == NULL)
                    continue; /* Should not happen */

                result = DetectAsn1Checks(node, ad);
                /* Got a match? */
                if (result == 1)
                    break;
            }
        }

        SCAsn1CtxDestroy(ac);
        DetectAsn1Free(ad);

    }

    if (result == 1) {
        printf("Error, double_overflow should not match any node: ");
        result = 0 ;
    } else {
        result = 1;
    }

    return result;
}

/**
 * \test DetectAsn1TestReal01 Ensure that all works together
 */
static int DetectAsn1TestReal01(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Pablo""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen = strlen((char *)buf) - 1;

    /* Check the start with AA (this is to test the relative_offset keyword) */
    uint8_t *buf2 = (uint8_t *) "AA\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen2 = strlen((char *)buf2) - 1;

    Packet *p[2];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf2, buflen2, IPPROTO_TCP);

    if (p[0] == NULL || p[1] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; "
             "content:\"Pablo\"; asn1:absolute_offset 0, "
             "oversize_length 130; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; "
             "content:\"AA\"; asn1:relative_offset 2, "
             "oversize_length 130; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; "
             "content:\"lalala\"; asn1: oversize_length 2000; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[2][3] = {
                              /* packet 0 match sid 1 */
                              {1, 0, 0},
                              /* packet 1 match sid 2 */
                              {0, 1, 0}};
    /* None of the packets should match sid 3 */

    result = UTHGenericTest(p, 2, sigs, sid, (uint32_t *) results, 3);

    UTHFreePackets(p, 2);
end:
    return result;
}

/**
 * \test DetectAsn1TestReal02 Ensure that all works together
 */
static int DetectAsn1TestReal02(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Pablo""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen = strlen((char *)buf) - 1;

    /* Check the start with AA (this is to test the relative_offset keyword) */
    uint8_t *buf2 = (uint8_t *) "AA\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen2 = strlen((char *)buf2) - 1;

    Packet *p[2];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf2, buflen2, IPPROTO_TCP);

    if (p[0] == NULL || p[1] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; "
             "content:\"Pablo\"; asn1:absolute_offset 0, "
             "oversize_length 140; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; "
             "content:\"AA\"; asn1:relative_offset 2, "
             "oversize_length 140; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; "
             "content:\"lalala\"; asn1: oversize_length 2000; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[2][3] = {
                              {0, 0, 0},
                              {0, 0, 0}};
    /* None of the packets should match */

    result = UTHGenericTest(p, 2, sigs, sid, (uint32_t *) results, 3);

    UTHFreePackets(p, 2);
end:
    return result;
}

/**
 * \test DetectAsn1TestReal03 Ensure that all works together
 */
static int DetectAsn1TestReal03(void)
{
    int result = 0;
    uint8_t buf[261] = "";
    /* universal class, primitive type, tag_num = 9 (Data type Real) */
    buf[0] = '\x09';
    /* length, definite form, 2 octets */
    buf[1] = '\x82';
    /* length is the sum of the following octets (257): */
    buf[2] = '\xFE';
    buf[3] = '\x03';

    /* Fill the content of the number */
    uint16_t i = 4;
    for (; i < 257;i++)
        buf[i] = '\x05';

    uint16_t buflen = 261;

    /* Check the start with AA (this is to test the relative_offset keyword) */
    uint8_t *buf2 = (uint8_t *) "AA\x03\x01\xFF";

    uint16_t buflen2 = 5;

    Packet *p[2] = { NULL, NULL };

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf2, buflen2, IPPROTO_TCP);

    if (p[0] == NULL || p[1] == NULL)
        goto end;

    const char *sigs[3];
            /* This should match the first packet */
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; "
             "asn1:absolute_offset 0, double_overflow; sid:1;)";
            /* This should match the second packet */
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; "
             "asn1:relative_offset 2, bitstring_overflow,"
             "oversize_length 140; sid:2;)";
            /* This should match no packet */
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; "
             "asn1: oversize_length 2000; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[2][3] = {{1, 0, 0},
                              {0, 1, 0}};

    result = UTHGenericTest(p, 2, sigs, sid, (uint32_t *) results, 3);

    UTHFreePackets(p, 2);
end:
    return result;
}

/**
 * \test DetectAsn1TestReal04 like the real test 02, but modified the
 *       relative offset to check negative offset values, in this case
 *       start decoding from -7 bytes respect the content match "John"
 */
static int DetectAsn1TestReal04(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *) "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Pablo""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen = strlen((char *)buf) - 1;

    /* Check the start with AA (this is to test the relative_offset keyword) */
    uint8_t *buf2 = (uint8_t *) "AA\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01"
                   "P""\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111"
                   "\x31\x1F\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05"
                   "Jones""\xA0\x0A\x43\x08""19590717"
                   "\x60\x81\x85\x61\x10\x1A\x04""John""\x1A\x01""P"
                   "\x1A\x05""Smith""\xA0\x0A\x1A\x08""Director"
                   "\x42\x01\x33\xA1\x0A\x43\x08""19710917"
                   "\xA2\x12\x61\x10\x1A\x04""Mary""\x1A\x01""T""\x1A\x05"
                   "Smith""\xA3\x42\x31\x1F\x61\x11\x1A\x05""Ralph""\x1A\x01"
                   "T""\x1A\x05""Smith""\xA0\x0A\x43\x08""19571111""\x31\x1F"
                   "\x61\x11\x1A\x05""Susan""\x1A\x01""B""\x1A\x05""Jones"
                   "\xA0\x0A\x43\x08""19590717";

    uint16_t buflen2 = strlen((char *)buf2) - 1;

    Packet *p[2];

    p[0] = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    p[1] = UTHBuildPacket((uint8_t *)buf2, buflen2, IPPROTO_TCP);

    if (p[0] == NULL || p[1] == NULL)
        goto end;

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; "
             "content:\"Pablo\"; asn1:absolute_offset 0, "
             "oversize_length 140; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; "
             "content:\"John\"; asn1:relative_offset -7, "
             "oversize_length 140; sid:2;)";
    sigs[2]= "alert ip any any -> any any (msg:\"Testing id 3\"; "
             "content:\"lalala\"; asn1: oversize_length 2000; sid:3;)";

    uint32_t sid[3] = {1, 2, 3};

    uint32_t results[2][3] = {
                              {0, 0, 0},
                              {0, 0, 0}};
    /* None of the packets should match */

    result = UTHGenericTest(p, 2, sigs, sid, (uint32_t *) results, 3);

    UTHFreePackets(p, 2);
end:
    return result;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectAsn1
 */
static void DetectAsn1RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectAsn1TestParse01", DetectAsn1TestParse01);
    UtRegisterTest("DetectAsn1TestParse02", DetectAsn1TestParse02);
    UtRegisterTest("DetectAsn1TestParse03", DetectAsn1TestParse03);

    UtRegisterTest("DetectAsn1TestParse04", DetectAsn1TestParse04);
    UtRegisterTest("DetectAsn1TestParse05", DetectAsn1TestParse05);
    UtRegisterTest("DetectAsn1TestParse06", DetectAsn1TestParse06);

    UtRegisterTest("DetectAsn1TestParse07", DetectAsn1TestParse07);
    UtRegisterTest("DetectAsn1TestParse08", DetectAsn1TestParse08);
    UtRegisterTest("DetectAsn1TestParse09", DetectAsn1TestParse09);

    UtRegisterTest("DetectAsn1TestParse10", DetectAsn1TestParse10);
    UtRegisterTest("DetectAsn1TestParse11", DetectAsn1TestParse11);
    UtRegisterTest("DetectAsn1TestParse12", DetectAsn1TestParse12);
    UtRegisterTest("DetectAsn1TestParse13", DetectAsn1TestParse13);
    UtRegisterTest("DetectAsn1TestParse14", DetectAsn1TestParse14);
    UtRegisterTest("DetectAsn1TestParse15", DetectAsn1TestParse15);
    UtRegisterTest("DetectAsn1Test01 - oversize_len", DetectAsn1Test01);
    UtRegisterTest("DetectAsn1Test02 - oversize_len", DetectAsn1Test02);
    UtRegisterTest("DetectAsn1Test03 - bitstring_ovf", DetectAsn1Test03);
    UtRegisterTest("DetectAsn1Test04 - bitstring_ovf", DetectAsn1Test04);
    UtRegisterTest("DetectAsn1Test05 - double_ovf", DetectAsn1Test05);
    UtRegisterTest("DetectAsn1Test06 - double_ovf", DetectAsn1Test06);
    UtRegisterTest("DetectAsn1TestReal01", DetectAsn1TestReal01);
    UtRegisterTest("DetectAsn1TestReal02", DetectAsn1TestReal02);
    UtRegisterTest("DetectAsn1TestReal03", DetectAsn1TestReal03);
    UtRegisterTest("DetectAsn1TestReal04", DetectAsn1TestReal04);

#endif /* UNITTESTS */
}
