/* Copyright (C) 2020-2022 Open Information Security Foundation
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
 * Implements "asn1" keyword
 */

#include "suricata-common.h"
#include "decode.h"
#include "rust.h"

#include "detect.h"
#include "detect-parse.h"

#include "flow.h"
#include "detect-asn1.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-byte.h"
#include "util-debug.h"

static int DetectAsn1Match(DetectEngineThreadCtx *, Packet *,
                     const Signature *, const SigMatchCtx *);
static int DetectAsn1Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectAsn1RegisterTests(void);
#endif
static void DetectAsn1Free(DetectEngineCtx *, void *);

/**
 * \brief Registration function for asn1
 */
void DetectAsn1Register(void)
{
    sigmatch_table[DETECT_ASN1].name = "asn1";
    sigmatch_table[DETECT_ASN1].Match = DetectAsn1Match;
    sigmatch_table[DETECT_ASN1].Setup = DetectAsn1Setup;
    sigmatch_table[DETECT_ASN1].Free  = DetectAsn1Free;
#ifdef UNITTESTS
    sigmatch_table[DETECT_ASN1].RegisterTests = DetectAsn1RegisterTests;
#endif
}

/**
 * \brief This function will decode the asn1 data and inspect the resulting
 *        nodes to detect if any of the specified checks match this data
 *
 * \param det_ctx pointer to the detect engine thread context
 * \param p pointer to the current packet
 * \param s pointer to the signature
 * \param ctx pointer to the sigmatch that we will cast into `DetectAsn1Data`
 *
 * \retval 1 match
 * \retval 0 no match
 */
static int DetectAsn1Match(DetectEngineThreadCtx *det_ctx, Packet *p,
                    const Signature *s, const SigMatchCtx *ctx)
{
    uint8_t ret = 0;

    if (p->payload_len == 0) {
        /* No error, parser done, no data in bounds to decode */
        return 0;
    }

    const DetectAsn1Data *ad = (const DetectAsn1Data *)ctx;

    Asn1 *asn1 = rs_asn1_decode(p->payload, p->payload_len, det_ctx->buffer_offset, ad);

    ret = rs_asn1_checks(asn1, ad);

    rs_asn1_free(asn1);

    return ret;
}

/**
 * \brief This function is used to parse asn1 options passed via asn1: keyword
 *
 * \param asn1str pointer to the user provided asn1 options
 *
 * \retval pointer to `DetectAsn1Data` on success
 * \retval NULL on failure
 */
static DetectAsn1Data *DetectAsn1Parse(const char *asn1str)
{
    DetectAsn1Data *ad = rs_detect_asn1_parse(asn1str);

    if (ad == NULL) {
        SCLogError(SC_EINVAL, "Malformed asn1 argument: %s", asn1str);
    }

    return ad;
}

/**
 * \brief this function is used to add the parsed asn1 data into
 *        the current signature
 *
 * \param de_ctx pointer to the detection engine context
 * \param s pointer to the current signature
 * \param asn1str pointer to the user provided asn1 options
 *
 * \retval 0 on success
 * \retval -1 on failure
 */
static int DetectAsn1Setup(DetectEngineCtx *de_ctx, Signature *s, const char *asn1str)
{
    DetectAsn1Data *ad = DetectAsn1Parse(asn1str);
    if (ad == NULL)
        return -1;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectAsn1Free(de_ctx, ad);
        return -1;
    }

    sm->type = DETECT_ASN1;
    sm->ctx = (SigMatchCtx *)ad;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;
}

/**
 * \brief this function will free memory associated with `DetectAsn1Data`
 *
 * \param de_ctx pointer to the detection engine context
 * \param ptr point to `DetectAsn1Data`
 */
static void DetectAsn1Free(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectAsn1Data *ad = (DetectAsn1Data *)ptr;
    rs_detect_asn1_free(ad);
}

#ifdef UNITTESTS

/**
 * \test DetectAsn1TestReal01 Ensure that all works together
 */
static int DetectAsn1TestReal01(void)
{
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
    FAIL_IF_NULL(p[0]);
    p[1] = UTHBuildPacket((uint8_t *)buf2, buflen2, IPPROTO_TCP);
    FAIL_IF_NULL(p[1]);

    const char *sigs[3];
    sigs[0]= "alert ip any any -> any any (msg:\"Testing id 1\"; "
             "content:\"Pablo\"; asn1:absolute_offset 0, "
             "oversize_length 130; sid:1;)";
    sigs[1]= "alert ip any any -> any any (msg:\"Testing id 2\"; "
             "content:\"AA\"; asn1:relative_offset 0, "
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
    FAIL_IF_NOT(UTHGenericTest(p, 2, sigs, sid, (uint32_t *)results, 3) == 1);

    UTHFreePackets(p, 2);
    PASS;
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
             "content:\"AA\"; asn1:relative_offset 0, "
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
    buf[2] = '\x01';
    buf[3] = '\x01';

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
             "content:\"John\"; asn1:relative_offset -11, "
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
 * \brief this function registers unit tests for DetectAsn1
 */
static void DetectAsn1RegisterTests(void)
{
    UtRegisterTest("DetectAsn1TestReal01", DetectAsn1TestReal01);
    UtRegisterTest("DetectAsn1TestReal02", DetectAsn1TestReal02);
    UtRegisterTest("DetectAsn1TestReal03", DetectAsn1TestReal03);
    UtRegisterTest("DetectAsn1TestReal04", DetectAsn1TestReal04);
}
#endif /* UNITTESTS */
