/* Copyright (C) 2020 Open Information Security Foundation
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
 * This file contains the implementation of the xor keyword to decrypt xor data
 * from a buffer and makes it available for the xor_data keyword.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-byte-extract.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-xor.h"
#include "util-byte.h"
#include "util-xor.h"

/** \brief Arbitrary maximum buffer size for decoded xor data. */
#define XOR_DECODE_MAX 65535

static const char decode_pattern[] =
    "^\\s*(?:key\\s+(?:\"([0-9a-fA-F]+)\"|([^\\s,\"]+)))"
    "(?:\\s*,\\s*bytes\\s+(\\d+))?"
    "(?:\\s*,\\s*offset\\s+(\\d+))?"
    "(?:\\s*,\\s*(relative))?"
    "\\s*$";

static DetectParseRegex decode_pcre;

static int g_xor_data_buffer_id = 0;

/** \brief Context for xor match */
typedef struct DetectXor_ {
    uint8_t *key; /** < xor key */
    uint16_t key_len; /** < xor key length */
    int bid; /** < id to get byte_extract variable when used, -1 otherwise */
    uint32_t bytes; /** < number of bytes to decode */
    uint32_t offset; /** < offset from the start of the current match buffer */
    bool relative; /** < makes offset relative to the current buffer offset */
} DetectXor;

static int DetectXorSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectXorFree(DetectEngineCtx *de_ctx, void *ptr);
static void DetectXorRegisterTests(void);

void DetectXorRegister(void)
{
    sigmatch_table[DETECT_XOR].name = "xor";
    sigmatch_table[DETECT_XOR].desc = "Decodes xor encoded data.";
    sigmatch_table[DETECT_XOR].url = "/rules/xor-keywords.html#xor";
    sigmatch_table[DETECT_XOR].Setup = DetectXorSetup;
    sigmatch_table[DETECT_XOR].Free = DetectXorFree;
    sigmatch_table[DETECT_XOR].RegisterTests = DetectXorRegisterTests;
    sigmatch_table[DETECT_XOR].flags |= SIGMATCH_OPTIONAL_OPT;

    /* Register the xor_data buffer now because we will be decoding xor
     * bytes into xor_data's inspect buffer. */
    g_xor_data_buffer_id = DetectBufferTypeRegister("xor_data");

    DetectSetupParseRegexes(decode_pattern, &decode_pcre);
}

/**
 * \brief Capture and xor decode payload data into an inspection buffer.
 *
 *  Captures payload or buffer data during DetectEngineContentInspection()
 *  to decode and place it in xor_data's inspection buffer.
 *
 * \retval 0 no match - if no bytes were placed in the buffer
 * \retval 1 match - if some bytes were placed in the buffer
 */
int DetectXorDoMatch(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchCtx *ctx, const uint8_t *payload, uint32_t payload_len)
{
    DetectXor *data = (DetectXor *) ctx;

    /* copy the key when using a byte_extract variable */
    if (data->bid >= 0) {
        uint64_t value = det_ctx->bj_values[data->bid];

        /* DetectXorParse() will ensure that data->key_len is between 1 and 8
         * (inclusive) when a byte_extract variable is used. */
        for (int i = 0; i < (int) data->key_len; i++) {
            /* Do the opposite of ByteExtract() assuming big endianness. */
            data->key[data->key_len - i - 1] = value >> ((i & 7) << 3);
        }
    }

    /* Adjust the payload according to the offsets */
    if (data->relative) {
        if (det_ctx->buffer_offset >= payload_len) {
            return 0;
        }
        payload += det_ctx->buffer_offset;
        payload_len -= det_ctx->buffer_offset;
    }

    if (data->offset > 0) {
        if (data->offset >= payload_len) {
            return 0;
        }
        payload += data->offset;
        payload_len -= data->offset;
    }

    /* A bytes value of 0 indicates that it may not have been set, so decode
     * until payload_len in that case. */
    if (data->bytes > 0) {
        payload_len = MIN(payload_len, data->bytes);
    }

    /* Makes sure we don't decode more than a fixed upper limit. */
    payload_len = MIN(payload_len, XOR_DECODE_MAX);

    InspectionBuffer *buffer =
            InspectionBufferGet(det_ctx, g_xor_data_buffer_id);

    if (unlikely(buffer == NULL)) {
        return 0;
    }

    InspectionBufferCheckAndExpand(buffer, payload_len);

    if (unlikely(buffer->buf == NULL || (buffer->size < payload_len))) {
        return 0;
    }

    /* Overwrite the contents of the inspection buffer directly. Avoids extra
     * allocations caused by InspectionBufferCopy(). */
    DecodeXor(buffer->buf, payload, payload_len, data->key, data->key_len);

    buffer->inspect = buffer->buf;
    buffer->inspect_len = payload_len;

    return payload_len > 0 ? 1 : 0;
}

/**
 * \brief Parse rule arguments for xor keyword.
 *
 * \param s Signature.
 * \param str Arguments to parse.
 * \param data Where to store the parsed arguments. This will need to be cleaned
 *             up on success or failure.
 *
 * \return 0 on error, 1 on success
 */
static int DetectXorParse(Signature *s, const char *str, DetectXor *data)
{
    static const int max = 30;
    int ov[max];
    int pcre_rc;
    const char *key_str = NULL;
    const char *key_be_str = NULL;
    const char *bytes_str = NULL;
    const char *offset_str = NULL;
    const char *relative_str = NULL;
    int retval = 0;

    pcre_rc = DetectParsePcreExec(&decode_pcre, str, 0, 0, ov, max);

    if (pcre_rc < 1) {
        goto cleanup;
    }

    if (pcre_rc >= 1) {
        int key_len = pcre_get_substring((char *)str, ov, max, 1, &key_str);

        if (key_len > UINT16_MAX) {
            SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                    "Bad value for xor key: %d exceeds max length of %"PRIu16,
                    key_len, UINT16_MAX);
            goto cleanup;
        } else if (key_len > 0) {
            size_t tmp_len = 0;

            data->key = BytesFromHexString(key_str, &tmp_len);
            data->key_len = (uint16_t) tmp_len;

            if (data->key == NULL || data->key_len == 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                    "Bad value for xor key: \"%s\"", key_str);
                goto cleanup;
            }
        }
    }

    if (pcre_rc >= 2) {
        if (pcre_get_substring((char *)str, ov, max, 2, &key_be_str) > 0) {
            SigMatch *bed_sm = DetectByteExtractRetrieveSMVar(key_be_str, s);
            if (bed_sm == NULL) {
                SCLogError(SC_ERR_INVALID_SIGNATURE,
                        "Bad value for xor key: \"%s\". "
                        "Unknown byte_extract variable. "
                        "For literal hex value, surround with double quotes.\n",
                        key_be_str);
                goto cleanup;
            }

            DetectByteExtractData *bed = (DetectByteExtractData *) bed_sm->ctx;

            data->bid = bed->local_id;

            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
                /* bytes were extracted from a string, can't use nbytes to
                 * determine key length so use entire value */
                data->key_len = 8;
            } else {
                /* bytes were extracted directly, use nbytes as key length */
                data->key_len = bed->nbytes;
            }

            if (data->key_len == 0 || data->key_len > 8) {
                SCLogError(SC_ERR_INVALID_SIGNATURE,
                        "Bad value for xor key: \"%s\". "
                        "byte_extract variable length should be between 1 and "
                        "8 but was %"PRIu16".\n",
                        key_str, data->key_len);
                goto cleanup;
            }

            /** \todo improve cache coherence by embedding the key array inside
             * the context struct instead of allocating it. This could work well
             * for short key sizes (i.e. up to 8 bytes) and be represented as a
             * union. This would require us to track when we choose to allocate
             * using a flag. */
            data->key = SCCalloc(data->key_len, sizeof(*data->key));

            if (unlikely(data->key == NULL)) {
                goto cleanup;
            }
        }
    }

    if (data->key == NULL && data->bid < 0) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                "Bad value for xor key: \"%s\". "
                "Expected hex string in double quotes or byte_extract variable.",
                key_str);
        goto cleanup;
    }

     if (pcre_rc >= 3) {
        if (pcre_get_substring((char *)str, ov, max, 3, &bytes_str)) {
            if (StringParseUint32(&data->bytes, 10, 0, bytes_str) <= 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                        "Bad value for xor bytes: \"%s\"", bytes_str);
                goto cleanup;
            }
        }
    }

    if (pcre_rc >= 4) {
        if (pcre_get_substring((char *)str, ov, max, 4, &offset_str)) {
            if (StringParseUint32(&data->offset, 10, 0, offset_str) <= 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                        "Bad value for xor offset: \"%s\"", offset_str);
                goto cleanup;
            }
        }
    }

    if (pcre_rc >= 5) {
        if (pcre_get_substring((char *)str, ov, max, 5, &relative_str)) {
            data->relative = true;
        }
    }

    /* set success and fall through to cleanup */
    retval = 1;

cleanup:
    if (key_str != NULL) {
        pcre_free_substring(key_str);
    }
    if (key_be_str != NULL) {
        pcre_free_substring(key_be_str);
    }
    if (bytes_str != NULL) {
        pcre_free_substring(bytes_str);
    }
    if (offset_str != NULL) {
        pcre_free_substring(offset_str);
    }
    if (relative_str != NULL) {
        pcre_free_substring(relative_str);
    }
    return retval;
}

/**
 * \brief Setup xor keyword match.
 *
 * \param de_ctx Detect engine context.
 * \param s Signature.
 * \param str Keyword arguments.
 *
 * \return 0 on success, -1 on failure
 */
static int DetectXorSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    DetectXor *data = NULL;
    int sm_list;
    SigMatch *sm = NULL;
    SigMatch *pm = NULL;

    data = SCMalloc(sizeof(*data));

    if (unlikely(data == NULL)) {
        goto error;
    }

    data->key = NULL;
    data->key_len = 0;
    data->bid = -1;
    data->bytes = 0;
    data->offset = 0;
    data->relative = 0;

    if (str == NULL) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                "expected arguments for xor keyword");
        goto error;
    }

    if (DetectXorParse(s, str, data) != 1) {
        goto error;
    }

    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        sm_list = s->init_data->list;
    } else {
        pm = DetectGetLastSMFromLists(s,
                DETECT_CONTENT, DETECT_PCRE,
                DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                DETECT_ISDATAAT, -1);
        if (pm == NULL) {
            sm_list = DETECT_SM_LIST_PMATCH;
        } else {
            sm_list = SigMatchListSMBelongsTo(s, pm);
            if (sm_list < 0) {
                goto error;
            }
        }
    }

    sm = SigMatchAlloc();

    if (unlikely(sm == NULL)) {
        goto error;
    }

    sm->type = DETECT_XOR;
    sm->ctx = (SigMatchCtx *)data;
    SigMatchAppendSMToList(s, sm, sm_list);

    return 0;
error:
    if (data != NULL) {
        DetectXorFree(de_ctx, data);
    }
    return -1;
}

/**
 * \brief Cleanup match context for xor data.
 *
 * \param de_ctx Detect engine context.
 * \param ptr Match context data to cleanup.
 *
 */
static void DetectXorFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL) {
        return;
    }

    DetectXor *data = (DetectXor *)ptr;

    if (data->key != NULL) {
        SCFree(data->key);
    }

    SCFree(data);
}

#ifdef UNITTESTS

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int g_http_client_body_buffer_id = 0;

/* Test helper for parsing xor keyword argument failures */
#define TEST_RUN(input)                                 \
    {                                                   \
        DetectXor data = {                              \
            .key = NULL,                                \
            .key_len = 0,                               \
            .bid = -1,                                  \
            .bytes = 0,                                 \
            .offset = 0,                                \
            .relative = false,                          \
        };                                              \
                                                        \
        int ret = DetectXorParse(NULL, input, &data);   \
                                                        \
        if (data.key != NULL) {                         \
            SCFree(data.key);                           \
            data.key = NULL;                            \
        }                                               \
                                                        \
        FAIL_IF(ret == 1);                              \
    }

/**
 * \brief Generates an xor keyword argument for testing
 *
 * \param hex_len number of 'f' hex chars to output
 *
 * \return Newly allocated argument string
 */
static char *DetectXorTestGenerateKeyString(size_t hex_len) {
    char *hex = SCMalloc((hex_len + 1) * sizeof(*hex));
    size_t key_size = hex_len + strlen("key \"\"") + 1;
    char *key = SCMalloc(key_size * sizeof(*key));

    if (hex == NULL || key == NULL) {
        goto error;
    }

    memset(hex, 'f', hex_len * sizeof(*hex));
    hex[hex_len] = '\0';

    if ((int) key_size - 1 == snprintf(key, key_size, "key \"%s\"", hex)) {
        /* jump over error on success */
        goto cleanup;
    }

error:
    if (key) {
        SCFree(key);
        key = NULL;
    }
    /* fall through to cleanup and return NULL */

cleanup:
    if (hex) {
        SCFree(hex);
    }

    return key;
}

/** \test Detect xor invalid rule keyword arguments */
static int DetectXorParseTestInvalid(void)
{
    /* empty string */
    TEST_RUN("");
    /* invalid chars */
    TEST_RUN("random chars");

    /* missing key value */
    TEST_RUN("key");
    TEST_RUN("key ");
    /* invalid key value */
    TEST_RUN("key \"\"");
    TEST_RUN("key \"invalid\"");
    TEST_RUN("key \"0\"");

    /* missing bytes value */
    TEST_RUN("key \"01\", bytes");
    /* invalid bytes value */
    TEST_RUN("key \"01\", bytes -1");

    /* missing offset */
    TEST_RUN("key \"01\", bytes 100, offset");
    /* invalid offset value */
    TEST_RUN("key \"01\", bytes 100, offset -1");

    /* invalid chars at the end */
    TEST_RUN("key \"01\", bytes 100, offset 0, other");

    /* arguments are out of order */
    TEST_RUN("key \"01\", offset 100, bytes 100");

    /* commas are required */
    TEST_RUN("key \"01\" bytes 100");
    TEST_RUN("key \"01\" bytes 100 offset 10");
    TEST_RUN("key \"01\" bytes 100 offset 10 relative");

    /* test key hex string max value */
    {
        /* UINT16_MAX is an odd number so it will fail */
        char *key = DetectXorTestGenerateKeyString(UINT16_MAX);
        FAIL_IF(key == NULL);
        TEST_RUN(key);
        SCFree(key);
    }

    {
        /* Test next even value that exceeds maximum */
        char *key = DetectXorTestGenerateKeyString(UINT16_MAX + 1);
        FAIL_IF(key == NULL);
        TEST_RUN(key);
        SCFree(key);
    }

    /* Test one over max values of UINT32_MAX */
    TEST_RUN("key \"01\", bytes 4294967296");
    TEST_RUN("key \"01\", offset 4294967296");

    PASS;
}

#undef TEST_RUN

/**
 * \brief Test runner for xor parse success
 *
 * \param input keyword arguments
 * \param exp_bytes expected bytes value
 * \param exp_offset expected offset value
 * \param exp_relative expected relative value
 * \param exp_key expected key value
 * \param exp_key_len expected key length
 *
 * \return 1 on success, 0 on failure
 */
static int DetectXorParseTestValidRun(const char *input,
        uint32_t exp_bytes, uint32_t exp_offset, bool exp_relative,
        uint8_t *exp_key, uint16_t exp_key_len)
{
    DetectXor data = {
        .key = NULL,
        .key_len = 0,
        .bid = -1,
        .bytes = 0,
        .offset = 0,
        .relative = false,
    };

    int ret = DetectXorParse(NULL, input, &data);

    FAIL_IF(ret != 1);

    FAIL_IF(data.key_len != exp_key_len);
    FAIL_IF(0 != memcmp(data.key, exp_key, exp_key_len));
    FAIL_IF(-1 != data.bid);
    FAIL_IF(data.bytes != exp_bytes);
    FAIL_IF(data.offset != exp_offset);
    FAIL_IF(data.relative != exp_relative);

    if (data.key != NULL) {
        SCFree(data.key);
    }

    PASS;
}

/* Test helper for parsing xor keyword argument successes */
#define TEST_RUN(input, exp_bytes, exp_offset, exp_relative, exp_key_init...)  \
    {                                                                          \
        uint8_t exp_key[] = { exp_key_init };                                  \
        size_t exp_key_len = sizeof(exp_key) / sizeof(*exp_key);               \
                                                                               \
        FAIL_IF_NOT(DetectXorParseTestValidRun(input, exp_bytes, exp_offset,   \
        exp_relative, exp_key, exp_key_len));                                  \
    }

/** \test Detect xor valid rule keyword arguments */
static int DetectXorParseTestValid(void)
{
    /* test full hex range */
    TEST_RUN("key \"0123456789abcdefABCDEF\"", 0, 0, false,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xAB, 0xCD, 0xEF);

    /* test options */
    TEST_RUN("key \"01\", bytes 100", 100, 0, false, 0x01);
    TEST_RUN("key \"01\", offset 10", 0, 10, false, 0x01);
    TEST_RUN("key \"01\", relative", 0, 0, true, 0x01);
    TEST_RUN("key \"01\", bytes 100, offset 10", 100, 10, false, 0x01);
    TEST_RUN("key \"01\", bytes 100, offset 10, relative", 100, 10, true, 0x01);

    /* test optional whitespace */
    TEST_RUN("key \"01\",bytes 100,offset 10,relative", 100, 10, true, 0x01);
    TEST_RUN("  key \"01\"  ,  bytes  100  ,  offset  10  ,  relative", 100, 10,
            true, 0x01);

    /* test max key hex string value: UINT16_MAX - 1 is the closest even number
     * to the max value. */
    {
        uint16_t key_len = UINT16_MAX - 1;
        char *key = DetectXorTestGenerateKeyString(key_len);

        uint16_t exp_len = key_len / 2;
        uint8_t *exp = SCMalloc(exp_len * sizeof(*exp));

        FAIL_IF(key == NULL || exp == NULL);

        memset(exp, 0xff, exp_len * sizeof(*exp));
        DetectXorParseTestValidRun(key, 0, 0, false, exp, exp_len);

        SCFree(exp);
        SCFree(key);
    }

    /* test max values */
    TEST_RUN("key \"01\", bytes 4294967295", UINT32_MAX, 0, false, 0x01);
    TEST_RUN("key \"01\", offset 4294967295", 0, UINT32_MAX, false, 0x01);

    PASS;
}

#undef TEST_RUN

/** \brief Helper function for testing xor setup */
static int DetectXorTestSetupFailureRun(const char *rule)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list != NULL);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/**
 * \brief Helper function for testing xor setup
 *
 * \param rule Rule keywords to test.
 * \param exp_pmatch Expect pmatch not to be NULL.
 * \param exp_buf_id Expect a sticky buffer list id not to be NULL.
 *
 * \return 1 on success, 0 on failure
 */
static int DetectXorTestSetupRun(const char *rule, bool exp_pmatch, int exp_buf_id)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list == NULL);

    if (exp_pmatch) {
        FAIL_IF(de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL);
    } else {
        FAIL_IF(de_ctx->sig_list->sm_lists_tail[DETECT_SM_LIST_PMATCH] != NULL);
    }

    if (exp_buf_id >= 0) {
        FAIL_IF(de_ctx->sig_list->sm_lists_tail[exp_buf_id] == NULL);
    }

    DetectEngineCtxFree(de_ctx);

    PASS;
}

/** \test Test xor setup failure conditions */
static int DetectXorTestSetupFailure(void)
{
    FAIL_IF_NOT(DetectXorTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"xor with no argument\";"
            "xor;"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"xor with invalid key length\";"
            "xor: key \"0\";"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"xor with missing byte_extract variable for key\";"
            "xor: key my_var;"
            "sid:1; rev:1;)"));

    FAIL_IF_NOT(DetectXorTestSetupFailureRun(
            "alert tcp any any -> any any ("
            "msg:\"xor with byte_extract zero length for key\";"
            "byte_extract: 0, 0, my_var;"
            "xor: key my_var;"
            "sid:1; rev:1;)"));

    PASS;
}

/** \test Detect xor test setup success on payload match */
static int DetectXorTestSetup(void)
{
    FAIL_IF_NOT(DetectXorTestSetupRun(
            "alert tcp any any -> any any ("
            "msg:\"xor setup success with payload match\"; "
            "xor: key \"01\"; "
            "sid:1; rev:1;)",
            true, -1));

    FAIL_IF_NOT(DetectXorTestSetupRun(
            "alert tcp any any -> any any ("
            "msg:\"xor setup success with content modifier\"; "
            "http.request_body; "
            "xor: key \"01\"; "
            "sid:1; rev:1;)",
            false, g_http_client_body_buffer_id));

    FAIL_IF_NOT(DetectXorTestSetupRun(
            "alert tcp any any -> any any ("
            "msg:\"xor setup success with byte_extract for key\";"
            "byte_extract: 4, 0, my_var;"
            "xor: key my_var;"
            "sid:1; rev:1;)",
            true, -1));

    PASS;
}

/**
 * \brief Test helper for checking decoded xor_data buffer.
 *
 * \param rule Rule to parse and load.
 * \param payload Data to decode.
 * \param payload_len Length of data to decode.
 * \param exp Decoded data to expect.
 * \param exp_len Length of decoded data to expect.
 *
 * \return 1 on success, 0 on failure.
 */
static int DetectXorTestDecodeRun(
        const char *rule,
        uint8_t *payload, size_t payload_len,
        uint8_t *exp, size_t exp_len)
{
    ThreadVars tv = {0};
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;

    FAIL_IF(de_ctx == NULL);

    de_ctx->sig_list = SigInit(de_ctx, rule);

    FAIL_IF(de_ctx->sig_list == NULL);
    FAIL_IF(-1 == SigGroupBuild(de_ctx));
    FAIL_IF(TM_ECODE_OK !=
            DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx));

    p = UTHBuildPacket(payload, payload_len, IPPROTO_TCP);
    FAIL_IF(p == NULL);

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, g_xor_data_buffer_id);
    FAIL_IF(buffer == NULL);

    FAIL_IF(buffer->size < exp_len);
    FAIL_IF(buffer->inspect_len != exp_len);
    FAIL_IF(0 != memcmp(buffer->buf, exp, exp_len));

    /* no alerts should occur without the xor_data keyword */
    FAIL_IF_NOT(p->alerts.cnt == 0);

    /* cleanup */
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    StatsThreadCleanup(&tv);
    DetectEngineCtxFree(de_ctx);
    UTHFreePacket(p);

    PASS;
}

/** \test Test cases for decoded xor data. */
static int DetectXorTestDecode(void)
{
    /* input payload data - randomly generated bytes */
    UTH_DECL_BUF(payload, 0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c);

    /* expected result for decoding entire payload */
    UTH_DECL_BUF(exp_full,
            0xce ^ 0xb2, 0x07 ^ 0x25, 0xd4 ^ 0x9a,
            0x47 ^ 0xb2, 0x5d ^ 0x25, 0x51 ^ 0x9a,
            0x4a ^ 0xb2, 0x4c ^ 0x25);

    /* expected result for first 4 bytes of payload */
    UTH_DECL_BUF(exp_0_to_3,
            0xce ^ 0xb2, 0x07 ^ 0x25, 0xd4 ^ 0x9a,
            0x47 ^ 0xb2);

    /* expected result for decoding payload[2] to payload[6] inclusive */
    UTH_DECL_BUF(exp_2_to_6,
            0xd4 ^ 0xb2, 0x47 ^ 0x25, 0x5d ^ 0x9a,
            0x51 ^ 0xb2, 0x4a ^ 0x25);

    /* expected result for decoding payload[3] to payload[7] inclusive */
    UTH_DECL_BUF(exp_3_to_7,
            0x47 ^ 0xb2, 0x5d ^ 0x25, 0x51 ^ 0x9a,
            0x4a ^ 0xb2, 0x4c ^ 0x25);

    /* expected result for decoding payload[4] to payload[6] inclusive */
    UTH_DECL_BUF(exp_4_to_6, 0x5d ^ 0xb2, 0x51 ^ 0x25, 0x4a ^ 0x9a);

    /* expected result for decoding payload[4] to payload[7] inclusive */
    UTH_DECL_BUF(exp_4_to_7,
            0x5d ^ 0xb2, 0x51 ^ 0x25, 0x4a ^ 0x9a,
            0x4c ^ 0xb2);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test empty payload\";"
            "xor: key \"b2259a\";"
            "sid:1; rev:1;)",
            NULL, 0,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with no args\";"
            "xor: key \"b2259a\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_full, exp_full_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with bytes specified\";"
            "xor: key \"b2259a\", bytes 4;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_0_to_3, exp_0_to_3_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with bytes out of range\";"
            "xor: key \"b2259a\", bytes 100;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_full, exp_full_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with offset in range\";"
            "xor: key \"b2259a\", offset 4;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_4_to_7, exp_4_to_7_len));


    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with offset at payload length\";"
            "xor: key \"b2259a\", offset 8;"
            "sid:1; rev:1;)",
            payload, payload_len,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with offset past payload length\";"
            "xor: key \"b2259a\", offset 10;"
            "sid:1; rev:1;)",
            payload, payload_len,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with relative offset at payload length\";"
            "content: \"|ce 07 d4 47|\";"
            "xor: key \"b2259a\", offset 4, relative;"
            "sid:1; rev:1;)",
            payload, payload_len,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with relative offset past payload length\";"
            "content: \"|ce 07 d4 47|\";"
            "xor: key \"b2259a\", offset 5, relative;"
            "sid:1; rev:1;)",
            payload, payload_len,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with bytes and offset in range\";"
            "xor: key \"b2259a\", bytes 5, offset 2;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_2_to_6, exp_2_to_6_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test with relative match\";"
            "content: \"|ce 07 d4|\";"
            "xor: key \"b2259a\", relative;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_3_to_7, exp_3_to_7_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test relative match with byte and offset\";"
            "content: \"|ce 07|\";"
            "xor: key \"b2259a\", bytes 3, offset 2, relative;"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_4_to_6, exp_4_to_6_len));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test relative match with byte and offset out of range values\";"
            "content: \"|ce 07 d4 47 5d 51 4a 4c|\";"
            "xor: key \"b2259a\", bytes 1000, offset 1000, relative;"
            "sid:1; rev:1;)",
            payload, payload_len,
            NULL, 0));

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test absolute match will ignore previous content match\";"
            "content: \"|ce 07 d4 47 5d 51 4a 4c|\";"
            "xor: key \"b2259a\";"
            "sid:1; rev:1;)",
            payload, payload_len,
            exp_full, exp_full_len));

    UTH_DECL_BUF(payload1,
            /* random bytes to ignore */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            /* indicates xor key will follow */
            0xbe, 0xef,
            /* use this 1 byte extract as the xor key */
            0xb2,
            /* use this data to decode */
            0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c,
            /* random bytes to ignore */
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04);

    /* expected result of decoding data shown above */
    UTH_DECL_BUF(exp_full_key_1,
            0xce ^ 0xb2, 0x07 ^ 0xb2, 0xd4 ^ 0xb2,
            0x47 ^ 0xb2, 0x5d ^ 0xb2, 0x51 ^ 0xb2,
            0x4a ^ 0xb2, 0x4c ^ 0xb2);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test using xor key from byte extract min length\";"
            "content: \"|be ef|\";"
            "byte_extract: 1, 0, xor_key, relative;"
            "xor: key xor_key, bytes 8, relative;"
            "sid:1; rev:1;)",
            payload1, payload1_len,
            exp_full_key_1, exp_full_key_1_len));

    UTH_DECL_BUF(payload2,
            /* random bytes to ignore */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            /* indicates xor key will follow */
            0xbe, 0xef,
            /* use this 3 byte extract as the xor key */
            0xb2, 0x25, 0x9a,
            /* use this data to decode */
            0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c,
            /* random bytes to ignore */
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test using xor key from byte extract length in range\";"
            "content: \"|be ef|\";"
            "byte_extract: 3, 0, xor_key, relative;"
            "xor: key xor_key, bytes 8, relative;"
            "sid:1; rev:1;)",
            payload2, payload2_len,
            exp_full, exp_full_len));


    UTH_DECL_BUF(payload3,
            /* random bytes to ignore */
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            /* indicates xor key will follow */
            0xbe, 0xef,
            /* use this 8 byte extract as the xor key */
            0xb2, 0x25, 0x9a, 0x23, 0x35, 0xbe, 0xa8, 0xa7,
            /* use this data to decode */
            0xce, 0x07, 0xd4, 0x47, 0x5d, 0x51, 0x4a, 0x4c,
            /* random bytes to ignore */
            0x01, 0x02, 0x03, 0x04, 0x01, 0x02, 0x03, 0x04);

    /* expected result of decoding data shown above */
    UTH_DECL_BUF(exp_full_key_8,
            0xce ^ 0xb2, 0x07 ^ 0x25, 0xd4 ^ 0x9a,
            0x47 ^ 0x23, 0x5d ^ 0x35, 0x51 ^ 0xbe,
            0x4a ^ 0xa8, 0x4c ^ 0xa7);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test using xor key from byte extract max length\";"
            "content: \"|be ef|\";"
            "byte_extract: 8, 0, xor_key, relative;"
            "xor: key xor_key, bytes 8, relative;"
            "sid:1; rev:1;)",
            payload3, payload3_len,
            exp_full_key_8, exp_full_key_8_len));

    /* expected result of decoding data in payload2 */
    UTH_DECL_BUF(exp_full_key_little,
            0xce ^ 0x9a, 0x07 ^ 0x25, 0xd4 ^ 0xb2,
            0x47 ^ 0x9a, 0x5d ^ 0x25, 0x51 ^ 0xb2,
            0x4a ^ 0x9a, 0x4c ^ 0x25);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test using xor key from little endian byte extract\";"
            "content: \"|be ef|\";"
            "byte_extract: 3, 0, xor_key, relative, little;"
            "xor: key xor_key, bytes 8, relative;"
            "sid:1; rev:1;)",
            payload2, payload2_len,
            exp_full_key_little, exp_full_key_little_len));

    /* short payload */
    UTH_DECL_BUF(payload4, 0xce);

    /* expected result for decoding first byte */
    UTH_DECL_BUF(exp_one_byte, 0xce ^ 0xb2);

    FAIL_IF_NOT(DetectXorTestDecodeRun(
            "alert tcp any any -> any any ("
            "msg:\"test payload length smaller than key\";"
            "xor: key \"b2259a\";"
            "sid:1; rev:1;)",
            payload4, payload4_len,
            exp_one_byte, exp_one_byte_len));

    PASS;
}

#endif /* UNITTESTS */

static void DetectXorRegisterTests(void)
{

#ifdef UNITTESTS

    g_http_client_body_buffer_id = DetectBufferTypeGetByName("http_client_body");

    UtRegisterTest("DetectXorParseTestInvalid", DetectXorParseTestInvalid);
    UtRegisterTest("DetectXorParseTestValid", DetectXorParseTestValid);
    UtRegisterTest("DetectXorTestSetupFailure", DetectXorTestSetupFailure);
    UtRegisterTest("DetectXorTestSetup", DetectXorTestSetup);
    UtRegisterTest("DetectXorTestDecode", DetectXorTestDecode);

#endif /* UNITTESTS */

}
