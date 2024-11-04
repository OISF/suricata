/* Copyright (C) 2020-2024 Open Information Security Foundation
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

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-base64-decode.h"
#include "util-byte.h"
#include "util-print.h"
#include "detect-engine-build.h"
#include "rust.h"

/* Arbitrary maximum buffer size for decoded base64 data. */
#define BASE64_DECODE_MAX 65535

typedef struct DetectBase64Decode_ {
    uint32_t bytes;
    uint32_t offset;
    uint8_t relative;
} DetectBase64Decode;

static const char decode_pattern[] = "\\s*(bytes\\s+(\\d+),?)?"
    "\\s*(offset\\s+(\\d+),?)?"
    "\\s*(\\w+)?";

static DetectParseRegex decode_pcre;

static int DetectBase64DecodeSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectBase64DecodeFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectBase64DecodeRegisterTests(void);
#endif

void DetectBase64DecodeRegister(void)
{
    sigmatch_table[DETECT_BASE64_DECODE].name = "base64_decode";
    sigmatch_table[DETECT_BASE64_DECODE].desc =
        "Decodes base64 encoded data.";
    sigmatch_table[DETECT_BASE64_DECODE].url =
        "/rules/base64-keywords.html#base64-decode";
    sigmatch_table[DETECT_BASE64_DECODE].Setup = DetectBase64DecodeSetup;
    sigmatch_table[DETECT_BASE64_DECODE].Free = DetectBase64DecodeFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BASE64_DECODE].RegisterTests =
        DetectBase64DecodeRegisterTests;
#endif
    sigmatch_table[DETECT_BASE64_DECODE].flags |= SIGMATCH_OPTIONAL_OPT;

    DetectSetupParseRegexes(decode_pattern, &decode_pcre);
}

int DetectBase64DecodeDoMatch(DetectEngineThreadCtx *det_ctx, const Signature *s,
    const SigMatchData *smd, const uint8_t *payload, uint32_t payload_len)
{
    DetectBase64Decode *data = (DetectBase64Decode *)smd->ctx;

#if 0
    printf("Input data:\n");
    PrintRawDataFp(stdout, payload, payload_len);
#endif

    if (data->relative) {
        payload += det_ctx->buffer_offset;
        DEBUG_VALIDATE_BUG_ON(det_ctx->buffer_offset > payload_len);
        payload_len -= det_ctx->buffer_offset;
    }

    if (data->offset) {
        if (data->offset >= payload_len) {
            return 0;
        }
        payload = payload + data->offset;
        payload_len -= data->offset;
    }

    uint32_t decode_len = MIN(payload_len, data->bytes);
#if 0
    printf("Decoding:\n");
    PrintRawDataFp(stdout, payload, decode_len);
#endif

    if (decode_len > 0) {
        uint32_t num_decoded =
                Base64Decode(payload, decode_len, Base64ModeRFC4648, det_ctx->base64_decoded);
        det_ctx->base64_decoded_len = num_decoded;
        SCLogDebug("Decoded %d bytes from base64 data.", det_ctx->base64_decoded_len);
    }
#if 0
    if (det_ctx->base64_decoded_len) {
        printf("Decoded data:\n");
        PrintRawDataFp(stdout, det_ctx->base64_decoded,
            det_ctx->base64_decoded_len);
    }
#endif

    return det_ctx->base64_decoded_len > 0;
}

static int DetectBase64DecodeParse(const char *str, uint32_t *bytes,
    uint32_t *offset, uint8_t *relative)
{
    const char *bytes_str = NULL;
    const char *offset_str = NULL;
    const char *relative_str = NULL;
    int retval = 0;

    *bytes = 0;
    *offset = 0;
    *relative = 0;
    size_t pcre2_len;
    pcre2_match_data *match = NULL;

    int pcre_rc = DetectParsePcreExec(&decode_pcre, &match, str, 0, 0);
    if (pcre_rc < 3) {
        goto error;
    }

    if (pcre_rc >= 3) {
        if (pcre2_substring_get_bynumber(match, 2, (PCRE2_UCHAR8 **)&bytes_str, &pcre2_len) == 0) {
            if (StringParseUint32(bytes, 10, 0, bytes_str) <= 0) {
                SCLogError("Bad value for bytes: \"%s\"", bytes_str);
                goto error;
            }
        }
     }

    if (pcre_rc >= 5) {
        if (pcre2_substring_get_bynumber(match, 4, (PCRE2_UCHAR8 **)&offset_str, &pcre2_len) == 0) {
            if (StringParseUint32(offset, 10, 0, offset_str) <= 0) {
                SCLogError("Bad value for offset: \"%s\"", offset_str);
                goto error;
            }
        }
    }

    if (pcre_rc >= 6) {
        if (pcre2_substring_get_bynumber(match, 5, (PCRE2_UCHAR8 **)&relative_str, &pcre2_len) ==
                0) {
            if (strcmp(relative_str, "relative") == 0) {
                *relative = 1;
            }
            else {
                SCLogError("Invalid argument: \"%s\"", relative_str);
                goto error;
            }
        }
    }

    retval = 1;

    pcre2_match_data_free(match);
    match = NULL;

error:

    if (bytes_str != NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)bytes_str);
    }
    if (offset_str != NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)offset_str);
    }
    if (relative_str != NULL) {
        pcre2_substring_free((PCRE2_UCHAR8 *)relative_str);
    }
    if (match) {
        pcre2_match_data_free(match);
    }
    return retval;
}

static int DetectBase64DecodeSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    uint32_t bytes = 0;
    uint32_t offset = 0;
    uint8_t relative = 0;
    DetectBase64Decode *data = NULL;
    int sm_list;
    SigMatch *pm = NULL;

    if (str != NULL) {
        if (!DetectBase64DecodeParse(str, &bytes, &offset, &relative)) {
            goto error;
        }
    }
    data = SCCalloc(1, sizeof(DetectBase64Decode));
    if (unlikely(data == NULL)) {
        goto error;
    }
    data->bytes = bytes;
    data->offset = offset;
    data->relative = relative;

    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        sm_list = s->init_data->list;
    }
    else {
        pm = DetectGetLastSMFromLists(s,
                DETECT_CONTENT, DETECT_PCRE,
                DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                DETECT_ISDATAAT, -1);
        if (pm == NULL) {
            sm_list = DETECT_SM_LIST_PMATCH;
        }
        else {
            sm_list = SigMatchListSMBelongsTo(s, pm);
            if (sm_list < 0) {
                goto error;
            }
        }
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_BASE64_DECODE, (SigMatchCtx *)data, sm_list) ==
            NULL) {
        goto error;
    }

    if (!data->bytes) {
        data->bytes = BASE64_DECODE_MAX;
    }
    if (data->bytes > de_ctx->base64_decode_max_len) {
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
        data->bytes = BASE64_DECODE_MAX;
#endif
        de_ctx->base64_decode_max_len = data->bytes;
    }

    return 0;
error:
    if (data != NULL) {
        SCFree(data);
    }
    return -1;
}

static void DetectBase64DecodeFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectBase64Decode *data = ptr;
    SCFree(data);
}


#ifdef UNITTESTS
#include "detect-engine.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "flow-util.h"
#include "stream-tcp.h"

static int g_http_header_buffer_id = 0;

static int DetectBase64TestDecodeParse(void)
{
    int retval = 0;
    uint32_t bytes = 0;
    uint32_t offset = 0;
    uint8_t relative = 0;

    if (!DetectBase64DecodeParse("bytes 1", &bytes, &offset, &relative)) {
        goto end;
    }
    if (bytes != 1 || offset != 0 || relative != 0) {
        goto end;
    }

    if (!DetectBase64DecodeParse("offset 9", &bytes, &offset, &relative)) {
        goto end;
    }
    if (bytes != 0 || offset != 9 || relative != 0) {
        goto end;
    }

    if (!DetectBase64DecodeParse("relative", &bytes, &offset, &relative)) {
        goto end;
    }
    if (bytes != 0 || offset != 0 || relative != 1) {
        goto end;
    }

    if (!DetectBase64DecodeParse("bytes 1, offset 2", &bytes, &offset,
            &relative)) {
        goto end;
    }
    if (bytes != 1 || offset != 2 || relative != 0) {
        goto end;
    }

    if (!DetectBase64DecodeParse("bytes 1, offset 2, relative", &bytes, &offset,
            &relative)) {
        goto end;
    }
    if (bytes != 1 || offset != 2 || relative != 1) {
        goto end;
    }

    if (!DetectBase64DecodeParse("offset 2, relative", &bytes, &offset,
            &relative)) {
        goto end;
    }
    if (bytes != 0 || offset != 2 || relative != 1) {
        goto end;
    }

    /* Misspelled relative. */
    if (DetectBase64DecodeParse("bytes 1, offset 2, relatve", &bytes, &offset,
            &relative)) {
        goto end;
    }

    /* Misspelled bytes. */
    if (DetectBase64DecodeParse("byts 1, offset 2, relatve", &bytes, &offset,
            &relative)) {
        goto end;
    }

    /* Misspelled offset. */
    if (DetectBase64DecodeParse("bytes 1, offst 2, relatve", &bytes, &offset,
            &relative)) {
        goto end;
    }

    /* Misspelled empty string. */
    if (DetectBase64DecodeParse("", &bytes, &offset, &relative)) {
        goto end;
    }

    retval = 1;
end:
    return retval;
}

/**
 * Test keyword setup on basic content.
 */
static int DetectBase64DecodeTestSetup(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                                 "base64_decode; content:\"content\"; "
                                                 "sid:1; rev:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectBase64DecodeTestDecode(void)
{
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;
    int retval = 0;

    uint8_t payload[] = {
        'S', 'G', 'V', 's', 'b', 'G', '8', 'g',
        'V', '2', '9', 'y', 'b', 'G', 'Q', '=',
    };

    memset(&tv, 0, sizeof(tv));

    if ((de_ctx = DetectEngineCtxInit()) == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any (msg:\"base64 test\"; "
        "base64_decode; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);
    if (p == NULL) {
        goto end;
    }

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (det_ctx->base64_decoded_len == 0) {
        goto end;
    }

    retval = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    if (p != NULL) {
        UTHFreePacket(p);
    }
    return retval;
}

static int DetectBase64DecodeTestDecodeWithOffset(void)
{
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;
    int retval = 0;

    uint8_t payload[] = {
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'S', 'G', 'V', 's', 'b', 'G', '8', 'g',
        'V', '2', '9', 'y', 'b', 'G', 'Q', '=',
    };
    char decoded[] = "Hello World";

    memset(&tv, 0, sizeof(tv));

    if ((de_ctx = DetectEngineCtxInit()) == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any (msg:\"base64 test\"; "
        "base64_decode: offset 8; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);
    if (p == NULL) {
        goto end;
    }

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (det_ctx->base64_decoded_len != (int)strlen(decoded)) {
        goto end;
    }
    if (memcmp(det_ctx->base64_decoded, decoded, strlen(decoded))) {
        goto end;
    }

    retval = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    if (p != NULL) {
        UTHFreePacket(p);
    }
    return retval;
}

static int DetectBase64DecodeTestDecodeLargeOffset(void)
{
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;
    int retval = 0;

    uint8_t payload[] = {
        'S', 'G', 'V', 's', 'b', 'G', '8', 'g',
        'V', '2', '9', 'y', 'b', 'G', 'Q', '=',
    };

    memset(&tv, 0, sizeof(tv));

    if ((de_ctx = DetectEngineCtxInit()) == NULL) {
        goto end;
    }

    /* Offset is out of range. */
    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any (msg:\"base64 test\"; "
        "base64_decode: bytes 16, offset 32; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);
    if (p == NULL) {
        goto end;
    }

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (det_ctx->base64_decoded_len != 0) {
        goto end;
    }

    retval = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    if (p != NULL) {
        UTHFreePacket(p);
    }
    return retval;
}

static int DetectBase64DecodeTestDecodeRelative(void)
{
    ThreadVars tv;
    DetectEngineCtx *de_ctx = NULL;
    DetectEngineThreadCtx *det_ctx = NULL;
    Packet *p = NULL;
    int retval = 0;

    uint8_t payload[] = {
        'a', 'a', 'a', 'a', 'a', 'a', 'a', 'a',
        'S', 'G', 'V', 's', 'b', 'G', '8', 'g',
        'V', '2', '9', 'y', 'b', 'G', 'Q', '=',
    };
    char decoded[] = "Hello World";

    memset(&tv, 0, sizeof(tv));

    if ((de_ctx = DetectEngineCtxInit()) == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any (msg:\"base64 test\"; "
        "content:\"aaaaaaaa\"; "
        "base64_decode: relative; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);

    p = UTHBuildPacket(payload, sizeof(payload), IPPROTO_TCP);
    if (p == NULL) {
        goto end;
    }

    SigMatchSignatures(&tv, de_ctx, det_ctx, p);
    if (det_ctx->base64_decoded_len != (int)strlen(decoded)) {
        goto end;
    }
    if (memcmp(det_ctx->base64_decoded, decoded, strlen(decoded))) {
        goto end;
    }

    retval = 1;
end:
    if (det_ctx != NULL) {
        DetectEngineThreadCtxDeinit(&tv, det_ctx);
    }
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    if (p != NULL) {
        UTHFreePacket(p);
    }
    return retval;
}

static void DetectBase64DecodeRegisterTests(void)
{
    g_http_header_buffer_id = DetectBufferTypeGetByName("http_header");

    UtRegisterTest("DetectBase64TestDecodeParse", DetectBase64TestDecodeParse);
    UtRegisterTest("DetectBase64DecodeTestSetup", DetectBase64DecodeTestSetup);
    UtRegisterTest("DetectBase64DecodeTestDecode",
                   DetectBase64DecodeTestDecode);
    UtRegisterTest("DetectBase64DecodeTestDecodeWithOffset",
                   DetectBase64DecodeTestDecodeWithOffset);
    UtRegisterTest("DetectBase64DecodeTestDecodeLargeOffset",
                   DetectBase64DecodeTestDecodeLargeOffset);
    UtRegisterTest("DetectBase64DecodeTestDecodeRelative",
                   DetectBase64DecodeTestDecodeRelative);
}
#endif /* UNITTESTS */
