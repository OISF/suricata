/* Copyright (C) 2015 Open Information Security Foundation
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
#include "util-base64.h"
#include "util-byte.h"
#include "util-print.h"

/* Arbitrary maximum buffer size for decoded base64 data. */
#define BASE64_DECODE_MAX 65535

static const char decode_pattern[] = "\\s*(bytes\\s+(\\d+),?)?"
    "\\s*(offset\\s+(\\d+),?)?"
    "\\s*(\\w+)?";
static pcre *decode_pcre = NULL;
static pcre_extra *decode_pcre_study = NULL;

static int DetectBase64DecodeSetup(DetectEngineCtx *, Signature *, char *);
static void DetectBase64DecodeFree(void *);
static void DetectBase64DecodeRegisterTests(void);

void DetectBase64DecodeRegister(void)
{
    const char *pcre_errptr;
    int pcre_erroffset;

    sigmatch_table[DETECT_BASE64_DECODE].name = "base64_decode";
    sigmatch_table[DETECT_BASE64_DECODE].desc =
        "Decodes base64 encoded data.";
    sigmatch_table[DETECT_BASE64_DECODE].url =
        "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Payload_keywords#base64_decode";
    sigmatch_table[DETECT_BASE64_DECODE].Setup = DetectBase64DecodeSetup;
    sigmatch_table[DETECT_BASE64_DECODE].Free = DetectBase64DecodeFree;
    sigmatch_table[DETECT_BASE64_DECODE].RegisterTests =
        DetectBase64DecodeRegisterTests;

    sigmatch_table[DETECT_BASE64_DECODE].flags |= SIGMATCH_PAYLOAD;
    sigmatch_table[DETECT_BASE64_DECODE].flags |= SIGMATCH_OPTIONAL_OPT;

    decode_pcre = pcre_compile(decode_pattern, 0, &pcre_errptr, &pcre_erroffset,
        NULL);
    if (decode_pcre == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "Failed to compile pattern \"%s\" at"
            " offset %d: %s", decode_pattern, pcre_erroffset, pcre_errptr);
        exit(EXIT_FAILURE);
    }

    decode_pcre_study = pcre_study(decode_pcre, 0, &pcre_errptr);
    if (pcre_errptr != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "Failed to study pattern \"%s\": %s",
            decode_pattern, pcre_errptr);
        exit(EXIT_FAILURE);
    }
}

int DetectBase64DecodeDoMatch(DetectEngineThreadCtx *det_ctx, Signature *s,
    const SigMatch *sm, uint8_t *payload, uint32_t payload_len)
{
    DetectBase64Decode *data = (DetectBase64Decode *)sm->ctx;
    int decode_len;

#if 0
    printf("Input data:\n");
    PrintRawDataFp(stdout, payload, payload_len);
#endif

    if (data->relative) {
        payload += det_ctx->buffer_offset;
        payload_len -= det_ctx->buffer_offset;
    }

    if (data->offset) {
        if (data->offset >= payload_len) {
            return 0;
        }
        payload = payload + data->offset;
        payload_len -= data->offset;
    }

    decode_len = MIN(payload_len, data->bytes);

#if 0
    printf("Decoding:\n");
    PrintRawDataFp(stdout, payload, decode_len);
#endif

    det_ctx->base64_decoded_len = DecodeBase64(det_ctx->base64_decoded,
        payload, decode_len, 0);
    SCLogDebug("Decoded %d bytes from base64 data.",
        det_ctx->base64_decoded_len);
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
    static const int max = 30;
    int ov[max];
    int pcre_rc;
    const char *bytes_str = NULL;
    const char *offset_str = NULL;
    const char *relative_str = NULL;
    int retval = 0;

    *bytes = 0;
    *offset = 0;
    *relative = 0;

    pcre_rc = pcre_exec(decode_pcre, decode_pcre_study, str, strlen(str), 0, 0,
        ov, max);
    if (pcre_rc < 3) {
        goto error;
    }

    if (pcre_rc >= 3) {
        if (pcre_get_substring((char *)str, ov, max, 2, &bytes_str) > 0) {
            if (ByteExtractStringUint32(bytes, 10, 0, bytes_str) <= 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                    "Bad value for bytes: \"%s\"", bytes_str);
                goto error;
            }
        }
     }

    if (pcre_rc >= 5) {
        if (pcre_get_substring((char *)str, ov, max, 4, &offset_str)) {
            if (ByteExtractStringUint32(offset, 10, 0, offset_str) <= 0) {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                    "Bad value for offset: \"%s\"", offset_str);
                goto error;
            }
        }
    }

    if (pcre_rc >= 6) {
        if (pcre_get_substring((char *)str, ov, max, 5, &relative_str)) {
            if (strcmp(relative_str, "relative") == 0) {
                *relative = 1;
            }
            else {
                SCLogError(SC_ERR_INVALID_RULE_ARGUMENT,
                    "Invalid argument: \"%s\"", relative_str);
                goto error;
            }
        }
    }

    retval = 1;
error:
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

static int DetectBase64DecodeSetup(DetectEngineCtx *de_ctx, Signature *s,
    char *str)
{
    uint32_t bytes = 0;
    uint32_t offset = 0;
    uint8_t relative = 0;
    DetectBase64Decode *data = NULL;
    int sm_list;
    SigMatch *sm = NULL;
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

    if (s->list != DETECT_SM_LIST_NOTSET) {
        sm_list = s->list;
#if 0
        if (data->relative) {
            pm = SigMatchGetLastSMFromLists(s, 4,
                DETECT_CONTENT, s->sm_lists_tail[sm_list],
                DETECT_PCRE, s->sm_lists_tail[sm_list]);
        }
#endif
    }
    else {
        /* Copied from detect-isdataat.c. */
        pm = SigMatchGetLastSMFromLists(s, 168,
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_BYTE_EXTRACT, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_UMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HCBDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_FILEDATA],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HRHDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HMDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HCDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HRUDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HSMDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HSCDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HUADMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HHHDMATCH],
            DETECT_ISDATAAT, s->sm_lists_tail[DETECT_SM_LIST_HRHHDMATCH]);
        if (pm == NULL) {
            sm_list = DETECT_SM_LIST_PMATCH;
        }
        else {
            sm_list = SigMatchListSMBelongsTo(s, pm);
        }
    }

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }
    sm->type = DETECT_BASE64_DECODE;
    sm->ctx = (SigMatchCtx *)data;
    SigMatchAppendSMToList(s, sm, sm_list);

    if (!data->bytes) {
        data->bytes = BASE64_DECODE_MAX;
    }
    if (data->bytes > de_ctx->base64_decode_max_len) {
        de_ctx->base64_decode_max_len = data->bytes;
    }

    return 0;
error:
    if (data != NULL) {
        SCFree(data);
    }
    return -1;
}

static void DetectBase64DecodeFree(void *ptr)
{
    DetectBase64Decode *data = ptr;
    SCFree(data);
}


#ifdef UNITTESTS

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "app-layer-parser.h"
#include "flow-util.h"
#include "stream-tcp.h"

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
    DetectEngineCtx *de_ctx = NULL;
    Signature *s;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"DetectBase64DecodeTestSetup\"; "
        "base64_decode; content:\"content\"; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    s = de_ctx->sig_list;
    if (s == NULL) {
        goto end;
    }
    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        goto end;
    }

    retval = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return retval;
}

/**
 * Test keyword setup when the prior rule has a content modifier on
 * it.
 */
static int DetectBase64DecodeHttpHeaderTestSetup(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s;
    int retval = 0;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->sig_list = SigInit(de_ctx,
        "alert tcp any any -> any any ("
        "msg:\"DetectBase64DecodeTestSetup\"; "
        "content:\"Authorization: basic \"; http_header; "
        "base64_decode; content:\"content\"; "
        "sid:1; rev:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }
    s = de_ctx->sig_list;
    if (s == NULL) {
        goto end;
    }

    /* I'm not complete sure if this list should not be NULL. */
    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        goto end;
    }

    /* Test that the http header list is not NULL. */
    if (s->sm_lists_tail[DETECT_SM_LIST_HHDMATCH] == NULL) {
        goto end;
    }

    retval = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return retval;
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

#endif

static void DetectBase64DecodeRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectBase64TestDecodeParse", DetectBase64TestDecodeParse,
        1);
    UtRegisterTest("DetectBase64DecodeTestSetup", DetectBase64DecodeTestSetup,
        1);
    UtRegisterTest("DetectBase64DecodeHttpHeaderTestSetup",
        DetectBase64DecodeHttpHeaderTestSetup, 1);
    UtRegisterTest("DetectBase64DecodeTestDecode", DetectBase64DecodeTestDecode,
        1);
    UtRegisterTest("DetectBase64DecodeTestDecodeWithOffset",
        DetectBase64DecodeTestDecodeWithOffset, 1);
    UtRegisterTest("DetectBase64DecodeTestDecodeLargeOffset",
        DetectBase64DecodeTestDecodeLargeOffset, 1);
    UtRegisterTest("DetectBase64DecodeTestDecodeRelative",
        DetectBase64DecodeTestDecodeRelative, 1);
#endif /* UNITTESTS */
}
