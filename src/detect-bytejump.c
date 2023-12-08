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
 * \file
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements byte_jump keyword.
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "app-layer.h"

#include "detect-byte.h"
#include "detect-byte-extract.h"
#include "detect-bytejump.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "util-validate.h"
#include "detect-pcre.h"
#include "detect-engine-build.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*" \
                     "([^\\s,]+\\s*,\\s*[^\\s,]+)" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "\\s*$"

static DetectParseRegex parse_regex;

static DetectBytejumpData *DetectBytejumpParse(
        DetectEngineCtx *de_ctx, const char *optstr, char **nbytes, char **offset);
static int DetectBytejumpSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr);
static void DetectBytejumpFree(DetectEngineCtx*, void *ptr);
#ifdef UNITTESTS
static void DetectBytejumpRegisterTests(void);
#endif

void DetectBytejumpRegister (void)
{
    sigmatch_table[DETECT_BYTEJUMP].name = "byte_jump";
    sigmatch_table[DETECT_BYTEJUMP].desc = "allow the ability to select a <num of bytes> from an <offset> and move the detection pointer to that position";
    sigmatch_table[DETECT_BYTEJUMP].url = "/rules/payload-keywords.html#byte-jump";
    sigmatch_table[DETECT_BYTEJUMP].Match = NULL;
    sigmatch_table[DETECT_BYTEJUMP].Setup = DetectBytejumpSetup;
    sigmatch_table[DETECT_BYTEJUMP].Free  = DetectBytejumpFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BYTEJUMP].RegisterTests = DetectBytejumpRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/* 23 - This is the largest string (octal, with a zero prefix) that
 *      will not overflow uint64_t.  The only way this length
 *      could be over 23 and still not overflow is if it were zero
 *      prefixed and we only support 1 byte of zero prefix for octal.
 *
 * "01777777777777777777777" = 0xffffffffffffffff
 *
 * 8 - Without string, the maximum byte extract count is 8.
 */
static inline bool DetectBytejumpValidateNbytesOnly(const DetectBytejumpData *data, int32_t nbytes)
{
    return (data->flags & DETECT_BYTEJUMP_STRING && nbytes <= 23) || (nbytes <= 8);
}

static bool DetectBytejumpValidateNbytes(const DetectBytejumpData *data, int32_t nbytes)
{
    if (!DetectBytejumpValidateNbytesOnly(data, nbytes)) {
        if (data->flags & DETECT_BYTEJUMP_STRING) {
            /* 23 - This is the largest string (octal, with a zero prefix) that
             *      will not overflow uint64_t.  The only way this length
             *      could be over 23 and still not overflow is if it were zero
             *      prefixed and we only support 1 byte of zero prefix for octal.
             *
             * "01777777777777777777777" = 0xffffffffffffffff
             */
            if (nbytes > 23) {
                SCLogError("Cannot test more than 23 bytes "
                           "with \"string\"");
            }
        } else {
            if (nbytes > 8) {
                SCLogError("Cannot test more than 8 bytes "
                           "without \"string\"");
            }
        }
        return false;
    }

    return true;
}

/** \brief Byte jump match function
 *  \param det_ctx thread detect engine ctx
 *  \param s signature
 *  \param m byte jump sigmatch
 *  \param payload ptr to the payload
 *  \param payload_len length of the payload
 *  \retval true match
 *  \retval false no match
 */
bool DetectBytejumpDoMatch(DetectEngineThreadCtx *det_ctx, const Signature *s,
        const SigMatchCtx *ctx, const uint8_t *payload, uint32_t payload_len, uint16_t flags,
        int32_t nbytes, int32_t offset)
{
    SCEnter();

    const DetectBytejumpData *data = (const DetectBytejumpData *)ctx;
    const uint8_t *ptr = NULL;
    int32_t len = 0;
    uint64_t val = 0;
    int extbytes;

    if (payload_len == 0) {
        SCReturnBool(false);
    }

    /* Validate the number of bytes we are testing
     * If the validation is successful, we know that
     * it contains a value <= 23. Thus, we can
     * safely cast it when extracting bytes
     */
    if (data->flags & DETECT_BYTEJUMP_NBYTES_VAR) {
        if (!DetectBytejumpValidateNbytesOnly(data, nbytes)) {
            SCLogDebug("Invalid byte_jump nbytes "
                       "seen in byte_jump - %d",
                    nbytes);
            SCReturnBool(false);
        }
    }

    /* Calculate the ptr value for the bytejump and length remaining in
     * the packet from that point.
     */
    ptr = payload + offset;
    len = payload_len - offset;
    if (flags & DETECT_BYTEJUMP_RELATIVE) {
        ptr += det_ctx->buffer_offset;
        len -= det_ctx->buffer_offset;

        SCLogDebug("[relative] after: ptr %p [len %d]", ptr, len);

        /* No match if there is no relative base */
        if (ptr == NULL || (nbytes && len <= 0)) {
            SCReturnBool(false);
        }
    }

    /* Verify the to-be-extracted data is within the packet */
    if (ptr < payload || nbytes > len) {
        SCLogDebug("Data not within payload "
                   "pkt=%p, ptr=%p, len=%" PRIi32 ", nbytes=%" PRIi32,
                payload, ptr, len, nbytes);
        SCReturnBool(false);
    }

    /* Extract the byte data */
    if (flags & DETECT_BYTEJUMP_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base, nbytes, (const char *)ptr);
        if(extbytes <= 0) {
            SCLogDebug("error extracting %d bytes of string data: %d", nbytes, extbytes);
            SCReturnBool(false);
        }
    }
    else {
        int endianness = (flags & DETECT_BYTEJUMP_LITTLE) ? BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, (uint16_t)nbytes, ptr);
        if (extbytes != nbytes) {
            SCLogDebug("error extracting %d bytes of numeric data: %d", nbytes, extbytes);
            SCReturnBool(false);
        }
    }

    SCLogDebug("VAL: (%" PRIu64 " x %" PRIu32 ") + %" PRIi32 " + %" PRId32, val, data->multiplier,
            extbytes, data->post_offset);

    /* Adjust the jump value based on flags */
    val *= data->multiplier;
    if (flags & DETECT_BYTEJUMP_ALIGN) {
        if ((val % 4) != 0) {
            val += 4 - (val % 4);
        }
    }
    val += data->post_offset;
    SCLogDebug("val: %" PRIi64 " post_offset: %" PRIi32, val, data->post_offset);

    const uint8_t *jumpptr;
    /* Calculate the jump location */
    if (flags & DETECT_BYTEJUMP_BEGIN) {
        jumpptr = payload + (int64_t)val;
        SCLogDebug("NEWVAL: payload %p + %" PRIi64 " = %p", payload, (int64_t)val, jumpptr + val);
    } else if (flags & DETECT_BYTEJUMP_END) {
        jumpptr = payload + payload_len + (int64_t)val;
        SCLogDebug(
                "NEWVAL: payload %p + %" PRIu32 " + %" PRIi64, payload, payload_len, (int64_t)val);
    } else {
        jumpptr = ptr + (int64_t)val + extbytes;
        SCLogDebug("NEWVAL: ptr %p + %" PRIi64 " = %p", ptr, val, jumpptr);
    }

    /* Validate that the jump location is still in the packet
     * \todo Should this validate it is still in the *payload*?
     */
    if (jumpptr < payload) {
        jumpptr = payload;
        SCLogDebug("jump location is before buffer start; resetting to buffer start");
    } else if (jumpptr > (payload + payload_len)) {
        SCLogDebug("Jump location (%" PRIu64 ") is not within payload (%" PRIu32 ")",
                payload_len + val, payload_len);
        SCReturnBool(false);
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        const uint8_t *sptr = (flags & DETECT_BYTEJUMP_BEGIN) ? payload : ptr;
        SCLogDebug("jumping %" PRId64 " bytes from %p (%08x)", val, sptr, (int)(sptr - payload));
    }
#endif /* DEBUG */

    /* Adjust the detection context to the jump location. */
    DEBUG_VALIDATE_BUG_ON(jumpptr < payload);
    det_ctx->buffer_offset = jumpptr - payload;

    SCReturnBool(true);
}

static DetectBytejumpData *DetectBytejumpParse(
        DetectEngineCtx *de_ctx, const char *optstr, char **nbytes_str, char **offset)
{
    DetectBytejumpData *data = NULL;
    char args[10][64];
    int res = 0;
    size_t pcre2len;
    int numargs = 0;
    int i = 0;
    uint32_t nbytes = 0;
    char *str_ptr;
    char *end_ptr;
    pcre2_match_data *match = NULL;

    memset(args, 0x00, sizeof(args));

    /* Execute the regex and populate args with captures. */
    int ret = DetectParsePcreExec(&parse_regex, &match, optstr, 0, 0);
    if (ret < 2 || ret > 10) {
        SCLogError("parse error, ret %" PRId32 ", string \"%s\"", ret, optstr);
        goto error;
    }

    /* The first two arguments are stashed in the first PCRE substring.
     * This is because byte_jump can take 10 arguments, but PCRE only
     * supports 9 substrings, sigh.
     */
    char str[512] = "";
    pcre2len = sizeof(str);
    res = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)str, &pcre2len);
    if (res < 0) {
        SCLogError("pcre2_substring_copy_bynumber failed "
                   "for arg 1");
        goto error;
    }

    /* Break up first substring into two parameters
     *
     * NOTE: Because of this, we cannot free args[1] as it is part of args[0],
     * and *yes* this *is* ugly.
     */
    end_ptr = str;
    while (!(isspace((unsigned char)*end_ptr) || (*end_ptr == ','))) end_ptr++;
    *(end_ptr++) = '\0';
    strlcpy(args[0], str, sizeof(args[0]));
    numargs++;

    str_ptr = end_ptr;
    while (isspace((unsigned char)*str_ptr) || (*str_ptr == ',')) str_ptr++;
    end_ptr = str_ptr;
    while (!(isspace((unsigned char)*end_ptr) || (*end_ptr == ',')) && (*end_ptr != '\0'))
        end_ptr++;
    *(end_ptr++) = '\0';
    strlcpy(args[1], str_ptr, sizeof(args[1]));
    numargs++;

    /* The remaining args are directly from PCRE substrings */
    for (i = 1; i < (ret - 1); i++) {
        pcre2len = sizeof(args[0]);
        res = pcre2_substring_copy_bynumber(match, i + 1, (PCRE2_UCHAR8 *)args[i + 1], &pcre2len);
        if (res < 0) {
            SCLogError("pcre2_substring_copy_bynumber failed for arg %d", i + 1);
            goto error;
        }
        numargs++;
    }

    /* Initialize the data */
    data = SCMalloc(sizeof(DetectBytejumpData));
    if (unlikely(data == NULL))
        goto error;
    data->base = DETECT_BYTEJUMP_BASE_UNSET;
    data->flags = 0;
    data->multiplier = 1;
    data->post_offset = 0;

    /*
     * The first two options are required and positional.  The
     * remaining arguments are flags and are not positional.
     */

    /* Number of bytes */
    if (args[0][0] != '-' && isalpha((unsigned char)args[0][0])) {
        if (nbytes_str == NULL) {
            SCLogError("byte_jump supplied with "
                       "var name for nbytes.  \"value\" argument supplied to "
                       "this function has to be non-NULL");
            goto error;
        }
        *nbytes_str = SCStrdup(args[0]);
        if (*nbytes_str == NULL)
            goto error;
        data->flags |= DETECT_BYTEJUMP_NBYTES_VAR;
    } else {
        if (StringParseUint32(&nbytes, 10, (uint16_t)strlen(args[0]), args[0]) <= 0) {
            SCLogError("Malformed number of bytes: %s", optstr);
            goto error;
        }
    }

    /* Offset */
    if (args[1][0] != '-' && isalpha((unsigned char)args[1][0])) {
        if (offset == NULL) {
            SCLogError("byte_jump supplied with "
                       "var name for offset.  \"value\" argument supplied to "
                       "this function has to be non-NULL");
            goto error;
        }
        *offset = SCStrdup(args[1]);
        if (*offset == NULL)
            goto error;
    } else {
        if (StringParseI32RangeCheck(
                    &data->offset, 10, (uint16_t)strlen(args[1]), args[1], -65535, 65535) <= 0) {
            SCLogError("Malformed offset: %s", optstr);
            goto error;
        }
    }

    /* The remaining options are flags. */
    /** \todo Error on dups? */
    for (i = 2; i < numargs; i++) {
        if (strcmp("relative", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_RELATIVE;
        } else if (strcasecmp("string", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_STRING;
        } else if (strcasecmp("dec", args[i]) == 0) {
            data->base |= DETECT_BYTEJUMP_BASE_DEC;
        } else if (strcasecmp("hex", args[i]) == 0) {
            data->base |= DETECT_BYTEJUMP_BASE_HEX;
        } else if (strcasecmp("oct", args[i]) == 0) {
            data->base |= DETECT_BYTEJUMP_BASE_OCT;
        } else if (strcasecmp("big", args[i]) == 0) {
            if (data->flags & DETECT_BYTEJUMP_LITTLE) {
                data->flags ^= DETECT_BYTEJUMP_LITTLE;
            }
            data->flags |= DETECT_BYTEJUMP_BIG;
        } else if (strcasecmp("little", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_LITTLE;
        } else if (strcasecmp("from_beginning", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_BEGIN;
        } else if (strcasecmp("from_end", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_END;
        } else if (strcasecmp("align", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_ALIGN;
        } else if (strncasecmp("multiplier ", args[i], 11) == 0) {
            if (StringParseU16RangeCheck(&data->multiplier, 10, (uint16_t)strlen(args[i]) - 11,
                        args[i] + 11, 1, 65535) <= 0) {
                SCLogError("Malformed multiplier: %s", optstr);
                goto error;
            }
        } else if (strncasecmp("post_offset ", args[i], 12) == 0) {
            if (StringParseI32RangeCheck(&data->post_offset, 10, (uint16_t)strlen(args[i]) - 12,
                        args[i] + 12, -65535, 65535) <= 0) {
                SCLogError("Malformed post_offset: %s", optstr);
                goto error;
            }
            SCLogDebug("post_offset: %s [%d]", optstr, data->post_offset);
        } else if (strcasecmp("dce", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_DCE;
        } else {
            SCLogError("Unknown option: \"%s\"", args[i]);
            goto error;
        }
    }

    if ((data->flags & DETECT_BYTEJUMP_END) && (data->flags & DETECT_BYTEJUMP_BEGIN)) {
        SCLogError("'from_end' and 'from_beginning' "
                   "cannot be used in the same byte_jump statement");
        goto error;
    }

    if (!(data->flags & DETECT_BYTEJUMP_NBYTES_VAR)) {
        if (!DetectBytejumpValidateNbytes(data, nbytes)) {
            goto error;
        }

        /* This is max 23 so it will fit in a byte (see validation function) */
        data->nbytes = (uint8_t)nbytes;
    }
    if (!(data->flags & DETECT_BYTEJUMP_STRING)) {
        if (data->base != DETECT_BYTEJUMP_BASE_UNSET) {
            SCLogError("Cannot use a base "
                       "without \"string\": %s",
                    optstr);
            goto error;
        }
    }

    pcre2_match_data_free(match);
    return data;

error:
    if (offset != NULL && *offset != NULL) {
        SCFree(*offset);
        *offset = NULL;
    }
    if (nbytes_str != NULL && *nbytes_str != NULL) {
        SCFree(*nbytes_str);
        *nbytes_str = NULL;
    }
    if (data != NULL)
        DetectBytejumpFree(de_ctx, data);
    if (match) {
        pcre2_match_data_free(match);
    }
    return NULL;
}

static int DetectBytejumpSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SigMatch *prev_pm = NULL;
    DetectBytejumpData *data = NULL;
    char *offset = NULL;
    char *nbytes = NULL;
    int ret = -1;

    data = DetectBytejumpParse(de_ctx, optstr, &nbytes, &offset);
    if (data == NULL)
        goto error;

    int sm_list;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        sm_list = s->init_data->list;

        if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE, -1);
        }
    } else if (data->flags & DETECT_BYTEJUMP_DCE) {
        if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s,
                    DETECT_CONTENT, DETECT_PCRE,
                    DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                    DETECT_ISDATAAT, DETECT_BYTEMATH, -1);
            if (prev_pm == NULL) {
                sm_list = DETECT_SM_LIST_PMATCH;
            } else {
                sm_list = SigMatchListSMBelongsTo(s, prev_pm);
                if (sm_list < 0)
                    goto error;
            }
        } else {
            sm_list = DETECT_SM_LIST_PMATCH;
        }

        if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0)
            goto error;

    } else if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
        prev_pm = DetectGetLastSMFromLists(s,
                DETECT_CONTENT, DETECT_PCRE,
                DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                DETECT_ISDATAAT, DETECT_BYTEMATH, -1);
        if (prev_pm == NULL) {
            sm_list = DETECT_SM_LIST_PMATCH;
        } else {
            sm_list = SigMatchListSMBelongsTo(s, prev_pm);
            if (sm_list < 0)
                goto error;
        }

    } else {
        sm_list = DETECT_SM_LIST_PMATCH;
    }

    if (data->flags & DETECT_BYTEJUMP_DCE) {
        if ((data->flags & DETECT_BYTEJUMP_STRING) ||
            (data->flags & DETECT_BYTEJUMP_LITTLE) ||
            (data->flags & DETECT_BYTEJUMP_BIG) ||
            (data->flags & DETECT_BYTEJUMP_BEGIN) ||
            (data->flags & DETECT_BYTEJUMP_END) ||
            (data->base == DETECT_BYTEJUMP_BASE_DEC) ||
            (data->base == DETECT_BYTEJUMP_BASE_HEX) ||
            (data->base == DETECT_BYTEJUMP_BASE_OCT) ) {
            SCLogError("Invalid option. "
                       "A byte_jump keyword with dce holds other invalid modifiers.");
            goto error;
        }
    }

    if (nbytes != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(nbytes, s, &index)) {
            SCLogError("Unknown byte_extract var "
                       "seen in byte_jump - %s",
                    nbytes);
            goto error;
        }
        data->nbytes = index;
        SCFree(nbytes);
        nbytes = NULL;
    }

    if (offset != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(offset, s, &index)) {
            SCLogError("Unknown byte_extract var "
                       "seen in byte_jump - %s",
                    offset);
            goto error;
        }
        data->offset = index;
        data->flags |= DETECT_BYTEJUMP_OFFSET_VAR;
        SCFree(offset);
        offset = NULL;
    }

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_BYTEJUMP, (SigMatchCtx *)data, sm_list) == NULL) {
        goto error;
    }

    if (!(data->flags & DETECT_BYTEJUMP_RELATIVE))
        goto okay;

    if (prev_pm == NULL)
        goto okay;

    if (prev_pm->type == DETECT_CONTENT) {
        DetectContentData *cd = (DetectContentData *)prev_pm->ctx;
        cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
    } else if (prev_pm->type == DETECT_PCRE) {
        DetectPcreData *pd = (DetectPcreData *)prev_pm->ctx;
        pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
    }

 okay:
    ret = 0;
    return ret;

 error:
     if (nbytes != NULL) {
         SCFree(nbytes);
     }
    if (offset != NULL) {
        SCFree(offset);
    }
    DetectBytejumpFree(de_ctx, data);
    return ret;
}

/**
 * \brief this function will free memory associated with DetectBytejumpData
 *
 * \param data pointer to DetectBytejumpData
 */
static void DetectBytejumpFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectBytejumpData *data = (DetectBytejumpData *)ptr;
    SCFree(data);
}


/* UNITTESTS */
#ifdef UNITTESTS
#include "util-unittest-helper.h"
static int g_file_data_buffer_id = 0;
static int g_dce_stub_data_buffer_id = 0;

/**
 * \test DetectBytejumpTestParse01 is a test to make sure that we return
 * "something" when given valid bytejump opt
 */
static int DetectBytejumpTestParse01(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL, "4,0", NULL, NULL);
    FAIL_IF_NULL(data);

    DetectBytejumpFree(NULL, data);
    PASS;
}

/**
 * \test DetectBytejumpTestParse02 is a test for setting the required opts
 */
static int DetectBytejumpTestParse02(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL, "4, 0", NULL, NULL);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->nbytes == 4);
    FAIL_IF_NOT(data->offset == 0);
    FAIL_IF_NOT(data->multiplier == 1);
    FAIL_IF_NOT(data->post_offset == 0);
    FAIL_IF_NOT(data->flags == 0);
    FAIL_IF_NOT(data->base == DETECT_BYTEJUMP_BASE_UNSET);

    DetectBytejumpFree(NULL, data);
    PASS;
}

/**
 * \test DetectBytejumpTestParse03 is a test for setting the optional flags
 */
static int DetectBytejumpTestParse03(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL,
            " 4,0 , relative , little, string, "
            "dec, align, from_beginning",
            NULL, NULL);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->nbytes == 4);
    FAIL_IF_NOT(data->offset == 0);
    FAIL_IF_NOT(data->multiplier == 1);
    FAIL_IF_NOT(data->post_offset == 0);
    FAIL_IF_NOT(data->flags ==
                (DETECT_BYTEJUMP_RELATIVE | DETECT_BYTEJUMP_LITTLE | DETECT_BYTEJUMP_STRING |
                        DETECT_BYTEJUMP_ALIGN | DETECT_BYTEJUMP_BEGIN));
    FAIL_IF_NOT(data->base == DETECT_BYTEJUMP_BASE_DEC);

    DetectBytejumpFree(NULL, data);
    PASS;
}

/**
 * \test DetectBytejumpTestParse04 is a test for setting the optional flags
 *       with parameters
 *
 * \todo This fails because we can only have 9 captures and there are 10.
 */
static int DetectBytejumpTestParse04(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL,
            " 4,0 , relative , little, string, "
            "dec, align, from_beginning , "
            "multiplier 2 , post_offset -16 ",
            NULL, NULL);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->nbytes == 4);
    FAIL_IF_NOT(data->offset == 0);
    FAIL_IF_NOT(data->multiplier == 2);
    FAIL_IF_NOT(data->post_offset == -16);
    FAIL_IF_NOT(data->flags ==
                (DETECT_BYTEJUMP_RELATIVE | DETECT_BYTEJUMP_LITTLE | DETECT_BYTEJUMP_ALIGN |
                        DETECT_BYTEJUMP_STRING | DETECT_BYTEJUMP_BEGIN));
    FAIL_IF_NOT(data->base == DETECT_BYTEJUMP_BASE_DEC);

    DetectBytejumpFree(NULL, data);
    PASS;
}

/**
 * \test DetectBytejumpTestParse05 is a test for setting base without string
 */
static int DetectBytejumpTestParse05(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL,
            " 4,0 , relative , little, dec, "
            "align, from_beginning",
            NULL, NULL);
    FAIL_IF_NOT_NULL(data);

    PASS;
}

/**
 * \test DetectBytejumpTestParse06 is a test for too many bytes to extract
 */
static int DetectBytejumpTestParse06(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL, "9, 0", NULL, NULL);
    FAIL_IF_NOT_NULL(data);

    PASS;
}

/**
 * \test DetectBytejumpTestParse07 is a test for too many string bytes to extract
 */
static int DetectBytejumpTestParse07(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL, "24, 0, string, dec", NULL, NULL);
    FAIL_IF_NOT_NULL(data);

    PASS;
}

/**
 * \test DetectBytejumpTestParse08 is a test for offset too big
 */
static int DetectBytejumpTestParse08(void)
{
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(NULL, "4, 0xffffffffffffffff", NULL, NULL);
    FAIL_IF_NOT_NULL(data);

    PASS;
}

/**
 * \test Test dce option.
 */
static int DetectBytejumpTestParse09(void)
{
    Signature *s = SigAlloc();
    FAIL_IF_NULL(s);

    FAIL_IF(DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0);

    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s,
                        "4,0, align, multiplier 2, "
                        "post_offset -16,dce") == 0);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s,
                        "4,0, multiplier 2, "
                        "post_offset -16,dce") == 0);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0,post_offset -16,dce") == 0);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0,dce") == 0);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0,dce") == 0);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, string, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, big, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, little, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, string, dec, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, string, oct, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, string, hex, dce") == -1);
    FAIL_IF_NOT(DetectBytejumpSetup(NULL, s, "4,0, from_beginning, dce") == -1);

    FAIL_IF_NULL(s->init_data->smlists[DETECT_SM_LIST_PMATCH]);
    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NOT_NULL(sm);

    SigFree(NULL, s);
    PASS;
}

/**
 * \test Test dce option.
 */
static int DetectBytejumpTestParse10(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(msg:\"Testing bytejump_body\"; "
                                                 "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                                                 "dce_stub_data; "
                                                 "content:\"one\"; distance:0; "
                                                 "byte_jump:4,0,align,multiplier 2, "
                                                 "post_offset -16,relative,dce; sid:1;)");
    FAIL_IF_NULL(s);
    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    FAIL_IF_NULL(sm->next);
    sm = sm->next;
    FAIL_IF_NOT(sm->type == DETECT_BYTEJUMP);

    DetectBytejumpData *bd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF_NOT(bd->flags & DETECT_BYTEJUMP_DCE);
    FAIL_IF_NOT(bd->flags & DETECT_BYTEJUMP_RELATIVE);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_STRING);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_BIG);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_LITTLE);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing bytejump_body\"; "
                                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                                      "dce_stub_data; "
                                      "content:\"one\"; distance:0; "
                                      "byte_jump:4,0,align,multiplier 2, "
                                      "post_offset -16,relative,dce; sid:2;)");
    FAIL_IF_NULL(s);
    sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NULL(sm);

    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    FAIL_IF_NULL(sm->next);
    sm = sm->next;
    FAIL_IF_NOT(sm->type == DETECT_BYTEJUMP);

    bd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF_NOT(bd->flags & DETECT_BYTEJUMP_DCE);
    FAIL_IF_NOT(bd->flags & DETECT_BYTEJUMP_RELATIVE);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_STRING);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_BIG);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_LITTLE);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                      "(msg:\"Testing bytejump_body\"; "
                                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                                      "dce_stub_data; "
                                      "content:\"one\"; distance:0; "
                                      "byte_jump:4,0,align,multiplier 2, "
                                      "post_offset -16,relative; sid:3;)");
    FAIL_IF_NULL(s);
    sm = DetectBufferGetFirstSigMatch(s, g_dce_stub_data_buffer_id);
    FAIL_IF_NULL(sm);

    FAIL_IF_NOT(sm->type == DETECT_CONTENT);
    FAIL_IF_NULL(sm->next);
    sm = sm->next;
    FAIL_IF_NOT(sm->type == DETECT_BYTEJUMP);

    bd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_DCE);
    FAIL_IF_NOT(bd->flags & DETECT_BYTEJUMP_RELATIVE);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_STRING);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_BIG);
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_LITTLE);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test dce option.
 */
static int DetectBytejumpTestParse11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->flags |= DE_QUIET;
    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_sub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,big,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,little,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,hex,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,dec,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,oct,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,from_beginning,dce; sid:1;)");
    FAIL_IF_NOT_NULL(s);

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test Test file_data
 */
static int DetectBytejumpTestParse12(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                                 "(file_data; byte_jump:4,0,align,multiplier 2, "
                                                 "post_offset -16,relative; sid:1;)");
    FAIL_IF_NULL(s);

    SigMatch *sm = DetectBufferGetFirstSigMatch(s, g_file_data_buffer_id);
    FAIL_IF_NULL(sm);
    FAIL_IF_NOT(sm->type == DETECT_BYTEJUMP);

    DetectBytejumpData *bd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF(bd->flags & DETECT_BYTEJUMP_DCE);
    FAIL_IF((bd->flags &
                    (DETECT_BYTEJUMP_RELATIVE | DETECT_BYTEJUMP_STRING | DETECT_BYTEJUMP_BIG)) ==
            (DETECT_BYTEJUMP_RELATIVE | DETECT_BYTEJUMP_STRING | DETECT_BYTEJUMP_BIG));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectBytejumpTestParse13(void)
{
    DetectBytejumpData *data = DetectBytejumpParse(NULL,
            " 4,0 , relative , little, string, dec, "
            "align, from_end",
            NULL, NULL);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->flags & DETECT_BYTEJUMP_END);

    DetectBytejumpFree(NULL, data);

    PASS;
}

static int DetectBytejumpTestParse14(void)
{
    DetectBytejumpData *data = DetectBytejumpParse(NULL,
            " 4,0 , relative , little, string, dec, "
            "align, from_beginning, from_end",
            NULL, NULL);

    FAIL_IF_NOT_NULL(data);

    PASS;
}

/**
 * \test DetectByteJumpTestPacket01 is a test to check matches of
 * byte_jump and byte_jump relative works if the previous keyword is pcre
 * (bug 142)
 */
static int DetectByteJumpTestPacket01 (void)
{
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"pcre + byte_test + "
    "relative\"; pcre:\"/AllWorkAndNoPlayMakesWillADullBoy/\"; byte_jump:1,6,"
    "relative,string,dec; content:\"0\"; sid:134; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);
    PASS;
}

/**
 * \test DetectByteJumpTestPacket02 is a test to check matches of
 * byte_jump and byte_jump relative works if the previous keyword is byte_jump
 * (bug 165)
 */
static int DetectByteJumpTestPacket02 (void)
{
    uint8_t buf[] = { 0x00, 0x00, 0x00, 0x77, 0xff, 0x53,
                    0x4d, 0x42, 0x2f, 0x00, 0x00, 0x00, 0x00, 0x18,
                    0x01, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08,
                    0x92, 0xa4, 0x01, 0x08, 0x17, 0x5c, 0x0e, 0xff,
                    0x00, 0x00, 0x00, 0x01, 0x40, 0x48, 0x00, 0x00,
                    0x00, 0xff };
    uint16_t buflen = sizeof(buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"byte_jump with byte_jump"
                 " + relative\"; byte_jump:1,13; byte_jump:4,0,relative; "
                 "content:\"|48 00 00|\"; within:3; sid:144; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);
    PASS;
}

static int DetectByteJumpTestPacket03(void)
{
    uint8_t *buf = NULL;
    uint16_t buflen = 0;
    buf = SCMalloc(4);
    if (unlikely(buf == NULL)) {
        printf("malloc failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf, "boom", 4);
    buflen = 4;

    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (msg:\"byte_jump\"; "
        "byte_jump:1,214748364; sid:1; rev:1;)";

    FAIL_IF(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);
    FAIL_IF_NULL(buf);

    SCFree(buf);
    PASS;
}

/**
 * \test check matches of with from_beginning (bug 626/627)
 */
static int DetectByteJumpTestPacket04 (void)
{
    uint8_t *buf = (uint8_t *)"XYZ04abcdABCD";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"XYZ\"; byte_jump:2,0,relative,string,dec; content:\"ABCD\"; distance:0; within:4; sid:1; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);
    PASS;
}

/**
 * \test check matches of with from_beginning (bug 626/627)
 */
static int DetectByteJumpTestPacket05 (void)
{
    uint8_t *buf = (uint8_t *)"XYZ04abcdABCD";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"XYZ\"; byte_jump:2,0,relative,string,dec; content:\"cdABCD\"; within:6; sid:1; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig) ? 0 : 1);

    UTHFreePacket(p);
    PASS;
}

/**
 * \test check matches of with from_beginning (bug 626/627)
 */
static int DetectByteJumpTestPacket06 (void)
{
    uint8_t *buf = (uint8_t *)"XX04abcdABCD";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"XX\"; byte_jump:2,0,relative,string,dec,from_beginning; content:\"ABCD\"; distance:4; within:4; sid:1; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);
    PASS;
}

/**
 * \test check matches of with from_beginning (bug 626/627)
 */
static int DetectByteJumpTestPacket07 (void)
{
    uint8_t *buf = (uint8_t *)"XX04abcdABCD";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"XX\"; byte_jump:2,0,relative,string,dec,from_beginning; content:\"abcdABCD\"; distance:0; within:8; sid:1; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig) ? 1 : 0);

    UTHFreePacket(p);
    PASS;
}

/**
 * \test check matches of with from_end
 */
static int DetectByteJumpTestPacket08 (void)
{
    uint8_t *buf = (uint8_t *)"XX04abcdABCD";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    FAIL_IF_NULL(p);

    char sig[] = "alert tcp any any -> any any (content:\"XX\"; byte_jump:2,0,"
        "relative,string,dec,from_end, post_offset -8; content:\"ABCD\";  sid:1; rev:1;)";

    FAIL_IF_NOT(UTHPacketMatchSig(p, sig));

    UTHFreePacket(p);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectBytejump
 */
static void DetectBytejumpRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

    UtRegisterTest("DetectBytejumpTestParse01", DetectBytejumpTestParse01);
    UtRegisterTest("DetectBytejumpTestParse02", DetectBytejumpTestParse02);
    UtRegisterTest("DetectBytejumpTestParse03", DetectBytejumpTestParse03);
    UtRegisterTest("DetectBytejumpTestParse04", DetectBytejumpTestParse04);
    UtRegisterTest("DetectBytejumpTestParse05", DetectBytejumpTestParse05);
    UtRegisterTest("DetectBytejumpTestParse06", DetectBytejumpTestParse06);
    UtRegisterTest("DetectBytejumpTestParse07", DetectBytejumpTestParse07);
    UtRegisterTest("DetectBytejumpTestParse08", DetectBytejumpTestParse08);
    UtRegisterTest("DetectBytejumpTestParse09", DetectBytejumpTestParse09);
    UtRegisterTest("DetectBytejumpTestParse10", DetectBytejumpTestParse10);
    UtRegisterTest("DetectBytejumpTestParse11", DetectBytejumpTestParse11);
    UtRegisterTest("DetectBytejumpTestParse12", DetectBytejumpTestParse12);
    UtRegisterTest("DetectBytejumpTestParse13", DetectBytejumpTestParse13);
    UtRegisterTest("DetectBytejumpTestParse14", DetectBytejumpTestParse14);

    UtRegisterTest("DetectByteJumpTestPacket01", DetectByteJumpTestPacket01);
    UtRegisterTest("DetectByteJumpTestPacket02", DetectByteJumpTestPacket02);
    UtRegisterTest("DetectByteJumpTestPacket03", DetectByteJumpTestPacket03);
    UtRegisterTest("DetectByteJumpTestPacket04", DetectByteJumpTestPacket04);
    UtRegisterTest("DetectByteJumpTestPacket05", DetectByteJumpTestPacket05);
    UtRegisterTest("DetectByteJumpTestPacket06", DetectByteJumpTestPacket06);
    UtRegisterTest("DetectByteJumpTestPacket07", DetectByteJumpTestPacket07);
    UtRegisterTest("DetectByteJumpTestPacket08", DetectByteJumpTestPacket08);
}
#endif /* UNITTESTS */
