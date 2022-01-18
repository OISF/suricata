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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-bytejump.h"
#include "detect-bytetest.h"
#include "detect-byte-extract.h"
#include "detect-isdataat.h"

#include "app-layer-protos.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

/* the default value of endianess to be used, if none's specified */
#define DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT DETECT_BYTE_EXTRACT_ENDIAN_BIG

/* the base to be used if string mode is specified.  These options would be
 * specified in DetectByteParseData->base */
#define DETECT_BYTE_EXTRACT_BASE_NONE 0
#define DETECT_BYTE_EXTRACT_BASE_HEX  16
#define DETECT_BYTE_EXTRACT_BASE_DEC  10
#define DETECT_BYTE_EXTRACT_BASE_OCT   8

/* the default value for multiplier.  Either ways we always store a
 * multiplier, 1 or otherwise, so that we can always multiply the extracted
 * value and store it, instead of checking if a multiplier is set or not */
#define DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT 1
/* the min/max limit for multiplier */
#define DETECT_BYTE_EXTRACT_MULTIPLIER_MIN_LIMIT 1
#define DETECT_BYTE_EXTRACT_MULTIPLIER_MAX_LIMIT 65535

/* the max no of bytes that can be extracted in string mode - (string, hex)
 * (string, oct) or (string, dec) */
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT 23
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC 20
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX 14
/* the max no of bytes that can be extraced in non-string mode */
#define NO_STRING_MAX_BYTES_TO_EXTRACT 8

#define PARSE_REGEX "^"                                                  \
    "\\s*([0-9]+)\\s*"                                                   \
    ",\\s*(-?[0-9]+)\\s*"                                               \
    ",\\s*([^\\s,]+)\\s*"                                                \
    "(?:(?:,\\s*([^\\s,]+)\\s*)|(?:,\\s*([^\\s,]+)\\s+([^\\s,]+)\\s*))?" \
    "(?:(?:,\\s*([^\\s,]+)\\s*)|(?:,\\s*([^\\s,]+)\\s+([^\\s,]+)\\s*))?" \
    "(?:(?:,\\s*([^\\s,]+)\\s*)|(?:,\\s*([^\\s,]+)\\s+([^\\s,]+)\\s*))?" \
    "(?:(?:,\\s*([^\\s,]+)\\s*)|(?:,\\s*([^\\s,]+)\\s+([^\\s,]+)\\s*))?" \
    "(?:(?:,\\s*([^\\s,]+)\\s*)|(?:,\\s*([^\\s,]+)\\s+([^\\s,]+)\\s*))?" \
    "$"

static DetectParseRegex parse_regex;

static int DetectByteExtractSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectByteExtractRegisterTests(void);
#endif
static void DetectByteExtractFree(DetectEngineCtx *, void *);

/**
 * \brief Registers the keyword handlers for the "byte_extract" keyword.
 */
void DetectByteExtractRegister(void)
{
    sigmatch_table[DETECT_BYTE_EXTRACT].name = "byte_extract";
    sigmatch_table[DETECT_BYTE_EXTRACT].desc = "extract <num of bytes> at a particular <offset> and store it in <var_name>";
    sigmatch_table[DETECT_BYTE_EXTRACT].url = "/rules/payload-keywords.html#byte-extract";
    sigmatch_table[DETECT_BYTE_EXTRACT].Match = NULL;
    sigmatch_table[DETECT_BYTE_EXTRACT].Setup = DetectByteExtractSetup;
    sigmatch_table[DETECT_BYTE_EXTRACT].Free = DetectByteExtractFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BYTE_EXTRACT].RegisterTests = DetectByteExtractRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

int DetectByteExtractDoMatch(DetectEngineThreadCtx *det_ctx, const SigMatchData *smd,
                             const Signature *s, const uint8_t *payload,
                             uint16_t payload_len, uint64_t *value,
                             uint8_t endian)
{
    DetectByteExtractData *data = (DetectByteExtractData *)smd->ctx;
    const uint8_t *ptr = NULL;
    int32_t len = 0;
    uint64_t val = 0;
    int extbytes;

    if (payload_len == 0) {
        return 0;
    }

    /* Calculate the ptr value for the bytetest and length remaining in
     * the packet from that point.
     */
    if (data->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
        SCLogDebug("relative, working with det_ctx->buffer_offset %"PRIu32", "
                   "data->offset %"PRIu32"", det_ctx->buffer_offset, data->offset);

        ptr = payload + det_ctx->buffer_offset;
        len = payload_len - det_ctx->buffer_offset;

        ptr += data->offset;
        len -= data->offset;

        /* No match if there is no relative base */
        if (len <= 0) {
            return 0;
        }
        //PrintRawDataFp(stdout,ptr,len);
    } else {
        SCLogDebug("absolute, data->offset %"PRIu32"", data->offset);

        ptr = payload + data->offset;
        len = payload_len - data->offset;
    }

    /* Validate that the to-be-extracted is within the packet */
    if (ptr < payload || data->nbytes > len) {
        SCLogDebug("Data not within payload pkt=%p, ptr=%p, len=%"PRIu32", nbytes=%d",
                    payload, ptr, len, data->nbytes);
        return 0;
    }

    /* Extract the byte data */
    if (data->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base,
                                           data->nbytes, (const char *)ptr);
        if (extbytes <= 0) {
            /* strtoull() return 0 if there is no numeric value in data string */
            if (val == 0) {
                SCLogDebug("No Numeric value");
                return 0;
            } else {
                SCLogDebug("error extracting %d bytes of string data: %d",
                        data->nbytes, extbytes);
                return -1;
            }
        }
    } else {
        int endianness = (endian == DETECT_BYTE_EXTRACT_ENDIAN_BIG) ?
                          BYTE_BIG_ENDIAN : BYTE_LITTLE_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (extbytes != data->nbytes) {
            SCLogDebug("error extracting %d bytes of numeric data: %d",
                    data->nbytes, extbytes);
            return 0;
        }
    }

    /* Adjust the jump value based on flags */
    val *= data->multiplier_value;
    if (data->flags & DETECT_BYTE_EXTRACT_FLAG_ALIGN) {
        if ((val % data->align_value) != 0) {
            val += data->align_value - (val % data->align_value);
        }
    }

    ptr += extbytes;

    det_ctx->buffer_offset = ptr - payload;

    *value = val;
    SCLogDebug("extracted value is %"PRIu64, val);
    return 1;
}

/**
 * \internal
 * \brief Used to parse byte_extract arg.
 *
 * \param de_ctx Pointer to the detection engine context
 * \arg The argument to parse.
 *
 * \param bed On success an instance containing the parsed data.
 *            On failure, NULL.
 */
static inline DetectByteExtractData *DetectByteExtractParse(DetectEngineCtx *de_ctx, const char *arg)
{
    DetectByteExtractData *bed = NULL;
    int ret = 0, res = 0;
    size_t pcre2len;
    int i = 0;

    ret = DetectParsePcreExec(&parse_regex, arg, 0, 0);
    if (ret < 3 || ret > 19) {
        SCLogError(SC_ERR_PCRE_PARSE, "parse error, ret %" PRId32
                   ", string \"%s\"", ret, arg);
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid arg to byte_extract : %s "
                   "for byte_extract", arg);
        goto error;
    }

    bed = SCMalloc(sizeof(DetectByteExtractData));
    if (unlikely(bed == NULL))
        goto error;
    memset(bed, 0, sizeof(DetectByteExtractData));

    /* no of bytes to extract */
    char nbytes_str[64] = "";
    pcre2len = sizeof(nbytes_str);
    res = pcre2_substring_copy_bynumber(
            parse_regex.match, 1, (PCRE2_UCHAR8 *)nbytes_str, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed "
                                              "for arg 1 for byte_extract");
        goto error;
    }
    if (StringParseUint8(&bed->nbytes, 10, 0,
                               (const char *)nbytes_str) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid value for number of bytes"
                   " to be extracted: \"%s\".", nbytes_str);
        goto error;
    }

    /* offset */
    char offset_str[64] = "";
    pcre2len = sizeof(offset_str);
    res = pcre2_substring_copy_bynumber(
            parse_regex.match, 2, (PCRE2_UCHAR8 *)offset_str, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed "
                                              "for arg 2 for byte_extract");
        goto error;
    }
    int32_t offset;
    if (StringParseI32RangeCheck(&offset, 10, 0, (const char *)offset_str, -65535, 65535) < 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid value for offset: \"%s\".", offset_str);
        goto error;
    }
    bed->offset = offset;

    /* var name */
    char varname_str[256] = "";
    pcre2len = sizeof(varname_str);
    res = pcre2_substring_copy_bynumber(
            parse_regex.match, 3, (PCRE2_UCHAR8 *)varname_str, &pcre2len);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_copy_bynumber failed "
                                              "for arg 3 for byte_extract");
        goto error;
    }
    bed->name = SCStrdup(varname_str);
    if (bed->name == NULL)
        goto error;

    /* check out other optional args */
    for (i = 4; i < ret; i++) {
        char opt_str[64] = "";
        pcre2len = sizeof(opt_str);
        res = SC_Pcre2SubstringCopy(parse_regex.match, i, (PCRE2_UCHAR8 *)opt_str, &pcre2len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                    "pcre2_substring_copy_bynumber failed "
                    "for arg %d for byte_extract with %d",
                    i, res);
            goto error;
        }

        if (strcmp("relative", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "relative specified more "
                           "than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_RELATIVE;
        } else if (strcmp("multiplier", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "multiplier specified more "
                           "than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER;
            i++;

            char multiplier_str[16] = "";
            pcre2len = sizeof(multiplier_str);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, i, (PCRE2_UCHAR8 *)multiplier_str, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                        "pcre2_substring_copy_bynumber failed "
                        "for arg %d for byte_extract",
                        i);
                goto error;
            }
            uint16_t multiplier;
            if (StringParseU16RangeCheck(&multiplier, 10, 0, (const char *)multiplier_str,
                        DETECT_BYTE_EXTRACT_MULTIPLIER_MIN_LIMIT,
                        DETECT_BYTE_EXTRACT_MULTIPLIER_MAX_LIMIT) < 0) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid value for"
                        "multiplier: \"%s\".", multiplier_str);
                goto error;
            }
            bed->multiplier_value = multiplier;
        } else if (strcmp("big", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "endian option specified "
                           "more than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_ENDIAN;
            bed->endian = DETECT_BYTE_EXTRACT_ENDIAN_BIG;
        } else if (strcmp("little", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "endian option specified "
                           "more than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_ENDIAN;
            bed->endian = DETECT_BYTE_EXTRACT_ENDIAN_LITTLE;
        } else if (strcmp("dce", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "endian option specified "
                           "more than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_ENDIAN;
            bed->endian = DETECT_BYTE_EXTRACT_ENDIAN_DCE;
        } else if (strcmp("string", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "string specified more "
                           "than once for byte_extract");
                goto error;
            }
            if (bed->base != DETECT_BYTE_EXTRACT_BASE_NONE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "The right way to specify "
                           "base is (string, base) and not (base, string) "
                           "for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_STRING;
        } else if (strcmp("hex", opt_str) == 0) {
            if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Base(hex) specified "
                           "without specifying string.  The right way is "
                           "(string, base) and not (base, string)");
                goto error;
            }
            if (bed->base != DETECT_BYTE_EXTRACT_BASE_NONE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "More than one base "
                           "specified for byte_extract");
                goto error;
            }
            bed->base = DETECT_BYTE_EXTRACT_BASE_HEX;
        } else if (strcmp("oct", opt_str) == 0) {
            if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Base(oct) specified "
                           "without specifying string.  The right way is "
                           "(string, base) and not (base, string)");
                goto error;
            }
            if (bed->base != DETECT_BYTE_EXTRACT_BASE_NONE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "More than one base "
                           "specified for byte_extract");
                goto error;
            }
            bed->base = DETECT_BYTE_EXTRACT_BASE_OCT;
        } else if (strcmp("dec", opt_str) == 0) {
            if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Base(dec) specified "
                           "without specifying string.  The right way is "
                           "(string, base) and not (base, string)");
                goto error;
            }
            if (bed->base != DETECT_BYTE_EXTRACT_BASE_NONE) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "More than one base "
                           "specified for byte_extract");
                goto error;
            }
            bed->base = DETECT_BYTE_EXTRACT_BASE_DEC;
        } else if (strcmp("align", opt_str) == 0) {
            if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_ALIGN) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Align specified more "
                           "than once for byte_extract");
                goto error;
            }
            bed->flags |= DETECT_BYTE_EXTRACT_FLAG_ALIGN;
            i++;

            char align_str[16] = "";
            pcre2len = sizeof(align_str);
            res = pcre2_substring_copy_bynumber(
                    parse_regex.match, i, (PCRE2_UCHAR8 *)align_str, &pcre2len);
            if (res < 0) {
                SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                        "pcre2_substring_copy_bynumber failed "
                        "for arg %d in byte_extract",
                        i);
                goto error;
            }
            if (StringParseUint8(&bed->align_value, 10, 0,
                                       (const char *)align_str) < 0) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid align_value: "
                           "\"%s\".", align_str);
                goto error;
            }
            if (!(bed->align_value == 2 || bed->align_value == 4)) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid align_value for "
                           "byte_extract - \"%d\"", bed->align_value);
                goto error;
            }
        } else if (strcmp("", opt_str) == 0) {
            ;
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Invalid option - \"%s\" "
                       "specified in byte_extract", opt_str);
            goto error;
        }
    } /* for (i = 4; i < ret; i++) */

    /* validation */
    if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER)) {
        /* default value */
        bed->multiplier_value = DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT;
    }

    if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
        if (bed->base == DETECT_BYTE_EXTRACT_BASE_NONE) {
            /* Default to decimal if base not specified. */
            bed->base = DETECT_BYTE_EXTRACT_BASE_DEC;
        }
        if (bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "byte_extract can't have "
                       "endian \"big\" or \"little\" specified along with "
                       "\"string\"");
            goto error;
        }
        if (bed->base == DETECT_BYTE_EXTRACT_BASE_OCT) {
            /* if are dealing with octal nos, the max no that can fit in a 8
             * byte value is 01777777777777777777777 */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                           STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT);
                goto error;
            }
        } else if (bed->base == DETECT_BYTE_EXTRACT_BASE_DEC) {
            /* if are dealing with decimal nos, the max no that can fit in a 8
             * byte value is 18446744073709551615 */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                           STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC);
                goto error;
            }
        } else if (bed->base == DETECT_BYTE_EXTRACT_BASE_HEX) {
            /* if are dealing with hex nos, the max no that can fit in a 8
             * byte value is 0xFFFFFFFFFFFFFFFF */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                           STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX);
                goto error;
            }
        } else {
            ; // just a placeholder.  we won't reach here.
        }
    } else {
        if (bed->nbytes > NO_STRING_MAX_BYTES_TO_EXTRACT) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "byte_extract can't process "
                       "more than %d bytes in \"non-string\" extraction",
                       NO_STRING_MAX_BYTES_TO_EXTRACT);
            goto error;
        }
        /* if string has not been specified and no endian option has been
         * specified, then set the default endian level of BIG */
        if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN))
            bed->endian = DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT;
    }

    return bed;
 error:
    if (bed != NULL)
        DetectByteExtractFree(de_ctx, bed);
    return NULL;
}

/**
 * \brief The setup function for the byte_extract keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatch for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectByteExtractSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SigMatch *sm = NULL;
    SigMatch *prev_pm = NULL;
    DetectByteExtractData *data = NULL;
    int ret = -1;

    data = DetectByteExtractParse(de_ctx, arg);
    if (data == NULL)
        goto error;

    int sm_list;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        sm_list = s->init_data->list;

        if (data->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE, -1);
        }
    } else if (data->endian == DETECT_BYTE_EXTRACT_ENDIAN_DCE) {
        if (data->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE,
                    DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                    DETECT_BYTEMATH, DETECT_ISDATAAT, -1);
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

        if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
            goto error;
        s->flags |= SIG_FLAG_APPLAYER;

    } else if (data->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE) {
        prev_pm = DetectGetLastSMFromLists(s,
                DETECT_CONTENT, DETECT_PCRE,
                DETECT_BYTETEST, DETECT_BYTEJUMP, DETECT_BYTE_EXTRACT,
                DETECT_BYTEMATH, DETECT_ISDATAAT, -1);
        if (prev_pm == NULL) {
            sm_list = DETECT_SM_LIST_PMATCH;
        } else {
            sm_list = SigMatchListSMBelongsTo(s, prev_pm);
            if (sm_list < 0)
                goto error;
            if (sm_list != DETECT_SM_LIST_PMATCH)
                s->flags |= SIG_FLAG_APPLAYER;
        }

    } else {
        sm_list = DETECT_SM_LIST_PMATCH;
    }

    if (data->endian == DETECT_BYTE_EXTRACT_ENDIAN_DCE) {
        if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0)
            goto error;

        if ((data->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            (data->base == DETECT_BYTE_EXTRACT_BASE_DEC) ||
            (data->base == DETECT_BYTE_EXTRACT_BASE_HEX) ||
            (data->base == DETECT_BYTE_EXTRACT_BASE_OCT) ) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "Invalid option. "
                       "A byte_jump keyword with dce holds other invalid modifiers.");
            goto error;
        }
    }

    SigMatch *prev_bed_sm = DetectGetLastSMByListId(s, sm_list,
            DETECT_BYTE_EXTRACT, -1);
    if (prev_bed_sm == NULL)
        data->local_id = 0;
    else
        data->local_id = ((DetectByteExtractData *)prev_bed_sm->ctx)->local_id + 1;
    if (data->local_id > de_ctx->byte_extract_max_local_id)
        de_ctx->byte_extract_max_local_id = data->local_id;


    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_BYTE_EXTRACT;
    sm->ctx = (void *)data;
    SigMatchAppendSMToList(s, sm, sm_list);


    if (!(data->flags & DETECT_BYTE_EXTRACT_FLAG_RELATIVE))
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
    DetectByteExtractFree(de_ctx, data);
    return ret;
}

/**
 * \brief Used to free instances of DetectByteExtractData.
 *
 * \param ptr Instance of DetectByteExtractData to be freed.
 */
static void DetectByteExtractFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        DetectByteExtractData *bed = ptr;
        if (bed->name != NULL)
            SCFree((void *)bed->name);
        SCFree(bed);
    }

    return;
}

/**
 * \brief Lookup the SigMatch for a named byte_extract variable.
 *
 * \param arg The name of the byte_extract variable to lookup.
 * \param s Pointer the signature to look in.
 *
 * \retval A pointer to the SigMatch if found, otherwise NULL.
 */
SigMatch *DetectByteExtractRetrieveSMVar(const char *arg, const Signature *s)
{
    const int nlists = s->init_data->smlists_array_size;
    for (int list = 0; list < nlists; list++) {
        SigMatch *sm = s->init_data->smlists[list];
        while (sm != NULL) {
            if (sm->type == DETECT_BYTE_EXTRACT) {
                const DetectByteExtractData *bed = (const DetectByteExtractData *)sm->ctx;
                if (strcmp(bed->name, arg) == 0) {
                    return sm;
                }
            }
            sm = sm->next;
        }
    }

    return NULL;
}

/*************************************Unittests********************************/

#ifdef UNITTESTS

static int g_file_data_buffer_id = 0;
static int g_http_uri_buffer_id = 0;

static int DetectByteExtractTest01(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != 0 ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest02(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, relative");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_RELATIVE ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest03(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, multiplier 10");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != 10) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest04(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, relative, multiplier 10");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != 10) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest05(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, big");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_BIG ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest06(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, little");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_LITTLE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest07(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, dce");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DCE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest08(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, hex");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest09(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, oct");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_OCT ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest10(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, dec");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_DEC ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest11(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_ALIGN ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest12(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN |
                       DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest13(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, big");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN |
                       DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                       DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_BIG ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest14(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, dce");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN |
                       DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                       DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DCE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest15(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, little");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN |
                       DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                       DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_LITTLE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest16(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, little, multiplier 2");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN |
                       DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                       DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_LITTLE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 4 ||
        bed->multiplier_value != 2) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest17(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "relative, little, "
                                                        "multiplier 2, string hex");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest18(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "relative, little, "
                                                        "multiplier 2, "
                                                        "relative");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest19(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "relative, little, "
                                                        "multiplier 2, "
                                                        "little");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest20(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "relative, "
                                                        "multiplier 2, "
                                                        "align 2");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest21(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "multiplier 2, "
                                                        "relative, "
                                                        "multiplier 2");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest22(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "string hex, "
                                                        "relative, "
                                                        "string hex");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest23(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "string hex, "
                                                        "relative, "
                                                        "string oct");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest24(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "24, 2, one, align 4, "
                                                        "string hex, "
                                                        "relative");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest25(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "9, 2, one, align 4, "
                                                        "little, "
                                                        "relative");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest26(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "little, "
                                                        "relative, "
                                                        "multiplier 65536");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest27(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
                                                        "little, "
                                                        "relative, "
                                                        "multiplier 0");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest28(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "23, 2, one, string, oct");
    if (bed == NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest29(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "24, 2, one, string, oct");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest30(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "20, 2, one, string, dec");
    if (bed == NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest31(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "21, 2, one, string, dec");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest32(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "14, 2, one, string, hex");
    if (bed == NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest33(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "15, 2, one, string, hex");
    if (bed != NULL)
        goto end;

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTest34(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,2,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strncmp(bed->name, "two", cd->content_len) != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest35(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectPcreData *pd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; pcre:/asf/; "
                                   "byte_extract:4,0,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_PCRE) {
        result = 0;
        goto end;
    }
    pd = (DetectPcreData *)sm->ctx;
    if (pd->flags != DETECT_PCRE_RELATIVE_NEXT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest36(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectBytejumpData *bjd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; byte_jump:1,13; "
                                   "byte_extract:4,0,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest37(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; uricontent:\"two\"; "
                                   "byte_extract:4,0,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)ud->content, "two", cd->content_len) != 0 ||
        ud->flags & DETECT_CONTENT_NOCASE ||
        ud->flags & DETECT_CONTENT_WITHIN ||
        ud->flags & DETECT_CONTENT_DISTANCE ||
        ud->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(ud->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        ud->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest38(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; uricontent:\"two\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags !=DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)ud->content, "two", cd->content_len) != 0 ||
        ud->flags & DETECT_CONTENT_NOCASE ||
        ud->flags & DETECT_CONTENT_WITHIN ||
        ud->flags & DETECT_CONTENT_DISTANCE ||
        ud->flags & DETECT_CONTENT_FAST_PATTERN ||
        ud->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        ud->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        result = 0;
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest39(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; content:\"two\"; http_uri; "
                                   "byte_extract:4,0,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)ud->content, "two", cd->content_len) != 0 ||
        ud->flags & DETECT_CONTENT_NOCASE ||
        ud->flags & DETECT_CONTENT_WITHIN ||
        ud->flags & DETECT_CONTENT_DISTANCE ||
        ud->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(ud->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        ud->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest40(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; content:\"two\"; http_uri; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags !=DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)ud->content, "two", cd->content_len) != 0 ||
        ud->flags & DETECT_CONTENT_NOCASE ||
        ud->flags & DETECT_CONTENT_WITHIN ||
        ud->flags & DETECT_CONTENT_DISTANCE ||
        ud->flags & DETECT_CONTENT_FAST_PATTERN ||
        ud->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        ud->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        result = 0;
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest41(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "three") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 1) {
        result = 0;
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest42(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "uricontent: \"three\"; "
                                   "byte_extract:4,0,four,string,hex,relative; "
                                   "byte_extract:4,0,five,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "five") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 1) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    ud = (DetectContentData *)sm->ctx;
    if (ud->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)ud->content, "three", cd->content_len) != 0 ||
        ud->flags & DETECT_CONTENT_NOCASE ||
        ud->flags & DETECT_CONTENT_WITHIN ||
        ud->flags & DETECT_CONTENT_DISTANCE ||
        ud->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(ud->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        ud->flags & DETECT_CONTENT_NEGATED ) {
        printf("two failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "four") != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                       DETECT_BYTE_EXTRACT_FLAG_STRING) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest43(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "content: \"three\"; offset:two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "three", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_OFFSET_VAR |
                      DETECT_CONTENT_OFFSET) ||
        cd->offset != bed->local_id) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest44(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "content: \"four\"; offset:two; "
                                   "content: \"five\"; offset:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_OFFSET_VAR |
                      DETECT_CONTENT_OFFSET) ||
        cd->offset != bed1->local_id) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "five", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_OFFSET_VAR |
                      DETECT_CONTENT_OFFSET) ||
        cd->offset != bed2->local_id) {
        printf("five failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest45(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "content: \"three\"; depth:two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "three", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DEPTH_VAR |
                      DETECT_CONTENT_DEPTH) ||
        cd->depth != bed->local_id ||
        cd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest46(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "content: \"four\"; depth:two; "
                                   "content: \"five\"; depth:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DEPTH_VAR |
                      DETECT_CONTENT_DEPTH) ||
        cd->depth != bed1->local_id) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "five", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DEPTH_VAR |
                      DETECT_CONTENT_DEPTH) ||
        cd->depth != bed2->local_id) {
        printf("five failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest47(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "content: \"three\"; distance:two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "three", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_DISTANCE) ||
        cd->distance != bed->local_id ||
        cd->offset != 0 ||
        cd->depth != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest48(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "content: \"four\"; distance:two; "
                                   "content: \"five\"; distance:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_DISTANCE |
                      DETECT_CONTENT_DISTANCE_NEXT) ||
        cd->distance != bed1->local_id ||
        cd->depth != 0 ||
        cd->offset != 0) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "five", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_DISTANCE) ||
        cd->distance != bed2->local_id ||
        cd->depth != 0 ||
        cd->offset != 0) {
        printf("five failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest49(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "content: \"three\"; within:two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "three", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_WITHIN) ||
        cd->within != bed->local_id ||
        cd->offset != 0 ||
        cd->depth != 0 ||
        cd->distance != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest50(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "content: \"four\"; within:two; "
                                   "content: \"five\"; within:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_WITHIN|
                      DETECT_CONTENT_WITHIN_NEXT) ||
        cd->within != bed1->local_id ||
        cd->depth != 0 ||
        cd->offset != 0 ||
        cd->distance != 0) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "five", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_WITHIN) ||
        cd->within != bed2->local_id ||
        cd->depth != 0 ||
        cd->offset != 0 ||
        cd->distance != 0) {
        printf("five failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest51(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_test: 2,=,10, two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags != DETECT_BYTETEST_OFFSET_VAR ||
        btd->value != 10 ||
        btd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest52(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectBytetestData *btd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_test: 2,=,two,three; "
                                   "byte_test: 3,=,10,three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags != (DETECT_BYTETEST_OFFSET_VAR |
                       DETECT_BYTETEST_VALUE_VAR) ||
        btd->value != 0 ||
        btd->offset != 1) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTETEST) {
        result = 0;
        goto end;
    }
    btd = (DetectBytetestData *)sm->ctx;
    if (btd->flags != DETECT_BYTETEST_OFFSET_VAR ||
        btd->value != 10 ||
        btd->offset != 1) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest53(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed = NULL;
    DetectBytejumpData *bjd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_jump: 2,two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 0 ||
        strcmp(bed->name, "two") != 0 ||
        bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest54(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectBytejumpData *bjd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_jump: 2,two; "
                                   "byte_jump: 3,three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 1) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest55(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing byte_extract\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_extract:4,0,four,string,hex; "
                                   "byte_extract:4,0,five,string,hex; "
                                   "content: \"four\"; within:two; distance:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed: ");
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_DISTANCE |
                      DETECT_CONTENT_WITHIN) ||
        cd->within != bed1->local_id ||
        cd->distance != bed2->local_id) {
        printf("four failed: ");
        goto end;
    }

    if (sm->next != NULL) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest56(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "uricontent:\"urione\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_extract:4,0,four,string,hex; "
                                   "byte_extract:4,0,five,string,hex; "
                                   "content: \"four\"; within:two; distance:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "urione", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_DISTANCE |
                      DETECT_CONTENT_WITHIN) ||
        cd->within != bed1->local_id ||
        cd->distance != bed2->local_id ) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest57(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectByteExtractData *bed2 = NULL;
    DetectByteExtractData *bed3 = NULL;
    DetectByteExtractData *bed4 = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "uricontent: \"urione\"; "
                                   "byte_extract:4,0,two,string,hex,relative; "
                                   "byte_extract:4,0,three,string,hex,relative; "
                                   "byte_extract:4,0,four,string,hex,relative; "
                                   "byte_extract:4,0,five,string,hex,relative; "
                                   "uricontent: \"four\"; within:two; distance:three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "urione", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING |
                        DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed2 = (DetectByteExtractData *)sm->ctx;
    if (bed2->local_id != 1) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed3 = (DetectByteExtractData *)sm->ctx;
    if (bed3->local_id != 2) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed4 = (DetectByteExtractData *)sm->ctx;
    if (bed4->local_id != 3) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
        cd->flags != (DETECT_CONTENT_DISTANCE_VAR |
                      DETECT_CONTENT_WITHIN_VAR |
                      DETECT_CONTENT_DISTANCE |
                      DETECT_CONTENT_WITHIN) ||
        cd->within != bed1->local_id ||
        cd->distance != bed2->local_id)  {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest58(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectBytejumpData *bjd = NULL;
    DetectIsdataatData *isdd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_jump: 2,two; "
                                   "byte_jump: 3,three; "
                                   "isdataat: three; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 1) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_ISDATAAT) {
        result = 0;
        goto end;
    }
    isdd = (DetectIsdataatData *)sm->ctx;
    if (isdd->flags != ISDATAAT_OFFSET_VAR ||
        isdd->dataat != 1) {
        printf("isdataat failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest59(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectBytejumpData *bjd = NULL;
    DetectIsdataatData *isdd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex; "
                                   "byte_extract:4,0,three,string,hex; "
                                   "byte_jump: 2,two; "
                                   "byte_jump: 3,three; "
                                   "isdataat: three,relative; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        cd->flags & DETECT_CONTENT_RELATIVE_NEXT ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != DETECT_BYTE_EXTRACT_FLAG_STRING ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 0) {
        printf("three failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTEJUMP) {
        result = 0;
        goto end;
    }
    bjd = (DetectBytejumpData *)sm->ctx;
    if (bjd->flags != DETECT_CONTENT_OFFSET_VAR ||
        bjd->offset != 1) {
        printf("four failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_ISDATAAT) {
        result = 0;
        goto end;
    }
    isdd = (DetectIsdataatData *)sm->ctx;
    if (isdd->flags != (ISDATAAT_OFFSET_VAR |
                        ISDATAAT_RELATIVE) ||
        isdd->dataat != 1) {
        printf("isdataat failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest60(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectIsdataatData *isdd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex,relative; "
                                   "uricontent: \"three\"; "
                                   "byte_extract:4,0,four,string,hex,relative; "
                                   "isdataat: two; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING |
                        DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_ISDATAAT) {
        result = 0;
        goto end;
    }
    isdd = (DetectIsdataatData *)sm->ctx;
    if (isdd->flags != (ISDATAAT_OFFSET_VAR) ||
        isdd->dataat != bed1->local_id) {
        printf("isdataat failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    if (s->sm_lists_tail[g_http_uri_buffer_id] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        strncmp((char *)cd->content, "three", cd->content_len) != 0) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "four") != 0 ||
        bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING |
                        DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest61(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteExtractData *bed1 = NULL;
    DetectIsdataatData *isdd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"Testing bytejump_body\"; "
                                   "content:\"one\"; "
                                   "byte_extract:4,0,two,string,hex,relative; "
                                   "uricontent: \"three\"; "
                                   "byte_extract:4,0,four,string,hex,relative; "
                                   "isdataat: four, relative; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES ||
        strncmp((char *)cd->content, "one", cd->content_len) != 0 ||
        cd->flags & DETECT_CONTENT_NOCASE ||
        cd->flags & DETECT_CONTENT_WITHIN ||
        cd->flags & DETECT_CONTENT_DISTANCE ||
        cd->flags & DETECT_CONTENT_FAST_PATTERN ||
        !(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) ||
        cd->flags & DETECT_CONTENT_NEGATED ) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "two") != 0 ||
        bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING |
                        DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    if (s->sm_lists_tail[g_http_uri_buffer_id] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->sm_lists[g_http_uri_buffer_id];
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags != DETECT_CONTENT_RELATIVE_NEXT ||
        strncmp((char *)cd->content, "three", cd->content_len) != 0) {
        printf("one failed\n");
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed1 = (DetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 ||
        bed1->offset != 0 ||
        strcmp(bed1->name, "four") != 0 ||
        bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING |
                        DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed1->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed1->align_value != 0 ||
        bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_ISDATAAT) {
        result = 0;
        goto end;
    }
    isdd = (DetectIsdataatData *)sm->ctx;
    if (isdd->flags != (ISDATAAT_OFFSET_VAR |
                        ISDATAAT_RELATIVE) ||
        isdd->dataat != bed1->local_id) {
        printf("isdataat failed\n");
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest62(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectByteExtractData *bed = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                   "(file_data; byte_extract:4,2,two,relative,string,hex; "
                                   "sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    if (s->sm_lists_tail[g_file_data_buffer_id] == NULL) {
        goto end;
    }

    sm = s->sm_lists[g_file_data_buffer_id];
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed = (DetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 ||
        bed->offset != 2 ||
        strncmp(bed->name, "two", 3) != 0 ||
        bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_HEX ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

static int DetectByteExtractTest63(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, -2, one");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 ||
        bed->offset != -2 ||
        strcmp(bed->name, "one") != 0 ||
        bed->flags != 0 ||
        bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_DEFAULT ||
        bed->base != DETECT_BYTE_EXTRACT_BASE_NONE ||
        bed->align_value != 0 ||
        bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static int DetectByteExtractTestParseNoBase(void)
{
    int result = 0;

    DetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4) {
        goto end;
    }
    if (bed->offset != 2) {
        goto end;
    }
    if (strcmp(bed->name, "one") != 0) {
        goto end;
    }
    if (bed->flags != DETECT_BYTE_EXTRACT_FLAG_STRING) {
        goto end;
    }
    if (bed->endian != DETECT_BYTE_EXTRACT_ENDIAN_NONE) {
        goto end;
    }
    if (bed->base != DETECT_BYTE_EXTRACT_BASE_DEC) {
        goto end;
    }
    if (bed->align_value != 0) {
        goto end;
    }
    if (bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    result = 1;
 end:
    if (bed != NULL)
        DetectByteExtractFree(NULL, bed);
    return result;
}

static void DetectByteExtractRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_http_uri_buffer_id = DetectBufferTypeGetByName("http_uri");

    UtRegisterTest("DetectByteExtractTest01", DetectByteExtractTest01);
    UtRegisterTest("DetectByteExtractTest02", DetectByteExtractTest02);
    UtRegisterTest("DetectByteExtractTest03", DetectByteExtractTest03);
    UtRegisterTest("DetectByteExtractTest04", DetectByteExtractTest04);
    UtRegisterTest("DetectByteExtractTest05", DetectByteExtractTest05);
    UtRegisterTest("DetectByteExtractTest06", DetectByteExtractTest06);
    UtRegisterTest("DetectByteExtractTest07", DetectByteExtractTest07);
    UtRegisterTest("DetectByteExtractTest08", DetectByteExtractTest08);
    UtRegisterTest("DetectByteExtractTest09", DetectByteExtractTest09);
    UtRegisterTest("DetectByteExtractTest10", DetectByteExtractTest10);
    UtRegisterTest("DetectByteExtractTest11", DetectByteExtractTest11);
    UtRegisterTest("DetectByteExtractTest12", DetectByteExtractTest12);
    UtRegisterTest("DetectByteExtractTest13", DetectByteExtractTest13);
    UtRegisterTest("DetectByteExtractTest14", DetectByteExtractTest14);
    UtRegisterTest("DetectByteExtractTest15", DetectByteExtractTest15);
    UtRegisterTest("DetectByteExtractTest16", DetectByteExtractTest16);
    UtRegisterTest("DetectByteExtractTest17", DetectByteExtractTest17);
    UtRegisterTest("DetectByteExtractTest18", DetectByteExtractTest18);
    UtRegisterTest("DetectByteExtractTest19", DetectByteExtractTest19);
    UtRegisterTest("DetectByteExtractTest20", DetectByteExtractTest20);
    UtRegisterTest("DetectByteExtractTest21", DetectByteExtractTest21);
    UtRegisterTest("DetectByteExtractTest22", DetectByteExtractTest22);
    UtRegisterTest("DetectByteExtractTest23", DetectByteExtractTest23);
    UtRegisterTest("DetectByteExtractTest24", DetectByteExtractTest24);
    UtRegisterTest("DetectByteExtractTest25", DetectByteExtractTest25);
    UtRegisterTest("DetectByteExtractTest26", DetectByteExtractTest26);
    UtRegisterTest("DetectByteExtractTest27", DetectByteExtractTest27);
    UtRegisterTest("DetectByteExtractTest28", DetectByteExtractTest28);
    UtRegisterTest("DetectByteExtractTest29", DetectByteExtractTest29);
    UtRegisterTest("DetectByteExtractTest30", DetectByteExtractTest30);
    UtRegisterTest("DetectByteExtractTest31", DetectByteExtractTest31);
    UtRegisterTest("DetectByteExtractTest32", DetectByteExtractTest32);
    UtRegisterTest("DetectByteExtractTest33", DetectByteExtractTest33);
    UtRegisterTest("DetectByteExtractTest34", DetectByteExtractTest34);
    UtRegisterTest("DetectByteExtractTest35", DetectByteExtractTest35);
    UtRegisterTest("DetectByteExtractTest36", DetectByteExtractTest36);
    UtRegisterTest("DetectByteExtractTest37", DetectByteExtractTest37);
    UtRegisterTest("DetectByteExtractTest38", DetectByteExtractTest38);
    UtRegisterTest("DetectByteExtractTest39", DetectByteExtractTest39);
    UtRegisterTest("DetectByteExtractTest40", DetectByteExtractTest40);
    UtRegisterTest("DetectByteExtractTest41", DetectByteExtractTest41);
    UtRegisterTest("DetectByteExtractTest42", DetectByteExtractTest42);

    UtRegisterTest("DetectByteExtractTest43", DetectByteExtractTest43);
    UtRegisterTest("DetectByteExtractTest44", DetectByteExtractTest44);

    UtRegisterTest("DetectByteExtractTest45", DetectByteExtractTest45);
    UtRegisterTest("DetectByteExtractTest46", DetectByteExtractTest46);

    UtRegisterTest("DetectByteExtractTest47", DetectByteExtractTest47);
    UtRegisterTest("DetectByteExtractTest48", DetectByteExtractTest48);

    UtRegisterTest("DetectByteExtractTest49", DetectByteExtractTest49);
    UtRegisterTest("DetectByteExtractTest50", DetectByteExtractTest50);

    UtRegisterTest("DetectByteExtractTest51", DetectByteExtractTest51);
    UtRegisterTest("DetectByteExtractTest52", DetectByteExtractTest52);

    UtRegisterTest("DetectByteExtractTest53", DetectByteExtractTest53);
    UtRegisterTest("DetectByteExtractTest54", DetectByteExtractTest54);

    UtRegisterTest("DetectByteExtractTest55", DetectByteExtractTest55);
    UtRegisterTest("DetectByteExtractTest56", DetectByteExtractTest56);
    UtRegisterTest("DetectByteExtractTest57", DetectByteExtractTest57);

    UtRegisterTest("DetectByteExtractTest58", DetectByteExtractTest58);
    UtRegisterTest("DetectByteExtractTest59", DetectByteExtractTest59);
    UtRegisterTest("DetectByteExtractTest60", DetectByteExtractTest60);
    UtRegisterTest("DetectByteExtractTest61", DetectByteExtractTest61);
    UtRegisterTest("DetectByteExtractTest62", DetectByteExtractTest62);
    UtRegisterTest("DetectByteExtractTest63", DetectByteExtractTest63);

    UtRegisterTest("DetectByteExtractTestParseNoBase",
                   DetectByteExtractTestParseNoBase);
}
#endif /* UNITTESTS */
