/* Copyright (C) 2007-2024 Open Information Security Foundation
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
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-bytejump.h"
#include "detect-bytetest.h"
#include "detect-byte-extract.h"
#include "detect-isdataat.h"
#include "detect-engine-build.h"

#include "rust.h"

#include "app-layer-protos.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

/* the base to be used if string mode is specified.  These options would be
 * specified in DetectByteParseData->base */
#define DETECT_BYTE_EXTRACT_BASE_HEX BaseHex
#define DETECT_BYTE_EXTRACT_BASE_DEC BaseDec
#define DETECT_BYTE_EXTRACT_BASE_OCT BaseOct

/* the max no of bytes that can be extracted in string mode - (string, hex)
 * (string, oct) or (string, dec) */
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT 23
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC 20
#define STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX 14
/* the max no of bytes that can be extracted in non-string mode */
#define NO_STRING_MAX_BYTES_TO_EXTRACT 8

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
}

int DetectByteExtractDoMatch(DetectEngineThreadCtx *det_ctx, const SigMatchData *smd,
        const Signature *s, const uint8_t *payload, uint32_t payload_len, uint64_t *value,
        uint8_t endian)
{
    if (payload_len == 0) {
        return 0;
    }

    /* Calculate the ptr value for the bytetest and length remaining in
     * the packet from that point.
     */
    const uint8_t *ptr;
    int32_t len;
    SCDetectByteExtractData *data = (SCDetectByteExtractData *)smd->ctx;
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
    uint64_t val = 0;
    int extbytes;
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
        int endianness = (endian == BigEndian) ? BYTE_BIG_ENDIAN : BYTE_LITTLE_ENDIAN;
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
static inline SCDetectByteExtractData *DetectByteExtractParse(
        DetectEngineCtx *de_ctx, const char *arg)
{
    SCDetectByteExtractData *bed = SCByteExtractParse(arg);
    if (bed == NULL) {
        SCLogError("invalid byte_extract values");
        goto error;
    }

    if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_SLICE) {
        SCLogError("byte_extract slice not yet supported; see issue #6831");
        goto error;
    }
    if (bed->flags & DETECT_BYTE_EXTRACT_FLAG_STRING) {
        if (bed->base == DETECT_BYTE_EXTRACT_BASE_OCT) {
            /* if are dealing with octal nos, the max no that can fit in a 8
             * byte value is 01777777777777777777777 */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT) {
                SCLogError("byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                        STRING_MAX_BYTES_TO_EXTRACT_FOR_OCT);
                goto error;
            }
        } else if (bed->base == DETECT_BYTE_EXTRACT_BASE_DEC) {
            /* if are dealing with decimal nos, the max no that can fit in a 8
             * byte value is 18446744073709551615 */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC) {
                SCLogError("byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                        STRING_MAX_BYTES_TO_EXTRACT_FOR_DEC);
                goto error;
            }
        } else if (bed->base == DETECT_BYTE_EXTRACT_BASE_HEX) {
            /* if are dealing with hex nos, the max no that can fit in a 8
             * byte value is 0xFFFFFFFFFFFFFFFF */
            if (bed->nbytes > STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX) {
                SCLogError("byte_extract can't process "
                           "more than %d bytes in \"string\" extraction",
                        STRING_MAX_BYTES_TO_EXTRACT_FOR_HEX);
                goto error;
            }
        } else {
            ; // just a placeholder.  we won't reach here.
        }
    } else {
        if (bed->nbytes > NO_STRING_MAX_BYTES_TO_EXTRACT) {
            SCLogError("byte_extract can't process "
                       "more than %d bytes in \"non-string\" extraction",
                    NO_STRING_MAX_BYTES_TO_EXTRACT);
            goto error;
        }
        /* if string has not been specified and no endian option has been
         * specified, then set the default endian level of BIG */
        if (!(bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN))
            bed->endian = BigEndian;
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
    SigMatch *prev_pm = NULL;
    SCDetectByteExtractData *data = NULL;
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
    } else if (data->endian == EndianDCE) {
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
        }

    } else {
        sm_list = DETECT_SM_LIST_PMATCH;
    }

    if (data->endian == EndianDCE) {
        if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0)
            goto error;

        if ((DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING) ==
                (data->flags & (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING))) {
            SCLogError("Invalid option. "
                       "A byte_jump keyword with dce holds other invalid modifiers.");
            goto error;
        }
    }

    SigMatch *prev_bed_sm = DetectGetLastSMByListId(s, sm_list,
            DETECT_BYTE_EXTRACT, -1);
    if (prev_bed_sm == NULL)
        data->local_id = 0;
    else
        data->local_id = ((SCDetectByteExtractData *)prev_bed_sm->ctx)->local_id + 1;
    if (data->local_id > de_ctx->byte_extract_max_local_id)
        de_ctx->byte_extract_max_local_id = data->local_id;

    if (SigMatchAppendSMToList(de_ctx, s, DETECT_BYTE_EXTRACT, (SigMatchCtx *)data, sm_list) ==
            NULL) {
        goto error;
    }

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
 * \brief Used to free instances of SCDetectByteExtractData.
 *
 * \param ptr Instance of SCDetectByteExtractData to be freed.
 */
static void DetectByteExtractFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCByteExtractFree(ptr);
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
    for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
        SigMatch *sm = s->init_data->buffers[x].head;
        while (sm != NULL) {
            if (sm->type == DETECT_BYTE_EXTRACT) {
                const SCDetectByteExtractData *bed = (const SCDetectByteExtractData *)sm->ctx;
                if (strcmp(bed->name, arg) == 0) {
                    return sm;
                }
            }
            sm = sm->next;
        }
    }

    for (int list = 0; list < DETECT_SM_LIST_MAX; list++) {
        SigMatch *sm = s->init_data->smlists[list];
        while (sm != NULL) {
            if (sm->type == DETECT_BYTE_EXTRACT) {
                const SCDetectByteExtractData *bed = (const SCDetectByteExtractData *)sm->ctx;
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 || bed->flags != 0 ||
            bed->endian != BigEndian || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, relative");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_RELATIVE || bed->endian != BigEndian ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, multiplier 10");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER || bed->endian != BigEndian ||
            bed->align_value != 0 || bed->multiplier_value != 10) {
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

    SCDetectByteExtractData *bed =
            DetectByteExtractParse(NULL, "4, 2, one, relative, multiplier 10");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags !=
                    (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) ||
            bed->endian != BigEndian || bed->align_value != 0 || bed->multiplier_value != 10) {
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, big");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN || bed->endian != BigEndian ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, little");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN || bed->endian != LittleEndian ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, dce");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_ENDIAN || bed->endian != EndianDCE ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, hex");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, oct");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_OCT || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string, dec");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_DEC || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != DETECT_BYTE_EXTRACT_FLAG_ALIGN || bed->endian != BigEndian ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, relative");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN | DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed->endian != BigEndian || bed->align_value != 4 ||
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

    SCDetectByteExtractData *bed =
            DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, big");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN | DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                                  DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed->endian != BigEndian || bed->align_value != 4 ||
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

    SCDetectByteExtractData *bed =
            DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, dce");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN | DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                                  DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed->endian != EndianDCE || bed->align_value != 4 ||
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

    SCDetectByteExtractData *bed =
            DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, little");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN | DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                                  DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed->endian != LittleEndian || bed->align_value != 4 ||
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

    SCDetectByteExtractData *bed =
            DetectByteExtractParse(NULL, "4, 2, one, align 4, relative, little, multiplier 2");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != 2 || strcmp(bed->name, "one") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_ALIGN | DETECT_BYTE_EXTRACT_FLAG_RELATIVE |
                                  DETECT_BYTE_EXTRACT_FLAG_ENDIAN |
                                  DETECT_BYTE_EXTRACT_FLAG_MULTIPLIER) ||
            bed->endian != LittleEndian || bed->align_value != 4 || bed->multiplier_value != 2) {
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "24, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "9, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, align 4, "
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "23, 2, one, string, oct");
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "24, 2, one, string, oct");
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "20, 2, one, string, dec");
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "21, 2, one, string, dec");
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "14, 2, one, string, hex");
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "15, 2, one, string, hex");
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 2 || strncmp(bed->name, "two", cd->content_len) != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                                 "content:\"one\"; byte_jump:1,13; "
                                                 "byte_extract:4,0,two,relative,string,hex; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]);

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF(sm->type != DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF(cd->flags & DETECT_CONTENT_RAWBYTES);
    FAIL_IF(strncmp((char *)cd->content, "one", cd->content_len) != 0);
    FAIL_IF(cd->flags & DETECT_CONTENT_NOCASE);
    FAIL_IF(cd->flags & DETECT_CONTENT_WITHIN);
    FAIL_IF(cd->flags & DETECT_CONTENT_DISTANCE);
    FAIL_IF(cd->flags & DETECT_CONTENT_FAST_PATTERN);
    FAIL_IF(cd->flags & DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF(cd->flags & DETECT_CONTENT_NEGATED);

    sm = sm->next;
    FAIL_IF(sm->type != DETECT_BYTEJUMP);
    DetectBytejumpData *bjd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF(bjd->flags != 0);
    sm = sm->next;
    FAIL_IF(sm->type != DETECT_BYTE_EXTRACT);
    SCDetectByteExtractData *bed = (SCDetectByteExtractData *)sm->ctx;
    FAIL_IF(bed->nbytes != 4);
    FAIL_IF(bed->offset != 0);
    FAIL_IF(strcmp(bed->name, "two") != 0);
    FAIL_IF(bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING));
    FAIL_IF(bed->base != DETECT_BYTE_EXTRACT_BASE_HEX);
    FAIL_IF(bed->align_value != 0);
    FAIL_IF(bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectByteExtractTest37(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
            bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
            bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "three") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "five") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
            bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed->local_id != 1) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "four") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_RELATIVE | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
            cd->flags != (DETECT_CONTENT_OFFSET_VAR | DETECT_CONTENT_OFFSET | DETECT_CONTENT_MPM) ||
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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
            cd->flags != (DETECT_CONTENT_OFFSET_VAR | DETECT_CONTENT_OFFSET | DETECT_CONTENT_MPM) ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
            cd->flags != (DETECT_CONTENT_DEPTH_VAR | DETECT_CONTENT_DEPTH | DETECT_CONTENT_MPM) ||
            cd->depth != bed->local_id || cd->offset != 0) {
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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
            cd->flags != (DETECT_CONTENT_DEPTH_VAR | DETECT_CONTENT_DEPTH | DETECT_CONTENT_MPM) ||
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
            cd->flags !=
                    (DETECT_CONTENT_DISTANCE_VAR | DETECT_CONTENT_DISTANCE | DETECT_CONTENT_MPM) ||
            cd->distance != bed->local_id || cd->offset != 0 || cd->depth != 0) {
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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
            cd->flags != (DETECT_CONTENT_DISTANCE_VAR | DETECT_CONTENT_DISTANCE |
                                 DETECT_CONTENT_DISTANCE_NEXT | DETECT_CONTENT_MPM) ||
            cd->distance != bed1->local_id || cd->depth != 0 || cd->offset != 0) {
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
    SCDetectByteExtractData *bed = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
            cd->flags != (DETECT_CONTENT_WITHIN_VAR | DETECT_CONTENT_WITHIN | DETECT_CONTENT_MPM) ||
            cd->within != bed->local_id || cd->offset != 0 || cd->depth != 0 || cd->distance != 0) {
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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

    sm = sm->next;
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (strncmp((char *)cd->content, "four", cd->content_len) != 0 ||
            cd->flags != (DETECT_CONTENT_WITHIN_VAR | DETECT_CONTENT_WITHIN |
                                 DETECT_CONTENT_WITHIN_NEXT | DETECT_CONTENT_MPM) ||
            cd->within != bed1->local_id || cd->depth != 0 || cd->offset != 0 ||
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
    SCDetectByteExtractData *bed = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 0 || strcmp(bed->name, "two") != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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
    SCDetectByteExtractData *bed1 = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                                 "content:\"one\"; "
                                                 "byte_extract:4,0,two,string,hex; "
                                                 "byte_jump: 2,two; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NULL(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]);

    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF(sm->type != DETECT_CONTENT);
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF(cd->flags != (DETECT_CONTENT_MPM | DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED));

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTE_EXTRACT);
    SCDetectByteExtractData *bed = (SCDetectByteExtractData *)sm->ctx;

    FAIL_IF(bed->nbytes != 4);
    FAIL_IF(bed->offset != 0);
    FAIL_IF(strcmp(bed->name, "two") != 0);
    FAIL_IF(bed->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING));
    FAIL_IF(bed->base != DETECT_BYTE_EXTRACT_BASE_HEX);
    FAIL_IF(bed->align_value != 0);
    FAIL_IF(bed->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT);
    FAIL_IF(bed->local_id != 0);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTEJUMP);
    DetectBytejumpData *bjd = (DetectBytejumpData *)sm->ctx;

    FAIL_IF(bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR);
    FAIL_IF(bjd->offset != 0);

    FAIL_IF_NOT_NULL(sm->next);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectByteExtractTest54(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    SCDetectByteExtractData *bed1 = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    if (bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR || bjd->offset != 0) {
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
    FAIL_IF(bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR);
    FAIL_IF(bjd->offset != 1);

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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

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
            cd->flags !=
                    (DETECT_CONTENT_DISTANCE_VAR | DETECT_CONTENT_WITHIN_VAR |
                            DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN | DETECT_CONTENT_MPM) ||
            cd->within != bed1->local_id || cd->distance != bed2->local_id) {
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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;

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
    SCDetectByteExtractData *bed1 = NULL;
    SCDetectByteExtractData *bed2 = NULL;
    SCDetectByteExtractData *bed3 = NULL;
    SCDetectByteExtractData *bed4 = NULL;

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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                   DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    bed2 = (SCDetectByteExtractData *)sm->ctx;
    if (bed2->local_id != 1) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed3 = (SCDetectByteExtractData *)sm->ctx;
    if (bed3->local_id != 2) {
        result = 0;
        goto end;
    }

    sm = sm->next;
    if (sm->type != DETECT_BYTE_EXTRACT) {
        result = 0;
        goto end;
    }
    bed4 = (SCDetectByteExtractData *)sm->ctx;
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
    SCDetectByteExtractData *bed1 = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    if (bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR || bjd->offset != 0) {
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
    if (bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR || bjd->offset != 1) {
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
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any ("
                                                 "content:\"one\"; "
                                                 "byte_extract:4,0,two,string,hex; "
                                                 "byte_extract:4,0,three,string,hex; "
                                                 "byte_jump: 2,two; "
                                                 "byte_jump: 3,three; "
                                                 "isdataat: three,relative; "
                                                 "sid:1;)");
    FAIL_IF_NULL(s);

    FAIL_IF_NULL(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH]);
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF(sm->type != DETECT_CONTENT);

    DetectContentData *cd = (DetectContentData *)sm->ctx;
    FAIL_IF(cd->flags & DETECT_CONTENT_RAWBYTES);
    FAIL_IF(strncmp((char *)cd->content, "one", cd->content_len) != 0);
    FAIL_IF(cd->flags & DETECT_CONTENT_NOCASE);
    FAIL_IF(cd->flags & DETECT_CONTENT_WITHIN);
    FAIL_IF(cd->flags & DETECT_CONTENT_DISTANCE);
    FAIL_IF(cd->flags & DETECT_CONTENT_FAST_PATTERN);
    FAIL_IF(cd->flags & DETECT_CONTENT_RELATIVE_NEXT);
    FAIL_IF(cd->flags & DETECT_CONTENT_NEGATED);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTE_EXTRACT);

    SCDetectByteExtractData *bed1 = (SCDetectByteExtractData *)sm->ctx;
    FAIL_IF(bed1->nbytes != 4);
    FAIL_IF(bed1->offset != 0);
    FAIL_IF(strcmp(bed1->name, "two") != 0);
    printf("a\n");
    FAIL_IF(bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_BASE | DETECT_BYTE_EXTRACT_FLAG_STRING));
    printf("b\n");
    FAIL_IF(bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX);
    FAIL_IF(bed1->align_value != 0);
    FAIL_IF(bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT);

    FAIL_IF(bed1->local_id != 0);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTE_EXTRACT);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTEJUMP);

    DetectBytejumpData *bjd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF(bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR);
    FAIL_IF(bjd->offset != 0);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_BYTEJUMP);

    bjd = (DetectBytejumpData *)sm->ctx;
    FAIL_IF(bjd->flags != DETECT_BYTEJUMP_OFFSET_VAR);
    FAIL_IF(bjd->offset != 1);

    sm = sm->next;
    FAIL_IF_NULL(sm);
    FAIL_IF(sm->type != DETECT_ISDATAAT);
    DetectIsdataatData *isdd = (DetectIsdataatData *)sm->ctx;
    FAIL_IF(isdd->flags != (ISDATAAT_OFFSET_VAR | ISDATAAT_RELATIVE));
    FAIL_IF(isdd->dataat != 1);

    FAIL_IF(sm->next != NULL);
    DetectEngineCtxFree(de_ctx);

    PASS;
}

static int DetectByteExtractTest60(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    SCDetectByteExtractData *bed1 = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                   DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
    if (sm == NULL) {
        result = 0;
        goto end;
    }
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_MPM) ||
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "four") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                   DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    SCDetectByteExtractData *bed1 = NULL;
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

    if (s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL) {
        result = 0;
        goto end;
    }

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "two") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                   DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
            bed1->multiplier_value != DETECT_BYTE_EXTRACT_MULTIPLIER_DEFAULT) {
        goto end;
    }
    if (bed1->local_id != 0) {
        result = 0;
        goto end;
    }

    if (sm->next != NULL)
        goto end;

    sm = DetectBufferGetFirstSigMatch(s, g_http_uri_buffer_id);
    if (sm == NULL) {
        result = 0;
        goto end;
    }
    if (sm->type != DETECT_CONTENT) {
        result = 0;
        goto end;
    }
    cd = (DetectContentData *)sm->ctx;
    if (cd->flags != (DETECT_CONTENT_RELATIVE_NEXT | DETECT_CONTENT_MPM) ||
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
    bed1 = (SCDetectByteExtractData *)sm->ctx;
    if (bed1->nbytes != 4 || bed1->offset != 0 || strcmp(bed1->name, "four") != 0 ||
            bed1->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                   DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed1->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed1->align_value != 0 ||
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
    SCDetectByteExtractData *bed = NULL;

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

    sm = DetectBufferGetFirstSigMatch(s, g_file_data_buffer_id);
    if (sm == NULL) {
        goto end;
    }
    if (sm->type != DETECT_BYTE_EXTRACT) {
        goto end;
    }
    bed = (SCDetectByteExtractData *)sm->ctx;
    if (bed->nbytes != 4 || bed->offset != 2 || strncmp(bed->name, "two", 3) != 0 ||
            bed->flags != (DETECT_BYTE_EXTRACT_FLAG_STRING | DETECT_BYTE_EXTRACT_FLAG_BASE |
                                  DETECT_BYTE_EXTRACT_FLAG_RELATIVE) ||
            bed->base != DETECT_BYTE_EXTRACT_BASE_HEX || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, -2, one");
    if (bed == NULL)
        goto end;

    if (bed->nbytes != 4 || bed->offset != -2 || strcmp(bed->name, "one") != 0 || bed->flags != 0 ||
            bed->endian != BigEndian || bed->align_value != 0 ||
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

    SCDetectByteExtractData *bed = DetectByteExtractParse(NULL, "4, 2, one, string");
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
