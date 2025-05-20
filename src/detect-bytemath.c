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
 * \file
 *
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 */

/*
 * Refer to the Snort manual, section 3.5.34 for details.
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "app-layer-parser.h"
#include "app-layer-protos.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-build.h"

#include "rust-bindings.h"

#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-byte.h"
#include "detect-bytemath.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-byte.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-spm.h"

static int DetectByteMathSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
#define DETECT_BYTEMATH_ENDIAN_DEFAULT (uint8_t) BigEndian
#define DETECT_BYTEMATH_BASE_DEFAULT   (uint8_t) BaseDec

static void DetectByteMathRegisterTests(void);
#endif
static void DetectByteMathFree(DetectEngineCtx *, void *);

/**
 * \brief Registers the keyword handlers for the "byte_math" keyword.
 */
void DetectBytemathRegister(void)
{
    sigmatch_table[DETECT_BYTEMATH].name = "byte_math";
    sigmatch_table[DETECT_BYTEMATH].Match = NULL;
    sigmatch_table[DETECT_BYTEMATH].Setup = DetectByteMathSetup;
    sigmatch_table[DETECT_BYTEMATH].Free = DetectByteMathFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BYTEMATH].RegisterTests = DetectByteMathRegisterTests;
#endif
}

static inline bool DetectByteMathValidateNbytesOnly(const DetectByteMathData *data, int32_t nbytes)
{
    return nbytes >= 1 &&
           (((data->flags & DETECT_BYTEMATH_FLAG_STRING) && nbytes <= 10) || (nbytes <= 4));
}

int DetectByteMathDoMatch(DetectEngineThreadCtx *det_ctx, const DetectByteMathData *data,
        const Signature *s, const uint8_t *payload, const uint32_t payload_len, uint8_t nbytes,
        uint64_t rvalue, uint64_t *value, uint8_t endian)
{
    if (payload_len == 0) {
        return 0;
    }

    if (!DetectByteMathValidateNbytesOnly(data, nbytes)) {
        return 0;
    }

    const uint8_t *ptr;
    int32_t len;
    uint64_t val;
    int extbytes;

    /* Calculate the ptr value for the byte-math op and length remaining in
     * the packet from that point.
     */
    if (data->flags & DETECT_BYTEMATH_FLAG_RELATIVE) {
        SCLogDebug("relative, working with det_ctx->buffer_offset %" PRIu32 ", "
                   "data->offset %" PRIi32 "",
                det_ctx->buffer_offset, data->offset);

        ptr = payload + det_ctx->buffer_offset;
        len = payload_len - det_ctx->buffer_offset;

        ptr += data->offset;
        len -= data->offset;

        /* No match if there is no relative base */
        if (len <= 0) {
            return 0;
        }
    } else {
        SCLogDebug("absolute, data->offset %" PRIi32 "", data->offset);

        ptr = payload + data->offset;
        len = payload_len - data->offset;
    }

    /* Validate that the to-be-extracted is within the packet */
    if (ptr < payload || nbytes > len) {
        SCLogDebug("Data not within payload pkt=%p, ptr=%p, len=%" PRIu32 ", nbytes=%d", payload,
                ptr, len, nbytes);
        return 0;
    }

    /* Extract the byte data */
    if (data->flags & DETECT_BYTEMATH_FLAG_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base, nbytes, (const char *)ptr);
        if (extbytes <= 0) {
            if (val == 0) {
                SCLogDebug("No Numeric value");
                return 0;
            } else {
                SCLogDebug("error extracting %d bytes of string data: %d", nbytes, extbytes);
                return -1;
            }
        }
    } else {
        ByteEndian bme = endian;
        int endianness = (bme == BigEndian) ? BYTE_BIG_ENDIAN : BYTE_LITTLE_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, nbytes, ptr);
        if (extbytes != nbytes) {
            SCLogDebug("error extracting %d bytes of numeric data: %d", nbytes, extbytes);
            return 0;
        }
    }

    BUG_ON(extbytes > len);

    ptr += extbytes;

    switch (data->oper) {
        case OperatorNone:
            break;
        case Addition:
            val += rvalue;
            break;
        case Subtraction:
            val -= rvalue;
            break;
        case Division:
            if (rvalue == 0) {
                SCLogDebug("avoiding division by zero");
                return 0;
            }
            val /= rvalue;
            break;
        case Multiplication:
            val *= rvalue;
            break;
        case LeftShift:
            if (rvalue < 64) {
                val <<= rvalue;
            } else {
                val = 0;
            }
            break;
        case RightShift:
            val >>= rvalue;
            break;
    }

    det_ctx->buffer_offset = (uint32_t)(ptr - payload);

    if (data->flags & DETECT_BYTEMATH_FLAG_BITMASK) {
        val &= data->bitmask_val;
        if (val && data->bitmask_shift_count) {
            val = val >> data->bitmask_shift_count;
        }
    }

    *value = val;
    return 1;
}

/**
 * \internal
 * \brief Used to parse byte_math arg.
 *
 * \param arg The argument to parse.
 * \param rvalue May be NULL. When non-null, will contain the variable
 *              name of rvalue (iff rvalue is not a scalar value)
 *
 * \retval bmd On success an instance containing the parsed data.
 *            On failure, NULL.
 */
static DetectByteMathData *DetectByteMathParse(
        DetectEngineCtx *de_ctx, const char *arg, char **nbytes, char **rvalue)
{
    DetectByteMathData *bmd;
    if ((bmd = SCByteMathParse(arg)) == NULL) {
        SCLogError("invalid bytemath values");
        return NULL;
    }

    if (bmd->nbytes_str) {
        if (nbytes == NULL) {
            SCLogError("byte_math supplied with "
                       "var name for nbytes. \"nbytes\" argument supplied to "
                       "this function must be non-NULL");
            goto error;
        }
        *nbytes = SCStrdup(bmd->nbytes_str);
        if (*nbytes == NULL) {
            goto error;
        }
    }

    if (bmd->rvalue_str) {
        if (rvalue == NULL) {
            SCLogError("byte_math supplied with "
                       "var name for rvalue. \"rvalue\" argument supplied to "
                       "this function must be non-NULL");
            goto error;
        }
        *rvalue = SCStrdup(bmd->rvalue_str);
        if (*rvalue == NULL) {
            goto error;
        }
    }

    if (bmd->flags & DETECT_BYTEMATH_FLAG_BITMASK) {
        if (bmd->bitmask_val) {
            uint32_t bmask = bmd->bitmask_val;
            while (!(bmask & 0x1)){
                bmask = bmask >> 1;
                bmd->bitmask_shift_count++;
            }
        }
    }

    return bmd;

 error:
    if (bmd != NULL)
        DetectByteMathFree(de_ctx, bmd);
    return NULL;
}

/**
 * \brief The setup function for the byte_math keyword for a signature.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int DetectByteMathSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    SigMatch *prev_pm = NULL;
    DetectByteMathData *data;
    char *rvalue = NULL;
    char *nbytes = NULL;
    int ret = -1;

    data = DetectByteMathParse(de_ctx, arg, &nbytes, &rvalue);
    if (data == NULL)
        goto error;

    int sm_list;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        sm_list = s->init_data->list;

        if (data->flags & DETECT_BYTEMATH_FLAG_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE, -1);
            if (!prev_pm) {
                SCLogError("relative specified without "
                           "previous pattern match");
                goto error;
            }
        }
    } else if (data->endian == EndianDCE) {
        if (data->flags & DETECT_BYTEMATH_FLAG_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE,
                                               DETECT_BYTETEST, DETECT_BYTEJUMP,
                                               DETECT_BYTE_EXTRACT,
                                               DETECT_BYTEMATH,
                                               DETECT_ISDATAAT, -1);
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

        if (SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0)
            goto error;

    } else if (data->flags & DETECT_BYTEMATH_FLAG_RELATIVE) {
        prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE,
                                           DETECT_BYTETEST, DETECT_BYTEJUMP,
                                           DETECT_BYTE_EXTRACT, DETECT_BYTEMATH,
                                           DETECT_ISDATAAT, -1);
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
        if (SCDetectSignatureSetAppProto(s, ALPROTO_DCERPC) != 0)
            goto error;

        if ((data->flags & DETECT_BYTEMATH_FLAG_STRING) || (data->base == BaseDec) ||
                (data->base == BaseHex) || (data->base == BaseOct)) {
            SCLogError("Invalid option. "
                       "A bytemath keyword with dce holds other invalid modifiers.");
            goto error;
        }
    }

    if (nbytes != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(nbytes, s, &index)) {
            SCLogError("unknown byte_ keyword var seen in byte_math - %s", nbytes);
            goto error;
        }
        data->nbytes = index;
        data->flags |= DETECT_BYTEMATH_FLAG_NBYTES_VAR;
        SCFree(nbytes);
        nbytes = NULL;
    }

    if (rvalue != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(rvalue, s, &index)) {
            SCLogError("unknown byte_ keyword var seen in byte_math - %s", rvalue);
            goto error;
        }
        data->rvalue = index;
        data->flags |= DETECT_BYTEMATH_FLAG_RVALUE_VAR;
        SCFree(rvalue);
        rvalue = NULL;
    }

    SigMatch *prev_bmd_sm = DetectGetLastSMByListId(s, sm_list,
            DETECT_BYTEMATH, -1);
    if (prev_bmd_sm == NULL) {
        data->local_id = 0;
    } else {
        data->local_id = ((DetectByteMathData *)prev_bmd_sm->ctx)->local_id + 1;
    }
    if (data->local_id > de_ctx->byte_extract_max_local_id) {
        de_ctx->byte_extract_max_local_id = data->local_id;
    }

    if (SCSigMatchAppendSMToList(de_ctx, s, DETECT_BYTEMATH, (SigMatchCtx *)data, sm_list) ==
            NULL) {
        goto error;
    }

    if (!(data->flags & DETECT_BYTEMATH_FLAG_RELATIVE))
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
    return 0;

 error:
    if (rvalue)
        SCFree(rvalue);
    if (nbytes)
        SCFree(nbytes);
    DetectByteMathFree(de_ctx, data);
    return ret;
}

/**
 * \brief Used to free instances of DetectByteMathractData.
 *
 * \param ptr Instance of DetectByteMathData to be freed.
 */
static void DetectByteMathFree(DetectEngineCtx *de_ctx, void *ptr)
{
    SCByteMathFree(ptr);
}

/**
 * \brief Lookup the SigMatch for a named byte_math variable.
 *
 * \param arg The name of the byte_math variable to lookup.
 * \param s Pointer the signature to look in.
 *
 * \retval A pointer to the SigMatch if found, otherwise NULL.
 */
SigMatch *DetectByteMathRetrieveSMVar(const char *arg, const Signature *s)
{
    for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
        SigMatch *sm = s->init_data->buffers[x].head;
        while (sm != NULL) {
            if (sm->type == DETECT_BYTEMATH) {
                const DetectByteMathData *bmd = (const DetectByteMathData *)sm->ctx;
                if (strcmp(bmd->result, arg) == 0) {
                    SCLogDebug("Retrieved SM for \"%s\"", arg);
                    return sm;
                }
            }
            sm = sm->next;
        }
    }

    for (int list = 0; list < DETECT_SM_LIST_MAX; list++) {
        SigMatch *sm = s->init_data->smlists[list];
        while (sm != NULL) {
            if (sm->type == DETECT_BYTEMATH) {
                const DetectByteMathData *bmd = (const DetectByteMathData *)sm->ctx;
                if (strcmp(bmd->result, arg) == 0) {
                    SCLogDebug("Retrieved SM for \"%s\"", arg);
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
#include "detect-engine-alert.h"

static int DetectByteMathParseTest01(void)
{

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue 10, result bar",
            NULL, NULL);
    FAIL_IF(bmd == NULL);

    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 10);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->endian == DETECT_BYTEMATH_ENDIAN_DEFAULT);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest02(void)
{
    /* bytes value invalid */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 257, offset 2, oper +, "
            "rvalue 39, result bar",
            NULL, NULL);

    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest03(void)
{
    /* bytes value invalid */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 11, offset 2, oper +, "
            "rvalue 39, result bar",
            NULL, NULL);
    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest04(void)
{
    /* offset value invalid */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 70000, oper +,"
            " rvalue 39, result bar",
            NULL, NULL);

    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest05(void)
{
    /* oper value invalid */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 11, offset 16, oper &,"
            "rvalue 39, result bar",
            NULL, NULL);
    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest06(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_RELATIVE;
    char *rvalue = NULL;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 0, oper +,"
            "rvalue 248, result var, relative",
            NULL, &rvalue);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 0);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 248);
    FAIL_IF_NOT(strcmp(bmd->result, "var") == 0);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == DETECT_BYTEMATH_ENDIAN_DEFAULT);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest07(void)
{
    char *rvalue = NULL;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue foo, result bar",
            NULL, &rvalue);
    FAIL_IF_NOT(rvalue);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(strcmp(rvalue, "foo") == 0);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->endian == DETECT_BYTEMATH_ENDIAN_DEFAULT);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    SCFree(rvalue);

    PASS;
}

static int DetectByteMathParseTest08(void)
{
    /* ensure Parse checks the pointer value when rvalue is a var */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue foo, result bar",
            NULL, NULL);
    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest09(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_RELATIVE;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue 39, result bar, relative",
            NULL, NULL);
    FAIL_IF(bmd == NULL);

    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == DETECT_BYTEMATH_ENDIAN_DEFAULT);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest10(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_ENDIAN;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue 39, result bar, endian"
            " big",
            NULL, NULL);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == BigEndian);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest11(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_ENDIAN;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +, "
            "rvalue 39, result bar, dce",
            NULL, NULL);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == EndianDCE);
    FAIL_IF_NOT(bmd->base == DETECT_BYTEMATH_BASE_DEFAULT);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest12(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_RELATIVE | DETECT_BYTEMATH_FLAG_STRING;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue 39, result bar, "
            "relative, string dec",
            NULL, NULL);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == BigEndian);
    FAIL_IF_NOT(bmd->base == BaseDec);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathParseTest13(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_STRING |
                    DETECT_BYTEMATH_FLAG_RELATIVE |
                    DETECT_BYTEMATH_FLAG_BITMASK;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +, "
            "rvalue 39, result bar, "
            "relative,  string dec, bitmask "
            "0x8f40",
            NULL, NULL);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->bitmask_val == 0x8f40);
    FAIL_IF_NOT(bmd->bitmask_shift_count == 6);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == BigEndian);
    FAIL_IF_NOT(bmd->base == BaseDec);

    DetectByteMathFree(NULL, bmd);

    PASS;
}


static int DetectByteMathParseTest14(void)
{
    /* incomplete */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +,"
            "rvalue foo",
            NULL, NULL);

    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest15(void)
{

    /* incomplete */
    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset 2, oper +, "
            "result bar",
            NULL, NULL);

    FAIL_IF_NOT(bmd == NULL);

    PASS;
}

static int DetectByteMathParseTest16(void)
{
    uint8_t flags = DETECT_BYTEMATH_FLAG_STRING | DETECT_BYTEMATH_FLAG_RELATIVE |
                    DETECT_BYTEMATH_FLAG_BITMASK;

    DetectByteMathData *bmd = DetectByteMathParse(NULL,
            "bytes 4, offset -2, oper +, "
            "rvalue 39, result bar, "
            "relative,  string dec, bitmask "
            "0x8f40",
            NULL, NULL);

    FAIL_IF(bmd == NULL);
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == -2);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->rvalue == 39);
    FAIL_IF_NOT(strcmp(bmd->result, "bar") == 0);
    FAIL_IF_NOT(bmd->bitmask_val == 0x8f40);
    FAIL_IF_NOT(bmd->bitmask_shift_count == 6);
    FAIL_IF_NOT(bmd->flags == flags);
    FAIL_IF_NOT(bmd->endian == BigEndian);
    FAIL_IF_NOT(bmd->base == BaseDec);

    DetectByteMathFree(NULL, bmd);

    PASS;
}

static int DetectByteMathPacket01(void)
{
    uint8_t buf[] = { 0x38, 0x35, 0x6d, 0x00, 0x00, 0x01,
                      0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                      0x00, 0x00, 0x6d, 0x00, 0x01, 0x00 };
    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP,
                           "192.168.1.5", "192.168.1.1",
                           41424, 53);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    /*
     * byte_extract: Extract 1 byte from offset 0 --> 0x0038
     * byte_math: Extract 1 byte from offset 2 (0x35)
     *            Add 0x35 + 0x38 = 109 (0x6d)
     * byte_test: Compare 2 bytes at offset 13 bytes from last
     *            match and compare with 0x6d
     */
    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                              "(byte_extract: 1, 0, extracted_val, relative;"
                              "byte_math: bytes 1, offset 1, oper +, rvalue extracted_val, result var;"
                              "byte_test: 2, =, var, 13;"
                              "msg:\"Byte extract and byte math with byte test verification\";"
                              "sid:1;)");
    FAIL_IF_NULL(s);

    /* this rule should not alert */
    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                              "(byte_extract: 1, 0, extracted_val, relative;"
                              "byte_math: bytes 1, offset 1, oper +, rvalue extracted_val, result var;"
                              "byte_test: 2, !=, var, 13;"
                              "msg:\"Byte extract and byte math with byte test verification\";"
                              "sid:2;)");
    FAIL_IF_NULL(s);

    /*
     * this rule should alert:
     * compares offset 15 with var ... 1 (offset 15) < 0x6d (var)
     */
    s = DetectEngineAppendSig(de_ctx, "alert udp any any -> any any "
                              "(byte_extract: 1, 0, extracted_val, relative;"
                              "byte_math: bytes 1, offset 1, oper +, rvalue extracted_val, result var;"
                              "byte_test: 2, <, var, 15;"
                              "msg:\"Byte extract and byte math with byte test verification\";"
                              "sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS,
                                STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* ensure sids 1 & 3 alerted */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 3));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static int DetectByteMathPacket02(void)
{
    uint8_t buf[] = { 0x38, 0x35, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x70, 0x00, 0x01, 0x00 };
    Flow f;
    void *dns_state = NULL;
    Packet *p = NULL;
    Signature *s = NULL;
    ThreadVars tv;
    DetectEngineThreadCtx *det_ctx = NULL;
    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&tv, 0, sizeof(ThreadVars));
    memset(&f, 0, sizeof(Flow));

    p = UTHBuildPacketReal(buf, sizeof(buf), IPPROTO_UDP, "192.168.1.5", "192.168.1.1", 41424, 53);
    FAIL_IF_NULL(p);

    FLOW_INITIALIZE(&f);
    f.flags |= FLOW_IPV4;
    f.proto = IPPROTO_UDP;
    f.protomap = FlowGetProtoMapping(f.proto);

    p->flow = &f;
    p->flags |= PKT_HAS_FLOW;
    p->flowflags |= FLOW_PKT_TOSERVER;
    f.alproto = ALPROTO_DNS;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    /*
     * byte_extract: Extract 1 byte from offset 0 --> 0x38
     * byte_math: Extract 1 byte from offset -1 (0x38)
     *            Add 0x38 + 0x38 = 112 (0x70)
     * byte_test: Compare 2 bytes at offset 13 bytes from last
     *            match and compare with 0x70
     */
    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any "
            "(byte_extract: 1, 0, extracted_val, relative;"
            "byte_math: bytes 1, offset -1, oper +, rvalue extracted_val, result var, relative;"
            "byte_test: 2, =, var, 13;"
            "msg:\"Byte extract and byte math with byte test verification\";"
            "sid:1;)");
    FAIL_IF_NULL(s);

    /* this rule should not alert */
    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any "
            "(byte_extract: 1, 0, extracted_val, relative;"
            "byte_math: bytes 1, offset -1, oper +,  rvalue extracted_val, result var, relative;"
            "byte_test: 2, !=, var, 13;"
            "msg:\"Byte extract and byte math with byte test verification\";"
            "sid:2;)");
    FAIL_IF_NULL(s);

    /*
     * this rule should alert:
     * compares offset 15 with var ... 1 (offset 15) < 0x70 (var)
     */
    s = DetectEngineAppendSig(de_ctx,
            "alert udp any any -> any any "
            "(byte_extract: 1, 0, extracted_val, relative;"
            "byte_math: bytes 1, offset -1, oper +, rvalue extracted_val, result var, relative;"
            "byte_test: 2, <, var, 15;"
            "msg:\"Byte extract and byte math with byte test verification\";"
            "sid:3;)");
    FAIL_IF_NULL(s);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&tv, (void *)de_ctx, (void *)&det_ctx);
    FAIL_IF_NULL(det_ctx);

    int r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DNS, STREAM_TOSERVER, buf, sizeof(buf));
    FAIL_IF_NOT(r == 0);

    dns_state = f.alstate;
    FAIL_IF_NULL(dns_state);

    /* do detect */
    SigMatchSignatures(&tv, de_ctx, det_ctx, p);

    /* ensure sids 1 & 3 alerted */
    FAIL_IF_NOT(PacketAlertCheck(p, 1));
    FAIL_IF(PacketAlertCheck(p, 2));
    FAIL_IF_NOT(PacketAlertCheck(p, 3));

    AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&tv, det_ctx);
    DetectEngineCtxFree(de_ctx);

    FLOW_DESTROY(&f);
    UTHFreePacket(p);

    PASS;
}

static int DetectByteMathContext01(void)
{
    DetectEngineCtx *de_ctx = NULL;
    Signature *s = NULL;
    SigMatch *sm = NULL;
    DetectContentData *cd = NULL;
    DetectByteMathData *bmd = NULL;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);

    de_ctx->flags |= DE_QUIET;
    s = de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                                           "(msg:\"Testing bytemath_body\"; "
                                           "content:\"|00 04 93 F3|\"; "
                                           "content:\"|00 00 00 07|\"; distance:4; within:4;"
                                           "byte_math:bytes 4, offset 0, oper +, rvalue "
                                           "248, result var, relative; sid:1;)");

    FAIL_IF(de_ctx->sig_list == NULL);

    FAIL_IF(s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH] == NULL);

    sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
    FAIL_IF(sm->type != DETECT_CONTENT);
    cd = (DetectContentData *)sm->ctx;
    FAIL_IF(cd->flags & DETECT_CONTENT_WITHIN);
    FAIL_IF(cd->flags & DETECT_CONTENT_DISTANCE);
    FAIL_IF(cd->content_len != 4);

    sm = sm->next;
    FAIL_IF(sm->type != DETECT_CONTENT);
    sm = sm->next;
    FAIL_IF(sm->type != DETECT_BYTEMATH);

    FAIL_IF(sm->ctx == NULL);

    bmd = (DetectByteMathData *)sm->ctx;
    FAIL_IF_NOT(bmd->nbytes == 4);
    FAIL_IF_NOT(bmd->offset == 0);
    FAIL_IF_NOT(bmd->rvalue == 248);
    FAIL_IF_NOT(strcmp(bmd->result, "var") == 0);
    FAIL_IF_NOT(bmd->flags == DETECT_BYTEMATH_FLAG_RELATIVE);
    FAIL_IF_NOT(bmd->endian == BigEndian);
    FAIL_IF_NOT(bmd->oper == Addition);
    FAIL_IF_NOT(bmd->base == BaseDec);

    DetectEngineCtxFree(de_ctx);

    PASS;
}

static void DetectByteMathRegisterTests(void)
{
    UtRegisterTest("DetectByteMathParseTest01", DetectByteMathParseTest01);
    UtRegisterTest("DetectByteMathParseTest02", DetectByteMathParseTest02);
    UtRegisterTest("DetectByteMathParseTest03", DetectByteMathParseTest03);
    UtRegisterTest("DetectByteMathParseTest04", DetectByteMathParseTest04);
    UtRegisterTest("DetectByteMathParseTest05", DetectByteMathParseTest05);
    UtRegisterTest("DetectByteMathParseTest06", DetectByteMathParseTest06);
    UtRegisterTest("DetectByteMathParseTest07", DetectByteMathParseTest07);
    UtRegisterTest("DetectByteMathParseTest08", DetectByteMathParseTest08);
    UtRegisterTest("DetectByteMathParseTest09", DetectByteMathParseTest09);
    UtRegisterTest("DetectByteMathParseTest10", DetectByteMathParseTest10);
    UtRegisterTest("DetectByteMathParseTest11", DetectByteMathParseTest11);
    UtRegisterTest("DetectByteMathParseTest12", DetectByteMathParseTest12);
    UtRegisterTest("DetectByteMathParseTest13", DetectByteMathParseTest13);
    UtRegisterTest("DetectByteMathParseTest14", DetectByteMathParseTest14);
    UtRegisterTest("DetectByteMathParseTest15", DetectByteMathParseTest15);
    UtRegisterTest("DetectByteMathParseTest16", DetectByteMathParseTest16);
    UtRegisterTest("DetectByteMathPacket01", DetectByteMathPacket01);
    UtRegisterTest("DetectByteMathPacket02", DetectByteMathPacket02);
    UtRegisterTest("DetectByteMathContext01", DetectByteMathContext01);
}
#endif /* UNITTESTS */
