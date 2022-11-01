/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Jeff Lucovsky <jeff@lucovsky.org>
 *
 * Implements byte_test keyword.
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-engine-build.h"

#include "detect-content.h"
#include "detect-byte.h"
#include "detect-bytetest.h"

#include "util-byte.h"
#include "detect-pcre.h"


/**
 * \brief Regex for parsing our options
 */
/** \todo We probably just need a simple tokenizer here */

/* PCRE supports 9 substrings so the 2nd and 3rd (negation, operator) and
 * 4th and 5th (test value, offset) are combined
 */
#define VALID_KW "relative|big|little|string|oct|dec|hex|dce|bitmask"
#define PARSE_REGEX  "^\\s*" \
                     "([^\\s,]+)\\s*,\\s*" \
                     "(\\!?\\s*[^\\s,]*)" \
                     "\\s*,\\s*([^\\s,]+\\s*,\\s*[^\\s,]+)" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "(?:\\s*,\\s*((?:"VALID_KW")\\s+[^\\s,]+|["VALID_KW"]+))?" \
                     "\\s*$"

static DetectParseRegex parse_regex;

static int DetectBytetestMatch(DetectEngineThreadCtx *det_ctx,
                        Packet *p, const Signature *s, const SigMatchCtx *ctx);
static int DetectBytetestSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr);
static void DetectBytetestFree(DetectEngineCtx *, void *ptr);
#ifdef UNITTESTS
static void DetectBytetestRegisterTests(void);
#endif

void DetectBytetestRegister (void)
{
    sigmatch_table[DETECT_BYTETEST].name = "byte_test";
    sigmatch_table[DETECT_BYTETEST].desc = "extract <num of bytes> and perform an operation selected with <operator> against the value in <test value> at a particular <offset>";
    sigmatch_table[DETECT_BYTETEST].url = "/rules/payload-keywords.html#byte-test";
    sigmatch_table[DETECT_BYTETEST].Match = DetectBytetestMatch;
    sigmatch_table[DETECT_BYTETEST].Setup = DetectBytetestSetup;
    sigmatch_table[DETECT_BYTETEST].Free  = DetectBytetestFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_BYTETEST].RegisterTests = DetectBytetestRegisterTests;
#endif
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/** \brief Bytetest detection code
 *
 *  Byte test works on the packet payload.
 *
 *  \param det_ctx thread de ctx
 *  \param s signature
 *  \param m sigmatch for this bytettest
 *  \param payload ptr to the start of the buffer to inspect
 *  \param payload_len length of the payload
 *  \retval 1 match
 *  \retval 0 no match
 */
int DetectBytetestDoMatch(DetectEngineThreadCtx *det_ctx,
                          const Signature *s, const SigMatchCtx *ctx,
                          const uint8_t *payload, uint32_t payload_len,
                          uint8_t flags, int32_t offset, uint64_t value)
{
    SCEnter();

    const DetectBytetestData *data = (const DetectBytetestData *)ctx;
    const uint8_t *ptr = NULL;
    int32_t len = 0;
    uint64_t val = 0;
    int extbytes;
    int neg;
    int match;

    if (payload_len == 0) {
        SCReturnInt(0);
    }

    /* Calculate the ptr value for the bytetest and length remaining in
     * the packet from that point.
     */
    if (flags & DETECT_BYTETEST_RELATIVE) {
        SCLogDebug("relative, working with det_ctx->buffer_offset %"PRIu32", "
                   "data->offset %"PRIi32"", det_ctx->buffer_offset, data->offset);

        ptr = payload + det_ctx->buffer_offset;
        len = payload_len - det_ctx->buffer_offset;

        ptr += offset;
        len -= offset;

        /* No match if there is no relative base */
        if (ptr == NULL || len <= 0) {
            SCReturnInt(0);
        }
    }
    else {
        SCLogDebug("absolute, data->offset %"PRIi32"", data->offset);

        ptr = payload + offset;
        len = payload_len - offset;
    }

    /* Validate that the to-be-extracted is within the packet
     * \todo Should this validate it is in the *payload*?
     */
    if (ptr < payload || data->nbytes > len) {
        SCLogDebug("Data not within payload pkt=%p, ptr=%p, len=%"PRIu32", nbytes=%d",
                    payload, ptr, len, data->nbytes);
        SCReturnInt(0);
    }

    neg = data->neg_op;

    /* Extract the byte data */
    if (flags & DETECT_BYTETEST_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base,
                                           data->nbytes, (const char *)ptr);
        if (extbytes <= 0) {
            /* ByteExtractStringUint64() returns 0 if there is no numeric value in data string */
            if (val == 0) {
                SCLogDebug("No Numeric value");
                SCReturnInt(0);
            } else {
                SCLogDebug("error extracting %d "
                        "bytes of string data: %d", data->nbytes, extbytes);
                SCReturnInt(-1);
            }
        }

        SCLogDebug("comparing base %d string 0x%" PRIx64 " %s%u 0x%" PRIx64,
               data->base, val, (neg ? "!" : ""), data->op, data->value);
    }
    else {
        int endianness = (flags & DETECT_BYTETEST_LITTLE) ?
                          BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (extbytes != data->nbytes) {
            SCLogDebug("error extracting %d bytes "
                   "of numeric data: %d", data->nbytes, extbytes);
            SCReturnInt(-1);
        }

        SCLogDebug("comparing numeric 0x%" PRIx64 " %s%u 0x%" PRIx64,
               val, (neg ? "!" : ""), data->op, data->value);
    }

    /* apply bitmask, if any and then right-shift 1 bit for each trailing 0 in
     * the bitmask. Note that it's one right shift for each trailing zero (not bit).
     */
    if (flags & DETECT_BYTETEST_BITMASK) {
        val &= data->bitmask;
        if (val && data->bitmask_shift_count) {
            val = val >> data->bitmask_shift_count;
        }
    }

    /* Compare using the configured operator */
    match = 0;
    switch (data->op) {
        case DETECT_BYTETEST_OP_EQ:
            if (val == value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_LT:
            if (val < value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_GT:
            if (val > value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_AND:
            if (val & value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_OR:
            if (val ^ value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_GE:
            if (val >= value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_LE:
            if (val <= value) {
                match = 1;
            }
            break;
        default:
            /* Should never get here as we handle this in parsing. */
            SCReturnInt(-1);
    }

    /* A successful match depends on negation */
    if ((!neg && match) || (neg && !match)) {
        SCLogDebug("MATCH [bt] extracted value is %"PRIu64, val);
        SCReturnInt(1);
    }

    SCLogDebug("NO MATCH");
    SCReturnInt(0);

}

static int DetectBytetestMatch(DetectEngineThreadCtx *det_ctx,
                        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    return DetectBytetestDoMatch(det_ctx, s, ctx, p->payload, p->payload_len,
                                 ((DetectBytetestData *)ctx)->flags, 0, 0);
}

static DetectBytetestData *DetectBytetestParse(const char *optstr, char **value, char **offset)
{
    DetectBytetestData *data = NULL;
    char *args[9] = {
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL
    };
    char *test_value =  NULL;
    char *data_offset = NULL;
    int ret = 0, res = 0;
    size_t pcre2_len;
    int i;
    uint32_t nbytes;
    const char *str_ptr = NULL;

    /* Execute the regex and populate args with captures. */
    ret = DetectParsePcreExec(&parse_regex, optstr, 0, 0);
    if (ret < 4 || ret > 9) {
        SCLogError(SC_ERR_PCRE_PARSE, "parse error, ret %" PRId32
               ", string %s", ret, optstr);
        goto error;
    }

    /* Subtract two since two values  are conjoined */
    for (i = 0; i < (ret - 1); i++) {
        res = pcre2_substring_get_bynumber(
                parse_regex.match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,
                    "pcre2_substring_get_bynumber failed "
                    "for arg %d",
                    i + 1);
            goto error;
        }
        /* args[2] is comma separated test value, offset */
        if (i == 2) {
            test_value = (char *) str_ptr;
            data_offset = SCStrdup((char *) str_ptr);
            if (data_offset == NULL) {
                goto error;
            }
        } else {
            args[i] = (char *)str_ptr;
        }
    }

    /* Initialize the data */
    data = SCMalloc(sizeof(DetectBytetestData));
    if (unlikely(data == NULL))
        goto error;
    data->base = DETECT_BYTETEST_BASE_UNSET;
    data->flags = 0;

    /*
     * The first four options are required and positional.  The
     * remaining arguments are flags and are not positional.
     *
     * The first four options have been collected into three
     * arguments:
     * - #1 -- byte count
     * - #2 -- operator, including optional negation (!)
     * - #3 -- test value and offset, comma separated
     */

    /* Number of bytes */
    if (StringParseUint32(&nbytes, 10, 0, args[0]) <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Malformed number of bytes: %s", str_ptr);
        goto error;
    }

    /* The operator is the next arg; it may contain a negation ! as the first char */
    data->op = 0;
    if (args[1] != NULL) {
        int op_offset = 0;
        char *op_ptr;
        if (args[1][op_offset] == '!') {
            data->neg_op = true;
            op_ptr = &args[1][1];
            while (isspace((char)*op_ptr) || (*op_ptr == ',')) op_ptr++;
            op_offset = op_ptr - &args[1][0];
        } else {
            data->neg_op = false;
        }
        op_ptr = args[1] + op_offset;
        if ((strcmp("=", op_ptr) == 0) || (data->neg_op
                && strcmp("", op_ptr) == 0)) {
            data->op |= DETECT_BYTETEST_OP_EQ;
        } else if (strcmp("<", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_LT;
        } else if (strcmp(">", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_GT;
        } else if (strcmp("&", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_AND;
        } else if (strcmp("^", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_OR;
        } else if (strcmp(">=", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_GE;
        } else if (strcmp("<=", op_ptr) == 0) {
            data->op |= DETECT_BYTETEST_OP_LE;
        } else {
            SCLogError(SC_ERR_INVALID_OPERATOR, "Invalid operator");
            goto error;
        }
    }

    if (test_value) {
        /*
         * test_value was created while fetching strings and contains the test value and offset,
         * comma separated. The values was allocated by test_value (pcre2_substring_get_bynumber)
         * and data_offset (SCStrdup), respectively; e.g., test_value,offset
         */
        char *end_ptr = test_value;
        while (!(isspace((unsigned char)*end_ptr) || (*end_ptr == ','))) end_ptr++;
        *end_ptr = '\0';

        if (test_value[0] != '-' && isalpha((unsigned char)test_value[0])) {
            if (value == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "byte_test supplied with "
                           "var name for value.  \"value\" argument supplied to "
                           "this function has to be non-NULL");
                goto error;
            }
            *value = SCStrdup(test_value);
            if (*value == NULL)
                goto error;
        } else {
            if (ByteExtractStringUint64(&data->value, 0, 0, test_value) <= 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed value: %s", test_value);
                goto error;
            }
        }
    }

    /* Offset -- note that this *also* contains test_value, offset so parse accordingly */
    if (data_offset) {
        char *end_ptr = data_offset;
        while (!(isspace((unsigned char)*end_ptr) || (*end_ptr == ','))) end_ptr++;
        str_ptr = ++end_ptr;
        while (isspace((unsigned char)*str_ptr) || (*str_ptr == ',')) str_ptr++;
        end_ptr = (char *)str_ptr;
        while (!(isspace((unsigned char)*end_ptr) || (*end_ptr == ',')) && (*end_ptr != '\0'))
            end_ptr++;
        memmove(data_offset, str_ptr, end_ptr - str_ptr);
        data_offset[end_ptr-str_ptr] = '\0';
        if (data_offset[0] != '-' && isalpha((unsigned char)data_offset[0])) {
            if (data_offset == NULL) {
                SCLogError(SC_ERR_INVALID_ARGUMENT, "byte_test supplied with "
                           "var name for offset.  \"offset\" argument supplied to "
                           "this function has to be non-NULL");
                goto error;
            }
            *offset = SCStrdup(data_offset);
            if (*offset == NULL)
                goto error;
        } else {
            if (StringParseInt32(&data->offset, 0, 0, data_offset) <= 0) {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed offset: %s", data_offset);
                goto error;
            }
        }
    }

    /* The remaining options are flags. */
    /** \todo Error on dups? */
    int bitmask_index = -1;
    for (i = 3; i < (ret - 1); i++) {
        if (args[i] != NULL) {
            if (strcmp("relative", args[i]) == 0) {
                data->flags |= DETECT_BYTETEST_RELATIVE;
            } else if (strcasecmp("string", args[i]) == 0) {
                data->flags |= DETECT_BYTETEST_STRING;
            } else if (strcasecmp("dec", args[i]) == 0) {
                data->base |= DETECT_BYTETEST_BASE_DEC;
            } else if (strcasecmp("hex", args[i]) == 0) {
                data->base |= DETECT_BYTETEST_BASE_HEX;
            } else if (strcasecmp("oct", args[i]) == 0) {
                data->base |= DETECT_BYTETEST_BASE_OCT;
            } else if (strcasecmp("big", args[i]) == 0) {
                if (data->flags & DETECT_BYTETEST_LITTLE) {
                    data->flags ^= DETECT_BYTETEST_LITTLE;
                }
                data->flags |= DETECT_BYTETEST_BIG;
            } else if (strcasecmp("little", args[i]) == 0) {
                data->flags |= DETECT_BYTETEST_LITTLE;
            } else if (strcasecmp("dce", args[i]) == 0) {
                data->flags |= DETECT_BYTETEST_DCE;
            } else if (strncasecmp("bitmask", args[i], strlen("bitmask")) == 0) {
                data->flags |= DETECT_BYTETEST_BITMASK;
                bitmask_index = i;
            } else {
                SCLogError(SC_ERR_UNKNOWN_VALUE, "Unknown value: \"%s\"",
                        args[i]);
                goto error;
            }
        }
    }

    if (data->flags & DETECT_BYTETEST_STRING) {
        /* 23 - This is the largest string (octal, with a zero prefix) that
         *      will not overflow uint64_t.  The only way this length
         *      could be over 23 and still not overflow is if it were zero
         *      prefixed and we only support 1 byte of zero prefix for octal.
         *
         * "01777777777777777777777" = 0xffffffffffffffff
         */
        if (nbytes > 23) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot test more than 23 bytes with \"string\": %s",
                        optstr);
            goto error;
        }
    } else {
        if (nbytes > 8) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot test more than 8 bytes without \"string\": %s",
                        optstr);
            goto error;
        }
        if (data->base != DETECT_BYTETEST_BASE_UNSET) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot use a base without \"string\": %s", optstr);
            goto error;
        }
    }

    /* This is max 23 so it will fit in a byte (see above) */
    data->nbytes = (uint8_t)nbytes;

    if (bitmask_index != -1 && data->flags & DETECT_BYTETEST_BITMASK) {
        if (ByteExtractStringUint32(&data->bitmask, 0, 0, args[bitmask_index]+strlen("bitmask")) <= 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed bitmask value: %s", args[bitmask_index]+strlen("bitmask"));
            goto error;
        }
        /* determine how many trailing 0's are in the bitmask. This will be used
         * to rshift the value after applying the bitmask
         */
        data->bitmask_shift_count = 0;
        if (data->bitmask) {
            uint32_t bmask = data->bitmask;
            while (!(bmask & 0x1)){
                bmask = bmask >> 1;
                data->bitmask_shift_count++;
            }
        }
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (data_offset) SCFree(data_offset);
    if (test_value)
        pcre2_substring_free((PCRE2_UCHAR8 *)test_value);
    return data;

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (data_offset) SCFree(data_offset);
    if (test_value)
        pcre2_substring_free((PCRE2_UCHAR8 *)test_value);
    if (data) SCFree(data);
    return NULL;
}

static int DetectBytetestSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SigMatch *sm = NULL;
    SigMatch *prev_pm = NULL;
    char *value = NULL;
    char *offset = NULL;
    int ret = -1;

    DetectBytetestData *data = DetectBytetestParse(optstr, &value, &offset);
    if (data == NULL)
        goto error;

    int sm_list;
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (DetectBufferGetActiveList(de_ctx, s) == -1)
            goto error;

        sm_list = s->init_data->list;

        if (data->flags & DETECT_BYTETEST_RELATIVE) {
            prev_pm = DetectGetLastSMFromLists(s, DETECT_CONTENT, DETECT_PCRE, -1);
        }

    } else if (data->flags & DETECT_BYTETEST_DCE) {
        if (data->flags & DETECT_BYTETEST_RELATIVE) {
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

    } else if (data->flags & DETECT_BYTETEST_RELATIVE) {
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

    if (data->flags & DETECT_BYTETEST_DCE) {
        if ((data->flags & DETECT_BYTETEST_STRING) ||
            (data->flags & DETECT_BYTETEST_LITTLE) ||
            (data->flags & DETECT_BYTETEST_BIG) ||
            (data->base == DETECT_BYTETEST_BASE_DEC) ||
            (data->base == DETECT_BYTETEST_BASE_HEX) ||
            (data->base == DETECT_BYTETEST_BASE_OCT) ) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "Invalid option. "
                       "A byte_test keyword with dce holds other invalid modifiers.");
            goto error;
        }
    }

    if (value != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(value, s, &index)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                       "seen in byte_test - %s\n", value);
            goto error;
        }
        data->value = index;
        data->flags |= DETECT_BYTETEST_VALUE_VAR;
        SCFree(value);
        value = NULL;
    }

    if (offset != NULL) {
        DetectByteIndexType index;
        if (!DetectByteRetrieveSMVar(offset, s, &index)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                       "seen in byte_test - %s\n", offset);
            goto error;
        }
        data->offset = index;
        data->flags |= DETECT_BYTETEST_OFFSET_VAR;
        SCFree(offset);
        offset = NULL;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_BYTETEST;
    sm->ctx = (SigMatchCtx *)data;
    SigMatchAppendSMToList(s, sm, sm_list);

    if (!(data->flags & DETECT_BYTETEST_RELATIVE))
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
    if (offset)
        SCFree(offset);
    if (value)
        SCFree(value);
    DetectBytetestFree(de_ctx, data);
    return ret;
}

/**
 * \brief this function will free memory associated with DetectBytetestData
 *
 * \param data pointer to DetectBytetestData
 */
static void DetectBytetestFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr == NULL)
        return;

    DetectBytetestData *data = (DetectBytetestData *)ptr;
    SCFree(data);
}


/* UNITTESTS */
#ifdef UNITTESTS
static int g_file_data_buffer_id = 0;
static int g_dce_stub_data_buffer_id = 0;

/**
 * \test DetectBytetestTestParse01 is a test to make sure that we return "something"
 *  when given valid bytetest opt
 */
static int DetectBytetestTestParse01(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1 , 0", NULL, NULL);
    if (data != NULL) {
        DetectBytetestFree(NULL, data);
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse02 is a test for setting the required opts
 */
static int DetectBytetestTestParse02(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse03 is a test for setting the relative flag
 */
static int DetectBytetestTestParse03(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0, relative", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->flags == DETECT_BYTETEST_RELATIVE)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse04 is a test for setting the string/oct flags
 */
static int DetectBytetestTestParse04(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0, string, oct", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->flags == DETECT_BYTETEST_STRING)
            && (data->base == DETECT_BYTETEST_BASE_OCT))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse05 is a test for setting the string/dec flags
 */
static int DetectBytetestTestParse05(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1, 0, string, dec", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_STRING)
            && (data->base == DETECT_BYTETEST_BASE_DEC))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse06 is a test for setting the string/hex flags
 */
static int DetectBytetestTestParse06(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, >, 1, 0, string, hex", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_GT)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_STRING)
            && (data->base == DETECT_BYTETEST_BASE_HEX))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse07 is a test for setting the big flag
 */
static int DetectBytetestTestParse07(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0, big", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_LT)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags & DETECT_BYTETEST_BIG)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse08 is a test for setting the little flag
 */
static int DetectBytetestTestParse08(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0, little", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_LT)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_LITTLE)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse09 is a test for neg operator only
 */
static int DetectBytetestTestParse09(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !, 5, 0", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse10 is a test for whitespace
 */
static int DetectBytetestTestParse10(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("	4 , ! &, 5	, 0 , little ", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_AND)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->flags == DETECT_BYTETEST_LITTLE)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse11 is a test for whitespace
 */
static int DetectBytetestTestParse11(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4,!^,5,0,little,string,relative,hex", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_OR)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->neg_op)
            && (data->flags == (DETECT_BYTETEST_LITTLE
                                |DETECT_BYTETEST_STRING
                                |DETECT_BYTETEST_RELATIVE))
            && (data->base == DETECT_BYTETEST_BASE_HEX))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse12 is a test for hex w/o string
 */
static int DetectBytetestTestParse12(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1, 0, hex", NULL, NULL);
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse13 is a test for too many bytes to extract
 */
static int DetectBytetestTestParse13(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("9, =, 1, 0", NULL, NULL);
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse14 is a test for large string extraction
 */
static int DetectBytetestTestParse14(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("23,=,0xffffffffffffffffULL,0,string,oct", NULL, NULL);
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 23)
            && (data->value == 0xffffffffffffffffULL)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_STRING)
            && (data->base == DETECT_BYTETEST_BASE_OCT))
        {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse15 is a test for too many bytes to extract (string)
 */
static int DetectBytetestTestParse15(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("24, =, 0xffffffffffffffffULL, 0, string", NULL, NULL);
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse16 is a test for offset too big
 */
static int DetectBytetestTestParse16(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4,=,0,0xffffffffffffffffULL", NULL, NULL);
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test Test dce option.
 */
static int DetectBytetestTestParse17(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0, dce", NULL, NULL);
    if (data != NULL) {
        if ( (data->op == DETECT_BYTETEST_OP_LT) &&
             (data->nbytes == 4) &&
             (data->value == 5) &&
             (data->offset == 0) &&
             (data->flags & DETECT_BYTETEST_DCE) ) {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test Test dce option.
 */
static int DetectBytetestTestParse18(void)
{
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0", NULL, NULL);
    if (data != NULL) {
        if ( (data->op == DETECT_BYTETEST_OP_LT) &&
             (data->nbytes == 4) &&
             (data->value == 5) &&
             (data->offset == 0) &&
             !(data->flags & DETECT_BYTETEST_DCE) ) {
            result = 1;
        }
        DetectBytetestFree(NULL, data);
    }

    return result;
}

/**
 * \test Test dce option.
 */
static int DetectBytetestTestParse19(void)
{
    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 1;

    if (DetectSignatureSetAppProto(s, ALPROTO_DCERPC) < 0) {
        SigFree(NULL, s);
        return 0;
    }

    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,dce") == 0);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,string,dce") == -1);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,big,dce") == -1);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,little,dce") == -1);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,hex,dce") == -1);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,oct,dce") == -1);
    result &= (DetectBytetestSetup(NULL, s, "1,=,1,6,dec,dce") == -1);

    SigFree(NULL, s);
    return result;
}

/**
 * \test Test dce option.
 */
static int DetectBytetestTestParse20(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    DetectBytetestData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytetest_body\"; "
                               "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                               "dce_stub_data; "
                               "content:\"one\"; distance:0; "
                               "byte_test:1,=,1,6,relative,dce; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    s = de_ctx->sig_list;
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_BYTETEST);
    bd = (DetectBytetestData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    if (!(bd->flags & DETECT_BYTETEST_DCE) &&
        !(bd->flags & DETECT_BYTETEST_RELATIVE) &&
        (bd->flags & DETECT_BYTETEST_STRING) &&
        (bd->flags & DETECT_BYTETEST_BIG) &&
        (bd->flags & DETECT_BYTETEST_LITTLE) &&
        (bd->neg_op) ) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytetest_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "byte_test:1,=,1,6,relative,dce; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_BYTETEST);
    bd = (DetectBytetestData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    if (!(bd->flags & DETECT_BYTETEST_DCE) &&
        !(bd->flags & DETECT_BYTETEST_RELATIVE) &&
        (bd->flags & DETECT_BYTETEST_STRING) &&
        (bd->flags & DETECT_BYTETEST_BIG) &&
        (bd->flags & DETECT_BYTETEST_LITTLE) &&
        (bd->neg_op) ) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytetest_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "byte_test:1,=,1,6,relative; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[g_dce_stub_data_buffer_id] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[g_dce_stub_data_buffer_id]->type == DETECT_BYTETEST);
    bd = (DetectBytetestData *)s->sm_lists_tail[g_dce_stub_data_buffer_id]->ctx;
    if ((bd->flags & DETECT_BYTETEST_DCE) &&
        !(bd->flags & DETECT_BYTETEST_RELATIVE) &&
        (bd->flags & DETECT_BYTETEST_STRING) &&
        (bd->flags & DETECT_BYTETEST_BIG) &&
        (bd->flags & DETECT_BYTETEST_LITTLE) &&
        (bd->neg_op) ) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test dce option.
 */
static int DetectBytetestTestParse21(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,string,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,big,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,little,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,hex,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,dec,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,oct,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,string,hex,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,big,string,hex,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,big,string,oct,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,little,string,hex,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytetest_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "content:\"one\"; byte_test:1,=,1,6,big,string,dec,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test file_data
 */
static int DetectBytetestTestParse22(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    DetectBytetestData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; byte_test:1,=,1,6,relative; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        printf("sig parse failed: ");
        goto end;
    }

    s = de_ctx->sig_list;
    if (s->sm_lists_tail[g_file_data_buffer_id] == NULL) {
        printf("empty server body list: ");
        goto end;
    }

    if (s->sm_lists_tail[g_file_data_buffer_id]->type != DETECT_BYTETEST) {
        printf("bytetest not last sm in server body list: ");
        goto end;
    }

    bd = (DetectBytetestData *)s->sm_lists_tail[g_file_data_buffer_id]->ctx;
    if (bd->flags & DETECT_BYTETEST_DCE &&
        bd->flags & DETECT_BYTETEST_RELATIVE &&
        (bd->flags & DETECT_BYTETEST_STRING) &&
        (bd->flags & DETECT_BYTETEST_BIG) &&
        (bd->flags & DETECT_BYTETEST_LITTLE) &&
        (bd->neg_op) ) {
        printf("wrong flags: ");
        goto end;
    }

    result = 1;
 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);
    DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test Test bitmask option.
 */
static int DetectBytetestTestParse23(void)
{
    DetectBytetestData *data;
    data = DetectBytetestParse("4, <, 5, 0, bitmask 0xf8", NULL, NULL);

    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->op == DETECT_BYTETEST_OP_LT);
    FAIL_IF_NOT(data->nbytes == 4);
    FAIL_IF_NOT(data->value == 5);
    FAIL_IF_NOT(data->offset == 0);
    FAIL_IF_NOT(data->flags & DETECT_BYTETEST_BITMASK);
    FAIL_IF_NOT(data->bitmask == 0xf8);
    FAIL_IF_NOT(data->bitmask_shift_count == 3);

    DetectBytetestFree(NULL, data);

    PASS;
}

/**
 * \test Test all options
 */
static int DetectBytetestTestParse24(void)
{
    DetectBytetestData *data;
    data = DetectBytetestParse("4, !<, 5, 0, relative,string,hex, big, bitmask 0xf8", NULL, NULL);
    FAIL_IF_NULL(data);
    FAIL_IF_NOT(data->op == DETECT_BYTETEST_OP_LT);
    FAIL_IF_NOT(data->nbytes == 4);
    FAIL_IF_NOT(data->value == 5);
    FAIL_IF_NOT(data->offset == 0);
    FAIL_IF_NOT(data->base == DETECT_BYTETEST_BASE_HEX);
    FAIL_IF_NOT(data->flags & DETECT_BYTETEST_BIG);
    FAIL_IF_NOT(data->flags & DETECT_BYTETEST_RELATIVE);
    FAIL_IF_NOT(data->flags & DETECT_BYTETEST_STRING);
    FAIL_IF_NOT(data->flags & DETECT_BYTETEST_BITMASK);
    FAIL_IF_NOT(data->bitmask == 0xf8);
    FAIL_IF_NOT(data->bitmask_shift_count == 3);

    DetectBytetestFree(NULL, data);

    PASS;
}

/**
 * \brief this function registers unit tests for DetectBytetest
 */
static void DetectBytetestRegisterTests(void)
{
    g_file_data_buffer_id = DetectBufferTypeGetByName("file_data");
    g_dce_stub_data_buffer_id = DetectBufferTypeGetByName("dce_stub_data");

    UtRegisterTest("DetectBytetestTestParse01", DetectBytetestTestParse01);
    UtRegisterTest("DetectBytetestTestParse02", DetectBytetestTestParse02);
    UtRegisterTest("DetectBytetestTestParse03", DetectBytetestTestParse03);
    UtRegisterTest("DetectBytetestTestParse04", DetectBytetestTestParse04);
    UtRegisterTest("DetectBytetestTestParse05", DetectBytetestTestParse05);
    UtRegisterTest("DetectBytetestTestParse06", DetectBytetestTestParse06);
    UtRegisterTest("DetectBytetestTestParse07", DetectBytetestTestParse07);
    UtRegisterTest("DetectBytetestTestParse08", DetectBytetestTestParse08);
    UtRegisterTest("DetectBytetestTestParse09", DetectBytetestTestParse09);
    UtRegisterTest("DetectBytetestTestParse10", DetectBytetestTestParse10);
    UtRegisterTest("DetectBytetestTestParse11", DetectBytetestTestParse11);
    UtRegisterTest("DetectBytetestTestParse12", DetectBytetestTestParse12);
    UtRegisterTest("DetectBytetestTestParse13", DetectBytetestTestParse13);
    UtRegisterTest("DetectBytetestTestParse14", DetectBytetestTestParse14);
    UtRegisterTest("DetectBytetestTestParse15", DetectBytetestTestParse15);
    UtRegisterTest("DetectBytetestTestParse16", DetectBytetestTestParse16);
    UtRegisterTest("DetectBytetestTestParse17", DetectBytetestTestParse17);
    UtRegisterTest("DetectBytetestTestParse18", DetectBytetestTestParse18);
    UtRegisterTest("DetectBytetestTestParse19", DetectBytetestTestParse19);
    UtRegisterTest("DetectBytetestTestParse20", DetectBytetestTestParse20);
    UtRegisterTest("DetectBytetestTestParse21", DetectBytetestTestParse21);
    UtRegisterTest("DetectBytetestTestParse22", DetectBytetestTestParse22);
    UtRegisterTest("DetectBytetestTestParse23", DetectBytetestTestParse23);
    UtRegisterTest("DetectBytetestTestParse24", DetectBytetestTestParse24);
}
#endif /* UNITTESTS */
