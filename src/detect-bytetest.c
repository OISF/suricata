/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-bytetest.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"


/**
 * \brief Regex for parsing our options
 */
/** \todo We probably just need a simple tokenizer here */
#define PARSE_REGEX  "^\\s*" \
                     "([^\\s,]+)" \
                     "\\s*,\\s*(\\!?)\\s*([^\\s,]*)" \
                     "\\s*,\\s*([^\\s,]+)" \
                     "\\s*,\\s*([^\\s,]+)" \
                     "(?:\\s*,\\s*([^\\s,]+))?" \
                     "(?:\\s*,\\s*([^\\s,]+))?" \
                     "(?:\\s*,\\s*([^\\s,]+))?" \
                     "(?:\\s*,\\s*([^\\s,]+))?" \
                     "\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

void DetectBytetestRegisterTests(void);

void DetectBytetestRegister (void) {
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_BYTETEST].name = "byte_test";
    sigmatch_table[DETECT_BYTETEST].Match = DetectBytetestMatch;
    sigmatch_table[DETECT_BYTETEST].Setup = DetectBytetestSetup;
    sigmatch_table[DETECT_BYTETEST].Free  = DetectBytetestFree;
    sigmatch_table[DETECT_BYTETEST].RegisterTests = DetectBytetestRegisterTests;

    sigmatch_table[DETECT_BYTETEST].flags |= SIGMATCH_PAYLOAD;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_PCRE_COMPILE_FAILED, "pcre compile of \"%s\" failed at "
                   "offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_PCRE_STUDY_FAILED, "pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

int DetectBytetestMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m)
{
    DetectBytetestData *data = (DetectBytetestData *)m->ctx;
    uint8_t *ptr = NULL;
    uint16_t len = 0;
    uint64_t val = 0;
    int extbytes;
    int neg;
    int match;

    if (p->payload_len == 0) {
        return 0;
    }

    /* Calculate the ptr value for the bytetest and length remaining in
     * the packet from that point.
     */
    if (data->flags & DETECT_BYTETEST_RELATIVE) {
        ptr = det_ctx->pkt_ptr;
        len = p->pktlen - det_ctx->pkt_off;

        /* No match if there is no relative base */
        if (ptr == NULL || len == 0) {
            return 0;
        }

        ptr += data->offset;
        len -= data->offset;
    }
    else {
        ptr = p->payload + data->offset;
        len = p->payload_len - data->offset;
    }

    /* Validate that the to-be-extracted is within the packet
     * \todo Should this validate it is in the *payload*?
     */
    if ((ptr < p->pkt) || (len < 0) || (data->nbytes > len)) {
        SCLogDebug("Data not within packet pkt=%p, ptr=%p, len=%d, nbytes=%d",
                    p->pkt, ptr, len, data->nbytes);
        return 0;
    }

    neg = data->flags & DETECT_BYTETEST_NEGOP;

    /* Extract the byte data */
    if (data->flags & DETECT_BYTETEST_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base,
                                           data->nbytes, (const char *)ptr);
        if (extbytes <= 0) {
            /* strtoull() return 0 if there is no numeric value in data string */
            if (val == 0) {
                SCLogDebug("No Numeric value");
                return 0;
            } else {
                SCLogError(SC_INVALID_NUM_BYTES, "Error extracting %d "
                        "bytes of string data: %d", data->nbytes, extbytes);
                return -1;
            }
        }

        SCLogDebug("comparing base %d string 0x%" PRIx64 " %s%c 0x%" PRIx64 "",
               data->base, val, (neg ? "!" : ""), data->op, data->value);
    }
    else {
        int endianness = (data->flags & DETECT_BYTETEST_LITTLE) ?
                          BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (extbytes != data->nbytes) {
            SCLogError(SC_INVALID_NUM_BYTES, "Error extracting %d bytes "
                   "of numeric data: %d\n", data->nbytes, extbytes);
            return -1;
        }

        SCLogDebug("comparing numeric 0x%" PRIx64 " %s%c 0x%" PRIx64 "",
               val, (neg ? "!" : ""), data->op, data->value);
    }


    /* Compare using the configured operator */
    match = 0;
    switch (data->op) {
        case DETECT_BYTETEST_OP_EQ:
            if (val == data->value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_LT:
            if (val < data->value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_GT:
            if (val > data->value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_AND:
            if (val & data->value) {
                match = 1;
            }
            break;
        case DETECT_BYTETEST_OP_OR:
            if (val ^ data->value) {
                match = 1;
            }
            break;
        default:
            /* Should never get here as we handle this in parsing. */
            return -1;
    }

    /* A successful match depends on negation */
    if ((!neg && match) || (neg && !match)) {
        SCLogDebug("MATCH");
        return 1;
    }

    SCLogDebug("NO MATCH");
    return 0;
}

DetectBytetestData *DetectBytetestParse(char *optstr)
{
    DetectBytetestData *data = NULL;
    char *args[9] = {
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL
    };
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    uint32_t nbytes;
    const char *str_ptr = NULL;

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, optstr,
                    strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 6 || ret > 10) {
        SCLogError(SC_PCRE_PARSE_FAILED, "parse error, ret %" PRId32
               ", string %s", ret, optstr);
        goto error;
    }
    for (i = 0; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS,
                                 i + 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_PCRE_GET_SUBSTRING_FAILED, "pcre_get_substring failed "
                   "for arg %d", i + 1);
            goto error;
        }
        args[i] = (char *)str_ptr;
    }

    /* Initialize the data */
    data = malloc(sizeof(DetectBytetestData));
    if (data == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "malloc failed");
        goto error;
    }
    data->base = DETECT_BYTETEST_BASE_UNSET;
    data->flags = 0;


    /*
     * The first four options are required and positional.  The
     * remaining arguments are flags and are not positional.
     */

    /* Number of bytes */
    if (ByteExtractStringUint32(&nbytes, 10, 0, args[0]) <= 0) {
        SCLogDebug("Malformed number of bytes: %s", str_ptr);
        goto error;
    }

    /* Operator is next two args: neg + op */
    data->op = 0;
    if (*args[1] == '!') {
        data->flags |= DETECT_BYTETEST_NEGOP;
    }
    if ((strcmp("=", args[2]) == 0) || ((data->flags & DETECT_BYTETEST_NEGOP)
                && strcmp("", args[2]) == 0))
    {
        data->op |= DETECT_BYTETEST_OP_EQ;
    } else if (strcmp("<", args[2]) == 0) {
        data->op |= DETECT_BYTETEST_OP_LT;
    } else if (strcmp(">", args[2]) == 0) {
        data->op |= DETECT_BYTETEST_OP_GT;
    } else if (strcmp("&", args[2]) == 0) {
        data->op |= DETECT_BYTETEST_OP_AND;
    } else if (strcmp("^", args[2]) == 0) {
        data->op |= DETECT_BYTETEST_OP_OR;
    } else {
        // XXX Error
        goto error;
    }

    /* Value */
    if (ByteExtractStringUint64(&data->value, 0, 0, args[3]) <= 0) {
        SCLogDebug("Malformed value: %s", str_ptr);
        goto error;
    }

    /* Offset */
    if (ByteExtractStringInt32(&data->offset, 0, 0, args[4]) <= 0) {
        SCLogDebug(" Malformed offset: %s", str_ptr);
        goto error;
    }


    /* The remaining options are flags. */
    /** \todo Error on dups? */
    for (i = 5; i < (ret - 1); i++) {
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
        } else if (strcasecmp("little", args[i]) == 0) {
            data->flags |= DETECT_BYTETEST_LITTLE;
        } else {
            SCLogDebug("Unknown option: \"%s\"", args[i]);
            goto error;
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
            SCLogDebug("Cannot test more than 23 bytes with \"string\": %s",
                        optstr);
            goto error;
        }
    } else {
        if (nbytes > 8) {
            SCLogDebug("Cannot test more than 8 bytes without \"string\": %s",
                        optstr);
            goto error;
        }
        if (data->base != DETECT_BYTETEST_BASE_UNSET) {
            SCLogDebug("Cannot use a base without \"string\": %s", optstr);
            goto error;
        }
    }

    /* This is max 23 so it will fit in a byte (see above) */
    data->nbytes = (uint8_t)nbytes;

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    return data;

error:
    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL) free(args[i]);
    }
    if (data != NULL) DetectBytetestFree(data);
    return NULL;
}

int DetectBytetestSetup(DetectEngineCtx *de_ctx, Signature *s,
                        SigMatch *m, char *optstr)
{
    DetectBytetestData *data = NULL;
    SigMatch *sm = NULL;

    //printf("DetectBytetestSetup: \'%s\'\n", optstr);

    data = DetectBytetestParse(optstr);
    if (data == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_BYTETEST;
    sm->ctx = (void *)data;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (data != NULL) DetectBytetestFree(data);
    if (sm != NULL) free(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectBytetestData
 *
 * \param data pointer to DetectBytetestData
 */
void DetectBytetestFree(void *ptr)
{
    DetectBytetestData *data = (DetectBytetestData *)ptr;
    free(data);
}


/* UNITTESTS */
#ifdef UNITTESTS

/**
 * \test DetectBytetestTestParse01 is a test to make sure that we return "something"
 *  when given valid bytetest opt
 */
int DetectBytetestTestParse01(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1 , 0");
    if (data != NULL) {
        DetectBytetestFree(data);
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse02 is a test for setting the required opts
 */
int DetectBytetestTestParse02(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_NEGOP)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse03 is a test for setting the relative flag
 */
int DetectBytetestTestParse03(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0, relative");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->flags == ( DETECT_BYTETEST_NEGOP
                                |DETECT_BYTETEST_RELATIVE))
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse04 is a test for setting the string/oct flags
 */
int DetectBytetestTestParse04(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !=, 1, 0, string, oct");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 1)
            && (data->offset == 0)
            && (data->flags == ( DETECT_BYTETEST_NEGOP
                                |DETECT_BYTETEST_STRING))
            && (data->base == DETECT_BYTETEST_BASE_OCT))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse05 is a test for setting the string/dec flags
 */
int DetectBytetestTestParse05(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1, 0, string, dec");
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
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse06 is a test for setting the string/hex flags
 */
int DetectBytetestTestParse06(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, >, 1, 0, string, hex");
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
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse07 is a test for setting the big flag
 */
int DetectBytetestTestParse07(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0, big");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_LT)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags == 0)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse08 is a test for setting the little flag
 */
int DetectBytetestTestParse08(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, <, 5, 0, little");
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
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse09 is a test for neg operator only
 */
int DetectBytetestTestParse09(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, !, 5, 0");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_EQ)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags == DETECT_BYTETEST_NEGOP)
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse10 is a test for whitespace
 */
int DetectBytetestTestParse10(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("	4 , ! &, 5	, 0 , little ");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_AND)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags == (DETECT_BYTETEST_NEGOP|DETECT_BYTETEST_LITTLE))
            && (data->base == DETECT_BYTETEST_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse11 is a test for whitespace
 */
int DetectBytetestTestParse11(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4,!^,5,0,little,string,relative,hex");
    if (data != NULL) {
        if (   (data->op == DETECT_BYTETEST_OP_OR)
            && (data->nbytes == 4)
            && (data->value == 5)
            && (data->offset == 0)
            && (data->flags == ( DETECT_BYTETEST_NEGOP
                                |DETECT_BYTETEST_LITTLE
                                |DETECT_BYTETEST_STRING
                                |DETECT_BYTETEST_RELATIVE))
            && (data->base == DETECT_BYTETEST_BASE_HEX))
        {
            result = 1;
        }
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse12 is a test for hex w/o string
 */
int DetectBytetestTestParse12(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4, =, 1, 0, hex");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse13 is a test for too many bytes to extract
 */
int DetectBytetestTestParse13(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("9, =, 1, 0");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse14 is a test for large string extraction
 */
int DetectBytetestTestParse14(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("23,=,0xffffffffffffffffULL,0,string,oct");
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
        DetectBytetestFree(data);
    }

    return result;
}

/**
 * \test DetectBytetestTestParse15 is a test for too many bytes to extract (string)
 */
int DetectBytetestTestParse15(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("24, =, 0xffffffffffffffffULL, 0, string");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytetestTestParse16 is a test for offset too big
 */
int DetectBytetestTestParse16(void) {
    int result = 0;
    DetectBytetestData *data = NULL;
    data = DetectBytetestParse("4,=,0,0xffffffffffffffffULL");
    if (data == NULL) {
        result = 1;
    }

    return result;
}
#endif /* UNITTESTS */


/**
 * \brief this function registers unit tests for DetectBytetest
 */
void DetectBytetestRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectBytetestTestParse01", DetectBytetestTestParse01, 1);
    UtRegisterTest("DetectBytetestTestParse02", DetectBytetestTestParse02, 1);
    UtRegisterTest("DetectBytetestTestParse03", DetectBytetestTestParse03, 1);
    UtRegisterTest("DetectBytetestTestParse04", DetectBytetestTestParse04, 1);
    UtRegisterTest("DetectBytetestTestParse05", DetectBytetestTestParse05, 1);
    UtRegisterTest("DetectBytetestTestParse06", DetectBytetestTestParse06, 1);
    UtRegisterTest("DetectBytetestTestParse07", DetectBytetestTestParse07, 1);
    UtRegisterTest("DetectBytetestTestParse08", DetectBytetestTestParse08, 1);
    UtRegisterTest("DetectBytetestTestParse09", DetectBytetestTestParse09, 1);
    UtRegisterTest("DetectBytetestTestParse10", DetectBytetestTestParse10, 1);
    UtRegisterTest("DetectBytetestTestParse11", DetectBytetestTestParse11, 1);
    UtRegisterTest("DetectBytetestTestParse12", DetectBytetestTestParse12, 1);
    UtRegisterTest("DetectBytetestTestParse13", DetectBytetestTestParse13, 1);
    UtRegisterTest("DetectBytetestTestParse14", DetectBytetestTestParse14, 1);
    UtRegisterTest("DetectBytetestTestParse15", DetectBytetestTestParse15, 1);
    UtRegisterTest("DetectBytetestTestParse16", DetectBytetestTestParse16, 1);
#endif /* UNITTESTS */
}

