/** Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Brian Rectanus <brectanu@gmail.com>
 */

#include <pcre.h>
#include <stdlib.h>

#include "eidps-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-bytejump.h"

#include "util-byte.h"
#include "util-unittest.h"

/**
 * \brief Regex for parsing our options
 */
/** \todo We probably just need a simple tokenizer here */
/** \todo Cannot have > 9 captures and we need 10 -- write a comma separated value tokenizer for this. */
#define PARSE_REGEX  "^\\s*" \
                     "([^\\s,]+)" \
                     "\\s*,\\s*([^\\s,]+)" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "(?:\\s*,\\s*((?:multiplier|post_offset)\\s+[^\\s,]+|[^\\s,]+))?" \
                     "\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

void DetectBytejumpRegisterTests(void);

void DetectBytejumpRegister (void) {
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_BYTEJUMP].name = "byte_jump";
    sigmatch_table[DETECT_BYTEJUMP].Match = DetectBytejumpMatch;
    sigmatch_table[DETECT_BYTEJUMP].Setup = DetectBytejumpSetup;
    sigmatch_table[DETECT_BYTEJUMP].Free  = DetectBytejumpFree;
    sigmatch_table[DETECT_BYTEJUMP].RegisterTests = DetectBytejumpRegisterTests;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        printf("DetectBytejumpRegister: pcre compile of \"%s\" failed at offset %" PRId32 ": %s\n", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        printf("DetectBytejumpRegister: pcre study failed: %s\n", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

int DetectBytejumpMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Packet *p, Signature *s, SigMatch *m)
{
    DetectBytejumpData *data = (DetectBytejumpData *)m->ctx;
    uint8_t *ptr = NULL;
    uint8_t *jumpptr = ptr;
    uint16_t len = 0;
    uint64_t val = 0;
    int match;

    if (p->payload_len == 0) {
        return 0;
    }

    /* Calculate the ptr value for the bytejump and length remaining in
     * the packet from that point.
     */
    if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
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

    /* Verify the to-be-extracted data is within the packet */
    if ((ptr < p->pkt) || (len < 0) || (data->nbytes > len)) {
        printf("DetectBytejumpMatch: Data not within packet pkt=%p, ptr=%p, len=%d, nbytes=%d\n", p->pkt, ptr, len, data->nbytes);
        return 0;
    }

    /* Extract the byte data */
    if (data->flags & DETECT_BYTEJUMP_STRING) {
        int ret = ByteExtractStringUint64(&val, data->base, data->nbytes, (const char *)ptr);
        if(ret != 0) {
            printf("DetectBytejumpMatch: Error extracting %d bytes of string data: %d\n", data->nbytes, ret);
            return -1;
        }
    }
    else {
        int endianness = (data->flags & DETECT_BYTEJUMP_LITTLE) ? BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        int ret = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (ret != 0) {
            printf("DetectBytejumpMatch: Error extracting %d bytes of numeric data: %d\n", data->nbytes, ret);
            return -1;
        }
    }

    /* Adjust the jump value based on flags */
    val *= data->multiplier;
    if (data->flags & DETECT_BYTEJUMP_ALIGN) {
        if ((val % 4) != 0) {
            val += 4 - (val % 4);
        }
    }
    val += data->post_offset;

    /* Calculate the jump location */
    if (data->flags & DETECT_BYTEJUMP_BEGIN) {
        jumpptr = p->payload + val;
    }
    else {
        jumpptr = ptr + val;
    }

    /* Validate that the jump location is still in the packet
     * \todo Should this validate it is still in the *payload*?
     */
    if ((jumpptr < p->pkt) || (jumpptr >= p->pkt + p->pktlen)) {
        printf("DetectBytejumpMatch: Jump location (%p) is not within packet (%p-%p)\n", jumpptr, p->pkt, p->pkt + p->pktlen - 1);
        return 0;
    }

#ifdef DEBUG
    {
        uint8_t *sptr = (data->flags & DETECT_BYTEJUMP_BEGIN) ? p->payload : ptr;
        printf("DetectBytejumpMatch: Jumping %" PRId64 " bytes from %p (%08x) to %p (%08x)\n", val, sptr, (int)(sptr - p->payload), jumpptr, (int)(jumpptr - p->payload));
    }
#endif /* DEBUG */

    /* Adjust the detection context to the jump location. */
    det_ctx->pkt_ptr = jumpptr;
    det_ctx->pkt_off = jumpptr - p->pkt;

#ifdef DEBUG
    if (match) {
        printf("DetectBytejumpMatch: MATCH\n");
    }
    else {
        printf("DetectBytejumpMatch: NO MATCH\n");
    }
#endif /* DEBUG */

    return match;
}

DetectBytejumpData *DetectBytejumpParse(char *optstr)
{
    DetectBytejumpData *data = NULL;
    char *args[10] = {
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL
    };
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    uint32_t nbytes;
    const char *str_ptr;

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, optstr, strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 10) {
        printf("DetectBytejumpParse: parse error, ret %" PRId32 ", string \"%s\"\n", ret, optstr);
        goto error;
    }
    for (i = 0; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS, i + 1, &str_ptr);
        if (res < 0) {
            printf("DetectBytejumpParse: pcre_get_substring failed for arg %d\n", i + 1);
            goto error;
        }
        args[i] = (char *)str_ptr;
    }

    /* Initialize the data */
    data = malloc(sizeof(DetectBytejumpData));
    if (data == NULL) {
        printf("DetectBytejumpParse: malloc failed\n");
        goto error;
    }
    data->base = DETECT_BYTEJUMP_BASE_UNSET;
    data->flags = 0;
    data->multiplier = 1;
    data->post_offset = 0;

    /*
     * The first two options are required and positional.  The
     * remaining arguments are flags and are not positional.
     */

    /* Number of bytes */
    if (ByteExtractStringUint32(&nbytes, 10, strlen(args[0]), args[0]) != 0) {
        printf("DetectBytejumpParse: Malformed number of bytes: %s\n", optstr);
        goto error;
    }

    /* Offset */
    if (ByteExtractStringInt32(&data->offset, 0, strlen(args[1]), args[1]) != 0) {
        printf("DetectBytejumpParse: Malformed offset: %s\n", optstr);
        goto error;
    }


    /* The remaining options are flags. */
    /** \todo Error on dups? */
    for (i = 2; i < (ret - 1); i++) {
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
        } else if (strcasecmp("little", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_LITTLE;
        } else if (strcasecmp("from_beginning", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_BEGIN;
        } else if (strcasecmp("align", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_ALIGN;
        } else if (strncasecmp("multiplier ", args[i], 11) == 0) {
            if (ByteExtractStringUint32(&data->multiplier, 10, strlen(args[i]) - 11, args[i] + 11) != 0) {
                printf("DetectBytejumpParse: Malformed multiplier: %s\n", optstr);
                goto error;
            }
            printf("MULTIPLIER: %d\n", data->multiplier);
        } else if (strncasecmp("post_offset ", args[i], 12) == 0) {
            if (ByteExtractStringInt32(&data->post_offset, 10, strlen(args[i]) - 12, args[i] + 12) != 0) {
                printf("DetectBytejumpParse: Malformed post_offset: %s\n", optstr);
                goto error;
            }
            printf("POST_OFFSET: %d\n", data->post_offset);
        } else {
            printf("DetectBytejumpParse: Unknown option: \"%s\"\n", args[i]);
            goto error;
        }
    }

    if (data->flags & DETECT_BYTEJUMP_STRING) {
        /* 23 - This is the largest string (octal, with a zero prefix) that
         *      will not overflow uint64_t.  The only way this length
         *      could be over 23 and still not overflow is if it were zero
         *      prefixed and we only support 1 byte of zero prefix for octal.
         *
         * "01777777777777777777777" = 0xffffffffffffffff
         */
        if (nbytes > 23) {
            printf("DetectBytejumpParse: Cannot test more than 23 bytes with \"string\": %s\n", optstr);
            goto error;
        }
    } else {
        if (nbytes > 8) {
            printf("DetectBytejumpParse: Cannot test more than 8 bytes without \"string\": %s\n", optstr);
            goto error;
        }
        if (data->base != DETECT_BYTEJUMP_BASE_UNSET) {
            printf("DetectBytejumpParse: Cannot use a base without \"string\": %s\n", optstr);
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
    if (data != NULL) DetectBytejumpFree(data);
    return NULL;
}

int DetectBytejumpSetup(DetectEngineCtx *de_ctx, Signature *s, SigMatch *m, char *optstr)
{
    DetectBytejumpData *data = NULL;
    SigMatch *sm = NULL;

    //printf("DetectBytejumpSetup: \'%s\'\n", optstr);

    data = DetectBytejumpParse(optstr);
    if (data == NULL) goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_BYTEJUMP;
    sm->ctx = (void *)data;

    SigMatchAppend(s,m,sm);

    return 0;

error:
    if (data != NULL) DetectBytejumpFree(data);
    if (sm != NULL) free(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectBytejumpData
 *
 * \param data pointer to DetectBytejumpData
 */
void DetectBytejumpFree(void *ptr)
{
    DetectBytejumpData *data = (DetectBytejumpData *)ptr;
    free(data);
}


/* UNITTESTS */
#ifdef UNITTESTS

/**
 * \test DetectBytejumpTestParse01 is a test to make sure that we return
 * "something" when given valid bytejump opt
 */
int DetectBytejumpTestParse01(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("4,0");
    if (data != NULL) {
        DetectBytejumpFree(data);
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse02 is a test for setting the required opts
 */
int DetectBytejumpTestParse02(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("4, 0");
    if (data != NULL) {
        if (   (data->nbytes == 4)
            && (data->offset == 0)
            && (data->multiplier == 1)
            && (data->post_offset == 0)
            && (data->flags == 0)
            && (data->base == DETECT_BYTEJUMP_BASE_UNSET))
        {
            result = 1;
        }
        DetectBytejumpFree(data);
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse03 is a test for setting the optional flags
 */
int DetectBytejumpTestParse03(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(" 4,0 , relative , little, string, dec, align, from_beginning");
    if (data != NULL) {
        if (   (data->nbytes == 4)
            && (data->offset == 0)
            && (data->multiplier == 1)
            && (data->post_offset == 0)
            && (data->flags == ( DETECT_BYTEJUMP_RELATIVE
                                |DETECT_BYTEJUMP_LITTLE
                                |DETECT_BYTEJUMP_STRING
                                |DETECT_BYTEJUMP_ALIGN
                                |DETECT_BYTEJUMP_BEGIN))
            && (data->base == DETECT_BYTEJUMP_BASE_DEC))
        {
            result = 1;
        }
        DetectBytejumpFree(data);
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse04 is a test for setting the optional flags
 *       with parameters
 *
 * \todo This fails becuase we can only have 9 captures and there are 10.
 */
int DetectBytejumpTestParse04(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(" 4,0 , relative , little, string, dec, align, from_beginning , multiplier 2 , post_offset -16 ");
    if (data != NULL) {
        if (   (data->nbytes == 4)
            && (data->offset == 0)
            && (data->multiplier == 2)
            && (data->post_offset == 0)
            && (data->flags == ( DETECT_BYTEJUMP_RELATIVE
                                |DETECT_BYTEJUMP_LITTLE
                                |DETECT_BYTEJUMP_ALIGN
                                |DETECT_BYTEJUMP_STRING
                                |DETECT_BYTEJUMP_BEGIN))
            && (data->base == DETECT_BYTEJUMP_BASE_DEC))
        {
            result = 1;
        }
        DetectBytejumpFree(data);
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse05 is a test for setting base without string
 */
int DetectBytejumpTestParse05(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse(" 4,0 , relative , little, dec, align, from_beginning");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse06 is a test for too many bytes to extract
 */
int DetectBytejumpTestParse06(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("9, 0");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse07 is a test for too many string bytes to extract
 */
int DetectBytejumpTestParse07(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("24, 0, string, dec");
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test DetectBytejumpTestParse08 is a test for offset too big
 */
int DetectBytejumpTestParse08(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("4, 0xffffffffffffffff");
    if (data == NULL) {
        result = 1;
    }

    return result;
}
#endif /* UNITTESTS */


/**
 * \brief this function registers unit tests for DetectBytejump
 */
void DetectBytejumpRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("DetectBytejumpTestParse01", DetectBytejumpTestParse01, 1);
    UtRegisterTest("DetectBytejumpTestParse02", DetectBytejumpTestParse02, 1);
    UtRegisterTest("DetectBytejumpTestParse03", DetectBytejumpTestParse03, 1);
    UtRegisterTest("DetectBytejumpTestParse04", DetectBytejumpTestParse04, 1);
    UtRegisterTest("DetectBytejumpTestParse05", DetectBytejumpTestParse05, 1);
    UtRegisterTest("DetectBytejumpTestParse06", DetectBytejumpTestParse06, 1);
    UtRegisterTest("DetectBytejumpTestParse07", DetectBytejumpTestParse07, 1);
    UtRegisterTest("DetectBytejumpTestParse08", DetectBytejumpTestParse08, 1);
#endif /* UNITTESTS */
}

