/* Copyright (C) 2007-2010 Open Information Security Foundation
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
#include "debug.h"
#include "decode.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "app-layer.h"

#include "detect-bytejump.h"
#include "detect-byte-extract.h"
#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-debug.h"
#include "detect-pcre.h"

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

    sigmatch_table[DETECT_BYTEJUMP].flags |= SIGMATCH_PAYLOAD;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if(parse_regex == NULL)
    {
        SCLogError(SC_ERR_PCRE_COMPILE,"pcre compile of \"%s\" failed "
               "at offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if(eb != NULL)
    {
        SCLogError(SC_ERR_PCRE_STUDY,"pcre study failed: %s", eb);
        goto error;
    }
    return;

error:
    /* XXX */
    return;
}

/** \brief Byte jump match function
 *  \param det_ctx thread detect engine ctx
 *  \param s signature
 *  \param m byte jump sigmatch
 *  \param payload ptr to the payload
 *  \param payload_len length of the payload
 *  \retval 1 match
 *  \retval 0 no match
 */
int DetectBytejumpDoMatch(DetectEngineThreadCtx *det_ctx, Signature *s,
                          SigMatch *m, uint8_t *payload, uint32_t payload_len,
                          uint8_t flags, int32_t offset)
{
    SCEnter();

    DetectBytejumpData *data = (DetectBytejumpData *)m->ctx;
    uint8_t *ptr = NULL;
    uint8_t *jumpptr = NULL;
    int32_t len = 0;
    uint64_t val = 0;
    int extbytes;

    if (payload_len == 0) {
        SCReturnInt(0);
    }

    /* Calculate the ptr value for the bytejump and length remaining in
     * the packet from that point.
     */
    if (flags & DETECT_BYTEJUMP_RELATIVE) {
        ptr = payload + det_ctx->payload_offset;
        len = payload_len - det_ctx->payload_offset;

        /* No match if there is no relative base */
        if (ptr == NULL || len == 0) {
            SCReturnInt(0);
        }

        ptr += offset;
        len -= offset;
    }
    else {
        ptr = payload + offset;
        len = payload_len - offset;
    }

    /* Verify the to-be-extracted data is within the packet */
    if (ptr < payload || data->nbytes > len) {
        SCLogDebug("Data not within payload "
               "pkt=%p, ptr=%p, len=%d, nbytes=%d",
               payload, ptr, len, data->nbytes);
        SCReturnInt(0);
    }

    /* Extract the byte data */
    if (flags & DETECT_BYTEJUMP_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base,
                                           data->nbytes, (const char *)ptr);
        if(extbytes <= 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED,"Error extracting %d bytes "
                   "of string data: %d", data->nbytes, extbytes);
            SCReturnInt(-1);
        }
    }
    else {
        int endianness = (flags & DETECT_BYTEJUMP_LITTLE) ? BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (extbytes != data->nbytes) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED,"Error extracting %d bytes "
                   "of numeric data: %d", data->nbytes, extbytes);
            SCReturnInt(-1);
        }
    }

    //printf("VAL: (%" PRIu64 " x %" PRIu32 ") + %d + %" PRId32 "\n", val, data->multiplier, extbytes, data->post_offset);

    /* Adjust the jump value based on flags */
    val *= data->multiplier;
    if (flags & DETECT_BYTEJUMP_ALIGN) {
        if ((val % 4) != 0) {
            val += 4 - (val % 4);
        }
    }
    val += extbytes + data->post_offset;

    /* Calculate the jump location */
    if (flags & DETECT_BYTEJUMP_BEGIN) {
        jumpptr = payload + val;
        //printf("NEWVAL: payload %p + %ld = %p\n", p->payload, val, jumpptr);
    }
    else {
        jumpptr = ptr + val;
        //printf("NEWVAL: ptr %p + %ld = %p\n", ptr, val, jumpptr);
    }


    /* Validate that the jump location is still in the packet
     * \todo Should this validate it is still in the *payload*?
     */
    if ((jumpptr < payload) || (jumpptr >= payload + payload_len)) {
        SCLogDebug("Jump location (%p) is not within "
               "payload (%p-%p)", jumpptr, payload, payload + payload_len - 1);
        SCReturnInt(0);
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        uint8_t *sptr = (flags & DETECT_BYTEJUMP_BEGIN) ? payload : ptr;
        SCLogDebug("jumping %" PRId64 " bytes from %p (%08x) to %p (%08x)",
               val, sptr, (int)(sptr - payload),
               jumpptr, (int)(jumpptr - payload));
    }
#endif /* DEBUG */

    /* Adjust the detection context to the jump location. */
    det_ctx->payload_offset = jumpptr - payload;

    SCReturnInt(1);
}

int DetectBytejumpMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
                        Packet *p, Signature *s, SigMatch *m)
{
    DetectBytejumpData *data = (DetectBytejumpData *)m->ctx;
    uint8_t *ptr = NULL;
    uint8_t *jumpptr = NULL;
    uint16_t len = 0;
    uint64_t val = 0;
    int extbytes;

    if (p->payload_len == 0) {
        return 0;
    }

    /* Calculate the ptr value for the bytejump and length remaining in
     * the packet from that point.
     */
    if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
        ptr = p->payload + det_ctx->payload_offset;
        len = p->payload_len - det_ctx->payload_offset;

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
    if (ptr < p->payload || data->nbytes > len) {
        SCLogDebug("Data not within packet "
               "payload=%p, ptr=%p, len=%d, nbytes=%d",
               p->payload, ptr, len, data->nbytes);
        return 0;
    }

    /* Extract the byte data */
    if (data->flags & DETECT_BYTEJUMP_STRING) {
        extbytes = ByteExtractStringUint64(&val, data->base,
                                           data->nbytes, (const char *)ptr);
        if(extbytes <= 0) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED,"Error extracting %d bytes "
                   "of string data: %d", data->nbytes, extbytes);
            return -1;
        }
    }
    else {
        int endianness = (data->flags & DETECT_BYTEJUMP_LITTLE) ? BYTE_LITTLE_ENDIAN : BYTE_BIG_ENDIAN;
        extbytes = ByteExtractUint64(&val, endianness, data->nbytes, ptr);
        if (extbytes != data->nbytes) {
            SCLogError(SC_ERR_BYTE_EXTRACT_FAILED,"Error extracting %d bytes "
                   "of numeric data: %d", data->nbytes, extbytes);
            return -1;
        }
    }

    //printf("VAL: (%" PRIu64 " x %" PRIu32 ") + %d + %" PRId32 "\n", val, data->multiplier, extbytes, data->post_offset);

    /* Adjust the jump value based on flags */
    val *= data->multiplier;
    if (data->flags & DETECT_BYTEJUMP_ALIGN) {
        if ((val % 4) != 0) {
            val += 4 - (val % 4);
        }
    }
    val += extbytes + data->post_offset;

    /* Calculate the jump location */
    if (data->flags & DETECT_BYTEJUMP_BEGIN) {
        jumpptr = p->payload + val;
        //printf("NEWVAL: payload %p + %ld = %p\n", p->payload, val, jumpptr);
    }
    else {
        jumpptr = ptr + val;
        //printf("NEWVAL: ptr %p + %ld = %p\n", ptr, val, jumpptr);
    }


    /* Validate that the jump location is still in the packet
     * \todo Should this validate it is still in the *payload*?
     */
    if ((jumpptr < p->payload) || (jumpptr >= p->payload + p->payload_len)) {
        SCLogDebug("Jump location (%p) is not within "
               "packet (%p-%p)", jumpptr, p->payload, p->payload + p->payload_len - 1);
        return 0;
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        uint8_t *sptr = (data->flags & DETECT_BYTEJUMP_BEGIN) ? p->payload
                                                              : ptr;
        SCLogDebug("jumping %" PRId64 " bytes from %p (%08x) to %p (%08x)",
               val, sptr, (int)(sptr - p->payload),
               jumpptr, (int)(jumpptr - p->payload));
    }
#endif /* DEBUG */

    /* Adjust the detection context to the jump location. */
    det_ctx->payload_offset = jumpptr - p->payload;

    return 1;
}

DetectBytejumpData *DetectBytejumpParse(char *optstr, char **offset)
{
    DetectBytejumpData *data = NULL;
    char *args[10] = {
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        NULL, NULL
    };
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int numargs = 0;
    int i = 0;
    uint32_t nbytes;
    char *str_ptr;
    char *end_ptr;

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, optstr,
                    strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2 || ret > 10) {
        SCLogError(SC_ERR_PCRE_PARSE,"parse error, ret %" PRId32
               ", string \"%s\"", ret, optstr);
        goto error;
    }

    /* The first two arguments are stashed in the first PCRE substring.
     * This is because byte_jump can take 10 arguments, but PCRE only
     * supports 9 substrings, sigh.
     */
    res = pcre_get_substring((char *)optstr, ov,
                             MAX_SUBSTRINGS, 1, (const char **)&str_ptr);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_get_substring failed "
               "for arg 1");
        goto error;
    }

    /* Break up first substring into two parameters
     *
     * NOTE: Because of this, we cannot free args[1] as it is part of args[0],
     * and *yes* this *is* ugly.
     */
    end_ptr = str_ptr;
    while (!(isspace(*end_ptr) || (*end_ptr == ','))) end_ptr++;
    *(end_ptr++) = '\0';
    args[0] = str_ptr;
    numargs++;

    str_ptr = end_ptr;
    while (isspace(*str_ptr) || (*str_ptr == ',')) str_ptr++;
    end_ptr = str_ptr;
    while (!(isspace(*end_ptr) || (*end_ptr == ',')) && (*end_ptr != '\0'))
        end_ptr++;
    *(end_ptr++) = '\0';
    args[1] = str_ptr;
    numargs++;

    /* The remaining args are directly from PCRE substrings */
    for (i = 1; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS, i + 1, (const char **)&str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING,"pcre_get_substring failed for arg %d", i + 1);
            goto error;
        }
        args[i+1] = str_ptr;
        numargs++;
    }

    /* Initialize the data */
    data = SCMalloc(sizeof(DetectBytejumpData));
    if (data == NULL)
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
    if (ByteExtractStringUint32(&nbytes, 10, strlen(args[0]), args[0]) <= 0) {
        SCLogError(SC_ERR_INVALID_VALUE, "Malformed number of bytes: %s", optstr);
        goto error;
    }

    /* Offset */
    if (args[1][0] != '-' && isalpha(args[1][0])) {
        if (offset == NULL) {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "byte_jump supplied with "
                       "var name for offset.  \"value\" argument supplied to "
                       "this function has to be non-NULL");
            goto error;
        }
        *offset = SCStrdup(args[1]);
        if (*offset == NULL)
            goto error;
    } else {
        if (ByteExtractStringInt32(&data->offset, 0, strlen(args[1]), args[1]) <= 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed offset: %s", optstr);
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
        } else if (strcasecmp("align", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_ALIGN;
        } else if (strncasecmp("multiplier ", args[i], 11) == 0) {
            if (ByteExtractStringUint32(&data->multiplier, 10,
                                        strlen(args[i]) - 11,
                                        args[i] + 11) <= 0)
            {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed multiplier: %s", optstr);
                goto error;
            }
        } else if (strncasecmp("post_offset ", args[i], 12) == 0) {
            if (ByteExtractStringInt32(&data->post_offset, 10,
                                       strlen(args[i]) - 12,
                                       args[i] + 12) <= 0)
            {
                SCLogError(SC_ERR_INVALID_VALUE, "Malformed post_offset: %s", optstr);
                goto error;
            }
        } else if (strcasecmp("dce", args[i]) == 0) {
            data->flags |= DETECT_BYTEJUMP_DCE;
        } else {
            SCLogError(SC_ERR_INVALID_VALUE, "Unknown option: \"%s\"", args[i]);
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
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot test more than 23 bytes "
                   "with \"string\": %s", optstr);
            goto error;
        }
    } else {
        if (nbytes > 8) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot test more than 8 bytes "
                   "without \"string\": %s\n", optstr);
            goto error;
        }
        if (data->base != DETECT_BYTEJUMP_BASE_UNSET) {
            SCLogError(SC_ERR_INVALID_VALUE, "Cannot use a base "
                   "without \"string\": %s", optstr);
            goto error;
        }
    }

    /* This is max 23 so it will fit in a byte (see above) */
    data->nbytes = (uint8_t)nbytes;

    for (i = 0; i < numargs; i++){
        if (i == 1) continue; /* args[1] is part of args[0] */
        if (args[i] != NULL) SCFree(args[i]);
    }
    return data;

error:
    for (i = 0; i < numargs; i++){
        if (i == 1) continue; /* args[1] is part of args[0] */
        if (args[i] != NULL) SCFree(args[i]);
    }
    if (data != NULL) DetectBytejumpFree(data);
    return NULL;
}

int DetectBytejumpSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    DetectBytejumpData *data = NULL;
    SigMatch *sm = NULL;
    char *offset = NULL;

    data = DetectBytejumpParse(optstr, &offset);
    if (data == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_BYTEJUMP;
    sm->ctx = (void *)data;

    /* check bytejump modifiers against the signature alproto.  In case they conflict
     * chuck out invalid signature */
    if (data->flags & DETECT_BYTEJUMP_DCE) {
        if (s->alproto != ALPROTO_DCERPC) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Non dce alproto sig has "
                       "bytetest with dce enabled");
            goto error;
        }
        if ( (data->flags & DETECT_BYTEJUMP_STRING) ||
             (data->flags & DETECT_BYTEJUMP_LITTLE) ||
             (data->flags & DETECT_BYTEJUMP_BIG) ||
             (data->flags & DETECT_BYTEJUMP_BEGIN) ||
             (data->base == DETECT_BYTEJUMP_BASE_DEC) ||
             (data->base == DETECT_BYTEJUMP_BASE_HEX) ||
             (data->base == DETECT_BYTEJUMP_BASE_OCT) ) {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "Invalid option. "
                       "DCERPC rule holds an invalid modifier for bytejump.");
            goto error;
        }
    }

    if (s->init_flags & SIG_FLAG_INIT_FILE_DATA) {
        if (data->flags & DETECT_BYTEJUMP_RELATIVE) {
            SigMatch *prev_sm = NULL;
            prev_sm = SigMatchGetLastSMFromLists(s, 8,
                    DETECT_AL_HTTP_SERVER_BODY, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_BYTETEST, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH],
                    DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH]);
            if (prev_sm == NULL) {
                data->flags &= ~DETECT_BYTEJUMP_RELATIVE;
            }

            s->flags |= SIG_FLAG_APPLAYER;
            AppLayerHtpEnableResponseBodyCallback();
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HSBDMATCH);
        } else {
            s->flags |= SIG_FLAG_APPLAYER;
            AppLayerHtpEnableResponseBodyCallback();
            SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_HSBDMATCH);
        }
    } else if (s->alproto == ALPROTO_DCERPC &&
        data->flags & DETECT_BYTEJUMP_RELATIVE) {
        SigMatch *pm = NULL;
        SigMatch *dm = NULL;

        pm = SigMatchGetLastSMFromLists(s, 6,
                                        DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                        DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_PMATCH],
                                        DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_PMATCH]);
        dm = SigMatchGetLastSMFromLists(s, 6,
                                        DETECT_CONTENT, s->sm_lists_tail[DETECT_SM_LIST_DMATCH],
                                        DETECT_PCRE, s->sm_lists_tail[DETECT_SM_LIST_DMATCH],
                                        DETECT_BYTEJUMP, s->sm_lists_tail[DETECT_SM_LIST_DMATCH]);

        if (pm == NULL) {
            SigMatchAppendDcePayload(s, sm);
        } else if (dm == NULL) {
            SigMatchAppendDcePayload(s, sm);
        } else if (pm->idx > dm->idx) {
            SigMatchAppendPayload(s, sm);
        } else {
            SigMatchAppendDcePayload(s, sm);
        }
    } else {
        SigMatchAppendPayload(s, sm);
    }

    if (offset != NULL) {
        SigMatch *bed_sm =
            DetectByteExtractRetrieveSMVar(offset, s,
                                           SigMatchListSMBelongsTo(s, sm));
        if (bed_sm == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown byte_extract var "
                       "seen in byte_jump - %s\n", offset);
            goto error;
        }
        DetectBytejumpData *bjd = sm->ctx;
        bjd->offset = ((DetectByteExtractData *)bed_sm->ctx)->local_id;
        bjd->flags |= DETECT_BYTEJUMP_OFFSET_BE;
        SCFree(offset);
    }

    if (s->init_flags & SIG_FLAG_INIT_FILE_DATA) {
        return 0;
    }

    if ( !(data->flags & DETECT_BYTEJUMP_RELATIVE)) {
        return(0);
    }

    SigMatch *prev_sm = NULL;
    prev_sm = SigMatchGetLastSMFromLists(s, 8,
                                         DETECT_CONTENT, sm->prev,
                                         DETECT_URICONTENT, sm->prev,
                                         DETECT_BYTEJUMP, sm->prev,
                                         DETECT_PCRE, sm->prev);
    if (prev_sm == NULL) {
        if (s->alproto == ALPROTO_DCERPC) {
            SCLogDebug("No preceding content or pcre keyword.  Possible "
                       "since this is an alproto sig.");
            return 0;
        } else {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "No preceding content "
                       "or uricontent or pcre option");
            return -1;
        }
    }

    DetectContentData *cd = NULL;
    DetectContentData *ud = NULL;
    DetectPcreData *pe = NULL;

    switch (prev_sm->type) {
        case DETECT_CONTENT:
            /* Set the relative next flag on the prev sigmatch */
            cd = (DetectContentData *)prev_sm->ctx;
            if (cd == NULL) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                           "previous keyword!");
                return -1;
            }
            cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;

            break;

        case DETECT_URICONTENT:
            /* Set the relative next flag on the prev sigmatch */
            ud = (DetectContentData *)prev_sm->ctx;
            if (ud == NULL) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                           "previous keyword!");
                return -1;
            }
            ud->flags |= DETECT_CONTENT_RELATIVE_NEXT;

            break;

        case DETECT_PCRE:
            pe = (DetectPcreData *)prev_sm->ctx;
            if (pe == NULL) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                           "previous keyword!");
                return -1;
            }
            pe->flags |= DETECT_PCRE_RELATIVE_NEXT;

            break;

        case DETECT_BYTEJUMP:
            SCLogDebug("No setting relative_next for bytejump.  We "
                       "have no use for it");

            break;

        default:
            /* this will never hit */
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Unknown previous-"
                       "previous keyword!");
            return -1;
    } /* switch */

    return 0;

error:
    if (data != NULL)
        DetectBytejumpFree(data);
    if (sm != NULL)
        SCFree(sm);
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
    SCFree(data);
}


/* UNITTESTS */
#ifdef UNITTESTS
#include "util-unittest-helper.h"
/**
 * \test DetectBytejumpTestParse01 is a test to make sure that we return
 * "something" when given valid bytejump opt
 */
int DetectBytejumpTestParse01(void) {
    int result = 0;
    DetectBytejumpData *data = NULL;
    data = DetectBytejumpParse("4,0", NULL);
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
    data = DetectBytejumpParse("4, 0", NULL);
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
    data = DetectBytejumpParse(" 4,0 , relative , little, string, "
                               "dec, align, from_beginning", NULL);
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
    data = DetectBytejumpParse(" 4,0 , relative , little, string, "
                               "dec, align, from_beginning , "
                               "multiplier 2 , post_offset -16 ", NULL);
    if (data != NULL) {
        if (   (data->nbytes == 4)
            && (data->offset == 0)
            && (data->multiplier == 2)
            && (data->post_offset == -16)
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
    data = DetectBytejumpParse(" 4,0 , relative , little, dec, "
                               "align, from_beginning", NULL);
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
    data = DetectBytejumpParse("9, 0", NULL);
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
    data = DetectBytejumpParse("24, 0, string, dec", NULL);
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
    data = DetectBytejumpParse("4, 0xffffffffffffffff", NULL);
    if (data == NULL) {
        result = 1;
    }

    return result;
}

/**
 * \test Test dce option.
 */
int DetectBytejumpTestParse09(void) {
    Signature *s = SigAlloc();
    int result = 1;

    s->alproto = ALPROTO_DCERPC;

    result &= (DetectBytejumpSetup(NULL, s, "4,0, align, multiplier 2, "
                                   "post_offset -16,dce") == 0);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, multiplier 2, "
                                   "post_offset -16,dce") == 0);
    result &= (DetectBytejumpSetup(NULL, s, "4,0,post_offset -16,dce") == 0);
    result &= (DetectBytejumpSetup(NULL, s, "4,0,dce") == 0);
    result &= (DetectBytejumpSetup(NULL, s, "4,0,dce") == 0);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, string, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, big, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, little, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, string, dec, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, string, oct, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, string, hex, dce") == -1);
    result &= (DetectBytejumpSetup(NULL, s, "4,0, from_beginning, dce") == -1);
    result &= (s->sm_lists[DETECT_SM_LIST_DMATCH] == NULL && s->sm_lists[DETECT_SM_LIST_PMATCH] != NULL);

    SigFree(s);
    return result;
}

/**
 * \test Test dce option.
 */
int DetectBytejumpTestParse10(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(msg:\"Testing bytejump_body\"; "
                               "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                               "dce_stub_data; "
                               "content:\"one\"; distance:0; "
                               "byte_jump:4,0,align,multiplier 2, "
                               "post_offset -16,relative,dce; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }
    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_BYTEJUMP);
    bd = (DetectBytejumpData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (!(bd->flags & DETECT_BYTEJUMP_DCE) &&
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) &&
        (bd->flags & DETECT_BYTEJUMP_STRING) &&
        (bd->flags & DETECT_BYTEJUMP_BIG) &&
        (bd->flags & DETECT_BYTEJUMP_LITTLE) ) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "byte_jump:4,0,align,multiplier 2, "
                      "post_offset -16,relative,dce; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_BYTEJUMP);
    bd = (DetectBytejumpData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if (!(bd->flags & DETECT_BYTEJUMP_DCE) &&
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) &&
        (bd->flags & DETECT_BYTEJUMP_STRING) &&
        (bd->flags & DETECT_BYTEJUMP_BIG) &&
        (bd->flags & DETECT_BYTEJUMP_LITTLE) ) {
        result = 0;
        goto end;
    }

    s->next = SigInit(de_ctx, "alert tcp any any -> any any "
                      "(msg:\"Testing bytejump_body\"; "
                      "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                      "dce_stub_data; "
                      "content:\"one\"; distance:0; "
                      "byte_jump:4,0,align,multiplier 2, "
                      "post_offset -16,relative; sid:1;)");
    if (s->next == NULL) {
        result = 0;
        goto end;
    }
    s = s->next;
    if (s->sm_lists_tail[DETECT_SM_LIST_DMATCH] == NULL) {
        result = 0;
        goto end;
    }
    result &= (s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->type == DETECT_BYTEJUMP);
    bd = (DetectBytejumpData *)s->sm_lists_tail[DETECT_SM_LIST_DMATCH]->ctx;
    if ((bd->flags & DETECT_BYTEJUMP_DCE) &&
        !(bd->flags & DETECT_BYTEJUMP_RELATIVE) &&
        (bd->flags & DETECT_BYTEJUMP_STRING) &&
        (bd->flags & DETECT_BYTEJUMP_BIG) &&
        (bd->flags & DETECT_BYTEJUMP_LITTLE) ) {
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
int DetectBytejumpTestParse11(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 1;
    Signature *s = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_sub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,big,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,little,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,hex,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,dec,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,string,oct,dce; sid:1;)");
    if (s != NULL) {
        result = 0;
        goto end;
    }

    s = SigInit(de_ctx, "alert tcp any any -> any any "
                "(msg:\"Testing bytejump_body\"; "
                "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5; "
                "dce_stub_data; "
                "content:\"one\"; byte_jump:4,0,align,multiplier 2, "
                "post_offset -16,from_beginning,dce; sid:1;)");
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
static int DetectBytejumpTestParse12(void)
{
    DetectEngineCtx *de_ctx = NULL;
    int result = 0;
    Signature *s = NULL;
    DetectBytejumpData *bd = NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;
    de_ctx->sig_list = SigInit(de_ctx, "alert tcp any any -> any any "
                               "(file_data; byte_jump:4,0,align,multiplier 2, "
                               "post_offset -16,relative; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        goto end;
    }

    s = de_ctx->sig_list;
    if (s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH] == NULL) {
        goto end;
    }

    if (s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH]->type != DETECT_BYTEJUMP) {
        goto end;
    }

    bd = (DetectBytejumpData *)s->sm_lists_tail[DETECT_SM_LIST_HSBDMATCH]->ctx;
    if ((bd->flags & DETECT_BYTEJUMP_DCE) &&
        (bd->flags & DETECT_BYTEJUMP_RELATIVE) &&
        (bd->flags & DETECT_BYTEJUMP_STRING) &&
        (bd->flags & DETECT_BYTEJUMP_BIG) &&
        (bd->flags & DETECT_BYTEJUMP_LITTLE) ) {
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

/**
 * \test DetectByteJumpTestPacket01 is a test to check matches of
 * byte_jump and byte_jump relative works if the previous keyword is pcre
 * (bug 142)
 */
int DetectByteJumpTestPacket01 (void) {
    int result = 0;
    uint8_t *buf = (uint8_t *)"GET /AllWorkAndNoPlayMakesWillADullBoy HTTP/1.0"
                    "User-Agent: Wget/1.11.4"
                    "Accept: */*"
                    "Host: www.google.com"
                    "Connection: Keep-Alive"
                    "Date: Mon, 04 Jan 2010 17:29:39 GMT";
    uint16_t buflen = strlen((char *)buf);
    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"pcre + byte_test + "
    "relative\"; pcre:\"/AllWorkAndNoPlayMakesWillADullBoy/\"; byte_jump:1,6,"
    "relative,string,dec; content:\"0\"; sid:134; rev:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}

/**
 * \test DetectByteJumpTestPacket02 is a test to check matches of
 * byte_jump and byte_jump relative works if the previous keyword is byte_jump
 * (bug 165)
 */
int DetectByteJumpTestPacket02 (void) {
    int result = 0;
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

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"byte_jump with byte_jump"
                 " + relative\"; byte_jump:1,13; byte_jump:4,0,relative; "
                 "content:\"|48 00 00|\"; within:3; sid:144; rev:1;)";

    result = UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);
end:
    return result;
}

int DetectByteJumpTestPacket03(void)
{
    int result = 0;
    uint8_t *buf = NULL;
    uint16_t buflen = 0;
    buf = SCMalloc(4);
    if (buf == NULL) {
        printf("malloc failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(buf, "boom", 4);
    buflen = 4;

    Packet *p;
    p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);

    if (p == NULL)
        goto end;

    char sig[] = "alert tcp any any -> any any (msg:\"byte_jump\"; "
        "byte_jump:1,214748364; sid:1; rev:1;)";

    result = !UTHPacketMatchSig(p, sig);

    UTHFreePacket(p);

end:
    if (buf != NULL)
        SCFree(buf);
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
    UtRegisterTest("DetectBytejumpTestParse09", DetectBytejumpTestParse09, 1);
    UtRegisterTest("DetectBytejumpTestParse10", DetectBytejumpTestParse10, 1);
    UtRegisterTest("DetectBytejumpTestParse11", DetectBytejumpTestParse11, 1);
    UtRegisterTest("DetectBytejumpTestParse12", DetectBytejumpTestParse12, 1);

    UtRegisterTest("DetectByteJumpTestPacket01", DetectByteJumpTestPacket01, 1);
    UtRegisterTest("DetectByteJumpTestPacket02", DetectByteJumpTestPacket02, 1);
    UtRegisterTest("DetectByteJumpTestPacket03", DetectByteJumpTestPacket03, 1);
#endif /* UNITTESTS */
}

