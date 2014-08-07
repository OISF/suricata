/* Copyright (C) 2013 Open Information Security Foundation
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
 * \author David Cameron <dave@davesomebody.com>
 *
 * SMTP STIX Indicator Detection
 */

#include "suricata-common.h"
#include "decode.h"
#include "detect.h"
#include "threads.h"
#include "flow.h"
#include "flow-bit.h"
#include "flow-util.h"
#include "detect-iprep.h"
#include "util-spm.h"
#include <string.h>
#include "htp/htp_table.h"

#include "app-layer-parser.h"
#include "app-layer-smtp.h"

#ifdef HAVE_NSS
#include <nss/sechash.h>
#endif // HAVE_NSS
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "app-layer-smtp.h"

#include "util-debug.h"
#include "util-smtp-indicators.h"

#include "host.h"

#include "util-unittest.h"

int DetectSMTPtMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *, Signature *, SigMatch *);
static int DetectSMTPSetup(DetectEngineCtx *, Signature *, char *);

void SMPTIndicatorsRegisterTests(void);

/**
 * \brief Registration function for keyword: stixsmtp
 */
void DetectSMPTIndicatorsRegister(void)
{
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].name = "stixsmtp";
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].Match = DetectSMTPtMatch;
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].Setup = DetectSMTPSetup;
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].Free = NULL;
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].alproto = ALPROTO_SMTP;
    sigmatch_table[DETECT_STIX_SMTP_INDICATORS].RegisterTests = SMPTIndicatorsRegisterTests;
    // sigmatch_table[DETECT_STIX_IPWATCH].flags |= SIGMATCH_IPONLY_COMPAT;
    SMTPIndicatorsCreateContext();
}

/**
 *  \brief Setup for stixsmtp
 *
 *  Register the detector.
 */
static int DetectSMTPSetup(DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{
    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL )
        goto error;

    sm->type = DETECT_STIX_SMTP_INDICATORS;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;
    error: if (sm != NULL )
        SCFree(sm);
    return -1;
}

#define STIX_HEADER "STIX SMTP Indicators was matched"

/* Used to indicate that the parser has completed */
#define SMTP_PARSER_STATE_TXN_COMPLETE 0x10

/* Used to indicate that the SMTP detector has run against */
#define SMTP_INDICATOR_DETECTION_COMPLETE 0x20

int MessageMatchesIndicator(SMTPState *state, SMTPIndicator* indicator);
int PartMatchesFileIndicator(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator);
int AddressMatchesIndicator(uint8_t *address, SMTPAddressIndicator *indicator);

/**
 * \brief Detection function for keyword: stix
 */
int DetectSMTPtMatch(ThreadVars * tv, DetectEngineThreadCtx * de_ctx,
        Packet * p, Signature * s, SigMatch *sm)
{
    // set the answer to none
    int answer = 0;

    SMTPState *state = p->flow->alstate;

    // fail out if the parsing has not completed
    if (!(state->parser_state & SMTP_PARSER_STATE_TXN_COMPLETE))
        return 0;

    // fail out if this has already been run
    if (state->parser_state & SMTP_INDICATOR_DETECTION_COMPLETE)
        return 0;

    // indicators are kept in a linked list
    SMTPIndicator *indicator = SMTPIndicatorGetRootIndicator();
    while (indicator != NULL ) {
        if (MessageMatchesIndicator(state, indicator)) {
            // set the answer to matched and complete
            answer = 1;
            goto done;
        }

        indicator = indicator->next;
    }

    done:

    // set the indicators complete flag
    state->parser_state &= SMTP_INDICATOR_DETECTION_COMPLETE;

    return answer;
}

/**
 * \brief Attempt to match a state against an indicator
 */
int MessageMatchesIndicator(SMTPState *state, SMTPIndicator* indicator)
{
    if (indicator->from != NULL ) {
        if (!AddressMatchesIndicator(state->from, indicator->from)) {
            return 0;
        }
    }
    SMTPIndicatorsFileObject *attachment_indicator = indicator->related_file_objects;

    // iterate over the attachments in the multi-part mime structures of state
    while (attachment_indicator != NULL ) {

        // no attachments if there was no multi-part mime parsing, no match
        if (state->mpartp_parser == NULL )
            return 0;

        // grab the multipart structure out of the parser
        htp_multipart_t *multipart = htp_mpartp_get_multipart(state->mpartp_parser);

        int matched = 0;
        int part_index = 0;
        for (part_index = 0; part_index < multipart->boundary_count; part_index++) {
            // grab the part
            htp_multipart_part_t *part = htp_list_array_get(multipart->parts, part_index);

            // preamble and epilogue are not interesting...
            if (part->type == MULTIPART_PART_PREAMBLE || part->type == MULTIPART_PART_EPILOGUE)
                continue;

            if (part->headers != NULL ) {
                if (PartMatchesFileIndicator(part, attachment_indicator)) {
                    matched = 1;
                    break;
                }
            }
        }

        // return 0 if no parts matched against the indicator
        if (!matched)
            return 0;

        // go to the next attachment indicator...if any
        attachment_indicator = attachment_indicator->next;
    }

    // nothing in the document matched the ind
    return 1;
}

int PartIsAttachment(htp_multipart_part_t *part);
int PartMatchesFileExtension(htp_multipart_part_t *part,
        SMTPIndicatorsFileObject *indicator);
int PartMatchesLengthAndContent(htp_multipart_part_t *part,
        SMTPIndicatorsFileObject *indicator);

/**
 * \brief Attempt to match a multi-part part against a file indicator
 */
int PartMatchesFileIndicator(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator)
{
    // first check if this is an attachment
    if (!PartIsAttachment(part))
        return 0;

    if (indicator->fields_used & SMTP_FILE_OBJECT_FILE_EXTENSION) {
        if (!PartMatchesFileExtension(part, indicator))
            return 0;
    }

    if (indicator->fields_used
            & (SMTP_FILE_OBJECT_SIZE_IN_BYTES | SMTP_FILE_OBJECT_HASHES)) {
        if (!PartMatchesLengthAndContent(part, indicator))
            return 0;
    }

    // everything matched!
    return 1;
}

/**
 * \brief Check if the part is an attachment
 */
int PartIsAttachment(htp_multipart_part_t *part)
{
    htp_header_t *content_disposition = htp_table_get_c(part->headers,
            "content-disposition");

    // Not an attachment if there is no content disposition
    if (content_disposition == NULL ) {
        return 0;
    }

    if (!bstr_begins_with_c_nocase(content_disposition->value, "attachment")) {
        return 0;
    }

    return 1;
}

/**
 * \brief Check if the part filename matches the file indicator extension
 */
int PartMatchesFileExtension(htp_multipart_part_t *part,
        SMTPIndicatorsFileObject *indicator)
{
    int answer = 0;

    // Declare this way out here so it may be cleaned up before existing way down there
    char *cd_value = NULL;

    // Can't compute hashes yet, so not checking those, return 0 if there is nothing to check
    if ((indicator->fields_used
            & (SMTP_FILE_OBJECT_FILE_EXTENSION | SMTP_FILE_OBJECT_SIZE_IN_BYTES)) == 0) {
        goto done;
    }

    htp_header_t *content_disposition = htp_table_get_c(part->headers,
            "content-disposition");

    // Not an attachment if there is no content disposition
    if (content_disposition == NULL ) {
        goto done;
    }

    cd_value = bstr_util_strdup_to_c(content_disposition->value);

    // if this is an attachment, then we know that the filename will follow the attachment...
    char *find_filename_ptr = strchr(cd_value, ';');

    // not much I can do if there is no filename here...doesn't match
    if (find_filename_ptr == NULL )
        goto done;

    find_filename_ptr++;

    while (*find_filename_ptr != '\0'
            && (*find_filename_ptr == ' ' || *find_filename_ptr == '\t'))
        find_filename_ptr++;

    if (strncmp(find_filename_ptr, "filename=\"", 8) == 0) {
        find_filename_ptr += 10;
        char *last_quote = strrchr(find_filename_ptr, '\"');

        if (last_quote != NULL ) {
            int indicator_len = strlen((char*) indicator->file_extension);
            // one final sanity check
            if (indicator_len > last_quote - find_filename_ptr)
                goto done;
            char *to_compare = last_quote - indicator_len;
            if (strncmp(to_compare, (char*) indicator->file_extension,
                    indicator_len) != 0) {
                goto done;
            }
        }
    } else {
        // did not find a filename, no match
        goto done;
    }

    // No rejections for any reason above, it matches!
    answer = 1;

    done:
    if (cd_value != NULL )
        free(cd_value);

    return answer;
}

/**
 * \brief More detailed file indicator check, length and hashes
 */
int PartMatchesLengthAndContent(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator)
{
    int answer = 0;
    // Variables that will be freed
    char *hash_string = NULL;
    unsigned char *hash_result = NULL;
    char *tmpstr = NULL;

    htp_header_t *transfer_encoding = htp_table_get_c(part->headers, "content-transfer-encoding");

    if (transfer_encoding == NULL ) {
        // no match if can't even find a transfer encoding...
        goto done;
    }

    if (bstr_cmp_c_nocase(transfer_encoding->value, "base64") == 0) {
        htp_base64_decoder decoder;

        htp_base64_decoder_init(&decoder);
        tmpstr = SCMalloc(part->value->len);

        if (tmpstr != NULL ) {
            // decode the base64 string and get the length
            size_t resulting_len = htp_base64_decode(&decoder,
                    bstr_ptr(part->value), part->value->len, tmpstr,
                    part->value->len);

            // check the length now, no need to check the hash if I can eliminate the length
            if ((indicator->fields_used & SMTP_FILE_OBJECT_SIZE_IN_BYTES)
                    && resulting_len != indicator->size_in_bytes)
                goto done;

#ifdef HAVE_NSS

            hash_result = SCMalloc(MD5_LENGTH+1);
            hash_string = SCMalloc((MD5_LENGTH*2)+1);
            if (unlikely(hash_result == NULL) || unlikely(hash_string == NULL) ) {
                goto done;
            }
            memset(hash_result, 0, MD5_LENGTH+1);
            unsigned int result_len = 0;

            // With the content look for a hash, using NSS
            HASHContext *hash_ctx = HASH_Create(HASH_AlgMD5);
            HASH_Begin(hash_ctx);
            HASH_Update(hash_ctx, (const unsigned char*)tmpstr, resulting_len);
            HASH_End(hash_ctx, hash_result, &result_len, MD5_LENGTH);
            HASH_Destroy(hash_ctx);

            // now turn the hash into the form more commnonly used...
            unsigned int hash_idx;
            for(hash_idx = 0; hash_idx < result_len; hash_idx++) {
                // Strip out the garbage in the string
                snprintf(hash_string+(hash_idx*2), (MD5_LENGTH*2)+1, "%02x", (int)hash_result[hash_idx]&0xff);
            }
            hash_string[MD5_LENGTH*2] = '\0'; // Null terminate

            // if the fields_used says there are hashes then check if one matches
            if((indicator->fields_used & SMTP_FILE_OBJECT_HASHES) && indicator->hashes != NULL) {
                int one_hash_matched = 0;

                // hashes are a null terminated list
                uint8_t **next_hash = indicator->hashes;
                while(*next_hash != NULL) {
                    if(strcmp((const char *)(*next_hash), hash_string) == 0) {
                        // any one match is a winner
                        one_hash_matched = 1;
                        break;
                    }

                    // increment to the next hash pointer
                    next_hash++;
                }

                if(!one_hash_matched)
                    goto done;
            }

#endif

        }
    }

    // I did not reject for any reason above, it matches!
    answer = 1;

    done:
    // clean up
    if (hash_string != NULL )
        SCFree(hash_string);
    if (tmpstr != NULL )
        SCFree(tmpstr);
    if (hash_result != NULL )
        SCFree(hash_result);

    return answer;
}

/**
 * \brief check if an address from the message matches addresses in the indicator
 */
int AddressMatchesIndicator(uint8_t *address, SMTPAddressIndicator *indicator)
{
    enum SMTPIndicatorAddressValueCondition condition = indicator->condition;

    if (condition == equals) {
        // return true if the strings match
        return strcmp((char*) address, (char*) (indicator->value)) == 0;
    } else if (condition == contains) {
        // return true if strstr found something, not null
        return strstr((char*) address, (char*) (indicator->value)) != NULL ;
    }

    return 0;
}

/**
 * \brief Check if the part filename matches the file indicator extension
 */
void SMPTIndicatorsRegisterTests(void)
{
#ifdef UNITTESTS
    // leave one old in place so I know what these tests would look like
    // UtRegisterTest("AddToWatchListTest01", AddToWatchListTest01, 1);
    // UtRegisterTest("IsInWatchListTest01", IsInWatchListTest01, 1);
#endif
}

/*
#ifdef UNITTESTS
 int
 AddToWatchListTest01(void)
 {

 int result = 1;
 CreateIpWatchListCtx();

 char* addresses[4];

 addresses[0] = "192.168.0.1";
 addresses[1] = "192.168.0.2";
 addresses[2] = "10.0.0.1";
 addresses[3] = "10.0.0.0/16";

 if (AddIpaddressesToWatchList("Test Watch List", addresses, 4))
 result = 0;

 CreateIpWatchListCtxFree();
 return result;
 }
}
#endif
*/
