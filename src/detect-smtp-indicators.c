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

#ifdef UNITTESTS
static int
addToWatchListTest01(void);
static int
isInWatchListTest01(void);
#endif


int
DetectSMTPtMatch(ThreadVars *, DetectEngineThreadCtx *, Packet *,
        Signature *, SigMatch *);
static int
DetectSMTPSetup(DetectEngineCtx *, Signature *, char *);

void
SMPTIndicatorsRegisterTests(void);

/**
 * \brief Registration function for keyword: stixsmtp
 */
void
DetectSMPTIndicatorsRegister(void)
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
static int
DetectSMTPSetup(DetectEngineCtx *de_ctx, Signature *s, char *rawstr)
{

//s->msg = "STIX IP Watch List was matched";
    SigMatch *sm = NULL;
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;


    sm->type = DETECT_STIX_SMTP_INDICATORS;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);

    return 0;
    error: if (sm != NULL)
        SCFree(sm);
    return -1;

}

#define STIX_HEADER "STIX SMTP Indicators was matched"


/* Used to indicate that the parser has completed */
#define SMTP_PARSER_STATE_TXN_COMPLETE 0x10

/* Used to indicate that the SMTP detector has run against */
#define SMTP_INDICATOR_DETECTION_COMPLETE 0x20

int messageMatchesIndicator(SMTPState *state, SMTPIndicator* indicator);
int partMatchesFileIndicator(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator);
int addressMatchesIndicator(uint8_t *address, SMTPAddressIndicator *indicator);


/**
 * \brief Detection function for keyword: stix
 */
int
DetectSMTPtMatch(ThreadVars * tv, DetectEngineThreadCtx * de_ctx,
        Packet * p, Signature * s, SigMatch *sm)
{
	// set the answer to none
	int answer = 0;

	SMTPState *state = p->flow->alstate;

	// fail out if the parsing has not completed
	if(!(state->parser_state & SMTP_PARSER_STATE_TXN_COMPLETE)) return 0;

	// fail out if this has already been run
	if(state->parser_state & SMTP_INDICATOR_DETECTION_COMPLETE) return 0;

	// indicators are kept in a linked list
	SMTPIndicator *indicator = SMTPIndicatorGetRootIndicator();
	while(indicator != NULL){
		if(messageMatchesIndicator(state, indicator)){
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
int
messageMatchesIndicator(SMTPState *state, SMTPIndicator* indicator){
	if(indicator->from != NULL){
		if(!addressMatchesIndicator(state->from, indicator->from)){
			return 0;
		}
	}
	SMTPIndicatorsFileObject *attachmentIndicator = indicator->relatedFileObjects;

	// iterate over the attachements in the multi-part mime structures of state
	while(attachmentIndicator != NULL){

		// no attachements if there was no multi-part mime parsing, no match
		if(state->mpartp_parser == NULL)
			return 0;

		// grab the multipart structure out of the parser
		htp_multipart_t *multipart = htp_mpartp_get_multipart(state->mpartp_parser);

		int matched = 0;
		int partIndex = 0;
		for(partIndex = 0; partIndex < multipart->boundary_count; partIndex++){
			// grab the part
			htp_multipart_part_t *part = htp_list_array_get(multipart->parts, partIndex);

			// preamble and epiloque are not interesting...
			if(part->type == MULTIPART_PART_PREAMBLE || part->type == MULTIPART_PART_EPILOGUE) continue;

			if(part->headers != NULL){

				if(partMatchesFileIndicator(part, attachmentIndicator)){
					matched = 1;
					break;
				}
			}
		}

		// return 0 if no parts mached against the indicator
		if(!matched) return 0;

		// go to the next attachment indicator...if any
		attachmentIndicator = attachmentIndicator->next;
	}

	// nothing in the document matched the ind
	return 1;
}


int partIsAttachment(htp_multipart_part_t *part);
int partMatchesFileExtension(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator);
int partMatchesLengthAndContent(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator);

/**
 * \brief Attempt to match a multi-part part against a file indicator
 */
int
partMatchesFileIndicator(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator){
	// try to keep things simple
	int answer = 0;

	// first check if this is an attachemnt
	if(!partIsAttachment(part)) return 0;

	if(indicator->fieldsUsed & SMTP_FILE_OBJECT_FILE_EXTENSION){
		if(!partMatchesFileExtension(part, indicator)) goto done;
	}

	if(indicator->fieldsUsed & (SMTP_FILE_OBJECT_SIZE_IN_BYTES | SMTP_FILE_OBJECT_HASHES)){
		if(!partMatchesLengthAndContent(part, indicator)) goto done;
	}

	// everything matched!
	answer = 1;

	done:
	return answer;
}
/**
 * \brief Check if the part is an attachment
 */
int
partIsAttachment(htp_multipart_part_t *part){

	// Content-Disposition has if it is an attachemnt and the filename if so
	htp_header_t *contentDisposition = htp_table_get_c(part->headers, "content-disposition");

	// probably not an attachment if there is no content disposition
	if(contentDisposition == NULL){
		return 0;
	}


	if(!bstr_begins_with_c_nocase(contentDisposition->value, "attachment")){
		return 0;
	}

	return 1;
}

/**
 * \brief Check if the part filename matches the file indicator extension
 */
int
partMatchesFileExtension(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator){
	int answer = 0;

	// declare this way out here so it may be cleaned up before existing way down there
	char *cdValue = NULL;

	// I can't compute hashes yet, so not checking those, return 0 if there is nothing to check
	if((indicator->fieldsUsed & (SMTP_FILE_OBJECT_FILE_EXTENSION | SMTP_FILE_OBJECT_SIZE_IN_BYTES)) == 0){
		goto done;
	}

	// Content-Disposition has if it is an attachment and the filename if so
	htp_header_t *contentDisposition = htp_table_get_c(part->headers, "content-disposition");

	// probably not an attachment if there is no content disposition
	if(contentDisposition == NULL){
		goto done;
	}

	cdValue = bstr_util_strdup_to_c(contentDisposition->value);

	// if this is an attachment, then we know that the filename will follow the attachment...
	char *findFilenamePtr = strchr(cdValue, ';');

	// not much I can do if there is no filename here...doesn't match
	if(findFilenamePtr == NULL) goto done;

	findFilenamePtr++;

	while(*findFilenamePtr != '\0' && (*findFilenamePtr == ' ' || *findFilenamePtr == '\t')) findFilenamePtr++;

	if(strncmp(findFilenamePtr, "filename=\"", 8) == 0){
		findFilenamePtr += 10;
		char *lastQuote = strrchr(findFilenamePtr, '\"');

		if(lastQuote != NULL){
			int indicatorLen = strlen((char*)indicator->fileExtension);
			// one final sanity check
			if(indicatorLen > lastQuote - findFilenamePtr) goto done;
			char *toCompare = lastQuote-indicatorLen;
			if(strncmp(toCompare, (char*)indicator->fileExtension, indicatorLen) != 0){
				goto done;
			}
		}
	} else {
		// did not find a filename, no match
		goto done;
	}

	// I did not reject for any reason above, it matches!
	answer = 1;

	done:

	if(cdValue != NULL) free(cdValue);

	return answer;
}


/**
 * \brief More detailed file indicator check, length and hashes
 */
int
partMatchesLengthAndContent(htp_multipart_part_t *part, SMTPIndicatorsFileObject *indicator){
	int answer = 0;
	// things I plan to leave to cleanup until the last moment
	char *hashString = NULL;
	unsigned char *hashResult = NULL;
	char *tmpstr = NULL;

	htp_header_t *transferEncoding = htp_table_get_c(part->headers, "content-transfer-encoding");

	if(transferEncoding == NULL){
		// no match if I can't even find a transfer encoding...
		goto done;
	}

	if(bstr_cmp_c_nocase(transferEncoding->value, "base64") == 0){
		htp_base64_decoder decoder;

		htp_base64_decoder_init(&decoder);
		tmpstr = SCMalloc(part->value->len);


		if (tmpstr != NULL){
			// decode the base64 string and get the length
			size_t resulting_len = htp_base64_decode(&decoder, bstr_ptr(part->value), part->value->len, tmpstr, part->value->len);

			// check the length now, no need to check the hash if I can eliminate the length
			if((indicator->fieldsUsed & SMTP_FILE_OBJECT_SIZE_IN_BYTES) && resulting_len != indicator->sizeInBytes) goto done;

#ifdef HAVE_NSS

			hashResult = SCMalloc(MD5_LENGTH+1);
			hashString = SCMalloc((MD5_LENGTH*2)+1);
			memset(hashResult, 0, MD5_LENGTH+1);
			unsigned int resultLen = 0;

			// now that I have the content look for a hash, using NSS
			HASHContext *hashCtx = HASH_Create(HASH_AlgMD5);
			HASH_Begin(hashCtx);
			HASH_Update(hashCtx, (const unsigned char*)tmpstr, resulting_len);
			HASH_End(hashCtx, hashResult, &resultLen, MD5_LENGTH);
			HASH_Destroy(hashCtx);

			// now turn the hash into the form more commnonly used...
			unsigned int hashIdx;
			for(hashIdx = 0; hashIdx < resultLen; hashIdx++){
				// not sure why there is garbage int he string, strip it out
				sprintf(hashString+(hashIdx*2), "%02x", (int)hashResult[hashIdx]&0xff);
			}
			hashString[MD5_LENGTH*2] = '\0'; // and null terminate the beast



			// if the fieldsUsed says there are hashes then check if one matches
			if((indicator->fieldsUsed & SMTP_FILE_OBJECT_HASHES) && indicator->hashes != NULL){
				int oneHashMatched = 0;

				// hashes are a null terminated list
				uint8_t **nextHash = indicator->hashes;
				while(*nextHash != NULL){
					if(strcmp((const char *)(*nextHash), hashString) == 0){
						// any one match is a winner
						oneHashMatched = 1;
						break;
					}

					// increment to the next hash pointer
					nextHash++;
				}

				if(!oneHashMatched) goto done;
			}

#endif

		}

	}

	// I did not reject for any reason above, it matches!
	answer = 1;

	done:
	// clean up
	if(hashString != NULL) SCFree(hashString);
	if(tmpstr != NULL) SCFree(tmpstr);
	if(hashResult != NULL) SCFree(hashResult);

	return answer;
}

/**
 * \brief check if an address from the message matches addresses in the indicator
 */
int
addressMatchesIndicator(uint8_t *address, SMTPAddressIndicator *indicator){
	enum SMTPIndicatorAddressValueCondition condition = indicator->condition;

	if(condition == equals){
		// return true if the strings match
		return strcmp((char*)address, (char*)(indicator->value)) == 0;
	} else if( condition == contains){
		// return true if strstr found something, not null
		return strstr((char*)address, (char*)(indicator->value)) != NULL;
	}

	return 0;
}

/**
 * \brief Check if the part filename matches the file indicator extension
 */
void
SMPTIndicatorsRegisterTests(void)
{
#ifdef UNITTESTS
	// leave one old in place so I know what these tests would look like
    // UtRegisterTest("addToWatchList", addToWatchListTest01, 1);
    UtRegisterTest("isInWatchListTest01", isInWatchListTest01, 1);
#endif
}
#ifdef UNITTESTS
/*
int
addToWatchListTest01(void)
{

    int result = 1;
    CreateIpWatchListCtx();

    char* addresses[4];

    addresses[0] = "192.168.0.1";
    addresses[1] = "192.168.0.2";
    addresses[2] = "10.0.0.1";
    addresses[3] = "10.0.0.0/16";

    if (addIpaddressesToWatchList("Test Watch List", addresses, 4))
        result = 0;

    CreateIpWatchListCtxFree();
    return result;
}
*/
}
#endif
