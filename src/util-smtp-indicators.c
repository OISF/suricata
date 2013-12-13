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
 * SMTP STIX Indicator
 */



#include <util-smtp-indicators.h>

static SMTPIndicatorsCtx *_smtpindicatorsCtx;



SMTPAddressIndicator *SMTPIndicatorCreateAddressIndicator(const uint8_t *value, enum SMTPIndicatorAddressValueCondition condition ){

	if(value != NULL){
		SMTPAddressIndicator *indicator = SCMalloc(sizeof(SMTPAddressIndicator));
		memset(indicator, 0, sizeof(SMTPAddressIndicator));

		indicator->value = SCMalloc(strlen((const char*)value)+1);
		strcpy((char*)indicator->value, (const char*)value);

		indicator->condition = condition;

		return indicator;
	} else {
		return NULL;
	}

}

int
SMTPIndicatorDestroyAddressIndicator(SMTPAddressIndicator *indicator){
	if(indicator->value != NULL){
		SCFree(indicator->value);
	}

	return 0;
}


SMTPIndicatorsFileObject * SMTPIndicatorCreateFileObject(const uint8_t *fileExtention, uint8_t **hashes, int hashCount, uint16_t sizeInBytes, int useSizeInBytes){
	SMTPIndicatorsFileObject *result = SCMalloc(sizeof(SMTPIndicatorsFileObject));
	memset(result, 0, sizeof(SMTPIndicatorsFileObject));
	if(fileExtention != NULL){
		result->fileExtension = SCMalloc(strlen((const char*)fileExtention)+1);
		strcpy((char*)(result->fileExtension), (const char*)fileExtention);
		result->fieldsUsed |= SMTP_FILE_OBJECT_FILE_EXTENSION;
	}

	if(hashes != NULL){
		result->hashes = SCMalloc(sizeof(uint8_t*)*(hashCount+1));
		int hashIdx = 0;

		// NUll terminated list of hashes
		while(hashIdx < hashCount){
			result->hashes[hashIdx] = SCMalloc(strlen((const char*)(hashes[hashIdx]))+1);
			strcpy((char*)(result->hashes[hashIdx]), (const char*)(hashes[hashIdx]));
			hashIdx++;
		}
		result->hashes[hashCount] = NULL;

		result->fieldsUsed |= SMTP_FILE_OBJECT_HASHES;
	}

	if(useSizeInBytes){
		result->sizeInBytes = sizeInBytes;
		result->fieldsUsed |= SMTP_FILE_OBJECT_SIZE_IN_BYTES;
	}

	return result;

}

int
SMTPIndicatorDestroyFileObject(SMTPIndicatorsFileObject *indicator){
	if(indicator->fileExtension != NULL) SCFree(indicator->fileExtension);
	if(indicator->hashes){
		// NULL terminated array of pointers
		uint8_t **hashPtr = indicator->hashes;
		while(*hashPtr != NULL){
			SCFree(*hashPtr);
			hashPtr++;
		}
	}

	return 0;
}

SMTPIndicator *SMTPIndicatorCreateIndicator(const uint8_t *name, SMTPAddressIndicator *from, SMTPIndicatorsFileObject *relatedFileObjects){


	if(name != NULL){
		SMTPIndicator *result = SCMalloc(sizeof(SMTPIndicator));
		memset(result, 0, sizeof(SMTPIndicator));

		result->name = SCMalloc(strlen((const char*)name)+1);
		strcpy((char*)result->name, (const char*)name);

		result->relatedFileObjects = relatedFileObjects;

		result->from = from;

		return result;
	}

	return NULL;




}

int
SMTPIndicatorDestroyIndicator(SMTPIndicator *indicator){
	if(indicator->from != NULL){
		SMTPIndicatorDestroyAddressIndicator(indicator->from);
	}

	if(indicator->name != NULL)
		SCFree(indicator->name);

	SMTPIndicatorsFileObject *nextFileObject = indicator->relatedFileObjects;
	while(nextFileObject != NULL){
		SMTPIndicatorDestroyFileObject(nextFileObject);
	}

	return 0;

}

SMTPIndicator *SMTPIndicatorGetRootIndicator(){
	if(_smtpindicatorsCtx == NULL) return NULL;

	return _smtpindicatorsCtx->smtpIndicators;
}

/**
 * Takes ownership of the indicator and adds it to the front
 * of the list of indicators.
 */
int
SMTPIndicatorAddIndicator(SMTPIndicator *indicator){
	// Returns 0 on success, like all good posix libraries do
	if(SCMutexLock(&(_smtpindicatorsCtx->mutex))) goto error;

	// add the new indicator at the front of the linked list
	indicator->next = _smtpindicatorsCtx->smtpIndicators;
	_smtpindicatorsCtx->smtpIndicators = indicator;

	SCMutexUnlock(&(_smtpindicatorsCtx->mutex));

	return 0;

	error:

	return -1;
}

int
SMTPIndicatorsCreateContext(){
	_smtpindicatorsCtx = SCMalloc(sizeof(SMTPIndicatorsCtx));

	if(_smtpindicatorsCtx == NULL) return 0;

	memset(_smtpindicatorsCtx, 0, sizeof(SMTPIndicatorsCtx));

	SCMutexInit(&(_smtpindicatorsCtx->mutex), NULL);

	return 0;

}

int
SMTPIndicatorDestroyContext(){
	if(_smtpindicatorsCtx != NULL){
		SMTPIndicator *nextIndicator = _smtpindicatorsCtx->smtpIndicators;

		while(nextIndicator != NULL){
			SMTPIndicatorDestroyIndicator(nextIndicator);
			nextIndicator = nextIndicator->next;
		}

		SCFree(_smtpindicatorsCtx);
	}

	return 0;
}
