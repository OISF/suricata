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

#ifndef UTIL_SMTL_WATCHLIST_H_
#define UTIL_SMTL_WATCHLIST_H_

#include "suricata-common.h"
#include "reputation.h"

#define SMTP_FILE_OBJECT_FILE_EXTENSION 0x01
#define SMTP_FILE_OBJECT_SIZE_IN_BYTES 0x02
#define SMTP_FILE_OBJECT_HASHES 0x04

typedef struct SMTPIndicatorsFileObject_ {
	uint8_t fields_used;

	uint8_t *file_extension;
	size_t size_in_bytes;

	uint8_t** hashes;
	struct SMTPIndicatorsFileObject_ *next;
} SMTPIndicatorsFileObject;

enum SMTPIndicatorAddressValueCondition {
	contains = 0,
	equals
};

typedef struct SMTPAddressIndicator_ {
	/** Indicator Value*/
	uint8_t *value;

	/** an enumeration of conditions */
	enum SMTPIndicatorAddressValueCondition condition;
} SMTPAddressIndicator;

typedef struct SMTPIndicator_{
	uint8_t *name;
	SMTPAddressIndicator *from;

	SMTPIndicatorsFileObject *related_file_objects;
	uint8_t relatedObjectsCount;

	struct SMTPIndicator_ *next;
} SMTPIndicator;

typedef struct SMTPIndicatorsCtx_ {
    /** Linked list of SMTP indicators */
	SMTPIndicator *smtp_indicators;

    /** Mutex to support concurrent access */
	SCMutex mutex;
}SMTPIndicatorsCtx;

int SMTPIndicatorsCreateContext();
SMTPIndicator *SMTPIndicatorGetRootIndicator();
SMTPAddressIndicator *SMTPIndicatorCreateAddressIndicator(const uint8_t *value,
        enum SMTPIndicatorAddressValueCondition condition);
SMTPIndicatorsFileObject * SMTPIndicatorCreateFileObject(
        const uint8_t *file_extension, uint8_t **hashes, int hash_count,
        uint16_t size_in_bytes, int use_size_in_bytes);
SMTPIndicator *SMTPIndicatorCreateIndicator(const uint8_t *name,
        SMTPAddressIndicator *from,
        SMTPIndicatorsFileObject *related_file_objects);
int SMTPIndicatorAddIndicator(SMTPIndicator *indicator);


#endif /* UTIL_SMTL_WATCHLIST_H_ */

