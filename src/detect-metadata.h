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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_METADATA_H__
#define __DETECT_METADATA_H__

/**
 * \brief Signature metadata list.
 */
typedef struct DetectMetadata_ {
    /* pointer to key stored in de_ctx hash table_metadata */
    const char *key;
    /* value data stored in de_ctx hash table_metadata */
    const char *value;
    /* next reference in the signature */
    struct DetectMetadata_ *next;
} DetectMetadata;

typedef struct DetectMetadataHead {
    char *json_str;
    DetectMetadata *list;
} DetectMetadataHead;

/* prototypes */
void DetectMetadataRegister (void);

void DetectMetadataFree(DetectMetadata *mdata);

#endif /* __DETECT_METADATA_H__ */

