/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef SURICATA_DETECT_REFERENCE_H
#define SURICATA_DETECT_REFERENCE_H

/**
 * \brief Signature reference list.
 */
typedef struct DetectReference_ {
    /* pointer to key */
    char *key;
    /* reference data */
    char *reference;

    /*
     * These have been length checked against REFERENCE_SYSTEM_NAME_MAX,
     * and REFERENCE_CONTENT_NAME_MAX
     */
    uint16_t key_len;
    uint16_t reference_len;
    /* next reference in the signature */
    struct DetectReference_ *next;
} DetectReference;

/**
 * Registration function for Reference keyword
 */
void DetectReferenceRegister(void);

/**
 * Free function for a Reference object
 */
void DetectReferenceFree(DetectReference *);

#endif /*SURICATA_DETECT_REFERENCE_H */
