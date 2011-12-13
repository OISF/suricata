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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __DETECT_CSUM_H__
#define __DETECT_CSUM_H__

#define DETECT_CSUM_VALID "valid"
#define DETECT_CSUM_INVALID "invalid"

typedef struct DetectCsumData_ {
    /* Indicates if the csum-<protocol> keyword in a rule holds the
       keyvalue "valid" or "invalid" */
    int16_t valid;
} DetectCsumData;

void DetectCsumRegister(void);

#endif /* __DETECT_CSUM_H__ */

