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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FLAGS_H__
#define __DETECT_FLAGS_H__


/**
 * \struct DetectFlagsData_
 * DetectFlagsData_ is used to store flags: input value
 */

/**
 * \typedef DetectFlagsData
 * A typedef for DetectFlagsData_
 */

typedef struct DetectFlagsData_ {
    uint8_t flags;  /**< TCP flags */
    uint8_t modifier; /**< !(1) +(2) *(3) modifiers */
    uint8_t ignored_flags;  /**< Ignored TCP flags defined by modifer , */
} DetectFlagsData;

/**
 * Registration function for flags: keyword
 */

void DetectFlagsRegister (void);

int DetectFlagsSignatureNeedsSynPackets(const Signature *s);
int DetectFlagsSignatureNeedsSynOnlyPackets(const Signature *s);

#endif /*__DETECT_FLAGS_H__ */
