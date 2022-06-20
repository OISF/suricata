/* Copyright (C) 2011 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 *
 * Based on detect-mark.h by Breno Silva <breno.silva@gmail.com>
 *
 * Implements the nfq_set_mark keyword
 */

#ifndef __DETECT_MARK_H__
#define __DETECT_MARK_H__


/**
 * \struct DetectMarkData_
 * DetectMarkData_ is used to store nfq_set_mark: input value
 */

/**
 * \typedef DetectMarkData
 * A typedef for DetectMarkData_
 */

typedef struct DetectMarkData_ {
    uint32_t mark;  /**< Rule mark */
    uint32_t mask;  /**< Rule mask */
} DetectMarkData;

/**
 * Registration function for nfq_set_mark: keyword
 */

void DetectMarkRegister (void);

#endif /*__DETECT_MARK_H__ */
