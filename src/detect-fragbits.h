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
 * \author Breno Silva <breno.silva@gmail.com>
 */

#ifndef __DETECT_FRAGBITS_H__
#define __DETECT_FRAGBITS_H__


/**
 * \struct DetectFragBitsData_
 * DetectFragBitsData_ is used to store fragbits: input value
 */

/**
 * \typedef DetectFragBitsData
 * A typedef for DetectFragBitsData_
 */

typedef struct DetectFragBitsData_ {
    uint8_t fragbits; /**< IP fragbits */
    uint8_t modifier; /**< !(1) +(2) *(3) modifiers */
} DetectFragBitsData;

/**
 * Registration function for fragbits: keyword
 */

void DetectFragBitsRegister (void);

#endif /*__DETECT_FRAGBITS_H__ */
