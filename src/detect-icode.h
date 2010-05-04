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
 * \file detect-icode.c
 *
 * \author Gerardo Iglesias <iglesiasg@gmail.com>
 */

#ifndef __DETECT_ICODE_H__
#define __DETECT_ICODE_H__

#define DETECT_ICODE_EQ   0   /**< "equal" operator */
#define DETECT_ICODE_LT   1   /**< "less than" operator */
#define DETECT_ICODE_GT   2   /**< "greater than" operator */
#define DETECT_ICODE_RN   3   /**< "range" operator */

typedef struct DetectICodeData_ {
    uint8_t code1;
    uint8_t code2;

    uint8_t mode;
}DetectICodeData;

/* prototypes */
void DetectICodeRegister(void);

#endif /* __DETECT_ICODE_H__ */
