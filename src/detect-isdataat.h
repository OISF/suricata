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
 * \author Pablo Rincon <pablo.rincon.crespo@gmail.com>
 */

#ifndef __DETECT_ISDATAAT_H__
#define __DETECT_ISDATAAT_H__

#define ISDATAAT_RELATIVE   0x01
#define ISDATAAT_RAWBYTES   0x02
#define ISDATAAT_NEGATED    0x04
#define ISDATAAT_OFFSET_VAR 0x08

#define ISDATAAT_MIN 0
#define ISDATAAT_MAX 65535

typedef struct DetectIsdataatData_ {
    uint16_t dataat;     /* data offset to match */
    uint8_t flags; /* isdataat options*/
} DetectIsdataatData;

/* prototypes */
void DetectIsdataatRegister (void);

#endif /* __DETECT_ISDATAAT_H__ */

