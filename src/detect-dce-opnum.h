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

#ifndef __DETECT_DCE_OPNUM_H__
#define __DETECT_DCE_OPNUM_H__

#define DCE_OPNUM_RANGE_MAX             65535
#define DCE_OPNUM_RANGE_UNINITIALIZED   100000

typedef struct DetectDceOpnumRange_ {
    uint32_t range1;
    uint32_t range2;
    struct DetectDceOpnumRange_ *next;
} DetectDceOpnumRange;

typedef struct DetectDceOpnumData_ {
    DetectDceOpnumRange *range;
} DetectDceOpnumData;

void DetectDceOpnumRegister(void);

#endif /* __DETECT_DCE_OPNUM_H__ */
