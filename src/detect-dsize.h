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

#ifndef __DETECT_DSIZE_H__
#define __DETECT_DSIZE_H__

#define DETECTDSIZE_LT 0
#define DETECTDSIZE_EQ 1
#define DETECTDSIZE_GT 2
#define DETECTDSIZE_RA 3

typedef struct DetectDsizeData_ {
    uint16_t dsize;
    uint16_t dsize2;
    uint8_t mode;
} DetectDsizeData;

/* prototypes */
void DetectDsizeRegister (void);

int SigParseMaxRequiredDsize(const Signature *s);
int SigParseGetMaxDsize(const Signature *s);
void SigParseSetDsizePair(Signature *s);
void SigParseApplyDsizeToContent(Signature *s);

#endif /* __DETECT_DSIZE_H__ */

