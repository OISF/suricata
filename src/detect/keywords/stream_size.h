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
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef _DETECT_STREAM_SIZE_H
#define	_DETECT_STREAM_SIZE_H

#define DETECTSSIZE_LT 0
#define DETECTSSIZE_LEQ 1
#define DETECTSSIZE_EQ 2
#define DETECTSSIZE_NEQ 3
#define DETECTSSIZE_GT 4
#define DETECTSSIZE_GEQ 5

#define STREAM_SIZE_SERVER 0x01
#define STREAM_SIZE_CLIENT 0x02
#define STREAM_SIZE_BOTH   0x04
#define STREAM_SIZE_EITHER 0x08

typedef struct DetectStreamSizeData_ {
    uint8_t flags;
    uint8_t mode;
    uint32_t ssize;
}DetectStreamSizeData;

void DetectStreamSizeRegister(void);

#endif	/* _DETECT_STREAM_SIZE_H */

