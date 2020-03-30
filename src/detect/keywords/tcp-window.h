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

#ifndef __DETECT_WINDOW_H__
#define __DETECT_WINDOW_H__

#define MIN_WINDOW_VALUE 0
#define MAX_WINDOW_VALUE 65535

typedef struct DetectWindowData_ {
    uint8_t negated;	/** negated? 1=True : 0=False */
    uint16_t size;     /** window size to match */
} DetectWindowData;

/* prototypes */
void DetectWindowRegister (void);

#endif /* __DETECT_WINDOW_H__ */
