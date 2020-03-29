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
 * \author Gurvinder Singh <gurvindersighdahiya@gmail.com>
 */

#ifndef _DETECT_TTL_H
#define	_DETECT_TTL_H

#define DETECT_TTL_LT   0   /**< "less than" operator */
#define DETECT_TTL_EQ   1   /**< "equals" operator (default) */
#define DETECT_TTL_GT   2   /**< "greater than" operator */
#define DETECT_TTL_RA   3   /**< "range" operator */

typedef struct DetectTtlData_ {
    uint8_t ttl1;   /**< first ttl value in the signature*/
    uint8_t ttl2;   /**< second ttl value in the signature, in case of range
                         operator*/
    uint8_t mode;   /**< operator used in the signature */
}DetectTtlData;

void DetectTtlRegister(void);

#endif	/* _DETECT_TTL_H */

