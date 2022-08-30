/* Copyright (C) 2014-2022 Open Information Security Foundation
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
 * \author Ken Steele <suricata@tilera.com>
 *
 * Memcpy_tolower()
 *
 */

#ifndef __UTIL_MEMCPY_H__
#define __UTIL_MEMCPY_H__

/**
 * \internal
 * \brief Does a memcpy of the input string to lowercase.
 *
 * \param d   Pointer to the target area for memcpy.
 * \param s   Pointer to the src string for memcpy.
 * \param len len of the string sent in s.
 */
static inline void memcpy_tolower(uint8_t *d, const uint8_t *s, uint16_t len)
{
    uint16_t i;
    for (i = 0; i < len; i++)
        d[i] = u8_tolower(s[i]);

    return;
}

#endif /* __UTIL_MEMCPY_H__ */
