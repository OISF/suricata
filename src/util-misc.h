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
 * \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#ifndef __UTIL_MISC_H__
#define __UTIL_MISC_H__

int ParseSizeStringU8(const char *, uint8_t *);
int ParseSizeStringU16(const char *, uint16_t *);
int ParseSizeStringU32(const char *, uint32_t *);
int ParseSizeStringU64(const char *, uint64_t *);
void UtilMiscRegisterTests(void);

#endif /* __UTIL_MISC_H__ */
