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
 * \author Jan Jezek <jjezek@kerio.com>
 */

#ifndef __WIN32_MISC_H__
#define __WIN32_MISC_H__

#define index strchr
#define rindex strrchr

#define bzero(s, n) memset(s, 0, n)

#ifndef O_NOFOLLOW
#define O_NOFOLLOW 0
#endif /* O_NOFOLLOW */

void setenv(const char *name, const char *value, int overwrite);
void unsetenv(const char *name);

const char* inet_ntop(int af, const void *src, char *dst, uint32_t cnt);
int inet_pton(int af, const char *src, void *dst);

#define geteuid() (0)

#endif
