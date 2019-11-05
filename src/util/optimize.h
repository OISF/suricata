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

#ifndef __UTIL_OPTIMIZE_H__
#define __UTIL_OPTIMIZE_H__

/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 */

#if CPPCHECK==1
#define likely
#define unlikely
#else
#ifndef likely
#define likely(expr) __builtin_expect(!!(expr), 1)
#endif
#ifndef unlikely
#define unlikely(expr) __builtin_expect(!!(expr), 0)
#endif
#endif

/** from http://en.wikipedia.org/wiki/Memory_ordering
 *
 *  C Compiler memory barrier
 */
#define cc_barrier() __asm__ __volatile__("": : :"memory")

/** from http://gcc.gnu.org/onlinedocs/gcc-4.1.2/gcc/Atomic-Builtins.html
 *
 * Hardware memory barrier
 */
#define hw_barrier() __sync_synchronize()

#endif /* __UTIL_OPTIMIZE_H__ */

