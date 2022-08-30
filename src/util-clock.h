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

#ifndef __UTIL_CLOCK_H__
#define __UTIL_CLOCK_H__

#include <time.h>

/* Feel free to add more macros */

#define CLOCK_INIT          clock_t clo1, clo2; clo1 = clo2 = 0;
#define CLOCK_START         clo1 = clock()

#define CLOCK_END           clo2 = clock()

#define CLOCK_PRINT_SEC                                                                            \
    printf("Seconds spent: %.4fs\n", ((double)(clo2 - clo1) / (double)CLOCKS_PER_SEC))

#define GET_CLOCK_END_SECS  ((clo1 - clo2)/(double)CLOCKS_PER_SEC)

#endif /*__UTIL_CLOCK_H__ */
