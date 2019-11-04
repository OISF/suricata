/* Copyright (C) 2007-2012 Open Information Security Foundation
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

#ifndef __UTIL_PROFILE_LOCKS_H__
#define __UTIL_PROFILE_LOCKS_H__

#ifdef PROFILING

#define PROFILING_MAX_LOCKS 64

enum {
    LOCK_MUTEX,
    LOCK_SPIN,
    LOCK_RWW,   /**< rwlock, writer */
    LOCK_RWR,   /**< rwlock, reader */
};

void SCProfilingAddPacketLocks(void *);

int LockRecordInitHash(void);
void LockRecordFreeHash(void);

#endif /* PROFILING */
#endif /* __UTIL_PROFILE_LOCKS_H__ */

