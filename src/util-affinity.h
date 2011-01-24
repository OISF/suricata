/* Copyright (C) 2010 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __UTIL_AFFINITY_H__
#define __UTIL_AFFINITY_H__
#include "suricata-common.h"

enum {
    RECEIVE_CPU_SET,
    DECODE_CPU_SET,
    STREAM_CPU_SET,
    DETECT_CPU_SET,
    VERDICT_CPU_SET,
    REJECT_CPU_SET,
    OUTPUT_CPU_SET,
    MAX_CPU_SET
};

enum {
    BALANCED_AFFINITY,
    EXCLUSIVE_AFFINITY,
    MAX_AFFINITY
};

typedef struct ThreadsAffinityType_ {
    char *name;
    cpu_set_t cpu_set;
    uint8_t mode_flag;
    uint8_t prio;
    uint16_t lcpu; /* use by exclusive mode */
} ThreadsAffinityType;

/** store thread affinity mode for all type of threads */
#ifndef _THREAD_AFFINITY
ThreadsAffinityType thread_affinity[MAX_CPU_SET];
#endif

void AffinitySetupLoadFromConfig();
ThreadsAffinityType * GetAffinityTypeFromName(const char *name);

int AffinityGetNextCPU(ThreadsAffinityType *taf);

#endif /* __UTIL_AFFINITY_H__ */
