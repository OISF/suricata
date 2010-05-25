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
 * \author Endace Technology Limited.
 */

#ifndef __UTIL_PROFILE_H__
#define __UTIL_PROFILE_H__

#ifdef PROFILING

#include "util-cpu.h"

extern int profiling_rules_enabled;

#define PROFILING_START \
    uint64_t profile_start_ = 0; \
    uint64_t profile_end_ = 0; \
    if (profiling_rules_enabled) { \
        profile_start_ = UtilCpuGetTicks(); \
    }

#define RULE_PROFILING_END(r, m) \
    if (profiling_rules_enabled) { \
        profile_end_ = UtilCpuGetTicks(); \
        SCProfilingUpdateRuleCounter(r->profiling_id, \
            profile_end_ - profile_start_, m); \
    }

void SCProfilingInit(void);
void SCProfilingDestroy(void);
void SCProfilingInitRuleCounters(DetectEngineCtx *);
void SCProfilingCounterAddUI64(uint16_t, uint64_t);
void SCProfilingRegisterTests(void);
void SCProfilingDump(FILE *);
void SCProfilingUpdateRuleCounter(uint16_t, uint64_t, int);

#else

#define PROFILING_START
#define RULE_PROFILING_END(r, m)

#endif /* PROFILING */

#endif /* ! __UTIL_PROFILE_H__ */
