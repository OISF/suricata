/* Copyright (C) 2007-2011 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __UTIL_PROFILE_H__
#define __UTIL_PROFILE_H__

#ifdef PROFILING

#include "util-cpu.h"

extern int profiling_rules_enabled;
extern int profiling_packets_enabled;
extern __thread int profiling_rules_entered;

void SCProfilingPrintPacketProfile(Packet *);
void SCProfilingAddPacket(Packet *);

#define RULE_PROFILING_START \
    uint64_t profile_rule_start_ = 0; \
    uint64_t profile_rule_end_ = 0; \
    if (profiling_rules_enabled) { \
        if (profiling_rules_entered > 0) { \
            SCLogError(SC_ERR_FATAL, "Re-entered profiling, exiting."); \
            exit(1); \
        } \
        profiling_rules_entered++; \
        profile_rule_start_ = UtilCpuGetTicks(); \
    }

#define RULE_PROFILING_END(r, m) \
    if (profiling_rules_enabled) { \
        profile_rule_end_ = UtilCpuGetTicks(); \
        SCProfilingUpdateRuleCounter(r->profiling_id, \
            profile_rule_end_ - profile_rule_start_, m); \
        profiling_rules_entered--; \
    }

#define PACKET_PROFILING_START(p)                                   \
    if (profiling_packets_enabled) {                                \
        (p)->profile.ticks_start = UtilCpuGetTicks();               \
    }

#define PACKET_PROFILING_END(p)                                     \
    if (profiling_packets_enabled) {                                \
        (p)->profile.ticks_end = UtilCpuGetTicks();                 \
        SCProfilingAddPacket((p));                                  \
    }

#define PACKET_PROFILING_TMM_START(p, id)                           \
    if (profiling_packets_enabled) {                                \
        if ((id) < TMM_SIZE) {                                      \
            (p)->profile.tmm[(id)].ticks_start = UtilCpuGetTicks(); \
        }                                                           \
    }

#define PACKET_PROFILING_TMM_END(p, id)                             \
    if (profiling_packets_enabled) {                                \
        if ((id) < TMM_SIZE) {                                      \
            (p)->profile.tmm[(id)].ticks_end = UtilCpuGetTicks();   \
        }                                                           \
    }

#define PACKET_PROFILING_RESET(p)                                   \
    if (profiling_packets_enabled) {                                \
        memset(&(p)->profile, 0x00, sizeof(PktProfiling));          \
    }

void SCProfilingInit(void);
void SCProfilingDestroy(void);
void SCProfilingInitRuleCounters(DetectEngineCtx *);
void SCProfilingCounterAddUI64(uint16_t, uint64_t);
void SCProfilingRegisterTests(void);
void SCProfilingDump(void);
void SCProfilingUpdateRuleCounter(uint16_t, uint64_t, int);

#else

#define RULE_PROFILING_START
#define RULE_PROFILING_END(r, m)

#define PACKET_PROFILING_START(p)
#define PACKET_PROFILING_END(p)

#define PACKET_PROFILING_TMM_START(p, id)
#define PACKET_PROFILING_TMM_END(p, id)

#define PACKET_PROFILING_RESET(p)

#endif /* PROFILING */

#endif /* ! __UTIL_PROFILE_H__ */
