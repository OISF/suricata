/* Copyright (C) 2024-2025 Open Information Security Foundation
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
 */

#ifndef UTIL_EXCEPTION_POLICY_TYPES_H
#define UTIL_EXCEPTION_POLICY_TYPES_H

enum ExceptionPolicy {
    EXCEPTION_POLICY_NOT_SET = 0,
    EXCEPTION_POLICY_AUTO,
    EXCEPTION_POLICY_PASS_PACKET,
    EXCEPTION_POLICY_PASS_FLOW,
    EXCEPTION_POLICY_BYPASS_FLOW,
    EXCEPTION_POLICY_DROP_PACKET,
    EXCEPTION_POLICY_DROP_FLOW,
    EXCEPTION_POLICY_REJECT,
};

#define EXCEPTION_POLICY_MAX EXCEPTION_POLICY_REJECT + 1

/* Max length = possible exception policy scenarios + counter names
 * + exception policy type. E.g.:
 * "tcp.reassembly_exception_policy.drop_packet" + 1 */
#define EXCEPTION_POLICY_COUNTER_MAX_LEN 45

/** Flags for possible scenario/ config settings for exception policies */
#define EXCEPTION_TARGET_FLAG_DEFRAG_MEMCAP     BIT_U8(0)
#define EXCEPTION_TARGET_FLAG_SESSION_MEMCAP    BIT_U8(1)
#define EXCEPTION_TARGET_FLAG_REASSEMBLY_MEMCAP BIT_U8(2)
#define EXCEPTION_TARGET_FLAG_FLOW_MEMCAP       BIT_U8(3)
#define EXCEPTION_TARGET_FLAG_MIDSTREAM         BIT_U8(4)
#define EXCEPTION_TARGET_FLAG_APPLAYER_ERROR    BIT_U8(5)

typedef struct ExceptionPolicyCounters_ {
    /* Follows enum order */
    uint16_t eps_id[EXCEPTION_POLICY_MAX];
} ExceptionPolicyCounters;

typedef struct ExceptionPolicyStatsSetts_ {
    char eps_name[EXCEPTION_POLICY_MAX][EXCEPTION_POLICY_COUNTER_MAX_LEN];
    bool valid_settings_ids[EXCEPTION_POLICY_MAX];
    bool valid_settings_ips[EXCEPTION_POLICY_MAX];
} ExceptionPolicyStatsSetts;

#endif
