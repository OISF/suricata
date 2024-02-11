/* Copyright (C) 2024 Open Information Security Foundation
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

#ifndef __UTIL_EXCEPTION_POLICY_TYPES_H__
#define __UTIL_EXCEPTION_POLICY_TYPES_H__

enum ExceptionPolicy {
    EXCEPTION_POLICY_NOT_SET = 0,
    EXCEPTION_POLICY_AUTO,
    // TODO - optimization? - since `AUTO` and `NOT_SET` are not actual values for policies and
    // stats (only for config), could we leave those out of the `max` count?
    EXCEPTION_POLICY_PASS_PACKET,
    EXCEPTION_POLICY_PASS_FLOW,
    EXCEPTION_POLICY_BYPASS_FLOW,
    EXCEPTION_POLICY_DROP_PACKET,
    EXCEPTION_POLICY_DROP_FLOW,
    EXCEPTION_POLICY_REJECT,
};

#define EXCEPTION_POLICY_MAX EXCEPTION_POLICY_REJECT + 1

typedef struct ExceptionPolicyCounters_ {
    /* Follows enum order */
    uint16_t eps_id[EXCEPTION_POLICY_MAX];
} ExceptionPolicyCounters;

typedef struct ExceptionPolicyStatsSetts_ {
    bool valid_settings_ids[EXCEPTION_POLICY_MAX];
    bool valid_settings_ips[EXCEPTION_POLICY_MAX];
} ExceptionPolicyStatsSetts;

#endif