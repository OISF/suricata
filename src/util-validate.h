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
 *
 * Functions & Macro's for validation of data structures. This is used for
 * code correctness.
 *
 * These will abort() the program if they fail, so they should _only_ be
 * used for testing.
 */


#ifndef __UTIL_VALIDATE_H__
#define __UTIL_VALIDATE_H__

#ifdef DEBUG_VALIDATION

/** \brief test if a flow is locked.
 *
 * If trylock returns 0 it got a lock. Which means
 * the flow was previously unlocked.
 */
#define DEBUG_ASSERT_FLOW_LOCKED(f) do {            \
    if ((f) != NULL) {                              \
        int r = SCMutexTrylock(&(f)->m);            \
        if (r == 0) {                               \
            BUG_ON(1);                              \
        }                                           \
    }                                               \
} while(0)

/** \brief validate the integrity of the flow
 *
 *  BUG_ON's on problems
 */
#define DEBUG_VALIDATE_FLOW(f) do {                 \
    if ((f) != NULL) {                              \
        BUG_ON((f)->flags & FLOW_IPV4 &&            \
               (f)->flags & FLOW_IPV6);             \
        if ((f)->proto == IPPROTO_TCP) {            \
            BUG_ON((f)->alstate != NULL &&          \
                   (f)->alparser == NULL);          \
        }                                           \
    }                                               \
} while(0)

/** \brief validate the integrity of the packet
 *
 *  BUG_ON's on problems
 */
#define DEBUG_VALIDATE_PACKET(p) do {               \
    if ((p) != NULL) {                              \
        if ((p)->flow != NULL) {                    \
            DEBUG_VALIDATE_FLOW((p)->flow);         \
        }                                           \
        if (!((p)->flags & (PKT_IS_FRAGMENT|PKT_IS_INVALID))) {          \
            if ((p)->proto == IPPROTO_TCP) {            \
                BUG_ON((p)->tcph == NULL);              \
            } else if ((p)->proto == IPPROTO_UDP) {     \
                BUG_ON((p)->udph == NULL);              \
            } else if ((p)->proto == IPPROTO_ICMP) {    \
                BUG_ON((p)->icmpv4h == NULL);           \
            } else if ((p)->proto == IPPROTO_SCTP) {    \
                BUG_ON((p)->sctph == NULL);             \
            } else if ((p)->proto == IPPROTO_ICMPV6) {  \
                BUG_ON((p)->icmpv6h == NULL);           \
            }                                           \
        }                                           \
        if ((p)->payload_len > 0) {                 \
            BUG_ON((p)->payload == NULL);           \
        }                                           \
        BUG_ON((p)->ip4h != NULL && (p)->ip6h != NULL);     \
        BUG_ON((p)->flowflags != 0 && (p)->flow == NULL);   \
        BUG_ON((p)->flowflags & FLOW_PKT_TOSERVER &&\
               (p)->flowflags & FLOW_PKT_TOCLIENT); \
    }                                               \
} while(0)

#define DEBUG_VALIDATE_BUG_ON(exp) BUG_ON((exp))

#elif defined(__clang_analyzer__)

#define DEBUG_ASSERT_FLOW_LOCKED(f)
#define DEBUG_VALIDATE_FLOW(f)
#define DEBUG_VALIDATE_PACKET(p)
#define DEBUG_VALIDATE_BUG_ON(exp) BUG_ON((exp))

#else /* DEBUG_VALIDATE */

#define DEBUG_ASSERT_FLOW_LOCKED(f)
#define DEBUG_VALIDATE_FLOW(f)
#define DEBUG_VALIDATE_PACKET(p)
#define DEBUG_VALIDATE_BUG_ON(exp)

#endif /* DEBUG_VALIDATE */

#endif /* __UTIL_VALIDATE_H__ */

