/* Copyright (C) 2025 Open Information Security Foundation
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
 * \brief Public interface for the tcp.session: keyword.
 *
 * This is the parameter half of Redmine #7704: a SigMatch keyword whose
 * argument is a comma-separated subset of {setup, established, closing}
 * that maps to TCP states from `enum TcpState` in stream-tcp-private.h.
 *
 * The matching strategy reuses the same `(p->flowflags & FLOW_PKT_ESTABLISHED)`
 * test that `flow:established` / `flow:not_established` use, plus a direct
 * `TcpSession::state` membership check for the closing phase.
 *
 * See the tcp.session match function and phase-flag definitions below for
 * the full design.
 */

#ifndef SURICATA_DETECT_TCP_SESSION_H
#define SURICATA_DETECT_TCP_SESSION_H

#include "suricata-common.h"

/** Phase flags encoded in DetectTcpSessionData::phase_flags.
 *
 * The set is intentionally a bitfield so the per-packet match function can
 * compute the packet's phase mask once (from p->flowflags + ssn->state) and
 * AND it against the rule's phase_flags in a single instruction.
 */
#define DETECT_TCP_SESSION_PHASE_SETUP       BIT_U8(0)
#define DETECT_TCP_SESSION_PHASE_ESTABLISHED BIT_U8(1)
#define DETECT_TCP_SESSION_PHASE_CLOSING     BIT_U8(2)

/** Keyword data structure: a single byte holding the OR of phase flags. */
typedef struct DetectTcpSessionData_ {
    uint8_t phase_flags; /**< OR of DETECT_TCP_SESSION_PHASE_* */
} DetectTcpSessionData;

/* prototypes */
void DetectTcpSessionRegister(void);

#endif /* SURICATA_DETECT_TCP_SESSION_H */
