/* Copyright (C) 2026 Open Information Security Foundation
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
 * \brief tcp.session: keyword (Redmine #7704).
 */

#ifndef SURICATA_DETECT_TCP_SESSION_H
#define SURICATA_DETECT_TCP_SESSION_H

#include "suricata-common.h"

#define DETECT_TCP_SESSION_PHASE_SETUP       BIT_U8(0)
#define DETECT_TCP_SESSION_PHASE_ESTABLISHED BIT_U8(1)
#define DETECT_TCP_SESSION_PHASE_CLOSING     BIT_U8(2)

typedef struct DetectTcpSessionData_ {
    uint8_t phase_flags; /**< OR of DETECT_TCP_SESSION_PHASE_* */
} DetectTcpSessionData;

void DetectTcpSessionRegister(void);

#endif /* SURICATA_DETECT_TCP_SESSION_H */
