/* Copyright (C) 2023-2024 Open Information Security Foundation
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

/** \file
 *
 *  \author Angelo Mirabella <angelo.mirabella@broadcom.com>
 *
 *  LIB packet and stream decoding support
 *
 */

#ifndef SURICATA_SOURCE_LIB_H
#define SURICATA_SOURCE_LIB_H

#include "tm-threads.h"

/** \brief register a "Decode" module for suricata as a library.
 *
 *  The "Decode" module is the first module invoked when processing a packet */
void TmModuleDecodeLibRegister(void);

/** \brief process a single packet.
 *
 * \param tv                    Pointer to the per-thread structure.
 * \param data                  Pointer to the raw packet.
 * \param datalink              Datalink type.
 * \param ts                    Timeval structure.
 * \param len                   Packet length.
 * \param tenant_id             Tenant id of the detection engine to use.
 * \param flags                 Packet flags (packet checksum, rule profiling...).
 * \param iface                 Sniffing interface this packet comes from (can be NULL).
 * \return                      Error code.
 */
int TmModuleLibHandlePacket(ThreadVars *tv, const uint8_t *data, int datalink, struct timeval ts,
        uint32_t len, uint32_t tenant_id, uint32_t flags, const char *iface);

#endif /* SURICATA_SOURCE_LIB_H */
