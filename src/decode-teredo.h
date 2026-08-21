/* Copyright (C) 2012-2020 Open Information Security Foundation
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
 * Teredo tunneling decoder (RFC 4380).
 */

#ifndef SURICATA_DECODE_TEREDO_H
#define SURICATA_DECODE_TEREDO_H

/** \brief Try to decode a Teredo-tunneled IPv6 packet from a UDP payload.
 *
 *  On success the inner IPv6 packet is queued on the thread's decode
 *  queue with \p p as its parent. On failure \p pkt is untouched and
 *  the caller should treat the datagram as regular UDP. Returns
 *  failure when Teredo decoding is disabled.
 *
 *  \retval TM_ECODE_OK     Teredo packet recognised and queued.
 *  \retval TM_ECODE_FAILED Not Teredo, disabled, or tunnel packet
 *                          could not be created. 
 */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint16_t len);

/** \brief Load Teredo settings (decoder.teredo.enabled,
 *         decoder.teredo.ports) from the YAML config.
 */
void DecodeTeredoConfig(void);

/** \brief Determines if Teredo decoding should be attempted
 *         for a specific UDP port pair.
 * Call DecodeTeredo() only when this returns true.
 * Depends on config loaded by DecodeTeredoConfig().
 *
 *  \retval true  enabled and at least one port is eligible
 *  \retval false disabled, or neither port is eligible 
 */
bool DecodeTeredoEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif /* SURICATA_DECODE_TEREDO_H */
