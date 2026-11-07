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
 * Teredo decoder (RFC 4380): IPv6 tunneled inside UDP.
 *
 * Teredo has no magic number, so detection is a best guess: the UDP
 * payload must look like a sane IPv6 packet. Port filtering is done
 * by the caller with DecodeTeredoEnabledForPort().
 *
 * Config (suricata.yaml):
 *   decoder.teredo.enabled  default: yes
 *   decoder.teredo.ports    default: any; at most 4 single ports
 */

#ifndef SURICATA_DECODE_TEREDO_H
#define SURICATA_DECODE_TEREDO_H

/** \brief Try to decode a UDP payload as Teredo.
 *
 *  Skips an optional origin indication, checks that an IPv6 packet
 *  fills the rest of the payload, and queues it as a tunnel packet.
 *
 *  \param pkt UDP payload
 *  \param len payload length
 *  \retval TM_ECODE_OK      Teredo; tunnel packet queued
 *  \retval TM_ECODE_FAILED  not Teredo, decoder disabled, or no
 *                           tunnel packet could be created */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint16_t len);

/** \brief Read the `decoder.teredo` settings. Call once at startup. */
void DecodeTeredoConfig(void);

/** \brief Should this UDP flow be tried as Teredo?
 *  \return true if the decoder is enabled and either no ports are
 *          configured ("any") or \p sp or \p dp is a configured port */
bool DecodeTeredoEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif
