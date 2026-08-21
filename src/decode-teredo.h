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
 * \author Eric Leblond <eric@regit.org>
 *
 * Decode Teredo Tunneling protocol.
 *
 * This implementation is based upon RFC 4380: http://www.ietf.org/rfc/rfc4380.txt
 */

#ifndef SURICATA_DECODE_TEREDO_H
#define SURICATA_DECODE_TEREDO_H

/**
 * \brief Attempt to decode a Teredo-tunneled IPv6 packet from a UDP payload.
 *
 * On success, an inner IPv6 tunnel packet is queued on the thread's decode
 * queue for further processing. On failure, the buffer is left untouched and
 * the caller should treat the datagram as regular UDP.
 *
 * Has no effect (returns failure) when Teredo decoding is disabled in the
 * configuration.
 *
 * \param tv  Current thread variables.
 * \param dtv Per-thread decoder state.
 * \param p   Outer packet carrying the UDP datagram; becomes the parent of
 *            the tunnel packet.
 * \param pkt Pointer to the UDP payload to inspect.
 * \param len Length in bytes of \p pkt.
 *
 * \retval TM_ECODE_OK     A Teredo packet was recognized and queued.
 * \retval TM_ECODE_FAILED Not a Teredo packet, decoding disabled, or the
 *                         tunnel packet could not be created.
 */
int DecodeTeredo(ThreadVars *tv, DecodeThreadVars *dtv, Packet *p,
                 const uint8_t *pkt, uint16_t len);

/**
 * \brief Load Teredo decoder settings from the Suricata configuration.
 *
 * Reads \c decoder.teredo.enabled and \c decoder.teredo.ports from the
 * running YAML configuration. Must be called once during engine startup,
 * before packet processing begins.
 */
void DecodeTeredoConfig(void);

/**
 * \brief Check whether Teredo decoding should be attempted for a UDP flow.
 *
 * Intended as a fast gate for the UDP decoder: only call DecodeTeredo()
 * when this returns true. The answer depends on the configuration loaded
 * by DecodeTeredoConfig() (global enable flag and configured port list).
 *
 * \param sp UDP source port.
 * \param dp UDP destination port.
 *
 * \retval true  Teredo decoding is enabled and at least one port is eligible.
 * \retval false Teredo decoding is disabled, or neither port is eligible.
 */
bool DecodeTeredoEnabledForPort(const uint16_t sp, const uint16_t dp);

#endif /* SURICATA_DECODE_TEREDO_H */
