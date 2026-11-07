/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef SURICATA_OUTPUT_JSON_HTTP_H
#define SURICATA_OUTPUT_JSON_HTTP_H

/* per-body logger cap, configurable for the alert http-body output */
#define HTTP_LOG_DEFAULT_BODY_LIMIT (100 * 1024)
#define HTTP_LOG_MAX_BODY_LIMIT     (256 * 1024)

void JsonHttpLogRegister(void);

bool EveHttpAddMetadata(const Flow *f, uint64_t tx_id, SCJsonBuilder *js);
void EveHttpLogJSONBody(SCJsonBuilder *js, Flow *f, uint64_t tx_id, bool base64, bool printable,
        uint32_t body_log_limit);

#endif /* SURICATA_OUTPUT_JSON_HTTP_H */
