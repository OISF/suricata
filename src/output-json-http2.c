/* Copyright (C) 2020-2021 Open Information Security Foundation
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
 * \author Philippe Antoine <p.antoine@catenacyber.fr>
 *
 * Implements HTTP2 JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "app-layer-parser.h"
#include "output-json.h"
#include "output-json-http2.h"
#include "rust.h"

bool EveHTTP2AddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *jb)
{
    void *state = FlowGetAppState(f);
    if (state) {
        void *tx = AppLayerParserGetTx(f->proto, ALPROTO_HTTP2, state, tx_id);
        if (tx) {
            return rs_http2_log_json(tx, jb);
        }
    }
    return false;
}
