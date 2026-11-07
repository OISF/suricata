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
 * Implement JSON/eve logging app-layer HTTP/2.
 */

#include "suricata-common.h"
#include "conf.h"

#include "output.h"
#include "output-json.h"

#include "output-json-http2.h"
#include "rust.h"

OutputInitResult JsonHttp2LogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    bool sensitive = false;
    if (conf != NULL) {
        const char *value = SCConfNodeLookupChildValue(conf, "sensitive-headers");
        sensitive = value != NULL && SCConfValIsTrue(value);
    }
    OutputJsonCtx *ojc = parent_ctx->data;
    ojc->http2_sensitive_headers = sensitive;
    return OutputJsonLogInitSub(conf, parent_ctx);
}
