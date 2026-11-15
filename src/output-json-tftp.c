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
 * Implement JSON/eve logging app-layer TFTP.
 */

#include "suricata-common.h"
#include "conf.h"

#include "output.h"
#include "output-json.h"

#include "output-json-tftp.h"
#include "rust.h"

OutputInitResult JsonTftpLogInitSub(SCConfNode *conf, OutputCtx *parent_ctx)
{
    bool filenames = false;
    if (conf != NULL) {
        const char *value = SCConfNodeLookupChildValue(conf, "filenames");
        filenames = value != NULL && SCConfValIsTrue(value);
    }
    OutputJsonCtx *ojc = parent_ctx->data;
    ojc->tftp_filenames = filenames;
    return OutputJsonLogInitSub(conf, parent_ctx);
}
