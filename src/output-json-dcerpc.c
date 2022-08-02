/* Copyright (C) 2017-2021 Open Information Security Foundation
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

#include "suricata-common.h"
#include "debug.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-unittest.h"
#include "util-buffer.h"
#include "util-debug.h"
#include "util-byte.h"

#include "output.h"
#include "output-json.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "output-json-dcerpc.h"

#include "rust.h"


static int JsonDCERPCLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_FLOW, "dcerpc", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "dcerpc");
    if (p->proto == IPPROTO_TCP) {
        if (!rs_dcerpc_log_json_record_tcp(state, tx, jb)) {
            goto error;
        }
    } else {
        if (!rs_dcerpc_log_json_record_udp(state, tx, jb)) {
            goto error;
        }
    }
    jb_close(jb);

    MemBufferReset(thread->buffer);
    OutputJsonBuilderBuffer(jb, thread);

    jb_free(jb);
    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static OutputInitResult DCERPCLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_DCERPC);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_DCERPC);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonDCERPCLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_DCERPC, "eve-log", "JsonDCERPCLog",
        "eve-log.dcerpc", DCERPCLogInitSub, ALPROTO_DCERPC,
        JsonDCERPCLogger, JsonLogThreadInit,
        JsonLogThreadDeinit, NULL);

    SCLogDebug("DCERPC JSON logger registered.");
}
