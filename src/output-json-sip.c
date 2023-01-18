/* Copyright (C) 2018-2021 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 *
 * Implement JSON/eve logging app-layer SIP.
 */

#include "suricata-common.h"
#include "detect.h"
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

#include "app-layer-sip.h"
#include "output-json-sip.h"

#include "rust.h"

void JsonSIPAddMetadata(JsonBuilder *js, const Flow *f, uint64_t tx_id)
{
    SIPState *state = FlowGetAppState(f);
    if (state) {
        SIPTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_SIP, state, tx_id);
        if (tx) {
            rs_sip_log_json(tx, js);
        }
    }
}

static int JsonSIPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SIPTransaction *siptx = tx;
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *js = CreateEveHeader((Packet *)p, LOG_DIR_PACKET, "sip", NULL, thread->ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }

    if (!rs_sip_log_json(siptx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static OutputInitResult OutputSIPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SIP);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonSIPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonSIPLog", "eve-log.sip",
            OutputSIPLogInitSub, ALPROTO_SIP, JsonSIPLogger, JsonLogThreadInit, JsonLogThreadDeinit,
            NULL);

    SCLogDebug("SIP JSON logger registered.");
}
