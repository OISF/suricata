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
 * \author Frank Honza <frank.honza@dcso.de>
 *
 * Implement JSON/eve logging app-layer RFB.
 */

#include "suricata-common.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "output-json-rfb.h"

bool JsonRFBAddMetadata(const Flow *f, uint64_t tx_id, JsonBuilder *js)
{
    RFBState *state = FlowGetAppState(f);
    if (state) {
        RFBTransaction *tx = AppLayerParserGetTx(f->proto, ALPROTO_RFB, state, tx_id);
        if (tx) {
            return rs_rfb_logger_log(state, tx, js);
        }
    }

    return false;
}

static int JsonRFBLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_FLOW, "rfb", NULL, thread->ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (!rs_rfb_logger_log(NULL, tx, js)) {
        goto error;
    }

    OutputJsonBuilderBuffer(js, thread);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static OutputInitResult OutputRFBLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RFB);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonRFBLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRFBLog", "eve-log.rfb",
            OutputRFBLogInitSub, ALPROTO_RFB, JsonRFBLogger, JsonLogThreadInit, JsonLogThreadDeinit,
            NULL);
}
