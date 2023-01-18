/* Copyright (C) 2019-2021 Open Information Security Foundation
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
 * \author Zach Kelly <zach.kelly@lmco.com>
 *
 * Application layer logger for RDP
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
#include "app-layer-rdp.h"
#include "output-json-rdp.h"
#include "rust.h"

static int JsonRdpLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(p, LOG_DIR_PACKET, "rdp", NULL, thread->ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_OK;
    }
    if (!rs_rdp_to_json(tx, js)) {
        jb_free(js);
        return TM_ECODE_FAILED;
    }
    OutputJsonBuilderBuffer(js, thread);

    jb_free(js);
    return TM_ECODE_OK;
}

static OutputInitResult OutputRdpLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_RDP);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonRdpLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonRdpLog", "eve-log.rdp",
            OutputRdpLogInitSub, ALPROTO_RDP, JsonRdpLogger, JsonLogThreadInit, JsonLogThreadDeinit,
            NULL);

    SCLogDebug("rdp json logger registered.");
}
