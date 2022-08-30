/* Copyright (C) 2018-2022 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Implement JSON/eve logging app-layer SNMP.
 */

#include "suricata-common.h"
#include "debug.h"
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

#include "app-layer-snmp.h"
#include "output-json-snmp.h"

#include "rust.h"

static int JsonSNMPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    SNMPTransaction *snmptx = tx;
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "snmp", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "snmp");
    if (!rs_snmp_log_json_response(jb, state, snmptx)) {
        goto error;
    }
    jb_close(jb);

    OutputJsonBuilderBuffer(jb, thread);

    jb_free(jb);
    return TM_ECODE_OK;

error:
    jb_free(jb);
    return TM_ECODE_FAILED;
}

static OutputInitResult OutputSNMPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_SNMP);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonSNMPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_SNMP, "eve-log", "JsonSNMPLog", "eve-log.snmp",
            OutputSNMPLogInitSub, ALPROTO_SNMP, JsonSNMPLogger, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);

    SCLogDebug("SNMP JSON logger registered.");
}
