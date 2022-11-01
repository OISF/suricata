/* Copyright (C) 2014-2021 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements SSH JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "detect.h"

#include "app-layer-parser.h"
#include "app-layer-ssh.h"

#include "output-json.h"
#include "output-json-ssh.h"

#define MODULE_NAME "LogSshLog"

static int JsonSshLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                         Flow *f, void *state, void *txptr, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;

    if (unlikely(state == NULL)) {
        return 0;
    }

    JsonBuilder *js = CreateEveHeaderWithTxId(p, LOG_DIR_FLOW, "ssh", NULL, tx_id, thread->ctx);
    if (unlikely(js == NULL))
        return 0;

    jb_open_object(js, "ssh");
    if (!rs_ssh_log_json(txptr, js)) {
        goto end;
    }
    jb_close(js);
    OutputJsonBuilderBuffer(js, thread);

end:
    jb_free(js);
    return 0;
}

static OutputInitResult OutputSshLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_SSH);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonSshLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterTxSubModuleWithCondition(LOGGER_JSON_TX, "eve-log", "JsonSshLog", "eve-log.ssh",
            OutputSshLogInitSub, ALPROTO_SSH, JsonSshLogger, SSHTxLogCondition, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);
}
