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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 *
 * Implement JSON/eve logging app-layer KRB5.
 */

#include "suricata-common.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "output-json-krb5.h"

static int JsonKRB5Logger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    KRB5Transaction *krb5tx = tx;
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "krb5", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "krb5");
    if (!rs_krb5_log_json_response(jb, state, krb5tx)) {
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

static OutputInitResult OutputKRB5LogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_KRB5);
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_KRB5);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonKRB5LogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_KRB5, "eve-log", "JsonKRB5Log", "eve-log.krb5",
            OutputKRB5LogInitSub, ALPROTO_KRB5, JsonKRB5Logger, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);

    SCLogDebug("KRB5 JSON logger registered.");
}
