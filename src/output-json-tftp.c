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
 * \author Clément Galland <clement.galland@epita.fr>
 *
 * Implement JSON/eve logging app-layer TFTP.
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

#include "app-layer-tftp.h"
#include "output-json-tftp.h"

#include "rust.h"

static int JsonTFTPLogger(ThreadVars *tv, void *thread_data,
    const Packet *p, Flow *f, void *state, void *tx, uint64_t tx_id)
{
    OutputJsonThreadCtx *thread = thread_data;

    JsonBuilder *jb = CreateEveHeader(p, LOG_DIR_PACKET, "tftp", NULL, thread->ctx);
    if (unlikely(jb == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(jb, "tftp");
    if (unlikely(!rs_tftp_log_json_request(tx, jb))) {
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

static OutputInitResult OutputTFTPLogInitSub(ConfNode *conf,
    OutputCtx *parent_ctx)
{
    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_TFTP);
    return OutputJsonLogInitSub(conf, parent_ctx);
}

void JsonTFTPLogRegister(void)
{
    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonTFTPLog", "eve-log.tftp",
            OutputTFTPLogInitSub, ALPROTO_TFTP, JsonTFTPLogger, JsonLogThreadInit,
            JsonLogThreadDeinit, NULL);

    SCLogDebug("TFTP JSON logger registered.");
}
