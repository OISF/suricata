/* Copyright (C) 2021 Open Information Security Foundation
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
 * Implement JSON/eve logging app-layer BitTorrent DHT.
 */

#include "suricata-common.h"
#include "detect.h"

#include "output-json.h"

#include "app-layer-parser.h"

#include "output-json-bittorrent-dht.h"

typedef struct LogBitTorrentDHTFileCtx_ {
    uint32_t flags;
    OutputJsonCtx *eve_ctx;
} LogBitTorrentDHTFileCtx;

typedef struct LogBitTorrentDHTLogThread_ {
    LogBitTorrentDHTFileCtx *bittorrent_dht_log_ctx;
    OutputJsonThreadCtx *ctx;
} LogBitTorrentDHTLogThread;

static int JsonBitTorrentDHTLogger(ThreadVars *tv, void *thread_data, const Packet *p, Flow *f,
        void *state, void *tx, uint64_t tx_id)
{
    LogBitTorrentDHTLogThread *thread = thread_data;

    JsonBuilder *js = CreateEveHeader(
            p, LOG_DIR_PACKET, "bittorrent_dht", NULL, thread->bittorrent_dht_log_ctx->eve_ctx);
    if (unlikely(js == NULL)) {
        return TM_ECODE_FAILED;
    }

    jb_open_object(js, "bittorrent_dht");
    if (!rs_bittorrent_dht_logger_log(tx, js)) {
        goto error;
    }
    jb_close(js);

    OutputJsonBuilderBuffer(js, thread->ctx);
    jb_free(js);

    return TM_ECODE_OK;

error:
    jb_free(js);
    return TM_ECODE_FAILED;
}

static void OutputBitTorrentDHTLogDeInitCtxSub(OutputCtx *output_ctx)
{
    LogBitTorrentDHTFileCtx *bittorrent_dht_log_ctx = (LogBitTorrentDHTFileCtx *)output_ctx->data;
    SCFree(bittorrent_dht_log_ctx);
    SCFree(output_ctx);
}

static OutputInitResult OutputBitTorrentDHTLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ajt = parent_ctx->data;

    LogBitTorrentDHTFileCtx *bittorrent_dht_log_ctx = SCCalloc(1, sizeof(*bittorrent_dht_log_ctx));
    if (unlikely(bittorrent_dht_log_ctx == NULL)) {
        return result;
    }
    bittorrent_dht_log_ctx->eve_ctx = ajt;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(*output_ctx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(bittorrent_dht_log_ctx);
        return result;
    }
    output_ctx->data = bittorrent_dht_log_ctx;
    output_ctx->DeInit = OutputBitTorrentDHTLogDeInitCtxSub;

    AppLayerParserRegisterLogger(IPPROTO_UDP, ALPROTO_BITTORRENT_DHT);

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static TmEcode JsonBitTorrentDHTLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    LogBitTorrentDHTLogThread *thread = SCCalloc(1, sizeof(*thread));
    if (unlikely(thread == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for EveLogBitTorrentDHT.  \"initdata\" is NULL.");
        goto error_exit;
    }

    thread->bittorrent_dht_log_ctx = ((OutputCtx *)initdata)->data;
    thread->ctx = CreateEveThreadCtx(t, thread->bittorrent_dht_log_ctx->eve_ctx);
    if (!thread->ctx) {
        goto error_exit;
    }
    *data = (void *)thread;

    return TM_ECODE_OK;

error_exit:
    SCFree(thread);
    return TM_ECODE_FAILED;
}

static TmEcode JsonBitTorrentDHTLogThreadDeinit(ThreadVars *t, void *data)
{
    LogBitTorrentDHTLogThread *thread = (LogBitTorrentDHTLogThread *)data;
    if (thread == NULL) {
        return TM_ECODE_OK;
    }
    FreeEveThreadCtx(thread->ctx);
    SCFree(thread);
    return TM_ECODE_OK;
}

void JsonBitTorrentDHTLogRegister(void)
{
    if (ConfGetNode("app-layer.protocols.bittorrent-dht") == NULL) {
        return;
    }

    /* Register as an eve sub-module. */
    OutputRegisterTxSubModule(LOGGER_JSON_TX, "eve-log", "JsonBitTorrentDHTLog",
            "eve-log.bittorrent-dht", OutputBitTorrentDHTLogInitSub, ALPROTO_BITTORRENT_DHT,
            JsonBitTorrentDHTLogger, JsonBitTorrentDHTLogThreadInit,
            JsonBitTorrentDHTLogThreadDeinit, NULL);
}
