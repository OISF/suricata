/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata-common.h"
#include "output.h"
#include "app-layer-dcerpc.h"
#include "app-layer-smb.h"
#include "util-debug.h"
#include "util-logopenfile.h"
#include "tm-modules.h"
#include "conf.h"
#include "util-buffer.h"
#include "app-layer-parser.h"
#include "app-layer.h"

#include "log-dcerpc.h"
#include "util-print.h"

#define MODULE_NAME "LogDCERPC"
#define DEFAULT_LOG_FILENAME "dcerpc.log"
#define OUTPUT_BUFFER_SIZE 65535

struct LogDCERPCThreadVars {
    LogFileCtx *file_ctx;
    uint32_t tx_cnt;
    MemBuffer *buffer;
};

static void CreateTimeString(const struct timeval *ts, char *str, size_t size)
{
    time_t time = ts->tv_sec;
    struct tm local_tm;
    struct tm *t = (struct tm *)SCLocalTime(time, &local_tm);

    snprintf(str, size, "%02d/%02d/%02d-%02d:%02d:%02d.%06u",
        t->tm_mon + 1, t->tm_mday, t->tm_year + 1900, t->tm_hour,
            t->tm_min, t->tm_sec, (uint32_t) ts->tv_usec);
}

static void LogDCERPCDeInitCtx(OutputCtx *output_ctx)
{
    LogFileFreeCtx(output_ctx->data);
    SCFree(output_ctx);

    return;
}

static OutputCtx *LogDCERPCInitCtx(ConfNode *conf)
{
    LogFileCtx* file_ctx = LogFileNewCtx();
    char *s_default_log_dir = NULL;
    OutputCtx *output_ctx = NULL;

    if (file_ctx == NULL) {
        SCLogError(SC_ERR_DCERPC_LOG_GENERIC, "Couldn't create new file_ctx");
        return NULL;
    }

    if (ConfGet("default-log-dir", &s_default_log_dir) != 1)
        s_default_log_dir = DEFAULT_LOG_DIR;

    if (SCConfLogOpenGeneric(conf, file_ctx, DEFAULT_LOG_FILENAME) < 0)
        goto error;

    output_ctx = SCMalloc(sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        goto error;
    output_ctx->data = file_ctx;
    output_ctx->DeInit = LogDCERPCDeInitCtx;

    return output_ctx;

error:
    if (file_ctx != NULL)
        LogFileFreeCtx(file_ctx);
    return NULL;
}

TmEcode LogDCERPCThreadInit(ThreadVars *t, void *initdata, void **data)
{
    struct LogDCERPCThreadVars *tctx = SCMalloc(sizeof(*tctx));
    if (tctx == NULL)
        return TM_ECODE_FAILED;
    memset(tctx, 0, sizeof(*tctx));

    tctx->buffer = MemBufferCreateNew(OUTPUT_BUFFER_SIZE);
    if (tctx->buffer == NULL) {
        SCFree(tctx);
        return TM_ECODE_FAILED;
    }

    tctx->file_ctx = ((OutputCtx *)initdata)->data;

    *data = (void *)tctx;

    return TM_ECODE_OK;
}

TmEcode LogDCERPCThreadDeInit(ThreadVars *t, void *data)
{
    MemBufferFree(((struct LogDCERPCThreadVars *)data)->buffer);
    SCFree(data);

    return TM_ECODE_OK;
}

void LogDCERPCThreadExitPrintStats(ThreadVars *tv, void *data)
{
    struct LogDCERPCThreadVars *tctx = (struct LogDCERPCThreadVars *)data;

    if (tctx->tx_cnt == 1)
        SCLogInfo("DCERPC logger logged %"PRIu32 " request", tctx->tx_cnt);
    else
        SCLogInfo("DCERPC logger logged %"PRIu32 " requests", tctx->tx_cnt);

    return;
}

TmEcode LogDCERPCLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    struct DCERPCState *dcerpc_state = NULL;
    uint64_t tx_id = 0;
    uint64_t total_txs = 0;
    int tx_progress_done_value = 0;
    struct DCERPCTx *tx = NULL;
    struct LogDCERPCThreadVars *tctx = (struct LogDCERPCThreadVars *)data;
    char srcip[46], dstip[46];
    Port sp, dp;
    int ipproto;
    char timebuf[64];
    uint16_t alproto;

    if (p->flow == NULL || !PKT_IS_TCP(p))
        return TM_ECODE_OK;

    if (PKT_IS_IPV4(p)) {
        ipproto = AF_INET;
    } else if (PKT_IS_IPV6(p)) {
        ipproto = AF_INET6;
    } else {
        return TM_ECODE_OK;
    }

    FLOWLOCK_WRLOCK(p->flow);
    dcerpc_state = (struct DCERPCState *)AppLayerGetProtoStateFromPacket(p);
    alproto = AppLayerGetProtoFromPacket(p);
    if (alproto != ALPROTO_DCERPC) {
        if (alproto == ALPROTO_SMB && ((SMBState *)dcerpc_state)->dcerpc_present)
            dcerpc_state = (struct DCERPCState *)(((SMBState *)dcerpc_state)->dcerpc);
        else
            goto end;
    }

    total_txs = AppLayerGetTxCnt(ALPROTO_DCERPC, dcerpc_state);
    tx_id = AppLayerTransactionGetLogId(p->flow);
    tx_progress_done_value = AppLayerGetAlstateProgressCompletionStatus(ALPROTO_DCERPC, 0);

    if (PKT_IS_TOSERVER(p)) {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->sp;
        dp = p->dp;
    } else {
        switch (ipproto) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                goto end;
        }
        sp = p->dp;
        dp = p->sp;
    }

    CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

    for (; tx_id < total_txs; tx_id++)
    {
        tx = AppLayerGetTx(ALPROTO_DCERPC, dcerpc_state, tx_id);
        if (tx == NULL) {
            SCLogDebug("tx is NULL not logging !!");
            continue;
        }

        if (AppLayerGetAlstateProgress(ALPROTO_DCERPC, tx, 0) < tx_progress_done_value)
            break;

        SCMutexLock(&tctx->file_ctx->fp_mutex);
        uint8_t *uuid = tx->iface.uuid;
        fprintf(tctx->file_ctx->fp, "[%s],[%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x],"
                "[opnum %"PRIu16"],[Stub_Length %"PRIu16"],"
                "[%s:%"PRIu16" -> %s:%"PRIu16"]\n",
                timebuf,
                (*(uint32_t *)uuid & 0xFF000000) >> 24, (*(uint32_t *)uuid & 0x00FF0000) >> 16,
                (*(uint32_t *)uuid & 0x0000FF00) >> 8, *(uint32_t *)uuid & 0x000000FF,
                (*(uint16_t *)(uuid + 4) & 0xFF00) >> 8, *(uint16_t *)(uuid + 4) & 0x00FF,
                (*(uint16_t *)(uuid + 6) & 0xFF00) >> 8, *(uint16_t *)(uuid + 6) & 0x00FF,
                (*(uint16_t *)(uuid + 8) & 0xFF00) >> 8, *(uint16_t *)(uuid + 8) & 0x00FF,
                uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15],
                tx->opnum, tx->stub_len[0],
                srcip, sp, dstip, dp);
        SCMutexUnlock(&tctx->file_ctx->fp_mutex);
        AppLayerTransactionUpdateLogId(p->flow);
        tctx->tx_cnt++;
    }

 end:
    FLOWLOCK_UNLOCK(p->flow);
    return TM_ECODE_OK;
}

void TmModuleLogDCERPCRegister(void)
{
    tmm_modules[TMM_LOGDCERPC].name = MODULE_NAME;
    tmm_modules[TMM_LOGDCERPC].ThreadInit = LogDCERPCThreadInit;
    tmm_modules[TMM_LOGDCERPC].Func = LogDCERPCLog;
    tmm_modules[TMM_LOGDCERPC].ThreadExitPrintStats = LogDCERPCThreadExitPrintStats;
    tmm_modules[TMM_LOGDCERPC].ThreadDeinit = LogDCERPCThreadDeInit;
    tmm_modules[TMM_LOGDCERPC].RegisterTests = NULL;
    tmm_modules[TMM_LOGDCERPC].cap_flags = 0;

    OutputRegisterModule(MODULE_NAME, "dcerpc-log", LogDCERPCInitCtx);

    AppLayerRegisterLogger(ALPROTO_DCERPC);

    return;
}

