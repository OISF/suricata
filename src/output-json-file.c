/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 *
 * Log files we track.
 *
 */

#include "suricata-common.h"

#include "util-validate.h"

#include "output-json.h"
#include "output-json-file.h"
#include "output-json-http.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"
#include "output-json-http2.h"

typedef struct OutputFileCtx_ {
    uint32_t file_cnt;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
    OutputJsonCtx *eve_ctx;
} OutputFileCtx;

typedef struct JsonFileLogThread_ {
    OutputFileCtx *filelog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonFileLogThread;

JsonBuilder *JsonBuildFileInfoRecord(const Packet *p, const File *ff, void *tx,
        const uint64_t tx_id, const bool stored, uint8_t dir, HttpXFFCfg *xff_cfg,
        OutputJsonCtx *eve_ctx)
{
    enum OutputJsonLogDirection fdir = LOG_DIR_FLOW;

    switch(dir) {
        case STREAM_TOCLIENT:
            fdir = LOG_DIR_FLOW_TOCLIENT;
            break;
        case STREAM_TOSERVER:
            fdir = LOG_DIR_FLOW_TOSERVER;
            break;
        default:
            DEBUG_VALIDATE_BUG_ON(1);
            break;
    }

    JsonAddrInfo addr = json_addr_info_zero;
    JsonAddrInfoInit(p, fdir, &addr);

    /* Overwrite address info with XFF if needed. */
    int have_xff_ip = 0;
    char xff_buffer[XFF_MAXLEN];
    if ((xff_cfg != NULL) && !(xff_cfg->flags & XFF_DISABLED)) {
        if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP1) {
            have_xff_ip = HttpXFFGetIPFromTx(p->flow, tx_id, xff_cfg, xff_buffer, XFF_MAXLEN);
        }
        if (have_xff_ip && xff_cfg->flags & XFF_OVERWRITE) {
            if (p->flowflags & FLOW_PKT_TOCLIENT) {
                strlcpy(addr.dst_ip, xff_buffer, JSON_ADDR_LEN);
            } else {
                strlcpy(addr.src_ip, xff_buffer, JSON_ADDR_LEN);
            }
            have_xff_ip = 0;
        }
    }

    JsonBuilder *js = CreateEveHeader(p, fdir, "fileinfo", &addr, eve_ctx);
    if (unlikely(js == NULL))
        return NULL;

    JsonBuilderMark mark = { 0, 0, 0 };
    switch (p->flow->alproto) {
        case ALPROTO_HTTP1:
            jb_open_object(js, "http");
            EveHttpAddMetadata(p->flow, tx_id, js);
            jb_close(js);
            break;
        case ALPROTO_SMTP:
            jb_get_mark(js, &mark);
            jb_open_object(js, "smtp");
            if (EveSMTPAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            jb_get_mark(js, &mark);
            jb_open_object(js, "email");
            if (EveEmailAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_NFS:
            /* rpc */
            jb_get_mark(js, &mark);
            jb_open_object(js, "rpc");
            if (EveNFSAddMetadataRPC(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            /* nfs */
            jb_get_mark(js, &mark);
            jb_open_object(js, "nfs");
            if (EveNFSAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_SMB:
            jb_get_mark(js, &mark);
            jb_open_object(js, "smb");
            if (EveSMBAddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_HTTP2:
            jb_get_mark(js, &mark);
            jb_open_object(js, "http2");
            if (EveHTTP2AddMetadata(p->flow, tx_id, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
    }

    jb_set_string(js, "app_proto", AppProtoToString(p->flow->alproto));

    jb_open_object(js, "fileinfo");
    EveFileInfo(js, ff, tx_id, stored);
    jb_close(js);

    /* xff header */
    if (have_xff_ip && xff_cfg->flags & XFF_EXTRADATA) {
        jb_set_string(js, "xff", xff_buffer);
    }

    return js;
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void FileWriteJsonRecord(JsonFileLogThread *aft, const Packet *p, const File *ff, void *tx,
        const uint64_t tx_id, uint8_t dir, OutputJsonCtx *eve_ctx)
{
    HttpXFFCfg *xff_cfg = aft->filelog_ctx->xff_cfg != NULL ?
        aft->filelog_ctx->xff_cfg : aft->filelog_ctx->parent_xff_cfg;;
    JsonBuilder *js = JsonBuildFileInfoRecord(
            p, ff, tx, tx_id, ff->flags & FILE_STORED ? true : false, dir, xff_cfg, eve_ctx);
    if (unlikely(js == NULL)) {
        return;
    }

    OutputJsonBuilderBuffer(js, aft->ctx);
    jb_free(js);
}

static int JsonFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff,
        void *tx, const uint64_t tx_id, uint8_t dir)
{
    SCEnter();
    JsonFileLogThread *aft = (JsonFileLogThread *)thread_data;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    FileWriteJsonRecord(aft, p, ff, tx, tx_id, dir, aft->filelog_ctx->eve_ctx);
    return 0;
}


static TmEcode JsonFileLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFileLogThread *aft = SCCalloc(1, sizeof(JsonFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogFile.  \"initdata\" argument NULL");
        goto error_exit;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->filelog_ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = CreateEveThreadCtx(t, aft->filelog_ctx->eve_ctx);
    if (!aft->ctx) {
        goto error_exit;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;

error_exit:
    SCFree(aft);
    return TM_ECODE_FAILED;
}

static TmEcode JsonFileLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFileLogThread *aft = (JsonFileLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    FreeEveThreadCtx(aft->ctx);

    /* clear memory */
    memset(aft, 0, sizeof(JsonFileLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputFileLogDeinitSub(OutputCtx *output_ctx)
{
    OutputFileCtx *ff_ctx = output_ctx->data;
    if (ff_ctx->xff_cfg != NULL) {
        SCFree(ff_ctx->xff_cfg);
    }
    SCFree(ff_ctx);
    SCFree(output_ctx);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
static OutputInitResult OutputFileLogInitSub(ConfNode *conf, OutputCtx *parent_ctx)
{
    OutputInitResult result = { NULL, false };
    OutputJsonCtx *ojc = parent_ctx->data;

    OutputFileCtx *output_file_ctx = SCCalloc(1, sizeof(OutputFileCtx));
    if (unlikely(output_file_ctx == NULL))
        return result;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(output_file_ctx);
        return result;
    }

    if (conf) {
        const char *force_filestore = ConfNodeLookupChildValue(conf, "force-filestore");
        if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
            FileForceFilestoreEnable();
            SCLogConfig("forcing filestore of all files");
        }

        const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
        if (force_magic != NULL && ConfValIsTrue(force_magic)) {
            FileForceMagicEnable();
            SCLogConfig("forcing magic lookup for logged files");
        }

        FileForceHashParseCfg(conf);
    }

    if (conf != NULL && ConfNodeLookupChild(conf, "xff") != NULL) {
        output_file_ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
        if (output_file_ctx->xff_cfg != NULL) {
            HttpXFFGetCfg(conf, output_file_ctx->xff_cfg);
        }
    } else if (ojc->xff_cfg) {
        output_file_ctx->parent_xff_cfg = ojc->xff_cfg;
    }

    output_file_ctx->eve_ctx = ojc;
    output_ctx->data = output_file_ctx;
    output_ctx->DeInit = OutputFileLogDeinitSub;

    FileForceTrackingEnable();
    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

void JsonFileLogRegister (void)
{
    /* register as child of eve-log */
    OutputRegisterFileSubModule(LOGGER_JSON_FILE, "eve-log", "JsonFileLog",
        "eve-log.files", OutputFileLogInitSub, JsonFileLogger,
        JsonFileLogThreadInit, JsonFileLogThreadDeinit, NULL);
}
