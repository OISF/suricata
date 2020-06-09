/* Copyright (C) 2007-2020 Open Information Security Foundation
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
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threadvars.h"
#include "tm-modules.h"

#include "threads.h"

#include "app-layer-parser.h"

#include "detect-filemagic.h"

#include "stream.h"

#include "util-print.h"
#include "util-unittest.h"
#include "util-privs.h"
#include "util-debug.h"
#include "util-atomic.h"
#include "util-file.h"
#include "util-time.h"
#include "util-buffer.h"
#include "util-byte.h"
#include "util-validate.h"

#include "util-logopenfile.h"

#include "output.h"
#include "output-json.h"
#include "output-json-file.h"
#include "output-json-http.h"
#include "output-json-smtp.h"
#include "output-json-email-common.h"
#include "output-json-nfs.h"
#include "output-json-smb.h"

#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

typedef struct OutputFileCtx_ {
    LogFileCtx *file_ctx;
    uint32_t file_cnt;
    HttpXFFCfg *xff_cfg;
    HttpXFFCfg *parent_xff_cfg;
} OutputFileCtx;

typedef struct JsonFileLogThread_ {
    OutputFileCtx *filelog_ctx;
    MemBuffer *buffer;
} JsonFileLogThread;

JsonBuilder *JsonBuildFileInfoRecord(const Packet *p, const File *ff,
        const bool stored, uint8_t dir, HttpXFFCfg *xff_cfg)
{
    json_t *hjs = NULL;
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
        if (FlowGetAppProtocol(p->flow) == ALPROTO_HTTP) {
            have_xff_ip = HttpXFFGetIPFromTx(p->flow, ff->txid, xff_cfg, xff_buffer, XFF_MAXLEN);
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

    JsonBuilder *js = CreateEveHeader(p, fdir, "fileinfo", &addr);
    if (unlikely(js == NULL))
        return NULL;

    JsonBuilderMark mark = { 0, 0, 0 };
    switch (p->flow->alproto) {
        case ALPROTO_HTTP:
            jb_open_object(js, "http");
            EveHttpAddMetadata(p->flow, ff->txid, js);
            jb_close(js);
            break;
        case ALPROTO_SMTP:
            jb_get_mark(js, &mark);
            jb_open_object(js, "smtp");
            if (EveSMTPAddMetadata(p->flow, ff->txid, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            jb_get_mark(js, &mark);
            jb_open_object(js, "email");
            if (EveEmailAddMetadata(p->flow, ff->txid, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_NFS:
            /* rpc */
            jb_get_mark(js, &mark);
            jb_open_object(js, "rpc");
            if (EveNFSAddMetadataRPC(p->flow, ff->txid, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            /* nfs */
            jb_get_mark(js, &mark);
            jb_open_object(js, "nfs");
            if (EveNFSAddMetadata(p->flow, ff->txid, js)) {
                jb_close(js);
            } else {
                jb_restore_mark(js, &mark);
            }
            break;
        case ALPROTO_SMB:
            hjs = JsonSMBAddMetadata(p->flow, ff->txid);
            if (hjs) {
                jb_set_jsont(js, "smb", hjs);
                json_decref(hjs);
            }
            break;
    }

    jb_set_string(js, "app_proto", AppProtoToString(p->flow->alproto));

    /* Open the fileinfo object. */
    jb_open_object(js, "fileinfo");

    size_t filename_size = ff->name_len * 2 + 1;
    char filename_string[filename_size];
    BytesToStringBuffer(ff->name, ff->name_len, filename_string, filename_size);
    jb_set_string(js, "filename", filename_string);

    jb_open_array(js, "sid");
    for (uint32_t i = 0; ff->sid != NULL && i < ff->sid_cnt; i++) {
        jb_append_uint(js, ff->sid[i]);
    }
    jb_close(js);

#ifdef HAVE_MAGIC
    if (ff->magic)
        jb_set_string(js, "magic", (char *)ff->magic);
#endif
    jb_set_bool(js, "gaps", ff->flags & FILE_HAS_GAPS);
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            jb_set_string(js, "state", "CLOSED");
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                size_t x;
                int i;
                char str[256];
                for (i = 0, x = 0; x < sizeof(ff->md5); x++) {
                    i += snprintf(&str[i], 255-i, "%02x", ff->md5[x]);
                }
                jb_set_string(js, "md5", str);
            }
            if (ff->flags & FILE_SHA1) {
                size_t x;
                int i;
                char str[256];
                for (i = 0, x = 0; x < sizeof(ff->sha1); x++) {
                    i += snprintf(&str[i], 255-i, "%02x", ff->sha1[x]);
                }
                jb_set_string(js, "sha1", str);
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            jb_set_string(js, "state", "TRUNCATED");
            break;
        case FILE_STATE_ERROR:
            jb_set_string(js, "state", "ERROR");
            break;
        default:
            jb_set_string(js, "state", "UNKNOWN");
            break;
    }

#ifdef HAVE_NSS
    if (ff->flags & FILE_SHA256) {
        size_t x;
        int i;
        char str[256];
        for (i = 0, x = 0; x < sizeof(ff->sha256); x++) {
            i += snprintf(&str[i], 255-i, "%02x", ff->sha256[x]);
        }
        jb_set_string(js, "sha256", str);
    }
#endif

    jb_set_bool(js, "stored", stored ? true : false);
    if (ff->flags & FILE_STORED) {
        jb_set_uint(js, "file_id", ff->file_store_id);
    }
    jb_set_uint(js, "size", FileTrackedSize(ff));
    if (ff->end > 0) {
        jb_set_uint(js, "start", ff->start);
        jb_set_uint(js, "end", ff->end);
    }
    jb_set_uint(js, "tx_id", ff->txid);

    /* Close fileinfo object */
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
static void FileWriteJsonRecord(JsonFileLogThread *aft, const Packet *p,
                                const File *ff, uint32_t dir)
{
    HttpXFFCfg *xff_cfg = aft->filelog_ctx->xff_cfg != NULL ?
        aft->filelog_ctx->xff_cfg : aft->filelog_ctx->parent_xff_cfg;;
    JsonBuilder *js = JsonBuildFileInfoRecord(p, ff,
            ff->flags & FILE_STORED ? true : false, dir, xff_cfg);
    if (unlikely(js == NULL)) {
        return;
    }

    MemBufferReset(aft->buffer);
    OutputJsonBuilderBuffer(js, aft->filelog_ctx->file_ctx, &aft->buffer);
    jb_free(js);
}

static int JsonFileLogger(ThreadVars *tv, void *thread_data, const Packet *p,
                          const File *ff, uint8_t dir)
{
    SCEnter();
    JsonFileLogThread *aft = (JsonFileLogThread *)thread_data;

    BUG_ON(ff->flags & FILE_LOGGED);

    SCLogDebug("ff %p", ff);

    FileWriteJsonRecord(aft, p, ff, dir);
    return 0;
}


static TmEcode JsonFileLogThreadInit(ThreadVars *t, const void *initdata, void **data)
{
    JsonFileLogThread *aft = SCMalloc(sizeof(JsonFileLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(JsonFileLogThread));

    if(initdata == NULL)
    {
        SCLogDebug("Error getting context for EveLogFile.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->filelog_ctx = ((OutputCtx *)initdata)->data;

    aft->buffer = MemBufferCreateNew(JSON_OUTPUT_BUFFER_SIZE);
    if (aft->buffer == NULL) {
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode JsonFileLogThreadDeinit(ThreadVars *t, void *data)
{
    JsonFileLogThread *aft = (JsonFileLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    MemBufferFree(aft->buffer);
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

    output_file_ctx->file_ctx = ojc->file_ctx;

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
