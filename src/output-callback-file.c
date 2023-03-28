/**
 * \file
 *
 * \author Angelo Mirabella <mirabellaa@vmware.com>
 *
 * Generate fileinfo events and invoke corresponding callback.
 *
 */

#include "suricata-common.h"

#include "output-callback-file.h"
#include "output.h"
#include "output-callback.h"
#include "threadvars.h"

#define MODULE_NAME       "CallbackFileLog"


typedef struct LogFileInfoCtx {
    uint8_t stored_only;
} LogFileInfoCtx;

typedef struct CallbackFileInfoLogThread {
    LogFileInfoCtx *fileinfo_ctx;
} CallbackFileInfoLogThread;

static TmEcode CallbackFileLogThreadInit(ThreadVars *t, const void *initdata, void **data) {
    CallbackFileInfoLogThread *aft = SCCalloc(1, sizeof(CallbackFileInfoLogThread));
    if (unlikely(aft == NULL)) {
        return TM_ECODE_FAILED;
    }

    if (initdata == NULL) {
        SCLogDebug("Error getting context for CallbackLogFile.  \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    aft->fileinfo_ctx = ((OutputCtx *)initdata)->data;
    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode CallbackFileLogThreadDeinit(ThreadVars *t, void *data) {
    CallbackFileInfoLogThread *aft = (CallbackFileInfoLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(CallbackFileInfoLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void CallbackFileLogDeinitSub(OutputCtx *output_ctx) {
    LogFileInfoCtx *fileinfo_ctx = output_ctx->data;

    SCFree(fileinfo_ctx);
    SCFree(output_ctx);
}

static OutputInitResult CallbackFileLogInitSub(ConfNode *conf, OutputCtx *parent_ctx) {
    OutputInitResult result = { NULL, false };

    LogFileInfoCtx *fileinfo_ctx = SCCalloc(1, sizeof(LogFileInfoCtx));
    if (unlikely(fileinfo_ctx == NULL)) {
        return result;
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(fileinfo_ctx);
        return result;
    }

    if (conf) {
        const char *force_filestore = ConfNodeLookupChildValue(conf, "force-filestore");
        if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
            FileForceFilestoreEnable();
            SCLogConfig("forcing filestore of all files");
        }

        fileinfo_ctx->stored_only = FALSE;
        const char *stored_only = ConfNodeLookupChildValue(conf, "stored-only");
        if (stored_only != NULL && ConfValIsTrue(stored_only)) {
            fileinfo_ctx->stored_only = TRUE;
            SCLogConfig("Dumping stored-only files");
        }
    }

    /* Just enable some filestore related features. */
    FileForceTrackingEnable();

    output_ctx->data = fileinfo_ctx;
    output_ctx->DeInit = CallbackFileLogDeinitSub;

    result.ctx = output_ctx;
    result.ok = true;
    return result;
}

static void FileGenerateEvent(const Packet *p, const File *ff, const uint64_t tx_id, uint32_t dir,
                              ThreadVars *tv) {
    /* TODO: add xff info? */
    FileinfoEvent event = {};
    enum OutputJsonLogDirection fdir = LOG_DIR_FLOW;

    switch (dir) {
        case STREAM_TOCLIENT:
            fdir = LOG_DIR_FLOW_TOCLIENT;
            break;
        case STREAM_TOSERVER:
            fdir = LOG_DIR_FLOW_TOSERVER;
            break;
        default:
            break;
    }

    JsonAddrInfo addr = json_addr_info_zero;
    EventAddCommonInfo(p, fdir, &event.common, &addr);

    /* TODO: add app layer metadata */
    CallbackAddAppLayer(p, tx_id, &event.app_layer);

    /* File info. */
    event.fileinfo.filename = ff->name;
    event.fileinfo.filename_len = ff->name_len;

    /* Sids. */
    uint32_t sids[event.fileinfo.sid_cnt];
    event.fileinfo.sid_cnt = ff->sid_cnt;
    event.fileinfo.sids = sids;

    for (uint32_t i = 0; ff->sid != NULL && i < ff->sid_cnt; i++) {
        event.fileinfo.sids[i] = ff->sid[i];
    }

#ifdef HAVE_MAGIC
    if (ff->magic)
        event.fileinfo.magic = ff->magic;
#endif

    event.fileinfo.gaps = ff->flags & FILE_HAS_GAPS;
    char md5[256];
    char sha1[256];
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            event.fileinfo.state = "CLOSED";
            if (ff->flags & FILE_MD5) {
                size_t x;
                int i;
                for (i = 0, x = 0; x < sizeof(ff->md5); x++) {
                    i += snprintf(&md5[i], 255-i, "%02x", ff->md5[x]);
                }
                event.fileinfo.md5 = md5;
            }
            if (ff->flags & FILE_SHA1) {
                size_t x;
                int i;
                for (i = 0, x = 0; x < sizeof(ff->sha1); x++) {
                    i += snprintf(&sha1[i], 255-i, "%02x", ff->sha1[x]);
                }
                event.fileinfo.sha1 = sha1;
            }
            break;
        case FILE_STATE_TRUNCATED:
            event.fileinfo.state = "TRUNCATED";
            break;
        case FILE_STATE_ERROR:
            event.fileinfo.state = "ERROR";
            break;
        default:
            event.fileinfo.state = "UNKNOWN";
            break;
    }

    char sha256[256];
    if (ff->flags & FILE_SHA256) {
        size_t x;
        int i;
        for (i = 0, x = 0; x < sizeof(ff->sha256); x++) {
            i += snprintf(&sha256[i], 255-i, "%02x", ff->sha256[x]);
        }
        event.fileinfo.sha256 = sha256;
    }

    event.fileinfo.stored = ff->flags & FILE_STORED;
    if (event.fileinfo.stored) {
        event.fileinfo.file_id = ff->file_store_id;
    }

    event.fileinfo.size = FileTrackedSize(ff);
    if (ff->end > 0) {
        event.fileinfo.start = ff->start;
        event.fileinfo.end = ff->end;
    }

    event.fileinfo.tx_id = tx_id;

    /* Invoke callback and cleanup. */
    tv->callbacks->fileinfo(&event, p->flow->tenant_uuid, p->flow->user_ctx);
    CallbackCleanupAppLayer(p, tx_id, &event.app_layer);
}

static int CallbackFileLogger(ThreadVars *tv, void *thread_data, const Packet *p, const File *ff,
                              void *tx, const uint64_t tx_id, uint8_t dir) {
    BUG_ON(ff->flags & FILE_LOGGED);
    CallbackFileInfoLogThread *aft = (CallbackFileInfoLogThread *)thread_data;

    if (!tv->callbacks->fileinfo) {
        return 0;
    }

    if (aft->fileinfo_ctx->stored_only && (ff->flags & FILE_STORED) == 0) {
        SCLogDebug("Not dumping information because file is not stored");
        return 0;
    }

    FileGenerateEvent(p, ff, tx_id, dir, tv);

    return 0;
}

void CallbackFileLogRegister(void) {
    OutputRegisterFileSubModule(LOGGER_CALLBACK_FILE, "callback", MODULE_NAME, "callback.fileinfo",
                                CallbackFileLogInitSub, CallbackFileLogger,
                                CallbackFileLogThreadInit, CallbackFileLogThreadDeinit, NULL);
}
