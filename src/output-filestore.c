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

#include "suricata-common.h"

#include "stream-tcp.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"
#include "app-layer-smtp.h"

#include "feature.h"

#include "output.h"
#include "output-filestore.h"
#include "output-json-file.h"

#include "util-print.h"
#include "util-misc.h"

#define MODULE_NAME "OutputFilestore"

/* Create a filestore specific PATH_MAX that is less than the system
 * PATH_MAX to prevent newer gcc truncation warnings with snprint. */
#define SHA256_STRING_LEN    (SC_SHA256_LEN * 2)
#define LEAF_DIR_MAX_LEN 4
#define FILESTORE_PREFIX_MAX (PATH_MAX - SHA256_STRING_LEN - LEAF_DIR_MAX_LEN)

/* The default log directory, relative to the default log
 * directory. */
static const char *default_log_dir = "filestore";

/* Atomic counter of simultaneously open files. */
static SC_ATOMIC_DECLARE(uint32_t, filestore_open_file_cnt);

typedef struct OutputFilestoreCtx_ {
    char prefix[FILESTORE_PREFIX_MAX];
    char tmpdir[FILESTORE_PREFIX_MAX];
    bool fileinfo;
    HttpXFFCfg *xff_cfg;
} OutputFilestoreCtx;

typedef struct OutputFilestoreLogThread_ {
    OutputFilestoreCtx *ctx;
    uint16_t counter_max_hits;
    uint16_t fs_error_counter;
} OutputFilestoreLogThread;

/* For WARN_ONCE, a record of warnings that have already been
 * issued. */
static thread_local bool once_errs[SC_ERR_MAX];

#define WARN_ONCE(err_code, ...)  do {                   \
        if (!once_errs[err_code]) {                      \
            once_errs[err_code] = true;                  \
            SCLogWarning(err_code, __VA_ARGS__);         \
        }                                                \
    } while (0)

static uint64_t OutputFilestoreOpenFilesCounter(void)
{
    return SC_ATOMIC_GET(filestore_open_file_cnt);
}

static uint32_t g_file_store_max_open_files = 0;

static void FileSetMaxOpenFiles(uint32_t count)
{
    g_file_store_max_open_files = count;
}

static uint32_t FileGetMaxOpenFiles(void)
{
    return g_file_store_max_open_files;
}

/**
 * \brief Update the timestamps on a file to match those of another
 *     file.
 *
 * \param src_filename Filename to use as timestamp source.
 * \param filename Filename to apply timestamps to.
 */
static void OutputFilestoreUpdateFileTime(const char *src_filename,
        const char *filename)
{
    struct stat sb;
    if (stat(src_filename, &sb) != 0) {
        SCLogDebug("Failed to stat %s: %s", filename, strerror(errno));
        return;
    }
    struct utimbuf utimbuf = {
        .actime = sb.st_atime,
        .modtime = sb.st_mtime,
    };
    if (utime(filename, &utimbuf) != 0) {
        SCLogDebug("Failed to update file timestamps: %s: %s", filename,
                strerror(errno));
    }
}

static void OutputFilestoreFinalizeFiles(ThreadVars *tv, const OutputFilestoreLogThread *oft,
        const OutputFilestoreCtx *ctx, const Packet *p, File *ff, void *tx, const uint64_t tx_id,
        uint8_t dir)
{
    /* Stringify the SHA256 which will be used in the final
     * filename. */
    char sha256string[(SC_SHA256_LEN * 2) + 1];
    PrintHexString(sha256string, sizeof(sha256string), ff->sha256,
            sizeof(ff->sha256));

    char tmp_filename[PATH_MAX] = "";
    snprintf(tmp_filename, sizeof(tmp_filename), "%s/file.%u", ctx->tmpdir,
            ff->file_store_id);

    char final_filename[PATH_MAX] = "";
    snprintf(final_filename, sizeof(final_filename), "%s/%c%c/%s",
            ctx->prefix, sha256string[0], sha256string[1], sha256string);

    if (SCPathExists(final_filename)) {
        OutputFilestoreUpdateFileTime(tmp_filename, final_filename);
        if (unlink(tmp_filename) != 0) {
            StatsIncr(tv, oft->fs_error_counter);
            WARN_ONCE(SC_WARN_REMOVE_FILE,
                    "Failed to remove temporary file %s: %s", tmp_filename,
                    strerror(errno));
        }
    } else if (rename(tmp_filename, final_filename) != 0) {
        StatsIncr(tv, oft->fs_error_counter);
        WARN_ONCE(SC_WARN_RENAMING_FILE, "Failed to rename %s to %s: %s",
                tmp_filename, final_filename, strerror(errno));
        if (unlink(tmp_filename) != 0) {
            /* Just increment, don't log as has_fs_errors would
             * already be set above. */
            StatsIncr(tv, oft->fs_error_counter);
        }
        return;
    }

    if (ctx->fileinfo) {
        char js_metadata_filename[PATH_MAX];
        if (snprintf(js_metadata_filename, sizeof(js_metadata_filename),
                        "%s.%"PRIuMAX".%u.json", final_filename,
                        (uintmax_t)p->ts.tv_sec, ff->file_store_id)
                == (int)sizeof(js_metadata_filename)) {
            WARN_ONCE(SC_ERR_SPRINTF,
                "Failed to write file info record. Output filename truncated.");
        } else {
            JsonBuilder *js_fileinfo =
                    JsonBuildFileInfoRecord(p, ff, tx, tx_id, true, dir, ctx->xff_cfg, NULL);
            if (likely(js_fileinfo != NULL)) {
                jb_close(js_fileinfo);
                FILE *out = fopen(js_metadata_filename, "w");
                if (out != NULL) {
                    size_t js_len = jb_len(js_fileinfo);
                    fwrite(jb_ptr(js_fileinfo), js_len, 1, out);
                    fclose(out);
                }
                jb_free(js_fileinfo);
            }
        }
    }
}

static int OutputFilestoreLogger(ThreadVars *tv, void *thread_data, const Packet *p, File *ff,
        void *tx, const uint64_t tx_id, const uint8_t *data, uint32_t data_len, uint8_t flags,
        uint8_t dir)
{
    SCEnter();
    OutputFilestoreLogThread *aft = (OutputFilestoreLogThread *)thread_data;
    OutputFilestoreCtx *ctx = aft->ctx;
    char filename[PATH_MAX] = "";
    int file_fd = -1;

    /* no flow, no files */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_IPV4(p) || PKT_IS_IPV6(p))) {
        return 0;
    }

    SCLogDebug("ff %p, data %p, data_len %u", ff, data, data_len);

    char base_filename[PATH_MAX] = "";
    snprintf(base_filename, sizeof(base_filename), "%s/file.%u",
            ctx->tmpdir, ff->file_store_id);
    snprintf(filename, sizeof(filename), "%s", base_filename);

    if (flags & OUTPUT_FILEDATA_FLAG_OPEN) {
        file_fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY,
                0644);
        if (file_fd == -1) {
            StatsIncr(tv, aft->fs_error_counter);
            SCLogWarning(SC_ERR_OPENING_FILE,
                    "Filestore (v2) failed to create %s: %s", filename,
                    strerror(errno));
            return -1;
        }

        if (SC_ATOMIC_GET(filestore_open_file_cnt) < FileGetMaxOpenFiles()) {
            SC_ATOMIC_ADD(filestore_open_file_cnt, 1);
            ff->fd = file_fd;
        } else {
            if (FileGetMaxOpenFiles() > 0) {
                StatsIncr(tv, aft->counter_max_hits);
            }
            ff->fd = -1;
        }
    /* we can get called with a NULL ffd when we need to close */
    } else if (data != NULL) {
        if (ff->fd == -1) {
            file_fd = open(filename, O_APPEND | O_NOFOLLOW | O_WRONLY);
            if (file_fd == -1) {
                StatsIncr(tv, aft->fs_error_counter);
                WARN_ONCE(SC_ERR_OPENING_FILE,
                        "Filestore (v2) failed to open file %s: %s",
                        filename, strerror(errno));
                return -1;
            }
        } else {
            file_fd = ff->fd;
        }
    }

    if (file_fd != -1) {
        ssize_t r = write(file_fd, (const void *)data, (size_t)data_len);
        if (r == -1) {
            StatsIncr(tv, aft->fs_error_counter);
            WARN_ONCE(SC_ERR_FWRITE,
                    "Filestore (v2) failed to write to %s: %s",
                    filename, strerror(errno));
            if (ff->fd != -1) {
                SC_ATOMIC_SUB(filestore_open_file_cnt, 1);
            }
            ff->fd = -1;
        }
        if (ff->fd == -1) {
            close(file_fd);
        }
    }

    if (flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
        if (ff->fd != -1) {
            close(ff->fd);
            ff->fd = -1;
            SC_ATOMIC_SUB(filestore_open_file_cnt, 1);
        }
        OutputFilestoreFinalizeFiles(tv, aft, ctx, p, ff, tx, tx_id, dir);
    }

    return 0;
}

static TmEcode OutputFilestoreLogThreadInit(ThreadVars *t, const void *initdata,
        void **data)
{
    OutputFilestoreLogThread *aft = SCMalloc(sizeof(OutputFilestoreLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(OutputFilestoreLogThread));

    if (initdata == NULL) {
        SCLogDebug("Error getting context for LogFileStore. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    OutputFilestoreCtx *ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = ctx;

    aft->counter_max_hits =
        StatsRegisterCounter("file_store.open_files_max_hit", t);

    /* File system type errors (open, write, rename) will only be
     * logged once. But this stat will be incremented for every
     * occurence. */
    aft->fs_error_counter = StatsRegisterCounter("file_store.fs_errors", t);

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode OutputFilestoreLogThreadDeinit(ThreadVars *t, void *data)
{
    OutputFilestoreLogThread *aft = (OutputFilestoreLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(OutputFilestoreLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void OutputFilestoreLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputFilestoreCtx *ctx = (OutputFilestoreCtx *)output_ctx->data;
    if (ctx->xff_cfg != NULL) {
        SCFree(ctx->xff_cfg);
    }
    SCFree(ctx);
    SCFree(output_ctx);
}

static void GetLogDirectory(const ConfNode *conf, char *out, size_t out_size)
{
    const char *log_base_dir = ConfNodeLookupChildValue(conf, "dir");
    if (log_base_dir == NULL) {
        SCLogConfig("Filestore (v2) default log directory %s", default_log_dir);
        log_base_dir = default_log_dir;
    }
    if (PathIsAbsolute(log_base_dir)) {
        strlcpy(out, log_base_dir, out_size);
    } else {
        const char *default_log_prefix = ConfigGetLogDirectory();
        snprintf(out, out_size, "%s/%s", default_log_prefix, log_base_dir);
    }
}

static bool InitFilestoreDirectory(const char *dir)
{
    const uint8_t dir_count = 0xff;

    if (!SCPathExists(dir)) {
        SCLogInfo("Filestore (v2) creating directory %s", dir);
        if (SCCreateDirectoryTree(dir, true) != 0) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Filestore (v2) failed to create directory %s: %s", dir,
                    strerror(errno));
            return false;
        }
    }

    for (int i = 0; i <= dir_count; i++) {
        char leaf[PATH_MAX];
        int n = snprintf(leaf, sizeof(leaf), "%s/%02x", dir, i);
        if (n < 0 || n >= PATH_MAX) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Filestore (v2) failed to create leaf directory: "
                    "path too long");
            return false;
        }
        if (!SCPathExists(leaf)) {
            SCLogInfo("Filestore (v2) creating directory %s", leaf);
            if (SCDefaultMkDir(leaf) != 0) {
                SCLogError(SC_ERR_CREATE_DIRECTORY,
                        "Filestore (v2) failed to create directory %s: %s",
                        leaf, strerror(errno));
                return false;
            }
        }
    }

    /* Make sure the tmp directory exists. */
    char tmpdir[PATH_MAX];
    int n = snprintf(tmpdir, sizeof(tmpdir), "%s/tmp", dir);
    if (n < 0 || n >= PATH_MAX) {
        SCLogError(SC_ERR_CREATE_DIRECTORY,
                "Filestore (v2) failed to create tmp directory: path too long");
        return false;
    }
    if (!SCPathExists(tmpdir)) {
        SCLogInfo("Filestore (v2) creating directory %s", tmpdir);
        if (SCDefaultMkDir(tmpdir) != 0) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Filestore (v2) failed to create directory %s: %s", tmpdir,
                    strerror(errno));
            return false;
        }
    }

    return true;
}

/** \brief Create a new http log OutputFilestoreCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, OutputFilestoreCtx* to the file_ctx if succesful
 * */
static OutputInitResult OutputFilestoreLogInitCtx(ConfNode *conf)
{
    OutputInitResult result = { NULL, false };

    intmax_t version = 0;
    if (!ConfGetChildValueInt(conf, "version", &version) || version < 2) {
        SCLogWarning(SC_WARN_DEPRECATED,
                "File-store v1 has been removed. Please update to file-store v2.");
        return result;
    }

    if (RunModeOutputFiledataEnabled()) {
        SCLogWarning(SC_ERR_NOT_SUPPORTED,
                "A file data logger is already enabled. Filestore (v2) "
                "will not be enabled.");
        return result;
    }

    char log_directory[PATH_MAX] = "";
    GetLogDirectory(conf, log_directory, sizeof(log_directory));
    if (!InitFilestoreDirectory(log_directory)) {
        return result;
    }

    OutputFilestoreCtx *ctx = SCCalloc(1, sizeof(*ctx));
    if (unlikely(ctx == NULL)) {
        return result;
    }

    strlcpy(ctx->prefix, log_directory, sizeof(ctx->prefix));
    int written = snprintf(ctx->tmpdir, sizeof(ctx->tmpdir) - 1, "%s/tmp",
            log_directory);
    if (written == sizeof(ctx->tmpdir)) {
        SCLogError(SC_ERR_SPRINTF, "File-store output directory overflow.");
        SCFree(ctx);
        return result;
    }

    ctx->xff_cfg = SCCalloc(1, sizeof(HttpXFFCfg));
    if (ctx->xff_cfg != NULL) {
        HttpXFFGetCfg(conf, ctx->xff_cfg);
    }

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(ctx);
        return result;
    }

    output_ctx->data = ctx;
    output_ctx->DeInit = OutputFilestoreLogDeInitCtx;

    const char *write_fileinfo = ConfNodeLookupChildValue(conf,
            "write-fileinfo");
    if (write_fileinfo != NULL && ConfValIsTrue(write_fileinfo)) {
        SCLogConfig("Filestore (v2) will output fileinfo records.");
        ctx->fileinfo = true;
    }

    const char *force_filestore = ConfNodeLookupChildValue(conf,
            "force-filestore");
    if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
        FileForceFilestoreEnable();
        SCLogInfo("forcing filestore of all files");
    }

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogConfig("Filestore (v2) forcing magic lookup for stored files");
    }

    FileForceHashParseCfg(conf);

    /* The new filestore requires SHA256. */
    FileForceSha256Enable();

    ProvidesFeature(FEATURE_OUTPUT_FILESTORE);

    const char *stream_depth_str = ConfNodeLookupChildValue(conf,
            "stream-depth");
    if (stream_depth_str != NULL && strcmp(stream_depth_str, "no")) {
        uint32_t stream_depth = 0;
        if (ParseSizeStringU32(stream_depth_str,
                               &stream_depth) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "file-store.stream-depth "
                       "from conf file - %s.  Killing engine",
                       stream_depth_str);
            exit(EXIT_FAILURE);
        }
        if (stream_depth) {
            if (stream_depth <= stream_config.reassembly_depth) {
                SCLogWarning(SC_WARN_FILESTORE_CONFIG,
                           "file-store.stream-depth value %" PRIu32 " has "
                           "no effect since it's less than stream.reassembly.depth "
                           "value.", stream_depth);
            } else {
                FileReassemblyDepthEnable(stream_depth);
            }
        }
    }

    const char *file_count_str = ConfNodeLookupChildValue(conf,
            "max-open-files");
    if (file_count_str != NULL) {
        uint32_t file_count = 0;
        if (ParseSizeStringU32(file_count_str,
                               &file_count) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing "
                       "file-store.max-open-files "
                       "from conf file - %s.  Killing engine",
                       file_count_str);
            exit(EXIT_FAILURE);
        } else {
            if (file_count != 0) {
                FileSetMaxOpenFiles(file_count);
                SCLogConfig("Filestore (v2) will keep a max of %d "
                        "simultaneously open files", file_count);
            }
        }
    }

    result.ctx = output_ctx;
    result.ok = true;
    SCReturnCT(result, "OutputInitResult");
}

void OutputFilestoreRegister(void)
{
    OutputRegisterFiledataModule(LOGGER_FILE_STORE, MODULE_NAME, "file-store",
            OutputFilestoreLogInitCtx, OutputFilestoreLogger,
            OutputFilestoreLogThreadInit, OutputFilestoreLogThreadDeinit,
            NULL);

    SC_ATOMIC_INIT(filestore_open_file_cnt);
    SC_ATOMIC_SET(filestore_open_file_cnt, 0);
}

void OutputFilestoreRegisterGlobalCounters(void)
{
    StatsRegisterGlobalCounter("file_store.open_files", OutputFilestoreOpenFilesCounter);
}
