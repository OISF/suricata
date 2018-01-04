/* Copyright (C) 2018 Open Information Security Foundation
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

#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-smtp.h"

#include "output.h"
#include "output-filestore.h"

#include "util-print.h"
#include "util-misc.h"

#ifdef HAVE_NSS

#define MODULE_NAME "OutputFilestore"

#define SHA256_STRING_LEN (SHA256_LENGTH * 2)
#define LEAF_DIR_MAX_LEN 4
#define FILESTORE_PREFIX_MAX (PATH_MAX - SHA256_STRING_LEN - LEAF_DIR_MAX_LEN)

static const char *default_log_dir = "filestore";

SC_ATOMIC_DECLARE(uint32_t, filestore_open_file_cnt);  /**< Atomic
                                                        * counter of
                                                        * simultaneously
                                                        * open
                                                        * files */

typedef struct OutputFilestoreCtx_ {
    char prefix[FILESTORE_PREFIX_MAX];
    char tmpdir[FILESTORE_PREFIX_MAX];
} OutputFilestoreCtx;

typedef struct OutputFilestoreLogThread_ {
    OutputFilestoreCtx *ctx;
    uint32_t file_cnt;
    uint16_t counter_max_hits;
} OutputFilestoreLogThread;

static uint64_t OutputFilestoreOpenFilesCounter(void)
{
    uint64_t fcopy = SC_ATOMIC_GET(filestore_open_file_cnt);
    return fcopy;
}

static void OutputFilestoreMetaGetUri(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud->request_uri_normalized != NULL) {
                PrintRawUriFp(fp, bstr_ptr(tx_ud->request_uri_normalized),
                              bstr_len(tx_ud->request_uri_normalized));
            }
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void OutputFilestoreMetaGetHost(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            PrintRawUriFp(fp, (uint8_t *)bstr_ptr(tx->request_hostname),
                          bstr_len(tx->request_hostname));
            return;
        }
    }

    fprintf(fp, "<unknown>");
}

static void OutputFilestoreMetaGetReferer(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "Referer");
            if (h != NULL) {
                PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                              bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void OutputFilestoreMetaGetUserAgent(FILE *fp, const Packet *p, const File *ff)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "User-Agent");
            if (h != NULL) {
                PrintRawUriFp(fp, (uint8_t *)bstr_ptr(h->value),
                              bstr_len(h->value));
                return;
            }
        }
    }

    fprintf(fp, "<unknown>");
}

static void OutputFilestoreMetaGetSmtp(FILE *fp, const Packet *p, const File *ff)
{
    SMTPState *state = (SMTPState *) p->flow->alstate;
    if (state != NULL) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, state, ff->txid);
        if (tx == NULL || tx->msg_tail == NULL)
            return;

        /* Message Id */
        if (tx->msg_tail->msg_id != NULL) {
            fprintf(fp, "MESSAGE-ID:        ");
            PrintRawUriFp(fp, (uint8_t *) tx->msg_tail->msg_id, tx->msg_tail->msg_id_len);
            fprintf(fp, "\n");
        }

        /* Sender */
        MimeDecField *field = MimeDecFindField(tx->msg_tail, "from");
        if (field != NULL) {
            fprintf(fp, "SENDER:            ");
            PrintRawUriFp(fp, (uint8_t *) field->value, field->value_len);
            fprintf(fp, "\n");
        }
    }
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

static void OutputFilestoreLogCreateMetaFile(const Packet *p, const File *ff,
        char *base_filename, int ipver) {
    char metafilename[PATH_MAX] = "";
    snprintf(metafilename, sizeof(metafilename), "%s.meta", base_filename);
    SCLogNotice("Opening %s.", metafilename);
    FILE *fp = fopen(metafilename, "w+");
    if (fp != NULL) {
        char timebuf[64];

        CreateTimeString(&p->ts, timebuf, sizeof(timebuf));

        fprintf(fp, "TIME:              %s\n", timebuf);
        if (p->pcap_cnt > 0) {
            fprintf(fp, "PCAP PKT NUM:      %"PRIu64"\n", p->pcap_cnt);
        }

        char srcip[46], dstip[46];
        Port sp, dp;
        switch (ipver) {
            case AF_INET:
                PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
                break;
            case AF_INET6:
                PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
                PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
                break;
            default:
                strlcpy(srcip, "<unknown>", sizeof(srcip));
                strlcpy(dstip, "<unknown>", sizeof(dstip));
                break;
        }
        sp = p->sp;
        dp = p->dp;

        fprintf(fp, "SRC IP:            %s\n", srcip);
        fprintf(fp, "DST IP:            %s\n", dstip);
        fprintf(fp, "PROTO:             %" PRIu32 "\n", p->proto);
        if (PKT_IS_TCP(p) || PKT_IS_UDP(p)) {
            fprintf(fp, "SRC PORT:          %" PRIu16 "\n", sp);
            fprintf(fp, "DST PORT:          %" PRIu16 "\n", dp);
        }

        fprintf(fp, "APP PROTO:         %s\n",
                AppProtoToString(p->flow->alproto));

        /* Only applicable to HTTP traffic */
        if (p->flow->alproto == ALPROTO_HTTP) {
            fprintf(fp, "HTTP URI:          ");
            OutputFilestoreMetaGetUri(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP HOST:         ");
            OutputFilestoreMetaGetHost(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP REFERER:      ");
            OutputFilestoreMetaGetReferer(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP USER AGENT:   ");
            OutputFilestoreMetaGetUserAgent(fp, p, ff);
            fprintf(fp, "\n");
        } else if (p->flow->alproto == ALPROTO_SMTP) {
            /* Only applicable to SMTP */
            OutputFilestoreMetaGetSmtp(fp, p, ff);
        }

        fprintf(fp, "FILENAME:          ");
        PrintRawUriFp(fp, ff->name, ff->name_len);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

static void OutputFilestoreLogCloseMetaFile(const OutputFilestoreCtx *ctx,
        const File *ff, const char *filename)
{
    FILE *fp = fopen(filename, "a");
    if (fp == NULL) {
        SCLogInfo("Failed to open %s: %s", filename, strerror(errno));
        return;
    }
#ifdef HAVE_MAGIC
    fprintf(fp, "MAGIC:             %s\n",
            ff->magic ? ff->magic : "<unknown>");
#endif
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            fprintf(fp, "STATE:             CLOSED\n");
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                fprintf(fp, "MD5:               ");
                size_t x;
                for (x = 0; x < sizeof(ff->md5); x++) {
                    fprintf(fp, "%02x", ff->md5[x]);
                }
                fprintf(fp, "\n");
            }
            if (ff->flags & FILE_SHA1) {
                fprintf(fp, "SHA1:              ");
                size_t x;
                for (x = 0; x < sizeof(ff->sha1); x++) {
                    fprintf(fp, "%02x", ff->sha1[x]);
                }
                fprintf(fp, "\n");
            }
            if (ff->flags & FILE_SHA256) {
                fprintf(fp, "SHA256:            ");
                size_t x;
                for (x = 0; x < sizeof(ff->sha256); x++) {
                    fprintf(fp, "%02x", ff->sha256[x]);
                }
                fprintf(fp, "\n");
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            fprintf(fp, "STATE:             TRUNCATED\n");
            break;
        case FILE_STATE_ERROR:
            fprintf(fp, "STATE:             ERROR\n");
            break;
        default:
            fprintf(fp, "STATE:             UNKNOWN\n");
            break;
    }
    fprintf(fp, "SIZE:              %"PRIu64"\n", FileTrackedSize(ff));
    
    fclose(fp);
}

static void PrintHexString(char *str, size_t size, uint8_t *buf, size_t buf_len)
{
    int i = 0;
    size_t x = 0;
    for (i = 0, x = 0; x < buf_len; x++) {
        i += snprintf(&str[i], size - i, "%02x", buf[x]);
    }
}

static void OutputFilestoreFinalizeFiles(const OutputFilestoreCtx *ctx,
        File *ff) {
    char final_filename[PATH_MAX] = "";
    snprintf(final_filename, sizeof(final_filename), "%s/file.%u",
            ctx->tmpdir, ff->file_store_id);
    char working_filename[PATH_MAX] = "";
    snprintf(working_filename, sizeof(working_filename), "%s",
            final_filename);
    char sha256string[(SHA256_LENGTH * 2) + 1];
    PrintHexString(sha256string, sizeof(sha256string), ff->sha256,
            sizeof(ff->sha256));
    snprintf(final_filename, sizeof(final_filename), "%s/%c%c/%s",
            ctx->prefix, sha256string[0], sha256string[1], sha256string);
    if (rename(working_filename, final_filename) != 0) {
        SCLogWarning(SC_WARN_RENAMING_FILE, "renaming file %s to %s failed",
                working_filename, final_filename);
        return;
    }

    /* Write metadata. */
    char final_metafilename[PATH_MAX] = "";
    snprintf(final_metafilename, sizeof(final_metafilename),
            "%s.meta", final_filename);
    char working_metafilename[PATH_MAX] = "";
    snprintf(working_metafilename, sizeof(working_metafilename),
            "%s.meta", working_filename);
    OutputFilestoreLogCloseMetaFile(ctx, ff, working_metafilename);
    if (rename(working_metafilename, final_metafilename) != 0) {
        SCLogWarning(SC_WARN_RENAMING_FILE,
                "renaming metafile %s to %s failed", working_metafilename,
                final_metafilename);
    }
}

static int OutputFilestoreLogger(ThreadVars *tv, void *thread_data,
        const Packet *p, File *ff, const uint8_t *data, uint32_t data_len,
        uint8_t flags)
{
    SCEnter();
    OutputFilestoreLogThread *aft = (OutputFilestoreLogThread *)thread_data;
    OutputFilestoreCtx *ctx = aft->ctx;
    char filename[PATH_MAX] = "";
    int file_fd = -1;
    int ipver = -1;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (PKT_IS_IPV4(p)) {
        ipver = AF_INET;
    } else if (PKT_IS_IPV6(p)) {
        ipver = AF_INET6;
    } else {
        return 0;
    }

    SCLogDebug("ff %p, data %p, data_len %u", ff, data, data_len);

    char base_filename[PATH_MAX] = "";
    snprintf(base_filename, sizeof(base_filename), "%s/file.%u",
            ctx->tmpdir, ff->file_store_id);
    snprintf(filename, sizeof(filename), "%s", base_filename);

    if (flags & OUTPUT_FILEDATA_FLAG_OPEN) {
        aft->file_cnt++;

        /* create a .meta file that contains time, src/dst/sp/dp/proto */
        OutputFilestoreLogCreateMetaFile(p, ff, base_filename, ipver);

        if (SC_ATOMIC_GET(filestore_open_file_cnt) < FileGetMaxOpenFiles()) {
            SC_ATOMIC_ADD(filestore_open_file_cnt, 1);
            SCLogNotice("Opening %s.", filename);
            ff->fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
            if (ff->fd == -1) {
                SCLogNotice("failed to create file");
                return -1;
            }
            file_fd = ff->fd;
        } else {
            SCLogNotice("Opening %s.", filename);
            file_fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
            if (file_fd == -1) {
                SCLogNotice("failed to create file");
                return -1;
            }
            if (FileGetMaxOpenFiles() > 0) {
                StatsIncr(tv, aft->counter_max_hits);
            }
        }
    /* we can get called with a NULL ffd when we need to close */
    } else if (data != NULL) {
        if (ff->fd == -1) {
            SCLogNotice("Opening %s.", filename);
            file_fd = open(filename, O_APPEND | O_NOFOLLOW | O_WRONLY);
            if (file_fd == -1) {
                SCLogNotice("failed to open file %s: %s", filename, strerror(errno));
                return -1;
            }
        } else {
            file_fd = ff->fd;
        }
    }

    if (file_fd != -1) {
        ssize_t r = write(file_fd, (const void *)data, (size_t)data_len);
        if (r == -1) {
            SCLogDebug("write failed: %s", strerror(errno));
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
        OutputFilestoreFinalizeFiles(ctx, ff);
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

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogFileStore. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    OutputFilestoreCtx *ctx = ((OutputCtx *)initdata)->data;
    aft->ctx = ctx;

    aft->counter_max_hits =
        StatsRegisterCounter("file_store.open_files_max_hit", t);

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

static void OutputFilestoreLogExitPrintStats(ThreadVars *tv, void *data)
{
    OutputFilestoreLogThread *aft = (OutputFilestoreLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files extracted %" PRIu32 "", tv->name, aft->file_cnt);
}

static void OutputFilestoreLogDeInitCtx(OutputCtx *output_ctx)
{
    OutputFilestoreCtx *ctx = (OutputFilestoreCtx *)output_ctx->data;
    SCFree(ctx);
    SCFree(output_ctx);
}

static void GetLogDirectory(const ConfNode *conf, char *out, size_t out_size)
{
    const char *log_base_dir = ConfNodeLookupChildValue(conf, "dir");
    if (log_base_dir == NULL) {
        SCLogNotice("Using default log directory %s", default_log_dir);
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
        SCLogNotice("Creating directory %s", dir);
        if (SCCreateDirectoryTree(dir, true) != 0) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Failed to create directory %s: %s", dir, strerror(errno));
            return false;
        }
    }

    for (int i = 0; i <= dir_count; i++) {
        char leaf[PATH_MAX];
        snprintf(leaf, sizeof(leaf) - 1, "%s/%02x", dir, i);
        if (!SCPathExists(leaf)) {
            SCLogNotice("Creating directory %s", leaf);
            if (SCDefaultMkDir(leaf) != 0) {
                SCLogError(SC_ERR_CREATE_DIRECTORY,
                        "Failed to create directory %s: %s", leaf,
                        strerror(errno));
                return false;
            }
        }
    }

    /* Make sure the tmp directory exists. */
    char tmpdir[PATH_MAX];
    snprintf(tmpdir, sizeof(tmpdir) - 1, "%s/tmp", dir);
    if (!SCPathExists(tmpdir)) {
        SCLogNotice("Creating directory %s", tmpdir);
        if (SCDefaultMkDir(tmpdir) != 0) {
            SCLogError(SC_ERR_CREATE_DIRECTORY,
                    "Failed to create directory %s: %s", tmpdir,
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
static OutputCtx *OutputFilestoreLogInitCtx(ConfNode *conf)
{
    intmax_t version = 0;
    if (!ConfGetChildValueInt(conf, "version", &version)) {
        return NULL;
    }
    if (version < 2) {
        return NULL;
    }

    char log_directory[PATH_MAX] = "";
    GetLogDirectory(conf, log_directory, sizeof(log_directory));
    if (!InitFilestoreDirectory(log_directory)) {
        return NULL;
    }

    OutputFilestoreCtx *ctx = SCCalloc(1, sizeof(*ctx));
    if (unlikely(ctx == NULL)) {
        return NULL;
    }
    strlcpy(ctx->prefix, log_directory, sizeof(ctx->prefix));
    snprintf(ctx->tmpdir, sizeof(ctx->tmpdir) - 1, "%s/tmp", log_directory);

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = ctx;
    output_ctx->DeInit = OutputFilestoreLogDeInitCtx;

    const char *force_filestore = ConfNodeLookupChildValue(conf,
            "force-filestore");
    if (force_filestore != NULL && ConfValIsTrue(force_filestore)) {
        FileForceFilestoreEnable();
        SCLogInfo("forcing filestore of all files");
    }

    const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
    if (force_magic != NULL && ConfValIsTrue(force_magic)) {
        FileForceMagicEnable();
        SCLogInfo("forcing magic lookup for stored files");
    }

    FileForceHashParseCfg(conf);

    /* The new filestore requires SHA256. */
    FileForceSha256Enable();

    SCLogInfo("storing files in %s", ctx->prefix);

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
        } else {
            FileReassemblyDepthEnable(stream_depth);
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
                       stream_depth_str);
            exit(EXIT_FAILURE);
        } else {
            if (file_count != 0) {
                FileSetMaxOpenFiles(file_count);
                SCLogInfo("file-store will keep a max of %d simultaneously"
                          " open files", file_count);
            }
        }
    }

    SCReturnPtr(output_ctx, "OutputCtx");
}

#endif /* HAVE_NSS */

void OutputFilestoreInitConfig(void)
{
#ifdef HAVE_NSS
    StatsRegisterGlobalCounter("file_store.open_files",
            OutputFilestoreOpenFilesCounter);
#endif /* HAVE_NSS */
}

void OutputFilestoreRegister (void)
{
#ifdef HAVE_NSS
    OutputRegisterFiledataModule(LOGGER_FILE_STORE, MODULE_NAME, "file-store",
            OutputFilestoreLogInitCtx, OutputFilestoreLogger,
            OutputFilestoreLogThreadInit, OutputFilestoreLogThreadDeinit,
            OutputFilestoreLogExitPrintStats);

    SC_ATOMIC_INIT(filestore_open_file_cnt);
    SC_ATOMIC_SET(filestore_open_file_cnt, 0);
    SCLogDebug("registered");
#endif
}
