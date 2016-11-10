/* Copyright (C) 2007-2013 Open Information Security Foundation
 * Copyright (C) 2016 Lockheed Martin Corporation
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
#include "util-misc.h"

#include "output.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "app-layer-smtp.h"
#include "util-decode-mime.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#ifdef HAVE_LIBHIREDIS
#include "hiredis/hiredis.h"
#endif
#include <jansson.h>

#define MODULE_NAME "LogFilestoreLog"

static char g_logfile_base_dir[PATH_MAX] = "/tmp";

typedef struct LogFilestoreLogThread_ {
    LogFileCtx *file_ctx;
    /** LogFilestoreCtx has the pointer to the file and a mutex to allow multithreading */
    uint32_t file_cnt;
    redisContext *redis;
} LogFilestoreLogThread;

static void LogFilestoreMetaGetUri(FILE *fp, const Packet *p, const File *ff)
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

static void LogFilestoreMetaGetHost(FILE *fp, const Packet *p, const File *ff)
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

static void LogFilestoreMetaGetReferer(FILE *fp, const Packet *p, const File *ff)
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

static void LogFilestoreMetaGetUserAgent(FILE *fp, const Packet *p, const File *ff)
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

static void LogFilestoreMetaGetSmtp(FILE *fp, const Packet *p, const File *ff)
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

static void LogFilestoreLogCreateMetaFile(const Packet *p, const File *ff, char *filename, int ipver) {
    char metafilename[PATH_MAX] = "";
    snprintf(metafilename, sizeof(metafilename), "%s.meta", filename);
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
            LogFilestoreMetaGetUri(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP HOST:         ");
            LogFilestoreMetaGetHost(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP REFERER:      ");
            LogFilestoreMetaGetReferer(fp, p, ff);
            fprintf(fp, "\n");
            fprintf(fp, "HTTP USER AGENT:   ");
            LogFilestoreMetaGetUserAgent(fp, p, ff);
            fprintf(fp, "\n");
        } else if (p->flow->alproto == ALPROTO_SMTP) {
            /* Only applicable to SMTP */
            LogFilestoreMetaGetSmtp(fp, p, ff);
        }

        fprintf(fp, "FILENAME:          ");
        PrintRawUriFp(fp, ff->name, ff->name_len);
        fprintf(fp, "\n");

        fclose(fp);
    }
}

static void LogFilestoreLogCloseMetaFile(const File *ff)
{
    char filename[PATH_MAX] = "";
    snprintf(filename, sizeof(filename), "%s/file.%u",
            g_logfile_base_dir, ff->file_id);
    char metafilename[PATH_MAX] = "";
    snprintf(metafilename, sizeof(metafilename), "%s.meta", filename);
    FILE *fp = fopen(metafilename, "a");
    if (fp != NULL) {
        fprintf(fp, "MAGIC:             %s\n",
                ff->magic ? ff->magic : "<unknown>");

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
        fprintf(fp, "SIZE:              %"PRIu64"\n", FileSize(ff));

        fclose(fp);
    } else {
        SCLogInfo("opening %s failed: %s", metafilename, strerror(errno));
    }
}

/* TODO: Untested sample caching functions
 * static int LogFilestoreRedisCacheCheck(redisContext *rc, const char *key)
 * {
 *     if (rc == NULL || key == NULL)
 *     {
 *         return -1;
 *     }
 * 
 *     redisReply *reply = redisCommand(rc, "GET %s", key);
 * 
 *     if (reply == NULL)
 *     {
 *         printf("NULL REPLY!\n");
 *         return -1;
 *     }
 * 
 *     switch (reply->type)
 *     {
 *         case REDIS_REPLY_NIL:
 *             return 0;
 *         case REDIS_REPLY_ERROR:
 *             printf("REDIS_REPLY_ERROR: %s\n", reply->str);
 *             break;
 *         case REDIS_REPLY_INTEGER:
 *             printf("REDIS_REPLY_INTEGER: %lld\n", reply->integer);
 *             break;
 *         case REDIS_REPLY_STATUS:
 *             printf("REDIS_REPLY_STATUS: %s\n", reply->str);
 *             break;
 *         default:
 *             printf("Unknown Error Value: %d\n", reply->type);
 *             break;
 *     }
 * 
 *     return -1;
 * }
 * 
 * 
 * static int LogFilestoreRedisCacheAdd(redisContext *rc, const char *key)
 * {
 *     if (rc == NULL || key == NULL)
 *     {
 *         return -1;
 *     }
 * 
 *     redisReply *reply = redisCommand(rc, "SET %s 1 EX 300", key);
 * 
 *     if (reply == NULL)
 *     {
 *         printf("NULL REPLY!\n");
 *         return -1;
 *     }
 * 
 *     switch (reply->type)
 *     {
 *         case REDIS_REPLY_NIL:
 *             return 0;
 *         case REDIS_REPLY_ERROR:
 *             printf("REDIS_REPLY_ERROR: %s\n", reply->str);
 *             break;
 *         case REDIS_REPLY_INTEGER:
 *             printf("REDIS_REPLY_INTEGER: %lld\n", reply->integer);
 *             break;
 *         case REDIS_REPLY_STATUS:
 *             printf("REDIS_REPLY_STATUS: %s\n", reply->str);
 *             break;
 *         default:
 *             printf("Unknown Error Value: %d\n", reply->type);
 *             break;
 *     }
 * 
 *     return -1;
 * }
 */

static inline void *LogFilestoreLoggerBuildRawHeaders(const void *header_raw, 
        const size_t header_raw_len, const bstr *header_line)
{
    if (header_raw == NULL || header_line == NULL)
    {
        return NULL;
    }

    char *raw_c = bstr_util_memdup_to_c(header_raw, header_raw_len);
    char *line_c = bstr_util_strdup_to_c(header_line);
    
    /* Add 3 for CRLF + NULL terminate */
    size_t mem_size = (size_t)header_raw_len + strlen(line_c) + 3;
    char *full_header = (char *)SCMalloc(mem_size);

    snprintf(full_header, mem_size, "%s\r\n%s", line_c, raw_c);

    SCFree(raw_c);
    SCFree(line_c);

    return full_header;
}

static inline int LogFilestoreLoggerAddBstrToJSON(const char *ckey, const bstr *val, json_t *js)
{
    char *cval = bstr_util_strdup_to_c(val);
    if (cval != NULL)
    {
        json_object_set_new(js, ckey, json_string(cval));
        SCFree(cval);
    }
    return 0;
}

static inline int LogFilestoreLoggerBuildParsedHdrJSON(const htp_table_t *h, json_t *js)
{
    bstr *key;
    htp_header_t *val;
    char *ckey, *cval;
    size_t n = htp_table_size(h);

    for (size_t i = 0; i < n; i++)
    {
        /* TODO modify libHTP to allow for iteration over table values */
        val = htp_table_get_index(h, i, &key);
        ckey = bstr_util_strdup_to_c(key);
        cval = bstr_util_strdup_to_c(val->value);
        json_object_set_new(js, ckey, json_string(cval));
        SCFree(ckey);
        SCFree(cval);
    }

    return 0;
}

static int LogFilestoreLoggerGetMetadataJSON(const Packet *p, const File *ff, json_t *js)
{
    SCEnter();

    char srcip[46], dstip[46];
    HtpTxUserData *tx_ud;
    htp_tx_t *tx;

    char *http_dir = "response";
    srcip[0] = '\0';
    dstip[0] = '\0';

    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL)
    {
        tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL)
        {
            json_t *req_js = json_object();
            json_t *res_js = json_object();

            /* build parsed request headers in JSON */
            LogFilestoreLoggerBuildParsedHdrJSON(tx->request_headers, req_js);
            LogFilestoreLoggerAddBstrToJSON("type", tx->request_method, req_js);
            LogFilestoreLoggerAddBstrToJSON("request", tx->request_uri, req_js);
            LogFilestoreLoggerAddBstrToJSON("protocol", tx->request_protocol, req_js);

            /* build parsed response headers in JSON */
            LogFilestoreLoggerBuildParsedHdrJSON(tx->response_headers, res_js);
            LogFilestoreLoggerAddBstrToJSON("code", tx->response_status, res_js);
            LogFilestoreLoggerAddBstrToJSON("message", tx->response_message, res_js);
            LogFilestoreLoggerAddBstrToJSON("protocol", tx->response_protocol, res_js);

            /* set HTTP direction to indicate if extracted file is from request or response */
            if (p->flowflags & FLOW_PKT_TOSERVER)
            {
                http_dir = "request";
            }

            tx_ud = htp_tx_get_user_data(tx);

            if (tx_ud != NULL)
            {
                /* obtain full raw request headers */
                char *raw = LogFilestoreLoggerBuildRawHeaders((void *)tx_ud->request_headers_raw,
                        (size_t)tx_ud->request_headers_raw_len,
                        tx->request_line);
                if (raw != NULL)
                {
                    json_object_set_new(req_js, "raw", json_string(raw));
                    SCFree(raw);
                }

                /* obtain full raw response headers */
                raw = LogFilestoreLoggerBuildRawHeaders((void *)tx_ud->response_headers_raw,
                        (size_t)tx_ud->response_headers_raw_len,
                        tx->response_line);
                if (raw != NULL)
                {
                    json_object_set_new(res_js, "raw", json_string(raw));
                    SCFree(raw);
                }
            }
            json_object_set_new(js, "http_request", req_js);
            json_object_set_new(js, "http_response", res_js);
        }
    }

    /* obtain source and destination IPs */
    if (PKT_IS_IPV4(p))
    {
        PrintInet(AF_INET, (const void *)GET_IPV4_SRC_ADDR_PTR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET, (const void *)GET_IPV4_DST_ADDR_PTR(p), dstip, sizeof(dstip));
    }
    else if (PKT_IS_IPV6(p))
    {
        PrintInet(AF_INET6, (const void *)GET_IPV6_SRC_ADDR(p), srcip, sizeof(srcip));
        PrintInet(AF_INET6, (const void *)GET_IPV6_DST_ADDR(p), dstip, sizeof(dstip));
    }
    else
    {
        strlcpy(srcip, "", sizeof(srcip));
        strlcpy(dstip, "", sizeof(dstip));
    }

    /* add IPs, ports, and direction to JSON metadata structure */
    json_object_set_new(js, "saddr", json_string(srcip));
    json_object_set_new(js, "daddr", json_string(dstip));
    json_object_set_new(js, "sport", json_integer(p->sp));
    json_object_set_new(js, "dport", json_integer(p->dp));
    json_object_set_new(js, "http_direction", json_string(http_dir));

    return 0;
}

static int LogFilestoreLoggerRedis(ThreadVars *tv, void *thread_data, const Packet *p,
        const File *ff, const uint8_t *data, uint32_t data_len, uint8_t flags)
{
    SCEnter();
    if (data == NULL || data_len == 0)
    {
        return 0;
    }

    /* TODO
     * Modify this to work for more than HTTP for acquiring metadata - (TLS Certs and SMTP)
     * Also - decide how to handle truncated files - hashing currently 
     * not supported for truncated files
     */
    if (p->flow->alproto != ALPROTO_HTTP)
    {
        SCLogInfo("FileStore Redis - Skipping Non-HTTP source");
        return -1;
    }
    if (ff->state != FILE_STATE_CLOSED)
    {
        SCLogInfo("FileStore Redis - Skipping truncated file");
        return 0;
    }

    char digest[512];
    char prefix_digest[512];

    json_t *js = json_object();

    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)thread_data;
    redisContext *rc = aft->redis;

    LogFilestoreLoggerGetMetadataJSON(p, ff, js);

    size_t x;
    for (x = 0; x < sizeof(ff->md5); x++)
    {
        snprintf(&digest[x*2], 3, "%02x", ff->md5[x]);
    }
    digest[x*2] = '\0';

    /* TODO Make prefix optional if caching is enabled (see sample functions
     * commented out above).
     * TODO Create an additional key prefix that is configurable to distinguish
     * keys within Redis as belonging to Suricata
     */
    snprintf(prefix_digest, 512, "%d_%s", ff->file_id, digest);

    char *js_out = json_dumps(js, 0);
    redisReply *reply = redisCommand(rc, "SET %s%s %s EX %d", prefix_digest, "_meta", js_out, 300);
    SCFree(js_out);

    if (reply == NULL)
    {
        SCLogInfo("Null redisReply object - FileStore Meta");
        return 0;
    }
 
    switch (reply->type)
    {
        case REDIS_REPLY_NIL:
            SCLogWarning(SC_ERR_SOCKET, "FileStore buffer: REDIS_REPLY_NIL");
            break;
        case REDIS_REPLY_ERROR:
            SCLogWarning(SC_ERR_SOCKET, "FileStore buffer: Redis error: %s", reply->str);
            break;
        case REDIS_REPLY_STATUS:
            SCLogDebug("Filestore buffer: REDIS_REPLY_STATUS: %s", reply->str);
            break;
        default:
            SCLogWarning(SC_ERR_SOCKET, "Filestore buffer: Unkown Redis Error Value: %d", reply->type);
            break;
    }

    reply = redisCommand(rc, "SET %s%s %b EX %d", prefix_digest, "_buf", data, data_len, 300);

    if (reply == NULL)
    {
        SCLogInfo("Null redisReply object - FileStore Buffer");
        return -1;
    }
 
    switch (reply->type)
    {
        case REDIS_REPLY_NIL:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Meta: REDIS_REPLY_NIL");
            break;
        case REDIS_REPLY_ERROR:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Meta: Redis error: %s", reply->str);
            break;
        case REDIS_REPLY_STATUS:
            SCLogDebug("FileStore Meta: REDIS_REPLY_STATUS: %s", reply->str);
            break;
        default:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Meta: Unkown Redis Error Value: %d", reply->type);
            break;
    }

    freeReplyObject(reply);

    /* Push digest onto Redis Queue */
    reply = redisCommand(rc, "RPUSH %s %s", "suricata_queue", prefix_digest);

    if (reply == NULL)
    {
        SCLogInfo("Null redisReply object - FileStore Queue");
        return -1;
    }
 
    switch (reply->type)
    {
        case REDIS_REPLY_NIL:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Queue: REDIS_REPLY_NIL");
            break;
        case REDIS_REPLY_ERROR:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Queue: Redis error: %s", reply->str);
            break;
        case REDIS_REPLY_INTEGER:
            SCLogDebug("FileStore Queue: REDIS_REPLY_INTEGER: %lld", reply->integer);
            break;
        default:
            SCLogWarning(SC_ERR_SOCKET, "FileStore Queue: Unkown Redis Error Value: %d", reply->type);
            break;
    }

    SCLogInfo("Pushed file to Redis queue: %d_%s\n", ff->file_id, digest);

    freeReplyObject(reply);
    json_object_clear(js);
    json_decref(js);
    aft->file_cnt++;

    return 0;
}

static int LogFilestoreLoggerDisk(ThreadVars *tv, void *thread_data, const Packet *p,
        const File *ff, const uint8_t *data, uint32_t data_len, uint8_t flags)
{
    SCEnter();
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)thread_data;
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

    snprintf(filename, sizeof(filename), "%s/file.%u",
            g_logfile_base_dir, ff->file_id);

    if (flags & OUTPUT_FILEDATA_FLAG_OPEN) {
        aft->file_cnt++;

        /* create a .meta file that contains time, src/dst/sp/dp/proto */
        LogFilestoreLogCreateMetaFile(p, ff, filename, ipver);

        file_fd = open(filename, O_CREAT | O_TRUNC | O_NOFOLLOW | O_WRONLY, 0644);
        if (file_fd == -1) {
            SCLogDebug("failed to create file");
            return -1;
        }
    /* we can get called with a NULL ffd when we need to close */
    } else if (data != NULL) {
        file_fd = open(filename, O_APPEND | O_NOFOLLOW | O_WRONLY);
        if (file_fd == -1) {
            SCLogDebug("failed to open file %s: %s", filename, strerror(errno));
            return -1;
        }
    }

    if (file_fd != -1) {
        ssize_t r = write(file_fd, (const void *)data, (size_t)data_len);
        if (r == -1) {
            SCLogDebug("write failed: %s", strerror(errno));
        }
        close(file_fd);
    }

    if (flags & OUTPUT_FILEDATA_FLAG_CLOSE) {
        LogFilestoreLogCloseMetaFile(ff);
    }

    return 0;
}

static int LogFilestoreLogger(ThreadVars *tv, void *thread_data, const Packet *p,
        const File *ff, const uint8_t *data, uint32_t data_len, uint8_t flags)
{
    /* TODO 
     * if-else design is solely for proof of concept - consider registering new
     * FileDataModule for Redis to separate from disk file storage
     */
    if (FileStoreRedis())
    {
        return LogFilestoreLoggerRedis(tv, thread_data, p, ff, data, data_len, flags);
    }
    else
    {
        return LogFilestoreLoggerDisk(tv, thread_data, p, ff, data, data_len, flags);
    }
}

static TmEcode LogFilestoreLogThreadInit(ThreadVars *t, void *initdata, void **data)
{
    LogFilestoreLogThread *aft = SCMalloc(sizeof(LogFilestoreLogThread));
    if (unlikely(aft == NULL))
        return TM_ECODE_FAILED;
    memset(aft, 0, sizeof(LogFilestoreLogThread));

    if (initdata == NULL)
    {
        SCLogDebug("Error getting context for LogFileStore. \"initdata\" argument NULL");
        SCFree(aft);
        return TM_ECODE_FAILED;
    }

    /* Use the Ouptut Context (file pointer and mutex) */
    aft->file_ctx = ((OutputCtx *)initdata)->data;

    struct stat stat_buf;
    if (stat(g_logfile_base_dir, &stat_buf) != 0) {
        int ret;
        ret = mkdir(g_logfile_base_dir, S_IRWXU|S_IXGRP|S_IRGRP);
        if (ret != 0) {
            int err = errno;
            if (err != EEXIST) {
                SCLogError(SC_ERR_LOGDIR_CONFIG,
                        "Cannot create file drop directory %s: %s",
                        g_logfile_base_dir, strerror(err));
                exit(EXIT_FAILURE);
            }
        } else {
            SCLogInfo("Created file drop directory %s",
                    g_logfile_base_dir);
        }

    }

    /* BEGIN_PROTOTYPE */
    /* TODO Figure out best place to open connection - make redis params configurable */
    redisContext *c = redisConnect("127.0.0.1", 6379);
    if (unlikely(c == NULL))
    {
        SCLogError(SC_ERR_SOCKET, "Error opening Redis connection");
        return TM_ECODE_FAILED;
    }

    aft->redis = c;
    SCLogNotice("Redis connection successful!!");
    /* END_PROTOTYPE */

    *data = (void *)aft;
    return TM_ECODE_OK;
}

static TmEcode LogFilestoreLogThreadDeinit(ThreadVars *t, void *data)
{
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
    if (aft == NULL) {
        return TM_ECODE_OK;
    }

    /* clear memory */
    memset(aft, 0, sizeof(LogFilestoreLogThread));

    SCFree(aft);
    return TM_ECODE_OK;
}

static void LogFilestoreLogExitPrintStats(ThreadVars *tv, void *data)
{
    LogFilestoreLogThread *aft = (LogFilestoreLogThread *)data;
    if (aft == NULL) {
        return;
    }

    SCLogInfo("(%s) Files extracted %" PRIu32 "", tv->name, aft->file_cnt);
}

/**
 *  \internal
 *
 *  \brief deinit the log ctx and write out the waldo
 *
 *  \param output_ctx output context to deinit
 */
static void LogFilestoreLogDeInitCtx(OutputCtx *output_ctx)
{
    LogFileCtx *logfile_ctx = (LogFileCtx *)output_ctx->data;
    LogFileFreeCtx(logfile_ctx);
    SCFree(output_ctx);

}

/** \brief Create a new http log LogFilestoreCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFilestoreCtx* to the file_ctx if succesful
 * */
static OutputCtx *LogFilestoreLogInitCtx(ConfNode *conf)
{
    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    output_ctx->data = NULL;
    output_ctx->DeInit = LogFilestoreLogDeInitCtx;

    const char *store_redis = NULL;
    store_redis = ConfNodeLookupChildValue(conf, "store-redis");
    if (store_redis != NULL && ConfValIsTrue(store_redis))
    {
        FileStoreRedisEnable();
        SCLogInfo("storing files to redis instead of local filesystem");
    }

    char *s_default_log_dir = NULL;
    s_default_log_dir = ConfigGetLogDirectory();

    const char *s_base_dir = NULL;
    s_base_dir = ConfNodeLookupChildValue(conf, "log-dir");
    if (s_base_dir == NULL || strlen(s_base_dir) == 0) {
        strlcpy(g_logfile_base_dir,
                s_default_log_dir, sizeof(g_logfile_base_dir));
    } else {
        if (PathIsAbsolute(s_base_dir)) {
            strlcpy(g_logfile_base_dir,
                    s_base_dir, sizeof(g_logfile_base_dir));
        } else {
            snprintf(g_logfile_base_dir, sizeof(g_logfile_base_dir),
                    "%s/%s", s_default_log_dir, s_base_dir);
        }
    }

    const char *force_filestore = ConfNodeLookupChildValue(conf, "force-filestore");
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
    SCLogInfo("storing files in %s", g_logfile_base_dir);

    const char *stream_depth_str = ConfNodeLookupChildValue(conf, "stream-depth");
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

    SCReturnPtr(output_ctx, "OutputCtx");
}

void LogFilestoreRegister (void)
{
    OutputRegisterFiledataModule(LOGGER_FILE_STORE, MODULE_NAME, "file",
        LogFilestoreLogInitCtx, LogFilestoreLogger, LogFilestoreLogThreadInit,
        LogFilestoreLogThreadDeinit, LogFilestoreLogExitPrintStats);
    OutputRegisterFiledataModule(LOGGER_FILE_STORE, MODULE_NAME, "file-store",
        LogFilestoreLogInitCtx, LogFilestoreLogger, LogFilestoreLogThreadInit,
        LogFilestoreLogThreadDeinit, LogFilestoreLogExitPrintStats);

    SCLogDebug("registered");
}
