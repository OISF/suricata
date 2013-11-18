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

#include "output.h"
#include "output-json.h"

#include "log-file.h"
#include "util-logopenfile.h"

#include "app-layer-htp.h"
#include "util-memcmp.h"
#include "stream-tcp-reassemble.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

typedef struct OutputFileCtx_ {
    uint32_t file_cnt;
} OutputFileCtx;

static json_t *LogFileMetaGetUri(Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud->request_uri_normalized != NULL) {
                char *s = SCStrndup((char *) bstr_ptr(tx_ud->request_uri_normalized),
                                    bstr_len(tx_ud->request_uri_normalized));
                js = json_string(s);
                if (s != NULL)
                    SCFree(s);
            }
            return js;
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetHost(Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            char *s = SCStrndup((char *) bstr_ptr(tx->request_hostname),
                                bstr_len(tx->request_hostname));
            js = json_string(s);
            if (s != NULL)
                SCFree(s);
            return js;
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetReferer(Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "Referer");
            if (h != NULL) {
                char *s = SCStrndup((char *)bstr_ptr(h->value),
                                    bstr_len(h->value));
                js = json_string(s);
                if (s != NULL)
                    SCFree(s);
                return js;
            }
        }
    }

    return json_string("<unknown>");
}

static json_t *LogFileMetaGetUserAgent(Packet *p, File *ff) {
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    json_t *js = NULL;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerGetTx(ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers,
                                                "User-Agent");
            if (h != NULL) {
                char *s = SCStrndup((char *)bstr_ptr(h->value),
                                    bstr_len(h->value));
                js = json_string(s);
                if (s != NULL)
                    SCFree(s);
                return js;
            }
        }
    }

    return json_string("<unknown>");
}

/**
 *  \internal
 *  \brief Write meta data on a single line json record
 */
static void LogFileWriteJsonRecord(AlertJsonThread /*LogFileLogThread*/ *aft, Packet *p, File *ff, int ipver) {
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    json_t *js = CreateJSONHeader(p, 0);
    if (unlikely(js == NULL))
        return;

    /* reset */
    MemBufferReset(buffer);

    json_t *fjs = json_object();
    if (unlikely(fjs == NULL)) {
        json_decref(js);
        return;
    }

    json_object_set_new(fjs, "http_uri", LogFileMetaGetUri(p, ff));
    json_object_set_new(fjs, "http_host", LogFileMetaGetHost(p, ff));
    json_object_set_new(fjs, "http_referer", LogFileMetaGetReferer(p, ff));
    json_object_set_new(fjs, "http_user_agent", LogFileMetaGetUserAgent(p, ff));
    char *s = SCStrndup((char *)ff->name, ff->name_len);
    json_object_set_new(fjs, "filename", json_string(s));
    if (s != NULL)
        SCFree(s);
    if (ff->magic)
        json_object_set_new(fjs, "magic", json_string((char *)ff->magic));
    else
        json_object_set_new(fjs, "magic", json_string("unknown"));
    switch (ff->state) {
        case FILE_STATE_CLOSED:
            json_object_set_new(fjs, "state", json_string("CLOSED"));
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                size_t x;
                int i;
                char *s = SCMalloc(256);
                if (likely(s != NULL)) {
                    for (i = 0, x = 0; x < sizeof(ff->md5); x++) {
                        i += snprintf(&s[i], 255-i, "%02x", ff->md5[x]);
                    }
                    json_object_set_new(fjs, "md5", json_string(s));
                    SCFree(s);
                }
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            json_object_set_new(fjs, "state", json_string("TRUNCATED"));
            break;
        case FILE_STATE_ERROR:
            json_object_set_new(fjs, "state", json_string("ERROR"));
            break;
        default:
            json_object_set_new(fjs, "state", json_string("UNKNOWN"));
            break;
    }
    json_object_set_new(fjs, "stored",
                        (ff->flags & FILE_STORED) ? json_true() : json_false());
    json_object_set_new(fjs, "size", json_integer(ff->size));

    json_object_set_new(js, "file", fjs);
    OutputJSON(js, aft, &aft->files_cnt);
    json_object_del(js, "file");

    json_object_clear(js);
    json_decref(js);
}

static TmEcode OutputFileLogWrap(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq, int ipver)
{
    SCEnter();
    AlertJsonThread *aft = (AlertJsonThread *)data;
    uint8_t flags = 0;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (p->flowflags & FLOW_PKT_TOCLIENT)
        flags |= STREAM_TOCLIENT;
    else
        flags |= STREAM_TOSERVER;

    int file_close = (p->flags & PKT_PSEUDO_STREAM_END) ? 1 : 0;
    int file_trunc = 0;

    FLOWLOCK_WRLOCK(p->flow);
    file_trunc = StreamTcpReassembleDepthReached(p);

    FileContainer *ffc = AppLayerGetFilesFromFlow(p->flow, flags);
    SCLogDebug("ffc %p", ffc);
    if (ffc != NULL) {
        File *ff;
        for (ff = ffc->head; ff != NULL; ff = ff->next) {
            if (ff->flags & FILE_LOGGED)
                continue;

            if (FileForceMagic() && ff->magic == NULL) {
                FilemagicGlobalLookup(ff);
            }

            SCLogDebug("ff %p", ff);

            if (file_trunc && ff->state < FILE_STATE_CLOSED)
                ff->state = FILE_STATE_TRUNCATED;

            if (ff->state == FILE_STATE_CLOSED ||
                    ff->state == FILE_STATE_TRUNCATED || ff->state == FILE_STATE_ERROR ||
                    (file_close == 1 && ff->state < FILE_STATE_CLOSED))
            {
                LogFileWriteJsonRecord(aft, p, ff, ipver);

                ff->flags |= FILE_LOGGED;
            }
        }

        FilePrune(ffc);
    }

    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);
}

TmEcode OutputFileLogIPv4(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return OutputFileLogWrap(tv, p, data, NULL, NULL, AF_INET);
}

TmEcode OutputFileLogIPv6(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq) {
    return OutputFileLogWrap(tv, p, data, NULL, NULL, AF_INET6);
}

TmEcode OutputFileLog (ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    int r = TM_ECODE_OK;

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    SCLogDebug("p->pcap_cnt %"PRIu64, p->pcap_cnt);

    if (PKT_IS_IPV4(p)) {
        r = OutputFileLogIPv4(tv, p, data, pq, postpq);
    } else if (PKT_IS_IPV6(p)) {
        r = OutputFileLogIPv6(tv, p, data, pq, postpq);
    }

    SCReturnInt(r);
}

/** \brief Create a new http log LogFileCtx.
 *  \param conf Pointer to ConfNode containing this loggers configuration.
 *  \return NULL if failure, LogFileCtx* to the file_ctx if succesful
 * */
OutputCtx *OutputFileLogInit(ConfNode *conf)
{
    OutputFileCtx *file_ctx = SCMalloc(sizeof(OutputFileCtx));
    if (unlikely(file_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL)) {
        SCFree(file_ctx);
        return NULL;
    }

    if (conf) {
        const char *force_magic = ConfNodeLookupChildValue(conf, "force-magic");
        if (force_magic != NULL && ConfValIsTrue(force_magic)) {
            FileForceMagicEnable();
            SCLogInfo("forcing magic lookup for logged files");
        }

        const char *force_md5 = ConfNodeLookupChildValue(conf, "force-md5");
        if (force_md5 != NULL && ConfValIsTrue(force_md5)) {
#ifdef HAVE_NSS
            FileForceMd5Enable();
            SCLogInfo("forcing md5 calculation for logged files");
#else
            SCLogInfo("md5 calculation requires linking against libnss");
#endif
        }
    }

    FileForceTrackingEnable();
    return output_ctx;
}

#endif
