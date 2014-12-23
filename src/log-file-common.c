/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Andreas Moe <moe.andreas@gmail.com>
 */

#include <suricata-common.h>

#include "app-layer-parser.h"

#include "app-layer-htp.h"
#include "app-layer-smtp.h"

#include "util-buffer.h"
#include "util-print.h"

#include "log-file-common.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>
#endif

void LogFileMetaGetSmtpMessageID(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    SMTPState *state = (SMTPState *) p->flow->alstate;
    if (state != NULL) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, state, ff->txid);
        if (tx == NULL || tx->msg_tail == NULL) {
            MemBufferWriteString(buffer, "unknown");
            return;
        }

        /* Message Id */
        if (tx->msg_tail->msg_id != NULL) {
                PrintRawUriBuf((char *)buffer->buffer, &buffer->offset, buffer->size,
                               (uint8_t *)tx->msg_tail->msg_id, tx->msg_tail->msg_id_len);
                return;
        }
    }
    MemBufferWriteString(buffer, "unknown");
}

void LogFileMetaGetSmtpSender(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    SMTPState *state = (SMTPState *) p->flow->alstate;
    if (state != NULL) {
        SMTPTransaction *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_SMTP, state, ff->txid);
        if (tx == NULL || tx->msg_tail == NULL) {
            MemBufferWriteString(buffer, "unknown");
            return;
        }

        /* Sender */
        MimeDecField *field = MimeDecFindField(tx->msg_tail, "from");
        if (field != NULL) {
                PrintRawUriBuf((char *)buffer->buffer, &buffer->offset, buffer->size,
                               (uint8_t *) field->value, field->value_len);
                return;
        }
    }
    MemBufferWriteString(buffer, "unknown");
}

void LogFileMetaGetUri(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            HtpTxUserData *tx_ud = htp_tx_get_user_data(tx);
            if (tx_ud->request_uri_normalized != NULL) {
                PrintRawUriBuf((char *)buffer->buffer, &buffer->offset,
                               buffer->size,
                               (uint8_t *)bstr_ptr(tx_ud->request_uri_normalized),
                               bstr_len(tx_ud->request_uri_normalized));
                return;
            }
        }
    }
    MemBufferWriteString(buffer, "unknown");
}

void LogFileMetaGetHost(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL && tx->request_hostname != NULL) {
            PrintRawUriBuf((char *)buffer->buffer, &buffer->offset, buffer->size,
                           (uint8_t *)bstr_ptr(tx->request_hostname),
                           bstr_len(tx->request_hostname));
            return;
        }
    }
    MemBufferWriteString(buffer, "unknown");
}

void LogFileMetaGetReferer(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers, "Referer");
            if (h != NULL) {
                PrintRawUriBuf((char *)buffer->buffer, &buffer->offset,
                               buffer->size, (uint8_t *)bstr_ptr(h->value),
                               bstr_len(h->value));
                return;
            }
        }
    }
    MemBufferWriteString(buffer, "unkown");
}

void LogFileMetaGetUserAgent(const Packet *p, const File *ff,
    MemBuffer *buffer, uint32_t fflag)
{
    HtpState *htp_state = (HtpState *)p->flow->alstate;
    if (htp_state != NULL) {
        htp_tx_t *tx = AppLayerParserGetTx(IPPROTO_TCP, ALPROTO_HTTP, htp_state, ff->txid);
        if (tx != NULL) {
            htp_header_t *h = NULL;
            h = (htp_header_t *)htp_table_get_c(tx->request_headers, "User-Agent");
            if (h != NULL) {
                PrintRawUriBuf((char *)buffer->buffer, &buffer->offset,
                               buffer->size, (uint8_t *)bstr_ptr(h->value),
                               bstr_len(h->value));
                return;
            }
        }
    }
    MemBufferWriteString(buffer, "unkown");
}

#ifdef HAVE_LIBJANSSON
void LogFileLogPrintJsonObj(FILE *fp, json_t *js)
{
    char *js_data = json_dumps(js,
                               JSON_PRESERVE_ORDER|
                               JSON_COMPACT|
                               JSON_ENSURE_ASCII|
#ifdef JSON_ESCAPE_SLASH
                               JSON_ESCAPE_SLASH
#else
                               0
#endif
                               );
    if (js_data != NULL) {
        fprintf(fp, "%s", js_data);
    } else {
        SCLogError(SC_ERR_EMPTY_METADATA_JSON,
                   "Could not print file metadata (empty json structure)");
    }
}

int LogFileLogTransactionMeta(const Packet *p, const File *ff,
    json_t *js, MemBuffer *buffer)
{
    MemBufferReset(buffer);
    if (p->flow->alproto == ALPROTO_HTTP) {
        json_t *http = json_object();
        if (unlikely(http == NULL))
            return TM_ECODE_OK;

        LogFileMetaGetUri(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(http, "uri", json_string((char *)buffer->buffer));
        MemBufferReset(buffer);
    
        LogFileMetaGetHost(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(http, "host", json_string((char *)buffer->buffer));
        MemBufferReset(buffer);
    
        LogFileMetaGetReferer(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(http, "referer", json_string((char *)buffer->buffer));
        MemBufferReset(buffer);
    
        LogFileMetaGetUserAgent(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(http, "useragent", json_string((char *)buffer->buffer));
        MemBufferReset(buffer);
        
        json_object_set_new(js, "http", http);
    } else if (p->flow->alproto == ALPROTO_SMTP) {
        json_t *smtp = json_object();
        if (unlikely(smtp == NULL))
            return TM_ECODE_OK; 
        LogFileMetaGetSmtpMessageID(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(smtp, "message-id", json_string((char *)buffer->buffer));
        MemBufferReset(buffer);

        LogFileMetaGetSmtpSender(p, ff, buffer, META_FORMAT_JSON);
        json_object_set_new(smtp, "sender", json_string((char *)buffer->buffer));
        json_object_set_new(js, "smtp", smtp);
    }
    return TM_ECODE_OK;
}


int LogFileLogFileMeta(const Packet *p, const File *ff,
    json_t *js, MemBuffer *buffer)
{
    json_t *container = json_object();
    if (unlikely(container == NULL))
        return TM_ECODE_OK;
    MemBufferReset(buffer);
    
    PrintRawUriBuf((char *)buffer->buffer, &buffer->offset, buffer->size, ff->name, ff->name_len);
    json_object_set_new(container, "filename", json_string((char *)buffer->buffer));

    if (ff->magic == NULL) {
        json_object_set_new(container, "magic", json_string("unknown"));
    } else {
        json_object_set_new(container, "magic", json_string(ff->magic));
    }

    switch(ff->state) {
        case FILE_STATE_CLOSED:
            json_object_set_new(container, "state", json_string("closed"));
#ifdef HAVE_NSS
            if (ff->flags & FILE_MD5) {
                char md5_buffer[META_MD5_BUFFER];
                size_t x;
                for (x = 0; x < sizeof(ff->md5); x++) {
                    snprintf(md5_buffer, META_MD5_BUFFER, "%02x", ff->md5[x]);
                }
                json_object_set_new(container, "md5", json_string(md5_buffer));
            }
#endif
            break;
        case FILE_STATE_TRUNCATED:
            json_object_set_new(container, "state", json_string("truncated"));
            break;
        case FILE_STATE_ERROR:
            json_object_set_new(container, "state", json_string("error"));
            break;
        default:
            json_object_set_new(container, "state", json_string("unknown"));
            break;
    }

    MemBufferReset(buffer);
    MemBufferWriteString(buffer, "%"PRIu64"", ff->size);
    json_object_set_new(container, "size", json_string((char *)buffer->buffer));

    MemBufferReset(buffer);
    MemBufferWriteString(buffer, ff->flags & FILE_STORED ? "true" : "false");
    json_object_set_new(container, "stored", json_string((char *)buffer->buffer));
    json_object_set_new(js, "metadata", container);

    return TM_ECODE_OK;
}
#endif
