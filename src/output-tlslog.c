/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * Implements TLS JSON logging portion of the engine.
 */

#include "suricata-common.h"
#include "debug.h"
#include "detect.h"
#include "pkt-var.h"
#include "conf.h"

#include "threads.h"
#include "threadvars.h"
#include "tm-threads.h"

#include "util-print.h"
#include "util-unittest.h"

#include "util-debug.h"

#include "output.h"
#include "log-tlslog.h"
#include "app-layer-ssl.h"
#include "app-layer.h"
#include "util-privs.h"
#include "util-buffer.h"

#include "util-logopenfile.h"
#include "util-crypt.h"

#include "alert-json.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>

SC_ATOMIC_DECLARE(unsigned int, cert_id);

#define MODULE_NAME "LogTlsLog"

#define LOG_TLS_DEFAULT     0
#define LOG_TLS_EXTENDED    (1 << 0)

typedef struct OutputTlsCtx_ {
    uint32_t flags; /** Store mode */
} OutputTlsCtx;

#define SSL_VERSION_LENGTH 13

static void LogTlsLogExtendedJSON(json_t *tjs, SSLState * state)
{
    char ssl_version[SSL_VERSION_LENGTH + 1];

    /* tls.fingerprint */
    json_object_set_new(tjs, "fingerprint",
                        json_string(state->server_connp.cert0_fingerprint));
    
    /* tls.version */
    switch (state->server_connp.version) {
        case TLS_VERSION_UNKNOWN:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "UNDETERMINED");
            break;
        case SSL_VERSION_2:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "SSLv2");
            break;
        case SSL_VERSION_3:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "SSLv3");
            break;
        case TLS_VERSION_10:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLSv1");
            break;
        case TLS_VERSION_11:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLS 1.1");
            break;
        case TLS_VERSION_12:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "TLS 1.2");
            break;
        default:
            snprintf(ssl_version, SSL_VERSION_LENGTH, "0x%04x",
                     state->server_connp.version);
            break;
    }
    json_object_set_new(tjs, "version", json_string(ssl_version));

}


static TmEcode LogTlsLogIPWrapperJSON(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();
    AlertJsonThread *aft = (AlertJsonThread *)data;
    MemBuffer *buffer = (MemBuffer *)aft->buffer;
    OutputTlsCtx *tls_ctx = aft->tls_ctx->data;

    /* no flow, no tls state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    /* check if we have TLS state or not */
    FLOWLOCK_WRLOCK(p->flow);
    uint16_t proto = AppLayerGetProtoFromPacket(p);
    if (proto != ALPROTO_TLS)
        goto end;

    SSLState *ssl_state = (SSLState *) AppLayerGetProtoStateFromPacket(p);
    if (ssl_state == NULL) {
        SCLogDebug("no tls state, so no request logging");
        goto end;
    }

    if (ssl_state->server_connp.cert0_issuerdn == NULL || ssl_state->server_connp.cert0_subject == NULL)
        goto end;

    if (AppLayerTransactionGetLogId(p->flow) != 0)
        goto end;

    json_t *js = CreateJSONHeader(p, 0);
    if (unlikely(js == NULL))
        goto end;

    json_t *tjs = json_object();
    if (tjs == NULL) {
        free(js);
        goto end;
    }

    /* reset */
    MemBufferReset(buffer);

    /* tls.subject */ 
    json_object_set_new(tjs, "subject",
                        json_string(ssl_state->server_connp.cert0_subject));

    /* tls.issuerdn */
    json_object_set_new(tjs, "issuerdn",
                        json_string(ssl_state->server_connp.cert0_issuerdn));

    if (tls_ctx->flags & LOG_TLS_EXTENDED) {
        LogTlsLogExtendedJSON(tjs, ssl_state);
    }

    json_object_set_new(js, "tls", tjs);

    OutputJSON(js, aft, &aft->tls_cnt);
    json_object_clear(js);
    json_decref(js);

end:
    FLOWLOCK_UNLOCK(p->flow);
    SCReturnInt(TM_ECODE_OK);

}

TmEcode OutputTlsLog(ThreadVars *tv, Packet *p, void *data, PacketQueue *pq, PacketQueue *postpq)
{
    SCEnter();

    /* no flow, no htp state */
    if (p->flow == NULL) {
        SCReturnInt(TM_ECODE_OK);
    }

    if (!(PKT_IS_TCP(p))) {
        SCReturnInt(TM_ECODE_OK);
    }

    LogTlsLogIPWrapperJSON(tv, p, data, pq, postpq);

    SCReturnInt(TM_ECODE_OK);
}

OutputCtx *OutputTlsLogInit(ConfNode *conf)
{
    OutputTlsCtx *tls_ctx = SCMalloc(sizeof(OutputTlsCtx));
    if (unlikely(tls_ctx == NULL))
        return NULL;

    OutputCtx *output_ctx = SCCalloc(1, sizeof(OutputCtx));
    if (unlikely(output_ctx == NULL))
        return NULL;

    tls_ctx->flags = LOG_TLS_DEFAULT;
    if (conf) {
        const char *extended = ConfNodeLookupChildValue(conf, "extended");

        if (extended != NULL) {
            if (ConfValIsTrue(extended)) {
                tls_ctx->flags = LOG_TLS_EXTENDED;
            }
        }
    }
    output_ctx->data = tls_ctx;
    output_ctx->DeInit = NULL;

    return output_ctx;
}
#endif
