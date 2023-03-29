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
 */

#ifndef __OUTPUT_JSON_TLS_H__
#define __OUTPUT_JSON_TLS_H__

#include "output-json.h"
#include "util-logopenfile.h"
#include "util-buffer.h"

#define LOG_TLS_DEFAULT                 0
#define LOG_TLS_EXTENDED                (1 << 0)
#define LOG_TLS_CUSTOM                  (1 << 1)
#define LOG_TLS_SESSION_RESUMPTION      (1 << 2)

#define LOG_TLS_FIELD_VERSION           (1 << 0)
#define LOG_TLS_FIELD_SUBJECT           (1 << 1)
#define LOG_TLS_FIELD_ISSUER            (1 << 2)
#define LOG_TLS_FIELD_SERIAL            (1 << 3)
#define LOG_TLS_FIELD_FINGERPRINT       (1 << 4)
#define LOG_TLS_FIELD_NOTBEFORE         (1 << 5)
#define LOG_TLS_FIELD_NOTAFTER          (1 << 6)
#define LOG_TLS_FIELD_SNI               (1 << 7)
#define LOG_TLS_FIELD_CERTIFICATE       (1 << 8)
#define LOG_TLS_FIELD_CHAIN             (1 << 9)
#define LOG_TLS_FIELD_SESSION_RESUMED   (1 << 10)
#define LOG_TLS_FIELD_JA3               (1 << 11)
#define LOG_TLS_FIELD_JA3S              (1 << 12)
#define LOG_TLS_FIELD_CLIENT            (1 << 13) /**< client fields (issuer, subject, etc) */
#define LOG_TLS_FIELD_CLIENT_CERT       (1 << 14)
#define LOG_TLS_FIELD_CLIENT_CHAIN      (1 << 15)

typedef struct {
    const char *name;
    uint64_t flag;
} TlsFields;

typedef struct OutputTlsCtx_ {
    uint32_t flags;  /** Store mode */
    uint64_t fields; /** Store fields */
    OutputJsonCtx *eve_ctx;
} OutputTlsCtx;


typedef struct JsonTlsLogThread_ {
    OutputTlsCtx *tlslog_ctx;
    OutputJsonThreadCtx *ctx;
} JsonTlsLogThread;

void JsonTlsLogRegister(void);

#include "app-layer-ssl.h"

void JsonTlsLogJSONBasic(JsonBuilder *js, SSLState *ssl_state);
void JsonTlsLogJSONExtended(JsonBuilder *js, SSLState *ssl_state);
void JsonTlsLogJSONCustom(OutputTlsCtx *tls_ctx, JsonBuilder *js, SSLState *ssl_state);
OutputTlsCtx *OutputTlsInitCtx(ConfNode *conf);
#endif /* __OUTPUT_JSON_TLS_H__ */
