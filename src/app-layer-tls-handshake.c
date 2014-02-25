/*
 * Copyright (C) 2011-2012 ANSSI
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL
 * THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * \author Pierre Chifflier <pierre.chifflier@ssi.gouv.fr>
 *
 * \brief Decode TLS Handshake messages, as described in RFC2246
 *
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"

#include "app-layer-parser.h"
#include "decode-events.h"

#include "app-layer-ssl.h"

#include "app-layer-tls-handshake.h"

#include <stdint.h>

#include "util-decode-der.h"
#include "util-decode-der-get.h"

#include "util-crypt.h"

#define SSLV3_RECORD_LEN 5

static void TLSCertificateErrCodeToWarning(SSLState *ssl_state, uint32_t errcode)
{
    if (errcode == 0)
        return;

    switch (errcode) {
        case ERR_DER_ELEMENT_SIZE_TOO_BIG:
        case ERR_DER_INVALID_SIZE:
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_CERTIFICATE_INVALID_LENGTH);
            break;
        case ERR_DER_UNSUPPORTED_STRING:
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_CERTIFICATE_INVALID_STRING);
            break;
        case ERR_DER_UNKNOWN_ELEMENT:
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_CERTIFICATE_UNKNOWN_ELEMENT);
            break;
        case ERR_DER_MISSING_ELEMENT:
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_CERTIFICATE_MISSING_ELEMENT);
            break;
        case ERR_DER_GENERIC:
        default:
            AppLayerDecoderEventsSetEvent(ssl_state->f,
                    TLS_DECODER_EVENT_INVALID_CERTIFICATE);
            break;
    };
}

int DecodeTLSHandshakeServerCertificate(SSLState *ssl_state, uint8_t *input, uint32_t input_len)
{
    uint32_t certificates_length, cur_cert_length;
    int i;
    Asn1Generic *cert;
    char buffer[256];
    int rc;
    int parsed;
    uint8_t *start_data;
    uint32_t errcode = 0;

    if (input_len < 3)
        return 1;

    certificates_length = input[0]<<16 | input[1]<<8 | input[2];
    /* check if the message is complete */
    if (input_len < certificates_length + 3)
        return 0;

    start_data = input;
    input += 3;
    parsed = 3;

    i = 0;
    while (certificates_length > 0) {
        cur_cert_length = input[0]<<16 | input[1]<<8 | input[2];
        input += 3;
        parsed += 3;

        if (input - start_data + cur_cert_length > input_len) {
            AppLayerDecoderEventsSetEvent(ssl_state->f, TLS_DECODER_EVENT_INVALID_CERTIFICATE);
            return -1;
        }
        cert = DecodeDer(input, cur_cert_length, &errcode);
        if (cert == NULL) {
            TLSCertificateErrCodeToWarning(ssl_state, errcode);
        }
        if (cert != NULL) {
            rc = Asn1DerGetSubjectDN(cert, buffer, sizeof(buffer), &errcode);
            if (rc != 0) {
                TLSCertificateErrCodeToWarning(ssl_state, errcode);
            } else {
                SSLCertsChain *ncert;
                //SCLogInfo("TLS Cert %d: %s\n", i, buffer);
                if (i == 0) {
                    if (ssl_state->server_connp.cert0_subject == NULL)
                        ssl_state->server_connp.cert0_subject = SCStrdup(buffer);
                    if (ssl_state->server_connp.cert0_subject == NULL) {
                        DerFree(cert);
                        return -1;
                    }
                }
                ncert = (SSLCertsChain *)SCMalloc(sizeof(SSLCertsChain));
                if (ncert == NULL) {
                    DerFree(cert);
                    return -1;
                }
                memset(ncert, 0, sizeof(*ncert));
                ncert->cert_data = input;
                ncert->cert_len = cur_cert_length;
                TAILQ_INSERT_TAIL(&ssl_state->server_connp.certs, ncert, next);
            }
            rc = Asn1DerGetIssuerDN(cert, buffer, sizeof(buffer), &errcode);
            if (rc != 0) {
                TLSCertificateErrCodeToWarning(ssl_state, errcode);
            } else {
                //SCLogInfo("TLS IssuerDN %d: %s\n", i, buffer);
                if (i == 0) {
                    if (ssl_state->server_connp.cert0_issuerdn == NULL)
                        ssl_state->server_connp.cert0_issuerdn = SCStrdup(buffer);
                    if (ssl_state->server_connp.cert0_issuerdn == NULL) {
                        DerFree(cert);
                        return -1;
                    }
                }
            }
            DerFree(cert);

            if (i == 0 && ssl_state->server_connp.cert0_fingerprint == NULL) {
                int msg_len = cur_cert_length;
                int hash_len = 20;
                int out_len = 60;
                char out[out_len];
                unsigned char *hash;
                hash = ComputeSHA1((unsigned char *) input, (int) msg_len);
                char *p = out;
                int j = 0;

                if (hash == NULL) {
                    SCLogWarning(SC_ERR_MEM_ALLOC, "Can not allocate fingerprint string");
                } else {
                    for (j = 0; j < hash_len; j++, p += 3) {
                        snprintf(p, 4, j == hash_len - 1 ? "%02x" : "%02x:", hash[j]);
                    }
                    SCFree(hash);
                    ssl_state->server_connp.cert0_fingerprint = SCStrdup(out);
                    if (ssl_state->server_connp.cert0_fingerprint == NULL) {
                        SCLogWarning(SC_ERR_MEM_ALLOC, "Can not allocate fingerprint string");
                    }
                }

                ssl_state->server_connp.cert_input = input;
                ssl_state->server_connp.cert_input_len = cur_cert_length;
            }

        }

        i++;
        certificates_length -= (cur_cert_length + 3);
        parsed += cur_cert_length;
        input += cur_cert_length;
    }

    return parsed;

}

