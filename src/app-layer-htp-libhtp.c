/*
 * We are using this file to hold APIs copied from libhtp 0.5.x.
 */

/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#include "suricata.h"
#include "suricata-common.h"
#include "app-layer-htp-libhtp.h"

/**
 * \brief Generates the normalized uri.
 *
 *        Libhtp doesn't recreate the whole normalized uri and save it.
 *        That duty has now been passed to us.  A lot of this code has been
 *        copied from libhtp.
 *
 *        Keep an eye out on the htp_tx_parsed_uri(tx) struct and how the parameters
 *        in it are generated, just in case some modifications are made to
 *        them in the future.
 *
 * \param uri_include_all boolean to indicate if scheme, username/password,
                          hostname and port should be part of the buffer
 */
bstr *SCHTPGenerateNormalizedUri(htp_tx_t *tx, const htp_uri_t *uri, int uri_include_all)
{
    if (uri == NULL)
        return NULL;

    // On the first pass determine the length of the final string
    size_t len = 0;

    if (uri_include_all) {
        if (htp_uri_scheme(uri) != NULL) {
            len += bstr_len(htp_uri_scheme(uri));
            len += 3; // "://"
        }

        if ((htp_uri_username(uri) != NULL) || (htp_uri_password(uri) != NULL)) {
            if (htp_uri_username(uri) != NULL) {
                len += bstr_len(htp_uri_username(uri));
            }

            len += 1; // ":"

            if (htp_uri_password(uri) != NULL) {
                len += bstr_len(htp_uri_password(uri));
            }

            len += 1; // "@"
        }

        if (htp_uri_hostname(uri) != NULL) {
            len += bstr_len(htp_uri_hostname(uri));
        }

        if (htp_uri_port(uri) != NULL) {
            len += 1; // ":"
            len += bstr_len(htp_uri_port(uri));
        }
    }

    if (htp_uri_path(uri) != NULL) {
        len += bstr_len(htp_uri_path(uri));
    }

    if (htp_uri_query(uri) != NULL) {
        len += 1; // "?"
        len += bstr_len(htp_uri_query(uri));
    }

    if (htp_uri_fragment(uri) != NULL) {
        len += 1; // "#"
        len += bstr_len(htp_uri_fragment(uri));
    }

    // On the second pass construct the string
    /* FIXME in memcap */
    bstr *r = bstr_alloc(len);
    if (r == NULL) {
        return NULL;
    }

    if (uri_include_all) {
        if (htp_uri_scheme(uri) != NULL) {
            bstr_add_noex(r, htp_uri_scheme(uri));
            bstr_add_c_noex(r, "://");
        }

        if ((htp_uri_username(uri) != NULL) || (htp_uri_password(uri) != NULL)) {
            if (htp_uri_username(uri) != NULL) {
                bstr_add_noex(r, htp_uri_username(uri));
            }

            bstr_add_c_noex(r, ":");

            if (htp_uri_password(uri) != NULL) {
                bstr_add_noex(r, htp_uri_password(uri));
            }

            bstr_add_c_noex(r, "@");
        }

        if (htp_uri_hostname(uri) != NULL) {
            bstr_add_noex(r, htp_uri_hostname(uri));
        }

        if (htp_uri_port(uri) != NULL) {
            bstr_add_c_noex(r, ":");
            bstr_add_noex(r, htp_uri_port(uri));
        }
    }

    if (htp_uri_path(uri) != NULL) {
        bstr_add_noex(r, htp_uri_path(uri));
    }

    if (htp_uri_query(uri) != NULL) {
        bstr *query = bstr_dup(htp_uri_query(uri));
        if (query) {
            uint64_t flags = 0;
            htp_urldecode_inplace(htp_tx_cfg(tx), HTP_DECODER_URLENCODED, query, &flags);
            bstr_add_c_noex(r, "?");
            bstr_add_noex(r, query);
            bstr_free(query);
        }
    }

    if (htp_uri_fragment(uri) != NULL) {
        bstr_add_c_noex(r, "#");
        bstr_add_noex(r, htp_uri_fragment(uri));
    }

    return r;
}
