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


/**
 * \brief A direct flick off libhtp-0.5.x htp_is_lws().
 */
static int SC_htp_is_lws(int c)
{
    if ((c == ' ') || (c == '\t')) return 1;
    else return 0;
}

/**
 * \brief A direct flick off libhtp-0.5.x htp_parse_positive_integer_whitespace().
 */
static int64_t SC_htp_parse_positive_integer_whitespace(unsigned char *data, size_t len, int base)
{
    if (len == 0) return -1003;

    size_t last_pos;
    size_t pos = 0;

    // Ignore LWS before
    while ((pos < len) && (SC_htp_is_lws(data[pos]))) pos++;
    if (pos == len) return -1001;

    int64_t r = bstr_util_mem_to_pint(data + pos, len - pos, base, &last_pos);
    if (r < 0) return r;

    // Move after the last digit
    pos += last_pos;

    // Ignore LWS after
    while (pos < len) {
        if (!SC_htp_is_lws(data[pos])) {
            return -1002;
        }

        pos++;
    }

    return r;
}

/**
 * \brief A direct flick off libhtp-0.5.x htp_parse_content_length()
 */
int64_t SC_htp_parse_content_length(bstr *b)
{
    return SC_htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(b), bstr_len(b), 10);
}

/**
 * \brief Generates the normalized uri.
 *
 *        Libhtp doesn't recreate the whole normalized uri and save it.
 *        That duty has now been passed to us.  A lot of this code has been
 *        copied from libhtp.
 *
 *        Keep an eye out on the tx->parsed_uri struct and how the parameters
 *        in it are generated, just in case some modifications are made to
 *        them in the future.
 *
 * \param uri_include_all boolean to indicate if scheme, username/password,
                          hostname and port should be part of the buffer
 */
bstr *SCHTPGenerateNormalizedUri(htp_tx_t *tx, htp_uri_t *uri, int uri_include_all)
{
    if (uri == NULL)
        return NULL;

    // On the first pass determine the length of the final string
    size_t len = 0;

    if (uri_include_all) {
        if (uri->scheme != NULL) {
            len += bstr_len(uri->scheme);
            len += 3; // "://"
        }

        if ((uri->username != NULL) || (uri->password != NULL)) {
            if (uri->username != NULL) {
                len += bstr_len(uri->username);
            }

            len += 1; // ":"

            if (uri->password != NULL) {
                len += bstr_len(uri->password);
            }

            len += 1; // "@"
        }

        if (uri->hostname != NULL) {
            len += bstr_len(uri->hostname);
        }

        if (uri->port != NULL) {
            len += 1; // ":"
            len += bstr_len(uri->port);
        }
    }

    if (uri->path != NULL) {
        len += bstr_len(uri->path);
    }

    if (uri->query != NULL) {
        len += 1; // "?"
        len += bstr_len(uri->query);
    }

    if (uri->fragment != NULL) {
        len += 1; // "#"
        len += bstr_len(uri->fragment);
    }

    // On the second pass construct the string
    /* FIXME in memcap */
    bstr *r = bstr_alloc(len);
    if (r == NULL) {
        return NULL;
    }

    if (uri_include_all) {
        if (uri->scheme != NULL) {
            bstr_add_noex(r, uri->scheme);
            bstr_add_c_noex(r, "://");
        }

        if ((uri->username != NULL) || (uri->password != NULL)) {
            if (uri->username != NULL) {
                bstr_add_noex(r, uri->username);
            }

            bstr_add_c(r, ":");

            if (uri->password != NULL) {
                bstr_add_noex(r, uri->password);
            }

            bstr_add_c_noex(r, "@");
        }

        if (uri->hostname != NULL) {
            bstr_add_noex(r, uri->hostname);
        }

        if (uri->port != NULL) {
            bstr_add_c(r, ":");
            bstr_add_noex(r, uri->port);
        }
    }

    if (uri->path != NULL) {
        bstr_add_noex(r, uri->path);
    }

    if (uri->query != NULL) {
        bstr *query = bstr_dup(uri->query);
        if (query) {
            uint64_t flags = 0;
            htp_urldecode_inplace(tx->cfg, HTP_DECODER_URLENCODED, query, &flags);
            bstr_add_c_noex(r, "?");
            bstr_add_noex(r, query);
            bstr_free(query);
        }
    }

    if (uri->fragment != NULL) {
        bstr_add_c_noex(r, "#");
        bstr_add_noex(r, uri->fragment);
    }

    return r;
}
