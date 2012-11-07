/*
 * LibHTP (http://www.libhtp.org)
 * Copyright 2009,2010 Ivan Ristic <ivanr@webkreator.com>
 *
 * LibHTP is an open source product, released under terms of the General Public Licence
 * version 2 (GPLv2). Please refer to the file LICENSE, which contains the complete text
 * of the license.
 *
 * In addition, there is a special exception that allows LibHTP to be freely
 * used with any OSI-approved open source licence. Please refer to the file
 * LIBHTP_LICENSING_EXCEPTION for the full text of the exception.
 *
 */

#include "htp.h"

/**
 * Extract one request header. A header can span multiple lines, in
 * which case they will be folded into one before parsing is attempted.
 *
 * @param connp
 * @return HTP_OK or HTP_ERROR
 */
int htp_process_request_header_apache_2_2(htp_connp_t *connp) {
    bstr *tempstr = NULL;
    unsigned char *data = NULL;
    size_t len = 0;

    // Create new header structure
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    // Ensure we have the necessary header data in a single buffer
    if (connp->in_header_line_index + 1 == connp->in_header_line_counter) {
        // Single line
        htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines,
            connp->in_header_line_index);
        if (hl == NULL) {
            // Internal error
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                "Process request header (Apache 2.2): Internal error");
            free(h);
            return HTP_ERROR;
        }

        data = (unsigned char *) bstr_ptr(hl->line);
        len = bstr_len(hl->line);
        hl->header = h;
    } else {
        // Multiple lines (folded)
        int i = 0;

        for (i = connp->in_header_line_index; i < connp->in_header_line_counter; i++) {
            htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines, i);
            if (hl == NULL) {
                // Internal error
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                        "Process request header (Apache 2.2): Internal error");
                free(h);
                return HTP_ERROR;
            }
            len += bstr_len(hl->line);
        }

        tempstr = bstr_alloc(len);
        if (tempstr == NULL) {
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                "Process request header (Apache 2.2): Failed to allocate bstring of %d bytes", len);
            free(h);
            return HTP_ERROR;
        }

        for (i = connp->in_header_line_index; i < connp->in_header_line_counter; i++) {
            htp_header_line_t *hl = list_get(connp->in_tx->request_header_lines, i);
            if (hl == NULL) {
                // Internal error
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0,
                        "Process request header (Apache 2.2): Internal error");
                bstr_free(tempstr);
                free(h);
                return HTP_ERROR;
            }
            char *data = bstr_ptr(hl->line);
            size_t len = bstr_len(hl->line);
            htp_chomp((unsigned char *)data, &len);
            bstr_add_mem_noex(tempstr, data, len);
            hl->header = h;
        }

        data = (unsigned char *) bstr_ptr(tempstr);
    }

    // Now try to parse the header
    if (htp_parse_request_header_apache_2_2(connp, h, data, len) != HTP_OK) {
        // Note: downstream responsible for error logging
        if (tempstr != NULL) {
            free(tempstr);
        }
        free(h);
        return HTP_ERROR;
    }

    // Do we already have a header with the same name?
    htp_header_t *h_existing = table_get(connp->in_tx->request_headers, h->name);
    if (h_existing != NULL) {
        // TODO Do we want to keep a list of the headers that are
        //      allowed to be combined in this way?

        // Add to existing header
        h_existing->value = bstr_expand(h_existing->value, bstr_len(h_existing->value)
            + 2 + bstr_len(h->value));
        bstr_add_mem_noex(h_existing->value, ", ", 2);
        bstr_add_str_noex(h_existing->value, h->value);

        // The header is no longer needed
        if (h->name != NULL)
            free(h->name);
        if (h->value != NULL)
            free(h->value);
        free(h);

        // Keep track of same-name headers        
        h_existing->flags |= HTP_FIELD_REPEATED;
    } else {
        // Add as a new header
        table_add(connp->in_tx->request_headers, h->name, h);
    }

    if (tempstr != NULL) {
        free(tempstr);
    }

    return HTP_OK;
}

/**
 * Parses a message header line as Apache 2.2 does.
 *
 * @param connp
 * @param h
 * @param data
 * @param len
 * @return HTP_OK or HTP_ERROR
 */
int htp_parse_request_header_apache_2_2(htp_connp_t *connp, htp_header_t *h, unsigned char *data, size_t len) {
    size_t name_start, name_end;
    size_t value_start, value_end;

    htp_chomp(data, &len);

    name_start = 0;

    // Look for the colon
    size_t colon_pos = 0;
    while ((colon_pos < len) && (data[colon_pos] != '\0') && (data[colon_pos] != ':')) colon_pos++;

    if ((colon_pos == len) || (data[colon_pos] == '\0')) {
        // Missing colon
        h->flags |= HTP_FIELD_UNPARSEABLE;

        if (!(connp->in_tx->flags & HTP_FIELD_UNPARSEABLE)) {
            connp->in_tx->flags |= HTP_FIELD_UNPARSEABLE;
            // Only log once per transaction
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request field invalid: colon missing");
        }

        return HTP_ERROR;
    }

    if (colon_pos == 0) {
        // Empty header name
        h->flags |= HTP_FIELD_INVALID;

        if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
            connp->in_tx->flags |= HTP_FIELD_INVALID;
            // Only log once per transaction
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request field invalid: empty name");
        }
    }

    name_end = colon_pos;

    // Ignore LWS after field-name
    size_t prev = name_end - 1;
    while ((prev > name_start) && (htp_is_lws(data[prev]))) {
        prev--;
        name_end--;

        h->flags |= HTP_FIELD_INVALID;

        if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
            connp->in_tx->flags |= HTP_FIELD_INVALID;
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request field invalid: LWS after name");
        }
    }

    // Value

    value_start = colon_pos;

    // Go over the colon
    if (value_start < len) {
        value_start++;
    }

    // Ignore LWS before field-content
    while ((value_start < len) && (htp_is_lws(data[value_start]))) {
        value_start++;
    }

    // Look for the end of field-content
    value_end = value_start;
    while ((value_end < len) && (data[value_end] != '\0')) value_end++;

    // Ignore LWS after field-content
    prev = value_end - 1;
    while ((prev > value_start) && (htp_is_lws(data[prev]))) {
        prev--;
        value_end--;
    }

    // Check that the header name is a token
    size_t i = name_start;
    while (i < name_end) {
        if (!htp_is_token(data[i])) {
            h->flags |= HTP_FIELD_INVALID;

            if (!(connp->in_tx->flags & HTP_FIELD_INVALID)) {
                connp->in_tx->flags |= HTP_FIELD_INVALID;
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_WARNING, 0, "Request header name is not a token");
            }

            break;
        }

        i++;
    }

    // Now extract the name and the value
    h->name = bstr_memdup((char *) data + name_start, name_end - name_start);
    if (h->name == NULL)
        return HTP_ERROR;
    h->value = bstr_memdup((char *) data + value_start, value_end - value_start);
    if (h->value == NULL) {
        bstr_free(h->name);
        return HTP_ERROR;
    }

    return HTP_OK;
}

/**
 * Parse request line as Apache 2.2 does.
 *
 * @param connp
 * @return HTP_OK or HTP_ERROR
 */
int htp_parse_request_line_apache_2_2(htp_connp_t *connp) {
    htp_tx_t *tx = connp->in_tx;
    unsigned char *data = (unsigned char *) bstr_ptr(tx->request_line);
    size_t len = bstr_len(tx->request_line);
    size_t pos = 0;

    // In this implementation we assume the
    // line ends with the first NUL byte.
    if (tx->request_line_nul_offset != -1) {
        len = tx->request_line_nul_offset - 1;
    }

    // The request method starts at the beginning of the
    // line and ends with the first whitespace character.
    while ((pos < len) && (!htp_is_space(data[pos]))) {
        pos++;
    }

    // No, we don't care if the method is empty.

    tx->request_method = bstr_memdup((char *) data, pos);
    if (tx->request_method == NULL) {
        return HTP_ERROR;
    }

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_method), bstr_len(tx->request_method));
#endif

    tx->request_method_number = htp_convert_method_to_number(tx->request_method);

    // Ignore whitespace after request method. The RFC allows
    // for only one SP, but then suggests any number of SP and HT
    // should be permitted. Apache uses isspace(), which is even
    // more permitting, so that's what we use here.
    while ((pos < len) && (isspace(data[pos]))) {
        pos++;
    }

    size_t start = pos;

    // The URI ends with the first whitespace.
    while ((pos < len) && (!htp_is_space(data[pos]))) {
        pos++;
    }

    tx->request_uri = bstr_memdup((char *) data + start, pos - start);
    if (tx->request_uri == NULL) {
        return HTP_ERROR;
    }

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_uri), bstr_len(tx->request_uri));
#endif

    // Ignore whitespace after URI
    while ((pos < len) && (htp_is_space(data[pos]))) {
        pos++;
    }

    // Is there protocol information available?
    if (pos == len) {
        // No, this looks like a HTTP/0.9 request.
        tx->protocol_is_simple = 1;
        return HTP_OK;
    }

    // The protocol information spreads until the end of the line.
    tx->request_protocol = bstr_memdup((char *) data + pos, len - pos);
    if (tx->request_protocol == NULL)
        return HTP_ERROR;
    tx->request_protocol_number = htp_parse_protocol(tx->request_protocol);

#ifdef HTP_DEBUG
    fprint_raw_data(stderr, __FUNCTION__, (unsigned char *)bstr_ptr(tx->request_protocol), bstr_len(tx->request_protocol));
#endif

    return HTP_OK;
}
