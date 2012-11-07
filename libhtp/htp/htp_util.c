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
#include "utf8_decoder.h"

/**
 * Is character a linear white space character?
 *
 * @param c
 * @return 0 or 1
 */
int htp_is_lws(int c) {
    if ((c == ' ') || (c == '\t')) return 1;
    else return 0;
}

/**
 * Is character a separator character?
 *
 * @param c
 * @return 0 or 1
 */
int htp_is_separator(int c) {
    /* separators = "(" | ")" | "<" | ">" | "@"
                  | "," | ";" | ":" | "\" | <">
                  | "/" | "[" | "]" | "?" | "="
                  | "{" | "}" | SP | HT         */
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return 1;
            break;
        default:
            return 0;
    }
}

/**
 * Is character a text character?
 *
 * @param c
 * @return 0 or 1
 */
int htp_is_text(int c) {
    if (c == '\t') return 1;
    if (c < 32) return 0;
    return 1;
}

/**
 * Is character a token character?
 *
 * @param c
 * @return 0 or 1
 */
int htp_is_token(int c) {
    /* token = 1*<any CHAR except CTLs or separators> */
    /* CHAR  = <any US-ASCII character (octets 0 - 127)> */
    if ((c < 32) || (c > 126)) return 0;
    if (htp_is_separator(c)) return 0;
    return 1;
}

/**
 * Remove one or more line terminators (LF or CRLF) from
 * the end of the line provided as input.
 *
 * @return 0 if nothing was removed, 1 if one or more LF characters were removed, or
 *         2 if one or more CR and/or LF characters were removed.
 */
int htp_chomp(unsigned char *data, size_t *len) {
    int r = 0;

    // Loop until there's no more stuff in the buffer
    while (*len > 0) {
        // Try one LF first
        if (data[*len - 1] == LF) {
            (*len)--;
            r = 1;

            if (*len == 0) return r;

            // A CR is allowed before LF
            if (data[*len - 1] == CR) {
                (*len)--;
                r = 2;
            }
        } else return r;
    }

    return r;
}

/**
 * Is character a white space character?
 *
 * @param c
 * @return 0 or 1
 */
int htp_is_space(int c) {
    switch (c) {
        case ' ':
        case '\f':
        case '\v':
        case '\t':
        case '\r':
        case '\n':
            return 1;
        default:
            return 0;
    }
}

/**
 * Converts request method, given as a string, into a number.
 *
 * @param method
 * @return Method number of M_UNKNOWN
 */
int htp_convert_method_to_number(bstr *method) {
    if (method == NULL) return M_UNKNOWN;
    // TODO Optimize using parallel matching, or something
    if (bstr_cmpc(method, "GET") == 0) return M_GET;
    if (bstr_cmpc(method, "PUT") == 0) return M_PUT;
    if (bstr_cmpc(method, "POST") == 0) return M_POST;
    if (bstr_cmpc(method, "DELETE") == 0) return M_DELETE;
    if (bstr_cmpc(method, "CONNECT") == 0) return M_CONNECT;
    if (bstr_cmpc(method, "OPTIONS") == 0) return M_OPTIONS;
    if (bstr_cmpc(method, "TRACE") == 0) return M_TRACE;
    if (bstr_cmpc(method, "PATCH") == 0) return M_PATCH;
    if (bstr_cmpc(method, "PROPFIND") == 0) return M_PROPFIND;
    if (bstr_cmpc(method, "PROPPATCH") == 0) return M_PROPPATCH;
    if (bstr_cmpc(method, "MKCOL") == 0) return M_MKCOL;
    if (bstr_cmpc(method, "COPY") == 0) return M_COPY;
    if (bstr_cmpc(method, "MOVE") == 0) return M_MOVE;
    if (bstr_cmpc(method, "LOCK") == 0) return M_LOCK;
    if (bstr_cmpc(method, "UNLOCK") == 0) return M_UNLOCK;
    if (bstr_cmpc(method, "VERSION_CONTROL") == 0) return M_VERSION_CONTROL;
    if (bstr_cmpc(method, "CHECKOUT") == 0) return M_CHECKOUT;
    if (bstr_cmpc(method, "UNCHECKOUT") == 0) return M_UNCHECKOUT;
    if (bstr_cmpc(method, "CHECKIN") == 0) return M_CHECKIN;
    if (bstr_cmpc(method, "UPDATE") == 0) return M_UPDATE;
    if (bstr_cmpc(method, "LABEL") == 0) return M_LABEL;
    if (bstr_cmpc(method, "REPORT") == 0) return M_REPORT;
    if (bstr_cmpc(method, "MKWORKSPACE") == 0) return M_MKWORKSPACE;
    if (bstr_cmpc(method, "MKACTIVITY") == 0) return M_MKACTIVITY;
    if (bstr_cmpc(method, "BASELINE_CONTROL") == 0) return M_BASELINE_CONTROL;
    if (bstr_cmpc(method, "MERGE") == 0) return M_MERGE;
    if (bstr_cmpc(method, "INVALID") == 0) return M_INVALID;
    if (bstr_cmpc(method, "HEAD") == 0) return M_HEAD;

    return M_UNKNOWN;
}

/**
 * Is the given line empty? This function expects the line to have
 * a terminating LF.
 *
 * @param data
 * @param len
 * @return 0 or 1
 */
int htp_is_line_empty(unsigned char *data, size_t len) {
    if ((len == 1) || ((len == 2) && (data[0] == CR))) {
        return 1;
    }

    return 0;
}

/**
 * Does line consist entirely of whitespace characters?
 * 
 * @param data
 * @param len
 * @return 0 or 1
 */
int htp_is_line_whitespace(unsigned char *data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        if (!isspace(data[i])) {
            return 0;
        }
    }

    return 1;
}

/**
 * Parses Content-Length string (positive decimal number).
 * White space is allowed before and after the number.
 *
 * @param b
 * @return Content-Length as a number, or -1 on error.
 */
int htp_parse_content_length(bstr *b) {
    return htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(b), bstr_len(b), 10);
}

/**
 * Parses chunk length (positive hexadecimal number).
 * White space is allowed before and after the number.
 *
 * @param data
 * @param len
 * @return Chunk length, or -1 on error.
 */
int htp_parse_chunked_length(unsigned char *data, size_t len) {
    return htp_parse_positive_integer_whitespace(data, len, 16);
}

/**
 * A forgiving parser for a positive integer in a given base.
 * White space is allowed before and after the number.
 * 
 * @param data
 * @param len
 * @param base
 * @return The parsed number, or -1 on error.
 */
int htp_parse_positive_integer_whitespace(unsigned char *data, size_t len, int base) {
    size_t pos = 0;

    // Ignore LWS before
    while ((pos < len) && (htp_is_lws(data[pos]))) pos++;
    if (pos == len) return -1001;

    int r = bstr_util_memtoip((char *) data + pos, len - pos, base, &pos);
    if (r < 0) return r;

    // Ignore LWS after
    while (pos < len) {
        if (!htp_is_lws(data[pos])) {
            return -1002;
        }

        pos++;
    }

    return r;
}

/**
 * Prints one log message to stderr.
 * 
 * @param log
 */
void htp_print_log(FILE *stream, htp_log_t *log) {
    if (log->code != 0) {
        fprintf(stream, "[%d][code %d][file %s][line %d] %s\n", log->level,
            log->code, log->file, log->line, log->msg);
    } else {
        fprintf(stream, "[%d][file %s][line %d] %s\n", log->level,
            log->file, log->line, log->msg);
    }
}

/**
 * Records one log message.
 * 
 * @param connp
 * @param file
 * @param line
 * @param level
 * @param code
 * @param fmt
 */
void htp_log(htp_connp_t *connp, const char *file, int line, int level, int code, const char *fmt, ...) {
    char buf[1024];
    va_list args;

    // Ignore messages below our log level
    if (connp->cfg->log_level < level) {
        return;
    }

    va_start(args, fmt);

    int r = vsnprintf(buf, 1023, fmt, args);

    va_end(args);

    if (r < 0) {
        // TODO Will vsnprintf ever return an error?
        snprintf(buf, 1024, "[vnsprintf returned error %d]", r);
    }

    // Indicate overflow with a '+' at the end
    if (r > 1023) {
        buf[1022] = '+';
        buf[1023] = '\0';
    }

    // Create a new log entry...
    htp_log_t *log = calloc(1, sizeof (htp_log_t));
    if (log == NULL) return;

    log->connp = connp;
    log->file = file;
    log->line = line;
    log->level = level;
    log->code = code;
    log->msg = strdup(buf);

    list_add(connp->conn->messages, log);

    if (level == HTP_LOG_ERROR) {
        connp->last_error = log;
    }

    hook_run_all(connp->cfg->hook_log, log);
}

/**
 * Determines if the given line is a continuation (of some previous line).
 *
 * @param connp
 * @param data
 * @param len
 * @return 0 or 1
 */
int htp_connp_is_line_folded(unsigned char *data, size_t len) {
    // Is there a line?
    if (len == 0) {
        return -1;
    }

    if (htp_is_lws(data[0])) return 1;
    else return 0;
}

/**
 * Determines if the given line is a request terminator.
 *
 * @param connp
 * @param data
 * @param len
 * @return 0 or 1
 */
int htp_connp_is_line_terminator(htp_connp_t *connp, unsigned char *data, size_t len) {
    // Is this the end of request headers?
    switch (connp->cfg->spersonality) {
        case HTP_SERVER_IIS_5_1:
            // IIS 5 will accept a whitespace line as a terminator
            if (htp_is_line_whitespace(data, len)) {
                return 1;
            }

            // Fall through
        default:
            // Treat an empty line as terminator
            if (htp_is_line_empty(data, len)) {
                return 1;
            }
            break;
    }

    return 0;
}

/**
 * Determines if the given line can be ignored when it appears before a request.
 *
 * @param connp
 * @param data
 * @param len
 * @return 0 or 1
 */
int htp_connp_is_line_ignorable(htp_connp_t *connp, unsigned char *data, size_t len) {
    return htp_connp_is_line_terminator(connp, data, len);
}

/**
 * Parses request URI, making no attempt to validate the contents.
 *
 * @param connp
 * @param authority
 * @param uri
 * @return HTP_ERROR on memory allocation failure, HTP_OK otherwise
 */
int htp_parse_authority(htp_connp_t *connp, bstr *authority, htp_uri_t **uri) {
    int colon = bstr_chr(authority, ':');
    if (colon == -1) {
        // Hostname alone
        (*uri)->hostname = bstr_strdup(authority);
        htp_normalize_hostname_inplace((*uri)->hostname);
    } else {
        // Hostname and port

        // Hostname
        (*uri)->hostname = bstr_strdup_ex(authority, 0, colon);
        // TODO Handle whitespace around hostname
        htp_normalize_hostname_inplace((*uri)->hostname);

        // Port
        int port = htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(authority)
            + colon + 1, bstr_len(authority) - colon - 1, 10);
        if (port < 0) {
            // Failed to parse port
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid server port information in request");
        } else if ((port > 0) && (port < 65536)) {
            // Valid port            
            (*uri)->port_number = port;
        } else {
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid authority port");
        }
    }

    return HTP_OK;
}

/**
 * Parses request URI, making no attempt to validate the contents.
 * 
 * @param input
 * @param uri
 * @return HTP_ERROR on memory allocation failure, HTP_OK otherwise
 */
int htp_parse_uri(bstr *input, htp_uri_t **uri) {
    if (input == NULL)
        return HTP_ERROR;
    char *data = bstr_ptr(input);
    size_t len = bstr_len(input);
    size_t start, pos;

    // Allow a htp_uri_t structure to be provided on input,
    // but allocate a new one if there isn't one
    if (*uri == NULL) {
        *uri = calloc(1, sizeof (htp_uri_t));
        if (*uri == NULL) return HTP_ERROR;
    }

    if (len == 0) {
        // Empty string
        return HTP_OK;
    }

    pos = 0;

    // Scheme test: if it doesn't start with a forward slash character (which it must
    // for the contents to be a path or an authority, then it must be the scheme part
    if (data[0] != '/') {
        // Parse scheme        

        // Find the colon, which marks the end of the scheme part
        start = pos;
        while ((pos < len) && (data[pos] != ':')) pos++;

        if (pos >= len) {
            // We haven't found a colon, which means that the URI
            // is invalid. Apache will ignore this problem and assume
            // the URI contains an invalid path so, for the time being,
            // we are going to do the same.
            pos = 0;
        } else {
            // Make a copy of the scheme
            (*uri)->scheme = bstr_memdup(data + start, pos - start);

            // Go over the colon
            pos++;
        }
    }

    // Authority test: two forward slash characters and it's an authority.
    // One, three or more slash characters, and it's a path. We, however,
    // only attempt to parse authority if we've seen a scheme.
    if ((*uri)->scheme != NULL)
        if ((pos + 2 < len) && (data[pos] == '/') && (data[pos + 1] == '/') && (data[pos + 2] != '/')) {
            // Parse authority

            // Go over the two slash characters
            start = pos = pos + 2;

            // Authority ends with a question mark, forward slash or hash
            while ((pos < len) && (data[pos] != '?') && (data[pos] != '/') && (data[pos] != '#')) pos++;

            char *hostname_start;
            size_t hostname_len;

            // Are the credentials included in the authority?
            char *m = memchr(data + start, '@', pos - start);
            if (m != NULL) {
                // Credentials present
                char *credentials_start = data + start;
                size_t credentials_len = m - data - start;

                // Figure out just the hostname part
                hostname_start = data + start + credentials_len + 1;
                hostname_len = pos - start - credentials_len - 1;

                // Extract the username and the password
                m = memchr(credentials_start, ':', credentials_len);
                if (m != NULL) {
                    // Username and password
                    (*uri)->username = bstr_memdup(credentials_start, m - credentials_start);
                    (*uri)->password = bstr_memdup(m + 1, credentials_len - (m - credentials_start) - 1);
                } else {
                    // Username alone
                    (*uri)->username = bstr_memdup(credentials_start, credentials_len);
                }
            } else {
                // No credentials
                hostname_start = data + start;
                hostname_len = pos - start;
            }

            // Still parsing authority; is there a port provided?
            m = memchr(hostname_start, ':', hostname_len);
            if (m != NULL) {
                size_t port_len = hostname_len - (m - hostname_start) - 1;
                hostname_len = hostname_len - port_len - 1;

                // Port string
                (*uri)->port = bstr_memdup(m + 1, port_len);

                // We deliberately don't want to try to convert the port
                // string as a number. That will be done later, during
                // the normalization and validation process.
            }

            // Hostname
            (*uri)->hostname = bstr_memdup(hostname_start, hostname_len);
        }

    // Path
    start = pos;

    // The path part will end with a question mark or a hash character, which
    // mark the beginning of the query part or the fragment part, respectively.
    while ((pos < len) && (data[pos] != '?') && (data[pos] != '#')) pos++;

    // Path
    (*uri)->path = bstr_memdup(data + start, pos - start);

    if (pos == len) return HTP_OK;

    // Query
    if (data[pos] == '?') {
        // Step over the question mark
        start = pos + 1;

        // The query part will end with the end of the input
        // or the beginning of the fragment part
        while ((pos < len) && (data[pos] != '#')) pos++;

        // Query string
        (*uri)->query = bstr_memdup(data + start, pos - start);

        if (pos == len) return HTP_OK;
    }

    // Fragment
    if (data[pos] == '#') {
        // Step over the hash character
        start = pos + 1;

        // Fragment; ends with the end of the input
        (*uri)->fragment = bstr_memdup(data + start, len - start);
    }

    return HTP_OK;
}

/**
 * Convert two input bytes, pointed to by the pointer parameter,
 * into a single byte by assuming the input consists of hexadecimal
 * characters. This function will happily convert invalid input.
 *
 * @param what
 * @return hex-decoded byte
 */
unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

/**
 * Convert a Unicode codepoint into a single-byte, using best-fit
 * mapping (as specified in the provided configuration structure).
 *
 * @param cfg
 * @param codepoint
 * @return converted single byte
 */
uint8_t bestfit_codepoint(htp_cfg_t *cfg, uint32_t codepoint) {
    // Is it a single-byte codepoint?
    if (codepoint < 0x100) {
        return (uint8_t) codepoint;
    }

    // Our current implementation only converts the 2-byte codepoints
    if (codepoint > 0xffff) {
        return cfg->path_replacement_char;
    }

    uint8_t *p = cfg->path_u_bestfit_map;

    // TODO Optimize lookup

    for (;;) {
        uint32_t x = (p[0] << 8) + p[1];

        if (x == 0) {
            return cfg->path_replacement_char;
        }

        if (x == codepoint) {
            return p[2];
            break;
        }

        // Move to the next triplet
        p += 3;
    }
}

/**
 * Decode a UTF-8 encoded path. Overlong characters will be decoded, invalid
 * chararacters will be left as-is. Best-fit mapping will be used to convert
 * UTF-8 into a single-byte stream.
 *
 * @param cfg
 * @param tx
 * @param path
 */
void htp_utf8_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path) {
    if (path == NULL)
        return;

    uint8_t *data = (unsigned char *) bstr_ptr(path);
    size_t len = bstr_len(path);
    size_t rpos = 0;
    size_t wpos = 0;
    size_t charpos = 0;
    uint32_t codepoint = 0;
    uint32_t state = UTF8_ACCEPT;
    uint32_t counter = 0;
    uint8_t seen_valid = 0;

    while (rpos < len) {
        counter++;

        switch (utf8_decode_allow_overlong(&state, &codepoint, data[rpos])) {
            case UTF8_ACCEPT:
                if (counter == 1) {
                    // ASCII character
                    data[wpos++] = (uint8_t) codepoint;
                } else {
                    // A valid UTF-8 character
                    seen_valid = 1;

                    // Check for overlong characters and set the
                    // flag accordingly
                    switch (counter) {
                        case 2:
                            if (codepoint < 0x80) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 3:
                            if (codepoint < 0x800) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 4:
                            if (codepoint < 0x10000) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                    }

                    // Special flag for fullwidth form evasion
                    if ((codepoint > 0xfeff) && (codepoint < 0x010000)) {
                        tx->flags |= HTP_PATH_FULLWIDTH_EVASION;
                    }

                    // Use best-fit mapping to convert to a single byte
                    data[wpos++] = bestfit_codepoint(cfg, codepoint);
                }

                // Advance over the consumed byte
                rpos++;

                // Prepare for the next character
                counter = 0;
                charpos = rpos;

                break;

            case UTF8_REJECT:
                // Invalid UTF-8 character
                tx->flags |= HTP_PATH_UTF8_INVALID;

                // Is the server expected to respond with 400?
                if (cfg->path_invalid_utf8_handling == STATUS_400) {
                    tx->response_status_expected_number = 400;
                }

                // Override the state in the UTF-8 decoder because
                // we want to ignore invalid characters
                state = UTF8_ACCEPT;

                // Copy the invalid bytes into the output stream
                while (charpos <= rpos) {
                    data[wpos++] = data[charpos++];
                }

                // Advance over the consumed byte
                rpos++;

                // Prepare for the next character
                counter = 0;
                charpos = rpos;

                break;

            default:
                // Keep going; the character is not yet formed
                rpos++;
                break;
        }
    }

    // Did the input stream seem like a valid UTF-8 string?
    if ((seen_valid) && (!(tx->flags & HTP_PATH_UTF8_INVALID))) {
        tx->flags |= HTP_PATH_UTF8_VALID;
    }

    // Adjust the length of the string, because
    // we're doing in-place decoding.
    bstr_len_adjust(path, wpos);
}

/**
 * Validate a path that is quite possibly UTF-8 encoded.
 *
 * @param cfg
 * @param tx
 * @param path
 */
void htp_utf8_validate_path(htp_tx_t *tx, bstr *path) {
    unsigned char *data = (unsigned char *) bstr_ptr(path);
    size_t len = bstr_len(path);
    size_t rpos = 0;
    uint32_t codepoint = 0;
    uint32_t state = UTF8_ACCEPT;
    uint32_t counter = 0;
    uint8_t seen_valid = 0;

    while (rpos < len) {
        counter++;

        switch (utf8_decode_allow_overlong(&state, &codepoint, data[rpos])) {
            case UTF8_ACCEPT:
                // ASCII character

                if (counter > 1) {
                    // A valid UTF-8 character
                    seen_valid = 1;

                    // Check for overlong characters and set the
                    // flag accordingly
                    switch (counter) {
                        case 2:
                            if (codepoint < 0x80) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 3:
                            if (codepoint < 0x800) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 4:
                            if (codepoint < 0x10000) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                    }
                }

                // Special flag for fullwidth form evasion
                if ((codepoint > 0xfeff) && (codepoint < 0x010000)) {
                    tx->flags |= HTP_PATH_FULLWIDTH_EVASION;
                }

                // Advance over the consumed byte
                rpos++;

                // Prepare for the next character
                counter = 0;

                break;

            case UTF8_REJECT:
                // Invalid UTF-8 character
                tx->flags |= HTP_PATH_UTF8_INVALID;

                // Override the state in the UTF-8 decoder because
                // we want to ignore invalid characters
                state = UTF8_ACCEPT;

                // Advance over the consumed byte
                rpos++;

                // Prepare for the next character
                counter = 0;

                break;

            default:
                // Keep going; the character is not yet formed
                rpos++;
                break;
        }
    }

    // Did the input stream seem like a valid UTF-8 string?
    if ((seen_valid) && (!(tx->flags & HTP_PATH_UTF8_INVALID))) {
        tx->flags |= HTP_PATH_UTF8_VALID;
    }
}

/**
 * Decode a %u-encoded character, using best-fit mapping as necessary.
 *
 * @param cfg
 * @param tx
 * @param data
 * @return decoded byte
 */
int decode_u_encoding(htp_cfg_t *cfg, htp_tx_t *tx, unsigned char *data) {
    unsigned int c1 = x2c(data);
    unsigned int c2 = x2c(data + 2);
    int r = cfg->path_replacement_char;

    if (c1 == 0x00) {
        r = c2;
        tx->flags |= HTP_PATH_OVERLONG_U;
    } else {
        // Check for fullwidth form evasion
        if (c1 == 0xff) {
            tx->flags |= HTP_PATH_FULLWIDTH_EVASION;
        }

        switch (cfg->path_unicode_mapping) {
            case STATUS_400:
                tx->response_status_expected_number = 400;
                break;
            case STATUS_404:
                tx->response_status_expected_number = 404;
                break;
        }

        // Use best-fit mapping
        unsigned char *p = cfg->path_u_bestfit_map;

        // TODO Optimize lookup

        for (;;) {
            // Have we reached the end of the map?
            if ((p[0] == 0) && (p[1] == 0)) {
                break;
            }

            // Have we found the mapping we're looking for?
            if ((p[0] == c1) && (p[1] == c2)) {
                r = p[2];
                break;
            }

            // Move to the next triplet
            p += 3;
        }
    }

    // Check for encoded path separators
    if ((r == '/') || ((cfg->path_backslash_separators) && (r == '\\'))) {
        tx->flags |= HTP_PATH_ENCODED_SEPARATOR;
    }

    return r;
}

/**
 * Decode a request path according to the settings in the
 * provided configuration structure.
 *
 * @param cfg
 * @param tx
 * @param path
 */
int htp_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path) {
    if (path == NULL)
        return -1;

    unsigned char *data = (unsigned char *) bstr_ptr(path);
    if (data == NULL) {
        return -1;
    }
    size_t len = bstr_len(path);

    // TODO I don't like this function. It's too complex.

    size_t rpos = 0;
    size_t wpos = 0;
    int previous_was_separator = 0;

    while (rpos < len) {
        int c = data[rpos];

        // Decode encoded characters
        if (c == '%') {
            if (rpos + 2 < len) {
                int handled = 0;

                if (cfg->path_decode_u_encoding) {
                    // Check for the %u encoding
                    if ((data[rpos + 1] == 'u') || (data[rpos + 1] == 'U')) {
                        handled = 1;

                        if (cfg->path_decode_u_encoding == STATUS_400) {
                            tx->response_status_expected_number = 400;
                        }

                        if (rpos + 5 < len) {
                            if (isxdigit(data[rpos + 2]) && (isxdigit(data[rpos + 3]))
                                && isxdigit(data[rpos + 4]) && (isxdigit(data[rpos + 5]))) {
                                // Decode a valid %u encoding
                                c = decode_u_encoding(cfg, tx, &data[rpos + 2]);
                                rpos += 6;

                                if (c == 0) {
                                    tx->flags |= HTP_PATH_ENCODED_NUL;

                                    if (cfg->path_nul_encoded_handling == STATUS_400) {
                                        tx->response_status_expected_number = 400;
                                    } else if (cfg->path_nul_encoded_handling == STATUS_404) {
                                        tx->response_status_expected_number = 404;
                                    }
                                }
                            } else {
                                // Invalid %u encoding
                                tx->flags |= HTP_PATH_INVALID_ENCODING;

                                switch (cfg->path_invalid_encoding_handling) {
                                    case URL_DECODER_REMOVE_PERCENT:
                                        // Do not place anything in output; eat
                                        // the percent character
                                        rpos++;
                                        continue;
                                        break;
                                    case URL_DECODER_PRESERVE_PERCENT:
                                        // Leave the percent character in output
                                        rpos++;
                                        break;
                                    case URL_DECODER_DECODE_INVALID:
                                        // Decode invalid %u encoding
                                        c = decode_u_encoding(cfg, tx, &data[rpos + 2]);
                                        rpos += 6;
                                        break;
                                    case URL_DECODER_STATUS_400:
                                        // Set expected status to 400
                                        tx->response_status_expected_number = 400;

                                        // Decode invalid %u encoding
                                        c = decode_u_encoding(cfg, tx, &data[rpos + 2]);
                                        rpos += 6;
                                        break;
                                        break;
                                    default:
                                        // Unknown setting
                                        return -1;
                                        break;
                                }
                            }
                        } else {
                            // Invalid %u encoding (not enough data)
                            tx->flags |= HTP_PATH_INVALID_ENCODING;

                            if (cfg->path_invalid_encoding_handling == URL_DECODER_REMOVE_PERCENT) {
                                // Remove the percent character from output
                                rpos++;
                                continue;
                            } else {
                                rpos++;
                            }
                        }
                    }
                }

                // Handle standard URL encoding
                if (!handled) {
                    if ((isxdigit(data[rpos + 1])) && (isxdigit(data[rpos + 2]))) {
                        c = x2c(&data[rpos + 1]);

                        if (c == 0) {
                            tx->flags |= HTP_PATH_ENCODED_NUL;

                            switch (cfg->path_nul_encoded_handling) {
                                case TERMINATE:
                                    bstr_len_adjust(path, wpos);
                                    return 1;
                                    break;
                                case STATUS_400:
                                    tx->response_status_expected_number = 400;
                                    break;
                                case STATUS_404:
                                    tx->response_status_expected_number = 404;
                                    break;
                            }
                        }

                        if ((c == '/') || ((cfg->path_backslash_separators) && (c == '\\'))) {
                            tx->flags |= HTP_PATH_ENCODED_SEPARATOR;

                            switch (cfg->path_decode_separators) {
                                case STATUS_404:
                                    tx->response_status_expected_number = 404;
                                    // Fall-through
                                case NO:
                                    // Leave encoded
                                    c = '%';
                                    rpos++;
                                    break;
                                case YES:
                                    // Decode
                                    rpos += 3;
                                    break;
                            }
                        } else {
                            // Decode
                            rpos += 3;
                        }
                    } else {
                        // Invalid encoding
                        tx->flags |= HTP_PATH_INVALID_ENCODING;

                        switch (cfg->path_invalid_encoding_handling) {
                            case URL_DECODER_REMOVE_PERCENT:
                                // Do not place anything in output; eat
                                // the percent character
                                rpos++;
                                continue;
                                break;
                            case URL_DECODER_PRESERVE_PERCENT:
                                // Leave the percent character in output
                                rpos++;
                                break;
                            case URL_DECODER_DECODE_INVALID:
                                // Decode
                                c = x2c(&data[rpos + 1]);
                                rpos += 3;
                                // Note: What if an invalid encoding decodes into a path
                                //       separator? This is theoretical at the moment, because
                                //       the only platform we know doesn't convert separators is
                                //       Apache, who will also respond with 400 if invalid encoding
                                //       is encountered. Thus no check for a separator here.
                                break;
                            case URL_DECODER_STATUS_400:
                                // Backend will reject request with 400, which means
                                // that it does not matter what we do.
                                tx->response_status_expected_number = 400;

                                // Preserve the percent character
                                rpos++;
                                break;
                            default:
                                // Unknown setting
                                return -1;
                                break;
                        }
                    }
                }
            } else {
                // Invalid encoding (not enough data)
                tx->flags |= HTP_PATH_INVALID_ENCODING;

                if (cfg->path_invalid_encoding_handling == URL_DECODER_REMOVE_PERCENT) {
                    // Do not place the percent character in output
                    rpos++;
                    continue;
                } else {
                    rpos++;
                }
            }
        } else {
            // One non-encoded character

            // Is it a NUL byte?
            if (c == 0) {
                switch (cfg->path_nul_raw_handling) {
                    case TERMINATE:
                        // Terminate path with a raw NUL byte
                        bstr_len_adjust(path, wpos);
                        return 1;
                        break;
                    case STATUS_400:
                        // Leave the NUL byte, but set the expected status
                        tx->response_status_expected_number = 400;
                        break;
                    case STATUS_404:
                        // Leave the NUL byte, but set the expected status
                        tx->response_status_expected_number = 404;
                        break;
                }
            }

            rpos++;
        }

        // Place the character into output

        // Check for control characters
        if (c < 0x20) {
            if (cfg->path_control_char_handling == STATUS_400) {
                tx->response_status_expected_number = 400;
            }
        }

        // Convert backslashes to forward slashes, if necessary
        if ((c == '\\') && (cfg->path_backslash_separators)) {
            c = '/';
        }

        // Lowercase characters, if necessary
        if (cfg->path_case_insensitive) {
            c = tolower(c);
        }

        // If we're compressing separators then we need
        // to track if the previous character was a separator
        if (cfg->path_compress_separators) {
            if (c == '/') {
                if (!previous_was_separator) {
                    data[wpos++] = c;
                    previous_was_separator = 1;
                } else {
                    // Do nothing; we don't want
                    // another separator in output
                }
            } else {
                data[wpos++] = c;
                previous_was_separator = 0;
            }
        } else {
            data[wpos++] = c;
        }
    }

    bstr_len_adjust(path, wpos);

    return 1;
}

/**
 * Normalize a previously-parsed request URI.
 *
 * @param connp
 * @param incomplete
 * @param normalized
 * @return HTP_OK or HTP_ERROR
 */
int htp_normalize_parsed_uri(htp_connp_t *connp, htp_uri_t *incomplete, htp_uri_t *normalized) {
    // Scheme
    if (incomplete->scheme != NULL) {
        // Duplicate and convert to lowercase
        normalized->scheme = bstr_dup_lower(incomplete->scheme);
        if (normalized->scheme == NULL)
            return HTP_ERROR;
    }

    // Username
    if (incomplete->username != NULL) {
        normalized->username = bstr_strdup(incomplete->username);
        if (normalized->username == NULL)
            return HTP_ERROR;
        htp_uriencoding_normalize_inplace(normalized->username);
    }

    // Password
    if (incomplete->password != NULL) {
        normalized->password = bstr_strdup(incomplete->password);
        if (normalized->password == NULL)
            return HTP_ERROR;
        htp_uriencoding_normalize_inplace(normalized->password);
    }

    // Hostname
    if (incomplete->hostname != NULL) {
        // We know that incomplete->hostname does not contain
        // port information, so no need to check for it here
        normalized->hostname = bstr_strdup(incomplete->hostname);
        if (normalized->hostname == NULL)
            return HTP_ERROR;
        htp_uriencoding_normalize_inplace(normalized->hostname);
        htp_normalize_hostname_inplace(normalized->hostname);
    }

    // Port
    if (incomplete->port != NULL) {
        // Parse provided port
        normalized->port_number = htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(incomplete->port),
            bstr_len(incomplete->port), 10);
        // We do not report failed port parsing, but leave
        // to upstream to detect and act upon it.
    }

    // Path
    if (incomplete->path != NULL) {
        // Make a copy of the path, on which we can work on
        normalized->path = bstr_strdup(incomplete->path);
        if (normalized->path != NULL) {
            // Decode URL-encoded (and %u-encoded) characters, as well as lowercase,
            // compress separators and convert backslashes.
            htp_decode_path_inplace(connp->cfg, connp->in_tx, normalized->path);

            // Handle UTF-8 in path
            if (connp->cfg->path_convert_utf8) {
                // Decode Unicode characters into a single-byte stream, using best-fit mapping
                htp_utf8_decode_path_inplace(connp->cfg, connp->in_tx, normalized->path);
            } else {
                // Only validate path as a UTF-8 stream
                htp_utf8_validate_path(connp->in_tx, normalized->path);
            }

            // RFC normalization
            htp_normalize_uri_path_inplace(normalized->path);
        } else {
            return HTP_ERROR;
        }
    }

    // Query
    if (incomplete->query != NULL) {
        // We cannot URL-decode the query string here; it needs to be
        // parsed into individual key-value pairs first.
        normalized->query = bstr_strdup(incomplete->query);
        if (normalized->query == NULL)
            return HTP_ERROR;
    }

    // Fragment
    if (incomplete->fragment != NULL) {
        normalized->fragment = bstr_strdup(incomplete->fragment);
        if (normalized->fragment == NULL)
            return HTP_ERROR;
        htp_uriencoding_normalize_inplace(normalized->fragment);
    }

    return HTP_OK;
}

/**
 * Normalize request hostname. Convert all characters to lowercase and
 * remove trailing dots from the end, if present.
 *
 * @param hostname
 * @return normalized hostnanme
 */
bstr *htp_normalize_hostname_inplace(bstr *hostname) {
    if (hostname == NULL)
        return NULL;
    bstr_tolowercase(hostname);

    char *data = bstr_ptr(hostname);
    size_t len = bstr_len(hostname);

    while (len > 0) {
        if (data[len - 1] != '.') return hostname;

        bstr_chop(hostname);
        len--;
    }

    return hostname;
}

/**
 * Replace the URI in the structure with the one provided as the parameter
 * to this function (which will typically be supplied in a Host header).
 *
 * @param connp
 * @param parsed_uri
 * @param hostname
 */
void htp_replace_hostname(htp_connp_t *connp, htp_uri_t *parsed_uri, bstr *hostname) {
    if (hostname == NULL)
        return;
    int colon = bstr_chr(hostname, ':');
    if (colon == -1) {
        // Hostname alone
        parsed_uri->hostname = bstr_strdup(hostname);
        htp_normalize_hostname_inplace(parsed_uri->hostname);
    } else {
        // Hostname
        parsed_uri->hostname = bstr_strdup_ex(hostname, 0, colon);
        // TODO Handle whitespace around hostname
        htp_normalize_hostname_inplace(parsed_uri->hostname);

        // Port
        int port = htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(hostname) + colon + 1,
            bstr_len(hostname) - colon - 1, 10);
        if (port < 0) {
            // Failed to parse port
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid server port information in request");
        } else if ((port > 0) && (port < 65536)) {
            // Valid port
            if (port != connp->conn->local_port) {
                // Port is different from the TCP port
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request server port number differs from the actual TCP port");
            } else {
                parsed_uri->port_number = port;
            }
        }
    }
}

/**
 * Is URI character reserved?
 *
 * @param c
 * @return 1 if it is, 0 if it isn't
 */
int htp_is_uri_unreserved(unsigned char c) {
    if (((c >= 0x41) && (c <= 0x5a)) ||
        ((c >= 0x61) && (c <= 0x7a)) ||
        ((c >= 0x30) && (c <= 0x39)) ||
        (c == 0x2d) || (c == 0x2e) ||
        (c == 0x5f) || (c == 0x7e)) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Decode a URL-encoded string, leaving the reserved
 * characters and invalid encodings alone.
 *
 * @param s
 */
void htp_uriencoding_normalize_inplace(bstr *s) {
    if (s == NULL) return;
    unsigned char *data = (unsigned char *) bstr_ptr(s);
    size_t len = bstr_len(s);

    size_t rpos = 0;
    size_t wpos = 0;

    while (rpos < len) {
        if (data[rpos] == '%') {
            if (rpos + 2 < len) {
                if (isxdigit(data[rpos + 1]) && (isxdigit(data[rpos + 2]))) {
                    unsigned char c = x2c(&data[rpos + 1]);

                    if (!htp_is_uri_unreserved(c)) {
                        // Leave reserved characters encoded, but convert
                        // the hexadecimal digits to uppercase
                        data[wpos++] = data[rpos++];
                        data[wpos++] = toupper(data[rpos++]);
                        data[wpos++] = toupper(data[rpos++]);
                    } else {
                        // Decode unreserved character
                        data[wpos++] = c;
                        rpos += 3;
                    }
                } else {
                    // Invalid URL encoding: invalid hex digits

                    // Copy over what's there
                    data[wpos++] = data[rpos++];
                    data[wpos++] = toupper(data[rpos++]);
                    data[wpos++] = toupper(data[rpos++]);
                }
            } else {
                // Invalid URL encoding: string too short

                // Copy over what's there
                data[wpos++] = data[rpos++];
                while (rpos < len) {
                    data[wpos++] = toupper(data[rpos++]);
                }
            }
        } else {
            data[wpos++] = data[rpos++];
        }
    }

    bstr_len_adjust(s, wpos);
}

#if 0

/**
 *
 */
int htp_prenormalize_uri_path_inplace(bstr *s, int *flags, int case_insensitive, int backslash, int decode_separators, int remove_consecutive) {
    char *data = bstr_ptr(s);
    size_t len = bstr_len(s);

    size_t rpos = 0;
    size_t wpos = 0;

    while (rpos < len) {
        char c = data[rpos];

        // Convert backslash characters where necessary
        if ((c == '/') || ((c == '\\') && (backslash))) {
            if ((!remove_consecutive) || (wpos == 0) || (data[wpos - 1] != '/')) {
                data[wpos++] = '/';
            }

            rpos++;
        } else
            if ((c == '%') && (decode_separators)) {
            if (rpos + 2 < len) {
                if (isxdigit(data[rpos + 1]) && (isxdigit(data[rpos + 2]))) {
                    unsigned char x = x2c(&data[rpos + 1]);

                    if (x == 0) {
                        (*flags) |= HTP_PATH_ENCODED_NUL;
                    }

                    if ((x == '/') || ((backslash) && (x == '\\'))) {
                        data[wpos++] = '/';
                        rpos += 3;
                        continue;
                    }
                } else {
                    // Invalid URL encoding
                    (*flags) |= HTP_PATH_INVALID_ENCODING;

                    // Copy over all three bytes
                    data[wpos++] = data[rpos++];
                    data[wpos++] = data[rpos++];
                    data[wpos++] = data[rpos++];
                }
            } else {
                // Not enough characters
                (*flags) |= HTP_PATH_INVALID_ENCODING;

                // Copy over what's there
                while (rpos < len) {
                    data[wpos++] = data[rpos++];
                }
            }
        } else {
            // Just copy the character
            if (case_insensitive) {
                data[wpos++] = tolower(c);
            } else {
                data[wpos++] = c;
            }

            rpos++;
        }
    }

    bstr_len_adjust(s, wpos);
}
#endif

/**
 * Normalize URL path. This function implements the remove dot segments algorithm
 * speficied in RFC 3986, section 5.2.4.
 *
 * @param s
 */
void htp_normalize_uri_path_inplace(bstr *s) {
    if (s == NULL) return;
    char *data = bstr_ptr(s);
    size_t len = bstr_len(s);

    size_t rpos = 0;
    size_t wpos = 0;

    int c = -1;
    while (rpos < len) {
        if (c == -1) {
            c = data[rpos++];
        }

        // A. If the input buffer begins with a prefix of "../" or "./",
        //    then remove that prefix from the input buffer; otherwise,
        if (c == '.') {
            if ((rpos + 1 < len) && (data[rpos] == '.') && (data[rpos + 1] == '/')) {
                c = -1;
                rpos += 2;
                continue;
            } else if ((rpos < len) && (data[rpos + 1] == '/')) {
                c = -1;
                rpos += 2;
                continue;
            }
        }

        if (c == '/') {
            // B. if the input buffer begins with a prefix of "/./" or "/.",
            //    where "." is a complete path segment, then replace that
            //    prefix with "/" in the input buffer; otherwise,
            if ((rpos + 1 < len) && (data[rpos] == '.') && (data[rpos + 1] == '/')) {
                c = '/';
                rpos += 2;
                continue;
            } else if ((rpos + 1 == len) && (data[rpos] == '.')) {
                c = '/';
                rpos += 1;
                continue;
            }

            // C. if the input buffer begins with a prefix of "/../" or "/..",
            //    where ".." is a complete path segment, then replace that
            //    prefix with "/" in the input buffer and remove the last
            //    segment and its preceding "/" (if any) from the output
            //    buffer; otherwise,
            if ((rpos + 2 < len) && (data[rpos] == '.') && (data[rpos + 1] == '.') && (data[rpos + 2] == '/')) {
                c = '/';
                rpos += 3;

                // Remove the last segment
                while ((wpos > 0) && (data[wpos - 1] != '/')) wpos--;
                if (wpos > 0) wpos--;
                continue;
            } else if ((rpos + 2 == len) && (data[rpos] == '.') && (data[rpos + 1] == '.')) {
                c = '/';
                rpos += 2;

                // Remove the last segment
                while ((wpos > 0) && (data[wpos - 1] != '/')) wpos--;
                if (wpos > 0) wpos--;
                continue;
            }
        }

        // D.  if the input buffer consists only of "." or "..", then remove
        // that from the input buffer; otherwise,
        if ((c == '.') && (rpos == len)) {
            rpos++;
            continue;
        }

        if ((c == '.') && (rpos + 1 == len) && (data[rpos] == '.')) {
            rpos += 2;
            continue;
        }

        // E.  move the first path segment in the input buffer to the end of
        // the output buffer, including the initial "/" character (if
        // any) and any subsequent characters up to, but not including,
        // the next "/" character or the end of the input buffer.
        data[wpos++] = c;

        while ((rpos < len) && (data[rpos] != '/')) {
            // data[wpos++] = data[rpos++];
            int c2 = data[rpos++];
            data[wpos++] = c2;
        }

        c = -1;
    }

    bstr_len_adjust(s, wpos);
}

/**
 *
 */
void fprint_raw_data(FILE *stream, const char *name, unsigned char *data, size_t len) {
    char buf[160];
    size_t offset = 0;

    fprintf(stream, "\n%s: data len %zd (0x%zx)\n", name, len, len);

    while (offset < len) {
        size_t i;

        sprintf(buf, "%08zx", offset);
        strcat(buf + strlen(buf), "  ");

        i = 0;
        while (i < 8) {
            if (offset + i < len) {
                sprintf(buf + strlen(buf), "%02x ", data[offset + i]);
            } else {
                strcat(buf + strlen(buf), "   ");
            }

            i++;
        }

        strcat(buf + strlen(buf), " ");

        i = 8;
        while (i < 16) {
            if (offset + i < len) {
                sprintf(buf + strlen(buf), "%02x ", data[offset + i]);
            } else {
                strcat(buf + strlen(buf), "   ");
            }

            i++;
        }

        strcat(buf + strlen(buf), " |");

        i = 0;
        char *p = buf + strlen(buf);
        while ((offset + i < len) && (i < 16)) {
            int c = data[offset + i];

            if (isprint(c)) {
                *p++ = c;
            } else {
                *p++ = '.';
            }

            i++;
        }

        *p++ = '|';
        *p++ = '\n';
        *p++ = '\0';

        fprintf(stream, "%s", buf);
        offset += 16;
    }

    fprintf(stream, "\n");
}


/*

 */

/**
 *
 */
char *htp_connp_in_state_as_string(htp_connp_t *connp) {
    if (connp == NULL) return "NULL";

    if (connp->in_state == htp_connp_REQ_IDLE) return "REQ_IDLE";
    if (connp->in_state == htp_connp_REQ_LINE) return "REQ_FIRST_LINE";
    if (connp->in_state == htp_connp_REQ_PROTOCOL) return "REQ_PROTOCOL";
    if (connp->in_state == htp_connp_REQ_HEADERS) return "REQ_HEADERS";
    if (connp->in_state == htp_connp_REQ_BODY_DETERMINE) return "REQ_BODY_DETERMINE";
    if (connp->in_state == htp_connp_REQ_BODY_IDENTITY) return "REQ_BODY_IDENTITY";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_LENGTH) return "REQ_BODY_CHUNKED_LENGTH";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_DATA) return "REQ_BODY_CHUNKED_DATA";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_DATA_END) return "REQ_BODY_CHUNKED_DATA_END";

    if (connp->in_state == htp_connp_REQ_CONNECT_CHECK) return "htp_connp_REQ_CONNECT_CHECK";
    if (connp->in_state == htp_connp_REQ_CONNECT_WAIT_RESPONSE) return "htp_connp_REQ_CONNECT_WAIT_RESPONSE";

    return "UNKNOWN";
}

/**
 *
 */
char *htp_connp_out_state_as_string(htp_connp_t *connp) {
    if (connp == NULL) return "NULL";

    if (connp->out_state == htp_connp_RES_IDLE) return "RES_IDLE";
    if (connp->out_state == htp_connp_RES_LINE) return "RES_LINE";
    if (connp->out_state == htp_connp_RES_HEADERS) return "RES_HEADERS";
    if (connp->out_state == htp_connp_RES_BODY_DETERMINE) return "RES_BODY_DETERMINE";
    if (connp->out_state == htp_connp_RES_BODY_IDENTITY) return "RES_BODY_IDENTITY";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_LENGTH) return "RES_BODY_CHUNKED_LENGTH";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_DATA) return "RES_BODY_CHUNKED_DATA";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_DATA_END) return "RES_BODY_CHUNKED_DATA_END";

    return "UNKNOWN";
}

/**
 *
 */
char *htp_tx_progress_as_string(htp_tx_t *tx) {
    if (tx == NULL) return "NULL";

    switch (tx->progress) {
        case TX_PROGRESS_NEW:
            return "NEW";
        case TX_PROGRESS_REQ_LINE:
            return "REQ_LINE";
        case TX_PROGRESS_REQ_HEADERS:
            return "REQ_HEADERS";
        case TX_PROGRESS_REQ_BODY:
            return "REQ_BODY";
        case TX_PROGRESS_REQ_TRAILER:
            return "REQ_TRAILER";
        case TX_PROGRESS_WAIT:
            return "WAIT";
        case TX_PROGRESS_RES_LINE:
            return "RES_LINE";
        case TX_PROGRESS_RES_HEADERS:
            return "RES_HEADERS";
        case TX_PROGRESS_RES_BODY:
            return "RES_BODY";
        case TX_PROGRESS_RES_TRAILER:
            return "RES_TRAILER";
        case TX_PROGRESS_DONE:
            return "DONE";
    }

    return "UNKNOWN";
}

bstr *htp_unparse_uri_noencode(htp_uri_t *uri) {
    if (uri == NULL) {
        return NULL;
    }   

    // On the first pass determine the length of the final string
    size_t len = 0;

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
    bstr *r = bstr_alloc(len);
    if (r == NULL) {
        return NULL;
    }   

    if (uri->scheme != NULL) {
        bstr_add_str_noex(r, uri->scheme);
        bstr_add_cstr_noex(r, "://");
    }   

    if ((uri->username != NULL) || (uri->password != NULL)) {
        if (uri->username != NULL) {
            bstr_add_str_noex(r, uri->username);
        }

        bstr_add_cstr(r, ":");

        if (uri->password != NULL) {
            bstr_add_str_noex(r, uri->password);
        }

        bstr_add_cstr_noex(r, "@");
    }   

    if (uri->hostname != NULL) {
        bstr_add_str_noex(r, uri->hostname);
    }   

    if (uri->port != NULL) {
        bstr_add_cstr(r, ":");
        bstr_add_str_noex(r, uri->port);
    }   

    if (uri->path != NULL) {
        bstr_add_str_noex(r, uri->path);
    }  

    if (uri->query != NULL) {
        bstr *query = bstr_strdup(uri->query);
        htp_uriencoding_normalize_inplace(query);
        bstr_add_cstr_noex(r, "?");
        bstr_add_str_noex(r, query);
        bstr_free(query);
    }     

    if (uri->fragment != NULL) {
        bstr_add_cstr_noex(r, "#");
        bstr_add_str_noex(r, uri->fragment);
    }
   
    return r;
}

/**
 * Construct a bstr that contains the raw request headers.
 *
 * @param tx
 * @return
 */
bstr *htp_tx_generate_request_headers_raw(htp_tx_t *tx) {
    bstr *request_headers_raw = NULL;
    size_t i, len = 0;

    for (i = 0; i < list_size(tx->request_header_lines); i++) {
        htp_header_line_t *hl = list_get(tx->request_header_lines, i);
        len += bstr_len(hl->line);
        if (hl->terminators)
            len += bstr_len(hl->terminators);
        else
            len += 2; // 0d 0a
    }

    request_headers_raw = bstr_alloc(len);
    if (request_headers_raw == NULL) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Failed to allocate bstring of %d bytes", len);
        return NULL;
    }

    for (i = 0; i < list_size(tx->request_header_lines); i++) {
        htp_header_line_t *hl = list_get(tx->request_header_lines, i);
        bstr_add_str_noex(request_headers_raw, hl->line);
        if (hl->terminators)
            bstr_add_str_noex(request_headers_raw, hl->terminators);
        else
            bstr_add_cstr_noex(request_headers_raw, "\r\n");
    }

    return request_headers_raw;
}

/**
 * Get a bstr that contains the raw request headers. This method will always
 * return an up-to-date buffer, containing the last known headers. Thus, if
 * it is called once after REQUEST_HEADERS phase it will return one buffer, but
 * it may return a different buffer if called after REQUEST_TRAILERS phase (but
 * only if the request actually contains trailer headers). Do not retain the
 * bstr pointer, as the buffer may change. If there are no changes to the
 * request header structure, only one buffer will be contstructed and used. (Multiple
 * invocations of this method will not cause multiple buffers to be created.)
 *
 * @param tx
 * @return
 */
bstr *htp_tx_get_request_headers_raw(htp_tx_t *tx) {
    // Check that we are not called too early
    if (tx->progress < TX_PROGRESS_REQ_HEADERS) return NULL;

    if (tx->request_headers_raw == NULL) {
        tx->request_headers_raw = htp_tx_generate_request_headers_raw(tx);
        tx->request_headers_raw_lines = list_size(tx->request_header_lines);
    } else {
        // Check that the buffer we have is not obsolete
        if (tx->request_headers_raw_lines < list_size(tx->request_header_lines)) {
            // Rebuild raw buffer
            bstr_free(tx->request_headers_raw);
            tx->request_headers_raw = htp_tx_generate_request_headers_raw(tx);
            tx->request_headers_raw_lines = list_size(tx->request_header_lines);
        }
    }

    return tx->request_headers_raw;
}

/**
 * Construct a bstr that contains the raw response headers.
 *
 * @param tx
 * @return
 */
bstr *htp_tx_generate_response_headers_raw(htp_tx_t *tx) {
    bstr *response_headers_raw = NULL;
    size_t i, len = 0;

    for (i = 0; i < list_size(tx->response_header_lines); i++) {
        htp_header_line_t *hl = list_get(tx->response_header_lines, i);
        len += bstr_len(hl->line);
        if (hl->terminators)
            len += bstr_len(hl->terminators);
        else
            len += 2; // 0d 0a
    }

    response_headers_raw = bstr_alloc(len);
    if (response_headers_raw == NULL) {
        htp_log(tx->connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Failed to allocate bstring of %d bytes", len);
        return NULL;
    }

    for (i = 0; i < list_size(tx->response_header_lines); i++) {
        htp_header_line_t *hl = list_get(tx->response_header_lines, i);
        bstr_add_str_noex(response_headers_raw, hl->line);
        if (hl->terminators)
            bstr_add_str_noex(response_headers_raw, hl->terminators);
        else
            bstr_add_cstr_noex(response_headers_raw, "\r\n");
    }

    return response_headers_raw;
}

/**
 * Get a bstr that contains the raw response headers. This method will always
 * return an up-to-date buffer, containing the last known headers. Thus, if
 * it is called once after RESPONSE_HEADERS phase it will return one buffer, but
 * it may return a different buffer if called after RESPONSE_TRAILERS phase (but
 * only if the response actually contains trailer headers). Do not retain the
 * bstr pointer, as the buffer may change. If there are no changes to the
 * response header structure, only one buffer will be contstructed and used. (Multiple
 * invocations of this method will not cause multiple buffers to be created.)
 *
 * @param tx
 * @return
 */
bstr *htp_tx_get_response_headers_raw(htp_tx_t *tx) {
    // Check that we are not called too early
    if (tx->progress < TX_PROGRESS_RES_HEADERS) return NULL;

    if (tx->response_headers_raw == NULL) {
        tx->response_headers_raw = htp_tx_generate_response_headers_raw(tx);
        tx->response_headers_raw_lines = list_size(tx->response_header_lines);
    } else {
        // Check that the buffer we have is not obsolete
        if (tx->response_headers_raw_lines < list_size(tx->response_header_lines)) {
            // Rebuild raw buffer
            bstr_free(tx->response_headers_raw);
            tx->response_headers_raw = htp_tx_generate_response_headers_raw(tx);
            tx->response_headers_raw_lines = list_size(tx->response_header_lines);
        }
    }

    return tx->response_headers_raw;
}
