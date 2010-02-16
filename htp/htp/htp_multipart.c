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
#include "htp_multipart.h"

#define PARAM_OTHER     0
#define PARAM_NAME      1
#define PARAM_FILENAME  2

/**
 * Determines the type of a Content-Disposition parameter.
 *
 * @param data
 * @param startpos
 * @param pos
 * @return PARAM_OTHER, PARAM_NAME or PARAM_FILENAME
 */
static int htp_mpartp_cd_param_type(unsigned char *data, size_t startpos, size_t pos) {
    if ((pos - startpos) == 4) {
        if (memcmp(data + startpos, "name", 4) == 0) return PARAM_NAME;
    } else if ((pos - startpos) == 8) {
        if (memcmp(data + startpos, "filename", 8) == 0) return PARAM_FILENAME;
    }

    return PARAM_OTHER;
}

/**
 * Process part headers. In the current implementation, we only parse the
 * Content-Disposition header if it is present.
 *
 * @param part
 * @return Success indication
 */
int htp_mpart_part_process_headers(htp_mpart_part_t *part) {
    // Find C-D header
    htp_header_t *h = (htp_header_t *) table_getc(part->headers, "content-disposition");
    if (h == NULL) {
        // TODO Error message
        return 0;
    }

    // fprint_raw_data(stderr, "C-D", (unsigned char *) bstr_ptr(h->value), bstr_len(h->value));

    if (bstr_indexofc(h->value, "form-data") != 0) {
        return -1;
    }

    // The parsing starts here
    unsigned char *data = (unsigned char *) bstr_ptr(h->value);
    size_t len = bstr_len(h->value);
    size_t pos = 9; // Start after "form-data"

    // Main parameter parsing loop (once per parameter)
    while (pos < len) {
        // Find semicolon and go over it
        while ((pos < len) && ((data[pos] == '\t') || (data[pos] == ' '))) pos++;
        if (pos == len) return -2;

        // Semicolon
        if (data[pos] != ';') return -3;
        pos++;

        // Go over the whitespace before parameter name
        while ((pos < len) && ((data[pos] == '\t') || (data[pos] == ' '))) pos++;
        if (pos == len) return -4;

        // Found starting position (name)
        size_t start = pos;

        // Look for ending position
        while ((pos < len) && (data[pos] != '\t') && (data[pos] != ' ') && (data[pos] != '=')) pos++;
        if (pos == len) return -5;

        // Ending position is in "pos" now

        // Is it a parameter we are interested in?
        int param_type = htp_mpartp_cd_param_type(data, start, pos);

        // Ignore whitespace
        while ((pos < len) && ((data[pos] == '\t') || (data[pos] == ' '))) pos++;
        if (pos == len) return -6;

        // Equals
        if (data[pos] != '=') return -7;
        pos++;

        // Go over the whitespace before value
        while ((pos < len) && ((data[pos] == '\t') || (data[pos] == ' '))) pos++;
        if (pos == len) return -8;

        // Found starting point (value)
        start = pos;

        // Quoting char indicator
        int qchar = -1;

        // Different handling for quoted and bare strings
        if (data[start] == '"') {
            // Quoted string
            qchar = data[start];
            start = ++pos;

            // Find the end of the value
            while ((pos < len) && (data[pos] != qchar)) {
                if (data[pos] == '\\') {
                    // Ignore invalid quoting pairs
                    if (pos + 1 < len) return -9;
                    // Go over the quoted character
                    pos++;
                }

                pos++;
            }
        } else {
            // Bare string
            while ((pos < len) && (!htp_is_token(data[pos]))) pos++;
        }

        switch (param_type) {
            case PARAM_NAME:
                // TODO Unquote
                part->name = bstr_memdup((char *)data + start, pos - start);
                // fprint_raw_data(stderr, "NAME", (unsigned char *) bstr_ptr(part->name), bstr_len(part->name));
                break;
            case PARAM_FILENAME:
                // TODO Unquote
                part->filename = bstr_memdup((char *)data + start, pos - start);
                // fprint_raw_data(stderr, "FILENAME", (unsigned char *) bstr_ptr(part->filename), bstr_len(part->filename));
                break;
            default:
                // Ignore unknown parameter
                // TODO Warn/log?
                break;
        }

        // Skip over the quoting character
        if (qchar != -1) {
            pos++;
        }

        // Continue to parse the next parameter, if any
    }

    return 1;
}

/**
 * Parses one part header.
 *
 * @param data
 * @param len
 * @param Success indication
 */
int htp_mpartp_parse_header(htp_mpart_part_t *part, unsigned char *data, size_t len) {
    size_t name_start, name_end;
    size_t value_start, value_end;

    name_start = 0;

    // Look for the colon
    size_t colon_pos = 0;

    while ((colon_pos < len) && (data[colon_pos] != ':')) colon_pos++;

    if (colon_pos == len) {
        // Missing colon
        // TODO Error message
        return -1;
    }

    if (colon_pos == 0) {
        // Empty header name
        // TODO Error message
    }

    name_end = colon_pos;

    // Ignore LWS after field-name
    size_t prev = name_end - 1;
    while ((prev > name_start) && (htp_is_lws(data[prev]))) {
        prev--;
        name_end--;

        // LWS after field name
        // TODO Error message
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

    while (value_end < len) value_end++;

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
            // Request field is not a token
            // TODO Error message

            break;
        }

        i++;
    }

    // Now extract the name and the value
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return -1;

    h->name = bstr_memdup((char *) data + name_start, name_end - name_start);
    h->value = bstr_memdup((char *) data + value_start, value_end - value_start);

    // Check if the header already exists
    htp_header_t * h_existing = table_get(part->headers, h->name);
    if (h_existing != NULL) {
        // Add to existing header
        h_existing->value = bstr_expand(h_existing->value, bstr_len(h_existing->value)
            + 2 + bstr_len(h->value));
        bstr_add_mem_noex(h_existing->value, ", ", 2);
        bstr_add_str_noex(h_existing->value, h->value);

        // The header is no longer needed
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);

        // Keep track of same-name headers
        h_existing->flags |= HTP_FIELD_REPEATED;
    } else {
        // Add as a new header

        table_add(part->headers, h->name, h);
    }

    return 1;
}

/**
 * Creates new multipart part.
 *
 * @param mpartp
 */
htp_mpart_part_t *htp_mpart_part_create(htp_mpartp_t *mpartp) {
    htp_mpart_part_t * part = calloc(1, sizeof (htp_mpart_part_t));
    if (part == NULL) return NULL;

    part->headers = table_create(32);
    if (part->headers == NULL) {
        free(part);
        return NULL;
    }

    part->mpartp = mpartp;
    part->mpartp->pieces_form_line = 0;

    bstr_builder_clear(mpartp->part_pieces);

    return part;
}

/**
 * Destroys multipart part.
 *
 * @param part
 */
void htp_mpart_part_destroy(htp_mpart_part_t *part) {
    if (part == NULL) return;

    bstr_free(part->name);
    bstr_free(part->filename);
    bstr_free(part->value);

    if (part->headers != NULL) {
        // Destroy request_headers
        htp_header_t *h = NULL;
        table_iterator_reset(part->headers);
        while (table_iterator_next(part->headers, (void **) & h) != NULL) {

            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
        }

        table_destroy(part->headers);
    }

    free(part);
}

/**
 * Finalizes part processing.
 *
 * @param part
 */
int htp_mpart_part_finalize_data(htp_mpart_part_t *part) {
    // We currently do not process the preamble and epilogue parts
    if ((part->type == MULTIPART_PART_PREAMBLE) || (part->type == MULTIPART_PART_EPILOGUE)) return 1;

    if (bstr_builder_size(part->mpartp->part_pieces) > 0) {

        part->value = bstr_builder_to_str(part->mpartp->part_pieces);
        bstr_builder_clear(part->mpartp->part_pieces);
        // fprint_raw_data(stderr, "PART DATA", (unsigned char *) bstr_ptr(part->value), bstr_len(part->value));
    }

    return 1;
}

/**
 * Handles part data.
 *
 * @param part
 * @param data
 * @param len
 * @param is_line
 */
int htp_mpart_part_handle_data(htp_mpart_part_t *part, unsigned char *data, size_t len, int is_line) {
    // fprint_raw_data_ex(stderr, "PART DATA", data, 0, len);
    // printf("PART DATA is_line %d mode %d\n", is_line, part->mpartp->current_mode);

    // TODO We don't actually need the is_line parameter, because we can
    //      discover that ourselves by looking at the last byte in the buffer.

    // Keep track of part length
    part->len += len;

    // We currently do not process the preamble and epilogue parts
    if ((part->type == MULTIPART_PART_PREAMBLE) || (part->type == MULTIPART_PART_EPILOGUE)) return 1;

    if (part->mpartp->current_mode == MULTIPART_MODE_LINE) {
        // Line mode

        // TODO Remove the extra characters from folded lines

        if (is_line) {
            // End of line

            // Ignore the line ending
            if (len > 1) {
                if (data[len - 1] == LF) len--;
                if (data[len - 1] == CR) len--;
            } else if (len > 0) {
                if (data[len - 1] == LF) len--;
            }

            // Is it an empty line?
            if ((len == 0) && ((bstr_builder_size(part->mpartp->part_pieces) == 0))) {
                // Empty line; switch to data mode
                part->mpartp->current_mode = MULTIPART_MODE_DATA;
                htp_mpart_part_process_headers(part); // TODO RC
            } else {
                // Not an empty line

                // Is there a folded line coming after this one?
                if ((part->mpartp->first_boundary_byte != ' ') && (part->mpartp->first_boundary_byte != '\t')) {
                    // No folded lines after this one, so process header

                    // Do we have more than once piece?
                    if (bstr_builder_size(part->mpartp->part_pieces) > 0) {
                        // Line in pieces

                        bstr_builder_append_mem(part->mpartp->part_pieces, (char *) data, len);

                        bstr *line = bstr_builder_to_str(part->mpartp->part_pieces); // TODO RC
                        // fprint_raw_data(stderr, "LINE(1)", (unsigned char *) bstr_ptr(line), bstr_len(line));
                        htp_mpartp_parse_header(part, (unsigned char *) bstr_ptr(line), bstr_len(line)); // TODO RC
                        bstr_free(line);

                        bstr_builder_clear(part->mpartp->part_pieces);
                    } else {
                        // Just this line
                        htp_mpartp_parse_header(part, data, len); // TODO RC
                    }

                    part->mpartp->pieces_form_line = 0;
                } else {
                    // Folded line, just store this piece for later
                    bstr_builder_append_mem(part->mpartp->part_pieces, (char *) data, len);
                    part->mpartp->pieces_form_line = 1;
                }
            }
        } else {
            // Not end of line; keep the data chunk for later
            bstr_builder_append_mem(part->mpartp->part_pieces, (char *) data, len);
            part->mpartp->pieces_form_line = 0;
        }
    } else {
        // Data mode; keep the data chunk for later (but not if it is a file)
        if (part->type != MULTIPART_PART_FILE) {

            bstr_builder_append_mem(part->mpartp->part_pieces, (char *) data, len);
        }
    }

    return 1;
}

/**
 * Handles data, creating new parts as necessary.
 *
 * @param mpartp
 * @param data
 * @param len
 * @param is_line
 */
static int htp_mpartp_handle_data(htp_mpartp_t *mpartp, unsigned char *data, size_t len, int is_line) {
    if (len == 0) return 1;

    // Do we have a part already?
    if (mpartp->current_part == NULL) {
        // Create new part
        mpartp->current_part = htp_mpart_part_create(mpartp);
        if (mpartp->current_part == NULL) return -1; // TODO RC

        if (mpartp->boundary_count == 0) {
            mpartp->current_part->type = MULTIPART_PART_PREAMBLE;
            mpartp->current_mode = MULTIPART_MODE_DATA;
        } else {
            if (mpartp->seen_last_boundary) {
                mpartp->current_part->type = MULTIPART_PART_EPILOGUE;
                mpartp->current_mode = MULTIPART_MODE_DATA;
            }
        }

        // Add part to the list.
        // TODO Perhaps we need a flag to know if a part has been finalized.
        list_push(mpartp->parts, mpartp->current_part);
    }

    // Send data to part
    htp_mpart_part_handle_data(mpartp->current_part, data, len, is_line); // TODO RC

    return 1;
}

/**
 * Handles a boundary event, which means that it will finalize a part
 * if one exists.
 *
 * @param mpartp
 */
static int htp_mpartp_handle_boundary(htp_mpartp_t * mpartp) {
    // TODO Having mpartp->seen_last_boundary set here means that there's
    //      a boundary after the "last boundary".

    if (mpartp->current_part != NULL) {

        if (htp_mpart_part_finalize_data(mpartp->current_part) < 0) return -1; // TODO RC

        // We're done with this part
        mpartp->current_part = NULL;

        // Revert to line mode
        mpartp->current_mode = MULTIPART_MODE_LINE;
    }

    return 1;
}

/**
 * Creates a new multipart/form-data parser.
 *
 * @param boundary
 * @return New parser, or NULL on memory allocation failure.
 */
htp_mpartp_t * htp_mpartp_create(char *boundary) {
    htp_mpartp_t *mpartp = calloc(1, sizeof (htp_mpartp_t));
    if (mpartp == NULL) return NULL;

    mpartp->boundary_pieces = bstr_builder_create();
    if (mpartp->boundary_pieces == NULL) {
        free(mpartp);
        return NULL;
    }

    mpartp->part_pieces = bstr_builder_create();
    if (mpartp->part_pieces == NULL) {
        bstr_builder_destroy(mpartp->boundary_pieces);
        free(mpartp);
        return NULL;
    }

    mpartp->parts = list_array_create(64);
    if (mpartp->parts == NULL) {
        bstr_builder_destroy(mpartp->part_pieces);
        bstr_builder_destroy(mpartp->boundary_pieces);
        free(mpartp);
        return NULL;
    }

    // Copy the boundary and convert it to lowercase

    mpartp->boundary_len = strlen(boundary) + 4;
    mpartp->boundary = malloc(mpartp->boundary_len + 1);
    if (mpartp->boundary == NULL) {
        bstr_builder_destroy(mpartp->boundary_pieces);
        free(mpartp);
        return NULL;
    }

    // TODO Not using the CR and LF any more
    mpartp->boundary[0] = CR;
    mpartp->boundary[1] = LF;
    mpartp->boundary[2] = '-';
    mpartp->boundary[3] = '-';

    size_t i = 4;
    while (i < mpartp->boundary_len) {
        mpartp->boundary[i] = tolower((int) ((unsigned char) boundary[i - 4]));
        i++;
    }

    mpartp->state = MULTIPART_STATE_BOUNDARY;
    mpartp->bpos = 2;

    mpartp->handle_data = htp_mpartp_handle_data;
    mpartp->handle_boundary = htp_mpartp_handle_boundary;

    return mpartp;
}

/**
 * Destroys a multipart/form-data parser.
 *
 * @param mpartp
 */
void htp_mpartp_destroy(htp_mpartp_t * mpartp) {
    if (mpartp == NULL) return;

    free(mpartp->boundary);

    bstr_builder_destroy(mpartp->part_pieces);
    bstr_builder_destroy(mpartp->boundary_pieces);

    // Free parts
    htp_mpart_part_t * part = NULL;
    list_iterator_reset(mpartp->parts);
    while ((part = list_iterator_next(mpartp->parts)) != NULL) {
        htp_mpart_part_destroy(part);
    }

    list_destroy(mpartp->parts);

    free(mpartp);
}

/**
 * Processes set-aside data.
 *
 * @param mpartp
 * @param data
 * @param pos
 * @param startpos
 * @param return_pos
 * @param matched
 */
static int htp_martp_process_aside(htp_mpartp_t *mpartp, int matched) {
    // The store data pieces can contain up to one line. If we're in data mode and there
    // was no boundary match, things are straightforward -- we process everything as data.
    // If there was a match, we need to take care to not send the line ending as data, nor
    // anything that follows (because it's going to be a part of the boundary). Similary,
    // when we are in line mode, we need to split the first data chunk, processing the first
    // part as line and the second part as data.

    // Do we need to do any chunk splitting?
    if (matched || (mpartp->current_mode == MULTIPART_MODE_LINE)) {
        // Line mode or boundary match

        // In line mode, we ignore lone CR bytes
        mpartp->cr_aside = 0;

        // We know that we went to match a boundary because
        // we saw a new line. Now we have to find that line and
        // process it. It's either going to be in the current chunk,
        // or in the first stored chunk.
        if (bstr_builder_size(mpartp->boundary_pieces) > 0) {
            // We have stored chunks

            bstr *b = NULL;
            int first = 1;
            list_iterator_reset(mpartp->boundary_pieces->pieces);
            while ((b = list_iterator_next(mpartp->boundary_pieces->pieces)) != NULL) {
                if (first) {
                    // Split the first chunk

                    if (!matched) {
                        // In line mode, we are OK with line endings
                        mpartp->handle_data(mpartp, (unsigned char *) bstr_ptr(b), mpartp->boundarypos, 1);
                    } else {
                        // But if there was a match, the line ending belongs to the boundary
                        unsigned char *dx = (unsigned char *) bstr_ptr(b);
                        size_t lx = mpartp->boundarypos;

                        // Remove LF or CRLF
                        if ((lx > 0) && (dx[lx - 1] == LF)) {
                            lx--;
                            // Remove CR
                            if ((lx > 0) && (dx[lx - 1] == CR)) {
                                lx--;
                            }
                        }

                        mpartp->handle_data(mpartp, dx, lx, 0);
                    }

                    // The second part of the split chunks belongs to the boundary
                    // when matched, data otherwise.
                    if (!matched) {
                        mpartp->handle_data(mpartp, (unsigned char *) bstr_ptr(b) + mpartp->boundarypos,
                            bstr_len(b) - mpartp->boundarypos, 0);
                    }

                    first = 0;
                } else {
                    // Do not send data if there was a boundary match. The stored
                    // data belongs to the boundary.
                    if (!matched) {
                        mpartp->handle_data(mpartp, (unsigned char *) bstr_ptr(b), bstr_len(b), 0);
                    }
                }
            }

            bstr_builder_clear(mpartp->boundary_pieces);
        }
    } else {
        // Data mode and no match

        // In data mode, we process the lone CR byte as data
        if (mpartp->cr_aside) {
            mpartp->handle_data(mpartp, (unsigned char *) &"\r", 1, 0 /* Not end of line */);
            mpartp->cr_aside = 0;
        }

        // We then process any pieces that we might have stored, also as data
        if (bstr_builder_size(mpartp->boundary_pieces) > 0) {
            bstr *b = NULL;
            list_iterator_reset(mpartp->boundary_pieces->pieces);
            while ((b = list_iterator_next(mpartp->boundary_pieces->pieces)) != NULL) {

                mpartp->handle_data(mpartp, (unsigned char *) bstr_ptr(b), bstr_len(b), 0);
            }

            bstr_builder_clear(mpartp->boundary_pieces);
        }
    }

    return 1;
}

/**
 * Finalize parsing.
 *
 * @param mpartp
 */
int htp_mpartp_finalize(htp_mpartp_t * mpartp) {
    if (mpartp->current_part != NULL) {
        htp_martp_process_aside(mpartp, 0);

        if (htp_mpart_part_finalize_data(mpartp->current_part) < 0) return -1; // TODO RC
    }

    bstr_builder_clear(mpartp->boundary_pieces);

    return 1;
}

/**
 * Parses a chunk of multipart/form-data data. This function should be called
 * as many times as necessary until all data has been consumed.
 *
 * @param mpartp
 * @parma data
 * @param len
 * @return Status indicator
 */
int htp_mpartp_parse(htp_mpartp_t *mpartp, unsigned char *data, size_t len) {
    // fprint_raw_data_ex(stderr, "INPUT", data, 0, len);

    size_t pos = 0; // Current position in the input chunk.
    size_t startpos = 0; // The starting position of data.
    size_t data_return_pos = 0; // The position of the (possible) boundary.
    //size_t local_aside_len = 0; // How many bytes have we put side from this chunk only?

    // Loop while there's data in the buffer
    while (pos < len) {
STATE_SWITCH:
        // fprintf(stderr, "STATE %d pos %d\n", mpartp->state, pos);

        switch (mpartp->state) {

            case MULTIPART_STATE_DATA:
                // We don't need a local aside any more since we're back
                // local_aside_len = 0;

                if ((pos == 0) && (mpartp->cr_aside) && (pos < len)) {
                    mpartp->handle_data(mpartp, (unsigned char *) &"\r", 1, 0);
                    mpartp->cr_aside = 0;
                }

                // Loop through available data
                while (pos < len) {
                    if (data[pos] == CR) {
                        // We have a CR byte

                        // Is this CR the last byte?
                        if (pos + 1 == len) {
                            // We have CR as the last byte in input. We are going to process
                            // what we have in the buffer as data, except for the CR byte,
                            // which we're going to leave for later. If it happens that a
                            // CR is followed by a LF and then a boundary, the CR is going
                            // to be discarded.
                            pos++; // Take CR from input

                            mpartp->cr_aside = 1;
                            // local_aside_len = 1;
                        } else {
                            // We have CR and at least one more byte in the buffer, so we
                            // are able to test for the LF byte too.
                            if (data[pos + 1] == LF) {
                                pos += 2; // Take CR and LF from input

                                // Prepare to switch to boundary testing
                                data_return_pos = pos;
                                mpartp->boundarypos = pos - startpos;
                                mpartp->bpos = 2; // After LF/first dash
                                mpartp->state = MULTIPART_STATE_BOUNDARY;

                                goto STATE_SWITCH;
                            }
                        }
                    } else if (data[pos] == LF) {
                        // Possible boundary start position (LF line)
                        pos++; // Take LF from input

                        // Prepare to switch to boundary testing
                        data_return_pos = pos;
                        mpartp->boundarypos = pos - startpos;
                        mpartp->bpos = 2; // After LF/first dash
                        mpartp->state = MULTIPART_STATE_BOUNDARY;

                        goto STATE_SWITCH;
                    } else {
                        // Take one byte from input
                        pos++;
                        mpartp->cr_aside = 0;
                    }
                } // while

                // End of data; process data chunk
                mpartp->handle_data(mpartp, data + startpos, pos - startpos - mpartp->cr_aside, 0);

                break;

            case MULTIPART_STATE_BOUNDARY:
                // Possible boundary
                while (pos < len) {
                    // fprintf(stderr, "B byte %d desired %d\n", data[pos], mpartp->boundary[mpartp->bpos]);

                    // Remember the first byte in the new line; we'll need to
                    // determine if the line is a part of a folder header.
                    if (mpartp->bpos == 2) {
                        mpartp->first_boundary_byte = data[pos];
                    }

                    // Check if the bytes match
                    if (!(data[pos] == mpartp->boundary[mpartp->bpos])) {
                        // Boundary mismatch

                        // Process stored data
                        htp_martp_process_aside(mpartp, 0);


                        // Return back where DATA parsing left off
                        if (mpartp->current_mode == MULTIPART_MODE_LINE) {
                            // In line mode, we process the line
                            mpartp->handle_data(mpartp, data + startpos, data_return_pos - startpos, 1);
                            startpos = data_return_pos;
                        } else {
                            // In data mode, we go back where we left off
                            pos = data_return_pos;
                        }

                        mpartp->state = MULTIPART_STATE_DATA;
                        goto STATE_SWITCH;
                    }

                    // Consume one matched boundary byte
                    pos++;

                    // Have we seen all boundary bytes?
                    if (++mpartp->bpos == mpartp->boundary_len) {
                        // Boundary match!

                        // Process stored data
                        htp_martp_process_aside(mpartp, 1);

                        // Process data prior to the boundary in the local chunk
                        mpartp->handle_data(mpartp, data + startpos, data_return_pos - startpos, 0);

                        // Keep track of how many boundaries we've seen.
                        mpartp->boundary_count++;

                        // Run boundary match.
                        mpartp->handle_boundary(mpartp);

                        // We now need to check if this is the last boundary in the payload
                        mpartp->state = MULTIPART_STATE_BOUNDARY_IS_LAST2;
                        goto STATE_SWITCH;
                    }
                } // while

                // No more data in the local chunk; store the unprocessed part for later
                bstr_builder_append_mem(mpartp->boundary_pieces, (char *) data + startpos, len - startpos);

                break;

            case MULTIPART_STATE_BOUNDARY_IS_LAST2:
                // We're expecting two dashes
                if (data[pos] == '-') {
                    // Still hoping!
                    pos++;
                    mpartp->state = MULTIPART_STATE_BOUNDARY_IS_LAST1;
                } else {
                    // Hmpf, it's not the last boundary.
                    mpartp->state = MULTIPART_STATE_BOUNDARY_EAT_LF;
                }
                break;

            case MULTIPART_STATE_BOUNDARY_IS_LAST1:
                // One more dash left to go
                if (data[pos] == '-') {
                    // This is indeed the last boundary in the payload
                    pos++;
                    mpartp->seen_last_boundary = 1;
                    mpartp->state = MULTIPART_STATE_BOUNDARY_EAT_LF;
                } else {
                    // The second character is not a dash. This means that we have
                    // an error in the payload. We should report the error and
                    // continue to eat the rest of the line.
                    // TODO Error
                    mpartp->state = MULTIPART_STATE_BOUNDARY_EAT_LF;
                }
                break;

            case MULTIPART_STATE_BOUNDARY_EAT_LF:
                if (data[pos] == LF) {
                    pos++;
                    startpos = pos;
                    mpartp->state = MULTIPART_STATE_DATA;
                } else {
                    // Error!
                    // Unexpected byte; remain in the same state
                    pos++;
                }
                break;
        } // switch
    }

    return 1;
}
