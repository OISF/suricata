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

#include "stdlib.h"

#include "htp_urlencoded.h"

/**
 * This method is invoked whenever a piece of data, belonging to a single field (name or value)
 * becomes available. It will either create a new parameter or store the transient information
 * until a parameter can be created.
 *
 * @param urlenp
 * @param data
 * @param startpos
 * @param endpos
 * @param c Should contain -1 if the reason this function is called is because the end of
 *          the current data chunk is reached.
 */
static void htp_urlenp_add_field_piece(htp_urlenp_t *urlenp, unsigned char *data, size_t startpos, size_t endpos, int c) {
    // Add field if we know it ended or if we know that
    // we've used all of the input data
    if ((c != -1) || (urlenp->_complete)) {
        // Add field
        bstr *field = NULL;

        // Did we use the string builder for this field?
        if (bstr_builder_size(urlenp->_bb) > 0) {
            // The current field consists of more than once piece,
            // we have to use the string builder

            // Add current piece to string builder
            if (endpos - startpos > 0) {
                bstr_builder_append_mem(urlenp->_bb, (char *) data + startpos, endpos - startpos);
            }

            // Generate the field and clear the string builder
            field = bstr_builder_to_str(urlenp->_bb);
            bstr_builder_clear(urlenp->_bb);
        } else {
            // We only have the current piece to work with, so
            // no need to involve the string builder
            field = bstr_memdup((char *) data + startpos, endpos - startpos);
        }

        // Process the field differently, depending on the current state
        if (urlenp->_state == HTP_URLENP_STATE_KEY) {
            // Store the name for later
            urlenp->_name = field;

            if (urlenp->_complete) {
                // Param with key but no value
                htp_urlen_param_t *param = calloc(1, sizeof (htp_urlen_param_t));
                param->name = urlenp->_name;
                urlenp->_name = NULL;
                param->value = bstr_cstrdup("");

                if (urlenp->decode_url_encoding) {
                    htp_uriencoding_normalize_inplace(param->name);
                }

                table_add(urlenp->params, param->name, param);

                #ifdef HTP_DEBUG
                fprint_raw_data(stderr, "NAME", (unsigned char *) bstr_ptr(param->name), bstr_len(param->name));
                fprint_raw_data(stderr, "VALUE", (unsigned char *) bstr_ptr(param->value), bstr_len(param->value));
                #endif
            }
        } else {
            // Param with key and value
            htp_urlen_param_t *param = calloc(1, sizeof (htp_urlen_param_t));
            param->name = urlenp->_name;
            urlenp->_name = NULL;
            param->value = field;

            if (urlenp->decode_url_encoding) {
                htp_uriencoding_normalize_inplace(param->name);
                htp_uriencoding_normalize_inplace(param->value);
            }

            table_add(urlenp->params, param->name, param);

            #ifdef HTP_DEBUG
            fprint_raw_data(stderr, "NAME", (unsigned char *) bstr_ptr(param->name), bstr_len(param->name));
            fprint_raw_data(stderr, "VALUE", (unsigned char *) bstr_ptr(param->value), bstr_len(param->value));
            #endif
        }
    } else {
        // Make a copy of the data and store it in an array for later
        if (endpos - startpos > 0) {
            bstr_builder_append_mem(urlenp->_bb, (char *) data + startpos, endpos - startpos);
        }
    }
}

/**
 * Creates a new URLENCODED parser.
 *
 * @return New parser, or NULL on memory allocation failure.
 */
htp_urlenp_t *htp_urlenp_create() {
    htp_urlenp_t *urlenp = calloc(1, sizeof (htp_urlenp_t));
    if (urlenp == NULL) return NULL;

    urlenp->params = table_create(HTP_URLENP_DEFAULT_PARAMS_SIZE);
    if (urlenp->params == NULL) {
        free(urlenp);
        return NULL;
    }

    urlenp->_bb = bstr_builder_create();
    if (urlenp->_bb == NULL) {
        table_destroy(urlenp->params);
        free(urlenp);
        return NULL;
    }

    urlenp->argument_separator = '&';
    urlenp->decode_url_encoding = 1;
    urlenp->_state = HTP_URLENP_STATE_KEY;

    return urlenp;
}

/**
 * Destroys an existing URLENCODED parser.
 *
 * @param urlenp
 */
void htp_urlenp_destroy(htp_urlenp_t *urlenp) {
    if (urlenp == NULL) return;

    if (urlenp->_name != NULL) {
        bstr_free(urlenp->_name);
    }

    bstr_builder_destroy(urlenp->_bb);

    // Destroy individual parameters
    htp_urlen_param_t *param = NULL;
    table_iterator_reset(urlenp->params);
    while (table_iterator_next(urlenp->params, (void **) & param) != NULL) {
        bstr_free(param->name);
        bstr_free(param->value);
        free(param);
    }

    table_destroy(urlenp->params);

    free(urlenp);
}

/**
 * Finalizes parsing, forcing the parser to convert any outstanding
 * data into parameters. This method should be invoked at the end
 * of a parsing operation that used htp_urlenp_parse_partial().
 *
 * @param urlenp
 * @return Success indication
 */
int htp_urlenp_finalize(htp_urlenp_t *urlenp) {
    return htp_urlenp_parse_complete(urlenp, NULL, 0);
}

/**
 * Parses the provided data chunk under the assumption
 * that it contains all the data that will be parsed. When this
 * method is used for parsing the finalization method should not
 * be invoked.
 *
 * @param urlenp
 * @param data
 * @param len
 * @return
 */
int htp_urlenp_parse_complete(htp_urlenp_t *urlenp, unsigned char *data, size_t len) {
    // TODO urlenp->complete must not already be 1
    urlenp->_complete = 1;
    return htp_urlenp_parse_partial(urlenp, data, len);
}

/**
 * Parses the provided data chunk, keeping state to allow streaming parsing, i.e., the
 * parsing where only partial information is available at any one time. The method
 * htp_urlenp_finalize() must be invoked at the end to finalize parsing.
 *
 * @param urlenp
 * @param data
 * @param len
 * @return
 */
int htp_urlenp_parse_partial(htp_urlenp_t *urlenp, unsigned char *data, size_t len) {
    size_t startpos = 0;
    size_t pos = 0;
    int c;

    if (data == NULL) len = 0;

    for (;;) {
        // Get the next character, or -1
        if (pos < len) c = data[pos];
        else c = -1;

        // printf("Pos %d C %c state %d\n", pos, c, urlenp->state);

        switch (urlenp->_state) {
                // Process key
            case HTP_URLENP_STATE_KEY:
                // Look for =, argument separator, or end of input
                if ((c == '=') || (c == urlenp->argument_separator) || (c == -1)) {
                    // Data from startpos to pos
                    htp_urlenp_add_field_piece(urlenp, data, startpos, pos, c);

                    if (c != -1) {
                        // Next state
                        startpos = pos + 1;
                        urlenp->_state = HTP_URLENP_STATE_VALUE;
                    }
                }
                break;

                // Process value
            case HTP_URLENP_STATE_VALUE:
                // Look for argument separator or end of input
                if ((c == urlenp->argument_separator) || (c == -1)) {
                    // Data from startpos to pos
                    htp_urlenp_add_field_piece(urlenp, data, startpos, pos, c);

                    if (c != -1) {
                        // Next state
                        startpos = pos + 1;
                        urlenp->_state = HTP_URLENP_STATE_KEY;
                    }
                }
                break;
        }

        // Have we reached the end of input?
        if (c == -1) break;

        pos++;
    }

    return HTP_OK;
}
