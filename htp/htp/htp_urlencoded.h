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

#ifndef _HTP_URLENCODED_H
#define	_HTP_URLENCODED_H

typedef struct htp_urlenp_t htp_urlenp_t;
typedef struct htp_urlen_param_t htp_urlen_param_t;

#include "htp.h"

#define HTP_URLENP_DEFAULT_PARAMS_SIZE 32

#define HTP_URLENP_STATE_KEY        1
#define HTP_URLENP_STATE_VALUE      2

/**
 * This is the main URLENCODED parser structure. It is used to store
 * parser configuration, temporary parsing data, as well as the parameters.
 */
struct htp_urlenp_t {
    /** The character used to separate parameters. Defaults to & and should
     *  not be changed without good reason.
     */
    unsigned char argument_separator;

    /** Whether to perform URL-decoding on parameters. */
    int decode_url_encoding;

    /** This table contains the list of parameters, indexed by name. */
    table_t *params;

    // Private fields; they are used during the parsing process
    int _state;
    int _complete;
    bstr *_name;
    bstr_builder_t *_bb;
};

/**
 * Holds one application/x-www-form-urlencoded parameter.
 */
struct htp_urlen_param_t {
    /** Parameter name. */
    bstr *name;

    /** Parameter value. */
    bstr *value;
};

htp_urlenp_t *htp_urlenp_create();
void htp_urlenp_destroy(htp_urlenp_t *urlenp);

void htp_urlenp_set_argument_separator(htp_urlenp_t *urlenp, unsigned char argument_separator);
void htp_urlenp_set_decode_url_encoding(htp_urlenp_t *urlenp, int decode_url_encoding);

int  htp_urlenp_parse_partial(htp_urlenp_t *urlenp, unsigned char *data, size_t len);
int  htp_urlenp_parse_complete(htp_urlenp_t *urlenp, unsigned char *data, size_t len);
int  htp_urlenp_finalize(htp_urlenp_t *urlenp);

#endif	/* _HTP_URLENCODED_H */

