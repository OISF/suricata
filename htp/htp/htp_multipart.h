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

#ifndef _HTP_MULTIPART_H
#define	_HTP_MULTIPART_H

typedef struct htp_mpartp_t htp_mpartp_t;
typedef struct htp_mpart_part_t htp_mpart_part_t;

#include "bstr.h"
#include "dslib.h"

#define MULTIPART_PART_UNKNOWN              0
#define MULTIPART_PART_TEXT                 1
#define MULTIPART_PART_FILE                 2
#define MULTIPART_PART_PREAMBLE             3
#define MULTIPART_PART_EPILOGUE             4

#define MULTIPART_MODE_LINE                 0
#define MULTIPART_MODE_DATA                 1

#define MULTIPART_STATE_DATA                1
#define MULTIPART_STATE_BOUNDARY            2
#define MULTIPART_STATE_BOUNDARY_IS_LAST1   3
#define MULTIPART_STATE_BOUNDARY_IS_LAST2   4
//#define MULTIPART_STATE_BOUNDARY_EAT_CRLF   5
#define MULTIPART_STATE_BOUNDARY_EAT_LF     6

#ifndef CR
#define CR '\r'
#endif

#ifndef LF
#define LF '\n'
#endif

struct htp_mpart_part_t {
    /** Pointer to the parser. */
    htp_mpartp_t *mpartp;

    /** Part type; see the MULTIPART_PART_* constants. */
    int type;

    /** Raw part length. */
    size_t len;

    /** Part name, from the Content-Disposition header. */
    bstr *name;

    /** Part filename, from the Content-Disposition header. */
    bstr *filename;

    /** Part value; currently only available for MULTIPART_PART_TEXT parts. */
    bstr *value;

    /** Part headers (htp_header_t instances), indexed by name. */
    table_t *headers;
};

struct htp_mpartp_t {
    /** Boundary to be used to extract parts. */
    char *boundary;

    /** Boundary length. */
    size_t boundary_len;

    /** How many boundaries were seen? */
    int boundary_count;

    /** Did we see the last boundary? */
    int seen_last_boundary;

    /** List of parts. */
    list_t *parts;

    // Parsing callbacks
    int (*handle_data)(htp_mpartp_t *mpartp, unsigned char *data, size_t len, int line_end);
    int (*handle_boundary)(htp_mpartp_t *mpartp);

    // Internal parsing fields
    // TODO Consider prefixing them with an underscore.
    int state;
    size_t bpos;
    unsigned char *current_data;
    htp_mpart_part_t *current_part;
    int current_mode;
    size_t current_len;
    bstr_builder_t *boundary_pieces;
    bstr_builder_t *part_pieces;
    int pieces_form_line;
    unsigned char first_boundary_byte;
    size_t boundarypos;
    int cr_aside;
};

htp_mpartp_t *htp_mpartp_create(char *boundary);
void htp_mpartp_destroy(htp_mpartp_t *mpartp);

int htp_mpartp_parse(htp_mpartp_t *mpartp, unsigned char *data, size_t len);
int htp_mpartp_finalize(htp_mpartp_t *mpartp);

htp_mpart_part_t *htp_mpart_part_create(htp_mpartp_t *mpartp);
int htp_mpart_part_receive_data(htp_mpart_part_t *part, unsigned char *data, size_t len, int line);
int htp_mpart_part_finalize_data(htp_mpart_part_t *part);
void htp_mpart_part_destroy(htp_mpart_part_t *part);

#endif	/* _HTP_MULTIPART_H */


