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

#ifndef _HTP_DECOMPRESSORS_H
#define	_HTP_DECOMPRESSORS_H

typedef struct htp_decompressor_gzip_t htp_decompressor_gzip_t;
typedef struct htp_decompressor_t htp_decompressor_t;

#include "zlib.h"

#define GZIP_BUF_SIZE       8192
#define GZIP_WINDOW_SIZE    -15

#define DEFLATE_MAGIC_1     0x1f
#define DEFLATE_MAGIC_2     0x8b

struct htp_decompressor_t {
    int (*decompress)(htp_decompressor_t *, htp_tx_data_t *);
    int (*callback)(htp_tx_data_t *);
    void (*destroy)(htp_decompressor_t *);
};

struct htp_decompressor_gzip_t {
    htp_decompressor_t super;
    int initialized;
    int zlib_initialized;
    uint8_t header[10];
    uint8_t header_len;
    z_stream stream;
    unsigned char *buffer;
    unsigned long crc;    
};

htp_decompressor_t * htp_gzip_decompressor_create(htp_connp_t *connp);

#endif	/* _HTP_DECOMPRESSORS_H */

