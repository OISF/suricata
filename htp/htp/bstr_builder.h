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

#ifndef _BSTR_BUILDER_H
#define	_BSTR_BUILDER_H

typedef struct bstr_builder_t bstr_builder_t;

#include "dslib.h"

struct bstr_builder_t {
    list_t *pieces;
};

#define BSTR_BUILDER_DEFAULT_SIZE 16

bstr_builder_t * bstr_builder_create();
void bstr_builder_destroy(bstr_builder_t *bb);

size_t bstr_builder_size(bstr_builder_t *bb);
void bstr_builder_clear(bstr_builder_t *bb);

int bstr_builder_append(bstr_builder_t *bb, bstr *b);
int bstr_builder_append_mem(bstr_builder_t *bb, char *data, size_t len);
int bstr_builder_append_cstr(bstr_builder_t *bb, char *str);
bstr * bstr_builder_to_str(bstr_builder_t *bb);

#endif	/* _BSTR_BUILDER_H */

