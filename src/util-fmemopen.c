/**
 * Copyright (c) 2009 Open Information Security Foundation
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *         Based on FMem.c of Alexandre Flori (2008/10/17 AF)
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "util-fmemopen.h"

#ifdef OS_DARWIN
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_FREEBSD
#define USE_FMEM_WRAPPER 1
#endif

#ifdef USE_FMEM_WRAPPER

/**
 * \brief Seek the mem file from offset and whence
 * \param handler pointer to the memfile
 * \param osffset number of bytes to move from whence
 * \param whence SEEK_SET, SEEK_CUR, SEEK_END
 * \retval pos the position by the last operation, -1 if sizes are out of bounds
 */
static fpos_t SeekFn(void *handler, fpos_t offset, int whence) {
    size_t pos = 0;
    fmem_t *mem = handler;

    switch (whence) {
        case SEEK_SET:
            if (offset > 0 && (size_t)offset <= mem->size)
                return mem->pos = offset;
        break;
        case SEEK_CUR:
            if (mem->pos + offset <= mem->size)
                return mem->pos = offset;
        break;
        case SEEK_END:
            /* must be negative */
            if (mem->size + offset <= mem->size)
                return pos = mem->size + offset;
        break;
    }

    return -1;
}

/**
 * \brief Read from the buffer looking for the available memory limits
 * \param handler pointer to the memfile
 * \param buf buffer to read from the handler
 * \param number of bytes to read
 * \retval count , the number of bytes read
 */
static int ReadFn(void *handler, char *buf, int size) {
    size_t count = 0;
    fmem_t *mem = handler;
    size_t available = mem->size - mem->pos;

    if (size < 0) return - 1;

    if ((size_t)size > available)
        size = available;

    while (count < (size_t)size)
        buf[count++] = mem->buffer[mem->pos++];

    return count;
}

/**
 * \brief Write into the buffer looking for the available memory limits
 * \param handler pointer to the memfile
 * \param buf buffer to write in the handler
 * \param number of bytes to write
 * \retval count , the number of bytes writen
 */
static int WriteFn(void *handler, const char *buf, int size) {
    size_t count = 0;
    fmem_t *mem = handler;
    size_t available = mem->size - mem->pos;

    if (size < 0) return - 1;

    if ((size_t)size > available)
        size = available;

    while (count < (size_t)size)
        mem->buffer[mem->pos++] = buf[count++];

    return count;
}

/**
 * \brief close the mem file handler
 * \param handler pointer to the memfile
 * \retval 0 on succesful
 */
static int CloseFn(void *handler) {
    free (handler);
    return 0;
}

/**
 * \brief portable version of SCFmemopen for OS X / BSD built on top of funopen()
 * \param buffer that holds the file content
 * \param size of the file buffer
 * \param mode mode of the file to open
 * \retval pointer to the file; NULL if something is wrong
 */
FILE *SCFmemopen(void *buf, size_t size, const char *mode) {
    fmem_t *mem = (fmem_t *) malloc(sizeof(fmem_t));

    memset(mem, 0, sizeof(fmem_t));
    mem->size = size, mem->buffer = buf;

    return funopen(mem, ReadFn, WriteFn, SeekFn, CloseFn);
}

#endif
