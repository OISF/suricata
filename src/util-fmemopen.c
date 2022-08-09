/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 * \author Pablo Rincon Crespo <pablo.rincon.crespo@gmail.com>
 *         Based on FMem.c of Alexandre Flori (2008/10/17 AF)
 */

#include "suricata-common.h"
#include "util-fmemopen.h"

#ifdef OS_DARWIN
#define USE_FMEM_WRAPPER 1
#endif

#ifdef OS_FREEBSD
#define USE_FMEM_WRAPPER 1
#endif

#ifdef __OpenBSD__
#define USE_FMEM_WRAPPER 1
#endif

#ifdef USE_FMEM_WRAPPER

#ifdef OS_WIN32

/**
 * \brief portable version of SCFmemopen for Windows works on top of real temp files
 * \param buffer that holds the file content
 * \param size of the file buffer
 * \param mode mode of the file to open
 * \retval pointer to the file; NULL if something is wrong
 */
FILE *SCFmemopen(void *buf, size_t size, const char *mode)
{
    char temppath[MAX_PATH - 13];
    if (0 == GetTempPath(sizeof(temppath), temppath))
        return NULL;

    char filename[MAX_PATH + 1];
    if (0 == GetTempFileName(temppath, "SC", 0, filename))
        return NULL;

    FILE *f = fopen(filename, "wb");
    if (NULL == f)
        return NULL;

    fwrite(buf, size, 1, f);
    fclose(f);

    return fopen(filename, mode);
}

#else

typedef struct SCFmem_ {
    size_t pos;
    size_t size;
    char *buffer;
} SCFmem;

/**
 * \brief Seek the mem file from offset and whence
 * \param handler pointer to the memfile
 * \param offset number of bytes to move from whence
 * \param whence SEEK_SET, SEEK_CUR, SEEK_END
 * \retval pos the position by the last operation, -1 if sizes are out of bounds
 */
static fpos_t SeekFn(void *handler, fpos_t offset, int whence)
{
    size_t pos = 0;
    SCFmem *mem = handler;

    switch (whence) {
        case SEEK_SET:
            if (offset >= 0 && (size_t)offset <= mem->size) {
                return mem->pos = offset;
            }
        break;
        case SEEK_CUR:
            if (mem->pos + offset <= mem->size)
                return mem->pos += offset;
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
static int ReadFn(void *handler, char *buf, int size)
{
    size_t count = 0;
    SCFmem *mem = handler;
    size_t available = mem->size - mem->pos;
    int is_eof = 0;

    if (size < 0) return - 1;

    if ((size_t)size > available) {
        size = available;
    } else {
        is_eof = 1;
    }

    while (count < (size_t)size)
        buf[count++] = mem->buffer[mem->pos++];

    if (is_eof == 1)
        return 0;

    return count;
}

/**
 * \brief Write into the buffer looking for the available memory limits
 * \param handler pointer to the memfile
 * \param buf buffer to write in the handler
 * \param number of bytes to write
 * \retval count , the number of bytes written
 */
static int WriteFn(void *handler, const char *buf, int size)
{
    size_t count = 0;
    SCFmem *mem = handler;
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
static int CloseFn(void *handler)
{
    SCFree(handler);
    return 0;
}

/**
 * \brief portable version of SCFmemopen for OS X / BSD built on top of funopen()
 * \param buffer that holds the file content
 * \param size of the file buffer
 * \param mode mode of the file to open
 * \retval pointer to the file; NULL if something is wrong
 */
FILE *SCFmemopen(void *buf, size_t size, const char *mode)
{
    SCFmem *mem = (SCFmem *) SCMalloc(sizeof(SCFmem));
    if (mem == NULL)
        return NULL;

    memset(mem, 0, sizeof(SCFmem));
    mem->size = size, mem->buffer = buf;

    return funopen(mem, ReadFn, WriteFn, SeekFn, CloseFn);
}

#endif /* OS_WIN32 */

#endif /* USE_FMEM_WRAPPER */
