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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Print utility functions
 */

#include "suricata-common.h"
#include "util-print.h"
#include "util-error.h"
#include "util-debug.h"
#include "util-validate.h"
#include "rust.h"

/**
 *  \brief print a buffer as hex on a single line
 *
 *  Prints in the format "00 AA BB"
 *
 *  \param nbuf buffer into which the output is written
 *  \param offset of where to start writting into the buffer
 *  \param max_size the size of the output buffer
 *  \param buf buffer to print from
 *  \param buflen length of the input buffer
 */
void PrintBufferRawLineHex(char *nbuf, int *offset, int max_size, const uint8_t *buf, uint32_t buflen)
{
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        PrintBufferData(nbuf, offset, max_size, "%02X ", buf[u]);
    }
}

/**
 *  \brief print a buffer as hex on a single line in to retbuf buffer
 *
 *  Prints in the format "00 AA BB"
 *
 *  \param retbuf pointer to the buffer which will have the result
 *  \param rebuflen length of the buffer
 *  \param buf buffer to print from
 *  \param buflen length of the input buffer
 */
void PrintRawLineHexBuf(char *retbuf, uint32_t retbuflen, const uint8_t *buf, uint32_t buflen)
{
    uint32_t offset = 0;
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        PrintBufferData(retbuf, &offset, retbuflen, "%02X ", buf[u]);
    }
}

void PrintRawJsonFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
#define BUFFER_LENGTH 2048
    char nbuf[BUFFER_LENGTH] = "";
    uint32_t offset = 0;
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        if (buf[u] == '\\' || buf[u] == '/' || buf[u] == '\"') {
            PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                             "\\%c", buf[u]);
        } else if (isprint(buf[u])) {
            PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                             "%c", buf[u]);
        } else {
            PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                            "\\\\x%02X", buf[u]);
        }
    }
    fprintf(fp, "%s", nbuf);
}

void PrintRawUriFp(FILE *fp, uint8_t *buf, uint32_t buflen)
{
#define BUFFER_LENGTH 2048
    char nbuf[BUFFER_LENGTH] = "";
    uint32_t offset = 0;
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        if (isprint(buf[u]) && buf[u] != '\"') {
            if (buf[u] == '\\') {
                PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                                "\\\\");
            } else {
                PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                                "%c", buf[u]);
            }
        } else {
            PrintBufferData(nbuf, &offset, BUFFER_LENGTH,
                            "\\x%02X", buf[u]);
        }
    }

    fprintf(fp, "%s", nbuf);
}

void PrintRawUriBuf(char *retbuf, uint32_t *offset, uint32_t retbuflen,
                    uint8_t *buf, uint32_t buflen)
{
    uint32_t u = 0;

    for (u = 0; u < buflen; u++) {
        if (isprint(buf[u]) && buf[u] != '\"') {
            if (buf[u] == '\\') {
                PrintBufferData(retbuf, offset, retbuflen,
                                "\\\\");
            } else {
                PrintBufferData(retbuf, offset, retbuflen,
                                "%c", buf[u]);
            }
        } else {
            PrintBufferData(retbuf, offset, retbuflen,
                            "\\x%02X", buf[u]);
        }
    }

    return;
}

void PrintRawDataFp(FILE *fp, const uint8_t *buf, uint32_t buflen)
{
    int ch = 0;
    uint32_t u = 0;

    if (buf == NULL) {
        fprintf(fp, " (null)\n");
        return;
    }
    for (u = 0; u < buflen; u+=16) {
        fprintf(fp ," %04X  ", u);
        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%02X ", (uint8_t)buf[u+ch]);

             if (ch == 7) fprintf(fp, " ");
        }
        if (ch == 16) fprintf(fp, "  ");
        else if (ch < 8) {
            int spaces = (16 - ch) * 3 + 2 + 1;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        } else if(ch < 16) {
            int spaces = (16 - ch) * 3 + 2;
            int s = 0;
            for ( ; s < spaces; s++) fprintf(fp, " ");
        }

        for (ch = 0; (u+ch) < buflen && ch < 16; ch++) {
             fprintf(fp, "%c", isprint((uint8_t)buf[u+ch]) ? (uint8_t)buf[u+ch] : '.');

             if (ch == 7)  fprintf(fp, " ");
             if (ch == 15) fprintf(fp, "\n");
        }
    }
    if (ch != 16)
        fprintf(fp, "\n");
}

void PrintRawDataToBuffer(uint8_t *dst_buf, uint32_t *dst_buf_offset_ptr, uint32_t dst_buf_size,
                          const uint8_t *src_buf, uint32_t src_buf_len)
{
    int ch = 0;
    uint32_t u = 0;

    for (u = 0; u < src_buf_len; u+=16) {
        PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size,
                        " %04X  ", u);
        for (ch = 0; (u + ch) < src_buf_len && ch < 16; ch++) {
            PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size,
                            "%02X ", (uint8_t)src_buf[u + ch]);

            if (ch == 7) {
                PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size,
                                " ");
            }
        }
        if (ch == 16) {
            PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, "  ");
        } else if (ch < 8) {
            int spaces = (16 - ch) * 3 + 2 + 1;
            int s = 0;
            for ( ; s < spaces; s++)
                PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, " ");
        } else if(ch < 16) {
            int spaces = (16 - ch) * 3 + 2;
            int s = 0;
            for ( ; s < spaces; s++)
                PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, " ");
        }

        for (ch = 0; (u+ch) < src_buf_len && ch < 16; ch++) {
            PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size,
                            "%c",
                            isprint((uint8_t)src_buf[u + ch]) ? (uint8_t)src_buf[u + ch] : '.');

             if (ch == 7)
                 PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, " ");
             if (ch == 15)
                 PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, "\n");
        }
    }
    if (ch != 16)
        PrintBufferData((char *)dst_buf, dst_buf_offset_ptr, dst_buf_size, "\n");

    return;
}

void PrintStringsToBuffer(uint8_t *dst_buf, uint32_t *dst_buf_offset_ptr, uint32_t dst_buf_size,
                          const uint8_t *src_buf, const uint32_t src_buf_len)
{
    uint32_t ch = 0;
    for (ch = 0; ch < src_buf_len && *dst_buf_offset_ptr < dst_buf_size;
            ch++, (*dst_buf_offset_ptr)++) {
        if (isprint((uint8_t)src_buf[ch]) || src_buf[ch] == '\n' || src_buf[ch] == '\r') {
            dst_buf[*dst_buf_offset_ptr] = src_buf[ch];
        } else {
            dst_buf[*dst_buf_offset_ptr] = '.';
        }
    }
    dst_buf[dst_buf_size - 1] = 0;

    return;
}

#ifndef s6_addr16
# define s6_addr16 __u6_addr.__u6_addr16
#endif

static const char *PrintInetIPv6(const void *src, char *dst, socklen_t size)
{
    int i;
    char s_part[6];
    uint16_t x[8];
    memcpy(&x, src, 16);

    /* current IPv6 format is fixed size */
    if (size < 8 * 5) {
        SCLogWarning(SC_ERR_ARG_LEN_LONG, "Too small buffer to write IPv6 address");
        return NULL;
    }
    memset(dst, 0, size);
    for(i = 0; i < 8; i++) {
        snprintf(s_part, sizeof(s_part), "%04x:", htons(x[i]));
        strlcat(dst, s_part, size);
    }
    /* suppress last ':' */
    dst[strlen(dst) - 1] = 0;

    return dst;
}

const char *PrintInet(int af, const void *src, char *dst, socklen_t size)
{
    switch (af) {
        case AF_INET:
#if defined(OS_WIN32) && NTDDI_VERSION >= NTDDI_VISTA
{
            // because Windows has to provide a non-conformant inet_ntop, of
            // course!
            struct in_addr _src;
            memcpy(&_src, src, sizeof(struct in_addr));
            return inet_ntop(af, &_src, dst, size);
}
#else
            return inet_ntop(af, src, dst, size);
#endif
        case AF_INET6:
            /* Format IPv6 without deleting zeroes */
            return PrintInetIPv6(src, dst, size);
        default:
            SCLogError(SC_EINVAL, "Unsupported protocol: %d", af);
    }
    return NULL;
}

void PrintHexString(char *str, size_t size, uint8_t *buf, size_t buf_len)
{
    DEBUG_VALIDATE_BUG_ON(size < 2 * buf_len);
    rs_to_hex((uint8_t *)str, size, buf, buf_len);
}
