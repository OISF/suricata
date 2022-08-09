/* Copyright (C) 2016 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 * Common custom logging format
 */

#ifndef __LOG_CF_COMMON_H__
#define __LOG_CF_COMMON_H__

#define LOG_MAXN_NODES 64
#define LOG_NODE_STRLEN 256
#define LOG_NODE_MAXOUTPUTLEN 8192

#define TIMESTAMP_DEFAULT_FORMAT "%D-%H:%M:%S"
#define TIMESTAMP_DEFAULT_FORMAT_LEN 62

/* Common format nodes */
#define LOG_CF_NONE "-"
#define LOG_CF_LITERAL '%'
#define LOG_CF_TIMESTAMP 't'
#define LOG_CF_TIMESTAMP_U 'z'
#define LOG_CF_CLIENT_IP 'a'
#define LOG_CF_SERVER_IP 'A'
#define LOG_CF_CLIENT_PORT 'p'
#define LOG_CF_SERVER_PORT 'P'

/* Line log common separators **/
#define LOG_CF_STAR_SEPARATOR "[**]"
#define LOG_CF_SPACE_SEPARATOR " "
#define LOG_CF_UNKNOWN_VALUE "-"

#define LOG_CF_WRITE_STAR_SEPARATOR(buffer) MemBufferWriteString(buffer, LOG_CF_STAR_SEPARATOR);

#define LOG_CF_WRITE_SPACE_SEPARATOR(buffer) \
    MemBufferWriteString(buffer, LOG_CF_SPACE_SEPARATOR);

#define LOG_CF_WRITE_UNKNOWN_VALUE(buffer) \
    MemBufferWriteString(buffer, LOG_CF_UNKNOWN_VALUE);

/* Include */
#include "suricata-common.h"
#include "util-buffer.h"

typedef struct LogCustomFormatNode_ {
    uint32_t type;              /**< Node format type. ie: LOG_CF_LITERAL, ... */
    uint32_t maxlen;            /**< Maximum length of the data */
    char data[LOG_NODE_STRLEN]; /**< optional data. ie: http header name */
} LogCustomFormatNode;


typedef struct LogCustomFormat_ {
    uint32_t cf_n;                                  /**< Total number of custom string format nodes */
    LogCustomFormatNode *cf_nodes[LOG_MAXN_NODES];  /**< Custom format string nodes */
} LogCustomFormat;

LogCustomFormatNode * LogCustomFormatNodeAlloc(void);
LogCustomFormat * LogCustomFormatAlloc(void);

void LogCustomFormatNodeFree(LogCustomFormatNode *node);
void LogCustomFormatFree(LogCustomFormat *cf);

void LogCustomFormatAddNode(LogCustomFormat *cf, LogCustomFormatNode *node);
int LogCustomFormatParse(LogCustomFormat *cf, const char *format);

void LogCustomFormatWriteTimestamp(MemBuffer *buffer, const char *fmt, const struct timeval *ts);
void LogCustomFormatRegister(void);

#endif /* __LOG_CF_COMMON_H__ */
