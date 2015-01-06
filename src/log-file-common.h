/* Copyright (C) 2007-2014 Open Information Security Foundation
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
 * \author Andreas Moe <moe.andreas@gmail.com>
 */

#ifndef __LOG_FILELOGCOMMON_H__
#define __LOG_FILELOGCOMMON_H__

#include "util-buffer.h"

#ifdef HAVE_LIBJANSSON
#include <jansson.h>
#endif

#define META_FORMAT_REGULAR 0
#define META_FORMAT_JSON 1
#define META_BUFFER_SIZE 2048
#define META_MD5_BUFFER 512

void LogFileMetadataGetSmtpMessageID(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetadataGetSmtpSender(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetadataGetUri(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetadataGetHost(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetadataGetReferer(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetadataGetUserAgent(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);

#ifdef HAVE_LIBJANSSON
typedef struct LogFileJSON_ {
    json_t *main;
    json_t *meta;
} LogFileJSON;

void LogFileClearJSON(LogFileJSON *json_data);
void LogFileCreateJSON(const Packet *p, const char *name, json_t *main, json_t *metadata);
void LogFileLogPrintJsonObj(FILE *fp, json_t *js);
int LogFileLogTransactionMeta(const Packet *p, const File *ff, json_t *js, MemBuffer *buffer);
int LogFileLogFileMeta(const Packet *p, const File *ff, json_t *js, MemBuffer *buffer);
#endif

#endif /* __LOG_FILELOG_H__ */
