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

/*
* \file
*
* \author Andreas Moe <moe.andreas@gmail.com>
*/

#ifndef __LOG_FILELOGCOMMON_H__
#define __LOG_FILELOGCOMMON_H__

#include "util-buffer.h"

#define META_FORMAT_REGULAR 0
#define META_FORMAT_JSON 1
#define META_BUFFER_SIZE 2048
#define CHECK_PROTO_NO 0
#define CHECK_PROTO_YES 1

void LogFileMetaGetSmtpMessageID(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetaGetSmtpSender(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetaGetUri(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetaGetHost(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetaGetReferer(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);
void LogFileMetaGetUserAgent(const Packet *p, const File *ff, MemBuffer *buffer, uint32_t fflag);

#ifdef HAVE_LIBJANSSON
void LogFileLogPrintJsonObj(FILE *fp, json_t *js);
void LogFileLogTransactionMeta(const Packet *p, const File *ff, json_t *js);
void LogFileLogFileMeta(const Packet *p, const File *ff, json_t *js);
#endif

#endif /* __LOG_FILELOG_H__ */
