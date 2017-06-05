/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <td@npulsetech.com>
 */

#ifndef __OUTPUT_JSON_H__
#define __OUTPUT_JSON_H__

#include "suricata-common.h"
#include "util-buffer.h"
#include "util-logopenfile.h"

void OutputJsonRegister(void);

#ifdef HAVE_LIBJANSSON
/* helper struct for OutputJSONMemBufferCallback */
typedef struct OutputJSONMemBufferWrapper_ {
    MemBuffer **buffer; /**< buffer to use & expand as needed */
    size_t expand_by;   /**< expand by this size */
} OutputJSONMemBufferWrapper;

int OutputJSONMemBufferCallback(const char *str, size_t size, void *data);

void JsonAddVars(const Packet *p, const Flow *f, json_t *js);
void CreateJSONFlowId(json_t *js, const Flow *f);
void JsonTcpFlags(uint8_t flags, json_t *js);
void JsonFiveTuple(const Packet *, int, json_t *);
json_t *CreateJSONHeader(const Packet *p, int direction_sensative, const char *event_type);
json_t *CreateJSONHeaderWithTxId(const Packet *p, int direction_sensitive, const char *event_type, uint64_t tx_id);
int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer **buffer);
OutputCtx *OutputJsonInitCtx(ConfNode *);

enum JsonFormat { COMPACT, INDENT };

/*
 * Global configuration context data
 */
typedef struct OutputJsonCtx_ {
    LogFileCtx *file_ctx;
    enum LogFileType json_out;
    enum JsonFormat format;
} OutputJsonCtx;

typedef struct AlertJsonThread_ {
    /** LogFileCtx has the pointer to the file and a mutex to allow multithreading */
    LogFileCtx *file_ctx;
} AlertJsonThread;

json_t *SCJsonBool(int val);

#endif /* HAVE_LIBJANSSON */

#endif /* __OUTPUT_JSON_H__ */
