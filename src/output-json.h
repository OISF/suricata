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

void TmModuleOutputJsonRegister (void);

#ifdef HAVE_LIBJANSSON

#include "suricata-common.h"
#include "util-buffer.h"
#include "util-logopenfile.h"

void CreateJSONFlowId(json_t *js, const Flow *f);
void JsonTcpFlags(uint8_t flags, json_t *js);
json_t *CreateJSONHeader(Packet *p, int direction_sensative, char *event_type);
json_t *CreateJSONHeaderWithTxId(Packet *p, int direction_sensitive, char *event_type, uint32_t tx_id);
TmEcode OutputJSON(json_t *js, void *data, uint64_t *count);
int OutputJSONBuffer(json_t *js, LogFileCtx *file_ctx, MemBuffer *buffer);
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

#endif /* HAVE_LIBJANSSON */

#endif /* __OUTPUT_JSON_H__ */
