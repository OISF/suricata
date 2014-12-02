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
 * \author Victor Julien <victor@inliniac.net>
 *
 * AppLayer Filedata Logger Output registration functions
 */

#ifndef __OUTPUT_STREAMING_H__
#define __OUTPUT_STREAMING_H__

#include "decode.h"
#include "util-file.h"

#define OUTPUT_STREAMING_FLAG_OPEN          0x01
#define OUTPUT_STREAMING_FLAG_CLOSE         0x02
#define OUTPUT_STREAMING_FLAG_TOSERVER      0x04
#define OUTPUT_STREAMING_FLAG_TOCLIENT      0x08
#define OUTPUT_STREAMING_FLAG_TRANSACTION   0x10

enum OutputStreamingType {
    STREAMING_TCP_DATA,
    STREAMING_HTTP_BODIES,
};

/** filedata logger function pointer type */
typedef int (*StreamingLogger)(ThreadVars *, void *thread_data,
        const Flow *f, const uint8_t *data, uint32_t data_len,
        uint64_t tx_id, uint8_t flags);

int OutputRegisterStreamingLogger(const char *name, StreamingLogger LogFunc, OutputCtx *,
        enum OutputStreamingType);

void TmModuleStreamingLoggerRegister (void);

void OutputStreamingShutdown(void);

#endif /* __OUTPUT_STREAMING_H__ */
