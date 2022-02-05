/* Copyright (C) 2007-2022 Open Information Security Foundation
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

#ifndef __OUTPUT_FILEDATA_H__
#define __OUTPUT_FILEDATA_H__

#include "decode.h"
#include "util-file.h"

#define OUTPUT_FILEDATA_FLAG_OPEN  0x01
#define OUTPUT_FILEDATA_FLAG_CLOSE 0x02

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputFiledataLoggerThreadData_ {
    OutputLoggerThreadStore *store;
#ifdef HAVE_MAGIC
    magic_t magic_ctx;
#endif
} OutputFiledataLoggerThreadData;

TmEcode OutputFiledataLogThreadInit(ThreadVars *tv, OutputFiledataLoggerThreadData **data);
TmEcode OutputFiledataLogThreadDeinit(ThreadVars *tv, OutputFiledataLoggerThreadData *thread_data);

void OutputFiledataLogFfc(ThreadVars *tv, OutputFiledataLoggerThreadData *td, Packet *p,
        FileContainer *ffc, void *txv, const uint64_t tx_id, AppLayerTxData *txd,
        const uint8_t call_flags, const bool file_close, const bool file_trunc, const uint8_t dir);

/** filedata logger function pointer type */
typedef int (*FiledataLogger)(ThreadVars *, void *thread_data, const Packet *, File *, void *tx,
        const uint64_t tx_id, const uint8_t *, uint32_t, uint8_t, uint8_t dir);

int OutputRegisterFiledataLogger(LoggerId id, const char *name,
    FiledataLogger LogFunc, OutputCtx *, ThreadInitFunc ThreadInit,
    ThreadDeinitFunc ThreadDeinit,
    ThreadExitPrintStatsFunc ThreadExitPrintStats);

void OutputFiledataLoggerRegister(void);

void OutputFiledataShutdown(void);

#endif /* __OUTPUT_FILEDATA_H__ */
