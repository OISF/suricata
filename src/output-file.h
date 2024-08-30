/* Copyright (C) 2007-2024 Open Information Security Foundation
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
 * AppLayer File Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_FILE_H
#define SURICATA_OUTPUT_FILE_H

#include "rust.h"

/** per thread data for this module, contains a list of per thread
 *  data for the packet loggers. */
typedef struct OutputFileLoggerThreadData_ {
    OutputLoggerThreadStore *store;
#ifdef HAVE_MAGIC
    magic_t magic_ctx;
#endif
} OutputFileLoggerThreadData;

TmEcode OutputFileLogThreadInit(ThreadVars *tv, OutputFileLoggerThreadData **data);
TmEcode OutputFileLogThreadDeinit(ThreadVars *tv, OutputFileLoggerThreadData *thread_data);

void OutputFileLogFfc(ThreadVars *tv, OutputFileLoggerThreadData *op_thread_data, Packet *p,
        FileContainer *ffc, void *txv, const uint64_t tx_id, AppLayerTxData *txd,
        const bool file_close, const bool file_trunc, uint8_t dir);

/** file logger function pointer type */
typedef int (*SCFileLogger)(ThreadVars *, void *thread_data, const Packet *, const File *, void *tx,
        const uint64_t tx_id, uint8_t direction);

/** \brief Register a file logger.
 *
 * \param logger_id An ID used to distinguish this logger from others
 *     while profiling.
 *
 * \param name An informational name for this logger. Used only for
 *     debugging.
 *
 * \param LogFunc A function that will be called to log each file to be logged.
 *
 * \param initdata Initialization data that will pass to the
 *     ThreadInitFunc.
 *
 * \param ThreadInitFunc Thread initialization function.
 *
 * \param ThreadDeinitFunc Thread de-initialization function.
 *
 * \retval 0 on success, -1 on failure.
 */
int SCOutputRegisterFileLogger(LoggerId id, const char *name, SCFileLogger LogFunc, void *initdata,
        ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

/** Internal function: private API. */
void OutputFileLoggerRegister(void);

/** Internal function: private API. */
void OutputFileShutdown(void);

#endif /* SURICATA_OUTPUT_FILE_H */
