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
 * AppLayer Filedata Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_FILEDATA_H
#define SURICATA_OUTPUT_FILEDATA_H

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
        AppLayerGetFileState files, void *txv, const uint64_t tx_id, AppLayerTxData *txd,
        const uint8_t call_flags, const bool file_close, const bool file_trunc, const uint8_t dir);

/**
 * \brief File-data logger function pointer type.
 */
typedef int (*SCFiledataLogger)(ThreadVars *, void *thread_data, const Packet *, File *, void *tx,
        const uint64_t tx_id, const uint8_t *, uint32_t, uint8_t, uint8_t dir);

/** \brief Register a file-data logger.
 *
 * \param logger_id An ID used to distinguish this logger from others
 *     while profiling.
 *
 * \param name An informational name for this logger. Used only for
 *     debugging.
 *
 * \param LogFunc A function that will be called to log each file-data.
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
int SCOutputRegisterFiledataLogger(LoggerId id, const char *name, SCFiledataLogger LogFunc,
        void *initdata, ThreadInitFunc ThreadInit, ThreadDeinitFunc ThreadDeinit);

void OutputFiledataLoggerRegister(void);

void OutputFiledataShutdown(void);

#endif /* SURICATA_OUTPUT_FILEDATA_H */
