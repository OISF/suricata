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
 * AppLayer TX Logger Output registration functions
 */

#ifndef SURICATA_OUTPUT_TX_H
#define SURICATA_OUTPUT_TX_H

#include "tm-threads.h"
#include "decode.h"
#include "flow.h"

/** \brief Transaction logger function pointer type. */
typedef int (*TxLogger)(ThreadVars *, void *thread_data, const Packet *, Flow *f, void *state, void *tx, uint64_t tx_id);

/** \brief Transaction logger condition function pointer type.
 *
 * If a TxLoggerCondition is provided to the registration function,
 * the logger function will only be called if this return true.
 */
typedef bool (*TxLoggerCondition)(
        ThreadVars *, const Packet *, void *state, void *tx, uint64_t tx_id);

/** \brief Register a transaction logger.
 *
 * \param logger_id An ID used to distinguish this logger from others
 *     while profiling. For transaction logging this is only used for
 *     some internal state tracking.
 *
 * \param name An informational name for this logger. Used for
 *     debugging.
 *
 * \param alproto The application layer protocol this logger is for,
 *     for example ALPROTO_DNS.
 *
 * \param LogFunc A pointer to the logging function.
 *
 * \param initdata Initialization data that will be provided to the
 *     ThreadInit callback.
 *
 * \param tc_log_progress The to_client progress state required for
 *     the log function to be called.
 *
 * \param ts_log_progress The to_server progress state required for
 *     the log function to be called.
 *
 * \param LogCondition A pointer to a function that will be called
 *     before the log function to test if the log function should be
 *     called.
 *
 * \param ThreadInitFunc Callback a thread initialization function,
 *     initdata will be provided.
 *
 * \param ThreadDeinitFunc Callback to a thread de-initialization
 *     function for cleanup.
 */
int SCOutputRegisterTxLogger(LoggerId id, const char *name, AppProto alproto, TxLogger LogFunc,
        void *, int tc_log_progress, int ts_log_progress, TxLoggerCondition LogCondition,
        ThreadInitFunc, ThreadDeinitFunc);

/** Internal function: private API. */
void OutputTxLoggerRegister (void);

/** Internal function: private API. */
void OutputTxShutdown(void);

#endif /* SURICATA_OUTPUT_TX_H */
