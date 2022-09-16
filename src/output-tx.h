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

#ifndef __OUTPUT_TX_H__
#define __OUTPUT_TX_H__

#include "decode.h"
#include "flow.h"

/** tx logger function pointer type */
typedef int (*TxLogger)(ThreadVars *, void *thread_data, const Packet *, Flow *f, void *state, void *tx, uint64_t tx_id);

/** tx logger condition function pointer type,
 *  must return true for tx that should be logged
 */
typedef int (*TxLoggerCondition)(ThreadVars *, const Packet *, void *state, void *tx, uint64_t tx_id);

int OutputRegisterTxLogger(LoggerId id, const char *name, AppProto alproto,
        TxLogger LogFunc,
        OutputCtx *, int tc_log_progress, int ts_log_progress,
        TxLoggerCondition LogCondition,
        ThreadInitFunc, ThreadDeinitFunc,
        void (*ThreadExitPrintStats)(ThreadVars *, void *));

void OutputTxLoggerRegister (void);

void OutputTxShutdown(void);

#endif /* __OUTPUT_TX_H__ */
