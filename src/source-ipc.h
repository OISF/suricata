/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Danny Browning <danny.browning@protectwise.com>
 */

#ifndef __SOURCE_IPC_H__
#define __SOURCE_IPC_H__

#include "suricata-common.h"
#include "tm-threads.h"
#include "rust-bindings.h"

void TmModuleReceiveIpcRegister (void);
void TmModuleDecodeIpcRegister (void);

/* per packet Ipc vars */
typedef struct IpcThreadVars_
{
    char *server_name;
    IpcClient *ipc;
    intmax_t allocation_batch;
    uint64_t pkts;
    uint64_t bytes;
    TmSlot *slot;
} IpcThreadVars;

#endif /* __SOURCE_IPC_H__ */

