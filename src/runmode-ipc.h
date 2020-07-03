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

/** \file
 *
 *  \author Danny Browning <bdbrowning2@gmail.com>
 */
#ifndef __RUNMODE_IPC_H__
#define __RUNMODE_IPC_H__

typedef struct IpcConfig_
{
    char **servers;
    /* number of servers, one acquisition per server */
    int nb_servers;
    /* Packet allocation batch size, defaults to 100 */
    intmax_t allocation_batch;

    /* ref counter for shared config */
    SC_ATOMIC_DECLARE(unsigned int, ref);
    /* ref counter for server index */
    SC_ATOMIC_DECLARE(unsigned int, server_id);
    void (*DerefFunc)(void *);
} IpcConfig;

int RunModeIpcSingle(void);
int RunModeIpcAutoFp(void);
void RunModeIpcRegister(void);
const char *RunModeIpcGetDefaultMode(void);

#endif /* __RUNMODE_IPC_H__ */
