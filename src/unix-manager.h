/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef UNIX_MANAGER_H
#define UNIX_MANAGER_H

#define UNIX_CMD_TAKE_ARGS 1

extern SCCtrlCondT unix_manager_ctrl_cond;
extern SCCtrlMutex unix_manager_ctrl_mutex;

int UnixManagerInit(void);
void UnixManagerThreadSpawn(int mode);
void UnixSocketKillSocketThread(void);

#ifdef BUILD_UNIX_SOCKET
TmEcode UnixManagerRegisterCommand(const char * keyword,
        TmEcode (*Func)(json_t *, json_t *, void *),
        void *data, int flags);
TmEcode UnixManagerRegisterBackgroundTask(
        TmEcode (*Func)(void *),
        void *data);
#endif

void TmModuleUnixManagerRegister(void);
void UnixManagerThreadSpawnNonRunmode(void);

#endif /* UNIX_MANAGER_H */
