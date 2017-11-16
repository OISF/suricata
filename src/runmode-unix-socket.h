/* Copyright (C) 2012 Open Information Security Foundation
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
 *  \author Eric Leblond <eric@regit.org>
 */

#ifndef __RUNMODE_UNIX_SOCKET_H__
#define __RUNMODE_UNIX_SOCKET_H__

void RunModeUnixSocketRegister(void);
const char *RunModeUnixSocketGetDefaultMode(void);

int RunModeUnixSocketIsActive(void);

void UnixSocketPcapFile(TmEcode tm);

#ifdef BUILD_UNIX_SOCKET
TmEcode UnixSocketRegisterTenantHandler(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketUnregisterTenantHandler(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketRegisterTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketReloadTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketUnregisterTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitAdd(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitRemove(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitList(json_t *cmd, json_t* answer, void *data);
#endif

#endif /* __RUNMODE_UNIX_SOCKET_H__ */
