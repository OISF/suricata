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

#ifndef SURICATA_RUNMODE_UNIX_SOCKET_H
#define SURICATA_RUNMODE_UNIX_SOCKET_H

void RunModeUnixSocketRegister(void);
const char *RunModeUnixSocketGetDefaultMode(void);

int RunModeUnixSocketIsActive(void);

TmEcode UnixSocketPcapFile(TmEcode tm, struct timespec *last_processed);

float MemcapsGetPressure(void);

#ifdef BUILD_UNIX_SOCKET
TmEcode UnixSocketDatasetAdd(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketDatasetRemove(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketDatasetDump(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketDatasetClear(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketDatasetLookup(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketDatajsonAdd(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketDatajsonRemove(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketDatajsonReplace(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketRegisterTenantHandler(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketUnregisterTenantHandler(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketRegisterTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketReloadTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketReloadTenants(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketUnregisterTenant(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitAdd(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitRemove(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketHostbitList(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketSetMemcap(json_t *cmd, json_t* answer, void *data);
TmEcode UnixSocketShowMemcap(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketShowAllMemcap(json_t *cmd, json_t *answer, void *data);
TmEcode UnixSocketGetFlowStatsById(json_t *cmd, json_t *answer, void *data);
#endif

#endif /* SURICATA_RUNMODE_UNIX_SOCKET_H */
