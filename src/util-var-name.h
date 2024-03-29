/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 */

#ifndef SURICATA_UTIL_VAR_NAME_H
#define SURICATA_UTIL_VAR_NAME_H

void VarNameStoreInit(void);
void VarNameStoreDestroy(void);

uint32_t VarNameStoreRegister(const char *name, const enum VarTypes type);
const char *VarNameStoreSetupLookup(const uint32_t id, const enum VarTypes type);
void VarNameStoreUnregister(const uint32_t id, const enum VarTypes type);
int VarNameStoreActivate(void);

const char *VarNameStoreLookupById(const uint32_t id, const enum VarTypes type);
uint32_t VarNameStoreLookupByName(const char *, const enum VarTypes type);

#endif

