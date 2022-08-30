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
 */

#ifndef __UTIL_VAR_NAME_H__
#define __UTIL_VAR_NAME_H__

int VarNameStoreSetupStaging(uint32_t de_ctx_version);
const char *VarNameStoreLookupById(const uint32_t id, const enum VarTypes type);
uint32_t VarNameStoreLookupByName(const char *name, const enum VarTypes type);
uint32_t VarNameStoreSetupAdd(const char *name, const enum VarTypes type);
char *VarNameStoreSetupLookup(uint32_t idx, const enum VarTypes type);
void VarNameStoreActivateStaging(void);
void VarNameStoreFreeOld(void);
void VarNameStoreFree(uint32_t de_ctx_version);

#endif

