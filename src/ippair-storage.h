/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 * IPPair wrapper around storage api
 */

#ifndef SURICATA_IPPAIR_STORAGE_H
#define SURICATA_IPPAIR_STORAGE_H

#include "ippair.h"

typedef struct SCIPPairStorageId {
    int id;
} SCIPPairStorageId;

unsigned int SCIPPairStorageSize(void);

void *SCIPPairGetStorageById(IPPair *h, SCIPPairStorageId id);
int SCIPPairSetStorageById(IPPair *h, SCIPPairStorageId id, void *ptr);

void SCIPPairFreeStorage(IPPair *h);

void SCRegisterIPPairStorageTests(void);

SCIPPairStorageId SCIPPairStorageRegister(const char *name, void (*Free)(void *));

#endif /* SURICATA_IPPAIR_STORAGE_H */
