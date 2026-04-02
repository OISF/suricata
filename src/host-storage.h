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
 * Host wrapper around storage api
 */

#ifndef SURICATA_HOST_STORAGE_H
#define SURICATA_HOST_STORAGE_H

#include "host.h"

typedef struct HostStorageId_ {
    int id;
} SCHostStorageId;

unsigned int SCHostStorageSize(void);

void *SCHostGetStorageById(Host *h, SCHostStorageId id);
int SCHostSetStorageById(Host *h, SCHostStorageId id, void *ptr);

void SCHostFreeStorage(Host *h);

void SCRegisterHostStorageTests(void);

SCHostStorageId SCHostStorageRegister(const char *name, void (*Free)(void *));

#endif /* SURICATA_HOST_STORAGE_H */
