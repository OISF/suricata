/* Copyright (C) 2024 Open Information Security Foundation
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
 * Thread wrapper around storage API.
 */

#ifndef SURICATA_THREAD_STORAGE_H
#define SURICATA_THREAD_STORAGE_H

#include "threadvars.h"

typedef struct ThreadStorageId {
    int id;
} ThreadStorageId;

unsigned int ThreadStorageSize(void);

void *ThreadGetStorageById(const ThreadVars *tv, ThreadStorageId id);
int ThreadSetStorageById(ThreadVars *tv, ThreadStorageId id, void *ptr);
void *ThreadAllocStorageById(ThreadVars *tv, ThreadStorageId id);

void ThreadFreeStorageById(ThreadVars *tv, ThreadStorageId id);
void ThreadFreeStorage(ThreadVars *tv);

void RegisterThreadStorageTests(void);

ThreadStorageId ThreadStorageRegister(const char *name, const unsigned int size,
        void *(*Alloc)(unsigned int), void (*Free)(void *));

#endif /* SURICATA_THREAD_STORAGE_H */
