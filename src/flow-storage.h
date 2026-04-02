/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Flow wrapper around storage api
 */

#ifndef SURICATA_FLOW_STORAGE_H
#define SURICATA_FLOW_STORAGE_H

#include "flow.h"

typedef struct SCFlowStorageId {
    int id;
} SCFlowStorageId;

unsigned int SCFlowStorageSize(void);

void *SCFlowGetStorageById(const Flow *h, SCFlowStorageId id);
int SCFlowSetStorageById(Flow *h, SCFlowStorageId id, void *ptr);

void SCFlowFreeStorageById(Flow *h, SCFlowStorageId id);
void SCFlowFreeStorage(Flow *h);

void SCRegisterFlowStorageTests(void);

SCFlowStorageId SCFlowStorageRegister(const char *name, void (*Free)(void *));

#endif /* SURICATA_FLOW_STORAGE_H */
