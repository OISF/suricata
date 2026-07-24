/* Copyright (C) 2022-2026 Open Information Security Foundation
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
 * \author Eric Leblond <el@stamus-networks.com>
 */

#ifndef SURICATA_UTIL_LANDLOCK_H
#define SURICATA_UTIL_LANDLOCK_H

#include "suricata.h"

/** Callback invoked by SCLandlockForEachOutput() for one output instance.
 *  \a conf is the node named after the output (e.g. the "eve-log" node), not
 *  the enclosing sequence entry. */
typedef void (*SCLandlockOutputFunc)(void *ruleset, SCConfNode *conf);

void SCLandlockForEachOutput(void *ruleset, const char *name, SCLandlockOutputFunc cb);

void SCLandlockGrantReadPath(void *ruleset, const char *path);
void SCLandlockGrantWritePath(void *ruleset, const char *path);

void SCLandlockGrantWriteReferPath(void *ruleset, const char *path);

void SCLandlockGrantWriteRemovePath(void *ruleset, const char *path);

/** Per-file access flags for SCLandlockGrantFile(). Combine as needed. */
#define SC_LANDLOCK_FILE_READ     (1U << 0)
#define SC_LANDLOCK_FILE_WRITE    (1U << 1)
#define SC_LANDLOCK_FILE_TRUNCATE (1U << 2)

void SCLandlockGrantFile(void *ruleset, const char *path, uint32_t access);

void SCLandlockRegisterFile(const char *path, uint32_t access);

void SCLandlockGrantNetBindTCP(void *ruleset, uint16_t port);

void SCLandlockGrantNetConnectTCP(void *ruleset, uint16_t port);

void LandlockSandboxing(SCInstance *suri);

#endif /* SURICATA_UTIL_LANDLOCK_H */
