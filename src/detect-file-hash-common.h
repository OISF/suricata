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
 * \author Duarte Silva <duarte.silva@serializing.me>
 *
 */

#ifndef __UTIL_DETECT_FILE_HASH_H__
#define __UTIL_DETECT_FILE_HASH_H__

#include "util-rohash.h"

typedef struct DetectFileHashData_ {
    ROHashTable *hash;
    int negated;
} DetectFileHashData;

/* prototypes */
int ReadHashString(uint8_t *, const char *, const char *, int, uint16_t);
int LoadHashTable(ROHashTable *, const char *, const char *, int, uint32_t);

int DetectFileHashMatch(DetectEngineThreadCtx *, Flow *, uint8_t,
        File *, const Signature *, const SigMatchCtx *);
int DetectFileHashSetup(DetectEngineCtx *, Signature *, const char *, uint16_t, int);
void DetectFileHashFree(DetectEngineCtx *, void *);

#endif /* __UTIL_DETECT_FILE_HASH_H__ */
