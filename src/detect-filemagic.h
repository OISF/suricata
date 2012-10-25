/* Copyright (C) 2007-2011 Open Information Security Foundation
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

#ifndef __DETECT_FILEMAGIC_H__
#define __DETECT_FILEMAGIC_H__

#include "util-spm-bm.h"
#include <magic.h>

typedef struct DetectFilemagicThreadData {
    magic_t ctx;
} DetectFilemagicThreadData;

typedef struct DetectFilemagicData {
    int thread_ctx_id;
    uint8_t *name; /** name of the file to match */
    BmCtx *bm_ctx; /** BM context */
    uint16_t len; /** name length */
    uint32_t flags;
} DetectFilemagicData;

/* prototypes */
void DetectFilemagicRegister (void);
int FilemagicGlobalLookup(File *file);

#endif /* __DETECT_FILEMAGIC_H__ */
