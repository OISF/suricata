/* Copyright (C) 2011-2014 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __DETECT_REPLACE_H__
#define __DETECT_REPLACE_H__

#include "detect-content.h"

DetectReplaceList * DetectReplaceAddToList(DetectReplaceList *replist, uint8_t *found, DetectContentData *cd);

/* Internal functions are only called via the inline functions below. */
void DetectReplaceExecuteInternal(Packet *p, DetectReplaceList *replist);
void DetectReplaceFreeInternal(DetectReplaceList *replist);

static inline void DetectReplaceFree(DetectEngineThreadCtx *det_ctx)
{
    if (det_ctx->replist) {
        DetectReplaceFreeInternal(det_ctx->replist);
        det_ctx->replist = NULL;
    }
}

void DetectReplaceRegister (void);

#endif
