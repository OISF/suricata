/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author  Victor Julien <victor@inliniac.net>
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __DETECT_URICONTENT_H__
#define __DETECT_URICONTENT_H__

#include "detect-content.h"

#include "util-spm-bm.h"
#include "app-layer-htp.h"

/* prototypes */
void DetectUricontentRegister (void);
uint32_t DetectUricontentMaxId(DetectEngineCtx *);
void DetectUricontentPrint(DetectContentData *);

uint32_t DetectUricontentInspectMpm(DetectEngineThreadCtx *det_ctx, Flow *f,
                                    HtpState *htp_state, uint8_t flags,
                                    void *tx, uint64_t idx);

#endif /* __DETECT_URICONTENT_H__ */
