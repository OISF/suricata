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

#define DETECT_URICONTENT_NOCASE            0x0001
#define DETECT_URICONTENT_DISTANCE          0x0002
#define DETECT_URICONTENT_WITHIN            0x0004
#define DETECT_URICONTENT_OFFSET            0x0008
#define DETECT_URICONTENT_DEPTH             0x0010

#define DETECT_URICONTENT_DISTANCE_NEXT     0x0020
#define DETECT_URICONTENT_WITHIN_NEXT       0x0040

#define DETECT_URICONTENT_RAWBYTES          0x0080
#define DETECT_URICONTENT_NEGATED           0x0100
#define DETECT_URICONTENT_RELATIVE_NEXT     0x0200

#define DETECT_URICONTENT_FAST_PATTERN      0x0400
#define DETECT_URICONTENT_FAST_PATTERN_ONLY 0x0800
#define DETECT_URICONTENT_FAST_PATTERN_CHOP 0x1000

#define DETECT_URICONTENT_IS_SINGLE(c) (!((c)->flags & DETECT_URICONTENT_DISTANCE || \
                                       (c)->flags & DETECT_URICONTENT_WITHIN || \
                                       (c)->flags & DETECT_URICONTENT_RELATIVE || \
                                       (c)->depth > 0 || \
                                       (c)->within > 0))

#include "util-spm-bm.h"
#include "app-layer-htp.h"

typedef struct DetectUricontentData_ {
    uint8_t *uricontent;
    uint8_t uricontent_len;
    PatIntId id;
    uint32_t flags;
    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    BmCtx *bm_ctx;     /**< Boyer Moore context (for spm search) */
    /* if someone wants to add an extra var to this structutre of size 1 byte
     * you can reduce the below var to uint8_t.  No problemo */
    uint16_t avoid_double_check;
    /* for chopped fast pattern, the offset */
    uint16_t fp_chop_offset;
    /* for chopped fast pattern, the length */
    uint16_t fp_chop_len;
} DetectUricontentData;

/* prototypes */
void DetectUricontentRegister (void);
uint32_t DetectUricontentMaxId(DetectEngineCtx *);
//uint32_t DetectUricontentInspectMpm(DetectEngineThreadCtx *det_ctx, void *alstate);
SigMatch *DetectUricontentGetLastPattern(SigMatch *);
void DetectUricontentPrint(DetectUricontentData *);

uint32_t DetectUricontentInspectMpm(DetectEngineThreadCtx *, Flow *, HtpState *);

#endif /* __DETECT_URICONTENT_H__ */

