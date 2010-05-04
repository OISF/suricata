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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_CONTENT_H__
#define __DETECT_CONTENT_H__

/* Flags affecting this content */

#define DETECT_CONTENT_NOCASE            0x01
#define DETECT_CONTENT_DISTANCE          0x02
#define DETECT_CONTENT_WITHIN            0x04
#define DETECT_CONTENT_FAST_PATTERN      0x08
/** content applies to a "raw"/undecoded field if applicable */
#define DETECT_CONTENT_RAWBYTES          0x10
/** content is negated */
#define DETECT_CONTENT_NEGATED           0x20

/** a relative match to this content is next, used in matching phase */
#define DETECT_CONTENT_RELATIVE_NEXT     0x40

#define DETECT_CONTENT_IS_SINGLE(c) (!((c)->flags & DETECT_CONTENT_DISTANCE || \
                                       (c)->flags & DETECT_CONTENT_WITHIN || \
                                       (c)->flags & DETECT_CONTENT_RELATIVE || \
                                       (c)->depth > 0 || \
                                       (c)->within > 0))

#include "util-spm-bm.h"

typedef struct DetectContentData_ {
    uint8_t *content;   /**< ptr to chunk of memory containing the pattern */
    uint8_t content_len;/**< length of the pattern (and size of the memory) */

    uint32_t id;        /**< unique pattern id */

    uint16_t depth;
    uint16_t offset;
    /** distance from the last match this match should start.
     *  Can be negative */
    int32_t distance;
    int32_t within;
    uint8_t flags;

    BmCtx *bm_ctx;     /**< Boyer Moore context (for spm search) */

} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse (char *contentstr);

void DetectContentPrint(DetectContentData *);

/** This function search backwards the first applicable SigMatch holding
 * a DETECT_CONTENT context (If it belongs to a chunk group, the first chunk
 * of the group will be returned). Modifiers must call this */
SigMatch *DetectContentGetLastPattern(SigMatch *);

/** This function search forwards the first applicable SigMatch holding
 * a DETECT_CONTENT context. The Match process call this */
SigMatch *DetectContentFindNextApplicableSM(SigMatch *);

/** This function search backwards if we have a SigMatch holding
 * a Pattern before the SigMatch passed as argument */
SigMatch *DetectContentHasPrevSMPattern(SigMatch *);

SigMatch *SigMatchGetLastPattern(Signature *s);

void DetectContentFree(void *);

int DetectContentTableInitHash(DetectEngineCtx *);
void DetectContentTableFreeHash(DetectEngineCtx *);
uint32_t DetectContentGetId(DetectEngineCtx *, DetectContentData *);

#endif /* __DETECT_CONTENT_H__ */
