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

#define DETECT_CONTENT_NOCASE            0x0001
#define DETECT_CONTENT_DISTANCE          0x0002
#define DETECT_CONTENT_WITHIN            0x0004
#define DETECT_CONTENT_OFFSET            0x0008
#define DETECT_CONTENT_DEPTH             0x0010
#define DETECT_CONTENT_FAST_PATTERN      0x0020
#define DETECT_CONTENT_FAST_PATTERN_ONLY 0x0040
#define DETECT_CONTENT_FAST_PATTERN_CHOP 0x0080
/** content applies to a "raw"/undecoded field if applicable */
#define DETECT_CONTENT_RAWBYTES          0x0100
/** content is negated */
#define DETECT_CONTENT_NEGATED           0x0200

/** a relative match to this content is next, used in matching phase */
#define DETECT_CONTENT_RELATIVE_NEXT     0x0400

#define DETECT_CONTENT_PACKET_MPM        0x0800
#define DETECT_CONTENT_STREAM_MPM        0x1000
#define DETECT_CONTENT_URI_MPM           0x2000

#define DETECT_CONTENT_IS_SINGLE(c) (!((c)->flags & DETECT_CONTENT_DISTANCE || \
                                       (c)->flags & DETECT_CONTENT_WITHIN || \
                                       (c)->flags & DETECT_CONTENT_RELATIVE_NEXT || \
                                       (c)->flags & DETECT_CONTENT_DEPTH || \
                                       (c)->flags & DETECT_CONTENT_OFFSET))

#include "util-spm-bm.h"

typedef struct DetectContentData_ {
    uint8_t *content;
    uint8_t content_len;
    uint16_t flags;
    PatIntId id;
    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    /* Boyer Moore context (for spm search) */
    BmCtx *bm_ctx;
    /* for chopped fast pattern, the offset */
    uint16_t fp_chop_offset;
    /* for chopped fast pattern, the length */
    uint16_t fp_chop_len;
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

#endif /* __DETECT_CONTENT_H__ */
