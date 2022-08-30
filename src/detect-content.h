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
 */

#ifndef __DETECT_CONTENT_H__
#define __DETECT_CONTENT_H__

/* Flags affecting this content */

#define DETECT_CONTENT_NOCASE            BIT_U32(0)
#define DETECT_CONTENT_DISTANCE          BIT_U32(1)
#define DETECT_CONTENT_WITHIN            BIT_U32(2)
#define DETECT_CONTENT_OFFSET            BIT_U32(3)
#define DETECT_CONTENT_DEPTH             BIT_U32(4)
#define DETECT_CONTENT_FAST_PATTERN      BIT_U32(5)
#define DETECT_CONTENT_FAST_PATTERN_ONLY BIT_U32(6)
#define DETECT_CONTENT_FAST_PATTERN_CHOP BIT_U32(7)
/** content applies to a "raw"/undecoded field if applicable */
#define DETECT_CONTENT_RAWBYTES          BIT_U32(8)
/** content is negated */
#define DETECT_CONTENT_NEGATED           BIT_U32(9)

#define DETECT_CONTENT_ENDS_WITH         BIT_U32(10)

/* BE - byte extract */
#define DETECT_CONTENT_OFFSET_VAR        BIT_U32(11)
#define DETECT_CONTENT_DEPTH_VAR         BIT_U32(12)
#define DETECT_CONTENT_DISTANCE_VAR      BIT_U32(13)
#define DETECT_CONTENT_WITHIN_VAR        BIT_U32(14)

/* replace data */
#define DETECT_CONTENT_REPLACE           BIT_U32(15)
/* this flag is set during the staging phase.  It indicates that a content
 * has been added to the mpm phase and requires no further inspection inside
 * the inspection phase */
#define DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED BIT_U32(16)

#define DETECT_CONTENT_WITHIN_NEXT      BIT_U32(17)
#define DETECT_CONTENT_DISTANCE_NEXT    BIT_U32(18)
#define DETECT_CONTENT_STARTS_WITH      BIT_U32(19)
/** MPM pattern selected by the engine or forced by fast_pattern keyword */
#define DETECT_CONTENT_MPM              BIT_U32(20)

/** a relative match to this content is next, used in matching phase */
#define DETECT_CONTENT_RELATIVE_NEXT    (DETECT_CONTENT_WITHIN_NEXT|DETECT_CONTENT_DISTANCE_NEXT)

#define DETECT_CONTENT_IS_SINGLE(c) (!( ((c)->flags & DETECT_CONTENT_DISTANCE) || \
                                        ((c)->flags & DETECT_CONTENT_WITHIN) || \
                                        ((c)->flags & DETECT_CONTENT_RELATIVE_NEXT) || \
                                        ((c)->flags & DETECT_CONTENT_DEPTH) || \
                                        ((c)->flags & DETECT_CONTENT_OFFSET) ))

/* if a pattern has no depth/offset limits, no relative specifiers and isn't
 * chopped for the mpm, we can take the mpm and consider this pattern a match
 * w/o further inspection. Warning: this may still mean other patterns depend
 * on this pattern that force match validation anyway. */
#define DETECT_CONTENT_MPM_IS_CONCLUSIVE(c) \
                                    !( ((c)->flags & DETECT_CONTENT_DISTANCE) || \
                                       ((c)->flags & DETECT_CONTENT_WITHIN)   || \
                                       ((c)->flags & DETECT_CONTENT_DEPTH)    || \
                                       ((c)->flags & DETECT_CONTENT_OFFSET)   || \
                                       ((c)->flags & DETECT_CONTENT_FAST_PATTERN_CHOP))


#include "util-spm.h"

typedef struct DetectContentData_ {
    uint8_t *content;
    uint16_t content_len;
    uint16_t replace_len;
    /* for chopped fast pattern, the length */
    uint16_t fp_chop_len;
    /* for chopped fast pattern, the offset */
    uint16_t fp_chop_offset;
    /* would want to move PatIntId here and flags down to remove the padding
     * gap, but I think the first four members was used as a template for
     * casting.  \todo check this and fix it if possible */
    uint32_t flags;
    PatIntId id;
    uint16_t depth;
    uint16_t offset;
    int32_t distance;
    int32_t within;
    /* SPM search context. */
    SpmCtx *spm_ctx;
    /* pointer to replacement data */
    uint8_t *replace;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse(SpmGlobalThreadCtx *spm_global_thread_ctx,
                                      const char *contentstr);
int DetectContentDataParse(const char *keyword, const char *contentstr,
    uint8_t **pstr, uint16_t *plen);
DetectContentData *DetectContentParseEncloseQuotes(SpmGlobalThreadCtx *spm_global_thread_ctx,
        const char *contentstr);

int DetectContentSetup(DetectEngineCtx *de_ctx, Signature *s, const char *contentstr);
void DetectContentPrint(DetectContentData *);

void DetectContentFree(DetectEngineCtx *, void *);
bool DetectContentPMATCHValidateCallback(const Signature *s);
void DetectContentPropagateLimits(Signature *s);

void DetectContentPatternPrettyPrint(const DetectContentData *cd, char *str, size_t str_len);

#endif /* __DETECT_CONTENT_H__ */
