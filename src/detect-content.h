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

#define DETECT_CONTENT_NOCASE            (1)
#define DETECT_CONTENT_DISTANCE          (1 << 1)
#define DETECT_CONTENT_WITHIN            (1 << 2)
#define DETECT_CONTENT_OFFSET            (1 << 3)
#define DETECT_CONTENT_DEPTH             (1 << 4)
#define DETECT_CONTENT_FAST_PATTERN      (1 << 5)
#define DETECT_CONTENT_FAST_PATTERN_ONLY (1 << 6)
#define DETECT_CONTENT_FAST_PATTERN_CHOP (1 << 7)
/** content applies to a "raw"/undecoded field if applicable */
#define DETECT_CONTENT_RAWBYTES          (1 << 8)
/** content is negated */
#define DETECT_CONTENT_NEGATED           (1 << 9)

/** a relative match to this content is next, used in matching phase */
#define DETECT_CONTENT_RELATIVE_NEXT     (1 << 10)

/* BE - byte extract */
#define DETECT_CONTENT_OFFSET_BE         (1 << 11)
#define DETECT_CONTENT_DEPTH_BE          (1 << 12)
#define DETECT_CONTENT_DISTANCE_BE       (1 << 13)
#define DETECT_CONTENT_WITHIN_BE         (1 << 14)

/* replace data */
#define DETECT_CONTENT_REPLACE           (1 << 15)
/* this flag is set during the staging phase.  It indicates that a content
 * has been added to the mpm phase and requires no further inspection inside
 * the inspection phase */
#define DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED (1 << 16)

#define DETECT_CONTENT_IS_SINGLE(c) (!( ((c)->flags & DETECT_CONTENT_DISTANCE) || \
                                        ((c)->flags & DETECT_CONTENT_WITHIN) || \
                                        ((c)->flags & DETECT_CONTENT_RELATIVE_NEXT) || \
                                        ((c)->flags & DETECT_CONTENT_DEPTH) || \
                                        ((c)->flags & DETECT_CONTENT_OFFSET) ))

#include "util-spm-bm.h"

typedef struct DetectContentData_ {
    uint8_t *content;
    uint16_t content_len;
    uint16_t replace_len;
    /* for chopped fast pattern, the length */
    uint16_t fp_chop_len;
    /* would want to move PatIntId here and flags down to remove the padding
     * gap, but I think the first four members was used as a template for
     * casting.  \todo check this and fix it if posssible */
    uint32_t flags;
    PatIntId id;
    uint16_t depth;
    uint16_t offset;
    /* for chopped fast pattern, the offset */
    uint16_t fp_chop_offset;
    int32_t distance;
    int32_t within;
    /* Boyer Moore context (for spm search) */
    BmCtx *bm_ctx;
    /* pointer to replacement data */
    uint8_t *replace;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse (char *contentstr);
int DetectContentDataParse(const char *keyword, const char *contentstr,
    uint8_t **pstr, uint16_t *plen, uint32_t *flags);
DetectContentData *DetectContentParseEncloseQuotes(char *);

int DetectContentSetup(DetectEngineCtx *de_ctx, Signature *s, char *contentstr);
void DetectContentPrint(DetectContentData *);

void DetectContentFree(void *);

#endif /* __DETECT_CONTENT_H__ */
