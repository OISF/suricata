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

#define DETECT_CONTENT_NOCASE            0x00000001
#define DETECT_CONTENT_DISTANCE          0x00000002
#define DETECT_CONTENT_WITHIN            0x00000004
#define DETECT_CONTENT_OFFSET            0x00000008
#define DETECT_CONTENT_DEPTH             0x00000010
#define DETECT_CONTENT_FAST_PATTERN      0x00000020
#define DETECT_CONTENT_FAST_PATTERN_ONLY 0x00000040
#define DETECT_CONTENT_FAST_PATTERN_CHOP 0x00000080
/** content applies to a "raw"/undecoded field if applicable */
#define DETECT_CONTENT_RAWBYTES          0x00000100
/** content is negated */
#define DETECT_CONTENT_NEGATED           0x00000200

/** a relative match to this content is next, used in matching phase */
#define DETECT_CONTENT_RELATIVE_NEXT     0x00000400

#define DETECT_CONTENT_PACKET_MPM        0x00000800
#define DETECT_CONTENT_STREAM_MPM        0x00001000
#define DETECT_CONTENT_URI_MPM           0x00002000
#define DETECT_CONTENT_HCBD_MPM          0x00004000
#define DETECT_CONTENT_HHD_MPM           0x00008000
#define DETECT_CONTENT_HRHD_MPM          0x00010000
#define DETECT_CONTENT_HMD_MPM           0x00020000
#define DETECT_CONTENT_HCD_MPM           0x00040000
#define DETECT_CONTENT_HRUD_MPM          0x00080000

/* BE - byte extract */
#define DETECT_CONTENT_OFFSET_BE         0x00100000
#define DETECT_CONTENT_DEPTH_BE          0x00200000
#define DETECT_CONTENT_DISTANCE_BE       0x00400000
#define DETECT_CONTENT_WITHIN_BE         0x00800000

/* replace data */
#define DETECT_CONTENT_REPLACE           0x01000000

#define DETECT_CONTENT_IS_SINGLE(c) (!((c)->flags & DETECT_CONTENT_DISTANCE || \
                                       (c)->flags & DETECT_CONTENT_WITHIN || \
                                       (c)->flags & DETECT_CONTENT_RELATIVE_NEXT || \
                                       (c)->flags & DETECT_CONTENT_DEPTH || \
                                       (c)->flags & DETECT_CONTENT_OFFSET))

#include "util-spm-bm.h"

typedef struct DetectContentData_ {
    uint8_t *content;
    uint8_t content_len;
    /* would want to move PatIntId here and flags down to remove the padding
     * gap, but I think the first four members was used as a template for
     * casting.  \todo check this and fix it if posssible */
    uint32_t flags;
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
    /* pointer to replacement data */
    uint8_t *replace;
    uint8_t replace_len;
} DetectContentData;

/* prototypes */
void DetectContentRegister (void);
uint32_t DetectContentMaxId(DetectEngineCtx *);
DetectContentData *DetectContentParse (char *contentstr);
int DetectContentDataParse(char *contentstr, char** pstr, uint16_t *plen, int *flags);
DetectContentData *DetectContentParseEncloseQuotes(char *);

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
