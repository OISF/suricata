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

#ifndef __DETECT_DSIZE_H__
#define __DETECT_DSIZE_H__

#include "detect-engine-uint.h"

/* prototypes */
void DetectDsizeRegister (void);

int SigParseGetMaxDsize(const Signature *s);
void SigParseSetDsizePair(Signature *s);
void SigParseApplyDsizeToContent(Signature *s);

/** Determine if a packet p should be kicked out during prefilter due
 *  to dsize outside the range specified in signature s */
static inline bool SigDsizePrefilter(const Packet *p, const Signature *s, uint32_t sflags)
{
    if (unlikely(sflags & SIG_FLAG_DSIZE)) {
        if (likely(p->payload_len < s->dsize_low || p->payload_len > s->dsize_high)) {
            if (!(s->dsize_mode == DETECT_UINT_NE)) {
                SCLogDebug("kicked out as p->payload_len %u, dsize low %u, hi %u", p->payload_len,
                        s->dsize_low, s->dsize_high);
                return true;
            }
        }
    }
    return false;
}

#endif /* __DETECT_DSIZE_H__ */

