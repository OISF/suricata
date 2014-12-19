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

#ifndef __IPPAIR_BIT_H__
#define __IPPAIR_BIT_H__

#include "ippair.h"
#include "util-var.h"

typedef struct XBit_ {
    uint8_t type; /* type, DETECT_XBITS in this case */
    uint16_t idx; /* name idx */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
} XBit;

void XBitFree(XBit *fb);

void IPPairBitInitCtx(void);
void IPPairBitFree(XBit *);
void IPPairBitRegisterTests(void);

int IPPairHasIPPairBits(IPPair *host);

void IPPairBitSet(IPPair *, uint16_t);
void IPPairBitUnset(IPPair *, uint16_t);
void IPPairBitToggle(IPPair *, uint16_t);
int IPPairBitIsset(IPPair *, uint16_t);
int IPPairBitIsnotset(IPPair *, uint16_t);

#endif /* __IPPAIR_BIT_H__ */
