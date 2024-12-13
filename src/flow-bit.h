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

#ifndef SURICATA_FLOW_BIT_H
#define SURICATA_FLOW_BIT_H

#include "flow.h"
#include "util-var.h"

typedef struct FlowBit_ {
    uint16_t type; /* type, DETECT_FLOWBITS in this case */
    uint8_t pad[2];
    uint32_t idx; /* name idx */
    GenericVar *next; /* right now just implement this as a list,
                       * in the long run we have think of something
                       * faster. */
} FlowBit;

void FlowBitFree(FlowBit *);
void FlowBitRegisterTests(void);

void FlowBitSet(Flow *, uint32_t);
void FlowBitUnset(Flow *, uint32_t);
void FlowBitToggle(Flow *, uint32_t);
int FlowBitIsset(Flow *, uint32_t);
int FlowBitIsnotset(Flow *, uint32_t);
#endif /* SURICATA_FLOW_BIT_H */
