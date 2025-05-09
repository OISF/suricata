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

#ifndef SURICATA_HOST_BIT_H
#define SURICATA_HOST_BIT_H

#include "host.h"
#include "util-var.h"

void HostBitInitCtx(void);
void HostBitRegisterTests(void);

int HostHasHostBits(Host *host);
int HostBitsTimedoutCheck(Host *h, SCTime_t ts);

void HostBitSet(Host *, uint32_t, SCTime_t);
void HostBitUnset(Host *, uint32_t);
void HostBitToggle(Host *, uint32_t, SCTime_t);
int HostBitIsset(Host *, uint32_t, SCTime_t);
int HostBitIsnotset(Host *, uint32_t, SCTime_t);
int HostBitList(Host *, XBit **);

#endif /* SURICATA_HOST_BIT_H */
