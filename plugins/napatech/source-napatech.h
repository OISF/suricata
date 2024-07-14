/* Copyright (C) 2012-2017 Open Information Security Foundation
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
 * \author nPulse Technologies, LLC.
 * \author Matt Keeler <mk@npulsetech.com>
 */
#ifndef SURICATA_SOURCE_NAPATECH_H
#define SURICATA_SOURCE_NAPATECH_H

void TmModuleReceiveNapatechRegister(int slot);
void TmModuleDecodeNapatechRegister(int slot);

TmEcode NapatechStreamThreadDeinit(ThreadVars *tv, void *data);

#include <nt.h>

struct NapatechStreamDevConf {
    uint16_t stream_id;
};

int NapatechSetPortmap(int port, int peer);
int NapatechGetAdapter(uint8_t port);

#endif /* SURICATA_SOURCE_NAPATECH_H */
