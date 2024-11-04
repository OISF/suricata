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
 *  \file
 *
 *  \autor nPulse Technologies, LLC.
 *  \author Matt Keeler <mk@npulsetech.com>
 */

#ifndef SURICATA_RUNMODE_NAPATECH_H
#define SURICATA_RUNMODE_NAPATECH_H

#include <nt.h>

int RunModeNapatechWorkers(void);
void RunModeNapatechRegister(int slot);
const char *RunModeNapatechGetDefaultMode(void);

uint16_t NapatechGetNumConfiguredStreams(void);
uint16_t NapatechGetNumFirstStream(void);
uint16_t NapatechGetNumLastStream(void);
bool NapatechIsAutoConfigEnabled(void);
bool NapatechUseHWBypass(void);

#endif /* SURICATA_RUNMODE_NAPATECH_H */
