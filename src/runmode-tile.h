/* Copyright (C) 2011-2013 Open Information Security Foundation
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
 * \author Tom DeCanio <decanio.tom@gmail.com>
 * \author Ken Steele, Tilera Corporation <suricata@tilera.com>
 *
 * Tilera TILE-Gx runmode support
 */

#ifndef __RUNMODE_TILE_H__
#define __RUNMODE_TILE_H__

#include "suricata-common.h"

const char *RunModeTileMpipeGetDefaultMode(void);
void RunModeTileMpipeRegister(void);

extern int tile_num_pipelines;

int RunModeTileMpipeWorkers(void);

void *ParseMpipeConfig(const char *iface);

#endif /* __RUNMODE_TILE_H__ */
