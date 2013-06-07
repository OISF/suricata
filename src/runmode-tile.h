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

/** \file
 *
 *  \author Tom DeCanio <decanio.tom@gmail.com>
 *  \author Tilera Corporation <suricata@tilera.com>
 */

#ifndef __RUNMODE_TILE_H__
#define __RUNMODE_TILE_H__

#include "suricata-common.h"

const char *RunModeIdsTileMpipeGetDefaultMode(void);
void RunModeIdsTileMpipeRegister(void);

#ifdef __tile__
#include <arch/cycle.h>

static inline void
cycle_pause(unsigned int delay)
{
    const uint64_t start = get_cycle_count();
    while (get_cycle_count() - start < delay)
        ;
}
#endif

extern unsigned int TileNumPipelines;

int RunModeIdsTileMpipeAuto(DetectEngineCtx *);
int RunModeIdsTileMpipeWorkers(DetectEngineCtx *);

const char *RunModeTileGetPipelineConfig(const char *custom_mode);

extern void *ParseMpipeConfig(const char *iface);

#endif /* __RUNMODE_TILE_H__ */
