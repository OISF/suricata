/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Giuseppe Longo <giuseppe@glongo.it>
 */

#ifndef __RUNMODES_SLOTS_H__
#define __RUNMODES_SLOTS_H__

#include "runmodes.h"
#define RUNMODES_MAX     2

typedef struct RunmodesSlots_ {
    enum RunModes run_mode[RUNMODES_MAX];
    int pos;
} RunmodesSlots;

extern RunmodesSlots runmodesslots;

int RunmodesSlotsSetRunmode(RunmodesSlots *runmodes, enum RunModes runmode);
int RunmodesSlotsGetRunmode(const RunmodesSlots *runmodes, int index);
int RunmodesSlotsGetFirstSlot(const RunmodesSlots *runmodes);
int RunmodesSlotsGetSecondSlot(const RunmodesSlots *runmodes);
int RunmodesSlotsGetSlotsCount(const RunmodesSlots *runmodes);
int RunmodesSlotsRunmodeIsInSlot(const RunmodesSlots *runmodes, const enum RunModes runmode);
bool RunmodesSlotsMaxSlotsReached(const RunmodesSlots *runmodes);
int RunmodesSlotsRunmodeIsUnknown(const RunmodesSlots *runmodes);
int RunmodeIsUnittests(void);

#endif /* __RUNMODES_SLOTS_H__ */
