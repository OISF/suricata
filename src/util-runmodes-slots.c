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

#include "suricata-common.h"
#include "util-runmodes-slots.h"

extern RunmodesSlots runmodesslots;

int RunmodeGetCurrent(void)
{
  return RunmodesSlotsGetFirstSlot(&runmodesslots);
}

int RunmodeIsUnittests(void)
{
    if (RunmodesSlotsGetFirstSlot(&runmodesslots) == RUNMODE_UNITTEST) {
        return 1;
    }
    return 0;
}

int RunmodesSlotsSetRunmode(RunmodesSlots *runmodes, enum RunModes runmode)
{
    runmodes->run_mode[runmodes->pos] = runmode;
    if (runmodes->pos < RUNMODES_MAX && (runmode == RUNMODE_NFLOG || runmode == RUNMODE_NFQ)) {
        runmodes->pos++;
    } else {
        return 0;
    }
    return 1;
}

int RunmodesSlotsGetRunmode(const RunmodesSlots *runmodes, int index)
{
    return runmodes->run_mode[index];
}

int RunmodesSlotsGetSlotsCount(const RunmodesSlots *runmodes)
{
    return runmodes->pos;
}

int RunmodesSlotsRunmodeIsUnknown(const RunmodesSlots *runmodes)
{
    return (runmodes->run_mode[runmodes->pos] == RUNMODE_UNKNOWN);
}

int RunmodesSlotsRunmodeIsInSlot(const RunmodesSlots *runmodes, const enum RunModes runmode)
{
    int i;
    for (i = 0; i < runmodes->pos; i++) {
        if (runmodes->run_mode[i] == runmode) {
            return 1;
        }
    }
    return 0;
}

int RunmodesSlotsGetFirstSlot(const RunmodesSlots *runmodes)
{
    return runmodes->run_mode[0];
}

int RunmodesSlotsGetSecondSlot(const RunmodesSlots *runmodes)
{
    return runmodes->run_mode[1];
}

bool RunmodesSlotsMaxSlotsReached(const RunmodesSlots *runmodes)
{
  if (runmodes->pos < RUNMODES_MAX) {
      return FALSE;
  }
  return TRUE;
}
