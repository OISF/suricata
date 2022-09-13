
/* Copyright (C) 2022 Open Information Security Foundation
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
 * \author Richard McConnell <richard_mcconnell@rapid7.com>
 */

#ifndef __RUNMODE_AFXDP_H__
#define __RUNMODE_AFXDP_H__

int RunModeIdsAFXDPSingle(void);
int RunModeIdsAFXDPWorkers(void);
void RunModeIdsAFXDPRegister(void);
const char *RunModeAFXDPGetDefaultMode(void);

#endif /* __RUNMODE_AFXDP_H__ */
