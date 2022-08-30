/* Copyright (C) 2014-2022 Open Information Security Foundation
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
*  \author Aleksey Katargin <gureedo@gmail.com>
*/

#ifndef __RUNMODE_NETMAP_H__
#define __RUNMODE_NETMAP_H__

int RunModeIdsNetmapSingle(void);
int RunModeIdsNetmapAutoFp(void);
int RunModeIdsNetmapWorkers(void);
void RunModeIdsNetmapRegister(void);
const char *RunModeNetmapGetDefaultMode(void);
int NetmapRunModeIsIPS(void);

#endif /* __RUNMODE_NETMAP_H__ */
