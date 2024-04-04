/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef __FLOW_MANAGER_H__
#define __FLOW_MANAGER_H__

/** flow manager scheduling condition */
extern SCCtrlCondT flow_manager_ctrl_cond;
extern SCCtrlMutex flow_manager_ctrl_mutex;
#define FlowWakeupFlowManagerThread() SCCtrlCondSignal(&flow_manager_ctrl_cond)
extern SCCtrlCondT flow_recycler_ctrl_cond;
extern SCCtrlMutex flow_recycler_ctrl_mutex;
#define FlowWakeupFlowRecyclerThread() SCCtrlCondSignal(&flow_recycler_ctrl_cond)

#define FlowTimeoutsReset() FlowTimeoutsInit()
void FlowTimeoutsInit(void);
void FlowTimeoutsEmergency(void);
void FlowManagerThreadSpawn(void);
void FlowDisableFlowManagerThread(void);
void FlowRecyclerThreadSpawn(void);
void FlowDisableFlowRecyclerThread(void);
void TmModuleFlowManagerRegister (void);
void TmModuleFlowRecyclerRegister (void);

/** periodic flow logging */
int FlowShouldPeriodicLog(const Flow *f);

#endif /* __FLOW_MANAGER_H__ */
