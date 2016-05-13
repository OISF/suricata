/* Copyright (C) 2007-2013 Open Information Security Foundation
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

#define FlowTimeoutsReset() FlowTimeoutsInit()
void FlowTimeoutsInit(void);
void FlowTimeoutsEmergency(void);

/** flow manager scheduling condition */
SCCtrlCondT flow_manager_ctrl_cond;
SCCtrlMutex flow_manager_ctrl_mutex;
#define FlowWakeupFlowManagerThread() SCCtrlCondSignal(&flow_manager_ctrl_cond)

void FlowManagerThreadSpawn(void);
void FlowDisableFlowManagerThread(void);
void FlowMgrRegisterTests (void);

/** flow recycler scheduling condition */
SCCtrlCondT flow_recycler_ctrl_cond;
SCCtrlMutex flow_recycler_ctrl_mutex;
#define FlowWakeupFlowRecyclerThread() \
    SCCtrlCondSignal(&flow_recycler_ctrl_cond)

void FlowRecyclerThreadSpawn(void);
void FlowDisableFlowRecyclerThread(void);

void TmModuleFlowManagerRegister (void);
void TmModuleFlowRecyclerRegister (void);

#endif /* __FLOW_MANAGER_H__ */
