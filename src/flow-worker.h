/* Copyright (C) 2016 Open Information Security Foundation
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

#ifndef __FLOW_WORKER_H__
#define __FLOW_WORKER_H__

enum ProfileFlowWorkerId {
    PROFILE_FLOWWORKER_FLOW = 0,
    PROFILE_FLOWWORKER_STREAM,
    PROFILE_FLOWWORKER_APPLAYERUDP,
    PROFILE_FLOWWORKER_DETECT,
    PROFILE_FLOWWORKER_TCPPRUNE,
    PROFILE_FLOWWORKER_SIZE
};
const char *ProfileFlowWorkerIdToString(enum ProfileFlowWorkerId fwi);

void FlowWorkerReplaceDetectCtx(void *flow_worker, void *detect_ctx);
void *FlowWorkerGetDetectCtxPtr(void *flow_worker);

void TmModuleFlowWorkerRegister (void);

#endif /* __FLOW_WORKER_H__ */
