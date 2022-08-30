/* Copyright (C) 2017-2022 Open Information Security Foundation
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
 * \author Eric Leblond <eric@regit.org>
 */

#ifndef __APP_LAYER_EXPECTATION__H__
#define __APP_LAYER_EXPECTATION__H__

#include "flow-storage.h"

void AppLayerExpectationSetup(void);
int AppLayerExpectationCreate(Flow *f, int direction, Port src, Port dst,
                              AppProto alproto, void *data);
AppProto AppLayerExpectationHandle(Flow *f, uint8_t flags);
FlowStorageId AppLayerExpectationGetFlowId(void);

void AppLayerExpectationClean(Flow *f);

uint64_t ExpectationGetCounter(void);

#endif /* __APP_LAYER_EXPECTATION__H__ */
