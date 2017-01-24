/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \author Kirby Kuehl <kkuehl@gmail.com>
 */

#ifndef __APP_LAYER_DCERPC_H__
#define __APP_LAYER_DCERPC_H__

#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc-common.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

typedef struct DCERPCState_ {
    DCERPC dcerpc;
    uint8_t data_needed_for_dir;
    DetectEngineState *de_state;
} DCERPCState;

void DCERPCInit(DCERPC *dcerpc);
void DCERPCCleanup(DCERPC *dcerpc);
void RegisterDCERPCParsers(void);
void DCERPCParserTests(void);
void DCERPCParserRegisterTests(void);

#endif /* __APP_LAYER_DCERPC_H__ */

