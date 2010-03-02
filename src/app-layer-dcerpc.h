/*
 * Copyright (c) 2009,2010 Open Information Security Foundation
 * app-layer-dcerpc.h
 *
 * \author Kirby Kuehl <kkuehl@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef APPLAYERDCERPC_H_
#define APPLAYERDCERPC_H_
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-dcerpc-common.h"
#include "flow.h"
#include "queue.h"
#include "util-byte.h"

typedef struct DCERPCState_ {
     DCERPC dcerpc;
}DCERPCState;

void RegisterDCERPCParsers(void);
void DCERPCParserTests(void);
void DCERPCParserRegisterTests(void);

#endif /* APPLAYERDCERPC_H_ */

