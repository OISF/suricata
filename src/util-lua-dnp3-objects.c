/* Copyright (C) 2015 Open Information Security Foundation
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
 * DO NOT EDIT. THIS FILE IS AUTO-GENERATED.
 */

#include "suricata-common.h"

#include "app-layer-dnp3.h"
#include "app-layer-dnp3-objects.h"

#ifdef HAVE_LUA

#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include "util-lua.h"

/**
 * \brief Push an object point item onto the stack.
 */
void DNP3PushPoint(lua_State *luastate, DNP3Object *object,
    DNP3Point *point)
{
    switch (DNP3_OBJECT_CODE(object->group, object->variation)) {
        case DNP3_OBJECT_CODE(1, 1): {
            DNP3ObjectG1V1 *data = point->data;
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(1, 2): {
            DNP3ObjectG1V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "chatter_filter");
            lua_pushinteger(luastate, data->chatter_filter);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(2, 1): {
            DNP3ObjectG2V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "chatter_filter");
            lua_pushinteger(luastate, data->chatter_filter);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(2, 2): {
            DNP3ObjectG2V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "chatter_filter");
            lua_pushinteger(luastate, data->chatter_filter);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(3, 1): {
            DNP3ObjectG3V1 *data = point->data;
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(3, 2): {
            DNP3ObjectG3V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "chatter_filter");
            lua_pushinteger(luastate, data->chatter_filter);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(4, 1): {
            DNP3ObjectG4V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "chatter_filter");
            lua_pushinteger(luastate, data->chatter_filter);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(10, 1): {
            DNP3ObjectG10V1 *data = point->data;
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(10, 2): {
            DNP3ObjectG10V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(12, 1): {
            DNP3ObjectG12V1 *data = point->data;
            lua_pushliteral(luastate, "op_type");
            lua_pushinteger(luastate, data->op_type);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "qu");
            lua_pushinteger(luastate, data->qu);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "cr");
            lua_pushinteger(luastate, data->cr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "tcc");
            lua_pushinteger(luastate, data->tcc);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "on_time");
            lua_pushinteger(luastate, data->on_time);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "off_time");
            lua_pushinteger(luastate, data->off_time);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(12, 2): {
            DNP3ObjectG12V2 *data = point->data;
            lua_pushliteral(luastate, "op_type");
            lua_pushinteger(luastate, data->op_type);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "qu");
            lua_pushinteger(luastate, data->qu);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "cr");
            lua_pushinteger(luastate, data->cr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "tcc");
            lua_pushinteger(luastate, data->tcc);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "on_time");
            lua_pushinteger(luastate, data->on_time);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "off_time");
            lua_pushinteger(luastate, data->off_time);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "res");
            lua_pushinteger(luastate, data->res);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 1): {
            DNP3ObjectG20V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 2): {
            DNP3ObjectG20V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 1): {
            DNP3ObjectG21V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 2): {
            DNP3ObjectG21V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 1): {
            DNP3ObjectG22V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 2): {
            DNP3ObjectG22V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "rollover");
            lua_pushinteger(luastate, data->rollover);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 1): {
            DNP3ObjectG30V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 2): {
            DNP3ObjectG30V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 4): {
            DNP3ObjectG30V4 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 5): {
            DNP3ObjectG30V5 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 1): {
            DNP3ObjectG32V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 2): {
            DNP3ObjectG32V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 3): {
            DNP3ObjectG32V3 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 5): {
            DNP3ObjectG32V5 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 7): {
            DNP3ObjectG32V7 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(34, 1): {
            DNP3ObjectG34V1 *data = point->data;
            lua_pushliteral(luastate, "deadband_value");
            lua_pushinteger(luastate, data->deadband_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(40, 1): {
            DNP3ObjectG40V1 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(40, 2): {
            DNP3ObjectG40V2 *data = point->data;
            lua_pushliteral(luastate, "online");
            lua_pushinteger(luastate, data->online);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "restart");
            lua_pushinteger(luastate, data->restart);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "comm_lost");
            lua_pushinteger(luastate, data->comm_lost);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "remote_forced");
            lua_pushinteger(luastate, data->remote_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "local_forced");
            lua_pushinteger(luastate, data->local_forced);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "over_range");
            lua_pushinteger(luastate, data->over_range);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reference_err");
            lua_pushinteger(luastate, data->reference_err);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(50, 1): {
            DNP3ObjectG50V1 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(50, 3): {
            DNP3ObjectG50V3 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(52, 1): {
            DNP3ObjectG52V1 *data = point->data;
            lua_pushliteral(luastate, "delay_ms");
            lua_pushinteger(luastate, data->delay_ms);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(52, 2): {
            DNP3ObjectG52V2 *data = point->data;
            lua_pushliteral(luastate, "delay_ms");
            lua_pushinteger(luastate, data->delay_ms);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(70, 3): {
            DNP3ObjectG70V3 *data = point->data;
            lua_pushliteral(luastate, "filename_offset");
            lua_pushinteger(luastate, data->filename_offset);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "filename_size");
            lua_pushinteger(luastate, data->filename_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "created");
            lua_pushinteger(luastate, data->created);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "permissions");
            lua_pushinteger(luastate, data->permissions);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "authentication_key");
            lua_pushinteger(luastate, data->authentication_key);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_size");
            lua_pushinteger(luastate, data->file_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "operational_mode");
            lua_pushinteger(luastate, data->operational_mode);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "maximum_block_size");
            lua_pushinteger(luastate, data->maximum_block_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "request_id");
            lua_pushinteger(luastate, data->request_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "filename");
            LuaPushStringBuffer(luastate, (uint8_t *)data->filename,
                strlen(data->filename));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(80, 1): {
            DNP3ObjectG80V1 *data = point->data;
            lua_pushliteral(luastate, "state");
            lua_pushinteger(luastate, data->state);
            lua_settable(luastate, -3);
            break;
        }
        default:
            break;
    }
}

#endif /* HAVE_LUA */
