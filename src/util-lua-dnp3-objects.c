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
        case DNP3_OBJECT_CODE(2, 3): {
            DNP3ObjectG2V3 *data = point->data;
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
        case DNP3_OBJECT_CODE(4, 2): {
            DNP3ObjectG4V2 *data = point->data;
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
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(4, 3): {
            DNP3ObjectG4V3 *data = point->data;
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
            lua_pushliteral(luastate, "relative_time_ms");
            lua_pushinteger(luastate, data->relative_time_ms);
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
        case DNP3_OBJECT_CODE(11, 1): {
            DNP3ObjectG11V1 *data = point->data;
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
        case DNP3_OBJECT_CODE(11, 2): {
            DNP3ObjectG11V2 *data = point->data;
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
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(12, 1): {
            DNP3ObjectG12V1 *data = point->data;
            lua_pushliteral(luastate, "opype");
            lua_pushinteger(luastate, data->opype);
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
            lua_pushliteral(luastate, "ontime");
            lua_pushinteger(luastate, data->ontime);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "offtime");
            lua_pushinteger(luastate, data->offtime);
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
            lua_pushliteral(luastate, "opype");
            lua_pushinteger(luastate, data->opype);
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
            lua_pushliteral(luastate, "ontime");
            lua_pushinteger(luastate, data->ontime);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "offtime");
            lua_pushinteger(luastate, data->offtime);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved");
            lua_pushinteger(luastate, data->reserved);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(12, 3): {
            DNP3ObjectG12V3 *data = point->data;
            lua_pushliteral(luastate, "point");
            lua_pushinteger(luastate, data->point);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(13, 1): {
            DNP3ObjectG13V1 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_state");
            lua_pushinteger(luastate, data->commanded_state);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(13, 2): {
            DNP3ObjectG13V2 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_state");
            lua_pushinteger(luastate, data->commanded_state);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 3): {
            DNP3ObjectG20V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 4): {
            DNP3ObjectG20V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 5): {
            DNP3ObjectG20V5 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 6): {
            DNP3ObjectG20V6 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 7): {
            DNP3ObjectG20V7 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(20, 8): {
            DNP3ObjectG20V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 3): {
            DNP3ObjectG21V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 4): {
            DNP3ObjectG21V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 5): {
            DNP3ObjectG21V5 *data = point->data;
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
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 6): {
            DNP3ObjectG21V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 7): {
            DNP3ObjectG21V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 8): {
            DNP3ObjectG21V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 9): {
            DNP3ObjectG21V9 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 10): {
            DNP3ObjectG21V10 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 11): {
            DNP3ObjectG21V11 *data = point->data;
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(21, 12): {
            DNP3ObjectG21V12 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 3): {
            DNP3ObjectG22V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 4): {
            DNP3ObjectG22V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 5): {
            DNP3ObjectG22V5 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 6): {
            DNP3ObjectG22V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 7): {
            DNP3ObjectG22V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(22, 8): {
            DNP3ObjectG22V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 1): {
            DNP3ObjectG23V1 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 2): {
            DNP3ObjectG23V2 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 3): {
            DNP3ObjectG23V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 4): {
            DNP3ObjectG23V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 5): {
            DNP3ObjectG23V5 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 6): {
            DNP3ObjectG23V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 7): {
            DNP3ObjectG23V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(23, 8): {
            DNP3ObjectG23V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count");
            lua_pushinteger(luastate, data->count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 3): {
            DNP3ObjectG30V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(30, 6): {
            DNP3ObjectG30V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 1): {
            DNP3ObjectG31V1 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 2): {
            DNP3ObjectG31V2 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 3): {
            DNP3ObjectG31V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 4): {
            DNP3ObjectG31V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 5): {
            DNP3ObjectG31V5 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 6): {
            DNP3ObjectG31V6 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 7): {
            DNP3ObjectG31V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(31, 8): {
            DNP3ObjectG31V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 4): {
            DNP3ObjectG32V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 6): {
            DNP3ObjectG32V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(32, 8): {
            DNP3ObjectG32V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 1): {
            DNP3ObjectG33V1 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 2): {
            DNP3ObjectG33V2 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 3): {
            DNP3ObjectG33V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 4): {
            DNP3ObjectG33V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 5): {
            DNP3ObjectG33V5 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 6): {
            DNP3ObjectG33V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 7): {
            DNP3ObjectG33V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(33, 8): {
            DNP3ObjectG33V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
        case DNP3_OBJECT_CODE(34, 2): {
            DNP3ObjectG34V2 *data = point->data;
            lua_pushliteral(luastate, "deadband_value");
            lua_pushinteger(luastate, data->deadband_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(34, 3): {
            DNP3ObjectG34V3 *data = point->data;
            lua_pushliteral(luastate, "deadband_value");
            lua_pushnumber(luastate, data->deadband_value);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(40, 3): {
            DNP3ObjectG40V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(40, 4): {
            DNP3ObjectG40V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(41, 1): {
            DNP3ObjectG41V1 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "control_status");
            lua_pushinteger(luastate, data->control_status);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(41, 2): {
            DNP3ObjectG41V2 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "control_status");
            lua_pushinteger(luastate, data->control_status);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(41, 3): {
            DNP3ObjectG41V3 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "control_status");
            lua_pushinteger(luastate, data->control_status);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(41, 4): {
            DNP3ObjectG41V4 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "control_status");
            lua_pushinteger(luastate, data->control_status);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 1): {
            DNP3ObjectG42V1 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 2): {
            DNP3ObjectG42V2 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 3): {
            DNP3ObjectG42V3 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 4): {
            DNP3ObjectG42V4 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 5): {
            DNP3ObjectG42V5 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 6): {
            DNP3ObjectG42V6 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 7): {
            DNP3ObjectG42V7 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(42, 8): {
            DNP3ObjectG42V8 *data = point->data;
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
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "value");
            lua_pushnumber(luastate, data->value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 1): {
            DNP3ObjectG43V1 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushinteger(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 2): {
            DNP3ObjectG43V2 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushinteger(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 3): {
            DNP3ObjectG43V3 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushinteger(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 4): {
            DNP3ObjectG43V4 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushinteger(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 5): {
            DNP3ObjectG43V5 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushnumber(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 6): {
            DNP3ObjectG43V6 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushnumber(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 7): {
            DNP3ObjectG43V7 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushnumber(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(43, 8): {
            DNP3ObjectG43V8 *data = point->data;
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved0");
            lua_pushinteger(luastate, data->reserved0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "commanded_value");
            lua_pushnumber(luastate, data->commanded_value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
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
        case DNP3_OBJECT_CODE(50, 2): {
            DNP3ObjectG50V2 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "interval");
            lua_pushinteger(luastate, data->interval);
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
        case DNP3_OBJECT_CODE(50, 4): {
            DNP3ObjectG50V4 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "interval_count");
            lua_pushinteger(luastate, data->interval_count);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "interval_units");
            lua_pushinteger(luastate, data->interval_units);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(51, 1): {
            DNP3ObjectG51V1 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(51, 2): {
            DNP3ObjectG51V2 *data = point->data;
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(52, 1): {
            DNP3ObjectG52V1 *data = point->data;
            lua_pushliteral(luastate, "delay_secs");
            lua_pushinteger(luastate, data->delay_secs);
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
        case DNP3_OBJECT_CODE(70, 1): {
            DNP3ObjectG70V1 *data = point->data;
            lua_pushliteral(luastate, "filename_size");
            lua_pushinteger(luastate, data->filename_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "filetype_code");
            lua_pushinteger(luastate, data->filetype_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "attribute_code");
            lua_pushinteger(luastate, data->attribute_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "start_record");
            lua_pushinteger(luastate, data->start_record);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "end_record");
            lua_pushinteger(luastate, data->end_record);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_size");
            lua_pushinteger(luastate, data->file_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "created_timestamp");
            lua_pushinteger(luastate, data->created_timestamp);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "permission");
            lua_pushinteger(luastate, data->permission);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_id");
            lua_pushinteger(luastate, data->file_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "owner_id");
            lua_pushinteger(luastate, data->owner_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "group_id");
            lua_pushinteger(luastate, data->group_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_function_code");
            lua_pushinteger(luastate, data->file_function_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "filename");
            LuaPushStringBuffer(luastate, (uint8_t *)data->filename,
                strlen(data->filename));
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "data_size");
            lua_pushinteger(luastate, data->data_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "data");
            LuaPushStringBuffer(luastate, (uint8_t *)data->data,
                strlen(data->data));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(70, 2): {
            DNP3ObjectG70V2 *data = point->data;
            lua_pushliteral(luastate, "username_offset");
            lua_pushinteger(luastate, data->username_offset);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username_size");
            lua_pushinteger(luastate, data->username_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "password_offset");
            lua_pushinteger(luastate, data->password_offset);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "password_size");
            lua_pushinteger(luastate, data->password_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "authentication_key");
            lua_pushinteger(luastate, data->authentication_key);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username");
            LuaPushStringBuffer(luastate, (uint8_t *)data->username,
                strlen(data->username));
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "password");
            LuaPushStringBuffer(luastate, (uint8_t *)data->password,
                strlen(data->password));
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
        case DNP3_OBJECT_CODE(70, 4): {
            DNP3ObjectG70V4 *data = point->data;
            lua_pushliteral(luastate, "file_handle");
            lua_pushinteger(luastate, data->file_handle);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_size");
            lua_pushinteger(luastate, data->file_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "maximum_block_size");
            lua_pushinteger(luastate, data->maximum_block_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "request_id");
            lua_pushinteger(luastate, data->request_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "optional_text");
            LuaPushStringBuffer(luastate, (uint8_t *)data->optional_text,
                strlen(data->optional_text));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(70, 5): {
            DNP3ObjectG70V5 *data = point->data;
            lua_pushliteral(luastate, "file_handle");
            lua_pushinteger(luastate, data->file_handle);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "block_number");
            lua_pushinteger(luastate, data->block_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_data");
            LuaPushStringBuffer(luastate, (uint8_t *)data->file_data,
                strlen(data->file_data));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(70, 6): {
            DNP3ObjectG70V6 *data = point->data;
            lua_pushliteral(luastate, "file_handle");
            lua_pushinteger(luastate, data->file_handle);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "block_number");
            lua_pushinteger(luastate, data->block_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "status_code");
            lua_pushinteger(luastate, data->status_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "optional_text");
            LuaPushStringBuffer(luastate, (uint8_t *)data->optional_text,
                strlen(data->optional_text));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(70, 7): {
            DNP3ObjectG70V7 *data = point->data;
            lua_pushliteral(luastate, "filename_offset");
            lua_pushinteger(luastate, data->filename_offset);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "filename_size");
            lua_pushinteger(luastate, data->filename_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_type");
            lua_pushinteger(luastate, data->file_type);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "file_size");
            lua_pushinteger(luastate, data->file_size);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "created_timestamp");
            lua_pushinteger(luastate, data->created_timestamp);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "permissions");
            lua_pushinteger(luastate, data->permissions);
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
        case DNP3_OBJECT_CODE(70, 8): {
            DNP3ObjectG70V8 *data = point->data;
            lua_pushliteral(luastate, "file_specification");
            LuaPushStringBuffer(luastate, (uint8_t *)data->file_specification,
                strlen(data->file_specification));
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
        case DNP3_OBJECT_CODE(81, 1): {
            DNP3ObjectG81V1 *data = point->data;
            lua_pushliteral(luastate, "fill_percentage");
            lua_pushinteger(luastate, data->fill_percentage);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "overflow_state");
            lua_pushinteger(luastate, data->overflow_state);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "group");
            lua_pushinteger(luastate, data->group);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "variation");
            lua_pushinteger(luastate, data->variation);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(83, 1): {
            DNP3ObjectG83V1 *data = point->data;
            lua_pushliteral(luastate, "vendor_code");
            LuaPushStringBuffer(luastate, (uint8_t *)data->vendor_code,
                strlen(data->vendor_code));
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "object_id");
            lua_pushinteger(luastate, data->object_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "length");
            lua_pushinteger(luastate, data->length);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "data_objects");
            lua_pushlstring(luastate, (const char *)data->data_objects,
                data->length);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(86, 2): {
            DNP3ObjectG86V2 *data = point->data;
            lua_pushliteral(luastate, "rd");
            lua_pushinteger(luastate, data->rd);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "wr");
            lua_pushinteger(luastate, data->wr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "st");
            lua_pushinteger(luastate, data->st);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "ev");
            lua_pushinteger(luastate, data->ev);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "df");
            lua_pushinteger(luastate, data->df);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "padding0");
            lua_pushinteger(luastate, data->padding0);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "padding1");
            lua_pushinteger(luastate, data->padding1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "padding2");
            lua_pushinteger(luastate, data->padding2);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(102, 1): {
            DNP3ObjectG102V1 *data = point->data;
            lua_pushliteral(luastate, "value");
            lua_pushinteger(luastate, data->value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 1): {
            DNP3ObjectG120V1 *data = point->data;
            lua_pushliteral(luastate, "csq");
            lua_pushinteger(luastate, data->csq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "usr");
            lua_pushinteger(luastate, data->usr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "mal");
            lua_pushinteger(luastate, data->mal);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reason");
            lua_pushinteger(luastate, data->reason);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "challenge_data");
            lua_pushlstring(luastate, (const char *)data->challenge_data,
                data->challenge_data_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 2): {
            DNP3ObjectG120V2 *data = point->data;
            lua_pushliteral(luastate, "csq");
            lua_pushinteger(luastate, data->csq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "usr");
            lua_pushinteger(luastate, data->usr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "mac_value");
            lua_pushlstring(luastate, (const char *)data->mac_value,
                data->mac_value_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 3): {
            DNP3ObjectG120V3 *data = point->data;
            lua_pushliteral(luastate, "csq");
            lua_pushinteger(luastate, data->csq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_number");
            lua_pushinteger(luastate, data->user_number);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 4): {
            DNP3ObjectG120V4 *data = point->data;
            lua_pushliteral(luastate, "user_number");
            lua_pushinteger(luastate, data->user_number);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 5): {
            DNP3ObjectG120V5 *data = point->data;
            lua_pushliteral(luastate, "ksq");
            lua_pushinteger(luastate, data->ksq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_number");
            lua_pushinteger(luastate, data->user_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "key_wrap_alg");
            lua_pushinteger(luastate, data->key_wrap_alg);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "key_status");
            lua_pushinteger(luastate, data->key_status);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "mal");
            lua_pushinteger(luastate, data->mal);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "challenge_data_len");
            lua_pushinteger(luastate, data->challenge_data_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "challenge_data");
            lua_pushlstring(luastate, (const char *)data->challenge_data,
                data->challenge_data_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "mac_value");
            lua_pushlstring(luastate, (const char *)data->mac_value,
                data->mac_value_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 6): {
            DNP3ObjectG120V6 *data = point->data;
            lua_pushliteral(luastate, "ksq");
            lua_pushinteger(luastate, data->ksq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "usr");
            lua_pushinteger(luastate, data->usr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "wrapped_key_data");
            lua_pushlstring(luastate, (const char *)data->wrapped_key_data,
                data->wrapped_key_data_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 7): {
            DNP3ObjectG120V7 *data = point->data;
            lua_pushliteral(luastate, "sequence_number");
            lua_pushinteger(luastate, data->sequence_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "usr");
            lua_pushinteger(luastate, data->usr);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "association_id");
            lua_pushinteger(luastate, data->association_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "error_code");
            lua_pushinteger(luastate, data->error_code);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "time_of_error");
            lua_pushinteger(luastate, data->time_of_error);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "error_text");
            LuaPushStringBuffer(luastate, (uint8_t *)data->error_text,
                strlen(data->error_text));
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 8): {
            DNP3ObjectG120V8 *data = point->data;
            lua_pushliteral(luastate, "key_change_method");
            lua_pushinteger(luastate, data->key_change_method);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "certificate_type");
            lua_pushinteger(luastate, data->certificate_type);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "certificate");
            lua_pushlstring(luastate, (const char *)data->certificate,
                data->certificate_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 9): {
            DNP3ObjectG120V9 *data = point->data;
            lua_pushliteral(luastate, "mac_value");
            lua_pushlstring(luastate, (const char *)data->mac_value,
                data->mac_value_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 10): {
            DNP3ObjectG120V10 *data = point->data;
            lua_pushliteral(luastate, "key_change_method");
            lua_pushinteger(luastate, data->key_change_method);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "operation");
            lua_pushinteger(luastate, data->operation);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "scs");
            lua_pushinteger(luastate, data->scs);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_role");
            lua_pushinteger(luastate, data->user_role);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_role_expiry_interval");
            lua_pushinteger(luastate, data->user_role_expiry_interval);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username_len");
            lua_pushinteger(luastate, data->username_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_public_key_len");
            lua_pushinteger(luastate, data->user_public_key_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "certification_data_len");
            lua_pushinteger(luastate, data->certification_data_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username");
            LuaPushStringBuffer(luastate, (uint8_t *)data->username,
                strlen(data->username));
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_public_key");
            lua_pushlstring(luastate, (const char *)data->user_public_key,
                data->user_public_key_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "certification_data");
            lua_pushlstring(luastate, (const char *)data->certification_data,
                data->certification_data_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 11): {
            DNP3ObjectG120V11 *data = point->data;
            lua_pushliteral(luastate, "key_change_method");
            lua_pushinteger(luastate, data->key_change_method);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username_len");
            lua_pushinteger(luastate, data->username_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "master_challenge_data_len");
            lua_pushinteger(luastate, data->master_challenge_data_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "username");
            LuaPushStringBuffer(luastate, (uint8_t *)data->username,
                strlen(data->username));
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "master_challenge_data");
            lua_pushlstring(luastate, (const char *)data->master_challenge_data,
                data->master_challenge_data_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 12): {
            DNP3ObjectG120V12 *data = point->data;
            lua_pushliteral(luastate, "ksq");
            lua_pushinteger(luastate, data->ksq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_number");
            lua_pushinteger(luastate, data->user_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "challenge_data_len");
            lua_pushinteger(luastate, data->challenge_data_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "challenge_data");
            lua_pushlstring(luastate, (const char *)data->challenge_data,
                data->challenge_data_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 13): {
            DNP3ObjectG120V13 *data = point->data;
            lua_pushliteral(luastate, "ksq");
            lua_pushinteger(luastate, data->ksq);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "user_number");
            lua_pushinteger(luastate, data->user_number);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "encrypted_update_key_len");
            lua_pushinteger(luastate, data->encrypted_update_key_len);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "encrypted_update_key_data");
            lua_pushlstring(luastate, (const char *)data->encrypted_update_key_data,
                data->encrypted_update_key_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 14): {
            DNP3ObjectG120V14 *data = point->data;
            lua_pushliteral(luastate, "digital_signature");
            lua_pushlstring(luastate, (const char *)data->digital_signature,
                data->digital_signature_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(120, 15): {
            DNP3ObjectG120V15 *data = point->data;
            lua_pushliteral(luastate, "mac");
            lua_pushlstring(luastate, (const char *)data->mac,
                data->mac_len);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(121, 1): {
            DNP3ObjectG121V1 *data = point->data;
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
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "association_id");
            lua_pushinteger(luastate, data->association_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count_value");
            lua_pushinteger(luastate, data->count_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(122, 1): {
            DNP3ObjectG122V1 *data = point->data;
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
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "association_id");
            lua_pushinteger(luastate, data->association_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count_value");
            lua_pushinteger(luastate, data->count_value);
            lua_settable(luastate, -3);
            break;
        }
        case DNP3_OBJECT_CODE(122, 2): {
            DNP3ObjectG122V2 *data = point->data;
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
            lua_pushliteral(luastate, "discontinuity");
            lua_pushinteger(luastate, data->discontinuity);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "reserved1");
            lua_pushinteger(luastate, data->reserved1);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "association_id");
            lua_pushinteger(luastate, data->association_id);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "count_value");
            lua_pushinteger(luastate, data->count_value);
            lua_settable(luastate, -3);
            lua_pushliteral(luastate, "timestamp");
            lua_pushinteger(luastate, data->timestamp);
            lua_settable(luastate, -3);
            break;
        }
        default:
            break;
    }
}

#endif /* HAVE_LUA */
