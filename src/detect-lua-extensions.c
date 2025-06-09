/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Functions to expose to the lua scripts.
 */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"

#include "flow.h"

#include "util-debug.h"

#include "detect-lua.h"

#include "rust.h"
#include "app-layer-parser.h"

#include "util-lua.h"
#include "util-lua-common.h"
#include "detect-lua-extensions.h"

/* Lua registry key for DetectLuaData. */
const char luaext_key_ld[] = "suricata:luadata";

void LuaExtensionsMatchSetup(lua_State *lua_state, DetectLuaData *ld,
        DetectEngineThreadCtx *det_ctx, Flow *f, Packet *p, const Signature *s, uint8_t flags)
{
    SCLogDebug("det_ctx %p, f %p", det_ctx, f);

    LuaStateSetSignature(lua_state, s);
    LuaStateSetFlow(lua_state, f);
    LuaStateSetDetCtx(lua_state, det_ctx);

    if (det_ctx->tx_id_set) {
        if (f && f->alstate) {
            void *txptr = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, det_ctx->tx_id);
            if (txptr) {
                LuaStateSetTX(lua_state, txptr, det_ctx->tx_id);
            }
        }
    }

    if (p != NULL)
        LuaStateSetPacket(lua_state, p);

    LuaStateSetDirection(lua_state, (flags & STREAM_TOSERVER));
}
