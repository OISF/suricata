/* Copyright (C) 2017 Open Information Security Foundation
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

use std::os::raw::c_int;

use lua::*;
use dns::dns::*;
use dns::log::*;

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_tx_id(clua: &mut CLuaState,
                                       tx: &mut DNSTransaction)
{
    let lua = LuaState{
        lua: clua,
    };

    lua.pushinteger(tx.tx_id() as i64);
}

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_rrname(clua: &mut CLuaState,
                                        tx: &mut DNSTransaction)
                                        -> c_int
{
    let lua = LuaState{
        lua: clua,
    };

    for request in &tx.request {
        for query in &request.queries {
            lua.pushstring(&String::from_utf8_lossy(&query.name));
            return 1;
        }
    }

    for response in &tx.response {
        for query in &response.queries {
            lua.pushstring(&String::from_utf8_lossy(&query.name));
            return 1;
        }
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_query_table(clua: &mut CLuaState,
                                             tx: &mut DNSTransaction)
                                             -> c_int
{
    let lua = LuaState{
        lua: clua,
    };

    let mut i: i64 = 0;

    for request in &tx.request {

        if request.queries.len() == 0 {
            break;
        }

        lua.newtable();

        for query in &request.queries {
            lua.pushinteger(i);
            i += 1;

            lua.newtable();

            lua.pushstring("type");
            lua.pushstring(&dns_rrtype_string(query.rrtype));
            lua.settable(-3);

            lua.pushstring("rrname");
            lua.pushstring(&String::from_utf8_lossy(&query.name));
            lua.settable(-3);

            lua.settable(-3);
        }

        return 1;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_answer_table(clua: &mut CLuaState,
                                              tx: &mut DNSTransaction)
                                              -> c_int
{
    let lua = LuaState{
        lua: clua,
    };

    let mut i: i64 = 0;

    for response in &tx.response {

        if response.answers.len() == 0 {
            break;
        }

        lua.newtable();

        for answer in &response.answers {
            lua.pushinteger(i);
            i += 1;

            lua.newtable();
            lua.pushstring("type");
            lua.pushstring(&dns_rrtype_string(answer.rrtype));
            lua.settable(-3);

            lua.pushstring("ttl");
            lua.pushinteger(answer.ttl as i64);
            lua.settable(-3);

            lua.pushstring("rrname");
            lua.pushstring(&String::from_utf8_lossy(&answer.name));
            lua.settable(-3);

            if answer.data.len() > 0 {
                lua.pushstring("addr");
                match answer.rrtype {
                    DNS_RTYPE_A | DNS_RTYPE_AAAA => {
                        lua.pushstring(&dns_print_addr(&answer.data));
                    }
                    _ => {
                        lua.pushstring(&String::from_utf8_lossy(&answer.data));
                    }
                }
                lua.settable(-3);
            }
            lua.settable(-3);
        }

        return 1;
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_authority_table(clua: &mut CLuaState,
                                                 tx: &mut DNSTransaction)
                                                 -> c_int
{
    let lua = LuaState{
        lua: clua,
    };

    let mut i: i64 = 0;

    for response in &tx.response {

        if response.authorities.len() == 0 {
            break;
        }

        lua.newtable();

        for answer in &response.authorities {
            lua.pushinteger(i);
            i += 1;

            lua.newtable();
            lua.pushstring("type");
            lua.pushstring(&dns_rrtype_string(answer.rrtype));
            lua.settable(-3);

            lua.pushstring("ttl");
            lua.pushinteger(answer.ttl as i64);
            lua.settable(-3);

            lua.pushstring("rrname");
            lua.pushstring(&String::from_utf8_lossy(&answer.name));
            lua.settable(-3);

            lua.settable(-3);
        }

        return 1;
    }

    return 0;
}
