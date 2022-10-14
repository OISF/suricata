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

use crate::lua::*;
use crate::dns::dns::*;
use crate::dns::log::*;

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

    if let &Some(ref request) = &tx.request {
        for query in &request.queries {
            lua.pushstring(&String::from_utf8_lossy(&query.name));
            return 1;
        }
    } else if let &Some(ref response) = &tx.response {
        for query in &response.queries {
            lua.pushstring(&String::from_utf8_lossy(&query.name));
            return 1;
        }
    }

    return 0;
}

#[no_mangle]
pub extern "C" fn rs_dns_lua_get_rcode(clua: &mut CLuaState,
                                       tx: &mut DNSTransaction)
                                       -> c_int
{
    let lua = LuaState{
        lua: clua,
    };

    let rcode = tx.rcode();
    if rcode > 0 {
        lua.pushstring(&dns_rcode_string(rcode));
        return 1;
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

    // Create table now to be consistent with C that always returns
    // table even in the absence of any authorities.
    lua.newtable();

    // We first look in the request for queries. However, if there is
    // no request, check the response for queries.
    if let &Some(ref request) = &tx.request {
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
    } else if let &Some(ref response) = &tx.response {
        for query in &response.queries {
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
    }

    // Again, always return 1 to be consistent with C, even if the
    // table is empty.
    return 1;
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

    // Create table now to be consistent with C that always returns
    // table even in the absence of any authorities.
    lua.newtable();

    if let &Some(ref response) = &tx.response {
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

            // All rdata types are pushed to "addr" for backwards compatibility
            match answer.data {
                DNSRData::A(ref bytes) | DNSRData::AAAA(ref bytes) => {
                    if !bytes.is_empty() {
                        lua.pushstring("addr");
                        lua.pushstring(&dns_print_addr(bytes));
                        lua.settable(-3);
                    }
                },
                DNSRData::CNAME(ref bytes) |
                DNSRData::MX(ref bytes) |
                DNSRData::NS(ref bytes) |
                DNSRData::TXT(ref bytes) |
                DNSRData::NULL(ref bytes) |
                DNSRData::PTR(ref bytes) |
                DNSRData::Unknown(ref bytes) => {
                    if !bytes.is_empty() {
                        lua.pushstring("addr");
                        lua.pushstring(&String::from_utf8_lossy(bytes));
                        lua.settable(-3);
                    }
                },
                DNSRData::SOA(ref soa) => {
                    if !soa.mname.is_empty() {
                        lua.pushstring("addr");
                        lua.pushstring(&String::from_utf8_lossy(&soa.mname));
                        lua.settable(-3);
                    }
                },
                DNSRData::SSHFP(ref sshfp) => {
                    lua.pushstring("addr");
                    lua.pushstring(&String::from_utf8_lossy(&sshfp.fingerprint));
                    lua.settable(-3);
                },
                DNSRData::SRV(ref srv) => {
                    lua.pushstring("addr");
                    lua.pushstring(&String::from_utf8_lossy(&srv.target));
                    lua.settable(-3);
                },
            }
            lua.settable(-3);
        }
    }

    // Again, always return 1 to be consistent with C, even if the
    // table is empty.
    return 1;
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

    // Create table now to be consistent with C that always returns
    // table even in the absence of any authorities.
    lua.newtable();

    if let &Some(ref response) = &tx.response {
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
    }

    // Again, always return 1 to be consistent with C, even if the
    // table is empty.
    return 1;
}
