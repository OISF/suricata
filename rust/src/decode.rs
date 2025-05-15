/* Copyright (C) 2025 Open Information Security Foundation
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

//! Decode module.

use crate::conf::conf_get_node;
use std::collections::HashMap;
use std::net::Ipv4Addr;

fn decoder_tunnel_type(s: &str) -> Option<u8> {
    return match s {
        "erspan" => Some(4), // DECODE_TUNNEL_ERSPANII
        "vxlan" => Some(6),  // DECODE_TUNNEL_VXLAN
        _ => None,
    };
}

fn decoder_ipv4(s: &str) -> Option<u32> {
    if let Ok(i) = s.parse::<Ipv4Addr>() {
        return Some(i.to_bits());
    }
    return None;
}

#[repr(C)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct flowtunnel_keys {
    src: u32,
    dst: u32,
    session: u32, // erspan spanid or vxlan vni
    tunnel_type: u8,
}

#[no_mangle]
pub unsafe extern "C" fn DecodeTunnelsConfig() -> *mut HashMap<flowtunnel_keys, u16> {
    let mut r = HashMap::new();
    if let Some(n) = conf_get_node("decoder.tunnels") {
        let mut node = n.first();
        loop {
            if node.is_none() {
                break;
            }
            let nodeu = node.unwrap();

            let nid = nodeu.get_child_from::<u16>("id");
            if nid.is_none() {
                SCLogWarning!("missing id for decoder tunnel");
                node = nodeu.next();
                continue;
            }
            let nid = nid.unwrap();

            let ntype = nodeu.get_child_value("type");
            if ntype.is_none() {
                SCLogWarning!("missing type for decoder tunnel");
                node = nodeu.next();
                continue;
            }
            let ntype = ntype.unwrap();
            let tunnel_type = decoder_tunnel_type(ntype);
            if tunnel_type.is_none() {
                SCLogWarning!("unknown type for decoder tunnel {}", ntype);
                node = nodeu.next();
                continue;
            }
            let tunnel_type = tunnel_type.unwrap();

            let session = nodeu.get_child_from::<u32>("session");
            if session.is_none() {
                SCLogWarning!("missing span id for decoder tunnel");
                node = nodeu.next();
                continue;
            }
            let session = session.unwrap();

            let nsrc = nodeu.get_child_value("src");
            if nsrc.is_none() {
                SCLogWarning!("missing src for decoder tunnel");
                node = nodeu.next();
                continue;
            }
            let nsrc = nsrc.unwrap();
            let src = decoder_ipv4(nsrc);
            if src.is_none() {
                SCLogWarning!("invalid ipv4 src for decoder tunnel {}", nsrc);
                node = nodeu.next();
                continue;
            }
            let src = src.unwrap();

            let ndst = nodeu.get_child_value("dst");
            if ndst.is_none() {
                SCLogWarning!("missing src for decoder tunnel");
                node = nodeu.next();
                continue;
            }
            let ndst = ndst.unwrap();
            let dst = decoder_ipv4(ndst);
            if dst.is_none() {
                SCLogWarning!("invalid ipv4 src for decoder tunnel {}", ndst);
                node = nodeu.next();
                continue;
            }
            let dst = dst.unwrap();

            let k = flowtunnel_keys {
                src,
                dst,
                session,
                tunnel_type,
            };
            r.insert(k, nid);

            node = nodeu.next();
        }
    }
    return Box::into_raw(Box::new(r));
}

#[no_mangle]
pub unsafe extern "C" fn DecodeTunnelsFree(map: *mut HashMap<flowtunnel_keys, u16>) {
    if !map.is_null() {
        let _ = Box::from_raw(map); // Automatically dropped at end of scope
    }
}

#[no_mangle]
pub unsafe extern "C" fn DecodeTunnelsId(
    map: *mut HashMap<flowtunnel_keys, u16>, key: flowtunnel_keys,
) -> u16 {
    if map.is_null() {
        return u16::MAX;
    }

    let map = &*map;
    match map.get(&key) {
        Some(value) => *value,
        None => u16::MAX, // PKT_TUNNEL_UNKNOWN
    }
}
