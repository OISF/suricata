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
use suricata_sys::sys::SCPacketTunnelType;

pub const PKT_TUNNEL_UNKNOWN: u16 = u16::MAX;

fn decoder_tunnel_type(s: Option<&str>) -> Option<u8> {
    return match s {
        Some("erspan2") => Some(SCPacketTunnelType::DECODE_TUNNEL_ERSPANII as u8),
        Some("vxlan") => Some(SCPacketTunnelType::DECODE_TUNNEL_VXLAN as u8),
        _ => None,
    };
}

fn decoder_ipv4(o: Option<&str>) -> Option<u32> {
    if let Some(s) = o {
        if let Ok(i) = s.parse::<Ipv4Addr>() {
            return Some(u32::from_be_bytes(i.octets()));
        }
    }
    return None;
}

#[repr(C)]
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct flowtunnel_keys {
    src: u32,
    dst: u32,
    // would be nice to have this field u24, like C __u32 session : 24; __u8 tunnel : 8;
    session: u32, // erspan spanid or vxlan vni
    tunnel_type: u8,
}

#[no_mangle]
pub unsafe extern "C" fn DecodeTunnelsConfig() -> *mut HashMap<flowtunnel_keys, u16> {
    let mut r = HashMap::new();
    if let Some(n) = conf_get_node("decoder.tunnels") {
        for nodeu in n.iter() {
            // Get all the fields with their right types
            let nid = nodeu.get_child_from::<u16>("id");
            if nid.is_none() {
                SCLogWarning!("missing id for decoder tunnel");
                continue;
            }
            let nid = nid.unwrap();

            let ntype = nodeu.get_child_value("type");
            let tunnel_type = decoder_tunnel_type(ntype);
            if tunnel_type.is_none() {
                SCLogWarning!("unknown type for decoder tunnel {:?}", ntype);
                continue;
            }
            let tunnel_type = tunnel_type.unwrap();

            let session = nodeu.get_child_from::<u32>("session");
            if session.is_none() {
                SCLogWarning!("missing session for decoder tunnel");
                continue;
            }
            let session = session.unwrap();

            let nsrc = nodeu.get_child_value("src");
            let src = decoder_ipv4(nsrc);
            if src.is_none() {
                SCLogWarning!("invalid ipv4 src for decoder tunnel {:?}", nsrc);
                continue;
            }
            let src = src.unwrap();

            let ndst = nodeu.get_child_value("dst");
            let dst = decoder_ipv4(ndst);
            if dst.is_none() {
                SCLogWarning!("invalid ipv4 src for decoder tunnel {:?}", ndst);
                continue;
            }
            let dst = dst.unwrap();

            // Finally insert the tunnel in the map
            let k = flowtunnel_keys {
                src,
                dst,
                session,
                tunnel_type,
            };
            r.insert(k, nid);
        }
    } else {
        // no decoder.tunnels section in conf
        return std::ptr::null_mut();
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
        return PKT_TUNNEL_UNKNOWN;
    }

    let map = &*map;
    match map.get(&key) {
        Some(value) => *value,
        None => PKT_TUNNEL_UNKNOWN,
    }
}
