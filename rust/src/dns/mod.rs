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

use log::*;
use conf;

pub mod parser;
pub use self::parser::*;

pub mod dns;
pub use self::dns::*;

#[no_mangle]
pub extern "C" fn rs_dns_init() {
    SCLogNotice!("Initializing DNS analyzer");
    
    match conf::conf_get("app-layer.protocols.dns.tcp.enabled") {
        Some(val) => SCLogNotice!("- TCP is enabled: {}", val),
        None => SCLogNotice!("- TCP is not enabled."),
    }

    match conf::conf_get("app-layer.protocols.dns.udp.enabled") {
        Some(val) => SCLogNotice!("- UDP is enabled: {}", val),
        None => SCLogNotice!("- UDP is not enabled."),
    }
}


