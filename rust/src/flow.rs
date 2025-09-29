/* Copyright (C) 2017-2025 Open Information Security Foundation
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

// Flow flags
pub const FLOW_DIR_REVERSED: u32 = BIT_U32!(26);

/// Opaque flow type (defined in C)
pub(crate) use suricata_sys::sys::{
    Flow, SCFlowGetDestinationPort, SCFlowGetFlags, SCFlowGetLastTimeAsParts, SCFlowGetSourcePort,
};

/// Return the time of the last flow update as a `Duration`
/// since the epoch.
pub fn flow_get_last_time(flow: &Flow) -> std::time::Duration {
    unsafe {
        let mut secs: u64 = 0;
        let mut usecs: u64 = 0;
        SCFlowGetLastTimeAsParts(flow, &mut secs, &mut usecs);
        std::time::Duration::new(secs, usecs as u32 * 1000)
    }
}

/// Return the flow flags.
pub fn flow_get_flags(flow: &Flow) -> u32 {
    unsafe { SCFlowGetFlags(flow) }
}

/// Return flow ports
pub fn flow_get_ports(flow: &Flow) -> (u16, u16) {
    unsafe { (SCFlowGetSourcePort(flow), SCFlowGetDestinationPort(flow)) }
}
