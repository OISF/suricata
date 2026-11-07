/* Copyright (C) 2026 Open Information Security Foundation
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

use std::marker::PhantomData;
use std::time::Duration;

use suricata_sys::sys;

use crate::flow::Flow;

pub use suricata_sys::sys::PacketL3Types;

/// A safe, read-only wrapper around a Suricata `sys::Packet` pointer.
///
/// A wrapper around `sys::Packet` that carries a lifetime tied to the callback
/// invocation it was created for, so the borrow checker prevents it, and data
/// borrowed from it, from being stored beyond the call.
pub struct Packet<'a> {
    p: *const sys::Packet,
    _marker: PhantomData<&'a sys::Packet>,
}

impl<'a> Packet<'a> {
    /// Wrap a raw `Packet` pointer.
    ///
    /// # Safety
    ///
    /// `p` must be a valid, non-null `Packet` pointer provided by Suricata,
    /// and must remain valid and unmodified for `'a`. No other `Flow` wrapper
    /// for the packet's flow may be in use while the `Flow` returned by
    /// [`Packet::flow`] is.
    pub unsafe fn from_ptr(p: *const sys::Packet) -> Self {
        Self {
            p,
            _marker: PhantomData,
        }
    }

    /// Return the underlying raw `Packet` pointer for read-only access.
    pub fn as_ptr(&self) -> *const sys::Packet {
        self.p
    }

    /// Return the IP protocol of the packet, regardless of IP version, or 0
    /// if it has none.
    pub fn ip_protocol(&self) -> u8 {
        unsafe { sys::SCPacketGetIPProto(self.p) }
    }

    /// Return whether the packet is marked as flowing to the server.
    ///
    /// Returns false if the direction has not been established.
    pub fn is_to_server(&self) -> bool {
        unsafe { sys::SCPacketIsToServer(self.p) }
    }

    /// Return whether the packet is marked as flowing to the client.
    ///
    /// Returns false if the direction has not been established.
    pub fn is_to_client(&self) -> bool {
        unsafe { sys::SCPacketIsToClient(self.p) }
    }

    /// Return the flow of the packet, or `None` if it has no flow.
    ///
    /// This takes `&mut self` so that the returned `Flow` is the only wrapper
    /// for the flow obtained through this packet while it is in use. Callbacks
    /// that already receive the packet's `Flow`, such as the flow callbacks,
    /// pass a `&Packet`, so this can't be used to obtain a second `Flow`
    /// wrapper for the same flow:
    ///
    /// ```compile_fail
    /// use suricata_ffi::flow::Flow;
    /// use suricata_ffi::packet::Packet;
    /// use suricata_ffi::thread::ThreadVars;
    ///
    /// fn on_flow_update(_tv: &mut ThreadVars, _f: &mut Flow, p: &Packet) {
    ///     let _flow = p.flow();
    /// }
    /// ```
    pub fn flow(&mut self) -> Option<Flow<'_>> {
        let f = unsafe { sys::SCPacketGetFlow(self.p) };
        if f.is_null() {
            None
        } else {
            Some(unsafe { Flow::from_ptr(f) })
        }
    }

    /// Return the packet timestamp as a `Duration` since the epoch.
    pub fn timestamp(&self) -> Duration {
        let mut secs: u64 = 0;
        let mut usecs: u64 = 0;
        unsafe {
            sys::SCPacketGetTimeAsParts(self.p, &mut secs, &mut usecs);
        }
        Duration::new(secs, usecs as u32 * 1000)
    }

    /// Return the type of the packet's decoded L3 layer.
    pub fn l3_type(&self) -> PacketL3Types {
        unsafe { sys::SCPacketGetL3Type(self.p) }
    }

    /// Return the L3 packet data, starting at the L3 header.
    ///
    /// For IPv4 and IPv6 this is the IP header and its payload, with the
    /// length taken from the IP header. For ARP it is the ARP header. Returns
    /// `None` if the packet has no decoded L3 layer.
    pub fn l3(&self) -> Option<&'a [u8]> {
        let mut len: u32 = 0;
        let ptr = unsafe { sys::SCPacketGetL3(self.p, &mut len) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { std::slice::from_raw_parts(ptr, len as usize) })
        }
    }
}
