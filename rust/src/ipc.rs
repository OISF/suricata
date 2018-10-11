/* Copyright (C) 2019 Open Information Security Foundation
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
use packet_ipc::{AsIpcPacket, Client, Packet as IpcPacket};
use std::sync::Arc;

pub struct IpcClient {
    pub inner: Client,
}

//IPC Integration
pub type SCPacketExtRelease = extern "C" fn(user: *mut u8);
pub enum Packet {}
pub type SCSetPacketDataFunc = extern "C" fn(
    packet: *mut Packet,
    pktdata: *const u8,
    pktlen: u32,
    linktype: u32,
    tv_sec: u32,
    tv_usec: u32,
    release: SCPacketExtRelease,
    user: *mut std::os::raw::c_void
) -> u32;

extern "C" fn ipc_packet_callback(user: *mut u8) {
    if user != std::ptr::null_mut() {
        unsafe {
            let packet = std::mem::transmute::<*mut u8, *mut IpcPacket>(user);
            let _packet = Arc::from_raw(packet);
            std::mem::drop(_packet);
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_ipc_populate_packets(ipc: *mut IpcClient, packets: *mut *mut Packet, len: u64) -> i64 {
    let sc = unsafe {
        if let Some(sc) = crate::core::SC {
            sc
        } else {
            return 0;
        }
    };

    if ipc.is_null() {
        SCLogNotice!("IPC passed to ipc_populate_packets was null");
        return -1;
    }

    if packets.is_null() {
        SCLogNotice!("Packets passed to ipc_populate_packets was null");
        return -1;
    }

    if len == 0 {
        SCLogNotice!("No packets requested");
        return -1;
    }

    match unsafe { (*ipc).inner.recv(len as usize) } {
        Err(_) => {
            SCLogNotice!("Failed to receive packets in ipc_populate_packets");
            return -1;
        }
        Ok(None) => {
            SCLogInfo!("IPC connection closed");
            return 0;
        }
        Ok(Some(mut ipc_packets)) => {
            if ipc_packets.is_empty() {
                SCLogInfo!("IPC connection closed");
                return 0;
            } else {
                SCLogDebug!("Received {} packets", ipc_packets.len());
                let packets_returned = ipc_packets.len();

                if packets_returned > len as usize {
                    SCLogNotice!("Incorrect number of packets returned ({}) vs available ({})", packets_returned, len);
                    return -1;
                }

                for (idx, packet) in ipc_packets.drain(..).enumerate() {
                    let raw_p = unsafe { *packets.offset(idx as isize) };
                    if raw_p.is_null() {
                        SCLogNotice!("Packet passed to ipc_populate_packets was null");
                        return -1;
                    }
                    if let Ok(dur) = packet.timestamp().duration_since(std::time::UNIX_EPOCH) {
                        let data_ptr = packet.data().as_ptr();
                        let data_len = packet.data().len() as u32;
                        if (sc.SetPacketData)(
                            raw_p,
                            data_ptr,
                            data_len,
                            1, //should probably come with the packet
                            dur.as_secs() as _,
                            dur.subsec_micros() as _,
                            ipc_packet_callback,
                            Arc::into_raw(packet) as *mut std::os::raw::c_void
                        ) != 0 {
                            SCLogNotice!("Failed to set packet data");
                            return -1;
                        }
                    } else {
                        SCLogNotice!("Unable to convert timestamp to timeval in ipc_populate_packets");
                        return -1;
                    }
                }
                return packets_returned as _;
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn rs_create_ipc_client(server_name: *const std::os::raw::c_char, client: *mut *mut IpcClient) -> u32 {
    let server = unsafe { std::ffi::CStr::from_ptr(server_name) };
    if let Ok(s) = server.to_str() {
        if let Ok(ipc) = Client::new(s.to_string()) {
            let raw = Box::into_raw(Box::new(IpcClient { inner: ipc }));
            unsafe { *client = raw };
            1
        } else {
            0
        }
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn rs_release_ipc_client(ipc: *mut IpcClient) {
    let _ipc: Box<IpcClient> = unsafe { Box::from_raw(ipc) };
    std::mem::drop(_ipc);
}