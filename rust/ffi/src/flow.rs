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

use std::os::raw::c_void;

use suricata_sys::sys::{Flow, Packet, ThreadVars};
use suricata_sys::sys::{
    SCFlowRegisterFinishCallback, SCFlowRegisterInitCallback, SCFlowRegisterUpdateCallback,
};

/// Register a flow initialization callback.
///
/// The callback is invoked whenever Suricata initializes a flow. It receives:
/// - `tv`: the `ThreadVars` for the thread creating the flow
/// - `f`: the newly initialized `Flow`
/// - `p`: the packet related to creating the flow
///
/// # Safety
///
/// The callback receives raw pointers from Suricata. These pointers are only
/// valid for the duration of the callback invocation and must not be stored.
///
/// The callback must not panic.
pub fn register_init_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(*mut ThreadVars, *mut Flow, *const Packet) + Send + Sync + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCFlowRegisterInitCallback(Some(init_callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register flow init callback")
    }
}

/// Register a flow update callback.
///
/// The callback is invoked whenever Suricata updates a flow with a packet. It
/// receives:
/// - `tv`: the `ThreadVars` for the thread updating the flow
/// - `f`: the flow being updated
/// - `p`: the packet responsible for the flow update
///
/// # Safety
///
/// The callback receives raw pointers from Suricata. These pointers are only
/// valid for the duration of the callback invocation and must not be stored.
///
/// The callback must not panic.
pub fn register_update_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(*mut ThreadVars, *mut Flow, *mut Packet) + Send + Sync + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCFlowRegisterUpdateCallback(Some(update_callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register flow update callback")
    }
}

/// Register a flow finish callback.
///
/// The callback is invoked when Suricata is finished with a flow. It receives:
/// - `tv`: the `ThreadVars` for the thread finishing the flow
/// - `f`: the flow being finished
///
/// # Safety
///
/// The callback receives raw pointers from Suricata. These pointers are only
/// valid for the duration of the callback invocation and must not be stored.
///
/// The callback must not panic.
pub fn register_finish_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(*mut ThreadVars, *mut Flow) + Send + Sync + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCFlowRegisterFinishCallback(Some(finish_callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register flow finish callback")
    }
}

unsafe extern "C" fn init_callback_wrapper<F>(
    tv: *mut ThreadVars, f: *mut Flow, p: *const Packet, user: *mut c_void,
) where
    F: Fn(*mut ThreadVars, *mut Flow, *const Packet) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(tv, f, p);
}

unsafe extern "C" fn update_callback_wrapper<F>(
    tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet, user: *mut c_void,
) where
    F: Fn(*mut ThreadVars, *mut Flow, *mut Packet) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(tv, f, p);
}

unsafe extern "C" fn finish_callback_wrapper<F>(
    tv: *mut ThreadVars, f: *mut Flow, user: *mut c_void,
) where
    F: Fn(*mut ThreadVars, *mut Flow) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(tv, f);
}
