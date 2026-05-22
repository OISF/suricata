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

use std::ffi::CString;
use std::marker::PhantomData;
use std::os::raw::c_void;

use suricata_sys::sys::{Flow as RawFlow, Packet as RawPacket, ThreadVars as RawThreadVars};
use suricata_sys::sys::{
    SCFlowGetStorageById, SCFlowRegisterFinishCallback, SCFlowRegisterInitCallback,
    SCFlowRegisterUpdateCallback, SCFlowSetStorageById, SCFlowStorageId, SCFlowStorageRegister,
};

pub struct Flow<'a> {
    ptr: *mut RawFlow,
    _marker: PhantomData<&'a RawFlow>,
}

impl<'a> Flow<'a> {
    pub fn from_ptr(ptr: *const RawFlow) -> Self {
        Self {
            ptr: ptr.cast_mut(),
            _marker: PhantomData,
        }
    }

    pub fn as_ptr(&self) -> *const RawFlow {
        self.ptr
    }

    fn as_mut_ptr(&mut self) -> *mut RawFlow {
        self.ptr
    }
}

/// Typed storage attached to a Suricata flow.
///
/// A storage slot must be registered before Suricata finalizes storage
/// registration. Values inserted through this wrapper are owned by Suricata and
/// are dropped automatically when the flow storage entry is freed.
pub struct FlowStorage<T> {
    id: SCFlowStorageId,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Copy for FlowStorage<T> {}

impl<T> Clone for FlowStorage<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> FlowStorage<T> {
    /// Register a flow storage slot for values of type `T`.
    pub fn register(name: &str) -> Result<Self, &'static str>
    where
        T: Send + 'static,
    {
        let name = CString::new(name).map_err(|_| "invalid flow storage name")?;
        let id = unsafe { SCFlowStorageRegister(name.as_ptr(), Some(Self::free)) };
        if id.id < 0 {
            return Err("failed to register flow storage");
        }

        // Suricata keeps the storage name pointer in the storage mapping.
        std::mem::forget(name);

        Ok(Self {
            id,
            _marker: PhantomData,
        })
    }

    /// Return the value stored on `flow`, if any.
    pub fn get<'flow>(&self, flow: &'flow Flow<'_>) -> Option<&'flow T> {
        let ptr = unsafe { SCFlowGetStorageById(flow.as_ptr(), self.id) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*(ptr as *const T) })
        }
    }

    /// Return the stored value, inserting the result of `init` if needed.
    pub fn get_or_insert_with<'flow>(
        &self, flow: &'flow mut Flow<'_>, init: impl FnOnce() -> T,
    ) -> Result<&'flow mut T, &'static str> {
        let ptr = unsafe { SCFlowGetStorageById(flow.as_ptr(), self.id) };
        if !ptr.is_null() {
            return Ok(unsafe { &mut *(ptr as *mut T) });
        }

        let ptr = Box::into_raw(Box::new(init()));
        let rc = unsafe { SCFlowSetStorageById(flow.as_mut_ptr(), self.id, ptr.cast()) };
        if rc != 0 {
            unsafe {
                drop(Box::from_raw(ptr));
            }
            return Err("failed to set flow storage");
        }

        Ok(unsafe { &mut *ptr })
    }

    unsafe extern "C" fn free(ptr: *mut c_void) {
        if !ptr.is_null() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                drop(Box::from_raw(ptr as *mut T));
            }));
        }
    }
}

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
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>, Option<crate::packet::Packet<'a>>)
        + Send
        + Sync
        + 'static,
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
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>, Option<crate::packet::Packet<'a>>)
        + Send
        + Sync
        + 'static,
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
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>) + Send + Sync + 'static,
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
    tv: *mut RawThreadVars, f: *mut RawFlow, p: *const RawPacket, user: *mut c_void,
) where
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>, Option<crate::packet::Packet<'a>>)
        + Send
        + Sync
        + 'static,
{
    let callback = &*(user as *const F);
    let packet = if p.is_null() {
        None
    } else {
        Some(crate::packet::Packet::from_ptr(p))
    };
    callback(
        crate::threadvars::ThreadVars::from_ptr(tv),
        Flow::from_ptr(f),
        packet,
    );
}

unsafe extern "C" fn update_callback_wrapper<F>(
    tv: *mut RawThreadVars, f: *mut RawFlow, p: *mut RawPacket, user: *mut c_void,
) where
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>, Option<crate::packet::Packet<'a>>)
        + Send
        + Sync
        + 'static,
{
    let callback = &*(user as *const F);
    let packet = if p.is_null() {
        None
    } else {
        Some(crate::packet::Packet::from_ptr(p))
    };
    callback(
        crate::threadvars::ThreadVars::from_ptr(tv),
        Flow::from_ptr(f),
        packet,
    );
}

unsafe extern "C" fn finish_callback_wrapper<F>(
    tv: *mut RawThreadVars, f: *mut RawFlow, user: *mut c_void,
) where
    F: for<'a> Fn(crate::threadvars::ThreadVars<'a>, Flow<'a>) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(
        crate::threadvars::ThreadVars::from_ptr(tv),
        Flow::from_ptr(f),
    );
}
