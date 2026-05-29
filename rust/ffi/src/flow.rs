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

use suricata_sys::sys::{
    self, Packet, SCFlowGetStorageById, SCFlowRegisterFinishCallback, SCFlowRegisterInitCallback,
    SCFlowRegisterUpdateCallback, SCFlowSetStorageById, SCFlowStorageId, SCFlowStorageRegister,
};

use crate::thread::ThreadVars;

/// A safe wrapper around a Suricata `sys::Flow` pointer.
///
/// A wrapper around `sys::Flow` that carries a lifetime tied to the callback
/// invocation it was created for, so the borrow checker prevents it from being
/// stored beyond the call.
pub struct Flow<'a> {
    flow: *mut sys::Flow,
    _marker: PhantomData<&'a mut sys::Flow>,
}

impl<'a> Flow<'a> {
    /// Wrap a raw `Flow` pointer.
    ///
    /// # Safety
    ///
    /// `flow` must be a valid `Flow` pointer provided by Suricata.
    pub unsafe fn from_ptr(flow: *mut sys::Flow) -> Self {
        Self {
            flow,
            _marker: PhantomData,
        }
    }

    /// Return the underlying raw `Flow` pointer for read-only access.
    pub fn as_ptr(&self) -> *const sys::Flow {
        self.flow
    }

    /// Return the underlying raw `Flow` pointer for mutable access.
    fn as_mut_ptr(&mut self) -> *mut sys::Flow {
        self.flow
    }
}

/// A typed handle to a per-flow storage slot.
///
/// `FlowStorage<T>` wraps the `SCFlowStorageId` returned when registering flow
/// storage with Suricata. Values are stored as a `Box<T>` owned by Suricata's
/// flow storage and are dropped automatically when the flow's storage is freed.
///
/// The handle only holds the storage id, so it is `Copy` and `Send`/`Sync`
/// regardless of `T`, and can be passed by value into the callbacks that need
/// it.
pub struct FlowStorage<T> {
    id: SCFlowStorageId,
    _marker: PhantomData<fn() -> T>,
}

// Manual `Copy`/`Clone` impls so the handle is copyable regardless of whether
// `T` is; it only holds the storage id.
impl<T> Clone for FlowStorage<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for FlowStorage<T> {}

impl<T: Send + 'static> FlowStorage<T> {
    /// Register a new flow storage slot for values of type `T`.
    ///
    /// `name` must be unique among registered flow storage. Registration has to
    /// happen during initialization, before Suricata finalizes storage
    /// registration (`SCStorageFinalize`).
    ///
    /// Returns an error if `name` contains an interior nul byte or if Suricata
    /// rejects the registration.
    pub fn register(name: &str) -> Result<Self, &'static str> {
        let name = CString::new(name).map_err(|_| "flow storage name contains a nul byte")?;
        let id = unsafe { SCFlowStorageRegister(name.as_ptr(), Some(Self::free)) };
        if id.id < 0 {
            return Err("Failed to register flow storage");
        }

        // Suricata keeps the storage name pointer in its storage mapping for
        // the lifetime of the process, so the CString is intentionally leaked.
        std::mem::forget(name);

        Ok(Self {
            id,
            _marker: PhantomData,
        })
    }

    /// Return a reference to the value stored for `f`, if any.
    pub fn get<'f>(&self, f: &'f Flow<'_>) -> Option<&'f T> {
        let ptr = unsafe { SCFlowGetStorageById(f.as_ptr(), self.id) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*(ptr as *const T) })
        }
    }

    /// Return a mutable reference to the value stored for `f`, if any.
    pub fn get_mut<'f>(&self, f: &'f mut Flow<'_>) -> Option<&'f mut T> {
        let ptr = unsafe { SCFlowGetStorageById(f.as_ptr(), self.id) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *(ptr as *mut T) })
        }
    }

    /// Return a mutable reference to the value stored for `f`, inserting the
    /// value produced by `init` if none is present yet.
    pub fn get_or_insert_with<'f>(
        &self, f: &'f mut Flow<'_>, init: impl FnOnce() -> T,
    ) -> Result<&'f mut T, &'static str> {
        let ptr = unsafe { SCFlowGetStorageById(f.as_ptr(), self.id) };
        if !ptr.is_null() {
            return Ok(unsafe { &mut *(ptr as *mut T) });
        }

        // `SCFlowSetStorageById` overwrites the slot without freeing any
        // previous value; we only reach here when the slot is empty.
        let ptr = Box::into_raw(Box::new(init()));
        let rc = unsafe { SCFlowSetStorageById(f.as_mut_ptr(), self.id, ptr.cast()) };
        if rc != 0 {
            unsafe {
                drop(Box::from_raw(ptr));
            }
            return Err("Failed to set flow storage");
        }

        Ok(unsafe { &mut *ptr })
    }

    /// Free callback registered with Suricata flow storage that drops the
    /// `Box<T>` backing a stored value.
    unsafe extern "C" fn free(ptr: *mut c_void) {
        if !ptr.is_null() {
            // The drop runs across an FFI boundary, so guard against unwinding
            // into C if `T`'s `Drop` panics.
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
    F: Fn(&mut ThreadVars, &mut Flow, *const Packet) + Send + Sync + 'static,
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
    F: Fn(&mut ThreadVars, &mut Flow, *mut Packet) + Send + Sync + 'static,
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
    F: Fn(&mut ThreadVars, &mut Flow) + Send + Sync + 'static,
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
    tv: *mut sys::ThreadVars, f: *mut sys::Flow, p: *const Packet, user: *mut c_void,
) where
    F: Fn(&mut ThreadVars, &mut Flow, *const Packet) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    let mut tv = ThreadVars::from_ptr(tv);
    let mut f = Flow::from_ptr(f);
    callback(&mut tv, &mut f, p);
}

unsafe extern "C" fn update_callback_wrapper<F>(
    tv: *mut sys::ThreadVars, f: *mut sys::Flow, p: *mut Packet, user: *mut c_void,
) where
    F: Fn(&mut ThreadVars, &mut Flow, *mut Packet) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    let mut tv = ThreadVars::from_ptr(tv);
    let mut f = Flow::from_ptr(f);
    callback(&mut tv, &mut f, p);
}

unsafe extern "C" fn finish_callback_wrapper<F>(
    tv: *mut sys::ThreadVars, f: *mut sys::Flow, user: *mut c_void,
) where
    F: Fn(&mut ThreadVars, &mut Flow) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    let mut tv = ThreadVars::from_ptr(tv);
    let mut f = Flow::from_ptr(f);
    callback(&mut tv, &mut f);
}
