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
    self, SCThreadGetStorageById, SCThreadRegisterInitCallback, SCThreadSetStorageById,
    SCThreadStorageId, SCThreadStorageRegister,
};

/// A safe wrapper around a Suricata `sys::ThreadVars` pointer.
///
/// A wrapper around `sys::ThreadVars` that carries a lifetime.
pub struct ThreadVars<'a> {
    tv: *mut sys::ThreadVars,
    _marker: PhantomData<&'a mut sys::ThreadVars>,
}

impl<'a> ThreadVars<'a> {
    /// Wrap a raw `ThreadVars` pointer.
    ///
    /// # Safety
    ///
    /// `tv` must be a valid `ThreadVars` pointer provided by Suricata.
    pub unsafe fn from_ptr(tv: *mut sys::ThreadVars) -> Self {
        Self {
            tv,
            _marker: PhantomData,
        }
    }

    /// Return the underlying raw `ThreadVars` pointer for read-only access.
    pub fn as_ptr(&self) -> *const sys::ThreadVars {
        self.tv
    }

    /// Return the underlying raw `ThreadVars` pointer for mutable access.
    ///
    /// Requires `&mut self` so that mutable use of the underlying
    /// `ThreadVars` (such as setting thread storage) is gated by an exclusive
    /// borrow of the wrapper.
    fn as_mut_ptr(&mut self) -> *mut sys::ThreadVars {
        self.tv
    }
}

/// A typed handle to a per-thread storage slot.
///
/// `ThreadStorage<T>` wraps the `SCThreadStorageId` returned when registering
/// thread storage with Suricata. Values are stored as a `Box<T>` owned by
/// Suricata's thread storage and are dropped automatically when the thread's
/// storage is freed.
///
/// The handle only holds the storage id, so it is `Copy` and `Send`/`Sync`
/// regardless of `T`, and can be passed by value into the callbacks that need
/// it.
pub struct ThreadStorage<T> {
    id: SCThreadStorageId,
    _marker: PhantomData<fn() -> T>,
}

// Manual `Copy`/`Clone` impls so the handle is copyable regardless of whether
// `T` is; it only holds the storage id.
impl<T> Clone for ThreadStorage<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ThreadStorage<T> {}

impl<T: Send + 'static> ThreadStorage<T> {
    /// Register a new thread storage slot for values of type `T`.
    ///
    /// `name` must be unique among registered thread storage. Registration has
    /// to happen during initialization, before Suricata finalizes storage
    /// registration (`SCStorageFinalize`).
    ///
    /// Returns an error if `name` contains an interior nul byte or if Suricata
    /// rejects the registration.
    pub fn register(name: &str) -> Result<Self, &'static str> {
        let name = CString::new(name).map_err(|_| "thread storage name contains a nul byte")?;
        let id = unsafe { SCThreadStorageRegister(name.as_ptr(), Some(Self::free)) };
        if id.id < 0 {
            return Err("Failed to register thread storage");
        }

        // Suricata keeps the storage name pointer in its storage mapping for
        // the lifetime of the process, so the CString is intentionally leaked.
        std::mem::forget(name);

        Ok(Self {
            id,
            _marker: PhantomData,
        })
    }

    /// Return a reference to the value stored for `tv`, if any.
    pub fn get<'t>(&self, tv: &'t ThreadVars<'_>) -> Option<&'t T> {
        let ptr = unsafe { SCThreadGetStorageById(tv.as_ptr(), self.id) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &*(ptr as *const T) })
        }
    }

    /// Return a mutable reference to the value stored for `tv`, if any.
    ///
    /// Takes `&mut ThreadVars` so the returned `&mut T` is the only live
    /// reference to the stored value for the duration of the borrow.
    pub fn get_mut<'t>(&self, tv: &'t mut ThreadVars<'_>) -> Option<&'t mut T> {
        let ptr = unsafe { SCThreadGetStorageById(tv.as_ptr(), self.id) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { &mut *(ptr as *mut T) })
        }
    }

    /// Return a mutable reference to the value stored for `tv`, inserting the
    /// value produced by `init` if none is present yet.
    ///
    /// Takes `&mut ThreadVars` so the returned `&mut T` is the only live
    /// reference to the stored value for the duration of the borrow.
    pub fn get_or_insert_with<'t>(
        &self, tv: &'t mut ThreadVars<'_>, init: impl FnOnce() -> T,
    ) -> Result<&'t mut T, &'static str> {
        let ptr = unsafe { SCThreadGetStorageById(tv.as_ptr(), self.id) };
        if !ptr.is_null() {
            return Ok(unsafe { &mut *(ptr as *mut T) });
        }

        // `SCThreadSetStorageById` overwrites the slot without freeing any
        // previous value; we only reach here when the slot is empty.
        let ptr = Box::into_raw(Box::new(init()));
        let rc = unsafe { SCThreadSetStorageById(tv.as_mut_ptr(), self.id, ptr.cast()) };
        if rc != 0 {
            unsafe {
                drop(Box::from_raw(ptr));
            }
            return Err("Failed to set thread storage");
        }

        Ok(unsafe { &mut *ptr })
    }

    /// Free callback registered with Suricata thread storage that drops the
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

/// Register a thread initialization callback.
///
/// The callback is invoked for every thread being initialized during Suricata
/// startup. It receives the `ThreadVars` for the thread that has just been
/// initialized.
pub fn register_init_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(&mut ThreadVars) + Send + Sync + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCThreadRegisterInitCallback(Some(init_callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register thread init callback")
    }
}

unsafe extern "C" fn init_callback_wrapper<F>(tv: *mut sys::ThreadVars, user: *mut c_void)
where
    F: Fn(&mut ThreadVars) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    let mut tv = ThreadVars::from_ptr(tv);
    callback(&mut tv);
}
