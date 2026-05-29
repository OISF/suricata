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
use std::os::raw::c_void;

use suricata_sys::sys::{self, SCThreadRegisterInitCallback};

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
}

/// Register a thread initialization callback.
///
/// The callback is invoked for every thread being initialized during Suricata
/// startup. It receives the `ThreadVars` for the thread that has just been
/// initialized.
///
/// # Safety
///
/// The callback receives a raw pointer from Suricata. This pointer is only
/// valid for the duration of the callback invocation and must not be stored.
///
/// The callback must not panic.
pub fn register_init_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(*mut sys::ThreadVars) + Send + Sync + 'static,
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
    F: Fn(*mut sys::ThreadVars) + Send + Sync + 'static,
{
    let callback = &*(user as *const F);
    callback(tv);
}
