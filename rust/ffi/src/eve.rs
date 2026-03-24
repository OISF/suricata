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
use std::os::raw::c_void;

pub use suricata_sys::sys::{Flow, Packet, SCEveUserCallbackFn, SCJsonBuilder, ThreadVars};
use suricata_sys::sys::{
    SCEveFileType, SCEveFileTypeDeinitFunc, SCEveFileTypeInitFunc, SCEveFileTypeThreadDeinitFunc,
    SCEveFileTypeThreadInitFunc, SCEveFileTypeWriteFunc, SCEveRegisterCallback,
    SCRegisterEveFileType,
};

pub struct EveFileType {
    pub name: &'static str,
    pub init: SCEveFileTypeInitFunc,
    pub deinit: SCEveFileTypeDeinitFunc,
    pub write: SCEveFileTypeWriteFunc,
    pub thread_init: SCEveFileTypeThreadInitFunc,
    pub thread_deinit: SCEveFileTypeThreadDeinitFunc,
}

impl EveFileType {
    pub fn register(ft: Self) -> Result<(), &'static str> {
        let name = CString::new(ft.name).map_err(|_| "invalid name")?;
        if ft.init.is_none() {
            return Err("None not allowed for init");
        }
        if ft.deinit.is_none() {
            return Err("None not allowed for deinit");
        }
        if ft.write.is_none() {
            return Err("None now allowed for write");
        }
        if ft.thread_init.is_none() {
            return Err("None now allowed for thread_init");
        }
        if ft.thread_deinit.is_none() {
            return Err("None not allowed for thread_deinit");
        }
        let mut cft = Box::new(SCEveFileType {
            name: name.as_ptr(),
            Init: ft.init,
            ThreadInit: ft.thread_init,
            Write: ft.write,
            ThreadDeinit: ft.thread_deinit,
            Deinit: ft.deinit,
            entries: Default::default(),
        });
        if unsafe { SCRegisterEveFileType(&mut *cft) } {
            std::mem::forget(cft);
            std::mem::forget(name);
            Ok(())
        } else {
            Err("Failed to register EveFileType")
        }
    }
}

/// Register an EVE callback.
///
/// The callback is invoked just before the top-level EVE JSON object
/// is closed. New fields may be added at that point, but objects and
/// fields already written to the `JsonBuilder` cannot be altered.
///
/// The callback receives:
/// - `tv`: the `ThreadVars` for the thread performing the logging
/// - `p`: the `Packet`, if available
/// - `f`: the `Flow`, if available
/// - `jb`: the JSON builder for the current EVE record
///
/// This API is intended for plugin and library users.
///
/// # Example
///
/// ```no_run
/// use suricata_ffi::eve;
///
/// eve::register_callback(|_tv, _p, _f, jb| {
///     jb.open_object("my_plugin")?;
///     jb.set_string("key", "value")?;
///     jb.close()?;
///     Ok(())
/// }).expect("failed to register EVE callback");
/// ```
///
/// If the callback returns `Err`, any JSON emitted by that callback
/// is discarded by restoring the builder to its initial mark.
///
/// # Safety
///
/// The callback receives raw pointers from Suricata. These pointers
/// are only valid for the duration of the callback invocation and
/// must not be stored.
///
/// The callback must not panic.
pub fn register_callback<F>(callback: F) -> Result<(), &'static str>
where
    F: Fn(
            *mut ThreadVars,
            *const Packet,
            *mut Flow,
            &mut crate::jsonbuilder::JsonBuilder,
        ) -> Result<(), crate::jsonbuilder::Error>
        + Send
        + Sync
        + 'static,
{
    let user = Box::into_raw(Box::new(callback)) as *mut c_void;
    if unsafe { SCEveRegisterCallback(Some(callback_wrapper::<F>), user) } {
        Ok(())
    } else {
        unsafe {
            drop(Box::from_raw(user as *mut F));
        }
        Err("Failed to register EVE callback")
    }
}

/// Internal wrapper used to adapt the C EVE callback to a Rust
/// closure callback.
unsafe extern "C" fn callback_wrapper<F>(
    tv: *mut ThreadVars, p: *const Packet, f: *mut Flow, jb: *mut SCJsonBuilder, user: *mut c_void,
) where
    F: Fn(
            *mut ThreadVars,
            *const Packet,
            *mut Flow,
            &mut crate::jsonbuilder::JsonBuilder,
        ) -> Result<(), crate::jsonbuilder::Error>
        + Send
        + Sync
        + 'static,
{
    let callback = &*(user as *const F);
    let mut jb = crate::jsonbuilder::JsonBuilder::from_raw(jb);
    let mark = jb.get_mark();
    if callback(tv, p, f, &mut jb).is_err() {
        let _ = jb.restore_mark(&mark);
    }
}
