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

use std::ffi::{CString, NulError};

use suricata_sys::sys::{
    SCEveFileType, SCEveFileTypeDeinitFunc, SCEveFileTypeInitFunc, SCEveFileTypeThreadDeinitFunc,
    SCEveFileTypeThreadInitFunc, SCEveFileTypeWriteFunc, SCRegisterEveFileType,
};

pub struct EveFileType {
    inner: Box<SCEveFileType>,

    // Never read, just used to hold the real string.
    _name: CString,
}

impl EveFileType {
    pub fn new(
        name: &str, init: SCEveFileTypeInitFunc, deinit: SCEveFileTypeDeinitFunc,
        write: SCEveFileTypeWriteFunc, thread_init: SCEveFileTypeThreadInitFunc,
        thread_deinit: SCEveFileTypeThreadDeinitFunc,
    ) -> Result<Self, NulError> {
        // These are all required, but we can't enforce it with the
        // function signature. Instead assert for early detection
        // during development of an EveFileType.
        //
        // Perhaps look at the typestate builder pattern to enforce at
        // compile time.
        assert!(init.is_some(), "init must not be None");
        assert!(deinit.is_some(), "deinit must not be None");
        assert!(write.is_some(), "write must not be None");
        assert!(thread_init.is_some(), "thread_init must not be None");
        assert!(thread_deinit.is_some(), "thread_deinit must not be None");

        let name = CString::new(name)?;

        let inner = Box::new(SCEveFileType {
            name: name.as_ptr(),
            Init: init,
            ThreadInit: thread_init,
            Write: write,
            ThreadDeinit: thread_deinit,
            Deinit: deinit,
            entries: Default::default(),
        });

        Ok(Self { inner, _name: name })
    }

    fn as_mut_ptr(&mut self) -> *mut SCEveFileType {
        &mut *self.inner
    }
}

pub fn register_file_type(mut ft: EveFileType) -> bool {
    if unsafe { SCRegisterEveFileType(ft.as_mut_ptr()) } {
        // Forget the file type now, as its now owned by the EVE
        // filetype registry.
        std::mem::forget(ft);
        true
    } else {
        false
    }
}
