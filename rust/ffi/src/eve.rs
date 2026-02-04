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

use suricata_sys::sys::{
    SCEveFileType, SCEveFileTypeDeinitFunc, SCEveFileTypeInitFunc, SCEveFileTypeThreadDeinitFunc,
    SCEveFileTypeThreadInitFunc, SCEveFileTypeWriteFunc, SCRegisterEveFileType,
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
