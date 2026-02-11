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

//! Rust wrappers around the C JsonBuilder API.
//!
//! This is for plugin and library users.

use std::ffi::{CString, NulError};

use suricata_sys::sys::{
    SCJbClose, SCJbOpenObject, SCJbSetFormatted, SCJbSetString, SCJsonBuilder,
};

// TODO: Map suricata::jsonbuilder::JsonBuilder errors as well,
// however that will require extending that API to pass errors over
// the FFI boundary as integer or strings.
#[derive(Debug)]
pub enum Error {
    NulError(NulError),
    Other,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NulError(err) => err.fmt(f),
            Self::Other => write!(f, "error"),
        }
    }
}

impl std::error::Error for Error {}

impl From<NulError> for Error {
    fn from(err: NulError) -> Self {
        Self::NulError(err)
    }
}

pub struct JsonBuilder {
    jb: *mut SCJsonBuilder,
}

impl JsonBuilder {
    pub fn from_raw(jb: *mut SCJsonBuilder) -> Self {
        Self { jb }
    }

    pub fn open_object(&mut self, key: &str) -> Result<&mut Self, Error> {
        let key = CString::new(key)?;
        if unsafe { SCJbOpenObject(self.jb, key.as_ptr()) } {
            Ok(self)
        } else {
            Err(Error::Other)
        }
    }

    pub fn set_string(&mut self, key: &str, val: &str) -> Result<&mut Self, Error> {
        let key = CString::new(key)?;
        let val = CString::new(val.escape_default().to_string())?;
        if unsafe { SCJbSetString(self.jb, key.as_ptr(), val.as_ptr()) } {
            Ok(self)
        } else {
            Err(Error::Other)
        }
    }

    pub fn set_formatted(&mut self, formatted: &str) -> Result<&mut Self, Error> {
        let formatted = CString::new(formatted)?;
        if unsafe { SCJbSetFormatted(self.jb, formatted.as_ptr()) } {
            Ok(self)
        } else {
            Err(Error::Other)
        }
    }

    pub fn close(&mut self) -> Result<&mut Self, Error> {
        if unsafe { SCJbClose(self.jb) } {
            Ok(self)
        } else {
            Err(Error::Other)
        }
    }
}
