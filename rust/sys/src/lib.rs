/* Copyright (C) 2025 Open Information Security Foundation
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

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(clippy::all)]
#![allow(unpredictable_function_pointer_comparisons)]

pub mod jsonbuilder;
pub mod sys;

use crate::sys::{AppLayerResult, AppLayerTxData};

impl AppLayerResult {
    /// parser has successfully processed in the input, and has consumed all of it
    pub fn ok() -> Self {
        Default::default()
    }
    /// parser has hit an unrecoverable error. Returning this to the API
    /// leads to no further calls to the parser.
    pub fn err() -> Self {
        return Self {
            status: -1,
            ..Default::default()
        };
    }
}

impl From<bool> for AppLayerResult {
    fn from(v: bool) -> Self {
        if !v {
            Self::err()
        } else {
            Self::ok()
        }
    }
}

impl From<i32> for AppLayerResult {
    fn from(v: i32) -> Self {
        if v < 0 {
            Self::err()
        } else {
            Self::ok()
        }
    }
}

#[cfg(not(feature = "suritest"))]
use crate::sys::SCAppLayerTxDataCleanup;

impl Drop for AppLayerTxData {
    fn drop(&mut self) {
        #[cfg(not(feature = "suritest"))]
        unsafe {
            SCAppLayerTxDataCleanup(self);
        }
    }
}
