/* Copyright (C) 2023 Open Information Security Foundation
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

//! Rust bindings to the "feature" API.
//!
//! As this feature module is a binding to a Suricata C module it is
//! not available to Rust unit tests. Instead when running Rust unit
//! tests and "mock" version is provided that will return true for any
//! feature starting with "true" and false for any other feature name.

#[cfg(test)]
mod mock {
    /// Check for a feature returning true if found.
    ///
    /// This a "mock" variant of `requires` that will return true for
    /// any feature starting with string `true`, and false for
    /// anything else.
    pub fn requires(feature: &str) -> bool {
        return feature.starts_with("true");
    }

    /// Check for a keyword returning true if found.
    ///
    /// This a "mock" variant of `has_keyword` that will return true
    /// for any keyword starting with string `true`, and false for
    /// anything else.
    pub fn has_keyword(keyword: &str) -> bool {
        return keyword.starts_with("true");
    }
}

#[cfg(not(test))]
mod real {
    use std::ffi::CString;
    use std::os::raw::c_char;

    extern "C" {
        fn RequiresFeature(feature: *const c_char) -> bool;
        fn SigTableHasKeyword(keyword: *const c_char) -> bool;
    }

    /// Check for a feature returning true if found.
    pub fn requires(feature: &str) -> bool {
        if let Ok(feature) = CString::new(feature) {
            unsafe { RequiresFeature(feature.as_ptr()) }
        } else {
            false
        }
    }

    pub fn has_keyword(keyword: &str) -> bool {
        if let Ok(keyword) = CString::new(keyword) {
            unsafe { SigTableHasKeyword(keyword.as_ptr()) }
        } else {
            false
        }
    }
}

#[cfg(not(test))]
pub use real::*;

#[cfg(test)]
pub use mock::*;
