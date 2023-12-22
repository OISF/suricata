/* Copyright (C) 2022 Open Information Security Foundation
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

//! Module for rule parsing.

pub mod byte_math;
pub mod error;
pub mod iprep;
pub mod parser;
pub mod stream_size;
pub mod uint;
pub mod uri;
pub mod requires;

/// Enum trait that will be implemented on enums that
/// derive StringEnum.
pub trait Enum<T> {
    /// Return the enum variant of the given numeric value.
    fn from_u(v: T) -> Option<Self> where Self: Sized;

    /// Convert the enum variant to the numeric value.
    fn into_u(&self) -> T;

    /// Return the string for logging the enum value.
    fn to_str(&self) -> &'static str;

    /// Get an enum variant from parsing a string.
    fn from_str(s: &str) -> Option<Self> where Self: Sized;
}
