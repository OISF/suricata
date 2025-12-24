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

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum EncryptionHandling {
    ENCRYPTION_HANDLING_TRACK_ONLY = 0, // Disable raw content inspection, continue tracking
    ENCRYPTION_HANDLING_BYPASS = 1,     // Skip processing of flow, bypass if possible
    ENCRYPTION_HANDLING_FULL = 2,       // Handle fully like any other protocol
}

impl std::str::FromStr for EncryptionHandling {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "full" => Ok(EncryptionHandling::ENCRYPTION_HANDLING_FULL),
            "track-only" => Ok(EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY),
            "bypass" => Ok(EncryptionHandling::ENCRYPTION_HANDLING_BYPASS),
            _ => Err(()),
        }
    }
}