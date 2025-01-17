/* Copyright (C) 2017-2025 Open Information Security Foundation
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

pub const DIR_BOTH: u8 = 0b0000_1100;
const DIR_TOSERVER: u8 = 0b0000_0100;
const DIR_TOCLIENT: u8 = 0b0000_1000;

#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Direction {
    ToServer = 0x04,
    ToClient = 0x08,
}

impl Direction {
    /// Return true if the direction is to server.
    pub fn is_to_server(&self) -> bool {
        matches!(self, Self::ToServer)
    }

    /// Return true if the direction is to client.
    pub fn is_to_client(&self) -> bool {
        matches!(self, Self::ToClient)
    }

    pub fn index(&self) -> usize {
        match self {
            Self::ToClient => 0,
            _ => 1,
        }
    }
}

impl Default for Direction {
    fn default() -> Self {
        Direction::ToServer
    }
}

impl std::fmt::Display for Direction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToServer => write!(f, "toserver"),
            Self::ToClient => write!(f, "toclient"),
        }
    }
}

impl From<u8> for Direction {
    fn from(d: u8) -> Self {
        if d & (DIR_TOSERVER | DIR_TOCLIENT) == (DIR_TOSERVER | DIR_TOCLIENT) {
            debug_validate_fail!("Both directions are set");
            Direction::ToServer
        } else if d & DIR_TOSERVER != 0 {
            Direction::ToServer
        } else if d & DIR_TOCLIENT != 0 {
            Direction::ToClient
        } else {
            debug_validate_fail!("Unknown direction!!");
            Direction::ToServer
        }
    }
}

impl From<Direction> for u8 {
    fn from(d: Direction) -> u8 {
        d as u8
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_direction() {
        assert!(Direction::ToServer.is_to_server());
        assert!(!Direction::ToServer.is_to_client());

        assert!(Direction::ToClient.is_to_client());
        assert!(!Direction::ToClient.is_to_server());
    }
}
